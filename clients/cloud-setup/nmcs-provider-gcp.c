/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libnm/nm-default-client.h"

#include "nmcs-provider-gcp.h"

#include "nm-cloud-setup-utils.h"

/*****************************************************************************/

#define HTTP_TIMEOUT_MS      3000
#define HTTP_REQ_MAX_DATA    512 * 1024
#define HTTP_POLL_TIMEOUT_MS 10000
#define HTTP_RATE_LIMIT_MS   1000

#define NM_GCP_HOST              "metadata.google.internal"
#define NM_GCP_BASE              "http://" NM_GCP_HOST
#define NM_GCP_API_VERSION       "/v1"
#define NM_GCP_METADATA_URL_BASE NM_GCP_BASE "/computeMetadata" NM_GCP_API_VERSION "/instance"
#define NM_GCP_METADATA_URL_NET  "/network-interfaces/"

#define NM_GCP_METADATA_HEADER "Metadata-Flavor: Google"

#define _gcp_uri_concat(...)     nmcs_utils_uri_build_concat(NM_GCP_METADATA_URL_BASE, __VA_ARGS__)
#define _gcp_uri_interfaces(...) _gcp_uri_concat(NM_GCP_METADATA_URL_NET, ##__VA_ARGS__)

/*****************************************************************************/

struct _NMCSProviderGCP {
    NMCSProvider parent;
};

struct _NMCSProviderGCPClass {
    NMCSProviderClass parent;
};

G_DEFINE_TYPE(NMCSProviderGCP, nmcs_provider_gcp, NMCS_TYPE_PROVIDER);

/*****************************************************************************/

static void
_detect_get_meta_data_done_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    gs_unref_object GTask *task     = user_data;
    gs_free_error GError *get_error = NULL;
    gs_free_error GError *error     = NULL;

    nm_http_client_poll_get_finish(NM_HTTP_CLIENT(source), result, NULL, NULL, &get_error);

    if (nm_utils_error_is_cancelled(get_error)) {
        g_task_return_error(task, g_steal_pointer(&get_error));
        return;
    }

    if (get_error) {
        nm_utils_error_set(&error,
                           NM_UTILS_ERROR_UNKNOWN,
                           "failure to get GCP metadata: %s",
                           get_error->message);
        g_task_return_error(task, g_steal_pointer(&error));
        return;
    }

    g_task_return_boolean(task, TRUE);
}

static void
detect(NMCSProvider *provider, GTask *task)
{
    NMHttpClient *http_client;
    gs_free char *uri = NULL;

    http_client = nmcs_provider_get_http_client(provider);

    nm_http_client_poll_get(http_client,
                            (uri = _gcp_uri_concat("id")),
                            HTTP_TIMEOUT_MS,
                            256 * 1024,
                            7000,
                            1000,
                            NM_MAKE_STRV(NM_GCP_METADATA_HEADER),
                            g_task_get_cancellable(task),
                            NULL,
                            NULL,
                            _detect_get_meta_data_done_cb,
                            task);
}

/*****************************************************************************/

typedef struct {
    NMCSProviderGetConfigTaskData * get_config_data;
    NMCSProviderGetConfigIfaceData *iface_get_config;
    gssize                          intern_iface_idx;
    gssize                          extern_iface_idx;
    guint                           n_fips_pending;
} GCPIfaceData;

static void
_gcp_iface_data_destroy(GCPIfaceData *iface_data)
{
    nm_g_slice_free(iface_data);
}

static void
_get_config_fip_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    NMCSProviderGetConfigTaskData * get_config_data;
    NMCSProviderGetConfigIfaceData *iface_get_config;
    gs_unref_bytes GBytes *response   = NULL;
    GCPIfaceData *         iface_data = user_data;
    gs_free_error GError *error       = NULL;
    gs_free char *        ipaddr      = NULL;
    NMIPRoute **          routes_arr;
    NMIPRoute *           route_new;

    nm_http_client_poll_get_finish(NM_HTTP_CLIENT(source), result, NULL, &response, &error);

    if (nm_utils_error_is_cancelled(error))
        return;

    get_config_data = iface_data->get_config_data;

    if (error)
        goto out_done;

    ipaddr = nmcs_utils_ipaddr_normalize_gbytes(AF_INET, response);
    if (!ipaddr) {
        error =
            nm_utils_error_new(NM_UTILS_ERROR_UNKNOWN, "forwarded-ip is not a valid ip address");
        goto out_done;
    }

    _LOGI("GCP interface[%" G_GSSIZE_FORMAT "]: adding forwarded-ip %s",
          iface_data->intern_iface_idx,
          ipaddr);

    iface_get_config = iface_data->iface_get_config;
    routes_arr       = iface_get_config->iproutes_arr;

    route_new = nm_ip_route_new(AF_INET, ipaddr, 32, NULL, 100, &error);
    if (error)
        goto out_done;

    nm_ip_route_set_attribute(route_new, NM_IP_ROUTE_ATTRIBUTE_TYPE, g_variant_new_string("local"));
    routes_arr[iface_get_config->iproutes_len] = route_new;
    ++iface_get_config->iproutes_len;

out_done:
    if (!error) {
        --iface_data->n_fips_pending;
        if (iface_data->n_fips_pending > 0)
            return;
    }

    --get_config_data->n_pending;
    _nmcs_provider_get_config_task_maybe_return(get_config_data, g_steal_pointer(&error));
}

static void
_get_config_ips_list_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    NMCSProviderGetConfigTaskData *get_config_data;
    gs_unref_ptrarray GPtrArray *uri_arr = NULL;
    gs_unref_bytes GBytes *response      = NULL;
    GCPIfaceData *         iface_data    = user_data;
    gs_free_error GError *error          = NULL;
    const char *          response_str   = NULL;
    gsize                 response_len;
    const char *          line;
    gsize                 line_len;
    guint                 i;

    nm_http_client_poll_get_finish(NM_HTTP_CLIENT(source), result, NULL, &response, &error);

    if (nm_utils_error_is_cancelled(error))
        return;

    get_config_data = iface_data->get_config_data;

    if (error)
        goto out_error;

    response_str = g_bytes_get_data(response, &response_len);
    /* NMHttpClient guarantees that there is a trailing NUL after the data. */
    nm_assert(response_str[response_len] == 0);

    uri_arr = g_ptr_array_new_with_free_func(g_free);
    while (nm_utils_parse_next_line(&response_str, &response_len, &line, &line_len)) {
        gint64 fip_index;

        /* Truncate the string. It's safe to do, because we own @response an it has an
         * extra NUL character after the buffer. */
        ((char *) line)[line_len] = '\0';

        fip_index = _nm_utils_ascii_str_to_int64(line, 10, 0, G_MAXINT64, -1);
        if (fip_index < 0)
            continue;

        g_ptr_array_add(uri_arr,
                        g_strdup_printf("%" G_GSSIZE_FORMAT "/forwarded-ips/%" G_GINT64_FORMAT,
                                        iface_data->intern_iface_idx,
                                        fip_index));
    }

    iface_data->n_fips_pending = uri_arr->len;

    _LOGI("GCP interface[%" G_GSSIZE_FORMAT "]: found %u forwarded ips",
          iface_data->intern_iface_idx,
          iface_data->n_fips_pending);

    if (iface_data->n_fips_pending == 0) {
        error = nm_utils_error_new(NM_UTILS_ERROR_UNKNOWN, "found no forwarded ip");
        goto out_error;
    }

    iface_data->iface_get_config->iproutes_arr = g_new(NMIPRoute *, iface_data->n_fips_pending);

    for (i = 0; i < uri_arr->len; ++i) {
        const char *        str = uri_arr->pdata[i];
        gs_free const char *uri = NULL;

        nm_http_client_poll_get(NM_HTTP_CLIENT(source),
                                (uri = _gcp_uri_interfaces(str)),
                                HTTP_TIMEOUT_MS,
                                HTTP_REQ_MAX_DATA,
                                HTTP_POLL_TIMEOUT_MS,
                                HTTP_RATE_LIMIT_MS,
                                NM_MAKE_STRV(NM_GCP_METADATA_HEADER),
                                get_config_data->intern_cancellable,
                                NULL,
                                NULL,
                                _get_config_fip_cb,
                                iface_data);
    }
    return;

out_error:
    --get_config_data->n_pending;
    _nmcs_provider_get_config_task_maybe_return(get_config_data, g_steal_pointer(&error));
}

static void
_get_config_iface_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    gs_unref_bytes GBytes *response         = NULL;
    GCPIfaceData *         iface_data       = user_data;
    gs_free_error GError *         error    = NULL;
    gs_free char *                 v_hwaddr = NULL;
    const char *                   hwaddr   = NULL;
    gs_free const char *           uri      = NULL;
    char                           sbuf[100];
    NMCSProviderGetConfigTaskData *get_config_data;
    gboolean                       is_requested;

    nm_http_client_poll_get_finish(NM_HTTP_CLIENT(source), result, NULL, &response, &error);

    if (nm_utils_error_is_cancelled(error))
        return;

    get_config_data = iface_data->get_config_data;

    if (error)
        goto out_done;

    v_hwaddr = nmcs_utils_hwaddr_normalize_gbytes(response);
    if (!v_hwaddr) {
        _LOGI("GCP interface[%" G_GSSIZE_FORMAT "]: invalid MAC address returned",
              iface_data->intern_iface_idx);
        error = nm_utils_error_new(NM_UTILS_ERROR_UNKNOWN,
                                   "invalid MAC address for index %" G_GSSIZE_FORMAT,
                                   iface_data->intern_iface_idx);
        goto out_done;
    }

    if (!g_hash_table_lookup_extended(get_config_data->result_dict,
                                      v_hwaddr,
                                      (gpointer *) &hwaddr,
                                      (gpointer *) &iface_data->iface_get_config)) {
        if (!get_config_data->any) {
            _LOGD("get-config: skip fetching meta data for %s (%" G_GSSIZE_FORMAT ")",
                  v_hwaddr,
                  iface_data->intern_iface_idx);
            goto out_done;
        }
        iface_data->iface_get_config = nmcs_provider_get_config_iface_data_new(FALSE);
        g_hash_table_insert(get_config_data->result_dict,
                            (char *) (hwaddr = g_steal_pointer(&v_hwaddr)),
                            iface_data->iface_get_config);
        is_requested = FALSE;
    } else {
        if (iface_data->iface_get_config->iface_idx >= 0) {
            _LOGI("GCP interface[%" G_GSSIZE_FORMAT "]: duplicate MAC address %s returned",
                  iface_data->intern_iface_idx,
                  hwaddr);
            error = nm_utils_error_new(NM_UTILS_ERROR_UNKNOWN,
                                       "duplicate MAC address for index %" G_GSSIZE_FORMAT,
                                       iface_data->intern_iface_idx);
            goto out_done;
        }
        is_requested = TRUE;
    }

    iface_data->iface_get_config->iface_idx = iface_data->extern_iface_idx;

    _LOGI("GCP interface[%" G_GSSIZE_FORMAT "]: found a %sdevice with hwaddr %s",
          iface_data->intern_iface_idx,
          is_requested ? "requested " : "",
          hwaddr);

    nm_sprintf_buf(sbuf, "%" G_GSSIZE_FORMAT "/forwarded-ips/", iface_data->intern_iface_idx);

    nm_http_client_poll_get(NM_HTTP_CLIENT(source),
                            (uri = _gcp_uri_interfaces(sbuf)),
                            HTTP_TIMEOUT_MS,
                            HTTP_REQ_MAX_DATA,
                            HTTP_POLL_TIMEOUT_MS,
                            HTTP_RATE_LIMIT_MS,
                            NM_MAKE_STRV(NM_GCP_METADATA_HEADER),
                            get_config_data->intern_cancellable,
                            NULL,
                            NULL,
                            _get_config_ips_list_cb,
                            iface_data);
    return;

out_done:
    --get_config_data->n_pending;
    _nmcs_provider_get_config_task_maybe_return(get_config_data, g_steal_pointer(&error));
}

static void
_get_net_ifaces_list_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    gs_unref_ptrarray GPtrArray *ifaces_arr = NULL;
    gs_unref_bytes GBytes *response         = NULL;
    gs_free_error GError *         error    = NULL;
    NMCSProviderGetConfigTaskData *get_config_data;
    const char *                   response_str;
    gsize                          response_len;
    const char *                   line;
    gsize                          line_len;
    guint                          i;
    gssize                         extern_iface_idx_cnt = 0;

    nm_http_client_poll_get_finish(NM_HTTP_CLIENT(source), result, NULL, &response, &error);

    if (nm_utils_error_is_cancelled(error))
        return;

    get_config_data = user_data;

    if (error) {
        _nmcs_provider_get_config_task_maybe_return(get_config_data, g_steal_pointer(&error));
        return;
    }

    response_str = g_bytes_get_data(response, &response_len);
    /* NMHttpClient guarantees that there is a trailing NUL after the data. */
    nm_assert(response_str[response_len] == 0);

    ifaces_arr = g_ptr_array_new_with_free_func((GDestroyNotify) _gcp_iface_data_destroy);

    while (nm_utils_parse_next_line(&response_str, &response_len, &line, &line_len)) {
        GCPIfaceData *iface_data;
        gssize        intern_iface_idx;

        if (line_len == 0)
            continue;

        /* Truncate the string. It's safe to do, because we own @response an it has an
         * extra NUL character after the buffer. */
        ((char *) line)[line_len] = '\0';
        if (line[line_len - 1] == '/')
            ((char *) line)[--line_len] = '\0';

        intern_iface_idx = _nm_utils_ascii_str_to_int64(line, 10, 0, G_MAXSSIZE, -1);
        if (intern_iface_idx < 0)
            continue;

        iface_data  = g_slice_new(GCPIfaceData);
        *iface_data = (GCPIfaceData){
            .get_config_data  = get_config_data,
            .iface_get_config = NULL,
            .intern_iface_idx = intern_iface_idx,
            .extern_iface_idx = extern_iface_idx_cnt++,
            .n_fips_pending   = 0,
        };
        g_ptr_array_add(ifaces_arr, iface_data);
    }

    _LOGI("found GCP interfaces: %u", ifaces_arr->len);

    if (ifaces_arr->len == 0) {
        _nmcs_provider_get_config_task_maybe_return(
            get_config_data,
            nm_utils_error_new(NM_UTILS_ERROR_UNKNOWN, "no GCP interfaces found"));
        return;
    }

    for (i = 0; i < ifaces_arr->len; ++i) {
        GCPIfaceData *      data = ifaces_arr->pdata[i];
        gs_free const char *uri  = NULL;
        char                sbuf[100];

        _LOGD("GCP interface[%" G_GSSIZE_FORMAT "]: retrieving configuration",
              data->intern_iface_idx);

        nm_sprintf_buf(sbuf, "%" G_GSSIZE_FORMAT "/mac", data->intern_iface_idx);

        get_config_data->n_pending++;
        nm_http_client_poll_get(NM_HTTP_CLIENT(source),
                                (uri = _gcp_uri_interfaces(sbuf)),
                                HTTP_TIMEOUT_MS,
                                HTTP_REQ_MAX_DATA,
                                HTTP_POLL_TIMEOUT_MS,
                                HTTP_RATE_LIMIT_MS,
                                NM_MAKE_STRV(NM_GCP_METADATA_HEADER),
                                get_config_data->intern_cancellable,
                                NULL,
                                NULL,
                                _get_config_iface_cb,
                                data);
    }

    get_config_data->extra_data         = g_steal_pointer(&ifaces_arr);
    get_config_data->extra_data_destroy = (GDestroyNotify) g_ptr_array_unref;
}

static void
get_config(NMCSProvider *provider, NMCSProviderGetConfigTaskData *get_config_data)
{
    gs_free const char *uri = NULL;

    nm_http_client_poll_get(nmcs_provider_get_http_client(provider),
                            (uri = _gcp_uri_interfaces()),
                            HTTP_TIMEOUT_MS,
                            HTTP_REQ_MAX_DATA,
                            HTTP_POLL_TIMEOUT_MS,
                            HTTP_RATE_LIMIT_MS,
                            NM_MAKE_STRV(NM_GCP_METADATA_HEADER),
                            get_config_data->intern_cancellable,
                            NULL,
                            NULL,
                            _get_net_ifaces_list_cb,
                            get_config_data);
}

/*****************************************************************************/

static void
nmcs_provider_gcp_init(NMCSProviderGCP *self)
{}

static void
nmcs_provider_gcp_class_init(NMCSProviderGCPClass *klass)
{
    NMCSProviderClass *provider_class = NMCS_PROVIDER_CLASS(klass);

    provider_class->_name                 = "GCP";
    provider_class->_env_provider_enabled = NMCS_ENV_VARIABLE("NM_CLOUD_SETUP_GCP");
    provider_class->detect                = detect;
    provider_class->get_config            = get_config;
}
