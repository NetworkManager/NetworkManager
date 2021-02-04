/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libnm/nm-default-client.h"

#include "nmcs-provider-azure.h"

#include "nm-cloud-setup-utils.h"

/*****************************************************************************/

#define HTTP_TIMEOUT_MS 3000

#define NM_AZURE_METADATA_HEADER   "Metadata:true"
#define NM_AZURE_HOST              "169.254.169.254"
#define NM_AZURE_BASE              "http://" NM_AZURE_HOST
#define NM_AZURE_API_VERSION       "?format=text&api-version=2017-04-02"
#define NM_AZURE_METADATA_URL_BASE /* $NM_AZURE_BASE/$NM_AZURE_API_VERSION */ \
    "/metadata/instance/network/interface/"

#define _azure_uri_concat(...) \
    nmcs_utils_uri_build_concat(NM_AZURE_BASE, __VA_ARGS__, NM_AZURE_API_VERSION)
#define _azure_uri_interfaces(...) _azure_uri_concat(NM_AZURE_METADATA_URL_BASE, ##__VA_ARGS__)

/*****************************************************************************/

struct _NMCSProviderAzure {
    NMCSProvider parent;
};

struct _NMCSProviderAzureClass {
    NMCSProviderClass parent;
};

G_DEFINE_TYPE(NMCSProviderAzure, nmcs_provider_azure, NMCS_TYPE_PROVIDER);

/*****************************************************************************/

static void
_detect_get_meta_data_done_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    gs_unref_object GTask *task     = user_data;
    gs_free_error GError *get_error = NULL;
    gs_free_error GError *error     = NULL;
    gboolean              success;

    success =
        nm_http_client_poll_get_finish(NM_HTTP_CLIENT(source), result, NULL, NULL, &get_error);

    if (nm_utils_error_is_cancelled(get_error)) {
        g_task_return_error(task, g_steal_pointer(&get_error));
        return;
    }

    if (get_error) {
        nm_utils_error_set(&error,
                           NM_UTILS_ERROR_UNKNOWN,
                           "failure to get Azure metadata: %s",
                           get_error->message);
        g_task_return_error(task, g_steal_pointer(&error));
        return;
    }

    if (!success) {
        nm_utils_error_set(&error, NM_UTILS_ERROR_UNKNOWN, "failure to detect azure metadata");
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
                            (uri = _azure_uri_concat("/metadata/instance")),
                            HTTP_TIMEOUT_MS,
                            256 * 1024,
                            7000,
                            1000,
                            NM_MAKE_STRV(NM_AZURE_METADATA_HEADER),
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
    guint                           n_ips_prefix_pending;
    const char *                    hwaddr;
} AzureIfaceData;

static void
_azure_iface_data_destroy(AzureIfaceData *iface_data)
{
    nm_g_slice_free(iface_data);
}

static void
_get_config_fetch_done_cb(NMHttpClient *  http_client,
                          GAsyncResult *  result,
                          AzureIfaceData *iface_data,
                          gboolean        is_ipv4)
{
    NMCSProviderGetConfigTaskData * get_config_data;
    NMCSProviderGetConfigIfaceData *iface_get_config;
    gs_unref_bytes GBytes *response = NULL;
    gs_free_error GError *error     = NULL;
    const char *          fip_str   = NULL;
    gsize                 fip_len;

    nm_http_client_poll_get_finish(http_client, result, NULL, &response, &error);

    if (nm_utils_error_is_cancelled(error))
        return;

    get_config_data = iface_data->get_config_data;

    if (error)
        goto out_done;

    fip_str = g_bytes_get_data(response, &fip_len);
    nm_assert(fip_str[fip_len] == '\0');

    iface_data->iface_get_config =
        g_hash_table_lookup(get_config_data->result_dict, iface_data->hwaddr);
    iface_get_config = iface_data->iface_get_config;

    if (is_ipv4) {
        char      tmp_addr_str[NM_UTILS_INET_ADDRSTRLEN];
        in_addr_t tmp_addr;

        if (!nmcs_utils_ipaddr_normalize_bin(AF_INET, fip_str, fip_len, NULL, &tmp_addr)) {
            error =
                nm_utils_error_new(NM_UTILS_ERROR_UNKNOWN, "ip is not a valid private ip address");
            goto out_done;
        }
        _LOGD("interface[%" G_GSSIZE_FORMAT "]: adding private ip %s",
              iface_data->intern_iface_idx,
              _nm_utils_inet4_ntop(tmp_addr, tmp_addr_str));
        iface_get_config->ipv4s_arr[iface_get_config->ipv4s_len] = tmp_addr;
        iface_get_config->has_ipv4s                              = TRUE;
        iface_get_config->ipv4s_len++;
    } else {
        int tmp_prefix = -1;

        if (fip_len > 0 && memchr(fip_str, '\0', fip_len - 1)) {
            /* we have an embedded "\0" inside the string (except trailing). That is not
             * allowed*/
        } else
            tmp_prefix = _nm_utils_ascii_str_to_int64(fip_str, 10, 0, 32, -1);

        if (tmp_prefix == -1) {
            _LOGD("interface[%" G_GSSIZE_FORMAT "]: invalid prefix", iface_data->intern_iface_idx);
            error =
                nm_utils_error_new(NM_UTILS_ERROR_UNKNOWN, "subnet does not give a valid prefix");
            goto out_done;
        }

        _LOGD("interface[%" G_GSSIZE_FORMAT "]: adding prefix %d",
              iface_data->intern_iface_idx,
              tmp_prefix);
        iface_get_config->cidr_prefix = tmp_prefix;
        iface_get_config->has_cidr    = TRUE;
    }

out_done:
    if (!error) {
        --iface_data->n_ips_prefix_pending;
        if (iface_data->n_ips_prefix_pending > 0)
            return;
    }

    --get_config_data->n_pending;
    _nmcs_provider_get_config_task_maybe_return(get_config_data, g_steal_pointer(&error));
}

static void
_get_config_fetch_done_cb_private_ipv4s(GObject *source, GAsyncResult *result, gpointer user_data)
{
    _get_config_fetch_done_cb(NM_HTTP_CLIENT(source), result, user_data, TRUE);
}

static void
_get_config_fetch_done_cb_subnet_cidr_prefix(GObject *     source,
                                             GAsyncResult *result,
                                             gpointer      user_data)
{
    _get_config_fetch_done_cb(NM_HTTP_CLIENT(source), result, user_data, FALSE);
}

static void
_get_config_ips_prefix_list_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    gs_unref_bytes GBytes *response             = NULL;
    AzureIfaceData *       iface_data           = user_data;
    gs_free_error GError *         error        = NULL;
    const char *                   response_str = NULL;
    gsize                          response_len;
    NMCSProviderGetConfigTaskData *get_config_data;
    const char *                   line;
    gsize                          line_len;

    nm_http_client_poll_get_finish(NM_HTTP_CLIENT(source), result, NULL, &response, &error);

    if (nm_utils_error_is_cancelled(error))
        return;

    get_config_data = iface_data->get_config_data;

    if (error)
        goto out_error;

    response_str = g_bytes_get_data(response, &response_len);
    /* NMHttpClient guarantees that there is a trailing NUL after the data. */
    nm_assert(response_str[response_len] == 0);

    nm_assert(!iface_data->iface_get_config->has_ipv4s);
    nm_assert(!iface_data->iface_get_config->ipv4s_arr);
    nm_assert(!iface_data->iface_get_config->has_cidr);

    while (nm_utils_parse_next_line(&response_str, &response_len, &line, &line_len)) {
        gint64 ips_prefix_idx;

        if (line_len == 0)
            continue;
        /* Truncate the string. It's safe to do, because we own @response an it has an
         * extra NULL character after the buffer. */
        ((char *) line)[line_len] = '\0';

        if (line[line_len - 1] == '/')
            ((char *) line)[--line_len] = '\0';

        ips_prefix_idx = _nm_utils_ascii_str_to_int64(line, 10, 0, G_MAXINT64, -1);

        if (ips_prefix_idx < 0)
            continue;

        {
            gs_free const char *uri = NULL;
            char                buf[100];

            iface_data->n_ips_prefix_pending++;

            nm_http_client_poll_get(
                NM_HTTP_CLIENT(source),
                (uri = _azure_uri_interfaces(nm_sprintf_buf(
                     buf,
                     "%" G_GSSIZE_FORMAT "/ipv4/ipAddress/%" G_GINT64_FORMAT "/privateIpAddress",
                     iface_data->intern_iface_idx,
                     ips_prefix_idx))),
                HTTP_TIMEOUT_MS,
                512 * 1024,
                10000,
                1000,
                NM_MAKE_STRV(NM_AZURE_METADATA_HEADER),
                get_config_data->intern_cancellable,
                NULL,
                NULL,
                _get_config_fetch_done_cb_private_ipv4s,
                iface_data);
        }
    }

    iface_data->iface_get_config->ipv4s_len = 0;
    iface_data->iface_get_config->ipv4s_arr = g_new(in_addr_t, iface_data->n_ips_prefix_pending);

    {
        gs_free const char *uri = NULL;
        char                buf[30];

        iface_data->n_ips_prefix_pending++;
        nm_http_client_poll_get(
            NM_HTTP_CLIENT(source),
            (uri = _azure_uri_interfaces(
                 nm_sprintf_buf(buf, "%" G_GSSIZE_FORMAT, iface_data->intern_iface_idx),
                 "/ipv4/subnet/0/prefix/")),
            HTTP_TIMEOUT_MS,
            512 * 1024,
            10000,
            1000,
            NM_MAKE_STRV(NM_AZURE_METADATA_HEADER),
            get_config_data->intern_cancellable,
            NULL,
            NULL,
            _get_config_fetch_done_cb_subnet_cidr_prefix,
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
    NMCSProviderGetConfigTaskData *get_config_data;
    gs_unref_bytes GBytes *response   = NULL;
    AzureIfaceData *       iface_data = user_data;
    gs_free char *         v_hwaddr   = NULL;
    gs_free_error GError *error       = NULL;
    gs_free const char *  uri         = NULL;
    char                  buf[100];

    nm_http_client_poll_get_finish(NM_HTTP_CLIENT(source), result, NULL, &response, &error);

    if (nm_utils_error_is_cancelled(error))
        return;

    get_config_data = iface_data->get_config_data;

    if (error)
        goto out_done;

    v_hwaddr = nmcs_utils_hwaddr_normalize_gbytes(response);
    if (!v_hwaddr) {
        _LOGI("interface[%" G_GSSIZE_FORMAT "]: invalid MAC address returned",
              iface_data->intern_iface_idx);
        error = nm_utils_error_new(NM_UTILS_ERROR_UNKNOWN,
                                   "invalid MAC address for index %" G_GSSIZE_FORMAT,
                                   iface_data->intern_iface_idx);
        goto out_done;
    }

    if (!g_hash_table_lookup_extended(get_config_data->result_dict,
                                      v_hwaddr,
                                      (gpointer *) &iface_data->hwaddr,
                                      (gpointer *) &iface_data->iface_get_config)) {
        if (!get_config_data->any) {
            _LOGD("get-config: skip fetching meta data for %s (%" G_GSSIZE_FORMAT ")",
                  v_hwaddr,
                  iface_data->intern_iface_idx);
            goto out_done;
        }
        iface_data->iface_get_config = nmcs_provider_get_config_iface_data_new(FALSE);
        g_hash_table_insert(get_config_data->result_dict,
                            (char *) (iface_data->hwaddr = g_steal_pointer(&v_hwaddr)),
                            iface_data->iface_get_config);
    } else {
        if (iface_data->iface_get_config->iface_idx >= 0) {
            _LOGI("interface[%" G_GSSIZE_FORMAT "]: duplicate MAC address %s returned",
                  iface_data->intern_iface_idx,
                  iface_data->hwaddr);
            error = nm_utils_error_new(NM_UTILS_ERROR_UNKNOWN,
                                       "duplicate MAC address for index %" G_GSSIZE_FORMAT,
                                       iface_data->intern_iface_idx);
            goto out_done;
        }
    }

    iface_data->iface_get_config->iface_idx = iface_data->extern_iface_idx;

    _LOGD("interface[%" G_GSSIZE_FORMAT "]: found a matching device with hwaddr %s",
          iface_data->intern_iface_idx,
          iface_data->hwaddr);

    nm_sprintf_buf(buf, "%" G_GSSIZE_FORMAT "/ipv4/ipAddress/", iface_data->intern_iface_idx);

    nm_http_client_poll_get(NM_HTTP_CLIENT(source),
                            (uri = _azure_uri_interfaces(buf)),
                            HTTP_TIMEOUT_MS,
                            512 * 1024,
                            10000,
                            1000,
                            NM_MAKE_STRV(NM_AZURE_METADATA_HEADER),
                            get_config_data->intern_cancellable,
                            NULL,
                            NULL,
                            _get_config_ips_prefix_list_cb,
                            iface_data);
    return;

out_done:
    --get_config_data->n_pending;
    _nmcs_provider_get_config_task_maybe_return(get_config_data, g_steal_pointer(&error));
}

static void
_get_net_ifaces_list_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    NMCSProviderGetConfigTaskData *get_config_data;
    gs_unref_ptrarray GPtrArray *ifaces_arr = NULL;
    gs_unref_bytes GBytes *response         = NULL;
    gs_free_error GError *error             = NULL;
    const char *          response_str;
    gsize                 response_len;
    const char *          line;
    gsize                 line_len;
    guint                 i;
    gssize                extern_iface_idx_cnt = 0;

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

    ifaces_arr = g_ptr_array_new_with_free_func((GDestroyNotify) _azure_iface_data_destroy);

    while (nm_utils_parse_next_line(&response_str, &response_len, &line, &line_len)) {
        AzureIfaceData *iface_data;
        gssize          intern_iface_idx;

        if (line_len == 0)
            continue;

        /* Truncate the string. It's safe to do, because we own @response an it has an
         * extra NULL character after the buffer. */
        ((char *) line)[line_len] = '\0';

        if (line[line_len - 1] == '/' && line_len != 0)
            ((char *) line)[--line_len] = '\0';

        intern_iface_idx = _nm_utils_ascii_str_to_int64(line, 10, 0, G_MAXSSIZE, -1);
        if (intern_iface_idx < 0)
            continue;

        iface_data  = g_slice_new(AzureIfaceData);
        *iface_data = (AzureIfaceData){
            .get_config_data      = get_config_data,
            .iface_get_config     = NULL,
            .intern_iface_idx     = intern_iface_idx,
            .extern_iface_idx     = extern_iface_idx_cnt++,
            .n_ips_prefix_pending = 0,
            .hwaddr               = NULL,
        };
        g_ptr_array_add(ifaces_arr, iface_data);
    }

    _LOGD("found azure interfaces: %u", ifaces_arr->len);

    if (ifaces_arr->len == 0) {
        _nmcs_provider_get_config_task_maybe_return(
            get_config_data,
            nm_utils_error_new(NM_UTILS_ERROR_UNKNOWN, "no Azure interfaces found"));
        return;
    }

    for (i = 0; i < ifaces_arr->len; ++i) {
        AzureIfaceData *    iface_data = ifaces_arr->pdata[i];
        gs_free const char *uri        = NULL;
        char                buf[100];

        _LOGD("azure interface[%" G_GSSIZE_FORMAT "]: retrieving configuration",
              iface_data->intern_iface_idx);

        nm_sprintf_buf(buf, "%" G_GSSIZE_FORMAT "/macAddress", iface_data->intern_iface_idx);

        get_config_data->n_pending++;
        nm_http_client_poll_get(NM_HTTP_CLIENT(source),
                                (uri = _azure_uri_interfaces(buf)),
                                HTTP_TIMEOUT_MS,
                                512 * 1024,
                                10000,
                                1000,
                                NM_MAKE_STRV(NM_AZURE_METADATA_HEADER),
                                get_config_data->intern_cancellable,
                                NULL,
                                NULL,
                                _get_config_iface_cb,
                                iface_data);
    }

    get_config_data->extra_data_destroy = (GDestroyNotify) g_ptr_array_unref;
    get_config_data->extra_data         = g_steal_pointer(&ifaces_arr);
}

static void
get_config(NMCSProvider *provider, NMCSProviderGetConfigTaskData *get_config_data)
{
    gs_free const char *uri = NULL;

    nm_http_client_poll_get(nmcs_provider_get_http_client(provider),
                            (uri = _azure_uri_interfaces()),
                            HTTP_TIMEOUT_MS,
                            256 * 1024,
                            15000,
                            1000,
                            NM_MAKE_STRV(NM_AZURE_METADATA_HEADER),
                            get_config_data->intern_cancellable,
                            NULL,
                            NULL,
                            _get_net_ifaces_list_cb,
                            get_config_data);
}

/*****************************************************************************/

static void
nmcs_provider_azure_init(NMCSProviderAzure *self)
{}

static void
nmcs_provider_azure_class_init(NMCSProviderAzureClass *klass)
{
    NMCSProviderClass *provider_class = NMCS_PROVIDER_CLASS(klass);

    provider_class->_name                 = "azure";
    provider_class->_env_provider_enabled = NMCS_ENV_VARIABLE("NM_CLOUD_SETUP_AZURE");
    provider_class->detect                = detect;
    provider_class->get_config            = get_config;
}
