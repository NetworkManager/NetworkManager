/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libnm-client-aux-extern/nm-default-client.h"

#include "nmcs-provider-aliyun.h"

#include <arpa/inet.h>

#include "nm-cloud-setup-utils.h"

/*****************************************************************************/

#define HTTP_TIMEOUT_MS 3000

#define NM_ALIYUN_HOST              "100.100.100.200"
#define NM_ALIYUN_BASE              "http://" NM_ALIYUN_HOST
#define NM_ALIYUN_API_VERSION       "2016-01-01"
#define NM_ALIYUN_METADATA_URL_BASE /* $NM_ALIYUN_BASE/$NM_ALIYUN_API_VERSION */ \
    "/meta-data/network/interfaces/macs/"

NMCS_DEFINE_HOST_BASE(_aliyun_base, NMCS_ENV_NM_CLOUD_SETUP_ALIYUN_HOST, NM_ALIYUN_HOST);

#define _aliyun_uri_concat(...) nmcs_utils_uri_build_concat(_aliyun_base(), __VA_ARGS__)
#define _aliyun_uri_interfaces(...) \
    _aliyun_uri_concat(NM_ALIYUN_API_VERSION, NM_ALIYUN_METADATA_URL_BASE, ##__VA_ARGS__)

/*****************************************************************************/

struct _NMCSProviderAliyun {
    NMCSProvider parent;
};

struct _NMCSProviderAliyunClass {
    NMCSProviderClass parent;
};

G_DEFINE_TYPE(NMCSProviderAliyun, nmcs_provider_aliyun, NMCS_TYPE_PROVIDER);

/*****************************************************************************/

static void
filter_chars(char *str, const char *chars)
{
    gsize i;
    gsize j;

    for (i = 0, j = 0; str[i]; i++) {
        if (!strchr(chars, str[i]))
            str[j++] = str[i];
    }
    str[j] = '\0';
}

static void
_detect_get_meta_data_done_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    gs_unref_object GTask *task      = user_data;
    gs_free_error GError  *get_error = NULL;
    gs_free_error GError  *error     = NULL;

    nm_http_client_poll_req_finish(NM_HTTP_CLIENT(source), result, NULL, NULL, &get_error);

    if (nm_utils_error_is_cancelled(get_error)) {
        g_task_return_error(task, g_steal_pointer(&get_error));
        return;
    }

    if (get_error) {
        nm_utils_error_set(&error,
                           NM_UTILS_ERROR_UNKNOWN,
                           "failure to get ALIYUN metadata: %s",
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

    nm_http_client_poll_req(http_client,
                            (uri = _aliyun_uri_concat(NM_ALIYUN_API_VERSION "/meta-data/")),
                            HTTP_TIMEOUT_MS,
                            256 * 1024,
                            7000,
                            1000,
                            NULL,
                            NULL,
                            g_task_get_cancellable(task),
                            NULL,
                            NULL,
                            _detect_get_meta_data_done_cb,
                            task);
}

/*****************************************************************************/

typedef enum {
    GET_CONFIG_FETCH_DONE_TYPE_SUBNET_VPC_CIDR_BLOCK,
    GET_CONFIG_FETCH_DONE_TYPE_PRIVATE_IPV4S,
    GET_CONFIG_FETCH_DONE_TYPE_PRIMARY_IP_ADDRESS,
    GET_CONFIG_FETCH_DONE_TYPE_NETMASK,
    GET_CONFIG_FETCH_DONE_TYPE_GATEWAY,
} GetConfigFetchDoneType;

static void
_get_config_fetch_done_cb(NMHttpClient                   *http_client,
                          GAsyncResult                   *result,
                          NMCSProviderGetConfigIfaceData *config_iface_data,
                          GetConfigFetchDoneType          fetch_type)
{
    gs_unref_bytes GBytes *response = NULL;
    gs_free_error GError  *error    = NULL;
    in_addr_t              tmp_addr;
    int                    tmp_prefix;
    in_addr_t              netmask_bin;
    in_addr_t              gateway_bin;
    gs_free const char   **s_addrs = NULL;
    gsize                  i;
    gsize                  len;

    nm_http_client_poll_req_finish(http_client, result, NULL, &response, &error);

    if (nm_utils_error_is_cancelled(error))
        return;

    if (error)
        goto out;

    switch (fetch_type) {
    case GET_CONFIG_FETCH_DONE_TYPE_PRIVATE_IPV4S:

        s_addrs = nm_strsplit_set_full(g_bytes_get_data(response, NULL),
                                       ",",
                                       NM_STRSPLIT_SET_FLAGS_STRSTRIP);
        len     = NM_PTRARRAY_LEN(s_addrs);
        nm_assert(!config_iface_data->has_ipv4s);
        nm_assert(!config_iface_data->ipv4s_arr);
        config_iface_data->has_ipv4s = TRUE;
        config_iface_data->ipv4s_len = 0;
        if (len > 0) {
            config_iface_data->ipv4s_arr = g_new(in_addr_t, len);
            for (i = 0; i < len; i++) {
                filter_chars((char *) s_addrs[i], "[]\"");
                if (nm_inet_parse_bin(AF_INET, s_addrs[i], NULL, &tmp_addr)) {
                    config_iface_data->ipv4s_arr[config_iface_data->ipv4s_len++] = tmp_addr;
                }
            }
        }
        break;

    case GET_CONFIG_FETCH_DONE_TYPE_PRIMARY_IP_ADDRESS:

        if (nm_inet_parse_bin(AF_INET, g_bytes_get_data(response, NULL), NULL, &tmp_addr)) {
            nm_assert(config_iface_data->priv.aliyun.primary_ip_address == 0);
            nm_assert(!config_iface_data->priv.aliyun.has_primary_ip_address);
            config_iface_data->priv.aliyun.primary_ip_address     = tmp_addr;
            config_iface_data->priv.aliyun.has_primary_ip_address = TRUE;
        }
        break;

    case GET_CONFIG_FETCH_DONE_TYPE_SUBNET_VPC_CIDR_BLOCK:

        if (nm_inet_parse_with_prefix_bin(AF_INET,
                                          g_bytes_get_data(response, NULL),
                                          NULL,
                                          &tmp_addr,
                                          &tmp_prefix)) {
            nm_assert(!config_iface_data->has_cidr);
            config_iface_data->has_cidr  = TRUE;
            config_iface_data->cidr_addr = tmp_addr;
        }
        break;

    case GET_CONFIG_FETCH_DONE_TYPE_NETMASK:

        if (nm_inet_parse_bin(AF_INET, g_bytes_get_data(response, NULL), NULL, &netmask_bin)) {
            config_iface_data->cidr_prefix = nm_ip4_addr_netmask_to_prefix(netmask_bin);
        };
        break;

    case GET_CONFIG_FETCH_DONE_TYPE_GATEWAY:

        if (nm_inet_parse_bin(AF_INET, g_bytes_get_data(response, NULL), NULL, &gateway_bin)) {
            config_iface_data->has_gateway = TRUE;
            config_iface_data->gateway     = gateway_bin;
        };
        break;
    }

    if (!config_iface_data->priv.aliyun.ipv4s_arr_ordered
        && config_iface_data->priv.aliyun.has_primary_ip_address
        && config_iface_data->ipv4s_len > 0) {
        for (i = 0; i < config_iface_data->ipv4s_len; i++) {
            if (config_iface_data->ipv4s_arr[i]
                != config_iface_data->priv.aliyun.primary_ip_address)
                continue;
            if (i > 0) {
                /* OK, at position [i] we found the primary address.
                 * Move the elements from [0..(i-1)] to [1..i] and then set [0]. */
                memmove(&config_iface_data->ipv4s_arr[1],
                        &config_iface_data->ipv4s_arr[0],
                        i * sizeof(in_addr_t));
                config_iface_data->ipv4s_arr[0] = config_iface_data->priv.aliyun.primary_ip_address;
            }
            break;
        }
        config_iface_data->priv.aliyun.ipv4s_arr_ordered = TRUE;
    }

out:
    config_iface_data->get_config_data->n_pending--;
    _nmcs_provider_get_config_task_maybe_return(config_iface_data->get_config_data,
                                                g_steal_pointer(&error));
}

static void
_get_config_fetch_done_cb_vpc_cidr_block(GObject *source, GAsyncResult *result, gpointer user_data)
{
    _get_config_fetch_done_cb(NM_HTTP_CLIENT(source),
                              result,
                              user_data,
                              GET_CONFIG_FETCH_DONE_TYPE_SUBNET_VPC_CIDR_BLOCK);
}

static void
_get_config_fetch_done_cb_private_ipv4s(GObject *source, GAsyncResult *result, gpointer user_data)
{
    _get_config_fetch_done_cb(NM_HTTP_CLIENT(source),
                              result,
                              user_data,
                              GET_CONFIG_FETCH_DONE_TYPE_PRIVATE_IPV4S);
}

static void
_get_config_fetch_done_cb_primary_ip_address(GObject      *source,
                                             GAsyncResult *result,
                                             gpointer      user_data)
{
    _get_config_fetch_done_cb(NM_HTTP_CLIENT(source),
                              result,
                              user_data,
                              GET_CONFIG_FETCH_DONE_TYPE_PRIMARY_IP_ADDRESS);
}

static void
_get_config_fetch_done_cb_netmask(GObject *source, GAsyncResult *result, gpointer user_data)
{
    _get_config_fetch_done_cb(NM_HTTP_CLIENT(source),
                              result,
                              user_data,
                              GET_CONFIG_FETCH_DONE_TYPE_NETMASK);
}

static void
_get_config_fetch_done_cb_gateway(GObject *source, GAsyncResult *result, gpointer user_data)
{
    _get_config_fetch_done_cb(NM_HTTP_CLIENT(source),
                              result,
                              user_data,
                              GET_CONFIG_FETCH_DONE_TYPE_GATEWAY);
}

typedef struct {
    gssize iface_idx;
    char   path[0];
} GetConfigMetadataMac;

static void
_get_config_metadata_ready_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    NMCSProviderGetConfigTaskData *get_config_data;
    gs_unref_hashtable GHashTable *response_parsed = NULL;
    gs_free_error GError          *error           = NULL;
    GetConfigMetadataMac          *v_mac_data;
    const char                    *v_hwaddr;
    GHashTableIter                 h_iter;
    NMHttpClient                  *http_client;

    nm_http_client_poll_req_finish(NM_HTTP_CLIENT(source), result, NULL, NULL, &error);

    if (nm_utils_error_is_cancelled(error))
        return;

    get_config_data = user_data;

    response_parsed                     = g_steal_pointer(&get_config_data->extra_data);
    get_config_data->extra_data_destroy = NULL;

    /* We ignore errors. Only if we got no response at all, it's a problem.
     * Otherwise, we proceed with whatever we could fetch. */
    if (!response_parsed) {
        _nmcs_provider_get_config_task_maybe_return(
            get_config_data,
            nm_utils_error_new(NM_UTILS_ERROR_UNKNOWN, "meta data for interfaces not found"));
        return;
    }

    http_client = nmcs_provider_get_http_client(g_task_get_source_object(get_config_data->task));

    g_hash_table_iter_init(&h_iter, response_parsed);
    while (g_hash_table_iter_next(&h_iter, (gpointer *) &v_hwaddr, (gpointer *) &v_mac_data)) {
        NMCSProviderGetConfigIfaceData *config_iface_data;
        gs_free char                   *uri1 = NULL;
        gs_free char                   *uri2 = NULL;
        gs_free char                   *uri3 = NULL;
        gs_free char                   *uri4 = NULL;
        gs_free char                   *uri5 = NULL;

        config_iface_data = g_hash_table_lookup(get_config_data->result_dict, v_hwaddr);

        if (!config_iface_data) {
            if (!get_config_data->any) {
                _LOGD("get-config: skip fetching meta data for %s (%s)",
                      v_hwaddr,
                      v_mac_data->path);
                continue;
            }

            config_iface_data =
                nmcs_provider_get_config_iface_data_create(get_config_data, FALSE, v_hwaddr);
        }

        nm_assert(config_iface_data->iface_idx == -1);

        config_iface_data->iface_idx = v_mac_data->iface_idx;

        _LOGD("get-config: start fetching meta data for #%" G_GSSIZE_FORMAT ", %s (%s)",
              config_iface_data->iface_idx,
              config_iface_data->hwaddr,
              v_mac_data->path);

        get_config_data->n_pending++;
        nm_http_client_poll_req(
            http_client,
            (uri1 = _aliyun_uri_interfaces(v_mac_data->path,
                                           NM_STR_HAS_SUFFIX(v_mac_data->path, "/") ? "" : "/",
                                           "vpc-cidr-block")),
            HTTP_TIMEOUT_MS,
            512 * 1024,
            10000,
            1000,
            NULL,
            NULL,
            get_config_data->intern_cancellable,
            NULL,
            NULL,
            _get_config_fetch_done_cb_vpc_cidr_block,
            config_iface_data);

        get_config_data->n_pending++;
        nm_http_client_poll_req(
            http_client,
            (uri2 = _aliyun_uri_interfaces(v_mac_data->path,
                                           NM_STR_HAS_SUFFIX(v_mac_data->path, "/") ? "" : "/",
                                           "private-ipv4s")),
            HTTP_TIMEOUT_MS,
            512 * 1024,
            10000,
            1000,
            NULL,
            NULL,
            get_config_data->intern_cancellable,
            NULL,
            NULL,
            _get_config_fetch_done_cb_private_ipv4s,
            config_iface_data);

        get_config_data->n_pending++;
        nm_http_client_poll_req(
            http_client,
            (uri3 = _aliyun_uri_interfaces(v_mac_data->path,
                                           NM_STR_HAS_SUFFIX(v_mac_data->path, "/") ? "" : "/",
                                           "primary-ip-address")),
            HTTP_TIMEOUT_MS,
            512 * 1024,
            10000,
            1000,
            NULL,
            NULL,
            get_config_data->intern_cancellable,
            NULL,
            NULL,
            _get_config_fetch_done_cb_primary_ip_address,
            config_iface_data);

        get_config_data->n_pending++;
        nm_http_client_poll_req(
            http_client,
            (uri4 = _aliyun_uri_interfaces(v_mac_data->path,
                                           NM_STR_HAS_SUFFIX(v_mac_data->path, "/") ? "" : "/",
                                           "netmask")),
            HTTP_TIMEOUT_MS,
            512 * 1024,
            10000,
            1000,
            NULL,
            NULL,
            get_config_data->intern_cancellable,
            NULL,
            NULL,
            _get_config_fetch_done_cb_netmask,
            config_iface_data);

        get_config_data->n_pending++;
        nm_http_client_poll_req(
            http_client,
            (uri5 = _aliyun_uri_interfaces(v_mac_data->path,
                                           NM_STR_HAS_SUFFIX(v_mac_data->path, "/") ? "" : "/",
                                           "gateway")),
            HTTP_TIMEOUT_MS,
            512 * 1024,
            10000,
            1000,
            NULL,
            NULL,
            get_config_data->intern_cancellable,
            NULL,
            NULL,
            _get_config_fetch_done_cb_gateway,
            config_iface_data);
    }

    _nmcs_provider_get_config_task_maybe_return(get_config_data, NULL);
}

static gboolean
_get_config_metadata_ready_check(long     response_code,
                                 GBytes  *response,
                                 gpointer check_user_data,
                                 GError **error)
{
    NMCSProviderGetConfigTaskData *get_config_data = check_user_data;
    gs_unref_hashtable GHashTable *response_parsed = NULL;
    const guint8                  *r_data;
    const char                    *cur_line;
    gsize                          r_len;
    gsize                          cur_line_len;
    GHashTableIter                 h_iter;
    gboolean                       has_all;
    const char                    *c_hwaddr;
    gssize                         iface_idx_counter = 0;

    if (response_code != 200 || !response) {
        /* we wait longer. */
        return FALSE;
    }

    r_data = g_bytes_get_data(response, &r_len);
    /* NMHttpClient guarantees that there is a trailing NUL after the data. */
    nm_assert(r_data[r_len] == 0);

    while (nm_utils_parse_next_line((const char **) &r_data, &r_len, &cur_line, &cur_line_len)) {
        GetConfigMetadataMac *mac_data;
        char                 *hwaddr;

        if (cur_line_len == 0)
            continue;

        /* Truncate the string. It's safe to do, because we own @response an it has an
         * extra NUL character after the buffer. */
        ((char *) cur_line)[cur_line_len] = '\0';

        hwaddr = nmcs_utils_hwaddr_normalize(
            cur_line,
            cur_line[cur_line_len - 1u] == '/' ? (gssize) (cur_line_len - 1u) : -1);
        if (!hwaddr)
            continue;

        if (!response_parsed)
            response_parsed = g_hash_table_new_full(nm_str_hash, g_str_equal, g_free, g_free);

        mac_data            = g_malloc(sizeof(GetConfigMetadataMac) + 1u + cur_line_len);
        mac_data->iface_idx = iface_idx_counter++;
        memcpy(mac_data->path, cur_line, cur_line_len + 1u);

        /* here we will ignore duplicate responses. */
        g_hash_table_insert(response_parsed, hwaddr, mac_data);
    }

    has_all = TRUE;
    g_hash_table_iter_init(&h_iter, get_config_data->result_dict);
    while (g_hash_table_iter_next(&h_iter, (gpointer *) &c_hwaddr, NULL)) {
        if (!response_parsed || !g_hash_table_contains(response_parsed, c_hwaddr)) {
            has_all = FALSE;
            break;
        }
    }

    nm_clear_pointer(&get_config_data->extra_data, g_hash_table_unref);
    if (response_parsed) {
        get_config_data->extra_data         = g_steal_pointer(&response_parsed);
        get_config_data->extra_data_destroy = (GDestroyNotify) g_hash_table_unref;
    }
    return has_all;
}

static void
get_config(NMCSProvider *provider, NMCSProviderGetConfigTaskData *get_config_data)
{
    gs_free char *uri = NULL;

    /* First we fetch the "macs/". If the caller requested some particular
     * MAC addresses, then we poll until we see them. They might not yet be
     * around from the start...
     */
    nm_http_client_poll_req(nmcs_provider_get_http_client(provider),
                            (uri = _aliyun_uri_interfaces()),
                            HTTP_TIMEOUT_MS,
                            256 * 1024,
                            15000,
                            1000,
                            NULL,
                            NULL,
                            get_config_data->intern_cancellable,
                            _get_config_metadata_ready_check,
                            get_config_data,
                            _get_config_metadata_ready_cb,
                            get_config_data);
}

/*****************************************************************************/

static void
nmcs_provider_aliyun_init(NMCSProviderAliyun *self)
{}

static void
nmcs_provider_aliyun_class_init(NMCSProviderAliyunClass *klass)
{
    NMCSProviderClass *provider_class = NMCS_PROVIDER_CLASS(klass);

    provider_class->_name                 = "aliyun";
    provider_class->_env_provider_enabled = NMCS_ENV_NM_CLOUD_SETUP_ALIYUN;
    provider_class->detect                = detect;
    provider_class->get_config            = get_config;
}
