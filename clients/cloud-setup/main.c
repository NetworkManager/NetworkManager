/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libnm/nm-default-client.h"

#include "nm-libnm-aux/nm-libnm-aux.h"

#include "nm-cloud-setup-utils.h"
#include "nmcs-provider-ec2.h"
#include "nmcs-provider-gcp.h"
#include "nmcs-provider-azure.h"
#include "nm-libnm-core-intern/nm-libnm-core-utils.h"

/*****************************************************************************/

typedef struct {
    GMainLoop *   main_loop;
    GCancellable *cancellable;
    NMCSProvider *provider_result;
    guint         detect_count;
} ProviderDetectData;

static void
_provider_detect_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    gs_unref_object NMCSProvider *provider = NMCS_PROVIDER(source);
    gs_free_error GError *error            = NULL;
    ProviderDetectData *  dd;
    gboolean              success;

    success = nmcs_provider_detect_finish(provider, result, &error);

    nm_assert(success != (!!error));

    if (nm_utils_error_is_cancelled(error))
        return;

    dd = user_data;

    nm_assert(dd->detect_count > 0);
    dd->detect_count--;

    if (error) {
        _LOGI("provider %s not detected: %s", nmcs_provider_get_name(provider), error->message);
        if (dd->detect_count > 0) {
            /* wait longer. */
            return;
        }

        _LOGI("no provider detected");
        goto done;
    }

    _LOGI("provider %s detected", nmcs_provider_get_name(provider));
    dd->provider_result = g_steal_pointer(&provider);

done:
    g_cancellable_cancel(dd->cancellable);
    g_main_loop_quit(dd->main_loop);
}

static void
_provider_detect_sigterm_cb(GCancellable *source, gpointer user_data)
{
    ProviderDetectData *dd = user_data;

    g_cancellable_cancel(dd->cancellable);
    g_clear_object(&dd->provider_result);
    dd->detect_count = 0;
    g_main_loop_quit(dd->main_loop);
}

static NMCSProvider *
_provider_detect(GCancellable *sigterm_cancellable)
{
    nm_auto_unref_gmainloop GMainLoop *main_loop = g_main_loop_new(NULL, FALSE);
    gs_unref_object GCancellable *cancellable    = g_cancellable_new();
    gs_unref_object NMHttpClient *http_client    = NULL;
    ProviderDetectData            dd             = {
        .cancellable     = cancellable,
        .main_loop       = main_loop,
        .detect_count    = 0,
        .provider_result = NULL,
    };
    const GType gtypes[] = {
        NMCS_TYPE_PROVIDER_EC2,
        NMCS_TYPE_PROVIDER_GCP,
        NMCS_TYPE_PROVIDER_AZURE,
    };
    int    i;
    gulong cancellable_signal_id;

    cancellable_signal_id = g_cancellable_connect(sigterm_cancellable,
                                                  G_CALLBACK(_provider_detect_sigterm_cb),
                                                  &dd,
                                                  NULL);
    if (!cancellable_signal_id)
        goto out;

    http_client = nmcs_wait_for_objects_register(nm_http_client_new());

    for (i = 0; i < G_N_ELEMENTS(gtypes); i++) {
        NMCSProvider *provider;

        provider = g_object_new(gtypes[i], NMCS_PROVIDER_HTTP_CLIENT, http_client, NULL);
        nmcs_wait_for_objects_register(provider);

        _LOGD("start detecting %s provider...", nmcs_provider_get_name(provider));
        dd.detect_count++;
        nmcs_provider_detect(provider, cancellable, _provider_detect_cb, &dd);
    }

    if (dd.detect_count > 0)
        g_main_loop_run(main_loop);

out:
    nm_clear_g_signal_handler(sigterm_cancellable, &cancellable_signal_id);
    return dd.provider_result;
}

/*****************************************************************************/

static char **
_nmc_get_hwaddrs(NMClient *nmc)
{
    gs_unref_ptrarray GPtrArray *hwaddrs = NULL;
    const GPtrArray *            devices;
    char **                      hwaddrs_v;
    gs_free char *               str = NULL;
    guint                        i;

    devices = nm_client_get_devices(nmc);

    for (i = 0; i < devices->len; i++) {
        NMDevice *  device = devices->pdata[i];
        const char *hwaddr;
        char *      s;

        if (!NM_IS_DEVICE_ETHERNET(device))
            continue;

        if (nm_device_get_state(device) < NM_DEVICE_STATE_UNAVAILABLE)
            continue;

        hwaddr = nm_device_ethernet_get_permanent_hw_address(NM_DEVICE_ETHERNET(device));
        if (!hwaddr)
            continue;

        s = nmcs_utils_hwaddr_normalize(hwaddr, -1);
        if (!s)
            continue;

        if (!hwaddrs)
            hwaddrs = g_ptr_array_new_with_free_func(g_free);
        g_ptr_array_add(hwaddrs, s);
    }

    if (!hwaddrs) {
        _LOGD("found interfaces: none");
        return NULL;
    }

    g_ptr_array_add(hwaddrs, NULL);
    hwaddrs_v = (char **) g_ptr_array_free(g_steal_pointer(&hwaddrs), FALSE);

    _LOGD("found interfaces: %s", (str = g_strjoinv(", ", hwaddrs_v)));

    return hwaddrs_v;
}

static NMDevice *
_nmc_get_device_by_hwaddr(NMClient *nmc, const char *hwaddr)
{
    const GPtrArray *devices;
    guint            i;

    devices = nm_client_get_devices(nmc);

    for (i = 0; i < devices->len; i++) {
        NMDevice *    device = devices->pdata[i];
        const char *  hwaddr_dev;
        gs_free char *s = NULL;

        if (!NM_IS_DEVICE_ETHERNET(device))
            continue;

        hwaddr_dev = nm_device_ethernet_get_permanent_hw_address(NM_DEVICE_ETHERNET(device));
        if (!hwaddr_dev)
            continue;

        s = nmcs_utils_hwaddr_normalize(hwaddr_dev, -1);
        if (s && nm_streq(s, hwaddr))
            return device;
    }

    return NULL;
}

/*****************************************************************************/

typedef struct {
    GMainLoop * main_loop;
    GHashTable *config_dict;
} GetConfigData;

static void
_get_config_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    GetConfigData *    data                    = user_data;
    gs_unref_hashtable GHashTable *config_dict = NULL;
    gs_free_error GError *error                = NULL;

    config_dict = nmcs_provider_get_config_finish(NMCS_PROVIDER(source), result, &error);

    if (!config_dict) {
        if (!nm_utils_error_is_cancelled(error))
            _LOGI("failure to get meta data: %s", error->message);
    } else
        _LOGD("meta data received");

    data->config_dict = g_steal_pointer(&config_dict);
    g_main_loop_quit(data->main_loop);
}

static GHashTable *
_get_config(GCancellable *sigterm_cancellable, NMCSProvider *provider, NMClient *nmc)
{
    nm_auto_unref_gmainloop GMainLoop *main_loop = g_main_loop_new(NULL, FALSE);
    GetConfigData                      data      = {
        .main_loop = main_loop,
    };
    gs_strfreev char **hwaddrs = NULL;

    hwaddrs = _nmc_get_hwaddrs(nmc);

    nmcs_provider_get_config(provider,
                             TRUE,
                             (const char *const *) hwaddrs,
                             sigterm_cancellable,
                             _get_config_cb,
                             &data);

    g_main_loop_run(main_loop);

    return data.config_dict;
}

/*****************************************************************************/

static gboolean
_nmc_skip_connection(NMConnection *connection)
{
    NMSettingUser *s_user;
    const char *   v;

    s_user = NM_SETTING_USER(nm_connection_get_setting(connection, NM_TYPE_SETTING_USER));
    if (!s_user)
        return FALSE;

#define USER_TAG_SKIP "org.freedesktop.nm-cloud-setup.skip"

    nm_assert(nm_setting_user_check_key(USER_TAG_SKIP, NULL));

    v = nm_setting_user_get_data(s_user, USER_TAG_SKIP);
    return _nm_utils_ascii_str_to_bool(v, FALSE);
}

static gboolean
_nmc_mangle_connection(NMDevice *                            device,
                       NMConnection *                        connection,
                       const NMCSProviderGetConfigIfaceData *config_data,
                       gboolean *                            out_changed)
{
    NMSettingIPConfig *s_ip;
    gsize              i;
    in_addr_t          gateway;
    gint64             rt_metric;
    guint32            rt_table;
    NMIPRoute *        route_entry;
    gboolean           addrs_changed        = FALSE;
    gboolean           rules_changed        = FALSE;
    gboolean           routes_changed       = FALSE;
    gs_unref_ptrarray GPtrArray *addrs_new  = NULL;
    gs_unref_ptrarray GPtrArray *rules_new  = NULL;
    gs_unref_ptrarray GPtrArray *routes_new = NULL;

    if (!nm_streq0(nm_connection_get_connection_type(connection), NM_SETTING_WIRED_SETTING_NAME))
        return FALSE;

    s_ip = nm_connection_get_setting_ip4_config(connection);
    if (!s_ip)
        return FALSE;

    addrs_new = g_ptr_array_new_full(config_data->ipv4s_len, (GDestroyNotify) nm_ip_address_unref);
    rules_new =
        g_ptr_array_new_full(config_data->ipv4s_len, (GDestroyNotify) nm_ip_routing_rule_unref);
    routes_new = g_ptr_array_new_full(config_data->iproutes_len + !!config_data->ipv4s_len,
                                      (GDestroyNotify) nm_ip_route_unref);

    if (config_data->has_ipv4s && config_data->has_cidr) {
        for (i = 0; i < config_data->ipv4s_len; i++) {
            NMIPAddress *entry;

            entry = nm_ip_address_new_binary(AF_INET,
                                             &config_data->ipv4s_arr[i],
                                             config_data->cidr_prefix,
                                             NULL);
            if (entry)
                g_ptr_array_add(addrs_new, entry);
        }

        gateway = nm_utils_ip4_address_clear_host_address(config_data->cidr_addr,
                                                          config_data->cidr_prefix);
        ((guint8 *) &gateway)[3] += 1;

        rt_metric = 10;
        rt_table  = 30400 + config_data->iface_idx;

        route_entry =
            nm_ip_route_new_binary(AF_INET, &nm_ip_addr_zero, 0, &gateway, rt_metric, NULL);
        nm_ip_route_set_attribute(route_entry,
                                  NM_IP_ROUTE_ATTRIBUTE_TABLE,
                                  g_variant_new_uint32(rt_table));
        g_ptr_array_add(routes_new, route_entry);

        for (i = 0; i < config_data->ipv4s_len; i++) {
            NMIPRoutingRule *entry;
            char             sbuf[NM_UTILS_INET_ADDRSTRLEN];

            entry = nm_ip_routing_rule_new(AF_INET);
            nm_ip_routing_rule_set_priority(entry, rt_table);
            nm_ip_routing_rule_set_from(entry,
                                        _nm_utils_inet4_ntop(config_data->ipv4s_arr[i], sbuf),
                                        32);
            nm_ip_routing_rule_set_table(entry, rt_table);

            nm_assert(nm_ip_routing_rule_validate(entry, NULL));

            g_ptr_array_add(rules_new, entry);
        }
    }

    for (i = 0; i < config_data->iproutes_len; ++i)
        g_ptr_array_add(routes_new, config_data->iproutes_arr[i]);

    addrs_changed = nmcs_setting_ip_replace_ipv4_addresses(s_ip,
                                                           (NMIPAddress **) addrs_new->pdata,
                                                           addrs_new->len);

    routes_changed = nmcs_setting_ip_replace_ipv4_routes(s_ip,
                                                         (NMIPRoute **) routes_new->pdata,
                                                         routes_new->len);

    rules_changed = nmcs_setting_ip_replace_ipv4_rules(s_ip,
                                                       (NMIPRoutingRule **) rules_new->pdata,
                                                       rules_new->len);

    NM_SET_OUT(out_changed, addrs_changed || routes_changed || rules_changed);
    return TRUE;
}

/*****************************************************************************/

static guint
_config_data_get_num_valid(GHashTable *config_dict)
{
    const NMCSProviderGetConfigIfaceData *config_data;
    GHashTableIter                        h_iter;
    guint                                 n = 0;

    g_hash_table_iter_init(&h_iter, config_dict);
    while (g_hash_table_iter_next(&h_iter, NULL, (gpointer *) &config_data)) {
        if (nmcs_provider_get_config_iface_data_is_valid(config_data))
            n++;
    }

    return n;
}

static gboolean
_config_one(GCancellable *                        sigterm_cancellable,
            NMClient *                            nmc,
            gboolean                              is_single_nic,
            const char *                          hwaddr,
            const NMCSProviderGetConfigIfaceData *config_data)
{
    gs_unref_object NMDevice *device                 = NULL;
    gs_unref_object NMConnection *applied_connection = NULL;
    guint64                       applied_version_id;
    gs_free_error GError *error = NULL;
    gboolean              changed;
    gboolean              version_id_changed;
    guint                 try_count;
    gboolean              any_changes = FALSE;

    g_main_context_iteration(NULL, FALSE);

    if (g_cancellable_is_cancelled(sigterm_cancellable))
        return FALSE;

    device = nm_g_object_ref(_nmc_get_device_by_hwaddr(nmc, hwaddr));
    if (!device) {
        _LOGD("config device %s: skip because device not found", hwaddr);
        return FALSE;
    }

    if (!nmcs_provider_get_config_iface_data_is_valid(config_data)) {
        _LOGD("config device %s: skip because meta data not successfully fetched", hwaddr);
        return FALSE;
    }

    _LOGD("config device %s: configuring \"%s\" (%s)...",
          hwaddr,
          nm_device_get_iface(device) ?: "/unknown/",
          nm_object_get_path(NM_OBJECT(device)));

    try_count = 0;

try_again:

    applied_connection = nmcs_device_get_applied_connection(device,
                                                            sigterm_cancellable,
                                                            &applied_version_id,
                                                            &error);
    if (!applied_connection) {
        if (!nm_utils_error_is_cancelled(error))
            _LOGD("config device %s: device has no applied connection (%s). Skip",
                  hwaddr,
                  error->message);
        return any_changes;
    }

    if (_nmc_skip_connection(applied_connection)) {
        _LOGD("config device %s: skip applied connection due to user data %s",
              hwaddr,
              USER_TAG_SKIP);
        return any_changes;
    }

    if (!_nmc_mangle_connection(device, applied_connection, config_data, &changed)) {
        _LOGD("config device %s: device has no suitable applied connection. Skip", hwaddr);
        return any_changes;
    }

    if (!changed) {
        _LOGD("config device %s: device needs no update to applied connection \"%s\" (%s). Skip",
              hwaddr,
              nm_connection_get_id(applied_connection),
              nm_connection_get_uuid(applied_connection));
        return any_changes;
    }

    _LOGD("config device %s: reapply connection \"%s\" (%s)",
          hwaddr,
          nm_connection_get_id(applied_connection),
          nm_connection_get_uuid(applied_connection));

    /* we are about to call Reapply(). If if that fails, it counts as if we changed something. */
    any_changes = TRUE;

    if (!nmcs_device_reapply(device,
                             sigterm_cancellable,
                             applied_connection,
                             applied_version_id,
                             &version_id_changed,
                             &error)) {
        if (version_id_changed && try_count < 5) {
            _LOGD("config device %s: applied connection changed in the meantime. Retry...", hwaddr);
            g_clear_object(&applied_connection);
            g_clear_error(&error);
            try_count++;
            goto try_again;
        }

        if (!nm_utils_error_is_cancelled(error)) {
            _LOGD("config device %s: failure to reapply connection \"%s\" (%s): %s",
                  hwaddr,
                  nm_connection_get_id(applied_connection),
                  nm_connection_get_uuid(applied_connection),
                  error->message);
        }
        return any_changes;
    }

    _LOGD("config device %s: connection \"%s\" (%s) reapplied",
          hwaddr,
          nm_connection_get_id(applied_connection),
          nm_connection_get_uuid(applied_connection));

    return any_changes;
}

static gboolean
_config_all(GCancellable *sigterm_cancellable, NMClient *nmc, GHashTable *config_dict)
{
    GHashTableIter                        h_iter;
    const NMCSProviderGetConfigIfaceData *c_config_data;
    const char *                          c_hwaddr;
    gboolean                              is_single_nic;
    gboolean                              any_changes = FALSE;

    is_single_nic = (_config_data_get_num_valid(config_dict) <= 1);

    g_hash_table_iter_init(&h_iter, config_dict);
    while (g_hash_table_iter_next(&h_iter, (gpointer *) &c_hwaddr, (gpointer *) &c_config_data)) {
        if (_config_one(sigterm_cancellable, nmc, is_single_nic, c_hwaddr, c_config_data))
            any_changes = TRUE;
    }

    return any_changes;
}

/*****************************************************************************/

static gboolean
sigterm_handler(gpointer user_data)
{
    GCancellable *sigterm_cancellable = user_data;

    if (!g_cancellable_is_cancelled(sigterm_cancellable)) {
        _LOGD("SIGTERM received");
        g_cancellable_cancel(user_data);
    } else
        _LOGD("SIGTERM received (again)");
    return G_SOURCE_CONTINUE;
}

/*****************************************************************************/

int
main(int argc, const char *const *argv)
{
    gs_unref_object GCancellable *    sigterm_cancellable     = NULL;
    nm_auto_destroy_and_unref_gsource GSource *sigterm_source = NULL;
    gs_unref_object NMCSProvider *provider                    = NULL;
    gs_unref_object NMClient *nmc                             = NULL;
    gs_unref_hashtable GHashTable *config_dict                = NULL;
    gs_free_error GError *error                               = NULL;

    _nm_logging_enabled_init(g_getenv(NMCS_ENV_VARIABLE("NM_CLOUD_SETUP_LOG")));

    _LOGD("nm-cloud-setup %s starting...", NM_DIST_VERSION);

    if (argc != 1) {
        g_printerr("%s: no command line arguments supported\n", argv[0]);
        return EXIT_FAILURE;
    }

    sigterm_cancellable = g_cancellable_new();

    sigterm_source = nm_g_source_attach(nm_g_unix_signal_source_new(SIGTERM,
                                                                    G_PRIORITY_DEFAULT,
                                                                    sigterm_handler,
                                                                    sigterm_cancellable,
                                                                    NULL),
                                        NULL);

    provider = _provider_detect(sigterm_cancellable);
    if (!provider)
        goto done;

    nmc_client_new_waitsync(sigterm_cancellable,
                            &nmc,
                            &error,
                            NM_CLIENT_INSTANCE_FLAGS,
                            (guint) NM_CLIENT_INSTANCE_FLAGS_NO_AUTO_FETCH_PERMISSIONS,
                            NULL);

    nmcs_wait_for_objects_register(nmc);
    nmcs_wait_for_objects_register(nm_client_get_context_busy_watcher(nmc));

    if (error) {
        if (!nm_utils_error_is_cancelled(error))
            _LOGI("failure to talk to NetworkManager: %s", error->message);
        goto done;
    }

    if (!nm_client_get_nm_running(nmc)) {
        _LOGI("NetworkManager is not running");
        goto done;
    }

    config_dict = _get_config(sigterm_cancellable, provider, nmc);
    if (!config_dict)
        goto done;

    if (_config_all(sigterm_cancellable, nmc, config_dict))
        _LOGI("some changes were applied for provider %s", nmcs_provider_get_name(provider));
    else
        _LOGD("no changes were applied for provider %s", nmcs_provider_get_name(provider));

done:
    nm_clear_pointer(&config_dict, g_hash_table_unref);
    g_clear_object(&nmc);
    g_clear_object(&provider);

    if (!nmcs_wait_for_objects_iterate_until_done(NULL, 2000)) {
        _LOGE("shutdown: timeout waiting to application to quit. This is a bug");
        nm_assert_not_reached();
    }

    nm_clear_g_source_inst(&sigterm_source);
    g_clear_object(&sigterm_cancellable);

    return 0;
}
