/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libnm-client-aux-extern/nm-default-client.h"

#include "libnm-client-aux-extern/nm-libnm-aux.h"

#include <linux/rtnetlink.h>

#include "nm-cloud-setup-utils.h"
#include "nmcs-provider-ec2.h"
#include "nmcs-provider-gcp.h"
#include "nmcs-provider-azure.h"
#include "nmcs-provider-aliyun.h"
#include "libnm-core-aux-intern/nm-libnm-core-utils.h"

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
        NMCS_TYPE_PROVIDER_ALIYUN,
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
    GMainLoop *                  main_loop;
    NMCSProviderGetConfigResult *result;
} GetConfigData;

static void
_get_config_cb(GObject *source, GAsyncResult *res, gpointer user_data)
{
    GetConfigData *                              data                                = user_data;
    nm_auto_free_nmcs_provider_get_config_result NMCSProviderGetConfigResult *result = NULL;
    gs_free_error GError *error                                                      = NULL;

    result = nmcs_provider_get_config_finish(NMCS_PROVIDER(source), res, &error);

    if (!result) {
        if (!nm_utils_error_is_cancelled(error))
            _LOGI("failure to get meta data: %s", error->message);
    } else
        _LOGD("meta data received");

    data->result = g_steal_pointer(&result);
    g_main_loop_quit(data->main_loop);
}

static NMCSProviderGetConfigResult *
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

    return data.result;
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
                       const NMCSProviderGetConfigResult *   result,
                       const NMCSProviderGetConfigIfaceData *config_data,
                       gboolean *                            out_skipped_single_addr,
                       gboolean *                            out_changed)
{
    NMSettingIPConfig * s_ip;
    NMActiveConnection *ac;
    NMConnection *      remote_connection;
    NMSettingIPConfig * remote_s_ip = NULL;
    gsize               i;
    gboolean            addrs_changed       = FALSE;
    gboolean            rules_changed       = FALSE;
    gboolean            routes_changed      = FALSE;
    gs_unref_ptrarray GPtrArray *addrs_new  = NULL;
    gs_unref_ptrarray GPtrArray *rules_new  = NULL;
    gs_unref_ptrarray GPtrArray *routes_new = NULL;

    NM_SET_OUT(out_skipped_single_addr, FALSE);
    NM_SET_OUT(out_changed, FALSE);

    if (!nm_streq0(nm_connection_get_connection_type(connection), NM_SETTING_WIRED_SETTING_NAME))
        return FALSE;

    s_ip = nm_connection_get_setting_ip4_config(connection);
    if (!s_ip)
        return FALSE;

    if ((ac = nm_device_get_active_connection(device))
        && (remote_connection = NM_CONNECTION(nm_active_connection_get_connection(ac))))
        remote_s_ip = nm_connection_get_setting_ip4_config(remote_connection);

    addrs_new = g_ptr_array_new_full(config_data->ipv4s_len, (GDestroyNotify) nm_ip_address_unref);
    rules_new =
        g_ptr_array_new_full(config_data->ipv4s_len, (GDestroyNotify) nm_ip_routing_rule_unref);
    routes_new = g_ptr_array_new_full(config_data->iproutes_len + !!config_data->ipv4s_len,
                                      (GDestroyNotify) nm_ip_route_unref);

    if (remote_s_ip) {
        guint len;
        guint j;

        len = nm_setting_ip_config_get_num_addresses(remote_s_ip);
        for (j = 0; j < len; j++) {
            g_ptr_array_add(addrs_new,
                            nm_ip_address_dup(nm_setting_ip_config_get_address(remote_s_ip, j)));
        }

        len = nm_setting_ip_config_get_num_routes(remote_s_ip);
        for (j = 0; j < len; j++) {
            g_ptr_array_add(routes_new,
                            nm_ip_route_dup(nm_setting_ip_config_get_route(remote_s_ip, j)));
        }

        len = nm_setting_ip_config_get_num_routing_rules(remote_s_ip);
        for (j = 0; j < len; j++) {
            g_ptr_array_add(
                rules_new,
                nm_ip_routing_rule_ref(nm_setting_ip_config_get_routing_rule(remote_s_ip, j)));
        }
    }

    if (result->num_valid_ifaces <= 1 && result->num_ipv4s <= 1) {
        /* this setup only has one interface and one IPv4 address (or less).
         * We don't need to configure policy routing in this case. */
        NM_SET_OUT(out_skipped_single_addr, TRUE);
    } else if (config_data->has_ipv4s && config_data->has_cidr) {
        gs_unref_hashtable GHashTable *unique_subnets =
            g_hash_table_new(nm_direct_hash, g_direct_equal);
        NMIPAddress *    addr_entry;
        NMIPRoute *      route_entry;
        NMIPRoutingRule *rule_entry;
        in_addr_t        gateway;
        char             sbuf[NM_UTILS_INET_ADDRSTRLEN];

        for (i = 0; i < config_data->ipv4s_len; i++) {
            addr_entry = nm_ip_address_new_binary(AF_INET,
                                                  &config_data->ipv4s_arr[i],
                                                  config_data->cidr_prefix,
                                                  NULL);
            nm_assert(addr_entry);
            g_ptr_array_add(addrs_new, addr_entry);
        }

        if (config_data->has_gateway && config_data->gateway) {
            gateway = config_data->gateway;
        } else {
            gateway = nm_utils_ip4_address_clear_host_address(config_data->cidr_addr,
                                                              config_data->cidr_prefix);
            if (config_data->cidr_prefix < 32)
                ((guint8 *) &gateway)[3] += 1;
        }

        for (i = 0; i < config_data->ipv4s_len; i++) {
            in_addr_t a = config_data->ipv4s_arr[i];

            a = nm_utils_ip4_address_clear_host_address(a, config_data->cidr_prefix);

            G_STATIC_ASSERT_EXPR(sizeof(gsize) >= sizeof(in_addr_t));
            if (g_hash_table_add(unique_subnets, GSIZE_TO_POINTER(a))) {
                route_entry =
                    nm_ip_route_new_binary(AF_INET, &a, config_data->cidr_prefix, NULL, 10, NULL);
                nm_ip_route_set_attribute(route_entry,
                                          NM_IP_ROUTE_ATTRIBUTE_TABLE,
                                          g_variant_new_uint32(30200 + config_data->iface_idx));
                g_ptr_array_add(routes_new, route_entry);
            }

            rule_entry = nm_ip_routing_rule_new(AF_INET);
            nm_ip_routing_rule_set_priority(rule_entry, 30200 + config_data->iface_idx);
            nm_ip_routing_rule_set_from(rule_entry,
                                        _nm_utils_inet4_ntop(config_data->ipv4s_arr[i], sbuf),
                                        32);
            nm_ip_routing_rule_set_table(rule_entry, 30200 + config_data->iface_idx);
            nm_assert(nm_ip_routing_rule_validate(rule_entry, NULL));
            g_ptr_array_add(rules_new, rule_entry);
        }

        rule_entry = nm_ip_routing_rule_new(AF_INET);
        nm_ip_routing_rule_set_priority(rule_entry, 30350);
        nm_ip_routing_rule_set_table(rule_entry, RT_TABLE_MAIN);
        nm_ip_routing_rule_set_suppress_prefixlength(rule_entry, 0);
        nm_assert(nm_ip_routing_rule_validate(rule_entry, NULL));
        g_ptr_array_add(rules_new, rule_entry);

        route_entry = nm_ip_route_new_binary(AF_INET, &nm_ip_addr_zero, 0, &gateway, 10, NULL);
        nm_ip_route_set_attribute(route_entry,
                                  NM_IP_ROUTE_ATTRIBUTE_TABLE,
                                  g_variant_new_uint32(30400 + config_data->iface_idx));
        g_ptr_array_add(routes_new, route_entry);

        for (i = 0; i < config_data->ipv4s_len; i++) {
            rule_entry = nm_ip_routing_rule_new(AF_INET);
            nm_ip_routing_rule_set_priority(rule_entry, 30400 + config_data->iface_idx);
            nm_ip_routing_rule_set_from(rule_entry,
                                        _nm_utils_inet4_ntop(config_data->ipv4s_arr[i], sbuf),
                                        32);
            nm_ip_routing_rule_set_table(rule_entry, 30400 + config_data->iface_idx);
            nm_assert(nm_ip_routing_rule_validate(rule_entry, NULL));
            g_ptr_array_add(rules_new, rule_entry);
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

static gboolean
_config_one(GCancellable *                     sigterm_cancellable,
            NMClient *                         nmc,
            const NMCSProviderGetConfigResult *result,
            guint                              idx)
{
    const NMCSProviderGetConfigIfaceData *config_data = result->iface_datas_arr[idx];
    const char *                          hwaddr      = config_data->hwaddr;
    gs_unref_object NMDevice *device                  = NULL;
    gs_unref_object NMConnection *applied_connection  = NULL;
    guint64                       applied_version_id;
    gs_free_error GError *error = NULL;
    gboolean              changed;
    gboolean              skipped_single_addr;
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

    if (config_data->iface_idx >= 100) {
        /* since we use the iface_idx to select a table number, the range is limited from
         * 0 to 99. Note that the providers are required to provide increasing numbers,
         * so this means we bail out after the first 100 devices.  */
        _LOGD("config device %s: skip because number of supported interfaces reached", hwaddr);
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

    if (!_nmc_mangle_connection(device,
                                applied_connection,
                                result,
                                config_data,
                                &skipped_single_addr,
                                &changed)) {
        _LOGD("config device %s: device has no suitable applied connection. Skip", hwaddr);
        return any_changes;
    }

    if (!changed) {
        if (skipped_single_addr) {
            _LOGD("config device %s: device needs no update to applied connection \"%s\" (%s) "
                  "because there are not multiple IP addresses. Skip",
                  hwaddr,
                  nm_connection_get_id(applied_connection),
                  nm_connection_get_uuid(applied_connection));
        } else {
            _LOGD(
                "config device %s: device needs no update to applied connection \"%s\" (%s). Skip",
                hwaddr,
                nm_connection_get_id(applied_connection),
                nm_connection_get_uuid(applied_connection));
        }
        return any_changes;
    }

    _LOGD("config device %s: reapply connection \"%s\" (%s)",
          hwaddr,
          nm_connection_get_id(applied_connection),
          nm_connection_get_uuid(applied_connection));

    /* we are about to call Reapply(). Even if that fails, it counts as if we changed something. */
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
_config_all(GCancellable *                     sigterm_cancellable,
            NMClient *                         nmc,
            const NMCSProviderGetConfigResult *result)
{
    gboolean any_changes = FALSE;
    guint    i;

    for (i = 0; i < result->n_iface_datas; i++) {
        if (_config_one(sigterm_cancellable, nmc, result, i))
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
    gs_unref_object GCancellable *    sigterm_cancellable                            = NULL;
    nm_auto_destroy_and_unref_gsource GSource *sigterm_source                        = NULL;
    gs_unref_object NMCSProvider *provider                                           = NULL;
    gs_unref_object NMClient *                   nmc                                 = NULL;
    nm_auto_free_nmcs_provider_get_config_result NMCSProviderGetConfigResult *result = NULL;
    gs_free_error GError *error                                                      = NULL;

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

    result = _get_config(sigterm_cancellable, provider, nmc);
    if (!result)
        goto done;

    if (_config_all(sigterm_cancellable, nmc, result))
        _LOGI("some changes were applied for provider %s", nmcs_provider_get_name(provider));
    else
        _LOGD("no changes were applied for provider %s", nmcs_provider_get_name(provider));

done:
    nm_clear_pointer(&result, nmcs_provider_get_config_result_free);
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
