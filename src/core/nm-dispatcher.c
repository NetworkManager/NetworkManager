/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2004 - 2018 Red Hat, Inc.
 * Copyright (C) 2005 - 2008 Novell, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-dispatcher.h"

#include "libnm-glib-aux/nm-dbus-aux.h"
#include "libnm-core-aux-extern/nm-dispatcher-api.h"
#include "NetworkManagerUtils.h"
#include "nm-utils.h"
#include "nm-connectivity.h"
#include "nm-act-request.h"
#include "devices/nm-device.h"
#include "nm-dhcp-config.h"
#include "nm-l3-config-data.h"
#include "nm-manager.h"
#include "settings/nm-settings-connection.h"
#include "libnm-platform/nm-platform.h"
#include "libnm-core-intern/nm-core-internal.h"

#define CALL_TIMEOUT (1000 * 60 * 10) /* 10 minutes for all scripts */

#define _NMLOG_DOMAIN      LOGD_DISPATCH
#define _NMLOG(level, ...) __NMLOG_DEFAULT(level, _NMLOG_DOMAIN, "dispatcher", __VA_ARGS__)

#define _NMLOG2_DOMAIN LOGD_DISPATCH
#define _NMLOG2(level, request_id, log_ifname, log_con_uuid, ...)  \
    nm_log((level),                                                \
           _NMLOG2_DOMAIN,                                         \
           (log_ifname),                                           \
           (log_con_uuid),                                         \
           "dispatcher: (%u) " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
           (request_id) _NM_UTILS_MACRO_REST(__VA_ARGS__))

#define _NMLOG3_DOMAIN LOGD_DISPATCH
#define _NMLOG3(level, call_id, ...)                          \
    G_STMT_START                                              \
    {                                                         \
        const NMDispatcherCallId *const _call_id = (call_id); \
                                                              \
        _NMLOG2(level,                                        \
                _call_id->request_id,                         \
                _call_id->log_ifname,                         \
                _call_id->log_con_uuid,                       \
                __VA_ARGS__);                                 \
    }                                                         \
    G_STMT_END

/*****************************************************************************/

struct NMDispatcherCallId {
    NMDispatcherFunc   callback;
    gpointer           user_data;
    const char        *log_ifname;
    const char        *log_con_uuid;
    gint64             start_at_msec;
    NMDispatcherAction action;
    guint              idle_id;
    guint32            request_id;
    char               extra_strings[];
};

/*****************************************************************************/

/* FIXME(shutdown): on shutdown, we should not run dispatcher scripts synchronously.
 *   Instead, we should of course still run them asynchronously.
 *
 *   Also, we should wait for all pending requests to complete before exiting the main-loop
 *   (with a watchdog). If we hit a timeout, we log a warning and quit (but leave the scripts
 *   running).
 *
 *   Finally, cleanup the global structures. */
static struct {
    GDBusConnection *dbus_connection;
    GHashTable      *requests;
    guint            request_id_counter;
} gl;

/*****************************************************************************/

static NMDispatcherCallId *
dispatcher_call_id_new(guint32            request_id,
                       gint64             start_at_msec,
                       NMDispatcherAction action,
                       NMDispatcherFunc   callback,
                       gpointer           user_data,
                       const char        *log_ifname,
                       const char        *log_con_uuid)
{
    NMDispatcherCallId *call_id;
    gsize               l_log_ifname;
    gsize               l_log_con_uuid;
    char               *extra_strings;

    l_log_ifname   = log_ifname ? (strlen(log_ifname) + 1) : 0u;
    l_log_con_uuid = log_con_uuid ? (strlen(log_con_uuid) + 1) : 0u;

    call_id = g_malloc(sizeof(NMDispatcherCallId) + l_log_ifname + l_log_con_uuid);

    call_id->action        = action;
    call_id->start_at_msec = start_at_msec;
    call_id->request_id    = request_id;
    call_id->callback      = callback;
    call_id->user_data     = user_data;
    call_id->idle_id       = 0;

    extra_strings = &call_id->extra_strings[0];

    if (log_ifname) {
        call_id->log_ifname = extra_strings;
        memcpy(extra_strings, log_ifname, l_log_ifname);
        extra_strings += l_log_ifname;
    } else
        call_id->log_ifname = NULL;

    if (log_con_uuid) {
        call_id->log_con_uuid = extra_strings;
        memcpy(extra_strings, log_con_uuid, l_log_con_uuid);
    } else
        call_id->log_con_uuid = NULL;

    return call_id;
}

static void
dispatcher_call_id_free(NMDispatcherCallId *call_id)
{
    nm_clear_g_source(&call_id->idle_id);
    g_free(call_id);
}

/*****************************************************************************/

static void
_init_dispatcher(void)
{
    if (G_UNLIKELY(gl.requests == NULL)) {
        gl.requests        = g_hash_table_new(nm_direct_hash, NULL);
        gl.dbus_connection = nm_g_object_ref(NM_MAIN_DBUS_CONNECTION_GET);

        if (!gl.dbus_connection)
            _LOGD("No D-Bus connection to talk with NetworkManager-dispatcher service");
    }
}

/*****************************************************************************/

static void
dump_proxy_to_props(const NML3ConfigData *l3cd, GVariantBuilder *builder)
{
    const char *s;

    if (nm_l3_config_data_get_proxy_method(l3cd) != NM_PROXY_CONFIG_METHOD_AUTO)
        return;

    s = nm_l3_config_data_get_proxy_pac_url(l3cd);
    if (s)
        g_variant_builder_add(builder, "{sv}", "pac-url", g_variant_new_string(s));

    s = nm_l3_config_data_get_proxy_pac_script(l3cd);
    if (s)
        g_variant_builder_add(builder, "{sv}", "pac-script", g_variant_new_string(s));
}

static void
dump_ip_to_props(const NML3ConfigData *l3cd, int addr_family, GVariantBuilder *builder)
{
    const int          IS_IPv4 = NM_IS_IPv4(addr_family);
    const NMPObject   *obj;
    GVariantBuilder    int_builder;
    NMDedupMultiIter   ipconf_iter;
    GVariant          *var1;
    GVariant          *var2;
    guint              n;
    guint              i;
    const NMPObject   *default_route;
    const char *const *strarr;
    const in_addr_t   *ip4arr;

    if (IS_IPv4)
        g_variant_builder_init(&int_builder, G_VARIANT_TYPE("aau"));
    else
        g_variant_builder_init(&int_builder, G_VARIANT_TYPE("a(ayuay)"));
    default_route = nm_l3_config_data_get_best_default_route(l3cd, addr_family);
    nm_l3_config_data_iter_obj_for_each (&ipconf_iter,
                                         l3cd,
                                         &obj,
                                         NMP_OBJECT_TYPE_IP_ADDRESS(IS_IPv4)) {
        const NMPlatformIPXAddress *addr = NMP_OBJECT_CAST_IPX_ADDRESS(obj);

        if (IS_IPv4) {
            guint32   array[3];
            in_addr_t gw;

            gw = 0u;
            if (default_route) {
                gw            = NMP_OBJECT_CAST_IP4_ROUTE(default_route)->gateway;
                default_route = NULL;
            }
            array[0] = addr->a4.address;
            array[1] = addr->a4.plen;
            array[2] = gw;
            g_variant_builder_add(&int_builder, "@au", nm_g_variant_new_au(array, 3));
        } else {
            const struct in6_addr *gw = &in6addr_any;

            if (default_route) {
                gw            = &NMP_OBJECT_CAST_IP6_ROUTE(default_route)->gateway;
                default_route = NULL;
            }
            var1 = nm_g_variant_new_ay_in6addr(&addr->a6.address);
            var2 = nm_g_variant_new_ay_in6addr(gw);
            g_variant_builder_add(&int_builder, "(@ayu@ay)", var1, addr->a6.plen, var2);
        }
    }
    g_variant_builder_add(builder, "{sv}", "addresses", g_variant_builder_end(&int_builder));

    if (IS_IPv4)
        g_variant_builder_init(&int_builder, G_VARIANT_TYPE("au"));
    else
        g_variant_builder_init(&int_builder, G_VARIANT_TYPE("aay"));
    strarr = nm_l3_config_data_get_nameservers(l3cd, addr_family, &n);
    for (i = 0; i < n; i++) {
        NMIPAddr a;

        if (!nm_utils_dnsname_parse_assert(addr_family, strarr[i], NULL, &a, NULL))
            continue;

        if (IS_IPv4)
            g_variant_builder_add(&int_builder, "u", a.addr4);
        else
            g_variant_builder_add(&int_builder, "@ay", nm_g_variant_new_ay_in6addr(&a.addr6));
    }
    g_variant_builder_add(builder, "{sv}", "nameservers", g_variant_builder_end(&int_builder));

    g_variant_builder_init(&int_builder, G_VARIANT_TYPE("as"));
    strarr = nm_l3_config_data_get_domains(l3cd, addr_family, &n);
    for (i = 0; i < n; i++)
        g_variant_builder_add(&int_builder, "s", strarr[i]);
    g_variant_builder_add(builder, "{sv}", "domains", g_variant_builder_end(&int_builder));

    if (IS_IPv4) {
        g_variant_builder_init(&int_builder, G_VARIANT_TYPE("au"));
        ip4arr = nm_l3_config_data_get_wins(l3cd, &n);
        for (i = 0; i < n; i++)
            g_variant_builder_add(&int_builder, "u", ip4arr[i]);
        g_variant_builder_add(builder, "{sv}", "wins-servers", g_variant_builder_end(&int_builder));
    }

    if (IS_IPv4)
        g_variant_builder_init(&int_builder, G_VARIANT_TYPE("aau"));
    else
        g_variant_builder_init(&int_builder, G_VARIANT_TYPE("a(ayuayu)"));
    nm_l3_config_data_iter_obj_for_each (&ipconf_iter,
                                         l3cd,
                                         &obj,
                                         NMP_OBJECT_TYPE_IP_ROUTE(IS_IPv4)) {
        const NMPlatformIPXRoute *route = NMP_OBJECT_CAST_IPX_ROUTE(obj);

        if (NM_PLATFORM_IP_ROUTE_IS_DEFAULT(route))
            continue;

        if (IS_IPv4) {
            guint32 array[4];

            array[0] = route->r4.network;
            array[1] = route->r4.plen;
            array[2] = route->r4.gateway;
            array[3] = route->r4.metric;
            g_variant_builder_add(&int_builder, "@au", nm_g_variant_new_au(array, 4));
        } else {
            var1 = nm_g_variant_new_ay_in6addr(&route->r6.network);
            var2 = nm_g_variant_new_ay_in6addr(&route->r6.gateway);
            g_variant_builder_add(&int_builder,
                                  "(@ayu@ayu)",
                                  var1,
                                  route->r6.plen,
                                  var2,
                                  route->r6.metric);
        }
    }
    g_variant_builder_add(builder, "{sv}", "routes", g_variant_builder_end(&int_builder));
}

static void
fill_device_props(NMDevice        *device,
                  GVariantBuilder *dev_builder,
                  GVariantBuilder *proxy_builder,
                  GVariantBuilder *ip4_builder,
                  GVariantBuilder *ip6_builder,
                  GVariant       **dhcp4_props,
                  GVariant       **dhcp6_props)
{
    const NML3ConfigData *l3cd;
    NMDhcpConfig         *dhcp_config;

    /* If the action is for a VPN, send the VPN's IP interface instead of the device's */
    g_variant_builder_add(dev_builder,
                          "{sv}",
                          NMD_DEVICE_PROPS_IP_INTERFACE,
                          g_variant_new_string(nm_device_get_ip_iface(device)));
    g_variant_builder_add(dev_builder,
                          "{sv}",
                          NMD_DEVICE_PROPS_INTERFACE,
                          g_variant_new_string(nm_device_get_iface(device)));
    g_variant_builder_add(dev_builder,
                          "{sv}",
                          NMD_DEVICE_PROPS_TYPE,
                          g_variant_new_uint32(nm_device_get_device_type(device)));
    g_variant_builder_add(dev_builder,
                          "{sv}",
                          NMD_DEVICE_PROPS_STATE,
                          g_variant_new_uint32(nm_device_get_state(device)));
    if (nm_dbus_object_is_exported(NM_DBUS_OBJECT(device))) {
        g_variant_builder_add(
            dev_builder,
            "{sv}",
            NMD_DEVICE_PROPS_PATH,
            g_variant_new_object_path(nm_dbus_object_get_path(NM_DBUS_OBJECT(device))));
    }

    l3cd = nm_device_get_l3cd(device, TRUE);
    if (l3cd) {
        dump_ip_to_props(l3cd, AF_INET, ip4_builder);
        dump_ip_to_props(l3cd, AF_INET6, ip6_builder);
        dump_proxy_to_props(l3cd, proxy_builder);
    }

    dhcp_config = nm_device_get_dhcp_config(device, AF_INET);
    if (dhcp_config)
        *dhcp4_props = nm_g_variant_ref(nm_dhcp_config_get_options(dhcp_config));

    dhcp_config = nm_device_get_dhcp_config(device, AF_INET6);
    if (dhcp_config)
        *dhcp6_props = nm_g_variant_ref(nm_dhcp_config_get_options(dhcp_config));
}

static void
fill_vpn_props(const NML3ConfigData *l3cd,
               GVariantBuilder      *proxy_builder,
               GVariantBuilder      *ip4_builder,
               GVariantBuilder      *ip6_builder)
{
    if (l3cd) {
        dump_ip_to_props(l3cd, AF_INET, ip4_builder);
        dump_ip_to_props(l3cd, AF_INET6, ip6_builder);
        dump_proxy_to_props(l3cd, proxy_builder);
    }
}

static const char *
dispatch_result_to_string(DispatchResult result)
{
    switch (result) {
    case DISPATCH_RESULT_UNKNOWN:
        return "unknown";
    case DISPATCH_RESULT_SUCCESS:
        return "success";
    case DISPATCH_RESULT_EXEC_FAILED:
        return "exec failed";
    case DISPATCH_RESULT_FAILED:
        return "failed";
    case DISPATCH_RESULT_TIMEOUT:
        return "timed out";
    }
    g_assert_not_reached();
}

static void
dispatcher_results_process(guint32     request_id,
                           gint64      start_at_msec,
                           gint64      now_msec,
                           const char *log_ifname,
                           const char *log_con_uuid,
                           GVariant   *v_results)
{
    nm_auto_free_variant_iter GVariantIter *results = NULL;
    const char                             *script, *err;
    guint32                                 result;
    gsize                                   n_children;

    g_variant_get(v_results, "(a(sus))", &results);

    n_children = g_variant_iter_n_children(results);

    _LOG2D(request_id,
           log_ifname,
           log_con_uuid,
           "succeeded (after %ld.%03d sec, %zu scripts invoked)",
           (long int) ((now_msec - start_at_msec) / 1000),
           (int) ((now_msec - start_at_msec) % 1000),
           n_children);

    if (n_children == 0)
        return;

    while (g_variant_iter_next(results, "(&su&s)", &script, &result, &err)) {
        if (result == DISPATCH_RESULT_SUCCESS) {
            _LOG2D(request_id, log_ifname, log_con_uuid, "%s succeeded", script);
        } else {
            _LOG2W(request_id,
                   log_ifname,
                   log_con_uuid,
                   "%s failed (%s): %s",
                   script,
                   dispatch_result_to_string(result),
                   err);
        }
    }
}

static void
dispatcher_done_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    gs_unref_variant GVariant *ret     = NULL;
    gs_free_error GError      *error   = NULL;
    NMDispatcherCallId        *call_id = user_data;
    gint64                     now_msec;

    nm_assert((gpointer) source == gl.dbus_connection);

    now_msec = nm_utils_get_monotonic_timestamp_msec();

    ret = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), result, &error);
    if (!ret) {
        NMLogLevel log_level = LOGL_DEBUG;

        if (nm_dbus_error_is(error, "org.freedesktop.systemd1.LoadFailed")) {
            g_dbus_error_strip_remote_error(error);
            log_level = LOGL_WARN;
        }
        _NMLOG3(log_level,
                call_id,
                "failed to call dispatcher scripts (after %ld.%03d sec): %s",
                (long int) ((now_msec - call_id->start_at_msec) / 1000),
                (int) ((now_msec - call_id->start_at_msec) % 1000),
                error->message);
    } else {
        dispatcher_results_process(call_id->request_id,
                                   call_id->start_at_msec,
                                   now_msec,
                                   call_id->log_ifname,
                                   call_id->log_con_uuid,
                                   ret);
    }

    g_hash_table_remove(gl.requests, call_id);

    if (call_id->callback)
        call_id->callback(call_id, call_id->user_data);

    dispatcher_call_id_free(call_id);
}

static const char *action_table[] = {[NM_DISPATCHER_ACTION_HOSTNAME]      = NMD_ACTION_HOSTNAME,
                                     [NM_DISPATCHER_ACTION_PRE_UP]        = NMD_ACTION_PRE_UP,
                                     [NM_DISPATCHER_ACTION_UP]            = NMD_ACTION_UP,
                                     [NM_DISPATCHER_ACTION_PRE_DOWN]      = NMD_ACTION_PRE_DOWN,
                                     [NM_DISPATCHER_ACTION_DOWN]          = NMD_ACTION_DOWN,
                                     [NM_DISPATCHER_ACTION_VPN_PRE_UP]    = NMD_ACTION_VPN_PRE_UP,
                                     [NM_DISPATCHER_ACTION_VPN_UP]        = NMD_ACTION_VPN_UP,
                                     [NM_DISPATCHER_ACTION_VPN_PRE_DOWN]  = NMD_ACTION_VPN_PRE_DOWN,
                                     [NM_DISPATCHER_ACTION_VPN_DOWN]      = NMD_ACTION_VPN_DOWN,
                                     [NM_DISPATCHER_ACTION_DHCP_CHANGE_4] = NMD_ACTION_DHCP4_CHANGE,
                                     [NM_DISPATCHER_ACTION_DHCP_CHANGE_6] = NMD_ACTION_DHCP6_CHANGE,
                                     [NM_DISPATCHER_ACTION_CONNECTIVITY_CHANGE] =
                                         NMD_ACTION_CONNECTIVITY_CHANGE,
                                     [NM_DISPATCHER_ACTION_REAPPLY] = NMD_ACTION_REAPPLY};

static const char *
action_to_string(NMDispatcherAction action)
{
    if (G_UNLIKELY((gsize) action >= G_N_ELEMENTS(action_table)))
        g_return_val_if_reached(NULL);
    return action_table[(gsize) action];
}

static gboolean
_dispatcher_call(NMDispatcherAction    action,
                 gboolean              blocking,
                 NMDevice             *device,
                 NMSettingsConnection *settings_connection,
                 NMConnection         *applied_connection,
                 gboolean              activation_type_external,
                 NMConnectivityState   connectivity_state,
                 const char           *vpn_iface,
                 const NML3ConfigData *l3cd,
                 NMDispatcherFunc      callback,
                 gpointer              user_data,
                 NMDispatcherCallId  **out_call_id)
{
    GVariant                  *connection_dict;
    GVariantBuilder            connection_props;
    GVariantBuilder            device_props;
    GVariantBuilder            device_proxy_props;
    GVariantBuilder            device_ip4_props;
    GVariantBuilder            device_ip6_props;
    gs_unref_variant GVariant *parameters_floating = NULL;
    gs_unref_variant GVariant *device_dhcp4_props  = NULL;
    gs_unref_variant GVariant *device_dhcp6_props  = NULL;
    GVariantBuilder            vpn_proxy_props;
    GVariantBuilder            vpn_ip4_props;
    GVariantBuilder            vpn_ip6_props;
    NMDispatcherCallId        *call_id;
    guint                      request_id;
    const char                *connectivity_state_string = "UNKNOWN";
    const char                *log_ifname;
    const char                *log_con_uuid;
    gint64                     start_at_msec;
    gint64                     now_msec;

    g_return_val_if_fail(!blocking || (!callback && !user_data), FALSE);

    NM_SET_OUT(out_call_id, NULL);

    _init_dispatcher();

    if (!gl.dbus_connection)
        return FALSE;

    log_ifname = device ? nm_device_get_iface(device) : NULL;
    log_con_uuid =
        settings_connection ? nm_settings_connection_get_uuid(settings_connection) : NULL;

    request_id = ++gl.request_id_counter;
    if (G_UNLIKELY(!request_id))
        request_id = ++gl.request_id_counter;

    /* All actions except 'hostname' and 'connectivity-change' require a device */
    if (action == NM_DISPATCHER_ACTION_HOSTNAME
        || action == NM_DISPATCHER_ACTION_CONNECTIVITY_CHANGE) {
        _LOG2D(request_id,
               log_ifname,
               log_con_uuid,
               "dispatching action '%s'%s",
               action_to_string(action),
               blocking ? " (blocking)" : (callback ? " (with callback)" : ""));
    } else {
        g_return_val_if_fail(NM_IS_DEVICE(device), FALSE);

        _LOG2D(request_id,
               log_ifname,
               log_con_uuid,
               "(%s) dispatching action '%s'%s",
               vpn_iface ?: nm_device_get_iface(device),
               action_to_string(action),
               blocking ? " (blocking)" : (callback ? " (with callback)" : ""));
    }

    if (applied_connection)
        connection_dict =
            nm_connection_to_dbus(applied_connection, NM_CONNECTION_SERIALIZE_WITH_NON_SECRET);
    else
        connection_dict = nm_g_variant_singleton_aLsaLsvII();

    g_variant_builder_init(&connection_props, G_VARIANT_TYPE_VARDICT);
    if (settings_connection) {
        const char *connection_path;
        const char *filename;

        connection_path = nm_dbus_object_get_path(NM_DBUS_OBJECT(settings_connection));
        if (connection_path) {
            g_variant_builder_add(&connection_props,
                                  "{sv}",
                                  NMD_CONNECTION_PROPS_PATH,
                                  g_variant_new_object_path(connection_path));
        }
        filename = nm_settings_connection_get_filename(settings_connection);
        if (filename) {
            g_variant_builder_add(&connection_props,
                                  "{sv}",
                                  NMD_CONNECTION_PROPS_FILENAME,
                                  g_variant_new_string(filename));
        }
        if (activation_type_external) {
            g_variant_builder_add(&connection_props,
                                  "{sv}",
                                  NMD_CONNECTION_PROPS_EXTERNAL,
                                  g_variant_new_boolean(TRUE));
        }
    }

    g_variant_builder_init(&device_props, G_VARIANT_TYPE_VARDICT);
    g_variant_builder_init(&device_proxy_props, G_VARIANT_TYPE_VARDICT);
    g_variant_builder_init(&device_ip4_props, G_VARIANT_TYPE_VARDICT);
    g_variant_builder_init(&device_ip6_props, G_VARIANT_TYPE_VARDICT);
    g_variant_builder_init(&vpn_proxy_props, G_VARIANT_TYPE_VARDICT);
    g_variant_builder_init(&vpn_ip4_props, G_VARIANT_TYPE_VARDICT);
    g_variant_builder_init(&vpn_ip6_props, G_VARIANT_TYPE_VARDICT);

    /* hostname and connectivity-change actions don't send device data */
    if (action != NM_DISPATCHER_ACTION_HOSTNAME
        && action != NM_DISPATCHER_ACTION_CONNECTIVITY_CHANGE) {
        fill_device_props(device,
                          &device_props,
                          &device_proxy_props,
                          &device_ip4_props,
                          &device_ip6_props,
                          &device_dhcp4_props,
                          &device_dhcp6_props);
        if (l3cd) {
            fill_vpn_props(l3cd, &vpn_proxy_props, &vpn_ip4_props, &vpn_ip6_props);
        }
    }

    connectivity_state_string = nm_connectivity_state_to_string(connectivity_state);

    parameters_floating =
        g_variant_new("(s@a{sa{sv}}a{sv}a{sv}a{sv}a{sv}a{sv}@a{sv}@a{sv}ssa{sv}a{sv}a{sv}b)",
                      action_to_string(action),
                      connection_dict,
                      &connection_props,
                      &device_props,
                      &device_proxy_props,
                      &device_ip4_props,
                      &device_ip6_props,
                      device_dhcp4_props ?: nm_g_variant_singleton_aLsvI(),
                      device_dhcp6_props ?: nm_g_variant_singleton_aLsvI(),
                      connectivity_state_string,
                      vpn_iface ?: "",
                      &vpn_proxy_props,
                      &vpn_ip4_props,
                      &vpn_ip6_props,
                      nm_logging_enabled(LOGL_DEBUG, LOGD_DISPATCH));

    start_at_msec = nm_utils_get_monotonic_timestamp_msec();

    /* Send the action to the dispatcher */
    if (blocking) {
        gs_unref_variant GVariant *ret   = NULL;
        gs_free_error GError      *error = NULL;

        ret = g_dbus_connection_call_sync(gl.dbus_connection,
                                          NM_DISPATCHER_DBUS_SERVICE,
                                          NM_DISPATCHER_DBUS_PATH,
                                          NM_DISPATCHER_DBUS_INTERFACE,
                                          "Action",
                                          g_steal_pointer(&parameters_floating),
                                          G_VARIANT_TYPE("(a(sus))"),
                                          G_DBUS_CALL_FLAGS_NONE,
                                          CALL_TIMEOUT,
                                          NULL,
                                          &error);

        now_msec = nm_utils_get_monotonic_timestamp_msec();

        if (!ret) {
            g_dbus_error_strip_remote_error(error);
            _LOG2W(request_id,
                   log_ifname,
                   log_con_uuid,
                   "failed (after %ld.%03d sec): %s",
                   (long int) ((now_msec - start_at_msec) / 1000),
                   (int) ((now_msec - start_at_msec) % 1000),
                   error->message);
            return FALSE;
        }
        dispatcher_results_process(request_id,
                                   start_at_msec,
                                   now_msec,
                                   log_ifname,
                                   log_con_uuid,
                                   ret);
        return TRUE;
    }

    call_id = dispatcher_call_id_new(request_id,
                                     start_at_msec,
                                     action,
                                     callback,
                                     user_data,
                                     log_ifname,
                                     log_con_uuid);

    g_dbus_connection_call(gl.dbus_connection,
                           NM_DISPATCHER_DBUS_SERVICE,
                           NM_DISPATCHER_DBUS_PATH,
                           NM_DISPATCHER_DBUS_INTERFACE,
                           "Action",
                           g_steal_pointer(&parameters_floating),
                           G_VARIANT_TYPE("(a(sus))"),
                           G_DBUS_CALL_FLAGS_NONE,
                           CALL_TIMEOUT,
                           NULL,
                           dispatcher_done_cb,
                           call_id);
    g_hash_table_add(gl.requests, call_id);
    NM_SET_OUT(out_call_id, call_id);
    return TRUE;
}

/**
 * nm_dispatcher_call_hostname:
 * @callback: a caller-supplied callback to execute when done
 * @user_data: caller-supplied pointer passed to @callback
 * @out_call_id: on success, a call identifier which can be passed to
 * nm_dispatcher_call_cancel()
 *
 * This method always invokes the dispatcher action asynchronously.
 *
 * Returns: %TRUE if the action was dispatched, %FALSE on failure
 */
gboolean
nm_dispatcher_call_hostname(NMDispatcherFunc     callback,
                            gpointer             user_data,
                            NMDispatcherCallId **out_call_id)
{
    return _dispatcher_call(NM_DISPATCHER_ACTION_HOSTNAME,
                            FALSE,
                            NULL,
                            NULL,
                            NULL,
                            FALSE,
                            NM_CONNECTIVITY_UNKNOWN,
                            NULL,
                            NULL,
                            callback,
                            user_data,
                            out_call_id);
}

/**
 * nm_dispatcher_call_device:
 * @action: the %NMDispatcherAction
 * @device: the #NMDevice the action applies to
 * @act_request: the #NMActRequest for the action. If %NULL, use the
 *   current request of the device.
 * @callback: a caller-supplied callback to execute when done
 * @user_data: caller-supplied pointer passed to @callback
 * @out_call_id: on success, a call identifier which can be passed to
 * nm_dispatcher_call_cancel()
 *
 * This method always invokes the device dispatcher action asynchronously.  To ignore
 * the result, pass %NULL to @callback.
 *
 * Returns: %TRUE if the action was dispatched, %FALSE on failure
 */
gboolean
nm_dispatcher_call_device(NMDispatcherAction   action,
                          NMDevice            *device,
                          NMActRequest        *act_request,
                          NMDispatcherFunc     callback,
                          gpointer             user_data,
                          NMDispatcherCallId **out_call_id)
{
    nm_assert(NM_IS_DEVICE(device));
    if (!act_request) {
        act_request = nm_device_get_act_request(device);
        if (!act_request)
            return FALSE;
    }
    nm_assert(NM_IN_SET(nm_active_connection_get_device(NM_ACTIVE_CONNECTION(act_request)),
                        NULL,
                        device));
    return _dispatcher_call(
        action,
        FALSE,
        device,
        nm_act_request_get_settings_connection(act_request),
        nm_act_request_get_applied_connection(act_request),
        nm_active_connection_get_activation_type(NM_ACTIVE_CONNECTION(act_request))
            == NM_ACTIVATION_TYPE_EXTERNAL,
        NM_CONNECTIVITY_UNKNOWN,
        NULL,
        NULL,
        callback,
        user_data,
        out_call_id);
}

/**
 * nm_dispatcher_call_device_sync():
 * @action: the %NMDispatcherAction
 * @device: the #NMDevice the action applies to
 * @act_request: the #NMActRequest for the action. If %NULL, use the
 *   current request of the device.
 *
 * This method always invokes the dispatcher action synchronously and it may
 * take a long time to return.
 *
 * Returns: %TRUE if the action was dispatched, %FALSE on failure
 */
gboolean
nm_dispatcher_call_device_sync(NMDispatcherAction action,
                               NMDevice          *device,
                               NMActRequest      *act_request)
{
    nm_assert(NM_IS_DEVICE(device));
    if (!act_request) {
        act_request = nm_device_get_act_request(device);
        if (!act_request)
            return FALSE;
    }
    nm_assert(NM_IN_SET(nm_active_connection_get_device(NM_ACTIVE_CONNECTION(act_request)),
                        NULL,
                        device));
    return _dispatcher_call(
        action,
        TRUE,
        device,
        nm_act_request_get_settings_connection(act_request),
        nm_act_request_get_applied_connection(act_request),
        nm_active_connection_get_activation_type(NM_ACTIVE_CONNECTION(act_request))
            == NM_ACTIVATION_TYPE_EXTERNAL,
        NM_CONNECTIVITY_UNKNOWN,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL);
}

/**
 * nm_dispatcher_call_vpn():
 * @action: the %NMDispatcherAction
 * @settings_connection: the #NMSettingsConnection the action applies to
 * @applied_connection: the currently applied connection
 * @parent_device: the parent #NMDevice of the VPN connection
 * @vpn_iface: the IP interface of the VPN tunnel, if any
 * @vpn_l3cd: the #NML3ConfigData of the VPN connection
 * @callback: a caller-supplied callback to execute when done
 * @user_data: caller-supplied pointer passed to @callback
 * @out_call_id: on success, a call identifier which can be passed to
 * nm_dispatcher_call_cancel()
 *
 * This method always invokes the dispatcher action asynchronously.  To ignore
 * the result, pass %NULL to @callback.
 *
 * Returns: %TRUE if the action was dispatched, %FALSE on failure
 */
gboolean
nm_dispatcher_call_vpn(NMDispatcherAction    action,
                       NMSettingsConnection *settings_connection,
                       NMConnection         *applied_connection,
                       NMDevice             *parent_device,
                       const char           *vpn_iface,
                       const NML3ConfigData *l3cd,
                       NMDispatcherFunc      callback,
                       gpointer              user_data,
                       NMDispatcherCallId  **out_call_id)
{
    return _dispatcher_call(action,
                            FALSE,
                            parent_device,
                            settings_connection,
                            applied_connection,
                            FALSE,
                            NM_CONNECTIVITY_UNKNOWN,
                            vpn_iface,
                            l3cd,
                            callback,
                            user_data,
                            out_call_id);
}

/**
 * nm_dispatcher_call_vpn_sync():
 * @action: the %NMDispatcherAction
 * @settings_connection: the #NMSettingsConnection the action applies to
 * @applied_connection: the currently applied connection
 * @parent_device: the parent #NMDevice of the VPN connection
 * @vpn_iface: the IP interface of the VPN tunnel, if any
 * @vpn_l3cd: the #NML3ConfigData of the VPN connection
 *
 * This method always invokes the dispatcher action synchronously and it may
 * take a long time to return.
 *
 * Returns: %TRUE if the action was dispatched, %FALSE on failure
 */
gboolean
nm_dispatcher_call_vpn_sync(NMDispatcherAction    action,
                            NMSettingsConnection *settings_connection,
                            NMConnection         *applied_connection,
                            NMDevice             *parent_device,
                            const char           *vpn_iface,
                            const NML3ConfigData *l3cd)
{
    return _dispatcher_call(action,
                            TRUE,
                            parent_device,
                            settings_connection,
                            applied_connection,
                            FALSE,
                            NM_CONNECTIVITY_UNKNOWN,
                            vpn_iface,
                            l3cd,
                            NULL,
                            NULL,
                            NULL);
}

/**
 * nm_dispatcher_call_connectivity():
 * @connectivity_state: the #NMConnectivityState value
 * @callback: a caller-supplied callback to execute when done
 * @user_data: caller-supplied pointer passed to @callback
 * @out_call_id: on success, a call identifier which can be passed to
 * nm_dispatcher_call_cancel()
 *
 * This method does not block the caller.
 *
 * Returns: %TRUE if the action was dispatched, %FALSE on failure
 */
gboolean
nm_dispatcher_call_connectivity(NMConnectivityState  connectivity_state,
                                NMDispatcherFunc     callback,
                                gpointer             user_data,
                                NMDispatcherCallId **out_call_id)
{
    return _dispatcher_call(NM_DISPATCHER_ACTION_CONNECTIVITY_CHANGE,
                            FALSE,
                            NULL,
                            NULL,
                            NULL,
                            FALSE,
                            connectivity_state,
                            NULL,
                            NULL,
                            callback,
                            user_data,
                            out_call_id);
}

void
nm_dispatcher_call_cancel(NMDispatcherCallId *call_id)
{
    if (!call_id || g_hash_table_lookup(gl.requests, call_id) != call_id || !call_id->callback)
        g_return_if_reached();

    /* Canceling just means the callback doesn't get called, so set the
     * DispatcherInfo's callback to NULL.
     */
    _LOG3D(call_id, "cancelling dispatcher callback action");
    call_id->callback = NULL;
}
