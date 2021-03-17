/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2017 Intel Corporation
 */

#include "src/core/nm-default-daemon.h"

#include "nm-device-iwd.h"

#include <linux/if_ether.h>

#include "devices/nm-device-private.h"
#include "devices/nm-device.h"
#include "nm-act-request.h"
#include "nm-config.h"
#include "nm-core-internal.h"
#include "nm-dbus-manager.h"
#include "nm-glib-aux/nm-ref-string.h"
#include "nm-iwd-manager.h"
#include "nm-libnm-core-intern/nm-common-macros.h"
#include "nm-setting-8021x.h"
#include "nm-setting-connection.h"
#include "nm-setting-wireless-security.h"
#include "nm-setting-wireless.h"
#include "nm-std-aux/nm-dbus-compat.h"
#include "nm-utils.h"
#include "nm-wifi-common.h"
#include "nm-wifi-utils.h"
#include "settings/nm-settings-connection.h"
#include "settings/nm-settings.h"
#include "supplicant/nm-supplicant-types.h"
#include "nm-auth-utils.h"
#include "nm-manager.h"

#define _NMLOG_DEVICE_TYPE NMDeviceIwd
#include "devices/nm-device-logging.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE(NMDeviceIwd,
                             PROP_MODE,
                             PROP_BITRATE,
                             PROP_ACCESS_POINTS,
                             PROP_ACTIVE_ACCESS_POINT,
                             PROP_CAPABILITIES,
                             PROP_SCANNING,
                             PROP_LAST_SCAN, );

typedef struct {
    GDBusObject *                 dbus_obj;
    GDBusProxy *                  dbus_device_proxy;
    GDBusProxy *                  dbus_station_proxy;
    GDBusProxy *                  dbus_ap_proxy;
    GDBusProxy *                  dbus_adhoc_proxy;
    CList                         aps_lst_head;
    NMWifiAP *                    current_ap;
    GCancellable *                cancellable;
    NMDeviceWifiCapabilities      capabilities;
    NMActRequestGetSecretsCallId *wifi_secrets_id;
    guint                         periodic_scan_id;
    guint                         periodic_update_id;
    bool                          enabled : 1;
    bool                          can_scan : 1;
    bool                          nm_autoconnect : 1;
    bool                          iwd_autoconnect : 1;
    bool                          scanning : 1;
    bool                          scan_requested : 1;
    bool                          act_mode_switch : 1;
    bool                          secrets_failed : 1;
    bool                          networks_requested : 1;
    bool                          networks_changed : 1;
    gint64                        last_scan;
    uint32_t                      ap_id;
    guint32                       rate;
    NMEtherAddr                   current_ap_bssid;
    GDBusMethodInvocation *       pending_agent_request;
    NMActiveConnection *          assumed_ac;
    guint                         assumed_ac_timeout;
} NMDeviceIwdPrivate;

struct _NMDeviceIwd {
    NMDevice           parent;
    NMDeviceIwdPrivate _priv;
};

struct _NMDeviceIwdClass {
    NMDeviceClass parent;
};

/*****************************************************************************/

G_DEFINE_TYPE(NMDeviceIwd, nm_device_iwd, NM_TYPE_DEVICE)

#define NM_DEVICE_IWD_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMDeviceIwd, NM_IS_DEVICE_IWD, NMDevice)

/*****************************************************************************/

static void schedule_periodic_scan(NMDeviceIwd *self, gboolean initial_scan);

static gboolean check_scanning_prohibited(NMDeviceIwd *self, gboolean periodic);

/*****************************************************************************/

static void
_ap_dump(NMDeviceIwd *self, NMLogLevel log_level, const NMWifiAP *ap, const char *prefix)
{
    char buf[1024];

    buf[0] = '\0';
    _NMLOG(log_level,
           LOGD_WIFI_SCAN,
           "wifi-ap: %-7s %s",
           prefix,
           nm_wifi_ap_to_string(ap, buf, sizeof(buf), 0));
}

/* Callers ensure we're not removing current_ap */
static void
ap_add_remove(NMDeviceIwd *self,
              gboolean     is_adding, /* or else is removing */
              NMWifiAP *   ap,
              gboolean     recheck_available_connections)
{
    NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE(self);

    if (is_adding) {
        g_object_ref(ap);
        ap->wifi_device = NM_DEVICE(self);
        c_list_link_tail(&priv->aps_lst_head, &ap->aps_lst);
        nm_dbus_object_export(NM_DBUS_OBJECT(ap));
        _ap_dump(self, LOGL_DEBUG, ap, "added");
        nm_device_wifi_emit_signal_access_point(NM_DEVICE(self), ap, TRUE);
    } else {
        ap->wifi_device = NULL;
        c_list_unlink(&ap->aps_lst);
        _ap_dump(self, LOGL_DEBUG, ap, "removed");
    }

    _notify(self, PROP_ACCESS_POINTS);

    if (!is_adding) {
        nm_device_wifi_emit_signal_access_point(NM_DEVICE(self), ap, FALSE);
        nm_dbus_object_clear_and_unexport(&ap);
    }

    if (priv->enabled && !priv->iwd_autoconnect)
        nm_device_emit_recheck_auto_activate(NM_DEVICE(self));

    if (recheck_available_connections)
        nm_device_recheck_available_connections(NM_DEVICE(self));
}

static void
set_current_ap(NMDeviceIwd *self, NMWifiAP *new_ap, gboolean recheck_available_connections)
{
    NMDeviceIwdPrivate *priv;
    NMWifiAP *          old_ap;

    g_return_if_fail(NM_IS_DEVICE_IWD(self));

    priv   = NM_DEVICE_IWD_GET_PRIVATE(self);
    old_ap = priv->current_ap;

    if (old_ap == new_ap)
        return;

    if (new_ap)
        priv->current_ap = g_object_ref(new_ap);
    else
        priv->current_ap = NULL;

    if (old_ap) {
        if (nm_wifi_ap_get_fake(old_ap))
            ap_add_remove(self, FALSE, old_ap, recheck_available_connections);
        g_object_unref(old_ap);
    }

    memset(&priv->current_ap_bssid, 0, ETH_ALEN);
    _notify(self, PROP_ACTIVE_ACCESS_POINT);
    _notify(self, PROP_MODE);
}

static void
remove_all_aps(NMDeviceIwd *self)
{
    NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE(self);
    NMWifiAP *          ap, *ap_safe;

    if (c_list_is_empty(&priv->aps_lst_head))
        return;

    c_list_for_each_entry_safe (ap, ap_safe, &priv->aps_lst_head, aps_lst)
        ap_add_remove(self, FALSE, ap, FALSE);

    if (!priv->iwd_autoconnect)
        nm_device_emit_recheck_auto_activate(NM_DEVICE(self));

    nm_device_recheck_available_connections(NM_DEVICE(self));
}

static NM80211ApSecurityFlags
ap_security_flags_from_network_type(const char *type)
{
    NM80211ApSecurityFlags flags;

    if (nm_streq(type, "psk"))
        flags = NM_802_11_AP_SEC_KEY_MGMT_PSK;
    else if (nm_streq(type, "8021x"))
        flags = NM_802_11_AP_SEC_KEY_MGMT_802_1X;
    else
        return NM_802_11_AP_SEC_NONE;

    flags |= NM_802_11_AP_SEC_PAIR_CCMP;
    flags |= NM_802_11_AP_SEC_GROUP_CCMP;
    return flags;
}

static NMWifiAP *
ap_from_network(NMDeviceIwd *self,
                GDBusProxy * network,
                NMRefString *bss_path,
                gint64       last_seen_msec,
                int16_t      signal)
{
    NMDeviceIwdPrivate *priv              = NM_DEVICE_IWD_GET_PRIVATE(self);
    gs_unref_variant GVariant *name_value = NULL;
    gs_unref_variant GVariant *type_value = NULL;
    const char *               name;
    const char *               type;
    uint32_t                   ap_id;
    gs_unref_bytes GBytes *ssid = NULL;
    NMWifiAP *             ap;
    NMSupplicantBssInfo    bss_info;

    g_return_val_if_fail(network, NULL);

    name_value = g_dbus_proxy_get_cached_property(network, "Name");
    type_value = g_dbus_proxy_get_cached_property(network, "Type");
    if (!name_value || !g_variant_is_of_type(name_value, G_VARIANT_TYPE_STRING) || !type_value
        || !g_variant_is_of_type(type_value, G_VARIANT_TYPE_STRING))
        return NULL;

    name = g_variant_get_string(name_value, NULL);
    type = g_variant_get_string(type_value, NULL);

    if (nm_streq(type, "wep")) {
        /* WEP not supported */
        return NULL;
    }

    /* What we get from IWD are networks, or ESSs, that may contain
     * multiple APs, or BSSs, each.  We don't get information about any
     * specific BSSs within an ESS but we can safely present each ESS
     * as an individual BSS to NM, which will be seen as ESSs comprising
     * a single BSS each.  NM won't be able to handle roaming but IWD
     * already does that.  We fake the BSSIDs as they don't play any
     * role either.
     */
    ap_id = priv->ap_id++;

    ssid = g_bytes_new(name, NM_MIN(32u, strlen(name)));

    bss_info = (NMSupplicantBssInfo){
        .bss_path       = bss_path,
        .last_seen_msec = last_seen_msec,
        .bssid_valid    = TRUE,
        .mode           = NM_802_11_MODE_INFRA,
        .rsn_flags      = ap_security_flags_from_network_type(type),
        .ssid           = ssid,
        .signal_percent = nm_wifi_utils_level_to_quality(signal / 100),
        .frequency      = 2417,
        .max_rate       = 65000,
        .bssid          = NM_ETHER_ADDR_INIT(0x00, 0x01, 0x02, ap_id >> 16, ap_id >> 8, ap_id),
    };

    ap = nm_wifi_ap_new_from_properties(&bss_info);

    nm_assert(bss_path == nm_wifi_ap_get_supplicant_path(ap));

    return ap;
}

static void
insert_ap_from_network(NMDeviceIwd *self,
                       GHashTable * aps,
                       const char * path,
                       gint64       last_seen_msec,
                       int16_t      signal)
{
    gs_unref_object GDBusProxy *network_proxy = NULL;
    nm_auto_ref_string NMRefString *bss_path  = nm_ref_string_new(path);
    NMWifiAP *                      ap;

    if (g_hash_table_lookup(aps, bss_path)) {
        _LOGD(LOGD_WIFI, "Duplicate network at %s", path);
        return;
    }

    network_proxy =
        nm_iwd_manager_get_dbus_interface(nm_iwd_manager_get(), path, NM_IWD_NETWORK_INTERFACE);

    ap = ap_from_network(self, network_proxy, bss_path, last_seen_msec, signal);
    if (!ap)
        return;

    g_hash_table_insert(aps, bss_path, ap);
}

static void
get_ordered_networks_cb(GObject *source, GAsyncResult *res, gpointer user_data)
{
    NMDeviceIwd *       self = user_data;
    NMDeviceIwdPrivate *priv;
    gs_free_error GError *error        = NULL;
    gs_unref_variant GVariant *variant = NULL;
    GVariantIter *             networks;
    const char *               path;
    int16_t                    signal;
    NMWifiAP *                 ap, *ap_safe, *new_ap;
    gboolean                   changed;
    GHashTableIter             ap_iter;
    gs_unref_hashtable GHashTable *new_aps = NULL;
    gint64                         last_seen_msec;

    variant = g_dbus_proxy_call_finish(G_DBUS_PROXY(source), res, &error);
    if (!variant && nm_utils_error_is_cancelled(error))
        return;

    priv                     = NM_DEVICE_IWD_GET_PRIVATE(self);
    priv->networks_requested = FALSE;

    if (!variant) {
        _LOGE(LOGD_WIFI, "Station.GetOrderedNetworks failed: %s", error->message);
        return;
    }

    if (!g_variant_is_of_type(variant, G_VARIANT_TYPE("(a(on))"))) {
        _LOGE(LOGD_WIFI,
              "Station.GetOrderedNetworks returned type %s instead of (a(on))",
              g_variant_get_type_string(variant));
        return;
    }

    new_aps = g_hash_table_new_full(nm_direct_hash, NULL, NULL, g_object_unref);
    g_variant_get(variant, "(a(on))", &networks);

    last_seen_msec = nm_utils_get_monotonic_timestamp_msec();
    while (g_variant_iter_next(networks, "(&on)", &path, &signal))
        insert_ap_from_network(self, new_aps, path, last_seen_msec, signal);

    g_variant_iter_free(networks);

    changed                = priv->networks_changed;
    priv->networks_changed = FALSE;

    c_list_for_each_entry_safe (ap, ap_safe, &priv->aps_lst_head, aps_lst) {
        new_ap = g_hash_table_lookup(new_aps, nm_wifi_ap_get_supplicant_path(ap));
        if (new_ap) {
            if (nm_wifi_ap_set_strength(ap, nm_wifi_ap_get_strength(new_ap))) {
                _ap_dump(self, LOGL_TRACE, ap, "updated");
                changed = TRUE;
            }
            g_hash_table_remove(new_aps, nm_wifi_ap_get_supplicant_path(ap));
            continue;
        }

        if (ap == priv->current_ap) {
            /* Normally IWD will prevent the current AP from being
             * removed from the list and set a low signal strength,
             * but just making sure.
             */
            continue;
        }

        ap_add_remove(self, FALSE, ap, FALSE);
        changed = TRUE;
    }

    g_hash_table_iter_init(&ap_iter, new_aps);
    while (g_hash_table_iter_next(&ap_iter, NULL, (gpointer) &ap)) {
        ap_add_remove(self, TRUE, ap, FALSE);
        g_hash_table_iter_remove(&ap_iter);
        changed = TRUE;
    }

    if (changed) {
        if (!priv->iwd_autoconnect)
            nm_device_emit_recheck_auto_activate(NM_DEVICE(self));

        nm_device_recheck_available_connections(NM_DEVICE(self));
    }
}

static void
update_aps(NMDeviceIwd *self)
{
    NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE(self);

    if (!priv->cancellable)
        priv->cancellable = g_cancellable_new();

    g_dbus_proxy_call(priv->dbus_station_proxy,
                      "GetOrderedNetworks",
                      NULL,
                      G_DBUS_CALL_FLAGS_NONE,
                      2000,
                      priv->cancellable,
                      get_ordered_networks_cb,
                      self);
    priv->networks_requested = TRUE;
}

static void
periodic_update(NMDeviceIwd *self)
{
    NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE(self);
    int                 ifindex;
    guint32             new_rate;
    int                 percent;
    NMEtherAddr         bssid;
    gboolean            ap_changed = FALSE;
    NMPlatform *        platform;

    ifindex = nm_device_get_ifindex(NM_DEVICE(self));
    if (ifindex <= 0)
        g_return_if_reached();

    platform = nm_device_get_platform(NM_DEVICE(self));

    /* TODO: obtain quality through the net.connman.iwd.SignalLevelAgent API.
     * For now we're waking up for the rate/BSSID updates anyway.
     */
    if (!nm_platform_wifi_get_station(platform, ifindex, &bssid, &percent, &new_rate)) {
        _LOGD(LOGD_WIFI, "BSSID / quality / rate platform query failed");
        return;
    }

    if (nm_wifi_ap_set_strength(priv->current_ap, (gint8) percent)) {
#if NM_MORE_LOGGING
        ap_changed = TRUE;
#endif
    }

    if (new_rate != priv->rate) {
        priv->rate = new_rate;
        _notify(self, PROP_BITRATE);
    }

    if (nm_ether_addr_is_valid(&bssid) && !nm_ether_addr_equal(&bssid, &priv->current_ap_bssid)) {
        priv->current_ap_bssid = bssid;
        ap_changed |= nm_wifi_ap_set_address_bin(priv->current_ap, &bssid);
        ap_changed |= nm_wifi_ap_set_freq(priv->current_ap,
                                          nm_platform_wifi_get_frequency(platform, ifindex));
    }

    if (ap_changed)
        _ap_dump(self, LOGL_DEBUG, priv->current_ap, "updated");
}

static gboolean
periodic_update_cb(gpointer user_data)
{
    periodic_update(user_data);
    return TRUE;
}

static void
send_disconnect(NMDeviceIwd *self)
{
    NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE(self);

    g_dbus_proxy_call(priv->dbus_station_proxy,
                      "Disconnect",
                      NULL,
                      G_DBUS_CALL_FLAGS_NONE,
                      -1,
                      NULL,
                      NULL,
                      NULL);
}

static void
wifi_secrets_cancel(NMDeviceIwd *self)
{
    NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE(self);

    if (priv->wifi_secrets_id)
        nm_act_request_cancel_secrets(NULL, priv->wifi_secrets_id);
    nm_assert(!priv->wifi_secrets_id);

    if (priv->pending_agent_request) {
        g_dbus_method_invocation_return_error_literal(priv->pending_agent_request,
                                                      NM_DEVICE_ERROR,
                                                      NM_DEVICE_ERROR_INVALID_CONNECTION,
                                                      "NM secrets request cancelled");
        g_clear_object(&priv->pending_agent_request);
    }
}

static void
cleanup_assumed_connect(NMDeviceIwd *self)
{
    NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE(self);

    if (!priv->assumed_ac)
        return;

    g_signal_handlers_disconnect_by_data(priv->assumed_ac, self);
    g_clear_object(&priv->assumed_ac);
}

static void
cleanup_association_attempt(NMDeviceIwd *self, gboolean disconnect)
{
    NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE(self);

    cleanup_assumed_connect(self);
    wifi_secrets_cancel(self);

    set_current_ap(self, NULL, TRUE);
    nm_clear_g_source(&priv->periodic_update_id);
    nm_clear_g_source(&priv->assumed_ac_timeout);

    if (disconnect && priv->dbus_station_proxy)
        send_disconnect(self);
}

static void
reset_mode(NMDeviceIwd *       self,
           GCancellable *      cancellable,
           GAsyncReadyCallback callback,
           gpointer            user_data)
{
    NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE(self);

    g_dbus_proxy_call(
        priv->dbus_device_proxy,
        DBUS_INTERFACE_PROPERTIES ".Set",
        g_variant_new("(ssv)", NM_IWD_DEVICE_INTERFACE, "Mode", g_variant_new_string("station")),
        G_DBUS_CALL_FLAGS_NONE,
        2000,
        cancellable,
        callback,
        user_data);
}

static gboolean
get_variant_boolean(GVariant *v, const char *property)
{
    if (!v || !g_variant_is_of_type(v, G_VARIANT_TYPE_BOOLEAN)) {
        nm_log_warn(LOGD_DEVICE | LOGD_WIFI,
                    "Property %s not cached or not boolean type",
                    property);

        return FALSE;
    }

    return g_variant_get_boolean(v);
}

static const char *
get_variant_state(GVariant *v)
{
    if (!v || !g_variant_is_of_type(v, G_VARIANT_TYPE_STRING)) {
        nm_log_warn(LOGD_DEVICE | LOGD_WIFI, "State property not cached or not a string");

        return "unknown";
    }

    return g_variant_get_string(v, NULL);
}

static void
deactivate(NMDevice *device)
{
    NMDeviceIwd *       self = NM_DEVICE_IWD(device);
    NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE(self);

    if (!priv->dbus_obj)
        return;

    if (priv->dbus_station_proxy) {
        gs_unref_variant GVariant *value =
            g_dbus_proxy_get_cached_property(priv->dbus_station_proxy, "State");

        if (NM_IN_STRSET(get_variant_state(value), "disconnecting", "disconnected"))
            return;
    }

    cleanup_association_attempt(self, FALSE);
    priv->act_mode_switch = FALSE;

    /* Don't trigger any actions on the IWD side until the device is managed */
    if (priv->iwd_autoconnect && nm_device_get_state(device) < NM_DEVICE_STATE_DISCONNECTED)
        return;

    if (priv->dbus_station_proxy)
        send_disconnect(self);
    else
        reset_mode(self, NULL, NULL, NULL);
}

static void
disconnect_cb(GObject *source, GAsyncResult *res, gpointer user_data)
{
    gs_unref_object NMDeviceIwd *self = NULL;
    NMDeviceDeactivateCallback   callback;
    gpointer                     callback_user_data;
    gs_unref_variant GVariant *variant = NULL;
    gs_free_error GError *error        = NULL;

    nm_utils_user_data_unpack(user_data, &self, &callback, &callback_user_data);

    variant = g_dbus_proxy_call_finish(G_DBUS_PROXY(source), res, &error);
    callback(NM_DEVICE(self), error, callback_user_data);
}

static void
disconnect_cb_on_idle(gpointer user_data, GCancellable *cancellable)
{
    gs_unref_object NMDeviceIwd *self = NULL;
    NMDeviceDeactivateCallback   callback;
    gpointer                     callback_user_data;
    gs_free_error GError *cancelled_error = NULL;

    nm_utils_user_data_unpack(user_data, &self, &callback, &callback_user_data);

    g_cancellable_set_error_if_cancelled(cancellable, &cancelled_error);
    callback(NM_DEVICE(self), cancelled_error, callback_user_data);
}

static void
deactivate_async(NMDevice *                 device,
                 GCancellable *             cancellable,
                 NMDeviceDeactivateCallback callback,
                 gpointer                   callback_user_data)
{
    NMDeviceIwd *       self = NM_DEVICE_IWD(device);
    NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE(self);
    gpointer            user_data;

    nm_assert(G_IS_CANCELLABLE(cancellable));
    nm_assert(callback);

    user_data = nm_utils_user_data_pack(g_object_ref(self), callback, callback_user_data);

    if (!priv->dbus_obj) {
        nm_utils_invoke_on_idle(cancellable, disconnect_cb_on_idle, user_data);
        return;
    }

    cleanup_association_attempt(self, FALSE);
    priv->act_mode_switch = FALSE;

    if (priv->iwd_autoconnect && nm_device_get_state(device) < NM_DEVICE_STATE_DISCONNECTED) {
        nm_utils_invoke_on_idle(cancellable, disconnect_cb_on_idle, user_data);
        return;
    }

    if (priv->dbus_station_proxy) {
        g_dbus_proxy_call(priv->dbus_station_proxy,
                          "Disconnect",
                          NULL,
                          G_DBUS_CALL_FLAGS_NONE,
                          -1,
                          cancellable,
                          disconnect_cb,
                          user_data);
    } else
        reset_mode(self, cancellable, disconnect_cb, user_data);
}

static gboolean
is_connection_known_network(NMConnection *connection)
{
    NMIwdNetworkSecurity security;
    gs_free char *       ssid = NULL;

    if (!nm_wifi_connection_get_iwd_ssid_and_security(connection, &ssid, &security))
        return FALSE;

    return nm_iwd_manager_is_known_network(nm_iwd_manager_get(), ssid, security);
}

static gboolean
is_ap_known_network(NMWifiAP *ap)
{
    gs_unref_object GDBusProxy *network_proxy = NULL;
    gs_unref_variant GVariant *known_network  = NULL;

    network_proxy =
        nm_iwd_manager_get_dbus_interface(nm_iwd_manager_get(),
                                          nm_ref_string_get_str(nm_wifi_ap_get_supplicant_path(ap)),
                                          NM_IWD_NETWORK_INTERFACE);
    if (!network_proxy)
        return FALSE;

    known_network = g_dbus_proxy_get_cached_property(network_proxy, "KnownNetwork");
    return nm_g_variant_is_of_type(known_network, G_VARIANT_TYPE_OBJECT_PATH);
}

static gboolean
check_connection_compatible(NMDevice *device, NMConnection *connection, GError **error)
{
    NMDeviceIwd *        self = NM_DEVICE_IWD(device);
    NMDeviceIwdPrivate * priv = NM_DEVICE_IWD_GET_PRIVATE(self);
    NMSettingWireless *  s_wireless;
    const char *         mac;
    const char *const *  mac_blacklist;
    int                  i;
    const char *         perm_hw_addr;
    const char *         mode;
    NMIwdNetworkSecurity security;
    GBytes *             ssid;
    const guint8 *       ssid_bytes;
    gsize                ssid_len;

    if (!NM_DEVICE_CLASS(nm_device_iwd_parent_class)
             ->check_connection_compatible(device, connection, error))
        return FALSE;

    s_wireless = nm_connection_get_setting_wireless(connection);

    /* complete_connection would be called (if at all) before this function
     * so an SSID should always be set.  IWD doesn't support non-UTF8 SSIDs
     * (ignores BSSes with such SSIDs and has no way to represent them on
     * DBus) so we can cut it short for connections with a non-UTF8 SSID.
     */
    ssid = nm_setting_wireless_get_ssid(s_wireless);
    if (!ssid)
        return FALSE;

    ssid_bytes = g_bytes_get_data(ssid, &ssid_len);
    if (!g_utf8_validate((const char *) ssid_bytes, ssid_len, NULL)) {
        nm_utils_error_set_literal(error,
                                   NM_UTILS_ERROR_CONNECTION_AVAILABLE_INCOMPATIBLE,
                                   "non-UTF-8 connection SSID not supported by IWD backend");
        return FALSE;
    }

    perm_hw_addr = nm_device_get_permanent_hw_address(device);
    mac          = nm_setting_wireless_get_mac_address(s_wireless);
    if (perm_hw_addr) {
        if (mac && !nm_utils_hwaddr_matches(mac, -1, perm_hw_addr, -1)) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_INCOMPATIBLE,
                                       "device MAC address does not match the profile");
            return FALSE;
        }

        /* Check for MAC address blacklist */
        mac_blacklist = nm_setting_wireless_get_mac_address_blacklist(s_wireless);
        for (i = 0; mac_blacklist[i]; i++) {
            nm_assert(nm_utils_hwaddr_valid(mac_blacklist[i], ETH_ALEN));

            if (nm_utils_hwaddr_matches(mac_blacklist[i], -1, perm_hw_addr, -1)) {
                nm_utils_error_set_literal(error,
                                           NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                           "MAC address blacklisted");
                return FALSE;
            }
        }
    } else if (mac) {
        nm_utils_error_set_literal(error,
                                   NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                   "device has no valid MAC address as required by profile");
        return FALSE;
    }

    if (!nm_wifi_connection_get_iwd_ssid_and_security(connection, NULL, &security)
        || security == NM_IWD_NETWORK_SECURITY_WEP) {
        nm_utils_error_set_literal(error,
                                   NM_UTILS_ERROR_CONNECTION_AVAILABLE_INCOMPATIBLE,
                                   "connection authentication type not supported by IWD backend");
        return FALSE;
    }

    mode = nm_setting_wireless_get_mode(s_wireless);

    /* Hidden SSIDs only supported in client mode */
    if (nm_setting_wireless_get_hidden(s_wireless)
        && !NM_IN_STRSET(mode, NULL, NM_SETTING_WIRELESS_MODE_INFRA)) {
        nm_utils_error_set_literal(
            error,
            NM_UTILS_ERROR_CONNECTION_AVAILABLE_INCOMPATIBLE,
            "non-infrastructure hidden networks not supported by the IWD backend");
        return FALSE;
    }

    if (NM_IN_STRSET(mode, NULL, NM_SETTING_WIRELESS_MODE_INFRA)) {
        /* 8021x networks can only be used if they've been provisioned on the IWD side and
         * thus are Known Networks.
         */
        if (security == NM_IWD_NETWORK_SECURITY_8021X) {
            if (!is_connection_known_network(connection)) {
                nm_utils_error_set_literal(error,
                                           NM_UTILS_ERROR_CONNECTION_AVAILABLE_INCOMPATIBLE,
                                           "802.1x connections must have IWD provisioning files");
                return FALSE;
            }
        } else if (!NM_IN_SET(security,
                              NM_IWD_NETWORK_SECURITY_OPEN,
                              NM_IWD_NETWORK_SECURITY_PSK)) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_INCOMPATIBLE,
                                       "IWD backend only supports Open, PSK and 802.1x network "
                                       "authentication in Infrastructure mode");
            return FALSE;
        }
    } else if (nm_streq(mode, NM_SETTING_WIRELESS_MODE_AP)) {
        NMSettingWirelessSecurity *s_wireless_sec =
            nm_connection_get_setting_wireless_security(connection);

        if (!(priv->capabilities & NM_WIFI_DEVICE_CAP_AP)) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_INCOMPATIBLE,
                                       "device does not support Access Point mode");
            return FALSE;
        }

        if (!NM_IN_SET(security, NM_IWD_NETWORK_SECURITY_PSK) || !s_wireless_sec
            || !nm_streq0(nm_setting_wireless_security_get_key_mgmt(s_wireless_sec), "wpa-psk")) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_INCOMPATIBLE,
                                       "IWD backend only supports PSK authentication in AP mode");
            return FALSE;
        }
    } else if (nm_streq(mode, NM_SETTING_WIRELESS_MODE_ADHOC)) {
        NMSettingWirelessSecurity *s_wireless_sec =
            nm_connection_get_setting_wireless_security(connection);

        if (!(priv->capabilities & NM_WIFI_DEVICE_CAP_ADHOC)) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_INCOMPATIBLE,
                                       "device does not support Ad-Hoc mode");
            return FALSE;
        }

        if (!NM_IN_SET(security, NM_IWD_NETWORK_SECURITY_OPEN, NM_IWD_NETWORK_SECURITY_PSK)
            || (s_wireless_sec
                && !nm_streq0(nm_setting_wireless_security_get_key_mgmt(s_wireless_sec),
                              "wpa-psk"))) {
            nm_utils_error_set_literal(
                error,
                NM_UTILS_ERROR_CONNECTION_AVAILABLE_INCOMPATIBLE,
                "IWD backend only supports Open and PSK authentication in Ad-Hoc mode");
            return FALSE;
        }
    } else {
        nm_utils_error_set(error,
                           NM_UTILS_ERROR_CONNECTION_AVAILABLE_INCOMPATIBLE,
                           "'%s' type profiles not supported by IWD backend",
                           mode);
        return FALSE;
    }

    return TRUE;
}

static gboolean
check_connection_available(NMDevice *                     device,
                           NMConnection *                 connection,
                           NMDeviceCheckConAvailableFlags flags,
                           const char *                   specific_object,
                           GError **                      error)
{
    NMDeviceIwd *        self = NM_DEVICE_IWD(device);
    NMDeviceIwdPrivate * priv = NM_DEVICE_IWD_GET_PRIVATE(self);
    NMSettingWireless *  s_wifi;
    const char *         mode;
    NMWifiAP *           ap = NULL;
    NMIwdNetworkSecurity security;

    s_wifi = nm_connection_get_setting_wireless(connection);
    g_return_val_if_fail(s_wifi, FALSE);

    /* a connection that is available for a certain @specific_object, MUST
     * also be available in general (without @specific_object). */

    if (specific_object) {
        ap = nm_wifi_ap_lookup_for_device(NM_DEVICE(self), specific_object);
        if (!ap) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "requested access point not found");
            return FALSE;
        }
        if (!nm_wifi_ap_check_compatible(ap, connection)) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "requested access point is not compatible with profile");
            return FALSE;
        }
    }

    /* AP and Ad-Hoc connections can be activated independent of the scan list */
    mode = nm_setting_wireless_get_mode(s_wifi);
    if (NM_IN_STRSET(mode, NM_SETTING_WIRELESS_MODE_AP, NM_SETTING_WIRELESS_MODE_ADHOC))
        return TRUE;

    /* Hidden SSIDs obviously don't always appear in the scan list either.
     *
     * For an explicit user-activation-request, a connection is considered
     * available because for hidden Wi-Fi, clients didn't consistently
     * set the 'hidden' property to indicate hidden SSID networks.  If
     * activating but the network isn't available let the device recheck
     * availability.
     */
    if (nm_setting_wireless_get_hidden(s_wifi)
        || NM_FLAGS_HAS(flags, _NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST_IGNORE_AP))
        return TRUE;

    if (!ap)
        ap = nm_wifi_aps_find_first_compatible(&priv->aps_lst_head, connection);

    if (!ap) {
        nm_utils_error_set_literal(error,
                                   NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                   "no compatible access point found");
        return FALSE;
    }

    /* 8021x networks can only be used if they've been provisioned on the IWD side and
     * thus are Known Networks.
     */
    if (nm_wifi_connection_get_iwd_ssid_and_security(connection, NULL, &security)
        && security == NM_IWD_NETWORK_SECURITY_8021X) {
        if (!is_ap_known_network(ap)) {
            nm_utils_error_set_literal(
                error,
                NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                "802.1x network is not an IWD Known Network (missing provisioning file?)");
            return FALSE;
        }
    }

    return TRUE;
}

/* To be used where the SSID has been validated before */
static char *
iwd_ssid_to_str(const GBytes *ssid)
{
    const guint8 *ssid_bytes;
    gsize         ssid_len;

    ssid_bytes = g_bytes_get_data((GBytes *) ssid, &ssid_len);
    nm_assert(ssid && g_utf8_validate((const char *) ssid_bytes, ssid_len, NULL));
    return g_strndup((const char *) ssid_bytes, ssid_len);
}

static gboolean
complete_connection(NMDevice *           device,
                    NMConnection *       connection,
                    const char *         specific_object,
                    NMConnection *const *existing_connections,
                    GError **            error)
{
    NMDeviceIwd *       self = NM_DEVICE_IWD(device);
    NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE(self);
    NMSettingWireless * s_wifi;
    gs_free char *      ssid_utf8 = NULL;
    NMWifiAP *          ap;
    GBytes *            ssid   = NULL;
    gboolean            hidden = FALSE;
    const char *        mode;

    s_wifi = nm_connection_get_setting_wireless(connection);

    mode = s_wifi ? nm_setting_wireless_get_mode(s_wifi) : NULL;

    if (nm_streq0(mode, NM_SETTING_WIRELESS_MODE_AP) || !specific_object) {
        const guint8 *ssid_bytes;
        gsize         ssid_len;

        /* If not given a specific object, we need at minimum an SSID */
        if (!s_wifi) {
            g_set_error_literal(error,
                                NM_DEVICE_ERROR,
                                NM_DEVICE_ERROR_INVALID_CONNECTION,
                                "A 'wireless' setting is required if no AP path was given.");
            return FALSE;
        }

        ssid       = nm_setting_wireless_get_ssid(s_wifi);
        ssid_bytes = g_bytes_get_data(ssid, &ssid_len);

        if (!ssid || ssid_len == 0 || !g_utf8_validate((const char *) ssid_bytes, ssid_len, NULL)) {
            g_set_error_literal(error,
                                NM_DEVICE_ERROR,
                                NM_DEVICE_ERROR_INVALID_CONNECTION,
                                "A 'wireless' setting with a valid UTF-8 SSID is required if no AP "
                                "path was given.");
            return FALSE;
        }
    }

    if (nm_streq0(mode, NM_SETTING_WIRELESS_MODE_AP)) {
        if (!nm_setting_verify(NM_SETTING(s_wifi), connection, error))
            return FALSE;
        ap = NULL;
    } else if (!specific_object) {
        /* Find a compatible AP in the scan list */
        ap = nm_wifi_aps_find_first_compatible(&priv->aps_lst_head, connection);
        if (!ap) {
            /* If we still don't have an AP, then the WiFI settings needs to be
             * fully specified by the client.  Might not be able to find an AP
             * if the network isn't broadcasting the SSID for example.
             */
            if (!nm_setting_verify(NM_SETTING(s_wifi), connection, error))
                return FALSE;

            /* We could either require the profile to be marked as hidden by the
             * client or at least check that a hidden AP with a matching security
             * type is in range using Station.GetHiddenAccessPoints().  For now
             * assume it is hidden even though that will reveal the SSID on the
             * air.
             */
            hidden = TRUE;
        }
    } else {
        ap = nm_wifi_ap_lookup_for_device(NM_DEVICE(self), specific_object);
        if (!ap) {
            g_set_error(error,
                        NM_DEVICE_ERROR,
                        NM_DEVICE_ERROR_SPECIFIC_OBJECT_NOT_FOUND,
                        "The access point %s was not in the scan list.",
                        specific_object);
            return FALSE;
        }

        ssid = nm_wifi_ap_get_ssid(ap);

        /* Add a wifi setting if one doesn't exist yet */
        if (!s_wifi) {
            s_wifi = (NMSettingWireless *) nm_setting_wireless_new();
            nm_connection_add_setting(connection, NM_SETTING(s_wifi));
        }
    }

    if (ap) {
        if (!nm_wifi_ap_complete_connection(ap, connection, FALSE, error))
            return FALSE;
    }

    ssid_utf8 = iwd_ssid_to_str(ssid);
    nm_utils_complete_generic(
        nm_device_get_platform(device),
        connection,
        NM_SETTING_WIRELESS_SETTING_NAME,
        existing_connections,
        ssid_utf8,
        ssid_utf8,
        NULL,
        nm_setting_wireless_get_mac_address(s_wifi) ? NULL : nm_device_get_iface(device),
        TRUE);

    if (hidden)
        g_object_set(s_wifi, NM_SETTING_WIRELESS_HIDDEN, TRUE, NULL);

    return TRUE;
}

static gboolean
is_available(NMDevice *device, NMDeviceCheckDevAvailableFlags flags)
{
    NMDeviceIwd *       self  = NM_DEVICE_IWD(device);
    NMDeviceIwdPrivate *priv  = NM_DEVICE_IWD_GET_PRIVATE(self);
    NMDeviceState       state = nm_device_get_state(device);

    /* Available if either the device is UP and in station mode
     * or in AP/Ad-Hoc modes while activating or activated.  Device
     * may be temporarily DOWN while activating or deactivating and
     * we don't want it to be marked unavailable because of this.
     *
     * For reference:
     * We call nm_device_queue_recheck_available whenever
     * priv->enabled changes or priv->dbus_station_proxy changes.
     */
    return priv->dbus_obj && priv->enabled
           && (priv->dbus_station_proxy
               || (state >= NM_DEVICE_STATE_CONFIG && state <= NM_DEVICE_STATE_DEACTIVATING));
}

static gboolean
get_autoconnect_allowed(NMDevice *device)
{
    NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE(NM_DEVICE_IWD(device));

    return priv->nm_autoconnect;
}

static gboolean
can_auto_connect(NMDevice *device, NMSettingsConnection *sett_conn, char **specific_object)
{
    NMDeviceIwd *       self = NM_DEVICE_IWD(device);
    NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE(self);
    NMConnection *      connection;
    NMSettingWireless * s_wifi;
    NMWifiAP *          ap;
    const char *        mode;
    guint64             timestamp = 0;

    nm_assert(!specific_object || !*specific_object);

    if (!NM_DEVICE_CLASS(nm_device_iwd_parent_class)->can_auto_connect(device, sett_conn, NULL))
        return FALSE;

    connection = nm_settings_connection_get_connection(sett_conn);

    s_wifi = nm_connection_get_setting_wireless(connection);
    g_return_val_if_fail(s_wifi, FALSE);

    /* Don't auto-activate AP or Ad-Hoc connections.
     * Note the wpa_supplicant backend has the opposite policy.
     */
    mode = nm_setting_wireless_get_mode(s_wifi);
    if (mode && g_strcmp0(mode, NM_SETTING_WIRELESS_MODE_INFRA) != 0)
        return FALSE;

    /* Don't autoconnect to networks that have been tried at least once
     * but haven't been successful, since these are often accidental choices
     * from the menu and the user may not know the password.
     */
    if (nm_settings_connection_get_timestamp(sett_conn, &timestamp)) {
        if (timestamp == 0)
            return FALSE;
    }

    ap = nm_wifi_aps_find_first_compatible(&priv->aps_lst_head, connection);
    if (ap) {
        /* All good; connection is usable */
        NM_SET_OUT(specific_object, g_strdup(nm_dbus_object_get_path(NM_DBUS_OBJECT(ap))));
        return TRUE;
    }

    return FALSE;
}

const CList *
_nm_device_iwd_get_aps(NMDeviceIwd *self)
{
    return &NM_DEVICE_IWD_GET_PRIVATE(self)->aps_lst_head;
}

static void
scan_cb(GObject *source, GAsyncResult *res, gpointer user_data)
{
    NMDeviceIwd *       self = user_data;
    NMDeviceIwdPrivate *priv;
    gs_unref_variant GVariant *variant = NULL;
    gs_free_error GError *error        = NULL;

    variant = g_dbus_proxy_call_finish(G_DBUS_PROXY(source), res, &error);
    if (!variant && nm_utils_error_is_cancelled(error))
        return;

    priv                 = NM_DEVICE_IWD_GET_PRIVATE(self);
    priv->scan_requested = FALSE;
    priv->last_scan      = nm_utils_get_monotonic_timestamp_msec();
    _notify(self, PROP_LAST_SCAN);

    /* On success, priv->scanning becomes true right before or right
     * after this callback, so the next automatic scan will be
     * scheduled when priv->scanning goes back to false.  On error,
     * schedule a retry now.
     */
    if (error && !priv->scanning)
        schedule_periodic_scan(self, FALSE);
}

static void
dbus_request_scan_cb(NMDevice *             device,
                     GDBusMethodInvocation *context,
                     NMAuthSubject *        subject,
                     GError *               error,
                     gpointer               user_data)
{
    NMDeviceIwd *       self = NM_DEVICE_IWD(device);
    NMDeviceIwdPrivate *priv;
    gs_unref_variant GVariant *scan_options = user_data;

    if (error) {
        g_dbus_method_invocation_return_gerror(context, error);
        return;
    }

    if (check_scanning_prohibited(self, FALSE)) {
        g_dbus_method_invocation_return_error_literal(context,
                                                      NM_DEVICE_ERROR,
                                                      NM_DEVICE_ERROR_NOT_ALLOWED,
                                                      "Scanning not allowed at this time");
        return;
    }

    priv = NM_DEVICE_IWD_GET_PRIVATE(self);

    if (!priv->can_scan) {
        g_dbus_method_invocation_return_error_literal(context,
                                                      NM_DEVICE_ERROR,
                                                      NM_DEVICE_ERROR_NOT_ALLOWED,
                                                      "Scanning not allowed while unavailable");
        return;
    }

    if (scan_options) {
        gs_unref_variant GVariant *val = g_variant_lookup_value(scan_options, "ssids", NULL);

        if (val) {
            g_dbus_method_invocation_return_error_literal(context,
                                                          NM_DEVICE_ERROR,
                                                          NM_DEVICE_ERROR_NOT_ALLOWED,
                                                          "'ssid' scan option not supported");
            return;
        }
    }

    if (!priv->scanning && !priv->scan_requested) {
        g_dbus_proxy_call(priv->dbus_station_proxy,
                          "Scan",
                          NULL,
                          G_DBUS_CALL_FLAGS_NONE,
                          -1,
                          priv->cancellable,
                          scan_cb,
                          self);
        priv->scan_requested = TRUE;
    }

    g_dbus_method_invocation_return_value(context, NULL);
}

void
_nm_device_iwd_request_scan(NMDeviceIwd *self, GVariant *options, GDBusMethodInvocation *invocation)
{
    NMDeviceIwdPrivate *priv   = NM_DEVICE_IWD_GET_PRIVATE(self);
    NMDevice *          device = NM_DEVICE(self);

    if (!priv->can_scan) {
        g_dbus_method_invocation_return_error_literal(invocation,
                                                      NM_DEVICE_ERROR,
                                                      NM_DEVICE_ERROR_NOT_ALLOWED,
                                                      "Scanning not allowed while unavailable");
        return;
    }

    nm_device_auth_request(device,
                           invocation,
                           NULL,
                           NM_AUTH_PERMISSION_WIFI_SCAN,
                           TRUE,
                           NULL,
                           dbus_request_scan_cb,
                           nm_g_variant_ref(options));
}

static gboolean
check_scanning_prohibited(NMDeviceIwd *self, gboolean periodic)
{
    NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE(self);

    g_return_val_if_fail(priv->dbus_obj != NULL, TRUE);

    switch (nm_device_get_state(NM_DEVICE(self))) {
    case NM_DEVICE_STATE_UNKNOWN:
    case NM_DEVICE_STATE_UNMANAGED:
    case NM_DEVICE_STATE_UNAVAILABLE:
    case NM_DEVICE_STATE_PREPARE:
    case NM_DEVICE_STATE_CONFIG:
    case NM_DEVICE_STATE_IP_CONFIG:
    case NM_DEVICE_STATE_IP_CHECK:
    case NM_DEVICE_STATE_SECONDARIES:
    case NM_DEVICE_STATE_DEACTIVATING:
        /* Prohibit scans when unusable or activating */
        return TRUE;
    case NM_DEVICE_STATE_DISCONNECTED:
    case NM_DEVICE_STATE_FAILED:
    case NM_DEVICE_STATE_ACTIVATED:
    case NM_DEVICE_STATE_NEED_AUTH:
        break;
    }

    /* Prohibit scans if IWD is busy */
    return !priv->can_scan;
}

static const char *
get_agent_request_network_path(GDBusMethodInvocation *invocation)
{
    const char *method_name  = g_dbus_method_invocation_get_method_name(invocation);
    GVariant *  params       = g_dbus_method_invocation_get_parameters(invocation);
    const char *network_path = NULL;

    if (nm_streq(method_name, "RequestPassphrase"))
        g_variant_get(params, "(&o)", &network_path);
    else if (nm_streq(method_name, "RequestPrivateKeyPassphrase"))
        g_variant_get(params, "(&o)", &network_path);
    else if (nm_streq(method_name, "RequestUserNameAndPassword"))
        g_variant_get(params, "(&o)", &network_path);
    else if (nm_streq(method_name, "RequestUserPassword"))
        g_variant_get(params, "(&os)", &network_path, NULL);

    return network_path;
}

/*
 * try_reply_agent_request
 *
 * Check if the connection settings already have the secrets corresponding
 * to the IWD agent method that was invoked.  If they do, send the method reply
 * with the appropriate secrets.  Otherwise, return the missing secret's setting
 * name and key so the caller can send a NM secrets request with this data.
 * Return TRUE in either case, return FALSE if an error is detected.
 */
static gboolean
try_reply_agent_request(NMDeviceIwd *          self,
                        NMConnection *         connection,
                        GDBusMethodInvocation *invocation,
                        const char **          setting_name,
                        const char **          setting_key,
                        gboolean *             replied)
{
    const char *               method_name = g_dbus_method_invocation_get_method_name(invocation);
    NMSettingWirelessSecurity *s_wireless_sec;
    NMSetting8021x *           s_8021x;

    s_wireless_sec = nm_connection_get_setting_wireless_security(connection);
    s_8021x        = nm_connection_get_setting_802_1x(connection);

    *replied = FALSE;

    if (nm_streq(method_name, "RequestPassphrase")) {
        const char *psk;

        if (!s_wireless_sec)
            return FALSE;

        psk = nm_setting_wireless_security_get_psk(s_wireless_sec);
        if (psk) {
            _LOGD(LOGD_DEVICE | LOGD_WIFI, "Returning the PSK to the IWD Agent");

            g_dbus_method_invocation_return_value(invocation, g_variant_new("(s)", psk));
            *replied = TRUE;
            return TRUE;
        }

        *setting_name = NM_SETTING_WIRELESS_SECURITY_SETTING_NAME;
        *setting_key  = NM_SETTING_WIRELESS_SECURITY_PSK;
        return TRUE;
    } else if (nm_streq(method_name, "RequestPrivateKeyPassphrase")) {
        const char *password;

        if (!s_8021x)
            return FALSE;

        password = nm_setting_802_1x_get_private_key_password(s_8021x);
        if (password) {
            _LOGD(LOGD_DEVICE | LOGD_WIFI, "Returning the private key password to the IWD Agent");

            g_dbus_method_invocation_return_value(invocation, g_variant_new("(s)", password));
            *replied = TRUE;
            return TRUE;
        }

        *setting_name = NM_SETTING_802_1X_SETTING_NAME;
        *setting_key  = NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD;
        return TRUE;
    } else if (nm_streq(method_name, "RequestUserNameAndPassword")) {
        const char *identity, *password;

        if (!s_8021x)
            return FALSE;

        identity = nm_setting_802_1x_get_identity(s_8021x);
        password = nm_setting_802_1x_get_password(s_8021x);
        if (identity && password) {
            _LOGD(LOGD_DEVICE | LOGD_WIFI, "Returning the username and password to the IWD Agent");

            g_dbus_method_invocation_return_value(invocation,
                                                  g_variant_new("(ss)", identity, password));
            *replied = TRUE;
            return TRUE;
        }

        *setting_name = NM_SETTING_802_1X_SETTING_NAME;
        if (!identity)
            *setting_key = NM_SETTING_802_1X_IDENTITY;
        else
            *setting_key = NM_SETTING_802_1X_PASSWORD;
        return TRUE;
    } else if (nm_streq(method_name, "RequestUserPassword")) {
        const char *password;

        if (!s_8021x)
            return FALSE;

        password = nm_setting_802_1x_get_password(s_8021x);
        if (password) {
            _LOGD(LOGD_DEVICE | LOGD_WIFI, "Returning the user password to the IWD Agent");

            g_dbus_method_invocation_return_value(invocation, g_variant_new("(s)", password));
            *replied = TRUE;
            return TRUE;
        }

        *setting_name = NM_SETTING_802_1X_SETTING_NAME;
        *setting_key  = NM_SETTING_802_1X_PASSWORD;
        return TRUE;
    } else
        return FALSE;
}

static gboolean
assumed_ac_timeout_cb(gpointer user_data)
{
    NMDeviceIwd *       self = user_data;
    NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE(self);

    nm_assert(priv->assumed_ac);

    priv->assumed_ac_timeout = 0;
    nm_device_state_changed(NM_DEVICE(self),
                            NM_DEVICE_STATE_FAILED,
                            NM_DEVICE_STATE_REASON_SUPPLICANT_TIMEOUT);
    /* NMDevice's state change -> NMActRequests/NMActiveConnection's state
     * change -> assumed_connection_state_changed_before_managed() ->
     * cleanup_association_attempt() so no need to call it explicitly.
     */
    return G_SOURCE_REMOVE;
}

static void wifi_secrets_get_one(NMDeviceIwd *                self,
                                 const char *                 setting_name,
                                 NMSecretAgentGetSecretsFlags flags,
                                 const char *                 setting_key,
                                 GDBusMethodInvocation *      invocation);

static void
wifi_secrets_cb(NMActRequest *                req,
                NMActRequestGetSecretsCallId *call_id,
                NMSettingsConnection *        s_connection,
                GError *                      error,
                gpointer                      user_data)
{
    NMDeviceIwd *                self;
    NMDeviceIwdPrivate *         priv;
    NMDevice *                   device;
    GDBusMethodInvocation *      invocation;
    const char *                 setting_name;
    const char *                 setting_key;
    gboolean                     replied;
    NMSecretAgentGetSecretsFlags get_secret_flags =
        NM_SECRET_AGENT_GET_SECRETS_FLAG_ALLOW_INTERACTION;

    nm_utils_user_data_unpack(user_data, &self, &invocation);

    g_return_if_fail(NM_IS_DEVICE_IWD(self));

    priv   = NM_DEVICE_IWD_GET_PRIVATE(self);
    device = NM_DEVICE(self);

    g_return_if_fail(priv->wifi_secrets_id == call_id);

    priv->wifi_secrets_id = NULL;

    if (nm_utils_error_is_cancelled(error)) {
        priv->secrets_failed = TRUE;
        g_dbus_method_invocation_return_error_literal(invocation,
                                                      NM_DEVICE_ERROR,
                                                      NM_DEVICE_ERROR_INVALID_CONNECTION,
                                                      "NM secrets request cancelled");
        return;
    }

    g_return_if_fail(req == nm_device_get_act_request(device));
    g_return_if_fail(nm_act_request_get_settings_connection(req) == s_connection);

    if (nm_device_get_state(device) != NM_DEVICE_STATE_NEED_AUTH)
        goto secrets_error;

    if (error) {
        _LOGW(LOGD_WIFI, "%s", error->message);
        goto secrets_error;
    }

    if (!try_reply_agent_request(self,
                                 nm_act_request_get_applied_connection(req),
                                 invocation,
                                 &setting_name,
                                 &setting_key,
                                 &replied))
        goto secrets_error;

    if (replied) {
        /* If we replied to the secrets request from IWD in the "disconnected"
         * state and IWD doesn't move to a new state within 1 second, assume
         * something went wrong (shouldn't happen).  If a state change arrives
         * after that nothing is lost, state_changed() will try to assume the
         * connection again.
         */
        if (priv->assumed_ac) {
            gs_unref_variant GVariant *value =
                g_dbus_proxy_get_cached_property(priv->dbus_station_proxy, "State");

            if (nm_streq(get_variant_state(value), "disconnected"))
                priv->assumed_ac_timeout = g_timeout_add_seconds(1, assumed_ac_timeout_cb, self);
        }

        /* Change state back to what it was before NEED_AUTH */
        nm_device_state_changed(device, NM_DEVICE_STATE_CONFIG, NM_DEVICE_STATE_REASON_NONE);
        return;
    }

    if (nm_settings_connection_get_timestamp(nm_act_request_get_settings_connection(req), NULL))
        get_secret_flags |= NM_SECRET_AGENT_GET_SECRETS_FLAG_REQUEST_NEW;

    /* Request further secrets if we still need something */
    wifi_secrets_get_one(self, setting_name, get_secret_flags, setting_key, invocation);
    return;

secrets_error:
    g_dbus_method_invocation_return_error_literal(invocation,
                                                  NM_DEVICE_ERROR,
                                                  NM_DEVICE_ERROR_INVALID_CONNECTION,
                                                  "NM secrets request failed");

    if (priv->assumed_ac) {
        nm_device_state_changed(device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_NO_SECRETS);
        /* NMDevice's state change -> NMActRequests/NMActiveConnection's state
         * change -> assumed_connection_state_changed_before_managed() ->
         * cleanup_association_attempt() so no need to call it explicitly.
         */
    } else {
        priv->secrets_failed = TRUE;
        /* Now wait for the Connect callback to update device state */
    }
}

static void
wifi_secrets_get_one(NMDeviceIwd *                self,
                     const char *                 setting_name,
                     NMSecretAgentGetSecretsFlags flags,
                     const char *                 setting_key,
                     GDBusMethodInvocation *      invocation)
{
    NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE(self);
    NMActRequest *      req;

    wifi_secrets_cancel(self);

    req = nm_device_get_act_request(NM_DEVICE(self));
    g_return_if_fail(NM_IS_ACT_REQUEST(req));

    priv->wifi_secrets_id = nm_act_request_get_secrets(req,
                                                       TRUE,
                                                       setting_name,
                                                       flags,
                                                       NM_MAKE_STRV(setting_key),
                                                       wifi_secrets_cb,
                                                       nm_utils_user_data_pack(self, invocation));
}

static void
network_connect_cb(GObject *source, GAsyncResult *res, gpointer user_data)
{
    NMDeviceIwd *       self           = user_data;
    NMDevice *          device         = NM_DEVICE(self);
    NMDeviceIwdPrivate *priv           = NM_DEVICE_IWD_GET_PRIVATE(self);
    gs_unref_variant GVariant *variant = NULL;
    gs_free_error GError *error        = NULL;
    NMConnection *        connection;
    gs_free char *        ssid   = NULL;
    NMDeviceStateReason   reason = NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED;
    GVariant *            value;
    gboolean              disconnect;

    disconnect = !priv->iwd_autoconnect
                 || nm_device_autoconnect_blocked_get(device, NM_DEVICE_AUTOCONNECT_BLOCKED_ALL);

    variant = g_dbus_proxy_call_finish(G_DBUS_PROXY(source), res, &error);
    if (!variant) {
        gs_free char *dbus_error = NULL;

        /* Connection failed; radio problems or if the network wasn't
         * open, the passwords or certificates may be wrong.
         */

        _LOGE(LOGD_DEVICE | LOGD_WIFI,
              "Activation: (wifi) Network.Connect failed: %s",
              error->message);

        if (nm_utils_error_is_cancelled(error))
            return;

        if (!NM_IN_SET(nm_device_get_state(device),
                       NM_DEVICE_STATE_CONFIG,
                       NM_DEVICE_STATE_NEED_AUTH))
            return;

        connection = nm_device_get_applied_connection(device);
        if (!connection)
            goto failed;

        if (g_error_matches(error, G_IO_ERROR, G_IO_ERROR_DBUS_ERROR))
            dbus_error = g_dbus_error_get_remote_error(error);

        if (nm_streq0(dbus_error, "net.connman.iwd.Failed")) {
            nm_connection_clear_secrets(connection);

            /* If secrets were wrong, we'd be getting a net.connman.iwd.Failed */
            reason = NM_DEVICE_STATE_REASON_NO_SECRETS;
        } else if (nm_streq0(dbus_error, "net.connman.iwd.Aborted") && priv->secrets_failed) {
            /* If agent call was cancelled we'd be getting a net.connman.iwd.Aborted */
            reason = NM_DEVICE_STATE_REASON_NO_SECRETS;
        }

        goto failed;
    }

    nm_assert(nm_device_get_state(device) == NM_DEVICE_STATE_CONFIG);

    disconnect = TRUE;

    connection = nm_device_get_applied_connection(device);
    if (!connection)
        goto failed;

    if (!nm_wifi_connection_get_iwd_ssid_and_security(connection, &ssid, NULL))
        goto failed;

    _LOGI(LOGD_DEVICE | LOGD_WIFI,
          "Activation: (wifi) Stage 2 of 5 (Device Configure) successful.  Connected to '%s'.",
          ssid);
    nm_device_activate_schedule_stage3_ip_config_start(device);

    return;

failed:
    /* If necessary call Disconnect to make sure IWD's autoconnect is disabled */
    cleanup_association_attempt(self, disconnect);

    nm_device_state_changed(device, NM_DEVICE_STATE_FAILED, reason);

    value = g_dbus_proxy_get_cached_property(priv->dbus_station_proxy, "State");
    if (!priv->iwd_autoconnect && nm_streq(get_variant_state(value), "disconnected")) {
        schedule_periodic_scan(self, TRUE);

        if (!priv->nm_autoconnect) {
            priv->nm_autoconnect = true;
            nm_device_emit_recheck_auto_activate(device);
        }
    }
    g_variant_unref(value);
}

static void
act_failed_cb(GObject *source, GAsyncResult *res, gpointer user_data)
{
    NMDeviceIwd *    self              = user_data;
    NMDevice *       device            = NM_DEVICE(self);
    gs_unref_variant GVariant *variant = NULL;
    gs_free_error GError *error        = NULL;

    variant = g_dbus_proxy_call_finish(G_DBUS_PROXY(source), res, &error);
    if (!variant && nm_utils_error_is_cancelled(error))
        return;

    /* Change state to FAILED unless already done by state_changed
     * which may have been triggered by the station interface
     * appearing on DBus.
     */
    if (nm_device_get_state(device) == NM_DEVICE_STATE_CONFIG)
        nm_device_queue_state(device,
                              NM_DEVICE_STATE_FAILED,
                              NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
}

static void
act_start_cb(GObject *source, GAsyncResult *res, gpointer user_data)
{
    NMDeviceIwd *       self           = user_data;
    NMDeviceIwdPrivate *priv           = NM_DEVICE_IWD_GET_PRIVATE(self);
    NMDevice *          device         = NM_DEVICE(self);
    gs_unref_variant GVariant *variant = NULL;
    gs_free_error GError *error        = NULL;
    gs_free char *        ssid         = NULL;

    variant = g_dbus_proxy_call_finish(G_DBUS_PROXY(source), res, &error);
    if (!variant) {
        _LOGE(LOGD_DEVICE | LOGD_WIFI,
              "Activation: (wifi) {AccessPoint,AdHoc}.Start() failed: %s",
              error->message);

        if (nm_utils_error_is_cancelled(error))
            return;

        if (!NM_IN_SET(nm_device_get_state(device), NM_DEVICE_STATE_CONFIG))
            return;

        goto error;
    }

    nm_assert(nm_device_get_state(device) == NM_DEVICE_STATE_CONFIG);

    if (!nm_wifi_connection_get_iwd_ssid_and_security(nm_device_get_applied_connection(device),
                                                      &ssid,
                                                      NULL))
        goto error;

    _LOGI(LOGD_DEVICE | LOGD_WIFI,
          "Activation: (wifi) Stage 2 of 5 (Device Configure) successful.  Started '%s'.",
          ssid);
    nm_device_activate_schedule_stage3_ip_config_start(device);

    return;

error:
    reset_mode(self, priv->cancellable, act_failed_cb, self);
}

/* Check if we're activating an AP/AdHoc connection and if the target
 * DBus interface has appeared already.  If so proceed to call Start or
 * StartOpen on that interface.
 */
static void
act_check_interface(NMDeviceIwd *self)
{
    NMDeviceIwdPrivate * priv   = NM_DEVICE_IWD_GET_PRIVATE(self);
    NMDevice *           device = NM_DEVICE(self);
    NMSettingWireless *  s_wireless;
    GDBusProxy *         proxy = NULL;
    gs_free char *       ssid  = NULL;
    const char *         mode;
    NMIwdNetworkSecurity security;

    if (!priv->act_mode_switch)
        return;

    s_wireless =
        (NMSettingWireless *) nm_device_get_applied_setting(device, NM_TYPE_SETTING_WIRELESS);

    mode = nm_setting_wireless_get_mode(s_wireless);
    if (nm_streq0(mode, NM_SETTING_WIRELESS_MODE_AP))
        proxy = priv->dbus_ap_proxy;
    else if (nm_streq0(mode, NM_SETTING_WIRELESS_MODE_ADHOC))
        proxy = priv->dbus_adhoc_proxy;

    if (!proxy)
        return;

    priv->act_mode_switch = FALSE;

    if (!NM_IN_SET(nm_device_get_state(device), NM_DEVICE_STATE_CONFIG))
        return;

    if (!nm_wifi_connection_get_iwd_ssid_and_security(nm_device_get_applied_connection(device),
                                                      &ssid,
                                                      &security))
        goto failed;

    if (security == NM_IWD_NETWORK_SECURITY_OPEN) {
        g_dbus_proxy_call(proxy,
                          "StartOpen",
                          g_variant_new("(s)", ssid),
                          G_DBUS_CALL_FLAGS_NONE,
                          G_MAXINT,
                          priv->cancellable,
                          act_start_cb,
                          self);
    } else if (security == NM_IWD_NETWORK_SECURITY_PSK) {
        NMSettingWirelessSecurity *s_wireless_sec;
        const char *               psk;

        s_wireless_sec = (NMSettingWirelessSecurity *) nm_device_get_applied_setting(
            device,
            NM_TYPE_SETTING_WIRELESS_SECURITY);
        psk = nm_setting_wireless_security_get_psk(s_wireless_sec);

        if (!psk) {
            _LOGE(LOGD_DEVICE | LOGD_WIFI, "Activation: (wifi) No PSK for '%s'.", ssid);
            goto failed;
        }

        g_dbus_proxy_call(proxy,
                          "Start",
                          g_variant_new("(ss)", ssid, psk),
                          G_DBUS_CALL_FLAGS_NONE,
                          G_MAXINT,
                          priv->cancellable,
                          act_start_cb,
                          self);
    } else
        goto failed;

    _LOGD(LOGD_DEVICE | LOGD_WIFI, "Activation: (wifi) Called Start('%s').", ssid);
    return;

failed:
    reset_mode(self, priv->cancellable, act_failed_cb, self);
}

static void
act_set_mode_cb(GObject *source, GAsyncResult *res, gpointer user_data)
{
    NMDeviceIwd *       self           = user_data;
    NMDeviceIwdPrivate *priv           = NM_DEVICE_IWD_GET_PRIVATE(self);
    NMDevice *          device         = NM_DEVICE(self);
    gs_unref_variant GVariant *variant = NULL;
    gs_free_error GError *error        = NULL;

    variant = g_dbus_proxy_call_finish(G_DBUS_PROXY(source), res, &error);
    if (!variant) {
        _LOGE(LOGD_DEVICE | LOGD_WIFI,
              "Activation: (wifi) Setting Device.Mode failed: %s",
              error->message);

        if (nm_utils_error_is_cancelled(error))
            return;

        if (!NM_IN_SET(nm_device_get_state(device), NM_DEVICE_STATE_CONFIG)
            || !priv->act_mode_switch)
            return;

        priv->act_mode_switch = FALSE;
        nm_device_queue_state(device,
                              NM_DEVICE_STATE_FAILED,
                              NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
        return;
    }

    _LOGD(LOGD_DEVICE | LOGD_WIFI, "Activation: (wifi) IWD Device.Mode set successfully");

    act_check_interface(self);
}

static void
act_set_mode(NMDeviceIwd *self)
{
    NMDeviceIwdPrivate *priv   = NM_DEVICE_IWD_GET_PRIVATE(self);
    NMDevice *          device = NM_DEVICE(self);
    const char *        iwd_mode;
    const char *        mode;
    NMSettingWireless * s_wireless;

    s_wireless =
        (NMSettingWireless *) nm_device_get_applied_setting(device, NM_TYPE_SETTING_WIRELESS);
    mode = nm_setting_wireless_get_mode(s_wireless);

    /* We need to first set interface mode (Device.Mode) to ap or ad-hoc.
     * We can't directly queue a call to the Start/StartOpen method on
     * the DBus interface that's going to be created after the property
     * set call returns.
     */
    iwd_mode = nm_streq(mode, NM_SETTING_WIRELESS_MODE_AP) ? "ap" : "ad-hoc";

    if (!priv->cancellable)
        priv->cancellable = g_cancellable_new();

    g_dbus_proxy_call(
        priv->dbus_device_proxy,
        DBUS_INTERFACE_PROPERTIES ".Set",
        g_variant_new("(ssv)", NM_IWD_DEVICE_INTERFACE, "Mode", g_variant_new("s", iwd_mode)),
        G_DBUS_CALL_FLAGS_NONE,
        2000,
        priv->cancellable,
        act_set_mode_cb,
        self);
    priv->act_mode_switch = TRUE;
}

static void
act_psk_cb(NMActRequest *                req,
           NMActRequestGetSecretsCallId *call_id,
           NMSettingsConnection *        s_connection,
           GError *                      error,
           gpointer                      user_data)
{
    NMDeviceIwd *       self = user_data;
    NMDeviceIwdPrivate *priv;
    NMDevice *          device;

    if (nm_utils_error_is_cancelled(error))
        return;

    priv   = NM_DEVICE_IWD_GET_PRIVATE(self);
    device = NM_DEVICE(self);

    g_return_if_fail(priv->wifi_secrets_id == call_id);
    priv->wifi_secrets_id = NULL;

    g_return_if_fail(req == nm_device_get_act_request(device));
    g_return_if_fail(nm_act_request_get_settings_connection(req) == s_connection);

    if (nm_device_get_state(device) != NM_DEVICE_STATE_NEED_AUTH)
        goto secrets_error;

    if (error) {
        _LOGW(LOGD_WIFI, "%s", error->message);
        goto secrets_error;
    }

    _LOGD(LOGD_DEVICE | LOGD_WIFI, "Activation: (wifi) missing PSK request completed");

    /* Change state back to what it was before NEED_AUTH */
    nm_device_state_changed(device, NM_DEVICE_STATE_CONFIG, NM_DEVICE_STATE_REASON_NONE);
    act_set_mode(self);
    return;

secrets_error:
    nm_device_state_changed(device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_NO_SECRETS);
    cleanup_association_attempt(self, FALSE);
}

static void
set_powered(NMDeviceIwd *self, gboolean powered)
{
    NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE(self);

    g_dbus_proxy_call(
        priv->dbus_device_proxy,
        DBUS_INTERFACE_PROPERTIES ".Set",
        g_variant_new("(ssv)", NM_IWD_DEVICE_INTERFACE, "Powered", g_variant_new("b", powered)),
        G_DBUS_CALL_FLAGS_NONE,
        2000,
        NULL,
        NULL,
        NULL);
}

/*****************************************************************************/

static NMWifiAP *
find_ap_by_supplicant_path(NMDeviceIwd *self, const NMRefString *path)
{
    NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE(self);
    NMWifiAP *          tmp;

    c_list_for_each_entry (tmp, &priv->aps_lst_head, aps_lst)
        if (nm_wifi_ap_get_supplicant_path(tmp) == path)
            return tmp;

    return NULL;
}

static void
assumed_connection_state_changed(NMActiveConnection *active, GParamSpec *pspec, NMDeviceIwd *self)
{
    NMSettingsConnection *  sett_conn = nm_active_connection_get_settings_connection(active);
    NMActiveConnectionState state     = nm_active_connection_get_state(active);

    /* Delete the temporary connection created for an external IWD connection
     * (triggered by somebody outside of NM, be it IWD autoconnect or a
     * parallel client), unless it's been referenced by a Known Network
     * object since, which would remove the EXTERNAL flag.
     *
     * Note we can't do this too early, e.g. at the same time that we're
     * setting the device state to FAILED or DISCONNECTING because the
     * connection shouldn't disappear while it's still being used.  We do
     * this on the connection's transition to DEACTIVATED same as as
     * NMManager does for external activations.
     */
    if (state != NM_ACTIVE_CONNECTION_STATE_DEACTIVATED)
        return;

    g_signal_handlers_disconnect_by_func(active, assumed_connection_state_changed, NULL);

    if (sett_conn
        && NM_FLAGS_HAS(nm_settings_connection_get_flags(sett_conn),
                        NM_SETTINGS_CONNECTION_INT_FLAGS_EXTERNAL))
        nm_settings_connection_delete(sett_conn, FALSE);
}

static void
assumed_connection_state_changed_before_managed(NMActiveConnection *active,
                                                GParamSpec *        pspec,
                                                NMDeviceIwd *       self)
{
    NMDeviceIwdPrivate *    priv  = NM_DEVICE_IWD_GET_PRIVATE(self);
    NMActiveConnectionState state = nm_active_connection_get_state(active);
    gboolean                disconnect;

    if (state != NM_ACTIVE_CONNECTION_STATE_DEACTIVATED)
        return;

    /* When an assumed connection fails we always get called, even if the
     * activation hasn't reached PREPARE or CONFIG, e.g. because of a policy
     * or authorization problem in NMManager.  .deactivate would only be
     * called starting at some stage so we can't rely on that.
     *
     * If the error happened before PREPARE (where we set a non-NULL
     * priv->current_ap) that will mean NM is somehow blocking autoconnect
     * so we want to call IWD's Station.Disconnect() to block its
     * autoconnect.  If this happens during or after PREPARE, we just
     * clean up and wait for a new attempt by IWD.
     *
     * cleanup_association_attempt will clear priv->assumed_ac, disconnect
     * this callback from the signal and also send a Disconnect to IWD if
     * needed.
     *
     * Note this function won't be called after IWD transitions to
     * "connected" (and NMDevice to IP_CONFIG) as we disconnect from the
     * signal at that point, cleanup_association_attempt() will be
     * triggered by an IWD state change instead.
     */
    disconnect = !priv->current_ap;
    cleanup_association_attempt(self, disconnect);
}

static void
assume_connection(NMDeviceIwd *self, NMWifiAP *ap)
{
    NMDeviceIwdPrivate *  priv = NM_DEVICE_IWD_GET_PRIVATE(self);
    NMSettingsConnection *sett_conn;
    gs_unref_object NMAuthSubject *subject = NULL;
    NMActiveConnection *           ac;
    gs_free_error GError *error = NULL;

    /* We can use the .update_connection / nm_device_emit_recheck_assume
     * API but we can also pass an assumed/external activation type
     * directly to nm_manager_activate_connection() and skip the
     * complicated process of creating a matching connection, taking
     * advantage of the Known Networks pointing directly to a mirror
     * connection.  The only downside seems to be
     * nm_manager_activate_connection() goes through the extra
     * authorization.
     *
     * However for now we implement a similar behaviour using a normal
     * "managed" activation.  For one, assumed/external
     * connection state is not reflected in nm_manager_get_state() until
     * fully activated.  Secondly setting the device state to FAILED
     * is treated as ACTIVATED so we'd have to find another way to signal
     * that stage2 is failing asynchronously.  Thirdly the connection
     * becomes "managed" only when ACTIVATED but for IWD it's really
     * managed when IP_CONFIG starts.
     */
    sett_conn = nm_iwd_manager_get_ap_mirror_connection(nm_iwd_manager_get(), ap);
    if (!sett_conn)
        goto error;

    subject = nm_auth_subject_new_internal();
    ac      = nm_manager_activate_connection(
        NM_MANAGER_GET,
        sett_conn,
        NULL,
        nm_dbus_object_get_path(NM_DBUS_OBJECT(ap)),
        NM_DEVICE(self),
        subject,
        NM_ACTIVATION_TYPE_MANAGED,
        NM_ACTIVATION_REASON_ASSUME,
        NM_ACTIVATION_STATE_FLAG_LIFETIME_BOUND_TO_PROFILE_VISIBILITY,
        &error);

    if (!ac) {
        _LOGW(LOGD_WIFI, "Activation: (wifi) assume error: %s", error->message);
        goto error;
    }

    /* If no Known Network existed for this AP, we generated a temporary
     * NMSettingsConnection with the EXTERNAL flag.  It is not referenced by
     * any Known Network objects at this time so we want to delete it if the
     * IWD connection ends up failing or a later part of the activation fails
     * before IWD created a Known Network.
     * Setting the activation type to EXTERNAL would do this by causing
     * NM_ACTIVATION_STATE_FLAG_EXTERNAL to be set on the NMActiveConnection
     * but we don't want the connection to be marked EXTERNAL because we
     * will be assuming the ownership of it in IP_CONFIG or thereabouts.
     *
     * This callback stays connected forever while the second one gets
     * disconnected when we reset the activation type to managed.
     */
    g_signal_connect(ac,
                     "notify::" NM_ACTIVE_CONNECTION_STATE,
                     G_CALLBACK(assumed_connection_state_changed),
                     NULL);
    g_signal_connect(ac,
                     "notify::" NM_ACTIVE_CONNECTION_STATE,
                     G_CALLBACK(assumed_connection_state_changed_before_managed),
                     self);
    priv->assumed_ac = g_object_ref(ac);

    return;

error:
    send_disconnect(self);

    if (sett_conn
        && NM_FLAGS_HAS(nm_settings_connection_get_flags(sett_conn),
                        NM_SETTINGS_CONNECTION_INT_FLAGS_EXTERNAL))
        nm_settings_connection_delete(sett_conn, FALSE);
}

static void
assumed_connection_progress_to_ip_config(NMDeviceIwd *self, gboolean was_postponed)
{
    NMDeviceIwdPrivate *priv      = NM_DEVICE_IWD_GET_PRIVATE(self);
    NMDevice *          device    = NM_DEVICE(self);
    NMDeviceState       dev_state = nm_device_get_state(device);

    wifi_secrets_cancel(self);
    nm_clear_g_source(&priv->assumed_ac_timeout);

    /* NM takes over the activation from this point on so clear the assumed
     * activation state and if we were using NM_ACTIVATION_TYPE_ASSUMED or
     * _EXTERNAL we'd need to reset the activation type to _MANAGED at this
     * point instead of waiting for the ACTIVATED state (as done in
     * nm_active_connection_set_state).
     */
    cleanup_assumed_connect(self);

    if (dev_state == NM_DEVICE_STATE_NEED_AUTH)
        nm_device_state_changed(NM_DEVICE(self),
                                NM_DEVICE_STATE_CONFIG,
                                NM_DEVICE_STATE_REASON_NONE);

    /* If stage2 had returned NM_ACT_STAGE_RETURN_POSTPONE, we tell NMDevice
     * that stage2 is done.
     */
    if (was_postponed)
        nm_device_activate_schedule_stage3_ip_config_start(NM_DEVICE(self));
}

static void
initial_check_assume(NMDeviceIwd *self)
{
    NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE(self);
    const char *        network_path_str;
    nm_auto_ref_string NMRefString *network_path = NULL;
    NMWifiAP *                      ap           = NULL;
    gs_unref_variant GVariant *state_value =
        g_dbus_proxy_get_cached_property(priv->dbus_station_proxy, "State");
    gs_unref_variant GVariant *cn_value =
        g_dbus_proxy_get_cached_property(priv->dbus_station_proxy, "ConnectedNetwork");

    if (!NM_IN_STRSET(get_variant_state(state_value), "connecting", "connected", "roaming"))
        return;

    if (!priv->iwd_autoconnect) {
        send_disconnect(self);
        return;
    }

    if (!cn_value || !g_variant_is_of_type(cn_value, G_VARIANT_TYPE_OBJECT_PATH)) {
        _LOGW(LOGD_DEVICE | LOGD_WIFI,
              "ConnectedNetwork property not cached or not an object path");
        return;
    }

    network_path_str = g_variant_get_string(cn_value, NULL);
    network_path     = nm_ref_string_new(network_path_str);
    ap               = find_ap_by_supplicant_path(self, network_path);

    if (!ap) {
        _LOGW(LOGD_DEVICE | LOGD_WIFI,
              "ConnectedNetwork points to an unknown Network %s",
              network_path_str);
        return;
    }

    _LOGD(LOGD_DEVICE | LOGD_WIFI, "assuming connection in initial_check_assume");
    assume_connection(self, ap);
}

static NMActStageReturn
act_stage1_prepare(NMDevice *device, NMDeviceStateReason *out_failure_reason)
{
    NMDeviceIwd *       self          = NM_DEVICE_IWD(device);
    NMDeviceIwdPrivate *priv          = NM_DEVICE_IWD_GET_PRIVATE(self);
    NMWifiAP *          ap            = NULL;
    gs_unref_object NMWifiAP *ap_fake = NULL;
    NMActRequest *            req;
    NMConnection *            connection;
    NMSettingWireless *       s_wireless;
    const char *              mode;
    const char *              ap_path;

    req = nm_device_get_act_request(device);
    g_return_val_if_fail(req, NM_ACT_STAGE_RETURN_FAILURE);

    connection = nm_act_request_get_applied_connection(req);
    g_return_val_if_fail(connection, NM_ACT_STAGE_RETURN_FAILURE);

    s_wireless = nm_connection_get_setting_wireless(connection);
    g_return_val_if_fail(s_wireless, NM_ACT_STAGE_RETURN_FAILURE);

    /* AP, Ad-Hoc modes never use a specific object or existing scanned AP */
    mode = nm_setting_wireless_get_mode(s_wireless);
    if (NM_IN_STRSET(mode, NM_SETTING_WIRELESS_MODE_AP, NM_SETTING_WIRELESS_MODE_ADHOC))
        goto add_new;

    ap_path = nm_active_connection_get_specific_object(NM_ACTIVE_CONNECTION(req));
    ap      = ap_path ? nm_wifi_ap_lookup_for_device(NM_DEVICE(self), ap_path) : NULL;
    if (ap) {
        set_current_ap(self, ap, TRUE);
        return NM_ACT_STAGE_RETURN_SUCCESS;
    }

    ap = nm_wifi_aps_find_first_compatible(&priv->aps_lst_head, connection);
    if (ap) {
        nm_active_connection_set_specific_object(NM_ACTIVE_CONNECTION(req),
                                                 nm_dbus_object_get_path(NM_DBUS_OBJECT(ap)));
        set_current_ap(self, ap, TRUE);
        return NM_ACT_STAGE_RETURN_SUCCESS;
    }

    /* In infrastructure mode the specific object should be set by now except
     * for a first-time connection to a hidden network.  If a hidden network is
     * a Known Network it should still have been in the AP list.
     */
    if (!nm_setting_wireless_get_hidden(s_wireless) || is_connection_known_network(connection))
        return NM_ACT_STAGE_RETURN_FAILURE;

add_new:
    /* If the user is trying to connect to an AP that NM doesn't yet know about
     * (hidden network or something) or starting a Hotspot, create a fake AP
     * from the security settings in the connection.  This "fake" AP gets used
     * until the real one is found in the scan list (Ad-Hoc or Hidden), or until
     * the device is deactivated (Ad-Hoc or Hotspot).
     */
    ap_fake = nm_wifi_ap_new_fake_from_connection(connection);
    if (!ap_fake)
        g_return_val_if_reached(NM_ACT_STAGE_RETURN_FAILURE);

    if (nm_wifi_ap_is_hotspot(ap_fake))
        nm_wifi_ap_set_address(ap_fake, nm_device_get_hw_address(device));

    g_object_freeze_notify(G_OBJECT(self));
    ap_add_remove(self, TRUE, ap_fake, FALSE);
    g_object_thaw_notify(G_OBJECT(self));
    set_current_ap(self, ap_fake, FALSE);
    nm_active_connection_set_specific_object(NM_ACTIVE_CONNECTION(req),
                                             nm_dbus_object_get_path(NM_DBUS_OBJECT(ap_fake)));
    return NM_ACT_STAGE_RETURN_SUCCESS;
}

static NMActStageReturn
act_stage2_config(NMDevice *device, NMDeviceStateReason *out_failure_reason)
{
    NMDeviceIwd *       self = NM_DEVICE_IWD(device);
    NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE(self);
    NMActRequest *      req;
    NMConnection *      connection;
    NMSettingWireless * s_wireless;
    const char *        mode;

    req        = nm_device_get_act_request(device);
    connection = nm_act_request_get_applied_connection(req);
    s_wireless = nm_connection_get_setting_wireless(connection);
    g_return_val_if_fail(s_wireless, NM_ACT_STAGE_RETURN_FAILURE);

    mode = nm_setting_wireless_get_mode(s_wireless);

    if (NM_IN_STRSET(mode, NULL, NM_SETTING_WIRELESS_MODE_INFRA)) {
        gs_unref_object GDBusProxy *network_proxy = NULL;
        NMWifiAP *                  ap            = priv->current_ap;
        NMSettingWirelessSecurity * s_wireless_sec;

        if (!ap) {
            NM_SET_OUT(out_failure_reason, NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
            goto out_fail;
        }

        /* With priv->iwd_autoconnect, if we're assuming a connection because
         * of a state change to "connecting", signal stage 2 is still running.
         * If "connected" or "roaming", we can go right to the IP_CONFIG state
         * and there's nothing left to do in CONFIG.
         * If we're assuming the connection because of an agent request we
         * switch to NEED_AUTH and actually send the request now that we
         * have an activation request.
         *
         * This all assumes ConnectedNetwork hasn't changed.
         */
        if (priv->assumed_ac) {
            gboolean result;

            if (!priv->pending_agent_request) {
                gs_unref_variant GVariant *value =
                    g_dbus_proxy_get_cached_property(priv->dbus_station_proxy, "State");

                if (nm_streq(get_variant_state(value), "connecting")) {
                    return NM_ACT_STAGE_RETURN_POSTPONE;
                } else {
                    /* This basically forgets that the connection was "assumed"
                     * as we can treat it like any connection triggered by a
                     * Network.Connect() call from now on.
                     */
                    assumed_connection_progress_to_ip_config(self, FALSE);
                    return NM_ACT_STAGE_RETURN_SUCCESS;
                }
            }

            result = nm_device_iwd_agent_query(self, priv->pending_agent_request);
            g_clear_object(&priv->pending_agent_request);
            nm_assert(result);

            return NM_ACT_STAGE_RETURN_POSTPONE;
        }

        /* 802.1x networks that are not IWD Known Networks will definitely
         * fail, for other combinations we will let the Connect call fail
         * or ask us for any missing secrets through the Agent.
         */
        if (nm_connection_get_setting_802_1x(connection) && !is_ap_known_network(ap)) {
            _LOGI(LOGD_DEVICE | LOGD_WIFI,
                  "Activation: (wifi) access point '%s' has 802.1x security but is not configured "
                  "in IWD.",
                  nm_connection_get_id(connection));

            NM_SET_OUT(out_failure_reason, NM_DEVICE_STATE_REASON_NO_SECRETS);
            goto out_fail;
        }

        priv->secrets_failed = FALSE;

        if (nm_wifi_ap_get_fake(ap)) {
            gs_free char *ssid = NULL;

            if (!nm_setting_wireless_get_hidden(s_wireless)) {
                _LOGW(LOGD_DEVICE | LOGD_WIFI,
                      "Activation: (wifi) target network not known to IWD but is not "
                      "marked hidden");
                NM_SET_OUT(out_failure_reason, NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
                goto out_fail;
            }

            if (!nm_wifi_connection_get_iwd_ssid_and_security(connection, &ssid, NULL)) {
                NM_SET_OUT(out_failure_reason, NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
                goto out_fail;
            }

            /* Use Station.ConnectHiddenNetwork method instead of Network proxy. */
            g_dbus_proxy_call(priv->dbus_station_proxy,
                              "ConnectHiddenNetwork",
                              g_variant_new("(s)", ssid),
                              G_DBUS_CALL_FLAGS_NONE,
                              G_MAXINT,
                              priv->cancellable,
                              network_connect_cb,
                              self);
            return NM_ACT_STAGE_RETURN_POSTPONE;
        }

        network_proxy = nm_iwd_manager_get_dbus_interface(
            nm_iwd_manager_get(),
            nm_ref_string_get_str(nm_wifi_ap_get_supplicant_path(ap)),
            NM_IWD_NETWORK_INTERFACE);
        if (!network_proxy) {
            _LOGW(LOGD_DEVICE | LOGD_WIFI,
                  "Activation: (wifi) could not get Network interface proxy for %s",
                  nm_ref_string_get_str(nm_wifi_ap_get_supplicant_path(ap)));
            NM_SET_OUT(out_failure_reason, NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
            goto out_fail;
        }

        if (!priv->cancellable)
            priv->cancellable = g_cancellable_new();

        s_wireless_sec = nm_connection_get_setting_wireless_security(connection);
        if (s_wireless_sec
            && nm_streq0(nm_setting_wireless_security_get_key_mgmt(s_wireless_sec), "owe")) {
            _LOGI(LOGD_WIFI,
                  "An OWE connection is requested but IWD may connect to either an OWE "
                  "or unsecured network and there won't be any indication of whether "
                  "encryption is in use -- proceed at your own risk!");
        }

        /* Call Network.Connect.  No timeout because IWD already handles
         * timeouts.
         */
        g_dbus_proxy_call(network_proxy,
                          "Connect",
                          NULL,
                          G_DBUS_CALL_FLAGS_NONE,
                          G_MAXINT,
                          priv->cancellable,
                          network_connect_cb,
                          self);

        return NM_ACT_STAGE_RETURN_POSTPONE;
    }

    if (NM_IN_STRSET(mode, NM_SETTING_WIRELESS_MODE_AP, NM_SETTING_WIRELESS_MODE_ADHOC)) {
        NMSettingWirelessSecurity *s_wireless_sec;

        s_wireless_sec = nm_connection_get_setting_wireless_security(connection);
        if (s_wireless_sec && !nm_setting_wireless_security_get_psk(s_wireless_sec)) {
            /* PSK is missing from the settings, have to request it */

            wifi_secrets_cancel(self);

            priv->wifi_secrets_id =
                nm_act_request_get_secrets(req,
                                           TRUE,
                                           NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
                                           NM_SECRET_AGENT_GET_SECRETS_FLAG_ALLOW_INTERACTION,
                                           NM_MAKE_STRV(NM_SETTING_WIRELESS_SECURITY_PSK),
                                           act_psk_cb,
                                           self);
            nm_device_state_changed(device, NM_DEVICE_STATE_NEED_AUTH, NM_DEVICE_STATE_REASON_NONE);
        } else
            act_set_mode(self);

        return NM_ACT_STAGE_RETURN_POSTPONE;
    }

    _LOGW(LOGD_DEVICE | LOGD_WIFI, "Activation: (wifi) iwd cannot handle mode %s", mode);
    NM_SET_OUT(out_failure_reason, NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);

out_fail:
    cleanup_association_attempt(self, FALSE);
    return NM_ACT_STAGE_RETURN_FAILURE;
}

static guint32
get_configured_mtu(NMDevice *device, NMDeviceMtuSource *out_source, gboolean *out_force)
{
    return nm_device_get_configured_mtu_from_connection(device,
                                                        NM_TYPE_SETTING_WIRELESS,
                                                        out_source);
}

static gboolean
periodic_scan_timeout_cb(gpointer user_data)
{
    NMDeviceIwd *       self = user_data;
    NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE(self);

    priv->periodic_scan_id = 0;

    if (priv->scanning || priv->scan_requested)
        return FALSE;

    g_dbus_proxy_call(priv->dbus_station_proxy,
                      "Scan",
                      NULL,
                      G_DBUS_CALL_FLAGS_NONE,
                      -1,
                      priv->cancellable,
                      scan_cb,
                      self);
    priv->scan_requested = TRUE;

    return FALSE;
}

static void
schedule_periodic_scan(NMDeviceIwd *self, gboolean initial_scan)
{
    NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE(self);
    guint               interval;

    /* Automatically start a scan after a disconnect, mode change or device UP,
     * otherwise scan periodically every 10 seconds if needed for NM's
     * autoconnect.  There's no need to scan When using IWD's autoconnect or
     * when connected, we update the AP list on UI requests.
     *
     * (initial_scan && disconnected && !priv->iwd_autoconnect) override
     * priv->scanning below because of an IWD quirk where a device will often
     * be in the autoconnect state and scanning at the time of our initial_scan,
     * but our logic will then send it a Disconnect() causing IWD to exit
     * autoconnect and interrupt the ongoing scan, meaning that we still want
     * a new scan ASAP.
     */
    if (!priv->can_scan || priv->scan_requested || priv->current_ap || priv->iwd_autoconnect)
        interval = -1;
    else if (initial_scan && priv->scanning)
        interval = 0;
    else if (priv->scanning)
        interval = -1;
    else if (!priv->periodic_scan_id)
        interval = 10;
    else
        return;

    nm_clear_g_source(&priv->periodic_scan_id);

    if (interval != (guint) -1)
        priv->periodic_scan_id = g_timeout_add_seconds(interval, periodic_scan_timeout_cb, self);
}

static void
set_can_scan(NMDeviceIwd *self, gboolean can_scan)
{
    NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE(self);

    if (priv->can_scan == can_scan)
        return;

    priv->can_scan = can_scan;

    if (!priv->iwd_autoconnect)
        schedule_periodic_scan(self, TRUE);
}

static void
device_state_changed(NMDevice *          device,
                     NMDeviceState       new_state,
                     NMDeviceState       old_state,
                     NMDeviceStateReason reason)
{
    NMDeviceIwd *       self = NM_DEVICE_IWD(device);
    NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE(self);
    NMSettingWireless * s_wireless;
    const char *        mode;

    switch (new_state) {
    case NM_DEVICE_STATE_UNMANAGED:
        break;
    case NM_DEVICE_STATE_UNAVAILABLE:
        /*
         * If the device is enabled and the IWD manager is ready,
         * transition to DISCONNECTED because the device is now
         * ready to use.
         */
        if (priv->enabled && priv->dbus_station_proxy) {
            nm_device_queue_recheck_available(device,
                                              NM_DEVICE_STATE_REASON_SUPPLICANT_AVAILABLE,
                                              NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
        }
        break;
    case NM_DEVICE_STATE_DISCONNECTED:
        if (old_state == NM_DEVICE_STATE_UNAVAILABLE)
            initial_check_assume(self);
        break;
    case NM_DEVICE_STATE_IP_CONFIG:
        s_wireless =
            (NMSettingWireless *) nm_device_get_applied_setting(device, NM_TYPE_SETTING_WIRELESS);
        mode = nm_setting_wireless_get_mode(s_wireless);
        if (!priv->periodic_update_id
            && NM_IN_STRSET(mode,
                            NULL,
                            NM_SETTING_WIRELESS_MODE_INFRA,
                            NM_SETTING_WIRELESS_MODE_ADHOC)) {
            priv->periodic_update_id = g_timeout_add_seconds(6, periodic_update_cb, self);
            periodic_update(self);
        }
        break;
    default:
        break;
    }
}

static gboolean
get_enabled(NMDevice *device)
{
    return NM_DEVICE_IWD_GET_PRIVATE(device)->enabled;
}

static void
set_enabled(NMDevice *device, gboolean enabled)
{
    NMDeviceIwd *       self = NM_DEVICE_IWD(device);
    NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE(self);
    NMDeviceState       state;

    enabled = !!enabled;

    if (priv->enabled == enabled)
        return;

    priv->enabled = enabled;

    _LOGD(LOGD_WIFI, "device now %s", enabled ? "enabled" : "disabled");

    state = nm_device_get_state(device);
    if (state < NM_DEVICE_STATE_UNAVAILABLE) {
        _LOGD(LOGD_WIFI, "(%s): device blocked by UNMANAGED state", enabled ? "enable" : "disable");
        return;
    }

    if (priv->dbus_obj)
        set_powered(self, enabled);

    if (enabled) {
        if (state != NM_DEVICE_STATE_UNAVAILABLE)
            _LOGW(LOGD_CORE, "not in expected unavailable state!");

        if (priv->dbus_station_proxy) {
            nm_device_queue_recheck_available(device,
                                              NM_DEVICE_STATE_REASON_SUPPLICANT_AVAILABLE,
                                              NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
        }
    } else {
        nm_device_state_changed(device, NM_DEVICE_STATE_UNAVAILABLE, NM_DEVICE_STATE_REASON_NONE);
    }
}

static gboolean
can_reapply_change(NMDevice *  device,
                   const char *setting_name,
                   NMSetting * s_old,
                   NMSetting * s_new,
                   GHashTable *diffs,
                   GError **   error)
{
    NMDeviceClass *device_class;

    /* Only handle wireless setting here, delegate other settings to parent class */
    if (nm_streq(setting_name, NM_SETTING_WIRELESS_SETTING_NAME)) {
        return nm_device_hash_check_invalid_keys(
            diffs,
            NM_SETTING_WIRELESS_SETTING_NAME,
            error,
            NM_SETTING_WIRELESS_SEEN_BSSIDS, /* ignored */
            NM_SETTING_WIRELESS_MTU);        /* reapplied with IP config */
    }

    device_class = NM_DEVICE_CLASS(nm_device_iwd_parent_class);
    return device_class->can_reapply_change(device, setting_name, s_old, s_new, diffs, error);
}

/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMDeviceIwd *       self = NM_DEVICE_IWD(object);
    NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE(self);
    const char **       list;

    switch (prop_id) {
    case PROP_MODE:
        if (!priv->current_ap)
            g_value_set_uint(value, NM_802_11_MODE_UNKNOWN);
        else if (nm_wifi_ap_is_hotspot(priv->current_ap))
            g_value_set_uint(value, NM_802_11_MODE_AP);
        else
            g_value_set_uint(value, nm_wifi_ap_get_mode(priv->current_ap));

        break;
    case PROP_BITRATE:
        g_value_set_uint(value, priv->rate);
        break;
    case PROP_CAPABILITIES:
        g_value_set_uint(value, priv->capabilities);
        break;
    case PROP_ACCESS_POINTS:
        list = nm_wifi_aps_get_paths(&priv->aps_lst_head, TRUE);
        g_value_take_boxed(value, nm_utils_strv_make_deep_copied(list));
        break;
    case PROP_ACTIVE_ACCESS_POINT:
        nm_dbus_utils_g_value_set_object_path(value, priv->current_ap);
        break;
    case PROP_SCANNING:
        g_value_set_boolean(value, priv->scanning);
        break;
    case PROP_LAST_SCAN:
        g_value_set_int64(
            value,
            priv->last_scan > 0
                ? nm_utils_monotonic_timestamp_as_boottime(priv->last_scan, NM_UTILS_NSEC_PER_MSEC)
                : (gint64) -1);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

/*****************************************************************************/

static void
state_changed(NMDeviceIwd *self, const char *new_state)
{
    NMDeviceIwdPrivate *priv           = NM_DEVICE_IWD_GET_PRIVATE(self);
    NMDevice *          device         = NM_DEVICE(self);
    NMDeviceState       dev_state      = nm_device_get_state(device);
    gboolean            nm_connection  = priv->current_ap || priv->assumed_ac;
    gboolean            iwd_connection = FALSE;
    NMWifiAP *          ap             = NULL;
    gboolean            can_connect    = priv->nm_autoconnect;

    _LOGI(LOGD_DEVICE | LOGD_WIFI, "new IWD device state is %s", new_state);

    if (NM_IN_STRSET(new_state, "connecting", "connected", "roaming")) {
        gs_unref_variant GVariant *value = NULL;
        const char *               network_path_str;
        nm_auto_ref_string NMRefString *network_path = NULL;

        value = g_dbus_proxy_get_cached_property(priv->dbus_station_proxy, "ConnectedNetwork");
        if (!value || !g_variant_is_of_type(value, G_VARIANT_TYPE_OBJECT_PATH)) {
            _LOGW(LOGD_DEVICE | LOGD_WIFI,
                  "ConnectedNetwork property not cached or not an object path");
            return;
        }

        iwd_connection   = TRUE;
        network_path_str = g_variant_get_string(value, NULL);
        network_path     = nm_ref_string_new(network_path_str);
        ap               = find_ap_by_supplicant_path(self, network_path);

        if (!ap) {
            _LOGW(LOGD_DEVICE | LOGD_WIFI,
                  "ConnectedNetwork points to an unknown Network %s",
                  network_path_str);
            return;
        }
    }

    /* Don't allow scanning while connecting, disconnecting or roaming */
    set_can_scan(self, NM_IN_STRSET(new_state, "connected", "disconnected"));

    priv->nm_autoconnect = FALSE;

    if (nm_connection && iwd_connection && priv->current_ap && ap != priv->current_ap) {
        gboolean switch_ap = priv->iwd_autoconnect && priv->assumed_ac;

        _LOGW(LOGD_DEVICE | LOGD_WIFI,
              "IWD is connecting to the wrong AP, %s activation",
              switch_ap ? "replacing" : "aborting");
        cleanup_association_attempt(self, !switch_ap);
        nm_device_state_changed(device,
                                NM_DEVICE_STATE_FAILED,
                                NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT);

        if (switch_ap)
            assume_connection(self, ap);
        return;
    }

    if (priv->iwd_autoconnect && iwd_connection) {
        if (dev_state < NM_DEVICE_STATE_DISCONNECTED)
            return;

        /* If IWD is in any state other than disconnected and the NMDevice is
         * in DISCONNECTED then someone else, possibly IWD's autoconnect, has
         * commanded an action and we need to update our NMDevice's state to
         * match, including finding the NMSettingsConnection and NMWifiAP
         * matching the network pointed to by Station.ConnectedNetwork.
         *
         * If IWD is in the connected state and we're in CONFIG, we only have
         * to signal that the existing connection request has advanced to a new
         * state.  If the connection request came from NM, we must have used
         * Network.Connect() so that method call's callback will update the
         * connection request, otherwise we do it here.
         *
         * If IWD is disconnecting or just disconnected, the common code below
         * (independent from priv->iwd_autoconnect) will handle this case.
         * If IWD is disconnecting but we never saw a connection request in the
         * first place (maybe because we're only startig up) we won't be
         * setting up an NMActiveConnection just to put the NMDevice in the
         * DEACTIVATING state and we ignore this case.
         *
         * If IWD was in the disconnected state and transitioned to
         * "connecting" but we were already in NEED_AUTH because we handled an
         * agent query -- IWD normally stays in "disconnected" until it has all
         * the secrets -- we record this fact and remain in NEED_AUTH.
         */
        if (!nm_connection) {
            _LOGD(LOGD_DEVICE | LOGD_WIFI, "This is a new connection, 'assuming' it");
            assume_connection(self, ap);
            return;
        }

        if (priv->assumed_ac && dev_state >= NM_DEVICE_STATE_PREPARE
            && dev_state < NM_DEVICE_STATE_IP_CONFIG
            && NM_IN_STRSET(new_state, "connected", "roaming")) {
            _LOGD(LOGD_DEVICE | LOGD_WIFI, "Updating assumed activation state");
            assumed_connection_progress_to_ip_config(self, TRUE);
            return;
        }

        if (priv->assumed_ac) {
            _LOGD(LOGD_DEVICE | LOGD_WIFI, "Clearing assumed activation timeout");
            nm_clear_g_source(&priv->assumed_ac_timeout);
            return;
        }
    } else if (!priv->iwd_autoconnect && iwd_connection) {
        /* If we were connecting, do nothing, the confirmation of
         * a connection success is handled in the Device.Connect
         * method return callback.  Otherwise, IWD must have connected
         * without Network Manager's will so for simplicity force a
         * disconnect.
         */
        if (nm_connection)
            return;

        _LOGW(LOGD_DEVICE | LOGD_WIFI, "Unsolicited connection, asking IWD to disconnect");
        send_disconnect(self);
    } else if (NM_IN_STRSET(new_state, "disconnecting", "disconnected")) {
        /* If necessary, call Disconnect on the IWD device object to make sure
         * it disables its autoconnect.
         */
        if ((!priv->iwd_autoconnect
             || nm_device_autoconnect_blocked_get(device, NM_DEVICE_AUTOCONNECT_BLOCKED_ALL))
            && !priv->wifi_secrets_id && !priv->pending_agent_request)
            send_disconnect(self);

        /*
         * If IWD is still handling the Connect call, let our Connect
         * callback for the dbus method handle the failure.  The main
         * reason we don't want to handle the failure here is because the
         * method callback will have more information on the specific
         * failure reason.
         *
         * If IWD is handling an autoconnect agent call, let the agent's
         * Cancel() handler take care of this.
         */
        if (NM_IN_SET(dev_state, NM_DEVICE_STATE_CONFIG, NM_DEVICE_STATE_NEED_AUTH)
            && !priv->assumed_ac)
            return;
        if (NM_IN_SET(dev_state, NM_DEVICE_STATE_NEED_AUTH) && priv->assumed_ac)
            return;

        if (nm_connection) {
            cleanup_association_attempt(self, FALSE);
            nm_device_state_changed(device,
                                    NM_DEVICE_STATE_FAILED,
                                    NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT);
        }
    } else if (!nm_streq(new_state, "unknown")) {
        _LOGE(LOGD_WIFI, "State %s unknown", new_state);
        return;
    }

    /* Don't allow new connection until iwd exits disconnecting and no
     * Connect callback is pending.
     */
    if (!priv->iwd_autoconnect && NM_IN_STRSET(new_state, "disconnected")) {
        priv->nm_autoconnect = TRUE;
        if (!can_connect)
            nm_device_emit_recheck_auto_activate(device);
    }
}

static void
scanning_changed(NMDeviceIwd *self, gboolean new_scanning)
{
    NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE(self);

    if (new_scanning == priv->scanning)
        return;

    priv->scanning = new_scanning;

    _notify(self, PROP_SCANNING);

    if (!priv->scanning) {
        update_aps(self);

        if (!priv->scan_requested && !priv->iwd_autoconnect)
            schedule_periodic_scan(self, FALSE);
    }
}

static void
station_properties_changed(GDBusProxy *proxy,
                           GVariant *  changed_properties,
                           GStrv       invalidate_properties,
                           gpointer    user_data)
{
    NMDeviceIwd *self = user_data;
    const char * new_str;
    gboolean     new_bool;

    if (g_variant_lookup(changed_properties, "State", "&s", &new_str))
        state_changed(self, new_str);

    if (g_variant_lookup(changed_properties, "Scanning", "b", &new_bool))
        scanning_changed(self, new_bool);
}

static void
ap_adhoc_properties_changed(GDBusProxy *proxy,
                            GVariant *  changed_properties,
                            GStrv       invalidate_properties,
                            gpointer    user_data)
{
    NMDeviceIwd *self = user_data;
    gboolean     new_bool;

    if (g_variant_lookup(changed_properties, "Started", "b", &new_bool))
        _LOGI(LOGD_DEVICE | LOGD_WIFI,
              "IWD AP/AdHoc state is now %s",
              new_bool ? "Started" : "Stopped");
}

static void
powered_changed(NMDeviceIwd *self, gboolean new_powered)
{
    NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE(self);
    GDBusInterface *    interface;

    nm_device_queue_recheck_available(NM_DEVICE(self),
                                      NM_DEVICE_STATE_REASON_SUPPLICANT_AVAILABLE,
                                      NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);

    interface =
        new_powered ? g_dbus_object_get_interface(priv->dbus_obj, NM_IWD_AP_INTERFACE) : NULL;

    if (priv->dbus_ap_proxy) {
        g_signal_handlers_disconnect_by_func(priv->dbus_ap_proxy,
                                             ap_adhoc_properties_changed,
                                             self);
        g_clear_object(&priv->dbus_ap_proxy);
    }

    if (interface) {
        priv->dbus_ap_proxy = G_DBUS_PROXY(interface);
        g_signal_connect(priv->dbus_ap_proxy,
                         "g-properties-changed",
                         G_CALLBACK(ap_adhoc_properties_changed),
                         self);

        if (priv->act_mode_switch)
            act_check_interface(self);
        else
            reset_mode(self, NULL, NULL, NULL);
    }

    interface =
        new_powered ? g_dbus_object_get_interface(priv->dbus_obj, NM_IWD_ADHOC_INTERFACE) : NULL;

    if (priv->dbus_adhoc_proxy) {
        g_signal_handlers_disconnect_by_func(priv->dbus_adhoc_proxy,
                                             ap_adhoc_properties_changed,
                                             self);
        g_clear_object(&priv->dbus_adhoc_proxy);
    }

    if (interface) {
        priv->dbus_adhoc_proxy = G_DBUS_PROXY(interface);
        g_signal_connect(priv->dbus_adhoc_proxy,
                         "g-properties-changed",
                         G_CALLBACK(ap_adhoc_properties_changed),
                         self);

        if (priv->act_mode_switch)
            act_check_interface(self);
        else
            reset_mode(self, NULL, NULL, NULL);
    }

    /* We expect one of the three interfaces to always be present when
     * device is Powered so if AP and AdHoc are not present we should
     * be in station mode.
     */
    if (new_powered && !priv->dbus_ap_proxy && !priv->dbus_adhoc_proxy) {
        interface = g_dbus_object_get_interface(priv->dbus_obj, NM_IWD_STATION_INTERFACE);
        if (!interface) {
            _LOGE(LOGD_WIFI,
                  "Interface %s not found on obj %s",
                  NM_IWD_STATION_INTERFACE,
                  g_dbus_object_get_object_path(priv->dbus_obj));
            interface = NULL;
        }
    } else
        interface = NULL;

    if (priv->dbus_station_proxy) {
        g_signal_handlers_disconnect_by_func(priv->dbus_station_proxy,
                                             station_properties_changed,
                                             self);
        g_clear_object(&priv->dbus_station_proxy);
    }

    if (interface) {
        GVariant *value;

        priv->dbus_station_proxy = G_DBUS_PROXY(interface);
        g_signal_connect(priv->dbus_station_proxy,
                         "g-properties-changed",
                         G_CALLBACK(station_properties_changed),
                         self);

        value          = g_dbus_proxy_get_cached_property(priv->dbus_station_proxy, "Scanning");
        priv->scanning = get_variant_boolean(value, "Scanning");
        g_variant_unref(value);

        value = g_dbus_proxy_get_cached_property(priv->dbus_station_proxy, "State");
        state_changed(self, get_variant_state(value));
        g_variant_unref(value);

        update_aps(self);

        /* When a device is brought UP in station mode, including after a mode
         * switch, IWD re-enables autoconnect.  This is unlike NM's autoconnect
         * where a mode change doesn't interfere with the
         * BLOCKED_MANUAL_DISCONNECT flag.
         */
        if (priv->iwd_autoconnect) {
            nm_device_autoconnect_blocked_unset(NM_DEVICE(self),
                                                NM_DEVICE_AUTOCONNECT_BLOCKED_INTERNAL);
        }
    } else {
        set_can_scan(self, FALSE);
        priv->scanning       = FALSE;
        priv->scan_requested = FALSE;
        priv->nm_autoconnect = FALSE;
        cleanup_association_attempt(self, FALSE);
        remove_all_aps(self);
    }
}

static void
device_properties_changed(GDBusProxy *proxy,
                          GVariant *  changed_properties,
                          GStrv       invalidate_properties,
                          gpointer    user_data)
{
    NMDeviceIwd *self = user_data;
    gboolean     new_bool;

    if (g_variant_lookup(changed_properties, "Powered", "b", &new_bool))
        powered_changed(self, new_bool);
}

static void
config_changed(NMConfig *          config,
               NMConfigData *      config_data,
               NMConfigChangeFlags changes,
               NMConfigData *      old_data,
               NMDeviceIwd *       self)
{
    NMDeviceIwdPrivate *priv       = NM_DEVICE_IWD_GET_PRIVATE(self);
    gboolean            old_iwd_ac = priv->iwd_autoconnect;

    priv->iwd_autoconnect =
        nm_config_data_get_device_config_boolean(config_data,
                                                 NM_CONFIG_KEYFILE_KEY_DEVICE_WIFI_IWD_AUTOCONNECT,
                                                 NM_DEVICE(self),
                                                 TRUE,
                                                 TRUE);

    if (old_iwd_ac != priv->iwd_autoconnect && priv->dbus_station_proxy && !priv->current_ap) {
        gs_unref_variant GVariant *value = NULL;

        if (!priv->iwd_autoconnect
            && !nm_device_autoconnect_blocked_get(NM_DEVICE(self),
                                                  NM_DEVICE_AUTOCONNECT_BLOCKED_ALL))
            send_disconnect(self);

        value = g_dbus_proxy_get_cached_property(priv->dbus_station_proxy, "State");
        state_changed(self, get_variant_state(value));
    }
}

void
nm_device_iwd_set_dbus_object(NMDeviceIwd *self, GDBusObject *object)
{
    NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE(self);
    GDBusInterface *    interface;
    gs_unref_variant GVariant *value          = NULL;
    gs_unref_object GDBusProxy *adapter_proxy = NULL;
    GVariantIter *              iter;
    const char *                mode;
    gboolean                    powered;
    NMDeviceWifiCapabilities    capabilities;

    if (!nm_g_object_ref_set(&priv->dbus_obj, object))
        return;

    if (priv->dbus_device_proxy) {
        g_signal_handlers_disconnect_by_func(priv->dbus_device_proxy,
                                             device_properties_changed,
                                             self);
        g_clear_object(&priv->dbus_device_proxy);

        powered_changed(self, FALSE);

        priv->act_mode_switch = FALSE;

        g_signal_handlers_disconnect_by_func(nm_config_get(), config_changed, self);
    }

    if (!object)
        return;

    interface = g_dbus_object_get_interface(object, NM_IWD_DEVICE_INTERFACE);
    if (!interface) {
        _LOGE(LOGD_WIFI,
              "Interface %s not found on obj %s",
              NM_IWD_DEVICE_INTERFACE,
              g_dbus_object_get_object_path(object));
        g_clear_object(&priv->dbus_obj);
        return;
    }

    priv->dbus_device_proxy = G_DBUS_PROXY(interface);

    g_signal_connect(priv->dbus_device_proxy,
                     "g-properties-changed",
                     G_CALLBACK(device_properties_changed),
                     self);

    /* Parse list of interface modes supported by adapter (wiphy) */

    value = g_dbus_proxy_get_cached_property(priv->dbus_device_proxy, "Adapter");
    if (!value || !g_variant_is_of_type(value, G_VARIANT_TYPE_OBJECT_PATH)) {
        nm_log_warn(LOGD_DEVICE | LOGD_WIFI, "Adapter property not cached or not an object path");
        goto error;
    }

    adapter_proxy = nm_iwd_manager_get_dbus_interface(nm_iwd_manager_get(),
                                                      g_variant_get_string(value, NULL),
                                                      NM_IWD_WIPHY_INTERFACE);
    if (!adapter_proxy) {
        nm_log_warn(LOGD_DEVICE | LOGD_WIFI, "Can't get DBus proxy for IWD Adapter for IWD Device");
        goto error;
    }

    g_variant_unref(value);
    value = g_dbus_proxy_get_cached_property(adapter_proxy, "SupportedModes");
    if (!value || !g_variant_is_of_type(value, G_VARIANT_TYPE_STRING_ARRAY)) {
        nm_log_warn(LOGD_DEVICE | LOGD_WIFI,
                    "SupportedModes property not cached or not a string array");
        goto error;
    }

    capabilities = NM_WIFI_DEVICE_CAP_CIPHER_CCMP | NM_WIFI_DEVICE_CAP_RSN;

    g_variant_get(value, "as", &iter);
    while (g_variant_iter_next(iter, "&s", &mode)) {
        if (nm_streq(mode, "ap"))
            capabilities |= NM_WIFI_DEVICE_CAP_AP;
        else if (nm_streq(mode, "ad-hoc"))
            capabilities |= NM_WIFI_DEVICE_CAP_ADHOC;
    }
    g_variant_iter_free(iter);

    if (priv->capabilities != capabilities) {
        priv->capabilities = capabilities;
        _notify(self, PROP_CAPABILITIES);
    }

    /* Update iwd_autoconnect before any state_changed call */
    g_signal_connect(nm_config_get(),
                     NM_CONFIG_SIGNAL_CONFIG_CHANGED,
                     G_CALLBACK(config_changed),
                     self);
    config_changed(NULL, NM_CONFIG_GET_DATA, 0, NULL, self);

    g_variant_unref(value);
    value   = g_dbus_proxy_get_cached_property(priv->dbus_device_proxy, "Powered");
    powered = get_variant_boolean(value, "Powered");

    if (powered != priv->enabled)
        set_powered(self, priv->enabled);
    else if (powered)
        powered_changed(self, TRUE);

    return;

error:
    g_signal_handlers_disconnect_by_func(priv->dbus_device_proxy, device_properties_changed, self);
    g_clear_object(&priv->dbus_device_proxy);
}

gboolean
nm_device_iwd_agent_query(NMDeviceIwd *self, GDBusMethodInvocation *invocation)
{
    NMDevice *                   device = NM_DEVICE(self);
    NMDeviceIwdPrivate *         priv   = NM_DEVICE_IWD_GET_PRIVATE(self);
    NMDeviceState                state  = nm_device_get_state(device);
    const char *                 setting_name;
    const char *                 setting_key;
    gboolean                     replied;
    NMWifiAP *                   ap;
    NMSecretAgentGetSecretsFlags get_secret_flags =
        NM_SECRET_AGENT_GET_SECRETS_FLAG_ALLOW_INTERACTION;
    nm_auto_ref_string NMRefString *network_path = NULL;

    if (!invocation) {
        gs_unref_variant GVariant *value =
            g_dbus_proxy_get_cached_property(priv->dbus_station_proxy, "State");
        gboolean disconnect;

        if (!priv->wifi_secrets_id && !priv->pending_agent_request)
            return FALSE;

        _LOGI(LOGD_WIFI, "IWD agent request is being cancelled");
        wifi_secrets_cancel(self);

        if (state == NM_DEVICE_STATE_NEED_AUTH)
            nm_device_state_changed(device, NM_DEVICE_STATE_CONFIG, NM_DEVICE_STATE_REASON_NONE);

        /* The secrets request is being cancelled.  If we don't have an assumed
         * connection than we've probably called Network.Connect and that method
         * call's callback is going to handle the failure.  And if the state was
         * not "disconnected" then let the state change handler process the
         * failure.
         */
        if (!priv->assumed_ac)
            return TRUE;

        if (!nm_streq(get_variant_state(value), "disconnected"))
            return TRUE;

        disconnect = nm_device_autoconnect_blocked_get(device, NM_DEVICE_AUTOCONNECT_BLOCKED_ALL);
        cleanup_association_attempt(self, disconnect);
        nm_device_state_changed(device,
                                NM_DEVICE_STATE_FAILED,
                                NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
        return TRUE;
    }

    if (state > NM_DEVICE_STATE_CONFIG && state < NM_DEVICE_STATE_DEACTIVATING) {
        _LOGW(LOGD_WIFI, "Can't handle the IWD agent request in current device state");
        return FALSE;
    }

    if (priv->wifi_secrets_id || priv->pending_agent_request) {
        _LOGW(LOGD_WIFI, "There's already a pending agent request for this device");
        return FALSE;
    }

    network_path = nm_ref_string_new(get_agent_request_network_path(invocation));
    ap           = find_ap_by_supplicant_path(self, network_path);
    if (!ap) {
        _LOGW(LOGD_WIFI, "IWD Network object not found for the agent request");
        return FALSE;
    }

    if (priv->assumed_ac) {
        const char *ac_ap_path = nm_active_connection_get_specific_object(priv->assumed_ac);

        if (!nm_streq(ac_ap_path, nm_dbus_object_get_path(NM_DBUS_OBJECT(ap)))) {
            _LOGW(LOGD_WIFI,
                  "Dropping an existing assumed connection to create a new one based on the IWD "
                  "agent request network parameter");

            if (priv->current_ap)
                nm_device_state_changed(device,
                                        NM_DEVICE_STATE_FAILED,
                                        NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);

            cleanup_association_attempt(self, FALSE);
            priv->pending_agent_request = g_object_ref(invocation);
            assume_connection(self, ap);
            return TRUE;
        }

        if (state != NM_DEVICE_STATE_CONFIG) {
            _LOGI(LOGD_WIFI, "IWD agent request deferred until in CONFIG");
            priv->pending_agent_request = g_object_ref(invocation);
            return TRUE;
        }

        /* Otherwise handle as usual */
    } else if (!priv->current_ap) {
        _LOGI(LOGD_WIFI, "IWD is asking for secrets without explicit connect request");

        if (priv->iwd_autoconnect) {
            priv->pending_agent_request = g_object_ref(invocation);
            assume_connection(self, ap);
            return TRUE;
        }

        send_disconnect(self);
        return FALSE;
    } else if (priv->current_ap) {
        if (priv->current_ap != ap) {
            _LOGW(LOGD_WIFI, "IWD agent request for a wrong network object");
            cleanup_association_attempt(self, TRUE);
            nm_device_state_changed(device,
                                    NM_DEVICE_STATE_FAILED,
                                    NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
            return FALSE;
        }

        /* Otherwise handle as usual */
    }

    if (!try_reply_agent_request(self,
                                 nm_device_get_applied_connection(device),
                                 invocation,
                                 &setting_name,
                                 &setting_key,
                                 &replied)) {
        priv->secrets_failed = TRUE;
        return FALSE;
    }

    if (replied)
        return TRUE;

    /* Normally require new secrets every time IWD asks for them.
     * IWD only queries us if it has not saved the secrets (e.g. by policy)
     * or a previous attempt has failed with current secrets so it wants
     * a fresh set.  However if this is a new connection it may include
     * all of the needed settings already so allow using these, too.
     * Connection timestamp is set after activation or after first
     * activation failure (to 0).
     */
    if (nm_settings_connection_get_timestamp(nm_device_get_settings_connection(device), NULL))
        get_secret_flags |= NM_SECRET_AGENT_GET_SECRETS_FLAG_REQUEST_NEW;

    nm_device_state_changed(device, NM_DEVICE_STATE_NEED_AUTH, NM_DEVICE_STATE_REASON_NO_SECRETS);
    wifi_secrets_get_one(self, setting_name, get_secret_flags, setting_key, invocation);

    return TRUE;
}

void
nm_device_iwd_network_add_remove(NMDeviceIwd *self, GDBusProxy *network, bool add)
{
    NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE(self);
    NMWifiAP *          ap   = NULL;
    bool                recheck;
    nm_auto_ref_string NMRefString *bss_path = NULL;

    bss_path = nm_ref_string_new(g_dbus_proxy_get_object_path(network));
    ap       = find_ap_by_supplicant_path(self, bss_path);

    /* We could schedule an update_aps(self) idle call here but up to IWD 1.9
     * when a hidden network connection is attempted, that network is initially
     * only added as a Network object but not shown in GetOrderedNetworks()
     * return values, and for some corner case scenarios it's beneficial to
     * have that Network reflected in our ap list so that we don't attempt
     * calling ConnectHiddenNetwork() on it, as that will fail in 1.9.  But we
     * can skip recheck-available if we're currently scanning or in the middle
     * of a GetOrderedNetworks() call as that will trigger the recheck too.
     */
    recheck = priv->enabled && !priv->scanning && !priv->networks_requested;

    if (!add) {
        if (ap) {
            ap_add_remove(self, FALSE, ap, recheck);
            priv->networks_changed |= !recheck;
        }

        return;
    }

    if (!ap) {
        ap = ap_from_network(self,
                             network,
                             bss_path,
                             nm_utils_get_monotonic_timestamp_msec(),
                             -10000);
        if (!ap)
            return;

        ap_add_remove(self, TRUE, ap, recheck);
        g_object_unref(ap);
        priv->networks_changed |= !recheck;
        return;
    }
}

static void
autoconnect_changed(NMDevice *device, GParamSpec *pspec, NMDeviceIwd *self)
{
    NMDeviceIwdPrivate *priv         = NM_DEVICE_IWD_GET_PRIVATE(self);
    gs_unref_variant GVariant *value = NULL;

    /* Note IWD normally remains in "disconnected" during a secret request
     * and we don't want to interrupt it by calling Station.Disconnect().
     */
    if (!priv->dbus_station_proxy || !priv->iwd_autoconnect
        || !nm_device_autoconnect_blocked_get(device, NM_DEVICE_AUTOCONNECT_BLOCKED_ALL)
        || priv->wifi_secrets_id || priv->pending_agent_request)
        return;

    value = g_dbus_proxy_get_cached_property(priv->dbus_station_proxy, "State");
    if (!nm_streq(get_variant_state(value), "disconnected"))
        return;

    send_disconnect(self);
}

/*****************************************************************************/

static const char *
get_type_description(NMDevice *device)
{
    nm_assert(NM_IS_DEVICE_IWD(device));

    return "wifi";
}

/*****************************************************************************/

static void
nm_device_iwd_init(NMDeviceIwd *self)
{
    NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE(self);

    c_list_init(&priv->aps_lst_head);

    g_signal_connect(self, "notify::" NM_DEVICE_AUTOCONNECT, G_CALLBACK(autoconnect_changed), self);

    /* Make sure the manager is running */
    (void) nm_iwd_manager_get();
}

NMDevice *
nm_device_iwd_new(const char *iface)
{
    return g_object_new(NM_TYPE_DEVICE_IWD,
                        NM_DEVICE_IFACE,
                        iface,
                        NM_DEVICE_TYPE_DESC,
                        "802.11 Wi-Fi",
                        NM_DEVICE_DEVICE_TYPE,
                        NM_DEVICE_TYPE_WIFI,
                        NM_DEVICE_LINK_TYPE,
                        NM_LINK_TYPE_WIFI,
                        NM_DEVICE_RFKILL_TYPE,
                        RFKILL_TYPE_WLAN,
                        NULL);
}

static void
dispose(GObject *object)
{
    NMDeviceIwd *       self = NM_DEVICE_IWD(object);
    NMDeviceIwdPrivate *priv = NM_DEVICE_IWD_GET_PRIVATE(self);

    nm_clear_g_cancellable(&priv->cancellable);

    g_signal_handlers_disconnect_by_func(self, autoconnect_changed, self);
    nm_device_iwd_set_dbus_object(self, NULL);

    G_OBJECT_CLASS(nm_device_iwd_parent_class)->dispose(object);

    nm_assert(c_list_is_empty(&priv->aps_lst_head));
}

static void
nm_device_iwd_class_init(NMDeviceIwdClass *klass)
{
    GObjectClass *     object_class      = G_OBJECT_CLASS(klass);
    NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS(klass);
    NMDeviceClass *    device_class      = NM_DEVICE_CLASS(klass);

    object_class->get_property = get_property;
    object_class->dispose      = dispose;

    dbus_object_class->interface_infos =
        NM_DBUS_INTERFACE_INFOS(&nm_interface_info_device_wireless);

    device_class->connection_type_supported        = NM_SETTING_WIRELESS_SETTING_NAME;
    device_class->connection_type_check_compatible = NM_SETTING_WIRELESS_SETTING_NAME;
    device_class->link_types                       = NM_DEVICE_DEFINE_LINK_TYPES(NM_LINK_TYPE_WIFI);

    device_class->can_auto_connect            = can_auto_connect;
    device_class->is_available                = is_available;
    device_class->get_autoconnect_allowed     = get_autoconnect_allowed;
    device_class->check_connection_compatible = check_connection_compatible;
    device_class->check_connection_available  = check_connection_available;
    device_class->complete_connection         = complete_connection;
    device_class->get_enabled                 = get_enabled;
    device_class->set_enabled                 = set_enabled;
    device_class->get_type_description        = get_type_description;

    device_class->act_stage1_prepare = act_stage1_prepare;
    device_class->act_stage2_config  = act_stage2_config;
    device_class->get_configured_mtu = get_configured_mtu;
    device_class->deactivate         = deactivate;
    device_class->deactivate_async   = deactivate_async;
    device_class->can_reapply_change = can_reapply_change;

    /* Stage 1 needed only for the set_current_ap() call.  Stage 2 is
     * needed if we're assuming a connection still in the "connecting"
     * state or on an agent request.
     */
    device_class->act_stage1_prepare_also_for_external_or_assume = TRUE;
    device_class->act_stage2_config_also_for_external_or_assume  = TRUE;

    device_class->state_changed = device_state_changed;

    obj_properties[PROP_MODE] = g_param_spec_uint(NM_DEVICE_IWD_MODE,
                                                  "",
                                                  "",
                                                  NM_802_11_MODE_UNKNOWN,
                                                  NM_802_11_MODE_AP,
                                                  NM_802_11_MODE_INFRA,
                                                  G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_BITRATE] = g_param_spec_uint(NM_DEVICE_IWD_BITRATE,
                                                     "",
                                                     "",
                                                     0,
                                                     G_MAXUINT32,
                                                     0,
                                                     G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_ACCESS_POINTS] =
        g_param_spec_boxed(NM_DEVICE_IWD_ACCESS_POINTS,
                           "",
                           "",
                           G_TYPE_STRV,
                           G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_ACTIVE_ACCESS_POINT] =
        g_param_spec_string(NM_DEVICE_IWD_ACTIVE_ACCESS_POINT,
                            "",
                            "",
                            NULL,
                            G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_CAPABILITIES] =
        g_param_spec_uint(NM_DEVICE_IWD_CAPABILITIES,
                          "",
                          "",
                          0,
                          G_MAXUINT32,
                          NM_WIFI_DEVICE_CAP_NONE,
                          G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_SCANNING] = g_param_spec_boolean(NM_DEVICE_IWD_SCANNING,
                                                         "",
                                                         "",
                                                         FALSE,
                                                         G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_LAST_SCAN] = g_param_spec_int64(NM_DEVICE_IWD_LAST_SCAN,
                                                        "",
                                                        "",
                                                        -1,
                                                        G_MAXINT64,
                                                        -1,
                                                        G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
