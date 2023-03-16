/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2021 Intel Corporation
 */

#include "src/core/nm-default-daemon.h"

#include "nm-device-iwd-p2p.h"

#include "NetworkManagerUtils.h"
#include "devices/nm-device-private.h"
#include "nm-act-request.h"
#include "libnm-core-aux-intern/nm-libnm-core-utils.h"
#include "libnm-core-intern/nm-core-internal.h"
#include "libnm-std-aux/nm-dbus-compat.h"
#include "nm-setting-wifi-p2p.h"
#include "nm-utils.h"
#include "nm-wifi-p2p-peer.h"
#include "nm-iwd-manager.h"
#include "settings/nm-settings.h"

#define _NMLOG_DEVICE_TYPE NMDeviceIwdP2P
#include "devices/nm-device-logging.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE(NMDeviceIwdP2P, PROP_PEERS, );

typedef struct {
    GDBusObject *dbus_obj;
    GDBusProxy  *dbus_p2p_proxy;
    GDBusProxy  *dbus_peer_proxy;
    CList        peers_lst_head;

    GSource *find_peer_timeout_source;
    GSource *peer_dump_source;

    GCancellable *find_cancellable;
    GCancellable *connect_cancellable;

    bool enabled : 1;

    bool stage2_ready : 1;

    bool wfd_registered : 1;
} NMDeviceIwdP2PPrivate;

struct _NMDeviceIwdP2P {
    NMDevice              parent;
    NMDeviceIwdP2PPrivate _priv;
};

struct _NMDeviceIwdP2PClass {
    NMDeviceClass parent;
};

G_DEFINE_TYPE(NMDeviceIwdP2P, nm_device_iwd_p2p, NM_TYPE_DEVICE)

#define NM_DEVICE_IWD_P2P_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMDeviceIwdP2P, NM_IS_DEVICE_IWD_P2P, NMDevice)

/*****************************************************************************/

static const NMDBusInterfaceInfoExtended interface_info_device_wifi_p2p;
static const GDBusSignalInfo             nm_signal_info_wifi_p2p_peer_added;
static const GDBusSignalInfo             nm_signal_info_wifi_p2p_peer_removed;
static gboolean                          iwd_discovery_timeout_cb(gpointer user_data);

/*****************************************************************************/

static void
_peer_dump(NMDeviceIwdP2P      *self,
           NMLogLevel           log_level,
           const NMWifiP2PPeer *peer,
           const char          *prefix,
           gint32               now_s)
{
    char buf[1024];

    _NMLOG(log_level,
           LOGD_WIFI_SCAN,
           "wifi-peer: %-7s %s",
           prefix,
           nm_wifi_p2p_peer_to_string(peer, buf, sizeof(buf), now_s));
}

static gboolean
peer_list_dump(gpointer user_data)
{
    NMDeviceIwdP2P        *self = NM_DEVICE_IWD_P2P(user_data);
    NMDeviceIwdP2PPrivate *priv = NM_DEVICE_IWD_P2P_GET_PRIVATE(self);

    nm_clear_g_source_inst(&priv->peer_dump_source);

    if (_LOGD_ENABLED(LOGD_WIFI_SCAN)) {
        NMWifiP2PPeer *peer;
        gint32         now_s = nm_utils_get_monotonic_timestamp_sec();

        _LOGD(LOGD_WIFI_SCAN, "P2P Peers: [now:%u]", now_s);
        c_list_for_each_entry (peer, &priv->peers_lst_head, peers_lst)
            _peer_dump(self, LOGL_DEBUG, peer, "dump", now_s);
    }

    return G_SOURCE_REMOVE;
}

static void
schedule_peer_list_dump(NMDeviceIwdP2P *self)
{
    NMDeviceIwdP2PPrivate *priv = NM_DEVICE_IWD_P2P_GET_PRIVATE(self);

    if (!priv->peer_dump_source && _LOGD_ENABLED(LOGD_WIFI_SCAN)) {
        priv->peer_dump_source = nm_g_timeout_add_seconds_source(1, peer_list_dump, self);
    }
}

/*****************************************************************************/

static gboolean
is_available(NMDevice *device, NMDeviceCheckDevAvailableFlags flags)
{
    NMDeviceIwdP2P        *self = NM_DEVICE_IWD_P2P(device);
    NMDeviceIwdP2PPrivate *priv = NM_DEVICE_IWD_P2P_GET_PRIVATE(self);

    return priv->enabled;
}

static gboolean
check_connection_compatible(NMDevice     *device,
                            NMConnection *connection,
                            gboolean      check_properties,
                            GError      **error)
{
    NMSettingWifiP2P  *s_wifi_p2p;
    GBytes            *wfd_ies;
    NMSettingIPConfig *s_ip;

    if (!NM_DEVICE_CLASS(nm_device_iwd_p2p_parent_class)
             ->check_connection_compatible(device, connection, check_properties, error))
        return FALSE;

    s_wifi_p2p =
        NM_SETTING_WIFI_P2P(nm_connection_get_setting(connection, NM_TYPE_SETTING_WIFI_P2P));

    /* Any of the existing values other than DISABLED is ok */
    if (nm_setting_wifi_p2p_get_wps_method(s_wifi_p2p)
        == NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_DISABLED) {
        nm_utils_error_set_literal(error,
                                   NM_UTILS_ERROR_CONNECTION_AVAILABLE_INCOMPATIBLE,
                                   "No WPS method enabled");
        return FALSE;
    }

    wfd_ies = nm_setting_wifi_p2p_get_wfd_ies(s_wifi_p2p);
    if (wfd_ies && !nm_wifi_utils_parse_wfd_ies(wfd_ies, NULL)) {
        nm_utils_error_set_literal(error,
                                   NM_UTILS_ERROR_CONNECTION_AVAILABLE_INCOMPATIBLE,
                                   "Can't parse connection WFD IEs");
        return FALSE;
    }

    s_ip = NM_SETTING_IP_CONFIG(nm_connection_get_setting_ip4_config(connection));
    if (s_ip
        && !NM_IN_STRSET(nm_setting_ip_config_get_method(s_ip),
                         NULL,
                         NM_SETTING_IP4_CONFIG_METHOD_AUTO)) {
        nm_utils_error_set_literal(error,
                                   NM_UTILS_ERROR_CONNECTION_AVAILABLE_INCOMPATIBLE,
                                   "P2P implies 'auto' IPv4 config method");
        return FALSE;
    }

    return TRUE;
}

static gboolean
check_connection_available(NMDevice                      *device,
                           NMConnection                  *connection,
                           NMDeviceCheckConAvailableFlags flags,
                           const char                    *specific_object,
                           GError                       **error)
{
    NMDeviceIwdP2P        *self = NM_DEVICE_IWD_P2P(device);
    NMDeviceIwdP2PPrivate *priv = NM_DEVICE_IWD_P2P_GET_PRIVATE(self);
    NMSettingWifiP2P      *s_wifi_p2p;
    GBytes                *wfd_ies;
    NMWifiP2PPeer         *peer;

    if (specific_object) {
        peer = nm_wifi_p2p_peer_lookup_for_device(NM_DEVICE(self), specific_object);
        if (!peer) {
            g_set_error(error,
                        NM_UTILS_ERROR,
                        NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                        "The P2P peer %s is unknown",
                        specific_object);
            return FALSE;
        }

        if (!nm_wifi_p2p_peer_check_compatible(peer, connection, FALSE)) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "Requested P2P peer is not compatible with profile");
            return FALSE;
        }
    } else {
        peer = nm_wifi_p2p_peers_find_first_compatible(&priv->peers_lst_head, connection, FALSE);
        if (!peer) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "No compatible P2P peer found");
            return FALSE;
        }
    }

    s_wifi_p2p =
        NM_SETTING_WIFI_P2P(nm_connection_get_setting(connection, NM_TYPE_SETTING_WIFI_P2P));
    wfd_ies = nm_setting_wifi_p2p_get_wfd_ies(s_wifi_p2p);
    if (wfd_ies) {
        NMIwdWfdInfo wfd_info = {};

        if (!nm_wifi_utils_parse_wfd_ies(wfd_ies, &wfd_info)) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_INCOMPATIBLE,
                                       "Can't parse connection WFD IEs");
            return FALSE;
        }

        if (!nm_iwd_manager_check_wfd_info_compatible(nm_iwd_manager_get(), &wfd_info)) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "An incompatible WFD connection is active");
            return FALSE;
        }
    }

    return TRUE;
}

static gboolean
complete_connection(NMDevice            *device,
                    NMConnection        *connection,
                    const char          *specific_object,
                    NMConnection *const *existing_connections,
                    GError             **error)
{
    NMDeviceIwdP2P   *self         = NM_DEVICE_IWD_P2P(device);
    gs_free char     *setting_name = NULL;
    NMSettingWifiP2P *s_wifi_p2p;
    NMWifiP2PPeer    *peer;
    const char       *setting_peer;

    s_wifi_p2p =
        NM_SETTING_WIFI_P2P(nm_connection_get_setting(connection, NM_TYPE_SETTING_WIFI_P2P));

    if (!specific_object) {
        /* If not given a specific object, we need at minimum a peer address */
        if (!s_wifi_p2p) {
            g_set_error(error,
                        NM_DEVICE_ERROR,
                        NM_DEVICE_ERROR_INVALID_CONNECTION,
                        "A '%s' setting is required if no Peer path was given",
                        NM_SETTING_WIFI_P2P_SETTING_NAME);
            return FALSE;
        }

        setting_peer = nm_setting_wifi_p2p_get_peer(s_wifi_p2p);
        if (!setting_peer) {
            g_set_error(error,
                        NM_DEVICE_ERROR,
                        NM_DEVICE_ERROR_INVALID_CONNECTION,
                        "A '%s' setting with a valid Peer is required if no Peer path was given",
                        NM_SETTING_WIFI_P2P_SETTING_NAME);
            return FALSE;
        }
    } else {
        peer = nm_wifi_p2p_peer_lookup_for_device(NM_DEVICE(self), specific_object);
        if (!peer) {
            g_set_error(error,
                        NM_DEVICE_ERROR,
                        NM_DEVICE_ERROR_SPECIFIC_OBJECT_NOT_FOUND,
                        "The P2P peer %s is unknown",
                        specific_object);
            return FALSE;
        }

        setting_peer = nm_wifi_p2p_peer_get_address(peer);
        g_return_val_if_fail(setting_peer, FALSE);
    }

    /* Add a Wi-Fi P2P setting if one doesn't exist yet */
    s_wifi_p2p = _nm_connection_ensure_setting(connection, NM_TYPE_SETTING_WIFI_P2P);

    g_object_set(G_OBJECT(s_wifi_p2p), NM_SETTING_WIFI_P2P_PEER, setting_peer, NULL);

    setting_name = g_strdup_printf("Wi-Fi P2P Peer %s", setting_peer);
    nm_utils_complete_generic(nm_device_get_platform(device),
                              connection,
                              NM_SETTING_WIFI_P2P_SETTING_NAME,
                              existing_connections,
                              setting_name,
                              setting_name,
                              NULL,
                              NULL,
                              TRUE);

    return TRUE;
}

static gboolean
get_enabled(NMDevice *device)
{
    return NM_DEVICE_IWD_P2P_GET_PRIVATE(device)->enabled;
}

static void
set_enabled_cb(GObject *source, GAsyncResult *res, gpointer user_data)
{
    NMDeviceIwdP2P            *self    = user_data;
    gs_unref_variant GVariant *variant = NULL;
    gs_free_error GError      *error   = NULL;

    variant = g_dbus_proxy_call_finish(G_DBUS_PROXY(source), res, &error);
    if (!variant) {
        _LOGE(LOGD_DEVICE | LOGD_WIFI, ".Set failed: %s", error->message);
        return;
    }
    _LOGD(LOGD_DEVICE | LOGD_WIFI, ".Set OK!");
}

static void
set_enabled(NMDevice *device, gboolean enabled)
{
    NMDeviceIwdP2P        *self = NM_DEVICE_IWD_P2P(device);
    NMDeviceIwdP2PPrivate *priv = NM_DEVICE_IWD_P2P_GET_PRIVATE(self);

    enabled = !!enabled;

    if (priv->enabled == enabled)
        return;

    _LOGD(LOGD_WIFI, "device will be %s", enabled ? "enabled" : "disabled");

    g_dbus_proxy_call(
        priv->dbus_p2p_proxy,
        DBUS_INTERFACE_PROPERTIES ".Set",
        g_variant_new("(ssv)", NM_IWD_P2P_INTERFACE, "Enabled", g_variant_new("b", enabled)),
        G_DBUS_CALL_FLAGS_NONE,
        2000,
        NULL,
        set_enabled_cb,
        self);
}

static void
p2p_properties_changed_cb(GDBusProxy *proxy,
                          GVariant   *changed_properties,
                          GStrv       invalidate_properties,
                          gpointer    user_data)
{
    NMDeviceIwdP2P        *self   = user_data;
    NMDeviceIwdP2PPrivate *priv   = NM_DEVICE_IWD_P2P_GET_PRIVATE(self);
    NMDevice              *device = NM_DEVICE(self);
    gboolean               new_bool;

    if (g_variant_lookup(changed_properties, "Enabled", "b", &new_bool)
        && new_bool != priv->enabled) {
        priv->enabled = new_bool;

        _LOGD(LOGD_WIFI, "device now %s", priv->enabled ? "enabled" : "disabled");

        if (priv->enabled) {
            NMDeviceState state = nm_device_get_state(device);

            if (state != NM_DEVICE_STATE_UNAVAILABLE)
                _LOGW(LOGD_CORE, "not in expected unavailable state!");

            nm_device_queue_recheck_available(device,
                                              NM_DEVICE_STATE_REASON_SUPPLICANT_AVAILABLE,
                                              NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
        } else {
            nm_device_state_changed(device,
                                    NM_DEVICE_STATE_UNAVAILABLE,
                                    NM_DEVICE_STATE_REASON_NONE);
        }
    }
}

static void
iwd_request_discovery_cb(GObject *source, GAsyncResult *res, gpointer user_data)
{
    NMDeviceIwdP2P            *self    = user_data;
    NMDeviceIwdP2PPrivate     *priv    = NM_DEVICE_IWD_P2P_GET_PRIVATE(self);
    gs_unref_variant GVariant *variant = NULL;
    gs_free_error GError      *error   = NULL;

    variant = g_dbus_proxy_call_finish(G_DBUS_PROXY(source), res, &error);
    if (!variant) {
        NMDevice *device = NM_DEVICE(self);

        _LOGE(LOGD_DEVICE | LOGD_WIFI,
              "%s(wifi-p2p) IWD p2p.Device.RequestDiscovery failed: %s",
              nm_device_is_activating(device) ? "Activation: " : "",
              error->message);

        if (nm_utils_error_is_cancelled(error) && !nm_device_is_activating(device))
            return;

        nm_clear_g_cancellable(&priv->find_cancellable);
        nm_device_state_changed(device,
                                NM_DEVICE_STATE_FAILED,
                                NM_DEVICE_STATE_REASON_PEER_NOT_FOUND);
        return;
    }

    nm_clear_g_cancellable(&priv->find_cancellable);
    _LOGI(LOGD_DEVICE | LOGD_WIFI,
          "%s(wifi-p2p) Target peer discovery running",
          nm_device_is_activating(NM_DEVICE(self)) ? "Activation: " : "");
}

static void
iwd_request_discovery(NMDeviceIwdP2P *self, unsigned timeout)
{
    NMDeviceIwdP2PPrivate *priv      = NM_DEVICE_IWD_P2P_GET_PRIVATE(self);
    bool                   requested = priv->find_peer_timeout_source != NULL;

    nm_clear_g_source_inst(&priv->find_peer_timeout_source);
    priv->find_peer_timeout_source =
        nm_g_timeout_add_seconds_source(timeout, iwd_discovery_timeout_cb, self);

    if (!requested) {
        priv->find_cancellable = g_cancellable_new();

        g_dbus_proxy_call(priv->dbus_p2p_proxy,
                          "RequestDiscovery",
                          NULL,
                          G_DBUS_CALL_FLAGS_NONE,
                          G_MAXINT,
                          priv->find_cancellable,
                          iwd_request_discovery_cb,
                          self);
    }
}

static void
iwd_release_discovery(NMDeviceIwdP2P *self)
{
    NMDeviceIwdP2PPrivate *priv = NM_DEVICE_IWD_P2P_GET_PRIVATE(self);

    nm_clear_g_source_inst(&priv->find_peer_timeout_source);
    nm_clear_g_cancellable(&priv->find_cancellable);

    g_dbus_proxy_call(priv->dbus_p2p_proxy,
                      "ReleaseDiscovery",
                      NULL,
                      G_DBUS_CALL_FLAGS_NONE,
                      G_MAXINT,
                      NULL,
                      NULL,
                      self);
}

/*
 * Called when IWD has been unable to find the peer we want to connect to within the
 * 10s time limit or when a D-bus Find() ends.
 */
static gboolean
iwd_discovery_timeout_cb(gpointer user_data)
{
    NMDeviceIwdP2P        *self   = NM_DEVICE_IWD_P2P(user_data);
    NMDeviceIwdP2PPrivate *priv   = NM_DEVICE_IWD_P2P_GET_PRIVATE(self);
    NMDevice              *device = NM_DEVICE(self);

    nm_clear_g_source_inst(&priv->find_peer_timeout_source);

    iwd_release_discovery(self);

    if (nm_device_is_activating(device)) {
        _LOGW(LOGD_DEVICE | LOGD_WIFI,
              "Activation: (wifi-p2p) Could not find peer, failing activation");
        nm_device_state_changed(device,
                                NM_DEVICE_STATE_FAILED,
                                NM_DEVICE_STATE_REASON_PEER_NOT_FOUND);
    } else {
        _LOGD(LOGD_DEVICE | LOGD_WIFI, "(wifi-p2p) Find timeout");
    }

    return G_SOURCE_REMOVE;
}

static void
cleanup_connect_attempt(NMDeviceIwdP2P *self)
{
    NMDeviceIwdP2PPrivate *priv = NM_DEVICE_IWD_P2P_GET_PRIVATE(self);

    if (priv->find_peer_timeout_source)
        iwd_release_discovery(self);

    if (priv->wfd_registered) {
        nm_iwd_manager_unregister_wfd(nm_iwd_manager_get());
        priv->wfd_registered = FALSE;
    }

    if (!priv->dbus_peer_proxy)
        return;

    if (nm_device_is_activating(NM_DEVICE(self)))
        nm_device_set_ip_iface(NM_DEVICE(self), NULL);

    priv->stage2_ready = FALSE;
    g_signal_handlers_disconnect_by_data(priv->dbus_peer_proxy, self);
    g_clear_object(&priv->dbus_peer_proxy);
    nm_clear_g_cancellable(&priv->connect_cancellable);
}

static void
peer_properties_changed_cb(GDBusProxy *proxy,
                           GVariant   *changed_properties,
                           GStrv       invalidate_properties,
                           gpointer    user_data)
{
    NMDeviceIwdP2P *self  = user_data;
    NMDeviceState   state = nm_device_get_state(NM_DEVICE(self));
    gboolean        new_bool;
    const char     *new_str;

    if (g_variant_lookup(changed_properties, "Connected", "b", &new_bool) && !new_bool
        && state >= NM_DEVICE_STATE_CONFIG && state <= NM_DEVICE_STATE_DEACTIVATING) {
        cleanup_connect_attempt(self);
        nm_device_state_changed(NM_DEVICE(self),
                                NM_DEVICE_STATE_DISCONNECTED,
                                NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT);
    }

    if (g_variant_lookup(changed_properties, "ConnectedInterface", "&s", &new_str)
        && state >= NM_DEVICE_STATE_CONFIG && state <= NM_DEVICE_STATE_IP_CONFIG) {
        nm_device_set_ip_iface(NM_DEVICE(self), new_str);
    }
}

static NMActStageReturn
act_stage1_prepare(NMDevice *device, NMDeviceStateReason *out_failure_reason)
{
    NMDeviceIwdP2P        *self = NM_DEVICE_IWD_P2P(device);
    NMDeviceIwdP2PPrivate *priv = NM_DEVICE_IWD_P2P_GET_PRIVATE(self);
    NMConnection          *connection;
    NMSettingWifiP2P      *s_wifi_p2p;
    NMWifiP2PPeer         *peer;
    GBytes                *wfd_ies;

    if (!priv->enabled) {
        NM_SET_OUT(out_failure_reason, NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
        return NM_ACT_STAGE_RETURN_FAILURE;
    }

    connection = nm_device_get_applied_connection(NM_DEVICE(self));
    g_return_val_if_fail(connection, NM_ACT_STAGE_RETURN_FAILURE);

    s_wifi_p2p =
        NM_SETTING_WIFI_P2P(nm_connection_get_setting(connection, NM_TYPE_SETTING_WIFI_P2P));
    g_return_val_if_fail(s_wifi_p2p, NM_ACT_STAGE_RETURN_FAILURE);

    /* Set the WFD IEs before connecting and before peer discovery if that is needed,
     * usually the WFD IEs need to actually be sent in the Probe frames before we can
     * receive the peers' WFD IEs and decide whether the peer is compatible with the
     * requested WFD parameters.  In the current setup we only get the WFD IEs from
     * the connection settings so during a normal find the client will not be getting
     * any WFD information about the peers and has to decide to connect based on the
     * name and device type (category + subcategory) -- assuming that the peers even
     * bother to reply to probes without WFD IEs.  We'll then need to redo the find
     * here in PREPARE because IWD wants to see that the parameters in the peer's
     * WFD IEs match those in our WFD IEs.  The normal use case for IWD is that the
     * WFD client registers its WFD parameters as soon as it starts and they remain
     * registered during the find and then during the connect.  */
    wfd_ies = nm_setting_wifi_p2p_get_wfd_ies(s_wifi_p2p);
    if (wfd_ies) {
        NMIwdWfdInfo wfd_info = {};

        if (!nm_wifi_utils_parse_wfd_ies(wfd_ies, &wfd_info)) {
            _LOGE(LOGD_DEVICE | LOGD_WIFI, "Activation: (wifi-p2p) Can't parse connection WFD IEs");
            NM_SET_OUT(out_failure_reason, NM_DEVICE_STATE_REASON_CONFIG_FAILED);
            return NM_ACT_STAGE_RETURN_FAILURE;
        }

        if (!nm_iwd_manager_check_wfd_info_compatible(nm_iwd_manager_get(), &wfd_info)) {
            _LOGE(LOGD_DEVICE | LOGD_WIFI,
                  "Activation: (wifi-p2p) An incompatible WFD connection is active");
            NM_SET_OUT(out_failure_reason, NM_DEVICE_STATE_REASON_CONFIG_FAILED);
            return NM_ACT_STAGE_RETURN_FAILURE;
        }

        if (!nm_iwd_manager_register_wfd(nm_iwd_manager_get(), &wfd_info)) {
            _LOGE(LOGD_DEVICE | LOGD_WIFI, "Activation: (wifi-p2p) Can't register WFD service");
            NM_SET_OUT(out_failure_reason, NM_DEVICE_STATE_REASON_CONFIG_FAILED);
            return NM_ACT_STAGE_RETURN_FAILURE;
        }

        priv->wfd_registered = TRUE;
    }

    peer = nm_wifi_p2p_peers_find_first_compatible(&priv->peers_lst_head, connection, TRUE);
    if (!peer) {
        iwd_request_discovery(self, 10);
        return NM_ACT_STAGE_RETURN_POSTPONE;
    } else if (priv->find_peer_timeout_source) {
        iwd_release_discovery(self);
    }

    return NM_ACT_STAGE_RETURN_SUCCESS;
}

static void
iwd_wsc_connect_cb(GObject *source, GAsyncResult *res, gpointer user_data)
{
    NMDeviceIwdP2P            *self    = user_data;
    NMDeviceIwdP2PPrivate     *priv    = NM_DEVICE_IWD_P2P_GET_PRIVATE(self);
    gs_unref_variant GVariant *variant = NULL;
    gs_free_error GError      *error   = NULL;
    NMDevice                  *device  = NM_DEVICE(self);

    variant = g_dbus_proxy_call_finish(G_DBUS_PROXY(source), res, &error);
    if (!variant) {
        _LOGE(LOGD_DEVICE | LOGD_WIFI,
              "Activation: (wifi-p2p) IWD SimpleConfiguration.PushButton/StartPin() failed: %s",
              error->message);

        if (nm_utils_error_is_cancelled(error) && !nm_device_is_activating(device))
            return;

        nm_clear_g_cancellable(&priv->connect_cancellable);
        nm_device_state_changed(device,
                                NM_DEVICE_STATE_FAILED,
                                NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
        return;
    }

    nm_clear_g_cancellable(&priv->connect_cancellable);
    _LOGI(LOGD_DEVICE | LOGD_WIFI, "Activation: (wifi-p2p) IWD connection successful");

    g_signal_connect(priv->dbus_peer_proxy,
                     "g-properties-changed",
                     G_CALLBACK(peer_properties_changed_cb),
                     self);

    priv->stage2_ready = TRUE;

    nm_device_activate_schedule_stage2_device_config(device, FALSE);
}

static NMActStageReturn
act_stage2_config(NMDevice *device, NMDeviceStateReason *out_failure_reason)
{
    NMDeviceIwdP2P             *self = NM_DEVICE_IWD_P2P(device);
    NMDeviceIwdP2PPrivate      *priv = NM_DEVICE_IWD_P2P_GET_PRIVATE(self);
    NMConnection               *connection;
    NMSettingWifiP2P           *s_wifi_p2p;
    NMWifiP2PPeer              *peer;
    gs_unref_object GDBusProxy *peer_proxy = NULL;
    gs_unref_object GDBusProxy *wsc_proxy  = NULL;

    if (priv->stage2_ready)
        return NM_ACT_STAGE_RETURN_SUCCESS;

    if (!priv->dbus_p2p_proxy) {
        cleanup_connect_attempt(self);
        NM_SET_OUT(out_failure_reason, NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
        return NM_ACT_STAGE_RETURN_FAILURE;
    }

    if (nm_clear_g_source_inst(&priv->find_peer_timeout_source))
        nm_assert_not_reached();

    connection = nm_device_get_applied_connection(device);
    g_return_val_if_fail(connection, NM_ACT_STAGE_RETURN_FAILURE);
    nm_assert(
        NM_IS_SETTING_WIFI_P2P(nm_connection_get_setting(connection, NM_TYPE_SETTING_WIFI_P2P)));

    /* The prepare stage ensures that the peer has been found */
    peer = nm_wifi_p2p_peers_find_first_compatible(&priv->peers_lst_head, connection, TRUE);
    if (!peer) {
        cleanup_connect_attempt(self);
        NM_SET_OUT(out_failure_reason, NM_DEVICE_STATE_REASON_PEER_NOT_FOUND);
        return NM_ACT_STAGE_RETURN_FAILURE;
    }

    s_wifi_p2p =
        NM_SETTING_WIFI_P2P(nm_connection_get_setting(connection, NM_TYPE_SETTING_WIFI_P2P));
    if (nm_setting_wifi_p2p_get_wps_method(s_wifi_p2p)
        == NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_PIN) {
        /* TODO: check we have the pin secret, if so use StartPin(pin) otherwise request pin,
         * move to NEED_AUTH and return postpone */
        cleanup_connect_attempt(self);
        NM_SET_OUT(out_failure_reason, NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
        return NM_ACT_STAGE_RETURN_FAILURE;
    }

    peer_proxy = nm_iwd_manager_get_dbus_interface(nm_iwd_manager_get(),
                                                   nm_wifi_p2p_peer_get_supplicant_path(peer),
                                                   NM_IWD_P2P_PEER_INTERFACE);
    wsc_proxy  = nm_iwd_manager_get_dbus_interface(nm_iwd_manager_get(),
                                                  nm_wifi_p2p_peer_get_supplicant_path(peer),
                                                  NM_IWD_WSC_INTERFACE);

    if (!wsc_proxy || !peer_proxy) {
        cleanup_connect_attempt(self);
        NM_SET_OUT(out_failure_reason, NM_DEVICE_STATE_REASON_PEER_NOT_FOUND);
        return NM_ACT_STAGE_RETURN_FAILURE;
    }

    g_dbus_proxy_call(wsc_proxy,
                      "PushButton",
                      NULL,
                      G_DBUS_CALL_FLAGS_NONE,
                      G_MAXINT,
                      priv->connect_cancellable,
                      iwd_wsc_connect_cb,
                      self);

    priv->dbus_peer_proxy = g_steal_pointer(&peer_proxy);
    return NM_ACT_STAGE_RETURN_POSTPONE;
}

/*****************************************************************************/

static void
emit_signal_p2p_peer_add_remove(NMDeviceIwdP2P *device,
                                NMWifiP2PPeer  *peer,
                                gboolean        is_added /* or else is_removed */)
{
    nm_dbus_object_emit_signal(NM_DBUS_OBJECT(device),
                               &interface_info_device_wifi_p2p,
                               is_added ? &nm_signal_info_wifi_p2p_peer_added
                                        : &nm_signal_info_wifi_p2p_peer_removed,
                               "(o)",
                               nm_dbus_object_get_path(NM_DBUS_OBJECT(peer)));
}

static void
act_check_new_peer_compatible(NMDeviceIwdP2P *self, NMWifiP2PPeer *peer)
{
    NMDevice     *device = NM_DEVICE(self);
    NMConnection *connection;

    connection = nm_device_get_applied_connection(device);
    nm_assert(NM_IS_CONNECTION(connection));

    if (nm_wifi_p2p_peer_check_compatible(peer, connection, TRUE)) {
        /* A peer for the connection was found, cancel the timeout and go to configure state. */
        iwd_release_discovery(self);
        nm_device_activate_schedule_stage2_device_config(device, FALSE);
    }
}

static void
peer_add_remove(NMDeviceIwdP2P *self,
                gboolean        is_adding, /* or else removing */
                NMWifiP2PPeer  *peer,
                gboolean        recheck_available_connections)
{
    NMDevice              *device = NM_DEVICE(self);
    NMDeviceIwdP2PPrivate *priv   = NM_DEVICE_IWD_P2P_GET_PRIVATE(self);

    if (is_adding) {
        g_object_ref(peer);
        peer->wifi_device = device;
        c_list_link_tail(&priv->peers_lst_head, &peer->peers_lst);
        nm_dbus_object_export(NM_DBUS_OBJECT(peer));
        _peer_dump(self, LOGL_DEBUG, peer, "added", 0);

        emit_signal_p2p_peer_add_remove(self, peer, TRUE);
    } else {
        peer->wifi_device = NULL;
        c_list_unlink(&peer->peers_lst);
        _peer_dump(self, LOGL_DEBUG, peer, "removed", 0);
    }

    _notify(self, PROP_PEERS);

    if (!is_adding) {
        emit_signal_p2p_peer_add_remove(self, peer, FALSE);
        nm_dbus_object_clear_and_unexport(&peer);
    }

    if (is_adding) {
        /* If we are in prepare state, then we are currently running a find
         * to search for the requested peer. */
        if (priv->find_peer_timeout_source
            && nm_device_get_state(device) == NM_DEVICE_STATE_PREPARE)
            act_check_new_peer_compatible(self, peer);

        /* TODO: We may want to re-check auto-activation here */
    }
}

static void
iwd_peer_interface_added_cb(GDBusObject *peer_obj, GDBusInterface *interface, gpointer user_data)
{
    NMDeviceIwdP2P        *self = user_data;
    NMDeviceIwdP2PPrivate *priv = NM_DEVICE_IWD_P2P_GET_PRIVATE(self);
    const char            *iface_name;
    NMWifiP2PPeer         *peer;

    g_return_if_fail(G_IS_DBUS_PROXY(interface));

    iface_name = g_dbus_proxy_get_interface_name(G_DBUS_PROXY(interface));
    if (!nm_streq(iface_name, NM_IWD_P2P_WFD_INTERFACE))
        return;

    peer = nm_wifi_p2p_peers_find_by_supplicant_path(&priv->peers_lst_head,
                                                     g_dbus_object_get_object_path(peer_obj));
    if (!peer)
        return;

    nm_wifi_p2p_peer_update_from_iwd_object(peer, peer_obj);

    /* If we are in prepare state, then we are currently running a find
     * to search for the requested peer. */
    if (priv->find_peer_timeout_source)
        act_check_new_peer_compatible(self, peer);
}

static void
iwd_peer_interface_removed_cb(GDBusObject *peer_obj, GDBusInterface *interface, gpointer user_data)
{
    NMDeviceIwdP2P        *self = user_data;
    NMDeviceIwdP2PPrivate *priv = NM_DEVICE_IWD_P2P_GET_PRIVATE(self);
    const char            *iface_name;
    NMWifiP2PPeer         *peer;

    g_return_if_fail(G_IS_DBUS_PROXY(interface));

    iface_name = g_dbus_proxy_get_interface_name(G_DBUS_PROXY(interface));
    if (!nm_streq(iface_name, NM_IWD_P2P_WFD_INTERFACE))
        return;

    peer = nm_wifi_p2p_peers_find_by_supplicant_path(&priv->peers_lst_head,
                                                     g_dbus_object_get_object_path(peer_obj));
    if (!peer)
        return;

    nm_wifi_p2p_peer_set_wfd_ies(peer, NULL);
}

void
nm_device_iwd_p2p_peer_add_remove(NMDeviceIwdP2P *self, GDBusObject *peer_obj, bool add)
{
    NMDeviceIwdP2PPrivate *priv = NM_DEVICE_IWD_P2P_GET_PRIVATE(self);
    NMWifiP2PPeer         *found_peer;

    found_peer = nm_wifi_p2p_peers_find_by_supplicant_path(&priv->peers_lst_head,
                                                           g_dbus_object_get_object_path(peer_obj));

    if (found_peer && !add) {
        if (priv->dbus_peer_proxy
            && !nm_streq(g_dbus_object_get_object_path(peer_obj),
                         g_dbus_proxy_get_object_path(priv->dbus_peer_proxy))) {
            cleanup_connect_attempt(self);
            nm_device_state_changed(NM_DEVICE(self),
                                    NM_DEVICE_STATE_DISCONNECTED,
                                    NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT);
        }

        peer_add_remove(self, FALSE, found_peer, TRUE);
        g_signal_handlers_disconnect_by_data(peer_obj, self);
    }

    if (!found_peer && add) {
        gs_unref_object NMWifiP2PPeer *peer = nm_wifi_p2p_peer_new_from_iwd_object(peer_obj);

        if (!peer) {
            _LOGD(LOGD_DEVICE | LOGD_WIFI,
                  "Can't interpret IWD Peer properties at %s",
                  g_dbus_object_get_object_path(peer_obj));
            return;
        }

        peer_add_remove(self, TRUE, peer, TRUE);

        /* None of the D-Bus properties that we use on this interface emit PropertiesChanges
         * signals, only the WFD properties do.  We do listen to changes to "Connected"
         * but only while we're connecting/connected to a given peer.
         */
        g_signal_connect(peer_obj,
                         "interface-added",
                         G_CALLBACK(iwd_peer_interface_added_cb),
                         self);
        g_signal_connect(peer_obj,
                         "interface-removed",
                         G_CALLBACK(iwd_peer_interface_removed_cb),
                         self);

        /* TODO: every now and then call p2p.Device.GetPeers() and update the signal strength
         * values for all peers we got through ObjectManager events.
         */
    }

    schedule_peer_list_dump(self);
}

/*****************************************************************************/

static void
deactivate(NMDevice *device)
{
    NMDeviceIwdP2P        *self = NM_DEVICE_IWD_P2P(device);
    NMDeviceIwdP2PPrivate *priv = NM_DEVICE_IWD_P2P_GET_PRIVATE(self);

    if (priv->find_peer_timeout_source)
        iwd_release_discovery(self);

    if (priv->dbus_peer_proxy) {
        g_dbus_proxy_call(priv->dbus_peer_proxy,
                          "Disconnect",
                          NULL,
                          G_DBUS_CALL_FLAGS_NONE,
                          G_MAXINT,
                          NULL,
                          NULL,
                          self);

        cleanup_connect_attempt(self);
    }
}

static guint32
get_configured_mtu(NMDevice *device, NMDeviceMtuSource *out_source, gboolean *out_force)
{
    *out_source = NM_DEVICE_MTU_SOURCE_NONE;
    return 0;
}

static gboolean
unmanaged_on_quit(NMDevice *self)
{
    return TRUE;
}

static void
device_state_changed(NMDevice           *device,
                     NMDeviceState       new_state,
                     NMDeviceState       old_state,
                     NMDeviceStateReason reason)
{
    NMDeviceIwdP2P        *self = NM_DEVICE_IWD_P2P(device);
    NMDeviceIwdP2PPrivate *priv = NM_DEVICE_IWD_P2P_GET_PRIVATE(self);

    switch (new_state) {
    case NM_DEVICE_STATE_UNMANAGED:
        break;
    case NM_DEVICE_STATE_UNAVAILABLE:
        if (priv->enabled) {
            nm_device_queue_recheck_available(device,
                                              NM_DEVICE_STATE_REASON_SUPPLICANT_AVAILABLE,
                                              NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
        }
        break;
    case NM_DEVICE_STATE_IP_CONFIG:
        /* TODO: start periodic RSSI and bitrate updates? */
        break;
    default:
        break;
    }
}

static void
impl_device_iwd_p2p_start_find(NMDBusObject                      *obj,
                               const NMDBusInterfaceInfoExtended *interface_info,
                               const NMDBusMethodInfoExtended    *method_info,
                               GDBusConnection                   *connection,
                               const char                        *sender,
                               GDBusMethodInvocation             *invocation,
                               GVariant                          *parameters)
{
    NMDeviceIwdP2P            *self    = NM_DEVICE_IWD_P2P(obj);
    NMDeviceIwdP2PPrivate     *priv    = NM_DEVICE_IWD_P2P_GET_PRIVATE(self);
    gs_unref_variant GVariant *options = NULL;
    const char                *opts_key;
    GVariant                  *opts_val;
    GVariantIter               iter;
    gint32                     timeout = 30;

    g_variant_get(parameters, "(@a{sv})", &options);

    g_variant_iter_init(&iter, options);
    while (g_variant_iter_next(&iter, "{&sv}", &opts_key, &opts_val)) {
        _nm_unused gs_unref_variant GVariant *opts_val_free = opts_val;

        if (nm_streq(opts_key, "timeout")) {
            if (!g_variant_is_of_type(opts_val, G_VARIANT_TYPE_INT32)) {
                g_dbus_method_invocation_return_error_literal(
                    invocation,
                    NM_DEVICE_ERROR,
                    NM_DEVICE_ERROR_INVALID_ARGUMENT,
                    "\"timeout\" must be an integer \"i\"");
                return;
            }

            timeout = g_variant_get_int32(opts_val);
            if (timeout <= 0 || timeout > 600) {
                g_dbus_method_invocation_return_error_literal(
                    invocation,
                    NM_DEVICE_ERROR,
                    NM_DEVICE_ERROR_NOT_ALLOWED,
                    "The timeout for a find operation needs to be in the range of 1-600s.");
                return;
            }

            continue;
        }

        g_dbus_method_invocation_return_error(invocation,
                                              NM_DEVICE_ERROR,
                                              NM_DEVICE_ERROR_INVALID_ARGUMENT,
                                              "Unsupported options key \"%s\"",
                                              opts_key);
        return;
    }

    if (!priv->enabled || nm_device_is_activating(NM_DEVICE(self))) {
        g_dbus_method_invocation_return_error_literal(invocation,
                                                      NM_DEVICE_ERROR,
                                                      NM_DEVICE_ERROR_NOT_ACTIVE,
                                                      "P2P device not enabled or busy.");
        return;
    }

    iwd_request_discovery(self, timeout);
    g_dbus_method_invocation_return_value(invocation, NULL);
}

static void
impl_device_iwd_p2p_stop_find(NMDBusObject                      *obj,
                              const NMDBusInterfaceInfoExtended *interface_info,
                              const NMDBusMethodInfoExtended    *method_info,
                              GDBusConnection                   *connection,
                              const char                        *sender,
                              GDBusMethodInvocation             *invocation,
                              GVariant                          *parameters)
{
    NMDeviceIwdP2P        *self = NM_DEVICE_IWD_P2P(obj);
    NMDeviceIwdP2PPrivate *priv = NM_DEVICE_IWD_P2P_GET_PRIVATE(self);

    if (!priv->find_peer_timeout_source || nm_device_is_activating(NM_DEVICE(self))) {
        g_dbus_method_invocation_return_error_literal(invocation,
                                                      NM_DEVICE_ERROR,
                                                      NM_DEVICE_ERROR_NOT_ACTIVE,
                                                      "Find phase is not active.");
        return;
    }

    iwd_release_discovery(self);
    g_dbus_method_invocation_return_value(invocation, NULL);
}

/*****************************************************************************/

static bool
nm_device_iwd_p2p_set_dbus_obj(NMDeviceIwdP2P *self, GDBusObject *obj)
{
    NMDeviceIwdP2PPrivate     *priv;
    gs_unref_variant GVariant *enabled_value = NULL;

    g_return_val_if_fail(NM_IS_DEVICE_IWD_P2P(self), FALSE);

    priv = NM_DEVICE_IWD_P2P_GET_PRIVATE(self);

    if (priv->dbus_obj == obj)
        goto done;

    if (priv->dbus_obj) {
        cleanup_connect_attempt(self);
        g_signal_handlers_disconnect_by_data(priv->dbus_p2p_proxy, self);
        g_clear_object(&priv->dbus_p2p_proxy);
        g_clear_object(&priv->dbus_obj);
        priv->enabled = FALSE;
    }

    if (!obj)
        goto done;

    priv->dbus_p2p_proxy = G_DBUS_PROXY(g_dbus_object_get_interface(obj, NM_IWD_P2P_INTERFACE));
    if (!priv->dbus_p2p_proxy)
        return FALSE;

    enabled_value = g_dbus_proxy_get_cached_property(priv->dbus_p2p_proxy, "Enabled");
    if (!enabled_value || !g_variant_is_of_type(enabled_value, G_VARIANT_TYPE_BOOLEAN))
        return FALSE;

    priv->dbus_obj = g_object_ref(obj);

    g_signal_connect(priv->dbus_p2p_proxy,
                     "g-properties-changed",
                     G_CALLBACK(p2p_properties_changed_cb),
                     self);

    priv->enabled = g_variant_get_boolean(enabled_value);
    _LOGD(LOGD_WIFI, "iniital state is %s", priv->enabled ? "enabled" : "disabled");

done:
    nm_device_queue_recheck_available(NM_DEVICE(self),
                                      NM_DEVICE_STATE_REASON_SUPPLICANT_AVAILABLE,
                                      NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
    return TRUE;
}

void
nm_device_iwd_p2p_remove(NMDeviceIwdP2P *self)
{
    g_signal_emit_by_name(self, NM_DEVICE_REMOVED);
}

/*****************************************************************************/

static const char *
get_type_description(NMDevice *device)
{
    return "wifi-p2p";
}

/*****************************************************************************/

static const GDBusSignalInfo nm_signal_info_wifi_p2p_peer_added = NM_DEFINE_GDBUS_SIGNAL_INFO_INIT(
    "PeerAdded",
    .args = NM_DEFINE_GDBUS_ARG_INFOS(NM_DEFINE_GDBUS_ARG_INFO("peer", "o"), ), );

static const GDBusSignalInfo nm_signal_info_wifi_p2p_peer_removed =
    NM_DEFINE_GDBUS_SIGNAL_INFO_INIT(
        "PeerRemoved",
        .args = NM_DEFINE_GDBUS_ARG_INFOS(NM_DEFINE_GDBUS_ARG_INFO("peer", "o"), ), );

static const NMDBusInterfaceInfoExtended interface_info_device_wifi_p2p = {
    .parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT(
        NM_DBUS_INTERFACE_DEVICE_WIFI_P2P,
        .methods = NM_DEFINE_GDBUS_METHOD_INFOS(
            NM_DEFINE_DBUS_METHOD_INFO_EXTENDED(
                NM_DEFINE_GDBUS_METHOD_INFO_INIT(
                    "StartFind",
                    .in_args = NM_DEFINE_GDBUS_ARG_INFOS(
                        NM_DEFINE_GDBUS_ARG_INFO("options", "a{sv}"), ), ),
                .handle = impl_device_iwd_p2p_start_find, ),
            NM_DEFINE_DBUS_METHOD_INFO_EXTENDED(NM_DEFINE_GDBUS_METHOD_INFO_INIT("StopFind", ),
                                                .handle = impl_device_iwd_p2p_stop_find, ), ),
        .signals    = NM_DEFINE_GDBUS_SIGNAL_INFOS(&nm_signal_info_wifi_p2p_peer_added,
                                                &nm_signal_info_wifi_p2p_peer_removed, ),
        .properties = NM_DEFINE_GDBUS_PROPERTY_INFOS(
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("HwAddress", "s", NM_DEVICE_HW_ADDRESS),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Peers",
                                                           "ao",
                                                           NM_DEVICE_IWD_P2P_PEERS), ), ),
};

/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMDeviceIwdP2P        *self = NM_DEVICE_IWD_P2P(object);
    NMDeviceIwdP2PPrivate *priv = NM_DEVICE_IWD_P2P_GET_PRIVATE(self);
    const char           **list;

    switch (prop_id) {
    case PROP_PEERS:
        list = nm_wifi_p2p_peers_get_paths(&priv->peers_lst_head);
        g_value_take_boxed(value, nm_strv_make_deep_copied(list));
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

/*****************************************************************************/

static void
nm_device_iwd_p2p_init(NMDeviceIwdP2P *self)
{
    NMDeviceIwdP2PPrivate *priv = NM_DEVICE_IWD_P2P_GET_PRIVATE(self);

    c_list_init(&priv->peers_lst_head);
}

NMDeviceIwdP2P *
nm_device_iwd_p2p_new(GDBusObject *dbus_obj)
{
    gs_unref_object NMDeviceIwdP2P *self = NULL;

    g_return_val_if_fail(!dbus_obj || G_IS_DBUS_OBJECT(dbus_obj), NULL);

    /* cfg80211 P2P-Device virtual interfaces don't map to netdev-type interfaces.
     * Provide a false unique interface name only to avoid triggering assertions
     * in NMManager and for that name to appear in debug messages.  */
    self = g_object_new(NM_TYPE_DEVICE_IWD_P2P,
                        NM_DEVICE_IFACE,
                        g_dbus_object_get_object_path(dbus_obj),
                        NM_DEVICE_TYPE_DESC,
                        "802.11 Wi-Fi P2P",
                        NM_DEVICE_DEVICE_TYPE,
                        NM_DEVICE_TYPE_WIFI_P2P,
                        NM_DEVICE_LINK_TYPE,
                        NM_LINK_TYPE_WIFI,
                        NULL);

    if (!self || !nm_device_iwd_p2p_set_dbus_obj(self, dbus_obj))
        return NULL;

    return nm_steal_pointer(&self);
}

static void
dispose(GObject *object)
{
    NMDeviceIwdP2P        *self = NM_DEVICE_IWD_P2P(object);
    NMDeviceIwdP2PPrivate *priv = NM_DEVICE_IWD_P2P_GET_PRIVATE(object);

    nm_clear_g_source_inst(&priv->peer_dump_source);

    nm_device_iwd_p2p_set_dbus_obj(self, NULL);

    G_OBJECT_CLASS(nm_device_iwd_p2p_parent_class)->dispose(object);
}

static void
nm_device_iwd_p2p_class_init(NMDeviceIwdP2PClass *klass)
{
    GObjectClass      *object_class      = G_OBJECT_CLASS(klass);
    NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS(klass);
    NMDeviceClass     *device_class      = NM_DEVICE_CLASS(klass);

    object_class->get_property = get_property;
    object_class->dispose      = dispose;

    dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS(&interface_info_device_wifi_p2p);

    device_class->connection_type_supported        = NM_SETTING_WIFI_P2P_SETTING_NAME;
    device_class->connection_type_check_compatible = NM_SETTING_WIFI_P2P_SETTING_NAME;
    device_class->link_types           = NM_DEVICE_DEFINE_LINK_TYPES(NM_LINK_TYPE_WIFI_P2P);
    device_class->get_type_description = get_type_description;

    device_class->is_available                = is_available;
    device_class->check_connection_compatible = check_connection_compatible;
    device_class->check_connection_available  = check_connection_available;
    device_class->complete_connection         = complete_connection;
    device_class->get_enabled                 = get_enabled;
    device_class->set_enabled                 = set_enabled;

    device_class->act_stage1_prepare = act_stage1_prepare;
    device_class->act_stage2_config  = act_stage2_config;
    device_class->get_configured_mtu = get_configured_mtu;

    device_class->deactivate        = deactivate;
    device_class->unmanaged_on_quit = unmanaged_on_quit;

    device_class->state_changed = device_state_changed;

    device_class->rfkill_type = NM_RFKILL_TYPE_WLAN;

    obj_properties[PROP_PEERS] = g_param_spec_boxed(NM_DEVICE_IWD_P2P_PEERS,
                                                    "",
                                                    "",
                                                    G_TYPE_STRV,
                                                    G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
