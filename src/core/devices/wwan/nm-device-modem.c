/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2009 - 2019 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-device-modem.h"

#include "nm-modem.h"
#include "nm-l3-config-data.h"
#include "devices/nm-device-private.h"
#include "nm-rfkill-manager.h"
#include "settings/nm-settings-connection.h"
#include "nm-modem-broadband.h"
#include "NetworkManagerUtils.h"
#include "libnm-core-intern/nm-core-internal.h"

#define _NMLOG_DEVICE_TYPE NMDeviceModem
#include "devices/nm-device-logging.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE(NMDeviceModem,
                             PROP_MODEM,
                             PROP_CAPABILITIES,
                             PROP_CURRENT_CAPABILITIES,
                             PROP_DEVICE_ID,
                             PROP_OPERATOR_CODE,
                             PROP_APN, );

typedef struct {
    NMModem                  *modem;
    NMDeviceModemCapabilities caps;
    NMDeviceModemCapabilities current_caps;
    NMUtilsIPv6IfaceId        iid;
    char                     *device_id;
    char                     *operator_code;
    char                     *apn;
    bool                      rf_enabled : 1;
    NMDeviceStageState        stage1_state : 3;
    NMDeviceStageState        stage2_state : 3;
} NMDeviceModemPrivate;

struct _NMDeviceModem {
    NMDevice             parent;
    NMDeviceModemPrivate _priv;
};

struct _NMDeviceModemClass {
    NMDeviceClass parent;
};

G_DEFINE_TYPE(NMDeviceModem, nm_device_modem, NM_TYPE_DEVICE)

#define NM_DEVICE_MODEM_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMDeviceModem, NM_IS_DEVICE_MODEM, NMDevice)

/*****************************************************************************/

static void
ppp_failed(NMModem *modem, guint i_reason, gpointer user_data)
{
    NMDevice           *device = NM_DEVICE(user_data);
    NMDeviceStateReason reason = i_reason;

    nm_device_state_changed(device, NM_DEVICE_STATE_FAILED, reason);
}

static void
modem_prepare_result(NMModem *modem, gboolean success, guint i_reason, gpointer user_data)
{
    NMDeviceModem        *self   = NM_DEVICE_MODEM(user_data);
    NMDeviceModemPrivate *priv   = NM_DEVICE_MODEM_GET_PRIVATE(self);
    NMDevice             *device = NM_DEVICE(self);
    NMDeviceStateReason   reason = i_reason;

    if (nm_device_get_state(device) != NM_DEVICE_STATE_PREPARE
        || priv->stage1_state != NM_DEVICE_STAGE_STATE_PENDING) {
        nm_assert_not_reached();
        success = FALSE;
    }

    if (!success) {
        /* There are several reasons to block autoconnection at device level:
         *
         *  - Wrong SIM-PIN: The device won't autoconnect because it doesn't make sense
         *    to retry the connection with the same PIN. This error also makes autoconnection
         *    blocked at settings level, so not even a modem unplug and replug will allow
         *    autoconnection again. It is somewhat redundant to block autoconnection at
         *    both device and setting level really.
         *
         *  - SIM wrong or not inserted: If the modem is reporting a SIM not inserted error,
         *    we can block autoconnection at device level, so that if the same device is
         *    unplugged and replugged with a SIM (or if a SIM hotplug event happens in MM,
         *    recreating the device completely), we can try the autoconnection again.
         *
         *  - Modem initialization failed: For some reason unknown to NM, the modem wasn't
         *    initialized correctly, which leads to an unusable device. A device unplug and
         *    replug may solve the issue, so make it a device-level autoconnection blocking
         *    reason.
         */
        switch (nm_device_state_reason_check(reason)) {
        case NM_DEVICE_STATE_REASON_GSM_SIM_PIN_REQUIRED:
        case NM_DEVICE_STATE_REASON_GSM_SIM_PUK_REQUIRED:
        case NM_DEVICE_STATE_REASON_SIM_PIN_INCORRECT:
            nm_device_autoconnect_blocked_set(device, NM_DEVICE_AUTOCONNECT_BLOCKED_WRONG_PIN);
            break;
        case NM_DEVICE_STATE_REASON_GSM_SIM_NOT_INSERTED:
        case NM_DEVICE_STATE_REASON_GSM_SIM_WRONG:
            nm_device_autoconnect_blocked_set(device, NM_DEVICE_AUTOCONNECT_BLOCKED_SIM_MISSING);
            break;
        case NM_DEVICE_STATE_REASON_MODEM_INIT_FAILED:
            nm_device_autoconnect_blocked_set(device, NM_DEVICE_AUTOCONNECT_BLOCKED_INIT_FAILED);
            break;
        default:
            break;
        }
        nm_device_state_changed(device, NM_DEVICE_STATE_FAILED, reason);
        return;
    }

    priv->stage1_state = NM_DEVICE_STAGE_STATE_COMPLETED;
    nm_device_activate_schedule_stage1_device_prepare(device, FALSE);
}

static void
modem_auth_requested(NMModem *modem, gpointer user_data)
{
    NMDevice *device = NM_DEVICE(user_data);

    /* Auth requests (PIN, PAP/CHAP passwords, etc) only get handled
     * during activation.
     */
    if (!nm_device_is_activating(device))
        return;

    nm_device_state_changed(device, NM_DEVICE_STATE_NEED_AUTH, NM_DEVICE_STATE_REASON_NONE);
}

static void
modem_auth_result(NMModem *modem, GError *error, gpointer user_data)
{
    NMDevice             *device = NM_DEVICE(user_data);
    NMDeviceModemPrivate *priv   = NM_DEVICE_MODEM_GET_PRIVATE(device);

    g_return_if_fail(nm_device_get_state(device) == NM_DEVICE_STATE_NEED_AUTH);

    if (error) {
        nm_device_state_changed(device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_NO_SECRETS);
        return;
    }

    priv->stage1_state = NM_DEVICE_STAGE_STATE_INIT;
    nm_device_activate_schedule_stage1_device_prepare(device, FALSE);
}

static void
modem_new_config(NMModem                  *modem,
                 int                       addr_family,
                 const NML3ConfigData     *l3cd,
                 gboolean                  do_auto,
                 const NMUtilsIPv6IfaceId *iid,
                 int                       failure_reason_i,
                 GError                   *error,
                 gpointer                  user_data)
{
    const int             IS_IPv4 = NM_IS_IPv4(addr_family);
    NMDeviceModem        *self    = NM_DEVICE_MODEM(user_data);
    NMDeviceModemPrivate *priv    = NM_DEVICE_MODEM_GET_PRIVATE(self);
    NMDevice             *device  = NM_DEVICE(self);

    if (nm_device_devip_get_state(device, addr_family) != NM_DEVICE_IP_STATE_PENDING) {
        _LOGD(LOGD_MB, "retrieving IP configuration while no longer in pending state");
        return;
    }

    if (error) {
        _LOGW(LOGD_MB, "retrieving IP configuration failed: %s", error->message);
        nm_device_devip_set_failed(device, addr_family, failure_reason_i);
        return;
    }

    if (!IS_IPv4) {
        priv->iid = iid ? *iid : ((NMUtilsIPv6IfaceId) NM_UTILS_IPV6_IFACE_ID_INIT);
        nm_device_sysctl_ip_conf_set(device, AF_INET6, "disable_ipv6", "0");
    }

    if (do_auto) {
        if (IS_IPv4)
            nm_device_ip_method_dhcp4_start(device);
        else
            nm_device_ip_method_autoconf6_start(device);
    }

    nm_device_devip_set_state(device, addr_family, NM_DEVICE_IP_STATE_READY, l3cd);
}

static void
ip_ifindex_changed_cb(NMModem *modem, GParamSpec *pspec, gpointer user_data)
{
    NMDevice             *device = NM_DEVICE(user_data);
    NMDeviceModem        *self   = NM_DEVICE_MODEM(device);
    NMDeviceModemPrivate *priv   = NM_DEVICE_MODEM_GET_PRIVATE(self);

    if (!nm_device_is_activating(device))
        return;

    if (!nm_device_set_ip_ifindex(device, nm_modem_get_ip_ifindex(modem))) {
        nm_device_state_changed(device,
                                NM_DEVICE_STATE_FAILED,
                                NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
        return;
    }

    /* Disable IPv6 immediately on the interface since NM handles IPv6
     * internally, and leaving it enabled could allow the kernel's IPv6
     * RA handling code to run before NM is ready.
     */
    nm_device_sysctl_ip_conf_set(device, AF_INET6, "disable_ipv6", "1");

    if (priv->stage2_state == NM_DEVICE_STAGE_STATE_PENDING) {
        priv->stage2_state = NM_DEVICE_STAGE_STATE_COMPLETED;
        nm_device_activate_schedule_stage2_device_config(device, FALSE);
    }
}

static void
operator_code_changed_cb(NMModem *modem, GParamSpec *pspec, gpointer user_data)
{
    NMDeviceModem        *self          = NM_DEVICE_MODEM(user_data);
    NMDeviceModemPrivate *priv          = NM_DEVICE_MODEM_GET_PRIVATE(self);
    const char           *operator_code = nm_modem_get_operator_code(modem);

    if (g_strcmp0(priv->operator_code, operator_code) != 0) {
        g_free(priv->operator_code);
        priv->operator_code = g_strdup(operator_code);
        _notify(self, PROP_OPERATOR_CODE);
    }
}

static void
apn_changed_cb(NMModem *modem, GParamSpec *pspec, gpointer user_data)
{
    NMDeviceModem        *self = NM_DEVICE_MODEM(user_data);
    NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE(self);
    const char           *apn  = nm_modem_get_apn(modem);

    if (g_strcmp0(priv->apn, apn) != 0) {
        g_free(priv->apn);
        priv->apn = g_strdup(apn);
        _notify(self, PROP_APN);
    }
}

static void
ids_changed_cb(NMModem *modem, GParamSpec *pspec, gpointer user_data)
{
    nm_device_recheck_available_connections(NM_DEVICE(user_data));
}

static void
modem_state_cb(NMModem *modem, int new_state_i, int old_state_i, gpointer user_data)
{
    NMModemState          new_state = new_state_i;
    NMModemState          old_state = old_state_i;
    NMDevice             *device    = NM_DEVICE(user_data);
    NMDeviceModemPrivate *priv      = NM_DEVICE_MODEM_GET_PRIVATE(device);
    NMDeviceState         dev_state = nm_device_get_state(device);

    if (new_state <= NM_MODEM_STATE_DISABLING && old_state > NM_MODEM_STATE_DISABLING
        && priv->rf_enabled) {
        /* Called when the ModemManager modem enabled state is changed externally
         * to NetworkManager (eg something using MM's D-Bus API directly).
         */

        if (!NM_MODEM_GET_CLASS(priv->modem)->set_mm_enabled) {
            /* We cannot re-enable this modem, thus device becomes unavailable. */
            nm_device_state_changed(device,
                                    NM_DEVICE_STATE_UNAVAILABLE,
                                    NM_DEVICE_STATE_REASON_USER_REQUESTED);
            return;
        }

        if (nm_device_is_activating(device) || dev_state == NM_DEVICE_STATE_ACTIVATED) {
            /* user-initiated action, hence DISCONNECTED not FAILED */
            nm_device_state_changed(device,
                                    NM_DEVICE_STATE_DISCONNECTED,
                                    NM_DEVICE_STATE_REASON_USER_REQUESTED);
            return;
        }
    }

    if (new_state < NM_MODEM_STATE_CONNECTING && old_state >= NM_MODEM_STATE_CONNECTING
        && dev_state >= NM_DEVICE_STATE_NEED_AUTH && dev_state <= NM_DEVICE_STATE_ACTIVATED) {
        /* Fail the device if the modem disconnects unexpectedly while the
         * device is activating/activated. */
        nm_device_state_changed(device,
                                NM_DEVICE_STATE_FAILED,
                                NM_DEVICE_STATE_REASON_MODEM_NO_CARRIER);
    }

    if (new_state > NM_MODEM_STATE_LOCKED && old_state == NM_MODEM_STATE_LOCKED) {
        /* If the modem is now unlocked, enable/disable it according to the
         * device's enabled/disabled state.
         */
        nm_modem_set_mm_enabled(priv->modem, priv->rf_enabled);

        if (dev_state == NM_DEVICE_STATE_NEED_AUTH) {
            /* The modem was unlocked externally to NetworkManager,
             * deactivate so the default connection can be
             * automatically activated again */
            nm_device_state_changed(device,
                                    NM_DEVICE_STATE_DEACTIVATING,
                                    NM_DEVICE_STATE_REASON_MODEM_AVAILABLE);
        }

        /* Now allow connections without a PIN to be available */
        nm_device_recheck_available_connections(device);
    }

    nm_device_queue_recheck_available(device,
                                      NM_DEVICE_STATE_REASON_MODEM_AVAILABLE,
                                      NM_DEVICE_STATE_REASON_MODEM_FAILED);
}

static void
modem_removed_cb(NMModem *modem, gpointer user_data)
{
    g_signal_emit_by_name(NM_DEVICE(user_data), NM_DEVICE_REMOVED);
}

/*****************************************************************************/

static gboolean
owns_iface(NMDevice *device, const char *iface)
{
    NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE(device);

    g_return_val_if_fail(priv->modem, FALSE);

    return nm_modem_owns_port(priv->modem, iface);
}

/*****************************************************************************/

static void
device_state_changed(NMDevice           *device,
                     NMDeviceState       new_state,
                     NMDeviceState       old_state,
                     NMDeviceStateReason reason)
{
    NMDeviceModem        *self = NM_DEVICE_MODEM(device);
    NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE(self);

    g_return_if_fail(priv->modem);

    if (new_state == NM_DEVICE_STATE_UNAVAILABLE && old_state < NM_DEVICE_STATE_UNAVAILABLE) {
        /* Log initial modem state */
        _LOGI(LOGD_MB,
              "modem state '%s'",
              nm_modem_state_to_string(nm_modem_get_state(priv->modem)));
    }
    nm_modem_device_state_changed(priv->modem, new_state, old_state);
}

static NMDeviceCapabilities
get_generic_capabilities(NMDevice *device)
{
    return NM_DEVICE_CAP_IS_NON_KERNEL;
}

static const char *
get_type_description(NMDevice *device)
{
    NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE(device);

    if (NM_FLAGS_HAS(priv->current_caps, NM_DEVICE_MODEM_CAPABILITY_GSM_UMTS))
        return "gsm";
    if (NM_FLAGS_HAS(priv->current_caps, NM_DEVICE_MODEM_CAPABILITY_CDMA_EVDO))
        return "cdma";
    return NM_DEVICE_CLASS(nm_device_modem_parent_class)->get_type_description(device);
}

static gboolean
check_connection_compatible(NMDevice *device, NMConnection *connection, GError **error)
{
    GError *local = NULL;

    if (!NM_DEVICE_CLASS(nm_device_modem_parent_class)
             ->check_connection_compatible(device, connection, error))
        return FALSE;

    if (!nm_modem_check_connection_compatible(NM_DEVICE_MODEM_GET_PRIVATE(device)->modem,
                                              connection,
                                              error ? &local : NULL)) {
        if (error) {
            g_set_error(error,
                        NM_UTILS_ERROR,
                        g_error_matches(local,
                                        NM_UTILS_ERROR,
                                        NM_UTILS_ERROR_CONNECTION_AVAILABLE_INCOMPATIBLE)
                            ? NM_UTILS_ERROR_CONNECTION_AVAILABLE_INCOMPATIBLE
                            : NM_UTILS_ERROR_UNKNOWN,
                        "modem is incompatible with connection: %s",
                        local->message);
            g_error_free(local);
        }
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
    NMDeviceModem        *self = NM_DEVICE_MODEM(device);
    NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE(self);
    NMModemState          state;

    if (!priv->rf_enabled) {
        nm_utils_error_set_literal(error,
                                   NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                   "RFKILL for modem enabled");
        return FALSE;
    }

    if (!priv->modem) {
        nm_utils_error_set_literal(error,
                                   NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                   "modem not available");
        return FALSE;
    }

    state = nm_modem_get_state(priv->modem);
    if (state <= NM_MODEM_STATE_INITIALIZING) {
        nm_utils_error_set_literal(error,
                                   NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                   "modem not initialized");
        return FALSE;
    }

    if (!NM_MODEM_GET_CLASS(priv->modem)->set_mm_enabled && state <= NM_MODEM_STATE_DISABLING) {
        nm_utils_error_set_literal(error,
                                   NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                   "modem is disabled and NM cannot enable it");
        return FALSE;
    }

    if (state == NM_MODEM_STATE_LOCKED) {
        if (!nm_connection_get_setting_gsm(connection)) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "modem is locked without pin available");
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
    NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE(device);

    return nm_modem_complete_connection(priv->modem,
                                        nm_device_get_iface(device),
                                        connection,
                                        existing_connections,
                                        error);
}

static void
deactivate(NMDevice *device)
{
    NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE(device);

    nm_modem_deactivate(priv->modem, device);
    priv->stage1_state = NM_DEVICE_STAGE_STATE_INIT;
    priv->stage2_state = NM_DEVICE_STAGE_STATE_INIT;
}

/*****************************************************************************/

static void
modem_deactivate_async_cb(NMModem *modem, GError *error, gpointer user_data)
{
    gs_unref_object NMDevice  *self = NULL;
    NMDeviceDeactivateCallback callback;
    gpointer                   callback_user_data;

    nm_utils_user_data_unpack(user_data, &self, &callback, &callback_user_data);
    callback(self, error, callback_user_data);
}

static void
deactivate_async(NMDevice                  *self,
                 GCancellable              *cancellable,
                 NMDeviceDeactivateCallback callback,
                 gpointer                   user_data)
{
    nm_assert(G_IS_CANCELLABLE(cancellable));
    nm_assert(callback);

    nm_modem_deactivate_async(NM_DEVICE_MODEM_GET_PRIVATE(self)->modem,
                              self,
                              cancellable,
                              modem_deactivate_async_cb,
                              nm_utils_user_data_pack(g_object_ref(self), callback, user_data));
}

/*****************************************************************************/

static NMActStageReturn
act_stage1_prepare(NMDevice *device, NMDeviceStateReason *out_failure_reason)
{
    NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE(device);
    NMActRequest         *req;

    req = nm_device_get_act_request(device);
    g_return_val_if_fail(req, NM_ACT_STAGE_RETURN_FAILURE);

    if (priv->stage1_state == NM_DEVICE_STAGE_STATE_INIT) {
        priv->stage1_state = NM_DEVICE_STAGE_STATE_PENDING;
        return nm_modem_act_stage1_prepare(NM_DEVICE_MODEM_GET_PRIVATE(device)->modem,
                                           req,
                                           out_failure_reason);
    }

    if (priv->stage1_state == NM_DEVICE_STAGE_STATE_PENDING)
        return NM_ACT_STAGE_RETURN_POSTPONE;

    nm_assert(priv->stage1_state == NM_DEVICE_STAGE_STATE_COMPLETED);
    return NM_ACT_STAGE_RETURN_SUCCESS;
}

static NMActStageReturn
act_stage2_config(NMDevice *device, NMDeviceStateReason *out_failure_reason)
{
    NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE(device);

    if (priv->stage2_state == NM_DEVICE_STAGE_STATE_INIT) {
        priv->stage2_state = NM_DEVICE_STAGE_STATE_PENDING;
        return nm_modem_act_stage2_config(NM_DEVICE_MODEM_GET_PRIVATE(device)->modem,
                                          device,
                                          out_failure_reason);
    }
    if (priv->stage2_state == NM_DEVICE_STAGE_STATE_PENDING)
        return NM_ACT_STAGE_RETURN_POSTPONE;

    nm_assert(priv->stage2_state == NM_DEVICE_STAGE_STATE_COMPLETED);
    return NM_ACT_STAGE_RETURN_SUCCESS;
}

static void
act_stage3_ip_config(NMDevice *device, int addr_family)
{
    NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE(device);

    if (nm_modem_stage3_ip_config_start(priv->modem, addr_family, device))
        nm_device_devip_set_state(device, addr_family, NM_DEVICE_IP_STATE_PENDING, NULL);
}

static gboolean
get_ip_iface_identifier(NMDevice *device, NMUtilsIPv6IfaceId *out_iid)
{
    NMDeviceModem        *self = NM_DEVICE_MODEM(device);
    NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE(self);

    g_return_val_if_fail(priv->modem, FALSE);

    if (priv->iid.id != 0) {
        *out_iid = priv->iid;
        return TRUE;
    }

    return NM_DEVICE_CLASS(nm_device_modem_parent_class)->get_ip_iface_identifier(device, out_iid);
}

/*****************************************************************************/

static gboolean
get_enabled(NMDevice *device)
{
    NMDeviceModemPrivate *priv        = NM_DEVICE_MODEM_GET_PRIVATE(device);
    NMModemState          modem_state = nm_modem_get_state(priv->modem);

    return priv->rf_enabled && (modem_state >= NM_MODEM_STATE_LOCKED);
}

static void
set_enabled(NMDevice *device, gboolean enabled)
{
    NMDeviceModem        *self = NM_DEVICE_MODEM(device);
    NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE(self);

    /* Called only by the Manager in response to rfkill switch changes or
     * global user WWAN enable/disable preference changes.
     */
    priv->rf_enabled = enabled;

    if (priv->modem) {
        /* Sync the ModemManager modem enabled/disabled with rfkill/user preference */
        nm_modem_set_mm_enabled(priv->modem, enabled);
    }

    if (enabled == FALSE) {
        nm_device_state_changed(device, NM_DEVICE_STATE_UNAVAILABLE, NM_DEVICE_STATE_REASON_NONE);
    } else {
        /* It's possible that the modem is enabled outside of NM. Need to recheck. */
        nm_device_queue_recheck_available(device,
                                          NM_DEVICE_STATE_REASON_MODEM_AVAILABLE,
                                          NM_DEVICE_STATE_REASON_MODEM_FAILED);
    }
}

static gboolean
is_available(NMDevice *device, NMDeviceCheckDevAvailableFlags flags)
{
    NMDeviceModem        *self = NM_DEVICE_MODEM(device);
    NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE(self);
    NMModemState          modem_state;

    if (!priv->rf_enabled)
        return FALSE;

    g_assert(priv->modem);
    modem_state = nm_modem_get_state(priv->modem);
    if (modem_state <= NM_MODEM_STATE_INITIALIZING)
        return FALSE;

    if (!NM_MODEM_GET_CLASS(priv->modem)->set_mm_enabled && modem_state <= NM_MODEM_STATE_DISABLING)
        return FALSE;

    return TRUE;
}

static gboolean
ready_for_ip_config(NMDevice *device, gboolean is_manual)
{
    /* Tell NMDevice to only run manual and device-specific IP
     * configuration (devip) and skip other methods
     * (dhcp, link-local, shared, etc).
     */
    return is_manual;
}

/*****************************************************************************/

static void
set_modem(NMDeviceModem *self, NMModem *modem)
{
    NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE(self);

    g_return_if_fail(modem != NULL);

    priv->modem = nm_modem_claim(modem);

    g_signal_connect(modem, NM_MODEM_PPP_FAILED, G_CALLBACK(ppp_failed), self);
    g_signal_connect(modem, NM_MODEM_PREPARE_RESULT, G_CALLBACK(modem_prepare_result), self);
    g_signal_connect(modem, NM_MODEM_NEW_CONFIG, G_CALLBACK(modem_new_config), self);
    g_signal_connect(modem, NM_MODEM_AUTH_REQUESTED, G_CALLBACK(modem_auth_requested), self);
    g_signal_connect(modem, NM_MODEM_AUTH_RESULT, G_CALLBACK(modem_auth_result), self);
    g_signal_connect(modem, NM_MODEM_STATE_CHANGED, G_CALLBACK(modem_state_cb), self);
    g_signal_connect(modem, NM_MODEM_REMOVED, G_CALLBACK(modem_removed_cb), self);

    g_signal_connect(modem,
                     "notify::" NM_MODEM_IP_IFINDEX,
                     G_CALLBACK(ip_ifindex_changed_cb),
                     self);
    g_signal_connect(modem, "notify::" NM_MODEM_DEVICE_ID, G_CALLBACK(ids_changed_cb), self);
    g_signal_connect(modem, "notify::" NM_MODEM_SIM_ID, G_CALLBACK(ids_changed_cb), self);
    g_signal_connect(modem, "notify::" NM_MODEM_SIM_OPERATOR_ID, G_CALLBACK(ids_changed_cb), self);
    g_signal_connect(modem,
                     "notify::" NM_MODEM_OPERATOR_CODE,
                     G_CALLBACK(operator_code_changed_cb),
                     self);
    g_signal_connect(modem, "notify::" NM_MODEM_APN, G_CALLBACK(apn_changed_cb), self);
}

static guint32
get_dhcp_timeout_for_device(NMDevice *device, int addr_family)
{
    /* DHCP is always done by the modem firmware, not by the network, and
     * by the time we get around to DHCP the firmware should already know
     * the IP addressing details.  So the DHCP timeout can be much shorter.
     */
    return 15;
}

/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE(object);

    switch (prop_id) {
    case PROP_MODEM:
        g_value_set_object(value, priv->modem);
        break;
    case PROP_CAPABILITIES:
        g_value_set_uint(value, priv->caps);
        break;
    case PROP_CURRENT_CAPABILITIES:
        g_value_set_uint(value, priv->current_caps);
        break;
    case PROP_DEVICE_ID:
        g_value_set_string(value, priv->device_id);
        break;
    case PROP_OPERATOR_CODE:
        g_value_set_string(value, priv->operator_code);
        break;
    case PROP_APN:
        g_value_set_string(value, priv->apn);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
    NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE(object);

    switch (prop_id) {
    case PROP_MODEM:
        /* construct-only */
        set_modem(NM_DEVICE_MODEM(object), g_value_get_object(value));
        break;
    case PROP_CAPABILITIES:
        priv->caps = g_value_get_uint(value);
        break;
    case PROP_CURRENT_CAPABILITIES:
        priv->current_caps = g_value_get_uint(value);
        break;
    case PROP_DEVICE_ID:
        /* construct-only */
        priv->device_id = g_value_dup_string(value);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

/*****************************************************************************/

static void
nm_device_modem_init(NMDeviceModem *self)
{}

NMDevice *
nm_device_modem_new(NMModem *modem)
{
    NMDeviceModemCapabilities caps         = NM_DEVICE_MODEM_CAPABILITY_NONE;
    NMDeviceModemCapabilities current_caps = NM_DEVICE_MODEM_CAPABILITY_NONE;

    g_return_val_if_fail(NM_IS_MODEM(modem), NULL);

    /* Load capabilities */
    nm_modem_get_capabilities(modem, &caps, &current_caps);

    return g_object_new(NM_TYPE_DEVICE_MODEM,
                        NM_DEVICE_UDI,
                        nm_modem_get_path(modem),
                        NM_DEVICE_IFACE,
                        nm_modem_get_uid(modem),
                        NM_DEVICE_DRIVER,
                        nm_modem_get_driver(modem),
                        NM_DEVICE_TYPE_DESC,
                        "Broadband",
                        NM_DEVICE_DEVICE_TYPE,
                        NM_DEVICE_TYPE_MODEM,
                        NM_DEVICE_MODEM_MODEM,
                        modem,
                        NM_DEVICE_MODEM_CAPABILITIES,
                        (guint) ((guint32) caps),
                        NM_DEVICE_MODEM_CURRENT_CAPABILITIES,
                        (guint) ((guint32) current_caps),
                        NM_DEVICE_MODEM_DEVICE_ID,
                        nm_modem_get_device_id(modem),
                        NULL);
}

static void
dispose(GObject *object)
{
    NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE(object);

    if (priv->modem) {
        g_signal_handlers_disconnect_by_data(priv->modem, NM_DEVICE_MODEM(object));
        nm_clear_pointer(&priv->modem, nm_modem_unclaim);
    }

    nm_clear_g_free(&priv->device_id);
    nm_clear_g_free(&priv->operator_code);
    nm_clear_g_free(&priv->apn);

    G_OBJECT_CLASS(nm_device_modem_parent_class)->dispose(object);
}

static const NMDBusInterfaceInfoExtended interface_info_device_modem = {
    .parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT(
        NM_DBUS_INTERFACE_DEVICE_MODEM,
        .properties = NM_DEFINE_GDBUS_PROPERTY_INFOS(
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("ModemCapabilities",
                                                           "u",
                                                           NM_DEVICE_MODEM_CAPABILITIES),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("CurrentCapabilities",
                                                           "u",
                                                           NM_DEVICE_MODEM_CURRENT_CAPABILITIES),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("DeviceId",
                                                           "s",
                                                           NM_DEVICE_MODEM_DEVICE_ID),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("OperatorCode",
                                                           "s",
                                                           NM_DEVICE_MODEM_OPERATOR_CODE),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Apn", "s", NM_DEVICE_MODEM_APN), ), ),
};

static void
nm_device_modem_class_init(NMDeviceModemClass *klass)
{
    GObjectClass      *object_class      = G_OBJECT_CLASS(klass);
    NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS(klass);
    NMDeviceClass     *device_class      = NM_DEVICE_CLASS(klass);

    object_class->dispose      = dispose;
    object_class->get_property = get_property;
    object_class->set_property = set_property;

    dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS(&interface_info_device_modem);

    device_class->get_generic_capabilities    = get_generic_capabilities;
    device_class->get_type_description        = get_type_description;
    device_class->check_connection_compatible = check_connection_compatible;
    device_class->check_connection_available  = check_connection_available;
    device_class->complete_connection         = complete_connection;
    device_class->deactivate_async            = deactivate_async;
    device_class->deactivate                  = deactivate;
    device_class->act_stage1_prepare          = act_stage1_prepare;
    device_class->act_stage2_config           = act_stage2_config;
    device_class->act_stage3_ip_config        = act_stage3_ip_config;
    device_class->get_enabled                 = get_enabled;
    device_class->set_enabled                 = set_enabled;
    device_class->owns_iface                  = owns_iface;
    device_class->is_available                = is_available;
    device_class->get_ip_iface_identifier     = get_ip_iface_identifier;
    device_class->get_configured_mtu          = nm_modem_get_configured_mtu;
    device_class->get_dhcp_timeout_for_device = get_dhcp_timeout_for_device;
    device_class->ready_for_ip_config         = ready_for_ip_config;

    device_class->state_changed = device_state_changed;

    device_class->rfkill_type = NM_RFKILL_TYPE_WWAN;

    obj_properties[PROP_MODEM] =
        g_param_spec_object(NM_DEVICE_MODEM_MODEM,
                            "",
                            "",
                            NM_TYPE_MODEM,
                            G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_CAPABILITIES] =
        g_param_spec_uint(NM_DEVICE_MODEM_CAPABILITIES,
                          "",
                          "",
                          0,
                          G_MAXUINT32,
                          NM_DEVICE_MODEM_CAPABILITY_NONE,
                          G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_CURRENT_CAPABILITIES] =
        g_param_spec_uint(NM_DEVICE_MODEM_CURRENT_CAPABILITIES,
                          "",
                          "",
                          0,
                          G_MAXUINT32,
                          NM_DEVICE_MODEM_CAPABILITY_NONE,
                          G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_DEVICE_ID] =
        g_param_spec_string(NM_DEVICE_MODEM_DEVICE_ID,
                            "",
                            "",
                            NULL,
                            G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_OPERATOR_CODE] =
        g_param_spec_string(NM_DEVICE_MODEM_OPERATOR_CODE,
                            "",
                            "",
                            NULL,
                            G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_APN] = g_param_spec_string(NM_DEVICE_MODEM_APN,
                                                   "",
                                                   "",
                                                   NULL,
                                                   G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
