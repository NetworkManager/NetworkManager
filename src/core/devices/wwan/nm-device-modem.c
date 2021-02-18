/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2009 - 2019 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-device-modem.h"

#include "nm-modem.h"
#include "nm-ip4-config.h"
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
    NMModem *                 modem;
    NMDeviceModemCapabilities caps;
    NMDeviceModemCapabilities current_caps;
    char *                    device_id;
    char *                    operator_code;
    char *                    apn;
    bool                      rf_enabled : 1;
    NMDeviceStageState        stage1_state : 3;
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
    NMDevice *          device = NM_DEVICE(user_data);
    NMDeviceModem *     self   = NM_DEVICE_MODEM(user_data);
    NMDeviceStateReason reason = i_reason;

    switch (nm_device_get_state(device)) {
    case NM_DEVICE_STATE_PREPARE:
    case NM_DEVICE_STATE_CONFIG:
    case NM_DEVICE_STATE_NEED_AUTH:
        nm_device_state_changed(device, NM_DEVICE_STATE_FAILED, reason);
        break;
    case NM_DEVICE_STATE_IP_CONFIG:
    case NM_DEVICE_STATE_IP_CHECK:
    case NM_DEVICE_STATE_SECONDARIES:
    case NM_DEVICE_STATE_ACTIVATED:
        if (nm_device_activate_ip4_state_in_conf(device))
            nm_device_activate_schedule_ip_config_timeout(device, AF_INET);
        else if (nm_device_activate_ip6_state_in_conf(device))
            nm_device_activate_schedule_ip_config_timeout(device, AF_INET6);
        else if (nm_device_activate_ip4_state_done(device)) {
            nm_device_ip_method_failed(device,
                                       AF_INET,
                                       NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
        } else if (nm_device_activate_ip6_state_done(device)) {
            nm_device_ip_method_failed(device,
                                       AF_INET6,
                                       NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
        } else {
            _LOGW(LOGD_MB,
                  "PPP failure in unexpected state %u",
                  (guint) nm_device_get_state(device));
            nm_device_state_changed(device,
                                    NM_DEVICE_STATE_FAILED,
                                    NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
        }
        break;
    default:
        break;
    }
}

static void
modem_prepare_result(NMModem *modem, gboolean success, guint i_reason, gpointer user_data)
{
    NMDeviceModem *       self   = NM_DEVICE_MODEM(user_data);
    NMDeviceModemPrivate *priv   = NM_DEVICE_MODEM_GET_PRIVATE(self);
    NMDevice *            device = NM_DEVICE(self);
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
    NMDevice *            device = NM_DEVICE(user_data);
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
modem_ip4_config_result(NMModem *modem, NMIP4Config *config, GError *error, gpointer user_data)
{
    NMDeviceModem *self   = NM_DEVICE_MODEM(user_data);
    NMDevice *     device = NM_DEVICE(self);

    g_return_if_fail(nm_device_activate_ip4_state_in_conf(device) == TRUE);

    if (error) {
        _LOGW(LOGD_MB | LOGD_IP4, "retrieving IPv4 configuration failed: %s", error->message);
        nm_device_ip_method_failed(device, AF_INET, NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
    } else {
        nm_device_set_dev2_ip_config(device, AF_INET, NM_IP_CONFIG_CAST(config));
        nm_device_activate_schedule_ip_config_result(device, AF_INET, NULL);
    }
}

static void
modem_ip6_config_result(NMModem *    modem,
                        NMIP6Config *config,
                        gboolean     do_slaac,
                        GError *     error,
                        gpointer     user_data)
{
    NMDeviceModem *     self   = NM_DEVICE_MODEM(user_data);
    NMDevice *          device = NM_DEVICE(self);
    NMActStageReturn    ret;
    NMDeviceStateReason failure_reason      = NM_DEVICE_STATE_REASON_NONE;
    gs_unref_object NMIP6Config *ignored    = NULL;
    gboolean                     got_config = !!config;

    g_return_if_fail(nm_device_activate_ip6_state_in_conf(device) == TRUE);

    if (error) {
        _LOGW(LOGD_MB | LOGD_IP6, "retrieving IPv6 configuration failed: %s", error->message);
        nm_device_ip_method_failed(device, AF_INET6, NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
        return;
    }

    /* Re-enable IPv6 on the interface */
    nm_device_sysctl_ip_conf_set(device, AF_INET6, "disable_ipv6", "0");

    if (config)
        nm_device_set_dev2_ip_config(device, AF_INET6, NM_IP_CONFIG_CAST(config));

    if (do_slaac == FALSE) {
        if (got_config)
            nm_device_activate_schedule_ip_config_result(device, AF_INET6, NULL);
        else {
            _LOGW(LOGD_MB | LOGD_IP6,
                  "retrieving IPv6 configuration failed: SLAAC not requested and no addresses");
            nm_device_ip_method_failed(device,
                                       AF_INET6,
                                       NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
        }
        return;
    }

    /* Start SLAAC now that we have a link-local address from the modem */
    ret =
        NM_DEVICE_CLASS(nm_device_modem_parent_class)
            ->act_stage3_ip_config_start(device, AF_INET6, (gpointer *) &ignored, &failure_reason);

    nm_assert(ignored == NULL);

    switch (ret) {
    case NM_ACT_STAGE_RETURN_FAILURE:
        nm_device_ip_method_failed(device, AF_INET6, failure_reason);
        break;
    case NM_ACT_STAGE_RETURN_IP_FAIL:
        /* all done */
        nm_device_activate_schedule_ip_config_result(device, AF_INET6, NULL);
        break;
    case NM_ACT_STAGE_RETURN_POSTPONE:
        /* let SLAAC run */
        break;
    default:
        /* Should never get here since we've assured that the IPv6 method
         * will either be "auto" or "ignored" when starting IPv6 configuration.
         */
        nm_assert_not_reached();
    }
}

static void
ip_ifindex_changed_cb(NMModem *modem, GParamSpec *pspec, gpointer user_data)
{
    NMDevice *device = NM_DEVICE(user_data);

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
}

static void
operator_code_changed_cb(NMModem *modem, GParamSpec *pspec, gpointer user_data)
{
    NMDeviceModem *       self          = NM_DEVICE_MODEM(user_data);
    NMDeviceModemPrivate *priv          = NM_DEVICE_MODEM_GET_PRIVATE(self);
    const char *          operator_code = nm_modem_get_operator_code(modem);

    if (g_strcmp0(priv->operator_code, operator_code) != 0) {
        g_free(priv->operator_code);
        priv->operator_code = g_strdup(operator_code);
        _notify(self, PROP_OPERATOR_CODE);
    }
}

static void
apn_changed_cb(NMModem *modem, GParamSpec *pspec, gpointer user_data)
{
    NMDeviceModem *       self = NM_DEVICE_MODEM(user_data);
    NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE(self);
    const char *          apn  = nm_modem_get_apn(modem);

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
    NMDevice *            device    = NM_DEVICE(user_data);
    NMDeviceModemPrivate *priv      = NM_DEVICE_MODEM_GET_PRIVATE(device);
    NMDeviceState         dev_state = nm_device_get_state(device);

    if (new_state <= NM_MODEM_STATE_DISABLING && old_state > NM_MODEM_STATE_DISABLING
        && priv->rf_enabled) {
        /* Called when the ModemManager modem enabled state is changed externally
         * to NetworkManager (eg something using MM's D-Bus API directly).
         */
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
        return;
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
device_state_changed(NMDevice *          device,
                     NMDeviceState       new_state,
                     NMDeviceState       old_state,
                     NMDeviceStateReason reason)
{
    NMDeviceModem *       self = NM_DEVICE_MODEM(device);
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
check_connection_available(NMDevice *                     device,
                           NMConnection *                 connection,
                           NMDeviceCheckConAvailableFlags flags,
                           const char *                   specific_object,
                           GError **                      error)
{
    NMDeviceModem *       self = NM_DEVICE_MODEM(device);
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
complete_connection(NMDevice *           device,
                    NMConnection *       connection,
                    const char *         specific_object,
                    NMConnection *const *existing_connections,
                    GError **            error)
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
}

/*****************************************************************************/

static void
modem_deactivate_async_cb(NMModem *modem, GError *error, gpointer user_data)
{
    gs_unref_object NMDevice * self = NULL;
    NMDeviceDeactivateCallback callback;
    gpointer                   callback_user_data;

    nm_utils_user_data_unpack(user_data, &self, &callback, &callback_user_data);
    callback(self, error, callback_user_data);
}

static void
deactivate_async(NMDevice *                 self,
                 GCancellable *             cancellable,
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
    NMActRequest *        req;

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
    nm_modem_act_stage2_config(NM_DEVICE_MODEM_GET_PRIVATE(device)->modem);
    return NM_ACT_STAGE_RETURN_SUCCESS;
}

static NMActStageReturn
act_stage3_ip_config_start(NMDevice *           device,
                           int                  addr_family,
                           gpointer *           out_config,
                           NMDeviceStateReason *out_failure_reason)
{
    NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE(device);

    nm_assert_addr_family(addr_family);

    if (addr_family == AF_INET) {
        return nm_modem_stage3_ip4_config_start(priv->modem,
                                                device,
                                                NM_DEVICE_CLASS(nm_device_modem_parent_class),
                                                out_failure_reason);
    } else {
        return nm_modem_stage3_ip6_config_start(priv->modem, device, out_failure_reason);
    }
}

static void
ip4_config_pre_commit(NMDevice *device, NMIP4Config *config)
{
    nm_modem_ip4_pre_commit(NM_DEVICE_MODEM_GET_PRIVATE(device)->modem, device, config);
}

static gboolean
get_ip_iface_identifier(NMDevice *device, NMUtilsIPv6IfaceId *out_iid)
{
    NMDeviceModem *       self = NM_DEVICE_MODEM(device);
    NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE(self);
    gboolean              success;

    g_return_val_if_fail(priv->modem, FALSE);
    success = nm_modem_get_iid(priv->modem, out_iid);
    if (!success)
        success =
            NM_DEVICE_CLASS(nm_device_modem_parent_class)->get_ip_iface_identifier(device, out_iid);
    return success;
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
    NMDeviceModem *       self = NM_DEVICE_MODEM(device);
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
    }
}

static gboolean
is_available(NMDevice *device, NMDeviceCheckDevAvailableFlags flags)
{
    NMDeviceModem *       self = NM_DEVICE_MODEM(device);
    NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE(self);
    NMModemState          modem_state;

    if (!priv->rf_enabled)
        return FALSE;

    g_assert(priv->modem);
    modem_state = nm_modem_get_state(priv->modem);
    if (modem_state <= NM_MODEM_STATE_INITIALIZING)
        return FALSE;

    return TRUE;
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
    g_signal_connect(modem, NM_MODEM_IP4_CONFIG_RESULT, G_CALLBACK(modem_ip4_config_result), self);
    g_signal_connect(modem, NM_MODEM_IP6_CONFIG_RESULT, G_CALLBACK(modem_ip6_config_result), self);
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
                        NM_DEVICE_RFKILL_TYPE,
                        RFKILL_TYPE_WWAN,
                        NM_DEVICE_MODEM_MODEM,
                        modem,
                        NM_DEVICE_MODEM_CAPABILITIES,
                        caps,
                        NM_DEVICE_MODEM_CURRENT_CAPABILITIES,
                        current_caps,
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
        .signals    = NM_DEFINE_GDBUS_SIGNAL_INFOS(&nm_signal_info_property_changed_legacy, ),
        .properties = NM_DEFINE_GDBUS_PROPERTY_INFOS(
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L("ModemCapabilities",
                                                             "u",
                                                             NM_DEVICE_MODEM_CAPABILITIES),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L("CurrentCapabilities",
                                                             "u",
                                                             NM_DEVICE_MODEM_CURRENT_CAPABILITIES),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("DeviceId",
                                                           "s",
                                                           NM_DEVICE_MODEM_DEVICE_ID),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("OperatorCode",
                                                           "s",
                                                           NM_DEVICE_MODEM_OPERATOR_CODE),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Apn", "s", NM_DEVICE_MODEM_APN), ), ),
    .legacy_property_changed = TRUE,
};

static void
nm_device_modem_class_init(NMDeviceModemClass *klass)
{
    GObjectClass *     object_class      = G_OBJECT_CLASS(klass);
    NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS(klass);
    NMDeviceClass *    device_class      = NM_DEVICE_CLASS(klass);

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
    device_class->act_stage3_ip_config_start  = act_stage3_ip_config_start;
    device_class->ip4_config_pre_commit       = ip4_config_pre_commit;
    device_class->get_enabled                 = get_enabled;
    device_class->set_enabled                 = set_enabled;
    device_class->owns_iface                  = owns_iface;
    device_class->is_available                = is_available;
    device_class->get_ip_iface_identifier     = get_ip_iface_identifier;
    device_class->get_configured_mtu          = nm_modem_get_configured_mtu;
    device_class->get_dhcp_timeout_for_device = get_dhcp_timeout_for_device;

    device_class->state_changed = device_state_changed;

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
