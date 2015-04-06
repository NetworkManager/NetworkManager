/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2009 - 2011 Red Hat, Inc.
 */

#include "config.h"

#include <string.h>

#include "nm-glib.h"
#include "nm-device-modem.h"
#include "nm-modem.h"
#include "nm-device-private.h"
#include "nm-rfkill-manager.h"
#include "nm-logging.h"
#include "nm-dbus-manager.h"
#include "nm-settings-connection.h"
#include "nm-modem-broadband.h"
#include "NetworkManagerUtils.h"
#include "nm-core-internal.h"

#include "nm-device-logging.h"
_LOG_DECLARE_SELF(NMDeviceModem);

G_DEFINE_TYPE (NMDeviceModem, nm_device_modem, NM_TYPE_DEVICE)

#define NM_DEVICE_MODEM_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_MODEM, NMDeviceModemPrivate))

#include "nm-device-modem-glue.h"

typedef struct {
	NMModem *modem;
	NMDeviceModemCapabilities caps;
	NMDeviceModemCapabilities current_caps;
	gboolean rf_enabled;
} NMDeviceModemPrivate;

enum {
	PROP_0,
	PROP_MODEM,
	PROP_CAPABILITIES,
	PROP_CURRENT_CAPABILITIES,
};

/*****************************************************************************/

static void
ppp_failed (NMModem *modem, NMDeviceStateReason reason, gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);

	switch (nm_device_get_state (device)) {
	case NM_DEVICE_STATE_PREPARE:
	case NM_DEVICE_STATE_CONFIG:
	case NM_DEVICE_STATE_NEED_AUTH:
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, reason);
		break;
	case NM_DEVICE_STATE_IP_CONFIG:
	case NM_DEVICE_STATE_IP_CHECK:
	case NM_DEVICE_STATE_SECONDARIES:
	case NM_DEVICE_STATE_ACTIVATED:
		if (nm_device_activate_ip4_state_in_conf (device))
			nm_device_activate_schedule_ip4_config_timeout (device);
		else {
			nm_device_state_changed (device,
			                         NM_DEVICE_STATE_FAILED,
			                         NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
		}
		break;
	default:
		break;
	}
}

static void
modem_prepare_result (NMModem *modem,
                      gboolean success,
                      NMDeviceStateReason reason,
                      gpointer user_data)
{
	NMDeviceModem *self = NM_DEVICE_MODEM (user_data);
	NMDevice *device = NM_DEVICE (self);
	NMDeviceState state;

	state = nm_device_get_state (device);
	g_return_if_fail (state == NM_DEVICE_STATE_PREPARE);

	if (success)
		nm_device_activate_schedule_stage2_device_config (device);
	else {
		if (reason == NM_DEVICE_STATE_REASON_SIM_PIN_INCORRECT) {
			/* If the connect failed because the SIM PIN was wrong don't allow
			 * the device to be auto-activated anymore, which would risk locking
			 * the SIM if the incorrect PIN continues to be used.
			 */
			g_object_set (G_OBJECT (device), NM_DEVICE_AUTOCONNECT, FALSE, NULL);
			_LOGI (LOGD_MB, "disabling autoconnect due to failed SIM PIN");
		}

		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, reason);
	}
}

static void
modem_auth_requested (NMModem *modem, gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);

	/* Auth requests (PIN, PAP/CHAP passwords, etc) only get handled
	 * during activation.
	 */
	if (!nm_device_is_activating (device))
		return;

	nm_device_state_changed (device,
	                         NM_DEVICE_STATE_NEED_AUTH,
	                         NM_DEVICE_STATE_REASON_NONE);
}

static void
modem_auth_result (NMModem *modem, GError *error, gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);

	if (error) {
		nm_device_state_changed (device,
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_NO_SECRETS);
	} else {
		/* Otherwise, on success for modem secrets we need to schedule stage1 again */
		g_return_if_fail (nm_device_get_state (device) == NM_DEVICE_STATE_NEED_AUTH);
		nm_device_activate_schedule_stage1_device_prepare (device);
	}
}

static void
modem_ip4_config_result (NMModem *modem,
                         NMIP4Config *config,
                         GError *error,
                         gpointer user_data)
{
	NMDeviceModem *self = NM_DEVICE_MODEM (user_data);
	NMDevice *device = NM_DEVICE (self);

	g_return_if_fail (nm_device_activate_ip4_state_in_conf (device) == TRUE);

	if (error) {
		_LOGW (LOGD_MB | LOGD_IP4, "retrieving IPv4 configuration failed: (%d) %s",
		       error->code, error->message ? error->message : "(unknown)");

		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
	} else {
		nm_device_set_wwan_ip4_config (device, config);
		nm_device_activate_schedule_ip4_config_result (device, NULL);
	}
}

static void
modem_ip6_config_result (NMModem *modem,
                         NMIP6Config *config,
                         gboolean do_slaac,
                         GError *error,
                         gpointer user_data)
{
	NMDeviceModem *self = NM_DEVICE_MODEM (user_data);
	NMDevice *device = NM_DEVICE (self);
	NMActStageReturn ret;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;
	NMIP6Config *ignored = NULL;
	gboolean got_config = !!config;

	g_return_if_fail (nm_device_activate_ip6_state_in_conf (device) == TRUE);

	if (error) {
		_LOGW (LOGD_MB | LOGD_IP6, "retrieving IPv6 configuration failed: (%d) %s",
		       error->code, error->message ? error->message : "(unknown)");

		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
		return;
	}

	/* Re-enable IPv6 on the interface */
	nm_device_ipv6_sysctl_set (device, "disable_ipv6", "0");

	if (config)
		nm_device_set_wwan_ip6_config (device, config);

	if (do_slaac == FALSE) {
		if (got_config)
			nm_device_activate_schedule_ip6_config_result (device);
		else {
			_LOGW (LOGD_MB | LOGD_IP6, "retrieving IPv6 configuration failed: SLAAC not requested and no addresses");
			nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
		}
		return;
	}

	/* Start SLAAC now that we have a link-local address from the modem */
	ret = NM_DEVICE_CLASS (nm_device_modem_parent_class)->act_stage3_ip6_config_start (device, &ignored, &reason);
	g_assert (ignored == NULL);
	switch (ret) {
	case NM_ACT_STAGE_RETURN_FAILURE:
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, reason);
		break;
	case NM_ACT_STAGE_RETURN_STOP:
		/* all done */
		nm_device_activate_schedule_ip6_config_result (device);
		break;
	case NM_ACT_STAGE_RETURN_POSTPONE:
		/* let SLAAC run */
		break;
	default:
		/* Should never get here since we've assured that the IPv6 method
		 * will either be "auto" or "ignored" when starting IPv6 configuration.
		 */
		g_assert_not_reached ();
	}
}

static void
data_port_changed_cb (NMModem *modem, GParamSpec *pspec, gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	const char *old = nm_device_get_ip_iface (self);
	const char *new = nm_modem_get_data_port (modem);
	gboolean changed = FALSE;

	if (new && g_strcmp0 (new, old))
		changed = TRUE;

	/* We set the IP iface in the device as soon as we know it, so that we
	 * properly ifup it if needed */
	nm_device_set_ip_iface (self, new);

	/* Disable IPv6 immediately on the interface since NM handles IPv6
	 * internally, and leaving it enabled could allow the kernel's IPv6
	 * RA handling code to run before NM is ready.
	 */
	if (changed)
		nm_device_ipv6_sysctl_set (self, "disable_ipv6", "1");
}

static void
modem_state_cb (NMModem *modem,
                NMModemState new_state,
                NMModemState old_state,
                gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);
	NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE (device);
	NMDeviceState dev_state = nm_device_get_state (device);

	if (new_state <= NM_MODEM_STATE_DISABLING &&
	    old_state > NM_MODEM_STATE_DISABLING &&
	    priv->rf_enabled) {
		/* Called when the ModemManager modem enabled state is changed externally
		 * to NetworkManager (eg something using MM's D-Bus API directly).
		 */
		if (nm_device_is_activating (device) || dev_state == NM_DEVICE_STATE_ACTIVATED) {
			/* user-initiated action, hence DISCONNECTED not FAILED */
			nm_device_state_changed (device,
			                         NM_DEVICE_STATE_DISCONNECTED,
			                         NM_DEVICE_STATE_REASON_USER_REQUESTED);
			return;
		}
	}

	if (new_state < NM_MODEM_STATE_CONNECTING &&
	    old_state >= NM_MODEM_STATE_CONNECTING &&
	    dev_state >= NM_DEVICE_STATE_NEED_AUTH &&
	    dev_state <= NM_DEVICE_STATE_ACTIVATED) {
		/* Fail the device if the modem disconnects unexpectedly while the
		 * device is activating/activated. */
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_MODEM_NO_CARRIER);
		return;
	}

	if (new_state > NM_MODEM_STATE_LOCKED && old_state == NM_MODEM_STATE_LOCKED) {
		/* If the modem is now unlocked, enable/disable it according to the
		 * device's enabled/disabled state.
		 */
		nm_modem_set_mm_enabled (priv->modem, priv->rf_enabled);

		/* Now allow connections without a PIN to be available */
		nm_device_recheck_available_connections (device);
	}

	nm_device_queue_recheck_available (device,
	                                   NM_DEVICE_STATE_REASON_MODEM_AVAILABLE,
	                                   NM_DEVICE_STATE_REASON_MODEM_FAILED);
}

static void
modem_removed_cb (NMModem *modem, gpointer user_data)
{
	g_signal_emit_by_name (NM_DEVICE (user_data), NM_DEVICE_REMOVED);
}

/*****************************************************************************/

static gboolean
owns_iface (NMDevice *device, const char *iface)
{
	NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE (device);

	g_assert (priv->modem);
	return nm_modem_owns_port (priv->modem, iface);
}

/*****************************************************************************/

static void
device_state_changed (NMDevice *device,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason)
{
	NMDeviceModem *self = NM_DEVICE_MODEM (device);
	NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE (device);
	NMConnection *connection = nm_device_get_connection (device);

	g_assert (priv->modem);

	if (new_state == NM_DEVICE_STATE_UNAVAILABLE &&
	    old_state < NM_DEVICE_STATE_UNAVAILABLE) {
		/* Log initial modem state */
		_LOGI (LOGD_MB, "modem state '%s'",
		       nm_modem_state_to_string (nm_modem_get_state (priv->modem)));
	}

	nm_modem_device_state_changed (priv->modem, new_state, old_state, reason);

	switch (reason) {
	case NM_DEVICE_STATE_REASON_GSM_REGISTRATION_DENIED:
	case NM_DEVICE_STATE_REASON_GSM_REGISTRATION_NOT_SEARCHING:
	case NM_DEVICE_STATE_REASON_GSM_SIM_NOT_INSERTED:
	case NM_DEVICE_STATE_REASON_GSM_SIM_PIN_REQUIRED:
	case NM_DEVICE_STATE_REASON_GSM_SIM_PUK_REQUIRED:
	case NM_DEVICE_STATE_REASON_GSM_SIM_WRONG:
	case NM_DEVICE_STATE_REASON_SIM_PIN_INCORRECT:
	case NM_DEVICE_STATE_REASON_MODEM_INIT_FAILED:
	case NM_DEVICE_STATE_REASON_GSM_APN_FAILED:
		/* Block autoconnect of the just-failed connection for situations
		 * where a retry attempt would just fail again.
		 */
		if (connection)
			nm_settings_connection_set_autoconnect_blocked_reason (NM_SETTINGS_CONNECTION (connection), reason);
		break;
	default:
		break;
	}
}

static NMDeviceCapabilities
get_generic_capabilities (NMDevice *device)
{
	return NM_DEVICE_CAP_IS_NON_KERNEL;
}

static const char *
get_type_description (NMDevice *device)
{
	NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE (device);

	if (NM_FLAGS_HAS (priv->current_caps, NM_DEVICE_MODEM_CAPABILITY_GSM_UMTS))
		return "gsm";
	if (NM_FLAGS_HAS (priv->current_caps, NM_DEVICE_MODEM_CAPABILITY_CDMA_EVDO))
		return "cdma";
	return NM_DEVICE_CLASS (nm_device_modem_parent_class)->get_type_description (device);
}

static gboolean
check_connection_compatible (NMDevice *device, NMConnection *connection)
{
	if (!NM_DEVICE_CLASS (nm_device_modem_parent_class)->check_connection_compatible (device, connection))
		return FALSE;

	return nm_modem_check_connection_compatible (NM_DEVICE_MODEM_GET_PRIVATE (device)->modem, connection);
}

static gboolean
check_connection_available (NMDevice *device,
                            NMConnection *connection,
                            NMDeviceCheckConAvailableFlags flags,
                            const char *specific_object)
{
	NMDeviceModem *self = NM_DEVICE_MODEM (device);
	NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE (self);
	NMModemState state;

	if (!priv->rf_enabled || !priv->modem)
		return FALSE;

	state = nm_modem_get_state (priv->modem);
	if (state <= NM_MODEM_STATE_INITIALIZING)
		return FALSE;

	if (state == NM_MODEM_STATE_LOCKED) {
		NMSettingGsm *s_gsm = nm_connection_get_setting_gsm (connection);

		/* Can't use a connection without a PIN if the modem is locked */
		if (!s_gsm || !nm_setting_gsm_get_pin (s_gsm))
			return FALSE;
	}

	return TRUE;
}

static gboolean
complete_connection (NMDevice *device,
                     NMConnection *connection,
                     const char *specific_object,
                     const GSList *existing_connections,
                     GError **error)
{
	NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE (device);

	return nm_modem_complete_connection (priv->modem, connection, existing_connections, error);
}

static void
deactivate (NMDevice *device)
{
	nm_modem_deactivate (NM_DEVICE_MODEM_GET_PRIVATE (device)->modem, device);
}

/***********************************************************/

static gboolean
deactivate_async_finish (NMDevice *self,
                         GAsyncResult *res,
                         GError **error)
{
	return !g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (res), error);
}

static void
modem_deactivate_async_ready (NMModem *modem,
                              GAsyncResult *res,
                              GSimpleAsyncResult *simple)
{
	GError *error = NULL;

	if (!nm_modem_deactivate_async_finish (modem, res, &error))
		g_simple_async_result_take_error (simple, error);
	g_simple_async_result_complete (simple);
	g_object_unref (simple);
}

static void
deactivate_async (NMDevice *self,
                  GCancellable *cancellable,
                  GAsyncReadyCallback callback,
                  gpointer user_data)
{
	GSimpleAsyncResult *simple;

	simple = g_simple_async_result_new (G_OBJECT (self),
	                                    callback,
	                                    user_data,
	                                    deactivate_async);
	nm_modem_deactivate_async (NM_DEVICE_MODEM_GET_PRIVATE (self)->modem,
	                           self,
	                           cancellable,
	                           (GAsyncReadyCallback) modem_deactivate_async_ready,
	                           simple);
}

/***********************************************************/

static NMActStageReturn
act_stage1_prepare (NMDevice *device, NMDeviceStateReason *reason)
{
	NMActStageReturn ret;
	NMActRequest *req;

	ret = NM_DEVICE_CLASS (nm_device_modem_parent_class)->act_stage1_prepare (device, reason);
	if (ret != NM_ACT_STAGE_RETURN_SUCCESS)
		return ret;

	req = nm_device_get_act_request (device);
	g_assert (req);

	return nm_modem_act_stage1_prepare (NM_DEVICE_MODEM_GET_PRIVATE (device)->modem, req, reason);
}

static NMActStageReturn
act_stage2_config (NMDevice *device, NMDeviceStateReason *reason)
{
	NMActRequest *req;

	req = nm_device_get_act_request (device);
	g_assert (req);

	return nm_modem_act_stage2_config (NM_DEVICE_MODEM_GET_PRIVATE (device)->modem, req, reason);
}

static NMActStageReturn
act_stage3_ip4_config_start (NMDevice *device,
                             NMIP4Config **out_config,
                             NMDeviceStateReason *reason)
{
	return nm_modem_stage3_ip4_config_start (NM_DEVICE_MODEM_GET_PRIVATE (device)->modem,
	                                         device,
	                                         NM_DEVICE_CLASS (nm_device_modem_parent_class),
	                                         reason);
}

static void
ip4_config_pre_commit (NMDevice *device, NMIP4Config *config)
{
	nm_modem_ip4_pre_commit (NM_DEVICE_MODEM_GET_PRIVATE (device)->modem, device, config);
}

static NMActStageReturn
act_stage3_ip6_config_start (NMDevice *device,
                             NMIP6Config **out_config,
                             NMDeviceStateReason *reason)
{
	return nm_modem_stage3_ip6_config_start (NM_DEVICE_MODEM_GET_PRIVATE (device)->modem,
	                                         nm_device_get_act_request (device),
	                                         reason);
}

static gboolean
get_ip_iface_identifier (NMDevice *device, NMUtilsIPv6IfaceId *out_iid)
{
	NMDeviceModem *self = NM_DEVICE_MODEM (device);
	NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE (self);
	gboolean success;

	g_return_val_if_fail (priv->modem, FALSE);
	success = nm_modem_get_iid (priv->modem, out_iid);
	if (!success)
		success = NM_DEVICE_CLASS (nm_device_modem_parent_class)->get_ip_iface_identifier (device, out_iid);
	return success;
}

/*****************************************************************************/

static gboolean
get_enabled (NMDevice *device)
{
	NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE (device);
	NMModemState modem_state = nm_modem_get_state (priv->modem);

	return priv->rf_enabled && (modem_state >= NM_MODEM_STATE_LOCKED);
}

static void
set_enabled (NMDevice *device, gboolean enabled)
{
	NMDeviceModem *self = NM_DEVICE_MODEM (device);
	NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE (self);

	/* Called only by the Manager in response to rfkill switch changes or
	 * global user WWAN enable/disable preference changes.
	 */
	priv->rf_enabled = enabled;

	if (priv->modem) {
		/* Sync the ModemManager modem enabled/disabled with rfkill/user preference */
		nm_modem_set_mm_enabled (priv->modem, enabled);
	}

	if (enabled == FALSE) {
		nm_device_state_changed (device,
		                         NM_DEVICE_STATE_UNAVAILABLE,
		                         NM_DEVICE_STATE_REASON_NONE);
	}
}

static gboolean
is_available (NMDevice *device, NMDeviceCheckDevAvailableFlags flags)
{
	NMDeviceModem *self = NM_DEVICE_MODEM (device);
	NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE (self);
	NMModemState modem_state;

	if (!priv->rf_enabled)
		return FALSE;

	g_assert (priv->modem);
	modem_state = nm_modem_get_state (priv->modem);
	if (modem_state <= NM_MODEM_STATE_INITIALIZING)
		return FALSE;

	return TRUE;
}

/*****************************************************************************/

NMDevice *
nm_device_modem_new (NMModem *modem)
{
	NMDeviceModemCapabilities caps = NM_DEVICE_MODEM_CAPABILITY_NONE;
	NMDeviceModemCapabilities current_caps = NM_DEVICE_MODEM_CAPABILITY_NONE;
	NMDevice *device;
	const char *data_port;

	g_return_val_if_fail (NM_IS_MODEM (modem), NULL);

	/* Load capabilities */
	nm_modem_get_capabilities (modem, &caps, &current_caps);

	device = (NMDevice *) g_object_new (NM_TYPE_DEVICE_MODEM,
	                                    NM_DEVICE_UDI, nm_modem_get_path (modem),
	                                    NM_DEVICE_IFACE, nm_modem_get_uid (modem),
	                                    NM_DEVICE_DRIVER, nm_modem_get_driver (modem),
	                                    NM_DEVICE_TYPE_DESC, "Broadband",
	                                    NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_MODEM,
	                                    NM_DEVICE_RFKILL_TYPE, RFKILL_TYPE_WWAN,
	                                    NM_DEVICE_MODEM_MODEM, modem,
	                                    NM_DEVICE_MODEM_CAPABILITIES, caps,
	                                    NM_DEVICE_MODEM_CURRENT_CAPABILITIES, current_caps,
	                                    NULL);

	/* If the data port is known, set it as the IP interface immediately */
	data_port = nm_modem_get_data_port (modem);
	if (data_port) {
		nm_device_set_ip_iface (device, data_port);
		nm_device_ipv6_sysctl_set (device, "disable_ipv6", "1");
	}

	return device;
}

static void
nm_device_modem_init (NMDeviceModem *self)
{
}

static void
constructed (GObject *object)
{
	G_OBJECT_CLASS (nm_device_modem_parent_class)->constructed (object);

	/* DHCP is always done by the modem firmware, not by the network, and
	 * by the time we get around to DHCP the firmware should already know
	 * the IP addressing details.  So the DHCP timeout can be much shorter.
	 */
	nm_device_set_dhcp_timeout (NM_DEVICE (object), 15);
}

static void
set_modem (NMDeviceModem *self, NMModem *modem)
{
	NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE (self);

	g_return_if_fail (modem != NULL);

	priv->modem = g_object_ref (modem);

	g_signal_connect (modem, NM_MODEM_PPP_FAILED, G_CALLBACK (ppp_failed), self);
	g_signal_connect (modem, NM_MODEM_PREPARE_RESULT, G_CALLBACK (modem_prepare_result), self);
	g_signal_connect (modem, NM_MODEM_IP4_CONFIG_RESULT, G_CALLBACK (modem_ip4_config_result), self);
	g_signal_connect (modem, NM_MODEM_IP6_CONFIG_RESULT, G_CALLBACK (modem_ip6_config_result), self);
	g_signal_connect (modem, NM_MODEM_AUTH_REQUESTED, G_CALLBACK (modem_auth_requested), self);
	g_signal_connect (modem, NM_MODEM_AUTH_RESULT, G_CALLBACK (modem_auth_result), self);
	g_signal_connect (modem, NM_MODEM_STATE_CHANGED, G_CALLBACK (modem_state_cb), self);
	g_signal_connect (modem, NM_MODEM_REMOVED, G_CALLBACK (modem_removed_cb), self);

	/* In the old ModemManager the data port is known from the very beginning;
	 * while in the new ModemManager the data port is set afterwards when the bearer gets
	 * created */
	g_signal_connect (modem, "notify::" NM_MODEM_DATA_PORT, G_CALLBACK (data_port_changed_cb), self);
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_MODEM:
		/* construct-only */
		set_modem (NM_DEVICE_MODEM (object), g_value_get_object (value));
		break;
	case PROP_CAPABILITIES:
		priv->caps = g_value_get_uint (value);
		break;
	case PROP_CURRENT_CAPABILITIES:
		priv->current_caps = g_value_get_uint (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_MODEM:
		g_value_set_object (value, priv->modem);
		break;
	case PROP_CAPABILITIES:
		g_value_set_uint (value, priv->caps);
		break;
	case PROP_CURRENT_CAPABILITIES:
		g_value_set_uint (value, priv->current_caps);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
dispose (GObject *object)
{
	NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE (object);

	if (priv->modem)
		g_signal_handlers_disconnect_by_data (priv->modem, NM_DEVICE_MODEM (object));
	g_clear_object (&priv->modem);

	G_OBJECT_CLASS (nm_device_modem_parent_class)->dispose (object);
}

static void
nm_device_modem_class_init (NMDeviceModemClass *mclass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (mclass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (mclass);

	g_type_class_add_private (object_class, sizeof (NMDeviceModemPrivate));

	/* Virtual methods */
	object_class->dispose = dispose;
	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->constructed = constructed;

	device_class->get_generic_capabilities = get_generic_capabilities;
	device_class->get_type_description = get_type_description;
	device_class->check_connection_compatible = check_connection_compatible;
	device_class->check_connection_available = check_connection_available;
	device_class->complete_connection = complete_connection;
	device_class->deactivate_async = deactivate_async;
	device_class->deactivate_async_finish = deactivate_async_finish;
	device_class->deactivate = deactivate;
	device_class->act_stage1_prepare = act_stage1_prepare;
	device_class->act_stage2_config = act_stage2_config;
	device_class->act_stage3_ip4_config_start = act_stage3_ip4_config_start;
	device_class->act_stage3_ip6_config_start = act_stage3_ip6_config_start;
	device_class->ip4_config_pre_commit = ip4_config_pre_commit;
	device_class->get_enabled = get_enabled;
	device_class->set_enabled = set_enabled;
	device_class->owns_iface = owns_iface;
	device_class->is_available = is_available;
	device_class->get_ip_iface_identifier = get_ip_iface_identifier;

	device_class->state_changed = device_state_changed;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_MODEM,
		 g_param_spec_object (NM_DEVICE_MODEM_MODEM, "", "",
		                      NM_TYPE_MODEM,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_CAPABILITIES,
		 g_param_spec_uint (NM_DEVICE_MODEM_CAPABILITIES, "", "",
		                    0, G_MAXUINT32, NM_DEVICE_MODEM_CAPABILITY_NONE,
		                    G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_CURRENT_CAPABILITIES,
		 g_param_spec_uint (NM_DEVICE_MODEM_CURRENT_CAPABILITIES, "", "",
		                    0, G_MAXUINT32, NM_DEVICE_MODEM_CAPABILITY_NONE,
		                    G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                    G_PARAM_STATIC_STRINGS));

	nm_dbus_manager_register_exported_type (nm_dbus_manager_get (),
	                                        G_TYPE_FROM_CLASS (mclass),
	                                        &dbus_glib_nm_device_modem_object_info);
}
