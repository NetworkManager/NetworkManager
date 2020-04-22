// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2009 - 2011 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device-bt.h"

#include <stdio.h>

#include "nm-core-internal.h"
#include "nm-bluez-common.h"
#include "nm-bluez-manager.h"
#include "devices/nm-device-private.h"
#include "ppp/nm-ppp-manager.h"
#include "nm-setting-connection.h"
#include "nm-setting-bluetooth.h"
#include "nm-setting-cdma.h"
#include "nm-setting-gsm.h"
#include "nm-setting-serial.h"
#include "nm-setting-ppp.h"
#include "NetworkManagerUtils.h"
#include "settings/nm-settings-connection.h"
#include "nm-utils.h"
#include "nm-bt-error.h"
#include "nm-ip4-config.h"
#include "platform/nm-platform.h"

#include "devices/wwan/nm-modem-manager.h"
#include "devices/wwan/nm-modem.h"

#include "devices/nm-device-logging.h"
_LOG_DECLARE_SELF(NMDeviceBt);

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMDeviceBt,
	PROP_BT_BDADDR,
	PROP_BT_BZ_MGR,
	PROP_BT_CAPABILITIES,
	PROP_BT_DBUS_PATH,
	PROP_BT_NAME,
);

enum {
	PPP_STATS,
	LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	NMModemManager *modem_manager;

	NMBluezManager *bz_mgr;

	char *dbus_path;

	char *bdaddr;
	char *name;

	char *connect_rfcomm_iface;

	GSList *connect_modem_candidates;

	NMModem *modem;

	GCancellable *connect_bz_cancellable;

	gulong connect_watch_link_id;

	guint connect_watch_link_idle_id;

	guint connect_wait_modem_id;

	NMBluetoothCapabilities capabilities:6;

	NMBluetoothCapabilities connect_bt_type:6;  /* BT type of the current connection */

	NMDeviceStageState stage1_bt_state:3;
	NMDeviceStageState stage1_modem_prepare_state:3;

	bool is_connected:1;

	bool mm_running:1;

} NMDeviceBtPrivate;

struct _NMDeviceBt {
	NMDevice parent;
	NMDeviceBtPrivate _priv;
};

struct _NMDeviceBtClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceBt, nm_device_bt, NM_TYPE_DEVICE)

#define NM_DEVICE_BT_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMDeviceBt, NM_IS_DEVICE_BT, NMDevice)

/*****************************************************************************/

NMBluetoothCapabilities nm_device_bt_get_capabilities (NMDeviceBt *self)
{
	g_return_val_if_fail (NM_IS_DEVICE_BT (self), NM_BT_CAPABILITY_NONE);

	return NM_DEVICE_BT_GET_PRIVATE (self)->capabilities;
}

static NMBluetoothCapabilities
get_connection_bt_type (NMConnection *connection)
{
	NMSettingBluetooth *s_bt;
	const char *bt_type;

	s_bt = nm_connection_get_setting_bluetooth (connection);

	if (s_bt) {
		bt_type = nm_setting_bluetooth_get_connection_type (s_bt);
		if (bt_type) {
			if (nm_streq (bt_type, NM_SETTING_BLUETOOTH_TYPE_DUN))
				return NM_BT_CAPABILITY_DUN;
			else if (nm_streq (bt_type, NM_SETTING_BLUETOOTH_TYPE_PANU))
				return NM_BT_CAPABILITY_NAP;
		}
	}

	return NM_BT_CAPABILITY_NONE;
}

static gboolean
get_connection_bt_type_check (NMDeviceBt *self,
                              NMConnection *connection,
                              NMBluetoothCapabilities *out_bt_type,
                              GError **error)
{
	NMBluetoothCapabilities bt_type;

	bt_type = get_connection_bt_type (connection);

	NM_SET_OUT (out_bt_type, bt_type);

	if (bt_type == NM_BT_CAPABILITY_NONE) {
		nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
		                            "profile is not a PANU/DUN bluetooth type");
		return FALSE;
	}

	if (!NM_FLAGS_ALL (NM_DEVICE_BT_GET_PRIVATE (self)->capabilities, bt_type)) {
		nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
		                            "device does not support bluetooth type");
		return FALSE;
	}

	return TRUE;
}

static NMDeviceCapabilities
get_generic_capabilities (NMDevice *device)
{
	return NM_DEVICE_CAP_IS_NON_KERNEL;
}

static gboolean
can_auto_connect (NMDevice *device,
                  NMSettingsConnection *sett_conn,
                  char **specific_object)
{
	NMDeviceBt *self = NM_DEVICE_BT (device);
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (self);
	NMBluetoothCapabilities bt_type;

	nm_assert (!specific_object || !*specific_object);

	if (!NM_DEVICE_CLASS (nm_device_bt_parent_class)->can_auto_connect (device, sett_conn, NULL))
		return FALSE;

	if (!get_connection_bt_type_check (self,
	                                   nm_settings_connection_get_connection (sett_conn),
	                                   &bt_type,
	                                   NULL))
		return FALSE;

	/* Can't auto-activate a DUN connection without ModemManager */
	if (   bt_type == NM_BT_CAPABILITY_DUN
	    && priv->mm_running == FALSE)
		return FALSE;

	return TRUE;
}

static gboolean
check_connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	NMDeviceBt *self = NM_DEVICE_BT (device);
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (self);
	NMSettingBluetooth *s_bt;
	const char *bdaddr;

	if (!NM_DEVICE_CLASS (nm_device_bt_parent_class)->check_connection_compatible (device, connection, error))
		return FALSE;

	if (!get_connection_bt_type_check (self, connection, NULL, error))
		return FALSE;

	s_bt = nm_connection_get_setting_bluetooth (connection);

	bdaddr = nm_setting_bluetooth_get_bdaddr (s_bt);
	if (!bdaddr) {
		nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
		                            "profile lacks bdaddr setting");
		return FALSE;
	}
	if (!nm_utils_hwaddr_matches (priv->bdaddr, -1, bdaddr, -1)) {
		nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
		                            "devices bdaddr setting mismatches");
		return FALSE;
	}

	return TRUE;
}

static gboolean
check_connection_available (NMDevice *device,
                            NMConnection *connection,
                            NMDeviceCheckConAvailableFlags flags,
                            const char *specific_object,
                            GError **error)
{
	NMDeviceBt *self = NM_DEVICE_BT (device);
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (self);
	NMBluetoothCapabilities bt_type;

	if (!get_connection_bt_type_check (self, connection, &bt_type, error))
		return FALSE;

	if (   bt_type == NM_BT_CAPABILITY_DUN
	    && !priv->mm_running) {
		nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
		                            "ModemManager missing for DUN profile");
		return FALSE;
	}

	return TRUE;
}

static gboolean
complete_connection (NMDevice *device,
                     NMConnection *connection,
                     const char *specific_object,
                     NMConnection *const*existing_connections,
                     GError **error)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (device);
	NMSettingBluetooth *s_bt;
	const char *setting_bdaddr;
	const char *ctype;
	gboolean is_dun = FALSE;
	gboolean is_pan = FALSE;
	NMSettingGsm *s_gsm;
	NMSettingCdma *s_cdma;
	NMSettingSerial *s_serial;
	NMSettingPpp *s_ppp;
	const char *fallback_prefix = NULL, *preferred = NULL;

	s_gsm = nm_connection_get_setting_gsm (connection);
	s_cdma = nm_connection_get_setting_cdma (connection);
	s_serial = nm_connection_get_setting_serial (connection);
	s_ppp = nm_connection_get_setting_ppp (connection);

	s_bt = nm_connection_get_setting_bluetooth (connection);
	if (!s_bt) {
		s_bt = (NMSettingBluetooth *) nm_setting_bluetooth_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_bt));
	}

	ctype = nm_setting_bluetooth_get_connection_type (s_bt);
	if (ctype) {
		if (!strcmp (ctype, NM_SETTING_BLUETOOTH_TYPE_DUN))
			is_dun = TRUE;
		else if (!strcmp (ctype, NM_SETTING_BLUETOOTH_TYPE_PANU))
			is_pan = TRUE;
	} else {
		if (s_gsm || s_cdma)
			is_dun = TRUE;
		else if (priv->capabilities & NM_BT_CAPABILITY_NAP)
			is_pan = TRUE;
	}

	if (is_pan) {
		/* Make sure the device supports PAN */
		if (!(priv->capabilities & NM_BT_CAPABILITY_NAP)) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("PAN requested, but Bluetooth device does not support NAP"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_BLUETOOTH_SETTING_NAME, NM_SETTING_BLUETOOTH_TYPE);
			return FALSE;
		}

		/* PAN can't use any DUN-related settings */
		if (   s_gsm
		    || s_cdma
		    || s_serial
		    || s_ppp) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_SETTING,
			                     _("PAN connections cannot specify GSM, CDMA, or serial settings"));
			g_prefix_error (error, "%s: ",
			                s_gsm ? NM_SETTING_GSM_SETTING_NAME :
			                s_cdma ? NM_SETTING_CDMA_SETTING_NAME :
			                s_serial ? NM_SETTING_SERIAL_SETTING_NAME :
			                NM_SETTING_PPP_SETTING_NAME);
			return FALSE;
		}

		g_object_set (G_OBJECT (s_bt),
		              NM_SETTING_BLUETOOTH_TYPE, NM_SETTING_BLUETOOTH_TYPE_PANU,
		              NULL);

		fallback_prefix = _("PAN connection");
	} else if (is_dun) {
		/* Make sure the device supports PAN */
		if (!(priv->capabilities & NM_BT_CAPABILITY_DUN)) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("DUN requested, but Bluetooth device does not support DUN"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_BLUETOOTH_SETTING_NAME, NM_SETTING_BLUETOOTH_TYPE);
			return FALSE;
		}

		/* Need at least a GSM or a CDMA setting */
		if (   !s_gsm
		    && !s_cdma) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_SETTING,
			                     _("DUN connection must include a GSM or CDMA setting"));
			g_prefix_error (error, "%s: ", NM_SETTING_BLUETOOTH_SETTING_NAME);
			return FALSE;
		}

		g_object_set (G_OBJECT (s_bt),
		              NM_SETTING_BLUETOOTH_TYPE, NM_SETTING_BLUETOOTH_TYPE_DUN,
		              NULL);

		if (s_gsm) {
			fallback_prefix = _("GSM connection");
		} else {
			fallback_prefix = _("CDMA connection");
			if (!nm_setting_cdma_get_number (s_cdma))
				g_object_set (G_OBJECT (s_cdma), NM_SETTING_CDMA_NUMBER, "#777", NULL);
		}
	} else {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("Unknown/unhandled Bluetooth connection type"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_BLUETOOTH_SETTING_NAME, NM_SETTING_BLUETOOTH_TYPE);
		return FALSE;
	}

	nm_utils_complete_generic (nm_device_get_platform (device),
	                           connection,
	                           NM_SETTING_BLUETOOTH_SETTING_NAME,
	                           existing_connections,
	                           preferred,
	                           fallback_prefix,
	                           NULL,
	                           NULL,
	                           is_dun ? FALSE : TRUE); /* No IPv6 yet for DUN */

	setting_bdaddr = nm_setting_bluetooth_get_bdaddr (s_bt);
	if (setting_bdaddr) {
		/* Make sure the setting BT Address (if any) matches the device's */
		if (!nm_utils_hwaddr_matches (setting_bdaddr, -1, priv->bdaddr, -1)) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("connection does not match device"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_BLUETOOTH_SETTING_NAME, NM_SETTING_BLUETOOTH_BDADDR);
			return FALSE;
		}
	} else {
		/* Lock the connection to this device by default */
		if (!nm_utils_hwaddr_matches (priv->bdaddr, -1, NULL, ETH_ALEN))
			g_object_set (G_OBJECT (s_bt), NM_SETTING_BLUETOOTH_BDADDR, priv->bdaddr, NULL);
	}

	return TRUE;
}

/*****************************************************************************/
/* IP method PPP */

static void
ppp_stats (NMModem *modem,
           guint i_in_bytes,
           guint i_out_bytes,
           gpointer user_data)
{
	guint32 in_bytes = i_in_bytes;
	guint32 out_bytes = i_out_bytes;

	g_signal_emit (NM_DEVICE_BT (user_data), signals[PPP_STATS], 0, (guint) in_bytes, (guint) out_bytes);
}

static void
ppp_failed (NMModem *modem,
            guint i_reason,
            gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);
	NMDeviceBt *self = NM_DEVICE_BT (user_data);
	NMDeviceStateReason reason = i_reason;

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
			nm_device_activate_schedule_ip_config_timeout (device, AF_INET);
		else if (nm_device_activate_ip6_state_in_conf (device))
			nm_device_activate_schedule_ip_config_timeout (device, AF_INET6);
		else if (nm_device_activate_ip4_state_done (device)) {
			nm_device_ip_method_failed (device,
			                            AF_INET,
			                            NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
		} else if (nm_device_activate_ip6_state_done (device)) {
			nm_device_ip_method_failed (device,
			                            AF_INET6,
			                            NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
		} else {
			_LOGW (LOGD_MB, "PPP failure in unexpected state %u", (guint) nm_device_get_state (device));
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
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (device);

	g_return_if_fail (nm_device_get_state (device) == NM_DEVICE_STATE_NEED_AUTH);

	if (error) {
		nm_device_state_changed (device,
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_NO_SECRETS);
		return;
	}

	priv->stage1_modem_prepare_state = NM_DEVICE_STAGE_STATE_INIT;
	nm_device_activate_schedule_stage1_device_prepare (device);
}

static void
modem_prepare_result (NMModem *modem,
                      gboolean success,
                      guint i_reason,
                      gpointer user_data)
{
	NMDeviceBt *self = user_data;
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (self);
	NMDeviceStateReason reason = i_reason;
	NMDeviceState state;

	state = nm_device_get_state (NM_DEVICE (self));

	g_return_if_fail (NM_IN_SET (state, NM_DEVICE_STATE_PREPARE,
	                                    NM_DEVICE_STATE_NEED_AUTH));

	nm_assert (priv->stage1_modem_prepare_state == NM_DEVICE_STAGE_STATE_PENDING);

	if (!success) {
		if (nm_device_state_reason_check (reason) == NM_DEVICE_STATE_REASON_SIM_PIN_INCORRECT) {
			/* If the connect failed because the SIM PIN was wrong don't allow
			 * the device to be auto-activated anymore, which would risk locking
			 * the SIM if the incorrect PIN continues to be used.
			 */
			nm_device_autoconnect_blocked_set (NM_DEVICE (self), NM_DEVICE_AUTOCONNECT_BLOCKED_WRONG_PIN);
		}

		nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_FAILED, reason);
		return;
	}

	priv->stage1_modem_prepare_state = NM_DEVICE_STAGE_STATE_COMPLETED;
	nm_device_activate_schedule_stage1_device_prepare (NM_DEVICE (self));
}

static void
device_state_changed (NMDevice *device,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (device);

	if (priv->modem)
		nm_modem_device_state_changed (priv->modem, new_state, old_state);

	/* Need to recheck available connections whenever MM appears or disappears,
	 * since the device could be both DUN and NAP capable and thus may not
	 * change state (which rechecks available connections) when MM comes and goes.
	 */
	if (   priv->mm_running
	    && NM_FLAGS_HAS (priv->capabilities, NM_BT_CAPABILITY_DUN))
	    nm_device_recheck_available_connections (device);
}

static void
modem_ip4_config_result (NMModem *modem,
                         NMIP4Config *config,
                         GError *error,
                         gpointer user_data)
{
	NMDeviceBt *self = NM_DEVICE_BT (user_data);
	NMDevice *device = NM_DEVICE (self);

	g_return_if_fail (nm_device_activate_ip4_state_in_conf (device) == TRUE);

	if (error) {
		_LOGW (LOGD_MB | LOGD_IP4 | LOGD_BT,
		       "retrieving IP4 configuration failed: %s",
		       error->message);
		nm_device_ip_method_failed (device,
		                            AF_INET,
		                            NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
		return;
	}

	nm_device_activate_schedule_ip_config_result (device, AF_INET, NM_IP_CONFIG_CAST (config));
}

static void
ip_ifindex_changed_cb (NMModem *modem, GParamSpec *pspec, gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);

	if (!nm_device_is_activating (device))
		return;

	if (!nm_device_set_ip_ifindex (device,
	                               nm_modem_get_ip_ifindex (modem))) {
		nm_device_state_changed (device,
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
	}
}

/*****************************************************************************/

static void
modem_cleanup (NMDeviceBt *self)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (self);

	if (priv->modem) {
		g_signal_handlers_disconnect_matched (priv->modem, G_SIGNAL_MATCH_DATA, 0, 0, NULL, NULL, self);
		nm_clear_pointer (&priv->modem, nm_modem_unclaim);
	}
}

static void
modem_state_cb (NMModem *modem,
                int new_state_i,
                int old_state_i,
                gpointer user_data)
{
	NMModemState new_state = new_state_i;
	NMModemState old_state = old_state_i;
	NMDevice *device = NM_DEVICE (user_data);
	NMDeviceState dev_state = nm_device_get_state (device);

	if (   new_state <= NM_MODEM_STATE_DISABLING
	    && old_state > NM_MODEM_STATE_DISABLING) {
		/* Will be called whenever something external to NM disables the
		 * modem directly through ModemManager.
		 */
		if (   nm_device_is_activating (device)
		    || dev_state == NM_DEVICE_STATE_ACTIVATED) {
			nm_device_state_changed (device,
			                         NM_DEVICE_STATE_DISCONNECTED,
			                         NM_DEVICE_STATE_REASON_USER_REQUESTED);
			return;
		}
	}

	if (   new_state < NM_MODEM_STATE_CONNECTING
	    && old_state >= NM_MODEM_STATE_CONNECTING
	    && dev_state >= NM_DEVICE_STATE_NEED_AUTH
	    && dev_state <= NM_DEVICE_STATE_ACTIVATED) {
		/* Fail the device if the modem disconnects unexpectedly while the
		 * device is activating/activated. */
		nm_device_state_changed (device,
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_MODEM_NO_CARRIER);
		return;
	}
}

static void
modem_removed_cb (NMModem *modem, gpointer user_data)
{
	NMDeviceBt *self = NM_DEVICE_BT (user_data);
	NMDeviceState state;

	state = nm_device_get_state (NM_DEVICE (self));
	if (   nm_device_is_activating (NM_DEVICE (self))
	    || state == NM_DEVICE_STATE_ACTIVATED) {
		nm_device_state_changed (NM_DEVICE (self),
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_BT_FAILED);
		return;
	}

	modem_cleanup (self);
}

static gboolean
modem_try_claim (NMDeviceBt *self,
                 NMModem *modem)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (self);
	gs_free char *rfcomm_base_name = NULL;
	NMDeviceState state;

	if (priv->modem) {
		if (priv->modem == modem)
			return TRUE;
		return FALSE;
	}

	if (nm_modem_is_claimed (modem))
		return FALSE;

	if (!priv->connect_rfcomm_iface)
		return FALSE;

	rfcomm_base_name = g_path_get_basename (priv->connect_rfcomm_iface);
	if (!nm_streq0 (rfcomm_base_name, nm_modem_get_control_port (modem)))
		return FALSE;

	/* Can only accept the modem in stage1, but since the interface matched
	 * what we were expecting, don't let anything else claim the modem either.
	 */
	state = nm_device_get_state (NM_DEVICE (self));
	if (state != NM_DEVICE_STATE_PREPARE) {
		_LOGD (LOGD_BT | LOGD_MB,
		       "modem found but device not in correct state (%d)",
		       nm_device_get_state (NM_DEVICE (self)));
		return FALSE;
	}

	priv->modem = nm_modem_claim (modem);
	priv->stage1_modem_prepare_state = NM_DEVICE_STAGE_STATE_INIT;

	g_signal_connect (modem, NM_MODEM_PPP_STATS, G_CALLBACK (ppp_stats), self);
	g_signal_connect (modem, NM_MODEM_PPP_FAILED, G_CALLBACK (ppp_failed), self);
	g_signal_connect (modem, NM_MODEM_PREPARE_RESULT, G_CALLBACK (modem_prepare_result), self);
	g_signal_connect (modem, NM_MODEM_IP4_CONFIG_RESULT, G_CALLBACK (modem_ip4_config_result), self);
	g_signal_connect (modem, NM_MODEM_AUTH_REQUESTED, G_CALLBACK (modem_auth_requested), self);
	g_signal_connect (modem, NM_MODEM_AUTH_RESULT, G_CALLBACK (modem_auth_result), self);
	g_signal_connect (modem, NM_MODEM_STATE_CHANGED, G_CALLBACK (modem_state_cb), self);
	g_signal_connect (modem, NM_MODEM_REMOVED, G_CALLBACK (modem_removed_cb), self);
	g_signal_connect (modem, "notify::" NM_MODEM_IP_IFINDEX, G_CALLBACK (ip_ifindex_changed_cb), self);

	_LOGD (LOGD_BT | LOGD_MB,
	       "modem found");

	return TRUE;
}

static void
mm_modem_added_cb (NMModemManager *manager,
                   NMModem *modem,
                   gpointer user_data)
{
	NMDeviceBt *self = user_data;
	NMDeviceBtPrivate *priv;

	if (!modem_try_claim (user_data, modem))
		return;

	priv = NM_DEVICE_BT_GET_PRIVATE (self);

	if (priv->stage1_bt_state == NM_DEVICE_STAGE_STATE_COMPLETED)
		nm_device_activate_schedule_stage1_device_prepare (NM_DEVICE (self));
}

/*****************************************************************************/

void
_nm_device_bt_notify_set_connected (NMDeviceBt *self,
                                    gboolean connected)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (self);

	connected = !!connected;
	if (priv->is_connected == connected)
		return;

	priv->is_connected = connected;

	if (   connected
	    || priv->stage1_bt_state != NM_DEVICE_STAGE_STATE_COMPLETED
	    || nm_device_get_state (NM_DEVICE (self)) > NM_DEVICE_STATE_ACTIVATED) {
		_LOGT (LOGD_BT, "set-connected: %d", connected);
		return;
	}

	_LOGT (LOGD_BT, "set-connected: %d (disconnecting device...)", connected);
	nm_device_state_changed (NM_DEVICE (self),
	                         NM_DEVICE_STATE_FAILED,
	                         NM_DEVICE_STATE_REASON_CARRIER);
}

static gboolean
connect_watch_link_idle_cb (gpointer user_data)
{
	NMDeviceBt *self = user_data;
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (self);
	int ifindex;

	priv->connect_watch_link_idle_id = 0;

	if (nm_device_get_state (NM_DEVICE (self)) <= NM_DEVICE_STATE_ACTIVATED) {
		ifindex = nm_device_get_ip_ifindex (NM_DEVICE (self));
		if (   ifindex > 0
		    && !nm_platform_link_get (nm_device_get_platform (NM_DEVICE (self)), ifindex)) {
			_LOGT (LOGD_BT, "device disappeared");
			nm_device_state_changed (NM_DEVICE (self),
			                         NM_DEVICE_STATE_FAILED,
			                         NM_DEVICE_STATE_REASON_BT_FAILED);
		}
	}

	return G_SOURCE_REMOVE;
}

static void
connect_watch_link_cb (NMPlatform *platform,
                       int obj_type_i,
                       int ifindex,
                       NMPlatformLink *info,
                       int change_type_i,
                       NMDevice *self)
{
	const NMPlatformSignalChangeType change_type = change_type_i;
	NMDeviceBtPrivate *priv;

	/* bluez doesn't notify us when the connection disconnects.
	 * Neither does NMManager (or NMDevice) tell us when the ip-ifindex goes away.
	 * This is horrible, and should be improved. For now, watch the link ourself... */

	if (NM_IN_SET (change_type, NM_PLATFORM_SIGNAL_CHANGED,
	                            NM_PLATFORM_SIGNAL_REMOVED)) {
		priv = NM_DEVICE_BT_GET_PRIVATE (self);
		if (priv->connect_watch_link_idle_id == 0)
			priv->connect_watch_link_idle_id = g_idle_add (connect_watch_link_idle_cb, self);
	}
}

static gboolean
connect_wait_modem_timeout (gpointer user_data)
{
	NMDeviceBt *self = NM_DEVICE_BT (user_data);
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (self);

	/* since this timeout is longer than the connect timeout, we must have already
	 * hit the connect-timeout first or being connected. */
	nm_assert (priv->stage1_bt_state == NM_DEVICE_STAGE_STATE_COMPLETED);

	priv->connect_wait_modem_id = 0;
	nm_clear_g_cancellable (&priv->connect_bz_cancellable);

	if (priv->modem)
		_LOGD (LOGD_BT, "timeout connecting modem for DUN connection");
	else
		_LOGD (LOGD_BT, "timeout finding modem for DUN connection");

	nm_device_state_changed (NM_DEVICE (self),
	                         NM_DEVICE_STATE_FAILED,
	                         NM_DEVICE_STATE_REASON_MODEM_NOT_FOUND);
	return G_SOURCE_REMOVE;
}

static void
connect_bz_cb (NMBluezManager *bz_mgr,
               gboolean is_complete,
               const char *device_name,
               GError *error,
               gpointer user_data)
{
	NMDeviceBt *self;
	NMDeviceBtPrivate *priv;
	char sbuf[100];

	if (nm_utils_error_is_cancelled (error, FALSE))
		return;

	self = user_data;
	priv = NM_DEVICE_BT_GET_PRIVATE (self);

	nm_assert (nm_device_is_activating (NM_DEVICE (self)));
	nm_assert (NM_IN_SET ((NMBluetoothCapabilities) priv->connect_bt_type, NM_BT_CAPABILITY_DUN,
	                                                                       NM_BT_CAPABILITY_NAP));

	if (!is_complete) {
		nm_assert (priv->connect_bt_type == NM_BT_CAPABILITY_DUN);
		nm_assert (device_name);
		nm_assert (!error);

		if (!nm_streq0 (priv->connect_rfcomm_iface, device_name)) {
			nm_assert (!priv->connect_rfcomm_iface);
			_LOGD (LOGD_BT, "DUN is still connecting but got serial port \"%s\" to claim modem", device_name);
			g_free (priv->connect_rfcomm_iface);
			priv->connect_rfcomm_iface = g_strdup (device_name);
		}
		return;
	}

	g_clear_object (&priv->connect_bz_cancellable);

	if (!device_name) {
		_LOGW (LOGD_BT, "%s connect request failed: %s",
		       nm_bluetooth_capability_to_string (priv->connect_bt_type, sbuf, sizeof (sbuf)),
		       error->message);
		nm_device_state_changed (NM_DEVICE (self),
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_BT_FAILED);
		return;
	}

	_LOGD (LOGD_BT, "%s connect request successful (%s)",
	       nm_bluetooth_capability_to_string (priv->connect_bt_type, sbuf, sizeof (sbuf)),
	       device_name);

	if (priv->connect_bt_type == NM_BT_CAPABILITY_DUN) {
		if (!nm_streq0 (priv->connect_rfcomm_iface, device_name)) {
			nm_assert_not_reached ();
			g_free (priv->connect_rfcomm_iface);
			priv->connect_rfcomm_iface = g_strdup (device_name);
		}
	} else {
		nm_assert (priv->connect_bt_type == NM_BT_CAPABILITY_NAP);
		if (!nm_device_set_ip_iface (NM_DEVICE (self), device_name)) {
			_LOGW (LOGD_BT, "Error connecting with bluez: cannot find device %s", device_name);
			nm_device_state_changed (NM_DEVICE (self),
			                         NM_DEVICE_STATE_FAILED,
			                         NM_DEVICE_STATE_REASON_BT_FAILED);
			return;
		}
		priv->connect_watch_link_id = g_signal_connect (nm_device_get_platform (NM_DEVICE (self)),
		                                                NM_PLATFORM_SIGNAL_LINK_CHANGED,
		                                                G_CALLBACK (connect_watch_link_cb),
		                                                self);
	}

	if (!priv->is_connected) {
		/* we got the callback from NMBluezManager with succes. We actually should be
		 * connected and this line shouldn't be reached. */
		nm_assert_not_reached ();
		_LOGE (LOGD_BT, "bluetooth is unexpectedly not in connected state");
		nm_device_state_changed (NM_DEVICE (self),
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_BT_FAILED);
		return;
	}

	priv->stage1_bt_state = NM_DEVICE_STAGE_STATE_COMPLETED;
	nm_device_activate_schedule_stage1_device_prepare (NM_DEVICE (self));
}

static NMActStageReturn
act_stage1_prepare (NMDevice *device,
                    NMDeviceStateReason *out_failure_reason)
{
	NMDeviceBt *self = NM_DEVICE_BT (device);
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (self);
	gs_free_error GError *error = NULL;
	NMConnection *connection;

	connection = nm_device_get_applied_connection (device);
	g_return_val_if_fail (connection, NM_ACT_STAGE_RETURN_FAILURE);

	priv->connect_bt_type = get_connection_bt_type (connection);
	if (priv->connect_bt_type == NM_BT_CAPABILITY_NONE) {
		NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_BT_FAILED);
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	if (   priv->connect_bt_type == NM_BT_CAPABILITY_DUN
	    && !priv->mm_running) {
		NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_MODEM_MANAGER_UNAVAILABLE);
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	if (priv->stage1_bt_state == NM_DEVICE_STAGE_STATE_PENDING)
		return NM_ACT_STAGE_RETURN_POSTPONE;
	else if (priv->stage1_bt_state == NM_DEVICE_STAGE_STATE_INIT) {
		gs_unref_object GCancellable *cancellable = NULL;
		char sbuf[100];

		_LOGD (LOGD_BT, "connecting to %s bluetooth device",
		       nm_bluetooth_capability_to_string (priv->connect_bt_type, sbuf, sizeof (sbuf)));

		cancellable = g_cancellable_new ();

		if (!nm_bluez_manager_connect (priv->bz_mgr,
		                               priv->dbus_path,
		                               priv->connect_bt_type,
		                               30000,
		                               cancellable,
		                               connect_bz_cb,
		                               self,
		                               &error)) {
			_LOGD (LOGD_BT, "cannot connect to bluetooth device: %s", error->message);
			*out_failure_reason = NM_DEVICE_STATE_REASON_BT_FAILED;
			return NM_ACT_STAGE_RETURN_FAILURE;
		}

		priv->connect_bz_cancellable = g_steal_pointer (&cancellable);
		priv->stage1_bt_state = NM_DEVICE_STAGE_STATE_PENDING;
		return NM_ACT_STAGE_RETURN_POSTPONE;
	}

	if (priv->connect_bt_type == NM_BT_CAPABILITY_DUN) {
		if (!priv->modem) {
			gs_free NMModem **modems = NULL;
			guint i, n;

			if (priv->connect_wait_modem_id == 0)
				priv->connect_wait_modem_id = g_timeout_add_seconds (30, connect_wait_modem_timeout, self);

			modems = nm_modem_manager_get_modems (priv->modem_manager, &n);
			for (i = 0; i < n; i++) {
				if (modem_try_claim (self, modems[i]))
					break;
			}
			if (!priv->modem)
				return NM_ACT_STAGE_RETURN_POSTPONE;
		}

		if (priv->stage1_modem_prepare_state == NM_DEVICE_STAGE_STATE_PENDING)
			return NM_ACT_STAGE_RETURN_POSTPONE;
		if (priv->stage1_modem_prepare_state == NM_DEVICE_STAGE_STATE_INIT) {
			priv->stage1_modem_prepare_state = NM_DEVICE_STAGE_STATE_PENDING;
			return nm_modem_act_stage1_prepare (priv->modem,
			                                    nm_device_get_act_request (NM_DEVICE (self)),
			                                    out_failure_reason);
		}
	}

	return NM_ACT_STAGE_RETURN_SUCCESS;
}

static NMActStageReturn
act_stage2_config (NMDevice *device,
                   NMDeviceStateReason *out_failure_reason)
{
	NMDeviceBt *self = NM_DEVICE_BT (device);
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (self);

	if (priv->connect_bt_type == NM_BT_CAPABILITY_DUN)
		nm_modem_act_stage2_config (priv->modem);

	return NM_ACT_STAGE_RETURN_SUCCESS;
}

static NMActStageReturn
act_stage3_ip_config_start (NMDevice *device,
                            int addr_family,
                            gpointer *out_config,
                            NMDeviceStateReason *out_failure_reason)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (device);

	nm_assert_addr_family (addr_family);

	if (priv->connect_bt_type == NM_BT_CAPABILITY_DUN) {
		if (addr_family == AF_INET) {
			return nm_modem_stage3_ip4_config_start (priv->modem,
			                                         device,
			                                         NM_DEVICE_CLASS (nm_device_bt_parent_class),
			                                         out_failure_reason);
		} else {
			return nm_modem_stage3_ip6_config_start (priv->modem,
			                                         device,
			                                         out_failure_reason);
		}
	}

	return NM_DEVICE_CLASS (nm_device_bt_parent_class)->act_stage3_ip_config_start (device, addr_family, out_config, out_failure_reason);
}

static void
deactivate (NMDevice *device)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (device);

	nm_clear_g_signal_handler (nm_device_get_platform (device), &priv->connect_watch_link_id);
	nm_clear_g_source (&priv->connect_watch_link_idle_id);
	priv->stage1_bt_state = NM_DEVICE_STAGE_STATE_INIT;
	nm_clear_g_source (&priv->connect_wait_modem_id);
	nm_clear_g_cancellable (&priv->connect_bz_cancellable);

	priv->stage1_bt_state = NM_DEVICE_STAGE_STATE_INIT;

	if (priv->connect_bt_type == NM_BT_CAPABILITY_DUN) {
		if (priv->modem) {
			nm_modem_deactivate (priv->modem, device);

			/* Since we're killing the Modem object before it'll get the
			 * state change signal, simulate the state change here.
			 */
			nm_modem_device_state_changed (priv->modem,
			                               NM_DEVICE_STATE_DISCONNECTED,
			                               NM_DEVICE_STATE_ACTIVATED);
			modem_cleanup (NM_DEVICE_BT (device));
		}
	}

	if (priv->connect_bt_type != NM_BT_CAPABILITY_NONE) {
		priv->connect_bt_type = NM_BT_CAPABILITY_NONE;
		nm_bluez_manager_disconnect (priv->bz_mgr, priv->dbus_path);
	}

	nm_clear_g_free (&priv->connect_rfcomm_iface);

	if (NM_DEVICE_CLASS (nm_device_bt_parent_class)->deactivate)
		NM_DEVICE_CLASS (nm_device_bt_parent_class)->deactivate (device);
}

void
_nm_device_bt_notify_removed (NMDeviceBt *self)
{
	g_signal_emit_by_name (self, NM_DEVICE_REMOVED);
}

/*****************************************************************************/

gboolean
_nm_device_bt_for_same_device (NMDeviceBt *self,
                               const char *dbus_path,
                               const char *bdaddr,
                               const char *name,
                               NMBluetoothCapabilities capabilities)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (self);

	return    nm_streq (priv->dbus_path, dbus_path)
	       && nm_streq (priv->bdaddr, bdaddr)
	       && capabilities == priv->capabilities
	       && (!name || nm_streq (priv->name, name));
}

void
_nm_device_bt_notify_set_name (NMDeviceBt *self, const char *name)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (self);

	nm_assert (name);

	if (!nm_streq (priv->name, name)) {
		_LOGT (LOGD_BT, "set-name: %s", name);
		g_free (priv->name);
		priv->name = g_strdup (name);
		_notify (self, PROP_BT_NAME);
	}
}

/*****************************************************************************/

static gboolean
is_available (NMDevice *dev, NMDeviceCheckDevAvailableFlags flags)
{
	NMDeviceBt *self = NM_DEVICE_BT (dev);
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (self);

	/* PAN doesn't need ModemManager, so devices that support it are always available */
	if (priv->capabilities & NM_BT_CAPABILITY_NAP)
		return TRUE;

	/* DUN requires ModemManager */
	return priv->mm_running;
}

static void
set_mm_running (NMDeviceBt *self)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (self);
	gboolean running;

	running = (nm_modem_manager_name_owner_get (priv->modem_manager) != NULL);

	if (priv->mm_running != running) {
		_LOGD (LOGD_BT, "ModemManager now %s",
		       running ? "available" : "unavailable");

		priv->mm_running = running;
		nm_device_queue_recheck_available (NM_DEVICE (self),
		                                   NM_DEVICE_STATE_REASON_NONE,
		                                   NM_DEVICE_STATE_REASON_MODEM_MANAGER_UNAVAILABLE);
	}
}

static void
mm_name_owner_changed_cb (GObject *object,
                          GParamSpec *pspec,
                          gpointer user_data)
{
	set_mm_running (user_data);
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE ((NMDeviceBt *) object);

	switch (prop_id) {
	case PROP_BT_NAME:
		g_value_set_string (value, priv->name);
		break;
	case PROP_BT_CAPABILITIES:
		g_value_set_uint (value, priv->capabilities);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE ((NMDeviceBt *) object);

	switch (prop_id) {
	case PROP_BT_BZ_MGR:
		/* construct-only */
		priv->bz_mgr = g_object_ref (g_value_get_pointer (value));
		nm_assert (NM_IS_BLUEZ_MANAGER (priv->bz_mgr));
		break;
	case PROP_BT_DBUS_PATH:
		/* construct-only */
		priv->dbus_path = g_value_dup_string (value);
		nm_assert (priv->dbus_path);
		break;
	case PROP_BT_BDADDR:
		/* construct-only */
		priv->bdaddr = g_value_dup_string (value);
		nm_assert (priv->bdaddr);
		break;
	case PROP_BT_NAME:
		/* construct-only */
		priv->name = g_value_dup_string (value);
		nm_assert (priv->name);
		break;
	case PROP_BT_CAPABILITIES:
		/* construct-only */
		priv->capabilities = g_value_get_uint (value);
		nm_assert (NM_IN_SET ((NMBluetoothCapabilities) priv->capabilities, NM_BT_CAPABILITY_DUN,
		                                                                    NM_BT_CAPABILITY_NAP,
		                                                                    NM_BT_CAPABILITY_DUN | NM_BT_CAPABILITY_NAP));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_device_bt_init (NMDeviceBt *self)
{
}

static void
constructed (GObject *object)
{
	NMDeviceBt *self = NM_DEVICE_BT (object);
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (self);

	G_OBJECT_CLASS (nm_device_bt_parent_class)->constructed (object);

	priv->modem_manager = g_object_ref (nm_modem_manager_get ());

	nm_modem_manager_name_owner_ref (priv->modem_manager);

	g_signal_connect (priv->modem_manager,
	                  NM_MODEM_MANAGER_MODEM_ADDED,
	                  G_CALLBACK (mm_modem_added_cb),
	                  self);

	g_signal_connect (priv->modem_manager,
	                  "notify::"NM_MODEM_MANAGER_NAME_OWNER,
	                  G_CALLBACK (mm_name_owner_changed_cb),
	                  self);

	set_mm_running (self);
}

NMDeviceBt *
nm_device_bt_new (NMBluezManager *bz_mgr,
                  const char *dbus_path,
                  const char *bdaddr,
                  const char *name,
                  NMBluetoothCapabilities capabilities)
{
	g_return_val_if_fail (NM_IS_BLUEZ_MANAGER (bz_mgr), NULL);
	g_return_val_if_fail (dbus_path, NULL);
	g_return_val_if_fail (bdaddr, NULL);
	g_return_val_if_fail (name, NULL);
	g_return_val_if_fail (capabilities != NM_BT_CAPABILITY_NONE, NULL);

	return g_object_new (NM_TYPE_DEVICE_BT,
	                     NM_DEVICE_UDI, dbus_path,
	                     NM_DEVICE_IFACE, bdaddr,
	                     NM_DEVICE_DRIVER, "bluez",
	                     NM_DEVICE_PERM_HW_ADDRESS, bdaddr,
	                     NM_DEVICE_BT_BDADDR, bdaddr,
	                     NM_DEVICE_BT_BZ_MGR, bz_mgr,
	                     NM_DEVICE_BT_CAPABILITIES, (guint) capabilities,
	                     NM_DEVICE_BT_DBUS_PATH, dbus_path,
	                     NM_DEVICE_BT_NAME, name,
	                     NM_DEVICE_TYPE_DESC, "Bluetooth",
	                     NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_BT,
	                     NULL);
}

static void
dispose (GObject *object)
{
	NMDeviceBt *self = NM_DEVICE_BT (object);
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (self);

	nm_clear_g_signal_handler (nm_device_get_platform (NM_DEVICE (self)), &priv->connect_watch_link_id);
	nm_clear_g_source (&priv->connect_watch_link_idle_id);

	nm_clear_g_source (&priv->connect_wait_modem_id);
	nm_clear_g_cancellable (&priv->connect_bz_cancellable);

	if (priv->modem_manager) {
		g_signal_handlers_disconnect_by_func (priv->modem_manager, G_CALLBACK (mm_name_owner_changed_cb), self);
		g_signal_handlers_disconnect_by_func (priv->modem_manager, G_CALLBACK (mm_modem_added_cb), self);
		nm_modem_manager_name_owner_unref (priv->modem_manager);
		g_clear_object (&priv->modem_manager);
	}

	modem_cleanup (self);

	G_OBJECT_CLASS (nm_device_bt_parent_class)->dispose (object);

	g_clear_object (&priv->bz_mgr);
}

static void
finalize (GObject *object)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE ((NMDeviceBt *) object);

	g_free (priv->connect_rfcomm_iface);
	g_free (priv->dbus_path);
	g_free (priv->name);
	g_free (priv->bdaddr);

	G_OBJECT_CLASS (nm_device_bt_parent_class)->finalize (object);
}

static const NMDBusInterfaceInfoExtended interface_info_device_bluetooth = {
	.parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (
		NM_DBUS_INTERFACE_DEVICE_BLUETOOTH,
		.signals = NM_DEFINE_GDBUS_SIGNAL_INFOS (
			&nm_signal_info_property_changed_legacy,
		),
		.properties = NM_DEFINE_GDBUS_PROPERTY_INFOS (
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("HwAddress",      "s",  NM_DEVICE_HW_ADDRESS),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Name",           "s",  NM_DEVICE_BT_NAME),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("BtCapabilities", "u",  NM_DEVICE_BT_CAPABILITIES),
		),
	),
	.legacy_property_changed = TRUE,
};

static void
nm_device_bt_class_init (NMDeviceBtClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	object_class->constructed = constructed;
	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS (&interface_info_device_bluetooth);

	device_class->connection_type_check_compatible = NM_SETTING_BLUETOOTH_SETTING_NAME;

	device_class->get_generic_capabilities = get_generic_capabilities;
	device_class->can_auto_connect = can_auto_connect;
	device_class->deactivate = deactivate;
	device_class->act_stage1_prepare = act_stage1_prepare;
	device_class->act_stage2_config = act_stage2_config;
	device_class->act_stage3_ip_config_start = act_stage3_ip_config_start;
	device_class->check_connection_compatible = check_connection_compatible;
	device_class->check_connection_available = check_connection_available;
	device_class->complete_connection = complete_connection;
	device_class->is_available = is_available;
	device_class->get_configured_mtu = nm_modem_get_configured_mtu;

	device_class->state_changed = device_state_changed;

	obj_properties[PROP_BT_BZ_MGR] =
	     g_param_spec_pointer (NM_DEVICE_BT_BZ_MGR, "", "",
	                           G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY |
	                           G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_BT_BDADDR] =
	     g_param_spec_string (NM_DEVICE_BT_BDADDR, "", "",
	                          NULL,
	                          G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_BT_DBUS_PATH] =
	     g_param_spec_string (NM_DEVICE_BT_DBUS_PATH, "", "",
	                          NULL,
	                          G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_BT_NAME] =
	     g_param_spec_string (NM_DEVICE_BT_NAME, "", "",
	                          NULL,
	                          G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_BT_CAPABILITIES] =
	     g_param_spec_uint (NM_DEVICE_BT_CAPABILITIES, "", "",
	                        NM_BT_CAPABILITY_NONE, G_MAXUINT, NM_BT_CAPABILITY_NONE,
	                        G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                        G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	signals[PPP_STATS] =
	    g_signal_new (NM_DEVICE_BT_PPP_STATS,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 2,
	                  G_TYPE_UINT /*guint32 in_bytes*/,
	                  G_TYPE_UINT /*guint32 out_bytes*/);
}
