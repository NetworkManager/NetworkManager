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

#include "nm-default.h"

#include "nm-device-bt.h"

#include <stdio.h>
#include <string.h>

#include "nm-bluez-common.h"
#include "nm-bluez-device.h"
#include "nm-device-private.h"
#include "ppp-manager/nm-ppp-manager.h"
#include "nm-setting-connection.h"
#include "nm-setting-bluetooth.h"
#include "nm-setting-cdma.h"
#include "nm-setting-gsm.h"
#include "nm-setting-serial.h"
#include "nm-setting-ppp.h"
#include "NetworkManagerUtils.h"
#include "nm-bt-enum-types.h"
#include "nm-utils.h"
#include "nm-bt-error.h"
#include "nm-bt-enum-types.h"
#include "nm-platform.h"

#include "nmdbus-device-bt.h"

#define MM_DBUS_SERVICE   "org.freedesktop.ModemManager1"
#define MM_DBUS_PATH      "/org/freedesktop/ModemManager1"
#define MM_DBUS_INTERFACE "org.freedesktop.ModemManager1"

#include "nm-device-logging.h"
_LOG_DECLARE_SELF(NMDeviceBt);

G_DEFINE_TYPE (NMDeviceBt, nm_device_bt, NM_TYPE_DEVICE)

#define NM_DEVICE_BT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_BT, NMDeviceBtPrivate))

static gboolean modem_stage1 (NMDeviceBt *self, NMModem *modem, NMDeviceStateReason *reason);

typedef struct {
	GDBusProxy *mm_proxy;
	gboolean mm_running;

	NMBluezDevice *bt_device;

	char *bdaddr;
	char *name;
	guint32 capabilities;

	gboolean connected;
	gboolean have_iface;

	char *rfcomm_iface;
	NMModem *modem;
	guint32 timeout_id;

	guint32 bt_type;  /* BT type of the current connection */
} NMDeviceBtPrivate;

enum {
	PROP_0,
	PROP_BT_NAME,
	PROP_BT_CAPABILITIES,
	PROP_BT_DEVICE,

	LAST_PROP
};

enum {
	PPP_STATS,

	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };


guint32 nm_device_bt_get_capabilities (NMDeviceBt *self)
{
	g_return_val_if_fail (NM_IS_DEVICE_BT (self), NM_BT_CAPABILITY_NONE);

	return NM_DEVICE_BT_GET_PRIVATE (self)->capabilities;
}

static guint32
get_connection_bt_type (NMConnection *connection)
{
	NMSettingBluetooth *s_bt;
	const char *bt_type;

	s_bt = nm_connection_get_setting_bluetooth (connection);
	if (!s_bt)
		return NM_BT_CAPABILITY_NONE;

	bt_type = nm_setting_bluetooth_get_connection_type (s_bt);
	g_assert (bt_type);

	if (!strcmp (bt_type, NM_SETTING_BLUETOOTH_TYPE_DUN))
		return NM_BT_CAPABILITY_DUN;
	else if (!strcmp (bt_type, NM_SETTING_BLUETOOTH_TYPE_PANU))
		return NM_BT_CAPABILITY_NAP;

	return NM_BT_CAPABILITY_NONE;
}

static NMDeviceCapabilities
get_generic_capabilities (NMDevice *device)
{
	return NM_DEVICE_CAP_IS_NON_KERNEL;
}

static gboolean
can_auto_connect (NMDevice *device,
                  NMConnection *connection,
                  char **specific_object)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (device);
	guint32 bt_type;

	if (!NM_DEVICE_CLASS (nm_device_bt_parent_class)->can_auto_connect (device, connection, specific_object))
		return FALSE;

	/* Can't auto-activate a DUN connection without ModemManager */
	bt_type = get_connection_bt_type (connection);
	if (bt_type == NM_BT_CAPABILITY_DUN && priv->mm_running == FALSE)
		return FALSE;

	return TRUE;
}

static gboolean
check_connection_compatible (NMDevice *device, NMConnection *connection)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (device);
	NMSettingConnection *s_con;
	NMSettingBluetooth *s_bt;
	const char *bdaddr;
	guint32 bt_type;

	if (!NM_DEVICE_CLASS (nm_device_bt_parent_class)->check_connection_compatible (device, connection))
		return FALSE;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	if (strcmp (nm_setting_connection_get_connection_type (s_con), NM_SETTING_BLUETOOTH_SETTING_NAME))
		return FALSE;

	s_bt = nm_connection_get_setting_bluetooth (connection);
	if (!s_bt)
		return FALSE;

	bt_type = get_connection_bt_type (connection);
	if (!(bt_type & priv->capabilities))
		return FALSE;

	bdaddr = nm_setting_bluetooth_get_bdaddr (s_bt);
	if (!bdaddr)
		return FALSE;
	if (!nm_utils_hwaddr_matches (priv->bdaddr, -1, bdaddr, -1))
		return FALSE;

	return TRUE;
}

static gboolean
check_connection_available (NMDevice *device,
                            NMConnection *connection,
                            NMDeviceCheckConAvailableFlags flags,
                            const char *specific_object)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (device);
	guint32 bt_type;

	bt_type = get_connection_bt_type (connection);
	if (!(bt_type & priv->capabilities))
		return FALSE;

	/* DUN connections aren't available without ModemManager */
	if (bt_type == NM_BT_CAPABILITY_DUN && priv->mm_running == FALSE)
		return FALSE;

	return TRUE;
}

static gboolean
complete_connection (NMDevice *device,
                     NMConnection *connection,
                     const char *specific_object,
                     const GSList *existing_connections,
                     GError **error)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (device);
	NMSettingBluetooth *s_bt;
	const char *setting_bdaddr;
	const char *ctype;
	gboolean is_dun = FALSE, is_pan = FALSE;
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
		if (s_gsm || s_cdma || s_serial || s_ppp) {
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
		if (!s_gsm && !s_cdma) {
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
			if (!nm_setting_gsm_get_number (s_gsm))
				g_object_set (G_OBJECT (s_gsm), NM_SETTING_GSM_NUMBER, "*99#", NULL);
		} else {
			fallback_prefix = _("CDMA connection");
			if (!nm_setting_cdma_get_number (s_cdma))
				g_object_set (G_OBJECT (s_cdma), NM_SETTING_GSM_NUMBER, "#777", NULL);
		}
	} else {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("Unknown/unhandled Bluetooth connection type"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_BLUETOOTH_SETTING_NAME, NM_SETTING_BLUETOOTH_TYPE);
		return FALSE;
	}

	nm_utils_complete_generic (NM_PLATFORM_GET,
	                           connection,
	                           NM_SETTING_BLUETOOTH_SETTING_NAME,
	                           existing_connections,
	                           preferred,
	                           fallback_prefix,
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
		   guint32 in_bytes,
		   guint32 out_bytes,
		   gpointer user_data)
{
	g_signal_emit (NM_DEVICE_BT (user_data), signals[PPP_STATS], 0, in_bytes, out_bytes);
}

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
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;

	if (error) {
		nm_device_state_changed (device,
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_NO_SECRETS);
	} else {
		/* Otherwise, on success for GSM/CDMA secrets we need to schedule modem stage1 again */
		g_return_if_fail (nm_device_get_state (device) == NM_DEVICE_STATE_NEED_AUTH);
		if (!modem_stage1 (NM_DEVICE_BT (device), priv->modem, &reason))
			nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, reason);
	}
}

static void
modem_prepare_result (NMModem *modem,
                      gboolean success,
                      NMDeviceStateReason reason,
                      gpointer user_data)
{
	NMDeviceBt *self = NM_DEVICE_BT (user_data);
	NMDevice *device = NM_DEVICE (self);
	NMDeviceState state;

	state = nm_device_get_state (device);
	g_return_if_fail (state == NM_DEVICE_STATE_CONFIG || state == NM_DEVICE_STATE_NEED_AUTH);

	if (success) {
		NMActRequest *req;
		NMActStageReturn ret;
		NMDeviceStateReason stage2_reason = NM_DEVICE_STATE_REASON_NONE;

		req = nm_device_get_act_request (device);
		g_assert (req);

		ret = nm_modem_act_stage2_config (modem, req, &stage2_reason);
		switch (ret) {
		case NM_ACT_STAGE_RETURN_POSTPONE:
			break;
		case NM_ACT_STAGE_RETURN_SUCCESS:
			nm_device_activate_schedule_stage3_ip_config_start (device);
			break;
		case NM_ACT_STAGE_RETURN_FAILURE:
		default:
			nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, stage2_reason);
			break;
		}
	} else {
		if (reason == NM_DEVICE_STATE_REASON_SIM_PIN_INCORRECT) {
			/* If the connect failed because the SIM PIN was wrong don't allow
			 * the device to be auto-activated anymore, which would risk locking
			 * the SIM if the incorrect PIN continues to be used.
			 */
			nm_device_set_autoconnect (device, FALSE);
			_LOGI (LOGD_MB, "disabling autoconnect due to failed SIM PIN");
		}

		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, reason);
	}
}

static void
device_state_changed (NMDevice *device,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (device);

	if (priv->modem)
		nm_modem_device_state_changed (priv->modem, new_state, old_state, reason);

	/* Need to recheck available connections whenever MM appears or disappears,
	 * since the device could be both DUN and NAP capable and thus may not
	 * change state (which rechecks available connections) when MM comes and goes.
	 */
	if (priv->mm_running && (priv->capabilities & NM_BT_CAPABILITY_DUN))
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

		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
	} else
		nm_device_activate_schedule_ip4_config_result (device, config);
}

static void
data_port_changed_cb (NMModem *modem, GParamSpec *pspec, gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);

	nm_device_set_ip_iface (self, nm_modem_get_data_port (modem));
}

static gboolean
modem_stage1 (NMDeviceBt *self, NMModem *modem, NMDeviceStateReason *reason)
{
	NMActRequest *req;
	NMActStageReturn ret;

	g_return_val_if_fail (reason != NULL, FALSE);

	req = nm_device_get_act_request (NM_DEVICE (self));
	g_assert (req);

	ret = nm_modem_act_stage1_prepare (modem, req, reason);
	switch (ret) {
	case NM_ACT_STAGE_RETURN_POSTPONE:
	case NM_ACT_STAGE_RETURN_SUCCESS:
		/* Success, wait for the 'prepare-result' signal */
		return TRUE;
	case NM_ACT_STAGE_RETURN_FAILURE:
	default:
		break;
	}

	return FALSE;
}

/*****************************************************************************/

static void
modem_cleanup (NMDeviceBt *self)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (self);

	if (priv->modem) {
		g_signal_handlers_disconnect_matched (priv->modem, G_SIGNAL_MATCH_DATA, 0, 0, NULL, NULL, self);
		g_clear_object (&priv->modem);
	}
}

static void
modem_state_cb (NMModem *modem,
                NMModemState new_state,
                NMModemState old_state,
                gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);
	NMDeviceState dev_state = nm_device_get_state (device);

	if (new_state <= NM_MODEM_STATE_DISABLING && old_state > NM_MODEM_STATE_DISABLING) {
		/* Will be called whenever something external to NM disables the
		 * modem directly through ModemManager.
		 */
		if (nm_device_is_activating (device) || dev_state == NM_DEVICE_STATE_ACTIVATED) {
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
}

static void
modem_removed_cb (NMModem *modem, gpointer user_data)
{
	NMDeviceBt *self = NM_DEVICE_BT (user_data);
	NMDeviceState state;

	/* Fail the device if the modem was removed while active */
	state = nm_device_get_state (NM_DEVICE (self));
	if (   state == NM_DEVICE_STATE_ACTIVATED
	    || nm_device_is_activating (NM_DEVICE (self))) {
		nm_device_state_changed (NM_DEVICE (self),
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_BT_FAILED);
	} else
		modem_cleanup (self);
}

static gboolean
component_added (NMDevice *device, GObject *component)
{
	NMDeviceBt *self = NM_DEVICE_BT (device);
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (self);
	NMModem *modem;
	const gchar *modem_data_port;
	const gchar *modem_control_port;
	char *base;
	NMDeviceState state;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;

	if (!NM_IS_MODEM (component))
		return FALSE;
	modem = NM_MODEM (component);

	modem_data_port = nm_modem_get_data_port (modem);
	modem_control_port = nm_modem_get_control_port (modem);
	g_return_val_if_fail (modem_data_port != NULL || modem_control_port != NULL, FALSE);

	if (!priv->rfcomm_iface)
		return FALSE;

	base = g_path_get_basename (priv->rfcomm_iface);
	if (g_strcmp0 (base, modem_data_port) && g_strcmp0 (base, modem_control_port)) {
		g_free (base);
		return FALSE;
	}
	g_free (base);

	/* Got the modem */
	nm_clear_g_source (&priv->timeout_id);

	/* Can only accept the modem in stage2, but since the interface matched
	 * what we were expecting, don't let anything else claim the modem either.
	 */
	state = nm_device_get_state (NM_DEVICE (self));
	if (state != NM_DEVICE_STATE_CONFIG) {
		_LOGW (LOGD_BT | LOGD_MB,
		       "modem found but device not in correct state (%d)",
		       nm_device_get_state (NM_DEVICE (self)));
		return TRUE;
	}

	_LOGI (LOGD_BT | LOGD_MB,
	       "Activation: (bluetooth) Stage 2 of 5 (Device Configure) modem found.");

	if (priv->modem) {
		g_warn_if_reached ();
		modem_cleanup (self);
	}

	priv->modem = g_object_ref (modem);
	g_signal_connect (modem, NM_MODEM_PPP_STATS, G_CALLBACK (ppp_stats), self);
	g_signal_connect (modem, NM_MODEM_PPP_FAILED, G_CALLBACK (ppp_failed), self);
	g_signal_connect (modem, NM_MODEM_PREPARE_RESULT, G_CALLBACK (modem_prepare_result), self);
	g_signal_connect (modem, NM_MODEM_IP4_CONFIG_RESULT, G_CALLBACK (modem_ip4_config_result), self);
	g_signal_connect (modem, NM_MODEM_AUTH_REQUESTED, G_CALLBACK (modem_auth_requested), self);
	g_signal_connect (modem, NM_MODEM_AUTH_RESULT, G_CALLBACK (modem_auth_result), self);
	g_signal_connect (modem, NM_MODEM_STATE_CHANGED, G_CALLBACK (modem_state_cb), self);
	g_signal_connect (modem, NM_MODEM_REMOVED, G_CALLBACK (modem_removed_cb), self);

	g_signal_connect (modem, "notify::" NM_MODEM_DATA_PORT, G_CALLBACK (data_port_changed_cb), self);

	/* Kick off the modem connection */
	if (!modem_stage1 (self, modem, &reason))
		nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_FAILED, reason);

	return TRUE;
}

static gboolean
modem_find_timeout (gpointer user_data)
{
	NMDeviceBt *self = NM_DEVICE_BT (user_data);

	NM_DEVICE_BT_GET_PRIVATE (self)->timeout_id = 0;
	nm_device_state_changed (NM_DEVICE (self),
	                         NM_DEVICE_STATE_FAILED,
	                         NM_DEVICE_STATE_REASON_MODEM_NOT_FOUND);
	return FALSE;
}

static void
check_connect_continue (NMDeviceBt *self)
{
	NMDevice *device = NM_DEVICE (self);
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (self);
	gboolean pan = (priv->bt_type == NM_BT_CAPABILITY_NAP);
	gboolean dun = (priv->bt_type == NM_BT_CAPABILITY_DUN);

	if (!priv->connected || !priv->have_iface)
		return;

	_LOGI (LOGD_BT,
	       "Activation: (bluetooth) Stage 2 of 5 (Device Configure) successful. Will connect via %s.",
	       dun ? "DUN" : (pan ? "PAN" : "unknown"));

	/* Kill the connect timeout since we're connected now */
	nm_clear_g_source (&priv->timeout_id);

	if (pan) {
		/* Bluez says we're connected now.  Start IP config. */
		nm_device_activate_schedule_stage3_ip_config_start (device);
	} else if (dun) {
		/* Wait for ModemManager to find the modem */
		priv->timeout_id = g_timeout_add_seconds (30, modem_find_timeout, self);

		_LOGI (LOGD_BT | LOGD_MB,
		       "Activation: (bluetooth) Stage 2 of 5 (Device Configure) waiting for modem to appear.");
	} else
		g_assert_not_reached ();
}

static void
bluez_connect_cb (GObject *object,
                  GAsyncResult *res,
                  void *user_data)
{
	NMDeviceBt *self = NM_DEVICE_BT (user_data);
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (self);
	GError *error = NULL;
	const char *device;

	device = nm_bluez_device_connect_finish (NM_BLUEZ_DEVICE (object),
	                                         res, &error);

	if (!device) {
		_LOGW (LOGD_BT, "Error connecting with bluez: %s", error->message);
		g_clear_error (&error);

		nm_device_state_changed (NM_DEVICE (self),
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_BT_FAILED);
		g_object_unref (self);
		return;
	}

	if (priv->bt_type == NM_BT_CAPABILITY_DUN) {
		g_free (priv->rfcomm_iface);
		priv->rfcomm_iface = g_strdup (device);
	} else if (priv->bt_type == NM_BT_CAPABILITY_NAP) {
		nm_device_set_ip_iface (NM_DEVICE (self), device);
	}

	_LOGD (LOGD_BT, "connect request successful");

	/* Stage 3 gets scheduled when Bluez says we're connected */
	priv->have_iface = TRUE;
	check_connect_continue (self);
	g_object_unref (self);
}

static void
bluez_connected_changed (NMBluezDevice *bt_device,
                         GParamSpec *pspec,
                         NMDevice *device)
{
	NMDeviceBt *self = NM_DEVICE_BT (device);
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (self);
	gboolean connected;
	NMDeviceState state;

	state = nm_device_get_state (device);
	connected = nm_bluez_device_get_connected (bt_device);
	if (connected) {
		if (state == NM_DEVICE_STATE_CONFIG) {
			_LOGD (LOGD_BT, "connected to the device");

			priv->connected = TRUE;
			check_connect_continue (self);
		}
	} else {
		gboolean fail = FALSE;

		/* Bluez says we're disconnected from the device.  Suck. */

		if (nm_device_is_activating (device)) {
			_LOGI (LOGD_BT, "Activation: (bluetooth) bluetooth link disconnected.");
			fail = TRUE;
		} else if (state == NM_DEVICE_STATE_ACTIVATED) {
			_LOGI (LOGD_BT, "bluetooth link disconnected.");
			fail = TRUE;
		}

		if (fail) {
			nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_CARRIER);
			priv->connected = FALSE;
		}
	}
}

static gboolean
bt_connect_timeout (gpointer user_data)
{
	NMDeviceBt *self = NM_DEVICE_BT (user_data);

	_LOGD (LOGD_BT, "initial connection timed out");

	NM_DEVICE_BT_GET_PRIVATE (self)->timeout_id = 0;
	nm_device_state_changed (NM_DEVICE (self),
	                         NM_DEVICE_STATE_FAILED,
	                         NM_DEVICE_STATE_REASON_BT_FAILED);
	return FALSE;
}

static NMActStageReturn
act_stage2_config (NMDevice *device, NMDeviceStateReason *reason)
{
	NMDeviceBt *self = NM_DEVICE_BT (device);
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (device);
	NMConnection *connection;

	connection = nm_device_get_applied_connection (device);
	g_assert (connection);
	priv->bt_type = get_connection_bt_type (connection);
	if (priv->bt_type == NM_BT_CAPABILITY_NONE) {
		// FIXME: set a reason code
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	if (priv->bt_type == NM_BT_CAPABILITY_DUN && !priv->mm_running) {
		*reason = NM_DEVICE_STATE_REASON_MODEM_MANAGER_UNAVAILABLE;
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	_LOGD (LOGD_BT, "requesting connection to the device");

	/* Connect to the BT device */
	nm_bluez_device_connect_async (priv->bt_device,
	                               priv->bt_type & (NM_BT_CAPABILITY_DUN | NM_BT_CAPABILITY_NAP),
	                               bluez_connect_cb, g_object_ref (device));

	if (priv->timeout_id)
		g_source_remove (priv->timeout_id);
	priv->timeout_id = g_timeout_add_seconds (30, bt_connect_timeout, device);

	return NM_ACT_STAGE_RETURN_POSTPONE;
}

static NMActStageReturn
act_stage3_ip4_config_start (NMDevice *device,
                             NMIP4Config **out_config,
                             NMDeviceStateReason *reason)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (device);
	NMActStageReturn ret;

	if (priv->bt_type == NM_BT_CAPABILITY_DUN) {
		ret = nm_modem_stage3_ip4_config_start (NM_DEVICE_BT_GET_PRIVATE (device)->modem,
		                                        device,
		                                        NM_DEVICE_CLASS (nm_device_bt_parent_class),
		                                        reason);
	} else
		ret = NM_DEVICE_CLASS (nm_device_bt_parent_class)->act_stage3_ip4_config_start (device, out_config, reason);

	return ret;
}

static NMActStageReturn
act_stage3_ip6_config_start (NMDevice *device,
                             NMIP6Config **out_config,
                             NMDeviceStateReason *reason)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (device);
	NMActStageReturn ret;

	if (priv->bt_type == NM_BT_CAPABILITY_DUN) {
		ret = nm_modem_stage3_ip6_config_start (NM_DEVICE_BT_GET_PRIVATE (device)->modem,
		                                        nm_device_get_act_request (device),
		                                        reason);
	} else
		ret = NM_DEVICE_CLASS (nm_device_bt_parent_class)->act_stage3_ip6_config_start (device, out_config, reason);

	return ret;
}

static void
deactivate (NMDevice *device)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (device);

	priv->have_iface = FALSE;
	priv->connected = FALSE;

	if (priv->bt_type == NM_BT_CAPABILITY_DUN) {
		if (priv->modem) {
			nm_modem_deactivate (priv->modem, device);

			/* Since we're killing the Modem object before it'll get the
			 * state change signal, simulate the state change here.
			 */
			nm_modem_device_state_changed (priv->modem,
			                               NM_DEVICE_STATE_DISCONNECTED,
			                               NM_DEVICE_STATE_ACTIVATED,
			                               NM_DEVICE_STATE_REASON_USER_REQUESTED);
			modem_cleanup (NM_DEVICE_BT (device));
		}
	}

	if (priv->bt_type != NM_BT_CAPABILITY_NONE)
		nm_bluez_device_disconnect (priv->bt_device);

	nm_clear_g_source (&priv->timeout_id);

	priv->bt_type = NM_BT_CAPABILITY_NONE;

	g_free (priv->rfcomm_iface);
	priv->rfcomm_iface = NULL;

	if (NM_DEVICE_CLASS (nm_device_bt_parent_class)->deactivate)
		NM_DEVICE_CLASS (nm_device_bt_parent_class)->deactivate (device);
}

static void
bluez_device_removed (NMBluezDevice *bdev, gpointer user_data)
{
	g_signal_emit_by_name (NM_DEVICE_BT (user_data), NM_DEVICE_REMOVED);
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
set_mm_running (NMDeviceBt *self, gboolean running)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (self);

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
mm_name_owner_changed (GObject *object,
                       GParamSpec *pspec,
                       NMDeviceBt *self)
{
	char *owner;

	owner = g_dbus_proxy_get_name_owner (G_DBUS_PROXY (object));
	if (owner) {
		set_mm_running (self, TRUE);
		g_free (owner);
	} else
		set_mm_running (self, FALSE);
}

/*****************************************************************************/

NMDevice *
nm_device_bt_new (NMBluezDevice *bt_device,
                  const char *udi,
                  const char *bdaddr,
                  const char *name,
                  guint32 capabilities)
{
	g_return_val_if_fail (udi != NULL, NULL);
	g_return_val_if_fail (bdaddr != NULL, NULL);
	g_return_val_if_fail (name != NULL, NULL);
	g_return_val_if_fail (capabilities != NM_BT_CAPABILITY_NONE, NULL);
	g_return_val_if_fail (NM_IS_BLUEZ_DEVICE (bt_device), NULL);

	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_BT,
	                                  NM_DEVICE_UDI, udi,
	                                  NM_DEVICE_IFACE, bdaddr,
	                                  NM_DEVICE_DRIVER, "bluez",
	                                  NM_DEVICE_HW_ADDRESS, bdaddr,
	                                  NM_DEVICE_BT_DEVICE, bt_device,
	                                  NM_DEVICE_BT_NAME, name,
	                                  NM_DEVICE_BT_CAPABILITIES, capabilities,
	                                  NM_DEVICE_TYPE_DESC, "Bluetooth",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_BT,
	                                  NULL);
}

static void
nm_device_bt_init (NMDeviceBt *self)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (self);
	GError *error = NULL;

	priv->mm_proxy = g_dbus_proxy_new_for_bus_sync (G_BUS_TYPE_SYSTEM,
	                                                G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES |
	                                                    G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS |
	                                                    G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START,
	                                                NULL,
	                                                MM_DBUS_SERVICE,
	                                                MM_DBUS_PATH,
	                                                MM_DBUS_INTERFACE,
	                                                NULL, &error);
	if (priv->mm_proxy) {
		g_signal_connect (priv->mm_proxy, "notify::g-name-owner",
		                  G_CALLBACK (mm_name_owner_changed),
		                  self);
		mm_name_owner_changed (G_OBJECT (priv->mm_proxy), NULL, self);
	} else {
		_LOGW (LOGD_MB, "Could not create proxy for '%s': %s",
		       MM_DBUS_SERVICE, error->message);
		g_clear_error (&error);
	}
}

static void
constructed (GObject *object)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (object);
	const char *my_hwaddr;

	G_OBJECT_CLASS (nm_device_bt_parent_class)->constructed (object);

	my_hwaddr = nm_device_get_hw_address (NM_DEVICE (object));
	g_assert (my_hwaddr);
	priv->bdaddr = g_strdup (my_hwaddr);

	/* Watch for BT device property changes */
	g_signal_connect (priv->bt_device, "notify::" NM_BLUEZ_DEVICE_CONNECTED,
	                  G_CALLBACK (bluez_connected_changed),
	                  object);
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_BT_NAME:
		/* Construct only */
		priv->name = g_value_dup_string (value);
		break;
	case PROP_BT_CAPABILITIES:
		/* Construct only */
		priv->capabilities = g_value_get_uint (value);
		break;
	case PROP_BT_DEVICE:
		/* Construct only */
		priv->bt_device = g_value_dup_object (value);
		g_signal_connect (priv->bt_device, "removed", G_CALLBACK (bluez_device_removed), object);
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
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_BT_NAME:
		g_value_set_string (value, priv->name);
		break;
	case PROP_BT_CAPABILITIES:
		g_value_set_uint (value, priv->capabilities);
		break;
	case PROP_BT_DEVICE:
		g_value_set_object (value, priv->bt_device);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
dispose (GObject *object)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (object);

	nm_clear_g_source (&priv->timeout_id);

	g_signal_handlers_disconnect_matched (priv->bt_device, G_SIGNAL_MATCH_DATA, 0, 0, NULL, NULL, object);

	if (priv->mm_proxy) {
		g_signal_handlers_disconnect_by_func (priv->mm_proxy, G_CALLBACK (mm_name_owner_changed), object);
		g_clear_object (&priv->mm_proxy);
	}

	modem_cleanup (NM_DEVICE_BT (object));
	g_clear_object (&priv->bt_device);

	G_OBJECT_CLASS (nm_device_bt_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (object);

	g_free (priv->rfcomm_iface);
	g_free (priv->name);
	g_free (priv->bdaddr);

	G_OBJECT_CLASS (nm_device_bt_parent_class)->finalize (object);
}

static void
nm_device_bt_class_init (NMDeviceBtClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMDeviceBtPrivate));

	object_class->constructed = constructed;
	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	device_class->get_generic_capabilities = get_generic_capabilities;
	device_class->can_auto_connect = can_auto_connect;
	device_class->deactivate = deactivate;
	device_class->act_stage2_config = act_stage2_config;
	device_class->act_stage3_ip4_config_start = act_stage3_ip4_config_start;
	device_class->act_stage3_ip6_config_start = act_stage3_ip6_config_start;
	device_class->check_connection_compatible = check_connection_compatible;
	device_class->check_connection_available = check_connection_available;
	device_class->complete_connection = complete_connection;
	device_class->is_available = is_available;
	device_class->component_added = component_added;

	device_class->state_changed = device_state_changed;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_BT_NAME,
		 g_param_spec_string (NM_DEVICE_BT_NAME, "", "",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_BT_CAPABILITIES,
		 g_param_spec_uint (NM_DEVICE_BT_CAPABILITIES, "", "",
		                    NM_BT_CAPABILITY_NONE, G_MAXUINT, NM_BT_CAPABILITY_NONE,
		                    G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_BT_DEVICE,
		 g_param_spec_object (NM_DEVICE_BT_DEVICE, "", "",
		                      NM_TYPE_BLUEZ_DEVICE,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                      G_PARAM_STATIC_STRINGS));

	/* Signals */
	signals[PPP_STATS] =
		g_signal_new ("ppp-stats",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMDeviceBtClass, ppp_stats),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 2,
		              G_TYPE_UINT, G_TYPE_UINT);

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (klass),
	                                        NMDBUS_TYPE_DEVICE_BLUETOOTH_SKELETON,
	                                        NULL);
}
