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
 * Copyright (C) 2009 - 2010 Red Hat, Inc.
 */

#include <stdio.h>
#include <string.h>
#include <net/ethernet.h>

#include "nm-glib-compat.h"
#include "nm-bluez-common.h"
#include "nm-dbus-manager.h"
#include "nm-device-bt.h"
#include "nm-device-interface.h"
#include "nm-device-private.h"
#include "nm-logging.h"
#include "nm-marshal.h"
#include "ppp-manager/nm-ppp-manager.h"
#include "nm-properties-changed-signal.h"
#include "nm-setting-connection.h"
#include "nm-setting-bluetooth.h"
#include "nm-setting-cdma.h"
#include "nm-setting-gsm.h"
#include "nm-device-bt-glue.h"
#include "NetworkManagerUtils.h"

#define BLUETOOTH_DUN_UUID "dun"
#define BLUETOOTH_NAP_UUID "nap"

G_DEFINE_TYPE (NMDeviceBt, nm_device_bt, NM_TYPE_DEVICE)

#define NM_DEVICE_BT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_BT, NMDeviceBtPrivate))

typedef struct {
	char *bdaddr;
	char *name;
	guint32 capabilities;

	gboolean connected;
	gboolean have_iface;

	DBusGProxy *type_proxy;
	DBusGProxy *dev_proxy;

	char *rfcomm_iface;
	NMModem *modem;
	guint32 timeout_id;

	guint32 bt_type;  /* BT type of the current connection */
} NMDeviceBtPrivate;

enum {
	PROP_0,
	PROP_HW_ADDRESS,
	PROP_BT_NAME,
	PROP_BT_CAPABILITIES,

	LAST_PROP
};

enum {
	PPP_STATS,
	PROPERTIES_CHANGED,

	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };


typedef enum {
	NM_BT_ERROR_CONNECTION_NOT_BT = 0,
	NM_BT_ERROR_CONNECTION_INVALID,
	NM_BT_ERROR_CONNECTION_INCOMPATIBLE,
} NMBtError;

#define NM_BT_ERROR (nm_bt_error_quark ())
#define NM_TYPE_BT_ERROR (nm_bt_error_get_type ())

static GQuark
nm_bt_error_quark (void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string ("nm-bt-error");
	return quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

static GType
nm_bt_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Connection was not a BT connection. */
			ENUM_ENTRY (NM_BT_ERROR_CONNECTION_NOT_BT, "ConnectionNotBt"),
			/* Connection was not a valid BT connection. */
			ENUM_ENTRY (NM_BT_ERROR_CONNECTION_INVALID, "ConnectionInvalid"),
			/* Connection does not apply to this device. */
			ENUM_ENTRY (NM_BT_ERROR_CONNECTION_INCOMPATIBLE, "ConnectionIncompatible"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("NMBtError", values);
	}
	return etype;
}


guint32 nm_device_bt_get_capabilities (NMDeviceBt *self)
{
	g_return_val_if_fail (self != NULL, NM_BT_CAPABILITY_NONE);
	g_return_val_if_fail (NM_IS_DEVICE_BT (self), NM_BT_CAPABILITY_NONE);

	return NM_DEVICE_BT_GET_PRIVATE (self)->capabilities;
}

const char *nm_device_bt_get_hw_address (NMDeviceBt *self)
{
	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (NM_IS_DEVICE_BT (self), NULL);

	return NM_DEVICE_BT_GET_PRIVATE (self)->bdaddr;
}

static guint32
get_connection_bt_type (NMConnection *connection)
{
	NMSettingBluetooth *s_bt;
	const char *bt_type;

	s_bt = (NMSettingBluetooth *) nm_connection_get_setting (connection, NM_TYPE_SETTING_BLUETOOTH);
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

static NMConnection *
real_get_best_auto_connection (NMDevice *device,
                               GSList *connections,
                               char **specific_object)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (device);
	GSList *iter;

	for (iter = connections; iter; iter = g_slist_next (iter)) {
		NMConnection *connection = NM_CONNECTION (iter->data);
		NMSettingConnection *s_con;
		guint32 bt_type;

		s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
		g_assert (s_con);

		if (!nm_setting_connection_get_autoconnect (s_con))
			continue;

		if (strcmp (nm_setting_connection_get_connection_type (s_con), NM_SETTING_BLUETOOTH_SETTING_NAME))
			continue;

		bt_type = get_connection_bt_type (connection);
		if (!(bt_type & priv->capabilities))
			continue;

		return connection;
	}
	return NULL;
}

static gboolean
real_check_connection_compatible (NMDevice *device,
                                  NMConnection *connection,
                                  GError **error)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (device);
	NMSettingConnection *s_con;
	NMSettingBluetooth *s_bt;
	const GByteArray *array;
	char *str;
	int addr_match = FALSE;
	guint32 bt_type;

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_con);

	if (strcmp (nm_setting_connection_get_connection_type (s_con), NM_SETTING_BLUETOOTH_SETTING_NAME)) {
		g_set_error (error,
		             NM_BT_ERROR, NM_BT_ERROR_CONNECTION_NOT_BT,
		             "The connection was not a Bluetooth connection.");
		return FALSE;
	}

	s_bt = NM_SETTING_BLUETOOTH (nm_connection_get_setting (connection, NM_TYPE_SETTING_BLUETOOTH));
	if (!s_bt) {
		g_set_error (error,
		             NM_BT_ERROR, NM_BT_ERROR_CONNECTION_INVALID,
		             "The connection was not a valid Bluetooth connection.");
		return FALSE;
	}

	array = nm_setting_bluetooth_get_bdaddr (s_bt);
	if (!array || (array->len != ETH_ALEN)) {
		g_set_error (error,
		             NM_BT_ERROR, NM_BT_ERROR_CONNECTION_INVALID,
		             "The connection did not contain a valid Bluetooth address.");
		return FALSE;
	}

	bt_type = get_connection_bt_type (connection);
	if (!(bt_type & priv->capabilities)) {
		g_set_error (error,
		             NM_BT_ERROR, NM_BT_ERROR_CONNECTION_INCOMPATIBLE,
		             "The connection was not compatible with the device's capabilities.");
		return FALSE;
	}

	str = g_strdup_printf ("%02X:%02X:%02X:%02X:%02X:%02X",
	                       array->data[0], array->data[1], array->data[2],
	                       array->data[3], array->data[4], array->data[5]);
	addr_match = !strcmp (priv->bdaddr, str);
	g_free (str);

	return addr_match;
}

static guint32
real_get_generic_capabilities (NMDevice *dev)
{
	return NM_DEVICE_CAP_NM_SUPPORTED;
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

	switch (nm_device_interface_get_state (NM_DEVICE_INTERFACE (device))) {
	case NM_DEVICE_STATE_PREPARE:
	case NM_DEVICE_STATE_CONFIG:
	case NM_DEVICE_STATE_NEED_AUTH:
	case NM_DEVICE_STATE_ACTIVATED:
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, reason);
		break;
	case NM_DEVICE_STATE_IP_CONFIG:
		if (nm_device_ip_config_should_fail (device, FALSE)) {
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
modem_need_auth (NMModem *modem,
	             const char *setting_name,
	             gboolean retry,
	             RequestSecretsCaller caller,
	             const char *hint1,
	             const char *hint2,
	             gpointer user_data)
{
	NMDeviceBt *self = NM_DEVICE_BT (user_data);
	NMActRequest *req;

	req = nm_device_get_act_request (NM_DEVICE (self));
	g_assert (req);

	nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_NEED_AUTH, NM_DEVICE_STATE_REASON_NONE);
	nm_act_request_get_secrets (req, setting_name, retry, caller, hint1, hint2);
}

static void
modem_prepare_result (NMModem *modem,
                      gboolean success,
                      NMDeviceStateReason reason,
                      gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);
	NMDeviceState state;

	state = nm_device_interface_get_state (NM_DEVICE_INTERFACE (device));
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
	} else
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, reason);
}

static void
device_state_changed (NMDevice *device,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason,
                      gpointer user_data)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (device);

	if (priv->modem)
		nm_modem_device_state_changed (priv->modem, new_state, old_state, reason);
}

static void
modem_ip4_config_result (NMModem *self,
                         const char *iface,
                         NMIP4Config *config,
                         GError *error,
                         gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);
	NMDeviceState state;

	state = nm_device_interface_get_state (NM_DEVICE_INTERFACE (device));
	g_return_if_fail (state == NM_DEVICE_STATE_IP_CONFIG);

	if (error) {
		nm_log_warn (LOGD_MB | LOGD_IP4 | LOGD_BT,
		             "(%s): retrieving IP4 configuration failed: (%d) %s",
		             nm_device_get_ip_iface (device),
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");

		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
	} else {
		if (iface)
			nm_device_set_ip_iface (device, iface);

		nm_device_activate_schedule_stage4_ip4_config_get (device);
	}
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

static void
real_connection_secrets_updated (NMDevice *device,
                                 NMConnection *connection,
                                 GSList *updated_settings,
                                 RequestSecretsCaller caller)
{
	NMDeviceBt *self = NM_DEVICE_BT (device);
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (self);
	NMActRequest *req;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;

	g_return_if_fail (IS_ACTIVATING_STATE (nm_device_get_state (device)));

	req = nm_device_get_act_request (device);
	g_assert (req);

	if (!nm_modem_connection_secrets_updated (priv->modem,
                                              req,
                                              connection,
                                              updated_settings,
                                              caller)) {
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_NO_SECRETS);
		return;
	}

	/* PPP handles stuff itself... */
	if (caller == SECRETS_CALLER_PPP)
		return;

	/* Otherwise, on success for GSM/CDMA secrets we need to schedule modem stage1 again */
	g_return_if_fail (nm_device_get_state (device) == NM_DEVICE_STATE_NEED_AUTH);
	if (!modem_stage1 (self, priv->modem, &reason))
		nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_FAILED, reason);
}

/*****************************************************************************/

gboolean
nm_device_bt_modem_added (NMDeviceBt *self,
                          NMModem *modem,
                          const char *driver)
{
	NMDeviceBtPrivate *priv;
	const char *modem_iface;
	char *base;
	NMDeviceState state;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (NM_IS_DEVICE_BT (self), FALSE);
	g_return_val_if_fail (modem != NULL, FALSE);
	g_return_val_if_fail (NM_IS_MODEM (modem), FALSE);

	priv = NM_DEVICE_BT_GET_PRIVATE (self);
	modem_iface = nm_modem_get_iface (modem);
	g_return_val_if_fail (modem_iface != NULL, FALSE);

	if (!priv->rfcomm_iface)
		return FALSE;

	base = g_path_get_basename (priv->rfcomm_iface);
	if (strcmp (base, modem_iface)) {
		g_free (base);
		return FALSE;
	}
	g_free (base);

	/* Got the modem */
	if (priv->timeout_id) {
		g_source_remove (priv->timeout_id);
		priv->timeout_id = 0;
	}

	/* Can only accept the modem in stage2, but since the interface matched
	 * what we were expecting, don't let anything else claim the modem either.
	 */
	state = nm_device_interface_get_state (NM_DEVICE_INTERFACE (self));
	if (state != NM_DEVICE_STATE_CONFIG) {
		nm_log_warn (LOGD_BT | LOGD_MB,
		             "(%s): modem found but device not in correct state (%d)",
		             nm_device_get_iface (NM_DEVICE (self)),
		             nm_device_get_state (NM_DEVICE (self)));
		return TRUE;
	}

	nm_log_info (LOGD_BT | LOGD_MB,
	             "Activation (%s/bluetooth) Stage 2 of 5 (Device Configure) modem found.",
	             nm_device_get_iface (NM_DEVICE (self)));

	if (priv->modem) {
		g_warn_if_reached ();
		g_object_unref (priv->modem);
	}

	priv->modem = g_object_ref (modem);
	g_signal_connect (modem, NM_MODEM_PPP_STATS, G_CALLBACK (ppp_stats), self);
	g_signal_connect (modem, NM_MODEM_PPP_FAILED, G_CALLBACK (ppp_failed), self);
	g_signal_connect (modem, NM_MODEM_PREPARE_RESULT, G_CALLBACK (modem_prepare_result), self);
	g_signal_connect (modem, NM_MODEM_IP4_CONFIG_RESULT, G_CALLBACK (modem_ip4_config_result), self);
	g_signal_connect (modem, NM_MODEM_NEED_AUTH, G_CALLBACK (modem_need_auth), self);

	/* Kick off the modem connection */
	if (!modem_stage1 (self, modem, &reason))
		nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_FAILED, reason);

	return TRUE;
}

gboolean
nm_device_bt_modem_removed (NMDeviceBt *self, NMModem *modem)
{
	NMDeviceBtPrivate *priv;
	NMDeviceState state;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (NM_IS_DEVICE_BT (self), FALSE);
	g_return_val_if_fail (modem != NULL, FALSE);
	g_return_val_if_fail (NM_IS_MODEM (modem), FALSE);

	priv = NM_DEVICE_BT_GET_PRIVATE (self);

	if (modem != priv->modem)
		return FALSE;

	state = nm_device_get_state (NM_DEVICE (self));
	nm_modem_device_state_changed (priv->modem,
	                               NM_DEVICE_STATE_DISCONNECTED,
	                               state,
	                               NM_DEVICE_STATE_REASON_USER_REQUESTED);

	g_object_unref (priv->modem);
	priv->modem = NULL;
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

	nm_log_info (LOGD_BT, "Activation (%s %s/bluetooth) Stage 2 of 5 (Device Configure) "
	             "successful.  Will connect via %s.",
	             nm_device_get_iface (device),
	             nm_device_get_ip_iface (device),
	             dun ? "DUN" : (pan ? "PAN" : "unknown"));

	/* Kill the connect timeout since we're connected now */
	if (priv->timeout_id) {
		g_source_remove (priv->timeout_id);
		priv->timeout_id = 0;
	}

	if (pan) {
		/* Bluez says we're connected now.  Start IP config. */
		nm_device_activate_schedule_stage3_ip_config_start (device);
	} else if (dun) {
		/* Wait for ModemManager to find the modem */
		priv->timeout_id = g_timeout_add_seconds (30, modem_find_timeout, self);

		nm_log_info (LOGD_BT | LOGD_MB, "Activation (%s/bluetooth) Stage 2 of 5 (Device Configure) "
		             "waiting for modem to appear.",
		             nm_device_get_iface (device));
	} else
		g_assert_not_reached ();
}

static void
bluez_connect_cb (DBusGProxy *proxy,
                  DBusGProxyCall *call_id,
                  void *user_data)
{
	NMDeviceBt *self = NM_DEVICE_BT (user_data);
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (self);
	GError *error = NULL;
	char *device;

	if (dbus_g_proxy_end_call (proxy, call_id, &error,
	                           G_TYPE_STRING, &device,
	                           G_TYPE_INVALID) == FALSE) {
		nm_log_warn (LOGD_BT, "Error connecting with bluez: %s",
		             error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);

		nm_device_state_changed (NM_DEVICE (self),
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_BT_FAILED);
		return;
	}

	if (!device || !strlen (device)) {
		nm_log_warn (LOGD_BT, "Invalid network device returned by bluez");

		nm_device_state_changed (NM_DEVICE (self),
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_BT_FAILED);
	}

	if (priv->bt_type == NM_BT_CAPABILITY_DUN) {
		g_free (priv->rfcomm_iface);
		priv->rfcomm_iface = device;
	} else if (priv->bt_type == NM_BT_CAPABILITY_NAP) {
		nm_device_set_ip_iface (NM_DEVICE (self), device);
		g_free (device);
	}

	nm_log_dbg (LOGD_BT, "(%s): connect request successful",
	            nm_device_get_iface (NM_DEVICE (self)));

	/* Stage 3 gets scheduled when Bluez says we're connected */
	priv->have_iface = TRUE;
	check_connect_continue (self);
}

static void
bluez_property_changed (DBusGProxy *proxy,
                        const char *property,
                        GValue *value,
                        gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);
	NMDeviceBt *self = NM_DEVICE_BT (user_data);
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (self);
	gboolean connected;
	NMDeviceState state;
	const char *prop_str = "(unknown)";

	if (G_VALUE_HOLDS_STRING (value))
		prop_str = g_value_get_string (value);
	else if (G_VALUE_HOLDS_BOOLEAN (value))
		prop_str = g_value_get_boolean (value) ? "true" : "false";

	nm_log_dbg (LOGD_BT, "(%s): bluez property '%s' changed to '%s'",
	            nm_device_get_iface (device),
	            property,
	            prop_str);

	if (strcmp (property, "Connected"))
		return;

	state = nm_device_get_state (device);
	connected = g_value_get_boolean (value);
	if (connected) {
		if (state == NM_DEVICE_STATE_CONFIG) {
			nm_log_dbg (LOGD_BT, "(%s): connected to the device",
			            nm_device_get_iface (device));

			priv->connected = TRUE;
			check_connect_continue (self);
		}
	} else {
		gboolean fail = FALSE;

		/* Bluez says we're disconnected from the device.  Suck. */

		if (nm_device_is_activating (device)) {
			nm_log_info (LOGD_BT,
			             "Activation (%s/bluetooth): bluetooth link disconnected.",
			             nm_device_get_iface (device));
			fail = TRUE;
		} else if (state == NM_DEVICE_STATE_ACTIVATED) {
			nm_log_info (LOGD_BT, "(%s): bluetooth link disconnected.",
			             nm_device_get_iface (device));
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

	nm_log_dbg (LOGD_BT, "(%s): initial connection timed out",
	            nm_device_get_iface (NM_DEVICE (self)));

	NM_DEVICE_BT_GET_PRIVATE (self)->timeout_id = 0;
	nm_device_state_changed (NM_DEVICE (self),
	                         NM_DEVICE_STATE_FAILED,
	                         NM_DEVICE_STATE_REASON_BT_FAILED);
	return FALSE;
}

static NMActStageReturn
real_act_stage2_config (NMDevice *device, NMDeviceStateReason *reason)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (device);
	NMActRequest *req;
	NMDBusManager *dbus_mgr;
	DBusGConnection *g_connection;
	gboolean dun = FALSE;

	req = nm_device_get_act_request (device);
	g_assert (req);

	priv->bt_type = get_connection_bt_type (nm_act_request_get_connection (req));
	if (priv->bt_type == NM_BT_CAPABILITY_NONE) {
		// FIXME: set a reason code
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	dbus_mgr = nm_dbus_manager_get ();
	g_connection = nm_dbus_manager_get_connection (dbus_mgr);
	g_object_unref (dbus_mgr);

	if (priv->bt_type == NM_BT_CAPABILITY_DUN)
		dun = TRUE;
	else if (priv->bt_type == NM_BT_CAPABILITY_NAP)
		dun = FALSE;
	else
		g_assert_not_reached ();

	priv->dev_proxy = dbus_g_proxy_new_for_name (g_connection,
	                                               BLUEZ_SERVICE,
	                                               nm_device_get_udi (device),
	                                               BLUEZ_DEVICE_INTERFACE);
	if (!priv->dev_proxy) {
		// FIXME: set a reason code
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	/* Watch for BT device property changes */
	dbus_g_object_register_marshaller (_nm_marshal_VOID__STRING_BOXED,
	                                   G_TYPE_NONE,
	                                   G_TYPE_STRING, G_TYPE_VALUE,
	                                   G_TYPE_INVALID);
	dbus_g_proxy_add_signal (priv->dev_proxy, "PropertyChanged",
	                         G_TYPE_STRING, G_TYPE_VALUE, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->dev_proxy, "PropertyChanged",
	                             G_CALLBACK (bluez_property_changed), device, NULL);

	priv->type_proxy = dbus_g_proxy_new_for_name (g_connection,
	                                              BLUEZ_SERVICE,
	                                              nm_device_get_udi (device),
	                                              dun ? BLUEZ_SERIAL_INTERFACE : BLUEZ_NETWORK_INTERFACE);
	if (!priv->type_proxy) {
		// FIXME: set a reason code
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	nm_log_dbg (LOGD_BT, "(%s): requesting connection to the device",
	            nm_device_get_iface (device));

	/* Connect to the BT device */
	dbus_g_proxy_begin_call_with_timeout (priv->type_proxy, "Connect",
	                                      bluez_connect_cb,
	                                      device,
	                                      NULL,
	                                      20000,
	                                      G_TYPE_STRING, dun ? BLUETOOTH_DUN_UUID : BLUETOOTH_NAP_UUID,
	                                      G_TYPE_INVALID);

	if (priv->timeout_id)
		g_source_remove (priv->timeout_id);
	priv->timeout_id = g_timeout_add_seconds (30, bt_connect_timeout, device);

	return NM_ACT_STAGE_RETURN_POSTPONE;
}

static NMActStageReturn
real_act_stage3_ip4_config_start (NMDevice *device, NMDeviceStateReason *reason)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (device);
	NMActStageReturn ret;

	if (priv->bt_type == NM_BT_CAPABILITY_DUN) {
		ret = nm_modem_stage3_ip4_config_start (NM_DEVICE_BT_GET_PRIVATE (device)->modem,
		                                        device,
		                                        NM_DEVICE_CLASS (nm_device_bt_parent_class),
		                                        reason);
	} else
		ret = NM_DEVICE_CLASS (nm_device_bt_parent_class)->act_stage3_ip4_config_start (device, reason);

	return ret;
}

static NMActStageReturn
real_act_stage4_get_ip4_config (NMDevice *device,
                                NMIP4Config **config,
                                NMDeviceStateReason *reason)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (device);
	NMActStageReturn ret;

	if (priv->bt_type == NM_BT_CAPABILITY_DUN) {
		ret = nm_modem_stage4_get_ip4_config (NM_DEVICE_BT_GET_PRIVATE (device)->modem,
		                                      device,
		                                      NM_DEVICE_CLASS (nm_device_bt_parent_class),
		                                      config,
		                                      reason);
	} else
		ret = NM_DEVICE_CLASS (nm_device_bt_parent_class)->act_stage4_get_ip4_config (device, config, reason);

	return ret;
}

static void
real_deactivate_quickly (NMDevice *device)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (device);

	priv->have_iface = FALSE;
	priv->connected = FALSE;

	if (priv->bt_type == NM_BT_CAPABILITY_DUN) {

		if (priv->modem) {
			nm_modem_deactivate_quickly (priv->modem, device);

			/* Since we're killing the Modem object before it'll get the
			 * state change signal, simulate the state change here.
			 */
			nm_modem_device_state_changed (priv->modem,
			                               NM_DEVICE_STATE_DISCONNECTED,
			                               NM_DEVICE_STATE_ACTIVATED,
			                               NM_DEVICE_STATE_REASON_USER_REQUESTED);
			g_object_unref (priv->modem);
			priv->modem = NULL;
		}

		if (priv->type_proxy) {
			/* Don't ever pass NULL through dbus; rfcomm_iface
			 * might happen to be NULL for some reason.
			 */
			if (priv->rfcomm_iface) {
				dbus_g_proxy_call_no_reply (priv->type_proxy, "Disconnect",
				                            G_TYPE_STRING, priv->rfcomm_iface,
				                            G_TYPE_INVALID);
			}
			g_object_unref (priv->type_proxy);
			priv->type_proxy = NULL;
		}
	} else if (priv->bt_type == NM_BT_CAPABILITY_NAP) {
		if (priv->type_proxy) {
			dbus_g_proxy_call_no_reply (priv->type_proxy, "Disconnect",
			                            G_TYPE_INVALID);
			g_object_unref (priv->type_proxy);
			priv->type_proxy = NULL;
		}
	}

	if (priv->dev_proxy) {
		g_object_unref (priv->dev_proxy);
		priv->dev_proxy = NULL;
	}

	if (priv->timeout_id) {
		g_source_remove (priv->timeout_id);
		priv->timeout_id = 0;
	}

	priv->bt_type = NM_BT_CAPABILITY_NONE;

	g_free (priv->rfcomm_iface);
	priv->rfcomm_iface = NULL;

	if (NM_DEVICE_CLASS (nm_device_bt_parent_class)->deactivate_quickly)
		NM_DEVICE_CLASS (nm_device_bt_parent_class)->deactivate_quickly (device);
}

/*****************************************************************************/

NMDevice *
nm_device_bt_new (const char *udi,
                  const char *bdaddr,
                  const char *name,
                  guint32 capabilities,
                  gboolean managed)
{
	NMDevice *device;

	g_return_val_if_fail (udi != NULL, NULL);
	g_return_val_if_fail (bdaddr != NULL, NULL);
	g_return_val_if_fail (name != NULL, NULL);
	g_return_val_if_fail (capabilities != NM_BT_CAPABILITY_NONE, NULL);

	device = (NMDevice *) g_object_new (NM_TYPE_DEVICE_BT,
	                                    NM_DEVICE_INTERFACE_UDI, udi,
	                                    NM_DEVICE_INTERFACE_IFACE, bdaddr,
	                                    NM_DEVICE_INTERFACE_DRIVER, "bluez",
	                                    NM_DEVICE_BT_HW_ADDRESS, bdaddr,
	                                    NM_DEVICE_BT_NAME, name,
	                                    NM_DEVICE_BT_CAPABILITIES, capabilities,
	                                    NM_DEVICE_INTERFACE_MANAGED, managed,
	                                    NM_DEVICE_INTERFACE_TYPE_DESC, "Bluetooth",
	                                    NM_DEVICE_INTERFACE_DEVICE_TYPE, NM_DEVICE_TYPE_BT,
	                                    NULL);
	if (device)
		g_signal_connect (device, "state-changed", G_CALLBACK (device_state_changed), device);

	return device;
}

static void
nm_device_bt_init (NMDeviceBt *self)
{
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_HW_ADDRESS:
		/* Construct only */
		priv->bdaddr = g_ascii_strup (g_value_get_string (value), -1);
		break;
	case PROP_BT_NAME:
		/* Construct only */
		priv->name = g_value_dup_string (value);
		break;
	case PROP_BT_CAPABILITIES:
		/* Construct only */
		priv->capabilities = g_value_get_uint (value);
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
	case PROP_HW_ADDRESS:
		g_value_set_string (value, priv->bdaddr);
		break;
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
finalize (GObject *object)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (object);

	if (priv->timeout_id) {
		g_source_remove (priv->timeout_id);
		priv->timeout_id = 0;
	}

	if (priv->type_proxy)
		g_object_unref (priv->type_proxy);

	if (priv->dev_proxy)
		g_object_unref (priv->dev_proxy);

	if (priv->modem)
		g_object_unref (priv->modem);

	g_free (priv->rfcomm_iface);
	g_free (priv->bdaddr);
	g_free (priv->name);

	G_OBJECT_CLASS (nm_device_bt_parent_class)->finalize (object);
}

static void
nm_device_bt_class_init (NMDeviceBtClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMDeviceBtPrivate));

	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->finalize = finalize;

	device_class->get_best_auto_connection = real_get_best_auto_connection;
	device_class->get_generic_capabilities = real_get_generic_capabilities;
	device_class->connection_secrets_updated = real_connection_secrets_updated;
	device_class->deactivate_quickly = real_deactivate_quickly;
	device_class->act_stage2_config = real_act_stage2_config;
	device_class->act_stage3_ip4_config_start = real_act_stage3_ip4_config_start;
	device_class->act_stage4_get_ip4_config = real_act_stage4_get_ip4_config;
	device_class->check_connection_compatible = real_check_connection_compatible;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_BT_HW_ADDRESS,
		                      "Bluetooth address",
		                      "Bluetooth address",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_BT_NAME,
		 g_param_spec_string (NM_DEVICE_BT_NAME,
		                      "Bluetooth device name",
		                      "Bluetooth device name",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_BT_CAPABILITIES,
		 g_param_spec_uint (NM_DEVICE_BT_CAPABILITIES,
		                    "Bluetooth device capabilities",
		                    "Bluetooth device capabilities",
		                    NM_BT_CAPABILITY_NONE, G_MAXUINT, NM_BT_CAPABILITY_NONE,
		                    G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	/* Signals */
	signals[PPP_STATS] =
		g_signal_new ("ppp-stats",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMDeviceBtClass, ppp_stats),
		              NULL, NULL,
		              _nm_marshal_VOID__UINT_UINT,
		              G_TYPE_NONE, 2,
		              G_TYPE_UINT, G_TYPE_UINT);

	signals[PROPERTIES_CHANGED] = 
		nm_properties_changed_signal_new (object_class,
		                                  G_STRUCT_OFFSET (NMDeviceBtClass, properties_changed));

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (klass),
	                                 &dbus_glib_nm_device_bt_object_info);

	dbus_g_error_domain_register (NM_BT_ERROR, NULL, NM_TYPE_BT_ERROR);
}
