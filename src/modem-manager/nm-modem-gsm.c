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
 * Copyright (C) 2009 Novell, Inc.
 */

#include <string.h>
#include "nm-dbus-glib-types.h"
#include "nm-modem-gsm.h"
#include "nm-device.h"
#include "nm-setting-connection.h"
#include "nm-setting-gsm.h"
#include "nm-modem-types.h"
#include "nm-logging.h"
#include "NetworkManagerUtils.h"

typedef enum {
    MM_MODEM_GSM_NETWORK_DEPRECATED_MODE_ANY = 0,
    MM_MODEM_GSM_NETWORK_DEPRECATED_MODE_GPRS,
    MM_MODEM_GSM_NETWORK_DEPRECATED_MODE_EDGE,
    MM_MODEM_GSM_NETWORK_DEPRECATED_MODE_UMTS,
    MM_MODEM_GSM_NETWORK_DEPRECATED_MODE_HSDPA,
    MM_MODEM_GSM_NETWORK_DEPRECATED_MODE_2G_PREFERRED,
    MM_MODEM_GSM_NETWORK_DEPRECATED_MODE_3G_PREFERRED,
    MM_MODEM_GSM_NETWORK_DEPRECATED_MODE_2G_ONLY,
    MM_MODEM_GSM_NETWORK_DEPRECATED_MODE_3G_ONLY,
    MM_MODEM_GSM_NETWORK_DEPRECATED_MODE_HSUPA,
    MM_MODEM_GSM_NETWORK_DEPRECATED_MODE_HSPA,

    MM_MODEM_GSM_NETWORK_DEPRECATED_MODE_LAST = MM_MODEM_GSM_NETWORK_DEPRECATED_MODE_HSPA
} MMModemDeprecatedMode;

typedef enum {
    MM_MODEM_GSM_ALLOWED_MODE_ANY          = 0,
    MM_MODEM_GSM_ALLOWED_MODE_2G_PREFERRED = 1,
    MM_MODEM_GSM_ALLOWED_MODE_3G_PREFERRED = 2,
    MM_MODEM_GSM_ALLOWED_MODE_2G_ONLY      = 3,
    MM_MODEM_GSM_ALLOWED_MODE_3G_ONLY      = 4,

    MM_MODEM_GSM_ALLOWED_MODE_LAST = MM_MODEM_GSM_ALLOWED_MODE_3G_ONLY
} MMModemGsmAllowedMode;


G_DEFINE_TYPE (NMModemGsm, nm_modem_gsm, NM_TYPE_MODEM)

#define NM_MODEM_GSM_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_MODEM_GSM, NMModemGsmPrivate))

typedef struct {
	DBusGProxyCall *call;

	GHashTable *connect_properties;
	guint32 pin_tries;
} NMModemGsmPrivate;


typedef enum {
	NM_GSM_ERROR_CONNECTION_NOT_GSM = 0,
	NM_GSM_ERROR_CONNECTION_INVALID,
	NM_GSM_ERROR_CONNECTION_INCOMPATIBLE,
} NMGsmError;

#define NM_GSM_ERROR (nm_gsm_error_quark ())
#define NM_TYPE_GSM_ERROR (nm_gsm_error_get_type ())

static GQuark
nm_gsm_error_quark (void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string ("nm-gsm-error");
	return quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

static GType
nm_gsm_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Connection was not a GSM connection. */
			ENUM_ENTRY (NM_GSM_ERROR_CONNECTION_NOT_GSM, "ConnectionNotGsm"),
			/* Connection was not a valid GSM connection. */
			ENUM_ENTRY (NM_GSM_ERROR_CONNECTION_INVALID, "ConnectionInvalid"),
			/* Connection does not apply to this device. */
			ENUM_ENTRY (NM_GSM_ERROR_CONNECTION_INCOMPATIBLE, "ConnectionIncompatible"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("NMGsmError", values);
	}
	return etype;
}


NMModem *
nm_modem_gsm_new (const char *path,
                  const char *device,
                  const char *data_device,
                  guint32 ip_method)
{
	g_return_val_if_fail (path != NULL, NULL);
	g_return_val_if_fail (device != NULL, NULL);
	g_return_val_if_fail (data_device != NULL, NULL);

	return (NMModem *) g_object_new (NM_TYPE_MODEM_GSM,
	                                 NM_MODEM_PATH, path,
	                                 NM_MODEM_DEVICE, device,
	                                 NM_MODEM_IFACE, data_device,
	                                 NM_MODEM_IP_METHOD, ip_method,
	                                 NULL);
}

static NMDeviceStateReason
translate_mm_error (GError *error)
{
	NMDeviceStateReason reason;

	if (dbus_g_error_has_name (error, MM_MODEM_CONNECT_ERROR_NO_CARRIER))
		reason = NM_DEVICE_STATE_REASON_MODEM_NO_CARRIER;
	if (dbus_g_error_has_name (error, MM_MODEM_CONNECT_ERROR_NO_DIALTONE))
		reason = NM_DEVICE_STATE_REASON_MODEM_DIAL_TIMEOUT;
	if (dbus_g_error_has_name (error, MM_MODEM_CONNECT_ERROR_BUSY))
		reason = NM_DEVICE_STATE_REASON_MODEM_BUSY;
	if (dbus_g_error_has_name (error, MM_MODEM_CONNECT_ERROR_NO_ANSWER))
		reason = NM_DEVICE_STATE_REASON_MODEM_DIAL_TIMEOUT;
	if (dbus_g_error_has_name (error, MM_MODEM_ERROR_NETWORK_NOT_ALLOWED))
		reason = NM_DEVICE_STATE_REASON_GSM_REGISTRATION_DENIED;
	if (dbus_g_error_has_name (error, MM_MODEM_ERROR_NETWORK_TIMEOUT))
		reason = NM_DEVICE_STATE_REASON_GSM_REGISTRATION_TIMEOUT;
	if (dbus_g_error_has_name (error, MM_MODEM_ERROR_NO_NETWORK))
		reason = NM_DEVICE_STATE_REASON_GSM_REGISTRATION_NOT_SEARCHING;

	/* FIXME: We have only GSM error messages here, and we have no idea which 
	   activation state failed. Reasons like:
	   NM_DEVICE_STATE_REASON_MODEM_DIAL_FAILED,
	   NM_DEVICE_STATE_REASON_MODEM_INIT_FAILED,
	   NM_DEVICE_STATE_REASON_GSM_APN_FAILED,
	   NM_DEVICE_STATE_REASON_GSM_REGISTRATION_FAILED,
	   NM_DEVICE_STATE_REASON_GSM_PIN_CHECK_FAILED
	   are not used.
	*/
	else
		reason = NM_DEVICE_STATE_REASON_UNKNOWN;

	return reason;
}

static void
ask_for_pin (NMModemGsm *self, gboolean always_ask)
{
	NMModemGsmPrivate *priv;
	guint32 tries = 0;

	g_return_if_fail (self != NULL);
	g_return_if_fail (NM_IS_MODEM_GSM (self));

	priv = NM_MODEM_GSM_GET_PRIVATE (self);

	if (!always_ask)
		tries = priv->pin_tries++;

	g_signal_emit_by_name (self, NM_MODEM_NEED_AUTH,
	                       NM_SETTING_GSM_SETTING_NAME,
	                       (tries || always_ask) ? TRUE : FALSE,
	                       SECRETS_CALLER_MOBILE_BROADBAND,
	                       NM_SETTING_GSM_PIN,
	                       NULL);
}

static void
stage1_prepare_done (DBusGProxy *proxy, DBusGProxyCall *call, gpointer user_data)
{
	NMModemGsm *self = NM_MODEM_GSM (user_data);
	NMModemGsmPrivate *priv = NM_MODEM_GSM_GET_PRIVATE (self);
	GError *error = NULL;

	priv->call = NULL;

	if (priv->connect_properties) {
		g_hash_table_destroy (priv->connect_properties);
		priv->connect_properties = NULL;
	}

	if (dbus_g_proxy_end_call (proxy, call, &error, G_TYPE_INVALID))
		g_signal_emit_by_name (self, NM_MODEM_PREPARE_RESULT, TRUE, NM_DEVICE_STATE_REASON_NONE);
	else {
		if (dbus_g_error_has_name (error, MM_MODEM_ERROR_SIM_PIN))
			ask_for_pin (self, FALSE);
		else if (dbus_g_error_has_name (error, MM_MODEM_ERROR_SIM_WRONG))
			ask_for_pin (self, TRUE);
		else {
			nm_log_warn (LOGD_MB, "GSM connection failed: (%d) %s",
			             error ? error->code : -1,
			             error && error->message ? error->message : "(unknown)");

			g_signal_emit_by_name (self, NM_MODEM_PREPARE_RESULT, FALSE, translate_mm_error (error));
		}

		g_error_free (error);
	}
}

static void
do_connect (NMModemGsm *self)
{
	NMModemGsmPrivate *priv = NM_MODEM_GSM_GET_PRIVATE (self);
	DBusGProxy *proxy;

	proxy = nm_modem_get_proxy (NM_MODEM (self), MM_DBUS_INTERFACE_MODEM_SIMPLE);
	dbus_g_proxy_begin_call_with_timeout (proxy,
	                                      "Connect", stage1_prepare_done,
	                                      self, NULL, 120000,
	                                      DBUS_TYPE_G_MAP_OF_VARIANT, priv->connect_properties,
	                                      G_TYPE_INVALID);
}

static void stage1_enable_done (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data);

static void
do_enable (NMModemGsm *self)
{
	DBusGProxy *proxy;

	g_return_if_fail (self != NULL);
	g_return_if_fail (NM_IS_MODEM_GSM (self));

	proxy = nm_modem_get_proxy (NM_MODEM (self), MM_DBUS_INTERFACE_MODEM);
	dbus_g_proxy_begin_call_with_timeout (proxy,
	                                      "Enable", stage1_enable_done,
	                                      self, NULL, 20000,
	                                      G_TYPE_BOOLEAN, TRUE,
	                                      G_TYPE_INVALID);
}

static void
stage1_pin_done (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMModemGsm *self = NM_MODEM_GSM (user_data);
	GError *error = NULL;

	if (dbus_g_proxy_end_call (proxy, call_id, &error, G_TYPE_INVALID)) {
		/* Success; go back and try the enable again */
		do_enable (self);
	} else {
		nm_log_warn (LOGD_MB, "GSM PIN unlock failed: (%d) %s",
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
		g_error_free (error);

		g_signal_emit_by_name (self, NM_MODEM_PREPARE_RESULT, FALSE, NM_DEVICE_STATE_REASON_MODEM_INIT_FAILED);
	}
}

static void
handle_enable_pin_required (NMModemGsm *self)
{
	NMModemGsmPrivate *priv = NM_MODEM_GSM_GET_PRIVATE (self);
	const char *pin = NULL;
	GValue *value;
	DBusGProxy *proxy;

	/* See if we have a PIN already */
	value = g_hash_table_lookup (priv->connect_properties, "pin");
	if (value && G_VALUE_HOLDS_STRING (value))
		pin = g_value_get_string (value);

	/* If we do, send it */
	if (pin) {
		proxy = nm_modem_get_proxy (NM_MODEM (self), MM_DBUS_INTERFACE_MODEM_GSM_CARD);
		dbus_g_proxy_begin_call_with_timeout (proxy,
		                                      "SendPin", stage1_pin_done,
		                                      self, NULL, 10000,
		                                      G_TYPE_STRING, pin,
		                                      G_TYPE_INVALID);
	} else
		ask_for_pin (self, FALSE);
}

static void
stage1_enable_done (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMModemGsm *self = NM_MODEM_GSM (user_data);
	GError *error = NULL;

	if (dbus_g_proxy_end_call (proxy, call_id, &error, G_TYPE_INVALID))
		do_connect (self);
	else {
		nm_log_warn (LOGD_MB, "GSM modem enable failed: (%d) %s",
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");

		if (dbus_g_error_has_name (error, MM_MODEM_ERROR_SIM_PIN))
			handle_enable_pin_required (self);
		else
			g_signal_emit_by_name (self, NM_MODEM_PREPARE_RESULT, FALSE, NM_DEVICE_STATE_REASON_MODEM_INIT_FAILED);

		g_error_free (error);
	}
}


static GHashTable *
create_connect_properties (NMConnection *connection)
{
	NMSettingGsm *setting;
	GHashTable *properties;
	const char *str;

	setting = NM_SETTING_GSM (nm_connection_get_setting (connection, NM_TYPE_SETTING_GSM));
	properties = value_hash_create ();

	str = nm_setting_gsm_get_number (setting);
	if (str)
		value_hash_add_str (properties, "number", str);

	str = nm_setting_gsm_get_apn (setting);
	if (str)
		value_hash_add_str (properties, "apn", str);

	str = nm_setting_gsm_get_network_id (setting);
	if (str)
		value_hash_add_str (properties, "network_id", str);

	str = nm_setting_gsm_get_pin (setting);
	if (str)
		value_hash_add_str (properties, "pin", str);

	str = nm_setting_gsm_get_username (setting);
	if (str)
		value_hash_add_str (properties, "username", str);

	str = nm_setting_gsm_get_password (setting);
	if (str)
		value_hash_add_str (properties, "password", str);

	/* Add both old and new preferred modes */
	switch (nm_setting_gsm_get_network_type (setting)) {
	case NM_SETTING_GSM_NETWORK_TYPE_UMTS_HSPA:
		value_hash_add_uint (properties, "network_mode", MM_MODEM_GSM_NETWORK_DEPRECATED_MODE_3G_ONLY);
		value_hash_add_uint (properties, "allowed_mode", MM_MODEM_GSM_ALLOWED_MODE_3G_ONLY);
		break;
	case NM_SETTING_GSM_NETWORK_TYPE_GPRS_EDGE:
		value_hash_add_uint (properties, "network_mode", MM_MODEM_GSM_NETWORK_DEPRECATED_MODE_2G_ONLY);
		value_hash_add_uint (properties, "allowed_mode", MM_MODEM_GSM_ALLOWED_MODE_2G_ONLY);
		break;
	case NM_SETTING_GSM_NETWORK_TYPE_PREFER_UMTS_HSPA:
		value_hash_add_uint (properties, "network_mode", MM_MODEM_GSM_NETWORK_DEPRECATED_MODE_3G_PREFERRED);
		value_hash_add_uint (properties, "allowed_mode", MM_MODEM_GSM_ALLOWED_MODE_3G_PREFERRED);
		break;
	case NM_SETTING_GSM_NETWORK_TYPE_PREFER_GPRS_EDGE:
		value_hash_add_uint (properties, "network_mode", MM_MODEM_GSM_NETWORK_DEPRECATED_MODE_2G_PREFERRED);
		value_hash_add_uint (properties, "allowed_mode", MM_MODEM_GSM_ALLOWED_MODE_2G_PREFERRED);
		break;
	default:
		value_hash_add_uint (properties, "network_mode", MM_MODEM_GSM_NETWORK_DEPRECATED_MODE_ANY);
		value_hash_add_uint (properties, "allowed_mode", MM_MODEM_GSM_ALLOWED_MODE_ANY);
		break;
	}

	/* Roaming */
	if (nm_setting_gsm_get_home_only (setting))
		value_hash_add_bool (properties, "home_only", TRUE);

	return properties;
}

static NMActStageReturn
real_act_stage1_prepare (NMModem *modem,
                         NMActRequest *req,
                         GPtrArray **out_hints,
                         const char **out_setting_name,
                         NMDeviceStateReason *reason)
{
	NMModemGsm *self = NM_MODEM_GSM (modem);
	NMModemGsmPrivate *priv = NM_MODEM_GSM_GET_PRIVATE (self);
	NMConnection *connection;

	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	*out_setting_name = nm_connection_need_secrets (connection, out_hints);
	if (!*out_setting_name) {
		gboolean enabled = nm_modem_get_mm_enabled (modem);

		if (priv->connect_properties)
			g_hash_table_destroy (priv->connect_properties);
		priv->connect_properties = create_connect_properties (connection);

		if (enabled)
			do_connect (self);
		else
			do_enable (self);
	} else {
		/* NMModem will handle requesting secrets... */
	}

	return NM_ACT_STAGE_RETURN_POSTPONE;
}

static NMConnection *
real_get_best_auto_connection (NMModem *modem,
							   GSList *connections,
							   char **specific_object)
{
	GSList *iter;

	for (iter = connections; iter; iter = g_slist_next (iter)) {
		NMConnection *connection = NM_CONNECTION (iter->data);
		NMSettingConnection *s_con;

		s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
		g_assert (s_con);

		if (!nm_setting_connection_get_autoconnect (s_con))
			continue;

		if (strcmp (nm_setting_connection_get_connection_type (s_con), NM_SETTING_GSM_SETTING_NAME))
			continue;

		return connection;
	}
	return NULL;
}

static gboolean
real_check_connection_compatible (NMModem *modem,
                                  NMConnection *connection,
                                  GError **error)
{
	NMSettingConnection *s_con;
	NMSettingGsm *s_gsm;

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_con);

	if (strcmp (nm_setting_connection_get_connection_type (s_con), NM_SETTING_GSM_SETTING_NAME)) {
		g_set_error (error,
		             NM_GSM_ERROR, NM_GSM_ERROR_CONNECTION_NOT_GSM,
		             "The connection was not a GSM connection.");
		return FALSE;
	}

	s_gsm = NM_SETTING_GSM (nm_connection_get_setting (connection, NM_TYPE_SETTING_GSM));
	if (!s_gsm) {
		g_set_error (error,
		             NM_GSM_ERROR, NM_GSM_ERROR_CONNECTION_INVALID,
		             "The connection was not a valid GSM connection.");
		return FALSE;
	}

	return TRUE;
}

static gboolean
real_get_user_pass (NMModem *modem,
                    NMConnection *connection,
                    const char **user,
                    const char **pass)
{
	NMSettingGsm *s_gsm;

	s_gsm = (NMSettingGsm *) nm_connection_get_setting (connection, NM_TYPE_SETTING_GSM);
	if (!s_gsm)
		return FALSE;

	if (user)
		*user = nm_setting_gsm_get_username (s_gsm);
	if (pass)
		*pass = nm_setting_gsm_get_password (s_gsm);

	return TRUE;
}

static const char *
real_get_setting_name (NMModem *modem)
{
	return NM_SETTING_GSM_SETTING_NAME;
}

static void
real_deactivate_quickly (NMModem *modem, NMDevice *device)
{
	NMModemGsmPrivate *priv = NM_MODEM_GSM_GET_PRIVATE (modem);

	if (priv->call) {
		DBusGProxy *proxy;

		proxy = nm_modem_get_proxy (modem, MM_DBUS_INTERFACE_MODEM_SIMPLE);
		dbus_g_proxy_cancel_call (proxy, priv->call);
		priv->call = NULL;
	}

	priv->pin_tries = 0;

	NM_MODEM_CLASS (nm_modem_gsm_parent_class)->deactivate_quickly (modem, device);	
}


/*****************************************************************************/

static void
nm_modem_gsm_init (NMModemGsm *self)
{
}

static void
dispose (GObject *object)
{
	NMModemGsm *self = NM_MODEM_GSM (object);
	NMModemGsmPrivate *priv = NM_MODEM_GSM_GET_PRIVATE (self);

	if (priv->connect_properties)
		g_hash_table_destroy (priv->connect_properties);

	G_OBJECT_CLASS (nm_modem_gsm_parent_class)->dispose (object);
}

static void
nm_modem_gsm_class_init (NMModemGsmClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMModemClass *modem_class = NM_MODEM_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMModemGsmPrivate));

	/* Virtual methods */
	object_class->dispose = dispose;
	modem_class->get_user_pass = real_get_user_pass;
	modem_class->get_setting_name = real_get_setting_name;
	modem_class->get_best_auto_connection = real_get_best_auto_connection;
	modem_class->check_connection_compatible = real_check_connection_compatible;
	modem_class->act_stage1_prepare = real_act_stage1_prepare;
	modem_class->deactivate_quickly = real_deactivate_quickly;

	dbus_g_error_domain_register (NM_GSM_ERROR, NULL, NM_TYPE_GSM_ERROR);
}
