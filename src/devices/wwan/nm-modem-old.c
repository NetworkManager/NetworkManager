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
 * Copyright (C) 2009 - 2013 Red Hat, Inc.
 * Copyright (C) 2009 Novell, Inc.
 */

#include <string.h>
#include <glib/gi18n.h>

#include "nm-modem-old.h"
#include "nm-dbus-manager.h"
#include "nm-setting-connection.h"
#include "nm-properties-changed-signal.h"
#include "nm-modem-old-types.h"
#include "nm-logging.h"
#include "NetworkManagerUtils.h"
#include "nm-device-private.h"
#include "nm-dbus-glib-types.h"
#include "nm-glib-compat.h"

G_DEFINE_TYPE (NMModemOld, nm_modem_old, NM_TYPE_MODEM)

#define NM_MODEM_OLD_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_MODEM_OLD, NMModemOldPrivate))

typedef struct {
	DBusGProxy *proxy;
	DBusGProxy *props_proxy;

	MMOldModemState state;
	NMDeviceModemCapabilities caps;
	char *unlock_required;

	DBusGProxyCall *call;
	GHashTable *connect_properties;

	guint32 pin_tries;
	guint enable_delay_id;
} NMModemOldPrivate;

#define CAPS_3GPP (NM_DEVICE_MODEM_CAPABILITY_GSM_UMTS | NM_DEVICE_MODEM_CAPABILITY_LTE)

/*****************************************************************************/

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
    MM_MODEM_GSM_ALLOWED_MODE_4G_PREFERRED = 5,
    MM_MODEM_GSM_ALLOWED_MODE_4G_ONLY      = 6,

    MM_MODEM_GSM_ALLOWED_MODE_LAST = MM_MODEM_GSM_ALLOWED_MODE_4G_ONLY
} MMModemGsmAllowedMode;

typedef enum {
	MM_MODEM_GSM_ALLOWED_AUTH_UNKNOWN  = 0x0000,
    /* bits 0..4 order match Ericsson device bitmap */
    MM_MODEM_GSM_ALLOWED_AUTH_NONE     = 0x0001,
    MM_MODEM_GSM_ALLOWED_AUTH_PAP      = 0x0002,
    MM_MODEM_GSM_ALLOWED_AUTH_CHAP     = 0x0004,
    MM_MODEM_GSM_ALLOWED_AUTH_MSCHAP   = 0x0008,
    MM_MODEM_GSM_ALLOWED_AUTH_MSCHAPV2 = 0x0010,
    MM_MODEM_GSM_ALLOWED_AUTH_EAP      = 0x0020,

    MM_MODEM_GSM_ALLOWED_AUTH_LAST = MM_MODEM_GSM_ALLOWED_AUTH_EAP
} MMModemGsmAllowedAuth;

static NMDeviceStateReason
translate_mm_error (GError *error)
{
	NMDeviceStateReason reason;

	if (dbus_g_error_has_name (error, MM_OLD_MODEM_CONNECT_ERROR_NO_CARRIER))
		reason = NM_DEVICE_STATE_REASON_MODEM_NO_CARRIER;
	else if (dbus_g_error_has_name (error, MM_OLD_MODEM_CONNECT_ERROR_NO_DIALTONE))
		reason = NM_DEVICE_STATE_REASON_MODEM_NO_DIAL_TONE;
	else if (dbus_g_error_has_name (error, MM_OLD_MODEM_CONNECT_ERROR_BUSY))
		reason = NM_DEVICE_STATE_REASON_MODEM_BUSY;
	else if (dbus_g_error_has_name (error, MM_OLD_MODEM_CONNECT_ERROR_NO_ANSWER))
		reason = NM_DEVICE_STATE_REASON_MODEM_DIAL_TIMEOUT;
	else if (dbus_g_error_has_name (error, MM_OLD_MODEM_ERROR_NETWORK_NOT_ALLOWED))
		reason = NM_DEVICE_STATE_REASON_GSM_REGISTRATION_DENIED;
	else if (dbus_g_error_has_name (error, MM_OLD_MODEM_ERROR_NETWORK_TIMEOUT))
		reason = NM_DEVICE_STATE_REASON_GSM_REGISTRATION_TIMEOUT;
	else if (dbus_g_error_has_name (error, MM_OLD_MODEM_ERROR_NO_NETWORK))
		reason = NM_DEVICE_STATE_REASON_GSM_REGISTRATION_NOT_SEARCHING;
	else if (dbus_g_error_has_name (error, MM_OLD_MODEM_ERROR_SIM_NOT_INSERTED))
		reason = NM_DEVICE_STATE_REASON_GSM_SIM_NOT_INSERTED;
	else if (dbus_g_error_has_name (error, MM_OLD_MODEM_ERROR_SIM_PIN))
		reason = NM_DEVICE_STATE_REASON_GSM_SIM_PIN_REQUIRED;
	else if (dbus_g_error_has_name (error, MM_OLD_MODEM_ERROR_SIM_PUK))
		reason = NM_DEVICE_STATE_REASON_GSM_SIM_PUK_REQUIRED;
	else if (dbus_g_error_has_name (error, MM_OLD_MODEM_ERROR_SIM_WRONG))
		reason = NM_DEVICE_STATE_REASON_GSM_SIM_WRONG;
	else if (dbus_g_error_has_name (error, MM_OLD_MODEM_ERROR_WRONG_PASSWORD))
		reason = NM_DEVICE_STATE_REASON_SIM_PIN_INCORRECT;
	else {
		/* unable to map the ModemManager error to a NM_DEVICE_STATE_REASON */
		nm_log_dbg (LOGD_MB, "unmapped dbus error detected: '%s'", dbus_g_error_get_name (error));
		reason = NM_DEVICE_STATE_REASON_UNKNOWN;
	}

	/* FIXME: We have only GSM error messages here, and we have no idea which
	   activation state failed. Reasons like:
	   NM_DEVICE_STATE_REASON_MODEM_DIAL_FAILED,
	   NM_DEVICE_STATE_REASON_MODEM_INIT_FAILED,
	   NM_DEVICE_STATE_REASON_GSM_APN_FAILED,
	   NM_DEVICE_STATE_REASON_GSM_REGISTRATION_FAILED,
	   NM_DEVICE_STATE_REASON_GSM_PIN_CHECK_FAILED
	   are not used.
	*/
	return reason;
}

#define MAP_STATE(name) case MM_OLD_MODEM_STATE_##name: return NM_MODEM_STATE_##name;

static NMModemState
mm_state_to_nm (MMOldModemState mm_state, const char *unlock_required)
{
	if (unlock_required && *unlock_required)
		return NM_MODEM_STATE_LOCKED;

	switch (mm_state) {
	MAP_STATE(UNKNOWN)
	MAP_STATE(DISABLED)
	MAP_STATE(DISABLING)
	MAP_STATE(ENABLING)
	MAP_STATE(ENABLED)
	MAP_STATE(SEARCHING)
	MAP_STATE(REGISTERED)
	MAP_STATE(DISCONNECTING)
	MAP_STATE(CONNECTING)
	MAP_STATE(CONNECTED)
	}
	return NM_MODEM_STATE_UNKNOWN;
};

/*****************************************************************************/

static DBusGProxy *
nm_modem_old_get_proxy (NMModemOld *self, const char *interface)
{

	NMModemOldPrivate *priv = NM_MODEM_OLD_GET_PRIVATE (self);
	const char *current_iface;

	g_return_val_if_fail (NM_IS_MODEM_OLD (self), NULL);

	/* Default to the default interface. */
	if (interface == NULL)
		interface = MM_OLD_DBUS_INTERFACE_MODEM;

	if (interface && !strcmp (interface, DBUS_INTERFACE_PROPERTIES))
		return priv->props_proxy;

	current_iface = dbus_g_proxy_get_interface (priv->proxy);
	if (!current_iface || strcmp (current_iface, interface))
		dbus_g_proxy_set_interface (priv->proxy, interface);

	return priv->proxy;
}

/*****************************************************************************/
/* Query/Update enabled state */

static void
set_mm_enabled_done (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	GError *error = NULL;

	if (!dbus_g_proxy_end_call (proxy, call_id, &error, G_TYPE_INVALID)) {
		nm_log_warn (LOGD_MB, "failed to enable/disable modem: (%d) %s",
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
		nm_modem_set_prev_state (NM_MODEM (user_data), "enable/disable failed");
	}
	/* Wait for the state change signal to indicate enabled state changed */
}

static void
set_mm_enabled (NMModem *self, gboolean enabled)
{
	dbus_g_proxy_begin_call (nm_modem_old_get_proxy (NM_MODEM_OLD (self), MM_OLD_DBUS_INTERFACE_MODEM),
	                         "Enable", set_mm_enabled_done,
	                         g_object_ref (self), g_object_unref,
	                         G_TYPE_BOOLEAN, enabled,
	                         G_TYPE_INVALID);
}

/*****************************************************************************/

static void
ask_for_pin (NMModemOld *self, gboolean always_ask)
{
	NMModemOldPrivate *priv = NM_MODEM_OLD_GET_PRIVATE (self);
	guint32 tries = 0;

	g_return_if_fail (NM_IS_MODEM_OLD (self));

	if (!always_ask)
		tries = priv->pin_tries++;

	nm_modem_get_secrets (NM_MODEM (self),
	                      NM_SETTING_GSM_SETTING_NAME,
	                      (tries || always_ask) ? TRUE : FALSE,
	                      NM_SETTING_GSM_PIN);
}

static void
stage1_prepare_done (DBusGProxy *proxy, DBusGProxyCall *call, gpointer user_data)
{
	NMModemOld *self = NM_MODEM_OLD (user_data);
	NMModemOldPrivate *priv = NM_MODEM_OLD_GET_PRIVATE (self);
	GError *error = NULL;
	gboolean asked = FALSE;

	priv->call = NULL;

	if (priv->connect_properties) {
		g_hash_table_destroy (priv->connect_properties);
		priv->connect_properties = NULL;
	}

	if (dbus_g_proxy_end_call (proxy, call, &error, G_TYPE_INVALID))
		g_signal_emit_by_name (self, NM_MODEM_PREPARE_RESULT, TRUE, NM_DEVICE_STATE_REASON_NONE);
	else {
		if (priv->caps & CAPS_3GPP) {
			if (dbus_g_error_has_name (error, MM_OLD_MODEM_ERROR_SIM_PIN)) {
				ask_for_pin (self, FALSE);
				asked = TRUE;
			} else if (dbus_g_error_has_name (error, MM_OLD_MODEM_ERROR_SIM_WRONG)) {
				ask_for_pin (self, TRUE);
				asked = TRUE;
			}
		}

		if (!asked) {
			nm_log_warn (LOGD_MB, "Mobile connection failed: (%d) %s",
					     error ? error->code : -1,
					     error && error->message ? error->message : "(unknown)");
			g_signal_emit_by_name (self, NM_MODEM_PREPARE_RESULT, FALSE, translate_mm_error (error));
		}
		g_error_free (error);
	}
}

static void
do_connect (NMModemOld *self)
{
	NMModemOldPrivate *priv = NM_MODEM_OLD_GET_PRIVATE (self);
	DBusGProxy *proxy;

	proxy = nm_modem_old_get_proxy (NM_MODEM_OLD (self), MM_OLD_DBUS_INTERFACE_MODEM_SIMPLE);
	priv->call = dbus_g_proxy_begin_call_with_timeout (proxy,
	                                                   "Connect", stage1_prepare_done,
	                                                   self, NULL, 120000,
	                                                   DBUS_TYPE_G_MAP_OF_VARIANT, priv->connect_properties,
	                                                   G_TYPE_INVALID);
}

static void stage1_enable_done (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data);

/* do_enable() is used as a GSourceFunc, hence the gboolean return */
static gboolean
do_enable (NMModemOld *self)
{
	DBusGProxy *proxy;

	g_return_val_if_fail (NM_IS_MODEM_OLD (self), FALSE);

	NM_MODEM_OLD_GET_PRIVATE (self)->enable_delay_id = 0;
	proxy = nm_modem_old_get_proxy (NM_MODEM_OLD (self), MM_OLD_DBUS_INTERFACE_MODEM);
	dbus_g_proxy_begin_call_with_timeout (proxy,
	                                      "Enable", stage1_enable_done,
	                                      self, NULL, 20000,
	                                      G_TYPE_BOOLEAN, TRUE,
	                                      G_TYPE_INVALID);
	return FALSE;
}

static void
stage1_pin_done (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMModemOld *self = NM_MODEM_OLD (user_data);
	NMModemOldPrivate *priv = NM_MODEM_OLD_GET_PRIVATE (self);
	NMDeviceStateReason reason;
	GError *error = NULL;

	if (dbus_g_proxy_end_call (proxy, call_id, &error, G_TYPE_INVALID)) {
		/* Success; try to enable the modem again.  Wait a few seconds to ensure
		 * that ModemManager is ready for the enable right after the unlock.
		 */
		if (priv->enable_delay_id == 0)
			priv->enable_delay_id = g_timeout_add_seconds (4, (GSourceFunc) do_enable, self);
	} else {
		nm_log_warn (LOGD_MB, "GSM PIN unlock failed: (%d) %s",
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");

		/* try to translate the error reason */
		reason = translate_mm_error (error);
		if (reason == NM_DEVICE_STATE_REASON_UNKNOWN)
			reason = NM_DEVICE_STATE_REASON_MODEM_INIT_FAILED;

		g_signal_emit_by_name (self, NM_MODEM_PREPARE_RESULT, FALSE, reason);
		g_error_free (error);
	}
}

static void
handle_enable_pin_required (NMModemOld *self)
{
	NMModemOldPrivate *priv = NM_MODEM_OLD_GET_PRIVATE (self);
	const char *pin = NULL;
	GValue *value;
	DBusGProxy *proxy;

	g_assert (priv->caps & CAPS_3GPP);

	/* See if we have a PIN already */
	value = g_hash_table_lookup (priv->connect_properties, "pin");
	if (value && G_VALUE_HOLDS_STRING (value))
		pin = g_value_get_string (value);

	/* If we do, send it */
	if (pin) {
		proxy = nm_modem_old_get_proxy (NM_MODEM_OLD (self), MM_OLD_DBUS_INTERFACE_MODEM_GSM_CARD);
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
	NMModemOld *self = NM_MODEM_OLD (user_data);
	NMModemOldPrivate *priv = NM_MODEM_OLD_GET_PRIVATE (self);
	NMDeviceStateReason reason;
	GError *error = NULL;

	if (dbus_g_proxy_end_call (proxy, call_id, &error, G_TYPE_INVALID))
		do_connect (self);
	else {
		if ((priv->caps & CAPS_3GPP) && dbus_g_error_has_name (error, MM_OLD_MODEM_ERROR_SIM_PIN))
			handle_enable_pin_required (self);
		else {
			nm_log_warn (LOGD_MB, "Modem enable failed: (%d) %s",
				         error ? error->code : -1,
				         error && error->message ? error->message : "(unknown)");

			/* try to translate the error reason */
			reason = translate_mm_error (error);
			if (reason == NM_DEVICE_STATE_REASON_UNKNOWN)
				reason = NM_DEVICE_STATE_REASON_MODEM_INIT_FAILED;
			g_signal_emit_by_name (self, NM_MODEM_PREPARE_RESULT, FALSE, reason);
		}

		g_error_free (error);
	}
}

static GHashTable *
create_connect_properties (NMConnection *connection)
{
	NMSettingCdma *s_cdma;
	NMSettingGsm *s_gsm;
	NMSettingPPP *s_ppp;
	GHashTable *properties;
	const char *str;

	properties = value_hash_create ();

	s_cdma = nm_connection_get_setting_cdma (connection);
	if (s_cdma) {
		str = nm_setting_cdma_get_number (s_cdma);
		if (str)
			value_hash_add_str (properties, "number", str);
		return properties;
	}

	s_gsm = nm_connection_get_setting_gsm (connection);
	if (s_gsm) {
		str = nm_setting_gsm_get_number (s_gsm);
		if (str)
			value_hash_add_str (properties, "number", str);

		str = nm_setting_gsm_get_apn (s_gsm);
		if (str)
			value_hash_add_str (properties, "apn", str);

		str = nm_setting_gsm_get_network_id (s_gsm);
		if (str)
			value_hash_add_str (properties, "network_id", str);

		str = nm_setting_gsm_get_pin (s_gsm);
		if (str)
			value_hash_add_str (properties, "pin", str);

		str = nm_setting_gsm_get_username (s_gsm);
		if (str)
			value_hash_add_str (properties, "username", str);

		str = nm_setting_gsm_get_password (s_gsm);
		if (str)
			value_hash_add_str (properties, "password", str);

G_GNUC_BEGIN_IGNORE_DEPRECATIONS
		/* Add both old and new preferred modes */
		switch (nm_setting_gsm_get_network_type (s_gsm)) {
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
		case NM_SETTING_GSM_NETWORK_TYPE_PREFER_4G:
			/* deprecated modes not extended for 4G, so no need to set them here */
			value_hash_add_uint (properties, "allowed_mode", MM_MODEM_GSM_ALLOWED_MODE_4G_PREFERRED);
			break;
		case NM_SETTING_GSM_NETWORK_TYPE_4G:
			/* deprecated modes not extended for 4G, so no need to set them here */
			value_hash_add_uint (properties, "allowed_mode", MM_MODEM_GSM_ALLOWED_MODE_4G_ONLY);
			break;
		default:
			value_hash_add_uint (properties, "network_mode", MM_MODEM_GSM_NETWORK_DEPRECATED_MODE_ANY);
			value_hash_add_uint (properties, "allowed_mode", MM_MODEM_GSM_ALLOWED_MODE_ANY);
			break;
		}
G_GNUC_END_IGNORE_DEPRECATIONS

		/* Roaming */
		if (nm_setting_gsm_get_home_only (s_gsm))
			value_hash_add_bool (properties, "home_only", TRUE);

		/* For IpMethod == STATIC or DHCP */
		s_ppp = nm_connection_get_setting_ppp (connection);
		if (s_ppp) {
			guint32 auth = MM_MODEM_GSM_ALLOWED_AUTH_UNKNOWN;

			if (nm_setting_ppp_get_noauth (s_ppp))
				auth |= MM_MODEM_GSM_ALLOWED_AUTH_NONE;
			if (!nm_setting_ppp_get_refuse_pap (s_ppp))
				auth |= MM_MODEM_GSM_ALLOWED_AUTH_PAP;
			if (!nm_setting_ppp_get_refuse_chap (s_ppp))
				auth |= MM_MODEM_GSM_ALLOWED_AUTH_CHAP;
			if (!nm_setting_ppp_get_refuse_mschap (s_ppp))
				auth |= MM_MODEM_GSM_ALLOWED_AUTH_MSCHAP;
			if (!nm_setting_ppp_get_refuse_mschapv2 (s_ppp))
				auth |= MM_MODEM_GSM_ALLOWED_AUTH_MSCHAPV2;
			if (!nm_setting_ppp_get_refuse_eap (s_ppp))
				auth |= MM_MODEM_GSM_ALLOWED_AUTH_EAP;

			if (auth != MM_MODEM_GSM_ALLOWED_AUTH_UNKNOWN)
				value_hash_add_uint (properties, "allowed_auth", auth);
		}

		return properties;
	}

	g_hash_table_destroy (properties);
	return NULL;
}

static NMActStageReturn
act_stage1_prepare (NMModem *modem,
                    NMConnection *connection,
                    NMDeviceStateReason *reason)
{
	NMModemOld *self = NM_MODEM_OLD (modem);
	NMModemOldPrivate *priv = NM_MODEM_OLD_GET_PRIVATE (self);

	if (priv->connect_properties)
		g_hash_table_destroy (priv->connect_properties);
	priv->connect_properties = create_connect_properties (connection);

	if (nm_modem_get_state (modem) >= NM_MODEM_STATE_ENABLING)
		do_connect (self);
	else
		do_enable (self);

	return NM_ACT_STAGE_RETURN_POSTPONE;
}

/*****************************************************************************/
/* IP method static */

static char addr_to_string_buf[INET6_ADDRSTRLEN + 1];

static const char *
ip_address_to_string (guint32 numeric)
{
	guint32 temp_addr;

	memset (&addr_to_string_buf, '\0', sizeof (addr_to_string_buf));
	temp_addr = numeric;

	if (inet_ntop (AF_INET, &temp_addr, addr_to_string_buf, INET_ADDRSTRLEN)) {
		return addr_to_string_buf;
	} else {
		nm_log_warn (LOGD_VPN, "error converting IP4 address 0x%X",
		             ntohl (temp_addr));
		return NULL;
	}
}

static void
static_stage3_done (DBusGProxy *proxy, DBusGProxyCall *call, gpointer user_data)
{
	NMModemOld *self = NM_MODEM_OLD (user_data);
	NMModemOldPrivate *priv = NM_MODEM_OLD_GET_PRIVATE (self);
	GValueArray *ret_array = NULL;
	GError *error = NULL;
	NMIP4Config *config = NULL;

	priv->call = NULL;

	/* Returned value array is (uuuu): [IP, DNS1, DNS2, DNS3], all in
	 * network byte order.
	 */
	if (dbus_g_proxy_end_call (proxy, call, &error,
	                           G_TYPE_VALUE_ARRAY, &ret_array,
	                           G_TYPE_INVALID)) {
		NMPlatformIP4Address address;
		int i;

		config = nm_ip4_config_new ();
		memset (&address, 0, sizeof (address));

		nm_log_info (LOGD_MB, "(%s): IPv4 static configuration:",
		             nm_modem_get_uid (NM_MODEM (self)));

		/* IP address */
		address.address = g_value_get_uint (g_value_array_get_nth (ret_array, 0));
		address.plen = 32;
		address.source = NM_PLATFORM_SOURCE_WWAN;
		nm_ip4_config_add_address (config, &address);

		nm_log_info (LOGD_MB, "  address %s/%d",
		             ip_address_to_string (address.address),
		             address.plen);

		/* DNS servers */
		for (i = 1; i < ret_array->n_values; i++) {
			GValue *value = g_value_array_get_nth (ret_array, i);
			guint32 tmp = g_value_get_uint (value);

			if (tmp > 0) {
				nm_ip4_config_add_nameserver (config, tmp);
				nm_log_info (LOGD_MB, "  DNS %s", ip_address_to_string (tmp));
			}
		}
		g_value_array_free (ret_array);
	}

	g_signal_emit_by_name (self, NM_MODEM_IP4_CONFIG_RESULT, config, error);
	g_clear_error (&error);
}

static NMActStageReturn
static_stage3_ip4_config_start (NMModem *self,
                                NMActRequest *req,
                                NMDeviceStateReason *reason)
{
	NMModemOldPrivate *priv;

	g_return_val_if_fail (NM_IS_MODEM (self), NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (NM_IS_ACT_REQUEST (req), NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (reason !=	NULL, NM_ACT_STAGE_RETURN_FAILURE);

	priv = NM_MODEM_OLD_GET_PRIVATE (self);

	priv->call = dbus_g_proxy_begin_call (nm_modem_old_get_proxy (NM_MODEM_OLD (self),
	                                                                  MM_OLD_DBUS_INTERFACE_MODEM),
	                                      "GetIP4Config", static_stage3_done,
	                                      self, NULL,
	                                      G_TYPE_INVALID);

	return NM_ACT_STAGE_RETURN_POSTPONE;
}

/*****************************************************************************/

static void
disconnect_done (DBusGProxy *proxy,
                 DBusGProxyCall *call_id,
                 gpointer user_data)
{
	GError *error = NULL;
	gboolean warn = GPOINTER_TO_UINT (user_data);

	if (!dbus_g_proxy_end_call (proxy, call_id, &error, G_TYPE_INVALID) && warn) {
		nm_log_info (LOGD_MB, "disconnect failed: (%d) %s",
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
	}
}

static void
disconnect (NMModem *self,
            gboolean warn)
{
	dbus_g_proxy_begin_call (nm_modem_old_get_proxy (NM_MODEM_OLD (self),
	                                                     MM_OLD_DBUS_INTERFACE_MODEM),
	                         "Disconnect",
	                         disconnect_done,
	                         GUINT_TO_POINTER (warn),
	                         NULL,
	                         G_TYPE_INVALID);
}

/*****************************************************************************/

static void
deactivate (NMModem *self, NMDevice *device)
{
	NMModemOldPrivate *priv = NM_MODEM_OLD_GET_PRIVATE (self);

	priv->pin_tries = 0;

	if (priv->call) {
		dbus_g_proxy_cancel_call (priv->proxy, priv->call);
		priv->call = NULL;
	}

	if (priv->enable_delay_id) {
		g_source_remove (priv->enable_delay_id);
		priv->enable_delay_id = 0;
	}

	/* Chain up parent */
	NM_MODEM_CLASS (nm_modem_old_parent_class)->deactivate (self, device);
}

/*****************************************************************************/

static void
modem_properties_changed (DBusGProxy *proxy,
                          const char *interface,
                          GHashTable *props,
                          gpointer user_data)
{
	NMModemOld *self = NM_MODEM_OLD (user_data);
	NMModemOldPrivate *priv = NM_MODEM_OLD_GET_PRIVATE (self);
	GValue *value;
	gboolean update_state = FALSE;

	if (strcmp (interface, MM_OLD_DBUS_INTERFACE_MODEM) &&
	    strcmp (interface, MM_OLD_DBUS_INTERFACE_MODEM_GSM_CARD))
		return;

	value = g_hash_table_lookup (props, "IpMethod");
	if (value && G_VALUE_HOLDS_UINT (value)) {
		g_object_set (self,
		              NM_MODEM_IP_METHOD, g_value_get_uint (value),
		              NULL);
	}

	value = g_hash_table_lookup (props, "SimIdentifier");
	if (value && G_VALUE_HOLDS_STRING (value)) {
		const char *sim_id = g_value_get_string (value);

		g_object_set (self,
		              NM_MODEM_SIM_ID, (sim_id && *sim_id) ? sim_id : NULL,
		              NULL);
	}

	value = g_hash_table_lookup (props, "UnlockRequired");
	if (value && G_VALUE_HOLDS_STRING (value)) {
		g_free (priv->unlock_required);
		priv->unlock_required = g_value_dup_string (value);
		update_state = TRUE;
	}

	value = g_hash_table_lookup (props, "State");
	if (value && G_VALUE_HOLDS_UINT (value)) {
		priv->state = g_value_get_uint (value);
		update_state = TRUE;
	}

	if (update_state) {
		nm_modem_set_state (NM_MODEM (self),
		                    mm_state_to_nm (priv->state, priv->unlock_required),
		                    NULL);
	}
}

/*****************************************************************************/

static gboolean
check_connection_compatible (NMModem *modem, NMConnection *connection)
{
	NMModemOldPrivate *priv = NM_MODEM_OLD_GET_PRIVATE (modem);
	NMSettingConnection *s_con;
	gboolean valid_cdma = FALSE, valid_gsm = FALSE;
	const char *ctype;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	ctype = nm_setting_connection_get_connection_type (s_con);
	g_assert (ctype);

	/* Check for valid CDMA first */
	if (strcmp (ctype, NM_SETTING_CDMA_SETTING_NAME) == 0)
		valid_cdma = !!nm_connection_get_setting_cdma (connection);

	if (strcmp (ctype, NM_SETTING_GSM_SETTING_NAME) == 0)
		valid_gsm = !!nm_connection_get_setting_gsm (connection);

	/* Validate CDMA */
	if (priv->caps & NM_DEVICE_MODEM_CAPABILITY_CDMA_EVDO) {
		if (valid_cdma)
			return TRUE;

		/* If the modem is only CDMA and the connection is not CDMA, error */
		if ((priv->caps ^ NM_DEVICE_MODEM_CAPABILITY_CDMA_EVDO) == 0)
			return FALSE;
	}

	/* Validate 3GPP */
	if (priv->caps & CAPS_3GPP)
		return valid_gsm;

	return FALSE;
}

/*****************************************************************************/

static void
complete_ppp_setting (NMConnection *connection)
{
	NMSettingPPP *s_ppp;

	s_ppp = nm_connection_get_setting_ppp (connection);
	if (!s_ppp) {
		s_ppp = (NMSettingPPP *) nm_setting_ppp_new ();
		g_object_set (G_OBJECT (s_ppp),
		              NM_SETTING_PPP_LCP_ECHO_FAILURE, 5,
		              NM_SETTING_PPP_LCP_ECHO_INTERVAL, 30,
		              NULL);
		nm_connection_add_setting (connection, NM_SETTING (s_ppp));
	}
}

static gboolean
complete_connection_3gpp (NMConnection *connection,
                          const GSList *existing_connections,
                          GError **error)
{
	NMSettingGsm *s_gsm;

	s_gsm = nm_connection_get_setting_gsm (connection);
	if (!s_gsm || !nm_setting_gsm_get_apn (s_gsm)) {
		/* Need an APN at least */
		g_set_error_literal (error,
		                     NM_SETTING_GSM_ERROR,
		                     NM_SETTING_GSM_ERROR_MISSING_PROPERTY,
		                     NM_SETTING_GSM_APN);
		return FALSE;
	}

	if (!nm_setting_gsm_get_number (s_gsm))
		g_object_set (G_OBJECT (s_gsm), NM_SETTING_GSM_NUMBER, "*99#", NULL);

	complete_ppp_setting (connection);

	nm_utils_complete_generic (connection,
	                           NM_SETTING_GSM_SETTING_NAME,
	                           existing_connections,
	                           _("GSM connection %d"),
	                           NULL,
	                           FALSE); /* No IPv6 yet by default */
	return TRUE;
}

static gboolean
complete_connection_cdma (NMConnection *connection,
                          const GSList *existing_connections,
                          GError **error)
{
	NMSettingCdma *s_cdma;

	s_cdma = nm_connection_get_setting_cdma (connection);
	if (!s_cdma) {
		s_cdma = (NMSettingCdma *) nm_setting_cdma_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_cdma));
	}

	if (!nm_setting_cdma_get_number (s_cdma))
		g_object_set (G_OBJECT (s_cdma), NM_SETTING_CDMA_NUMBER, "#777", NULL);

	complete_ppp_setting (connection);

	nm_utils_complete_generic (connection,
	                           NM_SETTING_CDMA_SETTING_NAME,
	                           existing_connections,
	                           _("CDMA connection %d"),
	                           NULL,
	                           FALSE); /* No IPv6 yet by default */
	return TRUE;
}

static gboolean
complete_connection (NMModem *modem,
                     NMConnection *connection,
                     const GSList *existing_connections,
                     GError **error)
{
	NMModemOldPrivate *priv = NM_MODEM_OLD_GET_PRIVATE (modem);

	/* If the modem has LTE, complete as 3GPP */
	if (priv->caps & NM_DEVICE_MODEM_CAPABILITY_LTE)
		return complete_connection_3gpp (connection, existing_connections, error);

	/* Otherwise, prefer CDMA on the theory that if the modem has CDMA/EVDO
	 * that's most likely what the user will be using.
	 */
	if (priv->caps & NM_DEVICE_MODEM_CAPABILITY_CDMA_EVDO)
		return complete_connection_cdma (connection, existing_connections, error);

	if (priv->caps & NM_DEVICE_MODEM_CAPABILITY_GSM_UMTS)
		return complete_connection_3gpp (connection, existing_connections, error);

	g_set_error_literal (error, NM_MODEM_ERROR, NM_MODEM_ERROR_CONNECTION_INCOMPATIBLE,
	                     "Modem had no WWAN capabilities.");
	return FALSE;
}

/*****************************************************************************/

static gboolean
get_user_pass (NMModem *modem,
               NMConnection *connection,
               const char **user,
               const char **pass)
{
	NMModemOldPrivate *priv = NM_MODEM_OLD_GET_PRIVATE (modem);
	NMSettingCdma *s_cdma;
	NMSettingGsm *s_gsm;

	if (priv->caps & NM_DEVICE_MODEM_CAPABILITY_CDMA_EVDO) {
		s_cdma = nm_connection_get_setting_cdma (connection);
		if (s_cdma) {
			if (user)
				*user = nm_setting_cdma_get_username (s_cdma);
			if (pass)
				*pass = nm_setting_cdma_get_password (s_cdma);
			return TRUE;
		}
	}

	/* Fall back to GSM; will be used for CDMA devices on LTE networks too */
	s_gsm = nm_connection_get_setting_gsm (connection);
	if (s_gsm) {
		if (user)
			*user = nm_setting_gsm_get_username (s_gsm);
		if (pass)
			*pass = nm_setting_gsm_get_password (s_gsm);
		return TRUE;
	}

	return FALSE;
}

/*****************************************************************************/

static void
get_capabilities (NMModem *_self,
                  NMDeviceModemCapabilities *modem_caps,
                  NMDeviceModemCapabilities *current_caps)
{
	NMModemOld *self = NM_MODEM_OLD (_self);

	*current_caps = *modem_caps = NM_MODEM_OLD_GET_PRIVATE (self)->caps;
}

/*****************************************************************************/

NMModem *
nm_modem_old_new (const char *path, GHashTable *properties, GError **error)
{
	NMDeviceModemCapabilities caps = NM_DEVICE_MODEM_CAPABILITY_NONE;
	NMModemOld *self;
	GHashTableIter iter;
	const char *prop;
	GValue *value;
	const char *data_device = NULL;
	const char *driver = NULL;
	const char *master_device = NULL;
	const char *unlock_required = NULL;
	const char *device_id = NULL;
	guint32 modem_type = MM_OLD_MODEM_TYPE_UNKNOWN;
	guint32 ip_method = MM_MODEM_IP_METHOD_PPP;
	guint32 ip_timeout = 0;
	MMOldModemState state = MM_OLD_MODEM_STATE_UNKNOWN;

	g_return_val_if_fail (path != NULL, NULL);
	g_return_val_if_fail (properties != NULL, NULL);

	g_hash_table_iter_init (&iter, properties);
	while (g_hash_table_iter_next (&iter, (gpointer) &prop, (gpointer) &value)) {
		if (g_strcmp0 (prop, "Type") == 0)
			modem_type = g_value_get_uint (value);
		else if (g_strcmp0 (prop, "MasterDevice") == 0)
			master_device = g_value_get_string (value);
		else if (g_strcmp0 (prop, "IpMethod") == 0)
			ip_method = g_value_get_uint (value);
		else if (g_strcmp0 (prop, "Device") == 0)
			data_device = g_value_get_string (value);
		else if (g_strcmp0 (prop, "Driver") == 0)
			driver = g_value_get_string (value);
		else if (g_strcmp0 (prop, "IpTimeout") == 0)
			ip_timeout = g_value_get_uint (value);
		else if (g_strcmp0 (prop, "State") == 0)
			state = g_value_get_uint (value);
		else if (g_strcmp0 (prop, "UnlockRequired") == 0)
			unlock_required = g_value_get_string (value);
		else if (g_strcmp0 (prop, "DeviceIdentifier") == 0)
			device_id = g_value_get_string (value);
	}

	if (modem_type == MM_OLD_MODEM_TYPE_UNKNOWN) {
		g_set_error (error, NM_MODEM_ERROR, NM_MODEM_ERROR_INITIALIZATION_FAILED,
		             "Unhandled modem type %d", modem_type);
		return NULL;
	}

	if (!master_device || !strlen (master_device)) {
		g_set_error_literal (error, NM_MODEM_ERROR, NM_MODEM_ERROR_INITIALIZATION_FAILED,
		                     "Failed to retrieve modem master device.");
		return NULL;
	}

	if (!driver || !strlen (driver)) {
		g_set_error_literal (error, NM_MODEM_ERROR, NM_MODEM_ERROR_INITIALIZATION_FAILED,
		                     "Failed to retrieve modem driver.");
		return NULL;
	}

	if (!data_device || !strlen (data_device)) {
		g_set_error_literal (error, NM_MODEM_ERROR, NM_MODEM_ERROR_INITIALIZATION_FAILED,
		                     "Failed to retrieve modem data device.");
		return NULL;
	}

	self = (NMModemOld *) g_object_new (NM_TYPE_MODEM_OLD,
	                                    NM_MODEM_PATH, path,
	                                    NM_MODEM_DRIVER, driver,
	                                    NM_MODEM_UID, data_device,
	                                    NM_MODEM_CONTROL_PORT, NULL,
	                                    NM_MODEM_DATA_PORT, data_device,
	                                    NM_MODEM_IP_METHOD, ip_method,
	                                    NM_MODEM_IP_TIMEOUT, ip_timeout,
	                                    NM_MODEM_DEVICE_ID, device_id,
	                                    NM_MODEM_STATE, mm_state_to_nm (state, unlock_required),
	                                    NULL);
	if (self) {
		if (modem_type == MM_OLD_MODEM_TYPE_CDMA)
			caps |= NM_DEVICE_MODEM_CAPABILITY_CDMA_EVDO;
		if (modem_type == MM_OLD_MODEM_TYPE_GSM)
			caps |= NM_DEVICE_MODEM_CAPABILITY_GSM_UMTS;

		NM_MODEM_OLD_GET_PRIVATE (self)->caps = caps;
		NM_MODEM_OLD_GET_PRIVATE (self)->state = state;
		NM_MODEM_OLD_GET_PRIVATE (self)->unlock_required = g_strdup (unlock_required);
	}

	return (NMModem *) self;
}

static void
nm_modem_old_init (NMModemOld *self)
{
}

static void
get_sim_id_done (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMModemOld *self = NM_MODEM_OLD (user_data);
	GValue value = G_VALUE_INIT;

	if (dbus_g_proxy_end_call (proxy, call_id, NULL, G_TYPE_VALUE, &value, G_TYPE_INVALID)) {
		if (G_VALUE_HOLDS_STRING (&value)) {
			const char *sim_id = g_value_get_string (&value);

			if (sim_id && *sim_id)
				g_object_set (G_OBJECT (self), NM_MODEM_SIM_ID, sim_id, NULL);
		}
		g_value_unset (&value);
	}
}

static GObject*
constructor (GType type,
			 guint n_construct_params,
			 GObjectConstructParam *construct_params)
{
	GObject *object;
	NMModemOldPrivate *priv;
	DBusGConnection *bus;

	object = G_OBJECT_CLASS (nm_modem_old_parent_class)->constructor (type, n_construct_params, construct_params);
	if (!object)
		return NULL;

	priv = NM_MODEM_OLD_GET_PRIVATE (object);

	bus = nm_dbus_manager_get_connection (nm_dbus_manager_get ());
	priv->proxy = dbus_g_proxy_new_for_name (bus,
	                                         MM_OLD_DBUS_SERVICE,
	                                         nm_modem_get_path (NM_MODEM (object)),
	                                         MM_OLD_DBUS_INTERFACE_MODEM);

	priv->props_proxy = dbus_g_proxy_new_for_name (bus,
	                                               MM_OLD_DBUS_SERVICE,
	                                               nm_modem_get_path (NM_MODEM (object)),
	                                               DBUS_INTERFACE_PROPERTIES);
	dbus_g_object_register_marshaller (g_cclosure_marshal_generic,
	                                   G_TYPE_NONE,
	                                   G_TYPE_STRING, DBUS_TYPE_G_MAP_OF_VARIANT,
	                                   G_TYPE_INVALID);
	dbus_g_proxy_add_signal (priv->props_proxy, "MmPropertiesChanged",
	                         G_TYPE_STRING, DBUS_TYPE_G_MAP_OF_VARIANT,
	                         G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->props_proxy, "MmPropertiesChanged",
	                             G_CALLBACK (modem_properties_changed),
	                             object,
	                             NULL);

	/* Request the SIM ID */
	dbus_g_proxy_begin_call (priv->props_proxy,
	                         "Get",
	                         get_sim_id_done,
	                         g_object_ref (object), g_object_unref,
	                         G_TYPE_STRING, MM_OLD_DBUS_INTERFACE_MODEM_GSM_CARD,
	                         G_TYPE_STRING, "SimIdentifier",
	                         G_TYPE_INVALID);

	return object;
}

static void
dispose (GObject *object)
{
	NMModemOldPrivate *priv = NM_MODEM_OLD_GET_PRIVATE (object);

	if (priv->proxy) {
		g_object_unref (priv->proxy);
		priv->proxy = NULL;
	}

	if (priv->props_proxy) {
		g_object_unref (priv->props_proxy);
		priv->props_proxy = NULL;
	}

	if (priv->connect_properties) {
		g_hash_table_destroy (priv->connect_properties);
		priv->connect_properties = NULL;
	}

	if (priv->enable_delay_id) {
		g_source_remove (priv->enable_delay_id);
		priv->enable_delay_id = 0;
	}

	g_free (priv->unlock_required);
	priv->unlock_required = NULL;

	G_OBJECT_CLASS (nm_modem_old_parent_class)->dispose (object);
}

static void
nm_modem_old_class_init (NMModemOldClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMModemClass *modem_class = NM_MODEM_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMModemOldPrivate));

	/* Virtual methods */
	object_class->constructor = constructor;
	object_class->dispose = dispose;

	modem_class->get_capabilities = get_capabilities;
	modem_class->get_user_pass = get_user_pass;
	modem_class->complete_connection = complete_connection;
	modem_class->check_connection_compatible = check_connection_compatible;
	modem_class->act_stage1_prepare = act_stage1_prepare;
	modem_class->static_stage3_ip4_config_start = static_stage3_ip4_config_start;
	modem_class->disconnect = disconnect;
	modem_class->deactivate = deactivate;
	modem_class->set_mm_enabled = set_mm_enabled;
}
