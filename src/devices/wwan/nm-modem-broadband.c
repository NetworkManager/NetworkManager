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
 * Copyright (C) 2012 Aleksander Morgado <aleksander@gnu.org>
 */

#include <glib/gi18n.h>
#include <string.h>
#include <libmm-glib.h>
#include "nm-modem-broadband.h"
#include "nm-setting-connection.h"
#include "nm-logging.h"
#include "NetworkManagerUtils.h"
#include "nm-device-private.h"

G_DEFINE_TYPE (NMModemBroadband, nm_modem_broadband, NM_TYPE_MODEM)

struct _NMModemBroadbandPrivate {
	/* The modem object from dbus */
	MMObject *modem_object;
	/* Per-interface objects */
	MMModem *modem_iface;
	MMModemSimple *simple_iface;

	/* Connection setup */
	MMSimpleConnectProperties *connect_properties;
	MMBearer *bearer;
	MMBearerIpConfig *ipv4_config;
	MMBearerIpConfig *ipv6_config;

	guint32 pin_tries;
};

enum {
	PROP_0,
	PROP_MODEM,
};

#define MODEM_CAPS_3GPP(caps) (caps & (MM_MODEM_CAPABILITY_GSM_UMTS |    \
                                       MM_MODEM_CAPABILITY_LTE |         \
                                       MM_MODEM_CAPABILITY_LTE_ADVANCED))

#define MODEM_CAPS_3GPP2(caps) (caps & (MM_MODEM_CAPABILITY_CDMA_EVDO))

/* Maximum time to keep the DBus call waiting for a connection result */
#define MODEM_CONNECT_TIMEOUT_SECS 120

/*****************************************************************************/

static NMDeviceStateReason
translate_mm_error (GError *error)
{
	NMDeviceStateReason reason;

	g_return_val_if_fail (error != NULL, NM_DEVICE_STATE_REASON_UNKNOWN);

	if (g_error_matches (error, MM_CONNECTION_ERROR, MM_CONNECTION_ERROR_NO_CARRIER))
		reason = NM_DEVICE_STATE_REASON_MODEM_NO_CARRIER;
	else if (g_error_matches (error, MM_CONNECTION_ERROR, MM_CONNECTION_ERROR_NO_DIALTONE))
		reason = NM_DEVICE_STATE_REASON_MODEM_NO_DIAL_TONE;
	else if (g_error_matches (error, MM_CONNECTION_ERROR, MM_CONNECTION_ERROR_BUSY))
		reason = NM_DEVICE_STATE_REASON_MODEM_BUSY;
	else if (g_error_matches (error, MM_CONNECTION_ERROR, MM_CONNECTION_ERROR_NO_ANSWER))
		reason = NM_DEVICE_STATE_REASON_MODEM_DIAL_TIMEOUT;
	else if (g_error_matches (error, MM_MOBILE_EQUIPMENT_ERROR, MM_MOBILE_EQUIPMENT_ERROR_NETWORK_NOT_ALLOWED))
		reason = NM_DEVICE_STATE_REASON_GSM_REGISTRATION_DENIED;
	else if (g_error_matches (error, MM_MOBILE_EQUIPMENT_ERROR, MM_MOBILE_EQUIPMENT_ERROR_NETWORK_TIMEOUT))
		reason = NM_DEVICE_STATE_REASON_GSM_REGISTRATION_TIMEOUT;
	else if (g_error_matches (error, MM_MOBILE_EQUIPMENT_ERROR, MM_MOBILE_EQUIPMENT_ERROR_NO_NETWORK))
		reason = NM_DEVICE_STATE_REASON_GSM_REGISTRATION_NOT_SEARCHING;
	else if (g_error_matches (error, MM_MOBILE_EQUIPMENT_ERROR, MM_MOBILE_EQUIPMENT_ERROR_SIM_NOT_INSERTED))
		reason = NM_DEVICE_STATE_REASON_GSM_SIM_NOT_INSERTED;
	else if (g_error_matches (error, MM_MOBILE_EQUIPMENT_ERROR, MM_MOBILE_EQUIPMENT_ERROR_SIM_PIN))
		reason = NM_DEVICE_STATE_REASON_GSM_SIM_PIN_REQUIRED;
	else if (g_error_matches (error, MM_MOBILE_EQUIPMENT_ERROR, MM_MOBILE_EQUIPMENT_ERROR_SIM_PUK))
		reason = NM_DEVICE_STATE_REASON_GSM_SIM_PUK_REQUIRED;
	else if (g_error_matches (error, MM_MOBILE_EQUIPMENT_ERROR, MM_MOBILE_EQUIPMENT_ERROR_SIM_WRONG))
		reason = NM_DEVICE_STATE_REASON_GSM_SIM_WRONG;
	else if (g_error_matches (error, MM_MOBILE_EQUIPMENT_ERROR, MM_MOBILE_EQUIPMENT_ERROR_INCORRECT_PASSWORD))
		reason = NM_DEVICE_STATE_REASON_SIM_PIN_INCORRECT;
	else {
		/* unable to map the ModemManager error to a NM_DEVICE_STATE_REASON */
		nm_log_dbg (LOGD_MB, "unmapped error detected: '%s'", error->message);
		reason = NM_DEVICE_STATE_REASON_UNKNOWN;
	}

	return reason;
}

/*****************************************************************************/

static void
get_capabilities (NMModem *_self,
                  NMDeviceModemCapabilities *modem_caps,
                  NMDeviceModemCapabilities *current_caps)
{
	NMModemBroadband *self = NM_MODEM_BROADBAND (_self);
	MMModemCapability all_supported = MM_MODEM_CAPABILITY_NONE;
	MMModemCapability *supported;
	guint n_supported;

	/* For now, we don't care about the capability combinations, just merge all
	 * combinations in a single mask */
	if (mm_modem_get_supported_capabilities (self->priv->modem_iface, &supported, &n_supported)) {
		guint i;

		for (i = 0; i < n_supported; i++)
			all_supported |= supported[i];

		g_free (supported);
	}

	*modem_caps = (NMDeviceModemCapabilities) all_supported;
	*current_caps = (NMDeviceModemCapabilities) mm_modem_get_current_capabilities (self->priv->modem_iface);
}

static gboolean
owns_port (NMModem *_self, const char *iface)
{
	NMModemBroadband *self = NM_MODEM_BROADBAND (_self);
	const MMModemPortInfo *ports = NULL;
	guint n_ports = 0, i;
	gboolean owns = FALSE;

	mm_modem_peek_ports (self->priv->modem_iface, &ports, &n_ports);
	for (i = 0; i < n_ports && !owns; i++)
		owns = (g_strcmp0 (iface, ports[i].name) == 0);
	return owns;
}

/*****************************************************************************/

static void
ask_for_pin (NMModemBroadband *self)
{
	guint32 tries;

	tries = self->priv->pin_tries++;
	nm_modem_get_secrets (NM_MODEM (self),
	                      NM_SETTING_GSM_SETTING_NAME,
	                      tries ? TRUE : FALSE,
	                      NM_SETTING_GSM_PIN);
}

static void
connect_ready (MMModemSimple *simple_iface,
               GAsyncResult *res,
               NMModemBroadband *self)
{
	GError *error = NULL;
	guint ip_method;

	g_clear_object (&self->priv->connect_properties);

	self->priv->bearer = mm_modem_simple_connect_finish (simple_iface, res, &error);
	if (!self->priv->bearer) {
		if (g_error_matches (error,
		                     MM_MOBILE_EQUIPMENT_ERROR,
		                     MM_MOBILE_EQUIPMENT_ERROR_SIM_PIN) ||
			(g_error_matches (error,
		                          MM_CORE_ERROR,
		                          MM_CORE_ERROR_UNAUTHORIZED) &&
			 mm_modem_get_unlock_required (self->priv->modem_iface) == MM_MODEM_LOCK_SIM_PIN)) {
			/* Request PIN */
			ask_for_pin (self);
		} else {
			/* Strip remote error info before logging it */
			if (g_dbus_error_is_remote_error (error))
				g_dbus_error_strip_remote_error (error);

			nm_log_warn (LOGD_MB, "(%s) failed to connect modem: %s",
			             nm_modem_get_uid (NM_MODEM (self)),
			             error && error->message ? error->message : "(unknown)");
			g_signal_emit_by_name (self, NM_MODEM_PREPARE_RESULT, FALSE, translate_mm_error (error));
		}

		g_clear_error (&error);
		g_object_unref (self);
		return;
	}

	/* Grab IP configurations */
	self->priv->ipv4_config = mm_bearer_get_ipv4_config (self->priv->bearer);
	self->priv->ipv6_config = mm_bearer_get_ipv6_config (self->priv->bearer);

	switch (mm_bearer_ip_config_get_method (self->priv->ipv4_config)) {
	case MM_BEARER_IP_METHOD_PPP:
		ip_method = MM_MODEM_IP_METHOD_PPP;
		break;
	case MM_BEARER_IP_METHOD_STATIC:
		ip_method = MM_MODEM_IP_METHOD_STATIC;
		break;
	case MM_BEARER_IP_METHOD_DHCP:
		ip_method = MM_MODEM_IP_METHOD_DHCP;
		break;
	default:
		error = g_error_new (NM_MODEM_ERROR,
		                     NM_MODEM_ERROR_CONNECTION_INVALID,
		                     "invalid IP config");
		nm_log_warn (LOGD_MB, "(%s) failed to connect modem: %s",
		             nm_modem_get_uid (NM_MODEM (self)),
		             error->message);
		g_signal_emit_by_name (self, NM_MODEM_PREPARE_RESULT, FALSE, translate_mm_error (error));
		g_error_free (error);
		g_object_unref (self);
		return;
	}

	/* IPv4 for now only */
	g_object_set (self,
	              NM_MODEM_DATA_PORT,  mm_bearer_get_interface (self->priv->bearer),
	              NM_MODEM_IP_METHOD,  ip_method,
	              NM_MODEM_IP_TIMEOUT, mm_bearer_get_ip_timeout (self->priv->bearer),
	              NULL);

	g_signal_emit_by_name (self, NM_MODEM_PREPARE_RESULT, TRUE, NM_DEVICE_STATE_REASON_NONE);
	g_object_unref (self);
}

static MMSimpleConnectProperties *
create_cdma_connect_properties (NMConnection *connection)
{
	NMSettingCdma *setting;
	MMSimpleConnectProperties *properties;
	const gchar *str;

	setting = nm_connection_get_setting_cdma (connection);
	properties = mm_simple_connect_properties_new ();

	str = nm_setting_cdma_get_number (setting);
	if (str)
		mm_simple_connect_properties_set_number (properties, str);

	return properties;
}

static MMSimpleConnectProperties *
create_gsm_connect_properties (NMConnection *connection)
{
	NMSettingGsm *setting;
	NMSettingPPP *s_ppp;
	MMSimpleConnectProperties *properties;
	const gchar *str;

	setting = nm_connection_get_setting_gsm (connection);
	properties = mm_simple_connect_properties_new ();

	/* TODO: not needed */
	str = nm_setting_gsm_get_number (setting);
	if (str)
		mm_simple_connect_properties_set_number (properties, str);

	str = nm_setting_gsm_get_apn (setting);
	if (str)
		mm_simple_connect_properties_set_apn (properties, str);

	str = nm_setting_gsm_get_network_id (setting);
	if (str)
		mm_simple_connect_properties_set_operator_id (properties, str);

	str = nm_setting_gsm_get_pin (setting);
	if (str)
		mm_simple_connect_properties_set_pin (properties, str);

	str = nm_setting_gsm_get_username (setting);
	if (str)
		mm_simple_connect_properties_set_user (properties, str);

	str = nm_setting_gsm_get_password (setting);
	if (str)
		mm_simple_connect_properties_set_password (properties, str);

	/* Roaming */
	if (nm_setting_gsm_get_home_only (setting))
		mm_simple_connect_properties_set_allow_roaming (properties, FALSE);

	/* For IpMethod == STATIC or DHCP */
	s_ppp = nm_connection_get_setting_ppp (connection);
	if (s_ppp) {
		MMBearerAllowedAuth allowed_auth = MM_BEARER_ALLOWED_AUTH_UNKNOWN;

		if (nm_setting_ppp_get_noauth (s_ppp))
			allowed_auth = MM_BEARER_ALLOWED_AUTH_NONE;
		if (!nm_setting_ppp_get_refuse_pap (s_ppp))
			allowed_auth |= MM_BEARER_ALLOWED_AUTH_PAP;
		if (!nm_setting_ppp_get_refuse_chap (s_ppp))
			allowed_auth |= MM_BEARER_ALLOWED_AUTH_CHAP;
		if (!nm_setting_ppp_get_refuse_mschap (s_ppp))
			allowed_auth |= MM_BEARER_ALLOWED_AUTH_MSCHAP;
		if (!nm_setting_ppp_get_refuse_mschapv2 (s_ppp))
			allowed_auth |= MM_BEARER_ALLOWED_AUTH_MSCHAPV2;
		if (!nm_setting_ppp_get_refuse_eap (s_ppp))
			allowed_auth |= MM_BEARER_ALLOWED_AUTH_EAP;

		mm_simple_connect_properties_set_allowed_auth (properties, allowed_auth);
	}

	return properties;
}

static NMActStageReturn
act_stage1_prepare (NMModem *_self,
                    NMConnection *connection,
                    NMDeviceStateReason *reason)
{
	NMModemBroadband *self = NM_MODEM_BROADBAND (_self);
	MMModemCapability caps;

	g_clear_object (&self->priv->connect_properties);

	caps = mm_modem_get_current_capabilities (self->priv->modem_iface);
	if (MODEM_CAPS_3GPP (caps))
		self->priv->connect_properties = create_gsm_connect_properties (connection);
	else if (MODEM_CAPS_3GPP2 (caps))
		self->priv->connect_properties = create_cdma_connect_properties (connection);
	else {
		nm_log_warn (LOGD_MB, "(%s) not a mobile broadband modem",
					 nm_modem_get_uid (NM_MODEM (self)));
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	if (!self->priv->simple_iface)
		self->priv->simple_iface = mm_object_get_modem_simple (self->priv->modem_object);

	g_dbus_proxy_set_default_timeout (G_DBUS_PROXY (self->priv->simple_iface), MODEM_CONNECT_TIMEOUT_SECS * 1000);
	mm_modem_simple_connect (self->priv->simple_iface,
	                         self->priv->connect_properties,
	                         NULL,
	                         (GAsyncReadyCallback)connect_ready,
	                         g_object_ref (self));

	return NM_ACT_STAGE_RETURN_POSTPONE;
}

/*****************************************************************************/

static gboolean
check_connection_compatible (NMModem *_self, NMConnection *connection)
{
	NMModemBroadband *self = NM_MODEM_BROADBAND (_self);
	MMModemCapability modem_caps;
	NMSettingConnection *s_con;

	modem_caps = mm_modem_get_current_capabilities (self->priv->modem_iface);
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	if (MODEM_CAPS_3GPP (modem_caps)) {
		NMSettingGsm *s_gsm;

		if (!g_str_equal (nm_setting_connection_get_connection_type (s_con),
		                  NM_SETTING_GSM_SETTING_NAME))
			return FALSE;

		s_gsm = nm_connection_get_setting_gsm (connection);
		if (!s_gsm)
			return FALSE;

		return TRUE;
	}

	if (MODEM_CAPS_3GPP2 (modem_caps)) {
		NMSettingCdma *s_cdma;

		if (!g_str_equal (nm_setting_connection_get_connection_type (s_con),
		                  NM_SETTING_CDMA_SETTING_NAME))
			return FALSE;

		s_cdma = nm_connection_get_setting_cdma (connection);
		if (!s_cdma)
			return FALSE;

		return TRUE;
	}

	return FALSE;
}

/*****************************************************************************/

static gboolean
complete_connection (NMModem *_self,
                     NMConnection *connection,
                     const GSList *existing_connections,
                     GError **error)
{
	NMModemBroadband *self = NM_MODEM_BROADBAND (_self);
	MMModemCapability modem_caps;
	NMSettingPPP *s_ppp;

	modem_caps = mm_modem_get_current_capabilities (self->priv->modem_iface);

	/* PPP settings common to 3GPP and 3GPP2 */
	s_ppp = nm_connection_get_setting_ppp (connection);
	if (!s_ppp) {
		s_ppp = (NMSettingPPP *) nm_setting_ppp_new ();
		g_object_set (G_OBJECT (s_ppp),
		              NM_SETTING_PPP_LCP_ECHO_FAILURE, 5,
		              NM_SETTING_PPP_LCP_ECHO_INTERVAL, 30,
		              NULL);
		nm_connection_add_setting (connection, NM_SETTING (s_ppp));
	}

	if (MODEM_CAPS_3GPP (modem_caps)) {
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

		/* TODO: This is not needed */
		if (!nm_setting_gsm_get_number (s_gsm))
			g_object_set (G_OBJECT (s_gsm), NM_SETTING_GSM_NUMBER, "*99#", NULL);

		nm_utils_complete_generic (connection,
		                           NM_SETTING_GSM_SETTING_NAME,
		                           existing_connections,
		                           _("GSM connection %d"),
		                           NULL,
		                           FALSE); /* No IPv6 yet by default */

		return TRUE;
	}

	if (MODEM_CAPS_3GPP2 (modem_caps)) {
		NMSettingCdma *s_cdma;

		s_cdma = nm_connection_get_setting_cdma (connection);
		if (!s_cdma) {
			s_cdma = (NMSettingCdma *) nm_setting_cdma_new ();
			nm_connection_add_setting (connection, NM_SETTING (s_cdma));
		}

		if (!nm_setting_cdma_get_number (s_cdma))
			g_object_set (G_OBJECT (s_cdma), NM_SETTING_CDMA_NUMBER, "#777", NULL);

		nm_utils_complete_generic (connection,
		                           NM_SETTING_CDMA_SETTING_NAME,
		                           existing_connections,
		                           _("CDMA connection %d"),
		                           NULL,
		                           FALSE); /* No IPv6 yet by default */

		return TRUE;
	}

	g_set_error (error,
	             NM_MODEM_ERROR,
	             NM_MODEM_ERROR_CONNECTION_INCOMPATIBLE,
	             "Device is not a mobile broadband modem");
	return FALSE;
}

/*****************************************************************************/

static gboolean
get_user_pass (NMModem *modem,
               NMConnection *connection,
               const char **user,
               const char **pass)
{
	NMSettingGsm *s_gsm;
	NMSettingCdma *s_cdma;

	s_gsm = nm_connection_get_setting_gsm (connection);
	s_cdma = nm_connection_get_setting_cdma (connection);
	if (!s_gsm && !s_cdma)
		return FALSE;

	if (user) {
		if (s_gsm)
			*user = nm_setting_gsm_get_username (s_gsm);
		else if (s_cdma)
			*user = nm_setting_cdma_get_username (s_cdma);
	}
	if (pass) {
		if (s_gsm)
			*pass = nm_setting_gsm_get_password (s_gsm);
		else if (s_cdma)
			*pass = nm_setting_cdma_get_password (s_cdma);
	}

	return TRUE;
}

/*****************************************************************************/
/* Query/Update enabled state */

static void
set_power_state_low_ready (MMModem *modem,
                           GAsyncResult *result,
                           NMModemBroadband *self)
{
	GError *error = NULL;

	if (!mm_modem_set_power_state_finish (modem, result, &error)) {
		/* Log but ignore errors; not all modems support low power state */
		nm_log_dbg (LOGD_MB, "(%s) failed to set modem low power state: %s",
		             nm_modem_get_uid (NM_MODEM (self)),
		             error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
	}

	/* Balance refcount */
	g_object_unref (self);
}

static void
modem_disable_ready (MMModem *modem_iface,
                     GAsyncResult *res,
                     NMModemBroadband *self)
{
	GError *error = NULL;

	if (mm_modem_disable_finish (modem_iface, res, &error)) {
		/* Once disabled, move to low-power mode */
		mm_modem_set_power_state (modem_iface,
		                          MM_MODEM_POWER_STATE_LOW,
		                          NULL,
		                          (GAsyncReadyCallback) set_power_state_low_ready,
		                          g_object_ref (self));
	} else {
		nm_log_warn (LOGD_MB, "(%s) failed to disable modem: %s",
		             nm_modem_get_uid (NM_MODEM (self)),
		             error && error->message ? error->message : "(unknown)");
		nm_modem_set_prev_state (NM_MODEM (self), "disable failed");
		g_clear_error (&error);
	}

	/* Balance refcount */
	g_object_unref (self);
}

static void
modem_enable_ready (MMModem *modem_iface,
                    GAsyncResult *res,
                    NMModemBroadband *self)
{
	GError *error = NULL;

	if (!mm_modem_enable_finish (modem_iface, res, &error)) {
		nm_log_warn (LOGD_MB, "(%s) failed to enable modem: %s",
		             nm_modem_get_uid (NM_MODEM (self)),
		             error && error->message ? error->message : "(unknown)");
		nm_modem_set_prev_state (NM_MODEM (self), "enable failed");
		g_clear_error (&error);
	}

	/* Balance refcount */
	g_object_unref (self);
}

static void
set_mm_enabled (NMModem *_self,
                gboolean enabled)
{
	NMModemBroadband *self = NM_MODEM_BROADBAND (_self);

	if (enabled) {
		mm_modem_enable (self->priv->modem_iface,
		                 NULL, /* cancellable */
		                 (GAsyncReadyCallback)modem_enable_ready,
		                 g_object_ref (self));
	} else {
		mm_modem_disable (self->priv->modem_iface,
		                  NULL, /* cancellable */
		                  (GAsyncReadyCallback)modem_disable_ready,
		                  g_object_ref (self));
	}
}

/*****************************************************************************/
/* IP method static */

static gboolean
ip_string_to_network_address (const gchar *str,
                              guint32 *out)
{
	guint32 addr = 0;
	gboolean success = FALSE;

	if (!str || inet_pton (AF_INET, str, &addr) != 1)
		addr = 0;
	else
		success = TRUE;

	*out = (guint32)addr;
	return success;
}

static gboolean
static_stage3_done (NMModemBroadband *self)
{
	GError *error = NULL;
	NMIP4Config *config = NULL;
	const gchar *address_string;
	const gchar *gw_string;
	guint32 address_network;
	guint32 gw;
	NMPlatformIP4Address address;
	const gchar **dns;
	guint i;

	g_assert (self->priv->ipv4_config);

	nm_log_info (LOGD_MB, "(%s): IPv4 static configuration:",
	             nm_modem_get_uid (NM_MODEM (self)));

	/* Fully fail if invalid IP address retrieved */
	address_string = mm_bearer_ip_config_get_address (self->priv->ipv4_config);
	if (!ip_string_to_network_address (address_string, &address_network)) {
		error = g_error_new (NM_MODEM_ERROR,
		                     NM_MODEM_ERROR_CONNECTION_INVALID,
		                     "(%s) retrieving IP4 configuration failed: invalid address given '%s'",
		                     nm_modem_get_uid (NM_MODEM (self)),
		                     address_string);
		goto out;
	}

	/* Missing gateway not a hard failure */
	gw_string = mm_bearer_ip_config_get_gateway (self->priv->ipv4_config);
	ip_string_to_network_address (gw_string, &gw);

	config = nm_ip4_config_new ();

	memset (&address, 0, sizeof (address));
	address.address = address_network;
	address.plen = mm_bearer_ip_config_get_prefix (self->priv->ipv4_config);
	address.source = NM_PLATFORM_SOURCE_WWAN;
	nm_ip4_config_add_address (config, &address);

	nm_log_info (LOGD_MB, "  address %s/%d", address_string, address.plen);

	if (gw) {
		nm_ip4_config_set_gateway (config, gw);
		nm_log_info (LOGD_MB, "  gateway %s", gw_string);
	}

	/* DNS servers */
	dns = mm_bearer_ip_config_get_dns (self->priv->ipv4_config);
	for (i = 0; dns[i]; i++) {
		if (   ip_string_to_network_address (dns[i], &address_network)
		    && address_network > 0) {
			nm_ip4_config_add_nameserver (config, address_network);
			nm_log_info (LOGD_MB, "  DNS %s", dns[i]);
		}
	}

out:
	g_signal_emit_by_name (self, NM_MODEM_IP4_CONFIG_RESULT, config, error);
	g_clear_error (&error);
	return FALSE;
}

static NMActStageReturn
static_stage3_ip4_config_start (NMModem *_self,
                                NMActRequest *req,
                                NMDeviceStateReason *reason)
{
	NMModemBroadband *self = NM_MODEM_BROADBAND (_self);

	/* We schedule it in an idle just to follow the same logic as in the
	 * generic modem implementation. */
	g_idle_add ((GSourceFunc)static_stage3_done, self);

	return NM_ACT_STAGE_RETURN_POSTPONE;
}

/*****************************************************************************/
/* Disconnect */

typedef struct {
	NMModemBroadband *self;
	gboolean warn;
} SimpleDisconnectContext;

static void
simple_disconnect_context_free (SimpleDisconnectContext *ctx)
{
	g_object_unref (ctx->self);
	g_slice_free (SimpleDisconnectContext, ctx);
}

static void
simple_disconnect_ready (MMModemSimple *modem_iface,
                         GAsyncResult *res,
                         SimpleDisconnectContext *ctx)
{
	GError *error = NULL;

	if (!mm_modem_simple_disconnect_finish (modem_iface, res, &error)) {
		if (ctx->warn)
			nm_log_warn (LOGD_MB, "(%s) failed to disconnect modem: %s",
			             nm_modem_get_uid (NM_MODEM (ctx->self)),
			             error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
	}

	simple_disconnect_context_free (ctx);
}

static void
disconnect (NMModem *self,
            gboolean warn)
{
	SimpleDisconnectContext *ctx;

	ctx = g_slice_new (SimpleDisconnectContext);
	ctx->self = g_object_ref (self);

	/* Don't bother warning on FAILED since the modem is already gone */
	ctx->warn = warn;

	mm_modem_simple_disconnect (
		ctx->self->priv->simple_iface,
		NULL, /* bearer path; if NULL given ALL get disconnected */
		NULL, /* cancellable */
		(GAsyncReadyCallback)simple_disconnect_ready,
		ctx);
}

/*****************************************************************************/

static void
deactivate (NMModem *_self, NMDevice *device)
{
	NMModemBroadband *self = NM_MODEM_BROADBAND (_self);

	/* TODO: cancel SimpleConnect() if any */

	/* Cleanup IPv4 addresses and routes */
	g_clear_object (&self->priv->ipv4_config);
	g_clear_object (&self->priv->ipv6_config);
	g_clear_object (&self->priv->bearer);

	self->priv->pin_tries = 0;

	/* Chain up parent's */
	NM_MODEM_CLASS (nm_modem_broadband_parent_class)->deactivate (_self, device);
}

/*****************************************************************************/

#define MAP_STATE(name) case MM_MODEM_STATE_##name: return NM_MODEM_STATE_##name;

static NMModemState
mm_state_to_nm (MMModemState mm_state)
{
	switch (mm_state) {
	MAP_STATE(UNKNOWN)
	MAP_STATE(FAILED)
	MAP_STATE(INITIALIZING)
	MAP_STATE(LOCKED)
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
}

static void
modem_state_changed (MMModem *modem,
                     MMModemState old_state,
                     MMModemState new_state,
                     MMModemStateChangeReason reason,
                     NMModemBroadband *self)
{

	/* After the SIM is unlocked MM1 will move the device to INITIALIZING which
	 * is an unavailable state.  That makes state handling confusing here, so
	 * suppress this state change and let the modem move from LOCKED to DISABLED.
	 */
	if (new_state == MM_MODEM_STATE_INITIALIZING && old_state == MM_MODEM_STATE_LOCKED)
		return;

	nm_modem_set_state (NM_MODEM (self),
	                    mm_state_to_nm (new_state),
	                    mm_modem_state_change_reason_get_string (reason));
}

/*****************************************************************************/

NMModem *
nm_modem_broadband_new (GObject *object, GError **error)
{
	NMModem *modem;
	MMObject *modem_object;
	MMModem *modem_iface;
	gchar *drivers;

	g_return_val_if_fail (MM_IS_OBJECT (object), NULL);
	modem_object = MM_OBJECT (object);

	/* Ensure we have the 'Modem' interface and the primary port at least */
	modem_iface = mm_object_peek_modem (modem_object);
	g_return_val_if_fail (!!modem_iface, NULL);
	g_return_val_if_fail (!!mm_modem_get_primary_port (modem_iface), NULL);

	/* Build a single string with all drivers listed */
	drivers = g_strjoinv (", ", (gchar **)mm_modem_get_drivers (modem_iface));

	modem = g_object_new (NM_TYPE_MODEM_BROADBAND,
	                      NM_MODEM_PATH, mm_object_get_path (modem_object),
	                      NM_MODEM_UID, mm_modem_get_primary_port (modem_iface),
	                      NM_MODEM_CONTROL_PORT, mm_modem_get_primary_port (modem_iface),
	                      NM_MODEM_DATA_PORT, NULL, /* We don't know it until bearer created */
	                      NM_MODEM_STATE, mm_state_to_nm (mm_modem_get_state (modem_iface)),
	                      NM_MODEM_DEVICE_ID, mm_modem_get_device_identifier (modem_iface),
	                      NM_MODEM_BROADBAND_MODEM, modem_object,
	                      NM_MODEM_DRIVER, drivers,
	                      NULL);
	g_free (drivers);
	return modem;
}

static void
get_sim_ready (MMModem *modem,
               GAsyncResult *res,
               NMModemBroadband *self)
{
	GError *error = NULL;
	MMSim *new_sim;

	new_sim = mm_modem_get_sim_finish (modem, res, &error);
	if (new_sim) {
		g_object_set (G_OBJECT (self),
		              NM_MODEM_SIM_ID, mm_sim_get_identifier (new_sim),
		              NULL);
		g_object_unref (new_sim);
	} else {
		nm_log_warn (LOGD_MB, "(%s) failed to retrieve SIM object: %s",
		             nm_modem_get_uid (NM_MODEM (self)),
		             error && error->message ? error->message : "(unknown)");
	}
	g_clear_error (&error);
	g_object_unref (self);
}

static void
sim_changed (MMModem *modem, GParamSpec *pspec, gpointer user_data)
{
	NMModemBroadband *self = NM_MODEM_BROADBAND (user_data);

	g_return_if_fail (modem == self->priv->modem_iface);

	if (mm_modem_get_sim_path (self->priv->modem_iface)) {
		mm_modem_get_sim (self->priv->modem_iface,
		                  NULL,  /* cancellable */
		                  (GAsyncReadyCallback) get_sim_ready,
		                  g_object_ref (self));
	} else
		g_object_set (G_OBJECT (self), NM_MODEM_SIM_ID, NULL, NULL);
}

static void
nm_modem_broadband_init (NMModemBroadband *self)
{
	self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
	                                          NM_TYPE_MODEM_BROADBAND,
	                                          NMModemBroadbandPrivate);
}

static void
set_property (GObject *object,
              guint prop_id,
			  const GValue *value,
              GParamSpec *pspec)
{
	NMModemBroadband *self = NM_MODEM_BROADBAND (object);

	switch (prop_id) {
	case PROP_MODEM:
		/* construct-only */
		self->priv->modem_object = g_value_dup_object (value);
		self->priv->modem_iface = mm_object_get_modem (self->priv->modem_object);
		g_assert (self->priv->modem_iface != NULL);
		g_signal_connect (self->priv->modem_iface,
		                  "state-changed",
		                  G_CALLBACK (modem_state_changed),
		                  self);
		g_signal_connect (self->priv->modem_iface,
		                  "notify::sim",
		                  G_CALLBACK (sim_changed),
		                  self);
		sim_changed (self->priv->modem_iface, NULL, self);

		/* Note: don't grab the Simple iface here; the Modem interface is the
		 * only one assumed to be always valid and available */
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object,
              guint prop_id,
			  GValue *value,
              GParamSpec *pspec)
{
	NMModemBroadband *self = NM_MODEM_BROADBAND (object);

	switch (prop_id) {
	case PROP_MODEM:
		g_value_set_object (value, self->priv->modem_object);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
dispose (GObject *object)
{
	NMModemBroadband *self = NM_MODEM_BROADBAND (object);

	g_clear_object (&self->priv->ipv4_config);
	g_clear_object (&self->priv->ipv6_config);
	g_clear_object (&self->priv->bearer);
	g_clear_object (&self->priv->modem_iface);
	g_clear_object (&self->priv->simple_iface);
	g_clear_object (&self->priv->modem_object);

	G_OBJECT_CLASS (nm_modem_broadband_parent_class)->dispose (object);
}

static void
nm_modem_broadband_class_init (NMModemBroadbandClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMModemClass *modem_class = NM_MODEM_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMModemBroadbandPrivate));

	/* Virtual methods */
	object_class->dispose = dispose;
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	modem_class->get_capabilities = get_capabilities;
	modem_class->static_stage3_ip4_config_start = static_stage3_ip4_config_start;
	modem_class->disconnect = disconnect;
	modem_class->deactivate = deactivate;
	modem_class->set_mm_enabled = set_mm_enabled;
	modem_class->get_user_pass = get_user_pass;
	modem_class->check_connection_compatible = check_connection_compatible;
	modem_class->complete_connection = complete_connection;
	modem_class->act_stage1_prepare = act_stage1_prepare;
	modem_class->owns_port = owns_port;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_MODEM,
		 g_param_spec_object (NM_MODEM_BROADBAND_MODEM,
		                      "Modem",
		                      "Broadband modem object",
		                      MM_GDBUS_TYPE_OBJECT,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}
