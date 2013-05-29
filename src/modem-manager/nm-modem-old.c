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
 * Copyright (C) 2009 Novell, Inc.
 */

#include <string.h>
#include <glib/gi18n.h>

#include "nm-modem-old.h"
#include "nm-system.h"
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

	DBusGProxyCall *call;
	GHashTable *connect_properties;
} NMModemOldPrivate;

/*****************************************************************************/

DBusGProxy *
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
update_mm_enabled (NMModem *self,
                   gboolean new_enabled)
{
	if (nm_modem_get_mm_enabled (self) != new_enabled) {
		g_object_set (self,
		              NM_MODEM_ENABLED, new_enabled,
		              NULL);
	}
}

static void
get_mm_enabled_done (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMModem *self = NM_MODEM (user_data);
	GError *error = NULL;
	GValue value = G_VALUE_INIT;

	if (!dbus_g_proxy_end_call (proxy, call_id, &error,
	                            G_TYPE_VALUE, &value,
	                            G_TYPE_INVALID)) {
		nm_log_warn (LOGD_MB, "failed get modem enabled state: (%d) %s",
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
		return;
	}

	if (G_VALUE_HOLDS_BOOLEAN (&value)) {
		update_mm_enabled (self, g_value_get_boolean (&value));
	} else
		nm_log_warn (LOGD_MB, "failed get modem enabled state: unexpected reply type");

	g_value_unset (&value);
}

static void
query_mm_enabled (NMModemOld *self)
{
	dbus_g_proxy_begin_call (NM_MODEM_OLD_GET_PRIVATE (self)->props_proxy,
	                         "Get", get_mm_enabled_done,
	                         self, NULL,
	                         G_TYPE_STRING, MM_OLD_DBUS_INTERFACE_MODEM,
	                         G_TYPE_STRING, "Enabled",
	                         G_TYPE_INVALID);
}

static void
set_mm_enabled_done (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	GError *error = NULL;

	if (!dbus_g_proxy_end_call (proxy, call_id, &error, G_TYPE_INVALID)) {
		nm_log_warn (LOGD_MB, "failed to enable/disable modem: (%d) %s",
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
	}

	/* Update enabled/disabled state again */
	query_mm_enabled (NM_MODEM_OLD (user_data));
}

static void
set_mm_enabled (NMModem *self, gboolean enabled)
{
	/* FIXME: For now this just toggles the ModemManager enabled state.  In the
	 * future we want to tie this into rfkill state instead so that the user can
	 * toggle rfkill status of the WWAN modem.
	 */
	dbus_g_proxy_begin_call (nm_modem_old_get_proxy (NM_MODEM_OLD (self),
	                                                     MM_OLD_DBUS_INTERFACE_MODEM),
	                         "Enable", set_mm_enabled_done,
	                         self, NULL,
	                         G_TYPE_BOOLEAN, enabled,
	                         G_TYPE_INVALID);
	/* If we are disabling the modem, stop saying that it's enabled. */
	if (!enabled)
		update_mm_enabled (self, enabled);
}

/*****************************************************************************/

static void
stage1_prepare_done (DBusGProxy *proxy, DBusGProxyCall *call, gpointer user_data)
{
	NMModemOld *self = NM_MODEM_OLD (user_data);
	NMModemOldPrivate *priv = NM_MODEM_OLD_GET_PRIVATE (self);
	GError *error = NULL;

	priv->call = NULL;

	if (priv->connect_properties) {
		g_hash_table_destroy (priv->connect_properties);
		priv->connect_properties = NULL;
	}

	if (dbus_g_proxy_end_call (proxy, call, &error, G_TYPE_INVALID))
		g_signal_emit_by_name (self, NM_MODEM_PREPARE_RESULT, TRUE, NM_DEVICE_STATE_REASON_NONE);
	else {
		nm_log_warn (LOGD_MB, "Modem connection failed: (%d) %s",
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
		g_error_free (error);
		g_signal_emit_by_name (self, NM_MODEM_PREPARE_RESULT, FALSE, NM_DEVICE_STATE_REASON_NONE);
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

static void
stage1_enable_done (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMModemOld *self = NM_MODEM_OLD (user_data);
	GError *error = NULL;

	if (dbus_g_proxy_end_call (proxy, call_id, &error, G_TYPE_INVALID))
		do_connect (self);
	else {
		nm_log_warn (LOGD_MB, "Modem enable failed: (%d) %s",
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
		g_error_free (error);
		g_signal_emit_by_name (self, NM_MODEM_PREPARE_RESULT, FALSE, NM_DEVICE_STATE_REASON_MODEM_INIT_FAILED);
	}
}

static GHashTable *
create_connect_properties (NMConnection *connection)
{
	NMSettingCdma *s_cdma;
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

	g_hash_table_destroy (properties);
	return NULL;
}

static NMActStageReturn
act_stage1_prepare (NMModem *modem,
                    NMActRequest *req,
                    GPtrArray **out_hints,
                    const char **out_setting_name,
                    NMDeviceStateReason *reason)
{
	NMModemOld *self = NM_MODEM_OLD (modem);
	NMModemOldPrivate *priv = NM_MODEM_OLD_GET_PRIVATE (self);
	NMConnection *connection;

	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	*out_setting_name = nm_connection_need_secrets (connection, out_hints);
	if (!*out_setting_name) {
		gboolean enabled = nm_modem_get_mm_enabled (modem);
		DBusGProxy *proxy;

		if (priv->connect_properties)
			g_hash_table_destroy (priv->connect_properties);
		priv->connect_properties = create_connect_properties (connection);

		if (enabled)
			do_connect (self);
		else {
			proxy = nm_modem_old_get_proxy (NM_MODEM_OLD (modem), MM_OLD_DBUS_INTERFACE_MODEM);
			dbus_g_proxy_begin_call_with_timeout (proxy,
			                                      "Enable", stage1_enable_done,
			                                      modem, NULL, 20000,
			                                      G_TYPE_BOOLEAN, TRUE,
			                                      G_TYPE_INVALID);
		}
	} else {
		/* NMModem will handle requesting secrets... */
	}

	return NM_ACT_STAGE_RETURN_POSTPONE;
}

/*****************************************************************************/
/* IP method static */

static char addr_to_string_buf[INET6_ADDRSTRLEN + 1];

static const char *
ip_address_to_string (guint32 numeric)
{
	struct in_addr temp_addr;

	memset (&addr_to_string_buf, '\0', sizeof (addr_to_string_buf));
	temp_addr.s_addr = numeric;

	if (inet_ntop (AF_INET, &temp_addr, addr_to_string_buf, INET_ADDRSTRLEN)) {
		return addr_to_string_buf;
	} else {
		nm_log_warn (LOGD_VPN, "error converting IP4 address 0x%X",
		             ntohl (temp_addr.s_addr));
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
		NMIP4Address *addr;
		int i;

		config = nm_ip4_config_new ();

		addr = nm_ip4_address_new ();

		nm_log_info (LOGD_MB, "(%s): IPv4 static configuration:",
		             nm_modem_get_uid (NM_MODEM (self)));

		/* IP address */
		nm_ip4_address_set_address (addr, g_value_get_uint (g_value_array_get_nth (ret_array, 0)));
		nm_ip4_address_set_prefix (addr, 32);
		nm_ip4_config_take_address (config, addr);

		nm_log_info (LOGD_MB, "  address %s/%d",
		             ip_address_to_string (nm_ip4_address_get_address (addr)),
		             nm_ip4_address_get_prefix (addr));

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
	NMModemOldPrivate *priv;

	g_assert (NM_IS_MODEM_OLD (self));
	g_assert (NM_IS_DEVICE (device));

	priv = NM_MODEM_OLD_GET_PRIVATE (self);

	if (priv->call) {
		dbus_g_proxy_cancel_call (priv->proxy, priv->call);
		priv->call = NULL;
	}

	/* Chain up parent's */
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
	MMOldModemState new_state;

	if (strcmp (interface, MM_OLD_DBUS_INTERFACE_MODEM))
		return;

	value = g_hash_table_lookup (props, "Enabled");
	if (value && G_VALUE_HOLDS_BOOLEAN (value)) {
		g_object_set (self,
		              NM_MODEM_ENABLED, g_value_get_boolean (value),
		              NULL);
	}

	value = g_hash_table_lookup (props, "IpMethod");
	if (value && G_VALUE_HOLDS_UINT (value)) {
		g_object_set (self,
		              NM_MODEM_IP_METHOD, g_value_get_uint (value),
		              NULL);
	}

	value = g_hash_table_lookup (props, "State");
	if (value && G_VALUE_HOLDS_UINT (value)) {
		new_state = g_value_get_uint (value);
		if (new_state != priv->state) {
			if (new_state == MM_OLD_MODEM_STATE_CONNECTED)
				g_object_set (self,
				              NM_MODEM_CONNECTED, TRUE,
				              NULL);
			else if (priv->state == MM_OLD_MODEM_STATE_CONNECTED)
				g_object_set (self,
				              NM_MODEM_CONNECTED, FALSE,
				              NULL);
			priv->state = new_state;
		}
	}
}

/*****************************************************************************/

static gboolean
check_connection_compatible (NMModem *modem,
                             NMConnection *connection,
                             GError **error)
{
	NMModemOldPrivate *priv = NM_MODEM_OLD_GET_PRIVATE (modem);
	NMSettingConnection *s_con;
	gboolean valid_cdma = FALSE;
	const char *ctype;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	ctype = nm_setting_connection_get_connection_type (s_con);
	g_assert (ctype);

	/* Check for valid CDMA first */
	if (strcmp (ctype, NM_SETTING_CDMA_SETTING_NAME) == 0)
		valid_cdma = !!nm_connection_get_setting_cdma (connection);

	/* Validate CDMA */
	if (priv->caps & NM_DEVICE_MODEM_CAPABILITY_CDMA_EVDO) {
		if (valid_cdma)
			return TRUE;

		/* If the modem is only CDMA and the connection is not CDMA, error */
		if ((priv->caps ^ NM_DEVICE_MODEM_CAPABILITY_CDMA_EVDO) == 0) {
			g_set_error (error, NM_MODEM_ERROR, NM_MODEM_ERROR_CONNECTION_NOT_CDMA,
				         "The connection was not a CDMA connection.");
			return FALSE;
		}
	}

	g_set_error (error, NM_MODEM_ERROR, NM_MODEM_ERROR_CONNECTION_INCOMPATIBLE,
		         "The connection was not not compatible with this modem (caps 0x%X)",
		         priv->caps);
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

	if (priv->caps & NM_DEVICE_MODEM_CAPABILITY_CDMA_EVDO)
		return complete_connection_cdma (connection, existing_connections, error);

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

	return FALSE;
}

/*****************************************************************************/

void
nm_modem_old_get_capabilities (NMModemOld *self,
                               NMDeviceModemCapabilities *modem_caps,
                               NMDeviceModemCapabilities *current_caps)
{
	*current_caps = *modem_caps = NM_MODEM_OLD_GET_PRIVATE (self)->caps;
}

/*****************************************************************************/

NMModem *
nm_modem_old_new (const char *path,
                  const char *data_device,
                  guint32 ip_method,
                  guint32 modem_type,
                  MMOldModemState state)
{
	NMDeviceModemCapabilities caps = NM_DEVICE_MODEM_CAPABILITY_NONE;
	NMModemOld *self;

	g_return_val_if_fail (path != NULL, NULL);
	g_return_val_if_fail (data_device != NULL, NULL);
	g_return_val_if_fail (modem_type != MM_OLD_MODEM_TYPE_UNKNOWN, NULL);

	self = (NMModemOld *) g_object_new (NM_TYPE_MODEM_OLD,
	                                    NM_MODEM_PATH, path,
	                                    NM_MODEM_UID, data_device,
	                                    NM_MODEM_CONTROL_PORT, NULL,
	                                    NM_MODEM_DATA_PORT, data_device,
	                                    NM_MODEM_IP_METHOD, ip_method,
	                                    NM_MODEM_CONNECTED, (state == MM_OLD_MODEM_STATE_CONNECTED),
	                                    NULL);
	if (self) {
		if (modem_type == MM_OLD_MODEM_TYPE_CDMA)
			caps |= NM_DEVICE_MODEM_CAPABILITY_CDMA_EVDO;

		NM_MODEM_OLD_GET_PRIVATE (self)->caps = caps;
	}

	return (NMModem *) self;
}

static void
nm_modem_old_init (NMModemOld *self)
{
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

	query_mm_enabled (NM_MODEM_OLD (object));

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

	modem_class->get_user_pass = get_user_pass;
	modem_class->complete_connection = complete_connection;
	modem_class->check_connection_compatible = check_connection_compatible;
	modem_class->act_stage1_prepare = act_stage1_prepare;
	modem_class->static_stage3_ip4_config_start = static_stage3_ip4_config_start;
	modem_class->disconnect = disconnect;
	modem_class->deactivate = deactivate;
	modem_class->set_mm_enabled = set_mm_enabled;
}
