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
#include "nm-modem-generic.h"
#include "nm-system.h"
#include "nm-dbus-manager.h"
#include "nm-setting-connection.h"
#include "nm-marshal.h"
#include "nm-properties-changed-signal.h"
#include "nm-modem-types.h"
#include "nm-logging.h"
#include "NetworkManagerUtils.h"
#include "nm-device-private.h"
#include "nm-dbus-glib-types.h"

G_DEFINE_TYPE (NMModemGeneric, nm_modem_generic, NM_TYPE_MODEM)

#define NM_MODEM_GENERIC_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_MODEM_GENERIC, NMModemGenericPrivate))

typedef struct {
	NMDBusManager *dbus_mgr;
	DBusGProxy *proxy;
	DBusGProxy *props_proxy;

	DBusGProxyCall *call;

	NMModemState state;
} NMModemGenericPrivate;

/*****************************************************************************/

DBusGProxy *
nm_modem_generic_get_proxy (NMModemGeneric *self,
                            const char *interface)
{

	NMModemGenericPrivate *priv = NM_MODEM_GENERIC_GET_PRIVATE (self);
	const char *current_iface;

	g_return_val_if_fail (NM_IS_MODEM_GENERIC (self), NULL);

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
	GValue value = { 0, };

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
query_mm_enabled (NMModemGeneric *self)
{
	dbus_g_proxy_begin_call (NM_MODEM_GENERIC_GET_PRIVATE (self)->props_proxy,
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
	query_mm_enabled (NM_MODEM_GENERIC (user_data));
}

static void
set_mm_enabled (NMModem *self, gboolean enabled)
{
	/* FIXME: For now this just toggles the ModemManager enabled state.  In the
	 * future we want to tie this into rfkill state instead so that the user can
	 * toggle rfkill status of the WWAN modem.
	 */
	dbus_g_proxy_begin_call (nm_modem_generic_get_proxy (NM_MODEM_GENERIC (self),
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
	NMModemGeneric *self = NM_MODEM_GENERIC (user_data);
	NMModemGenericPrivate *priv = NM_MODEM_GENERIC_GET_PRIVATE (self);
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
	NMModemGenericPrivate *priv;

	g_return_val_if_fail (self != NULL, NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (NM_IS_MODEM (self), NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (req != NULL, NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (NM_IS_ACT_REQUEST (req), NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (reason !=	NULL, NM_ACT_STAGE_RETURN_FAILURE);

	priv = NM_MODEM_GENERIC_GET_PRIVATE (self);

	priv->call = dbus_g_proxy_begin_call (nm_modem_generic_get_proxy (NM_MODEM_GENERIC (self),
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
	dbus_g_proxy_begin_call (nm_modem_generic_get_proxy (NM_MODEM_GENERIC (self),
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
	NMModemGenericPrivate *priv;

	g_assert (NM_IS_MODEM_GENERIC (self));
	g_assert (NM_IS_DEVICE (device));

	priv = NM_MODEM_GENERIC_GET_PRIVATE (self);

	if (priv->call) {
		dbus_g_proxy_cancel_call (priv->proxy, priv->call);
		priv->call = NULL;
	}

	/* Chain up parent's */
	NM_MODEM_CLASS (nm_modem_generic_parent_class)->deactivate (self, device);
}

/*****************************************************************************/

static void
modem_properties_changed (DBusGProxy *proxy,
                          const char *interface,
                          GHashTable *props,
                          gpointer user_data)
{
	NMModemGeneric *self = NM_MODEM_GENERIC (user_data);
	NMModemGenericPrivate *priv = NM_MODEM_GENERIC_GET_PRIVATE (self);
	GValue *value;
	NMModemState new_state;

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
			if (new_state == NM_MODEM_STATE_CONNECTED)
				g_object_set (self,
				              NM_MODEM_CONNECTED, TRUE,
				              NULL);
			else if (priv->state == NM_MODEM_STATE_CONNECTED)
				g_object_set (self,
				              NM_MODEM_CONNECTED, FALSE,
				              NULL);
			priv->state = new_state;
		}
	}
}

/*****************************************************************************/

static void
nm_modem_generic_init (NMModemGeneric *self)
{
	NMModemGenericPrivate *priv = NM_MODEM_GENERIC_GET_PRIVATE (self);

	priv->dbus_mgr = nm_dbus_manager_get ();
}

static GObject*
constructor (GType type,
			 guint n_construct_params,
			 GObjectConstructParam *construct_params)
{
	GObject *object;
	NMModemGenericPrivate *priv;
	DBusGConnection *bus;

	object = G_OBJECT_CLASS (nm_modem_generic_parent_class)->constructor (type, n_construct_params, construct_params);
	if (!object)
		return NULL;

	priv = NM_MODEM_GENERIC_GET_PRIVATE (object);

	bus = nm_dbus_manager_get_connection (priv->dbus_mgr);
	priv->proxy = dbus_g_proxy_new_for_name (bus,
	                                         MM_OLD_DBUS_SERVICE,
	                                         nm_modem_get_path (NM_MODEM (object)),
	                                         MM_OLD_DBUS_INTERFACE_MODEM);

	priv->props_proxy = dbus_g_proxy_new_for_name (bus,
	                                               MM_OLD_DBUS_SERVICE,
	                                               nm_modem_get_path (NM_MODEM (object)),
	                                               DBUS_INTERFACE_PROPERTIES);
	dbus_g_object_register_marshaller (_nm_marshal_VOID__STRING_BOXED,
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

	query_mm_enabled (NM_MODEM_GENERIC (object));

	return object;
}

static void
dispose (GObject *object)
{
	NMModemGenericPrivate *priv = NM_MODEM_GENERIC_GET_PRIVATE (object);

	if (priv->proxy) {
		g_object_unref (priv->proxy);
		priv->proxy = NULL;
	}

	if (priv->props_proxy) {
		g_object_unref (priv->props_proxy);
		priv->props_proxy = NULL;
	}

	if (priv->dbus_mgr) {
		g_object_unref (priv->dbus_mgr);
		priv->dbus_mgr = NULL;
	}

	G_OBJECT_CLASS (nm_modem_generic_parent_class)->dispose (object);
}

static void
nm_modem_generic_class_init (NMModemGenericClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMModemClass *modem_class = NM_MODEM_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMModemGenericPrivate));

	/* Virtual methods */
	object_class->constructor = constructor;
	object_class->dispose = dispose;

	modem_class->static_stage3_ip4_config_start = static_stage3_ip4_config_start;
	modem_class->disconnect = disconnect;
	modem_class->deactivate = deactivate;
	modem_class->set_mm_enabled = set_mm_enabled;
}
