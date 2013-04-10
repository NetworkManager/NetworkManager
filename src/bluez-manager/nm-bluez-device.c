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
 * Copyright (C) 2009 - 2012 Red Hat, Inc.
 */

#include <glib.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ether.h>

#include "NetworkManager.h"
#include "nm-setting-bluetooth.h"

#include "nm-dbus-manager.h"
#include "nm-bluez-device.h"
#include "nm-bluez-common.h"
#include "nm-dbus-glib-types.h"
#include "nm-logging.h"


G_DEFINE_TYPE (NMBluezDevice, nm_bluez_device, G_TYPE_OBJECT)

#define NM_BLUEZ_DEVICE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_BLUEZ_DEVICE, NMBluezDevicePrivate))

typedef struct {
	char *path;
	DBusGProxy *proxy;
	gboolean initialized;
	gboolean usable;

	char *address;
	guint8 bin_address[ETH_ALEN];
	char *name;
	guint32 capabilities;
	gint rssi;

	NMConnectionProvider *provider;
	GSList *connections;
} NMBluezDevicePrivate;


enum {
	PROP_0,
	PROP_PATH,
	PROP_ADDRESS,
	PROP_NAME,
	PROP_CAPABILITIES,
	PROP_RSSI,
	PROP_USABLE,

	LAST_PROP
};

/* Signals */
enum {
	INITIALIZED,
	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };

/***********************************************************/

const char *
nm_bluez_device_get_path (NMBluezDevice *self)
{
	g_return_val_if_fail (NM_IS_BLUEZ_DEVICE (self), NULL);

	return NM_BLUEZ_DEVICE_GET_PRIVATE (self)->path;
}

const char *
nm_bluez_device_get_address (NMBluezDevice *self)
{
	g_return_val_if_fail (NM_IS_BLUEZ_DEVICE (self), NULL);

	return NM_BLUEZ_DEVICE_GET_PRIVATE (self)->address;
}

gboolean
nm_bluez_device_get_initialized (NMBluezDevice *self)
{
	g_return_val_if_fail (NM_IS_BLUEZ_DEVICE (self), FALSE);

	return NM_BLUEZ_DEVICE_GET_PRIVATE (self)->initialized;
}

gboolean
nm_bluez_device_get_usable (NMBluezDevice *self)
{
	g_return_val_if_fail (NM_IS_BLUEZ_DEVICE (self), FALSE);

	return NM_BLUEZ_DEVICE_GET_PRIVATE (self)->usable;
}

const char *
nm_bluez_device_get_name (NMBluezDevice *self)
{
	g_return_val_if_fail (NM_IS_BLUEZ_DEVICE (self), NULL);

	return NM_BLUEZ_DEVICE_GET_PRIVATE (self)->name;
}

guint32
nm_bluez_device_get_capabilities (NMBluezDevice *self)
{
	g_return_val_if_fail (NM_IS_BLUEZ_DEVICE (self), 0);

	return NM_BLUEZ_DEVICE_GET_PRIVATE (self)->capabilities;
}

gint
nm_bluez_device_get_rssi (NMBluezDevice *self)
{
	g_return_val_if_fail (NM_IS_BLUEZ_DEVICE (self), 0);

	return NM_BLUEZ_DEVICE_GET_PRIVATE (self)->rssi;
}

static void
check_emit_usable (NMBluezDevice *self)
{
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);
	gboolean new_usable;

	new_usable = (priv->initialized && priv->capabilities && priv->name && priv->address && priv->connections);
	if (new_usable != priv->usable) {
		priv->usable = new_usable;
		g_object_notify (G_OBJECT (self), NM_BLUEZ_DEVICE_USABLE);
	}
}

/********************************************************************/

static gboolean
connection_compatible (NMBluezDevice *self, NMConnection *connection)
{
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);
	NMSettingBluetooth *s_bt;
	const char *bt_type;
	const GByteArray *bdaddr;

	if (!nm_connection_is_type (connection, NM_SETTING_BLUETOOTH_SETTING_NAME))
		return FALSE;

	s_bt = nm_connection_get_setting_bluetooth (connection);
	if (!s_bt)
		return FALSE;

	bdaddr = nm_setting_bluetooth_get_bdaddr (s_bt);
	if (!bdaddr || bdaddr->len != ETH_ALEN)
		return FALSE;
	if (memcmp (bdaddr->data, priv->bin_address, ETH_ALEN) != 0)
		return FALSE;

	bt_type = nm_setting_bluetooth_get_connection_type (s_bt);
	if (   g_str_equal (bt_type, NM_SETTING_BLUETOOTH_TYPE_DUN)
	    && !(priv->capabilities & NM_BT_CAPABILITY_DUN))
	    	return FALSE;

	if (   g_str_equal (bt_type, NM_SETTING_BLUETOOTH_TYPE_PANU)
	    && !(priv->capabilities & NM_BT_CAPABILITY_NAP))
	    	return FALSE;

	return TRUE;
}

static void
_internal_add_connection (NMBluezDevice *self, NMConnection *connection)
{
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);

	if (!g_slist_find (priv->connections, connection)) {
		priv->connections = g_slist_prepend (priv->connections, g_object_ref (connection));
		check_emit_usable (self);
	}
}

static void
cp_connection_added (NMConnectionProvider *provider,
                     NMConnection *connection,
                     NMBluezDevice *self)
{
	if (connection_compatible (self, connection))
		_internal_add_connection (self, connection);
}

static void
cp_connection_removed (NMConnectionProvider *provider,
                       NMConnection *connection,
                       NMBluezDevice *self)
{
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);

	if (g_slist_find (priv->connections, connection)) {
		priv->connections = g_slist_remove (priv->connections, connection);
		g_object_unref (connection);
		check_emit_usable (self);
	}
}

static void
cp_connection_updated (NMConnectionProvider *provider,
                       NMConnection *connection,
                       NMBluezDevice *self)
{
	if (connection_compatible (self, connection))
		_internal_add_connection (self, connection);
	else
		cp_connection_removed (provider, connection, self);
}

static void
cp_connections_loaded (NMConnectionProvider *provider, NMBluezDevice *self)
{
	const GSList *connections, *iter;

	connections = nm_connection_provider_get_connections (provider);
	for (iter = connections; iter; iter = g_slist_next (iter))
		cp_connection_added (provider, NM_CONNECTION (iter->data), self);
}

/***********************************************************/

static guint32
convert_uuids_to_capabilities (const char **strings)
{
	const char **iter;
	guint32 capabilities = 0;

	for (iter = strings; iter && *iter; iter++) {
		char **parts;

		parts = g_strsplit (*iter, "-", -1);
		if (parts && parts[0]) {
			switch (g_ascii_strtoull (parts[0], NULL, 16)) {
			case 0x1103:
				capabilities |= NM_BT_CAPABILITY_DUN;
				break;
			case 0x1116:
				capabilities |= NM_BT_CAPABILITY_NAP;
				break;
			default:
				break;
			}
		}
		g_strfreev (parts);
	}

	return capabilities;
}

static void
property_changed (DBusGProxy *proxy,
                  const char *property,
                  GValue *value,
                  gpointer user_data)
{
	NMBluezDevice *self = NM_BLUEZ_DEVICE (user_data);
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);
	const char *str;
	guint32 uint_val;
	gint int_val;

	if (!strcmp (property, "Name")) {
		str = g_value_get_string (value);
		if (   (!priv->name && str)
		    || (priv->name && !str)
		    || (priv->name && str && strcmp (priv->name, str))) {
			g_free (priv->name);
			priv->name = g_strdup (str);
			g_object_notify (G_OBJECT (self), NM_BLUEZ_DEVICE_NAME);
		}
	} else if (!strcmp (property, "RSSI")) {
		int_val = g_value_get_int (value);
		if (priv->rssi != int_val) {
			priv->rssi = int_val;
			g_object_notify (G_OBJECT (self), NM_BLUEZ_DEVICE_RSSI);
		}
	} else if (!strcmp (property, "UUIDs")) {
		uint_val = convert_uuids_to_capabilities ((const char **) g_value_get_boxed (value));
		if (priv->capabilities != uint_val) {
			priv->capabilities = uint_val;
			g_object_notify (G_OBJECT (self), NM_BLUEZ_DEVICE_CAPABILITIES);
		}
	}

	check_emit_usable (self);
}

static void
get_properties_cb (DBusGProxy *proxy, DBusGProxyCall *call, gpointer user_data)
{
	NMBluezDevice *self = NM_BLUEZ_DEVICE (user_data);
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);
	GHashTable *properties = NULL;
	GError *err = NULL;
	GValue *value;
	const char **uuids;
	struct ether_addr *tmp;

	if (!dbus_g_proxy_end_call (proxy, call, &err,
	                            DBUS_TYPE_G_MAP_OF_VARIANT, &properties,
	                            G_TYPE_INVALID)) {
		nm_log_warn (LOGD_BT, "bluez error getting device properties: %s",
		             err && err->message ? err->message : "(unknown)");
		g_error_free (err);
		g_signal_emit (self, signals[INITIALIZED], 0, FALSE);
		return;
	}

	value = g_hash_table_lookup (properties, "Address");
	priv->address = value ? g_value_dup_string (value) : NULL;
	if (priv->address) {
		tmp = ether_aton (priv->address);
		g_assert (tmp);
		memcpy (priv->bin_address, tmp->ether_addr_octet, ETH_ALEN);
	}

	value = g_hash_table_lookup (properties, "Name");
	priv->name = value ? g_value_dup_string (value) : NULL;

	value = g_hash_table_lookup (properties, "RSSI");
	priv->rssi = value ? g_value_get_int (value) : 0;

	value = g_hash_table_lookup (properties, "UUIDs");
	if (value) {
		uuids = (const char **) g_value_get_boxed (value);
		priv->capabilities = convert_uuids_to_capabilities (uuids);
	} else
		priv->capabilities = NM_BT_CAPABILITY_NONE;

	g_hash_table_unref (properties);

	/* Check if any connections match this device */
	cp_connections_loaded (priv->provider, self);

	priv->initialized = TRUE;
	g_signal_emit (self, signals[INITIALIZED], 0, TRUE);

	check_emit_usable (self);
}

static void
query_properties (NMBluezDevice *self)
{
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);
	DBusGProxyCall *call;

	call = dbus_g_proxy_begin_call (priv->proxy, "GetProperties",
	                                get_properties_cb,
	                                self,
	                                NULL, G_TYPE_INVALID);
	if (!call) {
		nm_log_warn (LOGD_BT, "failed to request Bluetooth device properties for %s.",
		             priv->path);
	}
}

/********************************************************************/

NMBluezDevice *
nm_bluez_device_new (const char *path, NMConnectionProvider *provider)
{
	NMBluezDevice *self;
	NMBluezDevicePrivate *priv;
	DBusGConnection *connection;

	g_return_val_if_fail (path != NULL, NULL);
	g_return_val_if_fail (provider != NULL, NULL);

	self = (NMBluezDevice *) g_object_new (NM_TYPE_BLUEZ_DEVICE,
	                                       NM_BLUEZ_DEVICE_PATH, path,
	                                       NULL);
	if (!self)
		return NULL;

	priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);

	priv->provider = provider;

	g_signal_connect (priv->provider,
	                  NM_CP_SIGNAL_CONNECTION_ADDED,
	                  G_CALLBACK (cp_connection_added),
	                  self);

	g_signal_connect (priv->provider,
	                  NM_CP_SIGNAL_CONNECTION_REMOVED,
	                  G_CALLBACK (cp_connection_removed),
	                  self);

	g_signal_connect (priv->provider,
	                  NM_CP_SIGNAL_CONNECTION_UPDATED,
	                  G_CALLBACK (cp_connection_updated),
	                  self);

	g_signal_connect (priv->provider,
	                  NM_CP_SIGNAL_CONNECTIONS_LOADED,
	                  G_CALLBACK (cp_connections_loaded),
	                  self);

	connection = nm_dbus_manager_get_connection (nm_dbus_manager_get ());

	priv->proxy = dbus_g_proxy_new_for_name (connection,
	                                         BLUEZ_SERVICE,
	                                         priv->path,
	                                         BLUEZ_DEVICE_INTERFACE);

	dbus_g_object_register_marshaller (g_cclosure_marshal_generic,
	                                   G_TYPE_NONE,
	                                   G_TYPE_STRING, G_TYPE_VALUE,
	                                   G_TYPE_INVALID);
	dbus_g_proxy_add_signal (priv->proxy, "PropertyChanged",
	                         G_TYPE_STRING, G_TYPE_VALUE, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "PropertyChanged",
	                             G_CALLBACK (property_changed), self, NULL);

	query_properties (self);
	return self;
}

static void
nm_bluez_device_init (NMBluezDevice *self)
{
}

static void
dispose (GObject *object)
{
	NMBluezDevice *self = NM_BLUEZ_DEVICE (object);
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);

	g_slist_foreach (priv->connections, (GFunc) g_object_unref, NULL);
	g_slist_free (priv->connections);
	priv->connections = NULL;

	g_signal_handlers_disconnect_by_func (priv->provider, cp_connection_added, self);
	g_signal_handlers_disconnect_by_func (priv->provider, cp_connection_removed, self);
	g_signal_handlers_disconnect_by_func (priv->provider, cp_connection_updated, self);
	g_signal_handlers_disconnect_by_func (priv->provider, cp_connections_loaded, self);

	G_OBJECT_CLASS (nm_bluez_device_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (object);

	g_free (priv->path);
	g_free (priv->address);
	g_free (priv->name);
	g_object_unref (priv->proxy);

	G_OBJECT_CLASS (nm_bluez_device_parent_class)->finalize (object);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_PATH:
		g_value_set_string (value, priv->path);
		break;
	case PROP_ADDRESS:
		g_value_set_string (value, priv->address);
		break;
	case PROP_NAME:
		g_value_set_string (value, priv->name);
		break;
	case PROP_CAPABILITIES:
		g_value_set_uint (value, priv->capabilities);
		break;
	case PROP_RSSI:
		g_value_set_int (value, priv->rssi);
		break;
	case PROP_USABLE:
		g_value_set_boolean (value, priv->usable);
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
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_PATH:
		/* construct only */
		priv->path = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_bluez_device_class_init (NMBluezDeviceClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);

	g_type_class_add_private (config_class, sizeof (NMBluezDevicePrivate));

	/* virtual methods */
	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_PATH,
		 g_param_spec_string (NM_BLUEZ_DEVICE_PATH,
		                      "DBus Path",
		                      "DBus Path",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_ADDRESS,
		 g_param_spec_string (NM_BLUEZ_DEVICE_ADDRESS,
		                      "Address",
		                      "Address",
		                      NULL,
		                      G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_NAME,
		 g_param_spec_string (NM_BLUEZ_DEVICE_NAME,
		                      "Name",
		                      "Name",
		                      NULL,
		                      G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_CAPABILITIES,
		 g_param_spec_uint (NM_BLUEZ_DEVICE_CAPABILITIES,
		                      "Capabilities",
		                      "Capabilities",
		                      0, G_MAXUINT, 0,
		                      G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_RSSI,
		 g_param_spec_int (NM_BLUEZ_DEVICE_RSSI,
		                      "RSSI",
		                      "RSSI",
		                      G_MININT, G_MAXINT, 0,
		                      G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_USABLE,
		 g_param_spec_boolean (NM_BLUEZ_DEVICE_USABLE,
		                       "Usable",
		                       "Usable",
		                       FALSE,
		                       G_PARAM_READABLE));

	/* Signals */
	signals[INITIALIZED] = g_signal_new ("initialized",
	                                     G_OBJECT_CLASS_TYPE (object_class),
	                                     G_SIGNAL_RUN_LAST,
	                                     G_STRUCT_OFFSET (NMBluezDeviceClass, initialized),
	                                     NULL, NULL, NULL, 
	                                     G_TYPE_NONE, 1, G_TYPE_BOOLEAN);
}

