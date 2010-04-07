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

#include <glib.h>
#include <string.h>

#include "NetworkManager.h"
#include "nm-dbus-manager.h"
#include "nm-bluez-adapter.h"
#include "nm-bluez-device.h"
#include "nm-bluez-common.h"
#include "nm-dbus-glib-types.h"
#include "nm-logging.h"


G_DEFINE_TYPE (NMBluezAdapter, nm_bluez_adapter, G_TYPE_OBJECT)

#define NM_BLUEZ_ADAPTER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_BLUEZ_ADAPTER, NMBluezAdapterPrivate))

typedef struct {
	char *path;
	DBusGProxy *proxy;
	gboolean initialized;

	char *address;
	GHashTable *devices;
} NMBluezAdapterPrivate;


enum {
	PROP_0,
	PROP_PATH,
	PROP_ADDRESS,

	LAST_PROP
};

/* Signals */
enum {
	INITIALIZED,
	DEVICE_ADDED,
	DEVICE_REMOVED,
	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };

const char *
nm_bluez_adapter_get_path (NMBluezAdapter *self)
{
	g_return_val_if_fail (NM_IS_BLUEZ_ADAPTER (self), NULL);

	return NM_BLUEZ_ADAPTER_GET_PRIVATE (self)->path;
}

const char *
nm_bluez_adapter_get_address (NMBluezAdapter *self)
{
	g_return_val_if_fail (NM_IS_BLUEZ_ADAPTER (self), NULL);

	return NM_BLUEZ_ADAPTER_GET_PRIVATE (self)->address;
}

gboolean
nm_bluez_adapter_get_initialized (NMBluezAdapter *self)
{
	g_return_val_if_fail (NM_IS_BLUEZ_ADAPTER (self), FALSE);

	return NM_BLUEZ_ADAPTER_GET_PRIVATE (self)->initialized;
}

static void
devices_to_list (gpointer key, gpointer data, gpointer user_data)
{
	NMBluezDevice *device = NM_BLUEZ_DEVICE (data);
	GSList **list = user_data;

	if (nm_bluez_device_get_usable (device))
		*list = g_slist_append (*list, data);
}

GSList *
nm_bluez_adapter_get_devices (NMBluezAdapter *self)
{
	NMBluezAdapterPrivate *priv = NM_BLUEZ_ADAPTER_GET_PRIVATE (self);
	GSList *devices = NULL;

	g_hash_table_foreach (priv->devices, devices_to_list, &devices);
	return devices;
}

static void
device_usable (NMBluezDevice *device, GParamSpec *pspec, gpointer user_data)
{
	NMBluezAdapter *self = NM_BLUEZ_ADAPTER (user_data);
	NMBluezAdapterPrivate *priv = NM_BLUEZ_ADAPTER_GET_PRIVATE (self);

	if (nm_bluez_device_get_usable (device))
		g_signal_emit (self, signals[DEVICE_ADDED], 0, device);
	else {
		g_object_ref (device);
		g_hash_table_remove (priv->devices, nm_bluez_device_get_path (device));
		g_signal_emit (self, signals[DEVICE_REMOVED], 0, device);
		g_object_unref (device);
	}
}

static void
device_initialized (NMBluezDevice *device, gboolean success, gpointer user_data)
{
	NMBluezAdapter *self = NM_BLUEZ_ADAPTER (user_data);
	NMBluezAdapterPrivate *priv = NM_BLUEZ_ADAPTER_GET_PRIVATE (self);

	if (!success)
		g_hash_table_remove (priv->devices, nm_bluez_device_get_path (device));
}

static void
device_created (DBusGProxy *proxy, const char *path, gpointer user_data)
{
	NMBluezAdapter *self = NM_BLUEZ_ADAPTER (user_data);
	NMBluezAdapterPrivate *priv = NM_BLUEZ_ADAPTER_GET_PRIVATE (self);
	NMBluezDevice *device;

	device = nm_bluez_device_new (path);
	g_signal_connect (device, "initialized", G_CALLBACK (device_initialized), self);
	g_signal_connect (device, "notify::usable", G_CALLBACK (device_usable), self);
	g_hash_table_insert (priv->devices, g_strdup (path), device);
}

static void
device_removed (DBusGProxy *proxy, const char *path, gpointer user_data)
{
	NMBluezAdapter *self = NM_BLUEZ_ADAPTER (user_data);
	NMBluezAdapterPrivate *priv = NM_BLUEZ_ADAPTER_GET_PRIVATE (self);
	NMBluezDevice *device;

	device = g_hash_table_lookup (priv->devices, path);
	if (device) {
		g_object_ref (device);
		g_hash_table_remove (priv->devices, path);
		g_signal_emit (self, signals[DEVICE_REMOVED], 0, device);
		g_object_unref (device);
	}
}


static void
get_properties_cb (DBusGProxy *proxy, DBusGProxyCall *call, gpointer user_data)
{
	NMBluezAdapter *self = NM_BLUEZ_ADAPTER (user_data);
	NMBluezAdapterPrivate *priv = NM_BLUEZ_ADAPTER_GET_PRIVATE (self);
	GHashTable *properties = NULL;
	GError *err = NULL;
	GValue *value;
	GPtrArray *devices;
	int i;

	if (!dbus_g_proxy_end_call (proxy, call, &err,
	                            DBUS_TYPE_G_MAP_OF_VARIANT, &properties,
	                            G_TYPE_INVALID)) {
		nm_log_warn (LOGD_BT, "bluez error getting adapter properties: %s",
		             err && err->message ? err->message : "(unknown)");
		g_error_free (err);
		goto done;
	}

	value = g_hash_table_lookup (properties, "Address");
	priv->address = value ? g_value_dup_string (value) : NULL;

	value = g_hash_table_lookup (properties, "Devices");
	devices = value ? g_value_get_boxed (value) : NULL;

	for (i = 0; devices && i < devices->len; i++)
 		device_created (priv->proxy, g_ptr_array_index (devices, i), self);

	g_hash_table_unref (properties);

	priv->initialized = TRUE;

done:
	g_signal_emit (self, signals[INITIALIZED], 0, priv->initialized);
}

static void
query_properties (NMBluezAdapter *self)
{
	NMBluezAdapterPrivate *priv = NM_BLUEZ_ADAPTER_GET_PRIVATE (self);
	DBusGProxyCall *call;

	call = dbus_g_proxy_begin_call (priv->proxy, "GetProperties",
	                                get_properties_cb,
	                                self,
	                                NULL, G_TYPE_INVALID);
	if (!call) {
		nm_log_warn (LOGD_BT, "failed to request Bluetooth adapter properties for %s.",
		             priv->path);
	}
}

NMBluezAdapter *
nm_bluez_adapter_new (const char *path)
{
	NMBluezAdapter *self;
	NMBluezAdapterPrivate *priv;
	NMDBusManager *dbus_mgr;
	DBusGConnection *connection;

	self = (NMBluezAdapter *) g_object_new (NM_TYPE_BLUEZ_ADAPTER,
	                                        NM_BLUEZ_ADAPTER_PATH, path,
	                                        NULL);
	if (!self)
		return NULL;

	priv = NM_BLUEZ_ADAPTER_GET_PRIVATE (self);
	dbus_mgr = nm_dbus_manager_get ();
	connection = nm_dbus_manager_get_connection (dbus_mgr);

	priv->proxy = dbus_g_proxy_new_for_name (connection,
	                                         BLUEZ_SERVICE,
	                                         priv->path,
	                                         BLUEZ_ADAPTER_INTERFACE);
	g_object_unref (dbus_mgr);

	dbus_g_proxy_add_signal (priv->proxy, "DeviceCreated",
	                         DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "DeviceCreated",
	                             G_CALLBACK (device_created), self, NULL);

	dbus_g_proxy_add_signal (priv->proxy, "DeviceRemoved",
	                         DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "DeviceRemoved",
	                             G_CALLBACK (device_removed), self, NULL);

	query_properties (self);
	return self;
}

static void
nm_bluez_adapter_init (NMBluezAdapter *self)
{
	NMBluezAdapterPrivate *priv = NM_BLUEZ_ADAPTER_GET_PRIVATE (self);

	priv->devices = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                       g_free, g_object_unref);
}

static void
finalize (GObject *object)
{
	NMBluezAdapterPrivate *priv = NM_BLUEZ_ADAPTER_GET_PRIVATE (object);

	g_hash_table_destroy (priv->devices);
	g_free (priv->address);
	g_free (priv->path);
	g_object_unref (priv->proxy);

	G_OBJECT_CLASS (nm_bluez_adapter_parent_class)->finalize (object);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMBluezAdapterPrivate *priv = NM_BLUEZ_ADAPTER_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_PATH:
		g_value_set_string (value, priv->path);
		break;
	case PROP_ADDRESS:
		g_value_set_string (value, priv->address);
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
	NMBluezAdapterPrivate *priv = NM_BLUEZ_ADAPTER_GET_PRIVATE (object);

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
nm_bluez_adapter_class_init (NMBluezAdapterClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);

	g_type_class_add_private (config_class, sizeof (NMBluezAdapterPrivate));

	/* virtual methods */
	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->finalize = finalize;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_PATH,
		 g_param_spec_string (NM_BLUEZ_ADAPTER_PATH,
		                      "DBus Path",
		                      "DBus Path",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_ADDRESS,
		 g_param_spec_string (NM_BLUEZ_ADAPTER_ADDRESS,
		                      "Address",
		                      "Address",
		                      NULL,
		                      G_PARAM_READABLE));

	/* Signals */
	signals[INITIALIZED] = g_signal_new ("initialized",
	                                     G_OBJECT_CLASS_TYPE (object_class),
	                                     G_SIGNAL_RUN_LAST,
	                                     G_STRUCT_OFFSET (NMBluezAdapterClass, initialized),
	                                     NULL, NULL,
	                                     g_cclosure_marshal_VOID__BOOLEAN,
	                                     G_TYPE_NONE, 1, G_TYPE_BOOLEAN);

	signals[DEVICE_ADDED] = g_signal_new ("device-added",
	                                      G_OBJECT_CLASS_TYPE (object_class),
	                                      G_SIGNAL_RUN_LAST,
	                                      G_STRUCT_OFFSET (NMBluezAdapterClass, device_added),
	                                      NULL, NULL,
	                                      g_cclosure_marshal_VOID__OBJECT,
	                                      G_TYPE_NONE, 1, G_TYPE_OBJECT);

	signals[DEVICE_REMOVED] = g_signal_new ("device-removed",
	                                        G_OBJECT_CLASS_TYPE (object_class),
	                                        G_SIGNAL_RUN_LAST,
	                                        G_STRUCT_OFFSET (NMBluezAdapterClass, device_removed),
	                                        NULL, NULL,
	                                        g_cclosure_marshal_VOID__OBJECT,
	                                        G_TYPE_NONE, 1, G_TYPE_OBJECT);
}

