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

#include "NetworkManager.h"
#include "nm-dbus-manager.h"
#include "nm-bluez4-adapter.h"
#include "nm-bluez-device.h"
#include "nm-bluez-common.h"
#include "nm-dbus-glib-types.h"
#include "nm-logging.h"


G_DEFINE_TYPE (NMBluez4Adapter, nm_bluez4_adapter, G_TYPE_OBJECT)

#define NM_BLUEZ4_ADAPTER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_BLUEZ4_ADAPTER, NMBluez4AdapterPrivate))

typedef struct {
	char *path;
	DBusGProxy *proxy;
	gboolean initialized;

	char *address;
	GHashTable *devices;

	/* Cached for devices */
	NMConnectionProvider *provider;
} NMBluez4AdapterPrivate;


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

static void device_do_remove (NMBluez4Adapter *self, NMBluezDevice *device);

const char *
nm_bluez4_adapter_get_path (NMBluez4Adapter *self)
{
	g_return_val_if_fail (NM_IS_BLUEZ4_ADAPTER (self), NULL);

	return NM_BLUEZ4_ADAPTER_GET_PRIVATE (self)->path;
}

const char *
nm_bluez4_adapter_get_address (NMBluez4Adapter *self)
{
	g_return_val_if_fail (NM_IS_BLUEZ4_ADAPTER (self), NULL);

	return NM_BLUEZ4_ADAPTER_GET_PRIVATE (self)->address;
}

gboolean
nm_bluez4_adapter_get_initialized (NMBluez4Adapter *self)
{
	g_return_val_if_fail (NM_IS_BLUEZ4_ADAPTER (self), FALSE);

	return NM_BLUEZ4_ADAPTER_GET_PRIVATE (self)->initialized;
}

GSList *
nm_bluez4_adapter_get_devices (NMBluez4Adapter *self)
{
	GSList *devices = NULL;
	GHashTableIter iter;
	NMBluezDevice *device;

	g_hash_table_iter_init (&iter, NM_BLUEZ4_ADAPTER_GET_PRIVATE (self)->devices);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer) &device)) {
		if (nm_bluez_device_get_usable (device))
			devices = g_slist_append (devices, device);
	}
	return devices;
}

static void
emit_device_removed (NMBluez4Adapter *self, NMBluezDevice *device)
{
	nm_log_dbg (LOGD_BT, "(%s): bluez device now unusable",
	            nm_bluez_device_get_path (device));
	g_signal_emit (self, signals[DEVICE_REMOVED], 0, device);
}

static void
device_usable (NMBluezDevice *device, GParamSpec *pspec, gpointer user_data)
{
	NMBluez4Adapter *self = NM_BLUEZ4_ADAPTER (user_data);

	if (nm_bluez_device_get_usable (device)) {
		nm_log_dbg (LOGD_BT, "(%s): bluez device now usable (device address is %s)",
		            nm_bluez_device_get_path (device),
		            nm_bluez_device_get_address (device));
		g_signal_emit (self, signals[DEVICE_ADDED], 0, device);
	} else
		emit_device_removed (self, device);
}

static void
device_initialized (NMBluezDevice *device, gboolean success, gpointer user_data)
{
	NMBluez4Adapter *self = NM_BLUEZ4_ADAPTER (user_data);

	nm_log_dbg (LOGD_BT, "(%s): bluez device %s",
	            nm_bluez_device_get_path (device),
	            success ? "initialized" : "failed to initialize");
	if (!success)
		device_do_remove (self, device);
}

static void
device_do_remove (NMBluez4Adapter *self, NMBluezDevice *device)
{
	NMBluez4AdapterPrivate *priv = NM_BLUEZ4_ADAPTER_GET_PRIVATE (self);

	if (g_hash_table_remove (priv->devices, nm_bluez_device_get_path (device))) {
		g_signal_handlers_disconnect_by_func (device, G_CALLBACK (device_initialized), self);
		g_signal_handlers_disconnect_by_func (device, G_CALLBACK (device_usable), self);

		if (nm_bluez_device_get_usable (device))
			emit_device_removed (self, device);

		g_object_unref (device);
	}
}

static void
device_created (DBusGProxy *proxy, const char *path, gpointer user_data)
{
	NMBluez4Adapter *self = NM_BLUEZ4_ADAPTER (user_data);
	NMBluez4AdapterPrivate *priv = NM_BLUEZ4_ADAPTER_GET_PRIVATE (self);
	NMBluezDevice *device;

	device = nm_bluez_device_new (path, priv->provider, 4);
	g_signal_connect (device, "initialized", G_CALLBACK (device_initialized), self);
	g_signal_connect (device, "notify::usable", G_CALLBACK (device_usable), self);
	g_hash_table_insert (priv->devices, (gpointer) nm_bluez_device_get_path (device), device);

	nm_log_dbg (LOGD_BT, "(%s): new bluez device found", path);
}

static void
device_removed (DBusGProxy *proxy, const char *path, gpointer user_data)
{
	NMBluez4Adapter *self = NM_BLUEZ4_ADAPTER (user_data);
	NMBluez4AdapterPrivate *priv = NM_BLUEZ4_ADAPTER_GET_PRIVATE (self);
	NMBluezDevice *device;

	nm_log_dbg (LOGD_BT, "(%s): bluez device removed", path);

	device = g_hash_table_lookup (priv->devices, path);
	if (device)
		device_do_remove (self, device);
}


static void
get_properties_cb (DBusGProxy *proxy, DBusGProxyCall *call, gpointer user_data)
{
	NMBluez4Adapter *self = NM_BLUEZ4_ADAPTER (user_data);
	NMBluez4AdapterPrivate *priv = NM_BLUEZ4_ADAPTER_GET_PRIVATE (self);
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
query_properties (NMBluez4Adapter *self)
{
	NMBluez4AdapterPrivate *priv = NM_BLUEZ4_ADAPTER_GET_PRIVATE (self);
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

/***********************************************************/

NMBluez4Adapter *
nm_bluez4_adapter_new (const char *path, NMConnectionProvider *provider)
{
	NMBluez4Adapter *self;
	NMBluez4AdapterPrivate *priv;
	DBusGConnection *connection;

	self = (NMBluez4Adapter *) g_object_new (NM_TYPE_BLUEZ4_ADAPTER,
	                                         NM_BLUEZ4_ADAPTER_PATH, path,
	                                         NULL);
	if (!self)
		return NULL;

	priv = NM_BLUEZ4_ADAPTER_GET_PRIVATE (self);

	priv->provider = provider;

	connection = nm_dbus_manager_get_connection (nm_dbus_manager_get ());

	priv->proxy = dbus_g_proxy_new_for_name (connection,
	                                         BLUEZ_SERVICE,
	                                         priv->path,
	                                         BLUEZ4_ADAPTER_INTERFACE);

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
nm_bluez4_adapter_init (NMBluez4Adapter *self)
{
	NMBluez4AdapterPrivate *priv = NM_BLUEZ4_ADAPTER_GET_PRIVATE (self);

	priv->devices = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                       NULL, NULL);
}

static gboolean
_find_all (gpointer key, gpointer value, gpointer user_data)
{
	return TRUE;
}

static void
dispose (GObject *object)
{
	NMBluez4Adapter *self = NM_BLUEZ4_ADAPTER (object);
	NMBluez4AdapterPrivate *priv = NM_BLUEZ4_ADAPTER_GET_PRIVATE (self);
	NMBluezDevice *device;

	while ((device = g_hash_table_find (priv->devices, _find_all, NULL)))
		device_do_remove (self, device);

	G_OBJECT_CLASS (nm_bluez4_adapter_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMBluez4AdapterPrivate *priv = NM_BLUEZ4_ADAPTER_GET_PRIVATE (object);

	g_hash_table_destroy (priv->devices);
	g_free (priv->address);
	g_free (priv->path);
	g_object_unref (priv->proxy);

	G_OBJECT_CLASS (nm_bluez4_adapter_parent_class)->finalize (object);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMBluez4AdapterPrivate *priv = NM_BLUEZ4_ADAPTER_GET_PRIVATE (object);

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
	NMBluez4AdapterPrivate *priv = NM_BLUEZ4_ADAPTER_GET_PRIVATE (object);

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
nm_bluez4_adapter_class_init (NMBluez4AdapterClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);

	g_type_class_add_private (config_class, sizeof (NMBluez4AdapterPrivate));

	/* virtual methods */
	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_PATH,
		 g_param_spec_string (NM_BLUEZ4_ADAPTER_PATH,
		                      "DBus Path",
		                      "DBus Path",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_ADDRESS,
		 g_param_spec_string (NM_BLUEZ4_ADAPTER_ADDRESS,
		                      "Address",
		                      "Address",
		                      NULL,
		                      G_PARAM_READABLE));

	/* Signals */
	signals[INITIALIZED] = g_signal_new ("initialized",
	                                     G_OBJECT_CLASS_TYPE (object_class),
	                                     G_SIGNAL_RUN_LAST,
	                                     G_STRUCT_OFFSET (NMBluez4AdapterClass, initialized),
	                                     NULL, NULL,
	                                     g_cclosure_marshal_VOID__BOOLEAN,
	                                     G_TYPE_NONE, 1, G_TYPE_BOOLEAN);

	signals[DEVICE_ADDED] = g_signal_new ("device-added",
	                                      G_OBJECT_CLASS_TYPE (object_class),
	                                      G_SIGNAL_RUN_LAST,
	                                      G_STRUCT_OFFSET (NMBluez4AdapterClass, device_added),
	                                      NULL, NULL,
	                                      g_cclosure_marshal_VOID__OBJECT,
	                                      G_TYPE_NONE, 1, G_TYPE_OBJECT);

	signals[DEVICE_REMOVED] = g_signal_new ("device-removed",
	                                        G_OBJECT_CLASS_TYPE (object_class),
	                                        G_SIGNAL_RUN_LAST,
	                                        G_STRUCT_OFFSET (NMBluez4AdapterClass, device_removed),
	                                        NULL, NULL,
	                                        g_cclosure_marshal_VOID__OBJECT,
	                                        G_TYPE_NONE, 1, G_TYPE_OBJECT);
}

