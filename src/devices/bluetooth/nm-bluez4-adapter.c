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

#include "nm-default.h"

#include "nm-bluez4-adapter.h"

#include "nm-dbus-interface.h"
#include "nm-bluez-device.h"
#include "nm-bluez-common.h"
#include "nm-core-internal.h"
#include "settings/nm-settings.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_PATH,
	PROP_ADDRESS,
);

enum {
	INITIALIZED,
	DEVICE_ADDED,
	DEVICE_REMOVED,
	LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	char *path;
	GDBusProxy *proxy;
	GCancellable *proxy_cancellable;
	gboolean initialized;

	char *address;
	GHashTable *devices;

	/* Cached for devices */
	NMSettings *settings;
} NMBluez4AdapterPrivate;

struct _NMBluez4Adapter {
	GObject parent;
	NMBluez4AdapterPrivate _priv;
};

struct _NMBluez4AdapterClass {
	GObjectClass parent;
};

G_DEFINE_TYPE (NMBluez4Adapter, nm_bluez4_adapter, G_TYPE_OBJECT)

#define NM_BLUEZ4_ADAPTER_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMBluez4Adapter, NM_IS_BLUEZ4_ADAPTER)

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_BT
#define _NMLOG(level, ...) __NMLOG_DEFAULT (level, _NMLOG_DOMAIN, "bluez4-adapter", __VA_ARGS__)

/*****************************************************************************/

static void device_do_remove (NMBluez4Adapter *self, NMBluezDevice *device);

/*****************************************************************************/

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
	_LOGD ("(%s): bluez device now unusable",
	       nm_bluez_device_get_path (device));
	g_signal_emit (self, signals[DEVICE_REMOVED], 0, device);
}

static void
device_usable (NMBluezDevice *device, GParamSpec *pspec, gpointer user_data)
{
	NMBluez4Adapter *self = NM_BLUEZ4_ADAPTER (user_data);

	if (nm_bluez_device_get_usable (device)) {
		_LOGD ("(%s): bluez device now usable (device address is %s)",
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

	_LOGD ("(%s): bluez device %s",
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
device_created (GDBusProxy *proxy, const char *path, gpointer user_data)
{
	NMBluez4Adapter *self = NM_BLUEZ4_ADAPTER (user_data);
	NMBluez4AdapterPrivate *priv = NM_BLUEZ4_ADAPTER_GET_PRIVATE (self);
	NMBluezDevice *device;

	device = nm_bluez_device_new (path, priv->address, priv->settings, 4);
	g_signal_connect (device, NM_BLUEZ_DEVICE_INITIALIZED, G_CALLBACK (device_initialized), self);
	g_signal_connect (device, "notify::" NM_BLUEZ_DEVICE_USABLE, G_CALLBACK (device_usable), self);
	g_hash_table_insert (priv->devices, (gpointer) nm_bluez_device_get_path (device), device);

	_LOGD ("(%s): new bluez device found", path);
}

static void
device_removed (GDBusProxy *proxy, const char *path, gpointer user_data)
{
	NMBluez4Adapter *self = NM_BLUEZ4_ADAPTER (user_data);
	NMBluez4AdapterPrivate *priv = NM_BLUEZ4_ADAPTER_GET_PRIVATE (self);
	NMBluezDevice *device;

	_LOGD ("(%s): bluez device removed", path);

	device = g_hash_table_lookup (priv->devices, path);
	if (device)
		device_do_remove (self, device);
}

static void
get_properties_cb (GObject *proxy, GAsyncResult *result, gpointer user_data)
{
	NMBluez4Adapter *self;
	NMBluez4AdapterPrivate *priv;
	gs_free_error GError *error = NULL;
	GVariant *ret, *properties;
	char **devices;
	int i;

	ret = _nm_dbus_proxy_call_finish (G_DBUS_PROXY (proxy), result,
	                                  G_VARIANT_TYPE ("(a{sv})"), &error);

	if (   !ret
	    && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = NM_BLUEZ4_ADAPTER (user_data);
	priv = NM_BLUEZ4_ADAPTER_GET_PRIVATE (self);

	g_clear_object (&priv->proxy_cancellable);

	if (!ret) {
		g_dbus_error_strip_remote_error (error);
		_LOGW ("bluez error getting adapter properties: %s", error->message);
		goto done;
	}

	properties = g_variant_get_child_value (ret, 0);

	(void) g_variant_lookup (properties, "Address", "s", &priv->address);
	if (g_variant_lookup (properties, "Devices", "^ao", &devices)) {
		for (i = 0; devices[i]; i++)
			device_created (priv->proxy, devices[i], self);
		g_strfreev (devices);
	}

	g_variant_unref (properties);
	g_variant_unref (ret);

	priv->initialized = TRUE;

done:
	g_signal_emit (self, signals[INITIALIZED], 0, priv->initialized);
}

static void
_proxy_new_cb (GObject *source_object,
               GAsyncResult *result,
               gpointer user_data)
{
	NMBluez4Adapter *self;
	NMBluez4AdapterPrivate *priv;
	gs_free_error GError *error = NULL;
	GDBusProxy *proxy;

	proxy = g_dbus_proxy_new_for_bus_finish (result, &error);
	if (   !proxy
	    && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = user_data;
	priv = NM_BLUEZ4_ADAPTER_GET_PRIVATE (self);

	if (!proxy) {
		_LOGW ("bluez error creating D-Bus proxy: %s", error->message);
		g_clear_object (&priv->proxy_cancellable);
		g_signal_emit (self, signals[INITIALIZED], 0, priv->initialized);
		return;
	}

	priv->proxy = proxy;

	_nm_dbus_signal_connect (priv->proxy, "DeviceCreated", G_VARIANT_TYPE ("(o)"),
	                         G_CALLBACK (device_created), self);
	_nm_dbus_signal_connect (priv->proxy, "DeviceRemoved", G_VARIANT_TYPE ("(o)"),
	                         G_CALLBACK (device_removed), self);

	g_dbus_proxy_call (priv->proxy, "GetProperties",
	                   NULL,
	                   G_DBUS_CALL_FLAGS_NONE, -1,
	                   priv->proxy_cancellable,
	                   get_properties_cb,
	                   self);
}

/*****************************************************************************/

static gboolean
_find_all (gpointer key, gpointer value, gpointer user_data)
{
	return TRUE;
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMBluez4AdapterPrivate *priv = NM_BLUEZ4_ADAPTER_GET_PRIVATE ((NMBluez4Adapter *) object);

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
	NMBluez4AdapterPrivate *priv = NM_BLUEZ4_ADAPTER_GET_PRIVATE ((NMBluez4Adapter *) object);

	switch (prop_id) {
	case PROP_PATH:
		/* construct-only */
		priv->path = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_bluez4_adapter_init (NMBluez4Adapter *self)
{
	NMBluez4AdapterPrivate *priv = NM_BLUEZ4_ADAPTER_GET_PRIVATE (self);

	priv->devices = g_hash_table_new_full (nm_str_hash, g_str_equal,
	                                       NULL, NULL);
}

NMBluez4Adapter *
nm_bluez4_adapter_new (const char *path, NMSettings *settings)
{
	NMBluez4Adapter *self;
	NMBluez4AdapterPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTINGS (settings), NULL);

	self = (NMBluez4Adapter *) g_object_new (NM_TYPE_BLUEZ4_ADAPTER,
	                                         NM_BLUEZ4_ADAPTER_PATH, path,
	                                         NULL);
	priv = NM_BLUEZ4_ADAPTER_GET_PRIVATE (self);

	priv->settings = g_object_ref (settings);

	priv->proxy_cancellable = g_cancellable_new ();

	g_dbus_proxy_new_for_bus (G_BUS_TYPE_SYSTEM,
	                          G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
	                          NULL,
	                          NM_BLUEZ_SERVICE,
	                          priv->path,
	                          NM_BLUEZ4_ADAPTER_INTERFACE,
	                          priv->proxy_cancellable,
	                          _proxy_new_cb,
	                          self);
	return self;
}

static void
dispose (GObject *object)
{
	NMBluez4Adapter *self = NM_BLUEZ4_ADAPTER (object);
	NMBluez4AdapterPrivate *priv = NM_BLUEZ4_ADAPTER_GET_PRIVATE (self);
	NMBluezDevice *device;

	nm_clear_g_cancellable (&priv->proxy_cancellable);

	while ((device = g_hash_table_find (priv->devices, _find_all, NULL)))
		device_do_remove (self, device);

	if (priv->proxy) {
		g_signal_handlers_disconnect_by_data (priv->proxy, self);
		g_clear_object (&priv->proxy);
	}

	G_OBJECT_CLASS (nm_bluez4_adapter_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMBluez4Adapter *self = NM_BLUEZ4_ADAPTER (object);
	NMBluez4AdapterPrivate *priv = NM_BLUEZ4_ADAPTER_GET_PRIVATE (self);

	g_hash_table_destroy (priv->devices);
	g_free (priv->address);
	g_free (priv->path);

	G_OBJECT_CLASS (nm_bluez4_adapter_parent_class)->finalize (object);

	g_object_unref (priv->settings);
}

static void
nm_bluez4_adapter_class_init (NMBluez4AdapterClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);

	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	obj_properties[PROP_PATH] =
	     g_param_spec_string (NM_BLUEZ4_ADAPTER_PATH, "", "",
	                          NULL,
	                          G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_ADDRESS] =
	     g_param_spec_string (NM_BLUEZ4_ADAPTER_ADDRESS, "", "",
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	signals[INITIALIZED] = g_signal_new (NM_BLUEZ4_ADAPTER_INITIALIZED,
	                                     G_OBJECT_CLASS_TYPE (object_class),
	                                     G_SIGNAL_RUN_LAST,
	                                     0,
	                                     NULL, NULL,
	                                     g_cclosure_marshal_VOID__BOOLEAN,
	                                     G_TYPE_NONE, 1, G_TYPE_BOOLEAN);

	signals[DEVICE_ADDED] = g_signal_new (NM_BLUEZ4_ADAPTER_DEVICE_ADDED,
	                                      G_OBJECT_CLASS_TYPE (object_class),
	                                      G_SIGNAL_RUN_LAST,
	                                      0,
	                                      NULL, NULL,
	                                      g_cclosure_marshal_VOID__OBJECT,
	                                      G_TYPE_NONE, 1, G_TYPE_OBJECT);

	signals[DEVICE_REMOVED] = g_signal_new (NM_BLUEZ4_ADAPTER_DEVICE_REMOVED,
	                                        G_OBJECT_CLASS_TYPE (object_class),
	                                        G_SIGNAL_RUN_LAST,
	                                        0,
	                                        NULL, NULL,
	                                        g_cclosure_marshal_VOID__OBJECT,
	                                        G_TYPE_NONE, 1, G_TYPE_OBJECT);
}

