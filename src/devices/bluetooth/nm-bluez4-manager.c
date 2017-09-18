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
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2013 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-bluez4-manager.h"

#include <signal.h>
#include <string.h>
#include <stdlib.h>

#include "nm-bluez4-adapter.h"
#include "nm-bluez-common.h"
#include "nm-core-internal.h"
#include "settings/nm-settings.h"

/*****************************************************************************/

enum {
	BDADDR_ADDED,
	LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	gulong name_owner_changed_id;

	NMSettings *settings;

	GDBusProxy *proxy;
	GCancellable *proxy_cancellable;

	NMBluez4Adapter *adapter;
} NMBluez4ManagerPrivate;

struct _NMBluez4Manager {
	GObject parent;
	NMBluez4ManagerPrivate _priv;
};

struct _NMBluez4ManagerClass {
	GObjectClass parent;
};

G_DEFINE_TYPE (NMBluez4Manager, nm_bluez4_manager, G_TYPE_OBJECT)

#define NM_BLUEZ4_MANAGER_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMBluez4Manager, NM_IS_BLUEZ4_MANAGER)

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_BT
#define _NMLOG(level, ...) __NMLOG_DEFAULT (level, _NMLOG_DOMAIN, "bluez4-manager", __VA_ARGS__)

/*****************************************************************************/

static void
emit_bdaddr_added (NMBluez4Manager *self, NMBluezDevice *device)
{
	g_signal_emit (self, signals[BDADDR_ADDED], 0,
	               device,
	               nm_bluez_device_get_address (device),
	               nm_bluez_device_get_name (device),
	               nm_bluez_device_get_path (device),
	               nm_bluez_device_get_capabilities (device));
}

void
nm_bluez4_manager_query_devices (NMBluez4Manager *self)
{
	NMBluez4ManagerPrivate *priv = NM_BLUEZ4_MANAGER_GET_PRIVATE (self);
	GSList *devices, *iter;

	if (!priv->adapter)
		return;

	devices = nm_bluez4_adapter_get_devices (priv->adapter);
	for (iter = devices; iter; iter = g_slist_next (iter))
		emit_bdaddr_added (self, NM_BLUEZ_DEVICE (iter->data));
	g_slist_free (devices);
}

static void
device_added (NMBluez4Adapter *adapter, NMBluezDevice *device, gpointer user_data)
{
	emit_bdaddr_added (NM_BLUEZ4_MANAGER (user_data), device);
}

static void
device_removed (NMBluez4Adapter *adapter, NMBluezDevice *device, gpointer user_data)
{
	/* Re-emit the signal on the device for now; flatten this later */
	g_signal_emit_by_name (device, NM_BLUEZ_DEVICE_REMOVED);
}

static void
adapter_initialized (NMBluez4Adapter *adapter, gboolean success, gpointer user_data)
{
	NMBluez4Manager *self = NM_BLUEZ4_MANAGER (user_data);
	NMBluez4ManagerPrivate *priv = NM_BLUEZ4_MANAGER_GET_PRIVATE (self);

	if (success) {
		GSList *devices, *iter;

		devices = nm_bluez4_adapter_get_devices (adapter);
		for (iter = devices; iter; iter = g_slist_next (iter))
			emit_bdaddr_added (self, NM_BLUEZ_DEVICE (iter->data));
		g_slist_free (devices);

		g_signal_connect (adapter, NM_BLUEZ4_ADAPTER_DEVICE_ADDED,
		                  G_CALLBACK (device_added), self);
		g_signal_connect (adapter, NM_BLUEZ4_ADAPTER_DEVICE_REMOVED,
		                  G_CALLBACK (device_removed), self);
	} else {
		g_object_unref (priv->adapter);
		priv->adapter = NULL;
	}
}

static void
adapter_removed (GDBusProxy *proxy, const char *path, NMBluez4Manager *self)
{
	NMBluez4ManagerPrivate *priv = NM_BLUEZ4_MANAGER_GET_PRIVATE (self);

	if (priv->adapter && !strcmp (path, nm_bluez4_adapter_get_path (priv->adapter))) {
		if (nm_bluez4_adapter_get_initialized (priv->adapter)) {
			GSList *devices, *iter;

			devices = nm_bluez4_adapter_get_devices (priv->adapter);
			for (iter = devices; iter; iter = g_slist_next (iter))
				g_signal_emit_by_name (NM_BLUEZ_DEVICE (iter->data), NM_BLUEZ_DEVICE_REMOVED);
			g_slist_free (devices);
		}

		g_object_unref (priv->adapter);
		priv->adapter = NULL;
	}
}

static void
default_adapter_changed (GDBusProxy *proxy, const char *path, NMBluez4Manager *self)
{
	NMBluez4ManagerPrivate *priv = NM_BLUEZ4_MANAGER_GET_PRIVATE (self);
	const char *cur_path = NULL;

	if (priv->adapter)
		cur_path = nm_bluez4_adapter_get_path (priv->adapter);

	if (cur_path) {
		if (!path || strcmp (path, cur_path)) {
			/* Default adapter changed */
			adapter_removed (priv->proxy, cur_path, self);
		} else {
			/* This adapter is already the default */
			return;
		}
	}

	/* Add the new default adapter */
	if (path) {
		priv->adapter = nm_bluez4_adapter_new (path, priv->settings);
		g_signal_connect (priv->adapter, NM_BLUEZ4_ADAPTER_INITIALIZED,
		                  G_CALLBACK (adapter_initialized), self);
	}
}

static void
default_adapter_cb (GObject *proxy, GAsyncResult *result, gpointer user_data)
{
	NMBluez4Manager *self;
	NMBluez4ManagerPrivate *priv;
	gs_unref_variant GVariant *ret = NULL;
	gs_free_error GError *error = NULL;
	const char *default_adapter;

	ret = _nm_dbus_proxy_call_finish (G_DBUS_PROXY (proxy), result,
	                                  G_VARIANT_TYPE ("(o)"), &error);
	if (   !ret
	    && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = NM_BLUEZ4_MANAGER (user_data);
	priv = NM_BLUEZ4_MANAGER_GET_PRIVATE (self);

	g_clear_object (&priv->proxy_cancellable);

	if (!ret) {
		/* Ignore "No such adapter" errors; just means bluetooth isn't active */
		if (   !_nm_dbus_error_has_name (error, "org.bluez.Error.NoSuchAdapter")
		    && !_nm_dbus_error_has_name (error, "org.freedesktop.systemd1.LoadFailed")
		    && !g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_SERVICE_UNKNOWN)) {
			g_dbus_error_strip_remote_error (error);
			_LOGW ("bluez error getting default adapter: %s",
			       error->message);
		}
		return;
	}

	g_variant_get (ret, "(&o)", &default_adapter);
	default_adapter_changed (priv->proxy, default_adapter, self);
}

static void
name_owner_changed (NMBluez4Manager *self)
{
	NMBluez4ManagerPrivate *priv = NM_BLUEZ4_MANAGER_GET_PRIVATE (self);
	gs_free char *owner = NULL;

	nm_clear_g_cancellable (&priv->proxy_cancellable);

	owner = g_dbus_proxy_get_name_owner (priv->proxy);
	if (!owner) {
		/* Throwing away the adapter removes all devices too */
		g_clear_object (&priv->adapter);
		return;
	}

	priv->proxy_cancellable = g_cancellable_new ();

	g_dbus_proxy_call (priv->proxy, "DefaultAdapter",
	                   NULL,
	                   G_DBUS_CALL_FLAGS_NONE, -1,
	                   priv->proxy_cancellable,
	                   default_adapter_cb,
	                   self);
}

static void
name_owner_changed_cb (GObject *object,
                       GParamSpec *pspec,
                       gpointer user_data)
{
	name_owner_changed (user_data);
}

static void
_proxy_new_cb (GObject *source_object,
               GAsyncResult *result,
               gpointer user_data)
{
	NMBluez4Manager *self;
	NMBluez4ManagerPrivate *priv;
	gs_free_error GError *error = NULL;
	GDBusProxy *proxy;

	proxy = g_dbus_proxy_new_for_bus_finish (result, &error);
	if (   !proxy
	    && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = user_data;
	priv = NM_BLUEZ4_MANAGER_GET_PRIVATE (self);

	if (!proxy) {
		_LOGW ("bluez error creating D-Bus proxy: %s", error->message);
		g_clear_object (&priv->proxy_cancellable);
		return;
	}

	priv->proxy = proxy;

	_nm_dbus_signal_connect (priv->proxy, "AdapterRemoved", G_VARIANT_TYPE ("(o)"),
	                         G_CALLBACK (adapter_removed), self);
	_nm_dbus_signal_connect (priv->proxy, "DefaultAdapterChanged", G_VARIANT_TYPE ("(o)"),
	                         G_CALLBACK (default_adapter_changed), self);
	g_signal_connect (priv->proxy, "notify::g-name-owner",
	                  G_CALLBACK (name_owner_changed_cb), self);

	name_owner_changed (self);
}

/*****************************************************************************/

static void
nm_bluez4_manager_init (NMBluez4Manager *self)
{
	NMBluez4ManagerPrivate *priv = NM_BLUEZ4_MANAGER_GET_PRIVATE (self);

	priv->proxy_cancellable = g_cancellable_new ();

	g_dbus_proxy_new_for_bus (G_BUS_TYPE_SYSTEM,
	                          G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
	                          NULL,
	                          NM_BLUEZ_SERVICE,
	                          NM_BLUEZ_MANAGER_PATH,
	                          NM_BLUEZ4_MANAGER_INTERFACE,
	                          priv->proxy_cancellable,
	                          _proxy_new_cb,
	                          self);
}

NMBluez4Manager *
nm_bluez4_manager_new (NMSettings *settings)
{
	NMBluez4Manager *instance;

	g_return_val_if_fail (NM_IS_SETTINGS (settings), NULL);

	instance = g_object_new (NM_TYPE_BLUEZ4_MANAGER, NULL);
	NM_BLUEZ4_MANAGER_GET_PRIVATE (instance)->settings = g_object_ref (settings);
	return instance;
}

static void
dispose (GObject *object)
{
	NMBluez4Manager *self = NM_BLUEZ4_MANAGER (object);
	NMBluez4ManagerPrivate *priv = NM_BLUEZ4_MANAGER_GET_PRIVATE (self);

	nm_clear_g_cancellable (&priv->proxy_cancellable);

	if (priv->proxy) {
		g_signal_handlers_disconnect_by_data (priv->proxy, self);
		g_clear_object (&priv->proxy);
	}

	g_clear_object (&priv->adapter);

	G_OBJECT_CLASS (nm_bluez4_manager_parent_class)->dispose (object);

	g_clear_object (&priv->settings);
}

static void
nm_bluez4_manager_class_init (NMBluez4ManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->dispose = dispose;

	signals[BDADDR_ADDED] =
	    g_signal_new (NM_BLUEZ_MANAGER_BDADDR_ADDED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 5, G_TYPE_OBJECT, G_TYPE_STRING,
	                  G_TYPE_STRING, G_TYPE_STRING, G_TYPE_UINT);
}

