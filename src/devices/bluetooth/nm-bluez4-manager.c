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

#include "config.h"

#include <signal.h>
#include <string.h>
#include <stdlib.h>

#include "nm-default.h"
#include "nm-bluez-manager.h"
#include "nm-bluez4-manager.h"
#include "nm-bluez4-adapter.h"
#include "nm-bluez-common.h"
#include "nm-core-internal.h"

typedef struct {
	gulong name_owner_changed_id;

	NMConnectionProvider *provider;

	GDBusProxy *proxy;

	NMBluez4Adapter *adapter;
} NMBluez4ManagerPrivate;

#define NM_BLUEZ4_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_BLUEZ4_MANAGER, NMBluez4ManagerPrivate))

G_DEFINE_TYPE (NMBluez4Manager, nm_bluez4_manager, G_TYPE_OBJECT)

enum {
	BDADDR_ADDED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

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

		g_signal_connect (adapter, "device-added", G_CALLBACK (device_added), self);
		g_signal_connect (adapter, "device-removed", G_CALLBACK (device_removed), self);
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
		priv->adapter = nm_bluez4_adapter_new (path, priv->provider);
		g_signal_connect (priv->adapter, "initialized", G_CALLBACK (adapter_initialized), self);
	}
}

static void
default_adapter_cb (GObject *proxy, GAsyncResult *result, gpointer user_data)
{
	NMBluez4Manager *self = NM_BLUEZ4_MANAGER (user_data);
	NMBluez4ManagerPrivate *priv = NM_BLUEZ4_MANAGER_GET_PRIVATE (self);
	GVariant *ret;
	GError *err = NULL;

	ret = _nm_dbus_proxy_call_finish (G_DBUS_PROXY (proxy), result,
	                                  G_VARIANT_TYPE ("(o)"), &err);
	if (ret) {
		const char *default_adapter;

		g_variant_get (ret, "(&o)", &default_adapter);
		default_adapter_changed (priv->proxy, default_adapter, self);
		g_variant_unref (ret);
	} else {
		/* Ignore "No such adapter" errors; just means bluetooth isn't active */
		if (   !_nm_dbus_error_has_name (err, "org.bluez.Error.NoSuchAdapter")
		    && !_nm_dbus_error_has_name (err, "org.freedesktop.systemd1.LoadFailed")
		    && !g_error_matches (err, G_DBUS_ERROR, G_DBUS_ERROR_SERVICE_UNKNOWN)) {
			g_dbus_error_strip_remote_error (err);
			nm_log_warn (LOGD_BT, "bluez error getting default adapter: %s",
			             err->message);
		}
		g_error_free (err);
	}
}

static void
query_default_adapter (NMBluez4Manager *self)
{
	NMBluez4ManagerPrivate *priv = NM_BLUEZ4_MANAGER_GET_PRIVATE (self);

	g_dbus_proxy_call (priv->proxy, "DefaultAdapter",
	                   NULL,
	                   G_DBUS_CALL_FLAGS_NONE, -1,
	                   NULL,
	                   default_adapter_cb, self);
}

static void
name_owner_changed_cb (GObject *object,
                       GParamSpec *pspec,
                       gpointer user_data)
{
	NMBluez4Manager *self = NM_BLUEZ4_MANAGER (user_data);
	NMBluez4ManagerPrivate *priv = NM_BLUEZ4_MANAGER_GET_PRIVATE (self);
	char *owner;

	owner = g_dbus_proxy_get_name_owner (priv->proxy);
	if (owner) {
		query_default_adapter (self);
		g_free (owner);
	} else {
		/* Throwing away the adapter removes all devices too */
		g_clear_object (&priv->adapter);
	}
}

/****************************************************************/

NMBluez4Manager *
nm_bluez4_manager_new (NMConnectionProvider *provider)
{
	NMBluez4Manager *instance;

	instance = g_object_new (NM_TYPE_BLUEZ4_MANAGER, NULL);
	NM_BLUEZ4_MANAGER_GET_PRIVATE (instance)->provider = provider;
	return instance;
}

static void
nm_bluez4_manager_init (NMBluez4Manager *self)
{
	NMBluez4ManagerPrivate *priv = NM_BLUEZ4_MANAGER_GET_PRIVATE (self);

	priv->proxy = g_dbus_proxy_new_for_bus_sync (G_BUS_TYPE_SYSTEM,
	                                             G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
	                                             NULL,
	                                             BLUEZ_SERVICE,
	                                             BLUEZ_MANAGER_PATH,
	                                             BLUEZ4_MANAGER_INTERFACE,
	                                             NULL, NULL);
	_nm_dbus_signal_connect (priv->proxy, "AdapterRemoved", G_VARIANT_TYPE ("(o)"),
	                         G_CALLBACK (adapter_removed), self);
	_nm_dbus_signal_connect (priv->proxy, "DefaultAdapterChanged", G_VARIANT_TYPE ("(o)"),
	                         G_CALLBACK (default_adapter_changed), self);
	g_signal_connect (priv->proxy, "notify::g-name-owner",
	                  G_CALLBACK (name_owner_changed_cb), self);

	query_default_adapter (self);
}

static void
dispose (GObject *object)
{
	NMBluez4Manager *self = NM_BLUEZ4_MANAGER (object);
	NMBluez4ManagerPrivate *priv = NM_BLUEZ4_MANAGER_GET_PRIVATE (self);

	g_clear_object (&priv->proxy);
	g_clear_object (&priv->adapter);

	G_OBJECT_CLASS (nm_bluez4_manager_parent_class)->dispose (object);
}

static void
nm_bluez4_manager_class_init (NMBluez4ManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMBluez4ManagerPrivate));

	/* virtual methods */
	object_class->dispose = dispose;

	/* Signals */
	signals[BDADDR_ADDED] =
		g_signal_new (NM_BLUEZ_MANAGER_BDADDR_ADDED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMBluez4ManagerClass, bdaddr_added),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 5, G_TYPE_OBJECT, G_TYPE_STRING,
		              G_TYPE_STRING, G_TYPE_STRING, G_TYPE_UINT);
}

