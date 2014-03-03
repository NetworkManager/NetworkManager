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

#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <dbus/dbus-glib.h>

#include "nm-logging.h"
#include "nm-dbus-glib-types.h"
#include "nm-bluez-manager.h"
#include "nm-bluez4-manager.h"
#include "nm-bluez4-adapter.h"
#include "nm-dbus-manager.h"
#include "nm-bluez-common.h"


typedef struct {
	NMDBusManager *dbus_mgr;
	gulong name_owner_changed_id;

	NMConnectionProvider *provider;

	DBusGProxy *proxy;

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
adapter_removed (DBusGProxy *proxy, const char *path, NMBluez4Manager *self)
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
default_adapter_changed (DBusGProxy *proxy, const char *path, NMBluez4Manager *self)
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
default_adapter_cb (DBusGProxy *proxy, DBusGProxyCall *call, gpointer user_data)
{
	NMBluez4Manager *self = NM_BLUEZ4_MANAGER (user_data);
	NMBluez4ManagerPrivate *priv = NM_BLUEZ4_MANAGER_GET_PRIVATE (self);
	const char *default_adapter = NULL;
	GError *err = NULL;

	if (!dbus_g_proxy_end_call (proxy, call, &err,
	                            DBUS_TYPE_G_OBJECT_PATH, &default_adapter,
	                            G_TYPE_INVALID)) {
		/* Ignore "No such adapter" errors; just means bluetooth isn't active */
		if (   !dbus_g_error_has_name (err, "org.bluez.Error.NoSuchAdapter")
		    && !dbus_g_error_has_name (err, "org.freedesktop.systemd1.LoadFailed")
		    && !g_error_matches (err, DBUS_GERROR, DBUS_GERROR_SERVICE_UNKNOWN)) {
			nm_log_warn (LOGD_BT, "bluez error getting default adapter: %s",
			             err && err->message ? err->message : "(unknown)");
		}
		g_error_free (err);
		return;
	}

	default_adapter_changed (priv->proxy, default_adapter, self);
}

static void
query_default_adapter (NMBluez4Manager *self)
{
	NMBluez4ManagerPrivate *priv = NM_BLUEZ4_MANAGER_GET_PRIVATE (self);
	DBusGProxyCall *call;

	call = dbus_g_proxy_begin_call (priv->proxy, "DefaultAdapter",
	                                default_adapter_cb,
	                                self,
	                                NULL, G_TYPE_INVALID);
	if (!call)
		nm_log_warn (LOGD_BT, "failed to request default Bluetooth adapter.");
}

static void
bluez_connect (NMBluez4Manager *self)
{
	NMBluez4ManagerPrivate *priv = NM_BLUEZ4_MANAGER_GET_PRIVATE (self);
	DBusGConnection *connection;

	g_return_if_fail (priv->proxy == NULL);

	connection = nm_dbus_manager_get_connection (priv->dbus_mgr);
	if (!connection)
		return;

	priv->proxy = dbus_g_proxy_new_for_name (connection,
	                                         BLUEZ_SERVICE,
	                                         BLUEZ_MANAGER_PATH,
	                                         BLUEZ4_MANAGER_INTERFACE);

	dbus_g_proxy_add_signal (priv->proxy, "AdapterRemoved",
	                         DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "AdapterRemoved",
	                             G_CALLBACK (adapter_removed), self, NULL);

	dbus_g_proxy_add_signal (priv->proxy, "DefaultAdapterChanged",
	                         DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "DefaultAdapterChanged",
	                             G_CALLBACK (default_adapter_changed), self, NULL);

	query_default_adapter (self);
}

static void
name_owner_changed_cb (NMDBusManager *dbus_mgr,
                       const char *name,
                       const char *old_owner,
                       const char *new_owner,
                       gpointer user_data)
{
	NMBluez4Manager *self = NM_BLUEZ4_MANAGER (user_data);
	NMBluez4ManagerPrivate *priv = NM_BLUEZ4_MANAGER_GET_PRIVATE (self);
	gboolean old_owner_good = (old_owner && strlen (old_owner));
	gboolean new_owner_good = (new_owner && strlen (new_owner));

	/* Can't handle the signal if its not from the Bluez */
	if (strcmp (BLUEZ_SERVICE, name))
		return;

	if (!old_owner_good && new_owner_good)
		query_default_adapter (self);
	else if (old_owner_good && !new_owner_good) {
		/* Throwing away the adapter removes all devices too */
		if (priv->adapter) {
			g_object_unref (priv->adapter);
			priv->adapter = NULL;
		}
	}
}

static void
bluez_cleanup (NMBluez4Manager *self, gboolean do_signal)
{
	NMBluez4ManagerPrivate *priv = NM_BLUEZ4_MANAGER_GET_PRIVATE (self);

	if (priv->proxy) {
		g_object_unref (priv->proxy);
		priv->proxy = NULL;
	}

	if (priv->adapter) {
		g_object_unref (priv->adapter);
		priv->adapter = NULL;
	}
}

static void
dbus_connection_changed_cb (NMDBusManager *dbus_mgr,
                            DBusGConnection *connection,
                            gpointer user_data)
{
	NMBluez4Manager *self = NM_BLUEZ4_MANAGER (user_data);

	if (!connection)
		bluez_cleanup (self, TRUE);
	else
		bluez_connect (self);
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

	priv->dbus_mgr = nm_dbus_manager_get ();
	g_assert (priv->dbus_mgr);

	g_signal_connect (priv->dbus_mgr,
	                  NM_DBUS_MANAGER_NAME_OWNER_CHANGED,
	                  G_CALLBACK (name_owner_changed_cb),
	                  self);

	g_signal_connect (priv->dbus_mgr,
	                  NM_DBUS_MANAGER_DBUS_CONNECTION_CHANGED,
	                  G_CALLBACK (dbus_connection_changed_cb),
	                  self);

	bluez_connect (self);
}

static void
dispose (GObject *object)
{
	NMBluez4Manager *self = NM_BLUEZ4_MANAGER (object);
	NMBluez4ManagerPrivate *priv = NM_BLUEZ4_MANAGER_GET_PRIVATE (self);

	bluez_cleanup (self, FALSE);

	if (priv->dbus_mgr) {
		g_signal_handlers_disconnect_by_func (priv->dbus_mgr, name_owner_changed_cb, self);
		g_signal_handlers_disconnect_by_func (priv->dbus_mgr, dbus_connection_changed_cb, self);
		priv->dbus_mgr = NULL;
	}

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

