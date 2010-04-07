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
 * Copyright (C) 2007 - 2010 Red Hat, Inc.
 */

#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <dbus/dbus-glib.h>

#include "nm-logging.h"
#include "nm-dbus-glib-types.h"
#include "nm-marshal.h"
#include "nm-bluez-manager.h"
#include "nm-bluez-adapter.h"
#include "nm-dbus-manager.h"
#include "nm-bluez-common.h"


typedef struct {
	NMDBusManager *dbus_mgr;
	gulong name_owner_changed_id;

	DBusGProxy *proxy;

	NMBluezAdapter *adapter;
} NMBluezManagerPrivate;

#define NM_BLUEZ_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_BLUEZ_MANAGER, NMBluezManagerPrivate))

G_DEFINE_TYPE (NMBluezManager, nm_bluez_manager, G_TYPE_OBJECT)

enum {
	BDADDR_ADDED,
	BDADDR_REMOVED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static void

emit_bdaddr_added (NMBluezManager *self, NMBluezDevice *device)
{
	g_signal_emit (self, signals[BDADDR_ADDED], 0,
	               nm_bluez_device_get_address (device),
	               nm_bluez_device_get_name (device),
	               nm_bluez_device_get_path (device),
	               nm_bluez_device_get_capabilities (device));
}

void
nm_bluez_manager_query_devices (NMBluezManager *self)
{
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);
	GSList *devices, *iter;

	if (!priv->adapter)
		return;

	devices = nm_bluez_adapter_get_devices (priv->adapter);
	for (iter = devices; iter; iter = g_slist_next (iter))
		emit_bdaddr_added (self, NM_BLUEZ_DEVICE (iter->data));
	g_slist_free (devices);
}

static void
device_added (NMBluezAdapter *adapter, NMBluezDevice *device, gpointer user_data)
{
	emit_bdaddr_added (NM_BLUEZ_MANAGER (user_data), device);
}

static void
device_removed (NMBluezAdapter *adapter, NMBluezDevice *device, gpointer user_data)
{
	NMBluezManager *self = NM_BLUEZ_MANAGER (user_data);

	g_signal_emit (self, signals[BDADDR_REMOVED], 0,
	               nm_bluez_device_get_address (device),
	               nm_bluez_device_get_path (device));
}

static void
adapter_initialized (NMBluezAdapter *adapter, gboolean success, gpointer user_data)
{
	NMBluezManager *self = NM_BLUEZ_MANAGER (user_data);
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);

	if (success) {
		GSList *devices, *iter;

		devices = nm_bluez_adapter_get_devices (adapter);
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
adapter_removed (DBusGProxy *proxy, const char *path, NMBluezManager *self)
{
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);

	if (priv->adapter && !strcmp (path, nm_bluez_adapter_get_path (priv->adapter))) {
		if (nm_bluez_adapter_get_initialized (priv->adapter)) {
			GSList *devices, *iter;

			devices = nm_bluez_adapter_get_devices (priv->adapter);
			for (iter = devices; iter; iter = g_slist_next (iter)) {
				NMBluezDevice *device = NM_BLUEZ_DEVICE (iter->data);

				g_signal_emit (self, signals[BDADDR_REMOVED], 0,
				               nm_bluez_device_get_address (device),
				               nm_bluez_device_get_path (device));
			}
			g_slist_free (devices);
		}

		g_object_unref (priv->adapter);
		priv->adapter = NULL;
	}
}

static void
default_adapter_changed (DBusGProxy *proxy, const char *path, NMBluezManager *self)
{
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);
	const char *cur_path = NULL;

	if (priv->adapter)
		cur_path = nm_bluez_adapter_get_path (priv->adapter);

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
		priv->adapter = nm_bluez_adapter_new (path);
		g_signal_connect (priv->adapter, "initialized", G_CALLBACK (adapter_initialized), self);
	}
}

static void
default_adapter_cb (DBusGProxy *proxy, DBusGProxyCall *call, gpointer user_data)
{
	NMBluezManager *self = NM_BLUEZ_MANAGER (user_data);
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);
	const char *default_adapter = NULL;
	GError *err = NULL;

	if (!dbus_g_proxy_end_call (proxy, call, &err,
	                            DBUS_TYPE_G_OBJECT_PATH, &default_adapter,
	                            G_TYPE_INVALID)) {
		nm_log_warn (LOGD_BT, "bluez error getting default adapter: %s",
		             err && err->message ? err->message : "(unknown)");
		g_error_free (err);
		return;
	}

	default_adapter_changed (priv->proxy, default_adapter, self);
}

static void
query_default_adapter (NMBluezManager *self)
{
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);
	DBusGProxyCall *call;

	call = dbus_g_proxy_begin_call (priv->proxy, "DefaultAdapter",
	                                default_adapter_cb,
	                                self,
	                                NULL, G_TYPE_INVALID);
	if (!call)
		nm_log_warn (LOGD_BT, "failed to request default Bluetooth adapter.");
}

static void
bluez_connect (NMBluezManager *self)
{
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);
	DBusGConnection *connection;

	g_return_if_fail (priv->proxy == NULL);

	connection = nm_dbus_manager_get_connection (priv->dbus_mgr);
	if (!connection)
		return;

	priv->proxy = dbus_g_proxy_new_for_name (connection,
	                                         BLUEZ_SERVICE,
	                                         BLUEZ_MANAGER_PATH,
	                                         BLUEZ_MANAGER_INTERFACE);

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
remove_all_devices (NMBluezManager *self, gboolean do_signal)
{
	/* FIXME: do something */
}

static void
name_owner_changed_cb (NMDBusManager *dbus_mgr,
                       const char *name,
                       const char *old_owner,
                       const char *new_owner,
                       gpointer user_data)
{
	NMBluezManager *self = NM_BLUEZ_MANAGER (user_data);
	gboolean old_owner_good = (old_owner && strlen (old_owner));
	gboolean new_owner_good = (new_owner && strlen (new_owner));

	/* Can't handle the signal if its not from the supplicant service */
	if (strcmp (BLUEZ_SERVICE, name))
		return;

	if (old_owner_good && !new_owner_good)
		remove_all_devices (self, TRUE);
}

static void
bluez_cleanup (NMBluezManager *self, gboolean do_signal)
{
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);

	if (priv->proxy) {
		g_object_unref (priv->proxy);
		priv->proxy = NULL;
	}

	remove_all_devices (self, do_signal);
}

static void
dbus_connection_changed_cb (NMDBusManager *dbus_mgr,
                            DBusGConnection *connection,
                            gpointer user_data)
{
	NMBluezManager *self = NM_BLUEZ_MANAGER (user_data);

	if (!connection)
		bluez_cleanup (self, TRUE);
	else
		bluez_connect (self);
}


NMBluezManager *
nm_bluez_manager_new (void)
{
	return NM_BLUEZ_MANAGER (g_object_new (NM_TYPE_BLUEZ_MANAGER, NULL));
}

NMBluezManager *
nm_bluez_manager_get (void)
{
	static NMBluezManager *singleton = NULL;

	if (!singleton)
		singleton = nm_bluez_manager_new ();
	else
		g_object_ref (singleton);

	g_assert (singleton);
	return singleton;
}

static void
nm_bluez_manager_init (NMBluezManager *self)
{
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);

	priv->dbus_mgr = nm_dbus_manager_get ();
	g_assert (priv->dbus_mgr);

	g_signal_connect (priv->dbus_mgr,
	                  "name-owner-changed",
	                  G_CALLBACK (name_owner_changed_cb),
	                  self);

	g_signal_connect (priv->dbus_mgr,
	                  "dbus-connection-changed",
	                  G_CALLBACK (dbus_connection_changed_cb),
	                  self);

	bluez_connect (self);
}

static void
finalize (GObject *object)
{
	NMBluezManager *self = NM_BLUEZ_MANAGER (object);

	bluez_cleanup (self, FALSE);

	G_OBJECT_CLASS (nm_bluez_manager_parent_class)->finalize (object);
}

static void
nm_bluez_manager_class_init (NMBluezManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMBluezManagerPrivate));

	/* virtual methods */
	object_class->finalize = finalize;

	/* Signals */
	signals[BDADDR_ADDED] =
		g_signal_new ("bdaddr-added",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMBluezManagerClass, bdaddr_added),
		              NULL, NULL,
		              _nm_marshal_VOID__STRING_STRING_STRING_UINT,
		              G_TYPE_NONE, 4, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_UINT);

	signals[BDADDR_REMOVED] =
		g_signal_new ("bdaddr-removed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMBluezManagerClass, bdaddr_removed),
		              NULL, NULL,
		              _nm_marshal_VOID__STRING_STRING,
		              G_TYPE_NONE, 2, G_TYPE_STRING, G_TYPE_STRING);
}

