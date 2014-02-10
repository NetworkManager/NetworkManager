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
 * Copyright (C) 2013 Intel Corporation.
 */

#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <gio/gio.h>

#include "nm-logging.h"
#include "nm-bluez-manager.h"
#include "nm-bluez5-manager.h"
#include "nm-bluez-device.h"
#include "nm-bluez-common.h"

#include "nm-dbus-manager.h"

typedef struct {
	NMDBusManager *dbus_mgr;
	gulong name_owner_changed_id;

	NMConnectionProvider *provider;

	GDBusProxy *proxy;

	GHashTable *devices;
} NMBluez5ManagerPrivate;

#define NM_BLUEZ5_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_BLUEZ5_MANAGER, NMBluez5ManagerPrivate))

G_DEFINE_TYPE (NMBluez5Manager, nm_bluez5_manager, G_TYPE_OBJECT)

enum {
	BDADDR_ADDED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static void device_initialized (NMBluezDevice *device, gboolean success, NMBluez5Manager *self);
static void device_usable (NMBluezDevice *device, GParamSpec *pspec, NMBluez5Manager *self);

static void
emit_bdaddr_added (NMBluez5Manager *self, NMBluezDevice *device)
{
	g_signal_emit (self, signals[BDADDR_ADDED], 0,
	               device,
	               nm_bluez_device_get_address (device),
	               nm_bluez_device_get_name (device),
	               nm_bluez_device_get_path (device),
	               nm_bluez_device_get_capabilities (device));
}

void
nm_bluez5_manager_query_devices (NMBluez5Manager *self)
{
	NMBluez5ManagerPrivate *priv = NM_BLUEZ5_MANAGER_GET_PRIVATE (self);
	NMBluezDevice *device;
	GHashTableIter iter;

	g_hash_table_iter_init (&iter, priv->devices);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer) &device)) {
		if (nm_bluez_device_get_usable (device))
			emit_bdaddr_added (self, device);
	}
}

static void
remove_device (NMBluez5Manager *self, NMBluezDevice *device)
{
	g_signal_handlers_disconnect_by_func (device, G_CALLBACK (device_initialized), self);
	g_signal_handlers_disconnect_by_func (device, G_CALLBACK (device_usable), self);
	if (nm_bluez_device_get_usable (device))
		g_signal_emit_by_name (device, NM_BLUEZ_DEVICE_REMOVED);
}

static void
remove_all_devices (NMBluez5Manager *self)
{
	GHashTableIter iter;
	NMBluezDevice *device;
	NMBluez5ManagerPrivate *priv = NM_BLUEZ5_MANAGER_GET_PRIVATE (self);

	g_hash_table_iter_init (&iter, priv->devices);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer) &device)) {
		g_hash_table_iter_steal (&iter);
		remove_device (self, device);
		g_object_unref (device);
	}
}

static void
device_usable (NMBluezDevice *device, GParamSpec *pspec, NMBluez5Manager *self)
{
	gboolean usable = nm_bluez_device_get_usable (device);

	nm_log_dbg (LOGD_BT, "(%s): bluez device now %s",
	            nm_bluez_device_get_path (device),
	            usable ? "usable" : "unusable");

	if (usable) {
		nm_log_dbg (LOGD_BT, "(%s): bluez device address %s",
				    nm_bluez_device_get_path (device),
				    nm_bluez_device_get_address (device));
		emit_bdaddr_added (self, device);
	} else
		g_signal_emit_by_name (device, NM_BLUEZ_DEVICE_REMOVED);
}

static void
device_initialized (NMBluezDevice *device, gboolean success, NMBluez5Manager *self)
{
	NMBluez5ManagerPrivate *priv = NM_BLUEZ5_MANAGER_GET_PRIVATE (self);

	nm_log_dbg (LOGD_BT, "(%s): bluez device %s",
	            nm_bluez_device_get_path (device),
	            success ? "initialized" : "failed to initialize");
	if (!success)
		g_hash_table_remove (priv->devices, nm_bluez_device_get_path (device));
}

static void
device_added (GDBusProxy *proxy, const gchar *path, NMBluez5Manager *self)
{
	NMBluez5ManagerPrivate *priv = NM_BLUEZ5_MANAGER_GET_PRIVATE (self);
	NMBluezDevice *device;

	device = nm_bluez_device_new (path, priv->provider, 5);
	g_signal_connect (device, "initialized", G_CALLBACK (device_initialized), self);
	g_signal_connect (device, "notify::usable", G_CALLBACK (device_usable), self);
	g_hash_table_insert (priv->devices, (gpointer) nm_bluez_device_get_path (device), device);

	nm_log_dbg (LOGD_BT, "(%s): new bluez device found", path);
}

static void
device_removed (GDBusProxy *proxy, const gchar *path, NMBluez5Manager *self)
{
	NMBluez5ManagerPrivate *priv = NM_BLUEZ5_MANAGER_GET_PRIVATE (self);
	NMBluezDevice *device;

	nm_log_dbg (LOGD_BT, "(%s): bluez device removed", path);

	device = g_hash_table_lookup (priv->devices, path);
	if (device) {
		g_hash_table_steal (priv->devices, nm_bluez_device_get_path (device));
		remove_device (NM_BLUEZ5_MANAGER (self), device);
		g_object_unref (device);
	}
}

static void
object_manager_g_signal (GDBusProxy     *proxy,
                         gchar          *sender_name,
                         gchar          *signal_name,
                         GVariant       *parameters,
                         NMBluez5Manager *self)
{
	GVariant *variant;
	const gchar *path;

	if (!strcmp (signal_name, "InterfacesRemoved")) {
		const gchar **ifaces;
		gsize i, length;

		g_variant_get (parameters, "(&o*)", &path, &variant);

		ifaces = g_variant_get_strv (variant, &length);

		for (i = 0; i < length; i++) {
			if (!strcmp (ifaces[i], BLUEZ5_DEVICE_INTERFACE)) {
				device_removed (proxy, path, self);
				break;
			}
		}

		g_free (ifaces);

	} else if (!strcmp (signal_name, "InterfacesAdded")) {
		g_variant_get (parameters, "(&o*)", &path, &variant);

		if (g_variant_lookup_value (variant, BLUEZ5_DEVICE_INTERFACE,
		                            G_VARIANT_TYPE_DICTIONARY))
			device_added (proxy, path, self);
	}
}

static void
get_managed_objects_cb (GDBusProxy *proxy,
                        GAsyncResult *res,
                        NMBluez5Manager *self)
{
	GVariant *variant, *ifaces;
	GVariantIter i;
	GError *error = NULL;
	const char *path;

	variant = g_dbus_proxy_call_finish (proxy, res, &error);

	if (!variant) {
		if (g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_UNKNOWN_METHOD))
			nm_log_warn (LOGD_BT, "Couldn't get managed objects: not running Bluez5?");
		else {
			nm_log_warn (LOGD_BT, "Couldn't get managed objects: %s",
				         error && error->message ? error->message : "(unknown)");
		}
		g_clear_error (&error);
		return;
	}
	g_variant_iter_init (&i, g_variant_get_child_value (variant, 0));
	while ((g_variant_iter_next (&i, "{&o*}", &path, &ifaces))) {
		if (g_variant_lookup_value (ifaces, BLUEZ5_DEVICE_INTERFACE,
		                            G_VARIANT_TYPE_DICTIONARY)) {
			device_added (proxy, path, self);
		}
	}

	g_variant_unref (variant);
}

static void
on_proxy_acquired (GObject *object,
                   GAsyncResult *res,
                   NMBluez5Manager *self)
{
	NMBluez5ManagerPrivate *priv = NM_BLUEZ5_MANAGER_GET_PRIVATE (self);
	GError *error = NULL;

	priv->proxy = g_dbus_proxy_new_for_bus_finish (res, &error);

	if (!priv->proxy) {
		nm_log_warn (LOGD_BT, "Couldn't acquire object manager proxy: %s",
		             error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
		return;
	}

	/* Get already managed devices. */
	g_dbus_proxy_call (priv->proxy, "GetManagedObjects",
	                   NULL,
	                   G_DBUS_CALL_FLAGS_NONE,
	                   -1,
	                   NULL,
	                   (GAsyncReadyCallback) get_managed_objects_cb,
	                   self);

	g_signal_connect (priv->proxy, "g-signal",
	                  G_CALLBACK (object_manager_g_signal), self);
}

static void
bluez_connect (NMBluez5Manager *self)
{
	NMBluez5ManagerPrivate *priv = NM_BLUEZ5_MANAGER_GET_PRIVATE (self);

	g_return_if_fail (priv->proxy == NULL);

	g_dbus_proxy_new_for_bus (G_BUS_TYPE_SYSTEM,
	                          G_DBUS_PROXY_FLAGS_NONE,
	                          NULL,
	                          BLUEZ_SERVICE,
	                          BLUEZ_MANAGER_PATH,
	                          OBJECT_MANAGER_INTERFACE,
	                          NULL,
	                          (GAsyncReadyCallback) on_proxy_acquired,
	                          self);
}

static void
name_owner_changed_cb (NMDBusManager *dbus_mgr,
                       const char *name,
                       const char *old_owner,
                       const char *new_owner,
                       gpointer user_data)
{
	NMBluez5Manager *self = NM_BLUEZ5_MANAGER (user_data);
	NMBluez5ManagerPrivate *priv = NM_BLUEZ5_MANAGER_GET_PRIVATE (self);
	gboolean old_owner_good = (old_owner && strlen (old_owner));
	gboolean new_owner_good = (new_owner && strlen (new_owner));

	/* Can't handle the signal if its not from the Bluez */
	if (strcmp (BLUEZ_SERVICE, name))
		return;

	if (old_owner_good && !new_owner_good) {
		if (priv->devices)
			remove_all_devices (self);
	}
}

static void
bluez_cleanup (NMBluez5Manager *self, gboolean do_signal)
{
	NMBluez5ManagerPrivate *priv = NM_BLUEZ5_MANAGER_GET_PRIVATE (self);

	if (priv->proxy) {
		g_object_unref (priv->proxy);
		priv->proxy = NULL;
	}

	if (do_signal)
		remove_all_devices (self);
	else
		g_hash_table_remove_all (priv->devices);
}

static void
dbus_connection_changed_cb (NMDBusManager *dbus_mgr,
                            DBusGConnection *connection,
                            gpointer user_data)
{
	NMBluez5Manager *self = NM_BLUEZ5_MANAGER (user_data);

	if (!connection)
		bluez_cleanup (self, TRUE);
	else
		bluez_connect (self);
}

/****************************************************************/

NMBluez5Manager *
nm_bluez5_manager_new (NMConnectionProvider *provider)
{
	NMBluez5Manager *instance = NULL;

	instance = g_object_new (NM_TYPE_BLUEZ5_MANAGER, NULL);
	NM_BLUEZ5_MANAGER_GET_PRIVATE (instance)->provider = provider;
	return instance;
}

static void
nm_bluez5_manager_init (NMBluez5Manager *self)
{
	NMBluez5ManagerPrivate *priv = NM_BLUEZ5_MANAGER_GET_PRIVATE (self);

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

	priv->devices = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                       NULL, g_object_unref);
}

static void
dispose (GObject *object)
{
	NMBluez5Manager *self = NM_BLUEZ5_MANAGER (object);
	NMBluez5ManagerPrivate *priv = NM_BLUEZ5_MANAGER_GET_PRIVATE (self);

	bluez_cleanup (self, FALSE);

	if (priv->dbus_mgr) {
		g_signal_handlers_disconnect_by_func (priv->dbus_mgr, name_owner_changed_cb, self);
		g_signal_handlers_disconnect_by_func (priv->dbus_mgr, dbus_connection_changed_cb, self);
		priv->dbus_mgr = NULL;
	}

	G_OBJECT_CLASS (nm_bluez5_manager_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMBluez5ManagerPrivate *priv = NM_BLUEZ5_MANAGER_GET_PRIVATE (object);

	g_hash_table_destroy (priv->devices);

	G_OBJECT_CLASS (nm_bluez5_manager_parent_class)->finalize (object);
}

static void
nm_bluez5_manager_class_init (NMBluez5ManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMBluez5ManagerPrivate));

	/* virtual methods */
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	/* Signals */
	signals[BDADDR_ADDED] =
		g_signal_new (NM_BLUEZ_MANAGER_BDADDR_ADDED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMBluez5ManagerClass, bdaddr_added),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 5, G_TYPE_OBJECT, G_TYPE_STRING,
		              G_TYPE_STRING, G_TYPE_STRING, G_TYPE_UINT);
}
