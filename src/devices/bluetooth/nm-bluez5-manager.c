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
 * Copyright (C) 2007 - 2017 Red Hat, Inc.
 * Copyright (C) 2013 Intel Corporation.
 */

#include "nm-default.h"

#include "nm-bluez5-manager.h"

#include <signal.h>
#include <string.h>
#include <stdlib.h>

#include "nm-core-internal.h"

#include "c-list/src/c-list.h"
#include "nm-bluez-device.h"
#include "nm-bluez-common.h"
#include "devices/nm-device-bridge.h"
#include "settings/nm-settings.h"

/*****************************************************************************/

enum {
	BDADDR_ADDED,
	NETWORK_SERVER_ADDED,
	LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	NMSettings *settings;

	GDBusProxy *proxy;

	GHashTable *devices;

	CList network_servers;
} NMBluez5ManagerPrivate;

struct _NMBluez5Manager {
	GObject parent;
	NMBtVTableNetworkServer network_server_vtable;
	NMBluez5ManagerPrivate _priv;
};

struct _NMBluez5ManagerClass {
	GObjectClass parent;
};

G_DEFINE_TYPE (NMBluez5Manager, nm_bluez5_manager, G_TYPE_OBJECT)

#define NM_BLUEZ5_MANAGER_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMBluez5Manager, NM_IS_BLUEZ5_MANAGER)

#define NM_BLUEZ5_MANAGER_GET_NETWORK_SERVER_VTABLE(self) (&(self)->network_server_vtable)
#define NETWORK_SERVER_VTABLE_GET_NM_BLUEZ5_MANAGER(vtable) \
	NM_BLUEZ5_MANAGER(((char *)(vtable)) - offsetof (struct _NMBluez5Manager, network_server_vtable))

/*****************************************************************************/

#define _NMLOG_DOMAIN LOGD_BT
#define _NMLOG(level, ...) __NMLOG_DEFAULT (level, _NMLOG_DOMAIN, "bluez5", __VA_ARGS__)

/*****************************************************************************/

static void device_initialized (NMBluezDevice *device, gboolean success, NMBluez5Manager *self);
static void device_usable (NMBluezDevice *device, GParamSpec *pspec, NMBluez5Manager *self);

/*****************************************************************************/

typedef struct {
	char *path;
	char *addr;
	NMDevice *device;
	CList lst_ns;
} NetworkServer;

static NetworkServer *
_find_network_server (NMBluez5Manager *self, const char *path, NMDevice *device)
{
	NMBluez5ManagerPrivate *priv = NM_BLUEZ5_MANAGER_GET_PRIVATE (self);
	NetworkServer *network_server;

	nm_assert (path || NM_IS_DEVICE (device));

	c_list_for_each_entry (network_server, &priv->network_servers, lst_ns) {
		if (path && !nm_streq (network_server->path, path))
			continue;
		if (device && network_server->device != device)
			continue;
		return network_server;
	}
	return NULL;
}

static NetworkServer *
_find_network_server_for_addr (NMBluez5Manager *self, const char *addr)
{
	NMBluez5ManagerPrivate *priv = NM_BLUEZ5_MANAGER_GET_PRIVATE (self);
	NetworkServer *network_server;

	c_list_for_each_entry (network_server, &priv->network_servers, lst_ns) {
		/* The address lookups need a server not assigned to a device
		 * and tolerate an empty address as a wildcard for "any". */
		if (   !network_server->device
		    && (!addr || nm_streq (network_server->addr, addr)))
			return network_server;
	}
	return NULL;
}

static void
_network_server_unregister (NMBluez5Manager *self, NetworkServer *network_server)
{
	NMBluez5ManagerPrivate *priv = NM_BLUEZ5_MANAGER_GET_PRIVATE (self);

	if (!network_server->device) {
		/* Not connected. */
		return;
	}

	_LOGI ("NAP: unregistering %s from %s",
	       nm_device_get_iface (network_server->device),
	       network_server->addr);

	g_dbus_connection_call (g_dbus_proxy_get_connection (priv->proxy),
	                        NM_BLUEZ_SERVICE,
	                        network_server->path,
	                        NM_BLUEZ5_NETWORK_SERVER_INTERFACE,
	                        "Unregister",
	                        g_variant_new ("(s)", BLUETOOTH_CONNECT_NAP),
	                        NULL,
	                        G_DBUS_CALL_FLAGS_NONE,
	                        -1, NULL, NULL, NULL);

	g_clear_object (&network_server->device);
}

static void
_network_server_free (NMBluez5Manager *self, NetworkServer *network_server)
{
	_network_server_unregister (self, network_server);
	c_list_unlink_stale (&network_server->lst_ns);
	g_free (network_server->path);
	g_free (network_server->addr);
	g_slice_free (NetworkServer, network_server);
}

static gboolean
network_server_is_available (const NMBtVTableNetworkServer *vtable,
                             const char *addr)
{
	NMBluez5Manager *self = NETWORK_SERVER_VTABLE_GET_NM_BLUEZ5_MANAGER (vtable);

	return !!_find_network_server_for_addr (self, addr);
}

static gboolean
network_server_register_bridge (const NMBtVTableNetworkServer *vtable,
                                const char *addr,
                                NMDevice *device)
{
	NMBluez5Manager *self = NETWORK_SERVER_VTABLE_GET_NM_BLUEZ5_MANAGER (vtable);
	NMBluez5ManagerPrivate *priv = NM_BLUEZ5_MANAGER_GET_PRIVATE (self);
	NetworkServer *network_server = _find_network_server_for_addr (self, addr);

	nm_assert (NM_IS_DEVICE (device));
	nm_assert (!_find_network_server (self, NULL, device));

	if (!network_server) {
		/* The device checked that a network server is available, before
		 * starting the activation, but for some reason it no longer is.
		 * Indicate that the activation should not proceed. */
		_LOGI ("NAP: %s is not available for %s", addr, nm_device_get_iface (device));
		return FALSE;
	}

	_LOGI ("NAP: registering %s on %s", nm_device_get_iface (device), network_server->addr);

	g_dbus_connection_call (g_dbus_proxy_get_connection (priv->proxy),
	                        NM_BLUEZ_SERVICE,
	                        network_server->path,
	                        NM_BLUEZ5_NETWORK_SERVER_INTERFACE,
	                        "Register",
	                        g_variant_new ("(ss)", BLUETOOTH_CONNECT_NAP, nm_device_get_iface (device)),
	                        NULL,
	                        G_DBUS_CALL_FLAGS_NONE,
	                        -1, NULL, NULL, NULL);

	network_server->device = g_object_ref (device);

	return TRUE;
}

static gboolean
network_server_unregister_bridge (const NMBtVTableNetworkServer *vtable,
                                  NMDevice *device)
{
	NMBluez5Manager *self = NETWORK_SERVER_VTABLE_GET_NM_BLUEZ5_MANAGER (vtable);
	NetworkServer *network_server = _find_network_server (self, NULL, device);

	if (network_server)
		_network_server_unregister (self, network_server);

	return TRUE;
}

static void
network_server_removed (GDBusProxy *proxy, const gchar *path, NMBluez5Manager *self)
{
	NetworkServer *network_server;

	network_server = _find_network_server (self, path, NULL);
	if (!network_server)
		return;

	if (network_server->device) {
		nm_device_queue_state (network_server->device, NM_DEVICE_STATE_DISCONNECTED,
		                       NM_DEVICE_STATE_REASON_BT_FAILED);
	}
	_LOGI ("NAP: removed interface %s", network_server->addr);
	_network_server_free (self, network_server);
}

static void
network_server_added (GDBusProxy *proxy, const gchar *path, const char *addr, NMBluez5Manager *self)
{
	NMBluez5ManagerPrivate *priv = NM_BLUEZ5_MANAGER_GET_PRIVATE (self);
	NetworkServer *network_server;

	/* If BlueZ messes up and announces a single network server twice,
	 * make sure we get rid of the older instance first. */
	network_server_removed (proxy, path, self);

	network_server = g_slice_new0 (NetworkServer);
	network_server->path = g_strdup (path);
	network_server->addr = g_strdup (addr);
	c_list_link_before (&priv->network_servers, &network_server->lst_ns);

	_LOGI ("NAP: added interface %s", addr);

	g_signal_emit (self, signals[NETWORK_SERVER_ADDED], 0);
}

/*****************************************************************************/

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

	_LOGD ("(%s): bluez device now %s",
	       nm_bluez_device_get_path (device),
	       usable ? "usable" : "unusable");

	if (usable) {
		_LOGD ("(%s): bluez device address %s",
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

	_LOGD ("(%s): bluez device %s",
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

	device = nm_bluez_device_new (path, NULL, priv->settings, 5);
	g_signal_connect (device, NM_BLUEZ_DEVICE_INITIALIZED, G_CALLBACK (device_initialized), self);
	g_signal_connect (device, "notify::" NM_BLUEZ_DEVICE_USABLE, G_CALLBACK (device_usable), self);
	g_hash_table_insert (priv->devices, (gpointer) nm_bluez_device_get_path (device), device);

	_LOGD ("(%s): new bluez device found", path);
}

static void
device_removed (GDBusProxy *proxy, const gchar *path, NMBluez5Manager *self)
{
	NMBluez5ManagerPrivate *priv = NM_BLUEZ5_MANAGER_GET_PRIVATE (self);
	NMBluezDevice *device;

	_LOGD ("(%s): bluez device removed", path);

	device = g_hash_table_lookup (priv->devices, path);
	if (device) {
		g_hash_table_steal (priv->devices, nm_bluez_device_get_path (device));
		remove_device (NM_BLUEZ5_MANAGER (self), device);
		g_object_unref (device);
	}
}

static void
object_manager_interfaces_added (GDBusProxy      *proxy,
                                 const char      *path,
                                 GVariant        *dict,
                                 NMBluez5Manager *self)
{
	if (g_variant_lookup (dict, NM_BLUEZ5_DEVICE_INTERFACE, "a{sv}", NULL))
		device_added (proxy, path, self);
	if (g_variant_lookup (dict, NM_BLUEZ5_NETWORK_SERVER_INTERFACE, "a{sv}", NULL)) {
		gs_unref_variant GVariant *adapter = g_variant_lookup_value (dict, NM_BLUEZ5_ADAPTER_INTERFACE, G_VARIANT_TYPE_DICTIONARY);
		const char *address;

		if (   adapter
		    && g_variant_lookup (adapter, "Address", "&s", &address))
			network_server_added (proxy, path, address, self);
	}
}

static void
object_manager_interfaces_removed (GDBusProxy       *proxy,
                                   const char       *path,
                                   const char      **ifaces,
                                   NMBluez5Manager  *self)
{
	if (ifaces && g_strv_contains (ifaces, NM_BLUEZ5_DEVICE_INTERFACE))
		device_removed (proxy, path, self);
	if (ifaces && g_strv_contains (ifaces, NM_BLUEZ5_NETWORK_SERVER_INTERFACE))
		network_server_removed (proxy, path, self);
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

	variant = _nm_dbus_proxy_call_finish (proxy, res,
	                                      G_VARIANT_TYPE ("(a{oa{sa{sv}}})"),
	                                      &error);
	if (!variant) {
		if (g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_UNKNOWN_METHOD))
			_LOGW ("Couldn't get managed objects: not running Bluez5?");
		else {
			g_dbus_error_strip_remote_error (error);
			_LOGW ("Couldn't get managed objects: %s", error->message);
		}
		g_clear_error (&error);
		return;
	}
	g_variant_iter_init (&i, g_variant_get_child_value (variant, 0));
	while ((g_variant_iter_next (&i, "{&o*}", &path, &ifaces))) {
		object_manager_interfaces_added (proxy, path, ifaces, self);
		g_variant_unref (ifaces);
	}

	g_variant_unref (variant);
}

static void name_owner_changed_cb (GObject *object, GParamSpec *pspec, gpointer user_data);

static void
on_proxy_acquired (GObject *object,
                   GAsyncResult *res,
                   NMBluez5Manager *self)
{
	NMBluez5ManagerPrivate *priv = NM_BLUEZ5_MANAGER_GET_PRIVATE (self);
	GError *error = NULL;

	priv->proxy = g_dbus_proxy_new_for_bus_finish (res, &error);

	if (!priv->proxy) {
		_LOGW ("Couldn't acquire object manager proxy: %s", error->message);
		g_clear_error (&error);
		return;
	}

	g_signal_connect (priv->proxy, "notify::g-name-owner",
	                  G_CALLBACK (name_owner_changed_cb), self);

	/* Get already managed devices. */
	g_dbus_proxy_call (priv->proxy, "GetManagedObjects",
	                   NULL,
	                   G_DBUS_CALL_FLAGS_NONE,
	                   -1,
	                   NULL,
	                   (GAsyncReadyCallback) get_managed_objects_cb,
	                   self);

	_nm_dbus_signal_connect (priv->proxy, "InterfacesAdded", G_VARIANT_TYPE ("(oa{sa{sv}})"),
	                         G_CALLBACK (object_manager_interfaces_added), self);
	_nm_dbus_signal_connect (priv->proxy, "InterfacesRemoved", G_VARIANT_TYPE ("(oas)"),
	                         G_CALLBACK (object_manager_interfaces_removed), self);
}

static void
bluez_connect (NMBluez5Manager *self)
{
	NMBluez5ManagerPrivate *priv = NM_BLUEZ5_MANAGER_GET_PRIVATE (self);

	g_return_if_fail (priv->proxy == NULL);

	g_dbus_proxy_new_for_bus (G_BUS_TYPE_SYSTEM,
	                          G_DBUS_PROXY_FLAGS_NONE,
	                          NULL,
	                          NM_BLUEZ_SERVICE,
	                          NM_BLUEZ_MANAGER_PATH,
	                          NM_OBJECT_MANAGER_INTERFACE,
	                          NULL,
	                          (GAsyncReadyCallback) on_proxy_acquired,
	                          self);
}

static void
name_owner_changed_cb (GObject *object,
                       GParamSpec *pspec,
                       gpointer user_data)
{
	NMBluez5Manager *self = NM_BLUEZ5_MANAGER (user_data);
	NMBluez5ManagerPrivate *priv = NM_BLUEZ5_MANAGER_GET_PRIVATE (self);
	char *owner;

	if (priv->devices) {
		owner = g_dbus_proxy_get_name_owner (priv->proxy);
		if (!owner)
			remove_all_devices (self);
		g_free (owner);
	}
}

/*****************************************************************************/

static void
nm_bluez5_manager_init (NMBluez5Manager *self)
{
	NMBluez5ManagerPrivate *priv = NM_BLUEZ5_MANAGER_GET_PRIVATE (self);
	NMBtVTableNetworkServer *network_server_vtable = NM_BLUEZ5_MANAGER_GET_NETWORK_SERVER_VTABLE (self);

	bluez_connect (self);

	priv->devices = g_hash_table_new_full (nm_str_hash, g_str_equal,
	                                       NULL, g_object_unref);

	c_list_init (&priv->network_servers);

	nm_assert (!nm_bt_vtable_network_server);
	network_server_vtable->is_available = network_server_is_available;
	network_server_vtable->register_bridge = network_server_register_bridge;
	network_server_vtable->unregister_bridge = network_server_unregister_bridge;
	nm_bt_vtable_network_server = network_server_vtable;
}

NMBluez5Manager *
nm_bluez5_manager_new (NMSettings *settings)
{
	NMBluez5Manager *instance = NULL;

	g_return_val_if_fail (NM_IS_SETTINGS (settings), NULL);

	instance = g_object_new (NM_TYPE_BLUEZ5_MANAGER, NULL);
	NM_BLUEZ5_MANAGER_GET_PRIVATE (instance)->settings = g_object_ref (settings);
	return instance;
}

static void
dispose (GObject *object)
{
	NMBluez5Manager *self = NM_BLUEZ5_MANAGER (object);
	NMBluez5ManagerPrivate *priv = NM_BLUEZ5_MANAGER_GET_PRIVATE (self);
	CList *iter, *safe;

	c_list_for_each_safe (iter, safe, &priv->network_servers)
		_network_server_free (self, c_list_entry (iter, NetworkServer, lst_ns));

	if (priv->proxy) {
		g_signal_handlers_disconnect_by_func (priv->proxy, G_CALLBACK (name_owner_changed_cb), self);
		g_clear_object (&priv->proxy);
	}

	g_hash_table_remove_all (priv->devices);

	G_OBJECT_CLASS (nm_bluez5_manager_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMBluez5Manager *self = NM_BLUEZ5_MANAGER (object);
	NMBluez5ManagerPrivate *priv = NM_BLUEZ5_MANAGER_GET_PRIVATE (self);

	g_hash_table_destroy (priv->devices);

	G_OBJECT_CLASS (nm_bluez5_manager_parent_class)->finalize (object);

	g_object_unref (priv->settings);
}

static void
nm_bluez5_manager_class_init (NMBluez5ManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->dispose = dispose;
	object_class->finalize = finalize;

	signals[BDADDR_ADDED] =
	    g_signal_new (NM_BLUEZ_MANAGER_BDADDR_ADDED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 5, G_TYPE_OBJECT, G_TYPE_STRING,
	                  G_TYPE_STRING, G_TYPE_STRING, G_TYPE_UINT);

	signals[NETWORK_SERVER_ADDED] =
	    g_signal_new (NM_BLUEZ_MANAGER_NETWORK_SERVER_ADDED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 0);
}
