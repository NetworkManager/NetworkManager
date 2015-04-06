/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2007 - 2008 Novell, Inc.
 * Copyright 2007 - 2013 Red Hat, Inc.
 */

#include "config.h"

#include <dbus/dbus-glib.h>
#include <string.h>
#include <nm-utils.h>

#include "nm-glib.h"
#include "nm-client.h"
#include "nm-device-ethernet.h"
#include "nm-device-wifi.h"
#include "nm-device-private.h"
#include "nm-types-private.h"
#include "nm-object-private.h"
#include "nm-active-connection.h"
#include "nm-vpn-connection.h"
#include "nm-object-cache.h"
#include "nm-dbus-glib-types.h"

void _nm_device_wifi_set_wireless_enabled (NMDeviceWifi *device, gboolean enabled);

static void nm_client_initable_iface_init (GInitableIface *iface);
static void nm_client_async_initable_iface_init (GAsyncInitableIface *iface);
static GInitableIface *nm_client_parent_initable_iface;
static GAsyncInitableIface *nm_client_parent_async_initable_iface;

G_DEFINE_TYPE_WITH_CODE (NMClient, nm_client, NM_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, nm_client_initable_iface_init);
                         G_IMPLEMENT_INTERFACE (G_TYPE_ASYNC_INITABLE, nm_client_async_initable_iface_init);
                         )

#define NM_CLIENT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_CLIENT, NMClientPrivate))

typedef struct {
	DBusGProxy *client_proxy;
	DBusGProxy *bus_proxy;
	gboolean manager_running;
	char *version;
	NMState state;
	gboolean startup;
	GPtrArray *devices;
	GPtrArray *active_connections;
	NMConnectivityState connectivity;
	NMActiveConnection *primary_connection;
	NMActiveConnection *activating_connection;

	DBusGProxyCall *perm_call;
	GHashTable *permissions;

	/* Activations waiting for their NMActiveConnection
	 * to appear and then their callback to be called.
	 */
	GSList *pending_activations;

	gboolean networking_enabled;
	gboolean wireless_enabled;
	gboolean wireless_hw_enabled;

	gboolean wwan_enabled;
	gboolean wwan_hw_enabled;

	gboolean wimax_enabled;
	gboolean wimax_hw_enabled;
} NMClientPrivate;

enum {
	PROP_0,
	PROP_VERSION,
	PROP_STATE,
	PROP_STARTUP,
	PROP_MANAGER_RUNNING,
	PROP_NETWORKING_ENABLED,
	PROP_WIRELESS_ENABLED,
	PROP_WIRELESS_HARDWARE_ENABLED,
	PROP_WWAN_ENABLED,
	PROP_WWAN_HARDWARE_ENABLED,
	PROP_WIMAX_ENABLED,
	PROP_WIMAX_HARDWARE_ENABLED,
	PROP_ACTIVE_CONNECTIONS,
	PROP_CONNECTIVITY,
	PROP_PRIMARY_CONNECTION,
	PROP_ACTIVATING_CONNECTION,
	PROP_DEVICES,

	LAST_PROP
};

enum {
	DEVICE_ADDED,
	DEVICE_REMOVED,
	PERMISSION_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static void proxy_name_owner_changed (DBusGProxy *proxy,
                                      const char *name,
                                      const char *old_owner,
                                      const char *new_owner,
                                      gpointer user_data);

/**********************************************************************/

/**
 * nm_client_error_quark:
 *
 * Registers an error quark for #NMClient if necessary.
 *
 * Returns: the error quark used for #NMClient errors.
 *
 * Since: 0.9.10
 **/
GQuark
nm_client_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-client-error-quark");
	return quark;
}

/**********************************************************************/

static void
nm_client_init (NMClient *client)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (client);

	priv->state = NM_STATE_UNKNOWN;

	priv->permissions = g_hash_table_new (g_direct_hash, g_direct_equal);
}

static void
poke_wireless_devices_with_rf_status (NMClient *client)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (client);
	int i;

	for (i = 0; priv->devices && (i < priv->devices->len); i++) {
		NMDevice *device = g_ptr_array_index (priv->devices, i);

		if (NM_IS_DEVICE_WIFI (device))
			_nm_device_wifi_set_wireless_enabled (NM_DEVICE_WIFI (device), priv->wireless_enabled);
	}
}

static void
wireless_enabled_cb (GObject *object, GParamSpec *pspec, gpointer user_data)
{
	poke_wireless_devices_with_rf_status (NM_CLIENT (object));
}

static void
register_properties (NMClient *client)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (client);
	const NMPropertiesInfo property_info[] = {
		{ NM_CLIENT_VERSION,                   &priv->version },
		{ NM_CLIENT_STATE,                     &priv->state },
		{ NM_CLIENT_STARTUP,                   &priv->startup },
		{ NM_CLIENT_NETWORKING_ENABLED,        &priv->networking_enabled },
		{ NM_CLIENT_WIRELESS_ENABLED,          &priv->wireless_enabled },
		{ NM_CLIENT_WIRELESS_HARDWARE_ENABLED, &priv->wireless_hw_enabled },
		{ NM_CLIENT_WWAN_ENABLED,              &priv->wwan_enabled },
		{ NM_CLIENT_WWAN_HARDWARE_ENABLED,     &priv->wwan_hw_enabled },
		{ NM_CLIENT_WIMAX_ENABLED,             &priv->wimax_enabled },
		{ NM_CLIENT_WIMAX_HARDWARE_ENABLED,    &priv->wimax_hw_enabled },
		{ NM_CLIENT_ACTIVE_CONNECTIONS,        &priv->active_connections, NULL, NM_TYPE_ACTIVE_CONNECTION },
		{ NM_CLIENT_CONNECTIVITY,              &priv->connectivity },
		{ NM_CLIENT_PRIMARY_CONNECTION,        &priv->primary_connection, NULL, NM_TYPE_ACTIVE_CONNECTION },
		{ NM_CLIENT_ACTIVATING_CONNECTION,     &priv->activating_connection, NULL, NM_TYPE_ACTIVE_CONNECTION },
		{ NM_CLIENT_DEVICES,                   &priv->devices, NULL, NM_TYPE_DEVICE, "device" },
		{ NULL },
	};

	_nm_object_register_properties (NM_OBJECT (client),
	                                priv->client_proxy,
	                                property_info);
}

#define NM_AUTH_PERMISSION_ENABLE_DISABLE_NETWORK     "org.freedesktop.NetworkManager.enable-disable-network"
#define NM_AUTH_PERMISSION_ENABLE_DISABLE_WIFI        "org.freedesktop.NetworkManager.enable-disable-wifi"
#define NM_AUTH_PERMISSION_ENABLE_DISABLE_WWAN        "org.freedesktop.NetworkManager.enable-disable-wwan"
#define NM_AUTH_PERMISSION_ENABLE_DISABLE_WIMAX       "org.freedesktop.NetworkManager.enable-disable-wimax"
#define NM_AUTH_PERMISSION_SLEEP_WAKE                 "org.freedesktop.NetworkManager.sleep-wake"
#define NM_AUTH_PERMISSION_NETWORK_CONTROL            "org.freedesktop.NetworkManager.network-control"
#define NM_AUTH_PERMISSION_WIFI_SHARE_PROTECTED       "org.freedesktop.NetworkManager.wifi.share.protected"
#define NM_AUTH_PERMISSION_WIFI_SHARE_OPEN            "org.freedesktop.NetworkManager.wifi.share.open"
#define NM_AUTH_PERMISSION_SETTINGS_MODIFY_SYSTEM     "org.freedesktop.NetworkManager.settings.modify.system"
#define NM_AUTH_PERMISSION_SETTINGS_MODIFY_OWN        "org.freedesktop.NetworkManager.settings.modify.own"
#define NM_AUTH_PERMISSION_SETTINGS_MODIFY_HOSTNAME   "org.freedesktop.NetworkManager.settings.modify.hostname"

static NMClientPermission
nm_permission_to_client (const char *nm)
{
	if (!strcmp (nm, NM_AUTH_PERMISSION_ENABLE_DISABLE_NETWORK))
		return NM_CLIENT_PERMISSION_ENABLE_DISABLE_NETWORK;
	else if (!strcmp (nm, NM_AUTH_PERMISSION_ENABLE_DISABLE_WIFI))
		return NM_CLIENT_PERMISSION_ENABLE_DISABLE_WIFI;
	else if (!strcmp (nm, NM_AUTH_PERMISSION_ENABLE_DISABLE_WWAN))
		return NM_CLIENT_PERMISSION_ENABLE_DISABLE_WWAN;
	else if (!strcmp (nm, NM_AUTH_PERMISSION_ENABLE_DISABLE_WIMAX))
		return NM_CLIENT_PERMISSION_ENABLE_DISABLE_WIMAX;
	else if (!strcmp (nm, NM_AUTH_PERMISSION_SLEEP_WAKE))
		return NM_CLIENT_PERMISSION_SLEEP_WAKE;
	else if (!strcmp (nm, NM_AUTH_PERMISSION_NETWORK_CONTROL))
		return NM_CLIENT_PERMISSION_NETWORK_CONTROL;
	else if (!strcmp (nm, NM_AUTH_PERMISSION_WIFI_SHARE_PROTECTED))
		return NM_CLIENT_PERMISSION_WIFI_SHARE_PROTECTED;
	else if (!strcmp (nm, NM_AUTH_PERMISSION_WIFI_SHARE_OPEN))
		return NM_CLIENT_PERMISSION_WIFI_SHARE_OPEN;
	else if (!strcmp (nm, NM_AUTH_PERMISSION_SETTINGS_MODIFY_SYSTEM))
		return NM_CLIENT_PERMISSION_SETTINGS_MODIFY_SYSTEM;
	else if (!strcmp (nm, NM_AUTH_PERMISSION_SETTINGS_MODIFY_OWN))
		return NM_CLIENT_PERMISSION_SETTINGS_MODIFY_OWN;
	else if (!strcmp (nm, NM_AUTH_PERMISSION_SETTINGS_MODIFY_HOSTNAME))
		return NM_CLIENT_PERMISSION_SETTINGS_MODIFY_HOSTNAME;

	return NM_CLIENT_PERMISSION_NONE;
}

static NMClientPermissionResult
nm_permission_result_to_client (const char *nm)
{
	if (!strcmp (nm, "yes"))
		return NM_CLIENT_PERMISSION_RESULT_YES;
	else if (!strcmp (nm, "no"))
		return NM_CLIENT_PERMISSION_RESULT_NO;
	else if (!strcmp (nm, "auth"))
		return NM_CLIENT_PERMISSION_RESULT_AUTH;
	return NM_CLIENT_PERMISSION_RESULT_UNKNOWN;
}

static void
update_permissions (NMClient *self, GHashTable *permissions)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);
	GHashTableIter iter;
	gpointer key, value;
	NMClientPermission perm;
	NMClientPermissionResult perm_result;
	GList *keys, *keys_iter;

	/* get list of old permissions for change notification */
	keys = g_hash_table_get_keys (priv->permissions);
	g_hash_table_remove_all (priv->permissions);

	if (permissions) {
		/* Process new permissions */
		g_hash_table_iter_init (&iter, permissions);
		while (g_hash_table_iter_next (&iter, &key, &value)) {
			perm = nm_permission_to_client ((const char *) key);
			perm_result = nm_permission_result_to_client ((const char *) value);
			if (perm) {
				g_hash_table_insert (priv->permissions,
				                     GUINT_TO_POINTER (perm),
				                     GUINT_TO_POINTER (perm_result));

				/* Remove this permission from the list of previous permissions
				 * we'll be sending NM_CLIENT_PERMISSION_RESULT_UNKNOWN for
				 * in the change signal since it is still a known permission.
				 */
				keys = g_list_remove (keys, GUINT_TO_POINTER (perm));
			}
		}
	}

	/* Signal changes in all updated permissions */
	g_hash_table_iter_init (&iter, priv->permissions);
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		g_signal_emit (self, signals[PERMISSION_CHANGED], 0,
		               GPOINTER_TO_UINT (key),
		               GPOINTER_TO_UINT (value));
	}

	/* And signal changes in all permissions that used to be valid but for
	 * some reason weren't received in the last request (if any).
	 */
	for (keys_iter = keys; keys_iter; keys_iter = g_list_next (keys_iter)) {
		g_signal_emit (self, signals[PERMISSION_CHANGED], 0,
		               GPOINTER_TO_UINT (keys_iter->data),
		               NM_CLIENT_PERMISSION_RESULT_UNKNOWN);
	}
	g_list_free (keys);
}

static gboolean
get_permissions_sync (NMClient *self, GError **error)
{
	gboolean success;
	GHashTable *permissions = NULL;

	success = dbus_g_proxy_call_with_timeout (NM_CLIENT_GET_PRIVATE (self)->client_proxy,
	                                          "GetPermissions", 3000, error,
	                                          G_TYPE_INVALID,
	                                          DBUS_TYPE_G_MAP_OF_STRING, &permissions, G_TYPE_INVALID);
	update_permissions (self, success ? permissions : NULL);
	if (permissions)
		g_hash_table_destroy (permissions);

	return success;
}

static void
get_permissions_reply (DBusGProxy *proxy,
                       DBusGProxyCall *call,
                       gpointer user_data)
{
	NMClient *self = NM_CLIENT (user_data);
	GHashTable *permissions;
	GError *error = NULL;

	dbus_g_proxy_end_call (proxy, call, &error,
	                       DBUS_TYPE_G_MAP_OF_STRING, &permissions,
	                       G_TYPE_INVALID);
	NM_CLIENT_GET_PRIVATE (self)->perm_call = NULL;
	update_permissions (NM_CLIENT (user_data), error ? NULL : permissions);
	g_clear_error (&error);
}

static void
client_recheck_permissions (DBusGProxy *proxy, gpointer user_data)
{
	NMClient *self = NM_CLIENT (user_data);
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);

	if (!priv->perm_call) {
		priv->perm_call = dbus_g_proxy_begin_call (NM_CLIENT_GET_PRIVATE (self)->client_proxy, "GetPermissions",
		                                           get_permissions_reply, self, NULL,
		                                           G_TYPE_INVALID);
	}
}

/**
 * nm_client_get_devices:
 * @client: a #NMClient
 *
 * Gets all the known network devices.  Use nm_device_get_type() or the
 * <literal>NM_IS_DEVICE_XXXX</literal> functions to determine what kind of
 * device member of the returned array is, and then you may use device-specific
 * methods such as nm_device_ethernet_get_hw_address().
 *
 * Returns: (transfer none) (element-type NMDevice): a #GPtrArray
 * containing all the #NMDevices.  The returned array is owned by the
 * #NMClient object and should not be modified.
 **/
const GPtrArray *
nm_client_get_devices (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);

	_nm_object_ensure_inited (NM_OBJECT (client));

	return handle_ptr_array_return (NM_CLIENT_GET_PRIVATE (client)->devices);
}

/**
 * nm_client_get_device_by_path:
 * @client: a #NMClient
 * @object_path: the object path to search for
 *
 * Gets a #NMDevice from a #NMClient.
 *
 * Returns: (transfer none): the #NMDevice for the given @object_path or %NULL if none is found.
 **/
NMDevice *
nm_client_get_device_by_path (NMClient *client, const char *object_path)
{
	const GPtrArray *devices;
	int i;
	NMDevice *device = NULL;

	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);
	g_return_val_if_fail (object_path, NULL);

	devices = nm_client_get_devices (client);
	if (!devices)
		return NULL;

	for (i = 0; i < devices->len; i++) {
		NMDevice *candidate = g_ptr_array_index (devices, i);
		if (!strcmp (nm_object_get_path (NM_OBJECT (candidate)), object_path)) {
			device = candidate;
			break;
		}
	}

	return device;
}

/**
 * nm_client_get_device_by_iface:
 * @client: a #NMClient
 * @iface: the interface name to search for
 *
 * Gets a #NMDevice from a #NMClient.
 *
 * Returns: (transfer none): the #NMDevice for the given @iface or %NULL if none is found.
 **/
NMDevice *
nm_client_get_device_by_iface (NMClient *client, const char *iface)
{
	const GPtrArray *devices;
	int i;
	NMDevice *device = NULL;

	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);
	g_return_val_if_fail (iface, NULL);

	devices = nm_client_get_devices (client);
	if (!devices)
		return NULL;

	for (i = 0; i < devices->len; i++) {
		NMDevice *candidate = g_ptr_array_index (devices, i);
		if (!strcmp (nm_device_get_iface (candidate), iface)) {
			device = candidate;
			break;
		}
	}

	return device;
}

typedef struct {
	NMClient *client;
	NMClientActivateFn act_fn;
	NMClientAddActivateFn add_act_fn;
	char *active_path;
	char *new_connection_path;
	guint idle_id;
	gpointer user_data;
} ActivateInfo;

static void
activate_info_free (ActivateInfo *info)
{
	if (info->idle_id)
		g_source_remove (info->idle_id);
	g_free (info->active_path);
	g_free (info->new_connection_path);
	memset (info, 0, sizeof (*info));
	g_slice_free (ActivateInfo, info);
}

static void
activate_info_complete (ActivateInfo *info,
                        NMActiveConnection *active,
                        GError *error)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (info->client);

	if (info->act_fn)
		info->act_fn (info->client, error ? NULL : active, error, info->user_data);
	else if (info->add_act_fn) {
		info->add_act_fn (info->client,
		                  error ? NULL : active,
		                  error ? NULL : info->new_connection_path,
		                  error,
		                  info->user_data);
	} else if (error)
		g_warning ("Device activation failed: (%d) %s", error->code, error->message);

	priv->pending_activations = g_slist_remove (priv->pending_activations, info);
}

static void
recheck_pending_activations (NMClient *self, const char *failed_path, GError *error)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);
	GSList *iter, *next;
	const GPtrArray *active_connections;
	gboolean found_in_active = FALSE;
	gboolean found_in_pending = FALSE;
	ActivateInfo *ainfo = NULL;
	int i;

	active_connections = nm_client_get_active_connections (self);

	/* For each pending activation, look for a active connection that has
	 * the pending activation's object path, and call pending connection's
	 * callback.
	 * If the connection to activate doesn't make it to active_connections,
	 * due to an error, we have to call the callback for failed_path.
	 */
	for (iter = priv->pending_activations; iter; iter = next) {
		ActivateInfo *info = iter->data;

		next = g_slist_next (iter);

		if (!found_in_pending && failed_path && g_strcmp0 (failed_path, info->active_path) == 0) {
			found_in_pending = TRUE;
			ainfo = info;
		}

		for (i = 0; active_connections && i < active_connections->len; i++) {
			NMActiveConnection *active = g_ptr_array_index (active_connections, i);
			const char *active_path = nm_object_get_path (NM_OBJECT (active));

			if (!found_in_active && failed_path && g_strcmp0 (failed_path, active_path) == 0)
				found_in_active = TRUE;

			if (g_strcmp0 (info->active_path, active_path) == 0) {
				/* Call the pending activation's callback and it all up */
				activate_info_complete (info, active, NULL);
				activate_info_free (info);
				break;
			}
		}
	}

	if (!found_in_active && found_in_pending) {
		/* A newly activated connection failed due to some immediate error
		 * and disappeared from active connection list.  Make sure the
		 * callback gets called.
		 */
		activate_info_complete (ainfo, NULL, error);
		activate_info_free (ainfo);
	}
}

static void
activate_cb (DBusGProxy *proxy,
             DBusGProxyCall *call,
             gpointer user_data)
{
	ActivateInfo *info = user_data;
	char *path;
	GError *error = NULL;

	dbus_g_proxy_end_call (proxy, call, &error,
	                       DBUS_TYPE_G_OBJECT_PATH, &path,
	                       G_TYPE_INVALID);
	if (error) {
		activate_info_complete (info, NULL, error);
		activate_info_free (info);
		g_clear_error (&error);
	} else {
		info->active_path = path;
		recheck_pending_activations (info->client, NULL, NULL);
	}
}

static gboolean
activate_nm_not_running (gpointer user_data)
{
	ActivateInfo *info = user_data;
	GError *error;

	info->idle_id = 0;

	error = g_error_new_literal (NM_CLIENT_ERROR,
	                             NM_CLIENT_ERROR_MANAGER_NOT_RUNNING,
	                             "NetworkManager is not running");
	activate_info_complete (info, NULL, error);
	activate_info_free (info);
	g_clear_error (&error);
	return FALSE;
}

/**
 * nm_client_activate_connection:
 * @client: a #NMClient
 * @connection: (allow-none): an #NMConnection
 * @device: (allow-none): the #NMDevice
 * @specific_object: (allow-none): the object path of a connection-type-specific
 *   object this activation should use. This parameter is currently ignored for
 *   wired and mobile broadband connections, and the value of %NULL should be used
 *   (ie, no specific object).  For Wi-Fi or WiMAX connections, pass the object
 *   path of a #NMAccessPoint or #NMWimaxNsp owned by @device, which you can
 *   get using nm_object_get_path(), and which will be used to complete the
 *   details of the newly added connection.
 * @callback: (scope async) (allow-none): the function to call when the call is done
 * @user_data: (closure): user data to pass to the callback function
 *
 * Starts a connection to a particular network using the configuration settings
 * from @connection and the network device @device.  Certain connection types
 * also take a "specific object" which is the object path of a connection-
 * specific object, like an #NMAccessPoint for Wi-Fi connections, or an
 * #NMWimaxNsp for WiMAX connections, to which you wish to connect.  If the
 * specific object is not given, NetworkManager can, in some cases, automatically
 * determine which network to connect to given the settings in @connection.
 *
 * If @connection is not given for a device-based activation, NetworkManager
 * picks the best available connection for the device and activates it.
 *
 * Note that the callback is invoked when NetworkManager has started activating
 * the new connection, not when it finishes. You can used the returned
 * #NMActiveConnection object (in particular, #NMActiveConnection:state) to
 * track the activation to its completion.
 **/
void
nm_client_activate_connection (NMClient *client,
                               NMConnection *connection,
                               NMDevice *device,
                               const char *specific_object,
                               NMClientActivateFn callback,
                               gpointer user_data)
{
	NMClientPrivate *priv;
	ActivateInfo *info;

	g_return_if_fail (NM_IS_CLIENT (client));
	if (device)
		g_return_if_fail (NM_IS_DEVICE (device));
	if (connection)
		g_return_if_fail (NM_IS_CONNECTION (connection));

	info = g_slice_new0 (ActivateInfo);
	info->act_fn = callback;
	info->user_data = user_data;
	info->client = client;

	priv = NM_CLIENT_GET_PRIVATE (client);
	priv->pending_activations = g_slist_prepend (priv->pending_activations, info);

	if (priv->manager_running == FALSE) {
		info->idle_id = g_idle_add (activate_nm_not_running, info);
		return;
	}

	dbus_g_proxy_begin_call (priv->client_proxy, "ActivateConnection",
	                         activate_cb, info, NULL,
	                         DBUS_TYPE_G_OBJECT_PATH, connection ? nm_connection_get_path (connection) : "/",
	                         DBUS_TYPE_G_OBJECT_PATH, device ? nm_object_get_path (NM_OBJECT (device)) : "/",
	                         DBUS_TYPE_G_OBJECT_PATH, specific_object ? specific_object : "/",
	                         G_TYPE_INVALID);
}

static void
add_activate_cb (DBusGProxy *proxy,
                 DBusGProxyCall *call,
                 gpointer user_data)
{
	ActivateInfo *info = user_data;
	char *connection_path;
	char *active_path;
	GError *error = NULL;

	dbus_g_proxy_end_call (proxy, call, &error,
	                       DBUS_TYPE_G_OBJECT_PATH, &connection_path,
	                       DBUS_TYPE_G_OBJECT_PATH, &active_path,
	                       G_TYPE_INVALID);
	if (error) {
		activate_info_complete (info, NULL, error);
		activate_info_free (info);
	} else {
		info->new_connection_path = connection_path;
		info->active_path = active_path;
		recheck_pending_activations (info->client, NULL, NULL);
	}
}

/**
 * nm_client_add_and_activate_connection:
 * @client: a #NMClient
 * @partial: (allow-none): an #NMConnection to add; the connection may be
 *   partially filled (or even %NULL) and will be completed by NetworkManager
 *   using the given @device and @specific_object before being added
 * @device: the #NMDevice
 * @specific_object: (allow-none): the object path of a connection-type-specific
 *   object this activation should use. This parameter is currently ignored for
 *   wired and mobile broadband connections, and the value of %NULL should be used
 *   (ie, no specific object).  For Wi-Fi or WiMAX connections, pass the object
 *   path of a #NMAccessPoint or #NMWimaxNsp owned by @device, which you can
 *   get using nm_object_get_path(), and which will be used to complete the
 *   details of the newly added connection.
 * @callback: (scope async) (allow-none): the function to call when the call is done
 * @user_data: (closure): user data to pass to the callback function
 *
 * Adds a new connection using the given details (if any) as a template,
 * automatically filling in missing settings with the capabilities of the
 * given device and specific object.  The new connection is then activated.
 * Cannot be used for VPN connections at this time.
 *
 * Note that the callback is invoked when NetworkManager has started activating
 * the new connection, not when it finishes. You can used the returned
 * #NMActiveConnection object (in particular, #NMActiveConnection:state) to
 * track the activation to its completion.
 **/
void
nm_client_add_and_activate_connection (NMClient *client,
                                       NMConnection *partial,
                                       NMDevice *device,
                                       const char *specific_object,
                                       NMClientAddActivateFn callback,
                                       gpointer user_data)
{
	NMClientPrivate *priv;
	ActivateInfo *info;
	GHashTable *hash = NULL;

	g_return_if_fail (NM_IS_CLIENT (client));
	g_return_if_fail (NM_IS_DEVICE (device));

	info = g_slice_new0 (ActivateInfo);
	info->add_act_fn = callback;
	info->user_data = user_data;
	info->client = client;

	if (partial)
		hash = nm_connection_to_hash (partial, NM_SETTING_HASH_FLAG_ALL);
	if (!hash)
		hash = g_hash_table_new (g_str_hash, g_str_equal);

	priv = NM_CLIENT_GET_PRIVATE (client);
	priv->pending_activations = g_slist_prepend (priv->pending_activations, info);

	if (priv->manager_running) {
		dbus_g_proxy_begin_call (priv->client_proxy, "AddAndActivateConnection",
		                         add_activate_cb, info, NULL,
		                         DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT, hash,
		                         DBUS_TYPE_G_OBJECT_PATH, nm_object_get_path (NM_OBJECT (device)),
		                         DBUS_TYPE_G_OBJECT_PATH, specific_object ? specific_object : "/",
		                         G_TYPE_INVALID);
	} else
		info->idle_id = g_idle_add (activate_nm_not_running, info);

	g_hash_table_unref (hash);
}

static void
active_connections_changed_cb (GObject *object, GParamSpec *pspec, gpointer user_data)
{
	recheck_pending_activations (NM_CLIENT (object), NULL, NULL);
}

static void
object_creation_failed_cb (GObject *object, GError *error, char *failed_path)
{
	if (error)
		recheck_pending_activations (NM_CLIENT (object), failed_path, error);
}

/**
 * nm_client_deactivate_connection:
 * @client: a #NMClient
 * @active: the #NMActiveConnection to deactivate
 *
 * Deactivates an active #NMActiveConnection.
 **/
void
nm_client_deactivate_connection (NMClient *client, NMActiveConnection *active)
{
	NMClientPrivate *priv;
	const char *path;
	GError *error = NULL;

	g_return_if_fail (NM_IS_CLIENT (client));
	g_return_if_fail (NM_IS_ACTIVE_CONNECTION (active));

	priv = NM_CLIENT_GET_PRIVATE (client);
	if (!priv->manager_running)
		return;

	path = nm_object_get_path (NM_OBJECT (active));
	if (!dbus_g_proxy_call (priv->client_proxy, "DeactivateConnection", &error,
	                        DBUS_TYPE_G_OBJECT_PATH, path,
	                        G_TYPE_INVALID,
	                        G_TYPE_INVALID)) {
		g_warning ("Could not deactivate connection '%s': %s", 
		           path, error ? error->message : "(unknown)");
		g_clear_error (&error);
	}
}

/**
 * nm_client_get_active_connections:
 * @client: a #NMClient
 *
 * Gets the active connections.
 *
 * Returns: (transfer none) (element-type NMActiveConnection): a #GPtrArray
 *  containing all the active #NMActiveConnections.
 * The returned array is owned by the client and should not be modified.
 **/
const GPtrArray *
nm_client_get_active_connections (NMClient *client)
{
	NMClientPrivate *priv;

	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);

	_nm_object_ensure_inited (NM_OBJECT (client));

	priv = NM_CLIENT_GET_PRIVATE (client);
	if (!priv->manager_running)
		return NULL;

	return handle_ptr_array_return (priv->active_connections);
}

/**
 * nm_client_wireless_get_enabled:
 * @client: a #NMClient
 *
 * Determines whether the wireless is enabled.
 *
 * Returns: %TRUE if wireless is enabled
 **/
gboolean
nm_client_wireless_get_enabled (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	_nm_object_ensure_inited (NM_OBJECT (client));
	return NM_CLIENT_GET_PRIVATE (client)->wireless_enabled;
}

/**
 * nm_client_wireless_set_enabled:
 * @client: a #NMClient
 * @enabled: %TRUE to enable wireless
 *
 * Enables or disables wireless devices.
 **/
void
nm_client_wireless_set_enabled (NMClient *client, gboolean enabled)
{
	GValue value = G_VALUE_INIT;

	g_return_if_fail (NM_IS_CLIENT (client));

	if (!NM_CLIENT_GET_PRIVATE (client)->manager_running)
		return;

	g_value_init (&value, G_TYPE_BOOLEAN);
	g_value_set_boolean (&value, enabled);

	_nm_object_set_property (NM_OBJECT (client),
	                         NM_DBUS_INTERFACE,
	                         "WirelessEnabled",
	                         &value);
}

/**
 * nm_client_wireless_hardware_get_enabled:
 * @client: a #NMClient
 *
 * Determines whether the wireless hardware is enabled.
 *
 * Returns: %TRUE if the wireless hardware is enabled
 **/
gboolean
nm_client_wireless_hardware_get_enabled (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	_nm_object_ensure_inited (NM_OBJECT (client));
	return NM_CLIENT_GET_PRIVATE (client)->wireless_hw_enabled;
}

/**
 * nm_client_wwan_get_enabled:
 * @client: a #NMClient
 *
 * Determines whether WWAN is enabled.
 *
 * Returns: %TRUE if WWAN is enabled
 **/
gboolean
nm_client_wwan_get_enabled (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	_nm_object_ensure_inited (NM_OBJECT (client));
	return NM_CLIENT_GET_PRIVATE (client)->wwan_enabled;
}

/**
 * nm_client_wwan_set_enabled:
 * @client: a #NMClient
 * @enabled: %TRUE to enable WWAN
 *
 * Enables or disables WWAN devices.
 **/
void
nm_client_wwan_set_enabled (NMClient *client, gboolean enabled)
{
	GValue value = G_VALUE_INIT;

	g_return_if_fail (NM_IS_CLIENT (client));

	if (!NM_CLIENT_GET_PRIVATE (client)->manager_running)
		return;

	g_value_init (&value, G_TYPE_BOOLEAN);
	g_value_set_boolean (&value, enabled);

	_nm_object_set_property (NM_OBJECT (client),
	                         NM_DBUS_INTERFACE,
	                         "WwanEnabled",
	                         &value);
}

/**
 * nm_client_wwan_hardware_get_enabled:
 * @client: a #NMClient
 *
 * Determines whether the WWAN hardware is enabled.
 *
 * Returns: %TRUE if the WWAN hardware is enabled
 **/
gboolean
nm_client_wwan_hardware_get_enabled (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	_nm_object_ensure_inited (NM_OBJECT (client));
	return NM_CLIENT_GET_PRIVATE (client)->wwan_hw_enabled;
}

/**
 * nm_client_wimax_get_enabled:
 * @client: a #NMClient
 *
 * Determines whether WiMAX is enabled.
 *
 * Returns: %TRUE if WiMAX is enabled
 **/
gboolean
nm_client_wimax_get_enabled (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	_nm_object_ensure_inited (NM_OBJECT (client));
	return NM_CLIENT_GET_PRIVATE (client)->wimax_enabled;
}

/**
 * nm_client_wimax_set_enabled:
 * @client: a #NMClient
 * @enabled: %TRUE to enable WiMAX
 *
 * Enables or disables WiMAX devices.
 **/
void
nm_client_wimax_set_enabled (NMClient *client, gboolean enabled)
{
	GValue value = G_VALUE_INIT;

	g_return_if_fail (NM_IS_CLIENT (client));

	if (!NM_CLIENT_GET_PRIVATE (client)->manager_running)
		return;

	g_value_init (&value, G_TYPE_BOOLEAN);
	g_value_set_boolean (&value, enabled);

	_nm_object_set_property (NM_OBJECT (client),
	                         NM_DBUS_INTERFACE,
	                         "WimaxEnabled",
	                         &value);
}

/**
 * nm_client_wimax_hardware_get_enabled:
 * @client: a #NMClient
 *
 * Determines whether the WiMAX hardware is enabled.
 *
 * Returns: %TRUE if the WiMAX hardware is enabled
 **/
gboolean
nm_client_wimax_hardware_get_enabled (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	_nm_object_ensure_inited (NM_OBJECT (client));
	return NM_CLIENT_GET_PRIVATE (client)->wimax_hw_enabled;
}

/**
 * nm_client_get_version:
 * @client: a #NMClient
 *
 * Gets NetworkManager version.
 *
 * Returns: string with the version
 **/
const char *
nm_client_get_version (NMClient *client)
{
	NMClientPrivate *priv;

	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);

	priv = NM_CLIENT_GET_PRIVATE (client);

	_nm_object_ensure_inited (NM_OBJECT (client));

	return priv->manager_running ? priv->version : NULL;
}

/**
 * nm_client_get_state:
 * @client: a #NMClient
 *
 * Gets the current daemon state.
 *
 * Returns: the current %NMState
 **/
NMState
nm_client_get_state (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NM_STATE_UNKNOWN);

	_nm_object_ensure_inited (NM_OBJECT (client));

	return NM_CLIENT_GET_PRIVATE (client)->state;
}

/**
 * nm_client_get_startup:
 * @client: a #NMClient
 *
 * Tests whether the daemon is still in the process of activating
 * connections at startup.
 *
 * Returns: whether the daemon is still starting up
 *
 * Since: 0.9.10
 **/
gboolean
nm_client_get_startup (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NM_STATE_UNKNOWN);

	_nm_object_ensure_inited (NM_OBJECT (client));

	return NM_CLIENT_GET_PRIVATE (client)->startup;
}

/**
 * nm_client_networking_get_enabled:
 * @client: a #NMClient
 *
 * Whether networking is enabled or disabled.
 *
 * Returns: %TRUE if networking is enabled, %FALSE if networking is disabled
 **/
gboolean
nm_client_networking_get_enabled (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	_nm_object_ensure_inited (NM_OBJECT (client));
	return NM_CLIENT_GET_PRIVATE (client)->networking_enabled;
}

/**
 * nm_client_networking_set_enabled:
 * @client: a #NMClient
 * @enabled: %TRUE to set networking enabled, %FALSE to set networking disabled
 *
 * Enables or disables networking.  When networking is disabled, all controlled
 * interfaces are disconnected and deactivated.  When networking is enabled,
 * all controlled interfaces are available for activation.
 **/
void
nm_client_networking_set_enabled (NMClient *client, gboolean enable)
{
	GError *err = NULL;

	g_return_if_fail (NM_IS_CLIENT (client));

	if (!NM_CLIENT_GET_PRIVATE (client)->manager_running)
		return;

	if (!dbus_g_proxy_call (NM_CLIENT_GET_PRIVATE (client)->client_proxy, "Enable", &err,
	                        G_TYPE_BOOLEAN, enable,
	                        G_TYPE_INVALID,
	                        G_TYPE_INVALID)) {
		g_warning ("Error enabling/disabling networking: %s",
		           err ? err->message : "(unknown)");
		g_clear_error (&err);
	}
}

/**
 * nm_client_sleep:
 * @client: a #NMClient
 * @sleep_: %TRUE to put the daemon to sleep
 *
 * Deprecated; use nm_client_networking_set_enabled() instead.
 **/
void
nm_client_sleep (NMClient *client, gboolean sleep_)
{
	nm_client_networking_set_enabled (client, !sleep_);
}

/**
 * nm_client_get_manager_running:
 * @client: a #NMClient
 *
 * Determines whether the daemon is running.
 *
 * Returns: %TRUE if the daemon is running
 **/
gboolean
nm_client_get_manager_running (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	return NM_CLIENT_GET_PRIVATE (client)->manager_running;
}

/**
 * nm_client_get_permission_result:
 * @client: a #NMClient
 * @permission: the permission for which to return the result, one of #NMClientPermission
 *
 * Requests the result of a specific permission, which indicates whether the
 * client can or cannot perform the action the permission represents
 *
 * Returns: the permission's result, one of #NMClientPermissionResult
 **/
NMClientPermissionResult
nm_client_get_permission_result (NMClient *client, NMClientPermission permission)
{
	gpointer result;

	g_return_val_if_fail (NM_IS_CLIENT (client), NM_CLIENT_PERMISSION_RESULT_UNKNOWN);

	result = g_hash_table_lookup (NM_CLIENT_GET_PRIVATE (client)->permissions,
	                              GUINT_TO_POINTER (permission));
	return GPOINTER_TO_UINT (result);
}

/**
 * nm_client_get_logging:
 * @client: a #NMClient
 * @level: (allow-none): return location for logging level string
 * @domains: (allow-none): return location for log domains string. The string is
 *   a list of domains separated by ","
 * @error: (allow-none): return location for a #GError, or %NULL
 *
 * Gets NetworkManager current logging level and domains.
 *
 * Returns: %TRUE on success, %FALSE otherwise
 *
 * Since: 0.9.8
 **/
gboolean
nm_client_get_logging (NMClient *client, char **level, char **domains, GError **error)
{
	NMClientPrivate *priv;

	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);
	g_return_val_if_fail (level == NULL || *level == NULL, FALSE);
	g_return_val_if_fail (domains == NULL || *domains == NULL, FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	priv = NM_CLIENT_GET_PRIVATE (client);
	if (!priv->manager_running) {
		g_set_error_literal (error,
		                     NM_CLIENT_ERROR,
		                     NM_CLIENT_ERROR_MANAGER_NOT_RUNNING,
		                     "NetworkManager is not running");
		return FALSE;
	}

	if (!level && !domains)
		return TRUE;

	return dbus_g_proxy_call (priv->client_proxy, "GetLogging", error,
	                          G_TYPE_INVALID,
	                          G_TYPE_STRING, level,
	                          G_TYPE_STRING, domains,
	                          G_TYPE_INVALID);
}

/**
 * nm_client_set_logging:
 * @client: a #NMClient
 * @level: (allow-none): logging level to set (%NULL or an empty string for no change)
 * @domains: (allow-none): logging domains to set. The string should be a list of log
 *   domains separated by ",". (%NULL or an empty string for no change)
 * @error: (allow-none): return location for a #GError, or %NULL
 *
 * Sets NetworkManager logging level and/or domains.
 *
 * Returns: %TRUE on success, %FALSE otherwise
 *
 * Since: 0.9.8
 **/
gboolean
nm_client_set_logging (NMClient *client, const char *level, const char *domains, GError **error)
{
	NMClientPrivate *priv;

	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	priv = NM_CLIENT_GET_PRIVATE (client);
	if (!priv->manager_running) {
		g_set_error_literal (error,
		                     NM_CLIENT_ERROR,
		                     NM_CLIENT_ERROR_MANAGER_NOT_RUNNING,
		                     "NetworkManager is not running");
		return FALSE;
	}

	if (!level && !domains)
		return TRUE;

	return dbus_g_proxy_call (priv->client_proxy, "SetLogging", error,
	                          G_TYPE_STRING, level ? level : "",
	                          G_TYPE_STRING, domains ? domains : "",
	                          G_TYPE_INVALID,
	                          G_TYPE_INVALID);
}

/**
 * nm_client_get_primary_connection:
 * @client: an #NMClient
 *
 * Gets the #NMActiveConnection corresponding to the primary active
 * network device.
 *
 * In particular, when there is no VPN active, or the VPN does not
 * have the default route, this returns the active connection that has
 * the default route. If there is a VPN active with the default route,
 * then this function returns the active connection that contains the
 * route to the VPN endpoint.
 *
 * If there is no default route, or the default route is over a
 * non-NetworkManager-recognized device, this will return %NULL.
 *
 * Returns: (transfer none): the appropriate #NMActiveConnection, if
 * any
 *
 * Since: 0.9.8.6
 */
NMActiveConnection *
nm_client_get_primary_connection (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);

	_nm_object_ensure_inited (NM_OBJECT (client));
	return NM_CLIENT_GET_PRIVATE (client)->primary_connection;
}

/**
 * nm_client_get_activating_connection:
 * @client: an #NMClient
 *
 * Gets the #NMActiveConnection corresponding to a
 * currently-activating connection that is expected to become the new
 * #NMClient:primary-connection upon successful activation.
 *
 * Returns: (transfer none): the appropriate #NMActiveConnection, if
 * any.
 *
 * Since: 0.9.8.6
 */
NMActiveConnection *
nm_client_get_activating_connection (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);

	_nm_object_ensure_inited (NM_OBJECT (client));
	return NM_CLIENT_GET_PRIVATE (client)->activating_connection;
}

/****************************************************************/

static void
free_devices (NMClient *client, gboolean emit_signals)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (client);
	GPtrArray *devices;
	NMDevice *device;
	int i;

	if (!priv->devices)
		return;

	devices = priv->devices;
	priv->devices = NULL;
	for (i = 0; i < devices->len; i++) {
		device = devices->pdata[i];
		if (emit_signals)
			g_signal_emit (client, signals[DEVICE_REMOVED], 0, device);
		g_object_unref (device);
	}
	g_ptr_array_free (devices, TRUE);
}

static void
free_active_connections (NMClient *client, gboolean emit_signals)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (client);
	GPtrArray *active_connections;
	NMActiveConnection *active_connection;
	int i;

	if (!priv->active_connections)
		return;

	active_connections = priv->active_connections;
	priv->active_connections = NULL;
	for (i = 0; i < active_connections->len; i++) {
		active_connection = active_connections->pdata[i];
		/* Break circular refs */
		g_object_run_dispose (G_OBJECT (active_connection));
		g_object_unref (active_connection);
	}
	g_ptr_array_free (active_connections, TRUE);

	if (emit_signals)
		g_object_notify (G_OBJECT (client), NM_CLIENT_ACTIVE_CONNECTIONS);
}

static void
updated_properties (GObject *object, GAsyncResult *result, gpointer user_data)
{
	NMClient *client = NM_CLIENT (user_data);
	GError *error = NULL;

	if (!_nm_object_reload_properties_finish (NM_OBJECT (object), result, &error)) {
		g_warning ("%s: error reading NMClient properties: %s", __func__, error->message);
		g_error_free (error);
	}

	_nm_object_queue_notify (NM_OBJECT (client), NM_CLIENT_MANAGER_RUNNING);
}

static void
proxy_name_owner_changed (DBusGProxy *proxy,
                          const char *name,
                          const char *old_owner,
                          const char *new_owner,
                          gpointer user_data)
{
	NMClient *client = NM_CLIENT (user_data);
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (client);
	gboolean old_good = (old_owner && strlen (old_owner));
	gboolean new_good = (new_owner && strlen (new_owner));
	gboolean new_running = FALSE;

	if (!name || strcmp (name, NM_DBUS_SERVICE))
		return;

	if (!old_good && new_good)
		new_running = TRUE;
	else if (old_good && !new_good)
		new_running = FALSE;

	if (new_running == priv->manager_running)
		return;

	priv->manager_running = new_running;
	if (!priv->manager_running) {
		priv->state = NM_STATE_UNKNOWN;
		priv->startup = FALSE;
		_nm_object_queue_notify (NM_OBJECT (client), NM_CLIENT_MANAGER_RUNNING);
		_nm_object_suppress_property_updates (NM_OBJECT (client), TRUE);
		poke_wireless_devices_with_rf_status (client);
		free_devices (client, TRUE);
		free_active_connections (client, TRUE);
		update_permissions (client, NULL);
		priv->wireless_enabled = FALSE;
		priv->wireless_hw_enabled = FALSE;
		priv->wwan_enabled = FALSE;
		priv->wwan_hw_enabled = FALSE;
		priv->wimax_enabled = FALSE;
		priv->wimax_hw_enabled = FALSE;
		g_free (priv->version);
		priv->version = NULL;

		/* Clear object cache to ensure bad refcounting by clients doesn't
		 * keep objects in the cache.
		 */
		_nm_object_cache_clear ();
	} else {
		_nm_object_suppress_property_updates (NM_OBJECT (client), FALSE);
		_nm_object_reload_properties_async (NM_OBJECT (client), updated_properties, client);
		client_recheck_permissions (priv->client_proxy, client);
	}
}

/**
 * nm_client_get_connectivity:
 * @client: an #NMClient
 *
 * Gets the current network connectivity state. Contrast
 * nm_client_check_connectivity() and
 * nm_client_check_connectivity_async(), which re-check the
 * connectivity state first before returning any information.
 *
 * Returns: the current connectivity state
 * Since: 0.9.8.6
 */
NMConnectivityState
nm_client_get_connectivity (NMClient *client)
{
	NMClientPrivate *priv;

	g_return_val_if_fail (NM_IS_CLIENT (client), NM_CONNECTIVITY_UNKNOWN);
	priv = NM_CLIENT_GET_PRIVATE (client);

	_nm_object_ensure_inited (NM_OBJECT (client));

	return priv->connectivity;
}

/**
 * nm_client_check_connectivity:
 * @client: an #NMClient
 * @cancellable: a #GCancellable
 * @error: return location for a #GError
 *
 * Updates the network connectivity state and returns the (new)
 * current state. Contrast nm_client_get_connectivity(), which returns
 * the most recent known state without re-checking.
 *
 * This is a blocking call; use nm_client_check_connectivity_async()
 * if you do not want to block.
 *
 * Returns: the (new) current connectivity state
 * Since: 0.9.8.6
 */
NMConnectivityState
nm_client_check_connectivity (NMClient *client,
                              GCancellable *cancellable,
                              GError **error)
{
	NMClientPrivate *priv;
	NMConnectivityState connectivity;

	g_return_val_if_fail (NM_IS_CLIENT (client), NM_CONNECTIVITY_UNKNOWN);
	priv = NM_CLIENT_GET_PRIVATE (client);

	if (!dbus_g_proxy_call (priv->client_proxy, "CheckConnectivity", error,
	                        G_TYPE_INVALID,
	                        G_TYPE_UINT, &connectivity,
	                        G_TYPE_INVALID))
		connectivity = NM_CONNECTIVITY_UNKNOWN;

	return connectivity;
}

typedef struct {
	NMClient *client;
	DBusGProxyCall *call;
	GCancellable *cancellable;
	guint cancelled_id;
	NMConnectivityState connectivity;
} CheckConnectivityData;

static void
check_connectivity_data_free (CheckConnectivityData *ccd)
{
	if (ccd->cancellable) {
		if (ccd->cancelled_id)
			g_signal_handler_disconnect (ccd->cancellable, ccd->cancelled_id);
		g_object_unref (ccd->cancellable);
	}

	g_slice_free (CheckConnectivityData, ccd);
}

static void
check_connectivity_cb (DBusGProxy *proxy,
                       DBusGProxyCall *call,
                       gpointer user_data)
{
	GSimpleAsyncResult *simple = user_data;
	CheckConnectivityData *ccd = g_simple_async_result_get_op_res_gpointer (simple);
	GError *error = NULL;

	if (ccd->cancellable) {
		g_signal_handler_disconnect (ccd->cancellable, ccd->cancelled_id);
		ccd->cancelled_id = 0;
	}

	if (!dbus_g_proxy_end_call (proxy, call, &error,
	                            G_TYPE_UINT, &ccd->connectivity,
	                            G_TYPE_INVALID))
		g_simple_async_result_take_error (simple, error);

	g_simple_async_result_complete (simple);
	g_object_unref (simple);
}

static void
check_connectivity_cancelled_cb (GCancellable *cancellable,
                                 gpointer user_data)
{
	GSimpleAsyncResult *simple = user_data;
	CheckConnectivityData *ccd = g_simple_async_result_get_op_res_gpointer (simple);

	g_signal_handler_disconnect (cancellable, ccd->cancelled_id);
	ccd->cancelled_id = 0;

	dbus_g_proxy_cancel_call (NM_CLIENT_GET_PRIVATE (ccd->client)->client_proxy, ccd->call);
	g_simple_async_result_complete_in_idle (simple);
}

/**
 * nm_client_check_connectivity_async:
 * @client: an #NMClient
 * @cancellable: a #GCancellable
 * @callback: callback to call with the result
 * @user_data: data for @callback.
 *
 * Asynchronously updates the network connectivity state and invokes
 * @callback when complete. Contrast nm_client_get_connectivity(),
 * which (immediately) returns the most recent known state without
 * re-checking, and nm_client_check_connectivity(), which blocks.
 *
 * Since: 0.9.8.6
 */
void
nm_client_check_connectivity_async (NMClient *client,
                                    GCancellable *cancellable,
                                    GAsyncReadyCallback callback,
                                    gpointer user_data)
{
	NMClientPrivate *priv;
	GSimpleAsyncResult *simple;
	CheckConnectivityData *ccd;

	g_return_if_fail (NM_IS_CLIENT (client));
	priv = NM_CLIENT_GET_PRIVATE (client);

	ccd = g_slice_new0 (CheckConnectivityData);
	ccd->client = client;

	simple = g_simple_async_result_new (G_OBJECT (client), callback, user_data,
	                                    nm_client_check_connectivity_async);
	g_simple_async_result_set_op_res_gpointer (simple, ccd, (GDestroyNotify) check_connectivity_data_free);

	if (cancellable) {
		ccd->cancellable = g_object_ref (cancellable);
		ccd->cancelled_id = g_signal_connect (cancellable, "cancelled",
		                                      G_CALLBACK (check_connectivity_cancelled_cb),
		                                      simple);
		g_simple_async_result_set_check_cancellable (simple, cancellable);
	}

	ccd->call = dbus_g_proxy_begin_call (priv->client_proxy, "CheckConnectivity",
	                                     check_connectivity_cb, simple, NULL,
	                                     G_TYPE_INVALID);
}

/**
 * nm_client_check_connectivity_finish:
 * @client: an #NMClient
 * @result: the #GAsyncResult
 * @error: return location for a #GError
 *
 * Retrieves the result of an nm_client_check_connectivity_async()
 * call.
 *
 * Returns: the (new) current connectivity state
 * Since: 0.9.8.6
 */
NMConnectivityState
nm_client_check_connectivity_finish (NMClient *client,
                                     GAsyncResult *result,
                                     GError **error)
{
	GSimpleAsyncResult *simple;
	CheckConnectivityData *ccd;

	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (client), nm_client_check_connectivity_async), NM_CONNECTIVITY_UNKNOWN);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	ccd = g_simple_async_result_get_op_res_gpointer (simple);

	if (g_simple_async_result_propagate_error (simple, error))
		return NM_CONNECTIVITY_UNKNOWN;

	return ccd->connectivity;
}

/****************************************************************/

/**
 * nm_client_new:
 *
 * Creates a new #NMClient.
 *
 * Note that this will do blocking D-Bus calls to initialize the
 * client. You can use nm_client_new_async() if you want to avoid
 * that.
 *
 * NOTE: #NMClient provides information about devices and a mechanism to
 * control them.  To access and modify network configuration data, use the
 * #NMRemoteSettings object.
 *
 * Returns: a new #NMClient or NULL on an error
 **/
NMClient *
nm_client_new (void)
{
	NMClient *client;

	client = g_object_new (NM_TYPE_CLIENT, NM_OBJECT_DBUS_PATH, NM_DBUS_PATH, NULL);

	/* NMObject's constructor() can fail on a D-Bus connection error. So we can
	 * get NULL here instead of a valid NMClient object.
	 */
	if (client)
		_nm_object_ensure_inited (NM_OBJECT (client));

	return client;
}

static void
client_inited (GObject *source, GAsyncResult *result, gpointer user_data)
{
	GSimpleAsyncResult *simple = user_data;
	GError *error = NULL;

	if (!g_async_initable_init_finish (G_ASYNC_INITABLE (source), result, &error))
		g_simple_async_result_take_error (simple, error);
	else
		g_simple_async_result_set_op_res_gpointer (simple, source, g_object_unref);
	g_simple_async_result_complete (simple);
	g_object_unref (simple);
}

/**
 * nm_client_new_async:
 * @cancellable: a #GCancellable, or %NULL
 * @callback: callback to call when the client is created
 * @user_data: data for @callback
 *
 * Creates a new #NMClient and begins asynchronously initializing it.
 * @callback will be called when it is done; use
 * nm_client_new_finish() to get the result. Note that on an error,
 * the callback can be invoked with two first parameters as NULL.
 *
 * NOTE: #NMClient provides information about devices and a mechanism to
 * control them.  To access and modify network configuration data, use the
 * #NMRemoteSettings object.
 **/
void
nm_client_new_async (GCancellable *cancellable,
                     GAsyncReadyCallback callback,
                     gpointer user_data)
{
	NMClient *client;
	GSimpleAsyncResult *simple;

	client = g_object_new (NM_TYPE_CLIENT, NM_OBJECT_DBUS_PATH, NM_DBUS_PATH, NULL);
	/* When client is NULL, do no continue with initialization and run callback
	 * directly with result == NULL indicating NMClient creation failure.
	 */
	if (!client) {
		callback (NULL, NULL, user_data);
		return;
	}

	simple = g_simple_async_result_new (NULL, callback, user_data, nm_client_new_async);
	g_async_initable_init_async (G_ASYNC_INITABLE (client), G_PRIORITY_DEFAULT,
	                             cancellable, client_inited, simple);
}

/**
 * nm_client_new_finish:
 * @result: a #GAsyncResult
 * @error: location for a #GError, or %NULL
 *
 * Gets the result of an nm_client_new_async() call.
 *
 * Returns: a new #NMClient, or %NULL on error
 **/
NMClient *
nm_client_new_finish (GAsyncResult *result, GError **error)
{
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!result) {
		g_set_error_literal (error,
		                     NM_CLIENT_ERROR,
		                     NM_CLIENT_ERROR_UNKNOWN,
		                     "NMClient initialization failed (or you passed NULL 'result' by mistake)");
		return NULL;
	}

	g_return_val_if_fail (g_simple_async_result_is_valid (result, NULL, nm_client_new_async), NULL);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return NULL;
	else
		return g_object_ref (g_simple_async_result_get_op_res_gpointer (simple));
}

/*
 * constructor() shouldn't be overriden in most cases, rather constructed()
 * method is preferred and more useful.
 * But, this serves as a workaround for bindings (use) calling the constructor()
 * directly instead of nm_client_new() function, and neither providing
 * construction properties. So, we fill "dbus-path" here if it was not specified
 * (was set to default value (NULL)).
 *
 * It allows this python code:
 * from gi.repository import NMClient
 * nmclient = NMClient.Client()
 * print nmclient.get_active_connections()
 *
 * instead of proper
 * nmclient = NMClient.Client().new()
 *
 * Note:
 * A nice overview of GObject construction is here:
 * http://blogs.gnome.org/desrt/2012/02/26/a-gentle-introduction-to-gobject-construction
 * It is much better explanation than the official docs
 * http://developer.gnome.org/gobject/unstable/chapter-gobject.html#gobject-instantiation
 */
static GObject*
constructor (GType type,
             guint n_construct_params,
             GObjectConstructParam *construct_params)
{
	GObject *object;
	guint i;
	const char *dbus_path;

	for (i = 0; i < n_construct_params; i++) {
		if (strcmp (construct_params[i].pspec->name, NM_OBJECT_DBUS_PATH) == 0) {
			dbus_path = g_value_get_string (construct_params[i].value);
			if (dbus_path == NULL) {
				g_value_set_static_string (construct_params[i].value, NM_DBUS_PATH);
			} else {
				if (!g_variant_is_object_path (dbus_path)) {
					g_warning ("Passed D-Bus object path '%s' is invalid; using default '%s' instead",
					           dbus_path, NM_DBUS_PATH);
					g_value_set_static_string (construct_params[i].value, NM_DBUS_PATH);
				}
			}
			break;
		}
	}

	object = G_OBJECT_CLASS (nm_client_parent_class)->constructor (type,
	                                                               n_construct_params,
	                                                               construct_params);

	return object;
}

static void
constructed (GObject *object)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (object);
	GError *error = NULL;

	if (!nm_utils_init (&error)) {
		g_warning ("Couldn't initilize nm-utils/crypto system: %d %s",
		           error->code, error->message);
		g_clear_error (&error);
	}

	G_OBJECT_CLASS (nm_client_parent_class)->constructed (object);

	priv->client_proxy = _nm_object_new_proxy (NM_OBJECT (object), NULL, NM_DBUS_INTERFACE);

	register_properties (NM_CLIENT (object));

	/* Permissions */
	dbus_g_proxy_add_signal (priv->client_proxy, "CheckPermissions", G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->client_proxy,
	                             "CheckPermissions",
	                             G_CALLBACK (client_recheck_permissions),
	                             object,
	                             NULL);

	if (_nm_object_is_connection_private (NM_OBJECT (object)))
		priv->manager_running = TRUE;
	else {
		priv->bus_proxy = dbus_g_proxy_new_for_name (nm_object_get_connection (NM_OBJECT (object)),
		                                             DBUS_SERVICE_DBUS,
		                                             DBUS_PATH_DBUS,
		                                             DBUS_INTERFACE_DBUS);
		g_assert (priv->bus_proxy);

		dbus_g_proxy_add_signal (priv->bus_proxy, "NameOwnerChanged",
		                         G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
		                         G_TYPE_INVALID);
		dbus_g_proxy_connect_signal (priv->bus_proxy,
		                             "NameOwnerChanged",
		                             G_CALLBACK (proxy_name_owner_changed),
		                             object, NULL);
	}

	g_signal_connect (object, "notify::" NM_CLIENT_WIRELESS_ENABLED,
	                  G_CALLBACK (wireless_enabled_cb), NULL);

	g_signal_connect (object, "notify::" NM_CLIENT_ACTIVE_CONNECTIONS,
	                  G_CALLBACK (active_connections_changed_cb), NULL);

	g_signal_connect (object, "object-creation-failed",
	                  G_CALLBACK (object_creation_failed_cb), NULL);
}

static gboolean
init_sync (GInitable *initable, GCancellable *cancellable, GError **error)
{
	NMClient *client = NM_CLIENT (initable);
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (client);

	if (!nm_client_parent_initable_iface->init (initable, cancellable, error))
		return FALSE;

	if (!_nm_object_is_connection_private (NM_OBJECT (client))) {
		if (!dbus_g_proxy_call (priv->bus_proxy,
		                        "NameHasOwner", error,
		                        G_TYPE_STRING, NM_DBUS_SERVICE,
		                        G_TYPE_INVALID,
		                        G_TYPE_BOOLEAN, &priv->manager_running,
		                        G_TYPE_INVALID))
			return FALSE;
	}

	if (priv->manager_running && !get_permissions_sync (client, error))
		return FALSE;

	return TRUE;
}

typedef struct {
	NMClient *client;
	GSimpleAsyncResult *result;
	gboolean properties_pending;
	gboolean permissions_pending;
} NMClientInitData;

static void
init_async_complete (NMClientInitData *init_data)
{
	if (init_data->properties_pending || init_data->permissions_pending)
		return;

	g_simple_async_result_complete (init_data->result);
	g_object_unref (init_data->result);
	g_slice_free (NMClientInitData, init_data);
}

static void
init_async_got_permissions (DBusGProxy *proxy, DBusGProxyCall *call, gpointer user_data)
{
	NMClientInitData *init_data = user_data;
	GHashTable *permissions;
	GError *error = NULL;

	dbus_g_proxy_end_call (proxy, call, &error,
	                       DBUS_TYPE_G_MAP_OF_STRING, &permissions,
	                       G_TYPE_INVALID);
	update_permissions (init_data->client, error ? NULL : permissions);
	g_clear_error (&error);

	init_data->permissions_pending = FALSE;
	init_async_complete (init_data);
}

static void
init_async_got_properties (GObject *source, GAsyncResult *result, gpointer user_data)
{
	NMClientInitData *init_data = user_data;
	GError *error = NULL;

	if (!nm_client_parent_async_initable_iface->init_finish (G_ASYNC_INITABLE (source), result, &error))
		g_simple_async_result_take_error (init_data->result, error);

	init_data->properties_pending = FALSE;
	init_async_complete (init_data);
}

static void
finish_init (NMClientInitData *init_data)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (init_data->client);

	nm_client_parent_async_initable_iface->init_async (G_ASYNC_INITABLE (init_data->client),
	                                                   G_PRIORITY_DEFAULT, NULL, /* FIXME cancellable */
	                                                   init_async_got_properties, init_data);
	init_data->properties_pending = TRUE;

	dbus_g_proxy_begin_call (priv->client_proxy, "GetPermissions",
	                         init_async_got_permissions, init_data, NULL,
	                         G_TYPE_INVALID);
	init_data->permissions_pending = TRUE;
}

static void
init_async_got_manager_running (DBusGProxy *proxy, DBusGProxyCall *call,
                                gpointer user_data)
{
	NMClientInitData *init_data = user_data;
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (init_data->client);
	GError *error = NULL;

	if (!dbus_g_proxy_end_call (proxy, call, &error,
	                            G_TYPE_BOOLEAN, &priv->manager_running,
	                            G_TYPE_INVALID)) {
		g_simple_async_result_take_error (init_data->result, error);
		init_async_complete (init_data);
		return;
	}

	if (!priv->manager_running) {
		init_async_complete (init_data);
		return;
	}

	finish_init (init_data);
}

static void
init_async (GAsyncInitable *initable, int io_priority,
            GCancellable *cancellable, GAsyncReadyCallback callback,
            gpointer user_data)
{
	NMClientInitData *init_data;
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (initable);

	init_data = g_slice_new0 (NMClientInitData);
	init_data->client = NM_CLIENT (initable);
	init_data->result = g_simple_async_result_new (G_OBJECT (initable), callback,
	                                               user_data, init_async);
	g_simple_async_result_set_op_res_gboolean (init_data->result, TRUE);

	if (_nm_object_is_connection_private (NM_OBJECT (init_data->client)))
		finish_init (init_data);
	else {
		/* Check if NM is running */
		dbus_g_proxy_begin_call (priv->bus_proxy, "NameHasOwner",
		                         init_async_got_manager_running,
		                         init_data, NULL,
		                         G_TYPE_STRING, NM_DBUS_SERVICE,
		                         G_TYPE_INVALID);
	}
}

static gboolean
init_finish (GAsyncInitable *initable, GAsyncResult *result, GError **error)
{
	GSimpleAsyncResult *simple = G_SIMPLE_ASYNC_RESULT (result);

	if (g_simple_async_result_propagate_error (simple, error))
		return FALSE;
	else
		return TRUE;
}

static void
dispose (GObject *object)
{
	NMClient *client = NM_CLIENT (object);
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (object);

	if (priv->perm_call) {
		dbus_g_proxy_cancel_call (priv->client_proxy, priv->perm_call);
		priv->perm_call = NULL;
	}

	g_clear_object (&priv->client_proxy);
	g_clear_object (&priv->bus_proxy);

	free_devices (client, FALSE);
	free_active_connections (client, FALSE);
	g_clear_object (&priv->primary_connection);
	g_clear_object (&priv->activating_connection);

	g_slist_free_full (priv->pending_activations, (GDestroyNotify) activate_info_free);
	priv->pending_activations = NULL;

	g_hash_table_destroy (priv->permissions);
	priv->permissions = NULL;

	G_OBJECT_CLASS (nm_client_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (object);

	g_free (priv->version);

	G_OBJECT_CLASS (nm_client_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (object);
	gboolean b;

	switch (prop_id) {
	case PROP_NETWORKING_ENABLED:
		b = g_value_get_boolean (value);
		if (priv->networking_enabled != b) {
			nm_client_networking_set_enabled (NM_CLIENT (object), b);
			/* Let the property value flip when we get the change signal from NM */
		}
		break;
	case PROP_WIRELESS_ENABLED:
		b = g_value_get_boolean (value);
		if (priv->wireless_enabled != b) {
			nm_client_wireless_set_enabled (NM_CLIENT (object), b);
			/* Let the property value flip when we get the change signal from NM */
		}
		break;
	case PROP_WWAN_ENABLED:
		b = g_value_get_boolean (value);
		if (priv->wwan_enabled != b) {
			nm_client_wwan_set_enabled (NM_CLIENT (object), b);
			/* Let the property value flip when we get the change signal from NM */
		}
		break;
	case PROP_WIMAX_ENABLED:
		b = g_value_get_boolean (value);
		if (priv->wimax_enabled != b) {
			nm_client_wimax_set_enabled (NM_CLIENT (object), b);
			/* Let the property value flip when we get the change signal from NM */
		}
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMClient *self = NM_CLIENT (object);
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);

	_nm_object_ensure_inited (NM_OBJECT (object));

	switch (prop_id) {
	case PROP_VERSION:
		g_value_set_string (value, nm_client_get_version (self));
		break;
	case PROP_STATE:
		g_value_set_uint (value, nm_client_get_state (self));
		break;
	case PROP_STARTUP:
		g_value_set_boolean (value, nm_client_get_startup (self));
		break;
	case PROP_MANAGER_RUNNING:
		g_value_set_boolean (value, priv->manager_running);
		break;
	case PROP_NETWORKING_ENABLED:
		g_value_set_boolean (value, nm_client_networking_get_enabled (self));
		break;
	case PROP_WIRELESS_ENABLED:
		g_value_set_boolean (value, priv->wireless_enabled);
		break;
	case PROP_WIRELESS_HARDWARE_ENABLED:
		g_value_set_boolean (value, priv->wireless_hw_enabled);
		break;
	case PROP_WWAN_ENABLED:
		g_value_set_boolean (value, priv->wwan_enabled);
		break;
	case PROP_WWAN_HARDWARE_ENABLED:
		g_value_set_boolean (value, priv->wwan_hw_enabled);
		break;
	case PROP_WIMAX_ENABLED:
		g_value_set_boolean (value, priv->wimax_enabled);
		break;
	case PROP_WIMAX_HARDWARE_ENABLED:
		g_value_set_boolean (value, priv->wimax_hw_enabled);
		break;
	case PROP_ACTIVE_CONNECTIONS:
		g_value_set_boxed (value, nm_client_get_active_connections (self));
		break;
	case PROP_CONNECTIVITY:
		g_value_set_uint (value, priv->connectivity);
		break;
	case PROP_PRIMARY_CONNECTION:
		g_value_set_object (value, priv->primary_connection);
		break;
	case PROP_ACTIVATING_CONNECTION:
		g_value_set_object (value, priv->activating_connection);
		break;
	case PROP_DEVICES:
		g_value_set_boxed (value, nm_client_get_devices (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_client_class_init (NMClientClass *client_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (client_class);

	g_type_class_add_private (client_class, sizeof (NMClientPrivate));

	/* virtual methods */
	object_class->constructor = constructor;
	object_class->constructed = constructed;
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	/* properties */

	/**
	 * NMClient:version:
	 *
	 * The NetworkManager version.
	 **/
	g_object_class_install_property
		(object_class, PROP_VERSION,
		 g_param_spec_string (NM_CLIENT_VERSION, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:state:
	 *
	 * The current daemon state.
	 **/
	g_object_class_install_property
		(object_class, PROP_STATE,
		 g_param_spec_uint (NM_CLIENT_STATE, "", "",
		                    NM_STATE_UNKNOWN, NM_STATE_CONNECTED_GLOBAL, NM_STATE_UNKNOWN,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:startup:
	 *
	 * Whether the daemon is still starting up.
	 *
	 * Since: 0.9.10
	 **/
	g_object_class_install_property
		(object_class, PROP_STARTUP,
		 g_param_spec_boolean (NM_CLIENT_STARTUP, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:manager-running:
	 *
	 * Whether the daemon is running.
	 **/
	g_object_class_install_property
		(object_class, PROP_MANAGER_RUNNING,
		 g_param_spec_boolean (NM_CLIENT_MANAGER_RUNNING, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:networking-enabled:
	 *
	 * Whether networking is enabled.
	 **/
	g_object_class_install_property
		(object_class, PROP_NETWORKING_ENABLED,
		 g_param_spec_boolean (NM_CLIENT_NETWORKING_ENABLED, "", "",
		                       TRUE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:wireless-enabled:
	 *
	 * Whether wireless is enabled.
	 **/
	g_object_class_install_property
		(object_class, PROP_WIRELESS_ENABLED,
		 g_param_spec_boolean (NM_CLIENT_WIRELESS_ENABLED, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:wireless-hardware-enabled:
	 *
	 * Whether the wireless hardware is enabled.
	 **/
	g_object_class_install_property
		(object_class, PROP_WIRELESS_HARDWARE_ENABLED,
		 g_param_spec_boolean (NM_CLIENT_WIRELESS_HARDWARE_ENABLED, "", "",
		                       TRUE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:wwan-enabled:
	 *
	 * Whether WWAN functionality is enabled.
	 **/
	g_object_class_install_property
		(object_class, PROP_WWAN_ENABLED,
		 g_param_spec_boolean (NM_CLIENT_WWAN_ENABLED, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:wwan-hardware-enabled:
	 *
	 * Whether the WWAN hardware is enabled.
	 **/
	g_object_class_install_property
		(object_class, PROP_WWAN_HARDWARE_ENABLED,
		 g_param_spec_boolean (NM_CLIENT_WWAN_HARDWARE_ENABLED, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:wimax-enabled:
	 *
	 * Whether WiMAX functionality is enabled.
	 **/
	g_object_class_install_property
		(object_class, PROP_WIMAX_ENABLED,
		 g_param_spec_boolean (NM_CLIENT_WIMAX_ENABLED, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:wimax-hardware-enabled:
	 *
	 * Whether the WiMAX hardware is enabled.
	 **/
	g_object_class_install_property
		(object_class, PROP_WIMAX_HARDWARE_ENABLED,
		 g_param_spec_boolean (NM_CLIENT_WIMAX_HARDWARE_ENABLED, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:active-connections:
	 *
	 * The active connections.
	 * Type: GLib.PtrArray
	 **/
	g_object_class_install_property
		(object_class, PROP_ACTIVE_CONNECTIONS,
		 g_param_spec_boxed (NM_CLIENT_ACTIVE_CONNECTIONS, "", "",
		                     NM_TYPE_OBJECT_ARRAY,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:connectivity:
	 *
	 * The network connectivity state.
	 *
	 * Since: 0.9.8.6
	 */
	g_object_class_install_property
		(object_class, PROP_CONNECTIVITY,
		 g_param_spec_uint (NM_CLIENT_CONNECTIVITY, "", "",
		                    NM_CONNECTIVITY_UNKNOWN, NM_CONNECTIVITY_FULL, NM_CONNECTIVITY_UNKNOWN,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:primary-connection:
	 *
	 * The #NMActiveConnection of the device with the default route;
	 * see nm_client_get_primary_connection() for more details.
	 *
	 * Since: 0.9.8.6
	 **/
	g_object_class_install_property
		(object_class, PROP_PRIMARY_CONNECTION,
		 g_param_spec_object (NM_CLIENT_PRIMARY_CONNECTION, "", "",
		                      NM_TYPE_ACTIVE_CONNECTION,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:activating-connection:
	 *
	 * The #NMActiveConnection of the activating connection that is
	 * likely to become the new #NMClient:primary-connection.
	 *
	 * Since: 0.9.8.6
	 **/
	g_object_class_install_property
		(object_class, PROP_ACTIVATING_CONNECTION,
		 g_param_spec_object (NM_CLIENT_ACTIVATING_CONNECTION, "", "",
		                      NM_TYPE_ACTIVE_CONNECTION,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMClient:devices:
	 *
	 * List of known network devices.
	 *
	 * Since: 0.9.10
	 **/
	g_object_class_install_property
		(object_class, PROP_DEVICES,
		 g_param_spec_boxed (NM_CLIENT_DEVICES, "", "",
		                     NM_TYPE_OBJECT_ARRAY,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	/* signals */

	/**
	 * NMClient::device-added:
	 * @client: the client that received the signal
	 * @device: (type NMDevice): the new device
	 *
	 * Notifies that a #NMDevice is added.
	 **/
	signals[DEVICE_ADDED] =
		g_signal_new ("device-added",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMClientClass, device_added),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1,
		              G_TYPE_OBJECT);

	/**
	 * NMClient::device-removed:
	 * @client: the client that received the signal
	 * @device: (type NMDevice): the removed device
	 *
	 * Notifies that a #NMDevice is removed.
	 **/
	signals[DEVICE_REMOVED] =
		g_signal_new ("device-removed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMClientClass, device_removed),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1,
		              G_TYPE_OBJECT);

	/**
	 * NMClient::permission-changed:
	 * @client: the client that received the signal
	 * @permission: a permission from #NMClientPermission
	 * @result: the permission's result, one of #NMClientPermissionResult
	 *
	 * Notifies that a permission has changed
	 **/
	signals[PERMISSION_CHANGED] =
		g_signal_new ("permission-changed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              0, NULL, NULL, NULL,
		              G_TYPE_NONE, 2, G_TYPE_UINT, G_TYPE_UINT);
}

static void
nm_client_initable_iface_init (GInitableIface *iface)
{
	nm_client_parent_initable_iface = g_type_interface_peek_parent (iface);

	iface->init = init_sync;
}

static void
nm_client_async_initable_iface_init (GAsyncInitableIface *iface)
{
	nm_client_parent_async_initable_iface = g_type_interface_peek_parent (iface);

	iface->init_async = init_async;
	iface->init_finish = init_finish;
}
