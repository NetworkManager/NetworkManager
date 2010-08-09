/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * libnm_glib -- Access network status & information from glib applications
 *
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
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2010 Red Hat, Inc.
 */

#include <dbus/dbus-glib.h>
#include <string.h>
#include <nm-utils.h>

#include "nm-client.h"
#include "nm-device-ethernet.h"
#include "nm-device-wifi.h"
#include "nm-gsm-device.h"
#include "nm-cdma-device.h"
#include "nm-device-private.h"
#include "nm-marshal.h"
#include "nm-types-private.h"
#include "nm-object-private.h"
#include "nm-active-connection.h"
#include "nm-vpn-connection.h"
#include "nm-object-cache.h"
#include "nm-dbus-glib-types.h"

#include "nm-client-bindings.h"

void _nm_device_wifi_set_wireless_enabled (NMDeviceWifi *device, gboolean enabled);


G_DEFINE_TYPE (NMClient, nm_client, NM_TYPE_OBJECT)

#define NM_CLIENT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_CLIENT, NMClientPrivate))

typedef struct {
	gboolean disposed;

	DBusGProxy *client_proxy;
	DBusGProxy *bus_proxy;
	gboolean manager_running;
	NMState state;
	GPtrArray *devices;
	GPtrArray *active_connections;

	DBusGProxyCall *perm_call;
	GHashTable *permissions;

	gboolean have_networking_enabled;
	gboolean networking_enabled;
	gboolean wireless_enabled;
	gboolean wireless_hw_enabled;

	gboolean wwan_enabled;
	gboolean wwan_hw_enabled;
} NMClientPrivate;

enum {
	PROP_0,
	PROP_STATE,
	PROP_MANAGER_RUNNING,
	PROP_NETWORKING_ENABLED,
	PROP_WIRELESS_ENABLED,
	PROP_WIRELESS_HARDWARE_ENABLED,
	PROP_WWAN_ENABLED,
	PROP_WWAN_HARDWARE_ENABLED,
	PROP_ACTIVE_CONNECTIONS,

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

static void client_device_added_proxy (DBusGProxy *proxy, char *path, gpointer user_data);
static void client_device_removed_proxy (DBusGProxy *proxy, char *path, gpointer user_data);

static void
handle_net_enabled_changed (GObject *object,
                            GParamSpec *pspec,
                            GValue *value,
                            gpointer user_data)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (object);

	/* Update the cache flag when it changes */
	priv->have_networking_enabled = TRUE;
}

static void
nm_client_init (NMClient *client)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (client);

	priv->state = NM_STATE_UNKNOWN;

	priv->permissions = g_hash_table_new (g_direct_hash, g_direct_equal);

	g_signal_connect (client,
	                  "notify::" NM_CLIENT_NETWORKING_ENABLED,
	                  G_CALLBACK (handle_net_enabled_changed),
	                  client);
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
update_wireless_status (NMClient *client, gboolean notify)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (client);
	gboolean val;
	gboolean poke = FALSE;

	val = _nm_object_get_boolean_property (NM_OBJECT (client),
										  NM_DBUS_INTERFACE,
										  "WirelessHardwareEnabled");
	if (val != priv->wireless_hw_enabled) {
		priv->wireless_hw_enabled = val;
		poke = TRUE;
		if (notify)
			_nm_object_queue_notify (NM_OBJECT (client), NM_CLIENT_WIRELESS_HARDWARE_ENABLED);
	}

	if (priv->wireless_hw_enabled == FALSE)
		val = FALSE;
	else
		val = _nm_object_get_boolean_property (NM_OBJECT (client),
				                              NM_DBUS_INTERFACE,
				                              "WirelessEnabled");
	if (val != priv->wireless_enabled) {
		priv->wireless_enabled = val;
		poke = TRUE;
		if (notify)
			_nm_object_queue_notify (NM_OBJECT (client), NM_CLIENT_WIRELESS_ENABLED);
	}

	if (poke)
		poke_wireless_devices_with_rf_status (client);
}

static void
wireless_enabled_cb (GObject *object, GParamSpec *pspec, gpointer user_data)
{
	poke_wireless_devices_with_rf_status (NM_CLIENT (object));
}

static void
update_wwan_status (NMClient *client, gboolean notify)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (client);
	gboolean val;

	val = _nm_object_get_boolean_property (NM_OBJECT (client),
	                                       NM_DBUS_INTERFACE,
	                                       "WwanHardwareEnabled");
	if (val != priv->wwan_hw_enabled) {
		priv->wwan_hw_enabled = val;
		if (notify)
			_nm_object_queue_notify (NM_OBJECT (client), NM_CLIENT_WWAN_HARDWARE_ENABLED);
	}

	if (priv->wwan_hw_enabled == FALSE)
		val = FALSE;
	else {
		val = _nm_object_get_boolean_property (NM_OBJECT (client),
		                                       NM_DBUS_INTERFACE,
		                                       "WwanEnabled");
	}

	if (val != priv->wwan_enabled) {
		priv->wwan_enabled = val;
		if (notify)
			_nm_object_queue_notify (NM_OBJECT (client), NM_CLIENT_WWAN_ENABLED);
	}
}

static GObject *
new_active_connection (DBusGConnection *connection, const char *path)
{
	DBusGProxy *proxy;
	GError *error = NULL;
	GValue value = {0,};
	GObject *object = NULL;

	proxy = dbus_g_proxy_new_for_name (connection,
									   NM_DBUS_SERVICE,
									   path,
									   "org.freedesktop.DBus.Properties");
	if (!proxy) {
		g_warning ("%s: couldn't create D-Bus object proxy.", __func__);
		return NULL;
	}

	/* Have to create an NMVPNConnection if it's a VPN connection, otherwise
	 * a plain NMActiveConnection.
	 */
	if (dbus_g_proxy_call (proxy,
	                       "Get", &error,
	                       G_TYPE_STRING, NM_DBUS_INTERFACE_ACTIVE_CONNECTION,
	                       G_TYPE_STRING, "Vpn",
	                       G_TYPE_INVALID,
	                       G_TYPE_VALUE, &value, G_TYPE_INVALID)) {
		if (g_value_get_boolean (&value))
			object = nm_vpn_connection_new (connection, path);
		else
			object = nm_active_connection_new (connection, path);
	} else {
		g_warning ("Error in getting active connection 'Vpn' property: (%d) %s",
		           error->code, error->message);
		g_error_free (error);
	}

	g_object_unref (proxy);
	return object;
}

static gboolean
demarshal_active_connections (NMObject *object,
                              GParamSpec *pspec,
                              GValue *value,
                              gpointer field)
{
	DBusGConnection *connection;

	connection = nm_object_get_connection (object);
	if (!_nm_object_array_demarshal (value, (GPtrArray **) field, connection, new_active_connection))
		return FALSE;

	_nm_object_queue_notify (object, NM_CLIENT_ACTIVE_CONNECTIONS);
	return TRUE;
}

static void
register_for_property_changed (NMClient *client)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (client);
	const NMPropertiesChangedInfo property_changed_info[] = {
		{ NM_CLIENT_STATE,                     _nm_object_demarshal_generic,  &priv->state },
		{ NM_CLIENT_NETWORKING_ENABLED,        _nm_object_demarshal_generic,  &priv->networking_enabled },
		{ NM_CLIENT_WIRELESS_ENABLED,          _nm_object_demarshal_generic,  &priv->wireless_enabled },
		{ NM_CLIENT_WIRELESS_HARDWARE_ENABLED, _nm_object_demarshal_generic,  &priv->wireless_hw_enabled },
		{ NM_CLIENT_WWAN_ENABLED,              _nm_object_demarshal_generic,  &priv->wwan_enabled },
		{ NM_CLIENT_WWAN_HARDWARE_ENABLED,     _nm_object_demarshal_generic,  &priv->wwan_hw_enabled },
		{ NM_CLIENT_ACTIVE_CONNECTIONS,        demarshal_active_connections, &priv->active_connections },
		{ NULL },
	};

	_nm_object_handle_properties_changed (NM_OBJECT (client),
	                                     priv->client_proxy,
	                                     property_changed_info);
}

#define NM_AUTH_PERMISSION_ENABLE_DISABLE_NETWORK "org.freedesktop.NetworkManager.enable-disable-network"
#define NM_AUTH_PERMISSION_ENABLE_DISABLE_WIFI    "org.freedesktop.NetworkManager.enable-disable-wifi"
#define NM_AUTH_PERMISSION_ENABLE_DISABLE_WWAN    "org.freedesktop.NetworkManager.enable-disable-wwan"
#define NM_AUTH_PERMISSION_USE_USER_CONNECTIONS   "org.freedesktop.NetworkManager.use-user-connections"

static NMClientPermission
nm_permission_to_client (const char *nm)
{
	if (!strcmp (nm, NM_AUTH_PERMISSION_ENABLE_DISABLE_NETWORK))
		return NM_CLIENT_PERMISSION_ENABLE_DISABLE_NETWORK;
	else if (!strcmp (nm, NM_AUTH_PERMISSION_ENABLE_DISABLE_WIFI))
		return NM_CLIENT_PERMISSION_ENABLE_DISABLE_WIFI;
	else if (!strcmp (nm, NM_AUTH_PERMISSION_ENABLE_DISABLE_WWAN))
		return NM_CLIENT_PERMISSION_ENABLE_DISABLE_WWAN;
	else if (!strcmp (nm, NM_AUTH_PERMISSION_USE_USER_CONNECTIONS))
		return NM_CLIENT_PERMISSION_USE_USER_CONNECTIONS;
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

static void
get_permissions_sync (NMClient *self)
{
	gboolean success;
	GHashTable *permissions = NULL;

	success = dbus_g_proxy_call_with_timeout (NM_CLIENT_GET_PRIVATE (self)->client_proxy,
	                                          "GetPermissions", 3000, NULL,
	                                          G_TYPE_INVALID,
	                                          DBUS_TYPE_G_MAP_OF_STRING, &permissions, G_TYPE_INVALID);
	update_permissions (self, success ? permissions : NULL);
	if (permissions)
		g_hash_table_destroy (permissions);
}

static void
get_permissions_reply (DBusGProxy *proxy,
                       GHashTable *permissions,
                       GError *error,
                       gpointer user_data)
{
	NMClient *self = NM_CLIENT (user_data);

	NM_CLIENT_GET_PRIVATE (self)->perm_call = NULL;
	update_permissions (NM_CLIENT (user_data), error ? NULL : permissions);
}

static void
client_recheck_permissions (DBusGProxy *proxy, gpointer user_data)
{
	NMClient *self = NM_CLIENT (user_data);
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);

	if (!priv->perm_call) {
		priv->perm_call = org_freedesktop_NetworkManager_get_permissions_async (NM_CLIENT_GET_PRIVATE (self)->client_proxy,
	                                                                            get_permissions_reply,
	                                                                            self);
	}
}

static GObject*
constructor (GType type,
		   guint n_construct_params,
		   GObjectConstructParam *construct_params)
{
	NMObject *object;
	DBusGConnection *connection;
	NMClientPrivate *priv;
	GError *err = NULL;

	object = (NMObject *) G_OBJECT_CLASS (nm_client_parent_class)->constructor (type,
																 n_construct_params,
																 construct_params);
	if (!object)
		return NULL;

	priv = NM_CLIENT_GET_PRIVATE (object);
	connection = nm_object_get_connection (object);

	priv->client_proxy = dbus_g_proxy_new_for_name (connection,
										   NM_DBUS_SERVICE,
										   nm_object_get_path (object),
										   NM_DBUS_INTERFACE);

	register_for_property_changed (NM_CLIENT (object));

	dbus_g_proxy_add_signal (priv->client_proxy, "DeviceAdded", DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->client_proxy,
						    "DeviceAdded",
						    G_CALLBACK (client_device_added_proxy),
						    object,
						    NULL);

	dbus_g_proxy_add_signal (priv->client_proxy, "DeviceRemoved", DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->client_proxy,
						    "DeviceRemoved",
						    G_CALLBACK (client_device_removed_proxy),
						    object,
						    NULL);

	/* Permissions */
	dbus_g_proxy_add_signal (priv->client_proxy, "CheckPermissions", G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->client_proxy,
	                             "CheckPermissions",
	                             G_CALLBACK (client_recheck_permissions),
	                             object,
	                             NULL);
	get_permissions_sync (NM_CLIENT (object));

	priv->bus_proxy = dbus_g_proxy_new_for_name (connection,
										"org.freedesktop.DBus",
										"/org/freedesktop/DBus",
										"org.freedesktop.DBus");

	dbus_g_proxy_add_signal (priv->bus_proxy, "NameOwnerChanged",
						G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
						G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->bus_proxy,
						    "NameOwnerChanged",
						    G_CALLBACK (proxy_name_owner_changed),
						    object, NULL);

	if (!dbus_g_proxy_call (priv->bus_proxy,
					    "NameHasOwner", &err,
					    G_TYPE_STRING, NM_DBUS_SERVICE,
					    G_TYPE_INVALID,
					    G_TYPE_BOOLEAN, &priv->manager_running,
					    G_TYPE_INVALID)) {
		g_warning ("Error on NameHasOwner DBUS call: %s", err->message);
		g_error_free (err);
	}

	if (priv->manager_running) {
		update_wireless_status (NM_CLIENT (object), FALSE);
		update_wwan_status (NM_CLIENT (object), FALSE);
		nm_client_get_state (NM_CLIENT (object));
	}

	g_signal_connect (G_OBJECT (object), "notify::" NM_CLIENT_WIRELESS_ENABLED,
	                  G_CALLBACK (wireless_enabled_cb), NULL);

	return G_OBJECT (object);
}

static void
free_object_array (GPtrArray **array)
{
	g_return_if_fail (array != NULL);

	if (*array) {
		g_ptr_array_foreach (*array, (GFunc) g_object_unref, NULL);
		g_ptr_array_free (*array, TRUE);
		*array = NULL;
	}
}

static void
dispose (GObject *object)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (object);

	if (priv->disposed) {
		G_OBJECT_CLASS (nm_client_parent_class)->dispose (object);
		return;
	}

	if (priv->perm_call)
		dbus_g_proxy_cancel_call (priv->client_proxy, priv->perm_call);

	g_object_unref (priv->client_proxy);
	g_object_unref (priv->bus_proxy);

	free_object_array (&priv->devices);
	free_object_array (&priv->active_connections);

	g_hash_table_destroy (priv->permissions);

	G_OBJECT_CLASS (nm_client_parent_class)->dispose (object);
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (object);
	gboolean b;

	switch (prop_id) {
	case PROP_WIRELESS_ENABLED:
		b = g_value_get_boolean (value);
		if (priv->wireless_enabled != b) {
			priv->wireless_enabled = b;
			_nm_object_queue_notify (NM_OBJECT (object), NM_CLIENT_WIRELESS_ENABLED);
		}
		break;
	case PROP_WIRELESS_HARDWARE_ENABLED:
		b = g_value_get_boolean (value);
		if (priv->wireless_hw_enabled != b) {
			priv->wireless_hw_enabled = b;
			_nm_object_queue_notify (NM_OBJECT (object), NM_CLIENT_WIRELESS_HARDWARE_ENABLED);
		}
		break;
	case PROP_WWAN_ENABLED:
		b = g_value_get_boolean (value);
		if (priv->wwan_enabled != b) {
			priv->wwan_enabled = b;
			_nm_object_queue_notify (NM_OBJECT (object), NM_CLIENT_WWAN_ENABLED);
		}
		break;
	case PROP_WWAN_HARDWARE_ENABLED:
		b = g_value_get_boolean (value);
		if (priv->wwan_hw_enabled != b) {
			priv->wwan_hw_enabled = b;
			_nm_object_queue_notify (NM_OBJECT (object), NM_CLIENT_WWAN_HARDWARE_ENABLED);
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

	switch (prop_id) {
	case PROP_STATE:
		g_value_set_uint (value, nm_client_get_state (self));
		break;
	case PROP_MANAGER_RUNNING:
		g_value_set_boolean (value, priv->manager_running);
		break;
	case PROP_NETWORKING_ENABLED:
		g_value_set_boolean (value, priv->networking_enabled);
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
	case PROP_ACTIVE_CONNECTIONS:
		g_value_set_boxed (value, nm_client_get_active_connections (self));
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
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->dispose = dispose;

	/* properties */

	/**
	 * NMClient:state:
	 *
	 * The current daemon state.
	 **/
	g_object_class_install_property
		(object_class, PROP_STATE,
		 g_param_spec_uint (NM_CLIENT_STATE,
						    "State",
						    "NetworkManager state",
						    NM_STATE_UNKNOWN, NM_STATE_DISCONNECTED, NM_STATE_UNKNOWN,
						    G_PARAM_READABLE));

	/**
	 * NMClient::manager-running:
	 *
	 * Whether the daemon is running.
	 **/
	g_object_class_install_property
		(object_class, PROP_MANAGER_RUNNING,
		 g_param_spec_boolean (NM_CLIENT_MANAGER_RUNNING,
						       "ManagerRunning",
						       "Whether NetworkManager is running",
						       FALSE,
						       G_PARAM_READABLE));

	/**
	 * NMClient::networking-enabled:
	 *
	 * Whether networking is enabled.
	 **/
	g_object_class_install_property
		(object_class, PROP_NETWORKING_ENABLED,
		 g_param_spec_boolean (NM_CLIENT_NETWORKING_ENABLED,
						   "NetworkingEnabled",
						   "Is networking enabled",
						   TRUE,
						   G_PARAM_READABLE));

	/**
	 * NMClient::wireless-enabled:
	 *
	 * Whether wireless is enabled.
	 **/
	g_object_class_install_property
		(object_class, PROP_WIRELESS_ENABLED,
		 g_param_spec_boolean (NM_CLIENT_WIRELESS_ENABLED,
						   "WirelessEnabled",
						   "Is wireless enabled",
						   TRUE,
						   G_PARAM_READWRITE));

	/**
	 * NMClient::wireless-hardware-enabled:
	 *
	 * Whether the wireless hardware is enabled.
	 **/
	g_object_class_install_property
		(object_class, PROP_WIRELESS_HARDWARE_ENABLED,
		 g_param_spec_boolean (NM_CLIENT_WIRELESS_HARDWARE_ENABLED,
						   "WirelessHardwareEnabled",
						   "Is wireless hardware enabled",
						   TRUE,
						   G_PARAM_READABLE));

	/**
	 * NMClient::wwan-enabled:
	 *
	 * Whether WWAN functionality is enabled.
	 **/
	g_object_class_install_property
		(object_class, PROP_WWAN_ENABLED,
		 g_param_spec_boolean (NM_CLIENT_WWAN_ENABLED,
		                       "WwanEnabled",
		                       "Is WWAN enabled",
		                       TRUE,
		                       G_PARAM_READWRITE | G_PARAM_CONSTRUCT));

	/**
	 * NMClient::wwan-hardware-enabled:
	 *
	 * Whether the WWAN hardware is enabled.
	 **/
	g_object_class_install_property
		(object_class, PROP_WWAN_HARDWARE_ENABLED,
		 g_param_spec_boolean (NM_CLIENT_WWAN_HARDWARE_ENABLED,
		                       "WwanHardwareEnabled",
		                       "Is WWAN hardware enabled",
		                       TRUE,
		                       G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	/**
	 * NMClient::active-connections:
	 *
	 * The active connections.
	 **/
	g_object_class_install_property
		(object_class, PROP_ACTIVE_CONNECTIONS,
		 g_param_spec_boxed (NM_CLIENT_ACTIVE_CONNECTIONS,
						   "Active connections",
						   "Active connections",
						   NM_TYPE_OBJECT_ARRAY,
						   G_PARAM_READABLE));

	/* signals */

	/**
	 * NMClient::device-added:
	 * @client: the client that received the signal
	 * @device: the new device
	 *
	 * Notifies that a #NMDevice is added.
	 **/
	signals[DEVICE_ADDED] =
		g_signal_new ("device-added",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMClientClass, device_added),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__OBJECT,
					  G_TYPE_NONE, 1,
					  G_TYPE_OBJECT);

	/**
	 * NMClient::device-removed:
	 * @widget: the client that received the signal
	 * @device: the removed device
	 *
	 * Notifies that a #NMDevice is removed.
	 **/
	signals[DEVICE_REMOVED] =
		g_signal_new ("device-removed",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMClientClass, device_removed),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__OBJECT,
					  G_TYPE_NONE, 1,
					  G_TYPE_OBJECT);

	/**
	 * NMClient::permission-changed:
	 * @widget: the client that received the signal
	 * @permission: a permission from #NMClientPermission
	 * @result: the permission's result, one of #NMClientPermissionResult
	 *
	 * Notifies that a permission has changed
	 **/
	signals[PERMISSION_CHANGED] =
		g_signal_new ("permission-changed",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  0, NULL, NULL,
					  _nm_marshal_VOID__UINT_UINT,
					  G_TYPE_NONE, 2, G_TYPE_UINT, G_TYPE_UINT);
}

/**
 * nm_client_new:
 *
 * Creates a new #NMClient.
 *
 * Returns: a new #NMClient
 **/
NMClient *
nm_client_new (void)
{
	DBusGConnection *connection;
	GError *err = NULL;

	connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, &err);
	if (!connection) {
		g_warning ("Couldn't connect to system bus: %s", err->message);
		g_error_free (err);
		return NULL;
	}

	return (NMClient *) g_object_new (NM_TYPE_CLIENT,
									  NM_OBJECT_DBUS_CONNECTION, connection,
									  NM_OBJECT_DBUS_PATH, NM_DBUS_PATH,
									  NULL);
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
		_nm_object_queue_notify (NM_OBJECT (client), NM_CLIENT_MANAGER_RUNNING);
		poke_wireless_devices_with_rf_status (client);
		free_object_array (&priv->devices);
		free_object_array (&priv->active_connections);
		priv->wireless_enabled = FALSE;
		priv->wireless_hw_enabled = FALSE;
		priv->wwan_enabled = FALSE;
		priv->wwan_hw_enabled = FALSE;
	} else {
		_nm_object_queue_notify (NM_OBJECT (client), NM_CLIENT_MANAGER_RUNNING);
		update_wireless_status (client, TRUE);
		update_wwan_status (client, TRUE);
	}
}

static void
client_device_added_proxy (DBusGProxy *proxy, char *path, gpointer user_data)
{
	NMClient *client = NM_CLIENT (user_data);
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (client);
	GObject *device;

	device = G_OBJECT (nm_client_get_device_by_path (client, path));
	if (!device) {
		DBusGConnection *connection = nm_object_get_connection (NM_OBJECT (client));

		device = G_OBJECT (_nm_object_cache_get (path));
		if (device) {
			g_ptr_array_add (priv->devices, g_object_ref (device));
		} else {
			device = G_OBJECT (nm_device_new (connection, path));
			if (device)
				g_ptr_array_add (priv->devices, device);
		}
	}

	if (device)
		g_signal_emit (client, signals[DEVICE_ADDED], 0, device);
}

static void
client_device_removed_proxy (DBusGProxy *proxy, char *path, gpointer user_data)
{
	NMClient *client = NM_CLIENT (user_data);
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (client);
	NMDevice *device;

	device = nm_client_get_device_by_path (client, path);
	if (device) {
		g_signal_emit (client, signals[DEVICE_REMOVED], 0, device);
		g_ptr_array_remove (priv->devices, device);
		g_object_unref (device);
	}
}

/**
 * nm_client_get_devices:
 * @client: a #NMClient
 *
 * Gets all the detected devices.
 *
 * Returns: a #GPtrArray containing all the #NMDevice<!-- -->s.
 * The returned array is owned by the client and should not be modified.
 **/
const GPtrArray *
nm_client_get_devices (NMClient *client)
{
	NMClientPrivate *priv;
	DBusGConnection *connection;
	GValue value = { 0, };
	GError *error = NULL;
	GPtrArray *temp;

	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);

	priv = NM_CLIENT_GET_PRIVATE (client);
	if (priv->devices)
		return handle_ptr_array_return (priv->devices);

	if (!org_freedesktop_NetworkManager_get_devices (priv->client_proxy, &temp, &error)) {
		g_warning ("%s: error getting devices: %s\n", __func__, error->message);
		g_error_free (error);
		return NULL;
	}

	g_value_init (&value, DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH);
	g_value_take_boxed (&value, temp);
	connection = nm_object_get_connection (NM_OBJECT (client));
	_nm_object_array_demarshal (&value, &priv->devices, connection, nm_device_new);
	g_value_unset (&value);

	return handle_ptr_array_return (priv->devices);
}

/**
 * nm_client_get_device_by_path:
 * @client: a #NMClient
 * @object_path: the object path to search for
 *
 * Gets a #NMDevice from a #NMClient.
 *
 * Returns: the #NMDevice for the given @object_path or %NULL if none is found.
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

typedef struct {
	NMClientActivateDeviceFn fn;
	gpointer user_data;
} ActivateDeviceInfo;

static void
activate_cb (DBusGProxy *proxy,
             char *path,
             GError *error,
             gpointer user_data)
{
	ActivateDeviceInfo *info = (ActivateDeviceInfo *) user_data;

	if (info->fn)
		info->fn (info->user_data, path, error);
	else if (error)
		nm_warning ("Device activation failed: (%d) %s", error->code, error->message);

	g_slice_free (ActivateDeviceInfo, info);
}

/**
 * nm_client_activate_connection:
 * @client: a #NMClient
 * @service_name: the connection's service name
 * @connection_path: the connection's DBus path
 * @device: the #NMDevice
 * @specific_object: the device specific object (currently used only for
 * activating wireless devices and should be the #NMAccessPoint<!-- -->'s path.
 * @callback: the function to call when the call is done
 * @user_data: user data to pass to the callback function
 *
 * Activates a connection with the given #NMDevice.
 **/
void
nm_client_activate_connection (NMClient *client,
					  const char *service_name,
					  const char *connection_path,
					  NMDevice *device,
					  const char *specific_object,
					  NMClientActivateDeviceFn callback,
					  gpointer user_data)
{
	ActivateDeviceInfo *info;
	char *internal_so = (char *) specific_object;

	g_return_if_fail (NM_IS_CLIENT (client));
	g_return_if_fail (NM_IS_DEVICE (device));
	g_return_if_fail (service_name != NULL);
	g_return_if_fail (connection_path != NULL);

	/* NULL specific object must be translated into "/" because D-Bus does
	 * not have any idea of NULL object paths.
	 */
	if (internal_so == NULL)
		internal_so = "/";

	info = g_slice_new (ActivateDeviceInfo);
	info->fn = callback;
	info->user_data = user_data;

	org_freedesktop_NetworkManager_activate_connection_async (NM_CLIENT_GET_PRIVATE (client)->client_proxy,
											    service_name,
											    connection_path,
											    nm_object_get_path (NM_OBJECT (device)),
											    internal_so,
											    activate_cb,
											    info);
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

	// FIXME: return errors
	priv = NM_CLIENT_GET_PRIVATE (client);
	path = nm_object_get_path (NM_OBJECT (active));
	if (!org_freedesktop_NetworkManager_deactivate_connection (priv->client_proxy, path, &error)) {
		g_warning ("Could not deactivate connection '%s': %s", path, error->message);
		g_error_free (error);
	}
}

/**
 * nm_client_get_active_connections:
 * @client: a #NMClient
 *
 * Gets the active connections.
 *
 * Returns: a #GPtrArray containing all the active #NMActiveConnection<!-- -->s.
 * The returned array is owned by the client and should not be modified.
 **/
const GPtrArray * 
nm_client_get_active_connections (NMClient *client)
{
	NMClientPrivate *priv;
	GValue value = { 0, };

	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);

	priv = NM_CLIENT_GET_PRIVATE (client);
	if (priv->active_connections)
		return handle_ptr_array_return (priv->active_connections);

	if (!priv->manager_running)
		return NULL;

	if (!_nm_object_get_property (NM_OBJECT (client),
	                             "org.freedesktop.NetworkManager",
	                             "ActiveConnections",
	                             &value)) {
		return NULL;
	}

	demarshal_active_connections (NM_OBJECT (client), NULL, &value, &priv->active_connections);	
	g_value_unset (&value);

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
	GValue value = {0,};

	g_return_if_fail (NM_IS_CLIENT (client));

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
	GValue value = {0,};

	g_return_if_fail (NM_IS_CLIENT (client));

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

	return NM_CLIENT_GET_PRIVATE (client)->wwan_hw_enabled;
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
	NMClientPrivate *priv;

	g_return_val_if_fail (NM_IS_CLIENT (client), NM_STATE_UNKNOWN);

	priv = NM_CLIENT_GET_PRIVATE (client);

	if (!priv->manager_running)
		return NM_STATE_UNKNOWN;

	if (priv->state == NM_STATE_UNKNOWN)
		priv->state = _nm_object_get_uint_property (NM_OBJECT (client), NM_DBUS_INTERFACE, "State");

	return priv->state;
}

/**
 * nm_client_networking_get_enabled:
 * @client: a #NMClient
 *
 * Whether networking is enabled or disabled.
 *
 * Returns: %TRUE if networking is disabled, %FALSE if networking is enabled
 **/
gboolean
nm_client_networking_get_enabled (NMClient *client)
{
	NMClientPrivate *priv;

	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	priv = NM_CLIENT_GET_PRIVATE (client);
	if (!priv->have_networking_enabled) {
		priv = NM_CLIENT_GET_PRIVATE (client);
		if (!priv->networking_enabled) {
			priv->networking_enabled = _nm_object_get_boolean_property (NM_OBJECT (client),
			                                                            NM_DBUS_INTERFACE,
			                                                            "NetworkingEnabled");
			priv->have_networking_enabled = TRUE;
		}
	}

	return priv->networking_enabled;
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

	if (!org_freedesktop_NetworkManager_enable (NM_CLIENT_GET_PRIVATE (client)->client_proxy, enable, &err)) {
		g_warning ("Error enabling/disabling networking: %s", err->message);
		g_error_free (err);
	}
}

/**
 * nm_client_sleep:
 * @client: a #NMClient
 * @sleep: %TRUE to put the daemon to sleep
 *
 * Deprecated; use nm_client_networking_set_enabled() instead.
 **/
void
nm_client_sleep (NMClient *client, gboolean sleep)
{
	nm_client_networking_set_enabled (client, !sleep);
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

