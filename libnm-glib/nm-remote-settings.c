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
 * Copyright (C) 2008 Novell, Inc.
 * Copyright (C) 2009 - 2010 Red Hat, Inc.
 */

#include <string.h>
#include <NetworkManager.h>
#include <nm-connection.h>

#include "nm-marshal.h"
#include "nm-dbus-glib-types.h"
#include "nm-remote-settings.h"
#include "nm-settings-bindings.h"
#include "nm-settings-interface.h"
#include "nm-remote-connection-private.h"

static void settings_interface_init (NMSettingsInterface *class);

G_DEFINE_TYPE_EXTENDED (NMRemoteSettings, nm_remote_settings, G_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_SETTINGS_INTERFACE, settings_interface_init))

#define NM_REMOTE_SETTINGS_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_REMOTE_SETTINGS, NMRemoteSettingsPrivate))

typedef struct {
	DBusGConnection *bus;

	DBusGProxy *proxy;
	GHashTable *connections;
	GHashTable *pending;  /* Connections we don't have settings for yet */
	gboolean service_running;
	
	DBusGProxy *props_proxy;
	NMSettingsPermissions permissions;
	gboolean have_permissions;
	char *hostname;
	gboolean can_modify;

	DBusGProxy *dbus_proxy;

	guint fetch_id;

	gboolean disposed;
} NMRemoteSettingsPrivate;

enum {
	PROP_0,
	PROP_BUS,
	PROP_SERVICE_RUNNING,

	LAST_PROP
};

static NMSettingsConnectionInterface *
get_connection_by_path (NMSettingsInterface *settings, const char *path)
{
	return g_hash_table_lookup (NM_REMOTE_SETTINGS_GET_PRIVATE (settings)->connections, path);
}

static void
connection_removed_cb (NMRemoteConnection *remote, gpointer user_data)
{
	NMRemoteSettings *self = NM_REMOTE_SETTINGS (user_data);
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);
	const char *path;

	path = nm_connection_get_path (NM_CONNECTION (remote));
	g_hash_table_remove (priv->connections, path);
	g_hash_table_remove (priv->pending, path);
}

static void
connection_init_result_cb (NMRemoteConnection *remote,
                           GParamSpec *pspec,
                           gpointer user_data)
{
	NMRemoteSettings *self = NM_REMOTE_SETTINGS (user_data);
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);
	guint32 init_result = NM_REMOTE_CONNECTION_INIT_RESULT_UNKNOWN;
	const char *path;

	/* Disconnect from the init-result signal just to be safe */
	g_signal_handlers_disconnect_matched (remote,
	                                      G_SIGNAL_MATCH_FUNC | G_SIGNAL_MATCH_DATA,
	                                      0,
	                                      0,
	                                      NULL,
	                                      G_CALLBACK (connection_init_result_cb),
	                                      self);

	path = nm_connection_get_path (NM_CONNECTION (remote));

	g_object_get (G_OBJECT (remote),
	              NM_REMOTE_CONNECTION_INIT_RESULT, &init_result,
	              NULL);

	switch (init_result) {
	case NM_REMOTE_CONNECTION_INIT_RESULT_SUCCESS:
		/* ref it when adding to ->connections, since removing it from ->pending
		 * will unref it.
		 */
		g_hash_table_insert (priv->connections, g_strdup (path), g_object_ref (remote));

		/* Finally, let users know of the new connection now that it has all
		 * its settings and is valid.
		 */
		g_signal_emit_by_name (self, "new-connection", remote);
		break;
	case NM_REMOTE_CONNECTION_INIT_RESULT_ERROR:
	default:
		break;
	}

	g_hash_table_remove (priv->pending, path);

	/* Let listeners know that all connections have been found */
	if (!g_hash_table_size (priv->pending))
		g_signal_emit_by_name (self, NM_SETTINGS_INTERFACE_CONNECTIONS_READ);
}

static void
new_connection_cb (DBusGProxy *proxy, const char *path, gpointer user_data)
{
	NMRemoteSettings *self = NM_REMOTE_SETTINGS (user_data);
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);
	NMRemoteConnection *connection;

	connection = nm_remote_connection_new (priv->bus, path);
	if (connection) {
		g_signal_connect (connection, "removed",
		                  G_CALLBACK (connection_removed_cb),
		                  self);

		g_signal_connect (connection, "notify::" NM_REMOTE_CONNECTION_INIT_RESULT,
		                  G_CALLBACK (connection_init_result_cb),
		                  self);

		/* Add the connection to the pending table to wait for it to retrieve
		 * it's settings asynchronously over D-Bus.  The connection isn't
		 * really valid until it has all its settings, so hide it until it does.
		 */
		g_hash_table_insert (priv->pending, g_strdup (path), connection);
	}
}

static void
fetch_connections_done (DBusGProxy *proxy,
                        GPtrArray *connections,
                        GError *error,
                        gpointer user_data)
{
	NMRemoteSettings *self = NM_REMOTE_SETTINGS (user_data);
	int i;

	if (error) {
		g_warning ("%s: error fetching connections: (%d) %s.",
		           __func__,
		           error->code,
		           error->message ? error->message : "(unknown)");
		g_clear_error (&error);
		return;
	}

	/* Let listeners know we are done getting connections */
	if (connections->len == 0) {
		g_signal_emit_by_name (self, NM_SETTINGS_INTERFACE_CONNECTIONS_READ);
		return;
	}

	for (i = 0; connections && (i < connections->len); i++) {
		char *path = g_ptr_array_index (connections, i);

		new_connection_cb (proxy, path, user_data);
		g_free (path);
	}
	g_ptr_array_free (connections, TRUE);
}

static gboolean
fetch_connections (gpointer user_data)
{
	NMRemoteSettings *self = NM_REMOTE_SETTINGS (user_data);
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);

	priv->fetch_id = 0;

	org_freedesktop_NetworkManagerSettings_list_connections_async (priv->proxy,
	                                                               fetch_connections_done,
	                                                               self);
	return FALSE;
}

static GSList *
list_connections (NMSettingsInterface *settings)
{
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (settings);
	GSList *list = NULL;
	GHashTableIter iter;
	gpointer value;

	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, NULL, &value))
		list = g_slist_prepend (list, NM_REMOTE_CONNECTION (value));

	return list;
}

typedef struct {
	NMSettingsInterface *self;
	NMSettingsAddConnectionFunc callback;
	gpointer callback_data;
} AddConnectionInfo;

static void
add_connection_done (DBusGProxy *proxy,
                     GError *error,
                     gpointer user_data)
{
	AddConnectionInfo *info = user_data;

	info->callback (info->self, error, info->callback_data);
	g_free (info);
}

static gboolean
add_connection (NMSettingsInterface *settings,
	            NMConnection *connection,
	            NMSettingsAddConnectionFunc callback,
	            gpointer user_data)
{
	NMRemoteSettings *self = NM_REMOTE_SETTINGS (settings);
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);
	AddConnectionInfo *info;
	GHashTable *new_settings;

	info = g_malloc0 (sizeof (AddConnectionInfo));
	info->self = settings;
	info->callback = callback;
	info->callback_data = user_data;

	new_settings = nm_connection_to_hash (connection);
	org_freedesktop_NetworkManagerSettings_add_connection_async (priv->proxy,
	                                                             new_settings,
	                                                             add_connection_done,
	                                                             info);
	g_hash_table_destroy (new_settings);
	return TRUE;
}

static gboolean
remove_connections (gpointer user_data)
{
	NMRemoteSettings *self = NM_REMOTE_SETTINGS (user_data);
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);
	GHashTableIter iter;
	gpointer value;
	GSList *list = NULL, *list_iter;

	/* Build up the list of connections; we can't emit "removed" during hash
	 * table iteration because emission of the "removed" signal may trigger code
	 * that explicitly removes the the connection from the hash table somewhere
	 * else.
	 */
	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, NULL, &value))
		list = g_slist_prepend (list, NM_REMOTE_CONNECTION (value));

	for (list_iter = list; list_iter; list_iter = g_slist_next (list_iter))
		g_signal_emit_by_name (NM_REMOTE_CONNECTION (list_iter->data), "removed");
	g_slist_free (list);

	g_hash_table_remove_all (priv->connections);
	return FALSE;
}

typedef struct {
	NMSettingsInterface *settings;
	NMSettingsSaveHostnameFunc callback;
	gpointer callback_data;
} SaveHostnameInfo;

static void
save_hostname_cb (DBusGProxy *proxy,
                  DBusGProxyCall *call,
                  gpointer user_data)
{
	SaveHostnameInfo *info = user_data;
	GError *error = NULL;

	dbus_g_proxy_end_call (proxy, call, &error, G_TYPE_INVALID);
	info->callback (info->settings, error, info->callback_data);
	g_clear_error (&error);
}

static gboolean
save_hostname (NMSettingsInterface *settings,
               const char *hostname,
               NMSettingsSaveHostnameFunc callback,
               gpointer user_data)
{
	NMRemoteSettings *self = NM_REMOTE_SETTINGS (settings);
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);
	SaveHostnameInfo *info;

	info = g_malloc0 (sizeof (SaveHostnameInfo));
	info->settings = settings;
	info->callback = callback;
	info->callback_data = user_data;

	dbus_g_proxy_begin_call (priv->proxy, "SaveHostname",
	                         save_hostname_cb,
	                         info,
	                         g_free,
	                         G_TYPE_STRING, hostname ? hostname : "",
	                         G_TYPE_INVALID);
	return TRUE;
}

typedef struct {
	NMSettingsInterface *settings;
	NMSettingsGetPermissionsFunc callback;
	gpointer callback_data;
} GetPermissionsInfo;

static void
get_permissions_cb  (DBusGProxy *proxy,
                     DBusGProxyCall *call,
                     gpointer user_data)
{
	GetPermissionsInfo *info = user_data;
	NMRemoteSettings *self = NM_REMOTE_SETTINGS (info->settings);
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);
	NMSettingsPermissions permissions = NM_SETTINGS_PERMISSION_NONE;
	GError *error = NULL;

	dbus_g_proxy_end_call (proxy, call, &error,
	                       G_TYPE_UINT, &permissions,
	                       G_TYPE_INVALID);
	priv->permissions = permissions;
	priv->have_permissions = !error;
	info->callback (info->settings, permissions, error, info->callback_data);
	g_clear_error (&error);
}

static gboolean
get_permissions (NMSettingsInterface *settings,
                 NMSettingsGetPermissionsFunc callback,
                 gpointer user_data)
{
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (settings);
	GetPermissionsInfo *info;

	/* Skip D-Bus if we already have permissions */
	if (priv->have_permissions) {
		callback (settings, priv->permissions, NULL, user_data);
		return TRUE;
	}

	/* Otherwise fetch them from NM */
	info = g_malloc0 (sizeof (GetPermissionsInfo));
	info->settings = settings;
	info->callback = callback;
	info->callback_data = user_data;

	dbus_g_proxy_begin_call (priv->proxy, "GetPermissions",
	                         get_permissions_cb,
	                         info,
	                         g_free,
	                         G_TYPE_INVALID);
	return TRUE;
}

static void
name_owner_changed (DBusGProxy *proxy,
                    const char *name,
                    const char *old_owner,
                    const char *new_owner,
                    gpointer user_data)
{
	NMRemoteSettings *self = NM_REMOTE_SETTINGS (user_data);
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);
	const char *sname = NM_DBUS_SERVICE_SYSTEM_SETTINGS;

	if (!strcmp (name, sname)) {
		if (priv->fetch_id)
			g_source_remove (priv->fetch_id);

		if (new_owner && strlen (new_owner) > 0) {
			priv->fetch_id = g_idle_add (fetch_connections, self);
			priv->service_running = TRUE;
		} else {
			priv->fetch_id = g_idle_add (remove_connections, self);
			priv->service_running = FALSE;
		}
		g_object_notify (G_OBJECT (self), NM_REMOTE_SETTINGS_SERVICE_RUNNING);
	}
}

static void
check_permissions_cb (DBusGProxy *proxy, gpointer user_data)
{
	NMRemoteSettings *self = NM_REMOTE_SETTINGS (user_data);
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);

	/* Permissions need to be re-fetched */
	priv->have_permissions = FALSE;
	g_signal_emit_by_name (self, NM_SETTINGS_INTERFACE_CHECK_PERMISSIONS);
}

static void
properties_changed_cb (DBusGProxy *proxy,
                       GHashTable *properties,
                       gpointer user_data)
{
	NMRemoteSettings *self = NM_REMOTE_SETTINGS (user_data);
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);
	GHashTableIter iter;
	gpointer key, tmp;

	g_hash_table_iter_init (&iter, properties);
	while (g_hash_table_iter_next (&iter, &key, &tmp)) {
		GValue *value = tmp;

		if (!strcmp ((const char *) key, "Hostname")) {
			g_free (priv->hostname);
			priv->hostname = g_value_dup_string (value);
			g_object_notify (G_OBJECT (self), NM_SETTINGS_INTERFACE_HOSTNAME);
		}

		if (!strcmp ((const char *) key, "CanModify")) {
			priv->can_modify = g_value_get_boolean (value);
			g_object_notify (G_OBJECT (self), NM_SETTINGS_INTERFACE_CAN_MODIFY);
		}
	}
}

static void
get_all_cb  (DBusGProxy *proxy,
             DBusGProxyCall *call,
             gpointer user_data)
{
	NMRemoteSettings *self = NM_REMOTE_SETTINGS (user_data);
	GHashTable *props = NULL;
	GError *error = NULL;

	if (!dbus_g_proxy_end_call (proxy, call, &error,
	                            DBUS_TYPE_G_MAP_OF_VARIANT, &props,
	                            G_TYPE_INVALID)) {
		/* Don't warn when the call times out because the settings service can't
		 * be activated or whatever.
		 */
		if (!(error->domain == DBUS_GERROR && error->code == DBUS_GERROR_NO_REPLY)) {
			g_warning ("%s: couldn't retrieve system settings properties: (%d) %s.",
			           __func__,
			           error ? error->code : -1,
			           (error && error->message) ? error->message : "(unknown)");
		}
		g_clear_error (&error);
		return;
	}

	properties_changed_cb (NULL, props, self);
	g_hash_table_destroy (props);
}

/****************************************************************/

static void
settings_interface_init (NMSettingsInterface *iface)
{
	/* interface implementation */
	iface->list_connections = list_connections;
	iface->get_connection_by_path = get_connection_by_path;
	iface->add_connection = add_connection;
	iface->save_hostname = save_hostname;
	iface->get_permissions = get_permissions;
}

/**
 * nm_remote_settings_new:
 * @bus: a valid and connected D-Bus connection
 *
 * Creates a new object representing the remote settings service.
 *
 * Returns: the new remote settings object on success, or %NULL on failure
 **/
NMRemoteSettings *
nm_remote_settings_new (DBusGConnection *bus)
{
	g_return_val_if_fail (bus != NULL, NULL);

	return (NMRemoteSettings *) g_object_new (NM_TYPE_REMOTE_SETTINGS,
	                                          NM_REMOTE_SETTINGS_BUS, bus,
	                                          NULL);
}

static void
nm_remote_settings_init (NMRemoteSettings *self)
{
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);

	priv->connections = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_object_unref);
	priv->pending = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_object_unref);
}

static GObject *
constructor (GType type,
             guint n_construct_params,
             GObjectConstructParam *construct_params)
{
	GObject *object;
	NMRemoteSettingsPrivate *priv;
	GError *error = NULL;

	object = G_OBJECT_CLASS (nm_remote_settings_parent_class)->constructor (type, n_construct_params, construct_params);
	if (!object)
		return NULL;

	priv = NM_REMOTE_SETTINGS_GET_PRIVATE (object);

	/* D-Bus proxy for clearing connections on NameOwnerChanged */
	priv->dbus_proxy = dbus_g_proxy_new_for_name (priv->bus,
	                                              "org.freedesktop.DBus",
	                                              "/org/freedesktop/DBus",
	                                              "org.freedesktop.DBus");
	g_assert (priv->dbus_proxy);

	dbus_g_object_register_marshaller (_nm_marshal_VOID__STRING_STRING_STRING,
	                                   G_TYPE_NONE,
	                                   G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
	                                   G_TYPE_INVALID);
	dbus_g_proxy_add_signal (priv->dbus_proxy, "NameOwnerChanged",
	                         G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
	                         G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->dbus_proxy,
	                             "NameOwnerChanged",
	                             G_CALLBACK (name_owner_changed),
	                             object, NULL);

	if (!dbus_g_proxy_call (priv->dbus_proxy, "NameHasOwner", &error,
	                        G_TYPE_STRING, NM_DBUS_SERVICE_SYSTEM_SETTINGS,
	                        G_TYPE_INVALID,
	                        G_TYPE_BOOLEAN, &priv->service_running,
	                        G_TYPE_INVALID)) {
		g_warning ("%s (NMRemoteSettings) error getting remote settings service status: (%d) %s\n",
		           __func__,
		           error ? error->code : -1,
		           error && error->message ? error->message : "(unknown)");
		g_error_free (error);
		priv->service_running = FALSE;
	}

	priv->proxy = dbus_g_proxy_new_for_name (priv->bus,
	                                         NM_DBUS_SERVICE_SYSTEM_SETTINGS,
	                                         NM_DBUS_PATH_SETTINGS,
	                                         NM_DBUS_IFACE_SETTINGS);
	g_assert (priv->proxy);
	dbus_g_proxy_set_default_timeout (priv->proxy, G_MAXINT);

	dbus_g_proxy_add_signal (priv->proxy, "NewConnection",
	                         DBUS_TYPE_G_OBJECT_PATH,
	                         G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "NewConnection",
	                             G_CALLBACK (new_connection_cb),
	                             object,
	                             NULL);

	priv->fetch_id = g_idle_add (fetch_connections, object);


	/* D-Bus properties proxy */
	priv->props_proxy = dbus_g_proxy_new_for_name (priv->bus,
	                                               NM_DBUS_SERVICE_SYSTEM_SETTINGS,
	                                               NM_DBUS_PATH_SETTINGS,
	                                               "org.freedesktop.DBus.Properties");
	g_assert (priv->props_proxy);

	/* Monitor properties */
	dbus_g_object_register_marshaller (g_cclosure_marshal_VOID__BOXED,
	                                   G_TYPE_NONE,
	                                   DBUS_TYPE_G_MAP_OF_VARIANT,
	                                   G_TYPE_INVALID);
	dbus_g_proxy_add_signal (priv->proxy, "PropertiesChanged",
	                         DBUS_TYPE_G_MAP_OF_VARIANT,
	                         G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "PropertiesChanged",
	                             G_CALLBACK (properties_changed_cb),
	                             object,
	                             NULL);

	/* Monitor for permissions changes */
	dbus_g_proxy_add_signal (priv->proxy, "CheckPermissions", G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "CheckPermissions",
	                             G_CALLBACK (check_permissions_cb),
	                             object,
	                             NULL);

	/* Get properties */
	dbus_g_proxy_begin_call (priv->props_proxy, "GetAll",
	                         get_all_cb,
	                         object,
	                         NULL,
	                         G_TYPE_STRING, NM_DBUS_IFACE_SETTINGS,
	                         G_TYPE_INVALID);	

	return object;
}

static void
dispose (GObject *object)
{
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (object);

	if (priv->disposed)
		return;

	priv->disposed = TRUE;

	if (priv->fetch_id)
		g_source_remove (priv->fetch_id);

	if (priv->connections)
		g_hash_table_destroy (priv->connections);

	if (priv->pending)
		g_hash_table_destroy (priv->pending);

	g_free (priv->hostname);

	g_object_unref (priv->dbus_proxy);
	g_object_unref (priv->proxy);
	g_object_unref (priv->props_proxy);
	dbus_g_connection_unref (priv->bus);

	G_OBJECT_CLASS (nm_remote_settings_parent_class)->dispose (object);
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_BUS:
		/* Construct only */
		priv->bus = dbus_g_connection_ref ((DBusGConnection *) g_value_get_boxed (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_BUS:
		g_value_set_boxed (value, priv->bus);
		break;
	case PROP_SERVICE_RUNNING:
		g_value_set_boolean (value, priv->service_running);
		break;
	case NM_SETTINGS_INTERFACE_PROP_HOSTNAME:
		g_value_set_string (value, priv->hostname);
		break;
	case NM_SETTINGS_INTERFACE_PROP_CAN_MODIFY:
		g_value_set_boolean (value, priv->can_modify);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_remote_settings_class_init (NMRemoteSettingsClass *class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (class);

	g_type_class_add_private (class, sizeof (NMRemoteSettingsPrivate));

	/* Virtual methods */
	object_class->constructor = constructor;
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->dispose = dispose;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_BUS,
		 g_param_spec_boxed (NM_REMOTE_SETTINGS_BUS,
		                     "DBusGConnection",
		                     "DBusGConnection",
		                     DBUS_TYPE_G_CONNECTION,
		                     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_SERVICE_RUNNING,
		 g_param_spec_boolean (NM_REMOTE_SETTINGS_SERVICE_RUNNING,
		                       "Service running",
		                       "Is service running",
		                       FALSE,
		                       G_PARAM_READABLE));

	g_object_class_override_property (object_class,
	                                  NM_SETTINGS_INTERFACE_PROP_HOSTNAME,
	                                  NM_SETTINGS_INTERFACE_HOSTNAME);

	g_object_class_override_property (object_class,
	                                  NM_SETTINGS_INTERFACE_PROP_CAN_MODIFY,
	                                  NM_SETTINGS_INTERFACE_CAN_MODIFY);

}

