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
 * Copyright (C) 2009 - 2011 Red Hat, Inc.
 */

#include <string.h>
#include <NetworkManager.h>
#include <nm-connection.h>

#include "nm-marshal.h"
#include "nm-dbus-glib-types.h"
#include "nm-remote-settings.h"
#include "nm-settings-bindings.h"
#include "nm-remote-connection-private.h"

G_DEFINE_TYPE (NMRemoteSettings, nm_remote_settings, G_TYPE_OBJECT)

#define NM_REMOTE_SETTINGS_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_REMOTE_SETTINGS, NMRemoteSettingsPrivate))

typedef struct {
	DBusGConnection *bus;

	DBusGProxy *proxy;
	GHashTable *connections;
	GHashTable *pending;  /* Connections we don't have settings for yet */
	gboolean service_running;
	guint32 init_left;

	/* AddConnectionInfo objects that are waiting for the connection to become initialized */
	GSList *add_list;
	
	DBusGProxy *props_proxy;
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
	PROP_HOSTNAME,
	PROP_CAN_MODIFY,

	LAST_PROP
};

/* Signals */
enum {
	NEW_CONNECTION,
	CONNECTIONS_READ,

	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };

/**********************************************************************/

/**
 * nm_remote_settings_error_quark:
 *
 * Registers an error quark for #NMRemoteSettings if necessary.
 *
 * Returns: the error quark used for #NMRemoteSettings errors.
 **/
GQuark
nm_remote_settings_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-remote-settings-error-quark");
	return quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
nm_remote_settings_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			ENUM_ENTRY (NM_REMOTE_SETTINGS_ERROR_UNKNOWN, "UnknownError"),
			ENUM_ENTRY (NM_REMOTE_SETTINGS_ERROR_CONNECTION_REMOVED, "ConnectionRemoved"),
			ENUM_ENTRY (NM_REMOTE_SETTINGS_ERROR_CONNECTION_UNAVAILABLE, "ConnectionUnavailable"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("NMRemoteSettingsError", values);
	}
	return etype;
}

/**********************************************************************/

typedef struct {
	NMRemoteSettings *self;
	NMRemoteSettingsAddConnectionFunc callback;
	gpointer callback_data;
	NMRemoteConnection *connection;
} AddConnectionInfo;

static AddConnectionInfo *
add_connection_info_find (NMRemoteSettings *self, NMRemoteConnection *connection)
{
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);
	GSList *iter;

	for (iter = priv->add_list; iter; iter = g_slist_next (iter)) {
		AddConnectionInfo *info = iter->data;

		if (info->connection == connection)
			return info;
	}

	return NULL;
}

static void
add_connection_info_dispose (NMRemoteSettings *self, AddConnectionInfo *info)
{
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);

	priv->add_list = g_slist_remove (priv->add_list, info);

	g_free (info);
}

static void
add_connection_info_complete (NMRemoteSettings *self,
                              AddConnectionInfo *info,
                              GError *error)
{
	g_return_if_fail (info != NULL);

	info->callback (info->self, error ? NULL : info->connection, error, info->callback_data);
	add_connection_info_dispose (self, info);
}

/**
 * nm_remote_settings_get_connection_by_path:
 * @settings: the %NMRemoteSettings
 * @path: the D-Bus object path of the remote connection
 *
 * Returns the %NMRemoteConnection representing the connection at @path.
 *
 * Returns: (transfer none): the remote connection object on success, or NULL if the object was
 *  not known
 **/
NMRemoteConnection *
nm_remote_settings_get_connection_by_path (NMRemoteSettings *settings, const char *path)
{
	g_return_val_if_fail (settings != NULL, NULL);
	g_return_val_if_fail (NM_IS_REMOTE_SETTINGS (settings), NULL);
	g_return_val_if_fail (path != NULL, NULL);

	return g_hash_table_lookup (NM_REMOTE_SETTINGS_GET_PRIVATE (settings)->connections, path);
}

/**
 * nm_remote_settings_get_connection_by_uuid:
 * @settings: the %NMRemoteSettings
 * @uuid: the UUID of the remote connection
 *
 * Returns the %NMRemoteConnection identified by @uuid.
 *
 * Returns: (transfer none): the remote connection object on success, or NULL if the object was
 *  not known
 **/
NMRemoteConnection *
nm_remote_settings_get_connection_by_uuid (NMRemoteSettings *settings, const char *uuid)
{
	GHashTableIter iter;
	NMRemoteConnection *candidate;

	g_return_val_if_fail (settings != NULL, NULL);
	g_return_val_if_fail (NM_IS_REMOTE_SETTINGS (settings), NULL);
	g_return_val_if_fail (uuid != NULL, NULL);

	g_hash_table_iter_init (&iter, NM_REMOTE_SETTINGS_GET_PRIVATE (settings)->connections);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer) &candidate)) {
		if (g_strcmp0 (uuid, nm_connection_get_uuid (NM_CONNECTION (candidate))) == 0)
			return candidate;
	}

	return NULL;
}

static void
connection_removed_cb (NMRemoteConnection *remote, gpointer user_data)
{
	NMRemoteSettings *self = NM_REMOTE_SETTINGS (user_data);
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);
	AddConnectionInfo *addinfo;
	GError *add_error;
	const char *path;

	/* Might have been removed while it was waiting to be initialized */
	addinfo = add_connection_info_find (self, remote);
	if (addinfo) {
		add_error = g_error_new_literal (NM_REMOTE_SETTINGS_ERROR,
		                                 NM_REMOTE_SETTINGS_ERROR_CONNECTION_REMOVED,
		                                 "Connection removed before it was initialized");
		add_connection_info_complete (self, addinfo, add_error);
		g_error_free (add_error);
	}

	path = nm_connection_get_path (NM_CONNECTION (remote));
	g_hash_table_remove (priv->connections, path);
	g_hash_table_remove (priv->pending, path);
}

static void
connection_visible_cb (NMRemoteConnection *remote,
                       gboolean visible,
                       gpointer user_data)
{
	NMRemoteSettings *self = NM_REMOTE_SETTINGS (user_data);
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);
	const char *path;

	path = nm_connection_get_path (NM_CONNECTION (remote));
	g_assert (path);

	/* When a connection becomes invisible, we put it back in the pending
	 * hash until it becomes visible again.  When it does, we move it back to
	 * the normal connections hash.
	 */
	if (visible) {
		/* Connection visible to this user again */
		if (g_hash_table_lookup (priv->pending, path)) {
			/* Move connection from pending to visible hash; emit for clients */
			g_hash_table_insert (priv->connections, g_strdup (path), g_object_ref (remote));
			g_hash_table_remove (priv->pending, path);
			g_signal_emit (self, signals[NEW_CONNECTION], 0, remote);
		}
	} else {
		/* Connection now invisible to this user */
		if (g_hash_table_lookup (priv->connections, path)) {
			/* Move connection to pending hash and wait for it to become visible again */
			g_hash_table_insert (priv->pending, g_strdup (path), g_object_ref (remote));
			g_hash_table_remove (priv->connections, path);

			/* Signal to clients that the connection is gone; but we have to
			 * block our connection removed handler so we don't destroy
			 * the connection when the signal is emitted.
			 */
			g_signal_handlers_block_by_func (remote, connection_removed_cb, self);
			g_signal_emit_by_name (remote, NM_REMOTE_CONNECTION_REMOVED);
			g_signal_handlers_unblock_by_func (remote, connection_removed_cb, self);
		}
	}
}

static void
connection_init_result_cb (NMRemoteConnection *remote,
                           GParamSpec *pspec,
                           gpointer user_data)
{
	NMRemoteSettings *self = NM_REMOTE_SETTINGS (user_data);
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);
	guint32 init_result = NM_REMOTE_CONNECTION_INIT_RESULT_UNKNOWN;
	AddConnectionInfo *addinfo;
	const char *path;
	GError *add_error = NULL;
	gboolean remove_from_pending = TRUE;

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

	addinfo = add_connection_info_find (self, remote);

	switch (init_result) {
	case NM_REMOTE_CONNECTION_INIT_RESULT_SUCCESS:
		/* ref it when adding to ->connections, since removing it from ->pending
		 * will unref it.
		 */
		g_hash_table_insert (priv->connections, g_strdup (path), g_object_ref (remote));

		/* If there's a pending AddConnection request, complete that here before
		 * signaling new-connection.
		 */
		if (addinfo)
			add_connection_info_complete (self, addinfo, NULL);

		/* Finally, let users know of the new connection now that it has all
		 * its settings and is valid.
		 */
		g_signal_emit (self, signals[NEW_CONNECTION], 0, remote);
		break;
	case NM_REMOTE_CONNECTION_INIT_RESULT_INVISIBLE:
		remove_from_pending = FALSE;
		/* fall through */
	case NM_REMOTE_CONNECTION_INIT_RESULT_ERROR:
		/* Complete pending AddConnection callbacks */
		if (addinfo) {
			add_error = g_error_new_literal (NM_REMOTE_SETTINGS_ERROR,
			                                 NM_REMOTE_SETTINGS_ERROR_CONNECTION_UNAVAILABLE,
			                                 "Connection not visible or not available");
			add_connection_info_complete (self, addinfo, add_error);
			g_error_free (add_error);
		}
		break;
	default:
		break;
	}

	if (remove_from_pending)
		g_hash_table_remove (priv->pending, path);

	/* Let listeners know that all connections have been found */
	priv->init_left--;
	if (priv->init_left == 0)
		g_signal_emit (self, signals[CONNECTIONS_READ], 0);
}

static NMRemoteConnection *
new_connection_cb (DBusGProxy *proxy, const char *path, gpointer user_data)
{
	NMRemoteSettings *self = NM_REMOTE_SETTINGS (user_data);
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);
	NMRemoteConnection *connection = NULL;

	/* Make double-sure we don't already have it */
	connection = g_hash_table_lookup (priv->pending, path);
	if (connection)
		return connection;
	connection = g_hash_table_lookup (priv->connections, path);
	if (connection)
		return connection;

	/* Create a new connection object for it */
	connection = nm_remote_connection_new (priv->bus, path);
	if (connection) {
		g_signal_connect (connection, NM_REMOTE_CONNECTION_REMOVED,
		                  G_CALLBACK (connection_removed_cb),
		                  self);

		g_signal_connect (connection, "visible",
		                  G_CALLBACK (connection_visible_cb),
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
	return connection;
}

static void
fetch_connections_done (DBusGProxy *proxy,
                        GPtrArray *connections,
                        GError *error,
                        gpointer user_data)
{
	NMRemoteSettings *self = NM_REMOTE_SETTINGS (user_data);
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);
	int i;

	if (error) {
		/* Ignore settings service spawn errors */
		if (   !g_error_matches (error, DBUS_GERROR, DBUS_GERROR_SERVICE_UNKNOWN)
		    && !g_error_matches (error, DBUS_GERROR, DBUS_GERROR_NAME_HAS_NO_OWNER)) {
			g_warning ("%s: error fetching connections: (%d) %s.",
			           __func__,
				       error->code,
				       error->message ? error->message : "(unknown)");
		}
		g_clear_error (&error);

		/* We tried to read connections and failed */
		g_signal_emit (self, signals[CONNECTIONS_READ], 0);
		return;
	}

	/* Let listeners know we are done getting connections */
	if (connections->len == 0)
		g_signal_emit (self, signals[CONNECTIONS_READ], 0);
	else {
		priv->init_left = connections->len;
		for (i = 0; i < connections->len; i++) {
			char *path = g_ptr_array_index (connections, i);

			new_connection_cb (proxy, path, user_data);
			g_free (path);
		}
	}

	g_ptr_array_free (connections, TRUE);
}

static gboolean
fetch_connections (gpointer user_data)
{
	NMRemoteSettings *self = NM_REMOTE_SETTINGS (user_data);
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);

	priv->fetch_id = 0;

	org_freedesktop_NetworkManager_Settings_list_connections_async (priv->proxy,
	                                                                fetch_connections_done,
	                                                                self);
	return FALSE;
}

/**
 * nm_remote_settings_list_connections:
 * @settings: the %NMRemoteSettings
 *
 * Returns: (transfer container) (element-type NMClient.RemoteConnection): a
 * list containing all connections provided by the remote settings service.
 * Each element of the returned list is a %NMRemoteConnection instance, which is
 * owned by the %NMRemoteSettings object and should not be freed by the caller.
 * The returned list is, however, owned by the caller and should be freed
 * using g_slist_free() when no longer required.
 **/
GSList *
nm_remote_settings_list_connections (NMRemoteSettings *settings)
{
	NMRemoteSettingsPrivate *priv;
	GSList *list = NULL;
	GHashTableIter iter;
	gpointer value;

	g_return_val_if_fail (settings != NULL, NULL);
	g_return_val_if_fail (NM_IS_REMOTE_SETTINGS (settings), NULL);

	priv = NM_REMOTE_SETTINGS_GET_PRIVATE (settings);

	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, NULL, &value))
		list = g_slist_prepend (list, NM_REMOTE_CONNECTION (value));

	return list;
}

static void
add_connection_done (DBusGProxy *proxy, DBusGProxyCall *call, gpointer user_data)
{
	AddConnectionInfo *info = user_data;
	GError *error = NULL;
	char *path = NULL;

	if (dbus_g_proxy_end_call (proxy, call, &error, DBUS_TYPE_G_OBJECT_PATH, &path, G_TYPE_INVALID)) {
		info->connection = new_connection_cb (proxy, path, info->self);
		g_assert (info->connection);
		/* Wait until this connection is fully initialized before calling the callback */
		g_free (path);
	} else
		add_connection_info_complete (info->self, info, error);

	g_clear_error (&error);
}

/**
 * nm_remote_settings_add_connection:
 * @settings: the %NMRemoteSettings
 * @connection: the connection to add. Note that this object's settings will be
 *   added, not the object itself
 * @callback: (scope async): callback to be called when the add operation completes
 * @user_data: caller-specific data passed to @callback
 *
 * Requests that the remote settings service add the given settings to a new
 * connection.
 *
 * Returns: TRUE if the request was successful, FALSE if it failed
 **/
gboolean
nm_remote_settings_add_connection (NMRemoteSettings *settings,
                                   NMConnection *connection,
                                   NMRemoteSettingsAddConnectionFunc callback,
                                   gpointer user_data)
{
	NMRemoteSettingsPrivate *priv;
	AddConnectionInfo *info;
	GHashTable *new_settings;

	g_return_val_if_fail (settings != NULL, FALSE);
	g_return_val_if_fail (NM_IS_REMOTE_SETTINGS (settings), FALSE);
	g_return_val_if_fail (connection != NULL, FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);
	g_return_val_if_fail (callback != NULL, FALSE);

	priv = NM_REMOTE_SETTINGS_GET_PRIVATE (settings);
	
	info = g_malloc0 (sizeof (AddConnectionInfo));
	info->self = settings;
	info->callback = callback;
	info->callback_data = user_data;

	new_settings = nm_connection_to_hash (connection, NM_SETTING_HASH_FLAG_ALL);
	dbus_g_proxy_begin_call (priv->proxy, "AddConnection",
	                         add_connection_done,
	                         info,
	                         NULL,
	                         DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT, new_settings,
	                         G_TYPE_INVALID);
	g_hash_table_destroy (new_settings);

	priv->add_list = g_slist_append (priv->add_list, info);

	return TRUE;
}

static void
clear_one_hash (GHashTable *table)
{
	GHashTableIter iter;
	gpointer value;
	GSList *list = NULL, *list_iter;

	/* Build up the list of connections; we can't emit "removed" during hash
	 * table iteration because emission of the "removed" signal may trigger code
	 * that explicitly removes the the connection from the hash table somewhere
	 * else.
	 */
	g_hash_table_iter_init (&iter, table);
	while (g_hash_table_iter_next (&iter, NULL, &value))
		list = g_slist_prepend (list, NM_REMOTE_CONNECTION (value));

	for (list_iter = list; list_iter; list_iter = g_slist_next (list_iter))
		g_signal_emit_by_name (NM_REMOTE_CONNECTION (list_iter->data), NM_REMOTE_CONNECTION_REMOVED);
	g_slist_free (list);

	g_hash_table_remove_all (table);
}

static gboolean
remove_connections (gpointer user_data)
{
	NMRemoteSettings *self = NM_REMOTE_SETTINGS (user_data);
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);

	clear_one_hash (priv->pending);
	clear_one_hash (priv->connections);
	return FALSE;
}

typedef struct {
	NMRemoteSettings *settings;
	NMRemoteSettingsSaveHostnameFunc callback;
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

/**
 * nm_remote_settings_save_hostname:
 * @settings: the %NMRemoteSettings
 * @hostname: the new persistent hostname to set, or NULL to clear any existing
 *  persistent hostname
 * @callback: (scope async): callback to be called when the hostname operation completes
 * @user_data: caller-specific data passed to @callback
 *
 * Requests that the machine's persistent hostname be set to the specified value
 * or cleared.
 *
 * Returns: TRUE if the request was successful, FALSE if it failed
 **/
gboolean
nm_remote_settings_save_hostname (NMRemoteSettings *settings,
                                  const char *hostname,
                                  NMRemoteSettingsSaveHostnameFunc callback,
                                  gpointer user_data)
{
	NMRemoteSettingsPrivate *priv;
	SaveHostnameInfo *info;

	g_return_val_if_fail (settings != NULL, FALSE);
	g_return_val_if_fail (NM_IS_REMOTE_SETTINGS (settings), FALSE);
	g_return_val_if_fail (hostname != NULL, FALSE);
	g_return_val_if_fail (callback != NULL, FALSE);
	
	priv = NM_REMOTE_SETTINGS_GET_PRIVATE (settings);

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

static void
name_owner_changed (DBusGProxy *proxy,
                    const char *name,
                    const char *old_owner,
                    const char *new_owner,
                    gpointer user_data)
{
	NMRemoteSettings *self = NM_REMOTE_SETTINGS (user_data);
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);
	const char *sname = NM_DBUS_SERVICE;

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
			g_object_notify (G_OBJECT (self), NM_REMOTE_SETTINGS_HOSTNAME);
		}

		if (!strcmp ((const char *) key, "CanModify")) {
			priv->can_modify = g_value_get_boolean (value);
			g_object_notify (G_OBJECT (self), NM_REMOTE_SETTINGS_CAN_MODIFY);
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

/**
 * nm_remote_settings_new:
 * @bus: (allow-none): a valid and connected D-Bus connection
 *
 * Creates a new object representing the remote settings service.
 *
 * Returns: the new remote settings object on success, or %NULL on failure
 **/
NMRemoteSettings *
nm_remote_settings_new (DBusGConnection *bus)
{
	if (bus == NULL)
		bus = dbus_g_bus_get (DBUS_BUS_SYSTEM, NULL);

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
	                        G_TYPE_STRING, NM_DBUS_SERVICE,
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
	                                         NM_DBUS_SERVICE,
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
	                                               NM_DBUS_SERVICE,
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
	NMRemoteSettings *self = NM_REMOTE_SETTINGS (object);
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);

	if (priv->disposed)
		return;

	priv->disposed = TRUE;

	if (priv->fetch_id)
		g_source_remove (priv->fetch_id);

	while (g_slist_length (priv->add_list))
		add_connection_info_dispose (self, (AddConnectionInfo *) priv->add_list->data);

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
	case PROP_HOSTNAME:
		g_value_set_string (value, priv->hostname);
		break;
	case PROP_CAN_MODIFY:
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

	g_object_class_install_property
		(object_class, PROP_HOSTNAME,
		 g_param_spec_string (NM_REMOTE_SETTINGS_HOSTNAME,
		                      "Hostname",
		                      "Persistent hostname",
		                      NULL,
		                      G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_CAN_MODIFY,
		 g_param_spec_boolean (NM_REMOTE_SETTINGS_CAN_MODIFY,
		                       "CanModify",
		                       "Can modify anything (hostname, connections, etc)",
		                       FALSE,
		                       G_PARAM_READABLE));

	/* Signals */
	signals[NEW_CONNECTION] = 
	                g_signal_new (NM_REMOTE_SETTINGS_NEW_CONNECTION,
	                              G_OBJECT_CLASS_TYPE (object_class),
	                              G_SIGNAL_RUN_FIRST,
	                              G_STRUCT_OFFSET (NMRemoteSettingsClass, new_connection),
	                              NULL, NULL,
	                              g_cclosure_marshal_VOID__OBJECT,
	                              G_TYPE_NONE, 1, G_TYPE_OBJECT);

	signals[CONNECTIONS_READ] = 
	                g_signal_new (NM_REMOTE_SETTINGS_CONNECTIONS_READ,
	                              G_OBJECT_CLASS_TYPE (object_class),
	                              G_SIGNAL_RUN_FIRST,
	                              G_STRUCT_OFFSET (NMRemoteSettingsClass, connections_read),
	                              NULL, NULL,
	                              g_cclosure_marshal_VOID__VOID,
	                              G_TYPE_NONE, 0);
}

