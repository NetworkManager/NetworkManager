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
 * Copyright (C) 2009 - 2012 Red Hat, Inc.
 */

#include <string.h>
#include <NetworkManager.h>
#include <nm-connection.h>

#include "nm-glib-marshal.h"
#include "nm-dbus-glib-types.h"
#include "nm-remote-settings.h"
#include "nm-remote-connection-private.h"
#include "nm-glib-compat.h"

static void nm_remote_settings_initable_iface_init (GInitableIface *iface);
static void nm_remote_settings_async_initable_iface_init (GAsyncInitableIface *iface);

G_DEFINE_TYPE_WITH_CODE (NMRemoteSettings, nm_remote_settings, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, nm_remote_settings_initable_iface_init);
                         G_IMPLEMENT_INTERFACE (G_TYPE_ASYNC_INITABLE, nm_remote_settings_async_initable_iface_init);
                         )

#define NM_REMOTE_SETTINGS_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_REMOTE_SETTINGS, NMRemoteSettingsPrivate))

typedef struct {
	DBusGConnection *bus;
	gboolean inited;

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

/**********************************************************************/

static void
_nm_remote_settings_ensure_inited (NMRemoteSettings *self)
{
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);
	GError *error = NULL;

	if (!priv->inited) {
		if (!g_initable_init (G_INITABLE (self), NULL, &error)) {
			/* Don't warn when the call times out because the settings service can't
			 * be activated or whatever.
			 */
			if (!g_error_matches (error, DBUS_GERROR, DBUS_GERROR_NO_REPLY)) {
				g_warning ("%s: (NMRemoteSettings) error initializing: %s\n",
					       __func__, error->message);
			}
			g_error_free (error);
		}
		priv->inited = TRUE;
	}
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
	NMRemoteSettingsPrivate *priv;

	g_return_val_if_fail (settings != NULL, NULL);
	g_return_val_if_fail (NM_IS_REMOTE_SETTINGS (settings), NULL);
	g_return_val_if_fail (path != NULL, NULL);

	priv = NM_REMOTE_SETTINGS_GET_PRIVATE (settings);

	_nm_remote_settings_ensure_inited (settings);

	return priv->service_running ? g_hash_table_lookup (priv->connections, path) : NULL;
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
	NMRemoteSettingsPrivate *priv;
	GHashTableIter iter;
	NMRemoteConnection *candidate;

	g_return_val_if_fail (settings != NULL, NULL);
	g_return_val_if_fail (NM_IS_REMOTE_SETTINGS (settings), NULL);
	g_return_val_if_fail (uuid != NULL, NULL);

	priv = NM_REMOTE_SETTINGS_GET_PRIVATE (settings);

	_nm_remote_settings_ensure_inited (settings);

	if (priv->service_running) {
		g_hash_table_iter_init (&iter, priv->connections);
		while (g_hash_table_iter_next (&iter, NULL, (gpointer) &candidate)) {
			if (g_strcmp0 (uuid, nm_connection_get_uuid (NM_CONNECTION (candidate))) == 0)
				return candidate;
		}
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

static void connection_visible_cb (NMRemoteConnection *remote,
                                   gboolean visible,
                                   gpointer user_data);

/* Takes a reference to the connection when adding to 'to' */
static void
move_connection (NMRemoteSettings *self,
                 NMRemoteConnection *remote,
                 GHashTable *from,
                 GHashTable *to)
{
	const char *path = nm_connection_get_path (NM_CONNECTION (remote));

	g_hash_table_insert (to, g_strdup (path), g_object_ref (remote));
	if (from)
		g_hash_table_remove (from, path);

	/* Setup connection signals since removing from 'from' clears them, but
	 * also the first time the connection is added to a hash if 'from' is NULL.
	 */
	if (!g_signal_handler_find (remote, G_SIGNAL_MATCH_FUNC,
	                            0, 0, NULL, connection_removed_cb, NULL)) {
		g_signal_connect (remote,
		                  NM_REMOTE_CONNECTION_REMOVED,
		                  G_CALLBACK (connection_removed_cb),
		                  self);
	}

	if (!g_signal_handler_find (remote, G_SIGNAL_MATCH_FUNC,
	                            0, 0, NULL, connection_visible_cb, NULL)) {
		g_signal_connect (remote,
		                  "visible",
		                  G_CALLBACK (connection_visible_cb),
		                  self);
	}
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
			move_connection (self, remote, priv->pending, priv->connections);
			g_signal_emit (self, signals[NEW_CONNECTION], 0, remote);
		}
	} else {
		/* Connection now invisible to this user */
		if (g_hash_table_lookup (priv->connections, path)) {
			/* Move connection to pending hash and wait for it to become visible again */
			move_connection (self, remote, priv->connections, priv->pending);

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
connection_inited (GObject *source, GAsyncResult *result, gpointer user_data)
{
	NMRemoteConnection *remote = NM_REMOTE_CONNECTION (source);
	NMRemoteSettings *self = NM_REMOTE_SETTINGS (user_data);
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);
	AddConnectionInfo *addinfo;
	const char *path;
	GError *error = NULL, *local;

	path = nm_connection_get_path (NM_CONNECTION (remote));
	addinfo = add_connection_info_find (self, remote);

	if (g_async_initable_init_finish (G_ASYNC_INITABLE (remote), result, &error)) {
		/* Connection is initialized and visible; expose it to clients */
		move_connection (self, remote, priv->pending, priv->connections);

		/* If there's a pending AddConnection request, complete that here before
		 * signaling new-connection.
		 */
		if (addinfo)
			add_connection_info_complete (self, addinfo, NULL);

		/* Finally, let users know of the new connection now that it has all
		 * its settings and is valid.
		 */
		g_signal_emit (self, signals[NEW_CONNECTION], 0, remote);
	} else {
		if (addinfo) {
			local = g_error_new_literal (NM_REMOTE_SETTINGS_ERROR,
			                             NM_REMOTE_SETTINGS_ERROR_CONNECTION_UNAVAILABLE,
			                             "Connection not visible or not available");
			add_connection_info_complete (self, addinfo, local);
			g_error_free (local);
		}

		/* PermissionDenied means the connection isn't visible to this user, so
		 * keep it in priv->pending to be notified later of visibility changes.
		 * Otherwise forget it.
		 */
		if (!dbus_g_error_has_name (error, "org.freedesktop.NetworkManager.Settings.PermissionDenied"))
			g_hash_table_remove (priv->pending, path);

		g_error_free (error);
	}

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
		g_async_initable_init_async (G_ASYNC_INITABLE (connection),
		                             G_PRIORITY_DEFAULT, NULL,
		                             connection_inited, self);

		/* Add the connection to the pending table to wait for it to retrieve
		 * it's settings asynchronously over D-Bus.  The connection isn't
		 * really valid until it has all its settings, so hide it until it does.
		 */
		move_connection (self, connection, NULL, priv->pending);
		g_object_unref (connection); /* move_connection() takes a ref */
	}
	return connection;
}

static void
fetch_connections_done (DBusGProxy *proxy,
                        DBusGProxyCall *call,
                        gpointer user_data)
{
	NMRemoteSettings *self = NM_REMOTE_SETTINGS (user_data);
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);
	GPtrArray *connections;
	GError *error = NULL;
	int i;

	if (!dbus_g_proxy_end_call (proxy, call, &error, 
	                            DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH, &connections,
	                            G_TYPE_INVALID)) {
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

	dbus_g_proxy_begin_call (priv->proxy, "ListConnections",
	                         fetch_connections_done, self, NULL,
	                         G_TYPE_INVALID);
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

	_nm_remote_settings_ensure_inited (settings);

	if (priv->service_running) {
		g_hash_table_iter_init (&iter, priv->connections);
		while (g_hash_table_iter_next (&iter, NULL, &value))
			list = g_slist_prepend (list, NM_REMOTE_CONNECTION (value));
	}

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
 * @user_data: (closure): caller-specific data passed to @callback
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

	_nm_remote_settings_ensure_inited (settings);

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
	if (info->callback != NULL)
		info->callback (info->settings, error, info->callback_data);
	g_clear_error (&error);
}

/**
 * nm_remote_settings_save_hostname:
 * @settings: the %NMRemoteSettings
 * @hostname: the new persistent hostname to set, or NULL to clear any existing
 *  persistent hostname
 * @callback: (scope async) (allow-none): callback to be called when the
 * hostname operation completes
 * @user_data: (closure): caller-specific data passed to @callback
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

	_nm_remote_settings_ensure_inited (settings);

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

/****************************************************************/

/**
 * nm_remote_settings_new:
 * @bus: (allow-none): a valid and connected D-Bus connection
 *
 * Creates a new object representing the remote settings service.
 *
 * Note that this will do blocking D-Bus calls to initialize the
 * settings object. You can use nm_remote_settings_new_async() if you
 * want to avoid that.
 *
 * Returns: the new remote settings object on success, or %NULL on failure
 **/
NMRemoteSettings *
nm_remote_settings_new (DBusGConnection *bus)
{
	return g_object_new (NM_TYPE_REMOTE_SETTINGS, NM_REMOTE_SETTINGS_BUS, bus, NULL);
}

static void
remote_settings_inited (GObject *source, GAsyncResult *result, gpointer user_data)
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
 * nm_remote_settings_new_async:
 * @bus: (allow-none): a valid and connected D-Bus connection
 * @cancellable: a #GCancellable, or %NULL
 * @callback: callback to call when the settings object is created
 * @user_data: data for @callback
 *
 * Creates a new object representing the remote settings service and
 * begins asynchronously initializing it. @callback will be called
 * when it is done; use nm_remote_settings_new_finish() to get the
 * result.
 **/
void
nm_remote_settings_new_async (DBusGConnection *bus, GCancellable *cancellable,
                              GAsyncReadyCallback callback, gpointer user_data)
{
	NMRemoteSettings *self;
	GSimpleAsyncResult *simple;

	simple = g_simple_async_result_new (NULL, callback, user_data, nm_remote_settings_new_async);

	self = g_object_new (NM_TYPE_REMOTE_SETTINGS,
	                     NM_REMOTE_SETTINGS_BUS, bus,
	                     NULL);
	g_async_initable_init_async (G_ASYNC_INITABLE (self), G_PRIORITY_DEFAULT,
	                             cancellable, remote_settings_inited, simple);
}

/**
 * nm_remote_settings_new_finish:
 * @result: a #GAsyncResult
 * @error: location for a #GError, or %NULL
 *
 * Gets the result of an nm_remote_settings_new_async() call.
 *
 * Returns: a new #NMRemoteSettings object, or %NULL on error
 **/
NMRemoteSettings *
nm_remote_settings_new_finish (GAsyncResult *result, GError **error)
{
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (g_simple_async_result_is_valid (result, NULL, nm_remote_settings_new_async), NULL);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return NULL;
	else
		return g_object_ref (g_simple_async_result_get_op_res_gpointer (simple));
}

static void
forget_connection (gpointer user_data)
{
	NMRemoteConnection *remote = NM_REMOTE_CONNECTION (user_data);

	g_signal_handlers_disconnect_matched (remote, G_SIGNAL_MATCH_FUNC,
	                                      0, 0, NULL, connection_removed_cb, NULL);
	g_signal_handlers_disconnect_matched (remote, G_SIGNAL_MATCH_FUNC,
	                                      0, 0, NULL, connection_visible_cb, NULL);
	g_object_unref (remote);
}

static void
nm_remote_settings_init (NMRemoteSettings *self)
{
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);

	priv->connections = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, forget_connection);
	priv->pending = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, forget_connection);
}

static void
constructed (GObject *object)
{
	NMRemoteSettingsPrivate *priv;

	priv = NM_REMOTE_SETTINGS_GET_PRIVATE (object);

	/* D-Bus proxy for clearing connections on NameOwnerChanged */
	priv->dbus_proxy = dbus_g_proxy_new_for_name (priv->bus,
	                                              "org.freedesktop.DBus",
	                                              "/org/freedesktop/DBus",
	                                              "org.freedesktop.DBus");
	g_assert (priv->dbus_proxy);

	dbus_g_object_register_marshaller (_nm_glib_marshal_VOID__STRING_STRING_STRING,
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
}

static gboolean
init_sync (GInitable *initable, GCancellable *cancellable, GError **error)
{
	NMRemoteSettings *settings = NM_REMOTE_SETTINGS (initable);
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (settings);
	GHashTable *props;

	if (!dbus_g_proxy_call (priv->dbus_proxy, "NameHasOwner", error,
	                        G_TYPE_STRING, NM_DBUS_SERVICE,
	                        G_TYPE_INVALID,
	                        G_TYPE_BOOLEAN, &priv->service_running,
	                        G_TYPE_INVALID)) {
		priv->service_running = FALSE;
		return FALSE;
	}

	/* Get properties */
	if (!dbus_g_proxy_call (priv->props_proxy, "GetAll", error,
	                        G_TYPE_STRING, NM_DBUS_IFACE_SETTINGS,
	                        G_TYPE_INVALID,
	                        DBUS_TYPE_G_MAP_OF_VARIANT, &props,
	                        G_TYPE_INVALID))
		return FALSE;
	properties_changed_cb (priv->props_proxy, props, settings);
	g_hash_table_destroy (props);

	/* FIXME: need a synchronous fetch_connections too */

	return TRUE;
}

typedef struct {
	NMRemoteSettings *settings;
	GSimpleAsyncResult *result;
} NMRemoteSettingsInitData;

static void
init_async_complete (NMRemoteSettingsInitData *init_data)
{
	g_simple_async_result_complete (init_data->result);
	g_object_unref (init_data->result);
	g_slice_free (NMRemoteSettingsInitData, init_data);
}

static void
init_read_connections (NMRemoteSettings *settings, gpointer user_data)
{
	NMRemoteSettingsInitData *init_data = user_data;

	g_signal_handlers_disconnect_by_func (settings, G_CALLBACK (init_read_connections), user_data);
	init_async_complete (init_data);
}

static void
init_async_got_properties (DBusGProxy *proxy, DBusGProxyCall *call,
                           gpointer user_data)
{
	NMRemoteSettingsInitData *init_data = user_data;
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (init_data->settings);
	GHashTable *props;
	GError *error = NULL;

	if (dbus_g_proxy_end_call (proxy, call, &error,
	                           DBUS_TYPE_G_MAP_OF_VARIANT, &props,
	                           G_TYPE_INVALID)) {
		properties_changed_cb (priv->props_proxy, props, init_data->settings);
		g_hash_table_destroy (props);
		g_simple_async_result_set_op_res_gboolean (init_data->result, TRUE);
	} else
		g_simple_async_result_take_error (init_data->result, error);

	if (priv->init_left) {
		/* Still creating initial connections; wait for that to complete */
		g_signal_connect (init_data->settings, "connections-read",
		                  G_CALLBACK (init_read_connections), init_data);
		return;
	}

	init_async_complete (init_data);
}

static void
init_async_got_manager_running (DBusGProxy *proxy, DBusGProxyCall *call,
                                gpointer user_data)
{
	NMRemoteSettingsInitData *init_data = user_data;
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (init_data->settings);
	GError *error = NULL;

	if (!dbus_g_proxy_end_call (proxy, call, &error,
	                            G_TYPE_BOOLEAN, &priv->service_running,
	                            G_TYPE_INVALID)) {
		g_simple_async_result_take_error (init_data->result, error);
		init_async_complete (init_data);
		return;
	}

	if (!priv->service_running) {
		g_simple_async_result_set_op_res_gboolean (init_data->result, TRUE);
		init_async_complete (init_data);
		return;
	}

	dbus_g_proxy_begin_call (priv->props_proxy, "GetAll",
	                         init_async_got_properties, init_data, NULL,
	                         G_TYPE_STRING, NM_DBUS_IFACE_SETTINGS,
	                         G_TYPE_INVALID);
}

static void
init_async (GAsyncInitable *initable, int io_priority,
			GCancellable *cancellable, GAsyncReadyCallback callback,
			gpointer user_data)
{
	NMRemoteSettingsInitData *init_data;
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (initable);

	init_data = g_slice_new0 (NMRemoteSettingsInitData);
	init_data->settings = NM_REMOTE_SETTINGS (initable);
	init_data->result = g_simple_async_result_new (G_OBJECT (initable), callback,
	                                               user_data, init_async);

	/* Check if NM is running */
	dbus_g_proxy_begin_call (priv->dbus_proxy, "NameHasOwner",
	                         init_async_got_manager_running,
	                         init_data, NULL,
	                         G_TYPE_STRING, NM_DBUS_SERVICE,
	                         G_TYPE_INVALID);
}

static void
dispose (GObject *object)
{
	NMRemoteSettings *self = NM_REMOTE_SETTINGS (object);
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);

	if (priv->fetch_id) {
		g_source_remove (priv->fetch_id);
		priv->fetch_id = 0;
	}

	while (g_slist_length (priv->add_list))
		add_connection_info_dispose (self, (AddConnectionInfo *) priv->add_list->data);

	if (priv->connections) {
		g_hash_table_destroy (priv->connections);
		priv->connections = NULL;
	}

	if (priv->pending) {
		g_hash_table_destroy (priv->pending);
		priv->pending = NULL;
	}

	g_free (priv->hostname);
	priv->hostname = NULL;

	g_clear_object (&priv->dbus_proxy);
	g_clear_object (&priv->proxy);
	g_clear_object (&priv->props_proxy);

	if (priv->bus) {
		dbus_g_connection_unref (priv->bus);
		priv->bus = NULL;
	}

	G_OBJECT_CLASS (nm_remote_settings_parent_class)->dispose (object);
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (object);
	DBusGConnection *connection;

	switch (prop_id) {
	case PROP_BUS:
		/* Construct only */
		connection = (DBusGConnection *) g_value_get_boxed (value);
		if (!connection)
			connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, NULL);
		priv->bus = dbus_g_connection_ref (connection);
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

	_nm_remote_settings_ensure_inited (NM_REMOTE_SETTINGS (object));

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
	object_class->constructed = constructed;
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

static void
nm_remote_settings_initable_iface_init (GInitableIface *iface)
{
	iface->init = init_sync;
}

static void
nm_remote_settings_async_initable_iface_init (GAsyncInitableIface *iface)
{
	iface->init_async = init_async;
}
