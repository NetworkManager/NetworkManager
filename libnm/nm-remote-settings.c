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
 * Copyright 2008 Novell, Inc.
 * Copyright 2009 - 2012 Red Hat, Inc.
 */

#include <string.h>
#include <nm-dbus-interface.h>
#include <nm-connection.h>

#include "nm-dbus-glib-types.h"
#include "nm-remote-settings.h"
#include "nm-remote-connection-private.h"
#include "nm-object-private.h"
#include "nm-dbus-helpers-private.h"
#include "nm-glib-compat.h"
#include "nm-object-private.h"
#include "nm-types.h"

/**
 * SECTION:nm-remote-settings
 * @Short_description: A helper for NetworkManager's settings API
 * @Title: NMRemoteSettings
 * @See_also:#NMRemoteConnection, #NMClient
 *
 * The #NMRemoteSettings object represents NetworkManager's "settings" service,
 * which stores network configuration and allows authenticated clients to
 * add, delete, and modify that configuration.  The data required to connect
 * to a specific network is called a "connection" and encapsulated by the
 * #NMConnection object.  Once a connection is known to NetworkManager, having
 * either been added by a user or read from on-disk storage, the
 * #NMRemoteSettings object creates a #NMRemoteConnection object which
 * represents this stored connection.  Use the #NMRemoteConnection object to
 * perform any operations like modification or deletion.
 *
 * To add a new network connection to the NetworkManager settings service, first
 * build up a template #NMConnection object.  Since this connection is not yet
 * added to NetworkManager, it is known only to your program and is not yet
 * an #NMRemoteConnection.  Then ask #NMRemoteSettings to add your connection.
 * When the connection is added successfully, the supplied callback is called
 * and returns to your program the new #NMRemoteConnection which represents
 * the stored object known to NetworkManager.
 *
 * |[<!-- language="C" -->
 * static void
 * added_cb (NMRemoteSettings *settings,
 *           NMRemoteConnection *remote,
 *           GError *error,
 *           gpointer user_data)
 * {
 *    if (error)
 *        g_print ("Error adding connection: %s", error->message);
 *    else {
 *        g_print ("Added: %s\n", nm_connection_get_path (NM_CONNECTION (remote)));
 *        /&ast; Use 'remote' with nm_remote_connection_commit_changes() to save
 *         * changes and nm_remote_connection_delete() to delete the connection &ast;/
 *    }
 * }
 *
 * static gboolean
 * add_wired_connection (const char *human_name)
 * {
 *    NMConnection *connection;
 *    NMSettingConnection *s_con;
 *    NMSettingWired *s_wired;
 *    char *uuid;
 *    gboolean success;
 *
 *    connection = nm_simple_connection_new ();
 *
 *    /&ast; Build up the 'connection' setting &ast;/
 *    s_con = (NMSettingConnection *) nm_setting_connection_new ();
 *    uuid = nm_utils_uuid_generate ();
 *    g_object_set (G_OBJECT (s_con),
 *                  NM_SETTING_CONNECTION_UUID, uuid,
 *                  NM_SETTING_CONNECTION_ID, human_name,
 *                  NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
 *                  NULL);
 *    g_free (uuid);
 *    nm_connection_add_setting (connection, NM_SETTING (s_con));
 *
 *    /&ast; Add the required 'wired' setting as this is a wired connection &ast;/
 *    nm_connection_add_setting (connection, nm_setting_wired_new ());
 *
 *    /&ast; Add an 'ipv4' setting using AUTO configuration (eg DHCP) &ast;/
 *    s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
 *    g_object_set (G_OBJECT (s_ip4),
 *                  NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
 *                  NULL);
 *    nm_connection_add_setting (connection, NM_SETTING (s_ip4));
 *
 *    /&ast; Ask NetworkManager to store the connection &ast;/
 *    success = nm_remote_settings_add_connection (settings, connection, added_cb, loop);
 *
 *    /&ast; Release the template connection; the actual stored connection will
 *     * be returned in added_cb() &ast;/
 *    g_object_unref (connection);
 *
 *    /&ast; Let glib event loop run and added_cb() will be called when NetworkManager
 *     * is done adding the new connection. &ast;/
 *
 *    return success;
 * }
 * ]|
 */

G_DEFINE_TYPE (NMRemoteSettings, nm_remote_settings, NM_TYPE_OBJECT)

#define NM_REMOTE_SETTINGS_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_REMOTE_SETTINGS, NMRemoteSettingsPrivate))

typedef struct {
	DBusGProxy *proxy;
	GPtrArray *all_connections;
	GPtrArray *visible_connections;

	/* AddConnectionInfo objects that are waiting for the connection to become initialized */
	GSList *add_list;

	char *hostname;
	gboolean can_modify;
} NMRemoteSettingsPrivate;

enum {
	PROP_0,
	PROP_NM_RUNNING,
	PROP_CONNECTIONS,
	PROP_HOSTNAME,
	PROP_CAN_MODIFY,

	LAST_PROP
};

/* Signals */
enum {
	CONNECTION_ADDED,
	CONNECTION_REMOVED,

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

typedef struct {
	NMRemoteSettings *self;
	NMRemoteSettingsAddConnectionFunc callback;
	gpointer callback_data;
	char *path;
} AddConnectionInfo;

static AddConnectionInfo *
add_connection_info_find (NMRemoteSettings *self, const char *path)
{
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);
	GSList *iter;

	for (iter = priv->add_list; iter; iter = g_slist_next (iter)) {
		AddConnectionInfo *info = iter->data;

		if (!g_strcmp0 (info->path, path))
			return info;
	}

	return NULL;
}

static void
add_connection_info_dispose (NMRemoteSettings *self, AddConnectionInfo *info)
{
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);

	priv->add_list = g_slist_remove (priv->add_list, info);

	g_free (info->path);
	g_free (info);
}

static void
add_connection_info_complete (NMRemoteSettings *self,
                              AddConnectionInfo *info,
                              NMRemoteConnection *connection,
                              GError *error)
{
	g_return_if_fail (info != NULL);

	info->callback (info->self, connection, error, info->callback_data);
	add_connection_info_dispose (self, info);
}

typedef const char * (*ConnectionStringGetter) (NMConnection *);

static NMRemoteConnection *
get_connection_by_string (NMRemoteSettings *settings,
                          const char *string,
                          ConnectionStringGetter get_comparison_string)
{
	NMRemoteSettingsPrivate *priv;
	NMConnection *candidate;
	int i;

	if (!_nm_object_get_nm_running (NM_OBJECT (settings)))
		return NULL;

	priv = NM_REMOTE_SETTINGS_GET_PRIVATE (settings);

	for (i = 0; i < priv->visible_connections->len; i++) {
		candidate = priv->visible_connections->pdata[i];
		if (!g_strcmp0 (string, get_comparison_string (candidate)))
			return NM_REMOTE_CONNECTION (candidate);
	}

	return NULL;
}

/**
 * nm_remote_settings_get_connection_by_id:
 * @settings: the %NMRemoteSettings
 * @id: the id of the remote connection
 *
 * Returns the first matching %NMRemoteConnection matching a given @id.
 *
 * Returns: (transfer none): the remote connection object on success, or %NULL if no
 *  matching object was found.
 **/
NMRemoteConnection *
nm_remote_settings_get_connection_by_id (NMRemoteSettings *settings, const char *id)
{
	g_return_val_if_fail (NM_IS_REMOTE_SETTINGS (settings), NULL);
	g_return_val_if_fail (id != NULL, NULL);

	return get_connection_by_string (settings, id, nm_connection_get_id);
}

/**
 * nm_remote_settings_get_connection_by_path:
 * @settings: the %NMRemoteSettings
 * @path: the D-Bus object path of the remote connection
 *
 * Returns the %NMRemoteConnection representing the connection at @path.
 *
 * Returns: (transfer none): the remote connection object on success, or %NULL if the object was
 *  not known
 **/
NMRemoteConnection *
nm_remote_settings_get_connection_by_path (NMRemoteSettings *settings, const char *path)
{
	g_return_val_if_fail (NM_IS_REMOTE_SETTINGS (settings), NULL);
	g_return_val_if_fail (path != NULL, NULL);

	return get_connection_by_string (settings, path, nm_connection_get_path);
}

/**
 * nm_remote_settings_get_connection_by_uuid:
 * @settings: the %NMRemoteSettings
 * @uuid: the UUID of the remote connection
 *
 * Returns the %NMRemoteConnection identified by @uuid.
 *
 * Returns: (transfer none): the remote connection object on success, or %NULL if the object was
 *  not known
 **/
NMRemoteConnection *
nm_remote_settings_get_connection_by_uuid (NMRemoteSettings *settings, const char *uuid)
{
	g_return_val_if_fail (NM_IS_REMOTE_SETTINGS (settings), NULL);
	g_return_val_if_fail (uuid != NULL, NULL);

	return get_connection_by_string (settings, uuid, nm_connection_get_uuid);
}

static void
connection_visible_changed (GObject *object,
                            GParamSpec *pspec,
                            gpointer user_data)
{
	NMRemoteConnection *connection = NM_REMOTE_CONNECTION (object);
	NMRemoteSettings *self = NM_REMOTE_SETTINGS (user_data);

	if (nm_remote_connection_get_visible (connection))
		g_signal_emit (self, signals[CONNECTION_ADDED], 0, connection);
	else
		g_signal_emit (self, signals[CONNECTION_REMOVED], 0, connection);
}

static void
cleanup_connection (NMRemoteSettings *self,
                    NMRemoteConnection *remote)
{
	g_signal_handlers_disconnect_by_func (remote, G_CALLBACK (connection_visible_changed), self);
}

static void
connection_removed (NMRemoteSettings *self,
                    NMRemoteConnection *remote)
{
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);
	gboolean still_exists = FALSE;
	int i;

	/* Check if the connection was actually removed or if it just turned invisible. */
	if (priv->all_connections) {
		for (i = 0; i < priv->all_connections->len; i++) {
			if (remote == priv->all_connections->pdata[i]) {
				still_exists = TRUE;
				break;
			}
		}
	}

	if (!still_exists)
		cleanup_connection (self, remote);

	/* Allow the signal to propagate if and only if @remote was in visible_connections */
	if (!g_ptr_array_remove (priv->visible_connections, remote))
		g_signal_stop_emission (self, signals[CONNECTION_REMOVED], 0);
}

static void
connection_added (NMRemoteSettings *self,
                  NMRemoteConnection *remote)
{
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);
	AddConnectionInfo *addinfo;
	const char *path;

	if (!g_signal_handler_find (remote, G_SIGNAL_MATCH_FUNC | G_SIGNAL_MATCH_DATA, 0, 0, NULL,
	                            G_CALLBACK (connection_visible_changed), self)) {
		g_signal_connect (remote,
		                  "notify::" NM_REMOTE_CONNECTION_VISIBLE,
		                  G_CALLBACK (connection_visible_changed),
		                  self);
	}

	if (nm_remote_connection_get_visible (remote))
		g_ptr_array_add (priv->visible_connections, remote);
	else
		g_signal_stop_emission (self, signals[CONNECTION_ADDED], 0);

	path = nm_connection_get_path (NM_CONNECTION (remote));
	addinfo = add_connection_info_find (self, path);
	if (addinfo)
		add_connection_info_complete (self, addinfo, remote, NULL);
}

static void
object_creation_failed (NMObject *object, GError *error, char *failed_path)
{
	NMRemoteSettings *self = NM_REMOTE_SETTINGS (object);
	AddConnectionInfo *addinfo;
	GError *add_error;

	addinfo = add_connection_info_find (self, failed_path);
	if (addinfo) {
		add_error = g_error_new_literal (NM_REMOTE_SETTINGS_ERROR,
		                                 NM_REMOTE_SETTINGS_ERROR_CONNECTION_REMOVED,
		                                 "Connection removed before it was initialized");
		add_connection_info_complete (self, addinfo, NULL, add_error);
		g_error_free (add_error);
	}
}

/**
 * nm_remote_settings_list_connections:
 * @settings: the %NMRemoteSettings
 *
 * Returns: (transfer container) (element-type NMRemoteConnection): a
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
	int i;

	g_return_val_if_fail (NM_IS_REMOTE_SETTINGS (settings), NULL);

	priv = NM_REMOTE_SETTINGS_GET_PRIVATE (settings);

	if (_nm_object_get_nm_running (NM_OBJECT (settings))) {
		for (i = 0; i < priv->visible_connections->len; i++)
			list = g_slist_prepend (list, priv->visible_connections->pdata[i]);
		list = g_slist_reverse (list);
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
		info->path = path;
		/* Wait until this connection is fully initialized before calling the callback */
	} else
		add_connection_info_complete (info->self, info, NULL, error);

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
 * connection.  The connection is immediately written to disk.  @connection is
 * untouched by this function and only serves as a template of the settings to
 * add.  The #NMRemoteConnection object that represents what NetworkManager
 * actually added is returned to @callback when the addition operation is complete.
 *
 * Note that the #NMRemoteConnection returned in @callback may not contain
 * identical settings to @connection as NetworkManager may perform automatic
 * completion and/or normalization of connection properties.
 *
 * Returns: %TRUE if the request was successful, %FALSE if it failed
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

	g_return_val_if_fail (NM_IS_REMOTE_SETTINGS (settings), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);
	g_return_val_if_fail (callback != NULL, FALSE);

	priv = NM_REMOTE_SETTINGS_GET_PRIVATE (settings);

	if (!_nm_object_get_nm_running (NM_OBJECT (settings)))
		return FALSE;

	info = g_malloc0 (sizeof (AddConnectionInfo));
	info->self = settings;
	info->callback = callback;
	info->callback_data = user_data;

	new_settings = nm_connection_to_dbus (connection, NM_CONNECTION_SERIALIZE_ALL);
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

/**
 * nm_remote_settings_add_connection_unsaved:
 * @settings: the %NMRemoteSettings
 * @connection: the connection to add. Note that this object's settings will be
 *   added, not the object itself
 * @callback: (scope async): callback to be called when the add operation completes
 * @user_data: (closure): caller-specific data passed to @callback
 *
 * Requests that the remote settings service add the given settings to a new
 * connection.  The connection is not written to disk, which may be done at
 * a later time by calling the connection's nm_remote_connection_commit_changes()
 * method.
 *
 * Returns: %TRUE if the request was successful, %FALSE if it failed
 **/
gboolean
nm_remote_settings_add_connection_unsaved (NMRemoteSettings *settings,
                                           NMConnection *connection,
                                           NMRemoteSettingsAddConnectionFunc callback,
                                           gpointer user_data)
{
	NMRemoteSettingsPrivate *priv;
	AddConnectionInfo *info;
	GHashTable *new_settings;

	g_return_val_if_fail (NM_IS_REMOTE_SETTINGS (settings), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);
	g_return_val_if_fail (callback != NULL, FALSE);

	priv = NM_REMOTE_SETTINGS_GET_PRIVATE (settings);

	if (!_nm_object_get_nm_running (NM_OBJECT (settings)))
		return FALSE;

	info = g_malloc0 (sizeof (AddConnectionInfo));
	info->self = settings;
	info->callback = callback;
	info->callback_data = user_data;

	new_settings = nm_connection_to_dbus (connection, NM_CONNECTION_SERIALIZE_ALL);
	dbus_g_proxy_begin_call (priv->proxy, "AddConnectionUnsaved",
	                         add_connection_done,
	                         info,
	                         NULL,
	                         DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT, new_settings,
	                         G_TYPE_INVALID);
	g_hash_table_destroy (new_settings);

	priv->add_list = g_slist_append (priv->add_list, info);

	return TRUE;
}

/**
 * nm_remote_settings_load_connections:
 * @settings: the %NMRemoteSettings
 * @filenames: %NULL-terminated array of filenames to load
 * @failures: (out) (transfer full): on return, a %NULL-terminated array of
 *   filenames that failed to load
 * @error: return location for #GError
 *
 * Requests that the remote settings service load or reload the given files,
 * adding or updating the connections described within.
 *
 * The changes to the indicated files will not yet be reflected in
 * @settings's connections array when the function returns.
 *
 * If all of the indicated files were successfully loaded, the
 * function will return %TRUE, and @failures will be set to %NULL. If
 * NetworkManager tried to load the files, but some (or all) failed,
 * then @failures will be set to a %NULL-terminated array of the
 * filenames that failed to load.

 * Returns: %TRUE if NetworkManager at least tried to load @filenames,
 * %FALSE if an error occurred (eg, permission denied).
 **/
gboolean
nm_remote_settings_load_connections (NMRemoteSettings *settings,
                                     char **filenames,
                                     char ***failures,
                                     GError **error)
{
	NMRemoteSettingsPrivate *priv;
	char **my_failures = NULL;
	gboolean ret;

	g_return_val_if_fail (NM_IS_REMOTE_SETTINGS (settings), FALSE);
	g_return_val_if_fail (filenames != NULL, FALSE);

	priv = NM_REMOTE_SETTINGS_GET_PRIVATE (settings);

	if (!_nm_object_get_nm_running (NM_OBJECT (settings))) {
		g_set_error_literal (error, NM_REMOTE_SETTINGS_ERROR,
		                     NM_REMOTE_SETTINGS_ERROR_SERVICE_UNAVAILABLE,
		                     "NetworkManager is not running.");
		return FALSE;
	}

	if (!dbus_g_proxy_call (priv->proxy, "LoadConnections", error,
	                        G_TYPE_STRV, filenames,
	                        G_TYPE_INVALID,
	                        G_TYPE_BOOLEAN, &ret,
	                        G_TYPE_STRV, &my_failures,
	                        G_TYPE_INVALID))
		ret = FALSE;

	if (failures) {
		if (my_failures && !*my_failures)
			g_clear_pointer (&my_failures, g_free);
		*failures = my_failures;
	} else
		g_strfreev (my_failures);

	return ret;
}

/**
 * nm_remote_settings_reload_connections:
 * @settings: the #NMRemoteSettings
 * @error: return location for #GError
 *
 * Requests that the remote settings service reload all connection
 * files from disk, adding, updating, and removing connections until
 * the in-memory state matches the on-disk state.
 *
 * Return value: %TRUE on success, %FALSE on failure
 **/
gboolean
nm_remote_settings_reload_connections (NMRemoteSettings *settings,
                                       GError **error)
{
	NMRemoteSettingsPrivate *priv;
	gboolean success;

	g_return_val_if_fail (NM_IS_REMOTE_SETTINGS (settings), FALSE);

	priv = NM_REMOTE_SETTINGS_GET_PRIVATE (settings);

	if (!_nm_object_get_nm_running (NM_OBJECT (settings))) {
		g_set_error_literal (error, NM_REMOTE_SETTINGS_ERROR,
		                     NM_REMOTE_SETTINGS_ERROR_SERVICE_UNAVAILABLE,
		                     "NetworkManager is not running.");
		return FALSE;
	}

	if (!dbus_g_proxy_call (priv->proxy, "ReloadConnections", error,
	                        G_TYPE_INVALID,
	                        G_TYPE_BOOLEAN, &success,
	                        G_TYPE_INVALID))
		return FALSE;
	return success;
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
 * @hostname: the new persistent hostname to set, or %NULL to clear any existing
 *  persistent hostname
 * @callback: (scope async) (allow-none): callback to be called when the
 * hostname operation completes
 * @user_data: (closure): caller-specific data passed to @callback
 *
 * Requests that the machine's persistent hostname be set to the specified value
 * or cleared.
 *
 * Returns: %TRUE if the request was successful, %FALSE if it failed
 **/
gboolean
nm_remote_settings_save_hostname (NMRemoteSettings *settings,
                                  const char *hostname,
                                  NMRemoteSettingsSaveHostnameFunc callback,
                                  gpointer user_data)
{
	NMRemoteSettingsPrivate *priv;
	SaveHostnameInfo *info;

	g_return_val_if_fail (NM_IS_REMOTE_SETTINGS (settings), FALSE);
	g_return_val_if_fail (hostname != NULL, FALSE);
	g_return_val_if_fail (callback != NULL, FALSE);

	priv = NM_REMOTE_SETTINGS_GET_PRIVATE (settings);

	if (!_nm_object_get_nm_running (NM_OBJECT (settings)))
		return FALSE;

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
updated_properties (GObject *object, GAsyncResult *result, gpointer user_data)
{
	NMRemoteSettings *self = NM_REMOTE_SETTINGS (user_data);
	GError *error = NULL;

	if (!_nm_object_reload_properties_finish (NM_OBJECT (object), result, &error)) {
		g_warning ("%s: error reading NMRemoteSettings properties: %s", __func__, error->message);
		g_error_free (error);
	}

	g_object_notify (G_OBJECT (self), NM_REMOTE_SETTINGS_NM_RUNNING);
}

static void
nm_running_changed (GObject *object,
                    GParamSpec *pspec,
                    gpointer user_data)
{
	NMRemoteSettings *self = NM_REMOTE_SETTINGS (object);
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);

	g_object_freeze_notify (object);

	if (!_nm_object_get_nm_running (NM_OBJECT (self))) {
		if (priv->all_connections) {
			GPtrArray *connections;
			int i;

			connections = priv->all_connections;
			priv->all_connections = NULL;

			for (i = 0; i < connections->len; i++) {
				g_signal_emit (self, signals[CONNECTION_REMOVED], 0, connections->pdata[i]);
				g_object_unref (connections->pdata[i]);
			}
			g_ptr_array_unref (connections);
		}

		/* Clear properties */
		if (priv->hostname) {
			g_free (priv->hostname);
			priv->hostname = NULL;
			g_object_notify (G_OBJECT (self), NM_REMOTE_SETTINGS_HOSTNAME);
		}

		if (priv->can_modify) {
			priv->can_modify = FALSE;
			g_object_notify (G_OBJECT (self), NM_REMOTE_SETTINGS_CAN_MODIFY);
		}

		_nm_object_suppress_property_updates (NM_OBJECT (self), TRUE);
		g_object_notify (G_OBJECT (self), NM_REMOTE_SETTINGS_NM_RUNNING);
	} else {
		_nm_object_suppress_property_updates (NM_OBJECT (self), FALSE);
		_nm_object_reload_properties_async (NM_OBJECT (self), updated_properties, self);
	}

	g_object_thaw_notify (object);
}

/****************************************************************/

/**
 * nm_remote_settings_new:
 * @cancellable: a #GCancellable, or %NULL
 * @error: location for a #GError, or %NULL
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
nm_remote_settings_new (GCancellable  *cancellable,
                        GError       **error)
{
	return g_initable_new (NM_TYPE_REMOTE_SETTINGS, cancellable, error,
	                       NULL);
}

/**
 * nm_remote_settings_new_async:
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
nm_remote_settings_new_async (GCancellable *cancellable,
                              GAsyncReadyCallback callback,
                              gpointer user_data)
{
	g_async_initable_new_async (NM_TYPE_REMOTE_SETTINGS, G_PRIORITY_DEFAULT, cancellable,
	                            callback, user_data,
	                            NULL);
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
	GObject *source;
	NMRemoteSettings *settings;

	source = g_async_result_get_source_object (result);
	settings = (NMRemoteSettings *) g_async_initable_new_finish (G_ASYNC_INITABLE (source), result, error);
	g_object_unref (source);

	return settings;
}

static void
nm_remote_settings_init (NMRemoteSettings *self)
{
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);

	priv->visible_connections = g_ptr_array_new ();
}

static void
init_dbus (NMObject *object)
{
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (object);
	const NMPropertiesInfo property_info[] = {
		{ NM_REMOTE_SETTINGS_CONNECTIONS,      &priv->all_connections, NULL, NM_TYPE_REMOTE_CONNECTION, "connection" },
		{ NM_REMOTE_SETTINGS_HOSTNAME,         &priv->hostname },
		{ NM_REMOTE_SETTINGS_CAN_MODIFY,       &priv->can_modify },
		{ NULL },
	};

	NM_OBJECT_CLASS (nm_remote_settings_parent_class)->init_dbus (object);

	priv->proxy = _nm_object_new_proxy (object,
	                                    NM_DBUS_PATH_SETTINGS,
	                                    NM_DBUS_INTERFACE_SETTINGS);
	_nm_object_register_properties (object,
	                                priv->proxy,
	                                property_info);

	g_signal_connect (object, "notify::" NM_OBJECT_NM_RUNNING,
	                  G_CALLBACK (nm_running_changed), NULL);
}

static GObject *
constructor (GType type,
             guint n_construct_params,
             GObjectConstructParam *construct_params)
{
	guint i;
	const char *dbus_path;

	/* Fill in the right D-Bus path if none was specified */
	for (i = 0; i < n_construct_params; i++) {
		if (strcmp (construct_params[i].pspec->name, NM_OBJECT_PATH) == 0) {
			dbus_path = g_value_get_string (construct_params[i].value);
			if (dbus_path == NULL) {
				g_value_set_static_string (construct_params[i].value, NM_DBUS_PATH_SETTINGS);
			} else {
				if (!g_variant_is_object_path (dbus_path)) {
					g_warning ("Passed D-Bus object path '%s' is invalid; using default '%s' instead",
					           dbus_path, NM_DBUS_PATH);
					g_value_set_static_string (construct_params[i].value, NM_DBUS_PATH_SETTINGS);
				}
			}
			break;
		}
	}

	return G_OBJECT_CLASS (nm_remote_settings_parent_class)->constructor (type,
	                                                                      n_construct_params,
	                                                                      construct_params);
}

static void
dispose (GObject *object)
{
	NMRemoteSettings *self = NM_REMOTE_SETTINGS (object);
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);

	while (g_slist_length (priv->add_list))
		add_connection_info_dispose (self, (AddConnectionInfo *) priv->add_list->data);

	if (priv->all_connections) {
		int i;

		for (i = 0; i < priv->all_connections->len; i++) {
			cleanup_connection (self, priv->all_connections->pdata[i]);
			g_object_unref (priv->all_connections->pdata[i]);
		}
		g_clear_pointer (&priv->all_connections, g_ptr_array_unref);
	}
	g_clear_pointer (&priv->visible_connections, g_ptr_array_unref);
	g_clear_pointer (&priv->hostname, g_free);
	g_clear_object (&priv->proxy);

	G_OBJECT_CLASS (nm_remote_settings_parent_class)->dispose (object);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_NM_RUNNING:
		g_value_set_boolean (value, _nm_object_get_nm_running (NM_OBJECT (object)));
		break;
	case PROP_CONNECTIONS:
		g_value_set_boxed (value, priv->visible_connections);
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
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (class);

	g_type_class_add_private (class, sizeof (NMRemoteSettingsPrivate));

	/* Virtual methods */
	object_class->constructor = constructor;
	object_class->get_property = get_property;
	object_class->dispose = dispose;

	nm_object_class->init_dbus = init_dbus;
	nm_object_class->object_creation_failed = object_creation_failed;

	class->connection_added = connection_added;
	class->connection_removed = connection_removed;

	/* Properties */

	/**
	 * NMRemoteSettings:nm-running:
	 *
	 * Whether the NetworkManager settings service is running.
	 */
	g_object_class_install_property
		(object_class, PROP_NM_RUNNING,
		 g_param_spec_boolean (NM_REMOTE_SETTINGS_NM_RUNNING, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMRemoteSettings:connections:
	 *
	 * The list of configured connections that are available to the user. (Note
	 * that this differs from the underlying D-Bus property, which may also
	 * contain the object paths of connections that the user does not have
	 * permission to read the details of.)
	 *
	 * Type: GPtrArray
	 */
	g_object_class_install_property
		(object_class, PROP_CONNECTIONS,
		 g_param_spec_boxed (NM_REMOTE_SETTINGS_CONNECTIONS, "", "",
		                     NM_TYPE_OBJECT_ARRAY,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMRemoteSettings:hostname:
	 *
	 * The machine hostname stored in persistent configuration. This can be
	 * modified by calling nm_remote_settings_save_hostname().
	 */
	g_object_class_install_property
		(object_class, PROP_HOSTNAME,
		 g_param_spec_string (NM_REMOTE_SETTINGS_HOSTNAME, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMRemoteSettings:can-modify:
	 *
	 * If %TRUE, adding and modifying connections is supported.
	 */
	g_object_class_install_property
		(object_class, PROP_CAN_MODIFY,
		 g_param_spec_boolean (NM_REMOTE_SETTINGS_CAN_MODIFY, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/* Signals */
	/**
	 * NMRemoteSettings::connection-added:
	 * @settings: the settings object that received the signal
	 * @connection: the new connection
	 *
	 * Notifies that a #NMConnection has been added.
	 **/
	signals[CONNECTION_ADDED] =
		g_signal_new (NM_REMOTE_SETTINGS_CONNECTION_ADDED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMRemoteSettingsClass, connection_added),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1,
		              NM_TYPE_REMOTE_CONNECTION);

	/**
	 * NMRemoteSettings::connection-removed:
	 * @settings: the settings object that received the signal
	 * @connection: the removed connection
	 *
	 * Notifies that a #NMConnection has been removed.
	 **/
	signals[CONNECTION_REMOVED] =
		g_signal_new (NM_REMOTE_SETTINGS_CONNECTION_REMOVED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMRemoteSettingsClass, connection_removed),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1,
		              NM_TYPE_REMOTE_CONNECTION);
}
