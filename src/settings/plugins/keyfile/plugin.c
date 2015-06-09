/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service - keyfile plugin
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
 * Copyright (C) 2008 Novell, Inc.
 * Copyright (C) 2008 - 2013 Red Hat, Inc.
 */

#include "config.h"

#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>

#include <gmodule.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>

#include <nm-connection.h>
#include <nm-setting.h>
#include <nm-setting-connection.h>
#include <nm-utils.h>
#include <nm-config.h>
#include <nm-logging.h>
#include "nm-core-internal.h"

#include "plugin.h"
#include "nm-system-config-interface.h"
#include "nm-keyfile-connection.h"
#include "writer.h"
#include "common.h"
#include "utils.h"
#include "gsystem-local-alloc.h"

static void system_config_interface_init (NMSystemConfigInterface *system_config_interface_class);

G_DEFINE_TYPE_EXTENDED (SCPluginKeyfile, sc_plugin_keyfile, G_TYPE_OBJECT, 0,
				    G_IMPLEMENT_INTERFACE (NM_TYPE_SYSTEM_CONFIG_INTERFACE,
									  system_config_interface_init))

#define SC_PLUGIN_KEYFILE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SC_TYPE_PLUGIN_KEYFILE, SCPluginKeyfilePrivate))

typedef struct {
	GHashTable *connections;  /* uuid::connection */

	gboolean initialized;
	GFileMonitor *monitor;
	guint monitor_id;

	NMConfig *config;
} SCPluginKeyfilePrivate;

static void
connection_removed_cb (NMSettingsConnection *obj, gpointer user_data)
{
	g_hash_table_remove (SC_PLUGIN_KEYFILE_GET_PRIVATE (user_data)->connections,
	                     nm_connection_get_uuid (NM_CONNECTION (obj)));
}

/* Monitoring */

static void
remove_connection (SCPluginKeyfile *self, NMKeyfileConnection *connection)
{
	gboolean removed;

	g_return_if_fail (connection != NULL);

	nm_log_info (LOGD_SETTINGS, "keyfile: removed " NM_KEYFILE_CONNECTION_LOG_FMT, NM_KEYFILE_CONNECTION_LOG_ARG (connection));

	/* Removing from the hash table should drop the last reference */
	g_object_ref (connection);
	g_signal_handlers_disconnect_by_func (connection, connection_removed_cb, self);
	removed = g_hash_table_remove (SC_PLUGIN_KEYFILE_GET_PRIVATE (self)->connections,
	                               nm_connection_get_uuid (NM_CONNECTION (connection)));
	nm_settings_connection_signal_remove (NM_SETTINGS_CONNECTION (connection));
	g_object_unref (connection);

	g_return_if_fail (removed);
}

static NMKeyfileConnection *
find_by_path (SCPluginKeyfile *self, const char *path)
{
	SCPluginKeyfilePrivate *priv = SC_PLUGIN_KEYFILE_GET_PRIVATE (self);
	GHashTableIter iter;
	NMSettingsConnection *candidate = NULL;

	g_return_val_if_fail (path != NULL, NULL);

	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer) &candidate)) {
		if (g_strcmp0 (path, nm_settings_connection_get_filename (candidate)) == 0)
			return NM_KEYFILE_CONNECTION (candidate);
	}
	return NULL;
}

/* update_connection:
 * @self: the plugin instance
 * @source: if %NULL, this re-reads the connection from @full_path
 *   and updates it. When passing @source, this adds a connection from
 *   memory.
 * @full_path: the filename of the keyfile to be loaded
 * @connection: an existing connection that might be updated.
 *   If given, @connection must be an existing connection that is currently
 *   owned by the plugin.
 * @protect_existing_connection: if %TRUE, and !@connection, we don't allow updating
 *   an existing connection with the same UUID.
 *   If %TRUE and @connection, allow updating only if the reload would modify
 *   @connection (without changing its UUID) or if we would create a new connection.
 *   In other words, if this paramter is %TRUE, we only allow creating a
 *   new connection (with an unseen UUID) or updating the passed in @connection
 *   (whereas the UUID cannot change).
 *   Note, that this allows for @connection to be replaced by a new connection.
 * @protected_connections: (allow-none): if given, we only update an
 *   existing connection if it is not contained in this hash.
 * @error: error in case of failure
 *
 * Loads a connection from file @full_path. This can both be used to
 * load a connection initially or to update an existing connection.
 *
 * If you pass in an existing connection and the reloaded file happens
 * to have a different UUID, the connection is deleted.
 * Beware, that means that after the function, you have a dangling pointer
 * if the returned connection is different from @connection.
 *
 * Returns: the updated connection.
 * */
static NMKeyfileConnection *
update_connection (SCPluginKeyfile *self,
                   NMConnection *source,
                   const char *full_path,
                   NMKeyfileConnection *connection,
                   gboolean protect_existing_connection,
                   GHashTable *protected_connections,
                   GError **error)
{
	SCPluginKeyfilePrivate *priv = SC_PLUGIN_KEYFILE_GET_PRIVATE (self);
	NMKeyfileConnection *connection_new;
	NMKeyfileConnection *connection_by_uuid;
	GError *local = NULL;
	const char *uuid;

	g_return_val_if_fail (!source || NM_IS_CONNECTION (source), NULL);
	g_return_val_if_fail (full_path || source, NULL);

	if (full_path)
		nm_log_dbg (LOGD_SETTINGS, "keyfile: loading from file \"%s\"...", full_path);

	connection_new = nm_keyfile_connection_new (source, full_path, &local);
	if (!connection_new) {
		/* Error; remove the connection */
		if (source)
			nm_log_warn (LOGD_SETTINGS, "keyfile: error creating connection %s: %s", nm_connection_get_uuid (source), local->message);
		else
			nm_log_warn (LOGD_SETTINGS, "keyfile: error loading connection from file %s: %s", full_path, local->message);
		if (   connection
		    && !protect_existing_connection
		    && (!protected_connections || !g_hash_table_contains (protected_connections, connection)))
			remove_connection (self, connection);
		g_propagate_error (error, local);
		return NULL;
	}

	uuid = nm_connection_get_uuid (NM_CONNECTION (connection_new));
	connection_by_uuid = g_hash_table_lookup (priv->connections, uuid);

	if (   connection
	    && connection != connection_by_uuid) {

		if (   (protect_existing_connection && connection_by_uuid != NULL)
		    || (protected_connections && g_hash_table_contains (protected_connections, connection))) {
			NMKeyfileConnection *conflicting = (protect_existing_connection && connection_by_uuid != NULL) ? connection_by_uuid : connection;

			if (source)
				nm_log_warn (LOGD_SETTINGS, "keyfile: cannot update protected "NM_KEYFILE_CONNECTION_LOG_FMT" connection due to conflicting UUID %s", NM_KEYFILE_CONNECTION_LOG_ARG (conflicting), uuid);
			else
				nm_log_warn (LOGD_SETTINGS, "keyfile: cannot load %s due to conflicting UUID for "NM_KEYFILE_CONNECTION_LOG_FMT, full_path, NM_KEYFILE_CONNECTION_LOG_ARG (conflicting));
			g_object_unref (connection_new);
			g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
			                      "Cannot update protected connection due to conflicting UUID");
			return NULL;
		}

		/* The new connection has a different UUID then the original one.
		 * Remove @connection. */
		remove_connection (self, connection);
	}

	if (   connection_by_uuid
	    && (   (!connection && protect_existing_connection)
	        || (protected_connections && g_hash_table_contains (protected_connections, connection_by_uuid)))) {
		if (source)
			nm_log_warn (LOGD_SETTINGS, "keyfile: cannot update connection due to conflicting UUID for "NM_KEYFILE_CONNECTION_LOG_FMT, NM_KEYFILE_CONNECTION_LOG_ARG (connection_by_uuid));
		else
			nm_log_warn (LOGD_SETTINGS, "keyfile: cannot load %s due to conflicting UUID for "NM_KEYFILE_CONNECTION_LOG_FMT, full_path, NM_KEYFILE_CONNECTION_LOG_ARG (connection_by_uuid));
		g_object_unref (connection_new);
		g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		                      "Skip updating protected connection during reload");
		return NULL;
	}

	if (connection_by_uuid) {
		const char *old_path;

		old_path = nm_settings_connection_get_filename (NM_SETTINGS_CONNECTION (connection_by_uuid));

		if (nm_connection_compare (NM_CONNECTION (connection_by_uuid),
		                           NM_CONNECTION (connection_new),
		                           NM_SETTING_COMPARE_FLAG_IGNORE_AGENT_OWNED_SECRETS |
		                           NM_SETTING_COMPARE_FLAG_IGNORE_NOT_SAVED_SECRETS)) {
			/* Nothing to do... except updating the path. */
			if (old_path && g_strcmp0 (old_path, full_path) != 0)
				nm_log_info (LOGD_SETTINGS, "keyfile: rename \"%s\" to "NM_KEYFILE_CONNECTION_LOG_FMT" without other changes", old_path, NM_KEYFILE_CONNECTION_LOG_ARG (connection_new));
		} else {
			/* An existing connection changed. */
			if (source)
				nm_log_info (LOGD_SETTINGS, "keyfile: update "NM_KEYFILE_CONNECTION_LOG_FMT" from %s", NM_KEYFILE_CONNECTION_LOG_ARG (connection_new), NM_KEYFILE_CONNECTION_LOG_PATH (old_path));
			else if (!g_strcmp0 (old_path, nm_settings_connection_get_filename (NM_SETTINGS_CONNECTION (connection_new))))
				nm_log_info (LOGD_SETTINGS, "keyfile: update "NM_KEYFILE_CONNECTION_LOG_FMT, NM_KEYFILE_CONNECTION_LOG_ARG (connection_new));
			else if (old_path)
				nm_log_info (LOGD_SETTINGS, "keyfile: rename \"%s\" to "NM_KEYFILE_CONNECTION_LOG_FMT, old_path, NM_KEYFILE_CONNECTION_LOG_ARG (connection_new));
			else
				nm_log_info (LOGD_SETTINGS, "keyfile: update and persist "NM_KEYFILE_CONNECTION_LOG_FMT, NM_KEYFILE_CONNECTION_LOG_ARG (connection_new));

			if (!nm_settings_connection_replace_settings (NM_SETTINGS_CONNECTION (connection_by_uuid),
			                                              NM_CONNECTION (connection_new),
			                                              FALSE,  /* don't set Unsaved */
			                                              "keyfile-update",
			                                              &local)) {
				/* Shouldn't ever get here as 'connection_new' was verified by the reader already
				 * and the UUID did not change. */
				g_assert_not_reached ();
			}
			g_assert_no_error (local);
		}
		nm_settings_connection_set_filename (NM_SETTINGS_CONNECTION (connection_by_uuid), full_path);
		g_object_unref (connection_new);
		return connection_by_uuid;
	} else {
		if (source)
			nm_log_info (LOGD_SETTINGS, "keyfile: add connection "NM_KEYFILE_CONNECTION_LOG_FMT, NM_KEYFILE_CONNECTION_LOG_ARG (connection_new));
		else
			nm_log_info (LOGD_SETTINGS, "keyfile: new connection "NM_KEYFILE_CONNECTION_LOG_FMT, NM_KEYFILE_CONNECTION_LOG_ARG (connection_new));
		g_hash_table_insert (priv->connections, g_strdup (uuid), connection_new);

		g_signal_connect (connection_new, NM_SETTINGS_CONNECTION_REMOVED,
		                  G_CALLBACK (connection_removed_cb),
		                  self);

		if (!source) {
			/* Only raise the signal if we were called without source, i.e. if we read the connection from file.
			 * Otherwise, we were called by add_connection() which does not expect the signal. */
			g_signal_emit_by_name (self, NM_SYSTEM_CONFIG_INTERFACE_CONNECTION_ADDED, connection_new);
		}
		return connection_new;
	}
}

static void
dir_changed (GFileMonitor *monitor,
             GFile *file,
             GFile *other_file,
             GFileMonitorEvent event_type,
             gpointer user_data)
{
	NMSystemConfigInterface *config = NM_SYSTEM_CONFIG_INTERFACE (user_data);
	SCPluginKeyfile *self = SC_PLUGIN_KEYFILE (config);
	NMKeyfileConnection *connection;
	char *full_path;
	gboolean exists;

	full_path = g_file_get_path (file);
	if (nm_keyfile_plugin_utils_should_ignore_file (full_path)) {
		g_free (full_path);
		return;
	}
	exists = g_file_test (full_path, G_FILE_TEST_EXISTS);

	nm_log_dbg (LOGD_SETTINGS, "dir_changed(%s) = %d; file %s", full_path, event_type, exists ? "exists" : "does not exist");

	connection = find_by_path (self, full_path);

	switch (event_type) {
	case G_FILE_MONITOR_EVENT_DELETED:
		if (!exists && connection)
			remove_connection (SC_PLUGIN_KEYFILE (config), connection);
		break;
	case G_FILE_MONITOR_EVENT_CREATED:
	case G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT:
		if (exists)
			update_connection (SC_PLUGIN_KEYFILE (config), NULL, full_path, connection, TRUE, NULL, NULL);
		break;
	default:
		break;
	}

	g_free (full_path);
}

static void
config_changed_cb (NMConfig *config,
                   NMConfigData *config_data,
                   NMConfigChangeFlags changes,
                   NMConfigData *old_data,
                   SCPluginKeyfile *self)
{
	gs_free char *old_value = NULL, *new_value = NULL;

	old_value = nm_config_data_get_value (old_data, NM_CONFIG_KEYFILE_GROUP_KEYFILE, "unmanaged-devices");
	new_value = nm_config_data_get_value (config_data, NM_CONFIG_KEYFILE_GROUP_KEYFILE, "unmanaged-devices");

	if (g_strcmp0 (old_value, new_value) != 0)
		g_signal_emit_by_name (self, NM_SYSTEM_CONFIG_INTERFACE_UNMANAGED_SPECS_CHANGED);
}

static void
setup_monitoring (NMSystemConfigInterface *config)
{
	SCPluginKeyfilePrivate *priv = SC_PLUGIN_KEYFILE_GET_PRIVATE (config);
	GFile *file;
	GFileMonitor *monitor;

	if (nm_config_get_monitor_connection_files (nm_config_get ())) {
		file = g_file_new_for_path (KEYFILE_DIR);
		monitor = g_file_monitor_directory (file, G_FILE_MONITOR_NONE, NULL, NULL);
		g_object_unref (file);

		if (monitor) {
			priv->monitor_id = g_signal_connect (monitor, "changed", G_CALLBACK (dir_changed), config);
			priv->monitor = monitor;
		}
	}

	g_signal_connect (G_OBJECT (priv->config),
	                  NM_CONFIG_SIGNAL_CONFIG_CHANGED,
	                  G_CALLBACK (config_changed_cb),
	                  config);
}

static GHashTable *
_paths_from_connections (GHashTable *connections)
{
	GHashTableIter iter;
	NMKeyfileConnection *connection;
	GHashTable *paths = g_hash_table_new (g_str_hash, g_str_equal);

	g_hash_table_iter_init (&iter, connections);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &connection)) {
		const char *path = nm_settings_connection_get_filename (NM_SETTINGS_CONNECTION (connection));

		if (path)
			g_hash_table_add (paths, (void *) path);
	}
	return paths;
}

static int
_sort_paths (const char **f1, const char **f2, GHashTable *paths)
{
	struct stat st;
	gboolean c1, c2;
	gint64 m1, m2;

	c1 = !!g_hash_table_contains (paths, *f1);
	c2 = !!g_hash_table_contains (paths, *f2);
	if (c1 != c2)
		return c1 ? -1 : 1;

	m1 = stat (*f1, &st) == 0 ? (gint64) st.st_mtime : G_MININT64;
	m2 = stat (*f2, &st) == 0 ? (gint64) st.st_mtime : G_MININT64;
	if (m1 != m2)
		return m1 > m2 ? -1 : 1;

	return strcmp (*f1, *f2);
}

static void
read_connections (NMSystemConfigInterface *config)
{
	SCPluginKeyfile *self = SC_PLUGIN_KEYFILE (config);
	SCPluginKeyfilePrivate *priv = SC_PLUGIN_KEYFILE_GET_PRIVATE (self);
	GDir *dir;
	GError *error = NULL;
	const char *item;
	GHashTable *alive_connections;
	GHashTableIter iter;
	NMKeyfileConnection *connection;
	GPtrArray *dead_connections = NULL;
	guint i;
	GPtrArray *filenames;
	GHashTable *paths;

	dir = g_dir_open (KEYFILE_DIR, 0, &error);
	if (!dir) {
		nm_log_warn (LOGD_SETTINGS, "keyfile: cannot read directory '%s': (%d) %s",
		             KEYFILE_DIR,
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
		return;
	}

	alive_connections = g_hash_table_new (NULL, NULL);

	filenames = g_ptr_array_new_with_free_func (g_free);
	while ((item = g_dir_read_name (dir))) {
		if (nm_keyfile_plugin_utils_should_ignore_file (item))
			continue;
		g_ptr_array_add (filenames, g_build_filename (KEYFILE_DIR, item, NULL));
	}
	g_dir_close (dir);

	/* While reloading, we don't replace connections that we already loaded while
	 * iterating over the files.
	 *
	 * To have sensible, reproducible behavior, sort the paths by last modification
	 * time prefering older files.
	 */
	paths = _paths_from_connections (priv->connections);
	g_ptr_array_sort_with_data (filenames, (GCompareDataFunc) _sort_paths, paths);
	g_hash_table_destroy (paths);

	for (i = 0; i < filenames->len; i++) {
		connection = update_connection (self, NULL, filenames->pdata[i], NULL, FALSE, alive_connections, NULL);
		if (connection)
			g_hash_table_add (alive_connections, connection);
	}
	g_ptr_array_free (filenames, TRUE);

	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &connection)) {
		if (   !g_hash_table_contains (alive_connections, connection)
		    && nm_settings_connection_get_filename (NM_SETTINGS_CONNECTION (connection))) {
			if (!dead_connections)
				dead_connections = g_ptr_array_new ();
			g_ptr_array_add (dead_connections, connection);
		}
	}
	g_hash_table_destroy (alive_connections);

	if (dead_connections) {
		for (i = 0; i < dead_connections->len; i++)
			remove_connection (self, dead_connections->pdata[i]);
		g_ptr_array_free (dead_connections, TRUE);
	}
}

/* Plugin */

static GSList *
get_connections (NMSystemConfigInterface *config)
{
	SCPluginKeyfilePrivate *priv = SC_PLUGIN_KEYFILE_GET_PRIVATE (config);

	if (!priv->initialized) {
		setup_monitoring (config);
		read_connections (config);
		priv->initialized = TRUE;
	}
	return _nm_utils_hash_values_to_slist (priv->connections);
}

static gboolean
load_connection (NMSystemConfigInterface *config,
                 const char *filename)
{
	SCPluginKeyfile *self = SC_PLUGIN_KEYFILE (config);
	NMKeyfileConnection *connection;
	int dir_len = strlen (KEYFILE_DIR);

	if (   strncmp (filename, KEYFILE_DIR, dir_len) != 0
	    || filename[dir_len] != '/'
	    || strchr (filename + dir_len + 1, '/') != NULL)
		return FALSE;

	if (nm_keyfile_plugin_utils_should_ignore_file (filename + dir_len + 1))
		return FALSE;

	connection = update_connection (self, NULL, filename, find_by_path (self, filename), TRUE, NULL, NULL);

	return (connection != NULL);
}

static void
reload_connections (NMSystemConfigInterface *config)
{
	read_connections (config);
}

static NMSettingsConnection *
add_connection (NMSystemConfigInterface *config,
                NMConnection *connection,
                gboolean save_to_disk,
                GError **error)
{
	SCPluginKeyfile *self = SC_PLUGIN_KEYFILE (config);
	gs_free char *path = NULL;

	if (save_to_disk) {
		if (!nm_keyfile_plugin_write_connection (connection, NULL, &path, error))
			return NULL;
	}
	return NM_SETTINGS_CONNECTION (update_connection (self, connection, path, NULL, FALSE, NULL, error));
}

static GSList *
get_unmanaged_specs (NMSystemConfigInterface *config)
{
	SCPluginKeyfilePrivate *priv = SC_PLUGIN_KEYFILE_GET_PRIVATE (config);
	gs_free char *value = NULL;

	value = nm_config_data_get_value (nm_config_get_data (priv->config), NM_CONFIG_KEYFILE_GROUP_KEYFILE, "unmanaged-devices");
	return nm_match_spec_split (value);
}

/* GObject */

static void
sc_plugin_keyfile_init (SCPluginKeyfile *plugin)
{
	SCPluginKeyfilePrivate *priv = SC_PLUGIN_KEYFILE_GET_PRIVATE (plugin);

	priv->connections = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_object_unref);
}

static void
get_property (GObject *object, guint prop_id,
		    GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_NAME:
		g_value_set_string (value, KEYFILE_PLUGIN_NAME);
		break;
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_INFO:
		g_value_set_string (value, KEYFILE_PLUGIN_INFO);
		break;
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_CAPABILITIES:
		g_value_set_uint (value, NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_CONNECTIONS);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
dispose (GObject *object)
{
	SCPluginKeyfilePrivate *priv = SC_PLUGIN_KEYFILE_GET_PRIVATE (object);

	if (priv->monitor) {
		if (priv->monitor_id) {
			g_signal_handler_disconnect (priv->monitor, priv->monitor_id);
			priv->monitor_id = 0;
		}

		g_file_monitor_cancel (priv->monitor);
		g_clear_object (&priv->monitor);
	}

	if (priv->connections) {
		g_hash_table_destroy (priv->connections);
		priv->connections = NULL;
	}

	if (priv->config) {
		g_signal_handlers_disconnect_by_func (priv->config, config_changed_cb, object);
		g_clear_object (&priv->config);
	}

	G_OBJECT_CLASS (sc_plugin_keyfile_parent_class)->dispose (object);
}

static void
sc_plugin_keyfile_class_init (SCPluginKeyfileClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	g_type_class_add_private (req_class, sizeof (SCPluginKeyfilePrivate));

	object_class->dispose = dispose;
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	g_object_class_override_property (object_class,
	                                  NM_SYSTEM_CONFIG_INTERFACE_PROP_NAME,
	                                  NM_SYSTEM_CONFIG_INTERFACE_NAME);

	g_object_class_override_property (object_class,
	                                  NM_SYSTEM_CONFIG_INTERFACE_PROP_INFO,
	                                  NM_SYSTEM_CONFIG_INTERFACE_INFO);

	g_object_class_override_property (object_class,
	                                  NM_SYSTEM_CONFIG_INTERFACE_PROP_CAPABILITIES,
	                                  NM_SYSTEM_CONFIG_INTERFACE_CAPABILITIES);
}

static void
system_config_interface_init (NMSystemConfigInterface *system_config_interface_class)
{
	/* interface implementation */
	system_config_interface_class->get_connections = get_connections;
	system_config_interface_class->load_connection = load_connection;
	system_config_interface_class->reload_connections = reload_connections;
	system_config_interface_class->add_connection = add_connection;
	system_config_interface_class->get_unmanaged_specs = get_unmanaged_specs;
}

GObject *
nm_settings_keyfile_plugin_new (void)
{
	static SCPluginKeyfile *singleton = NULL;
	SCPluginKeyfilePrivate *priv;
	char *value;

	if (!singleton) {
		singleton = SC_PLUGIN_KEYFILE (g_object_new (SC_TYPE_PLUGIN_KEYFILE, NULL));
		priv = SC_PLUGIN_KEYFILE_GET_PRIVATE (singleton);

		priv->config = g_object_ref (nm_config_get ());
		value = nm_config_data_get_value (nm_config_get_data (priv->config),
		                                  NM_CONFIG_KEYFILE_GROUP_KEYFILE, "hostname");
		if (value) {
			nm_log_warn (LOGD_SETTINGS, "keyfile: 'hostname' option is deprecated and has no effect");
			g_free (value);
		}
	} else
		g_object_ref (singleton);

	return G_OBJECT (singleton);
}
