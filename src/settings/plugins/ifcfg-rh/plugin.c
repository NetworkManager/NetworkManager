/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service
 *
 * Dan Williams <dcbw@redhat.com>
 * Søren Sandmann <sandmann@daimi.au.dk>
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
 * Copyright (C) 2007 - 2011 Red Hat, Inc.
 */

#include "nm-default.h"

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <gmodule.h>

#include "nm-setting-connection.h"

#include "common.h"
#include "plugin.h"
#include "nm-settings-plugin.h"
#include "nm-config.h"
#include "NetworkManagerUtils.h"

#include "nm-ifcfg-connection.h"
#include "shvar.h"
#include "reader.h"
#include "writer.h"
#include "utils.h"
#include "nm-dbus-compat.h"
#include "nm-exported-object.h"

#include "nmdbus-ifcfg-rh.h"

#define IFCFGRH1_DBUS_SERVICE_NAME "com.redhat.ifcfgrh1"
#define IFCFGRH1_DBUS_OBJECT_PATH "/com/redhat/ifcfgrh1"

#define _NMLOG_DOMAIN  LOGD_SETTINGS
#define _NMLOG(level, ...) \
    G_STMT_START { \
        nm_log ((level), (_NMLOG_DOMAIN), \
                "%s" _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
                "ifcfg-rh: " \
                _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
    } G_STMT_END

#define ERR_GET_MSG(err) (((err) && (err)->message) ? (err)->message : "(unknown)")


static NMIfcfgConnection *update_connection (SettingsPluginIfcfg *plugin,
                                             NMConnection *source,
                                             const char *full_path,
                                             NMIfcfgConnection *connection,
                                             gboolean protect_existing_connection,
                                             GHashTable *protected_connections,
                                             GError **error);

static void settings_plugin_interface_init (NMSettingsPluginInterface *plugin_iface);

G_DEFINE_TYPE_EXTENDED (SettingsPluginIfcfg, settings_plugin_ifcfg, G_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_SETTINGS_PLUGIN,
                                               settings_plugin_interface_init))

#define SETTINGS_PLUGIN_IFCFG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SETTINGS_TYPE_PLUGIN_IFCFG, SettingsPluginIfcfgPrivate))


typedef struct {
	NMConfig *config;

	struct {
		GDBusConnection *connection;
		GDBusInterfaceSkeleton *interface;
		GCancellable *cancellable;
		gulong signal_id;
	} dbus;

	GHashTable *connections;  /* uuid::connection */
	gboolean initialized;

	GFileMonitor *ifcfg_monitor;
	gulong ifcfg_monitor_id;
} SettingsPluginIfcfgPrivate;

static SettingsPluginIfcfg *settings_plugin_ifcfg_get (void);
NM_DEFINE_SINGLETON_GETTER (SettingsPluginIfcfg, settings_plugin_ifcfg_get, SETTINGS_TYPE_PLUGIN_IFCFG);

static void
connection_ifcfg_changed (NMIfcfgConnection *connection, gpointer user_data)
{
	SettingsPluginIfcfg *self = SETTINGS_PLUGIN_IFCFG (user_data);
	SettingsPluginIfcfgPrivate *priv = SETTINGS_PLUGIN_IFCFG_GET_PRIVATE (self);
	const char *path;

	path = nm_settings_connection_get_filename (NM_SETTINGS_CONNECTION (connection));
	g_return_if_fail (path != NULL);


	if (!priv->ifcfg_monitor) {
		_LOGD ("connection_ifcfg_changed("NM_IFCFG_CONNECTION_LOG_FMTD"): %s", NM_IFCFG_CONNECTION_LOG_ARGD (connection), "ignore event");
		return;
	}

	_LOGD ("connection_ifcfg_changed("NM_IFCFG_CONNECTION_LOG_FMTD"): %s", NM_IFCFG_CONNECTION_LOG_ARGD (connection), "reload");

	update_connection (self, NULL, path, connection, TRUE, NULL, NULL);
}

static void
connection_removed_cb (NMSettingsConnection *obj, gpointer user_data)
{
	g_hash_table_remove (SETTINGS_PLUGIN_IFCFG_GET_PRIVATE (user_data)->connections,
	                     nm_connection_get_uuid (NM_CONNECTION (obj)));
}

static void
remove_connection (SettingsPluginIfcfg *self, NMIfcfgConnection *connection)
{
	SettingsPluginIfcfgPrivate *priv = SETTINGS_PLUGIN_IFCFG_GET_PRIVATE (self);
	gboolean unmanaged, unrecognized;

	g_return_if_fail (self != NULL);
	g_return_if_fail (connection != NULL);

	_LOGI ("remove "NM_IFCFG_CONNECTION_LOG_FMT, NM_IFCFG_CONNECTION_LOG_ARG (connection));

	unmanaged = !!nm_ifcfg_connection_get_unmanaged_spec (connection);
	unrecognized = !!nm_ifcfg_connection_get_unrecognized_spec (connection);

	g_object_ref (connection);
	g_hash_table_remove (priv->connections, nm_connection_get_uuid (NM_CONNECTION (connection)));
	if (!unmanaged && !unrecognized)
		nm_settings_connection_signal_remove (NM_SETTINGS_CONNECTION (connection));
	g_object_unref (connection);

	/* Emit changes _after_ removing the connection */
	if (unmanaged)
		g_signal_emit_by_name (self, NM_SETTINGS_PLUGIN_UNMANAGED_SPECS_CHANGED);
	if (unrecognized)
		g_signal_emit_by_name (self, NM_SETTINGS_PLUGIN_UNRECOGNIZED_SPECS_CHANGED);
}

static NMIfcfgConnection *
find_by_path (SettingsPluginIfcfg *self, const char *path)
{
	SettingsPluginIfcfgPrivate *priv = SETTINGS_PLUGIN_IFCFG_GET_PRIVATE (self);
	GHashTableIter iter;
	NMSettingsConnection *candidate = NULL;

	g_return_val_if_fail (path != NULL, NULL);

	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer) &candidate)) {
		if (g_strcmp0 (path, nm_settings_connection_get_filename (candidate)) == 0)
			return NM_IFCFG_CONNECTION (candidate);
	}
	return NULL;
}

static NMIfcfgConnection *
update_connection (SettingsPluginIfcfg *self,
                   NMConnection *source,
                   const char *full_path,
                   NMIfcfgConnection *connection,
                   gboolean protect_existing_connection,
                   GHashTable *protected_connections,
                   GError **error)
{
	SettingsPluginIfcfgPrivate *priv = SETTINGS_PLUGIN_IFCFG_GET_PRIVATE (self);
	NMIfcfgConnection *connection_new;
	NMIfcfgConnection *connection_by_uuid;
	GError *local = NULL;
	const char *new_unmanaged = NULL, *old_unmanaged = NULL;
	const char *new_unrecognized = NULL, *old_unrecognized = NULL;
	gboolean unmanaged_changed = FALSE, unrecognized_changed = FALSE;
	const char *uuid;
	gboolean ignore_error = FALSE;

	g_return_val_if_fail (!source || NM_IS_CONNECTION (source), NULL);
	g_return_val_if_fail (full_path || source, NULL);

	if (full_path)
		_LOGD ("loading from file \"%s\"...", full_path);

	/* Create a NMIfcfgConnection instance, either by reading from @full_path or
	 * based on @source. */
	connection_new = nm_ifcfg_connection_new (source, full_path, &local, &ignore_error);
	if (!connection_new) {
		/* Unexpected failure. Probably the file is invalid? */
		if (   connection
		    && !protect_existing_connection
		    && (!protected_connections || !g_hash_table_contains (protected_connections, connection)))
			remove_connection (self, connection);
		if (!source) {
			_NMLOG (ignore_error ? LOGL_DEBUG : LOGL_WARN,
			        "loading \"%s\" fails: %s", full_path, local ? local->message : "(unknown reason)");
		}
		g_propagate_error (error, local);
		return NULL;
	}

	uuid = nm_connection_get_uuid (NM_CONNECTION (connection_new));
	connection_by_uuid = g_hash_table_lookup (priv->connections, uuid);

	if (   connection
	    && connection != connection_by_uuid) {

		if (   (protect_existing_connection && connection_by_uuid != NULL)
		    || (protected_connections && g_hash_table_contains (protected_connections, connection))) {
			NMIfcfgConnection *conflicting = (protect_existing_connection && connection_by_uuid != NULL) ? connection_by_uuid : connection;

			if (source)
				_LOGW ("cannot update protected connection "NM_IFCFG_CONNECTION_LOG_FMT" due to conflicting UUID %s", NM_IFCFG_CONNECTION_LOG_ARG (conflicting), uuid);
			else
				_LOGW ("cannot load %s due to conflicting UUID for "NM_IFCFG_CONNECTION_LOG_FMT, full_path, NM_IFCFG_CONNECTION_LOG_ARG (conflicting));
			g_object_unref (connection_new);
			g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
			                     "Cannot update protected connection due to conflicting UUID");
			return NULL;
		}

		/* The new connection has a different UUID then the original one that we
		 * are about to update. Remove @connection. */
		remove_connection (self, connection);
	}

	/* Check if the found connection with the same UUID is not protected from updating. */
	if (   connection_by_uuid
	    && (   (!connection && protect_existing_connection)
	        || (protected_connections && g_hash_table_contains (protected_connections, connection_by_uuid)))) {
		if (source)
			_LOGW ("cannot update connection due to conflicting UUID for "NM_IFCFG_CONNECTION_LOG_FMT, NM_IFCFG_CONNECTION_LOG_ARG (connection_by_uuid));
		else
			_LOGW ("cannot load %s due to conflicting UUID for "NM_IFCFG_CONNECTION_LOG_FMT, full_path, NM_IFCFG_CONNECTION_LOG_ARG (connection_by_uuid));
		g_object_unref (connection_new);
		g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		                      "Skip updating protected connection during reload");
		return NULL;
	}

	/* Evaluate unmanaged/unrecognized flags. */
	if (connection_by_uuid)
		old_unmanaged = nm_ifcfg_connection_get_unmanaged_spec (connection_by_uuid);
	new_unmanaged = nm_ifcfg_connection_get_unmanaged_spec (connection_new);
	unmanaged_changed = g_strcmp0 (old_unmanaged, new_unmanaged);

	if (connection_by_uuid)
		old_unrecognized = nm_ifcfg_connection_get_unrecognized_spec (connection_by_uuid);
	new_unrecognized = nm_ifcfg_connection_get_unrecognized_spec (connection_new);
	unrecognized_changed = g_strcmp0 (old_unrecognized, new_unrecognized);

	if (connection_by_uuid) {
		const char *old_path;

		old_path = nm_settings_connection_get_filename (NM_SETTINGS_CONNECTION (connection_by_uuid));

		if (   !unmanaged_changed
		    && !unrecognized_changed
		    && nm_connection_compare (NM_CONNECTION (connection_by_uuid),
		                              NM_CONNECTION (connection_new),
		                              NM_SETTING_COMPARE_FLAG_IGNORE_AGENT_OWNED_SECRETS |
		                              NM_SETTING_COMPARE_FLAG_IGNORE_NOT_SAVED_SECRETS)) {
			if (old_path && g_strcmp0 (old_path, full_path) != 0)
				_LOGI ("rename \"%s\" to "NM_IFCFG_CONNECTION_LOG_FMT" without other changes", nm_settings_connection_get_filename (NM_SETTINGS_CONNECTION (connection_by_uuid)), NM_IFCFG_CONNECTION_LOG_ARG (connection_new));
		} else {

			/*******************************************************
			 * UPDATE
			 *******************************************************/

			if (source)
				_LOGI ("update "NM_IFCFG_CONNECTION_LOG_FMT" from %s", NM_IFCFG_CONNECTION_LOG_ARG (connection_new), NM_IFCFG_CONNECTION_LOG_PATH (old_path));
			else if (!g_strcmp0 (old_path, nm_settings_connection_get_filename (NM_SETTINGS_CONNECTION (connection_new))))
				_LOGI ("update "NM_IFCFG_CONNECTION_LOG_FMT, NM_IFCFG_CONNECTION_LOG_ARG (connection_new));
			else if (old_path)
				_LOGI ("rename \"%s\" to "NM_IFCFG_CONNECTION_LOG_FMT, old_path, NM_IFCFG_CONNECTION_LOG_ARG (connection_new));
			else
				_LOGI ("update and persist "NM_IFCFG_CONNECTION_LOG_FMT, NM_IFCFG_CONNECTION_LOG_ARG (connection_new));

			g_object_set (connection_by_uuid,
			              NM_IFCFG_CONNECTION_UNMANAGED_SPEC, new_unmanaged,
			              NM_IFCFG_CONNECTION_UNRECOGNIZED_SPEC, new_unrecognized,
			              NULL);

			if (!nm_settings_connection_replace_settings (NM_SETTINGS_CONNECTION (connection_by_uuid),
			                                              NM_CONNECTION (connection_new),
			                                              FALSE,  /* don't set Unsaved */
			                                              "ifcfg-update",
			                                              &local)) {
				/* Shouldn't ever get here as 'connection_new' was verified by the reader already
				 * and the UUID did not change. */
				g_assert_not_reached ();
			}
			g_assert_no_error (local);

			if (new_unmanaged || new_unrecognized) {
				if (!old_unmanaged && !old_unrecognized) {
					g_object_ref (connection_by_uuid);
					/* Unexport the connection by telling the settings service it's
					 * been removed.
					 */
					nm_settings_connection_signal_remove (NM_SETTINGS_CONNECTION (connection_by_uuid));
					/* Remove the path so that claim_connection() doesn't complain later when
					 * interface gets managed and connection is re-added. */
					nm_connection_set_path (NM_CONNECTION (connection_by_uuid), NULL);

					/* signal_remove() will end up removing the connection from our hash,
					 * so add it back now.
					 */
					g_hash_table_insert (priv->connections,
					                     g_strdup (nm_connection_get_uuid (NM_CONNECTION (connection_by_uuid))),
					                     connection_by_uuid);
				}
			} else {
				if (old_unmanaged /* && !new_unmanaged */) {
					_LOGI ("Managing connection "NM_IFCFG_CONNECTION_LOG_FMT" and its device because NM_CONTROLLED was true.",
					       NM_IFCFG_CONNECTION_LOG_ARG (connection_new));
					g_signal_emit_by_name (self, NM_SETTINGS_PLUGIN_CONNECTION_ADDED, connection_by_uuid);
				} else if (old_unrecognized /* && !new_unrecognized */) {
					_LOGI ("Managing connection "NM_IFCFG_CONNECTION_LOG_FMT" because it is now a recognized type.",
					       NM_IFCFG_CONNECTION_LOG_ARG (connection_new));
					g_signal_emit_by_name (self, NM_SETTINGS_PLUGIN_CONNECTION_ADDED, connection_by_uuid);
				}
			}

			if (unmanaged_changed)
				g_signal_emit_by_name (self, NM_SETTINGS_PLUGIN_UNMANAGED_SPECS_CHANGED);
			if (unrecognized_changed)
				g_signal_emit_by_name (self, NM_SETTINGS_PLUGIN_UNRECOGNIZED_SPECS_CHANGED);
		}
		nm_settings_connection_set_filename (NM_SETTINGS_CONNECTION (connection_by_uuid), full_path);
		g_object_unref (connection_new);
		return connection_by_uuid;
	} else {

		/*******************************************************
		 * ADD
		 *******************************************************/

		if (source)
			_LOGI ("add connection "NM_IFCFG_CONNECTION_LOG_FMT, NM_IFCFG_CONNECTION_LOG_ARG (connection_new));
		else
			_LOGI ("new connection "NM_IFCFG_CONNECTION_LOG_FMT, NM_IFCFG_CONNECTION_LOG_ARG (connection_new));
		g_hash_table_insert (priv->connections, g_strdup (uuid), connection_new);

		g_signal_connect (connection_new, NM_SETTINGS_CONNECTION_REMOVED,
		                  G_CALLBACK (connection_removed_cb),
		                  self);

		if (nm_ifcfg_connection_get_unmanaged_spec (connection_new)) {
			const char *spec;
			const char *device_id;

			spec = nm_ifcfg_connection_get_unmanaged_spec (connection_new);
			device_id = strchr (spec, ':');
			if (device_id)
				device_id++;
			else
				device_id = spec;
			_LOGW ("Ignoring connection "NM_IFCFG_CONNECTION_LOG_FMT" / device '%s' due to NM_CONTROLLED=no.",
			       NM_IFCFG_CONNECTION_LOG_ARG (connection_new), device_id);
		} else if (nm_ifcfg_connection_get_unrecognized_spec (connection_new))
			_LOGW ("Ignoring connection "NM_IFCFG_CONNECTION_LOG_FMT" of unrecognized type.", NM_IFCFG_CONNECTION_LOG_ARG (connection_new));

		/* watch changes of ifcfg hardlinks */
		g_signal_connect (G_OBJECT (connection_new), "ifcfg-changed",
		                  G_CALLBACK (connection_ifcfg_changed), self);

		if (!source) {
			/* Only raise the signal if we were called without source, i.e. if we read the connection from file.
			 * Otherwise, we were called by add_connection() which does not expect the signal. */
			if (nm_ifcfg_connection_get_unmanaged_spec (connection_new))
				g_signal_emit_by_name (self, NM_SETTINGS_PLUGIN_UNMANAGED_SPECS_CHANGED);
			else if (nm_ifcfg_connection_get_unrecognized_spec (connection_new))
				g_signal_emit_by_name (self, NM_SETTINGS_PLUGIN_UNRECOGNIZED_SPECS_CHANGED);
			else
				g_signal_emit_by_name (self, NM_SETTINGS_PLUGIN_CONNECTION_ADDED, connection_new);
		}
		return connection_new;
	}
}

static void
ifcfg_dir_changed (GFileMonitor *monitor,
                   GFile *file,
                   GFile *other_file,
                   GFileMonitorEvent event_type,
                   gpointer user_data)
{
	SettingsPluginIfcfg *plugin = SETTINGS_PLUGIN_IFCFG (user_data);
	char *path, *ifcfg_path;
	NMIfcfgConnection *connection;

	path = g_file_get_path (file);

	ifcfg_path = utils_detect_ifcfg_path (path, FALSE);
	_LOGD ("ifcfg_dir_changed(%s) = %d // %s", path, event_type, ifcfg_path ? ifcfg_path : "(none)");
	if (ifcfg_path) {
		connection = find_by_path (plugin, ifcfg_path);
		switch (event_type) {
		case G_FILE_MONITOR_EVENT_DELETED:
			if (connection)
				remove_connection (plugin, connection);
			break;
		case G_FILE_MONITOR_EVENT_CREATED:
		case G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT:
			/* Update or new */
			update_connection (plugin, NULL, ifcfg_path, connection, TRUE, NULL, NULL);
			break;
		default:
			break;
		}
		g_free (ifcfg_path);
	}
	g_free (path);
}

static void
setup_ifcfg_monitoring (SettingsPluginIfcfg *plugin)
{
	SettingsPluginIfcfgPrivate *priv = SETTINGS_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	GFile *file;
	GFileMonitor *monitor;

	file = g_file_new_for_path (IFCFG_DIR "/");
	monitor = g_file_monitor_directory (file, G_FILE_MONITOR_NONE, NULL, NULL);
	g_object_unref (file);

	if (monitor) {
		priv->ifcfg_monitor_id = g_signal_connect (monitor, "changed",
		                                           G_CALLBACK (ifcfg_dir_changed), plugin);
		priv->ifcfg_monitor = monitor;
	}
}

static GHashTable *
_paths_from_connections (GHashTable *connections)
{
	GHashTableIter iter;
	NMIfcfgConnection *connection;
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
read_connections (SettingsPluginIfcfg *plugin)
{
	SettingsPluginIfcfgPrivate *priv = SETTINGS_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	GDir *dir;
	GError *err = NULL;
	const char *item;
	GHashTable *alive_connections;
	GHashTableIter iter;
	NMIfcfgConnection *connection;
	GPtrArray *dead_connections = NULL;
	guint i;
	GPtrArray *filenames;
	GHashTable *paths;

	dir = g_dir_open (IFCFG_DIR, 0, &err);
	if (!dir) {
		_LOGW ("Could not read directory '%s': %s", IFCFG_DIR, err->message);
		g_error_free (err);
		return;
	}

	alive_connections = g_hash_table_new (NULL, NULL);

	filenames = g_ptr_array_new_with_free_func (g_free);
	while ((item = g_dir_read_name (dir))) {
		char *full_path, *real_path;

		full_path = g_build_filename (IFCFG_DIR, item, NULL);
		real_path = utils_detect_ifcfg_path (full_path, TRUE);

		if (real_path)
			g_ptr_array_add (filenames, real_path);
		g_free (full_path);
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
		connection = update_connection (plugin, NULL, filenames->pdata[i], NULL, FALSE, alive_connections, NULL);
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
			remove_connection (plugin, dead_connections->pdata[i]);
		g_ptr_array_free (dead_connections, TRUE);
	}
}

static GSList *
get_connections (NMSettingsPlugin *config)
{
	SettingsPluginIfcfg *plugin = SETTINGS_PLUGIN_IFCFG (config);
	SettingsPluginIfcfgPrivate *priv = SETTINGS_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	GSList *list = NULL;
	GHashTableIter iter;
	NMIfcfgConnection *connection;

	if (!priv->initialized) {
		if (nm_config_get_monitor_connection_files (nm_config_get ()))
			setup_ifcfg_monitoring (plugin);
		read_connections (plugin);
		priv->initialized = TRUE;
	}

	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer) &connection)) {
		if (   !nm_ifcfg_connection_get_unmanaged_spec (connection)
		    && !nm_ifcfg_connection_get_unrecognized_spec (connection))
			list = g_slist_prepend (list, connection);
	}

	return list;
}

static gboolean
load_connection (NMSettingsPlugin *config,
                 const char *filename)
{
	SettingsPluginIfcfg *plugin = SETTINGS_PLUGIN_IFCFG (config);
	NMIfcfgConnection *connection;
	int dir_len = strlen (IFCFG_DIR);
	char *ifcfg_path;

	if (   strncmp (filename, IFCFG_DIR, dir_len) != 0
	    || filename[dir_len] != '/'
	    || strchr (filename + dir_len + 1, '/') != NULL)
		return FALSE;

	/* get the real ifcfg-path. This allows us to properly
	 * handle load command using a route-* file etc. */
	ifcfg_path = utils_detect_ifcfg_path (filename, FALSE);
	if (!ifcfg_path)
		return FALSE;

	connection = find_by_path (plugin, ifcfg_path);
	update_connection (plugin, NULL, ifcfg_path, connection, TRUE, NULL, NULL);
	if (!connection)
		connection = find_by_path (plugin, ifcfg_path);

	g_free (ifcfg_path);
	return (connection != NULL);
}

static void
reload_connections (NMSettingsPlugin *config)
{
	SettingsPluginIfcfg *plugin = SETTINGS_PLUGIN_IFCFG (config);

	read_connections (plugin);
}

static GSList *
get_unhandled_specs (NMSettingsPlugin *config,
                     const char *property)
{
	SettingsPluginIfcfgPrivate *priv = SETTINGS_PLUGIN_IFCFG_GET_PRIVATE (config);
	GSList *list = NULL, *list_iter;
	GHashTableIter iter;
	gpointer connection;
	char *spec;
	gboolean found;

	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, NULL, &connection)) {
		g_object_get (connection, property, &spec, NULL);
		if (spec) {
			/* Ignore duplicates */
			for (list_iter = list, found = FALSE; list_iter; list_iter = g_slist_next (list_iter)) {
				if (g_str_equal (list_iter->data, spec)) {
					found = TRUE;
					break;
				}
			}
			if (found)
				g_free (spec);
			else
				list = g_slist_prepend (list, spec);
		}
	}
	return list;
}

static GSList *
get_unmanaged_specs (NMSettingsPlugin *config)
{
	return get_unhandled_specs (config, NM_IFCFG_CONNECTION_UNMANAGED_SPEC);
}

static GSList *
get_unrecognized_specs (NMSettingsPlugin *config)
{
	return get_unhandled_specs (config, NM_IFCFG_CONNECTION_UNRECOGNIZED_SPEC);
}

static NMSettingsConnection *
add_connection (NMSettingsPlugin *config,
                NMConnection *connection,
                gboolean save_to_disk,
                GError **error)
{
	SettingsPluginIfcfg *self = SETTINGS_PLUGIN_IFCFG (config);
	gs_free char *path = NULL;

	/* Ensure we reject attempts to add the connection long before we're
	 * asked to write it to disk.
	 */
	if (!writer_can_write_connection (connection, error))
		return NULL;

	if (save_to_disk) {
		if (!writer_new_connection (connection, IFCFG_DIR, &path, error))
			return NULL;
	}
	return NM_SETTINGS_CONNECTION (update_connection (self, connection, path, NULL, FALSE, NULL, error));
}

static void
impl_ifcfgrh_get_ifcfg_details (SettingsPluginIfcfg *plugin,
                                GDBusMethodInvocation *context,
                                const char *in_ifcfg)
{
	NMIfcfgConnection *connection;
	NMSettingConnection *s_con;
	const char *uuid;
	const char *path;
	gs_free char *ifcfg_path = NULL;

	if (!g_path_is_absolute (in_ifcfg)) {
		g_dbus_method_invocation_return_error (context,
		                                       NM_SETTINGS_ERROR,
		                                       NM_SETTINGS_ERROR_INVALID_CONNECTION,
		                                       "ifcfg path '%s' is not absolute", in_ifcfg);
		return;
	}

	ifcfg_path = utils_detect_ifcfg_path (in_ifcfg, TRUE);
	if (!ifcfg_path) {
		g_dbus_method_invocation_return_error (context,
		                                       NM_SETTINGS_ERROR,
		                                       NM_SETTINGS_ERROR_INVALID_CONNECTION,
		                                       "ifcfg path '%s' is not an ifcfg base file", in_ifcfg);
		return;
	}

	connection = find_by_path (plugin, ifcfg_path);
	if (   !connection
	    || nm_ifcfg_connection_get_unmanaged_spec (connection)
	    || nm_ifcfg_connection_get_unrecognized_spec (connection)) {
		g_dbus_method_invocation_return_error (context,
		                                       NM_SETTINGS_ERROR,
		                                       NM_SETTINGS_ERROR_INVALID_CONNECTION,
		                                       "ifcfg file '%s' unknown", in_ifcfg);
		return;
	}

	s_con = nm_connection_get_setting_connection (NM_CONNECTION (connection));
	if (!s_con) {
		g_dbus_method_invocation_return_error (context,
		                                       NM_SETTINGS_ERROR,
		                                       NM_SETTINGS_ERROR_FAILED,
		                                       "unable to retrieve the connection setting");
		return;
	}

	uuid = nm_setting_connection_get_uuid (s_con);
	if (!uuid) {
		g_dbus_method_invocation_return_error (context,
		                                       NM_SETTINGS_ERROR,
		                                       NM_SETTINGS_ERROR_FAILED,
		                                       "unable to get the UUID");
		return;
	}

	path = nm_connection_get_path (NM_CONNECTION (connection));
	if (!path) {
		g_dbus_method_invocation_return_error (context,
		                                       NM_SETTINGS_ERROR,
		                                       NM_SETTINGS_ERROR_FAILED,
		                                       "unable to get the connection D-Bus path");
		return;
	}

	g_dbus_method_invocation_return_value (context,
	                                       g_variant_new ("(so)", uuid, path));
}

/*****************************************************************************/

static void
_dbus_clear (SettingsPluginIfcfg *self)
{
	SettingsPluginIfcfgPrivate *priv = SETTINGS_PLUGIN_IFCFG_GET_PRIVATE (self);

	nm_clear_g_signal_handler (priv->dbus.connection, &priv->dbus.signal_id);

	nm_clear_g_cancellable (&priv->dbus.cancellable);

	if (priv->dbus.interface) {
		g_dbus_interface_skeleton_unexport (priv->dbus.interface);
		nm_exported_object_skeleton_release (priv->dbus.interface);
		priv->dbus.interface = NULL;
	}

	g_clear_object (&priv->dbus.connection);
}

static void
_dbus_connection_closed (GDBusConnection *connection,
                         gboolean         remote_peer_vanished,
                         GError          *error,
                         gpointer         user_data)
{
	_LOGW ("dbus: %s bus closed", IFCFGRH1_DBUS_SERVICE_NAME);
	_dbus_clear (SETTINGS_PLUGIN_IFCFG (user_data));

	/* Retry or recover? */
}

static void
_dbus_request_name_done (GObject *source_object,
                         GAsyncResult *res,
                         gpointer user_data)
{
	GDBusConnection *connection = G_DBUS_CONNECTION (source_object);
	SettingsPluginIfcfg *self;
	SettingsPluginIfcfgPrivate *priv;
	gs_free_error GError *error = NULL;
	gs_unref_variant GVariant *ret = NULL;
	guint32 result;

	ret = g_dbus_connection_call_finish (connection, res, &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = SETTINGS_PLUGIN_IFCFG (user_data);
	priv = SETTINGS_PLUGIN_IFCFG_GET_PRIVATE (self);

	g_clear_object (&priv->dbus.cancellable);

	if (!ret) {
		_LOGW ("dbus: couldn't acquire D-Bus service: %s", error->message);
		_dbus_clear (self);
		return;
	}

	g_variant_get (ret, "(u)", &result);

	if (result != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
		_LOGW ("dbus: couldn't acquire ifcfgrh1 D-Bus service (already taken)");
		_dbus_clear (self);
		return;
	}

	{
		GType skeleton_type = NMDBUS_TYPE_IFCFGRH1_SKELETON;
		gs_free char *method_name_get_ifcfg_details = NULL;
		NMExportedObjectDBusMethodImpl methods[] = {
			{
				.method_name = (method_name_get_ifcfg_details = nm_exported_object_skeletonify_method_name ("GetIfcfgDetails")),
				.impl = G_CALLBACK (impl_ifcfgrh_get_ifcfg_details),
			},
		};

		priv->dbus.interface = nm_exported_object_skeleton_create (skeleton_type,
		                                                           g_type_class_peek (SETTINGS_TYPE_PLUGIN_IFCFG),
		                                                           methods,
		                                                           G_N_ELEMENTS (methods),
		                                                           (GObject *) self);

		if (!g_dbus_interface_skeleton_export (priv->dbus.interface,
		                                       priv->dbus.connection,
		                                       IFCFGRH1_DBUS_OBJECT_PATH,
		                                       &error)) {
			nm_exported_object_skeleton_release (priv->dbus.interface);
			priv->dbus.interface = NULL;
			_LOGW ("dbus: failed exporting interface: %s", error->message);
			_dbus_clear (self);
			return;
		}
	}

	_LOGD ("dbus: aquired D-Bus service %s and exported %s object",
	       IFCFGRH1_DBUS_SERVICE_NAME,
	       IFCFGRH1_DBUS_OBJECT_PATH);
}

static void
_dbus_create_done (GObject *source_object,
                   GAsyncResult *res,
                   gpointer user_data)
{
	SettingsPluginIfcfg *self;
	SettingsPluginIfcfgPrivate *priv;
	gs_free_error GError *error = NULL;
	GDBusConnection *connection;

	connection = g_dbus_connection_new_for_address_finish (res, &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = SETTINGS_PLUGIN_IFCFG (user_data);
	priv = SETTINGS_PLUGIN_IFCFG_GET_PRIVATE (self);

	g_clear_object (&priv->dbus.cancellable);

	if (!connection) {
		_LOGW ("dbus: couldn't initialize system bus: %s", error->message);
		return;
	}

	priv->dbus.connection = connection;
	priv->dbus.cancellable = g_cancellable_new ();

	priv->dbus.signal_id = g_signal_connect (priv->dbus.connection,
	                                         "closed",
	                                         G_CALLBACK (_dbus_connection_closed),
	                                         self);

	g_dbus_connection_call (priv->dbus.connection,
	                        DBUS_SERVICE_DBUS,
	                        DBUS_PATH_DBUS,
	                        DBUS_INTERFACE_DBUS,
	                        "RequestName",
	                        g_variant_new ("(su)",
	                                       IFCFGRH1_DBUS_SERVICE_NAME,
	                                       DBUS_NAME_FLAG_DO_NOT_QUEUE),
	                        G_VARIANT_TYPE ("(u)"),
	                        G_DBUS_CALL_FLAGS_NONE,
	                        -1,
	                        priv->dbus.cancellable,
	                        _dbus_request_name_done,
	                        self);
}

static void
_dbus_setup (SettingsPluginIfcfg *self)
{
	SettingsPluginIfcfgPrivate *priv = SETTINGS_PLUGIN_IFCFG_GET_PRIVATE (self);
	gs_free char *address = NULL;
	gs_free_error GError *error = NULL;

	g_return_if_fail (!priv->dbus.connection);

	address = g_dbus_address_get_for_bus_sync (G_BUS_TYPE_SYSTEM, NULL, &error);
	if (address == NULL) {
		_LOGW ("dbus: failed getting address for system bus: %s", error->message);
		return;
	}

	priv->dbus.cancellable = g_cancellable_new ();

	g_dbus_connection_new_for_address (address,
	                                   G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT
	                                   | G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION,
	                                   NULL,
	                                   priv->dbus.cancellable,
	                                   _dbus_create_done,
	                                   self);
}

static void
config_changed_cb (NMConfig *config,
                   NMConfigData *config_data,
                   NMConfigChangeFlags changes,
                   NMConfigData *old_data,
                   SettingsPluginIfcfg *self)
{
	/* If the dbus connection for some reason is borked the D-Bus service
	 * won't be offered.
	 *
	 * On SIGHUP and SIGUSR1 try to re-connect to D-Bus. So in the unlikely
	 * event that the D-Bus conneciton is broken, that allows for recovery
	 * without need for restarting NetworkManager. */
	if (   NM_FLAGS_HAS (changes, NM_CONFIG_CHANGE_SIGHUP)
	    || NM_FLAGS_HAS (changes, NM_CONFIG_CHANGE_SIGUSR1)) {
		if (!SETTINGS_PLUGIN_IFCFG_GET_PRIVATE (self)->dbus.connection)
			_dbus_setup (self);
	}
}

/*****************************************************************************/

static void
init (NMSettingsPlugin *config)
{
}

static void
settings_plugin_ifcfg_init (SettingsPluginIfcfg *plugin)
{
	SettingsPluginIfcfgPrivate *priv = SETTINGS_PLUGIN_IFCFG_GET_PRIVATE (plugin);

	priv->connections = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_object_unref);
}

static void
constructed (GObject *object)
{
	SettingsPluginIfcfg *self = SETTINGS_PLUGIN_IFCFG (object);
	SettingsPluginIfcfgPrivate *priv = SETTINGS_PLUGIN_IFCFG_GET_PRIVATE (self);

	G_OBJECT_CLASS (settings_plugin_ifcfg_parent_class)->constructed (object);

	priv->config = nm_config_get ();
	g_object_add_weak_pointer ((GObject *) priv->config, (gpointer *) &priv->config);
	g_signal_connect (priv->config,
	                  NM_CONFIG_SIGNAL_CONFIG_CHANGED,
	                  G_CALLBACK (config_changed_cb),
	                  self);

	_dbus_setup (self);
}

static void
dispose (GObject *object)
{
	SettingsPluginIfcfg *self = SETTINGS_PLUGIN_IFCFG (object);
	SettingsPluginIfcfgPrivate *priv = SETTINGS_PLUGIN_IFCFG_GET_PRIVATE (self);

	if (priv->config) {
		g_object_remove_weak_pointer ((GObject *) priv->config, (gpointer *) &priv->config);
		g_signal_handlers_disconnect_by_func (priv->config, config_changed_cb, self);
		priv->config = NULL;
	}

	_dbus_clear (self);

	if (priv->connections) {
		g_hash_table_destroy (priv->connections);
		priv->connections = NULL;
	}

	if (priv->ifcfg_monitor) {
		if (priv->ifcfg_monitor_id)
			g_signal_handler_disconnect (priv->ifcfg_monitor, priv->ifcfg_monitor_id);

		g_file_monitor_cancel (priv->ifcfg_monitor);
		g_object_unref (priv->ifcfg_monitor);
	}

	G_OBJECT_CLASS (settings_plugin_ifcfg_parent_class)->dispose (object);
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case NM_SETTINGS_PLUGIN_PROP_NAME:
		g_value_set_string (value, IFCFG_PLUGIN_NAME);
		break;
	case NM_SETTINGS_PLUGIN_PROP_INFO:
		g_value_set_string (value, IFCFG_PLUGIN_INFO);
		break;
	case NM_SETTINGS_PLUGIN_PROP_CAPABILITIES:
		g_value_set_uint (value, NM_SETTINGS_PLUGIN_CAP_MODIFY_CONNECTIONS);
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
settings_plugin_ifcfg_class_init (SettingsPluginIfcfgClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	g_type_class_add_private (req_class, sizeof (SettingsPluginIfcfgPrivate));

	object_class->constructed = constructed;
	object_class->dispose = dispose;
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	g_object_class_override_property (object_class,
	                                  NM_SETTINGS_PLUGIN_PROP_NAME,
	                                  NM_SETTINGS_PLUGIN_NAME);

	g_object_class_override_property (object_class,
	                                  NM_SETTINGS_PLUGIN_PROP_INFO,
	                                  NM_SETTINGS_PLUGIN_INFO);

	g_object_class_override_property (object_class,
	                                  NM_SETTINGS_PLUGIN_PROP_CAPABILITIES,
	                                  NM_SETTINGS_PLUGIN_CAPABILITIES);
}

static void
settings_plugin_interface_init (NMSettingsPluginInterface *plugin_iface)
{
	/* interface implementation */
	plugin_iface->get_connections = get_connections;
	plugin_iface->add_connection = add_connection;
	plugin_iface->load_connection = load_connection;
	plugin_iface->reload_connections = reload_connections;
	plugin_iface->get_unmanaged_specs = get_unmanaged_specs;
	plugin_iface->get_unrecognized_specs = get_unrecognized_specs;
	plugin_iface->init = init;
}

G_MODULE_EXPORT GObject *
nm_settings_plugin_factory (void)
{
	return g_object_ref (settings_plugin_ifcfg_get ());
}
