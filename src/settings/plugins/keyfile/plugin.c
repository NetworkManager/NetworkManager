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

#include <config.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/ether.h>
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

#include "plugin.h"
#include "nm-system-config-interface.h"
#include "nm-keyfile-connection.h"
#include "writer.h"
#include "common.h"
#include "utils.h"

static char *plugin_get_hostname (SCPluginKeyfile *plugin);
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

	const char *conf_file;
	GFileMonitor *conf_file_monitor;
	guint conf_file_monitor_id;

	char *hostname;

	gboolean disposed;
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

	nm_log_info (LOGD_SETTINGS, "removed %s.", nm_keyfile_connection_get_path (connection));

	/* Removing from the hash table should drop the last reference */
	g_object_ref (connection);
	g_signal_handlers_disconnect_by_func (connection, connection_removed_cb, self);
	removed = g_hash_table_remove (SC_PLUGIN_KEYFILE_GET_PRIVATE (self)->connections,
	                               nm_connection_get_uuid (NM_CONNECTION (connection)));
	nm_settings_connection_signal_remove (NM_SETTINGS_CONNECTION (connection));
	g_object_unref (connection);

	g_return_if_fail (removed);
}

static void
update_connection (SCPluginKeyfile *self,
                   NMKeyfileConnection *connection,
                   const char *name)
{
	NMKeyfileConnection *tmp;
	GError *error = NULL;

	tmp = nm_keyfile_connection_new (NULL, name, &error);
	if (!tmp) {
		/* Error; remove the connection */
		nm_log_warn (LOGD_SETTINGS, "    error in connection %s: %s", name,
		             (error && error->message) ? error->message : "(unknown)");
		g_clear_error (&error);
		remove_connection (self, connection);
		return;
	}

	if (!nm_connection_compare (NM_CONNECTION (connection),
	                            NM_CONNECTION (tmp),
	                            NM_SETTING_COMPARE_FLAG_IGNORE_AGENT_OWNED_SECRETS |
		                          NM_SETTING_COMPARE_FLAG_IGNORE_NOT_SAVED_SECRETS)) {
		nm_log_info (LOGD_SETTINGS, "updating %s", name);
		if (!nm_settings_connection_replace_settings (NM_SETTINGS_CONNECTION (connection),
		                                              NM_CONNECTION (tmp),
		                                              FALSE,  /* don't set Unsaved */
		                                              &error)) {
			/* Shouldn't ever get here as 'new' was verified by the reader already */
			g_assert_no_error (error);
		}
	}
	g_object_unref (tmp);
}

static NMKeyfileConnection *
find_by_path (SCPluginKeyfile *self, const char *path)
{
	SCPluginKeyfilePrivate *priv = SC_PLUGIN_KEYFILE_GET_PRIVATE (self);
	GHashTableIter iter;
	NMKeyfileConnection *candidate = NULL;

	g_return_val_if_fail (path != NULL, NULL);

	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer) &candidate)) {
		if (g_strcmp0 (path, nm_keyfile_connection_get_path (candidate)) == 0)
			return candidate;
	}
	return NULL;
}

static void
new_connection (SCPluginKeyfile *self,
                const char *name,
                char **out_old_path)
{
	SCPluginKeyfilePrivate *priv = SC_PLUGIN_KEYFILE_GET_PRIVATE (self);
	NMKeyfileConnection *tmp, *connection;
	GError *error = NULL;
	const char *uuid;

	if (out_old_path)
		*out_old_path = NULL;

	tmp = nm_keyfile_connection_new (NULL, name, &error);
	if (!tmp) {
		nm_log_warn (LOGD_SETTINGS, "    error in connection %s: %s", name,
		             (error && error->message) ? error->message : "(unknown)");
		g_clear_error (&error);
		return;
	}

	/* Connection renames will show as different paths but same UUID */
	uuid = nm_connection_get_uuid (NM_CONNECTION (tmp));
	connection = g_hash_table_lookup (priv->connections, uuid);
	if (connection) {
		nm_log_info (LOGD_SETTINGS, "rename %s -> %s", nm_keyfile_connection_get_path (connection), name);
		if (!nm_settings_connection_replace_settings (NM_SETTINGS_CONNECTION (connection),
		                                              NM_CONNECTION (tmp),
		                                              FALSE,  /* don't set Unsaved */
		                                              &error)) {
			/* Shouldn't ever get here as 'tmp' was verified by the reader already */
			g_assert_no_error (error);
		}
		g_object_unref (tmp);
		if (out_old_path)
			*out_old_path = g_strdup (nm_keyfile_connection_get_path (connection));
		nm_keyfile_connection_set_path (connection, name);
	} else {
		nm_log_info (LOGD_SETTINGS, "new connection %s", name);
		g_hash_table_insert (priv->connections, g_strdup (uuid), tmp);
		g_signal_emit_by_name (self, NM_SYSTEM_CONFIG_INTERFACE_CONNECTION_ADDED, tmp);

		g_signal_connect (tmp, NM_SETTINGS_CONNECTION_REMOVED,
		                  G_CALLBACK (connection_removed_cb),
		                  self);
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

	full_path = g_file_get_path (file);
	if (nm_keyfile_plugin_utils_should_ignore_file (full_path)) {
		g_free (full_path);
		return;
	}

	connection = find_by_path (self, full_path);

	switch (event_type) {
	case G_FILE_MONITOR_EVENT_DELETED:
		if (connection)
			remove_connection (SC_PLUGIN_KEYFILE (config), connection);
		break;
	case G_FILE_MONITOR_EVENT_CREATED:
	case G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT:
		if (connection)
			update_connection (SC_PLUGIN_KEYFILE (config), connection, full_path);
		else
			new_connection (SC_PLUGIN_KEYFILE (config), full_path, NULL);
		break;
	default:
		break;
	}

	g_free (full_path);
}

static void
conf_file_changed (GFileMonitor *monitor,
				   GFile *file,
				   GFile *other_file,
				   GFileMonitorEvent event_type,
				   gpointer data)
{
	SCPluginKeyfile *self = SC_PLUGIN_KEYFILE (data);
	SCPluginKeyfilePrivate *priv = SC_PLUGIN_KEYFILE_GET_PRIVATE (self);
	char *tmp;

	switch (event_type) {
	case G_FILE_MONITOR_EVENT_DELETED:
	case G_FILE_MONITOR_EVENT_CREATED:
	case G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT:
		g_signal_emit_by_name (self, NM_SYSTEM_CONFIG_INTERFACE_UNMANAGED_SPECS_CHANGED);

		/* hostname */
		tmp = plugin_get_hostname (self);
		if ((tmp && !priv->hostname)
			|| (!tmp && priv->hostname)
			|| (priv->hostname && tmp && strcmp (priv->hostname, tmp))) {

			g_free (priv->hostname);
			priv->hostname = tmp;
			tmp = NULL;
			g_object_notify (G_OBJECT (self), NM_SYSTEM_CONFIG_INTERFACE_HOSTNAME);
		}

		g_free (tmp);

		break;
	default:
		break;
	}
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

	if (priv->conf_file) {
		file = g_file_new_for_path (priv->conf_file);
		monitor = g_file_monitor_file (file, G_FILE_MONITOR_NONE, NULL, NULL);
		g_object_unref (file);

		if (monitor) {
			priv->conf_file_monitor_id = g_signal_connect (monitor, "changed", G_CALLBACK (conf_file_changed), config);
			priv->conf_file_monitor = monitor;
		}
	}
}

static void
read_connections (NMSystemConfigInterface *config)
{
	SCPluginKeyfile *self = SC_PLUGIN_KEYFILE (config);
	SCPluginKeyfilePrivate *priv = SC_PLUGIN_KEYFILE_GET_PRIVATE (self);
	GDir *dir;
	GError *error = NULL;
	const char *item;
	GHashTable *oldconns;
	GHashTableIter iter;
	gpointer data;

	dir = g_dir_open (KEYFILE_DIR, 0, &error);
	if (!dir) {
		nm_log_warn (LOGD_SETTINGS, "Cannot read directory '%s': (%d) %s",
		             KEYFILE_DIR,
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
		return;
	}

	oldconns = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, NULL, &data)) {
		const char *con_path = nm_keyfile_connection_get_path (data);
		if (con_path)
			g_hash_table_insert (oldconns, g_strdup (con_path), data);
	}

	while ((item = g_dir_read_name (dir))) {
		NMKeyfileConnection *connection;
		char *full_path, *old_path;

		if (nm_keyfile_plugin_utils_should_ignore_file (item))
			continue;

		full_path = g_build_filename (KEYFILE_DIR, item, NULL);

		connection = g_hash_table_lookup (oldconns, full_path);
		if (connection) {
			g_hash_table_remove (oldconns, full_path);
			update_connection (self, connection, full_path);
		} else {
			new_connection (self, full_path, &old_path);
			if (old_path) {
				g_hash_table_remove (oldconns, old_path);
				g_free (old_path);
			}
		}

		g_free (full_path);
	}
	g_dir_close (dir);

	g_hash_table_iter_init (&iter, oldconns);
	while (g_hash_table_iter_next (&iter, NULL, &data)) {
		g_hash_table_iter_remove (&iter);
		remove_connection (self, data);
	}
	g_hash_table_destroy (oldconns);
}

/* Plugin */

static GSList *
get_connections (NMSystemConfigInterface *config)
{
	SCPluginKeyfilePrivate *priv = SC_PLUGIN_KEYFILE_GET_PRIVATE (config);
	GHashTableIter iter;
	gpointer data = NULL;
	GSList *list = NULL;

	if (!priv->initialized) {
		setup_monitoring (config);
		read_connections (config);
		priv->initialized = TRUE;
	}

	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, NULL, &data))
		list = g_slist_prepend (list, data);
	return list;
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

	connection = find_by_path (self, filename);
	if (connection)
		update_connection (self, connection, filename);
	else {
		new_connection (self, filename, NULL);
		connection = find_by_path (self, filename);
	}

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
	SCPluginKeyfilePrivate *priv = SC_PLUGIN_KEYFILE_GET_PRIVATE (self);
	NMSettingsConnection *added = NULL;
	char *path = NULL;

	if (save_to_disk) {
		if (!nm_keyfile_plugin_write_connection (connection, NULL, &path, error))
			return NULL;
	}

	added = (NMSettingsConnection *) nm_keyfile_connection_new (connection, path, error);
	if (added) {
		g_hash_table_insert (priv->connections,
		                     g_strdup (nm_connection_get_uuid (NM_CONNECTION (added))),
		                     added);
		g_signal_connect (added, NM_SETTINGS_CONNECTION_REMOVED,
		                  G_CALLBACK (connection_removed_cb),
		                  self);
	}
	g_free (path);
	return added;
}

static gboolean
parse_key_file_allow_none (SCPluginKeyfilePrivate  *priv,
                           GKeyFile                *key_file,
                           GError                 **error)
{
	gboolean ret = FALSE;
	GError *local_error = NULL;

	if (!g_key_file_load_from_file (key_file, priv->conf_file, G_KEY_FILE_NONE, &local_error)) {
		if (g_error_matches (local_error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
			g_clear_error (&local_error);
		else {
			g_propagate_prefixed_error (error, local_error,
			                            "Error parsing file '%s': ",
			                            priv->conf_file);
			goto out;
		}
	}
	ret = TRUE;

 out:
	return ret;
}

static GSList *
get_unmanaged_specs (NMSystemConfigInterface *config)
{
	SCPluginKeyfilePrivate *priv = SC_PLUGIN_KEYFILE_GET_PRIVATE (config);
	GKeyFile *key_file;
	GSList *specs = NULL;
	GError *error = NULL;
	char *str;

	if (!priv->conf_file)
		return NULL;

	key_file = g_key_file_new ();
	if (!parse_key_file_allow_none (priv, key_file, &error))
		goto out;

	str = g_key_file_get_value (key_file, "keyfile", "unmanaged-devices", NULL);
	if (str) {
		char **udis;
		int i;

		udis = g_strsplit (str, ";", -1);
		g_free (str);

		for (i = 0; udis[i] != NULL; i++) {
			/* Verify unmanaged specification and add it to the list */
			if (!strncmp (udis[i], "mac:", 4) && nm_utils_hwaddr_valid (udis[i] + 4)) {
				specs = g_slist_append (specs, udis[i]);
			} else if (!strncmp (udis[i], "interface-name:", 15) && nm_utils_iface_valid_name (udis[i] + 15)) {
				specs = g_slist_append (specs, udis[i]);
			} else {
				nm_log_warn (LOGD_SETTINGS, "Error in file '%s': invalid unmanaged-devices entry: '%s'", priv->conf_file, udis[i]);
				g_free (udis[i]);
			}
		}

		g_free (udis); /* Yes, g_free, not g_strfreev because we need the strings in the list */
	}

 out:
	if (error) {
		nm_log_warn (LOGD_SETTINGS, "%s", error->message);
		g_error_free (error);
	}
	if (key_file)
		g_key_file_free (key_file);

	return specs;
}

static char *
plugin_get_hostname (SCPluginKeyfile *plugin)
{
	SCPluginKeyfilePrivate *priv = SC_PLUGIN_KEYFILE_GET_PRIVATE (plugin);
	GKeyFile *key_file;
	char *hostname = NULL;
	GError *error = NULL;

	if (!priv->conf_file)
		return NULL;

	key_file = g_key_file_new ();
	if (!parse_key_file_allow_none (priv, key_file, &error))
		goto out;

	hostname = g_key_file_get_value (key_file, "keyfile", "hostname", NULL);

 out:
	if (error) {
		nm_log_warn (LOGD_SETTINGS, "%s", error->message);
		g_error_free (error);
	}
	if (key_file)
		g_key_file_free (key_file);

	return hostname;
}

static gboolean
plugin_set_hostname (SCPluginKeyfile *plugin, const char *hostname)
{
	gboolean ret = FALSE;
	SCPluginKeyfilePrivate *priv = SC_PLUGIN_KEYFILE_GET_PRIVATE (plugin);
	GKeyFile *key_file = NULL;
	GError *error = NULL;
	char *data = NULL;
	gsize len;

	if (!priv->conf_file) {
		g_set_error (&error, G_IO_ERROR, G_IO_ERROR_FAILED,
		             "Error saving hostname: no config file");
		goto out;
	}

	g_free (priv->hostname);
	priv->hostname = g_strdup (hostname);

	key_file = g_key_file_new ();
	if (!parse_key_file_allow_none (priv, key_file, &error))
		goto out;

	g_key_file_set_string (key_file, "keyfile", "hostname", hostname);

	data = g_key_file_to_data (key_file, &len, &error);
	if (!data)
		goto out;

	if (!g_file_set_contents (priv->conf_file, data, len, &error)) {
		g_prefix_error (&error, "Error saving hostname: ");
		goto out;
	}

	ret = TRUE;

 out:
	if (error) {
		nm_log_warn (LOGD_SETTINGS, "%s", error->message);
		g_error_free (error);
	}
	g_free (data);
	if (key_file)
		g_key_file_free (key_file);

	return ret;
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
		g_value_set_uint (value, NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_CONNECTIONS | 
						  NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_HOSTNAME);
		break;
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_HOSTNAME:
		g_value_set_string (value, SC_PLUGIN_KEYFILE_GET_PRIVATE (object)->hostname);
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
	const char *hostname;

	switch (prop_id) {
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_HOSTNAME:
		hostname = g_value_get_string (value);
		if (hostname && strlen (hostname) < 1)
			hostname = NULL;
		plugin_set_hostname (SC_PLUGIN_KEYFILE (object), hostname);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
dispose (GObject *object)
{
	SCPluginKeyfilePrivate *priv = SC_PLUGIN_KEYFILE_GET_PRIVATE (object);

	if (priv->disposed)
		goto out;

	priv->disposed = TRUE;

	if (priv->monitor) {
		if (priv->monitor_id)
			g_signal_handler_disconnect (priv->monitor, priv->monitor_id);

		g_file_monitor_cancel (priv->monitor);
		g_object_unref (priv->monitor);
	}

	if (priv->conf_file_monitor) {
		if (priv->conf_file_monitor_id)
			g_signal_handler_disconnect (priv->conf_file_monitor, priv->conf_file_monitor_id);

		g_file_monitor_cancel (priv->conf_file_monitor);
		g_object_unref (priv->conf_file_monitor);
	}

	g_free (priv->hostname);

	if (priv->connections) {
		g_hash_table_destroy (priv->connections);
		priv->connections = NULL;
	}

out:
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

	g_object_class_override_property (object_class,
	                                  NM_SYSTEM_CONFIG_INTERFACE_PROP_HOSTNAME,
	                                  NM_SYSTEM_CONFIG_INTERFACE_HOSTNAME);
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

	if (!singleton) {
		singleton = SC_PLUGIN_KEYFILE (g_object_new (SC_TYPE_PLUGIN_KEYFILE, NULL));
		priv = SC_PLUGIN_KEYFILE_GET_PRIVATE (singleton);

		priv->conf_file = nm_config_get_path (nm_config_get ());

		/* plugin_set_hostname() has to be called *after* priv->conf_file is set */
		priv->hostname = plugin_get_hostname (singleton);
	} else
		g_object_ref (singleton);

	return G_OBJECT (singleton);
}
