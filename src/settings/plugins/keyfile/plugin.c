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
 * Copyright (C) 2008 - 2011 Red Hat, Inc.
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

#include "plugin.h"
#include "nm-system-config-interface.h"
#include "nm-keyfile-connection.h"
#include "writer.h"
#include "common.h"
#include "utils.h"

#define CONF_FILE SYSCONFDIR "/NetworkManager/NetworkManager.conf"
#define OLD_CONF_FILE SYSCONFDIR "/NetworkManager/nm-system-settings.conf"

static char *plugin_get_hostname (SCPluginKeyfile *plugin);
static void system_config_interface_init (NMSystemConfigInterface *system_config_interface_class);

G_DEFINE_TYPE_EXTENDED (SCPluginKeyfile, sc_plugin_keyfile, G_TYPE_OBJECT, 0,
				    G_IMPLEMENT_INTERFACE (NM_TYPE_SYSTEM_CONFIG_INTERFACE,
									  system_config_interface_init))

#define SC_PLUGIN_KEYFILE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SC_TYPE_PLUGIN_KEYFILE, SCPluginKeyfilePrivate))

typedef struct {
	GHashTable *hash;

	GFileMonitor *monitor;
	guint monitor_id;

	const char *conf_file;
	GFileMonitor *conf_file_monitor;
	guint conf_file_monitor_id;

	char *hostname;

	gboolean disposed;
} SCPluginKeyfilePrivate;

static NMSettingsConnection *
_internal_new_connection (SCPluginKeyfile *self,
                          const char *full_path,
                          NMConnection *source,
                          GError **error)
{
	SCPluginKeyfilePrivate *priv = SC_PLUGIN_KEYFILE_GET_PRIVATE (self);
	NMKeyfileConnection *connection;

	g_return_val_if_fail (full_path != NULL, NULL);

	connection = nm_keyfile_connection_new (full_path, source, error);
	if (connection) {
		g_hash_table_insert (priv->hash,
		                     (gpointer) nm_keyfile_connection_get_path (connection),
		                     connection);
	}

	return (NMSettingsConnection *) connection;
}

static void
read_connections (NMSystemConfigInterface *config)
{
	SCPluginKeyfile *self = SC_PLUGIN_KEYFILE (config);
	GDir *dir;
	GError *error = NULL;
	const char *item;

	dir = g_dir_open (KEYFILE_DIR, 0, &error);
	if (!dir) {
		PLUGIN_WARN (KEYFILE_PLUGIN_NAME, "Cannot read directory '%s': (%d) %s",
		             KEYFILE_DIR,
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
		return;
	}

	while ((item = g_dir_read_name (dir))) {
		NMSettingsConnection *connection;
		char *full_path;

		if (nm_keyfile_plugin_utils_should_ignore_file (item))
			continue;

		full_path = g_build_filename (KEYFILE_DIR, item, NULL);
		PLUGIN_PRINT (KEYFILE_PLUGIN_NAME, "parsing %s ... ", item);

		connection = _internal_new_connection (self, full_path, NULL, &error);
		if (connection) {
			PLUGIN_PRINT (KEYFILE_PLUGIN_NAME, "    read connection '%s'",
			              nm_connection_get_id (NM_CONNECTION (connection)));
		} else {
			PLUGIN_PRINT (KEYFILE_PLUGIN_NAME, "    error: %s",
				          (error && error->message) ? error->message : "(unknown)");
		}
		g_clear_error (&error);
		g_free (full_path);
	}
	g_dir_close (dir);
}

static void
update_connection_settings_commit_cb (NMSettingsConnection *orig, GError *error, gpointer user_data)
{
	if (error) {
		g_warning ("%s: '%s' / '%s' invalid: %d",
		       	   __func__,
		       	   error ? g_type_name (nm_connection_lookup_setting_type_by_quark (error->domain)) : "(none)",
		       	   (error && error->message) ? error->message : "(none)",
		       	   error ? error->code : -1);
		g_clear_error (&error);

		nm_settings_connection_signal_remove (orig);
	}
}

static void
update_connection_settings (NMKeyfileConnection *orig,
                            NMKeyfileConnection *new)
{
	nm_settings_connection_replace_and_commit (NM_SETTINGS_CONNECTION (orig),
	                                           NM_CONNECTION (new),
	                                           update_connection_settings_commit_cb, NULL);
}

/* Monitoring */

static void
remove_connection (SCPluginKeyfile *self,
                   NMKeyfileConnection *connection,
                   const char *name)
{
	g_return_if_fail (connection != NULL);
	g_return_if_fail (name != NULL);

	/* Removing from the hash table should drop the last reference */
	g_object_ref (connection);
	g_hash_table_remove (SC_PLUGIN_KEYFILE_GET_PRIVATE (self)->hash, name);
	nm_settings_connection_signal_remove (NM_SETTINGS_CONNECTION (connection));
	g_object_unref (connection);
}

static NMKeyfileConnection *
find_by_uuid (SCPluginKeyfile *self, const char *uuid)
{
	SCPluginKeyfilePrivate *priv = SC_PLUGIN_KEYFILE_GET_PRIVATE (self);
	GHashTableIter iter;
	gpointer data = NULL;

	g_return_val_if_fail (uuid != NULL, NULL);

	g_hash_table_iter_init (&iter, priv->hash);
	while (g_hash_table_iter_next (&iter, NULL, &data)) {
		NMConnection *candidate = NM_CONNECTION (data);

		if (strcmp (uuid, nm_connection_get_uuid (candidate)) == 0)
			return NM_KEYFILE_CONNECTION (candidate);
	}
	return NULL;
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
	SCPluginKeyfilePrivate *priv = SC_PLUGIN_KEYFILE_GET_PRIVATE (self);
	char *full_path;
	NMKeyfileConnection *connection;
	GError *error = NULL;

	full_path = g_file_get_path (file);
	if (nm_keyfile_plugin_utils_should_ignore_file (full_path)) {
		g_free (full_path);
		return;
	}

	connection = g_hash_table_lookup (priv->hash, full_path);

	switch (event_type) {
	case G_FILE_MONITOR_EVENT_DELETED:
		if (connection) {
			PLUGIN_PRINT (KEYFILE_PLUGIN_NAME, "removed %s.", full_path);
			remove_connection (SC_PLUGIN_KEYFILE (config), connection, full_path);
		}
		break;
	case G_FILE_MONITOR_EVENT_CREATED:
	case G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT:
		if (connection) {
			/* Update */
			NMKeyfileConnection *tmp;

			tmp = nm_keyfile_connection_new (full_path, NULL, &error);
			if (tmp) {
				if (!nm_connection_compare (NM_CONNECTION (connection),
				                            NM_CONNECTION (tmp),
				                            NM_SETTING_COMPARE_FLAG_EXACT)) {
					PLUGIN_PRINT (KEYFILE_PLUGIN_NAME, "updating %s", full_path);
					update_connection_settings (connection, tmp);
				}
				g_object_unref (tmp);
			} else {
				/* Error; remove the connection */
				PLUGIN_PRINT (KEYFILE_PLUGIN_NAME, "    error: %s",
						      (error && error->message) ? error->message : "(unknown)");
				g_clear_error (&error);
				remove_connection (SC_PLUGIN_KEYFILE (config), connection, full_path);
			}
		} else {
			PLUGIN_PRINT (KEYFILE_PLUGIN_NAME, "updating %s", full_path);

			/* New */
			connection = nm_keyfile_connection_new (full_path, NULL, &error);
			if (connection) {
				NMKeyfileConnection *found = NULL;

				/* Connection renames will show up as different files but with
				 * the same UUID.  Try to find the original connection.
				 * A connection rename is treated just like an update except
				 * there's a bit more housekeeping with the hash table.
				 */
				found = find_by_uuid (self, nm_connection_get_uuid (NM_CONNECTION (connection)));
				if (found) {
					const char *old_path = nm_keyfile_connection_get_path (connection);

					/* Removing from the hash table should drop the last reference,
					 * but of course we want to keep the connection around.
					 */
					g_object_ref (found);
					g_hash_table_remove (priv->hash, old_path);

					/* Updating settings should update the NMKeyfileConnection's
					 * filename property too.
					 */
					update_connection_settings (found, connection);

					/* Re-insert the connection back into the hash with the new filename */
					g_hash_table_insert (priv->hash,
					                     (gpointer) nm_keyfile_connection_get_path (found),
					                     found);

					/* Get rid of the temporary connection */
					g_object_unref (connection);
				} else {
					g_hash_table_insert (priv->hash,
					                     (gpointer) nm_keyfile_connection_get_path (connection),
					                     connection);
					g_signal_emit_by_name (config, NM_SYSTEM_CONFIG_INTERFACE_CONNECTION_ADDED, connection);
				}
			} else {
				PLUGIN_PRINT (KEYFILE_PLUGIN_NAME, "    error: %s",
						      (error && error->message) ? error->message : "(unknown)");
				g_clear_error (&error);
			}
		}
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

	priv->hash = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_object_unref);

	file = g_file_new_for_path (KEYFILE_DIR);
	monitor = g_file_monitor_directory (file, G_FILE_MONITOR_NONE, NULL, NULL);
	g_object_unref (file);

	if (monitor) {
		priv->monitor_id = g_signal_connect (monitor, "changed", G_CALLBACK (dir_changed), config);
		priv->monitor = monitor;
	}

	file = g_file_new_for_path (priv->conf_file);
	monitor = g_file_monitor_file (file, G_FILE_MONITOR_NONE, NULL, NULL);
	g_object_unref (file);

	if (monitor) {
		priv->conf_file_monitor_id = g_signal_connect (monitor, "changed", G_CALLBACK (conf_file_changed), config);
		priv->conf_file_monitor = monitor;
	}
}

/* Plugin */

static GSList *
get_connections (NMSystemConfigInterface *config)
{
	SCPluginKeyfilePrivate *priv = SC_PLUGIN_KEYFILE_GET_PRIVATE (config);
	GHashTableIter iter;
	gpointer data = NULL;
	GSList *list = NULL;

	if (!priv->hash) {
		setup_monitoring (config);
		read_connections (config);
	}

	g_hash_table_iter_init (&iter, priv->hash);
	while (g_hash_table_iter_next (&iter, NULL, &data))
		list = g_slist_prepend (list, data);
	return list;
}

static NMSettingsConnection *
add_connection (NMSystemConfigInterface *config,
                NMConnection *connection,
                GError **error)
{
	SCPluginKeyfile *self = SC_PLUGIN_KEYFILE (config);
	NMSettingsConnection *added = NULL;
	char *path = NULL;

	/* Write it out first, then add the connection to our internal list */
	if (nm_keyfile_plugin_write_connection (connection, NULL, &path, error)) {
		added = _internal_new_connection (self, path, connection, error);
		g_free (path);
	}
	return added;
}

static GSList *
get_unmanaged_specs (NMSystemConfigInterface *config)
{
	SCPluginKeyfilePrivate *priv = SC_PLUGIN_KEYFILE_GET_PRIVATE (config);
	GKeyFile *key_file;
	GSList *specs = NULL;
	GError *error = NULL;

	key_file = g_key_file_new ();
	if (g_key_file_load_from_file (key_file, priv->conf_file, G_KEY_FILE_NONE, &error)) {
		char *str;

		str = g_key_file_get_value (key_file, "keyfile", "unmanaged-devices", NULL);
		if (str) {
			char **udis;
			int i;

			udis = g_strsplit (str, ";", -1);
			g_free (str);

			for (i = 0; udis[i] != NULL; i++) {
				/* Verify unmanaged specification and add it to the list */
				if (strlen (udis[i]) > 4 && !strncmp (udis[i], "mac:", 4) && ether_aton (udis[i] + 4)) {
					char *p = udis[i];

					/* To accept uppercase MACs in configuration file, we have to convert values to lowercase here.
					 * Unmanaged MACs in specs are always in lowercase. */
					while (*p) {
				                *p = g_ascii_tolower (*p);
				                p++;
				        }
					specs = g_slist_append (specs, udis[i]);
				} else {
					g_warning ("Error in file '%s': invalid unmanaged-devices entry: '%s'", priv->conf_file, udis[i]);
					g_free (udis[i]);
				}
			}

			g_free (udis); /* Yes, g_free, not g_strfreev because we need the strings in the list */
		}
	} else {
		g_warning ("Error parsing file '%s': %s", priv->conf_file, error->message);
		g_error_free (error);
	}

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

	key_file = g_key_file_new ();
	if (g_key_file_load_from_file (key_file, priv->conf_file, G_KEY_FILE_NONE, &error))
		hostname = g_key_file_get_value (key_file, "keyfile", "hostname", NULL);
	else {
		g_warning ("Error parsing file '%s': %s", priv->conf_file, error->message);
		g_error_free (error);
	}

	g_key_file_free (key_file);

	return hostname;
}

static gboolean
plugin_set_hostname (SCPluginKeyfile *plugin, const char *hostname)
{
	SCPluginKeyfilePrivate *priv = SC_PLUGIN_KEYFILE_GET_PRIVATE (plugin);
	GKeyFile *key_file;
	GError *error = NULL;
	gboolean result = FALSE;

	key_file = g_key_file_new ();
	if (g_key_file_load_from_file (key_file, priv->conf_file, G_KEY_FILE_NONE, &error)) {
		char *data;
		gsize len;

		g_key_file_set_string (key_file, "keyfile", "hostname", hostname);

		data = g_key_file_to_data (key_file, &len, &error);
		if (data) {
			g_file_set_contents (priv->conf_file, data, len, &error);
			g_free (data);

			g_free (priv->hostname);
			priv->hostname = g_strdup (hostname);
			result = TRUE;
		}

		if (error) {
			g_warning ("Error saving hostname: %s", error->message);
			g_error_free (error);
		}
	} else {
		g_warning ("Error parsing file '%s': %s", priv->conf_file, error->message);
		g_error_free (error);
	}

	g_key_file_free (key_file);

	return result;
}

/* GObject */

static void
sc_plugin_keyfile_init (SCPluginKeyfile *plugin)
{
	SCPluginKeyfilePrivate *priv = SC_PLUGIN_KEYFILE_GET_PRIVATE (plugin);

	if (g_file_test (CONF_FILE, G_FILE_TEST_EXISTS))
		priv->conf_file = CONF_FILE;
	else
		priv->conf_file = OLD_CONF_FILE;

	priv->hostname = plugin_get_hostname (plugin);
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
		return;

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

	if (priv->hash)
		g_hash_table_destroy (priv->hash);

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
	system_config_interface_class->add_connection = add_connection;
	system_config_interface_class->get_unmanaged_specs = get_unmanaged_specs;
}

GObject *
nm_settings_keyfile_plugin_new (void)
{
	static SCPluginKeyfile *singleton = NULL;

	if (!singleton)
		singleton = SC_PLUGIN_KEYFILE (g_object_new (SC_TYPE_PLUGIN_KEYFILE, NULL));
	else
		g_object_ref (singleton);

	return G_OBJECT (singleton);
}
