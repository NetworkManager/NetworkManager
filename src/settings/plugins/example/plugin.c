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
 * Copyright (C) 2012 Red Hat, Inc.
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
#include "common.h"
#include "nm-example-connection.h"

static char *plugin_get_hostname (SCPluginExample *plugin);
static void system_config_interface_init (NMSystemConfigInterface *system_config_interface_class);

/* GObject object definition.  This actually defines the object and tells
 * GObject about the interfaces this object provides.  Here we provide
 * the "system config interface" which is the API that NetworkManager uses
 * to communicate with this plugin.
 *
 * Interface and super/sub-class access with GObject works via casting and
 * GObject magically figures out what needs to be called.  So, given:
 *
 *    SCPluginExample *plugin = <new plugin>;
 *
 * you can call GObject methods since SCPluginExample inherits from GObject
 * via the G_TYPE_OBJECT argument of G_DEFINE_TYPE_EXTENDED below:
 *
 *    g_object_set_data (G_OBJECT (plugin), ...);
 *
 * and since SCPluginExample implements NMSystemConfigInterface via the
 * G_IMPLEMENT_INTERFACE bit below, we can also call any methods of
 * NMSystemConfigInterface (defined in NM sources in nm-system-config-interface.c):
 *
 *    connections = nm_system_config_interface_get_connections (NM_SYSTEM_CONFIG_INTERFACE (plugin));
 *
 * For the call to nm_system_config_interface_get_connections() that eventually
 * ends up in the get_connections() method in this file because the
 * system_config_interface_init() function sets up the vtable for this objects
 * implementation of NMSystemConfigInterface.
 */
G_DEFINE_TYPE_EXTENDED (SCPluginExample, sc_plugin_example, G_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_SYSTEM_CONFIG_INTERFACE, system_config_interface_init))

/* Quick define to access the object's private data pointer; this pointer
 * points to the object's instance data.
 */
#define SC_PLUGIN_EXAMPLE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SC_TYPE_PLUGIN_EXAMPLE, SCPluginExamplePrivate))

/* Instance data.  When the object is created, a new structure of this type
 * will be created and zeroed for this instance of the object to use.  This
 * is actually done by g_type_class_add_private() when called from the object's
 * class init function.
 */
typedef struct {
	/* This hash holds each connection known to this plugin */
	GHashTable *connections;

	/* A watch for changes on the directory that holds the configuration files
	 * so the plugin can respond to configuration changes on-the-fly and
	 * tell NM that the connection data has changed.  Typically the plugin
	 * needs to monitor the directory itself (to watch for completely new files)
	 * while the individual connections watch their individual config files.
	 */
	GFileMonitor *monitor;
	guint monitor_id;

	/* Tracks changes to the global NM config file, just in case our
	 * plugin has some specific options (like unmanaged devices) that
	 * might be changed at runtime.
	 */
	const char *conf_file;
	GFileMonitor *conf_file_monitor;
	guint conf_file_monitor_id;

	/* Persistent hostname if the plugin supports hostnames.  Normally used
	 * for distro plugins; ie Red Hat uses /etc/sysconfig/hostname while
	 * Debian uses /etc/hostname.  Plugins can abstract the storage location
	 * and just tell NM what the persisten hostname is and when its backing
	 * file has changed.  NM handles actually setting the hostname.
	 */
	char *hostname;
} SCPluginExamplePrivate;

static NMSettingsConnection *
_internal_new_connection (SCPluginExample *self,
                          const char *full_path,
                          NMConnection *source,
                          GError **error)
{
	SCPluginExamplePrivate *priv = SC_PLUGIN_EXAMPLE_GET_PRIVATE (self);
	NMExampleConnection *connection;

	g_return_val_if_fail (full_path != NULL, NULL);

	/* 'source' will usually be NULL if we're going to read the connection
	 * off disk.  But if the new connection is coming from NetworkManager
	 * (ie, from a D-Bus AddConnection request) then we'll have 'source' too.
	 * This function expects the connection to already be written to disk
	 * so that the NMExampleConnection object can re-read it and intialize
	 * state in the same manner as when getting a change notification from
	 * the config directory.  That simplifies things somewhat.
	 */

	connection = nm_example_connection_new (full_path, source, error);
	if (connection) {
		g_hash_table_insert (priv->connections,
		                     g_strdup (nm_example_connection_get_path (connection)),
		                     connection);
	}

	return (NMSettingsConnection *) connection;
}

/* Read each file in our config directory and try to create a new
 * NMExamplePlugin for it.
 */
static void
read_connections (NMSystemConfigInterface *config)
{
	SCPluginExample *self = SC_PLUGIN_EXAMPLE (config);
	GDir *dir;
	GError *error = NULL;
	const char *item;

	dir = g_dir_open (EXAMPLE_DIR, 0, &error);
	if (!dir) {
		nm_log_warn (LOGD_SETTINGS, "Cannot read directory '%s': (%d) %s",
		             EXAMPLE_DIR,
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
		return;
	}

	while ((item = g_dir_read_name (dir))) {
		NMSettingsConnection *connection;
		char *full_path;

		/* XXX: Check file extension and ignore "~", ".tmp", ".bak", etc */

		full_path = g_build_filename (EXAMPLE_DIR, item, NULL);
		nm_log_info (LOGD_SETTINGS, "parsing %s ... ", item);

		connection = _internal_new_connection (self, full_path, NULL, &error);
		if (connection) {
			nm_log_info (LOGD_SETTINGS, "    read connection '%s'",
			             nm_connection_get_id (NM_CONNECTION (connection)));
		} else {
			nm_log_info (LOGD_SETTINGS, "    error: %s",
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
	/* If there was an error updating the connection's internal stuff, then
	 * we can't do anything except log it and remove the connection.  This might
	 * happen due to invalid data, but as the data would already have been
	 * verified before it ever got to this plugin, we shouldn't ever get
	 * an error here.
	 */
	if (error) {
		nm_log_warn (LOGD_SETTINGS, "%s: '%s' / '%s' invalid: %d",
		             __func__,
		             error ? g_type_name (nm_connection_lookup_setting_type_by_quark (error->domain)) : "(none)",
		             (error && error->message) ? error->message : "(none)",
		             error ? error->code : -1);
		g_clear_error (&error);

		nm_settings_connection_signal_remove (orig);
	}
}

static void
update_connection_settings (NMExampleConnection *orig,
                            NMExampleConnection *new)
{
	/* This just replaces the orig's internal settings with those from new */
	nm_settings_connection_replace_and_commit (NM_SETTINGS_CONNECTION (orig),
	                                           NM_CONNECTION (new),
	                                           update_connection_settings_commit_cb, NULL);
}

/* Monitoring */

static void
remove_connection (SCPluginExample *self,
                   NMExampleConnection *connection,
                   const char *name)
{
	g_return_if_fail (connection != NULL);
	g_return_if_fail (name != NULL);

	/* Removing from the hash table should drop the last reference, but since
	 * we need the object to stay alive across the signal emission to NM,
	 * we grab a temporary reference.
	 */
	g_object_ref (connection);
	g_hash_table_remove (SC_PLUGIN_EXAMPLE_GET_PRIVATE (self)->connections, name);

	/* Tell NM the connection is gone */
	nm_settings_connection_signal_remove (NM_SETTINGS_CONNECTION (connection));

	/* Remove the temporary reference; connection will now be destroyed */
	g_object_unref (connection);
}

/* Look through all connections we know about and return one with a given UUID */
static NMExampleConnection *
find_by_uuid (SCPluginExample *self, const char *uuid)
{
	SCPluginExamplePrivate *priv = SC_PLUGIN_EXAMPLE_GET_PRIVATE (self);
	GHashTableIter iter;
	gpointer data = NULL;

	g_return_val_if_fail (uuid != NULL, NULL);

	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, NULL, &data)) {
		NMConnection *candidate = NM_CONNECTION (data);

		if (strcmp (uuid, nm_connection_get_uuid (candidate)) == 0)
			return NM_EXAMPLE_CONNECTION (candidate);
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
	SCPluginExample *self = SC_PLUGIN_EXAMPLE (config);
	SCPluginExamplePrivate *priv = SC_PLUGIN_EXAMPLE_GET_PRIVATE (self);
	char *full_path;
	NMExampleConnection *connection;
	GError *error = NULL;

	full_path = g_file_get_path (file);
	/* XXX: Check here if you need to ignore this file, ie by checking for
	 * extensions like "~" and ".bak" or ".tmp".  If so just return;
	 */

	/* Check if we know about this connection already */
	connection = g_hash_table_lookup (priv->connections, full_path);

	switch (event_type) {
	case G_FILE_MONITOR_EVENT_DELETED:
		if (connection) {
			nm_log_info (LOGD_SETTINGS, "removed %s.", full_path);
			remove_connection (SC_PLUGIN_EXAMPLE (config), connection, full_path);
		}
		break;
	case G_FILE_MONITOR_EVENT_CREATED:
	case G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT:
		if (connection) {
			/* Update of an existing connection.  Here we re-read the file and
			 * compare it against the existing connection to check if anything
			 * actually changed.
			 */
			NMExampleConnection *tmp;

			tmp = nm_example_connection_new (full_path, NULL, &error);
			if (tmp) {
				if (!nm_connection_compare (NM_CONNECTION (connection),
				                            NM_CONNECTION (tmp),
				                            NM_SETTING_COMPARE_FLAG_IGNORE_AGENT_OWNED_SECRETS |
				                              NM_SETTING_COMPARE_FLAG_IGNORE_NOT_SAVED_SECRETS)) {
					/* Connection changed; update our internal connection object */
					nm_log_info (LOGD_SETTINGS, "updating %s", full_path);
					update_connection_settings (connection, tmp);
				}
				g_object_unref (tmp);
			} else {
				/* There was an error parsing the updated connection; it may
				 * no longer be valid and thus we've got to delete it.  If it
				 * becomes valid again later we'll get another change
				 * notification, we'll re-read it, and we'll treat it as new.
				 */
				nm_log_info (LOGD_SETTINGS, "    error: %s",
				             (error && error->message) ? error->message : "(unknown)");
				remove_connection (SC_PLUGIN_EXAMPLE (config), connection, full_path);
			}
			g_clear_error (&error);
		} else {
			nm_log_info (LOGD_SETTINGS, "updating %s", full_path);

			/* We don't know about the connection yet, so the change represents
			 * a completely new connection.
			 */
			connection = nm_example_connection_new (full_path, NULL, &error);
			if (connection) {
				NMExampleConnection *found = NULL;

				/* Connection renames will show up as different files but with
				 * the same UUID.  Try to find the original connection.
				 * A connection rename is treated just like an update except
				 * there's a bit more housekeeping with the hash table.
				 */
				found = find_by_uuid (self, nm_connection_get_uuid (NM_CONNECTION (connection)));
				if (found) {
					const char *old_path = nm_example_connection_get_path (connection);

					/* Removing from the hash table should drop the last reference,
					 * but of course we want to keep the connection around.
					 */
					g_object_ref (found);
					g_hash_table_remove (priv->connections, old_path);

					/* Updating settings should update the NMExampleConnection's
					 * filename property too.
					 */
					update_connection_settings (found, connection);

					/* Re-insert the connection back into the hash with the new filename */
					g_hash_table_insert (priv->connections,
					                     g_strdup (nm_example_connection_get_path (found)),
					                     found);

					/* Get rid of the temporary connection */
					g_object_unref (connection);
				} else {
					/* Completely new connection, not a rename. */
					g_hash_table_insert (priv->connections,
					                     g_strdup (nm_example_connection_get_path (connection)),
					                     connection);
					/* Tell NM we found a new connection */
					g_signal_emit_by_name (config, NM_SYSTEM_CONFIG_INTERFACE_CONNECTION_ADDED, connection);
				}
			} else {
				nm_log_info (LOGD_SETTINGS, "    error: %s", (error && error->message) ? error->message : "(unknown)");
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
	SCPluginExample *self = SC_PLUGIN_EXAMPLE (data);
	SCPluginExamplePrivate *priv = SC_PLUGIN_EXAMPLE_GET_PRIVATE (self);
	char *tmp;

	switch (event_type) {
	case G_FILE_MONITOR_EVENT_DELETED:
	case G_FILE_MONITOR_EVENT_CREATED:
	case G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT:
		/* Unmanaged devices option may have changed; just emit the changed
		 * signal for unmanaged specs and when NM calls back in to get the
		 * updated specs we'll re-read the config file then.
		 */
		g_signal_emit_by_name (self, NM_SYSTEM_CONFIG_INTERFACE_UNMANAGED_SPECS_CHANGED);

		/* Hostname may also have changed; read it and if it did actually
		 * change, notify NM.
		 */
		tmp = plugin_get_hostname (self);
		if (g_strcmp0 (tmp, priv->hostname) != 0) {
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

/* This function starts the inotify monitors that watch the plugin's config
 * file directory for new connections and changes to existing connections
 * (if not disabled by NetworkManager.conf), and for changes to the plugin's
 * non-connection config files.
 */
static void
setup_monitoring (NMSystemConfigInterface *config)
{
	SCPluginExamplePrivate *priv = SC_PLUGIN_EXAMPLE_GET_PRIVATE (config);
	GFileMonitor *monitor;
	GFile *file;

	/* Initialize connection hash here; we use the connection hash as the 
	 * "are we initialized yet" variable.
	 */
	priv->connections = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_object_unref);

	if (nm_config_get_monitor_connection_files (nm_config_get ())) {
		/* Set up the watch for our config directory */
		file = g_file_new_for_path (EXAMPLE_DIR);
		monitor = g_file_monitor_directory (file, G_FILE_MONITOR_NONE, NULL, NULL);
		g_object_unref (file);
		if (monitor) {
			/* This registers the dir_changed() function to be called whenever
			 * the GFileMonitor object notices a change in the directory.
			 */
			priv->monitor_id = g_signal_connect (monitor, "changed", G_CALLBACK (dir_changed), config);
			priv->monitor = monitor;
		}
	}

	/* Set up a watch on our configuration file, basically just for watching
	 * whether the user has changed the unmanaged devices option or the
	 * persistent hostname.
	 */
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

/*******************************************************************/

/* Return to NM the full list of connections this plugin owns */
static GSList *
get_connections (NMSystemConfigInterface *config)
{
	SCPluginExamplePrivate *priv = SC_PLUGIN_EXAMPLE_GET_PRIVATE (config);
	GHashTableIter iter;
	NMSettingsConnection *connection;
	GSList *list = NULL;

	if (!priv->connections) {
		/* If we haven't read connections in yet, do so now */
		setup_monitoring (config);
		read_connections (config);
	}

	/* Add each connection from our internal hash table to a list returned
	 * to NetworkManager.
	 */
	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer) &connection))
		list = g_slist_prepend (list, connection);
	return list;
}

/* Called by NetworkManager when a user adds a new connection via D-Bus.
 * The plugin should convert the data in 'connection' to its on-disk format
 * write it out to disk, and return an object that's a subclass of
 * NMSettingsConnection.  Typically plugins will subclass NMSettingsConnection
 * and use that class to handle any plugin-specific stuff like monitoring
 * the on-disk config files for changes, and/or parsing the file-format and
 * converting back and forth from that to NMConnection.
 */
static NMSettingsConnection *
add_connection (NMSystemConfigInterface *config,
                NMConnection *connection,
                gboolean save_to_disk,
                GError **error)
{
	SCPluginExample *self = SC_PLUGIN_EXAMPLE (config);
	NMSettingsConnection *added = NULL;
	char *path = NULL;

	/* Write it out first, then add the connection to our internal list; that
	 * way we don't trigger the new NMSettingsConnection subclass' file watch
	 * functions needlessly.
	 */
	if (save_to_disk && !write_connection (connection, NULL, &path, error))
		return NULL;

	added = _internal_new_connection (self, path, connection, error);
	g_free (path);
	return added;
}

/* This function returns a list of "unmanaged device specs" which represent
 * a list of devices that NetworkManager should not manage.  Each unmanaged
 * spec item has a specific format starting with a "tag" and followed by
 * tag-specific data.  The only currently specified items are "mac:" followed
 * by the MAC address of the interface NM should not manage, or "interface-name:"
 * followed by the name of the interface NM should not manage.  This function
 * reads the list of unmanaged devices from wherever the plugin wants to
 * store them and returns that list to NetworkManager.
 */
static GSList *
get_unmanaged_specs (NMSystemConfigInterface *config)
{
	SCPluginExamplePrivate *priv = SC_PLUGIN_EXAMPLE_GET_PRIVATE (config);
	GKeyFile *key_file;
	GSList *specs = NULL;
	GError *error = NULL;
	char *str, **ids;
	int i;

	if (!priv->conf_file)
		return NULL;

	key_file = g_key_file_new ();
	if (!g_key_file_load_from_file (key_file, priv->conf_file, G_KEY_FILE_NONE, &error)) {
		nm_log_warn (LOGD_SETTINGS, "Error parsing file '%s': %s", priv->conf_file, error->message);
		g_error_free (error);
		goto out;
	}


	str = g_key_file_get_value (key_file, "keyfile", "unmanaged-devices", NULL);
	if (!str)
		goto out;

	ids = g_strsplit (str, ";", -1);
	for (i = 0; ids[i] != NULL; i++) {
		/* Verify unmanaged specification and add it to the list */
		if (!strncmp (ids[i], "mac:", 4) && nm_utils_hwaddr_valid (ids[i] + 4)) {
			specs = g_slist_append (specs, ids[i]);
		} else if (!strncmp (ids[i], "interface-name:", 15) && nm_utils_iface_valid_name (ids[i] + 15)) {
			specs = g_slist_append (specs, ids[i]);
		} else {
			nm_log_warn (LOGD_SETTINGS, "Error in file '%s': invalid unmanaged-devices entry: '%s'", priv->conf_file, ids[i]);
			g_free (ids[i]);
		}
	}

	g_free (ids); /* Yes, g_free, not g_strfreev because we need the strings in the list */
	g_free (str);

out:
	g_key_file_free (key_file);
	return specs;
}


static char *
plugin_get_hostname (SCPluginExample *plugin)
{
	SCPluginExamplePrivate *priv = SC_PLUGIN_EXAMPLE_GET_PRIVATE (plugin);
	GKeyFile *key_file;
	char *hostname = NULL;
	GError *error = NULL;

	if (!priv->conf_file)
		return NULL;

	/* Read the persistent hostname out of backing storage, which happens
	 * to be the NM config file.  Other plugins (like distro-specific ones)
	 * should read it from the distro-specific location like /etc/hostname.
	 */
	key_file = g_key_file_new ();
	if (g_key_file_load_from_file (key_file, priv->conf_file, G_KEY_FILE_NONE, &error))
		hostname = g_key_file_get_value (key_file, "keyfile", "hostname", NULL);
	else {
		nm_log_warn (LOGD_SETTINGS, "Error parsing file '%s': %s", priv->conf_file, error->message);
		g_error_free (error);
	}

	g_key_file_free (key_file);
	return hostname;
}

static gboolean
plugin_set_hostname (SCPluginExample *plugin, const char *hostname)
{
	SCPluginExamplePrivate *priv = SC_PLUGIN_EXAMPLE_GET_PRIVATE (plugin);
	GKeyFile *key_file;
	GError *error = NULL;
	gboolean success = FALSE;
	char *data;
	gsize len;

	if (!priv->conf_file) {
		nm_log_warn (LOGD_SETTINGS, "Error saving hostname: no config file");
		return FALSE;
	}

	/* This just saves the hostname to the NM config file in a section
	 * private to this plugin.
	 */
	key_file = g_key_file_new ();
	if (!g_key_file_load_from_file (key_file, priv->conf_file, G_KEY_FILE_NONE, &error)) {
		nm_log_warn (LOGD_SETTINGS, "Error parsing file '%s': %s", priv->conf_file, error->message);
		g_error_free (error);
		goto out;
	}

	g_key_file_set_string (key_file, "example", "hostname", hostname);

	data = g_key_file_to_data (key_file, &len, &error);
	if (data) {
		/* Save updated file to disk */
		g_file_set_contents (priv->conf_file, data, len, &error);
		g_free (data);

		/* Update internal copy of hostname */
		g_free (priv->hostname);
		priv->hostname = g_strdup (hostname);
		success = TRUE;
	}

	if (error) {
		nm_log_warn (LOGD_SETTINGS, "Error saving hostname: %s", error->message);
		g_error_free (error);
	}

out:
	g_key_file_free (key_file);
	return success;
}

/* GObject */

static void
sc_plugin_example_init (SCPluginExample *plugin)
{
	/* Here we'd do any instance-specific initialization like setting
	 * members of SCPluginExamplePrivate to default values.  But we
	 * don't have anything to do here since most initialization is done
	 * when NM calls the various entry points.
	 */
}

static void
get_property (GObject *object, guint prop_id,
		    GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_NAME:
		g_value_set_string (value, EXAMPLE_PLUGIN_NAME);
		break;
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_INFO:
		g_value_set_string (value, EXAMPLE_PLUGIN_INFO);
		break;
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_CAPABILITIES:
		/* Return capabilities to NM; this plugin supports changing connections
		 * as well as being capable of saving the hostname to persistent storage.
		 * If the plugin can't write out updated configuration, then obviously
		 * it shouldn't advertise that capability.  If it can't save hostnames
		 * to persistent storage, it shouldn't advertise that capability either.
		 */
		g_value_set_uint (value, NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_CONNECTIONS | 
						  NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_HOSTNAME);
		break;
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_HOSTNAME:
		/* Return the hostname we've read from persistent storage */
		g_value_set_string (value, SC_PLUGIN_EXAMPLE_GET_PRIVATE (object)->hostname);
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
		/* We'll get here when the user has changed the hostname via NM's
		 * D-Bus interface and we're requested to save this hostname to
		 * persistent storage.
		 */
		hostname = g_value_get_string (value);
		if (hostname && strlen (hostname) < 1)
			hostname = NULL;
		plugin_set_hostname (SC_PLUGIN_EXAMPLE (object), hostname);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
dispose (GObject *object)
{
	SCPluginExamplePrivate *priv = SC_PLUGIN_EXAMPLE_GET_PRIVATE (object);

	/* GObject has a two-stage object destruction process: dispose and finalize.
	 * In dispose the object should free any references it might have on other
	 * objects to break circular refs, then it's finally cleaned up by finalize.
	 * We don't bother to implement a finalize, so we just make sure that we
	 * clean everything up (including clearing pointers) in dispose so that
	 * if GObject decides to revive this object post-dispose (yes, legal)
	 * we don't crash on dangling pointers.
	 */

	if (priv->monitor) {
		if (priv->monitor_id) {
			g_signal_handler_disconnect (priv->monitor, priv->monitor_id);
			priv->monitor_id = 0;
		}

		g_file_monitor_cancel (priv->monitor);
		g_object_unref (priv->monitor);
		priv->monitor = NULL;
	}

	if (priv->conf_file_monitor) {
		if (priv->conf_file_monitor_id) {
			g_signal_handler_disconnect (priv->conf_file_monitor, priv->conf_file_monitor_id);
			priv->conf_file_monitor_id = 0;
		}

		g_file_monitor_cancel (priv->conf_file_monitor);
		g_object_unref (priv->conf_file_monitor);
		priv->conf_file_monitor = NULL;
	}

	if (priv->connections) {
		/* Destroying the connections hash unrefs each connection in it
		 * due to the GHashTable value_destroy_func that we passed into
		 * g_hash_table_new_full().
		 */
		g_hash_table_destroy (priv->connections);
		priv->connections = NULL;
	}

	g_free (priv->hostname);
	priv->hostname = NULL;

	/* Chain up to the superclass */
	G_OBJECT_CLASS (sc_plugin_example_parent_class)->dispose (object);
}

/* This function gets called to set up any method and property overrides
 * of superclasses, and also (if we actually had any) to set up any
 * custom properties and signals this object might have.  This is called before
 * the object is actually instantiated; it just sets up the generic class
 * stuff, not anything related to a specific object instance.
 */
static void
sc_plugin_example_class_init (SCPluginExampleClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	/* This actually creates and zeros the object's instance data struct */
	g_type_class_add_private (req_class, sizeof (SCPluginExamplePrivate));

	/* Override GObject base class methods with our custom implementations */
	object_class->dispose = dispose;
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	/* Override various GObject properties that we need to change.  Here we
	 * just tell GObject that we will be handling the get/set operations for
	 * these specific properties.  They are actually defined by the
	 * NMSystemConfigInterface interface in nm-system-config-interface.c.
	 * What happens here is that we tell GObject that for a given property
	 * name (ie NM_SYSTEM_CONFIG_INTERFACE_NAME) we'll be using the enum value
	 * NM_SYSTEM_CONFIG_INTERFACE_PROP_NAME locally in get_property() and
	 * set_property().
	 */
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
system_config_interface_init (NMSystemConfigInterface *sci_intf)
{
	/* Interface implementation for NMSystemConfigInterface.  This sets
	 * up the GInterface vtable that lets GObject know what functions to
	 * call for each method of the NMSystemConfigInterface interface.
	 */
	sci_intf->get_connections = get_connections;
	sci_intf->add_connection = add_connection;
	sci_intf->get_unmanaged_specs = get_unmanaged_specs;
}

/*******************************************************************/

/* Factory function: this is the first entry point for NetworkManager, which
 * gets called during NM startup to create the instance of this plugin
 * that NetworkManager will actually use.  Since every plugin is a singleton
 * we just return a singleton instance.  This function should never be called
 * twice.
 */
G_MODULE_EXPORT GObject *
nm_system_config_factory (void)
{
	static SCPluginExample *singleton = NULL;
	SCPluginExamplePrivate *priv;

	if (!singleton) {
		/* Instantiate our plugin */
		singleton = SC_PLUGIN_EXAMPLE (g_object_new (SC_TYPE_PLUGIN_EXAMPLE, NULL));
		priv = SC_PLUGIN_EXAMPLE_GET_PRIVATE (singleton);

		/* Cache the config file path */
		priv->conf_file = nm_config_get_path (nm_config_get ());
	} else {
		/* This function should never be called twice */
		g_assert_not_reached ();
	}

	return G_OBJECT (singleton);
}

