/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

#include <config.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <gmodule.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <nm-connection.h>
#include <nm-setting.h>
#include <nm-setting-connection.h>

#ifndef NO_GIO
#include <gio/gio.h>
#else
#include <gfilemonitor/gfilemonitor.h>
#endif

#include "plugin.h"
#include "nm-system-config-interface.h"
#include "nm-keyfile-connection.h"
#include "writer.h"

#define KEYFILE_PLUGIN_NAME "keyfile"
#define KEYFILE_PLUGIN_INFO "(c) 2007 - 2008 Red Hat, Inc.  To report bugs please use the NetworkManager mailing list."

static void system_config_interface_init (NMSystemConfigInterface *system_config_interface_class);

G_DEFINE_TYPE_EXTENDED (SCPluginKeyfile, sc_plugin_keyfile, G_TYPE_OBJECT, 0,
				    G_IMPLEMENT_INTERFACE (NM_TYPE_SYSTEM_CONFIG_INTERFACE,
									  system_config_interface_init))

#define SC_PLUGIN_KEYFILE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SC_TYPE_PLUGIN_KEYFILE, SCPluginKeyfilePrivate))

typedef struct {
	GHashTable *hash;

	GFileMonitor *monitor;
	guint monitor_id;

	gboolean disposed;
} SCPluginKeyfilePrivate;

static void
read_connections (NMSystemConfigInterface *config)
{
	SCPluginKeyfilePrivate *priv = SC_PLUGIN_KEYFILE_GET_PRIVATE (config);
	GDir *dir;
	GError *err = NULL;

	dir = g_dir_open (KEYFILE_DIR, 0, &err);
	if (dir) {
		const char *item;

		while ((item = g_dir_read_name (dir))) {
			NMKeyfileConnection *connection;
			char *full_path;

			full_path = g_build_filename (KEYFILE_DIR, item, NULL);
			connection = nm_keyfile_connection_new (full_path);
			if (connection) {
				g_hash_table_insert (priv->hash,
				                     (gpointer) nm_keyfile_connection_get_filename (connection),
				                     connection);
			}
			g_free (full_path);
		}

		g_dir_close (dir);
	} else {
		g_warning ("Can not read directory '%s': %s", KEYFILE_DIR, err->message);
		g_error_free (err);
	}
}

typedef struct {
	const char *uuid;
	NMKeyfileConnection *found;
} FindByUUIDInfo;

static void
find_by_uuid (gpointer key, gpointer data, gpointer user_data)
{
	NMKeyfileConnection *keyfile = NM_KEYFILE_CONNECTION (key);
	FindByUUIDInfo *info = user_data;
	NMConnection *connection;
	NMSettingConnection *s_con;

	if (info->found)
		return;

	connection = nm_exported_connection_get_connection (NM_EXPORTED_CONNECTION (keyfile));
	s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
	if (s_con && s_con->uuid) {
		if (!strcmp (info->uuid, s_con->uuid))
			info->found = keyfile;
	}
}

static gboolean
update_connection_settings (NMExportedConnection *orig,
                            NMExportedConnection *new,
                            GError **error)
{
	GHashTable *settings;
	gboolean success;

	settings = nm_connection_to_hash (nm_exported_connection_get_connection (new));
	success = nm_exported_connection_update (orig, settings, error);
	g_hash_table_destroy (settings);

	return success;
}

/* Monitoring */

static void
dir_changed (GFileMonitor *monitor,
		   GFile *file,
		   GFile *other_file,
		   GFileMonitorEvent event_type,
		   gpointer user_data)
{
	NMSystemConfigInterface *config = NM_SYSTEM_CONFIG_INTERFACE (user_data);
	SCPluginKeyfilePrivate *priv = SC_PLUGIN_KEYFILE_GET_PRIVATE (config);
	char *name;
	NMKeyfileConnection *connection;

	name = g_file_get_path (file);
	connection = g_hash_table_lookup (priv->hash, name);

	switch (event_type) {
	case G_FILE_MONITOR_EVENT_DELETED:
		if (connection) {
			/* Removing from the hash table should drop the last reference */
			g_object_ref (connection);
			g_hash_table_remove (priv->hash, name);
			nm_exported_connection_signal_removed (NM_EXPORTED_CONNECTION (connection));
			g_object_unref (connection);
		}
		break;
	case G_FILE_MONITOR_EVENT_CREATED:
	case G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT:
		if (connection) {
			/* Update */
			NMExportedConnection *tmp;

			tmp = (NMExportedConnection *) nm_keyfile_connection_new (name);
			if (tmp) {
				GError *error = NULL;

				if (!update_connection_settings (NM_EXPORTED_CONNECTION (connection), tmp, &error)) {
					g_warning ("%s: couldn't update connection settings: (%d) %s",
					           __func__, error ? error->code : 0,
					           error ? error->message : "unknown");
					g_error_free (error);
				}
				g_object_unref (tmp);
			}
		} else {
			/* New */
			connection = nm_keyfile_connection_new (name);
			if (connection) {
				NMConnection *tmp;
				NMSettingConnection *s_con;
				NMKeyfileConnection *found = NULL;

				/* Connection renames will show up as different files but with
				 * the same UUID.  Try to find the original connection.
				 */
				tmp = nm_exported_connection_get_connection (NM_EXPORTED_CONNECTION (connection));
				s_con = (NMSettingConnection *) nm_connection_get_setting (tmp, NM_TYPE_SETTING_CONNECTION);
				if (s_con && s_con->uuid) {
					FindByUUIDInfo info = { .found = NULL, .uuid = s_con->uuid };

					g_hash_table_foreach (priv->hash, find_by_uuid, &info);
					found = info.found;
				}

				/* A connection rename is treated just like an update except
				 * there's a bit more housekeeping with the hash table.
				 */
				if (found) {
					const char *old_filename = nm_keyfile_connection_get_filename (connection);
					GError *error = NULL;

					/* Removing from the hash table should drop the last reference,
					 * but of course we want to keep the connection around.
					 */
					g_object_ref (found);
					g_hash_table_remove (priv->hash, old_filename);

					/* Updating settings should update the NMKeyfileConnection's
					 * filename property too.
					 */
					if (!update_connection_settings (NM_EXPORTED_CONNECTION (found),
					                                 NM_EXPORTED_CONNECTION (connection),
					                                 &error)) {
						g_warning ("%s: couldn't update connection settings: (%d) %s",
						           __func__, error ? error->code : 0,
						           error ? error->message : "unknown");
						g_error_free (error);
					}

					/* Re-insert the connection back into the hash with the new filename */
					g_hash_table_insert (priv->hash,
					                     (gpointer) nm_keyfile_connection_get_filename (found),
					                     found);

					/* Get rid of the temporary connection */
					g_object_unref (connection);
				} else {
					g_hash_table_insert (priv->hash,
					                     (gpointer) nm_keyfile_connection_get_filename (connection),
					                     connection);
					g_signal_emit_by_name (config, "connection-added", connection);
				}
			}
		}
		break;
	default:
		break;
	}

	g_free (name);
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
}

static void
hash_to_slist (gpointer key, gpointer value, gpointer user_data)
{
	GSList **list = (GSList **) user_data;

	*list = g_slist_prepend (*list, value);
}

/* Plugin */

static GSList *
get_connections (NMSystemConfigInterface *config)
{
	SCPluginKeyfilePrivate *priv = SC_PLUGIN_KEYFILE_GET_PRIVATE (config);
	GSList *connections = NULL;

	if (!priv->hash) {
		setup_monitoring (config);
		read_connections (config);
	}

	g_hash_table_foreach (priv->hash, hash_to_slist, &connections);

	return connections;
}

static gboolean
add_connection (NMSystemConfigInterface *config,
                NMConnection *connection,
                GError **error)
{
	return write_connection (connection, NULL, error);
}

/* GObject */

static void
sc_plugin_keyfile_init (SCPluginKeyfile *plugin)
{
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

	g_object_class_override_property (object_class,
							    NM_SYSTEM_CONFIG_INTERFACE_PROP_NAME,
							    NM_SYSTEM_CONFIG_INTERFACE_NAME);

	g_object_class_override_property (object_class,
							    NM_SYSTEM_CONFIG_INTERFACE_PROP_INFO,
							    NM_SYSTEM_CONFIG_INTERFACE_INFO);
}

static void
system_config_interface_init (NMSystemConfigInterface *system_config_interface_class)
{
	/* interface implementation */
	system_config_interface_class->get_connections = get_connections;
	system_config_interface_class->add_connection = add_connection;
}

G_MODULE_EXPORT GObject *
nm_system_config_factory (void)
{
	static SCPluginKeyfile *singleton = NULL;

	if (!singleton)
		singleton = SC_PLUGIN_KEYFILE (g_object_new (SC_TYPE_PLUGIN_KEYFILE, NULL));
	else
		g_object_ref (singleton);

	return G_OBJECT (singleton);
}
