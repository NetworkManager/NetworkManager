/* NetworkManager system settings service
 *
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2007 Red Hat, Inc.
 */

#include <gmodule.h>
#include <glib-object.h>
#include <glib/gi18n.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>

#include <nm-setting-connection.h>

#include "plugin.h"
#include "parser.h"
#include "shvar.h"
#include "nm-system-config-interface.h"

#define IFCFG_PLUGIN_NAME "ifcfg"
#define IFCFG_PLUGIN_INFO "(C) 2007 Red Hat, Inc.  To report bugs please use the NetworkManager mailing list."

static void system_config_interface_init (NMSystemConfigInterface *system_config_interface_class);

G_DEFINE_TYPE_EXTENDED (SCPluginIfcfg, sc_plugin_ifcfg, G_TYPE_OBJECT, 0,
						G_IMPLEMENT_INTERFACE (NM_TYPE_SYSTEM_CONFIG_INTERFACE,
											   system_config_interface_init))

#define SC_PLUGIN_IFCFG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SC_TYPE_PLUGIN_IFCFG, SCPluginIfcfgPrivate))


#define IFCFG_FILE_PATH_TAG "ifcfg-file-path"

typedef struct {
	gboolean initialized;
	GSList *connections;

	char *profile;

	int ifd;
	int profile_wd;
	GHashTable *watch_table;
} SCPluginIfcfgPrivate;


GQuark
ifcfg_plugin_error_quark (void)
{
	static GQuark error_quark = 0;

	if (G_UNLIKELY (error_quark == 0))
		error_quark = g_quark_from_static_string ("ifcfg-plugin-error-quark");

	return error_quark;
}

static char *
get_current_profile_path (void)
{
	shvarFile *file;
	char *buf, *path;

	if (!(file = svNewFile (SYSCONFDIR"/sysconfig/network")))
		return NULL;

	buf = svGetValue (file, "CURRENT_PROFILE");
	if (!buf)
		buf = strdup ("default");
	svCloseFile (file);

	path = g_strdup_printf (SYSCONFDIR "/sysconfig/networking/profiles/%s/", buf);
	g_free (buf);
	return path;
}

struct FindInfo {
	const char *path;
	gboolean found;
};

static void
find_watched_path (gpointer key, gpointer value, gpointer user_data)
{
	struct FindInfo *info = (struct FindInfo *) user_data;

	if (info->found)
		return;

	if (!strcmp (info->path, value)) {
		info->found = TRUE;
		return;
	}
}

static void
watch_path (const char *path, const int inotify_fd, GHashTable *table)
{
	char *basename;
	int wd;
	struct FindInfo info;

	basename = g_path_get_basename (path);
	g_return_if_fail (basename != NULL);

	info.found = FALSE;
	info.path = basename;
	g_hash_table_foreach (table, find_watched_path, &info);
	if (info.found)
		goto error;

	wd = inotify_add_watch (inotify_fd, basename,
	                        IN_CLOSE_WRITE | IN_CREATE | IN_DELETE | IN_MOVE);
	if (wd == -1)
		goto error;

	g_hash_table_insert (table, GINT_TO_POINTER (wd), basename);
	return;

error:
	g_free (basename);
}

static NMConnection *
build_one_connection (const char *profile_path, const char *filename)
{
	NMConnection *connection;
	char *ifcfg_file = NULL;
	GError *error = NULL;

	g_return_val_if_fail (profile_path != NULL, NULL);
	g_return_val_if_fail (filename != NULL, NULL);

	ifcfg_file = g_build_filename (profile_path, filename, NULL);
	g_return_val_if_fail (ifcfg_file != NULL, NULL);

	PLUGIN_PRINT (PLUGIN_NAME, "parsing %s ... ", ifcfg_file);

	connection = parser_parse_file (ifcfg_file, &error);
	if (connection) {
		NMSettingConnection *s_con;

		s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
		g_assert (s_con);
		g_assert (s_con->id);
		PLUGIN_PRINT (PLUGIN_NAME, "    found connection '%s'", s_con->id);
		g_object_set_data_full (G_OBJECT (connection), IFCFG_FILE_PATH_TAG,
		                        ifcfg_file, (GDestroyNotify) g_free);
	} else {
		PLUGIN_PRINT (PLUGIN_NAME, "    error: %s",
		              error->message ? error->message : "(unknown)");
		g_free (ifcfg_file);
	}

	return connection;
}

static GSList *
get_connections_for_profile (const char *profile_path,
                             const int inotify_fd,
                             GHashTable *watch_table)
{
	GSList *connections = NULL;
	GDir *dir;
	const char *item;

	g_return_val_if_fail (profile_path != NULL, NULL);
	g_return_val_if_fail (watch_table != NULL, NULL);

	dir = g_dir_open (profile_path, 0, NULL);
	if (!dir) {
		PLUGIN_WARN (PLUGIN_NAME, "couldn't access network profile directory '%s'.", profile_path);
		return NULL;
	}

	while ((item = g_dir_read_name (dir))) {
		NMConnection *connection;

		if (strncmp (item, IFCFG_TAG, strlen (IFCFG_TAG)))
			continue;

		connection = build_one_connection (profile_path, item);
		if (connection)
			connections = g_slist_append (connections, connection);
	}
	g_dir_close (dir);

	watch_path (profile_path, inotify_fd, watch_table);
	return connections;
}

static void
release_one_connection (gpointer item, gpointer user_data)
{
	NMConnection *connection = NM_CONNECTION (item);
	SCPluginIfcfg *plugin = SC_PLUGIN_IFCFG (user_data);

	g_signal_emit_by_name (plugin, "connection-removed", connection);
	g_object_unref (connection);
}

static void
free_watch (gpointer key, gpointer value, gpointer user_data)
{
	int ifd = GPOINTER_TO_INT (user_data);
	int wd = GPOINTER_TO_INT (value);

	if (inotify_rm_watch (ifd, wd) != 0)
		PLUGIN_WARN (PLUGIN_NAME, "error removing inotify watch on %s", (char *) key);
}

static void
clear_all_connections (SCPluginIfcfg *plugin)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);

	/* Remove all existing connections */
	if (priv->connections) {
		g_slist_foreach (priv->connections, release_one_connection, plugin);
		g_slist_free (priv->connections);
		priv->connections = NULL;
	}

	if (priv->watch_table) {
		g_hash_table_foreach (priv->watch_table, free_watch, GINT_TO_POINTER (priv->ifd));
		g_hash_table_destroy (priv->watch_table);
		priv->watch_table = NULL;
	}
}

static void
reload_all_connections (SCPluginIfcfg *plugin)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);

	clear_all_connections (plugin);

	priv->watch_table = g_hash_table_new_full (g_int_hash, g_int_equal, NULL, g_free);

	/* Add connections from the current profile */
	priv->connections = get_connections_for_profile (priv->profile, priv->ifd, priv->watch_table);
}

static GSList *
get_connections (NMSystemConfigInterface *config)
{
	SCPluginIfcfg *plugin = SC_PLUGIN_IFCFG (config);
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);

	if (!priv->initialized)
		reload_all_connections (plugin);

	return priv->connections;
}

static NMConnection *
find_connection_by_path (GSList *connections, const char *path)
{
	GSList *iter;

	g_return_val_if_fail (path != NULL, NULL);

	for (iter = connections; iter; iter = g_slist_next (iter)) {
		NMConnection *list_connection = NM_CONNECTION (iter->data);
		const char *list_connection_path;

		list_connection_path = g_object_get_data (G_OBJECT (list_connection), IFCFG_FILE_PATH_TAG);
		if (list_connection_path && !strcmp (list_connection_path, path))
			return list_connection;
	}
	return NULL;
}

static void
handle_profile_item_changed (SCPluginIfcfg *plugin,
                             struct inotify_event *evt,
                             const char *filename)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	const char *path;

	g_return_if_fail (plugin != NULL);
	g_return_if_fail (evt != NULL);

	path = g_hash_table_lookup (priv->watch_table, GINT_TO_POINTER (evt->wd));
	if (!path)
		return;

	if (!strncmp (filename, IFCFG_TAG, strlen (IFCFG_TAG))) {
		NMConnection *new_connection;
		const char *filepath;
		NMConnection *existing;

		new_connection = build_one_connection (priv->profile, filename);
		if (!new_connection)
			goto out;

		filepath = g_object_get_data (G_OBJECT (new_connection), IFCFG_FILE_PATH_TAG);
		g_assert (filepath);

		existing = find_connection_by_path (priv->connections, filepath);
		if (existing) {
			GHashTable *new_settings;

			/* update the settings of the existing connection for this
			 * ifcfg file and notify listeners that something has changed.
			 */
			new_settings = nm_connection_to_hash (new_connection);
			if (!nm_connection_replace_settings (existing, new_settings)) {
				/* couldn't replace the settings for some reason; have to
				 * remove the connection then.
				 */
				PLUGIN_WARN (PLUGIN_NAME, "couldn't update connection for '%s'.", filename);
				priv->connections = g_slist_remove (priv->connections, existing);
				g_signal_emit_by_name (plugin, "connection-removed", existing);
				g_object_unref (existing);
			} else {
				g_signal_emit_by_name (plugin, "connection-updated", existing);
			}
			g_object_unref (new_connection);
		} else {
			/* totally new connection */
			priv->connections = g_slist_append (priv->connections, new_connection);
			g_signal_emit_by_name (plugin, "connection-added", new_connection);
		}
	} else if (!strcmp (filename, "resolv.conf")) {
		// Update dns entries in all connections
	}

out:
	return;
}

static gboolean
stuff_changed (GIOChannel *channel, GIOCondition cond, gpointer user_data)
{
	SCPluginIfcfg *plugin = SC_PLUGIN_IFCFG (user_data);
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	struct inotify_event evt;

	/* read the notifications from the watch descriptor */
	while (g_io_channel_read_chars (channel, (gchar *) &evt, sizeof (struct inotify_event), NULL, NULL) == G_IO_STATUS_NORMAL) {
		gchar filename[PATH_MAX + 1];

		if (evt.len <= 0)
			continue;

		g_io_channel_read_chars (channel,
		                         filename,
		                         evt.len > PATH_MAX ? PATH_MAX : evt.len,
		                         NULL, NULL);

		if (evt.wd == priv->profile_wd) {
			if (!strcmp (filename, "network")) {
				char *new_profile;

				new_profile = get_current_profile_path ();
				if (!new_profile) {
					/* No new profile */
					clear_all_connections (plugin);
				} else if (!priv->profile || strcmp (new_profile, priv->profile)) {
					/* Valid new profile */
					g_free (priv->profile);
					priv->profile = g_strdup (new_profile);
					reload_all_connections (plugin);
				}
				g_free (new_profile);
			}
		} else
			handle_profile_item_changed (plugin, &evt, filename);
	}

	return TRUE;
}

static gboolean
sc_plugin_inotify_init (SCPluginIfcfg *plugin, GError **error)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	GIOChannel *channel;
	guint source_id;
	int ifd, wd;

	ifd = inotify_init ();
	if (ifd == -1) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Couldn't initialize inotify");
		return FALSE;
	}

	wd = inotify_add_watch (ifd, SYSCONFDIR "/sysconfig/", IN_CLOSE_WRITE);
	if (wd == -1) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Couldn't monitor %s", SYSCONFDIR "/sysconfig/");
		close (ifd);
		return FALSE;
	}

	priv->ifd = ifd;
	priv->profile_wd = wd;

	/* Watch the inotify descriptor for file/directory change events */
	channel = g_io_channel_unix_new (ifd);
	g_io_channel_set_flags (channel, G_IO_FLAG_NONBLOCK, NULL);
	g_io_channel_set_encoding (channel, NULL, NULL); 

	source_id = g_io_add_watch (channel,
	                            G_IO_IN | G_IO_ERR,
	                            (GIOFunc) stuff_changed,
	                            plugin);
	g_io_channel_unref (channel);



	return TRUE;
}

static void
init (NMSystemConfigInterface *config)
{
	SCPluginIfcfg *plugin = SC_PLUGIN_IFCFG (config);
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	GError *error = NULL;

	priv->profile = get_current_profile_path ();
	if (!priv->profile)
		PLUGIN_WARN (PLUGIN_NAME, "could not determine network profile path.");

	priv->ifd = sc_plugin_inotify_init (plugin, &error);
	if (error) {
		PLUGIN_PRINT (PLUGIN_NAME, "    inotify error: %s",
		              error->message ? error->message : "(unknown)");
	}
}

static void
sc_plugin_ifcfg_init (SCPluginIfcfg *plugin)
{
}

static void
dispose (GObject *object)
{
	G_OBJECT_CLASS (sc_plugin_ifcfg_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	G_OBJECT_CLASS (sc_plugin_ifcfg_parent_class)->finalize (object);
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_NAME:
		g_value_set_string (value, IFCFG_PLUGIN_NAME);
		break;
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_INFO:
		g_value_set_string (value, IFCFG_PLUGIN_INFO);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
sc_plugin_ifcfg_class_init (SCPluginIfcfgClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	g_type_class_add_private (req_class, sizeof (SCPluginIfcfgPrivate));

	object_class->dispose = dispose;
	object_class->finalize = finalize;
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
	system_config_interface_class->init = init;
}

G_MODULE_EXPORT GObject *
nm_system_config_factory (void)
{
	static GStaticMutex mutex = G_STATIC_MUTEX_INIT;
	static SCPluginIfcfg *singleton = NULL;

	g_static_mutex_lock (&mutex);
	if (!singleton)
		singleton = SC_PLUGIN_IFCFG (g_object_new (SC_TYPE_PLUGIN_IFCFG, NULL));
	g_object_ref (singleton);
	g_static_mutex_unlock (&mutex);

	return G_OBJECT (singleton);
}
