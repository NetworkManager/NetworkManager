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
#include <errno.h>

#include <nm-setting-connection.h>
#include <nm-setting-wired.h>
#include <nm-setting-wireless-security.h>
#include <nm-setting-8021x.h>

#include "plugin.h"
#include "parser.h"
#include "shvar.h"
#include "nm-system-config-interface.h"

#define IFCFG_PLUGIN_NAME "ifcfg-fedora"
#define IFCFG_PLUGIN_INFO "(c) 2007 - 2008 Red Hat, Inc.  To report bugs please use the NetworkManager mailing list."

static void system_config_interface_init (NMSystemConfigInterface *system_config_interface_class);

G_DEFINE_TYPE_EXTENDED (SCPluginIfcfg, sc_plugin_ifcfg, G_TYPE_OBJECT, 0,
						G_IMPLEMENT_INTERFACE (NM_TYPE_SYSTEM_CONFIG_INTERFACE,
											   system_config_interface_init))

#define SC_PLUGIN_IFCFG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SC_TYPE_PLUGIN_IFCFG, SCPluginIfcfgPrivate))


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

#define AUTO_WIRED_STAMP_FILE SYSCONFDIR"/NetworkManager/auto-wired-stamp"
#define AUTO_WIRED_FILE_NAME  _("Auto Wired")

static void
write_auto_wired_connection (const char *profile_path)
{
	GError *error = NULL;
	char *path;
	const char *contents = "# Written by nm-system-settings\nTYPE=Ethernet\nBOOTPROTO=dhcp\nONBOOT=yes\nUSERCTL=yes\nPEERDNS=yes\n";

	/* Write out a default autoconnect ethernet connection */
	if (g_file_test (AUTO_WIRED_STAMP_FILE, G_FILE_TEST_EXISTS) || !profile_path)
		return;

	path = g_strdup_printf ("%s/ifcfg-%s", profile_path, AUTO_WIRED_FILE_NAME);
	if (g_file_test (path, G_FILE_TEST_EXISTS))
		return;

	PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "writing default Auto Wired connection");
	if (!g_file_set_contents (path, contents, -1, &error)) {
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "could not write default wired connection: %s (%d).", error->message, error->code);
		g_error_free (error);
	} else {
		g_file_set_contents (AUTO_WIRED_STAMP_FILE, "", -1, NULL);
	}
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
	int wd;
	struct FindInfo info;

	g_return_if_fail (g_path_is_absolute (path));

	info.found = FALSE;
	info.path = path;
	g_hash_table_foreach (table, find_watched_path, &info);
	if (info.found)
		return;

	wd = inotify_add_watch (inotify_fd, path,
	                        IN_CLOSE_WRITE | IN_CREATE | IN_DELETE | IN_MOVE | IN_MOVE_SELF | IN_DELETE_SELF);
	if (wd == -1) {
		PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "    inotify error watching '%s': errno %d",
		              path, errno);
	} else {
		g_hash_table_insert (table, GINT_TO_POINTER (wd), g_strdup (path));
	}
}

static NMConnection *
build_one_connection (const char *profile_path, const char *filename)
{
	NMConnection *connection;
	GError *error = NULL;

	g_return_val_if_fail (profile_path != NULL, NULL);
	g_return_val_if_fail (filename != NULL, NULL);

	PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "parsing %s ... ", filename);

	connection = parser_parse_file (filename, &error);
	if (connection) {
		NMSettingConnection *s_con;

		s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
		g_assert (s_con);
		g_assert (s_con->id);
		PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "    read connection '%s'", s_con->id);
	} else {
		PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "    error: %s",
		              error->message ? error->message : "(unknown)");
	}

	return connection;
}

static NMConnection *
handle_new_ifcfg (const char *profile_path,
                  const char *file,
                  const int inotify_fd,
                  GHashTable *watch_table)
{
	NMConnection *connection;
	ConnectionData *cdata;
	char *keys_file, *basename;

	connection = build_one_connection (profile_path, file);
	if (!connection)
		return NULL;

	/* Watch the file too so we can match up the watch descriptor with the
	 * path we care about if the file is a hardlink.
	 */
	watch_path (file, inotify_fd, watch_table);

	/* If there's a keys file watch that too */
	basename = g_path_get_basename (file);
	if (basename) {
		keys_file = g_strdup_printf ("%s" KEYS_TAG "%s", profile_path, basename + strlen (IFCFG_TAG));
		if (keys_file && g_file_test (keys_file, G_FILE_TEST_EXISTS))
			watch_path (keys_file, inotify_fd, watch_table);
		g_free (keys_file);
		g_free (basename);
	}

	cdata = connection_data_get (connection);
	if (cdata->ignored) {
		PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "Ignoring connection '%s' because "
		              "NM_CONTROLLED was false.", file);
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
	char *resolv_conf;

	g_return_val_if_fail (profile_path != NULL, NULL);
	g_return_val_if_fail (watch_table != NULL, NULL);

	dir = g_dir_open (profile_path, 0, NULL);
	if (!dir) {
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "couldn't access network profile directory '%s'.", profile_path);
		return NULL;
	}

	while ((item = g_dir_read_name (dir))) {
		NMConnection *connection;
		char *ifcfg_file;

		if (strncmp (item, IFCFG_TAG, strlen (IFCFG_TAG)))
			continue;

		ifcfg_file = g_build_filename (profile_path, item, NULL);

		connection = handle_new_ifcfg (profile_path, ifcfg_file, inotify_fd, watch_table);
		if (connection)
			connections = g_slist_append (connections, connection);

		g_free (ifcfg_file);
	}
	g_dir_close (dir);

	watch_path (profile_path, inotify_fd, watch_table);

	/* Watch resolv.conf too */
	resolv_conf = g_strdup_printf ("%sresolv.conf", profile_path);
	if (g_file_test (resolv_conf, G_FILE_TEST_EXISTS))
		watch_path (resolv_conf, inotify_fd, watch_table);
	g_free (resolv_conf);

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
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "error removing inotify watch on %s", (char *) key);
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
	GSList *iter;
	gboolean have_wired = FALSE;

	clear_all_connections (plugin);

	priv->watch_table = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, g_free);

	/* Add connections from the current profile */
	priv->connections = get_connections_for_profile (priv->profile, priv->ifd, priv->watch_table);

	/* Check if we need to write out the auto wired connection */
	for (iter = priv->connections; iter; iter = g_slist_next (iter)) {
		NMConnection *connection = NM_CONNECTION (iter->data);
		NMSettingConnection *s_con;

		s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
		if (!strcmp (s_con->type, NM_SETTING_WIRED_SETTING_NAME))
			have_wired = TRUE;
	}

	if (!have_wired)
		write_auto_wired_connection (priv->profile);
}

static GSList *
get_connections (NMSystemConfigInterface *config)
{
	SCPluginIfcfg *plugin = SC_PLUGIN_IFCFG (config);
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	GSList *list = NULL, *iter;

	if (!priv->initialized)
		reload_all_connections (plugin);

	for (iter = priv->connections; iter; iter = g_slist_next (iter)) {
		NMConnection *connection = NM_CONNECTION (iter->data);
		ConnectionData *cdata;

		cdata = connection_data_get (connection);
		if (!cdata->ignored) {
			list = g_slist_append (list, connection);
			cdata->exported = TRUE;
		}
	}

	return list;
}

static GValue *
string_to_gvalue (const char *str)
{
	GValue *val;

	val = g_slice_new0 (GValue);
	g_value_init (val, G_TYPE_STRING);
	g_value_set_string (val, str);

	return val;
}

static void
add_one_secret (gpointer key, gpointer data, gpointer user_data)
{
	g_hash_table_insert ((GHashTable *) user_data, g_strdup (key), string_to_gvalue (data));	
}

static void
destroy_gvalue (gpointer data)
{
	GValue *value = (GValue *) data;

	g_value_unset (value);
	g_slice_free (GValue, value);
}

static GHashTable *
get_secrets (NMSystemConfigInterface *config,
             NMConnection *connection,
             NMSetting *setting)
{
	GHashTable *settings;
	ConnectionData *cdata;
	GHashTable *secrets;

	cdata = connection_data_get (connection);
	if (!cdata)
		return NULL;

	settings = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                  g_free, (GDestroyNotify) g_hash_table_destroy);

	if (cdata->wifi_secrets) {
		secrets = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, destroy_gvalue);
		g_hash_table_foreach (cdata->wifi_secrets, add_one_secret, secrets);
		g_hash_table_insert (settings, g_strdup (NM_SETTING_WIRELESS_SECURITY_SETTING_NAME), secrets);
	}

	if (cdata->onex_secrets) {
		secrets = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, destroy_gvalue);
		g_hash_table_foreach (cdata->onex_secrets, add_one_secret, secrets);
		g_hash_table_insert (settings, g_strdup (NM_SETTING_802_1X_SETTING_NAME), secrets);
	}

	/* FIXME: PPP secrets (which are actually split out into GSM/CDMA/etc */

	return settings;
}

static NMConnection *
find_connection_by_path (GSList *connections, const char *path)
{
	GSList *iter;

	g_return_val_if_fail (path != NULL, NULL);

	for (iter = connections; iter; iter = g_slist_next (iter)) {
		NMConnection *list_connection = NM_CONNECTION (iter->data);
		ConnectionData *cdata;

		cdata = connection_data_get (list_connection);
		g_assert (cdata);
		if (cdata->ifcfg_path && !strcmp (cdata->ifcfg_path, path))
			return list_connection;
	}
	return NULL;
}

static void
handle_connection_changed (SCPluginIfcfg *plugin,
                           const char *filename)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	NMConnection *new_connection;
	NMConnection *existing;
	ConnectionData *new_cdata;
	GHashTable *new_settings;
	ConnectionData *existing_cdata;
	gboolean remove = FALSE;

	/* Could return NULL if the connection got deleted */
	new_connection = build_one_connection (priv->profile, filename);

	existing = find_connection_by_path (priv->connections, filename);
	if (!existing) {
		if (new_connection) {
			new_cdata = connection_data_get (new_connection);
			g_assert (new_cdata);

			/* totally new connection */
			priv->connections = g_slist_append (priv->connections, new_connection);
			if (!new_cdata->ignored) {
				new_cdata->exported = TRUE;
				g_signal_emit_by_name (plugin, "connection-added", new_connection);
			}
		}
		return;
	}

	existing_cdata = connection_data_get (existing);
	g_assert (existing_cdata);

	if (new_connection) {
		/* update the settings of the existing connection for this
		 * ifcfg file and notify listeners that something has changed.
		 */
		new_settings = nm_connection_to_hash (new_connection);
		if (!nm_connection_replace_settings (existing, new_settings)) {
			/* couldn't replace the settings for some reason; have to
			 * remove the connection then.
			 */
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "couldn't update connection for '%s'.", filename);
			remove = TRUE;
		} else {
			/* Success */
			new_cdata = connection_data_get (new_connection);
			g_assert (new_cdata);

			connection_data_copy_secrets (new_cdata, existing_cdata);

			if (new_cdata->ignored && !existing_cdata->ignored) {
				/* connection now ignored */
				existing_cdata->ignored = TRUE;
				g_signal_emit_by_name (plugin, "connection-removed", existing);
				existing_cdata->exported = FALSE;
			} else if (!new_cdata->ignored && existing_cdata->ignored) {
				/* connection no longer ignored, let the system settings
				 * service know about it now.
				 */
				existing_cdata->ignored = FALSE;
				existing_cdata->exported = TRUE;
				g_signal_emit_by_name (plugin, "connection-added", existing);
			} else if (!new_cdata->ignored && !existing_cdata->ignored) {
				/* connection updated and not ignored */
				g_signal_emit_by_name (plugin, "connection-updated", existing);
			} else if (new_cdata->ignored && existing_cdata->ignored) {
				/* do nothing */
			}
		}
		g_object_unref (new_connection);
	} else {
		remove = TRUE;
	}

	if (remove) {
		priv->connections = g_slist_remove (priv->connections, existing);
		if (!existing_cdata->ignored)
			g_signal_emit_by_name (plugin, "connection-removed", existing);
		g_object_unref (existing);
		PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "    removed connection");
	}
}

static void
handle_resolv_conf_changed (SCPluginIfcfg *plugin, const char *path)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	char *contents = NULL;
	char **lines = NULL;
	GSList *iter;

	g_return_if_fail (path != NULL);

	g_file_get_contents (path, &contents, NULL, NULL);
	if (contents) {
		lines = g_strsplit (contents, "\n", 0);
		if (lines && !*lines) {
			g_strfreev (lines);
			lines = NULL;
		}
	}

	if (lines) {
		PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "Updating connections because %s changed.", path);
	} else {
		PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "Updating connections because %s was deleted.", path);
	}

	for (iter = priv->connections; iter; iter = g_slist_next (iter)) {
		NMConnection *connection = NM_CONNECTION (iter->data);
		NMSettingIP4Config *s_ip4;

		s_ip4 = NM_SETTING_IP4_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG));
		if (s_ip4) {
			ConnectionData *cdata;

			cdata = connection_data_get (connection);
			g_assert (cdata);

			connection_update_from_resolv_conf (lines, s_ip4);

			if (!cdata->ignored)
				g_signal_emit_by_name (plugin, "connection-updated", connection);
		}
	}

	if (lines)
		g_strfreev (lines);
	g_free (contents);
}

static void
handle_profile_item_changed (SCPluginIfcfg *plugin, const char *path)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	char *basename;

	g_return_if_fail (plugin != NULL);
	g_return_if_fail (path != NULL);

	basename = g_path_get_basename (path);
	if (!basename) {
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "not enough memory to parse connection change.");
		return;
	}

	if (!strncmp (basename, IFCFG_TAG, strlen (IFCFG_TAG)))
		handle_connection_changed (plugin, path);
	else if (!strncmp (basename, KEYS_TAG, strlen (KEYS_TAG))) {
		char *ifcfg;
		
		ifcfg = g_strdup_printf ("%s" IFCFG_TAG "%s", priv->profile, basename + strlen (KEYS_TAG));
		if (ifcfg)
			handle_connection_changed (plugin, ifcfg);
		g_free (ifcfg);
	} else if (!strcmp (basename, "resolv.conf"))
		handle_resolv_conf_changed (plugin, path);

	g_free (basename);
}

static void
handle_profile_item_new (SCPluginIfcfg *plugin, const char *filename)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	char *path;

	path = g_strdup_printf ("%s%s", priv->profile, filename);
	if (!path)
		return;

	if (!strcmp (filename, "resolv.conf")) {
		watch_path (path, priv->ifd, priv->watch_table);
		handle_resolv_conf_changed (plugin, path);
	} else if (!strncmp (filename, IFCFG_TAG, strlen (IFCFG_TAG))) {
		NMConnection *connection;

		connection = handle_new_ifcfg (priv->profile, path, priv->ifd, priv->watch_table);
		if (connection) {
			ConnectionData *cdata;

			cdata = connection_data_get (connection);
			g_assert (cdata);

			/* new connection */
			priv->connections = g_slist_append (priv->connections, connection);
			if (!cdata->ignored) {
				cdata->exported = TRUE;
				g_signal_emit_by_name (plugin, "connection-added", connection);
			}
		}
	}

	g_free (path);
}

typedef struct {
	gboolean found;
	const char *path;
} FindInfo;

static void
find_path_helper (gpointer key, gpointer data, gpointer user_data)
{
	FindInfo *info = (FindInfo *) user_data;

	if (!info->found && !strcmp (data, info->path))
		info->found = TRUE;
}

static gboolean
find_path (GHashTable *table, const char *path)
{
	FindInfo info = { FALSE, path };

	g_hash_table_foreach (table, find_path_helper, &info);
	return info.found;
}

static gboolean
stuff_changed (GIOChannel *channel, GIOCondition cond, gpointer user_data)
{
	SCPluginIfcfg *plugin = SC_PLUGIN_IFCFG (user_data);
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	struct inotify_event evt;

	/* read the notifications from the watch descriptor */
	while (g_io_channel_read_chars (channel, (gchar *) &evt, sizeof (struct inotify_event), NULL, NULL) == G_IO_STATUS_NORMAL) {
		const char *path;
		gchar filename[PATH_MAX + 1];

		path = g_hash_table_lookup (priv->watch_table, GINT_TO_POINTER (evt.wd));

		filename[0] = '\0';
		if (evt.len > 0) {
			g_io_channel_read_chars (channel,
			                        filename,
			                        evt.len > PATH_MAX ? PATH_MAX : evt.len,
			                        NULL, NULL);
		}

		if (!path && !strlen (filename))
			continue;

		if (evt.wd == priv->profile_wd) {
			char *basename;

			basename = g_path_get_basename (filename);

			if (basename && !strcmp (basename, "network")) {
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
			g_free (basename);
		} else {
			char *fullpath;
			gboolean path_found, delete = FALSE;

			/* If the item was deleted, stop tracking its watch */
			if (evt.mask & (IN_DELETE | IN_DELETE_SELF))
				delete = TRUE;

			/* Track moves out of the profile directory */
			if (   (evt.mask & IN_MOVE_SELF)
			    && path
			    && strcmp (path, priv->profile)
			    && !strncmp (path, priv->profile, strlen (priv->profile))
			    && !g_file_test (path, G_FILE_TEST_EXISTS))
				delete = TRUE;

			if (delete) {
				inotify_rm_watch (priv->ifd, evt.wd);
				g_hash_table_remove (priv->watch_table, GINT_TO_POINTER (evt.wd));
			}

			fullpath = g_strdup_printf ("%s%s", priv->profile, filename);
			path_found = find_path (priv->watch_table, fullpath);

			if (strlen (filename) && !strcmp (path, priv->profile) && !path_found) {
				/* Some file appeared */
				handle_profile_item_new (plugin, filename);
			} else {
				handle_profile_item_changed (plugin, path_found ? fullpath : path);
			}
			g_free (fullpath);
		}
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
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "could not determine network profile path.");

	if (!sc_plugin_inotify_init (plugin, &error)) {
		PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "    inotify error: %s",
		              error->message ? error->message : "(unknown)");
		g_error_free (error);
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
	system_config_interface_class->get_secrets = get_secrets;
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
