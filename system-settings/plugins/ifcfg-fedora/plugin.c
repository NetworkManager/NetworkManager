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

#define IFCFG_DIR SYSCONFDIR"/sysconfig/network-scripts/"

static void system_config_interface_init (NMSystemConfigInterface *system_config_interface_class);

G_DEFINE_TYPE_EXTENDED (SCPluginIfcfg, sc_plugin_ifcfg, G_TYPE_OBJECT, 0,
						G_IMPLEMENT_INTERFACE (NM_TYPE_SYSTEM_CONFIG_INTERFACE,
											   system_config_interface_init))

#define SC_PLUGIN_IFCFG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SC_TYPE_PLUGIN_IFCFG, SCPluginIfcfgPrivate))


typedef struct {
	gboolean initialized;
	GSList *connections;

	int ifd;
	int wd;
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
build_one_connection (const char *path)
{
	NMConnection *connection;
	GError *error = NULL;

	g_return_val_if_fail (path != NULL, NULL);

	PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "parsing %s ... ", path);

	connection = parser_parse_file (path, &error);
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
handle_new_ifcfg (const char *basename,
                  const int inotify_fd,
                  GHashTable *watch_table)
{
	NMConnection *connection = NULL;
	ConnectionData *cdata;
	char *keys_file;
	char *path;

	g_return_val_if_fail (basename != NULL, NULL);
	g_return_val_if_fail (watch_table != NULL, NULL);

	path = g_build_filename (IFCFG_DIR, basename, NULL);
	if (!path) {
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "not enough memory for new connection.");
		return NULL;
	}

	connection = build_one_connection (path);
	if (!connection)
		goto out;

	/* Watch the file too so we can match up the watch descriptor with the
	 * path we care about if the file is a hardlink.
	 */
	watch_path (path, inotify_fd, watch_table);

	/* If there's a keys file watch that too */
	keys_file = g_strdup_printf (IFCFG_DIR KEYS_TAG "%s", basename + strlen (IFCFG_TAG));
	if (keys_file && g_file_test (keys_file, G_FILE_TEST_EXISTS))
		watch_path (keys_file, inotify_fd, watch_table);
	g_free (keys_file);

	cdata = connection_data_get (connection);
	if (cdata->ignored) {
		PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "Ignoring connection '%s' because "
		              "NM_CONTROLLED was false.", basename);
	}

out:
	g_free (path);
	return connection;
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
read_all_connections (SCPluginIfcfg *plugin)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	GDir *dir;
	const char *item;
	GSList *iter;
	gboolean have_wired = FALSE;

	clear_all_connections (plugin);

	priv->watch_table = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, g_free);

	dir = g_dir_open (IFCFG_DIR, 0, NULL);
	if (dir) {
		while ((item = g_dir_read_name (dir))) {
			NMConnection *connection;

			if (strncmp (item, IFCFG_TAG, strlen (IFCFG_TAG)))
				continue;

			connection = handle_new_ifcfg (item, priv->ifd, priv->watch_table);
			if (connection)
				priv->connections = g_slist_append (priv->connections, connection);
		}
		g_dir_close (dir);
	} else {
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "couldn't access network config directory '" IFCFG_DIR "'.");
	}

	/* Check if we need to write out the auto wired connection */
	for (iter = priv->connections; iter; iter = g_slist_next (iter)) {
		NMConnection *connection = NM_CONNECTION (iter->data);
		NMSettingConnection *s_con;

		s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
		if (!strcmp (s_con->type, NM_SETTING_WIRED_SETTING_NAME))
			have_wired = TRUE;
	}

	if (!have_wired)
		write_auto_wired_connection (IFCFG_DIR);
}

static GSList *
get_connections (NMSystemConfigInterface *config)
{
	SCPluginIfcfg *plugin = SC_PLUGIN_IFCFG (config);
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	GSList *list = NULL, *iter;

	if (!priv->initialized)
		read_all_connections (plugin);

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
                           const char *basename)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	char *filename = NULL;
	NMConnection *new_connection;
	NMConnection *existing;
	ConnectionData *new_cdata;
	GHashTable *new_settings;
	ConnectionData *existing_cdata;
	gboolean remove = FALSE;

	if (!strncmp (basename, IFCFG_TAG, strlen (IFCFG_TAG))) {
		filename = g_strdup_printf (IFCFG_DIR "%s", basename);
	} else if (!strncmp (basename, KEYS_TAG, strlen (KEYS_TAG))) {
		filename = g_strdup_printf (IFCFG_DIR IFCFG_TAG "%s", basename + strlen (KEYS_TAG));
	} else {
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "ignored event for '%s'.", basename);
		return;
	}

	if (!filename) {
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "not enough memory to update connection.");
		return;
	}

	/* Could return NULL if the connection got deleted */
	new_connection = build_one_connection (filename);

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
		g_free (filename);
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

	g_free (filename);
}

static void
handle_new_item (SCPluginIfcfg *plugin, const char *basename)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	NMConnection *connection;
	ConnectionData *cdata;
	char *ifcfgfile;

	if (!strncmp (basename, KEYS_TAG, strlen (KEYS_TAG))) {
		ifcfgfile = g_strdup_printf (IFCFG_TAG "%s", basename + strlen (KEYS_TAG));
		handle_connection_changed (plugin, ifcfgfile);
		g_free (ifcfgfile);
		return;
	}

	if (strncmp (basename, IFCFG_TAG, strlen (IFCFG_TAG)))
		return;

	/* New connection */
	connection = handle_new_ifcfg (basename, priv->ifd, priv->watch_table);
	if (!connection)
		return;

	cdata = connection_data_get (connection);
	g_assert (cdata);

	/* new connection */
	priv->connections = g_slist_append (priv->connections, connection);
	if (!cdata->ignored) {
		cdata->exported = TRUE;
		g_signal_emit_by_name (plugin, "connection-added", connection);
	}
}

static gboolean
should_ignore_file (const char *basename, const char *tag)
{
	int len, tag_len;

	g_return_val_if_fail (basename != NULL, TRUE);
	g_return_val_if_fail (tag != NULL, TRUE);

	len = strlen (basename);
	tag_len = strlen (tag);
	if ((len > tag_len) && !strcasecmp (basename + len - tag_len, tag))
		return TRUE;
	return FALSE;
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

		if (evt.wd == priv->wd) {
			if (   strncmp (filename, IFCFG_TAG, strlen (IFCFG_TAG))
			    && strncmp (filename, KEYS_TAG, strlen (KEYS_TAG)))
				continue;

			/* ignore some files */
			if (   should_ignore_file (filename, BAK_TAG)
			    || should_ignore_file (filename, TILDE_TAG)
			    || should_ignore_file (filename, ORIG_TAG)
			    || should_ignore_file (filename, REJ_TAG))
				continue;

			if (evt.mask & (IN_CREATE | IN_MOVED_TO)) {
				handle_new_item (plugin, filename);
			} else if (evt.mask & (IN_DELETE | IN_MOVED_FROM)) {
				/* Remove connection */
				handle_connection_changed (plugin, filename);
			} else if (evt.mask & IN_CLOSE_WRITE) {
				/* Updated connection */
				handle_connection_changed (plugin, filename);
			}
		} else {
			/* Track deletions and moves of the file itself */
			if (   (evt.mask & IN_DELETE_SELF)
			    || ((evt.mask & IN_MOVE_SELF) && path && !g_file_test (path, G_FILE_TEST_EXISTS))) {
				char *basename;

				inotify_rm_watch (priv->ifd, evt.wd);
				g_hash_table_remove (priv->watch_table, GINT_TO_POINTER (evt.wd));

				/* Remove connection */
				basename = g_path_get_basename (path);
				handle_connection_changed (plugin, basename);
				g_free (basename);
			}
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

	wd = inotify_add_watch (ifd, IFCFG_DIR, 
	                        IN_CLOSE_WRITE | IN_CREATE | IN_DELETE | IN_MOVE);
	if (wd == -1) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Couldn't monitor " IFCFG_DIR);
		close (ifd);
		return FALSE;
	}

	priv->ifd = ifd;
	priv->wd = wd;

	/* Watch the inotify descriptor for file/directory change events */
	channel = g_io_channel_unix_new (ifd);
	if (!channel) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Couldn't create new GIOChannel");
		close (ifd);
		return FALSE;
	}
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
	GError *error = NULL;

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
	clear_all_connections (SC_PLUGIN_IFCFG (object));

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
