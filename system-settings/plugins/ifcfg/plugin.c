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
#include "nm-system-config-interface.h"

#define IFCFG_PLUGIN_NAME "ifcfg"
#define IFCFG_PLUGIN_INFO "(C) 2007 Red Hat, Inc.  To report bugs please use the NetworkManager mailing list."

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
} SCPluginIfcfgPrivate;


#define PROFILE_DIR SYSCONFDIR "/sysconfig/networking/profiles/"

GQuark
ifcfg_plugin_error_quark (void)
{
	static GQuark error_quark = 0;

	if (G_UNLIKELY (error_quark == 0))
		error_quark = g_quark_from_static_string ("ifcfg-plugin-error-quark");

	return error_quark;
}

static GSList *
get_initial_connections (char *profile_name)
{
	GSList *connections = NULL;
	char *profile_path = NULL;
	GDir *dir;
	const char *item;

	profile_path = g_strdup_printf (PROFILE_DIR "%s/", profile_name);
	if (!profile_path) {
		PLUGIN_WARN (PLUGIN_NAME, "out of memory getting profile path.");
		return NULL;
	}

	dir = g_dir_open (profile_path, 0, NULL);
	if (!dir) {
		PLUGIN_WARN (PLUGIN_NAME, "couldn't access network profile directory '%s'.", profile_path);
		goto out;
	}

	while ((item = g_dir_read_name (dir))) {
		NMConnection *connection;
		GError *error = NULL;
		char *filename;

		if (strncmp (item, IFCFG_TAG, strlen (IFCFG_TAG)))
			continue;

		filename = g_build_filename (profile_path, item, NULL);
		if (!filename)
			continue;

		PLUGIN_PRINT (PLUGIN_NAME, "parsing %s ... ", filename);

		if ((connection = parser_parse_file (filename, &error))) {
			NMSettingConnection *s_con;

			s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
			g_assert (s_con);
			g_assert (s_con->id);
			connections = g_slist_append (connections, connection);
			PLUGIN_PRINT (PLUGIN_NAME, "    added connection '%s'", s_con->id);
		} else {
			PLUGIN_PRINT (PLUGIN_NAME, "    error: %s",
			              error->message ? error->message : "(unknown)");
			g_clear_error (&error);
		}

		g_free (filename);
	}
	g_dir_close (dir);

out:
	g_free (profile_path);
	return connections;
}

static GSList *
get_connections (NMSystemConfigInterface *config)
{
	SCPluginIfcfg *plugin = SC_PLUGIN_IFCFG (config);
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);

	if (!priv->initialized)
		priv->connections = get_initial_connections (priv->profile);

	return priv->connections;
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
				char *new_profile = parser_get_current_profile_name ();

				if (strcmp (new_profile, priv->profile)) {
					g_free (priv->profile);
					priv->profile = g_strdup (new_profile);
				}
				g_free (new_profile);
			}
		} else {
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
		             "Couldn't monitor ");
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

	priv->profile = parser_get_current_profile_name ();

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
