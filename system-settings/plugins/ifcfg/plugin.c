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
	GSList *connections;
} SCPluginIfcfgPrivate;


#define PROFILE_DIR SYSCONFDIR "/sysconfig/networking/profiles/"

static gboolean
parse_files (gpointer data)
{
	SCPluginIfcfg *plugin = SC_PLUGIN_IFCFG (data);
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	char *profile = NULL;
	char *profile_path = NULL;
	gboolean added = FALSE;
	GDir *dir;
	const char *item;

	profile = parser_get_current_profile_name ();
	profile_path = g_strdup_printf (PROFILE_DIR "%s/", profile);
	if (!profile_path) {
		PLUGIN_WARN (PLUGIN_NAME, "current network profile directory '%s' not found.", profile);
		goto out;
	}
	g_free (profile);

	dir = g_dir_open (profile_path, 0, NULL);
	if (!dir) {
		PLUGIN_WARN (PLUGIN_NAME, "couldn't access network profile directory '%s'.", profile_path);
		goto out;
	}

	while ((item = g_dir_read_name (dir))) {
		NMConnection *connection;
		char *err = NULL;
		char *filename;

		if (strncmp (item, IFCFG_TAG, strlen (IFCFG_TAG)))
			continue;

		filename = g_build_filename (profile_path, item, NULL);
		if (!filename)
			continue;

		PLUGIN_PRINT (PLUGIN_NAME, "parsing %s ... ", filename);

		if ((connection = parser_parse_file (filename, &err))) {
			NMSettingConnection *s_con;

			s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
			g_assert (s_con);
			g_assert (s_con->id);
			priv->connections = g_slist_append (priv->connections, connection);
			PLUGIN_PRINT (PLUGIN_NAME, "    added connection '%s'", s_con->id);
			g_signal_emit_by_name (NM_SYSTEM_CONFIG_INTERFACE (plugin),
			                       "connection-added",
			                       connection);			
			added = TRUE;
		} else {
			PLUGIN_PRINT (PLUGIN_NAME, "   error: %s", err ? err : "(unknown)");
		}

		g_free (filename);
	}
	g_dir_close (dir);

out:
	g_free (profile_path);
	return FALSE;
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
}

G_MODULE_EXPORT GObject *
nm_system_config_factory (void)
{
	static GStaticMutex mutex = G_STATIC_MUTEX_INIT;
	static SCPluginIfcfg *singleton = NULL;

	g_static_mutex_lock (&mutex);
	if (!singleton) {
		singleton = SC_PLUGIN_IFCFG (g_object_new (SC_TYPE_PLUGIN_IFCFG, NULL));
		g_idle_add (parse_files, singleton);
	}
	g_object_ref (singleton);
	g_static_mutex_unlock (&mutex);

	return G_OBJECT (singleton);
}
