/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

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
#include <gio/gio.h>

#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>

#include "plugin.h"
#include "parser.h"
#include "nm-system-config-interface.h"

#define IFCFG_PLUGIN_NAME "ifcfg-suse"
#define IFCFG_PLUGIN_INFO "(C) 2008 Novell, Inc.  To report bugs please use the NetworkManager mailing list."
#define IFCFG_DIR SYSCONFDIR "/sysconfig/network"

static void system_config_interface_init (NMSystemConfigInterface *system_config_interface_class);

G_DEFINE_TYPE_EXTENDED (SCPluginIfcfg, sc_plugin_ifcfg, G_TYPE_OBJECT, 0,
				    G_IMPLEMENT_INTERFACE (NM_TYPE_SYSTEM_CONFIG_INTERFACE,
									  system_config_interface_init))

#define SC_PLUGIN_IFCFG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SC_TYPE_PLUGIN_IFCFG, SCPluginIfcfgPrivate))


#define IFCFG_FILE_PATH_TAG "ifcfg-file-path"

typedef struct {
	gboolean initialized;
	GSList *connections;

	GFileMonitor *monitor;
	guint monitor_id;
} SCPluginIfcfgPrivate;


GQuark
ifcfg_plugin_error_quark (void)
{
	static GQuark error_quark = 0;

	if (G_UNLIKELY (error_quark == 0))
		error_quark = g_quark_from_static_string ("ifcfg-plugin-error-quark");

	return error_quark;
}

struct FindInfo {
	const char *path;
	gboolean found;
};

static gboolean
is_ifcfg_file (const char *file)
{
	return g_str_has_prefix (file, IFCFG_TAG) && strcmp (file, IFCFG_TAG "lo");
}

static NMConnection *
build_one_connection (const char *ifcfg_file)
{
	NMConnection *connection;
	GError *err = NULL;

	PLUGIN_PRINT (PLUGIN_NAME, "parsing %s ... ", ifcfg_file);

	connection = parser_parse_ifcfg (ifcfg_file, &err);
	if (connection) {
		NMSettingConnection *s_con;

		s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
		g_assert (s_con);
		g_assert (s_con->id);
		PLUGIN_PRINT (PLUGIN_NAME, "    found connection '%s'", s_con->id);
	} else
		PLUGIN_PRINT (PLUGIN_NAME, "    error: %s", err->message ? err->message : "(unknown)");

	return connection;
}

typedef struct {
	SCPluginIfcfg *plugin;
	NMConnection *connection;
	GFileMonitor *monitor;
	guint monitor_id;
} ConnectionMonitor;

static void
connection_monitor_destroy (gpointer data)
{
	ConnectionMonitor *monitor = (ConnectionMonitor *) data;

	g_signal_handler_disconnect (monitor->monitor, monitor->monitor_id);
	g_file_monitor_cancel (monitor->monitor);
	g_object_unref (monitor->monitor);

	g_free (monitor);
}

static void
connection_file_changed (GFileMonitor *monitor,
					GFile *file,
					GFile *other_file,
					GFileMonitorEvent event_type,
					gpointer user_data)
{
	ConnectionMonitor *cm = (ConnectionMonitor *) user_data;
	gboolean remove_connection = FALSE;

	switch (event_type) {
	case G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT: {
		NMConnection *new_connection;
		GHashTable *new_settings;
		char *filename;
		char *ifcfg_file;

		/* In case anything goes wrong */
		remove_connection = TRUE;

		filename = g_file_get_basename (file);
		ifcfg_file = g_build_filename (IFCFG_DIR, filename, NULL);
		g_free (filename);

		new_connection = build_one_connection (ifcfg_file);
		g_free (ifcfg_file);

		if (new_connection) {
			new_settings = nm_connection_to_hash (new_connection);
			if (nm_connection_replace_settings (cm->connection, new_settings)) {
				/* Nothing went wrong */
				remove_connection = FALSE;
				g_signal_emit_by_name (cm->plugin, "connection-updated", cm->connection);
			}

			g_object_unref (new_connection);
		}

		break;
	}
	case G_FILE_MONITOR_EVENT_DELETED:
		remove_connection = TRUE;
		break;
	default:
		break;
	}

	if (remove_connection) {
		SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (cm->plugin);

		priv->connections = g_slist_remove (priv->connections, cm->connection);
		g_signal_emit_by_name (cm->plugin, "connection-removed", cm->connection);
		g_object_unref (cm->connection);
		PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "    removed connection");
	}
}

static void
monitor_connection (NMSystemConfigInterface *config, NMConnection *connection, const char *filename)
{
	GFile *file;
	GFileMonitor *monitor;

	file = g_file_new_for_path (filename);
	monitor = g_file_monitor_file (file, G_FILE_MONITOR_NONE, NULL, NULL);
	g_object_unref (file);

	if (monitor) {
		ConnectionMonitor *cm;

		cm = g_new (ConnectionMonitor, 1);
		cm->plugin = SC_PLUGIN_IFCFG (config);
		cm->connection = connection;
		cm->monitor = monitor;
		cm->monitor_id = g_signal_connect (monitor, "changed", G_CALLBACK (connection_file_changed), cm);
		g_object_set_data_full (G_OBJECT (connection), "file-monitor", cm, connection_monitor_destroy);
	}
}

static void
add_one_connection (NMSystemConfigInterface *config, const char *filename, gboolean emit_added)
{
	char *ifcfg_file;
	NMConnection *connection;

	if (!is_ifcfg_file (filename))
		return;
	
	ifcfg_file = g_build_filename (IFCFG_DIR, filename, NULL);
	connection = build_one_connection (ifcfg_file);
	if (connection) {
		SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (config);

		monitor_connection (config, connection, ifcfg_file);
		priv->connections = g_slist_append (priv->connections, connection);

		if (emit_added)
			g_signal_emit_by_name (config, "connection-added", connection);
	}

	g_free (ifcfg_file);
}

static void
update_default_routes (NMSystemConfigInterface *config, gboolean emit_updated)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (config);
	GSList *iter;
	NMConnection *connection;
	NMSettingIP4Config *ip4_setting;
	gboolean got_manual = FALSE;
	guint32 default_route;

	/* First, make sure we have any non-DHCP connections */
	for (iter = priv->connections; iter; iter = iter->next) {
		connection = NM_CONNECTION (iter->data);
		ip4_setting = (NMSettingIP4Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG);
		if (ip4_setting && !strcmp (ip4_setting->method, NM_SETTING_IP4_CONFIG_METHOD_MANUAL)) {
			got_manual = TRUE;
			break;
		}
	}

	if (!got_manual)
		return;

	default_route = parser_parse_routes (IFCFG_DIR "/routes", NULL);
	if (!default_route)
		return;

	for (iter = priv->connections; iter; iter = iter->next) {
		connection = NM_CONNECTION (iter->data);
		ip4_setting = (NMSettingIP4Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG);
		if (ip4_setting && !strcmp (ip4_setting->method, NM_SETTING_IP4_CONFIG_METHOD_MANUAL)) {
			GSList *address_iter;

			for (address_iter = ip4_setting->addresses; address_iter; address_iter = address_iter->next) {
				NMSettingIP4Address *addr = (NMSettingIP4Address *) address_iter->data;
				
				addr->gateway = default_route;
				if (emit_updated)
					g_signal_emit_by_name (config, "connection-updated", connection);
			}
		}
	}
}

static GSList *
get_connections (NMSystemConfigInterface *config)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (config);

	if (!priv->initialized) {
		GDir *dir;
		const char *item;
		GError *err = NULL;

		dir = g_dir_open (IFCFG_DIR, 0, &err);
		if (!dir) {
			PLUGIN_WARN (PLUGIN_NAME, "couldn't access network directory '%s': %s.", IFCFG_DIR, err->message);
			g_error_free (err);
			return NULL;
		}

		while ((item = g_dir_read_name (dir)))
			add_one_connection (config, item, FALSE);

		g_dir_close (dir);
		priv->initialized = TRUE;
	}

	if (!priv->connections)
		/* No need to do any futher work, we have nothing. */
		return priv->connections;

	update_default_routes (config, FALSE);

	return priv->connections;
}

static void
ifcfg_dir_changed (GFileMonitor *monitor,
			    GFile *file,
			    GFile *other_file,
			    GFileMonitorEvent event_type,
			    gpointer user_data)
{
	NMSystemConfigInterface *config = NM_SYSTEM_CONFIG_INTERFACE (user_data);
	char *name;

	name = g_file_get_basename (file);

	if (event_type == G_FILE_MONITOR_EVENT_CREATED) {
		add_one_connection (config, name, TRUE);
	}

	if (!strcmp (name, "routes"))
		update_default_routes (config, TRUE);

	g_free (name);
}

static void
init (NMSystemConfigInterface *config)
{
	GFile *file;
	GFileMonitor *monitor;
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (config);

	file = g_file_new_for_path (IFCFG_DIR);
	monitor = g_file_monitor_directory (file, G_FILE_MONITOR_NONE, NULL, NULL);
	g_object_unref (file);

	if (monitor) {
		priv->monitor_id = g_signal_connect (monitor, "changed", G_CALLBACK (ifcfg_dir_changed), config);
		priv->monitor = monitor;
	}
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
sc_plugin_ifcfg_init (SCPluginIfcfg *plugin)
{
}

static void
dispose (GObject *object)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (object);

	if (priv->connections) {
		g_slist_foreach (priv->connections, release_one_connection, object);
		g_slist_free (priv->connections);
	}

	if (priv->monitor) {
		if (priv->monitor_id)
			g_signal_handler_disconnect (priv->monitor, priv->monitor_id);

		g_file_monitor_cancel (priv->monitor);
		g_object_unref (priv->monitor);
	}

	G_OBJECT_CLASS (sc_plugin_ifcfg_parent_class)->dispose (object);
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

	object_class->get_property = get_property;
	object_class->dispose = dispose;

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
