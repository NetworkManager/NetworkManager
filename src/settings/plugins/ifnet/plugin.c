/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service (ifnet)
 *
 * Mu Qiao <qiaomuf@gmail.com>
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
 * Copyright (C) 1999-2010 Gentoo Foundation, Inc.
 */

#include <string.h>

#include <gmodule.h>
#include <glib.h>
#include <gio/gio.h>

#include <nm-utils.h>
#include <nm-setting-connection.h>

#include "NetworkManager.h"
#include "nm-system-config-interface.h"
#include "nm-ifnet-connection.h"

#include "plugin.h"
#include "net_utils.h"
#include "net_parser.h"
#include "wpa_parser.h"
#include "connection_parser.h"

#define IFNET_PLUGIN_NAME_PRINT "ifnet"
#define IFNET_PLUGIN_INFO "(C) 1999-2010 Gentoo Foundation, Inc. To report bugs please use bugs.gentoo.org with [networkmanager] or [qiaomuf] prefix."
#define IFNET_SYSTEM_HOSTNAME_FILE "/etc/conf.d/hostname"
#define IFNET_MANAGE_WELL_KNOWN_DEFAULT TRUE
#define IFNET_KEY_FILE_KEY_MANAGED "managed"

typedef struct {
	GHashTable *config_connections;
	gchar *hostname;
	gboolean unmanaged_well_known;

	GFileMonitor *hostname_monitor;
	GFileMonitor *net_monitor;
	GFileMonitor *wpa_monitor;

} SCPluginIfnetPrivate;

typedef void (*FileChangedFn) (gpointer user_data);

typedef struct {
	FileChangedFn callback;
	gpointer user_data;
} FileMonitorInfo;

static void system_config_interface_init (NMSystemConfigInterface *class);

static void reload_connections (gpointer config);

G_DEFINE_TYPE_EXTENDED (SCPluginIfnet, sc_plugin_ifnet, G_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_SYSTEM_CONFIG_INTERFACE, system_config_interface_init))
#define SC_PLUGIN_IFNET_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SC_TYPE_PLUGIN_IFNET, SCPluginIfnetPrivate))
/*
static void
ignore_cb(NMSettingsConnectionInterface * connection,
	  GError * error, gpointer user_data)
{
}
*/
static const char *
get_hostname (NMSystemConfigInterface * config)
{
	return SC_PLUGIN_IFNET_GET_PRIVATE (config)->hostname;
}

static void
update_system_hostname (gpointer config)
{
	SCPluginIfnetPrivate *priv = SC_PLUGIN_IFNET_GET_PRIVATE (config);

	if (priv->hostname)
		g_free (priv->hostname);
	priv->hostname = read_hostname (IFNET_SYSTEM_HOSTNAME_FILE);

	g_object_notify (G_OBJECT (config),
			 NM_SYSTEM_CONFIG_INTERFACE_HOSTNAME);
	PLUGIN_PRINT (IFNET_PLUGIN_NAME, "Hostname updated to: %s",
		      priv->hostname);
}

static void
write_system_hostname (NMSystemConfigInterface * config,
		       const gchar * newhostname)
{
	SCPluginIfnetPrivate *priv = SC_PLUGIN_IFNET_GET_PRIVATE (config);

	g_return_if_fail (newhostname);
	PLUGIN_PRINT (IFNET_PLUGIN_NAME, "Write system hostname: %s",
		      newhostname);
	if (write_hostname (newhostname, IFNET_SYSTEM_HOSTNAME_FILE)) {
		g_free (priv->hostname);
		priv->hostname = g_strdup (newhostname);
		g_object_notify (G_OBJECT (config),
				 NM_SYSTEM_CONFIG_INTERFACE_HOSTNAME);
	} else
		PLUGIN_WARN (IFNET_PLUGIN_NAME,
			     "Write system hostname: %s failed", newhostname);
}

static gboolean
is_managed_plugin ()
{
	const char *result = NULL;

	result = ifnet_get_global_setting (IFNET_KEY_FILE_GROUP, IFNET_KEY_FILE_KEY_MANAGED);
	if (result)
		return is_true (result);
	return IFNET_MANAGE_WELL_KNOWN_DEFAULT;
}

static void
file_changed (GFileMonitor * monitor,
	      GFile * file,
	      GFile * other_file,
	      GFileMonitorEvent event_type, gpointer user_data)
{
	FileMonitorInfo *info;

	switch (event_type) {
	case G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT:
		info = (FileMonitorInfo *) user_data;
		info->callback (info->user_data);
		break;
	default:
		break;
	}
}

static GFileMonitor *
monitor_file_changes (const char *filename,
		      FileChangedFn callback, gpointer user_data)
{
	GFile *file;
	GFileMonitor *monitor;
	FileMonitorInfo *info;
	GError **error = NULL;

	if (!g_file_test (filename, G_FILE_TEST_IS_REGULAR))
		return NULL;
	file = g_file_new_for_path (filename);
	monitor = g_file_monitor_file (file, G_FILE_MONITOR_NONE, NULL, error);
	g_object_unref (file);

	if (monitor) {
		info = g_new0 (FileMonitorInfo, 1);
		info->callback = callback;
		info->user_data = user_data;
		g_object_weak_ref (G_OBJECT (monitor), (GWeakNotify) g_free,
				   info);
		g_signal_connect (monitor, "changed", G_CALLBACK (file_changed),
				  info);
	} else
		PLUGIN_WARN (IFNET_PLUGIN_NAME,
			     "Monitoring %s failed, error: %s", filename,
			     error == NULL ? "nothing" : (*error)->message);

	return monitor;
}

/* Callback for nm_settings_connection_replace_and_commit. Report any errors
 * encountered when commiting connection settings updates. */
static void
commit_cb (NMSettingsConnection *connection, GError *error, gpointer unused) 
{
	if (error) {
		PLUGIN_WARN (IFNET_PLUGIN_NAME, "    error updating: %s",
	             	 (error && error->message) ? error->message : "(unknown)");
	} else {
		NMSettingConnection *s_con;

		s_con = (NMSettingConnection *) nm_connection_get_setting (NM_CONNECTION (connection),
		                                                           NM_TYPE_SETTING_CONNECTION);
		g_assert (s_con);
		PLUGIN_PRINT (IFNET_PLUGIN_NAME, "Connection %s updated",
		              nm_setting_connection_get_id (s_con));
	}
}

static void
setup_monitors (NMIfnetConnection * connection, gpointer user_data)
{
	SCPluginIfnet *self = SC_PLUGIN_IFNET (user_data);
	SCPluginIfnetPrivate *priv = SC_PLUGIN_IFNET_GET_PRIVATE (self);

	priv->hostname_monitor =
	    monitor_file_changes (IFNET_SYSTEM_HOSTNAME_FILE,
				  update_system_hostname, user_data);
	priv->net_monitor =
	    monitor_file_changes (CONF_NET_FILE, reload_connections, user_data);
	priv->wpa_monitor =
	    monitor_file_changes (WPA_SUPPLICANT_CONF, reload_connections,
				  user_data);
}

static void
cancel_monitors (NMIfnetConnection * connection, gpointer user_data)
{
	SCPluginIfnet *self = SC_PLUGIN_IFNET (user_data);
	SCPluginIfnetPrivate *priv = SC_PLUGIN_IFNET_GET_PRIVATE (self);

	if (priv->hostname_monitor) {
		g_file_monitor_cancel (priv->hostname_monitor);
		g_object_unref (priv->hostname_monitor);
	}
	if (priv->net_monitor) {
		g_file_monitor_cancel (priv->net_monitor);
		g_object_unref (priv->net_monitor);
	}
	if (priv->wpa_monitor) {
		g_file_monitor_cancel (priv->wpa_monitor);
		g_object_unref (priv->wpa_monitor);
	}
}

static void
reload_connections (gpointer config)
{
	SCPluginIfnet *self = SC_PLUGIN_IFNET (config);
	SCPluginIfnetPrivate *priv = SC_PLUGIN_IFNET_GET_PRIVATE (self);
	GList *conn_names = NULL, *n_iter = NULL;

	/* save names for removing unused connections */
	GHashTable *new_conn_names = NULL;
	GHashTableIter iter;
	gpointer key;
	gpointer value;

	if (priv->unmanaged_well_known)
		return;

	if (!reload_parsers ())
		return;

	PLUGIN_PRINT (IFNET_PLUGIN_NAME, "Loading connections");

	conn_names = ifnet_get_connection_names ();
	new_conn_names = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, NULL);
	for (n_iter = conn_names; n_iter; n_iter = g_list_next (n_iter)) {
		NMIfnetConnection *new;
		NMIfnetConnection *old;
		const char *conn_name = n_iter->data;

		/* read the new connection */
		new = nm_ifnet_connection_new (conn_name, NULL);
		if (!new)
			continue;

		g_signal_connect (G_OBJECT (new), "ifnet_setup_monitors",
		                  G_CALLBACK (setup_monitors), config);
		g_signal_connect (G_OBJECT (new), "ifnet_cancel_monitors",
		                  G_CALLBACK (cancel_monitors), config);

		old = g_hash_table_lookup (priv->config_connections, conn_name);
		if (old && new) {
			const char *auto_refresh;

			auto_refresh = ifnet_get_global_setting (IFNET_KEY_FILE_GROUP, "auto_refresh");
			if (auto_refresh && is_true (auto_refresh)) {
				if (!nm_connection_compare (NM_CONNECTION (old),
				                            NM_CONNECTION (new),
				                            NM_SETTING_COMPARE_FLAG_EXACT)) {
					PLUGIN_PRINT (IFNET_PLUGIN_NAME, "Auto refreshing %s", conn_name);

					/* Remove and re-add to disconnect and reconnect with new settings */
					nm_settings_connection_signal_remove (NM_SETTINGS_CONNECTION (old));
					g_hash_table_remove (priv->config_connections, conn_name);
					g_hash_table_insert (priv->config_connections, g_strdup (conn_name), new);
					if (is_managed_plugin () && is_managed (conn_name))
						g_signal_emit_by_name (self, NM_SYSTEM_CONFIG_INTERFACE_CONNECTION_ADDED, new);
				}
			} else {
				/* Update existing connection with new settings */
				nm_settings_connection_replace_and_commit (NM_SETTINGS_CONNECTION (old),
				                                           NM_CONNECTION (new),
				                                           commit_cb, NULL);
				g_object_unref (new);
			}
			g_signal_emit_by_name (self, NM_SYSTEM_CONFIG_INTERFACE_UNMANAGED_SPECS_CHANGED);
		} else if (new) {
			g_hash_table_insert (priv->config_connections, g_strdup (conn_name), new);
			if (is_managed_plugin () && is_managed (conn_name))
				g_signal_emit_by_name (self, NM_SYSTEM_CONFIG_INTERFACE_CONNECTION_ADDED, new);
		}
		g_hash_table_insert (new_conn_names, (gpointer) conn_name, (gpointer) conn_name);
	}

	/* remove unused connections */
	g_hash_table_iter_init (&iter, priv->config_connections);
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		if (!g_hash_table_lookup (new_conn_names, key)) {
			nm_settings_connection_signal_remove (NM_SETTINGS_CONNECTION (value));
			g_hash_table_remove (priv->config_connections, key);
		}
	}
	g_hash_table_destroy (new_conn_names);
	g_list_free (conn_names);
}

static NMSettingsConnection *
add_connection (NMSystemConfigInterface *config,
                NMConnection *source,
                GError **error)
{
	NMIfnetConnection *connection = NULL;
	char *conn_name;

	conn_name = ifnet_add_new_connection (source, CONF_NET_FILE, WPA_SUPPLICANT_CONF, error);
	if (conn_name)
		connection = nm_ifnet_connection_new (conn_name, source);
	reload_connections (config);
	return connection ? NM_SETTINGS_CONNECTION (connection) : NULL;
}

static void
check_unmanaged (gpointer key, gpointer data, gpointer user_data)
{
	GSList **list = (GSList **) user_data;
	gchar *conn_name = (gchar *) key;
	const char *unmanaged_spec;
	GSList *iter;

	if (is_managed (conn_name))
		return;
	PLUGIN_PRINT (IFNET_PLUGIN_NAME, "Checking unmanaged: %s", conn_name);
	unmanaged_spec = ifnet_get_data (conn_name, "mac");
	if (!unmanaged_spec)
		return;

	/* Just return if the unmanaged spec is already in the list */
	for (iter = *list; iter; iter = g_slist_next (iter)) {
		if (!strcmp ((char *) iter->data, unmanaged_spec))
			return;
	}

	PLUGIN_PRINT (IFNET_PLUGIN_NAME, "Add unmanaged: %s", unmanaged_spec);
	*list =
	    g_slist_prepend (*list, g_strdup_printf ("mac:%s", unmanaged_spec));
}

static GSList *
get_unmanaged_specs (NMSystemConfigInterface * config)
{
	SCPluginIfnetPrivate *priv = SC_PLUGIN_IFNET_GET_PRIVATE (config);
	GSList *list = NULL;

	g_return_val_if_fail (priv->config_connections != NULL, NULL);
	PLUGIN_PRINT (IFNET_PLUGIN_NAME, "getting unmanaged specs...");
	g_hash_table_foreach (priv->config_connections, check_unmanaged, &list);
	return list;
}

static void
SCPluginIfnet_init (NMSystemConfigInterface * config)
{
	SCPluginIfnet *self = SC_PLUGIN_IFNET (config);
	SCPluginIfnetPrivate *priv = SC_PLUGIN_IFNET_GET_PRIVATE (self);

	PLUGIN_PRINT (IFNET_PLUGIN_NAME, "Initializing!");
	if (!priv->config_connections)
		priv->config_connections =
		    g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
					   g_object_unref);
	priv->unmanaged_well_known = !is_managed_plugin ();
	PLUGIN_PRINT (IFNET_PLUGIN_NAME, "management mode: %s",
		      priv->unmanaged_well_known ? "unmanaged" : "managed");
	// GFileMonitor setup
	setup_monitors (NULL, config);
	reload_connections (config);
	/* Read hostname */
	update_system_hostname (self);

	PLUGIN_PRINT (IFNET_PLUGIN_NAME, "Initialzation complete!");
}

static GSList *
get_connections (NMSystemConfigInterface * config)
{
	SCPluginIfnetPrivate *priv = SC_PLUGIN_IFNET_GET_PRIVATE (config);
	GSList *connections = NULL;
	GHashTableIter iter;
	gpointer key, value;

	PLUGIN_PRINT (IFNET_PLUGIN_NAME, "(%d) ... get_connections.",
		      GPOINTER_TO_UINT (config));
	if (priv->unmanaged_well_known) {
		PLUGIN_PRINT (IFNET_PLUGIN_NAME,
			      "(%d) ... get_connections (managed=false): return empty list.",
			      GPOINTER_TO_UINT (config));
		return NULL;
	}

	g_hash_table_iter_init (&iter, priv->config_connections);
	while (g_hash_table_iter_next (&iter, &key, &value))
		if (is_managed ((gchar *) key))
			connections = g_slist_prepend (connections, value);
	PLUGIN_PRINT (IFNET_PLUGIN_NAME, "(%d) connections count: %d",
		      GPOINTER_TO_UINT (config), g_slist_length (connections));
	return connections;
}

static void
system_config_interface_init (NMSystemConfigInterface *class)
{
	class->init = SCPluginIfnet_init;
	class->get_connections = get_connections;
	class->get_unmanaged_specs = get_unmanaged_specs;
	class->add_connection = add_connection;
}

static void
sc_plugin_ifnet_init (SCPluginIfnet * plugin)
{
}

static void
get_property (GObject * object, guint prop_id, GValue * value,
	      GParamSpec * pspec)
{
	NMSystemConfigInterface *self = NM_SYSTEM_CONFIG_INTERFACE (object);

	switch (prop_id) {
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_NAME:
		g_value_set_string (value, IFNET_PLUGIN_NAME_PRINT);
		break;
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_INFO:
		g_value_set_string (value, IFNET_PLUGIN_INFO);
		break;
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_CAPABILITIES:
		g_value_set_uint (value,
				  NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_CONNECTIONS
				  |
				  NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_HOSTNAME);
		break;
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_HOSTNAME:
		g_value_set_string (value, get_hostname (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject * object, guint prop_id, const GValue * value,
	      GParamSpec * pspec)
{
	switch (prop_id) {
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_HOSTNAME:{
			const gchar *hostname = g_value_get_string (value);

			if (hostname && strlen (hostname) < 1)
				hostname = NULL;
			write_system_hostname (NM_SYSTEM_CONFIG_INTERFACE
					       (object), hostname);
			break;
		}
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
dispose (GObject * object)
{
	SCPluginIfnet *plugin = SC_PLUGIN_IFNET (object);
	SCPluginIfnetPrivate *priv = SC_PLUGIN_IFNET_GET_PRIVATE (plugin);

	cancel_monitors (NULL, object);
	if (priv->config_connections) {
		g_hash_table_remove_all (priv->config_connections);
		g_hash_table_destroy (priv->config_connections);
	}

	g_free (priv->hostname);
	ifnet_destroy ();
	wpa_parser_destroy ();
	G_OBJECT_CLASS (sc_plugin_ifnet_parent_class)->dispose (object);
}

static void
sc_plugin_ifnet_class_init (SCPluginIfnetClass * req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	g_type_class_add_private (req_class, sizeof (SCPluginIfnetPrivate));

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

G_MODULE_EXPORT GObject *
nm_system_config_factory (void)
{
	static SCPluginIfnet *singleton = NULL;

	if (!singleton)
		singleton
		    =
		    SC_PLUGIN_IFNET (g_object_new (SC_TYPE_PLUGIN_IFNET, NULL));
	else
		g_object_ref (singleton);
	return G_OBJECT (singleton);
}
