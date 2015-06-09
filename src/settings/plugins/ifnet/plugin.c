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

#include "config.h"

#include <string.h>

#include <gmodule.h>
#include <glib.h>
#include <gio/gio.h>

#include <nm-utils.h>
#include <nm-setting-connection.h>

#include "nm-dbus-interface.h"
#include "nm-system-config-interface.h"
#include "nm-logging.h"
#include "nm-ifnet-connection.h"
#include "nm-config.h"

#include "plugin.h"
#include "net_utils.h"
#include "net_parser.h"
#include "wpa_parser.h"
#include "connection_parser.h"

#define IFNET_PLUGIN_NAME_PRINT "ifnet"
#define IFNET_PLUGIN_INFO "(C) 1999-2010 Gentoo Foundation, Inc. To report bugs please use bugs.gentoo.org with [networkmanager] or [qiaomuf] prefix."
#define IFNET_MANAGE_WELL_KNOWN_DEFAULT TRUE
#define IFNET_KEY_FILE_KEY_MANAGED "managed"

typedef struct {
	GHashTable *connections;  /* uuid::connection */
	gboolean unmanaged_well_known;

	GFileMonitor *net_monitor;
	GFileMonitor *wpa_monitor;

} SCPluginIfnetPrivate;

typedef void (*FileChangedFn) (gpointer user_data);

typedef struct {
	FileChangedFn callback;
	gpointer user_data;
} FileMonitorInfo;

static void system_config_interface_init (NMSystemConfigInterface *class);

static void reload_connections (NMSystemConfigInterface *config);

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

static gboolean
is_managed_plugin (void)
{
	char *result = NULL;

	result = nm_config_data_get_value (nm_config_get_data_orig (nm_config_get ()),
	                                   IFNET_KEY_FILE_GROUP, IFNET_KEY_FILE_KEY_MANAGED);
	if (result) {
		gboolean ret = is_true (result);
		g_free (result);
		return ret;
	}
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
	} else {
		nm_log_warn (LOGD_SETTINGS, "Monitoring %s failed, error: %s", filename,
		             error == NULL ? "nothing" : (*error)->message);
	}

	return monitor;
}

static void
setup_monitors (NMIfnetConnection * connection, gpointer user_data)
{
	SCPluginIfnet *self = SC_PLUGIN_IFNET (user_data);
	SCPluginIfnetPrivate *priv = SC_PLUGIN_IFNET_GET_PRIVATE (self);

	if (nm_config_get_monitor_connection_files (nm_config_get ())) {
		priv->net_monitor =
			monitor_file_changes (CONF_NET_FILE, (FileChangedFn) reload_connections,
			                      user_data);
		priv->wpa_monitor =
			monitor_file_changes (WPA_SUPPLICANT_CONF, (FileChangedFn) reload_connections,
			                      user_data);
	}
}

static void
cancel_monitors (NMIfnetConnection * connection, gpointer user_data)
{
	SCPluginIfnet *self = SC_PLUGIN_IFNET (user_data);
	SCPluginIfnetPrivate *priv = SC_PLUGIN_IFNET_GET_PRIVATE (self);

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
connection_removed_cb (NMSettingsConnection *obj, gpointer user_data)
{
	g_hash_table_remove (SC_PLUGIN_IFNET_GET_PRIVATE (user_data)->connections,
	                     nm_connection_get_uuid (NM_CONNECTION (obj)));
}

static void
track_new_connection (SCPluginIfnet *self, NMIfnetConnection *connection)
{
	g_hash_table_insert (SC_PLUGIN_IFNET_GET_PRIVATE (self)->connections,
	                     g_strdup (nm_connection_get_uuid (NM_CONNECTION (connection))),
	                     g_object_ref (connection));
	g_signal_connect (connection, NM_SETTINGS_CONNECTION_REMOVED,
	                  G_CALLBACK (connection_removed_cb),
	                  self);
}

static void
reload_connections (NMSystemConfigInterface *config)
{
	SCPluginIfnet *self = SC_PLUGIN_IFNET (config);
	SCPluginIfnetPrivate *priv = SC_PLUGIN_IFNET_GET_PRIVATE (self);
	GList *conn_names = NULL, *n_iter = NULL;
	gboolean auto_refresh = FALSE;
	char *str_auto_refresh;
	GError *error = NULL;

	/* save names for removing unused connections */
	GHashTable *new_connections = NULL;
	GHashTableIter iter;
	const char *uuid;
	NMSettingsConnection *candidate;

	if (priv->unmanaged_well_known)
		return;

	if (!reload_parsers ())
		return;

	nm_log_info (LOGD_SETTINGS, "Loading connections");

	str_auto_refresh = nm_config_data_get_value (nm_config_get_data_orig (nm_config_get ()),
	                                             IFNET_KEY_FILE_GROUP, "auto_refresh");
	if (str_auto_refresh && is_true (str_auto_refresh))
		auto_refresh = TRUE;
	g_free (str_auto_refresh);

	new_connections = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_object_unref);

	/* Reread on-disk data and refresh in-memory connections from it */
	conn_names = ifnet_get_connection_names ();
	for (n_iter = conn_names; n_iter; n_iter = g_list_next (n_iter)) {
		NMIfnetConnection *new;
		NMIfnetConnection *old;
		const char *conn_name = n_iter->data;

		/* read the new connection */
		new = nm_ifnet_connection_new (NULL, conn_name);
		if (!new)
			continue;

		g_signal_connect (G_OBJECT (new), "ifnet_setup_monitors",
		                  G_CALLBACK (setup_monitors), config);
		g_signal_connect (G_OBJECT (new), "ifnet_cancel_monitors",
		                  G_CALLBACK (cancel_monitors), config);

		old = g_hash_table_lookup (priv->connections,
		                           nm_connection_get_uuid (NM_CONNECTION (new)));
		if (old && new) {
			if (auto_refresh) {
				/* If connection has changed, remove the old one and add the
				 * new one to force a disconnect/reconnect with new settings
				 */
				if (!nm_connection_compare (NM_CONNECTION (old),
				                            NM_CONNECTION (new),
				                            NM_SETTING_COMPARE_FLAG_IGNORE_AGENT_OWNED_SECRETS |
				                              NM_SETTING_COMPARE_FLAG_IGNORE_NOT_SAVED_SECRETS)) {
					nm_log_info (LOGD_SETTINGS, "Auto refreshing %s", conn_name);

					nm_settings_connection_signal_remove (NM_SETTINGS_CONNECTION (old));
					track_new_connection (self, new);
					if (is_managed_plugin () && is_managed (conn_name))
						g_signal_emit_by_name (self, NM_SYSTEM_CONFIG_INTERFACE_CONNECTION_ADDED, new);
				}
			} else {
				/* Update existing connection with new settings */
				if (!nm_settings_connection_replace_settings (NM_SETTINGS_CONNECTION (old),
				                                              NM_CONNECTION (new),
				                                              FALSE,  /* don't set Unsaved */
				                                              "ifnet-update",
				                                              &error)) {
					/* Shouldn't ever get here as 'new' was verified by the reader already
					 * and the UUID did not change. */
					g_assert_not_reached ();
				}
				g_assert_no_error (error);
				nm_log_info (LOGD_SETTINGS, "Connection %s updated",
				             nm_connection_get_id (NM_CONNECTION (new)));
			}
			g_signal_emit_by_name (self, NM_SYSTEM_CONFIG_INTERFACE_UNMANAGED_SPECS_CHANGED);
		} else if (new) {
			track_new_connection (self, new);
			if (is_managed_plugin () && is_managed (conn_name))
				g_signal_emit_by_name (self, NM_SYSTEM_CONFIG_INTERFACE_CONNECTION_ADDED, new);
		}

		/* Track all valid connections so we can remove deleted ones later */
		g_hash_table_insert (new_connections,
		                     (gpointer) nm_connection_get_uuid (NM_CONNECTION (new)),
		                     new);
	}

	/* remove deleted/unused connections */
	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, (gpointer) &uuid, (gpointer) &candidate)) {
		/* only saved connections (which have a conn_name) get removed; unsaved
		 * ones obviously don't exist in /etc/conf.d/net yet and shouldn't get
		 * blown away by net file changes.
		 */
		if (   nm_ifnet_connection_get_conn_name (NM_IFNET_CONNECTION (candidate))
		    && !g_hash_table_lookup (new_connections, uuid)) {
			nm_settings_connection_signal_remove (candidate);
			g_hash_table_iter_remove (&iter);
		}
	}
	g_hash_table_destroy (new_connections);
	g_list_free (conn_names);
}

static NMSettingsConnection *
add_connection (NMSystemConfigInterface *config,
                NMConnection *source,
                gboolean save_to_disk,
                GError **error)
{
	SCPluginIfnetPrivate *priv = SC_PLUGIN_IFNET_GET_PRIVATE (config);
	NMIfnetConnection *new = NULL;

	/* Ensure we reject attempts to add the connection long before we're
	 * asked to write it to disk.
	 */
	if (!ifnet_can_write_connection (source, error))
		return NULL;

	if (save_to_disk) {
		if (!ifnet_add_new_connection (source, CONF_NET_FILE, WPA_SUPPLICANT_CONF, NULL, NULL, error))
			return NULL;
		reload_connections (config);
		new = g_hash_table_lookup (priv->connections, nm_connection_get_uuid (source));
	} else {
		new = nm_ifnet_connection_new (source, NULL);
		if (new) {
			track_new_connection (SC_PLUGIN_IFNET (config), new);
			/* track_new_connection refs 'new' */
			g_object_unref (new);
		}
	}

	return (NMSettingsConnection *) new;
}

static void
check_unmanaged (gpointer key, gpointer data, gpointer user_data)
{
	NMIfnetConnection *connection = NM_IFNET_CONNECTION (data);
	GSList **list = (GSList **) user_data;
	const char *mac, *conn_name;
	char *unmanaged_spec;
	GSList *iter;

	conn_name = nm_ifnet_connection_get_conn_name (connection);

	if (!conn_name || is_managed (conn_name))
		return;

	nm_log_info (LOGD_SETTINGS, "Checking unmanaged: %s", conn_name);
	mac = ifnet_get_data (conn_name, "mac");
	if (mac)
		unmanaged_spec = g_strdup_printf ("mac:%s", mac);
	else
		unmanaged_spec = g_strdup_printf ("interface-name:%s", conn_name);

	/* Just return if the unmanaged spec is already in the list */
	for (iter = *list; iter; iter = g_slist_next (iter)) {
		if (g_str_equal (iter->data, unmanaged_spec)) {
			g_free (unmanaged_spec);
			return;
		}
	}

	nm_log_info (LOGD_SETTINGS, "Add unmanaged: %s", unmanaged_spec);
	*list = g_slist_prepend (*list, unmanaged_spec);
}

static GSList *
get_unmanaged_specs (NMSystemConfigInterface * config)
{
	SCPluginIfnetPrivate *priv = SC_PLUGIN_IFNET_GET_PRIVATE (config);
	GSList *list = NULL;

	nm_log_info (LOGD_SETTINGS, "getting unmanaged specs...");
	g_hash_table_foreach (priv->connections, check_unmanaged, &list);
	return list;
}

static void
init (NMSystemConfigInterface *config)
{
	SCPluginIfnet *self = SC_PLUGIN_IFNET (config);
	SCPluginIfnetPrivate *priv = SC_PLUGIN_IFNET_GET_PRIVATE (self);

	nm_log_info (LOGD_SETTINGS, "Initializing!");

	priv->connections = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_object_unref);
	priv->unmanaged_well_known = !is_managed_plugin ();
	nm_log_info (LOGD_SETTINGS, "management mode: %s",
	             priv->unmanaged_well_known ? "unmanaged" : "managed");

	setup_monitors (NULL, config);
	reload_connections (config);

	nm_log_info (LOGD_SETTINGS, "Initialzation complete!");
}

static GSList *
get_connections (NMSystemConfigInterface *config)
{
	SCPluginIfnetPrivate *priv = SC_PLUGIN_IFNET_GET_PRIVATE (config);
	GSList *connections = NULL;
	GHashTableIter iter;
	NMIfnetConnection *connection;

	nm_log_info (LOGD_SETTINGS, "(%p) ... get_connections.", config);

	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer) &connection)) {
		const char *conn_name = nm_ifnet_connection_get_conn_name (connection);

		if (!conn_name || (!priv->unmanaged_well_known && is_managed (conn_name)))
			connections = g_slist_prepend (connections, connection);
	}
	nm_log_info (LOGD_SETTINGS, "(%p) connections count: %d",
	             config, g_slist_length (connections));
	return connections;
}

static void
system_config_interface_init (NMSystemConfigInterface *class)
{
	class->init = init;
	class->get_connections = get_connections;
	class->get_unmanaged_specs = get_unmanaged_specs;
	class->add_connection = add_connection;
	class->reload_connections = reload_connections;
}

static void
sc_plugin_ifnet_init (SCPluginIfnet * plugin)
{
}

static void
get_property (GObject * object, guint prop_id, GValue * value,
	      GParamSpec * pspec)
{
	switch (prop_id) {
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_NAME:
		g_value_set_string (value, IFNET_PLUGIN_NAME_PRINT);
		break;
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_INFO:
		g_value_set_string (value, IFNET_PLUGIN_INFO);
		break;
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_CAPABILITIES:
		g_value_set_uint (value,
		                  NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_CONNECTIONS);
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
	if (priv->connections) {
		g_hash_table_destroy (priv->connections);
		priv->connections = NULL;
	}

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
}

G_MODULE_EXPORT GObject *
nm_system_config_factory (void)
{
	static SCPluginIfnet *singleton = NULL;
	SCPluginIfnetPrivate *priv;

	if (!singleton) {
		singleton = SC_PLUGIN_IFNET (g_object_new (SC_TYPE_PLUGIN_IFNET, NULL));
		priv = SC_PLUGIN_IFNET_GET_PRIVATE (singleton);
	} else
		g_object_ref (singleton);

	return G_OBJECT (singleton);
}
