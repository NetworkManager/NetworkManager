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

#include <config.h>
#include <gmodule.h>
#include <glib-object.h>
#include <glib/gi18n.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>

#ifndef NO_GIO
#include <gio/gio.h>
#else
#include <gfilemonitor/gfilemonitor.h>
#endif

#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>

#include "plugin.h"
#include "parser.h"
#include "nm-suse-connection.h"
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
	DBusGConnection *dbus_connection;
	NMSystemConfigHalManager *hal_manager;

	gboolean initialized;
	GHashTable *connections;
	GHashTable *unmanaged_devices;

	guint32 default_gw;
	GFileMonitor *default_gw_monitor;
	guint default_gw_monitor_id;
} SCPluginIfcfgPrivate;

GQuark
ifcfg_plugin_error_quark (void)
{
	static GQuark error_quark = 0;

	if (G_UNLIKELY (error_quark == 0))
		error_quark = g_quark_from_static_string ("ifcfg-plugin-error-quark");

	return error_quark;
}

static void
update_one_connection (gpointer key, gpointer val, gpointer user_data)
{
	NMExportedConnection *exported = NM_EXPORTED_CONNECTION (val);
	NMConnection *connection;
	NMSettingIP4Config *ip4_config;

	connection = nm_exported_connection_get_connection (exported);
	ip4_config = (NMSettingIP4Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG);
	if (!ip4_config)
		return;

	if (ip4_config->addresses) {
		/* suse only has one address per device */
		NMSettingIP4Address *ip4_address = (NMSettingIP4Address *) ip4_config->addresses->data;
		SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (user_data);
		GHashTable *settings;

		if (ip4_address->gateway != priv->default_gw) {
			ip4_address->gateway = priv->default_gw;
			settings = nm_connection_to_hash (connection);
			nm_exported_connection_signal_updated (exported, settings);
			g_hash_table_destroy (settings);
		}
	}
}

static void
update_connections (SCPluginIfcfg *self)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (self);

	g_hash_table_foreach (priv->connections, update_one_connection, self);
}

static void
routes_changed (GFileMonitor *monitor,
			 GFile *file,
			 GFile *other_file,
			 GFileMonitorEvent event_type,
			 gpointer user_data)
{
	SCPluginIfcfg *self = SC_PLUGIN_IFCFG (user_data);
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (self);
	char *filename;
	guint32 new_gw;

	switch (event_type) {
	case G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT:
	case G_FILE_MONITOR_EVENT_DELETED:
		filename = g_file_get_path (file);
		new_gw = parser_parse_routes (filename);
		g_free (filename);

		if (priv->default_gw != new_gw) {
			priv->default_gw = new_gw;
			update_connections (self);
		}
		break;
	default:
		break;
	}
}

static void
monitor_routes (SCPluginIfcfg *self, const char *filename)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (self);
	GFile *file;
	GFileMonitor *monitor;

	file = g_file_new_for_path (filename);
	monitor = g_file_monitor_file (file, G_FILE_MONITOR_NONE, NULL, NULL);
	g_object_unref (file);

	if (monitor) {
		priv->default_gw_monitor_id = g_signal_connect (monitor, "changed", G_CALLBACK (routes_changed), self);
		priv->default_gw_monitor = monitor;
	}
}

static char *
get_iface_by_udi (SCPluginIfcfg *self, const char *udi)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (self);
	DBusGProxy *proxy;
	char *iface = NULL;

	proxy = dbus_g_proxy_new_for_name (priv->dbus_connection,
								"org.freedesktop.Hal",
								udi,
								"org.freedesktop.Hal.Device");

	dbus_g_proxy_call_with_timeout (proxy, "GetPropertyString", 10000, NULL,
							  G_TYPE_STRING, "net.interface", G_TYPE_INVALID,
							  G_TYPE_STRING, &iface, G_TYPE_INVALID);
	g_object_unref (proxy);

	return iface;
}

static void
read_connection (SCPluginIfcfg *self, const char *udi, NMDeviceType dev_type)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (self);
	char *iface;

	iface = get_iface_by_udi (self, udi);
	if (iface) {
		if (parser_ignore_device (iface)) {
			g_hash_table_insert (priv->unmanaged_devices, g_strdup (udi), GINT_TO_POINTER (1));
			g_signal_emit_by_name (self, "unmanaged-devices-changed");
		} else {
			NMSuseConnection *connection;

			connection = nm_suse_connection_new (iface, dev_type);
			if (connection) {
				g_hash_table_insert (priv->connections, g_strdup (udi), connection);
				g_signal_emit_by_name (self, "connection-added", connection);
			}
		}
	}

	g_free (iface);
}

static void
read_connections_by_type (SCPluginIfcfg *self, NMDeviceType dev_type)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (self);
	GSList *list;
	GSList *iter;

	list = nm_system_config_hal_manager_get_devices_of_type (priv->hal_manager, dev_type);
	for (iter = list; iter; iter = iter->next) {
		read_connection (self, (char *) iter->data, dev_type);
		g_free (iter->data);
	}

	g_slist_free (list);
}

static void
device_added_cb (NMSystemConfigHalManager *hal_mgr,
                 const char *udi,
                 NMDeviceType dev_type,
                 gpointer user_data)
{
	SCPluginIfcfg *self = SC_PLUGIN_IFCFG (user_data);

	if (dev_type != DEVICE_TYPE_802_3_ETHERNET && dev_type != DEVICE_TYPE_802_11_WIRELESS)
		return;

	read_connection (self, udi, dev_type);
}

static void
device_removed_cb (NMSystemConfigHalManager *hal_mgr,
                   const char *udi,
                   NMDeviceType dev_type,
                   gpointer user_data)
{
	SCPluginIfcfg *self = SC_PLUGIN_IFCFG (user_data);
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (self);
	NMExportedConnection *exported;

	if (dev_type != DEVICE_TYPE_802_3_ETHERNET && dev_type != DEVICE_TYPE_802_11_WIRELESS)
		return;

	if (g_hash_table_remove (priv->unmanaged_devices, udi))
		g_signal_emit_by_name (self, "unmanaged-devices-changed");

	exported = (NMExportedConnection *) g_hash_table_lookup (priv->connections, udi);
	if (exported) {
		nm_exported_connection_signal_removed (exported);
		g_hash_table_remove (priv->connections, udi);
	}
}

static void
init (NMSystemConfigInterface *config, NMSystemConfigHalManager *hal_manager)
{
	SCPluginIfcfg *self = SC_PLUGIN_IFCFG (config);
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (self);

	priv->hal_manager = g_object_ref (hal_manager);

	g_signal_connect (priv->hal_manager, "device-added", G_CALLBACK (device_added_cb), self);
	g_signal_connect (priv->hal_manager, "device-removed", G_CALLBACK (device_removed_cb), self);
}

static void
get_connections_cb (gpointer key, gpointer val, gpointer user_data)
{
	GSList **list = (GSList **) user_data;

	*list = g_slist_prepend (*list, val);
}

static GSList *
get_connections (NMSystemConfigInterface *config)
{
	SCPluginIfcfg *self = SC_PLUGIN_IFCFG (config);
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (self);
	GSList *list = NULL;

	if (!priv->initialized) {
		const char *filename;

		read_connections_by_type (self, DEVICE_TYPE_802_3_ETHERNET);
		read_connections_by_type (self, DEVICE_TYPE_802_11_WIRELESS);

		filename = SYSCONFDIR"/sysconfig/network/routes";
		monitor_routes (self, filename);
		priv->default_gw = parser_parse_routes (filename);
		if (priv->default_gw)
			update_connections (self);

		priv->initialized = TRUE;
	}

	g_hash_table_foreach (priv->connections, get_connections_cb, &list);

	return list;
}

static void
get_unamanged_devices_cb (gpointer key, gpointer val, gpointer user_data)
{
	GSList **list = (GSList **) key;

	*list = g_slist_prepend (*list, g_strdup ((char *) key));
}

static GSList *
get_unmanaged_devices (NMSystemConfigInterface *config)
{
	GSList *list = NULL;

	g_hash_table_foreach (SC_PLUGIN_IFCFG_GET_PRIVATE (config)->unmanaged_devices,
					  get_unamanged_devices_cb, &list);

	return list;
}

static void
sc_plugin_ifcfg_init (SCPluginIfcfg *self)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (self);
	GError *err = NULL;

	priv->connections = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_object_unref);
	priv->unmanaged_devices = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

	priv->dbus_connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, &err);
	if (!priv->dbus_connection) {
		PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "    dbus-glib error: %s",
		              err->message ? err->message : "(unknown)");
		g_error_free (err);
	}
}

static void
dispose (GObject *object)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (object);

	g_hash_table_destroy (priv->connections);
	g_hash_table_destroy (priv->unmanaged_devices);

	if (priv->default_gw_monitor) {
		if (priv->default_gw_monitor_id)
			g_signal_handler_disconnect (priv->default_gw_monitor, priv->default_gw_monitor_id);

		g_file_monitor_cancel (priv->default_gw_monitor);
		g_object_unref (priv->default_gw_monitor);
	}

	if (priv->hal_manager)
		g_object_unref (priv->hal_manager);

	dbus_g_connection_unref (priv->dbus_connection);

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
	system_config_interface_class->get_unmanaged_devices = get_unmanaged_devices;
	system_config_interface_class->init = init;
}

G_MODULE_EXPORT GObject *
nm_system_config_factory (void)
{
	static SCPluginIfcfg *singleton = NULL;

	if (!singleton)
		singleton = SC_PLUGIN_IFCFG (g_object_new (SC_TYPE_PLUGIN_IFCFG, NULL));
	else
		g_object_ref (singleton);

	return G_OBJECT (singleton);
}
