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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2007 - 2009 Red Hat, Inc.
 * (C) Copyright 2007 - 2008 Novell, Inc.
 */

#include <config.h>
#include <gmodule.h>
#include <glib-object.h>
#include <glib/gi18n.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#ifndef NO_GIO
#include <gio/gio.h>
#else
#include <gfilemonitor/gfilemonitor.h>
#endif

#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>

#define G_UDEV_API_IS_SUBJECT_TO_CHANGE
#include <gudev/gudev.h>

#include "plugin.h"
#include "parser.h"
#include "nm-suse-connection.h"
#include "nm-system-config-interface.h"
#include "wireless-helper.h"

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
	GUdevClient *client;

	gboolean initialized;
	GHashTable *connections;
	GHashTable *unmanaged_specs;

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
ignore_cb (NMSettingsConnectionInterface *connection,
           GError *error,
           gpointer user_data)
{
}

static void
update_connections (SCPluginIfcfg *self)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (self);
	GHashTableIter iter;
	gpointer value;

	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, NULL, &value)) {
		NMSuseConnection *exported = NM_SUSE_CONNECTION (value);
		NMSettingIP4Config *ip4_config;

		ip4_config = (NMSettingIP4Config *) nm_connection_get_setting (NM_CONNECTION (exported), NM_TYPE_SETTING_IP4_CONFIG);
		if (!ip4_config)
			continue;

		if (nm_setting_ip4_config_get_num_addresses (ip4_config)) {
			/* suse only has one address per device */
			NMIP4Address *ip4_address;

			ip4_address = nm_setting_ip4_config_get_address (ip4_config, 0);
			if (nm_ip4_address_get_gateway (ip4_address) != priv->default_gw) {
				nm_ip4_address_set_gateway (ip4_address, priv->default_gw);
				nm_settings_connection_interface_update (NM_SETTINGS_CONNECTION_INTERFACE (exported),
				                                         ignore_cb,
				                                         NULL);
			}
		}
	}
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

static void
read_connection (SCPluginIfcfg *self, GUdevDevice *device, NMDeviceType dev_type)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (self);
	const char *iface, *address;
	guint32 ifindex;

	iface = g_udev_device_get_name (device);
	if (!iface)
		return;

	ifindex = (guint32) g_udev_device_get_property_as_uint64 (device, "IFINDEX");

	if (parser_ignore_device (iface)) {
		char *spec;

		address = g_udev_device_get_sysfs_attr (device, "address");
		if (address && (strlen (address) == 17)) {
			spec = g_strdup_printf ("mac:%s", address);
			g_hash_table_insert (priv->unmanaged_specs, GUINT_TO_POINTER (ifindex), spec);
			g_signal_emit_by_name (self, NM_SYSTEM_CONFIG_INTERFACE_UNMANAGED_SPECS_CHANGED);
		} else
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    (%s) error getting hardware address", iface);
	} else {
		NMSuseConnection *connection;

		connection = nm_suse_connection_new (iface, dev_type);
		if (connection) {
			g_hash_table_insert (priv->connections,
			                     GUINT_TO_POINTER (ifindex),
			                     connection);
			g_signal_emit_by_name (self, NM_SYSTEM_CONFIG_INTERFACE_CONNECTION_ADDED, connection);
		}
	}
}

static void
read_connections_by_type (SCPluginIfcfg *self, NMDeviceType dev_type)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (self);
	GList *devices, *iter;

	if (   (dev_type != NM_DEVICE_TYPE_ETHERNET)
	    && (dev_type != NM_DEVICE_TYPE_WIFI))
		return;

	devices = g_udev_client_query_by_subsystem (priv->client, "net");
	for (iter = devices; iter; iter = g_list_next (iter)) {
		read_connection (self, G_UDEV_DEVICE (iter->data), dev_type);
		g_object_unref (G_UDEV_DEVICE (iter->data));
	}
	g_list_free (devices);
}

static gboolean
is_wireless (GUdevDevice *device)
{
	char phy80211_path[255];
	struct stat s;
	int fd;
	struct iwreq iwr;
	const char *ifname, *path;
	gboolean is_wifi = FALSE;

	ifname = g_udev_device_get_name (device);
	g_assert (ifname);

	fd = socket (PF_INET, SOCK_DGRAM, 0);
	strncpy (iwr.ifr_ifrn.ifrn_name, ifname, IFNAMSIZ);

	path = g_udev_device_get_sysfs_path (device);
	snprintf (phy80211_path, sizeof (phy80211_path), "%s/phy80211", path);

	if (   (ioctl (fd, SIOCGIWNAME, &iwr) == 0)
	    || (stat (phy80211_path, &s) == 0 && (s.st_mode & S_IFDIR)))
		is_wifi = TRUE;

	close (fd);
	return is_wifi;
}

static void
handle_uevent (GUdevClient *client,
               const char *action,
               GUdevDevice *device,
               gpointer user_data)
{
	SCPluginIfcfg *self = SC_PLUGIN_IFCFG (user_data);
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (self);
	const char *subsys;
	gboolean wifi;

	g_return_if_fail (action != NULL);

	/* A bit paranoid */
	subsys = g_udev_device_get_subsystem (device);
	g_return_if_fail (subsys != NULL);
	g_return_if_fail (strcmp (subsys, "net") == 0);

	wifi = is_wireless (device);

	if (!strcmp (action, "add")) {
		read_connection (self,
		                 device,
		                 wifi ? NM_DEVICE_TYPE_WIFI : NM_DEVICE_TYPE_ETHERNET);
	} else if (!strcmp (action, "remove")) {
		NMExportedConnection *exported;
		guint32 ifindex;

		ifindex = (guint32) g_udev_device_get_property_as_uint64 (device, "IFINDEX");
		if (g_hash_table_remove (priv->unmanaged_specs, GUINT_TO_POINTER (ifindex)))
			g_signal_emit_by_name (self, NM_SYSTEM_CONFIG_INTERFACE_UNMANAGED_SPECS_CHANGED);

		exported = (NMExportedConnection *) g_hash_table_lookup (priv->connections,
		                                                         GUINT_TO_POINTER (ifindex));
		if (exported) {
			nm_settings_connection_interface_delete (NM_SETTINGS_CONNECTION_INTERFACE (exported),
			                                         ignore_cb,
			                                         NULL);
			g_hash_table_remove (priv->connections, GUINT_TO_POINTER (ifindex));
		}
	}
}

static void
init (NMSystemConfigInterface *config)
{
	SCPluginIfcfg *self = SC_PLUGIN_IFCFG (config);
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (self);
	const char *subsys[2] = { "net", NULL };

	priv->client = g_udev_client_new (subsys);
	if (!priv->client) {
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    error initializing libgudev");
	} else
		g_signal_connect (priv->client, "uevent", G_CALLBACK (handle_uevent), self);
}

static GSList *
get_connections (NMSystemConfigInterface *config)
{
	SCPluginIfcfg *self = SC_PLUGIN_IFCFG (config);
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (self);
	GSList *list = NULL;
	GHashTableIter iter;
	gpointer value;

	if (!priv->initialized) {
		const char *filename;

		read_connections_by_type (self, NM_DEVICE_TYPE_ETHERNET);
		read_connections_by_type (self, NM_DEVICE_TYPE_WIFI);

		filename = SYSCONFDIR"/sysconfig/network/routes";
		monitor_routes (self, filename);
		priv->default_gw = parser_parse_routes (filename);
		if (priv->default_gw)
			update_connections (self);

		priv->initialized = TRUE;
	}

	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, NULL, &value))
		list = g_slist_prepend (list, value);

	return list;
}

static void
add_one_unmanaged_spec (gpointer key, gpointer val, gpointer user_data)
{
	GSList **list = (GSList **) key;

	*list = g_slist_prepend (*list, g_strdup ((const char *) val));
}

static GSList *
get_unmanaged_specs (NMSystemConfigInterface *config)
{
	SCPluginIfcfg *self = SC_PLUGIN_IFCFG (config);
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (self);
	GSList *list = NULL;

	g_hash_table_foreach (priv->unmanaged_specs, add_one_unmanaged_spec, &list);
	return list;
}

static void
sc_plugin_ifcfg_init (SCPluginIfcfg *self)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (self);

	priv->connections = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, g_object_unref);
	priv->unmanaged_specs = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, g_free);
}

static void
dispose (GObject *object)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (object);

	g_hash_table_destroy (priv->connections);
	g_hash_table_destroy (priv->unmanaged_specs);

	if (priv->default_gw_monitor) {
		if (priv->default_gw_monitor_id)
			g_signal_handler_disconnect (priv->default_gw_monitor, priv->default_gw_monitor_id);

		g_file_monitor_cancel (priv->default_gw_monitor);
		g_object_unref (priv->default_gw_monitor);
	}

	if (priv->client)
		g_object_unref (priv->client);

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
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_CAPABILITIES:
		g_value_set_uint (value, NM_SYSTEM_CONFIG_INTERFACE_CAP_NONE);
		break;
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_HOSTNAME:
		g_value_set_string (value, "");
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

	g_object_class_override_property (object_class,
							    NM_SYSTEM_CONFIG_INTERFACE_PROP_CAPABILITIES,
							    NM_SYSTEM_CONFIG_INTERFACE_CAPABILITIES);

	g_object_class_override_property (object_class,
							    NM_SYSTEM_CONFIG_INTERFACE_PROP_HOSTNAME,
							    NM_SYSTEM_CONFIG_INTERFACE_HOSTNAME);
}

static void
system_config_interface_init (NMSystemConfigInterface *system_config_interface_class)
{
	/* interface implementation */
	system_config_interface_class->get_connections = get_connections;
	system_config_interface_class->get_unmanaged_specs = get_unmanaged_specs;
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
