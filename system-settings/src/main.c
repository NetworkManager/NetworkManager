/* NetworkManager system settings service
 *
 * Søren Sandmann <sandmann@daimi.au.dk>
 * Dan Williams <dcbw@redhat.com>
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
 * (C) Copyright 2007 - 2008 Red Hat, Inc.
 */

#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

#include <glib.h>
#include <glib/gi18n.h>
#include <gmodule.h>

#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>

#include <nm-connection.h>
#include <nm-setting-connection.h>
#include <nm-setting-wired.h>
#include <nm-setting-pppoe.h>
#include <nm-settings.h>
#include <nm-utils.h>
#include <NetworkManager.h>

#include "dbus-settings.h"
#include "nm-system-config-hal-manager.h"
#include "nm-system-config-interface.h"

typedef struct {
	DBusConnection *connection;
	DBusGConnection *g_connection;

	DBusGProxy *bus_proxy;
	NMSystemConfigHalManager *hal_mgr;

	NMSysconfigSettings *settings;
	GMainLoop *loop;

	GHashTable *wired_devices;
} Application;


NMSystemConfigHalManager *nm_system_config_hal_manager_get (DBusGConnection *g_connection);

static gboolean dbus_init (Application *app);
static gboolean start_dbus_service (Application *app);
static void destroy_cb (DBusGProxy *proxy, gpointer user_data);
static void device_added_cb (DBusGProxy *proxy, const char *udi, NMDeviceType devtype, gpointer user_data);


static GQuark
plugins_error_quark (void)
{
	static GQuark error_quark = 0;

	if (G_UNLIKELY (error_quark == 0))
		error_quark = g_quark_from_static_string ("plugins-error-quark");

	return error_quark;
}

static GObject *
find_plugin (GSList *list, const char *pname)
{
	GSList *iter;
	GObject *obj = NULL;

	g_return_val_if_fail (pname != NULL, FALSE);

	for (iter = list; iter && !obj; iter = g_slist_next (iter)) {
		NMSystemConfigInterface *plugin = NM_SYSTEM_CONFIG_INTERFACE (iter->data);
		char *list_pname = NULL;

		g_object_get (G_OBJECT (plugin),
		              NM_SYSTEM_CONFIG_INTERFACE_NAME,
		              &list_pname,
		              NULL);
		if (list_pname && !strcmp (pname, list_pname))
			obj = G_OBJECT (plugin);

		g_free (list_pname);
	}

	return obj;
}

static gboolean
load_plugins (Application *app, const char *plugins, GError **error)
{
	GSList *list = NULL;
	char **plist;
	char **pname;

	plist = g_strsplit (plugins, ",", 0);
	if (!plist)
		return FALSE;

	for (pname = plist; *pname; pname++) {
		GModule *plugin;
		char *full_name;
		char *path;
		GObject *obj;
		GObject * (*factory_func) (void);

		obj = find_plugin (list, *pname);
		if (obj)
			continue;

		full_name = g_strdup_printf ("nm-settings-plugin-%s", *pname);
		path = g_module_build_path (PLUGINDIR, full_name);

		plugin = g_module_open (path, G_MODULE_BIND_LOCAL);
		if (!plugin) {
			g_set_error (error, plugins_error_quark (), 0,
			             "Could not load plugin '%s': %s",
			             *pname, g_module_error ());
			g_free (full_name);
			g_free (path);
			break;
		}

		g_free (full_name);
		g_free (path);

		if (!g_module_symbol (plugin, "nm_system_config_factory", (gpointer) (&factory_func))) {
			g_set_error (error, plugins_error_quark (), 0,
			             "Could not find plugin '%s' factory function.",
			             *pname);
			break;
		}

		obj = (*factory_func) ();
		if (!obj || !NM_IS_SYSTEM_CONFIG_INTERFACE (obj)) {
			g_set_error (error, plugins_error_quark (), 0,
			             "Plugin '%s' returned invalid system config object.",
			             *pname);
			break;
		}

		g_module_make_resident (plugin);
		g_object_weak_ref (obj, (GWeakNotify) g_module_close, plugin);
		nm_sysconfig_settings_add_plugin (app->settings, NM_SYSTEM_CONFIG_INTERFACE (obj));
		list = g_slist_append (list, obj);
	}

	g_strfreev (plist);

	g_slist_foreach (list, (GFunc) g_object_unref, NULL);
	g_slist_free (list);

	return TRUE;
}

static gboolean
load_stuff (gpointer user_data)
{
	Application *app = (Application *) user_data;
	GSList *devs, *iter;

	/* Grab wired devices to make default DHCP connections for them if needed */
	devs = nm_system_config_hal_manager_get_devices_of_type (app->hal_mgr, NM_DEVICE_TYPE_ETHERNET);
	for (iter = devs; iter; iter = g_slist_next (iter)) {
		device_added_cb (NULL, (const char *) iter->data, NM_DEVICE_TYPE_ETHERNET, app);
		g_free (iter->data);
	}

	g_slist_free (devs);

	if (!start_dbus_service (app)) {
		g_main_loop_quit (app->loop);
		return FALSE;
	}

	return FALSE;
}

typedef struct {
	Application *app;
	NMExportedConnection *connection;
	guint add_id;
	char *udi;
	GByteArray *mac;
	char *iface;
} WiredDeviceInfo;

static void
wired_device_info_destroy (gpointer user_data)
{
	WiredDeviceInfo *info = (WiredDeviceInfo *) user_data;

	g_free (info->iface);
	if (info->mac)
		g_byte_array_free (info->mac, TRUE);
	if (info->add_id)
		g_source_remove (info->add_id);
	if (info->connection) {
		nm_sysconfig_settings_remove_connection (info->app->settings, info->connection);
		g_object_unref (info->connection);
	}
	g_free (info);
}

static char *
get_details_for_udi (Application *app, const char *udi, struct ether_addr *mac)
{
	DBusGProxy *dev_proxy = NULL;
	char *address = NULL;
	char *iface = NULL;
	struct ether_addr *temp;
	GError *error = NULL;

	g_return_val_if_fail (app != NULL, FALSE);
	g_return_val_if_fail (udi != NULL, FALSE);
	g_return_val_if_fail (mac != NULL, FALSE);

	dev_proxy = dbus_g_proxy_new_for_name (app->g_connection,
	                                       "org.freedesktop.Hal",
	                                       udi,
	                                       "org.freedesktop.Hal.Device");
	if (!dev_proxy)
		goto out;

	if (!dbus_g_proxy_call_with_timeout (dev_proxy,
	                                     "GetPropertyString", 5000, &error,
	                                     G_TYPE_STRING, "net.address", G_TYPE_INVALID,
	                                     G_TYPE_STRING, &address, G_TYPE_INVALID)) {
		g_message ("Error getting hardware address for %s: (%d) %s",
		           udi, error->code, error->message);
		g_error_free (error);
		goto out;
	}

	if (!address && !strlen (address))
		goto out;

	temp = ether_aton (address);
	if (!temp)
		goto out;
	memcpy (mac, temp, sizeof (struct ether_addr));

	if (!dbus_g_proxy_call_with_timeout (dev_proxy,
	                                     "GetPropertyString", 5000, &error,
	                                     G_TYPE_STRING, "net.interface", G_TYPE_INVALID,
	                                     G_TYPE_STRING, &iface, G_TYPE_INVALID)) {
		g_message ("Error getting interface name for %s: (%d) %s",
		           udi, error->code, error->message);
		g_error_free (error);
	}

out:
	g_free (address);
	if (dev_proxy)
		g_object_unref (dev_proxy);
	return iface;
}

static gboolean
have_connection_for_device (Application *app, GByteArray *mac)
{
	GSList *list, *iter;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	const GByteArray *setting_mac;
	gboolean ret = FALSE;

	g_return_val_if_fail (app != NULL, FALSE);
	g_return_val_if_fail (mac != NULL, FALSE);

	/* If the device doesn't have a connection advertised by any of the
	 * plugins, create a new default DHCP-enabled connection for it.
	 */
	list = nm_settings_list_connections (NM_SETTINGS (app->settings));
	for (iter = list; iter; iter = g_slist_next (iter)) {
		NMExportedConnection *exported = NM_EXPORTED_CONNECTION (iter->data);
		NMConnection *connection;
		const char *connection_type;

		connection = nm_exported_connection_get_connection (exported);
		if (!connection)
			continue;

		s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
		connection_type = nm_setting_connection_get_connection_type (s_con);

		if (   strcmp (connection_type, NM_SETTING_WIRED_SETTING_NAME)
		    && strcmp (connection_type, NM_SETTING_PPPOE_SETTING_NAME))
			continue;

		s_wired = (NMSettingWired *) nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRED);

		/* No wired setting; therefore the PPPoE connection applies to any device */
		if (!s_wired && !strcmp (connection_type, NM_SETTING_PPPOE_SETTING_NAME)) {
			ret = TRUE;
			break;
		}

		setting_mac = nm_setting_wired_get_mac_address (s_wired);
		if (setting_mac) {
			/* A connection mac-locked to this device */
			if (!memcmp (setting_mac->data, mac->data, ETH_ALEN)) {
				ret = TRUE;
				break;
			}

		} else {
			/* A connection that applies to any wired device */
			ret = TRUE;
			break;
		}
	}

	g_slist_free (list);

	return ret;
}

static gboolean
add_default_dhcp_connection (gpointer user_data)
{
	WiredDeviceInfo *info = (WiredDeviceInfo *) user_data;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMConnection *wrapped;
	GByteArray *setting_mac;
	char *id;
	char *uuid;

	if (info->add_id)
		info->add_id = 0;

	/* If the device isn't managed, ignore it */
	if (!nm_sysconfig_settings_is_device_managed (info->app->settings, info->udi))
		goto ignore;

	if (!info->iface) {
		struct ether_addr mac;

		info->iface = get_details_for_udi (info->app, info->udi, &mac);
		if (!info->iface)
			goto ignore;
		info->mac = g_byte_array_sized_new (ETH_ALEN);
		g_byte_array_append (info->mac, mac.ether_addr_octet, ETH_ALEN);
	}

	if (have_connection_for_device (info->app, info->mac))
		goto ignore;

	wrapped = nm_connection_new ();
	info->connection = nm_exported_connection_new (wrapped);
	g_object_unref (wrapped);

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());

	id = g_strdup_printf (_("Auto %s"), info->iface);
	uuid = nm_utils_uuid_generate ();

	g_object_set (s_con,
		      NM_SETTING_CONNECTION_ID, id,
		      NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
		      NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
		      NM_SETTING_CONNECTION_UUID, uuid,
		      NULL);

	nm_connection_add_setting (wrapped, NM_SETTING (s_con));

	g_message ("Adding default connection '%s' for %s", id, info->udi);
		
	g_free (id);
	g_free (uuid);

	/* Lock the connection to this device */
	s_wired = NM_SETTING_WIRED (nm_setting_wired_new ());

	setting_mac = g_byte_array_sized_new (ETH_ALEN);
	g_byte_array_append (setting_mac, info->mac->data, ETH_ALEN);
	g_object_set (s_wired, NM_SETTING_WIRED_MAC_ADDRESS, setting_mac, NULL);
	g_byte_array_free (setting_mac, TRUE);

	nm_connection_add_setting (wrapped, NM_SETTING (s_wired));

	nm_sysconfig_settings_add_connection (info->app->settings, info->connection);

	return FALSE;

ignore:
	g_hash_table_remove (info->app->wired_devices, info->udi);
	return FALSE;
}

static void
device_added_cb (DBusGProxy *proxy, const char *udi, NMDeviceType devtype, gpointer user_data)
{
	Application *app = (Application *) user_data;
	WiredDeviceInfo *info;

	if (devtype != NM_DEVICE_TYPE_ETHERNET)
		return;

	/* Wait for a plugin to figure out if the device should be managed or not */
	info = g_malloc0 (sizeof (WiredDeviceInfo));
	info->app = app;
	info->add_id = g_timeout_add (4000, add_default_dhcp_connection, info);
	info->udi = g_strdup (udi);
	g_hash_table_insert (app->wired_devices, info->udi, info);
}

static void
device_removed_cb (DBusGProxy *proxy, const char *udi, NMDeviceType devtype, gpointer user_data)
{
	Application *app = (Application *) user_data;

	g_hash_table_remove (app->wired_devices, udi);
}

/******************************************************************/

static void
dbus_cleanup (Application *app)
{
	if (app->g_connection) {
		dbus_g_connection_unref (app->g_connection);
		app->g_connection = NULL;
		app->connection = NULL;
	}

	if (app->bus_proxy) {
		g_signal_handlers_disconnect_by_func (app->bus_proxy, destroy_cb, app);
		g_object_unref (app->bus_proxy);
		app->bus_proxy = NULL;
	}
}

static void
destroy_cb (DBusGProxy *proxy, gpointer user_data)
{
	Application *app = (Application *) user_data;

	/* Clean up existing connection */
	g_warning ("disconnected from the system bus, exiting.");
	g_main_loop_quit (app->loop);
}

static gboolean
start_dbus_service (Application *app)
{
	int request_name_result;
	GError *err = NULL;

	if (!dbus_g_proxy_call (app->bus_proxy, "RequestName", &err,
							G_TYPE_STRING, NM_DBUS_SERVICE_SYSTEM_SETTINGS,
							G_TYPE_UINT, DBUS_NAME_FLAG_DO_NOT_QUEUE,
							G_TYPE_INVALID,
							G_TYPE_UINT, &request_name_result,
							G_TYPE_INVALID)) {
		g_warning ("Could not acquire the NetworkManagerSystemSettings service.\n"
		           "  Message: '%s'", err->message);
		g_error_free (err);
		return FALSE;
	}

	if (request_name_result != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
		g_warning ("Could not acquire the NetworkManagerSystemSettings service "
		           "as it is already taken.  Return: %d",
		           request_name_result);
		return FALSE;
	}

	return TRUE;
}

static gboolean
dbus_init (Application *app)
{
	GError *err = NULL;
	
	dbus_connection_set_change_sigpipe (TRUE);

	app->g_connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, &err);
	if (!app->g_connection) {
		g_warning ("Could not get the system bus.  Make sure "
		           "the message bus daemon is running!  Message: %s",
		           err->message);
		g_error_free (err);
		return FALSE;
	}

	app->connection = dbus_g_connection_get_connection (app->g_connection);
	dbus_connection_set_exit_on_disconnect (app->connection, FALSE);

	app->bus_proxy = dbus_g_proxy_new_for_name (app->g_connection,
	                                            "org.freedesktop.DBus",
	                                            "/org/freedesktop/DBus",
	                                            "org.freedesktop.DBus");
	if (!app->bus_proxy) {
		g_warning ("Could not get the DBus object!");
		return FALSE;
	}

	g_signal_connect (app->bus_proxy, "destroy", G_CALLBACK (destroy_cb), app);

	return TRUE;
}

static gboolean
parse_config_file (const char *filename, char **plugins, GError **error)
{
	GKeyFile *config;

	config = g_key_file_new ();
	if (!config) {
		g_set_error (error, plugins_error_quark (), 0,
		             "Not enough memory to load config file.");
		return FALSE;
	}

	g_key_file_set_list_separator (config, ',');
	if (!g_key_file_load_from_file (config, filename, G_KEY_FILE_NONE, error))
		return FALSE;

	*plugins = g_key_file_get_value (config, "main", "plugins", error);
	if (*error)
		return FALSE;

	g_key_file_free (config);
	return TRUE;
}

static void
log_handler (const gchar *log_domain,
             GLogLevelFlags log_level,
             const gchar *message,
             gpointer ignored)
{
	int syslog_priority;	

	switch (log_level) {
		case G_LOG_LEVEL_ERROR:
			syslog_priority = LOG_CRIT;
			break;

		case G_LOG_LEVEL_CRITICAL:
			syslog_priority = LOG_ERR;
			break;

		case G_LOG_LEVEL_WARNING:
			syslog_priority = LOG_WARNING;
			break;

		case G_LOG_LEVEL_MESSAGE:
			syslog_priority = LOG_NOTICE;
			break;

		case G_LOG_LEVEL_DEBUG:
			syslog_priority = LOG_DEBUG;
			break;

		case G_LOG_LEVEL_INFO:
		default:
			syslog_priority = LOG_INFO;
			break;
	}

	syslog (syslog_priority, "%s", message);
}


static void
logging_setup (void)
{
	openlog (G_LOG_DOMAIN, LOG_CONS, LOG_DAEMON);
	g_log_set_handler (G_LOG_DOMAIN, 
	                   G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL | G_LOG_FLAG_RECURSION,
	                   log_handler,
	                   NULL);
}

static void
logging_shutdown (void)
{
	closelog ();
}

int
main (int argc, char **argv)
{
	Application *app = g_new0 (Application, 1);
	GOptionContext *opt_ctx;
	GError *error = NULL;
	char *plugins = NULL;
	char *config = NULL;
	gboolean debug = FALSE;

	GOptionEntry entries[] = {
		{ "config", 0, 0, G_OPTION_ARG_FILENAME, &config, "Config file location", "/path/to/config.file" },
		{ "plugins", 0, 0, G_OPTION_ARG_STRING, &plugins, "List of plugins separated by ,", "plugin1,plugin2" },
		{ "debug", 0, 0, G_OPTION_ARG_NONE, &debug, "Output to console rather than syslog", NULL },
		{ NULL }
	};

	opt_ctx = g_option_context_new (NULL);
	g_option_context_set_summary (opt_ctx, "Provides system network settings to NetworkManager.");
	g_option_context_add_main_entries (opt_ctx, entries, NULL);

	if (!g_option_context_parse (opt_ctx, &argc, &argv, &error)) {
		g_warning ("%s\n", error->message);
		g_error_free (error);
		return 1;
	}

	g_option_context_free (opt_ctx);

	if (config) {
		if (!parse_config_file (config, &plugins, &error)) {
			g_warning ("Invalid config file: %s.", error->message);
			return 1;
		}
	}

	if (!plugins) {
		g_warning ("No plugins were specified.");
		return 1;
	}

	g_type_init ();

	if (!g_module_supported ()) {
		g_warning ("GModules are not supported on your platform!");
		return 1;
	}

	app->loop = g_main_loop_new (NULL, FALSE);

	if (!debug)
		logging_setup ();

	if (!dbus_init (app))
		return -1;

	app->hal_mgr = nm_system_config_hal_manager_get (app->g_connection);
	app->settings = nm_sysconfig_settings_new (app->g_connection, app->hal_mgr);

	app->wired_devices = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                            g_free, wired_device_info_destroy);
	g_signal_connect (G_OBJECT (app->hal_mgr), "device-added",
	                  G_CALLBACK (device_added_cb), app);
	g_signal_connect (G_OBJECT (app->hal_mgr), "device-removed",
	                  G_CALLBACK (device_removed_cb), app);

	/* Load the plugins; fail if a plugin is not found. */
	load_plugins (app, plugins, &error);
	if (error) {
		g_warning ("Error: %d - %s", error->code, error->message);
		return -1;
	}
	g_free (plugins);

	g_idle_add (load_stuff, app);

	g_main_loop_run (app->loop);

	g_object_unref (app->settings);
	g_object_unref (app->hal_mgr);

	g_hash_table_destroy (app->wired_devices);

	dbus_cleanup (app);

	if (!debug)
		logging_shutdown ();

	return 0;
}

