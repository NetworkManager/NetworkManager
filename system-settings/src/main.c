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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2007 Red Hat, Inc.
 */

#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <glib.h>
#include <gmodule.h>

#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>

#include <nm-connection.h>
#include <nm-setting-connection.h>
#include <nm-settings.h>
#include <NetworkManager.h>

#include "dbus-settings.h"
#include "nm-system-config-hal-manager.h"
#include "nm-system-config-hal-manager-private.h"
#include "nm-system-config-interface.h"

#define NM_SS_CONNECTIONS_TAG "nm-ss-connections"

typedef struct {
	DBusConnection *connection;
	DBusGConnection *g_connection;

	DBusGProxy *bus_proxy;
	NMSystemConfigHalManager *hal_mgr;
	gboolean started;

	NMSysconfigSettings *settings;
	GMainLoop *loop;

	GSList *plugins;   /* In priority order */
} Application;


static gboolean dbus_init (Application *app);
static void dbus_cleanup (Application *app);
static gboolean start_dbus_service (Application *app);
static void destroy_cb (DBusGProxy *proxy, gpointer user_data);


static GQuark
plugins_error_quark (void)
{
	static GQuark error_quark = 0;

	if (G_UNLIKELY (error_quark == 0))
		error_quark = g_quark_from_static_string ("plugins-error-quark");

	return error_quark;
}



static void
connection_added_cb (NMSystemConfigInterface *config,
                     NMConnection *connection,
                     Application *app)
{
	GSList **connections;

	connections = g_object_get_data (G_OBJECT (config), NM_SS_CONNECTIONS_TAG);
	*connections = g_slist_append (*connections, connection);

	nm_sysconfig_settings_add_connection (app->settings, connection, app->g_connection);
}

static void
connection_removed_cb (NMSystemConfigInterface *config,
                       NMConnection *connection,
                       Application *app)
{
	GSList **connections;

	connections = g_object_get_data (G_OBJECT (config), NM_SS_CONNECTIONS_TAG);
	*connections = g_slist_remove (*connections, connection);

	nm_sysconfig_settings_remove_connection (app->settings, connection);
}

static void
connection_updated_cb (NMSystemConfigInterface *config,
                       NMConnection *connection,
                       Application *app)
{
	nm_sysconfig_settings_update_connection (app->settings, connection);
}

static void
unmanaged_devices_changed_cb (NMSystemConfigInterface *config,
                              Application *app)
{
	GSList *udis = NULL, *temp, *iter;

	/* Ask all the plugins for their unmanaged devices */
	for (iter = app->plugins; iter; iter = g_slist_next (iter)) {
		temp = nm_system_config_interface_get_unmanaged_devices (NM_SYSTEM_CONFIG_INTERFACE (iter->data));
		udis = g_slist_concat (udis, temp);
	}

	nm_sysconfig_settings_update_unamanged_devices (app->settings, udis);
	g_slist_foreach (udis, (GFunc) g_free, NULL);
	g_slist_free (udis);
}

static void
register_plugin (Application *app, NMSystemConfigInterface *plugin)
{
	g_signal_connect (plugin, "connection-added", (GCallback) connection_added_cb, app);
	g_signal_connect (plugin, "connection-removed", (GCallback) connection_removed_cb, app);
	g_signal_connect (plugin, "connection-updated", (GCallback) connection_updated_cb, app);

	g_signal_connect (plugin, "unmanaged-devices-changed", (GCallback) unmanaged_devices_changed_cb, app);

	nm_system_config_interface_init (plugin, app->hal_mgr);
}

static GObject *
find_plugin (GSList *list, const char *pname)
{
	GSList *iter;

	g_return_val_if_fail (pname != NULL, FALSE);

	for (iter = list; iter; iter = g_slist_next (iter)) {
		NMSystemConfigInterface *plugin = NM_SYSTEM_CONFIG_INTERFACE (iter->data);
		char *list_pname;

		g_object_get (G_OBJECT (plugin),
		              NM_SYSTEM_CONFIG_INTERFACE_NAME,
		              &list_pname,
		              NULL);
		if (list_pname && !strcmp (pname, list_pname))
			return G_OBJECT (plugin);
	}

	return NULL;
}

static GSList *
load_plugins (Application *app, const char *plugins, GError **error)
{
	GSList *list = NULL;
	char **plist;
	char **pname;

	plist = g_strsplit (plugins, ",", 0);
	if (!plist)
		return NULL;

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
			             "Could not find plugin '%s' as %s!",
			             *pname, path);
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
		g_object_set_data_full (obj, "nm-ss-plugin", plugin, (GDestroyNotify) g_module_close);
		register_plugin (app, NM_SYSTEM_CONFIG_INTERFACE (obj));
		list = g_slist_append (list, obj);
	}
	
	g_strfreev (plist);
	return list;
}

static void
print_plugin_info (gpointer item, gpointer user_data)
{
	NMSystemConfigInterface *plugin = NM_SYSTEM_CONFIG_INTERFACE (item);
	char *pname;
	char *pinfo;

	g_object_get (G_OBJECT (plugin),
	              NM_SYSTEM_CONFIG_INTERFACE_NAME,
	              &pname,
	              NULL);

	g_object_get (G_OBJECT (plugin),
	              NM_SYSTEM_CONFIG_INTERFACE_INFO,
	              &pinfo,
	              NULL);

	g_message ("   %s: %s", pname, pinfo);
	g_free (pname);
	g_free (pinfo);
}

static void
free_plugin_connections (gpointer data)
{
	GSList **connections = (GSList **) data;

	g_slist_foreach (*connections, (GFunc) g_object_unref, NULL);
	g_slist_free (*connections);
}

static gboolean
load_stuff (gpointer user_data)
{
	Application *app = (Application *) user_data;
	GSList *iter;

	g_return_val_if_fail (app != NULL, FALSE);

	for (iter = app->plugins; iter; iter = g_slist_next (iter)) {
		NMSystemConfigInterface *plugin = NM_SYSTEM_CONFIG_INTERFACE (iter->data);
		GSList *plugin_connections, **connections;
		GSList *elt;

		plugin_connections = nm_system_config_interface_get_connections (plugin);

		connections = g_malloc0 (sizeof (GSList *));
		g_object_set_data_full (G_OBJECT (plugin), NM_SS_CONNECTIONS_TAG,
		                        connections, free_plugin_connections);

		// FIXME: ensure connections from plugins loaded with a lower priority
		// get rejected when they conflict with connections from a higher
		// priority plugin.

		for (elt = plugin_connections; elt; elt = g_slist_next (elt)) {
			g_object_ref (NM_CONNECTION (elt->data));
			g_object_set_data (G_OBJECT (elt->data), NM_SS_PLUGIN_TAG, plugin);
			connection_added_cb (NM_SYSTEM_CONFIG_INTERFACE (plugin), NM_CONNECTION (elt->data), app);
		}

		g_slist_free (plugin_connections);
	}

	unmanaged_devices_changed_cb (NULL, app);

	if (!start_dbus_service (app)) {
		g_main_loop_quit (app->loop);
		return FALSE;
	}

	return FALSE;
}

#if 0
static void
device_added_cb (DBusGProxy *proxy, const char *udi, gpointer user_data)
{
//	Application *app = (Application *) user_data;

	g_message ("Added: %s", udi);
}

static void
device_removed_cb (DBusGProxy *proxy, const char *udi, gpointer user_data)
{
//	Application *app = (Application *) user_data;

	g_message ("Removed: %s", udi);
}

static void
device_new_capability_cb (DBusGProxy *proxy,
                          const char *udi,
                          const char *capability,
                          gpointer user_data)
{
//	Application *app = (Application *) user_data;

	g_message ("New capability: %s --> %s", udi, capability);
}
#endif

/******************************************************************/

static gboolean
dbus_reconnect (gpointer user_data)
{
	Application *app = (Application *) user_data;

	if (dbus_init (app)) {
		if (start_dbus_service (app)) {
			g_message ("reconnected to the system bus.");
			nm_system_config_hal_manager_reinit_dbus (app->hal_mgr, app->g_connection);
			return TRUE;
		}
	}

	dbus_cleanup (app);
	return FALSE;
}

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

	nm_system_config_hal_manager_deinit_dbus (app->hal_mgr);

	app->started = FALSE;
}

static void
destroy_cb (DBusGProxy *proxy, gpointer user_data)
{
	Application *app = (Application *) user_data;

	/* Clean up existing connection */
	g_warning ("disconnected by the system bus.");
	dbus_cleanup (app);

	g_timeout_add (3000, dbus_reconnect, app);
}

static gboolean
start_dbus_service (Application *app)
{
	int request_name_result;
	GError *err = NULL;

	if (app->started) {
		g_warning ("Service has already started.");
		return FALSE;
	}

	if (!dbus_g_proxy_call (app->bus_proxy, "RequestName", &err,
							G_TYPE_STRING, NM_DBUS_SERVICE_SYSTEM_SETTINGS,
							G_TYPE_UINT, DBUS_NAME_FLAG_DO_NOT_QUEUE,
							G_TYPE_INVALID,
							G_TYPE_UINT, &request_name_result,
							G_TYPE_INVALID)) {
		g_warning ("Could not acquire the NetworkManagerSystemSettings service.\n"
		           "  Message: '%s'", err->message);
		g_error_free (err);
		goto out;
	}

	if (request_name_result != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
		g_warning ("Could not acquire the NetworkManagerSystemSettings service "
		           "as it is already taken.  Return: %d",
		           request_name_result);
		goto out;
	}

	app->started = TRUE;

out:
	if (!app->started)
		dbus_cleanup (app);

	return app->started;
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
		goto error;
	}

	g_signal_connect (app->bus_proxy, "destroy", G_CALLBACK (destroy_cb), app);

	return TRUE;

error:	
	dbus_cleanup (app);
	return FALSE;
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

	app->settings = nm_sysconfig_settings_new (app->g_connection);
	app->hal_mgr = nm_system_config_hal_manager_get (app->g_connection);

	/* Load the plugins; fail if a plugin is not found. */
	app->plugins = load_plugins (app, plugins, &error);
	if (error) {
		g_slist_foreach (app->plugins, (GFunc) g_object_unref, NULL);
		g_slist_free (app->plugins);
		g_warning ("Error: %d - %s", error->code, error->message);
		return -1;
	}
	g_free (plugins);
	g_message ("Loaded plugins:");
	g_slist_foreach (app->plugins, print_plugin_info, NULL);

	g_idle_add (load_stuff, app);

	g_main_loop_run (app->loop);

	g_slist_foreach (app->plugins, (GFunc) g_object_unref, NULL);
	g_slist_free (app->plugins);

	g_object_unref (app->settings);
	g_object_unref (app->hal_mgr);

	if (!debug)
		logging_shutdown ();

	return 0;
}

