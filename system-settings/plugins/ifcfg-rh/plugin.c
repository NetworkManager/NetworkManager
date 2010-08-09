/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service
 *
 * Dan Williams <dcbw@redhat.com>
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
 * Copyright (C) 2007 - 2008 Red Hat, Inc.
 */

#include <config.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <net/ethernet.h>
#include <netinet/ether.h>

#include <gmodule.h>
#include <glib-object.h>
#include <glib/gi18n.h>
#include <gio/gio.h>

#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>

#include <nm-setting-connection.h>
#include <nm-settings-interface.h>

#include "common.h"
#include "nm-dbus-glib-types.h"
#include "plugin.h"
#include "nm-system-config-interface.h"
#include "nm-ifcfg-connection.h"
#include "nm-inotify-helper.h"
#include "shvar.h"
#include "writer.h"
#include "utils.h"

#define DBUS_SERVICE_NAME "com.redhat.ifcfgrh1"
#define DBUS_OBJECT_PATH "/com/redhat/ifcfgrh1"

static gboolean impl_ifcfgrh_get_ifcfg_details (SCPluginIfcfg *plugin,
                                                const char *in_ifcfg,
                                                const char **out_uuid,
                                                const char **out_path,
                                                GError **error);

#include "nm-ifcfg-rh-glue.h"

static void system_config_interface_init (NMSystemConfigInterface *system_config_interface_class);

static void connection_changed_handler (SCPluginIfcfg *plugin,
                                        const char *path,
                                        NMIfcfgConnection *connection,
                                        gboolean *do_remove,
                                        gboolean *do_new);

static void handle_connection_remove_or_new (SCPluginIfcfg *plugin,
                                             const char *path,
                                             NMIfcfgConnection *connection,
                                             gboolean do_remove,
                                             gboolean do_new);

G_DEFINE_TYPE_EXTENDED (SCPluginIfcfg, sc_plugin_ifcfg, G_TYPE_OBJECT, 0,
						G_IMPLEMENT_INTERFACE (NM_TYPE_SYSTEM_CONFIG_INTERFACE,
											   system_config_interface_init))

#define SC_PLUGIN_IFCFG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SC_TYPE_PLUGIN_IFCFG, SCPluginIfcfgPrivate))


typedef struct {
	GHashTable *connections;

	gulong ih_event_id;
	int sc_network_wd;
	char *hostname;

	GFileMonitor *monitor;
	guint monitor_id;

	DBusGConnection *bus;
} SCPluginIfcfgPrivate;


static void
connection_unmanaged_changed (NMIfcfgConnection *connection,
                              GParamSpec *pspec,
                              gpointer user_data)
{
	g_signal_emit_by_name (SC_PLUGIN_IFCFG (user_data), NM_SYSTEM_CONFIG_INTERFACE_UNMANAGED_SPECS_CHANGED);
}

static void
connection_ifcfg_changed (NMIfcfgConnection *connection, gpointer user_data)
{
	SCPluginIfcfg *plugin = SC_PLUGIN_IFCFG (user_data);
	gboolean do_remove = FALSE, do_new = FALSE;
	const char *path;

	path = nm_ifcfg_connection_get_filename (connection);
	g_return_if_fail (path != NULL);

	connection_changed_handler (plugin, path, connection, &do_remove, &do_new);
	handle_connection_remove_or_new (plugin, path, connection, do_remove, do_new);
}

static NMIfcfgConnection *
read_one_connection (SCPluginIfcfg *plugin, const char *filename)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	NMIfcfgConnection *connection;
	GError *error = NULL;
	gboolean ignore_error = FALSE;

	PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "parsing %s ... ", filename);

	connection = nm_ifcfg_connection_new (filename, &error, &ignore_error);
	if (connection) {
		NMSettingConnection *s_con;
		const char *cid;

		s_con = (NMSettingConnection *) nm_connection_get_setting (NM_CONNECTION (connection), NM_TYPE_SETTING_CONNECTION);
		g_assert (s_con);

		cid = nm_setting_connection_get_id (s_con);
		g_assert (cid);

		g_hash_table_insert (priv->connections,
		                     (gpointer) nm_ifcfg_connection_get_filename (connection),
		                     g_object_ref (connection));
		PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "    read connection '%s'", cid);

		if (nm_ifcfg_connection_get_unmanaged_spec (connection)) {
			PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "Ignoring connection '%s' and its "
			              "device due to NM_CONTROLLED/BRIDGE/VLAN.", cid);
			g_signal_emit_by_name (plugin, NM_SYSTEM_CONFIG_INTERFACE_UNMANAGED_SPECS_CHANGED);
		} else {
			/* Wait for the connection to become unmanaged once it knows the
			 * UDI of it's device, if/when the device gets plugged in.
			 */
			g_signal_connect (G_OBJECT (connection), "notify::unmanaged",
			                  G_CALLBACK (connection_unmanaged_changed), plugin);
		}

		/* watch changes of ifcfg hardlinks */
		g_signal_connect (G_OBJECT (connection), "ifcfg-changed",
		                  G_CALLBACK (connection_ifcfg_changed), plugin);
	} else {
		if (!ignore_error) {
			PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "    error: %s",
			              (error && error->message) ? error->message : "(unknown)");
		}
		g_clear_error (&error);
	}

	return connection;
}

static void
read_connections (SCPluginIfcfg *plugin)
{
	GDir *dir;
	GError *err = NULL;

	dir = g_dir_open (IFCFG_DIR, 0, &err);
	if (dir) {
		const char *item;

		while ((item = g_dir_read_name (dir))) {
			char *full_path;

			if (utils_should_ignore_file (item, TRUE))
				continue;

			full_path = g_build_filename (IFCFG_DIR, item, NULL);
			read_one_connection (plugin, full_path);
			g_free (full_path);
		}

		g_dir_close (dir);
	} else {
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "Can not read directory '%s': %s", IFCFG_DIR, err->message);
		g_error_free (err);
	}
}

/* Monitoring */

static void
connection_changed_handler (SCPluginIfcfg *plugin,
                            const char *path,
                            NMIfcfgConnection *connection,
                            gboolean *do_remove,
                            gboolean *do_new)
{
	NMIfcfgConnection *new;
	GError *error = NULL;
	gboolean ignore_error = FALSE;
	const char *new_unmanaged = NULL, *old_unmanaged = NULL;

	g_return_if_fail (plugin != NULL);
	g_return_if_fail (path != NULL);
	g_return_if_fail (connection != NULL);
	g_return_if_fail (do_remove != NULL);
	g_return_if_fail (do_new != NULL);

	PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "updating %s", path);

	new = (NMIfcfgConnection *) nm_ifcfg_connection_new (path, &error, &ignore_error);
	if (!new) {
		/* errors reading connection; remove it */
		if (!ignore_error) {
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    error: %s",
			             (error && error->message) ? error->message : "(unknown)");
		}
		g_clear_error (&error);

		PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "removed %s.", path);
		*do_remove = TRUE;
		return;
	}

	/* Successfully read connection changes */

	old_unmanaged = nm_ifcfg_connection_get_unmanaged_spec (NM_IFCFG_CONNECTION (connection));
	new_unmanaged = nm_ifcfg_connection_get_unmanaged_spec (NM_IFCFG_CONNECTION (new));

	if (new_unmanaged) {
		if (!old_unmanaged) {
			/* Unexport the connection by destroying it, then re-creating it as unmanaged */
			*do_remove = *do_new = TRUE;
		}
	} else {
		if (old_unmanaged) {  /* now managed */
			NMSettingConnection *s_con;
			const char *cid;

			s_con = (NMSettingConnection *) nm_connection_get_setting (NM_CONNECTION (new), NM_TYPE_SETTING_CONNECTION);
			g_assert (s_con);

			cid = nm_setting_connection_get_id (s_con);
			g_assert (cid);

			PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "Managing connection '%s' and its "
			              "device because NM_CONTROLLED was true.", cid);
			g_signal_emit_by_name (plugin, NM_SYSTEM_CONFIG_INTERFACE_CONNECTION_ADDED, connection);
		}

		if (!nm_sysconfig_connection_update (NM_SYSCONFIG_CONNECTION (connection),
		                                     NM_CONNECTION (new),
		                                     TRUE,
		                                     &error)) {
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    error updating: %s",
			             (error && error->message) ? error->message : "(unknown)");
			g_clear_error (&error);
		}

		/* Update unmanaged status */
		g_object_set (connection, "unmanaged", new_unmanaged, NULL);
		g_signal_emit_by_name (plugin, NM_SYSTEM_CONFIG_INTERFACE_UNMANAGED_SPECS_CHANGED);
	}
	g_object_unref (new);
}

static void
handle_connection_remove_or_new (SCPluginIfcfg *plugin,
                                 const char *path,
                                 NMIfcfgConnection *connection,
                                 gboolean do_remove,
                                 gboolean do_new)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);

	g_return_if_fail (plugin != NULL);
	g_return_if_fail (path != NULL);

	if (do_remove) {
		const char *unmanaged;

		g_return_if_fail (connection != NULL);

		unmanaged = nm_ifcfg_connection_get_unmanaged_spec (connection);
		g_hash_table_remove (priv->connections, path);
		g_signal_emit_by_name (connection, "removed");

		/* Emit unmanaged changes _after_ removing the connection */
		if (unmanaged)
			g_signal_emit_by_name (plugin, NM_SYSTEM_CONFIG_INTERFACE_UNMANAGED_SPECS_CHANGED);
	}

	if (do_new) {
		connection = read_one_connection (plugin, path);
		if (connection) {
			if (!nm_ifcfg_connection_get_unmanaged_spec (connection))
				g_signal_emit_by_name (plugin, NM_SYSTEM_CONFIG_INTERFACE_CONNECTION_ADDED, connection);
		}
	}
}
static void
dir_changed (GFileMonitor *monitor,
		   GFile *file,
		   GFile *other_file,
		   GFileMonitorEvent event_type,
		   gpointer user_data)
{
	SCPluginIfcfg *plugin = SC_PLUGIN_IFCFG (user_data);
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	char *path, *name;
	NMIfcfgConnection *connection;
	gboolean do_remove = FALSE, do_new = FALSE;

	path = g_file_get_path (file);
	if (utils_should_ignore_file (path, FALSE)) {
		g_free (path);
		return;
	}

	/* Given any ifcfg, keys, or routes file, get the ifcfg file path */
	name = utils_get_ifcfg_path (path);
	g_free (path);

	connection = g_hash_table_lookup (priv->connections, name);
	switch (event_type) {
	case G_FILE_MONITOR_EVENT_DELETED:
		PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "removed %s.", name);
		if (connection)
			handle_connection_remove_or_new (plugin, name, connection, TRUE, FALSE);
		break;
	case G_FILE_MONITOR_EVENT_CREATED:
	case G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT:
		/* Update */
		if (!connection)
			do_new = TRUE;
		else
			connection_changed_handler (plugin, name, connection, &do_remove, &do_new);

		handle_connection_remove_or_new (plugin, name, connection, do_remove, do_new);
		break;
	default:
		break;
	}

	g_free (name);
}

static void
setup_ifcfg_monitoring (SCPluginIfcfg *plugin)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	GFile *file;
	GFileMonitor *monitor;

	priv->connections = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_object_unref);

	file = g_file_new_for_path (IFCFG_DIR "/");
	monitor = g_file_monitor_directory (file, G_FILE_MONITOR_NONE, NULL, NULL);
	g_object_unref (file);

	if (monitor) {
		priv->monitor_id = g_signal_connect (monitor, "changed", G_CALLBACK (dir_changed), plugin);
		priv->monitor = monitor;
	}
}

static GSList *
get_connections (NMSystemConfigInterface *config)
{
	SCPluginIfcfg *plugin = SC_PLUGIN_IFCFG (config);
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	GSList *list = NULL;
	GHashTableIter iter;
	gpointer value;

	if (!priv->connections) {
		setup_ifcfg_monitoring (plugin);
		read_connections (plugin);
	}

	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, NULL, &value)) {
		NMIfcfgConnection *exported = NM_IFCFG_CONNECTION (value);

		if (!nm_ifcfg_connection_get_unmanaged_spec (exported))
			list = g_slist_prepend (list, value);
	}

	return list;
}

static void
check_unmanaged (gpointer key, gpointer data, gpointer user_data)
{
	GSList **list = (GSList **) user_data;
	NMIfcfgConnection *connection = NM_IFCFG_CONNECTION (data);
	const char *unmanaged_spec;
	GSList *iter;

	unmanaged_spec = nm_ifcfg_connection_get_unmanaged_spec (connection);
	if (!unmanaged_spec)
		return;

	/* Just return if the unmanaged spec is already in the list */
	for (iter = *list; iter; iter = g_slist_next (iter)) {
		if (!strcmp ((char *) iter->data, unmanaged_spec))
			return;
	}

	*list = g_slist_prepend (*list, g_strdup (unmanaged_spec));
}

static GSList *
get_unmanaged_specs (NMSystemConfigInterface *config)
{
	SCPluginIfcfg *plugin = SC_PLUGIN_IFCFG (config);
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (config);
	GSList *list = NULL;

	if (!priv->connections) {
		setup_ifcfg_monitoring (plugin);
		read_connections (plugin);
	}

	g_hash_table_foreach (priv->connections, check_unmanaged, &list);
	return list;
}

static gboolean
add_connection (NMSystemConfigInterface *config,
                NMConnection *connection,
                GError **error)
{
	return writer_new_connection (connection, IFCFG_DIR, NULL, error);
}

#define SC_NETWORK_FILE SYSCONFDIR"/sysconfig/network"

static char *
plugin_get_hostname (SCPluginIfcfg *plugin)
{
	shvarFile *network;
	char *hostname;
	gboolean ignore_localhost;

	network = svNewFile (SC_NETWORK_FILE);
	if (!network) {
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "Could not get hostname: failed to read " SC_NETWORK_FILE);
		return FALSE;
	}

	hostname = svGetValue (network, "HOSTNAME", FALSE);
	ignore_localhost = svTrueValue (network, "NM_IGNORE_HOSTNAME_LOCALHOST", FALSE);
	if (ignore_localhost) {
		/* Ignore a hostname of 'localhost' or 'localhost.localdomain' to preserve
		 * 'network' service behavior.
		 */
		if (hostname && (!strcmp (hostname, "localhost") || !strcmp (hostname, "localhost.localdomain"))) {
			g_free (hostname);
			hostname = NULL;
		}
	}

	svCloseFile (network);
	return hostname;
}

static gboolean
plugin_set_hostname (SCPluginIfcfg *plugin, const char *hostname)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	shvarFile *network;

	network = svCreateFile (SC_NETWORK_FILE);
	if (!network) {
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "Could not save hostname: failed to create/open " SC_NETWORK_FILE);
		return FALSE;
	}

	svSetValue (network, "HOSTNAME", hostname, FALSE);
	svWriteFile (network, 0644);
	svCloseFile (network);

	g_free (priv->hostname);
	priv->hostname = hostname ? g_strdup (hostname) : NULL;
	return TRUE;
}

static void
sc_network_changed_cb (NMInotifyHelper *ih,
                       struct inotify_event *evt,
                       const char *path,
                       gpointer user_data)
{
	SCPluginIfcfg *plugin = SC_PLUGIN_IFCFG (user_data);
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	char *new_hostname;

	if (evt->wd != priv->sc_network_wd)
		return;

	new_hostname = plugin_get_hostname (plugin);
	if (   (new_hostname && !priv->hostname)
	    || (!new_hostname && priv->hostname)
	    || (priv->hostname && new_hostname && strcmp (priv->hostname, new_hostname))) {
		g_free (priv->hostname);
		priv->hostname = new_hostname;
		g_object_notify (G_OBJECT (plugin), NM_SYSTEM_CONFIG_INTERFACE_HOSTNAME);
	} else
		g_free (new_hostname);
}

static gboolean
impl_ifcfgrh_get_ifcfg_details (SCPluginIfcfg *plugin,
                                const char *in_ifcfg,
                                const char **out_uuid,
                                const char **out_path,
                                GError **error)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	NMIfcfgConnection *connection;
	NMSettingConnection *s_con;
	const char *uuid;
	const char *path;

	if (!g_path_is_absolute (in_ifcfg)) {
		g_set_error (error,
		             NM_SETTINGS_INTERFACE_ERROR,
		             NM_SETTINGS_INTERFACE_ERROR_INVALID_CONNECTION,
		             "ifcfg path '%s' is not absolute", in_ifcfg);
		return FALSE;
	}

	connection = g_hash_table_lookup (priv->connections, in_ifcfg);
	if (!connection || nm_ifcfg_connection_get_unmanaged_spec (connection)) {
		g_set_error (error,
		             NM_SETTINGS_INTERFACE_ERROR,
		             NM_SETTINGS_INTERFACE_ERROR_INVALID_CONNECTION,
		             "ifcfg file '%s' unknown", in_ifcfg);
		return FALSE;
	}

	s_con = (NMSettingConnection *) nm_connection_get_setting (NM_CONNECTION (connection), NM_TYPE_SETTING_CONNECTION);
	if (!s_con) {
		g_set_error (error,
		             NM_SETTINGS_INTERFACE_ERROR,
		             NM_SETTINGS_INTERFACE_ERROR_INTERNAL_ERROR,
		             "unable to retrieve the connection setting");
		return FALSE;
	}

	uuid = nm_setting_connection_get_uuid (s_con);
	if (!uuid) {
		g_set_error (error,
		             NM_SETTINGS_INTERFACE_ERROR,
		             NM_SETTINGS_INTERFACE_ERROR_INTERNAL_ERROR,
		             "unable to get the UUID");
		return FALSE;
	}
	
	path = nm_connection_get_path (NM_CONNECTION (connection));
	if (!path) {
		g_set_error (error,
		             NM_SETTINGS_INTERFACE_ERROR,
		             NM_SETTINGS_INTERFACE_ERROR_INTERNAL_ERROR,
		             "unable to get the connection D-Bus path");
		return FALSE;
	}

	*out_uuid = g_strdup (uuid);
	*out_path = g_strdup (path);

	return TRUE;
}

static void
init (NMSystemConfigInterface *config)
{
}

static void
sc_plugin_ifcfg_init (SCPluginIfcfg *plugin)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	NMInotifyHelper *ih;
	GError *error = NULL;
	gboolean success = FALSE;

	ih = nm_inotify_helper_get ();
	priv->ih_event_id = g_signal_connect (ih, "event", G_CALLBACK (sc_network_changed_cb), plugin);
	priv->sc_network_wd = nm_inotify_helper_add_watch (ih, SC_NETWORK_FILE);

	priv->hostname = plugin_get_hostname (plugin);

	priv->bus = dbus_g_bus_get (DBUS_BUS_SYSTEM, &error);
	if (!priv->bus) {
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "Couldn't connect to D-Bus: %s",
		             error->message);
		g_clear_error (&error);
	} else {
		DBusConnection *tmp;
		DBusGProxy *proxy;
		int result;

		tmp = dbus_g_connection_get_connection (priv->bus);
		dbus_connection_set_exit_on_disconnect (tmp, FALSE);

		proxy = dbus_g_proxy_new_for_name (priv->bus,
		                                   "org.freedesktop.DBus",
		                                   "/org/freedesktop/DBus",
		                                   "org.freedesktop.DBus");

		if (!dbus_g_proxy_call (proxy, "RequestName", &error,
		                        G_TYPE_STRING, DBUS_SERVICE_NAME,
		                        G_TYPE_UINT, DBUS_NAME_FLAG_DO_NOT_QUEUE,
		                        G_TYPE_INVALID,
		                        G_TYPE_UINT, &result,
		                        G_TYPE_INVALID)) {
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "Couldn't acquire D-Bus service: %s",
			             error->message);
			g_clear_error (&error);
		} else if (result != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "Couldn't acquire ifcfgrh1 D-Bus service (already taken)");
		} else
			success = TRUE;
	}

	if (!success) {
		dbus_g_connection_unref (priv->bus);
		priv->bus = NULL;
	}
}

static void
dispose (GObject *object)
{
	SCPluginIfcfg *plugin = SC_PLUGIN_IFCFG (object);
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	NMInotifyHelper *ih;

	if (priv->bus) {
		dbus_g_connection_unref (priv->bus);
		priv->bus = NULL;
	}

	ih = nm_inotify_helper_get ();

	g_signal_handler_disconnect (ih, priv->ih_event_id);

	if (priv->sc_network_wd >= 0)
		nm_inotify_helper_remove_watch (ih, priv->sc_network_wd);

	g_free (priv->hostname);

	if (priv->connections)
		g_hash_table_destroy (priv->connections);

	if (priv->monitor) {
		if (priv->monitor_id)
			g_signal_handler_disconnect (priv->monitor, priv->monitor_id);

		g_file_monitor_cancel (priv->monitor);
		g_object_unref (priv->monitor);
	}

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
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (object);

	switch (prop_id) {
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_NAME:
		g_value_set_string (value, IFCFG_PLUGIN_NAME);
		break;
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_INFO:
		g_value_set_string (value, IFCFG_PLUGIN_INFO);
		break;
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_CAPABILITIES:
		g_value_set_uint (value, NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_CONNECTIONS | NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_HOSTNAME);
		break;
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_HOSTNAME:
		g_value_set_string (value, priv->hostname);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec)
{
	const char *hostname;

	switch (prop_id) {
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_HOSTNAME:
		hostname = g_value_get_string (value);
		if (hostname && strlen (hostname) < 1)
			hostname = NULL;
		plugin_set_hostname (SC_PLUGIN_IFCFG (object), hostname);
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

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (req_class),
									 &dbus_glib_nm_ifcfg_rh_object_info);
}

static void
system_config_interface_init (NMSystemConfigInterface *system_config_interface_class)
{
	/* interface implementation */
	system_config_interface_class->get_connections = get_connections;
	system_config_interface_class->add_connection = add_connection;
	system_config_interface_class->get_unmanaged_specs = get_unmanaged_specs;
	system_config_interface_class->init = init;
}

G_MODULE_EXPORT GObject *
nm_system_config_factory (void)
{
	static SCPluginIfcfg *singleton = NULL;
	SCPluginIfcfgPrivate *priv;

	if (!singleton) {
		singleton = SC_PLUGIN_IFCFG (g_object_new (SC_TYPE_PLUGIN_IFCFG, NULL));
		if (singleton) {
			priv = SC_PLUGIN_IFCFG_GET_PRIVATE (singleton);
			if (priv->bus)
				dbus_g_connection_register_g_object (priv->bus,
				                                     DBUS_OBJECT_PATH,
				                                     G_OBJECT (singleton));
			PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "Acquired D-Bus service %s", DBUS_SERVICE_NAME);
		}
	} else
		g_object_ref (singleton);

	return G_OBJECT (singleton);
}
