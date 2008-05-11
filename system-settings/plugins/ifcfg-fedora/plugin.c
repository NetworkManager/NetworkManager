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
 * (C) Copyright 2008 Red Hat, Inc.
 */

#include <config.h>
#include <gmodule.h>
#include <glib-object.h>
#include <glib/gi18n.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <net/ethernet.h>
#include <netinet/ether.h>

#include <dbus/dbus-glib.h>

#include <nm-setting-connection.h>

#ifndef NO_GIO
#include <gio/gio.h>
#else
#include <gfilemonitor/gfilemonitor.h>
#endif

#include "common.h"
#include "nm-dbus-glib-types.h"
#include "plugin.h"
#include "nm-system-config-interface.h"
#include "nm-ifcfg-connection.h"

#define IFCFG_PLUGIN_NAME "ifcfg-fedora"
#define IFCFG_PLUGIN_INFO "(c) 2007 - 2008 Red Hat, Inc.  To report bugs please use the NetworkManager mailing list."

#define IFCFG_DIR SYSCONFDIR"/sysconfig/network-scripts/"

static void system_config_interface_init (NMSystemConfigInterface *system_config_interface_class);

G_DEFINE_TYPE_EXTENDED (SCPluginIfcfg, sc_plugin_ifcfg, G_TYPE_OBJECT, 0,
						G_IMPLEMENT_INTERFACE (NM_TYPE_SYSTEM_CONFIG_INTERFACE,
											   system_config_interface_init))

#define SC_PLUGIN_IFCFG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SC_TYPE_PLUGIN_IFCFG, SCPluginIfcfgPrivate))


typedef struct {
	DBusGConnection *g_connection;
	NMSystemConfigHalManager *hal_mgr;

	GHashTable *connections;

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

static void
check_unmanaged (gpointer key, gpointer data, gpointer user_data)
{
	GSList **list = (GSList **) user_data;
	NMIfcfgConnection *connection = NM_IFCFG_CONNECTION (data);
	const char *udi;
	GSList *iter;

	if (!nm_ifcfg_connection_get_unmanaged (connection))
		return;

	udi = nm_ifcfg_connection_get_udi (connection);
	if (!udi)
		return;

	/* Just return if the UDI is already in the list */
	for (iter = *list; iter; iter = g_slist_next (iter)) {
		if (!strcmp ((char *) iter->data, udi))
			return;
	}

	*list = g_slist_prepend (*list, g_strdup (udi));
}

static GSList *
get_unmanaged_devices (NMSystemConfigInterface *config)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (config);	
	GSList *list = NULL;

	g_hash_table_foreach (priv->connections, check_unmanaged, &list);
	return list;
}

static void
connection_unmanaged_changed (NMIfcfgConnection *connection,
                              GParamSpec *pspec,
                              gpointer user_data)
{
	g_signal_emit_by_name (SC_PLUGIN_IFCFG (user_data), "unmanaged-devices-changed");
}

static NMIfcfgConnection *
read_one_connection (SCPluginIfcfg *plugin, const char *filename)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	NMIfcfgConnection *connection;
	GError *error = NULL;

	PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "parsing %s ... ", filename);

	connection = nm_ifcfg_connection_new (filename, priv->g_connection, priv->hal_mgr, &error);
	if (connection) {
		NMConnection *wrapped;
		NMSettingConnection *s_con;

		wrapped = nm_exported_connection_get_connection (NM_EXPORTED_CONNECTION (connection));
		g_assert (wrapped);
		s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (wrapped, NM_TYPE_SETTING_CONNECTION));
		g_assert (s_con);
		g_assert (s_con->id);

		g_hash_table_insert (priv->connections,
		                     (gpointer) nm_ifcfg_connection_get_filename (connection),
		                     g_object_ref (connection));
		PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "    read connection '%s'", s_con->id);

		if (nm_ifcfg_connection_get_unmanaged (connection)) {
			PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "Ignoring connection '%s' and its "
			              "device because NM_CONTROLLED was false.", s_con->id);
			g_signal_emit_by_name (plugin, "unmanaged-devices-changed");
		} else {
			/* Wait for the connection to become unmanaged once it knows the
			 * UDI of it's device, if/when the device gets plugged in.
			 */
			g_signal_connect (G_OBJECT (connection), "notify::unmanaged",
			                  G_CALLBACK (connection_unmanaged_changed), plugin);
		}
	} else {
		PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "    error: %s",
		              error->message ? error->message : "(unknown)");
		g_error_free (error);
	}

	return connection;
}

static gboolean
should_ignore_file (const char *basename, const char *tag)
{
	int len, tag_len;

	g_return_val_if_fail (basename != NULL, TRUE);
	g_return_val_if_fail (tag != NULL, TRUE);

	len = strlen (basename);
	tag_len = strlen (tag);
	if ((len > tag_len) && !strcasecmp (basename + len - tag_len, tag))
		return TRUE;
	return FALSE;
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

			if (strncmp (item, IFCFG_TAG, strlen (IFCFG_TAG)))
				continue;

			/* ignore some files */
			if (   should_ignore_file (item, BAK_TAG)
			    || should_ignore_file (item, TILDE_TAG)
			    || should_ignore_file (item, ORIG_TAG)
			    || should_ignore_file (item, REJ_TAG))
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
dir_changed (GFileMonitor *monitor,
		   GFile *file,
		   GFile *other_file,
		   GFileMonitorEvent event_type,
		   gpointer user_data)
{
	SCPluginIfcfg *plugin = SC_PLUGIN_IFCFG (user_data);
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	char *name;
	NMIfcfgConnection *connection;
	gboolean do_remove = FALSE, do_new = FALSE;

	name = g_file_get_path (file);
	connection = g_hash_table_lookup (priv->connections, name);

	switch (event_type) {
	case G_FILE_MONITOR_EVENT_DELETED:
		if (connection) {
			PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "removed %s.", name);
			do_remove = TRUE;
		}
		break;
	case G_FILE_MONITOR_EVENT_CREATED:
	case G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT:
		if (connection) {
			/* Update */
			NMIfcfgConnection *tmp;
			GError *error = NULL;

			PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "updating %s", name);

			tmp = (NMIfcfgConnection *) nm_ifcfg_connection_new (name, priv->g_connection, priv->hal_mgr, &error);
			if (tmp) {
				GHashTable *settings;
				gboolean new_unmanaged, old_unmanaged;

				old_unmanaged = nm_ifcfg_connection_get_unmanaged (NM_IFCFG_CONNECTION (connection));
				new_unmanaged = nm_ifcfg_connection_get_unmanaged (NM_IFCFG_CONNECTION (tmp));

				if (new_unmanaged) {
					if (!old_unmanaged) {
						/* Unexport the connection by destroying it, then re-creating it as unmanaged */
						do_remove = do_new = TRUE;
					}
				} else {
					NMConnection *old_wrapped, *new_wrapped;

					if (old_unmanaged)  /* no longer unmanaged */
						g_signal_emit_by_name (plugin, "connection-added", connection);

					new_wrapped = nm_exported_connection_get_connection (NM_EXPORTED_CONNECTION (tmp));
					old_wrapped = nm_exported_connection_get_connection (NM_EXPORTED_CONNECTION (connection));

					/* Only update if different */
					if (!nm_connection_compare (new_wrapped, old_wrapped, COMPARE_FLAGS_EXACT)) {
						settings = nm_connection_to_hash (new_wrapped);
						nm_exported_connection_update (NM_EXPORTED_CONNECTION (connection), settings, NULL);
						g_hash_table_destroy (settings);
					}

					/* Update unmanaged status */
					g_object_set (connection, "unmanaged", new_unmanaged, NULL);
					g_signal_emit_by_name (plugin, "unmanaged-devices-changed");
				}
				g_object_unref (tmp);
			} else {
				/* couldn't read connection; remove it */

				PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    error: %s",
				             error->message ? error->message : "(unknown)");
				g_error_free (error);

				PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "removed %s.", name);
				do_remove = TRUE;
			}
		} else {
			do_new = TRUE;
		}
		break;
	default:
		break;
	}

	if (do_remove) {
		gboolean unmanaged = nm_ifcfg_connection_get_unmanaged (connection);

		g_hash_table_remove (priv->connections, name);
		nm_exported_connection_signal_removed (NM_EXPORTED_CONNECTION (connection));

		/* Emit unmanaged changes _after_ removing the connection */
		if (unmanaged)
			g_signal_emit_by_name (plugin, "unmanaged-devices-changed");
	}

	if (do_new) {
		connection = read_one_connection (plugin, name);
		if (connection) {
			if (!nm_ifcfg_connection_get_unmanaged (NM_IFCFG_CONNECTION (connection)))
				g_signal_emit_by_name (plugin, "connection-added", connection);
		}
	}

	g_free (name);
}

static void
setup_monitoring (SCPluginIfcfg *plugin)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	GFile *file;
	GFileMonitor *monitor;

	priv->connections = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_object_unref);

	file = g_file_new_for_path (IFCFG_DIR);
	monitor = g_file_monitor_directory (file, G_FILE_MONITOR_NONE, NULL, NULL);
	g_object_unref (file);

	if (monitor) {
		priv->monitor_id = g_signal_connect (monitor, "changed", G_CALLBACK (dir_changed), plugin);
		priv->monitor = monitor;
	}
}

static void
hash_to_slist (gpointer key, gpointer value, gpointer user_data)
{
	NMIfcfgConnection *exported = NM_IFCFG_CONNECTION (value);
	GSList **list = (GSList **) user_data;

	if (!nm_ifcfg_connection_get_unmanaged (exported))
		*list = g_slist_prepend (*list, value);
}

static GSList *
get_connections (NMSystemConfigInterface *config)
{
	SCPluginIfcfg *plugin = SC_PLUGIN_IFCFG (config);
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	GSList *list = NULL;

	if (!priv->connections) {
		setup_monitoring (plugin);
		read_connections (plugin);
	}

	g_hash_table_foreach (priv->connections, hash_to_slist, &list);

	return list;
}

static void
init (NMSystemConfigInterface *config, NMSystemConfigHalManager *hal_manager)
{
	SCPluginIfcfg *plugin = SC_PLUGIN_IFCFG (config);
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);

	priv->hal_mgr = g_object_ref (hal_manager);
}

static void
sc_plugin_ifcfg_init (SCPluginIfcfg *plugin)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	GError *error = NULL;

	priv->g_connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, &error);
	if (!priv->g_connection) {
		PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "    dbus-glib error: %s",
		              error->message ? error->message : "(unknown)");
		g_error_free (error);
	}
}

static void
dispose (GObject *object)
{
	SCPluginIfcfg *plugin = SC_PLUGIN_IFCFG (object);
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);

	g_object_unref (priv->hal_mgr);

	if (priv->g_connection)
		dbus_g_connection_unref (priv->g_connection);

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
