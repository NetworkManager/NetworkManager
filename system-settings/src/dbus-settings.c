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

#include <NetworkManager.h>
#include <nm-connection.h>
#include <dbus/dbus.h>
#include <string.h>

#include <nm-setting-connection.h>

#include "dbus-settings.h"
#include "nm-system-config-interface.h"
#include "nm-utils.h"

static void exported_connection_get_secrets (NMExportedConnection *connection,
                                             const gchar *setting_name,
                                             const gchar **hints,
                                             gboolean request_new,
                                             DBusGMethodInvocation *context);

G_DEFINE_TYPE (NMSysconfigExportedConnection, nm_sysconfig_exported_connection, NM_TYPE_EXPORTED_CONNECTION);

/*
 * NMSysconfigExportedConnection
 */

static void
check_for_secrets (gpointer key, gpointer data, gpointer user_data)
{
	gboolean *have_secrets = (gboolean *) user_data;

	if (*have_secrets)
		return;

	*have_secrets = g_hash_table_size ((GHashTable *) data) ? TRUE : FALSE;
}

static void
exported_connection_get_secrets (NMExportedConnection *sys_connection,
				 const gchar *setting_name,
				 const gchar **hints,
				 gboolean request_new,
				 DBusGMethodInvocation *context)
{
	NMConnection *connection;
	GError *error = NULL;
	NMSettingConnection *s_con;
	NMSetting *setting;
	GHashTable *settings = NULL;
	NMSystemConfigInterface *plugin;
	gboolean have_secrets = FALSE;

	connection = nm_exported_connection_get_connection (sys_connection);

	g_return_if_fail (NM_IS_CONNECTION (connection));
	g_return_if_fail (setting_name != NULL);

	setting = nm_connection_get_setting_by_name (connection, setting_name);
	if (!setting) {
		g_set_error (&error, NM_SETTINGS_ERROR, 1,
		             "%s.%d - Connection didn't have requested setting '%s'.",
		             __FILE__, __LINE__, setting_name);
		goto error;
	}

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection,
												   NM_TYPE_SETTING_CONNECTION));
	if (!s_con || !s_con->id || !strlen (s_con->id) || !s_con->type) {
		g_set_error (&error, NM_SETTINGS_ERROR, 1,
		             "%s.%d - Connection didn't have required '"
		             NM_SETTING_CONNECTION_SETTING_NAME
		             "' setting , or the connection name was invalid.",
		             __FILE__, __LINE__);
		goto error;
	}

	plugin = g_object_get_data (G_OBJECT (connection), NM_SS_PLUGIN_TAG);
	if (!plugin) {
		g_set_error (&error, NM_SETTINGS_ERROR, 1,
		             "%s.%d - Connection had no plugin to ask for secrets.",
		             __FILE__, __LINE__);
		goto error;
	}

	settings = nm_system_config_interface_get_secrets (plugin, connection, setting);
	if (!settings || (g_hash_table_size (settings) == 0)) {
		g_set_error (&error, NM_SETTINGS_ERROR, 1,
		             "%s.%d - Connection's plugin did not return a secrets hash.",
		             __FILE__, __LINE__);
		goto error;
	}

	g_hash_table_foreach (settings, check_for_secrets, &have_secrets);
	if (!have_secrets) {
		g_set_error (&error, NM_SETTINGS_ERROR, 1,
		             "%s.%d - Secrets were found for setting '%s' but none"
		             " were valid.", __FILE__, __LINE__, setting_name);
		goto error;
	} else {
		dbus_g_method_return (context, settings);
	}

	g_hash_table_destroy (settings);
	return;

error:
	if (settings)
		g_hash_table_destroy (settings);

	g_warning (error->message);
	dbus_g_method_return_error (context, error);
	g_error_free (error);
}

static void
nm_sysconfig_exported_connection_finalize (GObject *object)
{
	G_OBJECT_CLASS (nm_sysconfig_exported_connection_parent_class)->finalize (object);
}

static void
nm_sysconfig_exported_connection_class_init (NMSysconfigExportedConnectionClass *class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (class);
	NMExportedConnectionClass *connection = NM_EXPORTED_CONNECTION_CLASS (class);

	object_class->finalize = nm_sysconfig_exported_connection_finalize;

	connection->get_secrets = exported_connection_get_secrets;
}

static void
nm_sysconfig_exported_connection_init (NMSysconfigExportedConnection *sysconfig_exported_connection)
{
	
}

NMSysconfigExportedConnection *
nm_sysconfig_exported_connection_new (NMConnection *connection,
                                      DBusGConnection *g_conn)
{
	NMSysconfigExportedConnection *exported;

	exported = g_object_new (NM_TYPE_SYSCONFIG_EXPORTED_CONNECTION,
	                         NM_EXPORTED_CONNECTION_CONNECTION, connection,
	                         NULL);

	nm_exported_connection_register_object (NM_EXPORTED_CONNECTION (exported),
	                                        NM_CONNECTION_SCOPE_SYSTEM,
	                                        g_conn);

	return exported;
}

/*
 * NMSettings
 */

G_DEFINE_TYPE (NMSysconfigSettings, nm_sysconfig_settings, NM_TYPE_SETTINGS);

static GPtrArray *
nm_sysconfig_settings_list_connections (NMSettings *settings)
{
	GPtrArray *connections;
	NMSysconfigSettings *sysconfig_settings;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SYSCONFIG_SETTINGS (settings), NULL);

	sysconfig_settings = NM_SYSCONFIG_SETTINGS (settings);

	connections = g_ptr_array_new ();
	for (iter = sysconfig_settings->connections; iter; iter = g_slist_next (iter)) {
		NMExportedConnection *exported = NM_EXPORTED_CONNECTION (iter->data);
		NMConnection *connection;
		char *path;

		connection = nm_exported_connection_get_connection (exported);
		path = g_strdup (nm_connection_get_path (connection));
		if (path)
			g_ptr_array_add (connections, path);
	}
	
	/* Return a list of strings with paths to connection settings objects */
	return connections;
}

static void
nm_sysconfig_settings_finalize (GObject *object)
{
	NMSysconfigSettings *settings = NM_SYSCONFIG_SETTINGS (object);

	if (settings->connections) {
		g_slist_foreach (settings->connections, (GFunc) g_object_unref, NULL);
		g_slist_free (settings->connections);
		settings->connections = NULL;
	}

	G_OBJECT_CLASS (nm_sysconfig_settings_parent_class)->finalize (object);
}

static void
nm_sysconfig_settings_class_init (NMSysconfigSettingsClass *class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (class);	
	NMSettingsClass *settings_class = NM_SETTINGS_CLASS (class);
	
	object_class->finalize = nm_sysconfig_settings_finalize;
	settings_class->list_connections = nm_sysconfig_settings_list_connections;
}

static void
nm_sysconfig_settings_init (NMSysconfigSettings *sysconfig_settings)
{
	sysconfig_settings->connections = NULL;
}

NMSysconfigSettings *
nm_sysconfig_settings_new (DBusGConnection *g_conn)
{
	NMSysconfigSettings *settings;

	settings = g_object_new (nm_sysconfig_settings_get_type (), NULL);
	dbus_g_connection_register_g_object (g_conn, NM_DBUS_PATH_SETTINGS, G_OBJECT (settings));
	return settings;
}

void
nm_sysconfig_settings_add_connection (NMSysconfigSettings *settings,
                                      NMConnection *connection,
                                      DBusGConnection *g_connection)
{
	NMSysconfigExportedConnection *exported;

	g_return_if_fail (NM_IS_SYSCONFIG_SETTINGS (settings));
	g_return_if_fail (NM_IS_CONNECTION (connection));

	exported = nm_sysconfig_exported_connection_new (connection, g_connection);
	if (!exported) {
		g_warning ("%s: couldn't export the connection!", __func__);
		return;
	}

	settings->connections = g_slist_append (settings->connections, exported);

	nm_settings_signal_new_connection (NM_SETTINGS (settings),
	                                   NM_EXPORTED_CONNECTION (exported));
}

static void
remove_connection (NMSysconfigSettings *settings,
                   NMConnection *connection)
{
	GSList *iter;

	g_return_if_fail (NM_IS_SYSCONFIG_SETTINGS (settings));
	g_return_if_fail (NM_IS_CONNECTION (connection));

	for (iter = settings->connections; iter; iter = g_slist_next (iter)) {
		NMSysconfigExportedConnection *item = NM_SYSCONFIG_EXPORTED_CONNECTION (iter->data);
		NMExportedConnection *exported = NM_EXPORTED_CONNECTION (item);
		NMConnection *wrapped;

		wrapped = nm_exported_connection_get_connection (exported);

		if (wrapped == connection) {
			settings->connections = g_slist_remove (settings->connections, iter);
			nm_exported_connection_signal_removed (exported);
			g_object_unref (item);
			g_slist_free (iter);
			break;
		}
	}
}

void
nm_sysconfig_settings_remove_connection (NMSysconfigSettings *settings,
                                         NMConnection *connection)
{
	remove_connection (settings, connection);
}

void
nm_sysconfig_settings_update_connection (NMSysconfigSettings *settings,
                                         NMConnection *connection)
{
	GHashTable *hash;
	GSList *iter;
	NMSysconfigExportedConnection *found = NULL;

	g_return_if_fail (NM_IS_SYSCONFIG_SETTINGS (settings));
	g_return_if_fail (NM_IS_CONNECTION (connection));

	for (iter = settings->connections; iter; iter = g_slist_next (iter)) {
		NMSysconfigExportedConnection *item = NM_SYSCONFIG_EXPORTED_CONNECTION (iter->data);
		NMConnection *wrapped;

		wrapped = nm_exported_connection_get_connection (NM_EXPORTED_CONNECTION (item));

		if (wrapped == connection) {
			found = item;
			break;
		}
	}

	if (!found) {
		g_warning ("%s: cannot update unknown connection", __func__);
		return;
	}

	/* If the connection is no longer valid, it gets removed */
	if (!nm_connection_verify (connection)) {
		remove_connection (settings, connection);
		return;
	}

	hash = nm_connection_to_hash (connection);
	nm_exported_connection_signal_updated (NM_EXPORTED_CONNECTION (found), hash);
	g_hash_table_destroy (hash);
}

