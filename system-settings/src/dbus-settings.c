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
#include "nm-utils.h"

static gchar *connection_settings_get_id (NMConnectionSettings *connection);
static void connection_settings_get_secrets (NMConnectionSettings *connection,
                                             const gchar *setting_name,
                                             const gchar **hints,
                                             gboolean request_new,
                                             DBusGMethodInvocation *context);

G_DEFINE_TYPE (NMSysconfigConnectionSettings, nm_sysconfig_connection_settings, NM_TYPE_CONNECTION_SETTINGS);

/*
 * NMSysconfigConnectionSettings
 */
static gchar *
connection_settings_get_id (NMConnectionSettings *connection)
{
	NMSysconfigConnectionSettings *c = NM_SYSCONFIG_CONNECTION_SETTINGS (connection);

	return g_strdup (c->id);
}

static GHashTable *
connection_settings_get_settings (NMConnectionSettings *connection)
{
	NMSysconfigConnectionSettings *c = NM_SYSCONFIG_CONNECTION_SETTINGS (connection);

	return nm_connection_to_hash (c->connection);
}

static GValue *
string_to_gvalue (const char *str)
{
	GValue *val;

	val = g_slice_new0 (GValue);
	g_value_init (val, G_TYPE_STRING);
	g_value_set_string (val, str);

	return val;
}

static void
destroy_gvalue (gpointer data)
{
	GValue *value = (GValue *) data;

	g_value_unset (value);
	g_slice_free (GValue, value);
}

static void
add_one_secret_to_hash (NMSetting *setting,
                        const char *key,
                        const GValue *value,
                        gboolean secret,
                        gpointer user_data)
{
	GHashTable *secrets = (GHashTable *) user_data;
	const char *str_val;

	if (!secret)
		return;

	if (!G_VALUE_HOLDS (value, G_TYPE_STRING))
		return;

	str_val = g_object_get_data (G_OBJECT (setting), key);
	if (!str_val)
		return;

	g_hash_table_insert (secrets, g_strdup (key), string_to_gvalue (str_val));
}

static void
connection_settings_get_secrets (NMConnectionSettings *sys_connection,
				 const gchar *setting_name,
				 const gchar **hints,
				 gboolean request_new,
				 DBusGMethodInvocation *context)
{
	NMConnection *connection = NM_SYSCONFIG_CONNECTION_SETTINGS (sys_connection)->connection;
	GError *error = NULL;
	GHashTable *secrets;
	NMSettingConnection *s_con;
	NMSetting *setting;

	g_return_if_fail (NM_IS_CONNECTION (connection));
	g_return_if_fail (setting_name != NULL);

	setting = nm_connection_get_setting_by_name (connection, setting_name);
	if (!setting) {
		g_set_error (&error, NM_SETTINGS_ERROR, 1,
		             "%s.%d - Connection didn't have requested setting '%s'.",
		             __FILE__, __LINE__, setting_name);
		g_warning (error->message);
		dbus_g_method_return_error (context, error);
		g_error_free (error);
		return;
	}

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection,
												   NM_TYPE_SETTING_CONNECTION));
	if (!s_con || !s_con->id || !strlen (s_con->id) || !s_con->type) {
		g_set_error (&error, NM_SETTINGS_ERROR, 1,
		             "%s.%d - Connection didn't have required '"
		             NM_SETTING_CONNECTION_SETTING_NAME
		             "' setting , or the connection name was invalid.",
		             __FILE__, __LINE__);
		g_warning (error->message);
		dbus_g_method_return_error (context, error);
		g_error_free (error);
		return;
	}

	secrets = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, destroy_gvalue);
	nm_setting_enumerate_values (setting, add_one_secret_to_hash, secrets);
	if (g_hash_table_size (secrets) == 0) {
		g_set_error (&error, NM_SETTINGS_ERROR, 1,
		             "%s.%d - Secrets were found for setting '%s' but none"
		             " were valid.", __FILE__, __LINE__, setting_name);
		g_warning (error->message);
		dbus_g_method_return_error (context, error);
		g_error_free (error);
	} else {
		dbus_g_method_return (context, secrets);
	}

	g_hash_table_destroy (secrets);
}

static void
nm_sysconfig_connection_settings_finalize (GObject *object)
{
	G_OBJECT_CLASS (nm_sysconfig_connection_settings_parent_class)->finalize (object);
}

static void
nm_sysconfig_connection_settings_class_init (NMSysconfigConnectionSettingsClass *class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (class);
	NMConnectionSettingsClass *connection = NM_CONNECTION_SETTINGS_CLASS (class);

	object_class->finalize = nm_sysconfig_connection_settings_finalize;

	connection->get_id = connection_settings_get_id;
	connection->get_settings = connection_settings_get_settings;
	connection->get_secrets = connection_settings_get_secrets;
}

static void
nm_sysconfig_connection_settings_init (NMSysconfigConnectionSettings *sysconfig_connection_settings)
{
	
}

NMSysconfigConnectionSettings *
nm_sysconfig_connection_settings_new (NMConnection *connection,
                                      DBusGConnection *g_conn)
{
	NMSysconfigConnectionSettings *settings;
	NMSettingConnection *s_con;

	settings = g_object_new (nm_sysconfig_connection_settings_get_type(), NULL);
	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	settings->id = g_strdup (s_con->id);
	settings->connection = connection;

	nm_connection_settings_register_object (NM_CONNECTION_SETTINGS (settings), g_conn);
	
	return settings;
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
		NMConnectionSettings *connection = NM_CONNECTION_SETTINGS (iter->data);
		char *path;

		path = g_strdup (nm_connection_settings_get_dbus_object_path (connection));
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
	NMSysconfigConnectionSettings *exported;

	g_return_if_fail (NM_IS_SYSCONFIG_SETTINGS (settings));
	g_return_if_fail (NM_IS_CONNECTION (connection));

	exported = nm_sysconfig_connection_settings_new (connection, g_connection);
	if (!exported) {
		g_warning ("%s: couldn't export the connection!", __func__);
		return;
	}

	settings->connections = g_slist_append (settings->connections, exported);

	nm_settings_signal_new_connection (NM_SETTINGS (settings),
	                                   NM_CONNECTION_SETTINGS (exported));
}

static void
remove_connection (NMSysconfigSettings *settings,
                   NMConnection *connection)
{
	GSList *iter;

	g_return_if_fail (NM_IS_SYSCONFIG_SETTINGS (settings));
	g_return_if_fail (NM_IS_CONNECTION (connection));

	for (iter = settings->connections; iter; iter = g_slist_next (iter)) {
		NMSysconfigConnectionSettings *item = NM_SYSCONFIG_CONNECTION_SETTINGS (iter->data);

		if (item->connection == connection) {
			settings->connections = g_slist_remove (settings->connections, iter);
			nm_connection_settings_signal_removed (NM_CONNECTION_SETTINGS (item));
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
	NMSysconfigConnectionSettings *found = NULL;

	g_return_if_fail (NM_IS_SYSCONFIG_SETTINGS (settings));
	g_return_if_fail (NM_IS_CONNECTION (connection));

	for (iter = settings->connections; iter; iter = g_slist_next (iter)) {
		NMSysconfigConnectionSettings *item = NM_SYSCONFIG_CONNECTION_SETTINGS (iter->data);

		if (item->connection == connection) {
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
	nm_connection_settings_signal_updated (NM_CONNECTION_SETTINGS (found), hash);
	g_hash_table_destroy (hash);
}

