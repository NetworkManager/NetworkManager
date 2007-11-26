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

static void
connection_settings_get_secrets (NMConnectionSettings *connection,
				 const gchar *setting_name,
				 const gchar **hints,
				 gboolean request_new,
				 DBusGMethodInvocation *context)
{
	
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
static GPtrArray *nm_sysconfig_settings_list_connections (NMSettings *settings);

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
                                      NMSysconfigConnectionSettings *connection)
{
	g_return_if_fail (NM_IS_SYSCONFIG_SETTINGS (settings));
	g_return_if_fail (NM_IS_SYSCONFIG_CONNECTION_SETTINGS (connection));

	settings->connections = g_slist_append (settings->connections, connection);

	nm_settings_signal_new_connection (NM_SETTINGS (settings),
	                                   NM_CONNECTION_SETTINGS (connection));
}
