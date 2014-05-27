/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
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
 * (C) Copyright 2011 Red Hat, Inc.
 */

/*
 * The example shows how to call AddConnection() D-Bus method to add
 * a connection to system settings service. It uses dbus-glib and libnm-util
 * libraries.
 *
 * Compile with:
 *   gcc -Wall `pkg-config --libs --cflags glib-2.0 dbus-glib-1 libnm-util` add-connection-glib.c -o add-connection-glib
 */

#include <glib.h>
#include <dbus/dbus-glib.h>

#include <nm-connection.h>
#include <nm-setting-connection.h>
#include <nm-setting-wired.h>
#include <nm-setting-ip4-config.h>
#include <NetworkManager.h>
#include <nm-utils.h>

#define DBUS_TYPE_G_MAP_OF_VARIANT          (dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_VALUE))
#define DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT   (dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, DBUS_TYPE_G_MAP_OF_VARIANT))

static void
add_connection (DBusGProxy *proxy, const char *con_name)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	char *uuid, *new_con_path = NULL;
	GHashTable *hash;
	GError *error = NULL;

	/* Create a new connection object */
	connection = (NMConnection *) nm_connection_new ();

	/* Build up the 'connection' Setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	uuid = nm_utils_uuid_generate ();
	g_object_set (G_OBJECT (s_con),
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_ID, con_name,
	              NM_SETTING_CONNECTION_TYPE, "802-3-ethernet",
	              NULL);
	g_free (uuid);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	/* Build up the 'wired' Setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	/* Build up the 'ipv4' Setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	g_object_set (G_OBJECT (s_ip4),
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NULL);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	hash = nm_connection_to_hash (connection, NM_SETTING_HASH_FLAG_ALL);

	/* Call AddConnection with the hash as argument */
	if (!dbus_g_proxy_call (proxy, "AddConnection", &error,
	                        DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT, hash,
	                        G_TYPE_INVALID,
	                        DBUS_TYPE_G_OBJECT_PATH, &new_con_path,
	                        G_TYPE_INVALID)) {
		g_print ("Error adding connection: %s %s",
		         dbus_g_error_get_name (error),
		         error->message);
		g_clear_error (&error);
	} else {
		g_print ("Added: %s\n", new_con_path);
		g_free (new_con_path);
	}

	g_hash_table_destroy (hash);
	g_object_unref (connection);
}


int main (int argc, char *argv[])
{
	DBusGConnection *bus;
	DBusGProxy *proxy;

#if !GLIB_CHECK_VERSION (2, 35, 0)
	/* Initialize GType system */
	g_type_init ();
#endif

	/* Get system bus */
	bus = dbus_g_bus_get (DBUS_BUS_SYSTEM, NULL);

	/* Create a D-Bus proxy; NM_DBUS_* defined in NetworkManager.h */
	proxy = dbus_g_proxy_new_for_name (bus,
	                                   NM_DBUS_SERVICE,
	                                   NM_DBUS_PATH_SETTINGS,
	                                   NM_DBUS_IFACE_SETTINGS);

	/* Add a connection */
	add_connection (proxy, "__Test connection__");

	g_object_unref (proxy);
	dbus_g_connection_unref (bus);

	return 0;
}
