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
 * (C) Copyright 2010 -2014 Red Hat, Inc.
 */

/*
 * The example shows how to call the D-Bus properties interface to get the
 * list of currently active connections known to NetworkManager.  It uses
 * dbus-glib and libnm-util libraries.
 *
 * Compile with:
 *   gcc -Wall `pkg-config --libs --cflags glib-2.0 dbus-glib-1 libnm-util` get-active-connections-dbus-glib.c -o get-active-connections-dbus-glib
 */

#include <stdio.h>
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
#define DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH    (dbus_g_type_get_collection ("GPtrArray", DBUS_TYPE_G_OBJECT_PATH))

static void
print_connection (DBusGConnection *bus, const char *path)
{
	DBusGProxy *proxy;
	GError *error = NULL;
	GHashTable *hash = NULL;
	NMConnection *connection = NULL;

	/* This function asks NetworkManager for the details of the connection */

	/* Create the D-Bus proxy so we can ask it for the connection configuration details. */
	proxy = dbus_g_proxy_new_for_name (bus,
	                                   NM_DBUS_SERVICE,
	                                   path,
	                                   NM_DBUS_IFACE_SETTINGS_CONNECTION);
	g_assert (proxy);

	/* Request the all the configuration of the Connection */
	if (!dbus_g_proxy_call (proxy, "GetSettings", &error,
	                        G_TYPE_INVALID,
	                        DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT, &hash,
	                        G_TYPE_INVALID)) {
		g_warning ("Failed to get active connection Connection property: %s",
		           error->message);
		g_error_free (error);
		goto out;
	}

	/* Using the raw configuration, create an NMConnection object for it. This
	 * step also verifies that the data we got from NetworkManager are valid. */
	connection = nm_connection_new_from_hash (hash, &error);
	if (!connection) {
		g_warning ("Received invalid connection data: %s", error->message);
		g_error_free (error);
		goto out;
	}

	/* And finally dump all the configuration to stdout */
	printf ("%s <=> %s\n", nm_connection_get_id (connection), path);
	nm_connection_dump (connection);

out:
	if (connection)
		g_object_unref (connection);
	if (hash)
		g_hash_table_destroy (hash);
	g_object_unref (proxy);
}

static void
get_active_connection_details (DBusGConnection *bus, const char *obj_path)
{
	DBusGProxy *props_proxy;
	GValue path_value = G_VALUE_INIT;
	GError *error = NULL;
	const char *path = NULL;

	/* This function gets the backing Connection object that describes the
	 * network configuration that the ActiveConnection object is actually using.
	 * The ActiveConnection object contains the mapping between the configuration
	 * and the actual network interfaces that are using that configuration.
	 */

	/* Create a D-Bus object proxy for the active connection object's properties */
	props_proxy = dbus_g_proxy_new_for_name (bus,
	                                         NM_DBUS_SERVICE,
	                                         obj_path,
	                                         DBUS_INTERFACE_PROPERTIES);
	g_assert (props_proxy);
	
	/* Get the object path of the Connection details */
	if (!dbus_g_proxy_call (props_proxy, "Get", &error,
	                        G_TYPE_STRING, NM_DBUS_INTERFACE_ACTIVE_CONNECTION,
	                        G_TYPE_STRING, "Connection",
	                        G_TYPE_INVALID,
	                        G_TYPE_VALUE, &path_value,
	                        G_TYPE_INVALID)) {
		g_warning ("Failed to get active connection Connection property: %s",
		           error->message);
		g_error_free (error);
		goto out;
	}

	if (!G_VALUE_HOLDS (&path_value, DBUS_TYPE_G_OBJECT_PATH)) {
		g_warning ("Unexpected type returned getting Connection property: %s",
		           G_VALUE_TYPE_NAME (&path_value));
		goto out;
	}

	path = g_value_get_boxed (&path_value);
	if (!path) {
		g_warning ("Missing connection path!");
		goto out;
	}

	/* Print out the actual connection details */
	print_connection (bus, path);

out:
	g_value_unset (&path_value);
	g_object_unref (props_proxy);
}

static void
get_active_connections (DBusGConnection *bus, DBusGProxy *proxy)
{
	GError *error = NULL;
	GValue value = G_VALUE_INIT;
	GPtrArray *paths = NULL;
	const char *a_path;
	int i;

	/* Get the ActiveConnections property from the NM Manager object */
	if (!dbus_g_proxy_call (proxy, "Get", &error,
	                        G_TYPE_STRING, NM_DBUS_INTERFACE,
	                        G_TYPE_STRING, "ActiveConnections",
	                        G_TYPE_INVALID,
	                        G_TYPE_VALUE, &value,
	                        G_TYPE_INVALID)) {
		g_warning ("Failed to get ActiveConnections property: %s", error->message);
		g_error_free (error);
		return;
	}

	/* Make sure the ActiveConnections property is the type we expect it to be */
	if (!G_VALUE_HOLDS (&value, DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH)) {
		g_warning ("Unexpected type returned getting ActiveConnections: %s",
		           G_VALUE_TYPE_NAME (&value));
		goto out;
	}

	/* Extract the active connections array from the GValue */
	paths = g_value_get_boxed (&value);
	if (!paths) {
		g_warning ("Could not retrieve active connections property");
		goto out;
	}

	/* And print out the details for each active connection */
	for (i = 0; i < paths->len; i++) {
		a_path = g_ptr_array_index (paths, i);
		printf ("Active connection path: %s\n", a_path);
		get_active_connection_details (bus, a_path);
	}

out:
	g_value_unset (&value);
}


int main (int argc, char *argv[])
{
	DBusGConnection *bus;
	DBusGProxy *props_proxy;

#if !GLIB_CHECK_VERSION (2, 35, 0)
	/* Initialize GType system */
	g_type_init ();
#endif

	/* Get system bus */
	bus = dbus_g_bus_get (DBUS_BUS_SYSTEM, NULL);

	/* Create a D-Bus proxy to get the object properties from the NM Manager
	 * object.  NM_DBUS_* defines are from NetworkManager.h.
	 */
	props_proxy = dbus_g_proxy_new_for_name (bus,
	                                         NM_DBUS_SERVICE,
	                                         NM_DBUS_PATH,
	                                         DBUS_INTERFACE_PROPERTIES);
	g_assert (props_proxy);

	/* Get active connections */
	get_active_connections (bus, props_proxy);

	g_object_unref (props_proxy);
	dbus_g_connection_unref (bus);

	return 0;
}
