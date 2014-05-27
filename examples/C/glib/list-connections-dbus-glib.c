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
 * The example shows how to list connections from System Settings service using direct
 * D-Bus call of ListConnections method.
 * The example uses dbus-glib, libnm-util libraries.
 *
 * Compile with:
 *   gcc -Wall `pkg-config --libs --cflags glib-2.0 dbus-glib-1 libnm-util` list-connections-dbus.c -o list-connections-dbus
 */

#include <glib.h>
#include <dbus/dbus-glib.h>
#include <stdio.h>

#include <NetworkManager.h>
#include <nm-utils.h>

#define DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH    (dbus_g_type_get_collection ("GPtrArray", DBUS_TYPE_G_OBJECT_PATH))

static void
list_connections (DBusGProxy *proxy)
{
	int i;
	GError *error = NULL;
	GPtrArray *con_array;
	gboolean success;

	/* Call ListConnections D-Bus method */
	success = dbus_g_proxy_call (proxy, "ListConnections", &error,
	                             /* No input arguments */
	                             G_TYPE_INVALID,
	                             DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH, &con_array, /* Return values */
	                             G_TYPE_INVALID);
	if (!success) {
		printf ("ListConnections failed: %s", error->message);
		g_error_free (error);
		return;
	}

	for (i = 0; con_array && i < con_array->len; i++) {
		char *connection_path = g_ptr_array_index (con_array, i);
		printf ("%s\n", connection_path);
		g_free (connection_path);
	}
	g_ptr_array_free (con_array, TRUE);
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

	/* List connections of system settings service */
	list_connections (proxy);

	g_object_unref (proxy);
	dbus_g_connection_unref (bus);

	return 0;
}
