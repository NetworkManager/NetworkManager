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
 * The example shows how to call the D-Bus properties interface to get the list
 * of currently active connections known to NetworkManager.  It uses GDBus, plus
 * a few defines from the NetworkManager headers.
 *
 * Compile with:
 *   gcc -Wall `pkg-config --cflags libnm` `pkg-config --cflags --libs gio-2.0` get-active-connections-gdbus.c -o get-active-connections-gdbus
 */

#include <string.h>
#include <gio/gio.h>
#include <NetworkManager.h>

static void
print_setting (const char *setting_name, GVariant *setting)
{
	GVariantIter iter;
	const char *property_name;
	GVariant *value;
	char *printed_value;

	g_print ("  %s:\n", setting_name);
	g_variant_iter_init (&iter, setting);
	while (g_variant_iter_next (&iter, "{&sv}", &property_name, &value)) {
		printed_value = g_variant_print (value, FALSE);
		if (strcmp (printed_value, "[]") != 0)
			g_print ("    %s: %s\n", property_name, printed_value);
		g_free (printed_value);
		g_variant_unref (value);
	}
}

static void
print_connection (const char *path)
{
	GDBusProxy *proxy;
	GError *error = NULL;
	GVariant *ret, *connection = NULL, *s_con = NULL;
	const char *id, *type;
	gboolean found;
	GVariantIter iter;
	const char *setting_name;
	GVariant *setting;

	/* This function asks NetworkManager for the details of the connection */

	/* Create the D-Bus proxy so we can ask it for the connection configuration details. */
	proxy = g_dbus_proxy_new_for_bus_sync (G_BUS_TYPE_SYSTEM,
	                                       G_DBUS_PROXY_FLAGS_NONE,
	                                       NULL,
	                                       NM_DBUS_SERVICE,
	                                       path,
	                                       NM_DBUS_INTERFACE_SETTINGS_CONNECTION,
	                                       NULL, NULL);
	g_assert (proxy);

	/* Request the all the configuration of the Connection */
	ret = g_dbus_proxy_call_sync (proxy,
	                              "GetSettings",
	                              NULL,
	                              G_DBUS_CALL_FLAGS_NONE, -1,
	                              NULL, &error);
	if (!ret) {
		g_dbus_error_strip_remote_error (error);
		g_warning ("Failed to get connection settings: %s\n", error->message);
		g_error_free (error);
		goto out;
	}

	g_variant_get (ret, "(@a{sa{sv}})", &connection);

	s_con = g_variant_lookup_value (connection, NM_SETTING_CONNECTION_SETTING_NAME, NULL);
	g_assert (s_con != NULL);
	found = g_variant_lookup (s_con, NM_SETTING_CONNECTION_ID, "&s", &id);
	g_assert (found);
	found = g_variant_lookup (s_con, NM_SETTING_CONNECTION_TYPE, "&s", &type);
	g_assert (found);

	/* Dump the configuration to stdout */
	g_print ("%s <=> %s\n", id, path);

	/* Connection setting first */
	print_setting (NM_SETTING_CONNECTION_SETTING_NAME, s_con);

	/* Then the type-specific setting */
	setting = g_variant_lookup_value (connection, type, NULL);
	if (setting) {
		print_setting (type, setting);
		g_variant_unref (setting);
	}

	g_variant_iter_init (&iter, connection);
	while (g_variant_iter_next (&iter, "{&s@a{sv}}", &setting_name, &setting)) {
		if (   strcmp (setting_name, NM_SETTING_CONNECTION_SETTING_NAME) != 0
		    && strcmp (setting_name, type) != 0)
			print_setting (setting_name, setting);
		g_variant_unref (setting);
	}
	g_print ("\n");

out:
	if (s_con)
		g_variant_unref (s_con);
	if (connection)
		g_variant_unref (connection);
	if (ret)
		g_variant_unref (ret);
	g_object_unref (proxy);
}

static void
get_active_connection_details (const char *obj_path)
{
	GDBusProxy *props_proxy;
	GVariant *ret = NULL, *path_value = NULL;
	const char *path = NULL;
	GError *error = NULL;

	/* This function gets the backing Connection object that describes the
	 * network configuration that the ActiveConnection object is actually using.
	 * The ActiveConnection object contains the mapping between the configuration
	 * and the actual network interfaces that are using that configuration.
	 */

	/* Create a D-Bus object proxy for the active connection object's properties */
	props_proxy = g_dbus_proxy_new_for_bus_sync (G_BUS_TYPE_SYSTEM,
	                                             G_DBUS_PROXY_FLAGS_NONE,
	                                             NULL,
	                                             NM_DBUS_SERVICE,
	                                             obj_path,
	                                             "org.freedesktop.DBus.Properties",
	                                             NULL, NULL);
	g_assert (props_proxy);

	/* Get the object path of the Connection details */
	ret = g_dbus_proxy_call_sync (props_proxy,
	                              "Get",
	                              g_variant_new ("(ss)",
	                                             NM_DBUS_INTERFACE_ACTIVE_CONNECTION,
	                                             "Connection"),
	                              G_DBUS_CALL_FLAGS_NONE, -1,
	                              NULL, &error);
	if (!ret) {
		g_dbus_error_strip_remote_error (error);
		g_warning ("Failed to get active connection Connection property: %s\n",
		           error->message);
		g_error_free (error);
		goto out;
	}

	g_variant_get (ret, "(v)", &path_value);
	if (!g_variant_is_of_type (path_value, G_VARIANT_TYPE_OBJECT_PATH)) {
		g_warning ("Unexpected type returned getting Connection property: %s",
		           g_variant_get_type_string (path_value));
		goto out;
	}

	path = g_variant_get_string (path_value, NULL);

	/* Print out the actual connection details */
	print_connection (path);

out:
	if (path_value)
		g_variant_unref (path_value);
	if (ret)
		g_variant_unref (ret);
	g_object_unref (props_proxy);
}

static void
get_active_connections (GDBusProxy *proxy)
{
	GError *error = NULL;
	GVariant *ret = NULL, *value = NULL;
	char **paths;
	int i;

	/* Get the ActiveConnections property from the NM Manager object */
	ret = g_dbus_proxy_call_sync (proxy,
	                              "Get",
	                              g_variant_new ("(ss)",
	                                             NM_DBUS_INTERFACE,
	                                             "ActiveConnections"),
	                              G_DBUS_CALL_FLAGS_NONE, -1,
	                              NULL, &error);
	if (!ret) {
		g_dbus_error_strip_remote_error (error);
		g_warning ("Failed to get ActiveConnections property: %s\n", error->message);
		g_error_free (error);
		return;
	}

	g_variant_get (ret, "(v)", &value);

	/* Make sure the ActiveConnections property is the type we expect it to be */
	if (!g_variant_is_of_type (value, G_VARIANT_TYPE ("ao"))) {
		g_warning ("Unexpected type returned getting ActiveConnections: %s",
		           g_variant_get_type_string (value));
		goto out;
	}

	/* Extract the active connections array from the GValue */
	paths = g_variant_dup_objv (value, NULL);
	if (!paths) {
		g_warning ("Could not retrieve active connections property");
		goto out;
	}

	/* And print out the details for each active connection */
	for (i = 0; paths[i]; i++) {
		g_print ("Active connection path: %s\n", paths[i]);
		get_active_connection_details (paths[i]);
	}
	g_strfreev (paths);

out:
	if (value)
		g_variant_unref (value);
	if (ret)
		g_variant_unref (ret);
}


int
main (int argc, char *argv[])
{
	GDBusProxy *props_proxy;

#if !GLIB_CHECK_VERSION (2, 35, 0)
	/* Initialize GType system */
	g_type_init ();
#endif

	/* Create a D-Bus proxy to get the object properties from the NM Manager
	 * object.  NM_DBUS_* defines are from nm-dbus-interface.h.
	 */
	props_proxy = g_dbus_proxy_new_for_bus_sync (G_BUS_TYPE_SYSTEM,
	                                             G_DBUS_PROXY_FLAGS_NONE,
	                                             NULL,
	                                             NM_DBUS_SERVICE,
	                                             NM_DBUS_PATH,
	                                             "org.freedesktop.DBus.Properties",
	                                             NULL, NULL);
	g_assert (props_proxy);

	/* Get active connections */
	get_active_connections (props_proxy);

	g_object_unref (props_proxy);

	return 0;
}
