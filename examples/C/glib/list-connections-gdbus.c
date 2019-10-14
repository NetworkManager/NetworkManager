// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2011, 2014 Red Hat, Inc.
 */

/*
 * The example shows how to list connections from the System Settings service
 * using direct D-Bus calls.  The example uses GDBus, plus a few defines from
 * the NetworkManager headers.  Contrast list-connections-libnm, which is higher
 * level because it uses libnm.
 *
 * Compile with:
 *   gcc -Wall list-connections-gdbus.c -o list-connections-gdbus `pkg-config --cflags --libs libnm`
 */

#include <gio/gio.h>

#include <nm-dbus-interface.h>

static void
list_connections (GDBusProxy *proxy)
{
	int i;
	GError *error = NULL;
	GVariant *ret;
	char **paths;

	/* Call ListConnections D-Bus method */
	ret = g_dbus_proxy_call_sync (proxy,
	                              "ListConnections",
	                              NULL,
	                              G_DBUS_CALL_FLAGS_NONE, -1,
	                              NULL, &error);
	if (!ret) {
		g_dbus_error_strip_remote_error (error);
		g_print ("ListConnections failed: %s\n", error->message);
		g_error_free (error);
		return;
	}

	g_variant_get (ret, "(^ao)", &paths);
	g_variant_unref (ret);

	for (i = 0; paths[i]; i++)
		g_print ("%s\n", paths[i]);
	g_strfreev (paths);
}

int
main (int argc, char *argv[])
{
	GDBusProxy *proxy;

	/* Create a D-Bus proxy; NM_DBUS_* defined in nm-dbus-interface.h */
	proxy = g_dbus_proxy_new_for_bus_sync (G_BUS_TYPE_SYSTEM,
	                                       G_DBUS_PROXY_FLAGS_NONE,
	                                       NULL,
	                                       NM_DBUS_SERVICE,
	                                       NM_DBUS_PATH_SETTINGS,
	                                       NM_DBUS_INTERFACE_SETTINGS,
	                                       NULL, NULL);
	g_assert (proxy != NULL);

	/* List connections of system settings service */
	list_connections (proxy);

	g_object_unref (proxy);

	return 0;
}
