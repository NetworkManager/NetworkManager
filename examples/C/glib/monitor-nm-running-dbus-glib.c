/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* vim: set ft=c ts=4 sts=4 sw=4 noexpandtab smartindent: */
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
 * (C) Copyright 2012 Red Hat, Inc.
 */

/*
 * This example monitors whether NM is running by checking D-Bus
 * NameOwnerChanged signal.
 * It uses dbus-glib library.
 *
 * Standalone compilation:
 *   gcc -Wall `pkg-config --libs --cflags glib-2.0 dbus-glib-1` monitor-nm-running.c -o monitor-nm-running
 */

#include <glib.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-bindings.h>
#include <string.h>

#define NM_DBUS_SERVICE "org.freedesktop.NetworkManager"

static void
proxy_name_owner_changed (DBusGProxy *proxy,
                          const char *name,
                          const char *old_owner,
                          const char *new_owner,
                          gpointer user_data)
{
	gboolean *nm_running = (gboolean *) user_data;
	gboolean old_good = (old_owner && strlen (old_owner));
	gboolean new_good = (new_owner && strlen (new_owner));
	gboolean new_running = FALSE;

	/* We are only interested in NetworkManager */
	if (!name || strcmp (name, NM_DBUS_SERVICE) != 0)
		return;

	if (!old_good && new_good)
		new_running = TRUE;
	else if (old_good && !new_good)
		new_running = FALSE;

	*nm_running = new_running;

	g_print ("name: '%s', old_owner: '%s', new_owner: '%s'", name, old_owner, new_owner);
	g_print (" => NM is %s\n", *nm_running ? "running" : "not running");
}


int
main (int argc, char *argv[])
{
	DBusGConnection *bus;
	DBusGProxy *bus_proxy;
	GMainLoop *loop = NULL;
	GError *err = NULL;
	gboolean nm_running;

#if !GLIB_CHECK_VERSION (2, 35, 0)
	/* Initialize GType system */
	g_type_init ();
#endif

	g_print ("Monitor 'org.freedesktop.NetworkManager' D-Bus name\n");
	g_print ("===================================================\n");

	/* Get system bus */
	bus = dbus_g_bus_get (DBUS_BUS_SYSTEM, NULL);

	/* Create a D-Bus proxy to D-Bus daemon */
	bus_proxy = dbus_g_proxy_new_for_name (bus,
	                                       "org.freedesktop.DBus",
	                                       "/org/freedesktop/DBus",
	                                       "org.freedesktop.DBus");

	if (!bus_proxy) {
		g_message ("Error: Couldn't create D-Bus object proxy for org.freedesktop.DBus.");
		dbus_g_connection_unref (bus);
		return -1;
	}

	/* Call NameHasOwner method to find out if NM is running. When NM runs it claims
	 * 'org.freedesktop.NetworkManager' service name on D-Bus */
	if (!org_freedesktop_DBus_name_has_owner (bus_proxy, NM_DBUS_SERVICE, &nm_running, &err)) {
		g_message ("Error: NameHasOwner request failed: %s",
		                 (err && err->message) ? err->message : "(unknown)");
		g_clear_error (&err);
		g_object_unref (bus_proxy);
		dbus_g_connection_unref (bus);
		return -1;
	}
	g_print ("NM is %s\n", nm_running ? "running" : "not running");


	/* Connect to NameOwnerChanged signal to monitor NM running state */
	dbus_g_proxy_add_signal (bus_proxy, "NameOwnerChanged",
	                         G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
	                         G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (bus_proxy,
	                             "NameOwnerChanged",
	                             G_CALLBACK (proxy_name_owner_changed),
	                             &nm_running, NULL);

	loop = g_main_loop_new (NULL, FALSE);  /* Create main loop */
	g_main_loop_run (loop);                /* Run main loop */

	g_object_unref (bus_proxy);
	dbus_g_connection_unref (bus);

	return 0;
}

