/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright 2008, 2014 Red Hat, Inc.
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include <gio/gio.h>

#define NM_AVAHI_AUTOIPD_DBUS_SERVICE   "org.freedesktop.nm_avahi_autoipd"
#define NM_AVAHI_AUTOIPD_DBUS_INTERFACE "org.freedesktop.nm_avahi_autoipd"

static void
on_name_acquired (GDBusConnection *connection,
                  const gchar     *name,
                  gpointer         loop)
{
	g_main_loop_quit (loop);
}

static void
on_name_lost (GDBusConnection *connection,
              const gchar     *name,
              gpointer         user_data)
{
	g_printerr ("Error: Could not acquire the NM autoipd service.");
	exit (1);
}

int
main (int argc, char *argv[])
{
	GDBusConnection *connection;
	char *event, *iface, *address;
	GMainLoop *loop;
	GError *error = NULL;

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

	if (argc != 4) {
		g_printerr ("Error: expected 3 arguments (event, interface, address).\n");
		exit (1);
	}

	event = argv[1];
	iface = argv[2];
	address = argv[3] ? argv[3] : "";

	if (!event || !iface || !strlen (event) || !strlen (iface)) {
		g_printerr ("Error: unexpected arguments received from avahi-autoipd.\n");
		exit (1);
	}

	/* Get a connection to the system bus */
	connection = g_bus_get_sync (G_BUS_TYPE_SYSTEM, NULL, &error);
	if (error) {
		char *remote_error = g_dbus_error_get_remote_error (error);

		g_dbus_error_strip_remote_error (error);
		g_printerr ("Error: could not get the system bus.  Make sure "
		            "the message bus daemon is running!  Message: (%s) %s\n",
		            remote_error, error->message);
		g_free (remote_error);
		g_error_free (error);
		return 1;
	}

	/* Acquire the bus name */
	loop = g_main_loop_new (NULL, FALSE);
	g_bus_own_name_on_connection (connection,
	                              NM_AVAHI_AUTOIPD_DBUS_SERVICE,
	                              0,
	                              on_name_acquired,
	                              on_name_lost,
	                              loop, NULL);
	g_main_loop_run (loop);
	g_main_loop_unref (loop);

	/* Send the signal */
	if (!g_dbus_connection_emit_signal (connection,
	                                    NULL,
	                                    "/",
	                                    NM_AVAHI_AUTOIPD_DBUS_INTERFACE,
	                                    "Event",
	                                    g_variant_new ("(sss)",
	                                                   event,
	                                                   iface,
	                                                   address),
	                                    &error)) {
		g_dbus_error_strip_remote_error (error);
		g_printerr ("Error: Could not send autoipd Event signal: %s\n", error->message);
		g_error_free (error);
		return 1;
	}

	if (!g_dbus_connection_flush_sync (connection, NULL, &error)) {
		g_dbus_error_strip_remote_error (error);
		g_printerr ("Error: Could not flush D-Bus connection: %s\n", error->message);
		g_error_free (error);
		return 1;
	}

	g_object_unref (connection);
	return 0;
}

