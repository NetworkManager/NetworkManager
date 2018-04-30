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
 * Copyright 2012 Red Hat, Inc.
 */

/*
 * This example monitors whether NM is running by checking if
 * "org.freedesktop.NetworkManager" is owned by a process on D-Bus.
 * It uses g_bus_watch_name().
 *
 * See also http://developer.gnome.org/gio/stable/gio-Watching-Bus-Names.html
 *
 * Standalone compilation:
 *   gcc -Wall monitor-nm-running-gdbus.c -o monitor-nm-running-gdbus `pkg-config --libs --cflags gio-2.0`
 */

#include <gio/gio.h>

static void
on_name_appeared (GDBusConnection *connection,
                  const gchar     *name,
                  const gchar     *name_owner,
                  gpointer         user_data)
{
	g_print ("Name '%s' on the system bus is owned by %s => NM is running\n",
	         name, name_owner);
}

static void
on_name_vanished (GDBusConnection *connection,
                  const gchar     *name,
                  gpointer         user_data)
{
	g_print ("Name '%s' does not exist on the system bus => NM is not running\n", name);
}

int
main (int argc, char *argv[])
{
	guint watcher_id;
	GMainLoop *loop;
	GBusNameWatcherFlags flags;

	g_print ("Monitor 'org.freedesktop.NetworkManager' D-Bus name\n");
	g_print ("===================================================\n");

	flags = G_BUS_NAME_WATCHER_FLAGS_NONE;

	/* Start to watch "org.freedesktop.NetworkManager" bus name */
	watcher_id = g_bus_watch_name (G_BUS_TYPE_SYSTEM,
	                               "org.freedesktop.NetworkManager",
	                               flags,
	                               on_name_appeared,
	                               on_name_vanished,
	                               NULL,
	                               NULL);

	/* Run main loop */
	loop = g_main_loop_new (NULL, FALSE);
	g_main_loop_run (loop);

	/* Stop watching the name */
	g_bus_unwatch_name (watcher_id);

	return 0;
}

