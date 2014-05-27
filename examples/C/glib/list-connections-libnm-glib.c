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
 * The example shows how to list connections from System Settings service using libnm-glib
 * (that wraps direct D-Bus calls).
 * The example uses dbus-glib, libnm-util and libnm-glib libraries.
 *
 * Compile with:
 *   gcc -Wall `pkg-config --libs --cflags glib-2.0 dbus-glib-1 libnm-util libnm-glib` list-connections-libnm-glib.c -o list-connections-libnm-glib
 */

#include <glib.h>
#include <dbus/dbus-glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include <nm-connection.h>
#include <nm-setting-connection.h>
#include <NetworkManager.h>
#include <nm-utils.h>
#include <nm-remote-settings.h>


/* Global variables */
GMainLoop *loop = NULL; /* Main loop variable - needed for waiting for signal */
int result = EXIT_SUCCESS;

static void
signal_handler (int signo)
{
	if (signo == SIGINT || signo == SIGTERM) {
		g_message ("Caught signal %d, shutting down...", signo);
		g_main_loop_quit (loop);
	}
}

static void
setup_signals (void)
{
	struct sigaction action;
	sigset_t mask;

	sigemptyset (&mask);
	action.sa_handler = signal_handler;
	action.sa_mask = mask;
	action.sa_flags = 0;
	sigaction (SIGTERM,  &action, NULL);
	sigaction (SIGINT,  &action, NULL);
}

/* Print details of connection */
static void
show_connection (gpointer data, gpointer user_data)
{
	NMConnection *connection = (NMConnection *) data;
	NMSettingConnection *s_con;
	guint64 timestamp;
	char *timestamp_str;
	char timestamp_real_str[64];
	const char *val1, *val2, *val3, *val4, *val5;

	s_con = nm_connection_get_setting_connection (connection);
	if (s_con) {
		/* Get various info from NMSettingConnection and show it */
		timestamp = nm_setting_connection_get_timestamp (s_con);
		timestamp_str = g_strdup_printf ("%" G_GUINT64_FORMAT, timestamp);
		strftime (timestamp_real_str, sizeof (timestamp_real_str), "%c", localtime ((time_t *) &timestamp));

		val1 = nm_setting_connection_get_id (s_con);
		val2 = nm_setting_connection_get_uuid (s_con);
		val3 = nm_setting_connection_get_connection_type (s_con);
		val4 = nm_connection_get_path (connection);
		val5 = timestamp ? timestamp_real_str : "never";

		printf ("%-25s | %s | %-15s | %-43s | %s\n", val1, val2, val3, val4, val5);

		g_free (timestamp_str);
	}
}

/* This callback is called when connections from the settings service are ready.
 * Now the connections can be listed.
 */
static void
get_connections_cb (NMRemoteSettings *settings, gpointer user_data)
{
	GSList *connections;

	connections = nm_remote_settings_list_connections (settings);

	printf ("Connections:\n===================\n");

	g_slist_foreach (connections, show_connection, NULL);

	g_slist_free (connections);
	g_object_unref (settings);

	/* We are done, exit main loop */
	g_main_loop_quit (loop);
}

/* Get system settings and then connect to connections-read signal */
static gboolean
list_connections (gpointer data)
{
	DBusGConnection *bus = (DBusGConnection *) data;
	NMRemoteSettings *settings;
	gboolean settings_running;

	/* Get system settings */
	if (!(settings = nm_remote_settings_new (bus))) {
		g_message ("Error: Could not get system settings.");
		result = EXIT_FAILURE;
		g_main_loop_quit (loop);
		return FALSE;
	}

	/* Find out whether setting service is running */
	g_object_get (settings, NM_REMOTE_SETTINGS_SERVICE_RUNNING, &settings_running, NULL);

	if (!settings_running) {
		g_message ("Error: Can't obtain connections: settings service is not running.");
		result = EXIT_FAILURE;
		g_main_loop_quit (loop);
		return FALSE;
	}

	/* Connect to signal "connections-read" - emitted when connections are fetched and ready */
	g_signal_connect (settings, NM_REMOTE_SETTINGS_CONNECTIONS_READ,
	                  G_CALLBACK (get_connections_cb), NULL);

	return FALSE;
}

int main (int argc, char *argv[])
{
	DBusGConnection *bus;

#if !GLIB_CHECK_VERSION (2, 35, 0)
	/* Initialize GType system */
	g_type_init ();
#endif

	/* Get system bus */
	bus = dbus_g_bus_get (DBUS_BUS_SYSTEM, NULL);

	/* Run list_connections from main loop, because we need to wait for "connections-read"
	 * signal to have connections ready. The execution will be finished in get_connections_cb()
	 * callback on the signal.
	 */
	g_idle_add (list_connections, bus);

	loop = g_main_loop_new (NULL, FALSE);  /* Create main loop */
	setup_signals ();                      /* Setup UNIX signals */
	g_main_loop_run (loop);                /* Run main loop */

	g_main_loop_unref (loop);
	dbus_g_connection_unref (bus);

	return result;
}
