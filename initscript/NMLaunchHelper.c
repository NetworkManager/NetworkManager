/* NMLaunchHelper - Blocks until NetworkManager has a connection, or until
 *				a timeout occurs.  This is needed because NM daemonizes
 *				but startup scripts continue blindly as if the network
 *				were up.
 *
 * Dan Williams <dcbw@redhat.com>
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
 * (C) Copyright 2004 Red Hat, Inc.
 */

#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <stdio.h>


#define	NM_DBUS_SERVICE			"org.freedesktop.NetworkManager"

#define	NM_DBUS_PATH				"/org/freedesktop/NetworkManager"
#define	NM_DBUS_INTERFACE			"org.freedesktop.NetworkManager"


void get_nm_status (DBusConnection *connection)
{
	DBusMessage	*message;
	DBusMessage	*reply;
	DBusMessageIter iter;
	DBusError		 error;
	char *string;

	message = dbus_message_new_method_call ("org.freedesktop.NetworkManager",
						"/org/freedesktop/NetworkManager",
						"org.freedesktop.NetworkManager",
						"status");
	if (message == NULL)
	{
		fprintf (stderr, "Couldn't allocate the dbus message\n");
		return;
	}

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (connection, message, -1, &error);
	if (dbus_error_is_set (&error))
	{
		fprintf (stderr, "%s raised:\n %s\n\n", error.name, error.message);
		dbus_message_unref (message);
		return;
	}

	if (reply == NULL)
	{
		fprintf( stderr, "dbus reply message was NULL\n" );
		dbus_message_unref (message);
		return;
	}

	/* now analyze reply */
	dbus_message_iter_init (reply, &iter);
	string = dbus_message_iter_get_string (&iter);
	if (!string)
	{
		fprintf (stderr, "NetworkManager returned a NULL status" );
		return;
	}

	fprintf (stderr, "NM Status: '%s'\n", string );

	dbus_message_unref (reply);
	dbus_message_unref (message);
}

/*
 * dbus_filter
 *
 * Handles dbus messages from NetworkManager, exit our main loop if a device is active
 */
static DBusHandlerResult dbus_filter (DBusConnection *connection, DBusMessage *message, void *user_data)
{
	GMainLoop	*loop = (GMainLoop *)user_data;

	if (loop && dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceNowActive"))
	{
		g_main_loop_quit (loop);
		return (DBUS_HANDLER_RESULT_HANDLED);
	}

	return (DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
}



/*
 * dbus_init
 *
 * Initialize a connection to NetworkManager
 */
static DBusConnection *dbus_init (GMainLoop *loop)
{
	DBusConnection *connection = NULL;
	DBusError		 error;

	/* connect to NetworkManager service on the system bus */
	dbus_error_init (&error);
	connection = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
	if (connection == NULL)
	{
		fprintf (stderr, "dbus_init(): could not connect to the message bus.  dbus says: '%s'\n", error.message);
		dbus_error_free (&error);
		return (NULL);
	}

	dbus_connection_setup_with_g_main (connection, NULL);

	if (!dbus_connection_add_filter (connection, dbus_filter, (gpointer)loop, NULL))
		return (NULL);

	dbus_bus_add_match (connection,
				"type='signal',"
				"interface='" NM_DBUS_INTERFACE "',"
				"sender='" NM_DBUS_SERVICE "',"
				"path='" NM_DBUS_PATH "'", &error);
	if (dbus_error_is_set (&error))
		return (NULL);

	return (connection);
}


int main( int argc, char *argv[] )
{
	GMainLoop		*loop;
	DBusConnection *connection;
	guint		 timeout;

	g_type_init ();
	if (!g_thread_supported ())
		g_thread_init (NULL);

	loop = g_main_loop_new (NULL, FALSE);

	if (!(connection = dbus_init (loop)))
		return (1);

	/* If NM doesn't get a connection within a reasonable amount of time,
	 * exit to let bootup continue.
	 */
	timeout = g_timeout_add (10000, (GSourceFunc) g_main_loop_quit, loop);

	g_main_loop_run (loop);

	g_source_remove (timeout);

	return (0);
}
