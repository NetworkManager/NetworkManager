/* NetworkManagerDispatcher -- Dispatches messages from NetworkManager
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
#include <dbus/dbus-glib.h>
#include <getopt.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>


/* Globals */
DBusConnection		*connection = NULL;


static DBusHandlerResult nmd_dbus_filter (DBusConnection *connection, DBusMessage *message, void *user_data)
{
	const char	*object_path;
	DBusError		 error;
	char			*dev_object_path = NULL;
	gboolean		 handled = FALSE;

	dbus_error_init (&error);
	object_path = dbus_message_get_path (message);

	fprintf (stderr, "*** in filter_func, object_path=%s\n", object_path);

	if (dbus_message_is_signal (message, "org.freedesktop.NetworkManager", "DeviceNoLongerActive"))
	{
		if (dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &dev_object_path, DBUS_TYPE_INVALID))
		{
fprintf (stderr, "Device %s no longer active\n", dev_object_path);
			handled = TRUE;
			dbus_free (dev_object_path);
		}
	}
	else if (dbus_message_is_signal (message, "org.freedesktop.NetworkManager", "DeviceNowActive"))
	{
		if (dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &dev_object_path, DBUS_TYPE_INVALID))
		{
fprintf (stderr, "Device %s now active\n", dev_object_path);
			handled = TRUE;
			dbus_free (dev_object_path);
		}
	}

	return (handled ? DBUS_HANDLER_RESULT_HANDLED : DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
}


/*
 * nmd_dbus_init
 *
 * Initialize a connection to NetworkManager
 */
static DBusConnection *nmd_dbus_init (void)
{
	DBusConnection *connection = NULL;
	DBusError		 error;

	/* connect to hald service on the system bus */
	dbus_error_init (&error);
	connection = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
	if (connection == NULL)
	{
		fprintf (stderr, "nmd_dbus_init(): could not connect to the message bus.  dbus says: '%s'\n", error.message);
		dbus_error_free (&error);
		return (NULL);
	}

	dbus_connection_setup_with_g_main (connection, NULL);

	if (!dbus_connection_add_filter (connection, nmd_dbus_filter, NULL, NULL))
		return (NULL);

	dbus_bus_add_match (connection,
				"type='signal',"
				"interface='org.freedesktop.NetworkManager',"
				"sender='org.freedesktop.NetworkManager',"
				"path='/org/freedesktop/NetworkManager'", &error);
	if (dbus_error_is_set (&error))
		return (NULL);

	return (connection);
}

/*
 * nmd_print_usage
 *
 * Prints program usage.
 *
 */
static void nmd_print_usage (void)
{
	fprintf (stderr, "\n" "usage : NetworkManagerDispatcher [--daemon=yes|no] [--help]\n");
	fprintf (stderr,
		"\n"
		"        --daemon=yes|no    Become a daemon\n"
		"        --help             Show this information and exit\n"
		"\n"
		"NetworkManagerDispatcher listens for device messages from NetworkManager\n"
		"and runs scripts in /etc/networkmanager.\n"
		"\n");
}


/*
 * main
 *
 */
int main( int argc, char *argv[] )
{
	gboolean		 become_daemon = TRUE;
	GMainLoop		*loop  = NULL;

	/* Parse options */
	while (1)
	{
		int c;
		int option_index = 0;
		const char *opt;

		static struct option options[] = {
			{"daemon",	1, NULL, 0},
			{"help",		0, NULL, 0},
			{NULL,		0, NULL, 0}
		};

		c = getopt_long (argc, argv, "", options, &option_index);
		if (c == -1)
			break;

		switch (c)
		{
			case 0:
				opt = options[option_index].name;
				if (strcmp (opt, "help") == 0)
				{
					nmd_print_usage ();
					return 0;
				}
				else if (strcmp (opt, "daemon") == 0)
				{
					if (strcmp ("yes", optarg) == 0)
						become_daemon = TRUE;
					else if (strcmp ("no", optarg) == 0)
						become_daemon = FALSE;
					else
					{
						nmd_print_usage ();
						return 1;
					}
				}
				break;

			default:
				nmd_print_usage ();
				return 1;
				break;
		}
	}

	if (become_daemon)
	{
		int child_pid;
		int dev_null_fd;

		if (chdir ("/") < 0)
		{
			fprintf( stderr, "NetworkManagerDispatcher could not chdir to /.  errno=%d", errno);
			return 1;
		}

		child_pid = fork ();
		switch (child_pid)
		{
			case -1:
				fprintf( stderr, "NetworkManagerDispatcher could not daemonize.  errno = %d\n", errno );
				break;

			case 0:
				/* Child */
				break;

			default:
				exit (0);
				break;
		}
	}

	g_type_init ();
	if (!g_thread_supported ())
		g_thread_init (NULL);

	/* Create our dbus service */
	connection = nmd_dbus_init ();
	if (connection)
	{
		/* Run the main loop, all events processed by callbacks from libhal. */
		loop = g_main_loop_new (NULL, FALSE);
		g_main_loop_run (loop);
	}

	return 0;
}
