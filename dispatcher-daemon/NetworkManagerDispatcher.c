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
#include <sys/types.h>
#include <dirent.h>


enum NMDAction
{
	NMD_DEVICE_DONT_KNOW,
	NMD_DEVICE_NOW_INACTIVE,
	NMD_DEVICE_NOW_ACTIVE
};
typedef enum NMDAction	NMDAction;


/*
 * nmd_execute_scripts
 *
 * Call scripts in /etc/NetworkManager.d when devices go down or up
 *
 */
void nmd_execute_scripts (NMDAction action, char *iface_name)
{
	DIR			*dir = opendir ("/etc/NetworkManager.d");
	struct dirent	*ent;

	if (!dir)
	{
		fprintf (stderr, "nmd_execute_scripts(): opendir() could not open /etc/NetworkManager.d.  errno = %d\n", errno);
		return;
	}

	do
	{
		errno = 0;
		if ((ent = readdir (dir)) != NULL)
		{
			struct stat	s;
			char			path[500];

			snprintf (path, 499, "/etc/NetworkManager.d/%s", ent->d_name);
			if ((ent->d_name[0] != '.') && (stat (path, &s) == 0))
			{
				/* FIXME
				 * We should check the permissions and only execute files that
				 * are 0700 or 0500.
				 */
				if (S_ISREG (s.st_mode) && !S_ISLNK (s.st_mode) && (s.st_uid == 0))
				{
					char cmd[500];

					snprintf (cmd, 499, "%s %s %s", path, iface_name,
						(action == NMD_DEVICE_NOW_INACTIVE ? "down" :
							(action == NMD_DEVICE_NOW_ACTIVE ? "up" : "error")));
					system (cmd);
				}
			}
		}
	} while (ent);

	closedir (dir);
}


/*
 * nmd_get_device_name
 *
 * Queries NetworkManager for the name of a device, specified by a device path
 */
char * nmd_get_device_name (DBusConnection *connection, char *path)
{
	DBusMessage	*message;
	DBusMessage	*reply;
	DBusMessageIter iter;
	DBusError		 error;
	char			*ret_string = NULL;
	char			*dbus_string;

	message = dbus_message_new_method_call ("org.freedesktop.NetworkManager",
						path,
						"org.freedesktop.NetworkManager",
						"getName");
	if (message == NULL)
	{
		fprintf (stderr, "Couldn't allocate the dbus message\n");
		return (NULL);
	}

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (connection, message, -1, &error);
	if (dbus_error_is_set (&error))
	{
		fprintf (stderr, "%s raised:\n %s\n\n", error.name, error.message);
		dbus_message_unref (message);
		return (NULL);
	}

	if (reply == NULL)
	{
		fprintf( stderr, "dbus reply message was NULL\n" );
		dbus_message_unref (message);
		return (NULL);
	}

	/* now analyze reply */
	dbus_message_iter_init (reply, &iter);
	dbus_string = dbus_message_iter_get_string (&iter);
	ret_string = (dbus_string == NULL ? NULL : strdup (dbus_string));
	if (!ret_string)
		fprintf (stderr, "NetworkManager returned a NULL device name" );

	dbus_free (dbus_string);
	dbus_message_unref (reply);
	dbus_message_unref (message);

	return (ret_string);
}


/*
 * nmd_dbus_filter
 *
 * Handles dbus messages from NetworkManager, dispatches device active/not-active messages
 */
static DBusHandlerResult nmd_dbus_filter (DBusConnection *connection, DBusMessage *message, void *user_data)
{
	const char	*object_path;
	DBusError		 error;
	char			*dev_object_path = NULL;
	gboolean		 handled = FALSE;
	NMDAction		 action = NMD_DEVICE_DONT_KNOW;

	dbus_error_init (&error);
	object_path = dbus_message_get_path (message);

	if (dbus_message_is_signal (message, "org.freedesktop.NetworkManager", "DeviceNoLongerActive"))
		action = NMD_DEVICE_NOW_INACTIVE;
	else if (dbus_message_is_signal (message, "org.freedesktop.NetworkManager", "DeviceNowActive"))
		action = NMD_DEVICE_NOW_ACTIVE;

	if (action != NMD_DEVICE_DONT_KNOW)
	{
		if (dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &dev_object_path, DBUS_TYPE_INVALID))
		{
			char		*dev_iface_name = nmd_get_device_name (connection, dev_object_path);

			fprintf (stderr, "Device %s (%s) is now %s.\n", dev_object_path, dev_iface_name,
						(action == NMD_DEVICE_NOW_INACTIVE ? "down" :
							(action == NMD_DEVICE_NOW_ACTIVE ? "up" : "error")));

			nmd_execute_scripts (action, dev_iface_name);

			free (dev_iface_name);
			dbus_free (dev_object_path);

			handled = TRUE;
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
	DBusConnection	*connection = NULL;

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
