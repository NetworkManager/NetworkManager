/* nmtestdevices - Tool to create/delete/modify test devices for NetworkManager
 *                 (use when you are on a plane, don't have a wireless card, etc)
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
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>

#include "NetworkManager.h"

static void create_device (DBusConnection *connection, NMDeviceType type)
{
	DBusMessage	*message;
	DBusMessage	*reply;
	DBusError		 error;
	char *string;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (((type == DEVICE_TYPE_802_3_ETHERNET) || (type == DEVICE_TYPE_802_11_WIRELESS)));

	message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH, NM_DBUS_INTERFACE, "createTestDevice");
	if (message == NULL)
	{
		fprintf (stderr, "Couldn't allocate the dbus message\n");
		return;
	}

	dbus_error_init (&error);
	dbus_message_append_args (message, DBUS_TYPE_INT32, type, DBUS_TYPE_INVALID);
	reply = dbus_connection_send_with_reply_and_block (connection, message, -1, &error);
	dbus_message_unref (message);
	if (dbus_error_is_set (&error))
	{
		fprintf (stderr, "%s raised:\n %s\n\n", error.name, error.message);
		dbus_error_free (&error);
		return;
	}

	if (reply == NULL)
	{
		fprintf( stderr, "dbus reply message was NULL\n" );
		return;
	}

	dbus_error_init (&error);
	if (!dbus_message_get_args (reply, &error, DBUS_TYPE_STRING, &string, DBUS_TYPE_INVALID) || !string)
	{
		fprintf (stderr, "NetworkManager returned a NULL test device ID, test device could not be created." );
		dbus_message_unref (reply);
		if (dbus_error_is_set (&error))
			dbus_error_free (&error);
		return;
	}

	fprintf (stderr, "New test device ID: '%s'\n", string );

	dbus_message_unref (reply);
	dbus_free (string);
}


static void destroy_device (DBusConnection *connection, char *dev)
{
	DBusMessage	*message;
	DBusMessage	*reply;
	DBusError		 error;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (dev != NULL);

	message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH, NM_DBUS_INTERFACE, "removeTestDevice");
	if (message == NULL)
	{
		fprintf (stderr, "Couldn't allocate the dbus message\n");
		return;
	}

	dbus_error_init (&error);
	dbus_message_append_args (message, DBUS_TYPE_STRING, dev, DBUS_TYPE_INVALID);
	reply = dbus_connection_send_with_reply_and_block (connection, message, -1, &error);
	if (dbus_error_is_set (&error))
	{
		fprintf (stderr, "%s raised:\n %s\n\n", error.name, error.message);
		dbus_error_free (&error);
		dbus_message_unref (message);
		return;
	}

	if (reply == NULL)
	{
		fprintf( stderr, "dbus reply message was NULL\n" );
		dbus_message_unref (message);
		return;
	}

	dbus_message_unref (message);
	dbus_message_unref (reply);
}


static void set_link_active (DBusConnection *connection, char *dev, gboolean active)
{
	DBusMessage	*message;
	DBusMessage	*reply;
	DBusError		 error;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (dev != NULL);

	message = dbus_message_new_method_call (NM_DBUS_SERVICE, dev, NM_DBUS_INTERFACE_DEVICES, "setLinkActive");
	if (message == NULL)
	{
		fprintf (stderr, "Couldn't allocate the dbus message\n");
		return;
	}

	dbus_message_append_args (message, DBUS_TYPE_BOOLEAN, active, DBUS_TYPE_INVALID);

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (connection, message, -1, &error);
	if (dbus_error_is_set (&error))
	{
		fprintf (stderr, "%s raised:\n %s\n\n", error.name, error.message);
		dbus_error_free (&error);
		dbus_message_unref (message);
		return;
	}

	if (reply == NULL)
	{
		fprintf( stderr, "dbus reply message was NULL\n" );
		dbus_message_unref (message);
		return;
	}

	dbus_message_unref (message);
	dbus_message_unref (reply);
}


static void print_usage (void)
{
	fprintf (stderr, "\n" "usage : nmtestdevices [options] [--help]\n");
	fprintf (stderr,
		"\n"
		"        --create-device <wired | wireless>     Creates a test device, returns the new device ID\n"
		"        --remove-device <ID>                   Remove a test device (cannot remove real devices)\n"
		"        --make-link-active <ID>                Switch a test device's link ON\n"
		"        --make-link-inactive <ID>              Switch a test device's link OFF\n"
		"        --help                                 Show this information and exit\n"
		"\n"
		"This tool allows you to tell NetworkManager to create and manipulate fake 'test' devices.  This\n"
		"is useful in sitation where you may not have a particular device but still want to test\n"
		"NetworkManager out with it (For example, you forgot your wireless card at home and now you're\n"
		"taking a trip and want to hack on NM, and you're on a plane so you couldn't use the wireless\n"
		"card anyway).\n"
		"\n");
}


int main( int argc, char *argv[] )
{
	DBusConnection *connection;
	DBusError		 error;
	char			*dev = NULL;
	gboolean		 create = FALSE;
	gboolean		 destroy = FALSE;
	gboolean		 make_link_active = FALSE;
	gboolean		 make_link_inactive = FALSE;
	NMDeviceType	 dev_type = DEVICE_TYPE_UNKNOWN;

	if (argc < 2) {
		print_usage ();
		exit (0);
	}

	/* Parse options */
	while (1)
	{
		int c;
		int option_index = 0;
		const char *opt;

		static struct option options[] = {
			{"create-device",		1, NULL, 0},
			{"remove-device",		1, NULL, 0},
			{"make-link-active",	1, NULL, 0},
			{"make-link-inactive",	1, NULL, 0},
			{"help",				0, NULL, 0},
			{NULL,				0, NULL, 0}
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
					print_usage ();
					exit (0);
				}
				else if (strcmp (opt, "create-device") == 0)
				{
					create = TRUE;
					if (optarg)
					{
						if (strcmp (optarg, "wired") == 0)
							dev_type = DEVICE_TYPE_802_3_ETHERNET;
						else if (strcmp (optarg, "wireless") == 0)
							dev_type = DEVICE_TYPE_802_11_WIRELESS;
					}
				}
				else if (strcmp (opt, "remove-device") == 0)
				{
					destroy = TRUE;
					if (optarg)
						dev = g_strdup (optarg);
				}
				else if (strcmp (opt, "make-link-active") == 0)
				{
					make_link_active = TRUE;
					if (optarg)
						dev = g_strdup (optarg);
				}
				else if (strcmp (opt, "make-link-inactive") == 0)
				{
					make_link_inactive = TRUE;
					if (optarg)
						dev = g_strdup (optarg);
				}
				break;

			default:
				print_usage ();
				exit (1);
				break;
		}
	}

	g_type_init ();

	dbus_error_init (&error);
	connection = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
	if (connection == NULL)
	{
		fprintf (stderr, "Error connecting to system bus: %s\n", error.message);
		dbus_error_free (&error);
		return 1;
	}

	if (create)
		create_device (connection, dev_type);
	else if (destroy)
		destroy_device (connection, dev);
	else if (make_link_active)
		set_link_active (connection, dev, TRUE);
	else if (make_link_inactive)
		set_link_active (connection, dev, FALSE);

	return 0;
}
