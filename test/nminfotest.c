/* nminfotest -- test app for NetworkManagerInfo
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


char * get_network_string_property (DBusConnection *connection, char *network, char *method)
{
	DBusMessage	*message;
	DBusMessage	*reply;
	DBusMessageIter iter;
	DBusError		 error;

	message = dbus_message_new_method_call ("org.freedesktop.NetworkManagerInfo",
						"/org/freedesktop/NetworkManagerInfo",
						"org.freedesktop.NetworkManagerInfo",
						method);
	if (message == NULL)
	{
		fprintf (stderr, "Couldn't allocate the dbus message\n");
		return;
	}

	dbus_message_iter_init (message, &iter);
	dbus_message_iter_append_string (&iter, network);

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
	char *string, *ret_string;
	string = dbus_message_iter_get_string (&iter);
	if (!string)
	{
		fprintf (stderr, "NetworkManagerInfo returned a NULL active device object path" );
		return;
	}
	ret_string = g_strdup (string);
	dbus_free (string);

	dbus_message_unref (reply);
	dbus_message_unref (message);

	return (ret_string);
}

int get_network_prio (DBusConnection *connection, char *network)
{
	DBusMessage	*message;
	DBusMessage	*reply;
	DBusMessageIter iter;
	DBusError		 error;

	g_return_val_if_fail (connection != NULL, -1);
	g_return_val_if_fail (network != NULL, -1);

	message = dbus_message_new_method_call ("org.freedesktop.NetworkManagerInfo",
						"/org/freedesktop/NetworkManagerInfo",
						"org.freedesktop.NetworkManagerInfo",
						"getAllowedNetworkPriority");
	if (message == NULL)
	{
		fprintf (stderr, "Couldn't allocate the dbus message\n");
		return (-1);
	}

	dbus_message_iter_init (message, &iter);
	dbus_message_iter_append_string (&iter, network);

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (connection, message, -1, &error);
	if (dbus_error_is_set (&error))
	{
		fprintf (stderr, "%s raised:\n %s\n\n", error.name, error.message);
		dbus_message_unref (message);
		return (-1);
	}

	if (reply == NULL)
	{
		fprintf( stderr, "dbus reply message was NULL\n" );
		dbus_message_unref (message);
		return (-1);
	}

	/* now analyze reply */
	dbus_message_iter_init (reply, &iter);
	int	type;
	type = dbus_message_iter_get_uint32 (&iter);

	dbus_message_unref (reply);
	dbus_message_unref (message);

	return (type);
}


void get_allowed_networks (DBusConnection *connection)
{
	DBusMessage 	*message;
	DBusMessage 	*reply;
	DBusMessageIter iter;
	DBusError		 error;

	message = dbus_message_new_method_call ("org.freedesktop.NetworkManagerInfo",
						"/org/freedesktop/NetworkManagerInfo",
						"org.freedesktop.NetworkManagerInfo",
						"getAllowedNetworks");
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
	char **networks;
	int	num_networks;

	if (!dbus_message_iter_get_string_array (&iter, &networks, &num_networks))
	{
		fprintf (stderr, "NetworkManagerInfo returned no network list" );
		return;
	}

	dbus_message_unref (reply);
	dbus_message_unref (message);

	int i;
	fprintf( stderr, "Networks:\n" );
	for (i = 0; i < num_networks; i++)
	{
		char *essid = get_network_string_property (connection, networks[i], "getAllowedNetworkEssid");
		char *key = get_network_string_property (connection, networks[i], "getAllowedNetworkKey");

		fprintf( stderr, "   %d:\t%s\t%s\n",
				get_network_prio (connection, networks[i]), essid, key);
	}

	dbus_free_string_array (networks);
}


int main( int argc, char *argv[] )
{
	DBusConnection *connection;
	DBusError		error;

	g_type_init ();

	dbus_error_init (&error);
	connection = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
	if (connection == NULL)
	{
		fprintf (stderr, "Error connecting to system bus: %s\n", error.message);
		dbus_error_free (&error);
		return 1;
	}

	get_allowed_networks (connection);

	return 0;
}
