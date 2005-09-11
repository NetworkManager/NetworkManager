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
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "NetworkManager.h"


static char * get_network_string_property (DBusConnection *connection, const char *network, const char *method, NMNetworkType type)
{
	DBusMessage	*message;
	DBusMessage	*reply;
	DBusError		 error;
	char			*string = NULL;
	char			*ret_string = NULL;
	gint32		type_as_int;

	message = dbus_message_new_method_call (NMI_DBUS_SERVICE, NMI_DBUS_PATH, NMI_DBUS_INTERFACE, method);
	if (message == NULL)
	{
		fprintf (stderr, "Couldn't allocate the dbus message\n");
		return NULL;
	}

	type_as_int = (gint32) type;
	dbus_message_append_args (message, DBUS_TYPE_STRING, &network, DBUS_TYPE_INT32, &type_as_int, DBUS_TYPE_INVALID);
	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (connection, message, -1, &error);
	dbus_message_unref (message);
	if (dbus_error_is_set (&error))
	{
		fprintf (stderr, "%s raised:\n %s\n\n", error.name, error.message);
		dbus_error_free (&error);
		return NULL;
	}

	if (reply == NULL)
	{
		fprintf( stderr, "dbus reply message was NULL\n" );
		return NULL;
	}

	dbus_error_init (&error);
	if (dbus_message_get_args (reply, &error, DBUS_TYPE_STRING, &string, DBUS_TYPE_INVALID) && string)
	{
		ret_string = g_strdup (string);
	}
	dbus_message_unref (reply);
	
	if (!string)
		fprintf (stderr, "NetworkManagerInfo returned a NULL string for method '%s'", method );

	if (dbus_error_is_set (&error))
		dbus_error_free (&error);

	return (ret_string);
}

static gboolean get_network_trusted (DBusConnection *connection, const char *network, NMNetworkType type)
{
	DBusMessage	*message;
	DBusMessage	*reply;
	DBusError		 error;
	gboolean		 trusted = FALSE;
	gint32		type_as_int;

	g_return_val_if_fail (connection != NULL, -1);
	g_return_val_if_fail (network != NULL, -1);

	message = dbus_message_new_method_call (NMI_DBUS_SERVICE, NMI_DBUS_PATH, NMI_DBUS_INTERFACE, "getNetworkTrusted");
	if (message == NULL)
	{
		fprintf (stderr, "Couldn't allocate the dbus message\n");
		return (-1);
	}

	dbus_error_init (&error);
	type_as_int = (gint32) type;
	dbus_message_append_args (message, DBUS_TYPE_STRING, &network, DBUS_TYPE_INT32, &type_as_int, DBUS_TYPE_INVALID);
	reply = dbus_connection_send_with_reply_and_block (connection, message, -1, &error);
	dbus_message_unref (message);
	if (dbus_error_is_set (&error))
	{
		fprintf (stderr, "%s raised:\n %s\n\n", error.name, error.message);
		dbus_error_free (&error);
		dbus_message_unref (reply);
		return (-1);
	}

	if (reply == NULL)
	{
		fprintf( stderr, "dbus reply message was NULL\n" );
		return (-1);
	}

	/* now analyze reply */
	dbus_error_init (&error);
	if (!dbus_message_get_args (reply, &error, DBUS_TYPE_BOOLEAN, &trusted, DBUS_TYPE_INVALID))
		trusted = FALSE;
	if (dbus_error_is_set (&error))
		dbus_error_free (&error);

	dbus_message_unref (reply);

	return (trusted);
}


static void get_networks_of_type (DBusConnection *connection, NMNetworkType type)
{
	DBusMessage 	*message;
	DBusMessage 	*reply;
	DBusError		 error;
	gint32		type_as_int;
	char **networks;
	int	num_networks;
	int i;

	message = dbus_message_new_method_call (NMI_DBUS_SERVICE, NMI_DBUS_PATH, NMI_DBUS_INTERFACE, "getNetworks");
	if (message == NULL)
	{
		fprintf (stderr, "Couldn't allocate the dbus message\n");
		return;
	}

	dbus_error_init (&error);
	type_as_int = (gint32) type;
	dbus_message_append_args (message, DBUS_TYPE_INT32, &type_as_int, DBUS_TYPE_INVALID);
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

	/* now analyze reply */
	dbus_error_init (&error);
	if (!dbus_message_get_args (reply, &error, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
				&networks, &num_networks, DBUS_TYPE_INVALID))
	{
		fprintf (stderr, "NetworkManagerInfo returned no network list" );
		dbus_message_unref (reply);
		return;
	}

	dbus_message_unref (reply);

	if (!networks)
		fprintf( stderr, "No networks found\n" );

	fprintf( stderr, "Networks of type %d:\n", type );
	for (i = 0; i < num_networks; i++)
	{
		if (strlen (networks[i]) == 0)
		{
			fprintf( stderr, "   No networks found\n" );
			break;
		}
		else
		{
			char *essid = get_network_string_property (connection, networks[i], "getNetworkEssid", type);
			char *key = get_network_string_property (connection, networks[i], "getNetworkKey", type);

			fprintf(stderr, "   %s\t%s\t%s\n", essid, key, get_network_trusted (connection, networks[i], type) ? "trusted" : "untrusted");
		}
	}

	g_strfreev (networks);
}

static void get_user_key_for_network (DBusConnection *connection)
{
	DBusMessage *	message;
	const char *	dev_path = NM_DBUS_PATH_DEVICES"/eth1";
	const char *	net_path = NM_DBUS_PATH_DEVICES"/Networks/wireless-ap";
	const char *	essid = "wireless-ap";
	const int		attempts = 0;
	const gboolean	new_key = FALSE;

	g_return_if_fail (connection != NULL);

	message = dbus_message_new_method_call (NMI_DBUS_SERVICE, NMI_DBUS_PATH, NMI_DBUS_INTERFACE, "getKeyForNetwork");
	if (message == NULL)
	{
		fprintf (stderr, "get_user_key_for_network(): Couldn't allocate the dbus message\n");
		return;
	}

	dbus_message_append_args (message, DBUS_TYPE_STRING, &dev_path,
								DBUS_TYPE_STRING, &net_path,
								DBUS_TYPE_STRING, &essid,
								DBUS_TYPE_INT32, &attempts,
								DBUS_TYPE_BOOLEAN, &new_key,
								DBUS_TYPE_INVALID);

	if (!dbus_connection_send (connection, message, NULL))
		fprintf (stderr, "get_user_key_for_network(): could not send dbus message\n");

	dbus_message_unref (message);
}


static void set_user_key_for_network (DBusConnection *connection, DBusMessage *message, GMainLoop *loop)
{
	DBusError		error;
	char *		passphrase;
	int			key_type = -1;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (message != NULL);

	dbus_error_init (&error);
	if (dbus_message_get_args (message, &error,
							DBUS_TYPE_STRING, &passphrase,
							DBUS_TYPE_STRING, &key_type,
							DBUS_TYPE_INVALID))
	{
		fprintf( stderr, "Passphrase was '%s'\nKey type was %d\n", passphrase, key_type);


		g_main_loop_quit (loop);
	}
}


static DBusHandlerResult nm_message_handler (DBusConnection *connection, DBusMessage *message, void *user_data)
{
	const char		*method;
	const char		*path;
	gboolean			 handled = TRUE;

	g_return_val_if_fail (connection != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (message != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	method = dbus_message_get_member (message);
	path = dbus_message_get_path (message);

	fprintf (stderr, "nm_dbus_nm_message_handler() got method %s for path %s\n", method, path);

	if (strcmp ("setKeyForNetwork", method) == 0)
		set_user_key_for_network (connection, message, user_data);
	else
		handled = FALSE;

	return (handled ? DBUS_HANDLER_RESULT_HANDLED : DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
}


int main( int argc, char *argv[] )
{
	DBusConnection			*connection;
	DBusError				 error;
	DBusObjectPathVTable	 vtable = { NULL, &nm_message_handler, NULL, NULL, NULL, NULL };
	dbus_bool_t			 success = FALSE;
	GMainLoop				*loop = NULL;

	loop = g_main_loop_new (NULL, FALSE);

	g_type_init ();
	if (!g_thread_supported ())
		g_thread_init (NULL);

	dbus_error_init (&error);
	connection = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
	if (connection == NULL)
	{
		fprintf (stderr, "Error connecting to system bus: %s\n", error.message);
		dbus_error_free (&error);
		exit (1);
	}

	dbus_connection_setup_with_g_main (connection, NULL);
	dbus_error_init (&error);
	dbus_bus_request_name (connection, NM_DBUS_SERVICE, 0, &error);
	if (dbus_error_is_set (&error))
	{
		fprintf (stderr, "Could not acquire its service.  dbus_bus_request_name() says: '%s'\n", error.message);
		exit (1);
	}

	success = dbus_connection_register_object_path (connection, NM_DBUS_PATH, &vtable, loop);
	if (!success)
	{
		fprintf (stderr, "Could not register a handler for NetworkManager.  Not enough memory?\n");
		exit (1);
	}

	get_networks_of_type (connection, NETWORK_TYPE_ALLOWED);
	get_networks_of_type (connection, NETWORK_TYPE_DEVICE);
	get_user_key_for_network (connection);

	g_main_loop_run (loop);

	return 0;
}
