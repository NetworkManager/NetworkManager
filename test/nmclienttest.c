/* nmclienttest - test app for NetworkManager
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
#include <string.h>

#include "NetworkManager.h"


/* Return codes for functions that use dbus */
enum
{
	RETURN_SUCCESS = 1,
	RETURN_FAILURE = 0,
	RETURN_NO_NM = -1
};

/* dbus doesn't define a DBUS_TYPE_STRING_ARRAY so we fake one here for consistency */
#define	DBUS_TYPE_STRING_ARRAY		((int) '$')

#define	DBUS_NO_SERVICE_ERROR			"org.freedesktop.DBus.Error.ServiceDoesNotExist"

/*
 * nmwa_dbus_call_nm_method
 *
 * Do a method call on NetworkManager.
 *
 * Returns:	RETURN_SUCCESS on success
 *			RETURN_FAILURE on failure
 *			RETURN_NO_NM if NetworkManager service no longer exists
 */
static int nmwa_dbus_call_nm_method (DBusConnection *con, const char *path, const char *method, int arg_type, void **arg, int *item_count)
{
	DBusMessage	*message;
	DBusMessage	*reply;
	DBusError		 error;
	char			*dbus_string = NULL;
	int			 dbus_int = 0;
	gboolean		 dbus_bool = FALSE;
	char			**dbus_string_array = NULL;
	int			 num_items = 0;
	dbus_bool_t	 ret = TRUE;
	DBusMessageIter iter;

	g_return_val_if_fail (con != NULL, RETURN_FAILURE);
	g_return_val_if_fail (path != NULL, RETURN_FAILURE);
	g_return_val_if_fail (method != NULL, RETURN_FAILURE);
	g_return_val_if_fail (((arg_type == DBUS_TYPE_STRING) || (arg_type == DBUS_TYPE_INT32) || (arg_type == DBUS_TYPE_BOOLEAN) || (arg_type == DBUS_TYPE_STRING_ARRAY)), RETURN_FAILURE);
	g_return_val_if_fail (arg != NULL, RETURN_FAILURE);

	if ((arg_type == DBUS_TYPE_STRING) || (arg_type == DBUS_TYPE_STRING_ARRAY))
		g_return_val_if_fail (*arg == NULL, RETURN_FAILURE);

	if (arg_type == DBUS_TYPE_STRING_ARRAY)
	{
		g_return_val_if_fail (item_count != NULL, RETURN_FAILURE);
		*item_count = 0;
		*((char **)arg) = NULL;
	}

	if (!(message = dbus_message_new_method_call (NM_DBUS_SERVICE, path, NM_DBUS_INTERFACE, method)))
	{
		fprintf (stderr, "nmwa_dbus_call_nm_method(): Couldn't allocate the dbus message\n");
		return (RETURN_FAILURE);
	}

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (con, message, -1, &error);
	dbus_message_unref (message);
	if (dbus_error_is_set (&error))
	{
		int	ret = RETURN_FAILURE;

		if (!strcmp (error.name, DBUS_NO_SERVICE_ERROR))
			ret = RETURN_NO_NM;
		else if (!strcmp (error.name, NM_DBUS_NO_ACTIVE_NET_ERROR))
			ret = RETURN_SUCCESS;
		else if (!strcmp (error.name, NM_DBUS_NO_ACTIVE_DEVICE_ERROR))
			ret = RETURN_SUCCESS;
		else if (!strcmp (error.name, NM_DBUS_NO_NETWORKS_ERROR))
			ret = RETURN_SUCCESS;

		if (ret != RETURN_SUCCESS)
			fprintf (stderr, "nmwa_dbus_call_nm_method(): %s raised:\n %s\n\n", error.name, error.message);

		dbus_error_free (&error);
		return (ret);
	}

	if (reply == NULL)
	{
		fprintf (stderr, "nmwa_dbus_call_nm_method(): dbus reply message was NULL\n" );
		return (RETURN_FAILURE);
	}

	dbus_error_init (&error);
	switch (arg_type)
	{
		case DBUS_TYPE_STRING:
			ret = dbus_message_get_args (reply, &error, DBUS_TYPE_STRING, &dbus_string, DBUS_TYPE_INVALID);
			break;
		case DBUS_TYPE_STRING_ARRAY:
			dbus_message_iter_init (reply, &iter);
			ret = dbus_message_iter_get_string_array (&iter, &dbus_string_array, &num_items);
			break;
		case DBUS_TYPE_INT32:
			ret = dbus_message_get_args (reply, &error, DBUS_TYPE_INT32, &dbus_int, DBUS_TYPE_INVALID);
			break;
		case DBUS_TYPE_BOOLEAN:
			ret = dbus_message_get_args (reply, &error, DBUS_TYPE_BOOLEAN, &dbus_bool, DBUS_TYPE_INVALID);
			break;
		default:
			fprintf (stderr, "nmwa_dbus_call_nm_method(): Unknown argument type!\n");
			ret = FALSE;
			break;
	}

	if (!ret)
	{
		fprintf (stderr, "nmwa_dbus_call_nm_method(): error while getting args: name='%s' message='%s'\n", error.name, error.message);
		if (dbus_error_is_set (&error))
			dbus_error_free (&error);
		dbus_message_unref (reply);
		return (RETURN_FAILURE);
	}
	dbus_message_unref (reply);

	switch (arg_type)
	{
		case DBUS_TYPE_STRING:
			*((char **)(arg)) = dbus_string;
			break;
		case DBUS_TYPE_STRING_ARRAY:
			*((char ***)(arg)) = dbus_string_array;
			*item_count = num_items;
			break;
		case DBUS_TYPE_INT32:
			*((int *)(arg)) = dbus_int;
			break;
		case DBUS_TYPE_BOOLEAN:
			*((gboolean *)(arg)) = dbus_bool;
			break;
		default:
			g_assert_not_reached ();
			break;
	}

	return (RETURN_SUCCESS);
}



char * get_active_device (DBusConnection *connection)
{
	int	 ret;
	char *active_device = NULL;

	ret = nmwa_dbus_call_nm_method (connection, NM_DBUS_PATH, "getActiveDevice", DBUS_TYPE_STRING, (void *)(&active_device), NULL);
	if (ret == RETURN_SUCCESS)
		return (active_device);

	return (NULL);
}


char * get_object_name (DBusConnection *connection, char *path)
{
	int	 ret;
	char *name = NULL;

	ret = nmwa_dbus_call_nm_method (connection, path, "getName", DBUS_TYPE_STRING, (void *)(&name), NULL);
	if (ret == RETURN_SUCCESS)
		return (name);

	return (NULL);
}


int get_object_signal_strength (DBusConnection *connection, char *path)
{
	int	 ret;
	int strength = -1;

	ret = nmwa_dbus_call_nm_method (connection, path, "getStrength", DBUS_TYPE_INT32, (void *)(&strength), NULL);
	if (ret == RETURN_SUCCESS)
		return (strength);

	return (-1);
}


char * get_nm_status (DBusConnection *connection)
{
	int	 ret;
	char *status = NULL;

	ret = nmwa_dbus_call_nm_method (connection, NM_DBUS_PATH, "status", DBUS_TYPE_STRING, (void *)(&status), NULL);
	if (ret == RETURN_SUCCESS)
		return (status);

	return (NULL);
}


char * get_device_active_network (DBusConnection *connection, char *path)
{
	int	 ret;
	char *net = NULL;

	ret = nmwa_dbus_call_nm_method (connection, path, "getActiveNetwork", DBUS_TYPE_STRING, (void *)(&net), NULL);
	if (ret == RETURN_SUCCESS)
		return (net);

	return (NULL);
}


int get_device_type (DBusConnection *connection, char *path)
{
	int	ret;
	int	type = -1;

	ret = nmwa_dbus_call_nm_method (connection, path, "getType", DBUS_TYPE_INT32, (void *)(&type), NULL);
	if (ret == RETURN_SUCCESS)
		return (type);

	return (-1);
}


void print_device_networks (DBusConnection *connection, const char *path)
{
	int	  ret;
	char **networks = NULL;
	int	  num_networks = 0;
	int	  i;

	ret = nmwa_dbus_call_nm_method (connection, path, "getNetworks", DBUS_TYPE_STRING_ARRAY, (void **)(&networks), &num_networks);
	if (ret != RETURN_SUCCESS)
		return;

	fprintf( stderr, "       Networks:\n" );
	for (i = 0; i < num_networks; i++)
	{
		char *name = get_object_name (connection, networks[i]);

		fprintf( stderr, "           %s (%s)  Strength: %d%%\n", networks[i], name,
				get_object_signal_strength (connection, networks[i]) );
		dbus_free (name);
	}

	dbus_free_string_array (networks);
}


void print_devices (DBusConnection *connection)
{
	int	  ret;
	char **devices = NULL;
	int	  num_devices = 0;
	int	  i;

	ret = nmwa_dbus_call_nm_method (connection, NM_DBUS_PATH, "getDevices", DBUS_TYPE_STRING_ARRAY, (void **)(&devices), &num_devices);
	if (ret != RETURN_SUCCESS)
		return;

	fprintf( stderr, "Devices:\n" );
	for (i = 0; i < num_devices; i++)
	{
		int	 type = get_device_type (connection, devices[i]);

		fprintf (stderr, "   %s\n", devices[i]);
		if (type == DEVICE_TYPE_WIRELESS_ETHERNET)
		{
			char *active_network = get_device_active_network (connection, devices[i]);

			fprintf (stderr, "       Device type: wireless\n");
			fprintf (stderr, "       Strength: %d%%\n", get_object_signal_strength (connection, devices[i]));
			fprintf (stderr, "       Active Network: '%s'\n", active_network);
			dbus_free (active_network);
			
			print_device_networks (connection, devices[i]);
			fprintf (stderr, "\n");
		}
		else if (type == DEVICE_TYPE_WIRED_ETHERNET)
			fprintf (stderr, "       Device type: wired\n");
		else
			fprintf (stderr, "       Device type: unknown\n");
		fprintf (stderr, "\n");
	}
	dbus_free_string_array (devices);
}


void set_device_network (DBusConnection *connection, const char *path, const char *network)
{
	DBusMessage 	*message;
	DBusMessage 	*reply;
	DBusMessageIter iter;
	DBusError		 error;

	message = dbus_message_new_method_call ("org.freedesktop.NetworkManager",
						"/org/freedesktop/NetworkManager",
						"org.freedesktop.NetworkManager",
						"setActiveDevice");
	if (message == NULL)
	{
		fprintf (stderr, "Couldn't allocate the dbus message\n");
		return;
	}

	dbus_message_append_args (message, DBUS_TYPE_STRING, path,
							DBUS_TYPE_STRING, network, DBUS_TYPE_INVALID);

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (connection, message, -1, &error);
	if (dbus_error_is_set (&error))
	{
		fprintf (stderr, "%s raised:\n %s\n\n", error.name, error.message);
		dbus_message_unref (message);
		dbus_error_free (&error);
		return;
	}
	else
		fprintf (stderr, "Success!!\n");
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

	char *path;
	char *status;

	status = get_nm_status (connection);
	if (!status)
	{
		fprintf (stderr, "NetworkManager appears not to be running (could not get its status).  Will exit.\n");
		return (1);
	}
	fprintf (stderr, "NM Status: '%s'\n", status);
	dbus_free (status);

	path = get_active_device (connection);
	fprintf (stderr, "Active device: '%s'\n", path ? path : "(none)");
	if (path)
	{
		char *name = get_object_name (connection, path);
		fprintf (stderr, "Active device name: '%s'\n", name ? name : "(none)");
		dbus_free (name);
	}

	print_devices (connection);

	if (path && (argc == 2) && (get_device_type (connection, path) == DEVICE_TYPE_WIRELESS_ETHERNET))
	{
		fprintf (stderr, "Attempting to force AP '%s' for device '%s'\n", argv[1], path);
		set_device_network (connection, path, argv[1]);
	}

	dbus_free (path);

	return 0;
}
