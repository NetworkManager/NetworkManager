/* nm-dhcp-opt-test - test app for NetworkManager's DHCP Options interface
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
 * (C) Copyright 2005 Red Hat, Inc.
 */

#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "NetworkManager.h"

/* Return codes for functions that use dbus */
enum
{
	RETURN_SUCCESS = 1,
	RETURN_FAILURE = 0,
	RETURN_NO_NM = -1
};


#define	DBUS_NO_SERVICE_ERROR			"org.freedesktop.DBus.Error.ServiceDoesNotExist"
#define	NM_DHCP_OPT_NOT_FOUND_ERROR		"org.freedesktop.NetworkManager.OptionNotFound"

static char *dbus_type_to_string (int type)
{
	switch (type)
	{
		case DBUS_TYPE_UINT32:
			return "uint32";

		case DBUS_TYPE_BOOLEAN:
			return "boolean";

		case DBUS_TYPE_BYTE:
			return "byte";

		case DBUS_TYPE_STRING:
			return "string";
	}
	g_assert_not_reached ();
	return NULL;
}


gboolean get_one_arg (DBusMessage *message, int arg_type, int arg_type2, void **arg, int *item_count)
{
	gboolean	success = FALSE;

	g_return_val_if_fail (message != NULL, FALSE);
	g_return_val_if_fail (arg != NULL, FALSE);

	if (arg_type == DBUS_TYPE_ARRAY)
	{
		if (!item_count)
			return FALSE;
		success = dbus_message_get_args (message, NULL, DBUS_TYPE_ARRAY, arg_type2,
									arg, item_count, DBUS_TYPE_INVALID);
	}
	else
	{
		switch (arg_type)
		{
			case DBUS_TYPE_STRING:
				success = dbus_message_get_args (message, NULL, DBUS_TYPE_STRING, arg, DBUS_TYPE_INVALID);
				break;
			case DBUS_TYPE_BYTE:
			case DBUS_TYPE_INT32:
			case DBUS_TYPE_UINT32:
			case DBUS_TYPE_BOOLEAN:
				success = dbus_message_get_args (message, NULL, arg_type, arg, DBUS_TYPE_INVALID);
				break;
			default:
				fprintf (stderr, "get_one_arg (): Unknown argument type!\n");
				break;
		}
	}
	return success;
}


/*
 * call_nm_method
 *
 * Do a method call on NetworkManager.
 *
 * Returns:	RETURN_SUCCESS on success
 *			RETURN_FAILURE on failure
 *			RETURN_NO_NM if NetworkManager service no longer exists
 */
static int call_nm_method (DBusConnection *con, const char *method, int opt, int arg_type, int arg_type2, void **arg, int *item_count)
{
	DBusMessage	*message;
	DBusMessage	*reply;
	DBusError		 error;
	dbus_bool_t	 ret = TRUE;
	DBusMessageIter iter;

	g_return_val_if_fail (con != NULL, RETURN_FAILURE);
	g_return_val_if_fail (method != NULL, RETURN_FAILURE);
	g_return_val_if_fail (arg != NULL, RETURN_FAILURE);

	if ((arg_type == DBUS_TYPE_STRING) || (arg_type2 == DBUS_TYPE_ARRAY))
		g_return_val_if_fail (*arg == NULL, RETURN_FAILURE);

	if (arg_type == DBUS_TYPE_ARRAY)
	{
		g_return_val_if_fail (item_count != NULL, RETURN_FAILURE);
		*item_count = 0;
	}

	if (!(message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH_DHCP, NM_DBUS_INTERFACE_DHCP, method)))
	{
		fprintf (stderr, "call_nm_method(): Couldn't allocate the dbus message\n");
		return (RETURN_FAILURE);
	}
	dbus_message_append_args (message, DBUS_TYPE_UINT32, opt, DBUS_TYPE_INVALID);

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (con, message, -1, &error);
	dbus_message_unref (message);
	if (dbus_error_is_set (&error))
	{
		int	ret = RETURN_FAILURE;

		if (!strcmp (error.name, DBUS_NO_SERVICE_ERROR))
			ret = RETURN_NO_NM;

		if (ret != RETURN_SUCCESS && (strcmp (error.name, NM_DHCP_OPT_NOT_FOUND_ERROR) != 0))
			fprintf (stderr, "call_nm_method(): %s raised:\n %s\n\n", error.name, error.message);

		dbus_error_free (&error);
		return (ret);
	}

	if (reply == NULL)
	{
		fprintf (stderr, "call_nm_method(): dbus reply message was NULL\n" );
		return (RETURN_FAILURE);
	}

	ret = get_one_arg (reply, arg_type, arg_type2, arg, item_count);
	dbus_message_unref (reply);
	if (!ret)
	{
		fprintf (stderr, "call_nm_method(): error while getting args: name='%s' message='%s'\n", error.name, error.message);
		if (dbus_error_is_set (&error))
			dbus_error_free (&error);
		return (RETURN_FAILURE);
	}

	return (RETURN_SUCCESS);
}


int get_opt_type (DBusConnection *connection, int opt, gboolean record)
{
	int	ret;
	int	type = -1;

	ret = call_nm_method (connection, record ? "getRecordType" : "getType", opt, DBUS_TYPE_UINT32, DBUS_TYPE_INVALID, (void *)(&type), NULL);
	if (ret == RETURN_SUCCESS)
		return (type);

	return (-1);
}


void print_array (DBusConnection *connection, int opt, int opt_type)
{
	int num_items;
	unsigned int	*uint32 = NULL;
	int			*int32 = NULL;
	gboolean		*bool = NULL;
	unsigned char	*byte = NULL;
	void			*item = NULL;
	char			*method = NULL;
	int			 ret;
	const char	*name = NULL;

	switch (opt_type)
	{
		case DBUS_TYPE_UINT32:
			item = &uint32;
			method = "getIntegerv";
			break;

		case DBUS_TYPE_BOOLEAN:
			item = &bool;
			method = "getBooleanv";
			break;

		case DBUS_TYPE_BYTE:
			item = &byte;
			method = "getBytev";
			break;

		default:
			fprintf (stderr, "%d: Type %c\n", opt, opt_type);
			g_assert_not_reached ();
			break;
	}

	ret = call_nm_method (connection, "getName", opt, DBUS_TYPE_STRING, DBUS_TYPE_INVALID, (void *)(&name), NULL);
	if (ret != RETURN_SUCCESS)
		name = NULL;

	ret = call_nm_method (connection, method, opt, DBUS_TYPE_ARRAY, opt_type, item, &num_items);
	if ((ret == RETURN_SUCCESS) && (num_items > 0))
	{
		int i;
		fprintf (stderr, "%d ('%s'): (%d records of type %s)  ", opt, name, num_items, dbus_type_to_string (opt_type));
		for (i = 0; i < num_items; i++)
		{
			switch (opt_type)
			{
				case DBUS_TYPE_BYTE:
					fprintf (stderr, "%d, ", byte[i]);
					break;
				case DBUS_TYPE_BOOLEAN:
					fprintf (stderr, "%d, ", bool[i]);
					break;
				case DBUS_TYPE_UINT32:
					fprintf (stderr, "%u, ", uint32[i]);
					break;

				default:
					g_assert_not_reached ();
					break;
			}
		}
		fprintf (stderr, "\n");
	}
}

void print_one_item (DBusConnection *connection, int opt, int opt_type)
{
	unsigned int	 uint32;
	int			 int32;
	gboolean		 bool;
	unsigned char	 byte;
	char			*string = NULL;
	void			*item = NULL;
	char			*method = NULL;
	int			 ret;
	const char	*name = NULL;

	switch (opt_type)
	{
		case DBUS_TYPE_UINT32:
			item = &uint32;
			method = "getInteger";
			break;

		case DBUS_TYPE_BOOLEAN:
			item = &bool;
			method = "getBoolean";
			break;

		case DBUS_TYPE_BYTE:
			item = &byte;
			method = "getByte";
			break;

		case DBUS_TYPE_STRING:
			item = &string;
			method = "getString";
			break;

		default:
			fprintf (stderr, "%d: Type %c\n", opt, opt_type);
			g_assert_not_reached ();
			break;
	}

	ret = call_nm_method (connection, "getName", opt, DBUS_TYPE_STRING, DBUS_TYPE_INVALID, (void *)(&name), NULL);
	if (ret != RETURN_SUCCESS)
		name = NULL;

	ret = call_nm_method (connection, method, opt, opt_type, DBUS_TYPE_INVALID, item, NULL);
	if (ret == RETURN_SUCCESS)
	{
		fprintf (stderr, "%d ('%s'): (%s)  ", opt, name, dbus_type_to_string (opt_type));
		switch (opt_type)
		{
			case DBUS_TYPE_BYTE:
				fprintf (stderr, "%d\n", byte);
				break;
			case DBUS_TYPE_BOOLEAN:
				fprintf (stderr, "%d\n", bool);
				break;
			case DBUS_TYPE_UINT32:
				fprintf (stderr, "%u\n", uint32);
				break;
			case DBUS_TYPE_STRING:
				fprintf (stderr, "'%s'\n", string);
				break;

			default:
				g_assert_not_reached ();
				break;
		}
	}
}


void print_each_dhcp_option (DBusConnection *connection)
{
	DBusMessage	*message;
	DBusMessage	*reply;
	DBusMessageIter iter;
	DBusError		 error;
	int			 i;
	int			 opt_type;
	int			 ret;

	g_return_if_fail (connection != NULL);

	/* Loop through all available DHCP options and print each one. */
	for (i = 1; i < 62; i++)
	{
		int opt_type = get_opt_type (connection, i, FALSE);

		if (opt_type == DBUS_TYPE_ARRAY)
		{
			int opt_type2;

			/* get the array item type */
			opt_type2 = get_opt_type (connection, i, TRUE);
			print_array (connection, i, opt_type2);
		}
		else if (opt_type != -1)
			print_one_item (connection, i, opt_type);
	}
}


int main (int argc, char **argv)
{
	DBusConnection *connection;
	DBusError		 error;

	g_type_init ();

	dbus_error_init (&error);
	connection = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
	if (connection == NULL)
	{
		fprintf (stderr, "Error connecting to system bus: %s\n", error.message);
		dbus_error_free (&error);
		return 1;
	}

	print_each_dhcp_option (connection);

	exit (0);
}
