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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2005 Red Hat, Inc.
 */

#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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


/*
 * call_nm_method
 *
 * Do a method call on NetworkManager.
 *
 * Returns:	RETURN_SUCCESS on success
 *			RETURN_FAILURE on failure
 *			RETURN_NO_NM if NetworkManager service no longer exists
 */
static int call_nm_method (DBusConnection *con, const char *method, int opt, gboolean is_array, int arg_type, void **arg, int *item_count)
{
	DBusMessage	*message;
	DBusMessage	*reply;
	DBusError		 error;
	dbus_bool_t	 ret = TRUE;
	DBusMessageIter iter;

	g_return_val_if_fail (con != NULL, RETURN_FAILURE);
	g_return_val_if_fail (method != NULL, RETURN_FAILURE);
	g_return_val_if_fail (arg != NULL, RETURN_FAILURE);

	if (is_array)
	{
		g_return_val_if_fail (item_count != NULL, RETURN_FAILURE);
		*item_count = 0;
	}

	if (!(message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH_DHCP, NM_DBUS_INTERFACE_DHCP, method)))
	{
		fprintf (stderr, "call_nm_method(): Couldn't allocate the dbus message\n");
		return (RETURN_FAILURE);
	}
	dbus_message_append_args (message, DBUS_TYPE_UINT32, &opt, DBUS_TYPE_INVALID);

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

	if (is_array)
		ret = dbus_message_get_args (reply, NULL, DBUS_TYPE_ARRAY, arg_type, arg, item_count, DBUS_TYPE_INVALID);
	else
		ret = dbus_message_get_args (reply, NULL, arg_type, arg, DBUS_TYPE_INVALID);

/*
  We simply don't unref the message, so that the values returned stay
  valid in the caller of this function.
	dbus_message_unref (reply);
*/
	if (!ret)
	{
		fprintf (stderr, "call_nm_method(): error while getting args.\n");
		return (RETURN_FAILURE);
	}

	return (RETURN_SUCCESS);
}

void print_array (DBusConnection *connection, int opt)
{
	int num_items;
	unsigned int	*uint32 = NULL;
	int			*int32 = NULL;
	gboolean		*bool = NULL;
	unsigned char	*byte = NULL;
	char			**string = NULL;
	void			*item = NULL;
	char			*method = NULL;
	int			 ret;
	const char	*name = NULL;
	int			 opt_type = -1;
	unsigned int foo;
	char buf[INET_ADDRSTRLEN+1];

	memset (&buf, '\0', sizeof (buf));

	ret = call_nm_method (connection, "getName", opt, FALSE, DBUS_TYPE_STRING, (void *)(&name), NULL);
	if (ret != RETURN_SUCCESS)
		return;

	ret = call_nm_method (connection, "getElementType", opt, FALSE, DBUS_TYPE_UINT32, (void *)(&opt_type), NULL);
	if (ret != RETURN_SUCCESS)
		return;

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

	ret = call_nm_method (connection, method, opt, TRUE, opt_type, item, &num_items);
	if ((ret == RETURN_SUCCESS) && (num_items > 0))
	{
		int i;
		fprintf (stderr, "%d ('%s'): (%d %s of type %s)  ", opt, name, num_items, num_items > 1 ? "elements" : "element", dbus_type_to_string (opt_type));
		for (i = 0; i < num_items; i++)
		{
			guint32	in;
			gboolean	last = (i == num_items - 1) ? TRUE : FALSE;

			switch (opt_type)
			{
				case DBUS_TYPE_BYTE:
					fprintf (stderr, "%d%s", byte[i], last ? "" : ", ");
					break;
				case DBUS_TYPE_BOOLEAN:
					fprintf (stderr, "%d%s", bool[i], last ? "" : ", ");
					break;
				case DBUS_TYPE_UINT32:
					in = uint32[i];
					if (!inet_ntop (AF_INET, &in, buf, INET_ADDRSTRLEN))
						nm_warning ("%s: error converting IP4 address 0x%X",
						            __func__, ntohl (in));
					else
						fprintf (stderr, "%u (%s)%s", uint32[i], buf, last ? "" : ", ");
					break;
				case DBUS_TYPE_STRING:
					fprintf (stderr, "'%s'%s", string[i], last ? "" : ", ");
					break;

				default:
					g_assert_not_reached ();
					break;
			}
		}
		fprintf (stderr, "\n");
	}
	else
		fprintf (stderr, "%d ('%s'): could not get option value\n", opt, name);
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
		print_array (connection, i);
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
