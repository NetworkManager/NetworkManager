/* NetworkManager Wireless Applet -- Display wireless access points and allow user control
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

#include <stdio.h>
#include <dbus/dbus.h>
#include "NMWirelessAppletDbus.h"
#include "NMWirelessApplet.h"

#define	NM_DBUS_SERVICE			"org.freedesktop.NetworkManager"

#define	NM_DBUS_PATH				"/org/freedesktop/NetworkManager"
#define	NM_DBUS_INTERFACE			"org.freedesktop.NetworkManager"
#define	NM_DBUS_PATH_DEVICES		"/org/freedesktop/NetworkManager/Devices"
#define	NM_DBUS_INTERFACE_DEVICES	"org.freedesktop.NetworkManager.Devices"

#define	NMI_DBUS_SERVICE			"org.freedesktop.NetworkManagerInfo"
#define	NMI_DBUS_PATH				"/org/freedesktop/NetworkManagerInfo"
#define	NMI_DBUS_INTERFACE			"org.freedesktop.NetworkManagerInfo"


/*
 * nmwa_dbus_get_string
 *
 * NOTE: caller MUST free the returned string
 *
 */
char * nmwa_dbus_get_string (DBusConnection *connection, const char *path, const char *method)
{
	DBusMessage	*message;
	DBusMessage	*reply;
	DBusError		 error;
	char			*string = NULL;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);
	g_return_val_if_fail (method != NULL, NULL);

	if (!(message = dbus_message_new_method_call (NM_DBUS_SERVICE, path, NM_DBUS_INTERFACE, method)))
	{
		show_warning_dialog ("Couldn't allocate the dbus message\n");
		return (NULL);
	}

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (connection, message, -1, &error);
	if (dbus_error_is_set (&error))
	{
		show_warning_dialog ("aaa  %s raised:\n %s\n\n", error.name, error.message);
		dbus_message_unref (message);
		return (NULL);
	}

	if (reply == NULL)
	{
		show_warning_dialog ("dbus reply message was NULL\n" );
		dbus_message_unref (message);
		return (NULL);
	}

	dbus_error_init (&error);
	if (!dbus_message_get_args (reply, &error, DBUS_TYPE_STRING, &string, DBUS_TYPE_INVALID))
	{
		show_warning_dialog ("bbb  %s raised:\n %s\n\n", error.name, error.message);
		string = NULL;
	}

	dbus_message_unref (reply);
	dbus_message_unref (message);

	return (string);
}


/*
 * nmwa_dbus_get_int
 *
 */
gint32 nmwa_dbus_get_int (DBusConnection *connection, const char *path, const char *method)
{
	DBusMessage	*message;
	DBusMessage	*reply;
	DBusError		 error;
	gint32		 num;

	g_return_val_if_fail (connection != NULL, 0);
	g_return_val_if_fail (path != NULL, 0);
	g_return_val_if_fail (method != NULL, 0);

	if (!(message = dbus_message_new_method_call (NM_DBUS_SERVICE, path, NM_DBUS_INTERFACE, method)))
	{
		fprintf (stderr, "Couldn't allocate the dbus message\n");
		return (0);
	}

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (connection, message, -1, &error);
	if (dbus_error_is_set (&error))
	{
		fprintf (stderr, "%s raised:\n %s\n\n", error.name, error.message);
		dbus_message_unref (message);
		return (0);
	}

	if (reply == NULL)
	{
		fprintf( stderr, "dbus reply message was NULL\n" );
		dbus_message_unref (message);
		return (0);
	}

	dbus_error_init (&error);
	if (!dbus_message_get_args (reply, &error, DBUS_TYPE_INT32, &num, DBUS_TYPE_INVALID))
		num = 0;

	dbus_message_unref (reply);
	dbus_message_unref (message);

	return (num);
}


/*
 * nmwa_dbus_get_double
 *
 */
double nmwa_dbus_get_double (DBusConnection *connection, const char *path, const char *method)
{
	DBusMessage	*message;
	DBusMessage	*reply;
	DBusError		 error;
	double		 num;

	g_return_val_if_fail (connection != NULL, 0);
	g_return_val_if_fail (path != NULL, 0);
	g_return_val_if_fail (method != NULL, 0);

	if (!(message = dbus_message_new_method_call (NM_DBUS_SERVICE, path, NM_DBUS_INTERFACE, method)))
	{
		fprintf (stderr, "Couldn't allocate the dbus message\n");
		return (0);
	}

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (connection, message, -1, &error);
	if (dbus_error_is_set (&error))
	{
		fprintf (stderr, "%s raised:\n %s\n\n", error.name, error.message);
		dbus_message_unref (message);
		return (0);
	}

	if (reply == NULL)
	{
		fprintf( stderr, "dbus reply message was NULL\n" );
		dbus_message_unref (message);
		return (0);
	}

	dbus_error_init (&error);
	if (!dbus_message_get_args (reply, &error, DBUS_TYPE_DOUBLE, &num, DBUS_TYPE_INVALID))
		num = 0;

	dbus_message_unref (reply);
	dbus_message_unref (message);

	return (num);
}


/*
 * nmwa_dbus_get_string_array
 *
 * NOTE: caller MUST free the returned string array
 *
 */
char **nmwa_dbus_get_string_array (DBusConnection *connection, const char *path, const char *method, int *num_items)
{
	DBusMessage 	 *message;
	DBusMessage 	 *reply;
	DBusMessageIter  iter;
	DBusError		  error;
	char			**array;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);
	g_return_val_if_fail (method != NULL, NULL);
	g_return_val_if_fail (num_items != NULL, NULL);

	if (!(message = dbus_message_new_method_call (NM_DBUS_SERVICE, path, NM_DBUS_INTERFACE, method)))
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
	if (!dbus_message_iter_get_string_array (&iter, &array, num_items))
		array = NULL;

	dbus_message_unref (reply);
	dbus_message_unref (message);

	return (array);
}


/*
 * nmwa_dbus_get_active_wireless_device
 *
 * Returns the object_path of the currently active wireless device, if any.
 *
 */
char * nmwa_dbus_get_active_wireless_device (DBusConnection *connection)
{
	char	*active_device;

	if (!connection)
		return (NULL);

	if ((active_device = active_device = nmwa_dbus_get_string (connection, NM_DBUS_PATH, "getActiveDevice")))
	{
		int		 type;

		type = nmwa_dbus_get_int (connection, active_device, "getType");
		if (type != 2)	/* wireless */
		{
show_warning_dialog ("nmwa_dbus_get_active_wireless_device(): device was not wireless\n");
			dbus_free (active_device);
			active_device = NULL;
		}
else
show_warning_dialog ("nmwa_dbus_get_active_wireless_device(): device GOOD\n");
	}
else
show_warning_dialog ("nmwa_dbus_get_active_wireless_device(): could not get string from dbus\n");

	return (active_device);
}


/*
 * nmwa_dbus_add_networks_to_menu
 *
 * Query NetworkManager for networks and add any to the networks menu
 *
 */
void nmwa_dbus_add_networks_to_menu (DBusConnection *connection, gpointer user_data)
{
	char		 *active_device;
	char		 *active_network;
	char		**networks;
	int		  num_items = 0;

	if (!connection)
	{
		nmwa_add_menu_item ("No wireless networks found...", FALSE, user_data);
		return;
	}

	if (!(active_device = nmwa_dbus_get_active_wireless_device (connection)))
	{
		nmwa_add_menu_item ("No wireless networks found...", FALSE, user_data);
		return;
	}

	if (!(active_network = nmwa_dbus_get_string (connection, active_device, "getActiveNetwork")))
	{
		nmwa_add_menu_item ("No wireless networks found...", FALSE, user_data);
		return;
	}

	/* Get each of the networks in turn and add them to the menu */
	if ((networks = nmwa_dbus_get_string_array (connection, active_device, "getNetworks", &num_items)))
	{
		if (strlen (networks[0]) == 0)
			nmwa_add_menu_item ("No wireless networks found...", FALSE, user_data);
		else
		{
			int i;
			for (i = 0; i < num_items; i++)
			{
				char *name = nmwa_dbus_get_string (connection, networks[i], "getName");
				nmwa_add_menu_item (name, (strcmp (networks[i], active_network) == 0), user_data);
				dbus_free (name);
			}
		}
		dbus_free_string_array (networks);
	}

	dbus_free (active_device);
}


/*
 * nmwa_dbus_nm_is_running
 *
 * Ask dbus whether or not NetworkManager is running
 *
 */
gboolean nmwa_dbus_nm_is_running (DBusConnection *connection)
{
	DBusError		error;
	gboolean		exists;

	g_return_val_if_fail (connection != NULL, FALSE);

	dbus_error_init (&error);
	exists = dbus_bus_service_exists (connection, NM_DBUS_SERVICE, &error);
	return (exists);
}


/*
 * nmwa_dbus_filter
 *
 */
static DBusHandlerResult nmwa_dbus_filter (DBusConnection *connection, DBusMessage *message, void *user_data)
{
	NMWirelessApplet	*applet = (NMWirelessApplet *)user_data;
	gboolean			 handled = TRUE;

	g_return_val_if_fail (applet != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (connection != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (message != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	if (dbus_message_is_signal (message, DBUS_INTERFACE_ORG_FREEDESKTOP_DBUS, "ServiceCreated"))
	{
		char 	*service;
		DBusError	 error;

		dbus_error_init (&error);
		if (    dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &service, DBUS_TYPE_INVALID)
			&& (strcmp (service, NM_DBUS_SERVICE) == 0))
			applet->nm_active = TRUE;
	}
	else if (dbus_message_is_signal (message, DBUS_INTERFACE_ORG_FREEDESKTOP_DBUS, "ServiceDeleted"))
	{
		char 	*service;
		DBusError	 error;

		dbus_error_init (&error);
		if (    dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &service, DBUS_TYPE_INVALID)
			&& (strcmp (service, NM_DBUS_SERVICE) == 0))
			applet->nm_active = FALSE;
	}
	else
		handled = FALSE;

	return (handled ? DBUS_HANDLER_RESULT_HANDLED : DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
}


/*
 * nmwa_dbus_init
 *
 * Initialize a connection to NetworkManager if we can get one
 *
 */
DBusConnection * nmwa_dbus_init (gpointer user_data)
{
	DBusConnection	*connection;
	DBusError		 error;

	dbus_error_init (&error);
	connection = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
	if (!connection)
		return (NULL);

	if (!dbus_connection_add_filter (connection, nmwa_dbus_filter, user_data, NULL))
		return (NULL);

	dbus_connection_set_exit_on_disconnect (connection, FALSE);
	dbus_connection_setup_with_g_main (connection, NULL);

	dbus_bus_add_match(connection,
				"type='signal',"
				"interface='" DBUS_INTERFACE_ORG_FREEDESKTOP_DBUS "',"
				"sender='" DBUS_SERVICE_ORG_FREEDESKTOP_DBUS "'",
				&error);
	if (dbus_error_is_set (&error))
	{
		show_warning_dialog ("Could not add match, error: '%s'", error.message);
	}

	return (connection);
}

