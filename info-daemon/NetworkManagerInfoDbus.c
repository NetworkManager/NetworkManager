/* NetworkManagerInfo -- Manage allowed access points and provide a UI
 *                         for WEP key entry
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
#include <stdio.h>
#include <string.h>

#include "NetworkManagerInfo.h"
#include "NetworkManagerInfoDbus.h"

#define	NMI_DBUS_NMI_OBJECT_PATH_PREFIX		"/org/freedesktop/NetworkManagerInfo"
#define	NMI_DBUS_NMI_NAMESPACE				"org.freedesktop.NetworkManagerInfo"

/*
 * nmi_dbus_create_error_message
 *
 * Make a DBus error message
 *
 */
static DBusMessage *nmi_dbus_create_error_message (DBusMessage *message, const char *exception_namespace,
										const char *exception, const char *format, ...)
{
	DBusMessage	*reply_message;
	va_list		 args;
	char			 error_text[512];


	va_start (args, format);
	vsnprintf (error_text, 512, format, args);
	va_end (args);

	char *exception_text = g_strdup_printf ("%s.%s", exception_namespace, exception);
	reply_message = dbus_message_new_error (message, exception_text, error_text);
	g_free (exception_text);

	return (reply_message);
}


/*
 * nmi_dbus_dbus_return_user_key
 *
 * Alert NetworkManager of the new user key
 *
 */
void nmi_dbus_return_user_key (DBusConnection *connection, const char *device,
						const char *network, const char *passphrase)
{
	DBusMessage	*message;
	DBusMessageIter iter;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (device != NULL);
	g_return_if_fail (network != NULL);
	g_return_if_fail (passphrase != NULL);

	message = dbus_message_new_method_call ("org.freedesktop.NetworkManager",
									"/org/freedesktop/NetworkManager",
									"org.freedesktop.NetworkManager",
									"setKeyForNetwork");
	if (message == NULL)
	{
		fprintf (stderr, "nmi_dbus_return_user_key(): Couldn't allocate the dbus message\n");
		return;
	}

	/* Add network name and passphrase */
	dbus_message_iter_init (message, &iter);
	dbus_message_iter_append_string (&iter, device);
	dbus_message_iter_append_string (&iter, network);
	dbus_message_iter_append_string (&iter, passphrase);

	if (!dbus_connection_send (connection, message, NULL))
	{
		fprintf (stderr, "nmi_dbus_return_user_key(): dbus could not send the message\n");
		return;
	}
}


/*
 * nmi_dbus_nmi_message_handler
 *
 * Responds to requests for our services
 *
 */
static DBusHandlerResult nmi_dbus_nmi_message_handler (DBusConnection *connection, DBusMessage *message, void *user_data)
{
	const char		*method;
	const char		*path;
	NMIAppInfo		*info = (NMIAppInfo *)user_data;
	DBusMessage		*reply_message = NULL;

	g_return_val_if_fail (info != NULL, DBUS_HANDLER_RESULT_HANDLED);

	method = dbus_message_get_member (message);
	path = dbus_message_get_path (message);

	/* fprintf (stderr, "nmi_dbus_nmi_message_handler() got method %s for path %s\n", method, path); */

	if (strcmp ("getKeyForNetwork", method) == 0)
	{
		GtkWidget	*dialog = glade_xml_get_widget (info->xml, "passphrase_dialog");
		if (!GTK_WIDGET_VISIBLE (dialog))
		{
			DBusMessageIter	 iter;
			char				*dbus_string;
			char				*device = NULL;
			char				*network = NULL;

			dbus_message_iter_init (message, &iter);
			/* Grab device */
			dbus_string = dbus_message_iter_get_string (&iter);
			device = (dbus_string == NULL ? NULL : strdup (dbus_string));		
			dbus_free (dbus_string);

			/* Grab network to get key for */
			if (dbus_message_iter_next (&iter))
			{
				dbus_string = dbus_message_iter_get_string (&iter);
				network = (dbus_string == NULL ? NULL : strdup (dbus_string));		
				dbus_free (dbus_string);
			}

			if (device && network)
				nmi_show_user_key_dialog (device, network, info);

			g_free (device);
			g_free (network);
		}
	}
	else if (strcmp ("cancelGetKeyForNetwork", method) == 0)
	{
		GtkWidget	*dialog = glade_xml_get_widget (info->xml, "passphrase_dialog");
		if (GTK_WIDGET_VISIBLE (dialog))
			nmi_cancel_user_key_dialog (info);
	}
	else
	{
		reply_message = nmi_dbus_create_error_message (message, NMI_DBUS_NMI_NAMESPACE, "UnknownMethod",
							"NetworkManagerInfo knows nothing about the method %s for object %s", method, path);

		dbus_connection_send (connection, reply_message, NULL);
	}

	return (DBUS_HANDLER_RESULT_HANDLED);
}


/*
 * nmi_dbus_nmi_unregister_handler
 *
 * Nothing happens here.
 *
 */
void nmi_dbus_nmi_unregister_handler (DBusConnection *connection, void *user_data)
{
	/* do nothing */
}


/*
 * nmi_dbus_service_init
 *
 * Connect to the system messagebus and register ourselves as a service.
 *
 */
int nmi_dbus_service_init (DBusConnection *dbus_connection, NMIAppInfo *info)
{
	DBusError		 		 dbus_error;
	DBusObjectPathVTable	 nmi_vtable = { &nmi_dbus_nmi_unregister_handler, &nmi_dbus_nmi_message_handler, NULL, NULL, NULL, NULL };
	const char			*nmi_path[] = { "org", "freedesktop", "NetworkManagerInfo", NULL };

	dbus_error_init (&dbus_error);
	dbus_bus_acquire_service (dbus_connection, NMI_DBUS_NMI_NAMESPACE, 0, &dbus_error);
	if (dbus_error_is_set (&dbus_error))
	{
		fprintf (stderr, "nmi_dbus_service_init() could not acquire its service.  dbus_bus_acquire_service() says: '%s'\n", dbus_error.message);
		return (-1);
	}

	if (!dbus_connection_register_object_path (dbus_connection, nmi_path, &nmi_vtable, info))
	{
		fprintf (stderr, "nmi_dbus_service_init() could not register a handler for NetworkManagerInfo.  Not enough memory?\n");
		return (-1);
	}

	return (0);
}
