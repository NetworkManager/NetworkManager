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
#include <dbus/dbus.h>
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
 * nmi_dbus_get_key_for_network
 *
 * Throw up the user key dialog
 *
 */
static void nmi_dbus_get_key_for_network (NMIAppInfo *info, DBusMessage *message)
{
	DBusError			 error;
	char				*device = NULL;
	char				*network = NULL;

	dbus_error_init (&error);
	if (dbus_message_get_args (message, &error,
							DBUS_TYPE_STRING, &device,
							DBUS_TYPE_STRING, &network,
							DBUS_TYPE_INVALID))
	{
		nmi_show_user_key_dialog (device, network, info);

		dbus_free (device);
		dbus_free (network);
	}
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
	if (dbus_message_append_args (message, DBUS_TYPE_STRING, device,
								DBUS_TYPE_STRING, network,
								DBUS_TYPE_STRING, passphrase,
								DBUS_TYPE_INVALID))
	{
		if (!dbus_connection_send (connection, message, NULL))
			fprintf (stderr, "nmi_dbus_return_user_key(): dbus could not send the message\n");
	}

	dbus_message_unref (message);
}


/*
 * nmi_dbus_signal_update_allowed_network
 *
 * Signal NetworkManager that it needs to update info associated with a particular
 * allowed network.
 *
 */
void nmi_dbus_signal_update_allowed_network (DBusConnection *connection, const char *network)
{
	DBusMessage		*message;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (network != NULL);

	message = dbus_message_new_signal ("/org/freedesktop/NetworkManagerInfo", "org.freedesktop.NetworkManagerInfo",
									"AllowedNetworkUpdate");
	if (!message)
	{
		fprintf (stderr, "nmi_dbus_signal_update_allowed_network(): Not enough memory for new dbus message!\n");
		return;
	}

	dbus_message_append_args (message, DBUS_TYPE_STRING, network, DBUS_TYPE_INVALID);
	if (!dbus_connection_send (connection, message, NULL))
		fprintf (stderr, "nmi_dbus_signal_update_allowed_network(): Could not raise the AllowedNetworkUpdate signal!\n");

	dbus_message_unref (message);
}


/*
 * nmi_dbus_get_allowed_networks
 *
 * Grab a list of allowed access points from GConf and return it in the form
 * of a string array in a dbus message.
 *
 */
static DBusMessage *nmi_dbus_get_allowed_networks (NMIAppInfo *info, DBusMessage *message)
{
	GSList			*dir_list = NULL;
	GSList			*element = NULL;
	DBusMessage		*reply_message = NULL;
	DBusMessageIter	 iter;
	DBusMessageIter	 iter_array;

	g_return_val_if_fail (info != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	/* List all allowed access points that gconf knows about */
	element = dir_list = gconf_client_all_dirs (info->gconf_client, NMI_GCONF_ALLOWED_NETWORKS_PATH, NULL);

	reply_message = dbus_message_new_method_return (message);
	dbus_message_iter_init (reply_message, &iter);
	dbus_message_iter_append_array (&iter, &iter_array, DBUS_TYPE_STRING);

	if (!dir_list)
		dbus_message_iter_append_string (&iter_array, "");
	else
	{
		gboolean	value_added = FALSE;

		/* Append the essid of every allowed access point we know of 
		 * to a string array in the dbus message.
		 */
		while (element)
		{
			gchar		 key[100];
			GConfValue	*value;

			g_snprintf (&key[0], 99, "%s/essid", (char *)(element->data));
			value = gconf_client_get (info->gconf_client, key, NULL);
			if (value && gconf_value_get_string (value))
			{
				dbus_message_iter_append_string (&iter_array, gconf_value_get_string (value));
				value_added = TRUE;
				gconf_value_free (value);
			}

			g_free (element->data);
			element = element->next;
		}
		g_slist_free (dir_list);

		/* Make sure that there's at least one array element if all the gconf calls failed */
		if (!value_added)
			dbus_message_iter_append_string (&iter_array, "");
	}

	return (reply_message);
}
 

/*
 * nmi_dbus_get_allowed_network_prio
 *
 * If the specified allowed network exists, get its priority from gconf
 * and pass it back as a dbus message.
 *
 */
static DBusMessage *nmi_dbus_get_allowed_network_prio (NMIAppInfo *info, DBusMessage *message)
{
	DBusMessage		*reply_message = NULL;
	gchar			*key = NULL;
	char				*network = NULL;
	GConfValue		*value;
	DBusError			 error;

	g_return_val_if_fail (info != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	dbus_error_init (&error);
	if (!dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &network, DBUS_TYPE_INVALID))
	{
		reply_message = nmi_dbus_create_error_message (message, NMI_DBUS_NMI_NAMESPACE, "InvalidNetwork",
							"NetworkManagerInfo::getAllowedNetworkPriority called with invalid network.");
		return (reply_message);
	}

	/* Grab priority key for our access point from GConf */
	key = g_strdup_printf ("%s/%s/priority", NMI_GCONF_ALLOWED_NETWORKS_PATH, network);
	value = gconf_client_get (info->gconf_client, key, NULL);
	g_free (key);

	if (value)
	{
		reply_message = dbus_message_new_method_return (message);
		dbus_message_append_args (reply_message, DBUS_TYPE_UINT32, gconf_value_get_int (value), DBUS_TYPE_INVALID);
		gconf_value_free (value);
	}
	else
	{
		reply_message = nmi_dbus_create_error_message (message, NMI_DBUS_NMI_NAMESPACE, "BadNetworkData",
							"NetworkManagerInfo::getAllowedNetworkPriority could not access data for network '%s'", network);
	}

	dbus_free (network);
	return (reply_message);
}


/*
 * nmi_dbus_get_allowed_network_essid
 *
 * If the specified allowed network exists, get its essid from gconf
 * and pass it back as a dbus message.
 *
 */
static DBusMessage *nmi_dbus_get_allowed_network_essid (NMIAppInfo *info, DBusMessage *message)
{
	DBusMessage		*reply_message = NULL;
	gchar			*key = NULL;
	char				*network = NULL;
	GConfValue		*value;
	DBusError			 error;

	g_return_val_if_fail (info != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	dbus_error_init (&error);
	if (!dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &network, DBUS_TYPE_INVALID))
	{
		reply_message = nmi_dbus_create_error_message (message, NMI_DBUS_NMI_NAMESPACE, "InvalidNetwork",
							"NetworkManagerInfo::getAllowedNetworkEssid called with invalid network.");
		return (reply_message);
	}

	/* Grab essid key for our access point from GConf */
	key = g_strdup_printf ("%s/%s/essid", NMI_GCONF_ALLOWED_NETWORKS_PATH, network);
	value = gconf_client_get (info->gconf_client, key, NULL);
	g_free (key);

	if (value)
	{
		reply_message = dbus_message_new_method_return (message);
		dbus_message_append_args (reply_message, DBUS_TYPE_STRING, gconf_value_get_string (value), DBUS_TYPE_INVALID);
		gconf_value_free (value);
	}
	else
	{
		reply_message = nmi_dbus_create_error_message (message, NMI_DBUS_NMI_NAMESPACE, "BadNetworkData",
							"NetworkManagerInfo::getAllowedNetworkEssid could not access data for network '%s'", network);
	}

	dbus_free (network);
	return (reply_message);
}


/*
 * nmi_dbus_get_allowed_network_key
 *
 * If the specified allowed network exists, get its key from gconf
 * and pass it back as a dbus message.
 *
 */
static DBusMessage *nmi_dbus_get_allowed_network_key (NMIAppInfo *info, DBusMessage *message)
{
	DBusMessage		*reply_message = NULL;
	gchar			*key = NULL;
	char				*network = NULL;
	GConfValue		*value;
	DBusError			 error;

	g_return_val_if_fail (info != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	dbus_error_init (&error);
	if (!dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &network, DBUS_TYPE_INVALID))
	{
		reply_message = nmi_dbus_create_error_message (message, NMI_DBUS_NMI_NAMESPACE, "InvalidNetwork",
							"NetworkManagerInfo::getAllowedNetworkKey called with invalid network.");
		return (reply_message);
	}

	/* Grab user-key key for our access point from GConf */
	key = g_strdup_printf ("%s/%s/key", NMI_GCONF_ALLOWED_NETWORKS_PATH, network);
	value = gconf_client_get (info->gconf_client, key, NULL);
	g_free (key);

	/* We don't error out if no key was found in gconf, we return blank key */
	reply_message = dbus_message_new_method_return (message);
	if (value)
	{
		dbus_message_append_args (reply_message, DBUS_TYPE_STRING, gconf_value_get_string (value), DBUS_TYPE_INVALID);
		gconf_value_free (value);
	}
	else
		dbus_message_append_args (reply_message, DBUS_TYPE_STRING, "", DBUS_TYPE_INVALID);

	return (reply_message);
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
			nmi_dbus_get_key_for_network (info, message);
	}
	else if (strcmp ("cancelGetKeyForNetwork", method) == 0)
	{
		GtkWidget	*dialog = glade_xml_get_widget (info->xml, "passphrase_dialog");
		if (GTK_WIDGET_VISIBLE (dialog))
			nmi_cancel_user_key_dialog (info);
	}
	else if (strcmp ("getAllowedNetworks", method) == 0)
		reply_message = nmi_dbus_get_allowed_networks (info, message);
	else if (strcmp ("getAllowedNetworkPriority", method) == 0)
		reply_message = nmi_dbus_get_allowed_network_prio (info, message);
	else if (strcmp ("getAllowedNetworkEssid", method) == 0)
		reply_message = nmi_dbus_get_allowed_network_essid (info, message);
	else if (strcmp ("getAllowedNetworkKey", method) == 0)
		reply_message = nmi_dbus_get_allowed_network_key (info, message);
	else
	{
		reply_message = nmi_dbus_create_error_message (message, NMI_DBUS_NMI_NAMESPACE, "UnknownMethod",
							"NetworkManagerInfo knows nothing about the method %s for object %s", method, path);
	}

	if (reply_message)
	{
		dbus_connection_send (connection, reply_message, NULL);
		dbus_message_unref (reply_message);
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
