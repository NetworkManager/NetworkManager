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
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "NetworkManagerInfo.h"
#include "NetworkManagerInfoDbus.h"
#include "NetworkManagerInfoPassphraseDialog.h"
#include "NetworkManagerInfoVPN.h"


/*
 * nmi_show_warning_dialog
 *
 * pop up a warning or error dialog with certain text
 *
 */
static void nmi_show_warning_dialog (gboolean error, gchar *mesg, ...)
{
	GtkWidget	*dialog;
	char		*tmp;
	va_list	 ap;

	va_start (ap,mesg);
	tmp = g_strdup_vprintf (mesg,ap);
	dialog = gtk_message_dialog_new (NULL, 0, error ? GTK_MESSAGE_ERROR : GTK_MESSAGE_WARNING,
					 GTK_BUTTONS_OK, mesg, NULL);
	gtk_dialog_run (GTK_DIALOG (dialog));
	gtk_widget_destroy (dialog);
	g_free (tmp);
	va_end (ap);
}


/*
 * nmi_network_type_valid
 *
 * Helper to validate network types NMI can deal with
 *
 */
inline gboolean nmi_network_type_valid (NMNetworkType type)
{
	return ((type == NETWORK_TYPE_ALLOWED));
}


/*
 * nmi_dbus_create_error_message
 *
 * Make a DBus error message
 *
 */
static DBusMessage *nmi_dbus_create_error_message (DBusMessage *message, const char *exception_namespace,
										const char *exception, const char *format, ...)
{
	char *exception_text;
	DBusMessage	*reply_message;
	va_list		 args;
	char			 error_text[512];


	va_start (args, format);
	vsnprintf (error_text, 512, format, args);
	va_end (args);

	exception_text = g_strdup_printf ("%s.%s", exception_namespace, exception);
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
	int				 attempt = 0;

	dbus_error_init (&error);
	if (dbus_message_get_args (message, &error,
							DBUS_TYPE_STRING, &device,
							DBUS_TYPE_STRING, &network,
							DBUS_TYPE_INT32, &attempt,
							DBUS_TYPE_INVALID))
	{
		nmi_passphrase_dialog_show (device, network, info);

		dbus_free (device);
		dbus_free (network);
	}
}

/*
 * nmi_dbus_get_user_pass
 *
 * Request a username/password for VPN login
 *
 */
static void nmi_dbus_get_vpn_userpass (NMIAppInfo *info, DBusMessage *message)
{
	DBusError			 error;
	char				*vpn;
	char				*username;
	dbus_bool_t			 retry;


	dbus_error_init (&error);
	if (dbus_message_get_args (message, &error,
				   DBUS_TYPE_STRING, &vpn,
				   DBUS_TYPE_STRING, &username,
				   DBUS_TYPE_BOOLEAN, &retry,
				   DBUS_TYPE_INVALID))
	{
		if (username[0] == '\0') {
			dbus_free (username);
			username = NULL;
		}
		nmi_vpn_request_password (info, message, vpn, username, retry);
		dbus_free (vpn);
		dbus_free (username);
	}
}


/*
 * nmi_dbus_dbus_return_user_key
 *
 * Alert NetworkManager of the new user key
 *
 */
void nmi_dbus_return_user_key (DBusConnection *connection, const char *device,
						const char *network, const char *passphrase, const int key_type)
{
	DBusMessage	*message;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (device != NULL);
	g_return_if_fail (network != NULL);
	g_return_if_fail (passphrase != NULL);

	if (!(message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH, NM_DBUS_INTERFACE, "setKeyForNetwork")))
	{
		syslog (LOG_ERR, "nmi_dbus_return_user_key(): Couldn't allocate the dbus message");
		return;
	}

	/* Add network name and passphrase */
	if (dbus_message_append_args (message, DBUS_TYPE_STRING, device,
								DBUS_TYPE_STRING, network,
								DBUS_TYPE_STRING, passphrase,
								DBUS_TYPE_INT32, key_type,
								DBUS_TYPE_INVALID))
	{
		if (!dbus_connection_send (connection, message, NULL))
			syslog (LOG_ERR, "nmi_dbus_return_user_key(): dbus could not send the message");
	}

	dbus_message_unref (message);
}

/*
 * nmi_dbus_return_userpass
 *
 * Alert caller of the username/password
 *
 */
void nmi_dbus_return_vpn_password (DBusConnection *connection, DBusMessage *message, const char *password)
{
	DBusMessage	*reply;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (message != NULL);
	g_return_if_fail (password != NULL);

	if (password == NULL)
	{
		reply = dbus_message_new_error (message, NMI_DBUS_INTERFACE ".Cancelled", "Operation cancelled by user");
	}
	else
	{
		reply = dbus_message_new_method_return (message);
		dbus_message_append_args (reply,
					  DBUS_TYPE_STRING, password,
					  DBUS_TYPE_INVALID);
	}
	dbus_connection_send (connection, reply, NULL);
	dbus_message_unref (reply);
	dbus_message_unref (message);
}

/*
 * nmi_dbus_signal_update_network
 *
 * Signal NetworkManager that it needs to update info associated with a particular
 * allowed/ignored network.
 *
 */
void nmi_dbus_signal_update_network (DBusConnection *connection, const char *network, NMNetworkType type)
{
	DBusMessage		*message;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (network != NULL);

	if (type != NETWORK_TYPE_ALLOWED)
		return;

	message = dbus_message_new_signal (NMI_DBUS_PATH, NMI_DBUS_INTERFACE, "WirelessNetworkUpdate");
	if (!message)
	{
		syslog (LOG_ERR, "nmi_dbus_signal_update_network(): Not enough memory for new dbus message!");
		return;
	}

	dbus_message_append_args (message, DBUS_TYPE_STRING, network, DBUS_TYPE_INVALID);
	if (!dbus_connection_send (connection, message, NULL))
		syslog (LOG_WARNING, "nmi_dbus_signal_update_network(): Could not raise the 'WirelessNetworkUpdate' signal!");

	dbus_message_unref (message);
}


/*
 * nmi_dbus_get_networks
 *
 * Grab a list of access points from GConf and return it in the form
 * of a string array in a dbus message.
 *
 */
static DBusMessage *nmi_dbus_get_networks (NMIAppInfo *info, DBusMessage *message)
{
	GSList			*dir_list = NULL;
	GSList			*element = NULL;
	DBusError			 error;
	DBusMessage		*reply_message = NULL;
	DBusMessageIter	 iter;
	DBusMessageIter	 iter_array;
	NMNetworkType		 type;

	g_return_val_if_fail (info != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	dbus_error_init (&error);
	if (	   !dbus_message_get_args (message, &error, DBUS_TYPE_INT32, &type, DBUS_TYPE_INVALID)
		|| !nmi_network_type_valid (type))
	{
		reply_message = nmi_dbus_create_error_message (message, NMI_DBUS_INTERFACE, "InvalidArguments",
							"NetworkManagerInfo::getNetworks called with invalid arguments.");
		return (reply_message);
	}

	/* List all allowed access points that gconf knows about */
	element = dir_list = gconf_client_all_dirs (info->gconf_client, NMI_GCONF_WIRELESS_NETWORKS_PATH, NULL);
	if (!dir_list)
	{
		reply_message = nmi_dbus_create_error_message (message, NMI_DBUS_INTERFACE, "NoNetworks",
							"There were are no wireless networks stored.");
	}
	else
	{
		gboolean	value_added = FALSE;

		reply_message = dbus_message_new_method_return (message);
		dbus_message_iter_init (reply_message, &iter);
		dbus_message_iter_append_array (&iter, &iter_array, DBUS_TYPE_STRING);

		/* Append the essid of every allowed or ignored access point we know of 
		 * to a string array in the dbus message.
		 */
		while (element)
		{
			char			 key[100];
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

		if (!value_added)
		{
			dbus_message_unref (reply_message);
			reply_message = nmi_dbus_create_error_message (message, NMI_DBUS_INTERFACE, "NoNetworks",
							"There were are no wireless networks stored.");
		}
	}

	return (reply_message);
}


/*
 * nmi_dbus_get_network
 *
 * Returns the properties of a specific wireless network from gconf
 *
 */
static DBusMessage *nmi_dbus_get_network_properties (NMIAppInfo *info, DBusMessage *message)
{
	DBusMessage		*reply = NULL;
	gchar			*gconf_key = NULL;
	char				*network = NULL;
	GConfValue		*value;
	GConfValue		*ap_addrs_value;
	DBusError			 error;
	NMNetworkType		 type;
	char				*escaped_network;

	char				*essid = NULL;
	gint				 timestamp = -1;
	char				*key = NULL;
	NMEncKeyType		 key_type = -1;
	gboolean			 trusted = FALSE;
	NMDeviceAuthMethod	 auth_method = NM_DEVICE_AUTH_METHOD_UNKNOWN;

	g_return_val_if_fail (info != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	dbus_error_init (&error);
	if (    !dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &network, DBUS_TYPE_INT32, &type, DBUS_TYPE_INVALID)
		|| !nmi_network_type_valid (type)
		|| (strlen (network) <= 0))
	{
		reply = nmi_dbus_create_error_message (message, NMI_DBUS_INTERFACE, "InvalidArguments",
							"NetworkManagerInfo::getNetworkProperties called with invalid arguments.");
		return (reply);
	}

	escaped_network = gconf_escape_key (network, strlen (network));

	/* Grab essid key for our access point from GConf */
	gconf_key = g_strdup_printf ("%s/%s/essid", NMI_GCONF_WIRELESS_NETWORKS_PATH, escaped_network);
	if ((value = gconf_client_get (info->gconf_client, gconf_key, NULL)))
	{
		essid = g_strdup (gconf_value_get_string (value));
		gconf_value_free (value);
	}
	g_free (gconf_key);

	/* Grab timestamp key for our access point from GConf */
	gconf_key = g_strdup_printf ("%s/%s/timestamp", NMI_GCONF_WIRELESS_NETWORKS_PATH, escaped_network);
	if ((value = gconf_client_get (info->gconf_client, gconf_key, NULL)))
	{
		timestamp = gconf_value_get_int (value);
		gconf_value_free (value);
	}	
	g_free (gconf_key);

	/* Grab user-key key for our access point from GConf */
	gconf_key = g_strdup_printf ("%s/%s/key", NMI_GCONF_WIRELESS_NETWORKS_PATH, escaped_network);
	if ((value = gconf_client_get (info->gconf_client, gconf_key, NULL)))
	{
		key = g_strdup (gconf_value_get_string (value));
		gconf_value_free (value);
	}
	else
		key = g_strdup ("");
	g_free (gconf_key);

	gconf_key = g_strdup_printf ("%s/%s/key_type", NMI_GCONF_WIRELESS_NETWORKS_PATH, escaped_network);
	if ((value = gconf_client_get (info->gconf_client, gconf_key, NULL)))
	{
		key_type = gconf_value_get_int (value);
		gconf_value_free (value);
	}
	g_free (gconf_key);

	/* Grab the network's last authentication mode, if known */
	gconf_key = g_strdup_printf ("%s/%s/auth_method", NMI_GCONF_WIRELESS_NETWORKS_PATH, escaped_network);
	if ((value = gconf_client_get (info->gconf_client, gconf_key, NULL)))
	{
		auth_method = gconf_value_get_int (value);
		gconf_value_free (value);
	}
	g_free (gconf_key);

	/* Grab the network's trusted status */
	gconf_key = g_strdup_printf ("%s/%s/trusted", NMI_GCONF_WIRELESS_NETWORKS_PATH, escaped_network);
	if ((value = gconf_client_get (info->gconf_client, gconf_key, NULL)))
	{
		trusted = gconf_value_get_bool (value);
		gconf_value_free (value);
	}
	g_free (gconf_key);

	/* Grab the list of stored AP MAC addresses */
	gconf_key = g_strdup_printf ("%s/%s/addresses", NMI_GCONF_WIRELESS_NETWORKS_PATH, escaped_network);
	ap_addrs_value = gconf_client_get (info->gconf_client, gconf_key, NULL);
	g_free (gconf_key);

	if (!essid || (timestamp < 0) || (key_type < 0))
	{
		if (!essid)
		{
			reply = nmi_dbus_create_error_message (message, NMI_DBUS_INTERFACE, "BadNetworkData",
							"NetworkManagerInfo::getNetworkProperties could not access essid for network '%s'", network);
		}
		else if (timestamp < 0)
		{
			reply = nmi_dbus_create_error_message (message, NMI_DBUS_INTERFACE, "BadNetworkData",
							"NetworkManagerInfo::getNetworkProperties could not access timestamp for network '%s'", network);
		}
		else if (key_type < 0)
		{
			reply = nmi_dbus_create_error_message (message, NMI_DBUS_INTERFACE, "BadNetworkData",
							"NetworkManagerInfo::getNetworkProperties could not access key_type for network '%s'", network);
		}
	}
	else
	{
		char				**array = NULL;
		int				 num_items = 0;

		/* Add a string array of access point MAC addresses if the array is valid */
		if (    ap_addrs_value
			&& (ap_addrs_value->type == GCONF_VALUE_LIST)
			&& (gconf_value_get_list_type (ap_addrs_value) == GCONF_VALUE_STRING))
		{
			GSList	*list = gconf_value_get_list (ap_addrs_value);
			GSList	*elt;
			int		 i;

			num_items = g_slist_length (list); 
			if (num_items > 0)
				array = g_malloc0 (sizeof (char *) * num_items);

			for (elt = list, i = 0; elt; elt = g_slist_next (elt), i++)
			{
				const char *string;
				if ((string = gconf_value_get_string ((GConfValue *)elt->data)))
					array[i] = g_strdup (string);
			}
		}

		reply = dbus_message_new_method_return (message);

		/* Add general properties to dbus reply */
		dbus_message_append_args (reply,   DBUS_TYPE_STRING, essid,
									DBUS_TYPE_INT32, timestamp,
									DBUS_TYPE_STRING, key,
									DBUS_TYPE_INT32, key_type,
									DBUS_TYPE_INT32, auth_method,
									DBUS_TYPE_BOOLEAN, trusted,
									DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, array, num_items,
									DBUS_TYPE_INVALID);
	}	
	if (ap_addrs_value)
		gconf_value_free (ap_addrs_value);

	g_free (essid);
	g_free (key);

	g_free (escaped_network);
	dbus_free (network);
	return (reply);
}


/*
 * nmi_dbus_update_network_auth_method
 *
 * Update a network's authentication method entry in gconf
 *
 */
static DBusMessage *nmi_dbus_update_network_auth_method (NMIAppInfo *info, DBusMessage *message)
{
	DBusMessage		*reply_message = NULL;
	char				*network = NULL;
	NMDeviceAuthMethod	 auth_method = NM_DEVICE_AUTH_METHOD_UNKNOWN;
	char				*key;
	GConfValue		*value;
	DBusError			 error;
	char				*escaped_network;

	g_return_val_if_fail (info != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	dbus_error_init (&error);
	if (    !dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &network, DBUS_TYPE_INT32, &auth_method, DBUS_TYPE_INVALID)
		|| (strlen (network) <= 0)
		|| (auth_method == NM_DEVICE_AUTH_METHOD_UNKNOWN))
	{
		reply_message = nmi_dbus_create_error_message (message, NMI_DBUS_INTERFACE, "InvalidArguments",
							"NetworkManagerInfo::updateNetworkAuthMethod called with invalid arguments.");
		return (reply_message);
	}

	/* Ensure the access point exists in GConf */
	escaped_network = gconf_escape_key (network, strlen (network));
	key = g_strdup_printf ("%s/%s/essid", NMI_GCONF_WIRELESS_NETWORKS_PATH, escaped_network);
	value = gconf_client_get (info->gconf_client, key, NULL);
	g_free (key);

	if (value && (value->type == GCONF_VALUE_STRING))
	{
		key = g_strdup_printf ("%s/%s/auth_method", NMI_GCONF_WIRELESS_NETWORKS_PATH, escaped_network);
		gconf_client_set_int (info->gconf_client, key, auth_method, NULL);
		g_free (key);
	}
	if (value)
		gconf_value_free (value);

	g_free (escaped_network);

	return (NULL);
}


/*
 * nmi_dbus_add_network_address
 *
 * Add an AP's MAC address to a wireless network entry in gconf
 *
 */
static DBusMessage *nmi_dbus_add_network_address (NMIAppInfo *info, DBusMessage *message)
{
	DBusMessage		*reply_message = NULL;
	char				*network = NULL;
	NMNetworkType		 type;
	char				*addr;
	char				*key;
	GConfValue		*value;
	DBusError			 error;
	char				*escaped_network;
	GSList			*new_mac_list = NULL;
	gboolean			 found = FALSE;

	g_return_val_if_fail (info != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	dbus_error_init (&error);
	if (    !dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &network, DBUS_TYPE_INT32, &type, DBUS_TYPE_STRING, &addr, DBUS_TYPE_INVALID)
		|| !nmi_network_type_valid (type)
		|| (strlen (network) <= 0)
		|| !addr
		|| (strlen (addr) < 11))
	{
		reply_message = nmi_dbus_create_error_message (message, NMI_DBUS_INTERFACE, "InvalidArguments",
							"NetworkManagerInfo::addNetworkAddress called with invalid arguments.");
		return (reply_message);
	}

	/* Force-set the essid too so that we have a semi-complete network entry */
	escaped_network = gconf_escape_key (network, strlen (network));
	key = g_strdup_printf ("%s/%s/essid", NMI_GCONF_WIRELESS_NETWORKS_PATH, escaped_network);
	value = gconf_client_get (info->gconf_client, key, NULL);

	/* If the network doesn't already exist in GConf, add it and set its timestamp to now. */
	if (!value || (!value && (value->type == GCONF_VALUE_STRING)))
	{
		/* Set the essid of the network. */
		gconf_client_set_string (info->gconf_client, key, network, NULL);
		g_free (key);

		/* Update timestamp on network */
		key = g_strdup_printf ("%s/%s/timestamp", NMI_GCONF_WIRELESS_NETWORKS_PATH, escaped_network);
		gconf_client_set_int (info->gconf_client, key, time (NULL), NULL);
	}
	g_free (key);

	/* Get current list of access point MAC addresses for this AP from GConf */
	key = g_strdup_printf ("%s/%s/addresses", NMI_GCONF_WIRELESS_NETWORKS_PATH, escaped_network);
	value = gconf_client_get (info->gconf_client, key, NULL);
	g_free (escaped_network);

	if (value && (value->type == GCONF_VALUE_LIST) && (gconf_value_get_list_type (value) == GCONF_VALUE_STRING))
	{
		GSList	*elem;

		new_mac_list = gconf_client_get_list (info->gconf_client, key, GCONF_VALUE_STRING, NULL);
		gconf_value_free (value);

		/* Ensure that the MAC isn't already in the list */
		elem = new_mac_list;
		while (elem)
		{
			if (elem->data && !strcmp (addr, elem->data))
			{
				found = TRUE;
				break;
			}
			elem = g_slist_next (elem);
		}
	}

	/* Add the new MAC address to the end of the list */
	if (!found)
	{
		new_mac_list = g_slist_append (new_mac_list, g_strdup (addr));
		gconf_client_set_list (info->gconf_client, key, GCONF_VALUE_STRING, new_mac_list, NULL);
	}

	/* Free the list, since gconf_client_set_list deep-copies it */
	g_slist_foreach (new_mac_list, (GFunc)g_free, NULL);
	g_slist_free (new_mac_list);

	dbus_free (addr);
	g_free (key);

	return (NULL);
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

/*	syslog (LOG_WARNING, "nmi_dbus_nmi_message_handler() got method %s for path %s", method, path);*/

	if (strcmp ("getKeyForNetwork", method) == 0)
	{
		GtkWidget	*dialog = glade_xml_get_widget (info->passphrase_dialog, "passphrase_dialog");
		if (dialog && !GTK_WIDGET_VISIBLE (dialog))
			nmi_dbus_get_key_for_network (info, message);
	}
	else if (strcmp ("cancelGetKeyForNetwork", method) == 0)
	{
		GtkWidget	*dialog = glade_xml_get_widget (info->passphrase_dialog, "passphrase_dialog");
		if (dialog && GTK_WIDGET_VISIBLE (dialog))
			nmi_passphrase_dialog_cancel (info);
	}
	else if (strcmp ("getVPNUserPass", method) == 0)
	{
		nmi_dbus_get_vpn_userpass (info, message);
	}
	else if (strcmp ("networkNotFound", method) == 0)
	{
		char		*network;
		DBusError	 error;

		dbus_error_init (&error);
		if (dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &network, DBUS_TYPE_INVALID))
		{
			GtkDialog	*dialog;
			char		*text;

			dbus_error_free (&error);
			text = g_strdup_printf ( "The requested wireless network '%s' does not appear to be in range.  "
								"A different wireless network will be used if any are available.", network);
			dbus_free (network);

			dialog = GTK_DIALOG (gtk_message_dialog_new (NULL, 0, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, text, NULL));
			gtk_dialog_run (dialog);
			gtk_widget_destroy (GTK_WIDGET (dialog));
		}
	}
	else if (strcmp ("getNetworks", method) == 0)
		reply_message = nmi_dbus_get_networks (info, message);
	else if (strcmp ("getNetworkProperties", method) == 0)
		reply_message = nmi_dbus_get_network_properties (info, message);
	else if (strcmp ("updateNetworkAuthMethod", method) == 0)
		nmi_dbus_update_network_auth_method (info, message);
	else if (strcmp ("addNetworkAddress", method) == 0)
		nmi_dbus_add_network_address (info, message);
	else
	{
		reply_message = nmi_dbus_create_error_message (message, NMI_DBUS_INTERFACE, "UnknownMethod",
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

gboolean shutdown_callback (gpointer data)
{
	gtk_main_quit ();
	return FALSE;
}

static DBusHandlerResult nmi_dbus_filter (DBusConnection *connection, DBusMessage *message, void *user_data)
{
	gboolean		 handled = FALSE;
	NMIAppInfo	*info = (NMIAppInfo *) user_data;
	gboolean		 appeared = FALSE;
	gboolean		 disappeared = FALSE;

	g_return_val_if_fail (info != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	if (dbus_message_is_signal (message, NM_DBUS_INTERFACE, "WirelessNetworkAppeared"))
		appeared = TRUE;
	else if (dbus_message_is_signal (message, NM_DBUS_INTERFACE, "WirelessNetworkDisappeared"))
		disappeared = TRUE;
	else if (dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceActivationFailed"))
	{
		char		*dev = NULL;
		char		*net = NULL;
		DBusError	 error;

		dbus_error_init (&error);
		if (!dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &dev, DBUS_TYPE_STRING, &net, DBUS_TYPE_INVALID))
		{
			if (dbus_error_is_set (&error))
				dbus_error_free (&error);
			dbus_error_init (&error);
			dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &dev, DBUS_TYPE_INVALID);
		}
		if (dbus_error_is_set (&error))
			dbus_error_free (&error);
		if (dev && net)
		{
			char *string = g_strdup_printf ("Connection to the wireless network '%s' failed.\n", net);
			nmi_show_warning_dialog (TRUE, string);
			g_free (string);
		}
		else if (dev)
			nmi_show_warning_dialog (TRUE, "Connection to the wired network failed.\n");

		dbus_free (dev);
		dbus_free (net);
	}

	return (handled ? DBUS_HANDLER_RESULT_HANDLED : DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
}

/*
 * nmi_dbus_nm_is_running
 *
 * Ask dbus whether or not NetworkManager is running
 *
 */
static gboolean nmi_dbus_nm_is_running (DBusConnection *connection)
{
	DBusError		error;
	gboolean		exists;

	g_return_val_if_fail (connection != NULL, FALSE);

	dbus_error_init (&error);
	exists = dbus_bus_service_exists (connection, NM_DBUS_SERVICE, &error);
	if (dbus_error_is_set (&error))
		dbus_error_free (&error);
	return (exists);
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
	int acquisition;

	dbus_error_init (&dbus_error);
	acquisition = dbus_bus_acquire_service (dbus_connection, NMI_DBUS_SERVICE,
						DBUS_SERVICE_FLAG_PROHIBIT_REPLACEMENT,
						&dbus_error);
	if (dbus_error_is_set (&dbus_error))
	{
		syslog (LOG_ERR, "nmi_dbus_service_init() could not acquire its service.  dbus_bus_acquire_service() says: '%s'", dbus_error.message);
		dbus_error_free (&dbus_error);
		return (-1);
	}
	if (acquisition & DBUS_SERVICE_REPLY_SERVICE_EXISTS) {
	     exit (0);
	}

#if 0
	if (!nmi_dbus_nm_is_running (dbus_connection))
		return (-1);
#endif

	if (!dbus_connection_register_object_path (dbus_connection, NMI_DBUS_PATH, &nmi_vtable, info))
	{
		syslog (LOG_ERR, "nmi_dbus_service_init() could not register a handler for NetworkManagerInfo.  Not enough memory?");
		return (-1);
	}

	if (!dbus_connection_add_filter (dbus_connection, nmi_dbus_filter, info, NULL))
		return (-1);

	dbus_error_init (&dbus_error);
	dbus_bus_add_match (dbus_connection,
				"type='signal',"
				"interface='" NM_DBUS_INTERFACE "',"
				"sender='" NM_DBUS_SERVICE "',"
				"path='" NM_DBUS_PATH "'", &dbus_error);
	if (dbus_error_is_set (&dbus_error))
	{
		dbus_error_free (&dbus_error);
		return (-1);
	}

	dbus_bus_add_match(dbus_connection,
				"type='signal',"
				"interface='" DBUS_INTERFACE_ORG_FREEDESKTOP_DBUS "',"
				"sender='" DBUS_SERVICE_ORG_FREEDESKTOP_DBUS "'",
				&dbus_error);
	if (dbus_error_is_set (&dbus_error))
	{
		dbus_error_free (&dbus_error);
		return (-1);
	}

	return (0);
}
