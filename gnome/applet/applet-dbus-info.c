/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */
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
 * (C) Copyright 2004-2005 Red Hat, Inc.
 */


#include <string.h>
#include <stdio.h>
#include <time.h>
#include <glib.h>
#include <glib/gi18n.h>
#include <dbus/dbus.h>
#include <gtk/gtk.h>
#include <glade/glade.h>
#include <gnome-keyring.h>

#include "NetworkManager.h"
#include "applet.h"
#include "applet-dbus.h"
#include "applet-dbus-info.h"
#include "passphrase-dialog.h"
#include "nm-utils.h"


/*
 * nmi_network_type_valid
 *
 * Helper to validate network types NMI can deal with
 *
 */
static inline gboolean nmi_network_type_valid (NMNetworkType type)
{
	return ((type == NETWORK_TYPE_ALLOWED));
}


/*
 * nmi_dbus_create_error_message
 *
 * Make a DBus error message
 *
 */
DBusMessage *nmi_dbus_create_error_message (DBusMessage *message, const char *exception_namespace,
										const char *exception, const char *format, ...)
{
	char *		exception_text;
	DBusMessage *	reply_message;
	va_list		args;
	char			error_text[512];

	va_start (args, format);
	vsnprintf (error_text, 512, format, args);
	va_end (args);

	exception_text = g_strdup_printf ("%s.%s", exception_namespace, exception);
	reply_message = dbus_message_new_error (message, exception_text, error_text);
	g_free (exception_text);

	return (reply_message);
}


/*
 * nmi_dbus_get_network_key
 *
 * Grab the network's key from the keyring.
 *
 */
static char *nmi_dbus_get_network_key (NMWirelessApplet *applet, const char *essid)
{
	GnomeKeyringResult	ret;
	GList *			found_list = NULL;
	char *			key = NULL;

	g_return_val_if_fail (applet != NULL, NULL);
	g_return_val_if_fail (essid != NULL, NULL);

	/* Get the essid key, if any, from the keyring */
	ret = gnome_keyring_find_itemsv_sync (GNOME_KEYRING_ITEM_GENERIC_SECRET,
								   &found_list,
								   "essid",
								   GNOME_KEYRING_ATTRIBUTE_TYPE_STRING,
								   essid,
								   NULL);
	if (ret == GNOME_KEYRING_RESULT_OK)
	{
		GnomeKeyringFound *found = found_list->data;
		key = g_strdup (found->secret);
		gnome_keyring_found_list_free (found_list);
	}

	return key;
}


/*
 * nmi_dbus_get_key_for_network
 *
 * Throw up the user key dialog
 *
 */
static DBusMessage * nmi_dbus_get_key_for_network (NMWirelessApplet *applet, DBusMessage *message)
{
	char *	dev_path = NULL;
	char *	net_path = NULL;
	char *	essid = NULL;
	int		attempt = 0;
	gboolean	new_key = FALSE;
	gboolean	success = FALSE;

	if (dbus_message_get_args (message, NULL,
							DBUS_TYPE_OBJECT_PATH, &dev_path,
							DBUS_TYPE_OBJECT_PATH, &net_path,
							DBUS_TYPE_STRING, &essid,
							DBUS_TYPE_INT32, &attempt,
							DBUS_TYPE_BOOLEAN, &new_key,
							DBUS_TYPE_INVALID))
	{
		NetworkDevice *dev = NULL;

		if ((dev = nmwa_get_device_for_nm_path (applet->dbus_device_list, dev_path)))
		{
			WirelessNetwork *net = NULL;

			/* Try to get the key from the keyring.  If we fail, ask for a new key. */
			if (!new_key)
			{
				char *key;

				if ((key = nmi_dbus_get_network_key (applet, essid)))
				{
					char *		gconf_key;
					char *		escaped_network;
					GConfValue *	value;
					NMEncKeyType	key_type = -1;

					/* Grab key type from GConf since we need it for return message */
					escaped_network = gconf_escape_key (essid, strlen (essid));
					gconf_key = g_strdup_printf ("%s/%s/key_type", GCONF_PATH_WIRELESS_NETWORKS, escaped_network);
					g_free (escaped_network);
					if ((value = gconf_client_get (applet->gconf_client, gconf_key, NULL)))
					{
						key_type = gconf_value_get_int (value);
						gconf_value_free (value);
					}
					g_free (gconf_key);

					nmi_dbus_return_user_key (applet->connection, message, key, key_type);
					g_free (key);
					success = TRUE;
				}
				else
					new_key = TRUE;
			}

			/* We only ask the user for a new key when we know about the network from NM,
			 * since throwing up a dialog with a random essid from somewhere is a security issue.
			 */
			if (new_key && (net = network_device_get_wireless_network_by_nm_path (dev, net_path)))
				success = nmi_passphrase_dialog_schedule_show (dev, net, message, applet);
		}
	}

	if (!success)
		return nmi_dbus_create_error_message (message, NMI_DBUS_INTERFACE, "GetKeyError", "Could not get user key for network.");

	return NULL;
}


/*
 * nmi_dbus_dbus_return_user_key
 *
 * Alert NetworkManager of the new user key
 *
 */
void nmi_dbus_return_user_key (DBusConnection *connection, DBusMessage *message, const char *passphrase, const NMEncKeyType key_type)
{
	DBusMessage *	reply;
	const char *	dev_path;
	const char *	net_path;
	const int		tmp_key_type = (int)key_type;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (passphrase != NULL);

	if (!(reply = dbus_message_new_method_return (message)))
	{
		nm_warning ("nmi_dbus_return_user_key(): Couldn't allocate the dbus message");
		return;
	}

	dbus_message_append_args (reply, DBUS_TYPE_STRING, &passphrase, DBUS_TYPE_INT32, &tmp_key_type, DBUS_TYPE_INVALID);
	dbus_connection_send (connection, reply, NULL);
	dbus_message_unref (reply);
}


/*
 * nmi_dbus_signal_update_scan_method
 *
 * Signal NetworkManager that it needs to update its wireless scanning method
 *
 */
void nmi_dbus_signal_update_scan_method (DBusConnection *connection)
{
	DBusMessage		*message;

	g_return_if_fail (connection != NULL);

	message = dbus_message_new_signal (NMI_DBUS_PATH, NMI_DBUS_INTERFACE, "WirelessScanMethodUpdate");
	if (!message)
	{
		nm_warning ("nmi_dbus_signal_update_scan_method(): Not enough memory for new dbus message!");
		return;
	}

	if (!dbus_connection_send (connection, message, NULL))
		nm_warning ("nmi_dbus_signal_update_scan_method(): Could not raise the 'WirelessScanMethodUpdate' signal!");

	dbus_message_unref (message);
}


/*
 * nmi_dbus_get_wireless_scan_method
 *
 * Tell NetworkManager what wireless scanning method it should use
 *
 */
static DBusMessage *nmi_dbus_get_wireless_scan_method (NMWirelessApplet *applet, DBusMessage *message)
{
	DBusMessage *			reply = NULL;
	NMWirelessScanMethod	method = NM_SCAN_METHOD_ALWAYS;
	GConfEntry *			entry;

	g_return_val_if_fail (applet != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	method = nmwa_gconf_get_wireless_scan_method (applet);
	reply = dbus_message_new_method_return (message);
	dbus_message_append_args (reply, DBUS_TYPE_UINT32, &method, DBUS_TYPE_INVALID);

	return (reply);
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
		nm_warning ("nmi_dbus_signal_update_network(): Not enough memory for new dbus message!");
		return;
	}

	dbus_message_append_args (message, DBUS_TYPE_STRING, &network, DBUS_TYPE_INVALID);
	if (!dbus_connection_send (connection, message, NULL))
		nm_warning ("nmi_dbus_signal_update_network(): Could not raise the 'WirelessNetworkUpdate' signal!");

	dbus_message_unref (message);
}


/*
 * nmi_dbus_get_networks
 *
 * Grab a list of access points from GConf and return it in the form
 * of a string array in a dbus message.
 *
 */
static DBusMessage *nmi_dbus_get_networks (NMWirelessApplet *applet, DBusMessage *message)
{
	GSList			*dir_list = NULL;
	GSList			*element = NULL;
	DBusError			 error;
	DBusMessage		*reply_message = NULL;
	DBusMessageIter	 iter;
	DBusMessageIter	 iter_array;
	NMNetworkType		 type;

	g_return_val_if_fail (applet != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	dbus_error_init (&error);
	if (	   !dbus_message_get_args (message, &error, DBUS_TYPE_INT32, &type, DBUS_TYPE_INVALID)
		|| !nmi_network_type_valid (type))
	{
		reply_message = nmwa_dbus_create_error_message (message, NMI_DBUS_INTERFACE, "InvalidArguments",
							"NetworkManagerInfo::getNetworks called with invalid arguments.");
		return (reply_message);
	}

	/* List all allowed access points that gconf knows about */
	element = dir_list = gconf_client_all_dirs (applet->gconf_client, GCONF_PATH_WIRELESS_NETWORKS, NULL);
	if (!dir_list)
	{
		reply_message = nmwa_dbus_create_error_message (message, NMI_DBUS_INTERFACE, "NoNetworks",
							"There were are no wireless networks stored.");
	}
	else
	{
		gboolean	value_added = FALSE;

		reply_message = dbus_message_new_method_return (message);
		dbus_message_iter_init_append (reply_message, &iter);
		dbus_message_iter_open_container (&iter, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING_AS_STRING, &iter_array);

		/* Append the essid of every allowed or ignored access point we know of 
		 * to a string array in the dbus message.
		 */
		while (element)
		{
			char			 key[100];
			GConfValue	*value;

			g_snprintf (&key[0], 99, "%s/essid", (char *)(element->data));
			value = gconf_client_get (applet->gconf_client, key, NULL);
			if (value && gconf_value_get_string (value))
			{
				const gchar *essid;
				essid = gconf_value_get_string (value);
				dbus_message_iter_append_basic (&iter_array, DBUS_TYPE_STRING, &essid);
				value_added = TRUE;
				gconf_value_free (value);
			}

			g_free (element->data);
			element = element->next;
		}
		g_slist_free (dir_list);

		dbus_message_iter_close_container (&iter, &iter_array);

		if (!value_added)
		{
			dbus_message_unref (reply_message);
			reply_message = nmwa_dbus_create_error_message (message, NMI_DBUS_INTERFACE, "NoNetworks",
							"There were are no wireless networks stored.");
		}
	}

	return (reply_message);
}


/*
 * nmi_dbus_get_network_properties
 *
 * Returns the properties of a specific wireless network from gconf
 *
 */
static DBusMessage *nmi_dbus_get_network_properties (NMWirelessApplet *applet, DBusMessage *message)
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
	gint32			 i;
	NMEncKeyType		 key_type = -1;
	gboolean			 trusted = FALSE;
	NMDeviceAuthMethod	 auth_method = NM_DEVICE_AUTH_METHOD_UNKNOWN;

	g_return_val_if_fail (applet != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	dbus_error_init (&error);
	if (    !dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &network, DBUS_TYPE_INT32, &type, DBUS_TYPE_INVALID)
		|| !nmi_network_type_valid (type)
		|| (strlen (network) <= 0))
	{
		reply = nmwa_dbus_create_error_message (message, NMI_DBUS_INTERFACE, "InvalidArguments",
							"NetworkManagerInfo::getNetworkProperties called with invalid arguments.");
		return (reply);
	}

	escaped_network = gconf_escape_key (network, strlen (network));

	/* Grab essid key for our access point from GConf */
	gconf_key = g_strdup_printf ("%s/%s/essid", GCONF_PATH_WIRELESS_NETWORKS, escaped_network);
	if ((value = gconf_client_get (applet->gconf_client, gconf_key, NULL)))
	{
		essid = g_strdup (gconf_value_get_string (value));
		gconf_value_free (value);
	}
	g_free (gconf_key);

	/* Grab timestamp key for our access point from GConf */
	gconf_key = g_strdup_printf ("%s/%s/timestamp", GCONF_PATH_WIRELESS_NETWORKS, escaped_network);
	if ((value = gconf_client_get (applet->gconf_client, gconf_key, NULL)))
	{
		timestamp = gconf_value_get_int (value);
		gconf_value_free (value);
	}	
	g_free (gconf_key);

	gconf_key = g_strdup_printf ("%s/%s/key_type", GCONF_PATH_WIRELESS_NETWORKS, escaped_network);
	if ((value = gconf_client_get (applet->gconf_client, gconf_key, NULL)))
	{
		key_type = gconf_value_get_int (value);
		gconf_value_free (value);
	}
	g_free (gconf_key);

	/* Grab the network's last authentication mode, if known */
	gconf_key = g_strdup_printf ("%s/%s/auth_method", GCONF_PATH_WIRELESS_NETWORKS, escaped_network);
	if ((value = gconf_client_get (applet->gconf_client, gconf_key, NULL)))
	{
		auth_method = gconf_value_get_int (value);
		gconf_value_free (value);
	}
	g_free (gconf_key);

	/* Grab the network's trusted status */
	gconf_key = g_strdup_printf ("%s/%s/trusted", GCONF_PATH_WIRELESS_NETWORKS, escaped_network);
	if ((value = gconf_client_get (applet->gconf_client, gconf_key, NULL)))
	{
		trusted = gconf_value_get_bool (value);
		gconf_value_free (value);
	}
	g_free (gconf_key);

	/* Grab the list of stored AP MAC addresses */
	gconf_key = g_strdup_printf ("%s/%s/addresses", GCONF_PATH_WIRELESS_NETWORKS, escaped_network);
	ap_addrs_value = gconf_client_get (applet->gconf_client, gconf_key, NULL);
	g_free (gconf_key);

	/* FIXME: key_type is always nonnegative as it is unsigned */
	if (!essid || (timestamp < 0) || (key_type < 0))
	{
		if (!essid)
		{
			reply = nmwa_dbus_create_error_message (message, NMI_DBUS_INTERFACE, "BadNetworkData",
							"NetworkManagerInfo::getNetworkProperties could not access essid for network '%s'", network);
		}
		else if (timestamp < 0)
		{
			reply = nmwa_dbus_create_error_message (message, NMI_DBUS_INTERFACE, "BadNetworkData",
							"NetworkManagerInfo::getNetworkProperties could not access timestamp for network '%s'", network);
		}
		/* FIXME: key_type is always nonnegative as it is unsigned */
		else if (key_type < 0)
		{
			reply = nmwa_dbus_create_error_message (message, NMI_DBUS_INTERFACE, "BadNetworkData",
							"NetworkManagerInfo::getNetworkProperties could not access key_type for network '%s'", network);
		}
	}
	else
	{
		DBusMessageIter 		iter, array_iter;

		reply = dbus_message_new_method_return (message);

		dbus_message_iter_init_append (reply, &iter);

		dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &essid);
		i = (gint32) timestamp;
		dbus_message_iter_append_basic (&iter, DBUS_TYPE_INT32, &i);
		i = (gint32) key_type;
		dbus_message_iter_append_basic (&iter, DBUS_TYPE_INT32, &i);
		i = (gint32) auth_method;
		dbus_message_iter_append_basic (&iter, DBUS_TYPE_INT32, &i);
		dbus_message_iter_append_basic (&iter, DBUS_TYPE_BOOLEAN, &trusted);
		
		dbus_message_iter_open_container (&iter, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING_AS_STRING, &array_iter);

		/* Add a string array of access point MAC addresses if the array is valid */
		if (    ap_addrs_value
			&& (ap_addrs_value->type == GCONF_VALUE_LIST)
			&& (gconf_value_get_list_type (ap_addrs_value) == GCONF_VALUE_STRING))
		{
			GSList	*list = gconf_value_get_list (ap_addrs_value);
			GSList	*elt;

			for (elt = list; elt; elt = g_slist_next (elt))
			{
				const char *string;
				if ((string = gconf_value_get_string ((GConfValue *)elt->data)))
					dbus_message_iter_append_basic (&array_iter, DBUS_TYPE_STRING, &string);
			}
		}

		dbus_message_iter_close_container (&iter, &array_iter);
	}	

	if (ap_addrs_value != NULL)
		gconf_value_free (ap_addrs_value);

	g_free (essid);
	g_free (escaped_network);

	return reply;
}


/*
 * nmi_dbus_signal_update_vpn_connection
 *
 * Signal NetworkManager that it needs to update info associated with a particular
 * VPN connection.
 *
 */
void nmi_dbus_signal_update_vpn_connection (DBusConnection *connection, const char *name)
{
	DBusMessage		*message;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (name != NULL);

	if (!(message = dbus_message_new_signal (NMI_DBUS_PATH, NMI_DBUS_INTERFACE, "VPNConnectionUpdate")))
	{
		nm_warning ("nmi_dbus_signal_update_vpn_connection(): Not enough memory for new dbus message!");
		return;
	}

	dbus_message_append_args (message, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID);
	if (!dbus_connection_send (connection, message, NULL))
		nm_warning ("nmi_dbus_signal_update_vpn_connection(): Could not raise the 'VPNConnectionUpdate' signal!");

	dbus_message_unref (message);
}


/*
 * nmi_dbus_get_vpn_connections
 *
 * Grab a list of VPN connections from GConf and return it in the form
 * of a string array in a dbus message.
 *
 */
static DBusMessage *nmi_dbus_get_vpn_connections (NMWirelessApplet *applet, DBusMessage *message)
{
	GSList			*dir_list = NULL;
	GSList			*element = NULL;
	DBusError			 error;
	DBusMessage		*reply = NULL;
	DBusMessageIter	 iter;
	DBusMessageIter	 iter_array;

	g_return_val_if_fail (applet != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	dbus_error_init (&error);

	/*g_debug ("entering nmi_dbus_get_vpn_connections");*/

	/* List all VPN connections that gconf knows about */
	element = dir_list = gconf_client_all_dirs (applet->gconf_client, GCONF_PATH_VPN_CONNECTIONS, NULL);
	if (!dir_list)
	{
		reply = nmwa_dbus_create_error_message (message, NMI_DBUS_INTERFACE, "NoVPNConnections",
							"There are no VPN connections stored.");
	}
	else
	{
		gboolean	value_added = FALSE;

		reply = dbus_message_new_method_return (message);
		dbus_message_iter_init_append (reply, &iter);
		dbus_message_iter_open_container (&iter, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING_AS_STRING, &iter_array);

		/* Append the essid of every allowed or ignored access point we know of 
		 * to a string array in the dbus message.
		 */
		while (element)
		{
			char			 key[100];
			GConfValue	*value;

			g_snprintf (&key[0], 99, "%s/name", (char *)(element->data));
			value = gconf_client_get (applet->gconf_client, key, NULL);
			if (value && gconf_value_get_string (value))
			{
				const gchar *essid;
				essid = gconf_value_get_string (value);
				dbus_message_iter_append_basic (&iter_array, DBUS_TYPE_STRING, &essid);
				/*g_debug ("vpnid = '%s'", essid);*/
				value_added = TRUE;
				gconf_value_free (value);
			}


			g_free (element->data);
			element = element->next;
		}
		g_slist_free (dir_list);

		dbus_message_iter_close_container (&iter, &iter_array);

		if (!value_added)
		{
			dbus_message_unref (reply);
			reply = nmwa_dbus_create_error_message (message, NMI_DBUS_INTERFACE, "NoVPNConnections",
							"There are no VPN connections stored.");
		}
	}

	return (reply);
}


/*
 * nmi_dbus_get_vpn_connection_properties
 *
 * Returns the properties of a specific VPN connection from gconf
 *
 */
static DBusMessage *nmi_dbus_get_vpn_connection_properties (NMWirelessApplet *applet, DBusMessage *message)
{
	DBusMessage	*reply = NULL;
	gchar		*gconf_key = NULL;
	char			*vpn_connection = NULL;
	GConfValue	*value;
	DBusError		 error;
	char			*escaped_name;
	char			*name = NULL;
	char 		*service_name = NULL;
	const char     *user_name = NULL;

	g_return_val_if_fail (applet != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	dbus_error_init (&error);
	if (    !dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &vpn_connection, DBUS_TYPE_INVALID)
		|| (strlen (vpn_connection) <= 0))
	{
		reply = nmwa_dbus_create_error_message (message, NMI_DBUS_INTERFACE, "InvalidArguments",
							"NetworkManagerInfo::getVPNConnectionProperties called with invalid arguments.");
		return (reply);
	}

	escaped_name = gconf_escape_key (vpn_connection, strlen (vpn_connection));

	/*g_debug ("entering nmi_dbus_get_vpn_connection_properties for '%s'", escaped_name);*/

	/* User-visible name of connection */
	gconf_key = g_strdup_printf ("%s/%s/name", GCONF_PATH_VPN_CONNECTIONS, escaped_name);
	if ((value = gconf_client_get (applet->gconf_client, gconf_key, NULL)))
	{
		name = g_strdup (gconf_value_get_string (value));
		gconf_value_free (value);
		/*g_debug ("name '%s'", name);*/
	}
	g_free (gconf_key);

	/* Service name of connection */
	gconf_key = g_strdup_printf ("%s/%s/service_name", GCONF_PATH_VPN_CONNECTIONS, escaped_name);
	if ((value = gconf_client_get (applet->gconf_client, gconf_key, NULL)))
	{
		service_name = g_strdup (gconf_value_get_string (value));
		gconf_value_free (value);
		/*g_debug ("service '%s'", service_name);*/
	}
	g_free (gconf_key);

	/* User name of connection - use the logged in user */
	user_name = g_get_user_name ();

	if (!name)
	{
		reply = nmwa_dbus_create_error_message (message, NMI_DBUS_INTERFACE, "BadVPNConnectionData",
						"NetworkManagerInfo::getVPNConnectionProperties could not access the name for connection '%s'", vpn_connection);
		/*g_warning ("BadVPNConnectionData for '%s'", escaped_name);*/
	}
	else if (!service_name)
	{
		reply = nmwa_dbus_create_error_message (message, NMI_DBUS_INTERFACE, "BadVPNConnectionData",
						"NetworkManagerInfo::getVPNConnectionProperties could not access the service name for connection '%s'", vpn_connection);
		/*g_warning ("BadVPNConnectionData for '%s'", escaped_name);*/
	}
	else
	{
		DBusMessageIter 		iter, array_iter;

		reply = dbus_message_new_method_return (message);
		dbus_message_iter_init_append (reply, &iter);
		dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &name);
		dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &service_name);
		dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &user_name);
	}	

	g_free (service_name);
	g_free (name);
	g_free (escaped_name);

	return (reply);
}


/*
 * nmi_dbus_get_vpn_connection_vpn_data
 *
 * Returns vpn-daemon specific properties for a particular VPN connection.
 *
 */
static DBusMessage *nmi_dbus_get_vpn_connection_vpn_data (NMWirelessApplet *applet, DBusMessage *message)
{
	DBusMessage		*reply = NULL;
	gchar			*gconf_key = NULL;
	char				*name = NULL;
	GConfValue		*vpn_data_value = NULL;
	GConfValue		*value = NULL;
	DBusError			 error;
	char				*escaped_name;
	DBusMessageIter 	 iter, array_iter;
	GSList			*elt;

	g_return_val_if_fail (applet != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	dbus_error_init (&error);
	if (    !dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID)
		|| (strlen (name) <= 0))
	{
		reply = nmwa_dbus_create_error_message (message, NMI_DBUS_INTERFACE, "InvalidArguments",
							"NetworkManagerInfo::getVPNConnectionVPNData called with invalid arguments.");
		return reply;
	}

	escaped_name = gconf_escape_key (name, strlen (name));

	/* User-visible name of connection */
	gconf_key = g_strdup_printf ("%s/%s/name", GCONF_PATH_VPN_CONNECTIONS, escaped_name);
	if (!(value = gconf_client_get (applet->gconf_client, gconf_key, NULL)))
	{
		reply = nmwa_dbus_create_error_message (message, NMI_DBUS_INTERFACE, "BadVPNConnectionData",
						"NetworkManagerInfo::getVPNConnectionVPNData could not access the name for connection '%s'", name);
		return reply;
	}
	gconf_value_free (value);
	g_free (gconf_key);

	/* Grab vpn-daemon specific data */
	gconf_key = g_strdup_printf ("%s/%s/vpn_data", GCONF_PATH_VPN_CONNECTIONS, escaped_name);
	if (!(vpn_data_value = gconf_client_get (applet->gconf_client, gconf_key, NULL))
		|| !(vpn_data_value->type == GCONF_VALUE_LIST)
		|| !(gconf_value_get_list_type (vpn_data_value) == GCONF_VALUE_STRING))
	{
		reply = nmwa_dbus_create_error_message (message, NMI_DBUS_INTERFACE, "BadVPNConnectionData",
						"NetworkManagerInfo::getVPNConnectionVPNData could not access the VPN data for connection '%s'", name);
		if (vpn_data_value)
			gconf_value_free (vpn_data_value);
		return reply;
	}
	g_free (gconf_key);

	reply = dbus_message_new_method_return (message);
	dbus_message_iter_init_append (reply, &iter);
	dbus_message_iter_open_container (&iter, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING_AS_STRING, &array_iter);

	for (elt = gconf_value_get_list (vpn_data_value); elt; elt = g_slist_next (elt))
	{
		const char *string = gconf_value_get_string ((GConfValue *)elt->data);
		if (string)
			dbus_message_iter_append_basic (&array_iter, DBUS_TYPE_STRING, &string);
	}

	dbus_message_iter_close_container (&iter, &array_iter);

	gconf_value_free (vpn_data_value);
	g_free (escaped_name);

	return (reply);
}

/*
 * nmi_dbus_get_vpn_connection_routes
 *
 * Returns routes for a particular VPN connection.
 *
 */
static DBusMessage *nmi_dbus_get_vpn_connection_routes (NMWirelessApplet *applet, DBusMessage *message)
{
	DBusMessage		*reply = NULL;
	gchar			*gconf_key = NULL;
	char				*name = NULL;
	GConfValue		*routes_value = NULL;
	GConfValue		*value = NULL;
	DBusError			 error;
	char				*escaped_name;
	DBusMessageIter 	 iter, array_iter;
	GSList			*elt;

	g_return_val_if_fail (applet != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	dbus_error_init (&error);
	if (    !dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID)
		|| (strlen (name) <= 0))
	{
		reply = nmwa_dbus_create_error_message (message, NMI_DBUS_INTERFACE, "InvalidArguments",
							"NetworkManagerInfo::getVPNConnectionRoutes called with invalid arguments.");
		return reply;
	}

	escaped_name = gconf_escape_key (name, strlen (name));

	/* User-visible name of connection */
	gconf_key = g_strdup_printf ("%s/%s/name", GCONF_PATH_VPN_CONNECTIONS, escaped_name);
	if (!(value = gconf_client_get (applet->gconf_client, gconf_key, NULL)))
	{
		reply = nmwa_dbus_create_error_message (message, NMI_DBUS_INTERFACE, "BadVPNConnectionData",
						"NetworkManagerInfo::getVPNConnectionRoutes could not access the name for connection '%s'", name);
		return reply;
	}
	gconf_value_free (value);
	g_free (gconf_key);

	/* Grab vpn-daemon specific data */
	gconf_key = g_strdup_printf ("%s/%s/routes", GCONF_PATH_VPN_CONNECTIONS, escaped_name);
	if (!(routes_value = gconf_client_get (applet->gconf_client, gconf_key, NULL))
		|| !(routes_value->type == GCONF_VALUE_LIST)
		|| !(gconf_value_get_list_type (routes_value) == GCONF_VALUE_STRING))
	{
		reply = nmwa_dbus_create_error_message (message, NMI_DBUS_INTERFACE, "BadVPNConnectionData",
						"NetworkManagerInfo::getVPNConnectionRoutes could not access the routes for connection '%s'", name);
		if (routes_value)
			gconf_value_free (routes_value);
		return reply;
	}
	g_free (gconf_key);

	reply = dbus_message_new_method_return (message);
	dbus_message_iter_init_append (reply, &iter);
	dbus_message_iter_open_container (&iter, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING_AS_STRING, &array_iter);

	for (elt = gconf_value_get_list (routes_value); elt; elt = g_slist_next (elt))
	{
		const char *string = gconf_value_get_string ((GConfValue *)elt->data);
		if (string)
			dbus_message_iter_append_basic (&array_iter, DBUS_TYPE_STRING, &string);
	}

	dbus_message_iter_close_container (&iter, &array_iter);

	gconf_value_free (routes_value);
	g_free (escaped_name);

	return (reply);
}


/*
 * nmi_save_network_info
 *
 * Save information about a wireless network in gconf and the gnome keyring.
 *
 */
static void nmi_save_network_info (NMWirelessApplet *applet, const char *essid, const char *enc_key_source,
			const NMEncKeyType enc_key_type, const NMDeviceAuthMethod auth_method,
			gboolean user_requested)
{
	char *		key;
	GConfEntry *	gconf_entry;
	char *		escaped_network;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (essid != NULL);

	escaped_network = gconf_escape_key (essid, strlen (essid));
	key = g_strdup_printf ("%s/%s", GCONF_PATH_WIRELESS_NETWORKS, escaped_network);
	gconf_entry = gconf_client_get_entry (applet->gconf_client, key, NULL, TRUE, NULL);
	g_free (key);

	if (gconf_entry)
	{
		GnomeKeyringAttributeList *attributes;
		GnomeKeyringAttribute attr;
		GnomeKeyringResult ret;
		const char *name;
		guint32 item_id;

		if (enc_key_source && strlen (enc_key_source)
			&& (enc_key_type != NM_ENC_TYPE_UNKNOWN) && (enc_key_type != NM_ENC_TYPE_NONE))
		{
			/* Setup a request to the keyring to save the network passphrase */
			name = g_strdup_printf (_("Passphrase for wireless network %s"), essid);
			attributes = gnome_keyring_attribute_list_new ();
			attr.name = g_strdup ("essid");	/* FIXME: Do we need to free this ? */
			attr.type = GNOME_KEYRING_ATTRIBUTE_TYPE_STRING;
			attr.value.string = g_strdup (essid);
			g_array_append_val (attributes, attr);

			ret = gnome_keyring_item_create_sync (NULL,
										   GNOME_KEYRING_ITEM_GENERIC_SECRET,
										   name,
										   attributes,
										   enc_key_source,
										   TRUE,
										   &item_id);
			if (ret != GNOME_KEYRING_RESULT_OK)
				g_warning ("Error saving passphrase in keyring.  Ret=%d", ret);
			else
				gnome_keyring_attribute_list_free (attributes);
		}

		gconf_entry_unref (gconf_entry);

		key = g_strdup_printf ("%s/%s/essid", GCONF_PATH_WIRELESS_NETWORKS, escaped_network);
		gconf_client_set_string (applet->gconf_client, key, essid, NULL);
		g_free (key);

		key = g_strdup_printf ("%s/%s/key_type", GCONF_PATH_WIRELESS_NETWORKS, escaped_network);
		gconf_client_set_int (applet->gconf_client, key, (int)enc_key_type, NULL);
		g_free (key);

		/* We only update the timestamp if the user requested a particular network, not if
		 * NetworkManager decided to switch access points by itself.
		 */
		if (user_requested)
		{
			key = g_strdup_printf ("%s/%s/timestamp", GCONF_PATH_WIRELESS_NETWORKS, escaped_network);
			gconf_client_set_int (applet->gconf_client, key, time (NULL), NULL);
			g_free (key);
		}

		if (auth_method != NM_DEVICE_AUTH_METHOD_UNKNOWN)
		{
			key = g_strdup_printf ("%s/%s/auth_method", GCONF_PATH_WIRELESS_NETWORKS, escaped_network);
			gconf_client_set_int (applet->gconf_client, key, auth_method, NULL);
			g_free (key);
		}
	}
	g_free (escaped_network);
}



/*
 * nmi_dbus_update_network_info
 *
 * Update a network's authentication method and encryption key in gconf & the keyring
 *
 */
static void nmi_dbus_update_network_info (NMWirelessApplet *applet, DBusMessage *message)
{
	DBusMessage *		reply_message = NULL;
	char *			network = NULL;
	NMDeviceAuthMethod	auth_method = NM_DEVICE_AUTH_METHOD_UNKNOWN;
	char *			enc_key_source = NULL;
	int				enc_key_type = -1;
	char *			key;
	gboolean			user_requested;
	GConfValue *		value;
	DBusError			error;
	char *			escaped_network;
	dbus_bool_t		args_good;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (message != NULL);

	dbus_error_init (&error);
	args_good = dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &network,
											  DBUS_TYPE_STRING, &enc_key_source,
											  DBUS_TYPE_INT32, &enc_key_type,
											  DBUS_TYPE_INT32, &auth_method,
											  DBUS_TYPE_BOOLEAN, &user_requested,
											  DBUS_TYPE_INVALID);
	if (!args_good || (strlen (network) <= 0) || (auth_method == NM_DEVICE_AUTH_METHOD_UNKNOWN))
		return;
	if (enc_key_source && strlen (enc_key_source) && ((enc_key_type == NM_ENC_TYPE_UNKNOWN) || (enc_key_type == NM_ENC_TYPE_NONE)))
		return;

	nmi_save_network_info (applet, network, enc_key_source, (NMEncKeyType) enc_key_type, auth_method, user_requested);
}


/*
 * nmi_dbus_add_network_address
 *
 * Add an AP's MAC address to a wireless network entry in gconf
 *
 */
static DBusMessage *nmi_dbus_add_network_address (NMWirelessApplet *applet, DBusMessage *message)
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

	g_return_val_if_fail (applet != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	dbus_error_init (&error);
	if (    !dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &network, DBUS_TYPE_INT32, &type, DBUS_TYPE_STRING, &addr, DBUS_TYPE_INVALID)
		|| !nmi_network_type_valid (type)
		|| (strlen (network) <= 0)
		|| !addr
		|| (strlen (addr) < 11))
	{
		reply_message = nmwa_dbus_create_error_message (message, NMI_DBUS_INTERFACE, "InvalidArguments",
							"NetworkManagerInfo::addNetworkAddress called with invalid arguments.");
		return (reply_message);
	}

	/* Force-set the essid too so that we have a semi-complete network entry */
	escaped_network = gconf_escape_key (network, strlen (network));
	key = g_strdup_printf ("%s/%s/essid", GCONF_PATH_WIRELESS_NETWORKS, escaped_network);
	value = gconf_client_get (applet->gconf_client, key, NULL);

	/* If the network doesn't already exist in GConf, add it and set its timestamp to now. */
	if (!value || (!value && (value->type == GCONF_VALUE_STRING)))
	{
		/* Set the essid of the network. */
		gconf_client_set_string (applet->gconf_client, key, network, NULL);
		g_free (key);

		/* Update timestamp on network */
		key = g_strdup_printf ("%s/%s/timestamp", GCONF_PATH_WIRELESS_NETWORKS, escaped_network);
		gconf_client_set_int (applet->gconf_client, key, time (NULL), NULL);
	}
	g_free (key);

	/* Get current list of access point MAC addresses for this AP from GConf */
	key = g_strdup_printf ("%s/%s/addresses", GCONF_PATH_WIRELESS_NETWORKS, escaped_network);
	value = gconf_client_get (applet->gconf_client, key, NULL);
	g_free (escaped_network);

	if (value && (value->type == GCONF_VALUE_LIST) && (gconf_value_get_list_type (value) == GCONF_VALUE_STRING))
	{
		GSList	*elem;

		new_mac_list = gconf_client_get_list (applet->gconf_client, key, GCONF_VALUE_STRING, NULL);
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
		gconf_client_set_list (applet->gconf_client, key, GCONF_VALUE_STRING, new_mac_list, NULL);
	}

	/* Free the list, since gconf_client_set_list deep-copies it */
	g_slist_foreach (new_mac_list, (GFunc)g_free, NULL);
	g_slist_free (new_mac_list);

	g_free (key);

	return (NULL);
}


/*
 * nmi_dbus_info_message_handler
 *
 * Respond to requests against the NetworkManagerInfo object
 *
 */
DBusHandlerResult nmi_dbus_info_message_handler (DBusConnection *connection, DBusMessage *message, void *user_data)
{
	const char *		method;
	const char *		path;
	NMWirelessApplet *	applet = (NMWirelessApplet *)user_data;
	DBusMessage *		reply = NULL;

	g_return_val_if_fail (applet != NULL, DBUS_HANDLER_RESULT_HANDLED);

	method = dbus_message_get_member (message);
	path = dbus_message_get_path (message);

/*	nm_warning ("nmi_dbus_nmi_message_handler() got method %s for path %s", method, path); */

	if (strcmp ("getKeyForNetwork", method) == 0)
		reply = nmi_dbus_get_key_for_network (applet, message);
	else if (strcmp ("cancelGetKeyForNetwork", method) == 0)
		nmi_passphrase_dialog_schedule_cancel (applet);
#if 0  /* Not used at this time */
	else if (strcmp ("networkNotFound", method) == 0)
	{
		const char *	network;
		DBusError	 	error;

		dbus_error_init (&error);
		if (dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &network, DBUS_TYPE_INVALID))
		{
			GtkDialog	*dialog;
			char		*text;

			dbus_error_free (&error);
			text = g_strdup_printf (_("The requested wireless network '%s' does not appear to be in range.  "
								 "A different wireless network will be used if any are available."), network);

			dialog = GTK_DIALOG (gtk_message_dialog_new (NULL, 0, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, text, NULL));
			gtk_dialog_run (dialog);
			gtk_widget_destroy (GTK_WIDGET (dialog));
		}
	}
#endif
	else if (strcmp ("getWirelessScanMethod", method) == 0)
		reply = nmi_dbus_get_wireless_scan_method (applet, message);
	else if (strcmp ("getNetworks", method) == 0)
		reply = nmi_dbus_get_networks (applet, message);
	else if (strcmp ("getNetworkProperties", method) == 0)
		reply = nmi_dbus_get_network_properties (applet, message);
	else if (strcmp ("updateNetworkInfo", method) == 0)
		nmi_dbus_update_network_info (applet, message);
	else if (strcmp ("addNetworkAddress", method) == 0)
		nmi_dbus_add_network_address (applet, message);
	else if (strcmp ("getVPNConnections", method) == 0)
		reply = nmi_dbus_get_vpn_connections (applet, message);
	else if (strcmp ("getVPNConnectionProperties", method) == 0)
		reply = nmi_dbus_get_vpn_connection_properties (applet, message);
	else if (strcmp ("getVPNConnectionVPNData", method) == 0)
		reply = nmi_dbus_get_vpn_connection_vpn_data (applet, message);
	else if (strcmp ("getVPNConnectionRoutes", method) == 0)
		reply = nmi_dbus_get_vpn_connection_routes (applet, message);

	if (reply)
	{
		dbus_connection_send (connection, reply, NULL);
		dbus_message_unref (reply);
	}

	return (DBUS_HANDLER_RESULT_HANDLED);
}

