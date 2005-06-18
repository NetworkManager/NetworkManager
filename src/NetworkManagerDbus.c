/* NetworkManager -- Network link manager
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
#include <stdarg.h>
#include <iwlib.h>
#include <netinet/ether.h>

#include "NetworkManager.h"
#include "NetworkManagerUtils.h"
#include "NetworkManagerDevice.h"
#include "NetworkManagerDbus.h"
#include "NetworkManagerDbusUtils.h"
#include "NetworkManagerAP.h"
#include "NetworkManagerAPList.h"
#include "NetworkManagerPolicy.h"
#include "nm-dbus-nm.h"
#include "nm-dbus-device.h"
#include "nm-dbus-net.h"
#include "nm-dbus-dhcp.h"


/*
 * nm_dbus_create_error_message
 *
 * Make a DBus error message
 *
 */
DBusMessage *nm_dbus_create_error_message (DBusMessage *message, const char *exception_namespace,
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
 * nm_dbus_get_object_path_from_device
 *
 * Copies the object path for a device object.  Caller must free returned string.
 *
 */
static unsigned char * nm_dbus_get_object_path_from_device (NMDevice *dev)
{
	g_return_val_if_fail (dev != NULL, NULL);

	return (g_strdup_printf ("%s/%s", NM_DBUS_PATH_DEVICES, nm_device_get_iface (dev)));
}


/*
 * nm_dbus_get_device_from_object_path
 *
 * Returns the device associated with a dbus object path
 *
 */
NMDevice *nm_dbus_get_device_from_object_path (NMData *data, const char *path)
{
	NMDevice	*dev = NULL;

	g_return_val_if_fail (path != NULL, NULL);
	g_return_val_if_fail (data != NULL, NULL);

	/* FIXME
	 * This function could be much more efficient, for example we could
	 * actually _parse_ the object path, but that's a lot more code and
	 * stupid stuff.  The approach below is slower, less efficient, but
	 * less code and less error-prone.
	 */

	/* Iterate over device list */
	if (nm_try_acquire_mutex (data->dev_list_mutex, __FUNCTION__))
	{
		GSList	*elt;
		char		 compare_path[100];

		for (elt = data->dev_list; elt; elt = g_slist_next (elt))
		{
			if ((dev = (NMDevice *)(elt->data)))
			{
				snprintf (compare_path, 100, "%s/%s", NM_DBUS_PATH_DEVICES, nm_device_get_iface (dev));
				/* Compare against our constructed path, but ignore any trailing elements */
				if (strncmp (path, compare_path, strlen (compare_path)) == 0)
					break;
				dev = NULL;
			}
		}
		nm_unlock_mutex (data->dev_list_mutex, __FUNCTION__);
	}

	return (dev);
}


typedef struct NMNetNotFoundData
{
	NMData	*app_data;
	char		*net;
} NMNetNotFoundData;

/*
 * nm_dbus_send_network_not_found
 *
 * Tell the info-daemon to alert the user that a requested network was
 * not found.
 *
 */
static gboolean nm_dbus_send_network_not_found (gpointer user_data)
{
	NMNetNotFoundData	*cb_data = (NMNetNotFoundData *)user_data;
	DBusMessage		*message;

	g_return_val_if_fail (cb_data != NULL, FALSE);

	if (!cb_data->app_data || !cb_data->app_data->dbus_connection || !cb_data->net)
		goto out;

	message = dbus_message_new_method_call (NMI_DBUS_SERVICE, NMI_DBUS_PATH,
						NMI_DBUS_INTERFACE, "networkNotFound");
	if (message == NULL)
	{
		syslog (LOG_ERR, "nm_dbus_send_network_not_found(): Couldn't allocate the dbus message");
		goto out;
	}

	dbus_message_append_args (message, DBUS_TYPE_STRING, cb_data->net, DBUS_TYPE_INVALID);
	if (!dbus_connection_send (cb_data->app_data->dbus_connection, message, NULL))
		syslog (LOG_WARNING, "nm_dbus_send_network_not_found(): could not send dbus message");

	dbus_message_unref (message);

out:
	g_free (cb_data);
	return (FALSE);
}


void nm_dbus_schedule_network_not_found_signal (NMData *data, const char *network)
{
	NMNetNotFoundData	*cb_data;
	GSource			*source;

	g_return_if_fail (data != NULL);
	g_return_if_fail (network != NULL);

	cb_data = g_malloc0 (sizeof (NMNetNotFoundData));
	cb_data->app_data = data;
	cb_data->net = g_strdup (network);
	
	source = g_idle_source_new ();
	g_source_set_callback (source, nm_dbus_send_network_not_found, cb_data, NULL);
	g_source_attach (source, data->main_context);
	g_source_unref (source);
}



/*-------------------------------------------------------------*/
/* Handler code */
/*-------------------------------------------------------------*/

typedef struct NMStatusChangeData
{
	NMDevice		*dev;
	DeviceStatus	 status;
} NMStatusChangeData;


static gboolean nm_dbus_device_status_change_helper (gpointer user_data)
{
	NMStatusChangeData	*data = (NMStatusChangeData *)user_data;
	NMData			*app_data;

	g_return_val_if_fail (data != NULL, FALSE);

	if (!data->dev || !nm_device_get_app_data (data->dev))
		goto out;

	app_data = nm_device_get_app_data (data->dev);
	nm_dbus_signal_device_status_change (app_data->dbus_connection, data->dev, data->status);

out:
	g_free (data);
	return FALSE;
}

void nm_dbus_schedule_device_status_change (NMDevice *dev, DeviceStatus status)
{
	NMStatusChangeData	*data = NULL;
	GSource			*source;
	guint			 source_id = 0;
	NMData			*app_data;

	g_return_if_fail (dev != NULL);

	app_data = nm_device_get_app_data (dev);
	g_return_if_fail (app_data != NULL);
	
	data = g_malloc0 (sizeof (NMStatusChangeData));
	data->dev = dev;
	data->status = status;

	source = g_idle_source_new ();
	g_source_set_callback (source, nm_dbus_device_status_change_helper, data, NULL);
	source_id = g_source_attach (source, app_data->main_context);
	g_source_unref (source);
}


/*
 * nm_dbus_signal_device_status_change
 *
 * Notifies the bus that a particular device has had a status change, either
 * active or no longer active
 *
 */
void nm_dbus_signal_device_status_change (DBusConnection *connection, NMDevice *dev, DeviceStatus status)
{
	DBusMessage		*message;
	unsigned char		*dev_path;
	unsigned char		*signal = NULL;
	NMAccessPoint		*ap = NULL;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (dev != NULL);

	if (!(dev_path = nm_dbus_get_object_path_from_device (dev)))
		return;

	switch (status)
	{
		case (DEVICE_NO_LONGER_ACTIVE):
			signal = "DeviceNoLongerActive";
			break;
		case (DEVICE_NOW_ACTIVE):
			signal = "DeviceNowActive";
			break;
		case (DEVICE_ACTIVATING):
			signal = "DeviceActivating";
			break;
		case (DEVICE_LIST_CHANGE):
			signal = "DevicesChanged";
			break;
		case (DEVICE_STATUS_CHANGE):
			signal = "DeviceStatusChanged";
			break;
		case (DEVICE_ACTIVATION_FAILED):
			signal = "DeviceActivationFailed";
			break;
		default:
			syslog (LOG_ERR, "nm_dbus_signal_device_status_change(): got a bad signal name");
			return;
	}

	if (!(message = dbus_message_new_signal (NM_DBUS_PATH, NM_DBUS_INTERFACE, signal)))
	{
		syslog (LOG_ERR, "nm_dbus_signal_device_status_change(): Not enough memory for new dbus message!");
		g_free (dev_path);
		return;
	}

	if ((status == DEVICE_ACTIVATION_FAILED) && nm_device_is_wireless (dev))
		ap = nm_device_get_best_ap (dev);
	/* If the device was wireless, attach the name of the wireless network that failed to activate */
	if (ap && nm_ap_get_essid (ap))
		dbus_message_append_args (message, DBUS_TYPE_STRING, dev_path, DBUS_TYPE_STRING, nm_ap_get_essid (ap), DBUS_TYPE_INVALID);
	else
		dbus_message_append_args (message, DBUS_TYPE_STRING, dev_path, DBUS_TYPE_INVALID);

	if (ap)
		nm_ap_unref (ap);
	g_free (dev_path);

	if (!dbus_connection_send (connection, message, NULL))
		syslog (LOG_WARNING, "nm_dbus_signal_device_status_change(): Could not raise the signal!");

	dbus_message_unref (message);
}


/*
 * nm_dbus_network_status_from_data
 *
 * Return a network status string based on our network data
 *
 * Caller MUST free returned value
 *
 */
char *nm_dbus_network_status_from_data (NMData *data)
{
	char *status = NULL;

	g_return_val_if_fail (data != NULL, NULL);

	if (data->asleep == TRUE)
		status = g_strdup ("asleep");
	if (data->forcing_device)
		status = g_strdup ("scanning");
	else if (data->active_device && nm_device_is_activating (data->active_device))
	{
		if (nm_device_is_wireless (data->active_device) && nm_device_get_now_scanning (data->active_device))
			status = g_strdup ("scanning");
		else
			status = g_strdup ("connecting");
	}
	else if (data->active_device)
		status = g_strdup ("connected");
	else
		status = g_strdup ("disconnected");

	return (status);
}


/*
 * nm_dbus_signal_network_status_change
 *
 * Signal a change in general network status.
 *
 */
void nm_dbus_signal_network_status_change (DBusConnection *connection, NMData *data)
{
	DBusMessage	*message;
	char			*status = NULL;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (data != NULL);

	if (!(message = dbus_message_new_signal (NM_DBUS_PATH, NM_DBUS_INTERFACE, "NetworkStatusChange")))
	{
		syslog (LOG_ERR, "nm_dbus_signal_device_status_change(): Not enough memory for new dbus message!");
		return;
	}

	if ((status = nm_dbus_network_status_from_data (data)))
	{
		dbus_message_append_args (message, DBUS_TYPE_STRING, status, DBUS_TYPE_INVALID);

		if (!dbus_connection_send (connection, message, NULL))
			syslog (LOG_WARNING, "nm_dbus_signal_device_status_change(): Could not raise the signal!");
		g_free (status);
	}

	dbus_message_unref (message);
}


/*
 * nm_dbus_signal_device_ip4_address_change
 *
 * Notifies the bus that a particular device's IPv4 address changed.
 *
 */
void nm_dbus_signal_device_ip4_address_change (DBusConnection *connection, NMDevice *dev)
{
	DBusMessage		*message;
	unsigned char		*dev_path;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (dev != NULL);

	if (!(dev_path = nm_dbus_get_object_path_from_device (dev)))
		return;

	message = dbus_message_new_signal (NM_DBUS_PATH, NM_DBUS_INTERFACE, "DeviceIP4AddressChange");
	if (!message)
	{
		syslog (LOG_ERR, "nm_dbus_signal_device_ip4_address_change(): Not enough memory for new dbus message!");
		g_free (dev_path);
		return;
	}

	dbus_message_append_args (message, DBUS_TYPE_STRING, dev_path, DBUS_TYPE_INVALID);
	g_free (dev_path);

	if (!dbus_connection_send (connection, message, NULL))
		syslog (LOG_WARNING, "nm_dbus_signal_device_ip4_address_change(): Could not raise the IP4AddressChange signal!");

	dbus_message_unref (message);
}


/*
 * nm_dbus_signal_wireless_network_change
 *
 * Notifies the bus that a new wireless network has come into range
 *
 */
void nm_dbus_signal_wireless_network_change (DBusConnection *connection, NMDevice *dev, NMAccessPoint *ap, NMNetworkStatus status, gint8 strength)
{
	DBusMessage	*message;
	char			*dev_path;
	char			*ap_path;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (dev != NULL);
	g_return_if_fail (ap != NULL);

	if (!(dev_path = nm_dbus_get_object_path_from_device (dev)))
		return;

	if (!(ap_path = nm_device_get_path_for_ap (dev, ap)))
	{
		g_free (dev_path);
		return;
	}

	message = dbus_message_new_signal (NM_DBUS_PATH, NM_DBUS_INTERFACE, "WirelessNetworkUpdate");
	if (!message)
	{
		syslog (LOG_ERR, "nm_dbus_signal_wireless_network_appeared(): Not enough memory for new dbus message!");
		g_free (dev_path);
		g_free (ap_path);
		return;
	}

	dbus_message_append_args (message,
							DBUS_TYPE_STRING, dev_path,
							DBUS_TYPE_STRING, ap_path,
							DBUS_TYPE_UINT32, status,
							DBUS_TYPE_INVALID);
	g_free (ap_path);
	g_free (dev_path);

	/* Append signal-specific data */
	if (status == NETWORK_STATUS_STRENGTH_CHANGED)
		dbus_message_append_args (message, DBUS_TYPE_INT32, strength, DBUS_TYPE_INVALID);

	if (!dbus_connection_send (connection, message, NULL))
		syslog (LOG_WARNING, "nnm_dbus_signal_wireless_network_appeared(): Could not raise the WirelessNetworkAppeared signal!");

	dbus_message_unref (message);
}


/*
 * nm_dbus_get_user_key_for_network
 *
 * Asks NetworkManagerInfo for a user-entered WEP key.
 *
 */
void nm_dbus_get_user_key_for_network (DBusConnection *connection, NMDevice *dev, NMAccessPoint *ap, int attempt)
{
	DBusMessage		*message;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (dev != NULL);
	g_return_if_fail (ap != NULL);
	g_return_if_fail (nm_ap_get_essid (ap) != NULL);
	g_return_if_fail (attempt > 0);

	message = dbus_message_new_method_call (NMI_DBUS_SERVICE, NMI_DBUS_PATH,
						NMI_DBUS_INTERFACE, "getKeyForNetwork");
	if (message == NULL)
	{
		syslog (LOG_ERR, "nm_dbus_get_user_key_for_network(): Couldn't allocate the dbus message");
		return;
	}

	dbus_message_append_args (message, DBUS_TYPE_STRING, nm_device_get_iface (dev),
								DBUS_TYPE_STRING, nm_ap_get_essid (ap),
								DBUS_TYPE_INT32, attempt,
								DBUS_TYPE_INVALID);

	if (!dbus_connection_send (connection, message, NULL))
		syslog (LOG_WARNING, "nm_dbus_get_user_key_for_network(): could not send dbus message");

	dbus_message_unref (message);
}


/*
 * nm_dbus_cancel_get_user_key_for_network
 *
 * Sends a user-key cancellation message to NetworkManagerInfo
 *
 */
void nm_dbus_cancel_get_user_key_for_network (DBusConnection *connection)
{
	DBusMessage		*message;

	g_return_if_fail (connection != NULL);

	message = dbus_message_new_method_call (NMI_DBUS_SERVICE, NMI_DBUS_PATH,
						NMI_DBUS_INTERFACE, "cancelGetKeyForNetwork");
	if (message == NULL)
	{
		syslog (LOG_ERR, "nm_dbus_cancel_get_user_key_for_network(): Couldn't allocate the dbus message");
		return;
	}

	if (!dbus_connection_send (connection, message, NULL))
		syslog (LOG_WARNING, "nm_dbus_cancel_get_user_key_for_network(): could not send dbus message");

	dbus_message_unref (message);
}


/*
 * nm_dbus_get_network_properties
 *
 * Get a wireless network from NetworkManagerInfo
 *
 */
NMAccessPoint *nm_dbus_get_network_object (DBusConnection *connection, NMNetworkType type, const char *network)
{
	DBusMessage		*message;
	DBusError			 error;
	DBusMessage		*reply;
	gboolean			 success = FALSE;
	NMAccessPoint		*ap = NULL;

	char				*essid = NULL;
	gint				 timestamp_secs = -1;
	char				*key = NULL;
	NMEncKeyType		 key_type = -1;
	gboolean			 trusted = FALSE;
	NMDeviceAuthMethod	 auth_method = NM_DEVICE_AUTH_METHOD_UNKNOWN;
	char				**addrs = NULL;
	gint				 num_addr = -1;
	
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (network != NULL, NULL);
	g_return_val_if_fail (type != NETWORK_TYPE_UNKNOWN, NULL);

	if (!(message = dbus_message_new_method_call (NMI_DBUS_SERVICE, NMI_DBUS_PATH, NMI_DBUS_INTERFACE, "getNetworkProperties")))
	{
		syslog (LOG_ERR, "nm_dbus_get_network_object(): Couldn't allocate the dbus message");
		return (NULL);
	}

	dbus_message_append_args (message, DBUS_TYPE_STRING, network,
								DBUS_TYPE_INT32, (int)type,
								DBUS_TYPE_INVALID);

	/* Send message and get properties back from NetworkManagerInfo */
	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (connection, message, -1, &error);
	dbus_message_unref (message);

	if (dbus_error_is_set (&error))
	{
		syslog (LOG_ERR, "nm_dbus_get_network_object(): %s raised '%s'", error.name, error.message);
		goto out;
	}

	if (!reply)
	{
		syslog (LOG_NOTICE, "nm_dbus_get_network_object(): reply was NULL.");
		goto out;
	}

	dbus_error_init (&error);
	success = dbus_message_get_args (reply, &error,
								DBUS_TYPE_STRING, &essid,
								DBUS_TYPE_INT32, &timestamp_secs,
								DBUS_TYPE_STRING, &key,
								DBUS_TYPE_INT32, &key_type,
								DBUS_TYPE_INT32, &auth_method,
								DBUS_TYPE_BOOLEAN, &trusted,
								DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &addrs, &num_addr,
								DBUS_TYPE_INVALID);
	if (success)
	{
		if (timestamp_secs > 0)
		{
			GTimeVal	*timestamp = g_new0 (GTimeVal, 1);

			ap = nm_ap_new ();
			nm_ap_set_essid (ap, essid);

			timestamp->tv_sec = timestamp_secs;
			timestamp->tv_usec = 0;
			nm_ap_set_timestamp (ap, timestamp);
			g_free (timestamp);

			nm_ap_set_trusted (ap, trusted);

			if (key && strlen (key))
				nm_ap_set_enc_key_source (ap, key, key_type);
			else
				nm_ap_set_enc_key_source (ap, NULL, NM_ENC_TYPE_UNKNOWN);
			nm_ap_set_auth_method (ap, auth_method);

			/* Get user addresses, form into a GSList, and stuff into the AP */
			{
				GSList	*addr_list = NULL;
				int		 i;

				if (!addrs)
					num_addr = 0;

				for (i = 0; i < num_addr; i++)
				{
					if (addrs[i] && (strlen (addrs[i]) >= 11))
						addr_list = g_slist_append (addr_list, g_strdup (addrs[i]));
				}
				nm_ap_set_user_addresses (ap, addr_list);
				g_slist_foreach (addr_list, (GFunc)g_free, NULL);
				g_slist_free (addr_list);
			}
		}
		dbus_free_string_array (addrs);
		g_free (essid);
		g_free (key);
	}
	else
		syslog (LOG_ERR, "nm_dbus_get_network_object(): bad data, %s raised %s", error.name, error.message);

out:
	if (reply)
		dbus_message_unref (reply);

	return (ap);
}


/*
 * nm_dbus_update_wireless_scan_method
 *
 * Get the wireless scan method from NetworkManagerInfo
 *
 */
void nm_dbus_update_wireless_scan_method (DBusConnection *connection, NMData *data)
{
	DBusMessage *		message = NULL;
	DBusMessage *		reply = NULL;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (data != NULL);

	if (!(message = dbus_message_new_method_call (NMI_DBUS_SERVICE, NMI_DBUS_PATH, NMI_DBUS_INTERFACE, "getWirelessScanMethod")))
	{
		syslog (LOG_WARNING, "nm_dbus_update_wireless_scan_method(): Couldn't allocate the dbus message");
		return;
	}

	if ((reply = dbus_connection_send_with_reply_and_block (connection, message, -1, NULL)))
	{
		NMWirelessScanMethod	method;

		if (dbus_message_get_args (reply, NULL, DBUS_TYPE_UINT32, &method, DBUS_TYPE_INVALID))
		{
			if ((method == NM_SCAN_METHOD_ALWAYS) || (method == NM_SCAN_METHOD_NEVER) || (method == NM_SCAN_METHOD_WHEN_UNASSOCIATED))
				data->scanning_method = method;
		}
		dbus_message_unref (reply);
	}
	else
		syslog (LOG_WARNING, "nm_dbus_update_wireless_scan_method(): could not send dbus message");

	dbus_message_unref (message);
}


/*
 * nm_dbus_update_network_auth_method
 *
 * Tell NetworkManagerInfo the updated auth_method of the AP
 *
 */
gboolean nm_dbus_update_network_auth_method (DBusConnection *connection, const char *network, const NMDeviceAuthMethod auth_method)
{
	DBusMessage		*message;
	DBusError			 error;
	gboolean			 success = FALSE;

	g_return_val_if_fail (connection != NULL, FALSE);
	g_return_val_if_fail (network != NULL, FALSE);
	g_return_val_if_fail (auth_method != NM_DEVICE_AUTH_METHOD_UNKNOWN, FALSE);

	message = dbus_message_new_method_call (NMI_DBUS_SERVICE, NMI_DBUS_PATH, NMI_DBUS_INTERFACE, "updateNetworkAuthMethod");
	if (!message)
	{
		syslog (LOG_ERR, "nm_dbus_update_network_auth_method (): Couldn't allocate the dbus message");
		return (FALSE);
	}

	dbus_message_append_args (message, DBUS_TYPE_STRING, network,
								DBUS_TYPE_INT32, (int)auth_method,
								DBUS_TYPE_INVALID);

	/* Send message and get trusted status back from NetworkManagerInfo */
	dbus_error_init (&error);
	if (!dbus_connection_send (connection, message, NULL))
	{
		syslog (LOG_ERR, "nm_dbus_update_network_auth_method (): failed to send dbus message.");
		dbus_error_free (&error);
	}
	else
		success = TRUE;

	dbus_message_unref (message);
	return (success);
}


/*
 * nm_dbus_add_network_address
 *
 * Tell NetworkManagerInfo the MAC address of an AP
 *
 * Returns:	FALSE on error
 *			TRUE on success
 *
 */
gboolean nm_dbus_add_network_address (DBusConnection *connection, NMNetworkType type, const char *network, struct ether_addr *addr)
{
	DBusMessage		*message;
	DBusError			 error;
	gboolean			 success = FALSE;
	char				 char_addr[20];

	g_return_val_if_fail (connection != NULL, FALSE);
	g_return_val_if_fail (network != NULL, FALSE);
	g_return_val_if_fail (type != NETWORK_TYPE_UNKNOWN, FALSE);
	g_return_val_if_fail (addr != NULL, FALSE);

	message = dbus_message_new_method_call (NMI_DBUS_SERVICE, NMI_DBUS_PATH,
						NMI_DBUS_INTERFACE, "addNetworkAddress");
	if (!message)
	{
		syslog (LOG_ERR, "nm_dbus_add_network_ap_mac_address(): Couldn't allocate the dbus message");
		return (FALSE);
	}

	memset (char_addr, 0, 20);
	ether_ntoa_r (addr, &char_addr[0]);

	dbus_message_append_args (message, DBUS_TYPE_STRING, network,
								DBUS_TYPE_INT32, (int)type,
								DBUS_TYPE_STRING, &char_addr,
								DBUS_TYPE_INVALID);

	/* Send message and get trusted status back from NetworkManagerInfo */
	dbus_error_init (&error);
	if (!dbus_connection_send (connection, message, NULL))
	{
		syslog (LOG_ERR, "nm_dbus_add_network_ap_mac_address(): failed to send dbus message.");
		dbus_error_free (&error);
	}
	else
		success = TRUE;

	dbus_message_unref (message);
	return (success);
}


/*
 * nm_dbus_get_networks
 *
 * Get all networks of a specific type from NetworkManagerInfo
 *
 * NOTE: caller MUST free returned value using dbus_free_string_array()
 *
 */
char ** nm_dbus_get_networks (DBusConnection *connection, NMNetworkType type, int *num_networks)
{
	DBusMessage		*message;
	DBusError			 error;
	DBusMessage		*reply;
	char			    **networks = NULL;

	*num_networks = 0;
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (type != NETWORK_TYPE_UNKNOWN, NULL);

	message = dbus_message_new_method_call (NMI_DBUS_SERVICE, NMI_DBUS_PATH,
						NMI_DBUS_INTERFACE, "getNetworks");
	if (!message)
	{
		syslog (LOG_ERR, "nm_dbus_get_networks(): Couldn't allocate the dbus message");
		return (NULL);
	}

	dbus_message_append_args (message, DBUS_TYPE_INT32, (int)type, DBUS_TYPE_INVALID);

	/* Send message and get essid back from NetworkManagerInfo */
	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (connection, message, -1, &error);
	dbus_message_unref (message);
	if (dbus_error_is_set (&error))
		syslog (LOG_ERR, "nm_dbus_get_networks(): %s raised %s", error.name, error.message);
	else if (!reply)
		syslog (LOG_NOTICE, "nm_dbus_get_networks(): reply was NULL.");
	else
	{
		dbus_error_init (&error);
		dbus_message_get_args (reply, &error, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
								&networks, num_networks, DBUS_TYPE_INVALID);
		if (dbus_error_is_set (&error))
			dbus_error_free (&error);
	}

	if (reply)
		dbus_message_unref (reply);

	return (networks);
}


/*
 * nm_dbus_nmi_is_running
 *
 * Ask dbus whether or not NetworkManagerInfo is running
 *
 */
gboolean nm_dbus_nmi_is_running (DBusConnection *connection)
{
	DBusError		error;
	gboolean		exists;

	g_return_val_if_fail (connection != NULL, FALSE);

	dbus_error_init (&error);
	exists = dbus_bus_service_exists (connection, NMI_DBUS_SERVICE, &error);
	if (dbus_error_is_set (&error))
		dbus_error_free (&error);
	return (exists);
}


/*
 * nm_dbus_nmi_filter
 *
 * Respond to NetworkManagerInfo signals about changing Allowed Networks
 *
 */
static DBusHandlerResult nm_dbus_nmi_filter (DBusConnection *connection, DBusMessage *message, void *user_data)
{
	NMData		*data = (NMData *)user_data;
	const char	*object_path;
	const char	*method;
	gboolean		 handled = FALSE;
	DBusError		 error;

	g_return_val_if_fail (data != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (connection != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (message != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	method = dbus_message_get_member (message);
	if (!(object_path = dbus_message_get_path (message)))
		return (DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	/* syslog (LOG_DEBUG, "nm_dbus_nmi_filter() got method %s for path %s", method, object_path); */

	dbus_error_init (&error);

	if (strcmp (object_path, NMI_DBUS_PATH) == 0)
	{
		if (dbus_message_is_signal (message, NMI_DBUS_INTERFACE, "WirelessNetworkUpdate"))
		{
			char *	network = NULL;

			if (dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &network, DBUS_TYPE_INVALID))
			{
				/* Update a single wireless network's data */
				syslog (LOG_DEBUG, "NetworkManagerInfo triggered update of wireless network '%s'", network);
				nm_ap_list_update_network_from_nmi (data->allowed_ap_list, network, data);
				dbus_free (network);
				handled = TRUE;
			}
		}
		else if (dbus_message_is_signal (message, NMI_DBUS_INTERFACE, "WirelessScanMethodUpdate"))
			nm_dbus_update_wireless_scan_method (connection, data);
	}
#if (DBUS_VERSION_MAJOR == 0 && DBUS_VERSION_MINOR == 22)
	else if (dbus_message_is_signal (message, DBUS_INTERFACE_ORG_FREEDESKTOP_DBUS, "ServiceCreated"))
	{
		/* Only for dbus <= 0.22 */
		char 	*service;

		if (    dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &service, DBUS_TYPE_INVALID)
			&& (strcmp (service, NMI_DBUS_SERVICE) == 0))
		{
			nm_policy_schedule_allowed_ap_list_update (data);
		}
	}
#elif (DBUS_VERSION_MAJOR == 0 && DBUS_VERSION_MINOR == 23)
	else if (dbus_message_is_signal (message, DBUS_INTERFACE_ORG_FREEDESKTOP_DBUS, "ServiceOwnerChanged"))
	{
		/* New signal for dbus 0.23... */
		char 	*service;
		char		*old_owner;
		char		*new_owner;

		if (    dbus_message_get_args (message, &error,
									DBUS_TYPE_STRING, &service,
									DBUS_TYPE_STRING, &old_owner,
									DBUS_TYPE_STRING, &new_owner,
									DBUS_TYPE_INVALID)
			&& (strcmp (service, NMI_DBUS_SERVICE) == 0))
		{
			gboolean old_owner_good = (old_owner && (strlen (old_owner) > 0));
			gboolean new_owner_good = (new_owner && (strlen (new_owner) > 0));

			/* Service didn't used to have an owner, now it does.  Equivalent to
			 * "ServiceCreated" signal in dbus <= 0.22
			 */
			if (!old_owner_good && new_owner_good)
			{
				nm_policy_schedule_allowed_ap_list_update (data);
				nm_dbus_update_wireless_scan_method (connection, data);
			}
		}
	}
#else
#error "Unrecognized version of DBUS."
#endif

	if (dbus_error_is_set (&error))
		dbus_error_free (&error);

	return (handled ? DBUS_HANDLER_RESULT_HANDLED : DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
}


/*
 * nm_dbus_nm_message_handler
 *
 * Dispatch messages against our NetworkManager object
 *
 */
static DBusHandlerResult nm_dbus_nm_message_handler (DBusConnection *connection, DBusMessage *message, void *user_data)
{
	NMData			*data = (NMData *)user_data;
	gboolean			 handled = TRUE;
	DBusMessage		*reply = NULL;
	NMDbusCBData		 cb_data;

	g_return_val_if_fail (data != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (data->nm_methods != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (connection != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (message != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	cb_data.data = data;
	cb_data.dev = NULL;
	handled = nm_dbus_method_dispatch (data->nm_methods, connection, message, &cb_data, &reply);
	if (reply)
	{
		dbus_connection_send (connection, reply, NULL);
		dbus_message_unref (reply);
	}

	return (handled ? DBUS_HANDLER_RESULT_HANDLED : DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
}


/*
 * nm_dbus_devices_message_handler
 *
 * Dispatch messages against individual network devices
 *
 */
static DBusHandlerResult nm_dbus_devices_message_handler (DBusConnection *connection, DBusMessage *message, void *user_data)
{
	NMData			*data = (NMData *)user_data;
	gboolean			 handled = FALSE;
	const char		*path;
	DBusMessage		*reply = NULL;
	NMDevice			*dev;

	g_return_val_if_fail (data != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (connection != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (message != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	path = dbus_message_get_path (message);

	if (!(dev = nm_dbus_get_device_from_object_path (data, path)))
	{
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "DeviceNotFound",
						"The requested network device does not exist.");
	}
	else
	{
		char			*object_path;
		NMDbusCBData	 cb_data;

		cb_data.data = data;
		cb_data.dev = dev;

		/* Test whether or not the _networks_ of a device were queried instead of the device itself */
		object_path = g_strdup_printf ("%s/%s/Networks/", NM_DBUS_PATH_DEVICES, nm_device_get_iface (dev));
		if (strncmp (path, object_path, strlen (object_path)) == 0)
			handled = nm_dbus_method_dispatch (data->net_methods, connection, message, &cb_data, &reply);
		else
			handled = nm_dbus_method_dispatch (data->device_methods, connection, message, &cb_data, &reply);
	}

	if (reply)
	{
		dbus_connection_send (connection, reply, NULL);
		dbus_message_unref (reply);
		handled = TRUE;
	}

	return (handled ? DBUS_HANDLER_RESULT_HANDLED : DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
}


/*
 * nm_dbus_dhcp_message_handler
 *
 * Dispatch messages against our NetworkManager DHCP object
 *
 * All calls are in the form /NM_DBUS_PATH_DHCP->METHOD (STRING attribute)
 * For example, /org/freedesktop/NetworkManager/DhcpOptions->getType ("Name Server")
 *
 */
static DBusHandlerResult nm_dbus_dhcp_message_handler (DBusConnection *connection, DBusMessage *message, void *user_data)
{
	NMData			*data = (NMData *)user_data;
	gboolean			 handled = TRUE;
	DBusMessage		*reply = NULL;
	NMDbusCBData		 cb_data;

	g_return_val_if_fail (data != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (data->dhcp_methods != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (connection != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (message != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	cb_data.data = data;
	cb_data.dev = NULL;
	cb_data.opt_id = -1;
	handled = nm_dbus_method_dispatch (data->dhcp_methods, connection, message, &cb_data, &reply);
	if (reply)
	{
		dbus_connection_send (connection, reply, NULL);
		dbus_message_unref (reply);
	}

	return (handled ? DBUS_HANDLER_RESULT_HANDLED : DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
}


/*
 * nm_dbus_is_info_daemon_running
 *
 * Ask dbus whether or not the info daemon is providing its dbus service
 *
 */
gboolean nm_dbus_is_info_daemon_running (DBusConnection *connection)
{
	DBusError		error;
	gboolean		running = FALSE;

	g_return_val_if_fail (connection != NULL, FALSE);

	dbus_error_init (&error);
	running = dbus_bus_service_exists (connection, NMI_DBUS_SERVICE, &error);
	if (dbus_error_is_set (&error))
		dbus_error_free (&error);
	return (running);
}


/*
 * nm_dbus_init
 *
 * Connect to the system messagebus and register ourselves as a service.
 *
 */
DBusConnection *nm_dbus_init (NMData *data)
{
	DBusError		 		 error;
	DBusConnection			*connection;
	DBusObjectPathVTable	 nm_vtable = {NULL, &nm_dbus_nm_message_handler, NULL, NULL, NULL, NULL};
	DBusObjectPathVTable	 devices_vtable = {NULL, &nm_dbus_devices_message_handler, NULL, NULL, NULL, NULL};
	DBusObjectPathVTable	 dhcp_vtable = {NULL, &nm_dbus_dhcp_message_handler, NULL, NULL, NULL, NULL};

	dbus_connection_set_change_sigpipe (TRUE);

	dbus_error_init (&error);
	connection = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
	if ((connection == NULL) || dbus_error_is_set (&error))
	{
		syslog (LOG_ERR, "nm_dbus_init() could not get the system bus.  Make sure the message bus daemon is running?");
		connection = NULL;
		goto out;
	}

	dbus_connection_set_exit_on_disconnect (connection, FALSE);
	dbus_connection_setup_with_g_main (connection, data->main_context);

	data->nm_methods = nm_dbus_nm_methods_setup ();
	data->device_methods = nm_dbus_device_methods_setup ();
	data->net_methods = nm_dbus_net_methods_setup ();
	data->dhcp_methods = nm_dbus_dhcp_methods_setup ();

	if (    !dbus_connection_register_object_path (connection, NM_DBUS_PATH, &nm_vtable, data)
		|| !dbus_connection_register_fallback (connection, NM_DBUS_PATH_DEVICES, &devices_vtable, data)
		|| !dbus_connection_register_object_path (connection, NM_DBUS_PATH_DHCP, &dhcp_vtable, data))
	{
		syslog (LOG_CRIT, "nm_dbus_init() could not register D-BUS handlers.  Cannot continue.");
		connection = NULL;
		goto out;
	}

	if (!dbus_connection_add_filter (connection, nm_dbus_nmi_filter, data, NULL))
	{
		syslog (LOG_CRIT, "nm_dbus_init() could not attach a dbus message filter.  The NetworkManager dbus security policy may not be loaded.  Restart dbus?");
		connection = NULL;
		goto out;
	}

	dbus_bus_add_match (connection,
				"type='signal',"
				"interface='" NMI_DBUS_INTERFACE "',"
				"sender='" NMI_DBUS_SERVICE "',"
				"path='" NMI_DBUS_PATH "'",
				NULL);

	dbus_bus_add_match(connection,
				"type='signal',"
				"interface='" DBUS_INTERFACE_ORG_FREEDESKTOP_DBUS "',"
				"sender='" DBUS_SERVICE_ORG_FREEDESKTOP_DBUS "'",
				NULL);

	dbus_error_init (&error);
	dbus_bus_acquire_service (connection, NM_DBUS_SERVICE, 0, &error);
	if (dbus_error_is_set (&error))
	{
		syslog (LOG_ERR, "nm_dbus_init() could not acquire its service.  dbus_bus_acquire_service() says: '%s'", error.message);
		connection = NULL;
		goto out;
	}

out:
	if (dbus_error_is_set (&error))
		dbus_error_free (&error);

	return (connection);
}
