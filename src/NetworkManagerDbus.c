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
#include <dbus/dbus-glib.h>
#include <stdarg.h>
#include <iwlib.h>

extern gboolean debug;

#include "NetworkManager.h"
#include "NetworkManagerUtils.h"
#include "NetworkManagerDevice.h"
#include "NetworkManagerDbus.h"
#include "NetworkManagerAP.h"


/*
 * nm_dbus_create_error_message
 *
 * Make a DBus error message
 *
 */
static DBusMessage *nm_dbus_create_error_message (DBusMessage *message, const char *exception_namespace,
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
 * nm_dbus_get_object_path_from_device
 *
 * Copies the object path for a device object into a provided buffer
 *
 */
void nm_dbus_get_object_path_from_device (NMDevice *dev, unsigned char *buf, unsigned int buf_len)
{
	g_return_if_fail (buf != NULL);
	g_return_if_fail (buf_len > 0);
	memset (buf, 0, buf_len);

	g_return_if_fail (dev != NULL);

	snprintf (buf, buf_len-1, "%s/%s", NM_DBUS_DEVICES_OBJECT_PATH_PREFIX, nm_device_get_iface (dev));
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
		GSList	*element = data->dev_list;
		char		 compare_path[100];

		while (element)
		{
			if ((dev = (NMDevice *)(element->data)))
			{
				snprintf (compare_path, 100, "%s/%s", NM_DBUS_DEVICES_OBJECT_PATH_PREFIX, nm_device_get_iface (dev));
				/* Compare against our constructed path, but ignore any trailing elements */
				if (strncmp (path, compare_path, strlen (compare_path)) == 0)
					break;
				dev = NULL;
			}
			element = g_slist_next (element);
		}
		nm_unlock_mutex (data->dev_list_mutex, __FUNCTION__);
	}

	return (dev);
}


/*
 * nm_dbus_get_network_from_object_path
 *
 * Returns the network (ap) associated with a dbus object path
 *
 */
NMAccessPoint *nm_dbus_get_network_from_object_path (const char *path, NMDevice *dev)
{
	NMAccessPoint	*ap = NULL;
	int			 i = 0;
	char			 compare_path[100];

	g_return_val_if_fail (path != NULL, NULL);
	g_return_val_if_fail (dev != NULL, NULL);

	while ((ap = nm_device_ap_list_get_ap_by_index (dev, i)) != NULL)
	{
		snprintf (compare_path, 100, "%s/%s/Networks/%s", NM_DBUS_DEVICES_OBJECT_PATH_PREFIX,
				nm_device_get_iface (dev), nm_ap_get_essid (ap));
		if (strncmp (path, compare_path, strlen (compare_path)) == 0)
			break;
		ap = NULL;
		i++;
	}

	return (ap);
}


/*
 * nm_dbus_nm_get_active_device
 *
 * Returns the object path of the currently active device
 *
 */
static DBusMessage *nm_dbus_nm_get_active_device (DBusConnection *connection, DBusMessage *message, NMData *data)
{
	DBusMessage		*reply_message = NULL;
	DBusMessageIter	 iter;

	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	reply_message = dbus_message_new_method_return (message);
	if (!reply_message)
		return (NULL);

	dbus_message_iter_init (reply_message, &iter);

	/* Construct object path of "active" device and return it */
	if (data->active_device)
	{
		char *object_path = g_strdup_printf ("%s/%s", NM_DBUS_DEVICES_OBJECT_PATH_PREFIX, nm_device_get_iface (data->active_device));
		dbus_message_iter_append_string (&iter, object_path);
		g_free (object_path);
	}
	else
		dbus_message_iter_append_string (&iter, "");

	return (reply_message);
}


/*
 * nm_dbus_nm_get_devices
 *
 * Returns a string array of object paths corresponding to the
 * devices in the device list.
 *
 */
static DBusMessage *nm_dbus_nm_get_devices (DBusConnection *connection, DBusMessage *message, NMData *data)
{
	DBusMessage		*reply_message = NULL;
	DBusMessageIter	 iter;
	DBusMessageIter	 iter_array;

	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	reply_message = dbus_message_new_method_return (message);
	if (!reply_message)
		return (NULL);

	dbus_message_iter_init (reply_message, &iter);
	dbus_message_iter_append_array (&iter, &iter_array, DBUS_TYPE_STRING);

	/* Check for no devices */
	if (!data->dev_list)
	{
		dbus_message_iter_append_string (&iter_array, "");
		goto end;
	}

	/* Iterate over device list and grab index of "active device" */
	if (nm_try_acquire_mutex (data->dev_list_mutex, __FUNCTION__))
	{
		GSList	*element = data->dev_list;
		gboolean	 appended = FALSE;

		while (element)
		{
			NMDevice	*dev = (NMDevice *)(element->data);

			if (dev)
			{
				char *object_path = g_strdup_printf ("%s/%s", NM_DBUS_DEVICES_OBJECT_PATH_PREFIX, nm_device_get_iface (dev));
				dbus_message_iter_append_string (&iter_array, object_path);
				g_free (object_path);
				appended = TRUE;
			}
			element = g_slist_next (element);
		}

		/* If by some chance there is a device list, but it has no devices in it
		 * (something which should never happen), append an empty string like
		 * there are no devices in the list.
		 */
		if (!appended)
			dbus_message_iter_append_string (&iter_array, "");

		nm_unlock_mutex (data->dev_list_mutex, __FUNCTION__);
	}
	else
	{
		reply_message = nm_dbus_create_error_message (message, NM_DBUS_NM_NAMESPACE, "Retry",
						"NetworkManager could not lock device list, try again.");
	}

	end:
		return (reply_message);
}


/*-------------------------------------------------------------*/
/* Handler code */
/*-------------------------------------------------------------*/


/*
 * nm_dbus_signal_device_no_longer_active
 *
 * Notifies the bus that a particular device is no longer active.
 *
 */
void nm_dbus_signal_device_no_longer_active (DBusConnection *connection, NMDevice *dev)
{
	DBusMessage		*message;
	unsigned char		*object_path = g_new0 (unsigned char, 100);

	g_return_if_fail (connection != NULL);
	g_return_if_fail (dev != NULL);
	g_return_if_fail (object_path != NULL);

	message = dbus_message_new_signal (NM_DBUS_NM_OBJECT_PATH_PREFIX, NM_DBUS_NM_NAMESPACE, "DeviceNoLongerActive");
	if (!message)
	{
		NM_DEBUG_PRINT ("nm_dbus_signal_device_no_longer_active(): Not enough memory for new dbus message!\n");
		return;
	}

	nm_dbus_get_object_path_from_device (dev, object_path, 100);
	dbus_message_append_args (message, DBUS_TYPE_STRING, object_path, DBUS_TYPE_INVALID);
	g_free (object_path);

	if (!dbus_connection_send (connection, message, NULL))
		NM_DEBUG_PRINT ("nm_dbus_signal_device_no_longer_active(): Could not raise the DeviceNoLongerActive signal!\n");

	dbus_message_unref (message);
}


/*
 * nm_dbus_signal_device_now_active
 *
 * Notifies the bus that a particular device is newly active.
 *
 */
void nm_dbus_signal_device_now_active (DBusConnection *connection, NMDevice *dev)
{
	DBusMessage		*message;
	unsigned char		*object_path = g_new0 (unsigned char, 100);

	g_return_if_fail (connection != NULL);
	g_return_if_fail (dev != NULL);

	message = dbus_message_new_signal (NM_DBUS_NM_OBJECT_PATH_PREFIX, NM_DBUS_NM_NAMESPACE, "DeviceNowActive");
	if (!message)
	{
		NM_DEBUG_PRINT ("nm_dbus_signal_device_now_active(): Not enough memory for new dbus message!\n");
		return;
	}

	nm_dbus_get_object_path_from_device (dev, object_path, 100);
	dbus_message_append_args (message, DBUS_TYPE_STRING, object_path, DBUS_TYPE_INVALID);
	g_free (object_path);

	if (!dbus_connection_send (connection, message, NULL))
		NM_DEBUG_PRINT ("nm_dbus_signal_device_now_active(): Could not raise the DeviceNowActive signal!\n");

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
	unsigned char		*object_path = g_new0 (unsigned char, 100);

	g_return_if_fail (connection != NULL);
	g_return_if_fail (dev != NULL);

	message = dbus_message_new_signal (NM_DBUS_NM_OBJECT_PATH_PREFIX, NM_DBUS_NM_NAMESPACE, "DeviceIP4AddressChange");
	if (!message)
	{
		NM_DEBUG_PRINT ("nm_dbus_signal_device_ip4_address_change(): Not enough memory for new dbus message!\n");
		return;
	}

	nm_dbus_get_object_path_from_device (dev, object_path, 100);
	dbus_message_append_args (message, DBUS_TYPE_STRING, object_path, DBUS_TYPE_INVALID);
	g_free (object_path);

	if (!dbus_connection_send (connection, message, NULL))
		NM_DEBUG_PRINT ("nm_dbus_signal_device_ip4_address_change(): Could not raise the IP4AddressChange signal!\n");

	dbus_message_unref (message);
}

#if 0
/*
 * nm_dbus_get_user_key_for_network_callback
 *
 * Called from the DBus Pending Call upon receipt of a reply
 * message from NetworkManagerInfo.
 *
 */
void nm_dbus_get_user_key_for_network_callback (DBusPendingCall *pending, void *user_data)
{
	char				*key = NULL;
	DBusMessage		*reply;
	DBusMessageIter	 iter;
	NMDevice			*dev = (NMDevice *)user_data;

	g_return_if_fail (dev != NULL);

	reply = dbus_pending_call_get_reply (pending);
	if (reply && !dbus_message_is_error (reply, DBUS_ERROR_NO_REPLY))
	{
		dbus_message_iter_init (reply, &iter);
		key = dbus_message_iter_get_string (&iter);
		nm_device_pending_action_set_user_key (dev, key);
		fprintf (stderr, "dbus user key callback got key '%s'\n", key );
		dbus_free (key);
		dbus_pending_call_unref (pending);
	}
}


/*
 * nm_dbus_get_user_key_for_network_data_free
 *
 * Frees data used during the user key pending action
 *
 */
void nm_dbus_get_user_key_for_network_data_free (void *user_data)
{
	g_return_if_fail (user_data != NULL);

	nm_device_unref ((NMDevice *)user_data);
}
#endif

/*
 * nm_dbus_get_user_key_for_network
 *
 * Asks NetworkManagerInfo for a user-entered WEP key.
 *
 */
void nm_dbus_get_user_key_for_network (DBusConnection *connection, NMDevice *dev, NMAccessPoint *ap,
								DBusPendingCall **pending)
{
	DBusMessage		*message;
	DBusMessageIter	 iter;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (dev != NULL);
	g_return_if_fail (ap != NULL);
	g_return_if_fail (nm_ap_get_essid (ap) != NULL);

	message = dbus_message_new_method_call ("org.freedesktop.NetworkManagerInfo",
						"/org/freedesktop/NetworkManagerInfo",
						"org.freedesktop.NetworkManagerInfo",
						"getKeyForNetwork");
	if (message == NULL)
	{
		NM_DEBUG_PRINT ("nm_dbus_get_user_key_for_network(): Couldn't allocate the dbus message\n");
		return;
	}

	dbus_message_iter_init (message, &iter);
	dbus_message_iter_append_string (&iter, nm_device_get_iface (dev));
	dbus_message_iter_append_string (&iter, nm_ap_get_essid (ap));


	if (!dbus_connection_send (connection, message, NULL))
		NM_DEBUG_PRINT ("nm_dbus_get_user_key_for_network(): could not send dbus message\n");

	/* For asynchronous replies, disabled for now */
#if 0
	if (!dbus_connection_send_with_reply (connection, message, pending, -1))
	{
		fprintf (stderr, "%s raised:\n %s\n\n", error.name, error.message);
		dbus_message_unref (message);
		return;
	}

	nm_device_ref (dev);
	dbus_pending_call_ref (*pending);
	dbus_pending_call_set_notify (*pending, &nm_dbus_get_user_key_for_network_callback,
							(void *)dev, &nm_dbus_get_user_key_for_network_data_free);
#endif

	dbus_message_unref (message);
}


/*
 * nm_dbus_set_user_key_for_network
 *
 * In response to a NetworkManagerInfo message, sets the WEP key
 * for a particular wireless AP/network
 *
 */
static void nm_dbus_set_user_key_for_network (DBusConnection *connection, DBusMessage *message, NMData *data)
{
	DBusMessageIter	 iter;
	char				*device;
	char				*network;
	char				*passphrase;
	char				*dbus_string;

	g_return_if_fail (data != NULL);
	g_return_if_fail (connection != NULL);
	g_return_if_fail (message != NULL);

	dbus_message_iter_init (message, &iter);

	/* Grab device */
	dbus_string = dbus_message_iter_get_string (&iter);
	device = (dbus_string == NULL ? NULL : strdup (dbus_string));		
	dbus_free (dbus_string);

	/* Grab network */
	dbus_string = dbus_message_iter_get_string (&iter);
	network = (dbus_string == NULL ? NULL : strdup (dbus_string));		
	dbus_free (dbus_string);

	/* Grab passphrase */
	dbus_string = dbus_message_iter_get_string (&iter);
	passphrase = (dbus_string == NULL ? NULL : strdup (dbus_string));		
	dbus_free (dbus_string);

	if (device && network && passphrase)
	{
		NMDevice		*dev;
		if ((dev = nm_get_device_by_iface (data, device)))
			nm_device_pending_action_set_user_key (dev, passphrase);
	}

	g_free (device);
	g_free (network);
	g_free (passphrase);
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

	message = dbus_message_new_method_call ("org.freedesktop.NetworkManagerInfo",
						"/org/freedesktop/NetworkManagerInfo",
						"org.freedesktop.NetworkManagerInfo",
						"cancelGetKeyForNetwork");
	if (message == NULL)
	{
		NM_DEBUG_PRINT ("nm_dbus_cancel_get_user_key_for_network(): Couldn't allocate the dbus message\n");
		return;
	}

	if (!dbus_connection_send (connection, message, NULL))
		NM_DEBUG_PRINT ("nm_dbus_cancel_get_user_key_for_network(): could not send dbus message\n");

	dbus_message_unref (message);
}


/*
 * nm_dbus_nmi_filter
 *
 * Respond to NetworkManagerInfo signals about changing Allowed Networks
 *
 */
static DBusHandlerResult nm_dbus_nmi_filter (DBusConnection *connection, DBusMessage *message, void *user_data)
{
	NMData	*data = (NMData *)user_data;

	g_return_val_if_fail (data != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (connection != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (message != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	return (DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
}


/*
 * nm_dbus_devices_handle_networks_request
 *
 * Converts a property request on a _network_ into a dbus message.
 *
 */
static DBusMessage *nm_dbus_devices_handle_networks_request (DBusConnection *connection, DBusMessage *message,
									NMData *data, const char *path, const char *request, NMDevice *dev)
{
	NMAccessPoint		*ap;
	DBusMessage		*reply_message = NULL;
	DBusMessageIter	 iter;

	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);
	g_return_val_if_fail (request != NULL, NULL);
	g_return_val_if_fail (dev != NULL, NULL);

	if (!(ap = nm_dbus_get_network_from_object_path (path, dev)))
	{
		reply_message = nm_dbus_create_error_message (message, NM_DBUS_NM_NAMESPACE, "NetworkNotFound",
						"The requested network does not exist for this device.");
		return (reply_message);
	}

	reply_message = dbus_message_new_method_return (message);
	if (!reply_message)
		return (NULL);
	dbus_message_iter_init (reply_message, &iter);

	if (strcmp ("getName", request) == 0)
		dbus_message_iter_append_string (&iter, nm_ap_get_essid (ap));
	else if (strcmp ("getAddress", request) == 0)
	{
		char		buf[20];

		memset (&buf[0], 0, 20);
		iw_ether_ntop((const struct ether_addr *) (nm_ap_get_address (ap)), &buf[0]);
		dbus_message_iter_append_string (&iter, &buf[0]);
	}
	else if (strcmp ("getQuality", request) == 0)
		dbus_message_iter_append_int32 (&iter, nm_ap_get_quality (ap));
	else if (strcmp ("getFrequency", request) == 0)
		dbus_message_iter_append_double (&iter, nm_ap_get_freq (ap));
	else if (strcmp ("getRate", request) == 0)
		dbus_message_iter_append_int32 (&iter, nm_ap_get_rate (ap));
	else if (strcmp ("getStamp", request) == 0)
		dbus_message_iter_append_int32 (&iter, nm_ap_get_stamp (ap));
	else
	{
		/* Must destroy the allocated message */
		dbus_message_unref (reply_message);

		reply_message = nm_dbus_create_error_message (message, NM_DBUS_NM_NAMESPACE, "UnknownMethod",
							"NetworkManager knows nothing about the method %s for object %s", request, path);
	}

	return (reply_message);
}


/*
 * nm_dbus_devices_handle_request
 *
 * Converts a property request into a dbus message.
 *
 */
static DBusMessage *nm_dbus_devices_handle_request (DBusConnection *connection, NMData *data, DBusMessage *message,
											const char *path, const char *request)
{
	NMDevice			*dev;
	DBusMessage		*reply_message = NULL;
	DBusMessageIter	 iter;
	char				*object_path;

	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);
	g_return_val_if_fail (request != NULL, NULL);

	if (!(dev = nm_dbus_get_device_from_object_path (data, path)))
	{
		reply_message = nm_dbus_create_error_message (message, NM_DBUS_NM_NAMESPACE, "DeviceNotFound",
						"The requested network device does not exist.");
		return (reply_message);
	}

	/* Test whether or not the _networks_ of a device were queried instead of the device itself */
	object_path = g_strdup_printf ("%s/%s/Networks/", NM_DBUS_DEVICES_OBJECT_PATH_PREFIX, nm_device_get_iface (dev));
	if (strncmp (path, object_path, strlen (object_path)) == 0)
	{
		free (object_path);
		reply_message = nm_dbus_devices_handle_networks_request (connection, message, data, path, request, dev);
		return (reply_message);
	}
	free (object_path);

	reply_message = dbus_message_new_method_return (message);
	if (!reply_message)
		return (NULL);
	dbus_message_iter_init (reply_message, &iter);

	if (strcmp ("getName", request) == 0)
		dbus_message_iter_append_string (&iter, nm_device_get_iface (dev));
	else if (strcmp ("getType", request) == 0)
		dbus_message_iter_append_int32 (&iter, nm_device_get_iface_type (dev));
	else if (strcmp ("getIP4Address", request) == 0)
		dbus_message_iter_append_uint32 (&iter, nm_device_get_ip4_address (dev));
	else if (strcmp ("getActiveNetwork", request) == 0)
	{
		NMAccessPoint	*ap;
		if ((ap = nm_device_ap_list_get_ap_by_essid (dev, nm_device_get_essid (dev))))
		{
			object_path = g_strdup_printf ("%s/%s/Networks/%s", NM_DBUS_DEVICES_OBJECT_PATH_PREFIX,
									nm_device_get_iface (dev), nm_ap_get_essid (ap));
			dbus_message_iter_append_string (&iter, object_path);
			g_free (object_path);
		}
		else
			dbus_message_iter_append_string (&iter, "");
	}
	else if (strcmp ("getNetworks", request) == 0)
	{
		DBusMessageIter	 iter_array;
		NMAccessPoint		*ap = NULL;
		int				 i = 0;
	
		dbus_message_iter_append_array (&iter, &iter_array, DBUS_TYPE_STRING);
		while ((ap = nm_device_ap_list_get_ap_by_index (dev, i)) != NULL)
		{
			object_path = g_strdup_printf ("%s/%s/Networks/%s", NM_DBUS_DEVICES_OBJECT_PATH_PREFIX,
									nm_device_get_iface (dev), nm_ap_get_essid (ap));
			dbus_message_iter_append_string (&iter_array, object_path);
			g_free (object_path);
			
			i++;
		}
	}
	else
	{
		/* Must destroy the allocated message */
		dbus_message_unref (reply_message);
		reply_message = NULL;
	}

	return (reply_message);
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
	const char		*method;
	const char		*path;
	DBusMessage		*reply_message = NULL;
	gboolean			 handled = TRUE;

	g_return_val_if_fail (data != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (connection != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (message != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	method = dbus_message_get_member (message);
	path = dbus_message_get_path (message);

	NM_DEBUG_PRINT_2 ("nm_dbus_nm_message_handler() got method %s for path %s\n", method, path);

	if (strcmp ("getActiveDevice", method) == 0)
		reply_message = nm_dbus_nm_get_active_device (connection, message, data);
	else if (strcmp ("getDevices", method) == 0)
		reply_message = nm_dbus_nm_get_devices (connection, message, data);
	else if (strcmp ("setKeyForNetwork", method) == 0)
		nm_dbus_set_user_key_for_network (connection, message, data);
	else
		handled = FALSE;

	if (reply_message)
	{
		dbus_connection_send (connection, reply_message, NULL);
		dbus_message_unref (reply_message);
	}

	return (handled ? DBUS_HANDLER_RESULT_HANDLED : DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
}


/*
 * nm_dbus_nm_unregister_handler
 *
 * Nothing happens here.
 *
 */
void nm_dbus_nm_unregister_handler (DBusConnection *connection, void *user_data)
{
	/* do nothing */
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
	const char		*method;
	const char		*path;
	DBusMessage		*reply_message = NULL;

	g_return_val_if_fail (data != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (connection != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (message != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	method = dbus_message_get_member (message);
	path = dbus_message_get_path (message);

	if ((reply_message = nm_dbus_devices_handle_request (connection, data, message, path, method)))
	{
		dbus_connection_send (connection, reply_message, NULL);
		dbus_message_unref (reply_message);
		handled = TRUE;
	}

	return (handled ? DBUS_HANDLER_RESULT_HANDLED : DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
}


/*
 * nm_dbus_devices_unregister_handler
 *
 * Nothing happens here.
 *
 */
void nm_dbus_devices_unregister_handler (DBusConnection *connection, void *user_data)
{
	/* do nothing */
}


/*
 * nm_dbus_init
 *
 * Connect to the system messagebus and register ourselves as a service.
 *
 */
DBusConnection *nm_dbus_init (NMData *data)
{
	DBusError		 		 dbus_error;
	dbus_bool_t			 success;
	DBusConnection			*connection;
	DBusObjectPathVTable	 nm_vtable = { &nm_dbus_nm_unregister_handler, &nm_dbus_nm_message_handler, NULL, NULL, NULL, NULL };
	const char			*nm_path[] = { "org", "freedesktop", "NetworkManager", NULL };
	DBusObjectPathVTable	 devices_vtable = { &nm_dbus_devices_unregister_handler, &nm_dbus_devices_message_handler, NULL, NULL, NULL, NULL };
	const char			*devices_path[] = { "org", "freedesktop", "NetworkManager", "Devices", NULL };

	dbus_connection_set_change_sigpipe (TRUE);

	dbus_error_init (&dbus_error);
	connection = dbus_bus_get (DBUS_BUS_SYSTEM, &dbus_error);
	if (connection == NULL)
	{
		NM_DEBUG_PRINT ("nm_dbus_init() could not get the system bus.  Make sure the message bus daemon is running?\n");
		return (NULL);
	}

	dbus_connection_set_exit_on_disconnect (connection, FALSE);
	dbus_connection_setup_with_g_main (connection, NULL);
	dbus_bus_acquire_service (connection, NM_DBUS_NM_NAMESPACE, 0, &dbus_error);
	if (dbus_error_is_set (&dbus_error))
	{
		NM_DEBUG_PRINT_1 ("nm_dbus_init() could not acquire its service.  dbus_bus_acquire_service() says: '%s'\n", dbus_error.message);
		return (NULL);
	}

	success = dbus_connection_register_object_path (connection, nm_path, &nm_vtable, data);
	if (!success)
	{
		NM_DEBUG_PRINT ("nm_dbus_init() could not register a handler for NetworkManager.  Not enough memory?\n");
		return (NULL);
	}

	success = dbus_connection_register_fallback (connection, devices_path, &devices_vtable, data);
	if (!success)
	{
		NM_DEBUG_PRINT ("nm_dbus_init() could not register a handler for NetworkManager devices.  Not enough memory?\n");
		return (NULL);
	}

	if (!dbus_connection_add_filter (connection, nm_dbus_nmi_filter, data, NULL))
		return (NULL);

	dbus_bus_add_match (connection,
				"type='signal',"
				"interface='org.freedesktop.NetworkManagerInfo',"
				"sender='org.freedesktop.NetworkManagerInfo',"
				"path='/org/freedesktop/NetworkManagerInfo'", &dbus_error);

	return (connection);
}
