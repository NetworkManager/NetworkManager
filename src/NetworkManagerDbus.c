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
void nm_dbus_get_object_path_from_device (NMDevice *dev, unsigned char *buf, unsigned int buf_len, gboolean lock_dev_list)
{
	NMData	*data = nm_get_global_data ();

	g_return_if_fail (buf != NULL);
	g_return_if_fail (buf_len > 0);
	memset (buf, 0, buf_len);

	g_return_if_fail (dev != NULL);
	g_return_if_fail (data != NULL);

	/* Iterate over device list */
	if (!lock_dev_list || nm_try_acquire_mutex (data->dev_list_mutex, __FUNCTION__))
	{
		NMDevice	*list_dev = NULL;
		GSList	*element = data->dev_list;
		int		 i = 0;

		while (element)
		{
			list_dev = (NMDevice *)(element->data);
			if (dev == list_dev)
			{
				snprintf (buf, buf_len-1, "%s/%d", NM_DBUS_DEVICES_OBJECT_PATH_PREFIX, i);
				break;
			}

			i++;
			element = g_slist_next (element);
		}

		if (lock_dev_list)
			nm_unlock_mutex (data->dev_list_mutex, __FUNCTION__);
	}
}


/*
 * nm_dbus_get_device_from_object_path
 *
 * Returns the device associated with a dbus object path
 *
 */
NMDevice *nm_dbus_get_device_from_object_path (const char *path, int *dev_index)
{
	NMData	*data = nm_get_global_data ();
	NMDevice	*dev = NULL;

	*dev_index = -1;

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
		int		 i = 0;

		while (element)
		{
			snprintf (compare_path, 100, "%s/%d", NM_DBUS_DEVICES_OBJECT_PATH_PREFIX, i);

			/* Compare against our constructed path, but ignore any trailing elements */
			dev = (NMDevice *)(element->data);
			if (dev && (strncmp (path, compare_path, strlen (compare_path)) == 0))
			{
				*dev_index = i;
				break;
			}
			else
				dev = NULL;

			i++;
			element = g_slist_next (element);
		}
		nm_unlock_mutex (data->dev_list_mutex, __FUNCTION__);
	}

	return (dev);
}


/*
 * nm_dbus_get_network_by_object_path
 *
 * Returns the network (ap) associated with a dbus object path
 *
 */
NMAccessPoint *nm_dbus_get_network_by_object_path (const char *path, NMDevice *dev, int dev_index, int *ap_index)
{
	NMData		*data;
	NMAccessPoint	*ap = NULL;
	int			 i = 0;
	char			 compare_path[100];

	*ap_index = -1;

	g_return_val_if_fail (path != NULL, NULL);

	while (ap = nm_device_ap_list_get_ap (dev, i))
	{
		snprintf (compare_path, 100, "%s/%d/Networks/%d", NM_DBUS_DEVICES_OBJECT_PATH_PREFIX, dev_index, i);
		if (strncmp (path, compare_path, strlen (compare_path)) == 0)
		{
			*ap_index = i;
			break;
		}
		else
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
static DBusMessage *nm_dbus_nm_get_active_device (DBusConnection *connection, DBusMessage *message)
{
	DBusMessage		*reply_message = NULL;
	DBusMessageIter	 iter;
	NMData			*data;

	data = nm_get_global_data ();
	if (!data)
	{
		/* If we can't get our global data, something is really wrong... */
		reply_message = nm_dbus_create_error_message (message, NM_DBUS_NM_NAMESPACE, "NoGlobalData",
							"NetworkManager couldn't get its global data.");
		goto end;
	}

	if (!data->active_device)
	{
		reply_message = dbus_message_new_method_return (message);
		dbus_message_iter_init (reply_message, &iter);
		dbus_message_iter_append_string (&iter, "");

		goto end;
	}

	/* Iterate over device list and grab index of "active device" */
	if (nm_try_acquire_mutex (data->dev_list_mutex, __FUNCTION__))
	{
		GSList	*element = data->dev_list;
		int		 i = 0;

		while (element)
		{
			NMDevice	*dev = (NMDevice *)(element->data);

			if (dev && (dev == data->active_device))
			{
				char *object_path = g_strdup_printf ("%s/%d", NM_DBUS_DEVICES_OBJECT_PATH_PREFIX, i);

				reply_message = dbus_message_new_method_return (message);
				dbus_message_iter_init (reply_message, &iter);
				dbus_message_iter_append_string (&iter, object_path);
				g_free (object_path);

				break;
			}

			i++;
			element = g_slist_next (element);
		}

		if (!reply_message)
		{
			/* If the active device wasn't in the list, its been removed. */
			reply_message = dbus_message_new_method_return (message);
			dbus_message_iter_init (reply_message, &iter);
			dbus_message_iter_append_string (&iter, "");
		}

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


/*
 * nm_dbus_nm_get_devices
 *
 * Returns a string array of object paths corresponding to the
 * devices in the device list.
 *
 */
static DBusMessage *nm_dbus_nm_get_devices (DBusConnection *connection, DBusMessage *message)
{
	DBusMessage		*reply_message = NULL;
	DBusMessageIter	 iter;
	DBusMessageIter	 iter_array;
	NMData			*data;

	data = nm_get_global_data ();
	if (!data)
	{
		/* If we can't get our global data, something is really wrong... */
		reply_message = nm_dbus_create_error_message (message, NM_DBUS_NM_NAMESPACE, "NoGlobalData",
							"NetworkManager couldn't get its global data.");
		goto end;
	}

	/* Check for no devices */
	if (!data->dev_list)
	{
		reply_message = dbus_message_new_method_return (message);
		dbus_message_iter_init (reply_message, &iter);
		dbus_message_iter_append_array (&iter, &iter_array, DBUS_TYPE_STRING);
		dbus_message_iter_append_string (&iter_array, "");

		goto end;
	}

	/* Iterate over device list and grab index of "active device" */
	if (nm_try_acquire_mutex (data->dev_list_mutex, __FUNCTION__))
	{
		GSList	*element = data->dev_list;
		int		 i = 0;
		gboolean	 appended = FALSE;

		reply_message = dbus_message_new_method_return (message);
		dbus_message_iter_init (reply_message, &iter);
		dbus_message_iter_append_array (&iter, &iter_array, DBUS_TYPE_STRING);

		while (element)
		{
			NMDevice	*dev = (NMDevice *)(element->data);

			if (dev)
			{
				char *object_path = g_strdup_printf ("%s/%d", NM_DBUS_DEVICES_OBJECT_PATH_PREFIX, i);
				dbus_message_iter_append_string (&iter_array, object_path);
				g_free (object_path);
				appended = TRUE;
			}

			i++;
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

	g_return_if_fail (object_path != NULL);

	message = dbus_message_new_signal (NM_DBUS_NM_OBJECT_PATH_PREFIX, NM_DBUS_NM_NAMESPACE, "DeviceNoLongerActive");
	if (!message)
	{
		NM_DEBUG_PRINT ("nm_dbus_signal_device_no_longer_active(): Not enough memory for new dbus message!\n");
	}

	nm_dbus_get_object_path_from_device (dev, object_path, 100, FALSE);
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

	message = dbus_message_new_signal (NM_DBUS_NM_OBJECT_PATH_PREFIX, NM_DBUS_NM_NAMESPACE, "DeviceNowActive");
	if (!message)
	{
		NM_DEBUG_PRINT ("nm_dbus_signal_device_now_active(): Not enough memory for new dbus message!\n");
	}

	nm_dbus_get_object_path_from_device (dev, object_path, 100, FALSE);
	dbus_message_append_args (message, DBUS_TYPE_STRING, object_path, DBUS_TYPE_INVALID);
	g_free (object_path);

	if (!dbus_connection_send (connection, message, NULL))
		NM_DEBUG_PRINT ("nm_dbus_signal_device_now_active(): Could not raise the DeviceNowActive signal!\n");

	dbus_message_unref (message);
}


/*
 * nm_dbus_devices_handle_networks_request
 *
 * Converts a property request on a _network_ into a dbus message.
 *
 */
static DBusMessage *nm_dbus_devices_handle_networks_request (DBusConnection *connection, DBusMessage *message,
									const char *path, const char *request, NMDevice *dev, int dev_index)
{
	NMAccessPoint		*ap;
	DBusMessage		*reply_message = NULL;
	DBusMessageIter	 iter;
	int				 ap_index;

	ap = nm_dbus_get_network_by_object_path (path, dev, dev_index, &ap_index);
	if (!ap || (ap_index == -1))
	{
		reply_message = nm_dbus_create_error_message (message, NM_DBUS_NM_NAMESPACE, "NetworkNotFound",
						"The requested network does not exist for this device.");
		return (reply_message);
	}

	reply_message = dbus_message_new_method_return (message);
	dbus_message_iter_init (reply_message, &iter);

	if (strcmp ("getName", request) == 0)
		dbus_message_iter_append_string (&iter, nm_ap_get_essid (ap));
	else if (strcmp ("getAddress", request) == 0)
		dbus_message_iter_append_string (&iter, nm_ap_get_address (ap));
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
static DBusMessage *nm_dbus_devices_handle_request (DBusConnection *connection, DBusMessage *message, const char *path, const char *request)
{
	NMDevice			*dev;
	DBusMessage		*reply_message = NULL;
	DBusMessageIter	 iter;
	int				 dev_index;
	char				*object_path;

	dev = nm_dbus_get_device_from_object_path (path, &dev_index);
	if (!dev || (dev_index == -1))
	{
		reply_message = nm_dbus_create_error_message (message, NM_DBUS_NM_NAMESPACE, "DeviceNotFound",
						"The requested network device does not exist.");
		return (reply_message);
	}

	/* Test whether or not the _networks_ of a device were queried instead of the device itself */
	object_path = g_strdup_printf ("%s/%d/Networks/", NM_DBUS_DEVICES_OBJECT_PATH_PREFIX, dev_index);
	if (strncmp (path, object_path, strlen (object_path)) == 0)
	{
		free (object_path);
		reply_message = nm_dbus_devices_handle_networks_request (connection, message, path, request, dev, dev_index);
		return (reply_message);
	}
	free (object_path);

	reply_message = dbus_message_new_method_return (message);
	dbus_message_iter_init (reply_message, &iter);

	if (strcmp ("getName", request) == 0)
		dbus_message_iter_append_string (&iter, nm_device_get_iface (dev));
	else if (strcmp ("getType", request) == 0)
		dbus_message_iter_append_int32 (&iter, nm_device_get_iface_type (dev));
	else if (strcmp ("getActiveNetwork", request) == 0)
	{
		NMAccessPoint		*ap = NULL;
		int				 i = 0;
	
		while (ap = nm_device_ap_list_get_ap (dev, i))
		{
			if (nm_null_safe_strcmp (nm_ap_get_essid (ap), nm_device_get_essid (dev)) == 0)
			{
				object_path = g_strdup_printf ("%s/%d/Networks/%d", NM_DBUS_DEVICES_OBJECT_PATH_PREFIX, dev_index, i);
				dbus_message_iter_append_string (&iter, object_path);
				g_free (object_path);
				break;
			}
			i++;
			ap = NULL;
		}

		/* If we didn't find the devices current network among the known networks, just append a blank item */
		if (!ap)
			dbus_message_iter_append_string (&iter, "");
	}
	else if (strcmp ("getNetworks", request) == 0)
	{
		DBusMessageIter	 iter_array;
		NMAccessPoint		*ap = NULL;
		int				 i = 0;
	
		dbus_message_iter_append_array (&iter, &iter_array, DBUS_TYPE_STRING);

		while (ap = nm_device_ap_list_get_ap (dev, i))
		{
			object_path = g_strdup_printf ("%s/%d/Networks/%d", NM_DBUS_DEVICES_OBJECT_PATH_PREFIX, dev_index, i);
			dbus_message_iter_append_string (&iter_array, object_path);
			g_free (object_path);
			
			i++;
		}
	}
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
 * nm_dbus_nm_message_handler
 *
 * Dispatch messages against our NetworkManager object
 *
 */
static DBusHandlerResult nm_dbus_nm_message_handler (DBusConnection *connection, DBusMessage *message, void *user_data)
{
	const char		*method;
	const char		*path;
	DBusMessage		*reply_message = NULL;

	method = dbus_message_get_member (message);
	path = dbus_message_get_path (message);

	NM_DEBUG_PRINT_2 ("nm_dbus_devices_message_handler() got method %s for path %s\n", method, path);

	if (strcmp ("getActiveDevice", method) == 0)
	{
		reply_message = nm_dbus_nm_get_active_device (connection, message);
	}
	else if (strcmp ("getDevices", method) == 0)
	{
		reply_message = nm_dbus_nm_get_devices (connection, message);
	}
	else
	{
		reply_message = nm_dbus_create_error_message (message, NM_DBUS_NM_NAMESPACE, "UnknownMethod",
							"NetworkManager knows nothing about the method %s for object %s", method, path);
	}

	dbus_connection_send (connection, reply_message, NULL);

	return DBUS_HANDLER_RESULT_HANDLED;
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
	const char		*method;
	const char		*path;
	DBusMessage		*reply_message = NULL;

	method = dbus_message_get_member (message);
	path = dbus_message_get_path (message);

	/* NM_DEBUG_PRINT_2 ("nm_dbus_nm_message_handler() got method %s for path %s\n", method, path); */

	reply_message = nm_dbus_devices_handle_request (connection, message, path, method);
	dbus_connection_send (connection, reply_message, NULL);

	return DBUS_HANDLER_RESULT_HANDLED;
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
DBusConnection *nm_dbus_init (void)
{
	DBusError		 		 dbus_error;
	dbus_bool_t			 success;
	DBusConnection			*dbus_connection;
	DBusObjectPathVTable	 nm_vtable = { &nm_dbus_nm_unregister_handler, &nm_dbus_nm_message_handler, NULL, NULL, NULL, NULL };
	const char			*nm_path[] = { "org", "freedesktop", "NetworkManager", NULL };
	DBusObjectPathVTable	 devices_vtable = { &nm_dbus_devices_unregister_handler, &nm_dbus_devices_message_handler, NULL, NULL, NULL, NULL };
	const char			*devices_path[] = { "org", "freedesktop", "NetworkManager", "Devices", NULL };

	dbus_connection_set_change_sigpipe (TRUE);

	dbus_error_init (&dbus_error);
	dbus_connection = dbus_bus_get (DBUS_BUS_SYSTEM, &dbus_error);
	if (dbus_connection == NULL)
	{
		NM_DEBUG_PRINT ("nm_dbus_init() could not get the system bus.  Make sure the message bus daemon is running?\n");
		return (NULL);
	}

	dbus_connection_set_exit_on_disconnect (dbus_connection, FALSE);
	dbus_connection_setup_with_g_main (dbus_connection, NULL);
	dbus_bus_acquire_service (dbus_connection, NM_DBUS_NM_NAMESPACE, 0, &dbus_error);
	if (dbus_error_is_set (&dbus_error))
	{
		NM_DEBUG_PRINT_1 ("nm_dbus_init() could not acquire its service.  dbus_bus_acquire_service() says: '%s'\n", dbus_error.message);
		return (NULL);
	}

	success = dbus_connection_register_object_path (dbus_connection, nm_path, &nm_vtable, NULL);
	if (!success)
	{
		NM_DEBUG_PRINT ("nm_dbus_init() could not register a handler for NetworkManager.  Not enough memory?\n");
		return (NULL);
	}

	success = dbus_connection_register_fallback (dbus_connection, devices_path, &devices_vtable, NULL);
	if (!success)
	{
		NM_DEBUG_PRINT ("nm_dbus_init() could not register a handler for NetworkManager devices.  Not enough memory?\n");
		return (NULL);
	}

	return (dbus_connection);
}
