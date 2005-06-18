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
 * (C) Copyright 2005 Red Hat, Inc.
 */

#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>
#include <stdarg.h>


#include "nm-dbus-nm.h"
#include "NetworkManagerDbus.h"
#include "NetworkManagerDbusUtils.h"
#include "NetworkManagerUtils.h"
#include "NetworkManagerPolicy.h"


/*
 * nm_dbus_nm_get_active_device
 *
 * Returns the object path of the currently active device
 *
 */
static DBusMessage *nm_dbus_nm_get_active_device (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage	*reply = NULL;

	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (data->data != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	/* Construct object path of "active" device and return it */
	if (data->data->active_device)
	{
		char *object_path;

		reply = dbus_message_new_method_return (message);
		if (!reply)
			return (NULL);

		object_path = g_strdup_printf ("%s/%s", NM_DBUS_PATH_DEVICES, nm_device_get_iface (data->data->active_device));
		dbus_message_append_args (reply, DBUS_TYPE_STRING, object_path, DBUS_TYPE_INVALID);
		g_free (object_path);
	}
	else
	{
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "NoActiveDevice",
						"There is no currently active device.");
	}

	return (reply);
}


/*
 * nm_dbus_nm_get_devices
 *
 * Returns a string array of object paths corresponding to the
 * devices in the device list.
 *
 */
static DBusMessage *nm_dbus_nm_get_devices (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage		*reply = NULL;
	DBusMessageIter	 iter;
	DBusMessageIter	 iter_array;

	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (data->data != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	/* Check for no devices */
	if (!data->data->dev_list)
		return (nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "NoDevices",
					"There are no available network devices."));

	if (!(reply = dbus_message_new_method_return (message)))
		return NULL;

	dbus_message_iter_init (reply, &iter);
	dbus_message_iter_append_array (&iter, &iter_array, DBUS_TYPE_STRING);

	/* Iterate over device list and grab index of "active device" */
	if (nm_try_acquire_mutex (data->data->dev_list_mutex, __FUNCTION__))
	{
		GSList	*elt;
		gboolean	 appended = FALSE;

		for (elt = data->data->dev_list; elt; elt = g_slist_next (elt))
		{
			NMDevice	*dev = (NMDevice *)(elt->data);

			if (dev && (nm_device_get_driver_support_level (dev) != NM_DRIVER_UNSUPPORTED))
			{
				char *object_path = g_strdup_printf ("%s/%s", NM_DBUS_PATH_DEVICES, nm_device_get_iface (dev));
				dbus_message_iter_append_string (&iter_array, object_path);
				g_free (object_path);
				appended = TRUE;
			}
		}

		/* If by some chance there is a device list, but it has no devices in it
		 * (something which should never happen), die.
		 */
		if (!appended)
		{
			syslog (LOG_ERR, "Device list existed, but no devices were in it.\n");
			g_assert_not_reached ();
		}

		nm_unlock_mutex (data->data->dev_list_mutex, __FUNCTION__);
	}
	else
	{
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "Retry",
						"NetworkManager could not lock device list, try again.");
	}

	return (reply);
}


/*
 * nm_dbus_nm_set_active_device
 *
 * Notify the state modification handler that we want to lock to a specific
 * device.
 *
 */
static DBusMessage *nm_dbus_nm_set_active_device (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	NMDevice			*dev = NULL;
	DBusMessage		*reply = NULL;
	char				*dev_path = NULL;
	char				*network = NULL;
	char				*key = NULL;
	int				 key_type = -1;
	DBusError			 error;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);
	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (data->data != NULL, NULL);

	/* Try to grab both device _and_ network first, and if that fails then just the device. */
	dbus_error_init (&error);
	if (!dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &dev_path,
							DBUS_TYPE_STRING, &network, DBUS_TYPE_STRING, &key,
							DBUS_TYPE_INT32, &key_type, DBUS_TYPE_INVALID))
	{
		network = NULL;
		key = NULL;
		key_type = -1;

		if (dbus_error_is_set (&error))
			dbus_error_free (&error);

		/* So if that failed, try getting just the device */
		dbus_error_init (&error);
		if (!dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &dev_path, DBUS_TYPE_INVALID))
		{
			if (dbus_error_is_set (&error))
				dbus_error_free (&error);

			reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "InvalidArguments",
							"NetworkManager::setActiveDevice called with invalid arguments.");
			goto out;
		} else syslog (LOG_INFO, "FORCE: device '%s'", dev_path);
	} else syslog (LOG_INFO, "FORCE: device '%s', network '%s'", dev_path, network);
	
	/* So by now we have a valid device and possibly a network as well */

	dev = nm_dbus_get_device_from_object_path (data->data, dev_path);
	if (!dev || (nm_device_get_driver_support_level (dev) == NM_DRIVER_UNSUPPORTED))
	{
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "DeviceNotFound",
						"The requested network device does not exist.");
		goto out;
	}
	nm_device_ref (dev);

	/* Make sure network is valid and device is wireless */
	if (nm_device_is_wireless (dev) && !network)
	{
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "InvalidArguments",
							"NetworkManager::setActiveDevice called with invalid arguments.");
		goto out;
	}

	data->data->forcing_device = TRUE;
	nm_device_deactivate (dev, FALSE);
	nm_device_schedule_force_use (dev, network, key, key_type);

out:
	dbus_free (dev_path);
	dbus_free (network);
	dbus_free (key);
	return (reply);
}


/*
 * nm_dbus_nm_create_wireless_network
 *
 * Create a new wireless network and 
 *
 */
static DBusMessage *nm_dbus_nm_create_wireless_network (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	NMDevice			*dev = NULL;
	DBusMessage		*reply = NULL;
	char				*dev_path = NULL;
	NMAccessPoint		*new_ap = NULL;
	char				*network = NULL;
	char				*key = NULL;
	int				 key_type = -1;
	DBusError			 error;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);
	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (data->data != NULL, NULL);

	/* Try to grab both device _and_ network first, and if that fails then just the device. */
	dbus_error_init (&error);
	if (!dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &dev_path,
							DBUS_TYPE_STRING, &network, DBUS_TYPE_STRING, &key,
							DBUS_TYPE_INT32, &key_type, DBUS_TYPE_INVALID))
	{
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "InvalidArguments",
						"NetworkManager::createWirelessNetwork called with invalid arguments.");
		return (reply);
	} else syslog (LOG_INFO, "Creating network '%s' on device '%s'.", network, dev_path);
	
	dev = nm_dbus_get_device_from_object_path (data->data, dev_path);
	dbus_free (dev_path);
	if (!dev || (nm_device_get_driver_support_level (dev) == NM_DRIVER_UNSUPPORTED))
	{
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "DeviceNotFound",
						"The requested network device does not exist.");
		return (reply);
	}
	nm_device_ref (dev);

	/* Make sure network is valid and device is wireless */
	if (!nm_device_is_wireless (dev) || !network)
	{
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "InvalidArguments",
							"NetworkManager::createWirelessNetwork called with invalid arguments.");
		goto out;
	}

	data->data->forcing_device = TRUE;

	new_ap = nm_ap_new ();

	/* Fill in the description of the network to create */
	nm_ap_set_essid (new_ap, network);
	if (nm_is_enc_key_valid (key, key_type))
	{
		nm_ap_set_encrypted (new_ap, TRUE);
		nm_ap_set_enc_key_source (new_ap, key, key_type);
		nm_ap_set_auth_method (new_ap, NM_DEVICE_AUTH_METHOD_OPEN_SYSTEM);
	}
	nm_ap_set_mode (new_ap, NETWORK_MODE_ADHOC);
	nm_ap_set_user_created (new_ap, TRUE);

	nm_device_set_best_ap (dev, new_ap);		
	nm_device_freeze_best_ap (dev);
	nm_device_activation_cancel (dev);

	/* Schedule this device to be used next. */
	nm_policy_schedule_device_switch (dev, data->data);

out:
	dbus_free (network);
	dbus_free (key);
	nm_device_unref (dev);
	return (reply);
}


static DBusMessage *nm_dbus_nm_create_test_device (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusError		err;
	NMDeviceType	type;
	DBusMessage	*reply = NULL;
	static int	 test_dev_num = 0;

	g_return_val_if_fail (data && data->data && connection && message, NULL);

	dbus_error_init (&err);
	if (    dbus_message_get_args (message, &err, DBUS_TYPE_INT32, &type, DBUS_TYPE_INVALID)
		&& ((type == DEVICE_TYPE_WIRED_ETHERNET) || (type == DEVICE_TYPE_WIRELESS_ETHERNET)))
	{
		char			*interface = g_strdup_printf ("test%d", test_dev_num);
		char			*udi = g_strdup_printf ("/test-devices/%s", interface);
		NMDevice		*dev = NULL;

		dev = nm_create_device_and_add_to_list (data->data, udi, interface, TRUE, type);
		test_dev_num++;
		if ((reply = dbus_message_new_method_return (message)))
		{
			char		*dev_path = g_strdup_printf ("%s/%s", NM_DBUS_PATH_DEVICES, nm_device_get_iface (dev));
			dbus_message_append_args (reply, DBUS_TYPE_STRING, dev_path, DBUS_TYPE_INVALID);
			g_free (dev_path);
		}
		g_free (interface);
		g_free (udi);
	}
	else
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "BadType", "The test device type was invalid.");

	return (reply);
}

static DBusMessage *nm_dbus_nm_remove_test_device (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage	*reply = NULL;
	DBusError		 err;
	char			*dev_path;

	g_return_val_if_fail (data && data->data && connection && message, NULL);

	dbus_error_init (&err);
	if (dbus_message_get_args (message, &err, DBUS_TYPE_STRING, &dev_path, DBUS_TYPE_INVALID))
	{
		NMDevice	*dev;

		if ((dev = nm_dbus_get_device_from_object_path (data->data, dev_path)))
		{
			if (nm_device_is_test_device (dev))
				nm_remove_device_from_list (data->data, nm_device_get_udi (dev));
			else
				reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "NotTestDevice",
							"Only test devices can be removed via dbus calls.");
		}
		else
		{
			reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "DeviceNotFound",
							"The requested network device does not exist.");
		}
	}
	else
	{
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "DeviceBad",
					"The device ID was bad.");
	}

	if (dbus_error_is_set (&err))
		dbus_error_free (&err);

	return (reply);
}


/*
 * nm_dbus_nm_set_user_key_for_network
 *
 * In response to a NetworkManagerInfo message, sets the WEP key
 * for a particular wireless AP/network
 *
 */
static DBusMessage * nm_dbus_nm_set_user_key_for_network (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusError		 error;
	char			*device;
	char			*network;
	char			*passphrase;
	NMEncKeyType	 key_type;

	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (data->data != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	dbus_error_init (&error);
	if (dbus_message_get_args (message, &error,
							DBUS_TYPE_STRING, &device,
							DBUS_TYPE_STRING, &network,
							DBUS_TYPE_STRING, &passphrase,
							DBUS_TYPE_INT32, &key_type,
							DBUS_TYPE_INVALID))
	{
		NMDevice		*dev;

		if ((dev = nm_get_device_by_iface (data->data, device)))
			nm_device_set_user_key_for_network (dev, data->data->invalid_ap_list, network, passphrase, key_type);

		dbus_free (device);
		dbus_free (network);
		dbus_free (passphrase);
	}

	return (NULL);
}


static DBusMessage *nm_dbus_nm_get_wireless_scan_method (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage	*reply = NULL;

	g_return_val_if_fail (data && data->data && connection && message, NULL);

	if ((reply = dbus_message_new_method_return (message)))
		dbus_message_append_args (reply, DBUS_TYPE_BOOLEAN, data->data->scanning_method, DBUS_TYPE_INVALID);
	
	return reply;
}

static DBusMessage *nm_dbus_nm_set_wireless_enabled (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	gboolean	enabled = FALSE;
	DBusError	err;

	g_return_val_if_fail (data && data->data && connection && message, NULL);

	dbus_error_init (&err);
	if (dbus_message_get_args (message, &err, DBUS_TYPE_BOOLEAN, &enabled, DBUS_TYPE_INVALID))
	{
		GSList	*elt;
		NMData	*app_data;

		app_data = data->data;
		app_data->wireless_enabled = enabled;

		/* Physically down all wireless devices */
		nm_lock_mutex (app_data->dev_list_mutex, __FUNCTION__);
		for (elt = app_data->dev_list; elt; elt = g_slist_next (elt))
		{
			NMDevice	*dev = (NMDevice *)(elt->data);
			if (nm_device_is_wireless (dev))
			{
				nm_device_deactivate (dev, FALSE);
				nm_device_bring_down (dev);
			}
		}
		nm_unlock_mutex (app_data->dev_list_mutex, __FUNCTION__);
		nm_policy_schedule_state_update (app_data);
	}

	return NULL;
}

static DBusMessage *nm_dbus_nm_get_wireless_enabled (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage	*reply = NULL;

	g_return_val_if_fail (data && data->data && connection && message, NULL);

	if ((reply = dbus_message_new_method_return (message)))
		dbus_message_append_args (reply, DBUS_TYPE_BOOLEAN, data->data->wireless_enabled, DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *nm_dbus_nm_sleep (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	GSList	*elt;
	NMData	*app_data;

	g_return_val_if_fail (data && data->data && connection && message, NULL);

	app_data = data->data;
	if (app_data->asleep == FALSE)
	{
		app_data->asleep = TRUE;

		/* Physically down all devices */
		nm_lock_mutex (app_data->dev_list_mutex, __FUNCTION__);
		for (elt = app_data->dev_list; elt; elt = g_slist_next (elt))
		{
			NMDevice	*dev = (NMDevice *)(elt->data);

			nm_device_deactivate (dev, FALSE);
			nm_device_bring_down (dev);
		}
		nm_unlock_mutex (app_data->dev_list_mutex, __FUNCTION__);
		nm_policy_schedule_state_update (app_data);
	}

	return NULL;
}

static DBusMessage *nm_dbus_nm_wake (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	NMData	*app_data;

	g_return_val_if_fail (data && data->data && connection && message, NULL);

	app_data = data->data;
	if (app_data->asleep == TRUE)
	{
		app_data->asleep = FALSE;
		nm_policy_schedule_state_update (app_data);
	}

	return NULL;
}

static DBusMessage *nm_dbus_nm_get_status (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage	*reply = NULL;
	char 		*status;

	g_return_val_if_fail (data && data->data && connection && message, NULL);

	status = nm_dbus_network_status_from_data (data->data);
	if (status && (reply = dbus_message_new_method_return (message)))
			dbus_message_append_args (reply, DBUS_TYPE_STRING, status, DBUS_TYPE_INVALID);
	g_free (status);

	return reply;
}


/*
 * nm_dbus_nm_methods_setup
 *
 * Register handlers for dbus methods on the org.freedesktop.NetworkManager object.
 *
 */
NMDbusMethodList *nm_dbus_nm_methods_setup (void)
{
	NMDbusMethodList	*list = nm_dbus_method_list_new (NULL);

	nm_dbus_method_list_add_method (list, "getActiveDevice",		nm_dbus_nm_get_active_device);
	nm_dbus_method_list_add_method (list, "getDevices",			nm_dbus_nm_get_devices);
	nm_dbus_method_list_add_method (list, "setActiveDevice",		nm_dbus_nm_set_active_device);
	nm_dbus_method_list_add_method (list, "createWirelessNetwork",	nm_dbus_nm_create_wireless_network);
	nm_dbus_method_list_add_method (list, "setKeyForNetwork",		nm_dbus_nm_set_user_key_for_network);
	nm_dbus_method_list_add_method (list, "getWirelessScanMethod",	nm_dbus_nm_get_wireless_scan_method);
	nm_dbus_method_list_add_method (list, "setWirelessEnabled",		nm_dbus_nm_set_wireless_enabled);
	nm_dbus_method_list_add_method (list, "getWirelessEnabled",		nm_dbus_nm_get_wireless_enabled);
	nm_dbus_method_list_add_method (list, "sleep",				nm_dbus_nm_sleep);
	nm_dbus_method_list_add_method (list, "wake",				nm_dbus_nm_wake);
	nm_dbus_method_list_add_method (list, "status",				nm_dbus_nm_get_status);
	nm_dbus_method_list_add_method (list, "createTestDevice",		nm_dbus_nm_create_test_device);
	nm_dbus_method_list_add_method (list, "removeTestDevice",		nm_dbus_nm_remove_test_device);

	return (list);
}


