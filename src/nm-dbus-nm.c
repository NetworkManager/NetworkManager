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
#include "nm-utils.h"
#include "NetworkManagerDbus.h"
#include "NetworkManagerDbusUtils.h"
#include "NetworkManagerUtils.h"
#include "NetworkManagerPolicy.h"
#include "NetworkManagerDialup.h"
#include "NetworkManagerSystem.h"
#include "NetworkManager.h"


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

	dbus_message_iter_init_append (reply, &iter);
	/* Iterate over device list and grab index of "active device" */
	if (nm_try_acquire_mutex (data->data->dev_list_mutex, __FUNCTION__))
	{
		GSList	*elt;
		gboolean	 appended = FALSE;

		dbus_message_iter_open_container (&iter, DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH_AS_STRING, &iter_array);

		for (elt = data->data->dev_list; elt; elt = g_slist_next (elt))
		{
			NMDevice	*dev = (NMDevice *)(elt->data);

			if (dev && (nm_device_get_driver_support_level (dev) != NM_DRIVER_UNSUPPORTED))
			{
				char *op = nm_dbus_get_object_path_for_device (dev);

				dbus_message_iter_append_basic (&iter_array, DBUS_TYPE_OBJECT_PATH, &op);
				g_free (op);
				appended = TRUE;
			}
		}

		/* If by some chance there is a device list, but it has no devices in it
		 * (something which should never happen), die.
		 */
		if (!appended)
		{
			nm_warning ("Device list existed, but no devices were in it.");
			g_assert_not_reached ();
		}

		dbus_message_iter_close_container (&iter, &iter_array);
		nm_unlock_mutex (data->data->dev_list_mutex, __FUNCTION__);
	}
	else
	{
		dbus_message_unref (reply);
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "Retry",
						"NetworkManager could not lock device list, try again.");
	}

	return (reply);
}


static DBusMessage *nm_dbus_nm_get_dialup (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage *reply = NULL;
	DBusMessageIter iter;

	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (data->data != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	/* Check for no dialup devices */
	if (!data->data->dialup_list)
		return (nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "NoDialup",
					"There are no available dialup devices."));

	reply = dbus_message_new_method_return (message);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append (reply, &iter);
	if (nm_try_acquire_mutex (data->data->dialup_list_mutex, __FUNCTION__))
	{
		DBusMessageIter iter_array;
		GSList *elt;

		dbus_message_iter_open_container (&iter, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING_AS_STRING, &iter_array);

		for (elt = data->data->dialup_list; elt; elt = g_slist_next (elt))
		{
			NMDialUpConfig *config = (NMDialUpConfig *) elt->data;
			dbus_message_iter_append_basic (&iter_array, DBUS_TYPE_STRING, &config->name);
		}

		dbus_message_iter_close_container (&iter, &iter_array);
		nm_unlock_mutex (data->data->dialup_list_mutex, __FUNCTION__);
	}
	else
	{
		dbus_message_unref (reply);
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "Retry",
						"NetworkManager could not lock dialup list, try again.");
	}

	return reply;
}


static DBusMessage *nm_dbus_nm_activate_dialup (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage *reply = NULL;
	NMData *nm_data = (NMData *) data->data;
	const char *dialup;

	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (data->data != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	reply = dbus_message_new_method_return (message);
	if (!reply)
		return NULL;

	if (!dbus_message_get_args (message, NULL, DBUS_TYPE_STRING, &dialup, DBUS_TYPE_INVALID))
	{
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "InvalidArguments",
									   "NetworkManager::activateDialup called with invalid arguments.");
		goto out;
	}

	nm_lock_mutex (nm_data->dialup_list_mutex, __FUNCTION__);
	if (!nm_system_activate_dialup (nm_data->dialup_list, dialup))
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "ActivationFailed",
									   "Failed to activate the dialup device.");
	nm_unlock_mutex (nm_data->dialup_list_mutex, __FUNCTION__);

out:
	return reply;
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
	NMDevice *		dev = NULL;
	DBusMessage *		reply = NULL;
	char *			dev_path = NULL;
	char *			essid = NULL;
	char *			key = NULL;
	int				key_type = -1;
	NMAccessPoint *	ap = NULL;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);
	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (data->data != NULL, NULL);

	/* Try to grab both device _and_ network first, and if that fails then just the device. */
	if (!dbus_message_get_args (message, NULL,	DBUS_TYPE_OBJECT_PATH, &dev_path,
										DBUS_TYPE_STRING, &essid,
										DBUS_TYPE_STRING, &key,
										DBUS_TYPE_INT32, &key_type, DBUS_TYPE_INVALID))
	{
		/* So if that failed, try getting just the device */
		if (!dbus_message_get_args (message, NULL, DBUS_TYPE_OBJECT_PATH, &dev_path, DBUS_TYPE_INVALID))
		{
			reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "InvalidArguments",
							"NetworkManager::setActiveDevice called with invalid arguments.");
			goto out;
		} else nm_info ("FORCE: device '%s'", dev_path);
	} else nm_info ("FORCE: device '%s', network '%s'", dev_path, essid);

	/* So by now we have a valid device and possibly a network as well */
	dev_path = nm_dbus_unescape_object_path (dev_path);
	dev = nm_dbus_get_device_from_object_path (data->data, dev_path);
	g_free (dev_path);
	if (!dev || (nm_device_get_driver_support_level (dev) == NM_DRIVER_UNSUPPORTED))
	{
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "DeviceNotFound",
						"The requested network device does not exist.");
		goto out;
	}

	/* Make sure network is valid and device is wireless */
	if (nm_device_is_wireless (dev) && !essid)
	{
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "InvalidArguments",
							"NetworkManager::setActiveDevice called with invalid arguments.");
		goto out;
	}

	nm_device_deactivate (dev);

	nm_schedule_state_change_signal_broadcast (data->data);

	if (nm_device_is_wireless (dev))
		ap = nm_device_wireless_get_activation_ap (dev, essid, key, (NMEncKeyType)key_type);
	nm_policy_schedule_device_activation (nm_act_request_new (data->data, dev, ap, TRUE));

out:
	return reply;
}

/*
 * nm_dbus_nm_create_wireless_network
 *
 * Create a new wireless network and 
 *
 */
static DBusMessage *nm_dbus_nm_create_wireless_network (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	NMDevice *		dev = NULL;
	DBusMessage *		reply = NULL;
	char *			dev_path = NULL;
	NMAccessPoint *	new_ap = NULL;
	char *			network = NULL;
	char *			key = NULL;
	int				key_type = -1;
	DBusError			error;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);
	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (data->data != NULL, NULL);

	/* Try to grab both device _and_ network first, and if that fails then just the device. */
	dbus_error_init (&error);
	if (!dbus_message_get_args (message, &error, DBUS_TYPE_OBJECT_PATH, &dev_path,
										DBUS_TYPE_STRING, &network,
										DBUS_TYPE_STRING, &key,
										DBUS_TYPE_INT32, &key_type, DBUS_TYPE_INVALID))
	{
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "InvalidArguments",
						"NetworkManager::createWirelessNetwork called with invalid arguments.");
		return reply;
	} else nm_info ("Creating network '%s' on device '%s'.", network, dev_path);

	dev_path = nm_dbus_unescape_object_path (dev_path);
	dev = nm_dbus_get_device_from_object_path (data->data, dev_path);
	g_free (dev_path);
	if (!dev || (nm_device_get_driver_support_level (dev) == NM_DRIVER_UNSUPPORTED))
	{
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "DeviceNotFound",
						"The requested network device does not exist.");
		return reply;
	}
	nm_device_ref (dev);

	/* Make sure network is valid and device is wireless */
	if (!nm_device_is_wireless (dev) || !network)
	{
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "InvalidArguments",
							"NetworkManager::createWirelessNetwork called with invalid arguments.");
		goto out;
	}

	new_ap = nm_ap_new ();

	/* Fill in the description of the network to create */
	nm_ap_set_essid (new_ap, network);
	if (nm_is_enc_key_valid (key, (NMEncKeyType)key_type))
	{
		nm_ap_set_encrypted (new_ap, TRUE);
		nm_ap_set_enc_key_source (new_ap, key, (NMEncKeyType)key_type);
		nm_ap_set_auth_method (new_ap, NM_DEVICE_AUTH_METHOD_OPEN_SYSTEM);
	}
	nm_ap_set_mode (new_ap, NETWORK_MODE_ADHOC);
	nm_ap_set_user_created (new_ap, TRUE);

	nm_policy_schedule_device_activation (nm_act_request_new (data->data, dev, new_ap, TRUE));

out:
	nm_device_unref (dev);
	return reply;
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
			char		*dev_path, *escaped_dev_path;
			dev_path = g_strdup_printf ("%s/%s", NM_DBUS_PATH_DEVICES, nm_device_get_iface (dev));
			escaped_dev_path = nm_dbus_escape_object_path (dev_path);
			dbus_message_append_args (reply, DBUS_TYPE_STRING, &dev_path, DBUS_TYPE_INVALID);
			g_free (dev_path);
			g_free (escaped_dev_path);
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

		dev_path = nm_dbus_unescape_object_path (dev_path);

		if ((dev = nm_dbus_get_device_from_object_path (data->data, dev_path)))
		{
			if (nm_device_is_test_device (dev))
				nm_remove_device (data->data, dev);
			else
				reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "NotTestDevice",
							"Only test devices can be removed via dbus calls.");
		}
		else
		{
			reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "DeviceNotFound",
							"The requested network device does not exist.");
		}

		g_free (dev_path);
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

static DBusMessage *nm_dbus_nm_set_wireless_enabled (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	gboolean	enabled = FALSE;
	DBusError	err;
	NMData	*app_data;

	g_return_val_if_fail (data && data->data && connection && message, NULL);

	dbus_error_init (&err);
	if (!dbus_message_get_args (message, &err, DBUS_TYPE_BOOLEAN, &enabled, DBUS_TYPE_INVALID))
		return NULL;

	app_data = data->data;
	app_data->wireless_enabled = enabled;

	if (!enabled)
	{
		GSList	*elt;

		/* Physically down all wireless devices */
		nm_lock_mutex (app_data->dev_list_mutex, __FUNCTION__);
		for (elt = app_data->dev_list; elt; elt = g_slist_next (elt))
		{
			NMDevice	*dev = (NMDevice *)(elt->data);
			if (nm_device_is_wireless (dev))
			{
				nm_device_deactivate (dev);
				nm_device_bring_down (dev);
			}
		}
		nm_unlock_mutex (app_data->dev_list_mutex, __FUNCTION__);
	}

	nm_policy_schedule_device_change_check (data->data);

	return NULL;
}

static DBusMessage *nm_dbus_nm_get_wireless_enabled (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage	*reply = NULL;

	g_return_val_if_fail (data && data->data && connection && message, NULL);

	if ((reply = dbus_message_new_method_return (message)))
		dbus_message_append_args (reply, DBUS_TYPE_BOOLEAN, &data->data->wireless_enabled, DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *nm_dbus_nm_sleep (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	NMData	*app_data;

	g_return_val_if_fail (data && data->data && connection && message, NULL);

	app_data = data->data;
	if (app_data->asleep == FALSE)
	{
		nm_info ("Going to sleep.");

		app_data->asleep = TRUE;

		/* Remove all devices from the device list */
		nm_lock_mutex (app_data->dev_list_mutex, __FUNCTION__);
		while (g_slist_length (app_data->dev_list))
		{
			NMDevice	*dev = (NMDevice *)(app_data->dev_list->data);

			fprintf (stderr, "dev %p\n", dev);
			nm_remove_device (app_data, dev);
		}
		nm_unlock_mutex (app_data->dev_list_mutex, __FUNCTION__);

		nm_lock_mutex (app_data->dialup_list_mutex, __FUNCTION__);
		nm_system_deactivate_all_dialup (app_data->dialup_list);
		nm_unlock_mutex (app_data->dialup_list_mutex, __FUNCTION__);

		nm_schedule_state_change_signal_broadcast (app_data);
		nm_policy_schedule_device_change_check (data->data);
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
		nm_info  ("Waking up from sleep.");
		app_data->asleep = FALSE;

		nm_add_initial_devices (app_data);

		nm_schedule_state_change_signal_broadcast (app_data);
		nm_policy_schedule_device_change_check (data->data);
	}

	return NULL;
}

static DBusMessage *nm_dbus_nm_get_state (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage *	reply = NULL;
	NMState		state;

	g_return_val_if_fail (data && data->data && connection && message, NULL);

	state = nm_get_app_state_from_data (data->data);
	if ((reply = dbus_message_new_method_return (message)))
		dbus_message_append_args (reply, DBUS_TYPE_UINT32, &state, DBUS_TYPE_INVALID);

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

	nm_dbus_method_list_add_method (list, "getDevices",			nm_dbus_nm_get_devices);
	nm_dbus_method_list_add_method (list, "getDialup",			nm_dbus_nm_get_dialup);
	nm_dbus_method_list_add_method (list, "activateDialup",		nm_dbus_nm_activate_dialup);
	nm_dbus_method_list_add_method (list, "setActiveDevice",		nm_dbus_nm_set_active_device);
	nm_dbus_method_list_add_method (list, "createWirelessNetwork",	nm_dbus_nm_create_wireless_network);
	nm_dbus_method_list_add_method (list, "setWirelessEnabled",		nm_dbus_nm_set_wireless_enabled);
	nm_dbus_method_list_add_method (list, "getWirelessEnabled",		nm_dbus_nm_get_wireless_enabled);
	nm_dbus_method_list_add_method (list, "sleep",				nm_dbus_nm_sleep);
	nm_dbus_method_list_add_method (list, "wake",				nm_dbus_nm_wake);
	nm_dbus_method_list_add_method (list, "state",				nm_dbus_nm_get_state);
	nm_dbus_method_list_add_method (list, "createTestDevice",		nm_dbus_nm_create_test_device);
	nm_dbus_method_list_add_method (list, "removeTestDevice",		nm_dbus_nm_remove_test_device);

	return (list);
}
