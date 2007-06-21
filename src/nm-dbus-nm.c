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
#include "nm-ap-security.h"
#include "nm-device-802-3-ethernet.h"
#include "nm-device-802-11-wireless.h"


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
	if (nm_try_acquire_mutex (data->data->dev_list_mutex, __FUNCTION__))
	{
		GSList	*elt;

		dbus_message_iter_open_container (&iter, DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH_AS_STRING, &iter_array);
		for (elt = data->data->dev_list; elt; elt = g_slist_next (elt))
		{
			NMDevice	*dev = (NMDevice *)(elt->data);

			if (dev)
			{
				char *op = nm_dbus_get_object_path_for_device (dev);

				dbus_message_iter_append_basic (&iter_array, DBUS_TYPE_OBJECT_PATH, &op);
				g_free (op);
			}
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
	else
		nm_data->modem_active = TRUE;
	nm_unlock_mutex (nm_data->dialup_list_mutex, __FUNCTION__);

out:
	return reply;
}


static DBusMessage *nm_dbus_nm_deactivate_dialup (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
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
									   "NetworkManager::deactivateDialup called with invalid arguments.");
		goto out;
	}

	nm_lock_mutex (nm_data->dialup_list_mutex, __FUNCTION__);
	if (!nm_system_deactivate_dialup (nm_data->dialup_list, dialup))
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "DeactivationFailed",
									   "Failed to deactivate the dialup device.");
	else
		nm_data->modem_active = FALSE;
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
	const char * INVALID_ARGS_ERROR = "InvalidArguments";
	const char * INVALID_ARGS_MESSAGE = "NetworkManager::setActiveDevice called with invalid arguments.";
	NMDevice *		dev = NULL;
	DBusMessage *		reply = NULL;
	char *			dev_path;
	NMAccessPoint *	ap = NULL;
	NMActRequest * req;
	DBusMessageIter	iter;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);
	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (data->data != NULL, NULL);

	dbus_message_iter_init (message, &iter);

	if (dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_OBJECT_PATH)
	{
		nm_warning ("%s:%d (%s): Invalid arguments (first arg type was not OBJECT_PATH).",
					__FILE__, __LINE__, __func__);
		goto out;
	}

	dbus_message_iter_get_basic (&iter, &dev_path);
	dev = nm_dbus_get_device_from_escaped_object_path (data->data, dev_path);

	/* Ensure the device exists in our list and is supported */
	if (!dev || !(nm_device_get_capabilities (dev) & NM_DEVICE_CAP_NM_SUPPORTED))
	{
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "DeviceNotFound",
						"The requested network device does not exist.");
		nm_warning ("%s:%d (%s): Invalid device (device not found).", __FILE__, __LINE__, __func__);
		goto out;
	}

	if (nm_device_is_802_11_wireless (dev))
	{
		NMAPSecurity * 	security = NULL;
		char *			essid = NULL;

		if (!dbus_message_iter_next (&iter) || (dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_STRING))
		{
			nm_warning ("%s:%d (%s): Invalid argument type (essid).", __FILE__, __LINE__, __func__);
			goto out;
		}

		/* grab ssid and ensure validity */
		dbus_message_iter_get_basic (&iter, &essid);
		if (!essid || (strlen (essid) <= 0))
		{
			nm_warning ("%s:%d (%s): Invalid argument (essid).", __FILE__, __LINE__, __func__);
			goto out;
		}

		/* If there's security information, we use that.  If not, we
		 * make some up from the scan list.
		 */
		if (dbus_message_iter_next (&iter))
		{
			if (!(security = nm_ap_security_new_deserialize (&iter)))
			{
				/* There was security info, but it was invalid */
				reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, INVALID_ARGS_ERROR, INVALID_ARGS_MESSAGE);
				nm_warning ("%s:%d (%s): Invalid argument (wireless security info).", __FILE__, __LINE__, __func__);
				goto out;
			}
		}

		/* Set up the wireless-specific activation request properties */
		ap = nm_device_802_11_wireless_get_activation_ap (NM_DEVICE_802_11_WIRELESS (dev), essid, security);
		if (security)
	 		g_object_unref (G_OBJECT (security));

		nm_info ("User Switch: %s / %s", dev_path, essid);
	}
	else if (nm_device_is_802_3_ethernet (dev))
	{
		nm_info ("User Switch: %s", dev_path);
	}

	nm_device_deactivate (dev);
	nm_schedule_state_change_signal_broadcast (data->data);
	req = nm_act_request_new (data->data, dev, ap, TRUE);
	nm_policy_schedule_device_activation (req);
	nm_act_request_unref (req);

	/* empty success message */
	reply = dbus_message_new_method_return (message);
	if (!reply)
		nm_warning ("Could not allocate dbus message.");

out:
	if (!reply)
	{
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE,
						INVALID_ARGS_ERROR, INVALID_ARGS_MESSAGE);
	}

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
	const char *		INVALID_ARGS_ERROR = "InvalidArguments";
	const char *		INVALID_ARGS_MESSAGE = "NetworkManager::createWirelessNetwork called with invalid arguments.";
	NMDevice *		dev = NULL;
	DBusMessage *		reply = NULL;
	char *			dev_path = NULL;
	NMAccessPoint *	new_ap = NULL;
	NMAPSecurity * 	security = NULL;
	char *			essid = NULL;
	NMActRequest * req;
	DBusMessageIter	iter;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);
	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (data->data != NULL, NULL);

	dbus_message_iter_init (message, &iter);

	if (dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_OBJECT_PATH)
	{
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, INVALID_ARGS_ERROR, INVALID_ARGS_MESSAGE);
		goto out;
	}

	dbus_message_iter_get_basic (&iter, &dev_path);
	dev = nm_dbus_get_device_from_escaped_object_path (data->data, dev_path);

	/* Ensure the device exists in our list and is supported */
	if (!dev || !(nm_device_get_capabilities (dev) & NM_DEVICE_CAP_NM_SUPPORTED))
	{
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "DeviceNotFound",
						"The requested network device does not exist.");
		goto out;
	}

	if (    !nm_device_is_802_11_wireless (dev)
		|| !dbus_message_iter_next (&iter)
		|| (dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_STRING))
	{
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, INVALID_ARGS_ERROR, INVALID_ARGS_MESSAGE);
		goto out;
	}

	/* grab ssid and ensure validity */
	dbus_message_iter_get_basic (&iter, &essid);
	if (!essid || (strlen (essid) <= 0) || !dbus_message_iter_next (&iter))
	{
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, INVALID_ARGS_ERROR, INVALID_ARGS_MESSAGE);
		goto out;
	}

	if (!(security = nm_ap_security_new_deserialize (&iter)))
	{
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, INVALID_ARGS_ERROR, INVALID_ARGS_MESSAGE);
		goto out;
	}

	nm_info ("Creating network '%s' on device '%s'.", essid, dev_path);

	new_ap = nm_ap_new ();
	nm_ap_set_essid (new_ap, essid);
	nm_ap_set_mode (new_ap, IW_MODE_ADHOC);
	nm_ap_set_security (new_ap, security);
	g_object_unref (G_OBJECT (security));
	nm_ap_set_user_created (new_ap, TRUE);

	req = nm_act_request_new (data->data, dev, new_ap, TRUE);
	nm_policy_schedule_device_activation (req);
	nm_act_request_unref (req);

out:
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
		&& ((type == DEVICE_TYPE_802_3_ETHERNET) || (type == DEVICE_TYPE_802_11_WIRELESS)))
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

		if ((dev = nm_dbus_get_device_from_escaped_object_path (data->data, dev_path)))
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

static DBusMessage *nm_dbus_nm_set_wireless_enabled (DBusConnection *connection, DBusMessage *message, NMDbusCBData *cb_data)
{
	gboolean	enabled = FALSE;
	DBusError	err;
	NMData	*	data;
	DBusMessage * ret = NULL;

	g_return_val_if_fail (cb_data && cb_data->data && connection && message, NULL);

	dbus_error_init (&err);
	if (!dbus_message_get_args (message, &err, DBUS_TYPE_BOOLEAN, &enabled, DBUS_TYPE_INVALID))
		goto out;

	data = cb_data->data;
	if (enabled == data->wireless_enabled)
		goto out;

	/* Hardware rfkill overrides whatever user wants */
	if (!data->hw_rf_enabled) {
		nm_info ("User request to %s wireless overridden by radio killswitch.",
		         enabled ? "enable" : "disable");

		/* Return error if user tries to re-enable wireless, or just ignore
		 * a disable wireless request when wireless is already disabled.
		 */
		if (enabled) {
			ret = nm_dbus_create_error_message (message,
			                                    NM_DBUS_INTERFACE,
			                                    "DisabledBySystem",
			                                    "Wireless disabled by hardware switch.");
		}
		goto out;
	}

	nm_info ("User request to %s wireless.", enabled ? "enable" : "disable");

	data->wireless_enabled = enabled;
	if (!data->wireless_enabled) {
		GSList * elt;

		/* Deactivate all wireless devices and force them down so they
		 * turn off their radios.
		 */
		nm_lock_mutex (data->dev_list_mutex, __FUNCTION__);
		for (elt = data->dev_list; elt; elt = g_slist_next (elt)) {
			NMDevice * dev = (NMDevice *) elt->data;
			if (nm_device_is_802_11_wireless (dev)) {
				nm_device_deactivate (dev);
				nm_device_bring_down (dev);
			}
		}
		nm_unlock_mutex (data->dev_list_mutex, __FUNCTION__);
	}

	nm_policy_schedule_device_change_check (data);
	nm_dbus_signal_wireless_enabled (data);

out:
	return ret;
}

static DBusMessage *nm_dbus_nm_get_wireless_enabled (DBusConnection *connection, DBusMessage *message, NMDbusCBData *cb_data)
{
	NMData * data;
	DBusMessage	*reply = NULL;

	g_return_val_if_fail (cb_data && connection && message, NULL);

	data = cb_data->data;
	g_return_val_if_fail (data != NULL, NULL);

	if ((reply = dbus_message_new_method_return (message))) {
		dbus_message_append_args (reply,
		                          DBUS_TYPE_BOOLEAN, &data->wireless_enabled,
		                          DBUS_TYPE_BOOLEAN, &data->hw_rf_enabled,
		                          DBUS_TYPE_INVALID);
	}

	return reply;
}

static DBusMessage *nm_dbus_nm_sleep (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	NMData	*app_data;

	g_return_val_if_fail (data && data->data && connection && message, NULL);

	app_data = data->data;
	if (app_data->asleep == FALSE)
	{
		GSList *elt;
		DBusMessageIter iter;

		dbus_message_iter_init (message, &iter);

		switch (dbus_message_iter_get_arg_type (&iter)) {
		case DBUS_TYPE_INVALID:
			/* The boolean argument to differentiate between sleep and disabling networking
			   is optional and defaults to sleep */
			app_data->disconnected = FALSE;
			break;
		case DBUS_TYPE_BOOLEAN:
			dbus_message_iter_get_basic (&iter, &app_data->disconnected);
			break;
		default:
			return nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "InvalidArguments",
												 "NetworkManager::sleep called with invalid arguments.");
			break;
		}

		if (app_data->disconnected)
			nm_info ("Disconnected.");
		else
			nm_info ("Going to sleep.");

		app_data->asleep = TRUE;
		/* Not using nm_schedule_state_change_signal_broadcast() here
		 * because we want the signal to go out ASAP.
		 */
		nm_dbus_signal_state_change (connection, app_data);

		/* Remove all devices from the device list */
		nm_lock_mutex (app_data->dev_list_mutex, __FUNCTION__);
		for (elt = app_data->dev_list; elt; elt = g_slist_next (elt))
		{
			NMDevice *dev = (NMDevice *)(elt->data);
			nm_device_set_removed (dev, TRUE);
			nm_device_deactivate_quickly (dev);
			nm_system_device_set_up_down (dev, FALSE);
		}
		nm_unlock_mutex (app_data->dev_list_mutex, __FUNCTION__);

		nm_lock_mutex (app_data->dialup_list_mutex, __FUNCTION__);
		nm_system_deactivate_all_dialup (app_data->dialup_list);
		app_data->modem_active = FALSE;
		nm_unlock_mutex (app_data->dialup_list_mutex, __FUNCTION__);
	}

	return NULL;
}

static DBusMessage *nm_dbus_nm_wake (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	NMData	*app_data;
	DBusMessageIter iter;
	gboolean enable_networking = FALSE;

	g_return_val_if_fail (data && data->data && connection && message, NULL);

	dbus_message_iter_init (message, &iter);

	switch (dbus_message_iter_get_arg_type (&iter)) {
	case DBUS_TYPE_INVALID:
		/* The boolean argument to differentiate between wake up from sleep and
		   enabling networking is optional and defaults to wake up. */
		break;
	case DBUS_TYPE_BOOLEAN:
		dbus_message_iter_get_basic (&iter, &enable_networking);
		break;
	default:
		return nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "InvalidArguments",
											 "NetworkManager::wake called with invalid arguments.");
		break;
	}

	app_data = data->data;
	/* Restore networking only if we're not disconnected or
	   enable_networking argument is passed. */
	if (app_data->asleep && (!app_data->disconnected || enable_networking)) {
		if (enable_networking)
			nm_info ("Enabling networking.");
		else
			nm_info ("Waking up from sleep.");

		app_data->asleep = app_data->disconnected = FALSE;

		/* Remove all devices from the device list */
		nm_lock_mutex (app_data->dev_list_mutex, __FUNCTION__);
		while (g_slist_length (app_data->dev_list))
			nm_remove_device (app_data, (NMDevice *)(app_data->dev_list->data));
		nm_unlock_mutex (app_data->dev_list_mutex, __FUNCTION__);

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
	nm_dbus_method_list_add_method (list, "deactivateDialup",		nm_dbus_nm_deactivate_dialup);
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
