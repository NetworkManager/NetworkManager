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
static DBusMessage *
nm_dbus_nm_get_devices (DBusConnection *connection,
                        DBusMessage *message,
                        void * user_data)
{
	NMData *		data = (NMData *) user_data;
	DBusMessage *	reply = NULL;
	DBusMessageIter	iter;
	DBusMessageIter	iter_array;
	GSList	*       elt;

	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	/* Check for no devices */
	if (!data->dev_list) {
		return nm_dbus_create_error_message (message,
		                                     NM_DBUS_INTERFACE,
		                                     "NoDevices",
		                                     "There are no available network devices.");
	}

	if (!(reply = dbus_message_new_method_return (message))) {
		nm_warning ("Not enough memory to create dbus message.");
		return NULL;
	}

	dbus_message_iter_init_append (reply, &iter);
	dbus_message_iter_open_container (&iter,
	                                  DBUS_TYPE_ARRAY,
	                                  DBUS_TYPE_OBJECT_PATH_AS_STRING,
	                                  &iter_array);

	for (elt = data->dev_list; elt; elt = g_slist_next (elt)) {
		NMDevice *	dev = NM_DEVICE (elt->data);
		char *		op = nm_dbus_get_object_path_for_device (dev);

		dbus_message_iter_append_basic (&iter_array, DBUS_TYPE_OBJECT_PATH, &op);
		g_free (op);
	}

	dbus_message_iter_close_container (&iter, &iter_array);

	return reply;
}


static DBusMessage *
nm_dbus_nm_get_dialup (DBusConnection *connection,
                       DBusMessage *message,
                       void * user_data)
{
	NMData * data = (NMData *) user_data;
	DBusMessage * reply = NULL;
	DBusMessageIter iter;
	DBusMessageIter iter_array;
	GSList *        elt;

	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	/* Check for no dialup devices */
	if (!data->dialup_list) {
		return nm_dbus_create_error_message (message,
		                                     NM_DBUS_INTERFACE,
		                                     "NoDialup",
		                                     "There are no available dialup devices.");
	}

	if (!(reply = dbus_message_new_method_return (message))) {
		nm_warning ("Not enough memory to create dbus message.");
		return NULL;
	}

	dbus_message_iter_init_append (reply, &iter);
	dbus_message_iter_open_container (&iter,
	                                  DBUS_TYPE_ARRAY,
	                                  DBUS_TYPE_STRING_AS_STRING,
	                                  &iter_array);

	for (elt = data->dialup_list; elt; elt = g_slist_next (elt)) {
		NMDialUpConfig *config = (NMDialUpConfig *) elt->data;
		dbus_message_iter_append_basic (&iter_array,
		                                DBUS_TYPE_STRING, &config->name);
	}

	dbus_message_iter_close_container (&iter, &iter_array);

	return reply;
}


static DBusMessage *
nm_dbus_nm_activate_dialup (DBusConnection *connection,
                            DBusMessage *message,
                            void * user_data)
{
	NMData *data = (NMData *) user_data;
	DBusMessage *reply = NULL;
	const char *dialup;

	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	if (!(reply = dbus_message_new_method_return (message))) {
		nm_warning ("Not enough memory to create dbus message.");
		return NULL;
	}

	if (!dbus_message_get_args (message, NULL, DBUS_TYPE_STRING, &dialup, DBUS_TYPE_INVALID))
	{
		reply = nm_dbus_new_invalid_args_error (message, NM_DBUS_INTERFACE);
		goto out;
	}

	if (!nm_system_activate_dialup (data->dialup_list, dialup)) {
		reply = nm_dbus_create_error_message (message,
		                                      NM_DBUS_INTERFACE,
		                                      "ActivationFailed",
		                                      "Failed to activate the dialup "
		                                      "device.");
	} else {
		data->modem_active = TRUE;
	}

out:
	return reply;
}


static DBusMessage *
nm_dbus_nm_deactivate_dialup (DBusConnection *connection,
                              DBusMessage *message,
                              void * user_data)
{
	NMData *data = (NMData *) user_data;
	DBusMessage *reply = NULL;
	const char *dialup;

	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	if (!(reply = dbus_message_new_method_return (message))) {
		nm_warning ("Not enough memory to create dbus message.");
		return NULL;
	}

	if (!dbus_message_get_args (message,
	                            NULL,
	                            DBUS_TYPE_STRING, &dialup,
	                            DBUS_TYPE_INVALID)) {
		reply = nm_dbus_new_invalid_args_error (message, NM_DBUS_INTERFACE);
		goto out;
	}

	if (!nm_system_deactivate_dialup (data->dialup_list, dialup)) {
		reply = nm_dbus_create_error_message (message,
		                                      NM_DBUS_INTERFACE,
		                                      "DeactivationFailed",
		                                      "Failed to deactivate the dialup "
		                                      " device.");
	} else {
		data->modem_active = FALSE;
	}

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
static DBusMessage *
nm_dbus_nm_set_active_device (DBusConnection *connection,
                              DBusMessage *message,
                              void * user_data)
{
	NMData *		data = (NMData *) user_data;
	NMDevice *		dev = NULL;
	DBusMessage *		reply = NULL;
	char *			dev_path;
	NMAccessPoint *	ap = NULL;
	DBusMessageIter	iter;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);
	g_return_val_if_fail (data != NULL, NULL);

	dbus_message_iter_init (message, &iter);

	if (dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_OBJECT_PATH) {
		nm_warning ("%s:%d (%s): Invalid arguments (first arg type was not OBJECT_PATH).",
					__FILE__, __LINE__, __func__);
		goto out;
	}

	dbus_message_iter_get_basic (&iter, &dev_path);
	dev = nm_dbus_get_device_from_escaped_object_path (data, dev_path);

	/* Ensure the device exists in our list and is supported */
	if (!dev || !(nm_device_get_capabilities (dev) & NM_DEVICE_CAP_NM_SUPPORTED)) {
		reply = nm_dbus_create_error_message (message,
		                                      NM_DBUS_INTERFACE,
		                                      "DeviceNotFound",
		                                      "The requested network device "
		                                      "does not exist.");
		nm_warning ("%s:%d (%s): Invalid device (device not found).", __FILE__,
		            __LINE__, __func__);
		goto out;
	}

	if (nm_device_is_802_11_wireless (dev)) {
		NMAPSecurity * 	security = NULL;
		char *			essid = NULL;
		gboolean			fallback = FALSE;

		if (   !dbus_message_iter_next (&iter)
		    || (dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_STRING)) {
			nm_warning ("%s:%d (%s): Invalid argument type (essid).", __FILE__,
			            __LINE__, __func__);
			goto out;
		}

		/* grab ssid and ensure validity */
		dbus_message_iter_get_basic (&iter, &essid);
		if (!essid || (strlen (essid) <= 0)) {
			nm_warning ("%s:%d (%s): Invalid argument (essid).",
			            __FILE__, __LINE__, __func__);
			goto out;
		}

		if (   !dbus_message_iter_next (&iter)
		    || (dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_BOOLEAN)) {
			nm_warning ("Invalid argument type (fallback");
			goto out;
		}

		/* grab the fallback bit */
		dbus_message_iter_get_basic (&iter, &fallback);

		/* If there's security information, we use that.  If not, we
		 * make some up from the scan list.
		 */
		if (dbus_message_iter_next (&iter)) {
			if (!(security = nm_ap_security_new_deserialize (&iter))) {
				/* There was security info, but it was invalid */
				reply = nm_dbus_new_invalid_args_error (message, NM_DBUS_INTERFACE);
				nm_warning ("%s:%d (%s): Invalid argument (wireless security "
				            "info).", __FILE__, __LINE__, __func__);
				goto out;
			}
		}

		/* Set up the wireless-specific activation request properties */
		ap = nm_device_802_11_wireless_get_activation_ap (NM_DEVICE_802_11_WIRELESS (dev), essid, security);
		nm_ap_set_fallback (ap, fallback);
		if (security)
	 		g_object_unref (G_OBJECT (security));

		nm_info ("User Switch: %s / %s", dev_path, essid);
	} else if (nm_device_is_802_3_ethernet (dev)) {
		nm_info ("User Switch: %s", dev_path);
	}

	nm_device_deactivate (dev);
	nm_schedule_state_change_signal_broadcast (data);
	nm_policy_schedule_device_activation (nm_act_request_new (data, dev, ap, TRUE));

	/* empty success message */
	reply = dbus_message_new_method_return (message);
	if (!reply)
		nm_warning ("Could not allocate dbus message.");

out:
	if (dev)
		g_object_unref (G_OBJECT (dev));
	if (!reply)
		reply = nm_dbus_new_invalid_args_error (message, NM_DBUS_INTERFACE);

	return reply;
}

/*
 * nm_dbus_nm_create_wireless_network
 *
 * Create a new wireless network and 
 *
 */
static DBusMessage *
nm_dbus_nm_create_wireless_network (DBusConnection *connection,
                                    DBusMessage *message,
                                    void * user_data)
{
	NMData *		data = (NMData *) user_data;
	NMDevice *		dev = NULL;
	DBusMessage *		reply = NULL;
	char *			dev_path = NULL;
	NMAccessPoint *	new_ap = NULL;
	NMAPSecurity * 	security = NULL;
	char *			essid = NULL;
	DBusMessageIter	iter;
	NMActRequest *	req;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);
	g_return_val_if_fail (data != NULL, NULL);

	dbus_message_iter_init (message, &iter);

	if (dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_OBJECT_PATH) {
		reply = nm_dbus_new_invalid_args_error (message, NM_DBUS_INTERFACE);
		goto out;
	}

	dbus_message_iter_get_basic (&iter, &dev_path);
	dev = nm_dbus_get_device_from_escaped_object_path (data, dev_path);

	/* Ensure the device exists in our list and is supported */
	if (!dev || !(nm_device_get_capabilities (dev) & NM_DEVICE_CAP_NM_SUPPORTED)) {
		reply = nm_dbus_create_error_message (message,
		                                      NM_DBUS_INTERFACE,
		                                      "DeviceNotFound",
		                                      "The requested network device "
		                                      "does not exist.");
		goto out;
	}

	if (   !nm_device_is_802_11_wireless (dev)
		|| !dbus_message_iter_next (&iter)
		|| (dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_STRING)) {
		reply = nm_dbus_new_invalid_args_error (message, NM_DBUS_INTERFACE);
		goto out;
	}

	/* grab ssid and ensure validity */
	dbus_message_iter_get_basic (&iter, &essid);
	if (!essid || (strlen (essid) <= 0) || !dbus_message_iter_next (&iter)) {
		reply = nm_dbus_new_invalid_args_error (message, NM_DBUS_INTERFACE);
		goto out;
	}

	if (!(security = nm_ap_security_new_deserialize (&iter))) {
		reply = nm_dbus_new_invalid_args_error (message, NM_DBUS_INTERFACE);
		goto out;
	}

	nm_info ("Creating network '%s' on device '%s'.", essid, dev_path);

	new_ap = nm_ap_new ();
	nm_ap_set_essid (new_ap, essid);
	nm_ap_set_mode (new_ap, IW_MODE_ADHOC);
	nm_ap_set_security (new_ap, security);
	g_object_unref (G_OBJECT (security));
	nm_ap_set_user_created (new_ap, TRUE);

	req = nm_act_request_new (data, dev, new_ap, TRUE);
	nm_policy_schedule_device_activation (req);

out:
	if (dev)
		g_object_unref (G_OBJECT (dev));
	return reply;
}


static DBusMessage *
nm_dbus_nm_create_test_device (DBusConnection *connection,
                               DBusMessage *message,
                               void * user_data)
{
	NMData *		data = (NMData *) user_data;
	NMDeviceType	type;
	DBusMessage	*reply = NULL;
	static int	 test_dev_num = 0;
	NMDevice *		dev;
	char *			iface;
	char *			udi;
	char *			dev_path;
	char *			escaped_dev_path;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);
	g_return_val_if_fail (data != NULL, NULL);

	if (!dbus_message_get_args (message,
	                            NULL,
	                            DBUS_TYPE_INT32, &type,
	                            DBUS_TYPE_INVALID)) {
		reply = nm_dbus_new_invalid_args_error (message, NM_DBUS_INTERFACE);
		goto out;
	}

	if (   (type != DEVICE_TYPE_802_3_ETHERNET)
	    && (type == DEVICE_TYPE_802_11_WIRELESS)) {
		reply = nm_dbus_new_invalid_args_error (message, NM_DBUS_INTERFACE);
		goto out;
	}

	if (!(reply = dbus_message_new_method_return (message))) {
		nm_warning ("Not enough memory to create dbus message.");
		goto out;
	}

	iface = g_strdup_printf ("test%d", test_dev_num);
	udi = g_strdup_printf ("/test-devices/%s", iface);

	dev = nm_create_device_and_add_to_list (data, udi, iface, TRUE, type);
	g_free (iface);
	g_free (udi);

	test_dev_num++;

	dev_path = g_strdup_printf ("%s/%s", NM_DBUS_PATH_DEVICES, nm_device_get_iface (dev));
	escaped_dev_path = nm_dbus_escape_object_path (dev_path);
	g_free (dev_path);

	dbus_message_append_args (reply, DBUS_TYPE_STRING, &escaped_dev_path, DBUS_TYPE_INVALID);
	g_free (escaped_dev_path);

out:
	return reply;
}

static DBusMessage *
nm_dbus_nm_remove_test_device (DBusConnection *connection,
                               DBusMessage *message,
                               void * user_data)
{
	NMData *	data = (NMData *) user_data;
	DBusMessage	*reply = NULL;
	char *		dev_path;
	NMDevice *	dev = NULL;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);
	g_return_val_if_fail (data != NULL, NULL);

	if (!dbus_message_get_args (message,
	                            NULL,
	                            DBUS_TYPE_STRING, &dev_path,
	                            DBUS_TYPE_INVALID)) {
		reply = nm_dbus_new_invalid_args_error (message, NM_DBUS_INTERFACE);
		goto out;
	}

	if (!(dev = nm_dbus_get_device_from_escaped_object_path (data, dev_path))) {
		reply = nm_dbus_new_invalid_args_error (message, NM_DBUS_INTERFACE);
		goto out;
	}

	if (!nm_device_is_test_device (dev)) {
		reply = nm_dbus_create_error_message (message,
		                                      NM_DBUS_INTERFACE,
		                                      "NotTestDevice",
		                                      "Only test devices can be removed"
		                                      " via the DBus interface.");
		goto out;
	}

	nm_remove_device (data, dev);

out:
	if (dev)
		g_object_unref (G_OBJECT (dev));
	return reply;
}

static DBusMessage *
nm_dbus_nm_set_wireless_enabled (DBusConnection *connection,
                                 DBusMessage *message,
                                 void * user_data)
{
	NMData *		data = (NMData *) user_data;
	gboolean		enabled = FALSE;
	DBusMessage *	reply = NULL;
	GSList *        elt;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);
	g_return_val_if_fail (data != NULL, NULL);

	if (!dbus_message_get_args (message,
	                            NULL,
	                            DBUS_TYPE_BOOLEAN, &enabled,
	                            DBUS_TYPE_INVALID)) {
		reply = nm_dbus_new_invalid_args_error (message, NM_DBUS_INTERFACE);
		goto out;
	}

	data->wireless_enabled = enabled;

	if (!enabled) {
		/* Down all wireless devices */
		for (elt = data->dev_list; elt; elt = g_slist_next (elt)) {
			NMDevice * dev = NM_DEVICE (elt->data);

			if (nm_device_is_802_11_wireless (dev)) {
				nm_device_deactivate (dev);
				nm_device_bring_down (dev);
			}
		}
	}

	nm_policy_schedule_device_change_check (data);

out:
	return reply;
}

static DBusMessage *
nm_dbus_nm_get_wireless_enabled (DBusConnection *connection,
                                 DBusMessage *message,
                                 void * user_data)
{
	NMData * data = (NMData *) user_data;
	DBusMessage	*reply = NULL;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);
	g_return_val_if_fail (data != NULL, NULL);

	if ((reply = dbus_message_new_method_return (message))) {
		dbus_message_append_args (reply,
		                          DBUS_TYPE_BOOLEAN, &data->wireless_enabled,
		                          DBUS_TYPE_INVALID);
	}

	return reply;
}

static DBusMessage *
nm_dbus_nm_sleep (DBusConnection *connection,
                  DBusMessage *message,
                  void * user_data)
{
	NMData * data = (NMData *) user_data;
	GSList * elt;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);
	g_return_val_if_fail (data != NULL, NULL);

	if (data->asleep)
		return NULL;

	nm_info ("Going to sleep.");
	data->asleep = TRUE;

	/* Not using nm_schedule_state_change_signal_broadcast() here
	 * because we want the signal to go out ASAP.
	 */
	nm_dbus_signal_state_change (connection, data);

	/* Just deactivate and down all devices from the device list,
	 * we'll remove them in 'wake' for speed's sake.
	 */
	for (elt = data->dev_list; elt; elt = g_slist_next (elt)) {
		NMDevice *dev = NM_DEVICE (elt->data);
		nm_device_set_removed (dev, TRUE);
		nm_device_deactivate_quickly (dev);
		nm_system_device_set_up_down (dev, FALSE);
	}

	nm_system_deactivate_all_dialup (data->dialup_list);
	data->modem_active = FALSE;

	return NULL;
}

static DBusMessage *
nm_dbus_nm_wake (DBusConnection *connection,
                 DBusMessage *message,
                 void * user_data)
{
	NMData * data = (NMData *) user_data;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);
	g_return_val_if_fail (data != NULL, NULL);

	if (!data->asleep)
		return NULL;

	nm_info  ("Waking up from sleep.");
	data->asleep = FALSE;

	/* Remove all devices from the device list */
	while (g_slist_length (data->dev_list))
		nm_remove_device (data, NM_DEVICE (data->dev_list->data));
	g_slist_free (data->dev_list);
	data->dev_list = NULL;

	nm_add_initial_devices (data);

	nm_schedule_state_change_signal_broadcast (data);
	nm_policy_schedule_device_change_check (data);

	return NULL;
}

static DBusMessage *
nm_dbus_nm_get_state (DBusConnection *connection,
                      DBusMessage *message,
                      void * user_data)
{
	NMData *	data = (NMData *) user_data;
	DBusMessage *	reply = NULL;
	NMState		state;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);
	g_return_val_if_fail (data != NULL, NULL);

	if (!(reply = dbus_message_new_method_return (message))) {
		nm_warning ("Not enough memory to create dbus message.");
		goto out;
	}

	state = nm_get_app_state_from_data (data);
	dbus_message_append_args (reply, DBUS_TYPE_UINT32, &state, DBUS_TYPE_INVALID);

out:
	return reply;
}


/*
 * nm_dbus_nm_methods_setup
 *
 * Register handlers for dbus methods on the org.freedesktop.NetworkManager object.
 *
 */
NMDbusMethodList *nm_dbus_nm_methods_setup (NMData *data)
{
	NMDbusMethodList * list;

	g_return_val_if_fail (data != NULL, NULL);

	list = nm_dbus_method_list_new (NM_DBUS_PATH, FALSE, data, NULL);

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

	return list;
}
