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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib/gi18n.h>
#include <stdio.h>
#include <string.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include "applet-dbus-devices.h"
#include "applet-dbus.h"
#include "applet.h"
#include "vpn-connection.h"
#include "nm-utils.h"

void nmwa_dbus_devices_schedule_copy (NMWirelessApplet *applet);


/*
 * nmwa_dbus_nm_state_cb
 *
 * Callback from nmwa_dbus_update_nm_state
 *
 */
static void nmwa_dbus_nm_state_cb (DBusPendingCall *pcall, void *user_data)
{
	DBusMessage *		reply;
	NMWirelessApplet *	applet = (NMWirelessApplet *) user_data;
	NMState			nm_state;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (applet != NULL);

	dbus_pending_call_ref (pcall);

	if (!dbus_pending_call_get_completed (pcall))
		goto out;

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (message_is_error (reply))
	{
		dbus_message_unref (reply);
		goto out;
	}

	if (dbus_message_get_args (reply, NULL, DBUS_TYPE_UINT32, &nm_state, DBUS_TYPE_INVALID))
	{
		applet->dbus_nm_state = nm_state;
		applet->gui_nm_state = nm_state;
	}
	dbus_message_unref (reply);

out:
	applet->dev_pending_call_list = g_slist_remove (applet->dev_pending_call_list, pcall);
	nmwa_dbus_devices_schedule_copy (applet);

	dbus_pending_call_unref (pcall);
}


/*
 * nmwa_dbus_update_nm_state
 *
 * Update internal applet state from NetworkManager state
 *
 */
void nmwa_dbus_update_nm_state (NMWirelessApplet *applet)
{
	DBusMessage *		message;
	DBusPendingCall *	pcall = NULL;

	g_return_if_fail (applet != NULL);

	if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH, NM_DBUS_INTERFACE, "state")))
	{
		dbus_connection_send_with_reply (applet->connection, message, &pcall, -1);
		dbus_message_unref (message);
		if (pcall)
		{
			dbus_pending_call_set_notify (pcall, nmwa_dbus_nm_state_cb, applet, NULL);
			applet->dev_pending_call_list = g_slist_append (applet->dev_pending_call_list, pcall);
		}
	}
}


/*
 * nmwa_dbus_update_wireless_enabled_cb
 *
 * Callback from nmwa_dbus_update_wireless_enabled
 *
 */
static void nmwa_dbus_update_wireless_enabled_cb (DBusPendingCall *pcall, void *user_data)
{
	DBusMessage *		reply;
	NMWirelessApplet *	applet = (NMWirelessApplet *) user_data;
	gboolean			wireless_enabled;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (applet != NULL);

	dbus_pending_call_ref (pcall);

	if (!dbus_pending_call_get_completed (pcall))
		goto out;

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (message_is_error (reply))
	{
		dbus_message_unref (reply);
		goto out;
	}

	if (dbus_message_get_args (reply, NULL, DBUS_TYPE_BOOLEAN, &wireless_enabled, DBUS_TYPE_INVALID))
		applet->wireless_enabled = wireless_enabled;
	dbus_message_unref (reply);

out:
	dbus_pending_call_unref (pcall);
}


/*
 * nmwa_dbus_update_wireless_enabled
 *
 * Get the wireless_enabled value from NetworkManager
 *
 */
static void nmwa_dbus_update_wireless_enabled (NMWirelessApplet *applet)
{
	DBusMessage *		message;
	DBusPendingCall *	pcall = NULL;

	g_return_if_fail (applet != NULL);

	if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH, NM_DBUS_INTERFACE, "getWirelessEnabled")))
	{
		dbus_connection_send_with_reply (applet->connection, message, &pcall, -1);
		dbus_message_unref (message);
		if (pcall)
			dbus_pending_call_set_notify (pcall, nmwa_dbus_update_wireless_enabled_cb, applet, NULL);
	}
}


/*
 * nmwa_dbus_get_hal_device_string_property
 *
 * Get a string property from a device
 *
 */
static char *nmwa_dbus_get_hal_device_string_property (DBusConnection *connection, const char *udi, const char *property_name)
{
	DBusError		 error;
	DBusMessage	*message;
	DBusMessage	*reply;
	char			*dbus_property = NULL;
	char			*property = NULL;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (udi != NULL, NULL);

	if (!(message = dbus_message_new_method_call ("org.freedesktop.Hal", udi, "org.freedesktop.Hal.Device", "GetPropertyString")))
		return (NULL);

	dbus_error_init (&error);
	dbus_message_append_args (message, DBUS_TYPE_STRING, &property_name, DBUS_TYPE_INVALID);
	reply = dbus_connection_send_with_reply_and_block (connection, message, -1, &error);
	dbus_message_unref (message);
	if (dbus_error_is_set (&error))
	{
		nm_warning ("nmwa_dbus_get_hal_device_string_property(): %s raised:\n %s\n\n", error.name, error.message);
		dbus_error_free (&error);
		return (NULL);
	}
	if (reply == NULL)
	{
		nm_warning ("nmwa_dbus_get_hal_device_string_property(): dbus reply message was NULL\n" );
		return (NULL);
	}

	dbus_error_init (&error);
	if (!dbus_message_get_args (reply, &error, DBUS_TYPE_STRING, &dbus_property, DBUS_TYPE_INVALID))
	{
		if (dbus_error_is_set (&error))
			dbus_error_free (&error);
	}
	else
		property = g_strdup (dbus_property);

	dbus_message_unref (reply);	
	return (property);
}


typedef struct HalInfoCBData
{
	NMWirelessApplet *	applet;
	NetworkDevice *	dev;
	char *			parent_op;
	char *			vendor;
} HalInfoCBData;

static void free_hal_info_cb_data (HalInfoCBData *cb_data)
{
	if (cb_data)
	{
		network_device_unref (cb_data->dev);
		g_free (cb_data->parent_op);
		g_free (cb_data->vendor);
		memset (cb_data, 0, sizeof (HalInfoCBData));
		g_free (cb_data);
	}
}


/*
 * hal_info_product_cb
 *
 * hal_info_vendor callback
 *
 */
static void hal_info_product_cb (DBusPendingCall *pcall, void *user_data)
{
	DBusMessage *		reply;
	HalInfoCBData *	cb_data = (HalInfoCBData *) user_data;
	char *			info_product;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (cb_data != NULL);
	g_return_if_fail (cb_data->applet != NULL);
	g_return_if_fail (cb_data->dev != NULL);
	g_return_if_fail (cb_data->parent_op != NULL);
	g_return_if_fail (cb_data->vendor != NULL);

	dbus_pending_call_ref (pcall);

	if (!dbus_pending_call_get_completed (pcall))
		goto out;

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (message_is_error (reply))
	{
		dbus_message_unref (reply);
		goto out;
	}

	if (dbus_message_get_args (reply, NULL, DBUS_TYPE_STRING, &info_product, DBUS_TYPE_INVALID))
	{
		char *desc = g_strdup_printf ("%s %s", cb_data->vendor, info_product);

		network_device_set_desc (cb_data->dev, desc);
	}
	dbus_message_unref (reply);

out:
	cb_data->applet->dev_pending_call_list = g_slist_remove (cb_data->applet->dev_pending_call_list, pcall);
	nmwa_dbus_devices_schedule_copy (cb_data->applet);

	dbus_pending_call_unref (pcall);
}


/*
 * hal_info_vendor_cb
 *
 * hal_info_parent callback
 *
 */
static void hal_info_vendor_cb (DBusPendingCall *pcall, void *user_data)
{
	DBusMessage *		reply;
	HalInfoCBData *	cb_data = (HalInfoCBData *) user_data;
	char *			info_vendor;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (cb_data != NULL);
	g_return_if_fail (cb_data->applet != NULL);
	g_return_if_fail (cb_data->dev != NULL);
	g_return_if_fail (cb_data->parent_op != NULL);

	dbus_pending_call_ref (pcall);

	if (!dbus_pending_call_get_completed (pcall))
		goto out;

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (message_is_error (reply))
	{
		dbus_message_unref (reply);
		goto out;
	}

	if (dbus_message_get_args (reply, NULL, DBUS_TYPE_STRING, &info_vendor, DBUS_TYPE_INVALID))
	{
		DBusMessage *		message;
		DBusPendingCall *	product_pcall = NULL;

		if ((message = dbus_message_new_method_call ("org.freedesktop.Hal", cb_data->parent_op,
											"org.freedesktop.Hal.Device", "GetPropertyString")))
		{
			const char *	prop = "info.product";

			dbus_message_append_args (message, DBUS_TYPE_STRING, &prop, DBUS_TYPE_INVALID);
			dbus_connection_send_with_reply (cb_data->applet->connection, message, &product_pcall, -1);
			dbus_message_unref (message);
			if (product_pcall)
			{
				HalInfoCBData *	product_cb_data = g_malloc0 (sizeof (HalInfoCBData));

				product_cb_data->applet = cb_data->applet;
				network_device_ref (cb_data->dev);
				product_cb_data->dev = cb_data->dev;
				product_cb_data->parent_op = g_strdup (cb_data->parent_op);
				product_cb_data->vendor = g_strdup (info_vendor);
				dbus_pending_call_set_notify (product_pcall, hal_info_product_cb, product_cb_data, (DBusFreeFunction) free_hal_info_cb_data);
				cb_data->applet->dev_pending_call_list = g_slist_append (cb_data->applet->dev_pending_call_list, product_pcall);
			}
		}
	}
	dbus_message_unref (reply);

out:
	cb_data->applet->dev_pending_call_list = g_slist_remove (cb_data->applet->dev_pending_call_list, pcall);
	nmwa_dbus_devices_schedule_copy (cb_data->applet);

	dbus_pending_call_unref (pcall);
}


/*
 * hal_info_parent_cb
 *
 * nmwa_dbus_update_device_info_from_hal callback
 *
 */
static void hal_info_parent_cb (DBusPendingCall *pcall, void *user_data)
{
	DBusMessage *		reply;
	HalInfoCBData *	cb_data = (HalInfoCBData *) user_data;
	char *			op;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (cb_data != NULL);
	g_return_if_fail (cb_data->applet != NULL);
	g_return_if_fail (cb_data->dev != NULL);

	dbus_pending_call_ref (pcall);

	if (!dbus_pending_call_get_completed (pcall))
		goto out;

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (message_is_error (reply))
	{
		dbus_message_unref (reply);
		goto out;
	}

	/* Grab the object path of the parent item of this "Network Interface" */
	if (dbus_message_get_args (reply, NULL, DBUS_TYPE_STRING, &op, DBUS_TYPE_INVALID))
	{
		DBusMessage *		message;
		DBusPendingCall *	vendor_pcall = NULL;

		if ((message = dbus_message_new_method_call ("org.freedesktop.Hal", op,
											"org.freedesktop.Hal.Device", "GetPropertyString")))
		{
			const char *	prop = "info.vendor";

			dbus_message_append_args (message, DBUS_TYPE_STRING, &prop, DBUS_TYPE_INVALID);
			dbus_connection_send_with_reply (cb_data->applet->connection, message, &vendor_pcall, -1);
			dbus_message_unref (message);
			if (vendor_pcall)
			{
				HalInfoCBData *	vendor_cb_data = g_malloc0 (sizeof (HalInfoCBData));

				vendor_cb_data->applet = cb_data->applet;
				network_device_ref (cb_data->dev);
				vendor_cb_data->dev = cb_data->dev;
				vendor_cb_data->parent_op = g_strdup (op);
				dbus_pending_call_set_notify (vendor_pcall, hal_info_vendor_cb, vendor_cb_data, (DBusFreeFunction) free_hal_info_cb_data);
				cb_data->applet->dev_pending_call_list = g_slist_append (cb_data->applet->dev_pending_call_list, vendor_pcall);
			}
		}
	}
	dbus_message_unref (reply);

out:
	cb_data->applet->dev_pending_call_list = g_slist_remove (cb_data->applet->dev_pending_call_list, pcall);
	nmwa_dbus_devices_schedule_copy (cb_data->applet);

	dbus_pending_call_unref (pcall);
}


/*
 * nmwa_dbus_update_device_info_from_hal
 *
 * Grab the info.product tag from hal for a specific UDI
 *
 */
static void nmwa_dbus_update_device_info_from_hal (NetworkDevice *dev, NMWirelessApplet *applet)
{
	DBusMessage *		message;
	DBusPendingCall *	pcall = NULL;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (applet->connection != NULL);
	g_return_if_fail (dev != NULL);

	if ((message = dbus_message_new_method_call ("org.freedesktop.Hal", network_device_get_hal_udi (dev),
										"org.freedesktop.Hal.Device", "GetPropertyString")))
	{
		const char *	prop = "info.parent";

		dbus_message_append_args (message, DBUS_TYPE_STRING, &prop, DBUS_TYPE_INVALID);
		dbus_connection_send_with_reply (applet->connection, message, &pcall, -1);
		dbus_message_unref (message);
		if (pcall)
		{
			HalInfoCBData *	cb_data = g_malloc0 (sizeof (HalInfoCBData));

			cb_data->applet = applet;
			network_device_ref (dev);
			cb_data->dev = dev;
			dbus_pending_call_set_notify (pcall, hal_info_parent_cb, cb_data, (DBusFreeFunction) free_hal_info_cb_data);
			applet->dev_pending_call_list = g_slist_append (applet->dev_pending_call_list, pcall);
		}
	}
}


void nmwa_free_gui_data_model (NMWirelessApplet *applet)
{
	g_return_if_fail (applet != NULL);

	if (applet->gui_device_list)
	{
		g_slist_foreach (applet->gui_device_list, (GFunc) network_device_unref, NULL);
		g_slist_free (applet->gui_device_list);
		applet->gui_device_list = NULL;
	}
}


void nmwa_free_dbus_data_model (NMWirelessApplet *applet)
{
	GSList	*elt;

	g_return_if_fail (applet != NULL);

	if (applet->dbus_device_list)
	{
		g_slist_foreach (applet->dbus_device_list, (GFunc) network_device_unref, NULL);
		g_slist_free (applet->dbus_device_list);
		applet->dbus_device_list = NULL;
	}
}


/*
 * nmwa_copy_data_model
 *
 * Copy the dbus data model over to the gui data model
 *
 */
static void nmwa_copy_data_model (NMWirelessApplet *applet)
{
	GSList		*elt;
	NetworkDevice	*act_dev = NULL;

	g_return_if_fail (applet != NULL);

	/* Free the existing GUI data model. */
	nmwa_free_gui_data_model (applet);

	/* Deep-copy network devices to GUI data model */
	for (elt = applet->dbus_device_list; elt; elt = g_slist_next (elt))
	{
		NetworkDevice	*src = (NetworkDevice *)(elt->data);
		NetworkDevice	*dst = network_device_copy (src);

		if (dst)
			applet->gui_device_list = g_slist_append (applet->gui_device_list, dst);
	}

	applet->gui_nm_state = applet->dbus_nm_state;
}


/*
 * nmwa_dbus_schedule_driver_notification
 *
 * Schedule the driver notification routine to run in the main loop.
 *
 */
static void nmwa_dbus_schedule_driver_notification (NMWirelessApplet *applet, NetworkDevice *dev)
{
	DriverNotifyCBData	*cb_data;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (dev != NULL);

	cb_data = g_malloc0 (sizeof (DriverNotifyCBData));
	cb_data->applet = applet;
	network_device_ref (dev);
	cb_data->dev = dev;

	g_idle_add (nmwa_driver_notify, (gpointer)cb_data);
}


/*
 * nmwa_dbus_check_drivers
 *
 * If a device got added, we notify the user if the device's driver
 * has any problems (no carrier detect, no wireless scanning, etc).
 *
 */
static void nmwa_dbus_check_drivers (NMWirelessApplet *applet)
{
	GSList	*elt;

	g_return_if_fail (applet != NULL);

	/* For every device that's in the dbus data model but not in
	 * the gui data model, signal the user.
	 */
	for (elt = applet->dbus_device_list; elt; elt = g_slist_next (elt))
	{
		NetworkDevice	*dbus_dev = (NetworkDevice *)(elt->data);
		GSList		*elt2;
		gboolean		 found = FALSE;
		
		for (elt2 = applet->gui_device_list; elt2; elt2 = g_slist_next (elt2))
		{
			NetworkDevice	*gui_dev = (NetworkDevice *)(elt2->data);

			if (    !nm_null_safe_strcmp (network_device_get_iface (dbus_dev), network_device_get_iface (gui_dev))
				&& !nm_null_safe_strcmp (network_device_get_address (dbus_dev), network_device_get_address (gui_dev))
				&& !nm_null_safe_strcmp (network_device_get_hal_udi (dbus_dev), network_device_get_hal_udi (gui_dev)))
			{
				found = TRUE;
				break;
			}
		}

		if (    !found
			&& (    (network_device_get_driver_support_level (dbus_dev) == NM_DRIVER_NO_CARRIER_DETECT)
				|| (network_device_get_driver_support_level (dbus_dev) == NM_DRIVER_NO_WIRELESS_SCAN)))
			nmwa_dbus_schedule_driver_notification (applet, dbus_dev);
	}
}


typedef struct NetPropCBData
{
	char *			dev_op;
	char *			act_net;
	NMWirelessApplet *	applet;
} NetPropCBData;

static void free_net_prop_cb_data (NetPropCBData *data)
{
	if (data)
	{
		g_free (data->dev_op);
		g_free (data->act_net);
	}
	g_free (data);
}


/*
 * nmwa_dbus_net_properties_cb
 *
 * Callback for each network we called "getProperties" on in nmwa_dbus_device_properties_cb().
 *
 */
static void nmwa_dbus_net_properties_cb (DBusPendingCall *pcall, void *user_data)
{
	DBusMessage *		reply;
	NetPropCBData *	cb_data = (NetPropCBData *) user_data;
	NMWirelessApplet *	applet;
	const char *		op = NULL;
	const char *		essid = NULL;
	const char *		hw_addr = NULL;
	dbus_int32_t		strength = -1;
	double 			freq = 0;
	dbus_int32_t		rate = 0;
	dbus_bool_t		enc = FALSE;
	dbus_uint32_t		mode = 0;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (cb_data != NULL);
	g_return_if_fail (cb_data->applet != NULL);
	g_return_if_fail (cb_data->dev_op != NULL);

	applet = cb_data->applet;

	dbus_pending_call_ref (pcall);

	if (!dbus_pending_call_get_completed (pcall))
		goto out;

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (dbus_message_is_error (reply, NM_DBUS_NO_NETWORKS_ERROR))
	{
		dbus_message_unref (reply);
		goto out;
	}

	if (dbus_message_get_args (reply, NULL,	DBUS_TYPE_OBJECT_PATH, &op,
									DBUS_TYPE_STRING, &essid,
									DBUS_TYPE_STRING, &hw_addr,
									DBUS_TYPE_INT32,  &strength,
									DBUS_TYPE_DOUBLE, &freq,
									DBUS_TYPE_INT32,  &rate,
									DBUS_TYPE_BOOLEAN,&enc,
									DBUS_TYPE_UINT32, &mode,
									DBUS_TYPE_INVALID))
	{
		NetworkDevice *	dev;

		if ((dev = nmwa_get_device_for_nm_path (applet->dbus_device_list, cb_data->dev_op)))
		{
			WirelessNetwork *	net = wireless_network_new (essid, op);
			WirelessNetwork *	tmp_net;
			char *			act_net = cb_data->act_net ? g_strdup (cb_data->act_net) : NULL;

			/* Remove any existing wireless network with this object path */
			if ((tmp_net = network_device_get_wireless_network_by_nm_path (dev, op)))
			{
				if (!act_net && wireless_network_get_active (tmp_net))
					act_net = g_strdup (wireless_network_get_nm_path (tmp_net));
				network_device_remove_wireless_network (dev, tmp_net);
			}

			wireless_network_set_encrypted (net, enc);
			wireless_network_set_strength (net, strength);
			if (act_net && strlen (act_net) && (strcmp (act_net, op) == 0))
				wireless_network_set_active (net, TRUE);

			network_device_add_wireless_network (dev, net);
			g_free (act_net);
		}
	}
	dbus_message_unref (reply);

out:
	applet->dev_pending_call_list = g_slist_remove (applet->dev_pending_call_list, pcall);
	nmwa_dbus_devices_schedule_copy (applet);

	dbus_pending_call_unref (pcall);
}


/*
 * nmwa_dbus_device_update_one_network
 *
 * Get properties on just one wireless network.
 *
 */
void nmwa_dbus_device_update_one_network (NMWirelessApplet *applet, const char *dev_path, const char *net_path, const char *active_net_path)
{
	DBusMessage *		message;
	DBusPendingCall *	pcall = NULL;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (dev_path != NULL);
	g_return_if_fail (net_path != NULL);

	if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, net_path, NM_DBUS_INTERFACE_DEVICES, "getProperties")))
	{
		dbus_connection_send_with_reply (applet->connection, message, &pcall, -1);
		dbus_message_unref (message);
		if (pcall)
		{
			NetPropCBData * cb_data = g_malloc0 (sizeof (NetPropCBData));

			cb_data->dev_op = g_strdup (dev_path);
			cb_data->act_net = (active_net_path && strlen (active_net_path)) ? g_strdup (active_net_path) : NULL;
			cb_data->applet = applet;
			dbus_pending_call_set_notify (pcall, nmwa_dbus_net_properties_cb, cb_data, (DBusFreeFunction) free_net_prop_cb_data);
			applet->dev_pending_call_list = g_slist_append (applet->dev_pending_call_list, pcall);
		}
	}
}


/*
 * nmwa_dbus_device_remove_one_network
 *
 * Remove a wireless network from a device.
 *
 */
void nmwa_dbus_device_remove_one_network (NMWirelessApplet *applet, const char *dev_path, const char *net_path)
{
	NetworkDevice *	dev;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (dev_path != NULL);
	g_return_if_fail (net_path != NULL);

	if ((dev = nmwa_get_device_for_nm_path (applet->dbus_device_list, dev_path)))
	{
		WirelessNetwork *	net;

		if ((net = network_device_get_wireless_network_by_nm_path (dev, net_path)))
		{
			network_device_remove_wireless_network (dev, net);
			nmwa_dbus_devices_schedule_copy (applet);
		}
	}
}


/*
 * nmwa_dbus_device_properties_cb
 *
 * Callback for each device we called "getProperties" on in nmwa_dbus_update_devices_cb().
 *
 */
static void nmwa_dbus_device_properties_cb (DBusPendingCall *pcall, void *user_data)
{
	DBusMessage *		reply;
	NMWirelessApplet *	applet = (NMWirelessApplet *) user_data;
	char *			op = NULL;
	const char *		iface = NULL;
	dbus_uint32_t		type = 0;
	const char *		udi = NULL;
	dbus_bool_t		active = FALSE;
	dbus_uint32_t		ip4_address = 0;
	const char *		hw_addr = NULL;
	dbus_uint32_t		mode = 0;
	dbus_int32_t		strength = -1;
	char *			active_network_path = NULL;
	dbus_bool_t		link_active = FALSE;
	dbus_uint32_t		driver_support_level = 0;
	char **			networks = NULL;
	int				num_networks = 0;
	NMActStage		act_stage = NM_ACT_STAGE_UNKNOWN;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (applet != NULL);

	dbus_pending_call_ref (pcall);

	if (!dbus_pending_call_get_completed (pcall))
		goto out;

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (dbus_message_get_type (reply) == DBUS_MESSAGE_TYPE_ERROR)
	{
		dbus_message_unref (reply);
		goto out;
	}

	if (dbus_message_get_args (reply, NULL,	DBUS_TYPE_OBJECT_PATH, &op,
									DBUS_TYPE_STRING, &iface,
									DBUS_TYPE_UINT32, &type,
									DBUS_TYPE_STRING, &udi,
									DBUS_TYPE_BOOLEAN,&active,
									DBUS_TYPE_UINT32, &act_stage,
									DBUS_TYPE_UINT32, &ip4_address,
									DBUS_TYPE_STRING, &hw_addr,
									DBUS_TYPE_UINT32, &mode,
									DBUS_TYPE_INT32,  &strength,
									DBUS_TYPE_BOOLEAN,&link_active,
									DBUS_TYPE_UINT32, &driver_support_level,
									DBUS_TYPE_STRING, &active_network_path,
									DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &networks, &num_networks,
									DBUS_TYPE_INVALID))
	{
		NetworkDevice *dev = network_device_new (iface, type, op);
		NetworkDevice *tmp_dev = nmwa_get_device_for_nm_path (applet->dbus_device_list, op);

		network_device_set_hal_udi (dev, udi);
		network_device_set_address (dev, hw_addr);
		network_device_set_active (dev, active);
		network_device_set_link (dev, link_active);
		network_device_set_driver_support_level (dev, driver_support_level);
		network_device_set_act_stage (dev, act_stage);

		/* If the device already exists in our list for some reason, remove it so we
		 * can add the new one with updated data.
		 */
		if (tmp_dev)
		{
			applet->dbus_device_list = g_slist_remove (applet->dbus_device_list, tmp_dev);
			network_device_unref (tmp_dev);
		}
		
		applet->dbus_device_list = g_slist_append (applet->dbus_device_list, dev);

		nmwa_dbus_update_device_info_from_hal (dev, applet);

		if (type == DEVICE_TYPE_WIRELESS_ETHERNET)
		{
			network_device_set_strength (dev, strength);

			/* Call the "getProperties" method on each wireless network the device may have. */
			if (num_networks > 0)
			{
				char ** item;

				for (item = networks; *item; item++)
					nmwa_dbus_device_update_one_network (applet, op, *item, active_network_path);
			}
		}

		dbus_free_string_array (networks);
	}
	dbus_message_unref (reply);

out:
	applet->dev_pending_call_list = g_slist_remove (applet->dev_pending_call_list, pcall);
	nmwa_dbus_devices_schedule_copy (applet);

	dbus_pending_call_unref (pcall);
}


/*
 * nmwa_dbus_device_update_one_device
 *
 * Get properties on just one device.
 *
 */
void nmwa_dbus_device_update_one_device (NMWirelessApplet *applet, const char *dev_path)
{
	DBusMessage *		message;
	DBusPendingCall *	pcall = NULL;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (dev_path != NULL);

	if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, dev_path, NM_DBUS_INTERFACE_DEVICES, "getProperties")))
	{
		dbus_connection_send_with_reply (applet->connection, message, &pcall, -1);
		dbus_message_unref (message);
		if (pcall)
		{
			dbus_pending_call_set_notify (pcall, nmwa_dbus_device_properties_cb, applet, NULL);
			applet->dev_pending_call_list = g_slist_append (applet->dev_pending_call_list, pcall);
		}
	}
}


/*
 * nmwa_dbus_update_devices_cb
 *
 * nmwa_dbus_update_devices callback.
 *
 */
static void nmwa_dbus_update_devices_cb (DBusPendingCall *pcall, void *user_data)
{
	DBusMessage *		reply;
	NMWirelessApplet *	applet = (NMWirelessApplet *) user_data;
	char **			devices;
	int				num_devices;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (applet != NULL);

	dbus_pending_call_ref (pcall);

	if (!dbus_pending_call_get_completed (pcall))
		goto out;

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (dbus_message_is_error (reply, NM_DBUS_NO_DEVICES_ERROR))
	{
		dbus_message_unref (reply);
		goto out;
	}

	if (dbus_message_get_args (reply, NULL, DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH, &devices, &num_devices, DBUS_TYPE_INVALID))
	{
		char ** item;

		/* For each device, fire off a "getProperties" call */
		for (item = devices; *item; item++)
			nmwa_dbus_device_update_one_device (applet, *item);

		dbus_free_string_array (devices);
	}
	dbus_message_unref (reply);

out:
	dbus_pending_call_unref (pcall);
}


/*
 * nmwa_dbus_update_devices
 *
 * Do a full update of network devices and wireless networks.
 *
 */
void nmwa_dbus_update_devices (NMWirelessApplet *applet)
{
	DBusMessage *		message;
	DBusPendingCall *	pcall;

	g_return_if_fail (applet->data_mutex != NULL);

	nmwa_free_dbus_data_model (applet);

	if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH, NM_DBUS_INTERFACE, "getDevices")))
	{
		dbus_connection_send_with_reply (applet->connection, message, &pcall, -1);
		dbus_message_unref (message);
		if (pcall)
			dbus_pending_call_set_notify (pcall, nmwa_dbus_update_devices_cb, applet, NULL);
	}

	nmwa_dbus_update_wireless_enabled (applet);
}


/*
 * nmwa_dbus_device_remove_one_device
 *
 * Remove a device from our list.
 *
 */
void nmwa_dbus_device_remove_one_device (NMWirelessApplet *applet, const char *dev_path)
{
	NetworkDevice *	dev;

	g_return_if_fail (applet != NULL);

	if ((dev = nmwa_get_device_for_nm_path (applet->dbus_device_list, dev_path)))
	{
		applet->dbus_device_list = g_slist_remove (applet->dbus_device_list, dev);
		network_device_unref (dev);
		nmwa_dbus_devices_schedule_copy (applet);
	}
}


/*
 * nmwa_dbus_set_device
 *
 * Tell NetworkManager to use a specific network device that the user picked, and
 * possibly a specific wireless network too.
 *
 */
void nmwa_dbus_set_device (DBusConnection *connection, NetworkDevice *dev, const char *essid,
						const NMEncKeyType key_type, const char *passphrase)
{
	DBusMessage	*message;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (dev != NULL);

	if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH, NM_DBUS_INTERFACE, "setActiveDevice")))
	{
		const char *dev_path = network_device_get_nm_path (dev);

		if (network_device_is_wireless (dev) && essid)
		{
			int tmp_key_type = (int)key_type;

			if (passphrase == NULL)
				passphrase = "";

			dbus_message_append_args (message, DBUS_TYPE_OBJECT_PATH, &dev_path,
										DBUS_TYPE_STRING, &essid,
										DBUS_TYPE_STRING, &passphrase,
										DBUS_TYPE_INT32, &tmp_key_type,
										DBUS_TYPE_INVALID);
		}
		else
		{
			nm_info ("Forcing device '%s'\n", network_device_get_nm_path (dev));
			dbus_message_append_args (message, DBUS_TYPE_OBJECT_PATH, &dev_path, DBUS_TYPE_INVALID);
		}
		dbus_connection_send (connection, message, NULL);
	}
	else
		nm_warning ("nmwa_dbus_set_device(): Couldn't allocate the dbus message\n");
}


/*
 * nmwa_dbus_create_network
 *
 * Tell NetworkManager to create an Ad-Hoc wireless network
 *
 */
void nmwa_dbus_create_network (DBusConnection *connection, NetworkDevice *dev, const char *essid,
						NMEncKeyType key_type, const char *passphrase)
{
	DBusMessage	*message;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (dev != NULL);
	g_return_if_fail (essid != NULL);
	g_return_if_fail (network_device_is_wireless (dev));

	if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH, NM_DBUS_INTERFACE, "createWirelessNetwork")))
	{
		const char *dev_path = network_device_get_nm_path (dev);

		if (dev_path)
		{
			nm_info ("Creating network '%s' %s passphrase on device '%s'.\n", essid, passphrase ? "with" : "without", dev_path);
			if (passphrase == NULL)
				passphrase = "";
			dbus_message_append_args (message, DBUS_TYPE_OBJECT_PATH, &dev_path,
									DBUS_TYPE_STRING, &essid,
									DBUS_TYPE_STRING, &passphrase,
									DBUS_TYPE_INT32, &key_type,
									DBUS_TYPE_INVALID);
			dbus_connection_send (connection, message, NULL);
		}
	}
	else
		nm_warning ("nmwa_dbus_set_device(): Couldn't allocate the dbus message\n");
}


/*
 * nmwa_dbus_enable_wireless
 *
 * Tell NetworkManager to enabled or disable all wireless devices.
 *
 */
void nmwa_dbus_enable_wireless (NMWirelessApplet *applet, gboolean enabled)
{
	DBusMessage	*message;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (applet->connection != NULL);

	if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH, NM_DBUS_INTERFACE, "setWirelessEnabled")))
	{
		dbus_message_append_args (message, DBUS_TYPE_BOOLEAN, &enabled, DBUS_TYPE_INVALID);
		dbus_connection_send (applet->connection, message, NULL);
		nmwa_dbus_update_wireless_enabled (applet);
	}
}


typedef struct StrengthCBData
{
	NMWirelessApplet *	applet;
	char *			dev_path;
} StrengthCBData;


static void free_strength_cb_data (StrengthCBData *data)
{
	if (data)
		g_free (data->dev_path);
	g_free (data);
}


/*
 * nmwa_dbus_update_device_strength_cb
 *
 * nmwa_dbus_update_device_strength callback.
 *
 */
static void nmwa_dbus_update_device_strength_cb (DBusPendingCall *pcall, void *user_data)
{
	DBusMessage *		reply;
	StrengthCBData *	cb_data = user_data;
	NMWirelessApplet *	applet;
	int				strength;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (cb_data != NULL);

	applet = cb_data->applet;
	g_return_if_fail (applet != NULL);

	dbus_pending_call_ref (pcall);

	if (!dbus_pending_call_get_completed (pcall))
		goto out;

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (message_is_error (reply))
	{
		dbus_message_unref (reply);
		goto out;
	}

	if (dbus_message_get_args (reply, NULL, DBUS_TYPE_INT32, &strength, DBUS_TYPE_INVALID))
	{
		NetworkDevice *dev;

		/* Update strength on dbus active device */
		if ((dev = nmwa_get_device_for_nm_path (applet->dbus_device_list, cb_data->dev_path)))
			network_device_set_strength (dev, strength);

		/* Update strength on gui active device too */
		if ((dev = nmwa_get_device_for_nm_path (applet->gui_device_list, cb_data->dev_path)))
			network_device_set_strength (dev, strength);
	}
	dbus_message_unref (reply);

out:
	dbus_pending_call_unref (pcall);
}


static void get_each_device_strength (NetworkDevice *dev, NMWirelessApplet *applet)
{
	g_return_if_fail (dev != NULL);

	if (network_device_get_active (dev))
	{
		DBusMessage *		message;
		DBusPendingCall *	pcall;

		if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, network_device_get_nm_path (dev), NM_DBUS_INTERFACE_DEVICES, "getStrength")))
		{
			dbus_connection_send_with_reply (applet->connection, message, &pcall, -1);
			dbus_message_unref (message);
			if (pcall)
			{
				StrengthCBData *	cb_data = g_malloc0 (sizeof (StrengthCBData));

				cb_data->applet = applet;
				cb_data->dev_path = g_strdup (network_device_get_nm_path (dev));
				dbus_pending_call_set_notify (pcall, nmwa_dbus_update_device_strength_cb, cb_data, (DBusFreeFunction) free_strength_cb_data);
			}
		}
	}
}

/*
 * nmwa_dbus_update_device_strength
 *
 * Update each active device's strength.
 *
 */
gboolean nmwa_dbus_update_device_strength (NMWirelessApplet *applet)
{
	NetworkDevice *	dev;
	DBusMessage *		message;
	DBusPendingCall *	pcall;

	g_return_val_if_fail (applet != NULL, TRUE);

	g_slist_foreach (applet->dbus_device_list, (GFunc) get_each_device_strength, applet);

	return TRUE;
}


/*
 * sort_devices_function
 *
 * Sort the devices for display...  Wired devices at the top.
 *
 */
static int
sort_devices_function (gconstpointer a, gconstpointer b)
{
	NetworkDevice *dev_a = (NetworkDevice *) a;
	NetworkDevice *dev_b = (NetworkDevice *) b;
	const char *name_a;
	const char *name_b;

	if (network_device_get_desc (dev_a))
		name_a = network_device_get_desc (dev_a);
	else if (network_device_get_nm_path (dev_a))
		name_a = network_device_get_nm_path (dev_a);
	else
		name_a = "";

	if (network_device_get_desc (dev_b))
		name_b = network_device_get_desc (dev_b);
	else if (network_device_get_nm_path (dev_b))
		name_b = network_device_get_nm_path (dev_b);
	else
		name_b = "";

	if (network_device_get_type (dev_a) == network_device_get_type (dev_b))
	{
		return strcmp (name_a, name_b);
	}
	if (network_device_is_wired (dev_a))
		return -1;
	if (network_device_is_wired (dev_b))
		return 1;
	if (network_device_is_wireless (dev_a))
		return -1;
	if (network_device_is_wireless (dev_b))
		return 1;

	/* Unknown device types.  Sort by name only at this point. */
	return strcmp (name_a, name_b);
}


static int devices_copy_idle_id = 0;

/*
 * nmwa_dbus_devices_lock_and_copy
 *
 * Copy our network model over to the GUI thread.
 *
 */
static gboolean nmwa_dbus_devices_lock_and_copy (NMWirelessApplet *applet)
{
	devices_copy_idle_id = 0;

	g_return_val_if_fail (applet != NULL, FALSE);

	/* Only copy over if we have a complete data model */
	if (g_slist_length (applet->dev_pending_call_list) == 0)
	{
		GSList *elt;

		nmwa_dbus_check_drivers (applet);

		/* Sort the devices for display */
		applet->dbus_device_list = g_slist_sort (applet->dbus_device_list, sort_devices_function);

		/* Sort the wireless networks of each device */
		for (elt = applet->dbus_device_list; elt; elt = g_slist_next (elt))
		{
			NetworkDevice *dev = (NetworkDevice *)(elt->data);

			if (dev && network_device_is_wireless (dev))
				network_device_sort_wireless_networks (dev);
		}

		/* Now copy the data over to the GUI side */
		g_mutex_lock (applet->data_mutex);
		nmwa_copy_data_model (applet);
		g_mutex_unlock (applet->data_mutex);

		nmwa_dbus_update_device_strength (applet);
	}

	return FALSE;
}

/*
 * nmwa_dbus_devices_schedule_copy
 *
 * Schedule a copy of our model over to the gui thread, batching copy requests.
 *
 */
void nmwa_dbus_devices_schedule_copy (NMWirelessApplet *applet)
{
	g_return_if_fail (applet != NULL);

	if (devices_copy_idle_id == 0)
	{
		GSource	*source = g_idle_source_new ();

		/* We want this idle source to run before any other idle source */
		g_source_set_priority (source, G_PRIORITY_HIGH_IDLE);
		g_source_set_callback (source, (GSourceFunc) nmwa_dbus_devices_lock_and_copy, applet, NULL);
		devices_copy_idle_id = g_source_attach (source, applet->thread_context);
		g_source_unref (source);
	}
}

