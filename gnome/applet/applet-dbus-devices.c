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

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (message_is_error (reply))
	{
		dbus_message_unref (reply);
		goto out;
	}

	if (dbus_message_get_args (reply, NULL, DBUS_TYPE_UINT32, &nm_state, DBUS_TYPE_INVALID))
		applet->nm_state = nm_state;

	dbus_message_unref (reply);

out:
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
		if (pcall)
			dbus_pending_call_set_notify (pcall, nmwa_dbus_nm_state_cb, applet, NULL);
		dbus_message_unref (message);
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
		if (pcall)
			dbus_pending_call_set_notify (pcall, nmwa_dbus_update_wireless_enabled_cb, applet, NULL);
		dbus_message_unref (message);
	}
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
			if (product_pcall)
			{
				HalInfoCBData *	product_cb_data = g_malloc0 (sizeof (HalInfoCBData));

				product_cb_data->applet = cb_data->applet;
				network_device_ref (cb_data->dev);
				product_cb_data->dev = cb_data->dev;
				product_cb_data->parent_op = g_strdup (cb_data->parent_op);
				product_cb_data->vendor = g_strdup (info_vendor);
				dbus_pending_call_set_notify (product_pcall, hal_info_product_cb, product_cb_data, (DBusFreeFunction) free_hal_info_cb_data);
			}
			dbus_message_unref (message);
		}
	}
	dbus_message_unref (reply);

out:
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
			if (vendor_pcall)
			{
				HalInfoCBData *	vendor_cb_data = g_malloc0 (sizeof (HalInfoCBData));

				vendor_cb_data->applet = cb_data->applet;
				network_device_ref (cb_data->dev);
				vendor_cb_data->dev = cb_data->dev;
				vendor_cb_data->parent_op = g_strdup (op);
				dbus_pending_call_set_notify (vendor_pcall, hal_info_vendor_cb, vendor_cb_data, (DBusFreeFunction) free_hal_info_cb_data);
			}
			dbus_message_unref (message);
		}
	}
	dbus_message_unref (reply);

out:
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
		if (pcall)
		{
			HalInfoCBData *	cb_data = g_malloc0 (sizeof (HalInfoCBData));

			cb_data->applet = applet;
			network_device_ref (dev);
			cb_data->dev = dev;
			dbus_pending_call_set_notify (pcall, hal_info_parent_cb, cb_data, (DBusFreeFunction) free_hal_info_cb_data);
		}
		dbus_message_unref (message);
	}
}


void nmwa_free_data_model (NMWirelessApplet *applet)
{
	g_return_if_fail (applet != NULL);

	if (applet->device_list)
	{
		g_slist_foreach (applet->device_list, (GFunc) network_device_unref, NULL);
		g_slist_free (applet->device_list);
		applet->device_list = NULL;
	}
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
	for (elt = applet->device_list; elt; elt = g_slist_next (elt))
	{
		NetworkDevice	*dbus_dev = (NetworkDevice *)(elt->data);
		GSList		*elt2;
		gboolean		 found = FALSE;
		
		for (elt2 = applet->device_list; elt2; elt2 = g_slist_next (elt2))
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

		if ((dev = nmwa_get_device_for_nm_path (applet->device_list, cb_data->dev_op)))
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
			g_free (act_net);

			network_device_add_wireless_network (dev, net);
			network_device_sort_wireless_networks (dev);
		}
	}
	dbus_message_unref (reply);

out:
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
		if (pcall)
		{
			NetPropCBData * cb_data = g_malloc0 (sizeof (NetPropCBData));

			cb_data->dev_op = g_strdup (dev_path);
			cb_data->act_net = (active_net_path && strlen (active_net_path)) ? g_strdup (active_net_path) : NULL;
			cb_data->applet = applet;
			dbus_pending_call_set_notify (pcall, nmwa_dbus_net_properties_cb, cb_data, (DBusFreeFunction) free_net_prop_cb_data);
		}
		dbus_message_unref (message);
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

	if ((dev = nmwa_get_device_for_nm_path (applet->device_list, dev_path)))
	{
		WirelessNetwork *	net;

		if ((net = network_device_get_wireless_network_by_nm_path (dev, net_path)))
			network_device_remove_wireless_network (dev, net);
	}
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
	const char *		ip4_address = NULL;
	const char *		broadcast = NULL;
	const char *		subnetmask = NULL;
	const char *		hw_addr = NULL;
	const char *		route = NULL;
	const char *		primary_dns = NULL;
	const char *		secondary_dns = NULL;
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
									DBUS_TYPE_STRING, &ip4_address,
									DBUS_TYPE_STRING, &subnetmask,
									DBUS_TYPE_STRING, &broadcast,
									DBUS_TYPE_STRING, &hw_addr,
									DBUS_TYPE_STRING, &route,
									DBUS_TYPE_STRING, &primary_dns,
									DBUS_TYPE_STRING, &secondary_dns,
									DBUS_TYPE_UINT32, &mode,
									DBUS_TYPE_INT32,  &strength,
									DBUS_TYPE_BOOLEAN,&link_active,
									DBUS_TYPE_UINT32, &driver_support_level,
									DBUS_TYPE_STRING, &active_network_path,
									DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &networks, &num_networks,
									DBUS_TYPE_INVALID))
	{
		NetworkDevice *dev = network_device_new (iface, type, op);
		NetworkDevice *tmp_dev = nmwa_get_device_for_nm_path (applet->device_list, op);

		network_device_set_hal_udi (dev, udi);
		network_device_set_address (dev, hw_addr);
		network_device_set_active (dev, active);
		network_device_set_link (dev, link_active);
		network_device_set_driver_support_level (dev, driver_support_level);
		network_device_set_act_stage (dev, act_stage);
		network_device_set_ip4_address (dev, ip4_address);
		network_device_set_broadcast (dev, broadcast);
		network_device_set_netmask (dev, subnetmask);
		network_device_set_route (dev, route);
		network_device_set_primary_dns (dev, primary_dns);
		network_device_set_secondary_dns (dev, secondary_dns);

		/* If the device already exists in our list for some reason, remove it so we
		 * can add the new one with updated data.
		 */
		if (tmp_dev)
		{
			applet->device_list = g_slist_remove (applet->device_list, tmp_dev);
			network_device_unref (tmp_dev);
		}

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

		applet->device_list = g_slist_append (applet->device_list, dev);
		applet->device_list = g_slist_sort (applet->device_list, (GCompareFunc) sort_devices_function);
	}
	dbus_message_unref (reply);

out:
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
		if (pcall)
			dbus_pending_call_set_notify (pcall, nmwa_dbus_device_properties_cb, applet, NULL);
		dbus_message_unref (message);
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
 * nmwa_dbus_update_dialup_cb
 *
 * nmwa_dbus_update_dialup DBUS callback.
 *
 */
static void nmwa_dbus_update_dialup_cb (DBusPendingCall *pcall, void *user_data)
{
	DBusMessage *reply;
	NMWirelessApplet *applet = (NMWirelessApplet *) user_data;
	char **dialup_devices;
	int num_devices;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (applet != NULL);

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (dbus_message_is_error (reply, NM_DBUS_NO_DIALUP_ERROR))
	{
		dbus_message_unref (reply);
		goto out;
	}

	if (dbus_message_get_args (reply, NULL, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &dialup_devices, &num_devices, DBUS_TYPE_INVALID))
	{
		char **item;
		GSList *elt;

		for (elt = applet->dialup_list; elt; elt = g_slist_next (elt))
			g_free (elt->data);
		if (applet->dialup_list)
		{
			g_slist_free (applet->dialup_list);
			applet->dialup_list = NULL;
		}

		for (item = dialup_devices; *item; item++)
			applet->dialup_list = g_slist_append (applet->dialup_list, g_strdup (*item));

		dbus_free_string_array (dialup_devices);
	}
	dbus_message_unref (reply);

out:
	dbus_pending_call_unref (pcall);
}


/*
 * nmwa_dbus_dialup_activate_connection
 *
 * Tell NetworkManager to activate a particular dialup connection.
 *
 */
void nmwa_dbus_dialup_activate_connection (NMWirelessApplet *applet, const char *name)
{
	DBusMessage *message;

	g_return_if_fail (name != NULL);

	if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH, NM_DBUS_INTERFACE, "activateDialup")))
	{

		nm_info ("Activating dialup connection '%s'.", name);
#if 0
		{
			DBusMessageIter iter;
			DBusMessageIter iter_array;
			dbus_message_iter_init_append (message, &iter);
			dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &name);
			dbus_message_iter_open_container (&iter, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING_AS_STRING, &iter_array);

			for (i = passwords; i != NULL; i = g_slist_next (i)) {
				dbus_message_iter_append_basic (&iter_array, DBUS_TYPE_STRING, &(i->data));
			}
			dbus_message_iter_close_container (&iter, &iter_array);
		}
#endif

		dbus_message_append_args (message, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID);
		if (!dbus_connection_send (applet->connection, message, NULL))
			nm_warning ("nmwa_dbus_activate_dialup_connection(): Could not send activateDialup message!");
		dbus_message_unref (message);
	}
	else
		nm_warning ("nmwa_dbus_activate_dialup_connection(): Couldn't allocate the dbus message!");
}


/*
 * nmwa_dbus_update_devices
 *
 * Do a full update of network devices, wireless networks, and dial up devices.
 *
 */
void nmwa_dbus_update_devices (NMWirelessApplet *applet)
{
	DBusMessage *		message;
	DBusPendingCall *	pcall;

	nmwa_free_data_model (applet);

	if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH, NM_DBUS_INTERFACE, "getDevices")))
	{
		dbus_connection_send_with_reply (applet->connection, message, &pcall, -1);
		if (pcall)
			dbus_pending_call_set_notify (pcall, nmwa_dbus_update_devices_cb, applet, NULL);
		dbus_message_unref (message);
	}
	nmwa_dbus_update_wireless_enabled (applet);
}


/*
 * nmwa_dbus_update_dialup
 *
 * Do an update of dial up devices.
 *
 */
void nmwa_dbus_update_dialup (NMWirelessApplet *applet)
{
	DBusMessage *message;
	DBusPendingCall *pcall;

	nmwa_free_data_model (applet);

	if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH, NM_DBUS_INTERFACE, "getDialup")))
	{
		dbus_connection_send_with_reply (applet->connection, message, &pcall, -1);
		if (pcall)
			dbus_pending_call_set_notify (pcall, nmwa_dbus_update_dialup_cb, applet, NULL);
		dbus_message_unref (message);
	}
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

	if ((dev = nmwa_get_device_for_nm_path (applet->device_list, dev_path)))
	{
		applet->device_list = g_slist_remove (applet->device_list, dev);
		network_device_unref (dev);
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
		dbus_message_unref (message);
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
		dbus_message_unref (message);
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
		dbus_message_unref (message);
	}
}

void nmwa_dbus_update_strength (NMWirelessApplet *applet, const char *dev_path, const char *net_path, int strength)
{
	NetworkDevice *dev;

	g_return_if_fail (applet != NULL);

	if ((dev = nmwa_get_device_for_nm_path (applet->device_list, dev_path)))
	{
		if (net_path != NULL)
		{
			WirelessNetwork *net;

			if ((net = network_device_get_wireless_network_by_nm_path (dev, net_path)))
				wireless_network_set_strength (net, strength);
		}
		else
			network_device_set_strength (dev, strength);
	}
}
