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

#ifdef ENABLE_NOTIFY
#include <libnotify/notify.h>
#endif

#include <glib/gi18n.h>
#include <stdio.h>
#include <string.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include "applet-notifications.h"
#include "applet-dbus-devices.h"
#include "applet-dbus.h"
#include "applet.h"
#include "vpn-connection.h"
#include "nm-utils.h"


/*
 * nma_dbus_nm_state_cb
 *
 * Callback from nma_dbus_update_nm_state
 *
 */
static void nma_dbus_nm_state_cb (DBusPendingCall *pcall, void *user_data)
{
	DBusMessage *		reply;
	NMApplet *	applet = (NMApplet *) user_data;
	NMState			nm_state;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (applet != NULL);

	nm_dbus_send_with_callback_replied (pcall, __func__);

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (message_is_error (reply))
	{
		DBusError err;

		dbus_error_init (&err);
		dbus_set_error_from_message (&err, reply);
		nm_warning ("dbus returned an error.\n  (%s) %s\n", err.name, err.message);
		dbus_error_free (&err);
		dbus_message_unref (reply);
		goto out;
	}

	if (dbus_message_get_args (reply, NULL, DBUS_TYPE_UINT32, &nm_state, DBUS_TYPE_INVALID))
		nma_set_state (applet, nm_state);

	dbus_message_unref (reply);

out:
	dbus_pending_call_unref (pcall);
}


/*
 * nma_dbus_update_nm_state
 *
 * Update internal applet state from NetworkManager state
 *
 */
void nma_dbus_update_nm_state (NMApplet *applet)
{
	DBusMessage *		message;

	g_return_if_fail (applet != NULL);

	if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH, NM_DBUS_INTERFACE, "state")))
	{
		nm_dbus_send_with_callback (applet->connection, message,
				nma_dbus_nm_state_cb, applet, NULL, __func__);
		dbus_message_unref (message);
	}
}


typedef struct DriverCBData
{
	NMApplet *		applet;
	NetworkDevice *	dev;
} DriverCBData;


/*
 * nma_dbus_device_get_driver_cb
 *
 * Callback from nma_dbus_update_wireless_enabled
 *
 */
static void nma_dbus_device_get_driver_cb (DBusPendingCall *pcall, void *user_data)
{
	DBusMessage *		reply;
	NMApplet *		applet = (NMApplet *) user_data;
	DriverCBData *		data = (DriverCBData *) user_data;
	const char *		driver;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (applet != NULL);

	nm_dbus_send_with_callback_replied (pcall, __func__);

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (message_is_error (reply))
	{
		DBusError err;

		dbus_error_init (&err);
		dbus_set_error_from_message (&err, reply);
		nm_warning ("dbus returned an error.\n  (%s) %s\n", err.name, err.message);
		dbus_error_free (&err);
		dbus_message_unref (reply);
		goto out;
	}

	if (dbus_message_get_args (reply, NULL, DBUS_TYPE_STRING, &driver, DBUS_TYPE_INVALID))
	{
		if (data && data->dev)
			network_device_set_driver (data->dev, driver);
	}

	dbus_message_unref (reply);

out:
	if (data)
	{
		if (data->dev)
			network_device_unref (data->dev);
		g_free (data);
	}
	dbus_pending_call_unref (pcall);
}


/*
 * nma_dbus_device_get_driver
 *
 * Get the device's driver name
 *
 */
static void nma_dbus_device_get_driver (NetworkDevice *dev, NMApplet *applet)
{
	DBusMessage *		message;
	const char *		op;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (dev != NULL);

	op = network_device_get_nm_path (dev);
	if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, op, NM_DBUS_INTERFACE_DEVICES, "getDriver")))
	{
		DriverCBData *	data = g_malloc0 (sizeof (DriverCBData));

		network_device_ref (dev);
		data->dev = dev;
		data->applet = applet;

		if (!nm_dbus_send_with_callback (applet->connection, message,
				nma_dbus_device_get_driver_cb, data, NULL, __func__))
		{
			network_device_unref (dev);
			g_free (data);
		}
		dbus_message_unref (message);
	}
}


/*
 * nma_dbus_update_wireless_enabled_cb
 *
 * Callback from nma_dbus_update_wireless_enabled
 *
 */
static void nma_dbus_update_wireless_enabled_cb (DBusPendingCall *pcall, void *user_data)
{
	DBusMessage *		reply;
	NMApplet *	applet = (NMApplet *) user_data;
	gboolean			wireless_enabled;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (applet != NULL);

	nm_dbus_send_with_callback_replied (pcall, __func__);

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (message_is_error (reply))
	{
		DBusError err;

		dbus_error_init (&err);
		dbus_set_error_from_message (&err, reply);
		nm_warning ("dbus returned an error.\n  (%s) %s\n", err.name, err.message);
		dbus_error_free (&err);
		dbus_message_unref (reply);
		goto out;
	}

	if (dbus_message_get_args (reply, NULL, DBUS_TYPE_BOOLEAN, &wireless_enabled, DBUS_TYPE_INVALID))
	{
		applet->wireless_enabled = wireless_enabled;
		nma_enable_wireless_set_active (applet);
	}

	dbus_message_unref (reply);

out:
	dbus_pending_call_unref (pcall);
}


/*
 * nma_dbus_update_wireless_enabled
 *
 * Get the wireless_enabled value from NetworkManager
 *
 */
static void nma_dbus_update_wireless_enabled (NMApplet *applet)
{
	DBusMessage *		message;

	g_return_if_fail (applet != NULL);

	if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH, NM_DBUS_INTERFACE, "getWirelessEnabled")))
	{
		nm_dbus_send_with_callback (applet->connection, message,
				nma_dbus_update_wireless_enabled_cb, applet, NULL, __func__);
		dbus_message_unref (message);
	}
}


typedef struct HalInfoCBData
{
	NMApplet *	applet;
	NetworkDevice *	dev;
	char *			parent_op;
	char *			vendor;
} HalInfoCBData;

static void free_hal_info_cb_data (HalInfoCBData *cb_data)
{
	if (!cb_data)
		return;

	network_device_unref (cb_data->dev);
	g_free (cb_data->parent_op);
	g_free (cb_data->vendor);
	memset (cb_data, 0, sizeof (HalInfoCBData));
	g_free (cb_data);
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

	nm_dbus_send_with_callback_replied (pcall, __func__);

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (message_is_error (reply))
	{
		DBusError err;

		dbus_error_init (&err);
		dbus_set_error_from_message (&err, reply);
		nm_warning ("dbus returned an error.\n  (%s) %s\n", err.name, err.message);
		dbus_error_free (&err);
		dbus_message_unref (reply);
		goto out;
	}

	if (dbus_message_get_args (reply, NULL, DBUS_TYPE_STRING, &info_product, DBUS_TYPE_INVALID))
	{
		char *desc;

 		desc = g_strdup_printf ("%s %s", cb_data->vendor, info_product);
 		network_device_set_desc (cb_data->dev, desc);
		g_free (desc);
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

	nm_dbus_send_with_callback_replied (pcall, __func__);

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (message_is_error (reply))
	{
		DBusError err;

		dbus_error_init (&err);
		dbus_set_error_from_message (&err, reply);
		nm_warning ("dbus returned an error.\n  (%s) %s\n", err.name, err.message);
		dbus_error_free (&err);
		dbus_message_unref (reply);
		goto out;
	}

	if (dbus_message_get_args (reply, NULL, DBUS_TYPE_STRING, &info_vendor, DBUS_TYPE_INVALID))
	{
		DBusMessage *		message;

		if ((message = dbus_message_new_method_call ("org.freedesktop.Hal", cb_data->parent_op,
											"org.freedesktop.Hal.Device", "GetPropertyString")))
		{
			const char *	prop = "info.product";
			HalInfoCBData *product_cb_data = g_malloc0 (sizeof (HalInfoCBData));

			dbus_message_append_args (message, DBUS_TYPE_STRING, &prop, DBUS_TYPE_INVALID);

			product_cb_data->applet = cb_data->applet;
			network_device_ref (cb_data->dev);
			product_cb_data->dev = cb_data->dev;
			product_cb_data->parent_op = g_strdup (cb_data->parent_op);
			product_cb_data->vendor = g_strdup (info_vendor);

			nm_dbus_send_with_callback (cb_data->applet->connection, message,
					hal_info_product_cb, product_cb_data,
					(DBusFreeFunction) free_hal_info_cb_data, __func__);
			dbus_message_unref (message);
		}
	}
	dbus_message_unref (reply);

out:
	dbus_pending_call_unref (pcall);
}


/*
 * hal_net_physdev_cb
 *
 * nma_dbus_update_device_info_from_hal callback
 *
 */
static void hal_net_physdev_cb (DBusPendingCall *pcall, void *user_data)
{
	DBusMessage *		reply;
	HalInfoCBData *	cb_data = (HalInfoCBData *) user_data;
	char *			op;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (cb_data != NULL);
	g_return_if_fail (cb_data->applet != NULL);
	g_return_if_fail (cb_data->dev != NULL);

	nm_dbus_send_with_callback_replied (pcall, __func__);

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (message_is_error (reply))
	{
		DBusError err;

		dbus_error_init (&err);
		dbus_set_error_from_message (&err, reply);
		nm_warning ("dbus returned an error.\n  (%s) %s\n", err.name, err.message);
		dbus_error_free (&err);
		dbus_message_unref (reply);
		goto out;
	}

	/* Grab the object path of the physical device of this "Network Interface" */
	if (dbus_message_get_args (reply, NULL, DBUS_TYPE_STRING, &op, DBUS_TYPE_INVALID))
	{
		DBusMessage *		message;

		if ((message = dbus_message_new_method_call ("org.freedesktop.Hal", op,
											"org.freedesktop.Hal.Device", "GetPropertyString")))
		{
			const char *	prop = "info.vendor";
			HalInfoCBData *vendor_cb_data = g_malloc0 (sizeof (HalInfoCBData));

			dbus_message_append_args (message, DBUS_TYPE_STRING, &prop, DBUS_TYPE_INVALID);

			vendor_cb_data->applet = cb_data->applet;
			network_device_ref (cb_data->dev);
			vendor_cb_data->dev = cb_data->dev;
			vendor_cb_data->parent_op = g_strdup (op);

			nm_dbus_send_with_callback (cb_data->applet->connection, message,
					hal_info_vendor_cb, vendor_cb_data,
					(DBusFreeFunction) free_hal_info_cb_data, __func__);
			dbus_message_unref (message);
		}
	}
	dbus_message_unref (reply);

out:
	dbus_pending_call_unref (pcall);
}


/*
 * nma_dbus_update_device_info_from_hal
 *
 * Grab the info.product tag from hal for a specific UDI
 *
 */
static void nma_dbus_update_device_info_from_hal (NetworkDevice *dev, NMApplet *applet)
{
	DBusMessage *		message;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (applet->connection != NULL);
	g_return_if_fail (dev != NULL);

	if ((message = dbus_message_new_method_call ("org.freedesktop.Hal", network_device_get_hal_udi (dev),
										"org.freedesktop.Hal.Device", "GetPropertyString")))
	{
		const char *	prop = "net.physical_device";
		HalInfoCBData *cb_data = g_malloc0 (sizeof (HalInfoCBData));

		dbus_message_append_args (message, DBUS_TYPE_STRING, &prop, DBUS_TYPE_INVALID);

		cb_data->applet = applet;
		network_device_ref (dev);
		cb_data->dev = dev;

		nm_dbus_send_with_callback (cb_data->applet->connection, message,
				hal_net_physdev_cb, cb_data,
				(DBusFreeFunction) free_hal_info_cb_data, __func__);
		dbus_message_unref (message);
	}
}


void nma_free_data_model (NMApplet *applet)
{
	g_return_if_fail (applet != NULL);

	if (applet->device_list)
	{
		g_slist_foreach (applet->device_list, (GFunc) network_device_unref, NULL);
		g_slist_free (applet->device_list);
		applet->device_list = NULL;
	}
}


typedef struct NetPropCBData
{
	char *			dev_op;
	char *			act_net;
	NMApplet *	applet;
} NetPropCBData;

static void free_net_prop_cb_data (NetPropCBData *data)
{
	if (!data)
		return;

	g_free (data->dev_op);
	g_free (data->act_net);
	g_free (data);
}


/*
 * nma_dbus_net_properties_cb
 *
 * Callback for each network we called "getProperties" on in nma_dbus_device_properties_cb().
 *
 */
static void nma_dbus_net_properties_cb (DBusPendingCall *pcall, void *user_data)
{
	DBusMessage *		reply;
	NetPropCBData *	cb_data = (NetPropCBData *) user_data;
	NMApplet *		applet;
	const char *		op = NULL;
	const char *		essid = NULL;
	const char *		hw_addr = NULL;
	dbus_int32_t		strength = -1;
	double 			freq = 0;
	dbus_int32_t		rate = 0;
	dbus_int32_t		mode = -1;
	dbus_int32_t		capabilities = NM_802_11_CAP_NONE;
	dbus_bool_t		broadcast = TRUE;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (cb_data != NULL);
	g_return_if_fail (cb_data->applet != NULL);
	g_return_if_fail (cb_data->dev_op != NULL);

	nm_dbus_send_with_callback_replied (pcall, __func__);

	applet = cb_data->applet;

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (dbus_message_is_error (reply, NM_DBUS_NO_NETWORKS_ERROR))
	{
		dbus_message_unref (reply);
		goto out;
	}

	if (message_is_error (reply))
	{
		DBusError err;

		dbus_error_init (&err);
		dbus_set_error_from_message (&err, reply);
		nm_warning ("dbus returned an error.\n  (%s) %s\n", err.name, err.message);
		dbus_error_free (&err);
		dbus_message_unref (reply);
		goto out;
	}

	if (dbus_message_get_args (reply, NULL,	DBUS_TYPE_OBJECT_PATH, &op,
									DBUS_TYPE_STRING,  &essid,
									DBUS_TYPE_STRING,  &hw_addr,
									DBUS_TYPE_INT32,   &strength,
									DBUS_TYPE_DOUBLE,  &freq,
									DBUS_TYPE_INT32,   &rate,
									DBUS_TYPE_INT32,   &mode,
									DBUS_TYPE_INT32,   &capabilities,
									DBUS_TYPE_BOOLEAN, &broadcast,
									DBUS_TYPE_INVALID))
	{
		NetworkDevice *	dev;

		if ((dev = nma_get_device_for_nm_path (applet->device_list, cb_data->dev_op)))
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

			wireless_network_set_mode (net, mode);
			wireless_network_set_capabilities (net, capabilities);
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
 * nma_dbus_device_update_one_network
 *
 * Get properties on just one wireless network.
 *
 */
void nma_dbus_device_update_one_network (NMApplet *applet, const char *dev_path, const char *net_path, const char *active_net_path)
{
	DBusMessage *		message;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (dev_path != NULL);
	g_return_if_fail (net_path != NULL);

	if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, net_path, NM_DBUS_INTERFACE_DEVICES, "getProperties")))
	{
		NetPropCBData * cb_data = g_malloc0 (sizeof (NetPropCBData));

		cb_data->dev_op = g_strdup (dev_path);
		cb_data->act_net = (active_net_path && strlen (active_net_path)) ? g_strdup (active_net_path) : NULL;
		cb_data->applet = applet;

		nm_dbus_send_with_callback (applet->connection, message,
			nma_dbus_net_properties_cb, cb_data,
			(DBusFreeFunction) free_net_prop_cb_data, __func__);
		dbus_message_unref (message);
	}
}


/*
 * nma_dbus_device_remove_one_network
 *
 * Remove a wireless network from a device.
 *
 */
void nma_dbus_device_remove_one_network (NMApplet *applet, const char *dev_path, const char *net_path)
{
	NetworkDevice *	dev;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (dev_path != NULL);
	g_return_if_fail (net_path != NULL);

	if ((dev = nma_get_device_for_nm_path (applet->device_list, dev_path)))
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
 * nma_dbus_device_properties_cb
 *
 * Callback for each device we called "getProperties" on in nma_dbus_update_devices_cb().
 *
 */
static void nma_dbus_device_properties_cb (DBusPendingCall *pcall, void *user_data)
{
	DBusMessage *		reply;
	NMApplet *	applet = (NMApplet *) user_data;
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
	dbus_int32_t		mode = -1;
	dbus_int32_t		strength = -1;
	dbus_int32_t		speed = 0;
	char *			active_network_path = NULL;
	dbus_bool_t		link_active = FALSE;
	dbus_uint32_t		caps = NM_DEVICE_CAP_NONE;
	dbus_uint32_t		type_caps = NM_DEVICE_CAP_NONE;
	char **			networks = NULL;
	int				num_networks = 0;
	NMActStage		act_stage = NM_ACT_STAGE_UNKNOWN;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (applet != NULL);

	nm_dbus_send_with_callback_replied (pcall, __func__);

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (message_is_error (reply))
	{
		DBusError err;

		dbus_error_init (&err);
		dbus_set_error_from_message (&err, reply);
		nm_warning ("dbus returned an error.\n  (%s) %s\n", err.name, err.message);
		dbus_error_free (&err);
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
									DBUS_TYPE_INT32,  &mode,
									DBUS_TYPE_INT32,  &strength,
									DBUS_TYPE_BOOLEAN,&link_active,
									DBUS_TYPE_INT32,  &speed,
									DBUS_TYPE_UINT32, &caps,
									DBUS_TYPE_UINT32, &type_caps,
									DBUS_TYPE_STRING, &active_network_path,
									DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &networks, &num_networks,
									DBUS_TYPE_INVALID))
	{
		NetworkDevice *dev = network_device_new (iface, type, op);
		NetworkDevice *tmp_dev = nma_get_device_for_nm_path (applet->device_list, op);

		network_device_set_hal_udi (dev, udi);
		network_device_set_address (dev, hw_addr);
		network_device_set_speed (dev, speed);
		network_device_set_active (dev, active);
		network_device_set_link (dev, link_active);
		network_device_set_capabilities (dev, caps);
		network_device_set_type_capabilities (dev, type_caps);
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

		nma_dbus_update_device_info_from_hal (dev, applet);
		nma_dbus_device_get_driver (dev, applet);

		if (type == DEVICE_TYPE_802_11_WIRELESS)
		{
			network_device_set_strength (dev, strength);

			/* Call the "getProperties" method on each wireless network the device may have. */
			if (num_networks > 0)
			{
				char ** item;

				for (item = networks; *item; item++)
					nma_dbus_device_update_one_network (applet, op, *item, active_network_path);
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
 * nma_dbus_device_update_one_device
 *
 * Get properties on just one device.
 *
 */
void nma_dbus_device_update_one_device (NMApplet *applet, const char *dev_path)
{
	DBusMessage *		message;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (dev_path != NULL);

	if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, dev_path, NM_DBUS_INTERFACE_DEVICES, "getProperties")))
	{
		nm_dbus_send_with_callback (applet->connection, message,
				nma_dbus_device_properties_cb, applet, NULL, __func__);
		dbus_message_unref (message);
	}
}

typedef struct _DeviceActivatedCBData
{
	NMApplet *applet;
	char	*essid;
} DeviceActivatedCBData;

static void free_device_activated_cb_data (DeviceActivatedCBData *obj)
{
	if (!obj)
		return;

	obj->applet = NULL;
	g_free (obj->essid);
	memset (obj, 0, sizeof (DeviceActivatedCBData));
	g_free (obj);
}

static void nma_dbus_device_activated_cb (DBusPendingCall *pcall, void *user_data)
{
	DeviceActivatedCBData *	cb_data = (DeviceActivatedCBData*) user_data;
	NMApplet *			applet = cb_data->applet;
#ifdef ENABLE_NOTIFY
	char *				essid = cb_data->essid;
	NetworkDevice *		active_device;
	char *				message = NULL;
	char *				icon = NULL;
#endif

	nm_dbus_send_with_callback_replied (pcall, __func__);

	nma_dbus_device_properties_cb (pcall, applet);

	/* Don't show anything if the applet isn't shown */
#ifdef HAVE_STATUS_ICON
	if (!gtk_status_icon_get_visible (applet->status_icon) ||
	    !gtk_status_icon_is_embedded (applet->status_icon))
		goto out;
#else
	if (!GTK_WIDGET_VISIBLE (GTK_WIDGET (applet->tray_icon)))
		goto out;
#endif /* HAVE_STATUS_ICON */

#ifdef ENABLE_NOTIFY
	active_device = nma_get_first_active_device (applet->device_list);
	if (active_device && network_device_is_wireless (active_device))
	{
		if (applet->is_adhoc)
		{
			message = g_strdup_printf (_("You are now connected to the Ad-Hoc wireless network '%s'."), essid);
			icon = "nm-adhoc";
		}
		else
		{
			message = g_strdup_printf (_("You are now connected to the wireless network '%s'."), essid);
			icon = "nm-device-wireless";
		}
		
	}
	else
	{
		message = g_strdup (_("You are now connected to the wired network."));
		icon = "nm-device-wired";
	}

	nm_info ("%s", message);

	nma_send_event_notification (applet, NOTIFY_URGENCY_LOW, _("Connection Established"), message, icon);
	g_free (message);
#endif

out:
	free_device_activated_cb_data (cb_data);
}


void nma_dbus_device_activated (NMApplet *applet, const char *dev_path, const char *essid)
{
	DBusMessage *			message;
	DeviceActivatedCBData *	cb_data = NULL;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (dev_path != NULL);

	cb_data = g_malloc0 (sizeof (DeviceActivatedCBData));
	cb_data->applet = applet;
	if (essid)
		cb_data->essid = g_strdup (essid);

	if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, dev_path, NM_DBUS_INTERFACE_DEVICES, "getProperties")))
	{
		nm_dbus_send_with_callback (applet->connection, message,
				nma_dbus_device_activated_cb, cb_data, NULL, __func__);
		dbus_message_unref (message);
	}
}


static void nma_dbus_device_deactivated_cb (DBusPendingCall *pcall, void *user_data)
{
	NMApplet *	applet = (NMApplet *) user_data;

	nm_dbus_send_with_callback_replied (pcall, __func__);

	nma_dbus_device_properties_cb (pcall, applet);

#ifdef ENABLE_NOTIFY
	/* Don't show anything if the applet isn't shown */
#ifdef HAVE_STATUS_ICON
	if (gtk_status_icon_get_visible (applet->status_icon) &&
	    gtk_status_icon_is_embedded (applet->status_icon))
#else
	if (GTK_WIDGET_VISIBLE (GTK_WIDGET (applet->tray_icon)))
#endif /* HAVE_STATUS_ICON */

	{
		nma_send_event_notification (applet, NOTIFY_URGENCY_NORMAL, _("Disconnected"),
			_("The network connection has been disconnected."), "nm-no-connection");
	}
#endif
}

void nma_dbus_device_deactivated (NMApplet *applet, const char *dev_path)
{
	DBusMessage *	message;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (dev_path != NULL);

	if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, dev_path, NM_DBUS_INTERFACE_DEVICES, "getProperties")))
	{
		nm_dbus_send_with_callback (applet->connection, message,
				nma_dbus_device_deactivated_cb, applet, NULL, __func__);
		dbus_message_unref (message);
	}
}


/*
 * nma_dbus_update_devices_cb
 *
 * nma_dbus_update_devices callback.
 *
 */
static void nma_dbus_update_devices_cb (DBusPendingCall *pcall, void *user_data)
{
	DBusMessage *	reply;
	NMApplet *	applet = (NMApplet *) user_data;
	char **		devices;
	int			num_devices;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (applet != NULL);

	nm_dbus_send_with_callback_replied (pcall, __func__);

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (dbus_message_is_error (reply, NM_DBUS_NO_DEVICES_ERROR))
	{
		dbus_message_unref (reply);
		goto out;
	}

	if (message_is_error (reply))
	{
		DBusError err;

		dbus_error_init (&err);
		dbus_set_error_from_message (&err, reply);
		nm_warning ("dbus returned an error.\n  (%s) %s\n", err.name, err.message);
		dbus_error_free (&err);
		dbus_message_unref (reply);
		goto out;
	}

	if (dbus_message_get_args (reply, NULL, DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH, &devices, &num_devices, DBUS_TYPE_INVALID))
	{
		char ** item;

		/* For each device, fire off a "getProperties" call */
		for (item = devices; *item; item++)
			nma_dbus_device_update_one_device (applet, *item);

		dbus_free_string_array (devices);
	}
	dbus_message_unref (reply);

out:
	dbus_pending_call_unref (pcall);
}


/*
 * nma_dbus_update_devices
 *
 * Do a full update of network devices, wireless networks, and dial up devices.
 *
 */
void nma_dbus_update_devices (NMApplet *applet)
{
	DBusMessage *		message;

	nma_free_data_model (applet);

	if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH, NM_DBUS_INTERFACE, "getDevices")))
	{
		nm_dbus_send_with_callback (applet->connection, message,
				nma_dbus_update_devices_cb, applet, NULL, __func__);
		dbus_message_unref (message);
	}
	nma_dbus_update_wireless_enabled (applet);
}


/*
 * nma_dbus_update_dialup_cb
 *
 * nma_dbus_update_dialup DBUS callback.
 *
 */
static void nma_dbus_update_dialup_cb (DBusPendingCall *pcall, void *user_data)
{
	DBusMessage *reply;
	NMApplet *applet = (NMApplet *) user_data;
	char **dialup_devices;
	int num_devices;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (applet != NULL);

	nm_dbus_send_with_callback_replied (pcall, __func__);

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (dbus_message_is_error (reply, NM_DBUS_NO_DIALUP_ERROR))
	{
		dbus_message_unref (reply);
		goto out;
	}

	if (message_is_error (reply))
	{
		DBusError err;

		dbus_error_init (&err);
		dbus_set_error_from_message (&err, reply);
		nm_warning ("dbus returned an error.\n  (%s) %s\n", err.name, err.message);
		dbus_error_free (&err);
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
 * nma_dbus_update_dialup
 *
 * Do an update of dial up devices.
 *
 */
void nma_dbus_update_dialup (NMApplet *applet)
{
	DBusMessage *message;

	nma_free_data_model (applet);

	if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH, NM_DBUS_INTERFACE, "getDialup")))
	{
		nm_dbus_send_with_callback (applet->connection, message,
				nma_dbus_update_dialup_cb, applet, NULL, __func__);
		dbus_message_unref (message);
	}
}


/*
 * nma_dbus_dialup_activate_connection
 *
 * Tell NetworkManager to activate a particular dialup connection.
 *
 */
void nma_dbus_dialup_activate_connection (NMApplet *applet, const char *name)
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
			nm_warning ("Could not send activateDialup message!");
		dbus_message_unref (message);
	}
	else
		nm_warning ("Couldn't allocate the dbus message!");
}


/*
 * nma_dbus_dialup_activate_connection
 *
 * Tell NetworkManager to activate a particular dialup connection.
 *
 */
void nma_dbus_dialup_deactivate_connection (NMApplet *applet, const char *name)
{
	DBusMessage *message;

	g_return_if_fail (name != NULL);

	if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH, NM_DBUS_INTERFACE, "deactivateDialup")))
	{

		nm_info ("Deactivating dialup connection '%s'.", name);
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
			nm_warning ("Could not send deactivateDialup message!");
		dbus_message_unref (message);
	}
	else
		nm_warning ("Couldn't allocate the dbus message!");
}


/*
 * nma_dbus_device_remove_one_device
 *
 * Remove a device from our list.
 *
 */
void nma_dbus_device_remove_one_device (NMApplet *applet, const char *dev_path)
{
	NetworkDevice *	dev;

	g_return_if_fail (applet != NULL);

	if ((dev = nma_get_device_for_nm_path (applet->device_list, dev_path)))
	{
		applet->device_list = g_slist_remove (applet->device_list, dev);
		network_device_unref (dev);
	}
}


/*
 * nma_dbus_set_device
 *
 * Tell NetworkManager to use a specific network device that the user picked, and
 * possibly a specific wireless network too.
 *
 */
void nma_dbus_set_device (DBusConnection *connection, NetworkDevice *dev, const char *essid,
					 gboolean fallback, WirelessSecurityOption * opt)
{
	DBusMessage *	message;
	gboolean		success = TRUE;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (dev != NULL);
	if (network_device_is_wireless (dev))
		g_return_if_fail (essid != NULL);

	if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH, NM_DBUS_INTERFACE, "setActiveDevice")))
	{
		const char *dev_path = network_device_get_nm_path (dev);

		if (network_device_is_wireless (dev))
		{
			/* Build up the required args */
			dbus_message_append_args (message, DBUS_TYPE_OBJECT_PATH, &dev_path,
										DBUS_TYPE_STRING, &essid,
										DBUS_TYPE_BOOLEAN, &fallback,
										DBUS_TYPE_INVALID);

			/* If we have specific wireless security options, add them */
			if (opt)
				success = wso_append_dbus_params (opt, essid, message);
		}
		else
		{
			nm_info ("Forcing device '%s'\n", network_device_get_nm_path (dev));
			dbus_message_append_args (message, DBUS_TYPE_OBJECT_PATH, &dev_path, DBUS_TYPE_INVALID);
		}
		if (success)
			dbus_connection_send (connection, message, NULL);
		dbus_message_unref (message);
	}
	else
		nm_warning ("Couldn't allocate the dbus message\n");
}


/*
 * nma_dbus_create_network
 *
 * Tell NetworkManager to create an Ad-Hoc wireless network
 *
 */
void nma_dbus_create_network (DBusConnection *connection, NetworkDevice *dev, const char *essid,
						WirelessSecurityOption * opt)
{
	DBusMessage	*message;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (dev != NULL);
	g_return_if_fail (essid != NULL);
	g_return_if_fail (network_device_is_wireless (dev));
	g_return_if_fail (opt != NULL);

	if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH, NM_DBUS_INTERFACE, "createWirelessNetwork")))
	{
		const char *dev_path;

		if ((dev_path = network_device_get_nm_path (dev)))
		{
			nm_info ("Creating network '%s' on device '%s'.\n", essid, dev_path);
			dbus_message_append_args (message, DBUS_TYPE_OBJECT_PATH, &dev_path,
										DBUS_TYPE_STRING, &essid,
										DBUS_TYPE_INVALID);
			wso_append_dbus_params (opt, essid, message);
			dbus_connection_send (connection, message, NULL);
		} else
			nm_warning ("Could not get the device path!\n");
		dbus_message_unref (message);
	}
	else
		nm_warning ("Couldn't allocate the dbus message\n");
}


/*
 * nma_dbus_enable_wireless
 *
 * Tell NetworkManager to enabled or disable all wireless devices.
 *
 */
void nma_dbus_enable_wireless (NMApplet *applet, gboolean enabled)
{
	DBusMessage	*message;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (applet->connection != NULL);

	if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH, NM_DBUS_INTERFACE, "setWirelessEnabled")))
	{
		dbus_message_append_args (message, DBUS_TYPE_BOOLEAN, &enabled, DBUS_TYPE_INVALID);
		dbus_connection_send (applet->connection, message, NULL);
		nma_dbus_update_wireless_enabled (applet);
		dbus_message_unref (message);
	}
}

/*
 * nma_dbus_enable_networking
 *
 * Tell NetworkManager to enabled or disable all wireless devices.
 *
 */
void nma_dbus_enable_networking (NMApplet *applet, gboolean enabled)
{
	DBusMessage	*message;
	const char	*method;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (applet->connection != NULL);

	if (enabled)
		method = "wake";
	else
		method = "sleep";

	if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH, NM_DBUS_INTERFACE, method)))
	{
		dbus_connection_send (applet->connection, message, NULL);
		dbus_message_unref (message);
	}
}


void nma_dbus_update_strength (NMApplet *applet, const char *dev_path, const char *net_path, int strength)
{
	NetworkDevice *dev;

	g_return_if_fail (applet != NULL);

	if ((dev = nma_get_device_for_nm_path (applet->device_list, dev_path)))
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
