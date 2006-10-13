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
#include <syslog.h>
#include <netinet/ether.h>

#include "nm-utils.h"
#include "nm-device.h"
#include "NetworkManagerDbus.h"
#include "NetworkManagerDbusUtils.h"
#include "NetworkManagerPolicy.h"
#include "NetworkManagerUtils.h"
#include "nm-dbus-device.h"
#include "nm-device-802-3-ethernet.h"
#include "nm-device-802-11-wireless.h"
#include "nm-device-private.h"
#include "nm-dbus-net.h"


static DBusMessage *
new_invalid_device_type_error (DBusMessage *replyto)
{
	return nm_dbus_create_error_message (replyto,
		                                 NM_DBUS_INTERFACE,
		                                 "InvalidDeviceType",
                                         "Invalid device type for this"
                                         "request.");
}


static DBusMessage *
nm_dbus_device_get_name (DBusConnection *connection,
                         DBusMessage *message,
                         gpointer user_data)
{
	NMDbusCBData *data = (NMDbusCBData *) user_data;
	DBusMessage	*reply = NULL;
	const char *iface;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);
	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (data->dev != NULL, NULL);

	if (!(reply = dbus_message_new_method_return (message))) {
		nm_warning ("Not enough memory to create dbus message.");
		return NULL;
	}

	iface = nm_device_get_iface (data->dev);
	dbus_message_append_args (reply, DBUS_TYPE_STRING, &iface, DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *
nm_dbus_device_get_type (DBusConnection *connection,
                         DBusMessage *message,
                         gpointer user_data)
{
	NMDbusCBData *data = (NMDbusCBData *) user_data;
	DBusMessage	*reply = NULL;
	dbus_int32_t type;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);
	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (data->dev != NULL, NULL);

	if (!(reply = dbus_message_new_method_return (message))) {
		nm_warning ("Not enough memory to create dbus message.");
		return NULL;
	}

	type = nm_device_get_device_type (data->dev);
	dbus_message_append_args (reply, DBUS_TYPE_INT32, &type, DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *
nm_dbus_device_get_hal_udi (DBusConnection *connection,
                            DBusMessage *message,
                            gpointer user_data)
{
	NMDbusCBData *data = (NMDbusCBData *) user_data;
	DBusMessage	*reply = NULL;
	const char *udi;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);
	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (data->dev != NULL, NULL);

	if (!(reply = dbus_message_new_method_return (message))) {
		nm_warning ("Not enough memory to create dbus message.");
		return NULL;
	}

	udi = nm_device_get_udi (data->dev);
	dbus_message_append_args (reply, DBUS_TYPE_STRING, &udi, DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *
nm_dbus_device_get_ip4_address (DBusConnection *connection,
                                DBusMessage *message,
                                gpointer user_data)
{
	NMDbusCBData *data = (NMDbusCBData *) user_data;
	DBusMessage	*reply = NULL;
	dbus_uint32_t address;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);
	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (data->dev != NULL, NULL);

	if (!(reply = dbus_message_new_method_return (message))) {
		nm_warning ("Not enough memory to create dbus message.");
		return NULL;
	}
                
	address = nm_device_get_ip4_address (data->dev);
	dbus_message_append_args (reply, DBUS_TYPE_UINT32, &address, DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *
nm_dbus_device_get_hw_address (DBusConnection *connection,
                               DBusMessage *message,
                               gpointer user_data)
{
	NMDbusCBData *data = (NMDbusCBData *) user_data;
	DBusMessage	*reply = NULL;
	struct ether_addr	addr;
	char				char_addr[20];
	char *			ptr = &char_addr[0];

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);
	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (data->dev != NULL, NULL);

	if (!(reply = dbus_message_new_method_return (message))) {
		nm_warning ("Not enough memory to create dbus message.");
		return NULL;
	}

	memset (&addr, 0, sizeof (struct ether_addr));
	if (nm_device_is_802_3_ethernet (data->dev)) {
		nm_device_802_3_ethernet_get_address (NM_DEVICE_802_3_ETHERNET (data->dev), &addr);
	} else if (nm_device_is_802_11_wireless (data->dev)) {
		nm_device_802_11_wireless_get_address (NM_DEVICE_802_11_WIRELESS (data->dev), &addr);
	}
	memset (char_addr, 0, 20);
	iw_ether_ntop (&addr, char_addr);
	dbus_message_append_args (reply, DBUS_TYPE_STRING, &ptr, DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *
nm_dbus_device_get_mode (DBusConnection *connection,
                         DBusMessage *message,
                         gpointer user_data)
{
	NMDbusCBData *data = (NMDbusCBData *) user_data;
	DBusMessage	*reply = NULL;
	dbus_int32_t mode;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);
	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (data->dev != NULL, NULL);

	if (!nm_device_is_802_11_wireless (data->dev)) {
		reply = new_invalid_device_type_error (message);
		goto out;
	}

	if (!(reply = dbus_message_new_method_return (message))) {
		nm_warning ("Not enough memory to create dbus message.");
		goto out;
	}

	mode = (dbus_int32_t) nm_device_802_11_wireless_get_mode (NM_DEVICE_802_11_WIRELESS (data->dev));
	dbus_message_append_args (reply, DBUS_TYPE_INT32, &mode, DBUS_TYPE_INVALID);

out:
	return reply;
}

static DBusMessage *
nm_dbus_device_get_link_active (DBusConnection *connection,
                                DBusMessage *message,
                                gpointer user_data)
{
	NMDbusCBData *data = (NMDbusCBData *) user_data;
	DBusMessage	*reply = NULL;
	dbus_bool_t is_active;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);
	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (data->dev != NULL, NULL);

	if (!(reply = dbus_message_new_method_return (message))) {
		nm_warning ("Not enough memory to create dbus message.");
		return NULL;
	}

	is_active = nm_device_has_active_link (data->dev);
	dbus_message_append_args (reply, DBUS_TYPE_BOOLEAN, &is_active, DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *
nm_dbus_device_get_active_network (DBusConnection *connection,
                                   DBusMessage *message,
                                   gpointer user_data)
{
	NMDbusCBData *data = (NMDbusCBData *) user_data;
	DBusMessage	*reply = NULL;
	NMDevice *	dev;
	gboolean		 success = FALSE;
	NMActRequest *	req;
	NMAccessPoint *	ap;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);
	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (data->dev != NULL, NULL);

	/* Only wireless devices have an active network */
	dev = data->dev;
	if (!nm_device_is_802_11_wireless (dev))
	{
		reply = new_invalid_device_type_error (message);
		goto out;
	}

	if (!(reply = dbus_message_new_method_return (message))) {
		nm_warning ("Not enough memory to create dbus message.");
		goto out;
	}

	req = nm_device_get_act_request (dev);
	if (req && (ap = nm_act_request_get_ap (req))) {
		NMAccessPoint *tmp_ap;
		char *		object_path = NULL;

		tmp_ap = nm_device_802_11_wireless_ap_list_get_ap_by_essid (NM_DEVICE_802_11_WIRELESS (dev), nm_ap_get_essid (ap));
		if (tmp_ap && (object_path = nm_dbus_get_object_path_for_network (dev, tmp_ap))) {
			dbus_message_append_args (reply, DBUS_TYPE_OBJECT_PATH, &object_path, DBUS_TYPE_INVALID);
			g_free (object_path);
			success = TRUE;
		}
	}

	if (!success) {
		dbus_message_unref (reply);
		reply = nm_dbus_create_error_message (message,
		                                      NM_DBUS_INTERFACE,
		                                      "NoActiveNetwork",
		                                      "The device is not associated "
		                                      " with any networks at this time.");
	}

out:
	return reply;
}

static DBusMessage *
nm_dbus_device_get_networks (DBusConnection *connection,
                             DBusMessage *message,
                             gpointer user_data)
{
	NMDbusCBData *data = (NMDbusCBData *) user_data;
	DBusMessage	*		reply = NULL;
	NMDevice *			dev;
	DBusMessageIter		iter;
	DBusMessageIter		iter_array;
	NMAccessPoint *		ap = NULL;
	gboolean			success = FALSE;
	NMAccessPointList *	ap_list;
	NMAPListIter *		list_iter;
	char *				escaped_object_path;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);
	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (data->dev != NULL, NULL);

	if (!nm_device_is_802_11_wireless (data->dev)) {
		reply = new_invalid_device_type_error (message);
		goto out;
	}

	if (!(reply = dbus_message_new_method_return (message))) {
		nm_warning ("Not enough memory to create dbus message.");
		goto out;
	}

	dbus_message_iter_init_append (reply, &iter);
	dbus_message_iter_open_container (&iter, DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH_AS_STRING, &iter_array);

	dev = data->dev;
	if ((ap_list = nm_device_802_11_wireless_ap_list_get (NM_DEVICE_802_11_WIRELESS (dev)))) {
		if ((list_iter = nm_ap_list_iter_new (ap_list))) {
			while ((ap = nm_ap_list_iter_next (list_iter))) {
				if (nm_ap_get_essid (ap)) {
					escaped_object_path = nm_dbus_get_object_path_for_network (dev, ap);
					dbus_message_iter_append_basic (&iter_array, DBUS_TYPE_OBJECT_PATH, &escaped_object_path);
					g_free (escaped_object_path);
					success = TRUE;
				}
			}
			nm_ap_list_iter_free (list_iter);
		}
	}
	dbus_message_iter_close_container (&iter, &iter_array);

	if (!success) {
		dbus_message_unref (reply);
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "NoNetworks",
				"The device cannot see any wireless networks.");
	}

out:
	return reply;
}

static DBusMessage *
nm_dbus_device_get_capabilities (DBusConnection *connection,
                                 DBusMessage *message,
                                 gpointer user_data)
{
	NMDbusCBData *data = (NMDbusCBData *) user_data;
	DBusMessage	*reply = NULL;
	dbus_uint32_t capabilities;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);
	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (data->dev != NULL, NULL);

	if (!(reply = dbus_message_new_method_return (message))) {
		nm_warning ("Not enough memory to create dbus message.");
		return NULL;
	}

	capabilities = nm_device_get_capabilities (data->dev);
	dbus_message_append_args (reply, DBUS_TYPE_UINT32, &capabilities, DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *
nm_dbus_device_get_driver (DBusConnection *connection,
                           DBusMessage *message,
                           gpointer user_data)
{
	NMDbusCBData *data = (NMDbusCBData *) user_data;
	DBusMessage	*reply = NULL;
	const char * driver;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);
	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (data->dev != NULL, NULL);

	if (!(reply = dbus_message_new_method_return (message))) {
		nm_warning ("Not enough memory to create dbus message.");
		return NULL;
	}

	driver = nm_device_get_driver (data->dev);
	if (!driver)
		driver = "";
	dbus_message_append_args (reply, DBUS_TYPE_STRING, &driver, DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *
nm_dbus_device_set_link_active (DBusConnection *connection,
                                DBusMessage *message,
                                gpointer user_data)
{
	NMDbusCBData *data = (NMDbusCBData *) user_data;
	DBusMessage	*reply = NULL;
	gboolean	have_link;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);
	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (data->dev != NULL, NULL);
	g_return_val_if_fail (data->data != NULL, NULL);

	/* Can only set link status for test devices */
	if (!nm_device_is_test_device (data->dev))
	{
		reply = nm_dbus_create_error_message (message,
		                                      NM_DBUS_INTERFACE,
		                                      "NotTestDevice",
		                                      "Only test devices can have their"
		                                      " link status set manually.");
		goto out;
	}

	if (!(reply = dbus_message_new_method_return (message))) {
		nm_warning ("Not enough memory to create dbus message.");
		goto out;
	}

	if (!dbus_message_get_args (message, NULL,
	                            DBUS_TYPE_BOOLEAN, &have_link,
	                            DBUS_TYPE_INVALID)) {
		reply = nm_dbus_new_invalid_args_error (message, NM_DBUS_INTERFACE);
		goto out;
	}

	nm_device_set_active_link (data->dev, have_link);
	nm_policy_schedule_device_change_check (data->data);

out:
	return reply;
}

static DBusMessage *
nm_dbus_device_get_properties (DBusConnection *connection,
                               DBusMessage *message,
                               gpointer user_data)
{
	NMDbusCBData *		data = (NMDbusCBData *) user_data;
	DBusMessage	*		reply = NULL;
	NMDevice *			dev;
	char *				op;
	const char *		iface;
	dbus_uint32_t		type;
	const char *		udi;
	gchar *				ip4_address;
	gchar *				broadcast;
	gchar *				subnetmask;
	gchar *				route;
	gchar *				primary_dns;
	gchar *				secondary_dns;
	struct ether_addr	hw_addr;
	char				hw_addr_buf[20];
	char *				hw_addr_buf_ptr = &hw_addr_buf[0];
	dbus_int32_t		mode = -1;
	dbus_int32_t		strength = -1;
	dbus_int32_t		speed = 0;
	char *				active_network_path = NULL;
	dbus_bool_t			link_active;
	dbus_uint32_t		capabilities;
	dbus_uint32_t		type_capabilities;
	char **				networks = NULL;
	int					num_networks = 0;
	dbus_bool_t			active;
	NMActStage			act_stage;
	NMIP4Config *		ip4config;
	guint32				broadcast_addr = 0;
	guint32				subnetmask_addr = 0;
	guint32				route_addr = 0;
	guint32				primary_dns_addr = 0;
	guint32				secondary_dns_addr = 0;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);
	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (data->dev != NULL, NULL);
	g_return_val_if_fail (data->data != NULL, NULL);

	if (!(reply = dbus_message_new_method_return (message))) {
		nm_warning ("Not enough memory to create dbus message.");
		goto out;
	}

	dev = data->dev;
	op = nm_dbus_get_object_path_for_device (dev);
	iface = nm_device_get_iface (dev);
	type = nm_device_get_device_type (dev);
	udi = nm_device_get_udi (dev);
	link_active = (dbus_bool_t) nm_device_has_active_link (dev);
	capabilities = (dbus_uint32_t) nm_device_get_capabilities (dev);
	type_capabilities = (dbus_uint32_t) nm_device_get_type_capabilities (dev);
	active = nm_device_get_act_request (dev) ? TRUE : FALSE;
	act_stage = active ? nm_act_request_get_stage (nm_device_get_act_request (dev)) : NM_ACT_STAGE_UNKNOWN;

	memset (hw_addr_buf, 0, 20);
	if (nm_device_is_802_3_ethernet (dev))
		nm_device_802_3_ethernet_get_address (NM_DEVICE_802_3_ETHERNET (dev), &hw_addr);
	else if (nm_device_is_802_11_wireless (dev))
		nm_device_802_11_wireless_get_address (NM_DEVICE_802_11_WIRELESS (dev), &hw_addr);
	iw_ether_ntop (&hw_addr, hw_addr_buf);

	ip4config = nm_device_get_ip4_config (dev);
	if (ip4config) {
		guint32 nr_nameservers;

		broadcast_addr = nm_ip4_config_get_broadcast (ip4config);
		subnetmask_addr = nm_ip4_config_get_netmask (ip4config);
		route_addr = nm_ip4_config_get_gateway (ip4config);

		nr_nameservers = nm_ip4_config_get_num_nameservers (ip4config);
		if (nr_nameservers > 1)
			secondary_dns_addr = nm_ip4_config_get_nameserver (ip4config, 1);
		if (nr_nameservers > 0)
			primary_dns_addr = nm_ip4_config_get_nameserver (ip4config, 0);
	}
	ip4_address = nm_utils_inet_ip4_address_as_string (nm_device_get_ip4_address (dev));
	broadcast = nm_utils_inet_ip4_address_as_string (broadcast_addr);
	subnetmask = nm_utils_inet_ip4_address_as_string (subnetmask_addr);
	route = nm_utils_inet_ip4_address_as_string (route_addr);
	primary_dns = nm_utils_inet_ip4_address_as_string (primary_dns_addr);
	secondary_dns = nm_utils_inet_ip4_address_as_string (secondary_dns_addr);

	if (nm_device_is_802_11_wireless (dev)) {
		NMDevice80211Wireless *	wdev = NM_DEVICE_802_11_WIRELESS (dev);
		NMActRequest *		req = nm_device_get_act_request (dev);
		NMAccessPoint *	ap;
		NMAccessPointList *	ap_list;
		NMAPListIter *		iter;

		strength = nm_device_802_11_wireless_get_signal_strength (wdev);
		mode = nm_device_802_11_wireless_get_mode (wdev);
		speed = nm_device_802_11_wireless_get_bitrate (wdev);

		if (req && (ap = nm_act_request_get_ap (req))) {
			NMAccessPoint	*tmp_ap;

			if ((tmp_ap = nm_device_802_11_wireless_ap_list_get_ap_by_essid (wdev, nm_ap_get_essid (ap))))
				active_network_path = nm_dbus_get_object_path_for_network (dev, tmp_ap);
		}

		ap_list = nm_device_802_11_wireless_ap_list_get (wdev);
		if (ap_list && (num_networks = nm_ap_list_size (ap_list))) {
			if ((iter = nm_ap_list_iter_new (ap_list))) {
				int				i = 0;

				networks = g_malloc0 (sizeof (char *) * (num_networks + 1));
				while ((ap = nm_ap_list_iter_next (iter))) {
					char *ap_op = nm_dbus_get_object_path_for_network (dev, ap);
					if (ap_op)
						networks[i++] = ap_op;
				}
				num_networks = i;	/* # actually added to array, since we can have NULL essid access points */

				nm_ap_list_iter_free (iter);
			}
		}
	} else {
		speed = nm_device_802_3_ethernet_get_speed (NM_DEVICE_802_3_ETHERNET (dev));
	}

	if (!active_network_path)
		active_network_path = g_strdup ("");

	dbus_message_append_args (reply,
	                          DBUS_TYPE_OBJECT_PATH, &op,
	                          DBUS_TYPE_STRING, &iface,
	                          DBUS_TYPE_UINT32, &type,
	                          DBUS_TYPE_STRING, &udi,
	                          DBUS_TYPE_BOOLEAN,&active,
	                          DBUS_TYPE_UINT32, &act_stage,
	                          DBUS_TYPE_STRING, &ip4_address,
	                          DBUS_TYPE_STRING, &subnetmask,
	                          DBUS_TYPE_STRING, &broadcast,
	                          DBUS_TYPE_STRING, &hw_addr_buf_ptr,
	                          DBUS_TYPE_STRING, &route,
	                          DBUS_TYPE_STRING, &primary_dns,
	                          DBUS_TYPE_STRING, &secondary_dns,
	                          DBUS_TYPE_INT32,  &mode,
	                          DBUS_TYPE_INT32,  &strength,
	                          DBUS_TYPE_BOOLEAN,&link_active,
	                          DBUS_TYPE_INT32,  &speed,
	                          DBUS_TYPE_UINT32, &capabilities,
	                          DBUS_TYPE_UINT32, &type_capabilities,
	                          DBUS_TYPE_STRING, &active_network_path,
	                          DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &networks, num_networks,
	                          DBUS_TYPE_INVALID);
	g_free (op);
	g_free (active_network_path);
	g_strfreev (networks);
	g_free (route);
	g_free (ip4_address);
	g_free (broadcast);
	g_free (subnetmask);

out:
	return reply;
}


/*
 * nm_dbus_devices_message_handler
 *
 * Dispatch messages against individual network devices
 *
 */
static DBusHandlerResult
nm_dbus_device_message_handler (DBusConnection *connection,
                                DBusMessage *message,
                                void *user_data)
{
	NMData *		data = (NMData *)user_data;
	gboolean		handled = FALSE;
	const char *	path;
	DBusMessage *	reply = NULL;
	NMDevice *		dev;
	char *			object_path;
	char *			escaped_object_path;
	NMDbusCBData *	cb_data;

	g_return_val_if_fail (connection != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (message != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (data != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	path = dbus_message_get_path (message);
	if (!(dev = nm_dbus_get_device_from_escaped_object_path (data, path))) {
		reply = nm_dbus_create_error_message (message,
		                                      NM_DBUS_INTERFACE,
		                                      "DeviceNotFound",
		                                      "The requested device does not "
		                                      " exist.");
		goto out;
	}

	/* Test whether or not the _networks_ of a device were queried instead of the device itself */
	object_path = g_strdup_printf ("%s/%s/Networks/",
	                               NM_DBUS_PATH_DEVICES,
	                               nm_device_get_iface (dev));
	escaped_object_path = nm_dbus_escape_object_path (object_path);
	g_free (object_path);

	cb_data = g_slice_new0 (NMDbusCBData);
	cb_data->data = data;
	cb_data->dev = dev;

	if (strncmp (path, escaped_object_path, strlen (escaped_object_path)) == 0) {
		handled = nm_dbus_net_methods_dispatch (data->net_methods,
		                                        connection,
		                                        message,
		                                        cb_data,
		                                        &reply);
	} else {
		handled = nm_dbus_method_list_dispatch (data->device_methods,
		                                        connection,
		                                        message,
		                                        cb_data,
		                                        &reply);
	}
	g_object_unref (G_OBJECT (cb_data->dev));
	g_slice_free (NMDbusCBData, cb_data);
	g_free (escaped_object_path);

out:
	if (reply)
	{
		dbus_connection_send (connection, reply, NULL);
		dbus_message_unref (reply);
		handled = TRUE;
	}

	return (handled ? DBUS_HANDLER_RESULT_HANDLED : DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
}

/*
 * nm_dbus_device_methods_setup
 *
 * Register handlers for dbus methods on the org.freedesktop.NetworkManager.Devices object.
 *
 */
NMDbusMethodList *nm_dbus_device_methods_setup (NMData *data)
{
	NMDbusMethodList * list;

	g_return_val_if_fail (data != NULL, NULL);
	
	list = nm_dbus_method_list_new (NM_DBUS_PATH_DEVICES, TRUE, data, NULL);
	nm_dbus_method_list_set_custom_handler_func (list, nm_dbus_device_message_handler);

	nm_dbus_method_list_add_method (list, "getProperties",		nm_dbus_device_get_properties);
	nm_dbus_method_list_add_method (list, "getName",			nm_dbus_device_get_name);
	nm_dbus_method_list_add_method (list, "getType",			nm_dbus_device_get_type);
	nm_dbus_method_list_add_method (list, "getHalUdi",		nm_dbus_device_get_hal_udi);
	nm_dbus_method_list_add_method (list, "getIP4Address",		nm_dbus_device_get_ip4_address);
	nm_dbus_method_list_add_method (list, "getHWAddress",		nm_dbus_device_get_hw_address);
	nm_dbus_method_list_add_method (list, "getMode",			nm_dbus_device_get_mode);
	nm_dbus_method_list_add_method (list, "getActiveNetwork",	nm_dbus_device_get_active_network);
	nm_dbus_method_list_add_method (list, "getNetworks",		nm_dbus_device_get_networks);
	nm_dbus_method_list_add_method (list, "getLinkActive",		nm_dbus_device_get_link_active);
	nm_dbus_method_list_add_method (list, "setLinkActive",		nm_dbus_device_set_link_active);
	nm_dbus_method_list_add_method (list, "getCapabilities",	nm_dbus_device_get_capabilities);
	nm_dbus_method_list_add_method (list, "getDriver",		nm_dbus_device_get_driver);

	return (list);
}
