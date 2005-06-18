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

#include "NetworkManagerDevice.h"
#include "NetworkManagerDbus.h"
#include "NetworkManagerDbusUtils.h"
#include "NetworkManagerPolicy.h"
#include "nm-dbus-device.h"

static DBusMessage *nm_dbus_device_get_name (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage	*reply = NULL;
	NMDevice		*dev;

	g_return_val_if_fail (data && data->data && data->dev && connection && message, NULL);

	dev = data->dev;
	if ((reply = dbus_message_new_method_return (message)))
		dbus_message_append_args (reply, DBUS_TYPE_STRING, nm_device_get_iface (dev), DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *nm_dbus_device_get_type (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage	*reply = NULL;
	NMDevice		*dev;

	g_return_val_if_fail (data && data->data && data->dev && connection && message, NULL);

	dev = data->dev;
	if ((reply = dbus_message_new_method_return (message)))
		dbus_message_append_args (reply, DBUS_TYPE_INT32, nm_device_get_type (dev), DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *nm_dbus_device_get_hal_udi (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage	*reply = NULL;
	NMDevice		*dev;

	g_return_val_if_fail (data && data->data && data->dev && connection && message, NULL);

	dev = data->dev;
	if ((reply = dbus_message_new_method_return (message)))
		dbus_message_append_args (reply, DBUS_TYPE_STRING, nm_device_get_udi (dev), DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *nm_dbus_device_get_ip4_address (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage	*reply = NULL;
	NMDevice		*dev;

	g_return_val_if_fail (data && data->data && data->dev && connection && message, NULL);

	dev = data->dev;
	if ((reply = dbus_message_new_method_return (message)))
		dbus_message_append_args (reply, DBUS_TYPE_UINT32, nm_device_get_ip4_address (dev), DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *nm_dbus_device_get_hw_address (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage	*reply = NULL;
	NMDevice		*dev;

	g_return_val_if_fail (data && data->data && data->dev && connection && message, NULL);

	dev = data->dev;
	if ((reply = dbus_message_new_method_return (message)))
	{
		struct ether_addr	addr;
		char				char_addr[20];

		nm_device_get_hw_address (dev, (unsigned char *)&(addr.ether_addr_octet));
		memset (char_addr, 0, 20);
		ether_ntoa_r (&addr, &char_addr[0]);
		dbus_message_append_args (reply, DBUS_TYPE_STRING, char_addr, DBUS_TYPE_INVALID);
	}

	return reply;
}

static DBusMessage *nm_dbus_device_get_mode (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage	*reply = NULL;
	NMDevice		*dev;

	g_return_val_if_fail (data && data->data && data->dev && connection && message, NULL);

	dev = data->dev;
	if ((reply = dbus_message_new_method_return (message)))
		dbus_message_append_args (reply, DBUS_TYPE_UINT32, nm_device_get_mode (dev), DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *nm_dbus_device_get_link_active (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage	*reply = NULL;
	NMDevice		*dev;

	g_return_val_if_fail (data && data->data && data->dev && connection && message, NULL);

	dev = data->dev;
	if ((reply = dbus_message_new_method_return (message)))
		dbus_message_append_args (reply, DBUS_TYPE_BOOLEAN, nm_device_get_link_active (dev), DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *nm_dbus_device_get_strength (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage	*reply = NULL;
	NMDevice		*dev;

	g_return_val_if_fail (data && data->data && data->dev && connection && message, NULL);

	/* Only wireless devices have signal strength */
	dev = data->dev;
	if (!nm_device_is_wireless (dev))
	{
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "DeviceNotWireless",
				"Wired devices cannot have signal strength.");
	}
	else if ((reply = dbus_message_new_method_return (message)))
		dbus_message_append_args (reply, DBUS_TYPE_INT32, nm_device_get_signal_strength (dev), DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *nm_dbus_device_get_active_network (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage	*reply = NULL;
	gboolean		 success = FALSE;
	NMDevice		*dev;

	g_return_val_if_fail (data && data->data && data->dev && connection && message, NULL);

	/* Only wireless devices have an active network */
	dev = data->dev;
	if (!nm_device_is_wireless (dev))
	{
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "DeviceNotWireless",
				"Wired devices cannot have active networks.");
	}
	else if ((reply = dbus_message_new_method_return (message)))
	{
		NMAccessPoint	*best_ap;

		/* Return the network associated with the ESSID the card is currently associated with,
		 * if any, and only if that network is the "best" network.
		 */
		if ((best_ap = nm_device_get_best_ap (dev)))
		{
			NMAccessPoint	*tmp_ap;
			char			*object_path = g_strdup_printf ("%s/%s/Networks/", NM_DBUS_PATH_DEVICES, nm_device_get_iface (dev));

			if (    (tmp_ap = nm_device_ap_list_get_ap_by_essid (dev, nm_ap_get_essid (best_ap)))
				&& (object_path = nm_device_get_path_for_ap (dev, tmp_ap)))
			{
				dbus_message_append_args (reply, DBUS_TYPE_STRING, object_path, DBUS_TYPE_INVALID);
				success = TRUE;
			}
			nm_ap_unref (best_ap);
			g_free (object_path);
		}
		if (!success)
		{
			dbus_message_unref (reply);
			reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "NoActiveNetwork",
					"The device is not associated with any networks at this time.");
		}
	}

	return reply;
}

static DBusMessage *nm_dbus_device_get_networks (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage	*reply = NULL;
	NMDevice		*dev;

	g_return_val_if_fail (data && data->data && data->dev && connection && message, NULL);

	/* Only wireless devices have networks */
	dev = data->dev;
	if (!nm_device_is_wireless (dev))
	{
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "DeviceNotWireless",
				"Wired devices cannot see wireless networks.");
	}
	else if ((reply = dbus_message_new_method_return (message)))
	{
		DBusMessageIter	 iter;
		DBusMessageIter	 iter_array;
		NMAccessPoint		*ap = NULL;
		gboolean			 success = FALSE;
		NMAccessPointList	*ap_list;
		NMAPListIter		*list_iter;
		char				*object_path;

		dbus_message_iter_init (reply, &iter);
		dbus_message_iter_append_array (&iter, &iter_array, DBUS_TYPE_STRING);

		if ((ap_list = nm_device_ap_list_get (dev)))
		{
			if ((list_iter = nm_ap_list_iter_new (ap_list)))
			{
				while ((ap = nm_ap_list_iter_next (list_iter)))
				{
					if (nm_ap_get_essid (ap))
					{
						object_path = g_strdup_printf ("%s/%s/Networks/%s", NM_DBUS_PATH_DEVICES,
								nm_device_get_iface (dev), nm_ap_get_essid (ap));
						dbus_message_iter_append_string (&iter_array, object_path);
						g_free (object_path);
						success = TRUE;
					}
				}
				nm_ap_list_iter_free (list_iter);
			}
		}

		if (!success)
		{
			dbus_message_unref (reply);
			reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "NoNetworks",
					"The device cannot see any wireless networks.");
		}
	}

	return reply;
}

static DBusMessage *nm_dbus_device_get_driver_support_level (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage	*reply = NULL;
	NMDevice		*dev;

	g_return_val_if_fail (data && data->data && data->dev && connection && message, NULL);

	dev = data->dev;
	if ((reply = dbus_message_new_method_return (message)))
		dbus_message_append_args (reply, DBUS_TYPE_UINT32, nm_device_get_driver_support_level (dev), DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *nm_dbus_device_set_link_active (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage	*reply = NULL;
	NMDevice		*dev;

	g_return_val_if_fail (data && data->data && data->dev && connection && message, NULL);

	/* Can only set link status for active devices */
	dev = data->dev;
	if (!nm_device_is_test_device (dev))
	{
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "NotTestDevice",
					"Only test devices can have their link status set manually.");
	}
	else if ((reply = dbus_message_new_method_return (message)))
	{
		DBusError	error;
		gboolean	link;

		dbus_error_init (&error);
		if (dbus_message_get_args (message, &error, DBUS_TYPE_BOOLEAN, &link, DBUS_TYPE_INVALID))
		{
			nm_device_set_link_active (dev, link);
			nm_policy_schedule_state_update (data->data);
		}
	}

	return reply;
}


/*
 * nm_dbus_device_methods_setup
 *
 * Register handlers for dbus methods on the org.freedesktop.NetworkManager.Devices object.
 *
 */
NMDbusMethodList *nm_dbus_device_methods_setup (void)
{
	NMDbusMethodList	*list = nm_dbus_method_list_new (NULL);

	nm_dbus_method_list_add_method (list, "getName",				nm_dbus_device_get_name);
	nm_dbus_method_list_add_method (list, "getType",				nm_dbus_device_get_type);
	nm_dbus_method_list_add_method (list, "getHalUdi",			nm_dbus_device_get_hal_udi);
	nm_dbus_method_list_add_method (list, "getIP4Address",			nm_dbus_device_get_ip4_address);
	nm_dbus_method_list_add_method (list, "getHWAddress",			nm_dbus_device_get_hw_address);
	nm_dbus_method_list_add_method (list, "getMode",				nm_dbus_device_get_mode);
	nm_dbus_method_list_add_method (list, "getStrength",			nm_dbus_device_get_strength);
	nm_dbus_method_list_add_method (list, "getActiveNetwork",		nm_dbus_device_get_active_network);
	nm_dbus_method_list_add_method (list, "getNetworks",			nm_dbus_device_get_networks);
	nm_dbus_method_list_add_method (list, "getLinkActive",			nm_dbus_device_get_link_active);
	nm_dbus_method_list_add_method (list, "setLinkActive",			nm_dbus_device_set_link_active);
	nm_dbus_method_list_add_method (list, "getDriverSupportLevel",	nm_dbus_device_get_driver_support_level);

	return (list);
}

