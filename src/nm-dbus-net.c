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

#include "NetworkManagerDevice.h"
#include "NetworkManagerDbus.h"
#include "NetworkManagerAP.h"
#include "NetworkManagerAPList.h"
#include "NetworkManagerUtils.h"
#include "nm-dbus-net.h"

/*
 * nm_dbus_get_ap_from_object_path
 *
 * Returns the network (ap) associated with a dbus object path
 *
 */
static NMAccessPoint *nm_dbus_get_ap_from_object_path (const char *path, NMDevice *dev)
{
	NMAccessPoint		*ap = NULL;
	NMAccessPointList	*ap_list;
	NMAPListIter		*iter;
	char			 	 compare_path[100];

	g_return_val_if_fail (path != NULL, NULL);
	g_return_val_if_fail (dev != NULL, NULL);

	ap_list = nm_device_ap_list_get (dev);
	if (!ap_list)
		return (NULL);

	if (!(iter = nm_ap_list_iter_new (ap_list)))
		return (NULL);

	while ((ap = nm_ap_list_iter_next (iter)))
	{
		snprintf (compare_path, 100, "%s/%s/Networks/%s", NM_DBUS_PATH_DEVICES,
				nm_device_get_iface (dev), nm_ap_get_essid (ap));
		if (strncmp (path, compare_path, strlen (compare_path)) == 0)
			break;
	}
		
	nm_ap_list_iter_free (iter);
	return (ap);
}


static DBusMessage *nm_dbus_net_validate (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage	*reply = NULL;
	NMAccessPoint	*ap;
	const char	*path;

	g_return_val_if_fail (data && data->data && data->dev && connection && message, NULL);

	path = dbus_message_get_path (message);
	if ((ap = nm_dbus_get_ap_from_object_path (path, data->dev)))
		data->ap = ap;
	else
	{
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "NetworkNotFound",
						"The requested network does not exist for this device.");
	}

	return reply;
}

static DBusMessage *nm_dbus_net_get_name (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage	*reply = NULL;

	g_return_val_if_fail (data && data->data && data->dev && data->ap && connection && message, NULL);

	if ((reply = dbus_message_new_method_return (message)))
		dbus_message_append_args (reply, DBUS_TYPE_STRING, nm_ap_get_essid (data->ap), DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *nm_dbus_net_get_address (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage	*reply = NULL;

	g_return_val_if_fail (data && data->data && data->dev && data->ap && connection && message, NULL);

	if ((reply = dbus_message_new_method_return (message)))
	{
		char		buf[20];

		memset (&buf[0], 0, 20);
		iw_ether_ntop((const struct ether_addr *) (nm_ap_get_address (data->ap)), &buf[0]);
		dbus_message_append_args (reply, DBUS_TYPE_STRING, &buf[0], DBUS_TYPE_INVALID);
	}

	return reply;
}

static DBusMessage *nm_dbus_net_get_strength (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage	*reply = NULL;

	g_return_val_if_fail (data && data->data && data->dev && data->ap && connection && message, NULL);

	/* We iterate over the device list and return the best strength for all
	 * APs with the given ESSID.
	 */
	if ((reply = dbus_message_new_method_return (message)))
	{
		NMAccessPoint		*tmp_ap = NULL;
		NMAccessPointList	*ap_list;
		NMAPListIter		*iter;
		int				 best_strength = nm_ap_get_strength (data->ap);

		if (!(ap_list = nm_device_ap_list_get (data->dev)))
			goto append;

		if (!(iter = nm_ap_list_iter_new (ap_list)))
			goto append;

		/* Find best strength # among all APs that share this essid */
		while ((tmp_ap = nm_ap_list_iter_next (iter)))
		{
			if (nm_null_safe_strcmp (nm_ap_get_essid (data->ap), nm_ap_get_essid (tmp_ap)) == 0)
				if (nm_ap_get_strength (tmp_ap) > best_strength)
					best_strength = nm_ap_get_strength (tmp_ap);
		}
		nm_ap_list_iter_free (iter);

	append:
		dbus_message_append_args (reply, DBUS_TYPE_INT32, best_strength, DBUS_TYPE_INVALID);
	}

	return reply;
}

static DBusMessage *nm_dbus_net_get_frequency (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage	*reply = NULL;

	g_return_val_if_fail (data && data->data && data->dev && data->ap && connection && message, NULL);

	if ((reply = dbus_message_new_method_return (message)))
		dbus_message_append_args (reply, DBUS_TYPE_DOUBLE, nm_ap_get_freq (data->ap), DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *nm_dbus_net_get_rate (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage	*reply = NULL;

	g_return_val_if_fail (data && data->data && data->dev && data->ap && connection && message, NULL);

	if ((reply = dbus_message_new_method_return (message)))
		dbus_message_append_args (reply, DBUS_TYPE_INT32, nm_ap_get_rate (data->ap), DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *nm_dbus_net_get_encrypted (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage	*reply = NULL;

	g_return_val_if_fail (data && data->data && data->dev && data->ap && connection && message, NULL);

	if ((reply = dbus_message_new_method_return (message)))
		dbus_message_append_args (reply, DBUS_TYPE_BOOLEAN, nm_ap_get_encrypted (data->ap), DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *nm_dbus_net_get_mode (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage	*reply = NULL;

	g_return_val_if_fail (data && data->data && data->dev && data->ap && connection && message, NULL);

	if ((reply = dbus_message_new_method_return (message)))
		dbus_message_append_args (reply, DBUS_TYPE_UINT32, nm_ap_get_mode (data->ap), DBUS_TYPE_INVALID);

	return reply;
}


/*
 * nm_dbus_net_methods_setup
 *
 * Register handlers for dbus methods on the
 * org.freedesktop.NetworkManager.Devices.<dev>.Networks object.
 *
 */
NMDbusMethodList *nm_dbus_net_methods_setup (void)
{
	NMDbusMethodList	*list = nm_dbus_method_list_new (nm_dbus_net_validate);

	nm_dbus_method_list_add_method (list, "getName",			nm_dbus_net_get_name);
	nm_dbus_method_list_add_method (list, "getAddress",		nm_dbus_net_get_address);
	nm_dbus_method_list_add_method (list, "getStrength",		nm_dbus_net_get_strength);
	nm_dbus_method_list_add_method (list, "getFrequency",		nm_dbus_net_get_frequency);
	nm_dbus_method_list_add_method (list, "getRate",			nm_dbus_net_get_rate);
	nm_dbus_method_list_add_method (list, "getEncrypted",		nm_dbus_net_get_encrypted);
	nm_dbus_method_list_add_method (list, "getMode",			nm_dbus_net_get_mode);

	return (list);
}
