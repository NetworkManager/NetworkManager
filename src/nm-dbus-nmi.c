/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

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

#include "NetworkManager.h"
#include "nm-device.h"
#include "nm-activation-request.h"
#include "nm-device-802-3-ethernet.h"
#include "NetworkManagerAPList.h"
#include "NetworkManagerPolicy.h"
#include "NetworkManagerUtils.h"
#include "nm-dbus-nmi.h"
#include "nm-utils.h"


static gboolean
nm_dbus_get_wireless_user_key_done (DBusMessage *reply, NMActRequest *req)
{
	NMAccessPoint *ap;
	NMData *data;
	NMAPSecurity *security;
	DBusMessageIter iter;

	const char *iface = nm_device_get_iface (nm_act_request_get_dev (req));

	data = nm_act_request_get_data (req);
	g_assert (data);

	ap = nm_act_request_get_ap (req);
	g_assert (ap);

	if (message_is_error (reply)) {
		DBusError err;

		dbus_error_init (&err);
		dbus_set_error_from_message (&err, reply);

		/* Check for cancelled error */
		if (strcmp (err.name, NMI_DBUS_USER_KEY_CANCELED_ERROR) == 0)
			nm_info ("Activation (%s) New wireless user key request for network '%s' was canceled.",
				    iface, nm_ap_get_essid (ap));
		else
			nm_warning ("nm_dbus_get_user_key_for_network_cb(): dbus returned an error.\n  (%s) %s\n", err.name, err.message);

		dbus_error_free (&err);

		/* FIXME: since we're not marking the device as invalid, its a fair bet
		 * that NM will just try to reactivate the device again, and may fail
		 * to get the user key in exactly the same way, which ends up right back
		 * here...  ad nauseum.  Figure out how to deal with a failure here.
		 */
		nm_ap_list_append_ap (data->invalid_ap_list, ap);
		return FALSE;
	}

	nm_info ("Activation (%s) New wireless user key for network '%s' received.", iface, nm_ap_get_essid (ap));

	dbus_message_iter_init (reply, &iter);
	if ((security = nm_ap_security_new_deserialize (&iter))) {
		NMAccessPoint *allowed_ap;

		nm_ap_set_security (ap, security);

		/* Since we got a new security info, update the copy in allowed_ap_list */
		allowed_ap = nm_ap_list_get_ap_by_essid (data->allowed_ap_list, nm_ap_get_essid (ap));
		if (allowed_ap)
			nm_ap_set_security (allowed_ap, security);

		g_object_unref (G_OBJECT (security));	/* set_security copies the object */
	}

	return TRUE;
}

static gboolean
nm_dbus_get_wired_user_key_done (DBusMessage *reply, NMActRequest *req)
{
	NMAPSecurity *security;
	DBusMessageIter iter;
	NMWiredNetwork *wired_net;
	const char *iface = nm_device_get_iface (nm_act_request_get_dev (req));

	wired_net = nm_act_request_get_wired_network (req);
	g_assert (wired_net);

	if (message_is_error (reply)) {
		DBusError err;

		dbus_error_init (&err);
		dbus_set_error_from_message (&err, reply);

		/* Check for cancelled error */
		if (strcmp (err.name, NMI_DBUS_USER_KEY_CANCELED_ERROR) == 0)
			nm_info ("Activation (%s) New wired user key request was canceled.", iface);
		else
			nm_warning ("nm_dbus_get_user_key_for_network_cb(): dbus returned an error.\n  (%s) %s\n", err.name, err.message);

		dbus_error_free (&err);
		return FALSE;
	}

	nm_info ("Activation (%s) New wired user key received.", iface);

	dbus_message_iter_init (reply, &iter);
	if ((security = nm_ap_security_new_deserialize (&iter))) {
		nm_wired_network_set_security (wired_net, security);
		g_object_unref (security);
	}

	return TRUE;
}

/*
 * nm_dbus_get_user_key_for_network_cb
 *
 * Callback from nm_dbus_get_user_key_for_network when NetworkManagerInfo returns
 * the new user key.
 *
 */
static void nm_dbus_get_user_key_for_network_cb (DBusPendingCall *pcall, NMActRequest *req)
{
	NMDevice *dev;
	gboolean success;
	DBusMessage *reply = NULL;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (req != NULL);

	if (!dbus_pending_call_get_completed (pcall))
		goto out;

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	dev = nm_act_request_get_dev (req);
	g_assert (dev);

	nm_act_request_set_user_key_pending_call (req, NULL);

	if (NM_IS_DEVICE_802_11_WIRELESS (dev))
		success = nm_dbus_get_wireless_user_key_done (reply, req);
	else if (NM_IS_DEVICE_802_3_ETHERNET (dev))
		success = nm_dbus_get_wired_user_key_done (reply, req);
	else {
		g_error ("Unhandled device type (%s)", G_OBJECT_TYPE_NAME (dev));
		return;
	}

	if (success)
		nm_device_activate_schedule_stage1_device_prepare (req);
	else
		nm_policy_schedule_activation_failed (req);

 out:
	if (reply)
		dbus_message_unref (reply);
	nm_act_request_unref (req);
	dbus_pending_call_unref (pcall);
}


/*
 * nm_dbus_get_user_key_for_network
 *
 * Asks the info-daemon for a user-entered WEP key.
 *
 */
void nm_dbus_get_user_key_for_network (DBusConnection *connection, NMActRequest *req, const gboolean new_key)
{
	NMData *			data;
	NMDevice *		dev;
	gint32			attempt = 1;
	char *			dev_path;
	char *			net_path;
	const char *		essid;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (req != NULL);

	data = nm_act_request_get_data (req);
	g_assert (data);

	dev = nm_act_request_get_dev (req);
	g_assert (dev);

	if (NM_IS_DEVICE_802_11_WIRELESS (dev)) {
		NMAccessPoint *	ap;

		ap = nm_act_request_get_ap (req);
		g_assert (ap);

		essid = nm_ap_get_essid (ap);
		net_path = nm_dbus_get_object_path_for_network (dev, ap);

		nm_info ("Activation (%s) New wireless user key requested for network '%s'.",
			    nm_device_get_iface (dev), essid);

	} else if (NM_IS_DEVICE_802_3_ETHERNET (dev)) {
		NMWiredNetwork *wired_net;

		wired_net = nm_act_request_get_wired_network (req);
		g_assert (wired_net);
		
		essid = nm_wired_network_get_network_id (wired_net);
		net_path = g_strdup ("/");
	} else {
		g_error ("Unhandled device type (%s)", G_OBJECT_TYPE_NAME (dev));
		return;
	}

	dev_path = nm_dbus_get_object_path_for_device (dev);

	if (dev_path && strlen (dev_path) && net_path && strlen (net_path))
	{
		DBusMessage *message;
		DBusPendingCall *pcall;

		if (!(message = dbus_message_new_method_call (NMI_DBUS_SERVICE, NMI_DBUS_PATH, NMI_DBUS_INTERFACE, "getKeyForNetwork")))
		{
			nm_warning ("nm_dbus_get_user_key_for_network(): Couldn't allocate the dbus message");
			return;
		}

		dbus_message_append_args (message, DBUS_TYPE_OBJECT_PATH, &dev_path,
									DBUS_TYPE_OBJECT_PATH, &net_path,
									DBUS_TYPE_STRING, &essid,
									DBUS_TYPE_INT32, &attempt,
									DBUS_TYPE_BOOLEAN, &new_key,
									DBUS_TYPE_INVALID);
		if (dbus_connection_send_with_reply (connection, message, &pcall, INT_MAX) && pcall)
		{
			nm_act_request_ref (req);
			nm_act_request_set_stage (req, NM_ACT_STAGE_NEED_USER_KEY);
			nm_act_request_set_user_key_pending_call (req, pcall);
			dbus_pending_call_set_notify (pcall, (DBusPendingCallNotifyFunction) nm_dbus_get_user_key_for_network_cb, req, NULL);
		}
		else
			nm_warning ("nm_dbus_get_user_key_for_network(): could not send dbus message");

		dbus_message_unref (message);
	} else
		nm_warning ("nm_dbus_get_user_key_for_network(): bad object path data");

	g_free (net_path);
	g_free (dev_path);

	/* FIXME: figure out how to deal with a failure here, otherwise
	 * we just hang in the activation process and nothing happens
	 * until the user cancels stuff.
	 */
}


/*
 * nm_dbus_cancel_get_user_key_for_network
 *
 * Sends a user-key cancellation message to NetworkManagerInfo
 *
 */
void nm_dbus_cancel_get_user_key_for_network (DBusConnection *connection, NMActRequest *req)
{
	DBusMessage *		message;
	DBusPendingCall *	pcall;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (req != NULL);

	if ((pcall = nm_act_request_get_user_key_pending_call (req)))
		dbus_pending_call_cancel (pcall);

	if (!(message = dbus_message_new_method_call (NMI_DBUS_SERVICE, NMI_DBUS_PATH, NMI_DBUS_INTERFACE, "cancelGetKeyForNetwork")))
	{
		nm_warning ("nm_dbus_cancel_get_user_key_for_network(): Couldn't allocate the dbus message");
		return;
	}

	if (!dbus_connection_send (connection, message, NULL))
		nm_warning ("nm_dbus_cancel_get_user_key_for_network(): could not send dbus message");

	dbus_message_unref (message);
}


static gboolean update_network_info (DBusConnection *connection,
							  const char *network_id,
							  gboolean automatic,
							  const char *bssid,
							  NMAPSecurity *security)
{
	DBusMessage *message;
	DBusMessageIter iter;
	gboolean success = FALSE;

	if (!(message = dbus_message_new_method_call (NMI_DBUS_SERVICE, NMI_DBUS_PATH, NMI_DBUS_INTERFACE, "updateNetworkInfo")))
	{
		nm_warning ("nm_dbus_update_network_info(): Couldn't allocate the dbus message");
		goto out;
	}

	dbus_message_iter_init_append (message, &iter);

	/* First argument: ESSID (STRING) */
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &network_id);

	/* Second argument: Automatic (BOOLEAN) */
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_BOOLEAN, &automatic);

	/* Third argument: Access point's BSSID */
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &bssid);

	/* Serialize the AP's security info into the message */
	if (nm_ap_security_serialize (security, &iter) != 0)
		goto unref;

	if (dbus_connection_send (connection, message, NULL))
		success = TRUE;
	else
		nm_warning ("update_network_info(): failed to send dbus message.");

unref:
	dbus_message_unref (message);

out:
	return success;

}


/*
 * nm_dbus_update_network_info
 *
 * Tell NetworkManagerInfo the updated info of the AP
 *
 */
gboolean nm_dbus_update_network_info (DBusConnection *connection, NMAccessPoint *ap, const gboolean automatic)
{
	gboolean success;
	gchar *char_bssid;
	const struct ether_addr *addr;

	g_return_val_if_fail (connection != NULL, FALSE);
	g_return_val_if_fail (ap != NULL, FALSE);

	addr = nm_ap_get_address (ap);
	if ((nm_ap_get_mode (ap) == IW_MODE_INFRA) && nm_ethernet_address_is_valid (addr))
	{
		char_bssid = g_new0 (gchar, 20);
		iw_ether_ntop (addr, char_bssid);
	}
	else
	{
		/* Use an invalid BSSID for non-infrastructure networks, since
		 * the BSSID is usually randomly constructed by the driver and
		 * changed every time you activate the network.
		 */
		char_bssid = g_strdup (" ");
	}

	success = update_network_info (connection,
							 nm_ap_get_essid (ap),
							 automatic,
							 char_bssid,
							 nm_ap_get_security (ap));
	g_free (char_bssid);

	return success;
}


gboolean nm_dbus_update_wired_network_info (DBusConnection *connection, NMWiredNetwork *wired_net)
{
	g_return_val_if_fail (connection != NULL, FALSE);
	g_return_val_if_fail (wired_net != NULL, FALSE);

	return update_network_info (connection,
						   nm_wired_network_get_network_id (wired_net),
						   FALSE,
						   "WIRED", /* CRAPPY HACK */
						   nm_wired_network_get_security (wired_net));
}


typedef struct GetOneNetworkCBData
{
	NMData *			data;
	char *			network;
	NMAccessPointList *	list;
} GetOneNetworkCBData;


static void free_get_one_network_cb_data (GetOneNetworkCBData *data)
{
	if (data)
	{
		nm_ap_list_unref (data->list);
		g_free (data->network);
		data->list = NULL;
		data->network = NULL;
		data->data = NULL;
		g_free (data);
	}
}

typedef struct GetNetworksCBData
{
	NMData *			data;
	NMAccessPointList *	list;
} GetNetworksCBData;


static void free_get_networks_cb_data (GetNetworksCBData *data)
{
	if (data)
	{
		nm_ap_list_unref (data->list);
		data->data = NULL;
		data->list = NULL;
		g_free (data);
	}
}

/*
 * nm_dbus_get_network_data_cb
 *
 * Add a new NMAccessPoint to the allowed list with the correct properties
 *
 */
static void nm_dbus_get_network_data_cb (DBusPendingCall *pcall, void *user_data)
{
	GetOneNetworkCBData *	cb_data = (GetOneNetworkCBData *)user_data;
	DBusMessage *			reply = NULL;
	DBusMessageIter		iter;
	DBusMessageIter		subiter;
	const char *			essid = NULL;
	gint					timestamp_secs = -1;
	gboolean				trusted = FALSE;
	GSList *				addr_list = NULL;
	NMAPSecurity *			security;
	NMAccessPoint *		ap;
	NMAccessPoint *		list_ap;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (cb_data != NULL);
	g_return_if_fail (cb_data->data != NULL);
	g_return_if_fail (cb_data->network != NULL);
	g_return_if_fail (cb_data->list != NULL);

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (dbus_message_is_error (reply, "BadNetworkData"))
	{
		nm_ap_list_remove_ap_by_essid (cb_data->list, cb_data->network);
		goto out;
	}

	if (message_is_error (reply))
	{
		DBusError err;

		dbus_error_init (&err);
		dbus_set_error_from_message (&err, reply);
		nm_warning ("nm_dbus_get_network_data_cb(): dbus returned an error.\n  (%s) %s\n", err.name, err.message);
		dbus_error_free (&err);
		goto out;
	}

	dbus_message_iter_init (reply, &iter);

	/* First arg: ESSID (STRING) */
	if (dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_STRING)
	{
		nm_warning ("a message argument (essid) was invalid.");
		goto out;
	}
	dbus_message_iter_get_basic (&iter, &essid);

	/* Second arg: Timestamp (INT32) */
	if (!dbus_message_iter_next (&iter)
			|| (dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_INT32))
	{
		nm_warning ("a message argument (timestamp) was invalid.");
		goto out;
	}
	dbus_message_iter_get_basic (&iter, &timestamp_secs);

	/* Third arg: Trusted (BOOLEAN) */
	if (!dbus_message_iter_next (&iter)
			|| (dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_BOOLEAN))
	{
		nm_warning ("a message argument (trusted) was invalid.");
		goto out;
	}
	dbus_message_iter_get_basic (&iter, &trusted);

	/* Fourth arg: BSSID addresses (ARRAY, STRING) */
	if (!dbus_message_iter_next (&iter)
			|| (dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_ARRAY)
			|| (dbus_message_iter_get_element_type (&iter) != DBUS_TYPE_STRING))
	{
		nm_warning ("a message argument (addresses) was invalid.");
		goto out;
	}
	dbus_message_iter_recurse (&iter, &subiter);
	while (dbus_message_iter_get_arg_type (&subiter) == DBUS_TYPE_STRING)
	{
		char *address;
		dbus_message_iter_get_basic (&subiter, &address);
		if (address && strlen (address) >= 11)
			addr_list = g_slist_append (addr_list, address);
		dbus_message_iter_next (&subiter);
	}

	/* Unserialize access point security info */
	if (!dbus_message_iter_has_next (&iter))
	{
		nm_warning ("a message argument (security info) was invalid.");
		goto out;
	}
	dbus_message_iter_next (&iter);

	if (!(security = nm_ap_security_new_deserialize (&iter)))
	{
		nm_warning ("message arguments were invalid (could not deserialize "
				"wireless network security information.");
		goto out;
	}

	/* Construct the new access point */
	ap = nm_ap_new ();
	nm_ap_set_essid (ap, essid);
	nm_ap_set_security (ap, security);
	g_object_unref (G_OBJECT (security));	/* set_security copies the object */

	nm_ap_set_timestamp (ap, timestamp_secs, 0);

	nm_ap_set_trusted (ap, trusted);
	nm_ap_set_user_addresses (ap, addr_list);

	if ((list_ap = nm_ap_list_get_ap_by_essid (cb_data->list, essid)))
	{
		GSList *user_addresses;

		nm_ap_set_essid (list_ap, nm_ap_get_essid (ap));
		nm_ap_set_timestamp_via_timestamp (list_ap, nm_ap_get_timestamp (ap));
		nm_ap_set_trusted (list_ap, nm_ap_get_trusted (ap));
		nm_ap_set_security (list_ap, nm_ap_get_security (ap));

		user_addresses = nm_ap_get_user_addresses (ap);
		nm_ap_set_user_addresses (list_ap, user_addresses);
		g_slist_foreach (user_addresses, (GFunc) g_free, NULL);
		g_slist_free (user_addresses);
	}
	else
	{
		/* New AP, just add it to the list */
		nm_ap_list_append_ap (cb_data->list, ap);
	}
	nm_ap_unref (ap);

	/* Ensure all devices get new information copied into their device lists */
	nm_policy_schedule_device_ap_lists_update_from_allowed (cb_data->data);

out:
	if (addr_list)
		g_slist_free (addr_list);
	if (reply)
		dbus_message_unref (reply);
	dbus_pending_call_unref (pcall);
}


/*
 * nm_dbus_get_networks_cb
 *
 * Async callback from nm_dbus_get_networks
 *
 */
static void nm_dbus_get_networks_cb (DBusPendingCall *pcall, void *user_data)
{
	DBusMessage *		reply;
	DBusMessageIter	iter, array_iter;
	GetNetworksCBData *	cb_data =  (GetNetworksCBData *)user_data;

	g_return_if_fail (pcall);
	g_return_if_fail (cb_data != NULL);
	g_return_if_fail (cb_data->list != NULL);
	g_return_if_fail (cb_data->data != NULL);

	if (!dbus_pending_call_get_completed (pcall))
	{
		nm_warning ("pending call was not completed.");
		goto out;
	}

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
	{
		nm_warning ("could not retrieve the reply.");
		goto out;
	}

	if (message_is_error (reply))
	{
		DBusError	err;

		dbus_error_init (&err);
		dbus_set_error_from_message (&err, reply);
		nm_warning ("error received: %s - %s.", err.name, err.message);
		goto out;
	}

	dbus_message_iter_init (reply, &iter);
	dbus_message_iter_recurse (&iter, &array_iter);
	while (dbus_message_iter_get_arg_type (&array_iter) == DBUS_TYPE_STRING)
	{
		const char *		value;
		DBusMessage *		message;

		dbus_message_iter_get_basic (&array_iter, &value);

		/* Get properties on each network */
		if ((message = dbus_message_new_method_call (NMI_DBUS_SERVICE, NMI_DBUS_PATH, NMI_DBUS_INTERFACE, "getNetworkProperties")))
		{
			dbus_int32_t			type_as_int32 = nm_ap_list_get_type (cb_data->list);
			DBusPendingCall *		net_pcall = NULL;

			dbus_message_append_args (message, DBUS_TYPE_STRING, &value, DBUS_TYPE_INT32, &type_as_int32, DBUS_TYPE_INVALID);
			dbus_connection_send_with_reply (cb_data->data->dbus_connection, message, &net_pcall, -1);
			dbus_message_unref (message);
			if (net_pcall)
			{
				GetOneNetworkCBData *	net_cb_data = g_malloc0 (sizeof (GetOneNetworkCBData));

				net_cb_data->data = cb_data->data;
				net_cb_data->network = g_strdup (value);
				nm_ap_list_ref (cb_data->list);
				net_cb_data->list = cb_data->list;

				dbus_pending_call_set_notify (net_pcall, nm_dbus_get_network_data_cb, net_cb_data, (DBusFreeFunction) free_get_one_network_cb_data);
			}
		}

		dbus_message_iter_next(&array_iter);
	}
	dbus_message_unref (reply);

out:
	dbus_pending_call_unref (pcall);
}


/*
 * nm_dbus_update_allowed_networks
 *
 * Update all allowed networks from NetworkManagerInfo
 *
 */
void nm_dbus_update_allowed_networks (DBusConnection *connection, NMAccessPointList *list, NMData *data)
{
	DBusMessage *		message;
	dbus_int32_t		type_as_int32 = nm_ap_list_get_type (list);
	DBusPendingCall *	pcall = NULL;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (list != NULL);
	g_return_if_fail (data != NULL);

	if (!(message = dbus_message_new_method_call (NMI_DBUS_SERVICE, NMI_DBUS_PATH, NMI_DBUS_INTERFACE, "getNetworks")))
		return;

	dbus_message_append_args (message, DBUS_TYPE_INT32, &type_as_int32, DBUS_TYPE_INVALID);
	dbus_connection_send_with_reply (connection, message, &pcall, -1);
	dbus_message_unref (message);
	if (pcall)
	{
		GetNetworksCBData *	cb_data = g_malloc0 (sizeof (GetNetworksCBData));

		cb_data->data = data;
		nm_ap_list_ref (list);
		cb_data->list = list;
		dbus_pending_call_set_notify (pcall, nm_dbus_get_networks_cb, cb_data, (DBusFreeFunction) free_get_networks_cb_data);
	}
}


/*
 * nm_dbus_update_one_allowed_network
 *
 * Update all networks of a specific type from NetworkManagerInfo
 *
 */
void nm_dbus_update_one_allowed_network (DBusConnection *connection, const char *network, NMData *data)
{
	DBusMessage *			message;
	dbus_int32_t			type_as_int32 = NETWORK_TYPE_ALLOWED;
	DBusPendingCall *		pcall = NULL;
	GetOneNetworkCBData *	cb_data = NULL;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (data != NULL);

	if (!(message = dbus_message_new_method_call (NMI_DBUS_SERVICE, NMI_DBUS_PATH, NMI_DBUS_INTERFACE, "getNetworkProperties")))
	{
		nm_warning ("nm_dbus_update_one_allowed_network(): Couldn't allocate the dbus message");
		return;
	}

	cb_data = g_malloc0 (sizeof (GetOneNetworkCBData));
	cb_data->data = data;
	cb_data->network = g_strdup (network);
	cb_data->list = data->allowed_ap_list;
	nm_ap_list_ref (cb_data->list);

	dbus_message_append_args (message, DBUS_TYPE_STRING, &network, DBUS_TYPE_INT32, &type_as_int32, DBUS_TYPE_INVALID);
	dbus_connection_send_with_reply (connection, message, &pcall, -1);
	dbus_message_unref (message);
	if (!pcall)
		nm_warning ("nm_dbus_update_one_allowed_network(): pending call was NULL");
	else
		dbus_pending_call_set_notify (pcall, nm_dbus_get_network_data_cb, cb_data, (DBusFreeFunction) free_get_one_network_cb_data);
}


