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
#include "nm-device-interface.h"
#include "nm-device.h"
#include "nm-activation-request.h"
#include "NetworkManagerAPList.h"
#include "NetworkManagerPolicy.h"
#include "NetworkManagerUtils.h"
#include "nm-dbus-nmi.h"
#include "nm-utils.h"
#include "nm-dbus-manager.h"

#define NM_ACT_REQUEST_PENDING_CALL "nm-act-request-pending-call"

typedef struct {
	NMDevice *device;
	NMActRequest *req;
} UserKeyInfo;

static void
user_key_info_destroy (gpointer data)
{
	UserKeyInfo *info = (UserKeyInfo *) data;

	g_object_set_data (G_OBJECT (info->req), NM_ACT_REQUEST_PENDING_CALL, NULL);

	g_object_unref (info->device);
	g_object_unref (info->req);

	g_slice_free (UserKeyInfo, info);
}

/*
 * nm_dbus_get_user_key_for_network_cb
 *
 * Callback from nm_dbus_get_user_key_for_network when NetworkManagerInfo returns
 * the new user key.
 *
 */
static void
nm_dbus_get_user_key_for_network_cb (DBusPendingCall *pcall,
                                     UserKeyInfo *info)
{
	DBusMessage *		reply = NULL;
	NMData *			data;
	NMDevice *		dev;
	NMActRequest *req;
	NMAccessPoint *	ap;
	NMAPSecurity *		security;
	DBusMessageIter	iter;
	const GByteArray * ssid;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (info != NULL);

	dev = info->device;
	req = info->req;

	data = nm_device_get_app_data (dev);
	g_assert (data);

	ap = nm_device_802_11_wireless_get_activation_ap (NM_DEVICE_802_11_WIRELESS (dev));
	g_assert (ap);
	ssid = nm_ap_get_ssid (ap);

	nm_dbus_send_with_callback_replied (pcall, __func__);

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (message_is_error (reply)) {
		DBusError err;

		dbus_error_init (&err);
		dbus_set_error_from_message (&err, reply);

		/* Check for cancelled error */
		if (strcmp (err.name, NMI_DBUS_USER_KEY_CANCELED_ERROR) == 0) {
			nm_info ("Activation (%s) New wireless user key request for network"
			         " '%s' was canceled.",
			         nm_device_get_iface (dev),
			         ssid ? nm_utils_escape_ssid (ssid->data, ssid->len) : "(none)");
		} else {
			nm_warning ("dbus returned an error.\n  (%s) %s\n",
			            err.name,
			            err.message);
		}

		dbus_error_free (&err);

		/* FIXME: since we're not marking the device as invalid, its a fair bet
		 * that NM will just try to reactivate the device again, and may fail
		 * to get the user key in exactly the same way, which ends up right back
		 * here...  ad nauseum.  Figure out how to deal with a failure here.
		 */
		nm_ap_list_append_ap (data->invalid_ap_list, ap);
		nm_device_interface_deactivate (NM_DEVICE_INTERFACE (dev));

		goto out;
	}

	nm_info ("Activation (%s) New wireless user key for network '%s' received.",
	         nm_device_get_iface (dev),
	         ssid ? nm_utils_escape_ssid (ssid->data, ssid->len) : "(none)");

	dbus_message_iter_init (reply, &iter);
	if ((security = nm_ap_security_new_deserialize (&iter))) {
		nm_ap_set_security (ap, security);
		nm_device_activate_schedule_stage2_device_config (dev);
	}

out:
	if (reply)
		dbus_message_unref (reply);
	dbus_pending_call_unref (pcall);
}


/*
 * nm_dbus_get_user_key_for_network
 *
 * Asks the info-daemon for a user-entered WEP key.
 *
 */
void
nm_dbus_get_user_key_for_network (NMDevice *dev,
								  NMActRequest *req,
                                  const gboolean new_key)
{
	NMDBusManager *	dbus_mgr = NULL;
	DBusConnection *dbus_connection;
	DBusMessage *		message;
	DBusPendingCall *	pcall;
	UserKeyInfo *info;
	NMAccessPoint *	ap;
	gint32			attempt = 1;
	char *			dev_path;
	const char *	net_path;
	const GByteArray * ssid;

	g_return_if_fail (NM_IS_DEVICE (dev));
	g_return_if_fail (req != NULL);

	dbus_mgr = nm_dbus_manager_get ();
	dbus_connection = nm_dbus_manager_get_dbus_connection (dbus_mgr);
	if (!dbus_connection) {
		nm_warning ("could not get the dbus connection.");
		goto out;
	}

	ap = nm_device_802_11_wireless_get_activation_ap (NM_DEVICE_802_11_WIRELESS (dev));
	g_assert (ap);

	ssid = nm_ap_get_ssid (ap);
	nm_info ("Activation (%s) New wireless user key requested for network '%s'.",
	         nm_device_get_iface (dev),
	         ssid ? nm_utils_escape_ssid (ssid->data, ssid->len) : "(none)");

	message = dbus_message_new_method_call (NMI_DBUS_SERVICE,
	                                        NMI_DBUS_PATH,
	                                        NMI_DBUS_INTERFACE,
	                                        "getKeyForNetwork");
	if (!message) {
		nm_warning ("couldn't allocate the dbus message");
		goto out;
	}

	dev_path = nm_dbus_get_object_path_for_device (dev);
	net_path = nm_ap_get_dbus_path (ap);
	if (dev_path && strlen (dev_path) && net_path && strlen (net_path)) {
		char buf[IW_ESSID_MAX_SIZE + 1];
		char * ptr = &buf[0];

		memset (buf, 0, sizeof (buf));
		memcpy (buf, ssid->data, MIN (ssid->len, sizeof (buf) - 1));
		dbus_message_append_args (message, DBUS_TYPE_OBJECT_PATH, &dev_path,
									DBUS_TYPE_OBJECT_PATH, &net_path,
									DBUS_TYPE_STRING, &ptr,
									DBUS_TYPE_INT32, &attempt,
									DBUS_TYPE_BOOLEAN, &new_key,
									DBUS_TYPE_INVALID);

		info = g_slice_new (UserKeyInfo);
		info->device = g_object_ref (dev);
		info->req = g_object_ref (req);

		pcall = nm_dbus_send_with_callback (dbus_connection,
		                                    message,
		                                    (DBusPendingCallNotifyFunction) nm_dbus_get_user_key_for_network_cb,
		                                    info,
		                                    user_key_info_destroy,
		                                    __func__);
		if (pcall)
			g_object_set_data (G_OBJECT (req), NM_ACT_REQUEST_PENDING_CALL, pcall);
	} else {
		nm_warning ("bad object path data");
	}
	g_free (dev_path);

	/* FIXME: figure out how to deal with a failure here, otherwise
	 * we just hang in the activation process and nothing happens
	 * until the user cancels stuff.
	 */

	dbus_message_unref (message);

out:
	g_object_unref (dbus_mgr);
}


/*
 * nm_dbus_cancel_get_user_key_for_network
 *
 * Sends a user-key cancellation message to NetworkManagerInfo
 *
 */
void
nm_dbus_cancel_get_user_key_for_network (NMActRequest *req)
{
	DBusMessage *		message;
	DBusPendingCall *	pcall;
	NMDBusManager *		dbus_mgr;
	DBusConnection *	dbus_connection;

	g_return_if_fail (req != NULL);

	dbus_mgr = nm_dbus_manager_get ();
	dbus_connection = nm_dbus_manager_get_dbus_connection (dbus_mgr);
	if (!dbus_connection) {
		nm_warning ("could not get the dbus connection.");
		goto out;
	}

	pcall = (DBusPendingCall *) g_object_get_data (G_OBJECT (req), NM_ACT_REQUEST_PENDING_CALL);
	if (pcall)
		dbus_pending_call_cancel (pcall);

	message = dbus_message_new_method_call (NMI_DBUS_SERVICE,
	                                        NMI_DBUS_PATH,
	                                        NMI_DBUS_INTERFACE,
	                                        "cancelGetKeyForNetwork");
	if (!message) {
		nm_warning ("couldn't allocate the dbus message");
		goto out;
	}

	dbus_connection_send (dbus_connection, message, NULL);
	dbus_message_unref (message);

out:
	g_object_unref (dbus_mgr);
}


/*
 * nm_dbus_update_network_info
 *
 * Tell NetworkManagerInfo the updated info of the AP
 *
 */
void
nm_dbus_update_network_info (NMAccessPoint *ap,
                             const gboolean automatic)
{
	NMDBusManager *		dbus_mgr = NULL;
	DBusConnection *	dbus_connection;
	DBusMessage *		message;
	gboolean			fallback;
	const GByteArray *	ssid;
	gchar *			char_bssid;
	NMAPSecurity *		security;
	const struct ether_addr *addr;
	DBusMessageIter	iter;
	char buf[IW_ESSID_MAX_SIZE + 1];
	char * ptr = &buf[0];

	g_return_if_fail (ap != NULL);

	dbus_mgr = nm_dbus_manager_get ();
	dbus_connection = nm_dbus_manager_get_dbus_connection (dbus_mgr);
	if (!dbus_connection) {
		nm_warning ("could not get the dbus connection.");
		goto out;
	}

	message = dbus_message_new_method_call (NMI_DBUS_SERVICE,
	                                        NMI_DBUS_PATH,
	                                        NMI_DBUS_INTERFACE,
	                                        "updateNetworkInfo");
	if (!message) {
		nm_warning ("couldn't allocate the dbus message");
		goto out;
	}

	dbus_message_iter_init_append (message, &iter);

	/* First argument: ESSID (STRING) */
	ssid = nm_ap_get_ssid (ap);
	memset (buf, 0, sizeof (buf));
	memcpy (buf, ssid->data, MIN (ssid->len, IW_ESSID_MAX_SIZE));
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &ptr);

	/* Second argument: Automatic or user-driven connection? (BOOLEAN) */
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_BOOLEAN, &automatic);

	/* Third argument: Fallback? (BOOLEAN) */
	fallback = nm_ap_get_fallback (ap);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_BOOLEAN, &fallback);

	/* Fourth argument: Access point's BSSID */
	addr = nm_ap_get_address (ap);
	if ((nm_ap_get_mode (ap) == IW_MODE_INFRA) && nm_ethernet_address_is_valid (addr))
	{
		char_bssid = g_new0 (gchar, 20);
		iw_ether_ntop (addr, char_bssid);
		dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &char_bssid);
		g_free (char_bssid);
	}
	else
	{
		/* Use an invalid BSSID for non-infrastructure networks, since
		 * the BSSID is usually randomly constructed by the driver and
		 * changed every time you activate the network.
		 */
		char_bssid = " ";
		dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &char_bssid);
	}

	/* Serialize the AP's security info into the message */
	security = nm_ap_get_security (ap);
	g_assert (security);
	if (nm_ap_security_serialize (security, &iter) == 0)
		dbus_connection_send (dbus_connection, message, NULL);
	dbus_message_unref (message);

out:
	g_object_unref (dbus_mgr);
	return;
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
		g_slice_free (GetOneNetworkCBData, data);
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
		g_slice_free (GetNetworksCBData, data);
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
	const char *			tmp_ssid = NULL;
	guint32					tmp_ssid_len;
	gint					timestamp_secs = -1;
	gboolean				fallback = FALSE;
	GSList *				addr_list = NULL;
	NMAPSecurity *			security;
	NMAccessPoint *		ap;
	NMAccessPoint *		list_ap;
	GByteArray *		ssid;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (cb_data != NULL);
	g_return_if_fail (cb_data->data != NULL);
	g_return_if_fail (cb_data->network != NULL);
	g_return_if_fail (cb_data->list != NULL);

	nm_dbus_send_with_callback_replied (pcall, __func__);

	dbus_pending_call_ref (pcall);

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (dbus_message_is_error (reply, "BadNetworkData")) {
		guint32 rmv_len = strlen (cb_data->network);
		GByteArray * rmv_ssid;

		rmv_ssid = g_byte_array_sized_new (rmv_len);
		g_byte_array_append (rmv_ssid, cb_data->network, rmv_len);
		nm_ap_list_remove_ap_by_ssid (cb_data->list, rmv_ssid);
		g_byte_array_free (rmv_ssid, TRUE);
		goto out;
	}

	if (message_is_error (reply)) {
		DBusError err;

		dbus_error_init (&err);
		dbus_set_error_from_message (&err, reply);
		nm_warning ("dbus returned an error.\n  (%s) %s\n", err.name, err.message);
		dbus_error_free (&err);
		goto out;
	}

	dbus_message_iter_init (reply, &iter);

	/* First arg: ESSID (STRING) */
	if (dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_STRING)
	{
		nm_warning ("a message argument (SSID) was invalid.");
		goto out;
	}
	dbus_message_iter_get_basic (&iter, &tmp_ssid);

	/* Second arg: Timestamp (INT32) */
	if (!dbus_message_iter_next (&iter)
			|| (dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_INT32))
	{
		nm_warning ("a message argument (timestamp) was invalid.");
		goto out;
	}
	dbus_message_iter_get_basic (&iter, &timestamp_secs);

	/* Third arg: Fallback? (BOOLEAN) */
	if (!dbus_message_iter_next (&iter)
			|| (dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_BOOLEAN))
	{
		nm_warning ("a message argument (fallback) was invalid.");
		goto out;
	}
	dbus_message_iter_get_basic (&iter, &fallback);

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

	tmp_ssid_len = MIN (strlen (tmp_ssid), IW_ESSID_MAX_SIZE);
	ssid = g_byte_array_sized_new (tmp_ssid_len);
	g_byte_array_append (ssid, tmp_ssid, tmp_ssid_len);
	nm_ap_set_ssid (ap, ssid);

	nm_ap_set_security (ap, security);
	nm_ap_add_capabilities_from_security (ap, security);
	g_object_unref (G_OBJECT (security));	/* set_security copies the object */

	nm_ap_set_timestamp (ap, timestamp_secs, 0);

	nm_ap_set_fallback (ap, fallback);
	nm_ap_set_user_addresses (ap, addr_list);

	if ((list_ap = nm_ap_list_get_ap_by_ssid (cb_data->list, ssid)))
	{
		nm_ap_set_ssid (list_ap, nm_ap_get_ssid (ap));
		nm_ap_set_timestamp_via_timestamp (list_ap, nm_ap_get_timestamp (ap));
		nm_ap_set_fallback (list_ap, nm_ap_get_fallback (ap));
		nm_ap_set_security (list_ap, nm_ap_get_security (ap));
		nm_ap_set_user_addresses (list_ap, nm_ap_get_user_addresses (ap));
	}
	else
	{
		/* New AP, just add it to the list */
		nm_ap_list_append_ap (cb_data->list, ap);
	}
	g_byte_array_free (ssid, TRUE);
	g_object_unref (ap);

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
static void
nm_dbus_get_networks_cb (DBusPendingCall *pcall,
                         void *user_data)
{
	DBusMessage *		reply;
	DBusMessageIter	iter, array_iter;
	GetNetworksCBData *	cb_data =  (GetNetworksCBData *)user_data;
	NMDBusManager *	dbus_mgr = NULL;
	DBusConnection *dbus_connection;

	g_return_if_fail (pcall);
	g_return_if_fail (cb_data != NULL);
	g_return_if_fail (cb_data->list != NULL);
	g_return_if_fail (cb_data->data != NULL);

	nm_dbus_send_with_callback_replied (pcall, __func__);

	dbus_pending_call_ref (pcall);

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (message_is_error (reply)) {
		DBusError	err;

		dbus_error_init (&err);
		dbus_set_error_from_message (&err, reply);
		nm_warning ("error received: %s - %s.", err.name, err.message);
		goto out;
	}

	dbus_mgr = nm_dbus_manager_get ();
	dbus_connection = nm_dbus_manager_get_dbus_connection (dbus_mgr);
	if (!dbus_connection) {
		nm_warning ("couldn't get dbus connection.");
		goto out;
	}

	dbus_message_iter_init (reply, &iter);
	dbus_message_iter_recurse (&iter, &array_iter);
	while (dbus_message_iter_get_arg_type (&array_iter) == DBUS_TYPE_STRING) {
		const char *		value;
		DBusMessage *		message;

		dbus_message_iter_get_basic (&array_iter, &value);

		/* Get properties on each network */
		message = dbus_message_new_method_call (NMI_DBUS_SERVICE,
		                                        NMI_DBUS_PATH,
		                                        NMI_DBUS_INTERFACE,
		                                        "getNetworkProperties");
		if (message) {
			dbus_int32_t			type_as_int32 = nm_ap_list_get_type (cb_data->list);
			GetOneNetworkCBData *	net_cb_data = g_slice_new0 (GetOneNetworkCBData);

			net_cb_data->data = cb_data->data;
			net_cb_data->network = g_strdup (value);
			nm_ap_list_ref (cb_data->list);
			net_cb_data->list = cb_data->list;

			dbus_message_append_args (message,
			                          DBUS_TYPE_STRING, &value,
			                          DBUS_TYPE_INT32, &type_as_int32,
			                          DBUS_TYPE_INVALID);
			nm_dbus_send_with_callback (dbus_connection,
			                            message,
			                            (DBusPendingCallNotifyFunction) nm_dbus_get_network_data_cb,
			                            net_cb_data,
			                            (DBusFreeFunction) free_get_one_network_cb_data,
			                            __func__);
			dbus_message_unref (message);
		}
		dbus_message_iter_next(&array_iter);
	}
	dbus_message_unref (reply);

out:
	if (dbus_mgr)
		g_object_unref (dbus_mgr);
	dbus_pending_call_unref (pcall);
}


/*
 * nm_dbus_update_allowed_networks
 *
 * Update all allowed networks from NetworkManagerInfo
 *
 */
void
nm_dbus_update_allowed_networks (NMAccessPointList *list,
                                 NMData *data)
{
	NMDBusManager *		dbus_mgr = NULL;
	DBusConnection *	dbus_connection;
	DBusMessage *		message;
	dbus_int32_t		type_as_int32 = nm_ap_list_get_type (list);
	GetNetworksCBData *	cb_data;

	g_return_if_fail (list != NULL);
	g_return_if_fail (data != NULL);

	dbus_mgr = nm_dbus_manager_get ();
	dbus_connection = nm_dbus_manager_get_dbus_connection (dbus_mgr);
	if (!dbus_connection) {
		nm_warning ("could not get the dbus connection.");
		goto out;
	}

	message = dbus_message_new_method_call (NMI_DBUS_SERVICE,
	                                        NMI_DBUS_PATH,
	                                        NMI_DBUS_INTERFACE,
	                                        "getNetworks");
	if (!message) {
		nm_warning ("could not allocate the dbus message.");
		goto out;
	}

	dbus_message_append_args (message,
	                          DBUS_TYPE_INT32, &type_as_int32,
	                          DBUS_TYPE_INVALID);

	cb_data = g_slice_new0 (GetNetworksCBData);
	cb_data->data = data;
	nm_ap_list_ref (list);
	cb_data->list = list;

	nm_dbus_send_with_callback (dbus_connection,
	                            message,
	                           (DBusPendingCallNotifyFunction) nm_dbus_get_networks_cb,
	                           cb_data,
	                           (DBusFreeFunction) free_get_networks_cb_data,
	                           __func__);
	dbus_message_unref (message);

out:
	g_object_unref (dbus_mgr);
}


/*
 * nm_dbus_update_one_allowed_network
 *
 * Update all networks of a specific type from NetworkManagerInfo
 *
 */
void
nm_dbus_update_one_allowed_network (const char *network,
                                    NMData *data)
{
	NMDBusManager *			dbus_mgr = NULL;
	DBusConnection *		dbus_connection;
	DBusMessage *			message;
	dbus_int32_t			type_as_int32 = NETWORK_TYPE_ALLOWED;
	GetOneNetworkCBData *	cb_data = NULL;

	g_return_if_fail (data != NULL);

	dbus_mgr = nm_dbus_manager_get ();
	dbus_connection = nm_dbus_manager_get_dbus_connection (dbus_mgr);
	if (!dbus_connection) {
		nm_warning ("could not get the dbus connection.");
		goto out;
	}

	message = dbus_message_new_method_call (NMI_DBUS_SERVICE,
	                                        NMI_DBUS_PATH,
	                                        NMI_DBUS_INTERFACE,
	                                        "getNetworkProperties");
	if (!message) {
		nm_warning ("couldn't allocate the dbus message.");
		goto out;
	}

	cb_data = g_slice_new0 (GetOneNetworkCBData);
	cb_data->data = data;
	cb_data->network = g_strdup (network);
	cb_data->list = data->allowed_ap_list;

	dbus_message_append_args (message,
	                          DBUS_TYPE_STRING, &network,
	                          DBUS_TYPE_INT32, &type_as_int32,
	                          DBUS_TYPE_INVALID);
	nm_dbus_send_with_callback (dbus_connection,
	                            message,
	                            (DBusPendingCallNotifyFunction) nm_dbus_get_network_data_cb,
	                            cb_data,
	                            (DBusFreeFunction) free_get_one_network_cb_data,
	                            __func__);
	dbus_message_unref (message);

out:
	g_object_unref (dbus_mgr);
}


