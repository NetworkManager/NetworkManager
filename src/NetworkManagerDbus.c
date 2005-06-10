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
 * (C) Copyright 2004 Red Hat, Inc.
 */

#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>
#include <stdarg.h>
#include <signal.h>
#include <iwlib.h>
#include <netinet/ether.h>

#include "NetworkManager.h"
#include "NetworkManagerUtils.h"
#include "NetworkManagerDevice.h"
#include "NetworkManagerDbus.h"
#include "NetworkManagerDbusUtils.h"
#include "NetworkManagerAP.h"
#include "NetworkManagerAPList.h"
#include "NetworkManagerPolicy.h"
#include "nm-dbus-nm.h"
#include "nm-dbus-device.h"
#include "nm-dbus-net.h"
#include "nm-dbus-vpn.h"
#include "nm-utils.h"
#include "nm-dhcp-manager.h"

static char *get_nmi_match_string (const char *owner);

/*
 * nm_dbus_create_error_message
 *
 * Make a DBus error message
 *
 */
DBusMessage *nm_dbus_create_error_message (DBusMessage *message, const char *exception_namespace,
										const char *exception, const char *format, ...)
{
	char *exception_text;
	DBusMessage	*reply_message;
	va_list		 args;
	char			 error_text[512];

	va_start (args, format);
	vsnprintf (error_text, 512, format, args);
	va_end (args);

	exception_text = g_strdup_printf ("%s.%s", exception_namespace, exception);
	reply_message = dbus_message_new_error (message, exception_text, error_text);
	g_free (exception_text);

	return (reply_message);
}


/*
 * nm_dbus_get_object_path_for_device
 *
 * Copies the object path for a device object.  Caller must free returned string.
 *
 */
char * nm_dbus_get_object_path_for_device (NMDevice *dev)
{
	char *object_path, *escaped_object_path;

	g_return_val_if_fail (dev != NULL, NULL);

	object_path = g_strdup_printf ("%s/%s", NM_DBUS_PATH_DEVICES, nm_device_get_iface (dev));
	escaped_object_path = nm_dbus_escape_object_path (object_path);
	g_free (object_path);

	return escaped_object_path;
}


/*
 * nm_dbus_get_object_path_for_network
 *
 * Copies the object path for a network object.  Caller must free returned string.
 *
 */
char * nm_dbus_get_object_path_for_network (NMDevice *dev, NMAccessPoint *ap)
{
	char *object_path, *escaped_object_path;

	g_return_val_if_fail (dev != NULL, NULL);
	g_return_val_if_fail (ap != NULL, NULL);

	if (!nm_ap_get_essid (ap))
		return NULL;

	object_path = g_strdup_printf ("%s/%s/Networks/%s", NM_DBUS_PATH_DEVICES, nm_device_get_iface (dev), nm_ap_get_essid (ap));
	escaped_object_path = nm_dbus_escape_object_path (object_path);
	g_free (object_path);

	return escaped_object_path;
}


/*
 * nm_dbus_get_device_from_object_path
 *
 * Returns the device associated with a dbus object path
 *
 */
NMDevice *nm_dbus_get_device_from_object_path (NMData *data, const char *path)
{
	NMDevice	*dev = NULL;

	g_return_val_if_fail (path != NULL, NULL);
	g_return_val_if_fail (data != NULL, NULL);

	/* FIXME
	 * This function could be much more efficient, for example we could
	 * actually _parse_ the object path, but that's a lot more code and
	 * stupid stuff.  The approach below is slower, less efficient, but
	 * less code and less error-prone.
	 */

	/* Iterate over device list */
	if (nm_try_acquire_mutex (data->dev_list_mutex, __FUNCTION__))
	{
		GSList	*elt;
		char		 compare_path[100];
		char    *escaped_compare_path;

		for (elt = data->dev_list; elt; elt = g_slist_next (elt))
		{
			if ((dev = (NMDevice *)(elt->data)))
			{
				snprintf (compare_path, 100, "%s/%s", NM_DBUS_PATH_DEVICES, nm_device_get_iface (dev));
				escaped_compare_path = nm_dbus_escape_object_path (compare_path);
				/* Compare against our constructed path, but ignore any trailing elements */
				if (strncmp (path, compare_path, strlen (escaped_compare_path)) == 0)
				{
					g_free (escaped_compare_path);
					break;
				}
				g_free (escaped_compare_path);
				dev = NULL;
			}
		}
		nm_unlock_mutex (data->dev_list_mutex, __FUNCTION__);
	}

	return (dev);
}


/*-------------------------------------------------------------*/
/* Handler code */
/*-------------------------------------------------------------*/

typedef struct NMStatusChangeData
{
	NMData *			data;
	NMDevice *		dev;
	NMAccessPoint *	ap;
	DeviceStatus	 	status;
} NMStatusChangeData;


typedef struct
{
	DeviceStatus	status;
	const char *	signal;
} DeviceStatusSignals;

static DeviceStatusSignals dev_status_signals[] = 
{
	{ DEVICE_NO_LONGER_ACTIVE, 	"DeviceNoLongerActive"	},
	{ DEVICE_NOW_ACTIVE,		"DeviceNowActive"		},
	{ DEVICE_ACTIVATING,		"DeviceActivating"		},
	{ DEVICE_ACTIVATION_FAILED,	"DeviceActivationFailed"	},
	{ DEVICE_ADDED,			"DeviceAdded"			},
	{ DEVICE_REMOVED,			"DeviceRemoved"		},
	{ DEVICE_CARRIER_ON,		"DeviceCarrierOn"		},
	{ DEVICE_CARRIER_OFF,		"DeviceCarrierOff"		},
	{ DEVICE_STATUS_INVALID,		NULL					}
};

/*
 * nm_dbus_signal_device_status_change
 *
 * Notifies the bus that a particular device has had a status change
 *
 */
static gboolean nm_dbus_signal_device_status_change (gpointer user_data)
{
	NMStatusChangeData *cb_data = (NMStatusChangeData *)user_data;
	DBusMessage *		message;
	char *			dev_path;
	const char *		signal = NULL;
	int				i = 0;

	g_return_val_if_fail (cb_data->data, FALSE);
	g_return_val_if_fail (cb_data->data->dbus_connection, FALSE);
	g_return_val_if_fail (cb_data->dev, FALSE);

	while ((dev_status_signals[i].status != DEVICE_STATUS_INVALID) && (dev_status_signals[i].status != cb_data->status))
		i++;

	if (!(signal = dev_status_signals[i].signal))
		return FALSE;

	if (!(dev_path = nm_dbus_get_object_path_for_device (cb_data->dev)))
		return FALSE;

	if (!(message = dbus_message_new_signal (NM_DBUS_PATH, NM_DBUS_INTERFACE, signal)))
	{
		nm_warning ("nm_dbus_signal_device_status_change(): Not enough memory for new dbus message!");
		g_free (dev_path);
		return FALSE;
	}

	/* If the device was wireless, attach the name of the wireless network that failed to activate */
	if (cb_data->ap)
	{
		const char *essid = nm_ap_get_essid (cb_data->ap);
		if (essid)
			dbus_message_append_args (message, DBUS_TYPE_OBJECT_PATH, &dev_path, DBUS_TYPE_STRING, &essid, DBUS_TYPE_INVALID);
		nm_ap_unref (cb_data->ap);
	}
	else
		dbus_message_append_args (message, DBUS_TYPE_OBJECT_PATH, &dev_path, DBUS_TYPE_INVALID);

	g_free (dev_path);

	if (!dbus_connection_send (cb_data->data->dbus_connection, message, NULL))
		nm_warning ("nm_dbus_signal_device_status_change(): Could not raise the signal!");

	dbus_message_unref (message);

	nm_device_unref (cb_data->dev);
	g_free (cb_data);

	return FALSE;
}


void nm_dbus_schedule_device_status_change_signal (NMData *data, NMDevice *dev, NMAccessPoint *ap, DeviceStatus status)
{
	NMStatusChangeData	*cb_data = NULL;
	GSource			*source;

	g_return_if_fail (data != NULL);
	g_return_if_fail (dev != NULL);

	cb_data = g_malloc0 (sizeof (NMStatusChangeData));
	nm_device_ref (dev);
	cb_data->data = data;
	cb_data->dev = dev;
	if (ap)
	{
		nm_ap_ref (ap);
		cb_data->ap = ap;
	}
	cb_data->status = status;

	source = g_idle_source_new ();
	g_source_set_priority (source, G_PRIORITY_HIGH_IDLE);
	g_source_set_callback (source, nm_dbus_signal_device_status_change, cb_data, NULL);
	g_source_attach (source, data->main_context);
	g_source_unref (source);
}


/*
 * nm_dbus_network_status_from_data
 *
 * Return a network status string based on our network data
 *
 * Caller MUST free returned value
 *
 */
NMState nm_get_app_state_from_data (NMData *data)
{
	NMDevice *	act_dev = NULL;

	g_return_val_if_fail (data != NULL, NM_STATE_DISCONNECTED);

	if (data->asleep == TRUE)
		return NM_STATE_ASLEEP;

	act_dev = nm_get_active_device (data);
	if (!act_dev)
		return NM_STATE_DISCONNECTED;

	if (nm_device_is_activating (act_dev))
		return NM_STATE_CONNECTING;
	else
		return NM_STATE_CONNECTED;

	g_assert_not_reached ();

	return NM_STATE_UNKNOWN;
}


/*
 * nm_dbus_signal_state_change
 *
 * Signal a change in state
 *
 */
void nm_dbus_signal_state_change (DBusConnection *connection, NMData *data)
{
	DBusMessage *	message;
	NMState		state;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (data != NULL);

	if (!(message = dbus_message_new_signal (NM_DBUS_PATH, NM_DBUS_INTERFACE, NM_DBUS_SIGNAL_STATE_CHANGE)))
	{
		nm_warning ("nm_dbus_signal_state_change(): Not enough memory for new dbus message!");
		return;
	}

	state = nm_get_app_state_from_data (data);
	dbus_message_append_args (message, DBUS_TYPE_UINT32, &state, DBUS_TYPE_INVALID);
	if (!dbus_connection_send (connection, message, NULL))
		nm_warning ("nm_dbus_signal_state_change(): Could not raise the signal!");

	dbus_message_unref (message);
}

/*
 * nm_dbus_signal_wireless_network_change
 *
 * Notifies the bus that a new wireless network has come into range
 *
 */
void nm_dbus_signal_wireless_network_change (DBusConnection *connection, NMDevice *dev, NMAccessPoint *ap, NMNetworkStatus status, gint8 strength)
{
	DBusMessage *	message;
	char *		dev_path = NULL;
	char *		net_path = NULL;
	const char *	signal = NULL;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (dev != NULL);
	g_return_if_fail (ap != NULL);

	if (!(dev_path = nm_dbus_get_object_path_for_device (dev)))
		goto out;

	if (!(net_path = nm_dbus_get_object_path_for_network (dev, ap)))
		goto out;

	switch (status)
	{
		case NETWORK_STATUS_DISAPPEARED:
			signal = "WirelessNetworkDisappeared";
			break;
		case NETWORK_STATUS_APPEARED:
			signal = "WirelessNetworkAppeared";
			break;
		case NETWORK_STATUS_STRENGTH_CHANGED:
			signal = "WirelessNetworkStrengthChanged";
			break;
		default:
			break;
	}

	if (!signal)
	{
		nm_warning ("nm_dbus_signal_wireless_network_change(): tried to broadcast unknown signal.");
		goto out;
	}

	if (!(message = dbus_message_new_signal (NM_DBUS_PATH, NM_DBUS_INTERFACE, signal)))
	{
		nm_warning ("nm_dbus_signal_wireless_network_change(): Not enough memory for new dbus message!");
		goto out;
	}

	dbus_message_append_args (message, DBUS_TYPE_OBJECT_PATH, &dev_path, DBUS_TYPE_OBJECT_PATH, &net_path, DBUS_TYPE_INVALID);
	if (status == NETWORK_STATUS_STRENGTH_CHANGED)
		dbus_message_append_args (message, DBUS_TYPE_INT32, &strength, DBUS_TYPE_INVALID);

	if (!dbus_connection_send (connection, message, NULL))
		nm_warning ("nm_dbus_signal_wireless_network_change(): Could not raise the WirelessNetwork* signal!");

	dbus_message_unref (message);

out:
	g_free (net_path);
	g_free (dev_path);
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
	DBusMessage *		reply;
	NMData *			data;
	NMDevice *		dev;
	NMAccessPoint *	ap;
	char *			passphrase = NULL;
	NMEncKeyType		key_type = -1;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (req != NULL);

	data = nm_act_request_get_data (req);
	g_assert (data);

	dev = nm_act_request_get_dev (req);
	g_assert (dev);

	ap = nm_act_request_get_ap (req);
	g_assert (ap);

	dbus_pending_call_ref (pcall);

	nm_info ("Activation (%s) New wireless user key for network '%s' received.", nm_device_get_iface (dev), nm_ap_get_essid (ap));

	if (!dbus_pending_call_get_completed (pcall))
		goto out;

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (dbus_message_get_type (reply) == DBUS_MESSAGE_TYPE_ERROR)
	{
		/* FIXME: stop activation for this device if the dialog couldn't show */
		dbus_message_unref (reply);
		goto out;
	}

	if (dbus_message_get_args (reply, NULL, DBUS_TYPE_STRING, &passphrase, DBUS_TYPE_INT32, &key_type, DBUS_TYPE_INVALID))
		nm_device_set_user_key_for_network (req, passphrase, key_type);
	dbus_message_unref (reply);

	nm_act_request_set_user_key_pending_call (req, NULL);

out:
	nm_act_request_unref (req);
	dbus_pending_call_unref (pcall);
}


/*
 * nm_dbus_get_user_key_for_network
 *
 * Asks NetworkManagerInfo for a user-entered WEP key.
 *
 */
void nm_dbus_get_user_key_for_network (DBusConnection *connection, NMActRequest *req)
{
	DBusMessage *		message;
	DBusPendingCall *	pcall;
	NMData *			data;
	NMDevice *		dev;
	NMAccessPoint *	ap;
	gint32			attempt = 1;
	char *			dev_path;
	char *			net_path;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (req != NULL);

	data = nm_act_request_get_data (req);
	g_assert (data);

	dev = nm_act_request_get_dev (req);
	g_assert (dev);

	ap = nm_act_request_get_ap (req);
	g_assert (ap);

	nm_info ("Activation (%s) New wireless user key requested for network '%s'.", nm_device_get_iface (dev), nm_ap_get_essid (ap));

	if (!(message = dbus_message_new_method_call (NMI_DBUS_SERVICE, NMI_DBUS_PATH, NMI_DBUS_INTERFACE, "getKeyForNetwork")))
	{
		nm_warning ("nm_dbus_get_user_key_for_network(): Couldn't allocate the dbus message");
		return;
	}

	dev_path = nm_dbus_get_object_path_for_device (dev);
	net_path = nm_dbus_get_object_path_for_network (dev, ap);
	if (dev_path && strlen (dev_path) && net_path && strlen (net_path))
	{
		dbus_message_append_args (message, DBUS_TYPE_OBJECT_PATH, &dev_path,
									DBUS_TYPE_OBJECT_PATH, &net_path,
									DBUS_TYPE_INT32, &attempt,
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
	} else nm_warning ("nm_dbus_get_user_key_for_network(): bad object path data");
	g_free (net_path);
	g_free (dev_path);

	dbus_message_unref (message);
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


/*
 * nm_dbus_update_wireless_scan_method_cb
 *
 * Callback from nm_dbus_update_wireless_scan_method
 *
 */
static void nm_dbus_update_wireless_scan_method_cb (DBusPendingCall *pcall, NMData *data)
{
	DBusMessage *			reply;
	NMWirelessScanMethod	method = NM_SCAN_METHOD_UNKNOWN;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (data != NULL);

	if (!dbus_pending_call_get_completed (pcall))
		goto out;

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (dbus_message_get_type (reply) == DBUS_MESSAGE_TYPE_ERROR)
	{
		dbus_message_unref (reply);
		goto out;
	}

	if (dbus_message_get_args (reply, NULL, DBUS_TYPE_UINT32, &method, DBUS_TYPE_INVALID))
	{
		if ((method == NM_SCAN_METHOD_ON) || (method == NM_SCAN_METHOD_OFF) || (method == NM_SCAN_METHOD_AUTO))
			data->scanning_method = method;
	}
	dbus_message_unref (reply);

out:
	dbus_pending_call_unref (pcall);
}


/*
 * nm_dbus_update_wireless_scan_method
 *
 * Get the wireless scan method from NetworkManagerInfo
 *
 */
void nm_dbus_update_wireless_scan_method (DBusConnection *connection, NMData *data)
{
	DBusMessage *		message = NULL;
	DBusPendingCall *	pcall = NULL;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (data != NULL);

	if (!(message = dbus_message_new_method_call (NMI_DBUS_SERVICE, NMI_DBUS_PATH, NMI_DBUS_INTERFACE, "getWirelessScanMethod")))
	{
		nm_warning ("nm_dbus_update_wireless_scan_method(): Couldn't allocate the dbus message");
		return;
	}

	if (dbus_connection_send_with_reply (connection, message, &pcall, INT_MAX) && pcall)
		dbus_pending_call_set_notify (pcall, (DBusPendingCallNotifyFunction) nm_dbus_update_wireless_scan_method_cb, data, NULL);
	else
		nm_warning ("nm_dbus_update_wireless_scan_method(): could not send dbus message");

	dbus_message_unref (message);
}


/*
 * nm_dbus_update_network_auth_method
 *
 * Tell NetworkManagerInfo the updated auth_method of the AP
 *
 */
gboolean nm_dbus_update_network_auth_method (DBusConnection *connection, const char *network, const NMDeviceAuthMethod auth_method)
{
	DBusMessage *	message;
	gboolean		success = FALSE;
	dbus_int32_t	auth_method_as_int32 = (dbus_int32_t) auth_method;

	g_return_val_if_fail (connection != NULL, FALSE);
	g_return_val_if_fail (network != NULL, FALSE);
	g_return_val_if_fail (auth_method != NM_DEVICE_AUTH_METHOD_UNKNOWN, FALSE);

	if (!(message = dbus_message_new_method_call (NMI_DBUS_SERVICE, NMI_DBUS_PATH, NMI_DBUS_INTERFACE, "updateNetworkAuthMethod")))
	{
		nm_warning ("nm_dbus_update_network_auth_method (): Couldn't allocate the dbus message");
		return (FALSE);
	}

	dbus_message_append_args (message, DBUS_TYPE_STRING, &network, DBUS_TYPE_INT32, &auth_method, DBUS_TYPE_INVALID);
	if (!dbus_connection_send (connection, message, NULL))
		nm_warning ("nm_dbus_update_network_auth_method (): failed to send dbus message.");
	else
		success = TRUE;

	dbus_message_unref (message);
	return (success);
}


/*
 * nm_dbus_add_network_address
 *
 * Tell NetworkManagerInfo the MAC address of an AP
 *
 * Returns:	FALSE on error
 *			TRUE on success
 *
 */
gboolean nm_dbus_add_network_address (DBusConnection *connection, NMNetworkType type, const char *network, struct ether_addr *addr)
{
	DBusMessage *	message;
	gboolean		success = FALSE;
	gchar *		char_addr;
	dbus_int32_t	type_as_int32 = (dbus_int32_t) type;

	g_return_val_if_fail (connection != NULL, FALSE);
	g_return_val_if_fail (network != NULL, FALSE);
	g_return_val_if_fail (type != NETWORK_TYPE_UNKNOWN, FALSE);
	g_return_val_if_fail (addr != NULL, FALSE);

	if (!(message = dbus_message_new_method_call (NMI_DBUS_SERVICE, NMI_DBUS_PATH, NMI_DBUS_INTERFACE, "addNetworkAddress")))
	{
		nm_warning ("nm_dbus_add_network_ap_mac_address(): Couldn't allocate the dbus message");
		return (FALSE);
	}

	char_addr = g_new0 (gchar, 20);
	ether_ntoa_r (addr, char_addr);
	dbus_message_append_args (message, DBUS_TYPE_STRING, &network,
				  DBUS_TYPE_INT32, &type_as_int32,
				  DBUS_TYPE_STRING, &char_addr,
				  DBUS_TYPE_INVALID);
	g_free (char_addr);					

	if (!dbus_connection_send (connection, message, NULL))
		nm_warning ("nm_dbus_add_network_ap_mac_address(): failed to send dbus message.");
	else
		success = TRUE;

	dbus_message_unref (message);
	return (success);
}


typedef struct GetOneNetworkCBData
{
	NMData *			data;
	char *			network;
	NMAccessPointList *	list;
} GetOneNetworkCBData;


void free_get_one_network_cb_data (GetOneNetworkCBData *data)
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


void free_get_networks_cb_data (GetNetworksCBData *data)
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
void nm_dbus_get_network_data_cb (DBusPendingCall *pcall, void *user_data)
{
	GetOneNetworkCBData *	cb_data = (GetOneNetworkCBData *)user_data;
	DBusMessage *			reply;
	DBusError				error;
	const char *			essid = NULL;
	gint					timestamp_secs = -1;
	const char *			key = NULL;
	NMEncKeyType			key_type = -1;
	gboolean				trusted = FALSE;
	NMDeviceAuthMethod		auth_method = NM_DEVICE_AUTH_METHOD_UNKNOWN;
	char **				addresses;
	int					num_addresses;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (cb_data != NULL);
	g_return_if_fail (cb_data->data != NULL);
	g_return_if_fail (cb_data->network != NULL);
	g_return_if_fail (cb_data->list != NULL);

	dbus_pending_call_ref (pcall);

	if (!dbus_pending_call_get_completed (pcall))
		goto out;

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (dbus_message_is_error (reply, "BadNetworkData"))
	{
		dbus_message_unref (reply);
		nm_ap_list_remove_ap_by_essid (cb_data->list, cb_data->network);
		goto out;
	}

	dbus_error_init (&error);
	if (dbus_message_get_args (reply, &error, DBUS_TYPE_STRING, &essid,
									  DBUS_TYPE_INT32, &timestamp_secs,
									  DBUS_TYPE_STRING, &key,
									  DBUS_TYPE_INT32, &key_type,
									  DBUS_TYPE_INT32, &auth_method,
									  DBUS_TYPE_BOOLEAN, &trusted,
									  DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &addresses, &num_addresses,
									  DBUS_TYPE_INVALID))
	{
		if (timestamp_secs > 0)
		{
			NMAccessPoint *	ap;
			NMAccessPoint *	list_ap;
			GTimeVal *		timestamp = g_new0 (GTimeVal, 1);
			GSList *			addr_list = NULL;
			int				i;

			ap = nm_ap_new ();
			nm_ap_set_essid (ap, essid);

			timestamp->tv_sec = timestamp_secs;
			timestamp->tv_usec = 0;
			nm_ap_set_timestamp (ap, timestamp);
			g_free (timestamp);

			nm_ap_set_trusted (ap, trusted);

			if (key && strlen (key)) 
				nm_ap_set_enc_key_source (ap, key, key_type);
			else
				nm_ap_set_enc_key_source (ap, NULL, NM_ENC_TYPE_UNKNOWN);
			nm_ap_set_auth_method (ap, auth_method);

			for (i = 0; i < num_addresses; i++)
				if (strlen (addresses[i]) >= 11)
					addr_list = g_slist_append (addr_list, g_strdup (addresses[i]));
			nm_ap_set_user_addresses (ap, addr_list);

			if ((list_ap = nm_ap_list_get_ap_by_essid (cb_data->list, essid)))
			{
				nm_ap_set_essid (list_ap, nm_ap_get_essid (ap));
				nm_ap_set_timestamp (list_ap, nm_ap_get_timestamp (ap));
				nm_ap_set_trusted (list_ap, nm_ap_get_trusted (ap));
				nm_ap_set_enc_key_source (list_ap, nm_ap_get_enc_key_source (ap), nm_ap_get_enc_type (ap));
				nm_ap_set_auth_method (list_ap, nm_ap_get_auth_method (ap));
				nm_ap_set_user_addresses (list_ap, nm_ap_get_user_addresses (ap));
			}
			else
			{
				/* New AP, just add it to the list */
				nm_ap_list_append_ap (cb_data->list, ap);
			}
			nm_ap_unref (ap);

			/* Ensure all devices get new information copied into their device lists */
			nm_policy_schedule_device_ap_lists_update_from_allowed (cb_data->data);
		}
		dbus_free_string_array (addresses);
	}
	dbus_message_unref (reply);

out:
	dbus_pending_call_unref (pcall);
}


/*
 * nm_dbus_get_networks_cb
 *
 * Async callback from nm_dbus_get_networks
 *
 */
void nm_dbus_get_networks_cb (DBusPendingCall *pcall, void *user_data)
{
	DBusMessage *		reply;
	DBusMessageIter	iter, array_iter;
	GetNetworksCBData *	cb_data =  (GetNetworksCBData *)user_data;

	g_return_if_fail (pcall);
	g_return_if_fail (cb_data != NULL);
	g_return_if_fail (cb_data->list != NULL);
	g_return_if_fail (cb_data->data != NULL);

	dbus_pending_call_ref (pcall);

	if (!dbus_pending_call_get_completed (pcall))
		goto out;

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (message_is_error (reply))
		goto out;

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
			dbus_int32_t			type_as_int32 = (dbus_int32_t) nm_ap_list_get_type (cb_data->list);
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
	dbus_int32_t		type_as_int32 = (dbus_int32_t) nm_ap_list_get_type (list);
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
static void nm_dbus_update_one_allowed_network (DBusConnection *connection, const char *network, NMData *data)
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

	dbus_message_append_args (message, DBUS_TYPE_STRING, &network, DBUS_TYPE_INT32, &type_as_int32, DBUS_TYPE_INVALID);
	dbus_connection_send_with_reply (connection, message, &pcall, -1);
	dbus_message_unref (message);
	if (!pcall)
		nm_warning ("nm_dbus_update_one_allowed_network(): pending call was NULL");
	else
		dbus_pending_call_set_notify (pcall, nm_dbus_get_network_data_cb, cb_data, (DBusFreeFunction) free_get_one_network_cb_data);
}


/*
 * nm_dbus_signal_filter
 *
 * Respond to NetworkManagerInfo signals about changing Allowed Networks
 *
 */
static DBusHandlerResult nm_dbus_signal_filter (DBusConnection *connection, DBusMessage *message, void *user_data)
{
	NMData *		data = (NMData *)user_data;
	const char *	object_path;
	const char *	method;
	gboolean		handled = FALSE;
	DBusError		error;

	g_return_val_if_fail (data != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (connection != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (message != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	method = dbus_message_get_member (message);
	if (!(object_path = dbus_message_get_path (message)))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (dbus_message_get_type (message) != DBUS_MESSAGE_TYPE_SIGNAL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	/* nm_debug ("nm_dbus_nmi_filter() got method %s for path %s", method, object_path); */

	dbus_error_init (&error);

	if (strcmp (object_path, NMI_DBUS_PATH) == 0)
	{
		if (dbus_message_is_signal (message, NMI_DBUS_INTERFACE, "WirelessNetworkUpdate"))
		{
			char			*network = NULL;

			if (dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &network, DBUS_TYPE_INVALID))
			{
				/* Update a single wireless network's data */
				nm_debug ("NetworkManagerInfo triggered update of wireless network '%s'", network);
				nm_dbus_update_one_allowed_network (connection, network, data);
				handled = TRUE;
			}
		}
		else if (dbus_message_is_signal (message, NMI_DBUS_INTERFACE, "VPNConnectionUpdate"))
		{
			char	*name = NULL;

			if (dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID))
			{
				nm_debug ("NetworkManagerInfo triggered update of VPN connection '%s'", name);
				nm_dbus_vpn_update_one_vpn_connection (data->dbus_connection, name, data);
				handled = TRUE;
			}
		}
		else if (dbus_message_is_signal (message, NMI_DBUS_INTERFACE, "WirelessScanMethodUpdate"))
			nm_dbus_update_wireless_scan_method (data->dbus_connection, data);
	}
	else if (dbus_message_is_signal (message, DBUS_INTERFACE_DBUS, "Disconnected"))
	{
		/* FIXME: try to recover from disconnection */
		data->dbus_connection = NULL;
		handled = TRUE;
	}
	else if (dbus_message_is_signal (message, DBUS_INTERFACE_DBUS, "NameOwnerChanged"))
	{
		char 	*service;
		char		*old_owner;
		char		*new_owner;

		if (dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &service, DBUS_TYPE_STRING, &old_owner,
									DBUS_TYPE_STRING, &new_owner, DBUS_TYPE_INVALID))
		{
			if (strcmp (service, NMI_DBUS_SERVICE) == 0)
			{
				gboolean old_owner_good = (old_owner && (strlen (old_owner) > 0));
				gboolean new_owner_good = (new_owner && (strlen (new_owner) > 0));

				if (!old_owner_good && new_owner_good) /* NMI just appeared */
				{
					char *match = get_nmi_match_string (new_owner);
					dbus_bus_add_match (connection, match, NULL);
					nm_policy_schedule_allowed_ap_list_update (data);
					nm_dbus_vpn_schedule_vpn_connections_update (data);
					nm_dbus_update_wireless_scan_method (data->dbus_connection, data);
					g_free (match);
					handled = TRUE;
				}
				else if (old_owner_good && !new_owner_good)	/* NMI went away */
				{
					char *match = get_nmi_match_string (old_owner);
					dbus_bus_remove_match (connection, match, NULL);
					g_free (match);
				}
			}
			else if (nm_dhcp_manager_process_name_owner_changed (data->dhcp_manager, service, old_owner, new_owner) == TRUE)
			{
				/* Processed by the DHCP manager */
				handled = TRUE;
			}
			else if (nm_vpn_manager_process_name_owner_changed (data->vpn_manager, service, old_owner, new_owner) == TRUE)
			{
				/* Processed by the VPN manager */
				handled = TRUE;
			}
		}
	}
	else if (nm_dhcp_manager_process_signal (data->dhcp_manager, message) == TRUE)
	{
		/* Processed by the DHCP manager */
		handled = TRUE;
	}
	else if (nm_vpn_manager_process_signal (data->vpn_manager, message) == TRUE)
	{
		/* Processed by the VPN manager */
		handled = TRUE;
	}

	if (dbus_error_is_set (&error))
		dbus_error_free (&error);

	return (handled ? DBUS_HANDLER_RESULT_HANDLED : DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
}


/*
 * nm_dbus_nm_message_handler
 *
 * Dispatch messages against our NetworkManager object
 *
 */
static DBusHandlerResult nm_dbus_nm_message_handler (DBusConnection *connection, DBusMessage *message, void *user_data)
{
	NMData			*data = (NMData *)user_data;
	gboolean			 handled = TRUE;
	DBusMessage		*reply = NULL;
	NMDbusCBData		 cb_data;

	g_return_val_if_fail (data != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (data->nm_methods != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (connection != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (message != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	cb_data.data = data;
	cb_data.dev = NULL;
	handled = nm_dbus_method_dispatch (data->nm_methods, connection, message, &cb_data, &reply);
	if (reply)
	{
		dbus_connection_send (connection, reply, NULL);
		dbus_message_unref (reply);
	}

	return (handled ? DBUS_HANDLER_RESULT_HANDLED : DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
}


/*
 * nm_dbus_devices_message_handler
 *
 * Dispatch messages against individual network devices
 *
 */
static DBusHandlerResult nm_dbus_devices_message_handler (DBusConnection *connection, DBusMessage *message, void *user_data)
{
	NMData			*data = (NMData *)user_data;
	gboolean			 handled = FALSE;
	const char		*path;
	DBusMessage		*reply = NULL;
	NMDevice			*dev;

	g_return_val_if_fail (data != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (connection != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (message != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	path = dbus_message_get_path (message);

	if (!(dev = nm_dbus_get_device_from_object_path (data, path)))
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE, "DeviceNotFound", "The requested network device does not exist.");
	else
	{
		char			*object_path, *escaped_object_path;
		NMDbusCBData	 cb_data;

		cb_data.data = data;
		cb_data.dev = dev;

		/* Test whether or not the _networks_ of a device were queried instead of the device itself */
		object_path = g_strdup_printf ("%s/%s/Networks/", NM_DBUS_PATH_DEVICES, nm_device_get_iface (dev));
		escaped_object_path = nm_dbus_escape_object_path (object_path);
		g_free (object_path);
		if (strncmp (path, escaped_object_path, strlen (escaped_object_path)) == 0)
			handled = nm_dbus_method_dispatch (data->net_methods, connection, message, &cb_data, &reply);
		else
			handled = nm_dbus_method_dispatch (data->device_methods, connection, message, &cb_data, &reply);
		g_free (escaped_object_path);
	}

	if (reply)
	{
		dbus_connection_send (connection, reply, NULL);
		dbus_message_unref (reply);
		handled = TRUE;
	}

	return (handled ? DBUS_HANDLER_RESULT_HANDLED : DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
}


/*
 * nm_dbus_vpn_message_handler
 *
 * Dispatch messages against our NetworkManager VPNConnections object
 *
 */
static DBusHandlerResult nm_dbus_vpn_message_handler (DBusConnection *connection, DBusMessage *message, void *user_data)
{
	NMData			*data = (NMData *)user_data;
	gboolean			 handled = TRUE;
	DBusMessage		*reply = NULL;
	NMDbusCBData		 cb_data;

	g_return_val_if_fail (data != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (data->vpn_methods != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (connection != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (message != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	cb_data.data = data;
	cb_data.dev = NULL;
	handled = nm_dbus_method_dispatch (data->vpn_methods, connection, message, &cb_data, &reply);
	if (reply)
	{
		dbus_connection_send (connection, reply, NULL);
		dbus_message_unref (reply);
	}

	return (handled ? DBUS_HANDLER_RESULT_HANDLED : DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
}


/*
 * nm_dbus_is_info_daemon_running
 *
 * Ask dbus whether or not the info daemon is providing its dbus service
 *
 */
gboolean nm_dbus_is_info_daemon_running (DBusConnection *connection)
{
	DBusError		error;
	gboolean		running = FALSE;

	g_return_val_if_fail (connection != NULL, FALSE);

	dbus_error_init (&error);
	running = dbus_bus_name_has_owner (connection, NMI_DBUS_SERVICE, &error);
	if (dbus_error_is_set (&error))
	{
		running = FALSE;
		dbus_error_free (&error);
	}
	return running;
}


char *get_name_owner (DBusConnection *con, const char *name)
{
	DBusMessage *	message;
	DBusMessage *	reply;
	char *		owner = NULL;

	g_return_val_if_fail (con != NULL, NULL);
	g_return_val_if_fail (name != NULL, NULL);

	if ((message = dbus_message_new_method_call (DBUS_SERVICE_DBUS, DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS, "GetNameOwner")))
	{
		dbus_message_append_args (message, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID);
		if ((reply = dbus_connection_send_with_reply_and_block (con, message, -1, NULL)))
		{
			const char *tmp_name = NULL;
			if (dbus_message_get_args (reply, NULL, DBUS_TYPE_STRING, &tmp_name, DBUS_TYPE_INVALID))
				owner = g_strdup (tmp_name);
			dbus_message_unref (reply);
		}
		dbus_message_unref (message);
	}

fprintf (stderr, "GetNameOwner returning owner '%s' for name '%s'.\n", owner, name);
	return owner;
}


static char *get_nmi_match_string (const char *owner)
{
	g_return_val_if_fail (owner != NULL, NULL);

	return g_strdup_printf ("type='signal',interface='" NMI_DBUS_INTERFACE "',sender='%s',path='" NMI_DBUS_PATH "'", owner);
}


/*
 * nm_dbus_init
 *
 * Connect to the system messagebus and register ourselves as a service.
 *
 */
DBusConnection *nm_dbus_init (NMData *data)
{
	DBusError		 		error;
	DBusConnection *		connection;
	DBusObjectPathVTable	nm_vtable = {NULL, &nm_dbus_nm_message_handler, NULL, NULL, NULL, NULL};
	DBusObjectPathVTable	devices_vtable = {NULL, &nm_dbus_devices_message_handler, NULL, NULL, NULL, NULL};
	DBusObjectPathVTable	vpn_vtable = {NULL, &nm_dbus_vpn_message_handler, NULL, NULL, NULL, NULL};
	char *				owner;

	dbus_connection_set_change_sigpipe (TRUE);

	dbus_error_init (&error);
	connection = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
	if ((connection == NULL) || dbus_error_is_set (&error))
	{
		nm_warning ("nm_dbus_init() could not get the system bus.  Make sure the message bus daemon is running?");
		connection = NULL;
		goto out;
	}

//	dbus_connection_set_exit_on_disconnect (connection, FALSE);
	dbus_connection_setup_with_g_main (connection, data->main_context);

	data->nm_methods = nm_dbus_nm_methods_setup ();
	data->device_methods = nm_dbus_device_methods_setup ();
	data->net_methods = nm_dbus_net_methods_setup ();
	data->vpn_methods = nm_dbus_vpn_methods_setup ();

	if (    !dbus_connection_register_object_path (connection, NM_DBUS_PATH, &nm_vtable, data)
		|| !dbus_connection_register_fallback (connection, NM_DBUS_PATH_DEVICES, &devices_vtable, data)
		|| !dbus_connection_register_object_path (connection, NM_DBUS_PATH_VPN, &vpn_vtable, data))
	{
		nm_error ("nm_dbus_init() could not register D-BUS handlers.  Cannot continue.");
		connection = NULL;
		goto out;
	}

	if (!dbus_connection_add_filter (connection, nm_dbus_signal_filter, data, NULL))
	{
		nm_error ("nm_dbus_init() could not attach a dbus message filter.  The NetworkManager dbus security policy may not be loaded.  Restart dbus?");
		connection = NULL;
		goto out;
	}

	dbus_bus_add_match (connection,
				"type='signal',"
				"interface='" DBUS_INTERFACE_DBUS "',"
				"sender='" DBUS_SERVICE_DBUS "'",
				NULL);

	if ((owner = get_name_owner (connection, NMI_DBUS_SERVICE)))
	{
		char *match = get_nmi_match_string (owner);

		dbus_bus_add_match (connection, match, NULL);
		g_free (match);
		g_free (owner);
	}

	dbus_error_init (&error);
	dbus_bus_request_name (connection, NM_DBUS_SERVICE, 0, &error);
	if (dbus_error_is_set (&error))
	{
		nm_warning ("nm_dbus_init() could not acquire its service.  dbus_bus_acquire_service() says: '%s'", error.message);
		connection = NULL;
		goto out;
	}

out:
	if (dbus_error_is_set (&error))
		dbus_error_free (&error);

	return (connection);
}
