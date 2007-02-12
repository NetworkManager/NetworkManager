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
#include "nm-device.h"
#include "NetworkManagerDbus.h"
#include "NetworkManagerDbusUtils.h"
#include "NetworkManagerAP.h"
#include "NetworkManagerAPList.h"
#include "NetworkManagerPolicy.h"
#include "nm-dbus-nm.h"
#include "nm-dbus-device.h"
#include "nm-dbus-net.h"
#include "nm-dbus-vpn.h"
#include "nm-dbus-nmi.h"
#include "nm-utils.h"
#include "nm-dhcp-manager.h"
#include "nm-dbus-manager.h"

#if 0
static char *get_nmi_match_string (const char *owner);

static gpointer nm_dbus_reinit (gpointer user_data);
#endif

/*
 * nm_dbus_create_error_message
 *
 * Make a DBus error message
 *
 */
DBusMessage *
nm_dbus_create_error_message (DBusMessage *message,
                              const char *exception_namespace,
                              const char *exception,
                              const char *format,
                              ...)
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


DBusMessage *
nm_dbus_new_invalid_args_error (DBusMessage *replyto,
                                const char *namespace)
{
	return nm_dbus_create_error_message (replyto,
		                                 namespace,
		                                 "InvalidArguments",
		                                 "Invalid method arguments.");
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

	object_path = g_strdup_printf ("%s/%s", NM_DBUS_PATH_DEVICE, nm_device_get_iface (dev));
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

	object_path = g_strdup_printf ("%s/%s/Networks/%s", NM_DBUS_PATH_DEVICE, nm_device_get_iface (dev), nm_ap_get_essid (ap));
	escaped_object_path = nm_dbus_escape_object_path (object_path);
	g_free (object_path);

	return escaped_object_path;
}


/*
 * nm_dbus_get_device_from_escaped_object_path
 *
 * Returns the device associated with an _escaped_ dbus object path
 *
 */
NMDevice *nm_dbus_get_device_from_escaped_object_path (NMData *data, const char *path)
{
	NMDevice *dev = NULL;
	GSList *	elt;

	g_return_val_if_fail (path != NULL, NULL);
	g_return_val_if_fail (data != NULL, NULL);

	/* Iterate over the device list looking for the device with the matching object path. */
	for (elt = data->dev_list; elt; elt = g_slist_next (elt)) {
		char *compare_path;
		char *escaped_compare_path;
		int len;

		if (!(dev = NM_DEVICE (elt->data)))
			continue;

		compare_path = g_strdup_printf ("%s/%s", NM_DBUS_PATH_DEVICE, nm_device_get_iface (dev));
		escaped_compare_path = nm_dbus_escape_object_path (compare_path);
		g_free (compare_path);
		len = strlen (escaped_compare_path);

		/* Compare against our constructed path, but ignore any trailing elements */
		if (    (strncmp (path, escaped_compare_path, len) == 0)
			&& ((path[len] == '\0' || path[len] == '/')))
		{
			g_free (escaped_compare_path);
			g_object_ref (G_OBJECT (dev));
			break;
		}
		g_free (escaped_compare_path);
		dev = NULL;
	}

	return dev;
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
static gboolean
nm_dbus_signal_device_status_change (gpointer user_data)
{
	NMStatusChangeData *cb_data = (NMStatusChangeData *)user_data;
	DBusMessage *		message;
	char *			dev_path = NULL;
	const char *		sig = NULL;
	int				i = 0;
	NMDBusManager *	dbus_mgr = NULL;
	DBusConnection *dbus_connection;

	g_return_val_if_fail (cb_data->data, FALSE);
	g_return_val_if_fail (cb_data->dev, FALSE);

	dbus_mgr = nm_dbus_manager_get ();
	dbus_connection = nm_dbus_manager_get_dbus_connection (dbus_mgr);
	if (!dbus_connection) {
		nm_warning ("could not get the dbus connection.");
		goto out;
	}

	while ((dev_status_signals[i].status != DEVICE_STATUS_INVALID) && (dev_status_signals[i].status != cb_data->status))
		i++;

	if (!(sig = dev_status_signals[i].signal))
		goto out;

	if (!(dev_path = nm_dbus_get_object_path_for_device (cb_data->dev)))
		goto out;

	message = dbus_message_new_signal (NM_DBUS_PATH, NM_DBUS_INTERFACE, sig);
	if (!message) {
		nm_warning ("nm_dbus_signal_device_status_change(): Not enough memory for new dbus message!");
		goto out;
	}

	/* If the device was wireless, attach the name of the wireless network that failed to activate */
	if (cb_data->ap) {
		const char *essid = nm_ap_get_essid (cb_data->ap);
		if (essid)
			dbus_message_append_args (message, DBUS_TYPE_OBJECT_PATH, &dev_path, DBUS_TYPE_STRING, &essid, DBUS_TYPE_INVALID);
		nm_ap_unref (cb_data->ap);
	} else {
		dbus_message_append_args (message, DBUS_TYPE_OBJECT_PATH, &dev_path, DBUS_TYPE_INVALID);
	}

	dbus_connection_send (dbus_connection, message, NULL);
	dbus_message_unref (message);

	g_object_unref (G_OBJECT (cb_data->dev));
	g_slice_free (NMStatusChangeData, cb_data);

out:
	g_object_unref (dbus_mgr);
	g_free (dev_path);
	return FALSE;
}


void nm_dbus_schedule_device_status_change_signal (NMData *data, NMDevice *dev, NMAccessPoint *ap, DeviceStatus status)
{
	NMStatusChangeData * cb_data = NULL;
	GSource *            source;
	guint                id;

	g_return_if_fail (data != NULL);
	g_return_if_fail (dev != NULL);

	cb_data = g_slice_new0 (NMStatusChangeData);
	g_object_ref (G_OBJECT (dev));
	cb_data->data = data;
	cb_data->dev = dev;
	if (ap) {
		nm_ap_ref (ap);
		cb_data->ap = ap;
	}
	cb_data->status = status;

	id = g_idle_add (nm_dbus_signal_device_status_change, cb_data);
	source = g_main_context_find_source_by_id (NULL, id);
	if (source) {
		g_source_set_priority (source, G_PRIORITY_HIGH_IDLE);
	}
}


/*
 * nm_dbus_signal_state_change
 *
 * Signal a change in state
 *
 */
void nm_dbus_signal_state_change (DBusConnection *connection, NMState state)
{
	DBusMessage *	message;
	
	g_return_if_fail (connection != NULL);

	if (!(message = dbus_message_new_signal (NM_DBUS_PATH, NM_DBUS_INTERFACE, NM_DBUS_SIGNAL_STATE_CHANGE)))
	{
		nm_warning ("nm_dbus_signal_state_change(): Not enough memory for new dbus message!");
		return;
	}

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
void
nm_dbus_signal_wireless_network_change (NMDevice80211Wireless *dev,
                                        NMAccessPoint *ap,
                                        NMNetworkStatus status,
                                        gint strength)
{
	NMDBusManager *	dbus_mgr = NULL;
	DBusConnection *dbus_connection;
	DBusMessage *	message;
	char *		dev_path = NULL;
	char *		net_path = NULL;
	const char *	sig = NULL;

	g_return_if_fail (dev != NULL);
	g_return_if_fail (ap != NULL);

	dbus_mgr = nm_dbus_manager_get ();
	dbus_connection = nm_dbus_manager_get_dbus_connection (dbus_mgr);
	if (!dbus_connection) {
		nm_warning ("could not get the dbus connection.");
		goto out;
	}

	if (!(dev_path = nm_dbus_get_object_path_for_device (NM_DEVICE (dev))))
		goto out;

	if (!(net_path = nm_dbus_get_object_path_for_network (NM_DEVICE (dev), ap)))
		goto out;

	switch (status) {
		case NETWORK_STATUS_DISAPPEARED:
			sig = "WirelessNetworkDisappeared";
			break;
		case NETWORK_STATUS_APPEARED:
			sig = "WirelessNetworkAppeared";
			break;
		case NETWORK_STATUS_STRENGTH_CHANGED:
			sig = "WirelessNetworkStrengthChanged";
			break;
		default:
			break;
	}

	if (!sig) {
		nm_warning ("tried to broadcast unknown signal.");
		goto out;
	}

	message = dbus_message_new_signal (NM_DBUS_PATH, NM_DBUS_INTERFACE, sig);
	if (!message) {
		nm_warning ("could not allocate the dbus message.");
		goto out;
	}

	dbus_message_append_args (message,
	                          DBUS_TYPE_OBJECT_PATH, &dev_path,
	                          DBUS_TYPE_OBJECT_PATH, &net_path,
	                          DBUS_TYPE_INVALID);
	if (status == NETWORK_STATUS_STRENGTH_CHANGED) {
		dbus_message_append_args (message,
		                          DBUS_TYPE_INT32, &strength,
		                          DBUS_TYPE_INVALID);
	}

	dbus_connection_send (dbus_connection, message, NULL);
	dbus_message_unref (message);

out:
	g_free (net_path);
	g_free (dev_path);
	g_object_unref (dbus_mgr);
}


void
nm_dbus_signal_device_strength_change (NMDevice80211Wireless *dev,
                                       gint strength)
{
	NMDBusManager *	dbus_mgr = NULL;
	DBusConnection *dbus_connection;
	DBusMessage *	message;
	char *		dev_path = NULL;

	g_return_if_fail (dev != NULL);

	dbus_mgr = nm_dbus_manager_get ();
	dbus_connection = nm_dbus_manager_get_dbus_connection (dbus_mgr);
	if (!dbus_connection) {
		nm_warning ("could not get the dbus connection.");
		goto out;
	}

	if (!(dev_path = nm_dbus_get_object_path_for_device (NM_DEVICE (dev))))
		goto out;

	message = dbus_message_new_signal (NM_DBUS_PATH,
	                                   NM_DBUS_INTERFACE,
	                                   "DeviceStrengthChanged");
	if (!message) {
		nm_warning ("could not allocate the dbus message.");
		goto out;
	}

	dbus_message_append_args (message,
	                          DBUS_TYPE_OBJECT_PATH, &dev_path,
	                          DBUS_TYPE_INT32, &strength,
	                          DBUS_TYPE_INVALID);
	dbus_connection_send (dbus_connection, message, NULL);
	dbus_message_unref (message);

out:
	g_free (dev_path);
	g_object_unref (dbus_mgr);
}

gboolean
nm_dbus_nmi_signal_handler (DBusConnection *connection,
                            DBusMessage *message,
                            gpointer user_data)
{
	NMData * data = (NMData *) user_data;
	const char * object_path;
	gboolean	handled = FALSE;

	g_return_val_if_fail (data != NULL, FALSE);

	if (!(object_path = dbus_message_get_path (message)))
		return FALSE;

	if (strcmp (object_path, NMI_DBUS_PATH) != 0)
		return FALSE;

	if (dbus_message_is_signal (message, NMI_DBUS_INTERFACE, "WirelessNetworkUpdate")) {
		char			*network = NULL;

		if (dbus_message_get_args (message,
		                           NULL,
		                           DBUS_TYPE_STRING, &network,
		                           DBUS_TYPE_INVALID)) {
			/* Update a single wireless network's data */
			nm_debug ("NetworkManagerInfo triggered update of wireless network "
			          "'%s'",
			          network);
			nm_dbus_update_one_allowed_network (network, data);
			handled = TRUE;
		}
	} else if (dbus_message_is_signal (message, NMI_DBUS_INTERFACE, "VPNConnectionUpdate")) {
		char	*name = NULL;

		if (dbus_message_get_args (message,
		                           NULL,
		                           DBUS_TYPE_STRING, &name,
		                           DBUS_TYPE_INVALID)) {
			nm_debug ("NetworkManagerInfo triggered update of VPN connection "
			          " '%s'",
			          name);
			nm_dbus_vpn_update_one_vpn_connection (connection, name, data);
			handled = TRUE;
		}
	} else if (dbus_message_is_signal (message, NMI_DBUS_INTERFACE, "UserInterfaceActivated")) {
		nm_device_802_11_wireless_set_scan_interval (data,
		                                             NULL,
		                                             NM_WIRELESS_SCAN_INTERVAL_ACTIVE);
		handled = TRUE;
	}

	return handled;
}

