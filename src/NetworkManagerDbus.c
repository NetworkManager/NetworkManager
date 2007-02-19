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
	} else if (dbus_message_is_signal (message, NMI_DBUS_INTERFACE, "UserInterfaceActivated")) {
		nm_device_802_11_wireless_set_scan_interval (data,
		                                             NULL,
		                                             NM_WIRELESS_SCAN_INTERVAL_ACTIVE);
		handled = TRUE;
	}

	return handled;
}

