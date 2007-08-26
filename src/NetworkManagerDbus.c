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

/*-------------------------------------------------------------*/
/* Handler code */
/*-------------------------------------------------------------*/

gboolean
nm_dbus_nmi_signal_handler (DBusConnection *connection,
                            DBusMessage *message,
                            gpointer user_data)
{
	NMManager *manager = NM_MANAGER (user_data);
	const char * object_path;
	gboolean	handled = FALSE;

	g_return_val_if_fail (manager != NULL, FALSE);

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
			nm_debug ("NetworkManagerInfo triggered update of wireless network '%s'", network);
			nm_dbus_update_one_allowed_network (network,
												(NMData *) g_object_get_data (G_OBJECT (manager), "NM_DATA_HACK"));
			handled = TRUE;
		}
	} else if (dbus_message_is_signal (message, NMI_DBUS_INTERFACE, "UserInterfaceActivated")) {
		GSList *iter;

		for (iter = nm_manager_get_devices (manager); iter; iter = iter-> next) {
			NMDevice *device = NM_DEVICE (iter->data);

			if (NM_IS_DEVICE_802_11_WIRELESS (device))
				nm_device_802_11_wireless_reset_scan_interval (NM_DEVICE_802_11_WIRELESS (device));
		}

		handled = TRUE;
	}

	return handled;
}

