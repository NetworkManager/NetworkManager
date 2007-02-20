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

#ifndef NETWORK_MANAGER_DBUS_H
#define NETWORK_MANAGER_DBUS_H

#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include "NetworkManager.h"
#include "NetworkManagerMain.h"
#include "nm-device.h"
#include "nm-device-802-11-wireless.h"
#include "NetworkManagerAPList.h"


static inline gboolean message_is_error (DBusMessage *msg)
{
	g_return_val_if_fail (msg != NULL, FALSE);

	return (dbus_message_get_type (msg) == DBUS_MESSAGE_TYPE_ERROR);
}

char *		nm_dbus_get_object_path_for_device		(NMDevice *dev);
char *		nm_dbus_get_object_path_for_network	(NMDevice *dev, NMAccessPoint *ap);

DBusMessage *	nm_dbus_create_error_message			(DBusMessage *message, const char *exception_namespace, const char *exception, const char *format, ...);

DBusMessage *	nm_dbus_new_invalid_args_error (DBusMessage *replyto, const char *namespace);

gboolean nm_dbus_nmi_signal_handler (DBusConnection *connection,
                                     DBusMessage *message,
                                     gpointer user_data);

#endif
