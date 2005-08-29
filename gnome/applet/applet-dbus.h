/* NetworkManager Wireless Applet -- Display wireless access points and allow user control
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

#ifndef APPLET_DBUS_H
#define APPLET_DBUS_H

#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include "NetworkManager.h"
#include "applet.h"

/* Return codes for functions that use dbus */
enum
{
	RETURN_SUCCESS = 1,
	RETURN_FAILURE = 0,
	RETURN_NO_NM = -1
};

static inline gboolean message_is_error (DBusMessage *msg)
{
	g_return_val_if_fail (msg != NULL, FALSE);

	return (dbus_message_get_type (msg) == DBUS_MESSAGE_TYPE_ERROR);
}

int			nmwa_dbus_call_method_string			(DBusConnection *con, const char *path, const char *interface, const char *method, gboolean is_obj_path, char **string);
int			nmwa_dbus_call_method_uint32			(DBusConnection *con, const char *path, const char *interface, const char *method, guint32 *num);
int			nmwa_dbus_call_method_int32			(DBusConnection *con, const char *path, const char *interface, const char *method, gint32 *num);
int			nmwa_dbus_call_method_boolean			(DBusConnection *con, const char *path, const char *interface, const char *method, gboolean *num);
int			nmwa_dbus_call_method_string_array		(DBusConnection *con, const char *path, const char *interface, const char *method,
												gboolean is_obj_path, char ***array, guint32 *array_len);

DBusMessage *	nmwa_dbus_create_error_message		(DBusMessage *message, const char *exception_namespace, const char *exception, const char *format, ...);

void			nmwa_dbus_init_helper				(NMWirelessApplet *applet);

void			nmwa_dbus_enable_scanning			(NMWirelessApplet *applet, gboolean enabled);

void			nmwa_dbus_enable_wireless			(NMWirelessApplet *applet, gboolean enabled);

void			nmwa_free_gui_data_model				(NMWirelessApplet *applet);
void			nmwa_free_dbus_data_model			(NMWirelessApplet *applet);

#endif
