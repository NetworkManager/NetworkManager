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

void			nma_dbus_init_helper				(NMApplet *applet);
void			nma_start_dbus_connection_watch		(NMApplet *applet);
void			nma_dbus_enable_wireless			(NMApplet *applet, gboolean enabled);
void			nma_dbus_enable_networking			(NMApplet *applet, gboolean enabled);
void			nma_free_gui_data_model				(NMApplet *applet);
void			nma_free_dbus_data_model			(NMApplet *applet);

#endif
