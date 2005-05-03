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

#ifndef NETWORK_MANAGER_DBUS_UTILS_H
#define NETWORK_MANAGER_DBUS_UTILS_H

#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>

#include "NetworkManagerDevice.h"

typedef struct NMDbusCBData
{
	NMData		*data;
	NMDevice		*dev;
	NMAccessPoint	*ap;
} NMDbusCBData;

typedef DBusMessage* (*NMDbusMethod) (DBusConnection *, DBusMessage *, NMDbusCBData *);


NMDbusMethodList *	nm_dbus_method_list_new			(NMDbusMethod validate_method);

void				nm_dbus_method_list_add_method	(NMDbusMethodList *list, const char *method, NMDbusMethod callback);

gboolean			nm_dbus_method_dispatch			(NMDbusMethodList *list, DBusConnection *connection, DBusMessage *message,
													gpointer user_data, DBusMessage **reply);

void				nm_dbus_method_list_free			(NMDbusMethodList *list);


#endif
