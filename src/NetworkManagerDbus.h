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
#include <dbus/dbus-glib.h>


#define	NM_DBUS_NM_OBJECT_PATH_PREFIX			"/org/freedesktop/NetworkManager"
#define	NM_DBUS_NM_NAMESPACE				"org.freedesktop.NetworkManager"
#define	NM_DBUS_DEVICES_OBJECT_PATH_PREFIX		"/org/freedesktop/NetworkManager/Devices"
#define	NM_DBUS_DEVICES_NAMESPACE			"org.freedesktop.NetworkManager.Devices"


DBusConnection *	nm_dbus_init						(void);

void				nm_dbus_signal_device_no_longer_active	(DBusConnection *connection, NMDevice *dev);

void				nm_dbus_signal_device_now_active		(DBusConnection *connection, NMDevice *dev);

#endif
