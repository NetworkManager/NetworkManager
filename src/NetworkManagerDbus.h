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


#define	NM_DBUS_NM_OBJECT_PATH_PREFIX			"/org/freedesktop/NetworkManager"
#define	NM_DBUS_NM_NAMESPACE				"org.freedesktop.NetworkManager"
#define	NM_DBUS_DEVICES_OBJECT_PATH_PREFIX		"/org/freedesktop/NetworkManager/Devices"
#define	NM_DBUS_DEVICES_NAMESPACE			"org.freedesktop.NetworkManager.Devices"
#define	NM_DBUS_NMI_OBJECT_PATH				"/org/freedesktop/NetworkManagerInfo"
#define	NM_DBUS_NMI_NAMESPACE				"org.freedesktop.NetworkManagerInfo"


DBusConnection *	nm_dbus_init						(NMData *data);

void				nm_dbus_signal_device_no_longer_active	(DBusConnection *connection, NMDevice *dev);

void				nm_dbus_signal_device_now_active		(DBusConnection *connection, NMDevice *dev);

void				nm_dbus_signal_device_ip4_address_change(DBusConnection *connection, NMDevice *dev);

void				nm_dbus_get_user_key_for_network		(DBusConnection *connection, NMDevice *dev, NMAccessPoint *ap, DBusPendingCall **pending);

void				nm_dbus_cancel_get_user_key_for_network	(DBusConnection *connection);

char *			nm_dbus_get_allowed_network_essid		(DBusConnection *connection, const char *network);

char *			nm_dbus_get_allowed_network_key		(DBusConnection *connection, const char *network);

guint			nm_dbus_get_allowed_network_priority	(DBusConnection *connection, const char *network);

char **			nm_dbus_get_allowed_networks			(DBusConnection *connection, int *num_networks);

#endif
