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
#include "NetworkManagerAPList.h"


typedef enum
{
	DEVICE_NOW_ACTIVE,
	DEVICE_NO_LONGER_ACTIVE,
	DEVICE_ACTIVATING,
	DEVICE_ACTIVATION_FAILED,
	DEVICE_ACTIVATION_CANCELED,
	DEVICE_LIST_CHANGE,
	DEVICE_STATUS_CHANGE
} DeviceStatus;


DBusConnection *nm_dbus_init						(NMData *data);

gboolean		nm_dbus_is_info_daemon_running		(DBusConnection *connection);

void			nm_dbus_schedule_device_status_change	(NMDevice *dev, DeviceStatus status);
void			nm_dbus_signal_device_status_change	(DBusConnection *connection, NMDevice *dev, DeviceStatus status);

void			nm_dbus_schedule_network_not_found_signal	(NMData *data, const char *network);

void			nm_dbus_signal_network_status_change	(DBusConnection *connection, NMData *data);

void			nm_dbus_signal_device_ip4_address_change(DBusConnection *connection, NMDevice *dev);

void			nm_dbus_signal_wireless_network_change	(DBusConnection *connection, NMDevice *dev, NMAccessPoint *ap, NMNetworkStatus status, gint8 strength);

void			nm_dbus_get_user_key_for_network		(DBusConnection *connection, NMDevice *dev, NMAccessPoint *ap, int attempt);

void			nm_dbus_cancel_get_user_key_for_network	(DBusConnection *connection);

void			nm_dbus_update_wireless_scan_method	(DBusConnection *connection, NMData *data);

NMAccessPoint *nm_dbus_get_network_object			(DBusConnection *connection, NMNetworkType type, const char *network);

gboolean		nm_dbus_add_network_address			(DBusConnection *connection, NMNetworkType type, const char *network, struct ether_addr *addr);

gboolean		nm_dbus_update_network_auth_method		(DBusConnection *connection, const char *network, const NMDeviceAuthMethod auth_method);

gboolean		nm_dbus_nmi_is_running				(DBusConnection *connection);

char **		nm_dbus_get_networks				(DBusConnection *connection, NMNetworkType type, int *num_networks);

DBusMessage *	nm_dbus_create_error_message			(DBusMessage *message, const char *exception_namespace,
												const char *exception, const char *format, ...);

NMDevice *	nm_dbus_get_device_from_object_path	(NMData *data, const char *path);

char *		nm_dbus_network_status_from_data		(NMData *data);

#endif
