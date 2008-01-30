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


typedef enum
{
	DEVICE_STATUS_INVALID,
	DEVICE_NOW_ACTIVE,
	DEVICE_NO_LONGER_ACTIVE,
	DEVICE_ACTIVATING,
	DEVICE_ACTIVATION_FAILED,
	DEVICE_ACTIVATION_CANCELED,
	DEVICE_ADDED,
	DEVICE_REMOVED,
	DEVICE_CARRIER_ON,
	DEVICE_CARRIER_OFF
} DeviceStatus;


static inline gboolean message_is_error (DBusMessage *msg)
{
	g_return_val_if_fail (msg != NULL, FALSE);

	return (dbus_message_get_type (msg) == DBUS_MESSAGE_TYPE_ERROR);
}

DBusConnection *nm_dbus_init						(NMData *data);

gboolean		nm_dbus_is_info_daemon_running		(DBusConnection *connection);
char *		get_name_owner						(DBusConnection *con, const char *name);

char *		nm_dbus_get_object_path_for_device		(NMDevice *dev);
char *		nm_dbus_get_object_path_for_network	(NMDevice *dev, NMAccessPoint *ap);

void			nm_dbus_schedule_device_status_change_signal	(NMData *data, NMDevice *dev, const char *essid, DeviceStatus status);

void			nm_dbus_signal_state_change			(DBusConnection *connection, NMData *data);

void			nm_dbus_signal_wireless_network_change	(DBusConnection *connection, NMDevice80211Wireless *dev, NMAccessPoint *ap, NMNetworkStatus status, gint strength);
void			nm_dbus_signal_device_strength_change	(DBusConnection *connection, NMDevice80211Wireless *dev, gint strength);
void			nm_dbus_signal_wireless_enabled (NMData * data);

NMDevice *	nm_dbus_get_device_from_escaped_object_path	(NMData *data, const char *path);

NMState		nm_get_app_state_from_data			(NMData *data);

DBusMessage *	nm_dbus_create_error_message			(DBusMessage *message, const char *exception_namespace, const char *exception, const char *format, ...);

#endif
