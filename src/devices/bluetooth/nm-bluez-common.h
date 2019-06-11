/* NetworkManager -- Network link manager
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2017 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_BLUEZ_COMMON_H__
#define __NETWORKMANAGER_BLUEZ_COMMON_H__

#define BLUETOOTH_CONNECT_DUN "dun"
#define BLUETOOTH_CONNECT_NAP "nap"

#define NM_BLUEZ_SERVICE           "org.bluez"

#define NM_BLUEZ_MANAGER_PATH      "/"
#define NM_OBJECT_MANAGER_INTERFACE "org.freedesktop.DBus.ObjectManager"

#define NM_BLUEZ5_ADAPTER_INTERFACE "org.bluez.Adapter1"
#define NM_BLUEZ5_DEVICE_INTERFACE  "org.bluez.Device1"
#define NM_BLUEZ5_NETWORK_INTERFACE "org.bluez.Network1"
#define NM_BLUEZ5_NETWORK_SERVER_INTERFACE "org.bluez.NetworkServer1"

#define NM_BLUEZ4_MANAGER_INTERFACE "org.bluez.Manager"
#define NM_BLUEZ4_ADAPTER_INTERFACE "org.bluez.Adapter"
#define NM_BLUEZ4_DEVICE_INTERFACE  "org.bluez.Device"
#define NM_BLUEZ4_SERIAL_INTERFACE  "org.bluez.Serial"
#define NM_BLUEZ4_NETWORK_INTERFACE "org.bluez.Network"

#define NM_BLUEZ_MANAGER_BDADDR_ADDED "bdaddr-added"
#define NM_BLUEZ_MANAGER_NETWORK_SERVER_ADDED "network-server-added"

#endif  /* NM_BLUEZ_COMMON_H */
