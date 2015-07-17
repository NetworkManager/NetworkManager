/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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
 * Copyright (C) 2009 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_BLUEZ_COMMON_H__
#define __NETWORKMANAGER_BLUEZ_COMMON_H__

#include "config.h"

#define BLUETOOTH_CONNECT_DUN "dun"
#define BLUETOOTH_CONNECT_NAP "nap"

#define BLUEZ_SERVICE           "org.bluez"

#define BLUEZ_MANAGER_PATH      "/"
#define OBJECT_MANAGER_INTERFACE "org.freedesktop.DBus.ObjectManager"

#define BLUEZ5_ADAPTER_INTERFACE "org.bluez.Adapter1"
#define BLUEZ5_DEVICE_INTERFACE  "org.bluez.Device1"
#define BLUEZ5_NETWORK_INTERFACE "org.bluez.Network1"

#define BLUEZ4_MANAGER_INTERFACE "org.bluez.Manager"
#define BLUEZ4_ADAPTER_INTERFACE "org.bluez.Adapter"
#define BLUEZ4_DEVICE_INTERFACE  "org.bluez.Device"
#define BLUEZ4_SERIAL_INTERFACE  "org.bluez.Serial"
#define BLUEZ4_NETWORK_INTERFACE "org.bluez.Network"

#endif  /* NM_BLUEZ_COMMON_H */

