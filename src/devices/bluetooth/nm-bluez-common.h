// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_BLUEZ_COMMON_H__
#define __NETWORKMANAGER_BLUEZ_COMMON_H__

#define BLUETOOTH_CONNECT_DUN "dun"
#define BLUETOOTH_CONNECT_NAP "nap"

#define NM_BLUEZ_SERVICE           "org.bluez"

#define NM_BLUEZ_MANAGER_PATH      "/"

#define NM_BLUEZ5_ADAPTER_INTERFACE "org.bluez.Adapter1"
#define NM_BLUEZ5_DEVICE_INTERFACE  "org.bluez.Device1"
#define NM_BLUEZ5_NETWORK_INTERFACE "org.bluez.Network1"
#define NM_BLUEZ5_NETWORK_SERVER_INTERFACE "org.bluez.NetworkServer1"

#define NM_BLUEZ_MANAGER_BDADDR_ADDED "bdaddr-added"
#define NM_BLUEZ_MANAGER_NETWORK_SERVER_ADDED "network-server-added"

#endif  /* NM_BLUEZ_COMMON_H */
