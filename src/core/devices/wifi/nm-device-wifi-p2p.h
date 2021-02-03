/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2018 Red Hat, Inc.
 */

#ifndef __NM_DEVICE_WIFI_P2P_H__
#define __NM_DEVICE_WIFI_P2P_H__

#include "devices/nm-device.h"
#include "supplicant/nm-supplicant-interface.h"

#define NM_TYPE_DEVICE_WIFI_P2P (nm_device_wifi_p2p_get_type())
#define NM_DEVICE_WIFI_P2P(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DEVICE_WIFI_P2P, NMDeviceWifiP2P))
#define NM_DEVICE_WIFI_P2P_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DEVICE_WIFI_P2P, NMDeviceWifiP2PClass))
#define NM_IS_DEVICE_WIFI_P2P(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DEVICE_WIFI_P2P))
#define NM_IS_DEVICE_WIFI_P2P_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DEVICE_WIFI_P2P))
#define NM_DEVICE_WIFI_P2P_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DEVICE_WIFI_P2P, NMDeviceWifiP2PClass))

#define NM_DEVICE_WIFI_P2P_PEERS  "peers"
#define NM_DEVICE_WIFI_P2P_GROUPS "groups"

typedef struct _NMDeviceWifiP2P      NMDeviceWifiP2P;
typedef struct _NMDeviceWifiP2PClass NMDeviceWifiP2PClass;

GType nm_device_wifi_p2p_get_type(void);

NMDeviceWifiP2P *nm_device_wifi_p2p_new(const char *iface);

NMSupplicantInterface *nm_device_wifi_p2p_get_mgmt_iface(NMDeviceWifiP2P *self);
void nm_device_wifi_p2p_set_mgmt_iface(NMDeviceWifiP2P *self, NMSupplicantInterface *iface);

void nm_device_wifi_p2p_remove(NMDeviceWifiP2P *self);

#endif /* __NM_DEVICE_WIFI_P2P_H__ */
