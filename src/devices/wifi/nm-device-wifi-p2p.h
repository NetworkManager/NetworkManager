/* NetworkManager -- Wi-Fi P2P Device
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2018 Red Hat, Inc.
 */

#ifndef __NM_DEVICE_WIFI_P2P_H__
#define __NM_DEVICE_WIFI_P2P_H__

#include "devices/nm-device.h"
#include "supplicant/nm-supplicant-interface.h"

#define NM_TYPE_DEVICE_WIFI_P2P            (nm_device_wifi_p2p_get_type ())
#define NM_DEVICE_WIFI_P2P(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_WIFI_P2P, NMDeviceWifiP2P))
#define NM_DEVICE_WIFI_P2P_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE_WIFI_P2P, NMDeviceWifiP2PClass))
#define NM_IS_DEVICE_WIFI_P2P(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_WIFI_P2P))
#define NM_IS_DEVICE_WIFI_P2P_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE_WIFI_P2P))
#define NM_DEVICE_WIFI_P2P_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE_WIFI_P2P, NMDeviceWifiP2PClass))

#define NM_DEVICE_WIFI_P2P_PEERS       "peers"
#define NM_DEVICE_WIFI_P2P_GROUPS      "groups"

typedef struct _NMDeviceWifiP2P NMDeviceWifiP2P;
typedef struct _NMDeviceWifiP2PClass NMDeviceWifiP2PClass;

GType nm_device_wifi_p2p_get_type (void);

NMDeviceWifiP2P *nm_device_wifi_p2p_new (const char *iface);

NMSupplicantInterface * nm_device_wifi_p2p_get_mgmt_iface (NMDeviceWifiP2P *self);
void                    nm_device_wifi_p2p_set_mgmt_iface (NMDeviceWifiP2P *self,
                                                           NMSupplicantInterface  *iface);

void nm_device_wifi_p2p_remove (NMDeviceWifiP2P *self);

#endif /* __NM_DEVICE_WIFI_P2P_H__ */
