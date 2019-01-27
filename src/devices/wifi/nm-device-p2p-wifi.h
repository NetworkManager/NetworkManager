/* NetworkManager -- P2P Wi-Fi Device
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

#ifndef __NM_DEVICE_P2P_WIFI_H__
#define __NM_DEVICE_P2P_WIFI_H__

#include "devices/nm-device.h"
#include "supplicant/nm-supplicant-interface.h"

#define NM_TYPE_DEVICE_P2P_WIFI            (nm_device_p2p_wifi_get_type ())
#define NM_DEVICE_P2P_WIFI(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_P2P_WIFI, NMDeviceP2PWifi))
#define NM_DEVICE_P2P_WIFI_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE_P2P_WIFI, NMDeviceP2PWifiClass))
#define NM_IS_DEVICE_P2P_WIFI(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_P2P_WIFI))
#define NM_IS_DEVICE_P2P_WIFI_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE_P2P_WIFI))
#define NM_DEVICE_P2P_WIFI_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE_P2P_WIFI, NMDeviceP2PWifiClass))

#define NM_DEVICE_P2P_WIFI_GROUP_OWNER "group-owner"
#define NM_DEVICE_P2P_WIFI_PEERS       "peers"
#define NM_DEVICE_P2P_WIFI_GROUPS      "groups"
#define NM_DEVICE_P2P_WIFI_WFDIES      "WFDIEs"

#define NM_DEVICE_P2P_WIFI_MGMT_IFACE "mgmt-iface"


typedef struct _NMDeviceP2PWifi NMDeviceP2PWifi;
typedef struct _NMDeviceP2PWifiClass NMDeviceP2PWifiClass;

GType nm_device_p2p_wifi_get_type (void);

NMDevice* nm_device_p2p_wifi_new (NMSupplicantInterface *mgmt_iface,
                                  const char* iface);

NMSupplicantInterface * nm_device_p2p_wifi_get_mgmt_iface (NMDeviceP2PWifi *self);
void                    nm_device_p2p_wifi_set_mgmt_iface (NMDeviceP2PWifi *self,
                                                           NMSupplicantInterface  *iface);

void nm_device_p2p_wifi_remove (NMDeviceP2PWifi *self);

#endif /* __NM_DEVICE_P2P_WIFI_H__ */
