/*
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
 * Copyright 2018 - 2019 Red Hat, Inc.
 */

#ifndef __NM_DEVICE_WIFI_P2P_H__
#define __NM_DEVICE_WIFI_P2P_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_WIFI_P2P            (nm_device_wifi_p2p_get_type ())
#define NM_DEVICE_WIFI_P2P(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_WIFI_P2P, NMDeviceWifiP2P))
#define NM_DEVICE_WIFI_P2P_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DEVICE_WIFI_P2P, NMDeviceWifiP2PClass))
#define NM_IS_DEVICE_WIFI_P2P(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_WIFI_P2P))
#define NM_IS_DEVICE_WIFI_P2P_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DEVICE_WIFI_P2P))
#define NM_DEVICE_WIFI_P2P_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DEVICE_WIFI_P2P, NMDeviceWifiP2PClass))

#define NM_DEVICE_WIFI_P2P_HW_ADDRESS          "hw-address"
#define NM_DEVICE_WIFI_P2P_PEERS               "peers"
#define NM_DEVICE_WIFI_P2P_WFDIES              "wfdies"

typedef struct _NMDeviceWifiP2PClass NMDeviceWifiP2PClass;

NM_AVAILABLE_IN_1_16
GType nm_device_wifi_p2p_get_type (void);

NM_AVAILABLE_IN_1_16
const char *             nm_device_wifi_p2p_get_hw_address   (NMDeviceWifiP2P *device);

NM_AVAILABLE_IN_1_16
NMWifiP2PPeer *          nm_device_wifi_p2p_get_peer_by_path (NMDeviceWifiP2P *device,
                                                              const char *path);

NM_AVAILABLE_IN_1_16
const GPtrArray *        nm_device_wifi_p2p_get_peers        (NMDeviceWifiP2P *device);

NM_AVAILABLE_IN_1_16
void                     nm_device_wifi_p2p_start_find        (NMDeviceWifiP2P     *device,
                                                               GVariant            *options,
                                                               GCancellable        *cancellable,
                                                               GAsyncReadyCallback  callback,
                                                               gpointer             user_data);
NM_AVAILABLE_IN_1_16
gboolean                 nm_device_wifi_p2p_start_find_finish (NMDeviceWifiP2P     *device,
                                                               GAsyncResult        *result,
                                                               GError             **error);

NM_AVAILABLE_IN_1_16
void                     nm_device_wifi_p2p_stop_find         (NMDeviceWifiP2P     *device,
                                                               GCancellable        *cancellable,
                                                               GAsyncReadyCallback  callback,
                                                               gpointer             user_data);
NM_AVAILABLE_IN_1_16
gboolean                 nm_device_wifi_p2p_stop_find_finish  (NMDeviceWifiP2P     *device,
                                                               GAsyncResult        *result,
                                                               GError             **error);

G_END_DECLS

#endif /* __NM_DEVICE_WIFI_P2P_H__ */
