/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2021 Intel Corporation
 */

#ifndef __NM_DEVICE_IWD_P2P_H__
#define __NM_DEVICE_IWD_P2P_H__

#include "devices/nm-device.h"
#include "nm-device-wifi-p2p.h"

#define NM_TYPE_DEVICE_IWD_P2P (nm_device_iwd_p2p_get_type())
#define NM_DEVICE_IWD_P2P(obj) \
    (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DEVICE_IWD_P2P, NMDeviceIwdP2P))
#define NM_DEVICE_IWD_P2P_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DEVICE_IWD_P2P, NMDeviceIwdP2PClass))
#define NM_IS_DEVICE_IWD_P2P(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DEVICE_IWD_P2P))
#define NM_IS_DEVICE_IWD_P2P_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DEVICE_IWD_P2P))
#define NM_DEVICE_IWD_P2P_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DEVICE_IWD_P2P, NMDeviceIwdP2PClass))

#define NM_DEVICE_IWD_P2P_PEERS  NM_DEVICE_WIFI_P2P_PEERS
#define NM_DEVICE_IWD_P2P_GROUPS NM_DEVICE_WIFI_P2P_GROUPS

typedef struct _NMDeviceIwdP2P      NMDeviceIwdP2P;
typedef struct _NMDeviceIwdP2PClass NMDeviceIwdP2PClass;

GType nm_device_iwd_p2p_get_type(void);

NMDeviceIwdP2P *nm_device_iwd_p2p_new(GDBusObject *object);

void nm_device_iwd_p2p_remove(NMDeviceIwdP2P *p2p);

void nm_device_iwd_p2p_peer_add_remove(NMDeviceIwdP2P *p2p, GDBusObject *peer_obj, bool add);

#endif /* __NM_DEVICE_IWD_P2P_H__ */
