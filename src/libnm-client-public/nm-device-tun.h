/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2015 Red Hat, Inc.
 */

#ifndef __NM_DEVICE_TUN_H__
#define __NM_DEVICE_TUN_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_TUN (nm_device_tun_get_type())
#define NM_DEVICE_TUN(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DEVICE_TUN, NMDeviceTun))
#define NM_DEVICE_TUN_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DEVICE_TUN, NMDeviceTunClass))
#define NM_IS_DEVICE_TUN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DEVICE_TUN))
#define NM_IS_DEVICE_TUN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DEVICE_TUN))
#define NM_DEVICE_TUN_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DEVICE_TUN, NMDeviceTunClass))

#define NM_DEVICE_TUN_HW_ADDRESS  "hw-address"
#define NM_DEVICE_TUN_OWNER       "owner"
#define NM_DEVICE_TUN_GROUP       "group"
#define NM_DEVICE_TUN_MODE        "mode"
#define NM_DEVICE_TUN_NO_PI       "no-pi"
#define NM_DEVICE_TUN_VNET_HDR    "vnet-hdr"
#define NM_DEVICE_TUN_MULTI_QUEUE "multi-queue"

/**
 * NMDeviceTun:
 */
typedef struct _NMDeviceTunClass NMDeviceTunClass;

NM_AVAILABLE_IN_1_2
GType nm_device_tun_get_type(void);

NM_AVAILABLE_IN_1_2
NM_DEPRECATED_IN_1_24_FOR(nm_device_get_hw_address)
const char *nm_device_tun_get_hw_address(NMDeviceTun *device);

NM_AVAILABLE_IN_1_2
const char *nm_device_tun_get_mode(NMDeviceTun *device);
NM_AVAILABLE_IN_1_2
gint64 nm_device_tun_get_owner(NMDeviceTun *device);
NM_AVAILABLE_IN_1_2
gint64 nm_device_tun_get_group(NMDeviceTun *device);
NM_AVAILABLE_IN_1_2
gboolean nm_device_tun_get_no_pi(NMDeviceTun *device);
NM_AVAILABLE_IN_1_2
gboolean nm_device_tun_get_vnet_hdr(NMDeviceTun *device);
NM_AVAILABLE_IN_1_2
gboolean nm_device_tun_get_multi_queue(NMDeviceTun *device);

G_END_DECLS

#endif /* __NM_DEVICE_TUN_H__ */
