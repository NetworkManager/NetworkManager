// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_TUN_H__
#define __NETWORKMANAGER_DEVICE_TUN_H__

#include "nm-device-generic.h"

#define NM_TYPE_DEVICE_TUN            (nm_device_tun_get_type ())
#define NM_DEVICE_TUN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_TUN, NMDeviceTun))
#define NM_DEVICE_TUN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE_TUN, NMDeviceTunClass))
#define NM_IS_DEVICE_TUN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_TUN))
#define NM_IS_DEVICE_TUN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE_TUN))
#define NM_DEVICE_TUN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE_TUN, NMDeviceTunClass))

#define NM_DEVICE_TUN_OWNER       "owner"
#define NM_DEVICE_TUN_GROUP       "group"
#define NM_DEVICE_TUN_MODE        "mode"
#define NM_DEVICE_TUN_NO_PI       "no-pi"
#define NM_DEVICE_TUN_VNET_HDR    "vnet-hdr"
#define NM_DEVICE_TUN_MULTI_QUEUE "multi-queue"

typedef struct _NMDeviceTun NMDeviceTun;
typedef struct _NMDeviceTunClass NMDeviceTunClass;

GType nm_device_tun_get_type (void);

#endif /* __NETWORKMANAGER_DEVICE_TUN_H__ */
