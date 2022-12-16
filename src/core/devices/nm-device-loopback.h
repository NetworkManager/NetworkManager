/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2022 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_LOOPBACK_H__
#define __NETWORKMANAGER_DEVICE_LOOPBACK_H__

#include "nm-device-generic.h"

#define NM_TYPE_DEVICE_LOOPBACK (nm_device_loopback_get_type())
#define NM_DEVICE_LOOPBACK(obj) \
    (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DEVICE_LOOPBACK, NMDeviceLoopback))
#define NM_DEVICE_LOOPBACK_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DEVICE_LOOPBACK, NMDeviceLoopbackClass))
#define NM_IS_DEVICE_LOOPBACK(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DEVICE_LOOPBACK))
#define NM_IS_DEVICE_LOOPBACK_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DEVICE_LOOPBACK))
#define NM_DEVICE_LOOPBACK_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DEVICE_LOOPBACK, NMDeviceLoopbackClass))

typedef struct _NMDeviceLoopback      NMDeviceLoopback;
typedef struct _NMDeviceLoopbackClass NMDeviceLoopbackClass;

GType nm_device_loopback_get_type(void);

#endif /* __NETWORKMANAGER_DEVICE_LOOPBACK_H__ */
