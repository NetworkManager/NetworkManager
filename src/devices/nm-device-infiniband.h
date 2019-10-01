// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2011 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_INFINIBAND_H__
#define __NETWORKMANAGER_DEVICE_INFINIBAND_H__

#include "nm-device.h"

#define NM_TYPE_DEVICE_INFINIBAND               (nm_device_infiniband_get_type ())
#define NM_DEVICE_INFINIBAND(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_INFINIBAND, NMDeviceInfiniband))
#define NM_DEVICE_INFINIBAND_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE_INFINIBAND, NMDeviceInfinibandClass))
#define NM_IS_DEVICE_INFINIBAND(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_INFINIBAND))
#define NM_IS_DEVICE_INFINIBAND_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE_INFINIBAND))
#define NM_DEVICE_INFINIBAND_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE_INFINIBAND, NMDeviceInfinibandClass))

typedef struct _NMDeviceInfiniband NMDeviceInfiniband;
typedef struct _NMDeviceInfinibandClass NMDeviceInfinibandClass;

GType nm_device_infiniband_get_type (void);

#endif /* __NETWORKMANAGER_DEVICE_INFINIBAND_H__ */
