/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2011 - 2012 Red Hat, Inc.
 */

#ifndef __NM_DEVICE_INFINIBAND_H__
#define __NM_DEVICE_INFINIBAND_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_INFINIBAND (nm_device_infiniband_get_type())
#define NM_DEVICE_INFINIBAND(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DEVICE_INFINIBAND, NMDeviceInfiniband))
#define NM_DEVICE_INFINIBAND_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DEVICE_INFINIBAND, NMDeviceInfinibandClass))
#define NM_IS_DEVICE_INFINIBAND(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DEVICE_INFINIBAND))
#define NM_IS_DEVICE_INFINIBAND_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DEVICE_INFINIBAND))
#define NM_DEVICE_INFINIBAND_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DEVICE_INFINIBAND, NMDeviceInfinibandClass))

#define NM_DEVICE_INFINIBAND_HW_ADDRESS "hw-address"
#define NM_DEVICE_INFINIBAND_CARRIER    "carrier"

/**
 * NMDeviceInfiniband:
 */
typedef struct _NMDeviceInfiniband      NMDeviceInfiniband;
typedef struct _NMDeviceInfinibandClass NMDeviceInfinibandClass;

GType nm_device_infiniband_get_type(void);

NM_DEPRECATED_IN_1_24_FOR(nm_device_get_hw_address)
const char *nm_device_infiniband_get_hw_address(NMDeviceInfiniband *device);

gboolean nm_device_infiniband_get_carrier(NMDeviceInfiniband *device);

G_END_DECLS

#endif /* __NM_DEVICE_INFINIBAND_H__ */
