/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2023 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_HSR_H__
#define __NETWORKMANAGER_DEVICE_HSR_H__

#include "nm-device.h"

#define NM_TYPE_DEVICE_HSR (nm_device_hsr_get_type())
#define NM_DEVICE_HSR(obj) (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DEVICE_HSR, NMDeviceHsr))
#define NM_DEVICE_HSR_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DEVICE_HSR, NMDeviceHsrClass))
#define NM_IS_DEVICE_HSR(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DEVICE_HSR))
#define NM_IS_DEVICE_HSR_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DEVICE_HSR))
#define NM_DEVICE_HSR_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DEVICE_HSR, NMDeviceHsrClass))

#define NM_DEVICE_HSR_PORT1               "port1"
#define NM_DEVICE_HSR_PORT2               "port2"
#define NM_DEVICE_HSR_SUPERVISION_ADDRESS "supervision-address"
#define NM_DEVICE_HSR_MULTICAST_SPEC      "multicast-spec"
#define NM_DEVICE_HSR_PRP                 "prp"

typedef struct _NMDeviceHsr      NMDeviceHsr;
typedef struct _NMDeviceHsrClass NMDeviceHsrClass;

GType nm_device_hsr_get_type(void);

#endif /* __NETWORKMANAGER_DEVICE_HSR_H__ */
