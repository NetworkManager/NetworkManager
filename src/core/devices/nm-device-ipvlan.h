/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2024 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_IPVLAN_H__
#define __NETWORKMANAGER_DEVICE_IPVLAN_H__

#include "nm-device.h"

#define NM_TYPE_DEVICE_IPVLAN (nm_device_ipvlan_get_type())
#define NM_DEVICE_IPVLAN(obj) \
    (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DEVICE_IPVLAN, NMDeviceIpvlan))
#define NM_DEVICE_IPVLAN_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DEVICE_IPVLAN, NMDeviceIpvlanClass))
#define NM_IS_DEVICE_IPVLAN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DEVICE_IPVLAN))
#define NM_IS_DEVICE_IPVLAN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DEVICE_IPVLAN))
#define NM_DEVICE_IPVLAN_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DEVICE_IPVLAN, NMDeviceIpvlanClass))

#define NM_DEVICE_IPVLAN_PARENT  "parent"
#define NM_DEVICE_IPVLAN_MODE    "mode"
#define NM_DEVICE_IPVLAN_PRIVATE "private"
#define NM_DEVICE_IPVLAN_VEPA    "vepa"

typedef struct _NMDeviceIpvlan      NMDeviceIpvlan;
typedef struct _NMDeviceIpvlanClass NMDeviceIpvlanClass;

GType nm_device_ipvlan_get_type(void);

#endif /* __NETWORKMANAGER_DEVICE_IPVLAN_H__ */
