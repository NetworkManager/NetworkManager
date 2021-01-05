/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_MACVLAN_H__
#define __NETWORKMANAGER_DEVICE_MACVLAN_H__

#include "nm-device.h"

#define NM_TYPE_DEVICE_MACVLAN (nm_device_macvlan_get_type())
#define NM_DEVICE_MACVLAN(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DEVICE_MACVLAN, NMDeviceMacvlan))
#define NM_DEVICE_MACVLAN_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DEVICE_MACVLAN, NMDeviceMacvlanClass))
#define NM_IS_DEVICE_MACVLAN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DEVICE_MACVLAN))
#define NM_IS_DEVICE_MACVLAN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DEVICE_MACVLAN))
#define NM_DEVICE_MACVLAN_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DEVICE_MACVLAN, NMDeviceMacvlanClass))

#define NM_DEVICE_MACVLAN_MODE       "mode"
#define NM_DEVICE_MACVLAN_NO_PROMISC "no-promisc"
#define NM_DEVICE_MACVLAN_TAP        "tap"

typedef struct _NMDeviceMacvlan      NMDeviceMacvlan;
typedef struct _NMDeviceMacvlanClass NMDeviceMacvlanClass;

GType nm_device_macvlan_get_type(void);

#endif /* __NETWORKMANAGER_DEVICE_MACVLAN_H__ */
