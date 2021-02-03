/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2012 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_VLAN_H__
#define __NETWORKMANAGER_DEVICE_VLAN_H__

#include "nm-device.h"

#define NM_TYPE_DEVICE_VLAN (nm_device_vlan_get_type())
#define NM_DEVICE_VLAN(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DEVICE_VLAN, NMDeviceVlan))
#define NM_DEVICE_VLAN_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DEVICE_VLAN, NMDeviceVlanClass))
#define NM_IS_DEVICE_VLAN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DEVICE_VLAN))
#define NM_IS_DEVICE_VLAN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DEVICE_VLAN))
#define NM_DEVICE_VLAN_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DEVICE_VLAN, NMDeviceVlanClass))

typedef enum {
    NM_VLAN_ERROR_CONNECTION_NOT_VLAN = 0, /*< nick=ConnectionNotVlan >*/
    NM_VLAN_ERROR_CONNECTION_INVALID,      /*< nick=ConnectionInvalid >*/
    NM_VLAN_ERROR_CONNECTION_INCOMPATIBLE, /*< nick=ConnectionIncompatible >*/
} NMVlanError;

#define NM_DEVICE_VLAN_ID "vlan-id"

typedef struct _NMDeviceVlan      NMDeviceVlan;
typedef struct _NMDeviceVlanClass NMDeviceVlanClass;

GType nm_device_vlan_get_type(void);

#endif /* __NETWORKMANAGER_DEVICE_VLAN_H__ */
