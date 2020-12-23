/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2012 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_BOND_H__
#define __NETWORKMANAGER_DEVICE_BOND_H__

#include "nm-device.h"

#define NM_TYPE_DEVICE_BOND (nm_device_bond_get_type())
#define NM_DEVICE_BOND(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DEVICE_BOND, NMDeviceBond))
#define NM_DEVICE_BOND_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DEVICE_BOND, NMDeviceBondClass))
#define NM_IS_DEVICE_BOND(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DEVICE_BOND))
#define NM_IS_DEVICE_BOND_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DEVICE_BOND))
#define NM_DEVICE_BOND_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DEVICE_BOND, NMDeviceBondClass))

typedef struct _NMDeviceBond      NMDeviceBond;
typedef struct _NMDeviceBondClass NMDeviceBondClass;

GType nm_device_bond_get_type(void);

#endif /* NM_DEVICE_BOND_H */
