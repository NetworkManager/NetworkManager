/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2012 Red Hat, Inc.
 */

#ifndef __NM_DEVICE_BOND_H__
#define __NM_DEVICE_BOND_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_BOND (nm_device_bond_get_type())
#define NM_DEVICE_BOND(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DEVICE_BOND, NMDeviceBond))
#define NM_DEVICE_BOND_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DEVICE_BOND, NMDeviceBondClass))
#define NM_IS_DEVICE_BOND(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DEVICE_BOND))
#define NM_IS_DEVICE_BOND_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DEVICE_BOND))
#define NM_DEVICE_BOND_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DEVICE_BOND, NMDeviceBondClass))

#define NM_DEVICE_BOND_HW_ADDRESS "hw-address"
#define NM_DEVICE_BOND_CARRIER    "carrier"
#define NM_DEVICE_BOND_SLAVES     "slaves"

/**
 * NMDeviceBond:
 */
typedef struct _NMDeviceBondClass NMDeviceBondClass;

GType nm_device_bond_get_type(void);

NM_DEPRECATED_IN_1_24_FOR(nm_device_get_hw_address)
const char *nm_device_bond_get_hw_address(NMDeviceBond *device);

gboolean nm_device_bond_get_carrier(NMDeviceBond *device);

NM_DEPRECATED_IN_1_34_FOR(nm_device_get_ports)
const GPtrArray *nm_device_bond_get_slaves(NMDeviceBond *device);

G_END_DECLS

#endif /* __NM_DEVICE_BOND_H__ */
