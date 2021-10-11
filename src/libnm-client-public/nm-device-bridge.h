/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2012 Red Hat, Inc.
 */

#ifndef __NM_DEVICE_BRIDGE_H__
#define __NM_DEVICE_BRIDGE_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_BRIDGE (nm_device_bridge_get_type())
#define NM_DEVICE_BRIDGE(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DEVICE_BRIDGE, NMDeviceBridge))
#define NM_DEVICE_BRIDGE_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DEVICE_BRIDGE, NMDeviceBridgeClass))
#define NM_IS_DEVICE_BRIDGE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DEVICE_BRIDGE))
#define NM_IS_DEVICE_BRIDGE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DEVICE_BRIDGE))
#define NM_DEVICE_BRIDGE_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DEVICE_BRIDGE, NMDeviceBridgeClass))

#define NM_DEVICE_BRIDGE_HW_ADDRESS "hw-address"
#define NM_DEVICE_BRIDGE_CARRIER    "carrier"
#define NM_DEVICE_BRIDGE_SLAVES     "slaves"

/**
 * NMDeviceBridge:
 */
typedef struct _NMDeviceBridgeClass NMDeviceBridgeClass;

GType nm_device_bridge_get_type(void);

NM_DEPRECATED_IN_1_24_FOR(nm_device_get_hw_address)
const char *nm_device_bridge_get_hw_address(NMDeviceBridge *device);

gboolean nm_device_bridge_get_carrier(NMDeviceBridge *device);

NM_DEPRECATED_IN_1_34_FOR(nm_device_get_ports)
const GPtrArray *nm_device_bridge_get_slaves(NMDeviceBridge *device);

G_END_DECLS

#endif /* __NM_DEVICE_BRIDGE_H__ */
