/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2017, 2018 Red Hat, Inc.
 */

#ifndef __NM_DEVICE_OVS_BRIDGE_H__
#define __NM_DEVICE_OVS_BRIDGE_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_OVS_BRIDGE (nm_device_ovs_bridge_get_type())
#define NM_DEVICE_OVS_BRIDGE(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DEVICE_OVS_BRIDGE, NMDeviceOvsBridge))
#define NM_DEVICE_OVS_BRIDGE_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DEVICE_OVS_BRIDGE, NMDeviceOvsBridgeClass))
#define NM_IS_DEVICE_OVS_BRIDGE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DEVICE_OVS_BRIDGE))
#define NM_IS_DEVICE_OVS_BRIDGE_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DEVICE_OVS_BRIDGE))
#define NM_DEVICE_OVS_BRIDGE_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DEVICE_OVS_BRIDGE, NMDeviceOvsBridgeClass))

#define NM_DEVICE_OVS_BRIDGE_SLAVES "slaves"

/**
 * NMDeviceOvsBridge:
 */
typedef struct _NMDeviceOvsBridgeClass NMDeviceOvsBridgeClass;

NM_AVAILABLE_IN_1_10
GType nm_device_ovs_bridge_get_type(void);

NM_AVAILABLE_IN_1_14
const GPtrArray *nm_device_ovs_bridge_get_slaves(NMDeviceOvsBridge *device);

G_END_DECLS

#endif /* __NM_DEVICE_OVS_BRIDGE_H__ */
