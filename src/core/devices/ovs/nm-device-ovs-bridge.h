/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_OVS_BRIDGE_H__
#define __NETWORKMANAGER_DEVICE_OVS_BRIDGE_H__

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

typedef struct _NMDeviceOvsBridge      NMDeviceOvsBridge;
typedef struct _NMDeviceOvsBridgeClass NMDeviceOvsBridgeClass;

GType nm_device_ovs_bridge_get_type(void);

/*****************************************************************************/

void
nm_device_ovs_reapply_connection(NMDevice *device, NMConnection *con_old, NMConnection *con_new);

#endif /* __NETWORKMANAGER_DEVICE_OVS_BRIDGE_H__ */
