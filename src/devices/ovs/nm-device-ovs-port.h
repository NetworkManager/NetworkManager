// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2017 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_OVS_PORT_H__
#define __NETWORKMANAGER_DEVICE_OVS_PORT_H__

#define NM_TYPE_DEVICE_OVS_PORT            (nm_device_ovs_port_get_type ())
#define NM_DEVICE_OVS_PORT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_OVS_PORT, NMDeviceOvsPort))
#define NM_DEVICE_OVS_PORT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE_OVS_PORT, NMDeviceOvsPortClass))
#define NM_IS_DEVICE_OVS_PORT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_OVS_PORT))
#define NM_IS_DEVICE_OVS_PORT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE_OVS_PORT))
#define NM_DEVICE_OVS_PORT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE_OVS_PORT, NMDeviceOvsPortClass))

typedef struct _NMDeviceOvsPort NMDeviceOvsPort;
typedef struct _NMDeviceOvsPortClass NMDeviceOvsPortClass;

GType nm_device_ovs_port_get_type (void);

#endif /* __NETWORKMANAGER_DEVICE_OVS_PORT_H__ */
