/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#ifndef __NM_DEVICE_OVS_INTERFACE_H__
#define __NM_DEVICE_OVS_INTERFACE_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_OVS_INTERFACE (nm_device_ovs_interface_get_type())
#define NM_DEVICE_OVS_INTERFACE(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DEVICE_OVS_INTERFACE, NMDeviceOvsInterface))
#define NM_DEVICE_OVS_INTERFACE_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DEVICE_OVS_INTERFACE, NMDeviceOvsInterfaceClass))
#define NM_IS_DEVICE_OVS_INTERFACE(obj) \
    (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DEVICE_OVS_INTERFACE))
#define NM_IS_DEVICE_OVS_INTERFACE_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DEVICE_OVS_INTERFACE))
#define NM_DEVICE_OVS_INTERFACE_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DEVICE_OVS_INTERFACE, NMDeviceOvsInterfaceClass))

/**
 * NMDeviceOvsInterface:
 */
typedef struct _NMDeviceOvsInterfaceClass NMDeviceOvsInterfaceClass;

NM_AVAILABLE_IN_1_10
GType nm_device_ovs_interface_get_type(void);

G_END_DECLS

#endif /* __NM_DEVICE_OVS_INTERFACE_H__ */
