/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2008 - 2012 Red Hat, Inc.
 * Copyright (C) 2008 Novell, Inc.
 */

#ifndef __NM_DEVICE_BT_H__
#define __NM_DEVICE_BT_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_BT (nm_device_bt_get_type())
#define NM_DEVICE_BT(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DEVICE_BT, NMDeviceBt))
#define NM_DEVICE_BT_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DEVICE_BT, NMDeviceBtClass))
#define NM_IS_DEVICE_BT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DEVICE_BT))
#define NM_IS_DEVICE_BT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DEVICE_BT))
#define NM_DEVICE_BT_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DEVICE_BT, NMDeviceBtClass))

#define NM_DEVICE_BT_HW_ADDRESS   "hw-address"
#define NM_DEVICE_BT_NAME         "name"
#define NM_DEVICE_BT_CAPABILITIES "bt-capabilities"

/**
 * NMDeviceBt:
 */
typedef struct _NMDeviceBtClass NMDeviceBtClass;

GType nm_device_bt_get_type(void);

NM_DEPRECATED_IN_1_24_FOR(nm_device_get_hw_address)
const char *nm_device_bt_get_hw_address(NMDeviceBt *device);

const char *nm_device_bt_get_name(NMDeviceBt *device);

NMBluetoothCapabilities nm_device_bt_get_capabilities(NMDeviceBt *device);

G_END_DECLS

#endif /* __NM_DEVICE_BT_H__ */
