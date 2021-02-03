/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2009 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_BT_H__
#define __NETWORKMANAGER_DEVICE_BT_H__

#include "devices/nm-device.h"

#define NM_TYPE_DEVICE_BT (nm_device_bt_get_type())
#define NM_DEVICE_BT(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DEVICE_BT, NMDeviceBt))
#define NM_DEVICE_BT_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DEVICE_BT, NMDeviceBtClass))
#define NM_IS_DEVICE_BT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DEVICE_BT))
#define NM_IS_DEVICE_BT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DEVICE_BT))
#define NM_DEVICE_BT_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DEVICE_BT, NMDeviceBtClass))

#define NM_DEVICE_BT_BDADDR       "bt-bdaddr"
#define NM_DEVICE_BT_BZ_MGR       "bt-bz-mgr"
#define NM_DEVICE_BT_CAPABILITIES "bt-capabilities"
#define NM_DEVICE_BT_DBUS_PATH    "bt-dbus-path"
#define NM_DEVICE_BT_NAME         "bt-name"

#define NM_DEVICE_BT_PPP_STATS "ppp-stats"

typedef struct _NMDeviceBt      NMDeviceBt;
typedef struct _NMDeviceBtClass NMDeviceBtClass;

GType nm_device_bt_get_type(void);

struct _NMBluezManager;

NMDeviceBt *nm_device_bt_new(struct _NMBluezManager *bz_mgr,
                             const char *            dbus_path,
                             const char *            bdaddr,
                             const char *            name,
                             NMBluetoothCapabilities capabilities);

gboolean _nm_device_bt_for_same_device(NMDeviceBt *            device,
                                       const char *            dbus_path,
                                       const char *            bdaddr,
                                       const char *            name,
                                       NMBluetoothCapabilities capabilities);

NMBluetoothCapabilities nm_device_bt_get_capabilities(NMDeviceBt *device);

struct _NMModem;

gboolean nm_device_bt_modem_added(NMDeviceBt *device, struct _NMModem *modem, const char *driver);

void _nm_device_bt_notify_removed(NMDeviceBt *self);

void _nm_device_bt_notify_set_name(NMDeviceBt *self, const char *name);

void _nm_device_bt_notify_set_connected(NMDeviceBt *self, gboolean connected);

#endif /* __NETWORKMANAGER_DEVICE_BT_H__ */
