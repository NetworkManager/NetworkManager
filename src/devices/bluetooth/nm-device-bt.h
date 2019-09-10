// SPDX-License-Identifier: GPL-2.0+
/* NetworkManager -- Network link manager
 *
 * Copyright (C) 2009 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_BT_H__
#define __NETWORKMANAGER_DEVICE_BT_H__

#include "devices/nm-device.h"
#include "nm-bluez-device.h"

#define NM_TYPE_DEVICE_BT                   (nm_device_bt_get_type ())
#define NM_DEVICE_BT(obj)                   (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_BT, NMDeviceBt))
#define NM_DEVICE_BT_CLASS(klass)           (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE_BT, NMDeviceBtClass))
#define NM_IS_DEVICE_BT(obj)                (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_BT))
#define NM_IS_DEVICE_BT_CLASS(klass)        (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE_BT))
#define NM_DEVICE_BT_GET_CLASS(obj)         (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE_BT, NMDeviceBtClass))

#define NM_DEVICE_BT_NAME         "name"
#define NM_DEVICE_BT_CAPABILITIES "bt-capabilities"
#define NM_DEVICE_BT_DEVICE       "bt-device"

#define NM_DEVICE_BT_PPP_STATS    "ppp-stats"

typedef struct _NMDeviceBt NMDeviceBt;
typedef struct _NMDeviceBtClass NMDeviceBtClass;

GType nm_device_bt_get_type (void);

NMDevice *nm_device_bt_new (NMBluezDevice *bt_device,
                            const char *udi,
                            const char *bdaddr,
                            const char *name,
                            guint32 capabilities);

guint32 nm_device_bt_get_capabilities (NMDeviceBt *device);

struct _NMModem;

gboolean nm_device_bt_modem_added (NMDeviceBt *device,
                                   struct _NMModem *modem,
                                   const char *driver);

#endif /* __NETWORKMANAGER_DEVICE_BT_H__ */
