/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2009 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_BT_H__
#define __NETWORKMANAGER_DEVICE_BT_H__

#include "nm-device.h"
#include "nm-bluez-device.h"
#include "nm-modem.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_BT		(nm_device_bt_get_type ())
#define NM_DEVICE_BT(obj)		(G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_BT, NMDeviceBt))
#define NM_DEVICE_BT_CLASS(klass)	(G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE_BT, NMDeviceBtClass))
#define NM_IS_DEVICE_BT(obj)		(G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_BT))
#define NM_IS_DEVICE_BT_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE_BT))
#define NM_DEVICE_BT_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE_BT, NMDeviceBtClass))

#define NM_DEVICE_BT_NAME         "name"
#define NM_DEVICE_BT_CAPABILITIES "bt-capabilities"
#define NM_DEVICE_BT_DEVICE       "bt-device"

typedef struct {
	NMDevice parent;
} NMDeviceBt;

typedef struct {
	NMDeviceClass parent;

	/* Signals */
	void (*ppp_stats) (NMDeviceBt *device, guint32 in_bytes, guint32 out_bytes);
} NMDeviceBtClass;

GType nm_device_bt_get_type (void);

NMDevice *nm_device_bt_new (NMBluezDevice *bt_device,
                            const char *udi,
                            const char *bdaddr,
                            const char *name,
                            guint32 capabilities);

guint32 nm_device_bt_get_capabilities (NMDeviceBt *device);

gboolean nm_device_bt_modem_added (NMDeviceBt *device,
                                   NMModem *modem,
                                   const char *driver);

G_END_DECLS

#endif /* __NETWORKMANAGER_DEVICE_BT_H__ */
