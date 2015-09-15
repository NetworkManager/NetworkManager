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
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_TUN_H__
#define __NETWORKMANAGER_DEVICE_TUN_H__

#include "nm-device-generic.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_TUN            (nm_device_tun_get_type ())
#define NM_DEVICE_TUN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_TUN, NMDeviceTun))
#define NM_DEVICE_TUN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE_TUN, NMDeviceTunClass))
#define NM_IS_DEVICE_TUN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_TUN))
#define NM_IS_DEVICE_TUN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE_TUN))
#define NM_DEVICE_TUN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE_TUN, NMDeviceTunClass))

#define NM_DEVICE_TUN_OWNER       "owner"
#define NM_DEVICE_TUN_GROUP       "group"
#define NM_DEVICE_TUN_MODE        "mode"
#define NM_DEVICE_TUN_NO_PI       "no-pi"
#define NM_DEVICE_TUN_VNET_HDR    "vnet-hdr"
#define NM_DEVICE_TUN_MULTI_QUEUE "multi-queue"

typedef NMDevice NMDeviceTun;
typedef NMDeviceClass NMDeviceTunClass;

GType nm_device_tun_get_type (void);

G_END_DECLS

#endif	/* NM_DEVICE_TUN_H */
