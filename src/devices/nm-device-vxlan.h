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
 * Copyright 2013, 2014 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_VXLAN_H__
#define __NETWORKMANAGER_DEVICE_VXLAN_H__

#include "nm-device-generic.h"

#define NM_TYPE_DEVICE_VXLAN            (nm_device_vxlan_get_type ())
#define NM_DEVICE_VXLAN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_VXLAN, NMDeviceVxlan))
#define NM_DEVICE_VXLAN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE_VXLAN, NMDeviceVxlanClass))
#define NM_IS_DEVICE_VXLAN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_VXLAN))
#define NM_IS_DEVICE_VXLAN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE_VXLAN))
#define NM_DEVICE_VXLAN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE_VXLAN, NMDeviceVxlanClass))

#define NM_DEVICE_VXLAN_ID           "id"
#define NM_DEVICE_VXLAN_GROUP        "group"
#define NM_DEVICE_VXLAN_LOCAL        "local"
#define NM_DEVICE_VXLAN_TOS          "tos"
#define NM_DEVICE_VXLAN_TTL          "ttl"
#define NM_DEVICE_VXLAN_LEARNING     "learning"
#define NM_DEVICE_VXLAN_AGEING       "ageing"
#define NM_DEVICE_VXLAN_LIMIT        "limit"
#define NM_DEVICE_VXLAN_DST_PORT     "dst-port"
#define NM_DEVICE_VXLAN_SRC_PORT_MIN "src-port-min"
#define NM_DEVICE_VXLAN_SRC_PORT_MAX "src-port-max"
#define NM_DEVICE_VXLAN_PROXY        "proxy"
#define NM_DEVICE_VXLAN_RSC          "rsc"
#define NM_DEVICE_VXLAN_L2MISS       "l2miss"
#define NM_DEVICE_VXLAN_L3MISS       "l3miss"

typedef struct _NMDeviceVxlan NMDeviceVxlan;
typedef struct _NMDeviceVxlanClass NMDeviceVxlanClass;

GType nm_device_vxlan_get_type (void);

#endif /* __NETWORKMANAGER_DEVICE_VXLAN_H__ */
