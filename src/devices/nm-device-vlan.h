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
 * Copyright 2012 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_VLAN_H__
#define __NETWORKMANAGER_DEVICE_VLAN_H__

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_VLAN            (nm_device_vlan_get_type ())
#define NM_DEVICE_VLAN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_VLAN, NMDeviceVlan))
#define NM_DEVICE_VLAN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE_VLAN, NMDeviceVlanClass))
#define NM_IS_DEVICE_VLAN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_VLAN))
#define NM_IS_DEVICE_VLAN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE_VLAN))
#define NM_DEVICE_VLAN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE_VLAN, NMDeviceVlanClass))

typedef enum {
	NM_VLAN_ERROR_CONNECTION_NOT_VLAN = 0, /*< nick=ConnectionNotVlan >*/
	NM_VLAN_ERROR_CONNECTION_INVALID,      /*< nick=ConnectionInvalid >*/
	NM_VLAN_ERROR_CONNECTION_INCOMPATIBLE, /*< nick=ConnectionIncompatible >*/
} NMVlanError;

/* D-Bus exported properties */
#define NM_DEVICE_VLAN_PARENT     "parent"
#define NM_DEVICE_VLAN_ID         "vlan-id"

/* Internal non-exported properties */
#define NM_DEVICE_VLAN_INT_PARENT_DEVICE     "int-parent-device"

typedef NMDevice NMDeviceVlan;
typedef NMDeviceClass NMDeviceVlanClass;

GType nm_device_vlan_get_type (void);

G_END_DECLS

#endif	/* NM_DEVICE_VLAN_H */
