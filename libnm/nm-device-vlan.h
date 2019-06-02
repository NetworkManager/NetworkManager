/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2012 - 2014 Red Hat, Inc.
 */

#ifndef __NM_DEVICE_VLAN_H__
#define __NM_DEVICE_VLAN_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_VLAN            (nm_device_vlan_get_type ())
#define NM_DEVICE_VLAN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_VLAN, NMDeviceVlan))
#define NM_DEVICE_VLAN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DEVICE_VLAN, NMDeviceVlanClass))
#define NM_IS_DEVICE_VLAN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_VLAN))
#define NM_IS_DEVICE_VLAN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DEVICE_VLAN))
#define NM_DEVICE_VLAN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DEVICE_VLAN, NMDeviceVlanClass))

#define NM_DEVICE_VLAN_HW_ADDRESS  "hw-address"
#define NM_DEVICE_VLAN_CARRIER     "carrier"
#define NM_DEVICE_VLAN_PARENT      "parent"
#define NM_DEVICE_VLAN_VLAN_ID     "vlan-id"

/**
 * NMDeviceVlan:
 */
struct _NMDeviceVlan {
	NMDevice parent;
};

typedef struct {
	NMDeviceClass parent;

	/*< private >*/
	gpointer padding[4];
} NMDeviceVlanClass;

GType nm_device_vlan_get_type (void);

const char * nm_device_vlan_get_hw_address (NMDeviceVlan *device);
gboolean     nm_device_vlan_get_carrier (NMDeviceVlan *device);
NMDevice *   nm_device_vlan_get_parent  (NMDeviceVlan *device);
guint        nm_device_vlan_get_vlan_id (NMDeviceVlan *device);

G_END_DECLS

#endif /* __NM_DEVICE_VLAN_H__ */
