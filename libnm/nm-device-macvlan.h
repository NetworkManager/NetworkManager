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
 * Copyright 2015 Red Hat, Inc.
 */

#ifndef __NM_DEVICE_MACVLAN_H__
#define __NM_DEVICE_MACVLAN_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_MACVLAN            (nm_device_macvlan_get_type ())
#define NM_DEVICE_MACVLAN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_MACVLAN, NMDeviceMacvlan))
#define NM_DEVICE_MACVLAN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DEVICE_MACVLAN, NMDeviceMacvlanClass))
#define NM_IS_DEVICE_MACVLAN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_MACVLAN))
#define NM_IS_DEVICE_MACVLAN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DEVICE_MACVLAN))
#define NM_DEVICE_MACVLAN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DEVICE_MACVLAN, NMDeviceMacvlanClass))

#define NM_DEVICE_MACVLAN_PARENT      "parent"
#define NM_DEVICE_MACVLAN_MODE        "mode"
#define NM_DEVICE_MACVLAN_NO_PROMISC  "no-promisc"
#define NM_DEVICE_MACVLAN_TAP         "tap"
#define NM_DEVICE_MACVLAN_HW_ADDRESS  "hw-address"

/**
 * NMDeviceMacvlan:
 */
struct _NMDeviceMacvlan {
	NMDevice parent;
};

typedef struct {
	NMDeviceClass parent;

	/*< private >*/
	gpointer padding[4];
} NMDeviceMacvlanClass;

NM_AVAILABLE_IN_1_2
GType nm_device_macvlan_get_type (void);

NM_AVAILABLE_IN_1_2
NMDevice *   nm_device_macvlan_get_parent      (NMDeviceMacvlan *device);
NM_AVAILABLE_IN_1_2
const char * nm_device_macvlan_get_mode        (NMDeviceMacvlan *device);
NM_AVAILABLE_IN_1_2
gboolean     nm_device_macvlan_get_no_promisc  (NMDeviceMacvlan *device);
NM_AVAILABLE_IN_1_2
gboolean     nm_device_macvlan_get_tap         (NMDeviceMacvlan *device);
NM_AVAILABLE_IN_1_2
const char * nm_device_macvlan_get_hw_address  (NMDeviceMacvlan *device);

G_END_DECLS

#endif /* __NM_DEVICE_MACVLAN_H__ */
