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
 * Copyright 2017 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_OVS_INTERFACE_H__
#define __NETWORKMANAGER_DEVICE_OVS_INTERFACE_H__

#define NM_TYPE_DEVICE_OVS_INTERFACE            (nm_device_ovs_interface_get_type ())
#define NM_DEVICE_OVS_INTERFACE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_OVS_INTERFACE, NMDeviceOvsInterface))
#define NM_DEVICE_OVS_INTERFACE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE_OVS_INTERFACE, NMDeviceOvsInterfaceClass))
#define NM_IS_DEVICE_OVS_INTERFACE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_OVS_INTERFACE))
#define NM_IS_DEVICE_OVS_INTERFACE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE_OVS_INTERFACE))
#define NM_DEVICE_OVS_INTERFACE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE_OVS_INTERFACE, NMDeviceOvsInterfaceClass))

typedef struct _NMDeviceOvsInterface NMDeviceOvsInterface;
typedef struct _NMDeviceOvsInterfaceClass NMDeviceOvsInterfaceClass;

GType nm_device_ovs_interface_get_type (void);

#endif /* __NETWORKMANAGER_DEVICE_OVS_INTERFACE_H__ */
