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

#ifndef __NETWORKMANAGER_DEVICE_VETH_H__
#define __NETWORKMANAGER_DEVICE_VETH_H__

#include "nm-device-ethernet.h"

#define NM_TYPE_DEVICE_VETH            (nm_device_veth_get_type ())
#define NM_DEVICE_VETH(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_VETH, NMDeviceVeth))
#define NM_DEVICE_VETH_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE_VETH, NMDeviceVethClass))
#define NM_IS_DEVICE_VETH(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_VETH))
#define NM_IS_DEVICE_VETH_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE_VETH))
#define NM_DEVICE_VETH_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE_VETH, NMDeviceVethClass))

#define NM_DEVICE_VETH_PEER "peer"

typedef struct _NMDeviceVeth NMDeviceVeth;
typedef struct _NMDeviceVethClass NMDeviceVethClass;

GType nm_device_veth_get_type (void);

#endif /* __NETWORKMANAGER_DEVICE_VETH_H__ */
