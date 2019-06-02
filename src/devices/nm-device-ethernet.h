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
 * Copyright (C) 2005 - 2010 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_ETHERNET_H__
#define __NETWORKMANAGER_DEVICE_ETHERNET_H__

#include "nm-device.h"

#define NM_TYPE_DEVICE_ETHERNET                 (nm_device_ethernet_get_type ())
#define NM_DEVICE_ETHERNET(obj)                 (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_ETHERNET, NMDeviceEthernet))
#define NM_DEVICE_ETHERNET_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE_ETHERNET, NMDeviceEthernetClass))
#define NM_IS_DEVICE_ETHERNET(obj)              (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_ETHERNET))
#define NM_IS_DEVICE_ETHERNET_CLASS(klass)      (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE_ETHERNET))
#define NM_DEVICE_ETHERNET_GET_CLASS(obj)       (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE_ETHERNET, NMDeviceEthernetClass))

#define NM_DEVICE_ETHERNET_SPEED "speed"
#define NM_DEVICE_ETHERNET_S390_SUBCHANNELS "s390-subchannels"

struct _NMDeviceEthernetPrivate;

typedef struct {
        NMDevice parent;
        struct _NMDeviceEthernetPrivate *_priv;
} NMDeviceEthernet;

typedef struct {
        NMDeviceClass parent;
} NMDeviceEthernetClass;

GType nm_device_ethernet_get_type (void);

#endif /* __NETWORKMANAGER_DEVICE_ETHERNET_H__ */
