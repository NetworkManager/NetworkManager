/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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
 * Copyright 2007 - 2008 Novell, Inc.
 * Copyright 2007 - 2012 Red Hat, Inc.
 */

#ifndef __NM_DEVICE_ETHERNET_H__
#define __NM_DEVICE_ETHERNET_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include <nm-device.h>

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_ETHERNET            (nm_device_ethernet_get_type ())
#define NM_DEVICE_ETHERNET(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_ETHERNET, NMDeviceEthernet))
#define NM_DEVICE_ETHERNET_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DEVICE_ETHERNET, NMDeviceEthernetClass))
#define NM_IS_DEVICE_ETHERNET(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_ETHERNET))
#define NM_IS_DEVICE_ETHERNET_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DEVICE_ETHERNET))
#define NM_DEVICE_ETHERNET_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DEVICE_ETHERNET, NMDeviceEthernetClass))

#define NM_DEVICE_ETHERNET_HW_ADDRESS  "hw-address"
#define NM_DEVICE_ETHERNET_PERMANENT_HW_ADDRESS "perm-hw-address"
#define NM_DEVICE_ETHERNET_SPEED       "speed"
#define NM_DEVICE_ETHERNET_CARRIER     "carrier"
#define NM_DEVICE_ETHERNET_S390_SUBCHANNELS "s390-subchannels"

/**
 * NMDeviceEthernet:
 */
struct _NMDeviceEthernet {
	NMDevice parent;
};

typedef struct {
	NMDeviceClass parent;

	/*< private >*/
	gpointer padding[4];
} NMDeviceEthernetClass;

GType nm_device_ethernet_get_type (void);

const char * nm_device_ethernet_get_hw_address (NMDeviceEthernet *device);
const char * nm_device_ethernet_get_permanent_hw_address (NMDeviceEthernet *device);
guint32      nm_device_ethernet_get_speed   (NMDeviceEthernet *device);
gboolean     nm_device_ethernet_get_carrier (NMDeviceEthernet *device);
NM_AVAILABLE_IN_1_2
const char * const *nm_device_ethernet_get_s390_subchannels (NMDeviceEthernet *device);

G_END_DECLS

#endif /* __NM_DEVICE_ETHERNET_H__ */
