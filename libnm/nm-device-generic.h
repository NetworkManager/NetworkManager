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
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef __NM_DEVICE_GENERIC_H__
#define __NM_DEVICE_GENERIC_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_GENERIC            (nm_device_generic_get_type ())
#define NM_DEVICE_GENERIC(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_GENERIC, NMDeviceGeneric))
#define NM_DEVICE_GENERIC_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DEVICE_GENERIC, NMDeviceGenericClass))
#define NM_IS_DEVICE_GENERIC(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_GENERIC))
#define NM_IS_DEVICE_GENERIC_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DEVICE_GENERIC))
#define NM_DEVICE_GENERIC_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DEVICE_GENERIC, NMDeviceGenericClass))

#define NM_DEVICE_GENERIC_HW_ADDRESS       "hw-address"
#define NM_DEVICE_GENERIC_TYPE_DESCRIPTION "type-description"

/**
 * NMDeviceGeneric:
 */
struct _NMDeviceGeneric {
	NMDevice parent;
};

typedef struct {
	NMDeviceClass parent;

	/*< private >*/
	gpointer padding[4];
} NMDeviceGenericClass;

GType nm_device_generic_get_type (void);

const char *nm_device_generic_get_hw_address (NMDeviceGeneric *device);

G_END_DECLS

#endif /* __NM_DEVICE_GENERIC_H__ */
