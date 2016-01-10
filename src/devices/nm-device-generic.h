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

#ifndef __NETWORKMANAGER_DEVICE_GENERIC_H__
#define __NETWORKMANAGER_DEVICE_GENERIC_H__

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_GENERIC            (nm_device_generic_get_type ())
#define NM_DEVICE_GENERIC(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_GENERIC, NMDeviceGeneric))
#define NM_DEVICE_GENERIC_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE_GENERIC, NMDeviceGenericClass))
#define NM_IS_DEVICE_GENERIC(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_GENERIC))
#define NM_IS_DEVICE_GENERIC_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE_GENERIC))
#define NM_DEVICE_GENERIC_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE_GENERIC, NMDeviceGenericClass))

#define NM_DEVICE_GENERIC_TYPE_DESCRIPTION "type-description"

typedef struct {
	NMDevice parent;
} NMDeviceGeneric;

typedef struct {
	NMDeviceClass parent;

} NMDeviceGenericClass;

GType nm_device_generic_get_type (void);

NMDevice *nm_device_generic_new (const NMPlatformLink *plink);

G_END_DECLS

#endif	/* NM_DEVICE_GENERIC_H */
