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

#ifndef NM_DEVICE_MACVLAN_H
#define NM_DEVICE_MACVLAN_H

#include <glib-object.h>

#include "nm-device-generic.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_MACVLAN            (nm_device_macvlan_get_type ())
#define NM_DEVICE_MACVLAN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_MACVLAN, NMDeviceMacvlan))
#define NM_DEVICE_MACVLAN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE_MACVLAN, NMDeviceMacvlanClass))
#define NM_IS_DEVICE_MACVLAN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_MACVLAN))
#define NM_IS_DEVICE_MACVLAN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE_MACVLAN))
#define NM_DEVICE_MACVLAN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE_MACVLAN, NMDeviceMacvlanClass))

#define NM_DEVICE_MACVLAN_PARENT     "parent"
#define NM_DEVICE_MACVLAN_MODE       "mode"
#define NM_DEVICE_MACVLAN_NO_PROMISC "no-promisc"

typedef struct {
	NMDeviceGeneric parent;
} NMDeviceMacvlan;

typedef struct {
	NMDeviceGenericClass parent;

} NMDeviceMacvlanClass;

GType nm_device_macvlan_get_type (void);

NMDevice *nm_device_macvlan_new (NMPlatformLink *platform_device);

G_END_DECLS

#endif	/* NM_DEVICE_MACVLAN_H */
