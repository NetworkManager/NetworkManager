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

#ifndef NM_DEVICE_BOND_H
#define NM_DEVICE_BOND_H

#include <glib-object.h>

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_BOND            (nm_device_bond_get_type ())
#define NM_DEVICE_BOND(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_BOND, NMDeviceBond))
#define NM_DEVICE_BOND_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE_BOND, NMDeviceBondClass))
#define NM_IS_DEVICE_BOND(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_BOND))
#define NM_IS_DEVICE_BOND_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE_BOND))
#define NM_DEVICE_BOND_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE_BOND, NMDeviceBondClass))

typedef enum {
	NM_BOND_ERROR_CONNECTION_NOT_BOND = 0, /*< nick=ConnectionNotBond >*/
	NM_BOND_ERROR_CONNECTION_INVALID,      /*< nick=ConnectionInvalid >*/
	NM_BOND_ERROR_CONNECTION_INCOMPATIBLE, /*< nick=ConnectionIncompatible >*/
} NMBondError;

#define NM_DEVICE_BOND_SLAVES "slaves"

typedef struct {
	NMDevice parent;
} NMDeviceBond;

typedef struct {
	NMDeviceClass parent;

} NMDeviceBondClass;


GType nm_device_bond_get_type (void);

NMDevice *nm_device_bond_new (NMPlatformLink *platform_device);
NMDevice *nm_device_bond_new_for_connection (NMConnection *connection);

G_END_DECLS

#endif	/* NM_DEVICE_BOND_H */
