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
 * Copyright 2012 Red Hat, Inc.
 */

#ifndef NM_DEVICE_BOND_H
#define NM_DEVICE_BOND_H

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_BOND            (nm_device_bond_get_type ())
#define NM_DEVICE_BOND(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_BOND, NMDeviceBond))
#define NM_DEVICE_BOND_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DEVICE_BOND, NMDeviceBondClass))
#define NM_IS_DEVICE_BOND(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_BOND))
#define NM_IS_DEVICE_BOND_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DEVICE_BOND))
#define NM_DEVICE_BOND_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DEVICE_BOND, NMDeviceBondClass))

/**
 * NMDeviceBondError:
 * @NM_DEVICE_BOND_ERROR_UNKNOWN: unknown or unclassified error
 * @NM_DEVICE_BOND_ERROR_NOT_BOND_CONNECTION: the connection was not of bond type
 * @NM_DEVICE_BOND_ERROR_INVALID_BOND_CONNECTION: the bond connection was invalid
 * @NM_DEVICE_BOND_ERROR_INTERFACE_MISMATCH: the interfaces of the connection and the device mismatched
 */
typedef enum {
	NM_DEVICE_BOND_ERROR_UNKNOWN = 0,             /*< nick=UnknownError >*/
	NM_DEVICE_BOND_ERROR_NOT_BOND_CONNECTION,     /*< nick=NotBondConnection >*/
	NM_DEVICE_BOND_ERROR_INVALID_BOND_CONNECTION, /*< nick=InvalidBondConnection >*/
	NM_DEVICE_BOND_ERROR_INTERFACE_MISMATCH,      /*< nick=InterfaceMismatch >*/
} NMDeviceBondError;

#define NM_DEVICE_BOND_ERROR nm_device_bond_error_quark ()
GQuark nm_device_bond_error_quark (void);

#define NM_DEVICE_BOND_HW_ADDRESS  "hw-address"
#define NM_DEVICE_BOND_CARRIER     "carrier"
#define NM_DEVICE_BOND_SLAVES      "slaves"

typedef struct {
	NMDevice parent;
} NMDeviceBond;

typedef struct {
	NMDeviceClass parent;

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
	void (*_reserved5) (void);
	void (*_reserved6) (void);
} NMDeviceBondClass;

GType nm_device_bond_get_type (void);

GObject *nm_device_bond_new (DBusGConnection *connection, const char *path);

const char      *nm_device_bond_get_hw_address (NMDeviceBond *device);
gboolean         nm_device_bond_get_carrier    (NMDeviceBond *device);
const GPtrArray *nm_device_bond_get_slaves     (NMDeviceBond *device);

G_END_DECLS

#endif /* NM_DEVICE_BOND_H */
