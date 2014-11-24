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
 * Copyright 2012 - 2014 Red Hat, Inc.
 */

#ifndef NM_DEVICE_VLAN_H
#define NM_DEVICE_VLAN_H

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_VLAN            (nm_device_vlan_get_type ())
#define NM_DEVICE_VLAN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_VLAN, NMDeviceVlan))
#define NM_DEVICE_VLAN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DEVICE_VLAN, NMDeviceVlanClass))
#define NM_IS_DEVICE_VLAN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_VLAN))
#define NM_IS_DEVICE_VLAN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DEVICE_VLAN))
#define NM_DEVICE_VLAN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DEVICE_VLAN, NMDeviceVlanClass))

/**
 * NMDeviceVlanError:
 * @NM_DEVICE_VLAN_ERROR_UNKNOWN: unknown or unclassified error
 * @NM_DEVICE_VLAN_ERROR_NOT_VLAN_CONNECTION: the connection was not of VLAN type
 * @NM_DEVICE_VLAN_ERROR_INVALID_VLAN_CONNECTION: the VLAN connection was invalid
 * @NM_DEVICE_VLAN_ERROR_ID_MISMATCH: the VLAN identifiers of the connection and the device mismatched
 * @NM_DEVICE_VLAN_ERROR_INTERFACE_MISMATCH: the interfaces of the connection and the device mismatched
 * @NM_DEVICE_VLAN_ERROR_MAC_MISMATCH: the MACs of the connection and the device mismatched
 */
typedef enum {
	NM_DEVICE_VLAN_ERROR_UNKNOWN = 0,             /*< nick=UnknownError >*/
	NM_DEVICE_VLAN_ERROR_NOT_VLAN_CONNECTION,     /*< nick=NotVlanConnection >*/
	NM_DEVICE_VLAN_ERROR_INVALID_VLAN_CONNECTION, /*< nick=InvalidVlanConnection >*/
	NM_DEVICE_VLAN_ERROR_ID_MISMATCH,             /*< nick=IdMismatch >*/
	NM_DEVICE_VLAN_ERROR_INTERFACE_MISMATCH,      /*< nick=InterfaceMismatch >*/
	NM_DEVICE_VLAN_ERROR_MAC_MISMATCH,            /*< nick=MacMismatch >*/
} NMDeviceVlanError;

#define NM_DEVICE_VLAN_ERROR nm_device_vlan_error_quark ()
GQuark nm_device_vlan_error_quark (void);

#define NM_DEVICE_VLAN_HW_ADDRESS  "hw-address"
#define NM_DEVICE_VLAN_CARRIER     "carrier"
#define NM_DEVICE_VLAN_PARENT      "parent"
#define NM_DEVICE_VLAN_VLAN_ID     "vlan-id"

typedef struct {
	NMDevice parent;
} NMDeviceVlan;

typedef struct {
	NMDeviceClass parent;

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
	void (*_reserved5) (void);
	void (*_reserved6) (void);
} NMDeviceVlanClass;

GType nm_device_vlan_get_type (void);

GObject *nm_device_vlan_new (DBusGConnection *connection, const char *path);

const char * nm_device_vlan_get_hw_address (NMDeviceVlan *device);
gboolean     nm_device_vlan_get_carrier (NMDeviceVlan *device);
NM_AVAILABLE_IN_1_0
NMDevice *   nm_device_vlan_get_parent  (NMDeviceVlan *device);
guint        nm_device_vlan_get_vlan_id (NMDeviceVlan *device);

G_END_DECLS

#endif /* NM_DEVICE_VLAN_H */
