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

#ifndef NM_DEVICE_BRIDGE_H
#define NM_DEVICE_BRIDGE_H

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_BRIDGE            (nm_device_bridge_get_type ())
#define NM_DEVICE_BRIDGE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_BRIDGE, NMDeviceBridge))
#define NM_DEVICE_BRIDGE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DEVICE_BRIDGE, NMDeviceBridgeClass))
#define NM_IS_DEVICE_BRIDGE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_BRIDGE))
#define NM_IS_DEVICE_BRIDGE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DEVICE_BRIDGE))
#define NM_DEVICE_BRIDGE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DEVICE_BRIDGE, NMDeviceBridgeClass))

/**
 * NMDeviceBridgeError:
 * @NM_DEVICE_BRIDGE_ERROR_UNKNOWN: unknown or unclassified error
 * @NM_DEVICE_BRIDGE_ERROR_NOT_BRIDGE_CONNECTION: the connection was not of bridge type
 * @NM_DEVICE_BRIDGE_ERROR_INVALID_BRIDGE_CONNECTION: the bridge connection was invalid
 * @NM_DEVICE_BRIDGE_ERROR_INTERFACE_MISMATCH: the interfaces of the connection and the device mismatched
 *
 * Since: 0.9.8
 */
typedef enum {
	NM_DEVICE_BRIDGE_ERROR_UNKNOWN = 0,               /*< nick=UnknownError >*/
	NM_DEVICE_BRIDGE_ERROR_NOT_BRIDGE_CONNECTION,     /*< nick=NotBridgeConnection >*/
	NM_DEVICE_BRIDGE_ERROR_INVALID_BRIDGE_CONNECTION, /*< nick=InvalidBridgeConnection >*/
	NM_DEVICE_BRIDGE_ERROR_INTERFACE_MISMATCH,        /*< nick=InterfaceMismatch >*/
} NMDeviceBridgeError;

#define NM_DEVICE_BRIDGE_ERROR nm_device_bridge_error_quark ()
GQuark nm_device_bridge_error_quark (void);

#define NM_DEVICE_BRIDGE_HW_ADDRESS  "hw-address"
#define NM_DEVICE_BRIDGE_CARRIER     "carrier"
#define NM_DEVICE_BRIDGE_SLAVES      "slaves"

typedef struct {
	NMDevice parent;
} NMDeviceBridge;

typedef struct {
	NMDeviceClass parent;

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
	void (*_reserved5) (void);
	void (*_reserved6) (void);
} NMDeviceBridgeClass;

GType        nm_device_bridge_get_type (void);

GObject *    nm_device_bridge_new (DBusGConnection *connection, const char *path);

const char      *nm_device_bridge_get_hw_address (NMDeviceBridge *device);
gboolean         nm_device_bridge_get_carrier    (NMDeviceBridge *device);
const GPtrArray *nm_device_bridge_get_slaves     (NMDeviceBridge *device);

G_END_DECLS

#endif /* NM_DEVICE_BRIDGE_H */
