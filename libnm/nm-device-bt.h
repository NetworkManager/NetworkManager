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
 * Copyright 2008 - 2012 Red Hat, Inc.
 * Copyright 2008 Novell, Inc.
 */

#ifndef NM_DEVICE_BT_H
#define NM_DEVICE_BT_H

#include "NetworkManager.h"
#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_BT            (nm_device_bt_get_type ())
#define NM_DEVICE_BT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_BT, NMDeviceBt))
#define NM_DEVICE_BT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DEVICE_BT, NMDeviceBtClass))
#define NM_IS_DEVICE_BT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_BT))
#define NM_IS_DEVICE_BT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DEVICE_BT))
#define NM_DEVICE_BT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DEVICE_BT, NMDeviceBtClass))

/**
 * NMDeviceBtError:
 * @NM_DEVICE_BT_ERROR_UNKNOWN: unknown or unclassified error
 * @NM_DEVICE_BT_ERROR_NOT_BT_CONNECTION: the connection was not of bluetooth type
 * @NM_DEVICE_BT_ERROR_INVALID_BT_CONNECTION: the bluetooth connection was invalid
 * @NM_DEVICE_BT_ERROR_INVALID_DEVICE_MAC: the device's MAC was invalid
 * @NM_DEVICE_BT_ERROR_MAC_MISMATCH: the MACs of the connection and the device mismatched
 * @NM_DEVICE_BT_ERROR_MISSING_DEVICE_CAPS: the device missed required capabilities
 */
typedef enum {
	NM_DEVICE_BT_ERROR_UNKNOWN = 0,           /*< nick=UnknownError >*/
	NM_DEVICE_BT_ERROR_NOT_BT_CONNECTION,     /*< nick=NotBtConnection >*/
	NM_DEVICE_BT_ERROR_INVALID_BT_CONNECTION, /*< nick=InvalidBtConnection >*/
	NM_DEVICE_BT_ERROR_INVALID_DEVICE_MAC,    /*< nick=InvalidDeviceMac >*/
	NM_DEVICE_BT_ERROR_MAC_MISMATCH,          /*< nick=MacMismatch >*/
	NM_DEVICE_BT_ERROR_MISSING_DEVICE_CAPS,   /*< nick=MissingDeviceCaps >*/
} NMDeviceBtError;

#define NM_DEVICE_BT_ERROR nm_device_bt_error_quark ()
GQuark nm_device_bt_error_quark (void);

#define NM_DEVICE_BT_HW_ADDRESS   "hw-address"
#define NM_DEVICE_BT_NAME         "name"
#define NM_DEVICE_BT_CAPABILITIES "bt-capabilities"

typedef struct {
	NMDevice parent;
} NMDeviceBt;

typedef struct {
	NMDeviceClass parent;

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
	void (*_reserved5) (void);
	void (*_reserved6) (void);
} NMDeviceBtClass;

GType nm_device_bt_get_type (void);

GObject *nm_device_bt_new (DBusGConnection *connection, const char *path);

const char *nm_device_bt_get_hw_address   (NMDeviceBt *device);

const char *nm_device_bt_get_name         (NMDeviceBt *device);

NMBluetoothCapabilities nm_device_bt_get_capabilities (NMDeviceBt *device);

G_END_DECLS

#endif /* NM_DEVICE_BT_H */
