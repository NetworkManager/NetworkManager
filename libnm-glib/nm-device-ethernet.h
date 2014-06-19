/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * libnm_glib -- Access network status & information from glib applications
 *
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
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2012 Red Hat, Inc.
 */

#ifndef NM_DEVICE_ETHERNET_H
#define NM_DEVICE_ETHERNET_H

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_ETHERNET            (nm_device_ethernet_get_type ())
#define NM_DEVICE_ETHERNET(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_ETHERNET, NMDeviceEthernet))
#define NM_DEVICE_ETHERNET_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DEVICE_ETHERNET, NMDeviceEthernetClass))
#define NM_IS_DEVICE_ETHERNET(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_ETHERNET))
#define NM_IS_DEVICE_ETHERNET_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DEVICE_ETHERNET))
#define NM_DEVICE_ETHERNET_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DEVICE_ETHERNET, NMDeviceEthernetClass))

/**
 * NMDeviceEthernetError:
 * @NM_DEVICE_ETHERNET_ERROR_UNKNOWN: unknown or unclassified error
 * @NM_DEVICE_ETHERNET_ERROR_NOT_ETHERNET_CONNECTION: the connection was not of Ethernet or PPPoE type
 * @NM_DEVICE_ETHERNET_ERROR_INVALID_ETHERNET_CONNECTION: the Ethernet connection was invalid
 * @NM_DEVICE_ETHERNET_ERROR_INVALID_DEVICE_MAC: the device's MAC was invalid
 * @NM_DEVICE_ETHERNET_ERROR_MAC_MISMATCH: the MACs of the connection and the device mismatched
 */
typedef enum {
	NM_DEVICE_ETHERNET_ERROR_UNKNOWN = 0,                 /*< nick=UnknownError >*/
	NM_DEVICE_ETHERNET_ERROR_NOT_ETHERNET_CONNECTION,     /*< nick=NotEthernetConnection >*/
	NM_DEVICE_ETHERNET_ERROR_INVALID_ETHERNET_CONNECTION, /*< nick=InvalidEthernetConnection >*/
	NM_DEVICE_ETHERNET_ERROR_INVALID_DEVICE_MAC,          /*< nick=InvalidDeviceMac >*/
	NM_DEVICE_ETHERNET_ERROR_MAC_MISMATCH,                /*< nick=MacMismatch >*/
} NMDeviceEthernetError;

#define NM_DEVICE_ETHERNET_ERROR nm_device_ethernet_error_quark ()
GQuark nm_device_ethernet_error_quark (void);

#define NM_DEVICE_ETHERNET_HW_ADDRESS  "hw-address"
#define NM_DEVICE_ETHERNET_PERMANENT_HW_ADDRESS "perm-hw-address"
#define NM_DEVICE_ETHERNET_SPEED       "speed"
#define NM_DEVICE_ETHERNET_CARRIER     "carrier"

typedef struct {
	NMDevice parent;
} NMDeviceEthernet;

typedef struct {
	NMDeviceClass parent;

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
	void (*_reserved5) (void);
	void (*_reserved6) (void);
} NMDeviceEthernetClass;

GType nm_device_ethernet_get_type (void);

GObject *nm_device_ethernet_new (DBusGConnection *connection, const char *path);

const char * nm_device_ethernet_get_hw_address (NMDeviceEthernet *device);
const char * nm_device_ethernet_get_permanent_hw_address (NMDeviceEthernet *device);
guint32      nm_device_ethernet_get_speed   (NMDeviceEthernet *device);
gboolean     nm_device_ethernet_get_carrier (NMDeviceEthernet *device);

G_END_DECLS

#endif /* NM_DEVICE_ETHERNET_H */
