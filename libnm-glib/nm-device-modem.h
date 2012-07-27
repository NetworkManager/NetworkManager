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
 * Copyright (C) 2011 - 2012 Red Hat, Inc.
 * Copyright (C) 2008 Novell, Inc.
 */

#ifndef NM_DEVICE_MODEM_H
#define NM_DEVICE_MODEM_H

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_MODEM            (nm_device_modem_get_type ())
#define NM_DEVICE_MODEM(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_MODEM, NMDeviceModem))
#define NM_DEVICE_MODEM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DEVICE_MODEM, NMDeviceModemClass))
#define NM_IS_DEVICE_MODEM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_MODEM))
#define NM_IS_DEVICE_MODEM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DEVICE_MODEM))
#define NM_DEVICE_MODEM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DEVICE_MODEM, NMDeviceModemClass))

/**
 * NMDeviceModemError:
 * @NM_DEVICE_MODEM_ERROR_UNKNOWN: unknown or unclassified error
 * @NM_DEVICE_MODEM_ERROR_NOT_MODEM_CONNECTION: the connection was not of modem type
 * @NM_DEVICE_MODEM_ERROR_INVALID_MODEM_CONNECTION: the modem connection was invalid
 * @NM_DEVICE_MODEM_ERROR_MISSING_DEVICE_CAPS: the device missed required capabilities
 */
typedef enum {
	NM_DEVICE_MODEM_ERROR_UNKNOWN = 0,              /*< nick=UnknownError >*/
	NM_DEVICE_MODEM_ERROR_NOT_MODEM_CONNECTION,     /*< nick=NotModemConnection >*/
	NM_DEVICE_MODEM_ERROR_INVALID_MODEM_CONNECTION, /*< nick=InvalidModemConnection >*/
	NM_DEVICE_MODEM_ERROR_MISSING_DEVICE_CAPS,      /*< nick=MissingDeviceCaps >*/
} NMDeviceModemError;

#define NM_DEVICE_MODEM_ERROR nm_device_modem_error_quark ()
GQuark nm_device_modem_error_quark (void);

#define NM_DEVICE_MODEM_MODEM_CAPABILITIES   "modem-capabilities"
#define NM_DEVICE_MODEM_CURRENT_CAPABILITIES "current-capabilities"

typedef struct {
	NMDevice parent;
} NMDeviceModem;

typedef struct {
	NMDeviceClass parent;

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
	void (*_reserved5) (void);
	void (*_reserved6) (void);
} NMDeviceModemClass;

GType nm_device_modem_get_type (void);

NMDeviceModemCapabilities nm_device_modem_get_modem_capabilities (NMDeviceModem *self);
NMDeviceModemCapabilities nm_device_modem_get_current_capabilities (NMDeviceModem *self);

G_END_DECLS

#endif /* NM_DEVICE_MODEM_H */
