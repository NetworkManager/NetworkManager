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
 * Copyright (C) 2011 Pantelis Koukousoulas <pktoss@gmail.com>
 */

#ifndef NM_DEVICE_ADSL_H
#define NM_DEVICE_ADSL_H

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_ADSL            (nm_device_adsl_get_type ())
#define NM_DEVICE_ADSL(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_ADSL, NMDeviceAdsl))
#define NM_DEVICE_ADSL_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DEVICE_ADSL, NMDeviceAdslClass))
#define NM_IS_DEVICE_ADSL(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_ADSL))
#define NM_IS_DEVICE_ADSL_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DEVICE_ADSL))
#define NM_DEVICE_ADSL_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DEVICE_ADSL, NMDeviceAdslClass))

/**
 * NMDeviceAdslError:
 * @NM_DEVICE_ADSL_ERROR_UNKNOWN: unknown or unclassified error
 * @NM_DEVICE_ADSL_ERROR_NOT_ADSL_CONNECTION: the connection was not of ADSL type
 * @NM_DEVICE_ADSL_ERROR_INVALID_ADSL_CONNECTION: the ADSL connection was invalid
 */
typedef enum {
	NM_DEVICE_ADSL_ERROR_UNKNOWN = 0,             /*< nick=UnknownError >*/
	NM_DEVICE_ADSL_ERROR_NOT_ADSL_CONNECTION,     /*< nick=NotAdslConnection >*/
	NM_DEVICE_ADSL_ERROR_INVALID_ADSL_CONNECTION, /*< nick=InvalidAdslConnection >*/
} NMDeviceAdslError;

#define NM_DEVICE_ADSL_ERROR nm_device_adsl_error_quark ()
GQuark nm_device_adsl_error_quark (void);

#define NM_DEVICE_ADSL_CARRIER "carrier"

typedef struct {
	NMDevice parent;
} NMDeviceAdsl;

typedef struct {
	NMDeviceClass parent;

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
	void (*_reserved5) (void);
	void (*_reserved6) (void);
} NMDeviceAdslClass;

GType nm_device_adsl_get_type (void);

GObject *nm_device_adsl_new (DBusGConnection *connection, const char *path);
gboolean nm_device_adsl_get_carrier (NMDeviceAdsl *device);

G_END_DECLS

#endif /* NM_DEVICE_ADSL_H */
