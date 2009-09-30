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
 * Copyright (C) 2008 Novell, Inc.
 */

#ifndef NM_SERIAL_DEVICE_H
#define NM_SERIAL_DEVICE_H

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_SERIAL_DEVICE            (nm_serial_device_get_type ())
#define NM_SERIAL_DEVICE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SERIAL_DEVICE, NMSerialDevice))
#define NM_SERIAL_DEVICE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SERIAL_DEVICE, NMSerialDeviceClass))
#define NM_IS_SERIAL_DEVICE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SERIAL_DEVICE))
#define NM_IS_SERIAL_DEVICE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_SERIAL_DEVICE))
#define NM_SERIAL_DEVICE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SERIAL_DEVICE, NMSerialDeviceClass))

typedef struct {
	NMDevice parent;
} NMSerialDevice;

typedef struct {
	NMDeviceClass parent;

	/* Signals */
	void (*ppp_stats) (NMSerialDevice *self, guint32 in_bytes, guint32 out_bytes);

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
	void (*_reserved5) (void);
	void (*_reserved6) (void);
} NMSerialDeviceClass;

GType nm_serial_device_get_type (void);

guint32 nm_serial_device_get_bytes_received (NMSerialDevice *self);
guint32 nm_serial_device_get_bytes_sent     (NMSerialDevice *self);

G_END_DECLS

#endif /* NM_SERIAL_DEVICE_H */
