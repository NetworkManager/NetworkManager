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
 * Copyright (C) 2007 - 2011 Red Hat, Inc.
 */

#ifndef NM_DEVICE_INFINIBAND_H
#define NM_DEVICE_INFINIBAND_H

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_INFINIBAND            (nm_device_infiniband_get_type ())
#define NM_DEVICE_INFINIBAND(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_INFINIBAND, NMDeviceInfiniband))
#define NM_DEVICE_INFINIBAND_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DEVICE_INFINIBAND, NMDeviceInfinibandClass))
#define NM_IS_DEVICE_INFINIBAND(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_INFINIBAND))
#define NM_IS_DEVICE_INFINIBAND_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_DEVICE_INFINIBAND))
#define NM_DEVICE_INFINIBAND_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DEVICE_INFINIBAND, NMDeviceInfinibandClass))

#define NM_DEVICE_INFINIBAND_HW_ADDRESS  "hw-address"
#define NM_DEVICE_INFINIBAND_CARRIER     "carrier"

typedef struct {
	NMDevice parent;
} NMDeviceInfiniband;

typedef struct {
	NMDeviceClass parent;

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
	void (*_reserved5) (void);
	void (*_reserved6) (void);
} NMDeviceInfinibandClass;

GType nm_device_infiniband_get_type (void);

GObject *nm_device_infiniband_new (DBusGConnection *connection, const char *path);

const char * nm_device_infiniband_get_hw_address (NMDeviceInfiniband *device);
gboolean     nm_device_infiniband_get_carrier (NMDeviceInfiniband *device);

G_END_DECLS

#endif /* NM_DEVICE_INFINIBAND_H */
