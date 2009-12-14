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
 * Copyright (C) 2009 Novell, Inc.
 */

#ifndef NM_WIMAX_DEVICE_H
#define NM_WIMAX_DEVICE_H

#include "nm-device.h"
#include "nm-wimax-nsp.h"

G_BEGIN_DECLS

#define NM_TYPE_WIMAX_DEVICE            (nm_wimax_device_get_type ())
#define NM_WIMAX_DEVICE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_WIMAX_DEVICE, NMWimaxDevice))
#define NM_WIMAX_DEVICE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_WIMAX_DEVICE, NMWimaxDeviceClass))
#define NM_IS_WIMAX_DEVICE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_WIMAX_DEVICE))
#define NM_IS_WIMAX_DEVICE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_WIMAX_DEVICE))
#define NM_WIMAX_DEVICE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_WIMAX_DEVICE, NMWimaxDeviceClass))

#define NM_WIMAX_DEVICE_HW_ADDRESS "hw-address"
#define NM_WIMAX_DEVICE_ACTIVE_NSP "active-nsp"

typedef struct {
	NMDevice parent;
} NMWimaxDevice;

typedef struct {
	NMDeviceClass parent;

	/* Signals */
	void (*nsp_added)   (NMWimaxDevice *self, NMWimaxNsp *nsp);
	void (*nsp_removed) (NMWimaxDevice *self, NMWimaxNsp *nsp);
} NMWimaxDeviceClass;

GType nm_wimax_device_get_type (void);

GObject         *nm_wimax_device_new             (DBusGConnection *connection,
												  const char *path);

const char      *nm_wimax_device_get_hw_address  (NMWimaxDevice *wimax);
NMWimaxNsp      *nm_wimax_device_get_active_nsp  (NMWimaxDevice *wimax);
NMWimaxNsp      *nm_wimax_device_get_nsp_by_path (NMWimaxDevice *wimax,
												  const char *path);

const GPtrArray *nm_wimax_device_get_nsps        (NMWimaxDevice *wimax);

G_END_DECLS

#endif /* NM_WIMAX_DEVICE_H */
