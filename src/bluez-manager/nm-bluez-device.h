/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2009 Red Hat, Inc.
 */

#ifndef NM_BLUEZ_DEVICE_H
#define NM_BLUEZ_DEVICE_H

#include <glib.h>
#include <glib-object.h>

#define NM_TYPE_BLUEZ_DEVICE            (nm_bluez_device_get_type ())
#define NM_BLUEZ_DEVICE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_BLUEZ_DEVICE, NMBluezDevice))
#define NM_BLUEZ_DEVICE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_BLUEZ_DEVICE, NMBluezDeviceClass))
#define NM_IS_BLUEZ_DEVICE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_BLUEZ_DEVICE))
#define NM_IS_BLUEZ_DEVICE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_BLUEZ_DEVICE))
#define NM_BLUEZ_DEVICE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_BLUEZ_DEVICE, NMBluezDeviceClass))

#define NM_BLUEZ_DEVICE_PATH         "path"
#define NM_BLUEZ_DEVICE_ADDRESS      "address"
#define NM_BLUEZ_DEVICE_NAME         "name"
#define NM_BLUEZ_DEVICE_CAPABILITIES "capabilities"
#define NM_BLUEZ_DEVICE_RSSI         "rssi"
#define NM_BLUEZ_DEVICE_USABLE       "usable"

typedef struct {
	GObject parent;
} NMBluezDevice;

typedef struct {
	GObjectClass parent;

	/* virtual functions */
	void (*initialized) (NMBluezDevice *self, gboolean success);

	void (*invalid)     (NMBluezDevice *self);
} NMBluezDeviceClass;

GType nm_bluez_device_get_type (void);

NMBluezDevice *nm_bluez_device_new (const char *path);

const char *nm_bluez_device_get_path (NMBluezDevice *self);

gboolean nm_bluez_device_get_initialized (NMBluezDevice *self);

gboolean nm_bluez_device_get_usable (NMBluezDevice *self);

const char *nm_bluez_device_get_address (NMBluezDevice *self);

const char *nm_bluez_device_get_name (NMBluezDevice *self);

guint32 nm_bluez_device_get_class (NMBluezDevice *self);

guint32 nm_bluez_device_get_capabilities (NMBluezDevice *self);

gint nm_bluez_device_get_rssi (NMBluezDevice *self);

#endif /* NM_BLUEZ_DEVICE_H */

