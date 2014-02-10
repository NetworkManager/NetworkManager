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
 * Copyright (C) 2009 - 2012 Red Hat, Inc.
 */

#ifndef NM_BLUEZ4_ADAPTER_H
#define NM_BLUEZ4_ADAPTER_H

#include <glib.h>
#include <glib-object.h>

#include "nm-bluez-device.h"
#include "nm-connection-provider.h"

#define NM_TYPE_BLUEZ4_ADAPTER            (nm_bluez4_adapter_get_type ())
#define NM_BLUEZ4_ADAPTER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_BLUEZ4_ADAPTER, NMBluez4Adapter))
#define NM_BLUEZ4_ADAPTER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_BLUEZ4_ADAPTER, NMBluez4AdapterClass))
#define NM_IS_BLUEZ4_ADAPTER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_BLUEZ4_ADAPTER))
#define NM_IS_BLUEZ4_ADAPTER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_BLUEZ4_ADAPTER))
#define NM_BLUEZ4_ADAPTER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_BLUEZ4_ADAPTER, NMBluez4AdapterClass))

#define NM_BLUEZ4_ADAPTER_PATH    "path"
#define NM_BLUEZ4_ADAPTER_ADDRESS "address"

typedef struct {
	GObject parent;
} NMBluez4Adapter;

typedef struct {
	GObjectClass parent;

	/* virtual functions */
	void (*initialized)    (NMBluez4Adapter *self, gboolean success);

	void (*device_added)   (NMBluez4Adapter *self, NMBluezDevice *device);

	void (*device_removed) (NMBluez4Adapter *self, NMBluezDevice *device);
} NMBluez4AdapterClass;

GType nm_bluez4_adapter_get_type (void);

NMBluez4Adapter *nm_bluez4_adapter_new (const char *path,
                                        NMConnectionProvider *provider);

const char *nm_bluez4_adapter_get_path (NMBluez4Adapter *self);

const char *nm_bluez4_adapter_get_address (NMBluez4Adapter *self);

gboolean nm_bluez4_adapter_get_initialized (NMBluez4Adapter *self);

GSList *nm_bluez4_adapter_get_devices (NMBluez4Adapter *self);

#endif /* NM_BLUEZ4_ADAPTER_H */

