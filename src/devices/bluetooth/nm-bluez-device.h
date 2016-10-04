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
 * Copyright (C) 2009 - 2014 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_BLUEZ_DEVICE_H__
#define __NETWORKMANAGER_BLUEZ_DEVICE_H__

#include "nm-connection.h"

#define NM_TYPE_BLUEZ_DEVICE            (nm_bluez_device_get_type ())
#define NM_BLUEZ_DEVICE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_BLUEZ_DEVICE, NMBluezDevice))
#define NM_BLUEZ_DEVICE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_BLUEZ_DEVICE, NMBluezDeviceClass))
#define NM_IS_BLUEZ_DEVICE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_BLUEZ_DEVICE))
#define NM_IS_BLUEZ_DEVICE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_BLUEZ_DEVICE))
#define NM_BLUEZ_DEVICE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_BLUEZ_DEVICE, NMBluezDeviceClass))

/* Properties */
#define NM_BLUEZ_DEVICE_PATH         "path"
#define NM_BLUEZ_DEVICE_ADDRESS      "address"
#define NM_BLUEZ_DEVICE_NAME         "name"
#define NM_BLUEZ_DEVICE_CAPABILITIES "capabilities"
#define NM_BLUEZ_DEVICE_USABLE       "usable"
#define NM_BLUEZ_DEVICE_CONNECTED    "connected"

/* Signals */
#define NM_BLUEZ_DEVICE_REMOVED      "removed"

typedef struct _NMBluezDevice NMBluezDevice;
typedef struct _NMBluezDeviceClass NMBluezDeviceClass;

GType nm_bluez_device_get_type (void);

NMBluezDevice *nm_bluez_device_new (const char *path,
                                    const char *adapter_address,
                                    NMSettings *settings,
                                    int bluez_version);

const char *nm_bluez_device_get_path (NMBluezDevice *self);

gboolean nm_bluez_device_get_initialized (NMBluezDevice *self);

gboolean nm_bluez_device_get_usable (NMBluezDevice *self);

const char *nm_bluez_device_get_address (NMBluezDevice *self);

const char *nm_bluez_device_get_name (NMBluezDevice *self);

guint32 nm_bluez_device_get_class (NMBluezDevice *self);

guint32 nm_bluez_device_get_capabilities (NMBluezDevice *self);

gboolean nm_bluez_device_get_connected (NMBluezDevice *self);

void
nm_bluez_device_connect_async (NMBluezDevice *self,
                               NMBluetoothCapabilities connection_bt_type,
                               GAsyncReadyCallback callback,
                               gpointer user_data);

const char *
nm_bluez_device_connect_finish (NMBluezDevice *self,
                                GAsyncResult *result,
                                GError **error);

void
nm_bluez_device_disconnect (NMBluezDevice *self);

#endif /* __NETWORKMANAGER_BLUEZ_DEVICE_H__ */

