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

#ifndef __NETWORKMANAGER_BLUEZ4_ADAPTER_H__
#define __NETWORKMANAGER_BLUEZ4_ADAPTER_H__

#include "nm-bluez-device.h"

#define NM_TYPE_BLUEZ4_ADAPTER            (nm_bluez4_adapter_get_type ())
#define NM_BLUEZ4_ADAPTER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_BLUEZ4_ADAPTER, NMBluez4Adapter))
#define NM_BLUEZ4_ADAPTER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_BLUEZ4_ADAPTER, NMBluez4AdapterClass))
#define NM_IS_BLUEZ4_ADAPTER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_BLUEZ4_ADAPTER))
#define NM_IS_BLUEZ4_ADAPTER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_BLUEZ4_ADAPTER))
#define NM_BLUEZ4_ADAPTER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_BLUEZ4_ADAPTER, NMBluez4AdapterClass))

/* Properties */
#define NM_BLUEZ4_ADAPTER_PATH    "path"
#define NM_BLUEZ4_ADAPTER_ADDRESS "address"

/* Signals */
#define NM_BLUEZ4_ADAPTER_INITIALIZED      "initialized"
#define NM_BLUEZ4_ADAPTER_DEVICE_ADDED     "device-added"
#define NM_BLUEZ4_ADAPTER_DEVICE_REMOVED   "device-removed"

typedef struct _NMBluez4Adapter NMBluez4Adapter;
typedef struct _NMBluez4AdapterClass NMBluez4AdapterClass;

GType nm_bluez4_adapter_get_type (void);

NMBluez4Adapter *nm_bluez4_adapter_new (const char *path,
                                        NMSettings *settings);

const char *nm_bluez4_adapter_get_path (NMBluez4Adapter *self);

const char *nm_bluez4_adapter_get_address (NMBluez4Adapter *self);

gboolean nm_bluez4_adapter_get_initialized (NMBluez4Adapter *self);

GSList *nm_bluez4_adapter_get_devices (NMBluez4Adapter *self);

#endif /* __NETWORKMANAGER_BLUEZ4_ADAPTER_H__ */
