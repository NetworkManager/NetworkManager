// SPDX-License-Identifier: GPL-2.0+
/* NetworkManager -- Network link manager
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
#define NM_BLUEZ_DEVICE_INITIALIZED  "initialized"
#define NM_BLUEZ_DEVICE_REMOVED      "removed"

typedef struct _NMBluezDevice NMBluezDevice;
typedef struct _NMBluezDeviceClass NMBluezDeviceClass;

GType nm_bluez_device_get_type (void);

NMBluezDevice *nm_bluez_device_new (GDBusConnection *dbus_connection,
                                    const char *path,
                                    NMSettings *settings);

const char *nm_bluez_device_get_path (NMBluezDevice *self);

gboolean nm_bluez_device_get_initialized (NMBluezDevice *self);

gboolean nm_bluez_device_get_usable (NMBluezDevice *self);

const char *nm_bluez_device_get_address (NMBluezDevice *self);

const char *nm_bluez_device_get_name (NMBluezDevice *self);

guint32 nm_bluez_device_get_capabilities (NMBluezDevice *self);

gboolean nm_bluez_device_get_connected (NMBluezDevice *self);

typedef void (*NMBluezDeviceConnectCallback) (NMBluezDevice *self,
                                              const char *device,
                                              GError *error,
                                              gpointer user_data);

void
nm_bluez_device_connect_async (NMBluezDevice *self,
                               NMBluetoothCapabilities connection_bt_type,
                               GCancellable *cancellable,
                               NMBluezDeviceConnectCallback callback,
                               gpointer callback_user_data);

void
nm_bluez_device_disconnect (NMBluezDevice *self);

#endif /* __NETWORKMANAGER_BLUEZ_DEVICE_H__ */

