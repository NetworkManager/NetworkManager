// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2009 - 2019 Red Hat, Inc.
 */

#ifndef __NM_BLUEZ_MANAGER_H__
#define __NM_BLUEZ_MANAGER_H__

#define NM_TYPE_BLUEZ_MANAGER            (nm_bluez_manager_get_type ())
#define NM_BLUEZ_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_BLUEZ_MANAGER, NMBluezManager))
#define NM_BLUEZ_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_BLUEZ_MANAGER, NMBluezManagerClass))
#define NM_IS_BLUEZ_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_BLUEZ_MANAGER))
#define NM_IS_BLUEZ_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_BLUEZ_MANAGER))
#define NM_BLUEZ_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_BLUEZ_MANAGER, NMBluezManagerClass))

typedef struct _NMBluezManager NMBluezManager;
typedef struct _NMBluezManagerClass NMBluezManagerClass;

GType nm_bluez_manager_get_type (void);

typedef void (*NMBluezManagerConnectCb) (NMBluezManager *self,
                                         gboolean is_completed /* or else is early notification with DUN path */,
                                         const char *device_name,
                                         GError *error,
                                         gpointer user_data);

gboolean nm_bluez_manager_connect (NMBluezManager *self,
                                   const char *object_path,
                                   NMBluetoothCapabilities connection_bt_type,
                                   int timeout_msec,
                                   GCancellable *cancellable,
                                   NMBluezManagerConnectCb callback,
                                   gpointer callback_user_data,
                                   GError **error);

void nm_bluez_manager_disconnect (NMBluezManager *self,
                                  const char *object_path);

#endif /* __NM_BLUEZ_MANAGER_H__ */
