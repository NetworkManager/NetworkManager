// SPDX-License-Identifier: GPL-2.0+
/* nm-udev-utils.h - udev utils functions
 *
 * Copyright (C) 2017 Red Hat, Inc.
 */

#ifndef __NM_UDEV_UTILS_H__
#define __NM_UDEV_UTILS_H__

struct udev;
struct udev_device;
struct udev_enumerate;

gboolean nm_udev_utils_property_as_boolean (const char *uproperty);
const char *nm_udev_utils_property_decode    (const char *uproperty, char **to_free);
char       *nm_udev_utils_property_decode_cp (const char *uproperty);

typedef struct _NMPUdevClient NMUdevClient;

typedef void (*NMUdevClientEvent) (NMUdevClient *udev_client,
                                   struct udev_device *udevice,
                                   gpointer event_user_data);

NMUdevClient *nm_udev_client_new (const char *const*subsystems,
                                  NMUdevClientEvent event_handler,
                                  gpointer event_user_data);

NMUdevClient *nm_udev_client_unref (NMUdevClient *self);

struct udev *nm_udev_client_get_udev (NMUdevClient *self);

struct udev_enumerate *nm_udev_client_enumerate_new (NMUdevClient *self);

#endif /* __NM_UDEV_UTILS_H__ */
