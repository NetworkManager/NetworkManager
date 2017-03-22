/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-udev-utils.h - udev utils functions
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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
