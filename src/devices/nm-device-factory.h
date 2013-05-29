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
 * Copyright (C) 2007 - 2011 Red Hat, Inc.
 */

#ifndef NM_DEVICE_FACTORY_H
#define NM_DEVICE_FACTORY_H

#include <glib.h>
#include <glib-object.h>

#include "NetworkManager.h"
#include "nm-platform.h"

/* WARNING: this file is private API between NetworkManager and its internal
 * device plugins.  Its API can change at any time and is not guaranteed to be
 * stable.  NM and device plugins are distributed together and this API is
 * not meant to enable third-party plugins.
 */

/**
 * nm_device_factory_create_device:
 * @devpath: sysfs path of the device
 * @ifname: interface name of the device
 * @driver: driver of the device
 * @error: error for failure information
 *
 * Creates a #NMDevice subclass if the given information represents a device
 * the factory is capable of creating.  If the information does represent a
 * device the factory is capable of creating, but the device could not be
 * created, %NULL should be returned and @error should be set.  If the
 * factory is not capable of creating a device with the given information
 * (ie, the factory creates Ethernet devices but the information represents
 * a WiFi device) it should return %NULL and leave @error untouched.
 *
 * Returns: the device object (a subclass of #NMDevice) or %NULL
 */
GObject *nm_device_factory_create_device (NMPlatformLink *platform_device,
                                          GError **error);

/* Should match nm_device_factory() */
typedef GObject * (*NMDeviceFactoryCreateFunc) (NMPlatformLink *platform_device,
                                                GError **error);

/**
 * nm_device_factory_get_priority:
 *
 * Returns the priority of this plugin.  Higher numbers mean a higher priority.
 *
 * Returns: plugin priority
 */
guint32 nm_device_factory_get_priority (void);

typedef guint32 (*NMDeviceFactoryPriorityFunc) (void);

/**
 * nm_device_factory_get_type:
 *
 * Returns the type of device this factory can create.  Only one factory for
 * each type of device is allowed.
 *
 * Returns: the %NMDeviceType
 */
NMDeviceType nm_device_factory_get_type (void);

typedef NMDeviceType (*NMDeviceFactoryTypeFunc) (void);

#endif /* NM_DEVICE_FACTORY_H */

