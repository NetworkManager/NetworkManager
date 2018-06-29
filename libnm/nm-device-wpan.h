/*
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
 * Copyright 2018 Lubomir Rintel <lkundrak@v3.sk>
 */

#ifndef __NM_DEVICE_WPAN_H__
#define __NM_DEVICE_WPAN_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_WPAN            (nm_device_wpan_get_type ())
#define NM_DEVICE_WPAN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_WPAN, NMDeviceWpan))
#define NM_DEVICE_WPAN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DEVICE_WPAN, NMDeviceWpanClass))
#define NM_IS_DEVICE_WPAN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_WPAN))
#define NM_IS_DEVICE_WPAN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DEVICE_WPAN))
#define NM_DEVICE_WPAN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DEVICE_WPAN, NMDeviceWpanClass))

#define NM_DEVICE_WPAN_HW_ADDRESS "hw-address"

NM_AVAILABLE_IN_1_14
GType nm_device_wpan_get_type (void);

NM_AVAILABLE_IN_1_14
const char *nm_device_wpan_get_hw_address (NMDeviceWpan *device);

G_END_DECLS

#endif /* __NM_DEVICE_WPAN_H__ */
