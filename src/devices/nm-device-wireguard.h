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
 * Copyright 2018 Javier Arteaga <jarteaga@jbeta.is>
 */

#ifndef __NM_DEVICE_WIREGUARD_H__
#define __NM_DEVICE_WIREGUARD_H__

#include "nm-device.h"

#define NM_TYPE_DEVICE_WIREGUARD            (nm_device_wireguard_get_type ())
#define NM_DEVICE_WIREGUARD(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_WIREGUARD, NMDeviceWireGuard))
#define NM_DEVICE_WIREGUARD_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE_WIREGUARD, NMDeviceWireGuardClass))
#define NM_IS_DEVICE_WIREGUARD(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_WIREGUARD))
#define NM_IS_DEVICE_WIREGUARD_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE_WIREGUARD))
#define NM_DEVICE_WIREGUARD_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE_WIREGUARD, NMDeviceWireGuardClass))

#define NM_DEVICE_WIREGUARD_PUBLIC_KEY      "public-key"
#define NM_DEVICE_WIREGUARD_LISTEN_PORT     "listen-port"
#define NM_DEVICE_WIREGUARD_FWMARK          "fwmark"

typedef struct _NMDeviceWireGuard NMDeviceWireGuard;
typedef struct _NMDeviceWireGuardClass NMDeviceWireGuardClass;

GType nm_device_wireguard_get_type (void);

#endif /* __NM_DEVICE_WIREGUARD_H__ */
