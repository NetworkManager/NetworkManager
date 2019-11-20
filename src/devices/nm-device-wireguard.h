// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2018 Javier Arteaga <jarteaga@jbeta.is>
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
