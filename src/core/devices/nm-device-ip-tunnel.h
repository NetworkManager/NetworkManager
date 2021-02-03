/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2015 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_IP_TUNNEL_H__
#define __NETWORKMANAGER_DEVICE_IP_TUNNEL_H__

#include "nm-core-types.h"
#include "nm-device.h"

#define NM_TYPE_DEVICE_IP_TUNNEL (nm_device_ip_tunnel_get_type())
#define NM_DEVICE_IP_TUNNEL(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DEVICE_IP_TUNNEL, NMDeviceIPTunnel))
#define NM_DEVICE_IP_TUNNEL_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DEVICE_IP_TUNNEL, NMDeviceIPTunnelClass))
#define NM_IS_DEVICE_IP_TUNNEL(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DEVICE_IP_TUNNEL))
#define NM_IS_DEVICE_IP_TUNNEL_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DEVICE_IP_TUNNEL))
#define NM_DEVICE_IP_TUNNEL_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DEVICE_IP_TUNNEL, NMDeviceIPTunnelClass))

#define NM_DEVICE_IP_TUNNEL_MODE                "mode"
#define NM_DEVICE_IP_TUNNEL_LOCAL               "local"
#define NM_DEVICE_IP_TUNNEL_REMOTE              "remote"
#define NM_DEVICE_IP_TUNNEL_TTL                 "ttl"
#define NM_DEVICE_IP_TUNNEL_TOS                 "tos"
#define NM_DEVICE_IP_TUNNEL_PATH_MTU_DISCOVERY  "path-mtu-discovery"
#define NM_DEVICE_IP_TUNNEL_INPUT_KEY           "input-key"
#define NM_DEVICE_IP_TUNNEL_OUTPUT_KEY          "output-key"
#define NM_DEVICE_IP_TUNNEL_ENCAPSULATION_LIMIT "encapsulation-limit"
#define NM_DEVICE_IP_TUNNEL_FLOW_LABEL          "flow-label"
#define NM_DEVICE_IP_TUNNEL_FLAGS               "flags"

typedef struct _NMDeviceIPTunnel      NMDeviceIPTunnel;
typedef struct _NMDeviceIPTunnelClass NMDeviceIPTunnelClass;

GType nm_device_ip_tunnel_get_type(void);

#endif /* __NETWORKMANAGER_DEVICE_IP_TUNNEL_H__ */
