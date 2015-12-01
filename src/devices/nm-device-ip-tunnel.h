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
 * Copyright 2015 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_IP_TUNNEL_H__
#define __NETWORKMANAGER_DEVICE_IP_TUNNEL_H__

#include "nm-core-types.h"
#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_IP_TUNNEL            (nm_device_ip_tunnel_get_type ())
#define NM_DEVICE_IP_TUNNEL(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_IP_TUNNEL, NMDeviceIPTunnel))
#define NM_DEVICE_IP_TUNNEL_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE_IP_TUNNEL, NMDeviceIPTunnelClass))
#define NM_IS_DEVICE_IP_TUNNEL(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_IP_TUNNEL))
#define NM_IS_DEVICE_IP_TUNNEL_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE_IP_TUNNEL))
#define NM_DEVICE_IP_TUNNEL_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE_IP_TUNNEL, NMDeviceIPTunnelClass))

#define NM_DEVICE_IP_TUNNEL_MODE                "mode"
#define NM_DEVICE_IP_TUNNEL_PARENT              "parent"
#define NM_DEVICE_IP_TUNNEL_LOCAL               "local"
#define NM_DEVICE_IP_TUNNEL_REMOTE              "remote"
#define NM_DEVICE_IP_TUNNEL_TTL                 "ttl"
#define NM_DEVICE_IP_TUNNEL_TOS                 "tos"
#define NM_DEVICE_IP_TUNNEL_PATH_MTU_DISCOVERY  "path-mtu-discovery"
#define NM_DEVICE_IP_TUNNEL_INPUT_KEY           "input-key"
#define NM_DEVICE_IP_TUNNEL_OUTPUT_KEY          "output-key"
#define NM_DEVICE_IP_TUNNEL_ENCAPSULATION_LIMIT "encapsulation-limit"
#define NM_DEVICE_IP_TUNNEL_FLOW_LABEL          "flow-label"

typedef struct {
	NMDevice parent;
} NMDeviceIPTunnel;

typedef struct {
	NMDeviceClass parent;
} NMDeviceIPTunnelClass;

GType nm_device_ip_tunnel_get_type (void);

G_END_DECLS

#endif	/* NM_DEVICE_IP_TUNNEL_H */
