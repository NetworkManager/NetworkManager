/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

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
 * (C) Copyright 2015 Red Hat, Inc.
 */

#ifndef NM_CORE_TYPES_INTERNAL_H
#define NM_CORE_TYPES_INTERNAL_H

#if !((NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_CORE_INTERNAL)
#error Cannot use this header.
#endif

typedef struct {
	guint32 from;
	guint32 to;
} NMVlanQosMapping;

typedef struct {
	NMIPAddr ip;
	guint8 family;
	guint8 mask;
} NMWireGuardAllowedIP;

#define NM_WG_PUBLIC_KEY_LEN 32
#define NM_WG_SYMMETRIC_KEY_LEN 32

typedef struct {
	guint8 public_key[NM_WG_PUBLIC_KEY_LEN];
	guint8 preshared_key[NM_WG_SYMMETRIC_KEY_LEN];
	union {
		struct sockaddr addr;
		struct sockaddr_in addr4;
		struct sockaddr_in6 addr6;
	} endpoint;
	guint16 persistent_keepalive_interval;
	struct timespec last_handshake_time;
	guint64 rx_bytes, tx_bytes;

	gsize allowedips_len;
	NMWireGuardAllowedIP *allowedips;
} NMWireGuardPeer;

#define _NM_IP_TUNNEL_FLAG_ALL_IP6TNL \
	( NM_IP_TUNNEL_FLAG_IP6_IGN_ENCAP_LIMIT \
	| NM_IP_TUNNEL_FLAG_IP6_USE_ORIG_TCLASS \
	| NM_IP_TUNNEL_FLAG_IP6_USE_ORIG_FLOWLABEL \
	| NM_IP_TUNNEL_FLAG_IP6_MIP6_DEV \
	| NM_IP_TUNNEL_FLAG_IP6_RCV_DSCP_COPY \
	| NM_IP_TUNNEL_FLAG_IP6_USE_ORIG_FWMARK \
	)

#endif /* NM_CORE_TYPES_INTERNAL_H */
