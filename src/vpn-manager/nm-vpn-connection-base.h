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
 * (C) Copyright 2005 - 2011 Red Hat, Inc.
 */

#ifndef NM_VPN_CONNECTION_BASE_H
#define NM_VPN_CONNECTION_BASE_H

#include <glib-object.h>
#include "NetworkManagerVPN.h"
#include "nm-connection.h"

#define NM_TYPE_VPN_CONNECTION_BASE            (nm_vpn_connection_base_get_type ())
#define NM_VPN_CONNECTION_BASE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_VPN_CONNECTION_BASE, NMVpnConnectionBase))
#define NM_VPN_CONNECTION_BASE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_VPN_CONNECTION_BASE, NMVpnConnectionBaseClass))
#define NM_IS_VPN_CONNECTION_BASE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_VPN_CONNECTION_BASE))
#define NM_IS_VPN_CONNECTION_BASE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_VPN_CONNECTION_BASE))
#define NM_VPN_CONNECTION_BASE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_VPN_CONNECTION_BASE, NMVpnConnectionBaseClass))

typedef struct {
	GObject parent;
} NMVpnConnectionBase;

typedef struct {
	GObjectClass parent;
} NMVpnConnectionBaseClass;

GType nm_vpn_connection_base_get_type (void);

const char *nm_vpn_connection_base_get_ac_path (NMVpnConnectionBase *self);

void nm_vpn_connection_base_export (NMVpnConnectionBase *self,
                                    NMConnection *connection);

void nm_vpn_connection_base_set_state (NMVpnConnectionBase *self,
                                       NMVPNConnectionState vpn_state);

#endif /* NM_VPN_CONNECTION_BASE_H */

