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
 * Copyright 2007 - 2008 Novell, Inc.
 * Copyright 2007 - 2010 Red Hat, Inc.
 */

#ifndef __NM_VPN_CONNECTION_H__
#define __NM_VPN_CONNECTION_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-active-connection.h"
#include "nm-vpn-dbus-interface.h"

G_BEGIN_DECLS

#define NM_TYPE_VPN_CONNECTION            (nm_vpn_connection_get_type ())
#define NM_VPN_CONNECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_VPN_CONNECTION, NMVpnConnection))
#define NM_VPN_CONNECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_VPN_CONNECTION, NMVpnConnectionClass))
#define NM_IS_VPN_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_VPN_CONNECTION))
#define NM_IS_VPN_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_VPN_CONNECTION))
#define NM_VPN_CONNECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_VPN_CONNECTION, NMVpnConnectionClass))

#define NM_VPN_CONNECTION_VPN_STATE "vpn-state"
#define NM_VPN_CONNECTION_BANNER "banner"

/**
 * NMVpnConnection:
 */
struct _NMVpnConnection {
	NMActiveConnection parent;
};

typedef struct {
	NMActiveConnectionClass parent;

	/* Signals */

	/* NMVpnConnectionStateReason got deprecated in 1.8.0. Thus, vpn_state_changed()
	 * uses a deprecated type and is itself deprecated.
	 *
	 * If you use this signal slot, you are advised to cast the reason
	 * to the NMActiveConnectionStateReason type, which is fully compatible.
	 */
	G_GNUC_BEGIN_IGNORE_DEPRECATIONS
	NM_DEPRECATED_IN_1_8
	void (*vpn_state_changed) (NMVpnConnection *connection,
	                           NMVpnConnectionState state,
	                           NMVpnConnectionStateReason reason);
	G_GNUC_END_IGNORE_DEPRECATIONS

	/*< private >*/
	gpointer padding[4];
} NMVpnConnectionClass;

GType nm_vpn_connection_get_type (void);

NMVpnConnectionState  nm_vpn_connection_get_vpn_state  (NMVpnConnection *vpn);
const char *          nm_vpn_connection_get_banner (NMVpnConnection *vpn);

G_END_DECLS

#endif /* __NM_VPN_CONNECTION_H__ */
