/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2010 Red Hat, Inc.
 */

#ifndef __NM_VPN_CONNECTION_H__
#define __NM_VPN_CONNECTION_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-active-connection.h"
#include "nm-vpn-dbus-interface.h"

G_BEGIN_DECLS

#define NM_TYPE_VPN_CONNECTION (nm_vpn_connection_get_type())
#define NM_VPN_CONNECTION(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_VPN_CONNECTION, NMVpnConnection))
#define NM_VPN_CONNECTION_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_VPN_CONNECTION, NMVpnConnectionClass))
#define NM_IS_VPN_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_VPN_CONNECTION))
#define NM_IS_VPN_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_VPN_CONNECTION))
#define NM_VPN_CONNECTION_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_VPN_CONNECTION, NMVpnConnectionClass))

#define NM_VPN_CONNECTION_VPN_STATE "vpn-state"
#define NM_VPN_CONNECTION_BANNER    "banner"

/**
 * NMVpnConnection:
 */
typedef struct _NMVpnConnectionClass NMVpnConnectionClass;

GType nm_vpn_connection_get_type(void);

NMVpnConnectionState nm_vpn_connection_get_vpn_state(NMVpnConnection *vpn);
const char          *nm_vpn_connection_get_banner(NMVpnConnection *vpn);

G_END_DECLS

#endif /* __NM_VPN_CONNECTION_H__ */
