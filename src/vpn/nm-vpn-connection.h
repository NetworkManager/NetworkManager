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
 * Copyright (C) 2005 - 2011 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#ifndef __NM_VPN_CONNECTION_H__
#define __NM_VPN_CONNECTION_H__

#include "nm-vpn-dbus-interface.h"
#include "devices/nm-device.h"
#include "nm-auth-subject.h"
#include "nm-active-connection.h"
#include "nm-vpn-plugin-info.h"

#define NM_TYPE_VPN_CONNECTION            (nm_vpn_connection_get_type ())
#define NM_VPN_CONNECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_VPN_CONNECTION, NMVpnConnection))
#define NM_VPN_CONNECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_VPN_CONNECTION, NMVpnConnectionClass))
#define NM_IS_VPN_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_VPN_CONNECTION))
#define NM_IS_VPN_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_VPN_CONNECTION))
#define NM_VPN_CONNECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_VPN_CONNECTION, NMVpnConnectionClass))

/* Properties */
#define NM_VPN_CONNECTION_VPN_STATE "vpn-state"
#define NM_VPN_CONNECTION_BANNER "banner"

/* Signals */
#define NM_VPN_CONNECTION_INTERNAL_STATE_CHANGED       "internal-state-changed"
#define NM_VPN_CONNECTION_INTERNAL_RETRY_AFTER_FAILURE "internal-retry-after-failure"

typedef struct _NMVpnConnectionClass NMVpnConnectionClass;

GType nm_vpn_connection_get_type (void);

NMVpnConnection * nm_vpn_connection_new (NMSettingsConnection *settings_connection,
                                         NMDevice *parent_device,
                                         const char *specific_object,
                                         NMActivationReason activation_reason,
                                         NMActivationStateFlags initial_state_flags,
                                         NMAuthSubject *subject);

void                 nm_vpn_connection_activate        (NMVpnConnection *self,
                                                        NMVpnPluginInfo *plugin_info);
NMVpnConnectionState nm_vpn_connection_get_vpn_state   (NMVpnConnection *self);
const char *         nm_vpn_connection_get_banner      (NMVpnConnection *self);
const char *        nm_vpn_connection_get_service     (NMVpnConnection *self);

gboolean             nm_vpn_connection_deactivate      (NMVpnConnection *self,
                                                        NMActiveConnectionStateReason reason,
                                                        gboolean quitting);
void                 nm_vpn_connection_disconnect      (NMVpnConnection *self,
                                                        NMActiveConnectionStateReason reason,
                                                        gboolean quitting);

NMProxyConfig *      nm_vpn_connection_get_proxy_config (NMVpnConnection *self);

NMIP4Config *        nm_vpn_connection_get_ip4_config  (NMVpnConnection *self);
NMIP6Config *        nm_vpn_connection_get_ip6_config  (NMVpnConnection *self);
const char *         nm_vpn_connection_get_ip_iface    (NMVpnConnection *self, gboolean fallback_device);
int                  nm_vpn_connection_get_ip_ifindex  (NMVpnConnection *self, gboolean fallback_device);
guint32              nm_vpn_connection_get_ip4_internal_gateway (NMVpnConnection *self);
struct in6_addr *    nm_vpn_connection_get_ip6_internal_gateway (NMVpnConnection *self);

guint32              nm_vpn_connection_get_ip4_route_metric (NMVpnConnection *self);
guint32              nm_vpn_connection_get_ip6_route_metric (NMVpnConnection *self);

#endif /* __NM_VPN_CONNECTION_H__ */
