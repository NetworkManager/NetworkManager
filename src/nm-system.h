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
 * Copyright (C) 2004 - 2010 Red Hat, Inc.
 * Copyright (C) 2005 - 2008 Novell, Inc.
 */

#ifndef NETWORK_MANAGER_SYSTEM_H
#define NETWORK_MANAGER_SYSTEM_H

#include <netlink/route/rtnl.h>
#include <netlink/route/route.h>

#include <net/ethernet.h>

#include <glib.h>
#include "nm-device.h"
#include "nm-ip4-config.h"
#include "nm-setting-bond.h"
#include "nm-setting-vlan.h"

gboolean        nm_system_iface_flush_routes         (int ifindex, int family);

gboolean		nm_system_replace_default_ip4_route   (int ifindex,
                                                       guint32 gw,
                                                       guint32 mss);

gboolean		nm_system_replace_default_ip6_route   (int ifindex,
                                                       const struct in6_addr *gw);

gboolean		nm_system_replace_default_ip4_route_vpn (int ifindex,
                                                         guint32 ext_gw,
                                                         guint32 int_gw,
                                                         guint32 mss,
                                                         int parent_ifindex,
                                                         guint32 parent_mss);

gboolean		nm_system_replace_default_ip6_route_vpn (int ifindex,
                                                         const struct in6_addr *ext_gw,
                                                         const struct in6_addr *int_gw,
                                                         guint32 mss,
                                                         int parent_ifindex,
                                                         guint32 parent_mss);

struct rtnl_route *nm_system_add_ip4_vpn_gateway_route (NMDevice *parent_device,
                                                        guint32 vpn_gw);
struct rtnl_route *nm_system_add_ip6_vpn_gateway_route (NMDevice *parent_device,
                                                        const struct in6_addr *vpn_gw);

gboolean        nm_system_iface_flush_addresses         (int ifindex, int family);

gboolean		nm_system_apply_ip4_config              (int ifindex,
                                                         NMIP4Config *config,
                                                         int priority,
                                                         NMIP4ConfigCompareFlags flags);

int             nm_system_set_ip6_route                 (int ifindex,
                                                         const struct in6_addr *ip6_dest,
                                                         guint32 ip6_prefix,
                                                         const struct in6_addr *ip6_gateway,
                                                         guint32 metric,
                                                         int mss,
                                                         int protocol,
                                                         int table,
                                                         struct rtnl_route **out_route);

gboolean		nm_system_apply_ip6_config              (int ifindex,
                                                         NMIP6Config *config,
                                                         int priority,
                                                         NMIP6ConfigCompareFlags flags);

gboolean        nm_system_iface_set_up                  (int ifindex,
                                                         gboolean up,
                                                         gboolean *no_firmware);

guint32		nm_system_iface_get_flags		(int ifindex);
gboolean        nm_system_iface_is_up                   (int ifindex);

gboolean		nm_system_iface_set_mtu                 (int ifindex, guint32 mtu);

gboolean		nm_system_iface_set_mac                 (int ifindex, const struct ether_addr *mac);

gboolean        nm_system_iface_set_arp                 (int ifindex, gboolean arp);

gboolean        nm_system_apply_bonding_config          (const char *iface,
                                                         NMSettingBond *s_bond);
gboolean        nm_system_add_bonding_master            (const char *iface);

gboolean        nm_system_bond_enslave                  (gint master_ifindex,
                                                         const char *master_iface,
                                                         gint slave_ifindex,
                                                         const char *slave_iface);
gboolean        nm_system_bond_release                  (gint master_ifindex,
                                                         const char *master_iface,
                                                         gint slave_ifindex,
                                                         const char *slave_iface);

enum {
		NM_IFACE_TYPE_UNSPEC = 0,
		NM_IFACE_TYPE_BOND,
		NM_IFACE_TYPE_VLAN,
		NM_IFACE_TYPE_BRIDGE,
		NM_IFACE_TYPE_DUMMY
};

int             nm_system_get_iface_type      (int ifindex, const char *name);

gboolean        nm_system_get_iface_vlan_info (int ifindex,
                                               int *out_parent_ifindex,
                                               int *out_vlan_id);

gboolean        nm_system_add_vlan_iface (NMConnection *connection,
                                          const char *iface,
                                          int parent_ifindex);
gboolean        nm_system_del_vlan_iface (const char *iface);

gboolean        nm_system_create_bridge (const char *iface, gboolean *out_exists);
gboolean        nm_system_del_bridge (const char *iface);

gboolean        nm_system_bridge_attach (int master_ifindex,
                                         const char *master_iface,
                                         int slave_ifindex,
                                         const char *slave_iface);
gboolean        nm_system_bridge_detach (int master_ifindex,
                                         const char *master_iface,
                                         int slave_ifindex,
                                         const char *slave_iface);

#endif
