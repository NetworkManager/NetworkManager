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

#include <glib.h>
#include <netlink/route/route.h>

#include "nm-device.h"
#include "nm-ip4-config.h"
#include "nm-setting-bond.h"

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

gboolean        nm_system_apply_bonding_config          (const char *iface,
                                                         NMSettingBond *s_bond);
#endif
