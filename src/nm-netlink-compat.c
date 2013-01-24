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
 * Copyright (C) 2011 Caixa Magica Software.
 */

#include <glib.h>

#include "nm-netlink-compat.h"

static struct rtnl_nexthop *
nm_netlink_get_nh (struct rtnl_route * route)
{
	int hops;

	hops = rtnl_route_get_nnexthops (route);
	g_return_val_if_fail(hops > 0, NULL);
	return rtnl_route_nexthop_n (route, 0);
}

int
rtnl_route_get_oif (struct rtnl_route * route)
{
	struct rtnl_nexthop * nh;

	nh = nm_netlink_get_nh(route);
	g_return_val_if_fail(nh, -NLE_OBJ_NOTFOUND);
	return rtnl_route_nh_get_ifindex (nh);
}

int
rtnl_route_set_oif (struct rtnl_route * route, int ifindex)
{
	struct rtnl_nexthop * nh;

	nh = rtnl_route_nh_alloc();
	rtnl_route_nh_set_ifindex(nh, ifindex);
	rtnl_route_add_nexthop(route, nh);
	return 0;
}

struct nl_addr *
rtnl_route_get_gateway (struct rtnl_route * route)
{
	struct rtnl_nexthop * nh;

	nh = nm_netlink_get_nh(route);
	g_return_val_if_fail(nh, NULL);
	return rtnl_route_nh_get_gateway(nh);
}

int
rtnl_route_set_gateway (struct rtnl_route * route, struct nl_addr * gw_addr)
{
	struct rtnl_nexthop * nh;

	nh = nm_netlink_get_nh(route);
	g_return_val_if_fail(nh, -NLE_OBJ_NOTFOUND);

	rtnl_route_nh_set_gateway(nh, gw_addr);
	return 0;
}

int
rtnl_route_get_dst_len(struct rtnl_route * rtnlroute)
{
	struct nl_addr * dst;

	dst = rtnl_route_get_dst(rtnlroute);
	return nl_addr_get_prefixlen(dst);
}
