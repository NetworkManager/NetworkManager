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
 * Copyright (C) 2011 - 2012 Red Hat, Inc.
 */

#ifndef NM_NETLINK_COMPAT_H
#define NM_NETLINK_COMPAT_H

#include <netlink/route/route.h>

/* libnl-1 API compatibility for libnl-3 */
int rtnl_route_get_oif(struct rtnl_route *);
int rtnl_route_set_oif(struct rtnl_route *, int);
int rtnl_route_set_gateway(struct rtnl_route *, struct nl_addr *);
int rtnl_route_get_dst_len(struct rtnl_route *);
struct nl_addr * rtnl_route_get_gateway(struct rtnl_route *);

#endif /* NM_NETLINK_COMPAT_H */
