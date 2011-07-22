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
 * Copyright (C) 2011 Red Hat, Inc.
 */

#ifndef NM_NETLINK_UTILS_H
#define NM_NETLINK_UTILS_H

#include <glib.h>
#include <netlink/route/rtnl.h>
#include <netlink/route/route.h>

gboolean nm_netlink_find_address (int ifindex,
                                  int family,
                                  void *addr,  /* struct in_addr or struct in6_addr */
                                  int prefix_);

gboolean nm_netlink_route_delete (struct rtnl_route *route);

#endif  /* NM_NETLINK_MONITOR_H */
