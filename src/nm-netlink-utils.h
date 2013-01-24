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

#include <netlink/route/route.h>

gboolean nm_netlink_find_address (int ifindex,
                                  int family,
                                  void *addr,  /* struct in_addr or struct in6_addr */
                                  int prefix_);

typedef enum {
	NMNL_PROP_INVALID = 0,
	NMNL_PROP_PROT,
	NMNL_PROP_SCOPE,
	NMNL_PROP_TABLE,
	NMNL_PROP_PRIO,
} NmNlProp;

struct rtnl_route * nm_netlink_route_new (int ifindex,
                                          int family,
                                          int mss,
                                          ...) __attribute__((__sentinel__));

int nm_netlink_route4_add (struct rtnl_route *route,
                           guint32 *dst,
                           int prefix,
                           guint32 *gw,
                           int flags);

int nm_netlink_route6_add (struct rtnl_route *route,
                          const struct in6_addr *dst,
                          int prefix,
                          const struct in6_addr *gw,
                          int flags);

gboolean nm_netlink_route_delete (struct rtnl_route *route);

/**
 * NlRouteForeachFunc:
 * @route: the route being processed
 * @dst: the route's destination address
 * @iface: the interface name of the index passed to nm_netlink_foreach_route()
 * @in_family: the address family passed to nm_netlink_foreach_route()
 * @user_data: the user data pointer passed to nm_netlink_foreach_route()
 *
 * Returns: a route to return to the caller of nm_netlink_foreach_route() which
 * terminates routing table iteration, or NULL to continue iterating the
 * routing table.
 **/
typedef struct rtnl_route * (*NlRouteForeachFunc) (struct rtnl_route *route,
                                                   struct nl_addr *dst,
                                                   const char *iface,
                                                   gpointer user_data);

struct rtnl_route * nm_netlink_foreach_route (int ifindex,
                                              int family,
                                              int scope,
                                              gboolean ignore_inet6_ll_mc,
                                              NlRouteForeachFunc callback,
                                              gpointer user_data);

#endif  /* NM_NETLINK_UTILS_H */

