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

#include "logging/nm-logging.h"
#include "nm-netlink-utils.h"
#include "nm-netlink-monitor.h"
#include "nm-netlink-compat.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netlink/route/addr.h>

typedef struct {
	int ifindex;
	int family;
	void *addr;
	int addrlen;
	int prefix;
	gboolean found;
} FindAddrInfo;

static void
find_one_address (struct nl_object *object, void *user_data)
{
	FindAddrInfo *info = user_data;
	struct rtnl_addr *addr = (struct rtnl_addr *) object;
	struct nl_addr *local;
	void *binaddr;

	if (info->found)
		return;

	if (rtnl_addr_get_ifindex (addr) != info->ifindex)
		return;
	if (rtnl_addr_get_family (addr) != info->family)
		return;

	if (rtnl_addr_get_prefixlen (addr) != info->prefix)
		return;

	local = rtnl_addr_get_local (addr);
	if (nl_addr_get_family (local) != info->family)
		return;
	if (nl_addr_get_len (local) != info->addrlen)
		return;
	binaddr = nl_addr_get_binary_addr (local);
	if (binaddr) {
		if (memcmp (binaddr, info->addr, info->addrlen) == 0)
			info->found = TRUE; /* Yay, found it */
	}
}

/**
 * nm_netlink_find_address:
 * @ifindex: interface index
 * @family: address family, either AF_INET or AF_INET6
 * @addr: binary address, either struct in_addr* or struct in6_addr*
 * @prefix: prefix length
 *
 * Searches for a matching address on the given interface.
 *
 * Returns: %TRUE if the given address was found on the interface, %FALSE if it
 * was not found or an error occurred.
 **/
gboolean
nm_netlink_find_address (int ifindex,
                         int family,
                         void *addr,  /* struct in_addr or struct in6_addr */
                         int prefix)
{
	struct nl_sock *nlh = NULL;
	struct nl_cache *cache = NULL;
	FindAddrInfo info;

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (family == AF_INET || family == AF_INET6, FALSE);
	g_return_val_if_fail (addr != NULL, FALSE);
	g_return_val_if_fail (prefix >= 0, FALSE);

	memset (&info, 0, sizeof (info));
	info.ifindex = ifindex;
	info.family = family;
	info.prefix = prefix;
	info.addr = addr;
	if (family == AF_INET)
		info.addrlen = sizeof (struct in_addr);
	else if (family == AF_INET6)
		info.addrlen = sizeof (struct in6_addr);
	else
		g_assert_not_reached ();

	nlh = nm_netlink_get_default_handle ();
	if (nlh) {
		rtnl_addr_alloc_cache(nlh, &cache);
		if (cache) {
			nl_cache_mngt_provide (cache);
			nl_cache_foreach (cache, find_one_address, &info);
			nl_cache_free (cache);
		}
	}
	return info.found;
}

struct rtnl_route *
nm_netlink_route_new (int ifindex,
                      int family,
                      int mss,
                      ...)
{
	va_list var_args;
	struct rtnl_route *route;
	NmNlProp prop = NMNL_PROP_INVALID;
	int value;

	route = rtnl_route_alloc ();
	g_return_val_if_fail (route != NULL, NULL);

	if (ifindex > 0)
		rtnl_route_set_oif (route, ifindex);
	if (family != AF_UNSPEC)
		rtnl_route_set_family (route, family);
	if (mss > 0)
		rtnl_route_set_metric (route, RTAX_ADVMSS, mss);

	va_start (var_args, mss);
	prop = va_arg (var_args, NmNlProp);
	while (prop != NMNL_PROP_INVALID) {
		value = va_arg (var_args, int);

		if (prop == NMNL_PROP_PROT && value != RTPROT_UNSPEC)
			rtnl_route_set_protocol (route, value);
		else if (prop == NMNL_PROP_TABLE && value != RT_TABLE_UNSPEC)
			rtnl_route_set_table (route, value);
		else if (prop == NMNL_PROP_SCOPE && value != RT_SCOPE_NOWHERE)
			rtnl_route_set_scope (route, value);
		else if (prop == NMNL_PROP_PRIO && value > 0)
			rtnl_route_set_priority (route, value);

		prop = va_arg (var_args, NmNlProp);
	}
	va_end (var_args);

	return route;
}

/**
 * _route_add:
 * @route: the route to add
 * @family: address family, either %AF_INET or %AF_INET6
 * @dest: the route destination address, either a struct in_addr or a struct
 *   in6_addr depending on @family
 * @dest_prefix: the CIDR prefix of @dest
 * @gateway: the gateway through which to reach @dest, if any; given as a
 *   struct in_addr or struct in6_addr depending on @family
 * @flags: flags to pass to rtnl_route_add(), eg %NLM_F_REPLACE
 *
 * Returns: zero if succeeded or the netlink error otherwise.
 **/
static int
_route_add (struct rtnl_route *route,
            int family,
            const void *dest, /* in_addr or in6_addr */
            int dest_prefix,
            const void *gateway, /* in_addr or in6_addr */
            int flags)
{
	struct nl_sock *sk;
	struct nl_addr *dest_addr, *gw_addr;
	void *tmp_addr;
	int addrlen, err, log;

	if (family == AF_INET) {
		addrlen = sizeof (struct in_addr);
		log = LOGD_IP4;
	} else if (family == AF_INET6) {
		addrlen = sizeof (struct in6_addr);
		log = LOGD_IP6;
	} else
		g_assert_not_reached ();

	sk = nm_netlink_get_default_handle ();

	/* Build up the destination address */
	if (dest) {
		/* Copy to preserve const */
		tmp_addr = g_malloc0 (addrlen);
		memcpy (tmp_addr, dest, addrlen);

		dest_addr = nl_addr_build (family, tmp_addr, addrlen);
		g_free (tmp_addr);

		g_return_val_if_fail (dest_addr != NULL, -NLE_INVAL);
		nl_addr_set_prefixlen (dest_addr, dest_prefix);

		rtnl_route_set_dst (route, dest_addr);
		nl_addr_put (dest_addr);
	}

	/* Build up the gateway address */
	if (gateway) {
		tmp_addr = g_malloc0 (addrlen);
		memcpy (tmp_addr, gateway, addrlen);

		gw_addr = nl_addr_build (family, tmp_addr, addrlen);
		g_free (tmp_addr);

		if (gw_addr) {
			nl_addr_set_prefixlen (gw_addr, 0);
			rtnl_route_set_gateway (route, gw_addr);
			rtnl_route_set_scope (route, RT_SCOPE_UNIVERSE);
			nl_addr_put (gw_addr);
		} else
			nm_log_err (LOGD_DEVICE | log, "Invalid gateway");
	}

	err = rtnl_route_add (sk, route, flags);

	/* LIBNL Bug: Aliased ESRCH */
	if (err == -NLE_FAILURE)
		err = -NLE_OBJ_NOTFOUND;

	return err;
}

/**
 * nm_netlink_route4_add:
 * @route: the route to add
 * @dest: the route destination address in network byte order
 * @dest_prefix: the CIDR prefix of @dest
 * @gateway: the gateway through which to reach @dest, if any, in network byte order
 * @flags: flags to pass to rtnl_route_add(), eg %NLM_F_REPLACE
 *
 * Adds an IPv4 route with the given parameters.
 *
 * Returns: zero if succeeded or the netlink error otherwise.
 **/
int
nm_netlink_route4_add (struct rtnl_route *route,
                       guint32 *dst,
                       int prefix,
                       guint32 *gw,
                       int flags)
{
	return _route_add (route, AF_INET, dst, prefix, gw, flags);
}

/**
 * nm_netlink_route6_add:
 * @route: the route to add
 * @dest: the route destination address
 * @dest_prefix: the CIDR prefix of @dest
 * @gateway: the gateway through which to reach @dest, if any
 * @flags: flags to pass to rtnl_route_add(), eg %NLM_F_REPLACE
 *
 * Adds an IPv6 route with the given parameters.
 *
 * Returns: zero if succeeded or the netlink error otherwise.
 **/
int
nm_netlink_route6_add (struct rtnl_route *route,
                       const struct in6_addr *dst,
                       int prefix,
                       const struct in6_addr *gw,
                       int flags)
{
	return _route_add (route, AF_INET6, dst, prefix, gw, flags);
}

/**
 * nm_netlink_route_delete:
 * @route: the route to delete
 *
 * Returns: %TRUE if the request was successful, %FALSE if it failed
 **/
gboolean
nm_netlink_route_delete (struct rtnl_route *route)
{
	struct nl_sock *nlh;
	int err = 0;

	g_return_val_if_fail (route != NULL, FALSE);

	nlh = nm_netlink_get_default_handle ();
	err = rtnl_route_delete (nlh, route, 0);

	if (err)
		nm_log_dbg (LOGD_IP4 | LOGD_IP6, "%s (%d)", nl_geterror(err), err);

	/* Workaround libnl BUG: ESRCH is aliased to generic NLE_FAILURE
	 * See: http://git.kernel.org/?p=libs/netlink/libnl.git;a=commit;h=7e9d5f */
	if (err == -NLE_FAILURE)
		err = -NLE_OBJ_NOTFOUND;

	return (err && (err != -NLE_OBJ_NOTFOUND) && (err != -NLE_RANGE) ) ? FALSE : TRUE;
}


static void
dump_route (struct rtnl_route *route)
{
	char buf6[INET6_ADDRSTRLEN];
	char buf4[INET_ADDRSTRLEN];
	struct nl_addr *nl;
	struct in6_addr *addr6 = NULL;
	struct in_addr *addr4 = NULL;
	int prefixlen = 0;
	const char *sf = "UNSPEC";
	int family = rtnl_route_get_family (route);
	guint32 log_level = LOGD_IP4 | LOGD_IP6;

	memset (buf6, 0, sizeof (buf6));
	memset (buf4, 0, sizeof (buf4));
	nl = rtnl_route_get_dst (route);
	if (nl) {
		if (nl_addr_get_family (nl) == AF_INET) {
			addr4 = nl_addr_get_binary_addr (nl);
			if (addr4)
				inet_ntop (AF_INET, addr4, &buf4[0], sizeof (buf4));
		} else if (nl_addr_get_family (nl) == AF_INET6) {
			addr6 = nl_addr_get_binary_addr (nl);
			if (addr6)
				inet_ntop (AF_INET6, addr6, &buf6[0], sizeof (buf6));
		}
		prefixlen = nl_addr_get_prefixlen (nl);
	}

	if (family == AF_INET) {
		sf = "INET";
		log_level = LOGD_IP4;
	} else if (family == AF_INET6) {
		sf = "INET6";
		log_level = LOGD_IP6;
	}

	nm_log_dbg (log_level, "  route idx %d family %s (%d) addr %s/%d",
	            rtnl_route_get_oif (route),
	            sf, family,
	            strlen (buf4) ? buf4 : (strlen (buf6) ? buf6 : "<unknown>"),
	            prefixlen);
}


typedef struct {
	int ifindex;
	int family;
	int scope;
	gboolean ignore_inet6_ll_mc;
	char *iface;
	NlRouteForeachFunc callback;
	gpointer user_data;
	struct rtnl_route *out_route;
} ForeachRouteInfo;

static void
foreach_route_cb (struct nl_object *object, void *user_data)
{
	ForeachRouteInfo *info = user_data;
	struct rtnl_route *route = (struct rtnl_route *) object;
	struct nl_addr *dst;

	if (info->out_route)
		return;

	if (nm_logging_level_enabled (LOGL_DEBUG))
		dump_route (route);

	if (   info->ifindex > 0
	    && rtnl_route_get_oif (route) != info->ifindex)
		return;

	if (   info->scope != RT_SCOPE_UNIVERSE
	    && rtnl_route_get_scope (route) != info->scope)
		return;

	if (   info->family != AF_UNSPEC
	    && rtnl_route_get_family (route) != info->family)
		return;

	dst = rtnl_route_get_dst (route);

	/* Check for IPv6 LL and MC routes that might need to be ignored */
	if (   (info->family == AF_INET6 || info->family == AF_UNSPEC)
	    && (rtnl_route_get_family (route) == AF_INET6)) {
		struct in6_addr *addr = NULL;

		if (dst)
			addr = nl_addr_get_binary_addr (dst);
		if (addr) {
			if (   IN6_IS_ADDR_LINKLOCAL (addr)
			    || IN6_IS_ADDR_MC_LINKLOCAL (addr)
			    || (IN6_IS_ADDR_MULTICAST (addr) && (nl_addr_get_prefixlen (dst) == 8)))
				return;
		}
	}

	info->out_route = info->callback (route, dst, info->iface, info->user_data);
	if (info->out_route) {
		/* Ref the route so it sticks around after the cache is cleared */
		rtnl_route_get (info->out_route);
	}
}

/**
 * nm_netlink_foreach_route:
 * @ifindex: the interface index to filter routes for
 * @family: the address family to filter routes for
 * @scope: route scope, eg RT_SCOPE_LINK
 * @ignore_inet6_ll_mc: if %TRUE ignore IPv6 link-local and multi-cast routes
 * @callback: function called when a route matches the filter
 * @user_data: data passed to @callback
 *
 * Filters each route in the routing table against the given @ifindex and
 * @family (if given) and calls @callback for each matching route.
 *
 * Returns: a route if @callback returned one; the caller must dispose of the
 * route using rtnl_route_put() when it is no longer required.
 **/
struct rtnl_route *
nm_netlink_foreach_route (int ifindex,
                          int family,
                          int scope,
                          gboolean ignore_inet6_ll_mc,
                          NlRouteForeachFunc callback,
                          gpointer user_data)
{
	struct nl_cache *cache;
	ForeachRouteInfo info;

	memset (&info, 0, sizeof (info));
	info.ifindex = ifindex;
	info.family = family;
	info.scope = scope;
	info.ignore_inet6_ll_mc = ignore_inet6_ll_mc;
	info.callback = callback;
	info.user_data = user_data;
	info.iface = nm_netlink_index_to_iface (ifindex);

	rtnl_route_alloc_cache (nm_netlink_get_default_handle (), family, NL_AUTO_PROVIDE, &cache);
	g_warn_if_fail (cache != NULL);
	if (cache) {
		nl_cache_foreach (cache, foreach_route_cb, &info);
		nl_cache_free (cache);
	}
	g_free (info.iface);
	return info.out_route;
}


