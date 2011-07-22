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

#include "nm-netlink-utils.h"
#include "nm-netlink-monitor.h"

#include <netinet/in.h>
#include <netlink/netlink.h>
#include <netlink/addr.h>
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
	struct nl_handle *nlh = NULL;
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
		cache = rtnl_addr_alloc_cache (nlh);
		if (cache) {
			nl_cache_mngt_provide (cache);
			nl_cache_foreach (cache, find_one_address, &info);
			nl_cache_free (cache);
		}
	}
	return info.found;
}

