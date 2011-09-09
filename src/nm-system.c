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
 * Copyright (C) 1996 - 1997 Yoichi Hariguchi <yoichi@fore.com>
 * Copyright (C) January, 1998 Sergei Viznyuk <sv@phystech.com>
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <net/route.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <resolv.h>
#include <netdb.h>
#include <glib.h>
#include <ctype.h>
#include <net/if.h>

#include "nm-system.h"
#include "nm-device.h"
#include "NetworkManagerUtils.h"
#include "nm-utils.h"
#include "nm-logging.h"
#include "nm-netlink-monitor.h"
#include "nm-netlink-utils.h"
#include "nm-netlink-compat.h"

#include <netlink/route/addr.h>
#include <netlink/route/route.h>
#include <netlink/netlink.h>
#include <netlink/utils.h>
#include <netlink/route/link.h>

static void nm_system_device_set_priority (int ifindex,
                                           NMIP4Config *config,
                                           int priority);

static gboolean
ip4_dest_in_same_subnet (NMIP4Config *config, guint32 dest, guint32 dest_prefix)
{
	int num;
	int i;

	num = nm_ip4_config_get_num_addresses (config);
	for (i = 0; i < num; i++) {
		NMIP4Address *addr = nm_ip4_config_get_address (config, i);
		guint32 prefix = nm_ip4_address_get_prefix (addr);
		guint32 address = nm_ip4_address_get_address (addr);

		if (prefix <= dest_prefix) {
			guint32 masked_addr = ntohl(address) >> (32 - prefix);
			guint32 masked_dest = ntohl(dest) >> (32 - prefix);

			if (masked_addr == masked_dest)
				return TRUE;
		}
	}

	return FALSE;
}

static struct rtnl_route *
nm_system_device_set_ip4_route (int ifindex, 
                                guint32 ip4_dest,
                                guint32 ip4_prefix,
                                guint32 ip4_gateway,
                                guint32 metric,
                                int mss)
{
	struct nl_sock *nlh;
	struct rtnl_route *route;
	int err;
	const char *iface;

	g_return_val_if_fail (ifindex > 0, NULL);

	nlh = nm_netlink_get_default_handle ();
	g_return_val_if_fail (nlh != NULL, NULL);

	iface = nm_netlink_index_to_iface (ifindex);
	g_return_val_if_fail (iface != NULL, NULL);

	route = nm_netlink_route_new (ifindex, AF_INET, mss,
	                              NMNL_PROP_PRIO, metric,
	                              NULL);
	g_return_val_if_fail (route != NULL, NULL);

	/* Add the route */
	err = nm_netlink_route_add(route, AF_INET, &ip4_dest, ip4_prefix, &ip4_gateway, 0);
	if (err == -NLE_OBJ_NOTFOUND && ip4_gateway) {
		/* Gateway might be over a bridge; try adding a route to gateway first */
		struct rtnl_route *route2;

		route2 = nm_netlink_route_new (ifindex, AF_INET, mss, NULL);
		if (route2) {
			/* Add route to gateway over bridge */
			err = nm_netlink_route_add(route2, AF_INET, &ip4_gateway, 32, NULL, 0);
			if (!err) {
				err = nm_netlink_route_add(route, AF_INET, &ip4_dest, ip4_prefix, &ip4_gateway, 0);
				if (err)
					nm_netlink_route_delete (route2);
			}
			rtnl_route_put (route2);
		}
	}

	if (err) {
		nm_log_err (LOGD_DEVICE | LOGD_IP4,
		            "(%s): failed to set IPv4 route: %s",
		            iface, nl_geterror (err));
		rtnl_route_put (route);
		route = NULL;
	}

	return route;
}

static gboolean
sync_addresses (int ifindex,
                int family,
				struct rtnl_addr **addrs,
				int num_addrs)
{
	struct nl_sock *nlh;
	struct nl_cache *addr_cache;
	struct rtnl_addr *filter_addr, *match_addr;
	struct nl_object *match;
	struct nl_addr *nladdr;
	int i, err;
	guint32 log_domain = (family == AF_INET) ? LOGD_IP4 : LOGD_IP6;
	char buf[INET6_ADDRSTRLEN + 1];
	const char *iface;

	iface = nm_netlink_index_to_iface (ifindex);
	g_return_val_if_fail (iface != NULL, FALSE);

	log_domain |= LOGD_DEVICE;

	nlh = nm_netlink_get_default_handle ();
	if (!nlh)
		return FALSE;

	err = rtnl_addr_alloc_cache (nlh, &addr_cache);
	if (err < 0)
		return FALSE;

	filter_addr = rtnl_addr_alloc ();
	if (!filter_addr) {
		nl_cache_free (addr_cache);
		return FALSE;
	}
	rtnl_addr_set_ifindex (filter_addr, ifindex);
	if (family)
		rtnl_addr_set_family (filter_addr, family);

	nm_log_dbg (log_domain, "(%s): syncing addresses (family %d)", iface, family);

	/* Walk through the cache, comparing the addresses already on
	 * the interface to the addresses in addrs.
	 */
	for (match = nl_cache_get_first (addr_cache); match; match = nl_cache_get_next (match)) {
		gboolean buf_valid = FALSE;
		match_addr = (struct rtnl_addr *) match;

		/* Skip addresses not on our interface */
		if (!nl_object_match_filter (match, (struct nl_object *) filter_addr))
			continue;

		if (addrs) {
			for (i = 0; i < num_addrs; i++) {
				if (addrs[i] && nl_object_identical (match, (struct nl_object *) addrs[i]))
					break;
			}

			if (addrs[i]) {
				/* match == addrs[i], so remove it from addrs so we don't
				 * try to add it to the interface again below.
				 */
				rtnl_addr_put (addrs[i]);
				addrs[i] = NULL;
				continue;
			}
		}

		nladdr = rtnl_addr_get_local (match_addr);

		/* Don't delete IPv6 link-local addresses; they don't belong to NM */
		if (rtnl_addr_get_family (match_addr) == AF_INET6) {
			struct in6_addr *tmp;

			if (rtnl_addr_get_scope (match_addr) == RT_SCOPE_LINK) {
				nm_log_dbg (log_domain, "(%s): ignoring IPv6 link-local address", iface);
				continue;
			}

			tmp = nl_addr_get_binary_addr (nladdr);
			if (inet_ntop (AF_INET6, tmp, buf, sizeof (buf)))
				buf_valid = TRUE;
		} else if (rtnl_addr_get_family (match_addr) == AF_INET) {
			struct in_addr *tmp;

			tmp = nl_addr_get_binary_addr (nladdr);
			if (inet_ntop (AF_INET, tmp, buf, sizeof (buf)))
				buf_valid = TRUE;
		}

		if (buf_valid) {
			nm_log_dbg (log_domain, "(%s): removing address '%s/%d'",
			            iface, buf, nl_addr_get_prefixlen (nladdr));
		}

		/* Otherwise, match_addr should be removed from the interface. */
		err = rtnl_addr_delete (nlh, match_addr, 0);
		if (err < 0) {
			nm_log_err (log_domain, "(%s): error %d returned from rtnl_addr_delete(): %s",
						iface, err, nl_geterror (err));
		}
	}

	rtnl_addr_put (filter_addr);
	nl_cache_free (addr_cache);

	/* Now add the remaining new addresses */
	for (i = 0; i < num_addrs; i++) {
		struct in6_addr *in6tmp;
		struct in_addr *in4tmp;
		gboolean buf_valid = FALSE;

		if (!addrs[i])
			continue;

		nladdr = rtnl_addr_get_local (addrs[i]);
		if (rtnl_addr_get_family (addrs[i]) == AF_INET6) {
			in6tmp = nl_addr_get_binary_addr (nladdr);
			if (inet_ntop (AF_INET6, in6tmp, buf, sizeof (buf)))
				buf_valid = TRUE;
		} else if (rtnl_addr_get_family (addrs[i]) == AF_INET) {
			in4tmp = nl_addr_get_binary_addr (nladdr);
			if (inet_ntop (AF_INET, in4tmp, buf, sizeof (buf)))
				buf_valid = TRUE;
		}

		if (buf_valid) {
			nm_log_dbg (log_domain, "(%s): adding address '%s/%d'",
			            iface, buf, nl_addr_get_prefixlen (nladdr));
		}

		err = rtnl_addr_add (nlh, addrs[i], 0);
		if (err < 0 && (err != -NLE_EXIST)) {
			nm_log_err (log_domain,
			            "(%s): error %d returned from rtnl_addr_add():\n%s",
			            iface, err, nl_geterror (err));
		}

		rtnl_addr_put (addrs[i]);
	}
	g_free (addrs);

	return TRUE;
}

static gboolean
add_ip4_addresses (NMIP4Config *config, const char *iface)
{
	int num_addrs, i, iface_idx;
	guint32 flags = 0;
	gboolean did_gw = FALSE;
	struct rtnl_addr **addrs;

	iface_idx = nm_netlink_iface_to_index (iface);

	num_addrs = nm_ip4_config_get_num_addresses (config);
	addrs = g_new0 (struct rtnl_addr *, num_addrs + 1);

	for (i = 0; i < num_addrs; i++) {
		NMIP4Address *addr;

		addr = nm_ip4_config_get_address (config, i);
		g_assert (addr);

		flags = NM_RTNL_ADDR_DEFAULT;
		if (nm_ip4_address_get_gateway (addr) && !did_gw) {
			if (nm_ip4_config_get_ptp_address (config))
				flags |= NM_RTNL_ADDR_PTP_ADDR;
			did_gw = TRUE;
		}

		addrs[i] = nm_ip4_config_to_rtnl_addr (config, i, flags);
		if (!addrs[i]) {
			nm_log_warn (LOGD_DEVICE | LOGD_IP4,
			             "(%s): couldn't create rtnl address!",
			             iface);
			continue;
		}
		rtnl_addr_set_ifindex (addrs[i], iface_idx);
	}

	return sync_addresses (iface_idx, AF_INET, addrs, num_addrs);
}

struct rtnl_route *
nm_system_add_ip4_vpn_gateway_route (NMDevice *parent_device, NMIP4Config *vpn_config)
{
	NMIP4Config *parent_config;
	guint32 parent_gw = 0, parent_prefix = 0, vpn_gw = 0, i;
	NMIP4Address *tmp;
	struct rtnl_route *route = NULL;

	g_return_val_if_fail (NM_IS_DEVICE (parent_device), NULL);

	/* Set up a route to the VPN gateway's public IP address through the default
	 * network device if the VPN gateway is on a different subnet.
	 */

	parent_config = nm_device_get_ip4_config (parent_device);
	g_return_val_if_fail (parent_config != NULL, NULL);

	for (i = 0; i < nm_ip4_config_get_num_addresses (parent_config); i++) {
		tmp = nm_ip4_config_get_address (parent_config, i);
		if (nm_ip4_address_get_gateway (tmp)) {
			parent_gw = nm_ip4_address_get_gateway (tmp);
			parent_prefix = nm_ip4_address_get_prefix (tmp);
			break;
		}
	}

	for (i = 0; i < nm_ip4_config_get_num_addresses (vpn_config); i++) {
		tmp = nm_ip4_config_get_address (vpn_config, i);
		if (nm_ip4_address_get_gateway (tmp)) {
			vpn_gw = nm_ip4_address_get_gateway (tmp);
			break;
		}
	}

	if (!parent_gw || !vpn_gw)
		return NULL;

	/* If the VPN gateway is in the same subnet as one of the parent device's
	 * IP addresses, don't add the host route to it, but a route through the
	 * parent device.
	 */
	if (ip4_dest_in_same_subnet (parent_config, vpn_gw, parent_prefix)) {
		route = nm_system_device_set_ip4_route (nm_device_get_ip_ifindex (parent_device),
		                                        vpn_gw, 32, 0, 0, nm_ip4_config_get_mss (parent_config));
	} else {
		route = nm_system_device_set_ip4_route (nm_device_get_ip_ifindex (parent_device),
		                                        vpn_gw, 32, parent_gw, 0, nm_ip4_config_get_mss (parent_config));
	}

	return route;
}

/*
 * nm_system_apply_ip4_config
 *
 * Set IPv4 configuration of the device from an NMIP4Config object.
 *
 */
gboolean
nm_system_apply_ip4_config (int ifindex,
                            NMIP4Config *config,
                            int priority,
                            NMIP4ConfigCompareFlags flags)
{
	const char *iface;
	int i;

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (config != NULL, FALSE);

	iface = nm_netlink_index_to_iface (ifindex);
	g_return_val_if_fail (iface != NULL, FALSE);

	if (flags & NM_IP4_COMPARE_FLAG_ADDRESSES) {
		if (!add_ip4_addresses (config, iface))
			return FALSE;
		sleep (1);
	}

	if (flags & NM_IP4_COMPARE_FLAG_ROUTES) {
		for (i = 0; i < nm_ip4_config_get_num_routes (config); i++) {
			NMIP4Route *route = nm_ip4_config_get_route (config, i);
			struct rtnl_route *tmp;

			/* Don't add the route if it's more specific than one of the subnets
			 * the device already has an IP address on.
			 */
			if (ip4_dest_in_same_subnet (config,
			                             nm_ip4_route_get_dest (route),
			                             nm_ip4_route_get_prefix (route)))
				continue;

			/* Don't add the route if it doesn't have a gateway and the connection
			 * is never supposed to be the default connection.
			 */
			if (   nm_ip4_config_get_never_default (config)
			    && nm_ip4_route_get_dest (route) == 0)
				continue;

			tmp = nm_system_device_set_ip4_route (ifindex,
			                                      nm_ip4_route_get_dest (route),
			                                      nm_ip4_route_get_prefix (route),
			                                      nm_ip4_route_get_next_hop (route),
			                                      nm_ip4_route_get_metric (route),
			                                      nm_ip4_config_get_mss (config));
			rtnl_route_put (tmp);
		}
	}

	if (flags & NM_IP4_COMPARE_FLAG_MTU) {
		if (nm_ip4_config_get_mtu (config))
			nm_system_iface_set_mtu (ifindex, nm_ip4_config_get_mtu (config));
	}

	if (priority > 0)
		nm_system_device_set_priority (ifindex, config, priority);

	return TRUE;
}

int
nm_system_set_ip6_route (int ifindex,
                         const struct in6_addr *ip6_dest,
                         guint32 ip6_prefix,
                         const struct in6_addr *ip6_gateway,
                         guint32 metric,
                         int mss,
                         int protocol,
                         int table,
                         struct rtnl_route **out_route)
{
	struct nl_sock *nlh;
	struct rtnl_route *route;
	int err = 0;

	g_return_val_if_fail (ifindex >= 0, -1);

	nlh = nm_netlink_get_default_handle ();
	g_return_val_if_fail (nlh != NULL, -1);

	route = nm_netlink_route_new (ifindex, AF_INET6, mss,
	                              NMNL_PROP_PROT, protocol,
	                              NMNL_PROP_PRIO, metric,
	                              NMNL_PROP_TABLE, table,
	                              NULL);
	g_return_val_if_fail (route != NULL, -1);

	/* Add the route */
	err = nm_netlink_route_add(route, AF_INET6, &ip6_dest, ip6_prefix, &ip6_gateway, 0);
	if (err == -NLE_OBJ_NOTFOUND && ip6_gateway) {
		/* Gateway might be over a bridge; try adding a route to gateway first */
		struct rtnl_route *route2;

		route2 = nm_netlink_route_new (ifindex, AF_INET6, mss, NULL);
		if (route2) {
			err = nm_netlink_route_add(route, AF_INET6, &ip6_gateway, 128, NULL, 0);
			/* Add route to gateway over bridge */
			if (!err) {
				/* Try adding the route again */
				err = nm_netlink_route_add(route, AF_INET6, &ip6_dest, ip6_prefix, &ip6_gateway, 0);
				if (err)
					nm_netlink_route_delete (route2);
			}
			rtnl_route_put (route2);
		}
	}

	if (out_route)
		*out_route = route;
	else
		rtnl_route_put (route);

	return err;
}

static gboolean
add_ip6_addresses (NMIP6Config *config, const char *iface)
{
	int num_addrs, i, iface_idx;
	struct rtnl_addr **addrs;

	iface_idx = nm_netlink_iface_to_index (iface);

	num_addrs = nm_ip6_config_get_num_addresses (config);
	addrs = g_new0 (struct rtnl_addr *, num_addrs + 1);

	for (i = 0; i < num_addrs; i++) {
		NMIP6Address *addr;

		addr = nm_ip6_config_get_address (config, i);
		g_assert (addr);

		addrs[i] = nm_ip6_config_to_rtnl_addr (config, i, NM_RTNL_ADDR_DEFAULT);
		if (!addrs[i]) {
			nm_log_warn (LOGD_DEVICE | LOGD_IP6,
			             "(%s): couldn't create rtnl address!",
			             iface);
			continue;
		}
		rtnl_addr_set_ifindex (addrs[i], iface_idx);
	}

	return sync_addresses (iface_idx, AF_INET6, addrs, num_addrs);
}

/*
 * nm_system_apply_ip6_config
 *
 * Set IPv6 configuration of the device from an NMIP6Config object.
 *
 */
gboolean
nm_system_apply_ip6_config (int ifindex,
                            NMIP6Config *config,
                            int priority,
                            NMIP6ConfigCompareFlags flags)
{
	const char *iface;
	int i;

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (config != NULL, FALSE);

	iface = nm_netlink_index_to_iface (ifindex);
	g_return_val_if_fail (iface != NULL, FALSE);

	if (flags & NM_IP6_COMPARE_FLAG_ADDRESSES) {
		if (!add_ip6_addresses (config, iface))
			return FALSE;
		sleep (1); // FIXME?
	}

	if (flags & NM_IP6_COMPARE_FLAG_ROUTES) {
		for (i = 0; i < nm_ip6_config_get_num_routes (config); i++) {
			NMIP6Route *route = nm_ip6_config_get_route (config, i);
			int err;

			/* Don't add the route if it doesn't have a gateway and the connection
			 * is never supposed to be the default connection.
			 */
			if (   nm_ip6_config_get_never_default (config)
			    && IN6_IS_ADDR_UNSPECIFIED (nm_ip6_route_get_dest (route)))
				continue;

			err = nm_system_set_ip6_route (ifindex,
			                               nm_ip6_route_get_dest (route),
			                               nm_ip6_route_get_prefix (route),
			                               nm_ip6_route_get_next_hop (route),
			                               nm_ip6_route_get_metric (route),
			                               nm_ip6_config_get_mss (config),
			                               RTPROT_UNSPEC,
			                               RT_TABLE_UNSPEC,
			                               NULL);
			if (err) {
				nm_log_err (LOGD_DEVICE | LOGD_IP6,
				            "(%s): failed to set IPv6 route: %s",
				            iface, nl_geterror (err));
			}
		}
	}

// FIXME
//	if (priority > 0)
//		nm_system_device_set_priority (iface, config, priority);

	return TRUE;
}

/**
 * nm_system_iface_set_up:
 * @ifindex: interface index
 * @up: %TRUE to bring interface up, or %FALSE to take it down
 * @no_firmware: on return, %TRUE if the operation may have failed due to
 * missing firmware
 *
 * Bring the interface up or take it down.
 *
 * Returns: %TRUE on success, %FALSE on failure
 **/
gboolean
nm_system_iface_set_up (int ifindex,
                        gboolean up,
                        gboolean *no_firmware)
{
	struct rtnl_link *request = NULL, *old = NULL;
	struct nl_sock *nlh;
	gboolean success = FALSE;
	int err;

	g_return_val_if_fail (ifindex > 0, FALSE);
	if (no_firmware)
		g_return_val_if_fail (*no_firmware == FALSE, FALSE);

	if (!(request = rtnl_link_alloc ()))
		return FALSE;

	if (up)
		rtnl_link_set_flags (request, IFF_UP);
	else
		rtnl_link_unset_flags (request, IFF_UP);

	old = nm_netlink_index_to_rtnl_link (ifindex);
	if (old) {
		nlh = nm_netlink_get_default_handle ();
		if (nlh) {
			err = rtnl_link_change (nlh, old, request, 0);
			if (err == 0) {
				success = TRUE;
			} else {
				if ((err == -NLE_OBJ_NOTFOUND) && no_firmware && up)
					*no_firmware = TRUE;
			}
		}
	}

	rtnl_link_put (old);
	rtnl_link_put (request);
	return success;
}

/**
 * nm_system_iface_is_up:
 * @ifindex: interface index
 *
 * Returns: %TRUE if the interface is up, %FALSE if it was down or the check
 * failed.
 **/
gboolean
nm_system_iface_is_up (int ifindex)
{
	const char *iface;
	struct rtnl_link *l;
	guint32 flags;

	g_return_val_if_fail (ifindex > 0, FALSE);

	iface = nm_netlink_index_to_iface (ifindex);
	g_return_val_if_fail (iface != NULL, FALSE);

	l = nm_netlink_index_to_rtnl_link (ifindex);
	if (l == NULL) {
		nm_log_err (LOGD_HW, "(%s): failed to get interface link object", iface);
		return FALSE;
	}

	flags = rtnl_link_get_flags (l);
	rtnl_link_put (l);

	return flags & IFF_UP;
}

/**
 * nm_system_iface_set_mtu:
 * @ifindex: interface index
 * @mtu: the new MTU
 *
 * Returns: %TRUE if the request was successful, %FALSE if it failed
 **/
gboolean
nm_system_iface_set_mtu (int ifindex, guint32 mtu)
{
	struct rtnl_link *old;
	struct rtnl_link *new;
	gboolean success = FALSE;
	struct nl_sock *nlh;
	const char *iface;
	int err;

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (mtu > 0, FALSE);

	iface = nm_netlink_index_to_iface (ifindex);
	g_return_val_if_fail (iface != NULL, FALSE);

	new = rtnl_link_alloc ();
	if (!new)
		return FALSE;

	old = nm_netlink_index_to_rtnl_link (ifindex);
	if (old) {
		rtnl_link_set_mtu (new, mtu);
		nlh = nm_netlink_get_default_handle ();
		if (nlh) {
			err = rtnl_link_change (nlh, old, new, 0);
			if (err == 0)
				success = TRUE;
			else
				nm_log_warn (LOGD_HW, "(%s): failed to change interface MTU", iface);
		}
		rtnl_link_put (old);
	}
	rtnl_link_put (new);

	return success;
}

/**
 * nm_system_iface_set_mac:
 * @ifindex: interface index
 * @mac: new MAC address
 *
 * Attempts to change the interface's MAC address to the requested value,
 * ie MAC spoofing or cloning.
 *
 * Returns: %TRUE if the request succeeded, %FALSE if it failed.
 **/
gboolean
nm_system_iface_set_mac (int ifindex, const struct ether_addr *mac)
{
	struct rtnl_link *old, *new;
	gboolean success = FALSE;
	struct nl_sock *nlh;
	const char *iface;
	struct nl_addr *addr = NULL;
	int err;

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (mac != NULL, FALSE);

	iface = nm_netlink_index_to_iface (ifindex);
	g_return_val_if_fail (iface != NULL, FALSE);

	new = rtnl_link_alloc ();
	if (!new)
		return FALSE;

	old = nm_netlink_index_to_rtnl_link (ifindex);
	if (old) {
		addr = nl_addr_build (AF_LLC, (void *) mac, ETH_ALEN);
		if (!addr) {
			nm_log_err (LOGD_HW, "(%s): failed to allocate memory for MAC address change", iface);
			rtnl_link_put (old);
			rtnl_link_put (new);
			return FALSE;
		}
		rtnl_link_set_addr (new, addr);
		nl_addr_put (addr);
		nlh = nm_netlink_get_default_handle ();
		if (nlh) {
			err = rtnl_link_change (nlh, old, new, 0);
			if (err == 0)
				success = TRUE;
			else
				nm_log_warn (LOGD_HW, "(%s): failed to change interface MAC address", iface);
		}
		rtnl_link_put (old);
	}

	rtnl_link_put (new);
	return success;
}

static struct rtnl_route *
add_ip4_route_to_gateway (int ifindex, guint32 gw, guint32 mss)
{
	struct nl_sock *nlh;
	struct rtnl_route *route = NULL;
	const char *iface;
	int err;

	iface = nm_netlink_index_to_iface (ifindex);
	g_return_val_if_fail (iface != NULL, FALSE);

	nlh = nm_netlink_get_default_handle ();
	g_return_val_if_fail (nlh != NULL, NULL);

	/* Gateway might be over a bridge; try adding a route to gateway first */
	route = nm_netlink_route_new (ifindex, AF_INET, mss,
	                              NMNL_PROP_SCOPE, RT_SCOPE_LINK,
	                              NMNL_PROP_TABLE, RT_TABLE_MAIN,
	                              NULL);
	g_return_val_if_fail (route != NULL, NULL);

	/* Add direct route to the gateway */
	err = nm_netlink_route_add(route, AF_INET, &gw, 32, NULL, 0);
	if (err) {
		nm_log_err (LOGD_DEVICE | LOGD_IP4,
		            "(%s): failed to add IPv4 route to gateway (%d)",
		            iface, err);
		goto error;
	}

	return route;

error:
	rtnl_route_put (route);
	return NULL;
}

static int
replace_default_ip4_route (int ifindex, guint32 gw, guint32 mss)
{
	struct rtnl_route *route = NULL;
	struct nl_sock *nlh;
	int err = -1;
	int dst=0;

	g_return_val_if_fail (ifindex > 0, -ENODEV);

	nlh = nm_netlink_get_default_handle ();
	g_return_val_if_fail (nlh != NULL, -ENOMEM);

	route = nm_netlink_route_new (ifindex, AF_INET, mss,
	                              NMNL_PROP_SCOPE, RT_SCOPE_UNIVERSE,
	                              NMNL_PROP_TABLE, RT_TABLE_MAIN,
	                              NULL);
	g_return_val_if_fail (route != NULL, -ENOMEM);

	/* Add the new default route */
	err = nm_netlink_route_add (route, AF_INET, &dst, 0, &gw, NLM_F_REPLACE);

	rtnl_route_put (route);
	return err;
}

/*
 * nm_system_replace_default_ip4_route_vpn
 *
 * Replace default IPv4 route with one via the current device
 *
 */
gboolean
nm_system_replace_default_ip4_route_vpn (int ifindex,
                                         guint32 ext_gw,
                                         guint32 int_gw,
                                         guint32 mss,
                                         int parent_ifindex,
                                         guint32 parent_mss)
{
	struct rtnl_route *gw_route = NULL;
	struct nl_sock *nlh;
	gboolean success = FALSE;
	int err;
	const char *iface;

	iface = nm_netlink_index_to_iface (ifindex);
	g_return_val_if_fail (iface != NULL, FALSE);

	nlh = nm_netlink_get_default_handle ();
	g_return_val_if_fail (nlh != NULL, FALSE);

	err = replace_default_ip4_route (ifindex, int_gw, mss);
	if (err == 0) {
		return TRUE;
	} else if ((err != -NLE_OBJ_NOTFOUND) && (err != -NLE_FAILURE)) {
		nm_log_err (LOGD_DEVICE | LOGD_IP4,
		            "(%s): failed to set IPv4 default route: %d",
		            iface, err);
		return FALSE;
	}

	/* Try adding a direct route to the gateway first */
	gw_route = add_ip4_route_to_gateway (parent_ifindex, ext_gw, parent_mss);
	if (!gw_route)
		return FALSE;

	/* Try adding the original route again */
	err = replace_default_ip4_route (ifindex, int_gw, mss);
	if (err != 0) {
		nm_netlink_route_delete (gw_route);
		nm_log_err (LOGD_DEVICE | LOGD_IP4,
		            "(%s): failed to set IPv4 default route (pass #2): %d",
		            iface, err);
	} else
		success = TRUE;

	rtnl_route_put (gw_route);
	return success;
}

/*
 * nm_system_replace_default_ip4_route
 *
 * Replace default IPv4 route with one via the current device
 *
 */
gboolean
nm_system_replace_default_ip4_route (int ifindex, guint32 gw, guint32 mss)
{
	struct rtnl_route *gw_route = NULL;
	gboolean success = FALSE;
	const char *iface;
	int err;

	iface = nm_netlink_index_to_iface (ifindex);
	g_return_val_if_fail (iface != NULL, FALSE);

	err = replace_default_ip4_route (ifindex, gw, mss);
	if (err == 0) {
		return TRUE;
	} else if (err != -NLE_OBJ_NOTFOUND) {
		nm_log_err (LOGD_DEVICE | LOGD_IP4,
		            "(%s): failed to set IPv4 default route: %d",
		            iface, err);
		return FALSE;
	}

	/* Try adding a direct route to the gateway first */
	gw_route = add_ip4_route_to_gateway (ifindex, gw, mss);
	if (!gw_route)
		return FALSE;

	/* Try adding the original route again */
	err = replace_default_ip4_route (ifindex, gw, mss);
	if (err != 0) {
		nm_netlink_route_delete (gw_route);
		nm_log_err (LOGD_DEVICE | LOGD_IP4,
		            "(%s): failed to set IPv4 default route (pass #2): %d",
		            iface, err);
	} else
		success = TRUE;

	rtnl_route_put (gw_route);
	return success;
}

static struct rtnl_route *
add_ip6_route_to_gateway (int ifindex, const struct in6_addr *gw)
{
	struct nl_sock *nlh;
	struct rtnl_route *route = NULL;
	const char *iface;
	int err;

	iface = nm_netlink_index_to_iface (ifindex);
	g_return_val_if_fail (iface != NULL, NULL);

	nlh = nm_netlink_get_default_handle ();
	g_return_val_if_fail (nlh != NULL, NULL);

	/* Gateway might be over a bridge; try adding a route to gateway first */
	route = nm_netlink_route_new (ifindex, AF_INET6, 0,
	                              NMNL_PROP_SCOPE, RT_SCOPE_LINK,
	                              NMNL_PROP_TABLE, RT_TABLE_MAIN,
	                              NULL);
	g_return_val_if_fail (route != NULL, NULL);

	/* Add direct route to the gateway */
	err = nm_netlink_route_add(route, AF_INET, gw, 128, NULL, 0);
	if (err) {
		nm_log_err (LOGD_DEVICE | LOGD_IP6,
		            "(%s): failed to add IPv4 route to gateway (%d)",
		            iface, err);
		goto error;
	}

	return route;

error:
	rtnl_route_put (route);
	return NULL;
}

static int
replace_default_ip6_route (int ifindex, const struct in6_addr *gw)
{
	struct rtnl_route *route = NULL;
	struct nl_sock *nlh;
	const char *iface;
	int err = -1;

	g_return_val_if_fail (ifindex > 0, FALSE);

	iface = nm_netlink_index_to_iface (ifindex);
	g_return_val_if_fail (iface != NULL, FALSE);

	nlh = nm_netlink_get_default_handle ();
	g_return_val_if_fail (nlh != NULL, -ENOMEM);

	route = nm_netlink_route_new (ifindex, AF_INET6, 0,
	                              NMNL_PROP_SCOPE, RT_SCOPE_UNIVERSE,
	                              NMNL_PROP_TABLE, RT_TABLE_MAIN,
	                              NULL);
	g_return_val_if_fail (route != NULL, -ENOMEM);

	/* Add the new default route */
	nm_netlink_route_add(route, AF_INET6, NULL, 0, gw, NLM_F_REPLACE);
	if (err == -NLE_EXIST) {
		/* FIXME: even though we use NLM_F_REPLACE the kernel won't replace
		 * the route if it's the same.  Should try to remove it first, then
		 * add the new one again here.
		 */
		err = 0;
	}

	rtnl_route_put (route);
	return err;
}

/*
 * nm_system_replace_default_ip6_route
 *
 * Replace default IPv6 route with one via the given gateway
 *
 */
gboolean
nm_system_replace_default_ip6_route (int ifindex, const struct in6_addr *gw)
{
	struct rtnl_route *gw_route = NULL;
	gboolean success = FALSE;
	const char *iface;
	int err;

	iface = nm_netlink_index_to_iface (ifindex);
	g_return_val_if_fail (iface != NULL, FALSE);

	err = replace_default_ip6_route (ifindex, gw);
	if (err == 0)
		return TRUE;
	if (err != -NLE_OBJ_NOTFOUND) {
		nm_log_err (LOGD_DEVICE | LOGD_IP6,
		            "(%s): failed to set IPv6 default route: %d",
		            iface, err);
		return FALSE;
	}

	/* Try adding a direct route to the gateway first */
	gw_route = add_ip6_route_to_gateway (ifindex, gw);
	if (!gw_route)
		return FALSE;

	/* Try adding the original route again */
	err = replace_default_ip6_route (ifindex, gw);
	if (err != 0) {
		nm_netlink_route_delete (gw_route);
		nm_log_err (LOGD_DEVICE | LOGD_IP6,
		            "(%s): failed to set IPv6 default route (pass #2): %d",
		            iface, err);
	} else
		success = TRUE;

	rtnl_route_put (gw_route);
	return success;
}

/*
 * nm_system_iface_flush_addresses
 *
 * Flush all network addresses associated with a network device
 *
 */
gboolean
nm_system_iface_flush_addresses (int ifindex, int family)
{
	g_return_val_if_fail (ifindex > 0, FALSE);
	return sync_addresses (ifindex, family, NULL, 0);
}


static struct rtnl_route *
delete_one_route (struct rtnl_route *route,
                  struct nl_addr *dst,
                  const char *iface,
                  gpointer user_data)
{
	guint32 log_level = GPOINTER_TO_UINT (user_data);

	nm_log_dbg (log_level, "   deleting route");
	if (!nm_netlink_route_delete (route))
		nm_log_err (LOGD_DEVICE, "(%s): failed to delete route", iface);

	return NULL;
}

/**
 * nm_system_iface_flush_routes:
 * @ifindex: interface index
 * @family: address family, i.e. AF_INET, AF_INET6, or AF_UNSPEC
 *
 * Flush all network addresses associated with a network device.
 *
 * Returns: %TRUE on success, %FALSE on failure
 **/
gboolean
nm_system_iface_flush_routes (int ifindex, int family)
{
	guint32 log_level = LOGD_IP4 | LOGD_IP6;
	const char *sf = "UNSPEC";
	const char *iface;

	g_return_val_if_fail (ifindex > 0, FALSE);

	iface = nm_netlink_index_to_iface (ifindex);
	g_return_val_if_fail (iface != NULL, FALSE);

	if (family == AF_INET) {
		log_level = LOGD_IP4;
		sf = "INET";
	} else if (family == AF_INET6) {
		log_level = LOGD_IP6;
		sf = "INET6";
	}
	nm_log_dbg (log_level, "(%s): flushing routes ifindex %d family %s (%d)",
	            iface, ifindex, sf, family);

	/* We don't want to flush IPv6 link-local routes that may exist on the
	 * the interface since the LL address and routes should normally stay
	 * assigned all the time.
	 */
	nm_netlink_foreach_route (ifindex, family, RT_SCOPE_UNIVERSE, TRUE, delete_one_route, GUINT_TO_POINTER (log_level));
	return TRUE;
}

static struct rtnl_route *
find_route (struct rtnl_route *route,
            struct nl_addr *dst,
            const char *iface,
            gpointer user_data)
{
	NMIP4Config *config = user_data;
	struct in_addr *dst_addr;
	int num;
	int i;

	if (dst && (nl_addr_get_family (dst) != AF_INET))
		return NULL;

	/* Find the first route that handles a subnet of at least one of the
	 * device's IPv4 addresses.
	 */
	dst_addr = nl_addr_get_binary_addr (dst);
	num = nm_ip4_config_get_num_addresses (config);
	for (i = 0; i < num; i++) {
		NMIP4Address *addr = nm_ip4_config_get_address (config, i);
		guint32 prefix = nm_ip4_address_get_prefix (addr);
		guint32 address = nm_ip4_address_get_address (addr);

		if (   prefix == nl_addr_get_prefixlen (dst)
		    && (address & nm_utils_ip4_prefix_to_netmask (prefix)) == dst_addr->s_addr)
			return route;
	}
	return NULL;
}

static void
nm_system_device_set_priority (int ifindex,
                               NMIP4Config *config,
                               int priority)
{
	struct nl_sock *nlh;
	struct rtnl_route *found;

	found = nm_netlink_foreach_route (ifindex, AF_INET, RT_SCOPE_LINK, FALSE,  find_route, config);
	if (found) {
		nlh = nm_netlink_get_default_handle ();
		nm_netlink_route_delete (found);
		rtnl_route_set_priority (found, priority);
		rtnl_route_add (nlh, found, 0);
		rtnl_route_put (found);
	}
}
