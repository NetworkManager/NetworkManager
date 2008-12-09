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
 * Copyright (C) 2004 - 2008 Red Hat, Inc.
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

#include "NetworkManagerSystem.h"
#include "nm-device.h"
#include "nm-named-manager.h"
#include "NetworkManagerUtils.h"
#include "nm-utils.h"
#include "nm-netlink.h"

/* Because of a bug in libnl, rtnl.h should be included before route.h */
#include <netlink/route/rtnl.h>

#include <netlink/route/addr.h>
#include <netlink/route/route.h>
#include <netlink/netlink.h>
#include <netlink/utils.h>
#include <netlink/route/link.h>

static void nm_system_device_set_priority (const char *iface,
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
create_route (int iface_idx, int mss)
{
	struct rtnl_route *route;

	route = rtnl_route_alloc ();
	if (route) {
		rtnl_route_set_oif (route, iface_idx);

		if (mss && rtnl_route_set_metric (route, RTAX_ADVMSS, mss) < 0)
			nm_warning ("Could not set mss");
	} else
		nm_warning ("Could not allocate route");

	return route;
}

static struct rtnl_route *
nm_system_device_set_ip4_route (const char *iface, 
                                guint32 ip4_dest,
                                guint32 ip4_prefix,
                                guint32 ip4_gateway,
                                guint32 metric,
                                int mss)
{
	struct nl_handle *nlh;
	struct rtnl_route *route;
	struct nl_addr *dest_addr;
	struct nl_addr *gw_addr = NULL;
	int err, iface_idx;

	nlh = nm_netlink_get_default_handle ();
	g_return_val_if_fail (nlh != NULL, NULL);

	iface_idx = nm_netlink_iface_to_index (iface);
	g_return_val_if_fail (iface_idx >= 0, NULL);

	route = create_route (iface_idx, mss);
	g_return_val_if_fail (route != NULL, NULL);

	/* Destination */
	dest_addr = nl_addr_build (AF_INET, &ip4_dest, sizeof (ip4_dest));
	g_return_val_if_fail (dest_addr != NULL, NULL);
	nl_addr_set_prefixlen (dest_addr, (int) ip4_prefix);

	rtnl_route_set_dst (route, dest_addr);
	nl_addr_put (dest_addr);

	/* Gateway */
	if (ip4_gateway) {
		gw_addr = nl_addr_build (AF_INET, &ip4_gateway, sizeof (ip4_gateway));
		if (gw_addr) {
			rtnl_route_set_gateway (route, gw_addr);
			rtnl_route_set_scope (route, RT_SCOPE_UNIVERSE);
		} else {
			nm_warning ("Invalid gateway");
			rtnl_route_put (route);
			return NULL;
		}
	}

	/* Metric */
	if (metric)
		rtnl_route_set_prio (route, metric);

	/* Add the route */
	err = rtnl_route_add (nlh, route, 0);
	if (err == -ESRCH && ip4_gateway) {
		/* Gateway might be over a bridge; try adding a route to gateway first */
		struct rtnl_route *route2;

		route2 = create_route (iface_idx, mss);
		if (route2) {
			/* Add route to gateway over bridge */
			rtnl_route_set_dst (route2, gw_addr);
			err = rtnl_route_add (nlh, route2, 0);
			if (!err) {
				/* Try adding the route again */
				err = rtnl_route_add (nlh, route, 0);
				if (err)
					rtnl_route_del (nlh, route2, 0);
			}
			rtnl_route_put (route2);
		}
	}

	if (gw_addr)
		nl_addr_put (gw_addr);

	if (err) {
		nm_warning ("Failed to set IPv4 route on '%s': %s", iface, nl_geterror ());
		rtnl_route_put (route);
		route = NULL;
	}

	return route;
}

typedef struct {
	const char *iface;
	int ifindex;
	int family;
	struct nl_handle *nlh;
} AddrCheckData;

static void
check_one_address (struct nl_object *object, void *user_data)
{
	AddrCheckData *data = (AddrCheckData *) user_data;
	struct rtnl_addr *addr = (struct rtnl_addr *) object;
	int err;

	if (rtnl_addr_get_ifindex (addr) == data->ifindex) {
		if (rtnl_addr_get_family (addr) == data->family) {
			err = rtnl_addr_delete (data->nlh, addr, 0);
			if (err < 0) {
				nm_warning ("(%s) error %d returned from rtnl_addr_delete(): %s",
				            data->iface, err, nl_geterror());
			}
		}
	}
}

static gboolean
add_ip4_addresses (NMIP4Config *config, const char *iface)
{
	struct nl_handle *nlh = NULL;
	struct nl_cache *addr_cache = NULL;
	int i, iface_idx, err;
	AddrCheckData check_data;
	guint32 flags = 0;
	gboolean did_gw = FALSE;

	nlh = nm_netlink_get_default_handle ();
	if (!nlh)
		return FALSE;

	addr_cache = rtnl_addr_alloc_cache (nlh);
	if (!addr_cache)
		return FALSE;
	nl_cache_mngt_provide (addr_cache);

	iface_idx = nm_netlink_iface_to_index (iface);

	memset (&check_data, 0, sizeof (check_data));
	check_data.iface = iface;
	check_data.nlh = nlh;
	check_data.ifindex = iface_idx;
	check_data.family = AF_INET;

	/* Remove all existing IPv4 addresses */
	nl_cache_foreach (addr_cache, check_one_address, &check_data);

	for (i = 0; i < nm_ip4_config_get_num_addresses (config); i++) {
		NMIP4Address *addr;
		struct rtnl_addr *nl_addr = NULL;

		addr = nm_ip4_config_get_address (config, i);
		g_assert (addr);

		flags = NM_RTNL_ADDR_DEFAULT;
		if (nm_ip4_address_get_gateway (addr) && !did_gw) {
			if (nm_ip4_config_get_ptp_address (config))
				flags |= NM_RTNL_ADDR_PTP_ADDR;
			did_gw = TRUE;
		}

		nl_addr = nm_ip4_config_to_rtnl_addr (config, i, flags);
		if (!nl_addr) {
			nm_warning ("couldn't create rtnl address!\n");
			continue;
		}
		rtnl_addr_set_ifindex (nl_addr, iface_idx);

		if ((err = rtnl_addr_add (nlh, nl_addr, 0)) < 0)
			nm_warning ("(%s) error %d returned from rtnl_addr_add():\n%s", iface, err, nl_geterror());

		rtnl_addr_put (nl_addr);
	}

	nl_cache_free (addr_cache);
	return TRUE;
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
		route = nm_system_device_set_ip4_route (nm_device_get_ip_iface (parent_device),
		                                        vpn_gw, 32, 0, 0, nm_ip4_config_get_mss (parent_config));
	} else {
		route = nm_system_device_set_ip4_route (nm_device_get_ip_iface (parent_device),
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
nm_system_apply_ip4_config (const char *iface,
                            NMIP4Config *config,
                            int priority,
                            NMIP4ConfigCompareFlags flags)
{
	int i;

	g_return_val_if_fail (iface != NULL, FALSE);
	g_return_val_if_fail (config != NULL, FALSE);

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

			tmp = nm_system_device_set_ip4_route (iface,
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
			nm_system_device_set_mtu (iface, nm_ip4_config_get_mtu (config));
	}

	if (priority > 0)
		nm_system_device_set_priority (iface, config, priority);

	return TRUE;
}

/*
 * nm_system_device_set_up_down
 *
 * Mark the device as up or down.
 *
 */
gboolean
nm_system_device_set_up_down (NMDevice *dev,
                              gboolean up,
                              gboolean *no_firmware)
{
	g_return_val_if_fail (dev != NULL, FALSE);

	return nm_system_device_set_up_down_with_iface (nm_device_get_ip_iface (dev), up, no_firmware);
}

gboolean
nm_system_device_set_up_down_with_iface (const char *iface,
                                         gboolean up,
                                         gboolean *no_firmware)
{
	struct rtnl_link *request = NULL, *old = NULL;
	struct nl_handle *nlh;
	gboolean success = FALSE;
	guint32 idx;

	g_return_val_if_fail (iface != NULL, FALSE);
	if (no_firmware)
		g_return_val_if_fail (*no_firmware == FALSE, FALSE);

	if (!(request = rtnl_link_alloc ()))
		goto out;

	if (up)
		rtnl_link_set_flags (request, IFF_UP);
	else
		rtnl_link_unset_flags (request, IFF_UP);

	idx = nm_netlink_iface_to_index (iface);
	old = nm_netlink_index_to_rtnl_link (idx);
	if (old) {
		nlh = nm_netlink_get_default_handle ();
		if (nlh) {
			if (rtnl_link_change (nlh, old, request, 0) == 0)
				success = TRUE;
			else if ((nl_get_errno () == ENOENT) && no_firmware && up)
				*no_firmware = TRUE;
		}
	}

	rtnl_link_put (old);
	rtnl_link_put (request);

out:
	return success;
}

gboolean
nm_system_device_is_up (NMDevice *device)
{
	g_return_val_if_fail (device != NULL, FALSE);

	return nm_system_device_is_up_with_iface (nm_device_get_ip_iface (device));
}

gboolean
nm_system_device_is_up_with_iface (const char *iface)
{
	struct ifreq ifr;
	int fd;
	gboolean up = FALSE;

	fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		nm_warning ("couldn't open control socket.");
		return FALSE;
	}

	/* Get device's flags */
	memset (&ifr, 0, sizeof (ifr));
	strncpy (ifr.ifr_name, iface, IFNAMSIZ);
	if (ioctl (fd, SIOCGIFFLAGS, &ifr) < 0) {
		if (errno != ENODEV) {
			nm_warning ("%s: could not get flags for device %s.  errno = %d", 
			            __func__, iface, errno);
		}
	} else {
		up = !!(ifr.ifr_flags & IFF_UP);
	}
	close (fd);

	return up;
}

gboolean
nm_system_device_set_mtu (const char *iface, guint32 mtu)
{
	struct rtnl_link *old;
	struct rtnl_link *new;
	gboolean success = FALSE;
	struct nl_handle *nlh;
	int iface_idx;

	g_return_val_if_fail (iface != NULL, FALSE);
	g_return_val_if_fail (mtu > 0, FALSE);

	new = rtnl_link_alloc ();
	if (!new)
		return FALSE;

	iface_idx = nm_netlink_iface_to_index (iface);
	old = nm_netlink_index_to_rtnl_link (iface_idx);
	if (old) {
		rtnl_link_set_mtu (new, mtu);
		nlh = nm_netlink_get_default_handle ();
		if (nlh) {
			rtnl_link_change (nlh, old, new, 0);
			success = TRUE;
		}
		rtnl_link_put (old);
	}

	rtnl_link_put (new);
	return success;
}

static struct rtnl_route *
add_ip4_route_to_gateway (const char *iface, guint32 gw, guint32 mss)
{
	struct nl_handle *nlh;
	struct rtnl_route *route = NULL;
	struct nl_addr *gw_addr = NULL;
	int iface_idx, err;

	nlh = nm_netlink_get_default_handle ();
	g_return_val_if_fail (nlh != NULL, NULL);

	iface_idx = nm_netlink_iface_to_index (iface);
	if (iface_idx < 0)
		return NULL;

	/* Gateway might be over a bridge; try adding a route to gateway first */
	route = rtnl_route_alloc ();
	if (route == NULL)
		return NULL;

	rtnl_route_set_family (route, AF_INET);
	rtnl_route_set_table (route, RT_TABLE_MAIN);
	rtnl_route_set_oif (route, iface_idx);
	rtnl_route_set_scope (route, RT_SCOPE_LINK);

	gw_addr = nl_addr_build (AF_INET, &gw, sizeof (gw));
	if (!gw_addr)
		goto error;
	nl_addr_set_prefixlen (gw_addr, 32);
	rtnl_route_set_dst (route, gw_addr);
	nl_addr_put (gw_addr);

	if (mss) {
		if (rtnl_route_set_metric (route, RTAX_ADVMSS, mss) < 0)
			goto error;
	}

	/* Add direct route to the gateway */
	err = rtnl_route_add (nlh, route, 0);
	if (err) {
		nm_warning ("(%s): failed to add IPv4 route to gateway (%d)", iface, err);
		goto error;
	}

	return route;

error:
	rtnl_route_put (route);
	return NULL;
}

static int
replace_default_ip4_route (const char *iface, guint32 gw, guint32 mss)
{
	struct rtnl_route *route = NULL;
	struct nl_handle *nlh;
	struct nl_addr *dst_addr = NULL;
	guint32 dst = 0;
	struct nl_addr *gw_addr = NULL;
	int iface_idx, err = -1;

	g_return_val_if_fail (iface != NULL, -1);

	nlh = nm_netlink_get_default_handle ();
	g_return_val_if_fail (nlh != NULL, -1);

	iface_idx = nm_netlink_iface_to_index (iface);
	if (iface_idx < 0)
		return -1;

	route = rtnl_route_alloc();
	g_return_val_if_fail (route != NULL, -1);

	rtnl_route_set_family (route, AF_INET);
	rtnl_route_set_table (route, RT_TABLE_MAIN);
	rtnl_route_set_scope (route, RT_SCOPE_UNIVERSE);
	rtnl_route_set_oif (route, iface_idx);

	/* Build up the destination address */
	dst_addr = nl_addr_build (AF_INET, &dst, sizeof (dst));
	if (!dst_addr) {
		err = -1;
		goto out;
	}
	nl_addr_set_prefixlen (dst_addr, 0);
	rtnl_route_set_dst (route, dst_addr);

	/* Build up the gateway address */
	gw_addr = nl_addr_build (AF_INET, &gw, sizeof (gw));
	if (!gw_addr) {
		err = -1;
		goto out;
	}
	nl_addr_set_prefixlen (gw_addr, 0);
	rtnl_route_set_gateway (route, gw_addr);

	if (mss > 0) {
		if (rtnl_route_set_metric (route, RTAX_ADVMSS, mss) < 0)
			goto out;
	}

	/* Add the new default route */
	err = rtnl_route_add (nlh, route, NLM_F_REPLACE);

out:
	if (dst_addr)
		nl_addr_put (dst_addr);
	if (gw_addr)
		nl_addr_put (gw_addr);
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
nm_system_replace_default_ip4_route_vpn (const char *iface,
                                         guint32 ext_gw,
                                         guint32 int_gw,
                                         guint32 mss,
                                         const char *parent_iface,
                                         guint32 parent_mss)
{
	struct rtnl_route *gw_route = NULL;
	struct nl_handle *nlh;
	gboolean success = FALSE;
	int err;

	nlh = nm_netlink_get_default_handle ();
	g_return_val_if_fail (nlh != NULL, FALSE);

	err = replace_default_ip4_route (iface, int_gw, mss);
	if (err == 0) {
		return TRUE;
	} else if (err != -ESRCH) {
		nm_warning ("(%s): failed to set IPv4 default route (%d)", iface, err);
		return FALSE;
	}

	/* Try adding a direct route to the gateway first */
	gw_route = add_ip4_route_to_gateway (parent_iface, ext_gw, parent_mss);
	if (!gw_route)
		return FALSE;

	/* Try adding the original route again */
	err = replace_default_ip4_route (iface, int_gw, mss);
	if (err != 0) {
		rtnl_route_del (nlh, gw_route, 0);
		nm_warning ("(%s): failed to set IPv4 default route (%d)", iface, err);
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
nm_system_replace_default_ip4_route (const char *iface, guint32 gw, guint32 mss)
{
	struct rtnl_route *gw_route = NULL;
	struct nl_handle *nlh;
	gboolean success = FALSE;
	int err;

	nlh = nm_netlink_get_default_handle ();
	g_return_val_if_fail (nlh != NULL, FALSE);

	err = replace_default_ip4_route (iface, gw, mss);
	if (err == 0) {
		return TRUE;
	} else if (err != -ESRCH) {
		nm_warning ("replace_default_ip4_route() returned error %s (%d)",
		            strerror (err), err);
		return FALSE;
	}

	/* Try adding a direct route to the gateway first */
	gw_route = add_ip4_route_to_gateway (iface, gw, mss);
	if (!gw_route)
		return FALSE;

	/* Try adding the original route again */
	err = replace_default_ip4_route (iface, gw, mss);
	if (err != 0) {
		rtnl_route_del (nlh, gw_route, 0);
		nm_warning ("Failed to set IPv4 default route on '%s': %d", iface, err);
	} else
		success = TRUE;

	rtnl_route_put (gw_route);
	return success;
}

/*
 * nm_system_device_flush_ip4_addresses
 *
 * Flush all network addresses associated with a network device
 *
 */
void nm_system_device_flush_ip4_addresses (NMDevice *dev)
{
	g_return_if_fail (dev != NULL);

	nm_system_device_flush_ip4_addresses_with_iface (nm_device_get_ip_iface (dev));
}


/*
 * nm_system_device_flush_ip4_addresses_with_iface
 *
 * Flush all network addresses associated with a network device
 *
 */
void nm_system_device_flush_ip4_addresses_with_iface (const char *iface)
{
	struct nl_handle *nlh = NULL;
	struct nl_cache *addr_cache = NULL;
	int iface_idx;
	AddrCheckData check_data;

	g_return_if_fail (iface != NULL);
	iface_idx = nm_netlink_iface_to_index (iface);
	g_return_if_fail (iface_idx >= 0);

	nlh = nm_netlink_get_default_handle ();
	g_return_if_fail (nlh != NULL);

	memset (&check_data, 0, sizeof (check_data));
	check_data.iface = iface;
	check_data.nlh = nlh;
	check_data.family = AF_INET;
	check_data.ifindex = nm_netlink_iface_to_index (iface);

	addr_cache = rtnl_addr_alloc_cache (nlh);
	if (!addr_cache)
		return;
	nl_cache_mngt_provide (addr_cache);

	/* Remove all IP addresses for a device */
	nl_cache_foreach (addr_cache, check_one_address, &check_data);

	nl_cache_free (addr_cache);
}

/*
 * nm_system_device_flush_ip4_routes
 *
 * Flush all network addresses associated with a network device
 *
 */
void nm_system_device_flush_ip4_routes (NMDevice *dev)
{
	g_return_if_fail (dev != NULL);

	nm_system_device_flush_ip4_routes_with_iface (nm_device_get_ip_iface (dev));
}


static void
foreach_route (void (*callback)(struct nl_object *, gpointer),
			gpointer user_data)
{
	struct nl_handle *nlh;
	struct nl_cache *route_cache;

	nlh = nm_netlink_get_default_handle ();
	route_cache = rtnl_route_alloc_cache (nlh);
	nl_cache_mngt_provide (route_cache);
	nl_cache_foreach (route_cache, callback, user_data);
	nl_cache_free (route_cache);
}


typedef struct {
	const char *iface;
	int iface_idx;
} RouteCheckData;

static void
check_one_route (struct nl_object *object, void *user_data)
{
	RouteCheckData *data = (RouteCheckData *) user_data;
	struct rtnl_route *route = (struct rtnl_route *) object;
	int err;

	/* Delete all IPv4 routes from this interface */
	if (rtnl_route_get_oif (route) != data->iface_idx)
		return;
	if (rtnl_route_get_family (route) != AF_INET)
		return;

	err = rtnl_route_del (nm_netlink_get_default_handle (), route, 0);
	if (err < 0) {
		nm_warning ("(%s) error %d returned from rtnl_route_del(): %s",
		            data->iface, err, nl_geterror());
	}
}

/*
 * nm_system_device_flush_ip4_routes_with_iface
 *
 * Flush all routes associated with a network device
 *
 */
void nm_system_device_flush_ip4_routes_with_iface (const char *iface)
{
	int iface_idx;
	RouteCheckData check_data;

	g_return_if_fail (iface != NULL);
	iface_idx = nm_netlink_iface_to_index (iface);
	g_return_if_fail (iface_idx >= 0);

	memset (&check_data, 0, sizeof (check_data));
	check_data.iface = iface;
	check_data.iface_idx = iface_idx;

	foreach_route (check_one_route, &check_data);
}

typedef struct {
	struct rtnl_route *route;
	NMIP4Config *config;
	int iface;
} SetPriorityInfo;

static void
find_route (struct nl_object *object, gpointer user_data)
{
	struct rtnl_route *route = (struct rtnl_route *) object;
	SetPriorityInfo *info = (SetPriorityInfo *) user_data;
	struct nl_addr *dst;
	struct in_addr *dst_addr;
	int num;
	int i;

	if (info->route ||
	    rtnl_route_get_oif (route) != info->iface ||
	    rtnl_route_get_scope (route) != RT_SCOPE_LINK)
		return;

	dst = rtnl_route_get_dst (route);
	if (nl_addr_get_family (dst) != AF_INET)
		return;

	dst_addr = nl_addr_get_binary_addr (dst);
	num = nm_ip4_config_get_num_addresses (info->config);
	for (i = 0; i < num; i++) {
		NMIP4Address *addr = nm_ip4_config_get_address (info->config, i);
		guint32 prefix = nm_ip4_address_get_prefix (addr);
		guint32 address = nm_ip4_address_get_address (addr);

		if (prefix == nl_addr_get_prefixlen (dst) &&
		    (address & nm_utils_ip4_prefix_to_netmask (prefix)) == dst_addr->s_addr) {

			/* Ref the route so it sticks around after the cache is cleared */
			rtnl_route_get (route);
			info->route = route;
			break;
		}
	}
}

static void
nm_system_device_set_priority (const char *iface,
						 NMIP4Config *config,
						 int priority)
{
	SetPriorityInfo info;

	info.route = NULL;
	info.config = config;
	info.iface = nm_netlink_iface_to_index (iface);
	g_return_if_fail (info.iface >= 0);

	foreach_route (find_route, &info);
	if (info.route) {
		struct nl_handle *nlh;

		nlh = nm_netlink_get_default_handle ();
		rtnl_route_del (nlh, info.route, 0);

		rtnl_route_set_prio (info.route, priority);
		rtnl_route_add (nlh, info.route, 0);
		rtnl_route_put (info.route);
	}
}
