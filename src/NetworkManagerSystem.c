/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

/* NetworkManager -- Network link manager
 *
 * Dan Williams <dcbw@redhat.com>
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
 * Copyright (C) 2004 Red Hat, Inc.
 * Copyright (C) 1996 - 1997 Yoichi Hariguchi <yoichi@fore.com>
 * Copyright (C) January, 1998 Sergei Viznyuk <sv@phystech.com>
 *
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
#include <linux/if.h>

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

static gboolean
route_in_same_subnet (NMIP4Config *config, guint32 dest, guint32 prefix)
{
	int num;
	int i;

	num = nm_ip4_config_get_num_addresses (config);
	for (i = 0; i < num; i++) {
		const NMSettingIP4Address *addr;

		addr = nm_ip4_config_get_address (config, i);
		if (prefix == addr->prefix) {
			guint32 masked_addr = addr->address >> (32 - addr->prefix);
			guint32 masked_dest = dest >> (32 - prefix);

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

static void
nm_system_device_set_ip4_route (const char *iface, 
						  NMIP4Config *iface_config,
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

	if (iface_config && route_in_same_subnet (iface_config, ip4_dest, ip4_prefix))
		return;

	nlh = nm_netlink_get_default_handle ();
	g_return_if_fail (nlh != NULL);

	iface_idx = nm_netlink_iface_to_index (iface);
	g_return_if_fail (iface_idx >= 0);

	route = create_route (iface_idx, mss);
	g_return_if_fail (route != NULL);

	/* Destination */
	dest_addr = nl_addr_build (AF_INET, &ip4_dest, sizeof (ip4_dest));
	g_return_if_fail (dest_addr != NULL);
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
			return;
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

	if (err)
		nm_warning ("Failed to set IPv4 route on '%s': %s", iface, nl_geterror ());

	rtnl_route_put (route);
	if (gw_addr)
		nl_addr_put (gw_addr);
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
		const NMSettingIP4Address *addr;
		struct rtnl_addr *nl_addr = NULL;

		addr = nm_ip4_config_get_address (config, i);
		g_assert (addr);

		flags = NM_RTNL_ADDR_DEFAULT;
		if (addr->gateway && !did_gw) {
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

/*
 * nm_system_device_set_from_ip4_config
 *
 * Set IPv4 configuration of the device from an NMIP4Config object.
 *
 */
gboolean
nm_system_device_set_from_ip4_config (const char *iface,
							   NMIP4Config *config)
{
	int len, i;

	g_return_val_if_fail (iface != NULL, FALSE);
	g_return_val_if_fail (config != NULL, FALSE);

	if (!add_ip4_addresses (config, iface))
		return FALSE;

	sleep (1);

	len = nm_ip4_config_get_num_routes (config);
	for (i = 0; i < len; i++) {
		const NMSettingIP4Route *route = nm_ip4_config_get_route (config, i);

		nm_system_device_set_ip4_route (iface, config, 
								  route->address,
								  route->prefix,
								  route->next_hop,
								  route->metric,
								  nm_ip4_config_get_mss (config));
	}

	if (nm_ip4_config_get_mtu (config))
		nm_system_device_set_mtu (iface, nm_ip4_config_get_mtu (config));

	return TRUE;
}

/*
 * nm_system_vpn_device_set_from_ip4_config
 *
 * Set IPv4 configuration of a VPN device from an NMIP4Config object.
 *
 */
gboolean
nm_system_vpn_device_set_from_ip4_config (NMDevice *active_device,
                                          const char *iface,
                                          NMIP4Config *config)
{
	NMIP4Config *ad_config = NULL;
	NMNamedManager *named_mgr;
	int num;
	int i;

	g_return_val_if_fail (config != NULL, FALSE);

	/* Set up a route to the VPN gateway through the real network device */
	if (active_device && (ad_config = nm_device_get_ip4_config (active_device))) {
		guint32 ad_gw = 0, vpn_gw = 0;
		const NMSettingIP4Address *tmp;

		num = nm_ip4_config_get_num_addresses (ad_config);
		for (i = 0; i < num; i++) {
			tmp = nm_ip4_config_get_address (ad_config, i);
			if (tmp->gateway) {
				ad_gw = tmp->gateway;
				break;
			}
		}

		if (ad_gw) {
			num = nm_ip4_config_get_num_addresses (config);
			for (i = 0; i < num; i++) {
				tmp = nm_ip4_config_get_address (config, i);
				if (tmp->gateway) {
					vpn_gw = tmp->gateway;
					break;
				}
			}

			nm_system_device_set_ip4_route (nm_device_get_ip_iface (active_device),
									  ad_config, vpn_gw, 32, ad_gw, 0,
									  nm_ip4_config_get_mss (config));
		}
	}

	if (!iface || !strlen (iface))
		goto out;

	nm_system_device_set_up_down_with_iface (iface, TRUE);

	if (!add_ip4_addresses (config, iface))
		goto out;

	/* Set the MTU */
	if (nm_ip4_config_get_mtu (config))
		nm_system_device_set_mtu (iface, nm_ip4_config_get_mtu (config));

	/* Set routes */
	num = nm_ip4_config_get_num_routes (config);
	for (i = 0; i < num; i++) {
		const NMSettingIP4Route *route = nm_ip4_config_get_route (config, i);

		nm_system_device_set_ip4_route (iface, config,
								  route->address,
								  route->prefix,
								  route->next_hop,
								  route->metric,
								  nm_ip4_config_get_mss (config));
	}

	if (num == 0)
		nm_system_device_replace_default_ip4_route (iface, 0, 0);

out:
	named_mgr = nm_named_manager_get ();
	nm_named_manager_add_ip4_config (named_mgr, config, NM_NAMED_IP_CONFIG_TYPE_VPN);
	g_object_unref (named_mgr);

	return TRUE;
}


/*
 * nm_system_vpn_device_unset_from_ip4_config
 *
 * Unset an IPv4 configuration of a VPN device from an NMIP4Config object.
 *
 */
gboolean nm_system_vpn_device_unset_from_ip4_config (NMDevice *active_device, const char *iface, NMIP4Config *config)
{
	NMNamedManager *named_mgr;

	g_return_val_if_fail (active_device != NULL, FALSE);
	g_return_val_if_fail (config != NULL, FALSE);

	named_mgr = nm_named_manager_get ();
	nm_named_manager_remove_ip4_config (named_mgr, config);
	g_object_unref (named_mgr);

	return TRUE;
}


/*
 * nm_system_device_set_up_down
 *
 * Mark the device as up or down.
 *
 */
gboolean nm_system_device_set_up_down (NMDevice *dev, gboolean up)
{
	g_return_val_if_fail (dev != NULL, FALSE);

	return nm_system_device_set_up_down_with_iface (nm_device_get_iface (dev), up);
}

gboolean nm_system_device_set_up_down_with_iface (const char *iface, gboolean up)
{
	gboolean success = FALSE;
	guint32 idx;
	struct rtnl_link *	request = NULL;
	struct rtnl_link *	old = NULL;

	g_return_val_if_fail (iface != NULL, FALSE);

	if (!(request = rtnl_link_alloc ()))
		goto out;

	if (up)
		rtnl_link_set_flags (request, IFF_UP);
	else
		rtnl_link_unset_flags (request, IFF_UP);

	idx = nm_netlink_iface_to_index (iface);
	old = nm_netlink_index_to_rtnl_link (idx);
	if (old) {
		struct nl_handle *nlh;

		nlh = nm_netlink_get_default_handle ();
		if (nlh)
			rtnl_link_change (nlh, old, request, 0);
	}

	rtnl_link_put (old);
	rtnl_link_put (request);
	success = TRUE;

out:
	return success;
}

gboolean
nm_system_device_is_up (NMDevice *device)
{
	g_return_val_if_fail (device != NULL, FALSE);

	return nm_system_device_is_up_with_iface (nm_device_get_iface (device));
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

/*
 * nm_system_replace_default_ip4_route
 *
 * Replace default IPv4 route with one via the current device
 *
 */
void
nm_system_device_replace_default_ip4_route (const char *iface, guint32 gw, guint32 mss)
{
	struct rtnl_route * route;
	struct rtnl_route * route2 = NULL;
	struct nl_handle  * nlh;
	struct nl_addr    * gw_addr;
	int iface_idx, err;

	nlh = nm_netlink_get_default_handle ();
	g_return_if_fail (nlh != NULL);

	route = rtnl_route_alloc();
	g_return_if_fail (route != NULL);

	rtnl_route_set_scope (route, RT_SCOPE_UNIVERSE);

	iface_idx = nm_netlink_iface_to_index (iface);
	if (iface_idx < 0)
		goto out;
	rtnl_route_set_oif (route, iface_idx);

	/* Build up gateway address; a gateway of 0 (used in e.g. PPP links) means
	 * that all packets should be sent to the gateway since it's a point-to-point
	 * link and has no broadcast segment really.
	 */
	if (!(gw_addr = nl_addr_build (AF_INET, &gw, sizeof (gw))))
		goto out;
	rtnl_route_set_gateway (route, gw_addr);
	nl_addr_put (gw_addr);

	if (mss > 0) {
		if (rtnl_route_set_metric (route, RTAX_ADVMSS, mss) < 0)
			goto out;
	}

	err = rtnl_route_add (nlh, route, NLM_F_REPLACE);
	if (err == 0) {
		/* Everything good */
		goto out;
	} else if (err != -ESRCH) {
		nm_warning ("rtnl_route_add() returned error %s (%d)\n%s",
		            strerror (err), err, nl_geterror());
		goto out;
	}

	/* Gateway might be over a bridge; try adding a route to gateway first */
	route2 = rtnl_route_alloc ();
	if (route2 == NULL)
		goto out;
	rtnl_route_set_oif (route2, iface_idx);
	rtnl_route_set_dst (route2, gw_addr);

	if (mss) {
		if (rtnl_route_set_metric (route2, RTAX_ADVMSS, mss) < 0)
			goto out;
	}

	/* Add route to gateway over bridge */
	err = rtnl_route_add (nlh, route2, 0);
	if (err) {
		nm_warning ("Failed to add IPv4 default route on '%s': %s",
				  iface,
				  nl_geterror ());
		goto out;
	}

	/* Try adding the route again */
	err = rtnl_route_add (nlh, route, 0);
	if (err) {
		rtnl_route_del (nlh, route2, 0);
		nm_warning ("Failed to set IPv4 default route on '%s': %s",
				  iface,
				  nl_geterror ());
	}

out:
	if (route2)
		rtnl_route_put (route2);

	rtnl_route_put (route);
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

	nm_system_device_flush_ip4_addresses_with_iface (nm_device_get_iface (dev));
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

	nm_system_device_flush_ip4_routes_with_iface (nm_device_get_iface (dev));
}

typedef struct {
	const char *iface;
	struct nl_handle *nlh;
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

	err = rtnl_route_del (data->nlh, route, 0);
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
	struct nl_handle *nlh = NULL;
	struct nl_cache *route_cache = NULL;
	int iface_idx;
	RouteCheckData check_data;

	g_return_if_fail (iface != NULL);
	iface_idx = nm_netlink_iface_to_index (iface);
	g_return_if_fail (iface_idx >= 0);

	nlh = nm_netlink_get_default_handle ();
	g_return_if_fail (nlh != NULL);

	memset (&check_data, 0, sizeof (check_data));
	check_data.iface = iface;
	check_data.nlh = nlh;
	check_data.iface_idx = iface_idx;

	route_cache = rtnl_route_alloc_cache (nlh);
	g_return_if_fail (route_cache != NULL);
	nl_cache_mngt_provide (route_cache);

	/* Remove routing table entries */
	nl_cache_foreach (route_cache, check_one_route, &check_data);

	nl_cache_free (route_cache);
}
