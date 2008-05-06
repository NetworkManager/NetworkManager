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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
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


/*
 * nm_system_device_set_ip4_route
 *
 */
static gboolean
nm_system_device_set_ip4_route (const char *iface,
                                NMIP4Config *iface_config,
                                guint32 ip4_gateway,
                                guint32 ip4_dest,
                                int prefix,
                                int mss)
{
	gboolean success = FALSE;
	struct rtnl_route *route = NULL;
	struct rtnl_route *route2 = NULL;
	struct nl_handle *nlh = NULL;
	struct nl_addr *gw_addr = NULL;
	struct nl_addr *dest_addr = NULL;
	int err, iface_idx, i;

	/*
	 * Zero is not a legal gateway and the ioctl will fail.  But zero is a
	 * way of saying "no route" so we just return here.  Hopefully the
	 * caller flushed the routes, first.
	 */
	if (ip4_gateway == 0)
		return TRUE;

	/*
	 * Do not add the route if the destination is on the same subnet.
	 */
	if (iface_config) {
		for (i = 0; i < nm_ip4_config_get_num_addresses (iface_config); i++) {
			const NMSettingIP4Address *cfg_addr;

			cfg_addr = nm_ip4_config_get_address (iface_config, i);
		    if ((ip4_dest & cfg_addr->netmask) == (cfg_addr->address & cfg_addr->netmask))
		    	return TRUE;
		}
	}

	nlh = nm_netlink_get_default_handle ();
	g_return_val_if_fail (nlh != NULL, FALSE);

	iface_idx = nm_netlink_iface_to_index (iface);
	g_return_val_if_fail (iface_idx >= 0, FALSE);

	route = rtnl_route_alloc ();
	g_return_val_if_fail (route != NULL, FALSE);

	rtnl_route_set_scope (route, RT_SCOPE_UNIVERSE);
	rtnl_route_set_oif (route, iface_idx);

	gw_addr = nl_addr_build (AF_INET, &ip4_gateway, sizeof (ip4_gateway));
	if (gw_addr == NULL)
		goto out;
	rtnl_route_set_gateway (route, gw_addr);

	dest_addr = nl_addr_build (AF_INET, &ip4_dest, sizeof (ip4_dest));
	if (dest_addr == NULL)
		goto out;
	nl_addr_set_prefixlen (dest_addr, prefix);
	rtnl_route_set_dst (route, dest_addr);
	nl_addr_put (dest_addr);

	if (mss) {
		if (rtnl_route_set_metric (route, RTAX_ADVMSS, mss) < 0)
			goto out;
	}

	err = rtnl_route_add (nlh, route, 0);
	if (err == 0) {
		/* Everything good */
		success = TRUE;
		goto out;
	}

	if (err != ESRCH) {
		nm_warning ("Failed to set IPv4 default route on '%s': %s",
		            iface,
		            nl_geterror ());
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
	if (!err) {
		success = TRUE;
	} else {
		rtnl_route_del (nlh, route2, 0);
		nm_warning ("Failed to set IPv4 default route on '%s': %s",
		            iface,
		            nl_geterror ());
	}

out:
	if (gw_addr)
		nl_addr_put (gw_addr);
	if (route2)
		rtnl_route_put (route2);
	if (route)
		rtnl_route_put (route);
	return success;
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
							   NMIP4Config *config,
							   gboolean route_to_iface)
{
	int len, i;

	g_return_val_if_fail (iface != NULL, FALSE);
	g_return_val_if_fail (config != NULL, FALSE);

	if (!add_ip4_addresses (config, iface))
		return FALSE;

	sleep (1);

	len = nm_ip4_config_get_num_static_routes (config);
	for (i = 0; i < len; i++) {
		guint32 mss = nm_ip4_config_get_mss (config);
		guint32 route = nm_ip4_config_get_static_route (config, (i * 2) + 1);
		guint32 saddr = nm_ip4_config_get_static_route (config, i * 2);

		nm_system_device_set_ip4_route (iface, config, route, saddr, 32, mss);
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
                                          NMIP4Config *config,
                                          GSList *routes)
{
	NMIP4Config *ad_config = NULL;
	NMNamedManager *named_mgr;
	int i;

	g_return_val_if_fail (config != NULL, FALSE);

	/* Set up a route to the VPN gateway through the real network device */
	if (active_device && (ad_config = nm_device_get_ip4_config (active_device))) {
		guint32 ad_gw = 0, vpn_gw = 0;
		const NMSettingIP4Address *tmp;

		for (i = 0; i < nm_ip4_config_get_num_addresses (ad_config); i++) {
			tmp = nm_ip4_config_get_address (ad_config, i);
			if (tmp->gateway) {
				ad_gw = tmp->gateway;
				break;
			}
		}

		for (i = 0; i < nm_ip4_config_get_num_addresses (config); i++) {
			tmp = nm_ip4_config_get_address (config, i);
			if (tmp->gateway) {
				vpn_gw = tmp->gateway;
				break;
			}
		}

		nm_system_device_set_ip4_route (nm_device_get_ip_iface (active_device),
								  ad_config, ad_gw, vpn_gw, 32,
								  nm_ip4_config_get_mss (config));
	}

	if (!iface || !strlen (iface))
		goto out;

	nm_system_device_set_up_down_with_iface (iface, TRUE);

	if (!add_ip4_addresses (config, iface))
		goto out;

	/* Set the MTU */
	if (nm_ip4_config_get_mtu (config))
		nm_system_device_set_mtu (iface, nm_ip4_config_get_mtu (config));

	sleep (1);

	nm_system_device_flush_ip4_routes_with_iface (iface);

	if (g_slist_length (routes) == 0) {
		nm_system_device_replace_default_ip4_route (iface, 0, 0);
	} else {
		GSList *iter;

		for (iter = routes; iter; iter = iter->next)
			nm_system_device_add_ip4_route_via_device_with_iface (iface, (char *) iter->data);
	}

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
	int err, fd;

	fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		nm_warning ("couldn't open control socket.");
		return FALSE;
	}

	/* Get device's flags */
	strncpy (ifr.ifr_name, iface, IFNAMSIZ);
	err = ioctl (fd, SIOCGIFFLAGS, &ifr);
	close (fd);

	if (!err)
		return (!((ifr.ifr_flags^IFF_UP) & IFF_UP));

	if (errno != ENODEV) {
		nm_warning ("%s: could not get flags for device %s.  errno = %d", 
		            __func__, iface, errno);
	}

	return FALSE;
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
 * nm_system_device_add_ip4_route_via_device_with_iface
 *
 * Add route to the given device
 *
 */
void nm_system_device_add_ip4_route_via_device_with_iface (const char *iface, const char *addr)
{
	struct rtnl_route *route;
	struct nl_handle *nlh;
	struct nl_addr *dst;
	int iface_idx, err;

	nlh = nm_netlink_get_default_handle ();
	g_return_if_fail (nlh != NULL);

	route = rtnl_route_alloc ();
	g_return_if_fail (route != NULL);

	iface_idx = nm_netlink_iface_to_index (iface);
	if (iface_idx < 0)
		goto out;
	rtnl_route_set_oif (route, iface_idx);

	if (!(dst = nl_addr_parse (addr, AF_INET)))
		goto out;
	rtnl_route_set_dst (route, dst);
	nl_addr_put (dst);

	err = rtnl_route_add (nlh, route, 0);
	if (err) {
		nm_warning ("rtnl_route_add() returned error %s (%d)\n%s",
		            strerror (err), err, nl_geterror());
	}

out:
	rtnl_route_put (route);
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
	if (err) {
		nm_warning ("rtnl_route_add() returned error %s (%d)\n%s",
		            strerror (err), err, nl_geterror());
	}

out:
	rtnl_route_put (route);
}

