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
 * Copyright (C) 2004 - 2012 Red Hat, Inc.
 * Copyright (C) 2005 - 2008 Novell, Inc.
 * Copyright (C) 1996 - 1997 Yoichi Hariguchi <yoichi@fore.com>
 * Copyright (C) January, 1998 Sergei Viznyuk <sv@phystech.com>
 */

#include <config.h>
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
#include <linux/if.h>
#include <linux/sockios.h>

#include "nm-system.h"
#include "nm-platform.h"
#include "nm-device.h"
#include "NetworkManagerUtils.h"
#include "nm-utils.h"
#include "nm-logging.h"

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

NMPlatformIP4Route *
nm_system_add_ip4_vpn_gateway_route (NMDevice *parent_device, guint32 vpn_gw)
{
	NMIP4Config *parent_config;
	guint32 parent_gw = 0, parent_prefix = 0, i;
	NMIP4Address *tmp;
	NMPlatformIP4Route *route = g_new0 (NMPlatformIP4Route, 1);

	g_return_val_if_fail (NM_IS_DEVICE (parent_device), NULL);
	g_return_val_if_fail (vpn_gw != 0, NULL);

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

	if (!parent_gw) {
		g_free (route);
		return NULL;
	}

	route->ifindex = nm_device_get_ip_ifindex (parent_device);
	route->network = vpn_gw;
	route->plen = 32;
	route->gateway = parent_gw;
	route->metric = 1024;
	route->mss = nm_ip4_config_get_mss (parent_config);

	/* If the VPN gateway is in the same subnet as one of the parent device's
	 * IP addresses, don't add the host route to it, but a route through the
	 * parent device.
	 */
	if (ip4_dest_in_same_subnet (parent_config, vpn_gw, parent_prefix))
		route->gateway = 0;

	if (!nm_platform_ip4_route_add (route->ifindex,
	                               route->network,
	                               route->plen,
	                               route->gateway,
	                               route->metric,
	                               route->mss)) {
		g_free (route);
		nm_log_err (LOGD_DEVICE | LOGD_IP4,
			"(%s): failed to add IPv4 route to VPN gateway: %s",
			nm_device_get_iface (parent_device),
			nm_platform_get_error_msg ());
		return NULL;
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
	int i;

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (config != NULL, FALSE);

	if (flags & NM_IP4_COMPARE_FLAG_ADDRESSES) {
		int count = nm_ip4_config_get_num_addresses (config);
		NMIP4Address *config_address;
		GArray *addresses = g_array_sized_new (FALSE, FALSE, sizeof (NMPlatformIP4Address), count);
		NMPlatformIP4Address address;

		for (i = 0; i < count; i++) {
			config_address = nm_ip4_config_get_address (config, i);
			memset (&address, 0, sizeof (address));
			address.address = nm_ip4_address_get_address (config_address);
			address.plen = nm_ip4_address_get_prefix (config_address);
			g_array_append_val (addresses, address);
		}

		nm_platform_ip4_address_sync (ifindex, addresses);
		g_array_unref (addresses);
	}

	if (flags & NM_IP4_COMPARE_FLAG_ROUTES) {
		int count = nm_ip4_config_get_num_routes (config);
		NMIP4Route *config_route;
		GArray *routes = g_array_sized_new (FALSE, FALSE, sizeof (NMPlatformIP4Route), count);
		NMPlatformIP4Route route;

		for (i = 0; i < count; i++) {
			config_route = nm_ip4_config_get_route (config, i);
			memset (&route, 0, sizeof (route));
			route.network = nm_ip4_route_get_dest (config_route);
			route.plen = nm_ip4_route_get_prefix (config_route);
			route.gateway = nm_ip4_route_get_next_hop (config_route);
			route.metric = priority;

			/* Don't add the route if it's more specific than one of the subnets
			 * the device already has an IP address on.
			 */
			if (ip4_dest_in_same_subnet (config, route.network, route.plen))
				continue;

			/* Don't add the default route when and the connection
			 * is never supposed to be the default connection.
			 */
			if (nm_ip4_config_get_never_default (config) && route.network == 0)
				continue;

			g_array_append_val (routes, route);
		}

		nm_platform_ip4_route_sync (ifindex, routes);
		g_array_unref (routes);
	}

	if (flags & NM_IP4_COMPARE_FLAG_MTU) {
		if (nm_ip4_config_get_mtu (config))
			nm_platform_link_set_mtu (ifindex, nm_ip4_config_get_mtu (config));
	}

	return TRUE;
}

static gboolean
ip6_dest_in_same_subnet (NMIP6Config *config, const struct in6_addr *dest, guint32 dest_prefix)
{
	int num;
	int i;

	num = nm_ip6_config_get_num_addresses (config);
	for (i = 0; i < num; i++) {
		NMIP6Address *addr = nm_ip6_config_get_address (config, i);
		guint32 prefix = nm_ip6_address_get_prefix (addr);
		const struct in6_addr *address = nm_ip6_address_get_address (addr);

		if (prefix <= dest_prefix) {
			const guint8 *maskbytes = (const guint8 *)address;
			const guint8 *addrbytes = (const guint8 *)dest;
			int nbytes, nbits;

			/* Copied from g_inet_address_mask_matches() */
			nbytes = prefix / 8;
			if (nbytes != 0 && memcmp (maskbytes, addrbytes, nbytes) != 0)
				continue;

			nbits = prefix % 8;
			if (nbits == 0)
				return TRUE;

			if (maskbytes[nbytes] == (addrbytes[nbytes] & (0xFF << (8 - nbits))))
				return TRUE;
		}
	}

	return FALSE;
}

NMPlatformIP6Route *
nm_system_add_ip6_vpn_gateway_route (NMDevice *parent_device,
                                     const struct in6_addr *vpn_gw)
{
	NMIP6Config *parent_config;
	const struct in6_addr *parent_gw = NULL;
	guint32 parent_prefix = 0;
	int i;
	NMIP6Address *tmp;
	NMPlatformIP6Route *route = g_new0 (NMPlatformIP6Route, 1);

	g_return_val_if_fail (NM_IS_DEVICE (parent_device), NULL);
	g_return_val_if_fail (vpn_gw != NULL, NULL);

	/* This is all just the same as
	 * nm_system_add_ip4_vpn_gateway_route(), except with an IPv6
	 * address for the VPN gateway.
	 */

	parent_config = nm_device_get_ip6_config (parent_device);
	g_return_val_if_fail (parent_config != NULL, NULL);

	for (i = 0; i < nm_ip6_config_get_num_addresses (parent_config); i++) {
		tmp = nm_ip6_config_get_address (parent_config, i);
		if (nm_ip6_address_get_gateway (tmp)) {
			parent_gw = nm_ip6_address_get_gateway (tmp);
			parent_prefix = nm_ip6_address_get_prefix (tmp);
			break;
		}
	}

	if (!parent_gw) {
		g_free (route);
		return NULL;
	}

	route->ifindex = nm_device_get_ip_ifindex (parent_device);
	route->network = *vpn_gw;
	route->plen = 128;
	route->gateway = *parent_gw;
	route->metric = 1024;
	route->mss = nm_ip6_config_get_mss (parent_config);

	/* If the VPN gateway is in the same subnet as one of the parent device's
	 * IP addresses, don't add the host route to it, but a route through the
	 * parent device.
	 */
	if (ip6_dest_in_same_subnet (parent_config, vpn_gw, parent_prefix))
		route->gateway = in6addr_any;

	if (!nm_platform_ip6_route_add (route->ifindex,
	                               route->network,
	                               route->plen,
	                               route->gateway,
	                               route->metric,
	                               route->mss)) {
		g_free (route);
		nm_log_err (LOGD_DEVICE | LOGD_IP6,
			"(%s): failed to add IPv6 route to VPN gateway: %s",
			nm_device_get_iface (parent_device),
			nm_platform_get_error_msg ());
		return NULL;
	}

	return route;
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
	int i;

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (config != NULL, FALSE);

	if (flags & NM_IP6_COMPARE_FLAG_ADDRESSES) {
		int count = nm_ip6_config_get_num_addresses (config);
		NMIP6Address *config_address;
		GArray *addresses = g_array_sized_new (FALSE, FALSE, sizeof (NMPlatformIP6Address), count);
		NMPlatformIP6Address address;

		for (i = 0; i < count; i++) {
			config_address = nm_ip6_config_get_address (config, i);
			memset (&address, 0, sizeof (address));
			address.address = *nm_ip6_address_get_address (config_address);
			address.plen = nm_ip6_address_get_prefix (config_address);
			g_array_append_val (addresses, address);
		}

		nm_platform_ip6_address_sync (ifindex, addresses);
		g_array_unref (addresses);
	}

	if (flags & NM_IP6_COMPARE_FLAG_ROUTES) {
		int count = nm_ip6_config_get_num_routes (config);
		NMIP6Route *config_route;
		GArray *routes = g_array_sized_new (FALSE, FALSE, sizeof (NMPlatformIP6Route), count);
		NMPlatformIP6Route route;

		for (i = 0; i < count; i++) {
			config_route = nm_ip6_config_get_route (config, i);
			memset (&route, 0, sizeof (route));
			route.network = *nm_ip6_route_get_dest (config_route);
			route.plen = nm_ip6_route_get_prefix (config_route);
			route.gateway = *nm_ip6_route_get_next_hop (config_route);

			/* Don't add the route if it's more specific than one of the subnets
			 * the device already has an IP address on.
			 */
			if (ip6_dest_in_same_subnet (config, &route.network, route.plen))
				continue;

			/* Don't add the default route when and the connection
			 * is never supposed to be the default connection.
			 */
			if (nm_ip6_config_get_never_default (config) && IN6_IS_ADDR_UNSPECIFIED (&route.network))
				continue;

			g_array_append_val (routes, route);
		}

		nm_platform_ip6_route_sync (ifindex, routes);
		g_array_unref (routes);
	}

// FIXME
//	if (priority > 0)
//		nm_system_device_set_priority (iface, config, priority);

	return TRUE;
}

static const struct {
	const char *option;
	const char *default_value;
} bonding_defaults[] = {
	{ "mode", "balance-rr" },
	{ "arp_interval", "0" },
	{ "miimon", "0" },

	{ "ad_select", "stable" },
	{ "arp_validate", "none" },
	{ "downdelay", "0" },
	{ "fail_over_mac", "none" },
	{ "lacp_rate", "slow" },
	{ "min_links", "0" },
	{ "num_grat_arp", "1" },
	{ "num_unsol_na", "1" },
	{ "primary", "" },
	{ "primary_reselect", "always" },
	{ "resend_igmp", "1" },
	{ "updelay", "0" },
	{ "use_carrier", "1" },
	{ "xmit_hash_policy", "layer2" },
	{ NULL, NULL }
};

static void
remove_bonding_entries (const char *iface, const char *path)
{
	char cmd[20];
	char *value, **entries;
	gboolean ret;
	int i;

	if (!g_file_get_contents (path, &value, NULL, NULL))
		return;

	entries = g_strsplit (value, " ", -1);
	for (i = 0; entries[i]; i++) {
		snprintf (cmd, sizeof (cmd), "-%s", g_strstrip (entries[i]));
		ret = nm_utils_do_sysctl (path, cmd);
		if (!ret) {
			nm_log_warn (LOGD_HW, "(%s): failed to remove entry '%s' from '%s'",
			             iface, entries[i], path);
		}
	}
	g_strfreev (entries);
}

static gboolean
option_valid_for_nm_setting (const char *option, const char **valid_opts)
{
	while (*valid_opts) {
		if (strcmp (option, *valid_opts) == 0)
			return TRUE;
		valid_opts++;
	}
	return FALSE;
}

gboolean
nm_system_apply_bonding_config (const char *iface, NMSettingBond *s_bond)
{
	const char **valid_opts;
	const char *option, *value;
	char path[FILENAME_MAX];
	char *current, *space;
	gboolean ret;
	int i;

	g_return_val_if_fail (iface != NULL, FALSE);

	/* Remove old slaves and arp_ip_targets */
	snprintf (path, sizeof (path), "/sys/class/net/%s/bonding/arp_ip_target", iface);
	remove_bonding_entries (iface, path);
	snprintf (path, sizeof (path), "/sys/class/net/%s/bonding/slaves", iface);
	remove_bonding_entries (iface, path);

	/* Apply config/defaults */
	valid_opts = nm_setting_bond_get_valid_options (s_bond);
	for (i = 0; bonding_defaults[i].option; i++) {
		option = bonding_defaults[i].option;
		if (option_valid_for_nm_setting (option, valid_opts))
			value = nm_setting_bond_get_option_by_name (s_bond, option);
		else
			value = NULL;
		if (!value)
			value = bonding_defaults[i].default_value;

		snprintf (path, sizeof (path), "/sys/class/net/%s/bonding/%s", iface, option);
		if (g_file_get_contents (path, &current, NULL, NULL)) {
			g_strstrip (current);
			space = strchr (current, ' ');
			if (space)
				*space = '\0';
			if (strcmp (current, value) != 0) {
				ret = nm_utils_do_sysctl (path, value);
				if (!ret) {
					nm_log_warn (LOGD_HW, "(%s): failed to set bonding attribute "
					             "'%s' to '%s'", iface, option, value);
				}
			}
		}
	}

	/* Handle arp_ip_target */
	value = nm_setting_bond_get_option_by_name (s_bond, "arp_ip_target");
	if (value) {
		char **addresses, cmd[20];

		snprintf (path, sizeof (path), "/sys/class/net/%s/bonding/arp_ip_target", iface);
		addresses = g_strsplit (value, ",", -1);
		for (i = 0; addresses[i]; i++) {
			snprintf (cmd, sizeof (cmd), "+%s", g_strstrip (addresses[i]));
			ret = nm_utils_do_sysctl (path, cmd);
			if (!ret) {
				nm_log_warn (LOGD_HW, "(%s): failed to add arp_ip_target '%s'",
				             iface, addresses[i]);
			}
		}
		g_strfreev (addresses);
	}

	return TRUE;
}
