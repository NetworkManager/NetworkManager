/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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
 * Copyright (C) 2005 - 2010 Red Hat, Inc.
 *
 */

#include "nm-default.h"

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "nm-dhcp-utils.h"
#include "nm-utils.h"
#include "NetworkManagerUtils.h"
#include "nm-platform.h"

/********************************************/

static gboolean
ip4_process_dhcpcd_rfc3442_routes (const char *str,
                                   guint32 priority,
                                   NMIP4Config *ip4_config,
                                   guint32 *gwaddr)
{
	char **routes, **r;
	gboolean have_routes = FALSE;

	routes = g_strsplit (str, " ", 0);
	if (g_strv_length (routes) == 0)
		goto out;

	if ((g_strv_length (routes) % 2) != 0) {
		nm_log_warn (LOGD_DHCP4, "  classless static routes provided, but invalid");
		goto out;
	}

	for (r = routes; *r; r += 2) {
		char *slash;
		NMPlatformIP4Route route;
		int rt_cidr = 32;
		guint32 rt_addr, rt_route;

		slash = strchr(*r, '/');
		if (slash) {
			*slash = '\0';
			errno = 0;
			rt_cidr = strtol (slash + 1, NULL, 10);
			if (errno || rt_cidr > 32) {
				nm_log_warn (LOGD_DHCP4, "DHCP provided invalid classless static route cidr: '%s'", slash + 1);
				continue;
			}
		}
		if (inet_pton (AF_INET, *r, &rt_addr) <= 0) {
			nm_log_warn (LOGD_DHCP4, "DHCP provided invalid classless static route address: '%s'", *r);
			continue;
		}
		if (inet_pton (AF_INET, *(r + 1), &rt_route) <= 0) {
			nm_log_warn (LOGD_DHCP4, "DHCP provided invalid classless static route gateway: '%s'", *(r + 1));
			continue;
		}

		have_routes = TRUE;
		if (rt_cidr == 0 && rt_addr == 0) {
			/* FIXME: how to handle multiple routers? */
			*gwaddr = rt_route;
		} else {
			nm_log_info (LOGD_DHCP4, "  classless static route %s/%d gw %s", *r, rt_cidr, *(r + 1));
			memset (&route, 0, sizeof (route));
			route.network = rt_addr;
			route.plen = rt_cidr;
			route.gateway = rt_route;
			route.source = NM_IP_CONFIG_SOURCE_DHCP;
			route.metric = priority;
			nm_ip4_config_add_route (ip4_config, &route);
		}
	}

out:
	g_strfreev (routes);
	return have_routes;
}

static const char **
process_dhclient_rfc3442_route (const char **octets,
                                NMPlatformIP4Route *route,
                                gboolean *success)
{
	const char **o = octets;
	int addr_len = 0, i = 0;
	long int tmp;
	char *next_hop;
	guint32 tmp_addr;

	*success = FALSE;

	if (!*o)
		return o; /* no prefix */

	tmp = strtol (*o, NULL, 10);
	if (tmp < 0 || tmp > 32)  /* 32 == max IP4 prefix length */
		return o;

	memset (route, 0, sizeof (*route));
	route->plen = tmp;
	o++;

	if (tmp > 0)
		addr_len = ((tmp - 1) / 8) + 1;

	/* ensure there's at least the address + next hop left */
	if (g_strv_length ((char **) o) < addr_len + 4)
		goto error;

	if (tmp) {
		const char *addr[4] = { "0", "0", "0", "0" };
		char *str_addr;

		for (i = 0; i < addr_len; i++)
			addr[i] = *o++;

		str_addr = g_strjoin (".", addr[0], addr[1], addr[2], addr[3], NULL);
		if (inet_pton (AF_INET, str_addr, &tmp_addr) <= 0) {
			g_free (str_addr);
			goto error;
		}
		g_free (str_addr);
		tmp_addr &= nm_utils_ip4_prefix_to_netmask ((guint32) tmp);
		route->network = tmp_addr;
	}

	/* Handle next hop */
	next_hop = g_strjoin (".", o[0], o[1], o[2], o[3], NULL);
	if (inet_pton (AF_INET, next_hop, &tmp_addr) <= 0) {
		g_free (next_hop);
		goto error;
	}
	route->gateway = tmp_addr;
	g_free (next_hop);

	*success = TRUE;
	return o + 4; /* advance to past the next hop */

error:
	return o;
}

static gboolean
ip4_process_dhclient_rfc3442_routes (const char *str,
                                     guint32 priority,
                                     NMIP4Config *ip4_config,
                                     guint32 *gwaddr)
{
	char **octets, **o;
	gboolean have_routes = FALSE;
	NMPlatformIP4Route route;
	gboolean success;

	o = octets = g_strsplit_set (str, " .", 0);
	if (g_strv_length (octets) < 5) {
		nm_log_warn (LOGD_DHCP4, "ignoring invalid classless static routes '%s'", str);
		goto out;
	}

	while (*o) {
		memset (&route, 0, sizeof (route));
		o = (char **) process_dhclient_rfc3442_route ((const char **) o, &route, &success);
		if (!success) {
			nm_log_warn (LOGD_DHCP4, "ignoring invalid classless static routes");
			break;
		}

		have_routes = TRUE;
		if (!route.plen) {
			/* gateway passed as classless static route */
			*gwaddr = route.gateway;
		} else {
			char addr[INET_ADDRSTRLEN];

			/* normal route */
			route.source = NM_IP_CONFIG_SOURCE_DHCP;
			route.metric = priority;
			nm_ip4_config_add_route (ip4_config, &route);

			nm_log_info (LOGD_DHCP4, "  classless static route %s/%d gw %s",
			             nm_utils_inet4_ntop (route.network, addr), route.plen,
			             nm_utils_inet4_ntop (route.gateway, NULL));
		}
	}

out:
	g_strfreev (octets);
	return have_routes;
}

static gboolean
ip4_process_classless_routes (GHashTable *options,
                              guint32 priority,
                              NMIP4Config *ip4_config,
                              guint32 *gwaddr)
{
	const char *str, *p;

	g_return_val_if_fail (options != NULL, FALSE);
	g_return_val_if_fail (ip4_config != NULL, FALSE);

	*gwaddr = 0;

	/* dhcpd/dhclient in Fedora has support for rfc3442 implemented using a
	 * slightly different format:
	 *
	 * option classless-static-routes = array of (destination-descriptor ip-address);
	 *
	 * which results in:
	 *
	 * 0 192.168.0.113 25.129.210.177.132 192.168.0.113 7.2 10.34.255.6
	 *
	 * dhcpcd supports classless static routes natively and uses this same
	 * option identifier with the following format:
	 *
	 * 192.168.10.0/24 192.168.1.1 10.0.0.0/8 10.17.66.41
	 */
	str = g_hash_table_lookup (options, "classless_static_routes");

	/* dhclient doesn't have actual support for rfc3442 classless static routes
	 * upstream.  Thus, people resort to defining the option in dhclient.conf
	 * and using arbitrary formats like so:
	 *
	 * option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;
	 *
	 * See https://lists.isc.org/pipermail/dhcp-users/2008-December/007629.html
	 */
	if (!str)
		str = g_hash_table_lookup (options, "rfc3442_classless_static_routes");

	/* Microsoft version; same as rfc3442 but with a different option # (249) */
	if (!str)
		str = g_hash_table_lookup (options, "ms_classless_static_routes");

	if (!str || !strlen (str))
		return FALSE;

	p = str;
	while (*p) {
		if (!g_ascii_isdigit (*p) && (*p != ' ') && (*p != '.') && (*p != '/')) {
			nm_log_warn (LOGD_DHCP4, "ignoring invalid classless static routes '%s'", str);
			return FALSE;
		}
		p++;
	};

	if (strchr (str, '/')) {
		/* dhcpcd format */
		return ip4_process_dhcpcd_rfc3442_routes (str, priority, ip4_config, gwaddr);
	}

	return ip4_process_dhclient_rfc3442_routes (str, priority, ip4_config, gwaddr);
}

static void
process_classful_routes (GHashTable *options, guint32 priority, NMIP4Config *ip4_config)
{
	const char *str;
	char **searches, **s;

	str = g_hash_table_lookup (options, "static_routes");
	if (!str)
		return;

	searches = g_strsplit (str, " ", 0);
	if ((g_strv_length (searches) % 2)) {
		nm_log_info (LOGD_DHCP, "  static routes provided, but invalid");
		goto out;
	}

	for (s = searches; *s; s += 2) {
		NMPlatformIP4Route route;
		guint32 rt_addr, rt_route;

		if (inet_pton (AF_INET, *s, &rt_addr) <= 0) {
			nm_log_warn (LOGD_DHCP, "DHCP provided invalid static route address: '%s'", *s);
			continue;
		}
		if (inet_pton (AF_INET, *(s + 1), &rt_route) <= 0) {
			nm_log_warn (LOGD_DHCP, "DHCP provided invalid static route gateway: '%s'", *(s + 1));
			continue;
		}

		// FIXME: ensure the IP address and route are sane

		memset (&route, 0, sizeof (route));
		route.network = rt_addr;
		/* RFC 2132, updated by RFC 3442:
		   The Static Routes option (option 33) does not provide a subnet mask
		   for each route - it is assumed that the subnet mask is implicit in
		   whatever network number is specified in each route entry */
		route.plen = nm_utils_ip4_get_default_prefix (rt_addr);
		if (rt_addr & ~nm_utils_ip4_prefix_to_netmask (route.plen)) {
			/* RFC 943: target not "this network"; using host routing */
			route.plen = 32;
		}
		route.gateway = rt_route;
		route.source = NM_IP_CONFIG_SOURCE_DHCP;
		route.metric = priority;

		nm_ip4_config_add_route (ip4_config, &route);
		nm_log_info (LOGD_DHCP, "  static route %s",
		             nm_platform_ip4_route_to_string (&route, NULL, 0));
	}

out:
	g_strfreev (searches);
}

static void
process_domain_search (const char *str, GFunc add_func, gpointer user_data)
{
	char **searches, **s;
	char *unescaped, *p;
	int i;

	g_return_if_fail (str != NULL);
	g_return_if_fail (add_func != NULL);

	p = unescaped = g_strdup (str);
	do {
		p = strstr (p, "\\032");
		if (!p)
			break;

		/* Clear the escaped space with real spaces */
		for (i = 0; i < 4; i++)
			*p++ = ' ';
	} while (*p++);

	if (strchr (unescaped, '\\')) {
		nm_log_warn (LOGD_DHCP, "  invalid domain search: '%s'", unescaped);
		goto out;
	}

	searches = g_strsplit (unescaped, " ", 0);
	for (s = searches; *s; s++) {
		if (strlen (*s)) {
			nm_log_info (LOGD_DHCP, "  domain search '%s'", *s);
			add_func (*s, user_data);
		}
	}
	g_strfreev (searches);

out:
	g_free (unescaped);
}

static void
ip4_add_domain_search (gpointer data, gpointer user_data)
{
	nm_ip4_config_add_search (NM_IP4_CONFIG (user_data), (const char *) data);
}

NMIP4Config *
nm_dhcp_utils_ip4_config_from_options (int ifindex,
                                       const char *iface,
                                       GHashTable *options,
                                       guint32 priority)
{
	NMIP4Config *ip4_config = NULL;
	guint32 tmp_addr;
	in_addr_t addr;
	NMPlatformIP4Address address;
	char *str = NULL;
	guint32 gwaddr = 0;
	guint8 plen = 0;

	g_return_val_if_fail (options != NULL, NULL);

	ip4_config = nm_ip4_config_new (ifindex);
	memset (&address, 0, sizeof (address));
	address.timestamp = nm_utils_get_monotonic_timestamp_s ();

	str = g_hash_table_lookup (options, "ip_address");
	if (str && (inet_pton (AF_INET, str, &addr) > 0))
		nm_log_info (LOGD_DHCP4, "  address %s", str);
	else
		goto error;

	str = g_hash_table_lookup (options, "subnet_mask");
	if (str && (inet_pton (AF_INET, str, &tmp_addr) > 0)) {
		plen = nm_utils_ip4_netmask_to_prefix (tmp_addr);
		nm_log_info (LOGD_DHCP4, "  plen %d (%s)", plen, str);
	} else {
		/* Get default netmask for the IP according to appropriate class. */
		plen = nm_utils_ip4_get_default_prefix (addr);
		nm_log_info (LOGD_DHCP4, "  plen %d (default)", plen);
	}
	nm_platform_ip4_address_set_addr (&address, addr, plen);

	/* Routes: if the server returns classless static routes, we MUST ignore
	 * the 'static_routes' option.
	 */
	if (!ip4_process_classless_routes (options, priority, ip4_config, &gwaddr))
		process_classful_routes (options, priority, ip4_config);

	if (gwaddr) {
		nm_log_info (LOGD_DHCP4, "  gateway %s", nm_utils_inet4_ntop (gwaddr, NULL));
		nm_ip4_config_set_gateway (ip4_config, gwaddr);
	} else {
		/* If the gateway wasn't provided as a classless static route with a
		 * subnet length of 0, try to find it using the old-style 'routers' option.
		 */
		str = g_hash_table_lookup (options, "routers");
		if (str) {
			char **routers = g_strsplit (str, " ", 0);
			char **s;

			for (s = routers; *s; s++) {
				/* FIXME: how to handle multiple routers? */
				if (inet_pton (AF_INET, *s, &gwaddr) > 0) {
					nm_ip4_config_set_gateway (ip4_config, gwaddr);
					nm_log_info (LOGD_DHCP4, "  gateway %s", *s);
					break;
				} else
					nm_log_warn (LOGD_DHCP4, "ignoring invalid gateway '%s'", *s);
			}
			g_strfreev (routers);
		}
	}

	/*
	 * RFC 2132, section 9.7
	 *   DHCP clients use the contents of the 'server identifier' field
	 *   as the destination address for any DHCP messages unicast to
	 *   the DHCP server.
	 *
	 * Some ISP's provide leases from central servers that are on
	 * different subnets that the address offered.  If the host
	 * does not configure the interface as the default route, the
	 * dhcp server may not be reachable via unicast, and a host
	 * specific route is needed.
	 **/
	str = g_hash_table_lookup (options, "dhcp_server_identifier");
	if (str) {
		if (inet_pton (AF_INET, str, &tmp_addr) > 0) {

			nm_log_info (LOGD_DHCP4, "  server identifier %s", str);
			if (   nm_utils_ip4_address_clear_host_address(tmp_addr, address.plen) != nm_utils_ip4_address_clear_host_address(address.address, address.plen)
			    && !nm_ip4_config_get_direct_route_for_host (ip4_config, tmp_addr)) {
				/* DHCP server not on assigned subnet and the no direct route was returned. Add route */
				NMPlatformIP4Route route = { 0 };

				route.network = tmp_addr;
				route.plen = 32;
				/* this will be a device route if gwaddr is 0 */
				route.gateway = gwaddr;
				route.source = NM_IP_CONFIG_SOURCE_DHCP;
				route.metric = priority;
				nm_ip4_config_add_route (ip4_config, &route);
				nm_log_dbg (LOGD_IP, "adding route for server identifier: %s",
				                      nm_platform_ip4_route_to_string (&route, NULL, 0));
			}
		}
		else
			nm_log_warn (LOGD_DHCP4, "ignoring invalid server identifier '%s'", str);
	}

	str = g_hash_table_lookup (options, "dhcp_lease_time");
	if (str) {
		address.lifetime = address.preferred = strtoul (str, NULL, 10);
		nm_log_info (LOGD_DHCP4, "  lease time %u", address.lifetime);
	}

	address.source = NM_IP_CONFIG_SOURCE_DHCP;
	nm_ip4_config_add_address (ip4_config, &address);

	str = g_hash_table_lookup (options, "host_name");
	if (str)
		nm_log_info (LOGD_DHCP4, "  hostname '%s'", str);

	str = g_hash_table_lookup (options, "domain_name_servers");
	if (str) {
		char **dns = g_strsplit (str, " ", 0);
		char **s;

		for (s = dns; *s; s++) {
			if (inet_pton (AF_INET, *s, &tmp_addr) > 0) {
				if (tmp_addr) {
					nm_ip4_config_add_nameserver (ip4_config, tmp_addr);
					nm_log_info (LOGD_DHCP4, "  nameserver '%s'", *s);
				}
			} else
				nm_log_warn (LOGD_DHCP4, "ignoring invalid nameserver '%s'", *s);
		}
		g_strfreev (dns);
	}

	str = g_hash_table_lookup (options, "domain_name");
	if (str) {
		char **domains = g_strsplit (str, " ", 0);
		char **s;

		for (s = domains; *s; s++) {
			nm_log_info (LOGD_DHCP4, "  domain name '%s'", *s);
			nm_ip4_config_add_domain (ip4_config, *s);
		}
		g_strfreev (domains);
	}

	str = g_hash_table_lookup (options, "domain_search");
	if (str)
		process_domain_search (str, ip4_add_domain_search, ip4_config);

	str = g_hash_table_lookup (options, "netbios_name_servers");
	if (str) {
		char **nbns = g_strsplit (str, " ", 0);
		char **s;

		for (s = nbns; *s; s++) {
			if (inet_pton (AF_INET, *s, &tmp_addr) > 0) {
				if (tmp_addr) {
					nm_ip4_config_add_wins (ip4_config, tmp_addr);
					nm_log_info (LOGD_DHCP4, "  wins '%s'", *s);
				}
			} else
				nm_log_warn (LOGD_DHCP4, "ignoring invalid WINS server '%s'", *s);
		}
		g_strfreev (nbns);
	}

	str = g_hash_table_lookup (options, "interface_mtu");
	if (str) {
		int int_mtu;

		errno = 0;
		int_mtu = strtol (str, NULL, 10);
		if ((errno == EINVAL) || (errno == ERANGE))
			goto error;

		if (int_mtu > 576)
			nm_ip4_config_set_mtu (ip4_config, int_mtu, NM_IP_CONFIG_SOURCE_DHCP);
	}

	str = g_hash_table_lookup (options, "nis_domain");
	if (str) {
		nm_log_info (LOGD_DHCP4, "  NIS domain '%s'", str);
		nm_ip4_config_set_nis_domain (ip4_config, str);
	}

	str = g_hash_table_lookup (options, "nis_servers");
	if (str) {
		char **nis = g_strsplit (str, " ", 0);
		char **s;

		for (s = nis; *s; s++) {
			if (inet_pton (AF_INET, *s, &tmp_addr) > 0) {
				if (tmp_addr) {
					nm_ip4_config_add_nis_server (ip4_config, tmp_addr);
					nm_log_info (LOGD_DHCP4, "  nis '%s'", *s);
				}
			} else
				nm_log_warn (LOGD_DHCP4, "ignoring invalid NIS server '%s'", *s);
		}
		g_strfreev (nis);
	}

	str = g_hash_table_lookup (options, "vendor_encapsulated_options");
	nm_ip4_config_set_metered (ip4_config, str && strstr (str, "ANDROID_METERED"));

	return ip4_config;

error:
	g_object_unref (ip4_config);
	return NULL;
}

/********************************************/

static void
ip6_add_domain_search (gpointer data, gpointer user_data)
{
	nm_ip6_config_add_search (NM_IP6_CONFIG (user_data), (const char *) data);
}

NMIP6Config *
nm_dhcp_utils_ip6_config_from_options (int ifindex,
                                       const char *iface,
                                       GHashTable *options,
                                       guint32 priority,
                                       gboolean info_only)
{
	NMIP6Config *ip6_config = NULL;
	struct in6_addr tmp_addr;
	NMPlatformIP6Address address;
	char *str = NULL;
	GHashTableIter iter;
	gpointer key, value;

	g_return_val_if_fail (options != NULL, NULL);

	memset (&address, 0, sizeof (address));
	address.plen = 128;
	address.timestamp = nm_utils_get_monotonic_timestamp_s ();

	g_hash_table_iter_init (&iter, options);
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		nm_log_dbg (LOGD_DHCP6, "(%s): option '%s'=>'%s'",
		            iface, (const char *) key, (const char *) value);
	}

	ip6_config = nm_ip6_config_new (ifindex);

	str = g_hash_table_lookup (options, "max_life");
	if (str) {
		address.lifetime = strtoul (str, NULL, 10);
		nm_log_info (LOGD_DHCP6, "  valid_lft %u", address.lifetime);
	}

	str = g_hash_table_lookup (options, "preferred_life");
	if (str) {
		address.preferred = strtoul (str, NULL, 10);
		nm_log_info (LOGD_DHCP6, "  preferred_lft %u", address.preferred);
	}

	str = g_hash_table_lookup (options, "ip6_address");
	if (str) {
		if (!inet_pton (AF_INET6, str, &tmp_addr)) {
			nm_log_warn (LOGD_DHCP6, "(%s): DHCP returned invalid address '%s'",
			             iface, str);
			goto error;
		}

		address.address = tmp_addr;
		address.source = NM_IP_CONFIG_SOURCE_DHCP;
		nm_ip6_config_add_address (ip6_config, &address);
		nm_log_info (LOGD_DHCP6, "  address %s", str);
	} else if (info_only == FALSE) {
		/* No address in Managed mode is a hard error */
		goto error;
	}

	str = g_hash_table_lookup (options, "host_name");
	if (str)
		nm_log_info (LOGD_DHCP6, "  hostname '%s'", str);

	str = g_hash_table_lookup (options, "dhcp6_name_servers");
	if (str) {
		char **dns = g_strsplit (str, " ", 0);
		char **s;

		for (s = dns; *s; s++) {
			if (inet_pton (AF_INET6, *s, &tmp_addr) > 0) {
				if (!IN6_IS_ADDR_UNSPECIFIED (&tmp_addr)) {
					nm_ip6_config_add_nameserver (ip6_config, &tmp_addr);
					nm_log_info (LOGD_DHCP6, "  nameserver '%s'", *s);
				}
			} else
				nm_log_warn (LOGD_DHCP6, "ignoring invalid nameserver '%s'", *s);
		}
		g_strfreev (dns);
	}

	str = g_hash_table_lookup (options, "dhcp6_domain_search");
	if (str)
		process_domain_search (str, ip6_add_domain_search, ip6_config);

	return ip6_config;

error:
	g_object_unref (ip6_config);
	return NULL;
}

char *
nm_dhcp_utils_duid_to_string (const GByteArray *duid)
{
	guint32 i = 0;
	GString *s;

	g_return_val_if_fail (duid != NULL, NULL);

	s = g_string_sized_new (MIN (duid->len * 3, 50));
	while (i < duid->len) {
		if (s->len)
			g_string_append_c (s, ':');
		g_string_append_printf (s, "%02x", duid->data[i++]);
	}
	return g_string_free (s, FALSE);
}

/**
 * nm_dhcp_utils_client_id_string_to_bytes:
 * @client_id: the client ID string
 *
 * Accepts either a hex string ("aa:bb:cc") representing a binary client ID
 * (the first byte is assumed to be the 'type' field per RFC 2132 section 9.14),
 * or a string representing a non-hardware-address client ID, in which case
 * the 'type' field is set to 0.
 *
 * Returns: the binary client ID suitable for sending over the wire
 * to the DHCP server.
 */
GBytes *
nm_dhcp_utils_client_id_string_to_bytes (const char *client_id)
{
	GBytes *bytes = NULL;
	guint len;
	char *c;

	g_return_val_if_fail (client_id && client_id[0], NULL);

	/* Try as hex encoded */
	if (strchr (client_id, ':'))
		bytes = nm_utils_hexstr2bin (client_id);
	if (!bytes) {
		/* Fall back to string */
		len = strlen (client_id);
		c = g_malloc (len + 1);
		c[0] = 0;  /* type: non-hardware address per RFC 2132 section 9.14 */
		memcpy (c + 1, client_id, len);
		bytes = g_bytes_new_take (c, len + 1);
	}

	return bytes;
}

