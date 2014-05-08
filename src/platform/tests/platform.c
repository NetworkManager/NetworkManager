/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-platform.c - Handle runtime kernel networking configuration
 *
 * This program is free software; you can redistribute it and/or modify
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
 * Copyright (C) 2013 Red Hat, Inc.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netlink/route/addr.h>

#include "nm-platform.h"
#include "nm-linux-platform.h"
#include "nm-fake-platform.h"

#define error(...) fprintf (stderr, __VA_ARGS__)

typedef gboolean boolean_t;
typedef int decimal_t;
typedef const char *string_t;

#define print_boolean(value) printf ("%s\n", value ? "yes" : "no")
#define print_decimal(value) printf ("%d\n", value)
#define print_string(value) printf ("%s\n", value)

static gboolean
do_sysctl_set (char **argv)
{
	return nm_platform_sysctl_set (argv[0], argv[1]);
}

static gboolean
do_sysctl_get (char **argv)
{
	auto_g_free char *value = nm_platform_sysctl_get (argv[0]);

	printf ("%s\n", value);

	return !!value;
}

static int
parse_ifindex (const char *str)
{
	char *endptr;
	int ifindex = 0;

	ifindex = strtol (str, &endptr, 10);

	if (*endptr) {
		ifindex = nm_platform_link_get_ifindex (str);
	}

	return ifindex;
}

static gboolean
do_link_get_all (char **argv)
{
	GArray *links;
	NMPlatformLink *device;
	int i;

	links = nm_platform_link_get_all ();
	for (i = 0; i < links->len; i++) {
		device = &g_array_index (links, NMPlatformLink, i);

		printf ("%d: %s type %d\n", device->ifindex, device->name, device->type);
	}
	g_array_unref (links);

	return TRUE;
}

static gboolean
do_dummy_add (char **argv)
{
	return nm_platform_dummy_add (argv[0]);
}

static gboolean
do_bridge_add (char **argv)
{
	return nm_platform_bridge_add (argv[0], NULL, 0);
}

static gboolean
do_bond_add (char **argv)
{
	return nm_platform_bond_add (argv[0]);
}

static gboolean
do_team_add (char **argv)
{
	return nm_platform_team_add (argv[0]);
}

static gboolean
do_vlan_add (char **argv)
{
	const char *name = *argv++;
	int parent = parse_ifindex (*argv++);
	int vlanid = strtol (*argv++, NULL, 10);
	guint32 vlan_flags = strtol (*argv++, NULL, 10);

	return nm_platform_vlan_add (name, parent, vlanid, vlan_flags);
}

static gboolean
do_link_exists (char **argv)
{
	gboolean value = nm_platform_link_exists (argv[0]);

	print_boolean (value);

	return TRUE;
}

#define LINK_CMD(cmdname) \
	static gboolean \
	do_link_##cmdname (char **argv) \
	{ \
		int ifindex = parse_ifindex (argv[0]); \
		return ifindex ? nm_platform_link_##cmdname (ifindex) : FALSE; \
	}

#define LINK_CMD_GET_FULL(cmdname, type, cond) \
	static gboolean \
	do_link_##cmdname (char **argv) \
	{ \
		int ifindex = parse_ifindex (argv[0]); \
		if (ifindex) { \
			type##_t value = nm_platform_link_##cmdname (ifindex); \
			if (cond) { \
				print_##type (value); \
				return TRUE; \
			} \
		} \
		return FALSE; \
	}
#define LINK_CMD_GET(cmdname, type) LINK_CMD_GET_FULL (cmdname, type, TRUE);

LINK_CMD (delete)

/* do_link_delete_by_ifname:
 *
 * We don't need this as we allow ifname instead of ifindex anyway.
 */

static gboolean
do_link_get_ifindex (char **argv)
{
	int ifindex = nm_platform_link_get_ifindex (argv[0]);

	if (ifindex)
		printf ("%d\n", ifindex);

	return !!ifindex;
}

LINK_CMD_GET_FULL (get_name, string, value)
LINK_CMD_GET_FULL (get_type, decimal, value > 0)
LINK_CMD_GET (is_software, boolean)
LINK_CMD_GET (supports_slaves, boolean)

LINK_CMD (set_up)
LINK_CMD (set_down)
LINK_CMD (set_arp)
LINK_CMD (set_noarp)
LINK_CMD_GET (is_up, boolean)
LINK_CMD_GET (is_connected, boolean)
LINK_CMD_GET (uses_arp, boolean)

static gboolean
do_link_set_address (char **argv)
{
	int ifindex = parse_ifindex (*argv++);
	char *hex = *argv++;
	int hexlen = strlen (hex);
	char address[hexlen/2];
	char *endptr;
	int i;

	g_assert (!(hexlen % 2));

	for (i = 0; i < sizeof (address); i++) {
		char digit[3];

		digit[0] = hex[2*i];
		digit[1] = hex[2*i+1];
		digit[2] = '\0';

		address[i] = strtoul (digit, &endptr, 16);
		g_assert (!*endptr);
	}

	return nm_platform_link_set_address (ifindex, address, sizeof (address));
}

static gboolean
do_link_get_address (char **argv)
{
	int ifindex = parse_ifindex (*argv++);
	const char *address;
	size_t length;
	int i;

	address = nm_platform_link_get_address (ifindex, &length);

	if (!address || length <= 0)
		return FALSE;

	for (i = 0; i < length; i++)
		printf ("%02x", address[i]);
	printf ("\n");

	return TRUE;
}

static gboolean
do_link_set_mtu (char **argv)
{
	int ifindex = parse_ifindex (*argv++);
	int mtu = strtoul (*argv++, NULL, 10);

	return nm_platform_link_set_mtu (ifindex, mtu);
}

LINK_CMD_GET (get_mtu, decimal);
LINK_CMD_GET (supports_carrier_detect, boolean)
LINK_CMD_GET (supports_vlans, boolean)

static gboolean
do_link_enslave (char **argv)
{
	int master = parse_ifindex (*argv++);
	int slave = parse_ifindex (*argv++);

	return nm_platform_link_enslave (master, slave);
}

static gboolean
do_link_release (char **argv)
{
	int master = parse_ifindex (*argv++);
	int slave = parse_ifindex (*argv++);

	return nm_platform_link_release (master, slave);
}

LINK_CMD_GET (get_master, decimal)

static gboolean
do_master_set_option (char **argv)
{
	int ifindex = parse_ifindex (*argv++);
	const char *option = *argv++;
	const char *value = *argv++;

	return nm_platform_master_set_option (ifindex, option, value);
}

static gboolean
do_master_get_option (char **argv)
{
	int ifindex = parse_ifindex (*argv++);
	const char *option = *argv++;
	auto_g_free char *value = nm_platform_master_get_option (ifindex, option);

	printf ("%s\n", value);

	return !!value;
}

static gboolean
do_slave_set_option (char **argv)
{
	int ifindex = parse_ifindex (*argv++);
	const char *option = *argv++;
	const char *value = *argv++;

	return nm_platform_slave_set_option (ifindex, option, value);
}

static gboolean
do_slave_get_option (char **argv)
{
	int ifindex = parse_ifindex (*argv++);
	const char *option = *argv++;
	auto_g_free char *value = nm_platform_slave_get_option (ifindex, option);

	printf ("%s\n", value);

	return !!value;
}

static gboolean
do_vlan_get_info (char **argv)
{
	int ifindex = parse_ifindex (*argv++);
	int parent;
	int vlanid;

	if (!nm_platform_vlan_get_info (ifindex, &parent, &vlanid))
		return FALSE;

	printf ("%d %d\n", parent, vlanid);

	return TRUE;
}

static gboolean
do_vlan_set_ingress_map (char **argv)
{
	int ifindex = parse_ifindex (*argv++);
	int from = strtol (*argv++, NULL, 10);
	int to = strtol (*argv++, NULL, 10);

	return nm_platform_vlan_set_ingress_map (ifindex, from, to);
}

static gboolean
do_vlan_set_egress_map (char **argv)
{
	int ifindex = parse_ifindex (*argv++);
	int from = strtol (*argv++, NULL, 10);
	int to = strtol (*argv++, NULL, 10);

	return nm_platform_vlan_set_egress_map (ifindex, from, to);
}

static gboolean
do_veth_get_properties (char **argv)
{
	int ifindex = parse_ifindex (*argv++);
	NMPlatformVethProperties props;

	if (!nm_platform_veth_get_properties (ifindex, &props))
		return FALSE;

	printf ("peer: %d\n", props.peer);

	return TRUE;
}

static gboolean
do_tun_get_properties (char **argv)
{
	int ifindex = parse_ifindex (*argv++);
	NMPlatformTunProperties props;

	if (!nm_platform_tun_get_properties (ifindex, &props))
		return FALSE;

	printf ("mode: %s\n", props.mode);
	if (props.owner == -1)
		printf ("owner: none\n");
	else
		printf ("owner: %lu\n", (gulong) props.owner);
	if (props.group == -1)
		printf ("group: none\n");
	else
		printf ("group: %lu\n", (gulong) props.group);
	printf ("no-pi: ");
	print_boolean (props.no_pi);
	printf ("vnet-hdr: ");
	print_boolean (props.vnet_hdr);
	printf ("multi-queue: ");
	print_boolean (props.multi_queue);

	return TRUE;
}

static gboolean
do_macvlan_get_properties (char **argv)
{
	int ifindex = parse_ifindex (*argv++);
	NMPlatformMacvlanProperties props;

	if (!nm_platform_macvlan_get_properties (ifindex, &props))
		return FALSE;

	printf ("parent: %d\n", props.parent_ifindex);
	printf ("mode: %s\n", props.mode);
	printf ("no-promisc: ");
	print_boolean (props.no_promisc);
	return TRUE;
}

static gboolean
do_vxlan_get_properties (char **argv)
{
	int ifindex = parse_ifindex (*argv++);
	NMPlatformVxlanProperties props;
	char addrstr[INET6_ADDRSTRLEN];

	if (!nm_platform_vxlan_get_properties (ifindex, &props))
		return FALSE;

	printf ("parent-ifindex: %u\n", props.parent_ifindex);
	printf ("id: %u\n", props.id);
	if (props.group)
		inet_ntop (AF_INET, &props.group, addrstr, sizeof (addrstr));
	else if (props.group6.s6_addr[0])
		inet_ntop (AF_INET6, &props.group6, addrstr, sizeof (addrstr));
	else
		strcpy (addrstr, "-");
	printf ("group: %s\n", addrstr);
	if (props.local)
		inet_ntop (AF_INET, &props.local, addrstr, sizeof (addrstr));
	else if (props.local6.s6_addr[0])
		inet_ntop (AF_INET6, &props.local6, addrstr, sizeof (addrstr));
	else
		strcpy (addrstr, "-");
	printf ("local: %s\n", addrstr);
	printf ("tos: %u\n", props.tos);
	printf ("ttl: %u\n", props.ttl);
	printf ("learning: ");
	print_boolean (props.learning);
	printf ("ageing: %u\n", props.ageing);
	printf ("limit: %u\n", props.limit);
	printf ("dst-port: %u\n", props.dst_port);
	printf ("src-port-min: %u\n", props.src_port_min);
	printf ("src-port-max: %u\n", props.src_port_max);
	printf ("proxy: ");
	print_boolean (props.proxy);
	printf ("rsc: ");
	print_boolean (props.rsc);
	printf ("l2miss: ");
	print_boolean (props.l2miss);
	printf ("l3miss: ");
	print_boolean (props.l3miss);

	return TRUE;
}

static gboolean
do_gre_get_properties (char **argv)
{
	int ifindex = parse_ifindex (*argv++);
	NMPlatformGreProperties props;
	char addrstr[INET_ADDRSTRLEN];

	if (!nm_platform_gre_get_properties (ifindex, &props))
		return FALSE;

	printf ("parent-ifindex: %u\n", props.parent_ifindex);
	printf ("input-flags: %u\n", props.input_flags);
	printf ("output-flags: %u\n", props.input_flags);
	printf ("input-key: %u\n", props.input_key);
	printf ("output-key: %u\n", props.output_key);
	if (props.local)
		inet_ntop (AF_INET, &props.local, addrstr, sizeof (addrstr));
	else
		strcpy (addrstr, "-");
	printf ("local: %s\n", addrstr);
	if (props.remote)
		inet_ntop (AF_INET, &props.remote, addrstr, sizeof (addrstr));
	else
		strcpy (addrstr, "-");
	printf ("remote: %s\n", addrstr);
	printf ("ttl: %u\n", props.ttl);
	printf ("tos: %u\n", props.tos);
	printf ("path-mtu-discovery: ");
	print_boolean (props.path_mtu_discovery);

	return TRUE;
}

static gboolean
do_ip4_address_get_all (char **argv)
{
	int ifindex = parse_ifindex (argv[0]);
	GArray *addresses;
	NMPlatformIP4Address *address;
	char addrstr[INET_ADDRSTRLEN];
	int i;

	if (ifindex) {
		addresses = nm_platform_ip4_address_get_all (ifindex);
		for (i = 0; i < addresses->len; i++) {
			address = &g_array_index (addresses, NMPlatformIP4Address, i);
			inet_ntop (AF_INET, &address->address, addrstr, sizeof (addrstr));
			printf ("%s/%d\n", addrstr, address->plen);
		}
		g_array_unref (addresses);
	}

	return !!ifindex;
}

static gboolean
do_ip6_address_get_all (char **argv)
{
	int ifindex = parse_ifindex (argv[0]);
	GArray *addresses;
	NMPlatformIP6Address *address;
	char addrstr[INET6_ADDRSTRLEN];
	int i;

	if (ifindex) {
		addresses = nm_platform_ip6_address_get_all (ifindex);
		for (i = 0; i < addresses->len; i++) {
			address = &g_array_index (addresses, NMPlatformIP6Address, i);
			inet_ntop (AF_INET6, &address->address, addrstr, sizeof (addrstr));
			printf ("%s/%d\n", addrstr, address->plen);
		}
		g_array_unref (addresses);
	}

	return !!ifindex;
}

static gboolean
parse_ip_address (int family, char *str, gpointer address, int *plen)
{
	char *endptr;

	if (plen) {
		char *ptr = strchr (str, '/');
		if (ptr) {
			*ptr++ = '\0';
			*plen = strtol (ptr, &endptr, 10);
			if (*endptr)
				ptr = NULL;
		}
		if (!ptr) {
			error ("Bad format of IP address, expected address/plen.\n");
			return FALSE;
		}
	}

	if (inet_pton (family, str, address))
		return TRUE;

	error ("Bad format of IP address, expected address%s.\n", plen ? "/plen" : "");
	return FALSE;
}

typedef in_addr_t ip4_t;
typedef struct in6_addr ip6_t;

#define parse_ip4_address(s, a, p) parse_ip_address (AF_INET, s, a, p)
#define parse_ip6_address(s, a, p) parse_ip_address (AF_INET6, s, a, p)

static gboolean
do_ip4_address_add (char **argv)
{
	int ifindex = parse_ifindex (*argv++);
	ip4_t address;
	int plen;

	if (ifindex && parse_ip4_address (*argv++, &address, &plen)) {
		guint32 lifetime = strtol (*argv++, NULL, 10);
		guint32 preferred = strtol (*argv++, NULL, 10);

		gboolean value = nm_platform_ip4_address_add (ifindex, address, 0, plen, lifetime, preferred, NULL);
		return value;
	} else
		return FALSE;
}

static gboolean
do_ip6_address_add (char **argv)
{
	int ifindex = parse_ifindex (*argv++);
	ip6_t address;
	int plen;

	if (ifindex && parse_ip6_address (*argv++, &address, &plen)) {
		guint32 lifetime = strtol (*argv++, NULL, 10);
		guint32 preferred = strtol (*argv++, NULL, 10);
		guint flags = (*argv) ? rtnl_addr_str2flags (*argv++) : 0;

		gboolean value = nm_platform_ip6_address_add (ifindex, address, in6addr_any, plen, lifetime, preferred, flags);
		return value;
	} else
		return FALSE;
}

#define ADDR_CMD_FULL(v, cmdname, print) \
	static gboolean \
	do_##v##_address_##cmdname (char **argv) \
	{ \
		int ifindex = parse_ifindex (*argv++); \
		v##_t address; \
		int plen; \
		if (ifindex && parse_##v##_address (*argv++, &address, &plen)) { \
			gboolean value = nm_platform_##v##_address_##cmdname (ifindex, address, plen); \
			if (print) { \
				print_boolean (value); \
				return TRUE; \
			} else \
				return value; \
		} else \
			return FALSE; \
	}
#define ADDR_CMD(cmdname) ADDR_CMD_FULL (ip4, cmdname, FALSE) ADDR_CMD_FULL (ip6, cmdname, FALSE)
#define ADDR_CMD_PRINT(cmdname) ADDR_CMD_FULL (ip4, cmdname, TRUE) ADDR_CMD_FULL (ip6, cmdname, TRUE)

ADDR_CMD (delete)
ADDR_CMD_PRINT (exists)

static gboolean
do_ip4_route_get_all (char **argv)
{
	int ifindex = parse_ifindex (argv[0]);
	GArray *routes;
	NMPlatformIP4Route *route;
	char networkstr[INET_ADDRSTRLEN], gatewaystr[INET_ADDRSTRLEN];
	int i;

	if (ifindex) {
		routes = nm_platform_ip4_route_get_all (ifindex, TRUE);
		for (i = 0; i < routes->len; i++) {
			route = &g_array_index (routes, NMPlatformIP4Route, i);
			inet_ntop (AF_INET, &route->network, networkstr, sizeof (networkstr));
			inet_ntop (AF_INET, &route->gateway, gatewaystr, sizeof (gatewaystr));
			printf ("%s/%d via %s metric %d\n",
					networkstr, route->plen, gatewaystr, route->metric);
		}
		g_array_unref (routes);
	}

	return !!ifindex;
}

static gboolean
do_ip6_route_get_all (char **argv)
{
	int ifindex = parse_ifindex (argv[0]);
	GArray *routes;
	NMPlatformIP6Route *route;
	char networkstr[INET6_ADDRSTRLEN], gatewaystr[INET6_ADDRSTRLEN];
	int i;

	if (ifindex) {
		routes = nm_platform_ip6_route_get_all (ifindex, TRUE);
		for (i = 0; i < routes->len; i++) {
			route = &g_array_index (routes, NMPlatformIP6Route, i);
			inet_ntop (AF_INET6, &route->network, networkstr, sizeof (networkstr));
			inet_ntop (AF_INET6, &route->gateway, gatewaystr, sizeof (gatewaystr));
			printf ("%s/%d via %s metric %d\n",
					networkstr, route->plen, gatewaystr, route->metric);
		}
		g_array_unref (routes);
	}

	return !!ifindex;
}

static gboolean
do_ip4_route_add (char **argv)
{
	int ifindex = parse_ifindex (*argv++);
	in_addr_t network, gateway;
	int plen, metric, mss;

	parse_ip4_address (*argv++, &network, &plen);
	parse_ip4_address (*argv++, &gateway, NULL);
	metric = strtol (*argv++, NULL, 10);
	mss = strtol (*argv++, NULL, 10);

	return nm_platform_ip4_route_add (ifindex, NM_PLATFORM_SOURCE_USER,
	                                  network, plen, gateway,
	                                  metric, mss);
}

static gboolean
do_ip6_route_add (char **argv)
{
	int ifindex = parse_ifindex (*argv++);
	struct in6_addr network, gateway;
	int plen, metric, mss;

	parse_ip6_address (*argv++, &network, &plen);
	parse_ip6_address (*argv++, &gateway, NULL);
	metric = strtol (*argv++, NULL, 10);
	mss = strtol (*argv++, NULL, 10);
	return nm_platform_ip6_route_add (ifindex, NM_PLATFORM_SOURCE_USER,
	                                  network, plen, gateway,
	                                  metric, mss);
}

static gboolean
do_ip4_route_delete (char **argv)
{
	int ifindex = parse_ifindex (*argv++);
	in_addr_t network;
	int plen, metric;

	parse_ip4_address (*argv++, &network, &plen);
	metric = strtol (*argv++, NULL, 10);

	return nm_platform_ip4_route_delete (ifindex, network, plen, metric);
}

static gboolean
do_ip6_route_delete (char **argv)
{
	int ifindex = parse_ifindex (*argv++);
	struct in6_addr network;
	int plen, metric;

	parse_ip6_address (*argv++, &network, &plen);
	metric = strtol (*argv++, NULL, 10);

	return nm_platform_ip6_route_delete (ifindex, network, plen, metric);
}

static gboolean
do_ip4_route_exists (char **argv)
{
	int ifindex = parse_ifindex (*argv++);
	in_addr_t network;
	int plen, metric;

	parse_ip4_address (*argv++, &network, &plen);
	metric = strtol (*argv++, NULL, 10);

	print_boolean (nm_platform_ip4_route_exists (ifindex, network, plen, metric));
	return TRUE;
}

static gboolean
do_ip6_route_exists (char **argv)
{
	int ifindex = parse_ifindex (*argv++);
	struct in6_addr network;
	int plen, metric;

	parse_ip6_address (*argv++, &network, &plen);
	metric = strtol (*argv++, NULL, 10);

	print_boolean (nm_platform_ip6_route_exists (ifindex, network, plen, metric));
	return TRUE;
}

typedef struct {
	const char *name;
	const char *help;
	int (*handler) (char **argv);
	int argc;
	const char *arghelp;
} command_t;

static const command_t commands[] = {
	{ "sysctl-set", "get /proc/sys or /sys value", do_sysctl_set, 2, "<path> <value>" },
	{ "sysctl-get", "get /proc/sys or /sys value", do_sysctl_get, 1, "<value>" },
	{ "link-get-all", "print all links", do_link_get_all, 0, "" },
	{ "dummy-add", "add dummy interface", do_dummy_add, 1, "<ifname>" },
	{ "bridge-add", "add bridge interface", do_bridge_add, 1, "<ifname>" },
	{ "bond-add", "add bond interface", do_bond_add, 1, "<ifname>" },
	{ "team-add", "add team interface", do_team_add, 1, "<ifname>" },
	{ "vlan-add", "add vlan interface", do_vlan_add, 4, "<ifname> <parent> <vlanid> <vlanflags>" },
	{ "link-exists", "check ifname for existance", do_link_exists, 1, "<ifname>" },
	{ "link-delete", "delete interface", do_link_delete, 1, "<ifname/ifindex>" },
	{ "link-get-ifindex>", "get interface index", do_link_get_ifindex, 1, "<ifname>" },
	{ "link-get-name", "get interface name", do_link_get_name, 1, "<ifindex>" },
	{ "link-get-type", "get interface type", do_link_get_type, 1, "<ifname/ifindex>" },
	{ "link-is-software", "check if interface is a software one", do_link_is_software, 1, "<ifname/ifindex>" },
	{ "link-supports-slaves", "check if interface supports slaves", do_link_supports_slaves, 1, "<ifname/ifindex>" },
	{ "link-set-up", "set interface up", do_link_set_up, 1, "<ifname/ifindex>" },
	{ "link-set-down", "set interface down", do_link_set_down, 1, "<ifname/ifindex>" },
	{ "link-set-arp", "activate interface arp", do_link_set_arp, 1, "<ifname/ifindex>" },
	{ "link-set-noarp", "deactivate interface arp", do_link_set_noarp, 1, "<ifname/ifindex>" },
	{ "link-is-up", "check if interface is up", do_link_is_up, 1, "<ifname/ifindex>" },
	{ "link-is-connected", "check interface carrier", do_link_is_connected, 1, "<ifname/ifindex>" },
	{ "link-uses-arp", "check whether interface uses arp", do_link_uses_arp, 1, "<ifname/ifindex>" },
	{ "link-get-address", "print link address", do_link_get_address, 1, "<ifname/ifindex>" },
	{ "link-set-address", "set link address", do_link_set_address, 2, "<ifname/ifindex> <hex>" },
	{ "link-get-mtu", "print link mtu", do_link_get_mtu, 1, "<ifname/ifindex>" },
	{ "link-set-mtu", "set link mtu", do_link_set_mtu, 2, "<ifname/ifindex> <mtu>" },
	{ "link-supports-carrier-detect", "check whether interface supports carrier detect",
		do_link_supports_carrier_detect, 1, "<ifname/ifindex>" },
	{ "link-supports-vlans", "check whether interface supports VLANs",
		do_link_supports_vlans, 1, "<ifname/ifindex>" },
	{ "link-enslave", "enslave slave interface with master", do_link_enslave, 2, "<master> <slave>" },
	{ "link-release", "release save interface from master", do_link_release, 2, "<master> <slave>" },
	{ "link-get-master", "print master interface of a slave", do_link_get_master, 1, "<ifname/ifindex>" },
	{ "link-master-set-option", "set master option", do_master_set_option, 3,
		"<ifname/ifindex> <option> <value>" },
	{ "link-master-get-option", "get master option", do_master_get_option, 2,
		"<ifname/ifindex> <option>" },
	{ "link-slave-set-option", "set slave option", do_slave_set_option, 3,
		"<ifname/ifindex> <option>" },
	{ "link-slave-get-option", "get slave option", do_slave_get_option, 2,
		"<ifname/ifindex> <option>" },
	{ "vlan-get-info", "get vlan info", do_vlan_get_info, 1, "<ifname/ifindex>" },
	{ "vlan-set-ingress-map", "set vlan ingress map", do_vlan_set_ingress_map, 3,
		"<ifname/ifindex> <from> <to>" },
	{ "vlan-set-egress-map", "set vlan egress map", do_vlan_set_egress_map, 3,
		"<ifname/ifindex> <from> <to>" },
	{ "veth-get-properties", "get veth properties", do_veth_get_properties, 1,
	  "<ifname/ifindex>" },
	{ "tun-get-properties", "get tun/tap properties", do_tun_get_properties, 1,
	  "<ifname/ifindex>" },
	{ "macvlan-get-properties", "get macvlan properties", do_macvlan_get_properties, 1,
	  "<ifname/ifindex>" },
	{ "vxlan-get-properties", "get vxlan properties", do_vxlan_get_properties, 1,
	  "<ifname/ifindex>" },
	{ "gre-get-properties", "get gre properties", do_gre_get_properties, 1,
	  "<ifname/ifindex>" },
	{ "ip4-address-get-all", "print all IPv4 addresses", do_ip4_address_get_all, 1, "<ifname/ifindex>" },
	{ "ip6-address-get-all", "print all IPv6 addresses", do_ip6_address_get_all, 1, "<ifname/ifindex>" },
	{ "ip4-address-add", "add IPv4 address", do_ip4_address_add, 4, "<ifname/ifindex> <address>/<plen> <lifetime> <>" },
	{ "ip6-address-add", "add IPv6 address", do_ip6_address_add, 4, "<ifname/ifindex> <address>/<plen> <lifetime> [<flags>] <>" },
	{ "ip4-address-delete", "delete IPv4 address", do_ip4_address_delete, 2,
		"<ifname/ifindex> <address>/<plen>" },
	{ "ip6-address-delete", "delete IPv6 address", do_ip6_address_delete, 2,
		"<ifname/ifindex> <address>/<plen>" },
	{ "ip4-address-exists", "check for existence of IPv4 address", do_ip4_address_exists, 2,
		"<ifname/ifindex> <address>/<plen>" },
	{ "ip6-address-exists", "check for existence of IPv6 address", do_ip6_address_exists, 2,
		"<ifname/ifindex> <address>/<plen>" },
	{ "ip4-route-get-all", "print all IPv4 routes", do_ip4_route_get_all, 1, "<ifname/ifindex>" },
	{ "ip6-route-get-all", "print all IPv6 routes", do_ip6_route_get_all, 1, "<ifname/ifindex>" },
	{ "ip4-route-add", "add IPv4 route", do_ip4_route_add, 5,
		"<ifname/ifindex> <network>/<plen> <gateway> <metric> <mss>" },
	{ "ip6-route-add", "add IPv6 route", do_ip6_route_add, 5,
		"<ifname/ifindex> <network>/<plen> <gateway> <metric> <mss>" },
	{ "ip4-route-delete", "delete IPv4 route", do_ip4_route_delete, 3,
		"<ifname/ifindex> <network>/<plen> <metric>" },
	{ "ip6-route-delete", "delete IPv6 route", do_ip6_route_delete, 3,
		"<ifname/ifindex> <network>/<plen> <metric>" },
	{ "ip4-route-exists", "check for existence of IPv4 route", do_ip4_route_exists, 3,
		"<ifname/ifindex> <network>/<plen> <metric>" },
	{ "ip6-route-exists", "check for existence of IPv6 route", do_ip6_route_exists, 3,
		"<ifname/ifindex> <network>/<plen> <metric>" },
	{ NULL, NULL, NULL, 0, NULL },
};

int
main (int argc, char **argv)
{
	const char *arg0 = *argv++;
	const command_t *command = NULL;
	gboolean status = TRUE;
	int error;

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

	if (*argv && !g_strcmp0 (argv[1], "--fake")) {
		nm_fake_platform_setup ();
	} else
		nm_linux_platform_setup ();

	if (*argv)
		for (command = commands; command->name; command++)
			if (g_str_has_prefix (command->name, *argv))
				break;

	if (command && command->name) {
		argv++;
		if (g_strv_length (argv) == command->argc)
			status = command->handler (argv);
		else {
			error ("Wrong number of arguments to '%s' (expected %d).\n\nUsage: %s %s %s\n-- %s\n",
					command->name, command->argc,
					arg0, command->name, command->arghelp, command->help);
			return EXIT_FAILURE;
		}
	} else {
		error ("Usage: %s COMMAND\n\n", arg0);
		error ("COMMAND\n");
		for (command = commands; command->name; command++)
			error ("  %s %s\n    -- %s\n", command->name, command->arghelp, command->help);
		error ("\n");
	}

	error = nm_platform_get_error ();
	if (error) {
		const char *msg = nm_platform_get_error_msg ();

		error ("nm-platform: %s\n", msg);
	}

	return !!error;
}
