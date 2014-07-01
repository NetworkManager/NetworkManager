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
 * Copyright (C) 2008 - 2014 Red Hat, Inc.
 *
 */

#include <glib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include <nm-utils.h>

#include "nm-dhcp-utils.h"
#include "nm-logging.h"

#include "nm-test-utils.h"

typedef struct {
	const char *name;
	const char *value;
} Option;

static GHashTable *
fill_table (Option *test_options, GHashTable *table)
{
	Option *opt;

	if (!table)
		table = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, NULL);
	for (opt = test_options; opt->name; opt++)
		g_hash_table_insert (table, (gpointer) opt->name, (gpointer) opt->value);
	return table;
}

static Option generic_options[] = {
	{ "subnet_mask",            "255.255.255.0" },
	{ "ip_address",             "192.168.1.106" },
	{ "network_number",         "192.168.1.0" },
	{ "expiry",                 "1232324877" },
	{ "dhcp_lease_time",        "3600" },
	{ "dhcp_server_identifier", "192.168.1.1" },
	{ "routers",                "192.168.1.1" },
	{ "domain_name_servers",    "216.254.95.2 216.231.41.2" },
	{ "dhcp_message_type",      "5" },
	{ "broadcast_address",      "192.168.1.255" },
	{ "domain_search",          "foobar.com blah.foobar.com" },
	{ "host_name",              "nmreallywhipsthe" },
	{ "domain_name",            "lamasass.com" },
	{ "interface_mtu",          "987" },
	{ "static_routes",          "10.1.1.5 10.1.1.1 100.99.88.56 10.1.1.1" },
	{ NULL, NULL }
};

static void
test_generic_options (void)
{
	GHashTable *options;
	NMIP4Config *ip4_config;
	const NMPlatformIP4Address *address;
	const NMPlatformIP4Route *route;
	guint32 tmp;
	const char *expected_addr = "192.168.1.106";
	const char *expected_gw = "192.168.1.1";
	const char *expected_dns1 = "216.254.95.2";
	const char *expected_dns2 = "216.231.41.2";
	const char *expected_search1 = "foobar.com";
	const char *expected_search2 = "blah.foobar.com";
	const char *expected_route1_dest = "10.1.1.5";
	const char *expected_route1_gw = "10.1.1.1";
	const char *expected_route2_dest = "100.99.88.56";
	const char *expected_route2_gw = "10.1.1.1";

	options = fill_table (generic_options, NULL);
	ip4_config = nm_dhcp_utils_ip4_config_from_options ("eth0", options, 0);
	ASSERT (ip4_config != NULL,
	        "dhcp-generic", "failed to parse DHCP4 options");

	/* IP4 address */
	ASSERT (nm_ip4_config_get_num_addresses (ip4_config) == 1,
	        "dhcp-generic", "unexpected number of IP addresses");
	address = nm_ip4_config_get_address (ip4_config, 0);

	ASSERT (inet_pton (AF_INET, expected_addr, &tmp) > 0,
	        "dhcp-generic", "couldn't convert expected IP address");
	ASSERT (address->address == tmp,
	        "dhcp-generic", "unexpected IP address");
	ASSERT (address->peer_address == 0,
	        "dhcp-generic", "unexpected PTP address");

	ASSERT (address->plen == 24,
	        "dhcp-generic", "unexpected IP address prefix length");

	/* Gateway */
	ASSERT (inet_pton (AF_INET, expected_gw, &tmp) > 0,
	        "dhcp-generic", "couldn't convert expected IP gateway");
	ASSERT (nm_ip4_config_get_gateway (ip4_config) == tmp,
	        "dhcp-generic", "unexpected IP gateway");

	ASSERT (nm_ip4_config_get_num_wins (ip4_config) == 0,
	        "dhcp-generic", "unexpected number of WINS servers");

	ASSERT (nm_ip4_config_get_mtu (ip4_config) == 987,
	        "dhcp-generic", "unexpected MTU");

	/* Domain searches */
	ASSERT (nm_ip4_config_get_num_searches (ip4_config) == 2,
	        "dhcp-generic", "unexpected number of domain searches");
	ASSERT (strcmp (nm_ip4_config_get_search (ip4_config, 0), expected_search1) == 0,
	        "dhcp-generic", "unexpected domain search #1");
	ASSERT (strcmp (nm_ip4_config_get_search (ip4_config, 1), expected_search2) == 0,
	        "dhcp-generic", "unexpected domain search #2");

	/* DNS servers */
	ASSERT (nm_ip4_config_get_num_nameservers (ip4_config) == 2,
	        "dhcp-generic", "unexpected number of domain name servers");
	ASSERT (inet_pton (AF_INET, expected_dns1, &tmp) > 0,
	        "dhcp-generic", "couldn't convert expected DNS server address #1");
	ASSERT (nm_ip4_config_get_nameserver (ip4_config, 0) == tmp,
	        "dhcp-generic", "unexpected domain name server #1");
	ASSERT (inet_pton (AF_INET, expected_dns2, &tmp) > 0,
	        "dhcp-generic", "couldn't convert expected DNS server address #2");
	ASSERT (nm_ip4_config_get_nameserver (ip4_config, 1) == tmp,
	        "dhcp-generic", "unexpected domain name server #2");

	/* Routes */
	ASSERT (nm_ip4_config_get_num_routes (ip4_config) == 2,
	        "dhcp-generic", "unexpected number of routes");

	/* Route #1 */
	route = nm_ip4_config_get_route (ip4_config, 0);
	ASSERT (inet_pton (AF_INET, expected_route1_dest, &tmp) > 0,
	        "dhcp-generic", "couldn't convert expected route destination #1");
	ASSERT (route->network == tmp,
	        "dhcp-generic", "unexpected route #1 destination");

	ASSERT (inet_pton (AF_INET, expected_route1_gw, &tmp) > 0,
	        "dhcp-generic", "couldn't convert expected route next hop #1");
	ASSERT (route->gateway == tmp,
	        "dhcp-generic", "unexpected route #1 next hop");

	ASSERT (route->plen == 32,
	        "dhcp-generic", "unexpected route #1 prefix");
	ASSERT (route->metric == 0,
	        "dhcp-generic", "unexpected route #1 metric");

	/* Route #2 */
	route = nm_ip4_config_get_route (ip4_config, 1);
	ASSERT (inet_pton (AF_INET, expected_route2_dest, &tmp) > 0,
	        "dhcp-generic", "couldn't convert expected route destination #2");
	ASSERT (route->network == tmp,
	        "dhcp-generic", "unexpected route #2 destination");

	ASSERT (inet_pton (AF_INET, expected_route2_gw, &tmp) > 0,
	        "dhcp-generic", "couldn't convert expected route next hop #2");
	ASSERT (route->gateway == tmp,
	        "dhcp-generic", "unexpected route #2 next hop");

	ASSERT (route->plen == 32,
	        "dhcp-generic", "unexpected route #2 prefix");
	ASSERT (route->metric == 0,
	        "dhcp-generic", "unexpected route #2 metric");

	g_hash_table_destroy (options);
}

static Option wins_options[] = {
	{ "netbios_name_servers", "63.12.199.5 150.4.88.120" },
	{ NULL, NULL }
};

static void
test_wins_options (void)
{
	GHashTable *options;
	NMIP4Config *ip4_config;
	const NMPlatformIP4Address *address;
	guint32 tmp;
	const char *expected_wins1 = "63.12.199.5";
	const char *expected_wins2 = "150.4.88.120";

	options = fill_table (generic_options, NULL);
	options = fill_table (wins_options, options);
	ip4_config = nm_dhcp_utils_ip4_config_from_options ("eth0", options, 0);
	ASSERT (ip4_config != NULL,
	        "dhcp-wins", "failed to parse DHCP4 options");

	/* IP4 address */
	ASSERT (nm_ip4_config_get_num_addresses (ip4_config) == 1,
	        "dhcp-wins", "unexpected number of IP addresses");
	address = nm_ip4_config_get_address (ip4_config, 0);
	ASSERT (address != NULL, "dhcp-wins", "unexpectedly did not get address #0");

	ASSERT (nm_ip4_config_get_num_wins (ip4_config) == 2,
	        "dhcp-wins", "unexpected number of WINS servers");
	ASSERT (inet_pton (AF_INET, expected_wins1, &tmp) > 0,
	        "dhcp-wins", "couldn't convert expected WINS server address #1");
	ASSERT (nm_ip4_config_get_wins (ip4_config, 0) == tmp,
	        "dhcp-wins", "unexpected WINS server #1");
	ASSERT (inet_pton (AF_INET, expected_wins2, &tmp) > 0,
	        "dhcp-wins", "couldn't convert expected WINS server address #1");
	ASSERT (nm_ip4_config_get_wins (ip4_config, 1) == tmp,
	        "dhcp-wins", "unexpected WINS server #1");

	g_hash_table_destroy (options);
}

static void
ip4_test_route (const char *test,
                NMIP4Config *ip4_config,
                guint route_num,
                const char *expected_dest,
                const char *expected_gw,
                guint expected_prefix)
{
	const NMPlatformIP4Route *route;
	guint32 tmp;

	route = nm_ip4_config_get_route (ip4_config, route_num);
	ASSERT (inet_pton (AF_INET, expected_dest, &tmp) > 0,
	        test, "couldn't convert expected route destination #1");
	ASSERT (route->network == tmp,
	        test, "unexpected route %d destination", route_num + 1);

	ASSERT (inet_pton (AF_INET, expected_gw, &tmp) > 0,
	        test, "couldn't convert expected route next hop %d",
	        route_num + 1);
	ASSERT (route->gateway == tmp,
	        test, "unexpected route %d next hop", route_num + 1);

	ASSERT (route->plen == expected_prefix,
	        test, "unexpected route %d prefix", route_num + 1);
	ASSERT (route->metric == 0,
	        test, "unexpected route %d metric", route_num + 1);
}

static void
ip4_test_gateway (const char *test,
                  NMIP4Config *ip4_config,
                  const char *expected_gw)
{
	guint32 tmp;

	ASSERT (nm_ip4_config_get_num_addresses (ip4_config) == 1,
	        test, "unexpected number of IP addresses");
	ASSERT (inet_pton (AF_INET, expected_gw, &tmp) > 0,
	        test, "couldn't convert expected IP gateway");
	ASSERT (nm_ip4_config_get_gateway (ip4_config) == tmp,
	        test, "unexpected IP gateway");
}

static void
test_classless_static_routes_1 (void)
{
	GHashTable *options;
	NMIP4Config *ip4_config;
	const char *expected_route1_dest = "192.168.10.0";
	const char *expected_route1_gw = "192.168.1.1";
	const char *expected_route2_dest = "10.0.0.0";
	const char *expected_route2_gw = "10.17.66.41";
	static Option data[] = {
		/* dhclient custom format */
		{ "rfc3442_classless_static_routes", "24 192 168 10 192 168 1 1 8 10 10 17 66 41" },
		{ NULL, NULL }
	};

	options = fill_table (generic_options, NULL);
	options = fill_table (data, options);
	ip4_config = nm_dhcp_utils_ip4_config_from_options ("eth0", options, 0);
	ASSERT (ip4_config != NULL,
	        "dhcp-classless-1", "failed to parse DHCP4 options");

	/* IP4 routes */
	ASSERT (nm_ip4_config_get_num_routes (ip4_config) == 2,
	        "dhcp-classless-1", "unexpected number of IP routes");
	ip4_test_route ("dhcp-classless-1", ip4_config, 0,
	                expected_route1_dest, expected_route1_gw, 24);
	ip4_test_route ("dhcp-classless-1", ip4_config, 1,
	                expected_route2_dest, expected_route2_gw, 8);

	g_hash_table_destroy (options);
}

static void
test_classless_static_routes_2 (void)
{
	GHashTable *options;
	NMIP4Config *ip4_config;
	const char *expected_route1_dest = "192.168.10.0";
	const char *expected_route1_gw = "192.168.1.1";
	const char *expected_route2_dest = "10.0.0.0";
	const char *expected_route2_gw = "10.17.66.41";
	static Option data[] = {
		/* dhcpcd format */
		{ "classless_static_routes", "192.168.10.0/24 192.168.1.1 10.0.0.0/8 10.17.66.41" },
		{ NULL, NULL }
	};

	options = fill_table (generic_options, NULL);
	options = fill_table (data, options);
	ip4_config = nm_dhcp_utils_ip4_config_from_options ("eth0", options, 0);
	ASSERT (ip4_config != NULL,
	        "dhcp-classless-2", "failed to parse DHCP4 options");

	/* IP4 routes */
	ASSERT (nm_ip4_config_get_num_routes (ip4_config) == 2,
	        "dhcp-classless-2", "unexpected number of IP routes");
	ip4_test_route ("dhcp-classless-2", ip4_config, 0,
	                expected_route1_dest, expected_route1_gw, 24);
	ip4_test_route ("dhcp-classless-2", ip4_config, 1,
	                expected_route2_dest, expected_route2_gw, 8);

	g_hash_table_destroy (options);
}

static void
test_fedora_dhclient_classless_static_routes (void)
{
	GHashTable *options;
	NMIP4Config *ip4_config;
	const char *expected_route1_dest = "129.210.177.128";
	const char *expected_route1_gw = "192.168.0.113";
	const char *expected_route2_dest = "2.0.0.0";
	const char *expected_route2_gw = "10.34.255.6";
	const char *expected_gateway = "192.168.0.113";
	static Option data[] = {
		/* Fedora dhclient format */
		{ "classless_static_routes", "0 192.168.0.113 25.129.210.177.132 192.168.0.113 7.2 10.34.255.6" },
		{ NULL, NULL }
	};

	options = fill_table (generic_options, NULL);
	options = fill_table (data, options);
	ip4_config = nm_dhcp_utils_ip4_config_from_options ("eth0", options, 0);
	ASSERT (ip4_config != NULL,
	        "dhcp-fedora-dhclient-classless", "failed to parse DHCP4 options");

	/* IP4 routes */
	ASSERT (nm_ip4_config_get_num_routes (ip4_config) == 2,
	        "dhcp-fedora-dhclient-classless", "unexpected number of IP routes");
	ip4_test_route ("dhcp-fedora-dhclient-classless", ip4_config, 0,
	                expected_route1_dest, expected_route1_gw, 25);
	ip4_test_route ("dhcp-fedora-dhclient-classless", ip4_config, 1,
	                expected_route2_dest, expected_route2_gw, 7);

	/* Gateway */
	ip4_test_gateway ("dhcp-fedora-dhclient-classless", ip4_config, expected_gateway);

	g_hash_table_destroy (options);
}

static void
test_dhclient_invalid_classless_routes_1 (void)
{
	GHashTable *options;
	NMIP4Config *ip4_config;
	const char *expected_route1_dest = "192.168.10.0";
	const char *expected_route1_gw = "192.168.1.1";
	static Option data[] = {
		/* dhclient format */
		{ "rfc3442_classless_static_routes", "24 192 168 10 192 168 1 1 45 10 17 66 41" },
		{ NULL, NULL }
	};

	options = fill_table (generic_options, NULL);
	options = fill_table (data, options);

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*ignoring invalid classless static routes*");
	ip4_config = nm_dhcp_utils_ip4_config_from_options ("eth0", options, 0);
	ASSERT (ip4_config != NULL,
	        "dhcp-dhclient-classless-invalid-1", "failed to parse DHCP4 options");
	g_test_assert_expected_messages ();

	/* IP4 routes */
	ASSERT (nm_ip4_config_get_num_routes (ip4_config) == 1,
	        "dhcp-dhclient-classless-invalid-1", "unexpected number of IP routes");

	ip4_test_route ("dhcp-dhclient-classless-invalid-1", ip4_config, 0,
	                expected_route1_dest, expected_route1_gw, 24);

	g_hash_table_destroy (options);
}

static void
test_dhcpcd_invalid_classless_routes_1 (void)
{
	GHashTable *options;
	NMIP4Config *ip4_config;
	const char *expected_route1_dest = "10.1.1.5";
	const char *expected_route1_gw = "10.1.1.1";
	const char *expected_route2_dest = "100.99.88.56";
	const char *expected_route2_gw = "10.1.1.1";
	static Option data[] = {
		/* dhcpcd format */
		{ "classless_static_routes", "192.168.10.0/24 192.168.1.1 10.0.adfadf/44 10.17.66.41" },
		{ NULL, NULL }
	};

	options = fill_table (generic_options, NULL);
	options = fill_table (data, options);

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*ignoring invalid classless static routes*");
	ip4_config = nm_dhcp_utils_ip4_config_from_options ("eth0", options, 0);
	ASSERT (ip4_config != NULL,
	        "dhcp-dhcpcd-classless-invalid-1", "failed to parse DHCP4 options");
	g_test_assert_expected_messages ();

	/* Test falling back to old-style static routes if the classless static
	 * routes are invalid.
	 */
	ASSERT (nm_ip4_config_get_num_routes (ip4_config) == 2,
	        "dhcp-dhcpcdp-classless-invalid-1", "unexpected number of routes");
	ip4_test_route ("dhcp-dhcpcdp-classless-invalid-1", ip4_config, 0,
	                expected_route1_dest, expected_route1_gw, 32);
	ip4_test_route ("dhcp-dhcpcdp-classless-invalid-1", ip4_config, 1,
	                expected_route2_dest, expected_route2_gw, 32);

	g_hash_table_destroy (options);
}

static void
test_dhclient_invalid_classless_routes_2 (void)
{
	GHashTable *options;
	NMIP4Config *ip4_config;
	const char *expected_route1_dest = "10.1.1.5";
	const char *expected_route1_gw = "10.1.1.1";
	const char *expected_route2_dest = "100.99.88.56";
	const char *expected_route2_gw = "10.1.1.1";
	static Option data[] = {
		{ "rfc3442_classless_static_routes", "45 10 17 66 41 24 192 168 10 192 168 1 1" },
		{ NULL, NULL }
	};

	options = fill_table (generic_options, NULL);
	options = fill_table (data, options);

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*ignoring invalid classless static routes*");
	ip4_config = nm_dhcp_utils_ip4_config_from_options ("eth0", options, 0);
	ASSERT (ip4_config != NULL,
	        "dhcp-dhclient-classless-invalid-2", "failed to parse DHCP4 options");
	g_test_assert_expected_messages ();

	/* Test falling back to old-style static routes if the classless static
	 * routes are invalid.
	 */
	ASSERT (nm_ip4_config_get_num_routes (ip4_config) == 2,
	        "dhcp-dhclient-classless-invalid-2", "unexpected number of routes");
	ip4_test_route ("dhcp-dhclient-classless-invalid-2", ip4_config, 0,
	                expected_route1_dest, expected_route1_gw, 32);
	ip4_test_route ("dhcp-dhclient-classless-invalid-2", ip4_config, 1,
	                expected_route2_dest, expected_route2_gw, 32);

	g_hash_table_destroy (options);
}

static void
test_dhcpcd_invalid_classless_routes_2 (void)
{
	GHashTable *options;
	NMIP4Config *ip4_config;
	const char *expected_route1_dest = "10.1.1.5";
	const char *expected_route1_gw = "10.1.1.1";
	const char *expected_route2_dest = "100.99.88.56";
	const char *expected_route2_gw = "10.1.1.1";
	static Option data[] = {
		{ "classless_static_routes", "10.0.adfadf/44 10.17.66.41 192.168.10.0/24 192.168.1.1" },
		{ NULL, NULL }
	};

	options = fill_table (generic_options, NULL);
	options = fill_table (data, options);

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*ignoring invalid classless static routes*");
	ip4_config = nm_dhcp_utils_ip4_config_from_options ("eth0", options, 0);
	ASSERT (ip4_config != NULL,
	        "dhcp-dhcpcd-classless-invalid-2", "failed to parse DHCP4 options");
	g_test_assert_expected_messages ();

	/* Test falling back to old-style static routes if the classless static
	 * routes are invalid.
	 */

	/* Routes */
	ASSERT (nm_ip4_config_get_num_routes (ip4_config) == 2,
	        "dhcp-dhcpcd-classless-invalid-2", "unexpected number of routes");
	ip4_test_route ("dhcp-dhcpcd-classless-invalid-2", ip4_config, 0,
	                expected_route1_dest, expected_route1_gw, 32);
	ip4_test_route ("dhcp-dhcpcd-classless-invalid-2", ip4_config, 1,
	                expected_route2_dest, expected_route2_gw, 32);

	g_hash_table_destroy (options);
}

static void
test_dhclient_invalid_classless_routes_3 (void)
{
	GHashTable *options;
	NMIP4Config *ip4_config;
	const char *expected_route1_dest = "192.168.10.0";
	const char *expected_route1_gw = "192.168.1.1";
	static Option data[] = {
		{ "rfc3442_classless_static_routes", "24 192 168 10 192 168 1 1 32 128 10 17 66 41" },
		{ NULL, NULL }
	};

	options = fill_table (generic_options, NULL);
	options = fill_table (data, options);

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*ignoring invalid classless static routes*");
	ip4_config = nm_dhcp_utils_ip4_config_from_options ("eth0", options, 0);
	ASSERT (ip4_config != NULL,
	        "dhcp-dhclient-classless-invalid-3", "failed to parse DHCP4 options");
	g_test_assert_expected_messages ();

	/* IP4 routes */
	ASSERT (nm_ip4_config_get_num_routes (ip4_config) == 1,
	        "dhcp-dhclient-classless-invalid-3", "unexpected number of IP routes");
	ip4_test_route ("dhcp-dhclient-classless-invalid-3", ip4_config, 0,
	                expected_route1_dest, expected_route1_gw, 24);

	g_hash_table_destroy (options);
}

static void
test_dhcpcd_invalid_classless_routes_3 (void)
{
	GHashTable *options;
	NMIP4Config *ip4_config;
	const char *expected_route1_dest = "192.168.10.0";
	const char *expected_route1_gw = "192.168.1.1";
	static Option data[] = {
		{ "classless_static_routes", "192.168.10.0/24 192.168.1.1 128/32 10.17.66.41" },
		{ NULL, NULL }
	};

	options = fill_table (generic_options, NULL);
	options = fill_table (data, options);

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*DHCP provided invalid classless static route*");
	ip4_config = nm_dhcp_utils_ip4_config_from_options ("eth0", options, 0);
	ASSERT (ip4_config != NULL,
	        "dhcp-dhcpcd-classless-invalid-3", "failed to parse DHCP4 options");
	g_test_assert_expected_messages ();

	/* IP4 routes */
	ASSERT (nm_ip4_config_get_num_routes (ip4_config) == 1,
	        "dhcp-dhcpcd-classless-invalid-3", "unexpected number of IP routes");
	ip4_test_route ("dhcp-dhcpcd-classless-invalid-3", ip4_config, 0,
	                expected_route1_dest, expected_route1_gw, 24);

	g_hash_table_destroy (options);
}

static void
test_dhclient_gw_in_classless_routes (void)
{
	GHashTable *options;
	NMIP4Config *ip4_config;
	const char *expected_route1_dest = "192.168.10.0";
	const char *expected_route1_gw = "192.168.1.1";
	const char *expected_gateway = "192.2.3.4";
	static Option data[] = {
		{ "rfc3442_classless_static_routes", "24 192 168 10 192 168 1 1 0 192 2 3 4" },
		{ NULL, NULL }
	};

	options = fill_table (generic_options, NULL);
	options = fill_table (data, options);
	ip4_config = nm_dhcp_utils_ip4_config_from_options ("eth0", options, 0);
	ASSERT (ip4_config != NULL,
	        "dhcp-dhclient-classless-gateway", "failed to parse DHCP4 options");

	/* IP4 routes */
	ASSERT (nm_ip4_config_get_num_routes (ip4_config) == 1,
	        "dhcp-dhclient-classless-gateway", "unexpected number of IP routes");
	ip4_test_route ("dhcp-dhclient-classless-gateway", ip4_config, 0,
	                expected_route1_dest, expected_route1_gw, 24);

	/* Gateway */
	ip4_test_gateway ("dhcp-dhclient-classless-gateway", ip4_config, expected_gateway);

	g_hash_table_destroy (options);
}

static void
test_dhcpcd_gw_in_classless_routes (void)
{
	GHashTable *options;
	NMIP4Config *ip4_config;
	const char *expected_route1_dest = "192.168.10.0";
	const char *expected_route1_gw = "192.168.1.1";
	const char *expected_gateway = "192.2.3.4";
	static Option data[] = {
		{ "classless_static_routes", "192.168.10.0/24 192.168.1.1 0.0.0.0/0 192.2.3.4" },
		{ NULL, NULL }
	};

	options = fill_table (generic_options, NULL);
	options = fill_table (data, options);
	ip4_config = nm_dhcp_utils_ip4_config_from_options ("eth0", options, 0);
	ASSERT (ip4_config != NULL,
	        "dhcp-dhcpcd-classless-gateway", "failed to parse DHCP4 options");

	/* IP4 routes */
	ASSERT (nm_ip4_config_get_num_routes (ip4_config) == 1,
	        "dhcp-dhcpcd-classless-gateway", "unexpected number of IP routes");
	ip4_test_route ("dhcp-dhcpcd-classless-gateway", ip4_config, 0,
	                expected_route1_dest, expected_route1_gw, 24);

	/* Gateway */
	ip4_test_gateway ("dhcp-dhcpcd-classless-gateway", ip4_config, expected_gateway);

	g_hash_table_destroy (options);
}

static Option escaped_searches_options[] = {
	{ "domain_search", "host1\\032host2\\032host3" },
	{ NULL, NULL }
};

static void
test_escaped_domain_searches (void)
{
	GHashTable *options;
	NMIP4Config *ip4_config;
	const char *expected_search0 = "host1";
	const char *expected_search1 = "host2";
	const char *expected_search2 = "host3";

	options = fill_table (generic_options, NULL);
	options = fill_table (escaped_searches_options, options);
	ip4_config = nm_dhcp_utils_ip4_config_from_options ("eth0", options, 0);
	ASSERT (ip4_config != NULL,
	        "dhcp-escaped-domain-searches", "failed to parse DHCP4 options");

	/* domain searches */
	ASSERT (nm_ip4_config_get_num_searches (ip4_config) == 3,
	        "dhcp-escaped-domain-searches", "unexpected number of searches");
	ASSERT (!strcmp (nm_ip4_config_get_search (ip4_config, 0), expected_search0),
	        "dhcp-escaped-domain-searches", "unexpected domain search #1");
	ASSERT (!strcmp (nm_ip4_config_get_search (ip4_config, 1), expected_search1),
	        "dhcp-escaped-domain-searches", "unexpected domain search #1");
	ASSERT (!strcmp (nm_ip4_config_get_search (ip4_config, 2), expected_search2),
	        "dhcp-escaped-domain-searches", "unexpected domain search #1");

	g_hash_table_destroy (options);
}

static Option invalid_escaped_searches_options[] = {
	{ "domain_search", "host1\\aahost2\\032host3" },
	{ NULL, NULL }
};

static void
test_invalid_escaped_domain_searches (void)
{
	GHashTable *options;
	NMIP4Config *ip4_config;

	options = fill_table (generic_options, NULL);
	options = fill_table (invalid_escaped_searches_options, options);

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*invalid domain search*");
	ip4_config = nm_dhcp_utils_ip4_config_from_options ("eth0", options, 0);
	ASSERT (ip4_config != NULL,
	        "dhcp-invalid-escaped-domain-searches", "failed to parse DHCP4 options");
	g_test_assert_expected_messages ();

	/* domain searches */
	ASSERT (nm_ip4_config_get_num_searches (ip4_config) == 0,
	        "dhcp-invalid-escaped-domain-searches", "unexpected domain searches");

	g_hash_table_destroy (options);
}

static void
test_ip4_missing_prefix (const char *ip, guint32 expected_prefix)
{
	GHashTable *options;
	NMIP4Config *ip4_config;
	const NMPlatformIP4Address *address;

	options = fill_table (generic_options, NULL);
	g_hash_table_insert (options, "ip_address", (gpointer) ip);
	g_hash_table_remove (options, "subnet_mask");

	ip4_config = nm_dhcp_utils_ip4_config_from_options ("eth0", options, 0);
	ASSERT (ip4_config != NULL,
	        "dhcp-ip4-missing-prefix", "failed to parse DHCP4 options");

	ASSERT (nm_ip4_config_get_num_addresses (ip4_config) == 1,
	        "dhcp-ip4-missing-prefix", "unexpected number of IP4 addresses (not 1)");

	address = nm_ip4_config_get_address (ip4_config, 0);
	ASSERT (address,
	        "dhcp-ip4-missing-prefix", "missing IP4 address #1");

	ASSERT (address->plen == expected_prefix,
	        "dhcp-ip4-missing-prefix", "unexpected IP4 address prefix %d (expected %d)",
	        address->plen, expected_prefix);

	g_hash_table_destroy (options);
}

static void
test_ip4_missing_prefix_24 (void)
{
	test_ip4_missing_prefix ("192.168.1.10", 24);
}

static void
test_ip4_missing_prefix_16 (void)
{
	test_ip4_missing_prefix ("172.16.54.50", 16);
}

static void
test_ip4_missing_prefix_8 (void)
{
	test_ip4_missing_prefix ("10.1.2.3", 8);
}

static void
test_ip4_prefix_classless (void)
{
	GHashTable *options;
	NMIP4Config *ip4_config;
	const NMPlatformIP4Address *address;

	/* Ensure that the missing-subnet-mask handler doesn't mangle classless
	 * subnet masks at all.  The handler should trigger only if the server
	 * doesn't send the subnet mask.
	 */

	options = fill_table (generic_options, NULL);
	g_hash_table_insert (options, "ip_address", "172.16.54.22");
	g_hash_table_insert (options, "subnet_mask", "255.255.252.0");

	ip4_config = nm_dhcp_utils_ip4_config_from_options ("eth0", options, 0);
	ASSERT (ip4_config != NULL,
	        "dhcp-ip4-prefix-classless", "failed to parse DHCP4 options");

	ASSERT (nm_ip4_config_get_num_addresses (ip4_config) == 1,
	        "dhcp-ip4-prefix-classless", "unexpected number of IP4 addresses (not 1)");

	address = nm_ip4_config_get_address (ip4_config, 0);
	ASSERT (address,
	        "dhcp-ip4-prefix-classless", "missing IP4 address #1");

	ASSERT (address->plen == 22,
	        "dhcp-ip4-prefix-classless", "unexpected IP4 address prefix %d (expected 22)",
	        address->plen);

	g_hash_table_destroy (options);
}

NMTST_DEFINE ();

int main (int argc, char **argv)
{
	nmtst_init_assert_logging (&argc, &argv);
	nm_logging_setup ("WARN", "DEFAULT", NULL, NULL);

	g_test_add_func ("/dhcp/generic-options", test_generic_options);
	g_test_add_func ("/dhcp/wins-options", test_wins_options);
	g_test_add_func ("/dhcp/classless-static-routes-1", test_classless_static_routes_1);
	g_test_add_func ("/dhcp/classless-static-routes-2", test_classless_static_routes_2);
	g_test_add_func ("/dhcp/fedora-dhclient-classless-static-routes", test_fedora_dhclient_classless_static_routes);
	g_test_add_func ("/dhcp/dhclient-invalid-classless-routes-1", test_dhclient_invalid_classless_routes_1);
	g_test_add_func ("/dhcp/dhcpcd-invalid-classless-routes-1", test_dhcpcd_invalid_classless_routes_1);
	g_test_add_func ("/dhcp/dhclient-invalid-classless-routes-2", test_dhclient_invalid_classless_routes_2);
	g_test_add_func ("/dhcp/dhcpcd-invalid-classless-routes-2", test_dhcpcd_invalid_classless_routes_2);
	g_test_add_func ("/dhcp/dhclient-invalid-classless-routes-3", test_dhclient_invalid_classless_routes_3);
	g_test_add_func ("/dhcp/dhcpcd-invalid-classless-routes-3", test_dhcpcd_invalid_classless_routes_3);
	g_test_add_func ("/dhcp/dhclient-gw-in-classless-routes", test_dhclient_gw_in_classless_routes);
	g_test_add_func ("/dhcp/dhcpcd-gw-in-classless-routes", test_dhcpcd_gw_in_classless_routes);
	g_test_add_func ("/dhcp/escaped-domain-searches", test_escaped_domain_searches);
	g_test_add_func ("/dhcp/invalid-escaped-domain-searches", test_invalid_escaped_domain_searches);
	g_test_add_func ("/dhcp/ip4-missing-prefix-24", test_ip4_missing_prefix_24);
	g_test_add_func ("/dhcp/ip4-missing-prefix-16", test_ip4_missing_prefix_16);
	g_test_add_func ("/dhcp/ip4-missing-prefix-8", test_ip4_missing_prefix_8);
	g_test_add_func ("/dhcp/ip4-prefix-classless", test_ip4_prefix_classless);

	return g_test_run ();
}

