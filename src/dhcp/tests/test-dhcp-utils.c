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

#include "nm-default.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/rtnetlink.h>

#include "nm-utils/nm-dedup-multi.h"
#include "nm-utils.h"

#include "dhcp/nm-dhcp-utils.h"
#include "platform/nm-platform.h"

#include "nm-test-utils-core.h"

static NMIP4Config *
_ip4_config_from_options (int ifindex,
                          const char *iface,
                          GHashTable *options,
                          guint32 route_metric)
{
	nm_auto_unref_dedup_multi_index NMDedupMultiIndex *multi_idx = nm_dedup_multi_index_new ();
	NMIP4Config *config;

	config = nm_dhcp_utils_ip4_config_from_options (multi_idx, ifindex, iface, options, RT_TABLE_MAIN, route_metric);
	g_assert (config);
	return config;
}

typedef struct {
	const char *name;
	const char *value;
} Option;

static GHashTable *
fill_table (const Option *test_options, GHashTable *table)
{
	const Option *opt;

	if (!table)
		table = g_hash_table_new_full (nm_str_hash, g_str_equal, NULL, NULL);
	for (opt = test_options; opt->name; opt++)
		g_hash_table_insert (table, (gpointer) opt->name, (gpointer) opt->value);
	return table;
}

static const Option generic_options[] = {
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
	gs_unref_object NMIP4Config *ip4_config = NULL;
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
	ip4_config = _ip4_config_from_options (1, "eth0", options, 0);

	/* IP4 address */
	g_assert_cmpint (nm_ip4_config_get_num_addresses (ip4_config), ==, 1);
	address = _nmtst_ip4_config_get_address (ip4_config, 0);
	g_assert (inet_pton (AF_INET, expected_addr, &tmp) > 0);
	g_assert (address->address == tmp);
	g_assert (address->peer_address == tmp);
	g_assert_cmpint (address->plen, ==, 24);

	/* Gateway */
	g_assert (inet_pton (AF_INET, expected_gw, &tmp) > 0);
	g_assert (nmtst_ip4_config_get_gateway (ip4_config) == tmp);

	g_assert_cmpint (nm_ip4_config_get_num_wins (ip4_config), ==, 0);

	g_assert_cmpint (nm_ip4_config_get_mtu (ip4_config), ==, 987);

	/* Domain searches */
	g_assert_cmpint (nm_ip4_config_get_num_searches (ip4_config), ==, 2);
	g_assert_cmpstr (nm_ip4_config_get_search (ip4_config, 0), ==, expected_search1);
	g_assert_cmpstr (nm_ip4_config_get_search (ip4_config, 1), ==, expected_search2);

	/* DNS servers */
	g_assert_cmpint (nm_ip4_config_get_num_nameservers (ip4_config), ==, 2);
	g_assert (inet_pton (AF_INET, expected_dns1, &tmp) > 0);
	g_assert (nm_ip4_config_get_nameserver (ip4_config, 0) == tmp);
	g_assert (inet_pton (AF_INET, expected_dns2, &tmp) > 0);
	g_assert (nm_ip4_config_get_nameserver (ip4_config, 1) == tmp);

	/* Routes */
	g_assert_cmpint (nm_ip4_config_get_num_routes (ip4_config), ==, 3);

	/* Route #1 */
	route = _nmtst_ip4_config_get_route (ip4_config, 0);
	g_assert (inet_pton (AF_INET, expected_route1_dest, &tmp) > 0);
	g_assert (route->network == tmp);
	g_assert (inet_pton (AF_INET, expected_route1_gw, &tmp) > 0);
	g_assert (route->gateway == tmp);
	g_assert_cmpint (route->plen, ==, 32);
	g_assert_cmpint (route->metric, ==, 0);

	/* Route #2 */
	route = _nmtst_ip4_config_get_route (ip4_config, 1);
	g_assert (route->network == nmtst_inet4_from_string (expected_route2_dest));
	g_assert (route->gateway == nmtst_inet4_from_string (expected_route2_gw));
	g_assert_cmpint (route->plen, ==, 32);
	g_assert_cmpint (route->metric, ==, 0);

	route = _nmtst_ip4_config_get_route (ip4_config, 2);
	g_assert (route->network == nmtst_inet4_from_string ("0.0.0.0"));
	g_assert (route->gateway == nmtst_inet4_from_string ("192.168.1.1"));
	g_assert_cmpint (route->plen, ==, 0);
	g_assert_cmpint (route->metric, ==, 0);

	g_hash_table_destroy (options);
}

static void
test_wins_options (void)
{
	GHashTable *options;
	gs_unref_object NMIP4Config *ip4_config = NULL;
	const NMPlatformIP4Address *address;
	guint32 tmp;
	const char *expected_wins1 = "63.12.199.5";
	const char *expected_wins2 = "150.4.88.120";
	static const Option data[] = {
		{ "netbios_name_servers", "63.12.199.5 150.4.88.120" },
		{ NULL, NULL }
	};

	options = fill_table (generic_options, NULL);
	options = fill_table (data, options);
	ip4_config = _ip4_config_from_options (1, "eth0", options, 0);

	/* IP4 address */
	g_assert_cmpint (nm_ip4_config_get_num_addresses (ip4_config), ==, 1);
	address = _nmtst_ip4_config_get_address (ip4_config, 0);
	g_assert (address);
	g_assert_cmpint (nm_ip4_config_get_num_wins (ip4_config), ==, 2);
	g_assert (inet_pton (AF_INET, expected_wins1, &tmp) > 0);
	g_assert (nm_ip4_config_get_wins (ip4_config, 0) == tmp);
	g_assert (inet_pton (AF_INET, expected_wins2, &tmp) > 0);
	g_assert (nm_ip4_config_get_wins (ip4_config, 1) == tmp);

	g_hash_table_destroy (options);
}

static void
test_vendor_option_metered (void)
{
	GHashTable *options;
	gs_unref_object NMIP4Config *ip4_config = NULL;
	static const Option data[] = {
		{ "vendor_encapsulated_options", "ANDROID_METERED" },
		{ NULL, NULL }
	};

	options = fill_table (generic_options, NULL);
	ip4_config = _ip4_config_from_options (1, "eth0", options, 0);
	g_assert (nm_ip4_config_get_metered (ip4_config) == FALSE);
	g_hash_table_destroy (options);
	g_clear_object (&ip4_config);

	options = fill_table (generic_options, NULL);
	options = fill_table (data, options);
	ip4_config = _ip4_config_from_options (1, "eth0", options, 0);
	g_assert (nm_ip4_config_get_metered (ip4_config) == TRUE);
	g_hash_table_destroy (options);
}

static void
ip4_test_route (NMIP4Config *ip4_config,
                guint route_num,
                const char *expected_dest,
                const char *expected_gw,
                guint expected_prefix)
{
	const NMPlatformIP4Route *route;
	guint32 tmp;

	g_assert (expected_prefix <= 32);

	route = _nmtst_ip4_config_get_route (ip4_config, route_num);
	g_assert (inet_pton (AF_INET, expected_dest, &tmp) > 0);
	g_assert (route->network == tmp);
	g_assert (inet_pton (AF_INET, expected_gw, &tmp) > 0);
	g_assert (route->gateway == tmp);
	g_assert_cmpint (route->plen, ==, expected_prefix);
	g_assert_cmpint (route->metric, ==, 0);
}

static void
ip4_test_gateway (NMIP4Config *ip4_config, const char *expected_gw)
{
	guint32 tmp;

	g_assert_cmpint (nm_ip4_config_get_num_addresses (ip4_config), ==, 1);
	g_assert (inet_pton (AF_INET, expected_gw, &tmp) > 0);
	g_assert (nmtst_ip4_config_get_gateway (ip4_config) == tmp);
}

static void
test_classless_static_routes_1 (void)
{
	GHashTable *options;
	gs_unref_object NMIP4Config *ip4_config = NULL;
	const char *expected_route1_dest = "192.168.10.0";
	const char *expected_route1_gw = "192.168.1.1";
	const char *expected_route2_dest = "10.0.0.0";
	const char *expected_route2_gw = "10.17.66.41";
	static const Option data[] = {
		/* dhclient custom format */
		{ "rfc3442_classless_static_routes", "24 192 168 10 192 168 1 1 8 10 10 17 66 41" },
		{ NULL, NULL }
	};

	options = fill_table (generic_options, NULL);
	options = fill_table (data, options);
	ip4_config = _ip4_config_from_options (1, "eth0", options, 0);

	/* IP4 routes */
	g_assert_cmpint (nm_ip4_config_get_num_routes (ip4_config), ==, 3);
	ip4_test_route (ip4_config, 0, expected_route1_dest, expected_route1_gw, 24);
	ip4_test_route (ip4_config, 1, expected_route2_dest, expected_route2_gw, 8);
	ip4_test_route (ip4_config, 2, "0.0.0.0", "192.168.1.1", 0);

	g_hash_table_destroy (options);
}

static void
test_classless_static_routes_2 (void)
{
	GHashTable *options;
	gs_unref_object NMIP4Config *ip4_config = NULL;
	const char *expected_route1_dest = "192.168.10.0";
	const char *expected_route1_gw = "192.168.1.1";
	const char *expected_route2_dest = "10.0.0.0";
	const char *expected_route2_gw = "10.17.66.41";
	static const Option data[] = {
		/* dhcpcd format */
		{ "classless_static_routes", "192.168.10.0/24 192.168.1.1 10.0.0.0/8 10.17.66.41" },
		{ NULL, NULL }
	};

	options = fill_table (generic_options, NULL);
	options = fill_table (data, options);
	ip4_config = _ip4_config_from_options (1, "eth0", options, 0);

	/* IP4 routes */
	g_assert_cmpint (nm_ip4_config_get_num_routes (ip4_config), ==, 3);
	ip4_test_route (ip4_config, 0, expected_route1_dest, expected_route1_gw, 24);
	ip4_test_route (ip4_config, 1, expected_route2_dest, expected_route2_gw, 8);
	ip4_test_route (ip4_config, 2, "0.0.0.0", expected_route1_gw, 0);

	g_hash_table_destroy (options);
}

static void
test_fedora_dhclient_classless_static_routes (void)
{
	GHashTable *options;
	gs_unref_object NMIP4Config *ip4_config = NULL;
	const char *expected_route1_dest = "129.210.177.128";
	const char *expected_route1_gw = "192.168.0.113";
	const char *expected_route2_dest = "2.0.0.0";
	const char *expected_route2_gw = "10.34.255.6";
	const char *expected_gateway = "192.168.0.113";
	static const Option data[] = {
		/* Fedora dhclient format */
		{ "classless_static_routes", "0 192.168.0.113 25.129.210.177.132 192.168.0.113 7.2 10.34.255.6" },
		{ NULL, NULL }
	};

	options = fill_table (generic_options, NULL);
	options = fill_table (data, options);
	ip4_config = _ip4_config_from_options (1, "eth0", options, 0);

	/* IP4 routes */
	g_assert_cmpint (nm_ip4_config_get_num_routes (ip4_config), ==, 3);
	ip4_test_route (ip4_config, 0, expected_route1_dest, expected_route1_gw, 25);
	ip4_test_route (ip4_config, 1, expected_route2_dest, expected_route2_gw, 7);
	ip4_test_route (ip4_config, 2, "0.0.0.0", expected_route1_gw, 0);

	/* Gateway */
	ip4_test_gateway (ip4_config, expected_gateway);

	g_hash_table_destroy (options);
}

static void
test_dhclient_invalid_classless_routes_1 (void)
{
	GHashTable *options;
	gs_unref_object NMIP4Config *ip4_config = NULL;
	const char *expected_route1_dest = "192.168.10.0";
	const char *expected_route1_gw = "192.168.1.1";
	static const Option data[] = {
		/* dhclient format */
		{ "rfc3442_classless_static_routes", "24 192 168 10 192 168 1 1 45 10 17 66 41" },
		{ NULL, NULL }
	};

	options = fill_table (generic_options, NULL);
	options = fill_table (data, options);

	NMTST_EXPECT_NM_WARN ("*ignoring invalid classless static routes*");
	ip4_config = _ip4_config_from_options (1, "eth0", options, 0);
	g_test_assert_expected_messages ();

	/* IP4 routes */
	g_assert_cmpint (nm_ip4_config_get_num_routes (ip4_config), ==, 2);
	ip4_test_route (ip4_config, 0, expected_route1_dest, expected_route1_gw, 24);
	ip4_test_route (ip4_config, 1, "0.0.0.0", expected_route1_gw, 0);

	g_hash_table_destroy (options);
}

static void
test_dhcpcd_invalid_classless_routes_1 (void)
{
	GHashTable *options;
	gs_unref_object NMIP4Config *ip4_config = NULL;
	const char *expected_route1_dest = "10.1.1.5";
	const char *expected_route1_gw = "10.1.1.1";
	const char *expected_route2_dest = "100.99.88.56";
	const char *expected_route2_gw = "10.1.1.1";
	static const Option data[] = {
		/* dhcpcd format */
		{ "classless_static_routes", "192.168.10.0/24 192.168.1.1 10.0.adfadf/44 10.17.66.41" },
		{ NULL, NULL }
	};

	options = fill_table (generic_options, NULL);
	options = fill_table (data, options);

	NMTST_EXPECT_NM_WARN ("*ignoring invalid classless static routes*");
	ip4_config = _ip4_config_from_options (1, "eth0", options, 0);
	g_test_assert_expected_messages ();

	/* Test falling back to old-style static routes if the classless static
	 * routes are invalid.
	 */
	g_assert_cmpint (nm_ip4_config_get_num_routes (ip4_config), ==, 3);
	ip4_test_route (ip4_config, 0, expected_route1_dest, expected_route1_gw, 32);
	ip4_test_route (ip4_config, 1, expected_route2_dest, expected_route2_gw, 32);
	ip4_test_route (ip4_config, 2, "0.0.0.0", "192.168.1.1", 0);

	g_hash_table_destroy (options);
}

static void
test_dhclient_invalid_classless_routes_2 (void)
{
	GHashTable *options;
	gs_unref_object NMIP4Config *ip4_config = NULL;
	const char *expected_route1_dest = "10.1.1.5";
	const char *expected_route1_gw = "10.1.1.1";
	const char *expected_route2_dest = "100.99.88.56";
	const char *expected_route2_gw = "10.1.1.1";
	static const Option data[] = {
		{ "rfc3442_classless_static_routes", "45 10 17 66 41 24 192 168 10 192 168 1 1" },
		{ NULL, NULL }
	};

	options = fill_table (generic_options, NULL);
	options = fill_table (data, options);

	NMTST_EXPECT_NM_WARN ("*ignoring invalid classless static routes*");
	ip4_config = _ip4_config_from_options (1, "eth0", options, 0);
	g_test_assert_expected_messages ();

	/* Test falling back to old-style static routes if the classless static
	 * routes are invalid.
	 */
	g_assert_cmpint (nm_ip4_config_get_num_routes (ip4_config), ==, 3);
	ip4_test_route (ip4_config, 0, expected_route1_dest, expected_route1_gw, 32);
	ip4_test_route (ip4_config, 1, expected_route2_dest, expected_route2_gw, 32);
	ip4_test_route (ip4_config, 2, "0.0.0.0", "192.168.1.1", 0);

	g_hash_table_destroy (options);
}

static void
test_dhcpcd_invalid_classless_routes_2 (void)
{
	GHashTable *options;
	gs_unref_object NMIP4Config *ip4_config = NULL;
	const char *expected_route1_dest = "10.1.1.5";
	const char *expected_route1_gw = "10.1.1.1";
	const char *expected_route2_dest = "100.99.88.56";
	const char *expected_route2_gw = "10.1.1.1";
	static const Option data[] = {
		{ "classless_static_routes", "10.0.adfadf/44 10.17.66.41 192.168.10.0/24 192.168.1.1" },
		{ NULL, NULL }
	};

	options = fill_table (generic_options, NULL);
	options = fill_table (data, options);

	NMTST_EXPECT_NM_WARN ("*ignoring invalid classless static routes*");
	ip4_config = _ip4_config_from_options (1, "eth0", options, 0);
	g_test_assert_expected_messages ();

	/* Test falling back to old-style static routes if the classless static
	 * routes are invalid.
	 */

	/* Routes */
	g_assert_cmpint (nm_ip4_config_get_num_routes (ip4_config), ==, 3);
	ip4_test_route (ip4_config, 0, expected_route1_dest, expected_route1_gw, 32);
	ip4_test_route (ip4_config, 1, expected_route2_dest, expected_route2_gw, 32);
	ip4_test_route (ip4_config, 2, "0.0.0.0", "192.168.1.1", 0);

	g_hash_table_destroy (options);
}

static void
test_dhclient_invalid_classless_routes_3 (void)
{
	GHashTable *options;
	gs_unref_object NMIP4Config *ip4_config = NULL;
	const char *expected_route1_dest = "192.168.10.0";
	const char *expected_route1_gw = "192.168.1.1";
	static const Option data[] = {
		{ "rfc3442_classless_static_routes", "24 192 168 10 192 168 1 1 32 128 10 17 66 41" },
		{ NULL, NULL }
	};

	options = fill_table (generic_options, NULL);
	options = fill_table (data, options);

	NMTST_EXPECT_NM_WARN ("*ignoring invalid classless static routes*");
	ip4_config = _ip4_config_from_options (1, "eth0", options, 0);
	g_test_assert_expected_messages ();

	/* IP4 routes */
	g_assert_cmpint (nm_ip4_config_get_num_routes (ip4_config), ==, 2);
	ip4_test_route (ip4_config, 0, expected_route1_dest, expected_route1_gw, 24);
	ip4_test_route (ip4_config, 1, "0.0.0.0", expected_route1_gw, 0);

	g_hash_table_destroy (options);
}

static void
test_dhcpcd_invalid_classless_routes_3 (void)
{
	GHashTable *options;
	gs_unref_object NMIP4Config *ip4_config = NULL;
	const char *expected_route1_dest = "192.168.10.0";
	const char *expected_route1_gw = "192.168.1.1";
	static Option data[] = {
		{ "classless_static_routes", "192.168.10.0/24 192.168.1.1 128/32 10.17.66.41" },
		{ NULL, NULL }
	};

	options = fill_table (generic_options, NULL);
	options = fill_table (data, options);

	NMTST_EXPECT_NM_WARN ("*DHCP provided invalid classless static route*");
	ip4_config = _ip4_config_from_options (1, "eth0", options, 0);
	g_test_assert_expected_messages ();

	/* IP4 routes */
	g_assert_cmpint (nm_ip4_config_get_num_routes (ip4_config), ==, 2);
	ip4_test_route (ip4_config, 0, expected_route1_dest, expected_route1_gw, 24);
	ip4_test_route (ip4_config, 1, "0.0.0.0", expected_route1_gw, 0);

	g_hash_table_destroy (options);
}

static void
test_dhclient_gw_in_classless_routes (void)
{
	GHashTable *options;
	gs_unref_object NMIP4Config *ip4_config = NULL;
	const char *expected_route1_dest = "192.168.10.0";
	const char *expected_route1_gw = "192.168.1.1";
	const char *expected_gateway = "192.2.3.4";
	static Option data[] = {
		{ "rfc3442_classless_static_routes", "24 192 168 10 192 168 1 1 0 192 2 3 4" },
		{ NULL, NULL }
	};

	options = fill_table (generic_options, NULL);
	options = fill_table (data, options);
	ip4_config = _ip4_config_from_options (1, "eth0", options, 0);

	/* IP4 routes */
	g_assert_cmpint (nm_ip4_config_get_num_routes (ip4_config), ==, 2);
	ip4_test_route (ip4_config, 0, expected_route1_dest, expected_route1_gw, 24);
	ip4_test_route (ip4_config, 1, "0.0.0.0", "192.2.3.4", 0);

	/* Gateway */
	ip4_test_gateway (ip4_config, expected_gateway);

	g_hash_table_destroy (options);
}

static void
test_dhcpcd_gw_in_classless_routes (void)
{
	GHashTable *options;
	gs_unref_object NMIP4Config *ip4_config = NULL;
	const char *expected_route1_dest = "192.168.10.0";
	const char *expected_route1_gw = "192.168.1.1";
	const char *expected_gateway = "192.2.3.4";
	static Option data[] = {
		{ "classless_static_routes", "192.168.10.0/24 192.168.1.1 0.0.0.0/0 192.2.3.4" },
		{ NULL, NULL }
	};

	options = fill_table (generic_options, NULL);
	options = fill_table (data, options);
	ip4_config = _ip4_config_from_options (1, "eth0", options, 0);

	/* IP4 routes */
	g_assert_cmpint (nm_ip4_config_get_num_routes (ip4_config), ==, 2);
	ip4_test_route (ip4_config, 0, expected_route1_dest, expected_route1_gw, 24);
	ip4_test_route (ip4_config, 1, "0.0.0.0", "192.2.3.4", 0);

	/* Gateway */
	ip4_test_gateway (ip4_config, expected_gateway);

	g_hash_table_destroy (options);
}

static void
test_escaped_domain_searches (void)
{
	GHashTable *options;
	gs_unref_object NMIP4Config *ip4_config = NULL;
	const char *expected_search0 = "host1";
	const char *expected_search1 = "host2";
	const char *expected_search2 = "host3";
	static const Option data[] = {
		{ "domain_search", "host1\\032host2\\032host3" },
		{ NULL, NULL }
	};

	options = fill_table (generic_options, NULL);
	options = fill_table (data, options);
	ip4_config = _ip4_config_from_options (1, "eth0", options, 0);

	/* domain searches */
	g_assert_cmpint (nm_ip4_config_get_num_searches (ip4_config), ==, 3);
	g_assert_cmpstr (nm_ip4_config_get_search (ip4_config, 0), ==, expected_search0);
	g_assert_cmpstr (nm_ip4_config_get_search (ip4_config, 1), ==, expected_search1);
	g_assert_cmpstr (nm_ip4_config_get_search (ip4_config, 2), ==, expected_search2);

	g_hash_table_destroy (options);
}

static void
test_invalid_escaped_domain_searches (void)
{
	GHashTable *options;
	gs_unref_object NMIP4Config *ip4_config = NULL;
	static const Option data[] = {
		{ "domain_search", "host1\\aahost2\\032host3" },
		{ NULL, NULL }
	};

	options = fill_table (generic_options, NULL);
	options = fill_table (data, options);

	NMTST_EXPECT_NM_WARN ("*invalid domain search*");
	ip4_config = _ip4_config_from_options (1, "eth0", options, 0);
	g_test_assert_expected_messages ();

	/* domain searches */
	g_assert_cmpint (nm_ip4_config_get_num_searches (ip4_config), ==, 0);

	g_hash_table_destroy (options);
}

static void
test_ip4_missing_prefix (const char *ip, guint32 expected_prefix)
{
	GHashTable *options;
	gs_unref_object NMIP4Config *ip4_config = NULL;
	const NMPlatformIP4Address *address;

	options = fill_table (generic_options, NULL);
	g_hash_table_insert (options, "ip_address", (gpointer) ip);
	g_hash_table_remove (options, "subnet_mask");

	ip4_config = _ip4_config_from_options (1, "eth0", options, 0);

	g_assert_cmpint (nm_ip4_config_get_num_addresses (ip4_config), ==, 1);
	address = _nmtst_ip4_config_get_address (ip4_config, 0);
	g_assert (address);
	g_assert_cmpint (address->plen, ==, expected_prefix);

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
	gs_unref_object NMIP4Config *ip4_config = NULL;
	const NMPlatformIP4Address *address;

	/* Ensure that the missing-subnet-mask handler doesn't mangle classless
	 * subnet masks at all.  The handler should trigger only if the server
	 * doesn't send the subnet mask.
	 */

	options = fill_table (generic_options, NULL);
	g_hash_table_insert (options, "ip_address", "172.16.54.22");
	g_hash_table_insert (options, "subnet_mask", "255.255.252.0");

	ip4_config = _ip4_config_from_options (1, "eth0", options, 0);

	g_assert_cmpint (nm_ip4_config_get_num_addresses (ip4_config), ==, 1);
	address = _nmtst_ip4_config_get_address (ip4_config, 0);
	g_assert (address);
	g_assert_cmpint (address->plen, ==, 22);

	g_hash_table_destroy (options);
}

#define COMPARE_ID(src, is_str, expected, expected_len) \
G_STMT_START { \
	gs_unref_bytes GBytes *b = NULL; \
	const char *p; \
	gsize l; \
 \
	b = nm_dhcp_utils_client_id_string_to_bytes (src); \
	g_assert (b); \
	p = g_bytes_get_data (b, &l); \
	if (is_str) { \
		g_assert_cmpint (l, ==, expected_len + 1); \
		g_assert_cmpint (((const char *) p)[0], ==, 0); \
		g_assert (memcmp (p + 1, expected, expected_len) == 0); \
	} else { \
		g_assert_cmpint (l, ==, expected_len); \
		g_assert (memcmp (p, expected, expected_len) == 0); \
	} \
} G_STMT_END

static void
test_client_id_from_string (void)
{
	const char *nothex = "asdfasdfasdfasdfasdfasdfasdf";
	const char *allhex = "00:11:22:33:4:55:66:77:88";
	const guint8 allhex_bin[] = { 0x00, 0x11, 0x22, 0x33, 0x04, 0x55, 0x66, 0x77, 0x88 };
	const char *somehex = "00:11:22:33:44:55:asdfasdfasdf:99:10";
	const char *nocolons = "0011223344559910";
	const char *endcolon = "00:11:22:33:44:55:";

	COMPARE_ID (nothex, TRUE, nothex, strlen (nothex));
	COMPARE_ID (allhex, FALSE, allhex_bin, sizeof (allhex_bin));
	COMPARE_ID (somehex, TRUE, somehex, strlen (somehex));
	COMPARE_ID (nocolons, TRUE, nocolons, strlen (nocolons));
	COMPARE_ID (endcolon, TRUE, endcolon, strlen (endcolon));
}

NMTST_DEFINE ();

int main (int argc, char **argv)
{
	nmtst_init_assert_logging (&argc, &argv, "WARN", "DEFAULT");

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
	g_test_add_func ("/dhcp/client-id-from-string", test_client_id_from_string);
	g_test_add_func ("/dhcp/vendor-option-metered", test_vendor_option_metered);

	return g_test_run ();
}

