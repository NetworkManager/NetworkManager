/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-dhcp-manager.c - Handle the DHCP daemon for NetworkManager
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
 * Copyright (C) 2008 - 2010 Red Hat, Inc.
 *
 */

#include <glib.h>
#include <dbus/dbus-glib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include "nm-test-helpers.h"
#include <nm-utils.h>

#include "nm-dhcp-manager.h"

typedef struct {
	const char *name;
	const char *value;
} Option;

static void
destroy_gvalue (gpointer data)
{
	GValue *value = (GValue *) data;

	g_value_unset (value);
	g_slice_free (GValue, value);
}

static GValue *
string_to_byte_array_gvalue (const char *str)
{
	GByteArray *array;
	GValue *val;

	array = g_byte_array_sized_new (strlen (str));
	g_byte_array_append (array, (const guint8 *) str, strlen (str));

	val = g_slice_new0 (GValue);
	g_value_init (val, DBUS_TYPE_G_UCHAR_ARRAY);
	g_value_take_boxed (val, array);

	return val;
}

static GHashTable *
fill_table (Option *test_options, GHashTable *table)
{
	Option *opt;

	if (!table)
		table = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, destroy_gvalue);
	for (opt = test_options; opt->name; opt++) {
		g_hash_table_insert (table,
		                     (gpointer) opt->name,
		                     string_to_byte_array_gvalue (opt->value));
	}
	return table;
}

static Option generic_options[] = {
	{ "new_subnet_mask",            "255.255.255.0" },
	{ "new_ip_address",             "192.168.1.106" },
	{ "new_network_number",         "192.168.1.0" },
	{ "interface",                  "eth0" },
	{ "reason",                     "BOUND" },
	{ "new_expiry",                 "1232324877" },
	{ "new_dhcp_lease_time",        "3600" },
	{ "new_dhcp_server_identifier", "192.168.1.1" },
	{ "new_routers",                "192.168.1.1" },
	{ "new_domain_name_servers",    "216.254.95.2 216.231.41.2" },
	{ "new_dhcp_message_type",      "5" },
	{ "new_broadcast_address",      "192.168.1.255" },
	{ "new_domain_search",          "foobar.com blah.foobar.com" },
	{ "new_host_name",              "nmreallywhipsthe" },
	{ "new_domain_name",            "lamasass.com" },
	{ "new_interface_mtu",          "987" },
	{ "new_static_routes",          "10.1.1.5 10.1.1.1 100.99.88.56 10.1.1.1" },
	{ NULL, NULL }
};

static void
test_generic_options (const char *client)
{
	GHashTable *options;
	NMIP4Config *ip4_config;
	NMIP4Address *addr;
	NMIP4Route *route;
	struct in_addr tmp;
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
	ip4_config = nm_dhcp_manager_test_ip4_options_to_config (client, "eth0", options, "rebind");
	ASSERT (ip4_config != NULL,
	        "dhcp-generic", "failed to parse DHCP4 options");

	/* IP4 address */
	ASSERT (nm_ip4_config_get_num_addresses (ip4_config) == 1,
	        "dhcp-generic", "unexpected number of IP addresses");
	addr = nm_ip4_config_get_address (ip4_config, 0);

	ASSERT (inet_pton (AF_INET, expected_addr, &tmp) > 0,
	        "dhcp-generic", "couldn't convert expected IP address");
	ASSERT (nm_ip4_address_get_address (addr) == tmp.s_addr,
	        "dhcp-generic", "unexpected IP address");

	ASSERT (nm_ip4_address_get_prefix (addr) == 24,
	        "dhcp-generic", "unexpected IP address prefix length");

	/* Gateway */
	ASSERT (inet_pton (AF_INET, expected_gw, &tmp) > 0,
	        "dhcp-generic", "couldn't convert expected IP gateway");
	ASSERT (nm_ip4_address_get_gateway (addr) == tmp.s_addr,
	        "dhcp-generic", "unexpected IP gateway");

	ASSERT (nm_ip4_config_get_ptp_address (ip4_config) == 0,
	        "dhcp-generic", "unexpected PTP address");

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
	ASSERT (nm_ip4_config_get_nameserver (ip4_config, 0) == tmp.s_addr,
	        "dhcp-generic", "unexpected domain name server #1");
	ASSERT (inet_pton (AF_INET, expected_dns2, &tmp) > 0,
	        "dhcp-generic", "couldn't convert expected DNS server address #2");
	ASSERT (nm_ip4_config_get_nameserver (ip4_config, 1) == tmp.s_addr,
	        "dhcp-generic", "unexpected domain name server #2");

	/* Routes */
	ASSERT (nm_ip4_config_get_num_routes (ip4_config) == 2,
	        "dhcp-generic", "unexpected number of routes");

	/* Route #1 */
	route = nm_ip4_config_get_route (ip4_config, 0);
	ASSERT (inet_pton (AF_INET, expected_route1_dest, &tmp) > 0,
	        "dhcp-generic", "couldn't convert expected route destination #1");
	ASSERT (nm_ip4_route_get_dest (route) == tmp.s_addr,
	        "dhcp-generic", "unexpected route #1 destination");

	ASSERT (inet_pton (AF_INET, expected_route1_gw, &tmp) > 0,
	        "dhcp-generic", "couldn't convert expected route next hop #1");
	ASSERT (nm_ip4_route_get_next_hop (route) == tmp.s_addr,
	        "dhcp-generic", "unexpected route #1 next hop");

	ASSERT (nm_ip4_route_get_prefix (route) == 32,
	        "dhcp-generic", "unexpected route #1 prefix");
	ASSERT (nm_ip4_route_get_metric (route) == 0,
	        "dhcp-generic", "unexpected route #1 metric");

	/* Route #2 */
	route = nm_ip4_config_get_route (ip4_config, 1);
	ASSERT (inet_pton (AF_INET, expected_route2_dest, &tmp) > 0,
	        "dhcp-generic", "couldn't convert expected route destination #2");
	ASSERT (nm_ip4_route_get_dest (route) == tmp.s_addr,
	        "dhcp-generic", "unexpected route #2 destination");

	ASSERT (inet_pton (AF_INET, expected_route2_gw, &tmp) > 0,
	        "dhcp-generic", "couldn't convert expected route next hop #2");
	ASSERT (nm_ip4_route_get_next_hop (route) == tmp.s_addr,
	        "dhcp-generic", "unexpected route #2 next hop");

	ASSERT (nm_ip4_route_get_prefix (route) == 32,
	        "dhcp-generic", "unexpected route #2 prefix");
	ASSERT (nm_ip4_route_get_metric (route) == 0,
	        "dhcp-generic", "unexpected route #2 metric");

	g_hash_table_destroy (options);
}

static Option wins_options[] = {
	{ "new_netbios_name_servers", "63.12.199.5 150.4.88.120" },
	{ NULL, NULL }
};

static void
test_wins_options (const char *client)
{
	GHashTable *options;
	NMIP4Config *ip4_config;
	NMIP4Address *addr;
	struct in_addr tmp;
	const char *expected_wins1 = "63.12.199.5";
	const char *expected_wins2 = "150.4.88.120";

	options = fill_table (generic_options, NULL);
	options = fill_table (wins_options, options);

	ip4_config = nm_dhcp_manager_test_ip4_options_to_config (client, "eth0", options, "rebind");
	ASSERT (ip4_config != NULL,
	        "dhcp-wins", "failed to parse DHCP4 options");

	/* IP4 address */
	ASSERT (nm_ip4_config_get_num_addresses (ip4_config) == 1,
	        "dhcp-wins", "unexpected number of IP addresses");
	addr = nm_ip4_config_get_address (ip4_config, 0);

	ASSERT (nm_ip4_config_get_num_wins (ip4_config) == 2,
	        "dhcp-wins", "unexpected number of WINS servers");
	ASSERT (inet_pton (AF_INET, expected_wins1, &tmp) > 0,
	        "dhcp-wins", "couldn't convert expected WINS server address #1");
	ASSERT (nm_ip4_config_get_wins (ip4_config, 0) == tmp.s_addr,
	        "dhcp-wins", "unexpected WINS server #1");
	ASSERT (inet_pton (AF_INET, expected_wins2, &tmp) > 0,
	        "dhcp-wins", "couldn't convert expected WINS server address #1");
	ASSERT (nm_ip4_config_get_wins (ip4_config, 1) == tmp.s_addr,
	        "dhcp-wins", "unexpected WINS server #1");

	g_hash_table_destroy (options);
}

static Option classless_routes_options[] = {
	/* For dhclient */
	{ "new_rfc3442_classless_static_routes", "24 192 168 10 192 168 1 1 8 10 10 17 66 41" },
	/* For dhcpcd */
	{ "new_classless_static_routes", "192.168.10.0/24 192.168.1.1 10.0.0.0/8 10.17.66.41" },
	{ NULL, NULL }
};

static void
test_classless_static_routes (const char *client)
{
	GHashTable *options;
	NMIP4Config *ip4_config;
	NMIP4Route *route;
	struct in_addr tmp;
	const char *expected_route1_dest = "192.168.10.0";
	const char *expected_route1_gw = "192.168.1.1";
	const char *expected_route2_dest = "10.0.0.0";
	const char *expected_route2_gw = "10.17.66.41";

	options = fill_table (generic_options, NULL);
	options = fill_table (classless_routes_options, options);

	ip4_config = nm_dhcp_manager_test_ip4_options_to_config (client, "eth0", options, "rebind");
	ASSERT (ip4_config != NULL,
	        "dhcp-rfc3442", "failed to parse DHCP4 options");

	/* IP4 routes */
	ASSERT (nm_ip4_config_get_num_routes (ip4_config) == 2,
	        "dhcp-rfc3442", "unexpected number of IP routes");

	/* Route #1 */
	route = nm_ip4_config_get_route (ip4_config, 0);
	ASSERT (inet_pton (AF_INET, expected_route1_dest, &tmp) > 0,
	        "dhcp-rfc3442", "couldn't convert expected route destination #1");
	ASSERT (nm_ip4_route_get_dest (route) == tmp.s_addr,
	        "dhcp-rfc3442", "unexpected route #1 destination");

	ASSERT (inet_pton (AF_INET, expected_route1_gw, &tmp) > 0,
	        "dhcp-rfc3442", "couldn't convert expected route next hop #1");
	ASSERT (nm_ip4_route_get_next_hop (route) == tmp.s_addr,
	        "dhcp-rfc3442", "unexpected route #1 next hop");

	ASSERT (nm_ip4_route_get_prefix (route) == 24,
	        "dhcp-rfc3442", "unexpected route #1 prefix");
	ASSERT (nm_ip4_route_get_metric (route) == 0,
	        "dhcp-rfc3442", "unexpected route #1 metric");

	/* Route #2 */
	route = nm_ip4_config_get_route (ip4_config, 1);
	ASSERT (inet_pton (AF_INET, expected_route2_dest, &tmp) > 0,
	        "dhcp-rfc3442", "couldn't convert expected route destination #2");
	ASSERT (nm_ip4_route_get_dest (route) == tmp.s_addr,
	        "dhcp-rfc3442", "unexpected route #2 destination");

	ASSERT (inet_pton (AF_INET, expected_route2_gw, &tmp) > 0,
	        "dhcp-rfc3442", "couldn't convert expected route next hop #2");
	ASSERT (nm_ip4_route_get_next_hop (route) == tmp.s_addr,
	        "dhcp-rfc3442", "unexpected route #2 next hop");

	ASSERT (nm_ip4_route_get_prefix (route) == 8,
	        "dhcp-rfc3442", "unexpected route #2 prefix");
	ASSERT (nm_ip4_route_get_metric (route) == 0,
	        "dhcp-rfc3442", "unexpected route #2 metric");

	g_hash_table_destroy (options);
}

static Option invalid_classless_routes1[] = {
	/* For dhclient */
	{ "new_rfc3442_classless_static_routes", "24 192 168 10 192 168 1 1 45 10 17 66 41" },
	/* For dhcpcd */
	{ "new_classless_static_routes", "192.168.10.0/24 192.168.1.1 10.0.adfadf/44 10.17.66.41" },
	{ NULL, NULL }
};

static void
test_invalid_classless_routes1 (const char *client)
{
	GHashTable *options;
	NMIP4Config *ip4_config;
	NMIP4Route *route;
	struct in_addr tmp;
	const char *expected_route1_dest = "192.168.10.0";
	const char *expected_route1_gw = "192.168.1.1";

	options = fill_table (generic_options, NULL);
	options = fill_table (invalid_classless_routes1, options);

	ip4_config = nm_dhcp_manager_test_ip4_options_to_config (client, "eth0", options, "rebind");
	ASSERT (ip4_config != NULL,
	        "dhcp-rfc3442-invalid-1", "failed to parse DHCP4 options");

	/* IP4 routes */
	ASSERT (nm_ip4_config_get_num_routes (ip4_config) == 1,
	        "dhcp-rfc3442-invalid-1", "unexpected number of IP routes");

	/* Route #1 */
	route = nm_ip4_config_get_route (ip4_config, 0);
	ASSERT (inet_pton (AF_INET, expected_route1_dest, &tmp) > 0,
	        "dhcp-rfc3442-invalid-1", "couldn't convert expected route destination #1");
	ASSERT (nm_ip4_route_get_dest (route) == tmp.s_addr,
	        "dhcp-rfc3442-invalid-1", "unexpected route #1 destination");

	ASSERT (inet_pton (AF_INET, expected_route1_gw, &tmp) > 0,
	        "dhcp-rfc3442-invalid-1", "couldn't convert expected route next hop #1");
	ASSERT (nm_ip4_route_get_next_hop (route) == tmp.s_addr,
	        "dhcp-rfc3442-invalid-1", "unexpected route #1 next hop");

	ASSERT (nm_ip4_route_get_prefix (route) == 24,
	        "dhcp-rfc3442-invalid-1", "unexpected route #1 prefix");
	ASSERT (nm_ip4_route_get_metric (route) == 0,
	        "dhcp-rfc3442-invalid-1", "unexpected route #1 metric");

	g_hash_table_destroy (options);
}

static Option invalid_classless_routes2[] = {
	/* For dhclient */
	{ "new_rfc3442_classless_static_routes", "45 10 17 66 41 24 192 168 10 192 168 1 1" },
	/* For dhcpcd */
	{ "new_classless_static_routes", "10.0.adfadf/44 10.17.66.41 192.168.10.0/24 192.168.1.1" },
	{ NULL, NULL }
};

static void
test_invalid_classless_routes2 (const char *client)
{
	GHashTable *options;
	NMIP4Config *ip4_config;
	NMIP4Route *route;
	struct in_addr tmp;
	const char *expected_route1_dest = "10.1.1.5";
	const char *expected_route1_gw = "10.1.1.1";
	const char *expected_route2_dest = "100.99.88.56";
	const char *expected_route2_gw = "10.1.1.1";

	options = fill_table (generic_options, NULL);
	options = fill_table (invalid_classless_routes2, options);

	ip4_config = nm_dhcp_manager_test_ip4_options_to_config (client, "eth0", options, "rebind");
	ASSERT (ip4_config != NULL,
	        "dhcp-rfc3442-invalid-2", "failed to parse DHCP4 options");

	/* Test falling back to old-style static routes if the classless static
	 * routes are invalid.
	 */

	/* Routes */
	ASSERT (nm_ip4_config_get_num_routes (ip4_config) == 2,
	        "dhcp-rfc3442-invalid-2", "unexpected number of routes");

	/* Route #1 */
	route = nm_ip4_config_get_route (ip4_config, 0);
	ASSERT (inet_pton (AF_INET, expected_route1_dest, &tmp) > 0,
	        "dhcp-rfc3442-invalid-2", "couldn't convert expected route destination #1");
	ASSERT (nm_ip4_route_get_dest (route) == tmp.s_addr,
	        "dhcp-rfc3442-invalid-2", "unexpected route #1 destination");

	ASSERT (inet_pton (AF_INET, expected_route1_gw, &tmp) > 0,
	        "dhcp-rfc3442-invalid-2", "couldn't convert expected route next hop #1");
	ASSERT (nm_ip4_route_get_next_hop (route) == tmp.s_addr,
	        "dhcp-rfc3442-invalid-2", "unexpected route #1 next hop");

	ASSERT (nm_ip4_route_get_prefix (route) == 32,
	        "dhcp-rfc3442-invalid-2", "unexpected route #1 prefix");
	ASSERT (nm_ip4_route_get_metric (route) == 0,
	        "dhcp-rfc3442-invalid-2", "unexpected route #1 metric");

	/* Route #2 */
	route = nm_ip4_config_get_route (ip4_config, 1);
	ASSERT (inet_pton (AF_INET, expected_route2_dest, &tmp) > 0,
	        "dhcp-rfc3442-invalid-2", "couldn't convert expected route destination #2");
	ASSERT (nm_ip4_route_get_dest (route) == tmp.s_addr,
	        "dhcp-rfc3442-invalid-2", "unexpected route #2 destination");

	ASSERT (inet_pton (AF_INET, expected_route2_gw, &tmp) > 0,
	        "dhcp-rfc3442-invalid-2", "couldn't convert expected route next hop #2");
	ASSERT (nm_ip4_route_get_next_hop (route) == tmp.s_addr,
	        "dhcp-rfc3442-invalid-2", "unexpected route #2 next hop");

	ASSERT (nm_ip4_route_get_prefix (route) == 32,
	        "dhcp-rfc3442-invalid-2", "unexpected route #2 prefix");
	ASSERT (nm_ip4_route_get_metric (route) == 0,
	        "dhcp-rfc3442-invalid-2", "unexpected route #2 metric");

	g_hash_table_destroy (options);
}

static Option invalid_classless_routes3[] = {
	/* For dhclient */
	{ "new_rfc3442_classless_static_routes", "24 192 168 10 192 168 1 1 32 128 10 17 66 41" },
	/* For dhcpcd */
	{ "new_classless_static_routes", "192.168.10.0/24 192.168.1.1 128/32 10.17.66.41" },
	{ NULL, NULL }
};

static void
test_invalid_classless_routes3 (const char *client)
{
	GHashTable *options;
	NMIP4Config *ip4_config;
	NMIP4Route *route;
	struct in_addr tmp;
	const char *expected_route1_dest = "192.168.10.0";
	const char *expected_route1_gw = "192.168.1.1";

	options = fill_table (generic_options, NULL);
	options = fill_table (invalid_classless_routes3, options);

	ip4_config = nm_dhcp_manager_test_ip4_options_to_config (client, "eth0", options, "rebind");
	ASSERT (ip4_config != NULL,
	        "dhcp-rfc3442-invalid-3", "failed to parse DHCP4 options");

	/* IP4 routes */
	ASSERT (nm_ip4_config_get_num_routes (ip4_config) == 1,
	        "dhcp-rfc3442-invalid-3", "unexpected number of IP routes");

	/* Route #1 */
	route = nm_ip4_config_get_route (ip4_config, 0);
	ASSERT (inet_pton (AF_INET, expected_route1_dest, &tmp) > 0,
	        "dhcp-rfc3442-invalid-3", "couldn't convert expected route destination #1");
	ASSERT (nm_ip4_route_get_dest (route) == tmp.s_addr,
	        "dhcp-rfc3442-invalid-3", "unexpected route #1 destination");

	ASSERT (inet_pton (AF_INET, expected_route1_gw, &tmp) > 0,
	        "dhcp-rfc3442-invalid-3", "couldn't convert expected route next hop #1");
	ASSERT (nm_ip4_route_get_next_hop (route) == tmp.s_addr,
	        "dhcp-rfc3442-invalid-3", "unexpected route #1 next hop");

	ASSERT (nm_ip4_route_get_prefix (route) == 24,
	        "dhcp-rfc3442-invalid-3", "unexpected route #1 prefix");
	ASSERT (nm_ip4_route_get_metric (route) == 0,
	        "dhcp-rfc3442-invalid-3", "unexpected route #1 metric");

	g_hash_table_destroy (options);
}

static Option gw_in_classless_routes[] = {
	/* For dhclient */
	{ "new_rfc3442_classless_static_routes", "24 192 168 10 192 168 1 1 0 192 2 3 4" },
	/* For dhcpcd */
	{ "new_classless_static_routes", "192.168.10.0/24 192.168.1.1 0.0.0.0/0 192.2.3.4" },
	{ NULL, NULL }
};

static void
test_gateway_in_classless_routes (const char *client)
{
	GHashTable *options;
	NMIP4Config *ip4_config;
	NMIP4Address *addr;
	NMIP4Route *route;
	struct in_addr tmp;
	const char *expected_route1_dest = "192.168.10.0";
	const char *expected_route1_gw = "192.168.1.1";
	const char *expected_gateway = "192.2.3.4";

	options = fill_table (generic_options, NULL);
	options = fill_table (gw_in_classless_routes, options);

	ip4_config = nm_dhcp_manager_test_ip4_options_to_config (client, "eth0", options, "rebind");
	ASSERT (ip4_config != NULL,
	        "dhcp-rfc3442-gateway", "failed to parse DHCP4 options");

	/* IP4 routes */
	ASSERT (nm_ip4_config_get_num_routes (ip4_config) == 1,
	        "dhcp-rfc3442-gateway", "unexpected number of IP routes");

	/* Route #1 */
	route = nm_ip4_config_get_route (ip4_config, 0);
	ASSERT (inet_pton (AF_INET, expected_route1_dest, &tmp) > 0,
	        "dhcp-rfc3442-gateway", "couldn't convert expected route destination #1");
	ASSERT (nm_ip4_route_get_dest (route) == tmp.s_addr,
	        "dhcp-rfc3442-gateway", "unexpected route #1 destination");

	ASSERT (inet_pton (AF_INET, expected_route1_gw, &tmp) > 0,
	        "dhcp-rfc3442-gateway", "couldn't convert expected route next hop #1");
	ASSERT (nm_ip4_route_get_next_hop (route) == tmp.s_addr,
	        "dhcp-rfc3442-gateway", "unexpected route #1 next hop");

	ASSERT (nm_ip4_route_get_prefix (route) == 24,
	        "dhcp-rfc3442-gateway", "unexpected route #1 prefix");
	ASSERT (nm_ip4_route_get_metric (route) == 0,
	        "dhcp-rfc3442-gateway", "unexpected route #1 metric");

	/* Address */
	ASSERT (nm_ip4_config_get_num_addresses (ip4_config) == 1,
	        "dhcp-rfc3442-gateway", "unexpected number of IP addresses");
	addr = nm_ip4_config_get_address (ip4_config, 0);
	ASSERT (inet_pton (AF_INET, expected_gateway, &tmp) > 0,
	        "dhcp-rfc3442-gateway", "couldn't convert expected IP gateway");
	ASSERT (nm_ip4_address_get_gateway (addr) == tmp.s_addr,
	        "dhcp-rfc3442-gateway", "unexpected IP gateway");

	g_hash_table_destroy (options);
}

static Option escaped_searches_options[] = {
	{ "new_domain_search", "host1\\032host2\\032host3" },
	{ NULL, NULL }
};

static void
test_escaped_domain_searches (const char *client)
{
	GHashTable *options;
	NMIP4Config *ip4_config;
	const char *expected_search0 = "host1";
	const char *expected_search1 = "host2";
	const char *expected_search2 = "host3";

	options = fill_table (generic_options, NULL);
	options = fill_table (escaped_searches_options, options);

	ip4_config = nm_dhcp_manager_test_ip4_options_to_config (client, "eth0", options, "rebind");
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
	{ "new_domain_search", "host1\\aahost2\\032host3" },
	{ NULL, NULL }
};

static void
test_invalid_escaped_domain_searches (const char *client)
{
	GHashTable *options;
	NMIP4Config *ip4_config;

	options = fill_table (generic_options, NULL);
	options = fill_table (invalid_escaped_searches_options, options);

	ip4_config = nm_dhcp_manager_test_ip4_options_to_config (client, "eth0", options, "rebind");
	ASSERT (ip4_config != NULL,
	        "dhcp-invalid-escaped-domain-searches", "failed to parse DHCP4 options");

	/* domain searches */
	ASSERT (nm_ip4_config_get_num_searches (ip4_config) == 0,
	        "dhcp-invalid-escaped-domain-searches", "unexpected domain searches");

	g_hash_table_destroy (options);
}

static void
test_ip4_missing_prefix (const char *client, const char *ip, guint32 expected_prefix)
{
	GHashTable *options;
	NMIP4Config *ip4_config;
	NMIP4Address *addr;

	options = fill_table (generic_options, NULL);
	g_hash_table_insert (options, "new_ip_address", string_to_byte_array_gvalue (ip));
	g_hash_table_remove (options, "new_subnet_mask");

	ip4_config = nm_dhcp_manager_test_ip4_options_to_config (client, "eth0", options, "rebind");
	ASSERT (ip4_config != NULL,
	        "dhcp-ip4-missing-prefix", "failed to parse DHCP4 options");

	ASSERT (nm_ip4_config_get_num_addresses (ip4_config) == 1,
	        "dhcp-ip4-missing-prefix", "unexpected number of IP4 addresses (not 1)");

	addr = nm_ip4_config_get_address (ip4_config, 0);
	ASSERT (addr != NULL,
	        "dhcp-ip4-missing-prefix", "missing IP4 address #1");

	ASSERT (nm_ip4_address_get_prefix (addr) == expected_prefix,
	        "dhcp-ip4-missing-prefix", "unexpected IP4 address prefix %d (expected %d)",
	        nm_ip4_address_get_prefix (addr), expected_prefix);

	g_hash_table_destroy (options);
}

static void
test_ip4_prefix_classless (const char *client)
{
	GHashTable *options;
	NMIP4Config *ip4_config;
	NMIP4Address *addr;

	/* Ensure that the missing-subnet-mask handler doesn't mangle classless
	 * subnet masks at all.  The handler should trigger only if the server
	 * doesn't send the subnet mask.
	 */

	options = fill_table (generic_options, NULL);
	g_hash_table_insert (options, "new_ip_address", string_to_byte_array_gvalue ("172.16.54.22"));
	g_hash_table_insert (options, "new_subnet_mask", string_to_byte_array_gvalue ("255.255.252.0"));

	ip4_config = nm_dhcp_manager_test_ip4_options_to_config (client, "eth0", options, "rebind");
	ASSERT (ip4_config != NULL,
	        "dhcp-ip4-prefix-classless", "failed to parse DHCP4 options");

	ASSERT (nm_ip4_config_get_num_addresses (ip4_config) == 1,
	        "dhcp-ip4-prefix-classless", "unexpected number of IP4 addresses (not 1)");

	addr = nm_ip4_config_get_address (ip4_config, 0);
	ASSERT (addr != NULL,
	        "dhcp-ip4-prefix-classless", "missing IP4 address #1");

	ASSERT (nm_ip4_address_get_prefix (addr) == 22,
	        "dhcp-ip4-prefix-classless", "unexpected IP4 address prefix %d (expected 22)",
	        nm_ip4_address_get_prefix (addr));

	g_hash_table_destroy (options);
}

int main (int argc, char **argv)
{
	GError *error = NULL;
	DBusGConnection *bus;
	char *base;
	const char *clients[2][2] = { {DHCLIENT_PATH, "dhclient"}, {DHCPCD_PATH, "dhcpcd"} };
	guint32 i;

	g_type_init ();
	bus = dbus_g_bus_get (DBUS_BUS_SESSION, NULL);

	if (!nm_utils_init (&error))
		FAIL ("nm-utils-init", "failed to initialize libnm-util: %s", error->message);

	/* The tests */
	for (i = 0; i < 2; i++) {
		const char *client_path = clients[i][0];
		const char *client = clients[i][1];

		if (!client_path || !strlen (client_path))
			continue;

		test_generic_options (client);
		test_wins_options (client);
		test_classless_static_routes (client);
		test_invalid_classless_routes1 (client);
		test_invalid_classless_routes2 (client);
		test_invalid_classless_routes3 (client);
		test_gateway_in_classless_routes (client);
		test_escaped_domain_searches (client);
		test_invalid_escaped_domain_searches (client);
		test_ip4_missing_prefix (client, "192.168.1.10", 24);
		test_ip4_missing_prefix (client, "172.16.54.50", 16);
		test_ip4_missing_prefix (client, "10.1.2.3", 8);
		test_ip4_prefix_classless (client);
	}

	base = g_path_get_basename (argv[0]);
	fprintf (stdout, "%s: SUCCESS\n", base);
	g_free (base);
	return 0;
}

