/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
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
 * Copyright (C) 2013 - 2014 Red Hat, Inc.
 *
 */

#include "nm-default.h"

#include <arpa/inet.h>

#include "nm-ip4-config.h"
#include "platform/nm-platform.h"

#include "nm-test-utils-core.h"

static NMIP4Config *
build_test_config (void)
{
	NMIP4Config *config;
	NMPlatformIP4Address addr;
	NMPlatformIP4Route route;

	/* Build up the config to subtract */
	config = nmtst_ip4_config_new (1);

	nm_assert (NM_IP_CONFIG_CAST (config));

	addr = *nmtst_platform_ip4_address ("192.168.1.10", "1.2.3.4", 24);
	nm_ip4_config_add_address (config, &addr);

	route = *nmtst_platform_ip4_route ("10.0.0.0", 8, "192.168.1.1");
	nm_ip4_config_add_route (config, &route, NULL);

	route = *nmtst_platform_ip4_route ("172.16.0.0", 16, "192.168.1.1");
	nm_ip4_config_add_route (config, &route, NULL);

	{
		const NMPlatformIP4Route r = {
			.rt_source = NM_IP_CONFIG_SOURCE_DHCP,
			.gateway = nmtst_inet4_from_string ("192.168.1.1"),
			.table_coerced = 0,
			.metric = 100,
		};

		nm_ip4_config_add_route (config, &r, NULL);
	}

	nm_ip4_config_add_nameserver (config, nmtst_inet4_from_string ("4.2.2.1"));
	nm_ip4_config_add_nameserver (config, nmtst_inet4_from_string ("4.2.2.2"));
	nm_ip4_config_add_domain (config, "foobar.com");
	nm_ip4_config_add_domain (config, "baz.com");
	nm_ip4_config_add_search (config, "blahblah.com");
	nm_ip4_config_add_search (config, "beatbox.com");

	nm_ip4_config_add_nis_server (config, nmtst_inet4_from_string ("1.2.3.9"));
	nm_ip4_config_add_nis_server (config, nmtst_inet4_from_string ("1.2.3.10"));

	nm_ip4_config_add_wins (config, nmtst_inet4_from_string ("4.2.3.9"));
	nm_ip4_config_add_wins (config, nmtst_inet4_from_string ("4.2.3.10"));

	return config;
}

static void
test_subtract (void)
{
	NMIP4Config *src, *dst;
	NMPlatformIP4Address addr;
	NMPlatformIP4Route route;
	const NMPlatformIP4Address *test_addr;
	const NMPlatformIP4Route *test_route;
	const char *expected_addr = "192.168.1.12";
	guint32 expected_addr_plen = 24;
	const char *expected_route_dest = "8.0.0.0";
	guint32 expected_route_plen = 8;
	const char *expected_route_next_hop = "192.168.1.1";
	guint32 expected_ns1 = nmtst_inet4_from_string ("8.8.8.8");
	guint32 expected_ns2 = nmtst_inet4_from_string ("8.8.8.9");
	const char *expected_domain = "wonderfalls.com";
	const char *expected_search = "somewhere.com";
	guint32 expected_nis = nmtst_inet4_from_string ("1.2.3.13");
	guint32 expected_wins = nmtst_inet4_from_string ("2.3.4.5");
	guint32 expected_mtu = 1492;

	src = build_test_config ();

	/* add a couple more things to the test config */
	dst = build_test_config ();
	addr = *nmtst_platform_ip4_address (expected_addr, NULL, expected_addr_plen);
	nm_ip4_config_add_address (dst, &addr);

	route = *nmtst_platform_ip4_route (expected_route_dest, expected_route_plen, expected_route_next_hop);
	nm_ip4_config_add_route (dst, &route, NULL);

	nm_ip4_config_add_nameserver (dst, expected_ns1);
	nm_ip4_config_add_nameserver (dst, expected_ns2);
	nm_ip4_config_add_domain (dst, expected_domain);
	nm_ip4_config_add_search (dst, expected_search);

	nm_ip4_config_add_nis_server (dst, expected_nis);
	nm_ip4_config_add_wins (dst, expected_wins);

	nm_ip4_config_set_mtu (dst, expected_mtu, NM_IP_CONFIG_SOURCE_UNKNOWN);

	nm_ip4_config_subtract (dst, src, 0);

	/* ensure what's left is what we expect */
	g_assert_cmpuint (nm_ip4_config_get_num_addresses (dst), ==, 1);
	test_addr = _nmtst_ip4_config_get_address (dst, 0);
	g_assert (test_addr != NULL);
	g_assert_cmpuint (test_addr->address, ==, nmtst_inet4_from_string (expected_addr));
	g_assert_cmpuint (test_addr->peer_address, ==, test_addr->address);
	g_assert_cmpuint (test_addr->plen, ==, expected_addr_plen);

	g_assert (!nm_ip4_config_best_default_route_get (dst));
	g_assert_cmpuint (nmtst_ip4_config_get_gateway (dst), ==, 0);

	g_assert_cmpuint (nm_ip4_config_get_num_routes (dst), ==, 1);
	test_route = _nmtst_ip4_config_get_route (dst, 0);
	g_assert (test_route != NULL);
	g_assert_cmpuint (test_route->network, ==, nmtst_inet4_from_string (expected_route_dest));
	g_assert_cmpuint (test_route->plen, ==, expected_route_plen);
	g_assert_cmpuint (test_route->gateway, ==, nmtst_inet4_from_string (expected_route_next_hop));

	g_assert_cmpuint (nm_ip4_config_get_num_nameservers (dst), ==, 2);
	g_assert_cmpuint (nm_ip4_config_get_nameserver (dst, 0), ==, expected_ns1);
	g_assert_cmpuint (nm_ip4_config_get_nameserver (dst, 1), ==, expected_ns2);

	g_assert_cmpuint (nm_ip4_config_get_num_domains (dst), ==, 1);
	g_assert_cmpstr (nm_ip4_config_get_domain (dst, 0), ==, expected_domain);
	g_assert_cmpuint (nm_ip4_config_get_num_searches (dst), ==, 1);
	g_assert_cmpstr (nm_ip4_config_get_search (dst, 0), ==, expected_search);

	g_assert_cmpuint (nm_ip4_config_get_num_nis_servers (dst), ==, 1);
	g_assert_cmpuint (nm_ip4_config_get_nis_server (dst, 0), ==, expected_nis);

	g_assert_cmpuint (nm_ip4_config_get_num_wins (dst), ==, 1);
	g_assert_cmpuint (nm_ip4_config_get_wins (dst, 0), ==, expected_wins);

	g_assert_cmpuint (nm_ip4_config_get_mtu (dst), ==, expected_mtu);

	g_object_unref (src);
	g_object_unref (dst);
}

static void
test_compare_with_source (void)
{
	NMIP4Config *a, *b;
	NMPlatformIP4Address addr;
	NMPlatformIP4Route route;

	a = nmtst_ip4_config_new (1);
	b = nmtst_ip4_config_new (2);

	/* Address */
	addr = *nmtst_platform_ip4_address ("1.2.3.4", NULL, 24);
	addr.addr_source = NM_IP_CONFIG_SOURCE_USER;
	nm_ip4_config_add_address (a, &addr);

	addr.addr_source = NM_IP_CONFIG_SOURCE_VPN;
	nm_ip4_config_add_address (b, &addr);

	/* Route */
	route = *nmtst_platform_ip4_route ("10.0.0.0", 8, "192.168.1.1");
	route.rt_source = NM_IP_CONFIG_SOURCE_USER;
	nm_ip4_config_add_route (a, &route, NULL);

	route.rt_source = NM_IP_CONFIG_SOURCE_VPN;
	nm_ip4_config_add_route (b, &route, NULL);

	/* Assert that the configs are basically the same, eg that the source is ignored */
	g_assert (nm_ip4_config_equal (a, b));

	g_object_unref (a);
	g_object_unref (b);
}

static void
test_add_address_with_source (void)
{
	NMIP4Config *a;
	NMPlatformIP4Address addr;
	const NMPlatformIP4Address *test_addr;

	a = nmtst_ip4_config_new (1);

	/* Test that a higher priority source is not overwritten */
	addr = *nmtst_platform_ip4_address ("1.2.3.4", NULL, 24);
	addr.addr_source = NM_IP_CONFIG_SOURCE_USER;
	nm_ip4_config_add_address (a, &addr);

	test_addr = _nmtst_ip4_config_get_address (a, 0);
	g_assert_cmpint (test_addr->addr_source, ==, NM_IP_CONFIG_SOURCE_USER);

	addr.addr_source = NM_IP_CONFIG_SOURCE_VPN;
	nm_ip4_config_add_address (a, &addr);

	test_addr = _nmtst_ip4_config_get_address (a, 0);
	g_assert_cmpint (test_addr->addr_source, ==, NM_IP_CONFIG_SOURCE_USER);

	/* Test that a lower priority address source is overwritten */
	_nmtst_ip4_config_del_address (a, 0);
	addr.addr_source = NM_IP_CONFIG_SOURCE_KERNEL;
	nm_ip4_config_add_address (a, &addr);

	test_addr = _nmtst_ip4_config_get_address (a, 0);
	g_assert_cmpint (test_addr->addr_source, ==, NM_IP_CONFIG_SOURCE_KERNEL);

	addr.addr_source = NM_IP_CONFIG_SOURCE_USER;
	nm_ip4_config_add_address (a, &addr);

	test_addr = _nmtst_ip4_config_get_address (a, 0);
	g_assert_cmpint (test_addr->addr_source, ==, NM_IP_CONFIG_SOURCE_USER);

	g_object_unref (a);
}

static void
test_add_route_with_source (void)
{
	gs_unref_object NMIP4Config *a = NULL;
	NMPlatformIP4Route route;
	const NMPlatformIP4Route *test_route;

	a = nmtst_ip4_config_new (1);

	/* Test that a higher priority source is not overwritten */
	route = *nmtst_platform_ip4_route ("1.2.3.0", 24, "1.2.3.1");
	route.rt_source = NM_IP_CONFIG_SOURCE_USER;
	nm_ip4_config_add_route (a, &route, NULL);

	g_assert_cmpint (nm_ip4_config_get_num_routes (a), ==, 1);
	test_route = _nmtst_ip4_config_get_route (a, 0);
	g_assert_cmpint (test_route->rt_source, ==, NM_IP_CONFIG_SOURCE_USER);

	route.rt_source = NM_IP_CONFIG_SOURCE_VPN;
	nm_ip4_config_add_route (a, &route, NULL);

	g_assert_cmpint (nm_ip4_config_get_num_routes (a), ==, 1);
	test_route = _nmtst_ip4_config_get_route (a, 0);
	g_assert_cmpint (test_route->rt_source, ==, NM_IP_CONFIG_SOURCE_USER);

	_nmtst_ip4_config_del_route (a, 0);
	g_assert_cmpint (nm_ip4_config_get_num_routes (a), ==, 0);

	/* Test that a lower priority address source is overwritten */
	route.rt_source = NM_IP_CONFIG_SOURCE_RTPROT_KERNEL;
	nm_ip4_config_add_route (a, &route, NULL);

	g_assert_cmpint (nm_ip4_config_get_num_routes (a), ==, 1);
	test_route = _nmtst_ip4_config_get_route (a, 0);
	g_assert_cmpint (test_route->rt_source, ==, NM_IP_CONFIG_SOURCE_RTPROT_KERNEL);

	route.rt_source = NM_IP_CONFIG_SOURCE_KERNEL;
	nm_ip4_config_add_route (a, &route, NULL);

	g_assert_cmpint (nm_ip4_config_get_num_routes (a), ==, 1);
	test_route = _nmtst_ip4_config_get_route (a, 0);
	g_assert_cmpint (test_route->rt_source, ==, NM_IP_CONFIG_SOURCE_KERNEL);
}

static void
test_merge_subtract_mtu (void)
{
	NMIP4Config *cfg1, *cfg2, *cfg3;
	guint32 expected_mtu2 = 1492;
	guint32 expected_mtu3 = 666;

	cfg1 = build_test_config ();
	cfg2 = build_test_config ();
	cfg3 = build_test_config ();

	/* add MSS, MTU to configs to test them */
	nm_ip4_config_set_mtu (cfg2, expected_mtu2, NM_IP_CONFIG_SOURCE_UNKNOWN);
	nm_ip4_config_set_mtu (cfg3, expected_mtu3, NM_IP_CONFIG_SOURCE_UNKNOWN);

	nm_ip4_config_merge (cfg1, cfg2, NM_IP_CONFIG_MERGE_DEFAULT, 0);
	/* ensure MSS and MTU are in cfg1 */
	g_assert_cmpuint (nm_ip4_config_get_mtu (cfg1), ==, expected_mtu2);

	nm_ip4_config_merge (cfg1, cfg3, NM_IP_CONFIG_MERGE_DEFAULT, 0);
	/* ensure again the MSS and MTU in cfg1 got overridden */
	g_assert_cmpuint (nm_ip4_config_get_mtu (cfg1), ==, expected_mtu3);

	nm_ip4_config_subtract (cfg1, cfg3, 0);
	/* ensure MSS and MTU are zero in cfg1 */
	g_assert_cmpuint (nm_ip4_config_get_mtu (cfg1), ==, 0);

	g_object_unref (cfg1);
	g_object_unref (cfg2);
	g_object_unref (cfg3);
}

static void
test_strip_search_trailing_dot (void)
{
	NMIP4Config *config;

	config = nmtst_ip4_config_new (1);

	nm_ip4_config_add_search (config, ".");
	nm_ip4_config_add_search (config, "foo");
	nm_ip4_config_add_search (config, "bar.");
	nm_ip4_config_add_search (config, "baz.com");
	nm_ip4_config_add_search (config, "baz.com.");
	nm_ip4_config_add_search (config, "foobar..");
	nm_ip4_config_add_search (config, ".foobar");
	nm_ip4_config_add_search (config, "~.");

	g_assert_cmpuint (nm_ip4_config_get_num_searches (config), ==, 4);
	g_assert_cmpstr (nm_ip4_config_get_search (config, 0), ==, "foo");
	g_assert_cmpstr (nm_ip4_config_get_search (config, 1), ==, "bar");
	g_assert_cmpstr (nm_ip4_config_get_search (config, 2), ==, "baz.com");
	g_assert_cmpstr (nm_ip4_config_get_search (config, 3), ==, "~");

	g_object_unref (config);
}

/*****************************************************************************/

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	nmtst_init_with_logging (&argc, &argv, NULL, "DEFAULT");

	g_test_add_func ("/ip4-config/subtract", test_subtract);
	g_test_add_func ("/ip4-config/compare-with-source", test_compare_with_source);
	g_test_add_func ("/ip4-config/add-address-with-source", test_add_address_with_source);
	g_test_add_func ("/ip4-config/add-route-with-source", test_add_route_with_source);
	g_test_add_func ("/ip4-config/merge-subtract-mtu", test_merge_subtract_mtu);
	g_test_add_func ("/ip4-config/strip-search-trailing-dot", test_strip_search_trailing_dot);

	return g_test_run ();
}

