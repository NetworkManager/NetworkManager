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

#include "config.h"

#include <string.h>
#include <arpa/inet.h>

#include "nm-glib.h"
#include "nm-ip4-config.h"
#include "nm-platform.h"
#include "nm-logging.h"

#include "nm-test-utils.h"

static void
addr_init (NMPlatformIP4Address *a, const char *addr, const char *peer, guint plen)
{
	memset (a, 0, sizeof (*a));
	g_assert (inet_pton (AF_INET, addr, (void *) &a->address) == 1);
	if (peer)
		g_assert (inet_pton (AF_INET, peer, (void *) &a->peer_address) == 1);
	a->plen = plen;
}

static void
route_new (NMPlatformIP4Route *route, const char *network, guint plen, const char *gw)
{
	guint n;

	g_assert (route);
	memset (route, 0, sizeof (*route));
	g_assert (inet_pton (AF_INET, network, (void *) &n) == 1);
	route->network = n;
	route->plen = plen;
	if (gw) {
		n = 0;
		g_assert (inet_pton (AF_INET, gw, (void *) &n) == 1);
		route->gateway = n;
	}
}

static guint32
addr_to_num (const char *addr)
{
	guint n;

	g_assert (inet_pton (AF_INET, addr, (void *) &n) == 1);
	return n;
}

static NMIP4Config *
build_test_config (void)
{
	NMIP4Config *config;
	NMPlatformIP4Address addr;
	NMPlatformIP4Route route;

	/* Build up the config to subtract */
	config = nm_ip4_config_new (1);

	addr_init (&addr, "192.168.1.10", "1.2.3.4", 24);
	nm_ip4_config_add_address (config, &addr);
	
	route_new (&route, "10.0.0.0", 8, "192.168.1.1");
	nm_ip4_config_add_route (config, &route);

	route_new (&route, "172.16.0.0", 16, "192.168.1.1");
	nm_ip4_config_add_route (config, &route);

	nm_ip4_config_set_gateway (config, addr_to_num ("192.168.1.1"));

	nm_ip4_config_add_nameserver (config, addr_to_num ("4.2.2.1"));
	nm_ip4_config_add_nameserver (config, addr_to_num ("4.2.2.2"));
	nm_ip4_config_add_domain (config, "foobar.com");
	nm_ip4_config_add_domain (config, "baz.com");
	nm_ip4_config_add_search (config, "blahblah.com");
	nm_ip4_config_add_search (config, "beatbox.com");

	nm_ip4_config_add_nis_server (config, addr_to_num ("1.2.3.9"));
	nm_ip4_config_add_nis_server (config, addr_to_num ("1.2.3.10"));

	nm_ip4_config_add_wins (config, addr_to_num ("4.2.3.9"));
	nm_ip4_config_add_wins (config, addr_to_num ("4.2.3.10"));

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
	const char *expected_route_dest = "8.7.6.5";
	guint32 expected_route_plen = 8;
	const char *expected_route_next_hop = "192.168.1.1";
	guint32 expected_ns1 = addr_to_num ("8.8.8.8");
	guint32 expected_ns2 = addr_to_num ("8.8.8.9");
	const char *expected_domain = "wonderfalls.com";
	const char *expected_search = "somewhere.com";
	guint32 expected_nis = addr_to_num ("1.2.3.13");
	guint32 expected_wins = addr_to_num ("2.3.4.5");
	guint32 expected_mss = 1400;
	guint32 expected_mtu = 1492;

	src = build_test_config ();

	/* add a couple more things to the test config */
	dst = build_test_config ();
	addr_init (&addr, expected_addr, NULL, expected_addr_plen);
	nm_ip4_config_add_address (dst, &addr);
	
	route_new (&route, expected_route_dest, expected_route_plen, expected_route_next_hop);
	nm_ip4_config_add_route (dst, &route);

	nm_ip4_config_add_nameserver (dst, expected_ns1);
	nm_ip4_config_add_nameserver (dst, expected_ns2);
	nm_ip4_config_add_domain (dst, expected_domain);
	nm_ip4_config_add_search (dst, expected_search);

	nm_ip4_config_add_nis_server (dst, expected_nis);
	nm_ip4_config_add_wins (dst, expected_wins);

	nm_ip4_config_set_mss (dst, expected_mss);
	nm_ip4_config_set_mtu (dst, expected_mtu, NM_IP_CONFIG_SOURCE_UNKNOWN);

	nm_ip4_config_subtract (dst, src);

	/* ensure what's left is what we expect */
	g_assert_cmpuint (nm_ip4_config_get_num_addresses (dst), ==, 1);
	test_addr = nm_ip4_config_get_address (dst, 0);
	g_assert (test_addr != NULL);
	g_assert_cmpuint (test_addr->address, ==, addr_to_num (expected_addr));
	g_assert_cmpuint (test_addr->peer_address, ==, 0);
	g_assert_cmpuint (test_addr->plen, ==, expected_addr_plen);

	g_assert_cmpuint (nm_ip4_config_get_gateway (dst), ==, 0);

	g_assert_cmpuint (nm_ip4_config_get_num_routes (dst), ==, 1);
	test_route = nm_ip4_config_get_route (dst, 0);
	g_assert (test_route != NULL);
	g_assert_cmpuint (test_route->network, ==, addr_to_num (expected_route_dest));
	g_assert_cmpuint (test_route->plen, ==, expected_route_plen);
	g_assert_cmpuint (test_route->gateway, ==, addr_to_num (expected_route_next_hop));

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

	g_assert_cmpuint (nm_ip4_config_get_mss (dst), ==, expected_mss);
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

	a = nm_ip4_config_new (1);
	b = nm_ip4_config_new (2);

	/* Address */
	addr_init (&addr, "1.2.3.4", NULL, 24);
	addr.source = NM_IP_CONFIG_SOURCE_USER;
	nm_ip4_config_add_address (a, &addr);

	addr.source = NM_IP_CONFIG_SOURCE_VPN;
	nm_ip4_config_add_address (b, &addr);

	/* Route */
	route_new (&route, "10.0.0.0", 8, "192.168.1.1");
	route.source = NM_IP_CONFIG_SOURCE_USER;
	nm_ip4_config_add_route (a, &route);

	route.source = NM_IP_CONFIG_SOURCE_VPN;
	nm_ip4_config_add_route (b, &route);

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

	a = nm_ip4_config_new (1);

	/* Test that a higher priority source is not overwritten */
	addr_init (&addr, "1.2.3.4", NULL, 24);
	addr.source = NM_IP_CONFIG_SOURCE_USER;
	nm_ip4_config_add_address (a, &addr);

	test_addr = nm_ip4_config_get_address (a, 0);
	g_assert_cmpint (test_addr->source, ==, NM_IP_CONFIG_SOURCE_USER);

	addr.source = NM_IP_CONFIG_SOURCE_VPN;
	nm_ip4_config_add_address (a, &addr);

	test_addr = nm_ip4_config_get_address (a, 0);
	g_assert_cmpint (test_addr->source, ==, NM_IP_CONFIG_SOURCE_USER);

	/* Test that a lower priority address source is overwritten */
	nm_ip4_config_del_address (a, 0);
	addr.source = NM_IP_CONFIG_SOURCE_KERNEL;
	nm_ip4_config_add_address (a, &addr);

	test_addr = nm_ip4_config_get_address (a, 0);
	g_assert_cmpint (test_addr->source, ==, NM_IP_CONFIG_SOURCE_KERNEL);

	addr.source = NM_IP_CONFIG_SOURCE_USER;
	nm_ip4_config_add_address (a, &addr);

	test_addr = nm_ip4_config_get_address (a, 0);
	g_assert_cmpint (test_addr->source, ==, NM_IP_CONFIG_SOURCE_USER);

	g_object_unref (a);
}

static void
test_add_route_with_source (void)
{
	NMIP4Config *a;
	NMPlatformIP4Route route;
	const NMPlatformIP4Route *test_route;

	a = nm_ip4_config_new (1);

	/* Test that a higher priority source is not overwritten */
	route_new (&route, "1.2.3.4", 24, "1.2.3.1");
	route.source = NM_IP_CONFIG_SOURCE_USER;
	nm_ip4_config_add_route (a, &route);

	test_route = nm_ip4_config_get_route (a, 0);
	g_assert_cmpint (test_route->source, ==, NM_IP_CONFIG_SOURCE_USER);

	route.source = NM_IP_CONFIG_SOURCE_VPN;
	nm_ip4_config_add_route (a, &route);

	test_route = nm_ip4_config_get_route (a, 0);
	g_assert_cmpint (test_route->source, ==, NM_IP_CONFIG_SOURCE_USER);

	/* Test that a lower priority address source is overwritten */
	nm_ip4_config_del_route (a, 0);
	route.source = NM_IP_CONFIG_SOURCE_KERNEL;
	nm_ip4_config_add_route (a, &route);

	test_route = nm_ip4_config_get_route (a, 0);
	g_assert_cmpint (test_route->source, ==, NM_IP_CONFIG_SOURCE_KERNEL);

	route.source = NM_IP_CONFIG_SOURCE_USER;
	nm_ip4_config_add_route (a, &route);

	test_route = nm_ip4_config_get_route (a, 0);
	g_assert_cmpint (test_route->source, ==, NM_IP_CONFIG_SOURCE_USER);

	g_object_unref (a);
}

static void
test_merge_subtract_mss_mtu (void)
{
	NMIP4Config *cfg1, *cfg2, *cfg3;
	guint32 expected_mss2 = 1400;
	guint32 expected_mtu2 = 1492;
	guint32 expected_mss3 = 555;
	guint32 expected_mtu3 = 666;

	cfg1 = build_test_config ();
	cfg2 = build_test_config ();
	cfg3 = build_test_config ();

	/* add MSS, MTU to configs to test them */
	nm_ip4_config_set_mss (cfg2, expected_mss2);
	nm_ip4_config_set_mtu (cfg2, expected_mtu2, NM_IP_CONFIG_SOURCE_UNKNOWN);
	nm_ip4_config_set_mss (cfg3, expected_mss3);
	nm_ip4_config_set_mtu (cfg3, expected_mtu3, NM_IP_CONFIG_SOURCE_UNKNOWN);

	nm_ip4_config_merge (cfg1, cfg2);
	/* ensure MSS and MTU are in cfg1 */
	g_assert_cmpuint (nm_ip4_config_get_mss (cfg1), ==, expected_mss2);
	g_assert_cmpuint (nm_ip4_config_get_mtu (cfg1), ==, expected_mtu2);

	nm_ip4_config_merge (cfg1, cfg3);
	/* ensure again the MSS and MTU in cfg1 got overriden */
	g_assert_cmpuint (nm_ip4_config_get_mss (cfg1), ==, expected_mss3);
	g_assert_cmpuint (nm_ip4_config_get_mtu (cfg1), ==, expected_mtu3);

	nm_ip4_config_subtract (cfg1, cfg3);
	/* ensure MSS and MTU are zero in cfg1 */
	g_assert_cmpuint (nm_ip4_config_get_mss (cfg1), ==, 0);
	g_assert_cmpuint (nm_ip4_config_get_mtu (cfg1), ==, 0);

	g_object_unref (cfg1);
	g_object_unref (cfg2);
	g_object_unref (cfg3);
}

/*******************************************/

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	nmtst_init_with_logging (&argc, &argv, NULL, "DEFAULT");

	g_test_add_func ("/ip4-config/subtract", test_subtract);
	g_test_add_func ("/ip4-config/compare-with-source", test_compare_with_source);
	g_test_add_func ("/ip4-config/add-address-with-source", test_add_address_with_source);
	g_test_add_func ("/ip4-config/add-route-with-source", test_add_route_with_source);
	g_test_add_func ("/ip4-config/merge-subtract-mss-mtu", test_merge_subtract_mss_mtu);

	return g_test_run ();
}

