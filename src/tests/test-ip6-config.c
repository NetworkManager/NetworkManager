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
 * Copyright (C) 2013 Red Hat, Inc.
 *
 */

#include <glib.h>
#include <string.h>
#include <arpa/inet.h>

#include "nm-ip6-config.h"

#include "nm-test-utils.h"

static NMIP6Config *
build_test_config (void)
{
	NMIP6Config *config;

	/* Build up the config to subtract */
	config = nm_ip6_config_new ();

	nm_ip6_config_add_address (config, nmtst_platform_ip6_address ("abcd:1234:4321::cdde", "1:2:3:4::5", 64));
	nm_ip6_config_add_route (config, nmtst_platform_ip6_route ("abcd:1234:4321::", 24, "abcd:1234:4321:cdde::2"));
	nm_ip6_config_add_route (config, nmtst_platform_ip6_route ("2001:abba::", 16, "2001:abba::2234"));

	nm_ip6_config_set_gateway (config, nmtst_inet6_from_string ("3001:abba::3234"));

	nm_ip6_config_add_nameserver (config, nmtst_inet6_from_string ("1:2:3:4::1"));
	nm_ip6_config_add_nameserver (config, nmtst_inet6_from_string ("1:2:3:4::2"));
	nm_ip6_config_add_domain (config, "foobar.com");
	nm_ip6_config_add_domain (config, "baz.com");
	nm_ip6_config_add_search (config, "blahblah.com");
	nm_ip6_config_add_search (config, "beatbox.com");

	return config;
}

static void
test_subtract (void)
{
	NMIP6Config *src, *dst;
	const NMPlatformIP6Address *test_addr;
	const NMPlatformIP6Route *test_route;
	const char *expected_addr = "1122:3344:5566::7788";
	guint32 expected_addr_plen = 96;
	const char *expected_route_dest = "9991:8882:7773::";
	guint32 expected_route_plen = 24;
	const char *expected_route_next_hop = "1119:2228:3337:4446::5555";
	struct in6_addr expected_ns1;
	struct in6_addr expected_ns2;
	const char *expected_domain = "wonderfalls.com";
	const char *expected_search = "somewhere.com";
	struct in6_addr tmp;

	src = build_test_config ();

	/* add a couple more things to the test config */
	dst = build_test_config ();
	nm_ip6_config_add_address (dst, nmtst_platform_ip6_address (expected_addr, NULL, expected_addr_plen));
	nm_ip6_config_add_route (dst, nmtst_platform_ip6_route (expected_route_dest, expected_route_plen, expected_route_next_hop));

	expected_ns1 = *nmtst_inet6_from_string ("2222:3333:4444::5555");
	nm_ip6_config_add_nameserver (dst, &expected_ns1);
	expected_ns2 = *nmtst_inet6_from_string ("2222:3333:4444::5556");
	nm_ip6_config_add_nameserver (dst, &expected_ns2);

	nm_ip6_config_add_domain (dst, expected_domain);
	nm_ip6_config_add_search (dst, expected_search);

	nm_ip6_config_subtract (dst, src);

	/* ensure what's left is what we expect */
	g_assert_cmpuint (nm_ip6_config_get_num_addresses (dst), ==, 1);
	test_addr = nm_ip6_config_get_address (dst, 0);
	g_assert (test_addr != NULL);
	tmp = *nmtst_inet6_from_string (expected_addr);
	g_assert (memcmp (&test_addr->address, &tmp, sizeof (tmp)) == 0);
	g_assert (memcmp (&test_addr->peer_address, &in6addr_any, sizeof (tmp)) == 0);
	g_assert_cmpuint (test_addr->plen, ==, expected_addr_plen);

	g_assert (nm_ip6_config_get_gateway (dst) == NULL);

	g_assert_cmpuint (nm_ip6_config_get_num_routes (dst), ==, 1);
	test_route = nm_ip6_config_get_route (dst, 0);
	g_assert (test_route != NULL);

	tmp = *nmtst_inet6_from_string (expected_route_dest);
	g_assert (memcmp (&test_route->network, &tmp, sizeof (tmp)) == 0);
	g_assert_cmpuint (test_route->plen, ==, expected_route_plen);
	tmp = *nmtst_inet6_from_string  (expected_route_next_hop);
	g_assert (memcmp (&test_route->gateway, &tmp, sizeof (tmp)) == 0);

	g_assert_cmpuint (nm_ip6_config_get_num_nameservers (dst), ==, 2);
	g_assert (memcmp (nm_ip6_config_get_nameserver (dst, 0), &expected_ns1, sizeof (expected_ns1)) == 0);
	g_assert (memcmp (nm_ip6_config_get_nameserver (dst, 1), &expected_ns2, sizeof (expected_ns2)) == 0);

	g_assert_cmpuint (nm_ip6_config_get_num_domains (dst), ==, 1);
	g_assert_cmpstr (nm_ip6_config_get_domain (dst, 0), ==, expected_domain);
	g_assert_cmpuint (nm_ip6_config_get_num_searches (dst), ==, 1);
	g_assert_cmpstr (nm_ip6_config_get_search (dst, 0), ==, expected_search);

	g_object_unref (src);
	g_object_unref (dst);
}

static void
test_compare_with_source (void)
{
	NMIP6Config *a, *b;
	NMPlatformIP6Address addr;
	NMPlatformIP6Route route;

	a = nm_ip6_config_new ();
	b = nm_ip6_config_new ();

	/* Address */
	addr = *nmtst_platform_ip6_address ("1122:3344:5566::7788", NULL, 64);
	addr.source = NM_PLATFORM_SOURCE_USER;
	nm_ip6_config_add_address (a, &addr);

	addr.source = NM_PLATFORM_SOURCE_VPN;
	nm_ip6_config_add_address (b, &addr);

	/* Route */
	route = *nmtst_platform_ip6_route ("abcd:1234:4321::", 24, "abcd:1234:4321:cdde::2");
	route.source = NM_PLATFORM_SOURCE_USER;
	nm_ip6_config_add_route (a, &route);

	route.source = NM_PLATFORM_SOURCE_VPN;
	nm_ip6_config_add_route (b, &route);

	/* Assert that the configs are basically the same, eg that the source is ignored */
	g_assert (nm_ip6_config_equal (a, b));

	g_object_unref (a);
	g_object_unref (b);
}

static void
test_add_address_with_source (void)
{
	NMIP6Config *a;
	NMPlatformIP6Address addr;
	const NMPlatformIP6Address *test_addr;

	a = nm_ip6_config_new ();

	/* Test that a higher priority source is not overwritten */
	addr = *nmtst_platform_ip6_address ("1122:3344:5566::7788", NULL, 64);
	addr.source = NM_PLATFORM_SOURCE_USER;
	nm_ip6_config_add_address (a, &addr);

	test_addr = nm_ip6_config_get_address (a, 0);
	g_assert_cmpint (test_addr->source, ==, NM_PLATFORM_SOURCE_USER);

	addr.source = NM_PLATFORM_SOURCE_VPN;
	nm_ip6_config_add_address (a, &addr);

	test_addr = nm_ip6_config_get_address (a, 0);
	g_assert_cmpint (test_addr->source, ==, NM_PLATFORM_SOURCE_USER);

	/* Test that a lower priority address source is overwritten */
	nm_ip6_config_del_address (a, 0);
	addr.source = NM_PLATFORM_SOURCE_KERNEL;
	nm_ip6_config_add_address (a, &addr);

	test_addr = nm_ip6_config_get_address (a, 0);
	g_assert_cmpint (test_addr->source, ==, NM_PLATFORM_SOURCE_KERNEL);

	addr.source = NM_PLATFORM_SOURCE_USER;
	nm_ip6_config_add_address (a, &addr);

	test_addr = nm_ip6_config_get_address (a, 0);
	g_assert_cmpint (test_addr->source, ==, NM_PLATFORM_SOURCE_USER);

	g_object_unref (a);
}

static void
test_add_route_with_source (void)
{
	NMIP6Config *a;
	NMPlatformIP6Route route;
	const NMPlatformIP6Route *test_route;

	a = nm_ip6_config_new ();

	/* Test that a higher priority source is not overwritten */
	route = *nmtst_platform_ip6_route ("abcd:1234:4321::", 24, "abcd:1234:4321:cdde::2");
	route.source = NM_PLATFORM_SOURCE_USER;
	nm_ip6_config_add_route (a, &route);

	test_route = nm_ip6_config_get_route (a, 0);
	g_assert_cmpint (test_route->source, ==, NM_PLATFORM_SOURCE_USER);

	route.source = NM_PLATFORM_SOURCE_VPN;
	nm_ip6_config_add_route (a, &route);

	test_route = nm_ip6_config_get_route (a, 0);
	g_assert_cmpint (test_route->source, ==, NM_PLATFORM_SOURCE_USER);

	/* Test that a lower priority address source is overwritten */
	nm_ip6_config_del_route (a, 0);
	route.source = NM_PLATFORM_SOURCE_KERNEL;
	nm_ip6_config_add_route (a, &route);

	test_route = nm_ip6_config_get_route (a, 0);
	g_assert_cmpint (test_route->source, ==, NM_PLATFORM_SOURCE_KERNEL);

	route.source = NM_PLATFORM_SOURCE_USER;
	nm_ip6_config_add_route (a, &route);

	test_route = nm_ip6_config_get_route (a, 0);
	g_assert_cmpint (test_route->source, ==, NM_PLATFORM_SOURCE_USER);

	g_object_unref (a);
}

/*******************************************/

NMTST_DEFINE();

int
main (int argc, char **argv)
{
	nmtst_init (&argc, &argv);

	g_test_add_func ("/ip6-config/subtract", test_subtract);
	g_test_add_func ("/ip6-config/compare-with-source", test_compare_with_source);
	g_test_add_func ("/ip6-config/add-address-with-source", test_add_address_with_source);
	g_test_add_func ("/ip6-config/add-route-with-source", test_add_route_with_source);

	return g_test_run ();
}

