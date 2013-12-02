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

static void
addr_init (NMPlatformIP6Address *a, const char *addr, const char *peer, guint plen)
{
	memset (a, 0, sizeof (*a));
	g_assert (inet_pton (AF_INET6, addr, (void *) &a->address) == 1);
	if (peer)
		g_assert (inet_pton (AF_INET6, peer, (void *) &a->peer_address) == 1);
	a->plen = plen;
}

static void
route_new (NMPlatformIP6Route *route, const char *network, guint plen, const char *gw)
{
	g_assert (route);
	memset (route, 0, sizeof (*route));
	g_assert (inet_pton (AF_INET6, network, (void *) &route->network) == 1);
	route->plen = plen;
	if (gw)
		g_assert (inet_pton (AF_INET6, gw, (void *) &route->gateway) == 1);
}

static void
addr_to_num (const char *addr, struct in6_addr *out_addr)
{
	memset (out_addr, 0, sizeof (*out_addr));
	g_assert (inet_pton (AF_INET6, addr, (void *) out_addr) == 1);
}

static NMIP6Config *
build_test_config (void)
{
	NMIP6Config *config;
	NMPlatformIP6Address addr;
	NMPlatformIP6Route route;
	struct in6_addr tmp;

	/* Build up the config to subtract */
	config = nm_ip6_config_new ();

	addr_init (&addr, "abcd:1234:4321::cdde", "1:2:3:4::5", 64);
	nm_ip6_config_add_address (config, &addr);

	route_new (&route, "abcd:1234:4321::", 24, "abcd:1234:4321:cdde::2");
	nm_ip6_config_add_route (config, &route);

	route_new (&route, "2001:abba::", 16, "2001:abba::2234");
	nm_ip6_config_add_route (config, &route);

	addr_to_num ("3001:abba::3234", &tmp);
	nm_ip6_config_set_gateway (config, &tmp);

	addr_to_num ("1:2:3:4::1", &tmp);
	nm_ip6_config_add_nameserver (config, &tmp);
	addr_to_num ("1:2:3:4::2", &tmp);
	nm_ip6_config_add_nameserver (config, &tmp);
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
	NMPlatformIP6Address addr;
	NMPlatformIP6Route route;
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
	addr_init (&addr, expected_addr, NULL, expected_addr_plen);
	nm_ip6_config_add_address (dst, &addr);

	route_new (&route, expected_route_dest, expected_route_plen, expected_route_next_hop);
	nm_ip6_config_add_route (dst, &route);

	addr_to_num ("2222:3333:4444::5555", &expected_ns1);
	nm_ip6_config_add_nameserver (dst, &expected_ns1);
	addr_to_num ("2222:3333:4444::5556", &expected_ns2);
	nm_ip6_config_add_nameserver (dst, &expected_ns2);

	nm_ip6_config_add_domain (dst, expected_domain);
	nm_ip6_config_add_search (dst, expected_search);

	nm_ip6_config_subtract (dst, src);

	/* ensure what's left is what we expect */
	g_assert_cmpuint (nm_ip6_config_get_num_addresses (dst), ==, 1);
	test_addr = nm_ip6_config_get_address (dst, 0);
	g_assert (test_addr != NULL);
	addr_to_num (expected_addr, &tmp);
	g_assert (memcmp (&test_addr->address, &tmp, sizeof (tmp)) == 0);
	g_assert (memcmp (&test_addr->peer_address, &in6addr_any, sizeof (tmp)) == 0);
	g_assert_cmpuint (test_addr->plen, ==, expected_addr_plen);

	g_assert (nm_ip6_config_get_gateway (dst) == NULL);

	g_assert_cmpuint (nm_ip6_config_get_num_routes (dst), ==, 1);
	test_route = nm_ip6_config_get_route (dst, 0);
	g_assert (test_route != NULL);

	addr_to_num (expected_route_dest, &tmp);
	g_assert (memcmp (&test_route->network, &tmp, sizeof (tmp)) == 0);
	g_assert_cmpuint (test_route->plen, ==, expected_route_plen);
	addr_to_num (expected_route_next_hop, &tmp);
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

/*******************************************/

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

	g_type_init ();

	g_test_add_func ("/ip6-config/subtract", test_subtract);

	return g_test_run ();
}

