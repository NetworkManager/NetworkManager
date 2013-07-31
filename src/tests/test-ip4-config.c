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

#include "nm-ip4-config.h"

static void
addr_init (NMPlatformIP4Address *a, const char *addr, guint plen)
{
	memset (a, 0, sizeof (*a));
	g_assert (inet_pton (AF_INET, addr, (void *) &a->address) == 1);
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
	config = nm_ip4_config_new ();

	addr_init (&addr, "192.168.1.10", 24);
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

	nm_ip4_config_set_ptp_address (config, addr_to_num ("1.2.3.4"));

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
	const NMPlatformIP4Address *test_addr;
	NMPlatformIP4Route route, *test_route;
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

	src = build_test_config ();

	/* add a couple more things to the test config */
	dst = build_test_config ();
	addr_init (&addr, expected_addr, expected_addr_plen);
	nm_ip4_config_add_address (dst, &addr);
	
	route_new (&route, expected_route_dest, expected_route_plen, expected_route_next_hop);
	nm_ip4_config_add_route (dst, &route);

	nm_ip4_config_add_nameserver (dst, expected_ns1);
	nm_ip4_config_add_nameserver (dst, expected_ns2);
	nm_ip4_config_add_domain (dst, expected_domain);
	nm_ip4_config_add_search (dst, expected_search);

	nm_ip4_config_add_nis_server (dst, expected_nis);
	nm_ip4_config_add_wins (dst, expected_wins);

	nm_ip4_config_subtract (dst, src);

	/* ensure what's left is what we expect */
	g_assert_cmpuint (nm_ip4_config_get_num_addresses (dst), ==, 1);
	test_addr = nm_ip4_config_get_address (dst, 0);
	g_assert (test_addr != NULL);
	g_assert_cmpuint (test_addr->address, ==, addr_to_num (expected_addr));
	g_assert_cmpuint (test_addr->plen, ==, expected_addr_plen);

	g_assert_cmpuint (nm_ip4_config_get_ptp_address (dst), ==, 0);
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

	g_object_unref (src);
	g_object_unref (dst);
}

/*******************************************/

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

	g_type_init ();

	g_test_add_func ("/ip4-config/subtract", test_subtract);

	return g_test_run ();
}

