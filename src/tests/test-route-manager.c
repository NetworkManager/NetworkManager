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
 * Copyright (C) 2015 Red Hat, Inc.
 *
 */

#include "nm-default.h"

#include <arpa/inet.h>
#include <linux/rtnetlink.h>

#include "test-common.h"

#include "nm-platform.h"
#include "nm-route-manager.h"

#include "nm-test-utils.h"

typedef struct {
	int ifindex0, ifindex1;
} test_fixture;

/*****************************************************************************/

static void
setup_dev0_ip4 (int ifindex, guint mss_of_first_route, guint32 metric_of_second_route)
{
	GArray *routes = g_array_new (FALSE, FALSE, sizeof (NMPlatformIP4Route));
	NMPlatformIP4Route route = { 0 };

	route.ifindex = ifindex;
	route.mss = 0;

	route.source = NM_IP_CONFIG_SOURCE_USER;
	inet_pton (AF_INET, "6.6.6.0", &route.network);
	route.plen = 24;
	route.gateway = INADDR_ANY;
	route.metric = 20;
	route.mss = mss_of_first_route;
	g_array_append_val (routes, route);

	route.source = NM_IP_CONFIG_SOURCE_USER;
	inet_pton (AF_INET, "7.0.0.0", &route.network);
	route.plen = 8;
	inet_pton (AF_INET, "6.6.6.1", &route.gateway);
	route.metric = metric_of_second_route;
	route.mss = 0;
	g_array_append_val (routes, route);

	nm_route_manager_ip4_route_sync (nm_route_manager_get (), ifindex, routes, TRUE, TRUE);
	g_array_free (routes, TRUE);
}

static void
setup_dev1_ip4 (int ifindex)
{
	GArray *routes = g_array_new (FALSE, FALSE, sizeof (NMPlatformIP4Route));
	NMPlatformIP4Route route = { 0 };

	route.ifindex = ifindex;
	route.mss = 0;

	/* Add some route outside of route manager. The route manager
	 * should get rid of it upon sync. */
	if (!nm_platform_ip4_route_add (NM_PLATFORM_GET,
	                                route.ifindex,
	                                NM_IP_CONFIG_SOURCE_USER,
	                                nmtst_inet4_from_string ("9.0.0.0"),
	                                8,
	                                INADDR_ANY,
	                                0,
	                                10,
	                                route.mss))
		g_assert_not_reached ();

	route.source = NM_IP_CONFIG_SOURCE_USER;
	inet_pton (AF_INET, "6.6.6.0", &route.network);
	route.plen = 24;
	route.gateway = INADDR_ANY;
	route.metric = 20;
	g_array_append_val (routes, route);

	route.source = NM_IP_CONFIG_SOURCE_USER;
	inet_pton (AF_INET, "7.0.0.0", &route.network);
	route.plen = 8;
	route.gateway = INADDR_ANY;
	route.metric = 22;
	g_array_append_val (routes, route);

	route.source = NM_IP_CONFIG_SOURCE_USER;
	inet_pton (AF_INET, "8.0.0.0", &route.network);
	route.plen = 8;
	inet_pton (AF_INET, "6.6.6.2", &route.gateway);
	route.metric = 22;
	g_array_append_val (routes, route);

	nm_route_manager_ip4_route_sync (nm_route_manager_get (), ifindex, routes, TRUE, TRUE);
	g_array_free (routes, TRUE);
}

static void
update_dev0_ip4 (int ifindex)
{
	GArray *routes = g_array_new (FALSE, FALSE, sizeof (NMPlatformIP4Route));
	NMPlatformIP4Route route = { 0 };

	route.ifindex = ifindex;
	route.mss = 0;

	route.source = NM_IP_CONFIG_SOURCE_USER;
	inet_pton (AF_INET, "6.6.6.0", &route.network);
	route.plen = 24;
	route.gateway = INADDR_ANY;
	route.metric = 20;
	g_array_append_val (routes, route);

	route.source = NM_IP_CONFIG_SOURCE_USER;
	inet_pton (AF_INET, "7.0.0.0", &route.network);
	route.plen = 8;
	route.gateway = INADDR_ANY;
	route.metric = 21;
	g_array_append_val (routes, route);

	nm_route_manager_ip4_route_sync (nm_route_manager_get (), ifindex, routes, TRUE, TRUE);
	g_array_free (routes, TRUE);
}


static GArray *
ip4_routes (test_fixture *fixture)
{
	GArray *routes = nm_platform_ip4_route_get_all (NM_PLATFORM_GET,
	                                                fixture->ifindex0,
	                                                NM_PLATFORM_GET_ROUTE_FLAGS_WITH_NON_DEFAULT);
	GArray *routes1 = nm_platform_ip4_route_get_all (NM_PLATFORM_GET,
	                                                 fixture->ifindex1,
	                                                 NM_PLATFORM_GET_ROUTE_FLAGS_WITH_NON_DEFAULT);

	g_array_append_vals (routes, routes1->data, routes1->len);
	g_array_free (routes1, TRUE);

	return routes;
}

static void
test_ip4 (test_fixture *fixture, gconstpointer user_data)
{
	GArray *routes;

	NMPlatformIP4Route state1[] = {
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = nmtst_inet4_from_string ("6.6.6.0"),
			.plen = 24,
			.ifindex = fixture->ifindex0,
			.gateway = INADDR_ANY,
			.metric = 20,
			.mss = 1000,
			.scope_inv = nm_platform_route_scope_inv (RT_SCOPE_LINK),
		},
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = nmtst_inet4_from_string ("7.0.0.0"),
			.plen = 8,
			.ifindex = fixture->ifindex0,
			.gateway = nmtst_inet4_from_string ("6.6.6.1"),
			.metric = 21021,
			.mss = 0,
			.scope_inv = nm_platform_route_scope_inv (RT_SCOPE_UNIVERSE),
		},
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = nmtst_inet4_from_string ("7.0.0.0"),
			.plen = 8,
			.ifindex = fixture->ifindex1,
			.gateway = INADDR_ANY,
			.metric = 22,
			.mss = 0,
			.scope_inv = nm_platform_route_scope_inv (RT_SCOPE_LINK),
		},
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = nmtst_inet4_from_string ("6.6.6.0"),
			.plen = 24,
			.ifindex = fixture->ifindex1,
			.gateway = INADDR_ANY,
			.metric = 21,
			.mss = 0,
			.scope_inv = nm_platform_route_scope_inv (RT_SCOPE_LINK),
		},
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = nmtst_inet4_from_string ("8.0.0.0"),
			.plen = 8,
			.ifindex = fixture->ifindex1,
			.gateway = nmtst_inet4_from_string ("6.6.6.2"),
			.metric = 22,
			.mss = 0,
			.scope_inv = nm_platform_route_scope_inv (RT_SCOPE_UNIVERSE),
		},
	};

	NMPlatformIP4Route state2[] = {
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = nmtst_inet4_from_string ("6.6.6.0"),
			.plen = 24,
			.ifindex = fixture->ifindex0,
			.gateway = INADDR_ANY,
			.metric = 20,
			.mss = 0,
			.scope_inv = nm_platform_route_scope_inv (RT_SCOPE_LINK),
		},
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = nmtst_inet4_from_string ("7.0.0.0"),
			.plen = 8,
			.ifindex = fixture->ifindex0,
			.gateway = INADDR_ANY,
			.metric = 21,
			.mss = 0,
			.scope_inv = nm_platform_route_scope_inv (RT_SCOPE_LINK),
		},
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = nmtst_inet4_from_string ("7.0.0.0"),
			.plen = 8,
			.ifindex = fixture->ifindex1,
			.gateway = INADDR_ANY,
			.metric = 22,
			.mss = 0,
			.scope_inv = nm_platform_route_scope_inv (RT_SCOPE_LINK),
		},
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = nmtst_inet4_from_string ("6.6.6.0"),
			.plen = 24,
			.ifindex = fixture->ifindex1,
			.gateway = INADDR_ANY,
			.metric = 21,
			.mss = 0,
			.scope_inv = nm_platform_route_scope_inv (RT_SCOPE_LINK),
		},
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = nmtst_inet4_from_string ("8.0.0.0"),
			.plen = 8,
			.ifindex = fixture->ifindex1,
			.gateway = nmtst_inet4_from_string ("6.6.6.2"),
			.metric = 22,
			.mss = 0,
			.scope_inv = nm_platform_route_scope_inv (RT_SCOPE_UNIVERSE),
		},
	};

	NMPlatformIP4Route state3[] = {
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = nmtst_inet4_from_string ("7.0.0.0"),
			.plen = 8,
			.ifindex = fixture->ifindex1,
			.gateway = INADDR_ANY,
			.metric = 22,
			.mss = 0,
			.scope_inv = nm_platform_route_scope_inv (RT_SCOPE_LINK),
		},
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = nmtst_inet4_from_string ("6.6.6.0"),
			.plen = 24,
			.ifindex = fixture->ifindex1,
			.gateway = INADDR_ANY,
			.metric = 20,
			.mss = 0,
			.scope_inv = nm_platform_route_scope_inv (RT_SCOPE_LINK),
		},
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = nmtst_inet4_from_string ("8.0.0.0"),
			.plen = 8,
			.ifindex = fixture->ifindex1,
			.gateway = nmtst_inet4_from_string ("6.6.6.2"),
			.metric = 22,
			.mss = 0,
			.scope_inv = nm_platform_route_scope_inv (RT_SCOPE_UNIVERSE),
		},
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = nmtst_inet4_from_string ("6.6.6.0"),
			.plen = 24,
			.ifindex = fixture->ifindex1,
			.gateway = INADDR_ANY,
			/* this is a ghost entry because we synced ifindex0 and restore the route
			 * with metric 20 (above). But we don't remove the metric 21. */
			.metric = 21,
			.mss = 0,
			.scope_inv = nm_platform_route_scope_inv (RT_SCOPE_LINK),
		},
	};

	setup_dev0_ip4 (fixture->ifindex0, 1000, 21021);
	setup_dev1_ip4 (fixture->ifindex1);
	g_test_assert_expected_messages ();

	/* - 6.6.6.0/24 on dev0 won over 6.6.6.0/24 on dev1
	 * - 6.6.6.0/24 on dev1 has metric bumped.
	 * - 7.0.0.0/8 route, metric 21021 added
	 * - 7.0.0.0/8 route, metric 22 added
	 * - 8.0.0.0/8 could be added. */
	routes = ip4_routes (fixture);
	g_assert_cmpint (routes->len, ==, G_N_ELEMENTS (state1));
	nmtst_platform_ip4_routes_equal ((NMPlatformIP4Route *) routes->data, state1, routes->len, TRUE);
	g_array_free (routes, TRUE);

	setup_dev1_ip4 (fixture->ifindex1);
	g_test_assert_expected_messages ();

	setup_dev0_ip4 (fixture->ifindex0, 0, 21);

	/* Ensure nothing changed. */
	routes = ip4_routes (fixture);
	g_assert_cmpint (routes->len, ==, G_N_ELEMENTS (state1));
	state1[0].mss = 0;
	state1[1].metric = 21;
	nmtst_platform_ip4_routes_equal ((NMPlatformIP4Route *) routes->data, state1, routes->len, TRUE);
	g_array_free (routes, TRUE);

	update_dev0_ip4 (fixture->ifindex0);

	/* minor changes in the routes. Quite similar to state1. */
	routes = ip4_routes (fixture);
	g_assert_cmpint (routes->len, ==, G_N_ELEMENTS (state2));
	nmtst_platform_ip4_routes_equal ((NMPlatformIP4Route *) routes->data, state2, routes->len, TRUE);
	g_array_free (routes, TRUE);

	nm_route_manager_route_flush (nm_route_manager_get (), fixture->ifindex0);

	/* 6.6.6.0/24 is now on dev1
	 * 6.6.6.0/24 is also still on dev1 with bumped metric 21.
	 * 7.0.0.0/8 gone from dev0, still present on dev1
	 * 8.0.0.0/8 is present on dev1
	 * No dev0 routes left. */
	routes = ip4_routes (fixture);
	g_assert_cmpint (routes->len, ==, G_N_ELEMENTS (state3));
	nmtst_platform_ip4_routes_equal ((NMPlatformIP4Route *) routes->data, state3, routes->len, TRUE);
	g_array_free (routes, TRUE);

	nm_route_manager_route_flush (nm_route_manager_get (), fixture->ifindex1);

	/* No routes left. */
	routes = ip4_routes (fixture);
	g_assert_cmpint (routes->len, ==, 0);
	g_array_free (routes, TRUE);
}

static void
setup_dev0_ip6 (int ifindex)
{
	GArray *routes = g_array_new (FALSE, FALSE, sizeof (NMPlatformIP6Route));
	NMPlatformIP6Route *route;

	/* Add an address so that a route to the gateway below gets added. */
	nm_platform_ip6_address_add (NM_PLATFORM_GET,
	                             ifindex,
	                             *nmtst_inet6_from_string ("2001:db8:8086::666"),
	                             64,
	                             in6addr_any,
	                             3600,
	                             3600,
	                             0);

	route = nmtst_platform_ip6_route_full ("2001:db8:8086::",
	                                       48,
	                                       NULL,
	                                       ifindex,
	                                       NM_IP_CONFIG_SOURCE_USER,
	                                       20,
	                                       0);
	g_array_append_val (routes, *route);

	route = nmtst_platform_ip6_route_full ("2001:db8:1337::",
	                                       48,
	                                       NULL,
	                                       ifindex,
	                                       NM_IP_CONFIG_SOURCE_USER,
	                                       0,
	                                       0);
	g_array_append_val (routes, *route);

	route = nmtst_platform_ip6_route_full ("2001:db8:abad:c0de::",
	                                       64,
	                                       "2001:db8:8086::1",
	                                       ifindex,
	                                       NM_IP_CONFIG_SOURCE_USER,
	                                       21,
	                                       0);
	g_array_append_val (routes, *route);

	nm_route_manager_ip6_route_sync (nm_route_manager_get (), ifindex, routes, TRUE, TRUE);
	g_array_free (routes, TRUE);
}

static void
setup_dev1_ip6 (int ifindex)
{
	GArray *routes = g_array_new (FALSE, FALSE, sizeof (NMPlatformIP6Route));
	NMPlatformIP6Route *route;

	/* Add some route outside of route manager. The route manager
	 * should get rid of it upon sync. */
	if (!nm_platform_ip6_route_add (NM_PLATFORM_GET,
	                                ifindex,
	                                NM_IP_CONFIG_SOURCE_USER,
	                                *nmtst_inet6_from_string ("2001:db8:8088::"),
	                                48,
	                                in6addr_any,
	                                10,
	                                0))
		g_assert_not_reached ();

	route = nmtst_platform_ip6_route_full ("2001:db8:8086::",
	                                       48,
	                                       NULL,
	                                       ifindex,
	                                       NM_IP_CONFIG_SOURCE_USER,
	                                       20,
	                                       0);
	g_array_append_val (routes, *route);

	route = nmtst_platform_ip6_route_full ("2001:db8:1337::",
	                                       48,
	                                       NULL,
	                                       ifindex,
	                                       NM_IP_CONFIG_SOURCE_USER,
	                                       1024,
	                                       0);
	g_array_append_val (routes, *route);

	route = nmtst_platform_ip6_route_full ("2001:db8:d34d::",
	                                       64,
	                                       "2001:db8:8086::2",
	                                       ifindex,
	                                       NM_IP_CONFIG_SOURCE_USER,
	                                       20,
	                                       0);
	g_array_append_val (routes, *route);

	route = nmtst_platform_ip6_route_full ("2001:db8:abad:c0de::",
	                                       64,
	                                       NULL,
	                                       ifindex,
	                                       NM_IP_CONFIG_SOURCE_USER,
	                                       22,
	                                       0);
	g_array_append_val (routes, *route);

	nm_route_manager_ip6_route_sync (nm_route_manager_get (), ifindex, routes, TRUE, TRUE);
	g_array_free (routes, TRUE);
}

static void
update_dev0_ip6 (int ifindex)
{
	GArray *routes = g_array_new (FALSE, FALSE, sizeof (NMPlatformIP6Route));
	NMPlatformIP6Route *route;

	/* Add an address so that a route to the gateway below gets added. */
	nm_platform_ip6_address_add (NM_PLATFORM_GET,
	                             ifindex,
	                             *nmtst_inet6_from_string ("2001:db8:8086::2"),
	                             64,
	                             in6addr_any,
	                             3600,
	                             3600,
	                             0);

	route = nmtst_platform_ip6_route_full ("2001:db8:8086::",
	                                       48,
	                                       NULL,
	                                       ifindex,
	                                       NM_IP_CONFIG_SOURCE_USER,
	                                       20,
	                                       0);
	g_array_append_val (routes, *route);

	route = nmtst_platform_ip6_route_full ("2001:db8:1337::",
	                                       48,
	                                       NULL,
	                                       ifindex,
	                                       NM_IP_CONFIG_SOURCE_USER,
	                                       0,
	                                       0);
	g_array_append_val (routes, *route);

	route = nmtst_platform_ip6_route_full ("2001:db8:abad:c0de::",
	                                       64,
	                                       NULL,
	                                       ifindex,
	                                       NM_IP_CONFIG_SOURCE_USER,
	                                       21,
	                                       0);
	g_array_append_val (routes, *route);

	nm_route_manager_ip6_route_sync (nm_route_manager_get (), ifindex, routes, TRUE, TRUE);
	g_array_free (routes, TRUE);
}

static GArray *
ip6_routes (test_fixture *fixture)
{
	GArray *routes = nm_platform_ip6_route_get_all (NM_PLATFORM_GET,
	                                                fixture->ifindex0,
	                                                NM_PLATFORM_GET_ROUTE_FLAGS_WITH_NON_DEFAULT);
	GArray *routes1 = nm_platform_ip6_route_get_all (NM_PLATFORM_GET,
	                                                 fixture->ifindex1,
	                                                 NM_PLATFORM_GET_ROUTE_FLAGS_WITH_NON_DEFAULT);

	g_array_append_vals (routes, routes1->data, routes1->len);
	g_array_free (routes1, TRUE);

	return routes;
}

static void
test_ip6 (test_fixture *fixture, gconstpointer user_data)
{
	GArray *routes;

	NMPlatformIP6Route state1[] = {
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = *nmtst_inet6_from_string ("2001:db8:8086::"),
			.plen = 48,
			.ifindex = fixture->ifindex0,
			.gateway = in6addr_any,
			.metric = 20,
			.mss = 0,
		},
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = *nmtst_inet6_from_string ("2001:db8:1337::"),
			.plen = 48,
			.ifindex = fixture->ifindex0,
			.gateway = in6addr_any,
			.metric = 1024,
			.mss = 0,
		},
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = *nmtst_inet6_from_string ("2001:db8:abad:c0de::"),
			.plen = 64,
			.ifindex = fixture->ifindex0,
			.gateway = *nmtst_inet6_from_string ("2001:db8:8086::1"),
			.metric = 21,
			.mss = 0,
		},
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = *nmtst_inet6_from_string ("2001:db8:abad:c0de::"),
			.plen = 64,
			.ifindex = fixture->ifindex1,
			.gateway = in6addr_any,
			.metric = 22,
			.mss = 0,
		},
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = *nmtst_inet6_from_string ("2001:db8:1337::"),
			.plen = 48,
			.ifindex = fixture->ifindex1,
			.gateway = in6addr_any,
			.metric = 1025,
			.mss = 0,
		},
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = *nmtst_inet6_from_string ("2001:db8:8086::"),
			.plen = 48,
			.ifindex = fixture->ifindex1,
			.gateway = in6addr_any,
			.metric = 21,
			.mss = 0,
		},
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = *nmtst_inet6_from_string ("2001:db8:d34d::"),
			.plen = 64,
			.ifindex = fixture->ifindex1,
			.gateway = *nmtst_inet6_from_string ("2001:db8:8086::2"),
			.metric = 20,
			.mss = 0,
		},
	};

	NMPlatformIP6Route state2[] = {
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = *nmtst_inet6_from_string ("2001:db8:8086::"),
			.plen = 48,
			.ifindex = fixture->ifindex0,
			.gateway = in6addr_any,
			.metric = 20,
			.mss = 0,
		},
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = *nmtst_inet6_from_string ("2001:db8:1337::"),
			.plen = 48,
			.ifindex = fixture->ifindex0,
			.gateway = in6addr_any,
			.metric = 1024,
			.mss = 0,
		},
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = *nmtst_inet6_from_string ("2001:db8:abad:c0de::"),
			.plen = 64,
			.ifindex = fixture->ifindex0,
			.gateway = in6addr_any,
			.metric = 21,
			.mss = 0,
		},
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = *nmtst_inet6_from_string ("2001:db8:abad:c0de::"),
			.plen = 64,
			.ifindex = fixture->ifindex1,
			.gateway = in6addr_any,
			.metric = 22,
			.mss = 0,
		},
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = *nmtst_inet6_from_string ("2001:db8:1337::"),
			.plen = 48,
			.ifindex = fixture->ifindex1,
			.gateway = in6addr_any,
			.metric = 1025,
			.mss = 0,
		},
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = *nmtst_inet6_from_string ("2001:db8:8086::"),
			.plen = 48,
			.ifindex = fixture->ifindex1,
			.gateway = in6addr_any,
			.metric = 21,
			.mss = 0,
		},
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = *nmtst_inet6_from_string ("2001:db8:d34d::"),
			.plen = 64,
			.ifindex = fixture->ifindex1,
			.gateway = *nmtst_inet6_from_string ("2001:db8:8086::2"),
			.metric = 20,
			.mss = 0,
		},
	};

	NMPlatformIP6Route state3[] = {
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = *nmtst_inet6_from_string ("2001:db8:abad:c0de::"),
			.plen = 64,
			.ifindex = fixture->ifindex1,
			.gateway = in6addr_any,
			.metric = 22,
			.mss = 0,
		},
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = *nmtst_inet6_from_string ("2001:db8:8086::"),
			.plen = 48,
			.ifindex = fixture->ifindex1,
			.gateway = in6addr_any,
			.metric = 20,
			.mss = 0,
		},
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = *nmtst_inet6_from_string ("2001:db8:1337::"),
			.plen = 48,
			.ifindex = fixture->ifindex1,
			.gateway = in6addr_any,
			.metric = 1024,
			.mss = 0,
		},
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = *nmtst_inet6_from_string ("2001:db8:1337::"),
			.plen = 48,
			.ifindex = fixture->ifindex1,
			.gateway = in6addr_any,
			.metric = 1025,
			.mss = 0,
		},
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = *nmtst_inet6_from_string ("2001:db8:8086::"),
			.plen = 48,
			.ifindex = fixture->ifindex1,
			.gateway = in6addr_any,
			.metric = 21,
			.mss = 0,
		},
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = *nmtst_inet6_from_string ("2001:db8:d34d::"),
			.plen = 64,
			.ifindex = fixture->ifindex1,
			.gateway = *nmtst_inet6_from_string ("2001:db8:8086::2"),
			.metric = 20,
			.mss = 0,
		},
	};

	setup_dev0_ip6 (fixture->ifindex0);
	setup_dev1_ip6 (fixture->ifindex1);
	g_test_assert_expected_messages ();

	/* 2001:db8:8086::/48 on dev0 won over 2001:db8:8086::/48 on dev1
	 * 2001:db8:d34d::/64 on dev1 could not be added
	 * 2001:db8:1337::/48 on dev0 won over 2001:db8:1337::/48 on dev1 and has metric 1024
	 * 2001:db8:abad:c0de::/64 routes did not clash */
	routes = ip6_routes (fixture);
	g_assert_cmpint (routes->len, ==, G_N_ELEMENTS (state1));
	nmtst_platform_ip6_routes_equal ((NMPlatformIP6Route *) routes->data, state1, routes->len, TRUE);
	g_array_free (routes, TRUE);


	setup_dev1_ip6 (fixture->ifindex1);
	g_test_assert_expected_messages ();
	setup_dev0_ip6 (fixture->ifindex0);

	/* Ensure nothing changed. */
	routes = ip6_routes (fixture);
	g_assert_cmpint (routes->len, ==, G_N_ELEMENTS (state1));
	nmtst_platform_ip6_routes_equal ((NMPlatformIP6Route *) routes->data, state1, routes->len, TRUE);
	g_array_free (routes, TRUE);

	update_dev0_ip6 (fixture->ifindex0);

	/* 2001:db8:abad:c0de::/64 on dev0 was updated for gateway removal*/
	routes = ip6_routes (fixture);
	g_assert_cmpint (routes->len, ==, G_N_ELEMENTS (state2));
	nmtst_platform_ip6_routes_equal ((NMPlatformIP6Route *) routes->data, state2, routes->len, TRUE);
	g_array_free (routes, TRUE);

	nm_route_manager_route_flush (nm_route_manager_get (), fixture->ifindex0);

	/* 2001:db8:abad:c0de::/64 on dev1 is still there, went away from dev0
	 * 2001:db8:8086::/48 is now on dev1
	 * 2001:db8:1337::/48 is now on dev1, metric of 1024 still applies
	 * 2001:db8:d34d::/64 is present now that 2001:db8:8086::/48 is on dev1
	 * No dev0 routes left. */
	routes = ip6_routes (fixture);
	g_assert_cmpint (routes->len, ==, G_N_ELEMENTS (state3));
	nmtst_platform_ip6_routes_equal ((NMPlatformIP6Route *) routes->data, state3, routes->len, TRUE);
	g_array_free (routes, TRUE);

	nm_route_manager_route_flush (nm_route_manager_get (), fixture->ifindex1);

	/* No routes left. */
	routes = ip6_routes (fixture);
	g_assert_cmpint (routes->len, ==, 0);
	g_array_free (routes, TRUE);
}

/*****************************************************************************/

static void
_assert_route_check (const NMPlatformVTableRoute *vtable, gboolean has, const NMPlatformIPXRoute *route)
{
	const NMPlatformIPXRoute *r;

	g_assert (route);

	if (vtable->is_ip4)
		r = (const NMPlatformIPXRoute *) nm_platform_ip4_route_get (NM_PLATFORM_GET, route->rx.ifindex, route->r4.network, route->rx.plen, route->rx.metric);
	else
		r = (const NMPlatformIPXRoute *) nm_platform_ip6_route_get (NM_PLATFORM_GET, route->rx.ifindex, route->r6.network, route->rx.plen, route->rx.metric);

	if (!has) {
		g_assert (!r);
	} else {
		char buf[sizeof (_nm_utils_to_string_buffer)];

		if (!r || vtable->route_cmp (route, r) != 0)
			g_error ("Invalid route. Expect %s, has %s",
			         vtable->route_to_string (route, NULL, 0),
			         vtable->route_to_string (r, buf, sizeof (buf)));
		g_assert (r);
	}
}

static void
test_ip4_full_sync (test_fixture *fixture, gconstpointer user_data)
{
	const NMPlatformVTableRoute *vtable = &nm_platform_vtable_route_v4;
	gs_unref_array GArray *routes = g_array_new (FALSE, FALSE, sizeof (NMPlatformIP4Route));
	NMPlatformIP4Route r01, r02, r03;

	nm_log_dbg (LOGD_CORE, "TEST start test_ip4_full_sync(): start");

	r01 = *nmtst_platform_ip4_route_full ("12.3.4.0", 24, NULL,
	                                      fixture->ifindex0, NM_IP_CONFIG_SOURCE_USER,
	                                      100, 0, RT_SCOPE_LINK, NULL);
	r02 = *nmtst_platform_ip4_route_full ("13.4.5.6", 32, "12.3.4.1",
	                                      fixture->ifindex0, NM_IP_CONFIG_SOURCE_USER,
	                                      100, 0, RT_SCOPE_UNIVERSE, NULL);
	r03 = *nmtst_platform_ip4_route_full ("14.5.6.7", 32, "12.3.4.1",
	                                      fixture->ifindex0, NM_IP_CONFIG_SOURCE_USER,
	                                      110, 0, RT_SCOPE_UNIVERSE, NULL);
	g_array_set_size (routes, 2);
	g_array_index (routes, NMPlatformIP4Route, 0) = r01;
	g_array_index (routes, NMPlatformIP4Route, 1) = r02;
	nm_route_manager_ip4_route_sync (nm_route_manager_get (), fixture->ifindex0, routes, TRUE, TRUE);

	_assert_route_check (vtable, TRUE,  (const NMPlatformIPXRoute *) &r01);
	_assert_route_check (vtable, TRUE,  (const NMPlatformIPXRoute *) &r02);
	_assert_route_check (vtable, FALSE, (const NMPlatformIPXRoute *) &r03);

	vtable->route_add (NM_PLATFORM_GET, 0, (const NMPlatformIPXRoute *) &r03, -1);

	_assert_route_check (vtable, TRUE,  (const NMPlatformIPXRoute *) &r01);
	_assert_route_check (vtable, TRUE,  (const NMPlatformIPXRoute *) &r02);
	_assert_route_check (vtable, TRUE,  (const NMPlatformIPXRoute *) &r03);

	nm_route_manager_ip4_route_sync (nm_route_manager_get (), fixture->ifindex0, routes, TRUE, FALSE);

	_assert_route_check (vtable, TRUE,  (const NMPlatformIPXRoute *) &r01);
	_assert_route_check (vtable, TRUE,  (const NMPlatformIPXRoute *) &r02);
	_assert_route_check (vtable, TRUE,  (const NMPlatformIPXRoute *) &r03);

	g_array_set_size (routes, 1);

	nm_route_manager_ip4_route_sync (nm_route_manager_get (), fixture->ifindex0, routes, TRUE, FALSE);

	_assert_route_check (vtable, TRUE,  (const NMPlatformIPXRoute *) &r01);
	_assert_route_check (vtable, FALSE, (const NMPlatformIPXRoute *) &r02);
	_assert_route_check (vtable, TRUE,  (const NMPlatformIPXRoute *) &r03);

	nm_route_manager_ip4_route_sync (nm_route_manager_get (), fixture->ifindex0, routes, TRUE, TRUE);

	_assert_route_check (vtable, TRUE,  (const NMPlatformIPXRoute *) &r01);
	_assert_route_check (vtable, FALSE, (const NMPlatformIPXRoute *) &r02);
	_assert_route_check (vtable, FALSE, (const NMPlatformIPXRoute *) &r03);

	nm_log_dbg (LOGD_CORE, "TEST test_ip4_full_sync(): done");
}

/*****************************************************************************/

static void
fixture_setup (test_fixture *fixture, gconstpointer user_data)
{
	SignalData *link_added;

	link_added = add_signal_ifname (NM_PLATFORM_SIGNAL_LINK_CHANGED,
	                                NM_PLATFORM_SIGNAL_ADDED,
	                                link_callback,
	                                "nm-test-device0");
	nm_platform_link_delete (NM_PLATFORM_GET, nm_platform_link_get_ifindex (NM_PLATFORM_GET, "nm-test-device0"));
	g_assert (!nm_platform_link_get_by_ifname (NM_PLATFORM_GET, "nm-test-device0"));
	g_assert (nm_platform_link_dummy_add (NM_PLATFORM_GET, "nm-test-device0", NULL) == NM_PLATFORM_ERROR_SUCCESS);
	accept_signal (link_added);
	free_signal (link_added);
	fixture->ifindex0 = nm_platform_link_get_ifindex (NM_PLATFORM_GET, "nm-test-device0");
	g_assert (nm_platform_link_set_up (NM_PLATFORM_GET, fixture->ifindex0, NULL));

	link_added = add_signal_ifname (NM_PLATFORM_SIGNAL_LINK_CHANGED,
	                                NM_PLATFORM_SIGNAL_ADDED,
	                                link_callback,
	                                "nm-test-device1");
	nm_platform_link_delete (NM_PLATFORM_GET, nm_platform_link_get_ifindex (NM_PLATFORM_GET, "nm-test-device1"));
	g_assert (!nm_platform_link_get_by_ifname (NM_PLATFORM_GET, "nm-test-device1"));
	g_assert (nm_platform_link_dummy_add (NM_PLATFORM_GET, "nm-test-device1", NULL) == NM_PLATFORM_ERROR_SUCCESS);
	accept_signal (link_added);
	free_signal (link_added);
	fixture->ifindex1 = nm_platform_link_get_ifindex (NM_PLATFORM_GET, "nm-test-device1");
	g_assert (nm_platform_link_set_up (NM_PLATFORM_GET, fixture->ifindex1, NULL));
}

static void
fixture_teardown (test_fixture *fixture, gconstpointer user_data)
{
	nm_platform_link_delete (NM_PLATFORM_GET, fixture->ifindex0);
	nm_platform_link_delete (NM_PLATFORM_GET, fixture->ifindex1);
}

/*****************************************************************************/

void
_nmtstp_init_tests (int *argc, char ***argv)
{
	nmtst_init_assert_logging (argc, argv, "WARN", "ALL");
}

void
_nmtstp_setup_tests (void)
{
	g_test_add ("/route-manager/ip4", test_fixture, NULL, fixture_setup, test_ip4, fixture_teardown);
	g_test_add ("/route-manager/ip6", test_fixture, NULL, fixture_setup, test_ip6, fixture_teardown);

	g_test_add ("/route-manager/ip4-full-sync", test_fixture, NULL, fixture_setup, test_ip4_full_sync, fixture_teardown);
}
