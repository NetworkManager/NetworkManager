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

#include "config.h"

#include <glib.h>
#include <arpa/inet.h>
#include <linux/rtnetlink.h>

#include "test-common.h"

#include "nm-platform.h"
#include "nm-route-manager.h"
#include "nm-logging.h"

#include "nm-test-utils.h"

typedef struct {
	int ifindex0, ifindex1;
} test_fixture;

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

	nm_route_manager_ip4_route_sync (nm_route_manager_get (), ifindex, routes);
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
	nm_platform_ip4_route_add (NM_PLATFORM_GET,
	                           route.ifindex,
	                           NM_IP_CONFIG_SOURCE_USER,
	                           nmtst_inet4_from_string ("9.0.0.0"),
	                           8,
	                           INADDR_ANY,
	                           0,
	                           10,
	                           route.mss);

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

	nm_route_manager_ip4_route_sync (nm_route_manager_get (), ifindex, routes);
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

	nm_route_manager_ip4_route_sync (nm_route_manager_get (), ifindex, routes);
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
	};

	setup_dev0_ip4 (fixture->ifindex0, 1000, 21021);
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING, "*failure adding ip4-route '*: 8.0.0.0/8 22': *");
	setup_dev1_ip4 (fixture->ifindex1);
	g_test_assert_expected_messages ();

	/* 6.6.6.0/24 on dev0 won over 6.6.6.0/24 on dev1
	 * 7.0.0.0/8 routes did not clash
	 * 8.0.0.0/8 could not be added. */
	routes = ip4_routes (fixture);
	g_assert_cmpint (routes->len, ==, G_N_ELEMENTS (state1));
	nmtst_platform_ip4_routes_equal ((NMPlatformIP4Route *) routes->data, state1, routes->len, TRUE);
	g_array_free (routes, TRUE);

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING, "*failure adding ip4-route '*: 8.0.0.0/8 22': *");
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

	/* 7.0.0.0/8 on dev0 was updated for gateway removal*/
	routes = ip4_routes (fixture);
	g_assert_cmpint (routes->len, ==, G_N_ELEMENTS (state2));
	nmtst_platform_ip4_routes_equal ((NMPlatformIP4Route *) routes->data, state2, routes->len, TRUE);
	g_array_free (routes, TRUE);

	nm_route_manager_route_flush (nm_route_manager_get (), fixture->ifindex0);

	/* 6.6.6.0/24 is now on dev1
	 * 7.0.0.0/8 gone from dev0, still present on dev1
	 * 8.0.0.0/8 is present on dev1 now that 6.6.6.0/24 is on dev1 too
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
	                             *nmtst_inet6_from_string ("2001:db8:8086::2"),
	                             in6addr_any,
	                             64,
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

	nm_route_manager_ip6_route_sync (nm_route_manager_get (), ifindex, routes);
	g_array_free (routes, TRUE);
}

static void
setup_dev1_ip6 (int ifindex)
{
	GArray *routes = g_array_new (FALSE, FALSE, sizeof (NMPlatformIP6Route));
	NMPlatformIP6Route *route;

	/* Add some route outside of route manager. The route manager
	 * should get rid of it upon sync. */
	nm_platform_ip6_route_add (NM_PLATFORM_GET,
	                           ifindex,
	                           NM_IP_CONFIG_SOURCE_USER,
	                           *nmtst_inet6_from_string ("2001:db8:8088::"),
	                           48,
	                           in6addr_any,
	                           10,
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

	nm_route_manager_ip6_route_sync (nm_route_manager_get (), ifindex, routes);
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
	                             in6addr_any,
	                             64,
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

	nm_route_manager_ip6_route_sync (nm_route_manager_get (), ifindex, routes);
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
	};

	setup_dev0_ip6 (fixture->ifindex0);
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING, "*failure adding ip6-route '*: 2001:db8:d34d::/64 20': *");
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


	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING, "*failure adding ip6-route '*: 2001:db8:d34d::/64 20': *");
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
	g_assert (nm_platform_dummy_add (NM_PLATFORM_GET, "nm-test-device0", NULL) == NM_PLATFORM_ERROR_SUCCESS);
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
	g_assert (nm_platform_dummy_add (NM_PLATFORM_GET, "nm-test-device1", NULL) == NM_PLATFORM_ERROR_SUCCESS);
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

void
init_tests (int *argc, char ***argv)
{
	nmtst_init_assert_logging (argc, argv, "WARN", "ALL");
}

void
setup_tests (void)
{
	g_test_add ("/route-manager/ip4", test_fixture, NULL, fixture_setup, test_ip4, fixture_teardown);
	g_test_add ("/route-manager/ip6", test_fixture, NULL, fixture_setup, test_ip6, fixture_teardown);
}
