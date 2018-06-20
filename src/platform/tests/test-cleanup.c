/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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
 * Copyright 2016 Red Hat, Inc.
 */

#include "nm-default.h"

#include "test-common.h"

static void
test_cleanup_internal (void)
{
	SignalData *link_added = add_signal_ifname (NM_PLATFORM_SIGNAL_LINK_CHANGED, NM_PLATFORM_SIGNAL_ADDED, link_callback, DEVICE_NAME);
	int ifindex;
	GArray *addresses4;
	GArray *addresses6;
	GPtrArray *routes4;
	GPtrArray *routes6;
	in_addr_t addr4;
	in_addr_t network4;
	int plen4 = 24;
	in_addr_t gateway4;
	struct in6_addr addr6;
	struct in6_addr network6;
	int plen6 = 64;
	struct in6_addr gateway6;
	int lifetime = NM_PLATFORM_LIFETIME_PERMANENT;
	int preferred = NM_PLATFORM_LIFETIME_PERMANENT;
	int metric = 20;
	int mss = 1000;
	guint32 flags = 0;

	inet_pton (AF_INET, "192.0.2.1", &addr4);
	inet_pton (AF_INET, "192.0.3.0", &network4);
	inet_pton (AF_INET, "198.51.100.1", &gateway4);
	inet_pton (AF_INET6, "2001:db8:a:b:1:2:3:4", &addr6);
	inet_pton (AF_INET6, "2001:db8:c:d:0:0:0:0", &network6);
	inet_pton (AF_INET6, "2001:db8:e:f:1:2:3:4", &gateway6);

	/* Create and set up device */
	g_assert (nm_platform_link_dummy_add (NM_PLATFORM_GET, DEVICE_NAME, NULL) == NM_PLATFORM_ERROR_SUCCESS);
	accept_signal (link_added);
	free_signal (link_added);
	g_assert (nm_platform_link_set_up (NM_PLATFORM_GET, nm_platform_link_get_ifindex (NM_PLATFORM_GET, DEVICE_NAME), NULL));
	ifindex = nm_platform_link_get_ifindex (NM_PLATFORM_GET, DEVICE_NAME);
	g_assert (ifindex > 0);

	/* wait for kernel to add the IPv6 link local address... it takes a bit. */
	NMTST_WAIT_ASSERT (100, {
		gs_unref_array GArray *addrs = NULL;
		const NMPlatformIP6Address *a;

		if (nmtst_wait_iteration > 0) {
			nmtstp_wait_for_signal (NM_PLATFORM_GET, nmtst_wait_remaining_us / 1000);
			nm_platform_process_events (NM_PLATFORM_GET);
		}
		addrs = nmtstp_platform_ip6_address_get_all (NM_PLATFORM_GET, ifindex);
		if (   addrs->len == 1
		    && (a = &g_array_index (addrs, NMPlatformIP6Address, 0))
		    && IN6_IS_ADDR_LINKLOCAL (&a->address))
			break;
	});

	/* Add routes and addresses */
	g_assert (nm_platform_ip4_address_add (NM_PLATFORM_GET, ifindex, addr4, plen4, addr4, lifetime, preferred, 0, NULL));
	g_assert (nm_platform_ip6_address_add (NM_PLATFORM_GET, ifindex, addr6, plen6, in6addr_any, lifetime, preferred, flags));
	nmtstp_ip4_route_add (NM_PLATFORM_GET, ifindex, NM_IP_CONFIG_SOURCE_USER, gateway4, 32, INADDR_ANY, 0, metric, mss);
	nmtstp_ip4_route_add (NM_PLATFORM_GET, ifindex, NM_IP_CONFIG_SOURCE_USER, network4, plen4, gateway4, 0, metric, mss);
	nmtstp_ip4_route_add (NM_PLATFORM_GET, ifindex, NM_IP_CONFIG_SOURCE_USER, 0, 0, gateway4, 0, metric, mss);
	nmtstp_ip6_route_add (NM_PLATFORM_GET, ifindex, NM_IP_CONFIG_SOURCE_USER, gateway6, 128, in6addr_any, in6addr_any, metric, mss);
	nmtstp_ip6_route_add (NM_PLATFORM_GET, ifindex, NM_IP_CONFIG_SOURCE_USER, network6, plen6, gateway6, in6addr_any, metric, mss);
	nmtstp_ip6_route_add (NM_PLATFORM_GET, ifindex, NM_IP_CONFIG_SOURCE_USER, in6addr_any, 0, gateway6, in6addr_any, metric, mss);

	addresses4 = nmtstp_platform_ip4_address_get_all (NM_PLATFORM_GET, ifindex);
	addresses6 = nmtstp_platform_ip6_address_get_all (NM_PLATFORM_GET, ifindex);
	routes4 = nmtstp_ip4_route_get_all (NM_PLATFORM_GET, ifindex);
	routes6 = nmtstp_ip6_route_get_all (NM_PLATFORM_GET, ifindex);

	g_assert_cmpint (addresses4->len, ==, 1);
	g_assert_cmpint (addresses6->len, ==, 2); /* also has a IPv6 LL address. */
	g_assert_cmpint (routes4->len, ==, 3);
	g_assert_cmpint (routes6->len, ==, 3);

	g_array_unref (addresses4);
	g_array_unref (addresses6);
	g_ptr_array_unref (routes4);
	g_ptr_array_unref (routes6);

	/* Delete interface with all addresses and routes */
	g_assert (nm_platform_link_delete (NM_PLATFORM_GET, ifindex));

	addresses4 = nmtstp_platform_ip4_address_get_all (NM_PLATFORM_GET, ifindex);
	addresses6 = nmtstp_platform_ip6_address_get_all (NM_PLATFORM_GET, ifindex);
	routes4 = nmtstp_ip4_route_get_all (NM_PLATFORM_GET, ifindex);
	routes6 = nmtstp_ip6_route_get_all (NM_PLATFORM_GET, ifindex);

	g_assert_cmpint (addresses4->len, ==, 0);
	g_assert_cmpint (addresses6->len, ==, 0);
	g_assert (!routes4);
	g_assert (!routes6);

	g_array_unref (addresses4);
	g_array_unref (addresses6);
}

NMTstpSetupFunc const _nmtstp_setup_platform_func = SETUP;

void
_nmtstp_init_tests (int *argc, char ***argv)
{
	nmtst_init_with_logging (argc, argv, NULL, "ALL");
}

void
_nmtstp_setup_tests (void)
{
	nm_platform_link_delete (NM_PLATFORM_GET, nm_platform_link_get_ifindex (NM_PLATFORM_GET, DEVICE_NAME));
	g_assert (!nm_platform_link_get_by_ifname (NM_PLATFORM_GET, DEVICE_NAME));

	g_test_add_func ("/internal", test_cleanup_internal);
	/* FIXME: add external cleanup check */
}
