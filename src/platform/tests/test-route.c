/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager audit support
 *
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

#include <linux/rtnetlink.h>

#include "nm-core-utils.h"
#include "test-common.h"

#include "nm-test-utils.h"

#define DEVICE_NAME "nm-test-device"

static void
ip4_route_callback (NMPlatform *platform, NMPObjectType obj_type, int ifindex, const NMPlatformIP4Route *received, NMPlatformSignalChangeType change_type, SignalData *data)
{
	g_assert (received);
	g_assert_cmpint (received->ifindex, ==, ifindex);
	g_assert (data && data->name);
	g_assert_cmpstr (data->name, ==, NM_PLATFORM_SIGNAL_IP4_ROUTE_CHANGED);

	if (data->ifindex && data->ifindex != received->ifindex)
		return;
	if (data->change_type != change_type)
		return;

	if (data->loop)
		g_main_loop_quit (data->loop);

	data->received_count++;
	_LOGD ("Received signal '%s' %dth time.", data->name, data->received_count);
}

static void
ip6_route_callback (NMPlatform *platform, NMPObjectType obj_type, int ifindex, const NMPlatformIP6Route *received, NMPlatformSignalChangeType change_type, SignalData *data)
{
	g_assert (received);
	g_assert_cmpint (received->ifindex, ==, ifindex);
	g_assert (data && data->name);
	g_assert_cmpstr (data->name, ==, NM_PLATFORM_SIGNAL_IP6_ROUTE_CHANGED);

	if (data->ifindex && data->ifindex != received->ifindex)
		return;
	if (data->change_type != change_type)
		return;

	if (data->loop)
		g_main_loop_quit (data->loop);

	data->received_count++;
	_LOGD ("Received signal '%s' %dth time.", data->name, data->received_count);
}

static void
test_ip4_route_metric0 (void)
{
	int ifindex = nm_platform_link_get_ifindex (NM_PLATFORM_GET, DEVICE_NAME);
	SignalData *route_added = add_signal (NM_PLATFORM_SIGNAL_IP4_ROUTE_CHANGED, NM_PLATFORM_SIGNAL_ADDED, ip4_route_callback);
	SignalData *route_changed = add_signal (NM_PLATFORM_SIGNAL_IP4_ROUTE_CHANGED, NM_PLATFORM_SIGNAL_CHANGED, ip4_route_callback);
	SignalData *route_removed = add_signal (NM_PLATFORM_SIGNAL_IP4_ROUTE_CHANGED, NM_PLATFORM_SIGNAL_REMOVED, ip4_route_callback);
	in_addr_t network = nmtst_inet4_from_string ("192.0.2.5"); /* from 192.0.2.0/24 (TEST-NET-1) (rfc5737) */
	int plen = 32;
	int metric = 22987;
	int mss = 1000;

	/* No routes initially */
	nmtstp_assert_ip4_route_exists (NULL, FALSE, DEVICE_NAME, network, plen, 0);
	nmtstp_assert_ip4_route_exists (NULL, FALSE, DEVICE_NAME, network, plen, metric);

	/* add the first route */
	g_assert (nm_platform_ip4_route_add (NM_PLATFORM_GET, ifindex, NM_IP_CONFIG_SOURCE_USER, network, plen, INADDR_ANY, 0, metric, mss));
	accept_signal (route_added);

	nmtstp_assert_ip4_route_exists (NULL, FALSE, DEVICE_NAME, network, plen, 0);
	nmtstp_assert_ip4_route_exists (NULL, TRUE,  DEVICE_NAME, network, plen, metric);

	/* Deleting route with metric 0 does nothing */
	g_assert (nm_platform_ip4_route_delete (NM_PLATFORM_GET, ifindex, network, plen, 0));
	ensure_no_signal (route_removed);

	nmtstp_assert_ip4_route_exists (NULL, FALSE, DEVICE_NAME, network, plen, 0);
	nmtstp_assert_ip4_route_exists (NULL, TRUE,  DEVICE_NAME, network, plen, metric);

	/* add the second route */
	g_assert (nm_platform_ip4_route_add (NM_PLATFORM_GET, ifindex, NM_IP_CONFIG_SOURCE_USER, network, plen, INADDR_ANY, 0, 0, mss));
	accept_signal (route_added);

	nmtstp_assert_ip4_route_exists (NULL, TRUE,  DEVICE_NAME, network, plen, 0);
	nmtstp_assert_ip4_route_exists (NULL, TRUE,  DEVICE_NAME, network, plen, metric);

	/* Delete route with metric 0 */
	g_assert (nm_platform_ip4_route_delete (NM_PLATFORM_GET, ifindex, network, plen, 0));
	accept_signal (route_removed);

	nmtstp_assert_ip4_route_exists (NULL, FALSE, DEVICE_NAME, network, plen, 0);
	nmtstp_assert_ip4_route_exists (NULL, TRUE,  DEVICE_NAME, network, plen, metric);

	/* Delete route with metric 0 again (we expect nothing to happen) */
	g_assert (nm_platform_ip4_route_delete (NM_PLATFORM_GET, ifindex, network, plen, 0));
	ensure_no_signal (route_removed);

	nmtstp_assert_ip4_route_exists (NULL, FALSE, DEVICE_NAME, network, plen, 0);
	nmtstp_assert_ip4_route_exists (NULL, TRUE,  DEVICE_NAME, network, plen, metric);

	/* Delete the other route */
	g_assert (nm_platform_ip4_route_delete (NM_PLATFORM_GET, ifindex, network, plen, metric));
	accept_signal (route_removed);

	nmtstp_assert_ip4_route_exists (NULL, FALSE, DEVICE_NAME, network, plen, 0);
	nmtstp_assert_ip4_route_exists (NULL, FALSE, DEVICE_NAME, network, plen, metric);

	free_signal (route_added);
	free_signal (route_changed);
	free_signal (route_removed);
}

static void
test_ip4_route (void)
{
	int ifindex = nm_platform_link_get_ifindex (NM_PLATFORM_GET, DEVICE_NAME);
	SignalData *route_added = add_signal (NM_PLATFORM_SIGNAL_IP4_ROUTE_CHANGED, NM_PLATFORM_SIGNAL_ADDED, ip4_route_callback);
	SignalData *route_changed = add_signal (NM_PLATFORM_SIGNAL_IP4_ROUTE_CHANGED, NM_PLATFORM_SIGNAL_CHANGED, ip4_route_callback);
	SignalData *route_removed = add_signal (NM_PLATFORM_SIGNAL_IP4_ROUTE_CHANGED, NM_PLATFORM_SIGNAL_REMOVED, ip4_route_callback);
	GArray *routes;
	NMPlatformIP4Route rts[3];
	in_addr_t network;
	guint8 plen = 24;
	in_addr_t gateway;
	/* Choose a high metric so that we hopefully don't conflict. */
	int metric = 22986;
	int mss = 1000;

	inet_pton (AF_INET, "192.0.3.0", &network);
	inet_pton (AF_INET, "198.51.100.1", &gateway);

	/* Add route to gateway */
	g_assert (nm_platform_ip4_route_add (NM_PLATFORM_GET, ifindex, NM_IP_CONFIG_SOURCE_USER, gateway, 32, INADDR_ANY, 0, metric, mss));
	accept_signal (route_added);

	/* Add route */
	nmtstp_assert_ip4_route_exists (NULL, FALSE, DEVICE_NAME, network, plen, metric);
	g_assert (nm_platform_ip4_route_add (NM_PLATFORM_GET, ifindex, NM_IP_CONFIG_SOURCE_USER, network, plen, gateway, 0, metric, mss));
	nmtstp_assert_ip4_route_exists (NULL, TRUE, DEVICE_NAME, network, plen, metric);
	accept_signal (route_added);

	/* Add route again */
	g_assert (nm_platform_ip4_route_add (NM_PLATFORM_GET, ifindex, NM_IP_CONFIG_SOURCE_USER, network, plen, gateway, 0, metric, mss));
	accept_signals (route_changed, 0, 1);

	/* Add default route */
	nmtstp_assert_ip4_route_exists (NULL, FALSE, DEVICE_NAME, 0, 0, metric);
	g_assert (nm_platform_ip4_route_add (NM_PLATFORM_GET, ifindex, NM_IP_CONFIG_SOURCE_USER, 0, 0, gateway, 0, metric, mss));
	nmtstp_assert_ip4_route_exists (NULL, TRUE, DEVICE_NAME, 0, 0, metric);
	accept_signal (route_added);

	/* Add default route again */
	g_assert (nm_platform_ip4_route_add (NM_PLATFORM_GET, ifindex, NM_IP_CONFIG_SOURCE_USER, 0, 0, gateway, 0, metric, mss));
	accept_signals (route_changed, 0, 1);

	/* Test route listing */
	routes = nm_platform_ip4_route_get_all (NM_PLATFORM_GET, ifindex, NM_PLATFORM_GET_ROUTE_FLAGS_WITH_DEFAULT | NM_PLATFORM_GET_ROUTE_FLAGS_WITH_NON_DEFAULT);
	memset (rts, 0, sizeof (rts));
	rts[0].source = NM_IP_CONFIG_SOURCE_USER;
	rts[0].network = gateway;
	rts[0].plen = 32;
	rts[0].ifindex = ifindex;
	rts[0].gateway = INADDR_ANY;
	rts[0].metric = metric;
	rts[0].mss = mss;
	rts[0].scope_inv = nm_platform_route_scope_inv (RT_SCOPE_LINK);
	rts[1].source = NM_IP_CONFIG_SOURCE_USER;
	rts[1].network = network;
	rts[1].plen = plen;
	rts[1].ifindex = ifindex;
	rts[1].gateway = gateway;
	rts[1].metric = metric;
	rts[1].mss = mss;
	rts[1].scope_inv = nm_platform_route_scope_inv (RT_SCOPE_UNIVERSE);
	rts[2].source = NM_IP_CONFIG_SOURCE_USER;
	rts[2].network = 0;
	rts[2].plen = 0;
	rts[2].ifindex = ifindex;
	rts[2].gateway = gateway;
	rts[2].metric = metric;
	rts[2].mss = mss;
	rts[2].scope_inv = nm_platform_route_scope_inv (RT_SCOPE_UNIVERSE);
	g_assert_cmpint (routes->len, ==, 3);
	nmtst_platform_ip4_routes_equal ((NMPlatformIP4Route *) routes->data, rts, routes->len, TRUE);
	g_array_unref (routes);

	/* Remove route */
	g_assert (nm_platform_ip4_route_delete (NM_PLATFORM_GET, ifindex, network, plen, metric));
	nmtstp_assert_ip4_route_exists (NULL, FALSE, DEVICE_NAME, network, plen, metric);
	accept_signal (route_removed);

	/* Remove route again */
	g_assert (nm_platform_ip4_route_delete (NM_PLATFORM_GET, ifindex, network, plen, metric));

	free_signal (route_added);
	free_signal (route_changed);
	free_signal (route_removed);
}

static void
test_ip6_route (void)
{
	int ifindex = nm_platform_link_get_ifindex (NM_PLATFORM_GET, DEVICE_NAME);
	SignalData *route_added = add_signal (NM_PLATFORM_SIGNAL_IP6_ROUTE_CHANGED, NM_PLATFORM_SIGNAL_ADDED, ip6_route_callback);
	SignalData *route_changed = add_signal (NM_PLATFORM_SIGNAL_IP6_ROUTE_CHANGED, NM_PLATFORM_SIGNAL_CHANGED, ip6_route_callback);
	SignalData *route_removed = add_signal (NM_PLATFORM_SIGNAL_IP6_ROUTE_CHANGED, NM_PLATFORM_SIGNAL_REMOVED, ip6_route_callback);
	GArray *routes;
	NMPlatformIP6Route rts[3];
	struct in6_addr network;
	guint8 plen = 64;
	struct in6_addr gateway;
	/* Choose a high metric so that we hopefully don't conflict. */
	int metric = 22987;
	int mss = 1000;

	inet_pton (AF_INET6, "2001:db8:a:b:0:0:0:0", &network);
	inet_pton (AF_INET6, "2001:db8:c:d:1:2:3:4", &gateway);

	/* Add route to gateway */
	g_assert (nm_platform_ip6_route_add (NM_PLATFORM_GET, ifindex, NM_IP_CONFIG_SOURCE_USER, gateway, 128, in6addr_any, metric, mss));
	accept_signal (route_added);

	/* Add route */
	g_assert (!nm_platform_ip6_route_get (NM_PLATFORM_GET, ifindex, network, plen, metric));
	g_assert (nm_platform_ip6_route_add (NM_PLATFORM_GET, ifindex, NM_IP_CONFIG_SOURCE_USER, network, plen, gateway, metric, mss));
	g_assert (nm_platform_ip6_route_get (NM_PLATFORM_GET, ifindex, network, plen, metric));
	accept_signal (route_added);

	/* Add route again */
	g_assert (nm_platform_ip6_route_add (NM_PLATFORM_GET, ifindex, NM_IP_CONFIG_SOURCE_USER, network, plen, gateway, metric, mss));
	accept_signals (route_changed, 0, 1);

	/* Add default route */
	g_assert (!nm_platform_ip6_route_get (NM_PLATFORM_GET, ifindex, in6addr_any, 0, metric));
	g_assert (nm_platform_ip6_route_add (NM_PLATFORM_GET, ifindex, NM_IP_CONFIG_SOURCE_USER, in6addr_any, 0, gateway, metric, mss));
	g_assert (nm_platform_ip6_route_get (NM_PLATFORM_GET, ifindex, in6addr_any, 0, metric));
	accept_signal (route_added);

	/* Add default route again */
	g_assert (nm_platform_ip6_route_add (NM_PLATFORM_GET, ifindex, NM_IP_CONFIG_SOURCE_USER, in6addr_any, 0, gateway, metric, mss));
	accept_signals (route_changed, 0, 1);

	/* Test route listing */
	routes = nm_platform_ip6_route_get_all (NM_PLATFORM_GET, ifindex, NM_PLATFORM_GET_ROUTE_FLAGS_WITH_DEFAULT | NM_PLATFORM_GET_ROUTE_FLAGS_WITH_NON_DEFAULT);
	memset (rts, 0, sizeof (rts));
	rts[0].source = NM_IP_CONFIG_SOURCE_USER;
	rts[0].network = gateway;
	rts[0].plen = 128;
	rts[0].ifindex = ifindex;
	rts[0].gateway = in6addr_any;
	rts[0].metric = nm_utils_ip6_route_metric_normalize (metric);
	rts[0].mss = mss;
	rts[1].source = NM_IP_CONFIG_SOURCE_USER;
	rts[1].network = network;
	rts[1].plen = plen;
	rts[1].ifindex = ifindex;
	rts[1].gateway = gateway;
	rts[1].metric = nm_utils_ip6_route_metric_normalize (metric);
	rts[1].mss = mss;
	rts[2].source = NM_IP_CONFIG_SOURCE_USER;
	rts[2].network = in6addr_any;
	rts[2].plen = 0;
	rts[2].ifindex = ifindex;
	rts[2].gateway = gateway;
	rts[2].metric = nm_utils_ip6_route_metric_normalize (metric);
	rts[2].mss = mss;
	g_assert_cmpint (routes->len, ==, 3);
	nmtst_platform_ip6_routes_equal ((NMPlatformIP6Route *) routes->data, rts, routes->len, TRUE);
	g_array_unref (routes);

	/* Remove route */
	g_assert (nm_platform_ip6_route_delete (NM_PLATFORM_GET, ifindex, network, plen, metric));
	g_assert (!nm_platform_ip6_route_get (NM_PLATFORM_GET, ifindex, network, plen, metric));
	accept_signal (route_removed);

	/* Remove route again */
	g_assert (nm_platform_ip6_route_delete (NM_PLATFORM_GET, ifindex, network, plen, metric));

	free_signal (route_added);
	free_signal (route_changed);
	free_signal (route_removed);
}

/*****************************************************************************/

static void
test_ip4_zero_gateway (void)
{
	int ifindex = nm_platform_link_get_ifindex (NM_PLATFORM_GET, DEVICE_NAME);

	nmtstp_run_command_check ("ip route add 1.2.3.1/32 via 0.0.0.0 dev %s", DEVICE_NAME);
	nmtstp_run_command_check ("ip route add 1.2.3.2/32 dev %s", DEVICE_NAME);

	NMTST_WAIT_ASSERT (100, {
		nmtstp_wait_for_signal (NM_PLATFORM_GET, 10);
		if (   nm_platform_ip4_route_get (NM_PLATFORM_GET, ifindex, nmtst_inet4_from_string ("1.2.3.1"), 32, 0)
		    && nm_platform_ip4_route_get (NM_PLATFORM_GET, ifindex, nmtst_inet4_from_string ("1.2.3.2"), 32, 0))
			break;
	});

	nmtstp_run_command_check ("ip route flush dev %s", DEVICE_NAME);

	nmtstp_wait_for_signal (NM_PLATFORM_GET, 50);
	nm_platform_process_events (NM_PLATFORM_GET);
}

/*****************************************************************************/

void
_nmtstp_init_tests (int *argc, char ***argv)
{
	nmtst_init_with_logging (argc, argv, NULL, "ALL");
}

void
_nmtstp_setup_tests (void)
{
	SignalData *link_added = add_signal_ifname (NM_PLATFORM_SIGNAL_LINK_CHANGED, NM_PLATFORM_SIGNAL_ADDED, link_callback, DEVICE_NAME);

	nm_platform_link_delete (NM_PLATFORM_GET, nm_platform_link_get_ifindex (NM_PLATFORM_GET, DEVICE_NAME));
	g_assert (!nm_platform_link_get_by_ifname (NM_PLATFORM_GET, DEVICE_NAME));
	g_assert (nm_platform_link_dummy_add (NM_PLATFORM_GET, DEVICE_NAME, NULL) == NM_PLATFORM_ERROR_SUCCESS);
	accept_signal (link_added);
	free_signal (link_added);

	g_assert (nm_platform_link_set_up (NM_PLATFORM_GET, nm_platform_link_get_ifindex (NM_PLATFORM_GET, DEVICE_NAME), NULL));

	g_test_add_func ("/route/ip4", test_ip4_route);
	g_test_add_func ("/route/ip6", test_ip6_route);
	g_test_add_func ("/route/ip4_metric0", test_ip4_route_metric0);

	if (nmtstp_is_root_test ())
		g_test_add_func ("/route/ip4_zero_gateway", test_ip4_zero_gateway);
}
