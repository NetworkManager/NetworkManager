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
#include "platform/nm-platform-utils.h"

#include "test-common.h"

#define DEVICE_IFINDEX NMTSTP_ENV1_IFINDEX
#define EX             NMTSTP_ENV1_EX

static void
_wait_for_ipv6_addr_non_tentative (NMPlatform *platform,
                                   gint64 timeout_ms,
                                   int ifindex,
                                   guint addr_n,
                                   const struct in6_addr *addrs)
{
	guint i;

	/* Wait that the addresses become non-tentative.  Dummy interfaces are NOARP
	 * and thus don't do DAD, but the kernel sets the address as tentative for a
	 * small amount of time, which prevents the immediate addition of the route
	 * with RTA_PREFSRC */

	NMTST_WAIT_ASSERT (400, {
		gboolean should_wait = FALSE;
		const NMPlatformIP6Address *plt_addr;

		for (i = 0; i < addr_n; i++) {
			plt_addr = nm_platform_ip6_address_get (platform, ifindex, addrs[i]);
			if (   !plt_addr
			    || NM_FLAGS_HAS (plt_addr->n_ifa_flags, IFA_F_TENTATIVE)) {
				should_wait = TRUE;
				break;
			}
		}
		if (!should_wait)
			return;
		nmtstp_assert_wait_for_signal (platform,
		                               (nmtst_wait_end_us - g_get_monotonic_time ()) / 1000);
	});
}


static void
ip4_route_callback (NMPlatform *platform, int obj_type_i, int ifindex, const NMPlatformIP4Route *received, int change_type_i, SignalData *data)
{
	const NMPObjectType obj_type = obj_type_i;
	const NMPlatformSignalChangeType change_type = change_type_i;
	NMPObject o_id;
	nm_auto_nmpobj NMPObject *o_id_p = nmp_object_new (NMP_OBJECT_TYPE_IP4_ROUTE, NULL);

	g_assert_cmpint (obj_type, ==, NMP_OBJECT_TYPE_IP4_ROUTE);
	g_assert (received);
	g_assert_cmpint (received->ifindex, ==, ifindex);
	g_assert (data && data->name);
	g_assert_cmpstr (data->name, ==, NM_PLATFORM_SIGNAL_IP4_ROUTE_CHANGED);

	/* run code for initializing the ID only */
	nmp_object_stackinit_id (&o_id, NMP_OBJECT_UP_CAST (received));
	nmp_object_copy (o_id_p, NMP_OBJECT_UP_CAST (received), TRUE);
	nmp_object_copy (o_id_p, NMP_OBJECT_UP_CAST (received), FALSE);

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
ip6_route_callback (NMPlatform *platform, int obj_type_i, int ifindex, const NMPlatformIP6Route *received, int change_type_i, SignalData *data)
{
	const NMPObjectType obj_type = obj_type_i;
	const NMPlatformSignalChangeType change_type = change_type_i;
	NMPObject o_id;
	nm_auto_nmpobj NMPObject *o_id_p = nmp_object_new (NMP_OBJECT_TYPE_IP6_ROUTE, NULL);

	g_assert_cmpint (obj_type, ==, NMP_OBJECT_TYPE_IP6_ROUTE);
	g_assert (received);
	g_assert_cmpint (received->ifindex, ==, ifindex);
	g_assert (data && data->name);
	g_assert_cmpstr (data->name, ==, NM_PLATFORM_SIGNAL_IP6_ROUTE_CHANGED);

	/* run code for initializing the ID only */
	nmp_object_stackinit_id (&o_id, NMP_OBJECT_UP_CAST (received));
	nmp_object_copy (o_id_p, NMP_OBJECT_UP_CAST (received), TRUE);
	nmp_object_copy (o_id_p, NMP_OBJECT_UP_CAST (received), FALSE);

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
	nmtstp_ip4_route_add (NM_PLATFORM_GET, ifindex, NM_IP_CONFIG_SOURCE_USER, network, plen, INADDR_ANY, 0, metric, mss);
	accept_signal (route_added);

	nmtstp_assert_ip4_route_exists (NULL, FALSE, DEVICE_NAME, network, plen, 0);
	nmtstp_assert_ip4_route_exists (NULL, TRUE,  DEVICE_NAME, network, plen, metric);

	/* Deleting route with metric 0 does nothing */
	g_assert (nmtstp_platform_ip4_route_delete (NM_PLATFORM_GET, ifindex, network, plen, 0));
	ensure_no_signal (route_removed);

	nmtstp_assert_ip4_route_exists (NULL, FALSE, DEVICE_NAME, network, plen, 0);
	nmtstp_assert_ip4_route_exists (NULL, TRUE,  DEVICE_NAME, network, plen, metric);

	/* add the second route */
	nmtstp_ip4_route_add (NM_PLATFORM_GET, ifindex, NM_IP_CONFIG_SOURCE_USER, network, plen, INADDR_ANY, 0, 0, mss);
	accept_signal (route_added);

	nmtstp_assert_ip4_route_exists (NULL, TRUE,  DEVICE_NAME, network, plen, 0);
	nmtstp_assert_ip4_route_exists (NULL, TRUE,  DEVICE_NAME, network, plen, metric);

	/* Delete route with metric 0 */
	g_assert (nmtstp_platform_ip4_route_delete (NM_PLATFORM_GET, ifindex, network, plen, 0));
	accept_signal (route_removed);

	nmtstp_assert_ip4_route_exists (NULL, FALSE, DEVICE_NAME, network, plen, 0);
	nmtstp_assert_ip4_route_exists (NULL, TRUE,  DEVICE_NAME, network, plen, metric);

	/* Delete route with metric 0 again (we expect nothing to happen) */
	g_assert (nmtstp_platform_ip4_route_delete (NM_PLATFORM_GET, ifindex, network, plen, 0));
	ensure_no_signal (route_removed);

	nmtstp_assert_ip4_route_exists (NULL, FALSE, DEVICE_NAME, network, plen, 0);
	nmtstp_assert_ip4_route_exists (NULL, TRUE,  DEVICE_NAME, network, plen, metric);

	/* Delete the other route */
	g_assert (nmtstp_platform_ip4_route_delete (NM_PLATFORM_GET, ifindex, network, plen, metric));
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
	GPtrArray *routes;
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
	nmtstp_ip4_route_add (NM_PLATFORM_GET, ifindex, NM_IP_CONFIG_SOURCE_USER, gateway, 32, INADDR_ANY, 0, metric, mss);
	accept_signal (route_added);

	/* Add route */
	nmtstp_assert_ip4_route_exists (NULL, FALSE, DEVICE_NAME, network, plen, metric);
	nmtstp_ip4_route_add (NM_PLATFORM_GET, ifindex, NM_IP_CONFIG_SOURCE_USER, network, plen, gateway, 0, metric, mss);
	nmtstp_assert_ip4_route_exists (NULL, TRUE, DEVICE_NAME, network, plen, metric);
	accept_signal (route_added);

	/* Add route again */
	nmtstp_ip4_route_add (NM_PLATFORM_GET, ifindex, NM_IP_CONFIG_SOURCE_USER, network, plen, gateway, 0, metric, mss);
	accept_signals (route_changed, 0, 1);

	/* Add default route */
	nmtstp_assert_ip4_route_exists (NULL, FALSE, DEVICE_NAME, 0, 0, metric);
	nmtstp_ip4_route_add (NM_PLATFORM_GET, ifindex, NM_IP_CONFIG_SOURCE_USER, 0, 0, gateway, 0, metric, mss);
	nmtstp_assert_ip4_route_exists (NULL, TRUE, DEVICE_NAME, 0, 0, metric);
	accept_signal (route_added);

	/* Add default route again */
	nmtstp_ip4_route_add (NM_PLATFORM_GET, ifindex, NM_IP_CONFIG_SOURCE_USER, 0, 0, gateway, 0, metric, mss);
	accept_signals (route_changed, 0, 1);

	/* Test route listing */
	routes = nmtstp_ip4_route_get_all (NM_PLATFORM_GET, ifindex);
	memset (rts, 0, sizeof (rts));
	rts[0].rt_source = nmp_utils_ip_config_source_round_trip_rtprot (NM_IP_CONFIG_SOURCE_USER);
	rts[0].network = gateway;
	rts[0].plen = 32;
	rts[0].ifindex = ifindex;
	rts[0].gateway = INADDR_ANY;
	rts[0].metric = metric;
	rts[0].mss = mss;
	rts[0].scope_inv = nm_platform_route_scope_inv (RT_SCOPE_LINK);
	rts[1].rt_source = nmp_utils_ip_config_source_round_trip_rtprot (NM_IP_CONFIG_SOURCE_USER);
	rts[1].network = network;
	rts[1].plen = plen;
	rts[1].ifindex = ifindex;
	rts[1].gateway = gateway;
	rts[1].metric = metric;
	rts[1].mss = mss;
	rts[1].scope_inv = nm_platform_route_scope_inv (RT_SCOPE_UNIVERSE);
	rts[2].rt_source = nmp_utils_ip_config_source_round_trip_rtprot (NM_IP_CONFIG_SOURCE_USER);
	rts[2].network = 0;
	rts[2].plen = 0;
	rts[2].ifindex = ifindex;
	rts[2].gateway = gateway;
	rts[2].metric = metric;
	rts[2].mss = mss;
	rts[2].scope_inv = nm_platform_route_scope_inv (RT_SCOPE_UNIVERSE);
	g_assert_cmpint (routes->len, ==, 3);
	nmtst_platform_ip4_routes_equal_aptr ((const NMPObject *const*) routes->pdata, rts, routes->len, TRUE);
	g_ptr_array_unref (routes);

	/* Remove route */
	g_assert (nmtstp_platform_ip4_route_delete (NM_PLATFORM_GET, ifindex, network, plen, metric));
	nmtstp_assert_ip4_route_exists (NULL, FALSE, DEVICE_NAME, network, plen, metric);
	accept_signal (route_removed);

	/* Remove route again */
	g_assert (nmtstp_platform_ip4_route_delete (NM_PLATFORM_GET, ifindex, network, plen, metric));

	/* Remove default route */
	g_assert (nmtstp_platform_ip4_route_delete (NM_PLATFORM_GET, ifindex, 0, 0, metric));
	accept_signal (route_removed);

	/* Remove route to gateway */
	g_assert (nmtstp_platform_ip4_route_delete (NM_PLATFORM_GET, ifindex, gateway, 32, metric));
	accept_signal (route_removed);

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
	GPtrArray *routes;
	NMPlatformIP6Route rts[3];
	struct in6_addr network;
	guint8 plen = 64;
	struct in6_addr gateway, pref_src;
	/* Choose a high metric so that we hopefully don't conflict. */
	int metric = 22987;
	int mss = 1000;

	inet_pton (AF_INET6, "2001:db8:a:b:0:0:0:0", &network);
	inet_pton (AF_INET6, "2001:db8:c:d:1:2:3:4", &gateway);
	inet_pton (AF_INET6, "::42", &pref_src);

	g_assert (nm_platform_ip6_address_add (NM_PLATFORM_GET, ifindex, pref_src, 128, in6addr_any,
	                                       NM_PLATFORM_LIFETIME_PERMANENT, NM_PLATFORM_LIFETIME_PERMANENT, 0));
	accept_signals (route_added, 0, 1);

	_wait_for_ipv6_addr_non_tentative (NM_PLATFORM_GET, 200, ifindex, 1, &pref_src);

	/* Add route to gateway */
	nmtstp_ip6_route_add (NM_PLATFORM_GET, ifindex, NM_IP_CONFIG_SOURCE_USER, gateway, 128, in6addr_any, in6addr_any, metric, mss);
	accept_signal (route_added);

	/* Add route */
	g_assert (!nm_platform_ip6_route_get (NM_PLATFORM_GET, ifindex, network, plen, metric));
	nmtstp_ip6_route_add (NM_PLATFORM_GET, ifindex, NM_IP_CONFIG_SOURCE_USER, network, plen, gateway, pref_src, metric, mss);
	g_assert (nm_platform_ip6_route_get (NM_PLATFORM_GET, ifindex, network, plen, metric));
	accept_signal (route_added);

	/* Add route again */
	nmtstp_ip6_route_add (NM_PLATFORM_GET, ifindex, NM_IP_CONFIG_SOURCE_USER, network, plen, gateway, pref_src, metric, mss);
	accept_signals (route_changed, 0, 1);

	/* Add default route */
	g_assert (!nm_platform_ip6_route_get (NM_PLATFORM_GET, ifindex, in6addr_any, 0, metric));
	nmtstp_ip6_route_add (NM_PLATFORM_GET, ifindex, NM_IP_CONFIG_SOURCE_USER, in6addr_any, 0, gateway, in6addr_any, metric, mss);
	g_assert (nm_platform_ip6_route_get (NM_PLATFORM_GET, ifindex, in6addr_any, 0, metric));
	accept_signal (route_added);

	/* Add default route again */
	nmtstp_ip6_route_add (NM_PLATFORM_GET, ifindex, NM_IP_CONFIG_SOURCE_USER, in6addr_any, 0, gateway, in6addr_any, metric, mss);
	accept_signals (route_changed, 0, 1);

	/* Test route listing */
	routes = nmtstp_ip6_route_get_all (NM_PLATFORM_GET, ifindex);
	memset (rts, 0, sizeof (rts));
	rts[0].rt_source = nmp_utils_ip_config_source_round_trip_rtprot (NM_IP_CONFIG_SOURCE_USER);
	rts[0].network = gateway;
	rts[0].plen = 128;
	rts[0].ifindex = ifindex;
	rts[0].gateway = in6addr_any;
	rts[0].pref_src = in6addr_any;
	rts[0].metric = nm_utils_ip6_route_metric_normalize (metric);
	rts[0].mss = mss;
	rts[1].rt_source = nmp_utils_ip_config_source_round_trip_rtprot (NM_IP_CONFIG_SOURCE_USER);
	rts[1].network = network;
	rts[1].plen = plen;
	rts[1].ifindex = ifindex;
	rts[1].gateway = gateway;
	rts[1].pref_src = pref_src;
	rts[1].metric = nm_utils_ip6_route_metric_normalize (metric);
	rts[1].mss = mss;
	rts[2].rt_source = nmp_utils_ip_config_source_round_trip_rtprot (NM_IP_CONFIG_SOURCE_USER);
	rts[2].network = in6addr_any;
	rts[2].plen = 0;
	rts[2].ifindex = ifindex;
	rts[2].gateway = gateway;
	rts[2].pref_src = in6addr_any;
	rts[2].metric = nm_utils_ip6_route_metric_normalize (metric);
	rts[2].mss = mss;
	g_assert_cmpint (routes->len, ==, 3);
	nmtst_platform_ip6_routes_equal_aptr ((const NMPObject *const*) routes->pdata, rts, routes->len, TRUE);
	g_ptr_array_unref (routes);

	/* Remove route */
	g_assert (nmtstp_platform_ip6_route_delete (NM_PLATFORM_GET, ifindex, network, plen, metric));
	g_assert (!nm_platform_ip6_route_get (NM_PLATFORM_GET, ifindex, network, plen, metric));
	accept_signal (route_removed);

	/* Remove route again */
	g_assert (nmtstp_platform_ip6_route_delete (NM_PLATFORM_GET, ifindex, network, plen, metric));

	/* Remove default route */
	g_assert (nmtstp_platform_ip6_route_delete (NM_PLATFORM_GET, ifindex, in6addr_any, 0, metric));
	accept_signal (route_removed);

	/* Remove route to gateway */
	g_assert (nmtstp_platform_ip6_route_delete (NM_PLATFORM_GET, ifindex, gateway, 128, metric));
	accept_signal (route_removed);

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
}

static void
test_ip4_route_options (void)
{
	int ifindex = nm_platform_link_get_ifindex (NM_PLATFORM_GET, DEVICE_NAME);
	NMPlatformIP4Route route = { };
	in_addr_t network;
	GPtrArray *routes;
	NMPlatformIP4Route rts[1];

	inet_pton (AF_INET, "172.16.1.0", &network);

	route.ifindex = ifindex;
	route.rt_source = NM_IP_CONFIG_SOURCE_USER;
	route.network = network;
	route.plen = 24;
	route.metric = 20;
	route.tos = 0x28;
	route.window = 10000;
	route.cwnd = 16;
	route.initcwnd = 30;
	route.initrwnd = 50;
	route.mtu = 1350;
	route.lock_cwnd = TRUE;

	g_assert (nm_platform_ip4_route_add (NM_PLATFORM_GET, NMP_NLM_FLAG_REPLACE, &route));

	/* Test route listing */
	routes = nmtstp_ip4_route_get_all (NM_PLATFORM_GET, ifindex);
	memset (rts, 0, sizeof (rts));
	rts[0].rt_source = nmp_utils_ip_config_source_round_trip_rtprot (NM_IP_CONFIG_SOURCE_USER);
	rts[0].scope_inv = nm_platform_route_scope_inv (RT_SCOPE_LINK);
	rts[0].network = network;
	rts[0].plen = 24;
	rts[0].ifindex = ifindex;
	rts[0].metric = 20;
	rts[0].tos = 0x28;
	rts[0].window = 10000;
	rts[0].cwnd = 16;
	rts[0].initcwnd = 30;
	rts[0].initrwnd = 50;
	rts[0].mtu = 1350;
	rts[0].lock_cwnd = TRUE;
	g_assert_cmpint (routes->len, ==, 1);
	nmtst_platform_ip4_routes_equal_aptr ((const NMPObject *const*) routes->pdata, rts, routes->len, TRUE);

	/* Remove route */
	g_assert (nm_platform_ip_route_delete (NM_PLATFORM_GET, routes->pdata[0]));

	g_ptr_array_unref (routes);
}


static void
test_ip6_route_options (gconstpointer test_data)
{
	const int TEST_IDX = GPOINTER_TO_INT (test_data);
	const int IFINDEX = nm_platform_link_get_ifindex (NM_PLATFORM_GET, DEVICE_NAME);
	GPtrArray *routes;
#define RTS_MAX 1
	NMPlatformIP6Route rts_add[RTS_MAX] = { };
	NMPlatformIP6Route rts_cmp[RTS_MAX] = { };
	NMPlatformIP6Address addr[1] = { };
	struct in6_addr addr_in6[G_N_ELEMENTS (addr)] = { };
	guint rts_n = 0;
	guint addr_n = 0;
	guint i;

	switch (TEST_IDX) {
	case 1:
		rts_add[rts_n++] = ((NMPlatformIP6Route) {
			.ifindex = IFINDEX,
			.rt_source = NM_IP_CONFIG_SOURCE_USER,
			.network = *nmtst_inet6_from_string ("2001:db8:a:b:0:0:0:0"),
			.plen = 64,
			.gateway = in6addr_any,
			.metric = 1024,
			.window = 20000,
			.cwnd = 8,
			.initcwnd = 22,
			.initrwnd = 33,
			.mtu = 1300,
			.lock_mtu = TRUE,
		});
		break;
	case 2:
		addr[addr_n++] = ((NMPlatformIP6Address) {
			.ifindex = IFINDEX,
			.address = *nmtst_inet6_from_string ("2000::2"),
			.plen = 128,
			.peer_address = in6addr_any,
			.lifetime = NM_PLATFORM_LIFETIME_PERMANENT,
			.preferred = NM_PLATFORM_LIFETIME_PERMANENT,
			.n_ifa_flags = 0,
		});
		rts_add[rts_n++] = ((NMPlatformIP6Route) {
			.ifindex = IFINDEX,
			.rt_source = NM_IP_CONFIG_SOURCE_USER,
			.network = *nmtst_inet6_from_string ("1010::1"),
			.plen = 128,
			.gateway = in6addr_any,
			.metric = 256,
			.pref_src = *nmtst_inet6_from_string ("2000::2"),
		});
		break;
	default:
		g_assert_not_reached ();
	}

	for (i = 0; i < addr_n; i++) {
		g_assert (addr[i].ifindex == IFINDEX);
		addr_in6[i] = addr[i].address;
		g_assert (nm_platform_ip6_address_add (NM_PLATFORM_GET,
		                                       IFINDEX,
		                                       addr[i].address,
		                                       addr[i].plen,
		                                       addr[i].peer_address,
		                                       addr[i].lifetime,
		                                       addr[i].preferred,
		                                       addr[i].n_ifa_flags));
	}

	_wait_for_ipv6_addr_non_tentative (NM_PLATFORM_GET, 400, IFINDEX, addr_n, addr_in6);

	for (i = 0; i < rts_n; i++)
		g_assert (nm_platform_ip6_route_add (NM_PLATFORM_GET, NMP_NLM_FLAG_REPLACE, &rts_add[i]));

	routes = nmtstp_ip6_route_get_all (NM_PLATFORM_GET, IFINDEX);
	switch (TEST_IDX) {
	case 1:
	case 2:
		for (i = 0; i < rts_n; i++) {
			rts_cmp[i] = rts_add[i];
			rts_cmp[i].rt_source = nmp_utils_ip_config_source_round_trip_rtprot (NM_IP_CONFIG_SOURCE_USER);
		}
		break;
	default:
		g_assert_not_reached ();
	}
	g_assert_cmpint (routes->len, ==, rts_n);
	nmtst_platform_ip6_routes_equal_aptr ((const NMPObject *const*) routes->pdata, rts_cmp, routes->len, TRUE);
	g_ptr_array_unref (routes);

	for (i = 0; i < rts_n; i++) {
		g_assert (nmtstp_platform_ip6_route_delete (NM_PLATFORM_GET, IFINDEX,
		                                            rts_add[i].network, rts_add[i].plen,
		                                            rts_add[i].metric));
	}

	for (i = 0; i < addr_n; i++) {
		nmtstp_ip6_address_del (NM_PLATFORM_GET,
		                        EX,
		                        IFINDEX,
		                        rts_add[i].network,
		                        rts_add[i].plen);
	}
}

/*****************************************************************************/

NMTstpSetupFunc const _nmtstp_setup_platform_func = SETUP;

void
_nmtstp_init_tests (int *argc, char ***argv)
{
	nmtst_init_with_logging (argc, argv, NULL, "ALL");
}

void
_nmtstp_setup_tests (void)
{
#define add_test_func(testpath, test_func) nmtstp_env1_add_test_func(testpath, test_func, TRUE)
#define add_test_func_data(testpath, test_func, arg) nmtstp_env1_add_test_func_data(testpath, test_func, arg, TRUE)
	add_test_func ("/route/ip4", test_ip4_route);
	add_test_func ("/route/ip6", test_ip6_route);
	add_test_func ("/route/ip4_metric0", test_ip4_route_metric0);
	add_test_func ("/route/ip4_options", test_ip4_route_options);
	add_test_func_data ("/route/ip6_options/1", test_ip6_route_options, GINT_TO_POINTER (1));
	add_test_func_data ("/route/ip6_options/2", test_ip6_route_options, GINT_TO_POINTER (2));

	if (nmtstp_is_root_test ())
		add_test_func ("/route/ip4_zero_gateway", test_ip4_zero_gateway);
}
