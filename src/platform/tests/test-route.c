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
 * Copyright 2016 - 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include <linux/rtnetlink.h>

#include "nm-core-utils.h"
#include "platform/nm-platform-utils.h"

#include "test-common.h"

#define DEVICE_IFINDEX NMTSTP_ENV1_IFINDEX
#define EX             NMTSTP_ENV1_EX

static void
_wait_for_ipv4_addr_device_route (NMPlatform *platform,
                                  gint64 timeout_ms,
                                  int ifindex,
                                  in_addr_t addr,
                                  guint8 plen)
{
	/* Wait that the addresses gets a device-route. After adding a address,
	 * the device route is not added immediately. It takes a moment... */

	addr = nm_utils_ip4_address_clear_host_address (addr, plen);
	NMTST_WAIT_ASSERT (400, {
		NMDedupMultiIter iter;
		NMPLookup lookup;
		const NMPObject *o;

		nmp_cache_iter_for_each (&iter,
		                         nm_platform_lookup (platform,
		                                             nmp_lookup_init_object (&lookup,
		                                                                     NMP_OBJECT_TYPE_IP4_ROUTE,
		                                                                     ifindex)),
		                         &o) {
			const NMPlatformIP4Route *r = NMP_OBJECT_CAST_IP4_ROUTE (o);

			if (   r->plen == plen
			    && addr == nm_utils_ip4_address_clear_host_address (r->network, plen)
			    && r->metric == 0
			    && r->scope_inv == nm_platform_route_scope_inv (RT_SCOPE_LINK)
			    && r->rt_source == NM_IP_CONFIG_SOURCE_RTPROT_KERNEL)
				return;
		}
		nmtstp_assert_wait_for_signal (platform,
		                               (nmtst_wait_end_us - g_get_monotonic_time ()) / 1000);
	});
}

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

	NMTST_WAIT_ASSERT (timeout_ms, {
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
	nmtstp_assert_ip4_route_exists (NULL, 0, DEVICE_NAME, network, plen, 0, 0);
	nmtstp_assert_ip4_route_exists (NULL, 0, DEVICE_NAME, network, plen, metric, 0);

	/* add the first route */
	nmtstp_ip4_route_add (NM_PLATFORM_GET, ifindex, NM_IP_CONFIG_SOURCE_USER, network, plen, INADDR_ANY, 0, metric, mss);
	accept_signal (route_added);

	nmtstp_assert_ip4_route_exists (NULL, 0, DEVICE_NAME, network, plen, 0, 0);
	nmtstp_assert_ip4_route_exists (NULL, 1,  DEVICE_NAME, network, plen, metric, 0);

	/* Deleting route with metric 0 does nothing */
	g_assert (nmtstp_platform_ip4_route_delete (NM_PLATFORM_GET, ifindex, network, plen, 0));
	ensure_no_signal (route_removed);

	nmtstp_assert_ip4_route_exists (NULL, 0, DEVICE_NAME, network, plen, 0, 0);
	nmtstp_assert_ip4_route_exists (NULL, 1,  DEVICE_NAME, network, plen, metric, 0);

	/* add the second route */
	nmtstp_ip4_route_add (NM_PLATFORM_GET, ifindex, NM_IP_CONFIG_SOURCE_USER, network, plen, INADDR_ANY, 0, 0, mss);
	accept_signal (route_added);

	nmtstp_assert_ip4_route_exists (NULL, 1,  DEVICE_NAME, network, plen, 0, 0);
	nmtstp_assert_ip4_route_exists (NULL, 1,  DEVICE_NAME, network, plen, metric, 0);

	/* Delete route with metric 0 */
	g_assert (nmtstp_platform_ip4_route_delete (NM_PLATFORM_GET, ifindex, network, plen, 0));
	accept_signal (route_removed);

	nmtstp_assert_ip4_route_exists (NULL, 0, DEVICE_NAME, network, plen, 0, 0);
	nmtstp_assert_ip4_route_exists (NULL, 1,  DEVICE_NAME, network, plen, metric, 0);

	/* Delete route with metric 0 again (we expect nothing to happen) */
	g_assert (nmtstp_platform_ip4_route_delete (NM_PLATFORM_GET, ifindex, network, plen, 0));
	ensure_no_signal (route_removed);

	nmtstp_assert_ip4_route_exists (NULL, 0, DEVICE_NAME, network, plen, 0, 0);
	nmtstp_assert_ip4_route_exists (NULL, 1,  DEVICE_NAME, network, plen, metric, 0);

	/* Delete the other route */
	g_assert (nmtstp_platform_ip4_route_delete (NM_PLATFORM_GET, ifindex, network, plen, metric));
	accept_signal (route_removed);

	nmtstp_assert_ip4_route_exists (NULL, 0, DEVICE_NAME, network, plen, 0, 0);
	nmtstp_assert_ip4_route_exists (NULL, 0, DEVICE_NAME, network, plen, metric, 0);

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
	nmtstp_assert_ip4_route_exists (NULL, 0, DEVICE_NAME, network, plen, metric, 0);
	nmtstp_ip4_route_add (NM_PLATFORM_GET, ifindex, NM_IP_CONFIG_SOURCE_USER, network, plen, gateway, 0, metric, mss);
	nmtstp_assert_ip4_route_exists (NULL, 1, DEVICE_NAME, network, plen, metric, 0);
	accept_signal (route_added);

	/* Add route again */
	nmtstp_ip4_route_add (NM_PLATFORM_GET, ifindex, NM_IP_CONFIG_SOURCE_USER, network, plen, gateway, 0, metric, mss);
	accept_signals (route_changed, 0, 1);

	/* Add default route */
	nmtstp_assert_ip4_route_exists (NULL, 0, DEVICE_NAME, 0, 0, metric, 0);
	nmtstp_ip4_route_add (NM_PLATFORM_GET, ifindex, NM_IP_CONFIG_SOURCE_USER, 0, 0, gateway, 0, metric, mss);
	nmtstp_assert_ip4_route_exists (NULL, 1, DEVICE_NAME, 0, 0, metric, 0);
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
	nmtstp_assert_ip4_route_exists (NULL, 0, DEVICE_NAME, network, plen, metric, 0);
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
	g_assert (!nmtstp_ip6_route_get (NM_PLATFORM_GET, ifindex, &network, plen, metric, NULL, 0));
	nmtstp_ip6_route_add (NM_PLATFORM_GET, ifindex, NM_IP_CONFIG_SOURCE_USER, network, plen, gateway, pref_src, metric, mss);
	g_assert (nmtstp_ip6_route_get (NM_PLATFORM_GET, ifindex, &network, plen, metric, NULL, 0));
	accept_signal (route_added);

	/* Add route again */
	nmtstp_ip6_route_add (NM_PLATFORM_GET, ifindex, NM_IP_CONFIG_SOURCE_USER, network, plen, gateway, pref_src, metric, mss);
	accept_signals (route_changed, 0, 1);

	/* Add default route */
	g_assert (!nmtstp_ip6_route_get (NM_PLATFORM_GET, ifindex, &in6addr_any, 0, metric, NULL, 0));
	nmtstp_ip6_route_add (NM_PLATFORM_GET, ifindex, NM_IP_CONFIG_SOURCE_USER, in6addr_any, 0, gateway, in6addr_any, metric, mss);
	g_assert (nmtstp_ip6_route_get (NM_PLATFORM_GET, ifindex, &in6addr_any, 0, metric, NULL, 0));
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
	g_assert (!nmtstp_ip6_route_get (NM_PLATFORM_GET, ifindex, &network, plen, metric, NULL, 0));
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
test_ip4_route_get (void)
{
	int ifindex = nm_platform_link_get_ifindex (NM_PLATFORM_GET, DEVICE_NAME);
	in_addr_t a;
	NMPlatformError result;
	nm_auto_nmpobj NMPObject *route = NULL;
	const NMPlatformIP4Route *r;

	nmtstp_run_command_check ("ip route add 1.2.3.0/24 dev %s", DEVICE_NAME);

	NMTST_WAIT_ASSERT (100, {
		nmtstp_wait_for_signal (NM_PLATFORM_GET, 10);
		if (nmtstp_ip4_route_get (NM_PLATFORM_GET, ifindex, nmtst_inet4_from_string ("1.2.3.0"), 24, 0, 0))
			break;
	});

	a = nmtst_inet4_from_string ("1.2.3.1");
	result = nm_platform_ip_route_get (NM_PLATFORM_GET,
	                                   AF_INET,
	                                   &a,
	                                   nmtst_get_rand_int () % 2 ? 0 : ifindex,
	                                   &route);

	g_assert (result == NM_PLATFORM_ERROR_SUCCESS);
	g_assert (NMP_OBJECT_GET_TYPE (route) == NMP_OBJECT_TYPE_IP4_ROUTE);
	g_assert (!NMP_OBJECT_IS_STACKINIT (route));
	g_assert (route->parent._ref_count == 1);
	r = NMP_OBJECT_CAST_IP4_ROUTE (route);
	g_assert (NM_FLAGS_HAS (r->r_rtm_flags, RTM_F_CLONED));
	g_assert (r->ifindex == ifindex);
	g_assert (r->network == a);
	g_assert (r->plen == 32);

	nmtstp_run_command_check ("ip route flush dev %s", DEVICE_NAME);

	nmtstp_wait_for_signal (NM_PLATFORM_GET, 50);
}

static void
test_ip4_zero_gateway (void)
{
	int ifindex = nm_platform_link_get_ifindex (NM_PLATFORM_GET, DEVICE_NAME);

	nmtstp_run_command_check ("ip route add 1.2.3.1/32 via 0.0.0.0 dev %s", DEVICE_NAME);
	nmtstp_run_command_check ("ip route add 1.2.3.2/32 dev %s", DEVICE_NAME);

	NMTST_WAIT_ASSERT (100, {
		nmtstp_wait_for_signal (NM_PLATFORM_GET, 10);
		if (   nmtstp_ip4_route_get (NM_PLATFORM_GET, ifindex, nmtst_inet4_from_string ("1.2.3.1"), 32, 0, 0)
		    && nmtstp_ip4_route_get (NM_PLATFORM_GET, ifindex, nmtst_inet4_from_string ("1.2.3.2"), 32, 0, 0))
			break;
	});

	nmtstp_run_command_check ("ip route flush dev %s", DEVICE_NAME);

	nmtstp_wait_for_signal (NM_PLATFORM_GET, 50);
}

static void
test_ip4_route_options (gconstpointer test_data)
{
	const int TEST_IDX = GPOINTER_TO_INT (test_data);
	const int IFINDEX = nm_platform_link_get_ifindex (NM_PLATFORM_GET, DEVICE_NAME);
	gs_unref_ptrarray GPtrArray *routes = NULL;
#define RTS_MAX 3
	NMPlatformIP4Route rts_add[RTS_MAX] = { };
	NMPlatformIP4Route rts_cmp[RTS_MAX] = { };
	NMPlatformIP4Address addr[1] = { };
	guint i;
	guint rts_n = 0;
	guint addr_n = 0;

	switch (TEST_IDX) {
	case 1:
		rts_add[rts_n++] = ((NMPlatformIP4Route) {
			.ifindex = IFINDEX,
			.rt_source = NM_IP_CONFIG_SOURCE_USER,
			.network = nmtst_inet4_from_string ("172.16.1.0"),
			.plen = 24,
			.metric = 20,
			.tos = 0x28,
			.window = 10000,
			.cwnd = 16,
			.initcwnd = 30,
			.initrwnd = 50,
			.mtu = 1350,
			.lock_cwnd = TRUE,
		});
		break;
	case 2:
		addr[addr_n++] = ((NMPlatformIP4Address) {
			.ifindex = IFINDEX,
			.address = nmtst_inet4_from_string ("172.16.1.5"),
			.peer_address = nmtst_inet4_from_string ("172.16.1.5"),
			.plen = 24,
			.lifetime = NM_PLATFORM_LIFETIME_PERMANENT,
			.preferred = NM_PLATFORM_LIFETIME_PERMANENT,
			.n_ifa_flags = 0,
		});
		rts_add[rts_n++] = ((NMPlatformIP4Route) {
			.ifindex = IFINDEX,
			.rt_source = NM_IP_CONFIG_SOURCE_USER,
			.network = nmtst_inet4_from_string ("172.17.1.0"),
			.gateway = nmtst_inet4_from_string ("172.16.1.1"),
			.plen = 24,
			.metric = 20,
		});
		rts_add[rts_n++] = ((NMPlatformIP4Route) {
			.ifindex = IFINDEX,
			.rt_source = NM_IP_CONFIG_SOURCE_USER,
			.network = nmtst_inet4_from_string ("172.19.1.0"),
			.gateway = nmtst_inet4_from_string ("172.18.1.1"),
			.r_rtm_flags = RTNH_F_ONLINK,
			.plen = 24,
			.metric = 20,
		});
		break;
	default:
		g_assert_not_reached ();
		break;
	}
	g_assert (rts_n <= G_N_ELEMENTS (rts_add));
	g_assert (addr_n <= G_N_ELEMENTS (addr));

	for (i = 0; i < addr_n; i++) {
		const NMPlatformIP4Address *a = &addr[i];

		g_assert (a->ifindex == IFINDEX);
		g_assert (nm_platform_ip4_address_add (NM_PLATFORM_GET,
		                                       a->ifindex,
		                                       a->address,
		                                       a->plen,
		                                       a->peer_address,
		                                       a->lifetime,
		                                       a->preferred,
		                                       a->n_ifa_flags,
		                                       a->label));
		if (a->peer_address == a->address)
			_wait_for_ipv4_addr_device_route (NM_PLATFORM_GET, 200, a->ifindex, a->address, a->plen);
	}

	for (i = 0; i < rts_n; i++)
		g_assert (nm_platform_ip4_route_add (NM_PLATFORM_GET, NMP_NLM_FLAG_REPLACE, &rts_add[i]) == NM_PLATFORM_ERROR_SUCCESS);

	for (i = 0; i < rts_n; i++) {
		rts_cmp[i] = rts_add[i];
		nm_platform_ip_route_normalize (AF_INET, NM_PLATFORM_IP_ROUTE_CAST (&rts_cmp[i]));
	}

	routes = nmtstp_ip4_route_get_all (NM_PLATFORM_GET, IFINDEX);
	g_assert_cmpint (routes->len, ==, rts_n);
	nmtst_platform_ip4_routes_equal_aptr ((const NMPObject *const*) routes->pdata, rts_cmp, routes->len, TRUE);

	for (i = 0; i < rts_n; i++) {
		g_assert (nmtstp_platform_ip4_route_delete (NM_PLATFORM_GET, IFINDEX,
		                                            rts_add[i].network, rts_add[i].plen,
		                                            rts_add[i].metric));
	}
#undef RTS_MAX
}

static void
test_ip6_route_get (void)
{
	int ifindex = nm_platform_link_get_ifindex (NM_PLATFORM_GET, DEVICE_NAME);
	const struct in6_addr *a;
	NMPlatformError result;
	nm_auto_nmpobj NMPObject *route = NULL;
	const NMPlatformIP6Route *r;

	nmtstp_run_command_check ("ip -6 route add fd01:abcd::/64 via fe80::99 dev %s", DEVICE_NAME);

	NMTST_WAIT_ASSERT (100, {
		nmtstp_wait_for_signal (NM_PLATFORM_GET, 10);
		if (nmtstp_ip6_route_get (NM_PLATFORM_GET, ifindex, nmtst_inet6_from_string ("fd01:abcd::"), 64, 0, NULL, 0))
			break;
	});

	a = nmtst_inet6_from_string ("fd01:abcd::42");
	result = nm_platform_ip_route_get (NM_PLATFORM_GET,
	                                   AF_INET6,
	                                   a,
	                                   nmtst_get_rand_int () % 2 ? 0 : ifindex,
	                                   &route);

	g_assert (result == NM_PLATFORM_ERROR_SUCCESS);
	g_assert (NMP_OBJECT_GET_TYPE (route) == NMP_OBJECT_TYPE_IP6_ROUTE);
	g_assert (!NMP_OBJECT_IS_STACKINIT (route));
	g_assert (route->parent._ref_count == 1);
	r = NMP_OBJECT_CAST_IP6_ROUTE (route);
	g_assert (r->ifindex == ifindex);
	nmtst_assert_ip6_address (&r->network, "fd01:abcd::42");
	g_assert_cmpint (r->plen, ==, 128);
	nmtst_assert_ip6_address (&r->gateway, "fe80::99");

	nmtstp_run_command_check ("ip -6 route flush dev %s", DEVICE_NAME);

	nmtstp_wait_for_signal (NM_PLATFORM_GET, 50);
}

static void
test_ip6_route_options (gconstpointer test_data)
{
	const int TEST_IDX = GPOINTER_TO_INT (test_data);
	const int IFINDEX = nm_platform_link_get_ifindex (NM_PLATFORM_GET, DEVICE_NAME);
	gs_unref_ptrarray GPtrArray *routes = NULL;
#define RTS_MAX 3
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
	case 3:
		addr[addr_n++] = ((NMPlatformIP6Address) {
			.ifindex = IFINDEX,
			.address = *nmtst_inet6_from_string ("2001:db8:8086::5"),
			.plen = 128,
			.peer_address = in6addr_any,
			.lifetime = NM_PLATFORM_LIFETIME_PERMANENT,
			.preferred = NM_PLATFORM_LIFETIME_PERMANENT,
			.n_ifa_flags = 0,
		});
		rts_add[rts_n++] = ((NMPlatformIP6Route) {
			.ifindex = IFINDEX,
			.rt_source = nmp_utils_ip_config_source_round_trip_rtprot (NM_IP_CONFIG_SOURCE_USER),
			.network = *nmtst_inet6_from_string ("2001:db8:8086::"),
			.plen = 110,
			.metric = 10021,
			.mss = 0,
		});
		rts_add[rts_n++] = ((NMPlatformIP6Route) {
			.ifindex = IFINDEX,
			.rt_source = nmp_utils_ip_config_source_round_trip_rtprot (NM_IP_CONFIG_SOURCE_USER),
			.network = *nmtst_inet6_from_string ("2001:db8:abad:c0de::"),
			.plen = 64,
			.gateway = *nmtst_inet6_from_string ("2001:db8:8086::1"),
			.metric = 21,
			.mss = 0,
		});
		break;
	default:
		g_assert_not_reached ();
	}
	g_assert (rts_n <= G_N_ELEMENTS (rts_add));
	g_assert (addr_n <= G_N_ELEMENTS (addr));

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
		g_assert (nm_platform_ip6_route_add (NM_PLATFORM_GET, NMP_NLM_FLAG_REPLACE, &rts_add[i]) == NM_PLATFORM_ERROR_SUCCESS);

	for (i = 0; i < rts_n; i++) {
		rts_cmp[i] = rts_add[i];
		nm_platform_ip_route_normalize (AF_INET6, NM_PLATFORM_IP_ROUTE_CAST (&rts_cmp[i]));
	}

	routes = nmtstp_ip6_route_get_all (NM_PLATFORM_GET, IFINDEX);
	g_assert_cmpint (routes->len, ==, rts_n);
	nmtst_platform_ip6_routes_equal_aptr ((const NMPObject *const*) routes->pdata, rts_cmp, routes->len, TRUE);

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
#undef RTS_MAX
}

/*****************************************************************************/

static void
test_ip (gconstpointer test_data)
{
	const int TEST_IDX = GPOINTER_TO_INT (test_data);
	const int IFINDEX = nm_platform_link_get_ifindex (NM_PLATFORM_GET, DEVICE_NAME);
	guint i, j, k;
	const NMPlatformLink *l;
	char ifname[IFNAMSIZ];
	char ifname2[IFNAMSIZ];
	char s1[NM_UTILS_INET_ADDRSTRLEN];
	NMPlatform *platform = NM_PLATFORM_GET;
	const int EX_ = -1;
	struct {
		int ifindex;
	} iface_data[10] = { 0 };
	int order_idx[G_N_ELEMENTS (iface_data)] = { 0 };
	guint order_len;
	guint try;

	for (i = 0; i < G_N_ELEMENTS (iface_data); i++) {
		nm_sprintf_buf (ifname, "v%02u", i);
		nm_sprintf_buf (ifname2, "w%02u", i);

		g_assert (!nm_platform_link_get_by_ifname (platform, ifname));
		g_assert (!nm_platform_link_get_by_ifname (platform, ifname2));
		l = nmtstp_link_veth_add (platform, EX_, ifname, ifname2);
		iface_data[i].ifindex = l->ifindex;

		nmtstp_link_set_updown (platform, EX_, iface_data[i].ifindex, TRUE);
		nmtstp_link_set_updown (platform, EX_, nmtstp_link_get (platform, -1, ifname2)->ifindex, TRUE);

		nm_sprintf_buf (s1, "192.168.7.%d", 100 + i);
		nmtstp_ip4_address_add (platform,
		                        EX_,
		                        iface_data[i].ifindex,
		                        nmtst_inet4_from_string (s1),
		                        24,
		                        nmtst_inet4_from_string (s1),
		                        3600,
		                        3600,
		                        0,
		                        NULL);
	}

	order_len = 0;
	for (try = 0; try < 5 * G_N_ELEMENTS (order_idx); try++) {
		NMPObject o;
		NMPlatformIP4Route *r;
		guint idx;
		const NMDedupMultiHeadEntry *head_entry;
		NMPLookup lookup;

		nmp_object_stackinit (&o, NMP_OBJECT_TYPE_IP4_ROUTE, NULL);
		r = NMP_OBJECT_CAST_IP4_ROUTE (&o);
		r->network = nmtst_inet4_from_string ("192.168.9.0");
		r->plen = 24;
		r->metric = 109;

		if (   order_len == 0
		    || (   order_len < G_N_ELEMENTS (order_idx)
		        && nmtst_get_rand_int () % 2)) {
again_find_idx:
			idx = nmtst_get_rand_int () % G_N_ELEMENTS (iface_data);
			for (i = 0; i < order_len; i++) {
				if (order_idx[i] == idx)
					goto again_find_idx;
			}
			order_idx[order_len++] = idx;

			r->ifindex = iface_data[idx].ifindex;
			g_assert (nm_platform_ip4_route_add (platform, NMP_NLM_FLAG_APPEND, r) == NM_PLATFORM_ERROR_SUCCESS);
		} else {
			i = nmtst_get_rand_int () % order_len;
			idx = order_idx[i];
			for (i++; i < order_len; i++)
				order_idx[i - 1] = order_idx[i];
			order_len--;

			r->ifindex = iface_data[idx].ifindex;
			g_assert (nm_platform_object_delete (platform, &o));
		}

		head_entry = nm_platform_lookup (platform,
		                                 nmp_lookup_init_obj_type (&lookup, NMP_OBJECT_TYPE_IP4_ROUTE));
		for (j = 0; j < G_N_ELEMENTS (iface_data); j++) {
			gboolean has;
			NMDedupMultiIter iter;
			const NMPObject *o_cached;

			has = FALSE;
			for (k = 0; k < order_len; k++) {
				if (order_idx[k] == j) {
					g_assert (!has);
					has = TRUE;
				}
			}

			nmp_cache_iter_for_each (&iter, head_entry, &o_cached) {
				const NMPlatformIP4Route *r_cached = NMP_OBJECT_CAST_IP4_ROUTE (o_cached);

				if (   r_cached->ifindex != iface_data[j].ifindex
				    || r_cached->metric != 109)
					continue;

				g_assert (has);
				has = FALSE;
			}
			g_assert (!has);
		}
	}

	for (i = 0; i < G_N_ELEMENTS (iface_data); i++)
		g_assert (nm_platform_link_delete (platform, iface_data[i].ifindex));

	(void) TEST_IDX;
	(void) IFINDEX;
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
	add_test_func_data ("/route/ip4_options/1", test_ip4_route_options, GINT_TO_POINTER (1));
	if (nmtstp_is_root_test ())
		add_test_func_data ("/route/ip4_options/2", test_ip4_route_options, GINT_TO_POINTER (2));
	add_test_func_data ("/route/ip6_options/1", test_ip6_route_options, GINT_TO_POINTER (1));
	add_test_func_data ("/route/ip6_options/2", test_ip6_route_options, GINT_TO_POINTER (2));
	add_test_func_data ("/route/ip6_options/3", test_ip6_route_options, GINT_TO_POINTER (3));

	if (nmtstp_is_root_test ()) {
		add_test_func_data ("/route/ip/1", test_ip, GINT_TO_POINTER (1));
		add_test_func ("/route/ip4_route_get", test_ip4_route_get);
		add_test_func ("/route/ip6_route_get", test_ip6_route_get);
		add_test_func ("/route/ip4_zero_gateway", test_ip4_zero_gateway);
	}
}
