/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2016 - 2017 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include <linux/rtnetlink.h>
#include <linux/fib_rules.h>

#include "nm-core-utils.h"
#include "libnm-platform/nm-platform-utils.h"
#include "libnm-platform/nmp-global-tracker.h"

#include "test-common.h"

#define DEVICE_IFINDEX NMTSTP_ENV1_IFINDEX
#define EX             NMTSTP_ENV1_EX

static void
_wait_for_ipv4_addr_device_route(NMPlatform *platform,
                                 gint64      timeout_msec,
                                 int         ifindex,
                                 in_addr_t   addr,
                                 guint8      plen)
{
    /* Wait that the addresses gets a device-route. After adding a address,
     * the device route is not added immediately. It takes a moment... */

    addr = nm_ip4_addr_clear_host_address(addr, plen);
    NMTST_WAIT_ASSERT(400, {
        NMDedupMultiIter iter;
        NMPLookup        lookup;
        const NMPObject *o;

        nmp_cache_iter_for_each (
            &iter,
            nm_platform_lookup(
                platform,
                nmp_lookup_init_object_by_ifindex(&lookup, NMP_OBJECT_TYPE_IP4_ROUTE, ifindex)),
            &o) {
            const NMPlatformIP4Route *r = NMP_OBJECT_CAST_IP4_ROUTE(o);

            if (r->plen == plen && addr == nm_ip4_addr_clear_host_address(r->network, plen)
                && r->metric == 0 && r->scope_inv == nm_platform_route_scope_inv(RT_SCOPE_LINK)
                && r->rt_source == NM_IP_CONFIG_SOURCE_RTPROT_KERNEL)
                return;
        }
        nmtstp_assert_wait_for_signal(platform,
                                      (nmtst_wait_end_us - g_get_monotonic_time()) / 1000);
    });
}

static void
_wait_for_ipv6_addr_non_tentative(NMPlatform            *platform,
                                  gint64                 timeout_msec,
                                  int                    ifindex,
                                  guint                  addr_n,
                                  const struct in6_addr *addrs)
{
    guint i;

    /* Wait that the addresses become non-tentative.  Dummy interfaces are NOARP
     * and thus don't do DAD, but the kernel sets the address as tentative for a
     * small amount of time, which prevents the immediate addition of the route
     * with RTA_PREFSRC */

    NMTST_WAIT_ASSERT(timeout_msec, {
        gboolean                    should_wait = FALSE;
        const NMPlatformIP6Address *plt_addr;

        for (i = 0; i < addr_n; i++) {
            plt_addr = nm_platform_ip6_address_get(platform, ifindex, &addrs[i]);
            if (!plt_addr || NM_FLAGS_HAS(plt_addr->n_ifa_flags, IFA_F_TENTATIVE)) {
                should_wait = TRUE;
                break;
            }
        }
        if (!should_wait)
            return;
        nmtstp_assert_wait_for_signal(platform,
                                      (nmtst_wait_end_us - g_get_monotonic_time()) / 1000);
    });
}

static void
ip4_route_callback(NMPlatform               *platform,
                   int                       obj_type_i,
                   int                       ifindex,
                   const NMPlatformIP4Route *received,
                   int                       change_type_i,
                   SignalData               *data)
{
    const NMPObjectType              obj_type    = obj_type_i;
    const NMPlatformSignalChangeType change_type = change_type_i;
    NMPObject                        o_id;
    nm_auto_nmpobj NMPObject        *o_id_p = nmp_object_new(NMP_OBJECT_TYPE_IP4_ROUTE, NULL);

    g_assert_cmpint(obj_type, ==, NMP_OBJECT_TYPE_IP4_ROUTE);
    g_assert(received);
    g_assert_cmpint(received->ifindex, ==, ifindex);
    g_assert(data && data->name);
    g_assert_cmpstr(data->name, ==, NM_PLATFORM_SIGNAL_IP4_ROUTE_CHANGED);

    /* run code for initializing the ID only */
    nmp_object_stackinit_id(&o_id, NMP_OBJECT_UP_CAST(received));
    nmp_object_copy(o_id_p, NMP_OBJECT_UP_CAST(received), TRUE);
    nmp_object_copy(o_id_p, NMP_OBJECT_UP_CAST(received), FALSE);

    if (data->ifindex && data->ifindex != received->ifindex)
        return;
    if (data->change_type != change_type)
        return;

    if (data->loop)
        g_main_loop_quit(data->loop);

    data->received_count++;
    _LOGD("Received signal '%s' %dth time.", data->name, data->received_count);
}

static void
ip6_route_callback(NMPlatform               *platform,
                   int                       obj_type_i,
                   int                       ifindex,
                   const NMPlatformIP6Route *received,
                   int                       change_type_i,
                   SignalData               *data)
{
    const NMPObjectType              obj_type    = obj_type_i;
    const NMPlatformSignalChangeType change_type = change_type_i;
    NMPObject                        o_id;
    nm_auto_nmpobj NMPObject        *o_id_p = nmp_object_new(NMP_OBJECT_TYPE_IP6_ROUTE, NULL);

    g_assert_cmpint(obj_type, ==, NMP_OBJECT_TYPE_IP6_ROUTE);
    g_assert(received);
    g_assert_cmpint(received->ifindex, ==, ifindex);
    g_assert(data && data->name);
    g_assert_cmpstr(data->name, ==, NM_PLATFORM_SIGNAL_IP6_ROUTE_CHANGED);

    /* run code for initializing the ID only */
    nmp_object_stackinit_id(&o_id, NMP_OBJECT_UP_CAST(received));
    nmp_object_copy(o_id_p, NMP_OBJECT_UP_CAST(received), TRUE);
    nmp_object_copy(o_id_p, NMP_OBJECT_UP_CAST(received), FALSE);

    if (data->ifindex && data->ifindex != received->ifindex)
        return;
    if (data->change_type != change_type)
        return;

    if (data->loop)
        g_main_loop_quit(data->loop);

    data->received_count++;
    _LOGD("Received signal '%s' %dth time.", data->name, data->received_count);
}

static void
test_ip4_route_metric0(void)
{
    int         ifindex       = nm_platform_link_get_ifindex(NM_PLATFORM_GET, DEVICE_NAME);
    SignalData *route_added   = add_signal(NM_PLATFORM_SIGNAL_IP4_ROUTE_CHANGED,
                                         NM_PLATFORM_SIGNAL_ADDED,
                                         ip4_route_callback);
    SignalData *route_changed = add_signal(NM_PLATFORM_SIGNAL_IP4_ROUTE_CHANGED,
                                           NM_PLATFORM_SIGNAL_CHANGED,
                                           ip4_route_callback);
    SignalData *route_removed = add_signal(NM_PLATFORM_SIGNAL_IP4_ROUTE_CHANGED,
                                           NM_PLATFORM_SIGNAL_REMOVED,
                                           ip4_route_callback);
    in_addr_t   network =
        nmtst_inet4_from_string("192.0.2.5"); /* from 192.0.2.0/24 (TEST-NET-1) (rfc5737) */
    int plen   = 32;
    int metric = 22987;
    int mss    = 1000;

    /* No routes initially */
    nmtstp_assert_ip4_route_exists(NULL, 0, DEVICE_NAME, network, plen, 0, 0);
    nmtstp_assert_ip4_route_exists(NULL, 0, DEVICE_NAME, network, plen, metric, 0);

    /* add the first route */
    nmtstp_ip4_route_add(NM_PLATFORM_GET,
                         ifindex,
                         NM_IP_CONFIG_SOURCE_USER,
                         network,
                         plen,
                         INADDR_ANY,
                         0,
                         metric,
                         mss);
    accept_signal(route_added);

    nmtstp_assert_ip4_route_exists(NULL, 0, DEVICE_NAME, network, plen, 0, 0);
    nmtstp_assert_ip4_route_exists(NULL, 1, DEVICE_NAME, network, plen, metric, 0);

    /* Deleting route with metric 0 does nothing */
    g_assert(nmtstp_platform_ip4_route_delete(NM_PLATFORM_GET, ifindex, network, plen, 0));
    ensure_no_signal(route_removed);

    nmtstp_assert_ip4_route_exists(NULL, 0, DEVICE_NAME, network, plen, 0, 0);
    nmtstp_assert_ip4_route_exists(NULL, 1, DEVICE_NAME, network, plen, metric, 0);

    /* add the second route */
    nmtstp_ip4_route_add(NM_PLATFORM_GET,
                         ifindex,
                         NM_IP_CONFIG_SOURCE_USER,
                         network,
                         plen,
                         INADDR_ANY,
                         0,
                         0,
                         mss);
    accept_signal(route_added);

    nmtstp_assert_ip4_route_exists(NULL, 1, DEVICE_NAME, network, plen, 0, 0);
    nmtstp_assert_ip4_route_exists(NULL, 1, DEVICE_NAME, network, plen, metric, 0);

    /* Delete route with metric 0 */
    g_assert(nmtstp_platform_ip4_route_delete(NM_PLATFORM_GET, ifindex, network, plen, 0));
    accept_signal(route_removed);

    nmtstp_assert_ip4_route_exists(NULL, 0, DEVICE_NAME, network, plen, 0, 0);
    nmtstp_assert_ip4_route_exists(NULL, 1, DEVICE_NAME, network, plen, metric, 0);

    /* Delete route with metric 0 again (we expect nothing to happen) */
    g_assert(nmtstp_platform_ip4_route_delete(NM_PLATFORM_GET, ifindex, network, plen, 0));
    ensure_no_signal(route_removed);

    nmtstp_assert_ip4_route_exists(NULL, 0, DEVICE_NAME, network, plen, 0, 0);
    nmtstp_assert_ip4_route_exists(NULL, 1, DEVICE_NAME, network, plen, metric, 0);

    /* Delete the other route */
    g_assert(nmtstp_platform_ip4_route_delete(NM_PLATFORM_GET, ifindex, network, plen, metric));
    accept_signal(route_removed);

    nmtstp_assert_ip4_route_exists(NULL, 0, DEVICE_NAME, network, plen, 0, 0);
    nmtstp_assert_ip4_route_exists(NULL, 0, DEVICE_NAME, network, plen, metric, 0);

    free_signal(route_added);
    free_signal(route_changed);
    free_signal(route_removed);
}

static void
test_ip4_route(void)
{
    int                ifindex       = nm_platform_link_get_ifindex(NM_PLATFORM_GET, DEVICE_NAME);
    SignalData        *route_added   = add_signal(NM_PLATFORM_SIGNAL_IP4_ROUTE_CHANGED,
                                         NM_PLATFORM_SIGNAL_ADDED,
                                         ip4_route_callback);
    SignalData        *route_changed = add_signal(NM_PLATFORM_SIGNAL_IP4_ROUTE_CHANGED,
                                           NM_PLATFORM_SIGNAL_CHANGED,
                                           ip4_route_callback);
    SignalData        *route_removed = add_signal(NM_PLATFORM_SIGNAL_IP4_ROUTE_CHANGED,
                                           NM_PLATFORM_SIGNAL_REMOVED,
                                           ip4_route_callback);
    GPtrArray         *routes;
    NMPlatformIP4Route rts[3];
    in_addr_t          network;
    guint8             plen = 24;
    in_addr_t          gateway;
    /* Choose a high metric so that we hopefully don't conflict. */
    int metric = 22986;
    int mss    = 1000;

    inet_pton(AF_INET, "192.0.3.0", &network);
    inet_pton(AF_INET, "198.51.100.1", &gateway);

    /* Add route to gateway */
    nmtstp_ip4_route_add(NM_PLATFORM_GET,
                         ifindex,
                         NM_IP_CONFIG_SOURCE_USER,
                         gateway,
                         32,
                         INADDR_ANY,
                         0,
                         metric,
                         mss);
    accept_signal(route_added);

    /* Add route */
    nmtstp_assert_ip4_route_exists(NULL, 0, DEVICE_NAME, network, plen, metric, 0);
    nmtstp_ip4_route_add(NM_PLATFORM_GET,
                         ifindex,
                         NM_IP_CONFIG_SOURCE_USER,
                         network,
                         plen,
                         gateway,
                         0,
                         metric,
                         mss);
    nmtstp_assert_ip4_route_exists(NULL, 1, DEVICE_NAME, network, plen, metric, 0);
    accept_signal(route_added);

    /* Add route again */
    nmtstp_ip4_route_add(NM_PLATFORM_GET,
                         ifindex,
                         NM_IP_CONFIG_SOURCE_USER,
                         network,
                         plen,
                         gateway,
                         0,
                         metric,
                         mss);
    accept_signals(route_changed, 0, 1);

    /* Add default route */
    nmtstp_assert_ip4_route_exists(NULL, 0, DEVICE_NAME, 0, 0, metric, 0);
    nmtstp_ip4_route_add(NM_PLATFORM_GET,
                         ifindex,
                         NM_IP_CONFIG_SOURCE_USER,
                         0,
                         0,
                         gateway,
                         0,
                         metric,
                         mss);
    nmtstp_assert_ip4_route_exists(NULL, 1, DEVICE_NAME, 0, 0, metric, 0);
    accept_signal(route_added);

    /* Add default route again */
    nmtstp_ip4_route_add(NM_PLATFORM_GET,
                         ifindex,
                         NM_IP_CONFIG_SOURCE_USER,
                         0,
                         0,
                         gateway,
                         0,
                         metric,
                         mss);
    accept_signals(route_changed, 0, 1);

    /* Test route listing */
    routes = nmtstp_ip4_route_get_all(NM_PLATFORM_GET, ifindex);
    memset(rts, 0, sizeof(rts));
    rts[0].rt_source  = nmp_utils_ip_config_source_round_trip_rtprot(NM_IP_CONFIG_SOURCE_USER);
    rts[0].network    = gateway;
    rts[0].plen       = 32;
    rts[0].ifindex    = ifindex;
    rts[0].gateway    = INADDR_ANY;
    rts[0].metric     = metric;
    rts[0].mss        = mss;
    rts[0].scope_inv  = nm_platform_route_scope_inv(RT_SCOPE_LINK);
    rts[0].n_nexthops = 1;
    rts[1].rt_source  = nmp_utils_ip_config_source_round_trip_rtprot(NM_IP_CONFIG_SOURCE_USER);
    rts[1].network    = network;
    rts[1].plen       = plen;
    rts[1].ifindex    = ifindex;
    rts[1].gateway    = gateway;
    rts[1].metric     = metric;
    rts[1].mss        = mss;
    rts[1].scope_inv  = nm_platform_route_scope_inv(RT_SCOPE_UNIVERSE);
    rts[1].n_nexthops = 1;
    rts[2].rt_source  = nmp_utils_ip_config_source_round_trip_rtprot(NM_IP_CONFIG_SOURCE_USER);
    rts[2].network    = 0;
    rts[2].plen       = 0;
    rts[2].ifindex    = ifindex;
    rts[2].gateway    = gateway;
    rts[2].metric     = metric;
    rts[2].mss        = mss;
    rts[2].scope_inv  = nm_platform_route_scope_inv(RT_SCOPE_UNIVERSE);
    rts[2].n_nexthops = 1;
    g_assert_cmpint(routes->len, ==, 3);
    nmtst_platform_ip4_routes_equal_aptr((const NMPObject *const *) routes->pdata,
                                         rts,
                                         routes->len,
                                         TRUE);
    g_ptr_array_unref(routes);

    /* Remove route */
    g_assert(nmtstp_platform_ip4_route_delete(NM_PLATFORM_GET, ifindex, network, plen, metric));
    nmtstp_assert_ip4_route_exists(NULL, 0, DEVICE_NAME, network, plen, metric, 0);
    accept_signal(route_removed);

    /* Remove route again */
    g_assert(nmtstp_platform_ip4_route_delete(NM_PLATFORM_GET, ifindex, network, plen, metric));

    /* Remove default route */
    g_assert(nmtstp_platform_ip4_route_delete(NM_PLATFORM_GET, ifindex, 0, 0, metric));
    accept_signal(route_removed);

    /* Remove route to gateway */
    g_assert(nmtstp_platform_ip4_route_delete(NM_PLATFORM_GET, ifindex, gateway, 32, metric));
    accept_signal(route_removed);

    free_signal(route_added);
    free_signal(route_changed);
    free_signal(route_removed);
}

static void
test_ip6_route(void)
{
    int                ifindex       = nm_platform_link_get_ifindex(NM_PLATFORM_GET, DEVICE_NAME);
    SignalData        *route_added   = add_signal(NM_PLATFORM_SIGNAL_IP6_ROUTE_CHANGED,
                                         NM_PLATFORM_SIGNAL_ADDED,
                                         ip6_route_callback);
    SignalData        *route_changed = add_signal(NM_PLATFORM_SIGNAL_IP6_ROUTE_CHANGED,
                                           NM_PLATFORM_SIGNAL_CHANGED,
                                           ip6_route_callback);
    SignalData        *route_removed = add_signal(NM_PLATFORM_SIGNAL_IP6_ROUTE_CHANGED,
                                           NM_PLATFORM_SIGNAL_REMOVED,
                                           ip6_route_callback);
    GPtrArray         *routes;
    NMPlatformIP6Route rts[3];
    struct in6_addr    network;
    guint8             plen = 64;
    struct in6_addr    gateway, pref_src;
    /* Choose a high metric so that we hopefully don't conflict. */
    const int metric = 22987;
    int       mss    = 1000;

    inet_pton(AF_INET6, "2001:db8:a:b:0:0:0:0", &network);
    inet_pton(AF_INET6, "2001:db8:c:d:1:2:3:4", &gateway);
    inet_pton(AF_INET6, "::42", &pref_src);

    g_assert(nm_platform_ip6_address_add(NM_PLATFORM_GET,
                                         ifindex,
                                         pref_src,
                                         128,
                                         in6addr_any,
                                         NM_PLATFORM_LIFETIME_PERMANENT,
                                         NM_PLATFORM_LIFETIME_PERMANENT,
                                         0));
    accept_signals(route_added, 0, 3);

    _wait_for_ipv6_addr_non_tentative(NM_PLATFORM_GET, 200, ifindex, 1, &pref_src);

    /* Add route to gateway */
    nmtstp_ip6_route_add(NM_PLATFORM_GET,
                         ifindex,
                         NM_IP_CONFIG_SOURCE_USER,
                         gateway,
                         128,
                         in6addr_any,
                         in6addr_any,
                         metric,
                         mss);
    accept_signals(route_added, 0, 3);

    /* Add route */
    g_assert(!nmtstp_ip6_route_get(NM_PLATFORM_GET, ifindex, &network, plen, metric, NULL, 0));
    nmtstp_ip6_route_add(NM_PLATFORM_GET,
                         ifindex,
                         NM_IP_CONFIG_SOURCE_USER,
                         network,
                         plen,
                         gateway,
                         pref_src,
                         metric,
                         mss);
    g_assert(nmtstp_ip6_route_get(NM_PLATFORM_GET, ifindex, &network, plen, metric, NULL, 0));
    accept_signals(route_added, 1, 2);

    /* Add route again */
    nmtstp_ip6_route_add(NM_PLATFORM_GET,
                         ifindex,
                         NM_IP_CONFIG_SOURCE_USER,
                         network,
                         plen,
                         gateway,
                         pref_src,
                         metric,
                         mss);
    accept_signals(route_changed, 0, 1);

    /* Add default route */
    g_assert(!nmtstp_ip6_route_get(NM_PLATFORM_GET, ifindex, &in6addr_any, 0, metric, NULL, 0));
    nmtstp_ip6_route_add(NM_PLATFORM_GET,
                         ifindex,
                         NM_IP_CONFIG_SOURCE_USER,
                         in6addr_any,
                         0,
                         gateway,
                         in6addr_any,
                         metric,
                         mss);
    g_assert(nmtstp_ip6_route_get(NM_PLATFORM_GET, ifindex, &in6addr_any, 0, metric, NULL, 0));
    accept_signal(route_added);

    /* Add default route again */
    nmtstp_ip6_route_add(NM_PLATFORM_GET,
                         ifindex,
                         NM_IP_CONFIG_SOURCE_USER,
                         in6addr_any,
                         0,
                         gateway,
                         in6addr_any,
                         metric,
                         mss);
    accept_signals(route_changed, 0, 1);

    /* Test route listing */
    routes = nmtstp_ip6_route_get_all(NM_PLATFORM_GET, ifindex);
    memset(rts, 0, sizeof(rts));
    rts[0].rt_source = nmp_utils_ip_config_source_round_trip_rtprot(NM_IP_CONFIG_SOURCE_USER);
    rts[0].network   = gateway;
    rts[0].plen      = 128;
    rts[0].ifindex   = ifindex;
    rts[0].gateway   = in6addr_any;
    rts[0].pref_src  = in6addr_any;
    rts[0].metric    = metric;
    rts[0].mss       = mss;
    rts[1].rt_source = nmp_utils_ip_config_source_round_trip_rtprot(NM_IP_CONFIG_SOURCE_USER);
    rts[1].network   = network;
    rts[1].plen      = plen;
    rts[1].ifindex   = ifindex;
    rts[1].gateway   = gateway;
    rts[1].pref_src  = pref_src;
    rts[1].metric    = metric;
    rts[1].mss       = mss;
    rts[2].rt_source = nmp_utils_ip_config_source_round_trip_rtprot(NM_IP_CONFIG_SOURCE_USER);
    rts[2].network   = in6addr_any;
    rts[2].plen      = 0;
    rts[2].ifindex   = ifindex;
    rts[2].gateway   = gateway;
    rts[2].pref_src  = in6addr_any;
    rts[2].metric    = metric;
    rts[2].mss       = mss;
    g_assert_cmpint(routes->len, ==, 3);
    nmtst_platform_ip6_routes_equal_aptr((const NMPObject *const *) routes->pdata,
                                         rts,
                                         routes->len,
                                         TRUE);
    g_ptr_array_unref(routes);

    /* Remove route */
    g_assert(nmtstp_platform_ip6_route_delete(NM_PLATFORM_GET, ifindex, network, plen, metric));
    g_assert(!nmtstp_ip6_route_get(NM_PLATFORM_GET, ifindex, &network, plen, metric, NULL, 0));
    accept_signal(route_removed);

    /* Remove route again */
    g_assert(nmtstp_platform_ip6_route_delete(NM_PLATFORM_GET, ifindex, network, plen, metric));

    /* Remove default route */
    g_assert(nmtstp_platform_ip6_route_delete(NM_PLATFORM_GET, ifindex, in6addr_any, 0, metric));
    accept_signal(route_removed);

    /* Remove route to gateway */
    g_assert(nmtstp_platform_ip6_route_delete(NM_PLATFORM_GET, ifindex, gateway, 128, metric));
    accept_signal(route_removed);

    free_signal(route_added);
    free_signal(route_changed);
    free_signal(route_removed);
}

/*****************************************************************************/

static void
test_ip4_route_get(void)
{
    int                       ifindex = nm_platform_link_get_ifindex(NM_PLATFORM_GET, DEVICE_NAME);
    in_addr_t                 a;
    int                       result;
    nm_auto_nmpobj NMPObject *route = NULL;
    const NMPlatformIP4Route *r;

    nmtstp_run_command_check("ip route add 1.2.3.0/24 dev %s", DEVICE_NAME);

    NMTST_WAIT_ASSERT(100, {
        nmtstp_wait_for_signal(NM_PLATFORM_GET, 10);
        if (nmtstp_ip4_route_get(NM_PLATFORM_GET,
                                 ifindex,
                                 nmtst_inet4_from_string("1.2.3.0"),
                                 24,
                                 0,
                                 0))
            break;
    });

    a      = nmtst_inet4_from_string("1.2.3.1");
    result = nm_platform_ip_route_get(NM_PLATFORM_GET,
                                      AF_INET,
                                      &a,
                                      nmtst_get_rand_uint32() % 2 ? 0 : ifindex,
                                      &route);

    g_assert(NMTST_NM_ERR_SUCCESS(result));
    g_assert(NMP_OBJECT_GET_TYPE(route) == NMP_OBJECT_TYPE_IP4_ROUTE);
    g_assert(!NMP_OBJECT_IS_STACKINIT(route));
    g_assert(route->parent._ref_count == 1);
    r = NMP_OBJECT_CAST_IP4_ROUTE(route);
    g_assert(NM_FLAGS_HAS(r->r_rtm_flags, RTM_F_CLONED));
    g_assert(r->ifindex == ifindex);
    g_assert(r->network == a);
    g_assert(r->plen == 32);

    nmtstp_run_command_check("ip route flush dev %s", DEVICE_NAME);

    nmtstp_wait_for_signal(NM_PLATFORM_GET, 50);
}

static void
test_ip4_zero_gateway(void)
{
    int ifindex = nm_platform_link_get_ifindex(NM_PLATFORM_GET, DEVICE_NAME);

    nmtstp_run_command_check("ip route add 1.2.3.1/32 via 0.0.0.0 dev %s", DEVICE_NAME);
    nmtstp_run_command_check("ip route add 1.2.3.2/32 dev %s", DEVICE_NAME);

    NMTST_WAIT_ASSERT(100, {
        nmtstp_wait_for_signal(NM_PLATFORM_GET, 10);
        if (nmtstp_ip4_route_get(NM_PLATFORM_GET,
                                 ifindex,
                                 nmtst_inet4_from_string("1.2.3.1"),
                                 32,
                                 0,
                                 0)
            && nmtstp_ip4_route_get(NM_PLATFORM_GET,
                                    ifindex,
                                    nmtst_inet4_from_string("1.2.3.2"),
                                    32,
                                    0,
                                    0))
            break;
    });

    nmtstp_run_command_check("ip route flush dev %s", DEVICE_NAME);

    nmtstp_wait_for_signal(NM_PLATFORM_GET, 50);
}

static void
test_ip4_route_options(gconstpointer test_data)
{
    const int TEST_IDX = GPOINTER_TO_INT(test_data);
    const int IFINDEX  = nm_platform_link_get_ifindex(NM_PLATFORM_GET, DEVICE_NAME);
    gs_unref_ptrarray GPtrArray *routes = NULL;
#define RTS_MAX 3
    NMPlatformIP4Route   rts_add[RTS_MAX] = {};
    NMPlatformIP4Route   rts_cmp[RTS_MAX] = {};
    NMPlatformIP4Address addr[1]          = {};
    guint                i;
    guint                rts_n  = 0;
    guint                addr_n = 0;

    switch (TEST_IDX) {
    case 1:
        rts_add[rts_n++] = ((NMPlatformIP4Route){
            .ifindex    = IFINDEX,
            .rt_source  = NM_IP_CONFIG_SOURCE_USER,
            .network    = nmtst_inet4_from_string("172.16.1.0"),
            .plen       = 24,
            .metric     = 20,
            .tos        = 0x28,
            .window     = 10000,
            .cwnd       = 16,
            .initcwnd   = 30,
            .initrwnd   = 50,
            .mtu        = 1350,
            .lock_cwnd  = TRUE,
            .mss        = 1300,
            .quickack   = TRUE,
            .rto_min    = 1000,
            .n_nexthops = 1,
        });
        break;
    case 2:
        addr[addr_n++]   = ((NMPlatformIP4Address){
              .ifindex      = IFINDEX,
              .address      = nmtst_inet4_from_string("172.16.1.5"),
              .peer_address = nmtst_inet4_from_string("172.16.1.5"),
              .plen         = 24,
              .lifetime     = NM_PLATFORM_LIFETIME_PERMANENT,
              .preferred    = NM_PLATFORM_LIFETIME_PERMANENT,
              .n_ifa_flags  = 0,
        });
        rts_add[rts_n++] = ((NMPlatformIP4Route){
            .ifindex    = IFINDEX,
            .rt_source  = NM_IP_CONFIG_SOURCE_USER,
            .network    = nmtst_inet4_from_string("172.17.1.0"),
            .gateway    = nmtst_inet4_from_string("172.16.1.1"),
            .plen       = 24,
            .metric     = 20,
            .n_nexthops = 1,
        });
        rts_add[rts_n++] = ((NMPlatformIP4Route){
            .ifindex     = IFINDEX,
            .rt_source   = NM_IP_CONFIG_SOURCE_USER,
            .network     = nmtst_inet4_from_string("172.19.1.0"),
            .gateway     = nmtst_inet4_from_string("172.18.1.1"),
            .r_rtm_flags = RTNH_F_ONLINK,
            .plen        = 24,
            .metric      = 20,
            .n_nexthops  = 1,
        });
        break;
    default:
        g_assert_not_reached();
        break;
    }
    g_assert(rts_n <= G_N_ELEMENTS(rts_add));
    g_assert(addr_n <= G_N_ELEMENTS(addr));

    for (i = 0; i < addr_n; i++) {
        const NMPlatformIP4Address *a = &addr[i];

        g_assert(a->ifindex == IFINDEX);
        g_assert(nm_platform_ip4_address_add(NM_PLATFORM_GET,
                                             a->ifindex,
                                             a->address,
                                             a->plen,
                                             a->peer_address,
                                             nm_ip4_addr_get_broadcast_address(a->address, a->plen),
                                             a->lifetime,
                                             a->preferred,
                                             a->n_ifa_flags,
                                             a->label));
        if (a->peer_address == a->address)
            _wait_for_ipv4_addr_device_route(NM_PLATFORM_GET, 200, a->ifindex, a->address, a->plen);
    }

    for (i = 0; i < rts_n; i++)
        g_assert(NMTST_NM_ERR_SUCCESS(
            nm_platform_ip4_route_add(NM_PLATFORM_GET, NMP_NLM_FLAG_REPLACE, &rts_add[i], NULL)));

    for (i = 0; i < rts_n; i++) {
        rts_cmp[i] = rts_add[i];
        nm_platform_ip_route_normalize(AF_INET, NM_PLATFORM_IP_ROUTE_CAST(&rts_cmp[i]));
    }

    routes = nmtstp_ip4_route_get_all(NM_PLATFORM_GET, IFINDEX);
    g_assert_cmpint(routes->len, ==, rts_n);
    nmtst_platform_ip4_routes_equal_aptr((const NMPObject *const *) routes->pdata,
                                         rts_cmp,
                                         routes->len,
                                         TRUE);

    for (i = 0; i < rts_n; i++) {
        g_assert(nmtstp_platform_ip4_route_delete(NM_PLATFORM_GET,
                                                  IFINDEX,
                                                  rts_add[i].network,
                                                  rts_add[i].plen,
                                                  rts_add[i].metric));
    }
#undef RTS_MAX
}

static void
test_ip6_route_get(void)
{
    int                       ifindex = nm_platform_link_get_ifindex(NM_PLATFORM_GET, DEVICE_NAME);
    const struct in6_addr    *a;
    int                       result;
    nm_auto_nmpobj NMPObject *route = NULL;
    const NMPlatformIP6Route *r;

    nmtstp_run_command_check("ip -6 route add fd01:abcd::/64 via fe80::99 dev %s", DEVICE_NAME);

    NMTST_WAIT_ASSERT(100, {
        nmtstp_wait_for_signal(NM_PLATFORM_GET, 10);
        if (nmtstp_ip6_route_get(NM_PLATFORM_GET,
                                 ifindex,
                                 nmtst_inet6_from_string_p("fd01:abcd::"),
                                 64,
                                 NM_PLATFORM_ROUTE_METRIC_DEFAULT_IP6,
                                 NULL,
                                 0))
            break;
    });

    a      = nmtst_inet6_from_string_p("fd01:abcd::42");
    result = nm_platform_ip_route_get(NM_PLATFORM_GET,
                                      AF_INET6,
                                      a,
                                      nmtst_get_rand_uint32() % 2 ? 0 : ifindex,
                                      &route);

    g_assert(NMTST_NM_ERR_SUCCESS(result));
    g_assert(NMP_OBJECT_GET_TYPE(route) == NMP_OBJECT_TYPE_IP6_ROUTE);
    g_assert(!NMP_OBJECT_IS_STACKINIT(route));
    g_assert(route->parent._ref_count == 1);
    r = NMP_OBJECT_CAST_IP6_ROUTE(route);
    g_assert(r->ifindex == ifindex);
    nmtst_assert_ip6_address(&r->network, "fd01:abcd::42");
    g_assert_cmpint(r->plen, ==, 128);
    nmtst_assert_ip6_address(&r->gateway, "fe80::99");

    nmtstp_run_command_check("ip -6 route flush dev %s", DEVICE_NAME);

    nmtstp_wait_for_signal(NM_PLATFORM_GET, 50);
}

static void
test_ip6_route_options(gconstpointer test_data)
{
    const int TEST_IDX = GPOINTER_TO_INT(test_data);
    const int IFINDEX  = nm_platform_link_get_ifindex(NM_PLATFORM_GET, DEVICE_NAME);
    gs_unref_ptrarray GPtrArray *routes = NULL;
#define RTS_MAX 3
    NMPlatformIP6Route   rts_add[RTS_MAX]             = {};
    NMPlatformIP6Route   rts_cmp[RTS_MAX]             = {};
    NMPlatformIP6Address addr[1]                      = {};
    struct in6_addr      addr_in6[G_N_ELEMENTS(addr)] = {};
    guint                rts_n                        = 0;
    guint                addr_n                       = 0;
    guint                i;

    switch (TEST_IDX) {
    case 1:
        rts_add[rts_n++] = ((NMPlatformIP6Route){
            .ifindex   = IFINDEX,
            .rt_source = NM_IP_CONFIG_SOURCE_USER,
            .network   = nmtst_inet6_from_string("2001:db8:a:b:0:0:0:0"),
            .plen      = 64,
            .gateway   = in6addr_any,
            .metric    = 1024,
            .window    = 20000,
            .cwnd      = 8,
            .initcwnd  = 22,
            .initrwnd  = 33,
            .mtu       = 1300,
            .lock_mtu  = TRUE,
        });
        break;
    case 2:
        addr[addr_n++]   = ((NMPlatformIP6Address){
              .ifindex      = IFINDEX,
              .address      = nmtst_inet6_from_string("2000::2"),
              .plen         = 128,
              .peer_address = in6addr_any,
              .lifetime     = NM_PLATFORM_LIFETIME_PERMANENT,
              .preferred    = NM_PLATFORM_LIFETIME_PERMANENT,
              .n_ifa_flags  = 0,
        });
        rts_add[rts_n++] = ((NMPlatformIP6Route){
            .ifindex   = IFINDEX,
            .rt_source = NM_IP_CONFIG_SOURCE_USER,
            .network   = nmtst_inet6_from_string("1010::1"),
            .plen      = 128,
            .gateway   = in6addr_any,
            .metric    = 256,
            .pref_src  = nmtst_inet6_from_string("2000::2"),
        });
        break;
    case 3:
        addr[addr_n++]   = ((NMPlatformIP6Address){
              .ifindex      = IFINDEX,
              .address      = nmtst_inet6_from_string("2001:db8:8086::5"),
              .plen         = 128,
              .peer_address = in6addr_any,
              .lifetime     = NM_PLATFORM_LIFETIME_PERMANENT,
              .preferred    = NM_PLATFORM_LIFETIME_PERMANENT,
              .n_ifa_flags  = 0,
        });
        rts_add[rts_n++] = ((NMPlatformIP6Route){
            .ifindex   = IFINDEX,
            .rt_source = nmp_utils_ip_config_source_round_trip_rtprot(NM_IP_CONFIG_SOURCE_USER),
            .network   = nmtst_inet6_from_string("2001:db8:8086::"),
            .plen      = 110,
            .metric    = 10021,
            .mss       = 0,
        });
        rts_add[rts_n++] = ((NMPlatformIP6Route){
            .ifindex   = IFINDEX,
            .rt_source = nmp_utils_ip_config_source_round_trip_rtprot(NM_IP_CONFIG_SOURCE_USER),
            .network   = nmtst_inet6_from_string("2001:db8:abad:c0de::"),
            .plen      = 64,
            .gateway   = nmtst_inet6_from_string("2001:db8:8086::1"),
            .metric    = 21,
            .mss       = 0,
        });
        break;
    default:
        g_assert_not_reached();
    }
    g_assert(rts_n <= G_N_ELEMENTS(rts_add));
    g_assert(addr_n <= G_N_ELEMENTS(addr));

    for (i = 0; i < addr_n; i++) {
        g_assert(addr[i].ifindex == IFINDEX);
        addr_in6[i] = addr[i].address;
        g_assert(nm_platform_ip6_address_add(NM_PLATFORM_GET,
                                             IFINDEX,
                                             addr[i].address,
                                             addr[i].plen,
                                             addr[i].peer_address,
                                             addr[i].lifetime,
                                             addr[i].preferred,
                                             addr[i].n_ifa_flags));
    }
    _wait_for_ipv6_addr_non_tentative(NM_PLATFORM_GET, 400, IFINDEX, addr_n, addr_in6);

    for (i = 0; i < rts_n; i++)
        g_assert(NMTST_NM_ERR_SUCCESS(
            nm_platform_ip6_route_add(NM_PLATFORM_GET, NMP_NLM_FLAG_REPLACE, &rts_add[i])));

    for (i = 0; i < rts_n; i++) {
        rts_cmp[i] = rts_add[i];
        nm_platform_ip_route_normalize(AF_INET6, NM_PLATFORM_IP_ROUTE_CAST(&rts_cmp[i]));
    }

    routes = nmtstp_ip6_route_get_all(NM_PLATFORM_GET, IFINDEX);
    g_assert_cmpint(routes->len, ==, rts_n);
    nmtst_platform_ip6_routes_equal_aptr((const NMPObject *const *) routes->pdata,
                                         rts_cmp,
                                         routes->len,
                                         TRUE);

    for (i = 0; i < rts_n; i++) {
        g_assert(nmtstp_platform_ip6_route_delete(NM_PLATFORM_GET,
                                                  IFINDEX,
                                                  rts_add[i].network,
                                                  rts_add[i].plen,
                                                  rts_add[i].metric));
    }

    for (i = 0; i < addr_n; i++) {
        nmtstp_ip6_address_del(NM_PLATFORM_GET, EX, IFINDEX, rts_add[i].network, rts_add[i].plen);
    }
#undef RTS_MAX
}

/*****************************************************************************/

static void
test_ip(gconstpointer test_data)
{
    const int             TEST_IDX = GPOINTER_TO_INT(test_data);
    const int             IFINDEX  = nm_platform_link_get_ifindex(NM_PLATFORM_GET, DEVICE_NAME);
    guint                 i, j, k;
    const NMPlatformLink *l;
    char                  ifname[IFNAMSIZ];
    char                  ifname2[IFNAMSIZ];
    char                  s1[NM_INET_ADDRSTRLEN];
    NMPlatform           *platform = NM_PLATFORM_GET;
    const int             EX_      = -1;
    struct {
        int ifindex;
    } iface_data[10] = {
        {0},
    };
    int   order_idx[G_N_ELEMENTS(iface_data)] = {0};
    guint order_len;
    guint try;

    for (i = 0; i < G_N_ELEMENTS(iface_data); i++) {
        nm_sprintf_buf(ifname, "v%02u", i);
        nm_sprintf_buf(ifname2, "w%02u", i);

        g_assert(!nm_platform_link_get_by_ifname(platform, ifname));
        g_assert(!nm_platform_link_get_by_ifname(platform, ifname2));
        l                     = nmtstp_link_veth_add(platform, EX_, ifname, ifname2);
        iface_data[i].ifindex = l->ifindex;

        nmtstp_link_set_updown(platform, EX_, iface_data[i].ifindex, TRUE);
        nmtstp_link_set_updown(platform,
                               EX_,
                               nmtstp_link_get(platform, -1, ifname2)->ifindex,
                               TRUE);

        nm_sprintf_buf(s1, "192.168.7.%d", 100 + i);
        nmtstp_ip4_address_add(platform,
                               EX_,
                               iface_data[i].ifindex,
                               nmtst_inet4_from_string(s1),
                               24,
                               nmtst_inet4_from_string(s1),
                               3600,
                               3600,
                               0,
                               NULL);
    }

    order_len = 0;
    for (try = 0; try < 5 * G_N_ELEMENTS(order_idx); try++) {
        NMPObject                    o;
        NMPlatformIP4Route          *r;
        guint                        idx;
        const NMDedupMultiHeadEntry *head_entry;
        NMPLookup                    lookup;

        nmp_object_stackinit(&o, NMP_OBJECT_TYPE_IP4_ROUTE, NULL);
        r          = NMP_OBJECT_CAST_IP4_ROUTE(&o);
        r->network = nmtst_inet4_from_string("192.168.9.0");
        r->plen    = 24;
        r->metric  = 109;

        if (order_len == 0
            || (order_len < G_N_ELEMENTS(order_idx) && nmtst_get_rand_uint32() % 2)) {
again_find_idx:
            idx = nmtst_get_rand_uint32() % G_N_ELEMENTS(iface_data);
            for (i = 0; i < order_len; i++) {
                if (order_idx[i] == idx)
                    goto again_find_idx;
            }
            order_idx[order_len++] = idx;

            r->ifindex = iface_data[idx].ifindex;
            g_assert(NMTST_NM_ERR_SUCCESS(
                nm_platform_ip4_route_add(platform, NMP_NLM_FLAG_APPEND, r, NULL)));
        } else {
            i   = nmtst_get_rand_uint32() % order_len;
            idx = order_idx[i];
            for (i++; i < order_len; i++)
                order_idx[i - 1] = order_idx[i];
            order_len--;

            r->ifindex = iface_data[idx].ifindex;
            g_assert(nm_platform_object_delete(platform, &o));
        }

        head_entry =
            nm_platform_lookup(platform,
                               nmp_lookup_init_obj_type(&lookup, NMP_OBJECT_TYPE_IP4_ROUTE));
        for (j = 0; j < G_N_ELEMENTS(iface_data); j++) {
            gboolean         has;
            NMDedupMultiIter iter;
            const NMPObject *o_cached;

            has = FALSE;
            for (k = 0; k < order_len; k++) {
                if (order_idx[k] == j) {
                    g_assert(!has);
                    has = TRUE;
                }
            }

            nmp_cache_iter_for_each (&iter, head_entry, &o_cached) {
                const NMPlatformIP4Route *r_cached = NMP_OBJECT_CAST_IP4_ROUTE(o_cached);

                if (r_cached->ifindex != iface_data[j].ifindex || r_cached->metric != 109)
                    continue;

                g_assert(has);
                has = FALSE;
            }
            g_assert(!has);
        }
    }

    for (i = 0; i < G_N_ELEMENTS(iface_data); i++)
        g_assert(nm_platform_link_delete(platform, iface_data[i].ifindex));

    (void) TEST_IDX;
    (void) IFINDEX;
}

/*****************************************************************************/

#define FRA_SUPPRESS_IFGROUP   13
#define FRA_SUPPRESS_PREFIXLEN 14
#define FRA_L3MDEV             19
#define FRA_UID_RANGE          20
#define FRA_PROTOCOL           21
#define FRA_IP_PROTO           22
#define FRA_SPORT_RANGE        23
#define FRA_DPORT_RANGE        24

static const NMPObject *
_rule_find_by_priority(NMPlatform *platform, guint32 priority)
{
    const NMDedupMultiHeadEntry *head_entry;
    NMDedupMultiIter             iter;
    const NMPObject             *o;
    const NMPObject             *obj = NULL;
    NMPLookup                    lookup;

    nmp_lookup_init_obj_type(&lookup, NMP_OBJECT_TYPE_ROUTING_RULE);
    head_entry = nm_platform_lookup(platform, &lookup);
    nmp_cache_iter_for_each (&iter, head_entry, &o) {
        if (NMP_OBJECT_CAST_ROUTING_RULE(o)->priority != priority)
            continue;
        g_assert(!obj);
        obj = o;
    }
    return obj;
}

static const NMPObject *
_rule_check_kernel_support_one(NMPlatform *platform, const NMPlatformRoutingRule *rr)
{
    nm_auto_nmpobj const NMPObject *obj = NULL;
    int                             r;

    g_assert(!_rule_find_by_priority(platform, rr->priority));

    r = nm_platform_routing_rule_add(platform, NMP_NLM_FLAG_ADD, rr);
    g_assert_cmpint(r, ==, 0);

    obj = nmp_object_ref(_rule_find_by_priority(platform, rr->priority));
    g_assert(obj);

    r = nm_platform_object_delete(platform, obj);
    g_assert_cmpint(r, ==, TRUE);

    g_assert(!_rule_find_by_priority(platform, rr->priority));

    return g_steal_pointer(&obj);
}

static gboolean
_rule_check_kernel_support(NMPlatform *platform, int attribute)
{
    static int support[] = {
        [FRA_SUPPRESS_IFGROUP]   = 0,
        [FRA_SUPPRESS_PREFIXLEN] = 0,
        [FRA_L3MDEV]             = 0,
        [FRA_UID_RANGE]          = 0,
        [FRA_PROTOCOL]           = 0,
        [FRA_IP_PROTO]           = 0,
        [FRA_SPORT_RANGE]        = 0,
        [FRA_DPORT_RANGE]        = 0,
    };
    const guint32 PROBE_PRORITY = 12033;
    gboolean      sup;
    int           i;

    g_assert(NM_IS_PLATFORM(platform));

    if (attribute == -1) {
        for (i = 0; i < G_N_ELEMENTS(support); i++) {
            if (support[i] < 0) {
                /* indicate that some test was skipped. */
                return FALSE;
            }
        }
        return TRUE;
    }

    g_assert(attribute >= 0 && attribute < G_N_ELEMENTS(support));

    if (support[attribute] != 0)
        return support[attribute] >= 0;

    switch (attribute) {
    case FRA_SUPPRESS_IFGROUP:
    {
        nm_auto_nmpobj const NMPObject *obj = NULL;
        const NMPlatformRoutingRule     rr  = {
                 .addr_family              = AF_INET,
                 .priority                 = PROBE_PRORITY,
                 .suppress_ifgroup_inverse = ~((guint32) 1245),
        };

        obj = _rule_check_kernel_support_one(platform, &rr);

        sup = NMP_OBJECT_CAST_ROUTING_RULE(obj)->suppress_prefixlen_inverse
              == rr.suppress_ifgroup_inverse;
        break;
    }
    case FRA_SUPPRESS_PREFIXLEN:
    {
        nm_auto_nmpobj const NMPObject *obj = NULL;
        const NMPlatformRoutingRule     rr  = {
                 .addr_family                = AF_INET,
                 .priority                   = PROBE_PRORITY,
                 .suppress_prefixlen_inverse = ~((guint32) 1245),
        };

        obj = _rule_check_kernel_support_one(platform, &rr);

        sup = NMP_OBJECT_CAST_ROUTING_RULE(obj)->suppress_prefixlen_inverse
              == rr.suppress_prefixlen_inverse;
        break;
    }
    case FRA_L3MDEV:
    {
        nm_auto_nmpobj const NMPObject *obj = NULL;
        const NMPlatformRoutingRule     rr  = {
                 .addr_family = AF_INET,
                 .priority    = PROBE_PRORITY,
                 .l3mdev      = TRUE,
        };

        obj = _rule_check_kernel_support_one(platform, &rr);

        sup = NMP_OBJECT_CAST_ROUTING_RULE(obj)->l3mdev != 0;
        break;
    }
    case FRA_UID_RANGE:
    {
        nm_auto_nmpobj const NMPObject *obj = NULL;
        const NMPlatformRoutingRule     rr  = {
                 .addr_family = AF_INET,
                 .priority    = PROBE_PRORITY,
                 .uid_range =
                {
                         .start = 0,
                         .end   = 0,
                },
                 .uid_range_has = TRUE,
        };

        obj = _rule_check_kernel_support_one(platform, &rr);

        sup = NMP_OBJECT_CAST_ROUTING_RULE(obj)->uid_range_has;
        break;
    }
    case FRA_PROTOCOL:
    {
        nm_auto_nmpobj const NMPObject *obj = NULL;
        const NMPlatformRoutingRule     rr  = {
                 .addr_family = AF_INET,
                 .priority    = PROBE_PRORITY,
                 .protocol    = 30,
        };

        obj = _rule_check_kernel_support_one(platform, &rr);

        sup = NMP_OBJECT_CAST_ROUTING_RULE(obj)->protocol == 30;
        break;
    }
    case FRA_IP_PROTO:
    {
        nm_auto_nmpobj const NMPObject *obj = NULL;
        const NMPlatformRoutingRule     rr  = {
                 .addr_family = AF_INET,
                 .priority    = PROBE_PRORITY,
                 .ip_proto    = 30,
        };

        obj = _rule_check_kernel_support_one(platform, &rr);

        sup = NMP_OBJECT_CAST_ROUTING_RULE(obj)->ip_proto == 30;
        break;
    }
    case FRA_SPORT_RANGE:
    case FRA_DPORT_RANGE:
        /* these were added at the same time as FRA_IP_PROTO. */
        sup = _rule_check_kernel_support(platform, FRA_IP_PROTO);
        break;
    default:
        g_assert_not_reached();
        return FALSE;
    }

    support[attribute] = sup ? 1 : -1;

    _LOGD("kernel support for routing rule attribute #%d %s",
          attribute,
          sup ? "detected" : "not detected");
    return sup;
}

static const NMPObject *
_platform_has_routing_rule(NMPlatform *platform, const NMPObject *obj)
{
    const NMPObject *o;

    g_assert(NM_IS_PLATFORM(platform));
    g_assert(NMP_OBJECT_IS_VALID(obj));
    g_assert(NMP_OBJECT_GET_TYPE(obj) == NMP_OBJECT_TYPE_ROUTING_RULE);

    o = nm_platform_lookup_obj(platform, NMP_CACHE_ID_TYPE_OBJECT_TYPE, obj);
    if (o)
        g_assert(nm_platform_routing_rule_cmp(NMP_OBJECT_CAST_ROUTING_RULE(obj),
                                              NMP_OBJECT_CAST_ROUTING_RULE(o),
                                              NM_PLATFORM_ROUTING_RULE_CMP_TYPE_ID)
                 == 0);

    return o;
}

static guint32
_rr_rand_choose_u32(guint32 p)
{
    /* mostly, we just return zero. We want that each rule only has few
     * fields set -- having most fields at zero. */
    if ((p % 10000u) < 7500u)
        return 0;

    /* give 0xFFFFFFFFu extra probability. */
    if ((p % 10000u) < 8250u)
        return 0xFFFFFFFFu;

    /* choose a small number. */
    if ((p % 10000u) < 9125u)
        return (~p) % 10;

    /* finally, full random number. */
    return ~p;
}

#define _rr_rand_choose_u8(p) ((guint8) _rr_rand_choose_u32((p)))

static const NMPObject *
_rule_create_random(NMPlatform *platform)
{
    NMPObject             *obj;
    NMPlatformRoutingRule *rr;
    guint32                p;
    int                    addr_size;
    guint                  i;
    char                   saddr[NM_INET_ADDRSTRLEN];
    static struct {
        guint32 uid;
        guint32 euid;
        bool    initialized;
    } uids;

    if (G_UNLIKELY(!uids.initialized)) {
        uids.uid         = getuid();
        uids.euid        = geteuid();
        uids.initialized = TRUE;
    }

    obj = nmp_object_new(NMP_OBJECT_TYPE_ROUTING_RULE, NULL);
    rr  = NMP_OBJECT_CAST_ROUTING_RULE(obj);

    rr->addr_family = nmtst_rand_select(AF_INET, AF_INET6);

    addr_size = nm_utils_addr_family_to_size(rr->addr_family);

    p = nmtst_get_rand_uint32();
    if ((p % 1000u) < 50)
        rr->priority = 10000 + ((~p) % 20u);

    p = nmtst_get_rand_uint32();
    if ((p % 1000u) < 40)
        nm_sprintf_buf(rr->iifname, "t-iif-%u", (~p) % 20);
    else if ((p % 1000u) < 80)
        nm_sprintf_buf(rr->iifname, "%s", DEVICE_NAME);

    p = nmtst_get_rand_uint32();
    if ((p % 1000u) < 40)
        nm_sprintf_buf(rr->oifname, "t-oif-%d", (~p) % 20);
    else if ((p % 1000u) < 80)
        nm_sprintf_buf(rr->oifname, "%s", DEVICE_NAME);

    for (i = 0; i < 2; i++) {
        NMIPAddr *p_addr = i ? &rr->src : &rr->dst;
        guint8   *p_len  = i ? &rr->src_len : &rr->dst_len;

        p = nmtst_get_rand_uint32();
        if ((p % 1000u) < 100) {
            /* if we set src_len/dst_len to zero, the src/dst is actually ignored.
             *
             * For fuzzying, still set the address. It shall have no further effect.
             * */
            *p_len = (~p) % (addr_size * 8 + 1);
            p      = nmtst_get_rand_uint32();
            if ((p % 3u) == 0) {
                if (rr->addr_family == AF_INET)
                    p_addr->addr4 =
                        nmtst_inet4_from_string(nm_sprintf_buf(saddr, "192.192.5.%u", (~p) % 256u));
                else
                    p_addr->addr6 = nmtst_inet6_from_string(
                        nm_sprintf_buf(saddr, "1:2:3:4::f:%02x", (~p) % 256u));
            } else if ((p % 3u) == 1)
                nmtst_rand_buf(NULL, p_addr, addr_size);
        }
    }

    p = nmtst_get_rand_uint32();
    if ((p % 1000u) < 50)
        rr->tun_id = 10000 + ((~p) % 20);

again_action:
    p = nmtst_get_rand_uint32();
    if ((p % 1000u) < 500)
        rr->action = FR_ACT_UNSPEC;
    else if ((p % 1000u) < 750)
        rr->action = (~p) % 12u;
    else
        rr->action = (~p) % 0x100u;

    rr->priority = _rr_rand_choose_u32(nmtst_get_rand_uint32());

    if (rr->action == FR_ACT_GOTO && rr->priority == G_MAXINT32)
        goto again_action;

    p = nmtst_get_rand_uint32();
    if ((p % 10000u) < 100)
        rr->goto_target = rr->priority + 1;
    else
        rr->goto_target = _rr_rand_choose_u32(nmtst_get_rand_uint32());
    if (rr->action == FR_ACT_GOTO && rr->goto_target <= rr->priority)
        goto again_action;

    p = nmtst_get_rand_uint32();
    if ((p % 1000u) < 25) {
        if (_rule_check_kernel_support(platform, FRA_L3MDEV)) {
            rr->l3mdev = TRUE;
            rr->table  = RT_TABLE_UNSPEC;
        }
    }

again_table:
    if (!rr->l3mdev) {
        p = nmtst_get_rand_uint32();
        if ((p % 1000u) < 700)
            rr->table = RT_TABLE_UNSPEC;
        else if ((p % 1000u) < 850)
            rr->table = RT_TABLE_MAIN;
        else
            rr->table = 10000 + ((~p) % 10);
        if (rr->action == FR_ACT_TO_TBL && rr->table == RT_TABLE_UNSPEC)
            goto again_table;
    }

    rr->fwmark = _rr_rand_choose_u32(nmtst_get_rand_uint32());
    rr->fwmask = _rr_rand_choose_u32(nmtst_get_rand_uint32());

    rr->flow = _rr_rand_choose_u32(nmtst_get_rand_uint32());

    if (_rule_check_kernel_support(platform, FRA_PROTOCOL))
        rr->protocol = _rr_rand_choose_u8(nmtst_get_rand_uint32());

#define IPTOS_TOS_MASK 0x1E
#define INET_DSCP_MASK 0xFC

again_tos:
    rr->tos = _rr_rand_choose_u8(nmtst_get_rand_uint32());

    if (rr->addr_family == AF_INET && rr->tos & ~IPTOS_TOS_MASK)
        goto again_tos;

    if (rr->tos & ~INET_DSCP_MASK)
        goto again_tos;

    if (_rule_check_kernel_support(platform, FRA_IP_PROTO))
        rr->ip_proto = _rr_rand_choose_u8(nmtst_get_rand_uint32());

    if (_rule_check_kernel_support(platform, FRA_SUPPRESS_PREFIXLEN))
        rr->suppress_prefixlen_inverse = ~_rr_rand_choose_u32(nmtst_get_rand_uint32());

    if (_rule_check_kernel_support(platform, FRA_SUPPRESS_IFGROUP))
        rr->suppress_ifgroup_inverse = ~_rr_rand_choose_u32(nmtst_get_rand_uint32());

    if (_rule_check_kernel_support(platform, FRA_UID_RANGE)) {
        p                 = nmtst_get_rand_uint32();
        rr->uid_range_has = (p % 10000u) < 200;
    }

again_uid_range:
    rr->uid_range.start = nmtst_rand_select(0u, uids.uid, uids.euid);
    rr->uid_range.end   = nmtst_rand_select(0u, uids.uid, uids.euid);
    if (rr->uid_range_has) {
        if (rr->uid_range.end < rr->uid_range.start)
            NM_SWAP(&rr->uid_range.start, &rr->uid_range.end);
        if (rr->uid_range.start == ((guint32) -1) || rr->uid_range.end == ((guint32) -1))
            goto again_uid_range;
    }

    for (i = 0; i < 2; i++) {
        NMFibRulePortRange *range     = i ? &rr->sport_range : &rr->dport_range;
        int                 attribute = i ? FRA_SPORT_RANGE : FRA_DPORT_RANGE;

        if (!_rule_check_kernel_support(platform, attribute))
            continue;

        p = nmtst_get_rand_uint32();
        if ((p % 10000u) < 300) {
            while (range->start == 0) {
                p            = p ^ nmtst_get_rand_uint32();
                range->start = nmtst_rand_select(1u, 0xFFFEu, ((p) % 0xFFFEu) + 1);
                range->end =
                    nmtst_rand_select(1u, 0xFFFEu, ((p >> 16) % 0xFFFEu) + 1, range->start);
                if (range->end < range->start)
                    NM_SWAP(&range->start, &range->end);
            }
        }
    }

    p = nmtst_get_rand_uint32() % 1000u;
    if (p < 100)
        rr->flags |= FIB_RULE_INVERT;

    return obj;
}

static gboolean
_rule_fuzzy_equal(const NMPObject *obj, const NMPObject *obj_comp, int op_type)
{
    const NMPlatformRoutingRule *rr    = NMP_OBJECT_CAST_ROUTING_RULE(obj);
    NMPlatformRoutingRule        rr_co = *NMP_OBJECT_CAST_ROUTING_RULE(obj_comp);

    switch (op_type) {
    case RTM_NEWRULE:
        /* when adding rules with RTM_NEWRULE, kernel checks whether an existing
         * rule already exists and may fail with EEXIST. This check has issues
         * and reject legitimate rules (rh#1686075).
         *
         * Work around that. */
        if (rr->src_len == 0)
            rr_co.src_len = 0;
        if (rr->dst_len == 0)
            rr_co.dst_len = 0;
        if (rr->flow == 0)
            rr_co.flow = 0;
        if (rr->tos == 0)
            rr_co.tos = 0;
        rr_co.suppress_prefixlen_inverse = rr->suppress_prefixlen_inverse;
        rr_co.suppress_ifgroup_inverse   = rr->suppress_ifgroup_inverse;
        if (!NM_FLAGS_HAS(rr->flags, FIB_RULE_INVERT))
            rr_co.flags &= ~((guint32) FIB_RULE_INVERT);
        else
            rr_co.flags |= ((guint32) FIB_RULE_INVERT);
        break;
    case RTM_DELRULE:
        /* when deleting a rule with RTM_DELRULE, kernel tries to find the
         * candidate to delete. It might delete the wrong rule (rh#1685816). */
        if (rr->action == FR_ACT_UNSPEC)
            rr_co.action = FR_ACT_UNSPEC;
        if (rr->iifname[0] == '\0')
            rr_co.iifname[0] = '\0';
        if (rr->oifname[0] == '\0')
            rr_co.oifname[0] = '\0';
        if (rr->src_len == 0)
            rr_co.src_len = 0;
        if (rr->dst_len == 0)
            rr_co.dst_len = 0;
        if (rr->tun_id == 0)
            rr_co.tun_id = 0;
        if (rr->fwmark == 0)
            rr_co.fwmark = 0;
        if (rr->fwmask == 0)
            rr_co.fwmask = 0;
        if (rr->flow == 0)
            rr_co.flow = 0;
        if (rr->protocol == 0)
            rr_co.protocol = 0;
        if (rr->table == RT_TABLE_UNSPEC)
            rr_co.table = RT_TABLE_UNSPEC;
        if (rr->l3mdev == 0)
            rr_co.l3mdev = 0;
        if (rr->tos == 0)
            rr_co.tos = 0;
        if (rr->ip_proto == 0)
            rr_co.ip_proto = 0;
        rr_co.suppress_prefixlen_inverse = rr->suppress_prefixlen_inverse;
        if (rr->suppress_ifgroup_inverse == 0)
            rr_co.suppress_ifgroup_inverse = 0;
        if (!rr->uid_range_has)
            rr_co.uid_range_has = FALSE;
        if (rr->sport_range.start == 0 && rr->sport_range.end == 0) {
            rr_co.sport_range.start = 0;
            rr_co.sport_range.end   = 0;
        }
        if (rr->dport_range.start == 0 && rr->dport_range.end == 0) {
            rr_co.dport_range.start = 0;
            rr_co.dport_range.end   = 0;
        }
        if (!NM_FLAGS_HAS(rr->flags, FIB_RULE_INVERT))
            rr_co.flags &= ~((guint32) FIB_RULE_INVERT);
        else
            rr_co.flags |= ((guint32) FIB_RULE_INVERT);
        break;
    default:
        g_assert_not_reached();
        break;
    }

    return nm_platform_routing_rule_cmp(rr, &rr_co, NM_PLATFORM_ROUTING_RULE_CMP_TYPE_ID) == 0;
}

static void
test_rule(gconstpointer test_data)
{
    char                         sbuf1[NM_UTILS_TO_STRING_BUFFER_SIZE];
    const int                    TEST_IDX     = GPOINTER_TO_INT(test_data);
    const gboolean               TEST_SYNC    = (TEST_IDX == 4);
    gs_unref_ptrarray GPtrArray *objs         = NULL;
    gs_unref_ptrarray GPtrArray *objs_initial = NULL;
    NMPlatform                  *platform     = NM_PLATFORM_GET;
    guint                        i, j, n;
    int                          r;
    gboolean                     had_an_issue_exist = FALSE;

    nm_platform_process_events(platform);

    objs_initial = nmtstp_platform_routing_rules_get_all(platform, AF_UNSPEC);
    g_assert(objs_initial);
    g_assert_cmpint(objs_initial->len, ==, 5);

    nmtstp_run_command_check("ip rule add table 766");
    nm_platform_process_events(platform);

    for (i = 6; i > 0; i--) {
        gs_unref_ptrarray GPtrArray *objs_extern = NULL;
        const NMPObject             *obj;

        objs_extern = nmtstp_platform_routing_rules_get_all(platform, AF_UNSPEC);

        g_assert(objs_extern);
        g_assert_cmpint(objs_extern->len, ==, i);

        if (TEST_IDX != 1)
            nmtst_rand_perm(NULL, objs_extern->pdata, NULL, sizeof(gpointer), objs_extern->len);

        obj = objs_extern->pdata[0];

        r = nm_platform_object_delete(platform, obj);
        g_assert_cmpint(r, ==, TRUE);

        g_assert(!_platform_has_routing_rule(platform, obj));
    }

    g_assert_cmpint(nmtstp_platform_routing_rules_get_count(platform, AF_UNSPEC), ==, 0);

#define RR(...)                                  \
    nmp_object_new(NMP_OBJECT_TYPE_ROUTING_RULE, \
                   (const NMPlatformObject *) &((NMPlatformRoutingRule){__VA_ARGS__}))

    objs = g_ptr_array_new_with_free_func((GDestroyNotify) nmp_object_unref);

    g_ptr_array_add(objs, RR(.addr_family = AF_INET, .priority = 10, ));

    g_ptr_array_add(
        objs,
        RR(.addr_family = AF_INET, .priority = 400, .action = FR_ACT_GOTO, .goto_target = 10000, ));

    g_ptr_array_add(objs, RR(.addr_family = AF_INET6, ));

    g_ptr_array_add(objs,
                    RR(.addr_family = AF_INET6, .action = FR_ACT_TO_TBL, .table = RT_TABLE_MAIN, ));

    g_ptr_array_add(objs, RR(.addr_family = AF_INET6, .priority = 30, ));

    g_ptr_array_add(objs, RR(.addr_family = AF_INET6, .priority = 50, .iifname = "t-iif-1", ));

    g_ptr_array_add(objs, RR(.addr_family = AF_INET6, .priority = 50, .iifname = "t-oif-1", ));

    g_ptr_array_add(objs, RR(.addr_family = AF_INET, .priority = 50, .iifname = "t-oif-2", ));

    g_ptr_array_add(objs, RR(.addr_family = AF_INET, .priority = 51, .iifname = DEVICE_NAME, ));

    if (TEST_IDX == 1) {
        g_ptr_array_add(objs, RR(.addr_family = AF_INET, .table = 10000, ));
    }

    if (TEST_IDX != 1) {
        nmtst_rand_perm(NULL, objs->pdata, NULL, sizeof(gpointer), objs->len);
        g_ptr_array_set_size(objs, nmtst_get_rand_uint32() % (objs->len + 1));
    }

    n = (TEST_IDX != 1) ? nmtst_get_rand_uint32() % 50u : 0u;
    for (i = 0; i < n; i++) {
        nm_auto_nmpobj const NMPObject *o   = NULL;
        guint                           try = 0;

again:
        o = _rule_create_random(platform);
        for (j = 0; j < objs->len; j++) {
            if (nm_platform_routing_rule_cmp(NMP_OBJECT_CAST_ROUTING_RULE(o),
                                             NMP_OBJECT_CAST_ROUTING_RULE(objs->pdata[j]),
                                             NM_PLATFORM_ROUTING_RULE_CMP_TYPE_ID)
                == 0) {
                try++;
                g_assert(try < 200);
                nm_clear_pointer(&o, nmp_object_unref);
                goto again;
            }
        }
        g_ptr_array_add(objs, (gpointer) g_steal_pointer(&o));
    }

    if (TEST_IDX != 1)
        nmtst_rand_perm(NULL, objs->pdata, NULL, sizeof(gpointer), objs->len);

    if (TEST_SYNC) {
        gs_unref_hashtable GHashTable *unique_priorities = g_hash_table_new(NULL, NULL);
        nm_auto_unref_global_tracker NMPGlobalTracker *global_tracker =
            nmp_global_tracker_new(platform);
        gs_unref_ptrarray GPtrArray *objs_sync  = NULL;
        gconstpointer                USER_TAG_1 = &platform;
        gconstpointer                USER_TAG_2 = &unique_priorities;

        objs_sync = g_ptr_array_new_with_free_func((GDestroyNotify) nmp_object_unref);

        /* ensure that priorities are unique. Otherwise, it confuses the test, because
         * kernel may wrongly be unable to add/delete routes based on a wrong match
         * (rh#1685816, rh#1685816). */
        for (i = 0; i < objs->len; i++) {
            const NMPObject *obj  = objs->pdata[i];
            guint32          prio = NMP_OBJECT_CAST_ROUTING_RULE(obj)->priority;

            if (!NM_IN_SET(prio, 0, 32766, 32767)
                && !g_hash_table_contains(unique_priorities, GUINT_TO_POINTER(prio))) {
                g_hash_table_add(unique_priorities, GUINT_TO_POINTER(prio));
                g_ptr_array_add(objs_sync, (gpointer) nmp_object_ref(obj));
            }
        }

        for (i = 0; i < objs_sync->len; i++) {
            nmp_global_tracker_track_rule(global_tracker,
                                          NMP_OBJECT_CAST_ROUTING_RULE(objs_sync->pdata[i]),
                                          1,
                                          USER_TAG_1,
                                          NULL);
            if (nmtst_get_rand_bool()) {
                /* this has no effect, because a negative priority (of same absolute value)
                 * has lower priority than the positive priority above. */
                nmp_global_tracker_track_rule(global_tracker,
                                              NMP_OBJECT_CAST_ROUTING_RULE(objs_sync->pdata[i]),
                                              -1,
                                              USER_TAG_2,
                                              NULL);
            }
            if (nmtst_get_rand_uint32() % objs_sync->len == 0) {
                nmp_global_tracker_sync(global_tracker, NMP_OBJECT_TYPE_ROUTING_RULE, FALSE);
                g_assert_cmpint(nmtstp_platform_routing_rules_get_count(platform, AF_UNSPEC),
                                ==,
                                i + 1);
            }
        }

        nmp_global_tracker_sync(global_tracker, NMP_OBJECT_TYPE_ROUTING_RULE, FALSE);
        g_assert_cmpint(nmtstp_platform_routing_rules_get_count(platform, AF_UNSPEC),
                        ==,
                        objs_sync->len);

        for (i = 0; i < objs_sync->len; i++) {
            switch (nmtst_get_rand_uint32() % 3) {
            case 0:
                nmp_global_tracker_untrack_rule(global_tracker,
                                                NMP_OBJECT_CAST_ROUTING_RULE(objs_sync->pdata[i]),
                                                USER_TAG_1);
                nmp_global_tracker_untrack_rule(global_tracker,
                                                NMP_OBJECT_CAST_ROUTING_RULE(objs_sync->pdata[i]),
                                                USER_TAG_1);
                break;
            case 1:
                nmp_global_tracker_track_rule(global_tracker,
                                              NMP_OBJECT_CAST_ROUTING_RULE(objs_sync->pdata[i]),
                                              -1,
                                              USER_TAG_1,
                                              NULL);
                break;
            case 2:
                nmp_global_tracker_track_rule(global_tracker,
                                              NMP_OBJECT_CAST_ROUTING_RULE(objs_sync->pdata[i]),
                                              -2,
                                              USER_TAG_2,
                                              NULL);
                break;
            }
            if (nmtst_get_rand_uint32() % objs_sync->len == 0) {
                nmp_global_tracker_sync(global_tracker, NMP_OBJECT_TYPE_ROUTING_RULE, FALSE);
                g_assert_cmpint(nmtstp_platform_routing_rules_get_count(platform, AF_UNSPEC),
                                ==,
                                objs_sync->len - i - 1);
            }
        }

        nmp_global_tracker_sync(global_tracker, NMP_OBJECT_TYPE_ROUTING_RULE, FALSE);

    } else {
        for (i = 0; i < objs->len;) {
            const NMPObject *obj = objs->pdata[i];

            for (j = 0; j < objs->len; j++)
                g_assert((j < i) == (!!_platform_has_routing_rule(platform, objs->pdata[j])));

            r = nm_platform_routing_rule_add(platform,
                                             NMP_NLM_FLAG_ADD,
                                             NMP_OBJECT_CAST_ROUTING_RULE(obj));

            if (r == -EEXIST) {
                g_assert(!_platform_has_routing_rule(platform, obj));
                /* this should not happen, but there are bugs in kernel (rh#1686075). */
                for (j = 0; j < i; j++) {
                    const NMPObject *obj2 = objs->pdata[j];

                    g_assert(_platform_has_routing_rule(platform, obj2));

                    if (_rule_fuzzy_equal(obj, obj2, RTM_NEWRULE)) {
                        r = 0;
                        break;
                    }
                }
                if (r == 0) {
                    /* OK, the rule is shadowed by another rule, and kernel does not allow
                     * us to add this one (rh#1686075). Drop this from the test. */
                    g_ptr_array_remove_index(objs, i);
                    had_an_issue_exist = TRUE;
                    continue;
                }
            }

            if (r != 0) {
                NMPLookup                    lookup;
                const NMDedupMultiHeadEntry *head_entry;
                NMDedupMultiIter             iter;
                const NMPObject             *o;

                g_print(">>> failing... errno=%d, rule=%s\n",
                        r,
                        nmp_object_to_string(obj, NMP_OBJECT_TO_STRING_ALL, sbuf1, sizeof(sbuf1)));

                nmp_lookup_init_obj_type(&lookup, NMP_OBJECT_TYPE_ROUTING_RULE);
                head_entry = nm_platform_lookup(platform, &lookup);
                nmp_cache_iter_for_each (&iter, head_entry, &o) {
                    char ch = ' ';

                    if (NMP_OBJECT_CAST_ROUTING_RULE(o)->addr_family
                            == NMP_OBJECT_CAST_ROUTING_RULE(obj)->addr_family
                        && NMP_OBJECT_CAST_ROUTING_RULE(o)->priority
                               == NMP_OBJECT_CAST_ROUTING_RULE(obj)->priority)
                        ch = '*';
                    g_print(
                        ">>> existing rule: %c %s\n",
                        ch,
                        nmp_object_to_string(o, NMP_OBJECT_TO_STRING_ALL, sbuf1, sizeof(sbuf1)));
                }

                nmtstp_run_command_check("ip rule");
                nmtstp_run_command_check("ip -6 rule");
                g_assert_cmpint(r, ==, 0);
            }

            g_assert(_platform_has_routing_rule(platform, obj));

            g_assert_cmpint(nmtstp_platform_routing_rules_get_count(platform, AF_UNSPEC),
                            ==,
                            i + 1);

            i++;
        }

        if (TEST_IDX != 1)
            nmtst_rand_perm(NULL, objs->pdata, NULL, sizeof(gpointer), objs->len);

        if (_LOGD_ENABLED()) {
            nmtstp_run_command_check("ip rule");
            nmtstp_run_command_check("ip -6 rule");
        }

        for (i = 0; i < objs->len; i++) {
            const NMPObject *obj = objs->pdata[i];
            const NMPObject *obj2;

            for (j = 0; j < objs->len; j++)
                g_assert((j < i) == (!_platform_has_routing_rule(platform, objs->pdata[j])));

            g_assert(_platform_has_routing_rule(platform, obj));

            r = nm_platform_object_delete(platform, obj);
            g_assert_cmpint(r, ==, TRUE);

            obj2 = _platform_has_routing_rule(platform, obj);

            if (obj2) {
                guint k;

                /* When deleting a rule, kernel does a fuzzy match, ignoring for example:
                 *  - action, if it is FR_ACT_UNSPEC
                 *  - iifname,oifname if it is unspecified
                 * rh#1685816
                 *
                 * That means, we may have deleted the wrong rule. Which one? */
                k = i;
                for (j = i + 1; j < objs->len; j++) {
                    if (!_platform_has_routing_rule(platform, objs->pdata[j])) {
                        g_assert_cmpint(k, ==, i);
                        k = j;
                    }
                }
                g_assert_cmpint(k, >, i);

                if (!_rule_fuzzy_equal(obj, objs->pdata[k], RTM_DELRULE)) {
                    g_print(">>> failing...\n");
                    g_print(
                        ">>> no fuzzy match between: %s\n",
                        nmp_object_to_string(obj, NMP_OBJECT_TO_STRING_ALL, sbuf1, sizeof(sbuf1)));
                    g_print(">>>                    and: %s\n",
                            nmp_object_to_string(objs->pdata[k],
                                                 NMP_OBJECT_TO_STRING_ALL,
                                                 sbuf1,
                                                 sizeof(sbuf1)));
                    g_assert_not_reached();
                }

                objs->pdata[i] = objs->pdata[k];
                objs->pdata[k] = (gpointer) obj;
                obj2           = NULL;
            }

            g_assert(!obj2);

            g_assert_cmpint(nmtstp_platform_routing_rules_get_count(platform, AF_UNSPEC),
                            ==,
                            objs->len - i - 1);
        }
    }

    g_assert_cmpint(nmtstp_platform_routing_rules_get_count(platform, AF_UNSPEC), ==, 0);

    for (i = 0; i < objs_initial->len; i++) {
        const NMPObject *obj = objs_initial->pdata[i];

        for (j = 0; j < objs_initial->len; j++)
            g_assert((j < i) == (!!_platform_has_routing_rule(platform, objs_initial->pdata[j])));

        r = nm_platform_routing_rule_add(platform,
                                         NMP_NLM_FLAG_ADD,
                                         NMP_OBJECT_CAST_ROUTING_RULE(obj));
        g_assert_cmpint(r, ==, 0);
    }
    for (j = 0; j < objs_initial->len; j++)
        g_assert(_platform_has_routing_rule(platform, objs_initial->pdata[j]));
    g_assert_cmpint(nmtstp_platform_routing_rules_get_count(platform, AF_UNSPEC),
                    ==,
                    objs_initial->len);

    /* the tests passed as good as we could (as good as we implemented workarounds for them).
     * Still, with this kernel, not all features were fully tested. Mark the test as skipped. */
    if (had_an_issue_exist)
        g_test_skip("adding a rule failed with EEXIST although it should not (rh#1686075)");
    else if (!_rule_check_kernel_support(platform, -1))
        g_test_skip("some kernel features were not available and skipped for the test");
}

/*****************************************************************************/

static void
test_blackhole(gconstpointer test_data)
{
    int                          TEST_IDX    = GPOINTER_TO_INT(test_data);
    const int                    addr_family = (TEST_IDX == 1) ? AF_INET : AF_INET6;
    const int                    IS_IPv4     = NM_IS_IPv4(addr_family);
    const NMDedupMultiHeadEntry *head_entry;
    NMDedupMultiIter             iter;
    const NMPObject             *obj;
    NMPObject                    obj_stack;
    NMPlatformIPXRoute           rr = {};
    int                          r  = -1;
    int                          i;
    guint8                       rtn_type;

    rtn_type = nmtst_rand_select(RTN_BLACKHOLE, RTN_UNREACHABLE, RTN_PROHIBIT, RTN_THROW);

    if (IS_IPv4) {
        rr.r4 = (const NMPlatformIP4Route){
            .type_coerced = nm_platform_route_type_coerce(rtn_type),
        };
    } else {
        rr.r6 = (const NMPlatformIP6Route){
            .type_coerced = nm_platform_route_type_coerce(rtn_type),
            .metric       = 1000,
        };
    }

    nm_platform_ip_route_normalize(addr_family, &rr.rx);

    if (IS_IPv4)
        r = nm_platform_ip4_route_add(NM_PLATFORM_GET, NMP_NLM_FLAG_APPEND, &rr.r4, NULL);
    else
        r = nm_platform_ip6_route_add(NM_PLATFORM_GET, NMP_NLM_FLAG_APPEND, &rr.r6);

    g_assert_cmpint(r, ==, 0);

    nmp_object_stackinit(&obj_stack, NMP_OBJECT_TYPE_IP_ROUTE(IS_IPv4), &rr);

    obj = nm_platform_lookup_obj(NM_PLATFORM_GET, NMP_CACHE_ID_TYPE_OBJECT_TYPE, &obj_stack);

    _LOGT(">>> adding %s",
          nmp_object_to_string(&obj_stack, NMP_OBJECT_TO_STRING_ALL, g_alloca(1000), 1000));
    _LOGT(">>> found  %s",
          nmp_object_to_string(obj, NMP_OBJECT_TO_STRING_ALL, g_alloca(1000), 1000));

    g_assert(obj);

    head_entry = nm_platform_lookup_object(NM_PLATFORM_GET, NMP_OBJECT_TYPE_IP_ROUTE(IS_IPv4), 0);
    g_assert(head_entry);
    g_assert_cmpint(head_entry->len, ==, 1);
    i = 0;
    nm_dedup_multi_iter_for_each (&iter, head_entry) {
        i++;
        g_assert(iter.current->obj == obj);
    }
    g_assert_cmpint(i, ==, 1);
}

/*****************************************************************************/

static gboolean
_mptcp_has_permissions(void)
{
    static int has_permissions = -1;
    int        p;

    /* We create a new netns for testing, where we also have CAP_NET_ADMIN.
     * However, that is not enough for configuring MPTCP endpoints. Probably
     * you can only create them, by running the test as root. Detect the
     * inability, to skip the test.
     *
     * See https://lore.kernel.org/mptcp/20220805115020.525181-1-thaller@redhat.com/T/#u */

again:
    p = g_atomic_int_get(&has_permissions);

    if (p == -1) {
        static gsize              lock;
        const NMPlatformMptcpAddr mptcp_addr = (NMPlatformMptcpAddr){
            .id          = 1,
            .addr_family = AF_INET,
            .addr.addr4  = nmtst_inet4_from_string("1.2.3.4"),
        };
        int r;

        if (!g_once_init_enter(&lock))
            goto again;

        if (nmtst_get_rand_one_case_in(3)) {
            gs_unref_ptrarray GPtrArray *arr = NULL;

            arr = nm_platform_mptcp_addrs_dump(NM_PLATFORM_GET);
            g_assert_cmpint(nm_g_ptr_array_len(arr), ==, 0);
        }

        r = nm_platform_mptcp_addr_update(NM_PLATFORM_GET, TRUE, &mptcp_addr);
        if (r == 0)
            p = TRUE;
        else if (r == -EPERM)
            p = FALSE;
        else
            g_assert_cmpint(r, ==, 0);

        if (p) {
            if (nmtst_get_rand_one_case_in(3)) {
                gs_unref_ptrarray GPtrArray *arr = NULL;

                arr = nm_platform_mptcp_addrs_dump(NM_PLATFORM_GET);
                g_assert_cmpint(nm_g_ptr_array_len(arr), ==, 1);
            }

            r = nm_platform_mptcp_addr_update(NM_PLATFORM_GET, FALSE, &mptcp_addr);
            g_assert_cmpint(r, ==, 0);
        }

        if (nmtst_get_rand_one_case_in(3)) {
            gs_unref_ptrarray GPtrArray *arr = NULL;

            arr = nm_platform_mptcp_addrs_dump(NM_PLATFORM_GET);
            g_assert_cmpint(nm_g_ptr_array_len(arr), ==, 0);
        }

        g_atomic_int_set(&has_permissions, p);
        g_once_init_leave(&lock, 1);
    }

    return p;
}

static gboolean
_mptcp_skip_test(void)
{
    if (nm_platform_genl_get_family_id(NM_PLATFORM_GET, NMP_GENL_FAMILY_TYPE_MPTCP_PM) == 0) {
        g_test_skip("mptcp not available");
        return TRUE;
    }

    if (!_mptcp_has_permissions()) {
        g_test_skip("No permissions to create MPTCP endpoints");
        return TRUE;
    }

    return FALSE;
}

static void
test_mptcp(gconstpointer test_data)
{
    const int                                      TEST_IDX = GPOINTER_TO_INT(test_data);
    gs_unref_object NMPlatform                    *platform = g_object_ref(NM_PLATFORM_GET);
    nm_auto_unref_global_tracker NMPGlobalTracker *global_tracker =
        nmp_global_tracker_new(platform);
    gconstpointer const          USER_TAG = &TEST_IDX;
    const int                    IFINDEX  = nm_platform_link_get_ifindex(platform, DEVICE_NAME);
    guint                        i;
    guint                        j;
    int                          r;
    gs_unref_ptrarray GPtrArray *arr_external =
        g_ptr_array_new_with_free_func((GDestroyNotify) nmp_object_unref);
    gs_unref_ptrarray GPtrArray *arr_tracked =
        g_ptr_array_new_with_free_func((GDestroyNotify) nmp_object_unref);
    const NMPObject *obj;
    gboolean         delete_extra;

    g_assert_cmpint(IFINDEX, >, 0);

    if (_mptcp_skip_test())
        return;

    j = nmtst_get_rand_uint32() % 5;
    for (i = 0; i < j; i++) {
        obj = nmtst_object_new_mptcp_addr(.id          = i + 1,
                                          .ifindex     = IFINDEX,
                                          .addr_family = AF_INET,
                                          .addr.addr4  = htonl(0xC0A80001u + i));
        g_ptr_array_add(arr_external, (gpointer) obj);
        r = nm_platform_mptcp_addr_update(platform, TRUE, NMP_OBJECT_CAST_MPTCP_ADDR(obj));
        g_assert_cmpint(r, ==, 0);
    }

    j = nmtst_get_rand_uint32() % 10;
    for (i = 0; i < j; i++) {
        obj = nmtst_object_new_mptcp_addr(.ifindex     = IFINDEX,
                                          .addr_family = AF_INET,
                                          .addr.addr4  = htonl(0xC0A80001u + i));
        g_ptr_array_add(arr_tracked, (gpointer) obj);
        nmp_global_tracker_track(global_tracker,
                                 NMP_OBJECT_TYPE_MPTCP_ADDR,
                                 NMP_OBJECT_CAST_MPTCP_ADDR(obj),
                                 20 - i,
                                 USER_TAG,
                                 NULL);
    }
    for (i = 0; i < arr_tracked->len;) {
        if (nmtst_get_rand_bool()) {
            nmp_global_tracker_untrack(global_tracker,
                                       NMP_OBJECT_TYPE_MPTCP_ADDR,
                                       NMP_OBJECT_CAST_MPTCP_ADDR(arr_tracked->pdata[i]),
                                       USER_TAG);
            g_ptr_array_remove_index(arr_tracked, i);
        } else
            i++;
    }

    if (arr_tracked->len == 0 || nmtst_get_rand_bool()) {
        NMPlatformMptcpAddr a;

        /* Track a dummy object that marks the ifindex as managed. */
        nmp_global_tracker_track(global_tracker,
                                 NMP_OBJECT_TYPE_MPTCP_ADDR,
                                 nmp_global_tracker_mptcp_addr_init_for_ifindex(&a, IFINDEX),
                                 10,
                                 USER_TAG,
                                 NULL);
    }

    nmp_global_tracker_sync_mptcp_addrs(global_tracker, FALSE);

    if (nmtst_get_rand_bool()) {
        gboolean reapply;

        nmp_global_tracker_untrack_all(global_tracker, USER_TAG, TRUE, FALSE);
        reapply = nmtst_get_rand_bool();
        nmp_global_tracker_sync_mptcp_addrs(global_tracker, reapply);

        delete_extra = !reapply;
    } else
        delete_extra = TRUE;

    if (delete_extra) {
        gs_unref_ptrarray GPtrArray *arr = NULL;

        /* We need to delete all MPTCP address again, because the next test uses the
         * same netns (this test setup doesn't create a netns per test). */
        arr = nm_platform_mptcp_addrs_dump(platform);
        for (i = 0; i < nm_g_ptr_array_len(arr); i++) {
            r = nm_platform_mptcp_addr_update(platform,
                                              FALSE,
                                              NMP_OBJECT_CAST_MPTCP_ADDR(arr->pdata[i]));
            g_assert(NMTST_NM_ERR_SUCCESS(r));
        }
    }

    {
        gs_unref_ptrarray GPtrArray *arr = NULL;

        arr = nm_platform_mptcp_addrs_dump(platform);
        g_assert(arr);
        g_assert_cmpint(arr->len, ==, 0);
    }
}

/*****************************************************************************/

static void
_ensure_onlink_routes(void)
{
    int i;

    for (i = 0; i < G_N_ELEMENTS(NMTSTP_ENV1_DEVICE_NAME) && NMTSTP_ENV1_DEVICE_NAME[i]; i++) {
        nmtstp_run_command("ip route append 7.7.7.0/24 dev %s%s",
                           NMTSTP_ENV1_DEVICE_NAME[i],
                           nmtst_is_debug() ? "" : " &>/dev/null");
        nmtstp_run_command("ip route append 7:7:7::/64 dev %s%s",
                           NMTSTP_ENV1_DEVICE_NAME[i],
                           nmtst_is_debug() ? "" : " &>/dev/null");
    }
}

static void
test_cache_consistency_routes(gconstpointer test_data)
{
    const int                    TEST_IDX      = GPOINTER_TO_INT(test_data);
    NMPlatform                  *platform      = NM_PLATFORM_GET;
    gboolean                     is_test_quick = nmtst_test_quick();
    const int                    N_RUN         = is_test_quick ? 50 : 500;
    int                          i_run;
    gs_unref_ptrarray GPtrArray *keeper = g_ptr_array_new_with_free_func(g_free);

    _ensure_onlink_routes();

    for (i_run = 0; i_run < N_RUN; i_run++) {
        const char   *extra_options[100];
        gsize         n_extra_options   = 0;
        gs_free char *extra_options_str = NULL;
        int           i_if;
        int           ifindex;
        const char   *ifname;
        int           IS_IPv4;
        const char   *op;
        const char   *prefix;
        const char   *s;
        const char   *route_type;
        int           i;
        int           n;
        char          addr_family_char[2] = {'6', '4'};

        g_ptr_array_set_size(keeper, 0);

        switch (TEST_IDX) {
        case 1:
            IS_IPv4 = TRUE;
            break;
        case 2:
            IS_IPv4 = FALSE;
            break;
        default:
            IS_IPv4 = nmtst_get_rand_bool();
            break;
        }

        i_if = nmtst_get_rand_uint32() % 2;
        op   = nmtst_rand_select_str("flush", "add", "change", "append", "prepend", "replace");

        ifindex = NMTSTP_ENV1_IFINDEXES[i_if];
        ifname  = NMTSTP_ENV1_DEVICE_NAME[i_if];

        g_assert_cmpint(ifindex, ==, nm_platform_link_get_ifindex(platform, ifname));

        if (nm_streq(op, "flush")) {
            if (!nmtst_get_rand_one_case_in(10)) {
                /* flush more seldom. */
                continue;
            }
            nmtstp_run_command("ip -%c route flush dev %s"
                               " table %s" /* table */
                               "%s"        /* redirect */
                               "",
                               addr_family_char[IS_IPv4],
                               ifname,
                               nmtst_rand_select_str("main", "10222", "10223", "all"),
                               nmtst_is_debug() ? "" : " &>/dev/null");
            _ensure_onlink_routes();
            goto done;
        }

        route_type = nmtst_get_rand_one_case_in(4)
                         ? nmtst_rand_select_str("unicast", "blackhole", "local", "broadcast")
                         : NULL;

        if (NM_IN_STRSET(route_type, "blackhole")) {
            ifindex = 0;
            ifname  = NULL;
        }

        if (IS_IPv4) {
            prefix = nmtst_rand_select_str("192.168.4.0/24",
                                           "192.168.5.0/24",
                                           "192.168.5.5/32",
                                           "default");
        } else {
            prefix =
                nmtst_rand_select_str("a:b:c:d::/64", "a:b:c:e::/64", "a:b:c:f::/64", "default");
        }

        s = nmtst_rand_select_str(NULL, "kernel", "bird");
        if (s) {
            if (nmtst_get_rand_bool()) {
                s = nm_streq(s, "kernel") ? nmtst_rand_select_str("boot", "static", "ra")
                                          : nmtst_rand_select_str("zebra", "bird");
            }
            extra_options[n_extra_options++] = "proto";
            extra_options[n_extra_options++] = s;
        }

        s = nmtst_rand_select_str(NULL, "10", "20");
        if (s) {
            extra_options[n_extra_options++] = "metric";
            extra_options[n_extra_options++] = s;
        }

        s = nmtst_rand_select_str(NULL, "10222", "10223");
        if (s) {
            extra_options[n_extra_options++] = "table";
            extra_options[n_extra_options++] = s;
        }

        if (!IS_IPv4 && NM_IN_STRSET(op, "add", "change", "append", "prepend", "replace")) {
            /* kernel has a bug with append/prepend of IPv6 routes with next-hops.
             * This leads to wrong notification messages, wrong merging of multi-hop
             * routes and cache inconsistency in NMPlatform.
             *
             * https://bugzilla.redhat.com/show_bug.cgi?id=2161994
             *
             * For now, disable the test case to make the unit test not fail.
             *
             * While being a kernel bug, it leads to cache inconsistency in NMPlatform,
             * which is a problem for NetworkManager. I don't see how we can detect
             * this problem to trigger a refresh. */
        } else if (ifname && nmtst_get_rand_one_case_in(3)) {
            n = (nmtst_get_rand_uint32() % 4) + 1;
            for (i = 0; i < n; i++) {
                extra_options[n_extra_options++] = "nexthop";
                extra_options[n_extra_options++] = "via";
                if (IS_IPv4) {
                    extra_options[n_extra_options++] =
                        nmtst_keeper_printf(&keeper, "7.7.7.%d", i + 1);
                } else {
                    extra_options[n_extra_options++] =
                        nmtst_keeper_printf(&keeper, "7:7:7:7::%d", i + 1);
                }
                extra_options[n_extra_options++] = "dev";
                extra_options[n_extra_options++] = NMTSTP_ENV1_DEVICE_NAME[nmtst_get_rand_bool()];
                if (IS_IPv4 && i == 0) {
                    /* For IPv4, there is a problem if we configure a route with
                     * only one next-hop and a weight. In that case, kernel allows
                     * to add duplicates (that only differ by weight), but on netlink
                     * the weight is not exposed, so the routes look identical and
                     * are deduplicated by the hash.
                     * See https://bugzilla.redhat.com/show_bug.cgi?id=2162315
                     *
                     * This needs a kernel fix. Workaround that issue here, otherwise the test
                     * will randomly fail. */
                } else if (nmtst_get_rand_one_case_in(3)) {
                    extra_options[n_extra_options++] = "weight";
                    extra_options[n_extra_options++] = "5";
                }
            }

            ifname  = NULL;
            ifindex = 0;
        }

        g_assert_cmpint(n_extra_options, <, G_N_ELEMENTS(extra_options));
        extra_options[n_extra_options] = NULL;

        if (nmtst_is_debug())
            nmtstp_run_command("ip -%c -d route show table all", addr_family_char[IS_IPv4]);

        /* We ignore errors. The reason is that operations like "change" might fail if
         * the route doesn't exist. That's fine for our test. We just do randomly things
         * and some of them will stick. */
        nmtstp_run_command(
            "ip -%c route "
            "%s"   /* op */
            "%s%s" /* route_type */
            " %s"  /* prefix */
            "%s%s" /* ifname */
            "%s%s" /* extra_options */
            "%s"   /* redirect */
            "",
            addr_family_char[IS_IPv4],
            op,
            NM_PRINT_FMT_QUOTED2(route_type, " ", route_type, ""),
            prefix,
            NM_PRINT_FMT_QUOTED2(ifname, " dev ", ifname, ""),
            NM_PRINT_FMT_QUOTED2(extra_options[0],
                                 " ",
                                 (extra_options_str = g_strjoinv(" ", (char **) extra_options)),
                                 ""),
            nmtst_is_debug() ? "" : " &>/dev/null");

        if (nmtst_is_debug())
            nmtstp_run_command("ip -%c -d route show table all", addr_family_char[IS_IPv4]);
done:
        nm_platform_process_events(platform);

        if (!is_test_quick || (i_run + 1 == N_RUN) || nmtst_get_rand_one_case_in(5)) {
            nmtstp_check_platform(
                platform,
                nmtst_get_rand_one_case_in(5)
                    ? 0u
                    : nmp_object_type_to_flags(NMP_OBJECT_TYPE_IP_ROUTE(IS_IPv4)));
        }
    }

    if (is_test_quick) {
        gs_free char *msg = NULL;

        msg = g_strdup_printf("Ran a quick version of test %s (try NMTST_DEBUG=slow)",
                              nmtst_test_get_path());
        g_test_skip(msg);
    }
}

/*****************************************************************************/

NMTstpSetupFunc const _nmtstp_setup_platform_func = SETUP;

void
_nmtstp_init_tests(int *argc, char ***argv)
{
    nmtst_init_with_logging(argc, argv, NULL, "ALL");
}

void
_nmtstp_setup_tests(void)
{
#define add_test_func(testpath, test_func) nmtstp_env1_add_test_func(testpath, test_func, 1, TRUE)
#define add_test_func_data(testpath, test_func, arg) \
    nmtstp_env1_add_test_func_data(testpath, test_func, arg, 1, TRUE)
#define add_test_func_data_with_if2(testpath, test_func, arg) \
    nmtstp_env1_add_test_func_data(testpath, test_func, arg, 2, TRUE)

    add_test_func("/route/ip4", test_ip4_route);
    add_test_func("/route/ip6", test_ip6_route);
    add_test_func("/route/ip4_metric0", test_ip4_route_metric0);
    add_test_func_data("/route/ip4_options/1", test_ip4_route_options, GINT_TO_POINTER(1));
    if (nmtstp_is_root_test())
        add_test_func_data("/route/ip4_options/2", test_ip4_route_options, GINT_TO_POINTER(2));
    add_test_func_data("/route/ip6_options/1", test_ip6_route_options, GINT_TO_POINTER(1));
    add_test_func_data("/route/ip6_options/2", test_ip6_route_options, GINT_TO_POINTER(2));
    add_test_func_data("/route/ip6_options/3", test_ip6_route_options, GINT_TO_POINTER(3));

    if (nmtstp_is_root_test()) {
        add_test_func_data("/route/ip/1", test_ip, GINT_TO_POINTER(1));
        add_test_func("/route/ip4_route_get", test_ip4_route_get);
        add_test_func("/route/ip6_route_get", test_ip6_route_get);
        add_test_func("/route/ip4_zero_gateway", test_ip4_zero_gateway);
    }

    if (nmtstp_is_root_test()) {
        add_test_func_data("/route/rule/1", test_rule, GINT_TO_POINTER(1));
        add_test_func_data("/route/rule/2", test_rule, GINT_TO_POINTER(2));
        add_test_func_data("/route/rule/3", test_rule, GINT_TO_POINTER(3));
        add_test_func_data("/route/rule/4", test_rule, GINT_TO_POINTER(4));
    }
    if (nmtstp_is_root_test()) {
        add_test_func_data("/route/blackhole/1", test_blackhole, GINT_TO_POINTER(1));
        add_test_func_data("/route/blackhole/2", test_blackhole, GINT_TO_POINTER(2));
    }
    if (nmtstp_is_root_test()) {
        add_test_func_data("/route/mptcp/1", test_mptcp, GINT_TO_POINTER(1));
        add_test_func_data("/route/mptcp/2", test_mptcp, GINT_TO_POINTER(2));
    }
    if (nmtstp_is_root_test()) {
        add_test_func_data_with_if2("/route/test_cache_consistency_routes/1",
                                    test_cache_consistency_routes,
                                    GINT_TO_POINTER(1));
        add_test_func_data_with_if2("/route/test_cache_consistency_routes/2",
                                    test_cache_consistency_routes,
                                    GINT_TO_POINTER(2));
        add_test_func_data_with_if2("/route/test_cache_consistency_routes/3",
                                    test_cache_consistency_routes,
                                    GINT_TO_POINTER(3));
    }
}
