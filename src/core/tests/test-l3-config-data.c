/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "src/core/nm-default-daemon.h"

#include "nm-l3-config-data.h"
#include "nm-test-utils-core.h"

/*****************************************************************************/

static void
test_l3cd_cmp_default_routes(void)
{
    nm_auto_unref_dedup_multi_index NMDedupMultiIndex *multi_idx = nm_dedup_multi_index_new();
    nm_auto_unref_l3cd_init NML3ConfigData            *a         = NULL;
    nm_auto_unref_l3cd_init NML3ConfigData            *b         = NULL;
    const int                                          IFINDEX   = 1;

    a = nm_l3_config_data_new(multi_idx, IFINDEX, NM_IP_CONFIG_SOURCE_USER);
    nm_l3_config_data_add_route_4(
        a,
        NM_PLATFORM_IP4_ROUTE_INIT(.ifindex = IFINDEX,
                                   .network = 0,
                                   .plen    = 0,
                                   .gateway = nmtst_inet4_from_string("192.168.1.1"),
                                   .metric  = 100));

    b = nm_l3_config_data_new(multi_idx, IFINDEX, NM_IP_CONFIG_SOURCE_USER);
    nm_l3_config_data_add_route_4(
        b,
        NM_PLATFORM_IP4_ROUTE_INIT(.ifindex       = IFINDEX,
                                   .network       = 0,
                                   .plen          = 0,
                                   .gateway       = nmtst_inet4_from_string("192.168.1.1"),
                                   .metric        = 100,
                                   .table_coerced = nm_platform_route_table_coerce(100)));

    nm_l3_config_data_seal(a);
    nm_l3_config_data_seal(b);

    g_assert(nm_l3_config_data_get_best_default_route(a, AF_INET));
    g_assert(!nm_l3_config_data_get_best_default_route(b, AF_INET));

    g_assert_cmpint(nm_l3_config_data_cmp_full(a, b, NM_L3_CONFIG_CMP_FLAGS_ROUTES_ID), !=, 0);
    g_assert_cmpint(nm_l3_config_data_cmp_full(b, a, NM_L3_CONFIG_CMP_FLAGS_ROUTES_ID), !=, 0);

    g_assert_cmpint(nm_l3_config_data_cmp_full(a, b, NM_L3_CONFIG_CMP_FLAGS_ROUTES), !=, 0);
    g_assert_cmpint(nm_l3_config_data_cmp_full(b, a, NM_L3_CONFIG_CMP_FLAGS_ROUTES), !=, 0);

    g_assert_cmpint(nm_l3_config_data_cmp_full(a, b, NM_L3_CONFIG_CMP_FLAGS_ADDRESSES), ==, 0);
    g_assert_cmpint(nm_l3_config_data_cmp_full(b, a, NM_L3_CONFIG_CMP_FLAGS_ADDRESSES), ==, 0);

    g_assert_cmpint(nm_l3_config_data_cmp_full(a, a, NM_L3_CONFIG_CMP_FLAGS_ALL), ==, 0);
    g_assert_cmpint(nm_l3_config_data_cmp_full(b, b, NM_L3_CONFIG_CMP_FLAGS_ALL), ==, 0);
}

typedef struct {
    const char *gateway;
    guint32     metric;
    guint8      rt_pref;
} TestRoute6;

static struct in6_addr
_best_default_route_6_gateway(NMDedupMultiIndex *multi_idx,
                              int                ifindex,
                              const TestRoute6  *routes,
                              guint              n_routes)
{
    nm_auto_unref_l3cd_init NML3ConfigData *l3cd = NULL;
    const NMPObject                        *best;
    guint                                   i;

    l3cd = nm_l3_config_data_new(multi_idx, ifindex, NM_IP_CONFIG_SOURCE_USER);

    for (i = 0; i < n_routes; i++) {
        nm_l3_config_data_add_route_6(
            l3cd,
            NM_PLATFORM_IP6_ROUTE_INIT(.ifindex = ifindex,
                                       .network = in6addr_any,
                                       .plen    = 0,
                                       .gateway = nmtst_inet6_from_string(routes[i].gateway),
                                       .metric  = routes[i].metric,
                                       .rt_pref = routes[i].rt_pref));
    }

    nm_l3_config_data_seal(l3cd);

    g_assert_cmpint(nm_l3_config_data_get_num_routes(l3cd, AF_INET6), ==, n_routes);

    best = nm_l3_config_data_get_best_default_route(l3cd, AF_INET6);
    g_assert_true(best);

    return NMP_OBJECT_CAST_IP6_ROUTE(best)->gateway;
}

static void
test_l3cd_best_default_route_6_rt_pref(void)
{
    nm_auto_unref_dedup_multi_index NMDedupMultiIndex *multi_idx = nm_dedup_multi_index_new();
    const int                                          IFINDEX   = 1;
    struct in6_addr                                    gw;
    struct in6_addr                                    gw_rev;

    /* With the same metric, the route with the higher router preference wins.
     * The result must not depend on the order in which the routes are added. */
    {
        static const struct {
            guint8      rt_pref_a;
            guint8      rt_pref_b;
            const char *expected_gateway;
        } prefs[] = {
            {NM_ICMPV6_ROUTER_PREF_LOW, NM_ICMPV6_ROUTER_PREF_HIGH, "2001:db8::2"},
            {NM_ICMPV6_ROUTER_PREF_LOW, NM_ICMPV6_ROUTER_PREF_MEDIUM, "2001:db8::2"},
            {NM_ICMPV6_ROUTER_PREF_MEDIUM, NM_ICMPV6_ROUTER_PREF_HIGH, "2001:db8::2"},
            {NM_ICMPV6_ROUTER_PREF_HIGH, NM_ICMPV6_ROUTER_PREF_MEDIUM, "2001:db8::1"},
            {NM_ICMPV6_ROUTER_PREF_HIGH, NM_ICMPV6_ROUTER_PREF_LOW, "2001:db8::1"},
            {NM_ICMPV6_ROUTER_PREF_MEDIUM, NM_ICMPV6_ROUTER_PREF_LOW, "2001:db8::1"},
            /* The invalid preference must be treated as medium. */
            {NM_ICMPV6_ROUTER_PREF_INVALID, NM_ICMPV6_ROUTER_PREF_LOW, "2001:db8::1"},
            {NM_ICMPV6_ROUTER_PREF_INVALID, NM_ICMPV6_ROUTER_PREF_HIGH, "2001:db8::2"},
        };
        guint i;

        for (i = 0; i < G_N_ELEMENTS(prefs); i++) {
            const TestRoute6 routes[] = {
                {"2001:db8::1", 100, prefs[i].rt_pref_a},
                {"2001:db8::2", 100, prefs[i].rt_pref_b},
            };
            const TestRoute6 routes_rev[] = {
                {"2001:db8::2", 100, prefs[i].rt_pref_b},
                {"2001:db8::1", 100, prefs[i].rt_pref_a},
            };

            gw = _best_default_route_6_gateway(multi_idx, IFINDEX, routes, G_N_ELEMENTS(routes));
            nmtst_assert_ip6_address(&gw, prefs[i].expected_gateway);

            gw_rev = _best_default_route_6_gateway(multi_idx,
                                                   IFINDEX,
                                                   routes_rev,
                                                   G_N_ELEMENTS(routes_rev));
            nmtst_assert_ip6_address(&gw_rev, prefs[i].expected_gateway);
        }
    }

    /* The metric takes precedence over the router preference. */
    {
        const TestRoute6 routes[] = {
            {"2001:db8::1", 100, NM_ICMPV6_ROUTER_PREF_LOW},
            {"2001:db8::2", 200, NM_ICMPV6_ROUTER_PREF_HIGH},
        };
        const TestRoute6 routes_rev[] = {
            {"2001:db8::2", 200, NM_ICMPV6_ROUTER_PREF_HIGH},
            {"2001:db8::1", 100, NM_ICMPV6_ROUTER_PREF_LOW},
        };

        gw = _best_default_route_6_gateway(multi_idx, IFINDEX, routes, G_N_ELEMENTS(routes));
        nmtst_assert_ip6_address(&gw, "2001:db8::1");

        gw_rev =
            _best_default_route_6_gateway(multi_idx, IFINDEX, routes_rev, G_N_ELEMENTS(routes_rev));
        nmtst_assert_ip6_address(&gw_rev, "2001:db8::1");
    }

    /* With more than two routes, the one with the best preference wins. */
    {
        const TestRoute6 routes[] = {
            {"2001:db8::1", 100, NM_ICMPV6_ROUTER_PREF_MEDIUM},
            {"2001:db8::2", 100, NM_ICMPV6_ROUTER_PREF_LOW},
            {"2001:db8::3", 100, NM_ICMPV6_ROUTER_PREF_HIGH},
            {"2001:db8::4", 100, NM_ICMPV6_ROUTER_PREF_MEDIUM},
        };

        gw = _best_default_route_6_gateway(multi_idx, IFINDEX, routes, G_N_ELEMENTS(routes));
        nmtst_assert_ip6_address(&gw, "2001:db8::3");
    }

    /* If metric and preference are equal, the result is still deterministic. */
    {
        const TestRoute6 routes[] = {
            {"2001:db8::1", 100, NM_ICMPV6_ROUTER_PREF_MEDIUM},
            {"2001:db8::2", 100, NM_ICMPV6_ROUTER_PREF_MEDIUM},
        };
        const TestRoute6 routes_rev[] = {
            {"2001:db8::2", 100, NM_ICMPV6_ROUTER_PREF_MEDIUM},
            {"2001:db8::1", 100, NM_ICMPV6_ROUTER_PREF_MEDIUM},
        };

        gw = _best_default_route_6_gateway(multi_idx, IFINDEX, routes, G_N_ELEMENTS(routes));
        gw_rev =
            _best_default_route_6_gateway(multi_idx, IFINDEX, routes_rev, G_N_ELEMENTS(routes_rev));
        g_assert_true(IN6_ARE_ADDR_EQUAL(&gw, &gw_rev));
    }
}

static void
test_l3cd_merge_routes_nexthops(void)
{
    nm_auto_unref_dedup_multi_index NMDedupMultiIndex *multi_idx = nm_dedup_multi_index_new();
    nm_auto_unref_l3cd_init NML3ConfigData            *a         = NULL;
    nm_auto_unref_l3cd_init NML3ConfigData            *b         = NULL;
    nm_auto_unref_l3cd_init NML3ConfigData            *c         = NULL;
    const int                                          IFINDEX   = 1;
    const NMPlatformIP6NextHop                        *nh6;

    /*
     * l3cd A:
     *
     * l3cd B:
     *  - nexthop: id 1 dev 1 via 3fff::1
     *  - nexthop: id 2 dev 1 via 3fff::2
     *  - route:   fd01::/64 nhid 1
     *  - route:   fd03::/64 dev 1 via 3fff::3
     *
     * l3cd C:
     *  - nexthop: id 4 dev 1 via 3fff::4
     *  - nexthop: id 5 dev 1 via 3fff::5
     *  - nexthop: id 6 dev 1 via 3fff::6
     *  - nexthop: id 8 dev 1 via 3fff::8
     *  - route:   fd06::/64 nhid 6
     *  - route:   fd07::/64 dev 1 via 3fff::7
     *  - route:   ::/0 nhid 8
     */

    a = nm_l3_config_data_new(multi_idx, IFINDEX, NM_IP_CONFIG_SOURCE_USER);

    b = nm_l3_config_data_new(multi_idx, IFINDEX, NM_IP_CONFIG_SOURCE_USER);
    nm_l3_config_data_add_nexthop_6(
        b,
        NM_PLATFORM_IP6_NEXTHOP_INIT(.ifindex   = IFINDEX,
                                     .id        = 1,
                                     .nh_source = NM_IP_CONFIG_SOURCE_NDISC,
                                     .gateway   = nmtst_inet6_from_string("3fff::1")));
    nm_l3_config_data_add_nexthop_6(
        b,
        NM_PLATFORM_IP6_NEXTHOP_INIT(.ifindex   = IFINDEX,
                                     .id        = 2,
                                     .nh_source = NM_IP_CONFIG_SOURCE_NDISC,
                                     .gateway   = nmtst_inet6_from_string("3fff::2")));
    nm_l3_config_data_add_route_6(
        b,
        NM_PLATFORM_IP6_ROUTE_INIT(.ifindex = IFINDEX,
                                   .network = nmtst_inet6_from_string("fd01::"),
                                   .plen    = 64,
                                   .nhid    = 1,
                                   .gateway = nmtst_inet6_from_string("3fff::1"),
                                   .metric  = 100));
    nm_l3_config_data_add_route_6(
        b,
        NM_PLATFORM_IP6_ROUTE_INIT(.ifindex = IFINDEX,
                                   .network = nmtst_inet6_from_string("fd03::"),
                                   .plen    = 64,
                                   .gateway = nmtst_inet6_from_string("3fff::3"),
                                   .metric  = 100));

    c = nm_l3_config_data_new(multi_idx, IFINDEX, NM_IP_CONFIG_SOURCE_USER);
    nm_l3_config_data_add_nexthop_6(
        c,
        NM_PLATFORM_IP6_NEXTHOP_INIT(.ifindex   = IFINDEX,
                                     .id        = 4,
                                     .nh_source = NM_IP_CONFIG_SOURCE_NDISC,
                                     .gateway   = nmtst_inet6_from_string("3fff::4")));
    nm_l3_config_data_add_nexthop_6(
        c,
        NM_PLATFORM_IP6_NEXTHOP_INIT(.ifindex   = IFINDEX,
                                     .id        = 5,
                                     .nh_source = NM_IP_CONFIG_SOURCE_NDISC,
                                     .gateway   = nmtst_inet6_from_string("3fff::5")));
    nm_l3_config_data_add_nexthop_6(
        c,
        NM_PLATFORM_IP6_NEXTHOP_INIT(.ifindex   = IFINDEX,
                                     .id        = 6,
                                     .nh_source = NM_IP_CONFIG_SOURCE_NDISC,
                                     .gateway   = nmtst_inet6_from_string("3fff::6")));
    nm_l3_config_data_add_nexthop_6(
        c,
        NM_PLATFORM_IP6_NEXTHOP_INIT(.ifindex   = IFINDEX,
                                     .id        = 8,
                                     .nh_source = NM_IP_CONFIG_SOURCE_NDISC,
                                     .gateway   = nmtst_inet6_from_string("3fff::8")));
    nm_l3_config_data_add_route_6(
        c,
        NM_PLATFORM_IP6_ROUTE_INIT(.ifindex = IFINDEX,
                                   .network = nmtst_inet6_from_string("fd06::"),
                                   .plen    = 64,
                                   .nhid    = 6,
                                   .gateway = nmtst_inet6_from_string("3fff::6"),
                                   .metric  = 100));
    nm_l3_config_data_add_route_6(
        c,
        NM_PLATFORM_IP6_ROUTE_INIT(.ifindex = IFINDEX,
                                   .network = nmtst_inet6_from_string("fd07::"),
                                   .plen    = 64,
                                   .gateway = nmtst_inet6_from_string("3fff::7"),
                                   .metric  = 100));
    nm_l3_config_data_add_route_6(
        c,
        NM_PLATFORM_IP6_ROUTE_INIT(.ifindex = IFINDEX,
                                   .network = nmtst_inet6_from_string("::"),
                                   .plen    = 0,
                                   .nhid    = 8,
                                   .gateway = nmtst_inet6_from_string("3fff::8"),
                                   .metric  = 100));

    /* Nexthops not referenced by a route are removed during the merge */

    nm_l3_config_data_merge(a,
                            b,
                            NM_L3_CONFIG_MERGE_FLAGS_NONE,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL);
    nm_l3_config_data_merge(a,
                            c,
                            NM_L3_CONFIG_MERGE_FLAGS_NONE,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL);

    nm_l3_config_data_log(a, "merged", "", LOGL_DEBUG, LOGD_PLATFORM);

    g_assert_cmpint(nm_l3_config_data_get_num_nexthops(a, AF_INET6), ==, 3);
    g_assert_cmpint(nm_l3_config_data_get_num_routes(a, AF_INET6), ==, 5);

    nh6 = nmtst_l3_config_data_get_nexthop_at_6(a, 0);
    g_assert_true(nh6);
    g_assert_cmpint(nh6->id, ==, 1);
    nh6 = nmtst_l3_config_data_get_nexthop_at_6(a, 1);
    g_assert_true(nh6);
    g_assert_cmpint(nh6->id, ==, 6);
    nh6 = nmtst_l3_config_data_get_nexthop_at_6(a, 2);
    g_assert_true(nh6);
    g_assert_cmpint(nh6->id, ==, 8);

    /* Merge without default routes */

    nm_l3_config_data_unref(a);
    a = nm_l3_config_data_new(multi_idx, IFINDEX, NM_IP_CONFIG_SOURCE_USER);
    nm_l3_config_data_merge(a,
                            b,
                            NM_L3_CONFIG_MERGE_FLAGS_NO_DEFAULT_ROUTES,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL);
    nm_l3_config_data_merge(a,
                            c,
                            NM_L3_CONFIG_MERGE_FLAGS_NO_DEFAULT_ROUTES,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL);

    nm_l3_config_data_log(a, "merged-no-default-routes", "", LOGL_DEBUG, LOGD_PLATFORM);

    g_assert_cmpint(nm_l3_config_data_get_num_nexthops(a, AF_INET6), ==, 2);
    g_assert_cmpint(nm_l3_config_data_get_num_routes(a, AF_INET6), ==, 4);

    nh6 = nmtst_l3_config_data_get_nexthop_at_6(a, 0);
    g_assert_true(nh6);
    g_assert_cmpint(nh6->id, ==, 1);
    nh6 = nmtst_l3_config_data_get_nexthop_at_6(a, 1);
    g_assert_true(nh6);
    g_assert_cmpint(nh6->id, ==, 6);

    /* Merge without any routes */

    nm_l3_config_data_unref(a);
    a = nm_l3_config_data_new(multi_idx, IFINDEX, NM_IP_CONFIG_SOURCE_USER);

    nm_l3_config_data_merge(a,
                            b,
                            NM_L3_CONFIG_MERGE_FLAGS_NO_ROUTES,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL);
    nm_l3_config_data_merge(a,
                            c,
                            NM_L3_CONFIG_MERGE_FLAGS_NO_ROUTES,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL);

    nm_l3_config_data_log(a, "merged-no-routes", "", LOGL_DEBUG, LOGD_PLATFORM);

    g_assert_cmpint(nm_l3_config_data_get_num_nexthops(a, AF_INET6), ==, 0);
    g_assert_cmpint(nm_l3_config_data_get_num_routes(a, AF_INET6), ==, 0);
}

static void
test_l3cd_clone_nexthops(void)
{
    nm_auto_unref_dedup_multi_index NMDedupMultiIndex *multi_idx = nm_dedup_multi_index_new();
    nm_auto_unref_l3cd_init NML3ConfigData            *a         = NULL;
    nm_auto_unref_l3cd_init NML3ConfigData            *b         = NULL;
    const int                                          IFINDEX   = 1;

    /*
     * l3cd:
     *  - nexthop: id 1 dev 1 via 3fff::1  (referenced by a route)
     *  - nexthop: id 2 dev 1 via 3fff::2  (not referenced by a route)
     *  - route:   fd01::/64 nhid 1
     *  - route:   fd03::/64 dev 1 via 3fff::3
     */

    a = nm_l3_config_data_new(multi_idx, IFINDEX, NM_IP_CONFIG_SOURCE_USER);
    nm_l3_config_data_add_nexthop_6(
        a,
        NM_PLATFORM_IP6_NEXTHOP_INIT(.ifindex   = IFINDEX,
                                     .id        = 1,
                                     .nh_source = NM_IP_CONFIG_SOURCE_NDISC,
                                     .gateway   = nmtst_inet6_from_string("3fff::1")));
    nm_l3_config_data_add_nexthop_6(
        a,
        NM_PLATFORM_IP6_NEXTHOP_INIT(.ifindex   = IFINDEX,
                                     .id        = 2,
                                     .nh_source = NM_IP_CONFIG_SOURCE_NDISC,
                                     .gateway   = nmtst_inet6_from_string("3fff::2")));
    nm_l3_config_data_add_route_6(
        a,
        NM_PLATFORM_IP6_ROUTE_INIT(.ifindex = IFINDEX,
                                   .network = nmtst_inet6_from_string("fd01::"),
                                   .plen    = 64,
                                   .nhid    = 1,
                                   .gateway = nmtst_inet6_from_string("3fff::1"),
                                   .metric  = 100));
    nm_l3_config_data_add_route_6(
        a,
        NM_PLATFORM_IP6_ROUTE_INIT(.ifindex = IFINDEX,
                                   .network = nmtst_inet6_from_string("fd03::"),
                                   .plen    = 64,
                                   .gateway = nmtst_inet6_from_string("3fff::3"),
                                   .metric  = 100));

    b = nm_l3_config_data_new_clone(a, IFINDEX);
    g_assert_true(!!b);
    g_assert_cmpint(nm_l3_config_data_cmp_full(a, b, NM_L3_CONFIG_CMP_FLAGS_ALL), ==, 0);
}

/*****************************************************************************/

NMTST_DEFINE();

int
main(int argc, char **argv)
{
    nmtst_init_with_logging(&argc, &argv, NULL, "ALL");

    g_test_add_func("/l3cd/cmp_default_routes", test_l3cd_cmp_default_routes);
    g_test_add_func("/l3cd/best_default_route_6_rt_pref", test_l3cd_best_default_route_6_rt_pref);
    g_test_add_func("/l3cd/merge_routes_nexthops", test_l3cd_merge_routes_nexthops);
    g_test_add_func("/l3cd/clone_nexthops", test_l3cd_clone_nexthops);

    return g_test_run();
}
