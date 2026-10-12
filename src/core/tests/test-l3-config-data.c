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

/*****************************************************************************/

NMTST_DEFINE();

int
main(int argc, char **argv)
{
    nmtst_init_with_logging(&argc, &argv, NULL, "ALL");

    g_test_add_func("/l3cd/cmp_default_routes", test_l3cd_cmp_default_routes);

    return g_test_run();
}
