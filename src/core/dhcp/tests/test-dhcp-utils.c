/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2008 - 2014 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/rtnetlink.h>

#include "libnm-glib-aux/nm-dedup-multi.h"
#include "nm-utils.h"

#include "dhcp/nm-dhcp-utils.h"
#include "dhcp/nm-dhcp-options.h"
#include "libnm-platform/nm-platform.h"

#include "nm-test-utils-core.h"

/*****************************************************************************/

static const NML3ConfigData *
_ip4_config_from_options(int ifindex, const char *iface, GHashTable *options)
{
    nm_auto_unref_dedup_multi_index NMDedupMultiIndex *multi_idx = nm_dedup_multi_index_new();
    NML3ConfigData                                    *l3cd;

    l3cd = nm_dhcp_utils_ip4_config_from_options(multi_idx, ifindex, iface, options);
    g_assert(NM_IS_L3_CONFIG_DATA(l3cd));
    g_assert(!nm_l3_config_data_is_sealed(l3cd));
    if (nmtst_get_rand_bool())
        nm_l3_config_data_seal(l3cd);
    return l3cd;
}

typedef struct {
    const char *name;
    const char *value;
} Option;

static GHashTable *
fill_table(const Option *test_options, GHashTable *table)
{
    const Option *opt;

    if (!table)
        table = g_hash_table_new_full(nm_str_hash, g_str_equal, NULL, NULL);
    for (opt = test_options; opt->name; opt++)
        g_hash_table_insert(table, (gpointer) opt->name, (gpointer) opt->value);
    return table;
}

static const Option generic_options[] = {
    {"subnet_mask", "255.255.255.0"},
    {"ip_address", "192.168.1.106"},
    {"network_number", "192.168.1.0"},
    {"expiry", "1232324877"},
    {"dhcp_lease_time", "3600"},
    {"dhcp_server_identifier", "192.168.1.1"},
    {"routers", "192.168.1.1"},
    {"domain_name_servers", "216.254.95.2 216.231.41.2"},
    {"dhcp_message_type", "5"},
    {"broadcast_address", "192.168.1.255"},
    {"domain_search", "foobar.com blah.foobar.com"},
    {"host_name", "nmreallywhipsthe"},
    {"domain_name", "lamasass.com"},
    {"interface_mtu", "987"},
    {"static_routes", "10.1.1.5 10.1.1.1 100.99.88.56 10.1.1.1"},
    {NULL, NULL}};

static void
test_generic_options(void)
{
    gs_unref_hashtable GHashTable           *options = NULL;
    nm_auto_unref_l3cd const NML3ConfigData *l3cd    = NULL;
    const NMPlatformIP4Address              *address;
    const NMPlatformIP4Route                *route;
    guint32                                  tmp;
    const char                              *expected_addr        = "192.168.1.106";
    const char                              *expected_gw          = "192.168.1.1";
    const char                              *expected_dns1        = "216.254.95.2";
    const char                              *expected_dns2        = "216.231.41.2";
    const char                              *expected_search1     = "foobar.com";
    const char                              *expected_search2     = "blah.foobar.com";
    const char                              *expected_route1_dest = "10.1.1.5";
    const char                              *expected_route1_gw   = "10.1.1.1";
    const char                              *expected_route2_dest = "100.99.88.56";
    const char                              *expected_route2_gw   = "10.1.1.1";
    const char *const                       *strarr;
    guint                                    u;

    options = fill_table(generic_options, NULL);
    l3cd    = _ip4_config_from_options(1, "eth0", options);

    g_assert_cmpint(nm_l3_config_data_get_num_addresses(l3cd, AF_INET), ==, 1);
    address = nmtst_l3_config_data_get_address_at_4(l3cd, 0);
    g_assert(inet_pton(AF_INET, expected_addr, &tmp) > 0);
    g_assert(address->address == tmp);
    g_assert(address->peer_address == tmp);
    g_assert_cmpint(address->plen, ==, 24);

    nmtst_assert_ip_address(AF_INET,
                            nmtst_l3_config_data_get_best_gateway(l3cd, AF_INET),
                            expected_gw);

    g_assert(!nm_l3_config_data_get_wins(l3cd, &u));
    g_assert_cmpint(u, ==, 0);

    g_assert_cmpint(nm_l3_config_data_get_mtu(l3cd), ==, 987);

    strarr = nm_l3_config_data_get_searches(l3cd, AF_INET, &u);
    g_assert_cmpint(u, ==, 2);
    g_assert_cmpstr(strarr[0], ==, expected_search1);
    g_assert_cmpstr(strarr[1], ==, expected_search2);

    strarr = nm_l3_config_data_get_nameservers(l3cd, AF_INET, &u);
    g_assert_cmpint(u, ==, 2);
    g_assert_cmpstr(strarr[0], ==, expected_dns1);
    g_assert_cmpstr(strarr[1], ==, expected_dns2);

    g_assert_cmpint(nm_l3_config_data_get_num_routes(l3cd, AF_INET), ==, 3);

    route = nmtst_l3_config_data_get_route_at_4(l3cd, 0);
    g_assert(inet_pton(AF_INET, expected_route1_dest, &tmp) > 0);
    g_assert(route->network == tmp);
    g_assert(inet_pton(AF_INET, expected_route1_gw, &tmp) > 0);
    g_assert(route->gateway == tmp);
    g_assert_cmpint(route->plen, ==, 32);
    g_assert_cmpint(route->metric, ==, 0);

    route = nmtst_l3_config_data_get_route_at_4(l3cd, 1);
    g_assert(route->network == nmtst_inet4_from_string(expected_route2_dest));
    g_assert(route->gateway == nmtst_inet4_from_string(expected_route2_gw));
    g_assert_cmpint(route->plen, ==, 32);
    g_assert_cmpint(route->metric, ==, 0);

    route = nmtst_l3_config_data_get_route_at_4(l3cd, 2);
    g_assert(route->network == nmtst_inet4_from_string("0.0.0.0"));
    g_assert(route->gateway == nmtst_inet4_from_string("192.168.1.1"));
    g_assert_cmpint(route->plen, ==, 0);
    g_assert_cmpint(route->metric, ==, 0);
}

static void
test_wins_options(void)
{
    gs_unref_hashtable GHashTable           *options = NULL;
    nm_auto_unref_l3cd const NML3ConfigData *l3cd    = NULL;
    const NMPlatformIP4Address              *address;
    const char                              *expected_wins1 = "63.12.199.5";
    const char                              *expected_wins2 = "150.4.88.120";
    static const Option data[] = {{"netbios_name_servers", "63.12.199.5 150.4.88.120"},
                                  {NULL, NULL}};
    const in_addr_t    *ia_arr;
    guint               u;

    options = fill_table(generic_options, NULL);
    options = fill_table(data, options);
    l3cd    = _ip4_config_from_options(1, "eth0", options);

    g_assert_cmpint(nm_l3_config_data_get_num_addresses(l3cd, AF_INET), ==, 1);
    address = nmtst_l3_config_data_get_address_at_4(l3cd, 0);
    g_assert(address);

    ia_arr = nm_l3_config_data_get_wins(l3cd, &u);
    g_assert_cmpint(u, ==, 2);
    nmtst_assert_ip4_address(ia_arr[0], expected_wins1);
    nmtst_assert_ip4_address(ia_arr[1], expected_wins2);
}

static void
test_vendor_option_metered(void)
{
    gs_unref_hashtable GHashTable           *options = NULL;
    nm_auto_unref_l3cd const NML3ConfigData *l3cd    = NULL;
    static const Option data[] = {{"vendor_encapsulated_options", "ANDROID_METERED"}, {NULL, NULL}};

    options = fill_table(generic_options, NULL);
    l3cd    = _ip4_config_from_options(1, "eth0", options);
    g_assert(nm_l3_config_data_get_metered(l3cd) == NM_TERNARY_DEFAULT);
    nm_clear_pointer(&options, g_hash_table_destroy);
    nm_clear_l3cd(&l3cd);

    options = fill_table(generic_options, NULL);
    options = fill_table(data, options);
    l3cd    = _ip4_config_from_options(1, "eth0", options);
    g_assert(nm_l3_config_data_get_metered(l3cd) == TRUE);
}

static void
test_parse_search_list(void)
{
    guint8 *data;
    char  **domains;

    data    = (guint8[]){0x05, 'l', 'o', 'c', 'a', 'l', 0x00};
    domains = nm_dhcp_lease_data_parse_search_list(data, 7, NULL, 0, 0);
    g_assert(domains);
    g_assert_cmpint(g_strv_length(domains), ==, 1);
    g_assert_cmpstr(domains[0], ==, "local");
    g_strfreev(domains);

    data    = (guint8[]){0x04, 't',  'e',  's', 't', 0x07, 'e',  'x',  'a',  'm', 'p', 'l',
                         'e',  0x03, 'c',  'o', 'm', 0x00, 0xc0, 0x05, 0x03, 'a', 'b', 'c',
                         0xc0, 0x0d, 0x06, 'f', 'o', 'o',  'b',  'a',  'r',  0x00};
    domains = nm_dhcp_lease_data_parse_search_list(data, 34, NULL, 0, 0);
    g_assert(domains);
    g_assert_cmpint(g_strv_length(domains), ==, 4);
    g_assert_cmpstr(domains[0], ==, "test.example.com");
    g_assert_cmpstr(domains[1], ==, "example.com");
    g_assert_cmpstr(domains[2], ==, "abc.com");
    g_assert_cmpstr(domains[3], ==, "foobar");
    g_strfreev(domains);

    data = (guint8[]){
        0x40,
        'b',
        'a',
        'd',
    };
    domains = nm_dhcp_lease_data_parse_search_list(data, 4, NULL, 0, 0);
    g_assert(!domains);

    data = (guint8[]){
        0x04,
        'o',
        'k',
        'a',
        'y',
        0x00,
        0x40,
        'b',
        'a',
        'd',
    };
    domains = nm_dhcp_lease_data_parse_search_list(data, 10, NULL, 0, 0);
    g_assert(domains);
    g_assert_cmpint(g_strv_length(domains), ==, 1);
    g_assert_cmpstr(domains[0], ==, "okay");
    g_strfreev(domains);
}

static void
ip4_test_route(const NML3ConfigData *l3cd,
               guint                 route_num,
               const char           *expected_dest,
               const char           *expected_gw,
               guint                 expected_prefix)
{
    const NMPlatformIP4Route *route;
    guint32                   tmp;

    g_assert(expected_prefix <= 32);

    route = nmtst_l3_config_data_get_route_at_4(l3cd, route_num);
    g_assert(inet_pton(AF_INET, expected_dest, &tmp) > 0);
    g_assert(route->network == tmp);
    g_assert(inet_pton(AF_INET, expected_gw, &tmp) > 0);
    g_assert(route->gateway == tmp);
    g_assert_cmpint(route->plen, ==, expected_prefix);
    g_assert_cmpint(route->metric, ==, 0);
}

#define ip4_test_gateway(l3cd, expected_gw)                                            \
    G_STMT_START                                                                       \
    {                                                                                  \
        const NML3ConfigData *_l3cd = (l3cd);                                          \
                                                                                       \
        g_assert_cmpint(nm_l3_config_data_get_num_addresses(_l3cd, AF_INET), ==, 1);   \
        nmtst_assert_ip_address(AF_INET,                                               \
                                nmtst_l3_config_data_get_best_gateway(_l3cd, AF_INET), \
                                expected_gw);                                          \
    }                                                                                  \
    G_STMT_END

static void
test_classless_static_routes_1(void)
{
    gs_unref_hashtable GHashTable           *options              = NULL;
    nm_auto_unref_l3cd const NML3ConfigData *l3cd                 = NULL;
    const char                              *expected_route1_dest = "192.168.10.0";
    const char                              *expected_route1_gw   = "192.168.1.1";
    const char                              *expected_route2_dest = "10.0.0.0";
    const char                              *expected_route2_gw   = "10.17.66.41";
    static const Option                      data[]               = {
        /* dhclient custom format */
        {"rfc3442_classless_static_routes", "24 192 168 10 192 168 1 1 8 10 10 17 66 41"},
        {NULL, NULL}};

    options = fill_table(generic_options, NULL);
    options = fill_table(data, options);
    l3cd    = _ip4_config_from_options(1, "eth0", options);

    /* IP4 routes */
    g_assert_cmpint(nm_l3_config_data_get_num_routes(l3cd, AF_INET), ==, 3);
    ip4_test_route(l3cd, 0, expected_route1_dest, expected_route1_gw, 24);
    ip4_test_route(l3cd, 1, expected_route2_dest, expected_route2_gw, 8);
    ip4_test_route(l3cd, 2, "0.0.0.0", "192.168.1.1", 0);
}

static void
test_classless_static_routes_2(void)
{
    gs_unref_hashtable GHashTable           *options              = NULL;
    nm_auto_unref_l3cd const NML3ConfigData *l3cd                 = NULL;
    const char                              *expected_route1_dest = "192.168.10.0";
    const char                              *expected_route1_gw   = "192.168.1.1";
    const char                              *expected_route2_dest = "10.0.0.0";
    const char                              *expected_route2_gw   = "10.17.66.41";
    static const Option                      data[]               = {
        /* dhcpcd format */
        {"classless_static_routes", "192.168.10.0/24 192.168.1.1 10.0.0.0/8 10.17.66.41"},
        {NULL, NULL}};

    options = fill_table(generic_options, NULL);
    options = fill_table(data, options);
    l3cd    = _ip4_config_from_options(1, "eth0", options);

    /* IP4 routes */
    g_assert_cmpint(nm_l3_config_data_get_num_routes(l3cd, AF_INET), ==, 3);
    ip4_test_route(l3cd, 0, expected_route1_dest, expected_route1_gw, 24);
    ip4_test_route(l3cd, 1, expected_route2_dest, expected_route2_gw, 8);
    ip4_test_route(l3cd, 2, "0.0.0.0", expected_route1_gw, 0);
}

static void
test_fedora_dhclient_classless_static_routes(void)
{
    gs_unref_hashtable GHashTable           *options              = NULL;
    nm_auto_unref_l3cd const NML3ConfigData *l3cd                 = NULL;
    const char                              *expected_route1_dest = "129.210.177.128";
    const char                              *expected_route1_gw   = "192.168.0.113";
    const char                              *expected_route2_dest = "2.0.0.0";
    const char                              *expected_route2_gw   = "10.34.255.6";
    const char                              *expected_gateway     = "192.168.0.113";
    static const Option                      data[]               = {
        /* Fedora dhclient format */
        {"classless_static_routes",
                                            "0 192.168.0.113 25.129.210.177.132 192.168.0.113 7.2 10.34.255.6"},
        {NULL, NULL}};

    options = fill_table(generic_options, NULL);
    options = fill_table(data, options);
    l3cd    = _ip4_config_from_options(1, "eth0", options);

    /* IP4 routes */
    g_assert_cmpint(nm_l3_config_data_get_num_routes(l3cd, AF_INET), ==, 3);
    ip4_test_route(l3cd, 0, expected_route1_dest, expected_route1_gw, 25);
    ip4_test_route(l3cd, 1, expected_route2_dest, expected_route2_gw, 7);
    ip4_test_route(l3cd, 2, "0.0.0.0", expected_route1_gw, 0);

    ip4_test_gateway(l3cd, expected_gateway);
}

static void
test_dhclient_invalid_classless_routes_1(void)
{
    gs_unref_hashtable GHashTable           *options              = NULL;
    nm_auto_unref_l3cd const NML3ConfigData *l3cd                 = NULL;
    const char                              *expected_route1_dest = "192.168.10.0";
    const char                              *expected_route1_gw   = "192.168.1.1";
    static const Option                      data[]               = {
        /* dhclient format */
        {"rfc3442_classless_static_routes", "24 192 168 10 192 168 1 1 45 10 17 66 41"},
        {NULL, NULL}};

    options = fill_table(generic_options, NULL);
    options = fill_table(data, options);

    NMTST_EXPECT_NM_WARN("*ignoring invalid classless static routes*");
    l3cd = _ip4_config_from_options(1, "eth0", options);
    g_test_assert_expected_messages();

    /* IP4 routes */
    g_assert_cmpint(nm_l3_config_data_get_num_routes(l3cd, AF_INET), ==, 2);
    ip4_test_route(l3cd, 0, expected_route1_dest, expected_route1_gw, 24);
    ip4_test_route(l3cd, 1, "0.0.0.0", expected_route1_gw, 0);
}

static void
test_dhcpcd_invalid_classless_routes_1(void)
{
    gs_unref_hashtable GHashTable           *options              = NULL;
    nm_auto_unref_l3cd const NML3ConfigData *l3cd                 = NULL;
    const char                              *expected_route1_dest = "10.1.1.5";
    const char                              *expected_route1_gw   = "10.1.1.1";
    const char                              *expected_route2_dest = "100.99.88.56";
    const char                              *expected_route2_gw   = "10.1.1.1";
    static const Option                      data[]               = {
        /* dhcpcd format */
        {"classless_static_routes", "192.168.10.0/24 192.168.1.1 10.0.adfadf/44 10.17.66.41"},
        {NULL, NULL}};

    options = fill_table(generic_options, NULL);
    options = fill_table(data, options);

    NMTST_EXPECT_NM_WARN("*ignoring invalid classless static routes*");
    l3cd = _ip4_config_from_options(1, "eth0", options);
    g_test_assert_expected_messages();

    /* Test falling back to old-style static routes if the classless static
     * routes are invalid.
     */
    g_assert_cmpint(nm_l3_config_data_get_num_routes(l3cd, AF_INET), ==, 3);
    ip4_test_route(l3cd, 0, expected_route1_dest, expected_route1_gw, 32);
    ip4_test_route(l3cd, 1, expected_route2_dest, expected_route2_gw, 32);
    ip4_test_route(l3cd, 2, "0.0.0.0", "192.168.1.1", 0);
}

static void
test_dhclient_invalid_classless_routes_2(void)
{
    gs_unref_hashtable GHashTable           *options              = NULL;
    nm_auto_unref_l3cd const NML3ConfigData *l3cd                 = NULL;
    const char                              *expected_route1_dest = "10.1.1.5";
    const char                              *expected_route1_gw   = "10.1.1.1";
    const char                              *expected_route2_dest = "100.99.88.56";
    const char                              *expected_route2_gw   = "10.1.1.1";
    static const Option                      data[]               = {
        {"rfc3442_classless_static_routes", "45 10 17 66 41 24 192 168 10 192 168 1 1"},
        {NULL, NULL}};

    options = fill_table(generic_options, NULL);
    options = fill_table(data, options);

    NMTST_EXPECT_NM_WARN("*ignoring invalid classless static routes*");
    l3cd = _ip4_config_from_options(1, "eth0", options);
    g_test_assert_expected_messages();

    /* Test falling back to old-style static routes if the classless static
     * routes are invalid.
     */
    g_assert_cmpint(nm_l3_config_data_get_num_routes(l3cd, AF_INET), ==, 3);
    ip4_test_route(l3cd, 0, expected_route1_dest, expected_route1_gw, 32);
    ip4_test_route(l3cd, 1, expected_route2_dest, expected_route2_gw, 32);
    ip4_test_route(l3cd, 2, "0.0.0.0", "192.168.1.1", 0);
}

static void
test_dhcpcd_invalid_classless_routes_2(void)
{
    gs_unref_hashtable GHashTable           *options              = NULL;
    nm_auto_unref_l3cd const NML3ConfigData *l3cd                 = NULL;
    const char                              *expected_route1_dest = "10.1.1.5";
    const char                              *expected_route1_gw   = "10.1.1.1";
    const char                              *expected_route2_dest = "100.99.88.56";
    const char                              *expected_route2_gw   = "10.1.1.1";
    static const Option                      data[]               = {
        {"classless_static_routes", "10.0.adfadf/44 10.17.66.41 192.168.10.0/24 192.168.1.1"},
        {NULL, NULL}};

    options = fill_table(generic_options, NULL);
    options = fill_table(data, options);

    NMTST_EXPECT_NM_WARN("*ignoring invalid classless static routes*");
    l3cd = _ip4_config_from_options(1, "eth0", options);
    g_test_assert_expected_messages();

    /* Test falling back to old-style static routes if the classless static
     * routes are invalid.
     */

    /* Routes */
    g_assert_cmpint(nm_l3_config_data_get_num_routes(l3cd, AF_INET), ==, 3);
    ip4_test_route(l3cd, 0, expected_route1_dest, expected_route1_gw, 32);
    ip4_test_route(l3cd, 1, expected_route2_dest, expected_route2_gw, 32);
    ip4_test_route(l3cd, 2, "0.0.0.0", "192.168.1.1", 0);
}

static void
test_dhclient_invalid_classless_routes_3(void)
{
    gs_unref_hashtable GHashTable           *options              = NULL;
    nm_auto_unref_l3cd const NML3ConfigData *l3cd                 = NULL;
    const char                              *expected_route1_dest = "192.168.10.0";
    const char                              *expected_route1_gw   = "192.168.1.1";
    static const Option                      data[]               = {
        {"rfc3442_classless_static_routes", "24 192 168 10 192 168 1 1 32 128 10 17 66 41"},
        {NULL, NULL}};

    options = fill_table(generic_options, NULL);
    options = fill_table(data, options);

    NMTST_EXPECT_NM_WARN("*ignoring invalid classless static routes*");
    l3cd = _ip4_config_from_options(1, "eth0", options);
    g_test_assert_expected_messages();

    /* IP4 routes */
    g_assert_cmpint(nm_l3_config_data_get_num_routes(l3cd, AF_INET), ==, 2);
    ip4_test_route(l3cd, 0, expected_route1_dest, expected_route1_gw, 24);
    ip4_test_route(l3cd, 1, "0.0.0.0", expected_route1_gw, 0);
}

static void
test_dhcpcd_invalid_classless_routes_3(void)
{
    gs_unref_hashtable GHashTable           *options              = NULL;
    nm_auto_unref_l3cd const NML3ConfigData *l3cd                 = NULL;
    const char                              *expected_route1_dest = "192.168.10.0";
    const char                              *expected_route1_gw   = "192.168.1.1";
    static Option                            data[]               = {
        {"classless_static_routes", "192.168.10.0/24 192.168.1.1 128/32 10.17.66.41"},
        {NULL, NULL}};

    options = fill_table(generic_options, NULL);
    options = fill_table(data, options);

    NMTST_EXPECT_NM_WARN("*DHCP provided invalid classless static route*");
    l3cd = _ip4_config_from_options(1, "eth0", options);
    g_test_assert_expected_messages();

    /* IP4 routes */
    g_assert_cmpint(nm_l3_config_data_get_num_routes(l3cd, AF_INET), ==, 2);
    ip4_test_route(l3cd, 0, expected_route1_dest, expected_route1_gw, 24);
    ip4_test_route(l3cd, 1, "0.0.0.0", expected_route1_gw, 0);
}

static void
test_dhclient_gw_in_classless_routes(void)
{
    gs_unref_hashtable GHashTable           *options              = NULL;
    nm_auto_unref_l3cd const NML3ConfigData *l3cd                 = NULL;
    const char                              *expected_route1_dest = "192.168.10.0";
    const char                              *expected_route1_gw   = "192.168.1.1";
    const char                              *expected_gateway     = "192.2.3.4";
    static Option                            data[]               = {
        {"rfc3442_classless_static_routes", "24 192 168 10 192 168 1 1 0 192 2 3 4"},
        {NULL, NULL}};

    options = fill_table(generic_options, NULL);
    options = fill_table(data, options);
    l3cd    = _ip4_config_from_options(1, "eth0", options);

    /* IP4 routes */
    g_assert_cmpint(nm_l3_config_data_get_num_routes(l3cd, AF_INET), ==, 2);
    ip4_test_route(l3cd, 0, expected_route1_dest, expected_route1_gw, 24);
    ip4_test_route(l3cd, 1, "0.0.0.0", "192.2.3.4", 0);

    ip4_test_gateway(l3cd, expected_gateway);
}

static void
test_dhcpcd_gw_in_classless_routes(void)
{
    gs_unref_hashtable GHashTable           *options              = NULL;
    nm_auto_unref_l3cd const NML3ConfigData *l3cd                 = NULL;
    const char                              *expected_route1_dest = "192.168.10.0";
    const char                              *expected_route1_gw   = "192.168.1.1";
    const char                              *expected_gateway     = "192.2.3.4";
    static Option                            data[]               = {
        {"classless_static_routes", "192.168.10.0/24 192.168.1.1 0.0.0.0/0 192.2.3.4"},
        {NULL, NULL}};

    options = fill_table(generic_options, NULL);
    options = fill_table(data, options);
    l3cd    = _ip4_config_from_options(1, "eth0", options);

    /* IP4 routes */
    g_assert_cmpint(nm_l3_config_data_get_num_routes(l3cd, AF_INET), ==, 2);
    ip4_test_route(l3cd, 0, expected_route1_dest, expected_route1_gw, 24);
    ip4_test_route(l3cd, 1, "0.0.0.0", "192.2.3.4", 0);

    ip4_test_gateway(l3cd, expected_gateway);
}

static void
test_escaped_domain_searches(void)
{
    gs_unref_hashtable GHashTable           *options          = NULL;
    nm_auto_unref_l3cd const NML3ConfigData *l3cd             = NULL;
    const char                              *expected_search0 = "host1";
    const char                              *expected_search1 = "host2";
    const char                              *expected_search2 = "host3";
    static const Option data[] = {{"domain_search", "host1\\032host2\\032host3"}, {NULL, NULL}};
    const char *const  *strarr;
    guint               u;

    options = fill_table(generic_options, NULL);
    options = fill_table(data, options);
    l3cd    = _ip4_config_from_options(1, "eth0", options);

    strarr = nm_l3_config_data_get_searches(l3cd, AF_INET, &u);
    g_assert_cmpint(u, ==, 3);
    g_assert_cmpstr(strarr[0], ==, expected_search0);
    g_assert_cmpstr(strarr[1], ==, expected_search1);
    g_assert_cmpstr(strarr[2], ==, expected_search2);
}

static void
test_invalid_escaped_domain_searches(void)
{
    gs_unref_hashtable GHashTable           *options = NULL;
    nm_auto_unref_l3cd const NML3ConfigData *l3cd    = NULL;
    static const Option data[] = {{"domain_search", "host1\\aahost2\\032host3"}, {NULL, NULL}};
    const char *const  *strarr;
    guint               u;

    options = fill_table(generic_options, NULL);
    options = fill_table(data, options);

    NMTST_EXPECT_NM_WARN("*invalid domain search*");
    l3cd = _ip4_config_from_options(1, "eth0", options);
    g_test_assert_expected_messages();

    strarr = nm_l3_config_data_get_searches(l3cd, AF_INET, &u);
    g_assert_cmpint(u, ==, 0);
    g_assert(!strarr);
}

static void
test_ip4_missing_prefix(const char *ip, guint32 expected_prefix)
{
    gs_unref_hashtable GHashTable           *options = NULL;
    nm_auto_unref_l3cd const NML3ConfigData *l3cd    = NULL;
    const NMPlatformIP4Address              *address;

    options = fill_table(generic_options, NULL);
    g_hash_table_insert(options, "ip_address", (gpointer) ip);
    g_hash_table_remove(options, "subnet_mask");

    l3cd = _ip4_config_from_options(1, "eth0", options);

    g_assert_cmpint(nm_l3_config_data_get_num_addresses(l3cd, AF_INET), ==, 1);
    address = nmtst_l3_config_data_get_address_at_4(l3cd, 0);
    g_assert(address);
    g_assert_cmpint(address->plen, ==, expected_prefix);
}

static void
test_ip4_missing_prefix_24(void)
{
    test_ip4_missing_prefix("192.168.1.10", 24);
}

static void
test_ip4_missing_prefix_16(void)
{
    test_ip4_missing_prefix("172.16.54.50", 16);
}

static void
test_ip4_missing_prefix_8(void)
{
    test_ip4_missing_prefix("10.1.2.3", 8);
}

static void
test_ip4_prefix_classless(void)
{
    gs_unref_hashtable GHashTable           *options = NULL;
    nm_auto_unref_l3cd const NML3ConfigData *l3cd    = NULL;
    const NMPlatformIP4Address              *address;

    /* Ensure that the missing-subnet-mask handler doesn't mangle classless
     * subnet masks at all.  The handler should trigger only if the server
     * doesn't send the subnet mask.
     */

    options = fill_table(generic_options, NULL);
    g_hash_table_insert(options, "ip_address", "172.16.54.22");
    g_hash_table_insert(options, "subnet_mask", "255.255.252.0");

    l3cd = _ip4_config_from_options(1, "eth0", options);

    g_assert_cmpint(nm_l3_config_data_get_num_addresses(l3cd, AF_INET), ==, 1);
    address = nmtst_l3_config_data_get_address_at_4(l3cd, 0);
    g_assert(address);
    g_assert_cmpint(address->plen, ==, 22);
}

#define COMPARE_ID(src, is_str, expected, expected_len)           \
    G_STMT_START                                                  \
    {                                                             \
        gs_unref_bytes GBytes *b = NULL;                          \
        const char            *p;                                 \
        gsize                  l;                                 \
                                                                  \
        b = nm_dhcp_utils_client_id_string_to_bytes(src);         \
        g_assert(b);                                              \
        p = g_bytes_get_data(b, &l);                              \
        if (is_str) {                                             \
            g_assert_cmpint(l, ==, expected_len + 1);             \
            g_assert_cmpint(((const char *) p)[0], ==, 0);        \
            g_assert(memcmp(p + 1, expected, expected_len) == 0); \
        } else {                                                  \
            g_assert_cmpint(l, ==, expected_len);                 \
            g_assert(memcmp(p, expected, expected_len) == 0);     \
        }                                                         \
    }                                                             \
    G_STMT_END

static void
test_client_id_from_string(void)
{
    const char  *nothex       = "asdfasdfasdfasdfasdfasdfasdf";
    const char  *allhex       = "00:11:22:33:4:55:66:77:88";
    const guint8 allhex_bin[] = {0x00, 0x11, 0x22, 0x33, 0x04, 0x55, 0x66, 0x77, 0x88};
    const char  *somehex      = "00:11:22:33:44:55:asdfasdfasdf:99:10";
    const char  *nocolons     = "0011223344559910";
    const char  *endcolon     = "00:11:22:33:44:55:";

    COMPARE_ID(nothex, TRUE, nothex, strlen(nothex));
    COMPARE_ID(allhex, FALSE, allhex_bin, sizeof(allhex_bin));
    COMPARE_ID(somehex, TRUE, somehex, strlen(somehex));
    COMPARE_ID(nocolons, TRUE, nocolons, strlen(nocolons));
    COMPARE_ID(endcolon, TRUE, endcolon, strlen(endcolon));
}

/*****************************************************************************/

static void
test_dhcp_opt_list(gconstpointer test_data)
{
    const gboolean            IS_IPv4     = (GPOINTER_TO_INT(test_data) == 0);
    const int                 addr_family = IS_IPv4 ? AF_INET : AF_INET6;
    const NMDhcpOption *const options =
        IS_IPv4 ? _nm_dhcp_option_dhcp4_options : _nm_dhcp_option_dhcp6_options;
    const guint n = (IS_IPv4 ? G_N_ELEMENTS(_nm_dhcp_option_dhcp4_options)
                             : G_N_ELEMENTS(_nm_dhcp_option_dhcp6_options));
    guint       i;
    guint       j;

    g_assert(options);
    g_assert(n > 0);

    for (i = 0; i < n; i++) {
        const NMDhcpOption *const opt = &options[i];

        g_assert_cmpstr(opt->name, !=, NULL);
        g_assert(NM_STR_HAS_PREFIX(opt->name, NM_DHCP_OPTION_REQPREFIX));

        for (j = 0; j < i; j++) {
            const NMDhcpOption *const opt2 = &options[j];

            g_assert_cmpstr(opt->name, !=, opt2->name);
            g_assert_cmpint(opt->option_num, !=, opt2->option_num);
        }
    }

    for (i = 0; i < n; i++) {
        const NMDhcpOption *const opt = &options[i];

        g_assert(opt == nm_dhcp_option_find(addr_family, opt->option_num));
    }
}

/*****************************************************************************/

NMTST_DEFINE();

int
main(int argc, char **argv)
{
    nmtst_init_assert_logging(&argc, &argv, "WARN", "DEFAULT");

    g_test_add_func("/dhcp/generic-options", test_generic_options);
    g_test_add_func("/dhcp/wins-options", test_wins_options);
    g_test_add_func("/dhcp/classless-static-routes-1", test_classless_static_routes_1);
    g_test_add_func("/dhcp/classless-static-routes-2", test_classless_static_routes_2);
    g_test_add_func("/dhcp/fedora-dhclient-classless-static-routes",
                    test_fedora_dhclient_classless_static_routes);
    g_test_add_func("/dhcp/dhclient-invalid-classless-routes-1",
                    test_dhclient_invalid_classless_routes_1);
    g_test_add_func("/dhcp/dhcpcd-invalid-classless-routes-1",
                    test_dhcpcd_invalid_classless_routes_1);
    g_test_add_func("/dhcp/dhclient-invalid-classless-routes-2",
                    test_dhclient_invalid_classless_routes_2);
    g_test_add_func("/dhcp/dhcpcd-invalid-classless-routes-2",
                    test_dhcpcd_invalid_classless_routes_2);
    g_test_add_func("/dhcp/dhclient-invalid-classless-routes-3",
                    test_dhclient_invalid_classless_routes_3);
    g_test_add_func("/dhcp/dhcpcd-invalid-classless-routes-3",
                    test_dhcpcd_invalid_classless_routes_3);
    g_test_add_func("/dhcp/dhclient-gw-in-classless-routes", test_dhclient_gw_in_classless_routes);
    g_test_add_func("/dhcp/dhcpcd-gw-in-classless-routes", test_dhcpcd_gw_in_classless_routes);
    g_test_add_func("/dhcp/escaped-domain-searches", test_escaped_domain_searches);
    g_test_add_func("/dhcp/invalid-escaped-domain-searches", test_invalid_escaped_domain_searches);
    g_test_add_func("/dhcp/ip4-missing-prefix-24", test_ip4_missing_prefix_24);
    g_test_add_func("/dhcp/ip4-missing-prefix-16", test_ip4_missing_prefix_16);
    g_test_add_func("/dhcp/ip4-missing-prefix-8", test_ip4_missing_prefix_8);
    g_test_add_func("/dhcp/ip4-prefix-classless", test_ip4_prefix_classless);
    g_test_add_func("/dhcp/client-id-from-string", test_client_id_from_string);
    g_test_add_func("/dhcp/vendor-option-metered", test_vendor_option_metered);
    g_test_add_func("/dhcp/parse-search-list", test_parse_search_list);
    g_test_add_data_func("/dhcp/test_dhcp_opt_list/IPv4", GINT_TO_POINTER(0), test_dhcp_opt_list);
    g_test_add_data_func("/dhcp/test_dhcp_opt_list/IPv6", GINT_TO_POINTER(1), test_dhcp_opt_list);

    return g_test_run();
}
