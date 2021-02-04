/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2015 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include <syslog.h>

#include "ndisc/nm-ndisc.h"
#include "ndisc/nm-fake-ndisc.h"

#include "platform/nm-fake-platform.h"

#include "nm-test-utils-core.h"

/*****************************************************************************/

static NMFakeNDisc *
ndisc_new(void)
{
    NMNDisc *          ndisc;
    const int          ifindex = 1;
    const char *       ifname  = nm_platform_link_get_name(NM_PLATFORM_GET, ifindex);
    NMUtilsIPv6IfaceId iid     = {};

    ndisc        = nm_fake_ndisc_new(ifindex, ifname);
    iid.id_u8[7] = 1;
    nm_ndisc_set_iid(ndisc, iid);
    g_assert(ndisc);

    return NM_FAKE_NDISC(ndisc);
}

/*****************************************************************************/

static void
match_gateway(const NMNDiscData *rdata,
              guint              idx,
              const char *       addr,
              gint64             expiry_msec,
              NMIcmpv6RouterPref pref)
{
    const NMNDiscGateway *gw;

    g_assert(rdata);
    g_assert_cmpint(idx, <, rdata->gateways_n);
    g_assert(rdata->gateways);

    gw = &rdata->gateways[idx];

    nmtst_assert_ip6_address(&gw->address, addr);
    g_assert_cmpint(gw->expiry_msec, ==, expiry_msec);
    g_assert_cmpint(gw->preference, ==, pref);
}

#define match_address(rdata, idx, addr, _expiry_msec, _expiry_preferred_msec)     \
    G_STMT_START                                                                  \
    {                                                                             \
        const NMNDiscData *   _rdata = (rdata);                                   \
        guint                 _idx   = (idx);                                     \
        const NMNDiscAddress *_a;                                                 \
                                                                                  \
        g_assert(_rdata);                                                         \
        g_assert_cmpint(_idx, <, _rdata->addresses_n);                            \
        g_assert(_rdata->addresses);                                              \
                                                                                  \
        _a = &_rdata->addresses[_idx];                                            \
                                                                                  \
        nmtst_assert_ip6_address(&_a->address, (addr));                           \
        g_assert_cmpint(_a->expiry_msec, ==, (_expiry_msec));                     \
        g_assert_cmpint(_a->expiry_preferred_msec, ==, (_expiry_preferred_msec)); \
    }                                                                             \
    G_STMT_END

#define match_route(rdata, idx, nw, pl, gw, _expiry_msec, pref) \
    G_STMT_START                                                \
    {                                                           \
        const NMNDiscData * _rdata = (rdata);                   \
        guint               _idx   = (idx);                     \
        const NMNDiscRoute *_r;                                 \
        int                 _plen = (pl);                       \
                                                                \
        g_assert(_rdata);                                       \
        g_assert_cmpint(_idx, <, _rdata->routes_n);             \
        g_assert(_rdata->routes);                               \
        g_assert(_plen > 0 && _plen <= 128);                    \
                                                                \
        _r = &_rdata->routes[idx];                              \
                                                                \
        nmtst_assert_ip6_address(&_r->network, (nw));           \
        g_assert_cmpint((int) _r->plen, ==, _plen);             \
        nmtst_assert_ip6_address(&_r->gateway, (gw));           \
        g_assert_cmpint(_r->expiry_msec, ==, (_expiry_msec));   \
        g_assert_cmpint(_r->preference, ==, (pref));            \
    }                                                           \
    G_STMT_END

static void
match_dns_server(const NMNDiscData *rdata, guint idx, const char *addr, gint64 expiry_msec)
{
    const NMNDiscDNSServer *dns;

    g_assert(rdata);
    g_assert_cmpint(idx, <, rdata->dns_servers_n);
    g_assert(rdata->dns_servers);

    dns = &rdata->dns_servers[idx];

    nmtst_assert_ip6_address(&dns->address, addr);
    g_assert_cmpint(dns->expiry_msec, ==, expiry_msec);
}

static void
match_dns_domain(const NMNDiscData *rdata, guint idx, const char *domain, gint64 expiry_msec)
{
    const NMNDiscDNSDomain *dns;

    g_assert(rdata);
    g_assert_cmpint(idx, <, rdata->dns_domains_n);
    g_assert(rdata->dns_domains);

    dns = &rdata->dns_domains[idx];

    g_assert_cmpstr(dns->domain, ==, domain);
    g_assert_cmpint(dns->expiry_msec, ==, expiry_msec);
}

/*****************************************************************************/

typedef struct {
    GMainLoop *loop;
    gint64     timestamp_msec_1;
    guint      counter;
    guint      rs_counter;
    gint64     first_solicit_msec;
    guint32    timeout_id;
} TestData;

/*****************************************************************************/

static void
test_simple_changed(NMNDisc *ndisc, const NMNDiscData *rdata, guint changed_int, TestData *data)
{
    NMNDiscConfigMap changed = changed_int;

    switch (data->counter++) {
    case 0:
        g_assert_cmpint(changed,
                        ==,
                        NM_NDISC_CONFIG_DHCP_LEVEL | NM_NDISC_CONFIG_GATEWAYS
                            | NM_NDISC_CONFIG_ADDRESSES | NM_NDISC_CONFIG_ROUTES
                            | NM_NDISC_CONFIG_DNS_SERVERS | NM_NDISC_CONFIG_DNS_DOMAINS
                            | NM_NDISC_CONFIG_HOP_LIMIT | NM_NDISC_CONFIG_MTU);
        g_assert_cmpint(rdata->dhcp_level, ==, NM_NDISC_DHCP_LEVEL_OTHERCONF);
        match_gateway(rdata,
                      0,
                      "fe80::1",
                      data->timestamp_msec_1 + 10000,
                      NM_ICMPV6_ROUTER_PREF_MEDIUM);
        match_address(rdata,
                      0,
                      "2001:db8:a:a::1",
                      data->timestamp_msec_1 + 10000,
                      data->timestamp_msec_1 + 10000);
        match_route(rdata, 0, "2001:db8:a:a::", 64, "fe80::1", data->timestamp_msec_1 + 10000, 10);
        match_dns_server(rdata, 0, "2001:db8:c:c::1", data->timestamp_msec_1 + 10000);
        match_dns_domain(rdata, 0, "foobar.com", data->timestamp_msec_1 + 3500);

        g_assert(nm_fake_ndisc_done(NM_FAKE_NDISC(ndisc)));
        break;
    case 1:
        g_main_loop_quit(data->loop);
        break;
    default:
        g_assert_not_reached();
    }
}

static void
test_simple(void)
{
    nm_auto_unref_gmainloop GMainLoop *loop = g_main_loop_new(NULL, FALSE);
    gs_unref_object NMFakeNDisc *ndisc      = ndisc_new();
    const gint64                 now_msec   = nm_utils_get_monotonic_timestamp_msec();
    TestData                     data       = {
        .loop             = loop,
        .timestamp_msec_1 = now_msec,
    };
    guint id;

    id = nm_fake_ndisc_add_ra(ndisc, 1, NM_NDISC_DHCP_LEVEL_OTHERCONF, 4, 1500);
    g_assert(id);

    nm_fake_ndisc_add_gateway(ndisc, id, "fe80::1", now_msec + 10000, NM_ICMPV6_ROUTER_PREF_MEDIUM);
    nm_fake_ndisc_add_prefix(ndisc,
                             id,
                             "2001:db8:a:a::",
                             64,
                             "fe80::1",
                             now_msec + 10000,
                             now_msec + 10000,
                             10);
    nm_fake_ndisc_add_dns_server(ndisc, id, "2001:db8:c:c::1", now_msec + 10000);
    nm_fake_ndisc_add_dns_domain(ndisc, id, "foobar.com", now_msec + 3500);

    g_signal_connect(ndisc, NM_NDISC_CONFIG_RECEIVED, G_CALLBACK(test_simple_changed), &data);

    nm_ndisc_start(NM_NDISC(ndisc));
    nmtst_main_loop_run_assert(data.loop, 15000);
    g_assert_cmpint(data.counter, ==, 2);
}

/*****************************************************************************/

static void
test_everything_rs_sent(NMNDisc *ndisc, TestData *data)
{
    g_assert_cmpint(data->rs_counter, ==, 0);
    data->rs_counter++;
}

static void
test_everything_changed(NMNDisc *ndisc, const NMNDiscData *rdata, guint changed_int, TestData *data)
{
    NMNDiscConfigMap changed = changed_int;

    if (data->counter == 0) {
        g_assert_cmpint(data->rs_counter, ==, 1);
        g_assert_cmpint(changed,
                        ==,
                        NM_NDISC_CONFIG_DHCP_LEVEL | NM_NDISC_CONFIG_GATEWAYS
                            | NM_NDISC_CONFIG_ADDRESSES | NM_NDISC_CONFIG_ROUTES
                            | NM_NDISC_CONFIG_DNS_SERVERS | NM_NDISC_CONFIG_DNS_DOMAINS
                            | NM_NDISC_CONFIG_HOP_LIMIT | NM_NDISC_CONFIG_MTU);
        match_gateway(rdata,
                      0,
                      "fe80::1",
                      data->timestamp_msec_1 + 10000,
                      NM_ICMPV6_ROUTER_PREF_MEDIUM);
        match_address(rdata,
                      0,
                      "2001:db8:a:a::1",
                      data->timestamp_msec_1 + 10000,
                      data->timestamp_msec_1 + 10000);
        match_route(rdata, 0, "2001:db8:a:a::", 64, "fe80::1", data->timestamp_msec_1 + 10000, 10);
        match_dns_server(rdata, 0, "2001:db8:c:c::1", data->timestamp_msec_1 + 10000);
        match_dns_domain(rdata, 0, "foobar.com", data->timestamp_msec_1 + 10000);
    } else if (data->counter == 1) {
        g_assert_cmpint(changed,
                        ==,
                        NM_NDISC_CONFIG_GATEWAYS | NM_NDISC_CONFIG_ADDRESSES
                            | NM_NDISC_CONFIG_ROUTES | NM_NDISC_CONFIG_DNS_SERVERS
                            | NM_NDISC_CONFIG_DNS_DOMAINS);

        g_assert_cmpint(rdata->gateways_n, ==, 1);
        match_gateway(rdata,
                      0,
                      "fe80::2",
                      data->timestamp_msec_1 + 10000,
                      NM_ICMPV6_ROUTER_PREF_MEDIUM);
        g_assert_cmpint(rdata->addresses_n, ==, 2);
        match_address(rdata,
                      0,
                      "2001:db8:a:a::1",
                      data->timestamp_msec_1 + 10000,
                      data->timestamp_msec_1);
        match_address(rdata,
                      1,
                      "2001:db8:a:b::1",
                      data->timestamp_msec_1 + 10000,
                      data->timestamp_msec_1 + 10000);
        g_assert_cmpint(rdata->routes_n, ==, 1);
        match_route(rdata, 0, "2001:db8:a:b::", 64, "fe80::2", data->timestamp_msec_1 + 10000, 10);
        g_assert_cmpint(rdata->dns_servers_n, ==, 1);
        match_dns_server(rdata, 0, "2001:db8:c:c::2", data->timestamp_msec_1 + 10000);
        g_assert_cmpint(rdata->dns_domains_n, ==, 1);
        match_dns_domain(rdata, 0, "foobar2.com", data->timestamp_msec_1 + 10000);

        g_assert(nm_fake_ndisc_done(NM_FAKE_NDISC(ndisc)));
        g_main_loop_quit(data->loop);
    } else
        g_assert_not_reached();

    data->counter++;
}

static void
test_everything(void)
{
    nm_auto_unref_gmainloop GMainLoop *loop = g_main_loop_new(NULL, FALSE);
    gs_unref_object NMFakeNDisc *ndisc      = ndisc_new();
    const gint64                 now_msec   = nm_utils_get_monotonic_timestamp_msec();
    TestData                     data       = {
        .loop             = loop,
        .timestamp_msec_1 = now_msec,
    };
    guint id;

    id = nm_fake_ndisc_add_ra(ndisc, 1, NM_NDISC_DHCP_LEVEL_NONE, 4, 1500);
    g_assert(id);
    nm_fake_ndisc_add_gateway(ndisc, id, "fe80::1", now_msec + 10000, NM_ICMPV6_ROUTER_PREF_MEDIUM);
    nm_fake_ndisc_add_prefix(ndisc,
                             id,
                             "2001:db8:a:a::",
                             64,
                             "fe80::1",
                             now_msec + 10000,
                             now_msec + 10000,
                             10);
    nm_fake_ndisc_add_dns_server(ndisc, id, "2001:db8:c:c::1", now_msec + 10000);
    nm_fake_ndisc_add_dns_domain(ndisc, id, "foobar.com", now_msec + 10000);

    /* expire everything from the first RA in the second */
    id = nm_fake_ndisc_add_ra(ndisc, 1, NM_NDISC_DHCP_LEVEL_NONE, 4, 1500);
    g_assert(id);
    nm_fake_ndisc_add_gateway(ndisc, id, "fe80::1", now_msec, NM_ICMPV6_ROUTER_PREF_MEDIUM);
    nm_fake_ndisc_add_prefix(ndisc, id, "2001:db8:a:a::", 64, "fe80::1", now_msec, now_msec, 0);
    nm_fake_ndisc_add_dns_server(ndisc, id, "2001:db8:c:c::1", now_msec);
    nm_fake_ndisc_add_dns_domain(ndisc, id, "foobar.com", now_msec);

    /* and add some new stuff */
    nm_fake_ndisc_add_gateway(ndisc, id, "fe80::2", now_msec + 10000, NM_ICMPV6_ROUTER_PREF_MEDIUM);
    nm_fake_ndisc_add_prefix(ndisc,
                             id,
                             "2001:db8:a:b::",
                             64,
                             "fe80::2",
                             now_msec + 10000,
                             now_msec + 10000,
                             10);
    nm_fake_ndisc_add_dns_server(ndisc, id, "2001:db8:c:c::2", now_msec + 10000);
    nm_fake_ndisc_add_dns_domain(ndisc, id, "foobar2.com", now_msec + 10000);

    g_signal_connect(ndisc, NM_NDISC_CONFIG_RECEIVED, G_CALLBACK(test_everything_changed), &data);
    g_signal_connect(ndisc, NM_FAKE_NDISC_RS_SENT, G_CALLBACK(test_everything_rs_sent), &data);

    nm_ndisc_start(NM_NDISC(ndisc));
    nmtst_main_loop_run_assert(data.loop, 15000);
    g_assert_cmpint(data.counter, ==, 2);
    g_assert_cmpint(data.rs_counter, ==, 1);
}

static void
test_preference_order_cb(NMNDisc *          ndisc,
                         const NMNDiscData *rdata,
                         guint              changed_int,
                         TestData *         data)
{
    NMNDiscConfigMap changed = changed_int;

    if (data->counter == 1) {
        g_assert_cmpint(changed,
                        ==,
                        NM_NDISC_CONFIG_GATEWAYS | NM_NDISC_CONFIG_ADDRESSES
                            | NM_NDISC_CONFIG_ROUTES);

        g_assert_cmpint(rdata->gateways_n, ==, 2);
        match_gateway(rdata,
                      0,
                      "fe80::1",
                      data->timestamp_msec_1 + 10000,
                      NM_ICMPV6_ROUTER_PREF_HIGH);
        match_gateway(rdata,
                      1,
                      "fe80::2",
                      data->timestamp_msec_1 + 11000,
                      NM_ICMPV6_ROUTER_PREF_LOW);
        g_assert_cmpint(rdata->addresses_n, ==, 2);
        match_address(rdata,
                      0,
                      "2001:db8:a:a::1",
                      data->timestamp_msec_1 + 10000,
                      data->timestamp_msec_1 + 10000);
        match_address(rdata,
                      1,
                      "2001:db8:a:b::1",
                      data->timestamp_msec_1 + 11000,
                      data->timestamp_msec_1 + 10000);
        g_assert_cmpint(rdata->routes_n, ==, 2);
        match_route(rdata, 0, "2001:db8:a:b::", 64, "fe80::2", data->timestamp_msec_1 + 11000, 10);
        match_route(rdata, 1, "2001:db8:a:a::", 64, "fe80::1", data->timestamp_msec_1 + 10000, 5);

        g_assert(nm_fake_ndisc_done(NM_FAKE_NDISC(ndisc)));
        g_main_loop_quit(data->loop);
    }

    data->counter++;
}

static void
test_preference_order(void)
{
    nm_auto_unref_gmainloop GMainLoop *loop = g_main_loop_new(NULL, FALSE);
    gs_unref_object NMFakeNDisc *ndisc      = ndisc_new();
    const gint64                 now_msec   = nm_utils_get_monotonic_timestamp_msec();
    TestData                     data       = {
        .loop             = loop,
        .timestamp_msec_1 = now_msec,
    };
    guint id;

    /* Test insertion order of gateways */

    id = nm_fake_ndisc_add_ra(ndisc, 1, NM_NDISC_DHCP_LEVEL_NONE, 4, 1500);
    g_assert(id);
    nm_fake_ndisc_add_gateway(ndisc, id, "fe80::1", now_msec + 10000, NM_ICMPV6_ROUTER_PREF_HIGH);
    nm_fake_ndisc_add_prefix(ndisc,
                             id,
                             "2001:db8:a:a::",
                             64,
                             "fe80::1",
                             now_msec + 10000,
                             now_msec + 10000,
                             5);

    id = nm_fake_ndisc_add_ra(ndisc, 1, NM_NDISC_DHCP_LEVEL_NONE, 4, 1500);
    g_assert(id);
    nm_fake_ndisc_add_gateway(ndisc, id, "fe80::2", now_msec + 11000, NM_ICMPV6_ROUTER_PREF_LOW);
    nm_fake_ndisc_add_prefix(ndisc,
                             id,
                             "2001:db8:a:b::",
                             64,
                             "fe80::2",
                             now_msec + 11000,
                             now_msec + 10000,
                             10);

    g_signal_connect(ndisc, NM_NDISC_CONFIG_RECEIVED, G_CALLBACK(test_preference_order_cb), &data);

    nm_ndisc_start(NM_NDISC(ndisc));
    nmtst_main_loop_run_assert(data.loop, 15000);
    g_assert_cmpint(data.counter, ==, 2);
}

static void
test_preference_changed_cb(NMNDisc *          ndisc,
                           const NMNDiscData *rdata,
                           guint              changed_int,
                           TestData *         data)
{
    NMNDiscConfigMap changed = changed_int;

    if (data->counter == 1) {
        g_assert_cmpint(changed,
                        ==,
                        NM_NDISC_CONFIG_GATEWAYS | NM_NDISC_CONFIG_ADDRESSES
                            | NM_NDISC_CONFIG_ROUTES);
        g_assert_cmpint(rdata->gateways_n, ==, 2);
        match_gateway(rdata,
                      0,
                      "fe80::2",
                      data->timestamp_msec_1 + 11000,
                      NM_ICMPV6_ROUTER_PREF_MEDIUM);
        match_gateway(rdata,
                      1,
                      "fe80::1",
                      data->timestamp_msec_1 + 10000,
                      NM_ICMPV6_ROUTER_PREF_LOW);
        g_assert_cmpint(rdata->addresses_n, ==, 2);
        match_address(rdata,
                      0,
                      "2001:db8:a:a::1",
                      data->timestamp_msec_1 + 10000,
                      data->timestamp_msec_1 + 10000);
        match_address(rdata,
                      1,
                      "2001:db8:a:b::1",
                      data->timestamp_msec_1 + 11000,
                      data->timestamp_msec_1 + 11000);
        g_assert_cmpint(rdata->routes_n, ==, 2);
        match_route(rdata, 0, "2001:db8:a:b::", 64, "fe80::2", data->timestamp_msec_1 + 11000, 10);
        match_route(rdata, 1, "2001:db8:a:a::", 64, "fe80::1", data->timestamp_msec_1 + 10000, 5);
    } else if (data->counter == 2) {
        g_assert_cmpint(changed,
                        ==,
                        NM_NDISC_CONFIG_GATEWAYS | NM_NDISC_CONFIG_ADDRESSES
                            | NM_NDISC_CONFIG_ROUTES);

        g_assert_cmpint(rdata->gateways_n, ==, 2);
        match_gateway(rdata,
                      0,
                      "fe80::1",
                      data->timestamp_msec_1 + 12000,
                      NM_ICMPV6_ROUTER_PREF_HIGH);
        match_gateway(rdata,
                      1,
                      "fe80::2",
                      data->timestamp_msec_1 + 11000,
                      NM_ICMPV6_ROUTER_PREF_MEDIUM);
        g_assert_cmpint(rdata->addresses_n, ==, 2);
        match_address(rdata,
                      0,
                      "2001:db8:a:a::1",
                      data->timestamp_msec_1 + 12000,
                      data->timestamp_msec_1 + 12000);
        match_address(rdata,
                      1,
                      "2001:db8:a:b::1",
                      data->timestamp_msec_1 + 11000,
                      data->timestamp_msec_1 + 11000);
        g_assert_cmpint(rdata->routes_n, ==, 2);
        match_route(rdata, 0, "2001:db8:a:a::", 64, "fe80::1", data->timestamp_msec_1 + 12000, 15);
        match_route(rdata, 1, "2001:db8:a:b::", 64, "fe80::2", data->timestamp_msec_1 + 11000, 10);

        g_assert(nm_fake_ndisc_done(NM_FAKE_NDISC(ndisc)));
        g_main_loop_quit(data->loop);
    }

    data->counter++;
}

static void
test_preference_changed(void)
{
    nm_auto_unref_gmainloop GMainLoop *loop = g_main_loop_new(NULL, FALSE);
    gs_unref_object NMFakeNDisc *ndisc      = ndisc_new();
    const gint64                 now_msec   = nm_utils_get_monotonic_timestamp_msec();
    TestData                     data       = {
        .loop             = loop,
        .timestamp_msec_1 = now_msec,
    };
    guint id;

    /* Test that when a low-preference and medium gateway send advertisements,
     * that if the low-preference gateway switches to high-preference, we do
     * not get duplicates in the gateway list.
     */

    id = nm_fake_ndisc_add_ra(ndisc, 1, NM_NDISC_DHCP_LEVEL_NONE, 4, 1500);
    g_assert(id);
    nm_fake_ndisc_add_gateway(ndisc, id, "fe80::1", now_msec + 10000, NM_ICMPV6_ROUTER_PREF_LOW);
    nm_fake_ndisc_add_prefix(ndisc,
                             id,
                             "2001:db8:a:a::",
                             64,
                             "fe80::1",
                             now_msec + 10000,
                             now_msec + 10000,
                             5);

    id = nm_fake_ndisc_add_ra(ndisc, 1, NM_NDISC_DHCP_LEVEL_NONE, 4, 1500);
    g_assert(id);
    nm_fake_ndisc_add_gateway(ndisc, id, "fe80::2", now_msec + 11000, NM_ICMPV6_ROUTER_PREF_MEDIUM);
    nm_fake_ndisc_add_prefix(ndisc,
                             id,
                             "2001:db8:a:b::",
                             64,
                             "fe80::2",
                             now_msec + 11000,
                             now_msec + 11000,
                             10);

    id = nm_fake_ndisc_add_ra(ndisc, 1, NM_NDISC_DHCP_LEVEL_NONE, 4, 1500);
    g_assert(id);
    nm_fake_ndisc_add_gateway(ndisc, id, "fe80::1", now_msec + 12000, NM_ICMPV6_ROUTER_PREF_HIGH);
    nm_fake_ndisc_add_prefix(ndisc,
                             id,
                             "2001:db8:a:a::",
                             64,
                             "fe80::1",
                             now_msec + 12000,
                             now_msec + 12000,
                             15);

    g_signal_connect(ndisc,
                     NM_NDISC_CONFIG_RECEIVED,
                     G_CALLBACK(test_preference_changed_cb),
                     &data);

    nm_ndisc_start(NM_NDISC(ndisc));
    nmtst_main_loop_run_assert(data.loop, 15000);
    g_assert_cmpint(data.counter, ==, 3);
}

/*****************************************************************************/

static void
_test_dns_solicit_loop_changed(NMNDisc *          ndisc,
                               const NMNDiscData *rdata,
                               guint              changed_int,
                               TestData *         data)
{
    data->counter++;
}

static void
_test_dns_solicit_loop_rs_sent(NMFakeNDisc *ndisc, TestData *data)
{
    data->rs_counter++;
}

static void
test_dns_solicit_loop(void)
{
    nm_auto_unref_gmainloop GMainLoop *loop = g_main_loop_new(NULL, FALSE);
    gs_unref_object NMFakeNDisc *ndisc      = ndisc_new();
    const gint64                 now_msec   = nm_utils_get_monotonic_timestamp_msec();
    TestData                     data       = {
        .loop             = loop,
        .timestamp_msec_1 = now_msec,
    };
    guint id;

    /* Ensure that no solicitation loop happens when DNS servers or domains
     * stop being sent in advertisements.  This can happen if two routers
     * send RAs, but the one sending DNS info stops responding, or if one
     * router removes the DNS info from the RA without zero-lifetiming them
     * first.
     */

    id = nm_fake_ndisc_add_ra(ndisc, 1, NM_NDISC_DHCP_LEVEL_NONE, 4, 1500);
    g_assert(id);
    nm_fake_ndisc_add_gateway(ndisc, id, "fe80::1", now_msec + 10000, NM_ICMPV6_ROUTER_PREF_LOW);
    nm_fake_ndisc_add_dns_server(ndisc, id, "2001:db8:c:c::1", now_msec + 6000);

    g_signal_connect(ndisc,
                     NM_NDISC_CONFIG_RECEIVED,
                     G_CALLBACK(_test_dns_solicit_loop_changed),
                     &data);
    g_signal_connect(ndisc,
                     NM_FAKE_NDISC_RS_SENT,
                     G_CALLBACK(_test_dns_solicit_loop_rs_sent),
                     &data);

    nm_ndisc_start(NM_NDISC(ndisc));
    if (nmtst_main_loop_run(data.loop, 10000))
        g_error("we expect to run the loop until timeout. What is wrong?");
    g_assert_cmpint(data.counter, ==, 3);
    g_assert_cmpint(data.rs_counter, ==, 1);
}

/*****************************************************************************/

NMTST_DEFINE();

int
main(int argc, char **argv)
{
    nmtst_init_with_logging(&argc, &argv, NULL, "DEFAULT");

    if (nmtst_test_quick()) {
        g_print("Skipping test: don't run long running test %s (NMTST_DEBUG=slow)\n",
                g_get_prgname() ?: "test-ndisc-fake");
        return g_test_run();
    }

    nm_fake_platform_setup();

    g_test_add_func("/ndisc/simple", test_simple);
    g_test_add_func("/ndisc/everything-changed", test_everything);
    g_test_add_func("/ndisc/preference-order", test_preference_order);
    g_test_add_func("/ndisc/preference-changed", test_preference_changed);
    g_test_add_func("/ndisc/dns-solicit-loop", test_dns_solicit_loop);

    return g_test_run();
}
