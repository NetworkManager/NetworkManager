/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2015 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include <syslog.h>

#include "ndisc/nm-ndisc.h"
#include "ndisc/nm-fake-ndisc.h"

#include "platform/nm-fake-platform.h"
#include "nm-l3-config-data.h"
#include "nm-netns.h"

#include "platform/tests/test-common.h"

/*****************************************************************************/

static NMFakeNDisc *
ndisc_new(void)
{
    gs_unref_object NML3Cfg *l3cfg = NULL;
    NMNDisc                 *ndisc;
    const int                ifindex = 1;
    NMUtilsIPv6IfaceId       iid;

    l3cfg = nm_netns_l3cfg_acquire(NM_NETNS_GET, ifindex);

    ndisc = nm_fake_ndisc_new(l3cfg);
    g_assert(ndisc);

    memset(&iid, 0, sizeof(iid));
    iid.id_u8[7] = 1;
    nm_ndisc_set_iid(ndisc, iid, FALSE);

    return NM_FAKE_NDISC(ndisc);
}

/*****************************************************************************/

static void
match_gateway(const NMNDiscData *rdata,
              guint              idx,
              const char        *addr,
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
        const NMNDiscData    *_rdata = (rdata);                                   \
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
        const NMNDiscData  *_rdata = (rdata);                   \
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
test_simple_changed(NMNDisc              *ndisc,
                    const NMNDiscData    *rdata,
                    guint                 changed_i,
                    const NML3ConfigData *l3cd,
                    TestData             *data)
{
    NMNDiscConfigMap changed = changed_i;

    _LOGT("test_simple: callback (counter=%u)", data->counter);

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
        g_assert_cmpint(rdata->dns_servers_n, ==, 1);
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
    nm_auto_unref_gmainloop GMainLoop *loop     = g_main_loop_new(NULL, FALSE);
    gs_unref_object NMFakeNDisc       *ndisc    = ndisc_new();
    const gint64                       now_msec = nm_utils_get_monotonic_timestamp_msec();
    TestData                           data     = {
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
    /* the unspecified address is invalid and must be ignored. */
    nm_fake_ndisc_add_dns_server(ndisc, id, "::", now_msec + 10000);
    nm_fake_ndisc_add_dns_domain(ndisc, id, "foobar.com", now_msec + 3500);

    g_signal_connect(ndisc, NM_NDISC_CONFIG_RECEIVED, G_CALLBACK(test_simple_changed), &data);

    _LOGT("test_simple: start");
    nm_ndisc_start(NM_NDISC(ndisc));
    nmtst_main_loop_run_assert(data.loop, 15000);
    g_assert_cmpint(data.counter, ==, 2);
    _LOGT("test_simple: done");
}

/*****************************************************************************/

static void
test_everything_rs_sent(NMNDisc *ndisc, TestData *data)
{
    g_assert_cmpint(data->rs_counter, ==, 0);
    data->rs_counter++;
}

static void
test_everything_changed(NMNDisc              *ndisc,
                        const NMNDiscData    *rdata,
                        guint                 changed_i,
                        const NML3ConfigData *l3cd,
                        TestData             *data)
{
    NMNDiscConfigMap changed = changed_i;

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
    nm_auto_unref_gmainloop GMainLoop *loop     = g_main_loop_new(NULL, FALSE);
    gs_unref_object NMFakeNDisc       *ndisc    = ndisc_new();
    const gint64                       now_msec = nm_utils_get_monotonic_timestamp_msec();
    TestData                           data     = {
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
test_preference_order_cb(NMNDisc              *ndisc,
                         const NMNDiscData    *rdata,
                         guint                 changed_i,
                         const NML3ConfigData *l3cd,
                         TestData             *data)
{
    NMNDiscConfigMap changed = changed_i;

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
    nm_auto_unref_gmainloop GMainLoop *loop     = g_main_loop_new(NULL, FALSE);
    gs_unref_object NMFakeNDisc       *ndisc    = ndisc_new();
    const gint64                       now_msec = nm_utils_get_monotonic_timestamp_msec();
    TestData                           data     = {
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
test_preference_changed_cb(NMNDisc              *ndisc,
                           const NMNDiscData    *rdata,
                           guint                 changed_i,
                           const NML3ConfigData *l3cd,
                           TestData             *data)
{
    NMNDiscConfigMap changed = changed_i;

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
    nm_auto_unref_gmainloop GMainLoop *loop     = g_main_loop_new(NULL, FALSE);
    gs_unref_object NMFakeNDisc       *ndisc    = ndisc_new();
    const gint64                       now_msec = nm_utils_get_monotonic_timestamp_msec();
    TestData                           data     = {
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
_test_dns_solicit_loop_changed(NMNDisc              *ndisc,
                               const NMNDiscData    *rdata,
                               guint                 changed_i,
                               const NML3ConfigData *l3cd,
                               TestData             *data)
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
    nm_auto_unref_gmainloop GMainLoop *loop     = g_main_loop_new(NULL, FALSE);
    gs_unref_object NMFakeNDisc       *ndisc    = ndisc_new();
    const gint64                       now_msec = nm_utils_get_monotonic_timestamp_msec();
    TestData                           data     = {
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
    if (data.counter == 2) {
        /* Hm. I saw this too. Odd. But as there are dependencies on the run time,
         * I guess it can just happen. It's probably fine. */
    } else
        g_assert_cmpint(data.counter, ==, 3);
    g_assert_cmpint(data.rs_counter, ==, 1);
}

/*****************************************************************************/

typedef struct {
    /* Borrowed from NDisc, valid until its next configuration update. */
    const NMNDiscData    *rdata;
    const NML3ConfigData *l3cd;
    guint                 counter;
} NexthopTestData;

static void
nexthop_config_changed_cb(NMNDisc              *ndisc,
                          const NMNDiscData    *rdata,
                          guint                 changed,
                          const NML3ConfigData *l3cd,
                          NexthopTestData      *data)
{
    data->rdata = rdata;
    data->l3cd  = l3cd;
    data->counter++;
}

static guint
nexthop_add_router(NMFakeNDisc *ndisc, const char *gateway, NMIcmpv6RouterPref preference)
{
    guint ra_id;

    ra_id = nm_fake_ndisc_add_ra(ndisc, 0, NM_NDISC_DHCP_LEVEL_NONE, 64, 1500);
    nm_fake_ndisc_add_gateway(ndisc, ra_id, gateway, NM_NDISC_EXPIRY_INFINITY, preference);
    return ra_id;
}

static void
nexthop_receive_ras(NMFakeNDisc *ndisc, NexthopTestData *data)
{
    g_signal_connect(ndisc, NM_NDISC_CONFIG_RECEIVED, G_CALLBACK(nexthop_config_changed_cb), data);
    nm_ndisc_start(NM_NDISC(ndisc));
    nmtst_main_context_iterate_until_assert(NULL, 3000, nm_fake_ndisc_done(ndisc));
    g_assert(data->rdata);
    g_assert(data->l3cd);
}

static void
assert_gateway_nexthop(NMNDisc *ndisc, const NML3ConfigData *l3cd, const NMNDiscGateway *gw)
{
    guint i;
    guint n_found = 0;

    g_assert_cmpuint(gw->nexthop_id, >=, 1u << 31);
    g_assert(nm_netns_nexthop_id_is_reserved(NM_NETNS_GET, gw->nexthop_id));

    for (i = 0; i < nm_l3_config_data_get_num_nexthops(l3cd, AF_INET6); i++) {
        const NMPlatformIP6NextHop *nh;

        nh = nmtst_l3_config_data_get_nexthop_at_6(l3cd, i);
        if (nh->id != gw->nexthop_id)
            continue;
        n_found++;
        g_assert_cmpint(nh->ifindex, ==, nm_ndisc_get_ifindex(ndisc));
        g_assert_cmpint(nh->nh_source, ==, NM_IP_CONFIG_SOURCE_NDISC);
        g_assert(IN6_ARE_ADDR_EQUAL(&nh->gateway, &gw->address));
    }
    g_assert_cmpuint(n_found, ==, 1);
}

static void
assert_gateway_default_route(NMNDisc *ndisc, const NML3ConfigData *l3cd, const NMNDiscGateway *gw)
{
    guint i;
    guint n_found = 0;

    /* Find the route by nexthop ID, independently of its position in the L3 config. */
    for (i = 0; i < nm_l3_config_data_get_num_routes(l3cd, AF_INET6); i++) {
        const NMPlatformIP6Route *route;

        route = nmtst_l3_config_data_get_route_at_6(l3cd, i);
        if (route->nhid != gw->nexthop_id)
            continue;
        n_found++;
        g_assert_cmpint(route->ifindex, ==, nm_ndisc_get_ifindex(ndisc));
        g_assert_cmpint(route->rt_source, ==, NM_IP_CONFIG_SOURCE_NDISC);
        g_assert(IN6_IS_ADDR_UNSPECIFIED(&route->network));
        g_assert_cmpuint(route->plen, ==, 0);
        g_assert(IN6_ARE_ADDR_EQUAL(&route->gateway, &gw->address));
        g_assert_cmpint(route->rt_pref, ==, gw->preference);
        g_assert(route->metric_any);
        g_assert_cmpuint(route->metric, ==, 0);
    }
    g_assert_cmpuint(n_found, ==, 1);
}

static void
assert_nexthop_config(NMNDisc *ndisc, const NexthopTestData *data, guint n_routers)
{
    const NMNDiscData *rdata = data->rdata;
    guint              i;
    guint              j;

    g_assert_cmpuint(data->counter, ==, n_routers);
    g_assert_cmpuint(rdata->gateways_n, ==, n_routers);
    g_assert_cmpuint(nm_l3_config_data_get_num_nexthops(data->l3cd, AF_INET6), ==, n_routers);
    g_assert_cmpuint(nm_l3_config_data_get_num_routes(data->l3cd, AF_INET6),
                     ==,
                     n_routers + rdata->routes_n);

    /* Each router must have its own nexthop and default route. */
    for (i = 0; i < n_routers; i++) {
        const NMNDiscGateway *gw = &rdata->gateways[i];

        for (j = 0; j < i; j++)
            g_assert_cmpuint(gw->nexthop_id, !=, rdata->gateways[j].nexthop_id);
        assert_gateway_nexthop(ndisc, data->l3cd, gw);
        assert_gateway_default_route(ndisc, data->l3cd, gw);
    }
}

static void
test_nexthop_single_router(void)
{
    gs_unref_object NMFakeNDisc *ndisc = ndisc_new();
    NexthopTestData              data  = {};
    guint                        ra_id;
    guint                        i;
    guint                        n_prefix_routes = 0;

    /* Even a single router needs a nexthop: another profile can have a default
     * route with the same metric. Only the default route should reference it. */
    ra_id = nexthop_add_router(ndisc, "fe80::1", NM_ICMPV6_ROUTER_PREF_MEDIUM);
    nm_fake_ndisc_add_prefix(ndisc,
                             ra_id,
                             "2001:db8:1::",
                             80,
                             "fe80::1",
                             NM_NDISC_EXPIRY_INFINITY,
                             NM_NDISC_EXPIRY_INFINITY,
                             NM_ICMPV6_ROUTER_PREF_MEDIUM);

    nexthop_receive_ras(ndisc, &data);
    g_assert_cmpuint(data.rdata->routes_n, ==, 1);
    assert_nexthop_config(NM_NDISC(ndisc), &data, 1);
    match_gateway(data.rdata, 0, "fe80::1", NM_NDISC_EXPIRY_INFINITY, NM_ICMPV6_ROUTER_PREF_MEDIUM);

    for (i = 0; i < nm_l3_config_data_get_num_routes(data.l3cd, AF_INET6); i++) {
        const NMPlatformIP6Route *route;

        route = nmtst_l3_config_data_get_route_at_6(data.l3cd, i);
        if (route->plen == 0)
            continue;
        n_prefix_routes++;
        g_assert_cmpuint(route->nhid, ==, 0);
        nmtst_assert_ip6_address(&route->network, "2001:db8:1::");
        g_assert_cmpuint(route->plen, ==, 80);
        nmtst_assert_ip6_address(&route->gateway, "fe80::1");
        g_assert_cmpint(route->rt_pref, ==, NM_ICMPV6_ROUTER_PREF_MEDIUM);
    }
    g_assert_cmpuint(n_prefix_routes, ==, 1);
}

static void
test_nexthop_equal_preference(void)
{
    gs_unref_object NMFakeNDisc *ndisc = ndisc_new();
    NexthopTestData              data  = {};

    /* Equal-preference default routes have the same metric, but must remain
     * separate routes by referencing three distinct nexthop IDs. */
    nexthop_add_router(ndisc, "fe80::1", NM_ICMPV6_ROUTER_PREF_MEDIUM);
    nexthop_add_router(ndisc, "fe80::2", NM_ICMPV6_ROUTER_PREF_MEDIUM);
    nexthop_add_router(ndisc, "fe80::3", NM_ICMPV6_ROUTER_PREF_MEDIUM);

    nexthop_receive_ras(ndisc, &data);
    g_assert_cmpuint(data.rdata->routes_n, ==, 0);
    assert_nexthop_config(NM_NDISC(ndisc), &data, 3);
    match_gateway(data.rdata, 0, "fe80::1", NM_NDISC_EXPIRY_INFINITY, NM_ICMPV6_ROUTER_PREF_MEDIUM);
    match_gateway(data.rdata, 1, "fe80::2", NM_NDISC_EXPIRY_INFINITY, NM_ICMPV6_ROUTER_PREF_MEDIUM);
    match_gateway(data.rdata, 2, "fe80::3", NM_NDISC_EXPIRY_INFINITY, NM_ICMPV6_ROUTER_PREF_MEDIUM);
}

static void
test_nexthop_different_preference(void)
{
    gs_unref_object NMFakeNDisc *ndisc = ndisc_new();
    NexthopTestData              data  = {};

    /* Advertise out of preference order. Sorting the gateways must preserve
     * each router's association with its nexthop and default-route preference. */
    nexthop_add_router(ndisc, "fe80::1", NM_ICMPV6_ROUTER_PREF_LOW);
    nexthop_add_router(ndisc, "fe80::2", NM_ICMPV6_ROUTER_PREF_HIGH);
    nexthop_add_router(ndisc, "fe80::3", NM_ICMPV6_ROUTER_PREF_MEDIUM);

    nexthop_receive_ras(ndisc, &data);
    g_assert_cmpuint(data.rdata->routes_n, ==, 0);
    assert_nexthop_config(NM_NDISC(ndisc), &data, 3);
    match_gateway(data.rdata, 0, "fe80::2", NM_NDISC_EXPIRY_INFINITY, NM_ICMPV6_ROUTER_PREF_HIGH);
    match_gateway(data.rdata, 1, "fe80::3", NM_NDISC_EXPIRY_INFINITY, NM_ICMPV6_ROUTER_PREF_MEDIUM);
    match_gateway(data.rdata, 2, "fe80::1", NM_NDISC_EXPIRY_INFINITY, NM_ICMPV6_ROUTER_PREF_LOW);
}

static guint32
nexthop_id_probe(void)
{
    gs_unref_object NMFakeNDisc *ndisc = ndisc_new();
    NexthopTestData              data  = {};
    guint32                      nexthop_id;

    /* Learn the stable initial candidate without copying NDisc's hash function.
     * Destroying this instance releases the id for the tests below. */
    nexthop_add_router(ndisc, "fe80::1", NM_ICMPV6_ROUTER_PREF_MEDIUM);
    nexthop_receive_ras(ndisc, &data);
    assert_nexthop_config(NM_NDISC(ndisc), &data, 1);
    nexthop_id = data.rdata->gateways[0].nexthop_id;

    g_clear_object(&ndisc);
    g_assert(!nm_netns_nexthop_id_is_reserved(NM_NETNS_GET, nexthop_id));
    g_assert_cmpint(nm_platform_ip_nexthop_get(NM_PLATFORM_GET, nexthop_id, NULL),
                    ==,
                    -NME_PL_NOT_FOUND);
    return nexthop_id;
}

static void
test_nexthop_reuse(void)
{
    const guint32                nexthop_id = nexthop_id_probe();
    gs_unref_object NMFakeNDisc *ndisc      = ndisc_new();
    nm_auto_nmpobj NMPObject    *existing   = NULL;
    nm_auto_nmpobj NMPObject    *obj_get    = NULL;
    NexthopTestData              data       = {};
    NMPObject                    obj;

    /* Simulate a nexthop left behind after NM restarts. Unlike a user nexthop,
     * an RA nexthop with the same interface and gateway should be reused. */
    nmp_object_stackinit(&obj, NMP_OBJECT_TYPE_IP6_NEXTHOP, NULL);
    obj.ip6_nexthop = (NMPlatformIP6NextHop) {
        .id        = nexthop_id,
        .ifindex   = nm_ndisc_get_ifindex(NM_NDISC(ndisc)),
        .nh_source = NM_IP_CONFIG_SOURCE_NDISC,
        .gateway   = nmtst_inet6_from_string("fe80::1"),
    };
    g_assert_cmpint(nm_platform_ip_nexthop_add(NM_PLATFORM_GET, NMP_NLM_FLAG_ADD, &obj, NULL),
                    ==,
                    0);
    g_assert_cmpint(nm_platform_ip_nexthop_get(NM_PLATFORM_GET, nexthop_id, &existing), ==, 0);
    g_assert_cmpint(existing->ip6_nexthop.nh_source, ==, NM_IP_CONFIG_SOURCE_RTPROT_RA);
    g_assert(!nm_netns_nexthop_id_is_reserved(NM_NETNS_GET, nexthop_id));

    nexthop_add_router(ndisc, "fe80::1", NM_ICMPV6_ROUTER_PREF_MEDIUM);
    nexthop_receive_ras(ndisc, &data);
    g_assert_cmpuint(data.rdata->routes_n, ==, 0);
    assert_nexthop_config(NM_NDISC(ndisc), &data, 1);
    match_gateway(data.rdata, 0, "fe80::1", NM_NDISC_EXPIRY_INFINITY, NM_ICMPV6_ROUTER_PREF_MEDIUM);
    g_assert_cmpuint(data.rdata->gateways[0].nexthop_id, ==, nexthop_id);

    /* Releasing the reservation must leave the existing platform object intact. */
    g_clear_object(&ndisc);
    g_assert(!nm_netns_nexthop_id_is_reserved(NM_NETNS_GET, nexthop_id));
    g_assert_cmpint(nm_platform_ip_nexthop_get(NM_PLATFORM_GET, nexthop_id, &obj_get), ==, 0);
    g_assert(nmp_object_equal(existing, obj_get));
    g_assert(nm_platform_object_delete(NM_PLATFORM_GET, existing));
}

static void
test_nexthop_collision(void)
{
    const guint32                blocked_id = nexthop_id_probe();
    gs_unref_object NMFakeNDisc *ndisc      = ndisc_new();
    nm_auto_nmpobj NMPObject    *existing   = NULL;
    nm_auto_nmpobj NMPObject    *obj_get    = NULL;
    NexthopTestData              data       = {};
    NMPObject                    obj;
    guint32                      nexthop_id;

    /* Test a id collision by adding a nexthop manually that matches the
     * id generated by the NDisc. */
    nmp_object_stackinit(&obj, NMP_OBJECT_TYPE_IP6_NEXTHOP, NULL);
    obj.ip6_nexthop = (NMPlatformIP6NextHop) {
        .id        = blocked_id,
        .ifindex   = nm_ndisc_get_ifindex(NM_NDISC(ndisc)),
        .nh_source = NM_IP_CONFIG_SOURCE_USER,
        .gateway   = nmtst_inet6_from_string("fe80::1234"),
    };
    g_assert_cmpint(nm_platform_ip_nexthop_add(NM_PLATFORM_GET, NMP_NLM_FLAG_ADD, &obj, NULL),
                    ==,
                    0);
    g_assert_cmpint(nm_platform_ip_nexthop_get(NM_PLATFORM_GET, blocked_id, &existing), ==, 0);

    nexthop_add_router(ndisc, "fe80::1", NM_ICMPV6_ROUTER_PREF_MEDIUM);
    nexthop_receive_ras(ndisc, &data);
    g_assert_cmpuint(data.rdata->routes_n, ==, 0);
    assert_nexthop_config(NM_NDISC(ndisc), &data, 1);
    match_gateway(data.rdata, 0, "fe80::1", NM_NDISC_EXPIRY_INFINITY, NM_ICMPV6_ROUTER_PREF_MEDIUM);
    nexthop_id = data.rdata->gateways[0].nexthop_id;
    g_assert_cmpuint(nexthop_id, !=, blocked_id);
    g_assert(!nm_netns_nexthop_id_is_reserved(NM_NETNS_GET, blocked_id));
    g_assert_cmpint(nm_platform_ip_nexthop_get(NM_PLATFORM_GET, blocked_id, &obj_get), ==, 0);
    g_assert(nmp_object_equal(existing, obj_get));

    /* NDisc releases its reservation without changing or deleting the manual nexthop. */
    g_clear_object(&ndisc);
    g_assert(!nm_netns_nexthop_id_is_reserved(NM_NETNS_GET, nexthop_id));
    nm_clear_nmp_object(&obj_get);
    g_assert_cmpint(nm_platform_ip_nexthop_get(NM_PLATFORM_GET, blocked_id, &obj_get), ==, 0);
    g_assert(nmp_object_equal(existing, obj_get));
    g_assert(nm_platform_object_delete(NM_PLATFORM_GET, existing));
}

/*****************************************************************************/

NMTST_DEFINE();

int
main(int argc, char **argv)
{
    nmtst_init_with_logging(&argc, &argv, NULL, "DEFAULT");

    nm_fake_platform_setup();

    g_test_add_func("/ndisc/nexthop/routes/single", test_nexthop_single_router);
    g_test_add_func("/ndisc/nexthop/routes/equal-preference", test_nexthop_equal_preference);
    g_test_add_func("/ndisc/nexthop/routes/different-preference",
                    test_nexthop_different_preference);
    g_test_add_func("/ndisc/nexthop/reuse", test_nexthop_reuse);
    g_test_add_func("/ndisc/nexthop/collision", test_nexthop_collision);

    if (nmtst_test_quick()) {
        g_print("Skipping long-running tests in %s (NMTST_DEBUG=slow)\n",
                g_get_prgname() ?: "test-ndisc-fake");
        return g_test_run();
    }

    g_test_add_func("/ndisc/simple", test_simple);
    g_test_add_func("/ndisc/everything-changed", test_everything);
    g_test_add_func("/ndisc/preference-order", test_preference_order);
    g_test_add_func("/ndisc/preference-changed", test_preference_changed);
    g_test_add_func("/ndisc/dns-solicit-loop", test_dns_solicit_loop);

    return g_test_run();
}
