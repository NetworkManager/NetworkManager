/* ndisc.c - test program
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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
 * Copyright (C) 2015 Red Hat, Inc.
 */

#include "nm-default.h"

#include <syslog.h>

#include "ndisc/nm-ndisc.h"
#include "ndisc/nm-fake-ndisc.h"

#include "platform/nm-fake-platform.h"

#include "nm-test-utils-core.h"

static NMFakeNDisc *
ndisc_new (void)
{
	NMNDisc *ndisc;
	const int ifindex = 1;
	const char *ifname = nm_platform_link_get_name (NM_PLATFORM_GET, ifindex);
	NMUtilsIPv6IfaceId iid = { };

	ndisc = nm_fake_ndisc_new (ifindex, ifname);
	iid.id_u8[7] = 1;
	nm_ndisc_set_iid (ndisc, iid);
	g_assert (ndisc);
	return NM_FAKE_NDISC (ndisc);
}

static void
match_gateway (const NMNDiscData *rdata, guint idx, const char *addr, guint32 ts, guint32 lt, NMIcmpv6RouterPref pref)
{
	const NMNDiscGateway *gw;
	char buf[INET6_ADDRSTRLEN];

	g_assert (rdata);
	g_assert_cmpint (idx, <, rdata->gateways_n);
	g_assert (rdata->gateways);

	gw = &rdata->gateways[idx];

	g_assert_cmpstr (inet_ntop (AF_INET6, &gw->address, buf, sizeof (buf)), ==, addr);
	g_assert_cmpint (gw->timestamp, ==, ts);
	g_assert_cmpint (gw->lifetime, ==, lt);
	g_assert_cmpint (gw->preference, ==, pref);
}

static void
match_address (const NMNDiscData *rdata, guint idx, const char *addr, guint32 ts, guint32 lt, guint32 preferred)
{
	const NMNDiscAddress *a;
	char buf[INET6_ADDRSTRLEN];

	g_assert (rdata);
	g_assert_cmpint (idx, <, rdata->addresses_n);
	g_assert (rdata->addresses);

	a = &rdata->addresses[idx];

	g_assert_cmpstr (inet_ntop (AF_INET6, &a->address, buf, sizeof (buf)), ==, addr);
	g_assert_cmpint (a->timestamp, ==, ts);
	g_assert_cmpint (a->lifetime, ==, lt);
	g_assert_cmpint (a->preferred, ==, preferred);
}

static void
match_route (const NMNDiscData *rdata, guint idx, const char *nw, int plen, const char *gw, guint32 ts, guint32 lt, NMIcmpv6RouterPref pref)
{
	const NMNDiscRoute *route;
	char buf[INET6_ADDRSTRLEN];

	g_assert (rdata);
	g_assert_cmpint (idx, <, rdata->routes_n);
	g_assert (rdata->routes);
	g_assert (plen > 0 && plen <= 128);

	route = &rdata->routes[idx];

	g_assert_cmpstr (inet_ntop (AF_INET6, &route->network, buf, sizeof (buf)), ==, nw);
	g_assert_cmpint ((int) route->plen, ==, plen);
	g_assert_cmpstr (inet_ntop (AF_INET6, &route->gateway, buf, sizeof (buf)), ==, gw);
	g_assert_cmpint (route->timestamp, ==, ts);
	g_assert_cmpint (route->lifetime, ==, lt);
	g_assert_cmpint (route->preference, ==, pref);
}

static void
match_dns_server (const NMNDiscData *rdata, guint idx, const char *addr, guint32 ts, guint32 lt)
{
	const NMNDiscDNSServer *dns;
	char buf[INET6_ADDRSTRLEN];

	g_assert (rdata);
	g_assert_cmpint (idx, <, rdata->dns_servers_n);
	g_assert (rdata->dns_servers);

	dns = &rdata->dns_servers[idx];

	g_assert_cmpstr (inet_ntop (AF_INET6, &dns->address, buf, sizeof (buf)), ==, addr);
	g_assert_cmpint (dns->timestamp, ==, ts);
	g_assert_cmpint (dns->lifetime, ==, lt);
}

static void
match_dns_domain (const NMNDiscData *rdata, guint idx, const char *domain, guint32 ts, guint32 lt)
{
	const NMNDiscDNSDomain *dns;

	g_assert (rdata);
	g_assert_cmpint (idx, <, rdata->dns_domains_n);
	g_assert (rdata->dns_domains);

	dns = &rdata->dns_domains[idx];

	g_assert_cmpstr (dns->domain, ==, domain);
	g_assert_cmpint (dns->timestamp, ==, ts);
	g_assert_cmpint (dns->lifetime, ==, lt);
}

typedef struct {
	GMainLoop *loop;
	guint counter;
	guint rs_counter;
	guint32 timestamp1;
	guint32 first_solicit;
	guint32 timeout_id;
} TestData;

static void
test_simple_changed (NMNDisc *ndisc, const NMNDiscData *rdata, guint changed_int, TestData *data)
{
	NMNDiscConfigMap changed = changed_int;

	g_assert_cmpint (changed, ==, NM_NDISC_CONFIG_DHCP_LEVEL |
	                              NM_NDISC_CONFIG_GATEWAYS |
	                              NM_NDISC_CONFIG_ADDRESSES |
	                              NM_NDISC_CONFIG_ROUTES |
	                              NM_NDISC_CONFIG_DNS_SERVERS |
	                              NM_NDISC_CONFIG_DNS_DOMAINS |
	                              NM_NDISC_CONFIG_HOP_LIMIT |
	                              NM_NDISC_CONFIG_MTU);
	g_assert_cmpint (rdata->dhcp_level, ==, NM_NDISC_DHCP_LEVEL_OTHERCONF);
	match_gateway (rdata, 0, "fe80::1", data->timestamp1, 10, NM_ICMPV6_ROUTER_PREF_MEDIUM);
	match_address (rdata, 0, "2001:db8:a:a::1", data->timestamp1, 10, 10);
	match_route (rdata, 0, "2001:db8:a:a::", 64, "fe80::1", data->timestamp1, 10, 10);
	match_dns_server (rdata, 0, "2001:db8:c:c::1", data->timestamp1, 10);
	match_dns_domain (rdata, 0, "foobar.com", data->timestamp1, 10);

	g_assert (nm_fake_ndisc_done (NM_FAKE_NDISC (ndisc)));
	data->counter++;
	g_main_loop_quit (data->loop);
}

static void
test_simple (void)
{
	NMFakeNDisc *ndisc = ndisc_new ();
	guint32 now = nm_utils_get_monotonic_timestamp_s ();
	TestData data = { g_main_loop_new (NULL, FALSE), 0, 0, now };
	guint id;

	id = nm_fake_ndisc_add_ra (ndisc, 1, NM_NDISC_DHCP_LEVEL_OTHERCONF, 4, 1500);
	g_assert (id);
	nm_fake_ndisc_add_gateway (ndisc, id, "fe80::1", now, 10, NM_ICMPV6_ROUTER_PREF_MEDIUM);
	nm_fake_ndisc_add_prefix (ndisc, id, "2001:db8:a:a::", 64, "fe80::1", now, 10, 10, 10);
	nm_fake_ndisc_add_dns_server (ndisc, id, "2001:db8:c:c::1", now, 10);
	nm_fake_ndisc_add_dns_domain (ndisc, id, "foobar.com", now, 10);

	g_signal_connect (ndisc,
	                  NM_NDISC_CONFIG_RECEIVED,
	                  G_CALLBACK (test_simple_changed),
	                  &data);

	nm_ndisc_start (NM_NDISC (ndisc));
	g_main_loop_run (data.loop);
	g_assert_cmpint (data.counter, ==, 1);

	g_object_unref (ndisc);
	g_main_loop_unref (data.loop);
}

static void
test_everything_rs_sent (NMNDisc *ndisc, TestData *data)
{
	g_assert_cmpint (data->rs_counter, ==, 0);
	data->rs_counter++;
}

static void
test_everything_changed (NMNDisc *ndisc, const NMNDiscData *rdata, guint changed_int, TestData *data)
{
	NMNDiscConfigMap changed = changed_int;

	if (data->counter == 0) {
		g_assert_cmpint (data->rs_counter, ==, 1);
		g_assert_cmpint (changed, ==, NM_NDISC_CONFIG_DHCP_LEVEL |
		                              NM_NDISC_CONFIG_GATEWAYS |
		                              NM_NDISC_CONFIG_ADDRESSES |
		                              NM_NDISC_CONFIG_ROUTES |
		                              NM_NDISC_CONFIG_DNS_SERVERS |
		                              NM_NDISC_CONFIG_DNS_DOMAINS |
		                              NM_NDISC_CONFIG_HOP_LIMIT |
		                              NM_NDISC_CONFIG_MTU);
		match_gateway (rdata, 0, "fe80::1", data->timestamp1, 10, NM_ICMPV6_ROUTER_PREF_MEDIUM);
		match_address (rdata, 0, "2001:db8:a:a::1", data->timestamp1, 10, 10);
		match_route (rdata, 0, "2001:db8:a:a::", 64, "fe80::1", data->timestamp1, 10, 10);
		match_dns_server (rdata, 0, "2001:db8:c:c::1", data->timestamp1, 10);
		match_dns_domain (rdata, 0, "foobar.com", data->timestamp1, 10);
	} else if (data->counter == 1) {
		g_assert_cmpint (changed, ==, NM_NDISC_CONFIG_GATEWAYS |
		                              NM_NDISC_CONFIG_ADDRESSES |
		                              NM_NDISC_CONFIG_ROUTES |
		                              NM_NDISC_CONFIG_DNS_SERVERS |
		                              NM_NDISC_CONFIG_DNS_DOMAINS);

		g_assert_cmpint (rdata->gateways_n, ==, 1);
		match_gateway (rdata, 0, "fe80::2", data->timestamp1, 10, NM_ICMPV6_ROUTER_PREF_MEDIUM);
		g_assert_cmpint (rdata->addresses_n, ==, 2);
		match_address (rdata, 0, "2001:db8:a:a::1", data->timestamp1, 10, 0);
		match_address (rdata, 1, "2001:db8:a:b::1", data->timestamp1, 10, 10);
		g_assert_cmpint (rdata->routes_n, ==, 1);
		match_route (rdata, 0, "2001:db8:a:b::", 64, "fe80::2", data->timestamp1, 10, 10);
		g_assert_cmpint (rdata->dns_servers_n, ==, 1);
		match_dns_server (rdata, 0, "2001:db8:c:c::2", data->timestamp1, 10);
		g_assert_cmpint (rdata->dns_domains_n, ==, 1);
		match_dns_domain (rdata, 0, "foobar2.com", data->timestamp1, 10);

		g_assert (nm_fake_ndisc_done (NM_FAKE_NDISC (ndisc)));
		g_main_loop_quit (data->loop);
	} else
		g_assert_not_reached ();

	data->counter++;
}

static void
test_everything (void)
{
	NMFakeNDisc *ndisc = ndisc_new ();
	guint32 now = nm_utils_get_monotonic_timestamp_s ();
	TestData data = { g_main_loop_new (NULL, FALSE), 0, 0, now };
	guint id;

	id = nm_fake_ndisc_add_ra (ndisc, 1, NM_NDISC_DHCP_LEVEL_NONE, 4, 1500);
	g_assert (id);
	nm_fake_ndisc_add_gateway (ndisc, id, "fe80::1", now, 10, NM_ICMPV6_ROUTER_PREF_MEDIUM);
	nm_fake_ndisc_add_prefix (ndisc, id, "2001:db8:a:a::", 64, "fe80::1", now, 10, 10, 10);
	nm_fake_ndisc_add_dns_server (ndisc, id, "2001:db8:c:c::1", now, 10);
	nm_fake_ndisc_add_dns_domain (ndisc, id, "foobar.com", now, 10);

	/* expire everything from the first RA in the second */
	id = nm_fake_ndisc_add_ra (ndisc, 1, NM_NDISC_DHCP_LEVEL_NONE, 4, 1500);
	g_assert (id);
	nm_fake_ndisc_add_gateway (ndisc, id, "fe80::1", now, 0, NM_ICMPV6_ROUTER_PREF_MEDIUM);
	nm_fake_ndisc_add_prefix (ndisc, id, "2001:db8:a:a::", 64, "fe80::1", now, 0, 0, 0);
	nm_fake_ndisc_add_dns_server (ndisc, id, "2001:db8:c:c::1", now, 0);
	nm_fake_ndisc_add_dns_domain (ndisc, id, "foobar.com", now, 0);

	/* and add some new stuff */
	nm_fake_ndisc_add_gateway (ndisc, id, "fe80::2", now, 10, NM_ICMPV6_ROUTER_PREF_MEDIUM);
	nm_fake_ndisc_add_prefix (ndisc, id, "2001:db8:a:b::", 64, "fe80::2", now, 10, 10, 10);
	nm_fake_ndisc_add_dns_server (ndisc, id, "2001:db8:c:c::2", now, 10);
	nm_fake_ndisc_add_dns_domain (ndisc, id, "foobar2.com", now, 10);

	g_signal_connect (ndisc,
	                  NM_NDISC_CONFIG_RECEIVED,
	                  G_CALLBACK (test_everything_changed),
	                  &data);
	g_signal_connect (ndisc,
	                  NM_FAKE_NDISC_RS_SENT,
	                  G_CALLBACK (test_everything_rs_sent),
	                  &data);

	nm_ndisc_start (NM_NDISC (ndisc));
	g_main_loop_run (data.loop);
	g_assert_cmpint (data.counter, ==, 2);
	g_assert_cmpint (data.rs_counter, ==, 1);

	g_object_unref (ndisc);
	g_main_loop_unref (data.loop);
}

static void
test_preference_order_cb (NMNDisc *ndisc, const NMNDiscData *rdata, guint changed_int, TestData *data)
{
	NMNDiscConfigMap changed = changed_int;

	if (data->counter == 1) {
		g_assert_cmpint (changed, ==, NM_NDISC_CONFIG_GATEWAYS |
		                              NM_NDISC_CONFIG_ADDRESSES |
		                              NM_NDISC_CONFIG_ROUTES);

		g_assert_cmpint (rdata->gateways_n, ==, 2);
		match_gateway (rdata, 0, "fe80::1", data->timestamp1, 10, NM_ICMPV6_ROUTER_PREF_HIGH);
		match_gateway (rdata, 1, "fe80::2", data->timestamp1 + 1, 10, NM_ICMPV6_ROUTER_PREF_LOW);
		g_assert_cmpint (rdata->addresses_n, ==, 2);
		match_address (rdata, 0, "2001:db8:a:a::1", data->timestamp1, 10, 10);
		match_address (rdata, 1, "2001:db8:a:b::1", data->timestamp1 + 1, 10, 10);
		g_assert_cmpint (rdata->routes_n, ==, 2);
		match_route (rdata, 0, "2001:db8:a:b::", 64, "fe80::2", data->timestamp1 + 1, 10, 10);
		match_route (rdata, 1, "2001:db8:a:a::", 64, "fe80::1", data->timestamp1, 10, 5);

		g_assert (nm_fake_ndisc_done (NM_FAKE_NDISC (ndisc)));
		g_main_loop_quit (data->loop);
	}

	data->counter++;
}

static void
test_preference_order (void)
{
	NMFakeNDisc *ndisc = ndisc_new ();
	guint32 now = nm_utils_get_monotonic_timestamp_s ();
	TestData data = { g_main_loop_new (NULL, FALSE), 0, 0, now };
	guint id;

	/* Test insertion order of gateways */

	id = nm_fake_ndisc_add_ra (ndisc, 1, NM_NDISC_DHCP_LEVEL_NONE, 4, 1500);
	g_assert (id);
	nm_fake_ndisc_add_gateway (ndisc, id, "fe80::1", now, 10, NM_ICMPV6_ROUTER_PREF_HIGH);
	nm_fake_ndisc_add_prefix (ndisc, id, "2001:db8:a:a::", 64, "fe80::1", now, 10, 10, 5);

	id = nm_fake_ndisc_add_ra (ndisc, 1, NM_NDISC_DHCP_LEVEL_NONE, 4, 1500);
	g_assert (id);
	nm_fake_ndisc_add_gateway (ndisc, id, "fe80::2", ++now, 10, NM_ICMPV6_ROUTER_PREF_LOW);
	nm_fake_ndisc_add_prefix (ndisc, id, "2001:db8:a:b::", 64, "fe80::2", now, 10, 10, 10);

	g_signal_connect (ndisc,
	                  NM_NDISC_CONFIG_RECEIVED,
	                  G_CALLBACK (test_preference_order_cb),
	                  &data);

	nm_ndisc_start (NM_NDISC (ndisc));
	g_main_loop_run (data.loop);
	g_assert_cmpint (data.counter, ==, 2);

	g_object_unref (ndisc);
	g_main_loop_unref (data.loop);
}

static void
test_preference_changed_cb (NMNDisc *ndisc, const NMNDiscData *rdata, guint changed_int, TestData *data)
{
	NMNDiscConfigMap changed = changed_int;

	if (data->counter == 1) {
		g_assert_cmpint (changed, ==, NM_NDISC_CONFIG_GATEWAYS |
		                              NM_NDISC_CONFIG_ADDRESSES |
		                              NM_NDISC_CONFIG_ROUTES);
		g_assert_cmpint (rdata->gateways_n, ==, 2);
		match_gateway (rdata, 0, "fe80::2", data->timestamp1 + 1, 10, NM_ICMPV6_ROUTER_PREF_MEDIUM);
		match_gateway (rdata, 1, "fe80::1", data->timestamp1, 10, NM_ICMPV6_ROUTER_PREF_LOW);
		g_assert_cmpint (rdata->addresses_n, ==, 2);
		match_address (rdata, 0, "2001:db8:a:a::1", data->timestamp1, 10, 10);
		match_address (rdata, 1, "2001:db8:a:b::1", data->timestamp1 + 1, 10, 10);
		g_assert_cmpint (rdata->routes_n, ==, 2);
		match_route (rdata, 0, "2001:db8:a:b::", 64, "fe80::2", data->timestamp1 + 1, 10, 10);
		match_route (rdata, 1, "2001:db8:a:a::", 64, "fe80::1", data->timestamp1, 10, 5);
	} else if (data->counter == 2) {
		g_assert_cmpint (changed, ==, NM_NDISC_CONFIG_GATEWAYS |
		                              NM_NDISC_CONFIG_ADDRESSES |
		                              NM_NDISC_CONFIG_ROUTES);

		g_assert_cmpint (rdata->gateways_n, ==, 2);
		match_gateway (rdata, 0, "fe80::1", data->timestamp1 + 2, 10, NM_ICMPV6_ROUTER_PREF_HIGH);
		match_gateway (rdata, 1, "fe80::2", data->timestamp1 + 1, 10, NM_ICMPV6_ROUTER_PREF_MEDIUM);
		g_assert_cmpint (rdata->addresses_n, ==, 2);
		match_address (rdata, 0, "2001:db8:a:a::1", data->timestamp1 + 3, 9, 9);
		match_address (rdata, 1, "2001:db8:a:b::1", data->timestamp1 + 1, 10, 10);
		g_assert_cmpint (rdata->routes_n, ==, 2);
		match_route (rdata, 0, "2001:db8:a:a::", 64, "fe80::1", data->timestamp1 + 2, 10, 15);
		match_route (rdata, 1, "2001:db8:a:b::", 64, "fe80::2", data->timestamp1 + 1, 10, 10);

		g_assert (nm_fake_ndisc_done (NM_FAKE_NDISC (ndisc)));
		g_main_loop_quit (data->loop);
	}

	data->counter++;
}

static void
test_preference_changed (void)
{
	NMFakeNDisc *ndisc = ndisc_new ();
	guint32 now = nm_utils_get_monotonic_timestamp_s ();
	TestData data = { g_main_loop_new (NULL, FALSE), 0, 0, now };
	guint id;

	/* Test that when a low-preference and medium gateway send advertisements,
	 * that if the low-preference gateway switches to high-preference, we do
	 * not get duplicates in the gateway list.
	 */

	id = nm_fake_ndisc_add_ra (ndisc, 1, NM_NDISC_DHCP_LEVEL_NONE, 4, 1500);
	g_assert (id);
	nm_fake_ndisc_add_gateway (ndisc, id, "fe80::1", now, 10, NM_ICMPV6_ROUTER_PREF_LOW);
	nm_fake_ndisc_add_prefix (ndisc, id, "2001:db8:a:a::", 64, "fe80::1", now, 10, 10, 5);

	id = nm_fake_ndisc_add_ra (ndisc, 1, NM_NDISC_DHCP_LEVEL_NONE, 4, 1500);
	g_assert (id);
	nm_fake_ndisc_add_gateway (ndisc, id, "fe80::2", ++now, 10, NM_ICMPV6_ROUTER_PREF_MEDIUM);
	nm_fake_ndisc_add_prefix (ndisc, id, "2001:db8:a:b::", 64, "fe80::2", now, 10, 10, 10);

	id = nm_fake_ndisc_add_ra (ndisc, 1, NM_NDISC_DHCP_LEVEL_NONE, 4, 1500);
	g_assert (id);
	nm_fake_ndisc_add_gateway (ndisc, id, "fe80::1", ++now, 10, NM_ICMPV6_ROUTER_PREF_HIGH);
	nm_fake_ndisc_add_prefix (ndisc, id, "2001:db8:a:a::", 64, "fe80::1", now, 10, 10, 15);

	g_signal_connect (ndisc,
	                  NM_NDISC_CONFIG_RECEIVED,
	                  G_CALLBACK (test_preference_changed_cb),
	                  &data);

	nm_ndisc_start (NM_NDISC (ndisc));
	g_main_loop_run (data.loop);
	g_assert_cmpint (data.counter, ==, 3);

	g_object_unref (ndisc);
	g_main_loop_unref (data.loop);
}

static void
test_dns_solicit_loop_changed (NMNDisc *ndisc, const NMNDiscData *rdata, guint changed_int, TestData *data)
{
	data->counter++;
}

static gboolean
success_timeout (TestData *data)
{
	data->timeout_id = 0;
	g_main_loop_quit (data->loop);
	return G_SOURCE_REMOVE;
}

static void
test_dns_solicit_loop_rs_sent (NMFakeNDisc *ndisc, TestData *data)
{
	guint32 now = nm_utils_get_monotonic_timestamp_s ();
	guint id;

	if (data->rs_counter > 0 && data->rs_counter < 6) {
		if (data->rs_counter == 1) {
			data->first_solicit = now;
			/* Kill the test after 10 seconds if it hasn't failed yet */
			data->timeout_id = g_timeout_add_seconds (10, (GSourceFunc) success_timeout, data);
		}

		/* On all but the first solicitation, which should be triggered by the
		 * DNS servers reaching 1/2 lifetime, emit a new RA without the DNS
		 * servers again.
		 */
		id = nm_fake_ndisc_add_ra (ndisc, 0, NM_NDISC_DHCP_LEVEL_NONE, 4, 1500);
		g_assert (id);
		nm_fake_ndisc_add_gateway (ndisc, id, "fe80::1", now, 10, NM_ICMPV6_ROUTER_PREF_MEDIUM);

		nm_fake_ndisc_emit_new_ras (ndisc);
	} else if (data->rs_counter >= 6) {
		/* Fail if we've sent too many solicitations in the past 4 seconds */
		g_assert_cmpint (now - data->first_solicit, >, 4);
		g_source_remove (data->timeout_id);
		g_main_loop_quit (data->loop);
	}
	data->rs_counter++;
}

static void
test_dns_solicit_loop (void)
{
	NMFakeNDisc *ndisc = ndisc_new ();
	guint32 now = nm_utils_get_monotonic_timestamp_s ();
	TestData data = { g_main_loop_new (NULL, FALSE), 0, 0, now, 0 };
	guint id;

	/* Ensure that no solicitation loop happens when DNS servers or domains
	 * stop being sent in advertisements.  This can happen if two routers
	 * send RAs, but the one sending DNS info stops responding, or if one
	 * router removes the DNS info from the RA without zero-lifetiming them
	 * first.
	 */

	id = nm_fake_ndisc_add_ra (ndisc, 1, NM_NDISC_DHCP_LEVEL_NONE, 4, 1500);
	g_assert (id);
	nm_fake_ndisc_add_gateway (ndisc, id, "fe80::1", now, 10, NM_ICMPV6_ROUTER_PREF_LOW);
	nm_fake_ndisc_add_dns_server (ndisc, id, "2001:db8:c:c::1", now, 6);

	g_signal_connect (ndisc,
	                  NM_NDISC_CONFIG_RECEIVED,
	                  G_CALLBACK (test_dns_solicit_loop_changed),
	                  &data);
	g_signal_connect (ndisc,
	                  NM_FAKE_NDISC_RS_SENT,
	                  G_CALLBACK (test_dns_solicit_loop_rs_sent),
	                  &data);

	nm_ndisc_start (NM_NDISC (ndisc));
	g_main_loop_run (data.loop);
	g_assert_cmpint (data.counter, ==, 3);

	g_object_unref (ndisc);
	g_main_loop_unref (data.loop);
}

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	nmtst_init_with_logging (&argc, &argv, NULL, "DEFAULT");

	if (nmtst_test_quick ()) {
		g_print ("Skipping test: don't run long running test %s (NMTST_DEBUG=slow)\n", g_get_prgname () ?: "test-ndisc-fake");
		return g_test_run ();
	}

	nm_fake_platform_setup ();

	g_test_add_func ("/ndisc/simple", test_simple);
	g_test_add_func ("/ndisc/everything-changed", test_everything);
	g_test_add_func ("/ndisc/preference-order", test_preference_order);
	g_test_add_func ("/ndisc/preference-changed", test_preference_changed);
	g_test_add_func ("/ndisc/dns-solicit-loop", test_dns_solicit_loop);

	return g_test_run ();
}
