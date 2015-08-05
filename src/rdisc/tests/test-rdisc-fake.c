/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* rdisc.c - test program
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

#include "config.h"

#include <string.h>
#include <syslog.h>

#include "nm-rdisc.h"
#include "nm-fake-rdisc.h"
#include "nm-default.h"

#include "nm-fake-platform.h"

#include "nm-test-utils.h"

static NMFakeRDisc *
rdisc_new (void)
{
	NMRDisc *rdisc;
	const int ifindex = 1;
	const char *ifname = nm_platform_link_get_name (NM_PLATFORM_GET, ifindex);

	rdisc = nm_fake_rdisc_new (ifindex, ifname);
	g_assert (rdisc);
	return NM_FAKE_RDISC (rdisc);
}

static void
match_gateway (GArray *array, guint idx, const char *addr, guint32 ts, guint32 lt, NMRDiscPreference pref)
{
	NMRDiscGateway *gw = &g_array_index (array, NMRDiscGateway, idx);
	char buf[INET6_ADDRSTRLEN];

	g_assert_cmpstr (inet_ntop (AF_INET6, &gw->address, buf, sizeof (buf)), ==, addr);
	g_assert_cmpint (gw->timestamp, ==, ts);
	g_assert_cmpint (gw->lifetime, ==, lt);
	g_assert_cmpint (gw->preference, ==, pref);
}

static void
match_address (GArray *array, guint idx, const char *addr, guint32 ts, guint32 lt, guint32 preferred)
{
	NMRDiscAddress *a = &g_array_index (array, NMRDiscAddress, idx);
	char buf[INET6_ADDRSTRLEN];

	g_assert_cmpstr (inet_ntop (AF_INET6, &a->address, buf, sizeof (buf)), ==, addr);
	g_assert_cmpint (a->timestamp, ==, ts);
	g_assert_cmpint (a->lifetime, ==, lt);
	g_assert_cmpint (a->preferred, ==, preferred);
}

static void
match_route (GArray *array, guint idx, const char *nw, int plen, const char *gw, guint32 ts, guint32 lt, NMRDiscPreference pref)
{
	NMRDiscRoute *route = &g_array_index (array, NMRDiscRoute, idx);
	char buf[INET6_ADDRSTRLEN];

	g_assert_cmpstr (inet_ntop (AF_INET6, &route->network, buf, sizeof (buf)), ==, nw);
	g_assert_cmpint (route->plen, ==, plen);
	g_assert_cmpstr (inet_ntop (AF_INET6, &route->gateway, buf, sizeof (buf)), ==, gw);
	g_assert_cmpint (route->timestamp, ==, ts);
	g_assert_cmpint (route->lifetime, ==, lt);
	g_assert_cmpint (route->preference, ==, pref);
}

static void
match_dns_server (GArray *array, guint idx, const char *addr, guint32 ts, guint32 lt)
{
	NMRDiscDNSServer *dns = &g_array_index (array, NMRDiscDNSServer, idx);
	char buf[INET6_ADDRSTRLEN];

	g_assert_cmpstr (inet_ntop (AF_INET6, &dns->address, buf, sizeof (buf)), ==, addr);
	g_assert_cmpint (dns->timestamp, ==, ts);
	g_assert_cmpint (dns->lifetime, ==, lt);
}

static void
match_dns_domain (GArray *array, guint idx, const char *domain, guint32 ts, guint32 lt)
{
	NMRDiscDNSDomain *dns = &g_array_index (array, NMRDiscDNSDomain, idx);

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
test_simple_changed (NMRDisc *rdisc, NMRDiscConfigMap changed, TestData *data)
{
	g_assert_cmpint (changed, ==, NM_RDISC_CONFIG_DHCP_LEVEL |
	                              NM_RDISC_CONFIG_GATEWAYS |
	                              NM_RDISC_CONFIG_ADDRESSES |
	                              NM_RDISC_CONFIG_ROUTES |
	                              NM_RDISC_CONFIG_DNS_SERVERS |
	                              NM_RDISC_CONFIG_DNS_DOMAINS |
	                              NM_RDISC_CONFIG_HOP_LIMIT |
	                              NM_RDISC_CONFIG_MTU);
	g_assert_cmpint (rdisc->dhcp_level, ==, NM_RDISC_DHCP_LEVEL_OTHERCONF);
	match_gateway (rdisc->gateways, 0, "fe80::1", data->timestamp1, 10, NM_RDISC_PREFERENCE_MEDIUM);
	match_address (rdisc->addresses, 0, "2001:db8:a:a::1", data->timestamp1, 10, 10);
	match_route (rdisc->routes, 0, "2001:db8:a:a::", 64, "fe80::1", data->timestamp1, 10, 10);
	match_dns_server (rdisc->dns_servers, 0, "2001:db8:c:c::1", data->timestamp1, 10);
	match_dns_domain (rdisc->dns_domains, 0, "foobar.com", data->timestamp1, 10);

	g_assert (nm_fake_rdisc_done (NM_FAKE_RDISC (rdisc)));
	data->counter++;
	g_main_loop_quit (data->loop);
}

static void
test_simple (void)
{
	NMFakeRDisc *rdisc = rdisc_new ();
	guint32 now = nm_utils_get_monotonic_timestamp_s ();
	TestData data = { g_main_loop_new (NULL, FALSE), 0, 0, now };
	guint id;

	id = nm_fake_rdisc_add_ra (rdisc, 1, NM_RDISC_DHCP_LEVEL_OTHERCONF, 4, 1500);
	g_assert (id);
	nm_fake_rdisc_add_gateway (rdisc, id, "fe80::1", now, 10, NM_RDISC_PREFERENCE_MEDIUM);
	nm_fake_rdisc_add_address (rdisc, id, "2001:db8:a:a::1", now, 10, 10);
	nm_fake_rdisc_add_route (rdisc, id, "2001:db8:a:a::", 64, "fe80::1", now, 10, 10);
	nm_fake_rdisc_add_dns_server (rdisc, id, "2001:db8:c:c::1", now, 10);
	nm_fake_rdisc_add_dns_domain (rdisc, id, "foobar.com", now, 10);

	g_signal_connect (rdisc,
	                  NM_RDISC_CONFIG_CHANGED,
	                  G_CALLBACK (test_simple_changed),
	                  &data);

	nm_rdisc_start (NM_RDISC (rdisc));
	g_main_loop_run (data.loop);
	g_assert_cmpint (data.counter, ==, 1);

	g_object_unref (rdisc);
	g_main_loop_unref (data.loop);
}

static void
test_everything_rs_sent (NMRDisc *rdisc, TestData *data)
{
	g_assert_cmpint (data->rs_counter, ==, 0);
	data->rs_counter++;
}

static void
test_everything_changed (NMRDisc *rdisc, NMRDiscConfigMap changed, TestData *data)
{
	if (data->counter == 0) {
		g_assert_cmpint (data->rs_counter, ==, 1);
		g_assert_cmpint (changed, ==, NM_RDISC_CONFIG_DHCP_LEVEL |
			                          NM_RDISC_CONFIG_GATEWAYS |
			                          NM_RDISC_CONFIG_ADDRESSES |
			                          NM_RDISC_CONFIG_ROUTES |
			                          NM_RDISC_CONFIG_DNS_SERVERS |
			                          NM_RDISC_CONFIG_DNS_DOMAINS |
			                          NM_RDISC_CONFIG_HOP_LIMIT |
			                          NM_RDISC_CONFIG_MTU);
		match_gateway (rdisc->gateways, 0, "fe80::1", data->timestamp1, 10, NM_RDISC_PREFERENCE_MEDIUM);
		match_address (rdisc->addresses, 0, "2001:db8:a:a::1", data->timestamp1, 10, 10);
		match_route (rdisc->routes, 0, "2001:db8:a:a::", 64, "fe80::1", data->timestamp1, 10, 10);
		match_dns_server (rdisc->dns_servers, 0, "2001:db8:c:c::1", data->timestamp1, 10);
		match_dns_domain (rdisc->dns_domains, 0, "foobar.com", data->timestamp1, 10);
	} else if (data->counter == 1) {
		g_assert_cmpint (changed, ==, NM_RDISC_CONFIG_GATEWAYS |
			                          NM_RDISC_CONFIG_ADDRESSES |
			                          NM_RDISC_CONFIG_ROUTES |
			                          NM_RDISC_CONFIG_DNS_SERVERS |
			                          NM_RDISC_CONFIG_DNS_DOMAINS);

		g_assert_cmpint (rdisc->gateways->len, ==, 1);
		match_gateway (rdisc->gateways, 0, "fe80::2", data->timestamp1, 10, NM_RDISC_PREFERENCE_MEDIUM);
		g_assert_cmpint (rdisc->addresses->len, ==, 1);
		match_address (rdisc->addresses, 0, "2001:db8:a:a::2", data->timestamp1, 10, 10);
		g_assert_cmpint (rdisc->routes->len, ==, 1);
		match_route (rdisc->routes, 0, "2001:db8:a:b::", 64, "fe80::2", data->timestamp1, 10, 10);
		g_assert_cmpint (rdisc->dns_servers->len, ==, 1);
		match_dns_server (rdisc->dns_servers, 0, "2001:db8:c:c::2", data->timestamp1, 10);
		g_assert_cmpint (rdisc->dns_domains->len, ==, 1);
		match_dns_domain (rdisc->dns_domains, 0, "foobar2.com", data->timestamp1, 10);

		g_assert (nm_fake_rdisc_done (NM_FAKE_RDISC (rdisc)));
		g_main_loop_quit (data->loop);
	} else
		g_assert_not_reached ();

	data->counter++;
}

static void
test_everything (void)
{
	NMFakeRDisc *rdisc = rdisc_new ();
	guint32 now = nm_utils_get_monotonic_timestamp_s ();
	TestData data = { g_main_loop_new (NULL, FALSE), 0, 0, now };
	guint id;

	id = nm_fake_rdisc_add_ra (rdisc, 1, NM_RDISC_DHCP_LEVEL_NONE, 4, 1500);
	g_assert (id);
	nm_fake_rdisc_add_gateway (rdisc, id, "fe80::1", now, 10, NM_RDISC_PREFERENCE_MEDIUM);
	nm_fake_rdisc_add_address (rdisc, id, "2001:db8:a:a::1", now, 10, 10);
	nm_fake_rdisc_add_route (rdisc, id, "2001:db8:a:a::", 64, "fe80::1", now, 10, 10);
	nm_fake_rdisc_add_dns_server (rdisc, id, "2001:db8:c:c::1", now, 10);
	nm_fake_rdisc_add_dns_domain (rdisc, id, "foobar.com", now, 10);

	/* expire everything from the first RA in the second */
	id = nm_fake_rdisc_add_ra (rdisc, 1, NM_RDISC_DHCP_LEVEL_NONE, 4, 1500);
	g_assert (id);
	nm_fake_rdisc_add_gateway (rdisc, id, "fe80::1", now, 0, NM_RDISC_PREFERENCE_MEDIUM);
	nm_fake_rdisc_add_address (rdisc, id, "2001:db8:a:a::1", now, 0, 0);
	nm_fake_rdisc_add_route (rdisc, id, "2001:db8:a:a::", 64, "fe80::1", now, 0, 0);
	nm_fake_rdisc_add_dns_server (rdisc, id, "2001:db8:c:c::1", now, 0);
	nm_fake_rdisc_add_dns_domain (rdisc, id, "foobar.com", now, 0);

	/* and add some new stuff */
	nm_fake_rdisc_add_gateway (rdisc, id, "fe80::2", now, 10, NM_RDISC_PREFERENCE_MEDIUM);
	nm_fake_rdisc_add_address (rdisc, id, "2001:db8:a:a::2", now, 10, 10);
	nm_fake_rdisc_add_route (rdisc, id, "2001:db8:a:b::", 64, "fe80::2", now, 10, 10);
	nm_fake_rdisc_add_dns_server (rdisc, id, "2001:db8:c:c::2", now, 10);
	nm_fake_rdisc_add_dns_domain (rdisc, id, "foobar2.com", now, 10);

	g_signal_connect (rdisc,
	                  NM_RDISC_CONFIG_CHANGED,
	                  G_CALLBACK (test_everything_changed),
	                  &data);
	g_signal_connect (rdisc,
	                  NM_FAKE_RDISC_RS_SENT,
	                  G_CALLBACK (test_everything_rs_sent),
	                  &data);

	nm_rdisc_start (NM_RDISC (rdisc));
	g_main_loop_run (data.loop);
	g_assert_cmpint (data.counter, ==, 2);
	g_assert_cmpint (data.rs_counter, ==, 1);

	g_object_unref (rdisc);
	g_main_loop_unref (data.loop);
}

static void
test_preference_changed (NMRDisc *rdisc, NMRDiscConfigMap changed, TestData *data)
{
	if (data->counter == 1) {
		g_assert_cmpint (changed, ==, NM_RDISC_CONFIG_GATEWAYS |
			                          NM_RDISC_CONFIG_ADDRESSES |
			                          NM_RDISC_CONFIG_ROUTES);
		g_assert_cmpint (rdisc->gateways->len, ==, 2);
		match_gateway (rdisc->gateways, 0, "fe80::2", data->timestamp1 + 1, 10, NM_RDISC_PREFERENCE_MEDIUM);
		match_gateway (rdisc->gateways, 1, "fe80::1", data->timestamp1, 10, NM_RDISC_PREFERENCE_LOW);
		g_assert_cmpint (rdisc->addresses->len, ==, 2);
		match_address (rdisc->addresses, 0, "2001:db8:a:a::1", data->timestamp1, 10, 10);
		match_address (rdisc->addresses, 1, "2001:db8:a:a::2", data->timestamp1 + 1, 10, 10);
		g_assert_cmpint (rdisc->routes->len, ==, 2);
		match_route (rdisc->routes, 0, "2001:db8:a:b::", 64, "fe80::2", data->timestamp1 + 1, 10, 10);
		match_route (rdisc->routes, 1, "2001:db8:a:a::", 64, "fe80::1", data->timestamp1, 10, 5);
	} else if (data->counter == 2) {
		g_assert_cmpint (changed, ==, NM_RDISC_CONFIG_GATEWAYS |
			                          NM_RDISC_CONFIG_ADDRESSES |
			                          NM_RDISC_CONFIG_ROUTES);

		g_assert_cmpint (rdisc->gateways->len, ==, 2);
		match_gateway (rdisc->gateways, 0, "fe80::1", data->timestamp1 + 2, 10, NM_RDISC_PREFERENCE_HIGH);
		match_gateway (rdisc->gateways, 1, "fe80::2", data->timestamp1 + 1, 10, NM_RDISC_PREFERENCE_MEDIUM);
		g_assert_cmpint (rdisc->addresses->len, ==, 2);
		match_address (rdisc->addresses, 0, "2001:db8:a:a::1", data->timestamp1 + 2, 10, 10);
		match_address (rdisc->addresses, 1, "2001:db8:a:a::2", data->timestamp1 + 1, 10, 10);
		g_assert_cmpint (rdisc->routes->len, ==, 2);
		match_route (rdisc->routes, 0, "2001:db8:a:a::", 64, "fe80::1", data->timestamp1 + 2, 10, 15);
		match_route (rdisc->routes, 1, "2001:db8:a:b::", 64, "fe80::2", data->timestamp1 + 1, 10, 10);

		g_assert (nm_fake_rdisc_done (NM_FAKE_RDISC (rdisc)));
		g_main_loop_quit (data->loop);
	}

	data->counter++;
}

static void
test_preference (void)
{
	NMFakeRDisc *rdisc = rdisc_new ();
	guint32 now = nm_utils_get_monotonic_timestamp_s ();
	TestData data = { g_main_loop_new (NULL, FALSE), 0, 0, now };
	guint id;

	/* Test that when a low-preference and medium gateway send advertisements,
	 * that if the low-preference gateway switches to high-preference, we do
	 * not get duplicates in the gateway list.
	 */

	id = nm_fake_rdisc_add_ra (rdisc, 1, NM_RDISC_DHCP_LEVEL_NONE, 4, 1500);
	g_assert (id);
	nm_fake_rdisc_add_gateway (rdisc, id, "fe80::1", now, 10, NM_RDISC_PREFERENCE_LOW);
	nm_fake_rdisc_add_address (rdisc, id, "2001:db8:a:a::1", now, 10, 10);
	nm_fake_rdisc_add_route (rdisc, id, "2001:db8:a:a::", 64, "fe80::1", now, 10, 5);

	id = nm_fake_rdisc_add_ra (rdisc, 1, NM_RDISC_DHCP_LEVEL_NONE, 4, 1500);
	g_assert (id);
	nm_fake_rdisc_add_gateway (rdisc, id, "fe80::2", ++now, 10, NM_RDISC_PREFERENCE_MEDIUM);
	nm_fake_rdisc_add_address (rdisc, id, "2001:db8:a:a::2", now, 10, 10);
	nm_fake_rdisc_add_route (rdisc, id, "2001:db8:a:b::", 64, "fe80::2", now, 10, 10);

	id = nm_fake_rdisc_add_ra (rdisc, 1, NM_RDISC_DHCP_LEVEL_NONE, 4, 1500);
	g_assert (id);
	nm_fake_rdisc_add_gateway (rdisc, id, "fe80::1", ++now, 10, NM_RDISC_PREFERENCE_HIGH);
	nm_fake_rdisc_add_address (rdisc, id, "2001:db8:a:a::1", now, 10, 10);
	nm_fake_rdisc_add_route (rdisc, id, "2001:db8:a:a::", 64, "fe80::1", now, 10, 15);

	g_signal_connect (rdisc,
	                  NM_RDISC_CONFIG_CHANGED,
	                  G_CALLBACK (test_preference_changed),
	                  &data);

	nm_rdisc_start (NM_RDISC (rdisc));
	g_main_loop_run (data.loop);
	g_assert_cmpint (data.counter, ==, 3);

	g_object_unref (rdisc);
	g_main_loop_unref (data.loop);
}

static void
test_dns_solicit_loop_changed (NMRDisc *rdisc, NMRDiscConfigMap changed, TestData *data)
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
test_dns_solicit_loop_rs_sent (NMFakeRDisc *rdisc, TestData *data)
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
		id = nm_fake_rdisc_add_ra (rdisc, 0, NM_RDISC_DHCP_LEVEL_NONE, 4, 1500);
		g_assert (id);
		nm_fake_rdisc_add_gateway (rdisc, id, "fe80::1", now, 10, NM_RDISC_PREFERENCE_MEDIUM);
		nm_fake_rdisc_add_address (rdisc, id, "2001:db8:a:a::1", now, 10, 10);

		nm_fake_rdisc_emit_new_ras (rdisc);
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
	NMFakeRDisc *rdisc = rdisc_new ();
	guint32 now = nm_utils_get_monotonic_timestamp_s ();
	TestData data = { g_main_loop_new (NULL, FALSE), 0, 0, now, 0 };
	guint id;

	/* Ensure that no solicitation loop happens when DNS servers or domains
	 * stop being sent in advertisements.  This can happen if two routers
	 * send RAs, but the one sending DNS info stops responding, or if one
	 * router removes the DNS info from the RA without zero-lifetiming them
	 * first.
	 */

	id = nm_fake_rdisc_add_ra (rdisc, 1, NM_RDISC_DHCP_LEVEL_NONE, 4, 1500);
	g_assert (id);
	nm_fake_rdisc_add_gateway (rdisc, id, "fe80::1", now, 10, NM_RDISC_PREFERENCE_LOW);
	nm_fake_rdisc_add_address (rdisc, id, "2001:db8:a:a::1", now, 10, 10);
	nm_fake_rdisc_add_dns_server (rdisc, id, "2001:db8:c:c::1", now, 6);

	g_signal_connect (rdisc,
	                  NM_RDISC_CONFIG_CHANGED,
	                  G_CALLBACK (test_dns_solicit_loop_changed),
	                  &data);
	g_signal_connect (rdisc,
	                  NM_FAKE_RDISC_RS_SENT,
	                  G_CALLBACK (test_dns_solicit_loop_rs_sent),
	                  &data);

	nm_rdisc_start (NM_RDISC (rdisc));
	g_main_loop_run (data.loop);
	g_assert_cmpint (data.counter, ==, 3);

	g_object_unref (rdisc);
	g_main_loop_unref (data.loop);
}

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	nmtst_init_with_logging (&argc, &argv, NULL, "DEFAULT");

	if (nmtst_test_quick ()) {
		g_print ("Skipping test: don't run long running test %s (NMTST_DEBUG=slow)\n", str_if_set (g_get_prgname (), "test-rdisc-fake"));
		return g_test_run ();
	}

	nm_fake_platform_setup ();

	g_test_add_func ("/rdisc/simple", test_simple);
	g_test_add_func ("/rdisc/everything-changed", test_everything);
	g_test_add_func ("/rdisc/preference-changed", test_preference);
	g_test_add_func ("/rdisc/dns-solicit-loop", test_dns_solicit_loop);

	return g_test_run ();
}
