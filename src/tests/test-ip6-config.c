/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
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
 * Copyright (C) 2013 Red Hat, Inc.
 *
 */

#include "nm-default.h"

#include <arpa/inet.h>
#include <linux/if_addr.h>

#include "nm-ip6-config.h"

#include "platform/nm-platform.h"
#include "nm-test-utils-core.h"

static NMIP6Config *
build_test_config (void)
{
	NMIP6Config *config;

	/* Build up the config to subtract */
	config = nmtst_ip6_config_new (1);

	nm_ip6_config_add_address (config, nmtst_platform_ip6_address ("abcd:1234:4321::cdde", "1:2:3:4::5", 64));
	nm_ip6_config_add_route (config, nmtst_platform_ip6_route ("abcd:1200::", 24, "abcd:1234:4321:cdde::2", NULL), NULL);
	nm_ip6_config_add_route (config, nmtst_platform_ip6_route ("2001::", 16, "2001:abba::2234", NULL), NULL);

	nm_ip6_config_add_route (config, nmtst_platform_ip6_route ("::", 0, "3001:abba::3234", NULL), NULL);

	nm_ip6_config_add_nameserver (config, nmtst_inet6_from_string ("1:2:3:4::1"));
	nm_ip6_config_add_nameserver (config, nmtst_inet6_from_string ("1:2:3:4::2"));
	nm_ip6_config_add_domain (config, "foobar.com");
	nm_ip6_config_add_domain (config, "baz.com");
	nm_ip6_config_add_search (config, "blahblah.com");
	nm_ip6_config_add_search (config, "beatbox.com");

	return config;
}

static void
test_subtract (void)
{
	NMIP6Config *src, *dst;
	const NMPlatformIP6Address *test_addr;
	const NMPlatformIP6Route *test_route;
	const char *expected_addr = "1122:3344:5566::7788";
	guint32 expected_addr_plen = 96;
	const char *expected_route_dest = "9991:8800::";
	guint32 expected_route_plen = 24;
	const char *expected_route_next_hop = "1119:2228:3337:4446::5555";
	struct in6_addr expected_ns1;
	struct in6_addr expected_ns2;
	const char *expected_domain = "wonderfalls.com";
	const char *expected_search = "somewhere.com";
	struct in6_addr tmp;

	src = build_test_config ();

	/* add a couple more things to the test config */
	dst = build_test_config ();
	nm_ip6_config_add_address (dst, nmtst_platform_ip6_address (expected_addr, NULL, expected_addr_plen));
	nm_ip6_config_add_route (dst, nmtst_platform_ip6_route (expected_route_dest, expected_route_plen, expected_route_next_hop, NULL), NULL);

	expected_ns1 = *nmtst_inet6_from_string ("2222:3333:4444::5555");
	nm_ip6_config_add_nameserver (dst, &expected_ns1);
	expected_ns2 = *nmtst_inet6_from_string ("2222:3333:4444::5556");
	nm_ip6_config_add_nameserver (dst, &expected_ns2);

	nm_ip6_config_add_domain (dst, expected_domain);
	nm_ip6_config_add_search (dst, expected_search);

	nm_ip6_config_subtract (dst, src, 0);

	/* ensure what's left is what we expect */
	g_assert_cmpuint (nm_ip6_config_get_num_addresses (dst), ==, 1);
	test_addr = _nmtst_ip6_config_get_address (dst, 0);
	g_assert (test_addr != NULL);
	tmp = *nmtst_inet6_from_string (expected_addr);
	g_assert (memcmp (&test_addr->address, &tmp, sizeof (tmp)) == 0);
	g_assert (memcmp (&test_addr->peer_address, &in6addr_any, sizeof (tmp)) == 0);
	g_assert_cmpuint (test_addr->plen, ==, expected_addr_plen);

	g_assert (nm_ip6_config_best_default_route_get (dst) == NULL);

	g_assert_cmpuint (nm_ip6_config_get_num_routes (dst), ==, 1);
	test_route = _nmtst_ip6_config_get_route (dst, 0);
	g_assert (test_route != NULL);

	tmp = *nmtst_inet6_from_string (expected_route_dest);
	g_assert (memcmp (&test_route->network, &tmp, sizeof (tmp)) == 0);
	g_assert_cmpuint (test_route->plen, ==, expected_route_plen);
	tmp = *nmtst_inet6_from_string  (expected_route_next_hop);
	g_assert (memcmp (&test_route->gateway, &tmp, sizeof (tmp)) == 0);

	g_assert_cmpuint (nm_ip6_config_get_num_nameservers (dst), ==, 2);
	g_assert (memcmp (nm_ip6_config_get_nameserver (dst, 0), &expected_ns1, sizeof (expected_ns1)) == 0);
	g_assert (memcmp (nm_ip6_config_get_nameserver (dst, 1), &expected_ns2, sizeof (expected_ns2)) == 0);

	g_assert_cmpuint (nm_ip6_config_get_num_domains (dst), ==, 1);
	g_assert_cmpstr (nm_ip6_config_get_domain (dst, 0), ==, expected_domain);
	g_assert_cmpuint (nm_ip6_config_get_num_searches (dst), ==, 1);
	g_assert_cmpstr (nm_ip6_config_get_search (dst, 0), ==, expected_search);

	g_object_unref (src);
	g_object_unref (dst);
}

static void
test_compare_with_source (void)
{
	NMIP6Config *a, *b;
	NMPlatformIP6Address addr;
	NMPlatformIP6Route route;

	a = nmtst_ip6_config_new (1);
	b = nmtst_ip6_config_new (2);

	/* Address */
	addr = *nmtst_platform_ip6_address ("1122:3344:5566::7788", NULL, 64);
	addr.addr_source = NM_IP_CONFIG_SOURCE_USER;
	nm_ip6_config_add_address (a, &addr);

	addr.addr_source = NM_IP_CONFIG_SOURCE_VPN;
	nm_ip6_config_add_address (b, &addr);

	/* Route */
	route = *nmtst_platform_ip6_route ("abcd:1200::", 24, "abcd:1234:4321:cdde::2", NULL);
	route.rt_source = NM_IP_CONFIG_SOURCE_USER;
	nm_ip6_config_add_route (a, &route, NULL);

	route.rt_source = NM_IP_CONFIG_SOURCE_VPN;
	nm_ip6_config_add_route (b, &route, NULL);

	/* Assert that the configs are basically the same, eg that the source is ignored */
	g_assert (nm_ip6_config_equal (a, b));

	g_object_unref (a);
	g_object_unref (b);
}

static void
test_add_address_with_source (void)
{
	NMIP6Config *a;
	NMPlatformIP6Address addr;
	const NMPlatformIP6Address *test_addr;

	a = nmtst_ip6_config_new (1);

	/* Test that a higher priority source is not overwritten */
	addr = *nmtst_platform_ip6_address ("1122:3344:5566::7788", NULL, 64);
	addr.addr_source = NM_IP_CONFIG_SOURCE_USER;
	nm_ip6_config_add_address (a, &addr);

	test_addr = _nmtst_ip6_config_get_address (a, 0);
	g_assert_cmpint (test_addr->addr_source, ==, NM_IP_CONFIG_SOURCE_USER);

	addr.addr_source = NM_IP_CONFIG_SOURCE_VPN;
	nm_ip6_config_add_address (a, &addr);

	test_addr = _nmtst_ip6_config_get_address (a, 0);
	g_assert_cmpint (test_addr->addr_source, ==, NM_IP_CONFIG_SOURCE_USER);

	/* Test that a lower priority address source is overwritten */
	_nmtst_ip6_config_del_address (a, 0);
	addr.addr_source = NM_IP_CONFIG_SOURCE_KERNEL;
	nm_ip6_config_add_address (a, &addr);

	test_addr = _nmtst_ip6_config_get_address (a, 0);
	g_assert_cmpint (test_addr->addr_source, ==, NM_IP_CONFIG_SOURCE_KERNEL);

	addr.addr_source = NM_IP_CONFIG_SOURCE_USER;
	nm_ip6_config_add_address (a, &addr);

	test_addr = _nmtst_ip6_config_get_address (a, 0);
	g_assert_cmpint (test_addr->addr_source, ==, NM_IP_CONFIG_SOURCE_USER);

	g_object_unref (a);
}

static void
test_add_route_with_source (void)
{
	gs_unref_object NMIP6Config *a = NULL;
	NMPlatformIP6Route route;
	const NMPlatformIP6Route *test_route;

	a = nmtst_ip6_config_new (1);

	/* Test that a higher priority source is not overwritten */
	route = *nmtst_platform_ip6_route ("abcd:1200::", 24, "abcd:1234:4321:cdde::2", NULL);
	route.rt_source = NM_IP_CONFIG_SOURCE_USER;
	nm_ip6_config_add_route (a, &route, NULL);

	g_assert_cmpint (nm_ip6_config_get_num_routes (a), ==, 1);
	test_route = _nmtst_ip6_config_get_route (a, 0);
	g_assert_cmpint (test_route->rt_source, ==, NM_IP_CONFIG_SOURCE_USER);

	route.rt_source = NM_IP_CONFIG_SOURCE_VPN;
	nm_ip6_config_add_route (a, &route, NULL);

	g_assert_cmpint (nm_ip6_config_get_num_routes (a), ==, 1);
	test_route = _nmtst_ip6_config_get_route (a, 0);
	g_assert_cmpint (test_route->rt_source, ==, NM_IP_CONFIG_SOURCE_USER);

	_nmtst_ip6_config_del_route (a, 0);
	g_assert_cmpint (nm_ip6_config_get_num_routes (a), ==, 0);

	/* Test that a lower priority address source is overwritten */
	route.rt_source = NM_IP_CONFIG_SOURCE_KERNEL;
	nm_ip6_config_add_route (a, &route, NULL);

	g_assert_cmpint (nm_ip6_config_get_num_routes (a), ==, 1);
	test_route = _nmtst_ip6_config_get_route (a, 0);
	g_assert_cmpint (test_route->rt_source, ==, NM_IP_CONFIG_SOURCE_KERNEL);

	route.rt_source = NM_IP_CONFIG_SOURCE_USER;
	nm_ip6_config_add_route (a, &route, NULL);

	g_assert_cmpint (nm_ip6_config_get_num_routes (a), ==, 1);
	test_route = _nmtst_ip6_config_get_route (a, 0);
	g_assert_cmpint (test_route->rt_source, ==, NM_IP_CONFIG_SOURCE_USER);
}

static void
test_nm_ip6_config_addresses_sort_check (NMIP6Config *config, NMSettingIP6ConfigPrivacy use_tempaddr, int repeat)
{
	int addr_count = nm_ip6_config_get_num_addresses (config);
	int i, irepeat;
	NMIP6Config *copy, *copy2;
	int *idx = g_new (int, addr_count);

	nm_ip6_config_set_privacy (config, use_tempaddr);
	copy = nm_ip6_config_clone (config);
	g_assert (copy);
	copy2 = nm_ip6_config_clone (config);
	g_assert (copy2);

	/* initialize the array of indices, and keep shuffling them for every @repeat iteration. */
	for (i = 0; i < addr_count; i++)
		idx[i] = i;

	for (irepeat = 0; irepeat < repeat; irepeat++) {
		/* randomly shuffle the addresses. */
		nm_ip6_config_reset_addresses (copy);
		for (i = 0; i < addr_count; i++) {
			int j = g_rand_int_range (nmtst_get_rand (), i, addr_count);

			NMTST_SWAP (idx[i], idx[j]);
			nm_ip6_config_add_address (copy, _nmtst_ip6_config_get_address (config, idx[i]));
		}

		/* reorder them again */
		_nmtst_ip6_config_addresses_sort (copy);

		/* check equality using nm_ip6_config_equal() */
		if (!nm_ip6_config_equal (copy, config)) {
			g_message ("%s", "SORTING yields unexpected output:");
			for (i = 0; i < addr_count; i++) {
				g_message ("   >> [%d] = %s", i, nm_platform_ip6_address_to_string (_nmtst_ip6_config_get_address (config, i), NULL, 0));
				g_message ("   << [%d] = %s", i, nm_platform_ip6_address_to_string (_nmtst_ip6_config_get_address (copy, i), NULL, 0));
			}
			g_assert_not_reached ();
		}

		/* also check equality using nm_ip6_config_replace() */
		g_assert (nm_ip6_config_replace (copy2, copy, NULL) == FALSE);
	}

	g_free (idx);
	g_object_unref (copy);
	g_object_unref (copy2);
}

static void
test_nm_ip6_config_addresses_sort (void)
{
	NMIP6Config *config = build_test_config ();

#define ADDR_ADD(...) nm_ip6_config_add_address (config, nmtst_platform_ip6_address_full (__VA_ARGS__))

	nm_ip6_config_reset_addresses (config);
	ADDR_ADD("2607:f0d0:1002:51::4",     NULL,  64, 0, NM_IP_CONFIG_SOURCE_USER,   0, 0, 0, 0);
	ADDR_ADD("2607:f0d0:1002:51::5",     NULL,  64, 0, NM_IP_CONFIG_SOURCE_USER,   0, 0, 0, 0);
	ADDR_ADD("2607:f0d0:1002:51::6",     NULL,  64, 0, NM_IP_CONFIG_SOURCE_NDISC,  0, 0, 0, IFA_F_MANAGETEMPADDR);
	ADDR_ADD("2607:f0d0:1002:51::3",     NULL,  64, 0, NM_IP_CONFIG_SOURCE_USER,   0, 0, 0, IFA_F_TEMPORARY);
	ADDR_ADD("2607:f0d0:1002:51::8",     NULL,  64, 0, NM_IP_CONFIG_SOURCE_USER,   0, 0, 0, IFA_F_TEMPORARY);
	ADDR_ADD("2607:f0d0:1002:51::0",     NULL,  64, 0, NM_IP_CONFIG_SOURCE_KERNEL, 0, 0, 0, IFA_F_TEMPORARY);
	ADDR_ADD("fec0::1",                  NULL, 128, 0, NM_IP_CONFIG_SOURCE_KERNEL, 0, 0, 0, 0);
	ADDR_ADD("fe80::208:74ff:feda:625c", NULL, 128, 0, NM_IP_CONFIG_SOURCE_KERNEL, 0, 0, 0, 0);
	ADDR_ADD("fe80::208:74ff:feda:625d", NULL, 128, 0, NM_IP_CONFIG_SOURCE_KERNEL, 0, 0, 0, 0);
	ADDR_ADD("::1",                      NULL, 128, 0, NM_IP_CONFIG_SOURCE_USER, 0, 0, 0, 0);
	ADDR_ADD("2607:f0d0:1002:51::2",     NULL,  64, 0, NM_IP_CONFIG_SOURCE_USER,   0, 0, 0, IFA_F_TENTATIVE);
	test_nm_ip6_config_addresses_sort_check (config, NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN, 8);
	test_nm_ip6_config_addresses_sort_check (config, NM_SETTING_IP6_CONFIG_PRIVACY_DISABLED, 8);
	test_nm_ip6_config_addresses_sort_check (config, NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_PUBLIC_ADDR, 8);

	nm_ip6_config_reset_addresses (config);
	ADDR_ADD("2607:f0d0:1002:51::3",     NULL,  64, 0, NM_IP_CONFIG_SOURCE_USER,   0, 0, 0, IFA_F_TEMPORARY);
	ADDR_ADD("2607:f0d0:1002:51::4",     NULL,  64, 0, NM_IP_CONFIG_SOURCE_USER,   0, 0, 0, 0);
	ADDR_ADD("2607:f0d0:1002:51::5",     NULL,  64, 0, NM_IP_CONFIG_SOURCE_USER,   0, 0, 0, 0);
	ADDR_ADD("2607:f0d0:1002:51::8",     NULL,  64, 0, NM_IP_CONFIG_SOURCE_USER,   0, 0, 0, IFA_F_TEMPORARY);
	ADDR_ADD("2607:f0d0:1002:51::0",     NULL,  64, 0, NM_IP_CONFIG_SOURCE_KERNEL, 0, 0, 0, IFA_F_TEMPORARY);
	ADDR_ADD("2607:f0d0:1002:51::6",     NULL,  64, 0, NM_IP_CONFIG_SOURCE_NDISC,  0, 0, 0, IFA_F_MANAGETEMPADDR);
	ADDR_ADD("fec0::1",                  NULL, 128, 0, NM_IP_CONFIG_SOURCE_KERNEL, 0, 0, 0, 0);
	ADDR_ADD("fe80::208:74ff:feda:625c", NULL, 128, 0, NM_IP_CONFIG_SOURCE_KERNEL, 0, 0, 0, 0);
	ADDR_ADD("fe80::208:74ff:feda:625d", NULL, 128, 0, NM_IP_CONFIG_SOURCE_KERNEL, 0, 0, 0, 0);
	ADDR_ADD("::1",                      NULL, 128, 0, NM_IP_CONFIG_SOURCE_USER, 0, 0, 0, 0);
	ADDR_ADD("2607:f0d0:1002:51::2",     NULL,  64, 0, NM_IP_CONFIG_SOURCE_USER,   0, 0, 0, IFA_F_TENTATIVE);
	test_nm_ip6_config_addresses_sort_check (config, NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR, 8);

#undef ADDR_ADD
	g_object_unref (config);
}

static void
test_strip_search_trailing_dot (void)
{
	NMIP6Config *config;

	config = nmtst_ip6_config_new (1);

	nm_ip6_config_add_search (config, ".");
	nm_ip6_config_add_search (config, "foo");
	nm_ip6_config_add_search (config, "bar.");
	nm_ip6_config_add_search (config, "baz.com");
	nm_ip6_config_add_search (config, "baz.com.");
	nm_ip6_config_add_search (config, "foobar..");
	nm_ip6_config_add_search (config, ".foobar");
	nm_ip6_config_add_search (config, "~.");

	g_assert_cmpuint (nm_ip6_config_get_num_searches (config), ==, 4);
	g_assert_cmpstr (nm_ip6_config_get_search (config, 0), ==, "foo");
	g_assert_cmpstr (nm_ip6_config_get_search (config, 1), ==, "bar");
	g_assert_cmpstr (nm_ip6_config_get_search (config, 2), ==, "baz.com");
	g_assert_cmpstr (nm_ip6_config_get_search (config, 3), ==, "~");

	g_object_unref (config);
}

/*****************************************************************************/

static void
test_replace (gconstpointer user_data)
{
	nm_auto_unref_dedup_multi_index NMDedupMultiIndex *multi_idx = nm_dedup_multi_index_new ();
	const int TEST_IDX = GPOINTER_TO_INT (user_data);
	const int IFINDEX = 1;
	gs_unref_object NMIP6Config *src_conf = NULL;
	gs_unref_object NMIP6Config *dst_conf = NULL;
	NMPlatformIP6Address *addr;
	NMPlatformIP6Address addrs[5] = { };
	guint addrs_n = 0;
	guint i;

	dst_conf = nm_ip6_config_new (multi_idx, IFINDEX);
	src_conf = nm_ip6_config_new (multi_idx, IFINDEX);

	switch (TEST_IDX) {
	case 1:
		addr = &addrs[addrs_n++];
		addr->ifindex = IFINDEX;
		addr->address = *nmtst_inet6_from_string ("fe80::78ec:7a6d:602d:20f2");
		addr->plen = 64;
		addr->n_ifa_flags = IFA_F_PERMANENT;
		addr->addr_source = NM_IP_CONFIG_SOURCE_KERNEL;
		break;
	case 2:
		addr = &addrs[addrs_n++];
		addr->ifindex = IFINDEX;
		addr->address = *nmtst_inet6_from_string ("fe80::78ec:7a6d:602d:20f2");
		addr->plen = 64;
		addr->n_ifa_flags = IFA_F_PERMANENT;
		addr->addr_source = NM_IP_CONFIG_SOURCE_KERNEL;

		addr = &addrs[addrs_n++];
		addr->ifindex = IFINDEX;
		addr->address = *nmtst_inet6_from_string ("1::1");
		addr->plen = 64;
		addr->addr_source = NM_IP_CONFIG_SOURCE_USER;

		nm_ip6_config_add_address (dst_conf, addr);
		break;
	default:
		g_assert_not_reached ();
	}

	g_assert (addrs_n < G_N_ELEMENTS (addrs));

	for (i = 0; i < addrs_n; i++)
		nm_ip6_config_add_address (src_conf, &addrs[i]);

	nm_ip6_config_replace (dst_conf, src_conf, NULL);

	for (i = 0; i < addrs_n; i++) {
		const NMPlatformIP6Address *a = _nmtst_ip6_config_get_address (dst_conf, i);
		const NMPlatformIP6Address *b = _nmtst_ip6_config_get_address (src_conf, i);

		g_assert (nm_platform_ip6_address_cmp (&addrs[i], a) == 0);
		g_assert (nm_platform_ip6_address_cmp (&addrs[i], b) == 0);
	}
	g_assert (addrs_n == nm_ip6_config_get_num_addresses (dst_conf));
	g_assert (addrs_n == nm_ip6_config_get_num_addresses (src_conf));
}

/*****************************************************************************/

NMTST_DEFINE();

int
main (int argc, char **argv)
{
	nmtst_init_with_logging (&argc, &argv, NULL, "ALL");

	g_test_add_func ("/ip6-config/subtract", test_subtract);
	g_test_add_func ("/ip6-config/compare-with-source", test_compare_with_source);
	g_test_add_func ("/ip6-config/add-address-with-source", test_add_address_with_source);
	g_test_add_func ("/ip6-config/add-route-with-source", test_add_route_with_source);
	g_test_add_func ("/ip6-config/test_nm_ip6_config_addresses_sort", test_nm_ip6_config_addresses_sort);
	g_test_add_func ("/ip6-config/strip-search-trailing-dot", test_strip_search_trailing_dot);
	g_test_add_data_func ("/ip6-config/replace/1", GINT_TO_POINTER (1), test_replace);
	g_test_add_data_func ("/ip6-config/replace/2", GINT_TO_POINTER (2), test_replace);

	return g_test_run ();
}

