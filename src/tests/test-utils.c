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
 * Copyright (C) 2015 Red Hat, Inc.
 *
 */

#include "nm-default.h"

#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include "nm-core-utils.c"

#include "nm-test-utils-core.h"

static void
test_stable_privacy (void)
{
	struct in6_addr addr1;

	inet_pton (AF_INET6, "1234::", &addr1);
	_set_stable_privacy (NM_UTILS_STABLE_TYPE_UUID, &addr1, "eth666", "6b138152-9f3e-4b97-aaf7-e6e553f2a24e", 0, (guint8 *) "key", 3, NULL);
	nmtst_assert_ip6_address (&addr1, "1234::4ceb:14cd:3d54:793f");

	/* We get an address without the UUID. */
	inet_pton (AF_INET6, "1::", &addr1);
	_set_stable_privacy (NM_UTILS_STABLE_TYPE_UUID, &addr1, "eth666", NULL, 384, (guint8 *) "key", 3, NULL);
	nmtst_assert_ip6_address (&addr1, "1::11aa:2530:9144:dafa");

	/* We get a different address in a different network. */
	inet_pton (AF_INET6, "2::", &addr1);
	_set_stable_privacy (NM_UTILS_STABLE_TYPE_UUID, &addr1, "eth666", NULL, 384, (guint8 *) "key", 3, NULL);
	nmtst_assert_ip6_address (&addr1, "2::338e:8d:c11:8726");

	inet_pton (AF_INET6, "1234::", &addr1);
	_set_stable_privacy (NM_UTILS_STABLE_TYPE_STABLE_ID, &addr1, "eth666", "6b138152-9f3e-4b97-aaf7-e6e553f2a24e", 0, (guint8 *) "key", 3, NULL);
	nmtst_assert_ip6_address (&addr1, "1234::ad4c:ae44:3d30:af1e");

	inet_pton (AF_INET6, "1234::", &addr1);
	_set_stable_privacy (NM_UTILS_STABLE_TYPE_STABLE_ID, &addr1, "eth666", "stable-id-1", 0, (guint8 *) "key", 3, NULL);
	nmtst_assert_ip6_address (&addr1, "1234::4944:67b0:7a6c:1cf");
}

/*****************************************************************************/

static void
_do_test_hw_addr (NMUtilsStableType stable_type,
                  const char *stable_id,
                  const guint8 *secret_key,
                  gsize key_len,
                  const char *ifname,
                  const char *expected)
{
	gs_free char *generated = NULL;

	g_assert (expected);
	g_assert (nm_utils_hwaddr_valid (expected, ETH_ALEN));

	generated = _hw_addr_gen_stable_eth (stable_type,
	                                     stable_id,
	                                     secret_key,
	                                     key_len,
	                                     ifname);

	g_assert (generated);
	g_assert (nm_utils_hwaddr_valid (generated, ETH_ALEN));
	g_assert_cmpstr (generated, ==, expected);
	g_assert (nm_utils_hwaddr_matches (generated, -1, expected, -1));
}
#define do_test_hw_addr(stable_type, stable_id, secret_key, ifname, expected) \
	_do_test_hw_addr ((stable_type), (stable_id), (const guint8 *) ""secret_key"", NM_STRLEN (secret_key), (ifname), ""expected"")

static void
test_hw_addr_gen_stable_eth (void)
{
	do_test_hw_addr (NM_UTILS_STABLE_TYPE_UUID,      "stable-1", "key1", "eth0", "06:0D:CD:0C:9E:2C");
	do_test_hw_addr (NM_UTILS_STABLE_TYPE_STABLE_ID, "stable-1", "key1", "eth0", "C6:AE:A9:9A:76:09");
}

/*****************************************************************************/

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	nmtst_init_with_logging (&argc, &argv, NULL, "ALL");

	g_test_add_func ("/utils/stable_privacy", test_stable_privacy);
	g_test_add_func ("/utils/hw_addr_gen_stable_eth", test_hw_addr_gen_stable_eth);

	return g_test_run ();
}
