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

#include "config.h"

#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include "NetworkManagerUtils.c"

#include "nm-test-utils.h"

static void
test_stable_privacy (void)
{
	struct in6_addr addr1;

	inet_pton (AF_INET6, "1234::", &addr1);
	_set_stable_privacy (&addr1, "eth666", "6b138152-9f3e-4b97-aaf7-e6e553f2a24e", 0, "key", 3, NULL);
	nmtst_assert_ip6_address (&addr1, "1234::4ceb:14cd:3d54:793f");

	/* We get an address without the UUID. */
	inet_pton (AF_INET6, "1::", &addr1);
	_set_stable_privacy (&addr1, "eth666", NULL, 384, "key", 3, NULL);
	nmtst_assert_ip6_address (&addr1, "1::11aa:2530:9144:dafa");

	/* We get a different address in a different network. */
	inet_pton (AF_INET6, "2::", &addr1);
	_set_stable_privacy (&addr1, "eth666", NULL, 384, "key", 3, NULL);
	nmtst_assert_ip6_address (&addr1, "2::338e:8d:c11:8726");
}

/*******************************************/

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	nmtst_init_with_logging (&argc, &argv, NULL, "ALL");

	g_test_add_func ("/utils/stable_privacy", test_stable_privacy);

	return g_test_run ();
}
