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
 * Copyright (C) 2014 Red Hat, Inc.
 *
 */

#include <glib.h>
#include <string.h>
#include <errno.h>

#include "NetworkManagerUtils.h"


static void
test_nm_utils_ascii_str_to_int64_do (const char *str, guint base, gint64 min,
                                     gint64 max, gint64 fallback, int exp_errno,
                                     gint64 exp_val)
{
	gint64 v;

	errno = 0;
	v = nm_utils_ascii_str_to_int64 (str, base, min, max, fallback);
	g_assert_cmpint (errno, ==, exp_errno);
	g_assert_cmpint (v, ==, exp_val);
}

static void
test_nm_utils_ascii_str_to_int64 (void)
{
	test_nm_utils_ascii_str_to_int64_do ("4711", 10, 0, 10000, -1, 0, 4711);
	test_nm_utils_ascii_str_to_int64_do ("", 10, 0, 10000, -1, EINVAL, -1);
	test_nm_utils_ascii_str_to_int64_do (NULL, 10, 0, 10000, -1, EINVAL, -1);
	test_nm_utils_ascii_str_to_int64_do (" 1x ", 10, 0, 10000, -1, EINVAL, -1);
	test_nm_utils_ascii_str_to_int64_do (" 10000 ", 10, 0, 10000, -1, 0, 10000);
	test_nm_utils_ascii_str_to_int64_do (" 10001 ", 10, 0, 10000, -1, ERANGE, -1);
	test_nm_utils_ascii_str_to_int64_do (" 0xFF ", 16, 0, 10000, -1, 0, 255);
	test_nm_utils_ascii_str_to_int64_do (" FF ", 16, 0, 10000, -1, 0, 255);
	test_nm_utils_ascii_str_to_int64_do (" FF ", 10, 0, 10000, -2, EINVAL, -2);
	test_nm_utils_ascii_str_to_int64_do (" 9223372036854775807 ", 10, 0, G_MAXINT64, -2, 0, G_MAXINT64);
	test_nm_utils_ascii_str_to_int64_do (" 0x7FFFFFFFFFFFFFFF ", 16, 0, G_MAXINT64, -2, 0, G_MAXINT64);
	test_nm_utils_ascii_str_to_int64_do (" 7FFFFFFFFFFFFFFF ", 16, 0, G_MAXINT64, -2, 0, G_MAXINT64);
	test_nm_utils_ascii_str_to_int64_do (" 9223372036854775808 ", 10, 0, G_MAXINT64, -2, ERANGE, -2);
	test_nm_utils_ascii_str_to_int64_do (" -9223372036854775808 ", 10, G_MININT64, 0, -2, 0, G_MININT64);
	test_nm_utils_ascii_str_to_int64_do (" -9223372036854775808 ", 10, G_MININT64+1, 0, -2, ERANGE, -2);
	test_nm_utils_ascii_str_to_int64_do (" -9223372036854775809 ", 10, G_MININT64, 0, -2, ERANGE, -2);
	test_nm_utils_ascii_str_to_int64_do ("\r\n\t10000\t\n\t\n", 10, 0, 10000, -1, 0, 10000);
}

/* Reference implementation for nm_utils_ip6_address_clear_host_address.
 * Taken originally from set_address_masked(), src/rdisc/nm-lndp-rdisc.c
 **/
static void
ip6_address_clear_host_address_reference (struct in6_addr *dst, struct in6_addr *src, guint8 plen)
{
	guint nbytes = plen / 8;
	guint nbits = plen % 8;

	g_return_if_fail (plen <= 128);
	g_assert (src);
	g_assert (dst);

	if (plen >= 128)
		*dst = *src;
	else {
		memset (dst, 0, sizeof (*dst));
		memcpy (dst, src, nbytes);
		dst->s6_addr[nbytes] = (src->s6_addr[nbytes] & (0xFF << (8 - nbits)));
	}
}

static void
_randomize_in6_addr (struct in6_addr *addr, GRand *rand)
{
	int i;

	for (i=0; i < 4; i++)
		((guint32 *)addr)[i] = g_rand_int (rand);
}

static void
test_nm_utils_ip6_address_clear_host_address (void)
{
	GRand *rand = g_rand_new ();
	int plen, i;

	g_rand_set_seed (rand, 0);

	for (plen = 0; plen <= 128; plen++) {
		for (i =0; i<50; i++) {
			struct in6_addr addr_src, addr_ref;
			struct in6_addr addr1, addr2;

			_randomize_in6_addr (&addr_src, rand);
			_randomize_in6_addr (&addr_ref, rand);
			_randomize_in6_addr (&addr1, rand);
			_randomize_in6_addr (&addr2, rand);

			addr1 = addr_src;
			ip6_address_clear_host_address_reference (&addr_ref, &addr1, plen);

			_randomize_in6_addr (&addr1, rand);
			_randomize_in6_addr (&addr2, rand);
			addr1 = addr_src;
			nm_utils_ip6_address_clear_host_address (&addr2, &addr1, plen);
			g_assert_cmpint (memcmp (&addr1, &addr_src, sizeof (struct in6_addr)), ==, 0);
			g_assert_cmpint (memcmp (&addr2, &addr_ref, sizeof (struct in6_addr)), ==, 0);

			/* test for self assignment/inplace update. */
			_randomize_in6_addr (&addr1, rand);
			addr1 = addr_src;
			nm_utils_ip6_address_clear_host_address (&addr1, &addr1, plen);
			g_assert_cmpint (memcmp (&addr1, &addr_ref, sizeof (struct in6_addr)), ==, 0);
		}
	}

	g_rand_free (rand);
}

/*******************************************/

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

	g_type_init ();

	g_test_add_func ("/general/nm_utils_ascii_str_to_int64", test_nm_utils_ascii_str_to_int64);
	g_test_add_func ("/general/nm_utils_ip6_address_clear_host_address", test_nm_utils_ip6_address_clear_host_address);

	return g_test_run ();
}

