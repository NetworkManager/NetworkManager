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

/*******************************************/

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

	g_type_init ();

	g_test_add_func ("/general/nm_utils_ascii_str_to_int64", test_nm_utils_ascii_str_to_int64);

	return g_test_run ();
}

