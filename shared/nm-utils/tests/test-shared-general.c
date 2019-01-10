/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2018 Red Hat, Inc.
 */

#define NM_TEST_UTILS_NO_LIBNM 1

#include "nm-default.h"

#include "nm-utils/nm-time-utils.h"
#include "nm-utils/nm-random-utils.h"

#include "nm-utils/nm-test-utils.h"

/*****************************************************************************/

static int _monotonic_timestamp_initialized;

void
_nm_utils_monotonic_timestamp_initialized (const struct timespec *tp,
                                           gint64 offset_sec,
                                           gboolean is_boottime)
{
	g_assert (!_monotonic_timestamp_initialized);
	_monotonic_timestamp_initialized = 1;
}

/*****************************************************************************/

static void
test_monotonic_timestamp (void)
{
	g_assert (nm_utils_get_monotonic_timestamp_s () > 0);
	g_assert (_monotonic_timestamp_initialized);
}

/*****************************************************************************/

static void
test_nmhash (void)
{
	int rnd;

	nm_utils_random_bytes (&rnd, sizeof (rnd));

	g_assert (nm_hash_val (555, 4) != 0);
}

/*****************************************************************************/

static const char *
_make_strv_foo (void)
{
	return "foo";
}

static const char *const*const _tst_make_strv_1 = NM_MAKE_STRV ("1", "2");

static void
test_make_strv (void)
{
	const char *const*v1a = NM_MAKE_STRV ("a");
	const char *const*v1b = NM_MAKE_STRV ("a", );
	const char *const*v2a = NM_MAKE_STRV ("a", "b");
	const char *const*v2b = NM_MAKE_STRV ("a", "b", );
	const char *const v3[] = { "a", "b", };
	const char *const*v4b = NM_MAKE_STRV ("a", _make_strv_foo (), );

	g_assert (NM_PTRARRAY_LEN (v1a) == 1);
	g_assert (NM_PTRARRAY_LEN (v1b) == 1);
	g_assert (NM_PTRARRAY_LEN (v2a) == 2);
	g_assert (NM_PTRARRAY_LEN (v2b) == 2);

	g_assert (NM_PTRARRAY_LEN (_tst_make_strv_1) == 2);
	g_assert_cmpstr (_tst_make_strv_1[0], ==, "1");
	g_assert_cmpstr (_tst_make_strv_1[1], ==, "2");
	/* writing the static read-only variable leads to crash .*/
	//((char **) _tst_make_strv_1)[0] = NULL;
	//((char **) _tst_make_strv_1)[2] = "c";

	G_STATIC_ASSERT_EXPR (G_N_ELEMENTS (v3) == 2);

	g_assert (NM_PTRARRAY_LEN (v4b) == 2);

	G_STATIC_ASSERT_EXPR (G_N_ELEMENTS (NM_MAKE_STRV ("a", "b"  )) == 3);
	G_STATIC_ASSERT_EXPR (G_N_ELEMENTS (NM_MAKE_STRV ("a", "b", )) == 3);

	nm_strquote_a (300, "");
}

/*****************************************************************************/

NMTST_DEFINE ();

int main (int argc, char **argv)
{
	nmtst_init (&argc, &argv, TRUE);

	g_test_add_func ("/general/test_monotonic_timestamp", test_monotonic_timestamp);
	g_test_add_func ("/general/test_nmhash", test_nmhash);
	g_test_add_func ("/general/test_nm_make_strv", test_make_strv);

	return g_test_run ();
}

