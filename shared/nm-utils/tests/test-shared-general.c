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
#include "nm-utils/unaligned.h"

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

typedef enum {
	TEST_NM_STRDUP_ENUM_m1 = -1,
	TEST_NM_STRDUP_ENUM_3  = 3,
} TestNMStrdupIntEnum;

static void
test_nm_strdup_int (void)
{
#define _NM_STRDUP_INT_TEST(num, str) \
	G_STMT_START { \
		gs_free char *_s1 = NULL; \
		\
		_s1 = nm_strdup_int ((num)); \
		\
		g_assert (_s1); \
		g_assert_cmpstr (_s1, ==, str); \
	} G_STMT_END

#define _NM_STRDUP_INT_TEST_TYPED(type, num) \
	G_STMT_START { \
		type _num = ((type) num); \
		\
		_NM_STRDUP_INT_TEST (_num, G_STRINGIFY (num)); \
	} G_STMT_END

	_NM_STRDUP_INT_TEST_TYPED (char, 0);
	_NM_STRDUP_INT_TEST_TYPED (char, 1);
	_NM_STRDUP_INT_TEST_TYPED (guint8, 0);
	_NM_STRDUP_INT_TEST_TYPED (gint8, 25);
	_NM_STRDUP_INT_TEST_TYPED (char, 47);
	_NM_STRDUP_INT_TEST_TYPED (short, 47);
	_NM_STRDUP_INT_TEST_TYPED (int, 47);
	_NM_STRDUP_INT_TEST_TYPED (long, 47);
	_NM_STRDUP_INT_TEST_TYPED (unsigned char, 47);
	_NM_STRDUP_INT_TEST_TYPED (unsigned short, 47);
	_NM_STRDUP_INT_TEST_TYPED (unsigned, 47);
	_NM_STRDUP_INT_TEST_TYPED (unsigned long, 47);
	_NM_STRDUP_INT_TEST_TYPED (gint64, 9223372036854775807);
	_NM_STRDUP_INT_TEST_TYPED (gint64, -9223372036854775807);
	_NM_STRDUP_INT_TEST_TYPED (guint64, 0);
	_NM_STRDUP_INT_TEST_TYPED (guint64, 9223372036854775807);

	_NM_STRDUP_INT_TEST (TEST_NM_STRDUP_ENUM_m1, "-1");
	_NM_STRDUP_INT_TEST (TEST_NM_STRDUP_ENUM_3,  "3");
}

/*****************************************************************************/

static void
test_nm_strndup_a (void)
{
	int run;

	for (run = 0; run < 20; run++) {
		gs_free char *input = NULL;
		char ch;
		gsize i, l;

		input = g_strnfill (nmtst_get_rand_int () % 20, 'x');

		for (i = 0; input[i]; i++) {
			while ((ch = ((char) nmtst_get_rand_int ())) == '\0') {
				/* repeat. */
			}
			input[i] = ch;
		}

		{
			gs_free char *dup_free = NULL;
			const char *dup;

			l = strlen (input) + 1;
			dup = nm_strndup_a (10, input, l - 1, &dup_free);
			g_assert_cmpstr (dup, ==, input);
			if (strlen (dup) < 10)
				g_assert (!dup_free);
			else
				g_assert (dup == dup_free);
		}

		{
			gs_free char *dup_free = NULL;
			const char *dup;

			l = nmtst_get_rand_int () % 23;
			dup = nm_strndup_a (10, input, l, &dup_free);
			g_assert (strncmp (dup, input, l) == 0);
			g_assert (strlen (dup) <= l);
			if (l < 10)
				g_assert (!dup_free);
			else
				g_assert (dup == dup_free);
			if (strlen (input) < l)
				g_assert (nm_utils_memeqzero (&dup[strlen (input)], l - strlen (input)));
		}
	}
}

/*****************************************************************************/

static void
test_nm_ip4_addr_is_localhost (void)
{
	g_assert ( nm_ip4_addr_is_localhost (nmtst_inet4_from_string ("127.0.0.0")));
	g_assert ( nm_ip4_addr_is_localhost (nmtst_inet4_from_string ("127.0.0.1")));
	g_assert ( nm_ip4_addr_is_localhost (nmtst_inet4_from_string ("127.5.0.1")));
	g_assert (!nm_ip4_addr_is_localhost (nmtst_inet4_from_string ("126.5.0.1")));
	g_assert (!nm_ip4_addr_is_localhost (nmtst_inet4_from_string ("128.5.0.1")));
	g_assert (!nm_ip4_addr_is_localhost (nmtst_inet4_from_string ("129.5.0.1")));
}

/*****************************************************************************/

static void
test_unaligned (void)
{
	int shift;

	for (shift = 0; shift <= 32; shift++) {
		guint8 buf[100] = { };
		guint8 val = 0;

		while (val == 0)
			val = nmtst_get_rand_int () % 256;

		buf[shift] = val;

		g_assert_cmpint (unaligned_read_le64 (&buf[shift]), ==, (guint64) val);
		g_assert_cmpint (unaligned_read_be64 (&buf[shift]), ==, ((guint64) val) << 56);
		g_assert_cmpint (unaligned_read_ne64 (&buf[shift]), !=, 0);

		g_assert_cmpint (unaligned_read_le32 (&buf[shift]), ==, (guint32) val);
		g_assert_cmpint (unaligned_read_be32 (&buf[shift]), ==, ((guint32) val) << 24);
		g_assert_cmpint (unaligned_read_ne32 (&buf[shift]), !=, 0);

		g_assert_cmpint (unaligned_read_le16 (&buf[shift]), ==, (guint16) val);
		g_assert_cmpint (unaligned_read_be16 (&buf[shift]), ==, ((guint16) val) << 8);
		g_assert_cmpint (unaligned_read_ne16 (&buf[shift]), !=, 0);
	}
}

/*****************************************************************************/

NMTST_DEFINE ();

int main (int argc, char **argv)
{
	nmtst_init (&argc, &argv, TRUE);

	g_test_add_func ("/general/test_monotonic_timestamp", test_monotonic_timestamp);
	g_test_add_func ("/general/test_nmhash", test_nmhash);
	g_test_add_func ("/general/test_nm_make_strv", test_make_strv);
	g_test_add_func ("/general/test_nm_strdup_int", test_nm_strdup_int);
	g_test_add_func ("/general/test_nm_strndup_a", test_nm_strndup_a);
	g_test_add_func ("/general/test_nm_ip4_addr_is_localhost", test_nm_ip4_addr_is_localhost);
	g_test_add_func ("/general/test_unaligned", test_unaligned);

	return g_test_run ();
}

