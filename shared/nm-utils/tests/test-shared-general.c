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

#include "nm-std-aux/unaligned.h"
#include "nm-glib-aux/nm-random-utils.h"
#include "nm-glib-aux/nm-time-utils.h"

#include "nm-utils/nm-test-utils.h"

/*****************************************************************************/

static void
test_monotonic_timestamp (void)
{
	g_assert (nm_utils_get_monotonic_timestamp_s () > 0);
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

		input = g_strnfill (nmtst_get_rand_uint32 () % 20, 'x');

		for (i = 0; input[i]; i++) {
			while ((ch = ((char) nmtst_get_rand_uint32 ())) == '\0') {
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

			l = nmtst_get_rand_uint32 () % 23;
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
			val = nmtst_get_rand_uint32 () % 256;

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

static void
_strv_cmp_fuzz_input (const char *const*in,
                      gssize l,
                      const char ***out_strv_free_shallow,
                      char ***out_strv_free_deep,
                      const char *const* *out_s1,
                      const char *const* *out_s2)
{
	const char **strv;
	gsize i;

	/* Fuzz the input argument. It will return two output arrays that are semantically
	 * equal the input. */

	if (nmtst_get_rand_bool ()) {
		char **ss;

		if (l < 0)
			ss = g_strdupv ((char **) in);
		else if (l == 0) {
			ss =   nmtst_get_rand_bool ()
			     ? NULL
			     : g_new0 (char *, 1);
		} else {
			ss = nm_memdup (in, sizeof (const char *) * l);
			for (i = 0; i < (gsize) l; i++)
				ss[i] = g_strdup (ss[i]);
		}
		strv = (const char **) ss;
		*out_strv_free_deep = ss;
	} else {
		if (l < 0) {
			strv =   in
			       ? nm_memdup (in, sizeof (const char *) * (NM_PTRARRAY_LEN (in) + 1))
			       : NULL;
		} else if (l == 0) {
			strv =   nmtst_get_rand_bool ()
			       ? NULL
			       : g_new0 (const char *, 1);
		} else
			strv = nm_memdup (in, sizeof (const char *) * l);
		*out_strv_free_shallow = strv;
	}

	*out_s1 = in;
	*out_s2 = strv;

	if (nmtst_get_rand_bool ()) {
		/* randomly swap the original and the clone. That means, out_s1 is either
		 * the input argument (as-is) or the sementically equal clone. */
		NMTST_SWAP (*out_s1, *out_s2);
	}
	if (nmtst_get_rand_bool ()) {
		/* randomly make s1 and s2 the same. This is for testing that
		 * comparing two identical pointers yields the same result. */
		*out_s2 = *out_s1;
	}
}

static void
_strv_cmp_free_deep (char **strv,
                     gssize len)
{
	gssize i;

	if (strv) {
		if (len < 0)
			g_strfreev (strv);
		else {
			for (i = 0; i < len; i++)
				g_free (strv[i]);
			g_free (strv);
		}
	}
}

static void
test_strv_cmp (void)
{
	const char *const strv0[1] = { };
	const char *const strv1[2] = { "", };

#define _STRV_CMP(a1, l1, a2, l2, equal) \
	G_STMT_START { \
		gssize _l1 = (l1); \
		gssize _l2 = (l2); \
		const char *const*_a1; \
		const char *const*_a2; \
		const char *const*_a1x; \
		const char *const*_a2x; \
		char **_a1_free_deep = NULL; \
		char **_a2_free_deep = NULL; \
		gs_free const char **_a1_free_shallow = NULL; \
		gs_free const char **_a2_free_shallow = NULL; \
		int _c1, _c2; \
		\
		_strv_cmp_fuzz_input ((a1), _l1, &_a1_free_shallow, &_a1_free_deep, &_a1, &_a1x); \
		_strv_cmp_fuzz_input ((a2), _l2, &_a2_free_shallow, &_a2_free_deep, &_a2, &_a2x); \
		\
		_c1 = _nm_utils_strv_cmp_n (_a1, _l1, _a2, _l2); \
		_c2 = _nm_utils_strv_cmp_n (_a2, _l2, _a1, _l1); \
		if (equal) { \
			g_assert_cmpint (_c1, ==, 0); \
			g_assert_cmpint (_c2, ==, 0); \
		} else { \
			g_assert_cmpint (_c1, ==, -1); \
			g_assert_cmpint (_c2, ==, 1); \
		} \
		\
		/* Compare with self. _strv_cmp_fuzz_input() randomly swapped the arguments (_a1 and _a1x).
		 * Either way, the arrays must compare equal to their semantically equal alternative. */ \
		g_assert_cmpint (_nm_utils_strv_cmp_n (_a1, _l1, _a1x, _l1), ==, 0); \
		g_assert_cmpint (_nm_utils_strv_cmp_n (_a2, _l2, _a2x, _l2), ==, 0); \
		\
		_strv_cmp_free_deep (_a1_free_deep, _l1); \
		_strv_cmp_free_deep (_a2_free_deep, _l2); \
	} G_STMT_END

	_STRV_CMP (NULL,  -1, NULL,  -1, TRUE);

	_STRV_CMP (NULL,  -1, NULL,   0, FALSE);
	_STRV_CMP (NULL,  -1, strv0,  0, FALSE);
	_STRV_CMP (NULL,  -1, strv0, -1, FALSE);

	_STRV_CMP (NULL,   0, NULL,   0, TRUE);
	_STRV_CMP (NULL,   0, strv0,  0, TRUE);
	_STRV_CMP (NULL,   0, strv0, -1, TRUE);
	_STRV_CMP (strv0,  0, strv0,  0, TRUE);
	_STRV_CMP (strv0,  0, strv0, -1, TRUE);
	_STRV_CMP (strv0, -1, strv0, -1, TRUE);

	_STRV_CMP (NULL,   0, strv1, -1, FALSE);
	_STRV_CMP (NULL,   0, strv1,  1, FALSE);
	_STRV_CMP (strv0,  0, strv1, -1, FALSE);
	_STRV_CMP (strv0,  0, strv1,  1, FALSE);
	_STRV_CMP (strv0, -1, strv1, -1, FALSE);
	_STRV_CMP (strv0, -1, strv1,  1, FALSE);

	_STRV_CMP (strv1, -1, strv1,  1, TRUE);
	_STRV_CMP (strv1,  1, strv1,  1, TRUE);
}

/*****************************************************************************/

static void
_do_strstrip_avoid_copy (const char *str)
{
	gs_free char *str1 = g_strdup (str);
	gs_free char *str2 = g_strdup (str);
	gs_free char *str3 = NULL;
	gs_free char *str4 = NULL;
	const char *s3;
	const char *s4;

	if (str1)
		g_strstrip (str1);

	nm_strstrip (str2);

	g_assert_cmpstr (str1, ==, str2);

	s3 = nm_strstrip_avoid_copy (str, &str3);
	g_assert_cmpstr (str1, ==, s3);

	s4 = nm_strstrip_avoid_copy_a (10, str, &str4);
	g_assert_cmpstr (str1, ==, s4);
	g_assert (!str == !s4);
	g_assert (!s4 || strlen (s4) <= strlen (str));
	if (s4 && s4 == &str[strlen (str) - strlen (s4)]) {
		g_assert (!str4);
		g_assert (s3 == s4);
	} else if (s4 && strlen (s4) >= 10) {
		g_assert (str4);
		g_assert (s4 == str4);
	} else
		g_assert (!str4);

	if (!nm_streq0 (str1, str))
		_do_strstrip_avoid_copy (str1);
}

static void
test_strstrip_avoid_copy (void)
{
	_do_strstrip_avoid_copy (NULL);
	_do_strstrip_avoid_copy ("");
	_do_strstrip_avoid_copy (" ");
	_do_strstrip_avoid_copy (" a ");
	_do_strstrip_avoid_copy (" 012345678 ");
	_do_strstrip_avoid_copy (" 0123456789 ");
	_do_strstrip_avoid_copy (" 01234567890 ");
	_do_strstrip_avoid_copy (" 012345678901 ");
}

/*****************************************************************************/

static void
test_nm_utils_bin2hexstr (void)
{
	int n_run;

	for (n_run = 0; n_run < 100; n_run++) {
		guint8 buf[100];
		guint8 buf2[G_N_ELEMENTS (buf) + 1];
		gsize len = nmtst_get_rand_uint32 () % (G_N_ELEMENTS (buf) + 1);
		char strbuf1[G_N_ELEMENTS (buf) * 3];
		gboolean allocate = nmtst_get_rand_bool ();
		char delimiter = nmtst_get_rand_bool () ? ':' : '\0';
		gboolean upper_case = nmtst_get_rand_bool ();
		gsize expected_strlen;
		char *str_hex;
		gsize required_len;
		gboolean outlen_set;
		gsize outlen;
		guint8 *bin2;

		nmtst_rand_buf (NULL, buf, len);

		if (len == 0)
			expected_strlen = 0;
		else if (delimiter != '\0')
			expected_strlen = (len * 3u) - 1;
		else
			expected_strlen = len * 2u;

		g_assert_cmpint (expected_strlen, <, G_N_ELEMENTS (strbuf1));

		str_hex = nm_utils_bin2hexstr_full (buf, len, delimiter, upper_case, !allocate ? strbuf1 : NULL);

		g_assert (str_hex);
		if (!allocate)
			g_assert (str_hex == strbuf1);
		g_assert_cmpint (strlen (str_hex), ==, expected_strlen);

		g_assert (NM_STRCHAR_ALL (str_hex, ch,    (ch >= '0' && ch <= '9')
		                                       || ch == delimiter
		                                       || (  upper_case
		                                           ? (ch >= 'A' && ch <= 'F')
		                                           : (ch >= 'a' && ch <= 'f'))));

		required_len = nmtst_get_rand_bool () ? len : 0u;

		outlen_set = required_len == 0 || nmtst_get_rand_bool ();

		memset (buf2, 0, sizeof (buf2));

		bin2 = nm_utils_hexstr2bin_full (str_hex,
		                                 nmtst_get_rand_bool (),
		                                 delimiter != '\0' && nmtst_get_rand_bool (),
		                                   delimiter != '\0'
		                                 ? nmtst_rand_select ((const char *) ":", ":-")
		                                 : nmtst_rand_select ((const char *) ":", ":-", "", NULL),
		                                 required_len,
		                                 buf2,
		                                 len,
		                                 outlen_set ? &outlen : NULL);
		if (len > 0) {
			g_assert (bin2);
			g_assert (bin2 == buf2);
		} else
			g_assert (!bin2);

		if (outlen_set)
			g_assert_cmpint (outlen, ==, len);

		g_assert_cmpmem (buf, len, buf2, len);

		g_assert (buf2[len] == '\0');

		if (allocate)
			g_free (str_hex);
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
	g_test_add_func ("/general/test_strv_cmp", test_strv_cmp);
	g_test_add_func ("/general/test_strstrip_avoid_copy", test_strstrip_avoid_copy);
	g_test_add_func ("/general/test_nm_utils_bin2hexstr", test_nm_utils_bin2hexstr);

	return g_test_run ();
}
