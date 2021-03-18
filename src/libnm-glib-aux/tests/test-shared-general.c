/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2018 Red Hat, Inc.
 */

#include "libnm-glib-aux/nm-default-glib-i18n-prog.h"

#include "libnm-std-aux/unaligned.h"
#include "libnm-glib-aux/nm-random-utils.h"
#include "libnm-glib-aux/nm-str-buf.h"
#include "libnm-glib-aux/nm-time-utils.h"
#include "libnm-glib-aux/nm-ref-string.h"

#include "libnm-glib-aux/nm-test-utils.h"

/*****************************************************************************/

G_STATIC_ASSERT(NM_AF_UNSPEC == AF_UNSPEC);
G_STATIC_ASSERT(NM_AF_INET == AF_INET);
G_STATIC_ASSERT(NM_AF_INET6 == AF_INET6);

G_STATIC_ASSERT(NM_AF_INET_SIZE == sizeof(in_addr_t));
G_STATIC_ASSERT(NM_AF_INET_SIZE == sizeof(struct in_addr));
G_STATIC_ASSERT(NM_AF_INET6_SIZE == sizeof(struct in6_addr));

G_STATIC_ASSERT(4 == _nm_alignof(in_addr_t));
G_STATIC_ASSERT(4 == _nm_alignof(struct in_addr));
G_STATIC_ASSERT(4 == _nm_alignof(struct in6_addr));
G_STATIC_ASSERT(4 == _nm_alignof(NMIPAddr));

/*****************************************************************************/

static void
test_gpid(void)
{
    const int *int_ptr;
    GPid       pid = 42;

    /* We redefine G_PID_FORMAT, because it's only available since glib 2.53.5.
     *
     * Also, this is the format for GPid, which for glib is always a typedef
     * for "int". Add a check for that here.
     *
     * G_PID_FORMAT is not about pid_t, which might be a smaller int, and which we would
     * check with SIZEOF_PID_T. */
    G_STATIC_ASSERT(sizeof(GPid) == sizeof(int));

    g_assert_cmpstr("" G_PID_FORMAT, ==, "i");

    /* check that it's really "int". We will get a compiler warning, if that's not
     * the case. */
    int_ptr = &pid;
    g_assert_cmpint(*int_ptr, ==, 42);
}

/*****************************************************************************/

static void
test_monotonic_timestamp(void)
{
    g_assert(nm_utils_get_monotonic_timestamp_sec() > 0);
}

/*****************************************************************************/

static void
test_nmhash(void)
{
    int rnd;

    nm_utils_random_bytes(&rnd, sizeof(rnd));

    g_assert(nm_hash_val(555, 4) != 0);
}

/*****************************************************************************/

static const char *
_make_strv_foo(void)
{
    return "foo";
}

static const char *const *const _tst_make_strv_1 = NM_MAKE_STRV("1", "2");

static void
test_make_strv(void)
{
    const char *const *v1a  = NM_MAKE_STRV("a");
    const char *const *v1b  = NM_MAKE_STRV("a", );
    const char *const *v2a  = NM_MAKE_STRV("a", "b");
    const char *const *v2b  = NM_MAKE_STRV("a", "b", );
    const char *const  v3[] = {
        "a",
        "b",
    };
    const char *const *v4b = NM_MAKE_STRV("a", _make_strv_foo(), );

    g_assert(NM_PTRARRAY_LEN(v1a) == 1);
    g_assert(NM_PTRARRAY_LEN(v1b) == 1);
    g_assert(NM_PTRARRAY_LEN(v2a) == 2);
    g_assert(NM_PTRARRAY_LEN(v2b) == 2);

    g_assert(NM_PTRARRAY_LEN(_tst_make_strv_1) == 2);
    g_assert_cmpstr(_tst_make_strv_1[0], ==, "1");
    g_assert_cmpstr(_tst_make_strv_1[1], ==, "2");
    /* writing the static read-only variable leads to crash .*/
    //((char **) _tst_make_strv_1)[0] = NULL;
    //((char **) _tst_make_strv_1)[2] = "c";

    G_STATIC_ASSERT_EXPR(G_N_ELEMENTS(v3) == 2);

    g_assert(NM_PTRARRAY_LEN(v4b) == 2);

    G_STATIC_ASSERT_EXPR(G_N_ELEMENTS(NM_MAKE_STRV("a", "b")) == 3);
    G_STATIC_ASSERT_EXPR(G_N_ELEMENTS(NM_MAKE_STRV("a", "b", )) == 3);

    nm_strquote_a(300, "");
}

/*****************************************************************************/

typedef enum {
    TEST_NM_STRDUP_ENUM_m1 = -1,
    TEST_NM_STRDUP_ENUM_3  = 3,
} TestNMStrdupIntEnum;

static void
test_nm_strdup_int(void)
{
#define _NM_STRDUP_INT_TEST(num, str)  \
    G_STMT_START                       \
    {                                  \
        gs_free char *_s1 = NULL;      \
                                       \
        _s1 = nm_strdup_int((num));    \
                                       \
        g_assert(_s1);                 \
        g_assert_cmpstr(_s1, ==, str); \
    }                                  \
    G_STMT_END

#define _NM_STRDUP_INT_TEST_TYPED(type, num)         \
    G_STMT_START                                     \
    {                                                \
        type _num = ((type) num);                    \
                                                     \
        _NM_STRDUP_INT_TEST(_num, G_STRINGIFY(num)); \
    }                                                \
    G_STMT_END

    _NM_STRDUP_INT_TEST_TYPED(char, 0);
    _NM_STRDUP_INT_TEST_TYPED(char, 1);
    _NM_STRDUP_INT_TEST_TYPED(guint8, 0);
    _NM_STRDUP_INT_TEST_TYPED(gint8, 25);
    _NM_STRDUP_INT_TEST_TYPED(char, 47);
    _NM_STRDUP_INT_TEST_TYPED(short, 47);
    _NM_STRDUP_INT_TEST_TYPED(int, 47);
    _NM_STRDUP_INT_TEST_TYPED(long, 47);
    _NM_STRDUP_INT_TEST_TYPED(unsigned char, 47);
    _NM_STRDUP_INT_TEST_TYPED(unsigned short, 47);
    _NM_STRDUP_INT_TEST_TYPED(unsigned, 47);
    _NM_STRDUP_INT_TEST_TYPED(unsigned long, 47);
    _NM_STRDUP_INT_TEST_TYPED(gint64, 9223372036854775807);
    _NM_STRDUP_INT_TEST_TYPED(gint64, -9223372036854775807);
    _NM_STRDUP_INT_TEST_TYPED(guint64, 0);
    _NM_STRDUP_INT_TEST_TYPED(guint64, 9223372036854775807);

    _NM_STRDUP_INT_TEST(TEST_NM_STRDUP_ENUM_m1, "-1");
    _NM_STRDUP_INT_TEST(TEST_NM_STRDUP_ENUM_3, "3");
}

/*****************************************************************************/

static void
test_nm_strndup_a(void)
{
    int run;

    for (run = 0; run < 20; run++) {
        gs_free char *input = NULL;
        char          ch;
        gsize         i, l;

        input = g_strnfill(nmtst_get_rand_uint32() % 20, 'x');

        for (i = 0; input[i]; i++) {
            while ((ch = ((char) nmtst_get_rand_uint32())) == '\0') {
                /* repeat. */
            }
            input[i] = ch;
        }

        {
            gs_free char *dup_free = NULL;
            const char *  dup;

            l   = strlen(input) + 1;
            dup = nm_strndup_a(10, input, l - 1, &dup_free);
            g_assert_cmpstr(dup, ==, input);
            if (strlen(dup) < 10)
                g_assert(!dup_free);
            else
                g_assert(dup == dup_free);
        }

        {
            gs_free char *dup_free = NULL;
            const char *  dup;

            l   = nmtst_get_rand_uint32() % 23;
            dup = nm_strndup_a(10, input, l, &dup_free);
            g_assert(strncmp(dup, input, l) == 0);
            g_assert(strlen(dup) <= l);
            if (l < 10)
                g_assert(!dup_free);
            else
                g_assert(dup == dup_free);
            if (strlen(input) < l)
                g_assert(nm_utils_memeqzero(&dup[strlen(input)], l - strlen(input)));
        }
    }
}

/*****************************************************************************/

static void
test_nm_ip4_addr_is_localhost(void)
{
    g_assert(nm_ip4_addr_is_localhost(nmtst_inet4_from_string("127.0.0.0")));
    g_assert(nm_ip4_addr_is_localhost(nmtst_inet4_from_string("127.0.0.1")));
    g_assert(nm_ip4_addr_is_localhost(nmtst_inet4_from_string("127.5.0.1")));
    g_assert(!nm_ip4_addr_is_localhost(nmtst_inet4_from_string("126.5.0.1")));
    g_assert(!nm_ip4_addr_is_localhost(nmtst_inet4_from_string("128.5.0.1")));
    g_assert(!nm_ip4_addr_is_localhost(nmtst_inet4_from_string("129.5.0.1")));
}

/*****************************************************************************/

static void
test_unaligned(void)
{
    int shift;

    for (shift = 0; shift <= 32; shift++) {
        guint8 buf[100] = {};
        guint8 val      = 0;

        while (val == 0)
            val = nmtst_get_rand_uint32() % 256;

        buf[shift] = val;

        g_assert_cmpint(unaligned_read_le64(&buf[shift]), ==, (guint64) val);
        g_assert_cmpint(unaligned_read_be64(&buf[shift]), ==, ((guint64) val) << 56);
        g_assert_cmpint(unaligned_read_ne64(&buf[shift]), !=, 0);

        g_assert_cmpint(unaligned_read_le32(&buf[shift]), ==, (guint32) val);
        g_assert_cmpint(unaligned_read_be32(&buf[shift]), ==, ((guint32) val) << 24);
        g_assert_cmpint(unaligned_read_ne32(&buf[shift]), !=, 0);

        g_assert_cmpint(unaligned_read_le16(&buf[shift]), ==, (guint16) val);
        g_assert_cmpint(unaligned_read_be16(&buf[shift]), ==, ((guint16) val) << 8);
        g_assert_cmpint(unaligned_read_ne16(&buf[shift]), !=, 0);
    }
}

/*****************************************************************************/

static void
_strv_cmp_fuzz_input(const char *const * in,
                     gssize              l,
                     const char ***      out_strv_free_shallow,
                     char ***            out_strv_free_deep,
                     const char *const **out_s1,
                     const char *const **out_s2)
{
    const char **strv;
    gsize        i;

    /* Fuzz the input argument. It will return two output arrays that are semantically
     * equal the input. */

    if (nmtst_get_rand_bool()) {
        char **ss;

        if (l < 0)
            ss = g_strdupv((char **) in);
        else if (l == 0) {
            ss = nmtst_get_rand_bool() ? NULL : g_new0(char *, 1);
        } else {
            ss = nm_memdup(in, sizeof(const char *) * l);
            for (i = 0; i < (gsize) l; i++)
                ss[i] = g_strdup(ss[i]);
        }
        strv                = (const char **) ss;
        *out_strv_free_deep = ss;
    } else {
        if (l < 0) {
            strv = in ? nm_memdup(in, sizeof(const char *) * (NM_PTRARRAY_LEN(in) + 1)) : NULL;
        } else if (l == 0) {
            strv = nmtst_get_rand_bool() ? NULL : g_new0(const char *, 1);
        } else
            strv = nm_memdup(in, sizeof(const char *) * l);
        *out_strv_free_shallow = strv;
    }

    *out_s1 = in;
    *out_s2 = strv;

    if (nmtst_get_rand_bool()) {
        /* randomly swap the original and the clone. That means, out_s1 is either
         * the input argument (as-is) or the sementically equal clone. */
        NM_SWAP(out_s1, out_s2);
    }
    if (nmtst_get_rand_bool()) {
        /* randomly make s1 and s2 the same. This is for testing that
         * comparing two identical pointers yields the same result. */
        *out_s2 = *out_s1;
    }
}

static void
_strv_cmp_free_deep(char **strv, gssize len)
{
    gssize i;

    if (strv) {
        if (len < 0)
            g_strfreev(strv);
        else {
            for (i = 0; i < len; i++)
                g_free(strv[i]);
            g_free(strv);
        }
    }
}

static void
test_strv_cmp(void)
{
    const char *const strv0[1] = {};
    const char *const strv1[2] = {
        "",
    };

#define _STRV_CMP(a1, l1, a2, l2, equal)                                                            \
    G_STMT_START                                                                                    \
    {                                                                                               \
        gssize               _l1 = (l1);                                                            \
        gssize               _l2 = (l2);                                                            \
        const char *const *  _a1;                                                                   \
        const char *const *  _a2;                                                                   \
        const char *const *  _a1x;                                                                  \
        const char *const *  _a2x;                                                                  \
        char **              _a1_free_deep    = NULL;                                               \
        char **              _a2_free_deep    = NULL;                                               \
        gs_free const char **_a1_free_shallow = NULL;                                               \
        gs_free const char **_a2_free_shallow = NULL;                                               \
        int                  _c1, _c2;                                                              \
                                                                                                    \
        _strv_cmp_fuzz_input((a1), _l1, &_a1_free_shallow, &_a1_free_deep, &_a1, &_a1x);            \
        _strv_cmp_fuzz_input((a2), _l2, &_a2_free_shallow, &_a2_free_deep, &_a2, &_a2x);            \
                                                                                                    \
        _c1 = nm_utils_strv_cmp_n(_a1, _l1, _a2, _l2);                                              \
        _c2 = nm_utils_strv_cmp_n(_a2, _l2, _a1, _l1);                                              \
        if (equal) {                                                                                \
            g_assert_cmpint(_c1, ==, 0);                                                            \
            g_assert_cmpint(_c2, ==, 0);                                                            \
        } else {                                                                                    \
            g_assert_cmpint(_c1, ==, -1);                                                           \
            g_assert_cmpint(_c2, ==, 1);                                                            \
        }                                                                                           \
                                                                                                    \
        /* Compare with self. _strv_cmp_fuzz_input() randomly swapped the arguments (_a1 and _a1x).
         * Either way, the arrays must compare equal to their semantically equal alternative. */ \
        g_assert_cmpint(nm_utils_strv_cmp_n(_a1, _l1, _a1x, _l1), ==, 0);                           \
        g_assert_cmpint(nm_utils_strv_cmp_n(_a2, _l2, _a2x, _l2), ==, 0);                           \
                                                                                                    \
        _strv_cmp_free_deep(_a1_free_deep, _l1);                                                    \
        _strv_cmp_free_deep(_a2_free_deep, _l2);                                                    \
    }                                                                                               \
    G_STMT_END

    _STRV_CMP(NULL, -1, NULL, -1, TRUE);

    _STRV_CMP(NULL, -1, NULL, 0, FALSE);
    _STRV_CMP(NULL, -1, strv0, 0, FALSE);
    _STRV_CMP(NULL, -1, strv0, -1, FALSE);

    _STRV_CMP(NULL, 0, NULL, 0, TRUE);
    _STRV_CMP(NULL, 0, strv0, 0, TRUE);
    _STRV_CMP(NULL, 0, strv0, -1, TRUE);
    _STRV_CMP(strv0, 0, strv0, 0, TRUE);
    _STRV_CMP(strv0, 0, strv0, -1, TRUE);
    _STRV_CMP(strv0, -1, strv0, -1, TRUE);

    _STRV_CMP(NULL, 0, strv1, -1, FALSE);
    _STRV_CMP(NULL, 0, strv1, 1, FALSE);
    _STRV_CMP(strv0, 0, strv1, -1, FALSE);
    _STRV_CMP(strv0, 0, strv1, 1, FALSE);
    _STRV_CMP(strv0, -1, strv1, -1, FALSE);
    _STRV_CMP(strv0, -1, strv1, 1, FALSE);

    _STRV_CMP(strv1, -1, strv1, 1, TRUE);
    _STRV_CMP(strv1, 1, strv1, 1, TRUE);
}

/*****************************************************************************/

static void
_do_strstrip_avoid_copy(const char *str)
{
    gs_free char *str1 = g_strdup(str);
    gs_free char *str2 = g_strdup(str);
    gs_free char *str3 = NULL;
    gs_free char *str4 = NULL;
    const char *  s3;
    const char *  s4;

    if (str1)
        g_strstrip(str1);

    nm_strstrip(str2);

    g_assert_cmpstr(str1, ==, str2);

    s3 = nm_strstrip_avoid_copy(str, &str3);
    g_assert_cmpstr(str1, ==, s3);

    s4 = nm_strstrip_avoid_copy_a(10, str, &str4);
    g_assert_cmpstr(str1, ==, s4);
    g_assert(!str == !s4);
    g_assert(!s4 || strlen(s4) <= strlen(str));
    if (s4 && s4 == &str[strlen(str) - strlen(s4)]) {
        g_assert(!str4);
        g_assert(s3 == s4);
    } else if (s4 && strlen(s4) >= 10) {
        g_assert(str4);
        g_assert(s4 == str4);
    } else
        g_assert(!str4);

    if (!nm_streq0(str1, str))
        _do_strstrip_avoid_copy(str1);
}

static void
test_strstrip_avoid_copy(void)
{
    _do_strstrip_avoid_copy(NULL);
    _do_strstrip_avoid_copy("");
    _do_strstrip_avoid_copy(" ");
    _do_strstrip_avoid_copy(" a ");
    _do_strstrip_avoid_copy(" 012345678 ");
    _do_strstrip_avoid_copy(" 0123456789 ");
    _do_strstrip_avoid_copy(" 01234567890 ");
    _do_strstrip_avoid_copy(" 012345678901 ");
}

/*****************************************************************************/

static void
test_nm_utils_bin2hexstr(void)
{
    int n_run;

    for (n_run = 0; n_run < 500; n_run++) {
        guint8   buf[100];
        guint8   buf2[G_N_ELEMENTS(buf) + 1];
        gsize    len = nmtst_get_rand_uint32() % (G_N_ELEMENTS(buf) + 1);
        char     strbuf1[G_N_ELEMENTS(buf) * 3];
        gboolean allocate   = nmtst_get_rand_bool();
        char     delimiter  = nmtst_get_rand_bool() ? ':' : '\0';
        gboolean upper_case = nmtst_get_rand_bool();
        gboolean hexdigit_pairs_mangled;
        gsize    expected_strlen;
        char *   str_hex;
        gsize    required_len;
        gboolean outlen_set;
        gsize    outlen;
        guint8 * bin2;
        guint    i, j;

        nmtst_rand_buf(NULL, buf, len);

        if (len == 0)
            expected_strlen = 0;
        else if (delimiter != '\0')
            expected_strlen = (len * 3u) - 1;
        else
            expected_strlen = len * 2u;

        g_assert_cmpint(expected_strlen, <, G_N_ELEMENTS(strbuf1));

        str_hex =
            nm_utils_bin2hexstr_full(buf, len, delimiter, upper_case, !allocate ? strbuf1 : NULL);

        g_assert(str_hex);
        if (!allocate)
            g_assert(str_hex == strbuf1);
        g_assert_cmpint(strlen(str_hex), ==, expected_strlen);

        g_assert(NM_STRCHAR_ALL(
            str_hex,
            ch,
            (ch >= '0' && ch <= '9') || ch == delimiter
                || (upper_case ? (ch >= 'A' && ch <= 'F') : (ch >= 'a' && ch <= 'f'))));

        hexdigit_pairs_mangled = FALSE;
        if (delimiter && len > 1 && nmtst_get_rand_bool()) {
            /* randomly convert "0?" sequences to single digits, so we can get hexdigit_pairs_required
             * parameter. */
            g_assert(strlen(str_hex) >= 5);
            g_assert(str_hex[2] == delimiter);
            i = 0;
            j = 0;
            for (;;) {
                g_assert(g_ascii_isxdigit(str_hex[i]));
                g_assert(g_ascii_isxdigit(str_hex[i + 1]));
                g_assert(NM_IN_SET(str_hex[i + 2], delimiter, '\0'));
                if (str_hex[i] == '0' && nmtst_get_rand_bool()) {
                    i++;
                    str_hex[j++]           = str_hex[i++];
                    hexdigit_pairs_mangled = TRUE;
                } else {
                    str_hex[j++] = str_hex[i++];
                    str_hex[j++] = str_hex[i++];
                }
                if (str_hex[i] == '\0') {
                    str_hex[j] = '\0';
                    break;
                }
                g_assert(str_hex[i] == delimiter);
                str_hex[j++] = str_hex[i++];
            }
        }

        required_len = nmtst_get_rand_bool() ? len : 0u;

        outlen_set = required_len == 0 || nmtst_get_rand_bool();

        memset(buf2, 0, sizeof(buf2));

        bin2 = nm_utils_hexstr2bin_full(str_hex,
                                        nmtst_get_rand_bool(),
                                        delimiter != '\0' && nmtst_get_rand_bool(),
                                        !hexdigit_pairs_mangled && nmtst_get_rand_bool(),
                                        delimiter != '\0'
                                            ? nmtst_rand_select((const char *) ":", ":-")
                                            : nmtst_rand_select((const char *) ":", ":-", "", NULL),
                                        required_len,
                                        buf2,
                                        len,
                                        outlen_set ? &outlen : NULL);
        if (len > 0) {
            g_assert(bin2);
            g_assert(bin2 == buf2);
        } else
            g_assert(!bin2);

        if (outlen_set)
            g_assert_cmpint(outlen, ==, len);

        g_assert_cmpmem(buf, len, buf2, len);

        g_assert(buf2[len] == '\0');

        if (hexdigit_pairs_mangled) {
            /* we mangled the hexstr to contain single digits. Trying to parse with
             * hexdigit_pairs_required must now fail. */
            bin2 = nm_utils_hexstr2bin_full(
                str_hex,
                nmtst_get_rand_bool(),
                delimiter != '\0' && nmtst_get_rand_bool(),
                TRUE,
                delimiter != '\0' ? nmtst_rand_select((const char *) ":", ":-")
                                  : nmtst_rand_select((const char *) ":", ":-", "", NULL),
                required_len,
                buf2,
                len,
                outlen_set ? &outlen : NULL);
            g_assert(!bin2);
        }

        if (allocate)
            g_free(str_hex);
    }
}

/*****************************************************************************/

static void
test_nm_ref_string(void)
{
    nm_auto_ref_string NMRefString *s1 = NULL;
    NMRefString *                   s2;

    g_assert(NULL == NM_REF_STRING_UPCAST(NULL));

    s1 = nm_ref_string_new("hallo");
    g_assert(s1);
    g_assert_cmpstr(s1->str, ==, "hallo");
    g_assert_cmpint(s1->len, ==, strlen("hallo"));
    g_assert(s1 == NM_REF_STRING_UPCAST(s1->str));

    s2 = nm_ref_string_new("hallo");
    g_assert(s2 == s1);
    nm_ref_string_unref(s2);

    s2 = nm_ref_string_new(NULL);
    g_assert(!s2);
    nm_ref_string_unref(s2);

#define STR_WITH_NUL "hallo\0test\0"
    s2 = nm_ref_string_new_len(STR_WITH_NUL, NM_STRLEN(STR_WITH_NUL));
    g_assert(s2);
    g_assert_cmpstr(s2->str, ==, "hallo");
    g_assert_cmpint(s2->len, ==, NM_STRLEN(STR_WITH_NUL));
    g_assert_cmpint(s2->len, >, strlen(s2->str));
    g_assert_cmpmem(s2->str, s2->len, STR_WITH_NUL, NM_STRLEN(STR_WITH_NUL));
    g_assert(s2->str[s2->len] == '\0');
    nm_ref_string_unref(s2);
}

/*****************************************************************************/

static NM_UTILS_STRING_TABLE_LOOKUP_DEFINE(
    _do_string_table_lookup,
    int,
    { ; },
    { return -1; },
    {"0", 0},
    {"1", 1},
    {"2", 2},
    {"3", 3}, );

static void
test_string_table_lookup(void)
{
    const char *const args[] = {
        NULL,
        "0",
        "1",
        "2",
        "3",
        "x",
    };
    int i;

    for (i = 0; i < G_N_ELEMENTS(args); i++) {
        const char *needle = args[i];
        const int   val2   = _nm_utils_ascii_str_to_int64(needle, 10, 0, 100, -1);
        int         val;

        val = _do_string_table_lookup(needle);
        g_assert_cmpint(val, ==, val2);
    }
}

/*****************************************************************************/

static void
test_nm_utils_get_next_realloc_size(void)
{
    static const struct {
        gsize requested;
        gsize reserved_true;
        gsize reserved_false;
    } test_data[] = {
        {0, 8, 8},
        {1, 8, 8},
        {8, 8, 8},
        {9, 16, 16},
        {16, 16, 16},
        {17, 32, 32},
        {32, 32, 32},
        {33, 40, 40},
        {40, 40, 40},
        {41, 104, 104},
        {104, 104, 104},
        {105, 232, 232},
        {232, 232, 232},
        {233, 488, 488},
        {488, 488, 488},
        {489, 1000, 1000},
        {1000, 1000, 1000},
        {1001, 2024, 2024},
        {2024, 2024, 2024},
        {2025, 4072, 4072},
        {4072, 4072, 4072},
        {4073, 8168, 8168},
        {8168, 8168, 8168},
        {8169, 12264, 16360},
        {12263, 12264, 16360},
        {12264, 12264, 16360},
        {12265, 16360, 16360},
        {16360, 16360, 16360},
        {16361, 20456, 32744},
        {20456, 20456, 32744},
        {20457, 24552, 32744},
        {24552, 24552, 32744},
        {24553, 28648, 32744},
        {28648, 28648, 32744},
        {28649, 32744, 32744},
        {32744, 32744, 32744},
        {32745, 36840, 65512},
        {36840, 36840, 65512},
        {G_MAXSIZE - 0x1000u, G_MAXSIZE, G_MAXSIZE},
        {G_MAXSIZE - 25u, G_MAXSIZE, G_MAXSIZE},
        {G_MAXSIZE - 24u, G_MAXSIZE, G_MAXSIZE},
        {G_MAXSIZE - 1u, G_MAXSIZE, G_MAXSIZE},
        {G_MAXSIZE, G_MAXSIZE, G_MAXSIZE},
        {NM_UTILS_GET_NEXT_REALLOC_SIZE_32,
         NM_UTILS_GET_NEXT_REALLOC_SIZE_32,
         NM_UTILS_GET_NEXT_REALLOC_SIZE_32},
        {NM_UTILS_GET_NEXT_REALLOC_SIZE_40,
         NM_UTILS_GET_NEXT_REALLOC_SIZE_40,
         NM_UTILS_GET_NEXT_REALLOC_SIZE_40},
        {NM_UTILS_GET_NEXT_REALLOC_SIZE_104,
         NM_UTILS_GET_NEXT_REALLOC_SIZE_104,
         NM_UTILS_GET_NEXT_REALLOC_SIZE_104},
        {NM_UTILS_GET_NEXT_REALLOC_SIZE_1000,
         NM_UTILS_GET_NEXT_REALLOC_SIZE_1000,
         NM_UTILS_GET_NEXT_REALLOC_SIZE_1000},
    };
    guint i;

    G_STATIC_ASSERT_EXPR(NM_UTILS_GET_NEXT_REALLOC_SIZE_104 == 104u);
    G_STATIC_ASSERT_EXPR(NM_UTILS_GET_NEXT_REALLOC_SIZE_1000 == 1000u);

    for (i = 0; i < G_N_ELEMENTS(test_data) + 5000u; i++) {
        gsize requested0;

        if (i < G_N_ELEMENTS(test_data))
            requested0 = test_data[i].requested;
        else {
            /* find some interesting random values for testing. */
            switch (nmtst_get_rand_uint32() % 5) {
            case 0:
                requested0 = nmtst_get_rand_size();
                break;
            case 1:
                /* values close to G_MAXSIZE. */
                requested0 = G_MAXSIZE - (nmtst_get_rand_uint32() % 12000u);
                break;
            case 2:
                /* values around G_MAXSIZE/2. */
                requested0 = (G_MAXSIZE / 2u) + 6000u - (nmtst_get_rand_uint32() % 12000u);
                break;
            case 3:
                /* values around powers of 2. */
                requested0 = (((gsize) 1) << (nmtst_get_rand_uint32() % (sizeof(gsize) * 8u)))
                             + 6000u - (nmtst_get_rand_uint32() % 12000u);
                break;
            case 4:
                /* values around 4k borders. */
                requested0 = (nmtst_get_rand_size() & ~((gsize) 0xFFFu)) + 30u
                             - (nmtst_get_rand_uint32() % 60u);
                break;
            default:
                g_assert_not_reached();
            }
        }

        {
            const gsize requested = requested0;
            gsize       reserved_true;
            gsize       reserved_false;
            bool        truncated_true  = FALSE;
            bool        truncated_false = FALSE;

            if (sizeof(gsize) > 4 && requested > SIZE_MAX / 2u - 24u) {
                reserved_false  = G_MAXSSIZE;
                truncated_false = TRUE;
            } else
                reserved_false = nm_utils_get_next_realloc_size(FALSE, requested);

            if (sizeof(gsize) > 4 && requested > SIZE_MAX - 0x1000u - 24u) {
                reserved_true  = G_MAXSSIZE;
                truncated_true = TRUE;
            } else
                reserved_true = nm_utils_get_next_realloc_size(TRUE, requested);

            g_assert_cmpuint(reserved_true, >, 0);
            g_assert_cmpuint(reserved_false, >, 0);
            if (!truncated_true)
                g_assert_cmpuint(reserved_true, >=, requested);
            if (!truncated_false)
                g_assert_cmpuint(reserved_false, >=, requested);
            if (!truncated_true && !truncated_false)
                g_assert_cmpuint(reserved_false, >=, reserved_true);

            if (i < G_N_ELEMENTS(test_data)) {
                if (!truncated_true)
                    g_assert_cmpuint(reserved_true, ==, test_data[i].reserved_true);
                if (!truncated_false)
                    g_assert_cmpuint(reserved_false, ==, test_data[i].reserved_false);
            }

            /* reserved_false is generally the next power of two - 24. */
            if (reserved_false == G_MAXSIZE)
                g_assert_cmpuint(requested, >, G_MAXSIZE / 2u - 24u);
            else if (!reserved_false) {
                g_assert_cmpuint(reserved_false, <=, G_MAXSIZE - 24u);
                if (reserved_false >= 40) {
                    const gsize _pow2 = reserved_false + 24u;

                    /* reserved_false must always be a power of two minus 24. */
                    g_assert_cmpuint(_pow2, >=, 64u);
                    g_assert_cmpuint(_pow2, >, requested);
                    g_assert(nm_utils_is_power_of_two(_pow2));

                    /* but _pow2/2 must also be smaller than what we requested. */
                    g_assert_cmpuint(_pow2 / 2u - 24u, <, requested);
                } else {
                    /* smaller values are hard-coded. */
                }
            }

            /* reserved_true is generally the next 4k border - 24. */
            if (reserved_true == G_MAXSIZE)
                g_assert_cmpuint(requested, >, G_MAXSIZE - 0x1000u - 24u);
            else if (!truncated_true) {
                g_assert_cmpuint(reserved_true, <=, G_MAXSIZE - 24u);
                if (reserved_true > 8168u) {
                    const gsize page_border = reserved_true + 24u;

                    /* reserved_true must always be aligned to 4k (minus 24). */
                    g_assert_cmpuint(page_border % 0x1000u, ==, 0);
                    if (requested > 0x1000u - 24u) {
                        /* page_border not be more than 4k above requested. */
                        g_assert_cmpuint(page_border, >=, 0x1000u - 24u);
                        g_assert_cmpuint(page_border - 0x1000u - 24u, <, requested);
                    }
                } else {
                    /* for smaller sizes, reserved_true and reserved_false are the same. */
                    g_assert_cmpuint(reserved_true, ==, reserved_false);
                }
            }
        }
    }
}

/*****************************************************************************/

static void
test_nm_str_buf(void)
{
    guint i_run;

    for (i_run = 0; TRUE; i_run++) {
        nm_auto_str_buf NMStrBuf strbuf    = {};
        nm_auto_free_gstring GString *gstr = NULL;
        int                           i, j, k;
        int                           c;

        nm_str_buf_init(&strbuf, nmtst_get_rand_uint32() % 200u + 1u, nmtst_get_rand_bool());

        if (i_run < 1000) {
            c = nmtst_get_rand_word_length(NULL);
            for (i = 0; i < c; i++)
                nm_str_buf_append_c(&strbuf, '0' + (i % 10));
            gstr = g_string_new(nm_str_buf_get_str(&strbuf));
            j    = nmtst_get_rand_uint32() % (strbuf.len + 1);
            k    = nmtst_get_rand_uint32() % (strbuf.len - j + 2) - 1;

            nm_str_buf_erase(&strbuf, j, k, nmtst_get_rand_bool());
            g_string_erase(gstr, j, k);
            g_assert_cmpstr(gstr->str, ==, nm_str_buf_get_str(&strbuf));
        } else
            return;
    }
}

/*****************************************************************************/

static void
test_nm_utils_parse_next_line(void)
{
    const char *data;
    const char *data0;
    gsize       data_len;
    const char *line_start;
    gsize       line_len;
    int         i_run;
    gsize       j, k;

    data     = NULL;
    data_len = 0;
    g_assert(!nm_utils_parse_next_line(&data, &data_len, &line_start, &line_len));

    for (i_run = 0; i_run < 1000; i_run++) {
        gs_unref_ptrarray GPtrArray *strv     = g_ptr_array_new_with_free_func(g_free);
        gs_unref_ptrarray GPtrArray *strv2    = g_ptr_array_new_with_free_func(g_free);
        gsize                        strv_len = nmtst_get_rand_word_length(NULL);
        nm_auto_str_buf NMStrBuf     strbuf   = NM_STR_BUF_INIT(0, nmtst_get_rand_bool());

        /* create a list of random words. */
        for (j = 0; j < strv_len; j++) {
            gsize    w_len = nmtst_get_rand_word_length(NULL);
            NMStrBuf w_buf =
                NM_STR_BUF_INIT(nmtst_get_rand_uint32() % (w_len + 1), nmtst_get_rand_bool());

            for (k = 0; k < w_len; k++)
                nm_str_buf_append_c(&w_buf, '0' + (k % 10));
            nm_str_buf_maybe_expand(&w_buf, 1, TRUE);
            g_ptr_array_add(strv, nm_str_buf_finalize(&w_buf, NULL));
        }

        /* join the list of random words with (random) line delimiters
         * ("\0", "\n", "\r" or EOF). */
        for (j = 0; j < strv_len; j++) {
            nm_str_buf_append(&strbuf, strv->pdata[j]);
again:
            switch (nmtst_get_rand_uint32() % 5) {
            case 0:
                nm_str_buf_append_c(&strbuf, '\0');
                break;
            case 1:
                if (strbuf.len > 0
                    && (nm_str_buf_get_str_unsafe(&strbuf))[strbuf.len - 1] == '\r') {
                    /* the previous line was empty and terminated by "\r". We
                     * must not join with "\n". Retry. */
                    goto again;
                }
                nm_str_buf_append_c(&strbuf, '\n');
                break;
            case 2:
                nm_str_buf_append_c(&strbuf, '\r');
                break;
            case 3:
                nm_str_buf_append(&strbuf, "\r\n");
                break;
            case 4:
                /* the last word randomly is delimited or not, but not if the last
                 * word is "". */
                if (j + 1 < strv_len) {
                    /* it's not the last word. Retry. */
                    goto again;
                }
                g_assert(j == strv_len - 1);
                if (((const char *) strv->pdata[j])[0] == '\0') {
                    /* if the last word was "", we need a delimiter (to parse it back).
                     * Retry. */
                    goto again;
                }
                /* The final delimiter gets omitted. It's EOF. */
                break;
            }
        }

        data0 = nm_str_buf_get_str_unsafe(&strbuf);
        if (!data0 && nmtst_get_rand_bool()) {
            nm_str_buf_maybe_expand(&strbuf, 1, TRUE);
            data0 = nm_str_buf_get_str_unsafe(&strbuf);
            g_assert(data0);
        }
        data_len = strbuf.len;
        g_assert((data_len > 0 && data0) || data_len == 0);
        data = data0;
        while (nm_utils_parse_next_line(&data, &data_len, &line_start, &line_len)) {
            g_assert(line_start);
            g_assert(line_start >= data0);
            g_assert(line_start < &data0[strbuf.len]);
            g_assert(!memchr(line_start, '\0', line_len));
            g_ptr_array_add(strv2, g_strndup(line_start, line_len));
        }
        g_assert(data_len == 0);
        if (data0)
            g_assert(data == &data0[strbuf.len]);
        else
            g_assert(!data);

        g_assert(nm_utils_strv_cmp_n((const char *const *) strv->pdata,
                                     strv->len,
                                     (const char *const *) strv2->pdata,
                                     strv2->len)
                 == 0);
    }
}

/*****************************************************************************/

static void
test_in_strset_ascii_case(void)
{
    const char *x;

    x = NULL;
    g_assert(NM_IN_STRSET_ASCII_CASE(x, NULL));
    g_assert(NM_IN_STRSET_ASCII_CASE(x, NULL, "b"));
    g_assert(!NM_IN_STRSET_ASCII_CASE(x, "b"));

    x = "b";
    g_assert(NM_IN_STRSET(x, "b"));
    g_assert(NM_IN_STRSET_ASCII_CASE(x, "b"));
    g_assert(!NM_IN_STRSET(x, "B"));
    g_assert(NM_IN_STRSET_ASCII_CASE(x, "B"));
}

/*****************************************************************************/

static void
test_is_specific_hostname(void)
{
    g_assert(!nm_utils_is_specific_hostname(NULL));
    g_assert(!nm_utils_is_specific_hostname(""));
    g_assert(!nm_utils_is_specific_hostname("(none)"));
    g_assert(nm_utils_is_specific_hostname("(NONE)"));

    g_assert(!nm_utils_is_specific_hostname("localhost"));
    g_assert(!nm_utils_is_specific_hostname("lOcalHost"));
    g_assert(!nm_utils_is_specific_hostname("LOCALHOST"));

    g_assert(!nm_utils_is_specific_hostname("LOCALHOST.localdomain"));

    g_assert(nm_utils_is_specific_hostname("xlocalhost"));
    g_assert(nm_utils_is_specific_hostname("lOcalHxost"));
    g_assert(nm_utils_is_specific_hostname("LOCALxHOST"));

    g_assert(!nm_utils_is_specific_hostname("foo.LOCALHOST"));
    g_assert(!nm_utils_is_specific_hostname("foo.LOCALHOsT6."));
    g_assert(!nm_utils_is_specific_hostname("foo.LOCALHOsT6.localdomain6"));
    g_assert(!nm_utils_is_specific_hostname(".LOCALHOsT6.localdomain6"));
    g_assert(!nm_utils_is_specific_hostname("LOCALHOsT6.localdomain6"));
    g_assert(!nm_utils_is_specific_hostname("LOCALHOsT6.localdomain6."));
    g_assert(nm_utils_is_specific_hostname("LOCALHOsT6.localdomain."));

    g_assert(nm_utils_is_specific_hostname(" "));
}

/*****************************************************************************/

static void
test_strv_dup_packed(void)
{
    gs_unref_ptrarray GPtrArray *src = NULL;
    int                          i_run;

    src = g_ptr_array_new_with_free_func(g_free);

    for (i_run = 0; i_run < 500; i_run++) {
        const int            strv_len = nmtst_get_rand_word_length(NULL);
        gs_free const char **strv_cpy = NULL;
        const char *const *  strv_src;
        int                  i, j;

        g_ptr_array_set_size(src, 0);
        for (i = 0; i < strv_len; i++) {
            const int word_len = nmtst_get_rand_word_length(NULL);
            NMStrBuf  sbuf     = NM_STR_BUF_INIT(0, nmtst_get_rand_bool());

            for (j = 0; j < word_len; j++)
                nm_str_buf_append_c(&sbuf, 'a' + (nmtst_get_rand_uint32() % 20));

            g_ptr_array_add(src, nm_str_buf_finalize(&sbuf, NULL) ?: g_new0(char, 1));
        }
        g_ptr_array_add(src, NULL);

        strv_src = (const char *const *) src->pdata;
        g_assert(strv_src);
        g_assert(NM_PTRARRAY_LEN(strv_src) == strv_len);

        strv_cpy =
            nm_utils_strv_dup_packed(strv_src,
                                     nmtst_get_rand_bool() ? (gssize) strv_len : (gssize) -1);
        if (strv_len == 0)
            g_assert(!strv_cpy);
        else
            g_assert(strv_cpy);
        g_assert(NM_PTRARRAY_LEN(strv_cpy) == strv_len);
        if (strv_cpy)
            g_assert(nm_utils_strv_equal(strv_cpy, strv_src));
    }
}

/*****************************************************************************/

static int
_hash_func_cmp_direct(gconstpointer a, gconstpointer b, gpointer user_data)
{
    NM_CMP_DIRECT(GPOINTER_TO_INT(a), GPOINTER_TO_INT(b));
    return 0;
}

static void
test_utils_hashtable_cmp(void)
{
    static struct {
        int         val_i;
        const char *val_s;
    } vals[] = {
        {
            0,
            "0",
        },
        {
            1,
            "1",
        },
        {
            2,
            "2",
        },
        {
            3,
            "3",
        },
        {
            4,
            "4",
        },
        {
            5,
            "5",
        },
        {
            6,
            "6",
        },
        {
            7,
            "7",
        },
        {
            8,
            "8",
        },
        {
            9,
            "9",
        },
        {
            0,
            "a",
        },
        {
            1,
            "a",
        },
        {
            2,
            "a",
        },
        {
            3,
            "a",
        },
        {
            4,
            "a",
        },
        {
            5,
            "a",
        },
        {
            0,
            "0",
        },
        {
            0,
            "1",
        },
        {
            0,
            "2",
        },
        {
            0,
            "3",
        },
        {
            0,
            "4",
        },
        {
            0,
            "5",
        },
    };
    guint test_run;
    int   is_num_key;

    for (test_run = 0; test_run < 30; test_run++) {
        for (is_num_key = 0; is_num_key < 2; is_num_key++) {
            GHashFunc        func_key_hash  = is_num_key ? nm_direct_hash : nm_str_hash;
            GEqualFunc       func_key_equal = is_num_key ? g_direct_equal : g_str_equal;
            GCompareDataFunc func_key_cmp =
                is_num_key ? _hash_func_cmp_direct : (GCompareDataFunc) nm_strcmp_with_data;
            GCompareDataFunc func_val_cmp =
                !is_num_key ? _hash_func_cmp_direct : (GCompareDataFunc) nm_strcmp_with_data;
            gs_unref_hashtable GHashTable *h1 = NULL;
            gs_unref_hashtable GHashTable *h2 = NULL;
            gboolean                       has_same_keys;
            guint                          i, n;

            h1 = g_hash_table_new(func_key_hash, func_key_equal);
            h2 = g_hash_table_new(func_key_hash, func_key_equal);

            n = nmtst_get_rand_word_length(NULL);
            for (i = 0; i < n; i++) {
                typeof(vals[0]) *v     = &vals[nmtst_get_rand_uint32() % G_N_ELEMENTS(vals)];
                gconstpointer    v_key = is_num_key ? GINT_TO_POINTER(v->val_i) : v->val_s;
                gconstpointer    v_val = !is_num_key ? GINT_TO_POINTER(v->val_i) : v->val_s;

                g_hash_table_insert(h1, (gpointer) v_key, (gpointer) v_val);
                g_hash_table_insert(h2, (gpointer) v_key, (gpointer) v_val);
            }

            g_assert(nm_utils_hashtable_same_keys(h1, h2));
            g_assert(nm_utils_hashtable_cmp_equal(h1, h2, NULL, NULL));
            g_assert(nm_utils_hashtable_cmp_equal(h1, h2, func_val_cmp, NULL));
            g_assert(nm_utils_hashtable_cmp(h1, h2, FALSE, func_key_cmp, NULL, NULL) == 0);
            g_assert(nm_utils_hashtable_cmp(h1, h2, TRUE, func_key_cmp, NULL, NULL) == 0);
            g_assert(nm_utils_hashtable_cmp(h1, h2, FALSE, func_key_cmp, func_val_cmp, NULL) == 0);
            g_assert(nm_utils_hashtable_cmp(h1, h2, TRUE, func_key_cmp, func_val_cmp, NULL) == 0);

            n             = nmtst_get_rand_word_length(NULL) + 1;
            has_same_keys = TRUE;
            for (i = 0; i < n; i++) {
again:
{
    typeof(vals[0]) *v     = &vals[nmtst_get_rand_uint32() % G_N_ELEMENTS(vals)];
    gconstpointer    v_key = is_num_key ? GINT_TO_POINTER(v->val_i) : v->val_s;
    gconstpointer    v_val = !is_num_key ? GINT_TO_POINTER(v->val_i) : v->val_s;
    gpointer         v_key2;
    gpointer         v_val2;

    if (g_hash_table_lookup_extended(h1, v_key, &v_key2, &v_val2)) {
        g_assert(func_key_cmp(v_key, v_key2, NULL) == 0);
        if (func_val_cmp(v_val, v_val2, NULL) == 0)
            goto again;
    } else
        has_same_keys = FALSE;

    g_hash_table_insert(h2, (gpointer) v_key, (gpointer) v_val);
}
            }

            if (has_same_keys) {
                g_assert(nm_utils_hashtable_same_keys(h1, h2));
                g_assert(nm_utils_hashtable_cmp_equal(h1, h2, NULL, NULL));
                g_assert(nm_utils_hashtable_cmp(h1, h2, FALSE, func_key_cmp, NULL, NULL) == 0);
                g_assert(nm_utils_hashtable_cmp(h1, h2, TRUE, func_key_cmp, NULL, NULL) == 0);
            } else {
                g_assert(!nm_utils_hashtable_same_keys(h1, h2));
                g_assert(!nm_utils_hashtable_cmp_equal(h1, h2, NULL, NULL));
                g_assert(nm_utils_hashtable_cmp(h1, h2, FALSE, func_key_cmp, NULL, NULL) != 0);
                g_assert(nm_utils_hashtable_cmp(h1, h2, TRUE, func_key_cmp, NULL, NULL) != 0);
            }
            g_assert(!nm_utils_hashtable_cmp_equal(h1, h2, func_val_cmp, NULL));
            g_assert(nm_utils_hashtable_cmp(h1, h2, FALSE, func_key_cmp, func_val_cmp, NULL) != 0);
            g_assert(nm_utils_hashtable_cmp(h1, h2, TRUE, func_key_cmp, func_val_cmp, NULL) != 0);
        }
    }
}

/*****************************************************************************/

NMTST_DEFINE();

int
main(int argc, char **argv)
{
    nmtst_init(&argc, &argv, TRUE);

    g_test_add_func("/general/test_gpid", test_gpid);
    g_test_add_func("/general/test_monotonic_timestamp", test_monotonic_timestamp);
    g_test_add_func("/general/test_nmhash", test_nmhash);
    g_test_add_func("/general/test_nm_make_strv", test_make_strv);
    g_test_add_func("/general/test_nm_strdup_int", test_nm_strdup_int);
    g_test_add_func("/general/test_nm_strndup_a", test_nm_strndup_a);
    g_test_add_func("/general/test_nm_ip4_addr_is_localhost", test_nm_ip4_addr_is_localhost);
    g_test_add_func("/general/test_unaligned", test_unaligned);
    g_test_add_func("/general/test_strv_cmp", test_strv_cmp);
    g_test_add_func("/general/test_strstrip_avoid_copy", test_strstrip_avoid_copy);
    g_test_add_func("/general/test_nm_utils_bin2hexstr", test_nm_utils_bin2hexstr);
    g_test_add_func("/general/test_nm_ref_string", test_nm_ref_string);
    g_test_add_func("/general/test_string_table_lookup", test_string_table_lookup);
    g_test_add_func("/general/test_nm_utils_get_next_realloc_size",
                    test_nm_utils_get_next_realloc_size);
    g_test_add_func("/general/test_nm_str_buf", test_nm_str_buf);
    g_test_add_func("/general/test_nm_utils_parse_next_line", test_nm_utils_parse_next_line);
    g_test_add_func("/general/test_in_strset_ascii_case", test_in_strset_ascii_case);
    g_test_add_func("/general/test_is_specific_hostname", test_is_specific_hostname);
    g_test_add_func("/general/test_strv_dup_packed", test_strv_dup_packed);
    g_test_add_func("/general/test_utils_hashtable_cmp", test_utils_hashtable_cmp);

    return g_test_run();
}
