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
#include "libnm-glib-aux/nm-io-utils.h"
#include "libnm-glib-aux/nm-prioq.h"

#include "libnm-glib-aux/nm-test-utils.h"

/*****************************************************************************/

G_STATIC_ASSERT(NM_AF_UNSPEC == AF_UNSPEC);
G_STATIC_ASSERT(NM_AF_INET == AF_INET);
G_STATIC_ASSERT(NM_AF_INET6 == AF_INET6);

G_STATIC_ASSERT(NM_AF_INET_SIZE == sizeof(in_addr_t));
G_STATIC_ASSERT(NM_AF_INET_SIZE == sizeof(struct in_addr));
G_STATIC_ASSERT(NM_AF_INET6_SIZE == sizeof(struct in6_addr));

G_STATIC_ASSERT(_nm_alignof(in_addr_t) <= _nm_alignof(NMIPAddr));
G_STATIC_ASSERT(_nm_alignof(struct in_addr) <= _nm_alignof(NMIPAddr));
G_STATIC_ASSERT(_nm_alignof(struct in6_addr) <= _nm_alignof(NMIPAddr));
G_STATIC_ASSERT(_nm_alignof(NMEtherAddr) <= _nm_alignof(NMIPAddr));

/*****************************************************************************/

static void
test_nm_static_assert(void)
{
    int                                v1[NM_STATIC_ASSERT_EXPR_1(1)];
    typeof(NM_STATIC_ASSERT_EXPR_1(1)) v_int;
    int                               *p_int;

    G_STATIC_ASSERT(sizeof(v1) == sizeof(int));
    G_STATIC_ASSERT(NM_STATIC_ASSERT_EXPR_1(1) == 1);
    G_STATIC_ASSERT(NM_STATIC_ASSERT_EXPR_1(NM_STATIC_ASSERT_EXPR_1(1)) == 1);
    G_STATIC_ASSERT(NM_STATIC_ASSERT_EXPR_1(NM_STATIC_ASSERT_EXPR_1(NM_STATIC_ASSERT_EXPR_1(1)))
                    == 1);

    g_assert(NM_STATIC_ASSERT_EXPR_1(2) == 1);

    p_int = &v_int;
    g_assert(&v_int == p_int);

    (void) NM_STATIC_ASSERT_EXPR_1(2 > 1);

    NM_STATIC_ASSERT_EXPR_VOID(2 > 1);
}

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

    /* also check how assert() works. */
    assert(*int_ptr == 42);
}

/*****************************************************************************/

static void
test_monotonic_timestamp(void)
{
    g_assert(nm_utils_get_monotonic_timestamp_sec() > 0);
}

/*****************************************************************************/

static void
test_timespect_to(void)
{
    struct timespec ts;
    int             i;

    for (i = 0; i < 1000; i++) {
        gint64 t_msec;
        gint64 t_usec;
        gint64 t_nsec;

        nmtst_rand_buf(NULL, &ts, sizeof(ts));
        ts.tv_sec  = llabs(ts.tv_sec % 100000);
        ts.tv_nsec = llabs(ts.tv_nsec % NM_UTILS_NSEC_PER_SEC);

        t_msec = nm_utils_timespec_to_msec(&ts);
        t_usec = nm_utils_timespec_to_usec(&ts);
        t_nsec = nm_utils_timespec_to_nsec(&ts);

        g_assert_cmpint(t_msec, <=, t_usec / 1000);
        g_assert_cmpint(t_msec + 1, >=, t_usec / 1000);

        g_assert_cmpint(t_msec, <=, t_nsec / 1000000);
        g_assert_cmpint(t_msec + 1, >=, t_nsec / 1000000);

        g_assert_cmpint(t_usec, <=, t_nsec / 1000);
        g_assert_cmpint(t_usec + 1, >=, t_nsec / 1000);
    }
}

/*****************************************************************************/

static void
test_nmhash(void)
{
    int rnd;

    nm_random_get_bytes(&rnd, sizeof(rnd));

    g_assert(nm_hash_val(555, 4) != 0);
}

/*****************************************************************************/

static void
test_nm_random(void)
{
    int i_run;

    for (i_run = 0; i_run < 1000; i_run++) {
        guint64 begin;
        guint64 end;
        guint64 m;
        guint64 x;

        m = nmtst_get_rand_uint64();
        m = m >> (nmtst_get_rand_uint32() % 64);

        if (m == 0)
            continue;

        switch (nmtst_get_rand_uint32() % 4) {
        case 0:
            begin = 0;
            break;
        case 1:
            begin = nmtst_get_rand_uint64() % 1000;
            break;
        case 2:
            begin = ((G_MAXUINT64 - m) - 500) + (nmtst_get_rand_uint64() % 1000);
            break;
        default:
            begin = nmtst_get_rand_uint64() % (G_MAXUINT64 - m);
            break;
        }

        end = (begin + m) - 10 + (nmtst_get_rand_uint64() % 5);

        if (begin >= end)
            continue;

        if (begin == 0 && nmtst_get_rand_bool())
            x = nm_random_u64_range(end);
        else
            x = nm_random_u64_range_full(begin, end, nmtst_get_rand_bool());

        g_assert_cmpuint(x, >=, begin);
        g_assert_cmpuint(x, <, end);
    }
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
            const char   *dup;

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
            const char   *dup;

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
test_nm_ip4_addr_is_loopback(void)
{
    g_assert(nm_ip4_addr_is_loopback(nmtst_inet4_from_string("127.0.0.0")));
    g_assert(nm_ip4_addr_is_loopback(nmtst_inet4_from_string("127.0.0.1")));
    g_assert(nm_ip4_addr_is_loopback(nmtst_inet4_from_string("127.5.0.1")));
    g_assert(!nm_ip4_addr_is_loopback(nmtst_inet4_from_string("126.5.0.1")));
    g_assert(!nm_ip4_addr_is_loopback(nmtst_inet4_from_string("128.5.0.1")));
    g_assert(!nm_ip4_addr_is_loopback(nmtst_inet4_from_string("129.5.0.1")));
    g_assert_cmpint(nmtst_inet4_from_string("127.0.0.0"), ==, NM_IPV4LO_NETWORK);
    g_assert_cmpint(nmtst_inet4_from_string("127.0.0.1"), ==, NM_IPV4LO_ADDR1);
    g_assert_cmpint(nmtst_inet4_from_string("255.0.0.0"), ==, NM_IPV4LO_NETMASK);
    g_assert_cmpint(nm_ip4_addr_netmask_to_prefix(NM_IPV4LO_NETMASK), ==, NM_IPV4LO_PREFIXLEN);
}

/*****************************************************************************/

static void
test_nm_ip4_addr_netmask_from_prefix(void)
{
    g_assert_cmpint(nm_ip4_addr_netmask_from_prefix(0), ==, nmtst_inet4_from_string("0.0.0.0"));
    g_assert_cmpint(nm_ip4_addr_netmask_from_prefix(1), ==, nmtst_inet4_from_string("128.0.0.0"));
    g_assert_cmpint(nm_ip4_addr_netmask_from_prefix(2), ==, nmtst_inet4_from_string("192.0.0.0"));
    g_assert_cmpint(nm_ip4_addr_netmask_from_prefix(16),
                    ==,
                    nmtst_inet4_from_string("255.255.0.0"));
    g_assert_cmpint(nm_ip4_addr_netmask_from_prefix(24),
                    ==,
                    nmtst_inet4_from_string("255.255.255.0"));
    g_assert_cmpint(nm_ip4_addr_netmask_from_prefix(30),
                    ==,
                    nmtst_inet4_from_string("255.255.255.252"));
    g_assert_cmpint(nm_ip4_addr_netmask_from_prefix(31),
                    ==,
                    nmtst_inet4_from_string("255.255.255.254"));
    g_assert_cmpint(nm_ip4_addr_netmask_from_prefix(32),
                    ==,
                    nmtst_inet4_from_string("255.255.255.255"));
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
_strv_cmp_fuzz_input(const char *const  *in,
                     gssize              l,
                     const char       ***out_strv_free_shallow,
                     char             ***out_strv_free_deep,
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
        const char *const   *_a1;                                                                   \
        const char *const   *_a2;                                                                   \
        const char *const   *_a1x;                                                                  \
        const char *const   *_a2x;                                                                  \
        char               **_a1_free_deep    = NULL;                                               \
        char               **_a2_free_deep    = NULL;                                               \
        gs_free const char **_a1_free_shallow = NULL;                                               \
        gs_free const char **_a2_free_shallow = NULL;                                               \
        int                  _c1, _c2;                                                              \
                                                                                                    \
        _strv_cmp_fuzz_input((a1), _l1, &_a1_free_shallow, &_a1_free_deep, &_a1, &_a1x);            \
        _strv_cmp_fuzz_input((a2), _l2, &_a2_free_shallow, &_a2_free_deep, &_a2, &_a2x);            \
                                                                                                    \
        _c1 = nm_strv_cmp_n(_a1, _l1, _a2, _l2);                                                    \
        _c2 = nm_strv_cmp_n(_a2, _l2, _a1, _l1);                                                    \
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
        g_assert_cmpint(nm_strv_cmp_n(_a1, _l1, _a1x, _l1), ==, 0);                                 \
        g_assert_cmpint(nm_strv_cmp_n(_a2, _l2, _a2x, _l2), ==, 0);                                 \
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
    const char   *s3;
    const char   *s4;

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
        char    *str_hex;
        gsize    required_len;
        gboolean outlen_set;
        gsize    outlen;
        guint8  *bin2;
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
    NMRefString                    *s2;

    g_assert(NULL == NM_REF_STRING_UPCAST(NULL));
    g_assert(nm_ref_string_equal_str(NULL, NULL));
    g_assert(!nm_ref_string_equal_str(NULL, ""));
    g_assert(!nm_ref_string_equal_str(NULL, "a"));

    s1 = nm_ref_string_new("hallo");
    g_assert(s1);
    g_assert_cmpstr(s1->str, ==, "hallo");
    g_assert_cmpint(s1->len, ==, strlen("hallo"));
    g_assert(s1 == NM_REF_STRING_UPCAST(s1->str));
    g_assert(nm_ref_string_equal_str(s1, "hallo"));
    g_assert(!nm_ref_string_equal_str(s1, "hallox"));
    g_assert(!nm_ref_string_equal_str(s1, "hall"));
    g_assert(!nm_ref_string_equal_str(s1, NULL));

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
    g_assert(!nm_ref_string_equal_str(s2, "hallo"));
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
        {NM_UTILS_GET_NEXT_REALLOC_SIZE_232,
         NM_UTILS_GET_NEXT_REALLOC_SIZE_232,
         NM_UTILS_GET_NEXT_REALLOC_SIZE_232},
        {NM_UTILS_GET_NEXT_REALLOC_SIZE_488,
         NM_UTILS_GET_NEXT_REALLOC_SIZE_488,
         NM_UTILS_GET_NEXT_REALLOC_SIZE_488},
        {NM_UTILS_GET_NEXT_REALLOC_SIZE_1000,
         NM_UTILS_GET_NEXT_REALLOC_SIZE_1000,
         NM_UTILS_GET_NEXT_REALLOC_SIZE_1000},
    };
    guint i;

    G_STATIC_ASSERT_EXPR(NM_UTILS_GET_NEXT_REALLOC_SIZE_32 == 32u);
    G_STATIC_ASSERT_EXPR(NM_UTILS_GET_NEXT_REALLOC_SIZE_40 == 40u);
    G_STATIC_ASSERT_EXPR(NM_UTILS_GET_NEXT_REALLOC_SIZE_104 == 104u);
    G_STATIC_ASSERT_EXPR(NM_UTILS_GET_NEXT_REALLOC_SIZE_232 == 232u);
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

    for (i_run = 0; i_run < 1000; i_run++) {
        char                          stack_buf[1024];
        nm_auto_str_buf NMStrBuf      strbuf;
        nm_auto_free_gstring GString *gstr = NULL;
        int                           i, j, k;
        int                           c;

        switch (nmtst_get_rand_uint32() % 10) {
        case 0:
            memset(&strbuf, 0, sizeof(strbuf));
            break;
        case 1 ... 4:
            strbuf = NM_STR_BUF_INIT_FULL(stack_buf,
                                          0,
                                          nmtst_get_rand_uint32() % sizeof(stack_buf),
                                          FALSE,
                                          nmtst_get_rand_bool());
            break;
        default:
            strbuf = NM_STR_BUF_INIT(nmtst_get_rand_uint32() % 200u + 1u, nmtst_get_rand_bool());
            break;
        }

        c = nmtst_get_rand_word_length(NULL);
        for (i = 0; i < c; i++)
            nm_str_buf_append_c(&strbuf, '0' + (i % 10));
        gstr = g_string_new(nm_str_buf_get_str(&strbuf));
        j    = nmtst_get_rand_uint32() % (strbuf.len + 1);
        k    = nmtst_get_rand_uint32() % (strbuf.len - j + 2) - 1;

        nm_str_buf_erase(&strbuf, j, k, nmtst_get_rand_bool());
        g_string_erase(gstr, j, k);
        if (gstr->str[0])
            g_assert_cmpstr(gstr->str, ==, nm_str_buf_get_str(&strbuf));
        else
            g_assert(NM_IN_STRSET(nm_str_buf_get_str(&strbuf), NULL, ""));
    }

    for (i_run = 0; i_run < 50; i_run++) {
        char                     stack_buf[20];
        nm_auto_str_buf NMStrBuf strbuf = NM_STR_BUF_INIT_ARR(stack_buf, nmtst_get_rand_bool());

        nm_str_buf_append_c_len(&strbuf, 'a', nmtst_get_rand_uint32() % (sizeof(stack_buf) * 2));
        if (strbuf.len <= sizeof(stack_buf)) {
            g_assert(stack_buf == nm_str_buf_get_str_unsafe(&strbuf));
        } else
            g_assert(stack_buf != nm_str_buf_get_str_unsafe(&strbuf));

        if (strbuf.len < sizeof(stack_buf)) {
            g_assert(stack_buf == nm_str_buf_get_str(&strbuf));
        } else
            g_assert(stack_buf != nm_str_buf_get_str(&strbuf));
    }

    {
        nm_auto_str_buf NMStrBuf s1  = NM_STR_BUF_INIT_A(10, nmtst_get_rand_bool());
        gs_free char            *str = NULL;
        gsize                    l;

        nm_str_buf_append_len(&s1, "a\0b", 3);
        str = nm_str_buf_finalize(&s1, &l);
        g_assert_cmpmem(str, l + 1, "a\0b", 4);
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

        g_assert(nm_strv_cmp_n((const char *const *) strv->pdata,
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
        const char *const   *strv_src;
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
            nm_strv_dup_packed(strv_src, nmtst_get_rand_bool() ? (gssize) strv_len : (gssize) -1);
        if (strv_len == 0)
            g_assert(!strv_cpy);
        else
            g_assert(strv_cpy);
        g_assert(NM_PTRARRAY_LEN(strv_cpy) == strv_len);
        if (strv_cpy)
            g_assert(nm_strv_equal(strv_cpy, strv_src));
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
            GEqualFunc       func_key_equal = is_num_key ? NULL : g_str_equal;
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

static void
test_nm_g_source_sentinel(void)
{
    GSource *s1;
    GSource *s2;
    int      n;
    int      i;
    int      refs;

    s1 = nm_g_source_sentinel_get(0);
    g_assert_nonnull(s1);
    g_assert_cmpint(g_atomic_int_get(&s1->ref_count), ==, 1);

    s2 = nm_g_source_sentinel_get(0);
    g_assert_nonnull(s2);
    g_assert(s2 == s1);
    g_assert_cmpint(g_atomic_int_get(&s1->ref_count), ==, 1);

    n = nmtst_get_rand_uint32() % 7;
    for (refs = 0, i = 0; i < n; i++) {
        if (nmtst_get_rand_bool()) {
            refs++;
            g_source_ref(s1);
        }
        if (nmtst_get_rand_bool())
            g_source_destroy(s1);
        if (refs > 0 && nmtst_get_rand_bool()) {
            refs--;
            g_source_unref(s1);
        }

        if (nmtst_get_rand_bool()) {
            s2 = nm_g_source_sentinel_get(0);
            g_assert_cmpint(g_atomic_int_get(&s2->ref_count), >=, 1);
            g_assert(s2 == s1);
        }
    }

    for (; refs > 0;) {
        if (nmtst_get_rand_bool())
            g_source_destroy(s1);
        if (nmtst_get_rand_bool()) {
            refs--;
            g_source_unref(s1);
        }
    }

    g_assert_cmpint(g_atomic_int_get(&s1->ref_count), ==, 1);
}

/*****************************************************************************/

static void
test_nm_ascii(void)
{
    int i;

    for (i = 0; i < 256; i++) {
        const char ch = i;
        gboolean   is_space;

        if (ch == 127) {
            g_assert(nm_ascii_is_ctrl_or_del(ch));
            g_assert(!nm_ascii_is_ctrl(ch));
        } else
            g_assert(nm_ascii_is_ctrl_or_del(ch) == nm_ascii_is_ctrl(ch));
        g_assert(nm_ascii_is_ctrl_or_del(ch) == g_ascii_iscntrl(ch));

        g_assert(nm_ascii_is_non_ascii(ch) == (i >= 128));

        g_assert(!nm_ascii_is_ctrl_or_del(ch) || !nm_ascii_is_non_ascii(ch));

        g_assert((nm_ascii_is_ctrl_or_del(ch) || nm_ascii_is_regular(ch))
                 != nm_ascii_is_non_ascii(ch));

        g_assert(nm_ascii_is_regular(ch)
                 == (!nm_ascii_is_ctrl_or_del(ch) && !nm_ascii_is_non_ascii(ch)));

        is_space = g_ascii_isspace(ch);
        if (NM_IN_SET(ch, '\t', '\n', '\f', '\r')) {
            /* hack is-space, so that the check below works to check for regular ASCII characters. */
            g_assert(!nm_ascii_is_regular(ch));
            g_assert(is_space);
            is_space = FALSE;
        }
        g_assert(nm_ascii_is_regular(ch)
                 == (g_ascii_isalnum(ch) || g_ascii_isalpha(ch) || g_ascii_isdigit(ch)
                     || g_ascii_isgraph(ch) || g_ascii_islower(ch) || g_ascii_isprint(ch)
                     || g_ascii_ispunct(ch) || is_space || g_ascii_isupper(ch)
                     || g_ascii_isxdigit(ch)));
    }
}

/*****************************************************************************/

static int
_env_file_push_cb(unsigned line, const char *key, const char *value, void *user_data)
{
    char ***strv = user_data;
    char   *s_line;
    gsize   key_l;
    gsize   strv_l;
    gsize   i;

    g_assert(strv);
    g_assert(key);
    g_assert(key[0]);
    g_assert(!strchr(key, '='));
    g_assert(value);

    key_l = strlen(key);

    s_line = g_strconcat(key, "=", value, NULL);

    strv_l = 0;
    if (*strv) {
        const char *s;

        for (i = 0; (s = (*strv)[i]); i++) {
            if (g_str_has_prefix(s, key) && s[key_l] == '=') {
                g_free((*strv)[i]);
                (*strv)[i] = s_line;
                return 0;
            }
        }
        strv_l = i;
    }

    *strv               = g_realloc(*strv, sizeof(char *) * (strv_l + 2));
    (*strv)[strv_l]     = s_line;
    (*strv)[strv_l + 1] = NULL;

    return 0;
}

static void
test_parse_env_file(void)
{
    gs_strfreev char **data = NULL;
    gs_free char      *arg1 = NULL;
    gs_free char      *arg2 = NULL;
    int                r;

#define env_file_1                  \
    "a=a\n"                         \
    "a=b\n"                         \
    "a=b\n"                         \
    "a=a\n"                         \
    "b=b\\\n"                       \
    "c\n"                           \
    "d= d\\\n"                      \
    "e  \\\n"                       \
    "f  \n"                         \
    "g=g\\ \n"                      \
    "h= ąęół\\ śćńźżµ \n" \
    "i=i\\"
    r = nm_parse_env_file_full(env_file_1, _env_file_push_cb, &data);
    g_assert_cmpint(r, ==, 0);
    nmtst_assert_strv(data, "a=a", "b=bc", "d=de  f", "g=g ", "h=ąęół śćńźżµ", "i=i");
    nm_clear_pointer(&data, g_strfreev);

    r = nm_parse_env_file(env_file_1, "a", &arg1);
    g_assert_cmpint(r, ==, 0);
    g_assert_cmpstr(arg1, ==, "a");
    nm_clear_g_free(&arg1);

    r = nm_parse_env_file(env_file_1, "a", &arg1, "d", &arg2);
    g_assert_cmpint(r, ==, 0);
    g_assert_cmpstr(arg1, ==, "a");
    g_assert_cmpstr(arg2, ==, "de  f");
    nm_clear_g_free(&arg1);
    nm_clear_g_free(&arg2);

#define env_file_2 "a=a\\\n"
    r = nm_parse_env_file_full(env_file_2, _env_file_push_cb, &data);
    g_assert_cmpint(r, ==, 0);
    nmtst_assert_strv(data, "a=a");
    nm_clear_pointer(&data, g_strfreev);

#define env_file_3                                              \
    "#SPAMD_ARGS=\"-d --socketpath=/var/lib/bulwark/spamd \\\n" \
    "#--nouser-config                                     \\\n" \
    "normal=line                                          \\\n" \
    ";normal=ignored                                      \\\n" \
    "normal_ignored                                       \\\n" \
    "normal ignored                                       \\\n"
    r = nm_parse_env_file_full(env_file_3, _env_file_push_cb, &data);
    g_assert_cmpint(r, ==, 0);
    g_assert(!data);

#define env_file_4                          \
    "# Generated\n"                         \
    "\n"                                    \
    "HWMON_MODULES=\"coretemp f71882fg\"\n" \
    "\n"                                    \
    "# For compatibility reasons\n"         \
    "\n"                                    \
    "MODULE_0=coretemp\n"                   \
    "MODULE_1=f71882fg"
    r = nm_parse_env_file_full(env_file_4, _env_file_push_cb, &data);
    g_assert_cmpint(r, ==, 0);
    nmtst_assert_strv(data,
                      "HWMON_MODULES=coretemp f71882fg",
                      "MODULE_0=coretemp",
                      "MODULE_1=f71882fg");
    nm_clear_pointer(&data, g_strfreev);

#define env_file_5 \
    "a=\n"         \
    "b="
    r = nm_parse_env_file_full(env_file_5, _env_file_push_cb, &data);
    g_assert_cmpint(r, ==, 0);
    nmtst_assert_strv(data, "a=", "b=");
    nm_clear_pointer(&data, g_strfreev);

#define env_file_6                \
    "a=\\ \\n \\t \\x \\y \\' \n" \
    "b= \\$'                  \n" \
    "c= ' \\n\\t\\$\\`\\\\\n"     \
    "'   \n"                      \
    "d= \" \\n\\t\\$\\`\\\\\n"    \
    "\"   \n"
    r = nm_parse_env_file_full(env_file_6, _env_file_push_cb, &data);
    g_assert_cmpint(r, ==, 0);
    nmtst_assert_strv(data, "a= n t x y '", "b=$'", "c= \\n\\t\\$\\`\\\\\n", "d= \\n\\t$`\\\n");
    nm_clear_pointer(&data, g_strfreev);
}

/*****************************************************************************/

static void
test_unbase64char(void)
{
    static const int expected[128] = {
        [0] = -1,   [1] = -1,   [2] = -1,   [3] = -1,   [4] = -1,   [5] = -1,   [6] = -1,
        [7] = -1,   [8] = -1,   [9] = -1,   [10] = -1,  [11] = -1,  [12] = -1,  [13] = -1,
        [14] = -1,  [15] = -1,  [16] = -1,  [17] = -1,  [18] = -1,  [19] = -1,  [20] = -1,
        [21] = -1,  [22] = -1,  [23] = -1,  [24] = -1,  [25] = -1,  [26] = -1,  [27] = -1,
        [28] = -1,  [29] = -1,  [30] = -1,  [31] = -1,  [32] = -1,  [33] = -1,  [34] = -1,
        [35] = -1,  [36] = -1,  [37] = -1,  [38] = -1,  [39] = -1,  [40] = -1,  [41] = -1,
        [42] = -1,  ['+'] = 62, [44] = -1,  [45] = -1,  [46] = -1,  ['/'] = 63, ['0'] = 52,
        ['1'] = 53, ['2'] = 54, ['3'] = 55, ['4'] = 56, ['5'] = 57, ['6'] = 58, ['7'] = 59,
        ['8'] = 60, ['9'] = 61, [58] = -1,  [59] = -1,  [60] = -1,  [61] = -1,  [62] = -1,
        [63] = -1,  [64] = -1,  ['A'] = 0,  ['B'] = 1,  ['C'] = 2,  ['D'] = 3,  ['E'] = 4,
        ['F'] = 5,  ['G'] = 6,  ['H'] = 7,  ['I'] = 8,  ['J'] = 9,  ['K'] = 10, ['L'] = 11,
        ['M'] = 12, ['N'] = 13, ['O'] = 14, ['P'] = 15, ['Q'] = 16, ['R'] = 17, ['S'] = 18,
        ['T'] = 19, ['U'] = 20, ['V'] = 21, ['W'] = 22, ['X'] = 23, ['Y'] = 24, ['Z'] = 25,
        [91] = -1,  [92] = -1,  [93] = -1,  [94] = -1,  [95] = -1,  [96] = -1,  ['a'] = 26,
        ['b'] = 27, ['c'] = 28, ['d'] = 29, ['e'] = 30, ['f'] = 31, ['g'] = 32, ['h'] = 33,
        ['i'] = 34, ['j'] = 35, ['k'] = 36, ['l'] = 37, ['m'] = 38, ['n'] = 39, ['o'] = 40,
        ['p'] = 41, ['q'] = 42, ['r'] = 43, ['s'] = 44, ['t'] = 45, ['u'] = 46, ['v'] = 47,
        ['w'] = 48, ['x'] = 49, ['y'] = 50, ['z'] = 51, [123] = -1, [124] = -1, [125] = -1,
        [126] = -1, [127] = -1,
    };
    int i;

    /* Copied from systemd's TEST(unbase64char)
     * https://github.com/systemd/systemd/blob/688efe7703328c5a0251fafac55757b8864a9f9a/src/test/test-hexdecoct.c#L44 */

    g_assert_cmpint(nm_unbase64char('A'), ==, 0);
    g_assert_cmpint(nm_unbase64char('Z'), ==, 25);
    g_assert_cmpint(nm_unbase64char('a'), ==, 26);
    g_assert_cmpint(nm_unbase64char('z'), ==, 51);
    g_assert_cmpint(nm_unbase64char('0'), ==, 52);
    g_assert_cmpint(nm_unbase64char('9'), ==, 61);
    g_assert_cmpint(nm_unbase64char('+'), ==, 62);
    g_assert_cmpint(nm_unbase64char('/'), ==, 63);
    g_assert_cmpint(nm_unbase64char('='), ==, -ERANGE);
    g_assert_cmpint(nm_unbase64char('\0'), ==, -EINVAL);
    g_assert_cmpint(nm_unbase64char('\1'), ==, -EINVAL);
    g_assert_cmpint(nm_unbase64char('\x7F'), ==, -EINVAL);
    g_assert_cmpint(nm_unbase64char('\x80'), ==, -EINVAL);
    g_assert_cmpint(nm_unbase64char('\xFF'), ==, -EINVAL);

    for (i = 0; i < 256; i++) {
        int base64;

        base64 = nm_unbase64char((char) i);

        if (base64 < 0) {
            if (((char) i) == '=')
                g_assert_cmpint(base64, ==, -ERANGE);
            else
                g_assert_cmpint(base64, ==, -EINVAL);
            base64 = -1;
        }

        if (i >= G_N_ELEMENTS(expected)) {
            g_assert_cmpint(base64, ==, -1);
            continue;
        }
        g_assert_cmpint(base64, ==, expected[i]);
    }
}

/*****************************************************************************/

static void
test_unbase64mem1(void)
{
    nm_auto_str_buf NMStrBuf encoded_wrapped = NM_STR_BUF_INIT(400, FALSE);
    uint8_t                  data[4096];
    int                      i_run;

    /* Copied from systemd's TEST(base64mem_linebreak)
     * https://github.com/systemd/systemd/blob/688efe7703328c5a0251fafac55757b8864a9f9a/src/test/test-hexdecoct.c#L280 */

    for (i_run = 0; i_run < 20; i_run++) {
        gs_free char   *encoded = NULL;
        gs_free guint8 *decoded = NULL;
        gsize           decoded_size;
        guint64         n;
        guint64         m;
        guint64         i;
        guint64         j;
        gssize          l;
        int             r;

        /* Try a bunch of differently sized blobs */
        n = nmtst_get_rand_uint64() % sizeof(data);
        nmtst_rand_buf(NULL, data, n);

        /* Break at various different columns */
        m = 1 + (nmtst_get_rand_uint64() % (n + 5));

        encoded = g_base64_encode(data, n);
        g_assert(encoded);
        l = strlen(encoded);

        nm_str_buf_reset(&encoded_wrapped);
        for (i = 0, j = 0; i < l; i++, j++) {
            if (j == m) {
                nm_str_buf_append_c(&encoded_wrapped, '\n');
                j = 0;
            }
            nm_str_buf_append_c(&encoded_wrapped, encoded[i]);
        }

        g_assert_cmpint(strlen(nm_str_buf_get_str(&encoded_wrapped)), ==, encoded_wrapped.len);

        r = nm_unbase64mem_full(nm_str_buf_get_str(&encoded_wrapped),
                                nmtst_get_rand_bool() ? SIZE_MAX : encoded_wrapped.len,
                                nmtst_get_rand_bool(),
                                &decoded,
                                &decoded_size);
        g_assert_cmpint(r, >=, 0);
        g_assert_cmpmem(data, n, decoded, decoded_size);

        for (j = 0; j < encoded_wrapped.len; j++)
            g_assert((nm_str_buf_get_str(&encoded_wrapped)[j] == '\n') == (j % (m + 1) == m));
    }
}

/*****************************************************************************/

static void
_assert_unbase64mem(const char *input, const char *output, int ret)
{
    gs_free guint8 *buffer = NULL;
    gsize           size   = 0;
    int             r;

    r = nm_unbase64mem_full(input, SIZE_MAX, nmtst_get_rand_bool(), &buffer, &size);
    g_assert_cmpint(r, ==, ret);

    if (ret >= 0) {
        g_assert_cmpmem(buffer, size, output, strlen(output));
        g_assert_cmpint(((const char *) buffer)[size], ==, '\0');
    } else {
        g_assert(!buffer);
        g_assert_cmpint(size, ==, 0);
    }
}

static void
test_unbase64mem2(void)
{
    /* Copied from systemd's TEST(unbase64mem)
     * https://github.com/systemd/systemd/blob/688efe7703328c5a0251fafac55757b8864a9f9a/src/test/test-hexdecoct.c#L324 */

    _assert_unbase64mem("", "", 0);
    _assert_unbase64mem("Zg==", "f", 0);
    _assert_unbase64mem("Zm8=", "fo", 0);
    _assert_unbase64mem("Zm9v", "foo", 0);
    _assert_unbase64mem("Zm9vYg==", "foob", 0);
    _assert_unbase64mem("Zm9vYmE=", "fooba", 0);
    _assert_unbase64mem("Zm9vYmFy", "foobar", 0);

    _assert_unbase64mem(" ", "", 0);
    _assert_unbase64mem(" \n\r ", "", 0);
    _assert_unbase64mem("    Zg\n==       ", "f", 0);
    _assert_unbase64mem(" Zm 8=\r", "fo", 0);
    _assert_unbase64mem("  Zm9\n\r\r\nv   ", "foo", 0);
    _assert_unbase64mem(" Z m9vYg==\n\r", "foob", 0);
    _assert_unbase64mem(" Zm 9vYmE=   ", "fooba", 0);
    _assert_unbase64mem("   Z m9v    YmFy   ", "foobar", 0);

    _assert_unbase64mem("A", NULL, -EPIPE);
    _assert_unbase64mem("A====", NULL, -EINVAL);
    _assert_unbase64mem("AAB==", NULL, -EINVAL);
    _assert_unbase64mem(" A A A B = ", NULL, -EINVAL);
    _assert_unbase64mem(" Z m 8 = q u u x ", NULL, -ENAMETOOLONG);
}

/*****************************************************************************/

static void
_test_unbase64mem_mem(const char *base64, const guint8 *expected_arr, gsize expected_len)
{
    gs_free char        *expected_base64 = NULL;
    int                  r;
    nm_auto_free guint8 *exp2_arr = NULL;
    nm_auto_free guint8 *exp3_arr = NULL;
    gsize                exp2_len;
    gsize                exp3_len;

    expected_base64 = g_base64_encode(expected_arr, expected_len);

    r = nm_unbase64mem_full(expected_base64, strlen(expected_base64), TRUE, &exp2_arr, &exp2_len);
    g_assert_cmpint(r, ==, 0);
    g_assert_cmpmem(expected_arr, expected_len, exp2_arr, exp2_len);

    if (!nm_streq(base64, expected_base64)) {
        r = nm_unbase64mem_full(base64, strlen(base64), TRUE, &exp3_arr, &exp3_len);
        g_assert_cmpint(r, ==, 0);
        g_assert_cmpmem(expected_arr, expected_len, exp3_arr, exp3_len);
    }
}

#define _test_unbase64mem(base64, expected_str) \
    _test_unbase64mem_mem(base64, (const guint8 *) "" expected_str "", NM_STRLEN(expected_str))

static void
_test_unbase64mem_inval(const char *base64)
{
    gs_free guint8 *exp_arr = NULL;
    gsize           exp_len = 0;
    int             r;

    r = nm_unbase64mem_full(base64, strlen(base64), TRUE, &exp_arr, &exp_len);
    g_assert_cmpint(r, <, 0);
    g_assert(!exp_arr);
    g_assert(exp_len == 0);
}

static void
test_unbase64mem3(void)
{
    gs_free char *rnd_base64 = NULL;
    guint8        rnd_buf[30];
    guint         i, rnd_len;

    _test_unbase64mem("", "");
    _test_unbase64mem("  ", "");
    _test_unbase64mem(" Y Q == ", "a");
    _test_unbase64mem(" Y   WJjZGV mZ 2g = ", "abcdefgh");
    _test_unbase64mem_inval(" Y   %WJjZGV mZ 2g = ");
    _test_unbase64mem_inval(" Y   %WJjZGV mZ 2g = a");
    _test_unbase64mem("YQ==", "a");
    _test_unbase64mem_inval("YQ==a");

    rnd_len = nmtst_get_rand_uint32() % sizeof(rnd_buf);
    for (i = 0; i < rnd_len; i++)
        rnd_buf[i] = nmtst_get_rand_uint32() % 256;
    rnd_base64 = g_base64_encode(rnd_buf, rnd_len);
    _test_unbase64mem_mem(rnd_base64, rnd_buf, rnd_len);
}

/*****************************************************************************/

static void
assert_path_compare(const char *a, const char *b, int expected)
{
    int r;

    g_assert(NM_IN_SET(expected, -1, 0, 1));

    g_assert_cmpint(nm_path_compare(a, a), ==, 0);
    g_assert_cmpint(nm_path_compare(b, b), ==, 0);

    r = nm_path_compare(a, b);
    g_assert_cmpint(r, ==, expected);
    r = nm_path_compare(b, a);
    g_assert_cmpint(r, ==, -expected);

    g_assert(nm_path_equal(a, a) == 1);
    g_assert(nm_path_equal(b, b) == 1);
    g_assert(nm_path_equal(a, b) == (expected == 0));
    g_assert(nm_path_equal(b, a) == (expected == 0));
}

static void
test_path_compare(void)
{
    /* Copied from systemd.
     * https://github.com/systemd/systemd/blob/bc85f8b51d962597360e982811e674c126850f56/src/test/test-path-util.c#L126 */

    assert_path_compare("/goo", "/goo", 0);
    assert_path_compare("/goo", "/goo", 0);
    assert_path_compare("//goo", "/goo", 0);
    assert_path_compare("//goo/////", "/goo", 0);
    assert_path_compare("goo/////", "goo", 0);
    assert_path_compare("/goo/boo", "/goo//boo", 0);
    assert_path_compare("//goo/boo", "/goo/boo//", 0);
    assert_path_compare("//goo/././//./boo//././//", "/goo/boo//.", 0);
    assert_path_compare("/.", "//.///", 0);
    assert_path_compare("/x", "x/", 1);
    assert_path_compare("x/", "/", -1);
    assert_path_compare("/x/./y", "x/y", 1);
    assert_path_compare("/x/./y", "/x/y", 0);
    assert_path_compare("/x/./././y", "/x/y/././.", 0);
    assert_path_compare("./x/./././y", "./x/y/././.", 0);
    assert_path_compare(".", "./.", 0);
    assert_path_compare(".", "././.", 0);
    assert_path_compare("./..", ".", 1);
    assert_path_compare("x/.y", "x/y", -1);
    assert_path_compare("foo", "/foo", -1);
    assert_path_compare("/foo", "/foo/bar", -1);
    assert_path_compare("/foo/aaa", "/foo/b", -1);
    assert_path_compare("/foo/aaa", "/foo/b/a", -1);
    assert_path_compare("/foo/a", "/foo/aaa", -1);
    assert_path_compare("/foo/a/b", "/foo/aaa", -1);
}

/*****************************************************************************/

static void
test_path_equal(void)
{
#define _path_equal_check(path, expected)           \
    G_STMT_START                                    \
    {                                               \
        const char   *_path0    = (path);           \
        const char   *_expected = (expected);       \
        gs_free char *_path     = g_strdup(_path0); \
        const char   *_path_result;                 \
                                                    \
        _path_result = nm_path_simplify(_path);     \
        g_assert(_path_result == _path);            \
        g_assert_cmpstr(_path, ==, _expected);      \
    }                                               \
    G_STMT_END

    _path_equal_check("", "");
    _path_equal_check(".", ".");
    _path_equal_check("..", "..");
    _path_equal_check("/..", "/..");
    _path_equal_check("//..", "/..");
    _path_equal_check("/.", "/");
    _path_equal_check("./", ".");
    _path_equal_check("./.", ".");
    _path_equal_check(".///.", ".");
    _path_equal_check(".///./", ".");
    _path_equal_check(".////", ".");
    _path_equal_check("//..//foo/", "/../foo");
    _path_equal_check("///foo//./bar/.", "/foo/bar");
    _path_equal_check(".//./foo//./bar/.", "foo/bar");
}

/*****************************************************************************/

static void
assert_path_find_first_component(const char        *path,
                                 gboolean           accept_dot_dot,
                                 const char *const *expected,
                                 int                ret)
{
    const char *p;

    for (p = path;;) {
        const char *e;
        int         r;

        r = nm_path_find_first_component(&p, accept_dot_dot, &e);
        if (r <= 0) {
            if (r == 0) {
                if (path)
                    g_assert(p == path + strlen(path));
                else
                    g_assert(!p);
                g_assert(!e);
            }
            g_assert(r == ret);
            g_assert(!expected || !*expected);
            return;
        }

        g_assert(e);
        g_assert(strcspn(e, "/") == (size_t) r);
        g_assert(strlen(*expected) == (size_t) r);
        g_assert(strncmp(e, *expected++, r) == 0);
    }
}

static void
test_path_find_first_component(void)
{
    gs_free char *hoge = NULL;
    char          foo[NAME_MAX * 2];

    /* Copied from systemd.
     * https://github.com/systemd/systemd/blob/bc85f8b51d962597360e982811e674c126850f56/src/test/test-path-util.c#L631 */

    assert_path_find_first_component(NULL, false, NULL, 0);
    assert_path_find_first_component("", false, NULL, 0);
    assert_path_find_first_component("/", false, NULL, 0);
    assert_path_find_first_component(".", false, NULL, 0);
    assert_path_find_first_component("./", false, NULL, 0);
    assert_path_find_first_component("./.", false, NULL, 0);
    assert_path_find_first_component("..", false, NULL, -EINVAL);
    assert_path_find_first_component("/..", false, NULL, -EINVAL);
    assert_path_find_first_component("./..", false, NULL, -EINVAL);
    assert_path_find_first_component("////./././//.", false, NULL, 0);
    assert_path_find_first_component("a/b/c", false, NM_MAKE_STRV("a", "b", "c"), 0);
    assert_path_find_first_component("././//.///aa/bbb//./ccc",
                                     false,
                                     NM_MAKE_STRV("aa", "bbb", "ccc"),
                                     0);
    assert_path_find_first_component("././//.///aa/.../../bbb//./ccc/.",
                                     false,
                                     NM_MAKE_STRV("aa", "..."),
                                     -EINVAL);
    assert_path_find_first_component("//./aaa///.//./.bbb/..///c.//d.dd///..eeee/.",
                                     false,
                                     NM_MAKE_STRV("aaa", ".bbb"),
                                     -EINVAL);
    assert_path_find_first_component("a/foo./b", false, NM_MAKE_STRV("a", "foo.", "b"), 0);

    assert_path_find_first_component(NULL, true, NULL, 0);
    assert_path_find_first_component("", true, NULL, 0);
    assert_path_find_first_component("/", true, NULL, 0);
    assert_path_find_first_component(".", true, NULL, 0);
    assert_path_find_first_component("./", true, NULL, 0);
    assert_path_find_first_component("./.", true, NULL, 0);
    assert_path_find_first_component("..", true, NM_MAKE_STRV(".."), 0);
    assert_path_find_first_component("/..", true, NM_MAKE_STRV(".."), 0);
    assert_path_find_first_component("./..", true, NM_MAKE_STRV(".."), 0);
    assert_path_find_first_component("////./././//.", true, NULL, 0);
    assert_path_find_first_component("a/b/c", true, NM_MAKE_STRV("a", "b", "c"), 0);
    assert_path_find_first_component("././//.///aa/bbb//./ccc",
                                     true,
                                     NM_MAKE_STRV("aa", "bbb", "ccc"),
                                     0);
    assert_path_find_first_component("././//.///aa/.../../bbb//./ccc/.",
                                     true,
                                     NM_MAKE_STRV("aa", "...", "..", "bbb", "ccc"),
                                     0);
    assert_path_find_first_component("//./aaa///.//./.bbb/..///c.//d.dd///..eeee/.",
                                     true,
                                     NM_MAKE_STRV("aaa", ".bbb", "..", "c.", "d.dd", "..eeee"),
                                     0);
    assert_path_find_first_component("a/foo./b", true, NM_MAKE_STRV("a", "foo.", "b"), 0);

    memset(foo, 'a', sizeof(foo) - 1);
    foo[sizeof(foo) - 1] = '\0';

    assert_path_find_first_component(foo, false, NULL, -EINVAL);
    assert_path_find_first_component(foo, true, NULL, -EINVAL);

    hoge = g_strjoin("", "a/b/c/", foo, "//d/e/.//f/", NULL);
    g_assert(hoge);

    assert_path_find_first_component(hoge, false, NM_MAKE_STRV("a", "b", "c"), -EINVAL);
    assert_path_find_first_component(hoge, true, NM_MAKE_STRV("a", "b", "c"), -EINVAL);
}

/*****************************************************************************/

static void
assert_path_startswith(const char *path,
                       const char *prefix,
                       const char *skipped,
                       const char *expected)
{
    const char *p;

    p = nm_path_startswith(path, prefix);
    g_assert_cmpstr(p, ==, expected);
    if (p) {
        gs_free char *q = NULL;

        g_assert(skipped);
        q = g_strjoin("", skipped, p, NULL);
        g_assert_cmpstr(q, ==, path);
        g_assert(p == path + strlen(skipped));
    } else
        g_assert(!skipped);
}

static void
test_path_startswith(void)
{
    assert_path_startswith("/foo/bar/barfoo/", "/foo", "/foo/", "bar/barfoo/");
    assert_path_startswith("/foo/bar/barfoo/", "/foo/", "/foo/", "bar/barfoo/");
    assert_path_startswith("/foo/bar/barfoo/", "/", "/", "foo/bar/barfoo/");
    assert_path_startswith("/foo/bar/barfoo/", "////", "/", "foo/bar/barfoo/");
    assert_path_startswith("/foo/bar/barfoo/", "/foo//bar/////barfoo///", "/foo/bar/barfoo/", "");
    assert_path_startswith("/foo/bar/barfoo/", "/foo/bar/barfoo////", "/foo/bar/barfoo/", "");
    assert_path_startswith("/foo/bar/barfoo/", "/foo/bar///barfoo/", "/foo/bar/barfoo/", "");
    assert_path_startswith("/foo/bar/barfoo/", "/foo////bar/barfoo/", "/foo/bar/barfoo/", "");
    assert_path_startswith("/foo/bar/barfoo/", "////foo/bar/barfoo/", "/foo/bar/barfoo/", "");
    assert_path_startswith("/foo/bar/barfoo/", "/foo/bar/barfoo", "/foo/bar/barfoo/", "");

    assert_path_startswith("/foo/bar/barfoo/", "/foo/bar/barfooa/", NULL, NULL);
    assert_path_startswith("/foo/bar/barfoo/", "/foo/bar/barfooa", NULL, NULL);
    assert_path_startswith("/foo/bar/barfoo/", "", NULL, NULL);
    assert_path_startswith("/foo/bar/barfoo/", "/bar/foo", NULL, NULL);
    assert_path_startswith("/foo/bar/barfoo/", "/f/b/b/", NULL, NULL);
    assert_path_startswith("/foo/bar/barfoo/", "/foo/bar/barfo", NULL, NULL);
    assert_path_startswith("/foo/bar/barfoo/", "/foo/bar/bar", NULL, NULL);
    assert_path_startswith("/foo/bar/barfoo/", "/fo", NULL, NULL);
}

/*****************************************************************************/

static void
assert_path_simplify(const char *in, const char *out)
{
    gs_free char *p = NULL;

    g_assert(in);
    p = g_strdup(in);
    nm_path_simplify(p);
    g_assert_cmpstr(p, ==, out);
}

static void
test_path_simplify(void)
{
    gs_free char *hoge     = NULL;
    gs_free char *hoge_out = NULL;
    char          foo[NAME_MAX * 2];

    assert_path_simplify("", "");
    assert_path_simplify("aaa/bbb////ccc", "aaa/bbb/ccc");
    assert_path_simplify("//aaa/.////ccc", "/aaa/ccc");
    assert_path_simplify("///", "/");
    assert_path_simplify("///.//", "/");
    assert_path_simplify("///.//.///", "/");
    assert_path_simplify("////.././///../.", "/../..");
    assert_path_simplify(".", ".");
    assert_path_simplify("./", ".");
    assert_path_simplify(".///.//./.", ".");
    assert_path_simplify(".///.//././/", ".");
    assert_path_simplify("//./aaa///.//./.bbb/..///c.//d.dd///..eeee/.",
                         "/aaa/.bbb/../c./d.dd/..eeee");
    assert_path_simplify("//./aaa///.//./.bbb/..///c.//d.dd///..eeee/..",
                         "/aaa/.bbb/../c./d.dd/..eeee/..");
    assert_path_simplify(".//./aaa///.//./.bbb/..///c.//d.dd///..eeee/..",
                         "aaa/.bbb/../c./d.dd/..eeee/..");
    assert_path_simplify("..//./aaa///.//./.bbb/..///c.//d.dd///..eeee/..",
                         "../aaa/.bbb/../c./d.dd/..eeee/..");

    memset(foo, 'a', sizeof(foo) - 1);
    foo[sizeof(foo) - 1] = '\0';

    assert_path_simplify(foo, foo);

    hoge = g_strjoin("", "/", foo, NULL);
    g_assert(hoge);
    assert_path_simplify(hoge, hoge);
    nm_clear_g_free(&hoge);

    hoge =
        g_strjoin("", "a////.//././//./b///././/./c/////././//./", foo, "//.//////d/e/.//f/", NULL);
    g_assert(hoge);

    hoge_out = g_strjoin("", "a/b/c/", foo, "//.//////d/e/.//f/", NULL);
    g_assert(hoge_out);

    assert_path_simplify(hoge, hoge_out);
}

/*****************************************************************************/

static void
test_hostname_is_valid(void)
{
    g_assert(nm_hostname_is_valid("foobar", FALSE));
    g_assert(nm_hostname_is_valid("foobar.com", FALSE));
    g_assert(!nm_hostname_is_valid("foobar.com.", FALSE));
    g_assert(nm_hostname_is_valid("fooBAR", FALSE));
    g_assert(nm_hostname_is_valid("fooBAR.com", FALSE));
    g_assert(!nm_hostname_is_valid("fooBAR.", FALSE));
    g_assert(!nm_hostname_is_valid("fooBAR.com.", FALSE));
    g_assert(!nm_hostname_is_valid("fööbar", FALSE));
    g_assert(!nm_hostname_is_valid("", FALSE));
    g_assert(!nm_hostname_is_valid(".", FALSE));
    g_assert(!nm_hostname_is_valid("..", FALSE));
    g_assert(!nm_hostname_is_valid("foobar.", FALSE));
    g_assert(!nm_hostname_is_valid(".foobar", FALSE));
    g_assert(!nm_hostname_is_valid("foo..bar", FALSE));
    g_assert(!nm_hostname_is_valid("foo.bar..", FALSE));

    G_STATIC_ASSERT_EXPR(NM_HOST_NAME_MAX <= HOST_NAME_MAX);

#define _assert_hostname_length(n, valid)         \
    G_STMT_START                                  \
    {                                             \
        const gsize   _n = (n);                   \
        gs_free char *_h = g_strnfill(_n, 'x');   \
        gboolean      _valid;                     \
                                                  \
        _valid = nm_hostname_is_valid(_h, FALSE); \
        g_assert_cmpint(_valid, ==, (valid));     \
    }                                             \
    G_STMT_END

    _assert_hostname_length(NM_HOST_NAME_MAX - 10, TRUE);
    _assert_hostname_length(NM_HOST_NAME_MAX - 1, TRUE);
    _assert_hostname_length(NM_HOST_NAME_MAX, TRUE);
    _assert_hostname_length(NM_HOST_NAME_MAX + 1, FALSE);
    _assert_hostname_length(NM_HOST_NAME_MAX + 10, FALSE);

    g_assert(!nm_hostname_is_valid(
        "au-xph5-rvgrdsb5hcxc-47et3a5vvkrc-server-wyoz4elpdpe3.openstack.local",
        FALSE));

    g_assert(nm_hostname_is_valid("foobar", TRUE));
    g_assert(nm_hostname_is_valid("foobar.com", TRUE));
    g_assert(nm_hostname_is_valid("foobar.com.", TRUE));
    g_assert(nm_hostname_is_valid("fooBAR", TRUE));
    g_assert(nm_hostname_is_valid("fooBAR.com", TRUE));
    g_assert(!nm_hostname_is_valid("fooBAR.", TRUE));
    g_assert(nm_hostname_is_valid("fooBAR.com.", TRUE));
    g_assert(!nm_hostname_is_valid("fööbar", TRUE));
    g_assert(!nm_hostname_is_valid("", TRUE));
    g_assert(!nm_hostname_is_valid(".", TRUE));
    g_assert(!nm_hostname_is_valid("..", TRUE));
    g_assert(!nm_hostname_is_valid("foobar.", TRUE));
    g_assert(!nm_hostname_is_valid(".foobar", TRUE));
    g_assert(!nm_hostname_is_valid("foo..bar", TRUE));
    g_assert(!nm_hostname_is_valid("foo.bar..", TRUE));
    g_assert(
        nm_hostname_is_valid("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                             TRUE));
    g_assert(
        !nm_hostname_is_valid("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                              "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                              TRUE));
}

/*****************************************************************************/

static void
test_inet_utils(void)
{
    g_assert(nm_ip_addr_is_site_local(AF_INET, nmtst_inet_from_string(AF_INET, "172.16.0.1")));
    g_assert(nm_ip_addr_is_site_local(AF_INET, nmtst_inet_from_string(AF_INET, "172.17.0.1")));
    g_assert(nm_ip_addr_is_site_local(AF_INET, nmtst_inet_from_string(AF_INET, "192.168.7.5")));
    g_assert(!nm_ip_addr_is_site_local(AF_INET, nmtst_inet_from_string(AF_INET, "192.0.7.5")));
    g_assert(nm_ip_addr_is_site_local(AF_INET6, nmtst_inet_from_string(AF_INET6, "fec0::")));
    g_assert(!nm_ip_addr_is_site_local(AF_INET6, nmtst_inet_from_string(AF_INET6, "fc00::")));
}

/*****************************************************************************/

static gboolean
_inet_parse(int addr_family, const char *str, gboolean accept_legacy, gpointer out_addr)
{
    int        addr_family2   = -1;
    int *const p_addr_family2 = nmtst_get_rand_bool() ? &addr_family2 : NULL;
    NMIPAddr   addr;
    gboolean   success;

    g_assert(NM_IN_SET(addr_family, AF_INET, AF_INET6));

    success =
        nm_inet_parse_bin_full((p_addr_family2 && nmtst_get_rand_bool()) ? AF_UNSPEC : addr_family,
                               accept_legacy,
                               str,
                               p_addr_family2,
                               &addr);

    if (success) {
        g_assert(!p_addr_family2 || NM_IN_SET(*p_addr_family2, AF_INET, AF_INET6));
        if (p_addr_family2 && *p_addr_family2 != addr_family) {
            success = FALSE;
        } else
            g_assert(!p_addr_family2 || *p_addr_family2 == addr_family);
    } else
        g_assert(addr_family2 == -1);

    if (out_addr && success)
        nm_ip_addr_set(addr_family, out_addr, &addr);

    return success;
}

#define _inet_parse_fail(check, accept_legacy)                             \
    G_STMT_START                                                           \
    {                                                                      \
        NMIPAddr _addr;                                                    \
        gboolean _success;                                                 \
                                                                           \
        _success = _inet_parse(nmtst_get_rand_bool() ? AF_INET : AF_INET6, \
                               "" check "",                                \
                               (accept_legacy),                            \
                               nmtst_get_rand_bool() ? &_addr : NULL);     \
        g_assert(!_success);                                               \
    }                                                                      \
    G_STMT_END

#define _inet_parse_good(check, expected, accept_legacy)                        \
    G_STMT_START                                                                \
    {                                                                           \
        int               _accept_legacy = (accept_legacy);                     \
        const char *const _check         = "" check "";                         \
        const char *const _expected      = expected ?: _check;                  \
        NMIPAddr          _addr[2];                                             \
        gboolean          _success[2];                                          \
                                                                                \
        if (_accept_legacy == -1)                                               \
            _accept_legacy = nmtst_get_rand_bool();                             \
                                                                                \
        _success[0] = _inet_parse(AF_INET6, _check, _accept_legacy, &_addr[0]); \
        _success[1] = _inet_parse(AF_INET, _check, _accept_legacy, &_addr[1]);  \
                                                                                \
        g_assert(NM_IN_SET(_success[0], FALSE, TRUE));                          \
        g_assert(NM_IN_SET(_success[1], FALSE, TRUE));                          \
        g_assert(_success[0] != _success[1]);                                   \
                                                                                \
        if (_success[0])                                                        \
            nmtst_assert_ip6_address(&_addr[0].addr6, _expected);               \
        else                                                                    \
            nmtst_assert_ip4_address(_addr[1].addr4, _expected);                \
                                                                                \
        if (_success[1]) {                                                      \
            in_addr_t _a4;                                                      \
            int       _r;                                                       \
                                                                                \
            _r = nmtst_inet_aton(_check, &_a4);                                 \
            g_assert_cmpint(_r, ==, 0);                                         \
            nmtst_assert_ip4_address(_a4, _expected);                           \
        }                                                                       \
    }                                                                           \
    G_STMT_END

static void
test_inet_parse_ip4_legacy(void)
{
    _inet_parse_fail("", -1);
    _inet_parse_fail(" ", -1);
    _inet_parse_fail("a", -1);
    _inet_parse_fail("0", -1);
    _inet_parse_fail("0.1", -1);
    _inet_parse_fail("0.4.1", -1);
    _inet_parse_fail("1.2.3.05", FALSE);
    _inet_parse_fail("192.000.002.010", FALSE);
    _inet_parse_fail("1.2.3..5", -1);
    _inet_parse_fail("1.2.3.0x", -1);
    _inet_parse_fail("0xC0000234", -1);
    _inet_parse_fail("192.0.2.2X", -1);
    _inet_parse_fail("192.0.2.3 Y", -1);
    _inet_parse_fail("192.0.2.4\nZ", -1);
    _inet_parse_fail("192.0.2.5\tT", -1);
    _inet_parse_fail("192.0.2.6 Y", -1);
    _inet_parse_fail("192.0.2.7\n", -1);
    _inet_parse_fail("192.0.2.7\t", -1);
    _inet_parse_fail("192.0.2.7 ", -1);
    _inet_parse_fail("00x0019.0000001.000000.0x1", -1);
    _inet_parse_fail("192.0.2.7.", -1);
    _inet_parse_fail("192.0.2.7.0", -1);

    _inet_parse_good("192.0.2.1", NULL, -1);
    _inet_parse_good("1.2.3.4", NULL, -1);
    _inet_parse_good("192.167.3.4", NULL, -1);

    _inet_parse_good("192.000.002.010", "192.0.2.8", TRUE);
    _inet_parse_good("255.000.000.000", "255.0.0.0", TRUE);
    _inet_parse_good("1.2.3.05", "1.2.3.5", TRUE);
    _inet_parse_good("01.2.3.05", "1.2.3.5", TRUE);
    _inet_parse_good("192.00167.0003.4", "192.119.3.4", TRUE);
    _inet_parse_good("0x19.00167.0003.4", "25.119.3.4", TRUE);
    _inet_parse_good("0x19.000000167.0000003.4", "25.119.3.4", TRUE);
    _inet_parse_good("0x0019.000000167.0000003.04", "25.119.3.4", TRUE);
    _inet_parse_good("0x0019.0000001.000000.0x1", "25.1.0.1", TRUE);
}

/*****************************************************************************/

static void
test_garray(void)
{
    gs_unref_array GArray *arr = NULL;
    int                    v;

    arr = g_array_new(FALSE, FALSE, sizeof(int));
    g_assert(nm_g_array_index_p(arr, int, 0) == (gpointer) arr->data);

    v = 1;
    g_array_append_val(arr, v);
    g_assert(nm_g_array_index_p(arr, int, 0) == (gpointer) arr->data);
    g_assert(nm_g_array_index_p(arr, int, 1) == ((int *) ((gpointer) arr->data)) + 1);
    g_assert(&nm_g_array_index(arr, int, 0) == (gpointer) arr->data);
    g_assert(&nm_g_array_first(arr, int) == (gpointer) arr->data);
    g_assert(&nm_g_array_last(arr, int) == (gpointer) arr->data);
    g_assert(nm_g_array_index(arr, int, 0) == 1);

    v = 2;
    g_array_append_val(arr, v);
    g_assert(nm_g_array_index_p(arr, int, 0) == (gpointer) arr->data);
    g_assert(nm_g_array_index_p(arr, int, 1) == ((int *) ((gpointer) arr->data)) + 1);
    g_assert(nm_g_array_index_p(arr, int, 2) == ((int *) ((gpointer) arr->data)) + 2);
    g_assert(&nm_g_array_index(arr, int, 0) == (gpointer) arr->data);
    g_assert(&nm_g_array_first(arr, int) == (gpointer) arr->data);
    g_assert(&nm_g_array_last(arr, int) == ((int *) ((gpointer) arr->data)) + 1);
    g_assert(nm_g_array_index(arr, int, 0) == 1);
    g_assert(nm_g_array_index(arr, int, 1) == 2);
}

/*****************************************************************************/

static int
_prioq_cmp(gconstpointer a, gconstpointer b)
{
    NM_CMP_DIRECT(*((const guint32 *) a), *((const guint32 *) b));
    return 0;
}

static int
_prioq_cmp_with_data(gconstpointer a, gconstpointer b, gpointer user_data)
{
    return _prioq_cmp(a, b);
}

static void
test_nm_prioq(void)
{
    nm_auto_prioq NMPrioq q = NM_PRIOQ_ZERO;
    guint32               data[200];
    const guint32        *data_pop[200];
    guint                 data_idx[G_N_ELEMENTS(data)];
    guint                 i;
    guint                 n;
    guint                 m;
    gpointer              p;

    if (nmtst_get_rand_one_case_in(10))
        return;

    if (nmtst_get_rand_bool())
        nm_prioq_init(&q, _prioq_cmp);
    else
        nm_prioq_init_with_data(&q, _prioq_cmp_with_data, NULL);

    g_assert(nm_prioq_size(&q) == 0);

    if (nmtst_get_rand_one_case_in(100))
        return;

    for (i = 0; i < G_N_ELEMENTS(data); i++) {
        data[i]     = nmtst_get_rand_uint32() % G_N_ELEMENTS(data);
        data_idx[i] = NM_PRIOQ_IDX_NULL;
    }

    nm_prioq_put(&q, &data[0], NULL);
    g_assert(nm_prioq_size(&q) == 1);

    p = nm_prioq_pop(&q);
    g_assert(p == &data[0]);
    g_assert(nm_prioq_size(&q) == 0);

    g_assert(!nm_prioq_pop(&q));

    n = nmtst_get_rand_uint32() % G_N_ELEMENTS(data);
    for (i = 0; i < n; i++)
        nm_prioq_put(&q, &data[i], &data_idx[i]);

    m = n;
    for (i = 0; i < n; i++) {
        if (!nmtst_get_rand_bool())
            continue;

        data[i] = nmtst_get_rand_uint32() % G_N_ELEMENTS(data);
        switch (nmtst_get_rand_uint32() % 4) {
        case 0:
            nm_prioq_reshuffle(&q, &data[i], &data_idx[i]);
            break;
        case 1:
            nm_prioq_remove(&q, &data[i], nmtst_get_rand_bool() ? &data_idx[i] : NULL);
            m--;
            break;
        case 2:
            nm_prioq_update(&q, &data[i], &data_idx[i], TRUE);
            break;
        case 3:
            nm_prioq_update(&q, &data[i], nmtst_get_rand_bool() ? &data_idx[i] : NULL, FALSE);
            m--;
            break;
        }
    }

    g_assert_cmpint(nm_prioq_size(&q), ==, m);

    if (nmtst_get_rand_one_case_in(50))
        return;

    for (i = 0; i < m; i++) {
        data_pop[i] = nm_prioq_pop(&q);
        g_assert(data_pop[i]);
        g_assert_cmpint(*data_pop[i], >=, 0);
        g_assert_cmpint(*data_pop[i], <, G_N_ELEMENTS(data));
        g_assert(data_pop[i] >= &data[0]);
        g_assert(data_pop[i] < &data[n]);
        if (i > 0) {
            g_assert(_prioq_cmp(data_pop[i - 1], data_pop[i]) <= 0);
            g_assert_cmpint(*data_pop[i - 1], <=, *data_pop[i]);
        }
    }

    g_assert(!nm_prioq_pop(&q));
    g_assert(nm_prioq_size(&q) == 0);
}

/*****************************************************************************/

NMTST_DEFINE();

int
main(int argc, char **argv)
{
    nmtst_init(&argc, &argv, TRUE);

    g_test_add_func("/general/test_nm_static_assert", test_nm_static_assert);
    g_test_add_func("/general/test_gpid", test_gpid);
    g_test_add_func("/general/test_monotonic_timestamp", test_monotonic_timestamp);
    g_test_add_func("/general/test_timespect_to", test_timespect_to);
    g_test_add_func("/general/test_nmhash", test_nmhash);
    g_test_add_func("/general/test_nm_make_strv", test_make_strv);
    g_test_add_func("/general/test_nm_strdup_int", test_nm_strdup_int);
    g_test_add_func("/general/test_nm_strndup_a", test_nm_strndup_a);
    g_test_add_func("/general/test_nm_ip4_addr_is_loopback", test_nm_ip4_addr_is_loopback);
    g_test_add_func("/general/test_nm_ip4_addr_netmask_from_prefix",
                    test_nm_ip4_addr_netmask_from_prefix);
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
    g_test_add_func("/general/test_nm_g_source_sentinel", test_nm_g_source_sentinel);
    g_test_add_func("/general/test_nm_ascii", test_nm_ascii);
    g_test_add_func("/general/test_parse_env_file", test_parse_env_file);
    g_test_add_func("/general/test_unbase64char", test_unbase64char);
    g_test_add_func("/general/test_unbase64mem1", test_unbase64mem1);
    g_test_add_func("/general/test_unbase64mem2", test_unbase64mem2);
    g_test_add_func("/general/test_unbase64mem3", test_unbase64mem3);
    g_test_add_func("/general/test_path_compare", test_path_compare);
    g_test_add_func("/general/test_path_equal", test_path_equal);
    g_test_add_func("/general/test_path_find_first_component", test_path_find_first_component);
    g_test_add_func("/general/test_path_startswith", test_path_startswith);
    g_test_add_func("/general/test_path_simplify", test_path_simplify);
    g_test_add_func("/general/test_hostname_is_valid", test_hostname_is_valid);
    g_test_add_func("/general/test_inet_utils", test_inet_utils);
    g_test_add_func("/general/test_inet_parse_ip4_legacy", test_inet_parse_ip4_legacy);
    g_test_add_func("/general/test_garray", test_garray);
    g_test_add_func("/general/test_nm_prioq", test_nm_prioq);
    g_test_add_func("/general/test_nm_random", test_nm_random);

    return g_test_run();
}
