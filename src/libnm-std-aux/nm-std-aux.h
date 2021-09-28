/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NM_STD_AUX_H__
#define __NM_STD_AUX_H__

#include <assert.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stddef.h>

/*****************************************************************************/

#define _nm_packed             __attribute__((__packed__))
#define _nm_unused             __attribute__((__unused__))
#define _nm_used               __attribute__((__used__))
#define _nm_pure               __attribute__((__pure__))
#define _nm_const              __attribute__((__const__))
#define _nm_warn_unused_result __attribute__((__warn_unused_result__))
#define _nm_printf(a, b)       __attribute__((__format__(__printf__, a, b)))
#define _nm_align(s)           __attribute__((__aligned__(s)))
#define _nm_section(s)         __attribute__((__section__(s)))
#define _nm_alignof(type)      __alignof(type)
#define _nm_alignas(type)      _nm_align(_nm_alignof(type))
#define _nm_deprecated(msg)    __attribute__((__deprecated__(msg)))
#define nm_auto(fcn)           __attribute__((__cleanup__(fcn)))

#define _nm_nil

/* This is required to make LTO working.
 *
 * See https://gitlab.freedesktop.org/NetworkManager/NetworkManager/merge_requests/76#note_112694
 *     https://gcc.gnu.org/bugzilla/show_bug.cgi?id=48200#c28
 */
#ifndef __clang__
#define _nm_externally_visible __attribute__((__externally_visible__))
#else
#define _nm_externally_visible
#endif

#if __GNUC__ >= 7
#define _nm_fallthrough __attribute__((__fallthrough__))
#else
#define _nm_fallthrough
#endif

/*****************************************************************************/

#ifndef _NM_CC_SUPPORT_AUTO_TYPE
#if (defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 9)))
#define _NM_CC_SUPPORT_AUTO_TYPE 1
#else
#define _NM_CC_SUPPORT_AUTO_TYPE 0
#endif
#endif

#if _NM_CC_SUPPORT_AUTO_TYPE
#define _nm_auto_type __auto_type
#endif

#ifndef _NM_CC_SUPPORT_GENERIC
/* In the meantime, NetworkManager requires C11 and _Generic() should always be available.
 * However, shared/nm-utils may also be used in VPN/applet, which possibly did not yet
 * bump the C standard requirement. Leave this for the moment, but eventually we can
 * drop it.
 *
 * Technically, gcc 4.9 already has some support for _Generic(). But there seems
 * to be issues with propagating "const char *[5]" to "const char **". Only assume
 * we have _Generic() since gcc 5. */
#if (defined(__GNUC__) && __GNUC__ >= 5) || (defined(__clang__))
#define _NM_CC_SUPPORT_GENERIC 1
#else
#define _NM_CC_SUPPORT_GENERIC 0
#endif
#endif

/*****************************************************************************/

#ifdef __CHECKER__
#define _nm_bitwise __attribute__((__bitwise__))
#define _nm_force   __attribute__((__force__))
#else
#define _nm_bitwise
#define _nm_force
#endif

typedef uint16_t _nm_bitwise nm_le16_t;
typedef uint16_t _nm_bitwise nm_be16_t;
typedef uint32_t _nm_bitwise nm_le32_t;
typedef uint32_t _nm_bitwise nm_be32_t;
typedef uint64_t _nm_bitwise nm_le64_t;
typedef uint64_t _nm_bitwise nm_be64_t;

/*****************************************************************************/

#ifdef thread_local
#define _nm_thread_local thread_local
/*
 * Don't break on glibc < 2.16 that doesn't define __STDC_NO_THREADS__
 * see http://gcc.gnu.org/bugzilla/show_bug.cgi?id=53769
 */
#elif __STDC_VERSION__ >= 201112L     \
    && !(defined(__STDC_NO_THREADS__) \
         || (defined(__GNU_LIBRARY__) && __GLIBC__ == 2 && __GLIBC_MINOR__ < 16))
#define _nm_thread_local _Thread_local
#else
#define _nm_thread_local __thread
#endif

/*****************************************************************************/

#define _NM_DUMMY_STRUCT_FOR_TRAILING_SEMICOLON struct _nm_dummy_struct_for_trailing_semicolon

/*****************************************************************************/

#define NM_BIT(n) (1ull << (n))

/*****************************************************************************/

#define NM_PASTE_ARGS(identifier1, identifier2) identifier1##identifier2
#define NM_PASTE(identifier1, identifier2)      NM_PASTE_ARGS(identifier1, identifier2)

/* Taken from systemd's UNIQ_T and UNIQ macros. */

#define NM_UNIQ_T(x, uniq) NM_PASTE(__unique_prefix_, NM_PASTE(x, uniq))
#define NM_UNIQ            __COUNTER__

/*****************************************************************************/

#define _NM_BOOLEAN_EXPR_IMPL(v, expr) \
    ({                                 \
        int NM_UNIQ_T(V, v);           \
                                       \
        if (expr)                      \
            NM_UNIQ_T(V, v) = 1;       \
        else                           \
            NM_UNIQ_T(V, v) = 0;       \
        NM_UNIQ_T(V, v);               \
    })
#define NM_BOOLEAN_EXPR(expr) _NM_BOOLEAN_EXPR_IMPL(NM_UNIQ, expr)

#if defined(__GNUC__) && (__GNUC__ > 2) && defined(__OPTIMIZE__)
#define NM_LIKELY(expr)   (__builtin_expect(NM_BOOLEAN_EXPR(expr), 1))
#define NM_UNLIKELY(expr) (__builtin_expect(NM_BOOLEAN_EXPR(expr), 0))
#else
#define NM_LIKELY(expr)   NM_BOOLEAN_EXPR(expr)
#define NM_UNLIKELY(expr) NM_BOOLEAN_EXPR(expr)
#endif

/*****************************************************************************/

/* glib/C provides the following kind of assertions:
 *   - assert() -- disable with NDEBUG
 *   - g_return_if_fail() -- disable with G_DISABLE_CHECKS
 *   - g_assert() -- disable with G_DISABLE_ASSERT
 * but they are all enabled by default and usually even production builds have
 * these kind of assertions enabled. It also means, that disabling assertions
 * is an untested configuration, and might have bugs.
 *
 * Add our own assertion macro nm_assert(), which is disabled by default and must
 * be explicitly enabled. They are useful for more expensive checks or checks that
 * depend less on runtime conditions (that is, are generally expected to be true). */

#ifndef NM_MORE_ASSERTS
#define NM_MORE_ASSERTS 0
#endif

#ifndef _nm_assert_call
#define _nm_assert_call(cond)         assert(cond)
#define _nm_assert_call_not_reached() assert(0)
#endif

#if NM_MORE_ASSERTS
#define nm_assert(cond)        \
    ({                         \
        _nm_assert_call(cond); \
        1;                     \
    })
#define nm_assert_se(cond)                \
    ({                                    \
        if (NM_LIKELY(cond)) {            \
            ;                             \
        } else {                          \
            _nm_assert_call(0 && (cond)); \
        }                                 \
        1;                                \
    })
#define nm_assert_not_reached()        \
    ({                                 \
        _nm_assert_call_not_reached(); \
        1;                             \
    })
#else
#define nm_assert(cond)  \
    ({                   \
        if (0) {         \
            if (cond) {} \
        }                \
        1;               \
    })
#define nm_assert_se(cond)     \
    ({                         \
        if (NM_LIKELY(cond)) { \
            ;                  \
        }                      \
        1;                     \
    })
#define nm_assert_not_reached() ({ 1; })
#endif

/* This is similar nm_assert_not_reached(), but it's supposed to be used only during
 * development. Like _XXX_ comments, they can be used as a marker that something still
 * needs to be done. */
#define XXX(msg)   \
    nm_assert(!"X" \
               "XX error: " msg "")

#define nm_assert_unreachable_val(val) \
    ({                                 \
        nm_assert_not_reached();       \
        (val);                         \
    })

#define NM_STATIC_ASSERT(cond) static_assert(cond, "")
#define NM_STATIC_ASSERT_EXPR_1(cond) \
    (sizeof(struct { char __static_assert_expr_1[(cond) ? 1 : -1]; }) == 1)
#define NM_STATIC_ASSERT_EXPR_VOID(cond) \
    ((void) (sizeof(struct { char __static_assert_expr_void[(cond) ? 1 : -1]; }) == 1))

/*****************************************************************************/

#define NM_N_ELEMENTS(arr) (sizeof(arr) / sizeof((arr)[0]))

/*****************************************************************************/

#define nm_offsetof(t, m) offsetof(t, m)

#define nm_offsetofend(t, m) (nm_offsetof(t, m) + sizeof(((t *) NULL)->m))

/*****************************************************************************/

/* This does a compile time check that "type" is a suitable C type. It either
 * returns a compile time constant of 1 or it fails compilation. The point
 * is only in macros to check that a macro parameter (what we might pass to
 * sizeof() is really a type, and not a variable. */
#define NM_ENSURE_IS_TYPE(type) (sizeof(void (*)(type[])) == sizeof(void (*)(void *)))

/*****************************************************************************/

#if _NM_CC_SUPPORT_GENERIC
/* returns @value, if the type of @value matches @type.
     * This requires support for C11 _Generic(). If no support is
     * present, this returns @value directly.
     *
     * It's useful to check the let the compiler ensure that @value is
     * of a certain type. */
#define _NM_ENSURE_TYPE(type, value) (_Generic((value), type : (value)))
#define _NM_ENSURE_TYPE_CONST(type, value)              \
    (_Generic((value), const type                       \
              : ((const type)(value)), const type const \
              : ((const type)(value)), type             \
              : ((const type)(value)), type const       \
              : ((const type)(value))))
#else
#define _NM_ENSURE_TYPE(type, value)       (value)
#define _NM_ENSURE_TYPE_CONST(type, value) ((const type)(value))
#endif

/* returns void, but does a compile time check that the argument is a pointer
 * (that is, can be converted to (const void *)). It does not actually evaluate
 * (value). That means, it's also safe to call _NM_ENSURE_POINTER(array[0]) if
 * array might be NULL. It's also safe to call on a macro argument that is
 * supposed to be evaluate at most once (this macro will not "execute" the
 * argument). */
#define _NM_ENSURE_POINTER(value)                                                 \
    do {                                                                          \
        _nm_unused const void *const _unused_for_type_check = 0 ? (value) : NULL; \
    } while (0)

#if _NM_CC_SUPPORT_GENERIC && (!defined(__clang__) || __clang_major__ > 3)
#define NM_STRUCT_OFFSET_ENSURE_TYPE(type, container, field) \
    (_Generic((&(((container *) NULL)->field))[0], type : nm_offsetof(container, field)))
#else
#define NM_STRUCT_OFFSET_ENSURE_TYPE(type, container, field) nm_offsetof(container, field)
#endif

/*****************************************************************************/

static inline uint32_t
nm_add_clamped_u32(uint32_t a, uint32_t b)
{
    uint32_t c;

    /* returns a+b, or UINT32_MAX if the result would overflow. */

    c = a + b;
    if (c < a)
        return UINT32_MAX;
    return c;
}

static inline unsigned
nm_mult_clamped_u(unsigned a, unsigned b)
{
    unsigned c;

    /* returns a*b, or UINT_MAX if the result would overflow. */

    if (b == 0)
        return 0;

    c = a * b;

    if (c / b != a)
        return (unsigned) -1;

    return c;
}

/* glib's MIN()/MAX() macros don't have function-like behavior, in that they evaluate
 * the argument possibly twice.
 *
 * Taken from systemd's MIN()/MAX() macros. */

#define NM_MIN(a, b) __NM_MIN(NM_UNIQ, a, NM_UNIQ, b)
#define __NM_MIN(aq, a, bq, b)                                                         \
    ({                                                                                 \
        typeof(a) NM_UNIQ_T(A, aq) = (a);                                              \
        typeof(b) NM_UNIQ_T(B, bq) = (b);                                              \
        ((NM_UNIQ_T(A, aq) < NM_UNIQ_T(B, bq)) ? NM_UNIQ_T(A, aq) : NM_UNIQ_T(B, bq)); \
    })

#define NM_MAX(a, b) __NM_MAX(NM_UNIQ, a, NM_UNIQ, b)
#define __NM_MAX(aq, a, bq, b)                                                         \
    ({                                                                                 \
        typeof(a) NM_UNIQ_T(A, aq) = (a);                                              \
        typeof(b) NM_UNIQ_T(B, bq) = (b);                                              \
        ((NM_UNIQ_T(A, aq) > NM_UNIQ_T(B, bq)) ? NM_UNIQ_T(A, aq) : NM_UNIQ_T(B, bq)); \
    })

#define NM_CLAMP(x, low, high) __NM_CLAMP(NM_UNIQ, x, NM_UNIQ, low, NM_UNIQ, high)
#define __NM_CLAMP(xq, x, lowq, low, highq, high)                             \
    ({                                                                        \
        typeof(x)    NM_UNIQ_T(X, xq)       = (x);                            \
        typeof(low)  NM_UNIQ_T(LOW, lowq)   = (low);                          \
        typeof(high) NM_UNIQ_T(HIGH, highq) = (high);                         \
                                                                              \
        ((NM_UNIQ_T(X, xq) > NM_UNIQ_T(HIGH, highq)) ? NM_UNIQ_T(HIGH, highq) \
         : (NM_UNIQ_T(X, xq) < NM_UNIQ_T(LOW, lowq)) ? NM_UNIQ_T(LOW, lowq)   \
                                                     : NM_UNIQ_T(X, xq));     \
    })

#define NM_MAX_WITH_CMP(cmp, a, b)        \
    ({                                    \
        typeof(a) _a = (a);               \
        typeof(b) _b = (b);               \
                                          \
        (((cmp(_a, _b)) >= 0) ? _a : _b); \
    })

/* evaluates to (void) if _A or _B are not constant or of different types */
#define NM_CONST_MAX(_A, _B)                                                          \
    (__builtin_choose_expr((__builtin_constant_p(_A) && __builtin_constant_p(_B)      \
                            && __builtin_types_compatible_p(typeof(_A), typeof(_B))), \
                           ((_A) > (_B)) ? (_A) : (_B),                               \
                           ((void) 0)))

/* Determine whether @x is a power of two (@x being an integer type).
 * Basically, this returns TRUE, if @x has exactly one bit set.
 * For negative values and zero, this always returns FALSE. */
#define nm_utils_is_power_of_two(x)                       \
    ({                                                    \
        typeof(x)         _x2  = (x);                     \
        const typeof(_x2) _X_0 = ((typeof(_x2)) 0);       \
        const typeof(_x2) _X_1 = ((typeof(_x2)) 1);       \
                                                          \
        ((_x2 > _X_0) && ((_x2 & (_x2 - _X_1)) == _X_0)); \
    })

#define nm_utils_is_power_of_two_or_zero(x)            \
    ({                                                 \
        typeof(x) _x1 = (x);                           \
                                                       \
        ((_x1 == 0) || nm_utils_is_power_of_two(_x1)); \
    })

/*****************************************************************************/

#define NM_SWAP(p_a, p_b)                   \
    do {                                    \
        typeof(*(p_a)) *const _p_a = (p_a); \
        typeof(*(p_a)) *const _p_b = (p_b); \
        typeof(*(p_a))        _tmp;         \
                                            \
        _tmp  = *_p_a;                      \
        *_p_a = *_p_b;                      \
        *_p_b = _tmp;                       \
    } while (0)

/*****************************************************************************/

/* macro to return strlen() of a compile time string. */
#define NM_STRLEN(str) (sizeof("" str "") - 1u)

static inline size_t
_nm_ptrarray_len_impl(const void *const *array)
{
    size_t n = 0;

    if (array) {
        while (array[n])
            n++;
    }
    return n;
}

/* returns the length of a NULL terminated array of pointers,
 * like g_strv_length() does. The difference is:
 *  - it operates on arrays of pointers (of any kind, requiring no cast).
 *  - it accepts NULL to return zero. */
#define NM_PTRARRAY_LEN(array)                                \
    ({                                                        \
        _NM_ENSURE_POINTER((array)[0]);                       \
        _nm_ptrarray_len_impl((const void *const *) (array)); \
    })

/*****************************************************************************/

static inline int
nm_strcmp0(const char *s1, const char *s2)
{
    int c;

    /* like g_strcmp0(), but this is inlinable.
     *
     * Also, it is guaranteed to return either -1, 0, or 1. */
    if (s1 == s2)
        return 0;
    if (!s1)
        return -1;
    if (!s2)
        return 1;
    c = strcmp(s1, s2);
    if (c < 0)
        return -1;
    if (c > 0)
        return 1;
    return 0;
}

static inline int
nm_streq(const char *s1, const char *s2)
{
    return strcmp(s1, s2) == 0;
}

static inline int
nm_streq0(const char *s1, const char *s2)
{
    return (s1 == s2) || (s1 && s2 && strcmp(s1, s2) == 0);
}

#define NM_STR_HAS_PREFIX(str, prefix)                                                       \
    ({                                                                                       \
        const char *const _str_has_prefix = (str);                                           \
                                                                                             \
        nm_assert(strlen(prefix) == NM_STRLEN(prefix));                                      \
                                                                                             \
        _str_has_prefix && (strncmp(_str_has_prefix, "" prefix "", NM_STRLEN(prefix)) == 0); \
    })

#define NM_STR_HAS_SUFFIX(str, suffix)                                                         \
    ({                                                                                         \
        const char *const _str_has_suffix = (str);                                             \
        size_t            _l;                                                                  \
                                                                                               \
        nm_assert(strlen(suffix) == NM_STRLEN(suffix));                                        \
                                                                                               \
        (_str_has_suffix && ((_l = strlen(_str_has_suffix)) >= NM_STRLEN(suffix))              \
         && (memcmp(&_str_has_suffix[_l - NM_STRLEN(suffix)], "" suffix "", NM_STRLEN(suffix)) \
             == 0));                                                                           \
    })

/* whether @str starts with the string literal @prefix and is followed by
 * some other text. It is like NM_STR_HAS_PREFIX() && !nm_streq() together. */
#define NM_STR_HAS_PREFIX_WITH_MORE(str, prefix)                   \
    ({                                                             \
        const char *const _str_has_prefix_with_more = (str);       \
                                                                   \
        NM_STR_HAS_PREFIX(_str_has_prefix_with_more, "" prefix "") \
        &&_str_has_prefix_with_more[NM_STRLEN(prefix)] != '\0';    \
    })

#define NM_STR_HAS_SUFFIX_WITH_MORE(str, suffix)                                               \
    ({                                                                                         \
        const char *const _str_has_suffix = (str);                                             \
        size_t            _l;                                                                  \
                                                                                               \
        nm_assert(strlen(suffix) == NM_STRLEN(suffix));                                        \
                                                                                               \
        (_str_has_suffix && ((_l = strlen(_str_has_suffix)) > NM_STRLEN(suffix))               \
         && (memcmp(&_str_has_suffix[_l - NM_STRLEN(suffix)], "" suffix "", NM_STRLEN(suffix)) \
             == 0));                                                                           \
    })

/*****************************************************************************/

/* clang-format off */
#define _NM_MACRO_SELECT_ARG_120(_empty, \
                                 _1,   _2,   _3,   _4,   _5,   _6,   _7,   _8,   _9,   _10,  \
                                 _11,  _12,  _13,  _14,  _15,  _16,  _17,  _18,  _19,  _20,  \
                                 _21,  _22,  _23,  _24,  _25,  _26,  _27,  _28,  _29,  _30,  \
                                 _31,  _32,  _33,  _34,  _35,  _36,  _37,  _38,  _39,  _40,  \
                                 _41,  _42,  _43,  _44,  _45,  _46,  _47,  _48,  _49,  _50,  \
                                 _51,  _52,  _53,  _54,  _55,  _56,  _57,  _58,  _59,  _60,  \
                                 _61,  _62,  _63,  _64,  _65,  _66,  _67,  _68,  _69,  _70,  \
                                 _71,  _72,  _73,  _74,  _75,  _76,  _77,  _78,  _79,  _80,  \
                                 _81,  _82,  _83,  _84,  _85,  _86,  _87,  _88,  _89,  _90,  \
                                 _91,  _92,  _93,  _94,  _95,  _96,  _97,  _98,  _99,  _100, \
                                 _101, _102, _103, _104, _105, _106, _107, _108, _109, _110, \
                                 _111, _112, _113, _114, _115, _116, _117, _118, _119, _120, \
                                 N,      \
                                 ...)    \
    N

#define NM_NARG(...)                        \
    _NM_MACRO_SELECT_ARG_120(, ##__VA_ARGS__, \
                             120, \
                             119, 118, 117, 116, 115, 114, 113, 112, 111, 110, \
                             109, 108, 107, 106, 105, 104, 103, 102, 101, 100, \
                             99,  98,  97,  96,  95,  94,  93,  92,  91,  90,  \
                             89,  88,  87,  86,  85,  84,  83,  82,  81,  80,  \
                             79,  78,  77,  76,  75,  74,  73,  72,  71,  70,  \
                             69,  68,  67,  66,  65,  64,  63,  62,  61,  60,  \
                             59,  58,  57,  56,  55,  54,  53,  52,  51,  50,  \
                             49,  48,  47,  46,  45,  44,  43,  42,  41,  40,  \
                             39,  38,  37,  36,  35,  34,  33,  32,  31,  30,  \
                             29,  28,  27,  26,  25,  24,  23,  22,  21,  20,  \
                             19,  18,  17,  16,  15,  14,  13,  12,  11,  10,  \
                             9,   8,   7,   6,   5,   4,   3,   2,   1,   0)
#define NM_NARG_MAX1(...)                   \
    _NM_MACRO_SELECT_ARG_120(, ##__VA_ARGS__, \
                             1, \
                             1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 110 */ \
                             1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 100 */ \
                             1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 90  */ \
                             1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 80  */ \
                             1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 70  */ \
                             1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 60  */ \
                             1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 50  */ \
                             1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 40  */ \
                             1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 30  */ \
                             1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 20  */ \
                             1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 10  */ \
                             1, 1, 1, 1, 1, 1, 1, 1, 1, 0)
#define NM_NARG_MAX2(...)                   \
    _NM_MACRO_SELECT_ARG_120(, ##__VA_ARGS__, \
                             2, \
                             2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 110 */ \
                             2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 100 */ \
                             2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 90  */ \
                             2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 80  */ \
                             2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 70  */ \
                             2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 60  */ \
                             2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 50  */ \
                             2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 40  */ \
                             2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 30  */ \
                             2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 20  */ \
                             2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 10  */ \
                             2, 2, 2, 2, 2, 2, 2, 2, 1, 0)
/* clang-format on */

/*****************************************************************************/

#define _NM_MACRO_IDENTITY(...) __VA_ARGS__

#define _NM_MACRO_SELECT_FIRST(...)             _NM_MACRO_SELECT_FIRST_IMPL(__VA_ARGS__, throwaway)
#define _NM_MACRO_SELECT_FIRST_IMPL(first, ...) first

#define _NM_MACRO_CALL(macro, ...)  macro(__VA_ARGS__)
#define _NM_MACRO_CALL2(macro, ...) macro(__VA_ARGS__)

/*****************************************************************************/

/* clang-format off */
#define _NM_VA_ARGS_FOREACH_0(prefix, postfix, sep, op)
#define _NM_VA_ARGS_FOREACH_1(prefix, postfix, sep, op, x)          prefix _NM_MACRO_CALL2(op, x, 0  ) postfix
#define _NM_VA_ARGS_FOREACH_2(prefix, postfix, sep, op, x, ...)     prefix _NM_MACRO_CALL2(op, x, 1  ) postfix sep _NM_VA_ARGS_FOREACH_1(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_3(prefix, postfix, sep, op, x, ...)     prefix _NM_MACRO_CALL2(op, x, 2  ) postfix sep _NM_VA_ARGS_FOREACH_2(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_4(prefix, postfix, sep, op, x, ...)     prefix _NM_MACRO_CALL2(op, x, 3  ) postfix sep _NM_VA_ARGS_FOREACH_3(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_5(prefix, postfix, sep, op, x, ...)     prefix _NM_MACRO_CALL2(op, x, 4  ) postfix sep _NM_VA_ARGS_FOREACH_4(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_6(prefix, postfix, sep, op, x, ...)     prefix _NM_MACRO_CALL2(op, x, 5  ) postfix sep _NM_VA_ARGS_FOREACH_5(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_7(prefix, postfix, sep, op, x, ...)     prefix _NM_MACRO_CALL2(op, x, 6  ) postfix sep _NM_VA_ARGS_FOREACH_6(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_8(prefix, postfix, sep, op, x, ...)     prefix _NM_MACRO_CALL2(op, x, 7  ) postfix sep _NM_VA_ARGS_FOREACH_7(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_9(prefix, postfix, sep, op, x, ...)     prefix _NM_MACRO_CALL2(op, x, 8  ) postfix sep _NM_VA_ARGS_FOREACH_8(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_10(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 9  ) postfix sep _NM_VA_ARGS_FOREACH_9(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_11(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 10 ) postfix sep _NM_VA_ARGS_FOREACH_10(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_12(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 11 ) postfix sep _NM_VA_ARGS_FOREACH_11(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_13(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 12 ) postfix sep _NM_VA_ARGS_FOREACH_12(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_14(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 13 ) postfix sep _NM_VA_ARGS_FOREACH_13(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_15(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 14 ) postfix sep _NM_VA_ARGS_FOREACH_14(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_16(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 15 ) postfix sep _NM_VA_ARGS_FOREACH_15(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_17(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 16 ) postfix sep _NM_VA_ARGS_FOREACH_16(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_18(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 17 ) postfix sep _NM_VA_ARGS_FOREACH_17(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_19(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 18 ) postfix sep _NM_VA_ARGS_FOREACH_18(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_20(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 19 ) postfix sep _NM_VA_ARGS_FOREACH_19(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_21(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 20 ) postfix sep _NM_VA_ARGS_FOREACH_20(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_22(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 21 ) postfix sep _NM_VA_ARGS_FOREACH_21(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_23(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 22 ) postfix sep _NM_VA_ARGS_FOREACH_22(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_24(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 23 ) postfix sep _NM_VA_ARGS_FOREACH_23(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_25(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 24 ) postfix sep _NM_VA_ARGS_FOREACH_24(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_26(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 25 ) postfix sep _NM_VA_ARGS_FOREACH_25(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_27(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 26 ) postfix sep _NM_VA_ARGS_FOREACH_26(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_28(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 27 ) postfix sep _NM_VA_ARGS_FOREACH_27(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_29(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 28 ) postfix sep _NM_VA_ARGS_FOREACH_28(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_30(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 29 ) postfix sep _NM_VA_ARGS_FOREACH_29(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_31(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 30 ) postfix sep _NM_VA_ARGS_FOREACH_30(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_32(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 31 ) postfix sep _NM_VA_ARGS_FOREACH_31(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_33(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 32 ) postfix sep _NM_VA_ARGS_FOREACH_32(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_34(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 33 ) postfix sep _NM_VA_ARGS_FOREACH_33(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_35(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 34 ) postfix sep _NM_VA_ARGS_FOREACH_34(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_36(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 35 ) postfix sep _NM_VA_ARGS_FOREACH_35(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_37(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 36 ) postfix sep _NM_VA_ARGS_FOREACH_36(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_38(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 37 ) postfix sep _NM_VA_ARGS_FOREACH_37(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_39(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 38 ) postfix sep _NM_VA_ARGS_FOREACH_38(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_40(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 39 ) postfix sep _NM_VA_ARGS_FOREACH_39(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_41(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 40 ) postfix sep _NM_VA_ARGS_FOREACH_40(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_42(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 41 ) postfix sep _NM_VA_ARGS_FOREACH_41(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_43(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 42 ) postfix sep _NM_VA_ARGS_FOREACH_42(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_44(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 43 ) postfix sep _NM_VA_ARGS_FOREACH_43(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_45(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 44 ) postfix sep _NM_VA_ARGS_FOREACH_44(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_46(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 45 ) postfix sep _NM_VA_ARGS_FOREACH_45(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_47(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 46 ) postfix sep _NM_VA_ARGS_FOREACH_46(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_48(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 47 ) postfix sep _NM_VA_ARGS_FOREACH_47(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_49(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 48 ) postfix sep _NM_VA_ARGS_FOREACH_48(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_50(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 49 ) postfix sep _NM_VA_ARGS_FOREACH_49(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_51(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 50 ) postfix sep _NM_VA_ARGS_FOREACH_50(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_52(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 51 ) postfix sep _NM_VA_ARGS_FOREACH_51(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_53(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 52 ) postfix sep _NM_VA_ARGS_FOREACH_52(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_54(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 53 ) postfix sep _NM_VA_ARGS_FOREACH_53(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_55(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 54 ) postfix sep _NM_VA_ARGS_FOREACH_54(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_56(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 55 ) postfix sep _NM_VA_ARGS_FOREACH_55(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_57(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 56 ) postfix sep _NM_VA_ARGS_FOREACH_56(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_58(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 57 ) postfix sep _NM_VA_ARGS_FOREACH_57(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_59(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 58 ) postfix sep _NM_VA_ARGS_FOREACH_58(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_60(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 59 ) postfix sep _NM_VA_ARGS_FOREACH_59(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_61(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 10 ) postfix sep _NM_VA_ARGS_FOREACH_60(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_62(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 61 ) postfix sep _NM_VA_ARGS_FOREACH_61(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_63(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 62 ) postfix sep _NM_VA_ARGS_FOREACH_62(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_64(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 63 ) postfix sep _NM_VA_ARGS_FOREACH_63(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_65(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 64 ) postfix sep _NM_VA_ARGS_FOREACH_64(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_66(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 65 ) postfix sep _NM_VA_ARGS_FOREACH_65(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_67(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 66 ) postfix sep _NM_VA_ARGS_FOREACH_66(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_68(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 67 ) postfix sep _NM_VA_ARGS_FOREACH_67(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_69(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 68 ) postfix sep _NM_VA_ARGS_FOREACH_68(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_70(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 69 ) postfix sep _NM_VA_ARGS_FOREACH_69(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_71(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 70 ) postfix sep _NM_VA_ARGS_FOREACH_70(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_72(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 71 ) postfix sep _NM_VA_ARGS_FOREACH_71(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_73(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 72 ) postfix sep _NM_VA_ARGS_FOREACH_72(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_74(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 73 ) postfix sep _NM_VA_ARGS_FOREACH_73(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_75(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 74 ) postfix sep _NM_VA_ARGS_FOREACH_74(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_76(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 75 ) postfix sep _NM_VA_ARGS_FOREACH_75(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_77(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 76 ) postfix sep _NM_VA_ARGS_FOREACH_76(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_78(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 77 ) postfix sep _NM_VA_ARGS_FOREACH_77(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_79(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 78 ) postfix sep _NM_VA_ARGS_FOREACH_78(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_80(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 79 ) postfix sep _NM_VA_ARGS_FOREACH_79(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_81(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 80 ) postfix sep _NM_VA_ARGS_FOREACH_80(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_82(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 81 ) postfix sep _NM_VA_ARGS_FOREACH_81(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_83(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 82 ) postfix sep _NM_VA_ARGS_FOREACH_82(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_84(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 83 ) postfix sep _NM_VA_ARGS_FOREACH_83(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_85(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 84 ) postfix sep _NM_VA_ARGS_FOREACH_84(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_86(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 85 ) postfix sep _NM_VA_ARGS_FOREACH_85(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_87(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 86 ) postfix sep _NM_VA_ARGS_FOREACH_86(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_88(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 87 ) postfix sep _NM_VA_ARGS_FOREACH_87(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_89(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 88 ) postfix sep _NM_VA_ARGS_FOREACH_88(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_90(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 89 ) postfix sep _NM_VA_ARGS_FOREACH_89(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_91(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 90 ) postfix sep _NM_VA_ARGS_FOREACH_90(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_92(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 91 ) postfix sep _NM_VA_ARGS_FOREACH_91(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_93(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 92 ) postfix sep _NM_VA_ARGS_FOREACH_92(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_94(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 93 ) postfix sep _NM_VA_ARGS_FOREACH_93(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_95(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 94 ) postfix sep _NM_VA_ARGS_FOREACH_94(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_96(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 95 ) postfix sep _NM_VA_ARGS_FOREACH_95(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_97(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 96 ) postfix sep _NM_VA_ARGS_FOREACH_96(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_98(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 97 ) postfix sep _NM_VA_ARGS_FOREACH_97(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_99(prefix, postfix, sep, op, x, ...)    prefix _NM_MACRO_CALL2(op, x, 98 ) postfix sep _NM_VA_ARGS_FOREACH_98(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_100(prefix, postfix, sep, op, x, ...)   prefix _NM_MACRO_CALL2(op, x, 99 ) postfix sep _NM_VA_ARGS_FOREACH_99(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_101(prefix, postfix, sep, op, x, ...)   prefix _NM_MACRO_CALL2(op, x, 100) postfix sep _NM_VA_ARGS_FOREACH_100(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_102(prefix, postfix, sep, op, x, ...)   prefix _NM_MACRO_CALL2(op, x, 101) postfix sep _NM_VA_ARGS_FOREACH_101(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_103(prefix, postfix, sep, op, x, ...)   prefix _NM_MACRO_CALL2(op, x, 102) postfix sep _NM_VA_ARGS_FOREACH_102(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_104(prefix, postfix, sep, op, x, ...)   prefix _NM_MACRO_CALL2(op, x, 103) postfix sep _NM_VA_ARGS_FOREACH_103(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_105(prefix, postfix, sep, op, x, ...)   prefix _NM_MACRO_CALL2(op, x, 104) postfix sep _NM_VA_ARGS_FOREACH_104(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_106(prefix, postfix, sep, op, x, ...)   prefix _NM_MACRO_CALL2(op, x, 105) postfix sep _NM_VA_ARGS_FOREACH_105(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_107(prefix, postfix, sep, op, x, ...)   prefix _NM_MACRO_CALL2(op, x, 106) postfix sep _NM_VA_ARGS_FOREACH_106(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_108(prefix, postfix, sep, op, x, ...)   prefix _NM_MACRO_CALL2(op, x, 107) postfix sep _NM_VA_ARGS_FOREACH_107(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_109(prefix, postfix, sep, op, x, ...)   prefix _NM_MACRO_CALL2(op, x, 108) postfix sep _NM_VA_ARGS_FOREACH_108(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_110(prefix, postfix, sep, op, x, ...)   prefix _NM_MACRO_CALL2(op, x, 109) postfix sep _NM_VA_ARGS_FOREACH_109(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_111(prefix, postfix, sep, op, x, ...)   prefix _NM_MACRO_CALL2(op, x, 100) postfix sep _NM_VA_ARGS_FOREACH_110(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_112(prefix, postfix, sep, op, x, ...)   prefix _NM_MACRO_CALL2(op, x, 111) postfix sep _NM_VA_ARGS_FOREACH_111(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_113(prefix, postfix, sep, op, x, ...)   prefix _NM_MACRO_CALL2(op, x, 112) postfix sep _NM_VA_ARGS_FOREACH_112(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_114(prefix, postfix, sep, op, x, ...)   prefix _NM_MACRO_CALL2(op, x, 113) postfix sep _NM_VA_ARGS_FOREACH_113(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_115(prefix, postfix, sep, op, x, ...)   prefix _NM_MACRO_CALL2(op, x, 114) postfix sep _NM_VA_ARGS_FOREACH_114(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_116(prefix, postfix, sep, op, x, ...)   prefix _NM_MACRO_CALL2(op, x, 115) postfix sep _NM_VA_ARGS_FOREACH_115(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_117(prefix, postfix, sep, op, x, ...)   prefix _NM_MACRO_CALL2(op, x, 116) postfix sep _NM_VA_ARGS_FOREACH_116(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_118(prefix, postfix, sep, op, x, ...)   prefix _NM_MACRO_CALL2(op, x, 117) postfix sep _NM_VA_ARGS_FOREACH_117(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_119(prefix, postfix, sep, op, x, ...)   prefix _NM_MACRO_CALL2(op, x, 118) postfix sep _NM_VA_ARGS_FOREACH_118(prefix, postfix, sep, op, __VA_ARGS__)
#define _NM_VA_ARGS_FOREACH_120(prefix, postfix, sep, op, x, ...)   prefix _NM_MACRO_CALL2(op, x, 119) postfix sep _NM_VA_ARGS_FOREACH_119(prefix, postfix, sep, op, __VA_ARGS__)
/* clang-format on */
#define NM_VA_ARGS_FOREACH(prefix, postfix, sep, op, ...)                \
    _NM_MACRO_CALL(NM_PASTE(_NM_VA_ARGS_FOREACH_, NM_NARG(__VA_ARGS__)), \
                   prefix,                                               \
                   postfix,                                              \
                   sep,                                                  \
                   op,                                                   \
                   ##__VA_ARGS__)

/*****************************************************************************/

#define NM_VA_ARGS_JOIN(sep, ...) NM_VA_ARGS_FOREACH(, , sep, _NM_MACRO_SELECT_FIRST, __VA_ARGS__)

/*****************************************************************************/

#define _NM_IN_SET_OP(x, idx) (_x == (x))
#define _NM_IN_SET(op, type, x, ...)                                \
    ({                                                              \
        type _x = (x);                                              \
                                                                    \
        /* trigger a -Wenum-compare warning */                      \
        nm_assert(true || _x == (x));                               \
                                                                    \
        !!(NM_VA_ARGS_FOREACH(, , op, _NM_IN_SET_OP, __VA_ARGS__)); \
    })

/* Beware that this does short-circuit evaluation (use "||" instead of "|")
 * which has a possibly unexpected non-function-like behavior.
 * Use NM_IN_SET_SE if you need all arguments to be evaluated. */
#define NM_IN_SET(x, ...) _NM_IN_SET(||, typeof(x), x, __VA_ARGS__)

/* "SE" stands for "side-effect". Contrary to NM_IN_SET(), this does not do
 * short-circuit evaluation, which can make a difference if the arguments have
 * side-effects. */
#define NM_IN_SET_SE(x, ...) _NM_IN_SET(|, typeof(x), x, __VA_ARGS__)

/* the *_TYPED forms allow to explicitly select the type of "x". This is useful
 * if "x" doesn't support typeof (bitfields) or you want to gracefully convert
 * a type using automatic type conversion rules (but not forcing the conversion
 * with a cast). */
#define NM_IN_SET_TYPED(type, x, ...)    _NM_IN_SET(||, type, x, __VA_ARGS__)
#define NM_IN_SET_SE_TYPED(type, x, ...) _NM_IN_SET(|, type, x, __VA_ARGS__)

/*****************************************************************************/

static inline int
_NM_IN_STRSET_EVAL_op_streq(const char *x1, const char *x)
{
    return x && nm_streq(x1, x);
}

#define _NM_IN_STRSET_EVAL_OP_NULL(x, idx)  (((const char *) NULL) == (x))
#define _NM_IN_STRSET_EVAL_OP_STREQ(x, idx) _NM_IN_STRSET_EVAL_op_streq(_x1, x)
#define _NM_IN_STRSET_EVAL(op, eval_op, x1, ...)                                         \
    ({                                                                                   \
        const char *const _x1 = (x1);                                                    \
                                                                                         \
        !!(_x1 ? (NM_VA_ARGS_FOREACH(, , op, eval_op, __VA_ARGS__))                      \
               : (NM_VA_ARGS_FOREACH(, , op, _NM_IN_STRSET_EVAL_OP_NULL, __VA_ARGS__))); \
    })

/* Beware that this does short-circuit evaluation (use "||" instead of "|")
 * which has a possibly unexpected non-function-like behavior.
 * Use NM_IN_STRSET_SE if you need all arguments to be evaluated. */
#define NM_IN_STRSET(x1, ...) _NM_IN_STRSET_EVAL(||, _NM_IN_STRSET_EVAL_OP_STREQ, x1, __VA_ARGS__)

/* "SE" stands for "side-effect". Contrary to NM_IN_STRSET(), this does not do
 * short-circuit evaluation, which can make a difference if the arguments have
 * side-effects. */
#define NM_IN_STRSET_SE(x1, ...) _NM_IN_STRSET_EVAL(|, _NM_IN_STRSET_EVAL_OP_STREQ, x1, __VA_ARGS__)

/*****************************************************************************/

#define NM_STRCHAR_ALL(str, ch_iter, predicate) \
    ({                                          \
        int         _val = true;                \
        const char *_str = (str);               \
                                                \
        if (_str) {                             \
            for (;;) {                          \
                const char ch_iter = _str[0];   \
                                                \
                if (ch_iter != '\0') {          \
                    if (predicate) {            \
                        _str++;                 \
                        continue;               \
                    }                           \
                    _val = false;               \
                }                               \
                break;                          \
            }                                   \
        }                                       \
        _val;                                   \
    })

#define NM_STRCHAR_ANY(str, ch_iter, predicate) \
    ({                                          \
        int         _val = false;               \
        const char *_str = (str);               \
                                                \
        if (_str) {                             \
            for (;;) {                          \
                const char ch_iter = _str[0];   \
                                                \
                if (ch_iter != '\0') {          \
                    if (predicate) {            \
                        ;                       \
                    } else {                    \
                        _str++;                 \
                        continue;               \
                    }                           \
                    _val = true;                \
                }                               \
                break;                          \
            }                                   \
        }                                       \
        _val;                                   \
    })

/*****************************************************************************/

/**
 * nm_close:
 *
 * Like close() but throws an assertion if the input fd is
 * invalid.  Closing an invalid fd is a programming error, so
 * it's better to catch it early.
 */
static inline int
nm_close(int fd)
{
    int r;

    r = close(fd);
    nm_assert(r != -1 || fd < 0 || errno != EBADF);
    return r;
}

static inline bool
nm_clear_fd(int *p_fd)
{
    int fd;

    if (!p_fd || (fd = *p_fd) < 0)
        return false;

    *p_fd = -1;
    nm_close(fd);
    return true;
}

/*****************************************************************************/

/* Note: @value is only evaluated when *out_val is present.
 * Thus,
 *    NM_SET_OUT (out_str, g_strdup ("hallo"));
 * does the right thing.
 */
#define NM_SET_OUT(out_val, value)                \
    ({                                            \
        typeof(*(out_val)) *_out_val = (out_val); \
                                                  \
        if (_out_val) {                           \
            *_out_val = (value);                  \
        }                                         \
                                                  \
        (!!_out_val);                             \
    })

/*****************************************************************************/

#define NM_AUTO_DEFINE_FCN_VOID(CastType, name, func) \
    static inline void name(void *v)                  \
    {                                                 \
        func(*((CastType *) v));                      \
    }                                                 \
    _NM_DUMMY_STRUCT_FOR_TRAILING_SEMICOLON

#define NM_AUTO_DEFINE_FCN_VOID0(CastType, name, func) \
    static inline void name(void *v)                   \
    {                                                  \
        if (*((CastType *) v))                         \
            func(*((CastType *) v));                   \
    }                                                  \
    _NM_DUMMY_STRUCT_FOR_TRAILING_SEMICOLON

#define NM_AUTO_DEFINE_FCN(Type, name, func) \
    static inline void name(Type *v)         \
    {                                        \
        func(*v);                            \
    }                                        \
    _NM_DUMMY_STRUCT_FOR_TRAILING_SEMICOLON

#define NM_AUTO_DEFINE_FCN0(Type, name, func) \
    static inline void name(Type *v)          \
    {                                         \
        if (*v)                               \
            func(*v);                         \
    }                                         \
    _NM_DUMMY_STRUCT_FOR_TRAILING_SEMICOLON

/*****************************************************************************/

/**
 * nm_auto_free:
 *
 * Call free() on a variable location when it goes out of scope.
 * This is for pointers that are allocated with malloc() instead of
 * g_malloc().
 *
 * In practice, since glib 2.45, g_malloc()/g_free() always wraps malloc()/free().
 * See bgo#751592. In that case, it would be safe to free pointers allocated with
 * malloc() with gs_free or g_free().
 *
 * However, let's never mix them. To free malloc'ed memory, always use
 * free() or nm_auto_free.
 */
NM_AUTO_DEFINE_FCN_VOID0(void *, _nm_auto_free_impl, free);
#define nm_auto_free nm_auto(_nm_auto_free_impl)

static inline void
_nm_auto_protect_errno(const int *p_saved_errno)
{
    errno = *p_saved_errno;
}
#define NM_AUTO_PROTECT_ERRNO(errsv_saved) \
    nm_auto(_nm_auto_protect_errno) _nm_unused const int errsv_saved = (errno)

/*****************************************************************************/

static inline void
_nm_auto_close(int *pfd)
{
    if (*pfd >= 0) {
        NM_AUTO_PROTECT_ERRNO(errsv);
        (void) nm_close(*pfd);
    }
}
#define nm_auto_close nm_auto(_nm_auto_close)

static inline void
_nm_auto_fclose(FILE **pfd)
{
    if (*pfd) {
        NM_AUTO_PROTECT_ERRNO(errsv);
        (void) fclose(*pfd);
    }
}
#define nm_auto_fclose nm_auto(_nm_auto_fclose)

/*****************************************************************************/

#define nm_clear_pointer(pp, destroy)                                                \
    ({                                                                               \
        typeof(*(pp)) *_pp = (pp);                                                   \
        typeof(*_pp)   _p;                                                           \
        int            _changed = false;                                             \
                                                                                     \
        if (_pp && (_p = *_pp)) {                                                    \
            _NM_ENSURE_POINTER(_p);                                                  \
                                                                                     \
            *_pp = NULL;                                                             \
                                                                                     \
            /* g_clear_pointer() assigns @destroy first to a local variable, so that
             * you can call "g_clear_pointer (pp, (GDestroyNotify) destroy);" without
             * gcc emitting a warning. We don't do that, hence, you cannot cast
             * "destroy" first.
             *
             * On the upside: you are not supposed to cast fcn, because the pointer
             * types are preserved. If you really need a cast, you should cast @pp.
             * But that is hardly ever necessary. */ \
            (destroy)(_p);                                                           \
                                                                                     \
            _changed = true;                                                         \
        }                                                                            \
        _changed;                                                                    \
    })

#define nm_clear_free(pp) nm_clear_pointer(pp, free)

/*****************************************************************************/

#define nm_steal_pointer(pp)             \
    ({                                   \
        typeof(*(pp)) *const _pp = (pp); \
        typeof(*_pp)         _p  = *_pp; \
                                         \
        _NM_ENSURE_POINTER(_p);          \
                                         \
        *_pp = NULL;                     \
        _p;                              \
    })

/**
 * nm_steal_int:
 * @p_val: pointer to an int type.
 *
 * Returns: *p_val and sets *p_val to zero the same time.
 *   Accepts %NULL, in which case also numeric 0 will be returned.
 */
#define nm_steal_int(p_val)                   \
    ({                                        \
        typeof(p_val) const _p_val = (p_val); \
        typeof(*_p_val)     _val   = 0;       \
                                              \
        if (_p_val && (_val = *_p_val)) {     \
            *_p_val = 0;                      \
        }                                     \
        _val;                                 \
    })

static inline int
nm_steal_fd(int *p_fd)
{
    int fd;

    if (p_fd && ((fd = *p_fd) >= 0)) {
        *p_fd = -1;
        return fd;
    }
    return -1;
}

/*****************************************************************************/

static inline uintptr_t
nm_ptr_to_uintptr(const void *p)
{
    /* in C, pointers can only be compared (with less-than or greater-than) under certain
     * circumstances. Since uintptr_t is supposed to be able to represent the pointer
     * as a plain integer and also support to convert the integer back to the pointer,
     * it should be safer to compare the pointers directly.
     *
     * Of course, this function isn't very useful beyond that its use makes it clear
     * that we want to compare pointers by value, which otherwise may not be valid. */
    return (uintptr_t) p;
}

/*****************************************************************************/

#define NM_CMP_RETURN(c)             \
    do {                             \
        const int _cc = (c);         \
        if (_cc)                     \
            return _cc < 0 ? -1 : 1; \
    } while (0)

#define NM_CMP_RETURN_DIRECT(c) \
    do {                        \
        const int _cc = (c);    \
        if (_cc)                \
            return _cc;         \
    } while (0)

#define NM_CMP_SELF(a, b)   \
    do {                    \
        typeof(a) _a = (a); \
        typeof(b) _b = (b); \
                            \
        if (_a == _b)       \
            return 0;       \
        if (!_a)            \
            return -1;      \
        if (!_b)            \
            return 1;       \
    } while (0)

#define NM_CMP_DIRECT(a, b)            \
    do {                               \
        typeof(a) _a = (a);            \
        typeof(b) _b = (b);            \
                                       \
        if (_a != _b)                  \
            return (_a < _b) ? -1 : 1; \
    } while (0)

#define NM_CMP_DIRECT_UNSAFE(a, b)       \
    do {                                 \
        if ((a) != (b))                  \
            return ((a) < (b)) ? -1 : 1; \
    } while (0)

/* In the general case, direct pointer comparison is undefined behavior in C.
 * Avoid that by casting pointers to void* and then to uintptr_t. This comparison
 * is not really meaningful, except that it provides some kind of stable sort order
 * between pointers (that can otherwise not be compared). */
#define NM_CMP_DIRECT_PTR(a, b) NM_CMP_DIRECT(nm_ptr_to_uintptr(a), nm_ptr_to_uintptr(b))

#define NM_CMP_DIRECT_MEMCMP(a, b, size) NM_CMP_RETURN(memcmp((a), (b), (size)))

#define NM_CMP_DIRECT_STRCMP(a, b) NM_CMP_RETURN_DIRECT(strcmp((a), (b)))

#define NM_CMP_DIRECT_STRCMP0(a, b) NM_CMP_RETURN_DIRECT(nm_strcmp0((a), (b)))

#define NM_CMP_DIRECT_IN6ADDR(a, b)                             \
    do {                                                        \
        const struct in6_addr *const _a = (a);                  \
        const struct in6_addr *const _b = (b);                  \
        NM_CMP_RETURN(memcmp(_a, _b, sizeof(struct in6_addr))); \
    } while (0)

#define NM_CMP_FIELD(a, b, field) NM_CMP_DIRECT(((a)->field), ((b)->field))

#define NM_CMP_FIELD_UNSAFE(a, b, field)                                   \
    do {                                                                   \
        /* it's unsafe, because it evaluates the arguments more then once.
         * This is necessary for bitfields, for which typeof() doesn't work. */ \
        if (((a)->field) != ((b)->field))                                  \
            return ((a)->field < ((b)->field)) ? -1 : 1;                   \
    } while (0)

#define NM_CMP_FIELD_BOOL(a, b, field) NM_CMP_DIRECT(!!((a)->field), !!((b)->field))

#define NM_CMP_FIELD_STR(a, b, field) NM_CMP_RETURN(strcmp(((a)->field), ((b)->field)))

#define NM_CMP_FIELD_STR_INTERNED(a, b, field)        \
    do {                                              \
        const char *_a = ((a)->field);                \
        const char *_b = ((b)->field);                \
                                                      \
        if (_a != _b) {                               \
            NM_CMP_RETURN_DIRECT(nm_strcmp0(_a, _b)); \
        }                                             \
    } while (0)

#define NM_CMP_FIELD_STR0(a, b, field) NM_CMP_RETURN_DIRECT(nm_strcmp0(((a)->field), ((b)->field)))

#define NM_CMP_FIELD_MEMCMP_LEN(a, b, field, len) \
    NM_CMP_RETURN(memcmp(&((a)->field), &((b)->field), NM_MIN(len, sizeof((a)->field))))

#define NM_CMP_FIELD_MEMCMP(a, b, field) \
    NM_CMP_RETURN(memcmp(&((a)->field), &((b)->field), sizeof((a)->field)))

#define NM_CMP_FIELD_IN6ADDR(a, b, field)                       \
    do {                                                        \
        const struct in6_addr *const _a = &((a)->field);        \
        const struct in6_addr *const _b = &((b)->field);        \
        NM_CMP_RETURN(memcmp(_a, _b, sizeof(struct in6_addr))); \
    } while (0)

/*****************************************************************************/

#define NM_AF_UNSPEC 0  /* AF_UNSPEC */
#define NM_AF_INET   2  /* AF_INET   */
#define NM_AF_INET6  10 /* AF_INET6  */

#define NM_AF_INET_SIZE  4  /* sizeof (in_addr_t)      */
#define NM_AF_INET6_SIZE 16 /* sizeof (stuct in6_addr) */

static inline const char *
nm_utils_addr_family_to_str(int addr_family)
{
    switch (addr_family) {
    case NM_AF_UNSPEC:
        return "";
    case NM_AF_INET:
        return "4";
    case NM_AF_INET6:
        return "6";
    }
    nm_assert_not_reached();
    return "?";
}

static inline char
nm_utils_addr_family_to_char(int addr_family)
{
    switch (addr_family) {
    case NM_AF_UNSPEC:
        return 'X';
    case NM_AF_INET:
        return '4';
    case NM_AF_INET6:
        return '6';
    }
    nm_assert_not_reached();
    return '?';
}

#define nm_assert_addr_family(addr_family) \
    nm_assert(NM_IN_SET((addr_family), NM_AF_INET, NM_AF_INET6))

#define nm_assert_addr_family_or_unspec(addr_family) \
    nm_assert(NM_IN_SET((addr_family), NM_AF_UNSPEC, NM_AF_INET, NM_AF_INET6))

#define _NM_IS_IPv4(uniq, addr_family)                           \
    ({                                                           \
        const int NM_UNIQ_T(_addr_family, uniq) = (addr_family); \
                                                                 \
        nm_assert_addr_family(NM_UNIQ_T(_addr_family, uniq));    \
                                                                 \
        (NM_UNIQ_T(_addr_family, uniq) == NM_AF_INET);           \
    })

#define NM_IS_IPv4(addr_family) _NM_IS_IPv4(NM_UNIQ, addr_family)

static inline int
nm_utils_addr_family_other(int addr_family)
{
    return NM_IS_IPv4(addr_family) ? NM_AF_INET6 : NM_AF_INET;
}

static inline size_t
nm_utils_addr_family_to_size(int addr_family)
{
    switch (addr_family) {
    case NM_AF_INET:
        return NM_AF_INET_SIZE;
    case NM_AF_INET6:
        return NM_AF_INET6_SIZE;
    }
    return nm_assert_unreachable_val(0);
}

static inline int
nm_utils_addr_family_from_size(size_t len)
{
    switch (len) {
    case NM_AF_INET_SIZE:
        return NM_AF_INET;
    case NM_AF_INET6_SIZE:
        return NM_AF_INET6;
    }
    return NM_AF_UNSPEC;
}

#endif /* __NM_STD_AUX_H__ */
