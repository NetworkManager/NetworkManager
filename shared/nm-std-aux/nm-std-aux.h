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

/*****************************************************************************/

#define _nm_packed        __attribute__((__packed__))
#define _nm_unused        __attribute__((__unused__))
#define _nm_used          __attribute__((__used__))
#define _nm_pure          __attribute__((__pure__))
#define _nm_const         __attribute__((__const__))
#define _nm_printf(a, b)  __attribute__((__format__(__printf__, a, b)))
#define _nm_align(s)      __attribute__((__aligned__(s)))
#define _nm_section(s)    __attribute__((__section__(s)))
#define _nm_alignof(type) __alignof(type)
#define _nm_alignas(type) _nm_align(_nm_alignof(type))
#define nm_auto(fcn)      __attribute__((__cleanup__(fcn)))

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
        do {                       \
            _nm_assert_call(cond); \
        } while (0)
    #define nm_assert_se(cond)                \
        do {                                  \
            if (NM_LIKELY(cond)) {            \
                ;                             \
            } else {                          \
                _nm_assert_call(0 && (cond)); \
            }                                 \
        } while (0)
    #define nm_assert_not_reached()        \
        do {                               \
            _nm_assert_call_not_reached(); \
        } while (0)
#else
    #define nm_assert(cond)  \
        do {                 \
            if (0) {         \
                if (cond) {} \
            }                \
        } while (0)
    #define nm_assert_se(cond)     \
        do {                       \
            if (NM_LIKELY(cond)) { \
                ;                  \
            }                      \
        } while (0)
    #define nm_assert_not_reached() \
        do {                        \
            ;                       \
        } while (0)
#endif

#define nm_assert_unreachable_val(val) \
    ({                                 \
        nm_assert_not_reached();       \
        (val);                         \
    })

#define NM_STATIC_ASSERT(cond) static_assert(cond, "")
#define NM_STATIC_ASSERT_EXPR(cond) \
    ({                              \
        NM_STATIC_ASSERT(cond);     \
        1;                          \
    })

/*****************************************************************************/

#define NM_N_ELEMENTS(arr) (sizeof(arr) / sizeof((arr)[0]))

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
        typeof(x) NM_UNIQ_T(X, xq)          = (x);                            \
        typeof(low) NM_UNIQ_T(LOW, lowq)    = (low);                          \
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
        typeof(x) _x2          = (x);                     \
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
        typeof(*(p_a)) _tmp;                \
                                            \
        _tmp  = *_p_a;                      \
        *_p_a = *_p_b;                      \
        *_p_b = _tmp;                       \
    } while (0)

/*****************************************************************************/

/* macro to return strlen() of a compile time string. */
#define NM_STRLEN(str) (sizeof("" str "") - 1u)

/* returns the length of a NULL terminated array of pointers,
 * like g_strv_length() does. The difference is:
 *  - it operates on arrays of pointers (of any kind, requiring no cast).
 *  - it accepts NULL to return zero. */
#define NM_PTRARRAY_LEN(array)                                         \
    ({                                                                 \
        typeof(*(array)) *const _array = (array);                      \
        size_t                  _n     = 0;                            \
                                                                       \
        if (_array) {                                                  \
            _nm_unused const void *_type_check_is_pointer = _array[0]; \
                                                                       \
            while (_array[_n])                                         \
                _n++;                                                  \
        }                                                              \
        _n;                                                            \
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

#define _NM_IN_SET_EVAL_1(op, _x, y)       (_x == (y))
#define _NM_IN_SET_EVAL_2(op, _x, y, ...)  (_x == (y)) op _NM_IN_SET_EVAL_1(op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_3(op, _x, y, ...)  (_x == (y)) op _NM_IN_SET_EVAL_2(op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_4(op, _x, y, ...)  (_x == (y)) op _NM_IN_SET_EVAL_3(op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_5(op, _x, y, ...)  (_x == (y)) op _NM_IN_SET_EVAL_4(op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_6(op, _x, y, ...)  (_x == (y)) op _NM_IN_SET_EVAL_5(op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_7(op, _x, y, ...)  (_x == (y)) op _NM_IN_SET_EVAL_6(op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_8(op, _x, y, ...)  (_x == (y)) op _NM_IN_SET_EVAL_7(op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_9(op, _x, y, ...)  (_x == (y)) op _NM_IN_SET_EVAL_8(op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_10(op, _x, y, ...) (_x == (y)) op _NM_IN_SET_EVAL_9(op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_11(op, _x, y, ...) (_x == (y)) op _NM_IN_SET_EVAL_10(op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_12(op, _x, y, ...) (_x == (y)) op _NM_IN_SET_EVAL_11(op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_13(op, _x, y, ...) (_x == (y)) op _NM_IN_SET_EVAL_12(op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_14(op, _x, y, ...) (_x == (y)) op _NM_IN_SET_EVAL_13(op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_15(op, _x, y, ...) (_x == (y)) op _NM_IN_SET_EVAL_14(op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_16(op, _x, y, ...) (_x == (y)) op _NM_IN_SET_EVAL_15(op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_17(op, _x, y, ...) (_x == (y)) op _NM_IN_SET_EVAL_16(op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_18(op, _x, y, ...) (_x == (y)) op _NM_IN_SET_EVAL_17(op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_19(op, _x, y, ...) (_x == (y)) op _NM_IN_SET_EVAL_18(op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_20(op, _x, y, ...) (_x == (y)) op _NM_IN_SET_EVAL_19(op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_21(op, _x, y, ...) (_x == (y)) op _NM_IN_SET_EVAL_20(op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_22(op, _x, y, ...) (_x == (y)) op _NM_IN_SET_EVAL_21(op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_23(op, _x, y, ...) (_x == (y)) op _NM_IN_SET_EVAL_22(op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_24(op, _x, y, ...) (_x == (y)) op _NM_IN_SET_EVAL_23(op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_25(op, _x, y, ...) (_x == (y)) op _NM_IN_SET_EVAL_24(op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_26(op, _x, y, ...) (_x == (y)) op _NM_IN_SET_EVAL_25(op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_27(op, _x, y, ...) (_x == (y)) op _NM_IN_SET_EVAL_26(op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_28(op, _x, y, ...) (_x == (y)) op _NM_IN_SET_EVAL_27(op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_29(op, _x, y, ...) (_x == (y)) op _NM_IN_SET_EVAL_28(op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_30(op, _x, y, ...) (_x == (y)) op _NM_IN_SET_EVAL_29(op, _x, __VA_ARGS__)

#define _NM_IN_SET_EVAL_N2(op, _x, n, ...) (_NM_IN_SET_EVAL_##n(op, _x, __VA_ARGS__))
#define _NM_IN_SET_EVAL_N(op, type, x, n, ...)        \
    ({                                                \
        type _x = (x);                                \
                                                      \
        /* trigger a -Wenum-compare warning */        \
        nm_assert(true || _x == (x));                 \
                                                      \
        !!_NM_IN_SET_EVAL_N2(op, _x, n, __VA_ARGS__); \
    })

#define _NM_IN_SET(op, type, x, ...) \
    _NM_IN_SET_EVAL_N(op, type, x, NM_NARG(__VA_ARGS__), __VA_ARGS__)

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

#define _NM_IN_SETOP_EVAL_1(op, op_eq, _x, y) (op_eq(_x, y))
#define _NM_IN_SETOP_EVAL_2(op, op_eq, _x, y, ...) \
    (op_eq(_x, y)) op _NM_IN_SETOP_EVAL_1(op, op_eq, _x, __VA_ARGS__)
#define _NM_IN_SETOP_EVAL_3(op, op_eq, _x, y, ...) \
    (op_eq(_x, y)) op _NM_IN_SETOP_EVAL_2(op, op_eq, _x, __VA_ARGS__)
#define _NM_IN_SETOP_EVAL_4(op, op_eq, _x, y, ...) \
    (op_eq(_x, y)) op _NM_IN_SETOP_EVAL_3(op, op_eq, _x, __VA_ARGS__)
#define _NM_IN_SETOP_EVAL_5(op, op_eq, _x, y, ...) \
    (op_eq(_x, y)) op _NM_IN_SETOP_EVAL_4(op, op_eq, _x, __VA_ARGS__)
#define _NM_IN_SETOP_EVAL_6(op, op_eq, _x, y, ...) \
    (op_eq(_x, y)) op _NM_IN_SETOP_EVAL_5(op, op_eq, _x, __VA_ARGS__)
#define _NM_IN_SETOP_EVAL_7(op, op_eq, _x, y, ...) \
    (op_eq(_x, y)) op _NM_IN_SETOP_EVAL_6(op, op_eq, _x, __VA_ARGS__)
#define _NM_IN_SETOP_EVAL_8(op, op_eq, _x, y, ...) \
    (op_eq(_x, y)) op _NM_IN_SETOP_EVAL_7(op, op_eq, _x, __VA_ARGS__)
#define _NM_IN_SETOP_EVAL_9(op, op_eq, _x, y, ...) \
    (op_eq(_x, y)) op _NM_IN_SETOP_EVAL_8(op, op_eq, _x, __VA_ARGS__)
#define _NM_IN_SETOP_EVAL_10(op, op_eq, _x, y, ...) \
    (op_eq(_x, y)) op _NM_IN_SETOP_EVAL_9(op, op_eq, _x, __VA_ARGS__)
#define _NM_IN_SETOP_EVAL_11(op, op_eq, _x, y, ...) \
    (op_eq(_x, y)) op _NM_IN_SETOP_EVAL_10(op, op_eq, _x, __VA_ARGS__)
#define _NM_IN_SETOP_EVAL_12(op, op_eq, _x, y, ...) \
    (op_eq(_x, y)) op _NM_IN_SETOP_EVAL_11(op, op_eq, _x, __VA_ARGS__)
#define _NM_IN_SETOP_EVAL_13(op, op_eq, _x, y, ...) \
    (op_eq(_x, y)) op _NM_IN_SETOP_EVAL_12(op, op_eq, _x, __VA_ARGS__)
#define _NM_IN_SETOP_EVAL_14(op, op_eq, _x, y, ...) \
    (op_eq(_x, y)) op _NM_IN_SETOP_EVAL_13(op, op_eq, _x, __VA_ARGS__)
#define _NM_IN_SETOP_EVAL_15(op, op_eq, _x, y, ...) \
    (op_eq(_x, y)) op _NM_IN_SETOP_EVAL_14(op, op_eq, _x, __VA_ARGS__)
#define _NM_IN_SETOP_EVAL_16(op, op_eq, _x, y, ...) \
    (op_eq(_x, y)) op _NM_IN_SETOP_EVAL_15(op, op_eq, _x, __VA_ARGS__)
#define _NM_IN_SETOP_EVAL_17(op, op_eq, _x, y, ...) \
    (op_eq(_x, y)) op _NM_IN_SETOP_EVAL_16(op, op_eq, _x, __VA_ARGS__)
#define _NM_IN_SETOP_EVAL_18(op, op_eq, _x, y, ...) \
    (op_eq(_x, y)) op _NM_IN_SETOP_EVAL_17(op, op_eq, _x, __VA_ARGS__)
#define _NM_IN_SETOP_EVAL_19(op, op_eq, _x, y, ...) \
    (op_eq(_x, y)) op _NM_IN_SETOP_EVAL_18(op, op_eq, _x, __VA_ARGS__)
#define _NM_IN_SETOP_EVAL_20(op, op_eq, _x, y, ...) \
    (op_eq(_x, y)) op _NM_IN_SETOP_EVAL_19(op, op_eq, _x, __VA_ARGS__)
#define _NM_IN_SETOP_EVAL_21(op, op_eq, _x, y, ...) \
    (op_eq(_x, y)) op _NM_IN_SETOP_EVAL_20(op, op_eq, _x, __VA_ARGS__)
#define _NM_IN_SETOP_EVAL_22(op, op_eq, _x, y, ...) \
    (op_eq(_x, y)) op _NM_IN_SETOP_EVAL_21(op, op_eq, _x, __VA_ARGS__)
#define _NM_IN_SETOP_EVAL_23(op, op_eq, _x, y, ...) \
    (op_eq(_x, y)) op _NM_IN_SETOP_EVAL_22(op, op_eq, _x, __VA_ARGS__)
#define _NM_IN_SETOP_EVAL_24(op, op_eq, _x, y, ...) \
    (op_eq(_x, y)) op _NM_IN_SETOP_EVAL_23(op, op_eq, _x, __VA_ARGS__)
#define _NM_IN_SETOP_EVAL_25(op, op_eq, _x, y, ...) \
    (op_eq(_x, y)) op _NM_IN_SETOP_EVAL_24(op, op_eq, _x, __VA_ARGS__)
#define _NM_IN_SETOP_EVAL_26(op, op_eq, _x, y, ...) \
    (op_eq(_x, y)) op _NM_IN_SETOP_EVAL_25(op, op_eq, _x, __VA_ARGS__)
#define _NM_IN_SETOP_EVAL_27(op, op_eq, _x, y, ...) \
    (op_eq(_x, y)) op _NM_IN_SETOP_EVAL_26(op, op_eq, _x, __VA_ARGS__)
#define _NM_IN_SETOP_EVAL_28(op, op_eq, _x, y, ...) \
    (op_eq(_x, y)) op _NM_IN_SETOP_EVAL_27(op, op_eq, _x, __VA_ARGS__)
#define _NM_IN_SETOP_EVAL_29(op, op_eq, _x, y, ...) \
    (op_eq(_x, y)) op _NM_IN_SETOP_EVAL_28(op, op_eq, _x, __VA_ARGS__)
#define _NM_IN_SETOP_EVAL_30(op, op_eq, _x, y, ...) \
    (op_eq(_x, y)) op _NM_IN_SETOP_EVAL_29(op, op_eq, _x, __VA_ARGS__)

/*****************************************************************************/

#define _NM_IN_STRSET_EVAL_N2(op, op_ed, _x, n, ...) \
    (_NM_IN_SETOP_EVAL_##n(op, op_ed, _x, __VA_ARGS__))
#define _NM_IN_STRSET_EVAL_N(op, op_ed, x, n, ...)                                       \
    ({                                                                                   \
        const char *_x = (x);                                                            \
        (((_x == NULL) && _NM_IN_SET_EVAL_N2(op, ((const char *) NULL), n, __VA_ARGS__)) \
         || ((_x != NULL) && _NM_IN_STRSET_EVAL_N2(op, op_ed, _x, n, __VA_ARGS__)));     \
    })

/*****************************************************************************/

static inline int
_NM_IN_STRSET_op_streq(const char *x, const char *s)
{
    return s && strcmp(x, s) == 0;
}

/* Beware that this does short-circuit evaluation (use "||" instead of "|")
 * which has a possibly unexpected non-function-like behavior.
 * Use NM_IN_STRSET_SE if you need all arguments to be evaluated. */
#define NM_IN_STRSET(x, ...) \
    _NM_IN_STRSET_EVAL_N(||, _NM_IN_STRSET_op_streq, x, NM_NARG(__VA_ARGS__), __VA_ARGS__)

/* "SE" stands for "side-effect". Contrary to NM_IN_STRSET(), this does not do
 * short-circuit evaluation, which can make a difference if the arguments have
 * side-effects. */
#define NM_IN_STRSET_SE(x, ...) \
    _NM_IN_STRSET_EVAL_N(|, _NM_IN_STRSET_op_streq, x, NM_NARG(__VA_ARGS__), __VA_ARGS__)

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
        int errsv = errno;

        (void) nm_close(*pfd);
        errno = errsv;
    }
}
#define nm_auto_close nm_auto(_nm_auto_close)

static inline void
_nm_auto_fclose(FILE **pfd)
{
    if (*pfd) {
        int errsv = errno;

        (void) fclose(*pfd);
        errno = errsv;
    }
}
#define nm_auto_fclose nm_auto(_nm_auto_fclose)

/*****************************************************************************/

#define nm_clear_pointer(pp, destroy)                                                \
    ({                                                                               \
        typeof(*(pp)) *_pp = (pp);                                                   \
        typeof(*_pp) _p;                                                             \
        int _changed = false;                                                        \
                                                                                     \
        if (_pp && (_p = *_pp)) {                                                    \
            _nm_unused const void *_p_check_is_pointer = _p;                         \
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

static inline void *
_nm_steal_pointer(void *pp)
{
    void **ptr = (void **) pp;
    void * ref;

    ref  = *ptr;
    *ptr = NULL;
    return ref;
}

#define nm_steal_pointer(pp) ((typeof(*(pp))) _nm_steal_pointer(pp))

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
        typeof(*_p_val) _val       = 0;       \
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

#define NM_AF_UNSPEC 0 /* AF_UNSPEC */
#define NM_AF_INET   2 /* AF_INET   */
#define NM_AF_INET6  10 /* AF_INET6  */

#define NM_AF_INET_SIZE  4 /* sizeof (in_addr_t)      */
#define NM_AF_INET6_SIZE 16 /* sizeof (stuct in6_addr) */

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

static inline size_t
nm_utils_addr_family_to_size(int addr_family)
{
    switch (addr_family) {
    case NM_AF_INET:
        return NM_AF_INET_SIZE;
    case NM_AF_INET6:
        return NM_AF_INET6_SIZE;
    }
    nm_assert_not_reached();
    return 0;
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

#define nm_assert_addr_family(addr_family) \
    nm_assert(NM_IN_SET((addr_family), NM_AF_INET, NM_AF_INET6))

#define NM_IS_IPv4(addr_family)                 \
    ({                                          \
        const int _addr_family = (addr_family); \
                                                \
        nm_assert_addr_family(_addr_family);    \
                                                \
        (_addr_family == NM_AF_INET);           \
    })

#endif /* __NM_STD_AUX_H__ */
