// SPDX-License-Identifier: LGPL-2.1+

#ifndef __NM_STD_AUX_H__
#define __NM_STD_AUX_H__

#include <assert.h>
#include <string.h>

/*****************************************************************************/

#define _nm_packed           __attribute__ ((__packed__))
#define _nm_unused           __attribute__ ((__unused__))
#define _nm_used             __attribute__ ((__used__))
#define _nm_pure             __attribute__ ((__pure__))
#define _nm_const            __attribute__ ((__const__))
#define _nm_printf(a,b)      __attribute__ ((__format__ (__printf__, a, b)))
#define _nm_align(s)         __attribute__ ((__aligned__ (s)))
#define _nm_section(s)       __attribute__ ((__section__ (s)))
#define _nm_alignof(type)    __alignof (type)
#define _nm_alignas(type)    _nm_align (_nm_alignof (type))
#define nm_auto(fcn)         __attribute__ ((__cleanup__(fcn)))

/* This is required to make LTO working.
 *
 * See https://gitlab.freedesktop.org/NetworkManager/NetworkManager/merge_requests/76#note_112694
 *     https://gcc.gnu.org/bugzilla/show_bug.cgi?id=48200#c28
 */
#ifndef __clang__
#define _nm_externally_visible __attribute__ ((__externally_visible__))
#else
#define _nm_externally_visible
#endif


#if __GNUC__ >= 7
#define _nm_fallthrough      __attribute__ ((__fallthrough__))
#else
#define _nm_fallthrough
#endif

/*****************************************************************************/

#ifdef thread_local
#define _nm_thread_local thread_local
/*
 * Don't break on glibc < 2.16 that doesn't define __STDC_NO_THREADS__
 * see http://gcc.gnu.org/bugzilla/show_bug.cgi?id=53769
 */
#elif __STDC_VERSION__ >= 201112L && !(defined(__STDC_NO_THREADS__) || (defined(__GNU_LIBRARY__) && __GLIBC__ == 2 && __GLIBC_MINOR__ < 16))
#define _nm_thread_local _Thread_local
#else
#define _nm_thread_local __thread
#endif

/*****************************************************************************/

#if defined(__GNUC__) && (__GNUC__ > 2) && defined(__OPTIMIZE__)
#define NM_BOOLEAN_EXPR(expr) \
	({ \
		int _g_boolean_var_; \
		\
		if (expr) \
			_g_boolean_var_ = 1; \
		else  \
			_g_boolean_var_ = 0; \
		_g_boolean_var_; \
	})
#define NM_LIKELY(expr)   (__builtin_expect (NM_BOOLEAN_EXPR (expr), 1))
#define NM_UNLIKELY(expr) (__builtin_expect (NM_BOOLEAN_EXPR (expr), 0))
#else
#define NM_LIKELY(expr)   NM_BOOLEAN_EXPR (expr)
#define NM_UNLIKELY(expr) NM_BOOLEAN_EXPR (expr)
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
#define _nm_assert_call(cond)             assert(cond)
#define _nm_assert_call_not_reached()     assert(0)
#endif

#if NM_MORE_ASSERTS
#define nm_assert(cond)         do { _nm_assert_call (cond); } while (0)
#define nm_assert_se(cond)      do { if (NM_LIKELY (cond)) { ; } else { _nm_assert_call (0 && (cond)); } } while (0)
#define nm_assert_not_reached() do { _nm_assert_call_not_reached (); } while (0)
#else
#define nm_assert(cond)         do { if (0) { if (cond) { } } } while (0)
#define nm_assert_se(cond)      do { if (NM_LIKELY (cond)) { ; } } while (0)
#define nm_assert_not_reached() do { ; } while (0)
#endif

#define NM_STATIC_ASSERT(cond)      static_assert(cond, "")
#define NM_STATIC_ASSERT_EXPR(cond) ({ NM_STATIC_ASSERT (cond); 1; })

/*****************************************************************************/

#define NM_N_ELEMENTS(arr)  (sizeof (arr) / sizeof ((arr)[0]))

#define NM_PASTE_ARGS(identifier1,identifier2) identifier1 ## identifier2
#define NM_PASTE(identifier1,identifier2)      NM_PASTE_ARGS (identifier1, identifier2)

/* Taken from systemd's UNIQ_T and UNIQ macros. */

#define NM_UNIQ_T(x, uniq) NM_PASTE(__unique_prefix_, NM_PASTE(x, uniq))
#define NM_UNIQ __COUNTER__

/*****************************************************************************/

/* glib's MIN()/MAX() macros don't have function-like behavior, in that they evaluate
 * the argument possibly twice.
 *
 * Taken from systemd's MIN()/MAX() macros. */

#define NM_MIN(a, b) __NM_MIN(NM_UNIQ, a, NM_UNIQ, b)
#define __NM_MIN(aq, a, bq, b) \
	({ \
		typeof (a) NM_UNIQ_T(A, aq) = (a); \
		typeof (b) NM_UNIQ_T(B, bq) = (b); \
		((NM_UNIQ_T(A, aq) < NM_UNIQ_T(B, bq)) ? NM_UNIQ_T(A, aq) : NM_UNIQ_T(B, bq)); \
	})

#define NM_MAX(a, b) __NM_MAX(NM_UNIQ, a, NM_UNIQ, b)
#define __NM_MAX(aq, a, bq, b) \
	({ \
		typeof (a) NM_UNIQ_T(A, aq) = (a); \
		typeof (b) NM_UNIQ_T(B, bq) = (b); \
		((NM_UNIQ_T(A, aq) > NM_UNIQ_T(B, bq)) ? NM_UNIQ_T(A, aq) : NM_UNIQ_T(B, bq)); \
	})

#define NM_CLAMP(x, low, high) __NM_CLAMP(NM_UNIQ, x, NM_UNIQ, low, NM_UNIQ, high)
#define __NM_CLAMP(xq, x, lowq, low, highq, high) \
	({ \
		typeof(x)NM_UNIQ_T(X,xq) = (x); \
		typeof(low) NM_UNIQ_T(LOW,lowq) = (low); \
		typeof(high) NM_UNIQ_T(HIGH,highq) = (high); \
		\
		( (NM_UNIQ_T(X,xq) > NM_UNIQ_T(HIGH,highq)) \
		  ? NM_UNIQ_T(HIGH,highq) \
		  : (NM_UNIQ_T(X,xq) < NM_UNIQ_T(LOW,lowq)) \
		     ? NM_UNIQ_T(LOW,lowq) \
		     : NM_UNIQ_T(X,xq)); \
	})

#define NM_MAX_WITH_CMP(cmp, a, b) \
	({ \
		typeof (a) _a = (a); \
		typeof (b) _b = (b); \
		\
		(  ((cmp (_a, _b)) >= 0) \
		 ? _a \
		 : _b); \
	})

/* evaluates to (void) if _A or _B are not constant or of different types */
#define NM_CONST_MAX(_A, _B) \
	(__builtin_choose_expr ((   __builtin_constant_p (_A) \
	                         && __builtin_constant_p (_B) \
	                         && __builtin_types_compatible_p (typeof (_A), typeof (_B))), \
	                        ((_A) > (_B)) ? (_A) : (_B),                            \
	                        ((void)  0)))

/*****************************************************************************/

#define NM_SWAP(a, b) \
	do { \
		typeof (a) _tmp; \
		\
		_tmp = (a); \
		(a) = (b); \
		(b) = _tmp; \
	} while (0)

/*****************************************************************************/

/* macro to return strlen() of a compile time string. */
#define NM_STRLEN(str)     ( sizeof (""str"") - 1u )

/* returns the length of a NULL terminated array of pointers,
 * like g_strv_length() does. The difference is:
 *  - it operates on arrays of pointers (of any kind, requiring no cast).
 *  - it accepts NULL to return zero. */
#define NM_PTRARRAY_LEN(array) \
	({ \
		typeof (*(array)) *const _array = (array); \
		size_t _n = 0; \
		\
		if (_array) { \
			_nm_unused const void * _type_check_is_pointer = _array[0]; \
			\
			while (_array[_n]) \
				_n++; \
		} \
		_n; \
	})

/*****************************************************************************/

static inline int
nm_strcmp0 (const char *s1, const char *s2)
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
	c = strcmp (s1, s2);
	if (c < 0)
		return -1;
	if (c > 0)
		return 1;
	return 0;
}

static inline int
nm_streq (const char *s1, const char *s2)
{
	return strcmp (s1, s2) == 0;
}

static inline int
nm_streq0 (const char *s1, const char *s2)
{
	return    (s1 == s2)
	       || (s1 && s2 && strcmp (s1, s2) == 0);
}

#define NM_STR_HAS_PREFIX(str, prefix) \
	({ \
		const char *const _str_has_prefix = (str); \
		\
		nm_assert (strlen (prefix) == NM_STRLEN (prefix)); \
		\
		   _str_has_prefix \
		&& (strncmp (_str_has_prefix, ""prefix"", NM_STRLEN (prefix)) == 0); \
	})

#define NM_STR_HAS_SUFFIX(str, suffix) \
	({ \
		const char *const _str_has_suffix = (str); \
		size_t _l; \
		\
		nm_assert (strlen (suffix) == NM_STRLEN (suffix)); \
		\
		(   _str_has_suffix \
		 && ((_l = strlen (_str_has_suffix)) >= NM_STRLEN (suffix)) \
		 && (memcmp (&_str_has_suffix[_l - NM_STRLEN (suffix)], \
		             ""suffix"", \
		             NM_STRLEN (suffix)) == 0)); \
	})

/* whether @str starts with the string literal @prefix and is followed by
 * some other text. It is like NM_STR_HAS_PREFIX() && !nm_streq() together. */
#define NM_STR_HAS_PREFIX_WITH_MORE(str, prefix) \
	({ \
		const char *const _str_has_prefix_with_more = (str); \
		\
		   NM_STR_HAS_PREFIX (_str_has_prefix_with_more, ""prefix"") \
		&& _str_has_prefix_with_more[NM_STRLEN (prefix)] != '\0'; \
	})

/*****************************************************************************/

#define _NM_IN_SET_EVAL_1( op, _x, y)           (_x == (y))
#define _NM_IN_SET_EVAL_2( op, _x, y, ...)      (_x == (y)) op _NM_IN_SET_EVAL_1  (op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_3( op, _x, y, ...)      (_x == (y)) op _NM_IN_SET_EVAL_2  (op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_4( op, _x, y, ...)      (_x == (y)) op _NM_IN_SET_EVAL_3  (op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_5( op, _x, y, ...)      (_x == (y)) op _NM_IN_SET_EVAL_4  (op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_6( op, _x, y, ...)      (_x == (y)) op _NM_IN_SET_EVAL_5  (op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_7( op, _x, y, ...)      (_x == (y)) op _NM_IN_SET_EVAL_6  (op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_8( op, _x, y, ...)      (_x == (y)) op _NM_IN_SET_EVAL_7  (op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_9( op, _x, y, ...)      (_x == (y)) op _NM_IN_SET_EVAL_8  (op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_10(op, _x, y, ...)      (_x == (y)) op _NM_IN_SET_EVAL_9  (op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_11(op, _x, y, ...)      (_x == (y)) op _NM_IN_SET_EVAL_10 (op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_12(op, _x, y, ...)      (_x == (y)) op _NM_IN_SET_EVAL_11 (op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_13(op, _x, y, ...)      (_x == (y)) op _NM_IN_SET_EVAL_12 (op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_14(op, _x, y, ...)      (_x == (y)) op _NM_IN_SET_EVAL_13 (op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_15(op, _x, y, ...)      (_x == (y)) op _NM_IN_SET_EVAL_14 (op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_16(op, _x, y, ...)      (_x == (y)) op _NM_IN_SET_EVAL_15 (op, _x, __VA_ARGS__)

#define _NM_IN_SET_EVAL_N2(op, _x, n, ...)      (_NM_IN_SET_EVAL_##n(op, _x, __VA_ARGS__))
#define _NM_IN_SET_EVAL_N(op, type, x, n, ...)                      \
    ({                                                              \
        type _x = (x);                                              \
                                                                    \
        /* trigger a -Wenum-compare warning */                      \
        nm_assert (TRUE || _x == (x));                              \
                                                                    \
        !!_NM_IN_SET_EVAL_N2(op, _x, n, __VA_ARGS__);               \
    })

#define _NM_IN_SET(op, type, x, ...)        _NM_IN_SET_EVAL_N(op, type, x, NM_NARG (__VA_ARGS__), __VA_ARGS__)

/* Beware that this does short-circuit evaluation (use "||" instead of "|")
 * which has a possibly unexpected non-function-like behavior.
 * Use NM_IN_SET_SE if you need all arguments to be evaluated. */
#define NM_IN_SET(x, ...)                   _NM_IN_SET(||, typeof (x), x, __VA_ARGS__)

/* "SE" stands for "side-effect". Contrary to NM_IN_SET(), this does not do
 * short-circuit evaluation, which can make a difference if the arguments have
 * side-effects. */
#define NM_IN_SET_SE(x, ...)                _NM_IN_SET(|,  typeof (x), x, __VA_ARGS__)

/* the *_TYPED forms allow to explicitly select the type of "x". This is useful
 * if "x" doesn't support typeof (bitfields) or you want to gracefully convert
 * a type using automatic type conversion rules (but not forcing the conversion
 * with a cast). */
#define NM_IN_SET_TYPED(type, x, ...)       _NM_IN_SET(||, type,       x, __VA_ARGS__)
#define NM_IN_SET_SE_TYPED(type, x, ...)    _NM_IN_SET(|,  type,       x, __VA_ARGS__)

/*****************************************************************************/

static inline int
_NM_IN_STRSET_streq (const char *x, const char *s)
{
	return s && strcmp (x, s) == 0;
}

#define _NM_IN_STRSET_EVAL_1( op, _x, y)        _NM_IN_STRSET_streq (_x, y)
#define _NM_IN_STRSET_EVAL_2( op, _x, y, ...)   _NM_IN_STRSET_streq (_x, y) op _NM_IN_STRSET_EVAL_1  (op, _x, __VA_ARGS__)
#define _NM_IN_STRSET_EVAL_3( op, _x, y, ...)   _NM_IN_STRSET_streq (_x, y) op _NM_IN_STRSET_EVAL_2  (op, _x, __VA_ARGS__)
#define _NM_IN_STRSET_EVAL_4( op, _x, y, ...)   _NM_IN_STRSET_streq (_x, y) op _NM_IN_STRSET_EVAL_3  (op, _x, __VA_ARGS__)
#define _NM_IN_STRSET_EVAL_5( op, _x, y, ...)   _NM_IN_STRSET_streq (_x, y) op _NM_IN_STRSET_EVAL_4  (op, _x, __VA_ARGS__)
#define _NM_IN_STRSET_EVAL_6( op, _x, y, ...)   _NM_IN_STRSET_streq (_x, y) op _NM_IN_STRSET_EVAL_5  (op, _x, __VA_ARGS__)
#define _NM_IN_STRSET_EVAL_7( op, _x, y, ...)   _NM_IN_STRSET_streq (_x, y) op _NM_IN_STRSET_EVAL_6  (op, _x, __VA_ARGS__)
#define _NM_IN_STRSET_EVAL_8( op, _x, y, ...)   _NM_IN_STRSET_streq (_x, y) op _NM_IN_STRSET_EVAL_7  (op, _x, __VA_ARGS__)
#define _NM_IN_STRSET_EVAL_9( op, _x, y, ...)   _NM_IN_STRSET_streq (_x, y) op _NM_IN_STRSET_EVAL_8  (op, _x, __VA_ARGS__)
#define _NM_IN_STRSET_EVAL_10(op, _x, y, ...)   _NM_IN_STRSET_streq (_x, y) op _NM_IN_STRSET_EVAL_9  (op, _x, __VA_ARGS__)
#define _NM_IN_STRSET_EVAL_11(op, _x, y, ...)   _NM_IN_STRSET_streq (_x, y) op _NM_IN_STRSET_EVAL_10 (op, _x, __VA_ARGS__)
#define _NM_IN_STRSET_EVAL_12(op, _x, y, ...)   _NM_IN_STRSET_streq (_x, y) op _NM_IN_STRSET_EVAL_11 (op, _x, __VA_ARGS__)
#define _NM_IN_STRSET_EVAL_13(op, _x, y, ...)   _NM_IN_STRSET_streq (_x, y) op _NM_IN_STRSET_EVAL_12 (op, _x, __VA_ARGS__)
#define _NM_IN_STRSET_EVAL_14(op, _x, y, ...)   _NM_IN_STRSET_streq (_x, y) op _NM_IN_STRSET_EVAL_13 (op, _x, __VA_ARGS__)
#define _NM_IN_STRSET_EVAL_15(op, _x, y, ...)   _NM_IN_STRSET_streq (_x, y) op _NM_IN_STRSET_EVAL_14 (op, _x, __VA_ARGS__)
#define _NM_IN_STRSET_EVAL_16(op, _x, y, ...)   _NM_IN_STRSET_streq (_x, y) op _NM_IN_STRSET_EVAL_15 (op, _x, __VA_ARGS__)

#define _NM_IN_STRSET_EVAL_N2(op, _x, n, ...)   (_NM_IN_STRSET_EVAL_##n(op, _x, __VA_ARGS__))
#define _NM_IN_STRSET_EVAL_N(op, x, n, ...)                       \
    ({                                                            \
        const char *_x = (x);                                     \
        (   ((_x == NULL) && _NM_IN_SET_EVAL_N2    (op, ((const char *) NULL), n, __VA_ARGS__)) \
         || ((_x != NULL) && _NM_IN_STRSET_EVAL_N2 (op, _x,                    n, __VA_ARGS__)) \
        ); \
    })

/* Beware that this does short-circuit evaluation (use "||" instead of "|")
 * which has a possibly unexpected non-function-like behavior.
 * Use NM_IN_STRSET_SE if you need all arguments to be evaluated. */
#define NM_IN_STRSET(x, ...)               _NM_IN_STRSET_EVAL_N(||, x, NM_NARG (__VA_ARGS__), __VA_ARGS__)

/* "SE" stands for "side-effect". Contrary to NM_IN_STRSET(), this does not do
 * short-circuit evaluation, which can make a difference if the arguments have
 * side-effects. */
#define NM_IN_STRSET_SE(x, ...)            _NM_IN_STRSET_EVAL_N(|, x, NM_NARG (__VA_ARGS__), __VA_ARGS__)

/*****************************************************************************/

#define NM_STRCHAR_ALL(str, ch_iter, predicate) \
	({ \
		int _val = TRUE; \
		const char *_str = (str); \
		\
		if (_str) { \
			for (;;) { \
				const char ch_iter = _str[0]; \
				\
				if (ch_iter != '\0') { \
					if (predicate) {\
						_str++; \
						continue; \
					} \
					_val = FALSE; \
				} \
				break; \
			} \
		} \
		_val; \
	})

#define NM_STRCHAR_ANY(str, ch_iter, predicate) \
	({ \
		int _val = FALSE; \
		const char *_str = (str); \
		\
		if (_str) { \
			for (;;) { \
				const char ch_iter = _str[0]; \
				\
				if (ch_iter != '\0') { \
					if (predicate) { \
						; \
					} else { \
						_str++; \
						continue; \
					} \
					_val = TRUE; \
				} \
				break; \
			} \
		} \
		_val; \
	})

/*****************************************************************************/

/* Note: @value is only evaluated when *out_val is present.
 * Thus,
 *    NM_SET_OUT (out_str, g_strdup ("hallo"));
 * does the right thing.
 */
#define NM_SET_OUT(out_val, value) \
	({ \
		typeof(*(out_val)) *_out_val = (out_val); \
		\
		if (_out_val) { \
			*_out_val = (value); \
		} \
		\
		(!!_out_val); \
	})

#endif /* __NM_STD_AUX_H__ */
