// SPDX-License-Identifier: LGPL-2.1+

#ifndef __NM_STD_AUX_H__
#define __NM_STD_AUX_H__

#include <assert.h>

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

#endif /* __NM_STD_AUX_H__ */
