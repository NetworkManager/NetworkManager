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

#endif /* __NM_STD_AUX_H__ */
