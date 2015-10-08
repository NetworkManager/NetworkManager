/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
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
 * (C) Copyright 2014 Red Hat, Inc.
 */

#ifndef __NM_MACROS_INTERNAL_H__
#define __NM_MACROS_INTERNAL_H__

#include "nm-default.h"

/********************************************************/

/* http://stackoverflow.com/a/11172679 */
#define  _NM_UTILS_MACRO_FIRST(...)                           __NM_UTILS_MACRO_FIRST_HELPER(__VA_ARGS__, throwaway)
#define __NM_UTILS_MACRO_FIRST_HELPER(first, ...)             first

#define  _NM_UTILS_MACRO_REST(...)                            __NM_UTILS_MACRO_REST_HELPER(__NM_UTILS_MACRO_REST_NUM(__VA_ARGS__), __VA_ARGS__)
#define __NM_UTILS_MACRO_REST_HELPER(qty, ...)                __NM_UTILS_MACRO_REST_HELPER2(qty, __VA_ARGS__)
#define __NM_UTILS_MACRO_REST_HELPER2(qty, ...)               __NM_UTILS_MACRO_REST_HELPER_##qty(__VA_ARGS__)
#define __NM_UTILS_MACRO_REST_HELPER_ONE(first)
#define __NM_UTILS_MACRO_REST_HELPER_TWOORMORE(first, ...)    , __VA_ARGS__
#define __NM_UTILS_MACRO_REST_NUM(...) \
    __NM_UTILS_MACRO_REST_SELECT_20TH(__VA_ARGS__, \
                TWOORMORE, TWOORMORE, TWOORMORE, TWOORMORE, TWOORMORE,\
                TWOORMORE, TWOORMORE, TWOORMORE, TWOORMORE, TWOORMORE,\
                TWOORMORE, TWOORMORE, TWOORMORE, TWOORMORE, TWOORMORE,\
                TWOORMORE, TWOORMORE, TWOORMORE, ONE, throwaway)
#define __NM_UTILS_MACRO_REST_SELECT_20TH(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, ...) a20

/********************************************************/

/* http://stackoverflow.com/a/2124385/354393 */

#define NM_NARG(...) \
         _NM_NARG(__VA_ARGS__,_NM_NARG_RSEQ_N())
#define _NM_NARG(...) \
         _NM_NARG_ARG_N(__VA_ARGS__)
#define _NM_NARG_ARG_N( \
          _1, _2, _3, _4, _5, _6, _7, _8, _9,_10, \
         _11,_12,_13,_14,_15,_16,_17,_18,_19,_20, \
         _21,_22,_23,_24,_25,_26,_27,_28,_29,_30, \
         _31,_32,_33,_34,_35,_36,_37,_38,_39,_40, \
         _41,_42,_43,_44,_45,_46,_47,_48,_49,_50, \
         _51,_52,_53,_54,_55,_56,_57,_58,_59,_60, \
         _61,_62,_63,N,...) N
#define _NM_NARG_RSEQ_N() \
         63,62,61,60,                   \
         59,58,57,56,55,54,53,52,51,50, \
         49,48,47,46,45,44,43,42,41,40, \
         39,38,37,36,35,34,33,32,31,30, \
         29,28,27,26,25,24,23,22,21,20, \
         19,18,17,16,15,14,13,12,11,10, \
         9,8,7,6,5,4,3,2,1,0

/********************************************************/

#if defined (__GNUC__)
#define _NM_PRAGMA_WARNING_DO(warning)       G_STRINGIFY(GCC diagnostic ignored warning)
#elif defined (__clang__)
#define _NM_PRAGMA_WARNING_DO(warning)       G_STRINGIFY(clang diagnostic ignored warning)
#endif

/* you can only suppress a specific warning that the compiler
 * understands. Otherwise you will get another compiler warning
 * about invalid pragma option.
 * It's not that bad however, because gcc and clang often have the
 * same name for the same warning. */

#if defined (__GNUC__)
#define NM_PRAGMA_WARNING_DISABLE(warning) \
        _Pragma("GCC diagnostic push"); \
        _Pragma(_NM_PRAGMA_WARNING_DO(warning))
#elif defined (__clang__)
#define NM_PRAGMA_WARNING_DISABLE(warning) \
        _Pragma("clang diagnostic push"); \
        _Pragma(_NM_PRAGMA_WARNING_DO(warning))
#else
#define NM_PRAGMA_WARNING_DISABLE(warning)
#endif

#if defined (__GNUC__)
#define NM_PRAGMA_WARNING_REENABLE \
    _Pragma("GCC diagnostic pop")
#elif defined (__clang__)
#define NM_PRAGMA_WARNING_REENABLE \
    _Pragma("clang diagnostic pop")
#else
#define NM_PRAGMA_WARNING_REENABLE
#endif

/********************************************************/

/* macro to return strlen() of a compile time string. */
#define STRLEN(str)     ( sizeof ("" str) - 1 )

#define NM_SET_OUT(out_val, value) \
	G_STMT_START { \
		typeof(*(out_val)) *_out_val = (out_val); \
		\
		if (_out_val) { \
			*_out_val = (value); \
		} \
	} G_STMT_END

/********************************************************/

#define _NM_IN_SET_EVAL_1(op, x, y1)                              \
    ({                                                            \
        typeof(x) _x = (x);                                       \
        (   (_x == (y1))                                          \
        );                                                        \
    })

#define _NM_IN_SET_EVAL_2(op, x, y1, y2)                          \
    ({                                                            \
        typeof(x) _x = (x);                                       \
        (   (_x == (y1))                                          \
         op (_x == (y2))                                          \
        );                                                        \
    })

#define _NM_IN_SET_EVAL_3(op, x, y1, y2, y3)                      \
    ({                                                            \
        typeof(x) _x = (x);                                       \
        (   (_x == (y1))                                          \
         op (_x == (y2))                                          \
         op (_x == (y3))                                          \
        );                                                        \
    })

#define _NM_IN_SET_EVAL_4(op, x, y1, y2, y3, y4)                  \
    ({                                                            \
        typeof(x) _x = (x);                                       \
        (   (_x == (y1))                                          \
         op (_x == (y2))                                          \
         op (_x == (y3))                                          \
         op (_x == (y4))                                          \
        );                                                        \
    })

#define _NM_IN_SET_EVAL_5(op, x, y1, y2, y3, y4, y5)              \
    ({                                                            \
        typeof(x) _x = (x);                                       \
        (   (_x == (y1))                                          \
         op (_x == (y2))                                          \
         op (_x == (y3))                                          \
         op (_x == (y4))                                          \
         op (_x == (y5))                                          \
        );                                                        \
    })

#define _NM_IN_SET_EVAL_N2(op, x, n, ...)        _NM_IN_SET_EVAL_##n(op, x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_N(op, x, n, ...)         _NM_IN_SET_EVAL_N2(op, x, n, __VA_ARGS__)

/* Beware that this does short-circuit evaluation (use "||" instead of "|")
 * which has a possibly unexpected non-function-like behavior.
 * Use NM_IN_SET_SE if you need all arguments to be evaluted. */
#define NM_IN_SET(x, ...)               _NM_IN_SET_EVAL_N(||, x, NM_NARG (__VA_ARGS__), __VA_ARGS__)

/* "SE" stands for "side-effect". Contrary to NM_IN_SET(), this does not do
 * short-circuit evaluation, which can make a difference if the arguments have
 * side-effects. */
#define NM_IN_SET_SE(x, ...)            _NM_IN_SET_EVAL_N(|, x, NM_NARG (__VA_ARGS__), __VA_ARGS__)

/*****************************************************************************/

#define NM_PRINT_FMT_QUOTED(cond, prefix, str, suffix, str_else) \
	(cond) ? (prefix) : "", \
	(cond) ? (str) : (str_else), \
	(cond) ? (suffix) : ""
#define NM_PRINT_FMT_QUOTE_STRING(arg) NM_PRINT_FMT_QUOTED((arg), "\"", (arg), "\"", "(null)")

/*****************************************************************************/

#if NM_MORE_ASSERTS
#define nm_assert(cond) G_STMT_START { g_assert (cond); } G_STMT_END
#else
#define nm_assert(cond) G_STMT_START { if (FALSE) { if (cond) { } } } G_STMT_END
#endif

/*****************************************************************************/

static inline gboolean
nm_clear_g_source (guint *id)
{
	if (id && *id) {
		g_source_remove (*id);
		*id = 0;
		return TRUE;
	}
	return FALSE;
}

static inline gboolean
nm_clear_g_signal_handler (gpointer self, guint *id)
{
	if (id && *id) {
		g_signal_handler_disconnect (self, *id);
		*id = 0;
		return TRUE;
	}
	return FALSE;
}

static inline gboolean
nm_clear_g_variant (GVariant **variant)
{
	if (variant && *variant) {
		g_variant_unref (*variant);
		*variant = NULL;
		return TRUE;
	}
	return FALSE;
}

/*****************************************************************************/

/* Determine whether @x is a power of two (@x being an integer type).
 * For the special cases @x equals zero or one, it also returns true.
 * For negative @x, always returns FALSE. That only applies, if the data
 * type of @x is signed. */
#define nm_utils_is_power_of_two(x) ({ \
		const typeof(x) __x = (x); \
		\
		((__x & (__x - 1)) == 0) && \
			/* Check if the value is negative. In that case, return FALSE.
			 * The first expression is a compile time constant, depending on whether
			 * the type is signed. The second expression is a clumsy way for (__x >= 0),
			 * which causes a compiler warning for unsigned types. */ \
			( ( ((typeof(__x)) -1) > ((typeof(__x)) 0) ) || (__x > 0) || (__x == 0) ); \
	})

/*****************************************************************************/

/* check if @flags has exactly one flag (@check) set. You should call this
 * only with @check being a compile time constant and a power of two. */
#define NM_FLAGS_HAS(flags, check)  \
    ( (G_STATIC_ASSERT_EXPR ( ((check) != 0) && ((check) & ((check)-1)) == 0 )), (NM_FLAGS_ANY ((flags), (check))) )

#define NM_FLAGS_ANY(flags, check)  ( ( ((flags) & (check)) != 0       ) ? TRUE : FALSE )
#define NM_FLAGS_ALL(flags, check)  ( ( ((flags) & (check)) == (check) ) ? TRUE : FALSE )

#define NM_FLAGS_SET(flags, val)  ({ \
		const typeof(flags) _flags = (flags); \
		const typeof(flags) _val = (val); \
		\
		_flags | _val; \
	})

#define NM_FLAGS_UNSET(flags, val)  ({ \
		const typeof(flags) _flags = (flags); \
		const typeof(flags) _val = (val); \
		\
		_flags & (~_val); \
	})

#define NM_FLAGS_ASSIGN(flags, val, assign)  ({ \
		const typeof(flags) _flags = (flags); \
		const typeof(flags) _val = (val); \
		\
		(assign) \
			? _flags | (_val) \
			: _flags & (~_val); \
	})

/*****************************************************************************/

#define _NM_BACKPORT_SYMBOL_IMPL(VERSION, RETURN_TYPE, ORIG_FUNC, VERSIONED_FUNC, ARGS_TYPED, ARGS) \
RETURN_TYPE VERSIONED_FUNC ARGS_TYPED; \
RETURN_TYPE VERSIONED_FUNC ARGS_TYPED \
{ \
    return ORIG_FUNC ARGS; \
} \
RETURN_TYPE ORIG_FUNC ARGS_TYPED; \
__asm__(".symver "G_STRINGIFY(VERSIONED_FUNC)", "G_STRINGIFY(ORIG_FUNC)"@"G_STRINGIFY(VERSION))

#define NM_BACKPORT_SYMBOL(VERSION, RETURN_TYPE, FUNC, ARGS_TYPED, ARGS) \
_NM_BACKPORT_SYMBOL_IMPL(VERSION, RETURN_TYPE, FUNC, _##FUNC##_##VERSION, ARGS_TYPED, ARGS)

/*****************************************************************************/

static inline char *
nm_strstrip (char *str)
{
	/* g_strstrip doesn't like NULL. */
	return str ? g_strstrip (str) : NULL;
}

/*****************************************************************************/

static inline guint
nm_encode_version (guint major, guint minor, guint micro) {
	/* analog to the preprocessor macro NM_ENCODE_VERSION(). */
	return (major << 16) | (minor << 8) | micro;
}

static inline void
nm_decode_version (guint version, guint *major, guint *minor, guint *micro) {
	*major = (version & 0xFFFF0000u) >> 16;
	*minor = (version & 0x0000FF00u) >>  8;
	*micro = (version & 0x000000FFu);
}

/*****************************************************************************/

#endif /* __NM_MACROS_INTERNAL_H__ */
