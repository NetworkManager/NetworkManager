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
 * (C) Copyright 2017 Red Hat, Inc.
 */

#ifndef __NM_HASH_UTILS_H__
#define __NM_HASH_UTILS_H__

#include "c-siphash/src/c-siphash.h"
#include "nm-macros-internal.h"

struct _NMHashState {
	CSipHash _state;
};

typedef struct _NMHashState NMHashState;

guint nm_hash_static (guint static_seed);

void nm_hash_init (NMHashState *state, guint static_seed);

static inline guint
nm_hash_complete (NMHashState *state)
{
	guint64 h;

	nm_assert (state);

	h = c_siphash_finalize (&state->_state);

	/* we don't ever want to return a zero hash.
	 *
	 * NMPObject requires that in _idx_obj_part(), and it's just a good idea. */
	return (((guint) (h >> 32)) ^ ((guint) h)) ?: 1396707757u;
}

static inline void
nm_hash_update (NMHashState *state, const void *ptr, gsize n)
{
	nm_assert (state);
	nm_assert (ptr);
	nm_assert (n > 0);

	c_siphash_append (&state->_state, ptr, n);
}

#define nm_hash_update_val(state, val) \
	G_STMT_START { \
		typeof (val) _val = (val); \
		\
		nm_hash_update ((state), &_val, sizeof (_val)); \
	} G_STMT_END

static inline void
nm_hash_update_bool (NMHashState *state, bool val)
{
	nm_hash_update (state, &val, sizeof (val));
}

#define _NM_HASH_COMBINE_BOOLS_x_1( t, y)      ((y) ? ((t) (1ull <<  0)) : ((t) 0ull))
#define _NM_HASH_COMBINE_BOOLS_x_2( t, y, ...) ((y) ? ((t) (1ull <<  1)) : ((t) 0ull)) | _NM_HASH_COMBINE_BOOLS_x_1  (t, __VA_ARGS__)
#define _NM_HASH_COMBINE_BOOLS_x_3( t, y, ...) ((y) ? ((t) (1ull <<  2)) : ((t) 0ull)) | _NM_HASH_COMBINE_BOOLS_x_2  (t, __VA_ARGS__)
#define _NM_HASH_COMBINE_BOOLS_x_4( t, y, ...) ((y) ? ((t) (1ull <<  3)) : ((t) 0ull)) | _NM_HASH_COMBINE_BOOLS_x_3  (t, __VA_ARGS__)
#define _NM_HASH_COMBINE_BOOLS_x_5( t, y, ...) ((y) ? ((t) (1ull <<  4)) : ((t) 0ull)) | _NM_HASH_COMBINE_BOOLS_x_4  (t, __VA_ARGS__)
#define _NM_HASH_COMBINE_BOOLS_x_6( t, y, ...) ((y) ? ((t) (1ull <<  5)) : ((t) 0ull)) | _NM_HASH_COMBINE_BOOLS_x_5  (t, __VA_ARGS__)
#define _NM_HASH_COMBINE_BOOLS_x_7( t, y, ...) ((y) ? ((t) (1ull <<  6)) : ((t) 0ull)) | _NM_HASH_COMBINE_BOOLS_x_6  (t, __VA_ARGS__)
#define _NM_HASH_COMBINE_BOOLS_x_8( t, y, ...) ((y) ? ((t) (1ull <<  7)) : ((t) 0ull)) | _NM_HASH_COMBINE_BOOLS_x_7  (t, __VA_ARGS__)
#define _NM_HASH_COMBINE_BOOLS_x_9( t, y, ...) ((y) ? ((t) (1ull <<  8)) : ((t) 0ull)) | (G_STATIC_ASSERT_EXPR (sizeof (t) >= 2), (_NM_HASH_COMBINE_BOOLS_x_8  (t, __VA_ARGS__)))
#define _NM_HASH_COMBINE_BOOLS_x_10(t, y, ...) ((y) ? ((t) (1ull <<  9)) : ((t) 0ull)) | _NM_HASH_COMBINE_BOOLS_x_9  (t, __VA_ARGS__)
#define _NM_HASH_COMBINE_BOOLS_x_11(t, y, ...) ((y) ? ((t) (1ull << 10)) : ((t) 0ull)) | _NM_HASH_COMBINE_BOOLS_x_10 (t, __VA_ARGS__)
#define _NM_HASH_COMBINE_BOOLS_n2(t, n, ...) _NM_HASH_COMBINE_BOOLS_x_##n (t, __VA_ARGS__)
#define _NM_HASH_COMBINE_BOOLS_n(t, n, ...) _NM_HASH_COMBINE_BOOLS_n2(t, n, __VA_ARGS__)

#define NM_HASH_COMBINE_BOOLS(type, ...) ((type) (_NM_HASH_COMBINE_BOOLS_n(type, NM_NARG (__VA_ARGS__), __VA_ARGS__)))

#define nm_hash_update_bools(state, ...) \
	nm_hash_update_val (state, NM_HASH_COMBINE_BOOLS (guint8, __VA_ARGS__))

#define _NM_HASH_COMBINE_VALS_typ_x_1( y)       typeof (y) _v1;
#define _NM_HASH_COMBINE_VALS_typ_x_2( y, ...)  typeof (y) _v2;  _NM_HASH_COMBINE_VALS_typ_x_1  (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_typ_x_3( y, ...)  typeof (y) _v3;  _NM_HASH_COMBINE_VALS_typ_x_2  (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_typ_x_4( y, ...)  typeof (y) _v4;  _NM_HASH_COMBINE_VALS_typ_x_3  (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_typ_x_5( y, ...)  typeof (y) _v5;  _NM_HASH_COMBINE_VALS_typ_x_4  (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_typ_x_6( y, ...)  typeof (y) _v6;  _NM_HASH_COMBINE_VALS_typ_x_5  (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_typ_x_7( y, ...)  typeof (y) _v7;  _NM_HASH_COMBINE_VALS_typ_x_6  (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_typ_x_8( y, ...)  typeof (y) _v8;  _NM_HASH_COMBINE_VALS_typ_x_7  (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_typ_x_9( y, ...)  typeof (y) _v9;  _NM_HASH_COMBINE_VALS_typ_x_8  (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_typ_x_10(y, ...)  typeof (y) _v10; _NM_HASH_COMBINE_VALS_typ_x_9  (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_typ_x_11(y, ...)  typeof (y) _v11; _NM_HASH_COMBINE_VALS_typ_x_10  (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_typ_x_12(y, ...)  typeof (y) _v12; _NM_HASH_COMBINE_VALS_typ_x_11 (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_typ_x_13(y, ...)  typeof (y) _v13; _NM_HASH_COMBINE_VALS_typ_x_12 (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_typ_x_14(y, ...)  typeof (y) _v14; _NM_HASH_COMBINE_VALS_typ_x_13 (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_typ_x_15(y, ...)  typeof (y) _v15; _NM_HASH_COMBINE_VALS_typ_x_14 (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_typ_x_16(y, ...)  typeof (y) _v16; _NM_HASH_COMBINE_VALS_typ_x_15 (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_typ_x_17(y, ...)  typeof (y) _v17; _NM_HASH_COMBINE_VALS_typ_x_16 (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_typ_x_18(y, ...)  typeof (y) _v18; _NM_HASH_COMBINE_VALS_typ_x_17 (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_typ_x_19(y, ...)  typeof (y) _v19; _NM_HASH_COMBINE_VALS_typ_x_18 (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_typ_x_20(y, ...)  typeof (y) _v20; _NM_HASH_COMBINE_VALS_typ_x_19 (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_typ_n2(n, ...) _NM_HASH_COMBINE_VALS_typ_x_##n (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_typ_n(n, ...) _NM_HASH_COMBINE_VALS_typ_n2(n, __VA_ARGS__)

#define _NM_HASH_COMBINE_VALS_val_x_1( y)       ._v1  = (y),
#define _NM_HASH_COMBINE_VALS_val_x_2( y, ...)  ._v2  = (y), _NM_HASH_COMBINE_VALS_val_x_1  (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_val_x_3( y, ...)  ._v3  = (y), _NM_HASH_COMBINE_VALS_val_x_2  (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_val_x_4( y, ...)  ._v4  = (y), _NM_HASH_COMBINE_VALS_val_x_3  (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_val_x_5( y, ...)  ._v5  = (y), _NM_HASH_COMBINE_VALS_val_x_4  (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_val_x_6( y, ...)  ._v6  = (y), _NM_HASH_COMBINE_VALS_val_x_5  (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_val_x_7( y, ...)  ._v7  = (y), _NM_HASH_COMBINE_VALS_val_x_6  (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_val_x_8( y, ...)  ._v8  = (y), _NM_HASH_COMBINE_VALS_val_x_7  (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_val_x_9( y, ...)  ._v9  = (y), _NM_HASH_COMBINE_VALS_val_x_8  (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_val_x_10(y, ...)  ._v10 = (y), _NM_HASH_COMBINE_VALS_val_x_9  (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_val_x_11(y, ...)  ._v11 = (y), _NM_HASH_COMBINE_VALS_val_x_10  (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_val_x_12(y, ...)  ._v12 = (y), _NM_HASH_COMBINE_VALS_val_x_11 (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_val_x_13(y, ...)  ._v13 = (y), _NM_HASH_COMBINE_VALS_val_x_12 (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_val_x_14(y, ...)  ._v14 = (y), _NM_HASH_COMBINE_VALS_val_x_13 (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_val_x_15(y, ...)  ._v15 = (y), _NM_HASH_COMBINE_VALS_val_x_14 (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_val_x_16(y, ...)  ._v16 = (y), _NM_HASH_COMBINE_VALS_val_x_15 (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_val_x_17(y, ...)  ._v17 = (y), _NM_HASH_COMBINE_VALS_val_x_16 (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_val_x_18(y, ...)  ._v18 = (y), _NM_HASH_COMBINE_VALS_val_x_17 (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_val_x_19(y, ...)  ._v19 = (y), _NM_HASH_COMBINE_VALS_val_x_18 (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_val_x_20(y, ...)  ._v20 = (y), _NM_HASH_COMBINE_VALS_val_x_19 (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_val_n2(n, ...) _NM_HASH_COMBINE_VALS_val_x_##n (__VA_ARGS__)
#define _NM_HASH_COMBINE_VALS_val_n(n, ...) _NM_HASH_COMBINE_VALS_val_n2(n, __VA_ARGS__)

/* NM_HASH_COMBINE_VALS() is faster then nm_hash_update_val() as it combines multiple
 * calls to nm_hash_update() using a packed structure. */
#define NM_HASH_COMBINE_VALS(var, ...) \
	const struct _nm_packed { \
		_NM_HASH_COMBINE_VALS_typ_n (NM_NARG (__VA_ARGS__), __VA_ARGS__) \
	} var _nm_alignas (guint64) = { \
		_NM_HASH_COMBINE_VALS_val_n (NM_NARG (__VA_ARGS__), __VA_ARGS__) \
	}

/* nm_hash_update_vals() is faster then nm_hash_update_val() as it combines multiple
 * calls to nm_hash_update() using a packed structure. */
#define nm_hash_update_vals(state, ...) \
	G_STMT_START { \
		NM_HASH_COMBINE_VALS (_val, __VA_ARGS__); \
		\
		nm_hash_update ((state), &_val, sizeof (_val)); \
	} G_STMT_END

static inline void
nm_hash_update_mem (NMHashState *state, const void *ptr, gsize n)
{
	/* This also hashes the length of the data. That means,
	 * hashing two consecutive binary fields (of arbitrary
	 * length), will hash differently. That is,
	 * [[1,1], []] differs from [[1],[1]].
	 *
	 * If you have a constant length (sizeof), use nm_hash_update()
	 * instead. */
	nm_hash_update (state, &n, sizeof (n));
	if (n > 0)
		c_siphash_append (&state->_state, ptr, n);
}

static inline void
nm_hash_update_str0 (NMHashState *state, const char *str)
{
	if (str)
		nm_hash_update_mem (state, str, strlen (str));
	else {
		gsize n = G_MAXSIZE;

		nm_hash_update (state, &n, sizeof (n));
	}
}

static inline void
nm_hash_update_str (NMHashState *state, const char *str)
{
	nm_assert (str);
	nm_hash_update (state, str, strlen (str) + 1);
}

#if _NM_CC_SUPPORT_GENERIC
/* Like nm_hash_update_str(), but restricted to arrays only. nm_hash_update_str() only works
 * with a @str argument that cannot be NULL. If you have a string pointer, that is never NULL, use
 * nm_hash_update() instead. */
#define nm_hash_update_strarr(state, str) \
	(_Generic (&(str), \
		const char (*) [sizeof (str)]: nm_hash_update_str ((state), (str)), \
		char (*) [sizeof (str)]:       nm_hash_update_str ((state), (str))) \
	)
#else
#define nm_hash_update_strarr(state, str) nm_hash_update_str ((state), (str))
#endif

guint nm_hash_ptr (gconstpointer ptr);
guint nm_direct_hash (gconstpointer str);

guint nm_hash_str (const char *str);
guint nm_str_hash (gconstpointer str);

/*****************************************************************************/

/* nm_pstr_*() are for hashing keys that are pointers to strings,
 * that is, "const char *const*" types, using strcmp(). */

guint nm_pstr_hash (gconstpointer p);

gboolean nm_pstr_equal (gconstpointer a, gconstpointer b);

/*****************************************************************************/

#endif /* __NM_HASH_UTILS_H__ */
