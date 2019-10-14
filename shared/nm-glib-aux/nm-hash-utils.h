// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#ifndef __NM_HASH_UTILS_H__
#define __NM_HASH_UTILS_H__

#include "c-siphash/src/c-siphash.h"
#include "nm-macros-internal.h"

/*****************************************************************************/

#define NM_HASH_SEED_16(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, aa, ab, ac, ad, ae, af) \
	((const guint8[16]) { a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, aa, ab, ac, ad, ae, af })

void nm_hash_siphash42_init (CSipHash *h, guint static_seed);

/* Siphash24 of binary buffer @arr and @len, using the randomized seed from
 * other NMHash functions.
 *
 * Note, that this is guaranteed to use siphash42 under the hood (contrary to
 * all other NMHash API, which leave this undefined). That matters at the point,
 * where the caller needs to be sure that a reasonably strong hashing algorithm
 * is used.  (Yes, NMHash is all about siphash24, but otherwise that is not promised
 * anywhere).
 *
 * Another difference is, that this returns guint64 (not guint like other NMHash functions).
 *
 * Another difference is, that this may also return zero (not like nm_hash_complete()).
 *
 * Then, why not use c_siphash_hash() directly? Because this also uses the randomized,
 * per-run hash-seed like nm_hash_init(). So, you get siphash24 with a random
 * seed (which is cached for the current run of the program).
 */
static inline guint64
nm_hash_siphash42 (guint static_seed, const void *ptr, gsize n)
{
	CSipHash h;

	nm_hash_siphash42_init (&h, static_seed);
	c_siphash_append (&h, ptr, n);
	return c_siphash_finalize (&h);
}

/*****************************************************************************/

struct _NMHashState {
	CSipHash _state;
};

typedef struct _NMHashState NMHashState;

guint nm_hash_static (guint static_seed);

static inline void
nm_hash_init (NMHashState *state, guint static_seed)
{
	nm_assert (state);

	nm_hash_siphash42_init (&state->_state, static_seed);
}

static inline guint64
nm_hash_complete_u64 (NMHashState *state)
{
	nm_assert (state);

	/* this returns the native u64 hash value. Note that this differs
	 * from nm_hash_complete() in two ways:
	 *
	 * - the type, guint64 vs. guint.
	 * - nm_hash_complete() never returns zero.
	 *
	 * In practice, nm_hash*() API is implemented via siphash24, so this returns
	 * the siphash24 value. But that is not guaranteed by the API, and if you need
	 * siphash24 directly, use c_siphash_*() and nm_hash_siphash42*() API. */
	return c_siphash_finalize (&state->_state);
}

static inline guint
nm_hash_complete (NMHashState *state)
{
	guint64 h;

	h = nm_hash_complete_u64 (state);

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

	/* Note: the data passed in here might be sensitive data (secrets),
	 * that we should nm_explicty_zero() afterwards. However, since
	 * we are using siphash24 with a random key, that is not really
	 * necessary. Something to keep in mind, if we ever move away from
	 * this hash implementation. */
	c_siphash_append (&state->_state, ptr, n);
}

#define nm_hash_update_val(state, val) \
	G_STMT_START { \
		typeof (val) _val = (val); \
		\
		nm_hash_update ((state), &_val, sizeof (_val)); \
	} G_STMT_END

#define nm_hash_update_valp(state, val) \
	nm_hash_update ((state), (val), sizeof (*(val))) \

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
		nm_hash_update (state, ptr, n);
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

#define nm_hash_val(static_seed, val) \
	({ \
		NMHashState _h; \
		\
		nm_hash_init (&_h, (static_seed)); \
		nm_hash_update_val (&_h, (val)); \
		nm_hash_complete (&_h); \
	})

/*****************************************************************************/

/* nm_pstr_*() are for hashing keys that are pointers to strings,
 * that is, "const char *const*" types, using strcmp(). */

guint nm_pstr_hash (gconstpointer p);

gboolean nm_pstr_equal (gconstpointer a, gconstpointer b);

/*****************************************************************************/

/* this hashes/compares the pointer value that we point to. Basically,
 * (((const void *const*) a) == ((const void *const*) b)). */

guint nm_pdirect_hash (gconstpointer p);

gboolean nm_pdirect_equal (gconstpointer a, gconstpointer b);

/*****************************************************************************/

#define NM_HASH_OBFUSCATE_PTR_FMT "%016" G_GINT64_MODIFIER "x"

/* sometimes we want to log a pointer directly, for providing context/information about
 * the message that get logged. Logging pointer values directly defeats ASLR, so we should
 * not do that. This returns a "unsigned long long" value that can be used
 * instead.
 *
 * Note that there is a chance that two different pointer values hash to the same obfuscated
 * value. So beware of that when reviewing logs. However, such a collision is very unlikely. */
static inline guint64
nm_hash_obfuscate_ptr (guint static_seed, gconstpointer val)
{
	NMHashState h;

	nm_hash_init (&h, static_seed);
	nm_hash_update_val (&h, val);
	return nm_hash_complete_u64 (&h);
}

/* if you want to log obfuscated pointer for a certain context (like, NMPRuleManager
 * logging user-tags), then you are advised to use nm_hash_obfuscate_ptr() with your
 * own, unique static-seed.
 *
 * However, for example the singleton constructors log the obfuscated pointer values
 * for all singletons, so they must all be obfuscated with the same seed. So, this
 * macro uses a particular static seed that should be used by when comparing pointer
 * values in a global context. */
#define NM_HASH_OBFUSCATE_PTR(ptr) (nm_hash_obfuscate_ptr (1678382159u, ptr))

/*****************************************************************************/

#endif /* __NM_HASH_UTILS_H__ */
