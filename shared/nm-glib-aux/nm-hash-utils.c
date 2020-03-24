// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-hash-utils.h"

#include <stdint.h>

#include "nm-shared-utils.h"
#include "nm-random-utils.h"

/*****************************************************************************/

#define HASH_KEY_SIZE 16u
#define HASH_KEY_SIZE_GUINT ((HASH_KEY_SIZE + sizeof (guint) - 1) / sizeof (guint))

G_STATIC_ASSERT (sizeof (guint) * HASH_KEY_SIZE_GUINT >= HASH_KEY_SIZE);

static const guint8 *volatile global_seed = NULL;

static const guint8 *
_get_hash_key_init (void)
{
	/* the returned hash is aligned to guin64, hence, it is safe
	 * to use it as guint* or guint64* pointer. */
	static union {
		guint8 v8[HASH_KEY_SIZE];
		guint _align_as_uint;
		guint32 _align_as_uint32;
		guint64 _align_as_uint64;
	} g_arr;
	const guint8 *g;

again:
	g = g_atomic_pointer_get (&global_seed);
	if (!G_UNLIKELY (g)) {
		static gsize g_lock;
		uint64_t h;
		union {
			guint vuint;
			guint8 v8[HASH_KEY_SIZE];
			guint8 _extra_entropy[3 * HASH_KEY_SIZE];
		} t_arr;

		nm_utils_random_bytes (&t_arr, sizeof (t_arr));

		/* We only initialize one random hash key. So we can spend some effort
		 * of getting this right. For one, we collect more random bytes than
		 * necessary.
		 *
		 * Then, the first guint of the seed should have all the entropy that we could
		 * obtain in sizeof(t_arr). For that, siphash(t_arr) and xor the first guint
		 * with hash.
		 * The first guint is especially interesting for nm_hash_static() below that
		 * doesn't use siphash itself. */
		h = c_siphash_hash (t_arr.v8,
		                    (const guint8 *) &t_arr,
		                    sizeof (t_arr));
		if (sizeof (h) > sizeof (guint))
			t_arr.vuint = t_arr.vuint ^ ((guint) (h & G_MAXUINT)) ^ ((guint) (h >> 32));
		else
			t_arr.vuint = t_arr.vuint ^ ((guint) (h & G_MAXUINT));

		if (!g_once_init_enter (&g_lock)) {
			/* lost a race. The random key is already initialized. */
			goto again;
		}

		memcpy (g_arr.v8, t_arr.v8, HASH_KEY_SIZE);
		g = g_arr.v8;
		g_atomic_pointer_set (&global_seed, g);
		g_once_init_leave (&g_lock, 1);
	}

	nm_assert (g == g_arr.v8);
	return g;
}

#define _get_hash_key() \
	({ \
		const guint8 *_g; \
		\
		_g = g_atomic_pointer_get (&global_seed); \
		if (G_UNLIKELY (!_g)) \
			_g = _get_hash_key_init (); \
		_g; \
	})

guint
nm_hash_static (guint static_seed)
{
	/* Note that we only xor the static_seed with the first guint of the key.
	 *
	 * We don't use siphash, which would mix the bits better with _get_hash_key().
	 * Note that nm_hash_static() isn't used to hash the static_seed. Instead, it
	 * is used to get a unique hash value in a static context. That means, every
	 * caller is responsible to choose a static_seed that is sufficiently
	 * distinct from all other callers. In other words, static_seed should be a
	 * unique constant with good entropy.
	 *
	 * Note that _get_hash_key_init() already xored the first guint of the
	 * key with the siphash of the entire static key. That means, even if
	 * we got bad randomness for the first guint, the first guint is also
	 * mixed with the randomness of the entire random key.
	 *
	 * Also, ensure that we don't return zero (like for nm_hash_complete()).
	 */
	return    ((*((const guint *) _get_hash_key ())) ^ static_seed)
	       ?: 3679500967u;
}

void
nm_hash_siphash42_init (CSipHash *h, guint static_seed)
{
	const guint8 *g;
	union {
		guint64 _align_as_uint64;
		guint arr[HASH_KEY_SIZE_GUINT];
	} seed;

	nm_assert (h);

	g = _get_hash_key ();
	memcpy (&seed, g, HASH_KEY_SIZE);
	seed.arr[0] ^= static_seed;
	c_siphash_init (h, (const guint8 *) &seed);
}

guint
nm_hash_str (const char *str)
{
	NMHashState h;

	if (!str)
		return nm_hash_static (1867854211u);
	nm_hash_init (&h, 1867854211u);
	nm_hash_update_str (&h, str);
	return nm_hash_complete (&h);
}

guint
nm_str_hash (gconstpointer str)
{
	return nm_hash_str (str);
}

guint
nm_hash_ptr (gconstpointer ptr)
{
	NMHashState h;

	if (!ptr)
		return nm_hash_static (2907677551u);
	nm_hash_init (&h, 2907677551u);
	nm_hash_update (&h, &ptr, sizeof (ptr));
	return nm_hash_complete (&h);
}

guint
nm_direct_hash (gconstpointer ptr)
{
	return nm_hash_ptr (ptr);
}

/*****************************************************************************/

guint
nm_pstr_hash (gconstpointer p)
{
	const char *const*s = p;

	if (!s)
		return nm_hash_static (101061439u);
	return nm_hash_str (*s);
}

gboolean
nm_pstr_equal (gconstpointer a, gconstpointer b)
{
	const char *const*s1 = a;
	const char *const*s2 = b;

	return    (s1 == s2)
	       || (   s1
	           && s2
	           && nm_streq0 (*s1, *s2));
}

guint
nm_pint_hash (gconstpointer p)
{
	const int *s = p;

	if (!s)
		return nm_hash_static (298377461u);
	return nm_hash_val (1208815757u, *s);
}

gboolean
nm_pint_equals (gconstpointer a, gconstpointer b)
{
	const int *s1 = a;
	const int *s2 = a;

	return    s1 == s2
	       || (s1 && s2 && *s1 == *s2);
}

guint
nm_pdirect_hash (gconstpointer p)
{
	const void *const*s = p;

	if (!s)
		return nm_hash_static (1852748873u);
	return nm_direct_hash (*s);
}

gboolean
nm_pdirect_equal (gconstpointer a, gconstpointer b)
{
	const void *const*s1 = a;
	const void *const*s2 = b;

	return    (s1 == s2)
	       || (   s1
	           && s2
	           && *s1 == *s2);
}

guint
nm_ppdirect_hash (gconstpointer p)
{
	const void *const*const*s = p;

	if (!s)
		return nm_hash_static (396534869u);
	if (!*s)
		return nm_hash_static (1476102263u);
	return nm_direct_hash (**s);
}

gboolean
nm_ppdirect_equal (gconstpointer a, gconstpointer b)
{
	const void *const*const*s1 = a;
	const void *const*const*s2 = b;

	if (s1 == s2)
		return TRUE;
	if (!s1 || !s2)
		return FALSE;

	if (*s1 == *s2)
		return TRUE;
	if (!*s1 || !*s2)
		return FALSE;

	return **s1 == **s2;
}

/*****************************************************************************/

guint
nm_pgbytes_hash (gconstpointer p)
{
	GBytes *const*ptr = p;
	gconstpointer arr;
	gsize len;

	arr = g_bytes_get_data (*ptr, &len);
	return nm_hash_mem (1470631313u, arr, len);
}

gboolean
nm_pgbytes_equal (gconstpointer a, gconstpointer b)
{
	GBytes *const*ptr_a = a;
	GBytes *const*ptr_b = b;

	return g_bytes_equal (*ptr_a, *ptr_b);
}
