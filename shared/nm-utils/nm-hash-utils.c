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
	} g_arr _nm_alignas (guint64);
	static gsize g_lock;
	const guint8 *g;
	CSipHash siph_state;
	uint64_t h;
	guint *p;

	g = global_seed;
	if (G_LIKELY (g != NULL)) {
		nm_assert (g == g_arr.v8);
		return g;
	}

	if (g_once_init_enter (&g_lock)) {

		nm_utils_random_bytes (g_arr.v8, sizeof (g_arr.v8));

		/* use siphash() of the key-size, to mangle the first guint. Otherwise,
		 * the first guint has only the entropy that nm_utils_random_bytes()
		 * generated for the first 4 bytes and relies on a good random generator. */
		c_siphash_init (&siph_state, g_arr.v8);
		c_siphash_append (&siph_state, g_arr.v8, sizeof (g_arr.v8));
		h = c_siphash_finalize (&siph_state);
		p = (guint *) g_arr.v8;
		if (sizeof (guint) < sizeof (h))
			*p = *p ^ ((guint) (h & 0xFFFFFFFFu)) ^ ((guint) (h >> 32));
		else
			*p = *p ^ ((guint) (h & 0xFFFFFFFFu));

		g_atomic_pointer_compare_and_exchange (&global_seed, NULL, g_arr.v8);
		g_once_init_leave (&g_lock, 1);
	}

	nm_assert (global_seed == g_arr.v8);
	return g_arr.v8;
}

#define _get_hash_key() \
	({ \
		const guint8 *_g; \
		\
		_g = global_seed; \
		if (G_UNLIKELY (_g == NULL)) \
			_g = _get_hash_key_init (); \
		_g; \
	})

guint
nm_hash_static (guint static_seed)
{
	/* note that we only xor the static_seed with the key.
	 * We don't use siphash, which would mix the bits better.
	 * Note that this doesn't matter, because static_seed is not
	 * supposed to be a value that you are hashing (for that, use
	 * full siphash).
	 * Instead, different callers may set a different static_seed
	 * so that nm_hash_str(NULL) != nm_hash_ptr(NULL).
	 *
	 * Also, ensure that we don't return zero.
	 */
	return ((*((const guint *) _get_hash_key ())) ^ static_seed)
	       ?: static_seed ?: 3679500967u;
}

void
nm_hash_init (NMHashState *state, guint static_seed)
{
	const guint8 *g;
	guint seed[HASH_KEY_SIZE_GUINT];

	nm_assert (state);

	g = _get_hash_key ();
	memcpy (seed, g, HASH_KEY_SIZE);
	seed[0] ^= static_seed;
	c_siphash_init (&state->_state, (const guint8 *) seed);
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
