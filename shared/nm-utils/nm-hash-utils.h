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

#include "siphash24.h"

typedef struct {
	struct siphash _state;
} NMHashState;

void nm_hash_init (NMHashState *state, guint static_seed);

static inline guint
nm_hash_complete (NMHashState *state)
{
	guint64 h;

	nm_assert (state);

	h = siphash24_finalize (&state->_state);

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

	siphash24_compress (ptr, n, &state->_state);
}

static inline void
nm_hash_update_uint (NMHashState *state, guint val)
{
	nm_hash_update (state, &val, sizeof (val));
}

static inline void
nm_hash_update_uint64 (NMHashState *state, guint64 val)
{
	nm_hash_update (state, &val, sizeof (val));
}

static inline void
nm_hash_update_ptr (NMHashState *state, gconstpointer ptr)
{
	nm_hash_update (state, &ptr, sizeof (ptr));
}

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
		siphash24_compress (ptr, n, &state->_state);
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

#endif /* __NM_HASH_UTILS_H__ */
