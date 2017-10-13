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

#include <stdint.h>

typedef struct {
	guint hash;
} NMHashState;

void nm_hash_init (NMHashState *state, guint static_seed);

static inline guint
nm_hash_complete (NMHashState *state)
{
	nm_assert (state);
	/* we don't ever want to return a zero hash.
	 *
	 * NMPObject requires that in _idx_obj_part(), and it's just a good idea. */
	return state->hash ?: 1396707757u;
}

static inline void
nm_hash_update_uint (NMHashState *state, guint val)
{
	guint h;

	nm_assert (state);

	h = state->hash;
	h = (h << 5) + h + val;
	state->hash = h;
}

static inline void
nm_hash_update_uint64 (NMHashState *state, guint64 val)
{
	guint h;

	nm_assert (state);

	h = state->hash;
	h = (h << 5) + h + ((guint) val);
	h = (h << 5) + h + ((guint) (val >> 32));
	state->hash = h;
}

static inline void
nm_hash_update_ptr (NMHashState *state, gconstpointer ptr)
{
	if (sizeof (ptr) <= sizeof (guint))
		nm_hash_update_uint (state, ((guint) ((uintptr_t) ptr)));
	else
		nm_hash_update_uint64 (state, (guint64) ((uintptr_t) ptr));
}

static inline void
nm_hash_update_mem (NMHashState *state, const void *ptr, gsize n)
{
	gsize i;
	guint h;

	nm_assert (state);

	/* use the same hash seed as nm_hash_update_str().
	 * That way, nm_hash_update_str(&h, s) is identical to
	 * nm_hash_update_mem(&h, s, strlen(s)). */
	h = state->hash;
	for (i = 0; i < n; i++)
		h = (h << 5) + h + ((guint) ((const guint8 *) ptr)[i]);
	h = (h << 5) + h + 1774132687u;
	state->hash = h;
}

static inline void
nm_hash_update_str (NMHashState *state, const char *str)
{
	const guint8 *p = (const guint8 *) str;
	guint8 c;
	guint h;

	nm_assert (state);

	/* Note that NULL hashes differently from "". */
	h = state->hash;
	if (str) {
		while ((c = *p++))
			h = (h << 5) + h + ((guint) c);
		h = (h << 5) + h + 1774132687u;
	} else
		h = (h << 5) + h + 2967906233u;
	state->hash = h;
}

static inline guint
nm_hash_ptr (gconstpointer ptr)
{
	if (sizeof (ptr) <= sizeof (guint))
		return (guint) ((uintptr_t) ptr);
	else
		return ((guint) (((uintptr_t) ptr) >> 32)) ^ ((guint) ((uintptr_t) ptr));
}
guint nm_direct_hash (gconstpointer str);

guint nm_hash_str (const char *str);
guint nm_str_hash (gconstpointer str);

#endif /* __NM_HASH_UTILS_H__ */
