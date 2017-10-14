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

#include "nm-shared-utils.h"
#include "nm-random-utils.h"

/*****************************************************************************/

guint
NM_HASH_INIT (guint seed)
{
	static volatile guint global_seed = 0;
	guint g, s;

	/* we xor @seed with a random @global_seed. This is to make the hashing behavior
	 * less predictable and harder to exploit collisions. */
	g = global_seed;
	if (G_UNLIKELY (g == 0)) {
		nm_utils_random_bytes (&s, sizeof (s));
		if (s == 0)
			s = 42;
		g_atomic_int_compare_and_exchange ((int *) &global_seed, 0, s);
		g = global_seed;
		nm_assert (g);
	}

	return g ^ seed;
}
