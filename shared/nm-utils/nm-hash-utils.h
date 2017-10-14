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

guint NM_HASH_INIT (guint seed);

static inline guint
NM_HASH_COMBINE (guint h, guint val)
{
	/* see g_str_hash() for reasons */
	return (h << 5) + h + val;
}

static inline guint
NM_HASH_COMBINE_UINT64 (guint h, guint64 val)
{
	return NM_HASH_COMBINE (h, (((guint) val) & 0xFFFFFFFFu) + ((guint) (val >> 32)));
}

static inline guint
NM_HASH_POINTER (gconstpointer ptr)
{
	/* same as g_direct_hash(), but inline. */
	return GPOINTER_TO_UINT (ptr);
}

#endif /* __NM_HASH_UTILS_H__ */
