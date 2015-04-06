/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
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
 * Copyright 2008 Red Hat, Inc.
 */

#include "config.h"

#include <string.h>
#include "nm-glib.h"
#include "nm-object-cache.h"
#include "nm-object.h"

static GHashTable *cache = NULL;

static void
_init_cache (void)
{
	if (G_UNLIKELY (cache == NULL))
		cache = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
}

static void
_nm_object_cache_remove_by_path (char *path)
{
	_init_cache ();
	g_hash_table_remove (cache, path);
	g_free (path);
}

void
_nm_object_cache_add (NMObject *object)
{
	char *path;

	_init_cache ();
	path = g_strdup (nm_object_get_path (object));
	g_hash_table_insert (cache, path, object);
	g_object_set_data_full (G_OBJECT (object), "nm-object-cache-tag",
	                        g_strdup (path), (GDestroyNotify) _nm_object_cache_remove_by_path);
}

NMObject *
_nm_object_cache_get (const char *path)
{
	NMObject *object;

	_init_cache ();
	object = g_hash_table_lookup (cache, path);
	return object ? g_object_ref (object) : NULL;
}

void
_nm_object_cache_clear (void)
{
	GHashTableIter iter;
	GObject *obj;
	const char *path;
	char *foo;

	if (!cache)
		return;

	g_hash_table_iter_init (&iter, cache);
	while (g_hash_table_iter_next (&iter, (gpointer) &path, (gpointer) &obj)) {
		/* Remove the callback so that if the object isn't yet released
		 * by a client, when it does finally get unrefed, it won't trigger
		 * the cache removal for a new object with the same path as the
		 * one being released.
		 */
		foo = g_object_steal_data (obj, "nm-object-cache-tag");
		g_free (foo);

		g_hash_table_iter_remove (&iter);
	}
}
