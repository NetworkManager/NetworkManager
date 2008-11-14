/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * libnm_glib -- Access network status & information from glib applications
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
 * Copyright (C) 2008 Red Hat, Inc.
 */

#include <string.h>
#include <glib.h>
#include "nm-object-cache.h"
#include "nm-object.h"

static GHashTable *cache = NULL;

static void
_init_cache (void)
{
	if (G_UNLIKELY (cache == NULL))
		cache = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
}

void
_nm_object_cache_remove_by_path (const char *path)
{
	_init_cache ();
	g_hash_table_remove (cache, path);
}

void
_nm_object_cache_remove_by_object (NMObject *object)
{
	_init_cache ();
	g_hash_table_remove (cache, nm_object_get_path (object));
}

void
_nm_object_cache_add (NMObject *object)
{
	char *path;

	_init_cache ();
	path = g_strdup (nm_object_get_path (object));
	g_hash_table_insert (cache, path, object);
	g_object_set_data_full (G_OBJECT (object), "nm-object-cache-tag",
	                        path, (GDestroyNotify) _nm_object_cache_remove_by_path);
}

NMObject *
_nm_object_cache_get (const char *path)
{
	NMObject *object;

	_init_cache ();
	object = g_hash_table_lookup (cache, path);
	return object;
}

