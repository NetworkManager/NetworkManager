/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2007 Novell, Inc.
 * Copyright (C) 2010 Red Hat, Inc.
 */

#include "nm-call-store.h"
#include "nm-logging.h"

NMCallStore *
nm_call_store_new (void)
{
	return g_hash_table_new_full (NULL, NULL, NULL,
								  (GDestroyNotify) g_hash_table_destroy);
}

static void
object_destroyed_cb (gpointer data, GObject *object)
{
	g_hash_table_remove ((NMCallStore *) data, object);
}

void
nm_call_store_add (NMCallStore *store,
				   GObject *object,
				   gpointer *call_id)
{
	GHashTable *call_ids_hash;

	g_return_if_fail (store != NULL);
	g_return_if_fail (object != NULL);
	g_return_if_fail (call_id != NULL);

	call_ids_hash = g_hash_table_lookup (store, object);
	if (!call_ids_hash) {
		call_ids_hash = g_hash_table_new (NULL, NULL);
		g_hash_table_insert (store, object, call_ids_hash);
		g_object_weak_ref (object, object_destroyed_cb, store);
	}

	g_hash_table_insert (call_ids_hash, call_id, NULL);
}

void
nm_call_store_remove (NMCallStore *store,
					  GObject *object,
					  gpointer call_id)
{
	GHashTable *call_ids_hash;

	g_return_if_fail (store != NULL);
	g_return_if_fail (object != NULL);
	g_return_if_fail (call_id != NULL);

	call_ids_hash = g_hash_table_lookup (store, object);
	if (!call_ids_hash) {
		nm_log_warn (LOGD_CORE, "Trying to remove a non-existant call id.");
		return;
	}

	if (!g_hash_table_remove (call_ids_hash, call_id))
		nm_log_warn (LOGD_CORE, "Trying to remove a non-existant call id.");

	if (g_hash_table_size (call_ids_hash) == 0) {
		g_hash_table_remove (store, object);
		g_object_weak_unref (object, object_destroyed_cb, store);
	}
}

typedef struct {
	GObject *object;
	gint count;
	NMCallStoreFunc callback;
	gpointer user_data;
} StoreForeachInfo;

static void
call_callback (gpointer call_id, gpointer user_data)
{
	StoreForeachInfo *info = (StoreForeachInfo *) user_data;

	if (info->count >= 0) {
		if (info->callback (info->object, call_id, info->user_data))
			info->count++;
		else
			info->count = -1;
	}
}

static void
prepend_id (gpointer key, gpointer value, gpointer user_data)
{
	GSList **list = (GSList **) user_data;

	*list = g_slist_prepend (*list, key);
}

static GSList *
get_call_ids (GHashTable *hash)
{
	GSList *ids = NULL;

	g_hash_table_foreach (hash, prepend_id, &ids);

	return ids;
}

static void
call_all_callbacks (gpointer key, gpointer value, gpointer user_data)
{
	StoreForeachInfo *info = (StoreForeachInfo *) user_data;
	GSList *ids;

	info->object = G_OBJECT (key);

	/* Create a copy of the hash keys (call_ids) so that the callback is
	   free to modify the store */
	ids = get_call_ids ((GHashTable *) value);
	g_slist_foreach (ids, call_callback, info);
	g_slist_free (ids);
}

static void
duplicate_hash (gpointer key, gpointer value, gpointer user_data)
{
	g_hash_table_insert ((GHashTable *) user_data, key, value);
}

int
nm_call_store_foreach (NMCallStore *store,
					   GObject *object,
					   NMCallStoreFunc callback,
					   gpointer user_data)
{
	StoreForeachInfo info;

	g_return_val_if_fail (store != NULL, -1);
	g_return_val_if_fail (callback != NULL, -1);

	info.object = object;
	info.count = 0;
	info.callback = callback;
	info.user_data = user_data;

	if (object) {
		GHashTable *call_ids_hash;
		GSList *ids;

		call_ids_hash = g_hash_table_lookup (store, object);
		if (!call_ids_hash) {
			nm_log_warn (LOGD_CORE, "Object not in store");
			return -1;
		}

		/* Create a copy of the hash keys (call_ids) so that the callback is
		   free to modify the store */
		ids = get_call_ids (call_ids_hash);
		g_slist_foreach (ids, call_callback, &info);
		g_slist_free (ids);
	} else {
		GHashTable *copy;

		/* Create a copy of the main store so that callbacks can modify it */
		copy = g_hash_table_new (NULL, NULL);
		g_hash_table_foreach (store, duplicate_hash, copy);
		g_hash_table_foreach (copy, call_all_callbacks, &info);
		g_hash_table_destroy (copy);
	}

	return info.count;
}

static void
remove_weakref (gpointer key, gpointer value, gpointer user_data)
{
	g_object_weak_unref (G_OBJECT (key), object_destroyed_cb, user_data);
}

void
nm_call_store_clear (NMCallStore *store)
{
	g_return_if_fail (store);

	g_hash_table_foreach (store, remove_weakref, store);
	g_hash_table_remove_all (store);
}

void
nm_call_store_destroy (NMCallStore *store)
{
	g_return_if_fail (store);

	g_hash_table_destroy (store);
}
