#include "nm-call-store.h"
#include "nm-utils.h"

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
		nm_warning ("Trying to move a non-existant call id.");
		return;
	}

	if (!g_hash_table_remove (call_ids_hash, call_id))
		nm_warning ("Trying to move a non-existant call id.");

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
call_callback (gpointer key, gpointer value, gpointer user_data)
{
	StoreForeachInfo *info = (StoreForeachInfo *) user_data;

	if (info->count >= 0) {
		if (info->callback (info->object, key, info->user_data))
			info->count++;
		else
			info->count = -1;
	}
}

static void
call_all_callbacks (gpointer key, gpointer value, gpointer user_data)
{
	StoreForeachInfo *info = (StoreForeachInfo *) user_data;

	info->object = G_OBJECT (key);
	g_hash_table_foreach ((GHashTable *) value, call_callback, info);
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

		call_ids_hash = g_hash_table_lookup (store, object);
		if (!call_ids_hash) {
			nm_warning ("Object not in store");
			return -1;
		}

		g_hash_table_foreach (call_ids_hash, call_callback, &info);
	} else {
		g_hash_table_foreach (store, call_all_callbacks, &info);
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
