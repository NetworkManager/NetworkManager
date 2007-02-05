#ifndef NM_CALLBACK_STORE_H
#define NM_CALLBACK_STORE_H

#include <glib-object.h>

typedef GHashTable NMCallStore;

typedef gboolean (*NMCallStoreFunc) (GObject *object, gpointer call_id, gpointer user_data);

NMCallStore *nm_call_store_new     (void);
void         nm_call_store_add     (NMCallStore *store,
									GObject *object,
									gpointer *call_id);

void         nm_call_store_remove  (NMCallStore *store,
									GObject *object,
									gpointer call_id);

int          nm_call_store_foreach (NMCallStore *store,
									GObject *object,
									NMCallStoreFunc callback,
									gpointer user_data);

void         nm_call_store_clear   (NMCallStore *store);
void         nm_call_store_destroy (NMCallStore *store);

#endif /* NM_CALLBACK_STORE_H */
