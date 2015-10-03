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
 * Copyright 2007 - 2008 Novell, Inc.
 * Copyright 2007 - 2012 Red Hat, Inc.
 */

#include "config.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <nm-utils.h>
#include "nm-default.h"
#include "nm-dbus-interface.h"
#include "nm-object.h"
#include "nm-object-cache.h"
#include "nm-object-private.h"
#include "nm-dbus-helpers.h"
#include "nm-client.h"
#include "nm-core-internal.h"
#include "nm-macros-internal.h"

static gboolean debug = FALSE;
#define dbgmsg(f,...) if (G_UNLIKELY (debug)) { g_message (f, ## __VA_ARGS__ ); }

static void nm_object_initable_iface_init (GInitableIface *iface);
static void nm_object_async_initable_iface_init (GAsyncInitableIface *iface);

typedef struct {
	NMObjectDecideTypeFunc type_func;
	char *interface;
	char *property;
} NMObjectTypeFuncData;

static GHashTable *type_funcs;

typedef struct {
	GSList *interfaces;
} NMObjectClassPrivate;

#define NM_OBJECT_CLASS_GET_PRIVATE(k) (G_TYPE_CLASS_GET_PRIVATE ((k), NM_TYPE_OBJECT, NMObjectClassPrivate))

G_DEFINE_ABSTRACT_TYPE_WITH_CODE (NMObject, nm_object, G_TYPE_OBJECT,
                                  type_funcs = g_hash_table_new (NULL, NULL);
                                  g_type_add_class_private (g_define_type_id, sizeof (NMObjectClassPrivate));
                                  G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, nm_object_initable_iface_init);
                                  G_IMPLEMENT_INTERFACE (G_TYPE_ASYNC_INITABLE, nm_object_async_initable_iface_init);
                                  )

#define NM_OBJECT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_OBJECT, NMObjectPrivate))

typedef struct {
	PropertyMarshalFunc func;
	GType object_type;
	gpointer field;
	const char *signal_prefix;
} PropertyInfo;

static void reload_complete (NMObject *object, gboolean emit_now);
static gboolean demarshal_generic (NMObject *object, GParamSpec *pspec, GVariant *value, gpointer field);

typedef struct {
	GDBusConnection *connection;
	gboolean nm_running;

	char *path;
	GHashTable *proxies;
	GDBusProxy *properties_proxy;
	GSList *property_tables;
	NMObject *parent;
	gboolean suppress_property_updates;

	GSList *notify_items;
	guint32 notify_id;

	GSList *reload_results;
	guint reload_remaining;
	GError *reload_error;
} NMObjectPrivate;

enum {
	PROP_0,
	PROP_PATH,
	PROP_DBUS_CONNECTION,
	PROP_NM_RUNNING,

	LAST_PROP
};

/**
 * _nm_object_class_add_interface:
 * @object_class: an #NMObjectClass
 * @interface: a D-Bus interface name
 *
 * Registers that @object_class implements @interface. A proxy for that
 * interface will automatically be created at construction time, and can
 * be retrieved with _nm_object_get_proxy().
 */
void
_nm_object_class_add_interface (NMObjectClass *object_class,
                                const char    *interface)
{
	NMObjectClassPrivate *cpriv;

	g_return_if_fail (NM_IS_OBJECT_CLASS (object_class));
	g_return_if_fail (interface);

	cpriv = NM_OBJECT_CLASS_GET_PRIVATE (object_class);

	g_return_if_fail (g_slist_find_custom (cpriv->interfaces, interface, (GCompareFunc) g_strcmp0) == NULL);

	cpriv->interfaces = g_slist_prepend (cpriv->interfaces, g_strdup (interface));
}

/**
 * nm_object_get_path:
 * @object: a #NMObject
 *
 * Gets the DBus path of the #NMObject.
 *
 * Returns: the object's path. This is the internal string used by the
 * device, and must not be modified.
 **/
const char *
nm_object_get_path (NMObject *object)
{
	g_return_val_if_fail (NM_IS_OBJECT (object), NULL);

	return NM_OBJECT_GET_PRIVATE (object)->path;
}

/**
 * _nm_object_get_proxy:
 * @object: an #NMObject
 * @interface: a D-Bus interface implemented by @object
 *
 * Gets the D-Bus proxy for @interface on @object.
 *
 * Returns: (transfer none): a D-Bus proxy
 */
GDBusProxy *
_nm_object_get_proxy (NMObject   *object,
                      const char *interface)
{
	GDBusProxy *proxy;

	g_return_val_if_fail (NM_IS_OBJECT (object), NULL);

	proxy = g_hash_table_lookup (NM_OBJECT_GET_PRIVATE (object)->proxies, interface);
	g_return_val_if_fail (proxy != NULL, NULL);
	return proxy;
}

typedef enum {
	NOTIFY_SIGNAL_PENDING_NONE,
	NOTIFY_SIGNAL_PENDING_ADDED,
	NOTIFY_SIGNAL_PENDING_REMOVED,
	NOTIFY_SIGNAL_PENDING_ADDED_REMOVED,
} NotifySignalPending;

typedef struct {
	const char *property;
	const char *signal_prefix;
	NotifySignalPending pending;
	NMObject *changed;
} NotifyItem;

static void
notify_item_free (NotifyItem *item)
{
	g_clear_object (&item->changed);
	g_slice_free (NotifyItem, item);
}

static gboolean
deferred_notify_cb (gpointer data)
{
	NMObject *object = NM_OBJECT (data);
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);
	NMObjectClass *object_class = NM_OBJECT_GET_CLASS (object);
	GSList *props, *iter;

	priv->notify_id = 0;

	/* Wait until all reloads are done before notifying */
	if (priv->reload_remaining)
		return G_SOURCE_REMOVE;

	/* Clear priv->notify_items early so that an NMObject subclass that
	 * listens to property changes can queue up other property changes
	 * during the g_object_notify() call separately from the property
	 * list we're iterating.
	 */
	props = g_slist_reverse (priv->notify_items);
	priv->notify_items = NULL;

	g_object_ref (object);

	/* Emit added/removed signals first since some of our internal objects
	 * use the added/removed signals for new object processing.
	 */
	for (iter = props; iter; iter = g_slist_next (iter)) {
		NotifyItem *item = iter->data;
		char buf[50];
		gint ret = 0;

		switch (item->pending) {
		case NOTIFY_SIGNAL_PENDING_ADDED:
			ret = g_snprintf (buf, sizeof (buf), "%s-added", item->signal_prefix);
			break;
		case NOTIFY_SIGNAL_PENDING_REMOVED:
			ret = g_snprintf (buf, sizeof (buf), "%s-removed", item->signal_prefix);
			break;
		case NOTIFY_SIGNAL_PENDING_ADDED_REMOVED:
			if (object_class->object_creation_failed)
				object_class->object_creation_failed (object, nm_object_get_path (item->changed));
			break;
		case NOTIFY_SIGNAL_PENDING_NONE:
		default:
			break;
		}
		if (ret > 0) {
			g_assert (ret < sizeof (buf));
			g_signal_emit_by_name (object, buf, item->changed);
		}
	}

	/* Emit property change notifications second */
	for (iter = props; iter; iter = g_slist_next (iter)) {
		NotifyItem *item = iter->data;

		if (item->property)
			g_object_notify (G_OBJECT (object), item->property);
	}

	g_object_unref (object);

	g_slist_free_full (props, (GDestroyNotify) notify_item_free);
	return G_SOURCE_REMOVE;
}

static void
_nm_object_defer_notify (NMObject *object)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);

	if (!priv->notify_id)
		priv->notify_id = g_idle_add_full (G_PRIORITY_LOW, deferred_notify_cb, object, NULL);
}

static void
_nm_object_queue_notify_full (NMObject *object,
                              const char *property,
                              const char *signal_prefix,
                              gboolean added,
                              NMObject *changed)
{
	NMObjectPrivate *priv;
	NotifyItem *item;
	GSList *iter;

	g_return_if_fail (NM_IS_OBJECT (object));
	g_return_if_fail (!signal_prefix != !property);
	g_return_if_fail (!signal_prefix == !changed);

	priv = NM_OBJECT_GET_PRIVATE (object);
	_nm_object_defer_notify (object);

	property = g_intern_string (property);
	signal_prefix = g_intern_string (signal_prefix);
	for (iter = priv->notify_items; iter; iter = g_slist_next (iter)) {
		item = iter->data;

		if (property && (property == item->property))
			return;

		/* Collapse signals for the same object (such as "added->removed") to
		 * ensure we don't emit signals when their sum should have no effect.
		 * The "added->removed->removed" sequence requires special handling,
		 * hence the addition of the ADDED_REMOVED state to ensure that no
		 * signal is emitted in this case:
		 *
		 * Without the ADDED_REMOVED state:
		 *     NONE          + added   -> ADDED
		 *     ADDED         + removed -> NONE
		 *     NONE          + removed -> REMOVED (would emit 'removed' signal)
		 *
		 * With the ADDED_REMOVED state:
		 *     NONE | ADDED_REMOVED  + added   -> ADDED
		 *     ADDED                 + removed -> ADDED_REMOVED
		 *     ADDED_REMOVED         + removed -> ADDED_REMOVED (emits no signal)
		 */
		if (signal_prefix && (changed == item->changed) && (item->signal_prefix == signal_prefix)) {
			switch (item->pending) {
			case NOTIFY_SIGNAL_PENDING_ADDED:
				if (!added)
					item->pending = NOTIFY_SIGNAL_PENDING_ADDED_REMOVED;
				break;
			case NOTIFY_SIGNAL_PENDING_REMOVED:
				if (added)
					item->pending = NOTIFY_SIGNAL_PENDING_NONE;
				break;
			case NOTIFY_SIGNAL_PENDING_ADDED_REMOVED:
				if (added)
					item->pending = NOTIFY_SIGNAL_PENDING_ADDED;
				break;
			case NOTIFY_SIGNAL_PENDING_NONE:
				item->pending = added ? NOTIFY_SIGNAL_PENDING_ADDED : NOTIFY_SIGNAL_PENDING_REMOVED;
				break;
			default:
				g_assert_not_reached ();
			}
			return;
		}
	}

	item = g_slice_new0 (NotifyItem);
	item->property = property;
	if (signal_prefix) {
		item->signal_prefix = signal_prefix;
		item->pending = added ? NOTIFY_SIGNAL_PENDING_ADDED : NOTIFY_SIGNAL_PENDING_REMOVED;
		item->changed = changed ? g_object_ref (changed) : NULL;
	}
	priv->notify_items = g_slist_prepend (priv->notify_items, item);
}

void
_nm_object_queue_notify (NMObject *object, const char *property)
{
	_nm_object_queue_notify_full (object, property, NULL, FALSE, NULL);
}

void
_nm_object_register_type_func (GType base_type,
                               NMObjectDecideTypeFunc type_func,
                               const char *interface,
                               const char *property)
{
	NMObjectTypeFuncData *type_data;

	g_return_if_fail (type_func != NULL);
	g_return_if_fail (interface != NULL);
	g_return_if_fail (property != NULL);

	type_data = g_slice_new (NMObjectTypeFuncData);
	type_data->type_func = type_func;
	type_data->interface = g_strdup (interface);
	type_data->property = g_strdup (property);

	g_hash_table_insert (type_funcs,
	                     GSIZE_TO_POINTER (base_type),
	                     type_data);
}

static GObject *
_nm_object_create (GType type, GDBusConnection *connection, const char *path)
{
	NMObjectTypeFuncData *type_data;
	GObject *object;
	GError *error = NULL;

	type_data = g_hash_table_lookup (type_funcs, GSIZE_TO_POINTER (type));
	if (type_data) {
		GDBusProxy *proxy;
		GVariant *ret, *value;

		proxy = _nm_dbus_new_proxy_for_connection (connection, path,
		                                           DBUS_INTERFACE_PROPERTIES,
		                                           NULL, &error);
		if (!proxy) {
			g_warning ("Could not create proxy for %s: %s.", path, error->message);
			g_error_free (error);
			return NULL;
		}

		ret = g_dbus_proxy_call_sync (proxy,
		                              "Get",
		                              g_variant_new ("(ss)",
		                                             type_data->interface,
		                                             type_data->property),
		                              G_DBUS_CALL_FLAGS_NONE, -1,
		                              NULL, &error);
		g_object_unref (proxy);
		if (!ret) {
			dbgmsg ("Could not fetch property '%s' of interface '%s' on %s: %s\n",
			           type_data->property, type_data->interface, path, error->message);
			g_error_free (error);
			return NULL;
		}

		g_variant_get (ret, "(v)", &value);
		type = type_data->type_func (value);
		g_variant_unref (value);
		g_variant_unref (ret);
	}

	if (type == G_TYPE_INVALID) {
		dbgmsg ("Could not create object for %s: unknown object type", path);
		return NULL;
	}

	object = g_object_new (type,
	                       NM_OBJECT_PATH, path,
	                       NM_OBJECT_DBUS_CONNECTION, connection,
	                       NULL);
	/* Cache the object before initializing it (and in particular, loading its
	 * property values); this is necessary to make circular references work (eg,
	 * when creating an NMActiveConnection, it will create an NMDevice which
	 * will in turn try to create the parent NMActiveConnection). Since we don't
	 * support multi-threaded use, we know that we will have inited the object
	 * before any external code sees it.
	 */
	_nm_object_cache_add (NM_OBJECT (object));
	if (!g_initable_init (G_INITABLE (object), NULL, &error)) {
		dbgmsg ("Could not create object for %s: %s", path, error->message);
		g_error_free (error);
		g_clear_object (&object);
	}

	return object;
}

typedef void (*NMObjectCreateCallbackFunc) (GObject *, const char *, gpointer);
typedef struct {
	char *path;
	NMObjectCreateCallbackFunc callback;
	gpointer user_data;
	NMObjectTypeFuncData *type_data;
	GDBusConnection *connection;
} NMObjectTypeAsyncData;

static void
create_async_complete (GObject *object, NMObjectTypeAsyncData *async_data)
{
	async_data->callback (object, async_data->path, async_data->user_data);

	g_free (async_data->path);
	g_object_unref (async_data->connection);
	g_slice_free (NMObjectTypeAsyncData, async_data);
}

static void
create_async_inited (GObject *object, GAsyncResult *result, gpointer user_data)
{
	NMObjectTypeAsyncData *async_data = user_data;
	GError *error = NULL;

	if (!g_async_initable_init_finish (G_ASYNC_INITABLE (object), result, &error)) {
		dbgmsg ("Could not create object for %s: %s",
		        nm_object_get_path (NM_OBJECT (object)),
		        error->message);
		g_error_free (error);
		g_clear_object (&object);
	}

	create_async_complete (object, async_data);
}

static void
create_async_got_type (NMObjectTypeAsyncData *async_data, GType type)
{
	GObject *object;

	/* Ensure we don't have the object already; we may get multiple type
	 * requests for the same object if there are multiple properties on
	 * other objects that refer to the object at this path.  One of those
	 * other requests may have already completed.
	 */
	object = (GObject *) _nm_object_cache_get (async_data->path);
	if (object) {
		create_async_complete (object, async_data);
		return;
	}

	if (type == G_TYPE_INVALID) {
		/* Don't know how to create this object */
		create_async_complete (NULL, async_data);
		return;
	}

	object = g_object_new (type,
	                       NM_OBJECT_PATH, async_data->path,
	                       NM_OBJECT_DBUS_CONNECTION, async_data->connection,
	                       NULL);
	_nm_object_cache_add (NM_OBJECT (object));
	g_async_initable_init_async (G_ASYNC_INITABLE (object), G_PRIORITY_DEFAULT,
	                             NULL, create_async_inited, async_data);
}

static void
create_async_got_property (GObject *proxy, GAsyncResult *result, gpointer user_data)
{
	NMObjectTypeAsyncData *async_data = user_data;
	NMObjectTypeFuncData *type_data = async_data->type_data;
	GVariant *ret, *value;
	GError *error = NULL;
	GType type;

	ret = _nm_dbus_proxy_call_finish (G_DBUS_PROXY (proxy), result,
	                                  G_VARIANT_TYPE ("(v)"), &error);
	if (ret) {
		g_variant_get (ret, "(v)", &value);
		type = type_data->type_func (value);
		g_variant_unref (value);
		g_variant_unref (ret);
	} else {
		dbgmsg ("Could not fetch property '%s' of interface '%s' on %s: %s\n",
		        type_data->property, type_data->interface, async_data->path,
		        error->message);
		g_clear_error (&error);
		type = G_TYPE_INVALID;
	}

	create_async_got_type (async_data, type);
}

static void
create_async_got_proxy (GObject *object, GAsyncResult *result, gpointer user_data)
{
	NMObjectTypeAsyncData *async_data = user_data;
	GDBusProxy *proxy;
	GError *error = NULL;

	proxy = _nm_dbus_new_proxy_for_connection_finish (result, &error);
	if (!proxy) {
		g_warning ("Could not create proxy for %s: %s.", async_data->path, error->message);
		g_error_free (error);
		create_async_complete (NULL, async_data);
		return;
	}

	g_dbus_proxy_call (proxy,
	                   "Get",
	                   g_variant_new ("(ss)",
	                                  async_data->type_data->interface,
	                                  async_data->type_data->property),
	                   G_DBUS_CALL_FLAGS_NONE, -1,
	                   NULL,
	                   create_async_got_property, async_data);
}

static void
_nm_object_create_async (GType type, GDBusConnection *connection, const char *path,
                         NMObjectCreateCallbackFunc callback, gpointer user_data)
{
	NMObjectTypeAsyncData *async_data;

	async_data = g_slice_new (NMObjectTypeAsyncData);
	async_data->path = g_strdup (path);
	async_data->callback = callback;
	async_data->user_data = user_data;
	async_data->connection = g_object_ref (connection);

	async_data->type_data = g_hash_table_lookup (type_funcs, GSIZE_TO_POINTER (type));
	if (async_data->type_data) {
		_nm_dbus_new_proxy_for_connection_async (connection, path,
		                                         DBUS_INTERFACE_PROPERTIES,
		                                         NULL,
		                                         create_async_got_proxy, async_data);
		return;
	}

	create_async_got_type (async_data, type);
}

/* Stolen from dbus-glib */
static char*
wincaps_to_dash (const char *caps)
{
	const char *p;
	GString *str;

	str = g_string_new (NULL);
	p = caps;
	while (*p) {
		if (g_ascii_isupper (*p)) {
			if (str->len > 0 && (str->len < 2 || str->str[str->len-2] != '-'))
				g_string_append_c (str, '-');
			g_string_append_c (str, g_ascii_tolower (*p));
		} else
			g_string_append_c (str, *p);
		++p;
	}

	return g_string_free (str, FALSE);
}

/* Adds object to array if it's not already there */
static void
add_to_object_array_unique (GPtrArray *array, GObject *obj)
{
	guint i;

	g_return_if_fail (array != NULL);

	if (obj != NULL) {
		for (i = 0; i < array->len; i++) {
			if (g_ptr_array_index (array, i) == obj) {
				g_object_unref (obj);
				return;
			}
		}
		g_ptr_array_add (array, obj);
	}
}

typedef struct {
	NMObject *self;
	PropertyInfo *pi;

	GObject **objects;
	int length, remaining;

	GPtrArray *array;
	const char *property_name;
} ObjectCreatedData;

/* Places items from 'needles' that are not in 'haystack' into 'diff' */
static void
array_diff (GPtrArray *needles, GPtrArray *haystack, GPtrArray *diff)
{
	guint i, j;
	GObject *obj;

	g_assert (needles);
	g_assert (haystack);
	g_assert (diff);

	for (i = 0; i < needles->len; i++) {
		obj = g_ptr_array_index (needles, i);

		for (j = 0; j < haystack->len; j++) {
			if (g_ptr_array_index (haystack, j) == obj)
				break;
		}

		if (j == haystack->len)
			g_ptr_array_add (diff, obj);
	}
}

static void
queue_added_removed_signal (NMObject *self,
                            const char *signal_prefix,
                            NMObject *changed,
                            gboolean added)
{
	_nm_object_queue_notify_full (self, NULL, signal_prefix, added, changed);
}

static void
object_property_complete (ObjectCreatedData *odata)
{
	NMObject *self = odata->self;
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (self);
	PropertyInfo *pi = odata->pi;
	gboolean different = TRUE;

	if (odata->array) {
		GPtrArray *pi_old = *((GPtrArray **) pi->field);
		GPtrArray *old = odata->array;
		GPtrArray *new;
		int i;

		/* Build up new array */
		new = g_ptr_array_new_full (odata->length, g_object_unref);
		for (i = 0; i < odata->length; i++)
			add_to_object_array_unique (new, odata->objects[i]);

		*((GPtrArray **) pi->field) = new;

		if (pi->signal_prefix) {
			GPtrArray *added = g_ptr_array_sized_new (3);
			GPtrArray *removed = g_ptr_array_sized_new (3);

			/* Find objects in 'old' that do not exist in 'new' */
			array_diff (old, new, removed);

			/* Find objects in 'new' that do not exist in old */
			array_diff (new, old, added);

			/* Emit added & removed */
			for (i = 0; i < removed->len; i++) {
				queue_added_removed_signal (self,
				                            pi->signal_prefix,
				                            g_ptr_array_index (removed, i),
				                            FALSE);
			}

			for (i = 0; i < added->len; i++) {
				queue_added_removed_signal (self,
				                            pi->signal_prefix,
				                            g_ptr_array_index (added, i),
				                            TRUE);
			}

			different = removed->len || added->len;
			g_ptr_array_unref (added);
			g_ptr_array_unref (removed);
		} else {
			/* No added/removed signals to send, just replace the property with
			 * the new values.
			 */
			different = TRUE;
		}

		/* Free old array last since it will release references, thus freeing
		 * any objects in the 'removed' array.
		 */
		if (pi_old)
			g_ptr_array_unref (pi_old);
	} else {
		GObject **obj_p = pi->field;

		different = (*obj_p != odata->objects[0]);
		if (*obj_p)
			g_object_unref (*obj_p);
		*obj_p = odata->objects[0];
	}

	if (different && odata->property_name)
		_nm_object_queue_notify (self, odata->property_name);

	if (--priv->reload_remaining == 0)
		reload_complete (self, FALSE);

	g_object_unref (self);
	g_free (odata->objects);
	if (odata->array)
		g_ptr_array_unref (odata->array);
	g_slice_free (ObjectCreatedData, odata);
}

static void
object_created (GObject *obj, const char *path, gpointer user_data)
{
	ObjectCreatedData *odata = user_data;

	/* We assume that on error, the creator_func printed something */

	if (obj == NULL && g_strcmp0 (path, "/") != 0 ) {
		NMObjectClass *object_class = NM_OBJECT_GET_CLASS (odata->self);

		if (object_class->object_creation_failed)
			object_class->object_creation_failed (odata->self, path);
	}

	odata->objects[--odata->remaining] = obj;
	if (!odata->remaining)
		object_property_complete (odata);
}

static gboolean
handle_object_property (NMObject *self, const char *property_name, GVariant *value,
                        PropertyInfo *pi, gboolean synchronously)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (self);
	GObject *obj;
	const char *path;
	ObjectCreatedData *odata;

	odata = g_slice_new (ObjectCreatedData);
	odata->self = g_object_ref (self);
	odata->pi = pi;
	odata->objects = g_new (GObject *, 1);
	odata->length = odata->remaining = 1;
	odata->array = NULL;
	odata->property_name = property_name;

	priv->reload_remaining++;

	path = g_variant_get_string (value, NULL);

	if (!strcmp (path, "/")) {
		object_created (NULL, path, odata);
		return TRUE;
	}

	obj = G_OBJECT (_nm_object_cache_get (path));
	if (obj) {
		object_created (obj, path, odata);
		return TRUE;
	} else if (synchronously) {
		obj = _nm_object_create (pi->object_type, priv->connection, path);
		object_created (obj, path, odata);
		return obj != NULL;
	} else {
		_nm_object_create_async (pi->object_type, priv->connection, path,
		                         object_created, odata);
		/* Assume success */
		return TRUE;
	}
}

static gboolean
handle_object_array_property (NMObject *self, const char *property_name, GVariant *value,
                              PropertyInfo *pi, gboolean synchronously)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (self);
	GObject *obj;
	GVariantIter iter;
	gsize npaths;
	GPtrArray **array = pi->field;
	const char *path;
	ObjectCreatedData *odata;
	guint i, len = *array ? (*array)->len : 0;

	npaths = g_variant_n_children (value);

	odata = g_slice_new (ObjectCreatedData);
	odata->self = g_object_ref (self);
	odata->pi = pi;
	odata->objects = g_new0 (GObject *, npaths);
	odata->length = odata->remaining = npaths;
	odata->property_name = property_name;

	/* Objects known at this point. */
	odata->array = g_ptr_array_new_full (len, g_object_unref);
	for (i = 0; i < len; i++)
		g_ptr_array_add (odata->array, g_object_ref (g_ptr_array_index (*array, i)));

	priv->reload_remaining++;

	if (npaths == 0) {
		object_property_complete (odata);
		return TRUE;
	}

	g_variant_iter_init (&iter, value);
	while (g_variant_iter_next (&iter, "&o", &path)) {
		if (!strcmp (path, "/")) {
			/* FIXME: can't happen? */
			continue;
		}

		obj = G_OBJECT (_nm_object_cache_get (path));
		if (obj) {
			object_created (obj, path, odata);
		} else if (synchronously) {
			obj = _nm_object_create (pi->object_type, priv->connection, path);
			object_created (obj, path, odata);
		} else {
			_nm_object_create_async (pi->object_type, priv->connection, path,
			                         object_created, odata);
		}
	}

	if (!synchronously) {
		/* Assume success */
		return TRUE;
	}

	return *array && ((*array)->len == npaths);
}

static void
handle_property_changed (NMObject *self, const char *dbus_name,
                         GVariant *value, gboolean synchronously)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (self);
	char *prop_name;
	PropertyInfo *pi;
	GParamSpec *pspec;
	gboolean success = FALSE, found = FALSE;
	GSList *iter;

	prop_name = wincaps_to_dash (dbus_name);

	/* Iterate through the object and its parents to find the property */
	for (iter = priv->property_tables; iter; iter = g_slist_next (iter)) {
		pi = g_hash_table_lookup ((GHashTable *) iter->data, prop_name);
		if (pi) {
			if (!pi->field) {
				/* We know about this property but aren't tracking changes on it. */
				goto out;
			}

			found = TRUE;
			break;
		}
	}

	if (!found) {
		dbgmsg ("Property '%s' unhandled.", prop_name);
		goto out;
	}

	pspec = g_object_class_find_property (G_OBJECT_GET_CLASS (G_OBJECT (self)), prop_name);
	if (!pspec && pi->func == demarshal_generic) {
		dbgmsg ("%s: property '%s' changed but wasn't defined by object type %s.",
		        __func__,
		        prop_name,
		        G_OBJECT_TYPE_NAME (self));
		goto out;
	}

	if (G_UNLIKELY (debug)) {
		char *s;
		s = g_variant_print (value, FALSE);
		dbgmsg ("PC: (%p) %s:%s => '%s' (%s%s%s)",
		        self, G_OBJECT_TYPE_NAME (self),
		        prop_name,
		        s,
		        g_variant_get_type_string (value),
		        pi->object_type ? " / " : "",
		        pi->object_type ? g_type_name (pi->object_type) : "");
		g_free (s);
	}

	if (pspec && pi->object_type) {
		if (g_variant_is_of_type (value, G_VARIANT_TYPE_OBJECT_PATH))
			success = handle_object_property (self, pspec->name, value, pi, synchronously);
		else if (g_variant_is_of_type (value, G_VARIANT_TYPE ("ao")))
			success = handle_object_array_property (self, pspec->name, value, pi, synchronously);
		else {
			g_warn_if_reached ();
			goto out;
		}
	} else
		success = (*(pi->func)) (self, pspec, value, pi->field);

	if (!success) {
		dbgmsg ("%s: failed to update property '%s' of object type %s.",
		        __func__,
		        prop_name,
		        G_OBJECT_TYPE_NAME (self));
	}

out:
	g_free (prop_name);
}

static void
process_properties_changed (NMObject *self, GVariant *properties, gboolean synchronously)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (self);
	GVariantIter iter;
	const char *name;
	GVariant *value;

	if (priv->suppress_property_updates)
		return;

	g_variant_iter_init (&iter, properties);
	while (g_variant_iter_next (&iter, "{&sv}", &name, &value))
		handle_property_changed (self, name, value, synchronously);
}

static void
properties_changed (GDBusProxy *proxy,
                    GVariant   *properties,
                    gpointer    user_data)
{
	process_properties_changed (NM_OBJECT (user_data), properties, FALSE);
}

#define HANDLE_TYPE(vtype, ctype, getter) \
	G_STMT_START { \
		if (g_variant_is_of_type (value, vtype)) { \
			ctype *param = (ctype *) field; \
			*param = getter (value); \
		} else { \
			success = FALSE; \
			goto done; \
		} \
	} G_STMT_END

static gboolean
demarshal_generic (NMObject *object,
                   GParamSpec *pspec,
                   GVariant *value,
                   gpointer field)
{
	gboolean success = TRUE;

	if (pspec->value_type == G_TYPE_STRING) {
		if (g_variant_is_of_type (value, G_VARIANT_TYPE_STRING)) {
			char **param = (char **) field;
			g_free (*param);
			*param = g_variant_dup_string (value, NULL);
		} else if (g_variant_is_of_type (value, G_VARIANT_TYPE_OBJECT_PATH)) {
			char **param = (char **) field;
			g_free (*param);
			*param = g_variant_dup_string (value, NULL);
			/* Handle "NULL" object paths */
			if (g_strcmp0 (*param, "/") == 0) {
				g_free (*param);
				*param = NULL;
			}
		} else {
			success = FALSE;
			goto done;
		}
	} else if (pspec->value_type == G_TYPE_STRV) {
		char ***param = (char ***)field;
		if (*param)
			g_strfreev (*param);
		*param = g_variant_dup_strv (value, NULL);
	} else if (pspec->value_type == G_TYPE_BYTES) {
		GBytes **param = (GBytes **)field;
		gconstpointer val;
		gsize length;

		if (*param)
			g_bytes_unref (*param);
		val = g_variant_get_fixed_array (value, &length, 1);
		if (length)
			*param = g_bytes_new (val, length);
		else
			*param = NULL;
	} else if (G_IS_PARAM_SPEC_ENUM (pspec)) {
		int *param = (int *) field;

		if (g_variant_is_of_type (value, G_VARIANT_TYPE_INT32))
			*param = g_variant_get_int32 (value);
		else if (g_variant_is_of_type (value, G_VARIANT_TYPE_UINT32))
			*param = g_variant_get_uint32 (value);
		else {
			success = FALSE;
			goto done;
		}
	} else if (G_IS_PARAM_SPEC_FLAGS (pspec)) {
		guint *param = (guint *) field;

		if (g_variant_is_of_type (value, G_VARIANT_TYPE_INT32))
			*param = g_variant_get_int32 (value);
		else if (g_variant_is_of_type (value, G_VARIANT_TYPE_UINT32))
			*param = g_variant_get_uint32 (value);
		else {
			success = FALSE;
			goto done;
		}
	} else if (pspec->value_type == G_TYPE_BOOLEAN)
		HANDLE_TYPE (G_VARIANT_TYPE_BOOLEAN, gboolean, g_variant_get_boolean);
	else if (pspec->value_type == G_TYPE_UCHAR)
		HANDLE_TYPE (G_VARIANT_TYPE_BYTE, guchar, g_variant_get_byte);
	else if (pspec->value_type == G_TYPE_DOUBLE)
		HANDLE_TYPE (G_VARIANT_TYPE_DOUBLE, gdouble, g_variant_get_double);
	else if (pspec->value_type == G_TYPE_INT)
		HANDLE_TYPE (G_VARIANT_TYPE_INT32, gint, g_variant_get_int32);
	else if (pspec->value_type == G_TYPE_UINT)
		HANDLE_TYPE (G_VARIANT_TYPE_UINT32, guint, g_variant_get_uint32);
	else if (pspec->value_type == G_TYPE_INT64)
		HANDLE_TYPE (G_VARIANT_TYPE_INT64, gint, g_variant_get_int64);
	else if (pspec->value_type == G_TYPE_UINT64)
		HANDLE_TYPE (G_VARIANT_TYPE_UINT64, guint, g_variant_get_uint64);
	else if (pspec->value_type == G_TYPE_LONG)
		HANDLE_TYPE (G_VARIANT_TYPE_INT64, glong, g_variant_get_int64);
	else if (pspec->value_type == G_TYPE_ULONG)
		HANDLE_TYPE (G_VARIANT_TYPE_UINT64, gulong, g_variant_get_uint64);
	else {
		g_warning ("%s: %s:%s unhandled type %s.",
		           __func__,
		           G_OBJECT_TYPE_NAME (object),
		           pspec->name,
		           g_type_name (pspec->value_type));
		success = FALSE;
	}

done:
	if (success) {
		_nm_object_queue_notify (object, pspec->name);
	} else {
		dbgmsg ("%s: %s:%s (type %s) couldn't be set from D-Bus type %s.",
		        __func__, G_OBJECT_TYPE_NAME (object), pspec->name,
		        g_type_name (pspec->value_type), g_variant_get_type_string (value));
	}
	return success;
}

void
_nm_object_register_properties (NMObject *object,
                                const char *interface,
                                const NMPropertiesInfo *info)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);
	GDBusProxy *proxy;
	static gsize dval = 0;
	const char *debugstr;
	NMPropertiesInfo *tmp;
	GHashTable *instance;

	g_return_if_fail (NM_IS_OBJECT (object));
	g_return_if_fail (interface != NULL);
	g_return_if_fail (info != NULL);

	if (g_once_init_enter (&dval)) {
		debugstr = getenv ("LIBNM_GLIB_DEBUG");
		if (debugstr && strstr (debugstr, "properties-changed"))
			debug = TRUE;
		g_once_init_leave (&dval, 1);
	}

	proxy = _nm_object_get_proxy (object, interface);
	g_return_if_fail (proxy != NULL);

	_nm_dbus_signal_connect (proxy, "PropertiesChanged", G_VARIANT_TYPE ("(a{sv})"),
	                         G_CALLBACK (properties_changed), object);

	instance = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
	priv->property_tables = g_slist_prepend (priv->property_tables, instance);

	for (tmp = (NMPropertiesInfo *) info; tmp->name; tmp++) {
		PropertyInfo *pi;

		if (!tmp->name || (tmp->func && !tmp->field)) {
			g_warning ("%s: missing field in NMPropertiesInfo", __func__);
			continue;
		}

		pi = g_malloc0 (sizeof (PropertyInfo));
		pi->func = tmp->func ? tmp->func : demarshal_generic;
		pi->object_type = tmp->object_type;
		pi->field = tmp->field;
		pi->signal_prefix = tmp->signal_prefix;
		g_hash_table_insert (instance, g_strdup (tmp->name), pi);
	}
}

static gboolean
_nm_object_reload_properties (NMObject *object, GError **error)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);
	GVariant *ret, *props;
	GHashTableIter iter;
	const char *interface;
	GDBusProxy *proxy;

	if (!g_hash_table_size (priv->proxies) || !priv->nm_running)
		return TRUE;

	priv->reload_remaining++;

	g_hash_table_iter_init (&iter, priv->proxies);
	while (g_hash_table_iter_next (&iter, (gpointer *) &interface, (gpointer *) &proxy)) {
		ret = _nm_dbus_proxy_call_sync (priv->properties_proxy,
		                                "GetAll",
		                                g_variant_new ("(s)", interface),
		                                G_VARIANT_TYPE ("(a{sv})"),
		                                G_DBUS_CALL_FLAGS_NONE, -1,
		                                NULL, error);
		if (!ret) {
			if (error && *error)
				g_dbus_error_strip_remote_error (*error);
			return FALSE;
		}

		g_variant_get (ret, "(@a{sv})", &props);
		process_properties_changed (object, props, TRUE);
		g_variant_unref (props);
		g_variant_unref (ret);
	}

	if (--priv->reload_remaining == 0)
		reload_complete (object, TRUE);

	return TRUE;
}

void
_nm_object_suppress_property_updates (NMObject *object, gboolean suppress)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);

	priv->suppress_property_updates = suppress;
}


void
_nm_object_reload_property (NMObject *object,
                            const char *interface,
                            const char *prop_name)
{
	GVariant *ret, *value;
	GError *err = NULL;

	g_return_if_fail (NM_IS_OBJECT (object));
	g_return_if_fail (interface != NULL);
	g_return_if_fail (prop_name != NULL);

	if (!NM_OBJECT_GET_PRIVATE (object)->nm_running)
		return;

	ret = _nm_dbus_proxy_call_sync (NM_OBJECT_GET_PRIVATE (object)->properties_proxy,
	                                "Get",
	                                g_variant_new ("(ss)", interface, prop_name),
	                                G_VARIANT_TYPE ("(v)"),
	                                G_DBUS_CALL_FLAGS_NONE, 15000,
	                                NULL, &err);
	if (!ret) {
		dbgmsg ("%s: Error getting '%s' for %s: (%d) %s\n",
		        __func__,
		        prop_name,
		        nm_object_get_path (object),
		        err->code,
		        err->message);
		g_clear_error (&err);
		return;
	}

	g_variant_get (ret, "(v)", &value);
	handle_property_changed (object, prop_name, value, TRUE);
	g_variant_unref (value);
	g_variant_unref (ret);
}

void
_nm_object_set_property (NMObject *object,
                         const char *interface,
                         const char *prop_name,
                         const char *format_string,
                         ...)
{
	GVariant *val, *ret;
	va_list ap;

	g_return_if_fail (NM_IS_OBJECT (object));
	g_return_if_fail (interface != NULL);
	g_return_if_fail (prop_name != NULL);
	g_return_if_fail (format_string != NULL);

	if (!NM_OBJECT_GET_PRIVATE (object)->nm_running)
		return;

	va_start (ap, format_string);
	val = g_variant_new_va (format_string, NULL, &ap);
	va_end (ap);
	g_return_if_fail (val != NULL);

	ret = g_dbus_proxy_call_sync (NM_OBJECT_GET_PRIVATE (object)->properties_proxy,
	                              "Set",
	                              g_variant_new ("(ssv)", interface, prop_name, val),
	                              G_DBUS_CALL_FLAGS_NONE, 2000,
	                              NULL, NULL);
	/* Ignore errors. */
	if (ret)
		g_variant_unref (ret);
}

static void
reload_complete (NMObject *object, gboolean emit_now)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);
	GSimpleAsyncResult *simple;
	GSList *results, *iter;
	GError *error;

	if (emit_now) {
		nm_clear_g_source (&priv->notify_id);
		deferred_notify_cb (object);
	} else
		_nm_object_defer_notify (object);

	results = priv->reload_results;
	priv->reload_results = NULL;
	error = priv->reload_error;
	priv->reload_error = NULL;

	for (iter = results; iter; iter = iter->next) {
		simple = iter->data;

		if (error)
			g_simple_async_result_set_from_error (simple, error);
		else
			g_simple_async_result_set_op_res_gboolean (simple, TRUE);

		g_simple_async_result_complete (simple);
		g_object_unref (simple);
	}
	g_slist_free (results);
	g_clear_error (&error);
}

static void
reload_got_properties (GObject *proxy,
                       GAsyncResult *result,
                       gpointer user_data)
{
	NMObject *object = user_data;
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);
	GVariant *ret, *props;
	GError *error = NULL;

	ret = _nm_dbus_proxy_call_finish (G_DBUS_PROXY (proxy), result,
	                                  G_VARIANT_TYPE ("(a{sv})"),
	                                  &error);
	if (ret) {
		g_variant_get (ret, "(@a{sv})", &props);
		process_properties_changed (object, props, FALSE);
		g_variant_unref (props);
		g_variant_unref (ret);
	} else {
		g_dbus_error_strip_remote_error (error);
		if (priv->reload_error)
			g_error_free (error);
		else
			priv->reload_error = error;
	}

	if (--priv->reload_remaining == 0)
		reload_complete (object, FALSE);
}

void
_nm_object_reload_properties_async (NMObject *object,
                                    GCancellable *cancellable,
                                    GAsyncReadyCallback callback,
                                    gpointer user_data)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);
	GSimpleAsyncResult *simple;
	GHashTableIter iter;
	const char *interface;
	GDBusProxy *proxy;

	simple = g_simple_async_result_new (G_OBJECT (object), callback,
	                                    user_data, _nm_object_reload_properties_async);

	if (!g_hash_table_size (priv->proxies) || !priv->nm_running) {
		g_simple_async_result_complete_in_idle (simple);
		g_object_unref (simple);
		return;
	}

	priv->reload_results = g_slist_prepend (priv->reload_results, simple);

	/* If there was already a reload happening, we don't need to
	 * re-read the properties again, we just need to wait for the
	 * existing reload to finish.
	 */
	if (priv->reload_results->next)
		return;

	g_hash_table_iter_init (&iter, priv->proxies);
	while (g_hash_table_iter_next (&iter, (gpointer *) &interface, (gpointer *) &proxy)) {
		priv->reload_remaining++;
		g_dbus_proxy_call (priv->properties_proxy,
		                   "GetAll",
		                   g_variant_new ("(s)", interface),
		                   G_DBUS_CALL_FLAGS_NONE, -1,
		                   cancellable,
		                   reload_got_properties, object);
	}
}

gboolean
_nm_object_reload_properties_finish (NMObject *object, GAsyncResult *result, GError **error)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (NM_IS_OBJECT (object), FALSE);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (object), _nm_object_reload_properties_async), FALSE);

	/* NM might have disappeared meanwhile. That would cause a NoReply error to be emitted,
	 * but we don't care if property updates were disabled. */
	if (priv->suppress_property_updates)
		return TRUE;

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return FALSE;

	return g_simple_async_result_get_op_res_gboolean (simple);
}

gboolean
_nm_object_get_nm_running (NMObject *self)
{
	return NM_OBJECT_GET_PRIVATE (self)->nm_running;
}

/**************************************************************/

static void
on_name_owner_changed (GObject    *proxy,
                       GParamSpec *pspec,
                       gpointer    user_data)
{
	NMObject *self = NM_OBJECT (user_data);
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (self);
	gboolean now_running;
	char *owner;

	now_running = ((owner = g_dbus_proxy_get_name_owner (priv->properties_proxy)) != NULL);
	g_free (owner);
	if (now_running != priv->nm_running) {
		priv->nm_running = now_running;
		g_object_notify (G_OBJECT (self), NM_OBJECT_NM_RUNNING);
	}
}

static void
init_dbus (NMObject *object)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);
	char *owner;

	if (_nm_dbus_is_connection_private (priv->connection))
		priv->nm_running = TRUE;
	else {
		priv->nm_running = ((owner = g_dbus_proxy_get_name_owner (priv->properties_proxy)) != NULL);
		g_free (owner);
		g_signal_connect (priv->properties_proxy, "notify::g-name-owner",
		                  G_CALLBACK (on_name_owner_changed), object);
	}
}

static gboolean
init_sync (GInitable *initable, GCancellable *cancellable, GError **error)
{
	NMObject *self = NM_OBJECT (initable);
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (self);
	NMObjectClassPrivate *cpriv = NM_OBJECT_CLASS_GET_PRIVATE (NM_OBJECT_GET_CLASS (self));
	GSList *iter;

	if (!priv->path) {
		g_set_error_literal (error, NM_CLIENT_ERROR, NM_CLIENT_ERROR_OBJECT_CREATION_FAILED,
		                     _("Caller did not specify D-Bus path for object"));
		return FALSE;
	}

	if (!priv->connection)
		priv->connection = _nm_dbus_new_connection (cancellable, error);
	if (!priv->connection)
		return FALSE;

	/* Create proxies */
	for (iter = cpriv->interfaces; iter; iter = iter->next) {
		const char *interface = iter->data;
		GDBusProxy *proxy;

		proxy = _nm_dbus_new_proxy_for_connection (priv->connection, priv->path, interface,
		                                           cancellable, error);
		if (!proxy)
			return FALSE;
		g_hash_table_insert (priv->proxies, (char *) interface, proxy);
	}

	priv->properties_proxy = _nm_dbus_new_proxy_for_connection (priv->connection,
	                                                            priv->path,
	                                                            DBUS_INTERFACE_PROPERTIES,
	                                                            cancellable, error);
	if (!priv->properties_proxy)
		return FALSE;

	NM_OBJECT_GET_CLASS (self)->init_dbus (self);

	return _nm_object_reload_properties (self, error);
}

/**************************************************************/

typedef struct {
	NMObject *object;
	GSimpleAsyncResult *simple;
	GCancellable *cancellable;
	int proxies_pending;
	GError *error;
} NMObjectInitData;

static void
init_async_complete (NMObjectInitData *init_data)
{
	if (init_data->error)
		g_simple_async_result_take_error (init_data->simple, init_data->error);
	else
		g_simple_async_result_set_op_res_gboolean (init_data->simple, TRUE);
	g_simple_async_result_complete (init_data->simple);
	g_object_unref (init_data->simple);
	g_clear_object (&init_data->cancellable);
	g_slice_free (NMObjectInitData, init_data);
}

static void
init_async_got_properties (GObject *object, GAsyncResult *result, gpointer user_data)
{
	NMObjectInitData *init_data = user_data;

	_nm_object_reload_properties_finish (NM_OBJECT (object), result, &init_data->error);
	init_async_complete (init_data);
}

static void
init_async_got_proxy (GObject *object, GAsyncResult *result, gpointer user_data)
{
	NMObjectInitData *init_data = user_data;
	NMObject *self = init_data->object;
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (self);
	GDBusProxy *proxy;

	if (!init_data->error) {
		proxy = _nm_dbus_new_proxy_for_connection_finish (result, &init_data->error);
		if (proxy) {
			const char *interface = g_dbus_proxy_get_interface_name (proxy);

			if (!strcmp (interface, DBUS_INTERFACE_PROPERTIES))
				priv->properties_proxy = proxy;
			else
				g_hash_table_insert (priv->proxies, (char *) interface, proxy);
		}
	}

	init_data->proxies_pending--;
	if (init_data->proxies_pending)
		return;

	if (init_data->error) {
		init_async_complete (init_data);
		return;
	}

	NM_OBJECT_GET_CLASS (self)->init_dbus (self);

	_nm_object_reload_properties_async (init_data->object, init_data->cancellable, init_async_got_properties, init_data);
}

static void
init_async_got_bus (GObject *object, GAsyncResult *result, gpointer user_data)
{
	NMObjectInitData *init_data = user_data;
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (init_data->object);
	NMObjectClassPrivate *cpriv = NM_OBJECT_CLASS_GET_PRIVATE (NM_OBJECT_GET_CLASS (init_data->object));
	GSList *iter;

	priv->connection = _nm_dbus_new_connection_finish (result, &init_data->error);
	if (!priv->connection) {
		init_async_complete (init_data);
		return;
	}

	for (iter = cpriv->interfaces; iter; iter = iter->next) {
		const char *interface = iter->data;

		_nm_dbus_new_proxy_for_connection_async (priv->connection,
		                                         priv->path, interface,
		                                         init_data->cancellable,
		                                         init_async_got_proxy, init_data);
		init_data->proxies_pending++;
	}

	_nm_dbus_new_proxy_for_connection_async (priv->connection,
	                                         priv->path,
	                                         DBUS_INTERFACE_PROPERTIES,
	                                         init_data->cancellable,
	                                         init_async_got_proxy, init_data);
	init_data->proxies_pending++;
}

static void
init_async (GAsyncInitable *initable, int io_priority,
            GCancellable *cancellable, GAsyncReadyCallback callback,
            gpointer user_data)
{
	NMObject *self = NM_OBJECT (initable);
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (self);
	NMObjectInitData *init_data;

	if (!priv->path) {
		g_simple_async_report_error_in_idle (G_OBJECT (initable),
		                                     callback, user_data,
		                                     NM_CLIENT_ERROR,
		                                     NM_CLIENT_ERROR_OBJECT_CREATION_FAILED,
		                                     "%s",
		                                     _("Caller did not specify D-Bus path for object"));
		return;
	}

	init_data = g_slice_new0 (NMObjectInitData);
	init_data->object = self;
	init_data->simple = g_simple_async_result_new (G_OBJECT (initable), callback, user_data, init_async);
	init_data->cancellable = cancellable ? g_object_ref (cancellable) : NULL;

	_nm_dbus_new_connection_async (cancellable, init_async_got_bus, init_data);
}

static gboolean
init_finish (GAsyncInitable *initable, GAsyncResult *result, GError **error)
{
	GSimpleAsyncResult *simple = G_SIMPLE_ASYNC_RESULT (result);

	if (g_simple_async_result_propagate_error (simple, error))
		return FALSE;
	else
		return TRUE;
}

/**************************************************************/

static void
nm_object_initable_iface_init (GInitableIface *iface)
{
	iface->init = init_sync;
}

static void
nm_object_async_initable_iface_init (GAsyncInitableIface *iface)
{
	iface->init_async = init_async;
	iface->init_finish = init_finish;
}

static void
nm_object_init (NMObject *object)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);

	priv->proxies = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_object_unref);
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_PATH:
		/* Construct only */
		priv->path = g_value_dup_string (value);
		break;
	case PROP_DBUS_CONNECTION:
		/* Construct only */
		priv->connection = g_value_dup_object (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_PATH:
		g_value_set_string (value, priv->path);
		break;
	case PROP_DBUS_CONNECTION:
		g_value_set_object (value, priv->connection);
		break;
	case PROP_NM_RUNNING:
		g_value_set_boolean (value, priv->nm_running);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
dispose (GObject *object)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);

	if (priv->notify_id) {
		g_source_remove (priv->notify_id);
		priv->notify_id = 0;
	}

	g_slist_free_full (priv->notify_items, (GDestroyNotify) notify_item_free);
	priv->notify_items = NULL;

	g_clear_pointer (&priv->proxies, g_hash_table_unref);
	g_clear_object (&priv->properties_proxy);

	g_clear_object (&priv->connection);

	G_OBJECT_CLASS (nm_object_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);

	g_slist_free_full (priv->property_tables, (GDestroyNotify) g_hash_table_destroy);
	g_free (priv->path);

	G_OBJECT_CLASS (nm_object_parent_class)->finalize (object);
}

static void
nm_object_class_init (NMObjectClass *nm_object_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (nm_object_class);

	g_type_class_add_private (nm_object_class, sizeof (NMObjectPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	nm_object_class->init_dbus = init_dbus;

	/* Properties */

	/**
	 * NMObject:path:
	 *
	 * The D-Bus object path.
	 **/
	g_object_class_install_property
		(object_class, PROP_PATH,
		 g_param_spec_string (NM_OBJECT_PATH, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_CONSTRUCT_ONLY |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMObject:dbus-connection: (skip)
	 *
	 * The #GDBusConnection of the object.
	 **/
	g_object_class_install_property
	    (object_class, PROP_DBUS_CONNECTION,
	     g_param_spec_object (NM_OBJECT_DBUS_CONNECTION, "", "",
	                          G_TYPE_DBUS_CONNECTION,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS));

	/**
	 * NMObject:manager-running: (skip)
	 *
	 * Internal use only.
	 */
	g_object_class_install_property
		(object_class, PROP_NM_RUNNING,
		 g_param_spec_boolean (NM_OBJECT_NM_RUNNING, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));
}

