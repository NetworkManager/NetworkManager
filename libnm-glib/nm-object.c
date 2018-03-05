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

#include "nm-default.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "nm-utils.h"
#include "NetworkManager.h"
#include "nm-object.h"
#include "nm-object-cache.h"
#include "nm-object-private.h"
#include "nm-dbus-glib-types.h"
#include "nm-types.h"
#include "nm-dbus-helpers-private.h"

static gboolean debug = FALSE;
#define dbgmsg(f,...) if (G_UNLIKELY (debug)) { g_message (f, ## __VA_ARGS__ ); }

static void nm_object_initable_iface_init (GInitableIface *iface);
static void nm_object_async_initable_iface_init (GAsyncInitableIface *iface);

static GHashTable *type_funcs, *type_async_funcs;

G_DEFINE_ABSTRACT_TYPE_WITH_CODE (NMObject, nm_object, G_TYPE_OBJECT,
                                  type_funcs = g_hash_table_new (NULL, NULL);
                                  type_async_funcs = g_hash_table_new (NULL, NULL);
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

typedef struct {
	DBusGConnection *connection;
	DBusGProxy *bus_proxy;
	gboolean nm_running;

	char *path;
	DBusGProxy *properties_proxy;
	GSList *property_interfaces;
	GSList *property_tables;
	NMObject *parent;
	gboolean suppress_property_updates;

	GSList *notify_items;
	guint32 notify_id;
	gboolean inited;

	GSList *reload_results;
	guint reload_remaining;
	GError *reload_error;
} NMObjectPrivate;

enum {
	PROP_0,
	PROP_DBUS_CONNECTION,
	PROP_DBUS_PATH,

	LAST_PROP
};

enum {
	OBJECT_CREATION_FAILED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

/**
 * nm_object_error_quark:
 *
 * Registers an error quark for #NMObject if necessary.
 *
 * Returns: the error quark used for #NMObject errors.
 **/
GQuark
nm_object_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-object-error-quark");
	return quark;
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

static void
proxy_name_owner_changed (DBusGProxy *proxy,
                          const char *name,
                          const char *old_owner,
                          const char *new_owner,
                          gpointer user_data)
{
	NMObject *self = NM_OBJECT (user_data);
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (self);

	if (g_strcmp0 (name, NM_DBUS_SERVICE) == 0) {
		gboolean old_good = (old_owner && old_owner[0]);
		gboolean new_good = (new_owner && new_owner[0]);

		if (!old_good && new_good)
			priv->nm_running = TRUE;
		else if (old_good && !new_good)
			priv->nm_running = FALSE;
	}
}

static void
nm_object_init (NMObject *object)
{
}

static GObject*
constructor (GType type,
             guint n_construct_params,
             GObjectConstructParam *construct_params)
{
	GObject *object;
	NMObjectPrivate *priv;

	object = G_OBJECT_CLASS (nm_object_parent_class)->constructor (type,
	                                                               n_construct_params,
	                                                               construct_params);

	priv = NM_OBJECT_GET_PRIVATE (object);

	if (priv->connection == NULL) {
		GError *error = NULL;

		priv->connection = _nm_dbus_new_connection (&error);

		if (priv->connection == NULL) {
			g_warning ("Error connecting to system bus: %s", error->message);
			g_clear_error (&error);
			g_object_unref (object);
			return NULL;
		}
	}

	g_assert (priv->connection != NULL);

	if (priv->path == NULL) {
		g_warn_if_reached ();
		g_object_unref (object);
		return NULL;
	}

	return object;
}

static void
constructed (GObject *object)
{
	NMObject *self = NM_OBJECT (object);
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);

	if (G_OBJECT_CLASS (nm_object_parent_class)->constructed)
		G_OBJECT_CLASS (nm_object_parent_class)->constructed (object);

	priv->properties_proxy = _nm_object_new_proxy (self, NULL, DBUS_INTERFACE_PROPERTIES);

	priv->bus_proxy = dbus_g_proxy_new_for_name (priv->connection,
	                                             DBUS_SERVICE_DBUS,
	                                             DBUS_PATH_DBUS,
	                                             DBUS_INTERFACE_DBUS);
	g_assert (priv->bus_proxy);

	dbus_g_proxy_add_signal (priv->bus_proxy, "NameOwnerChanged",
	                         G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
	                         G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->bus_proxy,
	                             "NameOwnerChanged",
	                             G_CALLBACK (proxy_name_owner_changed),
	                             object, NULL);
}

static gboolean
init_sync (GInitable *initable, GCancellable *cancellable, GError **error)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (initable);

	if (priv->bus_proxy) {
		if (!dbus_g_proxy_call (priv->bus_proxy,
		                        "NameHasOwner", error,
		                        G_TYPE_STRING, NM_DBUS_SERVICE,
		                        G_TYPE_INVALID,
		                        G_TYPE_BOOLEAN, &priv->nm_running,
		                        G_TYPE_INVALID))
			return FALSE;
	}

	priv->inited = TRUE;
	return _nm_object_reload_properties (NM_OBJECT (initable), error);
}

/* Takes ownership of @error */
static void
init_async_complete (GSimpleAsyncResult *simple, GError *error)
{
	if (error)
		g_simple_async_result_take_error (simple, error);
	else
		g_simple_async_result_set_op_res_gboolean (simple, TRUE);
	g_simple_async_result_complete (simple);
	g_object_unref (simple);
}

static void
init_async_got_properties (GObject *object, GAsyncResult *result, gpointer user_data)
{
	GSimpleAsyncResult *simple = user_data;
	GError *error = NULL;

	NM_OBJECT_GET_PRIVATE (object)->inited = TRUE;
	if (!_nm_object_reload_properties_finish (NM_OBJECT (object), result, &error))
		g_assert (error);
	init_async_complete (simple, error);
}

static void
init_async_got_manager_running (DBusGProxy *proxy, DBusGProxyCall *call,
                                gpointer user_data)
{
	GSimpleAsyncResult *simple = user_data;
	NMObject *self;
	NMObjectPrivate *priv;
	GError *error = NULL;

	self = NM_OBJECT (g_async_result_get_source_object (G_ASYNC_RESULT (simple)));
	priv = NM_OBJECT_GET_PRIVATE (self);

	if (!dbus_g_proxy_end_call (proxy, call, &error,
	                            G_TYPE_BOOLEAN, &priv->nm_running,
	                            G_TYPE_INVALID)) {
		init_async_complete (simple, error);
	} else if (!priv->nm_running) {
		priv->inited = TRUE;
		init_async_complete (simple, NULL);
	} else
		_nm_object_reload_properties_async (self, init_async_got_properties, simple);

	/* g_async_result_get_source_object() adds a ref */
	g_object_unref (self);
}

static void
init_async (GAsyncInitable *initable, int io_priority,
            GCancellable *cancellable, GAsyncReadyCallback callback,
            gpointer user_data)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (initable);
	GSimpleAsyncResult *simple;

	simple = g_simple_async_result_new (G_OBJECT (initable), callback, user_data, init_async);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (simple, cancellable);

	/* Check if NM is running */
	dbus_g_proxy_begin_call (priv->bus_proxy, "NameHasOwner",
	                         init_async_got_manager_running,
	                         simple, NULL,
	                         G_TYPE_STRING, NM_DBUS_SERVICE,
	                         G_TYPE_INVALID);
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

	g_slist_free_full (priv->property_interfaces, g_free);
	priv->property_interfaces = NULL;

	g_clear_object (&priv->properties_proxy);
	g_clear_object (&priv->bus_proxy);

	if (priv->connection) {
		dbus_g_connection_unref (priv->connection);
		priv->connection = NULL;
	}

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
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_DBUS_CONNECTION:
		/* construct-only */
		priv->connection = g_value_dup_boxed (value);
		break;
	case PROP_DBUS_PATH:
		/* construct-only */
		priv->path = g_value_dup_string (value);
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
	case PROP_DBUS_CONNECTION:
		g_value_set_boxed (value, priv->connection);
		break;
	case PROP_DBUS_PATH:
		g_value_set_string (value, priv->path);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_object_class_init (NMObjectClass *nm_object_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (nm_object_class);

	g_type_class_add_private (nm_object_class, sizeof (NMObjectPrivate));

	/* virtual methods */
	object_class->constructor = constructor;
	object_class->constructed = constructed;
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	/* Properties */

	/**
	 * NMObject:connection:
	 *
	 * The #DBusGConnection of the object.
	 **/
	g_object_class_install_property
		(object_class, PROP_DBUS_CONNECTION,
		 g_param_spec_boxed (NM_OBJECT_DBUS_CONNECTION, "", "",
		                     DBUS_TYPE_G_CONNECTION,
		                     G_PARAM_READWRITE |
		                     G_PARAM_CONSTRUCT_ONLY |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMObject:path:
	 *
	 * The DBus object path.
	 **/
	g_object_class_install_property
		(object_class, PROP_DBUS_PATH,
		 g_param_spec_string (NM_OBJECT_DBUS_PATH, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_CONSTRUCT_ONLY |
		                      G_PARAM_STATIC_STRINGS));

	/* signals */

	/**
	 * NMObject::object-creation-failed:
	 * @master_object: the object that received the signal
	 * @error: the error that occured while creating object
	 * @failed_path: object path of the failed object
	 *
	 * Indicates that an error occured while creating an #NMObject object
	 * during property handling of @master_object.
	 *
	 * Note: Be aware that the signal is private for libnm-glib's internal
	 *       use.
	 **/
	signals[OBJECT_CREATION_FAILED] =
		g_signal_new ("object-creation-failed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMObjectClass, object_creation_failed),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 2, G_TYPE_POINTER, G_TYPE_POINTER);
}

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

/**
 * nm_object_get_connection:
 * @object: a #NMObject
 *
 * Gets the #NMObject's DBusGConnection.
 *
 * Returns: (transfer none): the connection
 **/
DBusGConnection *
nm_object_get_connection (NMObject *object)
{
	g_return_val_if_fail (NM_IS_OBJECT (object), NULL);

	return NM_OBJECT_GET_PRIVATE (object)->connection;
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

	/* Emit property change notifications first */
	for (iter = props; iter; iter = g_slist_next (iter)) {
		NotifyItem *item = iter->data;

		if (item->property)
			g_object_notify (G_OBJECT (object), item->property);
	}

	/* And added/removed signals second */
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
			// XXX
			if (object_class->object_creation_failed)
				object_class->object_creation_failed (object, NULL, g_strdup (nm_object_get_path (item->changed)));
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
_nm_object_register_type_func (GType base_type, NMObjectTypeFunc type_func,
                               NMObjectTypeAsyncFunc type_async_func)
{
	g_hash_table_insert (type_funcs,
	                     GSIZE_TO_POINTER (base_type),
	                     type_func);
	g_hash_table_insert (type_async_funcs,
	                     GSIZE_TO_POINTER (base_type),
	                     type_async_func);
}

static GObject *
_nm_object_create (GType type, DBusGConnection *connection, const char *path)
{
	NMObjectTypeFunc type_func;
	GObject *object;
	GError *error = NULL;

	type_func = g_hash_table_lookup (type_funcs, GSIZE_TO_POINTER (type));
	if (type_func)
		type = type_func (connection, path);

	if (type == G_TYPE_INVALID) {
		dbgmsg ("Could not create object for %s: unknown object type", path);
		return NULL;
	}

	object = g_object_new (type,
	                       NM_OBJECT_DBUS_CONNECTION, connection,
	                       NM_OBJECT_DBUS_PATH, path,
	                       NULL);
	if (NM_IS_OBJECT (object))
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
	DBusGConnection *connection;
	char *path;
	NMObjectCreateCallbackFunc callback;
	gpointer user_data;
} NMObjectTypeAsyncData;

static void
create_async_complete (GObject *object, NMObjectTypeAsyncData *async_data)
{
	async_data->callback (object, async_data->path, async_data->user_data);

	g_free (async_data->path);
	g_slice_free (NMObjectTypeAsyncData, async_data);
}

static const char *
nm_object_or_connection_get_path (gpointer instance)
{
	if (NM_IS_OBJECT (instance))
		return nm_object_get_path (instance);
	else if (NM_IS_CONNECTION (instance))
		return nm_connection_get_path (instance);

	g_assert_not_reached ();
}

static void
async_inited (GObject *source, GAsyncResult *result, gpointer user_data)
{
	NMObjectTypeAsyncData *async_data = user_data;
	GObject *object = G_OBJECT (source);
	GError *error = NULL;

	if (!g_async_initable_init_finish (G_ASYNC_INITABLE (object), result, &error)) {
		dbgmsg ("Could not create object for %s: %s",
		        nm_object_or_connection_get_path (object),
		        error->message);
		g_error_free (error);
		g_clear_object (&object);
	}

	create_async_complete (object, async_data);
}

static void
async_got_type (GType type, gpointer user_data)
{
	NMObjectTypeAsyncData *async_data = user_data;
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
	                       NM_OBJECT_DBUS_CONNECTION, async_data->connection,
	                       NM_OBJECT_DBUS_PATH, async_data->path,
	                       NULL);
	g_warn_if_fail (object != NULL);
	if (NM_IS_OBJECT (object))
		_nm_object_cache_add (NM_OBJECT (object));
	g_async_initable_init_async (G_ASYNC_INITABLE (object), G_PRIORITY_DEFAULT,
	                             NULL, async_inited, async_data);
}

static void
_nm_object_create_async (GType type, DBusGConnection *connection, const char *path,
                         NMObjectCreateCallbackFunc callback, gpointer user_data)
{
	NMObjectTypeAsyncFunc type_async_func;
	NMObjectTypeFunc type_func;
	NMObjectTypeAsyncData *async_data;

	async_data = g_slice_new (NMObjectTypeAsyncData);
	async_data->connection = connection;
	async_data->path = g_strdup (path);
	async_data->callback = callback;
	async_data->user_data = user_data;

	type_async_func = g_hash_table_lookup (type_async_funcs, GSIZE_TO_POINTER (type));
	if (type_async_func) {
		type_async_func (connection, path, async_got_type, async_data);
		return;
	}

	type_func = g_hash_table_lookup (type_funcs, GSIZE_TO_POINTER (type));
	if (type_func)
		type = type_func (connection, path);

	async_got_type (type, async_data);
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

	gboolean array;
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
		GPtrArray *old = *((GPtrArray **) pi->field);
		GPtrArray *new;
		int i;

		/* Build up new array */
		new = g_ptr_array_sized_new (odata->length);
		for (i = 0; i < odata->length; i++)
			add_to_object_array_unique (new, odata->objects[i]);

		if (pi->signal_prefix) {
			GPtrArray *added = g_ptr_array_sized_new (3);
			GPtrArray *removed = g_ptr_array_sized_new (3);

			if (old) {
				/* Find objects in 'old' that do not exist in 'new' */
				array_diff (old, new, removed);

				/* Find objects in 'new' that do not exist in old */
				array_diff (new, old, added);
			} else {
				for (i = 0; i < new->len; i++)
					g_ptr_array_add (added, g_ptr_array_index (new, i));
			}

			*((GPtrArray **) pi->field) = new;

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
			g_ptr_array_free (added, TRUE);
			g_ptr_array_free (removed, TRUE);
		} else {
			/* No added/removed signals to send, just replace the property with
			 * the new values.
			 */
			*((GPtrArray **) pi->field) = new;
			different = TRUE;
		}

		/* Free old array last since it will release references, thus freeing
		 * any objects in the 'removed' array.
		 */
		if (old)
			g_boxed_free (NM_TYPE_OBJECT_ARRAY, old);
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
	g_slice_free (ObjectCreatedData, odata);
}

static void
object_created (GObject *obj, const char *path, gpointer user_data)
{
	ObjectCreatedData *odata = user_data;

	/* We assume that on error, the creator_func printed something */

	if (obj == NULL && g_strcmp0 (path, "/") != 0 ) {
		GError *error;
		error = g_error_new (NM_OBJECT_ERROR,
		                     NM_OBJECT_ERROR_OBJECT_CREATION_FAILURE,
		                     "Creating object for path '%s' failed in libnm-glib.",
		                     path);
		/* Emit a signal about the error. */
		g_signal_emit (odata->self, signals[OBJECT_CREATION_FAILED], 0, error, path);
		g_error_free (error);
	}

	odata->objects[--odata->remaining] = obj;
	if (!odata->remaining)
		object_property_complete (odata);
}

static gboolean
handle_object_property (NMObject *self, const char *property_name, GValue *value,
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
	odata->array = FALSE;
	odata->property_name = property_name;

	priv->reload_remaining++;

	path = g_value_get_boxed (value);

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
handle_object_array_property (NMObject *self, const char *property_name, GValue *value,
                              PropertyInfo *pi, gboolean synchronously)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (self);
	GObject *obj;
	GPtrArray *paths;
	GPtrArray **array = pi->field;
	const char *path;
	ObjectCreatedData *odata;
	int i;

	paths = g_value_get_boxed (value);

	odata = g_slice_new (ObjectCreatedData);
	odata->self = g_object_ref (self);
	odata->pi = pi;
	odata->objects = g_new0 (GObject *, paths->len);
	odata->length = odata->remaining = paths->len;
	odata->array = TRUE;
	odata->property_name = property_name;

	priv->reload_remaining++;

	if (paths->len == 0) {
		object_property_complete (odata);
		return TRUE;
	}

	for (i = 0; i < paths->len; i++) {
		path = paths->pdata[i];
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

	return *array && ((*array)->len == paths->len);
}

static void
handle_property_changed (NMObject *self, const char *dbus_name, GValue *value, gboolean synchronously)
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
	if (!pspec) {
		dbgmsg ("%s: property '%s' changed but wasn't defined by object type %s.",
		        __func__,
		        prop_name,
		        G_OBJECT_TYPE_NAME (self));
		goto out;
	}

	if (G_UNLIKELY (debug)) {
		char *s;
		s = g_strdup_value_contents (value);
		dbgmsg ("PC: (%p) %s::%s => '%s' (%s%s%s)",
		        self, G_OBJECT_TYPE_NAME (self),
		        prop_name,
		        s,
		        G_VALUE_TYPE_NAME (value),
		        pi->object_type ? " / " : "",
		        pi->object_type ? g_type_name (pi->object_type) : "");
		g_free (s);
	}

	if (pi->object_type) {
		if (G_VALUE_HOLDS (value, DBUS_TYPE_G_OBJECT_PATH))
			success = handle_object_property (self, pspec->name, value, pi, synchronously);
		else if (G_VALUE_HOLDS (value, DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH))
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
process_properties_changed (NMObject *self, GHashTable *properties, gboolean synchronously)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (self);
	GHashTableIter iter;
	gpointer name, value;

	if (priv->suppress_property_updates)
		return;

	g_hash_table_iter_init (&iter, properties);
	while (g_hash_table_iter_next (&iter, &name, &value)) {
		if (value)
			handle_property_changed (self, name, value, synchronously);
		else {
			dbgmsg ("%s:%d %s(): object %s property '%s' value is unexpectedly NULL",
			        __FILE__, __LINE__, __func__, G_OBJECT_TYPE_NAME (self), (const char *) name);
		}
	}
}

static void
properties_changed_proxy (DBusGProxy *proxy,
                          GHashTable *properties,
                          gpointer user_data)
{
	process_properties_changed (NM_OBJECT (user_data), properties, FALSE);
}

#define HANDLE_TYPE(ucase, lcase, getter) \
	} else if (pspec->value_type == G_TYPE_##ucase) { \
		if (G_VALUE_HOLDS_##ucase (value)) { \
			g##lcase *param = (g##lcase *) field; \
			*param = g_value_get_##getter (value); \
		} else { \
			success = FALSE; \
			goto done; \
		}

static gboolean
demarshal_generic (NMObject *object,
                   GParamSpec *pspec,
                   GValue *value,
                   gpointer field)
{
	gboolean success = TRUE;

	if (pspec->value_type == G_TYPE_STRING) {
		if (G_VALUE_HOLDS_STRING (value)) {
			char **param = (char **) field;
			g_free (*param);
			*param = g_value_dup_string (value);
		} else if (G_VALUE_HOLDS (value, DBUS_TYPE_G_OBJECT_PATH)) {
			char **param = (char **) field;
			g_free (*param);
			*param = g_strdup (g_value_get_boxed (value));
			/* Handle "NULL" object paths */
			if (g_strcmp0 (*param, "/") == 0) {
				g_free (*param);
				*param = NULL;
			}
		} else {
			success = FALSE;
			goto done;
		}
	HANDLE_TYPE(BOOLEAN, boolean, boolean)
	HANDLE_TYPE(CHAR, char, schar)
	HANDLE_TYPE(UCHAR, uchar, uchar)
	HANDLE_TYPE(DOUBLE, double, double)
	HANDLE_TYPE(INT, int, int)
	HANDLE_TYPE(UINT, uint, uint)
	HANDLE_TYPE(INT64, int64, int64)
	HANDLE_TYPE(UINT64, uint64, uint64)
	HANDLE_TYPE(LONG, long, long)
	HANDLE_TYPE(ULONG, ulong, ulong)
	} else {
		dbgmsg ("%s: %s/%s unhandled type %s.",
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
		dbgmsg ("%s: %s/%s (type %s) couldn't be set with type %s.",
		        __func__, G_OBJECT_TYPE_NAME (object), pspec->name,
		        g_type_name (pspec->value_type), G_VALUE_TYPE_NAME (value));
	}
	return success;
}

void
_nm_object_register_properties (NMObject *object,
                                DBusGProxy *proxy,
                                const NMPropertiesInfo *info)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);
	static gsize dval = 0;
	const char *debugstr;
	NMPropertiesInfo *tmp;
	GHashTable *instance;

	g_return_if_fail (NM_IS_OBJECT (object));
	g_return_if_fail (proxy != NULL);
	g_return_if_fail (info != NULL);

	if (g_once_init_enter (&dval)) {
		debugstr = getenv ("LIBNM_GLIB_DEBUG");
		if (debugstr && strstr (debugstr, "properties-changed"))
			debug = TRUE;
		g_once_init_leave (&dval, 1);
	}

	priv->property_interfaces = g_slist_prepend (priv->property_interfaces,
	                                             g_strdup (dbus_g_proxy_get_interface (proxy)));

	dbus_g_proxy_add_signal (proxy, "PropertiesChanged", DBUS_TYPE_G_MAP_OF_VARIANT, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (proxy,
	                             "PropertiesChanged",
	                             G_CALLBACK (properties_changed_proxy),
	                             object,
	                             NULL);

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

gboolean
_nm_object_reload_properties (NMObject *object, GError **error)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);
	GHashTable *props = NULL;
	GSList *p;

	if (!priv->property_interfaces || !priv->nm_running)
		return TRUE;

	priv->reload_remaining++;

	for (p = priv->property_interfaces; p; p = p->next) {
		if (!dbus_g_proxy_call (priv->properties_proxy, "GetAll", error,
		                        G_TYPE_STRING, p->data,
		                        G_TYPE_INVALID,
		                        DBUS_TYPE_G_MAP_OF_VARIANT, &props,
		                        G_TYPE_INVALID))
			return FALSE;

		process_properties_changed (object, props, TRUE);
		g_hash_table_destroy (props);
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
_nm_object_ensure_inited (NMObject *object)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);
	GError *error = NULL;

	if (!priv->inited) {
		if (!g_initable_init (G_INITABLE (object), NULL, &error)) {
			dbgmsg ("Could not initialize %s %s: %s",
			        G_OBJECT_TYPE_NAME (object),
			        priv->path,
			        error->message);
			g_error_free (error);

			/* Only warn once */
			priv->inited = TRUE;
		}
	}
}

void
_nm_object_reload_property (NMObject *object,
                            const char *interface,
                            const char *prop_name)
{
	GValue value = G_VALUE_INIT;
	GError *err = NULL;

	g_return_if_fail (NM_IS_OBJECT (object));
	g_return_if_fail (interface != NULL);
	g_return_if_fail (prop_name != NULL);

	if (!NM_OBJECT_GET_PRIVATE (object)->nm_running)
		return;

	if (!dbus_g_proxy_call_with_timeout (NM_OBJECT_GET_PRIVATE (object)->properties_proxy,
	                                     "Get", 15000, &err,
	                                     G_TYPE_STRING, interface,
	                                     G_TYPE_STRING, prop_name,
	                                     G_TYPE_INVALID,
	                                     G_TYPE_VALUE, &value,
	                                     G_TYPE_INVALID)) {
		dbgmsg ("%s: Error getting '%s' for %s: %s\n",
		        __func__,
		        prop_name,
		        nm_object_get_path (object),
		        err->message);
		g_clear_error (&err);
		return;
	}

	handle_property_changed (object, prop_name, &value, TRUE);
	g_value_unset (&value);
}

void
_nm_object_set_property (NMObject *object,
                         const char *interface,
                         const char *prop_name,
                         GValue *value)
{
	g_return_if_fail (NM_IS_OBJECT (object));
	g_return_if_fail (interface != NULL);
	g_return_if_fail (prop_name != NULL);
	g_return_if_fail (G_IS_VALUE (value));

	if (!NM_OBJECT_GET_PRIVATE (object)->nm_running)
		return;

	if (!dbus_g_proxy_call_with_timeout (NM_OBJECT_GET_PRIVATE (object)->properties_proxy,
	                                     "Set", 2000, NULL,
	                                     G_TYPE_STRING, interface,
	                                     G_TYPE_STRING, prop_name,
	                                     G_TYPE_VALUE, value,
	                                     G_TYPE_INVALID)) {

		/* Ignore errors. dbus_g_proxy_call_with_timeout() is called instead of
		 * dbus_g_proxy_call_no_reply() to give NM chance to authenticate the caller.
		 */
	}
}

static void
reload_complete (NMObject *object, gboolean emit_now)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);
	GSimpleAsyncResult *simple;
	GSList *results, *iter;
	GError *error;

	if (emit_now) {
		if (priv->notify_id) {
			g_source_remove (priv->notify_id);
			priv->notify_id = 0;
		}
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
reload_got_properties (DBusGProxy *proxy, DBusGProxyCall *call,
                       gpointer user_data)
{
	NMObject *object = user_data;
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);
	GHashTable *props = NULL;
	GError *error = NULL;

	if (dbus_g_proxy_end_call (proxy, call, &error,
	                           DBUS_TYPE_G_MAP_OF_VARIANT, &props,
	                           G_TYPE_INVALID)) {
		process_properties_changed (object, props, FALSE);
		g_hash_table_destroy (props);
	} else {
		if (priv->reload_error)
			g_error_free (error);
		else
			priv->reload_error = error;
	}

	if (--priv->reload_remaining == 0)
		reload_complete (object, FALSE);
}

void
_nm_object_reload_properties_async (NMObject *object, GAsyncReadyCallback callback, gpointer user_data)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);
	GSimpleAsyncResult *simple;
	GSList *p;

	simple = g_simple_async_result_new (G_OBJECT (object), callback,
	                                    user_data, _nm_object_reload_properties_async);

	if (!priv->property_interfaces) {
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

	for (p = priv->property_interfaces; p; p = p->next) {
		priv->reload_remaining++;
		dbus_g_proxy_begin_call (priv->properties_proxy, "GetAll",
		                         reload_got_properties, object, NULL,
		                         G_TYPE_STRING, p->data,
		                         G_TYPE_INVALID);
	}
}

gboolean
_nm_object_reload_properties_finish (NMObject *object, GAsyncResult *result, GError **error)
{
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (NM_IS_OBJECT (object), FALSE);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (object), _nm_object_reload_properties_async), FALSE);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return FALSE;

	return g_simple_async_result_get_op_res_gboolean (simple);
}

DBusGProxy *
_nm_object_new_proxy (NMObject *self, const char *path, const char *interface)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (self);

	return _nm_dbus_new_proxy_for_connection (priv->connection, path ? path : priv->path, interface);
}
