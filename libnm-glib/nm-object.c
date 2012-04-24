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
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2012 Red Hat, Inc.
 */

#include <string.h>
#include <gio/gio.h>
#include <nm-utils.h>
#include "NetworkManager.h"
#include "nm-object.h"
#include "nm-object-cache.h"
#include "nm-object-private.h"
#include "nm-dbus-glib-types.h"
#include "nm-glib-compat.h"
#include "nm-types.h"
#include "nm-glib-marshal.h"

#define DEBUG 0

static void nm_object_initable_iface_init (GInitableIface *iface);
static void nm_object_async_initable_iface_init (GAsyncInitableIface *iface);

G_DEFINE_ABSTRACT_TYPE_WITH_CODE (NMObject, nm_object, G_TYPE_OBJECT,
                                  G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, nm_object_initable_iface_init);
                                  G_IMPLEMENT_INTERFACE (G_TYPE_ASYNC_INITABLE, nm_object_async_initable_iface_init);
                                  )

#define NM_OBJECT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_OBJECT, NMObjectPrivate))

static GHashTable *type_funcs, *type_async_funcs;

typedef struct {
	PropertyMarshalFunc func;
	GType object_type;

	gpointer field;
} PropertyInfo;

static void reload_complete (NMObject *object);

typedef struct {
	PropertyInfo pi;

	NMObject *self;
	DBusGProxy *proxy;

	char *get_method;
	NMPseudoPropertyChangedFunc added_func;
	NMPseudoPropertyChangedFunc removed_func;
} PseudoPropertyInfo;

typedef struct {
	DBusGConnection *connection;
	char *path;
	DBusGProxy *properties_proxy;
	GSList *property_interfaces;
	GSList *property_tables;
	GHashTable *pseudo_properties;
	NMObject *parent;
	gboolean suppress_property_updates;

	GSList *notify_props;
	guint32 notify_id;
	gboolean inited;

	GSList *reload_results;
	guint reload_remaining;
	GError *reload_error;
} NMObjectPrivate;

enum {
	PROP_0,
	PROP_CONNECTION,
	PROP_PATH,

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

	if (priv->connection == NULL || priv->path == NULL) {
		g_warning ("%s: bus connection and path required.", __func__);
		g_object_unref (object);
		return NULL;
	}

	_nm_object_cache_add (NM_OBJECT (object));

	return object;
}

static void
constructed (GObject *object)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);

	if (G_OBJECT_CLASS (nm_object_parent_class)->constructed)
		G_OBJECT_CLASS (nm_object_parent_class)->constructed (object);

	priv->properties_proxy = dbus_g_proxy_new_for_name (priv->connection,
	                                                    NM_DBUS_SERVICE,
	                                                    priv->path,
	                                                    "org.freedesktop.DBus.Properties");
}

static gboolean
init_sync (GInitable *initable, GCancellable *cancellable, GError **error)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (initable);

	priv->inited = TRUE;
	return _nm_object_reload_properties (NM_OBJECT (initable), error);
}

static void
init_async_got_properties (GObject *object, GAsyncResult *result, gpointer user_data)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);
	GSimpleAsyncResult *simple = user_data;
	GError *error = NULL;

	priv->inited = TRUE;
	if (_nm_object_reload_properties_finish (NM_OBJECT (object), result, &error))
		g_simple_async_result_set_op_res_gboolean (simple, TRUE);
	else
		g_simple_async_result_take_error (simple, error);

	g_simple_async_result_complete (simple);
	g_object_unref (simple);
}

static void
init_async (GAsyncInitable *initable, int io_priority,
            GCancellable *cancellable, GAsyncReadyCallback callback,
            gpointer user_data)
{
	GSimpleAsyncResult *simple;

	simple = g_simple_async_result_new (G_OBJECT (initable), callback, user_data, init_async);
	_nm_object_reload_properties_async (NM_OBJECT (initable), init_async_got_properties, simple);
}

static gboolean
init_finish (GAsyncInitable *initable, GAsyncResult *result, GError **error)
{
	GSimpleAsyncResult *simple = G_SIMPLE_ASYNC_RESULT (result);

	/* This is needed for now because of bug 667375; it can go away
	 * when we depend on glib >= 2.38
	 */

	if (g_simple_async_result_propagate_error (simple, error))
		return FALSE;
	else
		return g_simple_async_result_get_op_res_gboolean (simple);
}

static void
dispose (GObject *object)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);

	if (priv->notify_id) {
		g_source_remove (priv->notify_id);
		priv->notify_id = 0;
	}

	g_slist_foreach (priv->notify_props, (GFunc) g_free, NULL);
	g_slist_free (priv->notify_props);
	priv->notify_props = NULL;

	g_slist_foreach (priv->property_interfaces, (GFunc) g_free, NULL);
	g_slist_free (priv->property_interfaces);
	priv->property_interfaces = NULL;

	g_clear_object (&priv->properties_proxy);

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

	g_slist_foreach (priv->property_tables, (GFunc) g_hash_table_destroy, NULL);
	g_slist_free (priv->property_tables);
	g_free (priv->path);

	if (priv->pseudo_properties)
		g_hash_table_destroy (priv->pseudo_properties);

	G_OBJECT_CLASS (nm_object_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);
	DBusGConnection *connection;

	switch (prop_id) {
	case PROP_CONNECTION:
		/* Construct only */
		connection = (DBusGConnection *) g_value_get_boxed (value);
		if (!connection)
			connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, NULL);
		priv->connection = dbus_g_connection_ref (connection);
		break;
	case PROP_PATH:
		/* Construct only */
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
	case PROP_CONNECTION:
		g_value_set_boxed (value, priv->connection);
		break;
	case PROP_PATH:
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

	if (!type_funcs) {
		type_funcs = g_hash_table_new (NULL, NULL);
		type_async_funcs = g_hash_table_new (NULL, NULL);
	}

	/* virtual methods */
	object_class->constructor = constructor;
	object_class->constructed = constructed;
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	/* porperties */

	/**
	 * NMObject:connection:
	 *
	 * The #DBusGConnection of the object.
	 **/
	g_object_class_install_property
		(object_class, PROP_CONNECTION,
		 g_param_spec_boxed (NM_OBJECT_DBUS_CONNECTION,
							 "Connection",
							 "Connection",
							 DBUS_TYPE_G_CONNECTION,
							 G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	/**
	 * NMObject:path:
	 *
	 * The DBus object path.
	 **/
	g_object_class_install_property
		(object_class, PROP_PATH,
		 g_param_spec_string (NM_OBJECT_DBUS_PATH,
							  "Object Path",
							  "DBus Object Path",
							  NULL,
							  G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

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
		              NULL, NULL,
		              _nm_glib_marshal_VOID__POINTER_POINTER,
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
	GSList *props, *iter;

	priv->notify_id = 0;

	/* Clear priv->notify_props early so that an NMObject subclass that
	 * listens to property changes can queue up other property changes
	 * during the g_object_notify() call separately from the property
	 * list we're iterating.
	 */
	props = g_slist_reverse (priv->notify_props);
	priv->notify_props = NULL;

	for (iter = props; iter; iter = g_slist_next (iter)) {
		g_object_notify (G_OBJECT (object), (const char *) iter->data);
		g_free (iter->data);
	}
	g_slist_free (props);
	return FALSE;
}

void
_nm_object_queue_notify (NMObject *object, const char *property)
{
	NMObjectPrivate *priv;
	gboolean found = FALSE;
	GSList *iter;

	g_return_if_fail (NM_IS_OBJECT (object));
	g_return_if_fail (property != NULL);

	priv = NM_OBJECT_GET_PRIVATE (object);
	if (!priv->notify_id)
		priv->notify_id = g_idle_add_full (G_PRIORITY_LOW, deferred_notify_cb, object, NULL);

	for (iter = priv->notify_props; iter; iter = g_slist_next (iter)) {
		if (!strcmp ((char *) iter->data, property)) {
			found = TRUE;
			break;
		}
	}

	if (!found)
		priv->notify_props = g_slist_prepend (priv->notify_props, g_strdup (property));
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
		g_warning ("Could not create object for %s: unknown object type", path);
		return NULL;
	}

	object = g_object_new (type,
	                       NM_OBJECT_DBUS_CONNECTION, connection,
	                       NM_OBJECT_DBUS_PATH, path,
	                       NULL);
	if (!g_initable_init (G_INITABLE (object), NULL, &error)) {
		g_object_unref (object);
		object = NULL;
		g_warning ("Could not create object for %s: %s", path, error->message);
		g_error_free (error);
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

static void
async_inited (GObject *source, GAsyncResult *result, gpointer user_data)
{
	NMObjectTypeAsyncData *async_data = user_data;
	GObject *object = G_OBJECT (source);
	GError *error = NULL;

	if (!g_async_initable_init_finish (G_ASYNC_INITABLE (object), result, &error)) {
		g_warning ("Could not create object for %s: %s",
		           nm_object_get_path (NM_OBJECT (object)), error->message);
		g_error_free (error);
		g_object_unref (object);
		object = NULL;
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
			if (g_ptr_array_index (array, i) == obj)
				return;
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

static void
object_property_complete (ObjectCreatedData *odata)
{
	NMObject *self = odata->self;
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (self);
	PropertyInfo *pi = odata->pi;

	if (odata->array) {
		GPtrArray **array = pi->field;
		int i;

		if (*array)
			g_boxed_free (NM_TYPE_OBJECT_ARRAY, *array);
		*array = g_ptr_array_sized_new (odata->length);
		for (i = 0; i < odata->length; i++)
			add_to_object_array_unique (*array, odata->objects[i]);
	} else {
		GObject **obj_p = pi->field;

		if (*obj_p)
			g_object_unref (*obj_p);
		*obj_p = odata->objects[0];
	}

	if (odata->property_name)
		_nm_object_queue_notify (self, odata->property_name);

	if (priv->reload_results && --priv->reload_remaining == 0)
		reload_complete (self);

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

	if (priv->reload_results)
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

	if (priv->reload_results)
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
#if DEBUG
		g_warning ("Property '%s' unhandled.", prop_name);
#endif
		goto out;
	}

	pspec = g_object_class_find_property (G_OBJECT_GET_CLASS (G_OBJECT (self)), prop_name);
	if (!pspec) {
		g_warning ("%s: property '%s' changed but wasn't defined by object type %s.",
		           __func__,
		           prop_name,
		           G_OBJECT_TYPE_NAME (self));
		goto out;
	}

#if DEBUG
	{
		char *s;
		s = g_strdup_value_contents (value);
		g_message ("PC: %p (%s) prop (%s) '%s' value (%s) %s",
		           self, G_OBJECT_TYPE_NAME (self),
		           g_type_name (pspec->value_type), prop_name,
		           G_VALUE_TYPE_NAME (value), s);
		g_free (s);
	}
#endif
	if (pi->object_type) {
#if DEBUG
		g_message ("   Value is object type %s", g_type_name (pi->object_type));
#endif
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
		g_warning ("%s: failed to update property '%s' of object type %s.",
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
			g_warning ("%s:%d %s(): object %s property '%s' value is unexpectedly NULL",
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
	HANDLE_TYPE(INT64, int, int)
	HANDLE_TYPE(UINT64, uint, uint)
	HANDLE_TYPE(LONG, long, long)
	HANDLE_TYPE(ULONG, ulong, ulong)
	} else {
		g_warning ("%s: %s/%s unhandled type %s.",
		           __func__, G_OBJECT_TYPE_NAME (object), pspec->name,
		           g_type_name (pspec->value_type));
		success = FALSE;
	}

done:
	if (success) {
		_nm_object_queue_notify (object, pspec->name);
	} else {
		g_warning ("%s: %s/%s (type %s) couldn't be set with type %s.",
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
	NMPropertiesInfo *tmp;
	GHashTable *instance;

	g_return_if_fail (NM_IS_OBJECT (object));
	g_return_if_fail (proxy != NULL);
	g_return_if_fail (info != NULL);

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
		g_hash_table_insert (instance, g_strdup (tmp->name), pi);
	}
}

gboolean
_nm_object_reload_properties (NMObject *object, GError **error)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);
	GHashTable *props = NULL;
	GSList *p;
	GHashTableIter pp;
	gpointer name, info;

	if (!priv->property_interfaces)
		return TRUE;

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

	if (priv->pseudo_properties) {
		g_hash_table_iter_init (&pp, priv->pseudo_properties);
		while (g_hash_table_iter_next (&pp, &name, &info))
			_nm_object_reload_pseudo_property (object, name);
	}

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
			g_warning ("Could not initialize %s %s: %s",
			           G_OBJECT_TYPE_NAME (object), priv->path,
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
	GValue value = { 0, };
	GError *err = NULL;

	g_return_if_fail (NM_IS_OBJECT (object));
	g_return_if_fail (interface != NULL);
	g_return_if_fail (prop_name != NULL);

	if (!dbus_g_proxy_call_with_timeout (NM_OBJECT_GET_PRIVATE (object)->properties_proxy,
							"Get", 15000, &err,
							G_TYPE_STRING, interface,
							G_TYPE_STRING, prop_name,
							G_TYPE_INVALID,
							G_TYPE_VALUE, &value,
							G_TYPE_INVALID)) {
		/* Don't warn about D-Bus no reply/timeout errors; it's mostly noise and
		 * happens for example when NM quits and the applet is still running.
		 */
		if (!g_error_matches (err, DBUS_GERROR, DBUS_GERROR_NO_REPLY)) {
			g_warning ("%s: Error getting '%s' for %s: (%d) %s\n",
			           __func__,
			           prop_name,
			           nm_object_get_path (object),
			           err->code,
			           err->message);
		}
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
pseudo_property_object_created (GObject *obj, const char *path, gpointer user_data)
{
	PseudoPropertyInfo *ppi = user_data;

	if (obj) {
		GPtrArray **list_p = (GPtrArray **)ppi->pi.field;

		if (!*list_p)
			*list_p = g_ptr_array_new ();
		add_to_object_array_unique (*list_p, obj);
		ppi->added_func (ppi->self, NM_OBJECT (obj));
	}
}

static void
pseudo_property_added (DBusGProxy *proxy, const char *path, gpointer user_data)
{
	PseudoPropertyInfo *ppi = user_data;
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (ppi->self);
	NMObject *obj;

	if (priv->suppress_property_updates)
		return;

	obj = _nm_object_cache_get (path);
	if (obj)
		pseudo_property_object_created (G_OBJECT (obj), path, ppi);
	else {
		_nm_object_create_async (ppi->pi.object_type, priv->connection, path,
		                         pseudo_property_object_created, ppi);
	}
}

static void
pseudo_property_removed (DBusGProxy *proxy, const char *path, gpointer user_data)
{
	PseudoPropertyInfo *ppi = user_data;
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (ppi->self);
	GPtrArray *list = *(GPtrArray **)ppi->pi.field;
	NMObject *obj = NULL;
	int i;

	if (!list || priv->suppress_property_updates)
		return;

	for (i = 0; i < list->len; i++) {
		obj = list->pdata[i];
		if (!strcmp (path, nm_object_get_path (obj))) {
			g_ptr_array_remove_index (list, i);
			ppi->removed_func (ppi->self, obj);
			g_object_unref (obj);
			return;
		}
	}
}

static void
free_pseudo_property (PseudoPropertyInfo *ppi)
{
	g_object_unref (ppi->proxy);
	g_free (ppi->get_method);
	g_slice_free (PseudoPropertyInfo, ppi);
}

void
_nm_object_register_pseudo_property (NMObject *object,
                                     DBusGProxy *proxy,
                                     const char *name,
                                     gpointer field,
                                     GType object_type,
                                     NMPseudoPropertyChangedFunc added_func,
                                     NMPseudoPropertyChangedFunc removed_func)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);
	PseudoPropertyInfo *ppi;
	int basename_len;
	char *added_signal, *removed_signal;

	g_return_if_fail (NM_IS_OBJECT (object));
	g_return_if_fail (proxy != NULL);

	ppi = g_slice_new0 (PseudoPropertyInfo);
	ppi->pi.field = field;
	ppi->pi.object_type = object_type;
	ppi->self = object;
	ppi->proxy = g_object_ref (proxy);
	ppi->added_func = added_func;
	ppi->removed_func = removed_func;

	basename_len = strlen (name);
	if (basename_len > 4 && !strcmp (name + basename_len - 4, "List"))
		basename_len -= 4;
	else if (basename_len > 1 && name[basename_len - 1] == 's')
		basename_len--;
	else
		g_assert_not_reached ();

	ppi->get_method = g_strdup_printf ("Get%s", name);
	added_signal = g_strdup_printf ("%.*sAdded", basename_len, name);
	removed_signal = g_strdup_printf ("%.*sRemoved", basename_len, name);

	if (!priv->pseudo_properties) {
		priv->pseudo_properties = g_hash_table_new_full (g_str_hash, g_str_equal,
		                                                 g_free, (GDestroyNotify) free_pseudo_property);
	}
	g_hash_table_insert (priv->pseudo_properties, g_strdup (name), ppi);

	dbus_g_proxy_add_signal (proxy, added_signal,
	                         DBUS_TYPE_G_OBJECT_PATH,
	                         G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (proxy, added_signal,
	                             G_CALLBACK (pseudo_property_added),
	                             ppi, NULL);

	dbus_g_proxy_add_signal (proxy, removed_signal,
	                         DBUS_TYPE_G_OBJECT_PATH,
	                         G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (proxy, removed_signal,
	                             G_CALLBACK (pseudo_property_removed),
	                             ppi, NULL);

	g_free (added_signal);
	g_free (removed_signal);
}

void
_nm_object_reload_pseudo_property (NMObject *object,
                                   const char *name)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);
	PseudoPropertyInfo *ppi;
	GPtrArray *temp;
	GError *error = NULL;
	GValue value = { 0, };

	g_return_if_fail (NM_IS_OBJECT (object));
	g_return_if_fail (name != NULL);

	ppi = g_hash_table_lookup (priv->pseudo_properties, name);
	g_return_if_fail (ppi != NULL);

	if (!dbus_g_proxy_call (ppi->proxy, ppi->get_method, &error,
	                        G_TYPE_INVALID,
	                        DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH, &temp,
	                        G_TYPE_INVALID)) {
		g_warning ("%s: error calling %s: %s", __func__, ppi->get_method, error->message);
		g_error_free (error);
		return;
	}

	g_value_init (&value, DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH);
	g_value_take_boxed (&value, temp);
	handle_object_array_property (object, NULL, &value, &ppi->pi, TRUE);
	g_value_unset (&value);
}

static void
reload_complete (NMObject *object)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);
	GSimpleAsyncResult *simple;
	GSList *results, *iter;
	GError *error;

	results = priv->reload_results;
	priv->reload_results = NULL;
	error = priv->reload_error;
	priv->reload_error = NULL;

	for (iter = results; iter; iter = iter->next) {
		simple = results->data;

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
		reload_complete (object);
}

static void
reload_got_pseudo_property (DBusGProxy *proxy, DBusGProxyCall *call,
                            gpointer user_data)
{
	PseudoPropertyInfo *ppi = user_data;
	NMObject *object = ppi->self;
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);
	GPtrArray *temp;
	GValue value = { 0, };
	GError *error = NULL;

	if (dbus_g_proxy_end_call (proxy, call, &error,
	                           DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH, &temp,
	                           G_TYPE_INVALID)) {
		g_value_init (&value, DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH);
		g_value_take_boxed (&value, temp);
		if (!priv->suppress_property_updates)
			handle_object_array_property (object, NULL, &value, &ppi->pi, FALSE);
		g_value_unset (&value);
	} else {
		if (priv->reload_error)
			g_error_free (error);
		else
			priv->reload_error = error;
	}

	if (--priv->reload_remaining == 0)
		reload_complete (object);
}

void
_nm_object_reload_properties_async (NMObject *object, GAsyncReadyCallback callback, gpointer user_data)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);
	GSimpleAsyncResult *simple;
	GSList *p;

	simple = g_simple_async_result_new (G_OBJECT (object), callback,
	                                    user_data, _nm_object_reload_properties_async);

	if (!priv->property_interfaces && !priv->pseudo_properties) {
		g_simple_async_result_complete_in_idle (simple);
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

	if (priv->pseudo_properties) {
		GHashTableIter iter;
		gpointer key, value;
		PseudoPropertyInfo *ppi;

		g_hash_table_iter_init (&iter, priv->pseudo_properties);
		while (g_hash_table_iter_next (&iter, &key, &value)) {
			ppi = value;
			priv->reload_remaining++;
			dbus_g_proxy_begin_call (ppi->proxy, ppi->get_method,
			                         reload_got_pseudo_property, ppi, NULL,
			                         G_TYPE_INVALID);
		}
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
