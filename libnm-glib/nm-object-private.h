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
 * Copyright 2008 - 2011 Red Hat, Inc.
 */

#ifndef NM_OBJECT_PRIVATE_H
#define NM_OBJECT_PRIVATE_H

#include "nm-glib.h"
#include "nm-object.h"

void _nm_object_ensure_inited (NMObject *object);

typedef gboolean (*PropertyMarshalFunc) (NMObject *, GParamSpec *, GValue *, gpointer);

typedef GObject * (*NMObjectCreatorFunc) (DBusGConnection *, const char *);

typedef struct {
	const char *name;
	gpointer field;
	PropertyMarshalFunc func;
	GType object_type;
	const char *signal_prefix;
} NMPropertiesInfo;

DBusGProxy *_nm_object_new_proxy (NMObject *self,
                                  const char *path,
                                  const char *interface);

void _nm_object_register_properties (NMObject *object,
                                     DBusGProxy *proxy,
                                     const NMPropertiesInfo *info);

gboolean _nm_object_reload_properties (NMObject *object, GError **error);

void     _nm_object_reload_properties_async  (NMObject *object,
                                              GAsyncReadyCallback callback,
                                              gpointer user_data);
gboolean _nm_object_reload_properties_finish (NMObject *object,
                                              GAsyncResult *result,
                                              GError **error);

void _nm_object_queue_notify (NMObject *object, const char *property);

void _nm_object_suppress_property_updates (NMObject *object, gboolean suppress);

/* DBus property accessors */

void _nm_object_reload_property (NMObject *object,
                                 const char *interface,
                                 const char *prop_name);

void _nm_object_set_property (NMObject *object,
                              const char *interface,
                              const char *prop_name,
                              GValue *value);

static inline const GPtrArray *
handle_ptr_array_return (GPtrArray *array)
{
	/* zero-length is special-case; return NULL */
	if (!array || !array->len)
		return NULL;
	return array;
}

/* object demarshalling support */
typedef GType (*NMObjectTypeFunc) (DBusGConnection *, const char *);
typedef void (*NMObjectTypeCallbackFunc) (GType, gpointer);
typedef void (*NMObjectTypeAsyncFunc) (DBusGConnection *, const char *, NMObjectTypeCallbackFunc, gpointer);

void _nm_object_register_type_func (GType base_type, NMObjectTypeFunc type_func,
                                    NMObjectTypeAsyncFunc type_async_func);

#endif /* NM_OBJECT_PRIVATE_H */
