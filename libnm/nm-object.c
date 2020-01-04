// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2012 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-object.h"

#include <stdlib.h>
#include <stdio.h>

#include "nm-utils.h"
#include "nm-dbus-interface.h"
#include "nm-object-private.h"
#include "nm-dbus-helpers.h"
#include "nm-client.h"
#include "nm-core-internal.h"
#include "c-list/src/c-list.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_PATH,
);

typedef struct _NMObjectPrivate {
	NMClient *client;
	NMLDBusObject *dbobj;
} NMObjectPrivate;

G_DEFINE_ABSTRACT_TYPE (NMObject, nm_object, G_TYPE_OBJECT);

#define NM_OBJECT_GET_PRIVATE(self) _NM_GET_PRIVATE_PTR(self, NMObject, NM_IS_OBJECT)

static NMObjectClass *_nm_object_class = NULL;

/*****************************************************************************/

static gpointer
_nm_object_get_private (NMObjectClass *klass, NMObject *self, guint16 extra_offset)
{
	char *ptr;

	nm_assert (klass->priv_ptr_offset > 0);

	ptr = (char *) self;
	ptr += klass->priv_ptr_offset;
	if (klass->priv_ptr_indirect)
		ptr = *((gpointer *) ptr);
	return ptr + extra_offset;
}

NMLDBusObject *
_nm_object_get_dbobj (gpointer self)
{
	return NM_OBJECT_GET_PRIVATE (self)->dbobj;
}

const char *
_nm_object_get_path (gpointer self)
{
	return NM_OBJECT_GET_PRIVATE (self)->dbobj->dbus_path->str;
}

NMClient *
_nm_object_get_client (gpointer self)
{
	return NM_OBJECT_GET_PRIVATE (self)->client;
}

/**
 * nm_object_get_path:
 * @object: a #NMObject
 *
 * Gets the DBus path of the #NMObject.
 *
 * Returns: the object's path. This is the internal string used by the
 * object, and must not be modified.
 *
 * Note that the D-Bus path of an NMObject never changes, even
 * if the instance gets removed from the cache. To find out
 * whether the object is still alive/cached, check nm_object_get_client().
 **/
const char *
nm_object_get_path (NMObject *object)
{
	g_return_val_if_fail (NM_IS_OBJECT (object), NULL);

	return _nm_object_get_path (object);
}

/**
 * nm_object_get_client:
 * @object: a #NMObject
 *
 * Returns the #NMClient instance in which object is cached.
 * Also, if the object got removed from the client cached,
 * this returns %NULL. So it can be used to check whether the
 * object is still alive.
 *
 * Returns: (transfer none): the #NMClient cache in which the
 * object can be found, or %NULL if the object is no longer
 * cached.
 *
 * Since: 1.24
 **/
NMClient *
nm_object_get_client (NMObject *object)
{
	g_return_val_if_fail (NM_IS_OBJECT (object), NULL);

	return _nm_object_get_client (object);
}

/*****************************************************************************/

static void
clear_properties (NMObject *self,
                  NMClient *client)
{
	NMObjectClass *klass = NM_OBJECT_GET_CLASS (self);
	const _NMObjectClassFieldInfo *p;

	nm_assert (NM_IS_OBJECT (self));
	nm_assert (!client || NM_IS_CLIENT (client));

	for (p = klass->property_o_info; p; p = p->parent) {
		nml_dbus_property_o_clear_many (_nm_object_get_private (p->klass, self, p->offset),
		                                p->num,
		                                client);
	}

	for (p = klass->property_ao_info; p; p = p->parent) {
		nml_dbus_property_ao_clear_many (_nm_object_get_private (p->klass, self, p->offset),
		                                 p->num,
		                                 client);
	}
}

/*****************************************************************************/

static gboolean
is_ready (NMObject *self)
{
	NMObjectClass *klass = NM_OBJECT_GET_CLASS (self);
	NMClient *client = _nm_object_get_client (self);
	const _NMObjectClassFieldInfo *p;
	guint16 i;

	nm_assert (NM_IS_CLIENT (client));

	for (p = klass->property_o_info; p; p = p->parent) {
		NMLDBusPropertyO *fields = _nm_object_get_private (p->klass, self, p->offset);

		for (i = 0; i < p->num; i++) {
			if (!nml_dbus_property_o_is_ready (&fields[i]))
				return FALSE;
		}
	}

	for (p = klass->property_ao_info; p; p = p->parent) {
		NMLDBusPropertyAO *fields = _nm_object_get_private (p->klass, self, p->offset);

		for (i = 0; i < p->num; i++) {
			if (!nml_dbus_property_ao_is_ready (&fields[i]))
				return FALSE;
		}
	}

	return TRUE;
}

static void
obj_changed_notify (NMObject *self)
{
	NMObjectClass *klass = NM_OBJECT_GET_CLASS (self);
	NMClient *client = _nm_object_get_client (self);
	const _NMObjectClassFieldInfo *p;

	nm_assert (NM_IS_CLIENT (client));

	for (p = klass->property_o_info; p; p = p->parent) {
		nml_dbus_property_o_notify_changed_many (_nm_object_get_private (p->klass, self, p->offset),
		                                         p->num,
		                                         client);
	}

	for (p = klass->property_ao_info; p; p = p->parent) {
		nml_dbus_property_ao_notify_changed_many (_nm_object_get_private (p->klass, self, p->offset),
		                                          p->num,
		                                          client);
	}
}

/*****************************************************************************/

static void
register_client (NMObject *self,
                 NMClient *client,
                 NMLDBusObject *dbobj)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (self);

	nm_assert (!priv->client);
	nm_assert (NML_IS_DBUS_OBJECT (dbobj));
	nm_assert (dbobj->nmobj == G_OBJECT (self));

	priv->client = client;
	priv->dbobj = nml_dbus_object_ref (dbobj);
}

static void
unregister_client (NMObject *self,
                   NMClient *client,
                   NMLDBusObject *dbobj)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (self);

	nm_assert (NM_IS_CLIENT (client));
	nm_assert (priv->client == client);
	priv->client = NULL;

	clear_properties (self, client);
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMObject *self = NM_OBJECT (object);

	switch (prop_id) {
	case PROP_PATH:
		g_value_set_string (value, nm_object_get_path (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_object_init (NMObject *object)
{
	NMObject *self = NM_OBJECT (object);
	NMObjectPrivate *priv;

	priv = G_TYPE_INSTANCE_GET_PRIVATE (self, NM_TYPE_OBJECT, NMObjectPrivate);

	self->_priv = priv;

	c_list_init (&self->obj_base.queue_notify_lst);
}

static void
dispose (GObject *object)
{
	NMObject *self = NM_OBJECT (object);
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (self);

	self->obj_base.is_disposing = TRUE;

	nm_assert (c_list_is_empty (&self->obj_base.queue_notify_lst));
	nm_assert (!priv->client);
	nm_assert (!priv->dbobj || !priv->dbobj->nmobj);

	clear_properties (self, NULL);

	G_OBJECT_CLASS (nm_object_parent_class)->dispose (object);

	nm_clear_pointer (&priv->dbobj, nml_dbus_object_unref);
}

static void
nm_object_class_init (NMObjectClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	_nm_object_class = klass;

	g_type_class_add_private (klass, sizeof (NMObjectPrivate));

	object_class->get_property = get_property;
	object_class->dispose      = dispose;

	klass->register_client    = register_client;
	klass->unregister_client  = unregister_client;
	klass->is_ready           = is_ready;
	klass->obj_changed_notify = obj_changed_notify;

	/**
	 * NMObject:path:
	 *
	 * The D-Bus object path.
	 **/
	obj_properties[PROP_PATH] =
	    g_param_spec_string (NM_OBJECT_PATH, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
