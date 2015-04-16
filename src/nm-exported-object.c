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
 * Copyright 2014-2015 Red Hat, Inc.
 */

#include "config.h"

#include <string.h>

#include "nm-exported-object.h"
#include "nm-dbus-glib-types.h"
#include "nm-bus-manager.h"
#include "nm-logging.h"

static GHashTable *prefix_counters;

G_DEFINE_ABSTRACT_TYPE_WITH_CODE (NMExportedObject, nm_exported_object, G_TYPE_OBJECT,
                                  prefix_counters = g_hash_table_new (g_str_hash, g_str_equal);
                                  )

typedef struct {
	char *path;

	GHashTable *pending_notifies;
	guint notify_idle_id;
} NMExportedObjectPrivate;

#define NM_EXPORTED_OBJECT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_EXPORTED_OBJECT, NMExportedObjectPrivate))

enum {
	PROPERTIES_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	GHashTable *properties;
} NMExportedObjectClassInfo;

GQuark nm_exported_object_class_info_quark (void);
G_DEFINE_QUARK (NMExportedObjectClassInfo, nm_exported_object_class_info)

/**
 * nm_exported_object_class_add_interface:
 * @object_class: an #NMExportedObjectClass
 * @info: generated #DBusGObjectInfo for the class
 *
 * Adds @info to the list of D-Bus interfaces implemented by @object_class and
 * sets up automatic dbus-glib handling for instances of that class.
 *
 * If @info includes any properties, then a "PropertiesChanged" signal will
 * be emitted on @info's interface whenever any of those properties change on
 * an exported instance of @object_class.
 */
void
nm_exported_object_class_add_interface (NMExportedObjectClass *object_class,
                                        const DBusGObjectInfo *info)
{
	GType object_type = G_TYPE_FROM_CLASS (object_class);
	NMExportedObjectClassInfo *classinfo;
	const char *properties_info, *dbus_name, *gobject_name, *tmp_access;
	char *hyphen_name, *p;

	dbus_g_object_type_install_info (object_type, info);
	if (!info->exported_properties)
		return;

	classinfo = g_type_get_qdata (object_type, nm_exported_object_class_info_quark ());
	if (!classinfo) {
		classinfo = g_slice_new (NMExportedObjectClassInfo);
		classinfo->properties = g_hash_table_new (g_str_hash, g_str_equal);
		g_type_set_qdata (object_type, nm_exported_object_class_info_quark (), classinfo);
	}

	properties_info = info->exported_properties;
	while (*properties_info) {
		/* The format is: "interface\0DBusPropertyName\0gobject_property_name\0access\0" */
		dbus_name = strchr (properties_info, '\0') + 1;
		gobject_name = strchr (dbus_name, '\0') + 1;
		tmp_access = strchr (gobject_name, '\0') + 1;
		properties_info = strchr (tmp_access, '\0') + 1;

		if (strchr (gobject_name, '_')) {
			hyphen_name = g_strdup (gobject_name);
			for (p = hyphen_name; *p; p++) {
				if (*p == '_')
					*p = '-';
			}
			g_assert (!g_hash_table_contains (classinfo->properties, hyphen_name));
			g_hash_table_insert (classinfo->properties,
			                     (char *) g_intern_string (hyphen_name),
			                     (char *) dbus_name);
			g_free (hyphen_name);
		} else {
			g_assert (!g_hash_table_contains (classinfo->properties, (char *) gobject_name));
			g_hash_table_insert (classinfo->properties,
			                     (char *) gobject_name,
			                     (char *) dbus_name);
		}
	}
}

/**
 * nm_exported_object_export:
 * @self: an #NMExportedObject
 *
 * Exports @self on all active and future D-Bus connections.
 *
 * The path to export @self on is taken from its #NMObjectClass's %export_path
 * member. If the %export_path contains "%u", then it will be replaced with a
 * monotonically increasing integer ID (with each distinct %export_path having
 * its own counter). Otherwise, %export_path will be used literally (implying
 * that @self must be a singleton).
 *
 * Returns: the path @self was exported under
 */
const char *
nm_exported_object_export (NMExportedObject *self)
{
	NMExportedObjectPrivate *priv;
	const char *class_export_path, *p;

	g_return_val_if_fail (NM_IS_EXPORTED_OBJECT (self), NULL);
	priv = NM_EXPORTED_OBJECT_GET_PRIVATE (self);

	g_return_val_if_fail (priv->path == NULL, priv->path);

	class_export_path = NM_EXPORTED_OBJECT_GET_CLASS (self)->export_path;
	p = strchr (class_export_path, '%');
	if (p) {
		guint *counter;

		g_return_val_if_fail (p[1] == 'u', NULL);
		g_return_val_if_fail (strchr (p + 1, '%') == NULL, NULL);

		counter = g_hash_table_lookup (prefix_counters, class_export_path);
		if (!counter) {
			counter = g_new0 (guint, 1);
			g_hash_table_insert (prefix_counters, g_strdup (class_export_path), counter);
		}

		priv->path = g_strdup_printf (class_export_path, (*counter)++);
	} else
		priv->path = g_strdup (class_export_path);

	nm_bus_manager_register_object (nm_bus_manager_get (), priv->path, self);

	return priv->path;
}

/**
 * nm_exported_object_get_path:
 * @self: an #NMExportedObject
 *
 * Gets @self's D-Bus path.
 *
 * Returns: @self's D-Bus path, or %NULL if @self is not exported.
 */
const char *
nm_exported_object_get_path (NMExportedObject *self)
{
	g_return_val_if_fail (NM_IS_EXPORTED_OBJECT (self), NULL);

	return NM_EXPORTED_OBJECT_GET_PRIVATE (self)->path;
}

/**
 * nm_exported_object_is_exported:
 * @self: an #NMExportedObject
 *
 * Checks if @self is exported
 *
 * Returns: %TRUE if @self is exported
 */
gboolean
nm_exported_object_is_exported (NMExportedObject *self)
{
	g_return_val_if_fail (NM_IS_EXPORTED_OBJECT (self), FALSE);

	return NM_EXPORTED_OBJECT_GET_PRIVATE (self)->path != NULL;
}

/**
 * nm_exported_object_unexport:
 * @self: an #NMExportedObject
 *
 * Unexports @self on all active D-Bus connections (and prevents it from being
 * auto-exported on future connections).
 */
void
nm_exported_object_unexport (NMExportedObject *self)
{
	NMExportedObjectPrivate *priv;

	g_return_if_fail (NM_IS_EXPORTED_OBJECT (self));
	priv = NM_EXPORTED_OBJECT_GET_PRIVATE (self);

	g_return_if_fail (priv->path != NULL);

	g_clear_pointer (&priv->path, g_free);
	nm_bus_manager_unregister_object (nm_bus_manager_get (), self);
}

static void
destroy_value (gpointer data)
{
	GValue *val = (GValue *) data;

	g_value_unset (val);
	g_slice_free (GValue, val);
}

static void
nm_exported_object_init (NMExportedObject *self)
{
	NMExportedObjectPrivate *priv = NM_EXPORTED_OBJECT_GET_PRIVATE (self);

	priv->pending_notifies = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                                NULL, destroy_value);
}

static void
add_to_string (gpointer key, gpointer value, gpointer user_data)
{
	const char *name = (const char *) key;
	GString *buf = user_data;
	GValue str_val = G_VALUE_INIT;

	g_value_init (&str_val, G_TYPE_STRING);
	if (!g_value_transform ((GValue *) value, &str_val)) {
		if (G_VALUE_HOLDS_OBJECT (value)) {
			GObject *obj = g_value_get_object (value);

			if (obj) {
				g_string_append_printf (buf, "{%s: %p (%s)}, ", name, obj,
				                        G_OBJECT_TYPE_NAME (obj));
			} else
				g_string_append_printf (buf, "{%s: %p}, ", name, obj);
		} else
			g_string_append_printf (buf, "{%s: <transform error>}, ", name);
	} else
		g_string_append_printf (buf, "{%s: %s}, ", name, g_value_get_string (&str_val));
	g_value_unset (&str_val);
}

static gboolean
idle_emit_properties_changed (gpointer self)
{
	NMExportedObjectPrivate *priv = NM_EXPORTED_OBJECT_GET_PRIVATE (self);

	priv->notify_idle_id = 0;

	if (nm_logging_enabled (LOGL_DEBUG, LOGD_DBUS_PROPS)) {
		GString *buf = g_string_new (NULL);

		g_hash_table_foreach (priv->pending_notifies, add_to_string, buf);
		nm_log_dbg (LOGD_DBUS_PROPS, "%s -> %s", G_OBJECT_TYPE_NAME (self), buf->str);
		g_string_free (buf, TRUE);
	}

	g_signal_emit (self, signals[PROPERTIES_CHANGED], 0, priv->pending_notifies);
	g_hash_table_remove_all (priv->pending_notifies);

	return FALSE;
}

static void
nm_exported_object_notify (GObject *object, GParamSpec *pspec)
{
	NMExportedObjectPrivate *priv = NM_EXPORTED_OBJECT_GET_PRIVATE (object);
	NMExportedObjectClassInfo *classinfo;
	const char *dbus_property_name = NULL;
	GValue *value;
	GType type;

	for (type = G_OBJECT_TYPE (object); type; type = g_type_parent (type)) {
		classinfo = g_type_get_qdata (type, nm_exported_object_class_info_quark ());
		if (!classinfo)
			continue;

		dbus_property_name = g_hash_table_lookup (classinfo->properties, pspec->name);
		if (dbus_property_name)
			break;
	}
	if (!dbus_property_name) {
		nm_log_trace (LOGD_DBUS_PROPS, "ignoring notification for prop %s on type %s",
		              pspec->name, G_OBJECT_TYPE_NAME (object));
		return;
	}

	value = g_slice_new0 (GValue);
	g_value_init (value, pspec->value_type);
	g_object_get_property (object, pspec->name, value);
	g_hash_table_insert (priv->pending_notifies, (char *) dbus_property_name, value);

	if (!priv->notify_idle_id)
		priv->notify_idle_id = g_idle_add (idle_emit_properties_changed, object);
}

static void
nm_exported_object_dispose (GObject *object)
{
	NMExportedObjectPrivate *priv = NM_EXPORTED_OBJECT_GET_PRIVATE (object);

	if (priv->path)
		nm_exported_object_unexport (NM_EXPORTED_OBJECT (object));

	g_hash_table_remove_all (priv->pending_notifies);
	nm_clear_g_source (&priv->notify_idle_id);

	G_OBJECT_CLASS (nm_exported_object_parent_class)->dispose (object);
}

static void
nm_exported_object_finalize (GObject *object)
{
	NMExportedObjectPrivate *priv = NM_EXPORTED_OBJECT_GET_PRIVATE (object);

	g_hash_table_destroy (priv->pending_notifies);

	G_OBJECT_CLASS (nm_exported_object_parent_class)->finalize (object);
}

static void
nm_exported_object_class_init (NMExportedObjectClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMExportedObjectPrivate));

	object_class->notify  = nm_exported_object_notify;
	object_class->dispose = nm_exported_object_dispose;
	object_class->finalize = nm_exported_object_finalize;

	signals[PROPERTIES_CHANGED] = g_signal_new ("properties-changed",
	                                            G_OBJECT_CLASS_TYPE (object_class),
	                                            G_SIGNAL_RUN_FIRST,
	                                            0, NULL, NULL, NULL,
	                                            G_TYPE_NONE, 1, DBUS_TYPE_G_MAP_OF_VARIANT);

}
