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
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2008 - 2012 Red Hat, Inc.
 */

#include <string.h>
#include <stdio.h>

#include <dbus/dbus-glib.h>
#include "nm-logging.h"
#include "nm-properties-changed-signal.h"
#include "nm-dbus-glib-types.h"

typedef struct {
	GHashTable *exported_props;
	guint signal_id;
} NMPropertiesChangedClassInfo;

typedef struct {
	GHashTable *hash;
	guint signal_id;
	guint idle_id;
} NMPropertiesChangedInfo;

static GQuark
nm_properties_changed_signal_quark (void)
{
	static GQuark q;

	if (G_UNLIKELY (q == 0))
		q = g_quark_from_static_string ("nm-properties-changed-signal");

	return q;
}

static void
destroy_value (gpointer data)
{
	GValue *val = (GValue *) data;

	g_value_unset (val);
	g_slice_free (GValue, val);
}

static void
properties_changed_info_destroy (gpointer data)
{
	NMPropertiesChangedInfo *info = data;

	if (info->idle_id)
		g_source_remove (info->idle_id);

	g_hash_table_destroy (info->hash);
	g_slice_free (NMPropertiesChangedInfo, info);
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
properties_changed (gpointer data)
{
	GObject *object = G_OBJECT (data);
	NMPropertiesChangedInfo *info = g_object_get_qdata (object, nm_properties_changed_signal_quark ());

	g_assert (info);

	if (nm_logging_enabled (LOGL_DEBUG, LOGD_DBUS_PROPS)) {
		GString *buf = g_string_new (NULL);

		g_hash_table_foreach (info->hash, add_to_string, buf);
		nm_log_dbg (LOGD_DBUS_PROPS, "%s -> %s", G_OBJECT_TYPE_NAME (object), buf->str);
		g_string_free (buf, TRUE);
	}

	g_signal_emit (object, info->signal_id, 0, info->hash);
	g_hash_table_remove_all (info->hash);

	return FALSE;
}

static void
idle_id_reset (gpointer data)
{
	GObject *object = G_OBJECT (data);
	NMPropertiesChangedInfo *info = g_object_get_qdata (object, nm_properties_changed_signal_quark ());

	/* info is unset when the object is being destroyed */
	if (info)
		info->idle_id = 0;
}

static void
notify (GObject *object, GParamSpec *pspec)
{
	NMPropertiesChangedClassInfo *classinfo;
	NMPropertiesChangedInfo *info;
	const char *dbus_property_name = NULL;
	GValue *value;
	GType type;

	for (type = G_OBJECT_TYPE (object); type; type = g_type_parent (type)) {
		classinfo = g_type_get_qdata (type, nm_properties_changed_signal_quark ());
		if (!classinfo)
			continue;

		dbus_property_name = g_hash_table_lookup (classinfo->exported_props, pspec->name);
		if (dbus_property_name)
			break;
	}
	if (!dbus_property_name) {
		nm_log_dbg (LOGD_DBUS_PROPS, "ignoring notification for prop %s on type %s",
		            pspec->name, G_OBJECT_TYPE_NAME (object));
		return;
	}

	info = g_object_get_qdata (object, nm_properties_changed_signal_quark ());
	if (!info) {
		info = g_slice_new0 (NMPropertiesChangedInfo);
		info->hash = g_hash_table_new_full (g_str_hash, g_str_equal,
		                                    NULL, destroy_value);
		info->signal_id = classinfo->signal_id;

		g_object_set_qdata_full (object, nm_properties_changed_signal_quark (),
		                         info, properties_changed_info_destroy);
	}

	value = g_slice_new0 (GValue);
	g_value_init (value, pspec->value_type);
	g_object_get_property (object, pspec->name, value);
	g_hash_table_insert (info->hash, (char *) dbus_property_name, value);

	if (!info->idle_id)
		info->idle_id = g_idle_add_full (G_PRIORITY_DEFAULT_IDLE, properties_changed, object, idle_id_reset);
}

static NMPropertiesChangedClassInfo *
nm_properties_changed_signal_setup_type (GType type)
{
	NMPropertiesChangedClassInfo *classinfo;
	NMPropertiesChangedClassInfo *parent_classinfo = NULL;
	GObjectClass *object_class;
	GType parent;

	classinfo = g_slice_new (NMPropertiesChangedClassInfo);
	g_type_set_qdata (type, nm_properties_changed_signal_quark (), classinfo);

	object_class = g_type_class_ref (type);
	object_class->notify = notify;
	g_type_class_unref (object_class);

	classinfo->exported_props = g_hash_table_new (g_str_hash, g_str_equal);

	/* See if we've already added the signal to a parent class. (We can't just use
	 * g_signal_lookup() here because it prints a warning if the signal doesn't exist!)
	 */
	parent = g_type_parent (type);
	while (parent) {
		parent_classinfo = g_type_get_qdata (parent, nm_properties_changed_signal_quark ());
		if (parent_classinfo)
			break;
		parent = g_type_parent (parent);
	}

	if (parent_classinfo)
		classinfo->signal_id = parent_classinfo->signal_id;
	else {
		classinfo->signal_id = g_signal_new ("properties-changed",
		                                     type,
		                                     G_SIGNAL_RUN_FIRST,
		                                     0,
		                                     NULL, NULL,
		                                     g_cclosure_marshal_VOID__BOXED,
		                                     G_TYPE_NONE, 1, DBUS_TYPE_G_MAP_OF_VARIANT);
	}

	return classinfo;
}

void
nm_properties_changed_signal_add_property (GType       type,
                                           const char *dbus_property_name,
                                           const char *gobject_property_name)
{
	NMPropertiesChangedClassInfo *classinfo;
	char *hyphen_name, *p;

	classinfo = g_type_get_qdata (type, nm_properties_changed_signal_quark ());
	if (!classinfo)
		classinfo = nm_properties_changed_signal_setup_type (type);

	g_hash_table_insert (classinfo->exported_props,
	                     (char *) gobject_property_name,
	                     (char *) dbus_property_name);

	hyphen_name = g_strdup (gobject_property_name);
	for (p = hyphen_name; *p; p++) {
		if (*p == '_')
			*p = '-';
	}
	g_hash_table_insert (classinfo->exported_props,
	                     hyphen_name,
	                     (char *) dbus_property_name);
}
