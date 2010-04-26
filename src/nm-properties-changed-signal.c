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
 * Copyright (C) 2008 Red Hat, Inc.
 */

#include <string.h>
#include <stdio.h>

#include <dbus/dbus-glib.h>
#include "nm-properties-changed-signal.h"
#include "nm-dbus-glib-types.h"

#define NM_DBUS_PROPERTY_CHANGED "NM_DBUS_PROPERTY_CHANGED"

typedef struct {
	GHashTable *hash;
	gulong signal_id;
	guint idle_id;
} PropertiesChangedInfo;

static void
destroy_value (gpointer data)
{
	GValue *val = (GValue *) data;

	g_value_unset (val);
	g_slice_free (GValue, val);
}

static PropertiesChangedInfo *
properties_changed_info_new (void)
{
	PropertiesChangedInfo *info;

	info = g_slice_new0 (PropertiesChangedInfo);
	info->hash = g_hash_table_new_full (g_str_hash, g_str_equal, 
								 (GDestroyNotify) g_free,
								 destroy_value);
	return info;
}

static void
properties_changed_info_destroy (gpointer data)
{
	PropertiesChangedInfo *info = (PropertiesChangedInfo *) data;

	if (info->idle_id)
		g_source_remove (info->idle_id);

	g_hash_table_destroy (info->hash);
	g_slice_free (PropertiesChangedInfo, info);
}

#ifdef DEBUG
static void
add_to_string (gpointer key, gpointer value, gpointer user_data)
{
	char *buf = (char *) user_data;
	GValue str_val = { 0, };

	g_value_init (&str_val, G_TYPE_STRING);
	if (!g_value_transform ((GValue *) value, &str_val)) {
		if (G_VALUE_HOLDS_OBJECT (value)) {
			GObject *obj = g_value_get_object (value);

			if (g_value_get_object (value)) {
				sprintf (buf + strlen (buf), "{%s: %p (%s)}, ",
				         (const char *) key, obj, G_OBJECT_TYPE_NAME (obj));
			} else {
				sprintf (buf + strlen (buf), "{%s: %p}, ", (const char *) key, obj);
			}
		} else
			sprintf (buf + strlen (buf), "{%s: <transform error>}, ", (const char *) key);
	} else {
		sprintf (buf + strlen (buf), "{%s: %s}, ", (const char *) key, g_value_get_string (&str_val));
	}
	g_value_unset (&str_val);
}
#endif

static gboolean
properties_changed (gpointer data)
{
	GObject *object = G_OBJECT (data);
	PropertiesChangedInfo *info = (PropertiesChangedInfo *) g_object_get_data (object, NM_DBUS_PROPERTY_CHANGED);

	g_assert (info);

#ifdef DEBUG
	{
		char buf[2048] = { 0, };
		g_hash_table_foreach (info->hash, add_to_string, &buf);
		nm_log_dbg (LOGD_CORE, "%s -> %s", G_OBJECT_TYPE_NAME (object), buf);
	}
#endif

	g_signal_emit (object, info->signal_id, 0, info->hash);
	g_hash_table_remove_all (info->hash);

	return FALSE;
}

static void
idle_id_reset (gpointer data)
{
	GObject *object = G_OBJECT (data);
	PropertiesChangedInfo *info = (PropertiesChangedInfo *) g_object_get_data (object, NM_DBUS_PROPERTY_CHANGED);

	/* info is unset when the object is being destroyed */
	if (info)
		info->idle_id = 0;
}

static char*
uscore_to_wincaps (const char *uscore)
{
	const char *p;
	GString *str;
	gboolean last_was_uscore;

	last_was_uscore = TRUE;
  
	str = g_string_new (NULL);
	p = uscore;
	while (p && *p) {
		if (*p == '-' || *p == '_')
			last_was_uscore = TRUE;
		else {
			if (last_was_uscore) {
				g_string_append_c (str, g_ascii_toupper (*p));
				last_was_uscore = FALSE;
			} else
				g_string_append_c (str, *p);
		}
		++p;
	}

	return g_string_free (str, FALSE);
}

static void
notify (GObject *object, GParamSpec *pspec)
{
	PropertiesChangedInfo *info;
	GValue *value;

	/* Ignore properties that shouldn't be exported */
	if (pspec->flags & NM_PROPERTY_PARAM_NO_EXPORT)
		return;

	info = (PropertiesChangedInfo *) g_object_get_data (object, NM_DBUS_PROPERTY_CHANGED);
	if (!info) {
		info = properties_changed_info_new ();
		g_object_set_data_full (object, NM_DBUS_PROPERTY_CHANGED, info, properties_changed_info_destroy);
		info->signal_id = g_signal_lookup ("properties-changed", G_OBJECT_TYPE (object));
		g_assert (info->signal_id);
	}

	value = g_slice_new0 (GValue);
	g_value_init (value, pspec->value_type);
	g_object_get_property (object, pspec->name, value);
	g_hash_table_insert (info->hash, uscore_to_wincaps (pspec->name), value);

	if (!info->idle_id)
		info->idle_id = g_idle_add_full (G_PRIORITY_DEFAULT_IDLE, properties_changed, object, idle_id_reset);
}

guint
nm_properties_changed_signal_new (GObjectClass *object_class,
						    guint class_offset)
{
	guint id;

	object_class->notify = notify;

	id = g_signal_new ("properties-changed",
				    G_OBJECT_CLASS_TYPE (object_class),
				    G_SIGNAL_RUN_FIRST,
				    class_offset,
				    NULL, NULL,
				    g_cclosure_marshal_VOID__BOXED,
				    G_TYPE_NONE, 1, DBUS_TYPE_G_MAP_OF_VARIANT);

	return id;
}
