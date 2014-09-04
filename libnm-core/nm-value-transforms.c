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
 * Copyright 2005 - 2014 Red Hat, Inc.
 */

#include "config.h"

#include <string.h>

#include "nm-utils.h"
#include "nm-utils-private.h"
#include "nm-dbus-glib-types.h"
#include "nm-glib-compat.h"

static void
_nm_utils_convert_op_to_string (const GValue *src_value, GValue *dest_value)
{
	g_return_if_fail (g_type_is_a (G_VALUE_TYPE (src_value), DBUS_TYPE_G_OBJECT_PATH));

	g_value_set_string (dest_value, (const char *) g_value_get_boxed (src_value));
}

static void
_string_array_to_string (const GPtrArray *strings, GValue *dest_value)
{
	GString *printable;
	guint i;

	printable = g_string_new (NULL);
	for (i = 0; strings && i < strings->len; i++) {
		if (i > 0)
			g_string_append_c (printable, ',');
		g_string_append (printable, strings->pdata[i]);
	}

	g_value_take_string (dest_value, g_string_free (printable, FALSE));
}

static void
_nm_utils_convert_op_array_to_string (const GValue *src_value, GValue *dest_value)
{
	const GPtrArray *strings;

	g_return_if_fail (g_type_is_a (G_VALUE_TYPE (src_value), DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH));

	strings = (const GPtrArray *) g_value_get_boxed (src_value);
	_string_array_to_string (strings, dest_value);
}

static void
convert_one_gvalue_hash_entry (gpointer key, gpointer value, gpointer user_data)
{
	GString *printable = (GString *) user_data;
	char *value_as_string;

	value_as_string = g_strdup_value_contents ((GValue *) value);
	g_string_append_printf (printable, " { '%s': %s },", (const char *) key, value_as_string);
	g_free (value_as_string);
}

static void
_nm_utils_convert_gvalue_hash_to_string (const GValue *src_value, GValue *dest_value)
{
	GHashTable *hash;
	GString *printable;

	g_return_if_fail (g_type_is_a (G_VALUE_TYPE (src_value), DBUS_TYPE_G_MAP_OF_VARIANT));

	hash = (GHashTable *) g_value_get_boxed (src_value);

	printable = g_string_new ("[");
	g_hash_table_foreach (hash, convert_one_gvalue_hash_entry, printable);
	g_string_append (printable, " ]");

	g_value_take_string (dest_value, printable->str);
	g_string_free (printable, FALSE);
}

void
_nm_value_transforms_register (void)
{
	static gboolean registered = FALSE;

	if (G_UNLIKELY (!registered)) {
		g_value_register_transform_func (DBUS_TYPE_G_OBJECT_PATH,
		                                 G_TYPE_STRING,
		                                 _nm_utils_convert_op_to_string);
		g_value_register_transform_func (DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH,
		                                 G_TYPE_STRING,
		                                 _nm_utils_convert_op_array_to_string);
		g_value_register_transform_func (DBUS_TYPE_G_MAP_OF_VARIANT,
		                                 G_TYPE_STRING,
		                                 _nm_utils_convert_gvalue_hash_to_string);
		registered = TRUE;
	}
}
