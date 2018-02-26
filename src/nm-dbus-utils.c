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
 * Copyright 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-dbus-utils.h"

#include "nm-dbus-object.h"

/*****************************************************************************/

const GDBusSignalInfo nm_signal_info_property_changed_legacy = NM_DEFINE_GDBUS_SIGNAL_INFO_INIT (
	"PropertiesChanged",
	.args = NM_DEFINE_GDBUS_ARG_INFOS (
		NM_DEFINE_GDBUS_ARG_INFO ("properties", "a{sv}"),
	),
);

GDBusPropertyInfo *
nm_dbus_utils_interface_info_lookup_property (const GDBusInterfaceInfo *interface_info,
                                              const char *property_name)
{
	guint i;

	nm_assert (interface_info);
	nm_assert (property_name);

	/* there is also g_dbus_interface_info_lookup_property(), however that makes use
	 * of a global cache. */
	if (interface_info->properties) {
		for (i = 0; interface_info->properties[i]; i++) {
			GDBusPropertyInfo *info = interface_info->properties[i];

			if (nm_streq (info->name, property_name))
				return info;
		}
	}

	return NULL;
}

GDBusMethodInfo *
nm_dbus_utils_interface_info_lookup_method (const GDBusInterfaceInfo *interface_info,
                                            const char *method_name)
{
	guint i;

	nm_assert (interface_info);
	nm_assert (method_name);

	/* there is also g_dbus_interface_info_lookup_property(), however that makes use
	 * of a global cache. */
	if (interface_info->methods) {
		for (i = 0; interface_info->methods[i]; i++) {
			GDBusMethodInfo *info = interface_info->methods[i];

			if (nm_streq (info->name, method_name))
				return info;
		}
	}

	return NULL;
}

GVariant *
nm_dbus_utils_get_property (GObject *obj,
                            const char *signature,
                            const char *property_name)
{
	GParamSpec *pspec;
	nm_auto_unset_gvalue GValue value = G_VALUE_INIT;

	nm_assert (G_IS_OBJECT (obj));
	nm_assert (g_variant_type_string_is_valid (signature));
	nm_assert (property_name && property_name[0]);

	pspec = g_object_class_find_property (G_OBJECT_GET_CLASS (obj), property_name);
	if (!pspec)
		g_return_val_if_reached (NULL);

	g_value_init (&value, pspec->value_type);
	g_object_get_property (obj, property_name, &value);
	/* returns never-floating variant */
	return g_dbus_gvalue_to_gvariant (&value, G_VARIANT_TYPE (signature));
}

/*****************************************************************************/

void
nm_dbus_utils_g_value_set_object_path (GValue *value, gpointer object)
{
	const char *path;

	g_return_if_fail (!object || NM_IS_DBUS_OBJECT (object));

	if (   object
	    && (path = nm_dbus_object_get_path (object)))
		g_value_set_string (value, path);
	else
		g_value_set_string (value, "/");
}

void
nm_dbus_utils_g_value_set_object_path_array (GValue *value,
                                             GSList *objects,
                                             gboolean (*filter_func) (GObject *object, gpointer user_data),
                                             gpointer user_data)
{
	char **paths;
	guint i;
	GSList *iter;

	paths = g_new (char *, g_slist_length (objects) + 1);
	for (i = 0, iter = objects; iter; iter = iter->next) {
		NMDBusObject *object = iter->data;
		const char *path;

		path = nm_dbus_object_get_path (object);
		if (!path)
			continue;
		if (   filter_func
		    && !filter_func ((GObject *) object, user_data))
			continue;
		paths[i++] = g_strdup (path);
	}
	paths[i] = NULL;
	g_value_take_boxed (value, paths);
}

/*****************************************************************************/


