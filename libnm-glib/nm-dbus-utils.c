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
 */

#include "nm-dbus-utils.h"

char *
_nm_dbus_get_string_property (DBusGProxy *proxy,
							 const char *interface,
							 const char *prop_name)
{
	GError *err = NULL;
	char *str = NULL;
	GValue value = {0,};

	g_return_val_if_fail (DBUS_IS_G_PROXY (proxy), NULL);

	if (dbus_g_proxy_call (proxy, "Get", &err,
						   G_TYPE_STRING, interface,
						   G_TYPE_STRING, prop_name,
						   G_TYPE_INVALID,
						   G_TYPE_VALUE, &value,
						   G_TYPE_INVALID)) {
		str = g_strdup (g_value_get_string (&value));
	} else {
		g_warning ("Error in device_get_property: %s\n", err->message);
		g_error_free (err);
	}

	return str;
}

char *
_nm_dbus_get_object_path_property (DBusGProxy *proxy,
								  const char *interface,
								  const char *prop_name)
{
	GError *err = NULL;
	char *path = NULL;
	GValue value = {0,};

	g_return_val_if_fail (DBUS_IS_G_PROXY (proxy), NULL);

	if (dbus_g_proxy_call (proxy, "Get", &err,
						   G_TYPE_STRING, interface,
						   G_TYPE_STRING, prop_name,
						   G_TYPE_INVALID,
						   G_TYPE_VALUE, &value,
						   G_TYPE_INVALID)) {
		path = g_strdup (g_value_get_boxed (&value));
	} else {
		g_warning ("Error in device_get_property: %s\n", err->message);
		g_error_free (err);
	}

	return path;
}

gint32
_nm_dbus_get_int_property (DBusGProxy *proxy,
						  const char *interface,
						  const char *prop_name)
{
	GError *err = NULL;
	gint32 i = 0;
	GValue value = {0,};

	g_return_val_if_fail (DBUS_IS_G_PROXY (proxy), 0);

	if (dbus_g_proxy_call (proxy, "Get", &err,
						   G_TYPE_STRING, interface,
						   G_TYPE_STRING, prop_name,
						   G_TYPE_INVALID,
						   G_TYPE_VALUE, &value,
						   G_TYPE_INVALID)) {
		i = g_value_get_int (&value);
	} else {
		g_warning ("Error in device_get_property: %s\n", err->message);
		g_error_free (err);
	}

	return i;
}

guint32
_nm_dbus_get_uint_property (DBusGProxy *proxy,
						   const char *interface,
						   const char *prop_name)
{
	GError *err = NULL;
	guint32 i = 0;
	GValue value = {0,};

	g_return_val_if_fail (DBUS_IS_G_PROXY (proxy), 0);

	if (dbus_g_proxy_call (proxy, "Get", &err,
						   G_TYPE_STRING, interface,
						   G_TYPE_STRING, prop_name,
						   G_TYPE_INVALID,
						   G_TYPE_VALUE, &value,
						   G_TYPE_INVALID)) {
		i = g_value_get_uint (&value);
	} else {
		g_warning ("Error in device_get_property: %s\n", err->message);
		g_error_free (err);
	}

	return i;
}

gboolean
_nm_dbus_get_property (DBusGProxy *proxy,
					  const char *interface,
					  const char *prop_name,
					  GValue *value)
{
	DBusGProxy *properties_proxy;
	GError *err = NULL;
	gboolean ret = TRUE;

	g_return_val_if_fail (proxy != NULL, FALSE);
	g_return_val_if_fail (interface != NULL, FALSE);
	g_return_val_if_fail (prop_name != NULL, FALSE);

	properties_proxy = dbus_g_proxy_new_from_proxy (proxy,
													"org.freedesktop.DBus.Properties",
													dbus_g_proxy_get_path (proxy));

	if (!dbus_g_proxy_call (properties_proxy, "Get", &err,
							G_TYPE_STRING, interface,
							G_TYPE_STRING, prop_name,
							G_TYPE_INVALID,
							G_TYPE_VALUE, value,
							G_TYPE_INVALID)) {
		g_warning ("Error in device_get_property: %s\n", err->message);
		g_error_free (err);
		ret = FALSE;
	}

	g_object_unref (properties_proxy);

	return ret;
}

void
_nm_dbus_set_property (DBusGProxy *proxy,
					  const char *interface,
					  const char *prop_name,
					  GValue *value)
{
	DBusGProxy *properties_proxy;

	g_return_if_fail (proxy != NULL);
	g_return_if_fail (interface != NULL);
	g_return_if_fail (prop_name != NULL);

	properties_proxy = dbus_g_proxy_new_from_proxy (proxy,
													"org.freedesktop.DBus.Properties",
													dbus_g_proxy_get_path (proxy));

	dbus_g_proxy_call_no_reply (properties_proxy, "Set",
								G_TYPE_STRING, interface,
								G_TYPE_STRING, prop_name,
								G_TYPE_VALUE, value,
								G_TYPE_INVALID);

	g_object_unref (properties_proxy);
}

char *
_nm_dbus_introspect (DBusGConnection *connection,
					const char *interface,
					const char *path)
{
	DBusGProxy *remote_object_introspectable;
	char *introspect_data = NULL;
	GError *err = NULL;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (interface != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);

	remote_object_introspectable = dbus_g_proxy_new_for_name (connection,
															  interface,
															  path,
															  "org.freedesktop.DBus.Introspectable");
	if (!dbus_g_proxy_call (remote_object_introspectable, "Introspect", &err,
							G_TYPE_INVALID,
							G_TYPE_STRING, &introspect_data, G_TYPE_INVALID)) {
		g_error ("Failed to complete Introspect %s", err->message);
		g_error_free (err);
	}

	g_object_unref (G_OBJECT (remote_object_introspectable));

	return introspect_data;
}
