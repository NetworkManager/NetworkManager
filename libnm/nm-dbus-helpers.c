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
 * Copyright 2013 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-dbus-helpers.h"

#include <string.h>

#include "nm-dbus-interface.h"

static GBusType nm_bus = G_BUS_TYPE_SYSTEM;

GBusType
_nm_dbus_bus_type (void)
{
	static gsize init_value = 0;

	if (g_once_init_enter (&init_value)) {
		if (g_getenv ("LIBNM_USE_SESSION_BUS"))
			nm_bus = G_BUS_TYPE_SESSION;

		g_once_init_leave (&init_value, 1);
	}

	return nm_bus;
}

GDBusConnection *
_nm_dbus_new_connection (GCancellable *cancellable, GError **error)
{
	return g_bus_get_sync (_nm_dbus_bus_type (), cancellable, error);
}

static void
new_connection_async_got_system (GObject *source, GAsyncResult *result, gpointer user_data)
{
	GSimpleAsyncResult *simple = user_data;
	GDBusConnection *connection;
	GError *error = NULL;

	connection = g_bus_get_finish (result, &error);
	if (connection)
		g_simple_async_result_set_op_res_gpointer (simple, connection, g_object_unref);
	else
		g_simple_async_result_take_error (simple, error);

	g_simple_async_result_complete (simple);
	g_object_unref (simple);
}

void
_nm_dbus_new_connection_async (GCancellable *cancellable,
                               GAsyncReadyCallback callback,
                               gpointer user_data)
{
	GSimpleAsyncResult *simple;

	simple = g_simple_async_result_new (NULL, callback, user_data, _nm_dbus_new_connection_async);

	g_bus_get (_nm_dbus_bus_type (),
	           cancellable,
	           new_connection_async_got_system, simple);
}

GDBusConnection *
_nm_dbus_new_connection_finish (GAsyncResult *result,
                                GError **error)
{
	GSimpleAsyncResult *simple = G_SIMPLE_ASYNC_RESULT (result);

	if (g_simple_async_result_propagate_error (simple, error))
		return NULL;

	return g_object_ref (g_simple_async_result_get_op_res_gpointer (simple));
}

gboolean
_nm_dbus_is_connection_private (GDBusConnection *connection)
{
	return g_dbus_connection_get_unique_name (connection) == NULL;
}

static GHashTable *proxy_types;

#undef _nm_dbus_register_proxy_type
void
_nm_dbus_register_proxy_type (const char *interface,
                              GType       proxy_type)
{
	if (!proxy_types)
		proxy_types = g_hash_table_new (g_str_hash, g_str_equal);

	g_assert (g_hash_table_lookup (proxy_types, interface) == NULL);
	g_hash_table_insert (proxy_types, (char *) interface, GSIZE_TO_POINTER (proxy_type));
}

/* We don't (currently) use GDBus's property-handling code */
#define NM_DBUS_PROXY_FLAGS (G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES | \
                             G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START)

/* D-Bus has an upper limit on number of Match rules and it's rather easy
 * to hit as the proxy likes to add one for each object. Let's remove the Match
 * rule the proxy added and ensure a less granular rule is present instead.
 *
 * Also, don't do this immediately since it has a performance penalty.
 * Still better than loosing the signals altogether.
 *
 * Ideally, we should be able to tell glib not to hook its rules:
 * https://bugzilla.gnome.org/show_bug.cgi?id=758749
 */
static void
_nm_dbus_proxy_replace_match (GDBusProxy *proxy)
{
	GDBusConnection *connection = g_dbus_proxy_get_connection (proxy);
	static unsigned match_counter = 1024;
	gchar *match;

	nm_assert (!g_strcmp0 (g_dbus_proxy_get_name (proxy), NM_DBUS_SERVICE));

	if (match_counter == 1) {
		/* If we hit the low matches watermark, install a
		 * less granular one. */
		g_dbus_connection_call (connection,
		                        "org.freedesktop.DBus",
		                        "/org/freedesktop/DBus",
		                        "org.freedesktop.DBus",
		                        "AddMatch",
		                        g_variant_new ("(s)", "type='signal',sender='" NM_DBUS_SERVICE "'"),
		                        NULL,
		                        G_DBUS_CALL_FLAGS_NONE,
		                        -1,
		                        NULL,
		                        NULL,
		                        NULL);
	}

	if (match_counter)
		match_counter--;
	if (match_counter)
		return;

	/* Remove what this proxy added. */
	match = g_strdup_printf ("type='signal',sender='" NM_DBUS_SERVICE "',"
	                         "interface='%s',path='%s'",
	                         g_dbus_proxy_get_interface_name (proxy),
	                         g_dbus_proxy_get_object_path (proxy));
	g_dbus_connection_call (connection,
	                        "org.freedesktop.DBus",
	                        "/org/freedesktop/DBus",
	                        "org.freedesktop.DBus",
	                        "RemoveMatch",
	                        g_variant_new ("(s)", match),
	                        NULL,
	                        G_DBUS_CALL_FLAGS_NONE,
	                        -1,
	                        NULL,
	                        NULL,
	                        NULL);
	g_free (match);
}

GDBusProxy *
_nm_dbus_new_proxy_for_connection (GDBusConnection *connection,
                                   const char *path,
                                   const char *interface,
                                   GCancellable *cancellable,
                                   GError **error)
{
	GDBusProxy *proxy;
	GType proxy_type;
	const char *name;

	proxy_type = GPOINTER_TO_SIZE (g_hash_table_lookup (proxy_types, interface));
	if (!proxy_type)
		proxy_type = G_TYPE_DBUS_PROXY;

	if (_nm_dbus_is_connection_private (connection))
		name = NULL;
	else
		name = NM_DBUS_SERVICE;

	proxy = g_initable_new (proxy_type, cancellable, error,
	                        "g-connection", connection,
	                        "g-flags", NM_DBUS_PROXY_FLAGS,
	                        "g-name", name,
	                        "g-object-path", path,
	                        "g-interface-name", interface,
	                        NULL);
	_nm_dbus_proxy_replace_match (proxy);

	return proxy;
}

void
_nm_dbus_new_proxy_for_connection_async (GDBusConnection *connection,
                                         const char *path,
                                         const char *interface,
                                         GCancellable *cancellable,
                                         GAsyncReadyCallback callback,
                                         gpointer user_data)
{
	GType proxy_type;
	const char *name;

	proxy_type = GPOINTER_TO_SIZE (g_hash_table_lookup (proxy_types, interface));
	if (!proxy_type)
		proxy_type = G_TYPE_DBUS_PROXY;

	if (_nm_dbus_is_connection_private (connection))
		name = NULL;
	else
		name = NM_DBUS_SERVICE;

	g_async_initable_new_async (proxy_type, G_PRIORITY_DEFAULT,
	                            cancellable, callback, user_data,
	                            "g-connection", connection,
	                            "g-flags", NM_DBUS_PROXY_FLAGS,
	                            "g-name", name,
	                            "g-object-path", path,
	                            "g-interface-name", interface,
	                            NULL);
}

GDBusProxy *
_nm_dbus_new_proxy_for_connection_finish (GAsyncResult *result,
                                          GError **error)
{
	GObject *source;
	GDBusProxy *proxy;

	source = g_async_result_get_source_object (result);
	proxy = G_DBUS_PROXY (g_async_initable_new_finish (G_ASYNC_INITABLE (source), result, error));
	g_object_unref (source);
	_nm_dbus_proxy_replace_match (proxy);

	return proxy;
}

/* Binds the properties on a generated server-side GDBus object to the
 * corresponding properties on the public object.
 */
void
_nm_dbus_bind_properties (gpointer object, gpointer skeleton)
{
	GParamSpec **properties;
	guint n_properties;
	int i;

	properties = g_object_class_list_properties (G_OBJECT_GET_CLASS (skeleton), &n_properties);
	for (i = 0; i < n_properties; i++) {
		if (g_str_has_prefix (properties[i]->name, "g-"))
			continue;

		g_object_bind_property (object, properties[i]->name,
		                        skeleton, properties[i]->name,
		                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	}
	g_free (properties);
}

static char *
signal_name_from_method_name (const char *method_name)
{
	GString *signal_name;
	const char *p;

	signal_name = g_string_new ("handle");
	for (p = method_name; *p; p++) {
		if (g_ascii_isupper (*p))
			g_string_append_c (signal_name, '-');
		g_string_append_c (signal_name, g_ascii_tolower (*p));
	}

	return g_string_free (signal_name, FALSE);
}

static void
_nm_dbus_method_meta_marshal (GClosure *closure, GValue *return_value,
                              guint n_param_values, const GValue *param_values,
                              gpointer invocation_hint, gpointer marshal_data)
{
	closure->marshal (closure, return_value, n_param_values,
	                  param_values, invocation_hint,
	                  ((GCClosure *)closure)->callback);

	g_value_set_boolean (return_value, TRUE);
}

/* Takes (method_name, handler_func) pairs and connects the handlers to the
 * signals on skeleton, with object as the user_data, but swapped so it comes
 * first in the argument list, and handling the return value automatically.
 */
void
_nm_dbus_bind_methods (gpointer object, gpointer skeleton, ...)
{
	va_list ap;
	const char *method_name;
	char *signal_name;
	GCallback handler;
	GClosure *closure;

	va_start (ap, skeleton);
	while (   (method_name = va_arg (ap, const char *))
	       && (handler = va_arg (ap, GCallback))) {
		signal_name = signal_name_from_method_name (method_name);
		closure = g_cclosure_new_swap (handler, object, NULL);
		g_closure_set_meta_marshal (closure, NULL, _nm_dbus_method_meta_marshal);
		g_signal_connect_closure (skeleton, signal_name, closure, FALSE);
		g_free (signal_name);
	}
	va_end (ap);
}
