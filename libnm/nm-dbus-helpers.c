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

#include "config.h"

#include <string.h>

#include "nm-default.h"
#include "nm-dbus-helpers.h"
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

static struct {
	GMutex mutex;
	GWeakRef weak_ref;
} private_connection;

static void
_private_dbus_connection_closed_cb (GDBusConnection *connection,
                                    gboolean         remote_peer_vanished,
                                    GError          *error,
                                    gpointer         user_data)
{
	GDBusConnection *p;

	g_mutex_lock (&private_connection.mutex);
	p = g_weak_ref_get (&private_connection.weak_ref);
	if (connection == p) {
		g_signal_handlers_disconnect_by_func (G_OBJECT (connection), G_CALLBACK (_private_dbus_connection_closed_cb), NULL);
		g_weak_ref_set (&private_connection.weak_ref, NULL);
	}
	if (p)
		g_object_unref (p);
	g_mutex_unlock (&private_connection.mutex);
}

static GDBusConnection *
_private_dbus_connection_internalize (GDBusConnection *connection)
{
	GDBusConnection *p;

	g_return_val_if_fail (G_IS_DBUS_CONNECTION (connection), NULL);
	g_return_val_if_fail (!g_dbus_connection_is_closed (connection), NULL);

	g_mutex_lock (&private_connection.mutex);
	p = g_weak_ref_get (&private_connection.weak_ref);
	if (p) {
		g_object_unref (connection);
		connection = p;
	} else {
		g_weak_ref_set (&private_connection.weak_ref, connection);
		g_signal_connect (connection, "closed", G_CALLBACK (_private_dbus_connection_closed_cb), NULL);
	}
	g_mutex_unlock (&private_connection.mutex);
	return connection;
}

GDBusConnection *
_nm_dbus_new_connection (GCancellable *cancellable, GError **error)
{
	GDBusConnection *connection = NULL;

	/* If running as root try the private bus first */
	if (0 == geteuid () && !g_test_initialized ()) {

		GError *local = NULL;
		GDBusConnection *p;

		p = g_weak_ref_get (&private_connection.weak_ref);
		if (p)
			return p;

		connection = g_dbus_connection_new_for_address_sync ("unix:path=" NMRUNDIR "/private",
		                                                     G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT,
		                                                     NULL, cancellable, &local);
		if (connection)
			return _private_dbus_connection_internalize (connection);

		if (g_error_matches (local, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
			g_propagate_error (error, local);
			return NULL;
		}
		g_error_free (local);
	}

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

static void
new_connection_async_got_private (GObject *source, GAsyncResult *result, gpointer user_data)
{
	GSimpleAsyncResult *simple = user_data;
	GDBusConnection *connection;
	GError *error = NULL;

	connection = g_dbus_connection_new_for_address_finish (result, &error);
	if (connection) {
		connection = _private_dbus_connection_internalize (connection);
		g_simple_async_result_set_op_res_gpointer (simple, connection, g_object_unref);
		g_simple_async_result_complete (simple);
		g_object_unref (simple);
		return;
	}

	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		g_simple_async_result_take_error (simple, error);
		g_simple_async_result_complete (simple);
		g_object_unref (simple);
		return;
	}

	g_clear_error (&error);
	g_bus_get (_nm_dbus_bus_type (),
	           g_object_get_data (G_OBJECT (simple), "cancellable"),
	           new_connection_async_got_system, simple);
}

static void
_nm_dbus_new_connection_async_do (GSimpleAsyncResult *simple, GCancellable *cancellable)
{
	g_dbus_connection_new_for_address ("unix:path=" NMRUNDIR "/private",
	                                   G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT,
	                                   NULL,
	                                   cancellable,
	                                   new_connection_async_got_private, simple);
}

static gboolean
_nm_dbus_new_connection_async_get_private (gpointer user_data)
{
	GSimpleAsyncResult *simple = user_data;
	GDBusConnection *p;

	p = g_weak_ref_get (&private_connection.weak_ref);
	if (!p) {
		/* The connection is gone. Create a new one async... */
		_nm_dbus_new_connection_async_do (simple,
		                                  g_object_get_data (G_OBJECT (simple), "cancellable"));
	} else {
		g_simple_async_result_set_op_res_gpointer (simple, p, g_object_unref);
		g_simple_async_result_complete (simple);
		g_object_unref (simple);
	}

	return G_SOURCE_REMOVE;
}

void
_nm_dbus_new_connection_async (GCancellable *cancellable,
                               GAsyncReadyCallback callback,
                               gpointer user_data)
{
	GSimpleAsyncResult *simple;

	simple = g_simple_async_result_new (NULL, callback, user_data, _nm_dbus_new_connection_async);

	/* If running as root try the private bus first */
	if (0 == geteuid () && !g_test_initialized ()) {
		GDBusConnection *p;

		if (cancellable) {
			g_object_set_data_full (G_OBJECT (simple), "cancellable",
			                        g_object_ref (cancellable), g_object_unref);
		}
		p = g_weak_ref_get (&private_connection.weak_ref);
		if (p) {
			g_object_unref (p);
			g_idle_add (_nm_dbus_new_connection_async_get_private, simple);
		} else
			_nm_dbus_new_connection_async_do (simple, cancellable);
	} else {
		g_bus_get (_nm_dbus_bus_type (),
		           cancellable,
		           new_connection_async_got_system, simple);
	}
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

GDBusProxy *
_nm_dbus_new_proxy_for_connection (GDBusConnection *connection,
                                   const char *path,
                                   const char *interface,
                                   GCancellable *cancellable,
                                   GError **error)
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

	return g_initable_new (proxy_type, cancellable, error,
	                       "g-connection", connection,
	                       "g-flags", NM_DBUS_PROXY_FLAGS,
	                       "g-name", name,
	                       "g-object-path", path,
	                       "g-interface-name", interface,
	                       NULL);
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
	GObject *source, *proxy;

	source = g_async_result_get_source_object (result);
	proxy = g_async_initable_new_finish (G_ASYNC_INITABLE (source), result, error);
	g_object_unref (source);

	return G_DBUS_PROXY (proxy);
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
