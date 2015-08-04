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
 * Copyright 2015 Red Hat, Inc.
 */

#include "config.h"

#include <string.h>

#include "nm-default.h"
#include "nm-core-internal.h"

typedef struct {
	char *signal_name;
	const GVariantType *signature;
} NMDBusSignalData;

static void
dbus_signal_data_free (gpointer data, GClosure *closure)
{
	NMDBusSignalData *sd = data;

	g_free (sd->signal_name);
	g_slice_free (NMDBusSignalData, sd);
}

static void
dbus_signal_meta_marshal (GClosure     *closure,
                          GValue       *return_value,
                          guint         n_param_values,
                          const GValue *param_values,
                          gpointer      invocation_hint,
                          gpointer      marshal_data)
{
	NMDBusSignalData *sd = marshal_data;
	const char *signal_name;
	GVariant *parameters, *param;
	GValue *closure_params;
	gsize n_params, i;

	g_return_if_fail (n_param_values == 4);

	signal_name = g_value_get_string (&param_values[2]);
	parameters = g_value_get_variant (&param_values[3]);

	if (strcmp (signal_name, sd->signal_name) != 0)
		return;

	if (sd->signature) {
		if (!g_variant_is_of_type (parameters, sd->signature)) {
			g_warning ("%p: got signal '%s' but parameters were of type '%s', not '%s'",
			           g_value_get_object (&param_values[0]),
			           signal_name, g_variant_get_type_string (parameters),
			           g_variant_type_peek_string (sd->signature));
			return;
		}

		n_params = g_variant_n_children (parameters) + 1;
	} else
		n_params = 1;

	closure_params = g_new0 (GValue, n_params);
	g_value_init (&closure_params[0], G_TYPE_OBJECT);
	g_value_copy (&param_values[0], &closure_params[0]);

	for (i = 1; i < n_params; i++) {
		param = g_variant_get_child_value (parameters, i - 1);
		if (   g_variant_is_of_type (param, G_VARIANT_TYPE ("ay"))
		    || g_variant_is_of_type (param, G_VARIANT_TYPE ("aay"))) {
			/* g_dbus_gvariant_to_gvalue() thinks 'ay' means "non-UTF-8 NUL-terminated string" */
			g_value_init (&closure_params[i], G_TYPE_VARIANT);
			g_value_set_variant (&closure_params[i], param);
		} else
			g_dbus_gvariant_to_gvalue (param, &closure_params[i]);
		g_variant_unref (param);
	}

	g_cclosure_marshal_generic (closure,
	                            NULL,
	                            n_params,
	                            closure_params,
	                            invocation_hint,
	                            NULL);

	for (i = 0; i < n_params; i++)
		g_value_unset (&closure_params[i]);
	g_free (closure_params);
}

/**
 * _nm_dbus_signal_connect_data:
 * @proxy: a #GDBusProxy
 * @signal_name: the D-Bus signal to connect to
 * @signature: (allow-none): the signal's type signature (must be a tuple)
 * @c_handler: the signal handler function
 * @data: (allow-none): data to pass to @c_handler
 * @destroy_data: (allow-none): closure destroy notify for @data
 * @connect_flags: connection flags
 *
 * Connects to the D-Bus signal @signal_name on @proxy. @c_handler must be a
 * void function whose first argument is a #GDBusProxy, followed by arguments
 * for each element of @signature, ending with a #gpointer argument for @data.
 *
 * The argument types in @c_handler correspond to the types output by
 * g_dbus_gvariant_to_gvalue(), except for 'ay' and 'aay'. In particular:
 * - both 16-bit and 32-bit integers are passed as #gint/#guint
 * - 'as' values are passed as #GStrv (char **)
 * - all other array, tuple, and dict types are passed as #GVariant
 *
 * If @signature is %NULL, then the signal's parameters will be ignored, and
 * @c_handler should take only the #GDBusProxy and #gpointer arguments.
 *
 * Returns: the signal handler ID, which can be used with
 *   g_signal_handler_remove(). Beware that because of the way the signal is
 *   connected, you will not be able to remove it with
 *   g_signal_handlers_disconnect_by_func(), although
 *   g_signal_handlers_disconnect_by_data() will work correctly.
 */
gulong
_nm_dbus_signal_connect_data (GDBusProxy *proxy,
                              const char *signal_name,
                              const GVariantType *signature,
                              GCallback c_handler,
                              gpointer data,
                              GClosureNotify destroy_data,
                              GConnectFlags connect_flags)
{
	NMDBusSignalData *sd;
	GClosure *closure;
	gboolean swapped = !!(connect_flags & G_CONNECT_SWAPPED);
	gboolean after = !!(connect_flags & G_CONNECT_AFTER);

	g_return_val_if_fail (G_IS_DBUS_PROXY (proxy), 0);
	g_return_val_if_fail (signal_name != NULL, 0);
	g_return_val_if_fail (signature == NULL || g_variant_type_is_tuple (signature), 0);
	g_return_val_if_fail (c_handler != NULL, 0);

	sd = g_slice_new (NMDBusSignalData);
	sd->signal_name = g_strdup (signal_name);
	sd->signature = signature;

	closure = (swapped ? g_cclosure_new_swap : g_cclosure_new) (c_handler, data, destroy_data);
	g_closure_set_marshal (closure, g_cclosure_marshal_generic);
	g_closure_set_meta_marshal (closure, sd, dbus_signal_meta_marshal);
	g_closure_add_finalize_notifier (closure, sd, dbus_signal_data_free);

	return g_signal_connect_closure (proxy, "g-signal", closure, after);
}

/**
 * _nm_dbus_signal_connect:
 * @proxy: a #GDBusProxy
 * @signal_name: the D-Bus signal to connect to
 * @signature: the signal's type signature (must be a tuple)
 * @c_handler: the signal handler function
 * @data: (allow-none): data to pass to @c_handler
 *
 * Simplified version of _nm_dbus_signal_connect_data() with fewer arguments.
 *
 * Returns: the signal handler ID, as with _nm_signal_connect_data().
 */


static void
typecheck_response (GVariant           **response,
                    const GVariantType  *reply_type,
                    GError             **error)
{
	if (*response && reply_type && !g_variant_is_of_type (*response, reply_type)) {
		/* This is the same error code that g_dbus_connection_call() returns if
		 * @reply_type doesn't match.
		 */
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
		             _("Method returned type '%s', but expected '%s'"),
		             g_variant_get_type_string (*response),
		             g_variant_type_peek_string (reply_type));
		g_clear_pointer (response, g_variant_unref);
	}
}

/**
 * _nm_dbus_proxy_call_finish:
 * @proxy: A #GDBusProxy.
 * @res: A #GAsyncResult obtained from the #GAsyncReadyCallback passed to
 *   g_dbus_proxy_call().
 * @reply_type: (allow-none): the expected type of the reply, or %NULL
 * @error: Return location for error or %NULL.
 *
 * Finishes an operation started with g_dbus_proxy_call(), as with
 * g_dbus_proxy_call_finish(), except thatif @reply_type is non-%NULL, then it
 * will also check that the response matches that type signature, and return
 * an error if not.
 *
 * Returns: %NULL if @error is set. Otherwise a #GVariant tuple with
 * return values. Free with g_variant_unref().
 */
GVariant *
_nm_dbus_proxy_call_finish (GDBusProxy          *proxy,
                            GAsyncResult        *res,
                            const GVariantType  *reply_type,
                            GError             **error)
{
	GVariant *ret;

	ret = g_dbus_proxy_call_finish (proxy, res, error);
	typecheck_response (&ret, reply_type, error);
	return ret;
}

/**
 * _nm_dbus_proxy_call_sync:
 * @proxy: A #GDBusProxy.
 * @method_name: Name of method to invoke.
 * @parameters: (allow-none): A #GVariant tuple with parameters for the signal
 *   or %NULL if not passing parameters.
 * @reply_type: (allow-none): the expected type of the reply, or %NULL
 * @flags: Flags from the #GDBusCallFlags enumeration.
 * @timeout_msec: The timeout in milliseconds (with %G_MAXINT meaning
 *   "infinite") or -1 to use the proxy default timeout.
 * @cancellable: (allow-none): A #GCancellable or %NULL.
 * @error: Return location for error or %NULL.
 *
 * Synchronously invokes the @method_name method on @proxy, as with
 * g_dbus_proxy_call_sync(), except that if @reply_type is non-%NULL, then the
 * reply to the call will be checked against it, and an error returned if it
 * does not match.
 *
 * Returns: %NULL if @error is set. Otherwise a #GVariant tuple with
 * return values. Free with g_variant_unref().
 */
GVariant *
_nm_dbus_proxy_call_sync (GDBusProxy          *proxy,
                          const gchar         *method_name,
                          GVariant            *parameters,
                          const GVariantType  *reply_type,
                          GDBusCallFlags       flags,
                          gint                 timeout_msec,
                          GCancellable        *cancellable,
                          GError             **error)
{
	GVariant *ret;

	ret = g_dbus_proxy_call_sync (proxy, method_name, parameters,
	                              flags, timeout_msec,
	                              cancellable, error);
	typecheck_response (&ret, reply_type, error);
	return ret;
}

/**
 * _nm_dbus_error_has_name:
 * @error: (allow-none): a #GError, or %NULL
 * @dbus_error_name: a D-Bus error name
 *
 * Checks if @error is set and corresponds to the D-Bus error @dbus_error_name.
 *
 * Returns: %TRUE or %FALSE
 */
gboolean
_nm_dbus_error_has_name (GError     *error,
                         const char *dbus_error_name)
{
	gboolean has_name = FALSE;

	if (error && g_dbus_error_is_remote_error (error)) {
		char *error_name;

		error_name = g_dbus_error_get_remote_error (error);
		has_name = !g_strcmp0 (error_name, dbus_error_name);
		g_free (error_name);
	}

	return has_name;
}
