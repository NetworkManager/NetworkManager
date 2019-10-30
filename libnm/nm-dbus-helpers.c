// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-dbus-helpers.h"

#include "nm-dbus-interface.h"

GBusType
_nm_dbus_bus_type (void)
{
	static volatile int bus_type = G_BUS_TYPE_NONE;
	int v;

	v = g_atomic_int_get (&bus_type);
	if (G_UNLIKELY (v == G_BUS_TYPE_NONE)) {
		v = G_BUS_TYPE_SYSTEM;
		if (g_getenv ("LIBNM_USE_SESSION_BUS"))
			v = G_BUS_TYPE_SESSION;
		if (!g_atomic_int_compare_and_exchange (&bus_type, G_BUS_TYPE_NONE, v))
			v = g_atomic_int_get (&bus_type);
		nm_assert (v != G_BUS_TYPE_NONE);
	}
	return v;
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
