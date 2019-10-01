// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

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

/* D-Bus has an upper limit on number of Match rules and it's rather easy
 * to hit as the proxy likes to add one for each object. Let's remove the Match
 * rule the proxy added and ensure a less granular rule is present instead.
 *
 * Also, don't do this immediately since it has a performance penalty.
 * Still better than losing the signals altogether.
 *
 * Ideally, we should be able to tell glib not to hook its rules:
 * https://bugzilla.gnome.org/show_bug.cgi?id=758749
 */
void
_nm_dbus_proxy_replace_match (GDBusProxy *proxy)
{
	GDBusConnection *connection = g_dbus_proxy_get_connection (proxy);
	static unsigned match_counter = 1024;
	char *match;

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
