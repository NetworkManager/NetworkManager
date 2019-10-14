// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2011, 2014 Red Hat, Inc.
 */

/*
 * The example shows how to call the AddConnection() D-Bus method to add a
 * connection to the system settings service. It uses GDBus, plus a few defines
 * from the NetworkManager headers. Contrast add-connection-libnm, which is
 * higher level because it uses libnm.
 *
 * Compile with:
 *   gcc -Wall add-connection-gdbus.c -o add-connection-gdbus `pkg-config --cflags --libs libnm uuid`
 */

#include <gio/gio.h>
#include <uuid/uuid.h>

#include <nm-dbus-interface.h>

/* include NetworkManager.h for the defines, but we don't link against
 * libnm. */
#include <NetworkManager.h>

/* copied from libnm-core/nm-utils.c */
char *
nm_utils_uuid_generate (void)
{
	uuid_t uuid;
	char *buf;

	buf = g_malloc0 (37);
	uuid_generate_random (uuid);
	uuid_unparse_lower (uuid, &buf[0]);
	return buf;
}

static void
add_connection (GDBusProxy *proxy, const char *con_name)
{
	GVariantBuilder connection_builder;
	GVariantBuilder setting_builder;
	char *uuid;
	const char *new_con_path;
	GVariant *ret;
	GError *error = NULL;

	/* Initialize connection GVariantBuilder */
	g_variant_builder_init (&connection_builder, G_VARIANT_TYPE ("a{sa{sv}}"));

	/* Build up the 'connection' Setting */
	g_variant_builder_init (&setting_builder, G_VARIANT_TYPE ("a{sv}"));

	uuid = nm_utils_uuid_generate ();
	g_variant_builder_add (&setting_builder, "{sv}",
	                       NM_SETTING_CONNECTION_UUID,
	                       g_variant_new_string (uuid));
	g_free (uuid);

	g_variant_builder_add (&setting_builder, "{sv}",
	                       NM_SETTING_CONNECTION_ID,
	                       g_variant_new_string (con_name));
	g_variant_builder_add (&setting_builder, "{sv}",
	                       NM_SETTING_CONNECTION_TYPE,
	                       g_variant_new_string (NM_SETTING_WIRED_SETTING_NAME));

	g_variant_builder_add (&connection_builder, "{sa{sv}}",
	                       NM_SETTING_CONNECTION_SETTING_NAME,
	                       &setting_builder);

	/* Add the (empty) 'wired' Setting */
	g_variant_builder_init (&setting_builder, G_VARIANT_TYPE ("a{sv}"));
	g_variant_builder_add (&connection_builder, "{sa{sv}}",
	                       NM_SETTING_WIRED_SETTING_NAME,
	                       &setting_builder);

	/* Build up the 'ipv4' Setting */
	g_variant_builder_init (&setting_builder, G_VARIANT_TYPE ("a{sv}"));
	g_variant_builder_add (&setting_builder, "{sv}",
	                       NM_SETTING_IP_CONFIG_METHOD,
	                       g_variant_new_string (NM_SETTING_IP4_CONFIG_METHOD_AUTO));
	g_variant_builder_add (&connection_builder, "{sa{sv}}",
	                       NM_SETTING_IP4_CONFIG_SETTING_NAME,
	                       &setting_builder);

	/* Call AddConnection with the connection dictionary as argument.
	 * (g_variant_new() will consume the floating GVariant returned from
	 * &connection_builder, and g_dbus_proxy_call_sync() will consume the
	 * floating variant returned from g_variant_new(), so no cleanup is needed.
	 */
	ret = g_dbus_proxy_call_sync (proxy,
	                              "AddConnection",
	                              g_variant_new ("(a{sa{sv}})", &connection_builder),
	                              G_DBUS_CALL_FLAGS_NONE, -1,
	                              NULL, &error);
	if (ret) {
		g_variant_get (ret, "(&o)", &new_con_path);
		g_print ("Added: %s\n", new_con_path);
		g_variant_unref (ret);
	} else {
		g_dbus_error_strip_remote_error (error);
		g_print ("Error adding connection: %s\n", error->message);
		g_clear_error (&error);
	}
}

int
main (int argc, char *argv[])
{
	GDBusProxy *proxy;
	GError *error = NULL;

	/* Create a D-Bus proxy; NM_DBUS_* defined in nm-dbus-interface.h */
	proxy = g_dbus_proxy_new_for_bus_sync (G_BUS_TYPE_SYSTEM,
	                                       G_DBUS_PROXY_FLAGS_NONE,
	                                       NULL,
	                                       NM_DBUS_SERVICE,
	                                       NM_DBUS_PATH_SETTINGS,
	                                       NM_DBUS_INTERFACE_SETTINGS,
	                                       NULL, &error);
	if (!proxy) {
		g_dbus_error_strip_remote_error (error);
		g_print ("Could not create NetworkManager D-Bus proxy: %s\n", error->message);
		g_error_free (error);
		return 1;
	}

	/* Add a connection */
	add_connection (proxy, "__Test connection__");

	g_object_unref (proxy);

	return 0;
}
