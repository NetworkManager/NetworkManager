#include "nm-utils.h"

gboolean
nm_dbus_get_property (DBusGProxy *proxy,
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
nm_dbus_set_property (DBusGProxy *proxy,
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
nm_dbus_introspect (DBusGConnection *connection,
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
