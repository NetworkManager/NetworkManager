#ifndef NM_UTILS_H
#define NM_UTILS_H

#include <dbus/dbus-glib.h>

char *nm_dbus_get_string_property (DBusGProxy *proxy,
								   const char *interface,
								   const char *prop_name);

char *nm_dbus_get_object_path_property (DBusGProxy *proxy,
										const char *interface,
										const char *prop_name);

gint32 nm_dbus_get_int_property (DBusGProxy *proxy,
								 const char *interface,
								 const char *prop_name);

guint32 nm_dbus_get_uint_property (DBusGProxy *proxy,
								   const char *interface,
								   const char *prop_name);

gboolean  nm_dbus_get_property (DBusGProxy *proxy,
								const char *interface,
								const char *prop_name,
								GValue *value);
void      nm_dbus_set_property (DBusGProxy *proxy,
								const char *interface,
								const char *prop_name,
								GValue *value);

char     *nm_dbus_introspect   (DBusGConnection *connection,
								const char *interface,
								const char *path);

#endif /* NM_UTILS_H */
