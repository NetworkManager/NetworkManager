#ifndef NM_UTILS_H
#define NM_UTILS_H

#include <dbus/dbus-glib.h>

char *_nm_dbus_get_string_property (DBusGProxy *proxy,
								   const char *interface,
								   const char *prop_name);

char *_nm_dbus_get_object_path_property (DBusGProxy *proxy,
										const char *interface,
										const char *prop_name);

gint32 _nm_dbus_get_int_property (DBusGProxy *proxy,
								 const char *interface,
								 const char *prop_name);

guint32 _nm_dbus_get_uint_property (DBusGProxy *proxy,
								   const char *interface,
								   const char *prop_name);

gboolean  _nm_dbus_get_property (DBusGProxy *proxy,
								const char *interface,
								const char *prop_name,
								GValue *value);
void      _nm_dbus_set_property (DBusGProxy *proxy,
								const char *interface,
								const char *prop_name,
								GValue *value);

char     *_nm_dbus_introspect   (DBusGConnection *connection,
								const char *interface,
								const char *path);

#endif /* NM_UTILS_H */
