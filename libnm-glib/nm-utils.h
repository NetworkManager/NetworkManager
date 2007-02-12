#ifndef NM_UTILS_H
#define NM_UTILS_H

#include <dbus/dbus-glib.h>

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
