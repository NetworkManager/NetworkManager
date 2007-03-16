#ifndef NM_DEVICE_PRIVATE_H
#define NM_DEVICE_PRIVATE_H

#include <dbus/dbus-glib.h>

DBusGConnection *nm_device_get_connection       (NMDevice *device);
const char      *nm_device_get_path             (NMDevice *device);
DBusGProxy      *nm_device_get_properties_proxy (NMDevice *device);

/* static methods */
NMDeviceType     nm_device_type_for_path (DBusGConnection *connection,
										  const char *path);

#endif /* NM_DEVICE_PRIVATE_H */
