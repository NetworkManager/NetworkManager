#ifndef NM_DEVICE_PRIVATE_H
#define NM_DEVICE_PRIVATE_H

/* static methods */
NMDeviceType     nm_device_type_for_path (DBusGConnection *connection,
										  const char *path);

#endif /* NM_DEVICE_PRIVATE_H */
