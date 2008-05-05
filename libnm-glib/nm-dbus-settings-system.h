/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#ifndef NM_DBUS_SETTINGS_SYSTEM_H
#define NM_DBUS_SETTINGS_SYSTEM_H

#include <nm-dbus-settings.h>

G_BEGIN_DECLS

#define NM_TYPE_DBUS_SETTINGS_SYSTEM            (nm_dbus_settings_system_get_type ())
#define NM_DBUS_SETTINGS_SYSTEM(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DBUS_SETTINGS_SYSTEM, NMDBusSettingsSystem))
#define NM_DBUS_SETTINGS_SYSTEM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DBUS_SETTINGS_SYSTEM, NMDBusSettingsSystemClass))
#define NM_IS_DBUS_SETTINGS_SYSTEM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DBUS_SETTINGS_SYSTEM))
#define NM_IS_DBUS_SETTINGS_SYSTEM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_DBUS_SETTINGS_SYSTEM))
#define NM_DBUS_SETTINGS_SYSTEM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DBUS_SETTINGS_SYSTEM, NMDBusSettingsSystemClass))

#define NM_DBUS_SETTINGS_SYSTEM_UNMANAGED_DEVICES "unmanaged-devices"

typedef struct {
	NMDBusSettings parent;
} NMDBusSettingsSystem;

typedef struct {
	NMDBusSettingsClass parent;
} NMDBusSettingsSystemClass;

GType nm_dbus_settings_system_get_type (void);

NMDBusSettingsSystem *nm_dbus_settings_system_new (DBusGConnection *dbus_connection);

void nm_dbus_settings_system_add_connection (NMDBusSettingsSystem *self,
									NMConnection *connection);

GSList *nm_dbus_settings_system_get_unmanaged_devices (NMDBusSettingsSystem *self);


G_END_DECLS

#endif /* NM_DBUS_SETTINGS_SYSTEM_H */
