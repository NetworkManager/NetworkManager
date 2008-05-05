/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#ifndef NM_DBUS_SETTINGS_H
#define NM_DBUS_SETTINGS_H

#include <dbus/dbus-glib.h>
#include <nm-connection.h>
#include <nm-settings.h>
#include <nm-dbus-connection.h>

G_BEGIN_DECLS

#define NM_TYPE_DBUS_SETTINGS            (nm_dbus_settings_get_type ())
#define NM_DBUS_SETTINGS(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DBUS_SETTINGS, NMDBusSettings))
#define NM_DBUS_SETTINGS_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DBUS_SETTINGS, NMDBusSettingsClass))
#define NM_IS_DBUS_SETTINGS(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DBUS_SETTINGS))
#define NM_IS_DBUS_SETTINGS_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_DBUS_SETTINGS))
#define NM_DBUS_SETTINGS_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DBUS_SETTINGS, NMDBusSettingsClass))

#define NM_DBUS_SETTINGS_DBUS_CONNECTION "dbus-connection"
#define NM_DBUS_SETTINGS_SCOPE           "scope"

typedef struct {
	NMSettings parent;
} NMDBusSettings;

typedef struct {
	NMSettingsClass parent;
} NMDBusSettingsClass;

GType nm_dbus_settings_get_type (void);

NMDBusSettings *nm_dbus_settings_new (DBusGConnection *dbus_connection);

NMDBusConnection *nm_dbus_settings_get_connection_by_path (NMDBusSettings *self,
											    const char *path);

G_END_DECLS

#endif /* NM_DBUS_SETTINGS_H */
