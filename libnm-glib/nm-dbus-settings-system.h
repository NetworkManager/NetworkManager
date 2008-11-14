/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * libnm_glib -- Access network status & information from glib applications
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2008 Novell, Inc.
 * Copyright (C) 2008 Red Hat, Inc.
 */

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
#define NM_DBUS_SETTINGS_SYSTEM_HOSTNAME "hostname"
#define NM_DBUS_SETTINGS_SYSTEM_CAN_MODIFY "can-modify"

typedef struct {
	NMDBusSettings parent;
} NMDBusSettingsSystem;

typedef struct {
	NMDBusSettingsClass parent;
} NMDBusSettingsSystemClass;

GType nm_dbus_settings_system_get_type (void);

NMDBusSettingsSystem *nm_dbus_settings_system_new (DBusGConnection *dbus_connection);

gboolean nm_dbus_settings_system_add_connection (NMDBusSettingsSystem *self,
									    NMConnection *connection,
									    GError **err);

GSList *nm_dbus_settings_system_get_unmanaged_devices (NMDBusSettingsSystem *self);

const char *nm_dbus_settings_system_get_hostname (NMDBusSettingsSystem *self);

gboolean nm_dbus_settings_system_save_hostname (NMDBusSettingsSystem *self,
                                                const char *hostname,
                                                GError **err);

gboolean nm_dbus_settings_system_get_can_modify (NMDBusSettingsSystem *self);

G_END_DECLS

#endif /* NM_DBUS_SETTINGS_SYSTEM_H */
