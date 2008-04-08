/* NetworkManager system settings service
 *
 * Søren Sandmann <sandmann@daimi.au.dk>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2007 Red Hat, Inc.
 */

#ifndef __DBUS_SETTINGS_H__
#define __DBUS_SETTINGS_H__

#include <nm-connection.h>
#include <nm-settings.h>

#define NM_SS_PLUGIN_TAG "nm-ss-plugin"

typedef struct _NMSysconfigExportedConnection NMSysconfigExportedConnection;
typedef struct _NMSysconfigExportedConnectionClass NMSysconfigExportedConnectionClass;

/*
 * NMSysconfigExportedConnection
 */

#define NM_TYPE_SYSCONFIG_EXPORTED_CONNECTION            (nm_sysconfig_exported_connection_get_type ())
#define NM_SYSCONFIG_EXPORTED_CONNECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SYSCONFIG_EXPORTED_CONNECTION, NMSysconfigExportedConnection))
#define NM_SYSCONFIG_EXPORTED_CONNECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_SYSCONFIG_EXPORTED_CONNECTION, NMSysconfigExportedConnectionClass))
#define NM_IS_SYSCONFIG_EXPORTED_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SYSCONFIG_EXPORTED_CONNECTION))
#define NM_IS_SYSCONFIG_EXPORTED_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_SYSCONFIG_EXPORTED_CONNECTION))
#define NM_SYSCONFIG_EXPORTED_CONNECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_SYSCONFIG_EXPORTED_CONNECTION, NMSysconfigExportedConnectionClass))

struct _NMSysconfigExportedConnection
{
	NMExportedConnection parent_instance;
};

struct _NMSysconfigExportedConnectionClass
{
	NMExportedConnectionClass parent_class;
};

GType nm_sysconfig_exported_connection_get_type (void);
NMSysconfigExportedConnection *nm_sysconfig_exported_connection_new (NMConnection *connection,
                                                                     DBusGConnection *g_conn);

/*
 * NMSysconfigSettings
 */
typedef struct _NMSysconfigSettings NMSysconfigSettings;
typedef struct _NMSysconfigSettingsClass NMSysconfigSettingsClass;

#define NM_TYPE_SYSCONFIG_SETTINGS            (nm_sysconfig_settings_get_type ())
#define NM_SYSCONFIG_SETTINGS(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SYSCONFIG_SETTINGS, NMSysconfigSettings))
#define NM_SYSCONFIG_SETTINGS_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_SYSCONFIG_SETTINGS, NMSysconfigSettingsClass))
#define NM_IS_SYSCONFIG_SETTINGS(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SYSCONFIG_SETTINGS))
#define NM_IS_SYSCONFIG_SETTINGS_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_SYSCONFIG_SETTINGS))
#define NM_SYSCONFIG_SETTINGS_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_SYSCONFIG_SETTINGS, NMSysconfigSettingsClass))

#define NM_SYSCONFIG_SETTINGS_UNMANAGED_DEVICES "unmanaged-devices"

struct _NMSysconfigSettings
{
	NMSettings parent_instance;
};

struct _NMSysconfigSettingsClass
{
	NMSettingsClass parent_class;

	/* Signals */
	void (*properties_changed) (NMSysconfigSettings *settings, GHashTable *properties);
};

GType nm_sysconfig_settings_get_type (void);

NMSysconfigSettings *nm_sysconfig_settings_new (DBusGConnection *g_conn);

void nm_sysconfig_settings_add_connection (NMSysconfigSettings *settings,
                                           NMConnection *connection,
                                           DBusGConnection *g_connection);

void nm_sysconfig_settings_remove_connection (NMSysconfigSettings *settings,
                                              NMConnection *connection);

void nm_sysconfig_settings_update_connection (NMSysconfigSettings *settings,
                                              NMConnection *connection);

void nm_sysconfig_settings_update_unamanged_devices (NMSysconfigSettings *settings,
                                                     GSList *new_list);

#endif  /* __DBUS_SETTINGS_H__ */
