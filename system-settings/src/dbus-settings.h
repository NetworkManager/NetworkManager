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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2007 Red Hat, Inc.
 */

#ifndef __DBUS_SETTINGS_H__
#define __DBUS_SETTINGS_H__

#include <nm-connection.h>
#include <nm-settings.h>

#include "nm-system-config-interface.h"
#include "nm-system-config-hal-manager.h"

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

NMSysconfigSettings *nm_sysconfig_settings_new (DBusGConnection *g_conn,
						NMSystemConfigHalManager *hal_mgr);

void nm_sysconfig_settings_add_plugin     (NMSysconfigSettings *settings,
					   NMSystemConfigInterface *plugin);

void nm_sysconfig_settings_add_connection (NMSysconfigSettings *settings,
                                           NMExportedConnection *connection);

void nm_sysconfig_settings_remove_connection (NMSysconfigSettings *settings,
                                              NMExportedConnection *connection);

void nm_sysconfig_settings_update_unamanged_devices (NMSysconfigSettings *settings,
                                                     GSList *new_list);

gboolean nm_sysconfig_settings_is_device_managed (NMSysconfigSettings *settings,
                                                  const char *udi);

#endif  /* __DBUS_SETTINGS_H__ */
