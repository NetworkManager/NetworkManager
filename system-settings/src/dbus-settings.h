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

#include <nm-connection.h>
#include <nm-settings.h>

typedef struct _NMSysconfigConnectionSettings NMSysconfigConnectionSettings;
typedef struct _NMSysconfigConnectionSettingsClass NMSysconfigConnectionSettingsClass;

/*
 * NMSysconfigConnectionSettings
 */

#define NM_TYPE_SYSCONFIG_CONNECTION_SETTINGS            (nm_sysconfig_connection_settings_get_type ())
#define NM_SYSCONFIG_CONNECTION_SETTINGS(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SYSCONFIG_CONNECTION_SETTINGS, NMSysconfigConnectionSettings))
#define NM_SYSCONFIG_CONNECTION_SETTINGS_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_SYSCONFIG_CONNECTION_SETTINGS, NMSysconfigConnectionSettingsClass))
#define NM_IS_SYSCONFIG_CONNECTION_SETTINGS(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SYSCONFIG_CONNECTION_SETTINGS))
#define NM_IS_SYSCONFIG_CONNECTION_SETTINGS_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_SYSCONFIG_CONNECTION_SETTINGS))
#define NM_SYSCONFIG_CONNECTION_SETTINGS_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_SYSCONFIG_CONNECTION_SETTINGS, NMSysconfigConnectionSettingsClass))

struct _NMSysconfigConnectionSettings
{
    NMConnectionSettings parent_instance;

    char *id;
    NMConnection *connection;
};

struct _NMSysconfigConnectionSettingsClass
{
    NMConnectionSettingsClass parent_class;
};

GType nm_sysconfig_connection_settings_get_type (void);
NMSysconfigConnectionSettings *nm_sysconfig_connection_settings_new (NMConnection *connection,
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

struct _NMSysconfigSettings
{
    NMSettings parent_instance;

    GSList *connections;
};

struct _NMSysconfigSettingsClass
{
    NMSettingsClass parent_class;
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

