/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service
 *
 * Søren Sandmann <sandmann@daimi.au.dk>
 * Dan Williams <dcbw@redhat.com>
 * Tambet Ingo <tambet@gmail.com>
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
 * (C) Copyright 2007 - 2009 Red Hat, Inc.
 * (C) Copyright 2008 Novell, Inc.
 */

#ifndef __NM_SYSCONFIG_SETTINGS_H__
#define __NM_SYSCONFIG_SETTINGS_H__

#include <nm-connection.h>
#include <nm-settings.h>

#include "nm-sysconfig-connection.h"
#include "nm-system-config-interface.h"

typedef struct _NMSysconfigSettings NMSysconfigSettings;
typedef struct _NMSysconfigSettingsClass NMSysconfigSettingsClass;

#define NM_TYPE_SYSCONFIG_SETTINGS            (nm_sysconfig_settings_get_type ())
#define NM_SYSCONFIG_SETTINGS(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SYSCONFIG_SETTINGS, NMSysconfigSettings))
#define NM_SYSCONFIG_SETTINGS_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_SYSCONFIG_SETTINGS, NMSysconfigSettingsClass))
#define NM_IS_SYSCONFIG_SETTINGS(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SYSCONFIG_SETTINGS))
#define NM_IS_SYSCONFIG_SETTINGS_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_SYSCONFIG_SETTINGS))
#define NM_SYSCONFIG_SETTINGS_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_SYSCONFIG_SETTINGS, NMSysconfigSettingsClass))

#define NM_SYSCONFIG_SETTINGS_UNMANAGED_SPECS "unmanaged-specs"
#define NM_SYSCONFIG_SETTINGS_HOSTNAME "hostname"
#define NM_SYSCONFIG_SETTINGS_CAN_MODIFY "can-modify"

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

NMSysconfigSettings *nm_sysconfig_settings_new (const char *plugins, GError **error);

/* Registers an exising connection with the settings service */
void nm_sysconfig_settings_add_connection (NMSysconfigSettings *settings,
                                           NMExportedConnection *connection,
                                           gboolean do_export);

void nm_sysconfig_settings_remove_connection (NMSysconfigSettings *settings,
                                              NMExportedConnection *connection,
                                              gboolean do_signal);

NMSystemConfigInterface *nm_sysconfig_settings_get_plugin (NMSysconfigSettings *self,
                                                           guint32 capability);

/* Adds a new connection from a hash of that connection's settings,
 * potentially saving the new connection to persistent storage.
 */
gboolean nm_sysconfig_settings_add_new_connection (NMSysconfigSettings *self,
                                                   GHashTable *hash,
                                                   GError **error);

const GSList *nm_sysconfig_settings_get_unmanaged_specs (NMSysconfigSettings *self);

char *nm_sysconfig_settings_get_hostname (NMSysconfigSettings *self);

GSList *nm_sysconfig_settings_list_connections (NMSysconfigSettings *self);

NMSysconfigConnection *nm_sysconfig_settings_get_connection_by_path (NMSysconfigSettings *self,
                                                                     const char *path);

#endif  /* __NM_SYSCONFIG_SETTINGS_H__ */
