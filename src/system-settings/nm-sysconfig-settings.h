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
#include <nm-settings-service.h>

#include "nm-sysconfig-connection.h"
#include "nm-system-config-interface.h"
#include "nm-device.h"

#define NM_TYPE_SYSCONFIG_SETTINGS            (nm_sysconfig_settings_get_type ())
#define NM_SYSCONFIG_SETTINGS(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SYSCONFIG_SETTINGS, NMSysconfigSettings))
#define NM_SYSCONFIG_SETTINGS_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_SYSCONFIG_SETTINGS, NMSysconfigSettingsClass))
#define NM_IS_SYSCONFIG_SETTINGS(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SYSCONFIG_SETTINGS))
#define NM_IS_SYSCONFIG_SETTINGS_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_SYSCONFIG_SETTINGS))
#define NM_SYSCONFIG_SETTINGS_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_SYSCONFIG_SETTINGS, NMSysconfigSettingsClass))

#define NM_SYSCONFIG_SETTINGS_UNMANAGED_SPECS "unmanaged-specs"

typedef struct {
	NMSettingsService parent_instance;
} NMSysconfigSettings;

typedef struct {
	NMSettingsServiceClass parent_class;

	/* Signals */
	void (*properties_changed) (NMSysconfigSettings *self, GHashTable *properties);
} NMSysconfigSettingsClass;

GType nm_sysconfig_settings_get_type (void);

NMSysconfigSettings *nm_sysconfig_settings_new (const char *config_file,
                                                const char *plugins,
                                                DBusGConnection *bus,
                                                GError **error);

const GSList *nm_sysconfig_settings_get_unmanaged_specs (NMSysconfigSettings *self);

char *nm_sysconfig_settings_get_hostname (NMSysconfigSettings *self);

void nm_sysconfig_settings_device_added (NMSysconfigSettings *self, NMDevice *device);

void nm_sysconfig_settings_device_removed (NMSysconfigSettings *self, NMDevice *device);

#endif  /* __NM_SYSCONFIG_SETTINGS_H__ */
