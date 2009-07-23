/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2009 Red Hat, Inc.
 */

#ifndef NM_SETTINGS_SYSTEM_INTERFACE_H
#define NM_SETTINGS_SYSTEM_INTERFACE_H

#include <glib-object.h>

#include "NetworkManager.h"

#define NM_TYPE_SETTINGS_SYSTEM_INTERFACE               (nm_settings_system_interface_get_type ())
#define NM_SETTINGS_SYSTEM_INTERFACE(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTINGS_SYSTEM_INTERFACE, NMSettingsSystemInterface))
#define NM_IS_SETTINGS_SYSTEM_INTERFACE(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTINGS_SYSTEM_INTERFACE))
#define NM_SETTINGS_SYSTEM_INTERFACE_GET_INTERFACE(obj) (G_TYPE_INSTANCE_GET_INTERFACE ((obj), NM_TYPE_SETTINGS_SYSTEM_INTERFACE, NMSettingsSystemInterface))

#define NM_SETTINGS_SYSTEM_INTERFACE_HOSTNAME          "hostname"
#define NM_SETTINGS_SYSTEM_INTERFACE_CAN_MODIFY        "can-modify"

typedef enum {
	NM_SETTINGS_SYSTEM_INTERFACE_PROP_FIRST = 0x1000,

	NM_SETTINGS_SYSTEM_INTERFACE_PROP_HOSTNAME = NM_SETTINGS_SYSTEM_INTERFACE_PROP_FIRST,
	NM_SETTINGS_SYSTEM_INTERFACE_PROP_CAN_MODIFY
} NMSettingsSystemInterfaceProp;


typedef struct _NMSettingsSystemInterface NMSettingsSystemInterface;


typedef void (*NMSettingsSystemSaveHostnameFunc) (NMSettingsSystemInterface *settings,
                                                  GError *error,
                                                  gpointer user_data);

struct _NMSettingsSystemInterface {
	GTypeInterface g_iface;

	/* Methods */
	gboolean (*save_hostname) (NMSettingsSystemInterface *settings,
	                           const char *hostname,
	                           NMSettingsSystemSaveHostnameFunc callback,
	                           gpointer user_data);
};

GType nm_settings_system_interface_get_type (void);

gboolean nm_settings_system_interface_save_hostname (NMSettingsSystemInterface *settings,
                                                     const char *hostname,
                                                     NMSettingsSystemSaveHostnameFunc callback,
                                                     gpointer user_data);

#endif /* NM_SETTINGS_SYSTEM_INTERFACE_H */
