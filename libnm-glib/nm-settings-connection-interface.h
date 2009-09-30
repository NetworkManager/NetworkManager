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
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2009 Red Hat, Inc.
 */

#ifndef __NM_SETTINGS_CONNECTION_INTERFACE_H__
#define __NM_SETTINGS_CONNECTION_INTERFACE_H__

#include <glib-object.h>
#include <dbus/dbus-glib.h>

#include <nm-connection.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTINGS_CONNECTION_INTERFACE               (nm_settings_connection_interface_get_type ())
#define NM_SETTINGS_CONNECTION_INTERFACE(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTINGS_CONNECTION_INTERFACE, NMSettingsConnectionInterface))
#define NM_IS_SETTINGS_CONNECTION_INTERFACE(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTINGS_CONNECTION_INTERFACE))
#define NM_SETTINGS_CONNECTION_INTERFACE_GET_INTERFACE(obj) (G_TYPE_INSTANCE_GET_INTERFACE ((obj), NM_TYPE_SETTINGS_CONNECTION_INTERFACE, NMSettingsConnectionInterface))

#define NM_SETTINGS_CONNECTION_INTERFACE_UPDATED               "updated"
#define NM_SETTINGS_CONNECTION_INTERFACE_REMOVED               "removed"

typedef struct _NMSettingsConnectionInterface NMSettingsConnectionInterface;

typedef void (*NMSettingsConnectionInterfaceUpdateFunc) (NMSettingsConnectionInterface *connection,
                                                         GError *error,
                                                         gpointer user_data);

typedef void (*NMSettingsConnectionInterfaceDeleteFunc) (NMSettingsConnectionInterface *connection,
                                                         GError *error,
                                                         gpointer user_data);

typedef void (*NMSettingsConnectionInterfaceGetSecretsFunc) (NMSettingsConnectionInterface *connection,
                                                             GHashTable *secrets,
                                                             GError *error,
                                                             gpointer user_data);

struct _NMSettingsConnectionInterface {
	GTypeInterface g_iface;

	/* Methods */
	gboolean (*update) (NMSettingsConnectionInterface *connection,
	                    NMSettingsConnectionInterfaceUpdateFunc callback,
	                    gpointer user_data);

	gboolean (*delete) (NMSettingsConnectionInterface *connection,
	                    NMSettingsConnectionInterfaceDeleteFunc callback,
	                    gpointer user_data);

	gboolean (*get_secrets) (NMSettingsConnectionInterface *connection,
	                         const char *setting_name,
                             const char **hints,
                             gboolean request_new,
                             NMSettingsConnectionInterfaceGetSecretsFunc callback,
                             gpointer user_data);

	void (*emit_updated) (NMSettingsConnectionInterface *connection);

	/* Signals */
	/* 'new_settings' hash should *not* contain secrets */
	void (*updated) (NMSettingsConnectionInterface *connection,
	                 GHashTable *new_settings);

	void (*removed) (NMSettingsConnectionInterface *connection);

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
	void (*_reserved5) (void);
	void (*_reserved6) (void);
};

GType nm_settings_connection_interface_get_type (void);

gboolean nm_settings_connection_interface_update (NMSettingsConnectionInterface *connection,
                                                  NMSettingsConnectionInterfaceUpdateFunc callback,
                                                  gpointer user_data);

gboolean nm_settings_connection_interface_delete (NMSettingsConnectionInterface *connection,
                                                  NMSettingsConnectionInterfaceDeleteFunc callback,
                                                  gpointer user_data);

gboolean nm_settings_connection_interface_get_secrets (NMSettingsConnectionInterface *connection,
                                                       const char *setting_name,
                                                       const char **hints,
                                                       gboolean request_new,
                                                       NMSettingsConnectionInterfaceGetSecretsFunc callback,
                                                       gpointer user_data);

void nm_settings_connection_interface_emit_updated (NMSettingsConnectionInterface *connection);

G_END_DECLS

#endif  /* __NM_SETTINGS_CONNECTION_INTERFACE_H__ */

