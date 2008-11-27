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
 * Copyright (C) 2007 - 2008 Red Hat, Inc.
 */

#ifndef __NM_SETTINGS_H__
#define __NM_SETTINGS_H__

#include <glib-object.h>
#include <dbus/dbus-glib.h>

#include <nm-connection.h>

G_BEGIN_DECLS

typedef enum
{
	NM_SETTINGS_ERROR_INVALID_CONNECTION = 0,
	NM_SETTINGS_ERROR_READ_ONLY_CONNECTION,
	NM_SETTINGS_ERROR_INTERNAL_ERROR,
	NM_SETTINGS_ERROR_SECRETS_UNAVAILABLE,
	NM_SETTINGS_ERROR_SECRETS_REQUEST_CANCELED
} NMSettingsError;

#define NM_SETTINGS_ERROR (nm_settings_error_quark ())
GQuark nm_settings_error_quark (void);


#define NM_TYPE_EXPORTED_CONNECTION            (nm_exported_connection_get_type ())
#define NM_EXPORTED_CONNECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_EXPORTED_CONNECTION, NMExportedConnection))
#define NM_EXPORTED_CONNECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_EXPORTED_CONNECTION, NMExportedConnectionClass))
#define NM_IS_EXPORTED_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_EXPORTED_CONNECTION))
#define NM_IS_EXPORTED_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_EXPORTED_CONNECTION))
#define NM_EXPORTED_CONNECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_EXPORTED_CONNECTION, NMExportedConnectionClass))

#define NM_EXPORTED_CONNECTION_CONNECTION "connection"

#define NM_EXPORTED_CONNECTION_DBUS_METHOD_INVOCATION "nm-exported-connection-dbus-method-invocation"

typedef struct {
	GObject parent;
} NMExportedConnection;

typedef struct {
	GObjectClass parent_class;

	/* virtual methods */
	GHashTable * (*get_settings) (NMExportedConnection *connection);

	/* service_get_secrets is used in a D-Bus service (like the system settings
	 * service) to respond to GetSecrets requests from clients.
	 */
	void         (*service_get_secrets) (NMExportedConnection *connection,
	                                     const gchar *setting_name,
	                                     const gchar **hints,
	                                     gboolean request_new,
	                                     DBusGMethodInvocation *context);

	gboolean (*update) (NMExportedConnection *connection,
	                    GHashTable *new_settings,
	                    GError **err);

	gboolean (*do_delete) (NMExportedConnection *connection,
	                    GError **err);

	/* signals */
	void (*updated) (NMExportedConnection *connection, GHashTable *settings);
	void (*removed) (NMExportedConnection *connection);
} NMExportedConnectionClass;

GType nm_exported_connection_get_type (void);

NMExportedConnection *nm_exported_connection_new (NMConnection *wrapped);

void nm_exported_connection_register_object (NMExportedConnection *connection,
                                             NMConnectionScope scope,
                                             DBusGConnection *dbus_connection);

NMConnection *nm_exported_connection_get_connection (NMExportedConnection *connection);

gboolean nm_exported_connection_update (NMExportedConnection *connection,
								GHashTable *new_settings,
								GError **err);

gboolean nm_exported_connection_delete (NMExportedConnection *connection,
								GError **err);

void nm_exported_connection_signal_updated (NMExportedConnection *connection,
								    GHashTable *new_settings);

void nm_exported_connection_signal_removed (NMExportedConnection *connection);



#define NM_TYPE_SETTINGS            (nm_settings_get_type ())
#define NM_SETTINGS(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTINGS, NMSettings))
#define NM_SETTINGS_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTINGS, NMSettingsClass))
#define NM_IS_SETTINGS(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTINGS))
#define NM_IS_SETTINGS_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_SETTINGS))
#define NM_SETTINGS_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTINGS, NMSettingsClass))

typedef struct {
	GObject parent;
} NMSettings;

typedef struct {
	GObjectClass parent_class;

	/* virtual methods */
	/* Returns a list of NMExportedConnections. Caller should free the list. */
	GSList * (*list_connections) (NMSettings *settings);

	/* signals */
	void (* new_connection) (NMSettings *settings, NMExportedConnection *connection);
} NMSettingsClass;

GType nm_settings_get_type (void);

GSList *nm_settings_list_connections (NMSettings *settings);

void  nm_settings_signal_new_connection (NMSettings *settings, NMExportedConnection *connection);


G_END_DECLS

#endif
