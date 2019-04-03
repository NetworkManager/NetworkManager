/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
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
 * Copyright 2008 Novell, Inc.
 * Copyright 2009 - 2011 Red Hat, Inc.
 */

#ifndef NM_REMOTE_SETTINGS_H
#define NM_REMOTE_SETTINGS_H

#include <gio/gio.h>
#include <dbus/dbus-glib.h>
#include "nm-connection.h"
#include "nm-remote-connection.h"

G_BEGIN_DECLS

#define NM_TYPE_REMOTE_SETTINGS            (nm_remote_settings_get_type ())
#define NM_REMOTE_SETTINGS(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_REMOTE_SETTINGS, NMRemoteSettings))
#define NM_REMOTE_SETTINGS_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_REMOTE_SETTINGS, NMRemoteSettingsClass))
#define NM_IS_REMOTE_SETTINGS(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_REMOTE_SETTINGS))
#define NM_IS_REMOTE_SETTINGS_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_REMOTE_SETTINGS))
#define NM_REMOTE_SETTINGS_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_REMOTE_SETTINGS, NMRemoteSettingsClass))

/**
 * NMRemoteSettingsError:
 * @NM_REMOTE_SETTINGS_ERROR_UNKNOWN: unknown or unclassified error
 * @NM_REMOTE_SETTINGS_ERROR_CONNECTION_REMOVED: the #NMRemoteConnection object
 *   was removed before it was completely initialized
 * @NM_REMOTE_SETTINGS_ERROR_CONNECTION_UNAVAILABLE: the #NMRemoteConnection object
 *   is not visible or otherwise unreadable
 * @NM_REMOTE_SETTINGS_ERROR_SERVICE_UNAVAILABLE: NetworkManager is not running.
 *   (Since 0.9.10)
 *
 * Describes errors that may result from operations involving a #NMRemoteSettings.
 *
 **/
typedef enum {
	NM_REMOTE_SETTINGS_ERROR_UNKNOWN = 0,            /*< nick=UnknownError >*/
	NM_REMOTE_SETTINGS_ERROR_CONNECTION_REMOVED,     /*< nick=ConnectionRemoved >*/
	NM_REMOTE_SETTINGS_ERROR_CONNECTION_UNAVAILABLE, /*< nick=ConnectionUnavailable >*/
	NM_REMOTE_SETTINGS_ERROR_SERVICE_UNAVAILABLE,    /*< nick=ServiceUnavailable >*/
} NMRemoteSettingsError;

#define NM_REMOTE_SETTINGS_ERROR nm_remote_settings_error_quark ()
GQuark nm_remote_settings_error_quark (void);

#define NM_REMOTE_SETTINGS_BUS             "bus"
#define NM_REMOTE_SETTINGS_SERVICE_RUNNING "service-running"
#define NM_REMOTE_SETTINGS_HOSTNAME        "hostname"
#define NM_REMOTE_SETTINGS_CAN_MODIFY      "can-modify"

#define NM_REMOTE_SETTINGS_NEW_CONNECTION    "new-connection"
#define NM_REMOTE_SETTINGS_CONNECTIONS_READ  "connections-read"

typedef struct _NMRemoteSettings NMRemoteSettings;
typedef struct _NMRemoteSettingsClass NMRemoteSettingsClass;

typedef void (*NMRemoteSettingsAddConnectionFunc) (NMRemoteSettings *settings,
                                                   NMRemoteConnection *connection,
                                                   GError *error,
                                                   gpointer user_data);

typedef void (*NMRemoteSettingsLoadConnectionsFunc) (NMRemoteSettings *settings,
                                                     char **failures,
                                                     GError *error,
                                                     gpointer user_data);

typedef void (*NMRemoteSettingsSaveHostnameFunc) (NMRemoteSettings *settings,
                                                  GError *error,
                                                  gpointer user_data);

struct _NMRemoteSettings {
	GObject parent;
};

struct _NMRemoteSettingsClass {
	GObjectClass parent;

	/* Signals */
	void (*new_connection) (NMRemoteSettings *settings,
	                        NMRemoteConnection *connection);

	void (*connections_read) (NMRemoteSettings *settings);

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
	void (*_reserved5) (void);
	void (*_reserved6) (void);
};

GType nm_remote_settings_get_type (void);

NMRemoteSettings *nm_remote_settings_new (DBusGConnection *bus);

void              nm_remote_settings_new_async  (DBusGConnection      *bus,
                                                 GCancellable         *cancellable,
                                                 GAsyncReadyCallback   callback,
                                                 gpointer              user_data);
NMRemoteSettings *nm_remote_settings_new_finish (GAsyncResult         *result,
                                                 GError              **error);

GSList *nm_remote_settings_list_connections (NMRemoteSettings *settings);

NMRemoteConnection *nm_remote_settings_get_connection_by_id (NMRemoteSettings *settings,
                                                             const char *id);

NMRemoteConnection * nm_remote_settings_get_connection_by_path (NMRemoteSettings *settings,
                                                                const char *path);

NMRemoteConnection *nm_remote_settings_get_connection_by_uuid (NMRemoteSettings *settings,
                                                               const char *uuid);

gboolean nm_remote_settings_add_connection (NMRemoteSettings *settings,
                                            NMConnection *connection,
                                            NMRemoteSettingsAddConnectionFunc callback,
                                            gpointer user_data);

NM_AVAILABLE_IN_0_9_10
gboolean nm_remote_settings_add_connection_unsaved (NMRemoteSettings *settings,
                                                    NMConnection *connection,
                                                    NMRemoteSettingsAddConnectionFunc callback,
                                                    gpointer user_data);

NM_AVAILABLE_IN_0_9_10
gboolean nm_remote_settings_load_connections (NMRemoteSettings *settings,
                                              char **filenames,
                                              char ***failures,
                                              GError **error);

NM_AVAILABLE_IN_0_9_10
gboolean nm_remote_settings_reload_connections (NMRemoteSettings *settings,
                                                GError **error);

gboolean nm_remote_settings_save_hostname (NMRemoteSettings *settings,
                                           const char *hostname,
                                           NMRemoteSettingsSaveHostnameFunc callback,
                                           gpointer user_data);

G_END_DECLS

#endif /* NM_REMOTE_SETTINGS_H */
