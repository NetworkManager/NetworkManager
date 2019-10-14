// SPDX-License-Identifier: GPL-2.0+
/*
 * Søren Sandmann <sandmann@daimi.au.dk>
 * Dan Williams <dcbw@redhat.com>
 * Tambet Ingo <tambet@gmail.com>
 * Copyright (C) 2007 - 2011 Red Hat, Inc.
 * Copyright (C) 2008 Novell, Inc.
 */

#ifndef __NM_SETTINGS_H__
#define __NM_SETTINGS_H__

#include "nm-connection.h"

#include "nm-settings-connection.h"

#define NM_TYPE_SETTINGS            (nm_settings_get_type ())
#define NM_SETTINGS(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTINGS, NMSettings))
#define NM_SETTINGS_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_SETTINGS, NMSettingsClass))
#define NM_IS_SETTINGS(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTINGS))
#define NM_IS_SETTINGS_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_SETTINGS))
#define NM_SETTINGS_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_SETTINGS, NMSettingsClass))

#define NM_SETTINGS_UNMANAGED_SPECS  "unmanaged-specs"
#define NM_SETTINGS_HOSTNAME         "hostname"
#define NM_SETTINGS_CAN_MODIFY       "can-modify"
#define NM_SETTINGS_CONNECTIONS      "connections"
#define NM_SETTINGS_STARTUP_COMPLETE "startup-complete"

#define NM_SETTINGS_SIGNAL_CONNECTION_ADDED              "connection-added"
#define NM_SETTINGS_SIGNAL_CONNECTION_UPDATED            "connection-updated"
#define NM_SETTINGS_SIGNAL_CONNECTION_REMOVED            "connection-removed"
#define NM_SETTINGS_SIGNAL_CONNECTION_FLAGS_CHANGED      "connection-flags-changed"

/**
 * NMConnectionFilterFunc:
 * @settings: The #NMSettings requesting the filtering
 * @connection: the connection to be filtered
 * @func_data: the caller-provided data pointer
 *
 * Returns: %TRUE to allow the connection, %FALSE to ignore it
 */
typedef gboolean (*NMSettingsConnectionFilterFunc) (NMSettings *settings,
                                                    NMSettingsConnection *connection,
                                                    gpointer func_data);

typedef struct _NMSettingsClass NMSettingsClass;

typedef void (*NMSettingsSetHostnameCb) (const char *name, gboolean result, gpointer user_data);

GType nm_settings_get_type (void);

NMSettings *nm_settings_get (void);
#define NM_SETTINGS_GET (nm_settings_get ())

NMSettings *nm_settings_new (void);

gboolean nm_settings_start (NMSettings *self, GError **error);

typedef void (*NMSettingsAddCallback) (NMSettings *settings,
                                       NMSettingsConnection *connection,
                                       GError *error,
                                       GDBusMethodInvocation *context,
                                       NMAuthSubject *subject,
                                       gpointer user_data);

void nm_settings_add_connection_dbus (NMSettings *self,
                                      NMConnection *connection,
                                      NMSettingsConnectionPersistMode persist_mode,
                                      NMSettingsConnectionAddReason add_reason,
                                      NMSettingsConnectionIntFlags sett_flags,
                                      NMAuthSubject *subject,
                                      GDBusMethodInvocation *context,
                                      NMSettingsAddCallback callback,
                                      gpointer user_data);

NMSettingsConnection *const*nm_settings_get_connections (NMSettings *settings, guint *out_len);

NMSettingsConnection **nm_settings_get_connections_clone (NMSettings *self,
                                                          guint *out_len,
                                                          NMSettingsConnectionFilterFunc func,
                                                          gpointer func_data,
                                                          GCompareDataFunc sort_compare_func,
                                                          gpointer sort_data);

gboolean nm_settings_add_connection (NMSettings *settings,
                                     NMConnection *connection,
                                     NMSettingsConnectionPersistMode persist_mode,
                                     NMSettingsConnectionAddReason add_reason,
                                     NMSettingsConnectionIntFlags sett_flags,
                                     NMSettingsConnection **out_sett_conn,
                                     GError **error);

gboolean nm_settings_update_connection (NMSettings *self,
                                        NMSettingsConnection *sett_conn,
                                        NMConnection *new_connection,
                                        NMSettingsConnectionPersistMode persist_mode,
                                        NMSettingsConnectionIntFlags sett_flags,
                                        NMSettingsConnectionIntFlags sett_mask,
                                        NMSettingsConnectionUpdateReason update_reason,
                                        const char *log_context_name,
                                        GError **error);

void nm_settings_delete_connection (NMSettings *self,
                                    NMSettingsConnection *sett_conn,
                                    gboolean allow_add_to_no_auto_default);

NMSettingsConnection *nm_settings_get_connection_by_path (NMSettings *settings,
                                                          const char *path);

NMSettingsConnection *nm_settings_get_connection_by_uuid (NMSettings *settings,
                                                          const char *uuid);

const char *nm_settings_get_dbus_path_for_uuid (NMSettings *self,
                                                const char *uuid);

gboolean nm_settings_has_connection (NMSettings *self, NMSettingsConnection *connection);

const GSList *nm_settings_get_unmanaged_specs (NMSettings *self);

void nm_settings_device_added (NMSettings *self, NMDevice *device);

void nm_settings_device_removed (NMSettings *self, NMDevice *device, gboolean quitting);

const char *nm_settings_get_startup_complete_blocked_reason (NMSettings *self);

void nm_settings_kf_db_write (NMSettings *settings);

#endif  /* __NM_SETTINGS_H__ */
