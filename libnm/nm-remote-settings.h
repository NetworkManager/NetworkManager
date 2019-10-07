// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2008 Novell, Inc.
 * Copyright (C) 2009 - 2011 Red Hat, Inc.
 */

#ifndef __NM_REMOTE_SETTINGS_H__
#define __NM_REMOTE_SETTINGS_H__

#if !((NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_PRIVATE)
#error Cannot use this header.
#endif

#include "nm-object.h"
#include "nm-libnm-utils.h"

#define NM_TYPE_REMOTE_SETTINGS            (nm_remote_settings_get_type ())
#define NM_REMOTE_SETTINGS(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_REMOTE_SETTINGS, NMRemoteSettings))
#define NM_REMOTE_SETTINGS_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_REMOTE_SETTINGS, NMRemoteSettingsClass))
#define NM_IS_REMOTE_SETTINGS(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_REMOTE_SETTINGS))
#define NM_IS_REMOTE_SETTINGS_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_REMOTE_SETTINGS))
#define NM_REMOTE_SETTINGS_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_REMOTE_SETTINGS, NMRemoteSettingsClass))

#define NM_REMOTE_SETTINGS_CONNECTIONS     "connections"
#define NM_REMOTE_SETTINGS_HOSTNAME        "hostname"
#define NM_REMOTE_SETTINGS_CAN_MODIFY      "can-modify"

#define NM_REMOTE_SETTINGS_CONNECTION_ADDED   "connection-added"
#define NM_REMOTE_SETTINGS_CONNECTION_REMOVED "connection-removed"

typedef struct _NMRemoteSettings NMRemoteSettings;
typedef struct _NMRemoteSettingsClass NMRemoteSettingsClass;

/**
 * NMRemoteSettings:
 */
struct _NMRemoteSettings {
	NMObject parent;
};

struct _NMRemoteSettingsClass {
	NMObjectClass parent;

	void (*connection_added)   (NMRemoteSettings *settings,
	                            NMRemoteConnection *connection);
	void (*connection_removed) (NMRemoteSettings *settings,
	                            NMRemoteConnection *connection);
};

GType nm_remote_settings_get_type (void);

const GPtrArray    *nm_remote_settings_get_connections        (NMRemoteSettings *settings);

NMRemoteConnection *nm_remote_settings_get_connection_by_id   (NMRemoteSettings *settings,
                                                               const char *id);

NMRemoteConnection *nm_remote_settings_get_connection_by_path (NMRemoteSettings *settings,
                                                               const char *path);

NMRemoteConnection *nm_remote_settings_get_connection_by_uuid (NMRemoteSettings *settings,
                                                               const char *uuid);

typedef void (*NMRemoteSettingAddConnection2Callback) (NMRemoteSettings *self,
                                                       NMRemoteConnection *connection,
                                                       GVariant *results,
                                                       GError *error,
                                                       gpointer user_data);

void nm_remote_settings_add_connection2 (NMRemoteSettings *self,
                                         GVariant *settings,
                                         NMSettingsAddConnection2Flags flags,
                                         GVariant *args,
                                         gboolean ignore_out_result,
                                         GCancellable *cancellable,
                                         NMRemoteSettingAddConnection2Callback callback,
                                         gpointer user_data);

void     nm_remote_settings_save_hostname_async  (NMRemoteSettings *settings,
                                                  const char *hostname,
                                                  GCancellable *cancellable,
                                                  GAsyncReadyCallback callback,
                                                  gpointer user_data);
gboolean nm_remote_settings_save_hostname_finish (NMRemoteSettings *settings,
                                                  GAsyncResult *result,
                                                  GError **error);

#endif /* __NM_REMOTE_SETTINGS_H__ */
