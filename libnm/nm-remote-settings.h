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

typedef struct {
	NMRemoteConnection *connection;
	GVariant *extra_results;
} NMAddConnectionResultData;

void nm_add_connection_result_data_free (NMAddConnectionResultData *result_data);

NM_AUTO_DEFINE_FCN0 (NMAddConnectionResultData *, _nm_auto_free_add_connection_result_data, nm_add_connection_result_data_free)
#define nm_auto_free_add_connection_result_data nm_auto (_nm_auto_free_add_connection_result_data)

void nm_remote_settings_wait_for_connection (NMRemoteSettings *settings,
                                             const char *connection_path,
                                             GVariant *extra_results_take,
                                             GTask *task_take);

#endif /* __NM_REMOTE_SETTINGS_H__ */
