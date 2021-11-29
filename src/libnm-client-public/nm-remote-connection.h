/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2011 Red Hat, Inc.
 */

#ifndef __NM_REMOTE_CONNECTION_H__
#define __NM_REMOTE_CONNECTION_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-object.h"

G_BEGIN_DECLS

#define NM_TYPE_REMOTE_CONNECTION (nm_remote_connection_get_type())
#define NM_REMOTE_CONNECTION(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_REMOTE_CONNECTION, NMRemoteConnection))
#define NM_REMOTE_CONNECTION_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_REMOTE_CONNECTION, NMRemoteConnectionClass))
#define NM_IS_REMOTE_CONNECTION(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_REMOTE_CONNECTION))
#define NM_IS_REMOTE_CONNECTION_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_REMOTE_CONNECTION))
#define NM_REMOTE_CONNECTION_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_REMOTE_CONNECTION, NMRemoteConnectionClass))

/* Properties */
#define NM_REMOTE_CONNECTION_DBUS_CONNECTION "dbus-connection"
#define NM_REMOTE_CONNECTION_PATH            "path"
#define NM_REMOTE_CONNECTION_UNSAVED         "unsaved"
#define NM_REMOTE_CONNECTION_FLAGS           "flags"
#define NM_REMOTE_CONNECTION_FILENAME        "filename"
#define NM_REMOTE_CONNECTION_VISIBLE         "visible"

/**
 * NMRemoteConnection:
 */
typedef struct _NMRemoteConnectionClass NMRemoteConnectionClass;

GType nm_remote_connection_get_type(void);

NM_AVAILABLE_IN_1_12
void nm_remote_connection_update2(NMRemoteConnection    *connection,
                                  GVariant              *settings,
                                  NMSettingsUpdate2Flags flags,
                                  GVariant              *args,
                                  GCancellable          *cancellable,
                                  GAsyncReadyCallback    callback,
                                  gpointer               user_data);
NM_AVAILABLE_IN_1_12
GVariant *nm_remote_connection_update2_finish(NMRemoteConnection *connection,
                                              GAsyncResult       *result,
                                              GError            **error);

_NM_DEPRECATED_SYNC_METHOD
gboolean nm_remote_connection_commit_changes(NMRemoteConnection *connection,
                                             gboolean            save_to_disk,
                                             GCancellable       *cancellable,
                                             GError            **error);

void     nm_remote_connection_commit_changes_async(NMRemoteConnection *connection,
                                                   gboolean            save_to_disk,
                                                   GCancellable       *cancellable,
                                                   GAsyncReadyCallback callback,
                                                   gpointer            user_data);
gboolean nm_remote_connection_commit_changes_finish(NMRemoteConnection *connection,
                                                    GAsyncResult       *result,
                                                    GError            **error);

_NM_DEPRECATED_SYNC_METHOD
gboolean nm_remote_connection_save(NMRemoteConnection *connection,
                                   GCancellable       *cancellable,
                                   GError            **error);

void     nm_remote_connection_save_async(NMRemoteConnection *connection,
                                         GCancellable       *cancellable,
                                         GAsyncReadyCallback callback,
                                         gpointer            user_data);
gboolean nm_remote_connection_save_finish(NMRemoteConnection *connection,
                                          GAsyncResult       *result,
                                          GError            **error);

_NM_DEPRECATED_SYNC_METHOD
gboolean nm_remote_connection_delete(NMRemoteConnection *connection,
                                     GCancellable       *cancellable,
                                     GError            **error);

void     nm_remote_connection_delete_async(NMRemoteConnection *connection,
                                           GCancellable       *cancellable,
                                           GAsyncReadyCallback callback,
                                           gpointer            user_data);
gboolean nm_remote_connection_delete_finish(NMRemoteConnection *connection,
                                            GAsyncResult       *result,
                                            GError            **error);

_NM_DEPRECATED_SYNC_METHOD
GVariant *nm_remote_connection_get_secrets(NMRemoteConnection *connection,
                                           const char         *setting_name,
                                           GCancellable       *cancellable,
                                           GError            **error);

void      nm_remote_connection_get_secrets_async(NMRemoteConnection *connection,
                                                 const char         *setting_name,
                                                 GCancellable       *cancellable,
                                                 GAsyncReadyCallback callback,
                                                 gpointer            user_data);
GVariant *nm_remote_connection_get_secrets_finish(NMRemoteConnection *connection,
                                                  GAsyncResult       *result,
                                                  GError            **error);

gboolean nm_remote_connection_get_unsaved(NMRemoteConnection *connection);

NM_AVAILABLE_IN_1_12
NMSettingsConnectionFlags nm_remote_connection_get_flags(NMRemoteConnection *connection);

NM_AVAILABLE_IN_1_12
const char *nm_remote_connection_get_filename(NMRemoteConnection *connection);

gboolean nm_remote_connection_get_visible(NMRemoteConnection *connection);

G_END_DECLS

#endif /* __NM_REMOTE_CONNECTION__ */
