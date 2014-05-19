/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service
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
 * (C) Copyright 2008 Novell, Inc.
 * (C) Copyright 2008 - 2013 Red Hat, Inc.
 */

#ifndef NM_SETTINGS_CONNECTION_H
#define NM_SETTINGS_CONNECTION_H

#include <nm-connection.h>
#include "nm-settings-flags.h"
#include "nm-auth-subject.h"
#include <net/ethernet.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTINGS_CONNECTION            (nm_settings_connection_get_type ())
#define NM_SETTINGS_CONNECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTINGS_CONNECTION, NMSettingsConnection))
#define NM_SETTINGS_CONNECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTINGS_CONNECTION, NMSettingsConnectionClass))
#define NM_IS_SETTINGS_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTINGS_CONNECTION))
#define NM_IS_SETTINGS_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTINGS_CONNECTION))
#define NM_SETTINGS_CONNECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTINGS_CONNECTION, NMSettingsConnectionClass))

/* Signals */
#define NM_SETTINGS_CONNECTION_UPDATED "updated"
#define NM_SETTINGS_CONNECTION_REMOVED "removed"
#define NM_SETTINGS_CONNECTION_GET_SECRETS "get-secrets"
#define NM_SETTINGS_CONNECTION_CANCEL_SECRETS "cancel-secrets"

/* Emitted when connection is changed by a user action */
#define NM_SETTINGS_CONNECTION_UPDATED_BY_USER "updated-by-user"

/* Properties */
#define NM_SETTINGS_CONNECTION_VISIBLE "visible"
#define NM_SETTINGS_CONNECTION_UNSAVED "unsaved"

typedef struct _NMSettingsConnection NMSettingsConnection;
typedef struct _NMSettingsConnectionClass NMSettingsConnectionClass;

typedef void (*NMSettingsConnectionCommitFunc) (NMSettingsConnection *connection,
                                                GError *error,
                                                gpointer user_data);

typedef void (*NMSettingsConnectionDeleteFunc) (NMSettingsConnection *connection,
                                                GError *error,
                                                gpointer user_data);

struct _NMSettingsConnection {
	NMConnection parent;
};

struct _NMSettingsConnectionClass {
	NMConnectionClass parent;

	/* virtual methods */
	void (*commit_changes) (NMSettingsConnection *connection,
	                        NMSettingsConnectionCommitFunc callback,
	                        gpointer user_data);

	void (*delete) (NMSettingsConnection *connection,
	                NMSettingsConnectionDeleteFunc callback,
	                gpointer user_data);

	gboolean (*supports_secrets) (NMSettingsConnection *connection,
	                              const char *setting_name);
};

GType nm_settings_connection_get_type (void);

void nm_settings_connection_commit_changes (NMSettingsConnection *connection,
                                            NMSettingsConnectionCommitFunc callback,
                                            gpointer user_data);

gboolean nm_settings_connection_replace_settings (NMSettingsConnection *self,
                                                  NMConnection *new_connection,
                                                  gboolean update_unsaved,
                                                  GError **error);

void nm_settings_connection_replace_and_commit (NMSettingsConnection *self,
                                                NMConnection *new_connection,
                                                NMSettingsConnectionCommitFunc callback,
                                                gpointer user_data);

void nm_settings_connection_delete (NMSettingsConnection *connection,
                                    NMSettingsConnectionDeleteFunc callback,
                                    gpointer user_data);

typedef void (*NMSettingsConnectionSecretsFunc) (NMSettingsConnection *connection,
                                                 guint32 call_id,
                                                 const char *agent_username,
                                                 const char *setting_name,
                                                 GError *error,
                                                 gpointer user_data);

guint32 nm_settings_connection_get_secrets (NMSettingsConnection *connection,
                                            NMAuthSubject *subject,
                                            const char *setting_name,
                                            NMSettingsGetSecretsFlags flags,
                                            const char **hints,
                                            NMSettingsConnectionSecretsFunc callback,
                                            gpointer callback_data,
                                            GError **error);

void nm_settings_connection_cancel_secrets (NMSettingsConnection *connection,
                                            guint32 call_id);

gboolean nm_settings_connection_is_visible (NMSettingsConnection *self);

void nm_settings_connection_recheck_visibility (NMSettingsConnection *self);

gboolean nm_settings_connection_check_permission (NMSettingsConnection *self,
                                                  const char *permission);

void nm_settings_connection_signal_remove (NMSettingsConnection *self);

gboolean nm_settings_connection_get_unsaved (NMSettingsConnection *self);

gboolean nm_settings_connection_get_timestamp (NMSettingsConnection *connection,
                                               guint64 *out_timestamp);

void nm_settings_connection_update_timestamp (NMSettingsConnection *connection,
                                              guint64 timestamp,
                                              gboolean flush_to_disk);

void nm_settings_connection_read_and_fill_timestamp (NMSettingsConnection *connection);

GSList *nm_settings_connection_get_seen_bssids (NMSettingsConnection *connection);

gboolean nm_settings_connection_has_seen_bssid (NMSettingsConnection *connection,
                                                const struct ether_addr *bssid);

void nm_settings_connection_add_seen_bssid (NMSettingsConnection *connection,
                                            const struct ether_addr *seen_bssid);

void nm_settings_connection_read_and_fill_seen_bssids (NMSettingsConnection *connection);

int nm_settings_connection_get_autoconnect_retries (NMSettingsConnection *connection);
void nm_settings_connection_set_autoconnect_retries (NMSettingsConnection *connection,
                                                     int retries);
void nm_settings_connection_reset_autoconnect_retries (NMSettingsConnection *connection);

gint32 nm_settings_connection_get_autoconnect_retry_time (NMSettingsConnection *connection);

NMDeviceStateReason nm_settings_connection_get_autoconnect_blocked_reason (NMSettingsConnection *connection);
void nm_settings_connection_set_autoconnect_blocked_reason (NMSettingsConnection *connection,
                                                            NMDeviceStateReason reason);

gboolean nm_settings_connection_can_autoconnect (NMSettingsConnection *connection);

void     nm_settings_connection_set_nm_generated (NMSettingsConnection *connection);
gboolean nm_settings_connection_get_nm_generated (NMSettingsConnection *connection);

G_END_DECLS

#endif /* NM_SETTINGS_CONNECTION_H */
