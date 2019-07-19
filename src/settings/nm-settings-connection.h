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

#ifndef __NETWORKMANAGER_SETTINGS_CONNECTION_H__
#define __NETWORKMANAGER_SETTINGS_CONNECTION_H__

#include "nm-dbus-object.h"
#include "nm-connection.h"

#include "nm-settings-storage.h"

/*****************************************************************************/

typedef enum {

	NM_SETTINGS_CONNECTION_ADD_REASON_NONE                         = 0,

	NM_SETTINGS_CONNECTION_ADD_REASON_BLOCK_AUTOCONNECT            = (1u << 0),

} NMSettingsConnectionAddReason;

typedef enum {

	NM_SETTINGS_CONNECTION_UPDATE_REASON_NONE                      = 0,

	/* with persist-mode != NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY_ONLY, and
	 * update tries to update the profile on disk (which can always fail).
	 * In some cases we want to ignore such failure and proceed. For example,
	 * when we receive secrets from a secret-agent, we want to update the connection
	 * at all cost and ignore failures to write them to disk. */
	NM_SETTINGS_CONNECTION_UPDATE_REASON_IGNORE_PERSIST_FAILURE    = (1u << 0),

	/* When updating the profile, force renaming the file on disk. That matters
	 * only for keyfile plugin. Keyfile prefers a filename based on connection.id.
	 * When the connection.id changes we might want to rename the file on disk
	 * (that is, don't overwrite the existing file, but delete it and write it
	 * with the new name).
	 * This flag forces such rename. */
	NM_SETTINGS_CONNECTION_UPDATE_REASON_FORCE_RENAME              = (1u << 1),

	/* Usually, changing a profile that is currently active does not immediately
	 * reapply the changes. The exception are connection.zone and connection.metered
	 * properties. When this flag is set, then these two properties are reapplied
	 * right away.
	 *
	 * See also %NM_SETTINGS_UPDATE2_FLAG_NO_REAPPLY flag, to prevent partial reapply
	 * during Update2(). */
	NM_SETTINGS_CONNECTION_UPDATE_REASON_REAPPLY_PARTIAL           = (1u << 2),

	NM_SETTINGS_CONNECTION_UPDATE_REASON_CLEAR_SYSTEM_SECRETS      = (1u << 3),
	NM_SETTINGS_CONNECTION_UPDATE_REASON_RESET_SYSTEM_SECRETS      = (1u << 4),

	NM_SETTINGS_CONNECTION_UPDATE_REASON_CLEAR_AGENT_SECRETS       = (1u << 5),
	NM_SETTINGS_CONNECTION_UPDATE_REASON_RESET_AGENT_SECRETS       = (1u << 6),

	/* if a profile was greated as default-wired connection for a device, then
	 * when the user modifies it via D-Bus, the profile should become persisted
	 * to disk and it the purpose why the profile was created should be forgotten. */
	NM_SETTINGS_CONNECTION_UPDATE_REASON_CLEAR_DEFAULT_WIRED       = (1u << 7),

	NM_SETTINGS_CONNECTION_UPDATE_REASON_BLOCK_AUTOCONNECT         = (1u << 8),

} NMSettingsConnectionUpdateReason;

typedef enum {

	/* if the profile is in-memory, update it in-memory and keep it.
	 * if the profile is on-disk, update it on-disk, and keep it. */
	NM_SETTINGS_CONNECTION_PERSIST_MODE_KEEP,

	/* persist to disk. If the profile is currently in-memory, remove
	 * it from /run. Depending on the shadowed-storage, the pre-existing
	 * file is reused when moving the storage.
	 *
	 * Corresponds to %NM_SETTINGS_UPDATE2_FLAG_TO_DISK. */
	NM_SETTINGS_CONNECTION_PERSIST_MODE_TO_DISK,

	/* Update in-memory (i.e. persist to /run). If the profile is currently on disk,
	 * then a reference to the profile is remembered as "shadowed-storage".
	 * Later, when storing again to persistant storage, the shawowed-storage is
	 * updated. When deleting the profile, the shadowed-storage is also deleted
	 * from disk.
	 *
	 * Corresponds to %NM_SETTINGS_UPDATE2_FLAG_IN_MEMORY. */
	NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY,

	/* Update in-memory (i.e. persist to /run). This is almost like
	 * %NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY, except the in-memory profile
	 * remembers not to own the shadowed-storage ("shadowed-owned").
	 * The diffrence is that when deleting the in-memory profile, the original
	 * profile is not deleted but instead the nmmeta tombstone remembers the
	 * shadowed-storage and re-used it when re-adding the profile.
	 *
	 * Corresponds to %NM_SETTINGS_UPDATE2_FLAG_IN_MEMORY_DETACHED. */
	NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY_DETACHED,

	/* Update in-memory (i.e. persist to /run). If the profile is currently on disk,
	 * delete it from disk.
	 *
	 * If the profile is in-memory and has a shadowed-storage, the original profile
	 * will be deleted from disk.
	 *
	 * Corresponds to %NM_SETTINGS_UPDATE2_FLAG_IN_MEMORY_ONLY. */
	NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY_ONLY,

	/* This only updates the connection in-memory. Note that "in-memory" above
	 * means to write to keyfile in /run. This mode really means to not notify the
	 * settings plugin about the change. This should be only used for updating
	 * secrets.
	 */
	NM_SETTINGS_CONNECTION_PERSIST_MODE_NO_PERSIST,

} NMSettingsConnectionPersistMode;

/*****************************************************************************/

#define NM_TYPE_SETTINGS_CONNECTION            (nm_settings_connection_get_type ())
#define NM_SETTINGS_CONNECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTINGS_CONNECTION, NMSettingsConnection))
#define NM_SETTINGS_CONNECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTINGS_CONNECTION, NMSettingsConnectionClass))
#define NM_IS_SETTINGS_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTINGS_CONNECTION))
#define NM_IS_SETTINGS_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTINGS_CONNECTION))
#define NM_SETTINGS_CONNECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTINGS_CONNECTION, NMSettingsConnectionClass))

#define NM_SETTINGS_CONNECTION_GET_SECRETS "get-secrets"
#define NM_SETTINGS_CONNECTION_CANCEL_SECRETS "cancel-secrets"
#define NM_SETTINGS_CONNECTION_UPDATED_INTERNAL "updated-internal"
#define NM_SETTINGS_CONNECTION_FLAGS_CHANGED    "flags-changed"

/* Properties */
#define NM_SETTINGS_CONNECTION_UNSAVED  "unsaved"
#define NM_SETTINGS_CONNECTION_FLAGS    "flags"
#define NM_SETTINGS_CONNECTION_FILENAME "filename"

/**
 * NMSettingsConnectionIntFlags:
 * @NM_SETTINGS_CONNECTION_INT_FLAGS_NONE: no flag set
 * @NM_SETTINGS_CONNECTION_INT_FLAGS_UNSAVED: the connection is not saved to disk.
 *  See also #NM_SETTINGS_CONNECTION_FLAG_UNSAVED.
 * @NM_SETTINGS_CONNECTION_INT_FLAGS_NM_GENERATED: A connection is "nm-generated" if
 *  it was generated by NetworkManger. If the connection gets modified or saved
 *  by the user, the flag gets cleared. A nm-generated is implicitly unsaved.
 *  See also #NM_SETTINGS_CONNECTION_FLAG_NM_GENERATED.
 * @NM_SETTINGS_CONNECTION_INT_FLAGS_VOLATILE: The connection will be deleted
 *  when it disconnects. That is for in-memory connections (unsaved), which are
 *  currently active but cleanup on disconnect.
 *  See also #NM_SETTINGS_CONNECTION_FLAG_VOLATILE.
 * @NM_SETTINGS_CONNECTION_INT_FLAGS_VISIBLE: The connection is visible
 * @_NM_SETTINGS_CONNECTION_INT_FLAGS_EXPORTED_MASK: the entire enum is
 *   internal, however, parts of it is public API as #NMSettingsConnectionFlags.
 *   This mask, are the public flags.
 * @_NM_SETTINGS_CONNECTION_INT_FLAGS_ALL: special mask, for all known flags
 *
 * #NMSettingsConnection flags.
 **/
typedef enum _NMSettingsConnectionIntFlags {
	NM_SETTINGS_CONNECTION_INT_FLAGS_NONE                   = 0,

	NM_SETTINGS_CONNECTION_INT_FLAGS_UNSAVED                = NM_SETTINGS_CONNECTION_FLAG_UNSAVED,
	NM_SETTINGS_CONNECTION_INT_FLAGS_NM_GENERATED           = NM_SETTINGS_CONNECTION_FLAG_NM_GENERATED,
	NM_SETTINGS_CONNECTION_INT_FLAGS_VOLATILE               = NM_SETTINGS_CONNECTION_FLAG_VOLATILE,

	NM_SETTINGS_CONNECTION_INT_FLAGS_VISIBLE                = 0x08,

	_NM_SETTINGS_CONNECTION_INT_FLAGS_LAST,

	_NM_SETTINGS_CONNECTION_INT_FLAGS_EXPORTED_MASK         = 0
	                                                          | NM_SETTINGS_CONNECTION_INT_FLAGS_UNSAVED
	                                                          | NM_SETTINGS_CONNECTION_INT_FLAGS_NM_GENERATED
	                                                          | NM_SETTINGS_CONNECTION_INT_FLAGS_VOLATILE
	                                                          | 0,

	_NM_SETTINGS_CONNECTION_INT_FLAGS_PERSISTENT_MASK       = 0
	                                                          | NM_SETTINGS_CONNECTION_INT_FLAGS_NM_GENERATED
	                                                          | NM_SETTINGS_CONNECTION_INT_FLAGS_VOLATILE
	                                                          | 0,

	_NM_SETTINGS_CONNECTION_INT_FLAGS_ALL = ((_NM_SETTINGS_CONNECTION_INT_FLAGS_LAST - 1) << 1) - 1,
} NMSettingsConnectionIntFlags;

typedef enum {
	NM_SETTINGS_AUTO_CONNECT_BLOCKED_REASON_NONE                    = 0,

	NM_SETTINGS_AUTO_CONNECT_BLOCKED_REASON_USER_REQUEST            = (1LL << 0),
	NM_SETTINGS_AUTO_CONNECT_BLOCKED_REASON_FAILED                  = (1LL << 1),
	NM_SETTINGS_AUTO_CONNECT_BLOCKED_REASON_NO_SECRETS              = (1LL << 2),

	NM_SETTINGS_AUTO_CONNECT_BLOCKED_REASON_ALL                     = (  NM_SETTINGS_AUTO_CONNECT_BLOCKED_REASON_USER_REQUEST
	                                                                   | NM_SETTINGS_AUTO_CONNECT_BLOCKED_REASON_FAILED
	                                                                   | NM_SETTINGS_AUTO_CONNECT_BLOCKED_REASON_NO_SECRETS),
} NMSettingsAutoconnectBlockedReason;

typedef struct _NMSettingsConnectionCallId NMSettingsConnectionCallId;

typedef struct _NMSettingsConnectionClass NMSettingsConnectionClass;

struct _NMSettingsConnectionPrivate;

struct _NMSettingsConnection {
	NMDBusObject parent;
	CList _connections_lst;
	struct _NMSettingsConnectionPrivate *_priv;
};

GType nm_settings_connection_get_type (void);

NMSettingsConnection *nm_settings_connection_new (void);

NMConnection *nm_settings_connection_get_connection (NMSettingsConnection *self);

void _nm_settings_connection_set_connection (NMSettingsConnection *self,
                                             NMConnection *new_connection,
                                             NMConnection **out_old_connection,
                                             NMSettingsConnectionUpdateReason update_reason);

NMSettingsStorage *nm_settings_connection_get_storage (NMSettingsConnection *self);

void _nm_settings_connection_set_storage (NMSettingsConnection *self,
                                          NMSettingsStorage *storage);

gboolean nm_settings_connection_still_valid (NMSettingsConnection *self);

const char *nm_settings_connection_get_filename (NMSettingsConnection *self);

guint64 nm_settings_connection_get_last_secret_agent_version_id (NMSettingsConnection *self);

gboolean nm_settings_connection_has_unmodified_applied_connection (NMSettingsConnection *self,
                                                                   NMConnection *applied_connection,
                                                                   NMSettingCompareFlags compare_flage);

gboolean nm_settings_connection_update (NMSettingsConnection *self,
                                        NMConnection *new_connection,
                                        NMSettingsConnectionPersistMode persist_mode,
                                        NMSettingsConnectionIntFlags sett_flags,
                                        NMSettingsConnectionIntFlags sett_mask,
                                        NMSettingsConnectionUpdateReason update_reason,
                                        const char *log_context_name,
                                        GError **error);

void nm_settings_connection_delete (NMSettingsConnection *self,
                                    gboolean allow_add_to_no_auto_default);

typedef void (*NMSettingsConnectionSecretsFunc) (NMSettingsConnection *self,
                                                 NMSettingsConnectionCallId *call_id,
                                                 const char *agent_username,
                                                 const char *setting_name,
                                                 GError *error,
                                                 gpointer user_data);

gboolean nm_settings_connection_new_secrets (NMSettingsConnection *self,
                                             NMConnection *applied_connection,
                                             const char *setting_name,
                                             GVariant *secrets,
                                             GError **error);

NMSettingsConnectionCallId *nm_settings_connection_get_secrets (NMSettingsConnection *self,
                                                                NMConnection *applied_connection,
                                                                NMAuthSubject *subject,
                                                                const char *setting_name,
                                                                NMSecretAgentGetSecretsFlags flags,
                                                                const char *const*hints,
                                                                NMSettingsConnectionSecretsFunc callback,
                                                                gpointer callback_data);

void nm_settings_connection_cancel_secrets (NMSettingsConnection *self,
                                            NMSettingsConnectionCallId *call_id);

void nm_settings_connection_clear_secrets (NMSettingsConnection *self,
                                           gboolean clear_cached_system_secrets,
                                           gboolean persist);

gboolean nm_settings_connection_check_visibility (NMSettingsConnection *self,
                                                  NMSessionMonitor *session_monitor);

gboolean nm_settings_connection_check_permission (NMSettingsConnection *self,
                                                  const char *permission);

/*****************************************************************************/

NMDevice *nm_settings_connection_default_wired_get_device (NMSettingsConnection *self);
void      nm_settings_connection_default_wired_set_device (NMSettingsConnection *self,
                                                           NMDevice *device);

/*****************************************************************************/

NMSettingsConnectionIntFlags nm_settings_connection_get_flags (NMSettingsConnection *self);

static inline gboolean
nm_settings_connection_get_unsaved (NMSettingsConnection *self)
{
	return NM_FLAGS_HAS (nm_settings_connection_get_flags (self), NM_SETTINGS_CONNECTION_INT_FLAGS_UNSAVED);
}

NMSettingsConnectionIntFlags nm_settings_connection_set_flags_full (NMSettingsConnection *self, NMSettingsConnectionIntFlags mask, NMSettingsConnectionIntFlags value);

static inline NMSettingsConnectionIntFlags
nm_settings_connection_set_flags (NMSettingsConnection *self, NMSettingsConnectionIntFlags flags, gboolean set)
{
	return nm_settings_connection_set_flags_full (self,
	                                              flags,
	                                              set ? flags : NM_SETTINGS_CONNECTION_INT_FLAGS_NONE);
}

/*****************************************************************************/

int nm_settings_connection_cmp_timestamp (NMSettingsConnection *ac, NMSettingsConnection *ab);
int nm_settings_connection_cmp_timestamp_p_with_data (gconstpointer pa, gconstpointer pb, gpointer user_data);
int nm_settings_connection_cmp_autoconnect_priority (NMSettingsConnection *a, NMSettingsConnection *b);
int nm_settings_connection_cmp_autoconnect_priority_p_with_data (gconstpointer pa, gconstpointer pb, gpointer user_data);

struct _NMKeyFileDB;

void _nm_settings_connection_register_kf_dbs (NMSettingsConnection *self,
                                              struct _NMKeyFileDB *kf_db_timestamps,
                                              struct _NMKeyFileDB *kf_db_seen_bssids);

gboolean nm_settings_connection_get_timestamp (NMSettingsConnection *self,
                                               guint64 *out_timestamp);

void nm_settings_connection_update_timestamp (NMSettingsConnection *self,
                                              guint64 timestamp);

const char **nm_settings_connection_get_seen_bssids (NMSettingsConnection *self);

gboolean nm_settings_connection_has_seen_bssid (NMSettingsConnection *self,
                                                const char *bssid);

void nm_settings_connection_add_seen_bssid (NMSettingsConnection *self,
                                            const char *seen_bssid);

int nm_settings_connection_autoconnect_retries_get (NMSettingsConnection *self);
void nm_settings_connection_autoconnect_retries_set (NMSettingsConnection *self,
                                                     int retries);
void nm_settings_connection_autoconnect_retries_reset (NMSettingsConnection *self);

gint32 nm_settings_connection_autoconnect_retries_blocked_until (NMSettingsConnection *self);

NMSettingsAutoconnectBlockedReason nm_settings_connection_autoconnect_blocked_reason_get (NMSettingsConnection *self,
                                                                                          NMSettingsAutoconnectBlockedReason mask);
gboolean nm_settings_connection_autoconnect_blocked_reason_set_full (NMSettingsConnection *self,
                                                                     NMSettingsAutoconnectBlockedReason mask,
                                                                     NMSettingsAutoconnectBlockedReason value);

static inline gboolean
nm_settings_connection_autoconnect_blocked_reason_set (NMSettingsConnection *self,
                                                       NMSettingsAutoconnectBlockedReason mask,
                                                       gboolean set)
{
	return nm_settings_connection_autoconnect_blocked_reason_set_full (self, mask, set ? mask : NM_SETTINGS_AUTO_CONNECT_BLOCKED_REASON_NONE);
}

gboolean nm_settings_connection_autoconnect_is_blocked (NMSettingsConnection *self);

const char *nm_settings_connection_get_id              (NMSettingsConnection *connection);
const char *nm_settings_connection_get_uuid            (NMSettingsConnection *connection);
const char *nm_settings_connection_get_connection_type (NMSettingsConnection *connection);

/*****************************************************************************/

NMConnection **nm_settings_connections_array_to_connections (NMSettingsConnection *const*connections,
                                                             gssize n_connections);

/*****************************************************************************/

void _nm_settings_connection_emit_dbus_signal_updated (NMSettingsConnection *self);
void _nm_settings_connection_emit_dbus_signal_removed (NMSettingsConnection *self);

void _nm_settings_connection_emit_signal_updated_internal (NMSettingsConnection *self,
                                                           NMSettingsConnectionUpdateReason update_reason);

void _nm_settings_connection_cleanup_after_remove (NMSettingsConnection *self);

#endif /* __NETWORKMANAGER_SETTINGS_CONNECTION_H__ */
