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
 * Copyright 2008 Novell, Inc.
 * Copyright 2008 - 2014 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-settings-connection.h"

#include "c-list/src/c-list.h"

#include "nm-libnm-core-intern/nm-common-macros.h"
#include "nm-config.h"
#include "nm-config-data.h"
#include "nm-dbus-interface.h"
#include "nm-session-monitor.h"
#include "nm-auth-manager.h"
#include "nm-auth-utils.h"
#include "nm-auth-subject.h"
#include "nm-agent-manager.h"
#include "NetworkManagerUtils.h"
#include "nm-core-internal.h"
#include "nm-audit-manager.h"

#define SETTINGS_TIMESTAMPS_FILE  NMSTATEDIR "/timestamps"
#define SETTINGS_SEEN_BSSIDS_FILE NMSTATEDIR "/seen-bssids"

#define AUTOCONNECT_RETRIES_UNSET        -2
#define AUTOCONNECT_RETRIES_FOREVER      -1
#define AUTOCONNECT_RESET_RETRIES_TIMER 300

/*****************************************************************************/

NMConnection **
nm_settings_connections_array_to_connections (NMSettingsConnection *const*connections,
                                              gssize n_connections)
{
	NMConnection **arr;
	gssize i;

	if (n_connections < 0)
		n_connections = NM_PTRARRAY_LEN (connections);
	if (n_connections == 0)
		return NULL;

	arr = g_new (NMConnection *, n_connections + 1);
	for (i = 0; i < n_connections; i++)
		arr[i] = nm_settings_connection_get_connection (connections[i]);
	arr[i] = NULL;
	return arr;
}

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMSettingsConnection,
	PROP_UNSAVED,
	PROP_READY,
	PROP_FLAGS,
	PROP_FILENAME,
);

enum {
	REMOVED,
	UPDATED_INTERNAL,
	FLAGS_CHANGED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct _NMSettingsConnectionPrivate {

	NMAgentManager *agent_mgr;
	NMSessionMonitor *session_monitor;
	gulong session_changed_id;

	NMSettingsConnectionIntFlags flags:5;

	bool removed:1;
	bool ready:1;

	bool timestamp_set:1;

	NMSettingsAutoconnectBlockedReason autoconnect_blocked_reason:4;

	/* List of pending authentication requests */
	CList auth_lst_head;

	CList call_ids_lst_head; /* in-progress secrets requests */

	NMConnection *connection;

	/* Caches secrets from on-disk connections; were they not cached any
	 * call to nm_connection_clear_secrets() wipes them out and we'd have
	 * to re-read them from disk which defeats the purpose of having the
	 * connection in-memory at all.
	 */
	NMConnection *system_secrets;

	/* Caches secrets from agents during the activation process; if new system
	 * secrets are returned from an agent, they get written out to disk,
	 * triggering a re-read of the connection, which reads only system
	 * secrets, and would wipe out any agent-owned or not-saved secrets the
	 * agent also returned.
	 */
	NMConnection *agent_secrets;

	char *filename;

	GHashTable *seen_bssids; /* Up-to-date BSSIDs that's been seen for the connection */

	guint64 timestamp;   /* Up-to-date timestamp of connection use */

	guint64 last_secret_agent_version_id;

	int autoconnect_retries;
	gint32 autoconnect_retries_blocked_until;

} NMSettingsConnectionPrivate;

G_DEFINE_TYPE (NMSettingsConnection, nm_settings_connection, NM_TYPE_DBUS_OBJECT)

#define NM_SETTINGS_CONNECTION_GET_PRIVATE(self) _NM_GET_PRIVATE_PTR (self, NMSettingsConnection, NM_IS_SETTINGS_CONNECTION)

/*****************************************************************************/

#define _NMLOG_DOMAIN        LOGD_SETTINGS
#define _NMLOG_PREFIX_NAME   "settings-connection"
#define _NMLOG(level, ...) \
    G_STMT_START { \
        const NMLogLevel __level = (level); \
        \
        if (nm_logging_enabled (__level, _NMLOG_DOMAIN)) { \
            char __prefix[128]; \
            const char *__p_prefix = _NMLOG_PREFIX_NAME; \
            const char *__uuid = (self) ? nm_settings_connection_get_uuid (self) : NULL; \
            \
            if (self) { \
                g_snprintf (__prefix, sizeof (__prefix), "%s[%p%s%s]", _NMLOG_PREFIX_NAME, self, __uuid ? "," : "", __uuid ?: ""); \
                __p_prefix = __prefix; \
            } \
            _nm_log (__level, _NMLOG_DOMAIN, 0, NULL, __uuid, \
                     "%s: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
                     __p_prefix _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
        } \
    } G_STMT_END

/*****************************************************************************/

static const GDBusSignalInfo signal_info_updated;
static const GDBusSignalInfo signal_info_removed;
static const NMDBusInterfaceInfoExtended interface_info_settings_connection;

/*****************************************************************************/

NMConnection *
nm_settings_connection_get_connection (NMSettingsConnection *self)
{
	g_return_val_if_fail (NM_IS_SETTINGS_CONNECTION (self), NULL);

	return NM_SETTINGS_CONNECTION_GET_PRIVATE (self)->connection;
}

/*****************************************************************************/

gboolean
nm_settings_connection_has_unmodified_applied_connection (NMSettingsConnection *self,
                                                          NMConnection *applied_connection,
                                                          NMSettingCompareFlags compare_flags)
{
	g_return_val_if_fail (NM_IS_SETTINGS_CONNECTION (self), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (applied_connection), FALSE);

	/* for convenience, we *always* ignore certain settings. */
	compare_flags |= NM_SETTING_COMPARE_FLAG_IGNORE_SECRETS | NM_SETTING_COMPARE_FLAG_IGNORE_TIMESTAMP;

	return nm_connection_compare (nm_settings_connection_get_connection (self),
	                              applied_connection, compare_flags);
}

/*****************************************************************************/

guint64
nm_settings_connection_get_last_secret_agent_version_id (NMSettingsConnection *self)
{
	g_return_val_if_fail (NM_IS_SETTINGS_CONNECTION (self), 0);

	return NM_SETTINGS_CONNECTION_GET_PRIVATE (self)->last_secret_agent_version_id;
}

/*****************************************************************************/

static void
set_visible (NMSettingsConnection *self, gboolean new_visible)
{
	nm_settings_connection_set_flags (self,
	                                  NM_SETTINGS_CONNECTION_INT_FLAGS_VISIBLE,
	                                  new_visible);
}

void
nm_settings_connection_recheck_visibility (NMSettingsConnection *self)
{
	NMSettingsConnectionPrivate *priv;
	NMSettingConnection *s_con;
	guint32 num, i;

	g_return_if_fail (NM_IS_SETTINGS_CONNECTION (self));

	priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);

	s_con = nm_connection_get_setting_connection (nm_settings_connection_get_connection (self));

	/* Check every user in the ACL for a session */
	num = nm_setting_connection_get_num_permissions (s_con);
	if (num == 0) {
		/* Visible to all */
		set_visible (self, TRUE);
		return;
	}

	for (i = 0; i < num; i++) {
		const char *user;
		uid_t uid;

		if (!nm_setting_connection_get_permission (s_con, i, NULL, &user, NULL))
			continue;
		if (!nm_session_monitor_user_to_uid (user, &uid))
			continue;
		if (!nm_session_monitor_session_exists (priv->session_monitor, uid, FALSE))
			continue;

		set_visible (self, TRUE);
		return;
	}

	set_visible (self, FALSE);
}

static void
session_changed_cb (NMSessionMonitor *self, NMSettingsConnection *sett_conn)
{
	nm_settings_connection_recheck_visibility (sett_conn);
}

/*****************************************************************************/

/* Return TRUE if any active user in the connection's ACL has the given
 * permission without having to authorize for it via PolicyKit.  Connections
 * visible to everyone automatically pass the check.
 */
gboolean
nm_settings_connection_check_permission (NMSettingsConnection *self,
                                         const char *permission)
{
	NMSettingsConnectionPrivate *priv;
	NMSettingConnection *s_con;
	guint32 num, i;
	const char *puser;

	g_return_val_if_fail (NM_IS_SETTINGS_CONNECTION (self), FALSE);

	priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);

	if (!NM_FLAGS_HAS (nm_settings_connection_get_flags (self),
	                   NM_SETTINGS_CONNECTION_INT_FLAGS_VISIBLE))
		return FALSE;

	s_con = nm_connection_get_setting_connection (nm_settings_connection_get_connection (self));

	/* Check every user in the ACL for a session */
	num = nm_setting_connection_get_num_permissions (s_con);
	if (num == 0) {
		/* Visible to all so it's OK to auto-activate */
		return TRUE;
	}

	for (i = 0; i < num; i++) {
		/* For each user get their secret agent and check if that agent has the
		 * required permission.
		 *
		 * FIXME: what if the user isn't running an agent?  PolKit needs a bus
		 * name or a PID but if the user isn't running an agent they won't have
		 * either.
		 */
		if (nm_setting_connection_get_permission (s_con, i, NULL, &puser, NULL)) {
			NMSecretAgent *agent = nm_agent_manager_get_agent_by_user (priv->agent_mgr, puser);

			if (agent && nm_secret_agent_has_permission (agent, permission))
				return TRUE;
		}
	}

	return FALSE;
}

/*****************************************************************************/

static gboolean
secrets_filter_cb (NMSetting *setting,
                   const char *secret,
                   NMSettingSecretFlags flags,
                   gpointer user_data)
{
	NMSettingSecretFlags filter_flags = GPOINTER_TO_UINT (user_data);

	/* Returns TRUE to remove the secret */

	/* Can't use bitops with SECRET_FLAG_NONE so handle that specifically */
	if (   (flags == NM_SETTING_SECRET_FLAG_NONE)
	    && (filter_flags == NM_SETTING_SECRET_FLAG_NONE))
		return FALSE;

	/* Otherwise if the secret has at least one of the desired flags keep it */
	return (flags & filter_flags) ? FALSE : TRUE;
}

static void
update_system_secrets_cache (NMSettingsConnection *self)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);

	if (priv->system_secrets)
		g_object_unref (priv->system_secrets);
	priv->system_secrets = nm_simple_connection_new_clone (nm_settings_connection_get_connection (self));

	/* Clear out non-system-owned and not-saved secrets */
	nm_connection_clear_secrets_with_flags (priv->system_secrets,
	                                        secrets_filter_cb,
	                                        GUINT_TO_POINTER (NM_SETTING_SECRET_FLAG_NONE));
}

static void
update_agent_secrets_cache (NMSettingsConnection *self, NMConnection *new)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);
	NMSettingSecretFlags filter_flags = NM_SETTING_SECRET_FLAG_NOT_SAVED | NM_SETTING_SECRET_FLAG_AGENT_OWNED;

	if (priv->agent_secrets)
		g_object_unref (priv->agent_secrets);
	priv->agent_secrets = nm_simple_connection_new_clone (   new
	                                                      ?: nm_settings_connection_get_connection (self));

	/* Clear out non-system-owned secrets */
	nm_connection_clear_secrets_with_flags (priv->agent_secrets,
	                                        secrets_filter_cb,
	                                        GUINT_TO_POINTER (filter_flags));
}

static void
secrets_cleared_cb (NMConnection *connection, NMSettingsConnection *self)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);

	/* Clear agent secrets when connection's secrets are cleared since agent
	 * secrets are transient.
	 */
	if (priv->agent_secrets)
		g_object_unref (priv->agent_secrets);
	priv->agent_secrets = NULL;
}

static void
set_persist_mode (NMSettingsConnection *self, NMSettingsConnectionPersistMode persist_mode)
{
	NMSettingsConnectionIntFlags flags = NM_SETTINGS_CONNECTION_INT_FLAGS_NONE;
	const NMSettingsConnectionIntFlags ALL =   NM_SETTINGS_CONNECTION_INT_FLAGS_UNSAVED
	                                         | NM_SETTINGS_CONNECTION_INT_FLAGS_NM_GENERATED
	                                         | NM_SETTINGS_CONNECTION_INT_FLAGS_VOLATILE;

	switch (persist_mode) {
	case NM_SETTINGS_CONNECTION_PERSIST_MODE_DISK:
		flags = NM_SETTINGS_CONNECTION_INT_FLAGS_NONE;
		break;
	case NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY:
	case NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY_DETACHED:
	case NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY_ONLY:
		flags = NM_SETTINGS_CONNECTION_INT_FLAGS_UNSAVED;
		break;
	case NM_SETTINGS_CONNECTION_PERSIST_MODE_VOLATILE_DETACHED:
	case NM_SETTINGS_CONNECTION_PERSIST_MODE_VOLATILE_ONLY:
		flags = NM_SETTINGS_CONNECTION_INT_FLAGS_UNSAVED |
		        NM_SETTINGS_CONNECTION_INT_FLAGS_VOLATILE;
		break;
	case NM_SETTINGS_CONNECTION_PERSIST_MODE_UNSAVED:
		/* only set the connection as unsaved, but preserve the nm-generated
		 * and volatile flag. */
		nm_settings_connection_set_flags (self,
		                                  NM_SETTINGS_CONNECTION_INT_FLAGS_UNSAVED,
		                                  TRUE);
		return;
	case NM_SETTINGS_CONNECTION_PERSIST_MODE_KEEP:
	case NM_SETTINGS_CONNECTION_PERSIST_MODE_KEEP_SAVED:
		/* Nothing to do */
		return;
	}

	nm_settings_connection_set_flags_full (self, ALL, flags);
}

static void
_emit_updated (NMSettingsConnection *self, gboolean by_user)
{
	nm_dbus_object_emit_signal (NM_DBUS_OBJECT (self),
	                            &interface_info_settings_connection,
	                            &signal_info_updated,
	                            "()");
	g_signal_emit (self, signals[UPDATED_INTERNAL], 0, by_user);
}

static void
connection_changed_cb (NMConnection *connection, NMSettingsConnection *self)
{
	set_persist_mode (self, NM_SETTINGS_CONNECTION_PERSIST_MODE_UNSAVED);
	_emit_updated (self, FALSE);
}

static gboolean
_delete (NMSettingsConnection *self, GError **error)
{
	NMSettingsConnectionClass *klass;
	GError *local = NULL;
	const char *filename;

	nm_assert (NM_IS_SETTINGS_CONNECTION (self));

	klass = NM_SETTINGS_CONNECTION_GET_CLASS (self);
	if (!klass->delete) {
		g_set_error (&local,
		             NM_SETTINGS_ERROR,
		             NM_SETTINGS_ERROR_FAILED,
		             "delete not supported");
		goto fail;
	}
	if (!klass->delete (self,
	                    &local))
		goto fail;

	filename = nm_settings_connection_get_filename (self);
	if (filename) {
		_LOGD ("delete: success deleting connection (\"%s\")", filename);
		nm_settings_connection_set_filename (self, NULL);
	} else
		_LOGT ("delete: success deleting connection (no-file)");
	return TRUE;
fail:
	_LOGD ("delete: failure deleting connection: %s", local->message);
	g_propagate_error (error, local);
	return FALSE;
}

static gboolean
_update_prepare (NMSettingsConnection *self,
                 NMConnection *new_connection,
                 GError **error)
{
	g_return_val_if_fail (NM_IS_SETTINGS_CONNECTION (self), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (new_connection), FALSE);

	if (!nm_connection_normalize (new_connection, NULL, NULL, error))
		return FALSE;

	if (   nm_dbus_object_get_path (NM_DBUS_OBJECT (self))
	    && g_strcmp0 (nm_settings_connection_get_uuid (self), nm_connection_get_uuid (new_connection)) != 0) {
		/* Updating the UUID is not allowed once the path is exported. */
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "connection %s cannot change the UUID from %s to %s", nm_settings_connection_get_id (self),
		             nm_settings_connection_get_uuid (self), nm_connection_get_uuid (new_connection));
		return FALSE;
	}

	return TRUE;
}

gboolean
nm_settings_connection_update (NMSettingsConnection *self,
                               NMConnection *new_connection,
                               NMSettingsConnectionPersistMode persist_mode,
                               NMSettingsConnectionCommitReason commit_reason,
                               const char *log_diff_name,
                               GError **error)
{
	NMSettingsConnectionPrivate *priv;
	NMSettingsConnectionClass *klass = NULL;
	gs_unref_object NMConnection *reread_connection = NULL;
	NMConnection *replace_connection;
	gboolean replaced = FALSE;
	gs_free char *logmsg_change = NULL;
	GError *local = NULL;
	gs_unref_object NMConnection *simple = NULL;
	gs_unref_variant GVariant *con_agent_secrets = NULL;
	gs_unref_variant GVariant *new_agent_secrets = NULL;

	g_return_val_if_fail (NM_IS_SETTINGS_CONNECTION (self), FALSE);

	priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);

	if (persist_mode == NM_SETTINGS_CONNECTION_PERSIST_MODE_DISK) {
		klass = NM_SETTINGS_CONNECTION_GET_CLASS (self);
		if (!klass->commit_changes) {
			g_set_error (&local,
			             NM_SETTINGS_ERROR,
			             NM_SETTINGS_ERROR_FAILED,
			             "writing settings not supported");
			goto out;
		}
	}

	if (   new_connection
	    && !_update_prepare (self,
	                         new_connection,
	                         &local))
		goto out;

	if (persist_mode == NM_SETTINGS_CONNECTION_PERSIST_MODE_DISK) {
		if (!klass->commit_changes (self,
		                            new_connection ?: nm_settings_connection_get_connection (self),
		                            commit_reason,
		                            &reread_connection,
		                            &logmsg_change,
		                            &local))
			goto out;

		if (   reread_connection
		    && !_update_prepare (self,
		                         reread_connection,
		                         &local))
			goto out;
	}

	replace_connection = reread_connection ?: new_connection;

	/* Save agent-owned secrets from the new connection for later use */
	if (new_connection) {
		simple = nm_simple_connection_new_clone (new_connection);
		nm_connection_clear_secrets_with_flags (simple,
		                                        secrets_filter_cb,
		                                        GUINT_TO_POINTER (NM_SETTING_SECRET_FLAG_AGENT_OWNED));
		new_agent_secrets = nm_connection_to_dbus (simple, NM_CONNECTION_SERIALIZE_ONLY_SECRETS);
		g_clear_object (&simple);
	}

	/* Disconnect the changed signal to ensure we don't set Unsaved when
	 * it's not required.
	 */
	g_signal_handlers_block_by_func (priv->connection, G_CALLBACK (connection_changed_cb), self);

	/* Do nothing if there's nothing to update */
	if (   replace_connection
	    && !nm_connection_compare (nm_settings_connection_get_connection (self),
	                               replace_connection,
	                               NM_SETTING_COMPARE_FLAG_EXACT)) {

		if (log_diff_name) {
			nm_utils_log_connection_diff (replace_connection, nm_settings_connection_get_connection (self), LOGL_DEBUG, LOGD_CORE, log_diff_name, "++ ",
			                              nm_dbus_object_get_path (NM_DBUS_OBJECT (self)));
		}

		/* Make a copy of agent-owned secrets because they won't be present in
		 * the connection returned by plugins, as plugins return only what was
		 * reread from the file. */
		simple = nm_simple_connection_new_clone (nm_settings_connection_get_connection (self));
		nm_connection_clear_secrets_with_flags (simple,
		                                        secrets_filter_cb,
		                                        GUINT_TO_POINTER (NM_SETTING_SECRET_FLAG_AGENT_OWNED));
		con_agent_secrets = nm_connection_to_dbus (simple, NM_CONNECTION_SERIALIZE_ONLY_SECRETS);

		nm_connection_replace_settings_from_connection (nm_settings_connection_get_connection (self), replace_connection);

		replaced = TRUE;
	}

	nm_settings_connection_set_flags (self,
	                                  NM_SETTINGS_CONNECTION_INT_FLAGS_NM_GENERATED | NM_SETTINGS_CONNECTION_INT_FLAGS_VOLATILE,
	                                  FALSE);

	if (replaced) {
		/* Cache the just-updated system secrets in case something calls
		 * nm_connection_clear_secrets() and clears them.
		 */
		update_system_secrets_cache (self);

		/* Add agent and always-ask secrets back; they won't necessarily be
		 * in the replacement connection data if it was eg reread from disk.
		 */
		if (priv->agent_secrets) {
			GVariant *dict;

			dict = nm_connection_to_dbus (priv->agent_secrets, NM_CONNECTION_SERIALIZE_ONLY_SECRETS);
			if (dict) {
				(void) nm_connection_update_secrets (nm_settings_connection_get_connection (self), NULL, dict, NULL);
				g_variant_unref (dict);
			}
		}
		if (con_agent_secrets)
			(void) nm_connection_update_secrets (nm_settings_connection_get_connection (self), NULL, con_agent_secrets, NULL);
	}

	/* Apply agent-owned secrets from the new connection so that
	 * they can be sent to agents */
	if (new_agent_secrets) {
		(void) nm_connection_update_secrets (nm_settings_connection_get_connection (self),
		                                     NULL,
		                                     new_agent_secrets,
		                                     NULL);
	}

	nm_settings_connection_recheck_visibility (self);

	if (   replaced
	    && persist_mode == NM_SETTINGS_CONNECTION_PERSIST_MODE_KEEP)
		set_persist_mode (self, NM_SETTINGS_CONNECTION_PERSIST_MODE_UNSAVED);
	else
		set_persist_mode (self, persist_mode);

	if (NM_IN_SET (persist_mode, NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY_ONLY,
	                             NM_SETTINGS_CONNECTION_PERSIST_MODE_VOLATILE_ONLY))
		_delete (self, NULL);
	else if (NM_IN_SET (persist_mode, NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY_DETACHED,
	                                  NM_SETTINGS_CONNECTION_PERSIST_MODE_VOLATILE_DETACHED))
		nm_settings_connection_set_filename (self, NULL);

	g_signal_handlers_unblock_by_func (priv->connection, G_CALLBACK (connection_changed_cb), self);

	_emit_updated (self, TRUE);

out:
	if (local) {
		_LOGI ("write: failure to update connection: %s", local->message);
		g_propagate_error (error, local);
		return FALSE;
	}

	if (persist_mode == NM_SETTINGS_CONNECTION_PERSIST_MODE_DISK) {
		if (reread_connection)
			_LOGI ("write: successfully updated (%s), connection was modified in the process", logmsg_change);
		else if (new_connection)
			_LOGI ("write: successfully updated (%s)", logmsg_change);
		else
			_LOGI ("write: successfully committed (%s)", logmsg_change);
	}
	return TRUE;
}

static void
remove_entry_from_db (NMSettingsConnection *self, const char* db_name)
{
	GKeyFile *key_file;
	const char *db_file;

	if (strcmp (db_name, "timestamps") == 0)
		db_file = SETTINGS_TIMESTAMPS_FILE;
	else if (strcmp (db_name, "seen-bssids") == 0)
		db_file = SETTINGS_SEEN_BSSIDS_FILE;
	else
		return;

	key_file = g_key_file_new ();
	if (g_key_file_load_from_file (key_file, db_file, G_KEY_FILE_KEEP_COMMENTS, NULL)) {
		const char *connection_uuid;
		char *data;
		gsize len;
		GError *error = NULL;

		connection_uuid = nm_settings_connection_get_uuid (self);

		g_key_file_remove_key (key_file, db_name, connection_uuid, NULL);
		data = g_key_file_to_data (key_file, &len, &error);
		if (data) {
			g_file_set_contents (db_file, data, len, &error);
			g_free (data);
		}
		if (error) {
			_LOGW ("error writing %s file '%s': %s", db_name, db_file, error->message);
			g_error_free (error);
		}
	}
	g_key_file_free (key_file);
}

gboolean
nm_settings_connection_delete (NMSettingsConnection *self,
                               GError **error)
{
	gs_unref_object NMSettingsConnection *self_keep_alive = NULL;
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);
	NMConnection *for_agents;

	g_return_val_if_fail (NM_IS_SETTINGS_CONNECTION (self), FALSE);

	self_keep_alive = g_object_ref (self);

	if (!_delete (self, error))
		return FALSE;

	set_visible (self, FALSE);

	/* Tell agents to remove secrets for this connection */
	for_agents = nm_simple_connection_new_clone (nm_settings_connection_get_connection (self));
	nm_connection_clear_secrets (for_agents);
	nm_agent_manager_delete_secrets (priv->agent_mgr,
	                                 nm_dbus_object_get_path (NM_DBUS_OBJECT (self)),
	                                 for_agents);
	g_object_unref (for_agents);

	/* Remove timestamp from timestamps database file */
	remove_entry_from_db (self, "timestamps");

	/* Remove connection from seen-bssids database file */
	remove_entry_from_db (self, "seen-bssids");

	nm_settings_connection_signal_remove (self);
	return TRUE;
}

/*****************************************************************************/

typedef enum {
	CALL_ID_TYPE_REQ,
	CALL_ID_TYPE_IDLE,
} CallIdType;

struct _NMSettingsConnectionCallId {
	NMSettingsConnection *self;
	CList call_ids_lst;
	gboolean had_applied_connection;
	NMConnection *applied_connection;
	NMSettingsConnectionSecretsFunc callback;
	gpointer callback_data;

	CallIdType type;
	union {
		struct {
			NMAgentManagerCallId id;
		} req;
		struct {
			guint32 id;
			GError *error;
		} idle;
	} t;
};

static void
_get_secrets_info_callback (NMSettingsConnectionCallId *call_id,
                            const char *agent_username,
                            const char *setting_name,
                            GError *error)
{
	if (call_id->callback) {
		call_id->callback (call_id->self,
		                   call_id,
		                   agent_username,
		                   setting_name,
		                   error,
		                   call_id->callback_data);
	}
}

static void
_get_secrets_info_free (NMSettingsConnectionCallId *call_id)
{
	g_return_if_fail (call_id && call_id->self);
	nm_assert (!c_list_is_linked (&call_id->call_ids_lst));

	if (call_id->applied_connection)
		g_object_remove_weak_pointer (G_OBJECT (call_id->applied_connection), (gpointer *) &call_id->applied_connection);

	if (call_id->type == CALL_ID_TYPE_IDLE)
		g_clear_error (&call_id->t.idle.error);

	memset (call_id, 0, sizeof (*call_id));
	g_slice_free (NMSettingsConnectionCallId, call_id);
}

static gboolean
supports_secrets (NMSettingsConnection *self, const char *setting_name)
{
	/* All secrets supported */
	return TRUE;
}

typedef struct {
	NMSettingSecretFlags required;
	NMSettingSecretFlags forbidden;
} ForEachSecretFlags;

static gboolean
validate_secret_flags_cb (NMSettingSecretFlags flags,
                          gpointer user_data)
{
	ForEachSecretFlags *cmp_flags = user_data;

	if (!NM_FLAGS_ALL (flags, cmp_flags->required))
		return FALSE;
	if (NM_FLAGS_ANY (flags, cmp_flags->forbidden))
		return FALSE;
	return TRUE;
}

static GVariant *
validate_secret_flags (NMConnection *connection,
                       GVariant *secrets,
                       ForEachSecretFlags *cmp_flags)
{
	return g_variant_ref_sink (_nm_connection_for_each_secret (connection,
	                                                           secrets,
	                                                           TRUE,
	                                                           validate_secret_flags_cb,
	                                                           cmp_flags));
}

static gboolean
secret_is_system_owned (NMSettingSecretFlags flags,
                        gpointer user_data)
{
	return !NM_FLAGS_HAS (flags, NM_SETTING_SECRET_FLAG_AGENT_OWNED);
}

static void
get_cmp_flags (NMSettingsConnection *self, /* only needed for logging */
               NMSettingsConnectionCallId *call_id, /* only needed for logging */
               NMConnection *connection,
               const char *agent_dbus_owner,
               gboolean agent_has_modify,
               const char *setting_name, /* only needed for logging */
               NMSecretAgentGetSecretsFlags flags,
               GVariant *secrets,
               gboolean *agent_had_system,
               ForEachSecretFlags *cmp_flags)
{
	gboolean is_self = (nm_settings_connection_get_connection (self) == connection);

	g_return_if_fail (secrets);

	cmp_flags->required = NM_SETTING_SECRET_FLAG_NONE;
	cmp_flags->forbidden = NM_SETTING_SECRET_FLAG_NONE;

	*agent_had_system = FALSE;

	if (agent_dbus_owner) {
		if (is_self) {
			_LOGD ("(%s:%p) secrets returned from agent %s",
			       setting_name,
			       call_id,
			       agent_dbus_owner);
		}

		/* If the agent returned any system-owned secrets (initial connect and no
		 * secrets given when the connection was created, or something like that)
		 * make sure the agent's UID has the 'modify' permission before we use or
		 * save those system-owned secrets.  If not, discard them and use the
		 * existing secrets, or fail the connection.
		 */
		*agent_had_system = _nm_connection_find_secret (connection, secrets, secret_is_system_owned, NULL);
		if (*agent_had_system) {
			if (flags == NM_SECRET_AGENT_GET_SECRETS_FLAG_NONE) {
				/* No user interaction was allowed when requesting secrets; the
				 * agent is being bad.  Remove system-owned secrets.
				 */
				if (is_self) {
					_LOGD ("(%s:%p) interaction forbidden but agent %s returned system secrets",
					       setting_name,
					       call_id,
					       agent_dbus_owner);
				}

				cmp_flags->required |= NM_SETTING_SECRET_FLAG_AGENT_OWNED;
			} else if (agent_has_modify == FALSE) {
				/* Agent didn't successfully authenticate; clear system-owned secrets
				 * from the secrets the agent returned.
				 */
				if (is_self) {
					_LOGD ("(%s:%p) agent failed to authenticate but provided system secrets",
					       setting_name,
					       call_id);
				}

				cmp_flags->required |= NM_SETTING_SECRET_FLAG_AGENT_OWNED;
			}
		}
	} else {
		if (is_self) {
			_LOGD ("(%s:%p) existing secrets returned",
			       setting_name,
			       call_id);
		}
	}

	/* If no user interaction was allowed, make sure that no "unsaved" secrets
	 * came back.  Unsaved secrets by definition require user interaction.
	 */
	if (flags == NM_SECRET_AGENT_GET_SECRETS_FLAG_NONE) {
		cmp_flags->forbidden |= (  NM_SETTING_SECRET_FLAG_NOT_SAVED
		                         | NM_SETTING_SECRET_FLAG_NOT_REQUIRED);
	}
}

gboolean
nm_settings_connection_new_secrets (NMSettingsConnection *self,
                                    NMConnection *applied_connection,
                                    const char *setting_name,
                                    GVariant *secrets,
                                    GError **error)
{
	if (!nm_settings_connection_has_unmodified_applied_connection (self, applied_connection,
	                                                              NM_SETTING_COMPARE_FLAG_NONE)) {
		g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		                     "The connection was modified since activation");
		return FALSE;
	}

	if (!nm_connection_update_secrets (nm_settings_connection_get_connection (self), setting_name, secrets, error))
		return FALSE;

	update_system_secrets_cache (self);
	update_agent_secrets_cache (self, NULL);

	nm_settings_connection_update (self,
	                               NULL,
	                               NM_SETTINGS_CONNECTION_PERSIST_MODE_DISK,
	                               NM_SETTINGS_CONNECTION_COMMIT_REASON_NONE,
	                               "new-secrets",
	                               NULL);
	return TRUE;
}

static void
get_secrets_done_cb (NMAgentManager *manager,
                     NMAgentManagerCallId call_id_a,
                     const char *agent_dbus_owner,
                     const char *agent_username,
                     gboolean agent_has_modify,
                     const char *setting_name,
                     NMSecretAgentGetSecretsFlags flags,
                     GVariant *secrets,
                     GError *error,
                     gpointer user_data)
{
	NMSettingsConnectionCallId *call_id = user_data;
	NMSettingsConnection *self;
	NMSettingsConnectionPrivate *priv;
	NMConnection *applied_connection;
	gs_free_error GError *local = NULL;
	GVariant *dict = NULL;
	gboolean agent_had_system = FALSE;
	ForEachSecretFlags cmp_flags = { NM_SETTING_SECRET_FLAG_NONE, NM_SETTING_SECRET_FLAG_NONE };

	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = call_id->self;
	g_return_if_fail (NM_IS_SETTINGS_CONNECTION (self));

	priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);

	nm_assert (c_list_contains (&priv->call_ids_lst_head, &call_id->call_ids_lst));

	c_list_unlink (&call_id->call_ids_lst);

	if (error) {
		_LOGD ("(%s:%p) secrets request error: %s",
		       setting_name, call_id, error->message);

		_get_secrets_info_callback (call_id, NULL, setting_name, error);
		goto out;
	}

	if (   call_id->had_applied_connection
	    && !call_id->applied_connection) {
		g_set_error_literal (&local, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_SETTING_NOT_FOUND,
		                     "Applied connection deleted since requesting secrets");
		_get_secrets_info_callback (call_id, NULL, setting_name, local);
		goto out;
	}

	if (   call_id->had_applied_connection
	    && !nm_settings_connection_has_unmodified_applied_connection (self, call_id->applied_connection, NM_SETTING_COMPARE_FLAG_NONE)) {
		g_set_error_literal (&local, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		                     "The connection was modified since activation");
		_get_secrets_info_callback (call_id, NULL, setting_name, local);
		goto out;
	}

	if (!nm_connection_get_setting_by_name (nm_settings_connection_get_connection (self), setting_name)) {
		g_set_error (&local, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_SETTING_NOT_FOUND,
		             "Connection didn't have requested setting '%s'.",
		             setting_name);
		_get_secrets_info_callback (call_id, NULL, setting_name, local);
		goto out;
	}

	get_cmp_flags (self,
	               call_id,
	               nm_settings_connection_get_connection (self),
	               agent_dbus_owner,
	               agent_has_modify,
	               setting_name,
	               flags,
	               secrets,
	               &agent_had_system,
	               &cmp_flags);

	_LOGD ("(%s:%p) secrets request completed",
	       setting_name,
	       call_id);

	if (priv->system_secrets)
		dict = nm_connection_to_dbus (priv->system_secrets, NM_CONNECTION_SERIALIZE_ONLY_SECRETS);

	/* Update the connection with our existing secrets from backing storage */
	nm_connection_clear_secrets (nm_settings_connection_get_connection (self));
	if (!dict || nm_connection_update_secrets (nm_settings_connection_get_connection (self), setting_name, dict, &local)) {
		gs_unref_variant GVariant *filtered_secrets = NULL;

		/* Update the connection with the agent's secrets; by this point if any
		 * system-owned secrets exist in 'secrets' the agent that provided them
		 * will have been authenticated, so those secrets can replace the existing
		 * system secrets.
		 */
		filtered_secrets = validate_secret_flags (nm_settings_connection_get_connection (self), secrets, &cmp_flags);
		if (nm_connection_update_secrets (nm_settings_connection_get_connection (self), setting_name, filtered_secrets, &local)) {
			/* Now that all secrets are updated, copy and cache new secrets,
			 * then save them to backing storage.
			 */
			update_system_secrets_cache (self);
			update_agent_secrets_cache (self, NULL);

			/* Only save secrets to backing storage if the agent returned any
			 * new system secrets.  If it didn't, then the secrets are agent-
			 * owned and there's no point to writing out the connection when
			 * nothing has changed, since agent-owned secrets don't get saved here.
			 */
			if (agent_had_system) {
				_LOGD ("(%s:%p) saving new secrets to backing storage",
				       setting_name,
				       call_id);

				nm_settings_connection_update (self,
				                               NULL,
				                               NM_SETTINGS_CONNECTION_PERSIST_MODE_DISK,
				                               NM_SETTINGS_CONNECTION_COMMIT_REASON_NONE,
				                               "get-new-secrets",
				                               NULL);
			} else {
				_LOGD ("(%s:%p) new agent secrets processed",
				       setting_name,
				       call_id);
			}

		} else {
			_LOGD ("(%s:%p) failed to update with agent secrets: %s",
			       setting_name,
			       call_id,
			       local->message);
		}
	} else {
		_LOGD ("(%s:%p) failed to update with existing secrets: %s",
		       setting_name,
		       call_id,
		       local->message);
	}

	applied_connection = call_id->applied_connection;
	if (applied_connection) {
		get_cmp_flags (self,
		               call_id,
		               applied_connection,
		               agent_dbus_owner,
		               agent_has_modify,
		               setting_name,
		               flags,
		               secrets,
		               &agent_had_system,
		               &cmp_flags);

		nm_connection_clear_secrets (applied_connection);

		if (!dict || nm_connection_update_secrets (applied_connection, setting_name, dict, NULL)) {
			gs_unref_variant GVariant *filtered_secrets = NULL;

			filtered_secrets = validate_secret_flags (applied_connection, secrets, &cmp_flags);
			nm_connection_update_secrets (applied_connection, setting_name, filtered_secrets, NULL);
		}
	}

	_get_secrets_info_callback (call_id, agent_username, setting_name, local);
	g_clear_error (&local);
	if (dict)
		g_variant_unref (dict);

out:
	_get_secrets_info_free (call_id);
}

static gboolean
get_secrets_idle_cb (NMSettingsConnectionCallId *call_id)
{
	NMSettingsConnectionPrivate *priv;

	g_return_val_if_fail (call_id && NM_IS_SETTINGS_CONNECTION (call_id->self), G_SOURCE_REMOVE);

	priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (call_id->self);

	nm_assert (c_list_contains (&priv->call_ids_lst_head, &call_id->call_ids_lst));

	c_list_unlink (&call_id->call_ids_lst);

	_get_secrets_info_callback (call_id, NULL, NULL, call_id->t.idle.error);

	_get_secrets_info_free (call_id);
	return G_SOURCE_REMOVE;
}

/**
 * nm_settings_connection_get_secrets:
 * @self: the #NMSettingsConnection
 * @applied_connection: (allow-none): if provided, only request secrets
 *   if @self equals to @applied_connection. Also, update the secrets
 *   in the @applied_connection.
 * @subject: the #NMAuthSubject originating the request
 * @setting_name: the setting to return secrets for
 * @flags: flags to modify the secrets request
 * @hints: key names in @setting_name for which secrets may be required, or some
 *   other information about the request
 * @callback: the function to call with returned secrets
 * @callback_data: user data to pass to @callback
 *
 * Retrieves secrets from persistent storage and queries any secret agents for
 * additional secrets.
 *
 * With the returned call-id, the call can be cancelled. It is an error
 * to cancel a call more then once or a call that already completed.
 * The callback will always be invoked exactly once, also for cancellation
 * and disposing of @self. In those latter cases, the callback will be invoked
 * synchronously during cancellation/disposing.
 *
 * Returns: a call ID which may be used to cancel the ongoing secrets request.
 **/
NMSettingsConnectionCallId *
nm_settings_connection_get_secrets (NMSettingsConnection *self,
                                    NMConnection *applied_connection,
                                    NMAuthSubject *subject,
                                    const char *setting_name,
                                    NMSecretAgentGetSecretsFlags flags,
                                    const char *const*hints,
                                    NMSettingsConnectionSecretsFunc callback,
                                    gpointer callback_data)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);
	GVariant *existing_secrets = NULL;
	NMAgentManagerCallId call_id_a;
	gs_free char *joined_hints = NULL;
	NMSettingsConnectionCallId *call_id;
	GError *local = NULL;

	g_return_val_if_fail (NM_IS_SETTINGS_CONNECTION (self), NULL);
	g_return_val_if_fail (   !applied_connection
	                      || (   NM_IS_CONNECTION (applied_connection)
	                          && (nm_settings_connection_get_connection (self) != applied_connection)), NULL);

	call_id = g_slice_new0 (NMSettingsConnectionCallId);
	call_id->self = self;
	if (applied_connection) {
		call_id->had_applied_connection = TRUE;
		call_id->applied_connection = applied_connection;
		g_object_add_weak_pointer (G_OBJECT (applied_connection), (gpointer *) &call_id->applied_connection);
	}
	call_id->callback = callback;
	call_id->callback_data = callback_data;
	c_list_link_tail (&priv->call_ids_lst_head, &call_id->call_ids_lst);

	/* Make sure the request actually requests something we can return */
	if (!nm_connection_get_setting_by_name (nm_settings_connection_get_connection (self), setting_name)) {
		g_set_error (&local, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_SETTING_NOT_FOUND,
		             "Connection didn't have requested setting '%s'.",
		             setting_name);
		goto schedule_dummy;
	}

	if (   applied_connection
	    && !nm_settings_connection_has_unmodified_applied_connection (self, applied_connection, NM_SETTING_COMPARE_FLAG_NONE)) {
		g_set_error_literal (&local, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		                     "The connection was modified since activation");
		goto schedule_dummy;
	}

	/* Use priv->system_secrets to work around the fact that nm_connection_clear_secrets()
	 * will clear secrets on this object's settings.
	 */
	if (priv->system_secrets)
		existing_secrets = nm_connection_to_dbus (priv->system_secrets, NM_CONNECTION_SERIALIZE_ONLY_SECRETS);
	if (existing_secrets)
		g_variant_ref_sink (existing_secrets);

	/* we remember the current version-id of the secret-agents. The version-id is strictly increasing,
	 * as new agents register the number. We know hence, that this request was made against a certain
	 * set of secret-agents.
	 * If after making this request a new secret-agent registers, the version-id increases.
	 * Then we know that the this request probably did not yet include the latest secret-agent. */
	priv->last_secret_agent_version_id = nm_agent_manager_get_agent_version_id (priv->agent_mgr);

	call_id_a = nm_agent_manager_get_secrets (priv->agent_mgr,
	                                          nm_dbus_object_get_path (NM_DBUS_OBJECT (self)),
	                                          nm_settings_connection_get_connection (self),
	                                          subject,
	                                          existing_secrets,
	                                          setting_name,
	                                          flags,
	                                          hints,
	                                          get_secrets_done_cb,
	                                          call_id);
	g_assert (call_id_a);
	if (existing_secrets)
		g_variant_unref (existing_secrets);

	_LOGD ("(%s:%p) secrets requested flags 0x%X hints '%s'",
	       setting_name,
	       call_id_a,
	       flags,
	       (hints && hints[0]) ? (joined_hints = g_strjoinv (",", (char **) hints)) : "(none)");

	if (call_id_a) {
		call_id->type = CALL_ID_TYPE_REQ;
		call_id->t.req.id = call_id_a;
	} else {
schedule_dummy:
		call_id->type = CALL_ID_TYPE_IDLE;
		g_propagate_error (&call_id->t.idle.error, local);
		call_id->t.idle.id = g_idle_add ((GSourceFunc) get_secrets_idle_cb, call_id);
	}
	return call_id;
}

static void
_get_secrets_cancel (NMSettingsConnection *self,
                     NMSettingsConnectionCallId *call_id,
                     gboolean is_disposing)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);
	gs_free_error GError *error = NULL;

	nm_assert (c_list_contains (&priv->call_ids_lst_head, &call_id->call_ids_lst));

	c_list_unlink (&call_id->call_ids_lst);

	if (call_id->type == CALL_ID_TYPE_REQ)
		nm_agent_manager_cancel_secrets (priv->agent_mgr, call_id->t.req.id);
	else
		g_source_remove (call_id->t.idle.id);

	nm_utils_error_set_cancelled (&error, is_disposing, "NMSettingsConnection");

	_get_secrets_info_callback (call_id, NULL, NULL, error);

	_get_secrets_info_free (call_id);
}

void
nm_settings_connection_cancel_secrets (NMSettingsConnection *self,
                                       NMSettingsConnectionCallId *call_id)
{
	_LOGD ("(%p) secrets canceled", call_id);

	_get_secrets_cancel (self, call_id, FALSE);
}

/*****************************************************************************/

typedef void (*AuthCallback) (NMSettingsConnection *self,
                              GDBusMethodInvocation *context,
                              NMAuthSubject *subject,
                              GError *error,
                              gpointer data);

typedef struct {
	CList auth_lst;
	NMAuthManagerCallId *call_id;
	NMSettingsConnection *self;
	AuthCallback callback;
	gpointer callback_data;
	GDBusMethodInvocation *invocation;
	NMAuthSubject *subject;
} AuthData;

static void
pk_auth_cb (NMAuthManager *auth_manager,
            NMAuthManagerCallId *auth_call_id,
            gboolean is_authorized,
            gboolean is_challenge,
            GError *auth_error,
            gpointer user_data)
{
	AuthData *auth_data = user_data;
	NMSettingsConnection *self;
	gs_free_error GError *error = NULL;

	nm_assert (auth_data);
	nm_assert (NM_IS_SETTINGS_CONNECTION (auth_data->self));

	self = auth_data->self;

	auth_data->call_id = NULL;

	c_list_unlink (&auth_data->auth_lst);

	if (g_error_matches (auth_error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		error = g_error_new (NM_SETTINGS_ERROR,
		                     NM_SETTINGS_ERROR_FAILED,
		                     "Error checking authorization: connection was deleted");
	} else if (auth_error) {
		error = g_error_new (NM_SETTINGS_ERROR,
		                     NM_SETTINGS_ERROR_FAILED,
		                     "Error checking authorization: %s",
		                     auth_error->message);
	} else if (nm_auth_call_result_eval (is_authorized, is_challenge, auth_error) != NM_AUTH_CALL_RESULT_YES) {
		error = g_error_new_literal (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_PERMISSION_DENIED,
		                             "Insufficient privileges");
	}

	auth_data->callback (self,
	                     auth_data->invocation,
	                     auth_data->subject,
	                     error,
	                     auth_data->callback_data);

	g_object_unref (auth_data->invocation);
	g_object_unref (auth_data->subject);
	g_slice_free (AuthData, auth_data);
}

/**
 * _new_auth_subject:
 * @context: the D-Bus method invocation context
 * @error: on failure, a #GError
 *
 * Creates an NMAuthSubject for the caller.
 *
 * Returns: the #NMAuthSubject on success, or %NULL on failure and sets @error
 */
static NMAuthSubject *
_new_auth_subject (GDBusMethodInvocation *context, GError **error)
{
	NMAuthSubject *subject;

	subject = nm_auth_subject_new_unix_process_from_context (context);
	if (!subject) {
		g_set_error_literal (error,
		                     NM_SETTINGS_ERROR,
		                     NM_SETTINGS_ERROR_PERMISSION_DENIED,
		                     "Unable to determine UID of request.");
	}

	return subject;
}

/* may either invoke callback synchronously or asynchronously. */
static void
auth_start (NMSettingsConnection *self,
            GDBusMethodInvocation *invocation,
            NMAuthSubject *subject,
            const char *check_permission,
            AuthCallback callback,
            gpointer callback_data)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);
	AuthData *auth_data;
	GError *error = NULL;

	nm_assert (nm_dbus_object_is_exported (NM_DBUS_OBJECT (self)));
	nm_assert (G_IS_DBUS_METHOD_INVOCATION (invocation));
	nm_assert (NM_IS_AUTH_SUBJECT (subject));

	if (!nm_auth_is_subject_in_acl_set_error (nm_settings_connection_get_connection (self),
	                                          subject,
	                                          NM_SETTINGS_ERROR,
	                                          NM_SETTINGS_ERROR_PERMISSION_DENIED,
	                                          &error)) {
		callback (self, invocation, subject, error, callback_data);
		g_clear_error (&error);
		return;
	}

	if (!check_permission) {
		/* Don't need polkit auth, automatic success */
		callback (self, invocation, subject, NULL, callback_data);
		return;
	}

	auth_data = g_slice_new (AuthData);
	auth_data->self = self;
	auth_data->callback = callback;
	auth_data->callback_data = callback_data;
	auth_data->invocation = g_object_ref (invocation);
	auth_data->subject = g_object_ref (subject);
	c_list_link_tail (&priv->auth_lst_head, &auth_data->auth_lst);
	auth_data->call_id = nm_auth_manager_check_authorization (nm_auth_manager_get (),
	                                                          subject,
	                                                          check_permission,
	                                                          TRUE,
	                                                          pk_auth_cb,
	                                                          auth_data);
}

/**** DBus method handlers ************************************/

static gboolean
check_writable (NMConnection *self, GError **error)
{
	NMSettingConnection *s_con;

	g_return_val_if_fail (NM_IS_CONNECTION (self), FALSE);

	s_con = nm_connection_get_setting_connection (self);
	if (!s_con) {
		g_set_error_literal (error,
		                     NM_SETTINGS_ERROR,
		                     NM_SETTINGS_ERROR_INVALID_CONNECTION,
		                     "Connection did not have required 'connection' setting");
		return FALSE;
	}

	/* If the connection is read-only, that has to be changed at the source of
	 * the problem (ex a system settings plugin that can't write connections out)
	 * instead of over D-Bus.
	 */
	if (nm_setting_connection_get_read_only (s_con)) {
		g_set_error_literal (error,
		                     NM_SETTINGS_ERROR,
		                     NM_SETTINGS_ERROR_READ_ONLY_CONNECTION,
		                     "Connection is read-only");
		return FALSE;
	}

	return TRUE;
}

static void
get_settings_auth_cb (NMSettingsConnection *self,
                      GDBusMethodInvocation *context,
                      NMAuthSubject *subject,
                      GError *error,
                      gpointer data)
{
	if (error)
		g_dbus_method_invocation_return_gerror (context, error);
	else {
		gs_unref_object NMConnection *dupl_con = NULL;
		GVariant *settings;
		NMSettingConnection *s_con;
		NMSettingWireless *s_wifi;
		guint64 timestamp = 0;
		gs_free char **bssids = NULL;

		dupl_con = nm_simple_connection_new_clone (nm_settings_connection_get_connection (self));

		/* Timestamp is not updated in connection's 'timestamp' property,
		 * because it would force updating the connection and in turn
		 * writing to /etc periodically, which we want to avoid. Rather real
		 * timestamps are kept track of in a private variable. So, substitute
		 * timestamp property with the real one here before returning the settings.
		 */
		nm_settings_connection_get_timestamp (self, &timestamp);
		if (timestamp) {
			s_con = nm_connection_get_setting_connection (dupl_con);
			g_object_set (s_con, NM_SETTING_CONNECTION_TIMESTAMP, timestamp, NULL);
		}
		/* Seen BSSIDs are not updated in 802-11-wireless 'seen-bssids' property
		 * from the same reason as timestamp. Thus we put it here to GetSettings()
		 * return settings too.
		 */
		bssids = nm_settings_connection_get_seen_bssids (self);
		s_wifi = nm_connection_get_setting_wireless (dupl_con);
		if (bssids && bssids[0] && s_wifi)
			g_object_set (s_wifi, NM_SETTING_WIRELESS_SEEN_BSSIDS, bssids, NULL);

		/* Secrets should *never* be returned by the GetSettings method, they
		 * get returned by the GetSecrets method which can be better
		 * protected against leakage of secrets to unprivileged callers.
		 */
		settings = nm_connection_to_dbus (dupl_con, NM_CONNECTION_SERIALIZE_NO_SECRETS);
		g_dbus_method_invocation_return_value (context,
		                                       g_variant_new ("(@a{sa{sv}})", settings));
	}
}

static void
impl_settings_connection_get_settings (NMDBusObject *obj,
                                       const NMDBusInterfaceInfoExtended *interface_info,
                                       const NMDBusMethodInfoExtended *method_info,
                                       GDBusConnection *connection,
                                       const char *sender,
                                       GDBusMethodInvocation *invocation,
                                       GVariant *parameters)
{
	NMSettingsConnection *self = NM_SETTINGS_CONNECTION (obj);
	gs_unref_object NMAuthSubject *subject = NULL;
	GError *error = NULL;

	subject = _new_auth_subject (invocation, &error);
	if (!subject) {
		g_dbus_method_invocation_take_error (invocation, error);
		return;
	}

	auth_start (self, invocation, subject, NULL, get_settings_auth_cb, NULL);
}

typedef struct {
	GDBusMethodInvocation *context;
	NMAgentManager *agent_mgr;
	NMAuthSubject *subject;
	NMConnection *new_settings;
	NMSettingsUpdate2Flags flags;
	char *audit_args;
	bool is_update2:1;
} UpdateInfo;

static void
cached_secrets_to_connection (NMSettingsConnection *self, NMConnection *connection)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);
	GVariant *secrets_dict;

	if (priv->agent_secrets) {
		secrets_dict = nm_connection_to_dbus (priv->agent_secrets, NM_CONNECTION_SERIALIZE_ONLY_SECRETS);
		if (secrets_dict) {
			(void) nm_connection_update_secrets (connection, NULL, secrets_dict, NULL);
			g_variant_unref (secrets_dict);
		}
	}
	if (priv->system_secrets) {
		secrets_dict = nm_connection_to_dbus (priv->system_secrets, NM_CONNECTION_SERIALIZE_ONLY_SECRETS);
		if (secrets_dict) {
			(void) nm_connection_update_secrets (connection, NULL, secrets_dict, NULL);
			g_variant_unref (secrets_dict);
		}
	}
}

static void
update_complete (NMSettingsConnection *self,
                 UpdateInfo *info,
                 GError *error)
{
	if (error)
		g_dbus_method_invocation_return_gerror (info->context, error);
	else if (info->is_update2) {
		GVariantBuilder result;

		g_variant_builder_init (&result, G_VARIANT_TYPE ("a{sv}"));
		g_dbus_method_invocation_return_value (info->context,
		                                       g_variant_new ("(@a{sv})", g_variant_builder_end (&result)));
	} else
		g_dbus_method_invocation_return_value (info->context, NULL);

	nm_audit_log_connection_op (NM_AUDIT_OP_CONN_UPDATE, self, !error, info->audit_args,
	                            info->subject, error ? error->message : NULL);

	g_clear_object (&info->subject);
	g_clear_object (&info->agent_mgr);
	g_clear_object (&info->new_settings);
	g_free (info->audit_args);
	g_slice_free (UpdateInfo, info);
}

static void
update_auth_cb (NMSettingsConnection *self,
                GDBusMethodInvocation *context,
                NMAuthSubject *subject,
                GError *error,
                gpointer data)
{
	UpdateInfo *info = data;
	NMSettingsConnectionCommitReason commit_reason;
	gs_free_error GError *local = NULL;
	NMSettingsConnectionPersistMode persist_mode;
	const char *log_diff_name;

	if (error) {
		update_complete (self, info, error);
		return;
	}

	if (info->new_settings) {
		if (!_nm_connection_aggregate (info->new_settings, NM_CONNECTION_AGGREGATE_ANY_SECRETS, NULL)) {
			/* If the new connection has no secrets, we do not want to remove all
			 * secrets, rather we keep all the existing ones. Do that by merging
			 * them in to the new connection.
			 */
			cached_secrets_to_connection (self, info->new_settings);
		} else {
			/* Cache the new secrets from the agent, as stuff like inotify-triggered
			 * changes to connection's backing config files will blow them away if
			 * they're in the main connection.
			 */
			update_agent_secrets_cache (self, info->new_settings);
		}
	}

	if (info->new_settings) {
		if (nm_audit_manager_audit_enabled (nm_audit_manager_get ())) {
			gs_unref_hashtable GHashTable *diff = NULL;
			gboolean same;

			same = nm_connection_diff (nm_settings_connection_get_connection (self), info->new_settings,
			                           NM_SETTING_COMPARE_FLAG_EXACT |
			                           NM_SETTING_COMPARE_FLAG_DIFF_RESULT_NO_DEFAULT,
			                           &diff);
			if (!same && diff)
				info->audit_args = nm_utils_format_con_diff_for_audit (diff);
		}
	}

	commit_reason = NM_SETTINGS_CONNECTION_COMMIT_REASON_USER_ACTION;
	if (   info->new_settings
	    && !nm_streq0 (nm_connection_get_id (nm_settings_connection_get_connection (self)),
	                   nm_connection_get_id (info->new_settings)))
		commit_reason |= NM_SETTINGS_CONNECTION_COMMIT_REASON_ID_CHANGED;

	if (NM_FLAGS_HAS (info->flags, NM_SETTINGS_UPDATE2_FLAG_TO_DISK))
		persist_mode = NM_SETTINGS_CONNECTION_PERSIST_MODE_DISK;
	else if (NM_FLAGS_HAS (info->flags, NM_SETTINGS_UPDATE2_FLAG_IN_MEMORY))
		persist_mode = NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY;
	else if (NM_FLAGS_HAS (info->flags, NM_SETTINGS_UPDATE2_FLAG_IN_MEMORY_DETACHED)) {
		persist_mode = NM_FLAGS_HAS (info->flags, NM_SETTINGS_UPDATE2_FLAG_VOLATILE)
		               ? NM_SETTINGS_CONNECTION_PERSIST_MODE_VOLATILE_DETACHED
		               : NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY_DETACHED;
	} else if (NM_FLAGS_HAS (info->flags, NM_SETTINGS_UPDATE2_FLAG_IN_MEMORY_ONLY)) {
		persist_mode = NM_FLAGS_HAS (info->flags, NM_SETTINGS_UPDATE2_FLAG_VOLATILE)
		               ? NM_SETTINGS_CONNECTION_PERSIST_MODE_VOLATILE_ONLY
		               : NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY_ONLY;
	} else
		persist_mode = NM_SETTINGS_CONNECTION_PERSIST_MODE_KEEP;

	if (   persist_mode == NM_SETTINGS_CONNECTION_PERSIST_MODE_DISK
	    || (   persist_mode == NM_SETTINGS_CONNECTION_PERSIST_MODE_KEEP
	        && !nm_settings_connection_get_unsaved (self)))
		log_diff_name = info->new_settings ? "update-settings" : "write-out-to-disk";
	else
		log_diff_name = info->new_settings ? "update-unsaved" : "make-unsaved";

	if (NM_FLAGS_HAS (info->flags, NM_SETTINGS_UPDATE2_FLAG_BLOCK_AUTOCONNECT)) {
		nm_settings_connection_autoconnect_blocked_reason_set (self,
		                                                       NM_SETTINGS_AUTO_CONNECT_BLOCKED_REASON_USER_REQUEST,
		                                                       TRUE);
	}

	nm_settings_connection_update (self,
	                               info->new_settings,
	                               persist_mode,
	                               commit_reason,
	                               log_diff_name,
	                               &local);

	if (!local) {
		gs_unref_object NMConnection *for_agent = NULL;

		/* Dupe the connection so we can clear out non-agent-owned secrets,
		 * as agent-owned secrets are the only ones we send back be saved.
		 * Only send secrets to agents of the same UID that called update too.
		 */
		for_agent = nm_simple_connection_new_clone (nm_settings_connection_get_connection (self));
		nm_connection_clear_secrets_with_flags (for_agent,
		                                        secrets_filter_cb,
		                                        GUINT_TO_POINTER (NM_SETTING_SECRET_FLAG_AGENT_OWNED));
		nm_agent_manager_save_secrets (info->agent_mgr,
		                               nm_dbus_object_get_path (NM_DBUS_OBJECT (self)),
		                               for_agent,
		                               info->subject);
	}

	update_complete (self, info, local);
}

static const char *
get_update_modify_permission (NMConnection *old, NMConnection *new)
{
	NMSettingConnection *s_con;
	guint32 orig_num = 0, new_num = 0;

	s_con = nm_connection_get_setting_connection (old);
	orig_num = nm_setting_connection_get_num_permissions (s_con);

	s_con = nm_connection_get_setting_connection (new);
	new_num = nm_setting_connection_get_num_permissions (s_con);

	/* If the caller is the only user in either connection's permissions, then
	 * we use the 'modify.own' permission instead of 'modify.system'.
	 */
	if (orig_num == 1 && new_num == 1)
		return NM_AUTH_PERMISSION_SETTINGS_MODIFY_OWN;

	/* If the update request affects more than just the caller (ie if the old
	 * settings were system-wide, or the new ones are), require 'modify.system'.
	 */
	return NM_AUTH_PERMISSION_SETTINGS_MODIFY_SYSTEM;
}

static void
settings_connection_update (NMSettingsConnection *self,
                            gboolean is_update2,
                            GDBusMethodInvocation *context,
                            GVariant *new_settings,
                            NMSettingsUpdate2Flags flags)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);
	NMAuthSubject *subject = NULL;
	NMConnection *tmp = NULL;
	GError *error = NULL;
	UpdateInfo *info;
	const char *permission;

	/* If the connection is read-only, that has to be changed at the source of
	 * the problem (ex a system settings plugin that can't write connections out)
	 * instead of over D-Bus.
	 */
	if (!check_writable (nm_settings_connection_get_connection (self), &error))
		goto error;

	/* Check if the settings are valid first */
	if (new_settings) {
		if (!g_variant_is_of_type (new_settings, NM_VARIANT_TYPE_CONNECTION)) {
			g_set_error_literal (&error,
			                     NM_SETTINGS_ERROR,
			                     NM_SETTINGS_ERROR_INVALID_ARGUMENTS,
			                     "settings is of invalid type");
			goto error;
		}

		if (g_variant_n_children (new_settings) > 0) {
			tmp = _nm_simple_connection_new_from_dbus (new_settings,
			                                             NM_SETTING_PARSE_FLAGS_STRICT
			                                           | NM_SETTING_PARSE_FLAGS_NORMALIZE,
			                                           &error);
			if (!tmp)
				goto error;

			if (!nm_connection_verify_secrets (tmp, &error))
				goto error;
		}
	}

	subject = _new_auth_subject (context, &error);
	if (!subject)
		goto error;

	/* And that the new connection settings will be visible to the user
	 * that's sending the update request.  You can't make a connection
	 * invisible to yourself.
	 */
	if (!nm_auth_is_subject_in_acl_set_error (tmp ?: nm_settings_connection_get_connection (self),
	                                          subject,
	                                          NM_SETTINGS_ERROR,
	                                          NM_SETTINGS_ERROR_PERMISSION_DENIED,
	                                          &error))
		goto error;

	info = g_slice_new0 (UpdateInfo);
	info->is_update2 = is_update2;
	info->context = context;
	info->agent_mgr = g_object_ref (priv->agent_mgr);
	info->subject = subject;
	info->flags = flags;
	info->new_settings = tmp;

	permission = get_update_modify_permission (nm_settings_connection_get_connection (self),
	                                           tmp ?: nm_settings_connection_get_connection (self));
	auth_start (self, context, subject, permission, update_auth_cb, info);
	return;

error:
	nm_audit_log_connection_op (NM_AUDIT_OP_CONN_UPDATE, self, FALSE, NULL, subject,
	                            error->message);

	g_clear_object (&tmp);
	g_clear_object (&subject);

	g_dbus_method_invocation_take_error (context, error);
}

static void
impl_settings_connection_update (NMDBusObject *obj,
                                 const NMDBusInterfaceInfoExtended *interface_info,
                                 const NMDBusMethodInfoExtended *method_info,
                                 GDBusConnection *connection,
                                 const char *sender,
                                 GDBusMethodInvocation *invocation,
                                 GVariant *parameters)
{
	NMSettingsConnection *self = NM_SETTINGS_CONNECTION (obj);
	gs_unref_variant GVariant *settings = NULL;

	g_variant_get (parameters, "(@a{sa{sv}})", &settings);
	settings_connection_update (self, FALSE, invocation, settings, NM_SETTINGS_UPDATE2_FLAG_TO_DISK);
}

static void
impl_settings_connection_update_unsaved (NMDBusObject *obj,
                                         const NMDBusInterfaceInfoExtended *interface_info,
                                         const NMDBusMethodInfoExtended *method_info,
                                         GDBusConnection *connection,
                                         const char *sender,
                                         GDBusMethodInvocation *invocation,
                                         GVariant *parameters)
{
	NMSettingsConnection *self = NM_SETTINGS_CONNECTION (obj);
	gs_unref_variant GVariant *settings = NULL;

	g_variant_get (parameters, "(@a{sa{sv}})", &settings);
	settings_connection_update (self, FALSE, invocation, settings, NM_SETTINGS_UPDATE2_FLAG_IN_MEMORY);
}

static void
impl_settings_connection_save (NMDBusObject *obj,
                               const NMDBusInterfaceInfoExtended *interface_info,
                               const NMDBusMethodInfoExtended *method_info,
                               GDBusConnection *connection,
                               const char *sender,
                               GDBusMethodInvocation *invocation,
                               GVariant *parameters)
{
	NMSettingsConnection *self = NM_SETTINGS_CONNECTION (obj);

	settings_connection_update (self, FALSE, invocation, NULL, NM_SETTINGS_UPDATE2_FLAG_TO_DISK);
}

static void
impl_settings_connection_update2 (NMDBusObject *obj,
                                  const NMDBusInterfaceInfoExtended *interface_info,
                                  const NMDBusMethodInfoExtended *method_info,
                                  GDBusConnection *connection,
                                  const char *sender,
                                  GDBusMethodInvocation *invocation,
                                  GVariant *parameters)
{
	NMSettingsConnection *self = NM_SETTINGS_CONNECTION (obj);
	gs_unref_variant GVariant *settings = NULL;
	gs_unref_variant GVariant *args = NULL;
	guint32 flags_u;
	GError *error = NULL;
	GVariantIter iter;
	const char *args_name;
	NMSettingsUpdate2Flags flags;
	const NMSettingsUpdate2Flags ALL_PERSIST_MODES =   NM_SETTINGS_UPDATE2_FLAG_TO_DISK
	                                                 | NM_SETTINGS_UPDATE2_FLAG_IN_MEMORY
	                                                 | NM_SETTINGS_UPDATE2_FLAG_IN_MEMORY_DETACHED
	                                                 | NM_SETTINGS_UPDATE2_FLAG_IN_MEMORY_ONLY;

	g_variant_get (parameters, "(@a{sa{sv}}u@a{sv})", &settings, &flags_u, &args);

	if (NM_FLAGS_ANY (flags_u, ~((guint32) (ALL_PERSIST_MODES |
	                                        NM_SETTINGS_UPDATE2_FLAG_VOLATILE |
	                                        NM_SETTINGS_UPDATE2_FLAG_BLOCK_AUTOCONNECT)))) {
		error = g_error_new_literal (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_INVALID_ARGUMENTS,
		                             "Unknown flags");
		g_dbus_method_invocation_take_error (invocation, error);
		return;
	}

	flags = (NMSettingsUpdate2Flags) flags_u;

	if (   (   NM_FLAGS_ANY (flags, ALL_PERSIST_MODES)
	        && !nm_utils_is_power_of_two (flags & ALL_PERSIST_MODES))
	    || (   NM_FLAGS_HAS (flags, NM_SETTINGS_UPDATE2_FLAG_VOLATILE)
	        && !NM_FLAGS_ANY (flags, NM_SETTINGS_UPDATE2_FLAG_IN_MEMORY_DETACHED |
	                                 NM_SETTINGS_UPDATE2_FLAG_IN_MEMORY_ONLY))) {
		error = g_error_new_literal (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_INVALID_ARGUMENTS,
		                             "Conflicting flags");
		g_dbus_method_invocation_take_error (invocation, error);
		return;
	}

	if (!g_variant_is_of_type (args, G_VARIANT_TYPE ("a{sv}"))) {
		error = g_error_new_literal (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_INVALID_ARGUMENTS,
		                             "args is of invalid type");
		g_dbus_method_invocation_take_error (invocation, error);
		return;
	}

	g_variant_iter_init (&iter, args);
	while (g_variant_iter_next (&iter, "{&sv}", &args_name, NULL)) {
		error = g_error_new (NM_SETTINGS_ERROR,
		                     NM_SETTINGS_ERROR_INVALID_ARGUMENTS,
		                     "Unsupported argument '%s'", args_name);
		g_dbus_method_invocation_take_error (invocation, error);
		return;
	}

	settings_connection_update (self,
	                            TRUE,
	                            invocation,
	                            settings,
	                            flags);
}

static void
delete_auth_cb (NMSettingsConnection *self,
                GDBusMethodInvocation *context,
                NMAuthSubject *subject,
                GError *error,
                gpointer data)
{
	gs_unref_object NMSettingsConnection *self_keep_alive = NULL;
	gs_free_error GError *local = NULL;

	self_keep_alive = g_object_ref (self);

	if (error) {
		nm_audit_log_connection_op (NM_AUDIT_OP_CONN_DELETE, self, FALSE, NULL, subject,
		                            error->message);
		g_dbus_method_invocation_return_gerror (context, error);
		return;
	}

	nm_settings_connection_delete (self, &local);

	nm_audit_log_connection_op (NM_AUDIT_OP_CONN_DELETE, self,
	                            !local, NULL, subject, local ? local->message : NULL);

	if (local)
		g_dbus_method_invocation_return_gerror (context, local);
	else
		g_dbus_method_invocation_return_value (context, NULL);
}

static const char *
get_modify_permission_basic (NMSettingsConnection *self)
{
	NMSettingConnection *s_con;

	/* If the caller is the only user in the connection's permissions, then
	 * we use the 'modify.own' permission instead of 'modify.system'.  If the
	 * request affects more than just the caller, require 'modify.system'.
	 */
	s_con = nm_connection_get_setting_connection (nm_settings_connection_get_connection (self));
	if (nm_setting_connection_get_num_permissions (s_con) == 1)
		return NM_AUTH_PERMISSION_SETTINGS_MODIFY_OWN;

	return NM_AUTH_PERMISSION_SETTINGS_MODIFY_SYSTEM;
}

static void
impl_settings_connection_delete (NMDBusObject *obj,
                                 const NMDBusInterfaceInfoExtended *interface_info,
                                 const NMDBusMethodInfoExtended *method_info,
                                 GDBusConnection *connection,
                                 const char *sender,
                                 GDBusMethodInvocation *invocation,
                                 GVariant *parameters)
{
	NMSettingsConnection *self = NM_SETTINGS_CONNECTION (obj);
	gs_unref_object NMAuthSubject *subject = NULL;
	GError *error = NULL;

	if (!check_writable (nm_settings_connection_get_connection (self), &error))
		goto err;

	subject = _new_auth_subject (invocation, &error);
	if (!subject)
		goto err;

	auth_start (self, invocation, subject, get_modify_permission_basic (self), delete_auth_cb, NULL);
	return;
err:
	nm_audit_log_connection_op (NM_AUDIT_OP_CONN_DELETE, self, FALSE, NULL, subject, error->message);
	g_dbus_method_invocation_take_error (invocation, error);
}

/*****************************************************************************/

static void
dbus_get_agent_secrets_cb (NMSettingsConnection *self,
                           NMSettingsConnectionCallId *call_id,
                           const char *agent_username,
                           const char *setting_name,
                           GError *error,
                           gpointer user_data)
{
	GDBusMethodInvocation *context = user_data;
	GVariant *dict;

	if (error)
		g_dbus_method_invocation_return_gerror (context, error);
	else {
		/* Return secrets from agent and backing storage to the D-Bus caller;
		 * nm_settings_connection_get_secrets() will have updated itself with
		 * secrets from backing storage and those returned from the agent
		 * by the time we get here.
		 */
		dict = nm_connection_to_dbus (nm_settings_connection_get_connection (self), NM_CONNECTION_SERIALIZE_ONLY_SECRETS);
		if (!dict)
			dict = g_variant_new_array (G_VARIANT_TYPE ("{sa{sv}}"), NULL, 0);
		g_dbus_method_invocation_return_value (context, g_variant_new ("(@a{sa{sv}})", dict));
	}
}

static void
dbus_get_secrets_auth_cb (NMSettingsConnection *self,
                          GDBusMethodInvocation *context,
                          NMAuthSubject *subject,
                          GError *error,
                          gpointer user_data)
{
	char *setting_name = user_data;

	if (!error) {
		nm_settings_connection_get_secrets (self,
		                                    NULL,
		                                    subject,
		                                    setting_name,
		                                    NM_SECRET_AGENT_GET_SECRETS_FLAG_USER_REQUESTED
		                                      | NM_SECRET_AGENT_GET_SECRETS_FLAG_NO_ERRORS,
		                                    NULL,
		                                    dbus_get_agent_secrets_cb,
		                                    context);
	}

	if (error)
		g_dbus_method_invocation_return_gerror (context, error);

	g_free (setting_name);
}

static void
impl_settings_connection_get_secrets (NMDBusObject *obj,
                                      const NMDBusInterfaceInfoExtended *interface_info,
                                      const NMDBusMethodInfoExtended *method_info,
                                      GDBusConnection *connection,
                                      const char *sender,
                                      GDBusMethodInvocation *invocation,
                                      GVariant *parameters)
{
	NMSettingsConnection *self = NM_SETTINGS_CONNECTION (obj);
	gs_unref_object NMAuthSubject *subject = NULL;
	GError *error = NULL;
	const char *setting_name;

	subject = _new_auth_subject (invocation, &error);
	if (!subject) {
		g_dbus_method_invocation_take_error (invocation, error);
		return;
	}

	g_variant_get (parameters, "(&s)", &setting_name);

	auth_start (self,
	            invocation,
	            subject,
	            get_modify_permission_basic (self),
	            dbus_get_secrets_auth_cb,
	            g_strdup (setting_name));
}

static void
dbus_clear_secrets_auth_cb (NMSettingsConnection *self,
                            GDBusMethodInvocation *context,
                            NMAuthSubject *subject,
                            GError *error,
                            gpointer user_data)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);
	gs_free_error GError *local = NULL;

	if (error) {
		g_dbus_method_invocation_return_gerror (context, error);
		nm_audit_log_connection_op (NM_AUDIT_OP_CONN_CLEAR_SECRETS, self,
		                            FALSE, NULL, subject, error->message);
		return;
	}

	/* Clear secrets in connection and caches */
	nm_connection_clear_secrets (nm_settings_connection_get_connection (self));
	if (priv->system_secrets)
		nm_connection_clear_secrets (priv->system_secrets);
	if (priv->agent_secrets)
		nm_connection_clear_secrets (priv->agent_secrets);

	/* Tell agents to remove secrets for this connection */
	nm_agent_manager_delete_secrets (priv->agent_mgr,
	                                 nm_dbus_object_get_path (NM_DBUS_OBJECT (self)),
	                                 nm_settings_connection_get_connection (self));

	nm_settings_connection_update (self,
	                               NULL,
	                               NM_SETTINGS_CONNECTION_PERSIST_MODE_DISK,
	                               NM_SETTINGS_CONNECTION_COMMIT_REASON_NONE,
	                               "clear-secrets",
	                               &local);

	nm_audit_log_connection_op (NM_AUDIT_OP_CONN_CLEAR_SECRETS, self,
	                            !local, NULL, subject, local ? local->message : NULL);

	if (local)
		g_dbus_method_invocation_return_gerror (context, local);
	else
		g_dbus_method_invocation_return_value (context, NULL);
}

static void
impl_settings_connection_clear_secrets (NMDBusObject *obj,
                                        const NMDBusInterfaceInfoExtended *interface_info,
                                        const NMDBusMethodInfoExtended *method_info,
                                        GDBusConnection *connection,
                                        const char *sender,
                                        GDBusMethodInvocation *invocation,
                                        GVariant *parameters)
{
	NMSettingsConnection *self = NM_SETTINGS_CONNECTION (obj);
	gs_unref_object NMAuthSubject *subject = NULL;
	GError *error = NULL;

	subject = _new_auth_subject (invocation, &error);
	if (!subject) {
		nm_audit_log_connection_op (NM_AUDIT_OP_CONN_CLEAR_SECRETS, self,
		                            FALSE, NULL, NULL, error->message);
		g_dbus_method_invocation_take_error (invocation, error);
		return;
	}
	auth_start (self,
	            invocation,
	            subject,
	            get_modify_permission_basic (self),
	            dbus_clear_secrets_auth_cb,
	            NULL);
}

/*****************************************************************************/

void
nm_settings_connection_added (NMSettingsConnection *self)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);

	/* FIXME: we should always dispose connections that are removed
	 * and not reuse them, but currently plugins keep alive unmanaged
	 * (e.g. NM_CONTROLLED=no) connections. */
	priv->removed = FALSE;
}

void
nm_settings_connection_signal_remove (NMSettingsConnection *self)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);
	AuthData *auth_data;

	if (priv->removed)
		return;
	priv->removed = TRUE;

	while ((auth_data = c_list_first_entry (&priv->auth_lst_head, AuthData, auth_lst)))
		nm_auth_manager_check_authorization_cancel (auth_data->call_id);

	nm_dbus_object_emit_signal (NM_DBUS_OBJECT (self),
	                            &interface_info_settings_connection,
	                            &signal_info_removed,
	                            "()");
	g_signal_emit (self, signals[REMOVED], 0);
}

gboolean
nm_settings_connection_get_unsaved (NMSettingsConnection *self)
{
	return NM_FLAGS_HAS (nm_settings_connection_get_flags (self), NM_SETTINGS_CONNECTION_INT_FLAGS_UNSAVED);
}

/*****************************************************************************/

NM_UTILS_FLAGS2STR_DEFINE_STATIC (_settings_connection_flags_to_string, NMSettingsConnectionIntFlags,
	NM_UTILS_FLAGS2STR (NM_SETTINGS_CONNECTION_INT_FLAGS_NONE,          "none"),
	NM_UTILS_FLAGS2STR (NM_SETTINGS_CONNECTION_INT_FLAGS_UNSAVED,       "unsaved"),
	NM_UTILS_FLAGS2STR (NM_SETTINGS_CONNECTION_INT_FLAGS_NM_GENERATED,  "nm-generated"),
	NM_UTILS_FLAGS2STR (NM_SETTINGS_CONNECTION_INT_FLAGS_VOLATILE,      "volatile"),
	NM_UTILS_FLAGS2STR (NM_SETTINGS_CONNECTION_INT_FLAGS_VISIBLE,       "visible"),
);

NMSettingsConnectionIntFlags
nm_settings_connection_get_flags (NMSettingsConnection *self)
{
	g_return_val_if_fail (NM_IS_SETTINGS_CONNECTION (self), NM_SETTINGS_CONNECTION_INT_FLAGS_NONE);

	return NM_SETTINGS_CONNECTION_GET_PRIVATE (self)->flags;
}

NMSettingsConnectionIntFlags
nm_settings_connection_set_flags (NMSettingsConnection *self, NMSettingsConnectionIntFlags flags, gboolean set)
{
	return nm_settings_connection_set_flags_full (self,
	                                              flags,
	                                              set ? flags : NM_SETTINGS_CONNECTION_INT_FLAGS_NONE);
}

NMSettingsConnectionIntFlags
nm_settings_connection_set_flags_full (NMSettingsConnection *self,
                                       NMSettingsConnectionIntFlags mask,
                                       NMSettingsConnectionIntFlags value)
{
	NMSettingsConnectionPrivate *priv;
	NMSettingsConnectionIntFlags old_flags;

	g_return_val_if_fail (NM_IS_SETTINGS_CONNECTION (self), NM_SETTINGS_CONNECTION_INT_FLAGS_NONE);
	nm_assert (mask && !NM_FLAGS_ANY (mask, ~NM_SETTINGS_CONNECTION_INT_FLAGS_ALL));
	nm_assert (!NM_FLAGS_ANY (value, ~mask));

	priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);

	value = (priv->flags & ~mask) | value;

	old_flags = priv->flags;
	if (old_flags != value) {
		gboolean notify_unsaved = FALSE;
		char buf1[255], buf2[255];

		_LOGT ("update settings-connection flags to %s (was %s)",
		       _settings_connection_flags_to_string (value, buf1, sizeof (buf1)),
		       _settings_connection_flags_to_string (priv->flags, buf2, sizeof (buf2)));
		priv->flags = value;
		nm_assert (priv->flags == value);

		if (NM_FLAGS_HAS (old_flags, NM_SETTINGS_CONNECTION_INT_FLAGS_UNSAVED) != NM_FLAGS_HAS (value, NM_SETTINGS_CONNECTION_INT_FLAGS_UNSAVED)) {
			g_object_freeze_notify (G_OBJECT (self));
			_notify (self, PROP_UNSAVED);
			notify_unsaved = TRUE;
		}
		_notify (self, PROP_FLAGS);
		if (notify_unsaved)
			g_object_thaw_notify (G_OBJECT (self));

		g_signal_emit (self, signals[FLAGS_CHANGED], 0);
	}
	return old_flags;
}

/*****************************************************************************/

static int
_cmp_timestamp (NMSettingsConnection *a, NMSettingsConnection *b)
{
	gboolean a_has_ts, b_has_ts;
	guint64 ats = 0, bts = 0;

	nm_assert (NM_IS_SETTINGS_CONNECTION (a));
	nm_assert (NM_IS_SETTINGS_CONNECTION (b));

	a_has_ts = !!nm_settings_connection_get_timestamp (a, &ats);
	b_has_ts = !!nm_settings_connection_get_timestamp (b, &bts);
	if (a_has_ts != b_has_ts)
		return a_has_ts ? -1 : 1;
	if (a_has_ts && ats != bts)
		return (ats > bts) ? -1 : 1;
	return 0;
}

static int
_cmp_last_resort (NMSettingsConnection *a, NMSettingsConnection *b)
{
	NM_CMP_DIRECT_STRCMP0 (nm_settings_connection_get_uuid (a),
	                       nm_settings_connection_get_uuid (b));

	/* hm, same UUID. Use their pointer value to give them a stable
	 * order. */
	return (a > b) ? -1 : 1;
}

/* sorting for "best" connections.
 * The function sorts connections in descending timestamp order.
 * That means an older connection (lower timestamp) goes after
 * a newer one.
 */
int
nm_settings_connection_cmp_timestamp (NMSettingsConnection *a, NMSettingsConnection *b)
{
	NM_CMP_SELF (a, b);

	NM_CMP_RETURN (_cmp_timestamp (a, b));
	NM_CMP_RETURN (nm_utils_cmp_connection_by_autoconnect_priority (nm_settings_connection_get_connection (a),
	                                                                nm_settings_connection_get_connection (b)));
	return _cmp_last_resort (a, b);
}

int
nm_settings_connection_cmp_timestamp_p_with_data (gconstpointer pa, gconstpointer pb, gpointer user_data)
{
	return nm_settings_connection_cmp_timestamp (*((NMSettingsConnection **) pa),
	                                             *((NMSettingsConnection **) pb));
}

int
nm_settings_connection_cmp_autoconnect_priority (NMSettingsConnection *a, NMSettingsConnection *b)
{
	if (a == b)
		return 0;
	NM_CMP_RETURN (nm_utils_cmp_connection_by_autoconnect_priority (nm_settings_connection_get_connection (a),
	                                                                nm_settings_connection_get_connection (b)));
	NM_CMP_RETURN (_cmp_timestamp (a, b));
	return _cmp_last_resort (a, b);
}

int
nm_settings_connection_cmp_autoconnect_priority_p_with_data (gconstpointer pa, gconstpointer pb, gpointer user_data)
{
	return nm_settings_connection_cmp_autoconnect_priority (*((NMSettingsConnection **) pa),
	                                                        *((NMSettingsConnection **) pb));
}

/*****************************************************************************/

/**
 * nm_settings_connection_get_timestamp:
 * @self: the #NMSettingsConnection
 * @out_timestamp: the connection's timestamp
 *
 * Returns the time (in seconds since the Unix epoch) when the connection
 * was last successfully activated.
 *
 * Returns: %TRUE if the timestamp has ever been set, otherwise %FALSE.
 **/
gboolean
nm_settings_connection_get_timestamp (NMSettingsConnection *self,
                                      guint64 *out_timestamp)
{
	g_return_val_if_fail (NM_IS_SETTINGS_CONNECTION (self), FALSE);

	if (out_timestamp)
		*out_timestamp = NM_SETTINGS_CONNECTION_GET_PRIVATE (self)->timestamp;
	return NM_SETTINGS_CONNECTION_GET_PRIVATE (self)->timestamp_set;
}

/**
 * nm_settings_connection_update_timestamp:
 * @self: the #NMSettingsConnection
 * @timestamp: timestamp to set into the connection and to store into
 * the timestamps database
 * @flush_to_disk: if %TRUE, commit timestamp update to persistent storage
 *
 * Updates the connection and timestamps database with the provided timestamp.
 **/
void
nm_settings_connection_update_timestamp (NMSettingsConnection *self,
                                         guint64 timestamp,
                                         gboolean flush_to_disk)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);
	const char *connection_uuid;
	GKeyFile *timestamps_file;
	char *data, *tmp;
	gsize len;
	GError *error = NULL;

	g_return_if_fail (NM_IS_SETTINGS_CONNECTION (self));

	/* Update timestamp in private storage */
	priv->timestamp = timestamp;
	priv->timestamp_set = TRUE;

	if (flush_to_disk == FALSE)
		return;
	if (nm_config_get_configure_and_quit (nm_config_get ()) == NM_CONFIG_CONFIGURE_AND_QUIT_INITRD)
		return;

	/* Save timestamp to timestamps database file */
	timestamps_file = g_key_file_new ();
	if (!g_key_file_load_from_file (timestamps_file, SETTINGS_TIMESTAMPS_FILE, G_KEY_FILE_KEEP_COMMENTS, &error)) {
		if (!g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
			_LOGW ("error parsing timestamps file '%s': %s", SETTINGS_TIMESTAMPS_FILE, error->message);
		g_clear_error (&error);
	}

	connection_uuid = nm_settings_connection_get_uuid (self);
	tmp = g_strdup_printf ("%" G_GUINT64_FORMAT, timestamp);
	g_key_file_set_value (timestamps_file, "timestamps", connection_uuid, tmp);
	g_free (tmp);

	data = g_key_file_to_data (timestamps_file, &len, &error);
	if (data) {
		g_file_set_contents (SETTINGS_TIMESTAMPS_FILE, data, len, &error);
		g_free (data);
	}
	if (error) {
		_LOGW ("error saving timestamp to file '%s': %s", SETTINGS_TIMESTAMPS_FILE, error->message);
		g_error_free (error);
	}
	g_key_file_free (timestamps_file);
}

/**
 * nm_settings_connection_read_and_fill_timestamp:
 * @self: the #NMSettingsConnection
 *
 * Retrieves timestamp of the connection's last usage from database file and
 * stores it into the connection private data.
 **/
void
nm_settings_connection_read_and_fill_timestamp (NMSettingsConnection *self)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);
	gs_unref_keyfile GKeyFile *timestamps_file = NULL;
	gs_free_error GError *error = NULL;
	gs_free char *tmp_str = NULL;
	const char *connection_uuid;
	gint64 timestamp;

	g_return_if_fail (NM_IS_SETTINGS_CONNECTION (self));

	timestamps_file = g_key_file_new ();
	if (!g_key_file_load_from_file (timestamps_file, SETTINGS_TIMESTAMPS_FILE, G_KEY_FILE_KEEP_COMMENTS, &error)) {
		_LOGD ("failed to read connection timestamp: %s", error->message);
		return;
	}

	connection_uuid = nm_settings_connection_get_uuid (self);
	tmp_str = g_key_file_get_value (timestamps_file, "timestamps", connection_uuid, &error);
	if (!tmp_str) {
		_LOGD ("failed to read connection timestamp: %s", error->message);
		return;
	}

	timestamp = _nm_utils_ascii_str_to_int64 (tmp_str, 10, 0, G_MAXINT64, -1);
	if (timestamp < 0) {
		_LOGD ("failed to read connection timestamp: %s", "invalid number");
		return;
	}

	priv->timestamp = timestamp;
	priv->timestamp_set = TRUE;
}

/**
 * nm_settings_connection_get_seen_bssids:
 * @self: the #NMSettingsConnection
 *
 * Returns current list of seen BSSIDs for the connection.
 *
 * Returns: (transfer container) list of seen BSSIDs (in the standard hex-digits-and-colons notation).
 * The caller is responsible for freeing the list, but not the content.
 **/
char **
nm_settings_connection_get_seen_bssids (NMSettingsConnection *self)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);
	GHashTableIter iter;
	char **bssids, *bssid;
	int i;

	g_return_val_if_fail (NM_IS_SETTINGS_CONNECTION (self), NULL);

	bssids = g_new (char *, g_hash_table_size (priv->seen_bssids) + 1);

	i = 0;
	g_hash_table_iter_init (&iter, priv->seen_bssids);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer) &bssid))
		bssids[i++] = bssid;
	bssids[i] = NULL;

	return bssids;
}

/**
 * nm_settings_connection_has_seen_bssid:
 * @self: the #NMSettingsConnection
 * @bssid: the BSSID to check the seen BSSID list for
 *
 * Returns: %TRUE if the given @bssid is in the seen BSSIDs list
 **/
gboolean
nm_settings_connection_has_seen_bssid (NMSettingsConnection *self,
                                       const char *bssid)
{
	g_return_val_if_fail (NM_IS_SETTINGS_CONNECTION (self), FALSE);
	g_return_val_if_fail (bssid != NULL, FALSE);

	return !!g_hash_table_lookup (NM_SETTINGS_CONNECTION_GET_PRIVATE (self)->seen_bssids, bssid);
}

/**
 * nm_settings_connection_add_seen_bssid:
 * @self: the #NMSettingsConnection
 * @seen_bssid: BSSID to set into the connection and to store into
 * the seen-bssids database
 *
 * Updates the connection and seen-bssids database with the provided BSSID.
 **/
void
nm_settings_connection_add_seen_bssid (NMSettingsConnection *self,
                                       const char *seen_bssid)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);
	const char *connection_uuid;
	GKeyFile *seen_bssids_file;
	char *data, *bssid_str;
	const char **list;
	gsize len;
	GError *error = NULL;
	GHashTableIter iter;
	guint n;

	g_return_if_fail (seen_bssid != NULL);

	if (g_hash_table_lookup (priv->seen_bssids, seen_bssid))
		return;  /* Already in the list */

	/* Add the new BSSID; let the hash take ownership of the allocated BSSID string */
	bssid_str = g_strdup (seen_bssid);
	g_hash_table_insert (priv->seen_bssids, bssid_str, bssid_str);

	/* Build up a list of all the BSSIDs in string form */
	n = 0;
	list = g_malloc0 (g_hash_table_size (priv->seen_bssids) * sizeof (char *));
	g_hash_table_iter_init (&iter, priv->seen_bssids);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer) &bssid_str))
		list[n++] = bssid_str;

	/* Save BSSID to seen-bssids file */
	seen_bssids_file = g_key_file_new ();
	g_key_file_set_list_separator (seen_bssids_file, ',');
	if (!g_key_file_load_from_file (seen_bssids_file, SETTINGS_SEEN_BSSIDS_FILE, G_KEY_FILE_KEEP_COMMENTS, &error)) {
		if (!g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_NOENT)) {
			_LOGW ("error parsing seen-bssids file '%s': %s",
			       SETTINGS_SEEN_BSSIDS_FILE, error->message);
		}
		g_clear_error (&error);
	}

	connection_uuid = nm_settings_connection_get_uuid (self);
	g_key_file_set_string_list (seen_bssids_file, "seen-bssids", connection_uuid, list, n);
	g_free (list);

	data = g_key_file_to_data (seen_bssids_file, &len, &error);
	if (data) {
		g_file_set_contents (SETTINGS_SEEN_BSSIDS_FILE, data, len, &error);
		g_free (data);
	}
	g_key_file_free (seen_bssids_file);

	if (error) {
		_LOGW ("error saving seen-bssids to file '%s': %s",
		       SETTINGS_SEEN_BSSIDS_FILE, error->message);
		g_error_free (error);
	}
}

/**
 * nm_settings_connection_read_and_fill_seen_bssids:
 * @self: the #NMSettingsConnection
 *
 * Retrieves seen BSSIDs of the connection from database file and stores then into the
 * connection private data.
 **/
void
nm_settings_connection_read_and_fill_seen_bssids (NMSettingsConnection *self)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);
	const char *connection_uuid;
	GKeyFile *seen_bssids_file;
	char **tmp_strv = NULL;
	gsize i, len = 0;
	NMSettingWireless *s_wifi;

	/* Get seen BSSIDs from database file */
	seen_bssids_file = g_key_file_new ();
	g_key_file_set_list_separator (seen_bssids_file, ',');
	if (g_key_file_load_from_file (seen_bssids_file, SETTINGS_SEEN_BSSIDS_FILE, G_KEY_FILE_KEEP_COMMENTS, NULL)) {
		connection_uuid = nm_settings_connection_get_uuid (self);
		tmp_strv = g_key_file_get_string_list (seen_bssids_file, "seen-bssids", connection_uuid, &len, NULL);
	}
	g_key_file_free (seen_bssids_file);

	/* Update connection's seen-bssids */
	if (tmp_strv) {
		g_hash_table_remove_all (priv->seen_bssids);
		for (i = 0; i < len; i++)
			g_hash_table_insert (priv->seen_bssids, tmp_strv[i], tmp_strv[i]);
		g_free (tmp_strv);
	} else {
		/* If this connection didn't have an entry in the seen-bssids database,
		 * maybe this is the first time we've read it in, so populate the
		 * seen-bssids list from the deprecated seen-bssids property of the
		 * wifi setting.
		 */
		s_wifi = nm_connection_get_setting_wireless (nm_settings_connection_get_connection (self));
		if (s_wifi) {
			len = nm_setting_wireless_get_num_seen_bssids (s_wifi);
			for (i = 0; i < len; i++) {
				char *bssid_dup = g_strdup (nm_setting_wireless_get_seen_bssid (s_wifi, i));

				g_hash_table_insert (priv->seen_bssids, bssid_dup, bssid_dup);
			}
		}
	}
}

/*****************************************************************************/

static int
_autoconnect_retries_initial (NMSettingsConnection *self)
{
	NMSettingConnection *s_con;
	int retries = -1;

	s_con = nm_connection_get_setting_connection (nm_settings_connection_get_connection (self));
	if (s_con)
		retries = nm_setting_connection_get_autoconnect_retries (s_con);

	/* -1 means 'default' */
	if (retries == -1)
		retries = nm_config_data_get_autoconnect_retries_default (NM_CONFIG_GET_DATA);

	/* 0 means 'forever', which is translated to a retry count of -1 */
	if (retries == 0)
		retries = AUTOCONNECT_RETRIES_FOREVER;

	nm_assert (retries == AUTOCONNECT_RETRIES_FOREVER || retries >= 0);
	return retries;
}

static void
_autoconnect_retries_set (NMSettingsConnection *self,
                          int retries,
                          gboolean is_reset)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);

	g_return_if_fail (retries == AUTOCONNECT_RETRIES_FOREVER || retries >= 0);

	if (priv->autoconnect_retries != retries) {
		_LOGT ("autoconnect: retries set %d%s", retries,
		       is_reset ? " (reset)" : "");
		priv->autoconnect_retries = retries;
	}

	if (retries)
		priv->autoconnect_retries_blocked_until = 0;
	else {
		/* NOTE: the blocked time must be identical for all connections, otherwise
		 * the tracking of resetting the retry count in NMPolicy needs adjustment
		 * in _connection_autoconnect_retries_set() (as it would need to re-evaluate
		 * the next-timeout every time a connection gets blocked). */
		priv->autoconnect_retries_blocked_until = nm_utils_get_monotonic_timestamp_s () + AUTOCONNECT_RESET_RETRIES_TIMER;
	}
}

/**
 * nm_settings_connection_autoconnect_retries_get:
 * @self: the settings connection
 *
 * Returns the number of autoconnect retries left. If the value is
 * not yet set, initialize it with the value from the connection or
 * with the global default.
 */
int
nm_settings_connection_autoconnect_retries_get (NMSettingsConnection *self)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);

	if (G_UNLIKELY (priv->autoconnect_retries == AUTOCONNECT_RETRIES_UNSET)) {
		_autoconnect_retries_set (self,
		                          _autoconnect_retries_initial (self),
		                          TRUE);
	}
	return priv->autoconnect_retries;
}

void
nm_settings_connection_autoconnect_retries_set (NMSettingsConnection *self,
                                                int retries)
{
	g_return_if_fail (NM_IS_SETTINGS_CONNECTION (self));
	g_return_if_fail (retries >= 0);

	_autoconnect_retries_set (self, retries, FALSE);
}

void
nm_settings_connection_autoconnect_retries_reset (NMSettingsConnection *self)
{
	g_return_if_fail (NM_IS_SETTINGS_CONNECTION (self));

	_autoconnect_retries_set (self,
	                          _autoconnect_retries_initial (self),
	                          TRUE);
}

gint32
nm_settings_connection_autoconnect_retries_blocked_until (NMSettingsConnection *self)
{
	return NM_SETTINGS_CONNECTION_GET_PRIVATE (self)->autoconnect_retries_blocked_until;
}

NM_UTILS_FLAGS2STR_DEFINE_STATIC (_autoconnect_blocked_reason_to_string, NMSettingsAutoconnectBlockedReason,
	NM_UTILS_FLAGS2STR (NM_SETTINGS_AUTO_CONNECT_BLOCKED_REASON_NONE, "none"),
	NM_UTILS_FLAGS2STR (NM_SETTINGS_AUTO_CONNECT_BLOCKED_REASON_USER_REQUEST, "user-request"),
	NM_UTILS_FLAGS2STR (NM_SETTINGS_AUTO_CONNECT_BLOCKED_REASON_FAILED, "failed"),
	NM_UTILS_FLAGS2STR (NM_SETTINGS_AUTO_CONNECT_BLOCKED_REASON_NO_SECRETS, "no-secrets"),
);

NMSettingsAutoconnectBlockedReason
nm_settings_connection_autoconnect_blocked_reason_get (NMSettingsConnection *self, NMSettingsAutoconnectBlockedReason mask)
{
	return NM_SETTINGS_CONNECTION_GET_PRIVATE (self)->autoconnect_blocked_reason & (mask ?: NM_SETTINGS_AUTO_CONNECT_BLOCKED_REASON_ALL);
}

gboolean
nm_settings_connection_autoconnect_blocked_reason_set_full (NMSettingsConnection *self,
                                                            NMSettingsAutoconnectBlockedReason mask,
                                                            NMSettingsAutoconnectBlockedReason value)
{
	NMSettingsAutoconnectBlockedReason v;
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);
	char buf[100];

	nm_assert (mask);
	nm_assert (!NM_FLAGS_ANY (value, ~mask));

	v = priv->autoconnect_blocked_reason;
	v = (v & ~mask) | (value & mask);

	if (priv->autoconnect_blocked_reason == v)
		return FALSE;

	_LOGT ("autoconnect: blocked reason: %s", _autoconnect_blocked_reason_to_string (v, buf, sizeof (buf)));
	priv->autoconnect_blocked_reason = v;
	return TRUE;
}

gboolean
nm_settings_connection_autoconnect_is_blocked (NMSettingsConnection *self)
{
	NMSettingsConnectionPrivate *priv;
	NMSettingsConnectionIntFlags flags;

	g_return_val_if_fail (NM_IS_SETTINGS_CONNECTION (self), TRUE);

	priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);

	if (priv->autoconnect_blocked_reason != NM_SETTINGS_AUTO_CONNECT_BLOCKED_REASON_NONE)
		return TRUE;
	if (priv->autoconnect_retries == 0)
		return TRUE;

	flags = priv->flags;
	if (NM_FLAGS_HAS (flags, NM_SETTINGS_CONNECTION_INT_FLAGS_VOLATILE))
		return TRUE;
	if (!NM_FLAGS_HAS (flags, NM_SETTINGS_CONNECTION_INT_FLAGS_VISIBLE))
		return TRUE;

	return FALSE;
}

/*****************************************************************************/

gboolean
nm_settings_connection_get_ready (NMSettingsConnection *self)
{
	return NM_SETTINGS_CONNECTION_GET_PRIVATE (self)->ready;
}

void
nm_settings_connection_set_ready (NMSettingsConnection *self,
                                  gboolean ready)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);

	ready = !!ready;
	if (priv->ready != ready) {
		priv->ready = ready;
		_notify (self, PROP_READY);
	}
}

/**
 * nm_settings_connection_set_filename:
 * @self: an #NMSettingsConnection
 * @filename: @self's filename
 *
 * Called by a backend to sets the filename that @self is read
 * from/written to.
 */
void
nm_settings_connection_set_filename (NMSettingsConnection *self,
                                     const char *filename)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);

	if (g_strcmp0 (filename, priv->filename) != 0) {
		g_free (priv->filename);
		priv->filename = g_strdup (filename);
		_notify (self, PROP_FILENAME);
	}
}

/**
 * nm_settings_connection_get_filename:
 * @self: an #NMSettingsConnection
 *
 * Gets the filename that @self was read from/written to.  This may be
 * %NULL if @self is unsaved, or if it is associated with a backend that
 * does not store each connection in a separate file.
 *
 * Returns: @self's filename.
 */
const char *
nm_settings_connection_get_filename (NMSettingsConnection *self)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);

	return priv->filename;
}

const char *
nm_settings_connection_get_id (NMSettingsConnection *self)
{
	return nm_connection_get_id (nm_settings_connection_get_connection (self));
}

const char *
nm_settings_connection_get_uuid (NMSettingsConnection *self)
{
	return nm_connection_get_uuid (nm_settings_connection_get_connection (self));
}

const char *
nm_settings_connection_get_connection_type (NMSettingsConnection *self)
{
	return nm_connection_get_connection_type (nm_settings_connection_get_connection (self));
}

/*****************************************************************************/

static void
nm_settings_connection_init (NMSettingsConnection *self)
{
	NMSettingsConnectionPrivate *priv;

	priv = G_TYPE_INSTANCE_GET_PRIVATE (self, NM_TYPE_SETTINGS_CONNECTION, NMSettingsConnectionPrivate);
	self->_priv = priv;

	c_list_init (&self->_connections_lst);

	priv->ready = TRUE;
	c_list_init (&priv->call_ids_lst_head);
	c_list_init (&priv->auth_lst_head);

	priv->session_monitor = g_object_ref (nm_session_monitor_get ());
	priv->session_changed_id = g_signal_connect (priv->session_monitor,
	                                             NM_SESSION_MONITOR_CHANGED,
	                                             G_CALLBACK (session_changed_cb), self);

	priv->agent_mgr = g_object_ref (nm_agent_manager_get ());

	priv->seen_bssids = g_hash_table_new_full (nm_str_hash, g_str_equal, g_free, NULL);

	priv->autoconnect_retries = AUTOCONNECT_RETRIES_UNSET;

	priv->connection = nm_simple_connection_new ();

	g_signal_connect (priv->connection, NM_CONNECTION_SECRETS_CLEARED, G_CALLBACK (secrets_cleared_cb), self);
	g_signal_connect (priv->connection, NM_CONNECTION_CHANGED, G_CALLBACK (connection_changed_cb), self);
}

static void
constructed (GObject *object)
{
	NMSettingsConnection *self = NM_SETTINGS_CONNECTION (object);

	_LOGD ("constructed (%s)", G_OBJECT_TYPE_NAME (self));

	G_OBJECT_CLASS (nm_settings_connection_parent_class)->constructed (object);
}

static void
dispose (GObject *object)
{
	NMSettingsConnection *self = NM_SETTINGS_CONNECTION (object);
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);
	NMSettingsConnectionCallId *call_id, *call_id_safe;

	_LOGD ("disposing");

	nm_assert (c_list_is_empty (&self->_connections_lst));
	nm_assert (c_list_is_empty (&priv->auth_lst_head));

	/* Cancel in-progress secrets requests */
	if (priv->agent_mgr) {
		c_list_for_each_entry_safe (call_id, call_id_safe, &priv->call_ids_lst_head, call_ids_lst)
			_get_secrets_cancel (self, call_id, TRUE);
	}

	set_visible (self, FALSE);

	if (priv->connection) {
		/* Disconnect handlers.
		 * connection_changed_cb() has to be disconnected *before* nm_connection_clear_secrets(),
		 * because nm_connection_clear_secrets() emits NM_CONNECTION_CHANGED signal.
		 */
		g_signal_handlers_disconnect_by_func (priv->connection, G_CALLBACK (secrets_cleared_cb), self);
		g_signal_handlers_disconnect_by_func (priv->connection, G_CALLBACK (connection_changed_cb), self);

		/* FIXME(copy-on-write-connection): avoid modifying NMConnection instances and share them via copy-on-write. */
		nm_connection_clear_secrets (priv->connection);
	}

	g_clear_object (&priv->system_secrets);
	g_clear_object (&priv->agent_secrets);

	g_clear_pointer (&priv->seen_bssids, g_hash_table_destroy);

	nm_clear_g_signal_handler (priv->session_monitor, &priv->session_changed_id);
	g_clear_object (&priv->session_monitor);

	g_clear_object (&priv->agent_mgr);

	g_clear_object (&priv->connection);

	g_clear_pointer (&priv->filename, g_free);

	G_OBJECT_CLASS (nm_settings_connection_parent_class)->dispose (object);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingsConnection *self = NM_SETTINGS_CONNECTION (object);

	switch (prop_id) {
	case PROP_UNSAVED:
		g_value_set_boolean (value, nm_settings_connection_get_unsaved (self));
		break;
	case PROP_READY:
		g_value_set_boolean (value, nm_settings_connection_get_ready (self));
		break;
	case PROP_FLAGS:
		g_value_set_uint (value,
		                  nm_settings_connection_get_flags (self) & NM_SETTINGS_CONNECTION_INT_FLAGS_EXPORTED_MASK);
		break;
	case PROP_FILENAME:
		g_value_set_string (value, nm_settings_connection_get_filename (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingsConnection *self = NM_SETTINGS_CONNECTION (object);

	switch (prop_id) {
	case PROP_FILENAME:
		/* construct-only */
		nm_settings_connection_set_filename (self, g_value_get_string (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static const GDBusSignalInfo signal_info_updated = NM_DEFINE_GDBUS_SIGNAL_INFO_INIT (
	"Updated",
);

static const GDBusSignalInfo signal_info_removed = NM_DEFINE_GDBUS_SIGNAL_INFO_INIT (
	"Removed",
);

static const NMDBusInterfaceInfoExtended interface_info_settings_connection = {
	.parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (
		NM_DBUS_INTERFACE_SETTINGS_CONNECTION,
		.methods = NM_DEFINE_GDBUS_METHOD_INFOS (
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"Update",
					.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("properties", "a{sa{sv}}"),
					),
				),
				.handle = impl_settings_connection_update,
			),
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"UpdateUnsaved",
					.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("properties", "a{sa{sv}}"),
					),
				),
				.handle = impl_settings_connection_update_unsaved,
			),
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"Delete",
				),
				.handle = impl_settings_connection_delete,
			),
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"GetSettings",
					.out_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("settings", "a{sa{sv}}"),
					),
				),
				.handle = impl_settings_connection_get_settings,
			),
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"GetSecrets",
					.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("setting_name", "s"),
					),
					.out_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("secrets", "a{sa{sv}}"),
					),
				),
				.handle = impl_settings_connection_get_secrets,
			),
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"ClearSecrets",
				),
				.handle = impl_settings_connection_clear_secrets,
			),
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"Save",
				),
				.handle = impl_settings_connection_save,
			),
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"Update2",
					.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("settings", "a{sa{sv}}"),
						NM_DEFINE_GDBUS_ARG_INFO ("flags",    "u"),
						NM_DEFINE_GDBUS_ARG_INFO ("args",     "a{sv}"),
					),
					.out_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("result", "a{sv}"),
					),
				),
				.handle = impl_settings_connection_update2,
			),
		),
		.signals = NM_DEFINE_GDBUS_SIGNAL_INFOS (
			&nm_signal_info_property_changed_legacy,
			&signal_info_updated,
			&signal_info_removed,
		),
		.properties = NM_DEFINE_GDBUS_PROPERTY_INFOS (
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Unsaved",  "b",  NM_SETTINGS_CONNECTION_UNSAVED),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE   ("Flags",    "u",  NM_SETTINGS_CONNECTION_FLAGS),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE   ("Filename", "s",  NM_SETTINGS_CONNECTION_FILENAME),
		),
	),
	.legacy_property_changed = TRUE,
};

static void
nm_settings_connection_class_init (NMSettingsConnectionClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMSettingsConnectionPrivate));

	dbus_object_class->export_path = NM_DBUS_EXPORT_PATH_NUMBERED (NM_DBUS_PATH_SETTINGS);
	dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS (&interface_info_settings_connection);

	object_class->constructed = constructed;
	object_class->dispose = dispose;
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	klass->supports_secrets = supports_secrets;

	obj_properties[PROP_UNSAVED] =
	     g_param_spec_boolean (NM_SETTINGS_CONNECTION_UNSAVED, "", "",
	                           FALSE,
	                           G_PARAM_READABLE |
	                           G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_READY] =
	     g_param_spec_boolean (NM_SETTINGS_CONNECTION_READY, "", "",
	                           TRUE,
	                           G_PARAM_READABLE |
	                           G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_FLAGS] =
	     g_param_spec_uint (NM_SETTINGS_CONNECTION_FLAGS, "", "",
	                        0, G_MAXUINT32, 0,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_FILENAME] =
	     g_param_spec_string (NM_SETTINGS_CONNECTION_FILENAME, "", "",
	                          NULL,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	/* internal signal, with an argument (gboolean by_user). */
	signals[UPDATED_INTERNAL] =
	    g_signal_new (NM_SETTINGS_CONNECTION_UPDATED_INTERNAL,
	                  G_TYPE_FROM_CLASS (klass),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL,
	                  g_cclosure_marshal_VOID__BOOLEAN,
	                  G_TYPE_NONE, 1, G_TYPE_BOOLEAN);

	signals[REMOVED] =
	    g_signal_new (NM_SETTINGS_CONNECTION_REMOVED,
	                  G_TYPE_FROM_CLASS (klass),
	                  G_SIGNAL_RUN_FIRST,
	                  0,
	                  NULL, NULL,
	                  g_cclosure_marshal_VOID__VOID,
	                  G_TYPE_NONE, 0);

	signals[FLAGS_CHANGED] =
	    g_signal_new (NM_SETTINGS_CONNECTION_FLAGS_CHANGED,
	                  G_TYPE_FROM_CLASS (klass),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL,
	                  g_cclosure_marshal_VOID__VOID,
	                  G_TYPE_NONE, 0);
}
