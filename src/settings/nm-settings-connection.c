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
 * (C) Copyright 2008 - 2011 Red Hat, Inc.
 */

#include <string.h>

#include <NetworkManager.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <nm-setting-connection.h>
#include <nm-setting-vpn.h>
#include <nm-utils.h>

#include "nm-settings-connection.h"
#include "nm-session-monitor.h"
#include "nm-dbus-manager.h"
#include "nm-settings-error.h"
#include "nm-dbus-glib-types.h"
#include "nm-polkit-helpers.h"
#include "nm-logging.h"
#include "nm-manager-auth.h"
#include "nm-marshal.h"
#include "nm-agent-manager.h"

static void impl_settings_connection_get_settings (NMSettingsConnection *connection,
                                                   DBusGMethodInvocation *context);

static void impl_settings_connection_update (NMSettingsConnection *connection,
                                             GHashTable *new_settings,
                                             DBusGMethodInvocation *context);

static void impl_settings_connection_delete (NMSettingsConnection *connection,
                                             DBusGMethodInvocation *context);

static void impl_settings_connection_get_secrets (NMSettingsConnection *connection,
                                                  const gchar *setting_name,
                                                  DBusGMethodInvocation *context);

#include "nm-settings-connection-glue.h"

G_DEFINE_TYPE (NMSettingsConnection, nm_settings_connection, NM_TYPE_CONNECTION)

#define NM_SETTINGS_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                               NM_TYPE_SETTINGS_CONNECTION, \
                                               NMSettingsConnectionPrivate))

enum {
	PROP_0 = 0,
	PROP_VISIBLE,
};

enum {
	UPDATED,
	REMOVED,
	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	gboolean disposed;

	NMDBusManager *dbus_mgr;
	NMAgentManager *agent_mgr;

	PolkitAuthority *authority;
	GSList *pending_auths; /* List of pending authentication requests */
	NMConnection *secrets;
	gboolean visible; /* Is this connection is visible by some session? */

	GSList *reqs;  /* in-progress secrets requests */

	NMSessionMonitor *session_monitor;
	guint session_changed_id;
} NMSettingsConnectionPrivate;

/**************************************************************/

static void
set_visible (NMSettingsConnection *self, gboolean new_visible)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);

	if (new_visible == priv->visible)
		return;
	priv->visible = new_visible;
	g_object_notify (G_OBJECT (self), NM_SETTINGS_CONNECTION_VISIBLE);
}

gboolean
nm_settings_connection_is_visible (NMSettingsConnection *self)
{
	g_return_val_if_fail (NM_SETTINGS_CONNECTION (self), FALSE);

	return NM_SETTINGS_CONNECTION_GET_PRIVATE (self)->visible;
}

void
nm_settings_connection_recheck_visibility (NMSettingsConnection *self)
{
	NMSettingsConnectionPrivate *priv;
	NMSettingConnection *s_con;
	guint32 num, i;

	g_return_if_fail (NM_SETTINGS_CONNECTION (self));

	priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);

	s_con = (NMSettingConnection *) nm_connection_get_setting (NM_CONNECTION (self), NM_TYPE_SETTING_CONNECTION);
	g_assert (s_con);

	/* Check every user in the ACL for a session */
	num = nm_setting_connection_get_num_permissions (s_con);
	if (num == 0) {
		/* Visible to all */
		set_visible (self, TRUE);
		return;
	}

	for (i = 0; i < num; i++) {
		const char *puser;

		if (nm_setting_connection_get_permission (s_con, i, NULL, &puser, NULL)) {
			if (nm_session_monitor_user_has_session (priv->session_monitor, puser, NULL, NULL)) {
				set_visible (self, TRUE);
				return;
			}
		}
	}

	set_visible (self, FALSE);
}

static void
session_changed_cb (NMSessionMonitor *self, gpointer user_data)
{
	nm_settings_connection_recheck_visibility (NM_SETTINGS_CONNECTION (user_data));
}

/**************************************************************/

static void
only_system_secrets_cb (NMSetting *setting,
                        const char *key,
                        const GValue *value,
                        GParamFlags flags,
                        gpointer user_data)
{
	if (flags & NM_SETTING_PARAM_SECRET) {
		NMSettingSecretFlags secret_flags = NM_SETTING_SECRET_FLAG_NONE;

		/* VPNs are special; need to handle each secret separately */
		if (NM_IS_SETTING_VPN (setting) && !strcmp (key, NM_SETTING_VPN_SECRETS)) {
			GHashTableIter iter;
			const char *secret_name = NULL;

			g_hash_table_iter_init (&iter, (GHashTable *) g_value_get_boxed (value));
			while (g_hash_table_iter_next (&iter, (gpointer *) &secret_name, NULL)) {
				if (nm_setting_get_secret_flags (setting, secret_name, &secret_flags, NULL)) {
					if (secret_flags != NM_SETTING_SECRET_FLAG_NONE)
						nm_setting_vpn_remove_secret (NM_SETTING_VPN (setting), secret_name);
				}
			}
		} else {
			nm_setting_get_secret_flags (setting, key, &secret_flags, NULL);
			if (secret_flags != NM_SETTING_SECRET_FLAG_NONE)
				g_object_set (G_OBJECT (setting), key, NULL, NULL);
		}
	}
}

static void
update_secrets_cache (NMSettingsConnection *self)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);

	if (priv->secrets)
		g_object_unref (priv->secrets);
	priv->secrets = nm_connection_duplicate (NM_CONNECTION (self));

	/* Clear out non-system-owned and not-saved secrets */
	nm_connection_for_each_setting_value (priv->secrets, only_system_secrets_cb, NULL);
}

/* Update the settings of this connection to match that of 'new', taking care to
 * make a private copy of secrets. */
gboolean
nm_settings_connection_replace_settings (NMSettingsConnection *self,
                                         NMConnection *new,
                                         GError **error)
{
	NMSettingsConnectionPrivate *priv;
	GHashTable *new_settings;
	gboolean success = FALSE;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (NM_IS_SETTINGS_CONNECTION (self), FALSE);
	g_return_val_if_fail (new != NULL, FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (new), FALSE);

	priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);

	new_settings = nm_connection_to_hash (new, NM_SETTING_HASH_FLAG_ALL);
	g_assert (new_settings);
	if (nm_connection_replace_settings (NM_CONNECTION (self), new_settings, error)) {
		/* Copy the connection to keep its secrets around even if NM
		 * calls nm_connection_clear_secrets().
		 */
		update_secrets_cache (self);

		nm_settings_connection_recheck_visibility (self);
		success = TRUE;
	}
	g_hash_table_destroy (new_settings);
	return success;
}

static void
ignore_cb (NMSettingsConnection *connection,
           GError *error,
           gpointer user_data)
{
}

/* Replaces the settings in this connection with those in 'new'. If any changes
 * are made, commits them to permanent storage and to any other subsystems
 * watching this connection. Before returning, 'callback' is run with the given
 * 'user_data' along with any errors encountered.
 */
void
nm_settings_connection_replace_and_commit (NMSettingsConnection *self,
                                           NMConnection *new,
                                           NMSettingsConnectionCommitFunc callback,
                                           gpointer user_data)
{
	GError *error = NULL;

	g_return_if_fail (self != NULL);
	g_return_if_fail (NM_IS_SETTINGS_CONNECTION (self));
	g_return_if_fail (new != NULL);
	g_return_if_fail (NM_IS_CONNECTION (new));

	if (!callback)
		callback = ignore_cb;

	/* Do nothing if there's nothing to update */
	if (nm_connection_compare (NM_CONNECTION (self),
	                           NM_CONNECTION (new),
	                           NM_SETTING_COMPARE_FLAG_EXACT)) {
		callback (self, NULL, user_data);
		return;
	}

	if (nm_settings_connection_replace_settings (self, new, &error)) {
		nm_settings_connection_commit_changes (self, callback, user_data);
	} else {
		callback (self, error, user_data);
		g_clear_error (&error);
	}
}

void
nm_settings_connection_commit_changes (NMSettingsConnection *connection,
                                       NMSettingsConnectionCommitFunc callback,
                                       gpointer user_data)
{
	g_return_if_fail (connection != NULL);
	g_return_if_fail (NM_IS_SETTINGS_CONNECTION (connection));
	g_return_if_fail (callback != NULL);

	if (NM_SETTINGS_CONNECTION_GET_CLASS (connection)->commit_changes) {
		NM_SETTINGS_CONNECTION_GET_CLASS (connection)->commit_changes (connection,
		                                                               callback,
		                                                               user_data);
	} else {
		GError *error = g_error_new (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_INTERNAL_ERROR,
		                             "%s: %s:%d commit_changes() unimplemented", __func__, __FILE__, __LINE__);
		callback (connection, error, user_data);
		g_error_free (error);
	}
}

void
nm_settings_connection_delete (NMSettingsConnection *connection,
                               NMSettingsConnectionDeleteFunc callback,
                               gpointer user_data)
{
	g_return_if_fail (connection != NULL);
	g_return_if_fail (NM_IS_SETTINGS_CONNECTION (connection));
	g_return_if_fail (callback != NULL);

	if (NM_SETTINGS_CONNECTION_GET_CLASS (connection)->delete) {
		NM_SETTINGS_CONNECTION_GET_CLASS (connection)->delete (connection,
		                                                       callback,
		                                                       user_data);
	} else {
		GError *error = g_error_new (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_INTERNAL_ERROR,
		                             "%s: %s:%d delete() unimplemented", __func__, __FILE__, __LINE__);
		callback (connection, error, user_data);
		g_error_free (error);
	}
}

static void
commit_changes (NMSettingsConnection *connection,
                NMSettingsConnectionCommitFunc callback,
                gpointer user_data)
{
	g_object_ref (connection);
	g_signal_emit (connection, signals[UPDATED], 0);
	callback (connection, NULL, user_data);
	g_object_unref (connection);
}

static void
do_delete (NMSettingsConnection *connection,
           NMSettingsConnectionDeleteFunc callback,
           gpointer user_data)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (connection);
	NMConnection *for_agents;

	g_object_ref (connection);
	set_visible (connection, FALSE);

	/* Tell agents to remove secrets for this connection */
	for_agents = nm_connection_duplicate (NM_CONNECTION (connection));
	nm_connection_clear_secrets (for_agents);
	nm_agent_manager_delete_secrets (priv->agent_mgr, for_agents, FALSE, 0);

	/* Signal the connection is removed and deleted */
	g_signal_emit (connection, signals[REMOVED], 0);
	callback (connection, NULL, user_data);
	g_object_unref (connection);
}

/**************************************************************/

static gboolean
supports_secrets (NMSettingsConnection *connection, const char *setting_name)
{
	/* All secrets supported */
	return TRUE;
}

/* Return TRUE to continue, FALSE to stop */
typedef gboolean (*ForEachSecretFunc) (GHashTableIter *iter,
                                       NMSettingSecretFlags flags,
                                       gpointer user_data);

static gboolean
clear_nonagent_secrets (GHashTableIter *iter,
                        NMSettingSecretFlags flags,
                        gpointer user_data)
{
	if (flags != NM_SETTING_SECRET_FLAG_AGENT_OWNED)
		g_hash_table_iter_remove (iter);
	return TRUE;
}

static gboolean
clear_unsaved_secrets (GHashTableIter *iter,
                       NMSettingSecretFlags flags,
                       gpointer user_data)
{
	if (flags & (NM_SETTING_SECRET_FLAG_NOT_SAVED | NM_SETTING_SECRET_FLAG_NOT_REQUIRED))
		g_hash_table_iter_remove (iter);
	return TRUE;
}

static gboolean
has_system_owned_secrets (GHashTableIter *iter,
                          NMSettingSecretFlags flags,
                          gpointer user_data)
{
	gboolean *has_system_owned = user_data;

	if (!(flags & NM_SETTING_SECRET_FLAG_AGENT_OWNED)) {
		*has_system_owned = TRUE;
		return FALSE;
	}
	return TRUE;
}

static void
for_each_secret (NMConnection *connection,
                 GHashTable *secrets,
                 ForEachSecretFunc callback,
                 gpointer callback_data)
{
	GHashTableIter iter;
	const char *setting_name;
	GHashTable *setting_hash;

	/* Walk through the list of setting hashes */
	g_hash_table_iter_init (&iter, secrets);
	while (g_hash_table_iter_next (&iter,
	                               (gpointer *) &setting_name,
	                               (gpointer *) &setting_hash)) {
		GHashTableIter setting_iter;
		const char *secret_name;

		/* Walk through the list of keys in each setting hash */
		g_hash_table_iter_init (&setting_iter, setting_hash);
		while (g_hash_table_iter_next (&setting_iter, (gpointer *) &secret_name, NULL)) {
			NMSetting *setting;
			NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;

			/* Get the actual NMSetting from the connection so we can get secret flags */
			setting = nm_connection_get_setting_by_name (connection, setting_name);
			if (setting && nm_setting_get_secret_flags (setting, secret_name, &flags, NULL)) {
				if (callback (&setting_iter, flags, callback_data) == FALSE)
					return;
			}
		}
	}
}

static void
new_secrets_commit_cb (NMSettingsConnection *connection,
                       GError *error,
                       gpointer user_data)
{
	if (error) {
		nm_log_warn (LOGD_SETTINGS, "Error saving new secrets to backing storage: (%d) %s",
		             error->code, error->message ? error->message : "(unknown)");
	}
}

static void
agent_secrets_done_cb (NMAgentManager *manager,
                       guint32 call_id,
                       const char *agent_dbus_owner,
                       gboolean agent_has_modify,
                       const char *setting_name,
                       guint32 flags,
                       GHashTable *secrets,
                       GError *error,
                       gpointer user_data,
                       gpointer other_data2,
                       gpointer other_data3)
{
	NMSettingsConnection *self = NM_SETTINGS_CONNECTION (user_data);
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);
	NMSettingsConnectionSecretsFunc callback = other_data2;
	gpointer callback_data = other_data3;
	NMSettingConnection *s_con;
	GError *local = NULL;
	GHashTable *hash;

	s_con = (NMSettingConnection *) nm_connection_get_setting (NM_CONNECTION (self), NM_TYPE_SETTING_CONNECTION);
	g_assert (s_con);

	if (error) {
		nm_log_dbg (LOGD_SETTINGS, "(%s/%s:%u) secrets request error: (%d) %s",
		            nm_setting_connection_get_uuid (s_con),
		            setting_name,
		            call_id,
		            error->code,
		            error->message ? error->message : "(unknown)");

		callback (self, call_id, setting_name, error, callback_data);
		return;
	}

	if (!nm_connection_get_setting_by_name (NM_CONNECTION (self), setting_name)) {
		local = g_error_new (NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_SETTING,
		                     "%s.%d - Connection didn't have requested setting '%s'.",
		                     __FILE__, __LINE__, setting_name);
		callback (self, call_id, setting_name, local, callback_data);
		g_clear_error (&local);
		return;
	}

	g_assert (secrets);
	if (agent_dbus_owner) {
		gboolean has_system = FALSE;

		nm_log_dbg (LOGD_SETTINGS, "(%s/%s:%u) secrets returned from agent %s",
		            nm_setting_connection_get_uuid (s_con),
		            setting_name,
		            call_id,
		            agent_dbus_owner);

		/* If the agent returned any system-owned secrets (initial connect and no
		 * secrets given when the connection was created, or something like that)
		 * make sure the agent's UID has the 'modify' permission before we use or
		 * save those system-owned secrets.  If not, discard them and use the
		 * existing secrets, or fail the connection.
		 */
		for_each_secret (NM_CONNECTION (self), secrets, has_system_owned_secrets, &has_system);
		if (has_system) {
			if (flags == 0) {  /* ie SECRETS_FLAG_NONE */
				/* No user interaction was allowed when requesting secrets; the
				 * agent is being bad.  Remove system-owned secrets.
				 */
				nm_log_dbg (LOGD_SETTINGS, "(%s/%s:%u) interaction forbidden but agent %s returned system secrets",
				            nm_setting_connection_get_uuid (s_con),
				            setting_name,
				            call_id,
				            agent_dbus_owner);

				for_each_secret (NM_CONNECTION (self), secrets, clear_nonagent_secrets, NULL);
			} else if (agent_has_modify == FALSE) {
				/* Agent didn't successfully authenticate; clear system-owned secrets
				 * from the secrets the agent returned.
				 */
				nm_log_dbg (LOGD_SETTINGS, "(%s/%s:%u) agent failed to authenticate but provided system secrets",
				            nm_setting_connection_get_uuid (s_con),
				            setting_name,
				            call_id);

				for_each_secret (NM_CONNECTION (self), secrets, clear_nonagent_secrets, NULL);
			}
		}
	} else {
		nm_log_dbg (LOGD_SETTINGS, "(%s/%s:%u) existing secrets returned",
		            nm_setting_connection_get_uuid (s_con),
		            setting_name,
		            call_id);
	}

	nm_log_dbg (LOGD_SETTINGS, "(%s/%s:%u) secrets request completed",
	            nm_setting_connection_get_uuid (s_con),
	            setting_name,
	            call_id);

	/* If no user interaction was allowed, make sure that no "unsaved" secrets
	 * came back.  Unsaved secrets by definition require user interaction.
	 */
	if (flags == 0)  /* ie SECRETS_FLAG_NONE */
		for_each_secret (NM_CONNECTION (self), secrets, clear_unsaved_secrets, NULL);

	/* Update the connection with our existing secrets from backing storage */
	nm_connection_clear_secrets (NM_CONNECTION (self));
	hash = nm_connection_to_hash (priv->secrets, NM_SETTING_HASH_FLAG_ONLY_SECRETS);
	if (nm_connection_update_secrets (NM_CONNECTION (self), setting_name, hash, &local)) {
		/* Update the connection with the agent's secrets; by this point if any
		 * system-owned secrets exist in 'secrets' the agent that provided them
		 * will have been authenticated, so those secrets can replace the existing
		 * system secrets.
		 */
		if (nm_connection_update_secrets (NM_CONNECTION (self), setting_name, secrets, &local)) {
			/* Now that all secrets are updated, copy and cache new secrets, 
			 * then save them to backing storage.
			 */
			update_secrets_cache (self);

			nm_log_dbg (LOGD_SETTINGS, "(%s/%s:%u) saving new secrets to backing storage",
			            nm_setting_connection_get_uuid (s_con),
			            setting_name,
			            call_id);

			nm_settings_connection_commit_changes (self, new_secrets_commit_cb, NULL);
		} else {
			nm_log_dbg (LOGD_SETTINGS, "(%s/%s:%u) failed to update with agent secrets: (%d) %s",
			            nm_setting_connection_get_uuid (s_con),
			            setting_name,
			            call_id,
			            local->code,
			            local->message ? local->message : "(unknown)");
		}
	} else {
		nm_log_dbg (LOGD_SETTINGS, "(%s/%s:%u) failed to update with existing secrets: (%d) %s",
		            nm_setting_connection_get_uuid (s_con),
		            setting_name,
		            call_id,
		            local->code,
		            local->message ? local->message : "(unknown)");
	}

	callback (self, call_id, setting_name, local, callback_data);
	g_clear_error (&local);
	if (hash)
		g_hash_table_destroy (hash);
}

/**
 * nm_settings_connection_get_secrets:
 * @connection: the #NMSettingsConnection
 * @filter_by_uid: if TRUE, only request secrets from agents registered by the
 * same UID as @uid.
 * @uid: when @filter_by_uid is TRUE, only request secrets from agents belonging
 * to this UID
 * @setting_name: the setting to return secrets for
 * @flags: flags to modify the secrets request
 * @hint: the name of a key in @setting_name for which a secret may be required
 * @callback: the function to call with returned secrets
 * @callback_data: user data to pass to @callback
 *
 * Retrieves secrets from persistent storage and queries any secret agents for
 * additional secrets.
 *
 * Returns: a call ID which may be used to cancel the ongoing secrets request
 **/
guint32 
nm_settings_connection_get_secrets (NMSettingsConnection *self,
                                    gboolean filter_by_uid,
                                    gulong uid,
                                    const char *setting_name,
                                    guint32 flags,
                                    const char *hint,
                                    NMSettingsConnectionSecretsFunc callback,
                                    gpointer callback_data,
                                    GError **error)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);
	NMSettingConnection *s_con;
	GHashTable *existing_secrets;
	guint32 call_id = 0;

	/* Use priv->secrets to work around the fact that nm_connection_clear_secrets()
	 * will clear secrets on this object's settings.  priv->secrets should be
	 * a complete copy of this object and kept in sync by
	 * nm_settings_connection_replace_settings().
	 */
	if (!priv->secrets) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "%s.%d - Internal error; secrets cache invalid.",
		             __FILE__, __LINE__);
		return 0;
	}

	/* Make sure the request actually requests something we can return */
	if (!nm_connection_get_setting_by_name (NM_CONNECTION (self), setting_name)) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_SETTING,
		             "%s.%d - Connection didn't have requested setting '%s'.",
		             __FILE__, __LINE__, setting_name);
		return 0;
	}

	existing_secrets = nm_connection_to_hash (priv->secrets, NM_SETTING_HASH_FLAG_ONLY_SECRETS);
	call_id = nm_agent_manager_get_secrets (priv->agent_mgr,
	                                        NM_CONNECTION (self),
	                                        filter_by_uid,
	                                        uid,
	                                        existing_secrets,
	                                        setting_name,
	                                        flags,
	                                        hint,
	                                        agent_secrets_done_cb,
	                                        self,
	                                        callback,
	                                        callback_data);
	g_hash_table_unref (existing_secrets);

	s_con = (NMSettingConnection *) nm_connection_get_setting (NM_CONNECTION (self), NM_TYPE_SETTING_CONNECTION);
	nm_log_dbg (LOGD_SETTINGS, "(%s/%s:%u) secrets requested flags 0x%X hint '%s'",
	            nm_setting_connection_get_uuid (s_con),
	            setting_name,
	            call_id,
	            flags,
	            hint);

	return call_id;
}

void
nm_settings_connection_cancel_secrets (NMSettingsConnection *self,
                                       guint32 call_id)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);
	NMSettingConnection *s_con;

	s_con = (NMSettingConnection *) nm_connection_get_setting (NM_CONNECTION (self), NM_TYPE_SETTING_CONNECTION);
	nm_log_dbg (LOGD_SETTINGS, "(%s:%u) secrets canceled",
	            nm_setting_connection_get_uuid (s_con),
	            call_id);

	priv->reqs = g_slist_remove (priv->reqs, GUINT_TO_POINTER (call_id));
	nm_agent_manager_cancel_secrets (priv->agent_mgr, call_id);
}

/**** User authorization **************************************/

typedef void (*AuthCallback) (NMSettingsConnection *connection, 
                              DBusGMethodInvocation *context,
                              gulong sender_uid,
                              GError *error,
                              gpointer data);

typedef struct {
	AuthCallback callback;
	gpointer callback_data;
	gulong sender_uid;
} PkAuthInfo;

static void
pk_auth_cb (NMAuthChain *chain,
            GError *chain_error,
            DBusGMethodInvocation *context,
            gpointer user_data)
{
	NMSettingsConnection *self = NM_SETTINGS_CONNECTION (user_data);
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);
	GError *error = NULL;
	NMAuthCallResult result;
	PkAuthInfo *info;

	priv->pending_auths = g_slist_remove (priv->pending_auths, chain);

	/* If our NMSettingsConnection is already gone, do nothing */
	if (chain_error) {
		error = g_error_new (NM_SETTINGS_ERROR,
		                     NM_SETTINGS_ERROR_GENERAL,
		                     "Error checking authorization: %s",
		                     chain_error->message ? chain_error->message : "(unknown)");
	} else {
		result = nm_auth_chain_get_result (chain, NM_AUTH_PERMISSION_SETTINGS_MODIFY_SYSTEM);

		/* Caller didn't successfully authenticate */
		if (result != NM_AUTH_CALL_RESULT_YES) {
			error = g_error_new_literal (NM_SETTINGS_ERROR,
			                             NM_SETTINGS_ERROR_NOT_PRIVILEGED,
			                             "Insufficient privileges.");
		}
	}

	info = nm_auth_chain_get_data (chain, "pk-auth-info");
	info->callback (self, context, info->sender_uid, error, info->callback_data);

	g_clear_error (&error);
	nm_auth_chain_unref (chain);
}

static void
auth_start (NMSettingsConnection *self,
            DBusGMethodInvocation *context,
            gboolean check_modify,
            AuthCallback callback,
            gpointer callback_data)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);
	NMAuthChain *chain;
	gulong sender_uid = G_MAXULONG;
	PkAuthInfo *info;
	GError *error = NULL;
	char *error_desc = NULL;

	/* Get the caller's UID */
	if (!nm_auth_get_caller_uid (context,  NULL, &sender_uid, &error_desc)) {
		error = g_error_new_literal (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_PERMISSION_DENIED,
		                             error_desc);
		g_free (error_desc);
		goto error;
	}

	/* Make sure the UID can view this connection */
	if (0 != sender_uid) {
		if (!nm_auth_uid_in_acl (NM_CONNECTION (self),
		                         priv->session_monitor,
		                         sender_uid,
		                         &error_desc)) {
			error = g_error_new_literal (NM_SETTINGS_ERROR,
			                             NM_SETTINGS_ERROR_PERMISSION_DENIED,
			                             error_desc);
			g_free (error_desc);
			goto error;
		}
	}

	if (check_modify) {
		chain = nm_auth_chain_new (priv->authority, context, NULL, pk_auth_cb, self);
		g_assert (chain);

		info = g_malloc0 (sizeof (*info));
		info->callback = callback;
		info->callback_data = callback_data;
		info->sender_uid = sender_uid;
		nm_auth_chain_set_data (chain, "pk-auth-info", info, g_free);

		nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_SETTINGS_MODIFY_SYSTEM, TRUE);
		priv->pending_auths = g_slist_append (priv->pending_auths, chain);
	} else {
		/* Don't need polkit auth, automatic success */
		callback (self, context, sender_uid, NULL, callback_data);
	}

	return;

error:
	callback (self, context, G_MAXULONG, error, callback_data);
	g_error_free (error);
}

/**** DBus method handlers ************************************/

static gboolean
check_writable (NMConnection *connection, GError **error)
{
	NMSettingConnection *s_con;

	g_return_val_if_fail (connection != NULL, FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
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
	                  DBusGMethodInvocation *context,
	                  gulong sender_uid,
	                  GError *error,
	                  gpointer data)
{
	if (error)
		dbus_g_method_return_error (context, error);
	else {
		GHashTable *settings;

		/* Secrets should *never* be returned by the GetSettings method, they
		 * get returned by the GetSecrets method which can be better
		 * protected against leakage of secrets to unprivileged callers.
		 */
		settings = nm_connection_to_hash (NM_CONNECTION (self), NM_SETTING_HASH_FLAG_NO_SECRETS);
		g_assert (settings);
		dbus_g_method_return (context, settings);
		g_hash_table_destroy (settings);
	}
}

static void
impl_settings_connection_get_settings (NMSettingsConnection *self,
                                       DBusGMethodInvocation *context)
{
	auth_start (self, context, FALSE, get_settings_auth_cb, NULL);
}

static void
con_update_cb (NMSettingsConnection *connection,
               GError *error,
               gpointer user_data)
{
	DBusGMethodInvocation *context = user_data;

	if (error)
		dbus_g_method_return_error (context, error);
	else
		dbus_g_method_return (context);
}

static void
only_agent_secrets_cb (NMSetting *setting,
                       const char *key,
                       const GValue *value,
                       GParamFlags flags,
                       gpointer user_data)
{
	if (flags & NM_SETTING_PARAM_SECRET) {
		NMSettingSecretFlags secret_flags = NM_SETTING_SECRET_FLAG_NONE;

		/* Clear out system-owned or always-ask secrets */
		if (NM_IS_SETTING_VPN (setting) && !strcmp (key, NM_SETTING_VPN_SECRETS)) {
			GHashTableIter iter;
			const char *secret_name = NULL;

			/* VPNs are special; need to handle each secret separately */
			g_hash_table_iter_init (&iter, (GHashTable *) g_value_get_boxed (value));
			while (g_hash_table_iter_next (&iter, (gpointer *) &secret_name, NULL)) {
				if (nm_setting_get_secret_flags (setting, secret_name, &secret_flags, NULL)) {
					if (secret_flags != NM_SETTING_SECRET_FLAG_AGENT_OWNED)
						nm_setting_vpn_remove_secret (NM_SETTING_VPN (setting), secret_name);
				}
			}
		} else {
			nm_setting_get_secret_flags (setting, key, &secret_flags, NULL);
			if (secret_flags != NM_SETTING_SECRET_FLAG_AGENT_OWNED)
				g_object_set (G_OBJECT (setting), key, NULL, NULL);
		}
	}
}

static void
update_auth_cb (NMSettingsConnection *self,
                DBusGMethodInvocation *context,
                gulong sender_uid,
                GError *error,
                gpointer data)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);
	NMConnection *new_settings = data;
	NMConnection *for_agent;

	if (error)
		dbus_g_method_return_error (context, error);
	else {
		/* Update and commit our settings. */
		nm_settings_connection_replace_and_commit (self,
		                                           new_settings,
		                                           con_update_cb,
		                                           context);

		/* Dupe the connection and clear out non-agent-owned secrets so we can
		 * send the agent-owned ones to agents to be saved.  Only send them to
		 * agents of the same UID as the Update() request sender.
		 */
		for_agent = nm_connection_duplicate (NM_CONNECTION (self));
		nm_connection_for_each_setting_value (for_agent, only_agent_secrets_cb, NULL);
		nm_agent_manager_save_secrets (priv->agent_mgr, for_agent, TRUE, sender_uid);
		g_object_unref (for_agent);
	}

	g_object_unref (new_settings);
}

static void
impl_settings_connection_update (NMSettingsConnection *self,
                                 GHashTable *new_settings,
                                 DBusGMethodInvocation *context)
{
	NMConnection *tmp;
	GError *error = NULL;

	/* If the connection is read-only, that has to be changed at the source of
	 * the problem (ex a system settings plugin that can't write connections out)
	 * instead of over D-Bus.
	 */
	if (!check_writable (NM_CONNECTION (self), &error)) {
		dbus_g_method_return_error (context, error);
		g_error_free (error);
		return;
	}

	/* Check if the settings are valid first */
	tmp = nm_connection_new_from_hash (new_settings, &error);
	if (!tmp) {
		g_assert (error);
		dbus_g_method_return_error (context, error);
		g_error_free (error);
		return;
	}

	auth_start (self, context, TRUE, update_auth_cb, tmp);
}

static void
con_delete_cb (NMSettingsConnection *connection,
               GError *error,
               gpointer user_data)
{
	DBusGMethodInvocation *context = user_data;

	if (error)
		dbus_g_method_return_error (context, error);
	else
		dbus_g_method_return (context);
}

static void
delete_auth_cb (NMSettingsConnection *self, 
                DBusGMethodInvocation *context,
                gulong sender_uid,
                GError *error,
                gpointer data)
{
	if (error) {
		dbus_g_method_return_error (context, error);
		return;
	}

	nm_settings_connection_delete (self, con_delete_cb, context);
}

static void
impl_settings_connection_delete (NMSettingsConnection *self,
                                 DBusGMethodInvocation *context)
{
	GError *error = NULL;
	
	if (!check_writable (NM_CONNECTION (self), &error)) {
		dbus_g_method_return_error (context, error);
		g_error_free (error);
		return;
	}

	auth_start (self, context, TRUE, delete_auth_cb, NULL);
}

/**************************************************************/

static void
dbus_get_agent_secrets_cb (NMSettingsConnection *self,
                           guint32 call_id,
                           const char *setting_name,
                           GError *error,
                           gpointer user_data)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);
	DBusGMethodInvocation *context = user_data;
	GHashTable *hash;

	priv->reqs = g_slist_remove (priv->reqs, GUINT_TO_POINTER (call_id));

	if (error)
		dbus_g_method_return_error (context, error);
	else {
		/* The connection's secrets will have been updated by the agent manager,
		 * so we want to refresh the secrets cache.  Note that we will never save
		 * new secrets to backing storage here because D-Bus initated requests will
		 * never ask for completely new secrets from agents.  Thus system-owned
		 * secrets should not have changed from backing storage.  We also don't
		 * send agent-owned secrets back out to be saved since we assume the agent
		 * that provided the secrets saved them itself.
		 */
		update_secrets_cache (self);

		hash = nm_connection_to_hash (NM_CONNECTION (self), NM_SETTING_HASH_FLAG_ONLY_SECRETS);
		dbus_g_method_return (context, hash);
		g_hash_table_destroy (hash);
	}
}

static void
dbus_secrets_auth_cb (NMSettingsConnection *self, 
                      DBusGMethodInvocation *context,
                      gulong sender_uid,
                      GError *error,
                      gpointer user_data)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);
	char *setting_name = user_data;
	guint32 call_id = 0;
	GError *local = NULL;

	if (!error) {
		call_id = nm_settings_connection_get_secrets (self,
			                                          TRUE,
			                                          sender_uid,
			                                          setting_name,
			                                          0, /* GET_SECRETS_FLAG_NONE */
			                                          NULL,
			                                          dbus_get_agent_secrets_cb,
			                                          context,
			                                          &local);
		if (call_id > 0) {
			/* track the request and wait for the callback */
			priv->reqs = g_slist_append (priv->reqs, GUINT_TO_POINTER (call_id));
		}
	}

	if (error || local) {
		dbus_g_method_return_error (context, error ? error : local);
		g_clear_error (&local);
	}

	g_free (setting_name);
}

static void
impl_settings_connection_get_secrets (NMSettingsConnection *self,
                                      const gchar *setting_name,
                                      DBusGMethodInvocation *context)
{
	auth_start (self, context, TRUE, dbus_secrets_auth_cb, g_strdup (setting_name));
}

/**************************************************************/

static void
nm_settings_connection_init (NMSettingsConnection *self)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);
	static guint32 dbus_counter = 0;
	char *dbus_path;
	GError *error = NULL;

	priv->dbus_mgr = nm_dbus_manager_get ();

	priv->authority = polkit_authority_get_sync (NULL, &error);
	if (!priv->authority) {
		nm_log_warn (LOGD_SETTINGS, "failed to create PolicyKit authority: (%d) %s",
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
	}

	dbus_path = g_strdup_printf ("%s/%u", NM_DBUS_PATH_SETTINGS, dbus_counter++);
	nm_connection_set_path (NM_CONNECTION (self), dbus_path);
	g_free (dbus_path);
	priv->visible = FALSE;

	priv->session_monitor = nm_session_monitor_get ();
	priv->session_changed_id = g_signal_connect (priv->session_monitor,
	                                             NM_SESSION_MONITOR_CHANGED,
	                                             G_CALLBACK (session_changed_cb),
	                                             self);

	priv->agent_mgr = nm_agent_manager_get ();
}

static void
dispose (GObject *object)
{
	NMSettingsConnection *self = NM_SETTINGS_CONNECTION (object);
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);
	GSList *iter;

	if (priv->disposed)
		goto out;
	priv->disposed = TRUE;

	if (priv->secrets)
		g_object_unref (priv->secrets);

	/* Cancel PolicyKit requests */
	for (iter = priv->pending_auths; iter; iter = g_slist_next (iter))
		nm_auth_chain_unref ((NMAuthChain *) iter->data);
	g_slist_free (priv->pending_auths);
	priv->pending_auths = NULL;

	/* Cancel in-progress secrets requests */
	for (iter = priv->reqs; iter; iter = g_slist_next (iter))
		nm_agent_manager_cancel_secrets (priv->agent_mgr, GPOINTER_TO_UINT (iter->data));
	g_slist_free (priv->reqs);

	set_visible (self, FALSE);

	g_object_unref (priv->session_monitor);
	g_object_unref (priv->agent_mgr);
	g_object_unref (priv->dbus_mgr);
	g_object_unref (priv->authority);

out:
	G_OBJECT_CLASS (nm_settings_connection_parent_class)->dispose (object);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case PROP_VISIBLE:
		g_value_set_boolean (value, NM_SETTINGS_CONNECTION_GET_PRIVATE (object)->visible);
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
	G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
}

static void
nm_settings_connection_class_init (NMSettingsConnectionClass *class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (class);

	g_type_class_add_private (class, sizeof (NMSettingsConnectionPrivate));

	/* Virtual methods */
	object_class->dispose = dispose;
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	class->commit_changes = commit_changes;
	class->delete = do_delete;
	class->supports_secrets = supports_secrets;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_VISIBLE,
		 g_param_spec_boolean (NM_SETTINGS_CONNECTION_VISIBLE,
		                       "Visible",
		                       "Visible",
		                       FALSE,
		                       G_PARAM_READABLE));

	/* Signals */
	signals[UPDATED] = 
		g_signal_new (NM_SETTINGS_CONNECTION_UPDATED,
		              G_TYPE_FROM_CLASS (class),
		              G_SIGNAL_RUN_FIRST,
		              0,
		              NULL, NULL,
		              g_cclosure_marshal_VOID__VOID,
		              G_TYPE_NONE, 0);

	signals[REMOVED] = 
		g_signal_new (NM_SETTINGS_CONNECTION_REMOVED,
		              G_TYPE_FROM_CLASS (class),
		              G_SIGNAL_RUN_FIRST,
		              0,
		              NULL, NULL,
		              g_cclosure_marshal_VOID__VOID,
		              G_TYPE_NONE, 0);

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (class),
	                                 &dbus_glib_nm_settings_connection_object_info);
}
