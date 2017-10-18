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

#include <string.h>

#include "nm-common-macros.h"
#include "nm-config.h"
#include "nm-config-data.h"
#include "nm-dbus-interface.h"
#include "nm-session-monitor.h"
#include "nm-auth-utils.h"
#include "nm-auth-subject.h"
#include "nm-agent-manager.h"
#include "NetworkManagerUtils.h"
#include "nm-core-internal.h"
#include "nm-audit-manager.h"

#include "introspection/org.freedesktop.NetworkManager.Settings.Connection.h"

#define SETTINGS_TIMESTAMPS_FILE  NMSTATEDIR "/timestamps"
#define SETTINGS_SEEN_BSSIDS_FILE NMSTATEDIR "/seen-bssids"

#define AUTOCONNECT_RETRIES_UNSET       -2
#define AUTOCONNECT_RETRIES_FOREVER     -1
#define AUTOCONNECT_RETRIES_DEFAULT      4
#define AUTOCONNECT_RESET_RETRIES_TIMER 300

/*****************************************************************************/

static void nm_settings_connection_connection_interface_init (NMConnectionInterface *iface);

NM_GOBJECT_PROPERTIES_DEFINE (NMSettingsConnection,
	PROP_VISIBLE,
	PROP_UNSAVED,
	PROP_READY,
	PROP_FLAGS,
	PROP_FILENAME,
);

enum {
	UPDATED,
	REMOVED,
	UPDATED_INTERNAL,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct _NMSettingsConnectionPrivate {

	NMAgentManager *agent_mgr;
	NMSessionMonitor *session_monitor;
	gulong session_changed_id;

	NMSettingsConnectionFlags flags;

	bool removed:1;
	bool ready:1;

	/* Is this connection visible by some session? */
	bool visible:1;

	bool timestamp_set:1;

	NMSettingsAutoconnectBlockedReason autoconnect_blocked_reason:3;

	GSList *pending_auths; /* List of pending authentication requests */

	GSList *get_secret_requests;  /* in-progress secrets requests */

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

	guint64 timestamp;   /* Up-to-date timestamp of connection use */
	GHashTable *seen_bssids; /* Up-to-date BSSIDs that's been seen for the connection */

	int autoconnect_retries;
	gint32 autoconnect_retry_time;

	char *filename;
} NMSettingsConnectionPrivate;

G_DEFINE_TYPE_WITH_CODE (NMSettingsConnection, nm_settings_connection, NM_TYPE_EXPORTED_OBJECT,
                         G_IMPLEMENT_INTERFACE (NM_TYPE_CONNECTION, nm_settings_connection_connection_interface_init)
                         )

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
                g_snprintf (__prefix, sizeof (__prefix), "%s[%p%s%s]", _NMLOG_PREFIX_NAME, self, __uuid ? "," : "", __uuid ? __uuid : ""); \
                __p_prefix = __prefix; \
            } \
            _nm_log (__level, _NMLOG_DOMAIN, 0, NULL, __uuid, \
                     "%s: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
                     __p_prefix _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
        } \
    } G_STMT_END

/*****************************************************************************/

static void
_emit_updated (NMSettingsConnection *self, gboolean by_user)
{
	g_signal_emit (self, signals[UPDATED], 0);
	g_signal_emit (self, signals[UPDATED_INTERNAL], 0, by_user);
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

	return nm_connection_compare (NM_CONNECTION (self), applied_connection, compare_flags);
}

/*****************************************************************************/

/* Return TRUE to keep, FALSE to drop */
typedef gboolean (*ForEachSecretFunc) (NMSettingSecretFlags flags,
                                       gpointer user_data);

/* Returns always a non-NULL, non-floating variant that must
 * be unrefed by the caller. */
static GVariant *
for_each_secret (NMConnection *self,
                 GVariant *secrets,
                 gboolean remove_non_secrets,
                 ForEachSecretFunc callback,
                 gpointer callback_data)
{
	GVariantBuilder secrets_builder, setting_builder;
	GVariantIter secrets_iter, *setting_iter;
	const char *setting_name;

	/* This function, given a dict of dicts representing new secrets of
	 * an NMConnection, walks through each toplevel dict (which represents a
	 * NMSetting), and for each setting, walks through that setting dict's
	 * properties.  For each property that's a secret, it will check that
	 * secret's flags in the backing NMConnection object, and call a supplied
	 * callback.
	 *
	 * The one complexity is that the VPN setting's 'secrets' property is
	 * *also* a dict (since the key/value pairs are arbitrary and known
	 * only to the VPN plugin itself).  That means we have three levels of
	 * dicts that we potentially have to traverse here.  When we hit the
	 * VPN setting's 'secrets' property, we special-case that and iterate over
	 * each item in that 'secrets' dict, calling the supplied callback
	 * each time.
	 */

	g_return_val_if_fail (callback, NULL);

	g_variant_iter_init (&secrets_iter, secrets);
	g_variant_builder_init (&secrets_builder, NM_VARIANT_TYPE_CONNECTION);
	while (g_variant_iter_next (&secrets_iter, "{&sa{sv}}", &setting_name, &setting_iter)) {
		NMSetting *setting;
		const char *secret_name;
		GVariant *val;

		setting = nm_connection_get_setting_by_name (self, setting_name);
		if (setting == NULL) {
			g_variant_iter_free (setting_iter);
			continue;
		}

		g_variant_builder_init (&setting_builder, NM_VARIANT_TYPE_SETTING);
		while (g_variant_iter_next (setting_iter, "{&sv}", &secret_name, &val)) {
			NMSettingSecretFlags secret_flags = NM_SETTING_SECRET_FLAG_NONE;

			/* VPN secrets need slightly different treatment here since the
			 * "secrets" property is actually a hash table of secrets.
			 */
			if (NM_IS_SETTING_VPN (setting) && !g_strcmp0 (secret_name, NM_SETTING_VPN_SECRETS)) {
				GVariantBuilder vpn_secrets_builder;
				GVariantIter vpn_secrets_iter;
				const char *vpn_secret_name, *secret;

				/* Iterate through each secret from the VPN dict in the overall secrets dict */
				g_variant_builder_init (&vpn_secrets_builder, G_VARIANT_TYPE ("a{ss}"));
				g_variant_iter_init (&vpn_secrets_iter, val);
				while (g_variant_iter_next (&vpn_secrets_iter, "{&s&s}", &vpn_secret_name, &secret)) {
					if (!nm_setting_get_secret_flags (setting, vpn_secret_name, &secret_flags, NULL)) {
						if (!remove_non_secrets)
							g_variant_builder_add (&vpn_secrets_builder, "{ss}", vpn_secret_name, secret);
						continue;
					}

					if (callback (secret_flags, callback_data))
						g_variant_builder_add (&vpn_secrets_builder, "{ss}", vpn_secret_name, secret);
				}

				g_variant_builder_add (&setting_builder, "{sv}",
				                       secret_name, g_variant_builder_end (&vpn_secrets_builder));
			} else {
				if (!nm_setting_get_secret_flags (setting, secret_name, &secret_flags, NULL)) {
					if (!remove_non_secrets)
						g_variant_builder_add (&setting_builder, "{sv}", secret_name, val);
					continue;
				}
				if (callback (secret_flags, callback_data))
					g_variant_builder_add (&setting_builder, "{sv}", secret_name, val);
			}
			g_variant_unref (val);
		}

		g_variant_iter_free (setting_iter);
		g_variant_builder_add (&secrets_builder, "{sa{sv}}", setting_name, &setting_builder);
	}

	return g_variant_ref_sink (g_variant_builder_end (&secrets_builder));
}

typedef gboolean (*FindSecretFunc) (NMSettingSecretFlags flags,
                                    gpointer user_data);

typedef struct {
	FindSecretFunc find_func;
	gpointer find_func_data;
	gboolean found;
} FindSecretData;

static gboolean
find_secret_for_each_func (NMSettingSecretFlags flags,
                           gpointer user_data)
{
	FindSecretData *data = user_data;

	if (!data->found)
		data->found = data->find_func (flags, data->find_func_data);
	return FALSE;
}

static gboolean
find_secret (NMConnection *self,
             GVariant *secrets,
             FindSecretFunc callback,
             gpointer callback_data)
{
	FindSecretData data;
	GVariant *dummy;

	data.find_func = callback;
	data.find_func_data = callback_data;
	data.found = FALSE;

	dummy = for_each_secret (self, secrets, FALSE, find_secret_for_each_func, &data);
	g_variant_unref (dummy);
	return data.found;
}

/*****************************************************************************/

static void
set_visible (NMSettingsConnection *self, gboolean new_visible)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);

	if (new_visible == priv->visible)
		return;
	priv->visible = new_visible;
	_notify (self, PROP_VISIBLE);
}

gboolean
nm_settings_connection_is_visible (NMSettingsConnection *self)
{
	g_return_val_if_fail (NM_IS_SETTINGS_CONNECTION (self), FALSE);

	return NM_SETTINGS_CONNECTION_GET_PRIVATE (self)->visible;
}

void
nm_settings_connection_recheck_visibility (NMSettingsConnection *self)
{
	NMSettingsConnectionPrivate *priv;
	NMSettingConnection *s_con;
	guint32 num, i;

	g_return_if_fail (NM_IS_SETTINGS_CONNECTION (self));

	priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);

	s_con = nm_connection_get_setting_connection (NM_CONNECTION (self));
	g_assert (s_con);

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
session_changed_cb (NMSessionMonitor *self, gpointer user_data)
{
	nm_settings_connection_recheck_visibility (NM_SETTINGS_CONNECTION (user_data));
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

	if (priv->visible == FALSE)
		return FALSE;

	s_con = nm_connection_get_setting_connection (NM_CONNECTION (self));
	g_assert (s_con);

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
	priv->system_secrets = nm_simple_connection_new_clone (NM_CONNECTION (self));

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
	priv->agent_secrets = nm_simple_connection_new_clone (new ? new : NM_CONNECTION (self));

	/* Clear out non-system-owned secrets */
	nm_connection_clear_secrets_with_flags (priv->agent_secrets,
	                                        secrets_filter_cb,
	                                        GUINT_TO_POINTER (filter_flags));
}

static void
secrets_cleared_cb (NMSettingsConnection *self)
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
set_unsaved (NMSettingsConnection *self, gboolean now_unsaved)
{
	NMSettingsConnectionFlags flags = nm_settings_connection_get_flags (self);

	if (NM_FLAGS_HAS (flags, NM_SETTINGS_CONNECTION_FLAGS_UNSAVED) != !!now_unsaved) {
		if (now_unsaved)
			flags |= NM_SETTINGS_CONNECTION_FLAGS_UNSAVED;
		else {
			flags &= ~(NM_SETTINGS_CONNECTION_FLAGS_UNSAVED |
			           NM_SETTINGS_CONNECTION_FLAGS_NM_GENERATED |
			           NM_SETTINGS_CONNECTION_FLAGS_VOLATILE);
		}
		nm_settings_connection_set_flags_all (self, flags);
	}
}

static void
connection_changed_cb (NMSettingsConnection *self, gpointer unused)
{
	set_unsaved (self, TRUE);
	_emit_updated (self, FALSE);
}

/* Update the settings of this connection to match that of 'new_connection',
 * taking care to make a private copy of secrets.
 */
gboolean
nm_settings_connection_replace_settings (NMSettingsConnection *self,
                                         NMConnection *new_connection,
                                         gboolean update_unsaved,
                                         const char *log_diff_name,
                                         GError **error)
{
	NMSettingsConnectionPrivate *priv;
	gboolean success = FALSE;

	g_return_val_if_fail (NM_IS_SETTINGS_CONNECTION (self), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (new_connection), FALSE);

	priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);

	if (!nm_connection_normalize (new_connection, NULL, NULL, error))
		return FALSE;

	if (   nm_connection_get_path (NM_CONNECTION (self))
	    && g_strcmp0 (nm_settings_connection_get_uuid (self), nm_connection_get_uuid (new_connection)) != 0) {
		/* Updating the UUID is not allowed once the path is exported. */
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "connection %s cannot change the UUID from %s to %s", nm_settings_connection_get_id (self),
		             nm_settings_connection_get_uuid (self), nm_connection_get_uuid (new_connection));
		return FALSE;
	}

	/* Do nothing if there's nothing to update */
	if (nm_connection_compare (NM_CONNECTION (self),
	                           new_connection,
	                           NM_SETTING_COMPARE_FLAG_EXACT)) {
		return TRUE;
	}

	/* Disconnect the changed signal to ensure we don't set Unsaved when
	 * it's not required.
	 */
	g_signal_handlers_block_by_func (self, G_CALLBACK (connection_changed_cb), NULL);

	if (log_diff_name)
		nm_utils_log_connection_diff (new_connection, NM_CONNECTION (self), LOGL_DEBUG, LOGD_CORE, log_diff_name, "++ ");

	nm_connection_replace_settings_from_connection (NM_CONNECTION (self), new_connection);

	_LOGD ("replace settings from connection %p (%s)", new_connection, nm_connection_get_id (NM_CONNECTION (self)));

	nm_settings_connection_set_flags (self,
	                                  NM_SETTINGS_CONNECTION_FLAGS_NM_GENERATED | NM_SETTINGS_CONNECTION_FLAGS_VOLATILE,
	                                  FALSE);

	/* Cache the just-updated system secrets in case something calls
	 * nm_connection_clear_secrets() and clears them.
	 */
	update_system_secrets_cache (self);
	success = TRUE;

	/* Add agent and always-ask secrets back; they won't necessarily be
	 * in the replacement connection data if it was eg reread from disk.
	 */
	if (priv->agent_secrets) {
		GVariant *dict;

		dict = nm_connection_to_dbus (priv->agent_secrets, NM_CONNECTION_SERIALIZE_ONLY_SECRETS);
		if (dict) {
			(void) nm_connection_update_secrets (NM_CONNECTION (self), NULL, dict, NULL);
			g_variant_unref (dict);
		}
	}

	nm_settings_connection_recheck_visibility (self);

	/* Manually emit changed signal since we disconnected the handler, but
	 * only update Unsaved if the caller wanted us to.
	 */
	if (update_unsaved)
		set_unsaved (self, TRUE);

	g_signal_handlers_unblock_by_func (self, G_CALLBACK (connection_changed_cb), NULL);

	_emit_updated (self, TRUE);

	return success;
}

static void
ignore_cb (NMSettingsConnection *self,
           GError *error,
           gpointer user_data)
{
}

/* Replaces the settings in this connection with those in 'new_connection'. If
 * any changes are made, commits them to permanent storage and to any other
 * subsystems watching this connection. Before returning, 'callback' is run
 * with the given 'user_data' along with any errors encountered.
 */
static void
replace_and_commit (NMSettingsConnection *self,
                    NMConnection *new_connection,
                    NMSettingsConnectionCommitFunc callback,
                    gpointer user_data)
{
	GError *error = NULL;
	NMSettingsConnectionCommitReason commit_reason = NM_SETTINGS_CONNECTION_COMMIT_REASON_USER_ACTION;

	if (g_strcmp0 (nm_connection_get_id (NM_CONNECTION (self)),
	               nm_connection_get_id (new_connection)) != 0)
		commit_reason |= NM_SETTINGS_CONNECTION_COMMIT_REASON_ID_CHANGED;

	if (nm_settings_connection_replace_settings (self, new_connection, TRUE, "replace-and-commit-disk", &error))
		nm_settings_connection_commit_changes (self, commit_reason, callback, user_data);
	else {
		g_assert (error);
		if (callback)
			callback (self, error, user_data);
		g_clear_error (&error);
	}
}

void
nm_settings_connection_replace_and_commit (NMSettingsConnection *self,
                                           NMConnection *new_connection,
                                           NMSettingsConnectionCommitFunc callback,
                                           gpointer user_data)
{
	g_return_if_fail (NM_IS_SETTINGS_CONNECTION (self));
	g_return_if_fail (NM_IS_CONNECTION (new_connection));

	NM_SETTINGS_CONNECTION_GET_CLASS (self)->replace_and_commit (self, new_connection, callback, user_data);
}

static void
commit_changes (NMSettingsConnection *self,
                NMSettingsConnectionCommitReason commit_reason,
                NMSettingsConnectionCommitFunc callback,
                gpointer user_data)
{
	/* Subclasses only call this function if the save was successful, so at
	 * this point the connection is synced to disk and no longer unsaved.
	 */
	set_unsaved (self, FALSE);

	g_object_ref (self);
	callback (self, NULL, user_data);
	g_object_unref (self);
}

void
nm_settings_connection_commit_changes (NMSettingsConnection *self,
                                       NMSettingsConnectionCommitReason commit_reason,
                                       NMSettingsConnectionCommitFunc callback,
                                       gpointer user_data)
{
	g_return_if_fail (NM_IS_SETTINGS_CONNECTION (self));

	if (NM_SETTINGS_CONNECTION_GET_CLASS (self)->commit_changes) {
		NM_SETTINGS_CONNECTION_GET_CLASS (self)->commit_changes (self,
		                                                         commit_reason,
		                                                         callback ? callback : ignore_cb,
		                                                         user_data);
	} else {
		GError *error = g_error_new (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_FAILED,
		                             "%s: %s:%d commit_changes() unimplemented", __func__, __FILE__, __LINE__);
		if (callback)
			callback (self, error, user_data);
		g_error_free (error);
	}
}

void
nm_settings_connection_delete (NMSettingsConnection *self,
                               NMSettingsConnectionDeleteFunc callback,
                               gpointer user_data)
{
	g_return_if_fail (NM_IS_SETTINGS_CONNECTION (self));

	if (NM_SETTINGS_CONNECTION_GET_CLASS (self)->delete) {
		NM_SETTINGS_CONNECTION_GET_CLASS (self)->delete (self,
		                                                 callback ? callback : ignore_cb,
		                                                 user_data);
	} else {
		GError *error = g_error_new (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_FAILED,
		                             "%s: %s:%d delete() unimplemented", __func__, __FILE__, __LINE__);
		if (callback)
			callback (self, error, user_data);
		g_error_free (error);
	}
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

static void
do_delete (NMSettingsConnection *self,
           NMSettingsConnectionDeleteFunc callback,
           gpointer user_data)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);
	NMConnection *for_agents;

	g_object_ref (self);
	set_visible (self, FALSE);

	/* Tell agents to remove secrets for this connection */
	for_agents = nm_simple_connection_new_clone (NM_CONNECTION (self));
	nm_connection_clear_secrets (for_agents);
	nm_agent_manager_delete_secrets (priv->agent_mgr,
	                                 nm_connection_get_path (NM_CONNECTION (self)),
	                                 for_agents);
	g_object_unref (for_agents);

	/* Remove timestamp from timestamps database file */
	remove_entry_from_db (self, "timestamps");

	/* Remove connection from seen-bssids database file */
	remove_entry_from_db (self, "seen-bssids");

	nm_settings_connection_signal_remove (self, FALSE);

	callback (self, NULL, user_data);

	g_object_unref (self);
}

/*****************************************************************************/


typedef enum {
	GET_SECRETS_INFO_TYPE_REQ,
	GET_SECRETS_INFO_TYPE_IDLE,
} GetSecretsInfoType;

struct _NMSettingsConnectionCallId {
	NMSettingsConnection *self;
	gboolean had_applied_connection;
	NMConnection *applied_connection;
	NMSettingsConnectionSecretsFunc callback;
	gpointer callback_data;

	GetSecretsInfoType type;
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

typedef struct _NMSettingsConnectionCallId GetSecretsInfo;

static GetSecretsInfo *
_get_secrets_info_new (NMSettingsConnection *self,
                       NMConnection *applied_connection,
                       NMSettingsConnectionSecretsFunc callback,
                       gpointer callback_data)
{
	GetSecretsInfo *info;

	info = g_slice_new0 (GetSecretsInfo);

	info->self = self;
	if (applied_connection) {
		info->had_applied_connection = TRUE;
		info->applied_connection = applied_connection;
		g_object_add_weak_pointer (G_OBJECT (applied_connection), (gpointer *) &info->applied_connection);
	}
	info->callback = callback;
	info->callback_data = callback_data;

	return info;
}

static void
_get_secrets_info_callback (GetSecretsInfo *info,
                            const char *agent_username,
                            const char *setting_name,
                            GError *error)
{
	if (info->callback) {
		info->callback (info->self,
		                info,
		                agent_username,
		                setting_name,
		                error,
		                info->callback_data);
	}
}

static void
_get_secrets_info_free (GetSecretsInfo *info)
{
	g_return_if_fail (info && info->self);

	if (info->applied_connection)
		g_object_remove_weak_pointer (G_OBJECT (info->applied_connection), (gpointer *) &info->applied_connection);

	if (info->type == GET_SECRETS_INFO_TYPE_IDLE)
		g_clear_error (&info->t.idle.error);

	memset (info, 0, sizeof (*info));
	g_slice_free (GetSecretsInfo, info);
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
validate_secret_flags (NMSettingSecretFlags flags,
                       gpointer user_data)
{
	ForEachSecretFlags *cmp_flags = user_data;

	if (!NM_FLAGS_ALL (flags, cmp_flags->required))
		return FALSE;
	if (NM_FLAGS_ANY (flags, cmp_flags->forbidden))
		return FALSE;
	return TRUE;
}

static gboolean
secret_is_system_owned (NMSettingSecretFlags flags,
                        gpointer user_data)
{
	return !NM_FLAGS_HAS (flags, NM_SETTING_SECRET_FLAG_AGENT_OWNED);
}

static void
new_secrets_commit_cb (NMSettingsConnection *self,
                       GError *error,
                       gpointer user_data)
{
	if (error)
		_LOGW ("Error saving new secrets to backing storage: %s", error->message);
}

static void
get_cmp_flags (NMSettingsConnection *self, /* only needed for logging */
               GetSecretsInfo *info, /* only needed for logging */
               NMConnection *connection,
               const char *agent_dbus_owner,
               gboolean agent_has_modify,
               const char *setting_name, /* only needed for logging */
               NMSecretAgentGetSecretsFlags flags,
               GVariant *secrets,
               gboolean *agent_had_system,
               ForEachSecretFlags *cmp_flags)
{
	gboolean is_self = (((NMConnection *) self) == connection);

	g_return_if_fail (secrets);

	cmp_flags->required = NM_SETTING_SECRET_FLAG_NONE;
	cmp_flags->forbidden = NM_SETTING_SECRET_FLAG_NONE;

	*agent_had_system = FALSE;

	if (agent_dbus_owner) {
		if (is_self) {
			_LOGD ("(%s:%p) secrets returned from agent %s",
			       setting_name,
			       info,
			       agent_dbus_owner);
		}

		/* If the agent returned any system-owned secrets (initial connect and no
		 * secrets given when the connection was created, or something like that)
		 * make sure the agent's UID has the 'modify' permission before we use or
		 * save those system-owned secrets.  If not, discard them and use the
		 * existing secrets, or fail the connection.
		 */
		*agent_had_system = find_secret (connection, secrets, secret_is_system_owned, NULL);
		if (*agent_had_system) {
			if (flags == NM_SECRET_AGENT_GET_SECRETS_FLAG_NONE) {
				/* No user interaction was allowed when requesting secrets; the
				 * agent is being bad.  Remove system-owned secrets.
				 */
				if (is_self) {
					_LOGD ("(%s:%p) interaction forbidden but agent %s returned system secrets",
					       setting_name,
					       info,
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
					       info);
				}

				cmp_flags->required |= NM_SETTING_SECRET_FLAG_AGENT_OWNED;
			}
		}
	} else {
		if (is_self) {
			_LOGD ("(%s:%p) existing secrets returned",
			       setting_name,
			       info);
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

	if (!nm_connection_update_secrets (NM_CONNECTION (self), setting_name, secrets, error))
		return FALSE;

	update_system_secrets_cache (self);
	update_agent_secrets_cache (self, NULL);
	nm_settings_connection_commit_changes (self, NM_SETTINGS_CONNECTION_COMMIT_REASON_NONE,
	                                       new_secrets_commit_cb, NULL);

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
	GetSecretsInfo *info = user_data;
	NMSettingsConnection *self;
	NMSettingsConnectionPrivate *priv;
	NMConnection *applied_connection;
	gs_free_error GError *local = NULL;
	GVariant *dict;
	gboolean agent_had_system = FALSE;
	ForEachSecretFlags cmp_flags = { NM_SETTING_SECRET_FLAG_NONE, NM_SETTING_SECRET_FLAG_NONE };

	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = info->self;
	g_return_if_fail (NM_IS_SETTINGS_CONNECTION (self));

	priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);

	g_return_if_fail (g_slist_find (priv->get_secret_requests, info));

	priv->get_secret_requests = g_slist_remove (priv->get_secret_requests, info);

	if (error) {
		_LOGD ("(%s:%p) secrets request error: %s",
		       setting_name, info, error->message);

		_get_secrets_info_callback (info, NULL, setting_name, error);
		goto out;
	}

	if (   info->had_applied_connection
	    && !info->applied_connection) {
		g_set_error_literal (&local, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_SETTING_NOT_FOUND,
		                     "Applied connection deleted since requesting secrets");
		_get_secrets_info_callback (info, NULL, setting_name, local);
		goto out;
	}

	if (   info->had_applied_connection
	    && !nm_settings_connection_has_unmodified_applied_connection (self, info->applied_connection, NM_SETTING_COMPARE_FLAG_NONE)) {
		g_set_error_literal (&local, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		                     "The connection was modified since activation");
		_get_secrets_info_callback (info, NULL, setting_name, local);
		goto out;
	}

	if (!nm_connection_get_setting_by_name (NM_CONNECTION (self), setting_name)) {
		g_set_error (&local, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_SETTING_NOT_FOUND,
		             "Connection didn't have requested setting '%s'.",
		             setting_name);
		_get_secrets_info_callback (info, NULL, setting_name, local);
		goto out;
	}

	get_cmp_flags (self,
	               info,
	               NM_CONNECTION (self),
	               agent_dbus_owner,
	               agent_has_modify,
	               setting_name,
	               flags,
	               secrets,
	               &agent_had_system,
	               &cmp_flags);

	_LOGD ("(%s:%p) secrets request completed",
	       setting_name,
	       info);

	dict = nm_connection_to_dbus (priv->system_secrets, NM_CONNECTION_SERIALIZE_ONLY_SECRETS);

	/* Update the connection with our existing secrets from backing storage */
	nm_connection_clear_secrets (NM_CONNECTION (self));
	if (!dict || nm_connection_update_secrets (NM_CONNECTION (self), setting_name, dict, &local)) {
		GVariant *filtered_secrets;

		/* Update the connection with the agent's secrets; by this point if any
		 * system-owned secrets exist in 'secrets' the agent that provided them
		 * will have been authenticated, so those secrets can replace the existing
		 * system secrets.
		 */
		filtered_secrets = for_each_secret (NM_CONNECTION (self), secrets, TRUE, validate_secret_flags, &cmp_flags);
		if (nm_connection_update_secrets (NM_CONNECTION (self), setting_name, filtered_secrets, &local)) {
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
				       info);

				nm_settings_connection_commit_changes (self, NM_SETTINGS_CONNECTION_COMMIT_REASON_NONE, new_secrets_commit_cb, NULL);
			} else {
				_LOGD ("(%s:%p) new agent secrets processed",
				       setting_name,
				       info);
			}

		} else {
			_LOGD ("(%s:%p) failed to update with agent secrets: %s",
			       setting_name,
			       info,
			       local->message);
		}
		g_variant_unref (filtered_secrets);
	} else {
		_LOGD ("(%s:%p) failed to update with existing secrets: %s",
		       setting_name,
		       info,
		       local->message);
	}

	applied_connection = info->applied_connection;
	if (applied_connection) {
		get_cmp_flags (self,
		               info,
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
			GVariant *filtered_secrets;

			filtered_secrets = for_each_secret (applied_connection, secrets, TRUE, validate_secret_flags, &cmp_flags);
			nm_connection_update_secrets (applied_connection, setting_name, filtered_secrets, NULL);
			g_variant_unref (filtered_secrets);
		}
	}

	_get_secrets_info_callback (info, agent_username, setting_name, local);
	g_clear_error (&local);
	if (dict)
		g_variant_unref (dict);

out:
	_get_secrets_info_free (info);
}

static gboolean
get_secrets_idle_cb (GetSecretsInfo *info)
{
	NMSettingsConnectionPrivate *priv;

	g_return_val_if_fail (info && NM_IS_SETTINGS_CONNECTION (info->self), G_SOURCE_REMOVE);

	priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (info->self);

	g_return_val_if_fail (g_slist_find (priv->get_secret_requests, info), G_SOURCE_REMOVE);

	priv->get_secret_requests = g_slist_remove (priv->get_secret_requests, info);

	_get_secrets_info_callback (info, NULL, NULL, info->t.idle.error);

	_get_secrets_info_free (info);
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
NMSettingsConnectionCallId
nm_settings_connection_get_secrets (NMSettingsConnection *self,
                                    NMConnection *applied_connection,
                                    NMAuthSubject *subject,
                                    const char *setting_name,
                                    NMSecretAgentGetSecretsFlags flags,
                                    const char **hints,
                                    NMSettingsConnectionSecretsFunc callback,
                                    gpointer callback_data)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);
	GVariant *existing_secrets;
	NMAgentManagerCallId call_id_a;
	gs_free char *joined_hints = NULL;
	GetSecretsInfo *info;
	GError *local = NULL;

	g_return_val_if_fail (NM_IS_SETTINGS_CONNECTION (self), NULL);
	g_return_val_if_fail (   !applied_connection
	                      || (   NM_IS_CONNECTION (applied_connection)
	                          && (((NMConnection *) self) != applied_connection)), NULL);

	info = _get_secrets_info_new (self,
	                              applied_connection,
	                              callback,
	                              callback_data);

	priv->get_secret_requests = g_slist_append (priv->get_secret_requests, info);

	/* Use priv->secrets to work around the fact that nm_connection_clear_secrets()
	 * will clear secrets on this object's settings.
	 */
	if (!priv->system_secrets) {
		g_set_error_literal (&local, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		                     "secrets cache invalid");
		goto schedule_dummy;
	}

	/* Make sure the request actually requests something we can return */
	if (!nm_connection_get_setting_by_name (NM_CONNECTION (self), setting_name)) {
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

	existing_secrets = nm_connection_to_dbus (priv->system_secrets, NM_CONNECTION_SERIALIZE_ONLY_SECRETS);
	if (existing_secrets)
		g_variant_ref_sink (existing_secrets);
	call_id_a = nm_agent_manager_get_secrets (priv->agent_mgr,
	                                          nm_connection_get_path (NM_CONNECTION (self)),
	                                          NM_CONNECTION (self),
	                                          subject,
	                                          existing_secrets,
	                                          setting_name,
	                                          flags,
	                                          hints,
	                                          get_secrets_done_cb,
	                                          info);
	g_assert (call_id_a);
	if (existing_secrets)
		g_variant_unref (existing_secrets);

	_LOGD ("(%s:%p) secrets requested flags 0x%X hints '%s'",
	       setting_name,
	       call_id_a,
	       flags,
	       (hints && hints[0]) ? (joined_hints = g_strjoinv (",", (char **) hints)) : "(none)");

	if (call_id_a) {
		info->type = GET_SECRETS_INFO_TYPE_REQ;
		info->t.req.id = call_id_a;
	} else {
schedule_dummy:
		info->type = GET_SECRETS_INFO_TYPE_IDLE;
		g_propagate_error (&info->t.idle.error, local);
		info->t.idle.id = g_idle_add ((GSourceFunc) get_secrets_idle_cb, info);
	}
	return info;
}

static void
_get_secrets_cancel (NMSettingsConnection *self,
                     GetSecretsInfo *info,
                     gboolean is_disposing)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);
	gs_free_error GError *error = NULL;

	if (!g_slist_find (priv->get_secret_requests, info))
		g_return_if_reached ();

	priv->get_secret_requests = g_slist_remove (priv->get_secret_requests, info);

	if (info->type == GET_SECRETS_INFO_TYPE_REQ)
		nm_agent_manager_cancel_secrets (priv->agent_mgr, info->t.req.id);
	else
		g_source_remove (info->t.idle.id);

	nm_utils_error_set_cancelled (&error, is_disposing, "NMSettingsConnection");

	_get_secrets_info_callback (info, NULL, NULL, error);

	_get_secrets_info_free (info);
}

void
nm_settings_connection_cancel_secrets (NMSettingsConnection *self,
                                       NMSettingsConnectionCallId call_id)
{
	_LOGD ("(%p) secrets canceled", call_id);

	_get_secrets_cancel (self, call_id, FALSE);
}

/**** User authorization **************************************/

typedef void (*AuthCallback) (NMSettingsConnection *self,
                              GDBusMethodInvocation *context,
                              NMAuthSubject *subject,
                              GError *error,
                              gpointer data);

static void
pk_auth_cb (NMAuthChain *chain,
            GError *chain_error,
            GDBusMethodInvocation *context,
            gpointer user_data)
{
	NMSettingsConnection *self = NM_SETTINGS_CONNECTION (user_data);
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);
	GError *error = NULL;
	NMAuthCallResult result;
	const char *perm;
	AuthCallback callback;
	gpointer callback_data;
	NMAuthSubject *subject;

	priv->pending_auths = g_slist_remove (priv->pending_auths, chain);

	perm = nm_auth_chain_get_data (chain, "perm");
	g_assert (perm);
	result = nm_auth_chain_get_result (chain, perm);

	/* If our NMSettingsConnection is already gone, do nothing */
	if (chain_error) {
		error = g_error_new (NM_SETTINGS_ERROR,
		                     NM_SETTINGS_ERROR_FAILED,
		                     "Error checking authorization: %s",
		                     chain_error->message ? chain_error->message : "(unknown)");
	} else if (result != NM_AUTH_CALL_RESULT_YES) {
		error = g_error_new_literal (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_PERMISSION_DENIED,
		                             "Insufficient privileges.");
	}

	callback = nm_auth_chain_get_data (chain, "callback");
	callback_data = nm_auth_chain_get_data (chain, "callback-data");
	subject = nm_auth_chain_get_data (chain, "subject");
	callback (self, context, subject, error, callback_data);

	g_clear_error (&error);
	nm_auth_chain_unref (chain);
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

static void
auth_start (NMSettingsConnection *self,
            GDBusMethodInvocation *context,
            NMAuthSubject *subject,
            const char *check_permission,
            AuthCallback callback,
            gpointer callback_data)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);
	NMAuthChain *chain;
	GError *error = NULL;
	char *error_desc = NULL;

	g_return_if_fail (context != NULL);
	g_return_if_fail (NM_IS_AUTH_SUBJECT (subject));

	/* Ensure the caller can view this connection */
	if (!nm_auth_is_subject_in_acl (NM_CONNECTION (self),
	                                subject,
	                                &error_desc)) {
		error = g_error_new_literal (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_PERMISSION_DENIED,
		                             error_desc);
		g_free (error_desc);

		callback (self, context, subject, error, callback_data);
		g_clear_error (&error);
		return;
	}

	if (!check_permission) {
		/* Don't need polkit auth, automatic success */
		callback (self, context, subject, NULL, callback_data);
		return;
	}

	chain = nm_auth_chain_new_subject (subject, context, pk_auth_cb, self);
	if (!chain) {
		g_set_error_literal (&error,
		                     NM_SETTINGS_ERROR,
		                     NM_SETTINGS_ERROR_PERMISSION_DENIED,
		                     "Unable to authenticate the request.");
		callback (self, context, subject, error, callback_data);
		g_clear_error (&error);
		return;
	}

	priv->pending_auths = g_slist_append (priv->pending_auths, chain);
	nm_auth_chain_set_data (chain, "perm", (gpointer) check_permission, NULL);
	nm_auth_chain_set_data (chain, "callback", callback, NULL);
	nm_auth_chain_set_data (chain, "callback-data", callback_data, NULL);
	nm_auth_chain_set_data (chain, "subject", g_object_ref (subject), g_object_unref);
	nm_auth_chain_add_call (chain, check_permission, TRUE);
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
		GVariant *settings;
		NMConnection *dupl_con;
		NMSettingConnection *s_con;
		NMSettingWireless *s_wifi;
		guint64 timestamp = 0;
		char **bssids;

		dupl_con = nm_simple_connection_new_clone (NM_CONNECTION (self));
		g_assert (dupl_con);

		/* Timestamp is not updated in connection's 'timestamp' property,
		 * because it would force updating the connection and in turn
		 * writing to /etc periodically, which we want to avoid. Rather real
		 * timestamps are kept track of in a private variable. So, substitute
		 * timestamp property with the real one here before returning the settings.
		 */
		nm_settings_connection_get_timestamp (self, &timestamp);
		if (timestamp) {
			s_con = nm_connection_get_setting_connection (NM_CONNECTION (dupl_con));
			g_assert (s_con);
			g_object_set (s_con, NM_SETTING_CONNECTION_TIMESTAMP, timestamp, NULL);
		}
		/* Seen BSSIDs are not updated in 802-11-wireless 'seen-bssids' property
		 * from the same reason as timestamp. Thus we put it here to GetSettings()
		 * return settings too.
		 */
		bssids = nm_settings_connection_get_seen_bssids (self);
		s_wifi = nm_connection_get_setting_wireless (NM_CONNECTION (dupl_con));
		if (bssids && bssids[0] && s_wifi)
			g_object_set (s_wifi, NM_SETTING_WIRELESS_SEEN_BSSIDS, bssids, NULL);
		g_free (bssids);

		/* Secrets should *never* be returned by the GetSettings method, they
		 * get returned by the GetSecrets method which can be better
		 * protected against leakage of secrets to unprivileged callers.
		 */
		settings = nm_connection_to_dbus (NM_CONNECTION (dupl_con), NM_CONNECTION_SERIALIZE_NO_SECRETS);
		g_assert (settings);
		g_dbus_method_invocation_return_value (context,
		                                       g_variant_new ("(@a{sa{sv}})", settings));
		g_object_unref (dupl_con);
	}
}

static void
impl_settings_connection_get_settings (NMSettingsConnection *self,
                                       GDBusMethodInvocation *context)
{
	NMAuthSubject *subject;
	GError *error = NULL;

	subject = _new_auth_subject (context, &error);
	if (subject) {
		auth_start (self, context, subject, NULL, get_settings_auth_cb, NULL);
		g_object_unref (subject);
	} else
		g_dbus_method_invocation_take_error (context, error);
}

typedef struct {
	GDBusMethodInvocation *context;
	NMAgentManager *agent_mgr;
	NMAuthSubject *subject;
	NMConnection *new_settings;
	gboolean save_to_disk;
	char *audit_args;
} UpdateInfo;

typedef struct {
	GDBusMethodInvocation *context;
	NMAuthSubject *subject;
} CallbackInfo;

static void
has_some_secrets_cb (NMSetting *setting,
                     const char *key,
                     const GValue *value,
                     GParamFlags flags,
                     gpointer user_data)
{
	GParamSpec *pspec;

	if (NM_IS_SETTING_VPN (setting)) {
		if (nm_setting_vpn_get_num_secrets (NM_SETTING_VPN(setting)))
			*((gboolean *) user_data) = TRUE;
		return;
	}

	pspec = g_object_class_find_property (G_OBJECT_GET_CLASS (G_OBJECT (setting)), key);
	if (pspec) {
		if (   (flags & NM_SETTING_PARAM_SECRET)
		    && !g_param_value_defaults (pspec, (GValue *)value))
			*((gboolean *) user_data) = TRUE;
	}
}

static gboolean
any_secrets_present (NMConnection *self)
{
	gboolean has_secrets = FALSE;

	nm_connection_for_each_setting_value (self, has_some_secrets_cb, &has_secrets);
	return has_secrets;
}

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
	else
		g_dbus_method_invocation_return_value (info->context, NULL);

	nm_audit_log_connection_op (NM_AUDIT_OP_CONN_UPDATE, self, !error, info->audit_args,
	                            info->subject, error ? error->message : NULL);

	g_clear_object (&info->subject);
	g_clear_object (&info->agent_mgr);
	g_clear_object (&info->new_settings);
	g_free (info->audit_args);
	memset (info, 0, sizeof (*info));
	g_free (info);
}

static void
con_update_cb (NMSettingsConnection *self,
               GError *error,
               gpointer user_data)
{
	UpdateInfo *info = user_data;
	NMConnection *for_agent;

	if (!error) {
		/* Dupe the connection so we can clear out non-agent-owned secrets,
		 * as agent-owned secrets are the only ones we send back be saved.
		 * Only send secrets to agents of the same UID that called update too.
		 */
		for_agent = nm_simple_connection_new_clone (NM_CONNECTION (self));
		nm_connection_clear_secrets_with_flags (for_agent,
		                                        secrets_filter_cb,
		                                        GUINT_TO_POINTER (NM_SETTING_SECRET_FLAG_AGENT_OWNED));
		nm_agent_manager_save_secrets (info->agent_mgr,
		                               nm_connection_get_path (NM_CONNECTION (self)),
		                               for_agent,
		                               info->subject);
		g_object_unref (for_agent);
	}

	update_complete (self, info, error);
}

static void
update_auth_cb (NMSettingsConnection *self,
                GDBusMethodInvocation *context,
                NMAuthSubject *subject,
                GError *error,
                gpointer data)
{
	UpdateInfo *info = data;
	GError *local = NULL;

	if (error) {
		update_complete (self, info, error);
		return;
	}

	if (!info->new_settings) {
		/* We're just calling Save(). Just commit the existing connection. */
		if (info->save_to_disk) {
			nm_settings_connection_commit_changes (self,
			                                       NM_SETTINGS_CONNECTION_COMMIT_REASON_USER_ACTION,
			                                       con_update_cb,
			                                       info);
		}
		return;
	}

	if (!any_secrets_present (info->new_settings)) {
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

	if (nm_audit_manager_audit_enabled (nm_audit_manager_get ())) {
		gs_unref_hashtable GHashTable *diff = NULL;
		gboolean same;

		same = nm_connection_diff (NM_CONNECTION (self), info->new_settings,
		                           NM_SETTING_COMPARE_FLAG_EXACT |
		                           NM_SETTING_COMPARE_FLAG_DIFF_RESULT_NO_DEFAULT,
		                           &diff);
		if (!same && diff)
			info->audit_args = nm_utils_format_con_diff_for_audit (diff);
	}

	if (info->save_to_disk) {
		nm_settings_connection_replace_and_commit (self,
		                                           info->new_settings,
		                                           con_update_cb,
		                                           info);
	} else {
		if (!nm_settings_connection_replace_settings (self, info->new_settings, TRUE, "replace-and-commit-memory", &local))
			g_assert (local);
		con_update_cb (self, local, info);
		g_clear_error (&local);
	}
}

static const char *
get_update_modify_permission (NMConnection *old, NMConnection *new)
{
	NMSettingConnection *s_con;
	guint32 orig_num = 0, new_num = 0;

	s_con = nm_connection_get_setting_connection (old);
	g_assert (s_con);
	orig_num = nm_setting_connection_get_num_permissions (s_con);

	s_con = nm_connection_get_setting_connection (new);
	g_assert (s_con);
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
settings_connection_update_helper (NMSettingsConnection *self,
                                   GDBusMethodInvocation *context,
                                   GVariant *new_settings,
                                   gboolean save_to_disk)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);
	NMAuthSubject *subject = NULL;
	NMConnection *tmp = NULL;
	GError *error = NULL;
	UpdateInfo *info;
	const char *permission;
	char *error_desc = NULL;

	g_assert (new_settings != NULL || save_to_disk == TRUE);

	/* If the connection is read-only, that has to be changed at the source of
	 * the problem (ex a system settings plugin that can't write connections out)
	 * instead of over D-Bus.
	 */
	if (!check_writable (NM_CONNECTION (self), &error))
		goto error;

	/* Check if the settings are valid first */
	if (new_settings) {
		tmp = _nm_simple_connection_new_from_dbus (new_settings,
		                                             NM_SETTING_PARSE_FLAGS_STRICT
		                                           | NM_SETTING_PARSE_FLAGS_NORMALIZE,
		                                           &error);
		if (!tmp)
			goto error;
	}

	subject = _new_auth_subject (context, &error);
	if (!subject)
		goto error;

	/* And that the new connection settings will be visible to the user
	 * that's sending the update request.  You can't make a connection
	 * invisible to yourself.
	 */
	if (!nm_auth_is_subject_in_acl (tmp ? tmp : NM_CONNECTION (self),
	                                subject,
	                                &error_desc)) {
		error = g_error_new_literal (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_PERMISSION_DENIED,
		                             error_desc);
		g_free (error_desc);
		goto error;
	}

	info = g_malloc0 (sizeof (*info));
	info->context = context;
	info->agent_mgr = g_object_ref (priv->agent_mgr);
	info->subject = subject;
	info->save_to_disk = save_to_disk;
	info->new_settings = tmp;

	permission = get_update_modify_permission (NM_CONNECTION (self),
	                                           tmp ? tmp : NM_CONNECTION (self));
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
impl_settings_connection_update (NMSettingsConnection *self,
                                 GDBusMethodInvocation *context,
                                 GVariant *new_settings)
{
	settings_connection_update_helper (self, context, new_settings, TRUE);
}

static void
impl_settings_connection_update_unsaved (NMSettingsConnection *self,
                                         GDBusMethodInvocation *context,
                                         GVariant *new_settings)
{
	settings_connection_update_helper (self, context, new_settings, FALSE);
}

static void
impl_settings_connection_save (NMSettingsConnection *self,
                               GDBusMethodInvocation *context)
{
	settings_connection_update_helper (self, context, NULL, TRUE);
}

static void
con_delete_cb (NMSettingsConnection *self,
               GError *error,
               gpointer user_data)
{
	CallbackInfo *info = user_data;

	if (error)
		g_dbus_method_invocation_return_gerror (info->context, error);
	else
		g_dbus_method_invocation_return_value (info->context, NULL);

	nm_audit_log_connection_op (NM_AUDIT_OP_CONN_DELETE, self,
	                            !error, NULL, info->subject, error ? error->message : NULL);
	g_free (info);
}

static void
delete_auth_cb (NMSettingsConnection *self,
                GDBusMethodInvocation *context,
                NMAuthSubject *subject,
                GError *error,
                gpointer data)
{
	CallbackInfo *info;

	if (error) {
		nm_audit_log_connection_op (NM_AUDIT_OP_CONN_DELETE, self, FALSE, NULL, subject,
		                            error->message);
		g_dbus_method_invocation_return_gerror (context, error);
		return;
	}

	info = g_malloc0 (sizeof (*info));
	info->context = context;
	info->subject = subject;

	nm_settings_connection_delete (self, con_delete_cb, info);
}

static const char *
get_modify_permission_basic (NMSettingsConnection *self)
{
	NMSettingConnection *s_con;

	/* If the caller is the only user in the connection's permissions, then
	 * we use the 'modify.own' permission instead of 'modify.system'.  If the
	 * request affects more than just the caller, require 'modify.system'.
	 */
	s_con = nm_connection_get_setting_connection (NM_CONNECTION (self));
	g_assert (s_con);
	if (nm_setting_connection_get_num_permissions (s_con) == 1)
		return NM_AUTH_PERMISSION_SETTINGS_MODIFY_OWN;

	return NM_AUTH_PERMISSION_SETTINGS_MODIFY_SYSTEM;
}

static void
impl_settings_connection_delete (NMSettingsConnection *self,
                                 GDBusMethodInvocation *context)
{
	NMAuthSubject *subject = NULL;
	GError *error = NULL;

	if (!check_writable (NM_CONNECTION (self), &error))
		goto out_err;

	subject = _new_auth_subject (context, &error);
	if (subject) {
		auth_start (self, context, subject, get_modify_permission_basic (self), delete_auth_cb, NULL);
		g_object_unref (subject);
	} else
		goto out_err;

	return;
out_err:
	nm_audit_log_connection_op (NM_AUDIT_OP_CONN_DELETE, self, FALSE, NULL, subject, error->message);
	g_dbus_method_invocation_take_error (context, error);
}

/*****************************************************************************/

static void
dbus_get_agent_secrets_cb (NMSettingsConnection *self,
                           NMSettingsConnectionCallId call_id,
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
		dict = nm_connection_to_dbus (NM_CONNECTION (self), NM_CONNECTION_SERIALIZE_ONLY_SECRETS);
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
impl_settings_connection_get_secrets (NMSettingsConnection *self,
                                      GDBusMethodInvocation *context,
                                      const gchar *setting_name)
{
	NMAuthSubject *subject;
	GError *error = NULL;

	subject = _new_auth_subject (context, &error);
	if (subject) {
		auth_start (self,
		            context,
		            subject,
		            get_modify_permission_basic (self),
		            dbus_get_secrets_auth_cb,
		            g_strdup (setting_name));
		g_object_unref (subject);
	} else
		g_dbus_method_invocation_take_error (context, error);
}

static void
clear_secrets_cb (NMSettingsConnection *self,
                  GError *error,
                  gpointer user_data)
{
	CallbackInfo *info = user_data;

	if (error)
		g_dbus_method_invocation_return_gerror (info->context, error);
	else
		g_dbus_method_invocation_return_value (info->context, NULL);

	nm_audit_log_connection_op (NM_AUDIT_OP_CONN_CLEAR_SECRETS, self,
	                            !error, NULL, info->subject, error ? error->message : NULL);
	g_free (info);
}

static void
dbus_clear_secrets_auth_cb (NMSettingsConnection *self,
                            GDBusMethodInvocation *context,
                            NMAuthSubject *subject,
                            GError *error,
                            gpointer user_data)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);
	CallbackInfo *info;

	if (error) {
		g_dbus_method_invocation_return_gerror (context, error);
		nm_audit_log_connection_op (NM_AUDIT_OP_CONN_CLEAR_SECRETS, self,
		                            FALSE, NULL, subject, error->message);
	} else {
		/* Clear secrets in connection and caches */
		nm_connection_clear_secrets (NM_CONNECTION (self));
		if (priv->system_secrets)
			nm_connection_clear_secrets (priv->system_secrets);
		if (priv->agent_secrets)
			nm_connection_clear_secrets (priv->agent_secrets);

		/* Tell agents to remove secrets for this connection */
		nm_agent_manager_delete_secrets (priv->agent_mgr,
		                                 nm_connection_get_path (NM_CONNECTION (self)),
		                                 NM_CONNECTION (self));

		info = g_malloc0 (sizeof (*info));
		info->context = context;
		info->subject = subject;

		nm_settings_connection_commit_changes (self, NM_SETTINGS_CONNECTION_COMMIT_REASON_NONE, clear_secrets_cb, info);
	}
}

static void
impl_settings_connection_clear_secrets (NMSettingsConnection *self,
                                        GDBusMethodInvocation *context)
{
	NMAuthSubject *subject;
	GError *error = NULL;

	subject = _new_auth_subject (context, &error);
	if (subject) {
		auth_start (self,
		            context,
		            subject,
		            get_modify_permission_basic (self),
		            dbus_clear_secrets_auth_cb,
		            NULL);
		g_object_unref (subject);
	} else {
		nm_audit_log_connection_op (NM_AUDIT_OP_CONN_CLEAR_SECRETS, self,
		                            FALSE, NULL, NULL, error->message);
		g_dbus_method_invocation_take_error (context, error);
	}
}

/*****************************************************************************/

void
nm_settings_connection_signal_remove (NMSettingsConnection *self, gboolean allow_reuse)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);

	if (!allow_reuse) {
		if (priv->removed)
			g_return_if_reached ();
		priv->removed = TRUE;
	}
	g_signal_emit_by_name (self, NM_SETTINGS_CONNECTION_REMOVED);
}

gboolean
nm_settings_connection_get_unsaved (NMSettingsConnection *self)
{
	return NM_FLAGS_HAS (nm_settings_connection_get_flags (self), NM_SETTINGS_CONNECTION_FLAGS_UNSAVED);
}

/*****************************************************************************/

NMSettingsConnectionFlags
nm_settings_connection_get_flags (NMSettingsConnection *self)
{
	g_return_val_if_fail (NM_IS_SETTINGS_CONNECTION (self), NM_SETTINGS_CONNECTION_FLAGS_NONE);

	return NM_SETTINGS_CONNECTION_GET_PRIVATE (self)->flags;
}

NMSettingsConnectionFlags
nm_settings_connection_set_flags (NMSettingsConnection *self, NMSettingsConnectionFlags flags, gboolean set)
{
	NMSettingsConnectionFlags new_flags;

	g_return_val_if_fail (NM_IS_SETTINGS_CONNECTION (self), NM_SETTINGS_CONNECTION_FLAGS_NONE);
	g_return_val_if_fail ((flags & ~NM_SETTINGS_CONNECTION_FLAGS_ALL) == 0, NM_SETTINGS_CONNECTION_FLAGS_NONE);

	new_flags = NM_SETTINGS_CONNECTION_GET_PRIVATE (self)->flags;
	if (set)
		new_flags |= flags;
	else
		new_flags &= ~flags;
	return nm_settings_connection_set_flags_all (self, new_flags);
}

NMSettingsConnectionFlags
nm_settings_connection_set_flags_all (NMSettingsConnection *self, NMSettingsConnectionFlags flags)
{
	NMSettingsConnectionPrivate *priv;
	NMSettingsConnectionFlags old_flags;

	g_return_val_if_fail (NM_IS_SETTINGS_CONNECTION (self), NM_SETTINGS_CONNECTION_FLAGS_NONE);
	g_return_val_if_fail ((flags & ~NM_SETTINGS_CONNECTION_FLAGS_ALL) == 0, NM_SETTINGS_CONNECTION_FLAGS_NONE);
	priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);

	old_flags = priv->flags;
	if (old_flags != flags) {
		_LOGT ("update settings-connection flags to 0x%x (was 0x%x)", (guint) flags, (guint) priv->flags);
		priv->flags = flags;
		_notify (self, PROP_FLAGS);
		if (NM_FLAGS_HAS (old_flags, NM_SETTINGS_CONNECTION_FLAGS_UNSAVED) != NM_FLAGS_HAS (flags, NM_SETTINGS_CONNECTION_FLAGS_UNSAVED))
			_notify (self, PROP_UNSAVED);
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
	int c;

	nm_assert (NM_IS_SETTINGS_CONNECTION (a));
	nm_assert (NM_IS_SETTINGS_CONNECTION (b));

	c = g_strcmp0 (nm_connection_get_uuid (NM_CONNECTION (a)),
	               nm_connection_get_uuid (NM_CONNECTION (b)));
	if (c)
		return c;

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
	int c;

	if (a == b)
		return 0;
	if (!a)
		return 1;
	if (!b)
		return -1;

	if ((c = _cmp_timestamp (a, b)))
		return c;
	if ((c = nm_utils_cmp_connection_by_autoconnect_priority (NM_CONNECTION (a), NM_CONNECTION (b))))
		return c;
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
	int c;

	if (a == b)
		return 0;
	if ((c = nm_utils_cmp_connection_by_autoconnect_priority (NM_CONNECTION (a), NM_CONNECTION (b))))
		return c;
	if ((c = _cmp_timestamp (a, b)))
		return c;
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
		s_wifi = nm_connection_get_setting_wireless (NM_CONNECTION (self));
		if (s_wifi) {
			len = nm_setting_wireless_get_num_seen_bssids (s_wifi);
			for (i = 0; i < len; i++) {
				char *bssid_dup = g_strdup (nm_setting_wireless_get_seen_bssid (s_wifi, i));

				g_hash_table_insert (priv->seen_bssids, bssid_dup, bssid_dup);
			}
		}
	}
}

/**
 * nm_settings_connection_get_autoconnect_retries:
 * @self: the settings connection
 *
 * Returns the number of autoconnect retries left. If the value is
 * not yet set, initialize it with the value from the connection or
 * with the global default.
 */
int
nm_settings_connection_get_autoconnect_retries (NMSettingsConnection *self)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);

	if (G_UNLIKELY (priv->autoconnect_retries == AUTOCONNECT_RETRIES_UNSET)) {
		NMSettingConnection *s_con;
		int retries = -1;
		const char *value;

		s_con = nm_connection_get_setting_connection ((NMConnection *) self);
		if (s_con)
			retries = nm_setting_connection_get_autoconnect_retries (s_con);

		/* -1 means 'default' */
		if (retries == -1) {
			value = nm_config_data_get_value_cached (NM_CONFIG_GET_DATA,
			                                         NM_CONFIG_KEYFILE_GROUP_MAIN,
			                                         "autoconnect-retries-default",
			                                         NM_CONFIG_GET_VALUE_STRIP);

			retries = _nm_utils_ascii_str_to_int64 (value,
			                                        10, 0, G_MAXINT32,
			                                        AUTOCONNECT_RETRIES_DEFAULT);
		}

		/* 0 means 'forever', which is translated to a retry count of -1 */
		if (retries == 0)
			retries = AUTOCONNECT_RETRIES_FOREVER;

		_LOGT ("autoconnect-retries: init %d", retries);
		priv->autoconnect_retries = retries;
	}

	return priv->autoconnect_retries;
}

void
nm_settings_connection_set_autoconnect_retries (NMSettingsConnection *self,
                                                int retries)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);

	nm_assert (retries == AUTOCONNECT_RETRIES_UNSET || retries >= 0);

	if (priv->autoconnect_retries != retries) {
		_LOGT ("autoconnect-retries: set %d", retries);
		priv->autoconnect_retries = retries;
	}
	if (retries)
		priv->autoconnect_retry_time = 0;
	else
		priv->autoconnect_retry_time = nm_utils_get_monotonic_timestamp_s () + AUTOCONNECT_RESET_RETRIES_TIMER;
}

void
nm_settings_connection_reset_autoconnect_retries (NMSettingsConnection *self)
{
	nm_settings_connection_set_autoconnect_retries (self, AUTOCONNECT_RETRIES_UNSET);
}

gint32
nm_settings_connection_get_autoconnect_retry_time (NMSettingsConnection *self)
{
	return NM_SETTINGS_CONNECTION_GET_PRIVATE (self)->autoconnect_retry_time;
}

NMSettingsAutoconnectBlockedReason
nm_settings_connection_get_autoconnect_blocked_reason (NMSettingsConnection *self)
{
	return NM_SETTINGS_CONNECTION_GET_PRIVATE (self)->autoconnect_blocked_reason;
}

void
nm_settings_connection_set_autoconnect_blocked_reason (NMSettingsConnection *self,
                                                       NMSettingsAutoconnectBlockedReason reason)
{
	g_return_if_fail (NM_IN_SET (reason,
	                             NM_SETTINGS_AUTO_CONNECT_BLOCKED_REASON_NONE,
	                             NM_SETTINGS_AUTO_CONNECT_BLOCKED_REASON_USER_REQUEST,
	                             NM_SETTINGS_AUTO_CONNECT_BLOCKED_REASON_FAILED,
	                             NM_SETTINGS_AUTO_CONNECT_BLOCKED_REASON_NO_SECRETS));
	NM_SETTINGS_CONNECTION_GET_PRIVATE (self)->autoconnect_blocked_reason = reason;
}

gboolean
nm_settings_connection_can_autoconnect (NMSettingsConnection *self)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);
	NMSettingConnection *s_con;
	const char *permission;

	if (   !priv->visible
	    || nm_settings_connection_get_autoconnect_retries (self) == 0
	    || priv->autoconnect_blocked_reason != NM_SETTINGS_AUTO_CONNECT_BLOCKED_REASON_NONE)
		return FALSE;

	s_con = nm_connection_get_setting_connection (NM_CONNECTION (self));
	if (!nm_setting_connection_get_autoconnect (s_con))
		return FALSE;

	permission = nm_utils_get_shared_wifi_permission (NM_CONNECTION (self));
	if (permission) {
		if (nm_settings_connection_check_permission (self, permission) == FALSE)
			return FALSE;
	}

	return TRUE;
}

/**
 * nm_settings_connection_get_nm_generated:
 * @self: an #NMSettingsConnection
 *
 * Gets the "nm-generated" flag on @self.
 *
 * A connection is "nm-generated" if it was generated by
 * nm_device_generate_connection() and has not been modified or
 * saved by the user since then.
 */
gboolean
nm_settings_connection_get_nm_generated (NMSettingsConnection *self)
{
	return NM_FLAGS_HAS (nm_settings_connection_get_flags (self), NM_SETTINGS_CONNECTION_FLAGS_NM_GENERATED);
}

/**
 * nm_settings_connection_get_volatile:
 * @self: an #NMSettingsConnection
 *
 * Gets the "volatile" flag on @self.
 *
 * The connection is marked as volatile and will be removed when
 * it disconnects.
 */
gboolean
nm_settings_connection_get_volatile (NMSettingsConnection *self)
{
	return NM_FLAGS_HAS (nm_settings_connection_get_flags (self), NM_SETTINGS_CONNECTION_FLAGS_VOLATILE);
}

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
	return nm_connection_get_id (NM_CONNECTION (self));
}

const char *
nm_settings_connection_get_uuid (NMSettingsConnection *self)
{
	return nm_connection_get_uuid (NM_CONNECTION (self));
}

/*****************************************************************************/

static void
nm_settings_connection_init (NMSettingsConnection *self)
{
	NMSettingsConnectionPrivate *priv;

	priv = G_TYPE_INSTANCE_GET_PRIVATE (self, NM_TYPE_SETTINGS_CONNECTION, NMSettingsConnectionPrivate);
	self->_priv = priv;

	priv->visible = FALSE;
	priv->ready = TRUE;

	priv->session_monitor = g_object_ref (nm_session_monitor_get ());
	priv->session_changed_id = g_signal_connect (priv->session_monitor,
	                                             NM_SESSION_MONITOR_CHANGED,
	                                             G_CALLBACK (session_changed_cb), self);

	priv->agent_mgr = g_object_ref (nm_agent_manager_get ());

	priv->seen_bssids = g_hash_table_new_full (nm_str_hash, g_str_equal, g_free, NULL);

	priv->autoconnect_retries = AUTOCONNECT_RETRIES_UNSET;

	g_signal_connect (self, NM_CONNECTION_SECRETS_CLEARED, G_CALLBACK (secrets_cleared_cb), NULL);
	g_signal_connect (self, NM_CONNECTION_CHANGED, G_CALLBACK (connection_changed_cb), NULL);
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

	_LOGD ("disposing");

	/* Cancel in-progress secrets requests */
	if (priv->agent_mgr) {
		while (priv->get_secret_requests) {
			GetSecretsInfo *info = priv->get_secret_requests->data;

			_get_secrets_cancel (self, info, TRUE);
			g_return_if_fail (!priv->get_secret_requests || (info != priv->get_secret_requests->data));
		}
	}

	/* Disconnect handlers.
	 * connection_changed_cb() has to be disconnected *before* nm_connection_clear_secrets(),
	 * because nm_connection_clear_secrets() emits NM_CONNECTION_CHANGED signal.
	 */
	g_signal_handlers_disconnect_by_func (self, G_CALLBACK (secrets_cleared_cb), NULL);
	g_signal_handlers_disconnect_by_func (self, G_CALLBACK (connection_changed_cb), NULL);

	nm_connection_clear_secrets (NM_CONNECTION (self));
	g_clear_object (&priv->system_secrets);
	g_clear_object (&priv->agent_secrets);

	/* Cancel PolicyKit requests */
	g_slist_free_full (priv->pending_auths, (GDestroyNotify) nm_auth_chain_unref);
	priv->pending_auths = NULL;

	g_clear_pointer (&priv->seen_bssids, (GDestroyNotify) g_hash_table_destroy);

	set_visible (self, FALSE);

	nm_clear_g_signal_handler (priv->session_monitor, &priv->session_changed_id);
	g_clear_object (&priv->session_monitor);

	g_clear_object (&priv->agent_mgr);

	g_clear_pointer (&priv->filename, g_free);

	G_OBJECT_CLASS (nm_settings_connection_parent_class)->dispose (object);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingsConnection *self = NM_SETTINGS_CONNECTION (object);
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_VISIBLE:
		g_value_set_boolean (value, priv->visible);
		break;
	case PROP_UNSAVED:
		g_value_set_boolean (value, nm_settings_connection_get_unsaved (self));
		break;
	case PROP_READY:
		g_value_set_boolean (value, nm_settings_connection_get_ready (self));
		break;
	case PROP_FLAGS:
		g_value_set_uint (value, nm_settings_connection_get_flags (self));
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

static void
nm_settings_connection_class_init (NMSettingsConnectionClass *class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (class);
	NMExportedObjectClass *exported_object_class = NM_EXPORTED_OBJECT_CLASS (class);

	g_type_class_add_private (class, sizeof (NMSettingsConnectionPrivate));

	exported_object_class->export_path = NM_EXPORT_PATH_NUMBERED (NM_DBUS_PATH_SETTINGS);

	object_class->constructed = constructed;
	object_class->dispose = dispose;
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	class->replace_and_commit = replace_and_commit;
	class->commit_changes = commit_changes;
	class->delete = do_delete;
	class->supports_secrets = supports_secrets;

	obj_properties[PROP_VISIBLE] =
	     g_param_spec_boolean (NM_SETTINGS_CONNECTION_VISIBLE, "", "",
	                           FALSE,
	                           G_PARAM_READABLE |
	                           G_PARAM_STATIC_STRINGS);

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
	                        NM_SETTINGS_CONNECTION_FLAGS_NONE,
	                        NM_SETTINGS_CONNECTION_FLAGS_ALL,
	                        NM_SETTINGS_CONNECTION_FLAGS_NONE,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_FILENAME] =
	     g_param_spec_string (NM_SETTINGS_CONNECTION_FILENAME, "", "",
	                          NULL,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);


	signals[UPDATED] =
	    g_signal_new (NM_SETTINGS_CONNECTION_UPDATED,
	                  G_TYPE_FROM_CLASS (class),
	                  G_SIGNAL_RUN_FIRST,
	                  0,
	                  NULL, NULL,
	                  g_cclosure_marshal_VOID__VOID,
	                  G_TYPE_NONE, 0);

	/* internal signal, with an argument (gboolean by_user). */
	signals[UPDATED_INTERNAL] =
	    g_signal_new (NM_SETTINGS_CONNECTION_UPDATED_INTERNAL,
	                  G_TYPE_FROM_CLASS (class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL,
	                  g_cclosure_marshal_VOID__BOOLEAN,
	                  G_TYPE_NONE, 1, G_TYPE_BOOLEAN);

	signals[REMOVED] =
	    g_signal_new (NM_SETTINGS_CONNECTION_REMOVED,
	                  G_TYPE_FROM_CLASS (class),
	                  G_SIGNAL_RUN_FIRST,
	                  0,
	                  NULL, NULL,
	                  g_cclosure_marshal_VOID__VOID,
	                  G_TYPE_NONE, 0);

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (class),
	                                        NMDBUS_TYPE_SETTINGS_CONNECTION_SKELETON,
	                                        "Update", impl_settings_connection_update,
	                                        "UpdateUnsaved", impl_settings_connection_update_unsaved,
	                                        "Delete", impl_settings_connection_delete,
	                                        "GetSettings", impl_settings_connection_get_settings,
	                                        "GetSecrets", impl_settings_connection_get_secrets,
	                                        "ClearSecrets", impl_settings_connection_clear_secrets,
	                                        "Save", impl_settings_connection_save,
	                                        NULL);
}

static void
nm_settings_connection_connection_interface_init (NMConnectionInterface *iface)
{
}

