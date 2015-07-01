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

#include "config.h"

#include <string.h>

#include <nm-dbus-interface.h>
#include <dbus/dbus-glib-lowlevel.h>

#include "nm-glib.h"
#include "nm-settings-connection.h"
#include "nm-session-monitor.h"
#include "nm-dbus-glib-types.h"
#include "nm-logging.h"
#include "nm-auth-utils.h"
#include "nm-auth-subject.h"
#include "nm-agent-manager.h"
#include "NetworkManagerUtils.h"
#include "nm-core-internal.h"
#include "gsystem-local-alloc.h"

#define SETTINGS_TIMESTAMPS_FILE  NMSTATEDIR "/timestamps"
#define SETTINGS_SEEN_BSSIDS_FILE NMSTATEDIR "/seen-bssids"


#define _LOG_DOMAIN LOGD_SETTINGS
#define _LOG_PREFIX_NAME "settings-connection"

#define _LOG(level, domain, self, ...) \
    G_STMT_START { \
        const NMLogLevel __level = (level); \
        const NMLogDomain __domain = (domain); \
        \
        if (nm_logging_enabled (__level, __domain)) { \
            char __prefix[128]; \
            const char *__p_prefix = _LOG_PREFIX_NAME; \
            const void *const __self = (self); \
            \
            if (__self) { \
                const char *__uuid = nm_connection_get_uuid ((NMConnection *) __self); \
                \
                g_snprintf (__prefix, sizeof (__prefix), "%s[%p%s%s]", _LOG_PREFIX_NAME, __self, __uuid ? "," : "", __uuid ? __uuid : ""); \
                __p_prefix = __prefix; \
            } \
            _nm_log (__level, __domain, 0, \
                     "%s: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
                     __p_prefix _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
        } \
    } G_STMT_END
#define _LOG_LEVEL_ENABLED(level, domain) \
    ( nm_logging_enabled ((level), (domain)) )

#ifdef NM_MORE_LOGGING
#define _LOGT_ENABLED()     _LOG_LEVEL_ENABLED (LOGL_TRACE, _LOG_DOMAIN)
#define _LOGT(...)          _LOG (LOGL_TRACE, _LOG_DOMAIN, self, __VA_ARGS__)
#else
#define _LOGT_ENABLED()     FALSE
#define _LOGT(...)          G_STMT_START { if (FALSE) { _LOG (LOGL_TRACE, _LOG_DOMAIN, self, __VA_ARGS__); } } G_STMT_END
#endif

#define _LOGD(...)      _LOG (LOGL_DEBUG, _LOG_DOMAIN, self, __VA_ARGS__)
#define _LOGI(...)      _LOG (LOGL_INFO , _LOG_DOMAIN, self, __VA_ARGS__)
#define _LOGW(...)      _LOG (LOGL_WARN , _LOG_DOMAIN, self, __VA_ARGS__)
#define _LOGE(...)      _LOG (LOGL_ERR  , _LOG_DOMAIN, self, __VA_ARGS__)


static void impl_settings_connection_get_settings (NMSettingsConnection *self,
                                                   DBusGMethodInvocation *context);

static void impl_settings_connection_update (NMSettingsConnection *self,
                                             GHashTable *new_settings,
                                             DBusGMethodInvocation *context);

static void impl_settings_connection_update_unsaved (NMSettingsConnection *self,
                                                     GHashTable *new_settings,
                                                     DBusGMethodInvocation *context);

static void impl_settings_connection_save (NMSettingsConnection *self,
                                           DBusGMethodInvocation *context);

static void impl_settings_connection_delete (NMSettingsConnection *self,
                                             DBusGMethodInvocation *context);

static void impl_settings_connection_get_secrets (NMSettingsConnection *self,
                                                  const gchar *setting_name,
                                                  DBusGMethodInvocation *context);

static void impl_settings_connection_clear_secrets (NMSettingsConnection *self,
                                                    DBusGMethodInvocation *context);

#include "nm-settings-connection-glue.h"

static void nm_settings_connection_connection_interface_init (NMConnectionInterface *iface);

G_DEFINE_TYPE_WITH_CODE (NMSettingsConnection, nm_settings_connection, NM_TYPE_EXPORTED_OBJECT,
                         G_IMPLEMENT_INTERFACE (NM_TYPE_CONNECTION, nm_settings_connection_connection_interface_init)
                         )

#define NM_SETTINGS_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                               NM_TYPE_SETTINGS_CONNECTION, \
                                               NMSettingsConnectionPrivate))

enum {
	PROP_0 = 0,
	PROP_VISIBLE,
	PROP_UNSAVED,
	PROP_READY,
	PROP_FLAGS,
	PROP_FILENAME,
};

enum {
	UPDATED,
	REMOVED,
	UPDATED_BY_USER,
	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	gboolean removed;

	NMAgentManager *agent_mgr;
	guint session_changed_id;

	NMSettingsConnectionFlags flags;
	gboolean ready;

	guint updated_idle_id;

	GSList *pending_auths; /* List of pending authentication requests */
	gboolean visible; /* Is this connection is visible by some session? */
	GSList *reqs;  /* in-progress secrets requests */

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
	gboolean timestamp_set;
	GHashTable *seen_bssids; /* Up-to-date BSSIDs that's been seen for the connection */

	int autoconnect_retries;
	gint32 autoconnect_retry_time;
	NMDeviceStateReason autoconnect_blocked_reason;

	char *filename;

} NMSettingsConnectionPrivate;

/**************************************************************/

/* Return TRUE to keep, FALSE to drop */
typedef gboolean (*ForEachSecretFunc) (NMSettingSecretFlags flags,
                                       gpointer user_data);

static void
for_each_secret (NMConnection *self,
                 GHashTable *secrets,
                 gboolean remove_non_secrets,
                 ForEachSecretFunc callback,
                 gpointer callback_data)
{
	GHashTableIter iter;
	const char *setting_name;
	GHashTable *setting_hash;

	/* This function, given a hash of hashes representing new secrets of
	 * an NMConnection, walks through each toplevel hash (which represents a
	 * NMSetting), and for each setting, walks through that setting hash's
	 * properties.  For each property that's a secret, it will check that
	 * secret's flags in the backing NMConnection object, and call a supplied
	 * callback.
	 *
	 * The one complexity is that the VPN setting's 'secrets' property is
	 * *also* a hash table (since the key/value pairs are arbitrary and known
	 * only to the VPN plugin itself).  That means we have three levels of
	 * GHashTables that we potentially have to traverse here.  When we hit the
	 * VPN setting's 'secrets' property, we special-case that and iterate over
	 * each item in that 'secrets' hash table, calling the supplied callback
	 * each time.
	 */

	g_return_if_fail (callback);

	/* Walk through the list of setting hashes */
	g_hash_table_iter_init (&iter, secrets);
	while (g_hash_table_iter_next (&iter, (gpointer) &setting_name, (gpointer) &setting_hash)) {
		NMSetting *setting;
		GHashTableIter secret_iter;
		const char *secret_name;
		GValue *val;

		if (g_hash_table_size (setting_hash) == 0)
			continue;

		/* Get the actual NMSetting from the connection so we can get secret flags
		 * from the connection data, since flags aren't secrets.  What we're
		 * iterating here is just the secrets, not a whole connection.
		 */
		setting = nm_connection_get_setting_by_name (self, setting_name);
		if (setting == NULL)
			continue;

		/* Walk through the list of keys in each setting hash */
		g_hash_table_iter_init (&secret_iter, setting_hash);
		while (g_hash_table_iter_next (&secret_iter, (gpointer) &secret_name, (gpointer) &val)) {
			NMSettingSecretFlags secret_flags = NM_SETTING_SECRET_FLAG_NONE;

			/* VPN secrets need slightly different treatment here since the
			 * "secrets" property is actually a hash table of secrets.
			 */
			if (NM_IS_SETTING_VPN (setting) && (g_strcmp0 (secret_name, NM_SETTING_VPN_SECRETS) == 0)) {
				GHashTableIter vpn_secrets_iter;

				/* Iterate through each secret from the VPN hash in the overall secrets hash */
				g_hash_table_iter_init (&vpn_secrets_iter, g_value_get_boxed (val));
				while (g_hash_table_iter_next (&vpn_secrets_iter, (gpointer) &secret_name, NULL)) {
					secret_flags = NM_SETTING_SECRET_FLAG_NONE;
					if (!nm_setting_get_secret_flags (setting, secret_name, &secret_flags, NULL)) {
						if (remove_non_secrets)
							g_hash_table_iter_remove (&vpn_secrets_iter);
						continue;
					}
					if (!callback (secret_flags, callback_data))
						g_hash_table_iter_remove (&vpn_secrets_iter);
				}
			} else {
				if (!nm_setting_get_secret_flags (setting, secret_name, &secret_flags, NULL)) {
					if (remove_non_secrets)
						g_hash_table_iter_remove (&secret_iter);
					continue;
				}
				if (!callback (secret_flags, callback_data))
					g_hash_table_iter_remove (&secret_iter);
			}
		}
	}
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
	return TRUE;
}

static gboolean
find_secret (NMConnection *self,
             GHashTable *secrets,
             FindSecretFunc callback,
             gpointer callback_data)
{
	FindSecretData data;

	data.find_func = callback;
	data.find_func_data = callback_data;
	data.found = FALSE;

	for_each_secret (self, secrets, FALSE, find_secret_for_each_func, &data);
	return data.found;
}

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
		if (!nm_session_monitor_session_exists (uid, FALSE))
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

/**************************************************************/

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

/**************************************************************/

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

static gboolean
emit_updated (NMSettingsConnection *self)
{
	NM_SETTINGS_CONNECTION_GET_PRIVATE (self)->updated_idle_id = 0;
	g_signal_emit (self, signals[UPDATED], 0);
	return FALSE;
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
			           NM_SETTINGS_CONNECTION_FLAGS_NM_GENERATED_ASSUMED);
		}
		nm_settings_connection_set_flags_all (self, flags);
	}
}

static void
changed_cb (NMSettingsConnection *self, gpointer user_data)
{
	gboolean update_unsaved = !!user_data;

	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);

	if (update_unsaved)
		set_unsaved (self, TRUE);
	if (priv->updated_idle_id == 0)
		priv->updated_idle_id = g_idle_add ((GSourceFunc) emit_updated, self);
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
	    && g_strcmp0 (nm_connection_get_uuid (NM_CONNECTION (self)), nm_connection_get_uuid (new_connection)) != 0) {
		/* Updating the UUID is not allowed once the path is exported. */
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "connection %s cannot change the UUID from %s to %s", nm_connection_get_id (NM_CONNECTION (self)),
		             nm_connection_get_uuid (NM_CONNECTION (self)), nm_connection_get_uuid (new_connection));
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
	g_signal_handlers_block_by_func (self, G_CALLBACK (changed_cb), GUINT_TO_POINTER (TRUE));

	if (log_diff_name)
		nm_utils_log_connection_diff (new_connection, NM_CONNECTION (self), LOGL_DEBUG, LOGD_CORE, log_diff_name, "++ ");

	nm_connection_replace_settings_from_connection (NM_CONNECTION (self), new_connection);

	_LOGD ("replace settings from connection %p (%s)", new_connection, nm_connection_get_id (NM_CONNECTION (self)));

	nm_settings_connection_set_flags (self,
	                                  NM_SETTINGS_CONNECTION_FLAGS_NM_GENERATED | NM_SETTINGS_CONNECTION_FLAGS_NM_GENERATED_ASSUMED,
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
	changed_cb (self, GUINT_TO_POINTER (update_unsaved));

	g_signal_emit (self, signals[UPDATED_BY_USER], 0);

	g_signal_handlers_unblock_by_func (self, G_CALLBACK (changed_cb), GUINT_TO_POINTER (TRUE));

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

		connection_uuid = nm_connection_get_uuid (NM_CONNECTION (self));

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
	nm_agent_manager_delete_secrets (priv->agent_mgr, for_agents);
	g_object_unref (for_agents);

	/* Remove timestamp from timestamps database file */
	remove_entry_from_db (self, "timestamps");

	/* Remove connection from seen-bssids database file */
	remove_entry_from_db (self, "seen-bssids");

	nm_settings_connection_signal_remove (self);

	callback (self, NULL, user_data);

	g_object_unref (self);
}

/**************************************************************/

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
	if (error) {
		_LOGW ("Error saving new secrets to backing storage: (%d) %s",
		       error->code, error->message ? error->message : "(unknown)");
	}
}

static void
agent_secrets_done_cb (NMAgentManager *manager,
                       guint32 call_id,
                       const char *agent_dbus_owner,
                       const char *agent_username,
                       gboolean agent_has_modify,
                       const char *setting_name,
                       NMSecretAgentGetSecretsFlags flags,
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
	GError *local = NULL;
	GVariant *dict;
	gboolean agent_had_system = FALSE;
	ForEachSecretFlags cmp_flags = { NM_SETTING_SECRET_FLAG_NONE, NM_SETTING_SECRET_FLAG_NONE };

	if (error) {
		_LOGD ("(%s:%u) secrets request error: (%d) %s",
		       setting_name,
		       call_id,
		       error->code,
		       error->message ? error->message : "(unknown)");

		callback (self, call_id, NULL, setting_name, error, callback_data);
		return;
	}

	if (!nm_connection_get_setting_by_name (NM_CONNECTION (self), setting_name)) {
		local = g_error_new (NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_SETTING_NOT_FOUND,
		                     "%s.%d - Connection didn't have requested setting '%s'.",
		                     __FILE__, __LINE__, setting_name);
		callback (self, call_id, NULL, setting_name, local, callback_data);
		g_clear_error (&local);
		return;
	}

	g_assert (secrets);
	if (agent_dbus_owner) {
		_LOGD ("(%s:%u) secrets returned from agent %s",
		       setting_name,
		       call_id,
		       agent_dbus_owner);

		/* If the agent returned any system-owned secrets (initial connect and no
		 * secrets given when the connection was created, or something like that)
		 * make sure the agent's UID has the 'modify' permission before we use or
		 * save those system-owned secrets.  If not, discard them and use the
		 * existing secrets, or fail the connection.
		 */
		agent_had_system = find_secret (NM_CONNECTION (self), secrets, secret_is_system_owned, NULL);
		if (agent_had_system) {
			if (flags == NM_SECRET_AGENT_GET_SECRETS_FLAG_NONE) {
				/* No user interaction was allowed when requesting secrets; the
				 * agent is being bad.  Remove system-owned secrets.
				 */
				_LOGD ("(%s:%u) interaction forbidden but agent %s returned system secrets",
				       setting_name,
				       call_id,
				       agent_dbus_owner);

				cmp_flags.required |= NM_SETTING_SECRET_FLAG_AGENT_OWNED;
			} else if (agent_has_modify == FALSE) {
				/* Agent didn't successfully authenticate; clear system-owned secrets
				 * from the secrets the agent returned.
				 */
				_LOGD ("(%s:%u) agent failed to authenticate but provided system secrets",
				       setting_name,
				       call_id);

				cmp_flags.required |= NM_SETTING_SECRET_FLAG_AGENT_OWNED;
			}
		}
	} else {
		_LOGD ("(%s:%u) existing secrets returned",
		       setting_name,
		       call_id);
	}

	_LOGD ("(%s:%u) secrets request completed",
	       setting_name,
	       call_id);

	/* If no user interaction was allowed, make sure that no "unsaved" secrets
	 * came back.  Unsaved secrets by definition require user interaction.
	 */
	if (flags == NM_SECRET_AGENT_GET_SECRETS_FLAG_NONE) {
		cmp_flags.forbidden |= (  NM_SETTING_SECRET_FLAG_NOT_SAVED
		                        | NM_SETTING_SECRET_FLAG_NOT_REQUIRED);
	}

	for_each_secret (NM_CONNECTION (self), secrets, TRUE, validate_secret_flags, &cmp_flags);

	/* Update the connection with our existing secrets from backing storage */
	nm_connection_clear_secrets (NM_CONNECTION (self));
	dict = nm_connection_to_dbus (priv->system_secrets, NM_CONNECTION_SERIALIZE_ONLY_SECRETS);
	if (!dict || nm_connection_update_secrets (NM_CONNECTION (self), setting_name, dict, &local)) {
		GVariant *secrets_dict;

		/* Update the connection with the agent's secrets; by this point if any
		 * system-owned secrets exist in 'secrets' the agent that provided them
		 * will have been authenticated, so those secrets can replace the existing
		 * system secrets.
		 */
		secrets_dict = nm_utils_connection_hash_to_dict (secrets);
		if (nm_connection_update_secrets (NM_CONNECTION (self), setting_name, secrets_dict, &local)) {
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
				_LOGD ("(%s:%u) saving new secrets to backing storage",
				       setting_name,
				       call_id);

				nm_settings_connection_commit_changes (self, NM_SETTINGS_CONNECTION_COMMIT_REASON_NONE, new_secrets_commit_cb, NULL);
			} else {
				_LOGD ("(%s:%u) new agent secrets processed",
				       setting_name,
				       call_id);
			}
		} else {
			_LOGD ("(%s:%u) failed to update with agent secrets: (%d) %s",
			       setting_name,
			       call_id,
			       local ? local->code : -1,
			       (local && local->message) ? local->message : "(unknown)");
		}
		g_variant_unref (secrets_dict);
	} else {
		_LOGD ("(%s:%u) failed to update with existing secrets: (%d) %s",
		       setting_name,
		       call_id,
		       local ? local->code : -1,
		       (local && local->message) ? local->message : "(unknown)");
	}

	callback (self, call_id, agent_username, setting_name, local, callback_data);
	g_clear_error (&local);
	if (dict)
		g_variant_unref (dict);
}

/**
 * nm_settings_connection_get_secrets:
 * @self: the #NMSettingsConnection
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
 * Returns: a call ID which may be used to cancel the ongoing secrets request
 **/
guint32 
nm_settings_connection_get_secrets (NMSettingsConnection *self,
                                    NMAuthSubject *subject,
                                    const char *setting_name,
                                    NMSecretAgentGetSecretsFlags flags,
                                    const char **hints,
                                    NMSettingsConnectionSecretsFunc callback,
                                    gpointer callback_data,
                                    GError **error)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);
	GVariant *existing_secrets;
	GHashTable *existing_secrets_hash;
	guint32 call_id = 0;
	gs_free char *joined_hints = NULL;

	/* Use priv->secrets to work around the fact that nm_connection_clear_secrets()
	 * will clear secrets on this object's settings.
	 */
	if (!priv->system_secrets) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "%s.%d - Internal error; secrets cache invalid.",
		             __FILE__, __LINE__);
		return 0;
	}

	/* Make sure the request actually requests something we can return */
	if (!nm_connection_get_setting_by_name (NM_CONNECTION (self), setting_name)) {
		g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_SETTING_NOT_FOUND,
		             "%s.%d - Connection didn't have requested setting '%s'.",
		             __FILE__, __LINE__, setting_name);
		return 0;
	}

	existing_secrets = nm_connection_to_dbus (priv->system_secrets, NM_CONNECTION_SERIALIZE_ONLY_SECRETS);
	existing_secrets_hash = nm_utils_connection_dict_to_hash (existing_secrets);
	call_id = nm_agent_manager_get_secrets (priv->agent_mgr,
	                                        NM_CONNECTION (self),
	                                        subject,
	                                        existing_secrets_hash,
	                                        setting_name,
	                                        flags,
	                                        hints,
	                                        agent_secrets_done_cb,
	                                        self,
	                                        callback,
	                                        callback_data);
	if (existing_secrets_hash)
		g_hash_table_unref (existing_secrets_hash);
	if (existing_secrets)
		g_variant_unref (existing_secrets);

	_LOGD ("(%s:%u) secrets requested flags 0x%X hints '%s'",
	       setting_name,
	       call_id,
	       flags,
	       (hints && hints[0]) ? (joined_hints = g_strjoinv (",", (char **) hints)) : "(none)");

	return call_id;
}

void
nm_settings_connection_cancel_secrets (NMSettingsConnection *self,
                                       guint32 call_id)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);

	_LOGD ("(%u) secrets canceled",
	       call_id);

	priv->reqs = g_slist_remove (priv->reqs, GUINT_TO_POINTER (call_id));
	nm_agent_manager_cancel_secrets (priv->agent_mgr, call_id);
}

/**** User authorization **************************************/

typedef void (*AuthCallback) (NMSettingsConnection *self,
                              DBusGMethodInvocation *context,
                              NMAuthSubject *subject,
                              GError *error,
                              gpointer data);

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
_new_auth_subject (DBusGMethodInvocation *context, GError **error)
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
            DBusGMethodInvocation *context,
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
                      DBusGMethodInvocation *context,
                      NMAuthSubject *subject,
                      GError *error,
                      gpointer data)
{
	if (error)
		dbus_g_method_return_error (context, error);
	else {
		GVariant *settings;
		GHashTable *settings_hash;
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
		settings_hash = nm_utils_connection_dict_to_hash (settings);
		dbus_g_method_return (context, settings_hash);
		g_hash_table_destroy (settings_hash);
		g_variant_unref (settings);
		g_object_unref (dupl_con);
	}
}

static void
impl_settings_connection_get_settings (NMSettingsConnection *self,
                                       DBusGMethodInvocation *context)
{
	NMAuthSubject *subject;
	GError *error = NULL;

	subject = _new_auth_subject (context, &error);
	if (subject) {
		auth_start (self, context, subject, NULL, get_settings_auth_cb, NULL);
		g_object_unref (subject);
	} else {
		dbus_g_method_return_error (context, error);
		g_error_free (error);
	}
}

typedef struct {
	DBusGMethodInvocation *context;
	NMAgentManager *agent_mgr;
	NMAuthSubject *subject;
	NMConnection *new_settings;
	gboolean save_to_disk;
} UpdateInfo;

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
		dbus_g_method_return_error (info->context, error);
	else
		dbus_g_method_return (info->context);

	g_clear_object (&info->subject);
	g_clear_object (&info->agent_mgr);
	g_clear_object (&info->new_settings);
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
		nm_agent_manager_save_secrets (info->agent_mgr, for_agent, info->subject);
		g_object_unref (for_agent);
	}

	update_complete (self, info, error);
}

static void
update_auth_cb (NMSettingsConnection *self,
                DBusGMethodInvocation *context,
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
impl_settings_connection_update_helper (NMSettingsConnection *self,
                                        GHashTable *new_settings,
                                        DBusGMethodInvocation *context,
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
		GVariant *new_settings_dict = nm_utils_connection_hash_to_dict (new_settings);

		tmp = nm_simple_connection_new_from_dbus (new_settings_dict, &error);
		g_variant_unref (new_settings_dict);
		if (!tmp) {
			g_assert (error);
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
	g_clear_object (&tmp);
	g_clear_object (&subject);

	dbus_g_method_return_error (context, error);
	g_clear_error (&error);
}

static void
impl_settings_connection_update (NMSettingsConnection *self,
                                 GHashTable *new_settings,
                                 DBusGMethodInvocation *context)
{
	g_assert (new_settings);
	impl_settings_connection_update_helper (self, new_settings, context, TRUE);
}

static void
impl_settings_connection_update_unsaved (NMSettingsConnection *self,
                                         GHashTable *new_settings,
                                         DBusGMethodInvocation *context)
{
	g_assert (new_settings);
	impl_settings_connection_update_helper (self, new_settings, context, FALSE);
}

static void
impl_settings_connection_save (NMSettingsConnection *self,
                               DBusGMethodInvocation *context)
{
	/* Do nothing if the connection is already synced with disk */
	if (nm_settings_connection_get_unsaved (self))
		impl_settings_connection_update_helper (self, NULL, context, TRUE);
	else
		dbus_g_method_return (context);
}

static void
con_delete_cb (NMSettingsConnection *self,
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
                NMAuthSubject *subject,
                GError *error,
                gpointer data)
{
	if (error) {
		dbus_g_method_return_error (context, error);
		return;
	}

	nm_settings_connection_delete (self, con_delete_cb, context);
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
                                 DBusGMethodInvocation *context)
{
	NMAuthSubject *subject;
	GError *error = NULL;
	
	if (!check_writable (NM_CONNECTION (self), &error)) {
		dbus_g_method_return_error (context, error);
		g_error_free (error);
		return;
	}

	subject = _new_auth_subject (context, &error);
	if (subject) {
		auth_start (self, context, subject, get_modify_permission_basic (self), delete_auth_cb, NULL);
		g_object_unref (subject);
	} else {
		dbus_g_method_return_error (context, error);
		g_error_free (error);
	}
}

/**************************************************************/

static void
dbus_get_agent_secrets_cb (NMSettingsConnection *self,
                           guint32 call_id,
                           const char *agent_username,
                           const char *setting_name,
                           GError *error,
                           gpointer user_data)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);
	DBusGMethodInvocation *context = user_data;
	GVariant *dict;
	GHashTable *hash;

	priv->reqs = g_slist_remove (priv->reqs, GUINT_TO_POINTER (call_id));

	if (error)
		dbus_g_method_return_error (context, error);
	else {
		/* Return secrets from agent and backing storage to the D-Bus caller;
		 * nm_settings_connection_get_secrets() will have updated itself with
		 * secrets from backing storage and those returned from the agent
		 * by the time we get here.
		 */
		dict = nm_connection_to_dbus (NM_CONNECTION (self), NM_CONNECTION_SERIALIZE_ONLY_SECRETS);
		if (dict)
			hash = nm_utils_connection_dict_to_hash (dict);
		else
			hash = g_hash_table_new (NULL, NULL);
		dbus_g_method_return (context, hash);
		g_hash_table_destroy (hash);
		if (dict)
			g_variant_unref (dict);
	}
}

static void
dbus_get_secrets_auth_cb (NMSettingsConnection *self, 
                          DBusGMethodInvocation *context,
                          NMAuthSubject *subject,
                          GError *error,
                          gpointer user_data)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);
	char *setting_name = user_data;
	guint32 call_id = 0;
	GError *local = NULL;

	if (!error) {
		call_id = nm_settings_connection_get_secrets (self,
			                                          subject,
			                                          setting_name,
			                                            NM_SECRET_AGENT_GET_SECRETS_FLAG_USER_REQUESTED
			                                          | NM_SECRET_AGENT_GET_SECRETS_FLAG_NO_ERRORS,
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
	} else {
		dbus_g_method_return_error (context, error);
		g_error_free (error);
	}
}

static void
clear_secrets_cb (NMSettingsConnection *self,
                  GError *error,
                  gpointer user_data)
{
	DBusGMethodInvocation *context = (DBusGMethodInvocation *) user_data;

	if (error)
		dbus_g_method_return_error (context, error);
	else
		dbus_g_method_return (context);
}

static void
dbus_clear_secrets_auth_cb (NMSettingsConnection *self,
                            DBusGMethodInvocation *context,
                            NMAuthSubject *subject,
                            GError *error,
                            gpointer user_data)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);

	if (error)
		dbus_g_method_return_error (context, error);
	else {
		/* Clear secrets in connection and caches */
		nm_connection_clear_secrets (NM_CONNECTION (self));
		if (priv->system_secrets)
			nm_connection_clear_secrets (priv->system_secrets);
		if (priv->agent_secrets)
			nm_connection_clear_secrets (priv->agent_secrets);

		/* Tell agents to remove secrets for this connection */
		nm_agent_manager_delete_secrets (priv->agent_mgr, NM_CONNECTION (self));

		nm_settings_connection_commit_changes (self, NM_SETTINGS_CONNECTION_COMMIT_REASON_NONE, clear_secrets_cb, context);
	}
}

static void
impl_settings_connection_clear_secrets (NMSettingsConnection *self,
                                        DBusGMethodInvocation *context)
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
		dbus_g_method_return_error (context, error);
		g_error_free (error);
	}
}

/**************************************************************/

void
nm_settings_connection_signal_remove (NMSettingsConnection *self)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);

	if (priv->removed)
		g_return_if_reached ();
	priv->removed = TRUE;

	/* Emit removed first */
	g_signal_emit_by_name (self, NM_SETTINGS_CONNECTION_REMOVED);

	/* And unregister last to ensure the removed signal goes out before
	 * we take the connection off the bus.
	 */
	nm_exported_object_unexport (NM_EXPORTED_OBJECT (self));
}

gboolean
nm_settings_connection_get_unsaved (NMSettingsConnection *self)
{
	return NM_FLAGS_HAS (nm_settings_connection_get_flags (self), NM_SETTINGS_CONNECTION_FLAGS_UNSAVED);
}

/**************************************************************/

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
		priv->flags = flags;
		g_object_notify (G_OBJECT (self), NM_SETTINGS_CONNECTION_FLAGS);
		if (NM_FLAGS_HAS (old_flags, NM_SETTINGS_CONNECTION_FLAGS_UNSAVED) != NM_FLAGS_HAS (flags, NM_SETTINGS_CONNECTION_FLAGS_UNSAVED))
			g_object_notify (G_OBJECT (self), NM_SETTINGS_CONNECTION_UNSAVED);
	}
	return old_flags;
}

/*************************************************************/

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
		if (!(error->domain == G_FILE_ERROR && error->code == G_FILE_ERROR_NOENT))
			_LOGW ("error parsing timestamps file '%s': %s", SETTINGS_TIMESTAMPS_FILE, error->message);
		g_clear_error (&error);
	}

	connection_uuid = nm_connection_get_uuid (NM_CONNECTION (self));
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
	const char *connection_uuid;
	guint64 timestamp = 0;
	GKeyFile *timestamps_file;
	GError *err = NULL;
	char *tmp_str;

	g_return_if_fail (NM_IS_SETTINGS_CONNECTION (self));

	/* Get timestamp from database file */
	timestamps_file = g_key_file_new ();
	g_key_file_load_from_file (timestamps_file, SETTINGS_TIMESTAMPS_FILE, G_KEY_FILE_KEEP_COMMENTS, NULL);
	connection_uuid = nm_connection_get_uuid (NM_CONNECTION (self));
	tmp_str = g_key_file_get_value (timestamps_file, "timestamps", connection_uuid, &err);
	if (tmp_str) {
		timestamp = g_ascii_strtoull (tmp_str, NULL, 10);
		g_free (tmp_str);
	}

	/* Update connection's timestamp */
	if (!err) {
		priv->timestamp = timestamp;
		priv->timestamp_set = TRUE;
	} else {
		_LOGD ("failed to read connection timestamp: (%d) %s",
		       err->code, err->message);
		g_clear_error (&err);
	}
	g_key_file_free (timestamps_file);
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

	connection_uuid = nm_connection_get_uuid (NM_CONNECTION (self));
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
		connection_uuid = nm_connection_get_uuid (NM_CONNECTION (self));
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

#define AUTOCONNECT_RETRIES_DEFAULT 4
#define AUTOCONNECT_RESET_RETRIES_TIMER 300

int
nm_settings_connection_get_autoconnect_retries (NMSettingsConnection *self)
{
	return NM_SETTINGS_CONNECTION_GET_PRIVATE (self)->autoconnect_retries;
}

void
nm_settings_connection_set_autoconnect_retries (NMSettingsConnection *self,
                                                int retries)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);

	priv->autoconnect_retries = retries;
	if (retries)
		priv->autoconnect_retry_time = 0;
	else
		priv->autoconnect_retry_time = nm_utils_get_monotonic_timestamp_s () + AUTOCONNECT_RESET_RETRIES_TIMER;
}

void
nm_settings_connection_reset_autoconnect_retries (NMSettingsConnection *self)
{
	nm_settings_connection_set_autoconnect_retries (self, AUTOCONNECT_RETRIES_DEFAULT);
}

gint32
nm_settings_connection_get_autoconnect_retry_time (NMSettingsConnection *self)
{
	return NM_SETTINGS_CONNECTION_GET_PRIVATE (self)->autoconnect_retry_time;
}

NMDeviceStateReason
nm_settings_connection_get_autoconnect_blocked_reason (NMSettingsConnection *self)
{
	return NM_SETTINGS_CONNECTION_GET_PRIVATE (self)->autoconnect_blocked_reason;
}

void
nm_settings_connection_set_autoconnect_blocked_reason (NMSettingsConnection *self,
                                                       NMDeviceStateReason reason)
{
	NM_SETTINGS_CONNECTION_GET_PRIVATE (self)->autoconnect_blocked_reason = reason;
}

gboolean
nm_settings_connection_can_autoconnect (NMSettingsConnection *self)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);
	NMSettingConnection *s_con;
	const char *permission;

	if (   !priv->visible
	    || priv->autoconnect_retries == 0
	    || priv->autoconnect_blocked_reason != NM_DEVICE_STATE_REASON_NONE)
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
 * nm_settings_connection_get_nm_generated_assumed:
 * @self: an #NMSettingsConnection
 *
 * Gets the "nm-generated-assumed" flag on @self.
 *
 * The connection is a generated connection especially
 * generated for connection assumption.
 */
gboolean
nm_settings_connection_get_nm_generated_assumed (NMSettingsConnection *self)
{
	return NM_FLAGS_HAS (nm_settings_connection_get_flags (self), NM_SETTINGS_CONNECTION_FLAGS_NM_GENERATED_ASSUMED);
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
		g_object_notify (G_OBJECT (self), NM_SETTINGS_CONNECTION_READY);
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
		g_object_notify (G_OBJECT (self), NM_SETTINGS_CONNECTION_FILENAME);
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

/**************************************************************/

static void
nm_settings_connection_init (NMSettingsConnection *self)
{
	NMSettingsConnectionPrivate *priv = NM_SETTINGS_CONNECTION_GET_PRIVATE (self);

	priv->visible = FALSE;
	priv->ready = TRUE;

	priv->session_changed_id = nm_session_monitor_connect (session_changed_cb, self);

	priv->agent_mgr = g_object_ref (nm_agent_manager_get ());

	priv->seen_bssids = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

	priv->autoconnect_retries = AUTOCONNECT_RETRIES_DEFAULT;
	priv->autoconnect_blocked_reason = NM_DEVICE_STATE_REASON_NONE;

	g_signal_connect (self, NM_CONNECTION_SECRETS_CLEARED, G_CALLBACK (secrets_cleared_cb), NULL);
	g_signal_connect (self, NM_CONNECTION_CHANGED, G_CALLBACK (changed_cb), GUINT_TO_POINTER (TRUE));
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
	GSList *iter;

	_LOGD ("disposing");

	if (priv->updated_idle_id) {
		g_source_remove (priv->updated_idle_id);
		priv->updated_idle_id = 0;
	}

	/* Disconnect handlers.
	 * changed_cb() has to be disconnected *before* nm_connection_clear_secrets(),
	 * because nm_connection_clear_secrets() emits NM_CONNECTION_CHANGED signal.
	 */
	g_signal_handlers_disconnect_by_func (self, G_CALLBACK (secrets_cleared_cb), NULL);
	g_signal_handlers_disconnect_by_func (self, G_CALLBACK (changed_cb), GUINT_TO_POINTER (TRUE));

	nm_connection_clear_secrets (NM_CONNECTION (self));
	g_clear_object (&priv->system_secrets);
	g_clear_object (&priv->agent_secrets);

	/* Cancel PolicyKit requests */
	g_slist_free_full (priv->pending_auths, (GDestroyNotify) nm_auth_chain_unref);
	priv->pending_auths = NULL;

	/* Cancel in-progress secrets requests */
	for (iter = priv->reqs; iter; iter = g_slist_next (iter))
		nm_agent_manager_cancel_secrets (priv->agent_mgr, GPOINTER_TO_UINT (iter->data));
	g_slist_free (priv->reqs);
	priv->reqs = NULL;

	g_clear_pointer (&priv->seen_bssids, (GDestroyNotify) g_hash_table_destroy);

	set_visible (self, FALSE);

	if (priv->session_changed_id) {
		nm_session_monitor_disconnect (priv->session_changed_id);
		priv->session_changed_id = 0;
	}
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
	case PROP_READY:
		nm_settings_connection_set_ready (self, g_value_get_boolean (value));
		break;
	case PROP_FLAGS:
		nm_settings_connection_set_flags_all (self, g_value_get_uint (value));
		break;
	case PROP_FILENAME:
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

	exported_object_class->export_path = NM_DBUS_PATH_SETTINGS "/%u";

	/* Virtual methods */
	object_class->constructed = constructed;
	object_class->dispose = dispose;
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	class->replace_and_commit = replace_and_commit;
	class->commit_changes = commit_changes;
	class->delete = do_delete;
	class->supports_secrets = supports_secrets;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_VISIBLE,
		 g_param_spec_boolean (NM_SETTINGS_CONNECTION_VISIBLE, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_UNSAVED,
		 g_param_spec_boolean (NM_SETTINGS_CONNECTION_UNSAVED, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_READY,
		 g_param_spec_boolean (NM_SETTINGS_CONNECTION_READY, "", "",
		                       TRUE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
	    (object_class, PROP_FLAGS,
	     g_param_spec_uint (NM_SETTINGS_CONNECTION_FLAGS, "", "",
	                        NM_SETTINGS_CONNECTION_FLAGS_NONE,
	                        NM_SETTINGS_CONNECTION_FLAGS_ALL,
	                        NM_SETTINGS_CONNECTION_FLAGS_NONE,
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_FILENAME,
		 g_param_spec_string (NM_SETTINGS_CONNECTION_FILENAME, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

	/* Signals */

	/* Emitted when the connection is changed for any reason */
	signals[UPDATED] =
		g_signal_new (NM_SETTINGS_CONNECTION_UPDATED,
		              G_TYPE_FROM_CLASS (class),
		              G_SIGNAL_RUN_FIRST,
		              0,
		              NULL, NULL,
		              g_cclosure_marshal_VOID__VOID,
		              G_TYPE_NONE, 0);

	/* Emitted when connection is changed from D-Bus */
	signals[UPDATED_BY_USER] =
		g_signal_new (NM_SETTINGS_CONNECTION_UPDATED_BY_USER,
		              G_TYPE_FROM_CLASS (class),
		              G_SIGNAL_RUN_FIRST,
		              0, NULL, NULL,
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

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (class),
	                                        &dbus_glib_nm_settings_connection_object_info);
}

static void
nm_settings_connection_connection_interface_init (NMConnectionInterface *iface)
{
}

