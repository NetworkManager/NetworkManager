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
 * (C) Copyright 2008 - 2009 Red Hat, Inc.
 */

#include <NetworkManager.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <nm-setting-connection.h>
#include <nm-utils.h>

#include "nm-sysconfig-connection.h"
#include "nm-session-manager.h"
#include "nm-dbus-manager.h"
#include "nm-system-config-error.h"
#include "nm-dbus-glib-types.h"
#include "nm-polkit-helpers.h"
#include "nm-logging.h"

static void impl_sysconfig_connection_get_settings (NMSysconfigConnection *connection,
                                                    DBusGMethodInvocation *context);

static void impl_sysconfig_connection_update (NMSysconfigConnection *connection,
                                              GHashTable *new_settings,
                                              DBusGMethodInvocation *context);

static void impl_sysconfig_connection_delete (NMSysconfigConnection *connection,
                                              DBusGMethodInvocation *context);

static void impl_sysconfig_connection_get_secrets (NMSysconfigConnection *connection,
                                                   const gchar *setting_name,
                                                   const gchar **hints,
                                                   gboolean request_new,
                                                   DBusGMethodInvocation *context);

#include "nm-sysconfig-connection-glue.h"

G_DEFINE_TYPE (NMSysconfigConnection, nm_sysconfig_connection, NM_TYPE_CONNECTION)

#define NM_SYSCONFIG_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                                NM_TYPE_SYSCONFIG_CONNECTION, \
                                                NMSysconfigConnectionPrivate))

enum {
	UPDATED,
	CHECK_PERMISSIONS,
	REMOVED,
	PURGED,
	UNHIDDEN,

	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	PolkitAuthority *authority;
	GSList *pending_auths; /* List of PendingAuth structs*/
	NMConnection *secrets;
	gboolean visible; /* Is this connection is visible by some session? */
	GHashTable *access_list; /* Sessions that may access this connection. */
} NMSysconfigConnectionPrivate;

/**************************************************************/

/* Returns true iff the given session should be permitted to access this
 * connection. Used to update the access list */
static gboolean
session_allowed (NMSysconfigConnection *connection,
                 NMSessionInfo *session)
{
	NMSettingConnection *setting_connection = (NMSettingConnection *) nm_connection_get_setting (NM_CONNECTION (connection), NM_TYPE_SETTING_CONNECTION);
	GSList *permissions_entries;
	char *session_user;
	GSList *session_groups;
	GSList *p_iter;
	gboolean allowed = FALSE;

	g_object_get (setting_connection, NM_SETTING_CONNECTION_PERMISSIONS, &permissions_entries, NULL);

	/* If permissions list is empty, the connection is world-accessible. */
	if (permissions_entries == NULL) {
		allowed = TRUE;
		goto out;
	}

	/* The "default session" can only access world-accessible connections. */
	if (nm_session_info_is_default_session (session)) {
		allowed = FALSE;
		goto out;
	}

	session_user = nm_session_info_get_unix_user (session);
	session_groups = nm_session_info_get_unix_groups (session);

	for (p_iter = permissions_entries; p_iter != NULL; p_iter = p_iter->next) {
		char **p_comps = g_strsplit ((char *)p_iter->data, ":", 3);
		char *type = p_comps[0];
		char *name = p_comps[1];

		if (g_str_equal (type, "user")) {
			if (g_str_equal (session_user, name)) {
				allowed = TRUE;
				goto out;
			}
		} 
		else if (g_str_equal (type, "group")) {
			GSList *g_iter;

			for (g_iter = session_groups; g_iter != NULL; g_iter = g_iter->next ) {
				char *group_name = (char *) g_iter->data;
				if (g_str_equal (group_name, name)) {
					allowed = TRUE;
					goto out;
				}
			}
		} 
		else {
			nm_log_err (LOGD_SYS_SET, 
					    "connection %s: failed to parse permissions entry '%s'",
			            nm_setting_connection_get_id (setting_connection),
			            (char *) p_iter->data);
		}
	}

out:
	nm_utils_slist_free (permissions_entries, g_free);
	return allowed;
}

static void
set_visibility (NMSysconfigConnection *self, gboolean new_visibility)
{
	NMSysconfigConnectionPrivate *priv = NM_SYSCONFIG_CONNECTION_GET_PRIVATE (self);
	DBusGConnection *connection = nm_dbus_manager_get_connection (nm_dbus_manager_get());
	const char *dbus_path = nm_connection_get_path (NM_CONNECTION (self));

	if (new_visibility && !priv->visible) {
		priv->visible = TRUE;

		dbus_g_connection_register_g_object (connection, dbus_path, G_OBJECT (self));
		g_signal_emit (self, signals[UNHIDDEN], 0);
	}
	else
	if (!new_visibility && priv->visible) {
		priv->visible = FALSE;

		g_signal_emit (self, signals[REMOVED], 0);
		dbus_g_connection_unregister_g_object (connection, G_OBJECT (self));
	}
}

/* One of the sessions on our access list has been removed. */
static void
session_removed_cb (NMSessionInfo *removed_session,
                    gpointer user_data)
{
	NMSysconfigConnection *connection = NM_SYSCONFIG_CONNECTION (user_data);
	NMSysconfigConnectionPrivate *priv = NM_SYSCONFIG_CONNECTION_GET_PRIVATE (connection);
	char *removed_session_id = nm_session_info_get_id (removed_session);

	g_hash_table_remove (priv->access_list, removed_session_id);

	if (g_hash_table_size (priv->access_list) == 0) {
		set_visibility (connection, FALSE);
	} else {
		g_signal_emit (connection, signals[CHECK_PERMISSIONS], 0);
	}
}

/* The session manager reports that a new session has been added. */
static void
session_added_cb (NMSessionManager *mananager, 
                  NMSessionInfo *session,
                  gpointer user_data)
{
	NMSysconfigConnection *connection = NM_SYSCONFIG_CONNECTION (user_data);
	NMSysconfigConnectionPrivate *priv = NM_SYSCONFIG_CONNECTION_GET_PRIVATE (connection);

	if (session_allowed (connection, session)) {
		g_object_ref (session);
		g_signal_connect (session, NM_SESSION_INFO_REMOVED,
		                  G_CALLBACK(session_removed_cb), connection);
		g_hash_table_insert (priv->access_list, nm_session_info_get_id (session), session);
		g_signal_emit (connection, signals[CHECK_PERMISSIONS], 0);
		set_visibility (connection, TRUE);
	}
}

/* Our permissions property may have been changed. Update the access list. */
static void
update_access_list (NMSysconfigConnection *connection)
{
	NMSysconfigConnectionPrivate *priv = NM_SYSCONFIG_CONNECTION_GET_PRIVATE (connection);
	NMSessionManager *session_manager = nm_session_manager_get();
	GSList *sessions = nm_session_manager_get_sessions (session_manager);
	GSList *iter;

	if (!priv->access_list)
		return;

	g_hash_table_remove_all (priv->access_list);
	for (iter = sessions; iter != NULL; iter = iter->next) {
		NMSessionInfo *session = (NMSessionInfo *) iter->data;
		if (session_allowed (connection, iter->data)) {
			g_object_ref (session);
			g_signal_connect (session, NM_SESSION_INFO_REMOVED,
		                  	  G_CALLBACK(session_removed_cb), connection);
			g_hash_table_insert (priv->access_list, nm_session_info_get_id (session), session);
		}
	}

	if (g_hash_table_size (priv->access_list) == 0) {
		set_visibility (connection, FALSE);
	} else {
		g_signal_emit (connection, signals[CHECK_PERMISSIONS], 0);
	}
}

gboolean
nm_sysconfig_connection_is_visible (NMSysconfigConnection *connection)
{
	g_return_val_if_fail (NM_SYSCONFIG_CONNECTION (connection), FALSE);

	return NM_SYSCONFIG_CONNECTION_GET_PRIVATE (connection)->visible;
}

static void
prepend_slist (gpointer key, gpointer value, gpointer user_data)
{
	GSList **sessions = (GSList **) user_data;

	*sessions = g_slist_prepend (*sessions, value);
}

GSList *
nm_sysconfig_connection_get_session_access_list (NMSysconfigConnection *connection)
{
	NMSysconfigConnectionPrivate *priv = NM_SYSCONFIG_CONNECTION_GET_PRIVATE (connection);
	GSList *sessions = NULL;

	if (priv->access_list)
		g_hash_table_foreach (priv->access_list, prepend_slist, &sessions);

	return sessions;
}

gboolean
nm_sysconfig_connection_is_accessible_by_session (NMSysconfigConnection *connection,
                                                  NMSessionInfo *session)
{
	NMSysconfigConnectionPrivate *priv = NM_SYSCONFIG_CONNECTION_GET_PRIVATE (connection);
	NMSessionInfo *stored_session = NULL;

	g_return_val_if_fail (NM_IS_SYSCONFIG_CONNECTION (connection), FALSE);
	g_return_val_if_fail (NM_IS_SESSION_INFO (session), FALSE);

	if (!priv->access_list)
		return FALSE;

	stored_session = g_hash_table_lookup (priv->access_list,
	                                      nm_session_info_get_id (session));

	if (stored_session == session)
		return TRUE;

	return FALSE;
}

/**************************************************************/

/* Update the settings of this connection to match that of 'new', taking care to
 * make a private copy of secrets. */
gboolean
nm_sysconfig_connection_replace_settings (NMSysconfigConnection *self,
                                          NMConnection *new,
                                          GError **error)
{
	NMSysconfigConnectionPrivate *priv;
	GHashTable *new_settings;
	gboolean success = FALSE;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (NM_IS_SYSCONFIG_CONNECTION (self), FALSE);
	g_return_val_if_fail (new != NULL, FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (new), FALSE);

	priv = NM_SYSCONFIG_CONNECTION_GET_PRIVATE (self);

	new_settings = nm_connection_to_hash (new);
	g_assert (new_settings);
	if (nm_connection_replace_settings (NM_CONNECTION (self), new_settings, error)) {
		/* Copy the connection to keep its secrets around even if NM
		 * calls nm_connection_clear_secrets().
		 */
		if (priv->secrets)
			g_object_unref (priv->secrets);
		priv->secrets = nm_connection_duplicate (NM_CONNECTION (self));

		update_access_list (self);

		success = TRUE;
	}
	g_hash_table_destroy (new_settings);
	return success;
}

static void
ignore_cb (NMSysconfigConnection *connection,
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
nm_sysconfig_connection_replace_and_commit (NMSysconfigConnection *self,
                                            NMConnection *new,
                                            NMSysconfigConnectionCommitFunc callback,
                                            gpointer user_data)
{
	GError *error = NULL;

	g_return_if_fail (self != NULL);
	g_return_if_fail (NM_IS_SYSCONFIG_CONNECTION (self));
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

	if (nm_sysconfig_connection_replace_settings (self, new, &error)) {
		nm_sysconfig_connection_commit_changes (self, callback, user_data);
	} else {
		callback (self, error, user_data);
		g_clear_error (&error);
	}
}

void
nm_sysconfig_connection_commit_changes (NMSysconfigConnection *connection,
                                        NMSysconfigConnectionCommitFunc callback,
                                        gpointer user_data)
{
	g_return_if_fail (connection != NULL);
	g_return_if_fail (NM_IS_SYSCONFIG_CONNECTION (connection));
	g_return_if_fail (callback != NULL);

	if (NM_SYSCONFIG_CONNECTION_GET_CLASS (connection)->commit_changes) {
		NM_SYSCONFIG_CONNECTION_GET_CLASS (connection)->commit_changes (connection,
		                                                                callback,
		                                                                user_data);
	} else {
		GError *error = g_error_new (NM_SYSCONFIG_SETTINGS_ERROR,
		                             NM_SYSCONFIG_SETTINGS_ERROR_INTERNAL_ERROR,
		                             "%s: %s:%d commit_changes() unimplemented", __func__, __FILE__, __LINE__);
		callback (connection, error, user_data);
		g_error_free (error);
	}
}

void
nm_sysconfig_connection_delete (NMSysconfigConnection *connection,
                                NMSysconfigConnectionDeleteFunc callback,
                                gpointer user_data)
{
	g_return_if_fail (connection != NULL);
	g_return_if_fail (NM_IS_SYSCONFIG_CONNECTION (connection));
	g_return_if_fail (callback != NULL);

	if (NM_SYSCONFIG_CONNECTION_GET_CLASS (connection)->delete) {
		NM_SYSCONFIG_CONNECTION_GET_CLASS (connection)->delete (connection,
		                                                        callback,
		                                                        user_data);
	} else {
		GError *error = g_error_new (NM_SYSCONFIG_SETTINGS_ERROR,
		                             NM_SYSCONFIG_SETTINGS_ERROR_INTERNAL_ERROR,
		                             "%s: %s:%d delete() unimplemented", __func__, __FILE__, __LINE__);
		callback (connection, error, user_data);
		g_error_free (error);
	}
}

void
nm_sysconfig_connection_get_secrets (NMSysconfigConnection *connection,
                                     const char *setting_name,
                                     const char **hints,
                                     gboolean request_new,
                                     NMSysconfigConnectionGetSecretsFunc callback,
                                     gpointer user_data)
{
	g_return_if_fail (connection != NULL);
	g_return_if_fail (NM_IS_SYSCONFIG_CONNECTION (connection));
	g_return_if_fail (callback != NULL);

	if (NM_SYSCONFIG_CONNECTION_GET_CLASS (connection)->get_secrets) {
		NM_SYSCONFIG_CONNECTION_GET_CLASS (connection)->get_secrets (connection,
		                                                             setting_name,
		                                                             hints,
		                                                             request_new,
		                                                             callback,
		                                                             user_data);
	} else {
		GError *error = g_error_new (NM_SYSCONFIG_SETTINGS_ERROR,
		                             NM_SYSCONFIG_SETTINGS_ERROR_INTERNAL_ERROR,
		                             "%s: %s:%d get_secrets() unimplemented", __func__, __FILE__, __LINE__);
		callback (connection, NULL, error, user_data);
		g_error_free (error);
	}
}

/**************************************************************/

static void
emit_updated (NMSysconfigConnection *connection)
{
	NMConnection *tmp;
	GHashTable *settings;

	tmp = nm_connection_duplicate (NM_CONNECTION (connection));
	nm_connection_clear_secrets (tmp);
	settings = nm_connection_to_hash (tmp);
	g_object_unref (tmp);

	g_signal_emit (connection, signals[UPDATED], 0, settings);
	g_hash_table_destroy (settings);
}

static void
commit_changes (NMSysconfigConnection *connection,
                NMSysconfigConnectionCommitFunc callback,
                gpointer user_data)
{
	g_object_ref (connection);
	emit_updated (connection);
	callback (connection, NULL, user_data);
	g_object_unref (connection);
}

static void
do_delete (NMSysconfigConnection *connection,
	       NMSysconfigConnectionDeleteFunc callback,
	       gpointer user_data)
{
	g_object_ref (connection);
	set_visibility (connection, FALSE);
	g_signal_emit (connection, signals[PURGED], 0);
	callback (connection, NULL, user_data);
	g_object_unref (connection);
}

static GValue *
string_to_gvalue (const char *str)
{
	GValue *val = g_slice_new0 (GValue);

	g_value_init (val, G_TYPE_STRING);
	g_value_set_string (val, str);
	return val;
}

static GValue *
byte_array_to_gvalue (const GByteArray *array)
{
	GValue *val;

	val = g_slice_new0 (GValue);
	g_value_init (val, DBUS_TYPE_G_UCHAR_ARRAY);
	g_value_set_boxed (val, array);

	return val;
}

static void
copy_one_secret (gpointer key, gpointer value, gpointer user_data)
{
	const char *value_str = (const char *) value;

	if (value_str) {
		g_hash_table_insert ((GHashTable *) user_data,
		                     g_strdup ((char *) key),
		                     string_to_gvalue (value_str));
	}
}

static void
add_secrets (NMSetting *setting,
             const char *key,
             const GValue *value,
             GParamFlags flags,
             gpointer user_data)
{
	GHashTable *secrets = user_data;

	if (!(flags & NM_SETTING_PARAM_SECRET))
		return;

	/* Copy secrets into the returned hash table */
	if (G_VALUE_HOLDS_STRING (value)) {
		const char *tmp;

		tmp = g_value_get_string (value);
		if (tmp)
			g_hash_table_insert (secrets, g_strdup (key), string_to_gvalue (tmp));
	} else if (G_VALUE_HOLDS (value, DBUS_TYPE_G_MAP_OF_STRING)) {
		/* Flatten the string hash by pulling its keys/values out */
		g_hash_table_foreach (g_value_get_boxed (value), copy_one_secret, secrets);
	} else if (G_VALUE_TYPE (value) == DBUS_TYPE_G_UCHAR_ARRAY) {
		GByteArray *array;

		array = g_value_get_boxed (value);
		if (array)
			g_hash_table_insert (secrets, g_strdup (key), byte_array_to_gvalue (array));
	}
}

static void
destroy_gvalue (gpointer data)
{
	GValue *value = (GValue *) data;

	g_value_unset (value);
	g_slice_free (GValue, value);
}

static void
get_secrets (NMSysconfigConnection *connection,
	         const char *setting_name,
             const char **hints,
             gboolean request_new,
             NMSysconfigConnectionGetSecretsFunc callback,
             gpointer user_data)
{
	NMSysconfigConnectionPrivate *priv = NM_SYSCONFIG_CONNECTION_GET_PRIVATE (connection);
	GHashTable *settings = NULL;
	GHashTable *secrets = NULL;
	NMSetting *setting;
	GError *error = NULL;

	/* Use priv->secrets to work around the fact that nm_connection_clear_secrets()
	 * will clear secrets on this object's settings.  priv->secrets should be
	 * a complete copy of this object and kept in sync by
	 * nm_sysconfig_connection_replace_settings().
	 */
	if (!priv->secrets) {
		error = g_error_new (NM_SYSCONFIG_SETTINGS_ERROR,
		                     NM_SYSCONFIG_SETTINGS_ERROR_INVALID_CONNECTION,
		                     "%s.%d - Internal error; secrets cache invalid.",
		                     __FILE__, __LINE__);
		(*callback) (connection, NULL, error, user_data);
		g_error_free (error);
		return;
	}

	setting = nm_connection_get_setting_by_name (priv->secrets, setting_name);
	if (!setting) {
		error = g_error_new (NM_SYSCONFIG_SETTINGS_ERROR,
		                     NM_SYSCONFIG_SETTINGS_ERROR_INVALID_SETTING,
		                     "%s.%d - Connection didn't have requested setting '%s'.",
		                     __FILE__, __LINE__, setting_name);
		(*callback) (connection, NULL, error, user_data);
		g_error_free (error);
		return;
	}

	/* Returned secrets are a{sa{sv}}; this is the outer a{s...} hash that
	 * will contain all the individual settings hashes.
	 */
	settings = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                  g_free, (GDestroyNotify) g_hash_table_destroy);

	/* Add the secrets from this setting to the inner secrets hash for this setting */
	secrets = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, destroy_gvalue);
	nm_setting_enumerate_values (setting, add_secrets, secrets);

	g_hash_table_insert (settings, g_strdup (setting_name), secrets);
	callback (connection, settings, NULL, user_data);
	g_hash_table_destroy (settings);
}

/**** User authorization **************************************/

typedef void (*AuthCallback) (NMSysconfigConnection *connection, 
	                          DBusGMethodInvocation *context,
	                          GError *error,
	                          gpointer data);

typedef struct {
	NMSysconfigConnection *self;
	DBusGMethodInvocation *context;
	PolkitSubject *subject;
	GCancellable *cancellable;
	gboolean check_modify;
	gboolean disposed;

	AuthCallback callback;
	gpointer callback_data;
} PendingAuth;

static void
auth_finish (PendingAuth *info, GError *error)
{
	NMSysconfigConnectionPrivate *priv = NM_SYSCONFIG_CONNECTION_GET_PRIVATE (info->self);
	priv->pending_auths = g_slist_remove (priv->pending_auths, info);

	info->callback (info->self, info->context, error, info->callback_data);

	if (info->subject)
		g_object_unref (info->subject);
	if (info->cancellable)
		g_object_unref (info->cancellable);

	g_slice_free (PendingAuth, info);
}

static void
auth_pk_cb (GObject *object, GAsyncResult *result, gpointer user_data)
{
	PendingAuth *info = user_data;
	NMSysconfigConnectionPrivate *priv = NM_SYSCONFIG_CONNECTION_GET_PRIVATE (info->self);
	PolkitAuthorizationResult *pk_result;
	GError *error = NULL;

	if (info->disposed) {
		error = g_error_new_literal (NM_SYSCONFIG_SETTINGS_ERROR,
		                             NM_SYSCONFIG_SETTINGS_ERROR_GENERAL,
		                             "Request was canceled.");
		auth_finish (info, error);
		g_error_free (error);
		return;
	}

	pk_result = polkit_authority_check_authorization_finish (priv->authority,
	                                                         result,
	                                                         &error);

	if (error) {
		auth_finish (info, error);
		g_error_free (error);
		return;
	}

	if (!polkit_authorization_result_get_is_authorized (pk_result)) {
		error = g_error_new_literal (NM_SYSCONFIG_SETTINGS_ERROR,
		                             NM_SYSCONFIG_SETTINGS_ERROR_NOT_PRIVILEGED,
		                             "Insufficient privileges.");
		auth_finish (info, error);
		g_error_free (error);
		goto out;
	}

	auth_finish (info, NULL);

out:
	g_object_unref (pk_result);
}

static void
auth_get_session_cb (NMSessionInfo *session,
                     GError *session_error,
                     gpointer user_data)
{
	PendingAuth *info = user_data;
	NMSysconfigConnectionPrivate *priv = NM_SYSCONFIG_CONNECTION_GET_PRIVATE (info->self);
	GError *error = NULL;
	
	if (info->disposed || !session) {
		error = g_error_new_literal (NM_SYSCONFIG_SETTINGS_ERROR,
		                             NM_SYSCONFIG_SETTINGS_ERROR_GENERAL,
		                             "Request was canceled.");
		auth_finish (info, error);
		g_error_free (error);
		return;
	}

	if (!nm_sysconfig_connection_is_accessible_by_session (info->self, session)) {
		error = g_error_new_literal (NM_SYSCONFIG_SETTINGS_ERROR,
		                             NM_SYSCONFIG_SETTINGS_ERROR_PERMISSION_DENIED,
		                             "Caller's session is not authorized to access connection.");
		auth_finish (info, error);
		g_error_free (error);
		return;
	}

	if (!info->check_modify) {
		auth_finish (info, NULL);
	} else {
		char *sender = dbus_g_method_get_sender (info->context);
		info->subject = polkit_system_bus_name_new (sender);
		info->cancellable = g_cancellable_new();
		g_free (sender);

		polkit_authority_check_authorization (priv->authority,
	                                      	  info->subject,
	                                      	  NM_SYSCONFIG_POLICY_ACTION_CONNECTION_MODIFY,
	                                      	  NULL,
	                                      	  POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION,
	                                      	  info->cancellable,
	                                      	  auth_pk_cb,
	                                      	  info);
	}

}

static void
auth_start (NMSysconfigConnection *self,
            DBusGMethodInvocation *context,
            gboolean check_modify,
            AuthCallback callback,
            gpointer callback_data)
{
	NMSysconfigConnectionPrivate *priv = NM_SYSCONFIG_CONNECTION_GET_PRIVATE (self);
	PendingAuth *info = g_slice_new (PendingAuth);
	info->self = self;
	info->context = context;
	info->subject = NULL;
	info->cancellable = NULL;
	info->check_modify = check_modify;
	info->disposed = FALSE;
	info->callback_data = callback_data;

	priv->pending_auths = g_slist_prepend (priv->pending_auths, info);

	nm_session_manager_get_session_of_caller (nm_session_manager_get(),
	                                          context,
	                                          auth_get_session_cb,
	                                          info);

}

/**** DBus method handlers ************************************/

static gboolean
check_writable (NMConnection *connection, GError **error)
{
	NMSettingConnection *s_con;

	g_return_val_if_fail (connection != NULL, FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	s_con = (NMSettingConnection *) nm_connection_get_setting (connection,
	                                                           NM_TYPE_SETTING_CONNECTION);
	if (!s_con) {
		g_set_error_literal (error,
		                     NM_SYSCONFIG_SETTINGS_ERROR,
		                     NM_SYSCONFIG_SETTINGS_ERROR_INVALID_CONNECTION,
		                     "Connection did not have required 'connection' setting");
		return FALSE;
	}

	/* If the connection is read-only, that has to be changed at the source of
	 * the problem (ex a system settings plugin that can't write connections out)
	 * instead of over D-Bus.
	 */
	if (nm_setting_connection_get_read_only (s_con)) {
		g_set_error_literal (error,
		                     NM_SYSCONFIG_SETTINGS_ERROR,
		                     NM_SYSCONFIG_SETTINGS_ERROR_READ_ONLY_CONNECTION,
		                     "Connection is read-only");
		return FALSE;
	}

	return TRUE;
}

static void
get_settings_auth_cb (NMSysconfigConnection *self, 
	                  DBusGMethodInvocation *context,
	                  GError *error,
	                  gpointer data)
{
	NMConnection *no_secrets;
	GHashTable *settings;

	if (error) {
		dbus_g_method_return_error (context, error);
		return;
	}

	/* Secrets should *never* be returned by the GetSettings method, they
	 * get returned by the GetSecrets method which can be better
	 * protected against leakage of secrets to unprivileged callers.
	 */
	no_secrets = nm_connection_duplicate (NM_CONNECTION (self));
	g_assert (no_secrets);
	nm_connection_clear_secrets (no_secrets);
	settings = nm_connection_to_hash (no_secrets);
	g_assert (settings);

	dbus_g_method_return (context, settings);
	
	g_object_unref (no_secrets);
	g_object_unref (settings);
}

static void
impl_sysconfig_connection_get_settings (NMSysconfigConnection *self,
                                        DBusGMethodInvocation *context)
{
	auth_start (self, context, FALSE, get_settings_auth_cb, NULL);
}

static void
con_update_cb (NMSysconfigConnection *connection,
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
update_auth_cb (NMSysconfigConnection *self, 
	            DBusGMethodInvocation *context,
	            GError *error,
	            gpointer data)
{
	NMConnection *new_settings = data;

	if (error) {
		dbus_g_method_return_error (context, error);
		goto out;
	}

	/* Update and commit our settings. */
	nm_sysconfig_connection_replace_and_commit (self, 
	                                            new_settings,
	                                            con_update_cb,
	                                            context);

out:
	g_object_unref (new_settings);
}

static void
impl_sysconfig_connection_update (NMSysconfigConnection *self,
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
con_delete_cb (NMSysconfigConnection *connection,
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
delete_auth_cb (NMSysconfigConnection *self, 
	            DBusGMethodInvocation *context,
	            GError *error,
	            gpointer data)
{
	if (error) {
		dbus_g_method_return_error (context, error);
		return;
	}

	nm_sysconfig_connection_delete (self, con_delete_cb, context);
}

static void
impl_sysconfig_connection_delete (NMSysconfigConnection *self,
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

typedef struct {
	char *setting_name;
	char **hints;
	gboolean request_new;
} GetSecretsInfo;

static void
con_secrets_cb (NMSysconfigConnection *connection,
                GHashTable *secrets,
                GError *error,
                gpointer user_data)
{
	DBusGMethodInvocation *context = user_data;

	if (error)
		dbus_g_method_return_error (context, error);
	else
		dbus_g_method_return (context, secrets);
}

static void
secrets_auth_cb (NMSysconfigConnection *self, 
	             DBusGMethodInvocation *context,
	             GError *error,
	             gpointer data)
{
	GetSecretsInfo *info = data;

	if (error) {
		dbus_g_method_return_error (context, error);
		goto out;
	}

	nm_sysconfig_connection_get_secrets (self,
	                                     info->setting_name,
	                                     (const char **) info->hints,
	                                     info->request_new,
	                                     con_secrets_cb,
	                                     context);

out:
	g_free (info->setting_name);
	g_strfreev (info->hints);
	g_slice_free (GetSecretsInfo, info);
}

static void
impl_sysconfig_connection_get_secrets (NMSysconfigConnection *self,
                                       const gchar *setting_name,
                                       const gchar **hints,
                                       gboolean request_new,
                                       DBusGMethodInvocation *context)
{
	GetSecretsInfo *info = g_slice_new (GetSecretsInfo);
	info->setting_name = g_strdup (setting_name);
	info->hints = g_strdupv ((char **) hints);
	info->request_new = request_new;

	auth_start (self, context, TRUE, secrets_auth_cb, info);
}

/**************************************************************/

static void
nm_sysconfig_connection_init (NMSysconfigConnection *self)
{
	NMSysconfigConnectionPrivate *priv = NM_SYSCONFIG_CONNECTION_GET_PRIVATE (self);
	NMSessionManager *session_manager;
	static guint32 dbus_counter = 0;
	char *dbus_path;

	priv->authority = polkit_authority_get ();
	if (!priv->authority) {
		nm_log_err (LOGD_SYS_SET, "%s:error creating PolicyKit authority");
	}

	dbus_path = g_strdup_printf ("%s/%u", NM_DBUS_PATH_SETTINGS, dbus_counter++);
	nm_connection_set_path (NM_CONNECTION (self), dbus_path);	
	g_free (dbus_path);
	priv->visible = FALSE;

	priv->access_list = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_object_unref);
	session_manager = nm_session_manager_get();
	g_signal_connect (session_manager, NM_SESSION_MANAGER_SESSION_ADDED,
	                  G_CALLBACK (session_added_cb), self);

}

static void
access_list_dispose (gpointer key, gpointer value, gpointer user_data)
{
	NMSysconfigConnection *connection = (NMSysconfigConnection *) user_data;
	NMSessionInfo *session = (NMSessionInfo *) value;

	g_signal_handlers_disconnect_by_func (session, session_removed_cb, connection);
}

static void
dispose (GObject *object)
{
	NMSysconfigConnection *self = NM_SYSCONFIG_CONNECTION (object);
	NMSysconfigConnectionPrivate *priv = NM_SYSCONFIG_CONNECTION_GET_PRIVATE (self);
	NMSessionManager *session_manager = nm_session_manager_get ();
	GSList *iter;

	if (priv->secrets)
		g_object_unref (priv->secrets);

	/* Cancel PolicyKit requests */
	for (iter = priv->pending_auths; iter; iter = g_slist_next (iter)) {
		PendingAuth *call = iter->data;

		call->disposed = TRUE;
		g_cancellable_cancel (call->cancellable);
	}
	g_slist_free (priv->pending_auths);
	priv->pending_auths = NULL;

	set_visibility (self, FALSE);
	g_signal_handlers_disconnect_by_func (session_manager, session_added_cb, self);
	g_hash_table_foreach (priv->access_list, access_list_dispose, self);
	g_hash_table_unref (priv->access_list);
	priv->access_list = NULL;

	G_OBJECT_CLASS (nm_sysconfig_connection_parent_class)->dispose (object);
}

static void
nm_sysconfig_connection_class_init (NMSysconfigConnectionClass *class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (class);

	g_type_class_add_private (class, sizeof (NMSysconfigConnectionPrivate));

	/* Virtual methods */
	object_class->dispose = dispose;
	class->commit_changes = commit_changes;
	class->delete = do_delete;
	class->get_secrets = get_secrets;

	/* Signals */
	signals[UPDATED] = 
		g_signal_new (NM_SYSCONFIG_CONNECTION_UPDATED,
		              G_TYPE_FROM_CLASS (class),
		              G_SIGNAL_RUN_FIRST,
		              0,
		              NULL, NULL,
		              g_cclosure_marshal_VOID__BOXED,
		              G_TYPE_NONE, 1, DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT);

	signals[REMOVED] = 
		g_signal_new (NM_SYSCONFIG_CONNECTION_REMOVED,
		              G_TYPE_FROM_CLASS (class),
		              G_SIGNAL_RUN_FIRST,
		              0,
		              NULL, NULL,
		              g_cclosure_marshal_VOID__VOID,
		              G_TYPE_NONE, 0);

	signals[PURGED] = 
		g_signal_new (NM_SYSCONFIG_CONNECTION_PURGED,
		              G_TYPE_FROM_CLASS (class),
		              G_SIGNAL_RUN_FIRST,
		              0,
		              NULL, NULL,
		              g_cclosure_marshal_VOID__VOID,
		              G_TYPE_NONE, 0);

	signals[UNHIDDEN] = 
		g_signal_new (NM_SYSCONFIG_CONNECTION_UNHIDDEN,
		              G_TYPE_FROM_CLASS (class),
		              G_SIGNAL_RUN_FIRST,
		              0,
		              NULL, NULL,
		              g_cclosure_marshal_VOID__VOID,
		              G_TYPE_NONE, 0);

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (class),
	                                 &dbus_glib_nm_sysconfig_connection_object_info);

}
