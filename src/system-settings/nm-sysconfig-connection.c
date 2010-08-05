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

#include "nm-sysconfig-connection.h"
#include "nm-system-config-error.h"
#include "nm-dbus-glib-types.h"
#include "nm-polkit-helpers.h"
#include "nm-logging.h"

static gboolean impl_sysconfig_connection_get_settings (NMSysconfigConnection *connection,
                                                        GHashTable **settings,
                                                        GError **error);

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
	REMOVED,

	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	PolkitAuthority *authority;
	GSList *pk_calls;
	NMConnection *secrets;
} NMSysconfigConnectionPrivate;

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
	g_signal_emit (connection, signals[REMOVED], 0);
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

/**************************************************************/

static gboolean
impl_sysconfig_connection_get_settings (NMSysconfigConnection *self,
                                        GHashTable **settings,
                                        GError **error)
{
	NMConnection *no_secrets;

	/* Secrets should *never* be returned by the GetSettings method, they
	 * get returned by the GetSecrets method which can be better
	 * protected against leakage of secrets to unprivileged callers.
	 */
	no_secrets = nm_connection_duplicate (NM_CONNECTION (self));
	g_assert (no_secrets);
	nm_connection_clear_secrets (no_secrets);
	*settings = nm_connection_to_hash (no_secrets);
	g_assert (*settings);
	g_object_unref (no_secrets);
	return *settings ? TRUE : FALSE;
}

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

typedef struct {
	NMSysconfigConnection *self;
	DBusGMethodInvocation *context;
	PolkitSubject *subject;
	GCancellable *cancellable;
	gboolean disposed;

	/* Update */
	NMConnection *connection;

	/* Secrets */
	char *setting_name;
	char **hints;
	gboolean request_new;
} PolkitCall;

static PolkitCall *
polkit_call_new (NMSysconfigConnection *self,
                 DBusGMethodInvocation *context,
                 NMConnection *connection,
                 const char *setting_name,
                 const char **hints,
                 gboolean request_new)
{
	PolkitCall *call;
	char *sender;

	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (context != NULL, NULL);

	call = g_malloc0 (sizeof (PolkitCall));
	call->self = self;
	call->context = context;
	call->cancellable = g_cancellable_new ();
	call->connection = connection;
	call->setting_name = g_strdup (setting_name);
	if (hints)
		call->hints = g_strdupv ((char **) hints);
	call->request_new = request_new;

 	sender = dbus_g_method_get_sender (context);
	call->subject = polkit_system_bus_name_new (sender);
	g_free (sender);

	return call;
}

static void
polkit_call_free (PolkitCall *call)
{
	if (call->connection)
		g_object_unref (call->connection);
	g_free (call->setting_name);
	if (call->hints)
		g_strfreev (call->hints);

	g_object_unref (call->subject);
	g_object_unref (call->cancellable);
	g_free (call);
}

static void
con_update_cb (NMSysconfigConnection *connection,
               GError *error,
               gpointer user_data)
{
	PolkitCall *call = user_data;

	if (error)
		dbus_g_method_return_error (call->context, error);
	else
		dbus_g_method_return (call->context);

	polkit_call_free (call);
}

static void
pk_update_cb (GObject *object, GAsyncResult *result, gpointer user_data)
{
	PolkitCall *call = user_data;
	NMSysconfigConnection *self = call->self;
	NMSysconfigConnectionPrivate *priv;
	PolkitAuthorizationResult *pk_result;
	GError *error = NULL;

	/* If our NMSysconfigConnection is already gone, do nothing */
	if (call->disposed) {
		error = g_error_new_literal (NM_SYSCONFIG_SETTINGS_ERROR,
		                             NM_SYSCONFIG_SETTINGS_ERROR_GENERAL,
		                             "Request was canceled.");
		dbus_g_method_return_error (call->context, error);
		g_error_free (error);
		polkit_call_free (call);
		return;
	}

	priv = NM_SYSCONFIG_CONNECTION_GET_PRIVATE (self);

	priv->pk_calls = g_slist_remove (priv->pk_calls, call);

	pk_result = polkit_authority_check_authorization_finish (priv->authority,
	                                                         result,
	                                                         &error);
	/* Some random error happened */
	if (error) {
		dbus_g_method_return_error (call->context, error);
		g_error_free (error);
		polkit_call_free (call);
		return;
	}

	/* Caller didn't successfully authenticate */
	if (!polkit_authorization_result_get_is_authorized (pk_result)) {
		error = g_error_new_literal (NM_SYSCONFIG_SETTINGS_ERROR,
		                             NM_SYSCONFIG_SETTINGS_ERROR_NOT_PRIVILEGED,
		                             "Insufficient privileges.");
		dbus_g_method_return_error (call->context, error);
		g_error_free (error);
		polkit_call_free (call);
		goto out;
	}

	/* Update and commit our settings. */
	nm_sysconfig_connection_replace_and_commit (self, 
	                                            call->connection,
	                                            con_update_cb,
	                                            call);

out:
	g_object_unref (pk_result);
}

static void
impl_sysconfig_connection_update (NMSysconfigConnection *self,
                                  GHashTable *new_settings,
                                  DBusGMethodInvocation *context)
{
	NMSysconfigConnectionPrivate *priv = NM_SYSCONFIG_CONNECTION_GET_PRIVATE (self);
	PolkitCall *call;
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

	call = polkit_call_new (self, context, tmp, NULL, NULL, FALSE);
	g_assert (call);
	polkit_authority_check_authorization (priv->authority,
	                                      call->subject,
	                                      NM_SYSCONFIG_POLICY_ACTION_CONNECTION_MODIFY,
	                                      NULL,
	                                      POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION,
	                                      call->cancellable,
	                                      pk_update_cb,
	                                      call);
	priv->pk_calls = g_slist_prepend (priv->pk_calls, call);
}

static void
con_delete_cb (NMSysconfigConnection *connection,
               GError *error,
               gpointer user_data)
{
	PolkitCall *call = user_data;

	if (error)
		dbus_g_method_return_error (call->context, error);
	else
		dbus_g_method_return (call->context);

	polkit_call_free (call);
}

static void
pk_delete_cb (GObject *object, GAsyncResult *result, gpointer user_data)
{
	PolkitCall *call = user_data;
	NMSysconfigConnection *self = call->self;
	NMSysconfigConnectionPrivate *priv;
	PolkitAuthorizationResult *pk_result;
	GError *error = NULL;

	/* If our NMSysconfigConnection is already gone, do nothing */
	if (call->disposed) {
		error = g_error_new_literal (NM_SYSCONFIG_SETTINGS_ERROR,
		                             NM_SYSCONFIG_SETTINGS_ERROR_GENERAL,
		                             "Request was canceled.");
		dbus_g_method_return_error (call->context, error);
		g_error_free (error);
		polkit_call_free (call);
		return;
	}

	priv = NM_SYSCONFIG_CONNECTION_GET_PRIVATE (self);

	priv->pk_calls = g_slist_remove (priv->pk_calls, call);

	pk_result = polkit_authority_check_authorization_finish (priv->authority,
	                                                         result,
	                                                         &error);
	/* Some random error happened */
	if (error) {
		dbus_g_method_return_error (call->context, error);
		g_error_free (error);
		polkit_call_free (call);
		return;
	}

	/* Caller didn't successfully authenticate */
	if (!polkit_authorization_result_get_is_authorized (pk_result)) {
		error = g_error_new_literal (NM_SYSCONFIG_SETTINGS_ERROR,
		                             NM_SYSCONFIG_SETTINGS_ERROR_NOT_PRIVILEGED,
		                             "Insufficient privileges.");
		dbus_g_method_return_error (call->context, error);
		g_error_free (error);
		polkit_call_free (call);
		goto out;
	}

	/* Caller is authenticated, now we can finally try to delete */
	nm_sysconfig_connection_delete (self, con_delete_cb, call);

out:
	g_object_unref (pk_result);
}

static void
impl_sysconfig_connection_delete (NMSysconfigConnection *self,
                                  DBusGMethodInvocation *context)
{
	NMSysconfigConnectionPrivate *priv = NM_SYSCONFIG_CONNECTION_GET_PRIVATE (self);
	PolkitCall *call;
	GError *error = NULL;
	
	if (!check_writable (NM_CONNECTION (self), &error)) {
		dbus_g_method_return_error (context, error);
		g_error_free (error);
		return;
	}

	call = polkit_call_new (self, context, NULL, NULL, NULL, FALSE);
	g_assert (call);
	polkit_authority_check_authorization (priv->authority,
	                                      call->subject,
	                                      NM_SYSCONFIG_POLICY_ACTION_CONNECTION_MODIFY,
	                                      NULL,
	                                      POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION,
	                                      call->cancellable,
	                                      pk_delete_cb,
	                                      call);
	priv->pk_calls = g_slist_prepend (priv->pk_calls, call);
}

static void
con_secrets_cb (NMSysconfigConnection *connection,
                GHashTable *secrets,
                GError *error,
                gpointer user_data)
{
	PolkitCall *call = user_data;

	if (error)
		dbus_g_method_return_error (call->context, error);
	else
		dbus_g_method_return (call->context, secrets);

	polkit_call_free (call);
}

static void
pk_secrets_cb (GObject *object, GAsyncResult *result, gpointer user_data)
{
	PolkitCall *call = user_data;
	NMSysconfigConnection *self = call->self;
	NMSysconfigConnectionPrivate *priv;
	PolkitAuthorizationResult *pk_result;
	GError *error = NULL;

	/* If our NMSysconfigConnection is already gone, do nothing */
	if (call->disposed) {
		error = g_error_new_literal (NM_SYSCONFIG_SETTINGS_ERROR,
		                             NM_SYSCONFIG_SETTINGS_ERROR_GENERAL,
		                             "Request was canceled.");
		dbus_g_method_return_error (call->context, error);
		g_error_free (error);
		polkit_call_free (call);
		return;
	}

	priv = NM_SYSCONFIG_CONNECTION_GET_PRIVATE (self);

	priv->pk_calls = g_slist_remove (priv->pk_calls, call);

	pk_result = polkit_authority_check_authorization_finish (priv->authority,
	                                                         result,
	                                                         &error);
	/* Some random error happened */
	if (error) {
		dbus_g_method_return_error (call->context, error);
		g_error_free (error);
		polkit_call_free (call);
		return;
	}

	/* Caller didn't successfully authenticate */
	if (!polkit_authorization_result_get_is_authorized (pk_result)) {
		error = g_error_new_literal (NM_SYSCONFIG_SETTINGS_ERROR,
		                             NM_SYSCONFIG_SETTINGS_ERROR_NOT_PRIVILEGED,
		                             "Insufficient privileges.");
		dbus_g_method_return_error (call->context, error);
		g_error_free (error);
		polkit_call_free (call);
		goto out;
	}

	/* Caller is authenticated, now we can finally try to update */
	nm_sysconfig_connection_get_secrets (self,
	                                     call->setting_name,
	                                     (const char **) call->hints,
	                                     call->request_new,
	                                     con_secrets_cb,
	                                     call);

out:
	g_object_unref (pk_result);
}

static void
impl_sysconfig_connection_get_secrets (NMSysconfigConnection *self,
                                       const gchar *setting_name,
                                       const gchar **hints,
                                       gboolean request_new,
                                       DBusGMethodInvocation *context)
{
	NMSysconfigConnectionPrivate *priv = NM_SYSCONFIG_CONNECTION_GET_PRIVATE (self);
	PolkitCall *call;

	call = polkit_call_new (self, context, NULL, setting_name, hints, request_new);
	g_assert (call);
	polkit_authority_check_authorization (priv->authority,
	                                      call->subject,
	                                      NM_SYSCONFIG_POLICY_ACTION_CONNECTION_MODIFY,
	                                      NULL,
	                                      POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION,
	                                      call->cancellable,
	                                      pk_secrets_cb,
	                                      call);
	priv->pk_calls = g_slist_prepend (priv->pk_calls, call);
}

/**************************************************************/

static void
nm_sysconfig_connection_init (NMSysconfigConnection *self)
{
	NMSysconfigConnectionPrivate *priv = NM_SYSCONFIG_CONNECTION_GET_PRIVATE (self);

	priv->authority = polkit_authority_get ();
	if (!priv->authority) {
		nm_log_err (LOGD_SYS_SET, "%s: error creating PolicyKit authority");
	}
}

static void
dispose (GObject *object)
{
	NMSysconfigConnection *self = NM_SYSCONFIG_CONNECTION (object);
	NMSysconfigConnectionPrivate *priv = NM_SYSCONFIG_CONNECTION_GET_PRIVATE (self);
	GSList *iter;

	if (priv->secrets)
		g_object_unref (priv->secrets);

	/* Cancel PolicyKit requests */
	for (iter = priv->pk_calls; iter; iter = g_slist_next (iter)) {
		PolkitCall *call = iter->data;

		call->disposed = TRUE;
		g_cancellable_cancel (call->cancellable);
	}
	g_slist_free (priv->pk_calls);
	priv->pk_calls = NULL;

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

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (class),
	                                 &dbus_glib_nm_sysconfig_connection_object_info);

}
