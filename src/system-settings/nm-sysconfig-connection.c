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

#include "nm-sysconfig-connection.h"
#include "nm-system-config-error.h"
#include "nm-dbus-glib-types.h"
#include "nm-settings-connection-interface.h"
#include "nm-settings-interface.h"
#include "nm-polkit-helpers.h"
#include "nm-logging.h"


static void settings_connection_interface_init (NMSettingsConnectionInterface *klass);

G_DEFINE_TYPE_EXTENDED (NMSysconfigConnection, nm_sysconfig_connection, NM_TYPE_EXPORTED_CONNECTION, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_SETTINGS_CONNECTION_INTERFACE,
                                               settings_connection_interface_init))

#define NM_SYSCONFIG_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                                NM_TYPE_SYSCONFIG_CONNECTION, \
                                                NMSysconfigConnectionPrivate))

typedef struct {
	PolkitAuthority *authority;
	GSList *pk_calls;
	NMConnection *secrets;
} NMSysconfigConnectionPrivate;

/**************************************************************/

static void
ignore_cb (NMSettingsConnectionInterface *connection,
           GError *error,
           gpointer user_data)
{
}

gboolean
nm_sysconfig_connection_update (NMSysconfigConnection *self,
                                NMConnection *new,
                                gboolean signal_update,
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

	/* Do nothing if there's nothing to update */
	if (nm_connection_compare (NM_CONNECTION (self),
	                           NM_CONNECTION (new),
	                           NM_SETTING_COMPARE_FLAG_EXACT))
		return TRUE;

	new_settings = nm_connection_to_hash (new);
	g_assert (new_settings);
	if (nm_connection_replace_settings (NM_CONNECTION (self), new_settings, error)) {
		/* Copy the connection to keep its secrets around even if NM
		 * calls nm_connection_clear_secrets().
		 */
		if (priv->secrets)
			g_object_unref (priv->secrets);
		priv->secrets = nm_connection_duplicate (NM_CONNECTION (self));

		if (signal_update) {
			nm_settings_connection_interface_update (NM_SETTINGS_CONNECTION_INTERFACE (self),
			                                         ignore_cb,
			                                         NULL);
		}
		success = TRUE;
	}
	g_hash_table_destroy (new_settings);
	return success;
}

/**************************************************************/

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

static gboolean
get_secrets (NMSettingsConnectionInterface *connection,
	         const char *setting_name,
             const char **hints,
             gboolean request_new,
             NMSettingsConnectionInterfaceGetSecretsFunc callback,
             gpointer user_data)
{
	NMSysconfigConnection *self = NM_SYSCONFIG_CONNECTION (connection);
	NMSysconfigConnectionPrivate *priv = NM_SYSCONFIG_CONNECTION_GET_PRIVATE (self);
	GHashTable *settings = NULL;
	GHashTable *secrets = NULL;
	NMSetting *setting;
	GError *error = NULL;

	/* Use priv->secrets to work around the fact that nm_connection_clear_secrets()
	 * will clear secrets on this object's settings.  priv->secrets should be
	 * a complete copy of this object and kept in sync by
	 * nm_sysconfig_connection_update().
	 */
	if (!priv->secrets) {
		error = g_error_new (NM_SETTINGS_INTERFACE_ERROR,
		                     NM_SETTINGS_INTERFACE_ERROR_INVALID_CONNECTION,
		                     "%s.%d - Internal error; secrets cache invalid.",
		                     __FILE__, __LINE__);
		(*callback) (connection, NULL, error, user_data);
		g_error_free (error);
		return TRUE;
	}

	setting = nm_connection_get_setting_by_name (priv->secrets, setting_name);
	if (!setting) {
		error = g_error_new (NM_SETTINGS_INTERFACE_ERROR,
		                     NM_SETTINGS_INTERFACE_ERROR_INVALID_SETTING,
		                     "%s.%d - Connection didn't have requested setting '%s'.",
		                     __FILE__, __LINE__, setting_name);
		(*callback) (connection, NULL, error, user_data);
		g_error_free (error);
		return TRUE;
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
	return TRUE;
}

/**************************************************************/

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
con_update_cb (NMSettingsConnectionInterface *connection,
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

	/* Update our settings internally so the update() call will save the new
	 * ones.  We don't let nm_sysconfig_connection_update() handle the update
	 * signal since we need our own callback after the update is done.
	 */
	if (!nm_sysconfig_connection_update (self, call->connection, FALSE, &error)) {
		/* Shouldn't really happen since we've already validated the settings */
		dbus_g_method_return_error (call->context, error);
		g_error_free (error);
		polkit_call_free (call);
		goto out;
	}

	/* Caller is authenticated, now we can finally try to commit the update */
	nm_settings_connection_interface_update (NM_SETTINGS_CONNECTION_INTERFACE (self),
	                                         con_update_cb,
	                                         call);

out:
	g_object_unref (pk_result);
}

static void
dbus_update (NMExportedConnection *exported,
             GHashTable *new_settings,
             DBusGMethodInvocation *context)
{
	NMSysconfigConnection *self = NM_SYSCONFIG_CONNECTION (exported);
	NMSysconfigConnectionPrivate *priv = NM_SYSCONFIG_CONNECTION_GET_PRIVATE (self);
	PolkitCall *call;
	NMConnection *tmp;
	GError *error = NULL;

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
con_delete_cb (NMSettingsConnectionInterface *connection,
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
	nm_settings_connection_interface_delete (NM_SETTINGS_CONNECTION_INTERFACE (self),
	                                         con_delete_cb,
	                                         call);

out:
	g_object_unref (pk_result);
}

static void
dbus_delete (NMExportedConnection *exported,
             DBusGMethodInvocation *context)
{
	NMSysconfigConnection *self = NM_SYSCONFIG_CONNECTION (exported);
	NMSysconfigConnectionPrivate *priv = NM_SYSCONFIG_CONNECTION_GET_PRIVATE (self);
	PolkitCall *call;

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
con_secrets_cb (NMSettingsConnectionInterface *connection,
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
	nm_settings_connection_interface_get_secrets (NM_SETTINGS_CONNECTION_INTERFACE (self),
	                                              call->setting_name,
	                                              (const char **) call->hints,
	                                              call->request_new,
	                                              con_secrets_cb,
	                                              call);

out:
	g_object_unref (pk_result);
}

static void
dbus_get_secrets (NMExportedConnection *exported,
                  const gchar *setting_name,
                  const gchar **hints,
                  gboolean request_new,
                  DBusGMethodInvocation *context)
{
	NMSysconfigConnection *self = NM_SYSCONFIG_CONNECTION (exported);
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
settings_connection_interface_init (NMSettingsConnectionInterface *iface)
{
	iface->get_secrets = get_secrets;
}

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
	NMExportedConnectionClass *ec_class = NM_EXPORTED_CONNECTION_CLASS (class);

	g_type_class_add_private (class, sizeof (NMSysconfigConnectionPrivate));

	/* Virtual methods */
	object_class->dispose = dispose;
	ec_class->update = dbus_update;
	ec_class->delete = dbus_delete;
	ec_class->get_secrets = dbus_get_secrets;
}
