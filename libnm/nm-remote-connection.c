// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2011 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-remote-connection.h"

#include "nm-glib-aux/nm-dbus-aux.h"
#include "nm-dbus-interface.h"
#include "nm-utils.h"
#include "nm-setting-connection.h"
#include "nm-core-internal.h"
#include "nm-remote-connection-private.h"
#include "nm-object-private.h"
#include "nm-dbus-helpers.h"

/**
 * SECTION:nm-remote-connection
 * @short_description: A connection managed by NetworkManager server
 *
 * A #NMRemoteConnection represents a connection that is exported via
 * NetworkManager D-Bus interface.
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMRemoteConnection,
	PROP_UNSAVED,
	PROP_FLAGS,
	PROP_FILENAME,
	PROP_VISIBLE,
);

typedef struct {
	GCancellable *get_settings_cancellable;

	char *filename;
	guint32 flags;
	bool unsaved;

	bool visible:1;
	bool is_initialized:1;
} NMRemoteConnectionPrivate;

struct _NMRemoteConnection {
	NMObject parent;
	NMRemoteConnectionPrivate _priv;
};

struct _NMRemoteConnectionClass {
	NMObjectClass parent_class;
};

static void nm_remote_connection_connection_iface_init (NMConnectionInterface *iface);

G_DEFINE_TYPE_WITH_CODE (NMRemoteConnection, nm_remote_connection, NM_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (NM_TYPE_CONNECTION, nm_remote_connection_connection_iface_init);
                         )

#define NM_REMOTE_CONNECTION_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMRemoteConnection, NM_IS_REMOTE_CONNECTION, NMObject)

/*****************************************************************************/

/**
 * nm_remote_connection_update2:
 * @connection: the #NMRemoteConnection
 * @settings: (allow-none): optional connection to update the settings.
 * @flags: update-flags
 * @args: (allow-none): optional arguments.
 * @cancellable: a #GCancellable, or %NULL
 * @callback: callback to be called when the commit operation completes
 * @user_data: caller-specific data passed to @callback
 *
 * Asynchronously calls the Update2() D-Bus method.
 *
 * Since: 1.12
 **/
void
nm_remote_connection_update2 (NMRemoteConnection *connection,
                              GVariant *settings,
                              NMSettingsUpdate2Flags flags,
                              GVariant *args,
                              GCancellable *cancellable,
                              GAsyncReadyCallback callback,
                              gpointer user_data)
{
	g_return_if_fail (NM_IS_REMOTE_CONNECTION (connection));
	g_return_if_fail (!settings || g_variant_is_of_type (settings, NM_VARIANT_TYPE_CONNECTION));
	g_return_if_fail (!args || g_variant_is_of_type (args, G_VARIANT_TYPE ("a{sv}")));
	g_return_if_fail (!cancellable || G_IS_CANCELLABLE (cancellable));

	if (!settings)
		settings = g_variant_new_array (G_VARIANT_TYPE ("{sa{sv}}"), NULL, 0);
	if (!args)
		args = g_variant_new_array (G_VARIANT_TYPE ("{sv}"), NULL, 0);

	_nm_client_dbus_call (_nm_object_get_client (connection),
	                      connection,
	                      nm_remote_connection_update2,
	                      cancellable,
	                      callback,
	                      user_data,
	                      _nm_object_get_path (connection),
	                      NM_DBUS_INTERFACE_SETTINGS_CONNECTION,
	                      "Update2",
	                      g_variant_new ("(@a{sa{sv}}u@a{sv})",
	                                     settings,
	                                     (guint32) flags,
	                                     args),
	                      G_VARIANT_TYPE ("(a{sv})"),
	                      G_DBUS_CALL_FLAGS_NONE,
	                      NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                      nm_dbus_connection_call_finish_variant_strip_dbus_error_cb);
}

/**
 * nm_remote_connection_update2_finish:
 * @connection: the #NMRemoteConnection
 * @result: the result passed to the #GAsyncReadyCallback
 * @error: location for a #GError, or %NULL
 *
 * Gets the result of a call to nm_remote_connection_commit_changes_async().
 *
 * Returns: (transfer full): on success, a #GVariant of type "a{sv}" with the result. On failure,
 *   %NULL.
 **/
GVariant *
nm_remote_connection_update2_finish (NMRemoteConnection *connection,
                                     GAsyncResult *result,
                                     GError **error)
{
	gs_unref_variant GVariant *ret = NULL;
	GVariant *v_result;

	g_return_val_if_fail (NM_IS_REMOTE_CONNECTION (connection), NULL);
	g_return_val_if_fail (nm_g_task_is_valid (result, connection, nm_remote_connection_update2), NULL);

	ret = g_task_propagate_pointer (G_TASK (result), error);
	if (!ret)
		return NULL;

	g_variant_get (ret,
	               "(@a{sv})",
	               &v_result);

	return v_result;
}

/*****************************************************************************/

/**
 * nm_remote_connection_commit_changes:
 * @connection: the #NMRemoteConnection
 * @save_to_disk: whether to persist the changes to disk
 * @cancellable: a #GCancellable, or %NULL
 * @error: location for a #GError, or %NULL
 *
 * Send any local changes to the settings and properties of @connection to
 * NetworkManager. If @save_to_disk is %TRUE, the updated connection will be saved to
 * disk; if %FALSE, then only the in-memory representation will be changed.
 *
 * Returns: %TRUE on success, %FALSE on error, in which case @error will be set.
 *
 * Deprecated: 1.22, use nm_remote_connection_commit_changes_async() or GDBusConnection
 **/
gboolean
nm_remote_connection_commit_changes (NMRemoteConnection *connection,
                                     gboolean save_to_disk,
                                     GCancellable *cancellable,
                                     GError **error)
{
	gs_unref_variant GVariant *ret = NULL;

	g_return_val_if_fail (NM_IS_REMOTE_CONNECTION (connection), FALSE);
	g_return_val_if_fail (!cancellable || G_IS_CANCELLABLE (cancellable), FALSE);

	ret = _nm_client_dbus_call_sync (_nm_object_get_client (connection),
	                                 cancellable,
	                                 _nm_object_get_path (connection),
	                                 NM_DBUS_INTERFACE_SETTINGS_CONNECTION,
	                                 "Update2",
	                                 g_variant_new ("(@a{sa{sv}}u@a{sv})",
	                                                nm_connection_to_dbus (NM_CONNECTION (connection),
	                                                                       NM_CONNECTION_SERIALIZE_ALL),
	                                                (guint32) (  save_to_disk
	                                                           ? NM_SETTINGS_UPDATE2_FLAG_TO_DISK
	                                                           : NM_SETTINGS_UPDATE2_FLAG_IN_MEMORY),
	                                                g_variant_new_array (G_VARIANT_TYPE ("{sv}"), NULL, 0)),
	                                 G_VARIANT_TYPE ("(a{sv})"),
	                                 G_DBUS_CALL_FLAGS_NONE,
	                                 NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                                 TRUE,
	                                 error);
	if (!ret)
		return FALSE;

	return TRUE;
}

/**
 * nm_remote_connection_commit_changes_async:
 * @connection: the #NMRemoteConnection
 * @save_to_disk: whether to save the changes to persistent storage
 * @cancellable: a #GCancellable, or %NULL
 * @callback: callback to be called when the commit operation completes
 * @user_data: caller-specific data passed to @callback
 *
 * Asynchronously sends any local changes to the settings and properties of
 * @connection to NetworkManager. If @save is %TRUE, the updated connection will
 * be saved to disk; if %FALSE, then only the in-memory representation will be
 * changed.
 **/
void
nm_remote_connection_commit_changes_async (NMRemoteConnection *connection,
                                           gboolean save_to_disk,
                                           GCancellable *cancellable,
                                           GAsyncReadyCallback callback,
                                           gpointer user_data)
{
	g_return_if_fail (NM_IS_REMOTE_CONNECTION (connection));
	g_return_if_fail (!cancellable || G_IS_CANCELLABLE (cancellable));

	nm_remote_connection_update2 (connection,
	                              nm_connection_to_dbus (NM_CONNECTION (connection),
	                                                     NM_CONNECTION_SERIALIZE_ALL),
	                                save_to_disk
	                              ? NM_SETTINGS_UPDATE2_FLAG_TO_DISK
	                              : NM_SETTINGS_UPDATE2_FLAG_IN_MEMORY,
	                              NULL,
	                              cancellable,
	                              callback,
	                              user_data);
}

/**
 * nm_remote_connection_commit_changes_finish:
 * @connection: the #NMRemoteConnection
 * @result: the result passed to the #GAsyncReadyCallback
 * @error: location for a #GError, or %NULL
 *
 * Gets the result of a call to nm_remote_connection_commit_changes_async().
 *
 * Returns: %TRUE on success, %FALSE on error, in which case @error will be set.
 **/
gboolean
nm_remote_connection_commit_changes_finish (NMRemoteConnection *connection,
                                            GAsyncResult *result,
                                            GError **error)
{
	gs_unref_variant GVariant *v_result = NULL;

	v_result = nm_remote_connection_update2_finish (connection, result, error);
	return !!v_result;
}

/*****************************************************************************/

/**
 * nm_remote_connection_save:
 * @connection: the #NMRemoteConnection
 * @cancellable: a #GCancellable, or %NULL
 * @error: location for a #GError, or %NULL
 *
 * Saves the connection to disk if the connection has changes that have not yet
 * been written to disk, or if the connection has never been saved.
 *
 * Returns: %TRUE on success, %FALSE on error, in which case @error will be set.
 *
 * Deprecated: 1.22, use nm_remote_connection_save_async() or GDBusConnection
 **/
gboolean
nm_remote_connection_save (NMRemoteConnection *connection,
                           GCancellable *cancellable,
                           GError **error)
{
	g_return_val_if_fail (NM_IS_REMOTE_CONNECTION (connection), FALSE);
	g_return_val_if_fail (!cancellable || G_IS_CANCELLABLE (cancellable), FALSE);

	return _nm_client_dbus_call_sync_void (_nm_object_get_client (connection),
	                                       cancellable,
	                                       _nm_object_get_path (connection),
	                                       NM_DBUS_INTERFACE_SETTINGS_CONNECTION,
	                                       "Save",
	                                       g_variant_new ("()"),
	                                       G_DBUS_CALL_FLAGS_NONE,
	                                       NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                                       TRUE,
	                                       error);
}

/**
 * nm_remote_connection_save_async:
 * @connection: the #NMRemoteConnection
 * @cancellable: a #GCancellable, or %NULL
 * @callback: callback to be called when the save operation completes
 * @user_data: caller-specific data passed to @callback
 *
 * Saves the connection to disk if the connection has changes that have not yet
 * been written to disk, or if the connection has never been saved.
 **/
void
nm_remote_connection_save_async (NMRemoteConnection *connection,
                                 GCancellable *cancellable,
                                 GAsyncReadyCallback callback,
                                 gpointer user_data)
{
	g_return_if_fail (NM_IS_REMOTE_CONNECTION (connection));
	g_return_if_fail (!cancellable || G_IS_CANCELLABLE (cancellable));

	_nm_client_dbus_call (_nm_object_get_client (connection),
	                      connection,
	                      nm_remote_connection_save_async,
	                      cancellable,
	                      callback,
	                      user_data,
	                      _nm_object_get_path (connection),
	                      NM_DBUS_INTERFACE_SETTINGS_CONNECTION,
	                      "Save",
	                      g_variant_new ("()"),
	                      G_VARIANT_TYPE ("()"),
	                      G_DBUS_CALL_FLAGS_NONE,
	                      NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                      nm_dbus_connection_call_finish_void_strip_dbus_error_cb);
}

/**
 * nm_remote_connection_save_finish:
 * @connection: the #NMRemoteConnection
 * @result: the result passed to the #GAsyncReadyCallback
 * @error: location for a #GError, or %NULL
 *
 * Gets the result of a call to nm_remote_connection_save_async().
 *
 * Returns: %TRUE on success, %FALSE on error, in which case @error will be set.
 **/
gboolean
nm_remote_connection_save_finish (NMRemoteConnection *connection,
                                  GAsyncResult *result,
                                  GError **error)
{
	g_return_val_if_fail (NM_IS_REMOTE_CONNECTION (connection), FALSE);
	g_return_val_if_fail (nm_g_task_is_valid (result, connection, nm_remote_connection_save_async), FALSE);

	return g_task_propagate_boolean (G_TASK (result), error);
}

/*****************************************************************************/

/**
 * nm_remote_connection_delete:
 * @connection: the #NMRemoteConnection
 * @cancellable: a #GCancellable, or %NULL
 * @error: location for a #GError, or %NULL
 *
 * Deletes the connection.
 *
 * Returns: %TRUE on success, %FALSE on error, in which case @error will be set.
 *
 * Deprecated: 1.22, use nm_remote_connection_delete_async() or GDBusConnection
 **/
gboolean
nm_remote_connection_delete (NMRemoteConnection *connection,
                             GCancellable *cancellable,
                             GError **error)
{
	g_return_val_if_fail (NM_IS_REMOTE_CONNECTION (connection), FALSE);

	return _nm_client_dbus_call_sync_void (_nm_object_get_client (connection),
	                                       cancellable,
	                                       _nm_object_get_path (connection),
	                                       NM_DBUS_INTERFACE_SETTINGS_CONNECTION,
	                                       "Delete",
	                                       g_variant_new ("()"),
	                                       G_DBUS_CALL_FLAGS_NONE,
	                                       NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                                       TRUE,
	                                       error);
}

/**
 * nm_remote_connection_delete_async:
 * @connection: the #NMRemoteConnection
 * @cancellable: a #GCancellable, or %NULL
 * @callback: callback to be called when the delete operation completes
 * @user_data: caller-specific data passed to @callback
 *
 * Asynchronously deletes the connection.
 **/
void
nm_remote_connection_delete_async (NMRemoteConnection *connection,
                                   GCancellable *cancellable,
                                   GAsyncReadyCallback callback,
                                   gpointer user_data)
{
	g_return_if_fail (NM_IS_REMOTE_CONNECTION (connection));
	g_return_if_fail (!cancellable || G_IS_CANCELLABLE (cancellable));

	_nm_client_dbus_call (_nm_object_get_client (connection),
	                      connection,
	                      nm_remote_connection_delete_async,
	                      cancellable,
	                      callback,
	                      user_data,
	                      _nm_object_get_path (connection),
	                      NM_DBUS_INTERFACE_SETTINGS_CONNECTION,
	                      "Delete",
	                      g_variant_new ("()"),
	                      G_VARIANT_TYPE ("()"),
	                      G_DBUS_CALL_FLAGS_NONE,
	                      NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                      nm_dbus_connection_call_finish_void_strip_dbus_error_cb);
}

/**
 * nm_remote_connection_delete_finish:
 * @connection: the #NMRemoteConnection
 * @result: the result passed to the #GAsyncReadyCallback
 * @error: location for a #GError, or %NULL
 *
 * Gets the result of a call to nm_remote_connection_delete_async().
 *
 * Returns: %TRUE on success, %FALSE on error, in which case @error will be set.
 **/
gboolean
nm_remote_connection_delete_finish (NMRemoteConnection *connection,
                                    GAsyncResult *result,
                                    GError **error)
{
	g_return_val_if_fail (NM_IS_REMOTE_CONNECTION (connection), FALSE);
	g_return_val_if_fail (nm_g_task_is_valid (result, connection, nm_remote_connection_delete_async), FALSE);

	return g_task_propagate_boolean (G_TASK (result), error);
}

/**
 * nm_remote_connection_get_secrets:
 * @connection: the #NMRemoteConnection
 * @setting_name: the #NMSetting object name to get secrets for
 * @cancellable: a #GCancellable, or %NULL
 * @error: location for a #GError, or %NULL
 *
 * Request the connection's secrets. Note that this is a blocking D-Bus call,
 * not a simple property accessor.
 *
 * Returns: (transfer full): a #GVariant of type %NM_VARIANT_TYPE_CONNECTION containing
 * @connection's secrets, or %NULL on error.
 *
 * Deprecated: 1.22, use nm_remote_connection_get_secrets_async() or GDBusConnection
 **/
GVariant *
nm_remote_connection_get_secrets (NMRemoteConnection *connection,
                                  const char *setting_name,
                                  GCancellable *cancellable,
                                  GError **error)
{
	gs_unref_variant GVariant *ret = NULL;
	GVariant *secrets;

	g_return_val_if_fail (NM_IS_REMOTE_CONNECTION (connection), NULL);
	g_return_val_if_fail (setting_name, NULL);
	g_return_val_if_fail (!cancellable || G_IS_CANCELLABLE (cancellable), NULL);

	ret = _nm_client_dbus_call_sync (_nm_object_get_client (connection),
	                                 cancellable,
	                                 _nm_object_get_path (connection),
	                                 NM_DBUS_INTERFACE_SETTINGS_CONNECTION,
	                                 "GetSecrets",
	                                 g_variant_new ("(s)", setting_name),
	                                 G_VARIANT_TYPE ("(a{sa{sv}})"),
	                                 G_DBUS_CALL_FLAGS_NONE,
	                                 NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                                 TRUE,
	                                 error);
	if (!ret)
		return NULL;

	g_variant_get (ret,
	               "(@a{sa{sv}})",
	               &secrets);

	return secrets;
}

/**
 * nm_remote_connection_get_secrets_async:
 * @connection: the #NMRemoteConnection
 * @setting_name: the #NMSetting object name to get secrets for
 * @cancellable: a #GCancellable, or %NULL
 * @callback: callback to be called when the secret request completes
 * @user_data: caller-specific data passed to @callback
 *
 * Asynchronously requests the connection's secrets.
 **/
void
nm_remote_connection_get_secrets_async (NMRemoteConnection *connection,
                                        const char *setting_name,
                                        GCancellable *cancellable,
                                        GAsyncReadyCallback callback,
                                        gpointer user_data)
{
	g_return_if_fail (NM_IS_REMOTE_CONNECTION (connection));
	g_return_if_fail (setting_name);
	g_return_if_fail (!cancellable || G_IS_CANCELLABLE (cancellable));

	_nm_client_dbus_call (_nm_object_get_client (connection),
	                      connection,
	                      nm_remote_connection_get_secrets_async,
	                      cancellable,
	                      callback,
	                      user_data,
	                      _nm_object_get_path (connection),
	                      NM_DBUS_INTERFACE_SETTINGS_CONNECTION,
	                      "GetSecrets",
	                      g_variant_new ("(s)", setting_name),
	                      G_VARIANT_TYPE ("(a{sa{sv}})"),
	                      G_DBUS_CALL_FLAGS_NONE,
	                      NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                      nm_dbus_connection_call_finish_variant_strip_dbus_error_cb);
}

/**
 * nm_remote_connection_get_secrets_finish:
 * @connection: the #NMRemoteConnection
 * @result: the result passed to the #GAsyncReadyCallback
 * @error: location for a #GError, or %NULL
 *
 * Gets the result of a call to nm_remote_connection_get_secrets_async().
 *
 * Returns: (transfer full): a #GVariant of type %NM_VARIANT_TYPE_CONNECTION
 *   containing @connection's secrets, or %NULL on error.
 **/
GVariant *
nm_remote_connection_get_secrets_finish (NMRemoteConnection *connection,
                                         GAsyncResult *result,
                                         GError **error)
{
	gs_unref_variant GVariant *ret = NULL;
	GVariant *secrets;

	g_return_val_if_fail (NM_IS_REMOTE_CONNECTION (connection), NULL);
	g_return_val_if_fail (nm_g_task_is_valid (result, connection, nm_remote_connection_get_secrets_async), FALSE);

	ret = g_task_propagate_pointer (G_TASK (result), error);
	if (!ret)
		return NULL;

	g_variant_get (ret,
	               "(@a{sa{sv}})",
	               &secrets);

	return secrets;
}

/**
 * nm_remote_connection_get_unsaved:
 * @connection: the #NMRemoteConnection
 *
 * Returns: %TRUE if the remote connection contains changes that have not
 * been saved to disk, %FALSE if the connection is the same as its on-disk
 * representation.
 **/
gboolean
nm_remote_connection_get_unsaved (NMRemoteConnection *connection)
{
	g_return_val_if_fail (NM_IS_REMOTE_CONNECTION (connection), FALSE);

	return NM_REMOTE_CONNECTION_GET_PRIVATE (connection)->unsaved;
}

/**
 * nm_remote_connection_get_flags:
 * @connection: the #NMRemoteConnection
 *
 * Returns: the flags of the connection of type #NMSettingsConnectionFlags.
 *
 * Since: 1.12
 **/
NMSettingsConnectionFlags
nm_remote_connection_get_flags (NMRemoteConnection *connection)
{
	g_return_val_if_fail (NM_IS_REMOTE_CONNECTION (connection), FALSE);

	return (NMSettingsConnectionFlags) NM_REMOTE_CONNECTION_GET_PRIVATE (connection)->flags;
}

/**
 * nm_remote_connection_get_filename:
 * @connection: the #NMRemoteConnection
 *
 * Returns: file that stores the connection in case the connection is file-backed.
 *
 * Since: 1.12
 **/
const char *
nm_remote_connection_get_filename (NMRemoteConnection *connection)
{
	g_return_val_if_fail (NM_IS_REMOTE_CONNECTION (connection), NULL);

	return NM_REMOTE_CONNECTION_GET_PRIVATE (connection)->filename;
}

/**
 * nm_remote_connection_get_visible:
 * @connection: the #NMRemoteConnection
 *
 * Checks if the connection is visible to the current user.  If the
 * connection is not visible then it is essentially useless; it will
 * not contain any settings, and operations such as
 * nm_remote_connection_save() and nm_remote_connection_delete() will
 * always fail. (#NMRemoteSettings will not normally return
 * non-visible connections to callers, but it is possible for a
 * connection's visibility to change after you already have a
 * reference to it.)
 *
 * Returns: %TRUE if the remote connection is visible to the current
 * user, %FALSE if not.
 **/
gboolean
nm_remote_connection_get_visible (NMRemoteConnection *connection)
{
	g_return_val_if_fail (NM_IS_REMOTE_CONNECTION (connection), FALSE);

	return NM_REMOTE_CONNECTION_GET_PRIVATE (connection)->visible;
}

/*****************************************************************************/

GCancellable *
_nm_remote_settings_get_settings_prepare (NMRemoteConnection *self)
{
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (self);

	nm_clear_g_cancellable (&priv->get_settings_cancellable);
	priv->get_settings_cancellable = g_cancellable_new ();
	return priv->get_settings_cancellable;
}

void
_nm_remote_settings_get_settings_commit (NMRemoteConnection *self,
                                         GVariant *settings)
{
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (self);
	GError *error = NULL;
	gboolean visible = FALSE;
	gboolean changed = FALSE;

	g_clear_object (&priv->get_settings_cancellable);

	if (!priv->is_initialized) {
		changed = TRUE;
		priv->is_initialized = TRUE;
	}

	if (settings) {
		if (!_nm_connection_replace_settings ((NMConnection *) self,
		                                      settings,
		                                      NM_SETTING_PARSE_FLAGS_BEST_EFFORT,
		                                      &error)) {
			NML_NMCLIENT_LOG_E (_nm_object_get_client (self), "[%s] failure to update settings: %s",
			                    _nm_object_get_path (self),
			                    error->message);
			g_clear_error (&error);
		} else
			visible = TRUE;
	} else
		nm_connection_clear_settings (NM_CONNECTION (self));

	if (priv->visible != visible) {
		priv->visible = visible;
		_nm_client_queue_notify_object (_nm_object_get_client (self),
		                                self,
		                                obj_properties[PROP_VISIBLE]);
		changed = TRUE;
	}

	if (changed)
		_nm_client_notify_object_changed (_nm_object_get_client (self), _nm_object_get_dbobj (self));
}

/*****************************************************************************/

static gboolean
is_ready (NMObject *nmobj)
{
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (nmobj);

	if (!priv->is_initialized)
		return FALSE;;

	return NM_OBJECT_CLASS (nm_remote_connection_parent_class)->is_ready (nmobj);
}

/*****************************************************************************/

static void
register_client (NMObject *nmobj,
                 NMClient *client,
                 NMLDBusObject *dbobj)
{
	NM_OBJECT_CLASS (nm_remote_connection_parent_class)->register_client (nmobj, client, dbobj);
	nm_connection_set_path (NM_CONNECTION (nmobj),
	                        dbobj->dbus_path->str);
	_nm_client_get_settings_call (client, dbobj);
}

static void
unregister_client (NMObject *nmobj,
                   NMClient *client,
                   NMLDBusObject *dbobj)
{
	nm_clear_g_cancellable (&NM_REMOTE_CONNECTION_GET_PRIVATE (nmobj)->get_settings_cancellable);
	NM_OBJECT_CLASS (nm_remote_connection_parent_class)->unregister_client (nmobj, client, dbobj);
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case PROP_UNSAVED:
		g_value_set_boolean (value, NM_REMOTE_CONNECTION_GET_PRIVATE (object)->unsaved);
		break;
	case PROP_FLAGS:
		g_value_set_uint (value, NM_REMOTE_CONNECTION_GET_PRIVATE (object)->flags);
		break;
	case PROP_FILENAME:
		g_value_set_string (value, NM_REMOTE_CONNECTION_GET_PRIVATE (object)->filename);
		break;
	case PROP_VISIBLE:
		g_value_set_boolean (value, NM_REMOTE_CONNECTION_GET_PRIVATE (object)->visible);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_remote_connection_init (NMRemoteConnection *self)
{
}

static void
dispose (GObject *object)
{
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (object);

	nm_clear_g_free (&priv->filename);

	G_OBJECT_CLASS (nm_remote_connection_parent_class)->dispose (object);
}

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_settings_connection = NML_DBUS_META_IFACE_INIT_PROP (
	NM_DBUS_INTERFACE_SETTINGS_CONNECTION,
	nm_remote_connection_get_type,
	NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_HIGH,
	NML_DBUS_META_IFACE_DBUS_PROPERTIES (
		NML_DBUS_META_PROPERTY_INIT_S ("Filename", PROP_FILENAME, NMRemoteConnection, _priv.filename ),
		NML_DBUS_META_PROPERTY_INIT_U ("Flags",    PROP_FLAGS,    NMRemoteConnection, _priv.flags    ),
		NML_DBUS_META_PROPERTY_INIT_B ("Unsaved",  PROP_UNSAVED,  NMRemoteConnection, _priv.unsaved  ),
	),
);

static void
nm_remote_connection_class_init (NMRemoteConnectionClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (klass);

	object_class->get_property = get_property;
	object_class->dispose      = dispose;

	nm_object_class->is_ready          = is_ready;
	nm_object_class->register_client   = register_client;
	nm_object_class->unregister_client = unregister_client;

	/**
	 * NMRemoteConnection:unsaved:
	 *
	 * %TRUE if the remote connection contains changes that have not been saved
	 * to disk, %FALSE if the connection is the same as its on-disk representation.
	 **/
	obj_properties[PROP_UNSAVED] =
	    g_param_spec_boolean (NM_REMOTE_CONNECTION_UNSAVED, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMRemoteConnection:flags:
	 *
	 * The flags of the connection as unsigned integer. The values
	 * correspond to the #NMSettingsConnectionFlags enum.
	 *
	 * Since: 1.12
	 **/
	obj_properties[PROP_FLAGS] =
	    g_param_spec_uint (NM_REMOTE_CONNECTION_FLAGS, "", "",
	                       0, G_MAXUINT32, 0,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMRemoteConnection:filename:
	 *
	 * File that stores the connection in case the connection is
	 * file-backed.
	 *
	 * Since: 1.12
	 **/
	obj_properties[PROP_FILENAME] =
	    g_param_spec_string (NM_REMOTE_CONNECTION_FILENAME, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMRemoteConnection:visible:
	 *
	 * %TRUE if the remote connection is visible to the current user, %FALSE if
	 * not.  If the connection is not visible then it is essentially useless; it
	 * will not contain any settings, and operations such as
	 * nm_remote_connection_save() and nm_remote_connection_delete() will always
	 * fail. (#NMRemoteSettings will not normally return non-visible connections
	 * to callers, but it is possible for a connection's visibility to change
	 * after you already have a reference to it.)
	 **/
	obj_properties[PROP_VISIBLE] =
	    g_param_spec_boolean (NM_REMOTE_CONNECTION_VISIBLE, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	_nml_dbus_meta_class_init_with_properties (object_class, &_nml_dbus_meta_iface_nm_settings_connection);
}

static void
nm_remote_connection_connection_iface_init (NMConnectionInterface *iface)
{
}
