/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2007 - 2008 Novell, Inc.
 * Copyright 2007 - 2011 Red Hat, Inc.
 */

#include "nm-default.h"

#include <string.h>

#include "nm-dbus-interface.h"
#include "nm-utils.h"
#include "nm-setting-connection.h"
#include "nm-core-internal.h"

#include "nm-remote-connection.h"
#include "nm-remote-connection-private.h"
#include "nm-object-private.h"
#include "nm-dbus-helpers.h"

#include "introspection/org.freedesktop.NetworkManager.Settings.Connection.h"

/**
 * SECTION:nm-remote-connection
 * @short_description: A connection managed by NetworkManager server
 *
 * A #NMRemoteConnection represents a connection that is exported via
 * NetworkManager D-Bus interface.
 **/

static void nm_remote_connection_connection_iface_init (NMConnectionInterface *iface);
static void nm_remote_connection_initable_iface_init (GInitableIface *iface);
static void nm_remote_connection_async_initable_iface_init (GAsyncInitableIface *iface);
static GInitableIface *nm_remote_connection_parent_initable_iface;
static GAsyncInitableIface *nm_remote_connection_parent_async_initable_iface;

G_DEFINE_TYPE_WITH_CODE (NMRemoteConnection, nm_remote_connection, NM_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (NM_TYPE_CONNECTION, nm_remote_connection_connection_iface_init);
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, nm_remote_connection_initable_iface_init);
                         G_IMPLEMENT_INTERFACE (G_TYPE_ASYNC_INITABLE, nm_remote_connection_async_initable_iface_init);
                         )

enum {
	PROP_0,
	PROP_UNSAVED,
	PROP_FLAGS,
	PROP_FILENAME,
	PROP_VISIBLE,

	LAST_PROP
};

typedef struct {
	NMDBusSettingsConnection *proxy;

	gboolean unsaved;
	guint32 flags;
	char *filename;

	gboolean visible;
} NMRemoteConnectionPrivate;

#define NM_REMOTE_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_REMOTE_CONNECTION, NMRemoteConnectionPrivate))

/*****************************************************************************/

static void
update2_cb (GObject *proxy, GAsyncResult *result, gpointer user_data)
{
	GSimpleAsyncResult *simple = user_data;
	GError *error = NULL;
	GVariant *v;

	if (nmdbus_settings_connection_call_update2_finish (NMDBUS_SETTINGS_CONNECTION (proxy),
	                                                    &v,
	                                                    result,
	                                                    &error))
		g_simple_async_result_set_op_res_gpointer (simple,
		                                           v,
		                                           (GDestroyNotify) g_variant_unref);
	else {
		g_dbus_error_strip_remote_error (error);
		g_simple_async_result_take_error (simple, error);
	}
	g_simple_async_result_complete (simple);
	g_object_unref (simple);
}

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
	NMRemoteConnectionPrivate *priv;
	GSimpleAsyncResult *simple;
	GVariantBuilder builder;

	g_return_if_fail (NM_IS_REMOTE_CONNECTION (connection));
	g_return_if_fail (!settings || g_variant_is_of_type (settings, NM_VARIANT_TYPE_CONNECTION));
	g_return_if_fail (!args || g_variant_is_of_type (args, G_VARIANT_TYPE ("a{sv}")));
	g_return_if_fail (!cancellable || G_IS_CANCELLABLE (cancellable));

	priv = NM_REMOTE_CONNECTION_GET_PRIVATE (connection);

	simple = g_simple_async_result_new (G_OBJECT (connection), callback, user_data,
	                                    nm_remote_connection_update2);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (simple, cancellable);

	if (!settings) {
		g_variant_builder_init (&builder, NM_VARIANT_TYPE_CONNECTION);
		settings = g_variant_builder_end (&builder);
	}
	if (!args) {
		g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{sv}"));
		args = g_variant_builder_end (&builder);
	}
	nmdbus_settings_connection_call_update2 (priv->proxy,
	                                         settings,
	                                         flags,
	                                         args,
	                                         cancellable,
	                                         update2_cb,
	                                         simple);
}

/**
 * nm_remote_connection_update2_finish:
 * @connection: the #NMRemoteConnection
 * @result: the result passed to the #GAsyncReadyCallback
 * @error: location for a #GError, or %NULL
 *
 * Gets the result of a call to nm_remote_connection_commit_changes_async().
 *
 * Returns: on success, a #GVariant of type "a{sv}" with the result. On failure,
 *   %NULL.
 **/
GVariant *
nm_remote_connection_update2_finish (NMRemoteConnection *connection,
                                     GAsyncResult *result,
                                     GError **error)
{
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (connection), nm_remote_connection_update2), FALSE);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return NULL;
	else
		return g_variant_ref (g_simple_async_result_get_op_res_gpointer (simple));
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
 **/
gboolean
nm_remote_connection_commit_changes (NMRemoteConnection *connection,
                                     gboolean save_to_disk,
                                     GCancellable *cancellable,
                                     GError **error)
{
	NMRemoteConnectionPrivate *priv;
	gs_unref_variant GVariant *result = NULL;
	gboolean ret;
	GVariantBuilder args;

	g_return_val_if_fail (NM_IS_REMOTE_CONNECTION (connection), FALSE);

	priv = NM_REMOTE_CONNECTION_GET_PRIVATE (connection);

	g_variant_builder_init (&args, G_VARIANT_TYPE ("a{sv}"));
	ret = nmdbus_settings_connection_call_update2_sync (priv->proxy,
	                                                    nm_connection_to_dbus (NM_CONNECTION (connection),
	                                                                           NM_CONNECTION_SERIALIZE_ALL),
	                                                    save_to_disk
	                                                      ? NM_SETTINGS_UPDATE2_FLAG_TO_DISK
	                                                      : NM_SETTINGS_UPDATE2_FLAG_IN_MEMORY,
	                                                    g_variant_builder_end (&args),
	                                                    &result,
	                                                    cancellable,
	                                                    error);
	if (error && *error)
		g_dbus_error_strip_remote_error (*error);
	return ret;
}

static void
update_cb (GObject *proxy, GAsyncResult *result, gpointer user_data)
{
	GSimpleAsyncResult *simple = user_data;
	GError *error = NULL;
	gs_unref_variant GVariant *v = NULL;

	if (nmdbus_settings_connection_call_update2_finish (NMDBUS_SETTINGS_CONNECTION (proxy),
	                                                    &v,
	                                                    result,
	                                                    &error))
		g_simple_async_result_set_op_res_gboolean (simple, TRUE);
	else {
		g_dbus_error_strip_remote_error (error);
		g_simple_async_result_take_error (simple, error);
	}
	g_simple_async_result_complete (simple);
	g_object_unref (simple);
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
	NMRemoteConnectionPrivate *priv;
	GSimpleAsyncResult *simple;
	GVariantBuilder args;

	g_return_if_fail (NM_IS_REMOTE_CONNECTION (connection));

	priv = NM_REMOTE_CONNECTION_GET_PRIVATE (connection);

	simple = g_simple_async_result_new (G_OBJECT (connection), callback, user_data,
	                                    nm_remote_connection_commit_changes_async);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (simple, cancellable);

	g_variant_builder_init (&args, G_VARIANT_TYPE ("a{sv}"));
	nmdbus_settings_connection_call_update2 (priv->proxy,
	                                         nm_connection_to_dbus (NM_CONNECTION (connection),
	                                                                NM_CONNECTION_SERIALIZE_ALL),
	                                         save_to_disk
	                                           ? NM_SETTINGS_UPDATE2_FLAG_TO_DISK
	                                           : NM_SETTINGS_UPDATE2_FLAG_IN_MEMORY,
	                                         g_variant_builder_end (&args),
	                                         cancellable,
	                                         update_cb,
	                                         simple);
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
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (connection), nm_remote_connection_commit_changes_async), FALSE);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return FALSE;
	else
		return g_simple_async_result_get_op_res_gboolean (simple);
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
 **/
gboolean
nm_remote_connection_save (NMRemoteConnection *connection,
                           GCancellable *cancellable,
                           GError **error)
{
	NMRemoteConnectionPrivate *priv;
	gboolean ret;

	g_return_val_if_fail (NM_IS_REMOTE_CONNECTION (connection), FALSE);

	priv = NM_REMOTE_CONNECTION_GET_PRIVATE (connection);

	ret = nmdbus_settings_connection_call_save_sync (priv->proxy, cancellable, error);
	if (error && *error)
		g_dbus_error_strip_remote_error (*error);
	return ret;
}

static void
save_cb (GObject *proxy, GAsyncResult *result, gpointer user_data)
{
	GSimpleAsyncResult *simple = user_data;
	GError *error = NULL;

	if (nmdbus_settings_connection_call_save_finish (NMDBUS_SETTINGS_CONNECTION (proxy),
	                                                 result, &error))
		g_simple_async_result_set_op_res_gboolean (simple, TRUE);
	else {
		g_dbus_error_strip_remote_error (error);
		g_simple_async_result_take_error (simple, error);
	}
	g_simple_async_result_complete (simple);
	g_object_unref (simple);
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
	NMRemoteConnectionPrivate *priv;
	GSimpleAsyncResult *simple;

	g_return_if_fail (NM_IS_REMOTE_CONNECTION (connection));

	priv = NM_REMOTE_CONNECTION_GET_PRIVATE (connection);

	simple = g_simple_async_result_new (G_OBJECT (connection), callback, user_data,
	                                    nm_remote_connection_save_async);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (simple, cancellable);
	nmdbus_settings_connection_call_save (priv->proxy, cancellable, save_cb, simple);
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
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (connection), nm_remote_connection_save_async), FALSE);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return FALSE;
	else
		return g_simple_async_result_get_op_res_gboolean (simple);
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
 **/
gboolean
nm_remote_connection_delete (NMRemoteConnection *connection,
                             GCancellable *cancellable,
                             GError **error)
{
	NMRemoteConnectionPrivate *priv;
	gboolean ret;

	g_return_val_if_fail (NM_IS_REMOTE_CONNECTION (connection), FALSE);

	priv = NM_REMOTE_CONNECTION_GET_PRIVATE (connection);

	ret = nmdbus_settings_connection_call_delete_sync (priv->proxy, cancellable, error);
	if (error && *error)
		g_dbus_error_strip_remote_error (*error);
	return ret;
}

static void
delete_cb (GObject *proxy, GAsyncResult *result, gpointer user_data)
{
	GSimpleAsyncResult *simple = user_data;
	GError *error = NULL;

	if (nmdbus_settings_connection_call_delete_finish (NMDBUS_SETTINGS_CONNECTION (proxy),
	                                                   result, &error))
		g_simple_async_result_set_op_res_gboolean (simple, TRUE);
	else {
		g_dbus_error_strip_remote_error (error);
		g_simple_async_result_take_error (simple, error);
	}
	g_simple_async_result_complete (simple);
	g_object_unref (simple);
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
	NMRemoteConnectionPrivate *priv;
	GSimpleAsyncResult *simple;

	g_return_if_fail (NM_IS_REMOTE_CONNECTION (connection));

	priv = NM_REMOTE_CONNECTION_GET_PRIVATE (connection);

	simple = g_simple_async_result_new (G_OBJECT (connection), callback, user_data,
	                                    nm_remote_connection_delete_async);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (simple, cancellable);
	nmdbus_settings_connection_call_delete (priv->proxy, cancellable, delete_cb, simple);
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
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (connection), nm_remote_connection_delete_async), FALSE);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return FALSE;
	else
		return g_simple_async_result_get_op_res_gboolean (simple);
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
 * Returns: a #GVariant of type %NM_VARIANT_TYPE_CONNECTION containing
 * @connection's secrets, or %NULL on error.
 **/
GVariant *
nm_remote_connection_get_secrets (NMRemoteConnection *connection,
                                  const char *setting_name,
                                  GCancellable *cancellable,
                                  GError **error)
{
	NMRemoteConnectionPrivate *priv;
	GVariant *secrets;

	g_return_val_if_fail (NM_IS_REMOTE_CONNECTION (connection), NULL);

	priv = NM_REMOTE_CONNECTION_GET_PRIVATE (connection);

	if (nmdbus_settings_connection_call_get_secrets_sync (priv->proxy,
	                                                      setting_name,
	                                                      &secrets,
	                                                      cancellable, error))
		return secrets;
	else {
		if (error && *error)
			g_dbus_error_strip_remote_error (*error);
		return NULL;
	}
}

static void
get_secrets_cb (GObject *proxy, GAsyncResult *result, gpointer user_data)
{
	GSimpleAsyncResult *simple = user_data;
	GVariant *secrets = NULL;
	GError *error = NULL;

	if (nmdbus_settings_connection_call_get_secrets_finish (NMDBUS_SETTINGS_CONNECTION (proxy),
	                                                        &secrets, result, &error))
		g_simple_async_result_set_op_res_gpointer (simple, secrets, (GDestroyNotify) g_variant_unref);
	else {
		g_dbus_error_strip_remote_error (error);
		g_simple_async_result_take_error (simple, error);
	}

	g_simple_async_result_complete (simple);
	g_object_unref (simple);
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
	NMRemoteConnectionPrivate *priv;
	GSimpleAsyncResult *simple;

	g_return_if_fail (NM_IS_REMOTE_CONNECTION (connection));

	priv = NM_REMOTE_CONNECTION_GET_PRIVATE (connection);

	simple = g_simple_async_result_new (G_OBJECT (connection), callback, user_data,
	                                    nm_remote_connection_get_secrets_async);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (simple, cancellable);

	nmdbus_settings_connection_call_get_secrets (priv->proxy,
	                                             setting_name,
	                                             cancellable,
	                                             get_secrets_cb, simple);
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
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (connection), nm_remote_connection_get_secrets_async), FALSE);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return NULL;
	else
		return g_variant_ref (g_simple_async_result_get_op_res_gpointer (simple));
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

static void
replace_settings (NMRemoteConnection *self, GVariant *new_settings)
{
	GError *error = NULL;

	if (!_nm_connection_replace_settings ((NMConnection *) self,
	                                      new_settings,
	                                      NM_SETTING_PARSE_FLAGS_BEST_EFFORT,
	                                      &error))
		g_clear_error (&error);
}

static void
updated_get_settings_cb (GObject *proxy,
                         GAsyncResult *result,
                         gpointer user_data)
{
	NMRemoteConnection *self = user_data;
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (self);
	GVariant *new_settings;
	gboolean visible;

	if (!nmdbus_settings_connection_call_get_settings_finish (priv->proxy, &new_settings,
	                                                          result, NULL)) {
		/* Connection is no longer visible to this user. */
		nm_connection_clear_settings (NM_CONNECTION (self));

		visible = FALSE;
	} else {
		replace_settings (self, new_settings);
		g_variant_unref (new_settings);

		visible = TRUE;
	}

	if (visible != priv->visible) {
		priv->visible = visible;
		g_object_notify (G_OBJECT (self), NM_REMOTE_CONNECTION_VISIBLE);
	}

	g_object_unref (self);
}

static void
updated_cb (NMDBusSettingsConnection *proxy, gpointer user_data)
{
	NMRemoteConnection *self = NM_REMOTE_CONNECTION (user_data);
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (self);

	/* The connection got updated; request the replacement settings */
	nmdbus_settings_connection_call_get_settings (priv->proxy,
	                                              NULL,
	                                              updated_get_settings_cb,
	                                              g_object_ref (self));
}

/*****************************************************************************/

static void
init_dbus (NMObject *object)
{
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (object);
	const NMPropertiesInfo property_info[] = {
		{ NM_REMOTE_CONNECTION_UNSAVED, &priv->unsaved },
		{ NM_REMOTE_CONNECTION_FLAGS, &priv->flags },
		{ NM_REMOTE_CONNECTION_FILENAME, &priv->filename },
		{ NULL },
	};

	NM_OBJECT_CLASS (nm_remote_connection_parent_class)->init_dbus (object);

	_nm_object_register_properties (object,
	                                NM_DBUS_INTERFACE_SETTINGS_CONNECTION,
	                                property_info);
}

static gboolean
init_sync (GInitable *initable, GCancellable *cancellable, GError **error)
{
	NMRemoteConnection *self = NM_REMOTE_CONNECTION (initable);
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (initable);
	GVariant *settings;

	priv->proxy = NMDBUS_SETTINGS_CONNECTION (_nm_object_get_proxy (NM_OBJECT (initable), NM_DBUS_INTERFACE_SETTINGS_CONNECTION));
	g_signal_connect_object (priv->proxy, "updated", G_CALLBACK (updated_cb), initable, 0);

	if (nmdbus_settings_connection_call_get_settings_sync (priv->proxy,
	                                                       &settings,
	                                                       cancellable,
	                                                       NULL)) {
		priv->visible = TRUE;
		replace_settings (self, settings);
		g_variant_unref (settings);
	}

	if (!nm_remote_connection_parent_initable_iface->init (initable, cancellable, error))
		return FALSE;

	return TRUE;
}

typedef struct {
	NMRemoteConnection *connection;
	GCancellable *cancellable;
	GSimpleAsyncResult *result;
	GAsyncInitable *initable;
	int io_priority;
} NMRemoteConnectionInitData;

static void
init_async_complete (NMRemoteConnectionInitData *init_data, GError *error)
{
	if (error)
		g_simple_async_result_take_error (init_data->result, error);
	else
		g_simple_async_result_set_op_res_gboolean (init_data->result, TRUE);

	g_simple_async_result_complete (init_data->result);
	g_object_unref (init_data->result);
	g_clear_object (&init_data->cancellable);
	g_slice_free (NMRemoteConnectionInitData, init_data);
}

static void
init_async_parent_inited (GObject *source, GAsyncResult *result, gpointer user_data)
{
	NMRemoteConnectionInitData *init_data = user_data;
	GError *error = NULL;

	init_async_complete (init_data, error);
}

static void
init_get_settings_cb (GObject *proxy,
                      GAsyncResult *result,
                      gpointer user_data)
{
	NMRemoteConnectionInitData *init_data = user_data;
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (init_data->initable);
	GVariant *settings;
	GError *error = NULL;

	if (!nmdbus_settings_connection_call_get_settings_finish (priv->proxy, &settings,
	                                                          result, &error)) {
		g_error_free (error);
	} else {
		priv->visible = TRUE;
		replace_settings (NM_REMOTE_CONNECTION (init_data->initable), settings);
		g_variant_unref (settings);
	}

	nm_remote_connection_parent_async_initable_iface->
		init_async (init_data->initable, init_data->io_priority, init_data->cancellable, init_async_parent_inited, init_data);
}

static void
init_async (GAsyncInitable *initable, int io_priority,
            GCancellable *cancellable, GAsyncReadyCallback callback,
            gpointer user_data)
{
	NMRemoteConnectionInitData *init_data;
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (initable);

	init_data = g_slice_new0 (NMRemoteConnectionInitData);
	init_data->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	init_data->result = g_simple_async_result_new (G_OBJECT (initable), callback,
	                                               user_data, init_async);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (init_data->result, cancellable);
	init_data->initable = initable;
	init_data->io_priority = io_priority;

	priv->proxy = NMDBUS_SETTINGS_CONNECTION (_nm_object_get_proxy (NM_OBJECT (initable),
	                                          NM_DBUS_INTERFACE_SETTINGS_CONNECTION));

	g_signal_connect_object (priv->proxy, "updated",
	                         G_CALLBACK (updated_cb), initable, 0);

	nmdbus_settings_connection_call_get_settings (NM_REMOTE_CONNECTION_GET_PRIVATE (init_data->initable)->proxy,
	                                              init_data->cancellable,
	                                              init_get_settings_cb, init_data);
}

static void
nm_remote_connection_init (NMRemoteConnection *self)
{
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case PROP_UNSAVED:
		g_value_set_boolean (value, NM_REMOTE_CONNECTION_GET_PRIVATE (object)->unsaved);
		break;
	case PROP_FLAGS:
		g_value_set_boolean (value, NM_REMOTE_CONNECTION_GET_PRIVATE (object)->flags);
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

static void
constructed (GObject *object)
{
	G_OBJECT_CLASS (nm_remote_connection_parent_class)->constructed (object);

	nm_connection_set_path (NM_CONNECTION (object),
	                        nm_object_get_path (NM_OBJECT (object)));
}

static void
dispose (GObject *object)
{
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (object);

	g_clear_object (&priv->proxy);
	nm_clear_g_free (&priv->filename);

	G_OBJECT_CLASS (nm_remote_connection_parent_class)->dispose (object);
}

static void
nm_remote_connection_class_init (NMRemoteConnectionClass *remote_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (remote_class);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (remote_class);

	g_type_class_add_private (object_class, sizeof (NMRemoteConnectionPrivate));

	/* virtual methods */
	object_class->constructed = constructed;
	object_class->get_property = get_property;
	object_class->dispose = dispose;

	nm_object_class->init_dbus = init_dbus;

	/* Properties */
	/**
	 * NMRemoteConnection:unsaved:
	 *
	 * %TRUE if the remote connection contains changes that have not been saved
	 * to disk, %FALSE if the connection is the same as its on-disk representation.
	 **/
	g_object_class_install_property
		(object_class, PROP_UNSAVED,
		 g_param_spec_boolean (NM_REMOTE_CONNECTION_UNSAVED, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMRemoteConnection:flags:
	 *
	 * The flags of the connection as unsigned integer. The values
	 * correspond to the #NMSettingsConnectionFlags enum.
	 *
	 * Since: 1.12
	 **/
	g_object_class_install_property
		(object_class, PROP_FLAGS,
		 g_param_spec_uint (NM_REMOTE_CONNECTION_FLAGS, "", "",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMRemoteConnection:filename:
	 *
	 * File that stores the connection in case the connection is
	 * file-backed.
	 *
	 * Since: 1.12
	 **/
	g_object_class_install_property
	        (object_class, PROP_FILENAME,
	         g_param_spec_string (NM_REMOTE_CONNECTION_FILENAME, "", "",
	                              NULL,
	                              G_PARAM_READABLE |
	                              G_PARAM_STATIC_STRINGS));

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
	g_object_class_install_property
		(object_class, PROP_VISIBLE,
		 g_param_spec_boolean (NM_REMOTE_CONNECTION_VISIBLE, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));
}

static void
nm_remote_connection_connection_iface_init (NMConnectionInterface *iface)
{
}

static void
nm_remote_connection_initable_iface_init (GInitableIface *iface)
{
	nm_remote_connection_parent_initable_iface = g_type_interface_peek_parent (iface);

	iface->init = init_sync;
}

static void
nm_remote_connection_async_initable_iface_init (GAsyncInitableIface *iface)
{
	nm_remote_connection_parent_async_initable_iface = g_type_interface_peek_parent (iface);

	iface->init_async = init_async;
}
