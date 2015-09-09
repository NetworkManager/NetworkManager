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

#include "config.h"

#include <string.h>

#include <nm-dbus-interface.h>
#include <nm-utils.h>
#include <nm-setting-connection.h>
#include "nm-default.h"
#include "nm-remote-connection.h"
#include "nm-remote-connection-private.h"
#include "nm-object-private.h"
#include "nm-dbus-helpers.h"

#include "nmdbus-settings-connection.h"

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
	PROP_VISIBLE,

	LAST_PROP
};

typedef struct {
	NMDBusSettingsConnection *proxy;

	gboolean unsaved;

	gboolean visible;
} NMRemoteConnectionPrivate;

#define NM_REMOTE_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_REMOTE_CONNECTION, NMRemoteConnectionPrivate))

/****************************************************************/

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
	GVariant *settings;
	gboolean ret;

	g_return_val_if_fail (NM_IS_REMOTE_CONNECTION (connection), FALSE);

	priv = NM_REMOTE_CONNECTION_GET_PRIVATE (connection);

	settings = nm_connection_to_dbus (NM_CONNECTION (connection), NM_CONNECTION_SERIALIZE_ALL);
	if (save_to_disk) {
		ret = nmdbus_settings_connection_call_update_sync (priv->proxy,
		                                                   settings,
		                                                   cancellable, error);
	} else {
		ret = nmdbus_settings_connection_call_update_unsaved_sync (priv->proxy,
		                                                           settings,
		                                                           cancellable, error);
	}
	if (error && *error)
		g_dbus_error_strip_remote_error (*error);
	return ret;
}

static void
update_cb (GObject *proxy, GAsyncResult *result, gpointer user_data)
{
	GSimpleAsyncResult *simple = user_data;
	gboolean (*finish_func) (NMDBusSettingsConnection *, GAsyncResult *, GError **);
	GError *error = NULL;

	finish_func = g_object_get_data (G_OBJECT (simple), "finish_func");
	if (finish_func (NMDBUS_SETTINGS_CONNECTION (proxy), result, &error))
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
	GVariant *settings;

	g_return_if_fail (NM_IS_REMOTE_CONNECTION (connection));

	priv = NM_REMOTE_CONNECTION_GET_PRIVATE (connection);

	simple = g_simple_async_result_new (G_OBJECT (connection), callback, user_data,
	                                    nm_remote_connection_commit_changes_async);

	settings = nm_connection_to_dbus (NM_CONNECTION (connection), NM_CONNECTION_SERIALIZE_ALL);
	if (save_to_disk) {
		g_object_set_data (G_OBJECT (simple), "finish_func",
		                   nmdbus_settings_connection_call_update_finish);
		nmdbus_settings_connection_call_update (priv->proxy,
		                                        settings,
		                                        cancellable,
		                                        update_cb, simple);
	} else {
		g_object_set_data (G_OBJECT (simple), "finish_func",
		                   nmdbus_settings_connection_call_update_unsaved_finish);
		nmdbus_settings_connection_call_update_unsaved (priv->proxy,
		                                                settings,
		                                                cancellable,
		                                                update_cb, simple);
	}
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

/****************************************************************/

static void
replace_settings (NMRemoteConnection *self, GVariant *new_settings)
{
	GError *error = NULL;

	if (!nm_connection_replace_settings (NM_CONNECTION (self), new_settings, &error)) {
		g_warning ("%s: error updating connection %s settings: (%d) %s",
		           __func__,
		           nm_connection_get_path (NM_CONNECTION (self)),
		           error ? error->code : -1,
		           (error && error->message) ? error->message : "(unknown)");
		g_clear_error (&error);
	}
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

/****************************************************************/

static void
init_dbus (NMObject *object)
{
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (object);
	const NMPropertiesInfo property_info[] = {
		{ NM_REMOTE_CONNECTION_UNSAVED, &priv->unsaved },
		{ NULL },
	};

	NM_OBJECT_CLASS (nm_remote_connection_parent_class)->init_dbus (object);

	priv->proxy = NMDBUS_SETTINGS_CONNECTION (_nm_object_get_proxy (object, NM_DBUS_INTERFACE_SETTINGS_CONNECTION));
	g_assert (priv->proxy);

	_nm_object_register_properties (object,
	                                NM_DBUS_INTERFACE_SETTINGS_CONNECTION,
	                                property_info);

	g_signal_connect (priv->proxy, "updated",
	                  G_CALLBACK (updated_cb), object);
}

static gboolean
init_sync (GInitable *initable, GCancellable *cancellable, GError **error)
{
	NMRemoteConnection *self = NM_REMOTE_CONNECTION (initable);
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (initable);
	GVariant *settings;

	if (!nm_remote_connection_parent_initable_iface->init (initable, cancellable, error))
		return FALSE;

	if (!nmdbus_settings_connection_call_get_settings_sync (priv->proxy,
	                                                        &settings,
	                                                        cancellable, error)) {
		if (error && *error)
			g_dbus_error_strip_remote_error (*error);
		return FALSE;
	}

	priv->visible = TRUE;
	replace_settings (self, settings);
	g_variant_unref (settings);

	return TRUE;
}

typedef struct {
	NMRemoteConnection *connection;
	GCancellable *cancellable;
	GSimpleAsyncResult *result;
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
init_get_settings_cb (GObject *proxy,
                      GAsyncResult *result,
                      gpointer user_data)
{
	NMRemoteConnectionInitData *init_data = user_data;
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (init_data->connection);
	GVariant *settings;
	GError *error = NULL;

	if (!nmdbus_settings_connection_call_get_settings_finish (priv->proxy, &settings,
	                                                          result, &error)) {
		g_dbus_error_strip_remote_error (error);
		init_async_complete (init_data, error);
		return;
	}

	priv->visible = TRUE;
	replace_settings (init_data->connection, settings);
	g_variant_unref (settings);
	g_object_notify (init_data->connection, NM_REMOTE_CONNECTION_VISIBLE);

	init_async_complete (init_data, NULL);
}

static void
init_async_parent_inited (GObject *source, GAsyncResult *result, gpointer user_data)
{
	NMRemoteConnectionInitData *init_data = user_data;
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (init_data->connection);
	GError *error = NULL;

	if (!nm_remote_connection_parent_async_initable_iface->init_finish (G_ASYNC_INITABLE (source), result, &error)) {
		init_async_complete (init_data, error);
		return;
	}

	nmdbus_settings_connection_call_get_settings (priv->proxy,
	                                              init_data->cancellable,
	                                              init_get_settings_cb, init_data);
}

static void
init_async (GAsyncInitable *initable, int io_priority,
            GCancellable *cancellable, GAsyncReadyCallback callback,
            gpointer user_data)
{
	NMRemoteConnectionInitData *init_data;

	init_data = g_slice_new0 (NMRemoteConnectionInitData);
	init_data->connection = NM_REMOTE_CONNECTION (initable);
	init_data->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	init_data->result = g_simple_async_result_new (G_OBJECT (initable), callback,
	                                               user_data, init_async);

	nm_remote_connection_parent_async_initable_iface->
		init_async (initable, io_priority, cancellable, init_async_parent_inited, init_data);
}

static gboolean
init_finish (GAsyncInitable *initable, GAsyncResult *result, GError **error)
{
	GSimpleAsyncResult *simple = G_SIMPLE_ASYNC_RESULT (result);

	if (g_simple_async_result_propagate_error (simple, error))
		return FALSE;
	else
		return TRUE;
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
	nm_connection_set_path (NM_CONNECTION (object),
	                        nm_object_get_path (NM_OBJECT (object)));
}

static void
nm_remote_connection_class_init (NMRemoteConnectionClass *remote_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (remote_class);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (remote_class);

	g_type_class_add_private (object_class, sizeof (NMRemoteConnectionPrivate));

	_nm_object_class_add_interface (nm_object_class, NM_DBUS_INTERFACE_SETTINGS_CONNECTION);
	_nm_dbus_register_proxy_type (NM_DBUS_INTERFACE_SETTINGS_CONNECTION,
	                              NMDBUS_TYPE_SETTINGS_CONNECTION_PROXY);

	/* virtual methods */
	object_class->constructed = constructed;
	object_class->get_property = get_property;

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
	iface->init_finish = init_finish;
}
