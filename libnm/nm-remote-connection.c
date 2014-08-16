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

#include <string.h>
#include <gio/gio.h>
#include <glib/gi18n.h>

#include <nm-dbus-interface.h>
#include <nm-utils.h>
#include <nm-setting-connection.h>
#include "nm-remote-connection.h"
#include "nm-remote-connection-private.h"
#include "nm-object-private.h"
#include "nm-dbus-glib-types.h"
#include "nm-glib-compat.h"
#include "nm-dbus-helpers.h"
#include "nm-utils-private.h"

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

typedef struct RemoteCall RemoteCall;
typedef void (*RemoteCallFetchResultCb) (RemoteCall *call, DBusGProxyCall *proxy_call, GError *error);


struct RemoteCall {
	NMRemoteConnection *self;
	DBusGProxyCall *call;
	RemoteCallFetchResultCb fetch_result_cb;
	GFunc callback;
	gpointer user_data;
};

typedef struct {
	DBusGProxy *proxy;
	gboolean proxy_is_destroyed;
	GSList *calls;

	gboolean unsaved;

	gboolean visible;
} NMRemoteConnectionPrivate;

#define NM_REMOTE_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_REMOTE_CONNECTION, NMRemoteConnectionPrivate))

/**
 * nm_remote_connection_error_quark:
 *
 * Registers an error quark for #NMRemoteConnection if necessary.
 *
 * Returns: the error quark used for #NMRemoteConnection errors.
 **/
GQuark
nm_remote_connection_error_quark (void)
{
	static GQuark quark = 0;

	if (G_UNLIKELY (quark == 0))
		quark = g_quark_from_static_string ("nm-remote-connection-error-quark");
	return quark;
}

/****************************************************************/

static void
remote_call_dbus_cb (DBusGProxy *proxy, DBusGProxyCall *proxy_call, gpointer user_data)
{
	RemoteCall *call = user_data;
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (call->self);
	GError *error = NULL;

	g_assert ( (!proxy && !proxy_call &&  priv->proxy_is_destroyed) ||
	           ( proxy &&  proxy_call && !priv->proxy_is_destroyed && proxy == priv->proxy) );

	if (priv->proxy_is_destroyed) {
		error = g_error_new_literal (NM_REMOTE_CONNECTION_ERROR,
		                             NM_REMOTE_CONNECTION_ERROR_DISCONNECTED,
		                             _("Disconnected by D-Bus"));
	}
	call->fetch_result_cb (call, proxy_call, error);
	g_clear_error (&error);

	priv->calls = g_slist_remove (priv->calls, call);
	g_object_unref (call->self);
	g_free (call);
}

static gboolean
remote_call_cleanup_cb (void *user_data)
{
	remote_call_dbus_cb (NULL, NULL, user_data);
	return G_SOURCE_REMOVE;
}

static RemoteCall *
remote_call_new (NMRemoteConnection *self,
                 RemoteCallFetchResultCb fetch_result_cb,
                 GFunc callback,
                 gpointer user_data)
{
	RemoteCall *call;
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (self);

	g_assert (fetch_result_cb);

	if (priv->proxy_is_destroyed && !callback)
		return NULL;

	call = g_malloc0 (sizeof (RemoteCall));
	call->self = g_object_ref (self);
	call->fetch_result_cb = fetch_result_cb;
	call->user_data = user_data;
	call->callback = callback;

	if (priv->proxy_is_destroyed) {
		g_idle_add (remote_call_cleanup_cb, call);
		return NULL;
	}
	priv->calls = g_slist_prepend (priv->calls, call);
	return call;
}

static void
proxy_set_destroyed (NMRemoteConnection *self)
{
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (self);

	if (priv->proxy_is_destroyed) {
		g_assert (!priv->calls);
		return;
	}

	priv->proxy_is_destroyed = TRUE;

	priv->calls = g_slist_reverse (priv->calls);
	while (priv->calls)
		remote_call_dbus_cb (NULL, NULL, priv->calls->data);
}

static void
proxy_destroy_cb (DBusGProxy* proxy, gpointer user_data) {
	proxy_set_destroyed (user_data);
}

/****************************************************************/

static void
result_cb (RemoteCall *call, DBusGProxyCall *proxy_call, GError *error)
{
	NMRemoteConnectionResultFunc func = (NMRemoteConnectionResultFunc) call->callback;
	GError *local_error = NULL;

	if (!error) {
		dbus_g_proxy_end_call (NM_REMOTE_CONNECTION_GET_PRIVATE (call->self)->proxy,
		                       proxy_call, &local_error, G_TYPE_INVALID);
		error = local_error;
	}
	if (func)
		(*func) (call->self, error, call->user_data);
	g_clear_error (&local_error);
}

/**
 * nm_remote_connection_commit_changes:
 * @connection: the #NMRemoteConnection
 * @callback: (scope async) (allow-none): a function to be called when the
 * commit completes
 * @user_data: (closure): caller-specific data to be passed to @callback
 *
 * Send any local changes to the settings and properties of this connection to
 * NetworkManager, which will immediately save them to disk.
 **/
void
nm_remote_connection_commit_changes (NMRemoteConnection *self,
                                     NMRemoteConnectionResultFunc callback,
                                     gpointer user_data)
{
	NMRemoteConnectionPrivate *priv;
	RemoteCall *call;
	GVariant *settings_dict;
	GHashTable *settings;

	g_return_if_fail (NM_IS_REMOTE_CONNECTION (self));

	priv = NM_REMOTE_CONNECTION_GET_PRIVATE (self);

	call = remote_call_new (self, result_cb, (GFunc) callback, user_data);
	if (!call)
		return;

	settings_dict = nm_connection_to_dbus (NM_CONNECTION (self), NM_CONNECTION_SERIALIZE_ALL);
	settings = _nm_utils_connection_dict_to_hash (settings_dict);
	g_variant_unref (settings_dict);

	call->call = dbus_g_proxy_begin_call (priv->proxy, "Update",
	                                      remote_call_dbus_cb, call, NULL,
	                                      DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT, settings,
	                                      G_TYPE_INVALID);
	g_assert (call->call);
	g_hash_table_destroy (settings);
}

/**
 * nm_remote_connection_commit_changes_unsaved:
 * @connection: the #NMRemoteConnection
 * @callback: (scope async) (allow-none): a function to be called when the
 * commit completes
 * @user_data: (closure): caller-specific data to be passed to @callback
 *
 * Send any local changes to the settings and properties of this connection to
 * NetworkManager.  The changes are not saved to disk until either
 * nm_remote_connection_save() or nm_remote_connection_commit_changes() is
 * called.
 **/
void
nm_remote_connection_commit_changes_unsaved (NMRemoteConnection *connection,
                                             NMRemoteConnectionResultFunc callback,
                                             gpointer user_data)
{
	NMRemoteConnectionPrivate *priv;
	GVariant *settings_dict;
	GHashTable *settings;
	RemoteCall *call;

	g_return_if_fail (NM_IS_REMOTE_CONNECTION (connection));

	priv = NM_REMOTE_CONNECTION_GET_PRIVATE (connection);

	call = remote_call_new (connection, result_cb, (GFunc) callback, user_data);
	if (!call)
		return;

	settings_dict = nm_connection_to_dbus (NM_CONNECTION (connection), NM_CONNECTION_SERIALIZE_ALL);
	settings = _nm_utils_connection_dict_to_hash (settings_dict);
	g_variant_unref (settings_dict);
	call->call = dbus_g_proxy_begin_call (priv->proxy, "UpdateUnsaved",
	                                      remote_call_dbus_cb, call, NULL,
	                                      DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT, settings,
	                                      G_TYPE_INVALID);
	g_assert (call->call);
	g_hash_table_destroy (settings);
}

/**
 * nm_remote_connection_save:
 * @connection: the #NMRemoteConnection
 * @callback: (scope async) (allow-none): a function to be called when the
 * save completes
 * @user_data: (closure): caller-specific data to be passed to @callback
 *
 * Saves the connection to disk if the connection has changes that have not yet
 * been written to disk, or if the connection has never been saved.
 **/
void
nm_remote_connection_save (NMRemoteConnection *connection,
                           NMRemoteConnectionResultFunc callback,
                           gpointer user_data)
{
	NMRemoteConnectionPrivate *priv;
	RemoteCall *call;

	g_return_if_fail (NM_IS_REMOTE_CONNECTION (connection));

	priv = NM_REMOTE_CONNECTION_GET_PRIVATE (connection);

	call = remote_call_new (connection, result_cb, (GFunc) callback, user_data);
	if (!call)
		return;

	call->call = dbus_g_proxy_begin_call (priv->proxy, "Save", remote_call_dbus_cb, call, NULL, G_TYPE_INVALID);
	g_assert (call->call);
}

/**
 * nm_remote_connection_delete:
 * @connection: the #NMRemoteConnection
 * @callback: (scope async) (allow-none): a function to be called when the delete completes
 * @user_data: (closure): caller-specific data to be passed to @callback
 *
 * Delete the connection.
 **/
void
nm_remote_connection_delete (NMRemoteConnection *self,
                             NMRemoteConnectionResultFunc callback,
                             gpointer user_data)
{
	NMRemoteConnectionPrivate *priv;
	RemoteCall *call;

	g_return_if_fail (NM_IS_REMOTE_CONNECTION (self));

	priv = NM_REMOTE_CONNECTION_GET_PRIVATE (self);

	call = remote_call_new (self, result_cb, (GFunc) callback, user_data);
	if (!call)
		return;

	call->call = dbus_g_proxy_begin_call (priv->proxy, "Delete",
	                                      remote_call_dbus_cb, call, NULL,
	                                      G_TYPE_INVALID);
	g_assert (call->call);
}

static void
get_secrets_cb (RemoteCall *call, DBusGProxyCall *proxy_call, GError *error)
{
	NMRemoteConnectionGetSecretsFunc func = (NMRemoteConnectionGetSecretsFunc) call->callback;
	GHashTable *secrets = NULL;
	GError *local_error = NULL;

	if (!error) {
		dbus_g_proxy_end_call (NM_REMOTE_CONNECTION_GET_PRIVATE (call->self)->proxy,
		                       proxy_call, &local_error,
		                       DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT, &secrets,
		                       G_TYPE_INVALID);
		error = local_error;
	}
	if (func) {
		GVariant *secrets_dict;

		if (secrets)
			secrets_dict = _nm_utils_connection_hash_to_dict (secrets);
		else
			secrets_dict = NULL;

		(*func) (call->self, error ? NULL : secrets_dict, error, call->user_data);

		if (secrets_dict)
			g_variant_unref (secrets_dict);
	}
	g_clear_error (&local_error);
	if (secrets)
		g_hash_table_destroy (secrets);
}


/**
 * nm_remote_connection_get_secrets:
 * @connection: the #NMRemoteConnection
 * @setting_name: the #NMSetting object name to get secrets for
 * @callback: (scope async): a function to be called when the update completes;
 * must not be %NULL
 * @user_data: (closure): caller-specific data to be passed to @callback
 *
 * Request the connection's secrets.
 **/
void
nm_remote_connection_get_secrets (NMRemoteConnection *self,
                                  const char *setting_name,
                                  NMRemoteConnectionGetSecretsFunc callback,
                                  gpointer user_data)
{
	NMRemoteConnectionPrivate *priv;
	RemoteCall *call;

	g_return_if_fail (NM_IS_REMOTE_CONNECTION (self));
	g_return_if_fail (callback != NULL);

	priv = NM_REMOTE_CONNECTION_GET_PRIVATE (self);

	call = remote_call_new (self, get_secrets_cb, (GFunc) callback, user_data);
	if (!call)
		return;

	call->call = dbus_g_proxy_begin_call (priv->proxy, "GetSecrets",
	                                      remote_call_dbus_cb, call, NULL,
	                                      G_TYPE_STRING, setting_name,
	                                      G_TYPE_INVALID);
	g_assert (call->call);
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
replace_settings (NMRemoteConnection *self, GHashTable *new_settings)
{
	GError *error = NULL;
	GVariant *new_settings_dict;

	new_settings_dict = _nm_utils_connection_hash_to_dict (new_settings);
	if (!nm_connection_replace_settings (NM_CONNECTION (self), new_settings_dict, &error)) {
		g_warning ("%s: error updating connection %s settings: (%d) %s",
		           __func__,
		           nm_connection_get_path (NM_CONNECTION (self)),
		           error ? error->code : -1,
		           (error && error->message) ? error->message : "(unknown)");
		g_clear_error (&error);
	}
	g_variant_unref (new_settings_dict);
}

static void
updated_get_settings_cb (DBusGProxy *proxy,
                         DBusGProxyCall *call,
                         gpointer user_data)
{
	NMRemoteConnection *self = user_data;
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (self);
	GHashTable *new_settings;
	GError *error = NULL;
	gboolean visible;

	dbus_g_proxy_end_call (proxy, call, &error,
	                       DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT, &new_settings,
	                       G_TYPE_INVALID);
	if (error) {
		g_error_free (error);

		/* Connection is no longer visible to this user. */
		nm_connection_clear_settings (NM_CONNECTION (self));

		visible = FALSE;
	} else {
		replace_settings (self, new_settings);
		g_hash_table_destroy (new_settings);

		visible = TRUE;
	}

	if (visible != priv->visible) {
		priv->visible = visible;
		g_object_notify (G_OBJECT (self), NM_REMOTE_CONNECTION_VISIBLE);
	}
}

static void
updated_cb (DBusGProxy *proxy, gpointer user_data)
{
	NMRemoteConnection *self = NM_REMOTE_CONNECTION (user_data);
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (self);

	/* The connection got updated; request the replacement settings */
	if (!priv->proxy_is_destroyed) {
		dbus_g_proxy_begin_call (priv->proxy, "GetSettings",
		                         updated_get_settings_cb, self, NULL,
		                         G_TYPE_INVALID);
	}
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

	priv->proxy = _nm_object_get_proxy (object, NM_DBUS_INTERFACE_SETTINGS_CONNECTION);
	g_assert (priv->proxy);
	dbus_g_proxy_set_default_timeout (priv->proxy, G_MAXINT);

	_nm_object_register_properties (object,
	                                NM_DBUS_INTERFACE_SETTINGS_CONNECTION,
	                                property_info);

	dbus_g_proxy_add_signal (priv->proxy, "Updated", G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "Updated", G_CALLBACK (updated_cb), object, NULL);

	g_signal_connect (priv->proxy, "destroy", G_CALLBACK (proxy_destroy_cb), object);
}

static gboolean
init_sync (GInitable *initable, GCancellable *cancellable, GError **error)
{
	NMRemoteConnection *self = NM_REMOTE_CONNECTION (initable);
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (initable);
	GHashTable *hash;

	if (!nm_remote_connection_parent_initable_iface->init (initable, cancellable, error))
		return FALSE;

	if (!dbus_g_proxy_call (priv->proxy, "GetSettings", error,
	                        G_TYPE_INVALID,
	                        DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT, &hash,
	                        G_TYPE_INVALID))
		return FALSE;
	priv->visible = TRUE;
	replace_settings (self, hash);
	g_hash_table_destroy (hash);

	return TRUE;
}

typedef struct {
	NMRemoteConnection *connection;
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
	g_slice_free (NMRemoteConnectionInitData, init_data);
}

static void
init_get_settings_cb (DBusGProxy *proxy,
                      DBusGProxyCall *call,
                      gpointer user_data)
{
	NMRemoteConnectionInitData *init_data = user_data;
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (init_data->connection);
	GHashTable *settings;
	GError *error = NULL;

	dbus_g_proxy_end_call (proxy, call, &error,
	                       DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT, &settings,
	                       G_TYPE_INVALID);
	if (error) {
		init_async_complete (init_data, error);
		return;
	}

	priv->visible = TRUE;
	replace_settings (init_data->connection, settings);
	g_hash_table_destroy (settings);

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

	dbus_g_proxy_begin_call (priv->proxy, "GetSettings",
	                         init_get_settings_cb, init_data, NULL,
	                         G_TYPE_INVALID);
}

static void
init_async (GAsyncInitable *initable, int io_priority,
            GCancellable *cancellable, GAsyncReadyCallback callback,
            gpointer user_data)
{
	NMRemoteConnectionInitData *init_data;

	init_data = g_slice_new0 (NMRemoteConnectionInitData);
	init_data->connection = NM_REMOTE_CONNECTION (initable);
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
dispose (GObject *object)
{
	NMRemoteConnection *self = NM_REMOTE_CONNECTION (object);
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (self);

	proxy_set_destroyed (self);

	if (priv->proxy) {
		g_signal_handlers_disconnect_by_func (priv->proxy, proxy_destroy_cb, object);
		priv->proxy = NULL;
	}

	G_OBJECT_CLASS (nm_remote_connection_parent_class)->dispose (object);
}

static void
nm_remote_connection_class_init (NMRemoteConnectionClass *remote_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (remote_class);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (remote_class);

	g_type_class_add_private (object_class, sizeof (NMRemoteConnectionPrivate));

	_nm_object_class_add_interface (nm_object_class, NM_DBUS_INTERFACE_SETTINGS_CONNECTION);

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
