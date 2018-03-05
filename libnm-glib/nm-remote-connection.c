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

#include "NetworkManager.h"
#include "nm-utils.h"
#include "nm-setting-connection.h"
#include "nm-remote-connection.h"
#include "nm-remote-connection-private.h"
#include "nm-object-private.h"
#include "nm-dbus-glib-types.h"
#include "nm-dbus-helpers-private.h"
#include "nm-setting-private.h"

#define NM_REMOTE_CONNECTION_BUS "bus"
#define NM_REMOTE_CONNECTION_DBUS_CONNECTION "dbus-connection"
#define NM_REMOTE_CONNECTION_DBUS_PATH "dbus-path"

static void nm_remote_connection_initable_iface_init (GInitableIface *iface);
static void nm_remote_connection_async_initable_iface_init (GAsyncInitableIface *iface);

G_DEFINE_TYPE_WITH_CODE (NMRemoteConnection, nm_remote_connection, NM_TYPE_CONNECTION,
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, nm_remote_connection_initable_iface_init);
                         G_IMPLEMENT_INTERFACE (G_TYPE_ASYNC_INITABLE, nm_remote_connection_async_initable_iface_init);
                         )

enum {
	PROP_0,
	PROP_BUS,
	PROP_DBUS_CONNECTION,
	PROP_DBUS_PATH,
	PROP_UNSAVED,

	LAST_PROP
};

enum {
	UPDATED,
	REMOVED,
	VISIBLE,

	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };

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
	DBusGConnection *bus;
	DBusGProxy *proxy;
	DBusGProxy *props_proxy;
	gboolean proxy_is_destroyed;
	GSList *calls;

	gboolean inited;
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

/*****************************************************************************/

static void
_nm_remote_connection_ensure_inited (NMRemoteConnection *self)
{
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (self);
	GError *error = NULL;

	if (!priv->inited) {
		if (!g_initable_init (G_INITABLE (self), NULL, &error)) {
			/* Don't warn when the call times out because the settings service can't
			 * be activated or whatever.
			 */
			if (!g_error_matches (error, DBUS_GERROR, DBUS_GERROR_NO_REPLY)) {
				g_warning ("%s: (NMRemoteConnection) error initializing: %s\n",
				           __func__, error->message);
			}
			g_error_free (error);
		}
		priv->inited = TRUE;
	}
}

/*****************************************************************************/

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

/*****************************************************************************/

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
	GHashTable *settings;

	g_return_if_fail (NM_IS_REMOTE_CONNECTION (self));

	priv = NM_REMOTE_CONNECTION_GET_PRIVATE (self);

	call = remote_call_new (self, result_cb, (GFunc) callback, user_data);
	if (!call)
		return;

	settings = nm_connection_to_hash (NM_CONNECTION (self), NM_SETTING_HASH_FLAG_ALL);
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
 *
 * Since: 0.9.10
 **/
void
nm_remote_connection_commit_changes_unsaved (NMRemoteConnection *connection,
                                             NMRemoteConnectionResultFunc callback,
                                             gpointer user_data)
{
	NMRemoteConnectionPrivate *priv;
	GHashTable *settings = NULL;
	RemoteCall *call;

	g_return_if_fail (NM_IS_REMOTE_CONNECTION (connection));

	priv = NM_REMOTE_CONNECTION_GET_PRIVATE (connection);

	call = remote_call_new (connection, result_cb, (GFunc) callback, user_data);
	if (!call)
		return;

	settings = nm_connection_to_hash (NM_CONNECTION (connection), NM_SETTING_HASH_FLAG_ALL);
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
 *
 * Since: 0.9.10
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
	if (func)
		(*func) (call->self, error ? NULL : secrets, error, call->user_data);
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
 *
 * Since: 0.9.10
 **/
gboolean
nm_remote_connection_get_unsaved (NMRemoteConnection *connection)
{
	g_return_val_if_fail (NM_IS_REMOTE_CONNECTION (connection), FALSE);

	_nm_remote_connection_ensure_inited (connection);
	return NM_REMOTE_CONNECTION_GET_PRIVATE (connection)->unsaved;
}

/*****************************************************************************/

static void
updated_get_settings_cb (DBusGProxy *proxy,
                         DBusGProxyCall *call,
                         gpointer user_data)
{
	NMRemoteConnection *self = user_data;
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (self);
	GHashTable *new_settings;
	GError *error = NULL;

	dbus_g_proxy_end_call (proxy, call, &error,
	                       DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT, &new_settings,
	                       G_TYPE_INVALID);
	if (error) {
		GHashTable *hash;

		g_error_free (error);

		/* Connection is no longer visible to this user.  Let the settings
		 * service handle this via 'visible'.  The settings service will emit
		 * the "removed" signal for us since it handles the lifetime of this
		 * object.
		 */
		hash = g_hash_table_new (g_str_hash, g_str_equal);
		_nm_connection_replace_settings (NM_CONNECTION (self), hash);
		g_hash_table_destroy (hash);

		priv->visible = FALSE;
		g_signal_emit (self, signals[VISIBLE], 0, FALSE);
	} else {
		gs_unref_object NMRemoteConnection *self_alive = NULL;

		self_alive = g_object_ref (self);
		_nm_connection_replace_settings (NM_CONNECTION (self), new_settings);
		g_signal_emit (self, signals[UPDATED], 0, new_settings);
		g_hash_table_destroy (new_settings);

		/* Settings service will handle announcing the connection to clients */
		if (priv->visible == FALSE) {
			priv->visible = TRUE;
			g_signal_emit (self, signals[VISIBLE], 0, TRUE);
		}
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

static void
removed_cb (DBusGProxy *proxy, gpointer user_data)
{
	g_signal_emit (G_OBJECT (user_data), signals[REMOVED], 0);
}

static void
properties_changed_cb (DBusGProxy *proxy,
                       GHashTable *properties,
                       gpointer user_data)
{
	NMRemoteConnection *self = NM_REMOTE_CONNECTION (user_data);
	GHashTableIter iter;
	const char *key;
	GValue *value;

	g_hash_table_iter_init (&iter, properties);
	while (g_hash_table_iter_next (&iter, (gpointer) &key, (gpointer) &value)) {
		if (!strcmp (key, "Unsaved")) {
			NM_REMOTE_CONNECTION_GET_PRIVATE (self)->unsaved = g_value_get_boolean (value);
			g_object_notify (G_OBJECT (self), NM_REMOTE_CONNECTION_UNSAVED);
		}
	}
}

/*****************************************************************************/

/**
 * nm_remote_connection_new:
 * @bus: a valid and connected D-Bus connection
 * @path: the D-Bus path of the connection as exported by the settings service
 *
 * Creates a new object representing the remote connection.
 *
 * Returns: the new remote connection object on success, or %NULL on failure
 **/
NMRemoteConnection *
nm_remote_connection_new (DBusGConnection *bus,
                          const char *path)
{
	g_return_val_if_fail (bus != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);

	return (NMRemoteConnection *) g_object_new (NM_TYPE_REMOTE_CONNECTION,
	                                            NM_REMOTE_CONNECTION_BUS, bus,
	                                            NM_CONNECTION_PATH, path,
	                                            NULL);
}

static void
constructed (GObject *object)
{
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (object);

	G_OBJECT_CLASS (nm_remote_connection_parent_class)->constructed (object);

	g_assert (priv->bus);
	g_assert (nm_connection_get_path (NM_CONNECTION (object)));

	priv->proxy = _nm_dbus_new_proxy_for_connection (priv->bus,
	                                                 nm_connection_get_path (NM_CONNECTION (object)),
	                                                 NM_DBUS_IFACE_SETTINGS_CONNECTION);
	g_assert (priv->proxy);
	dbus_g_proxy_set_default_timeout (priv->proxy, G_MAXINT);

	dbus_g_proxy_add_signal (priv->proxy, "Updated", G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "Updated", G_CALLBACK (updated_cb), object, NULL);

	dbus_g_proxy_add_signal (priv->proxy, "Removed", G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "Removed", G_CALLBACK (removed_cb), object, NULL);

	g_signal_connect (priv->proxy, "destroy", G_CALLBACK (proxy_destroy_cb), object);

	/* Monitor properties */
	dbus_g_object_register_marshaller (g_cclosure_marshal_VOID__BOXED,
	                                   G_TYPE_NONE,
	                                   DBUS_TYPE_G_MAP_OF_VARIANT,
	                                   G_TYPE_INVALID);
	dbus_g_proxy_add_signal (priv->proxy, "PropertiesChanged",
	                         DBUS_TYPE_G_MAP_OF_VARIANT,
	                         G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "PropertiesChanged",
	                             G_CALLBACK (properties_changed_cb),
	                             object,
	                             NULL);

	priv->props_proxy = _nm_dbus_new_proxy_for_connection (priv->bus,
	                                                       nm_connection_get_path (NM_CONNECTION (object)),
	                                                       DBUS_INTERFACE_PROPERTIES);
	g_assert (priv->props_proxy);
}

static gboolean
init_sync (GInitable *initable, GCancellable *cancellable, GError **error)
{
	NMRemoteConnection *self = NM_REMOTE_CONNECTION (initable);
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (self);
	GHashTable *hash;
	gs_unref_object NMRemoteConnection *self_alive = NULL;

	if (!dbus_g_proxy_call (priv->proxy, "GetSettings", error,
	                        G_TYPE_INVALID,
	                        DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT, &hash,
	                        G_TYPE_INVALID))
		return FALSE;
	priv->visible = TRUE;
	self_alive = g_object_ref (self);
	_nm_connection_replace_settings (NM_CONNECTION (self), hash);
	g_signal_emit (self, signals[UPDATED], 0, hash);
	g_hash_table_destroy (hash);

	/* Get properties */
	hash = NULL;
	if (!dbus_g_proxy_call (priv->props_proxy, "GetAll", error,
	                        G_TYPE_STRING, NM_DBUS_IFACE_SETTINGS_CONNECTION,
	                        G_TYPE_INVALID,
	                        DBUS_TYPE_G_MAP_OF_VARIANT, &hash,
	                        G_TYPE_INVALID))
		return FALSE;
	properties_changed_cb (priv->props_proxy, hash, NM_REMOTE_CONNECTION (initable));
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
	else {
		g_simple_async_result_set_op_res_gboolean (init_data->result, TRUE);
		NM_REMOTE_CONNECTION_GET_PRIVATE (init_data->connection)->inited = TRUE;
	}

	g_simple_async_result_complete (init_data->result);
	g_object_unref (init_data->result);
	g_slice_free (NMRemoteConnectionInitData, init_data);
}

static void
init_async_got_properties (DBusGProxy *proxy, DBusGProxyCall *call, gpointer user_data)
{
	NMRemoteConnectionInitData *init_data = user_data;
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (init_data->connection);
	GHashTable *props;
	GError *error = NULL;

	if (dbus_g_proxy_end_call (proxy, call, &error,
	                           DBUS_TYPE_G_MAP_OF_VARIANT, &props,
	                           G_TYPE_INVALID)) {
		properties_changed_cb (priv->props_proxy, props, init_data->connection);
		g_hash_table_destroy (props);
	}
	init_async_complete (init_data, error);
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
	gs_unref_object NMRemoteConnection *self_alive = NULL;

	dbus_g_proxy_end_call (proxy, call, &error,
	                       DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT, &settings,
	                       G_TYPE_INVALID);
	if (error) {
		init_async_complete (init_data, error);
		return;
	}

	priv->visible = TRUE;
	self_alive = g_object_ref (init_data->connection);
	_nm_connection_replace_settings (NM_CONNECTION (init_data->connection), settings);
	g_signal_emit (init_data->connection, signals[UPDATED], 0, settings);
	g_hash_table_destroy (settings);

	/* Grab properties */
	dbus_g_proxy_begin_call (priv->props_proxy, "GetAll",
	                         init_async_got_properties, init_data, NULL,
	                         G_TYPE_STRING, NM_DBUS_IFACE_SETTINGS_CONNECTION,
	                         G_TYPE_INVALID);
}

static void
init_async (GAsyncInitable *initable, int io_priority,
            GCancellable *cancellable, GAsyncReadyCallback callback,
            gpointer user_data)
{
	NMRemoteConnectionInitData *init_data;
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (initable);


	init_data = g_slice_new0 (NMRemoteConnectionInitData);
	init_data->connection = NM_REMOTE_CONNECTION (initable);
	init_data->result = g_simple_async_result_new (G_OBJECT (initable), callback,
	                                               user_data, init_async);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (init_data->result, cancellable);

	dbus_g_proxy_begin_call (priv->proxy, "GetSettings",
	                         init_get_settings_cb, init_data, NULL,
	                         G_TYPE_INVALID);
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

static GObject *
constructor (GType type, guint n_construct_properties,
             GObjectConstructParam *construct_properties)
{
	static GParamSpec *nm_connection_path = NULL;
	static GParamSpec *nm_remote_connection_dbus_path = NULL;
	int i, path_index = -1, dbus_path_index = -1;

	if (!nm_connection_path) {
		nm_connection_path =
			g_object_class_find_property (g_type_class_peek (NM_TYPE_CONNECTION),
			                              NM_CONNECTION_PATH);
		nm_remote_connection_dbus_path =
			g_object_class_find_property (g_type_class_peek (NM_TYPE_REMOTE_CONNECTION),
			                              NM_REMOTE_CONNECTION_DBUS_PATH);
	}

	/* Find the two properties */
	for (i = 0; i < n_construct_properties; i++) {
		if (construct_properties[i].pspec == nm_connection_path)
			path_index = i;
		else if (construct_properties[i].pspec == nm_remote_connection_dbus_path)
			dbus_path_index = i;
	}
	g_assert (path_index != -1 && dbus_path_index != -1);

	/* If NMRemoteConnection:dbus-path is set, and NMConnection:path
	 * is not, then copy the value of the former to the latter.
	 */
	if (g_value_get_string (construct_properties[dbus_path_index].value) &&
	    !g_value_get_string (construct_properties[path_index].value))
		construct_properties[path_index].value = construct_properties[dbus_path_index].value;

	return G_OBJECT_CLASS (nm_remote_connection_parent_class)->
		constructor (type, n_construct_properties, construct_properties);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	_nm_remote_connection_ensure_inited (NM_REMOTE_CONNECTION (object));

	switch (prop_id) {
	case PROP_UNSAVED:
		g_value_set_boolean (value, NM_REMOTE_CONNECTION_GET_PRIVATE (object)->unsaved);
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
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_BUS:
	case PROP_DBUS_CONNECTION:
		/* construct-only */
		/* priv->bus is set from either of two properties so that it (a) remains
		 * backwards compatible with the previous "bus" property, and that (b)
		 * it can be created just like an NMObject using the "dbus-connection",
		 * even though it's not a subclass of NMObject.  So don't overwrite the
		 * a valid value that the other property set with NULL, if one of the
		 * properties isn't specified at construction time.
		 */
		if (!priv->bus)
			priv->bus = g_value_dup_boxed (value);
		break;
	case PROP_DBUS_PATH:
		/* Don't need to do anything; see constructor(). */
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
dispose (GObject *object)
{
	NMRemoteConnection *self = NM_REMOTE_CONNECTION (object);
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (self);

	proxy_set_destroyed (self);

	if (priv->proxy) {
		g_signal_handlers_disconnect_by_func (priv->proxy, proxy_destroy_cb, object);
		g_clear_object (&priv->proxy);
	}
	g_clear_object (&priv->props_proxy);

	if (priv->bus) {
		dbus_g_connection_unref (priv->bus);
		priv->bus = NULL;
	}

	G_OBJECT_CLASS (nm_remote_connection_parent_class)->dispose (object);
}

static void
nm_remote_connection_class_init (NMRemoteConnectionClass *remote_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (remote_class);

	g_type_class_add_private (object_class, sizeof (NMRemoteConnectionPrivate));

	/* virtual methods */
	object_class->constructor = constructor;
	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->dispose = dispose;
	object_class->constructed = constructed;

	/* Properties */
	/**
	 * NMRemoteConnection:bus:
	 *
	 * The #DBusGConnection that the #NMRemoteConnection is connected to.
	 */
	g_object_class_install_property
		(object_class, PROP_BUS,
		 g_param_spec_boxed (NM_REMOTE_CONNECTION_BUS, "", "",
		                     DBUS_TYPE_G_CONNECTION,
		                     G_PARAM_WRITABLE |
		                     G_PARAM_CONSTRUCT_ONLY |
		                     G_PARAM_STATIC_STRINGS));

	/* These are needed so _nm_object_create() can create NMRemoteConnections */
	g_object_class_install_property
		(object_class, PROP_DBUS_CONNECTION,
		 g_param_spec_boxed (NM_REMOTE_CONNECTION_DBUS_CONNECTION, "", "",
		                     DBUS_TYPE_G_CONNECTION,
		                     G_PARAM_WRITABLE |
		                     G_PARAM_CONSTRUCT_ONLY |
		                     G_PARAM_STATIC_STRINGS));
	g_object_class_install_property
		(object_class, PROP_DBUS_PATH,
		 g_param_spec_string (NM_REMOTE_CONNECTION_DBUS_PATH, "", "",
		                      NULL,
		                      G_PARAM_WRITABLE |
		                      G_PARAM_CONSTRUCT_ONLY |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMRemoteConnection:unsaved:
	 *
	 * %TRUE if the remote connection contains changes that have not been saved
	 * to disk, %FALSE if the connection is the same as its on-disk representation.
	 *
	 * Since: 0.9.10
	 **/
	g_object_class_install_property
		(object_class, PROP_UNSAVED,
		 g_param_spec_boolean (NM_REMOTE_CONNECTION_UNSAVED, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/* Signals */
	/**
	 * NMRemoteConnection::updated:
	 * @connection: a #NMConnection
	 *
	 * This signal is emitted when a connection changes, and it is
	 * still visible to the user.
	 */
	signals[UPDATED] =
		g_signal_new (NM_REMOTE_CONNECTION_UPDATED,
		              G_TYPE_FROM_CLASS (remote_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMRemoteConnectionClass, updated),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__VOID,
		              G_TYPE_NONE, 0);

	/**
	 * NMRemoteConnection::removed:
	 * @connection: a #NMConnection
	 *
	 * This signal is emitted when a connection is either deleted or becomes
	 * invisible to the current user.
	 */
	signals[REMOVED] =
		g_signal_new (NM_REMOTE_CONNECTION_REMOVED,
		              G_TYPE_FROM_CLASS (remote_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMRemoteConnectionClass, removed),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__VOID,
		              G_TYPE_NONE, 0);

	/* Private signal */
	signals[VISIBLE] =
		g_signal_new ("visible",
		              G_TYPE_FROM_CLASS (remote_class),
		              G_SIGNAL_RUN_FIRST,
		              0, NULL, NULL,
		              g_cclosure_marshal_VOID__BOOLEAN,
		              G_TYPE_NONE, 1, G_TYPE_BOOLEAN);
}

static void
nm_remote_connection_initable_iface_init (GInitableIface *iface)
{
	iface->init = init_sync;
}

static void
nm_remote_connection_async_initable_iface_init (GAsyncInitableIface *iface)
{
	iface->init_async = init_async;
	iface->init_finish = init_finish;
}
