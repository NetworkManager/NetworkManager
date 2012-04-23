/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * libnm_glib -- Access network status & information from glib applications
 *
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
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2011 Red Hat, Inc.
 */

#include <string.h>
#include <gio/gio.h>

#include <NetworkManager.h>
#include <nm-utils.h>
#include <nm-setting-connection.h>
#include "nm-remote-connection.h"
#include "nm-remote-connection-private.h"
#include "nm-dbus-glib-types.h"
#include "nm-glib-compat.h"

#define NM_REMOTE_CONNECTION_BUS "bus"

static void nm_remote_connection_initable_iface_init (GInitableIface *iface);
static void nm_remote_connection_async_initable_iface_init (GAsyncInitableIface *iface);

G_DEFINE_TYPE_WITH_CODE (NMRemoteConnection, nm_remote_connection, NM_TYPE_CONNECTION,
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, nm_remote_connection_initable_iface_init);
                         G_IMPLEMENT_INTERFACE (G_TYPE_ASYNC_INITABLE, nm_remote_connection_async_initable_iface_init);
                         )

enum {
	PROP_0,
	PROP_BUS,

	LAST_PROP
};

enum {
	UPDATED,
	REMOVED,
	VISIBLE,

	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };


typedef struct {
	NMRemoteConnection *self;
	DBusGProxyCall *call;
	GFunc callback;
	gpointer user_data;
} RemoteCall;

typedef struct {
	DBusGConnection *bus;
	DBusGProxy *proxy;
	GSList *calls;

	gboolean visible;
} NMRemoteConnectionPrivate;

#define NM_REMOTE_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_REMOTE_CONNECTION, NMRemoteConnectionPrivate))

/****************************************************************/

static void
remote_call_complete (NMRemoteConnection *self, RemoteCall *call)
{
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (self);

	priv->calls = g_slist_remove (priv->calls, call);
	/* Don't need to cancel it since this function should only be called from
	 * the dispose handler (where the proxy will be destroyed immediately after)
	 * or from the call's completion callback.
	 */
	memset (call, 0, sizeof (RemoteCall));
	g_free (call);
}

static void
update_cb (DBusGProxy *proxy, DBusGProxyCall *proxy_call, gpointer user_data)
{
	RemoteCall *call = user_data;
	NMRemoteConnectionCommitFunc func = (NMRemoteConnectionCommitFunc) call->callback;
	GError *error = NULL;

	dbus_g_proxy_end_call (proxy, proxy_call, &error,
	                       G_TYPE_INVALID);
	if (func != NULL)
		(*func)(call->self, error, call->user_data);
	g_clear_error (&error);
	remote_call_complete (call->self, call);
}

/**
 * nm_remote_connection_commit_changes:
 * @connection: the #NMRemoteConnection
 * @callback: (scope async) (allow-none): a function to be called when the
 * commit completes
 * @user_data: (closure): caller-specific data to be passed to @callback
 *
 * Save any local changes to the settings and properties of this connection and
 * save them in the settings service.
 **/
void
nm_remote_connection_commit_changes (NMRemoteConnection *self,
                                     NMRemoteConnectionCommitFunc callback,
                                     gpointer user_data)
{
	NMRemoteConnectionPrivate *priv;
	GHashTable *settings = NULL;
	RemoteCall *call;

	g_return_if_fail (self != NULL);
	g_return_if_fail (NM_IS_REMOTE_CONNECTION (self));
	g_return_if_fail (callback != NULL);

	priv = NM_REMOTE_CONNECTION_GET_PRIVATE (self);

	call = g_malloc0 (sizeof (RemoteCall));
	call->self = self;
	call->callback = (GFunc) callback;
	call->user_data = user_data;

	settings = nm_connection_to_hash (NM_CONNECTION (self), NM_SETTING_HASH_FLAG_ALL);

	call->call = dbus_g_proxy_begin_call (priv->proxy, "Update",
	                                      update_cb, call, NULL,
	                                      DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT, settings,
	                                      G_TYPE_INVALID);
	g_assert (call->call);
	priv->calls = g_slist_append (priv->calls, call);

	g_hash_table_destroy (settings);
}

static void
delete_cb (DBusGProxy *proxy, DBusGProxyCall *proxy_call, gpointer user_data)
{
	RemoteCall *call = user_data;
	NMRemoteConnectionDeleteFunc func = (NMRemoteConnectionDeleteFunc) call->callback;
	GError *error = NULL;

	dbus_g_proxy_end_call (proxy, proxy_call, &error,
	                       G_TYPE_INVALID);
	if (func != NULL)
		(*func)(call->self, error, call->user_data);
	g_clear_error (&error);
	remote_call_complete (call->self, call);
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
                             NMRemoteConnectionDeleteFunc callback,
                             gpointer user_data)
{
	NMRemoteConnectionPrivate *priv;
	RemoteCall *call;

	g_return_if_fail (self != NULL);
	g_return_if_fail (NM_IS_REMOTE_CONNECTION (self));

	priv = NM_REMOTE_CONNECTION_GET_PRIVATE (self);

	call = g_malloc0 (sizeof (RemoteCall));
	call->self = self;
	call->callback = (GFunc) callback;
	call->user_data = user_data;

	call->call = dbus_g_proxy_begin_call (priv->proxy, "Delete",
	                                      delete_cb, call, NULL,
	                                      G_TYPE_INVALID);
	g_assert (call->call);
	priv->calls = g_slist_append (priv->calls, call);
}

static void
get_secrets_cb (DBusGProxy *proxy, DBusGProxyCall *proxy_call, gpointer user_data)
{
	RemoteCall *call = user_data;
	NMRemoteConnectionGetSecretsFunc func = (NMRemoteConnectionGetSecretsFunc) call->callback;
	GHashTable *secrets;
	GError *error = NULL;

	dbus_g_proxy_end_call (proxy, proxy_call, &error,
	                       DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT, &secrets,
	                       G_TYPE_INVALID);
	(*func)(call->self, error ? NULL : secrets, error, call->user_data);
	g_clear_error (&error);
	remote_call_complete (call->self, call);
}

/**
 * nm_remote_connection_get_secrets:
 * @connection: the #NMRemoteConnection
 * @setting_name: the #NMSetting object name to get secrets for
 * @callback: (scope async): a function to be called when the update completes;
 * must not be NULL
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

	g_return_if_fail (self != NULL);
	g_return_if_fail (NM_IS_REMOTE_CONNECTION (self));
	g_return_if_fail (callback != NULL);

	priv = NM_REMOTE_CONNECTION_GET_PRIVATE (self);

	call = g_malloc0 (sizeof (RemoteCall));
	call->self = self;
	call->callback = (GFunc) callback;
	call->user_data = user_data;

	call->call = dbus_g_proxy_begin_call (priv->proxy, "GetSecrets",
	                                      get_secrets_cb, call, NULL,
	                                      G_TYPE_STRING, setting_name,
	                                      G_TYPE_INVALID);
	g_assert (call->call);
	priv->calls = g_slist_append (priv->calls, call);
}

/****************************************************************/

static void
replace_settings (NMRemoteConnection *self, GHashTable *new_settings)
{
	GError *error = NULL;

	if (nm_connection_replace_settings (NM_CONNECTION (self), new_settings, &error))
		g_signal_emit (self, signals[UPDATED], 0, new_settings);
	else {
		g_warning ("%s: error updating connection %s settings: (%d) %s",
		           __func__,
		           nm_connection_get_path (NM_CONNECTION (self)),
		           error ? error->code : -1,
		           (error && error->message) ? error->message : "(unknown)");
		g_clear_error (&error);

		g_signal_emit (self, signals[REMOVED], 0);
	}
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
		nm_connection_replace_settings (NM_CONNECTION (self), hash, NULL);
		g_hash_table_destroy (hash);

		priv->visible = FALSE;
		g_signal_emit (self, signals[VISIBLE], 0, FALSE);
	} else {
		replace_settings (self, new_settings);
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
	dbus_g_proxy_begin_call (priv->proxy, "GetSettings",
	                         updated_get_settings_cb, self, NULL,
	                         G_TYPE_INVALID);
}

static void
removed_cb (DBusGProxy *proxy, gpointer user_data)
{
	g_signal_emit (G_OBJECT (user_data), signals[REMOVED], 0);
}

/****************************************************************/

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
	NMRemoteConnectionPrivate *priv;

	priv = NM_REMOTE_CONNECTION_GET_PRIVATE (object);
	g_assert (priv->bus);
	g_assert (nm_connection_get_path (NM_CONNECTION (object)));

	priv->proxy = dbus_g_proxy_new_for_name (priv->bus,
	                                         NM_DBUS_SERVICE,
	                                         nm_connection_get_path (NM_CONNECTION (object)),
	                                         NM_DBUS_IFACE_SETTINGS_CONNECTION);
	g_assert (priv->proxy);
	dbus_g_proxy_set_default_timeout (priv->proxy, G_MAXINT);

	dbus_g_proxy_add_signal (priv->proxy, "Updated", G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "Updated", G_CALLBACK (updated_cb), object, NULL);

	dbus_g_proxy_add_signal (priv->proxy, "Removed", G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "Removed", G_CALLBACK (removed_cb), object, NULL);
}

static gboolean
init_sync (GInitable *initable, GCancellable *cancellable, GError **error)
{
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (initable);
	GHashTable *settings;

	if (!dbus_g_proxy_call (priv->proxy, "GetSettings", error,
	                        G_TYPE_STRING, NM_DBUS_IFACE_SETTINGS,
	                        G_TYPE_INVALID,
	                        DBUS_TYPE_G_MAP_OF_VARIANT, &settings,
	                        G_TYPE_INVALID))
		return FALSE;

	priv->visible = TRUE;
	replace_settings (NM_REMOTE_CONNECTION (initable), settings);
	g_hash_table_destroy (settings);
	return TRUE;
}

typedef struct {
	NMRemoteConnection *connection;
	GSimpleAsyncResult *result;
} NMRemoteConnectionInitData;

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
		g_simple_async_result_take_error (init_data->result, error);
	} else {
		priv->visible = TRUE;
		replace_settings (init_data->connection, settings);
		g_hash_table_destroy (settings);
		g_simple_async_result_set_op_res_gboolean (init_data->result, TRUE);
	}

	g_simple_async_result_complete (init_data->result);
	g_slice_free (NMRemoteConnectionInitData, init_data);
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

	dbus_g_proxy_begin_call (priv->proxy, "GetSettings",
	                         init_get_settings_cb, init_data, NULL,
	                         G_TYPE_INVALID);

}

static void
nm_remote_connection_init (NMRemoteConnection *self)
{
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_BUS:
		/* Construct only */
		priv->bus = dbus_g_connection_ref ((DBusGConnection *) g_value_get_boxed (value));
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
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (object);

	while (g_slist_length (priv->calls))
		remote_call_complete (self, priv->calls->data);

	g_clear_object (&priv->proxy);

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
	object_class->set_property = set_property;
	object_class->dispose = dispose;
	object_class->constructed = constructed;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_BUS,
		 g_param_spec_boxed (NM_REMOTE_CONNECTION_BUS,
						 "DBusGConnection",
						 "DBusGConnection",
						 DBUS_TYPE_G_CONNECTION,
						 G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY));

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
}
