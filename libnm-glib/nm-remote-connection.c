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
 * Copyright (C) 2007 - 2010 Red Hat, Inc.
 */

#include <string.h>

#include <NetworkManager.h>
#include <nm-utils.h>
#include <nm-setting-connection.h>
#include "nm-remote-connection.h"
#include "nm-remote-connection-private.h"
#include "nm-dbus-glib-types.h"
#include "nm-exported-connection-bindings.h"
#include "nm-settings-connection-interface.h"

#define NM_REMOTE_CONNECTION_BUS "bus"

static void settings_connection_interface_init (NMSettingsConnectionInterface *klass);

G_DEFINE_TYPE_EXTENDED (NMRemoteConnection, nm_remote_connection, NM_TYPE_CONNECTION, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_SETTINGS_CONNECTION_INTERFACE, settings_connection_interface_init))

enum {
	PROP_0,
	PROP_BUS,
	PROP_INIT_RESULT,

	LAST_PROP
};


typedef struct {
	NMRemoteConnection *self;
	DBusGProxy *proxy;
	DBusGProxyCall *call;
	GFunc callback;
	gpointer user_data;
} RemoteCall;

typedef struct {
	DBusGConnection *bus;
	DBusGProxy *proxy;
	DBusGProxy *secrets_proxy;
	GSList *calls;

	NMRemoteConnectionInitResult init_result;
	gboolean disposed;
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
update_cb (DBusGProxy *proxy, GError *error, gpointer user_data)
{
	RemoteCall *call = user_data;
	NMSettingsConnectionInterfaceUpdateFunc func = (NMSettingsConnectionInterfaceUpdateFunc) call->callback;

	(*func)(NM_SETTINGS_CONNECTION_INTERFACE (call->self), error, call->user_data);
	remote_call_complete (call->self, call);
}

static gboolean
update (NMSettingsConnectionInterface *connection,
        NMSettingsConnectionInterfaceUpdateFunc callback,
        gpointer user_data)
{
	NMRemoteConnection *self = NM_REMOTE_CONNECTION (connection);
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (self);
	GHashTable *settings = NULL;
	RemoteCall *call;

	call = g_malloc0 (sizeof (RemoteCall));
	call->self = self;
	call->callback = (GFunc) callback;
	call->user_data = user_data;
	call->proxy = priv->proxy;

	settings = nm_connection_to_hash (NM_CONNECTION (self));

	call->call = org_freedesktop_NetworkManagerSettings_Connection_update_async (priv->proxy,
	                                                                             settings,
	                                                                             update_cb,
	                                                                             call);
	g_assert (call->call);
	priv->calls = g_slist_append (priv->calls, call);

	g_hash_table_destroy (settings);

	return TRUE;
}

static void
delete_cb (DBusGProxy *proxy, GError *error, gpointer user_data)
{
	RemoteCall *call = user_data;
	NMSettingsConnectionInterfaceDeleteFunc func = (NMSettingsConnectionInterfaceDeleteFunc) call->callback;

	(*func)(NM_SETTINGS_CONNECTION_INTERFACE (call->self), error, call->user_data);
	remote_call_complete (call->self, call);
}

static gboolean
do_delete (NMSettingsConnectionInterface *connection,
           NMSettingsConnectionInterfaceDeleteFunc callback,
           gpointer user_data)
{
	NMRemoteConnection *self = NM_REMOTE_CONNECTION (connection);
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (self);
	RemoteCall *call;

	call = g_malloc0 (sizeof (RemoteCall));
	call->self = self;
	call->callback = (GFunc) callback;
	call->user_data = user_data;
	call->proxy = priv->proxy;

	call->call = org_freedesktop_NetworkManagerSettings_Connection_delete_async (priv->proxy,
	                                                                             delete_cb,
	                                                                             call);
	g_assert (call->call);
	priv->calls = g_slist_append (priv->calls, call);

	return TRUE;
}

static void
get_secrets_cb (DBusGProxy *proxy, GHashTable *secrets, GError *error, gpointer user_data)
{
	RemoteCall *call = user_data;
	NMSettingsConnectionInterfaceGetSecretsFunc func = (NMSettingsConnectionInterfaceGetSecretsFunc) call->callback;

	(*func)(NM_SETTINGS_CONNECTION_INTERFACE (call->self), error ? NULL : secrets, error, call->user_data);
	remote_call_complete (call->self, call);
}

static gboolean
get_secrets (NMSettingsConnectionInterface *connection,
             const char *setting_name,
             const char **hints,
             gboolean request_new,
             NMSettingsConnectionInterfaceGetSecretsFunc callback,
             gpointer user_data)
{
	NMRemoteConnection *self = NM_REMOTE_CONNECTION (connection);
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (self);
	RemoteCall *call;

	call = g_malloc0 (sizeof (RemoteCall));
	call->self = self;
	call->callback = (GFunc) callback;
	call->user_data = user_data;
	call->proxy = priv->secrets_proxy;

	call->call = org_freedesktop_NetworkManagerSettings_Connection_Secrets_get_secrets_async (priv->secrets_proxy,
	                                                                                          setting_name,
	                                                                                          hints,
	                                                                                          request_new,
	                                                                                          get_secrets_cb,
	                                                                                          call);
	g_assert (call->call);
	priv->calls = g_slist_append (priv->calls, call);

	return TRUE;
}

/****************************************************************/

static gboolean
replace_settings (NMRemoteConnection *self, GHashTable *new_settings)
{
	GError *error = NULL;

	if (!nm_connection_replace_settings (NM_CONNECTION (self), new_settings, &error)) {
		g_warning ("%s: error updating %s connection %s settings: (%d) %s",
		           __func__,
		           (nm_connection_get_scope (NM_CONNECTION (self)) == NM_CONNECTION_SCOPE_USER) ? "user" : "system",
		           nm_connection_get_path (NM_CONNECTION (self)),
		           error ? error->code : -1,
		           (error && error->message) ? error->message : "(unknown)");
		g_clear_error (&error);
		return FALSE;
	}

	/* Emit update irregardless to let listeners figure out what to do with
	 * the connection; whether to delete / ignore it or not.
	 */
	nm_settings_connection_interface_emit_updated (NM_SETTINGS_CONNECTION_INTERFACE (self));
	return TRUE;
}

static void
get_settings_cb (DBusGProxy *proxy,
                 GHashTable *new_settings,
                 GError *error,
                 gpointer user_data)
{
	NMRemoteConnection *self = user_data;
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (self);

	if (error) {
		g_warning ("%s: error getting %s connection %s settings: (%d) %s",
		           __func__,
		           (nm_connection_get_scope (NM_CONNECTION (self)) == NM_CONNECTION_SCOPE_USER) ? "user" : "system",
		           nm_connection_get_path (NM_CONNECTION (self)),
		           error ? error->code : -1,
		           (error && error->message) ? error->message : "(unknown)");
		g_error_free (error);
		priv->init_result = NM_REMOTE_CONNECTION_INIT_RESULT_ERROR;
		g_object_notify (G_OBJECT (self), NM_REMOTE_CONNECTION_INIT_RESULT);
	} else {
		replace_settings (self, new_settings);
		g_hash_table_destroy (new_settings);
		priv->init_result = NM_REMOTE_CONNECTION_INIT_RESULT_SUCCESS;
		g_object_notify (G_OBJECT (self), NM_REMOTE_CONNECTION_INIT_RESULT);
	}
}

static void
updated_cb (DBusGProxy *proxy, GHashTable *settings, gpointer user_data)
{
	replace_settings (NM_REMOTE_CONNECTION (user_data), settings);
}

static void
removed_cb (DBusGProxy *proxy, gpointer user_data)
{
	g_signal_emit_by_name (G_OBJECT (user_data), "removed");
}

/****************************************************************/

static void
settings_connection_interface_init (NMSettingsConnectionInterface *klass)
{
	/* interface implementation */
	klass->update = update;
	klass->delete = do_delete;
	klass->get_secrets = get_secrets;
}

/**
 * nm_remote_connection_new:
 * @bus: a valid and connected D-Bus connection
 * @scope: the Connection scope (either user or system)
 * @path: the D-Bus path of the connection as exported by the settings service
 *  indicated by @scope
 *
 * Creates a new object representing the remote connection.
 *
 * Returns: the new remote connection object on success, or %NULL on failure
 **/
NMRemoteConnection *
nm_remote_connection_new (DBusGConnection *bus,
                          NMConnectionScope scope,
                          const char *path)
{
	g_return_val_if_fail (bus != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);

	return (NMRemoteConnection *) g_object_new (NM_TYPE_REMOTE_CONNECTION,
	                                            NM_REMOTE_CONNECTION_BUS, bus,
	                                            NM_CONNECTION_SCOPE, scope,
	                                            NM_CONNECTION_PATH, path,
	                                            NULL);
}

static GObject *
constructor (GType type,
             guint n_construct_params,
             GObjectConstructParam *construct_params)
{
	GObject *object;
	NMRemoteConnectionPrivate *priv;
	const char *service = NM_DBUS_SERVICE_USER_SETTINGS;

	object = G_OBJECT_CLASS (nm_remote_connection_parent_class)->constructor (type, n_construct_params, construct_params);
	if (!object)
		return NULL;

	priv = NM_REMOTE_CONNECTION_GET_PRIVATE (object);
	g_assert (priv->bus);
	g_assert (nm_connection_get_path (NM_CONNECTION (object)));

	if (nm_connection_get_scope (NM_CONNECTION (object)) == NM_CONNECTION_SCOPE_SYSTEM)
		service = NM_DBUS_SERVICE_SYSTEM_SETTINGS;

	priv->proxy = dbus_g_proxy_new_for_name (priv->bus,
	                                         service,
	                                         nm_connection_get_path (NM_CONNECTION (object)),
	                                         NM_DBUS_IFACE_SETTINGS_CONNECTION);
	g_assert (priv->proxy);
	dbus_g_proxy_set_default_timeout (priv->proxy, G_MAXINT);

	priv->secrets_proxy = dbus_g_proxy_new_for_name (priv->bus,
	                                                 service,
	                                                 nm_connection_get_path (NM_CONNECTION (object)),
	                                                 NM_DBUS_IFACE_SETTINGS_CONNECTION_SECRETS);
	g_assert (priv->secrets_proxy);
	dbus_g_proxy_set_default_timeout (priv->secrets_proxy, G_MAXINT);

	dbus_g_proxy_add_signal (priv->proxy, "Updated", DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "Updated", G_CALLBACK (updated_cb), object, NULL);

	dbus_g_proxy_add_signal (priv->proxy, "Removed", G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "Removed", G_CALLBACK (removed_cb), object, NULL);

	org_freedesktop_NetworkManagerSettings_Connection_get_settings_async (priv->proxy,
	                                                                      get_settings_cb,
	                                                                      object);
	return object;
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
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMRemoteConnection *self = NM_REMOTE_CONNECTION (object);
	NMRemoteConnectionPrivate *priv = NM_REMOTE_CONNECTION_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_INIT_RESULT:
		g_value_set_uint (value, priv->init_result);
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

	if (!priv->disposed) {
		priv->disposed = TRUE;

		while (g_slist_length (priv->calls))
			remote_call_complete (self, priv->calls->data);

		g_object_unref (priv->proxy);
		g_object_unref (priv->secrets_proxy);
		dbus_g_connection_unref (priv->bus);
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
	object_class->get_property = get_property;
	object_class->dispose = dispose;
	object_class->constructor = constructor;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_BUS,
		 g_param_spec_boxed (NM_REMOTE_CONNECTION_BUS,
						 "DBusGConnection",
						 "DBusGConnection",
						 DBUS_TYPE_G_CONNECTION,
						 G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_INIT_RESULT,
		 g_param_spec_uint (NM_REMOTE_CONNECTION_INIT_RESULT,
		                    "Initialization result (PRIVATE)",
		                    "Initialization result (PRIVATE)",
		                    NM_REMOTE_CONNECTION_INIT_RESULT_UNKNOWN,
		                    NM_REMOTE_CONNECTION_INIT_RESULT_ERROR,
		                    NM_REMOTE_CONNECTION_INIT_RESULT_UNKNOWN,
		                    G_PARAM_READABLE));
}

