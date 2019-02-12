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
 * Copyright 2008 Novell, Inc.
 * Copyright 2009 - 2012 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-remote-settings.h"

#include "nm-dbus-interface.h"
#include "nm-connection.h"
#include "nm-client.h"
#include "nm-remote-connection.h"
#include "nm-remote-connection-private.h"
#include "nm-object-private.h"
#include "nm-dbus-helpers.h"
#include "nm-core-internal.h"

#include "introspection/org.freedesktop.NetworkManager.Settings.h"

G_DEFINE_TYPE (NMRemoteSettings, nm_remote_settings, NM_TYPE_OBJECT)

#define NM_REMOTE_SETTINGS_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_REMOTE_SETTINGS, NMRemoteSettingsPrivate))

typedef struct {
	NMDBusSettings *proxy;
	GPtrArray *all_connections;
	GPtrArray *visible_connections;

	/* AddConnectionInfo objects that are waiting for the connection to become initialized */
	GSList *add_list;

	char *hostname;
	gboolean can_modify;
} NMRemoteSettingsPrivate;

enum {
	PROP_0,
	PROP_CONNECTIONS,
	PROP_HOSTNAME,
	PROP_CAN_MODIFY,

	LAST_PROP
};

/* Signals */
enum {
	CONNECTION_ADDED,
	CONNECTION_REMOVED,

	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };

/*****************************************************************************/

typedef struct {
	NMRemoteSettings *self;
	GSimpleAsyncResult *simple;
	char *path;
	gboolean saved;
} AddConnectionInfo;

static AddConnectionInfo *
add_connection_info_find (NMRemoteSettings *self, const char *path)
{
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);
	GSList *iter;

	for (iter = priv->add_list; iter; iter = g_slist_next (iter)) {
		AddConnectionInfo *info = iter->data;

		if (!g_strcmp0 (info->path, path))
			return info;
	}

	return NULL;
}

static void
add_connection_info_complete (NMRemoteSettings *self,
                              AddConnectionInfo *info,
                              NMRemoteConnection *connection,
                              GError *error)
{
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);

	g_return_if_fail (info != NULL);

	if (connection) {
		g_simple_async_result_set_op_res_gpointer (info->simple,
		                                           g_object_ref (connection),
		                                           g_object_unref);
	} else
		g_simple_async_result_set_from_error (info->simple, error);
	g_simple_async_result_complete (info->simple);

	g_object_unref (info->simple);
	priv->add_list = g_slist_remove (priv->add_list, info);

	g_free (info->path);
	g_slice_free (AddConnectionInfo, info);
}

typedef const char * (*ConnectionStringGetter) (NMConnection *);

static NMRemoteConnection *
get_connection_by_string (NMRemoteSettings *settings,
                          const char *string,
                          ConnectionStringGetter get_comparison_string)
{
	NMRemoteSettingsPrivate *priv;
	NMConnection *candidate;
	int i;

	priv = NM_REMOTE_SETTINGS_GET_PRIVATE (settings);

	for (i = 0; i < priv->visible_connections->len; i++) {
		candidate = priv->visible_connections->pdata[i];
		if (!g_strcmp0 (string, get_comparison_string (candidate)))
			return NM_REMOTE_CONNECTION (candidate);
	}

	return NULL;
}

NMRemoteConnection *
nm_remote_settings_get_connection_by_id (NMRemoteSettings *settings, const char *id)
{
	g_return_val_if_fail (NM_IS_REMOTE_SETTINGS (settings), NULL);
	g_return_val_if_fail (id != NULL, NULL);

	return get_connection_by_string (settings, id, nm_connection_get_id);
}

NMRemoteConnection *
nm_remote_settings_get_connection_by_path (NMRemoteSettings *settings, const char *path)
{
	g_return_val_if_fail (NM_IS_REMOTE_SETTINGS (settings), NULL);
	g_return_val_if_fail (path != NULL, NULL);

	return get_connection_by_string (settings, path, nm_connection_get_path);
}

NMRemoteConnection *
nm_remote_settings_get_connection_by_uuid (NMRemoteSettings *settings, const char *uuid)
{
	g_return_val_if_fail (NM_IS_REMOTE_SETTINGS (settings), NULL);
	g_return_val_if_fail (uuid != NULL, NULL);

	return get_connection_by_string (settings, uuid, nm_connection_get_uuid);
}

static void
connection_visible_changed (GObject *object,
                            GParamSpec *pspec,
                            gpointer user_data)
{
	NMRemoteConnection *connection = NM_REMOTE_CONNECTION (object);
	NMRemoteSettings *self = NM_REMOTE_SETTINGS (user_data);

	if (nm_remote_connection_get_visible (connection))
		g_signal_emit (self, signals[CONNECTION_ADDED], 0, connection);
	else
		g_signal_emit (self, signals[CONNECTION_REMOVED], 0, connection);
}

static void
cleanup_connection (NMRemoteSettings *self,
                    NMRemoteConnection *remote)
{
	g_signal_handlers_disconnect_by_func (remote, G_CALLBACK (connection_visible_changed), self);
}

static void
connection_removed (NMRemoteSettings *self,
                    NMRemoteConnection *remote)
{
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);
	gboolean still_exists = FALSE;
	int i;

	/* Check if the connection was actually removed or if it just turned invisible. */
	for (i = 0; i < priv->all_connections->len; i++) {
		if (remote == priv->all_connections->pdata[i]) {
			still_exists = TRUE;
			break;
		}
	}

	if (!still_exists)
		cleanup_connection (self, remote);

	/* Allow the signal to propagate if and only if @remote was in visible_connections */
	if (!g_ptr_array_remove (priv->visible_connections, remote))
		g_signal_stop_emission (self, signals[CONNECTION_REMOVED], 0);
}

static void
connection_added (NMRemoteSettings *self,
                  NMRemoteConnection *remote)
{
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);
	AddConnectionInfo *addinfo;
	const char *path;

	if (!g_signal_handler_find (remote, G_SIGNAL_MATCH_FUNC | G_SIGNAL_MATCH_DATA, 0, 0, NULL,
	                            G_CALLBACK (connection_visible_changed), self)) {
		g_signal_connect (remote,
		                  "notify::" NM_REMOTE_CONNECTION_VISIBLE,
		                  G_CALLBACK (connection_visible_changed),
		                  self);
	}

	if (nm_remote_connection_get_visible (remote))
		g_ptr_array_add (priv->visible_connections, remote);
	else
		g_signal_stop_emission (self, signals[CONNECTION_ADDED], 0);

	path = nm_connection_get_path (NM_CONNECTION (remote));
	addinfo = add_connection_info_find (self, path);
	if (addinfo)
		add_connection_info_complete (self, addinfo, remote, NULL);
}

static void
object_creation_failed (NMObject *object, const char *failed_path)
{
	NMRemoteSettings *self = NM_REMOTE_SETTINGS (object);
	AddConnectionInfo *addinfo;
	GError *add_error;

	addinfo = add_connection_info_find (self, failed_path);
	if (addinfo) {
		add_error = g_error_new_literal (NM_CLIENT_ERROR,
		                                 NM_CLIENT_ERROR_OBJECT_CREATION_FAILED,
		                                 _("Connection removed before it was initialized"));
		add_connection_info_complete (self, addinfo, NULL, add_error);
		g_error_free (add_error);
	}
}

const GPtrArray *
nm_remote_settings_get_connections (NMRemoteSettings *settings)
{
	g_return_val_if_fail (NM_IS_REMOTE_SETTINGS (settings), NULL);

	return NM_REMOTE_SETTINGS_GET_PRIVATE (settings)->visible_connections;
}

static void
add_connection_done (GObject *proxy, GAsyncResult *result, gpointer user_data)
{
	AddConnectionInfo *info = user_data;
	GError *error = NULL;

	if (info->saved) {
		nmdbus_settings_call_add_connection_finish (NMDBUS_SETTINGS (proxy),
		                                            &info->path,
		                                            result, &error);
	} else {
		nmdbus_settings_call_add_connection_unsaved_finish (NMDBUS_SETTINGS (proxy),
		                                                    &info->path,
		                                                    result, &error);
	}

	if (error) {
		g_dbus_error_strip_remote_error (error);
		add_connection_info_complete (info->self, info, NULL, error);
		g_clear_error (&error);
	}

	/* On success, we still have to wait until the connection is fully
	 * initialized before calling the callback.
	 */
}

void
nm_remote_settings_add_connection_async (NMRemoteSettings *settings,
                                         NMConnection *connection,
                                         gboolean save_to_disk,
                                         GCancellable *cancellable,
                                         GAsyncReadyCallback callback,
                                         gpointer user_data)
{
	NMRemoteSettingsPrivate *priv;
	AddConnectionInfo *info;
	GVariant *new_settings;

	g_return_if_fail (NM_IS_REMOTE_SETTINGS (settings));
	g_return_if_fail (NM_IS_CONNECTION (connection));

	priv = NM_REMOTE_SETTINGS_GET_PRIVATE (settings);

	info = g_slice_new0 (AddConnectionInfo);
	info->self = settings;
	info->simple = g_simple_async_result_new (G_OBJECT (settings), callback, user_data,
	                                          nm_remote_settings_add_connection_async);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (info->simple, cancellable);
	info->saved = save_to_disk;

	new_settings = nm_connection_to_dbus (connection, NM_CONNECTION_SERIALIZE_ALL);

	if (save_to_disk) {
		nmdbus_settings_call_add_connection (priv->proxy,
		                                     new_settings,
		                                     NULL,
		                                     add_connection_done, info);
	} else {
		nmdbus_settings_call_add_connection_unsaved (priv->proxy,
		                                             new_settings,
		                                             NULL,
		                                             add_connection_done, info);
	}

	priv->add_list = g_slist_append (priv->add_list, info);
}

NMRemoteConnection *
nm_remote_settings_add_connection_finish (NMRemoteSettings *settings,
                                          GAsyncResult *result,
                                          GError **error)
{
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (settings), nm_remote_settings_add_connection_async), NULL);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return NULL;
	else
		return g_object_ref (g_simple_async_result_get_op_res_gpointer (simple));
}

gboolean
nm_remote_settings_load_connections (NMRemoteSettings *settings,
                                     char **filenames,
                                     char ***failures,
                                     GCancellable *cancellable,
                                     GError **error)
{
	NMRemoteSettingsPrivate *priv;
	gboolean success;

	g_return_val_if_fail (NM_IS_REMOTE_SETTINGS (settings), FALSE);
	g_return_val_if_fail (filenames != NULL, FALSE);

	priv = NM_REMOTE_SETTINGS_GET_PRIVATE (settings);

	if (!nmdbus_settings_call_load_connections_sync (priv->proxy,
	                                                 (const char * const *) filenames,
	                                                 &success,
	                                                 failures,
	                                                 cancellable, error)) {
		if (error && *error)
			g_dbus_error_strip_remote_error (*error);
		success = FALSE;
	}
	return success;
}

static void
load_connections_cb (GObject *proxy, GAsyncResult *result, gpointer user_data)
{
	GSimpleAsyncResult *simple = user_data;
	GError *error = NULL;
	gboolean success;
	char **failures = NULL;

	if (nmdbus_settings_call_load_connections_finish (NMDBUS_SETTINGS (proxy),
	                                                  &success, &failures,
	                                                  result, &error))
		g_simple_async_result_set_op_res_gpointer (simple, failures, (GDestroyNotify) g_strfreev);
	else {
		g_dbus_error_strip_remote_error (error);
		g_simple_async_result_take_error (simple, error);
	}

	g_simple_async_result_complete (simple);
	g_object_unref (simple);
}

void
nm_remote_settings_load_connections_async (NMRemoteSettings *settings,
                                           char **filenames,
                                           GCancellable *cancellable,
                                           GAsyncReadyCallback callback,
                                           gpointer user_data)
{
	NMRemoteSettingsPrivate *priv;
	GSimpleAsyncResult *simple;

	g_return_if_fail (NM_IS_REMOTE_SETTINGS (settings));
	g_return_if_fail (filenames != NULL);

	priv = NM_REMOTE_SETTINGS_GET_PRIVATE (settings);

	simple = g_simple_async_result_new (G_OBJECT (settings), callback, user_data,
	                                    nm_remote_settings_load_connections_async);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (simple, cancellable);

	nmdbus_settings_call_load_connections (priv->proxy,
	                                       (const char * const *) filenames,
	                                       cancellable, load_connections_cb, simple);
}

gboolean
nm_remote_settings_load_connections_finish (NMRemoteSettings *settings,
                                            char ***failures,
                                            GAsyncResult *result,
                                            GError **error)
{
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (settings), nm_remote_settings_load_connections_async), FALSE);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return FALSE;
	else {
		*failures = g_strdupv (g_simple_async_result_get_op_res_gpointer (simple));
		return TRUE;
	}
}

gboolean
nm_remote_settings_reload_connections (NMRemoteSettings *settings,
                                       GCancellable *cancellable,
                                       GError **error)
{
	NMRemoteSettingsPrivate *priv;
	gboolean success;

	g_return_val_if_fail (NM_IS_REMOTE_SETTINGS (settings), FALSE);

	priv = NM_REMOTE_SETTINGS_GET_PRIVATE (settings);

	if (!nmdbus_settings_call_reload_connections_sync (priv->proxy, &success,
	                                                   cancellable, error)) {
		if (error && *error)
			g_dbus_error_strip_remote_error (*error);
		success = FALSE;
	}

	return success;
}

static void
reload_connections_cb (GObject *proxy, GAsyncResult *result, gpointer user_data)
{
	GSimpleAsyncResult *simple = user_data;
	gboolean success;
	GError *error = NULL;

	if (nmdbus_settings_call_reload_connections_finish (NMDBUS_SETTINGS (proxy),
	                                                    &success,
	                                                    result, &error))
		g_simple_async_result_set_op_res_gboolean (simple, success);
	else {
		g_dbus_error_strip_remote_error (error);
		g_simple_async_result_take_error (simple, error);
	}

	g_simple_async_result_complete (simple);
	g_object_unref (simple);
}

void
nm_remote_settings_reload_connections_async (NMRemoteSettings *settings,
                                             GCancellable *cancellable,
                                             GAsyncReadyCallback callback,
                                             gpointer user_data)
{
	NMRemoteSettingsPrivate *priv;
	GSimpleAsyncResult *simple;

	g_return_if_fail (NM_IS_REMOTE_SETTINGS (settings));

	priv = NM_REMOTE_SETTINGS_GET_PRIVATE (settings);

	simple = g_simple_async_result_new (G_OBJECT (settings), callback, user_data,
	                                    nm_remote_settings_reload_connections_async);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (simple, cancellable);

	nmdbus_settings_call_reload_connections (priv->proxy, cancellable,
	                                         reload_connections_cb, simple);
}

gboolean
nm_remote_settings_reload_connections_finish (NMRemoteSettings *settings,
                                              GAsyncResult *result,
                                              GError **error)
{
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (settings), nm_remote_settings_reload_connections_async), FALSE);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return FALSE;
	else
		return g_simple_async_result_get_op_res_gboolean (simple);
}

gboolean
nm_remote_settings_save_hostname (NMRemoteSettings *settings,
                                  const char *hostname,
                                  GCancellable *cancellable,
                                  GError **error)
{
	NMRemoteSettingsPrivate *priv;
	gboolean ret;

	g_return_val_if_fail (NM_IS_REMOTE_SETTINGS (settings), FALSE);

	priv = NM_REMOTE_SETTINGS_GET_PRIVATE (settings);

	ret = nmdbus_settings_call_save_hostname_sync (priv->proxy,
	                                               hostname ?: "",
	                                               cancellable, error);
	if (error && *error)
		g_dbus_error_strip_remote_error (*error);
	return ret;
}

static void
save_hostname_cb (GObject *proxy,
                  GAsyncResult *result,
                  gpointer user_data)
{
	GSimpleAsyncResult *simple = user_data;
	GError *error = NULL;

	if (nmdbus_settings_call_save_hostname_finish (NMDBUS_SETTINGS (proxy), result, &error))
		g_simple_async_result_set_op_res_gboolean (simple, TRUE);
	else {
		g_dbus_error_strip_remote_error (error);
		g_simple_async_result_take_error (simple, error);
	}
	g_simple_async_result_complete (simple);
	g_object_unref (simple);
}

void
nm_remote_settings_save_hostname_async (NMRemoteSettings *settings,
                                        const char *hostname,
                                        GCancellable *cancellable,
                                        GAsyncReadyCallback callback,
                                        gpointer user_data)
{
	NMRemoteSettingsPrivate *priv;
	GSimpleAsyncResult *simple;

	g_return_if_fail (NM_IS_REMOTE_SETTINGS (settings));

	priv = NM_REMOTE_SETTINGS_GET_PRIVATE (settings);

	simple = g_simple_async_result_new (G_OBJECT (settings), callback, user_data,
	                                    nm_remote_settings_save_hostname_async);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (simple, cancellable);

	nmdbus_settings_call_save_hostname (priv->proxy,
	                                    hostname ?: "",
	                                    cancellable, save_hostname_cb, simple);
}

gboolean
nm_remote_settings_save_hostname_finish (NMRemoteSettings *settings,
                                         GAsyncResult *result,
                                         GError **error)
{
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (settings), nm_remote_settings_save_hostname_async), FALSE);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return FALSE;
	else
		return g_simple_async_result_get_op_res_gboolean (simple);
}

/*****************************************************************************/

static void
nm_remote_settings_init (NMRemoteSettings *self)
{
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);

	priv->all_connections = g_ptr_array_new ();
	priv->visible_connections = g_ptr_array_new ();
}

static void
init_dbus (NMObject *object)
{
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (object);
	const NMPropertiesInfo property_info[] = {
		{ NM_REMOTE_SETTINGS_CONNECTIONS,      &priv->all_connections, NULL, NM_TYPE_REMOTE_CONNECTION, "connection" },
		{ NM_REMOTE_SETTINGS_HOSTNAME,         &priv->hostname },
		{ NM_REMOTE_SETTINGS_CAN_MODIFY,       &priv->can_modify },
		{ NULL },
	};

	NM_OBJECT_CLASS (nm_remote_settings_parent_class)->init_dbus (object);

	priv->proxy = NMDBUS_SETTINGS (_nm_object_get_proxy (object, NM_DBUS_INTERFACE_SETTINGS));
	_nm_object_register_properties (object,
	                                NM_DBUS_INTERFACE_SETTINGS,
	                                property_info);
}

static GObject *
constructor (GType type,
             guint n_construct_params,
             GObjectConstructParam *construct_params)
{
	guint i;
	const char *dbus_path;

	/* Fill in the right D-Bus path if none was specified */
	for (i = 0; i < n_construct_params; i++) {
		if (strcmp (construct_params[i].pspec->name, NM_OBJECT_PATH) == 0) {
			dbus_path = g_value_get_string (construct_params[i].value);
			if (dbus_path == NULL) {
				g_value_set_static_string (construct_params[i].value, NM_DBUS_PATH_SETTINGS);
			} else {
				if (!g_variant_is_object_path (dbus_path)) {
					g_warning ("Passed D-Bus object path '%s' is invalid; using default '%s' instead",
					           dbus_path, NM_DBUS_PATH);
					g_value_set_static_string (construct_params[i].value, NM_DBUS_PATH_SETTINGS);
				}
			}
			break;
		}
	}

	return G_OBJECT_CLASS (nm_remote_settings_parent_class)->constructor (type,
	                                                                      n_construct_params,
	                                                                      construct_params);
}

static void
dispose (GObject *object)
{
	NMRemoteSettings *self = NM_REMOTE_SETTINGS (object);
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (self);
	int i;

	if (priv->all_connections) {
		for (i = 0; i < priv->all_connections->len; i++)
			cleanup_connection (self, priv->all_connections->pdata[i]);
		g_clear_pointer (&priv->all_connections, g_ptr_array_unref);
	}

	g_clear_pointer (&priv->visible_connections, g_ptr_array_unref);
	g_clear_pointer (&priv->hostname, g_free);
	g_clear_object (&priv->proxy);

	G_OBJECT_CLASS (nm_remote_settings_parent_class)->dispose (object);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMRemoteSettingsPrivate *priv = NM_REMOTE_SETTINGS_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_CONNECTIONS:
		g_value_take_boxed (value, _nm_utils_copy_object_array (priv->visible_connections));
		break;
	case PROP_HOSTNAME:
		g_value_set_string (value, priv->hostname);
		break;
	case PROP_CAN_MODIFY:
		g_value_set_boolean (value, priv->can_modify);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_remote_settings_class_init (NMRemoteSettingsClass *class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (class);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (class);

	g_type_class_add_private (class, sizeof (NMRemoteSettingsPrivate));

	/* Virtual methods */
	object_class->constructor = constructor;
	object_class->get_property = get_property;
	object_class->dispose = dispose;

	nm_object_class->init_dbus = init_dbus;
	nm_object_class->object_creation_failed = object_creation_failed;

	class->connection_added = connection_added;
	class->connection_removed = connection_removed;

	/* Properties */

	g_object_class_install_property
		(object_class, PROP_CONNECTIONS,
		 g_param_spec_boxed (NM_REMOTE_SETTINGS_CONNECTIONS, "", "",
		                     G_TYPE_PTR_ARRAY,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_HOSTNAME,
		 g_param_spec_string (NM_REMOTE_SETTINGS_HOSTNAME, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_CAN_MODIFY,
		 g_param_spec_boolean (NM_REMOTE_SETTINGS_CAN_MODIFY, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/* Signals */
	signals[CONNECTION_ADDED] =
		g_signal_new (NM_REMOTE_SETTINGS_CONNECTION_ADDED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMRemoteSettingsClass, connection_added),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1,
		              NM_TYPE_REMOTE_CONNECTION);

	signals[CONNECTION_REMOVED] =
		g_signal_new (NM_REMOTE_SETTINGS_CONNECTION_REMOVED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMRemoteSettingsClass, connection_removed),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1,
		              NM_TYPE_REMOTE_CONNECTION);
}
