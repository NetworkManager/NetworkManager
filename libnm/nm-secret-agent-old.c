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
 * Copyright 2010 - 2011 Red Hat, Inc.
 */

#include "nm-default.h"

#include <string.h>

#include "nm-dbus-interface.h"
#include "nm-secret-agent-old.h"
#include "nm-enum-types.h"
#include "nm-dbus-helpers.h"
#include "nm-simple-connection.h"
#include "nm-core-internal.h"

#include "introspection/org.freedesktop.NetworkManager.SecretAgent.h"
#include "introspection/org.freedesktop.NetworkManager.AgentManager.h"

static void nm_secret_agent_old_initable_iface_init (GInitableIface *iface);
static void nm_secret_agent_old_async_initable_iface_init (GAsyncInitableIface *iface);
G_DEFINE_ABSTRACT_TYPE_WITH_CODE (NMSecretAgentOld, nm_secret_agent_old, G_TYPE_OBJECT,
                                  G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, nm_secret_agent_old_initable_iface_init);
                                  G_IMPLEMENT_INTERFACE (G_TYPE_ASYNC_INITABLE, nm_secret_agent_old_async_initable_iface_init);
                                  )

#define NM_SECRET_AGENT_OLD_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SECRET_AGENT_OLD, NMSecretAgentOldPrivate))

typedef struct {
	gboolean registered;
	gboolean registering;
	NMSecretAgentCapabilities capabilities;

	GDBusConnection *bus;
	gboolean private_bus;
	gboolean session_bus;
	NMDBusAgentManager *manager_proxy;
	NMDBusSecretAgent *dbus_secret_agent;

	/* GetSecretsInfo structs of in-flight GetSecrets requests */
	GSList *pending_gets;

	char *identifier;
	gboolean auto_register;
	gboolean suppress_auto;
} NMSecretAgentOldPrivate;

enum {
	PROP_0,
	PROP_IDENTIFIER,
	PROP_AUTO_REGISTER,
	PROP_REGISTERED,
	PROP_CAPABILITIES,

	LAST_PROP
};

/*****************************************************************************/

static void
_internal_unregister (NMSecretAgentOld *self)
{
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);

	if (priv->registered) {
		g_dbus_interface_skeleton_unexport (G_DBUS_INTERFACE_SKELETON (priv->dbus_secret_agent));
		priv->registered = FALSE;
		priv->registering = FALSE;
		g_object_notify (G_OBJECT (self), NM_SECRET_AGENT_OLD_REGISTERED);
	}
}

typedef struct {
	char *path;
	char *setting_name;
	GDBusMethodInvocation *context;
} GetSecretsInfo;

static void
get_secrets_info_finalize (NMSecretAgentOld *self, GetSecretsInfo *info)
{
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);

	g_return_if_fail (info != NULL);

	priv->pending_gets = g_slist_remove (priv->pending_gets, info);

	g_free (info->path);
	g_free (info->setting_name);
	memset (info, 0, sizeof (*info));
	g_free (info);
}

static inline gboolean
should_auto_register (NMSecretAgentOld *self)
{
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);

	return (   priv->auto_register
	        && !priv->suppress_auto
	        && !priv->registered
	        && !priv->registering);
}

static void
name_owner_changed (GObject *proxy,
                    GParamSpec *pspec,
                    gpointer user_data)
{
	NMSecretAgentOld *self = NM_SECRET_AGENT_OLD (user_data);
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);
	GSList *iter;
	char *owner;

	owner = g_dbus_proxy_get_name_owner (G_DBUS_PROXY (proxy));
	if (owner != NULL) {
		if (should_auto_register (self))
			nm_secret_agent_old_register_async (self, NULL, NULL, NULL);
		g_free (owner);
	} else {
		/* Cancel any pending secrets requests */
		for (iter = priv->pending_gets; iter; iter = g_slist_next (iter)) {
			GetSecretsInfo *info = iter->data;

			NM_SECRET_AGENT_OLD_GET_CLASS (self)->cancel_get_secrets (self,
			                                                      info->path,
			                                                      info->setting_name);
		}
		g_slist_free (priv->pending_gets);
		priv->pending_gets = NULL;

		_internal_unregister (self);
	}
}

static gboolean
verify_sender (NMSecretAgentOld *self,
               GDBusMethodInvocation *context,
               GError **error)
{
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);
	char *nm_owner;
	const char *sender;
	guint32 sender_uid;
	GVariant *ret;
	GError *local = NULL;

	g_return_val_if_fail (context != NULL, FALSE);

	/* Private bus connection is always to NetworkManager, which is always
	 * UID 0.
	 */
	if (priv->private_bus)
		return TRUE;

	/* Verify that the sender is the same as NetworkManager's bus name owner. */

	nm_owner = g_dbus_proxy_get_name_owner (G_DBUS_PROXY (priv->manager_proxy));
	if (!nm_owner) {
		g_set_error_literal (error,
		                     NM_SECRET_AGENT_ERROR,
		                     NM_SECRET_AGENT_ERROR_PERMISSION_DENIED,
		                     "NetworkManager bus name owner unknown.");
		return FALSE;
	}

	sender = g_dbus_method_invocation_get_sender (context);
	if (!sender) {
		g_set_error_literal (error,
		                     NM_SECRET_AGENT_ERROR,
		                     NM_SECRET_AGENT_ERROR_PERMISSION_DENIED,
		                     "Failed to get request sender.");
		g_free (nm_owner);
		return FALSE;
	}

	/* Check that the sender matches the current NM bus name owner */
	if (strcmp (sender, nm_owner) != 0) {
		g_set_error_literal (error,
		                     NM_SECRET_AGENT_ERROR,
		                     NM_SECRET_AGENT_ERROR_PERMISSION_DENIED,
		                     "Request sender does not match NetworkManager bus name owner.");
		g_free (nm_owner);
		return FALSE;
	}
	g_free (nm_owner);

	/* If we're connected to the session bus, then this must be a test program,
	 * so skip the UID check.
	 */
	if (priv->session_bus)
		return TRUE;

	/* Check the UID of the sender */
	ret = g_dbus_connection_call_sync (priv->bus,
	                                   DBUS_SERVICE_DBUS,
	                                   DBUS_PATH_DBUS,
	                                   DBUS_INTERFACE_DBUS,
	                                   "GetConnectionUnixUser",
	                                   g_variant_new ("(s)", sender),
	                                   G_VARIANT_TYPE ("(u)"),
	                                   G_DBUS_CALL_FLAGS_NONE, -1,
	                                   NULL, &local);
	if (!ret) {
		char *remote_error = g_dbus_error_get_remote_error (local);

		g_dbus_error_strip_remote_error (local);
		g_set_error (error,
		             NM_SECRET_AGENT_ERROR,
		             NM_SECRET_AGENT_ERROR_PERMISSION_DENIED,
		             "Failed to request unix user: (%s) %s.",
		             remote_error ? remote_error : "",
		             local->message);
		g_free (remote_error);
		g_error_free (local);
		return FALSE;
	}
	g_variant_get (ret, "(u)", &sender_uid);
	g_variant_unref (ret);

	/* We only accept requests from NM, which always runs as root */
	if (0 != sender_uid) {
		g_set_error_literal (error,
		                     NM_SECRET_AGENT_ERROR,
		                     NM_SECRET_AGENT_ERROR_PERMISSION_DENIED,
		                     "Request sender is not root.");
		return FALSE;
	}

	return TRUE;
}

static gboolean
verify_request (NMSecretAgentOld *self,
                GDBusMethodInvocation *context,
                GVariant *connection_dict,
                const char *connection_path,
                NMConnection **out_connection,
                GError **error)
{
	NMConnection *connection = NULL;
	GError *local = NULL;

	if (!verify_sender (self, context, error))
		return FALSE;

	/* No connection?  If the sender verified, then we allow the request */
	if (connection_dict == NULL)
		return TRUE;

	/* If we have a connection dictionary, we require a path too */
	if (connection_path == NULL) {
		g_set_error_literal (error,
		                     NM_SECRET_AGENT_ERROR,
		                     NM_SECRET_AGENT_ERROR_INVALID_CONNECTION,
		                     "Invalid connection: no connection path given.");
		return FALSE;
	}

	/* Make sure the given connection is valid */
	g_assert (out_connection);
	connection = _nm_simple_connection_new_from_dbus (connection_dict, NM_SETTING_PARSE_FLAGS_BEST_EFFORT, &local);
	if (connection) {
		nm_connection_set_path (connection, connection_path);
		*out_connection = connection;
	} else {
		g_set_error (error,
		             NM_SECRET_AGENT_ERROR,
		             NM_SECRET_AGENT_ERROR_INVALID_CONNECTION,
		             "Invalid connection: %s", local->message);
		g_clear_error (&local);
	}

	return !!connection;
}

static void
get_secrets_cb (NMSecretAgentOld *self,
                NMConnection *connection,
                GVariant *secrets,
                GError *error,
                gpointer user_data)
{
	GetSecretsInfo *info = user_data;

	if (error)
		g_dbus_method_invocation_return_gerror (info->context, error);
	else {
		g_variant_take_ref (secrets);
		g_dbus_method_invocation_return_value (info->context,
		                                       g_variant_new ("(@a{sa{sv}})", secrets));
	}

	/* Remove the request from internal tracking */
	get_secrets_info_finalize (self, info);
}

static void
impl_secret_agent_old_get_secrets (NMSecretAgentOld *self,
                                   GDBusMethodInvocation *context,
                                   GVariant *connection_dict,
                                   const char *connection_path,
                                   const char *setting_name,
                                   const char * const *hints,
                                   guint flags,
                                   gpointer user_data)
{
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);
	GError *error = NULL;
	NMConnection *connection = NULL;
	GetSecretsInfo *info;

	/* Make sure the request comes from NetworkManager and is valid */
	if (!verify_request (self, context, connection_dict, connection_path, &connection, &error)) {
		g_dbus_method_invocation_take_error (context, error);
		return;
	}

	info = g_malloc0 (sizeof (GetSecretsInfo));
	info->path = g_strdup (connection_path);
	info->setting_name = g_strdup (setting_name);
	info->context = context;
	priv->pending_gets = g_slist_append (priv->pending_gets, info);

	NM_SECRET_AGENT_OLD_GET_CLASS (self)->get_secrets (self,
	                                               connection,
	                                               connection_path,
	                                               setting_name,
	                                               (const char **) hints,
	                                               flags,
	                                               get_secrets_cb,
	                                               info);
	g_object_unref (connection);
}

static GetSecretsInfo *
find_get_secrets_info (GSList *list, const char *path, const char *setting_name)
{
	GSList *iter;

	for (iter = list; iter; iter = g_slist_next (iter)) {
		GetSecretsInfo *candidate = iter->data;

		if (   g_strcmp0 (path, candidate->path) == 0
		    && g_strcmp0 (setting_name, candidate->setting_name) == 0)
			return candidate;
	}
	return NULL;
}

static void
impl_secret_agent_old_cancel_get_secrets (NMSecretAgentOld *self,
                                          GDBusMethodInvocation *context,
                                          const char *connection_path,
                                          const char *setting_name,
                                          gpointer user_data)
{
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);
	GError *error = NULL;
	GetSecretsInfo *info;

	/* Make sure the request comes from NetworkManager and is valid */
	if (!verify_request (self, context, NULL, NULL, NULL, &error)) {
		g_dbus_method_invocation_take_error (context, error);
		return;
	}

	info = find_get_secrets_info (priv->pending_gets, connection_path, setting_name);
	if (!info) {
		g_dbus_method_invocation_return_error (context,
		                                       NM_SECRET_AGENT_ERROR,
		                                       NM_SECRET_AGENT_ERROR_FAILED,
		                                       "No secrets request in progress for this connection.");
		return;
	}

	/* Send the cancel request up to the subclass and finalize it */
	NM_SECRET_AGENT_OLD_GET_CLASS (self)->cancel_get_secrets (self,
	                                                      info->path,
	                                                      info->setting_name);
	g_dbus_method_invocation_return_value (context, NULL);
}

static void
save_secrets_cb (NMSecretAgentOld *self,
                 NMConnection *connection,
                 GError *error,
                 gpointer user_data)
{
	GDBusMethodInvocation *context = user_data;

	if (error)
		g_dbus_method_invocation_return_gerror (context, error);
	else
		g_dbus_method_invocation_return_value (context, NULL);
}

static void
impl_secret_agent_old_save_secrets (NMSecretAgentOld *self,
                                    GDBusMethodInvocation *context,
                                    GVariant *connection_dict,
                                    const char *connection_path,
                                    gpointer user_data)
{
	GError *error = NULL;
	NMConnection *connection = NULL;

	/* Make sure the request comes from NetworkManager and is valid */
	if (!verify_request (self, context, connection_dict, connection_path, &connection, &error)) {
		g_dbus_method_invocation_take_error (context, error);
		return;
	}

	NM_SECRET_AGENT_OLD_GET_CLASS (self)->save_secrets (self,
	                                                connection,
	                                                connection_path,
	                                                save_secrets_cb,
	                                                context);
	g_object_unref (connection);
}

static void
delete_secrets_cb (NMSecretAgentOld *self,
                   NMConnection *connection,
                   GError *error,
                   gpointer user_data)
{
	GDBusMethodInvocation *context = user_data;

	if (error)
		g_dbus_method_invocation_return_gerror (context, error);
	else
		g_dbus_method_invocation_return_value (context, NULL);
}

static void
impl_secret_agent_old_delete_secrets (NMSecretAgentOld *self,
                                      GDBusMethodInvocation *context,
                                      GVariant *connection_dict,
                                      const char *connection_path,
                                      gpointer user_data)
{
	GError *error = NULL;
	NMConnection *connection = NULL;

	/* Make sure the request comes from NetworkManager and is valid */
	if (!verify_request (self, context, connection_dict, connection_path, &connection, &error)) {
		g_dbus_method_invocation_take_error (context, error);
		return;
	}

	NM_SECRET_AGENT_OLD_GET_CLASS (self)->delete_secrets (self,
	                                                  connection,
	                                                  connection_path,
	                                                  delete_secrets_cb,
	                                                  context);
	g_object_unref (connection);
}

/*****************************************************************************/

static gboolean
check_nm_running (NMSecretAgentOld *self, GError **error)
{
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);
	char *owner;

	if (priv->private_bus)
		return TRUE;
	owner = g_dbus_proxy_get_name_owner (G_DBUS_PROXY (priv->manager_proxy));
	if (owner) {
		g_free (owner);
		return TRUE;
	}

	g_set_error (error, NM_SECRET_AGENT_ERROR, NM_SECRET_AGENT_ERROR_FAILED,
	             "NetworkManager is not running");
	return FALSE;
}

/*****************************************************************************/

/**
 * nm_secret_agent_old_register:
 * @self: a #NMSecretAgentOld
 * @cancellable: a #GCancellable, or %NULL
 * @error: return location for a #GError, or %NULL
 *
 * Registers the #NMSecretAgentOld with the NetworkManager secret manager,
 * indicating to NetworkManager that the agent is able to provide and save
 * secrets for connections on behalf of its user.
 *
 * It is a programmer error to attempt to register an agent that is already
 * registered, or in the process of registering.
 *
 * Returns: %TRUE if registration was successful, %FALSE on error.
 **/
gboolean
nm_secret_agent_old_register (NMSecretAgentOld *self,
                              GCancellable *cancellable,
                              GError **error)
{
	NMSecretAgentOldPrivate *priv;
	NMSecretAgentOldClass *class;

	g_return_val_if_fail (NM_IS_SECRET_AGENT_OLD (self), FALSE);

	priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);

	g_return_val_if_fail (priv->registered == FALSE, FALSE);
	g_return_val_if_fail (priv->registering == FALSE, FALSE);
	g_return_val_if_fail (priv->bus != NULL, FALSE);
	g_return_val_if_fail (priv->manager_proxy != NULL, FALSE);

	/* Also make sure the subclass can actually respond to secrets requests */
	class = NM_SECRET_AGENT_OLD_GET_CLASS (self);
	g_return_val_if_fail (class->get_secrets != NULL, FALSE);
	g_return_val_if_fail (class->save_secrets != NULL, FALSE);
	g_return_val_if_fail (class->delete_secrets != NULL, FALSE);

	if (!check_nm_running (self, error))
		return FALSE;

	priv->suppress_auto = FALSE;

	/* Export our secret agent interface before registering with the manager */
	if (!g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (priv->dbus_secret_agent),
	                                       priv->bus,
	                                       NM_DBUS_PATH_SECRET_AGENT,
	                                       error))
		return FALSE;

	priv->registering = TRUE;
	if (nmdbus_agent_manager_call_register_with_capabilities_sync (priv->manager_proxy,
	                                                               priv->identifier,
	                                                               priv->capabilities,
	                                                               cancellable, NULL))
		goto success;

	/* Might be an old NetworkManager that doesn't support capabilities;
	 * fall back to old Register() method instead.
	 */
	if (nmdbus_agent_manager_call_register_sync (priv->manager_proxy,
	                                             priv->identifier,
	                                             cancellable, error))
		goto success;

	/* Failure */
	priv->registering = FALSE;
	_internal_unregister (self);
	return FALSE;

success:
	priv->registering = FALSE;
	priv->registered = TRUE;
	g_object_notify (G_OBJECT (self), NM_SECRET_AGENT_OLD_REGISTERED);
	return TRUE;
}

static void
reg_result (NMSecretAgentOld *self, GSimpleAsyncResult *simple, GError *error)
{
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);

	priv->registering = FALSE;

	if (error) {
		g_simple_async_result_take_error (simple, error);
		g_simple_async_result_complete (simple);

		/* If registration failed we shouldn't expose ourselves on the bus */
		_internal_unregister (self);
	} else {
		priv->registered = TRUE;
		g_object_notify (G_OBJECT (self), NM_SECRET_AGENT_OLD_REGISTERED);

		g_simple_async_result_set_op_res_gboolean (simple, TRUE);
		g_simple_async_result_complete (simple);
	}

	g_object_unref (simple);
}

static void
reg_request_cb (GObject *proxy,
                GAsyncResult *result,
                gpointer user_data)
{
	GSimpleAsyncResult *simple = user_data;
	NMSecretAgentOld *self;
	NMSecretAgentOldPrivate *priv;
	GError *error = NULL;

	self = NM_SECRET_AGENT_OLD (g_async_result_get_source_object (G_ASYNC_RESULT (simple)));
	g_object_unref (self); /* drop extra ref added by get_source_object() */
	priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);

	if (!nmdbus_agent_manager_call_register_finish (NMDBUS_AGENT_MANAGER (proxy), result, &error))
		g_dbus_error_strip_remote_error (error);
	reg_result (self, simple, error);
}

static void
reg_with_caps_cb (GObject *proxy,
                  GAsyncResult *result,
                  gpointer user_data)
{
	GSimpleAsyncResult *simple = user_data;
	NMSecretAgentOld *self;
	NMSecretAgentOldPrivate *priv;

	self = NM_SECRET_AGENT_OLD (g_async_result_get_source_object (G_ASYNC_RESULT (simple)));
	g_object_unref (self); /* drop extra ref added by get_source_object() */
	priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);

	if (nmdbus_agent_manager_call_register_with_capabilities_finish (NMDBUS_AGENT_MANAGER (proxy), result, NULL)) {
		reg_result (self, simple, NULL);
		return;
	}

	/* Might be an old NetworkManager that doesn't support capabilities;
	 * fall back to old Register() method instead.
	 */
	nmdbus_agent_manager_call_register (priv->manager_proxy,
	                                    priv->identifier,
	                                    NULL, reg_request_cb, simple);
}

/**
 * nm_secret_agent_old_register_async:
 * @self: a #NMSecretAgentOld
 * @cancellable: a #GCancellable, or %NULL
 * @callback: callback to call when the agent is registered
 * @user_data: data for @callback
 *
 * Asynchronously registers the #NMSecretAgentOld with the NetworkManager secret
 * manager, indicating to NetworkManager that the agent is able to provide and
 * save secrets for connections on behalf of its user.
 *
 * It is a programmer error to attempt to register an agent that is already
 * registered, or in the process of registering.
 **/
void
nm_secret_agent_old_register_async (NMSecretAgentOld *self,
                                    GCancellable *cancellable,
                                    GAsyncReadyCallback callback,
                                    gpointer user_data)
{
	NMSecretAgentOldPrivate *priv;
	NMSecretAgentOldClass *class;
	GSimpleAsyncResult *simple;
	GError *error = NULL;

	g_return_if_fail (NM_IS_SECRET_AGENT_OLD (self));

	priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);

	g_return_if_fail (priv->registered == FALSE);
	g_return_if_fail (priv->registering == FALSE);
	g_return_if_fail (priv->bus != NULL);
	g_return_if_fail (priv->manager_proxy != NULL);

	/* Also make sure the subclass can actually respond to secrets requests */
	class = NM_SECRET_AGENT_OLD_GET_CLASS (self);
	g_return_if_fail (class->get_secrets != NULL);
	g_return_if_fail (class->save_secrets != NULL);
	g_return_if_fail (class->delete_secrets != NULL);

	simple = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                    nm_secret_agent_old_register_async);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (simple, cancellable);

	if (!check_nm_running (self, &error)) {
		g_simple_async_result_take_error (simple, error);
		g_simple_async_result_complete_in_idle (simple);
		g_object_unref (simple);
		return;
	}

	/* Export our secret agent interface before registering with the manager */
	if (!g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (priv->dbus_secret_agent),
	                                       priv->bus,
	                                       NM_DBUS_PATH_SECRET_AGENT,
	                                       &error)) {
		g_simple_async_result_take_error (simple, error);
		g_simple_async_result_complete_in_idle (simple);
		g_object_unref (simple);
		return;
	}

	priv->suppress_auto = FALSE;
	priv->registering = TRUE;

	nmdbus_agent_manager_call_register_with_capabilities (priv->manager_proxy,
	                                                      priv->identifier,
	                                                      priv->capabilities,
	                                                      NULL,
	                                                      reg_with_caps_cb, simple);
}

/**
 * nm_secret_agent_old_register_finish:
 * @self: a #NMSecretAgentOld
 * @result: the result passed to the #GAsyncReadyCallback
 * @error: return location for a #GError, or %NULL
 *
 * Gets the result of a call to nm_secret_agent_old_register_async().
 *
 * Returns: %TRUE if registration was successful, %FALSE on error.
 **/
gboolean
nm_secret_agent_old_register_finish (NMSecretAgentOld *self,
                                     GAsyncResult *result,
                                     GError **error)
{
	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self), nm_secret_agent_old_register_async), FALSE);

	if (g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (result), error))
		return FALSE;
	else
		return TRUE;
}

/**
 * nm_secret_agent_old_unregister:
 * @self: a #NMSecretAgentOld
 * @cancellable: a #GCancellable, or %NULL
 * @error: return location for a #GError, or %NULL
 *
 * Unregisters the #NMSecretAgentOld with the NetworkManager secret manager,
 * indicating to NetworkManager that the agent will no longer provide or
 * store secrets on behalf of this user.
 *
 * Returns: %TRUE if unregistration was successful, %FALSE on error
 **/
gboolean
nm_secret_agent_old_unregister (NMSecretAgentOld *self,
                                GCancellable *cancellable,
                                GError **error)
{
	NMSecretAgentOldPrivate *priv;
	gboolean success;

	g_return_val_if_fail (NM_IS_SECRET_AGENT_OLD (self), FALSE);

	priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);

	g_return_val_if_fail (priv->bus != NULL, FALSE);
	g_return_val_if_fail (priv->manager_proxy != NULL, FALSE);

	priv->suppress_auto = TRUE;

	success = nmdbus_agent_manager_call_unregister_sync (priv->manager_proxy, cancellable, error);
	if (error && *error)
		g_dbus_error_strip_remote_error (*error);
	_internal_unregister (self);

	return success;
}

static void
unregister_cb (GObject *proxy, GAsyncResult *result, gpointer user_data)
{
	GSimpleAsyncResult *simple = user_data;
	NMSecretAgentOld *self;
	GError *error = NULL;

	self = NM_SECRET_AGENT_OLD (g_async_result_get_source_object (G_ASYNC_RESULT (simple)));
	g_object_unref (self); /* drop extra ref added by get_source_object() */

	_internal_unregister (self);

	if (nmdbus_agent_manager_call_unregister_finish (NMDBUS_AGENT_MANAGER (proxy),
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
 * nm_secret_agent_old_unregister_async:
 * @self: a #NMSecretAgentOld
 * @cancellable: a #GCancellable, or %NULL
 * @callback: callback to call when the agent is unregistered
 * @user_data: data for @callback
 *
 * Asynchronously unregisters the #NMSecretAgentOld with the NetworkManager secret
 * manager, indicating to NetworkManager that the agent will no longer provide
 * or store secrets on behalf of this user.
 **/
void
nm_secret_agent_old_unregister_async (NMSecretAgentOld *self,
                                      GCancellable *cancellable,
                                      GAsyncReadyCallback callback,
                                      gpointer user_data)
{
	NMSecretAgentOldPrivate *priv;
	GSimpleAsyncResult *simple;
	GError *error = NULL;

	g_return_if_fail (NM_IS_SECRET_AGENT_OLD (self));

	priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);

	g_return_if_fail (priv->bus != NULL);
	g_return_if_fail (priv->manager_proxy != NULL);

	simple = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                    nm_secret_agent_old_unregister_async);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (simple, cancellable);

	if (!check_nm_running (self, &error)) {
		g_simple_async_result_take_error (simple, error);
		g_simple_async_result_complete_in_idle (simple);
		g_object_unref (simple);
		return;
	}

	priv->suppress_auto = TRUE;

	nmdbus_agent_manager_call_unregister (priv->manager_proxy, cancellable,
	                                      unregister_cb, simple);
}

/**
 * nm_secret_agent_old_unregister_finish:
 * @self: a #NMSecretAgentOld
 * @result: the result passed to the #GAsyncReadyCallback
 * @error: return location for a #GError, or %NULL
 *
 * Gets the result of a call to nm_secret_agent_old_unregister_async().
 *
 * Returns: %TRUE if unregistration was successful, %FALSE on error.
 **/
gboolean
nm_secret_agent_old_unregister_finish (NMSecretAgentOld *self,
                                       GAsyncResult *result,
                                       GError **error)
{
	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self), nm_secret_agent_old_unregister_async), FALSE);

	if (g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (result), error))
		return FALSE;
	else
		return TRUE;
}

/**
 * nm_secret_agent_old_get_registered:
 * @self: a #NMSecretAgentOld
 *
 * Returns: a %TRUE if the agent is registered, %FALSE if it is not.
 **/
gboolean
nm_secret_agent_old_get_registered (NMSecretAgentOld *self)
{
	g_return_val_if_fail (NM_IS_SECRET_AGENT_OLD (self), FALSE);

	return NM_SECRET_AGENT_OLD_GET_PRIVATE (self)->registered;
}

/*****************************************************************************/

/**
 * nm_secret_agent_old_get_secrets:
 * @self: a #NMSecretAgentOld
 * @connection: the #NMConnection for which we're asked secrets
 * @setting_name: the name of the secret setting
 * @hints: (array zero-terminated=1): hints to the agent
 * @flags: flags that modify the behavior of the request
 * @callback: (scope async): a callback, to be invoked when the operation is done
 * @user_data: (closure): caller-specific data to be passed to @callback
 *
 * Asynchronously retrieves secrets belonging to @connection for the
 * setting @setting_name.  @flags indicate specific behavior that the secret
 * agent should use when performing the request, for example returning only
 * existing secrets without user interaction, or requesting entirely new
 * secrets from the user.
 *
 * Virtual: get_secrets
 */
void
nm_secret_agent_old_get_secrets (NMSecretAgentOld *self,
                                 NMConnection *connection,
                                 const char *setting_name,
                                 const char **hints,
                                 NMSecretAgentGetSecretsFlags flags,
                                 NMSecretAgentOldGetSecretsFunc callback,
                                 gpointer user_data)
{
	g_return_if_fail (NM_IS_SECRET_AGENT_OLD (self));
	g_return_if_fail (NM_IS_CONNECTION (connection));
	g_return_if_fail (nm_connection_get_path (connection));
	g_return_if_fail (setting_name != NULL);
	g_return_if_fail (strlen (setting_name) > 0);
	g_return_if_fail (!(flags & NM_SECRET_AGENT_GET_SECRETS_FLAG_ONLY_SYSTEM));
	g_return_if_fail (!(flags & NM_SECRET_AGENT_GET_SECRETS_FLAG_NO_ERRORS));
	g_return_if_fail (callback != NULL);

	NM_SECRET_AGENT_OLD_GET_CLASS (self)->get_secrets (self,
	                                               connection,
	                                               nm_connection_get_path (connection),
	                                               setting_name,
	                                               hints,
	                                               flags,
	                                               callback,
	                                               user_data);
}

/**
 * nm_secret_agent_old_save_secrets:
 * @self: a #NMSecretAgentOld
 * @connection: a #NMConnection
 * @callback: (scope async): a callback, to be invoked when the operation is done
 * @user_data: (closure): caller-specific data to be passed to @callback
 *
 * Asynchronously ensures that all secrets inside @connection are stored to
 * disk.
 *
 * Virtual: save_secrets
 */
void
nm_secret_agent_old_save_secrets (NMSecretAgentOld *self,
                                  NMConnection *connection,
                                  NMSecretAgentOldSaveSecretsFunc callback,
                                  gpointer user_data)
{
	g_return_if_fail (NM_IS_SECRET_AGENT_OLD (self));
	g_return_if_fail (NM_IS_CONNECTION (connection));
	g_return_if_fail (nm_connection_get_path (connection));

	NM_SECRET_AGENT_OLD_GET_CLASS (self)->save_secrets (self,
	                                                connection,
	                                                nm_connection_get_path (connection),
	                                                callback,
	                                                user_data);
}

/**
 * nm_secret_agent_old_delete_secrets:
 * @self: a #NMSecretAgentOld
 * @connection: a #NMConnection
 * @callback: (scope async): a callback, to be invoked when the operation is done
 * @user_data: (closure): caller-specific data to be passed to @callback
 *
 * Asynchronously asks the agent to delete all saved secrets belonging to
 * @connection.
 *
 * Virtual: delete_secrets
 */
void
nm_secret_agent_old_delete_secrets (NMSecretAgentOld *self,
                                    NMConnection *connection,
                                    NMSecretAgentOldDeleteSecretsFunc callback,
                                    gpointer user_data)
{
	g_return_if_fail (NM_IS_SECRET_AGENT_OLD (self));
	g_return_if_fail (NM_IS_CONNECTION (connection));
	g_return_if_fail (nm_connection_get_path (connection));

	NM_SECRET_AGENT_OLD_GET_CLASS (self)->delete_secrets (self,
	                                                  connection,
	                                                  nm_connection_get_path (connection),
	                                                  callback,
	                                                  user_data);
}

/*****************************************************************************/

static gboolean
validate_identifier (const char *identifier)
{
	const char *p = identifier;
	size_t id_len;

	/* Length between 3 and 255 characters inclusive */
	id_len = strlen (identifier);
	if (id_len < 3 || id_len > 255)
		return FALSE;

	if ((identifier[0] == '.') || (identifier[id_len - 1] == '.'))
		return FALSE;

	/* FIXME: do complete validation here */
	while (p && *p) {
		if (!g_ascii_isalnum (*p) && (*p != '_') && (*p != '-') && (*p != '.'))
			return FALSE;
		if ((*p == '.') && (*(p + 1) == '.'))
			return FALSE;
		p++;
	}

	return TRUE;
}

static void
nm_secret_agent_old_init (NMSecretAgentOld *self)
{
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);

	priv->dbus_secret_agent = nmdbus_secret_agent_skeleton_new ();
	_nm_dbus_bind_properties (self, priv->dbus_secret_agent);
	_nm_dbus_bind_methods (self, priv->dbus_secret_agent,
	                       "GetSecrets", impl_secret_agent_old_get_secrets,
	                       "CancelGetSecrets", impl_secret_agent_old_cancel_get_secrets,
	                       "DeleteSecrets", impl_secret_agent_old_delete_secrets,
	                       "SaveSecrets", impl_secret_agent_old_save_secrets,
	                       NULL);
}

static void
init_common (NMSecretAgentOld *self)
{
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);

	priv->private_bus = _nm_dbus_is_connection_private (priv->bus);

	if (priv->private_bus == FALSE) {
		priv->session_bus = _nm_dbus_bus_type () == G_BUS_TYPE_SESSION;

		g_signal_connect (priv->manager_proxy, "notify::g-name-owner",
		                  G_CALLBACK (name_owner_changed), self);
	}
}

static gboolean
init_sync (GInitable *initable, GCancellable *cancellable, GError **error)
{
	NMSecretAgentOld *self = NM_SECRET_AGENT_OLD (initable);
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);

	priv->bus = _nm_dbus_new_connection (cancellable, error);
	if (!priv->bus)
		return FALSE;

	priv->manager_proxy = nmdbus_agent_manager_proxy_new_sync (priv->bus,
	                                                             G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES
	                                                           | G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START,
	                                                           NM_DBUS_SERVICE,
	                                                           NM_DBUS_PATH_AGENT_MANAGER,
	                                                           cancellable,
	                                                           error);
	if (!priv->manager_proxy)
		return FALSE;

	init_common (self);

	if (priv->auto_register)
		return nm_secret_agent_old_register (self, cancellable, error);
	else
		return TRUE;
}

typedef struct {
	NMSecretAgentOld *self;
	GCancellable *cancellable;
	GSimpleAsyncResult *simple;
} NMSecretAgentOldInitData;

static void
init_async_complete (NMSecretAgentOldInitData *init_data, GError *error)
{
	if (!error)
		g_simple_async_result_set_op_res_gboolean (init_data->simple, TRUE);
	else
		g_simple_async_result_take_error (init_data->simple, error);

	g_simple_async_result_complete_in_idle (init_data->simple);

	g_object_unref (init_data->simple);
	g_clear_object (&init_data->cancellable);
	g_slice_free (NMSecretAgentOldInitData, init_data);
}

static void
init_async_registered (GObject *object, GAsyncResult *result, gpointer user_data)
{
	NMSecretAgentOld *self = NM_SECRET_AGENT_OLD (object);
	NMSecretAgentOldInitData *init_data = user_data;
	GError *error = NULL;

	nm_secret_agent_old_register_finish (self, result, &error);
	init_async_complete (init_data, error);
}

static void
init_async_got_proxy (GObject *object, GAsyncResult *result, gpointer user_data)
{
	NMSecretAgentOldInitData *init_data = user_data;
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (init_data->self);
	GError *error = NULL;

	priv->manager_proxy = nmdbus_agent_manager_proxy_new_finish (result, &error);
	if (!priv->manager_proxy) {
		init_async_complete (init_data, error);
		return;
	}

	init_common (init_data->self);

	if (priv->auto_register) {
		nm_secret_agent_old_register_async (init_data->self, init_data->cancellable,
		                                    init_async_registered, init_data);
	} else
		init_async_complete (init_data, NULL);
}

static void
init_async_got_bus (GObject *initable, GAsyncResult *result, gpointer user_data)
{
	NMSecretAgentOldInitData *init_data = user_data;
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (init_data->self);
	GError *error = NULL;

	priv->bus = _nm_dbus_new_connection_finish (result, &error);
	if (!priv->bus) {
		init_async_complete (init_data, error);
		return;
	}

	nmdbus_agent_manager_proxy_new (priv->bus,
	                                  G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES
	                                | G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START,
	                                NM_DBUS_SERVICE,
	                                NM_DBUS_PATH_AGENT_MANAGER,
	                                init_data->cancellable,
	                                init_async_got_proxy, init_data);
}

static void
init_async (GAsyncInitable *initable, int io_priority,
            GCancellable *cancellable, GAsyncReadyCallback callback,
            gpointer user_data)
{
	NMSecretAgentOld *self = NM_SECRET_AGENT_OLD (initable);
	NMSecretAgentOldInitData *init_data;

	init_data = g_slice_new (NMSecretAgentOldInitData);
	init_data->self = self;
	init_data->cancellable = cancellable ? g_object_ref (cancellable) : NULL;

	init_data->simple = g_simple_async_result_new (G_OBJECT (initable), callback,
	                                               user_data, init_async);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (init_data->simple, cancellable);

	_nm_dbus_new_connection_async (cancellable, init_async_got_bus, init_data);
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
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_IDENTIFIER:
		g_value_set_string (value, priv->identifier);
		break;
	case PROP_AUTO_REGISTER:
		g_value_set_boolean (value, priv->auto_register);
		break;
	case PROP_REGISTERED:
		g_value_set_boolean (value, priv->registered);
		break;
	case PROP_CAPABILITIES:
		g_value_set_flags (value, priv->capabilities);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object,
              guint prop_id,
              const GValue *value,
              GParamSpec *pspec)
{
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (object);
	const char *identifier;

	switch (prop_id) {
	case PROP_IDENTIFIER:
		identifier = g_value_get_string (value);

		g_return_if_fail (validate_identifier (identifier));

		g_free (priv->identifier);
		priv->identifier = g_strdup (identifier);
		break;
	case PROP_AUTO_REGISTER:
		priv->auto_register = g_value_get_boolean (value);
		break;
	case PROP_CAPABILITIES:
		priv->capabilities = g_value_get_flags (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
dispose (GObject *object)
{
	NMSecretAgentOld *self = NM_SECRET_AGENT_OLD (object);
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);

	if (priv->registered)
		nm_secret_agent_old_unregister_async (self, NULL, NULL, NULL);

	g_clear_pointer (&priv->identifier, g_free);

	while (priv->pending_gets)
		get_secrets_info_finalize (self, priv->pending_gets->data);

	g_signal_handlers_disconnect_matched (priv->dbus_secret_agent, G_SIGNAL_MATCH_DATA,
	                                      0, 0, NULL, NULL, self);
	g_object_unref (priv->dbus_secret_agent);

	g_clear_object (&priv->manager_proxy);
	g_clear_object (&priv->bus);

	G_OBJECT_CLASS (nm_secret_agent_old_parent_class)->dispose (object);
}

static void
nm_secret_agent_old_class_init (NMSecretAgentOldClass *class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (class);

	g_type_class_add_private (class, sizeof (NMSecretAgentOldPrivate));

	/* Virtual methods */
	object_class->dispose = dispose;
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	/**
	 * NMSecretAgentOld:identifier:
	 *
	 * Identifies this agent; only one agent in each user session may use the
	 * same identifier.  Identifier formatting follows the same rules as
	 * D-Bus bus names with the exception that the ':' character is not
	 * allowed.  The valid set of characters is "[A-Z][a-z][0-9]_-." and the
	 * identifier is limited in length to 255 characters with a minimum
	 * of 3 characters.  An example valid identifier is 'org.gnome.nm-applet'
	 * (without quotes).
	 **/
	g_object_class_install_property
		(object_class, PROP_IDENTIFIER,
		 g_param_spec_string (NM_SECRET_AGENT_OLD_IDENTIFIER, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_CONSTRUCT_ONLY |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSecretAgentOld:auto-register:
	 *
	 * If %TRUE (the default), the agent will always be registered when
	 * NetworkManager is running; if NetworkManager exits and restarts, the
	 * agent will re-register itself automatically.
	 *
	 * In particular, if this property is %TRUE at construct time, then the
	 * agent will register itself with NetworkManager during
	 * construction/initialization, and initialization will fail with an error
	 * if the agent is unable to register itself.
	 *
	 * If the property is %FALSE, the agent will not automatically register with
	 * NetworkManager, and nm_secret_agent_old_register() or
	 * nm_secret_agent_old_register_async() must be called to register it.
	 *
	 * Calling nm_secret_agent_old_unregister() will suppress auto-registration
	 * until nm_secret_agent_old_register() is called, which re-enables
	 * auto-registration. This ensures that the agent remains un-registered when
	 * you expect it to be unregistered.
	 **/
	g_object_class_install_property
		(object_class, PROP_AUTO_REGISTER,
		 g_param_spec_boolean (NM_SECRET_AGENT_OLD_AUTO_REGISTER, "", "",
		                       TRUE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSecretAgentOld:registered:
	 *
	 * %TRUE if the agent is registered with NetworkManager, %FALSE if not.
	 **/
	g_object_class_install_property
		(object_class, PROP_REGISTERED,
		 g_param_spec_boolean (NM_SECRET_AGENT_OLD_REGISTERED, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSecretAgentOld:capabilities:
	 *
	 * A bitfield of %NMSecretAgentCapabilities.
	 **/
	g_object_class_install_property
		(object_class, PROP_CAPABILITIES,
		 g_param_spec_flags (NM_SECRET_AGENT_OLD_CAPABILITIES, "", "",
		                     NM_TYPE_SECRET_AGENT_CAPABILITIES,
		                     NM_SECRET_AGENT_CAPABILITY_NONE,
		                     G_PARAM_READWRITE |
		                     G_PARAM_CONSTRUCT |
		                     G_PARAM_STATIC_STRINGS));
}

static void
nm_secret_agent_old_initable_iface_init (GInitableIface *iface)
{
	iface->init = init_sync;
}

static void
nm_secret_agent_old_async_initable_iface_init (GAsyncInitableIface *iface)
{
	iface->init_async = init_async;
	iface->init_finish = init_finish;
}
