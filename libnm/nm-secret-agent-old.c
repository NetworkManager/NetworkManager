// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2010 - 2011 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-secret-agent-old.h"

#include "c-list/src/c-list.h"
#include "nm-core-internal.h"
#include "nm-dbus-helpers.h"
#include "nm-dbus-interface.h"
#include "nm-enum-types.h"
#include "nm-glib-aux/nm-dbus-aux.h"
#include "nm-glib-aux/nm-time-utils.h"
#include "nm-simple-connection.h"

#include "introspection/org.freedesktop.NetworkManager.SecretAgent.h"
#include "introspection/org.freedesktop.NetworkManager.AgentManager.h"

#define REGISTER_RETRY_TIMEOUT_MSEC 2000

/*****************************************************************************/

typedef struct {
	char *path;
	char *setting_name;
	GDBusMethodInvocation *context;
	CList gsi_lst;
} GetSecretsInfo;

NM_GOBJECT_PROPERTIES_DEFINE (NMSecretAgentOld,
	PROP_IDENTIFIER,
	PROP_AUTO_REGISTER,
	PROP_REGISTERED,
	PROP_CAPABILITIES,
);

typedef struct {
	GDBusConnection *bus;
	NMDBusAgentManager *manager_proxy;
	NMDBusSecretAgent *dbus_secret_agent;

	/* GetSecretsInfo structs of in-flight GetSecrets requests */
	CList gsi_lst_head;

	char *identifier;

	NMSecretAgentCapabilities capabilities;

	gint64 registering_timeout_msec;
	guint registering_try_count;

	bool registered:1;
	bool session_bus:1;
	bool auto_register:1;
	bool suppress_auto:1;
} NMSecretAgentOldPrivate;

static void nm_secret_agent_old_initable_iface_init (GInitableIface *iface);
static void nm_secret_agent_old_async_initable_iface_init (GAsyncInitableIface *iface);

G_DEFINE_ABSTRACT_TYPE_WITH_CODE (NMSecretAgentOld, nm_secret_agent_old, G_TYPE_OBJECT,
                                  G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, nm_secret_agent_old_initable_iface_init);
                                  G_IMPLEMENT_INTERFACE (G_TYPE_ASYNC_INITABLE, nm_secret_agent_old_async_initable_iface_init);
                                  )

#define NM_SECRET_AGENT_OLD_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SECRET_AGENT_OLD, NMSecretAgentOldPrivate))

/*****************************************************************************/

#define _NMLOG(level, ...) \
	NML_DBUS_LOG((level), \
	              "secret-agent["NM_HASH_OBFUSCATE_PTR_FMT"]: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
	              NM_HASH_OBFUSCATE_PTR (self) \
	              _NM_UTILS_MACRO_REST (__VA_ARGS__))

/*****************************************************************************/

static void _register_call_cb (GObject *proxy,
                               GAsyncResult *result,
                               gpointer user_data);

/*****************************************************************************/

static void
_internal_unregister (NMSecretAgentOld *self)
{
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);

	if (priv->registered) {
		g_dbus_interface_skeleton_unexport (G_DBUS_INTERFACE_SKELETON (priv->dbus_secret_agent));
		priv->registered = FALSE;
		priv->registering_timeout_msec = 0;
		_notify (self, PROP_REGISTERED);
	}
}

static void
get_secrets_info_free (GetSecretsInfo *info)
{
	nm_assert (info);

	c_list_unlink_stale (&info->gsi_lst);

	g_free (info->path);
	g_free (info->setting_name);
	g_slice_free (GetSecretsInfo, info);
}

static gboolean
should_auto_register (NMSecretAgentOld *self)
{
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);

	return (   priv->auto_register
	        && !priv->suppress_auto
	        && !priv->registered
	        && priv->registering_timeout_msec == 0);
}

static void
name_owner_changed (GObject *proxy,
                    GParamSpec *pspec,
                    gpointer user_data)
{
	NMSecretAgentOld *self = NM_SECRET_AGENT_OLD (user_data);
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);
	gs_free char *owner = NULL;
	GetSecretsInfo *info;

	owner = g_dbus_proxy_get_name_owner (G_DBUS_PROXY (proxy));

	_LOGT ("name owner changed: %s%s%s", NM_PRINT_FMT_QUOTE_STRING (owner));

	if (owner) {
		if (should_auto_register (self))
			nm_secret_agent_old_register_async (self, NULL, NULL, NULL);
	} else {
		while ((info = c_list_first_entry (&priv->gsi_lst_head, GetSecretsInfo, gsi_lst))) {
			c_list_unlink (&info->gsi_lst);
			NM_SECRET_AGENT_OLD_GET_CLASS (self)->cancel_get_secrets (self,
			                                                          info->path,
			                                                          info->setting_name);
		}

		_internal_unregister (self);
	}
}

static gboolean
verify_sender (NMSecretAgentOld *self,
               GDBusMethodInvocation *context,
               GError **error)
{
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);
	gs_free char *owner = NULL;
	const char *sender;
	guint32 sender_uid;
	gs_unref_variant GVariant *ret = NULL;
	gs_free_error GError *local = NULL;

	g_return_val_if_fail (context != NULL, FALSE);

	/* Verify that the sender is the same as NetworkManager's bus name owner. */

	owner = g_dbus_proxy_get_name_owner (G_DBUS_PROXY (priv->manager_proxy));
	if (!owner) {
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
		return FALSE;
	}

	if (!nm_streq (sender, owner)) {
		g_set_error_literal (error,
		                     NM_SECRET_AGENT_ERROR,
		                     NM_SECRET_AGENT_ERROR_PERMISSION_DENIED,
		                     "Request sender does not match NetworkManager bus name owner.");
		return FALSE;
	}

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
		gs_free char *remote_error = NULL;

		remote_error = g_dbus_error_get_remote_error (local);
		g_dbus_error_strip_remote_error (local);
		g_set_error (error,
		             NM_SECRET_AGENT_ERROR,
		             NM_SECRET_AGENT_ERROR_PERMISSION_DENIED,
		             "Failed to request unix user: (%s) %s.",
		             remote_error ?: "",
		             local->message);
		return FALSE;
	}
	g_variant_get (ret, "(u)", &sender_uid);

	/* We only accept requests from NM, which always runs as root */
	if (sender_uid != 0) {
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
	gs_unref_object NMConnection *connection = NULL;
	gs_free_error GError *local = NULL;

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
	connection = _nm_simple_connection_new_from_dbus (connection_dict, NM_SETTING_PARSE_FLAGS_BEST_EFFORT, &local);
	if (!connection) {
		g_set_error (error,
		             NM_SECRET_AGENT_ERROR,
		             NM_SECRET_AGENT_ERROR_INVALID_CONNECTION,
		             "Invalid connection: %s", local->message);
		return FALSE;
	}

	nm_connection_set_path (connection, connection_path);
	NM_SET_OUT (out_connection, g_steal_pointer (&connection));
	return TRUE;
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

	get_secrets_info_free (info);
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
	gs_unref_object NMConnection *connection = NULL;
	GetSecretsInfo *info;

	/* Make sure the request comes from NetworkManager and is valid */
	if (!verify_request (self, context, connection_dict, connection_path, &connection, &error)) {
		g_dbus_method_invocation_take_error (context, error);
		return;
	}

	info = g_slice_new (GetSecretsInfo);
	*info = (GetSecretsInfo) {
		.path = g_strdup (connection_path),
		.setting_name = g_strdup (setting_name),
		.context = context,
	};
	c_list_link_tail (&priv->gsi_lst_head, &info->gsi_lst);

	NM_SECRET_AGENT_OLD_GET_CLASS (self)->get_secrets (self,
	                                                   connection,
	                                                   connection_path,
	                                                   setting_name,
	                                                   (const char **) hints,
	                                                   flags,
	                                                   get_secrets_cb,
	                                                   info);
}

static GetSecretsInfo *
find_get_secrets_info (NMSecretAgentOldPrivate *priv,
                       const char *path,
                       const char *setting_name)
{
	GetSecretsInfo *info;

	c_list_for_each_entry (info, &priv->gsi_lst_head, gsi_lst) {
		if (   nm_streq0 (path, info->path)
		    && nm_streq0 (setting_name, info->setting_name))
			return info;
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

	info = find_get_secrets_info (priv, connection_path, setting_name);
	if (!info) {
		g_dbus_method_invocation_return_error (context,
		                                       NM_SECRET_AGENT_ERROR,
		                                       NM_SECRET_AGENT_ERROR_FAILED,
		                                       "No secrets request in progress for this connection.");
		return;
	}

	c_list_unlink (&info->gsi_lst);

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
	gs_unref_object NMConnection *connection = NULL;
	GError *error = NULL;

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
	gs_unref_object NMConnection *connection = NULL;
	GError *error = NULL;

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
}

/*****************************************************************************/

static gboolean
check_nm_running (NMSecretAgentOld *self, GError **error)
{
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);
	gs_free char *owner = NULL;

	owner = g_dbus_proxy_get_name_owner (G_DBUS_PROXY (priv->manager_proxy));
	if (owner)
		return TRUE;

	g_set_error (error, NM_SECRET_AGENT_ERROR, NM_SECRET_AGENT_ERROR_FAILED,
	             "NetworkManager is not running");
	return FALSE;
}

/*****************************************************************************/

static gboolean
_register_should_retry (NMSecretAgentOldPrivate *priv,
                        guint *out_timeout_msec)
{
	guint timeout_msec;

	if (priv->registering_try_count++ == 0)
		timeout_msec = 0;
	else if (nm_utils_get_monotonic_timestamp_msec () < priv->registering_timeout_msec)
		timeout_msec = 1ULL * (1ULL << NM_MIN (7, priv->registering_try_count));
	else
		return FALSE;

	*out_timeout_msec = timeout_msec;
	return TRUE;
}

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
	g_return_val_if_fail (priv->registering_timeout_msec == 0, FALSE);
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

	priv->registering_timeout_msec = nm_utils_get_monotonic_timestamp_msec () + REGISTER_RETRY_TIMEOUT_MSEC;
	priv->registering_try_count = 0;

	while (TRUE) {
		gs_free_error GError *local = NULL;
		gs_free char *dbus_error = NULL;

		nmdbus_agent_manager_call_register_with_capabilities_sync (priv->manager_proxy,
		                                                           priv->identifier,
		                                                           priv->capabilities,
		                                                           cancellable,
		                                                           &local);
		if (nm_dbus_error_is (local, NM_DBUS_ERROR_NAME_UNKNOWN_METHOD)) {
			guint timeout_msec;

			if (_register_should_retry (priv, &timeout_msec)) {
				if (timeout_msec > 0)
					g_usleep (timeout_msec * 1000LU);
				continue;
			}
		}

		priv->registering_timeout_msec = 0;

		if (local) {
			g_dbus_error_strip_remote_error (local);
			g_propagate_error (error, g_steal_pointer (&local));
			_internal_unregister (self);
			return FALSE;
		}

		priv->registered = TRUE;
		_notify (self, PROP_REGISTERED);
		return TRUE;
	}
}

/*****************************************************************************/

typedef struct {
	GCancellable *cancellable;
	GSource *timeout_source;
	gulong cancellable_signal_id;
} RegisterData;

static void
_register_data_free (RegisterData *register_data)
{
	nm_clear_g_cancellable_disconnect (register_data->cancellable, &register_data->cancellable_signal_id);
	nm_clear_g_source_inst (&register_data->timeout_source);
	g_clear_object (&register_data->cancellable);
	nm_g_slice_free (register_data);
}

static gboolean
_register_retry_cb (gpointer user_data)
{
	gs_unref_object GTask *task = user_data;
	NMSecretAgentOld *self = g_task_get_source_object (task);
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);
	GCancellable *cancellable;

	_LOGT ("register: retry registration...");

	g_task_set_task_data (task, NULL, NULL);

	cancellable = g_task_get_cancellable (task);

	nmdbus_agent_manager_call_register_with_capabilities (priv->manager_proxy,
	                                                      priv->identifier,
	                                                      priv->capabilities,
	                                                      cancellable,
	                                                      _register_call_cb,
	                                                      g_steal_pointer (&task));
	return G_SOURCE_REMOVE;
}

static void
_register_cancelled_cb (GCancellable *cancellable,
                        gpointer user_data)
{
	gs_unref_object GTask *task = user_data;
	NMSecretAgentOld *self = g_task_get_source_object (task);
	RegisterData *register_data = g_task_get_task_data (task);
	GError *error = NULL;

	nm_clear_g_signal_handler (register_data->cancellable, &register_data->cancellable_signal_id);
	g_task_set_task_data (task, NULL, NULL);

	_LOGT ("register: registration cancelled. Stop waiting...");

	nm_utils_error_set_cancelled (&error, FALSE, NULL);
	g_task_return_error (task, error);
}

static void
_register_call_cb (GObject *proxy,
                   GAsyncResult *result,
                   gpointer user_data)
{
	gs_unref_object GTask *task = user_data;
	NMSecretAgentOld *self = g_task_get_source_object (task);
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);
	gs_free_error GError *error = NULL;

	nmdbus_agent_manager_call_register_with_capabilities_finish (NMDBUS_AGENT_MANAGER (proxy), result, &error);

	if (nm_utils_error_is_cancelled (error, FALSE)) {
		/* FIXME: we should unregister right away. For now, don't do that, likely the
		 * application is anyway about to exit. */
	} else if (nm_dbus_error_is (error, NM_DBUS_ERROR_NAME_UNKNOWN_METHOD)) {
		gboolean already_cancelled = FALSE;
		RegisterData *register_data;
		guint timeout_msec;

		if (!_register_should_retry (priv, &timeout_msec))
			goto done;

		_LOGT ("register: registration failed with error \"%s\". Retry in %u msec...", error->message, timeout_msec);
		nm_assert (G_IS_TASK (task));
		nm_assert (!g_task_get_task_data (task));

		register_data = g_slice_new (RegisterData);

		*register_data = (RegisterData) {
			.cancellable = nm_g_object_ref (g_task_get_cancellable (task)),
		};

		g_task_set_task_data (task,
		                      register_data,
		                      (GDestroyNotify) _register_data_free);

		if (register_data->cancellable) {
			register_data->cancellable_signal_id = g_cancellable_connect (register_data->cancellable,
			                                                              G_CALLBACK (_register_cancelled_cb),
			                                                              task,
			                                                              NULL);
			if (register_data->cancellable_signal_id == 0)
				already_cancelled = TRUE;
		}

		if (!already_cancelled) {
			register_data->timeout_source = nm_g_source_attach (nm_g_timeout_source_new (timeout_msec,
			                                                                             g_task_get_priority (task),
			                                                                             _register_retry_cb,
			                                                                             task,
			                                                                             NULL),
			                                                    g_task_get_context (task));
		}

		/* The reference of the task is owned by the _register_cancelled_cb and _register_retry_cb actions.
		 * Whichever completes first, will consume it. */
		g_steal_pointer (&task);
		return;
	}

done:
	priv->registering_timeout_msec = 0;

	if (error) {
		_LOGT ("register: registration failed with error \"%s\"", error->message);
		g_dbus_error_strip_remote_error (error);
		_internal_unregister (self);
		g_task_return_error (task, g_steal_pointer (&error));
		return;
	}

	_LOGT ("register: registration succeeded");
	priv->registered = TRUE;
	_notify (self, PROP_REGISTERED);

	g_task_return_boolean (task, TRUE);
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
	gs_unref_object GTask *task = NULL;
	gs_free_error GError *error = NULL;

	g_return_if_fail (NM_IS_SECRET_AGENT_OLD (self));

	priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);

	g_return_if_fail (priv->registered == FALSE);
	g_return_if_fail (priv->registering_timeout_msec == 0);
	g_return_if_fail (priv->bus != NULL);
	g_return_if_fail (priv->manager_proxy != NULL);

	/* Also make sure the subclass can actually respond to secrets requests */
	class = NM_SECRET_AGENT_OLD_GET_CLASS (self);
	g_return_if_fail (class->get_secrets != NULL);
	g_return_if_fail (class->save_secrets != NULL);
	g_return_if_fail (class->delete_secrets != NULL);

	task = nm_g_task_new (self, cancellable, nm_secret_agent_old_register_async, callback, user_data);

	if (!check_nm_running (self, &error)) {
		_LOGT ("register: failed because NetworkManager is not running");
		g_task_return_error (task, g_steal_pointer (&error));
		return;
	}

	/* Export our secret agent interface before registering with the manager */
	if (!g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (priv->dbus_secret_agent),
	                                       priv->bus,
	                                       NM_DBUS_PATH_SECRET_AGENT,
	                                       &error)) {
		_LOGT ("register: failed to export D-Bus service: %s", error->message);
		g_task_return_error (task, g_steal_pointer (&error));
		return;
	}

	priv->suppress_auto = FALSE;
	priv->registering_timeout_msec = nm_utils_get_monotonic_timestamp_msec () + REGISTER_RETRY_TIMEOUT_MSEC;
	priv->registering_try_count = 0;

	_LOGT ("register: starting asynchronous registration...");
	nmdbus_agent_manager_call_register_with_capabilities (priv->manager_proxy,
	                                                      priv->identifier,
	                                                      priv->capabilities,
	                                                      cancellable,
	                                                      _register_call_cb,
	                                                      g_steal_pointer (&task));
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
	g_return_val_if_fail (NM_IS_SECRET_AGENT_OLD (self), FALSE);
	g_return_val_if_fail (nm_g_task_is_valid (result, self, nm_secret_agent_old_register_async), FALSE);

	return g_task_propagate_boolean (G_TASK (result), error);
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
	gs_unref_object GTask *task = user_data;
	NMSecretAgentOld *self = g_task_get_source_object (task);
	gs_free_error GError *error = NULL;

	_internal_unregister (self);

	if (!nmdbus_agent_manager_call_unregister_finish (NMDBUS_AGENT_MANAGER (proxy),
	                                                  result,
	                                                  &error)) {
		g_dbus_error_strip_remote_error (error);
		g_task_return_error (task, g_steal_pointer (&error));
		return;
	}

	g_task_return_boolean (task, TRUE);
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
	gs_unref_object GTask *task = NULL;
	gs_free_error GError *error = NULL;

	g_return_if_fail (NM_IS_SECRET_AGENT_OLD (self));

	priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);

	g_return_if_fail (priv->bus != NULL);
	g_return_if_fail (priv->manager_proxy != NULL);

	task = nm_g_task_new (self, cancellable, nm_secret_agent_old_unregister_async, callback, user_data);

	if (!check_nm_running (self, &error)) {
		g_task_return_error (task, g_steal_pointer (&error));
		return;
	}

	priv->suppress_auto = TRUE;

	nmdbus_agent_manager_call_unregister (priv->manager_proxy,
	                                      cancellable,
	                                      unregister_cb,
	                                      g_steal_pointer (&task));
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
	g_return_val_if_fail (NM_IS_SECRET_AGENT_OLD (self), FALSE);
	g_return_val_if_fail (nm_g_task_is_valid (result, self, nm_secret_agent_old_unregister_async), FALSE);

	return g_task_propagate_boolean (G_TASK (result), error);
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
 * nm_secret_agent_old_get_secrets: (virtual get_secrets):
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
	g_return_if_fail (setting_name && setting_name[0]);
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
 * nm_secret_agent_old_save_secrets: (virtual save_secrets):
 * @self: a #NMSecretAgentOld
 * @connection: a #NMConnection
 * @callback: (scope async): a callback, to be invoked when the operation is done
 * @user_data: (closure): caller-specific data to be passed to @callback
 *
 * Asynchronously ensures that all secrets inside @connection are stored to
 * disk.
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
 * nm_secret_agent_old_delete_secrets: (virtual delete_secrets):
 * @self: a #NMSecretAgentOld
 * @connection: a #NMConnection
 * @callback: (scope async): a callback, to be invoked when the operation is done
 * @user_data: (closure): caller-specific data to be passed to @callback
 *
 * Asynchronously asks the agent to delete all saved secrets belonging to
 * @connection.
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

/*****************************************************************************/

static void
init_common (NMSecretAgentOld *self)
{
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);

	priv->session_bus = _nm_dbus_bus_type () == G_BUS_TYPE_SESSION;

	g_signal_connect (priv->manager_proxy, "notify::g-name-owner",
	                  G_CALLBACK (name_owner_changed), self);
}

static void
init_async_registered (GObject *object, GAsyncResult *result, gpointer user_data)
{
	gs_unref_object GTask *task = user_data;
	NMSecretAgentOld *self = g_task_get_source_object (task);
	GError *error = NULL;

	nm_secret_agent_old_register_finish (self, result, &error);

	if (error)
		g_task_return_error (task, error);
	else
		g_task_return_boolean (task, TRUE);
}

static void
init_async_got_proxy (GObject *object, GAsyncResult *result, gpointer user_data)
{
	gs_unref_object GTask *task = user_data;
	NMSecretAgentOld *self = g_task_get_source_object (task);
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);
	GError *error = NULL;

	priv->manager_proxy = nmdbus_agent_manager_proxy_new_finish (result, &error);
	if (!priv->manager_proxy) {
		g_task_return_error (task, error);
		return;
	}

	init_common (self);

	if (!priv->auto_register) {
		g_task_return_boolean (task, TRUE);
		return;
	}

	nm_secret_agent_old_register_async (self,
	                                    g_task_get_cancellable (task),
	                                    init_async_registered,
	                                    task);
	g_steal_pointer (&task);
}

static void
init_async_got_bus (GObject *initable, GAsyncResult *result, gpointer user_data)
{
	gs_unref_object GTask *task = user_data;
	NMSecretAgentOld *self = g_task_get_source_object (task);
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);
	GError *error = NULL;

	priv->bus = g_bus_get_finish (result, &error);
	if (!priv->bus) {
		g_task_return_error (task, error);
		return;
	}

	nmdbus_agent_manager_proxy_new (priv->bus,
	                                  G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES
	                                | G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START,
	                                NM_DBUS_SERVICE,
	                                NM_DBUS_PATH_AGENT_MANAGER,
	                                g_task_get_cancellable (task),
	                                init_async_got_proxy,
	                                task);
	g_steal_pointer (&task);
}

/*****************************************************************************/

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

/*****************************************************************************/

static void
nm_secret_agent_old_init (NMSecretAgentOld *self)
{
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);

	_LOGT ("create new instance");

	c_list_init (&priv->gsi_lst_head);
	priv->dbus_secret_agent = nmdbus_secret_agent_skeleton_new ();
	_nm_dbus_bind_properties (self, priv->dbus_secret_agent);
	_nm_dbus_bind_methods (self, priv->dbus_secret_agent,
	                       "GetSecrets", impl_secret_agent_old_get_secrets,
	                       "CancelGetSecrets", impl_secret_agent_old_cancel_get_secrets,
	                       "DeleteSecrets", impl_secret_agent_old_delete_secrets,
	                       "SaveSecrets", impl_secret_agent_old_save_secrets,
	                       NULL);
}

static gboolean
init_sync (GInitable *initable, GCancellable *cancellable, GError **error)
{
	NMSecretAgentOld *self = NM_SECRET_AGENT_OLD (initable);
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);

	_LOGT ("init-sync");

	priv->bus = g_bus_get_sync (_nm_dbus_bus_type (), cancellable, error);
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

static void
init_async (GAsyncInitable *initable, int io_priority,
            GCancellable *cancellable, GAsyncReadyCallback callback,
            gpointer user_data)
{
	NMSecretAgentOld *self = NM_SECRET_AGENT_OLD (initable);
	GTask *task;

	_LOGT ("init-async starting...");

	task = g_task_new (self, cancellable, callback, user_data);
	g_task_set_priority (task, io_priority);

	g_bus_get (_nm_dbus_bus_type (),
	           cancellable,
	           init_async_got_bus,
	           task);
}

static void
dispose (GObject *object)
{
	NMSecretAgentOld *self = NM_SECRET_AGENT_OLD (object);
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);
	GetSecretsInfo *info;

	_LOGT ("disposing");

	if (priv->registered) {
		priv->registered = FALSE;
		nm_secret_agent_old_unregister_async (self, NULL, NULL, NULL);
	}

	nm_clear_g_free (&priv->identifier);

	while ((info = c_list_first_entry (&priv->gsi_lst_head, GetSecretsInfo, gsi_lst)))
		get_secrets_info_free (info);

	if (priv->dbus_secret_agent) {
		g_signal_handlers_disconnect_matched (priv->dbus_secret_agent, G_SIGNAL_MATCH_DATA,
		                                      0, 0, NULL, NULL, self);
		g_clear_object (&priv->dbus_secret_agent);
	}

	g_clear_object (&priv->manager_proxy);
	g_clear_object (&priv->bus);

	G_OBJECT_CLASS (nm_secret_agent_old_parent_class)->dispose (object);
}

static void
nm_secret_agent_old_class_init (NMSecretAgentOldClass *class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (class);

	g_type_class_add_private (class, sizeof (NMSecretAgentOldPrivate));

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
	obj_properties[PROP_IDENTIFIER] =
	    g_param_spec_string (NM_SECRET_AGENT_OLD_IDENTIFIER, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_CONSTRUCT_ONLY |
	                         G_PARAM_STATIC_STRINGS);

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
	obj_properties[PROP_AUTO_REGISTER] =
	    g_param_spec_boolean (NM_SECRET_AGENT_OLD_AUTO_REGISTER, "", "",
	                          TRUE,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMSecretAgentOld:registered:
	 *
	 * %TRUE if the agent is registered with NetworkManager, %FALSE if not.
	 **/
	obj_properties[PROP_REGISTERED] =
	    g_param_spec_boolean (NM_SECRET_AGENT_OLD_REGISTERED, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMSecretAgentOld:capabilities:
	 *
	 * A bitfield of %NMSecretAgentCapabilities.
	 **/
	obj_properties[PROP_CAPABILITIES] =
	    g_param_spec_flags (NM_SECRET_AGENT_OLD_CAPABILITIES, "", "",
	                        NM_TYPE_SECRET_AGENT_CAPABILITIES,
	                        NM_SECRET_AGENT_CAPABILITY_NONE,
	                        G_PARAM_READWRITE |
	                        G_PARAM_CONSTRUCT |
	                        G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);
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
	/* Use default implementation for init_finish */
}
