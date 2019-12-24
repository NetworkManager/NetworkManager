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
#include "nm-glib-aux/nm-c-list.h"
#include "nm-glib-aux/nm-dbus-aux.h"
#include "nm-glib-aux/nm-time-utils.h"
#include "nm-simple-connection.h"

#define REGISTER_RETRY_TIMEOUT_MSEC  3000
#define _CALL_REGISTER_TIMEOUT_MSEC 15000

/*****************************************************************************/

typedef struct {
	char *connection_path;
	char *setting_name;
	GDBusMethodInvocation *context;
	CList gsi_lst;
	bool is_cancelling:1;
} GetSecretsInfo;

NM_GOBJECT_PROPERTIES_DEFINE (NMSecretAgentOld,
	PROP_IDENTIFIER,
	PROP_AUTO_REGISTER,
	PROP_REGISTERED,
	PROP_CAPABILITIES,
	PROP_DBUS_CONNECTION,
);

typedef struct {
	GDBusConnection *dbus_connection;
	GMainContext *main_context;
	GMainContext *dbus_context;
	GObject *context_busy_watcher;
	GCancellable *name_owner_cancellable;
	GCancellable *registering_cancellable;
	GSource *registering_retry_source;

	NMLInitData *init_data;

	CList gsi_lst_head;

	CList pending_tasks_register_lst_head;

	char *identifier;

	NMRefString *name_owner_curr;
	NMRefString *name_owner_next;

	gint64 registering_timeout_msec;

	guint name_owner_changed_id;

	guint exported_id;

	guint capabilities;

	guint8 registering_try_count;

	guint8 register_state_change_reenter:2;

	bool session_bus:1;

	bool auto_register:1;

	bool is_registered:1;

	bool is_enabled:1;

	bool registration_force_unregister:1;

	/* This is true, if we either are in the process of RegisterWithCapabilities() or
	 * are already successfully registered.
	 *
	 * This is only TRUE, if the name owner was authenticated to run as root user.
	 *
	 * It also means, we should follow up with an Unregister() call during shutdown. */
	bool registered_against_server:1;

	bool is_initialized:1;
	bool is_destroyed:1;
} NMSecretAgentOldPrivate;

static void nm_secret_agent_old_initable_iface_init (GInitableIface *iface);
static void nm_secret_agent_old_async_initable_iface_init (GAsyncInitableIface *iface);

G_DEFINE_ABSTRACT_TYPE_WITH_CODE (NMSecretAgentOld, nm_secret_agent_old, G_TYPE_OBJECT,
                                  G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, nm_secret_agent_old_initable_iface_init);
                                  G_IMPLEMENT_INTERFACE (G_TYPE_ASYNC_INITABLE, nm_secret_agent_old_async_initable_iface_init);
                                  )

#define NM_SECRET_AGENT_OLD_GET_PRIVATE(self) (G_TYPE_INSTANCE_GET_PRIVATE ((self), NM_TYPE_SECRET_AGENT_OLD, NMSecretAgentOldPrivate))

/*****************************************************************************/

#define _NMLOG(level, ...) \
	NML_DBUS_LOG((level), \
	              "secret-agent["NM_HASH_OBFUSCATE_PTR_FMT"]: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
	              NM_HASH_OBFUSCATE_PTR (self) \
	              _NM_UTILS_MACRO_REST (__VA_ARGS__))

/*****************************************************************************/

static const GDBusInterfaceInfo interface_info = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (
	NM_DBUS_INTERFACE_SECRET_AGENT,
	.methods = NM_DEFINE_GDBUS_METHOD_INFOS (
		NM_DEFINE_GDBUS_METHOD_INFO (
			"GetSecrets",
			.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
				NM_DEFINE_GDBUS_ARG_INFO ("connection",      "a{sa{sv}}"),
				NM_DEFINE_GDBUS_ARG_INFO ("connection_path", "o"),
				NM_DEFINE_GDBUS_ARG_INFO ("setting_name",    "s"),
				NM_DEFINE_GDBUS_ARG_INFO ("hints",           "as"),
				NM_DEFINE_GDBUS_ARG_INFO ("flags",           "u"),
			),
			.out_args = NM_DEFINE_GDBUS_ARG_INFOS (
				NM_DEFINE_GDBUS_ARG_INFO ("secrets",         "a{sa{sv}}"),
			),
		),
		NM_DEFINE_GDBUS_METHOD_INFO (
			"CancelGetSecrets",
			.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
				NM_DEFINE_GDBUS_ARG_INFO ("connection_path", "o"),
				NM_DEFINE_GDBUS_ARG_INFO ("setting_name",    "s"),
			),
		),
		NM_DEFINE_GDBUS_METHOD_INFO (
			"SaveSecrets",
			.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
				NM_DEFINE_GDBUS_ARG_INFO ("connection",      "a{sa{sv}}"),
				NM_DEFINE_GDBUS_ARG_INFO ("connection_path", "o"),
			),
		),
		NM_DEFINE_GDBUS_METHOD_INFO (
			"DeleteSecrets",
			.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
				NM_DEFINE_GDBUS_ARG_INFO ("connection",      "a{sa{sv}}"),
				NM_DEFINE_GDBUS_ARG_INFO ("connection_path", "o"),
			),
		),
	),
);

/*****************************************************************************/

static void _register_state_change (NMSecretAgentOld *self);

static void _register_dbus_call (NMSecretAgentOld *self);

static void _init_complete (NMSecretAgentOld *self, GError *error_take);

static void _register_state_complete (NMSecretAgentOld *self);

/*****************************************************************************/

/**
 * nm_secret_agent_old_get_dbus_connection:
 * @self: the #NMSecretAgentOld instance
 *
 * Returns: (transfer none): the #GDBusConnection used by the secret agent.
 *   You may either set this as construct property %NM_SECRET_AGENT_OLD_DBUS_CONNECTION,
 *   or it will automatically set during initialization.
 *
 * Since: 1.24
 */
GDBusConnection *
nm_secret_agent_old_get_dbus_connection (NMSecretAgentOld *self)
{
	g_return_val_if_fail (NM_IS_SECRET_AGENT_OLD (self), NULL);

	return NM_SECRET_AGENT_OLD_GET_PRIVATE (self)->dbus_connection;
}

/**
 * nm_secret_agent_old_get_main_context:
 * @self: the #NMSecretAgentOld instance
 *
 * Returns: (transfer none): the #GMainContext instance associate with the
 *   instance. This is the g_main_context_get_thread_default() at the time
 *   when creating the instance.
 *
 * Since: 1.24
 */
GMainContext *
nm_secret_agent_old_get_main_context (NMSecretAgentOld *self)
{
	g_return_val_if_fail (NM_IS_SECRET_AGENT_OLD (self), NULL);

	return NM_SECRET_AGENT_OLD_GET_PRIVATE (self)->main_context;
}

/**
 * nm_secret_agent_old_get_context_busy_watcher:
 * @self: the #NMSecretAgentOld instance
 *
 * Returns a #GObject that stays alive as long as there are pending
 * requests in the #GDBusConnection. Such requests keep the #GMainContext
 * alive, and thus you may want to keep iterating the context as long
 * until a weak reference indicates that this object is gone. This is
 * useful because even when you destroy the instance right away (and all
 * the internally pending requests get cancelled), any pending g_dbus_connection_call()
 * requests will still invoke the result on the #GMainContext. Hence, this
 * allows you to know how long you must iterate the context to know
 * that all remains are cleaned up.
 *
 * Returns: (transfer none): a #GObject that you may register a weak pointer
 *   to know that the #GMainContext is still kept busy by @self.
 *
 * Since: 1.24
 */
GObject *
nm_secret_agent_old_get_context_busy_watcher (NMSecretAgentOld *self)
{
	g_return_val_if_fail (NM_IS_SECRET_AGENT_OLD (self), NULL);

	return NM_SECRET_AGENT_OLD_GET_PRIVATE (self)->context_busy_watcher;
}

/**
 * nm_secret_agent_old_get_dbus_name_owner:
 * @self: the #NMSecretAgentOld instance
 *
 * Returns: the current D-Bus name owner. While this property
 *   is set while registering, it really only makes sense when
 *   the nm_secret_agent_old_get_registered() indicates that
 *   registration is successfull.
 *
 * Since: 1.24
 */
const char *
nm_secret_agent_old_get_dbus_name_owner (NMSecretAgentOld *self)
{
	g_return_val_if_fail (NM_IS_SECRET_AGENT_OLD (self), NULL);

	return nm_ref_string_get_str (NM_SECRET_AGENT_OLD_GET_PRIVATE (self)->name_owner_curr);
}

/**
 * nm_secret_agent_old_get_registered:
 * @self: a #NMSecretAgentOld
 *
 * Note that the secret agent transparently registers and re-registers
 * as the D-Bus name owner appears. Hence, this property is not really
 * useful. Also, to be graceful against races during registration, the
 * instance will already accept requests while being in the process of
 * registering.
 * If you need to avoid races and want to wait until @self is registered,
 * call nm_secret_agent_old_register_async(). If that function completes
 * with success, you know the instance is registered.
 *
 * Returns: a %TRUE if the agent is registered, %FALSE if it is not.
 **/
gboolean
nm_secret_agent_old_get_registered (NMSecretAgentOld *self)
{
	g_return_val_if_fail (NM_IS_SECRET_AGENT_OLD (self), FALSE);

	return NM_SECRET_AGENT_OLD_GET_PRIVATE (self)->is_registered;
}

/*****************************************************************************/

static void
get_secret_info_free (GetSecretsInfo *info)
{
	nm_assert (info);
	nm_assert (!info->context);

	c_list_unlink_stale (&info->gsi_lst);
	g_free (info->connection_path);
	g_free (info->setting_name);
	nm_g_slice_free (info);
}

static void
get_secret_info_complete_and_free (GetSecretsInfo *info,
                                   GVariant *secrets,
                                   GError *error)
{
	if (error) {
		if (secrets)
			nm_g_variant_unref_floating (secrets);
		g_dbus_method_invocation_return_gerror (g_steal_pointer (&info->context), error);
	} else {
		g_dbus_method_invocation_return_value (g_steal_pointer (&info->context),
		                                       g_variant_new ("(@a{sa{sv}})", secrets));
	}
	get_secret_info_free (info);
}

static void
get_secret_info_complete_and_free_error (GetSecretsInfo *info,
                                         GQuark error_domain,
                                         int error_code,
                                         const char *error_message)
{
	g_dbus_method_invocation_return_error_literal (g_steal_pointer (&info->context), error_domain, error_code, error_message);
	get_secret_info_free (info);
}

/*****************************************************************************/

static void
_dbus_connection_call_cb (GObject *source,
                          GAsyncResult *result,
                          gpointer user_data)
{
	gs_unref_object GObject *context_busy_watcher = NULL;
	GAsyncReadyCallback callback;
	gpointer callback_user_data;

	nm_utils_user_data_unpack (user_data, &context_busy_watcher, &callback, &callback_user_data);
	callback (source, result, callback_user_data);
}

static void
_dbus_connection_call (NMSecretAgentOld *self,
                       const char *bus_name,
                       const char *object_path,
                       const char *interface_name,
                       const char *method_name,
                       GVariant *parameters,
                       const GVariantType *reply_type,
                       GDBusCallFlags flags,
                       int timeout_msec,
                       GCancellable *cancellable,
                       GAsyncReadyCallback callback,
                       gpointer user_data)
{
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);

	nm_assert (nm_g_main_context_is_thread_default (priv->dbus_context));

	g_dbus_connection_call (priv->dbus_connection,
	                        bus_name,
	                        object_path,
	                        interface_name,
	                        method_name,
	                        parameters,
	                        reply_type,
	                        flags,
	                        timeout_msec,
	                        cancellable,
	                          callback
	                        ? _dbus_connection_call_cb
	                        : NULL,
	                          callback
	                        ? nm_utils_user_data_pack (g_object_ref (priv->context_busy_watcher), callback, user_data)
	                        : NULL);
}

/*****************************************************************************/

static GetSecretsInfo *
find_get_secrets_info (NMSecretAgentOldPrivate *priv,
                       const char *connection_path,
                       const char *setting_name)
{
	GetSecretsInfo *info;

	c_list_for_each_entry (info, &priv->gsi_lst_head, gsi_lst) {
		if (   nm_streq (connection_path, info->connection_path)
		    && nm_streq (setting_name, info->setting_name))
			return info;
	}
	return NULL;
}

static void
_cancel_get_secret_request (NMSecretAgentOld *self,
                            GetSecretsInfo *info,
                            const char *message)
{
	c_list_unlink (&info->gsi_lst);
	info->is_cancelling = TRUE;

	_LOGT ("cancel get-secrets request \"%s\", \"%s\": %s", info->connection_path, info->setting_name, message);

	NM_SECRET_AGENT_OLD_GET_CLASS (self)->cancel_get_secrets (self,
	                                                          info->connection_path,
	                                                          info->setting_name);

	get_secret_info_complete_and_free_error (info,
	                                         NM_SECRET_AGENT_ERROR,
	                                         NM_SECRET_AGENT_ERROR_AGENT_CANCELED,
	                                         message);
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

	if (!nm_dbus_path_not_empty (connection_path)) {
		g_set_error_literal (error,
		                     NM_SECRET_AGENT_ERROR,
		                     NM_SECRET_AGENT_ERROR_INVALID_CONNECTION,
		                     "Invalid connection: no connection path given.");
		return FALSE;
	}

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

	if (info->is_cancelling) {
		if (secrets)
			nm_g_variant_unref_floating (secrets);
		return;
	}

	_LOGT ("request: get-secrets request \"%s\", \"%s\" complete with %s%s%s",
	       info->connection_path,
	       info->setting_name,
	       NM_PRINT_FMT_QUOTED (error, "error: ", error->message, "", "success"));

	get_secret_info_complete_and_free (info, secrets, error);
}

static void
impl_get_secrets (NMSecretAgentOld *self,
                  GVariant *parameters,
                  GDBusMethodInvocation *context)
{
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);
	GError *error = NULL;
	gs_unref_object NMConnection *connection = NULL;
	GetSecretsInfo *info;
	gs_unref_variant GVariant *arg_connection = NULL;
	const char *arg_connection_path;
	const char *arg_setting_name;
	gs_free const char **arg_hints = NULL;
	guint32 arg_flags;

	g_variant_get (parameters,
	               "(@a{sa{sv}}&o&s^a&su)",
	               &arg_connection,
	               &arg_connection_path,
	               &arg_setting_name,
	               &arg_hints,
	               &arg_flags);

	if (!verify_request (self, context, arg_connection, arg_connection_path, &connection, &error)) {
		g_dbus_method_invocation_take_error (context, error);
		return;
	}

	_LOGT ("request: get-secrets(\"%s\", \"%s\")", arg_connection_path, arg_setting_name);

	info = find_get_secrets_info (priv, arg_connection_path, arg_setting_name);
	if (info)
		_cancel_get_secret_request (self, info, "Request aborted due to new request");

	info = g_slice_new (GetSecretsInfo);
	*info = (GetSecretsInfo) {
		.context         = context,
		.connection_path = g_strdup (arg_connection_path),
		.setting_name    = g_strdup (arg_setting_name),
	};
	c_list_link_tail (&priv->gsi_lst_head, &info->gsi_lst);

	NM_SECRET_AGENT_OLD_GET_CLASS (self)->get_secrets (self,
	                                                   connection,
	                                                   info->connection_path,
	                                                   info->setting_name,
	                                                   arg_hints,
	                                                   arg_flags,
	                                                   get_secrets_cb,
	                                                   info);
}

static void
impl_cancel_get_secrets (NMSecretAgentOld *self,
                         GVariant *parameters,
                         GDBusMethodInvocation *context)
{
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);
	GetSecretsInfo *info;
	const char *arg_connection_path;
	const char *arg_setting_name;

	g_variant_get (parameters,
	               "(&o&s)",
	               &arg_connection_path,
	               &arg_setting_name);

	info = find_get_secrets_info (priv, arg_connection_path, arg_setting_name);
	if (!info) {
		g_dbus_method_invocation_return_error_literal (context,
		                                               NM_SECRET_AGENT_ERROR,
		                                               NM_SECRET_AGENT_ERROR_FAILED,
		                                               "No secrets request in progress for this connection.");
		return;
	}

	_cancel_get_secret_request (self,
	                            info,
	                            "Request cancelled by NetworkManager");

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
impl_save_secrets (NMSecretAgentOld *self,
                   GVariant *parameters,
                   GDBusMethodInvocation *context)
{
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_variant GVariant *arg_connection = NULL;
	const char *arg_connection_path;
	GError *error = NULL;

	g_variant_get (parameters,
	               "(@a{sa{sv}}&o)",
	               &arg_connection,
	               &arg_connection_path);

	if (!verify_request (self, context, arg_connection, arg_connection_path, &connection, &error)) {
		g_dbus_method_invocation_take_error (context, error);
		return;
	}

	_LOGT ("request: save-secrets(\"%s\")", arg_connection_path);

	NM_SECRET_AGENT_OLD_GET_CLASS (self)->save_secrets (self,
	                                                    connection,
	                                                    arg_connection_path,
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
impl_delete_secrets (NMSecretAgentOld *self,
                     GVariant *parameters,
                     GDBusMethodInvocation *context)
{
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_variant GVariant *arg_connection = NULL;
	const char *arg_connection_path;
	GError *error = NULL;

	g_variant_get (parameters,
	               "(@a{sa{sv}}&o)",
	               &arg_connection,
	               &arg_connection_path);

	if (!verify_request (self, context, arg_connection, arg_connection_path, &connection, &error)) {
		g_dbus_method_invocation_take_error (context, error);
		return;
	}

	_LOGT ("request: delete-secrets(\"%s\")", arg_connection_path);

	NM_SECRET_AGENT_OLD_GET_CLASS (self)->delete_secrets (self,
	                                                      connection,
	                                                      arg_connection_path,
	                                                      delete_secrets_cb,
	                                                      context);
}

/*****************************************************************************/

/**
 * nm_secret_agent_old_enable:
 * @self: the #NMSecretAgentOld instance
 * @enable: whether to enable or disable the listener.
 *
 * This has the same effect as setting %NM_SECRET_AGENT_OLD_AUTO_REGISTER
 * property.
 *
 * Unlike most other functions, you may already call this function before
 * initialization completes.
 *
 * Since: 1.24
 */
void
nm_secret_agent_old_enable (NMSecretAgentOld *self,
                            gboolean enable)
{
	NMSecretAgentOldPrivate *priv;

	g_return_if_fail (NM_IS_SECRET_AGENT_OLD (self));

	priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);

	enable = (!!enable);

	if (priv->auto_register != enable) {
		priv->auto_register = enable;
		priv->is_enabled = enable;
		_notify (self, PROP_AUTO_REGISTER);
	}
	_register_state_change (self);
}

static void
_secret_agent_old_destroy (NMSecretAgentOld *self)
{
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);

	priv->is_destroyed = TRUE;

	if (priv->exported_id != 0) {
		g_dbus_connection_unregister_object (priv->dbus_connection,
		                                     nm_steal_int (&priv->exported_id));
	}

	_register_state_change (self);

	nm_assert (!priv->name_owner_changed_id);
	nm_assert (!priv->name_owner_curr);
	nm_assert (!priv->name_owner_next);
	nm_assert (!priv->name_owner_cancellable);
	nm_assert (!priv->registering_retry_source);
	nm_assert (!priv->registering_cancellable);
	nm_assert (!priv->init_data);
	nm_assert (c_list_is_empty (&priv->gsi_lst_head));
	nm_assert (c_list_is_empty (&priv->pending_tasks_register_lst_head));
}

/**
 * nm_secret_agent_old_destroy:
 * @self: the #NMSecretAgentOld instance.
 *
 * Since 1.24, the instance will already register a D-Bus object on the
 * D-Bus connection during initialization. That object will stay registered
 * until @self gets unrefed (destroyed) or this function is called. This
 * function performs the necessary cleanup to tear down the instance. Afterwards,
 * the function can not longer be used. This is optional, but necessary to
 * ensure unregistering the D-Bus object at a define point, when other users
 * might still have a reference on @self.
 *
 * You may call this function any time and repeatedly. However, after destroying
 * the instance, it is a bug to still use the instance for other purposes. The
 * instance becomes defunct and cannot re-register.
 *
 * Since: 1.24
 */
void
nm_secret_agent_old_destroy (NMSecretAgentOld *self)
{
	g_return_if_fail (NM_IS_SECRET_AGENT_OLD (self));

	_LOGT ("destroying");

	_secret_agent_old_destroy (self);
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
 * Returns: %TRUE if registration was successful, %FALSE on error.
 *
 * Since 1.24, this can no longer fail unless the @cancellable gets
 * cancelled. Contrary to nm_secret_agent_old_register_async(), this also
 * does not wait for the registration to succeed. You cannot synchronously
 * (without iterating the caller's GMainContext) wait for registration.
 *
 * Since 1.24, registration is idempotent. It has the same effect as setting
 * %NM_SECRET_AGENT_OLD_AUTO_REGISTER to %TRUE or nm_secret_agent_old_enable().
 *
 * Deprecated: 1.24: use nm_secret_agent_old_enable() or nm_secret_agent_old_register_async().
 **/
gboolean
nm_secret_agent_old_register (NMSecretAgentOld *self,
                              GCancellable *cancellable,
                              GError **error)
{
	NMSecretAgentOldPrivate *priv;

	g_return_val_if_fail (NM_IS_SECRET_AGENT_OLD (self), FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);

	g_return_val_if_fail (priv->is_initialized && !priv->is_destroyed, FALSE);

	priv->is_enabled = TRUE;
	_register_state_change (self);

	if (g_cancellable_set_error_if_cancelled (cancellable, error))
		return FALSE;

	/* This is a synchronous function, meaning: we are not allowed to iterate
	 * the caller's GMainContext. This is a catch 22, because we don't want
	 * to perform synchronous calls that bypasses the ordering of our otherwise
	 * asynchronous mode of operation. Hence, we always signal success.
	 * That's why this function is deprecated.
	 *
	 * So despite claiming success, we might still be in the process of registering
	 * or NetworkManager might not be available.
	 *
	 * This is a change in behavior with respect to libnm before 1.24.
	 */
	return TRUE;
}

static void
_register_cancelled_cb (GObject *object, gpointer user_data)
{
	GTask *task0 = user_data;
	gs_unref_object GTask *task = NULL;
	NMSecretAgentOld *self = g_task_get_source_object (task0);
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);
	gulong *p_cancelled_id;
	NMCListElem *elem;
	gs_free_error GError *error = NULL;

	elem = nm_c_list_elem_find_first (&priv->pending_tasks_register_lst_head, x, x == task0);

	g_return_if_fail (elem);

	task = nm_c_list_elem_free_steal (elem);

	p_cancelled_id = g_task_get_task_data (task);
	if (p_cancelled_id) {
		g_signal_handler_disconnect (g_task_get_cancellable (task), *p_cancelled_id);
		g_task_set_task_data (task, NULL, NULL);
	}

	nm_utils_error_set_cancelled (&error, FALSE, NULL);
	g_task_return_error (task, error);
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
 * Since 1.24, registration cannot fail and is idempotent. It has
 * the same effect as setting %NM_SECRET_AGENT_OLD_AUTO_REGISTER to %TRUE
 * or nm_secret_agent_old_enable().
 *
 * Since 1.24, the asynchronous result indicates whether the instance is successfully
 * registered. In any case, this call enables the agent and it will automatically
 * try to register and handle secret requests. A failure of this function only indicates
 * that currently the instance might not be ready (but since it will automatically
 * try to recover, it might be ready in a moment afterwards). Use this function if
 * you want to check and ensure that the agent is registered.
 **/
void
nm_secret_agent_old_register_async (NMSecretAgentOld *self,
                                    GCancellable *cancellable,
                                    GAsyncReadyCallback callback,
                                    gpointer user_data)
{
	NMSecretAgentOldPrivate *priv;

	g_return_if_fail (NM_IS_SECRET_AGENT_OLD (self));
	g_return_if_fail (!cancellable || G_IS_CANCELLABLE (cancellable));

	priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);

	g_return_if_fail (priv->is_initialized && !priv->is_destroyed);

	if (callback) {
		GTask *task;

		task = nm_g_task_new (self, cancellable, nm_secret_agent_old_register_async, callback, user_data);

		c_list_link_tail (&priv->pending_tasks_register_lst_head,
		                  &nm_c_list_elem_new_stale (task)->lst);

		if (cancellable) {
			gulong cancelled_id;

			cancelled_id = g_cancellable_connect (cancellable,
			                                      G_CALLBACK (_register_cancelled_cb),
			                                      task,
			                                      NULL);
			if (cancelled_id != 0) {
				g_task_set_task_data (task,
				                      g_memdup (&cancelled_id, sizeof (cancelled_id)),
				                      g_free);
			}
		}
	}

	priv->is_enabled = TRUE;
	_register_state_change (self);
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
 *
 * Since 1.24, registration cannot fail and is idempotent. It has
 * the same effect as setting %NM_SECRET_AGENT_OLD_AUTO_REGISTER to %TRUE
 * or nm_secret_agent_old_enable().
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
 *
 * Since 1.24, registration cannot fail and is idempotent. It has
 * the same effect as setting %NM_SECRET_AGENT_OLD_AUTO_REGISTER to %FALSE
 * or nm_secret_agent_old_enable().
 *
 * Deprecated: 1.24: use nm_secret_agent_old_enable()
 **/
gboolean
nm_secret_agent_old_unregister (NMSecretAgentOld *self,
                                GCancellable *cancellable,
                                GError **error)
{
	NMSecretAgentOldPrivate *priv;

	g_return_val_if_fail (NM_IS_SECRET_AGENT_OLD (self), FALSE);
	g_return_val_if_fail (!cancellable || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);

	g_return_val_if_fail (priv->is_initialized && !priv->is_destroyed, FALSE);

	priv->is_enabled = FALSE;
	_register_state_change (self);

	return !g_cancellable_set_error_if_cancelled (cancellable, error);
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
 *
 * Since 1.24, registration cannot fail and is idempotent. It has
 * the same effect as setting %NM_SECRET_AGENT_OLD_AUTO_REGISTER to %FALSE
 * or nm_secret_agent_old_enable().
 *
 * Deprecated: 1.24: use nm_secret_agent_old_enable()
 **/
void
nm_secret_agent_old_unregister_async (NMSecretAgentOld *self,
                                      GCancellable *cancellable,
                                      GAsyncReadyCallback callback,
                                      gpointer user_data)
{
	NMSecretAgentOldPrivate *priv;

	g_return_if_fail (NM_IS_SECRET_AGENT_OLD (self));
	g_return_if_fail (!cancellable || G_IS_CANCELLABLE (cancellable));

	priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);

	g_return_if_fail (priv->is_initialized && !priv->is_destroyed);

	if (callback) {
		gs_unref_object GTask *task = NULL;

		task = nm_g_task_new (self, cancellable, nm_secret_agent_old_unregister_async, callback, user_data);
		g_task_return_boolean (task, TRUE);
	}

	priv->is_enabled = FALSE;
	_register_state_change (self);
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
 *
 * Since 1.24, registration cannot fail and is idempotent. It has
 * the same effect as setting %NM_SECRET_AGENT_OLD_AUTO_REGISTER to %FALSE
 * or nm_secret_agent_old_enable().
 *
 * Deprecated: 1.24: use nm_secret_agent_old_enable()
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

static gboolean
_register_retry_cb (gpointer user_data)
{
	NMSecretAgentOld *self = user_data;
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);
	nm_auto_pop_gmaincontext GMainContext *dbus_context = NULL;

	dbus_context = nm_g_main_context_push_thread_default_if_necessary (priv->dbus_context);

	nm_clear_g_source_inst (&priv->registering_retry_source);
	_register_dbus_call (self);
	return G_SOURCE_CONTINUE;
}

static void
_register_call_cb (GObject *source,
                   GAsyncResult *result,
                   gpointer user_data)
{
	NMSecretAgentOld *self = user_data;
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);
	gs_unref_variant GVariant *ret = NULL;
	gs_free_error GError *error = NULL;

	ret = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source), result, &error);

	if (nm_utils_error_is_cancelled (error, FALSE))
		return;

	nm_assert (!priv->registering_retry_source);
	nm_assert (!priv->is_registered);
	nm_assert (priv->registering_cancellable);

	if (   nm_dbus_error_is (error, NM_DBUS_ERROR_NAME_UNKNOWN_METHOD)
	    && nm_utils_get_monotonic_timestamp_msec () < priv->registering_timeout_msec) {
		guint timeout_msec;

		timeout_msec = (2u << NM_MIN (6u, ++priv->registering_try_count));

		_LOGT ("register: registration failed with error \"%s\". Retry in %u msec...", error->message, timeout_msec);

		priv->registering_retry_source = nm_g_source_attach (nm_g_timeout_source_new (timeout_msec,
		                                                                              G_PRIORITY_DEFAULT,
		                                                                              _register_retry_cb,
		                                                                              self,
		                                                                              NULL),
		                                                     priv->dbus_context);
		return;
	}

	g_clear_object (&priv->registering_cancellable);

	if (error) {
		/* registration apparently failed. However we still keep priv->registered_against_server TRUE, because
		 *
		 * - eventually we want to still make an Unregister() call. Even if it probably has no effect,
		 *   better be sure.
		 *
		 * - we actually accept secret request (from the right name owner). We register so that
		 *   NetworkManager knows that we are here. We don't require the registration to succeed
		 *   for our purpose. If NetworkManager makes requests for us, despite the registration
		 *   failing, that is fine. */
		_LOGT ("register: registration failed with error \"%s\"", error->message);
		goto out;
	}

	_LOGT ("register: registration succeeded");
	priv->is_registered = TRUE;
	_notify (self, PROP_REGISTERED);

out:
	_register_state_complete (self);
}

static void
_register_dbus_call (NMSecretAgentOld *self)
{
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);

	_dbus_connection_call (self,
	                       nm_ref_string_get_str (priv->name_owner_curr),
	                       NM_DBUS_PATH_AGENT_MANAGER,
	                       NM_DBUS_INTERFACE_AGENT_MANAGER,
	                       "RegisterWithCapabilities",
	                       g_variant_new ("(su)",
	                                       priv->identifier,
	                                       (guint32) priv->capabilities),
	                       G_VARIANT_TYPE ("()"),
	                       G_DBUS_CALL_FLAGS_NONE,
	                       _CALL_REGISTER_TIMEOUT_MSEC,
	                       priv->registering_cancellable,
	                       _register_call_cb,
	                       self);
}

static void
_get_connection_unix_user_cb (GObject *source,
                              GAsyncResult *result,
                              gpointer user_data)
{
	NMSecretAgentOld *self;
	NMSecretAgentOldPrivate *priv;
	gs_unref_variant GVariant *ret = NULL;
	gs_free_error GError *error = NULL;
	guint32 sender_uid = 0;

	ret = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source), result, &error);
	if (nm_utils_error_is_cancelled (error, FALSE))
		return;

	self = user_data;
	priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);

	nm_assert (priv->registering_cancellable);
	nm_assert (!priv->registered_against_server);

	if (ret)
		g_variant_get (ret, "(u)", &sender_uid);

	if (   ret
	    && sender_uid == 0)
		_LOGT ("register: peer %s is owned by root. Validated to accept requests.", priv->name_owner_curr->str);
	else if (   ret
	         && priv->session_bus) {
		_LOGT ("register: peer %s is owned by user %d for session bus. Validated to accept requests.", priv->name_owner_curr->str, sender_uid);
	} else {
		/* the peer is not validated. We don't actually register. */
		if (ret)
			_LOGT ("register: peer %s is owned by user %u. Not validated as NetworkManager service.", priv->name_owner_curr->str, sender_uid);
		else
			_LOGT ("register: failed to get user id for peer %s: %s. Not validated as NetworkManager service.", priv->name_owner_curr->str, error->message);

		/* we actually don't do anything and keep the agent unregistered.
		 *
		 * We keep priv->registering_cancellable set to not retry this again, until we loose the
		 * name owner. But the state of the agent is lingering and won't accept any requests. */
		return;
	}

	priv->registering_timeout_msec = nm_utils_get_monotonic_timestamp_msec () + REGISTER_RETRY_TIMEOUT_MSEC;
	priv->registering_try_count = 0;
	priv->registered_against_server = TRUE;
	_register_dbus_call (self);
}

/*****************************************************************************/

static void
_name_owner_changed (NMSecretAgentOld *self,
                     const char *name_owner,
                     gboolean is_event)
{
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);

	if (is_event) {
		if (priv->name_owner_cancellable) {
			/* we are still fetching the name-owner. Ignore this event. */
			return;
		}
	} else
		g_clear_object (&priv->name_owner_cancellable);

	nm_ref_string_unref (priv->name_owner_next);
	priv->name_owner_next = nm_ref_string_new (nm_str_not_empty (name_owner));

	_LOGT ("name-owner changed: %s%s%s -> %s%s%s",
	       NM_PRINT_FMT_QUOTED (priv->name_owner_curr, "\"", priv->name_owner_curr->str, "\"", "(null)"),
	       NM_PRINT_FMT_QUOTED (priv->name_owner_next, "\"", priv->name_owner_next->str, "\"", "(null)"));

	_register_state_change (self);
}

static void
_name_owner_changed_cb (GDBusConnection *connection,
                        const char *sender_name,
                        const char *object_path,
                        const char *interface_name,
                        const char *signal_name,
                        GVariant *parameters,
                        gpointer user_data)
{
	NMSecretAgentOld *self = user_data;
	const char *new_owner;

	if (!g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(sss)")))
		return;

	g_variant_get (parameters,
	               "(&s&s&s)",
	               NULL,
	               NULL,
	               &new_owner);

	_name_owner_changed (self, new_owner, TRUE);
}

static void
_name_owner_get_cb (const char *name_owner,
                    GError *error,
                    gpointer user_data)
{
	if (   name_owner
	    || !nm_utils_error_is_cancelled (error, FALSE))
		_name_owner_changed (user_data, name_owner, FALSE);
}

/*****************************************************************************/

static void
_method_call (GDBusConnection *connection,
              const char *sender,
              const char *object_path,
              const char *interface_name,
              const char *method_name,
              GVariant *parameters,
              GDBusMethodInvocation *context,
              gpointer user_data)
{
	NMSecretAgentOld *self = user_data;
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);

	nm_assert (nm_streq0 (object_path, NM_DBUS_PATH_SECRET_AGENT));
	nm_assert (nm_streq0 (interface_name, NM_DBUS_INTERFACE_SECRET_AGENT));
	nm_assert (sender);
	nm_assert (nm_streq0 (sender, g_dbus_method_invocation_get_sender (context)));

	if (   !priv->name_owner_curr
	    || !priv->registered_against_server) {
		/* priv->registered_against_server means that we started to register, but not necessarily
		 * that the registration fully succeeded. However, we already authenticated the request
		 * and so we accept it, even if the registration is not yet complete. */
		g_dbus_method_invocation_return_error_literal (context,
		                                               NM_SECRET_AGENT_ERROR,
		                                               NM_SECRET_AGENT_ERROR_PERMISSION_DENIED,
		                                               "Request by non authenticated peer rejected");
		return;
	}

	if (nm_streq (method_name, "GetSecrets"))
		impl_get_secrets (self, parameters, context);
	else if (nm_streq (method_name, "CancelGetSecrets"))
		impl_cancel_get_secrets (self, parameters, context);
	else if (nm_streq (method_name, "SaveSecrets"))
		impl_save_secrets (self, parameters, context);
	else if (nm_streq (method_name, "DeleteSecrets"))
		impl_delete_secrets (self, parameters, context);
	else
		nm_assert_not_reached ();
}

/*****************************************************************************/

static void
_register_state_complete (NMSecretAgentOld *self)
{
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);
	NMCListElem *elem;
	gboolean any_tasks_to_complete = FALSE;

	if (!c_list_is_empty (&priv->pending_tasks_register_lst_head)) {
		/* add a dummy sentinel. We want to complete all the task we started
		 * so far, but as we invoke user callbacks, the user might register
		 * new tasks. Those we don't complete in this run. */
		g_object_ref (self);
		any_tasks_to_complete = TRUE;
		c_list_link_tail (&priv->pending_tasks_register_lst_head,
		                  &nm_c_list_elem_new_stale (&any_tasks_to_complete)->lst);
	}

	_init_complete (self, NULL);

	if (any_tasks_to_complete) {
		while ((elem = c_list_first_entry (&priv->pending_tasks_register_lst_head, NMCListElem, lst))) {
			gpointer data = nm_c_list_elem_free_steal (elem);
			gs_unref_object GTask *task = NULL;

			if (data == &any_tasks_to_complete) {
				any_tasks_to_complete = FALSE;
				break;
			}

			task = data;

			if (!priv->is_registered) {
				g_task_return_error (task,
				                     g_error_new_literal (NM_SECRET_AGENT_ERROR,
				                                          NM_SECRET_AGENT_ERROR_FAILED,
				                                          _("registration failed")));
				continue;
			}
			g_task_return_boolean (task, TRUE);
		}
		nm_assert (!any_tasks_to_complete);
		g_object_unref (self);
	}
}

static void
_register_state_change_do (NMSecretAgentOld *self)
{
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);

	if (priv->is_destroyed)
		priv->is_enabled = FALSE;

	if (   !priv->is_enabled
	    || priv->registration_force_unregister
	    || priv->name_owner_curr != priv->name_owner_next) {
		GetSecretsInfo *info;

		while ((info = c_list_first_entry (&priv->gsi_lst_head, GetSecretsInfo, gsi_lst))) {
			_cancel_get_secret_request (self, info, "The secret agent is going away");
			_register_state_change (self);
			return;
		}

		priv->registration_force_unregister = FALSE;

		nm_clear_g_cancellable (&priv->registering_cancellable);
		nm_clear_g_source_inst (&priv->registering_retry_source);

		if (priv->registered_against_server) {
			priv->registered_against_server = FALSE;
			if (priv->name_owner_curr) {
				_LOGT ("register: unregister from %s", priv->name_owner_curr->str);
				_dbus_connection_call (self,
				                       priv->name_owner_curr->str,
				                       NM_DBUS_PATH_AGENT_MANAGER,
				                       NM_DBUS_INTERFACE_AGENT_MANAGER,
				                       "Unregister",
				                       g_variant_new ("()"),
				                       G_VARIANT_TYPE ("()"),
				                       G_DBUS_CALL_FLAGS_NONE,
				                       _CALL_REGISTER_TIMEOUT_MSEC,
				                       NULL,
				                       NULL,
				                       NULL);
			}
		}

		if (!priv->is_enabled) {
			nm_clear_g_cancellable (&priv->name_owner_cancellable);
			nm_clear_g_dbus_connection_signal (priv->dbus_connection,
			                                   &priv->name_owner_changed_id);
			nm_clear_pointer (&priv->name_owner_curr, nm_ref_string_unref);
			nm_clear_pointer (&priv->name_owner_next, nm_ref_string_unref);
		}

		if (priv->is_registered) {
			priv->is_registered = FALSE;
			if (!priv->is_destroyed) {
				_LOGT ("register: now unregistered");
				_notify (self, PROP_REGISTERED);
				_register_state_change (self);
				return;
			}
		}

		if (!priv->is_enabled) {
			_register_state_complete (self);
			return;
		}

		if (priv->name_owner_curr != priv->name_owner_next) {
			nm_ref_string_unref (priv->name_owner_curr);
			priv->name_owner_curr = nm_ref_string_ref (priv->name_owner_next);
		}
	}

	if (priv->name_owner_changed_id == 0) {
		nm_assert (!priv->name_owner_cancellable);
		nm_assert (!priv->name_owner_curr);
		nm_assert (!priv->name_owner_next);
		priv->name_owner_cancellable = g_cancellable_new ();
		priv->name_owner_changed_id = nm_dbus_connection_signal_subscribe_name_owner_changed (priv->dbus_connection,
		                                                                                      NM_DBUS_SERVICE,
		                                                                                      _name_owner_changed_cb,
		                                                                                      self,
		                                                                                      NULL);
		nm_dbus_connection_call_get_name_owner (priv->dbus_connection,
		                                        NM_DBUS_SERVICE,
		                                        -1,
		                                        priv->name_owner_cancellable,
		                                        _name_owner_get_cb,
		                                        self);
		return;
	}

	if (priv->name_owner_cancellable) {
		/* we still wait for the name owner. Nothing to do for now. */
		return;
	}

	if (!priv->name_owner_curr) {
		/* we don't have a name owner. We are done and wait. */
		_register_state_complete (self);
		return;
	}

	if (priv->registering_cancellable) {
		/* we are already registering... wait longer. */
		return;
	}

	nm_assert (!priv->registering_retry_source);

	if (!priv->is_registered) {
		/* start registering... */
		priv->registering_cancellable = g_cancellable_new ();
		_dbus_connection_call (self,
		                       DBUS_SERVICE_DBUS,
		                       DBUS_PATH_DBUS,
		                       DBUS_INTERFACE_DBUS,
		                       "GetConnectionUnixUser",
		                       g_variant_new ("(s)", priv->name_owner_curr->str),
		                       G_VARIANT_TYPE ("(u)"),
		                       G_DBUS_CALL_FLAGS_NONE,
		                       _CALL_REGISTER_TIMEOUT_MSEC,
		                       priv->registering_cancellable,
		                       _get_connection_unix_user_cb,
		                       self);
		return;
	}

	/* we are fully registered and done. */
	_register_state_complete (self);
}

static void
_register_state_change (NMSecretAgentOld *self)
{
	_nm_unused gs_unref_object NMSecretAgentOld *self_keep_alive = g_object_ref (self);
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);
	nm_auto_pop_gmaincontext GMainContext *dbus_context = NULL;

	if (priv->register_state_change_reenter == 0) {
		/* We are not yet initialized. Do nothing. */
		return;
	}

	if (priv->register_state_change_reenter != 1) {
		/* Recursive calls are prevented. Do nothing for now, but repeat
		 * the state change afterwards. */
		priv->register_state_change_reenter = 3;
		return;
	}

	dbus_context = nm_g_main_context_push_thread_default_if_necessary (priv->dbus_context);

again:
	priv->register_state_change_reenter = 2;

	_register_state_change_do (self);

	if (priv->register_state_change_reenter != 2)
		goto again;

	priv->register_state_change_reenter = 1;
}

/*****************************************************************************/

static void
_init_complete (NMSecretAgentOld *self,
                GError *error_take)
{
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);
	gs_free_error GError *error = g_steal_pointer (&error_take);
	GError *error_cancelled = NULL;

	if (!priv->init_data)
		return;

	if (g_cancellable_set_error_if_cancelled (priv->init_data->cancellable, &error_cancelled)) {
		g_clear_error (&error);
		g_propagate_error (&error, error_cancelled);
	}

	priv->is_initialized = (!error);

	_LOGT ("%s init complete with %s%s%s",
	       priv->init_data->is_sync ? "sync" : "async",
	       NM_PRINT_FMT_QUOTED (error_take, "error: ", error_take->message, "", "success"));

	nml_init_data_return (g_steal_pointer (&priv->init_data),
	                      g_steal_pointer (&error));
}

static void
_init_register_object (NMSecretAgentOld *self)
{
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);
	gs_free_error GError *error = NULL;
	GDBusInterfaceVTable interface_vtable = {
		.method_call = _method_call,
	};

	if (g_cancellable_set_error_if_cancelled (priv->init_data->cancellable, &error)) {
		_init_complete (self, g_steal_pointer (&error));
		return;
	}

	priv->exported_id = g_dbus_connection_register_object (priv->dbus_connection,
	                                                       NM_DBUS_PATH_SECRET_AGENT,
	                                                       (GDBusInterfaceInfo*) &interface_info,
	                                                       &interface_vtable,
	                                                       self,
	                                                       NULL,
	                                                       &error);
	if (priv->exported_id == 0) {
		_init_complete (self, g_steal_pointer (&error));
		return;
	}

	priv->register_state_change_reenter = 1;

	_register_state_change (self);
}

static void
_init_got_bus (GObject *initable, GAsyncResult *result, gpointer user_data)
{
	NMSecretAgentOld *self = user_data;
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);
	gs_free_error GError *error = NULL;

	priv->dbus_connection = g_bus_get_finish (result, &error);
	if (!priv->dbus_connection) {
		_init_complete (self, g_steal_pointer (&error));
		return;
	}

	_LOGT ("init: got GDBusConnection");

	_notify (self, PROP_DBUS_CONNECTION);

	_init_register_object (self);
}

static void
_init_start (NMSecretAgentOld *self)
{
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);

	if (!priv->dbus_connection) {
		GBusType bus_type;

		bus_type = _nm_dbus_bus_type ();

		priv->session_bus = (bus_type == G_BUS_TYPE_SESSION);

		g_bus_get (bus_type,
		           priv->init_data->cancellable,
		           _init_got_bus,
		           self);
		return;
	}

	_init_register_object (self);
}

static void
init_async (GAsyncInitable *initable,
            int io_priority,
            GCancellable *cancellable,
            GAsyncReadyCallback callback,
            gpointer user_data)
{
	NMSecretAgentOld *self;
	NMSecretAgentOldClass *klass;
	NMSecretAgentOldPrivate *priv;
	nm_auto_pop_gmaincontext GMainContext *dbus_context = NULL;
	gs_unref_object GTask *task = NULL;

	g_return_if_fail (NM_IS_SECRET_AGENT_OLD (initable));

	self = NM_SECRET_AGENT_OLD (initable);
	priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);

	g_return_if_fail (!priv->dbus_context);
	g_return_if_fail (!priv->is_destroyed);

	klass = NM_SECRET_AGENT_OLD_GET_CLASS (self);
	g_return_if_fail (klass->get_secrets);
	g_return_if_fail (klass->cancel_get_secrets);
	g_return_if_fail (klass->save_secrets);
	g_return_if_fail (klass->delete_secrets);

	_LOGT ("init-async starting...");

	priv->dbus_context = g_main_context_ref (priv->main_context);

	dbus_context = nm_g_main_context_push_thread_default_if_necessary (priv->dbus_context);

	task = nm_g_task_new (self, cancellable, init_async, callback, user_data);
	g_task_set_priority (task, io_priority);

	priv->init_data = nml_init_data_new_async (cancellable, g_steal_pointer (&task));

	_init_start (self);
}

static gboolean
init_finish (GAsyncInitable *initable, GAsyncResult *result, GError **error)
{
	g_return_val_if_fail (NM_IS_SECRET_AGENT_OLD (initable), FALSE);
	g_return_val_if_fail (nm_g_task_is_valid (result, initable, init_async), FALSE);

	return g_task_propagate_boolean (G_TASK (result), error);
}

/*****************************************************************************/

static gboolean
init_sync (GInitable *initable,
           GCancellable *cancellable,
           GError **error)
{
	gs_unref_object NMSecretAgentOld *self = NULL;
	NMSecretAgentOldPrivate *priv;
	NMSecretAgentOldClass *klass;
	GMainLoop *main_loop;
	GError *local_error = NULL;

	g_return_val_if_fail (NM_IS_SECRET_AGENT_OLD (initable), FALSE);

	self = g_object_ref (NM_SECRET_AGENT_OLD (initable));
	priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);

	g_return_val_if_fail (!priv->dbus_context, FALSE);
	g_return_val_if_fail (!priv->is_destroyed, FALSE);

	klass = NM_SECRET_AGENT_OLD_GET_CLASS (self);
	g_return_val_if_fail (klass->get_secrets, FALSE);
	g_return_val_if_fail (klass->cancel_get_secrets, FALSE);
	g_return_val_if_fail (klass->save_secrets, FALSE);
	g_return_val_if_fail (klass->delete_secrets, FALSE);

	_LOGT ("init-sync");

	/* See NMClient's sync-init method for explanation about why we create
	 * an internal GMainContext priv->dbus_context. */

	priv->dbus_context = g_main_context_new ();

	g_main_context_push_thread_default (priv->dbus_context);

	main_loop = g_main_loop_new (priv->dbus_context, FALSE);

	priv->init_data = nml_init_data_new_sync (cancellable, main_loop, &local_error);

	_init_start (self);

	g_main_loop_run (main_loop);

	g_main_loop_unref (main_loop);

	g_main_context_pop_thread_default (priv->dbus_context);

	nm_context_busy_watcher_integrate_source (priv->main_context,
	                                          priv->dbus_context,
	                                          priv->context_busy_watcher);

	if (local_error) {
		g_propagate_error (error, local_error);
		return FALSE;
	}

	return TRUE;
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
	case PROP_DBUS_CONNECTION:
		g_value_set_object (value, priv->dbus_connection);
		break;
	case PROP_IDENTIFIER:
		g_value_set_string (value, priv->identifier);
		break;
	case PROP_AUTO_REGISTER:
		g_value_set_boolean (value, priv->auto_register);
		break;
	case PROP_REGISTERED:
		g_value_set_boolean (value, priv->is_registered);
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
	NMSecretAgentOld *self = NM_SECRET_AGENT_OLD (object);
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);
	guint u;

	switch (prop_id) {
	case PROP_DBUS_CONNECTION:
		/* construct-only */
		priv->dbus_connection = g_value_dup_object (value);
		break;
	case PROP_IDENTIFIER:
		/* construct-only */
		priv->identifier = g_value_dup_string (value);
		g_return_if_fail (validate_identifier (priv->identifier));
		break;
	case PROP_AUTO_REGISTER:
		/* construct */
		priv->auto_register = g_value_get_boolean (value);
		priv->is_enabled = priv->auto_register;
		_register_state_change (self);
		break;
	case PROP_CAPABILITIES:
		/* construct */
		u = g_value_get_flags (value);
		if (u != priv->capabilities) {
			priv->capabilities = u;
			priv->registration_force_unregister = TRUE;
			_register_state_change (self);
		}
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
	c_list_init (&priv->pending_tasks_register_lst_head);

	priv->main_context = g_main_context_ref_thread_default ();
	priv->context_busy_watcher = g_object_new (G_TYPE_OBJECT, NULL);
}

static void
dispose (GObject *object)
{
	NMSecretAgentOld *self = NM_SECRET_AGENT_OLD (object);

	_LOGT ("disposing");

	_secret_agent_old_destroy (self);

	G_OBJECT_CLASS (nm_secret_agent_old_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMSecretAgentOld *self = NM_SECRET_AGENT_OLD (object);
	NMSecretAgentOldPrivate *priv = NM_SECRET_AGENT_OLD_GET_PRIVATE (self);

	_LOGT ("finalizing");

	if (priv->dbus_context) {
		nml_cleanup_context_busy_watcher_on_idle (g_steal_pointer (&priv->context_busy_watcher),
		                                          priv->dbus_context);
	}

	g_clear_object (&priv->dbus_connection);
	nm_clear_pointer (&priv->dbus_context, g_main_context_unref);
	nm_clear_pointer (&priv->main_context, g_main_context_unref);

	g_clear_object (&priv->context_busy_watcher);

	g_free (priv->identifier);

	G_OBJECT_CLASS (nm_secret_agent_old_parent_class)->finalize (object);
}

static void
nm_secret_agent_old_class_init (NMSecretAgentOldClass *class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (class);

	g_type_class_add_private (class, sizeof (NMSecretAgentOldPrivate));

	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->dispose      = dispose;
	object_class->finalize     = finalize;

	/**
	 * NMSecretAgentOld:dbus-connection:
	 *
	 * The #GDBusConnection used by the instance. You may either set this
	 * as construct-only property, or otherwise #NMSecretAgentOld will choose
	 * a connection via g_bus_get() during initialization.
	 *
	 * Since: 1.24
	 **/
	obj_properties[PROP_DBUS_CONNECTION] =
	    g_param_spec_object (NM_SECRET_AGENT_OLD_DBUS_CONNECTION, "", "",
	                         G_TYPE_DBUS_CONNECTION,
	                         G_PARAM_READWRITE |
	                         G_PARAM_CONSTRUCT_ONLY |
	                         G_PARAM_STATIC_STRINGS);

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
	 * construction/initialization and initialization will only complete
	 * after registration is completed (either successfully or unsucessfully).
	 * Since 1.24, a failure to register will no longer cause initialization
	 * of #NMSecretAgentOld to fail.
	 *
	 * If the property is %FALSE, the agent will not automatically register with
	 * NetworkManager, and nm_secret_agent_old_enable() or
	 * nm_secret_agent_old_register_async() must be called to register it.
	 *
	 * Calling nm_secret_agent_old_enable() has the same effect as setting this
	 * property.
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
	 *
	 * Changing this property is possible at any time. In case the secret
	 * agent is currently registered, this will cause a re-registration.
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
	iface->init_async  = init_async;
	iface->init_finish = init_finish;
}
