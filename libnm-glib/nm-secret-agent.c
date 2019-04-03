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
#include <dbus/dbus-glib-lowlevel.h>

#include "NetworkManager.h"
#include "nm-secret-agent.h"
#include "nm-glib-enum-types.h"
#include "nm-dbus-helpers-private.h"
#include "nm-setting-private.h"

static void impl_secret_agent_get_secrets (NMSecretAgent *self,
                                           GHashTable *connection_hash,
                                           const char *connection_path,
                                           const char *setting_name,
                                           const char **hints,
                                           guint32 flags,
                                           DBusGMethodInvocation *context);

static void impl_secret_agent_cancel_get_secrets (NMSecretAgent *self,
                                                  const char *connection_path,
                                                  const char *setting_name,
                                                  DBusGMethodInvocation *context);

static void impl_secret_agent_save_secrets (NMSecretAgent *self,
                                            GHashTable *connection_hash,
                                            const char *connection_path,
                                            DBusGMethodInvocation *context);

static void impl_secret_agent_delete_secrets (NMSecretAgent *self,
                                              GHashTable *connection_hash,
                                              const char *connection_path,
                                              DBusGMethodInvocation *context);

#include "nm-secret-agent-glue.h"

G_DEFINE_ABSTRACT_TYPE (NMSecretAgent, nm_secret_agent, G_TYPE_OBJECT)

#define NM_SECRET_AGENT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SECRET_AGENT, NMSecretAgentPrivate))

static gboolean auto_register_cb (gpointer user_data);

typedef struct {
	gboolean registered;
	NMSecretAgentCapabilities capabilities;

	DBusGConnection *bus;
	DBusGProxy *dbus_proxy;
	DBusGProxy *manager_proxy;
	DBusGProxyCall *reg_call;

	/* GetSecretsInfo structs of in-flight GetSecrets requests */
	GSList *pending_gets;

	char *nm_owner;

	char *identifier;
	gboolean auto_register;
	gboolean suppress_auto;
	gboolean auto_register_id;
} NMSecretAgentPrivate;

enum {
	PROP_0,
	PROP_IDENTIFIER,
	PROP_AUTO_REGISTER,
	PROP_REGISTERED,
	PROP_CAPABILITIES,

	LAST_PROP
};

enum {
	REGISTRATION_RESULT,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

/*****************************************************************************/

GQuark
nm_secret_agent_error_quark (void)
{
	static GQuark ret = 0;

	if (G_UNLIKELY (ret == 0))
		ret = g_quark_from_static_string ("nm-secret-agent-error");
	return ret;
}

/*****************************************************************************/

static const char *
get_nm_owner (NMSecretAgent *self)
{
	NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (self);
	GError *error = NULL;
	char *owner;

	if (!priv->nm_owner) {
		if (!dbus_g_proxy_call_with_timeout (priv->dbus_proxy,
		                                     "GetNameOwner", 2000, &error,
		                                     G_TYPE_STRING, NM_DBUS_SERVICE,
		                                     G_TYPE_INVALID,
		                                     G_TYPE_STRING, &owner,
		                                     G_TYPE_INVALID))
			return NULL;

		priv->nm_owner = g_strdup (owner);
		g_free (owner);
	}

	return priv->nm_owner;
}

static void
_internal_unregister (NMSecretAgent *self)
{
	NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (self);

	if (priv->registered) {
		dbus_g_connection_unregister_g_object (priv->bus, G_OBJECT (self));
		priv->registered = FALSE;
		g_object_notify (G_OBJECT (self), NM_SECRET_AGENT_REGISTERED);
	}
}

typedef struct {
	char *path;
	char *setting_name;
	DBusGMethodInvocation *context;
} GetSecretsInfo;

static void
get_secrets_info_finalize (NMSecretAgent *self, GetSecretsInfo *info)
{
	NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (self);

	g_return_if_fail (info != NULL);

	priv->pending_gets = g_slist_remove (priv->pending_gets, info);

	g_free (info->path);
	g_free (info->setting_name);
	memset (info, 0, sizeof (*info));
	g_free (info);
}

static void
name_owner_changed (DBusGProxy *proxy,
                    const char *name,
                    const char *old_owner,
                    const char *new_owner,
                    gpointer user_data)
{
	NMSecretAgent *self = NM_SECRET_AGENT (user_data);
	NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (self);
	gboolean old_owner_good = (old_owner && strlen (old_owner));
	gboolean new_owner_good = (new_owner && strlen (new_owner));
	GSList *iter;

	if (strcmp (name, NM_DBUS_SERVICE) == 0) {
		g_free (priv->nm_owner);
		priv->nm_owner = g_strdup (new_owner);

		if (!old_owner_good && new_owner_good) {
			/* NM appeared */
			auto_register_cb (self);
		} else if (old_owner_good && !new_owner_good) {
			/* Cancel any pending secrets requests */
			for (iter = priv->pending_gets; iter; iter = g_slist_next (iter)) {
				GetSecretsInfo *info = iter->data;

				NM_SECRET_AGENT_GET_CLASS (self)->cancel_get_secrets (self,
				                                                      info->path,
				                                                      info->setting_name);
			}
			g_slist_free (priv->pending_gets);
			priv->pending_gets = NULL;

			/* NM disappeared */
			_internal_unregister (self);
		} else if (old_owner_good && new_owner_good && strcmp (old_owner, new_owner)) {
			/* Hmm, NM magically restarted */
			_internal_unregister (self);
			auto_register_cb (self);
		}
	}
}

static gboolean
verify_sender (NMSecretAgent *self,
               DBusGMethodInvocation *context,
               GError **error)
{
	NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (self);
	DBusConnection *bus;
	char *sender;
	const char *nm_owner;
	DBusError dbus_error;
	uid_t sender_uid = G_MAXUINT;
	gboolean allowed = FALSE;

	g_return_val_if_fail (context != NULL, FALSE);

	/* Verify the sender's UID is 0, and that the sender is the same as
	 * NetworkManager's bus name owner.
	 */

	nm_owner = get_nm_owner (self);
	if (!nm_owner) {
		g_set_error_literal (error,
		                     NM_SECRET_AGENT_ERROR,
		                     NM_SECRET_AGENT_ERROR_NOT_AUTHORIZED,
		                     "NetworkManager bus name owner unknown.");
		return FALSE;
	}

	bus = dbus_g_connection_get_connection (priv->bus);
	if (!bus) {
		g_set_error_literal (error,
		                     NM_SECRET_AGENT_ERROR,
		                     NM_SECRET_AGENT_ERROR_NOT_AUTHORIZED,
		                     "Failed to get DBus connection.");
		return FALSE;
	}

	sender = dbus_g_method_get_sender (context);
	if (!sender) {
		g_set_error_literal (error,
		                     NM_SECRET_AGENT_ERROR,
		                     NM_SECRET_AGENT_ERROR_NOT_AUTHORIZED,
		                     "Failed to get request sender.");
		return FALSE;
	}

	/* Check that the sender matches the current NM bus name owner */
	if (strcmp (sender, nm_owner) != 0) {
		g_set_error_literal (error,
		                     NM_SECRET_AGENT_ERROR,
		                     NM_SECRET_AGENT_ERROR_NOT_AUTHORIZED,
		                     "Request sender does not match NetworkManager bus name owner.");
		goto out;
	}

	dbus_error_init (&dbus_error);
	sender_uid = dbus_bus_get_unix_user (bus, sender, &dbus_error);
	if (dbus_error_is_set (&dbus_error)) {
		g_set_error (error,
		             NM_SECRET_AGENT_ERROR,
		             NM_SECRET_AGENT_ERROR_NOT_AUTHORIZED,
		             "Failed to get request unix user: (%s) %s.",
		             dbus_error.name, dbus_error.message);
		dbus_error_free (&dbus_error);
		goto out;
	}

	/* We only accept requests from NM, which always runs as root */
	if (0 != sender_uid) {
		g_set_error_literal (error,
		                     NM_SECRET_AGENT_ERROR,
		                     NM_SECRET_AGENT_ERROR_NOT_AUTHORIZED,
		                     "Request sender is not root.");
		goto out;
	}

	allowed = TRUE;

out:
	g_free (sender);
	return allowed;
}

static gboolean
verify_request (NMSecretAgent *self,
                DBusGMethodInvocation *context,
                GHashTable *connection_hash,
                const char *connection_path,
                NMConnection **out_connection,
                GError **error)
{
	NMConnection *connection = NULL;

	g_return_val_if_fail (!connection_hash || out_connection, FALSE);

	if (!verify_sender (self, context, error))
		return FALSE;

	/* No connection?  If the sender verified, then we allow the request */
	if (connection_hash == NULL)
		return TRUE;

	/* If we have a connection hash, we require a path too */
	if (connection_path == NULL) {
		g_set_error_literal (error,
		                     NM_SECRET_AGENT_ERROR,
		                     NM_SECRET_AGENT_ERROR_INVALID_CONNECTION,
		                     "Invalid connection: no connection path given.");
		return FALSE;
	}

	/* Make sure the given connection is valid */
	connection = _nm_connection_new_from_hash (connection_hash);
	nm_connection_set_path (connection, connection_path);
	*out_connection = connection;

	return TRUE;
}

static void
get_secrets_cb (NMSecretAgent *self,
                NMConnection *connection,
                GHashTable *secrets,
                GError *error,
                gpointer user_data)
{
	GetSecretsInfo *info = user_data;

	if (error)
		dbus_g_method_return_error (info->context, error);
	else
		dbus_g_method_return (info->context, secrets);

	/* Remove the request from internal tracking */
	get_secrets_info_finalize (self, info);
}

static void
impl_secret_agent_get_secrets (NMSecretAgent *self,
                               GHashTable *connection_hash,
                               const char *connection_path,
                               const char *setting_name,
                               const char **hints,
                               guint32 flags,
                               DBusGMethodInvocation *context)
{
	NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (self);
	GError *error = NULL;
	NMConnection *connection = NULL;
	GetSecretsInfo *info;

	/* Make sure the request comes from NetworkManager and is valid */
	if (!verify_request (self, context, connection_hash, connection_path, &connection, &error)) {
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		return;
	}

	info = g_malloc0 (sizeof (GetSecretsInfo));
	info->path = g_strdup (connection_path);
	info->setting_name = g_strdup (setting_name);
	info->context = context;
	priv->pending_gets = g_slist_append (priv->pending_gets, info);

	NM_SECRET_AGENT_GET_CLASS (self)->get_secrets (self,
	                                               connection,
	                                               connection_path,
	                                               setting_name,
	                                               hints,
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
impl_secret_agent_cancel_get_secrets (NMSecretAgent *self,
                                      const char *connection_path,
                                      const char *setting_name,
                                      DBusGMethodInvocation *context)
{
	NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (self);
	GError *error = NULL;
	GetSecretsInfo *info;

	/* Make sure the request comes from NetworkManager and is valid */
	if (!verify_request (self, context, NULL, NULL, NULL, &error)) {
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		return;
	}

	info = find_get_secrets_info (priv->pending_gets, connection_path, setting_name);
	if (!info) {
		g_set_error_literal (&error,
		                     NM_SECRET_AGENT_ERROR,
		                     NM_SECRET_AGENT_ERROR_INTERNAL_ERROR,
		                     "No secrets request in progress for this connection.");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		return;
	}

	/* Send the cancel request up to the subclass and finalize it */
	NM_SECRET_AGENT_GET_CLASS (self)->cancel_get_secrets (self,
	                                                      info->path,
	                                                      info->setting_name);
	dbus_g_method_return (context);
}

static void
save_secrets_cb (NMSecretAgent *self,
                 NMConnection *connection,
                 GError *error,
                 gpointer user_data)
{
	DBusGMethodInvocation *context = user_data;

	if (error)
		dbus_g_method_return_error (context, error);
	else
		dbus_g_method_return (context);
}

static void
impl_secret_agent_save_secrets (NMSecretAgent *self,
                                GHashTable *connection_hash,
                                const char *connection_path,
                                DBusGMethodInvocation *context)
{
	GError *error = NULL;
	NMConnection *connection = NULL;

	/* Make sure the request comes from NetworkManager and is valid */
	if (!verify_request (self, context, connection_hash, connection_path, &connection, &error)) {
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		return;
	}

	NM_SECRET_AGENT_GET_CLASS (self)->save_secrets (self,
	                                                connection,
	                                                connection_path,
	                                                save_secrets_cb,
	                                                context);
	g_object_unref (connection);
}

static void
delete_secrets_cb (NMSecretAgent *self,
                   NMConnection *connection,
                   GError *error,
                   gpointer user_data)
{
	DBusGMethodInvocation *context = user_data;

	if (error)
		dbus_g_method_return_error (context, error);
	else
		dbus_g_method_return (context);
}

static void
impl_secret_agent_delete_secrets (NMSecretAgent *self,
                                  GHashTable *connection_hash,
                                  const char *connection_path,
                                  DBusGMethodInvocation *context)
{
	GError *error = NULL;
	NMConnection *connection = NULL;

	/* Make sure the request comes from NetworkManager and is valid */
	if (!verify_request (self, context, connection_hash, connection_path, &connection, &error)) {
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		return;
	}

	NM_SECRET_AGENT_GET_CLASS (self)->delete_secrets (self,
	                                                  connection,
	                                                  connection_path,
	                                                  delete_secrets_cb,
	                                                  context);
	g_object_unref (connection);
}

/*****************************************************************************/

static void
reg_result (NMSecretAgent *self, GError *error)
{
	NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (self);

	if (error) {
		/* If registration failed we shouldn't expose ourselves on the bus */
		_internal_unregister (self);
	} else {
		priv->registered = TRUE;
		g_object_notify (G_OBJECT (self), NM_SECRET_AGENT_REGISTERED);
	}

	g_signal_emit (self, signals[REGISTRATION_RESULT], 0, error);
}

static void
reg_request_cb (DBusGProxy *proxy,
                DBusGProxyCall *call,
                gpointer user_data)
{
	NMSecretAgent *self = NM_SECRET_AGENT (user_data);
	NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (self);
	GError *error = NULL;

	priv->reg_call = NULL;

	dbus_g_proxy_end_call (proxy, call, &error, G_TYPE_INVALID);
	reg_result (self, error);
	g_clear_error (&error);
}

static void
reg_with_caps_cb (DBusGProxy *proxy,
                  DBusGProxyCall *call,
                  gpointer user_data)
{
	NMSecretAgent *self = NM_SECRET_AGENT (user_data);
	NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (self);

	priv->reg_call = NULL;

	if (dbus_g_proxy_end_call (proxy, call, NULL, G_TYPE_INVALID)) {
		reg_result (self, NULL);
		return;
	}

	/* Might be an old NetworkManager that doesn't support capabilities;
	 * fall back to old Register() method instead.
	 */
	priv->reg_call = dbus_g_proxy_begin_call_with_timeout (priv->manager_proxy,
	                                                       "Register",
	                                                       reg_request_cb,
	                                                       self,
	                                                       NULL,
	                                                       5000,
	                                                       G_TYPE_STRING, priv->identifier,
	                                                       G_TYPE_INVALID);
}

/**
 * nm_secret_agent_register:
 * @self: a #NMSecretAgent
 *
 * Registers the #NMSecretAgent with the NetworkManager secret manager,
 * indicating to NetworkManager that the agent is able to provide and save
 * secrets for connections on behalf of its user.  Registration is an
 * asynchronous operation and its success or failure is indicated via the
 * 'registration-result' signal.
 *
 * Returns: a new %TRUE if registration was successfully requested (this does
 * not mean registration itself was successful), %FALSE if registration was not
 * successfully requested.
 **/
gboolean
nm_secret_agent_register (NMSecretAgent *self)
{
	NMSecretAgentPrivate *priv;
	NMSecretAgentClass *class;

	g_return_val_if_fail (NM_IS_SECRET_AGENT (self), FALSE);

	priv = NM_SECRET_AGENT_GET_PRIVATE (self);

	g_return_val_if_fail (priv->registered == FALSE, FALSE);
	g_return_val_if_fail (priv->reg_call == NULL, FALSE);
	g_return_val_if_fail (priv->bus != NULL, FALSE);
	g_return_val_if_fail (priv->manager_proxy != NULL, FALSE);

	/* Also make sure the subclass can actually respond to secrets requests */
	class = NM_SECRET_AGENT_GET_CLASS (self);
	g_return_val_if_fail (class->get_secrets != NULL, FALSE);
	g_return_val_if_fail (class->save_secrets != NULL, FALSE);
	g_return_val_if_fail (class->delete_secrets != NULL, FALSE);

	if (!priv->nm_owner)
		return FALSE;

	priv->suppress_auto = FALSE;

	/* Export our secret agent interface before registering with the manager */
	dbus_g_connection_register_g_object (priv->bus,
	                                     NM_DBUS_PATH_SECRET_AGENT,
	                                     G_OBJECT (self));

	priv->reg_call = dbus_g_proxy_begin_call_with_timeout (priv->manager_proxy,
	                                                       "RegisterWithCapabilities",
	                                                       reg_with_caps_cb,
	                                                       self,
	                                                       NULL,
	                                                       5000,
	                                                       G_TYPE_STRING, priv->identifier,
	                                                       G_TYPE_UINT, priv->capabilities,
	                                                       G_TYPE_INVALID);
	return TRUE;
}

/**
 * nm_secret_agent_unregister:
 * @self: a #NMSecretAgent
 *
 * Unregisters the #NMSecretAgent with the NetworkManager secret manager,
 * indicating to NetworkManager that the agent is will no longer provide or
 * store secrets on behalf of this user.
 *
 * Returns: a new %TRUE if unregistration was successful, %FALSE if it was not.
 **/
gboolean
nm_secret_agent_unregister (NMSecretAgent *self)
{
	NMSecretAgentPrivate *priv;

	g_return_val_if_fail (NM_IS_SECRET_AGENT (self), FALSE);

	priv = NM_SECRET_AGENT_GET_PRIVATE (self);

	g_return_val_if_fail (priv->registered == TRUE, FALSE);
	g_return_val_if_fail (priv->bus != NULL, FALSE);
	g_return_val_if_fail (priv->manager_proxy != NULL, FALSE);

	if (!priv->nm_owner)
		return FALSE;

	dbus_g_proxy_call_no_reply (priv->manager_proxy, "Unregister", G_TYPE_INVALID);

	_internal_unregister (self);
	priv->suppress_auto = TRUE;

	return TRUE;
}

/**
 * nm_secret_agent_get_registered:
 * @self: a #NMSecretAgent
 *
 * Returns: a %TRUE if the agent is registered, %FALSE if it is not.
 **/
gboolean
nm_secret_agent_get_registered (NMSecretAgent *self)
{
	g_return_val_if_fail (NM_IS_SECRET_AGENT (self), FALSE);

	return NM_SECRET_AGENT_GET_PRIVATE (self)->registered;
}

static gboolean
auto_register_cb (gpointer user_data)
{
	NMSecretAgent *self = NM_SECRET_AGENT (user_data);
	NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (self);

	priv->auto_register_id = 0;
	if (priv->auto_register && !priv->suppress_auto &&
	   (priv->reg_call == NULL && !priv->registered))
		nm_secret_agent_register (self);
	return FALSE;
}

/*****************************************************************************/

/**
 * nm_secret_agent_get_secrets: (virtual get_secrets):
 * @self: a #NMSecretAgent
 * @connection: the #NMConnection for which we're asked secrets
 * @setting_name: the name of the secret setting
 * @hints: (array zero-terminated=1): hints to the agent
 * @flags: flags that modify the behavior of the request
 * @callback: (scope async): a callback, to be invoked when the operation is done
 * @user_data: (closure): caller-specific data to be passed to @callback
 *
 * Asynchronously retrieve secrets belonging to @connection for the
 * setting @setting_name.  @flags indicate specific behavior that the secret
 * agent should use when performing the request, for example returning only
 * existing secrets without user interaction, or requesting entirely new
 * secrets from the user.
 */
void
nm_secret_agent_get_secrets (NMSecretAgent *self,
                             NMConnection *connection,
                             const char *setting_name,
                             const char **hints,
                             NMSecretAgentGetSecretsFlags flags,
                             NMSecretAgentGetSecretsFunc callback,
                             gpointer user_data)
{
	g_return_if_fail (NM_IS_SECRET_AGENT (self));
	g_return_if_fail (NM_IS_CONNECTION (connection));
	g_return_if_fail (nm_connection_get_path (connection));
	g_return_if_fail (setting_name != NULL);
	g_return_if_fail (strlen (setting_name) > 0);
	g_return_if_fail (callback != NULL);

	NM_SECRET_AGENT_GET_CLASS (self)->get_secrets (self,
	                                               connection,
	                                               nm_connection_get_path (connection),
	                                               setting_name,
	                                               hints,
	                                               flags,
	                                               callback,
	                                               user_data);
}

/**
 * nm_secret_agent_save_secrets: (virtual save_secrets):
 * @self: a #NMSecretAgent
 * @connection: a #NMConnection
 * @callback: (scope async): a callback, to be invoked when the operation is done
 * @user_data: (closure): caller-specific data to be passed to @callback
 *
 * Asynchronously ensure that all secrets inside @connection
 * are stored to disk.
 */
void
nm_secret_agent_save_secrets (NMSecretAgent *self,
                              NMConnection *connection,
                              NMSecretAgentSaveSecretsFunc callback,
                              gpointer user_data)
{
	g_return_if_fail (NM_IS_SECRET_AGENT (self));
	g_return_if_fail (NM_IS_CONNECTION (connection));
	g_return_if_fail (nm_connection_get_path (connection));

	NM_SECRET_AGENT_GET_CLASS (self)->save_secrets (self,
	                                                connection,
	                                                nm_connection_get_path (connection),
	                                                callback,
	                                                user_data);
}

/**
 * nm_secret_agent_delete_secrets: (virtual delete_secrets):
 * @self: a #NMSecretAgent
 * @connection: a #NMConnection
 * @callback: (scope async): a callback, to be invoked when the operation is done
 * @user_data: (closure): caller-specific data to be passed to @callback
 *
 * Asynchronously ask the agent to delete all saved secrets belonging to
 * @connection.
 */
void
nm_secret_agent_delete_secrets (NMSecretAgent *self,
                                NMConnection *connection,
                                NMSecretAgentDeleteSecretsFunc callback,
                                gpointer user_data)
{
	g_return_if_fail (NM_IS_SECRET_AGENT (self));
	g_return_if_fail (NM_IS_CONNECTION (connection));
	g_return_if_fail (nm_connection_get_path (connection));

	NM_SECRET_AGENT_GET_CLASS (self)->delete_secrets (self,
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
nm_secret_agent_init (NMSecretAgent *self)
{
	NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (self);
	GError *error = NULL;

	priv->bus = _nm_dbus_new_connection (&error);
	if (!priv->bus) {
		g_warning ("Couldn't connect to system bus: %s", error->message);
		g_error_free (error);
		return;
	}

	priv->dbus_proxy = dbus_g_proxy_new_for_name (priv->bus,
	                                              DBUS_SERVICE_DBUS,
	                                              DBUS_PATH_DBUS,
	                                              DBUS_INTERFACE_DBUS);
	g_assert (priv->dbus_proxy);

	dbus_g_object_register_marshaller (g_cclosure_marshal_generic,
	                                   G_TYPE_NONE,
	                                   G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
	                                   G_TYPE_INVALID);
	dbus_g_proxy_add_signal (priv->dbus_proxy, "NameOwnerChanged",
	                         G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
	                         G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->dbus_proxy,
	                             "NameOwnerChanged",
	                             G_CALLBACK (name_owner_changed),
	                             self, NULL);

	get_nm_owner (self);

	priv->manager_proxy = _nm_dbus_new_proxy_for_connection (priv->bus,
	                                                         NM_DBUS_PATH_AGENT_MANAGER,
	                                                         NM_DBUS_INTERFACE_AGENT_MANAGER);
	if (!priv->manager_proxy) {
		g_warning ("Couldn't create NM agent manager proxy.");
		return;
	}

	if (priv->nm_owner)
		priv->auto_register_id = g_idle_add (auto_register_cb, self);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (object);

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
	NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (object);
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
	NMSecretAgent *self = NM_SECRET_AGENT (object);
	NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (self);

	if (priv->registered)
		nm_secret_agent_unregister (self);

	if (priv->auto_register_id) {
		g_source_remove (priv->auto_register_id);
		priv->auto_register_id = 0;
	}

	g_free (priv->identifier);
	priv->identifier = NULL;
	g_free (priv->nm_owner);
	priv->nm_owner = NULL;

	while (priv->pending_gets)
		get_secrets_info_finalize (self, priv->pending_gets->data);

	g_clear_object (&priv->dbus_proxy);
	g_clear_object (&priv->manager_proxy);

	if (priv->bus) {
		dbus_g_connection_unref (priv->bus);
		priv->bus = NULL;
	}

	G_OBJECT_CLASS (nm_secret_agent_parent_class)->dispose (object);
}

static void
nm_secret_agent_class_init (NMSecretAgentClass *class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (class);

	g_type_class_add_private (class, sizeof (NMSecretAgentPrivate));

	/* Virtual methods */
	object_class->dispose = dispose;
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	/**
	 * NMSecretAgent:identifier:
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
		 g_param_spec_string (NM_SECRET_AGENT_IDENTIFIER, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_CONSTRUCT_ONLY |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSecretAgent:auto-register:
	 *
	 * If TRUE, the agent will attempt to automatically register itself after
	 * it is created (via an idle handler) and to re-register itself if
	 * NetworkManager restarts.  If FALSE, the agent does not automatically
	 * register with NetworkManager, and nm_secret_agent_register() must be
	 * called.  If 'auto-register' is TRUE, calling nm_secret_agent_unregister()
	 * will suppress auto-registration until nm_secret_agent_register() is
	 * called, which re-enables auto-registration.
	 **/
	g_object_class_install_property
		(object_class, PROP_AUTO_REGISTER,
		 g_param_spec_boolean (NM_SECRET_AGENT_AUTO_REGISTER, "", "",
		                       TRUE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSecretAgent:registered:
	 *
	 * %TRUE if the agent is registered with NetworkManager, %FALSE if not.
	 **/
	g_object_class_install_property
		(object_class, PROP_REGISTERED,
		 g_param_spec_boolean (NM_SECRET_AGENT_REGISTERED, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSecretAgent:capabilities:
	 *
	 * A bitfield of %NMSecretAgentCapabilities.
	 **/
	g_object_class_install_property
		(object_class, PROP_CAPABILITIES,
		 g_param_spec_flags (NM_SECRET_AGENT_CAPABILITIES, "", "",
		                     NM_TYPE_SECRET_AGENT_CAPABILITIES,
		                     NM_SECRET_AGENT_CAPABILITY_NONE,
		                     G_PARAM_READWRITE |
		                     G_PARAM_CONSTRUCT |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMSecretAgent::registration-result:
	 * @agent: the agent that received the signal
	 * @error: the error, if any, that occurred while registering
	 *
	 * Indicates the result of a registration request; if @error is NULL the
	 * request was successful.
	 **/
	signals[REGISTRATION_RESULT] =
		g_signal_new (NM_SECRET_AGENT_REGISTRATION_RESULT,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              0, NULL, NULL, NULL,
		              G_TYPE_NONE, 1, G_TYPE_POINTER);

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (class),
	                                 &dbus_glib_nm_secret_agent_object_info);

	dbus_g_error_domain_register (NM_SECRET_AGENT_ERROR,
	                              NM_DBUS_INTERFACE_SECRET_AGENT,
	                              NM_TYPE_SECRET_AGENT_ERROR);
}
