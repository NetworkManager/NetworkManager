/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2010 - 2011 Red Hat, Inc.
 */

#include "config.h"

#include <sys/types.h>
#include <pwd.h>

#include "nm-default.h"
#include "nm-dbus-interface.h"
#include "nm-secret-agent.h"
#include "nm-bus-manager.h"
#include "nm-auth-subject.h"
#include "nm-simple-connection.h"

#include "nmdbus-secret-agent.h"

G_DEFINE_TYPE (NMSecretAgent, nm_secret_agent, G_TYPE_OBJECT)

#define NM_SECRET_AGENT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                        NM_TYPE_SECRET_AGENT, \
                                        NMSecretAgentPrivate))

typedef struct {
	char *description;
	NMAuthSubject *subject;
	char *identifier;
	char *owner_username;
	char *dbus_owner;
	NMSecretAgentCapabilities capabilities;

	GSList *permissions;

	NMDBusSecretAgent *proxy;

	GHashTable *requests;
} NMSecretAgentPrivate;

enum {
	DISCONNECTED,

	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };

/*************************************************************/

struct _NMSecretAgentCallId {
	NMSecretAgent *agent;
	GCancellable *cancellable;
	char *path;
	char *setting_name;
	gboolean is_get_secrets;
	NMSecretAgentCallback callback;
	gpointer callback_data;
};

typedef struct _NMSecretAgentCallId Request;

static Request *
request_new (NMSecretAgent *agent,
             const char *path,
             const char *setting_name,
             NMSecretAgentCallback callback,
             gpointer callback_data)
{
	Request *r;

	r = g_slice_new0 (Request);
	r->agent = agent;
	r->path = g_strdup (path);
	r->setting_name = g_strdup (setting_name);
	r->callback = callback;
	r->callback_data = callback_data;
	r->cancellable = g_cancellable_new ();
	return r;
}

static void
request_free (Request *r)
{
	g_free (r->path);
	g_free (r->setting_name);
	if (r->cancellable)
		g_object_unref (r->cancellable);
	g_slice_free (Request, r);
}

static gboolean
request_check_return (Request *r)
{
	NMSecretAgentPrivate *priv;

	if (!r->cancellable)
		return FALSE;

	g_return_val_if_fail (NM_IS_SECRET_AGENT (r->agent), FALSE);

	priv = NM_SECRET_AGENT_GET_PRIVATE (r->agent);

	if (!g_hash_table_remove (priv->requests, r))
		g_return_val_if_reached (FALSE);

	return TRUE;
}

/*************************************************************/

const char *
nm_secret_agent_get_description (NMSecretAgent *agent)
{
	NMSecretAgentPrivate *priv;

	g_return_val_if_fail (NM_IS_SECRET_AGENT (agent), NULL);

	priv = NM_SECRET_AGENT_GET_PRIVATE (agent);
	if (!priv->description) {
		priv->description = g_strdup_printf ("%s/%s/%lu",
		                                     priv->dbus_owner,
		                                     priv->identifier,
		                                     nm_auth_subject_get_unix_process_uid (priv->subject));
	}

	return priv->description;
}

const char *
nm_secret_agent_get_dbus_owner (NMSecretAgent *agent)
{
	g_return_val_if_fail (NM_IS_SECRET_AGENT (agent), NULL);

	return NM_SECRET_AGENT_GET_PRIVATE (agent)->dbus_owner;
}

const char *
nm_secret_agent_get_identifier (NMSecretAgent *agent)
{
	g_return_val_if_fail (NM_IS_SECRET_AGENT (agent), NULL);

	return NM_SECRET_AGENT_GET_PRIVATE (agent)->identifier;
}

gulong
nm_secret_agent_get_owner_uid  (NMSecretAgent *agent)
{
	g_return_val_if_fail (NM_IS_SECRET_AGENT (agent), G_MAXULONG);

	return nm_auth_subject_get_unix_process_uid (NM_SECRET_AGENT_GET_PRIVATE (agent)->subject);
}

const char *
nm_secret_agent_get_owner_username (NMSecretAgent *agent)
{
	g_return_val_if_fail (NM_IS_SECRET_AGENT (agent), NULL);

	return NM_SECRET_AGENT_GET_PRIVATE (agent)->owner_username;
}

gulong
nm_secret_agent_get_pid (NMSecretAgent *agent)
{
	g_return_val_if_fail (NM_IS_SECRET_AGENT (agent), G_MAXULONG);

	return nm_auth_subject_get_unix_process_pid (NM_SECRET_AGENT_GET_PRIVATE (agent)->subject);
}

NMSecretAgentCapabilities
nm_secret_agent_get_capabilities (NMSecretAgent *agent)
{
	g_return_val_if_fail (NM_IS_SECRET_AGENT (agent), NM_SECRET_AGENT_CAPABILITY_NONE);

	return NM_SECRET_AGENT_GET_PRIVATE (agent)->capabilities;
}

NMAuthSubject *
nm_secret_agent_get_subject (NMSecretAgent *agent)
{
	g_return_val_if_fail (NM_IS_SECRET_AGENT (agent), NULL);

	return NM_SECRET_AGENT_GET_PRIVATE (agent)->subject;
}

/**
 * nm_secret_agent_add_permission:
 * @agent: A #NMSecretAgent.
 * @permission: The name of the permission
 *
 * Records whether or not the agent has a given permission.
 */
void
nm_secret_agent_add_permission (NMSecretAgent *agent,
                                const char *permission,
                                gboolean allowed)
{
	NMSecretAgentPrivate *priv;
	GSList *iter;

	g_return_if_fail (agent != NULL);
	g_return_if_fail (permission != NULL);

	priv = NM_SECRET_AGENT_GET_PRIVATE (agent);

	/* Check if the permission is already in the list */
	for (iter = priv->permissions; iter; iter = g_slist_next (iter)) {
		if (g_strcmp0 (permission, iter->data) == 0) {
			/* If the permission is no longer allowed, remove it from the
			 * list.  If it is now allowed, do nothing since it's already
			 * in the list.
			 */
			if (allowed == FALSE) {
				g_free (iter->data);
				priv->permissions = g_slist_delete_link (priv->permissions, iter);
			}
			return;
		}
	}

	/* New permission that's allowed */
	if (allowed)
		priv->permissions = g_slist_prepend (priv->permissions, g_strdup (permission));
}

/**
 * nm_secret_agent_has_permission:
 * @agent: A #NMSecretAgent.
 * @permission: The name of the permission to check for
 *
 * Returns whether or not the agent has the given permission.
 * 
 * Returns: %TRUE if the agent has the given permission, %FALSE if it does not
 * or if the permission was not previous recorded with
 * nm_secret_agent_add_permission().
 */
gboolean
nm_secret_agent_has_permission (NMSecretAgent *agent, const char *permission)
{
	NMSecretAgentPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (agent != NULL, FALSE);
	g_return_val_if_fail (permission != NULL, FALSE);

	priv = NM_SECRET_AGENT_GET_PRIVATE (agent);

	/* Check if the permission is already in the list */
	for (iter = priv->permissions; iter; iter = g_slist_next (iter)) {
		if (g_strcmp0 (permission, iter->data) == 0)
			return TRUE;
	}
	return FALSE;
}

/*************************************************************/

static void
get_callback (GObject *proxy,
              GAsyncResult *result,
              gpointer user_data)
{
	Request *r = user_data;

	if (request_check_return (r)) {
		NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (r->agent);
		gs_free_error GError *error = NULL;
		gs_unref_variant GVariant *secrets = NULL;

		nmdbus_secret_agent_call_get_secrets_finish (priv->proxy, &secrets, result, &error);
		if (error)
			g_dbus_error_strip_remote_error (error);
		r->callback (r->agent, r, secrets, error, r->callback_data);
	}

	request_free (r);
}

NMSecretAgentCallId
nm_secret_agent_get_secrets (NMSecretAgent *self,
                             NMConnection *connection,
                             const char *setting_name,
                             const char **hints,
                             NMSecretAgentGetSecretsFlags flags,
                             NMSecretAgentCallback callback,
                             gpointer callback_data)
{
	NMSecretAgentPrivate *priv;
	static const char *no_hints[] = { NULL };
	GVariant *dict;
	Request *r;

	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (setting_name != NULL, NULL);

	priv = NM_SECRET_AGENT_GET_PRIVATE (self);
	g_return_val_if_fail (priv->proxy != NULL, NULL);

	dict = nm_connection_to_dbus (connection, NM_CONNECTION_SERIALIZE_ALL);

	/* Mask off the private flags if present */
	flags &= ~NM_SECRET_AGENT_GET_SECRETS_FLAG_ONLY_SYSTEM;
	flags &= ~NM_SECRET_AGENT_GET_SECRETS_FLAG_NO_ERRORS;

	r = request_new (self, nm_connection_get_path (connection), setting_name, callback, callback_data);
	r->is_get_secrets = TRUE;
	g_hash_table_add (priv->requests, r);
	nmdbus_secret_agent_call_get_secrets (priv->proxy,
	                                      dict,
	                                      nm_connection_get_path (connection),
	                                      setting_name,
	                                      hints ? hints : no_hints,
	                                      flags,
	                                      r->cancellable,
	                                      get_callback, r);

	return r;
}

/*************************************************************/

static void
cancel_done (GObject *proxy, GAsyncResult *result, gpointer user_data)
{
	char *description = user_data;
	GError *error = NULL;

	if (!nmdbus_secret_agent_call_cancel_get_secrets_finish (NMDBUS_SECRET_AGENT (proxy), result, &error)) {
		nm_log_dbg (LOGD_AGENTS, "%s%s%s: agent failed to cancel secrets: %s",
		            NM_PRINT_FMT_QUOTED (description, "(", description, ")", "???"),
		            error->message);
		g_clear_error (&error);
	}

	g_free (description);
}

static void
do_cancel_secrets (NMSecretAgent *self, Request *r, gboolean disposing)
{
	NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (self);
	GCancellable *cancellable;
	NMSecretAgentCallback callback;
	gpointer callback_data;

	g_return_if_fail (r->agent == self);
	g_return_if_fail (r->cancellable);

	if (   r->is_get_secrets
	    && priv->proxy) {
		/* for GetSecrets call, we must cancel the request. */
		nmdbus_secret_agent_call_cancel_get_secrets (priv->proxy,
		                                             r->path, r->setting_name,
		                                             NULL,
		                                             cancel_done,
		                                             g_strdup (nm_secret_agent_get_description (self)));
	}

	cancellable = r->cancellable;
	callback = r->callback;
	callback_data = r->callback_data;

	/* During g_cancellable_cancel() the d-bus method might return synchronously.
	 * Clear r->cancellable first, so that it doesn't actually do anything.
	 * After that, @r might be already freed. */
	r->cancellable = NULL;
	g_cancellable_cancel (cancellable);
	g_object_unref (cancellable);

	/* Don't free the request @r. It will be freed when the d-bus call returns.
	 * Only clear r->cancellable to indicate that the request was cancelled. */

	if (callback) {
		GError *error = NULL;

		if (disposing) {
			/* hijack an error code. G_IO_ERROR_CANCELLED is only used synchronously
			 * when the user calls nm_act_request_cancel_secrets().
			 * When the user disposes the instance, we also invoke the callback synchronously,
			 * but with a different error-reason. */
			g_set_error_literal (&error, G_IO_ERROR, G_IO_ERROR_FAILED,
		                         "Disposing NMSecretAgent instance");
		} else {
			g_set_error_literal (&error, G_IO_ERROR, G_IO_ERROR_CANCELLED,
			                     "Request cancelled");
		}
		/* @r might be a dangling pointer at this point. However, that is no problem
		 * to pass it as (opaque) call_id. */
		callback (self, r, NULL, error, callback_data);
		g_error_free (error);
	}
}

void
nm_secret_agent_cancel_secrets (NMSecretAgent *self, NMSecretAgentCallId call_id)
{
	NMSecretAgentPrivate *priv;
	Request *r = call_id;

	g_return_if_fail (NM_IS_SECRET_AGENT (self));
	g_return_if_fail (r);

	priv = NM_SECRET_AGENT_GET_PRIVATE (self);
	if (!g_hash_table_remove (priv->requests, r))
		g_return_if_reached ();

	do_cancel_secrets (self, r, FALSE);
}

/*************************************************************/

static void
agent_save_cb (GObject *proxy,
               GAsyncResult *result,
               gpointer user_data)
{
	Request *r = user_data;

	if (request_check_return (r)) {
		NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (r->agent);
		gs_free_error GError *error = NULL;

		nmdbus_secret_agent_call_save_secrets_finish (priv->proxy, result, &error);
		if (error)
			g_dbus_error_strip_remote_error (error);
		r->callback (r->agent, r, NULL, error, r->callback_data);
	}

	request_free (r);
}

NMSecretAgentCallId
nm_secret_agent_save_secrets (NMSecretAgent *self,
                              NMConnection *connection,
                              NMSecretAgentCallback callback,
                              gpointer callback_data)
{
	NMSecretAgentPrivate *priv;
	GVariant *dict;
	Request *r;
	const char *cpath;

	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);

	priv = NM_SECRET_AGENT_GET_PRIVATE (self);
	cpath = nm_connection_get_path (connection);

	/* Caller should have ensured that only agent-owned secrets exist in 'connection' */
	dict = nm_connection_to_dbus (connection, NM_CONNECTION_SERIALIZE_ALL);

	r = request_new (self, cpath, NULL, callback, callback_data);
	g_hash_table_add (priv->requests, r);
	nmdbus_secret_agent_call_save_secrets (priv->proxy,
	                                       dict, cpath,
	                                       NULL, /* cancelling the request does *not* cancel the D-Bus call. */
	                                       agent_save_cb, r);

	return r;
}

/*************************************************************/

static void
agent_delete_cb (GObject *proxy,
                 GAsyncResult *result,
                 gpointer user_data)
{
	Request *r = user_data;

	if (request_check_return (r)) {
		NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (r->agent);
		gs_free_error GError *error = NULL;

		nmdbus_secret_agent_call_delete_secrets_finish (priv->proxy, result, &error);
		if (error)
			g_dbus_error_strip_remote_error (error);
		r->callback (r->agent, r, NULL, error, r->callback_data);
	}

	request_free (r);
}

NMSecretAgentCallId
nm_secret_agent_delete_secrets (NMSecretAgent *self,
                                NMConnection *connection,
                                NMSecretAgentCallback callback,
                                gpointer callback_data)
{
	NMSecretAgentPrivate *priv;
	GVariant *dict;
	Request *r;
	const char *cpath;

	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);

	priv = NM_SECRET_AGENT_GET_PRIVATE (self);
	cpath = nm_connection_get_path (connection);

	/* No secrets sent; agents must be smart enough to track secrets using the UUID or something */
	dict = nm_connection_to_dbus (connection, NM_CONNECTION_SERIALIZE_NO_SECRETS);

	r = request_new (self, cpath, NULL, callback, callback_data);
	g_hash_table_add (priv->requests, r);
	nmdbus_secret_agent_call_delete_secrets (priv->proxy,
	                                         dict, cpath,
	                                         NULL, /* cancelling the request does *not* cancel the D-Bus call. */
	                                         agent_delete_cb, r);

	return r;
}

/*************************************************************/

static void
name_owner_changed_cb (GObject *proxy,
                       GParamSpec *pspec,
                       gpointer user_data)
{
	NMSecretAgent *self = NM_SECRET_AGENT (user_data);
	NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (self);
	char *owner;

	owner = g_dbus_proxy_get_name_owner (G_DBUS_PROXY (proxy));
	if (!owner) {
		g_signal_handlers_disconnect_by_func (priv->proxy, name_owner_changed_cb, self);
		g_clear_object (&priv->proxy);
		g_signal_emit (self, signals[DISCONNECTED], 0);
	} else
		g_free (owner);
}

/*************************************************************/

NMSecretAgent *
nm_secret_agent_new (GDBusMethodInvocation *context,
                     NMAuthSubject *subject,
                     const char *identifier,
                     NMSecretAgentCapabilities capabilities)
{
	NMSecretAgent *self;
	NMSecretAgentPrivate *priv;
	struct passwd *pw;
	GDBusProxy *proxy;
	char *owner_username = NULL;

	g_return_val_if_fail (context != NULL, NULL);
	g_return_val_if_fail (NM_IS_AUTH_SUBJECT (subject), NULL);
	g_return_val_if_fail (nm_auth_subject_is_unix_process (subject), NULL);
	g_return_val_if_fail (identifier != NULL, NULL);

	pw = getpwuid (nm_auth_subject_get_unix_process_uid (subject));
	if (pw && pw->pw_name && pw->pw_name[0])
		owner_username = g_strdup (pw->pw_name);

	self = (NMSecretAgent *) g_object_new (NM_TYPE_SECRET_AGENT, NULL);
	priv = NM_SECRET_AGENT_GET_PRIVATE (self);

	priv->identifier = g_strdup (identifier);
	priv->owner_username = owner_username;
	priv->dbus_owner = g_strdup (nm_auth_subject_get_unix_process_dbus_sender (subject));
	priv->capabilities = capabilities;
	priv->subject = g_object_ref (subject);

	proxy = nm_bus_manager_new_proxy (nm_bus_manager_get (),
	                                  context,
	                                  NMDBUS_TYPE_SECRET_AGENT_PROXY,
	                                  priv->dbus_owner,
	                                  NM_DBUS_PATH_SECRET_AGENT,
	                                  NM_DBUS_INTERFACE_SECRET_AGENT);
	g_assert (proxy);
	g_signal_connect (proxy, "notify::g-name-owner",
	                  G_CALLBACK (name_owner_changed_cb),
	                  self);
	priv->proxy = NMDBUS_SECRET_AGENT (proxy);

	return self;
}

static void
nm_secret_agent_init (NMSecretAgent *self)
{
	NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (self);

	priv->requests = g_hash_table_new (g_direct_hash, g_direct_equal);
}

static void
dispose (GObject *object)
{
	NMSecretAgent *self = NM_SECRET_AGENT (object);
	NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (self);
	GHashTableIter iter;
	Request *r;

	g_hash_table_iter_init (&iter, priv->requests);
	while (g_hash_table_iter_next (&iter, (gpointer *) &r, NULL)) {
		g_hash_table_iter_remove (&iter);
		do_cancel_secrets (self, r, TRUE);
	}

	g_clear_object (&priv->proxy);
	g_clear_object (&priv->subject);

	G_OBJECT_CLASS (nm_secret_agent_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (object);

	g_free (priv->description);
	g_free (priv->identifier);
	g_free (priv->owner_username);
	g_free (priv->dbus_owner);

	g_slist_free_full (priv->permissions, g_free);
	g_hash_table_destroy (priv->requests);

	G_OBJECT_CLASS (nm_secret_agent_parent_class)->finalize (object);
}

static void
nm_secret_agent_class_init (NMSecretAgentClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);

	g_type_class_add_private (config_class, sizeof (NMSecretAgentPrivate));

	/* virtual methods */
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	/* signals */
	signals[DISCONNECTED] =
		g_signal_new (NM_SECRET_AGENT_DISCONNECTED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMSecretAgentClass, disconnected),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__VOID,
		              G_TYPE_NONE, 0);
}

