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

#include "nm-default.h"

#include "nm-secret-agent.h"

#include <sys/types.h>
#include <pwd.h>

#include "nm-dbus-interface.h"
#include "nm-dbus-manager.h"
#include "nm-core-internal.h"
#include "nm-auth-subject.h"
#include "nm-simple-connection.h"
#include "NetworkManagerUtils.h"
#include "c-list/src/c-list.h"

/*****************************************************************************/

enum {
	DISCONNECTED,

	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	char *description;
	NMAuthSubject *subject;
	char *identifier;
	char *owner_username;
	char *dbus_owner;
	NMSecretAgentCapabilities capabilities;
	GSList *permissions;
	GDBusProxy *proxy;
	NMDBusManager *bus_mgr;
	GDBusConnection *connection;
	CList requests;
	gulong on_disconnected_id;
	bool connection_is_private:1;
} NMSecretAgentPrivate;

struct _NMSecretAgent {
	GObject parent;
	NMSecretAgentPrivate _priv;
};

struct _NMSecretAgentClass {
	GObjectClass parent;
};

G_DEFINE_TYPE (NMSecretAgent, nm_secret_agent, G_TYPE_OBJECT)

#define NM_SECRET_AGENT_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMSecretAgent, NM_IS_SECRET_AGENT)

/*****************************************************************************/

#define _NMLOG_PREFIX_NAME    "secret-agent"
#define _NMLOG_DOMAIN         LOGD_AGENTS
#define _NMLOG(level, ...) \
    G_STMT_START { \
        if (nm_logging_enabled ((level), (_NMLOG_DOMAIN))) { \
            char __prefix[32]; \
            \
            if ((self)) \
                g_snprintf (__prefix, sizeof (__prefix), "%s[%p]", ""_NMLOG_PREFIX_NAME"", (self)); \
            else \
                g_strlcpy (__prefix, _NMLOG_PREFIX_NAME, sizeof (__prefix)); \
            _nm_log ((level), (_NMLOG_DOMAIN), 0, NULL, NULL, \
                     "%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
                     __prefix _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
        } \
    } G_STMT_END

#define LOG_REQ_FMT          "req[%p,%s,%s%s%s%s]"
#define LOG_REQ_ARG(req)     (req), (req)->dbus_command, NM_PRINT_FMT_QUOTE_STRING ((req)->path), ((req)->cancellable ? "" : " (cancelled)")

/*****************************************************************************/

NM_UTILS_FLAGS2STR_DEFINE_STATIC (_capabilities_to_string, NMSecretAgentCapabilities,
	NM_UTILS_FLAGS2STR (NM_SECRET_AGENT_CAPABILITY_NONE, "none"),
	NM_UTILS_FLAGS2STR (NM_SECRET_AGENT_CAPABILITY_VPN_HINTS, "vpn-hints"),
);

/*****************************************************************************/

struct _NMSecretAgentCallId {
	CList lst;
	NMSecretAgent *agent;
	GCancellable *cancellable;
	char *path;
	const char *dbus_command;
	char *setting_name;
	gboolean is_get_secrets;
	NMSecretAgentCallback callback;
	gpointer callback_data;
};

static NMSecretAgentCallId *
request_new (NMSecretAgent *self,
             const char *dbus_command, /* this must be a static string. */
             const char *path,
             const char *setting_name,
             NMSecretAgentCallback callback,
             gpointer callback_data)
{
	NMSecretAgentCallId *r;

	r = g_slice_new0 (NMSecretAgentCallId);
	r->agent = self;
	r->path = g_strdup (path);
	r->setting_name = g_strdup (setting_name);
	r->dbus_command = dbus_command,
	r->callback = callback;
	r->callback_data = callback_data;
	r->cancellable = g_cancellable_new ();
	c_list_link_tail (&NM_SECRET_AGENT_GET_PRIVATE (self)->requests,
	                  &r->lst);
	_LOGt ("request "LOG_REQ_FMT": created", LOG_REQ_ARG (r));
	return r;
}
#define request_new(self,dbus_command,path,setting_name,callback,callback_data) request_new(self,""dbus_command"",path,setting_name,callback,callback_data)

static void
request_free (NMSecretAgentCallId *r)
{
	NMSecretAgent *self = r->agent;

	_LOGt ("request "LOG_REQ_FMT": destroyed", LOG_REQ_ARG (r));
	c_list_unlink_stale (&r->lst);
	g_free (r->path);
	g_free (r->setting_name);
	if (r->cancellable)
		g_object_unref (r->cancellable);
	g_slice_free (NMSecretAgentCallId, r);
}

static gboolean
request_check_return (NMSecretAgentCallId *r)
{
	if (!r->cancellable)
		return FALSE;

	g_return_val_if_fail (NM_IS_SECRET_AGENT (r->agent), FALSE);

	nm_assert (c_list_contains (&NM_SECRET_AGENT_GET_PRIVATE (r->agent)->requests,
	                            &r->lst));

	c_list_unlink (&r->lst);

	return TRUE;
}

/*****************************************************************************/

static char *
_create_description (const char *dbus_owner, const char *identifier, gulong uid)
{
	return g_strdup_printf ("%s/%s/%lu",
	                        dbus_owner,
	                        identifier,
	                        uid);
}

const char *
nm_secret_agent_get_description (NMSecretAgent *agent)
{
	NMSecretAgentPrivate *priv;

	g_return_val_if_fail (NM_IS_SECRET_AGENT (agent), NULL);

	priv = NM_SECRET_AGENT_GET_PRIVATE (agent);
	if (!priv->description) {
		priv->description = _create_description (priv->dbus_owner,
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

/*****************************************************************************/

static void
get_callback (GObject *proxy,
              GAsyncResult *result,
              gpointer user_data)
{
	NMSecretAgentCallId *r = user_data;

	if (request_check_return (r)) {
		NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (r->agent);
		gs_free_error GError *error = NULL;
		gs_unref_variant GVariant *ret = NULL;
		gs_unref_variant GVariant *secrets = NULL;

		ret = _nm_dbus_proxy_call_finish (priv->proxy, result, G_VARIANT_TYPE ("(a{sa{sv}})"), &error);
		if (!ret)
			g_dbus_error_strip_remote_error (error);
		else {
			g_variant_get (ret,
			               "(@a{sa{sv}})",
			               &secrets);
		}
		r->callback (r->agent, r, secrets, error, r->callback_data);
	}

	request_free (r);
}

NMSecretAgentCallId *
nm_secret_agent_get_secrets (NMSecretAgent *self,
                             const char *path,
                             NMConnection *connection,
                             const char *setting_name,
                             const char **hints,
                             NMSecretAgentGetSecretsFlags flags,
                             NMSecretAgentCallback callback,
                             gpointer callback_data)
{
	NMSecretAgentPrivate *priv;
	GVariant *dict;
	NMSecretAgentCallId *r;

	g_return_val_if_fail (NM_IS_SECRET_AGENT (self), NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (path && *path, NULL);
	g_return_val_if_fail (setting_name != NULL, NULL);

	priv = NM_SECRET_AGENT_GET_PRIVATE (self);
	g_return_val_if_fail (priv->proxy != NULL, NULL);

	dict = nm_connection_to_dbus (connection, NM_CONNECTION_SERIALIZE_ALL);

	/* Mask off the private flags if present */
	flags &= ~NM_SECRET_AGENT_GET_SECRETS_FLAG_ONLY_SYSTEM;
	flags &= ~NM_SECRET_AGENT_GET_SECRETS_FLAG_NO_ERRORS;

	r = request_new (self, "GetSecrets", path, setting_name, callback, callback_data);
	r->is_get_secrets = TRUE;

	g_dbus_proxy_call (priv->proxy,
	                   "GetSecrets",
	                   g_variant_new ("(@a{sa{sv}}os^asu)",
	                                  dict,
	                                  path,
	                                  setting_name,
	                                  hints ?: NM_PTRARRAY_EMPTY (const char *),
	                                  (guint32) flags),
	                   G_DBUS_CALL_FLAGS_NONE,
	                   120000,
	                   r->cancellable,
	                   get_callback,
	                   r);

	g_dbus_proxy_set_default_timeout (G_DBUS_PROXY (priv->proxy), -1);

	return r;
}

/*****************************************************************************/

static void
cancel_done (GObject *proxy, GAsyncResult *result, gpointer user_data)
{
	gs_free char *description = user_data;
	gs_free_error GError *error = NULL;
	gs_unref_variant GVariant *ret = NULL;

	ret = _nm_dbus_proxy_call_finish (G_DBUS_PROXY (proxy), result, G_VARIANT_TYPE ("()"), &error);
	if (!ret) {
		nm_log_dbg (LOGD_AGENTS, "%s%s%s: agent failed to cancel secrets: %s",
		            NM_PRINT_FMT_QUOTED (description, "(", description, ")", "???"),
		            error->message);
	}
}

static void
do_cancel_secrets (NMSecretAgent *self, NMSecretAgentCallId *r, gboolean disposing)
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
		g_dbus_proxy_call (G_DBUS_PROXY (priv->proxy),
		                   "CancelGetSecrets",
		                   g_variant_new ("(os)",
		                                  r->path,
		                                  r->setting_name),
		                   G_DBUS_CALL_FLAGS_NONE,
		                   -1,
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
		gs_free_error GError *error = NULL;

		nm_utils_error_set_cancelled (&error, disposing, "NMSecretAgent");
		/* @r might be a dangling pointer at this point. However, that is no problem
		 * to pass it as (opaque) call_id. */
		callback (self, r, NULL, error, callback_data);
	}
}

/**
 * nm_secret_agent_cancel_secrets:
 * @self: #NMSecretAgent instance
 * @call_id: the call id to cancel
 *
 * It is an error to pass an invalid @call_id or a @call_id for an operation
 * that already completed. NMSecretAgent will always invoke the callback,
 * also for cancel() and dispose().
 * In case of nm_secret_agent_cancel_secrets() this will synchronously invoke the
 * callback before nm_secret_agent_cancel_secrets() returns.
 */
void
nm_secret_agent_cancel_secrets (NMSecretAgent *self, NMSecretAgentCallId *call_id)
{
	NMSecretAgentCallId *r = call_id;

	g_return_if_fail (NM_IS_SECRET_AGENT (self));
	g_return_if_fail (r);

	nm_assert (c_list_contains (&NM_SECRET_AGENT_GET_PRIVATE (self)->requests,
	                            &r->lst));

	c_list_unlink (&r->lst);

	do_cancel_secrets (self, r, FALSE);
}

/*****************************************************************************/

static void
agent_save_cb (GObject *proxy,
               GAsyncResult *result,
               gpointer user_data)
{
	NMSecretAgentCallId *r = user_data;

	if (request_check_return (r)) {
		gs_free_error GError *error = NULL;
		gs_unref_variant GVariant *ret = NULL;

		ret = _nm_dbus_proxy_call_finish (G_DBUS_PROXY (proxy), result, G_VARIANT_TYPE ("()"), &error);
		if (!ret)
			g_dbus_error_strip_remote_error (error);
		r->callback (r->agent, r, NULL, error, r->callback_data);
	}

	request_free (r);
}

NMSecretAgentCallId *
nm_secret_agent_save_secrets (NMSecretAgent *self,
                              const char *path,
                              NMConnection *connection,
                              NMSecretAgentCallback callback,
                              gpointer callback_data)
{
	NMSecretAgentPrivate *priv;
	GVariant *dict;
	NMSecretAgentCallId *r;

	g_return_val_if_fail (NM_IS_SECRET_AGENT (self), NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (path && *path, NULL);

	priv = NM_SECRET_AGENT_GET_PRIVATE (self);

	/* Caller should have ensured that only agent-owned secrets exist in 'connection' */
	dict = nm_connection_to_dbus (connection, NM_CONNECTION_SERIALIZE_ALL);

	r = request_new (self, "SaveSecrets", path, NULL, callback, callback_data);
	g_dbus_proxy_call (priv->proxy,
	                   "SaveSecrets",
	                   g_variant_new ("(@a{sa{sv}}o)",
	                                  dict,
	                                  path),
	                   G_DBUS_CALL_FLAGS_NONE,
	                   -1,
	                   NULL, /* cancelling the request does *not* cancel the D-Bus call. */
	                   agent_save_cb,
	                   r);

	return r;
}

/*****************************************************************************/

static void
agent_delete_cb (GObject *proxy,
                 GAsyncResult *result,
                 gpointer user_data)
{
	NMSecretAgentCallId *r = user_data;

	if (request_check_return (r)) {
		gs_free_error GError *error = NULL;
		gs_unref_variant GVariant *ret = NULL;

		ret = _nm_dbus_proxy_call_finish (G_DBUS_PROXY (proxy), result, G_VARIANT_TYPE ("()"), &error);
		if (!ret)
			g_dbus_error_strip_remote_error (error);
		r->callback (r->agent, r, NULL, error, r->callback_data);
	}

	request_free (r);
}

NMSecretAgentCallId *
nm_secret_agent_delete_secrets (NMSecretAgent *self,
                                const char *path,
                                NMConnection *connection,
                                NMSecretAgentCallback callback,
                                gpointer callback_data)
{
	NMSecretAgentPrivate *priv;
	GVariant *dict;
	NMSecretAgentCallId *r;

	g_return_val_if_fail (NM_IS_SECRET_AGENT (self), NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (path && *path, NULL);

	priv = NM_SECRET_AGENT_GET_PRIVATE (self);

	/* No secrets sent; agents must be smart enough to track secrets using the UUID or something */
	dict = nm_connection_to_dbus (connection, NM_CONNECTION_SERIALIZE_NO_SECRETS);

	r = request_new (self, "DeleteSecrets", path, NULL, callback, callback_data);
	g_dbus_proxy_call (priv->proxy,
	                   "DeleteSecrets",
	                   g_variant_new ("(@a{sa{sv}}o)",
	                                  dict,
	                                  path),
	                   G_DBUS_CALL_FLAGS_NONE,
	                   -1,
	                   NULL, /* cancelling the request does *not* cancel the D-Bus call. */
	                   agent_delete_cb,
	                   r);
	return r;
}

/*****************************************************************************/

static void
_on_disconnected_cleanup (NMSecretAgentPrivate *priv)
{
	if (priv->on_disconnected_id) {
		if (priv->connection_is_private) {
			g_signal_handler_disconnect (priv->bus_mgr,
			                             priv->on_disconnected_id);
		} else {
			g_dbus_connection_signal_unsubscribe (priv->connection,
			                                      priv->on_disconnected_id);
		}
		priv->on_disconnected_id = 0;
	}

	g_clear_object (&priv->connection);
	g_clear_object (&priv->proxy);
	g_clear_object (&priv->bus_mgr);
}

static void
_on_disconnected_private_connection (NMDBusManager *mgr,
                                     GDBusConnection *connection,
                                     NMSecretAgent *self)
{
	NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (self);

	if (priv->connection != connection)
		return;

	_LOGt ("private connection disconnected");

	_on_disconnected_cleanup (priv);
	g_signal_emit (self, signals[DISCONNECTED], 0);
}

static void
_on_disconnected_name_owner_changed (GDBusConnection *connection,
                                     const char       *sender_name,
                                     const char       *object_path,
                                     const char       *interface_name,
                                     const char       *signal_name,
                                     GVariant         *parameters,
                                     gpointer          user_data)
{
	NMSecretAgent *self = NM_SECRET_AGENT (user_data);
	NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (self);
	const char *old_owner = NULL, *new_owner = NULL;

	g_variant_get (parameters,
	               "(&s&s&s)",
	               NULL,
	               &old_owner,
	               &new_owner);

	_LOGt ("name-owner-changed: %s%s%s => %s%s%s",
	       NM_PRINT_FMT_QUOTE_STRING (old_owner),
	       NM_PRINT_FMT_QUOTE_STRING (new_owner));

	if (!*new_owner) {
		_on_disconnected_cleanup (priv);
		g_signal_emit (self, signals[DISCONNECTED], 0);
	}
}

/*****************************************************************************/

NMSecretAgent *
nm_secret_agent_new (GDBusMethodInvocation *context,
                     NMAuthSubject *subject,
                     const char *identifier,
                     NMSecretAgentCapabilities capabilities)
{
	NMSecretAgent *self;
	NMSecretAgentPrivate *priv;
	const char *dbus_owner;
	struct passwd *pw;
	char *owner_username = NULL;
	char *description = NULL;
	char buf_subject[64];
	char buf_caps[150];
	gulong uid;
	GDBusConnection *connection;

	g_return_val_if_fail (context != NULL, NULL);
	g_return_val_if_fail (NM_IS_AUTH_SUBJECT (subject), NULL);
	g_return_val_if_fail (nm_auth_subject_is_unix_process (subject), NULL);
	g_return_val_if_fail (identifier != NULL, NULL);

	connection = g_dbus_method_invocation_get_connection (context);

	g_return_val_if_fail (G_IS_DBUS_CONNECTION (connection), NULL);

	uid = nm_auth_subject_get_unix_process_uid (subject);

	pw = getpwuid (uid);
	if (pw && pw->pw_name && pw->pw_name[0])
		owner_username = g_strdup (pw->pw_name);

	dbus_owner = nm_auth_subject_get_unix_process_dbus_sender (subject);

	self = (NMSecretAgent *) g_object_new (NM_TYPE_SECRET_AGENT, NULL);

	priv = NM_SECRET_AGENT_GET_PRIVATE (self);

	priv->bus_mgr = g_object_ref (nm_dbus_manager_get ());
	priv->connection = g_object_ref (connection);
	priv->connection_is_private = !!nm_dbus_manager_connection_get_private_name (priv->bus_mgr, connection);

	_LOGt ("constructed: %s, owner=%s%s%s (%s), private-connection=%d, unique-name=%s%s%s, capabilities=%s",
	       (description = _create_description (dbus_owner, identifier, uid)),
	       NM_PRINT_FMT_QUOTE_STRING (owner_username),
	       nm_auth_subject_to_string (subject, buf_subject, sizeof (buf_subject)),
	       priv->connection_is_private,
	       NM_PRINT_FMT_QUOTE_STRING (g_dbus_connection_get_unique_name (priv->connection)),
	       _capabilities_to_string (capabilities, buf_caps, sizeof (buf_caps)));

	priv->identifier = g_strdup (identifier);
	priv->owner_username = owner_username;
	priv->dbus_owner = g_strdup (dbus_owner);
	priv->description = description;
	priv->capabilities = capabilities;
	priv->subject = g_object_ref (subject);

	priv->proxy = nm_dbus_manager_new_proxy (priv->bus_mgr,
	                                         priv->connection,
	                                         G_TYPE_DBUS_PROXY,
	                                         priv->dbus_owner,
	                                         NM_DBUS_PATH_SECRET_AGENT,
	                                         NM_DBUS_INTERFACE_SECRET_AGENT);

	/* we cannot subscribe to notify::g-name-owner because that doesn't work
	 * for unique names and it doesn't work for private connections. */
	if (priv->connection_is_private) {
		priv->on_disconnected_id = g_signal_connect (priv->bus_mgr,
		                                             NM_DBUS_MANAGER_PRIVATE_CONNECTION_DISCONNECTED,
		                                             G_CALLBACK (_on_disconnected_private_connection),
		                                             self);
	} else {
		priv->on_disconnected_id = g_dbus_connection_signal_subscribe (priv->connection,
		                                                               "org.freedesktop.DBus",  /* name */
		                                                               "org.freedesktop.DBus",  /* interface */
		                                                               "NameOwnerChanged",      /* signal name */
		                                                               "/org/freedesktop/DBus", /* path */
		                                                               priv->dbus_owner,        /* arg0 */
		                                                               G_DBUS_SIGNAL_FLAGS_NONE,
		                                                               _on_disconnected_name_owner_changed,
		                                                               self,
		                                                               NULL);
	}

	return self;
}

static void
nm_secret_agent_init (NMSecretAgent *self)
{
	NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (self);

	c_list_init (&priv->requests);
}

static void
dispose (GObject *object)
{
	NMSecretAgent *self = NM_SECRET_AGENT (object);
	NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (self);
	CList *iter;

again:
	c_list_for_each (iter, &priv->requests) {
		c_list_unlink (iter);
		do_cancel_secrets (self, c_list_entry (iter, NMSecretAgentCallId, lst), TRUE);
		goto again;
	}

	_on_disconnected_cleanup (priv);

	g_clear_object (&priv->subject);

	G_OBJECT_CLASS (nm_secret_agent_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMSecretAgent *self = NM_SECRET_AGENT (object);
	NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (self);

	g_free (priv->description);
	g_free (priv->identifier);
	g_free (priv->owner_username);
	g_free (priv->dbus_owner);

	g_slist_free_full (priv->permissions, g_free);

	G_OBJECT_CLASS (nm_secret_agent_parent_class)->finalize (object);

	_LOGt ("finalized");
}

static void
nm_secret_agent_class_init (NMSecretAgentClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);

	object_class->dispose = dispose;
	object_class->finalize = finalize;

	signals[DISCONNECTED] =
	    g_signal_new (NM_SECRET_AGENT_DISCONNECTED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0,
	                  NULL, NULL,
	                  g_cclosure_marshal_VOID__VOID,
	                  G_TYPE_NONE, 0);
}

