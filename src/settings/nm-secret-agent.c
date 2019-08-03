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

#include "nm-glib-aux/nm-c-list.h"
#include "nm-glib-aux/nm-dbus-aux.h"
#include "nm-dbus-interface.h"
#include "nm-core-internal.h"
#include "nm-auth-subject.h"
#include "nm-simple-connection.h"
#include "NetworkManagerUtils.h"
#include "c-list/src/c-list.h"

/*****************************************************************************/

#define METHOD_GET_SECRETS        "GetSecrets"
#define METHOD_CANCEL_GET_SECRETS "CancelGetSecrets"
#define METHOD_SAVE_SECRETS       "SaveSecrets"
#define METHOD_DELETE_SECRETS     "DeleteSecrets"

enum {
	DISCONNECTED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	CList permissions;
	char *description;
	NMAuthSubject *subject;
	char *identifier;
	char *owner_username;
	char *dbus_owner;
	GDBusConnection *dbus_connection;
	GCancellable *name_owner_cancellable;
	CList requests;
	NMSecretAgentCapabilities capabilities;
	guint name_owner_changed_id;
	bool shutdown_wait_obj_registered:1;
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
            char _prefix[64]; \
            \
            if ((self)) { \
                g_snprintf (_prefix, \
                            sizeof (_prefix), \
                            _NMLOG_PREFIX_NAME"["NM_HASH_OBFUSCATE_PTR_FMT"]", \
                            NM_HASH_OBFUSCATE_PTR (self)); \
            } else \
                g_strlcpy (_prefix, _NMLOG_PREFIX_NAME, sizeof (_prefix)); \
            \
            _nm_log ((level), \
                     (_NMLOG_DOMAIN), \
                     0, \
                     NULL, \
                     NULL, \
                     "%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
                     _prefix \
                     _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
        } \
    } G_STMT_END

#define _NMLOG2(level, call_id, ...) \
    G_STMT_START { \
        NMSecretAgentCallId *const _call_id = (call_id); \
        \
        nm_assert (_call_id); \
        \
        nm_log ((level), \
                (_NMLOG_DOMAIN), \
                NULL, \
                NULL, \
                "%s["NM_HASH_OBFUSCATE_PTR_FMT"] request ["NM_HASH_OBFUSCATE_PTR_FMT",%s,%s%s%s%s]: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
                _NMLOG_PREFIX_NAME, \
                NM_HASH_OBFUSCATE_PTR (_call_id->self), \
                NM_HASH_OBFUSCATE_PTR (_call_id), \
                _call_id->method_name, \
                NM_PRINT_FMT_QUOTE_STRING (_call_id->path), \
                (_call_id->cancellable ? "" : " (cancelled)") \
                _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
    } G_STMT_END

/*****************************************************************************/

NM_UTILS_FLAGS2STR_DEFINE_STATIC (_capabilities_to_string, NMSecretAgentCapabilities,
	NM_UTILS_FLAGS2STR (NM_SECRET_AGENT_CAPABILITY_NONE,      "none"),
	NM_UTILS_FLAGS2STR (NM_SECRET_AGENT_CAPABILITY_VPN_HINTS, "vpn-hints"),
);

/*****************************************************************************/

struct _NMSecretAgentCallId {
	CList lst;
	NMSecretAgent *self;
	GCancellable *cancellable;
	char *path;
	const char *method_name;
	char *setting_name;
	NMSecretAgentCallback callback;
	gpointer callback_data;
};

static NMSecretAgentCallId *
_call_id_new (NMSecretAgent *self,
              const char *method_name, /* this must be a static string. */
              const char *path,
              const char *setting_name,
              NMSecretAgentCallback callback,
              gpointer callback_data)
{
	NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (self);
	NMSecretAgentCallId *call_id;

	call_id = g_slice_new (NMSecretAgentCallId);
	*call_id = (NMSecretAgentCallId) {
		.self              = g_object_ref (self),
		.path              = g_strdup (path),
		.setting_name      = g_strdup (setting_name),
		.method_name       = method_name,
		.callback          = callback,
		.callback_data     = callback_data,
		.cancellable       = g_cancellable_new (),
	};
	c_list_link_tail (&priv->requests, &call_id->lst);

	_LOG2T (call_id, "new request...");

	if (!priv->shutdown_wait_obj_registered) {
		/* self has async requests (that keep self alive). As long as
		 * we have pending requests, shutdown is blocked. */
		priv->shutdown_wait_obj_registered = TRUE;
		nm_shutdown_wait_obj_register (G_OBJECT (self), "secret-agent");
	}

	return call_id;
}

#define _call_id_new(self, method_name, path, setting_name, callback, callback_data) _call_id_new(self, ""method_name"", path, setting_name, callback, callback_data)

static void
_call_id_free (NMSecretAgentCallId *call_id)
{
	c_list_unlink_stale (&call_id->lst);
	g_free (call_id->path);
	g_free (call_id->setting_name);
	nm_g_object_unref (call_id->cancellable);
	g_object_unref (call_id->self);
	nm_g_slice_free (call_id);
}

static void
_call_id_invoke_callback (NMSecretAgentCallId *call_id,
                          GVariant *secrets,
                          GError *error,
                          gboolean cancelled,
                          gboolean free_call_id)
{
	gs_free_error GError *error_cancelled = NULL;

	nm_assert (call_id);
	nm_assert (!c_list_is_empty (&call_id->lst));

	c_list_unlink (&call_id->lst);

	if (cancelled) {
		nm_assert (!secrets);
		nm_assert (!error);
		if (call_id->callback) {
			nm_utils_error_set_cancelled (&error_cancelled, FALSE, "NMSecretAgent");
			error = error_cancelled;
		}
		_LOG2T (call_id, "cancelled");
	} else if (error) {
		nm_assert (!secrets);
		_LOG2T (call_id, "completed with failure: %s", error->message);
	} else {
		nm_assert (   !secrets
		           || g_variant_is_of_type (secrets, G_VARIANT_TYPE ("a{sa{sv}}")));
		nm_assert ((!!secrets) == nm_streq0 (call_id->method_name, METHOD_GET_SECRETS));
		_LOG2T (call_id, "completed successfully");
	}

	if (call_id->callback)
		call_id->callback (call_id->self, call_id, secrets, error, call_id->callback_data);

	if (free_call_id)
		_call_id_free (call_id);
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

/*****************************************************************************/

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

/*****************************************************************************/

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
	NMCListElem *elem;

	g_return_if_fail (agent != NULL);
	g_return_if_fail (permission != NULL);

	priv = NM_SECRET_AGENT_GET_PRIVATE (agent);

	elem = nm_c_list_elem_find_first (&priv->permissions, p, nm_streq (p, permission));

	if (elem) {
		if (!allowed)
			nm_c_list_elem_free_full (elem, g_free);
		return;
	}

	if (allowed) {
		c_list_link_tail (&priv->permissions,
		                  &nm_c_list_elem_new_stale (g_strdup (permission))->lst);
	}
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
	g_return_val_if_fail (agent != NULL, FALSE);
	g_return_val_if_fail (permission != NULL, FALSE);

	return !!nm_c_list_elem_find_first (&NM_SECRET_AGENT_GET_PRIVATE (agent)->permissions,
	                                    p, nm_streq (p, permission));
}

/*****************************************************************************/

static void
_dbus_call_cb (GObject *source,
               GAsyncResult *result,
               gpointer user_data)
{
	NMSecretAgentCallId *call_id;
	gs_unref_variant GVariant *ret = NULL;
	gs_unref_variant GVariant *secrets = NULL;
	gs_free_error GError *error = NULL;

	ret = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source), result, &error);

	if (   !ret
	    && nm_utils_error_is_cancelled (error, FALSE))
		return;

	call_id = user_data;

	if (!ret)
		g_dbus_error_strip_remote_error (error);
	else {
		if (nm_streq (call_id->method_name, METHOD_GET_SECRETS)) {
			g_variant_get (ret,
			               "(@a{sa{sv}})",
			               &secrets);
		}
	}

	_call_id_invoke_callback (call_id, secrets, error, FALSE, TRUE);
}

/*****************************************************************************/

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
	NMSecretAgentCallId *call_id;

	g_return_val_if_fail (NM_IS_SECRET_AGENT (self), NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (path && *path, NULL);
	g_return_val_if_fail (setting_name, NULL);
	g_return_val_if_fail (callback, NULL);

	priv = NM_SECRET_AGENT_GET_PRIVATE (self);

	dict = nm_connection_to_dbus (connection, NM_CONNECTION_SERIALIZE_ALL);

	/* Mask off the private flags if present */
	flags &= ~(  NM_SECRET_AGENT_GET_SECRETS_FLAG_ONLY_SYSTEM
	           | NM_SECRET_AGENT_GET_SECRETS_FLAG_NO_ERRORS);

	call_id = _call_id_new (self, METHOD_GET_SECRETS, path, setting_name, callback, callback_data);

	g_dbus_connection_call (priv->dbus_connection,
	                        priv->dbus_owner,
	                        NM_DBUS_PATH_SECRET_AGENT,
	                        NM_DBUS_INTERFACE_SECRET_AGENT,
	                        call_id->method_name,
	                        g_variant_new ("(@a{sa{sv}}os^asu)",
	                                       dict,
	                                       path,
	                                       setting_name,
	                                       hints ?: NM_PTRARRAY_EMPTY (const char *),
	                                       (guint32) flags),
	                        G_VARIANT_TYPE ("(a{sa{sv}})"),
	                        G_DBUS_CALL_FLAGS_NO_AUTO_START,
	                        120000,
	                        call_id->cancellable,
	                        _dbus_call_cb,
	                        call_id);

	return call_id;
}

/*****************************************************************************/

static void
_call_cancel_cb (GObject *source,
                 GAsyncResult *result,
                 gpointer user_data)
{
	NMSecretAgentCallId *call_id = user_data;
	gs_free_error GError *error = NULL;
	gs_unref_variant GVariant *ret = NULL;

	ret = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source), result, &error);

	if (ret)
		_LOG2T (call_id, "success cancelling GetSecrets");
	else if (g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_SERVICE_UNKNOWN))
		_LOG2T (call_id, "cancelling GetSecrets no longer works as service disconnected");
	else {
		_LOG2T (call_id, "failed to cancel GetSecrets: %s",
		        error->message);
	}

	_call_id_free (call_id);
}

/**
 * nm_secret_agent_cancel_call:
 * @self: the #NMSecretAgent instance for the @call_id.
 *   Maybe be %NULL if @call_id is %NULL.
 * @call_id: (allow-none): the call id to cancel. May be %NULL for convenience,
 *   in which case it does nothing.
 *
 * It is an error to pass an invalid @call_id or a @call_id for an operation
 * that already completed. It is also an error to cancel the call from inside
 * the callback, at that point the call is already completed.
 * In case of nm_secret_agent_cancel_call() this will synchronously invoke the
 * callback before nm_secret_agent_cancel_call() returns.
 */
void
nm_secret_agent_cancel_call (NMSecretAgent *self,
                             NMSecretAgentCallId *call_id)
{
	NMSecretAgentPrivate *priv;
	gboolean free_call_id = TRUE;

	if (!call_id) {
		/* for convenience, %NULL is accepted fine. */
		nm_assert (!self || NM_IS_SECRET_AGENT (self));
		return;
	}

	g_return_if_fail (NM_IS_SECRET_AGENT (call_id->self));
	g_return_if_fail (!c_list_is_empty (&call_id->lst));

	/* Theoretically, call-id already has a self pointer. But nm_secret_agent_cancel_call() has only
	 * one user: NMAgentManager. And that one has the self-pointer at hand, so the only purpose of
	 * the @self argument is to assert that we are cancelling the expected call.
	 *
	 * We could drop the @self argument, but that just remove an additional assert-check from
	 * our code, without making a simplification for the only caller of this function. */
	g_return_if_fail (self == call_id->self);

	priv = NM_SECRET_AGENT_GET_PRIVATE (self);

	nm_assert (c_list_contains (&priv->requests,
	                            &call_id->lst));

	nm_clear_g_cancellable (&call_id->cancellable);

	if (nm_streq (call_id->method_name, METHOD_GET_SECRETS)) {
		g_dbus_connection_call (priv->dbus_connection,
		                        priv->dbus_owner,
		                        NM_DBUS_PATH_SECRET_AGENT,
		                        NM_DBUS_INTERFACE_SECRET_AGENT,
		                        METHOD_CANCEL_GET_SECRETS,
		                        g_variant_new ("(os)",
		                                       call_id->path,
		                                       call_id->setting_name),
		                        G_VARIANT_TYPE ("()"),
		                        G_DBUS_CALL_FLAGS_NO_AUTO_START,
		                        NM_SHUTDOWN_TIMEOUT_MS,
		                        NULL, /* this operation is not cancellable. We rely on the timeout. */
		                        _call_cancel_cb,
		                        call_id);
		/* we keep call-id alive, but it will be unlinked from priv->requests.
		 * _call_cancel_cb() will finally free it later. */
		free_call_id = FALSE;
	}

	_call_id_invoke_callback (call_id, NULL, NULL, TRUE, free_call_id);
}

/*****************************************************************************/

NMSecretAgentCallId *
nm_secret_agent_save_secrets (NMSecretAgent *self,
                              const char *path,
                              NMConnection *connection,
                              NMSecretAgentCallback callback,
                              gpointer callback_data)
{
	NMSecretAgentPrivate *priv;
	GVariant *dict;
	NMSecretAgentCallId *call_id;

	g_return_val_if_fail (NM_IS_SECRET_AGENT (self), NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (path && *path, NULL);

	priv = NM_SECRET_AGENT_GET_PRIVATE (self);

	/* Caller should have ensured that only agent-owned secrets exist in 'connection' */
	dict = nm_connection_to_dbus (connection, NM_CONNECTION_SERIALIZE_ALL);

	call_id = _call_id_new (self, METHOD_SAVE_SECRETS, path, NULL, callback, callback_data);

	g_dbus_connection_call (priv->dbus_connection,
	                        priv->dbus_owner,
	                        NM_DBUS_PATH_SECRET_AGENT,
	                        NM_DBUS_INTERFACE_SECRET_AGENT,
	                        call_id->method_name,
	                        g_variant_new ("(@a{sa{sv}}o)",
	                                       dict,
	                                       path),
	                        G_VARIANT_TYPE ("()"),
	                        G_DBUS_CALL_FLAGS_NO_AUTO_START,
	                        60000,
	                        call_id->cancellable,
	                        _dbus_call_cb,
	                        call_id);

	return call_id;
}

/*****************************************************************************/

NMSecretAgentCallId *
nm_secret_agent_delete_secrets (NMSecretAgent *self,
                                const char *path,
                                NMConnection *connection,
                                NMSecretAgentCallback callback,
                                gpointer callback_data)
{
	NMSecretAgentPrivate *priv;
	GVariant *dict;
	NMSecretAgentCallId *call_id;

	g_return_val_if_fail (NM_IS_SECRET_AGENT (self), NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (path && *path, NULL);

	priv = NM_SECRET_AGENT_GET_PRIVATE (self);

	/* No secrets sent; agents must be smart enough to track secrets using the UUID or something */
	dict = nm_connection_to_dbus (connection, NM_CONNECTION_SERIALIZE_NO_SECRETS);

	call_id = _call_id_new (self, METHOD_DELETE_SECRETS, path, NULL, callback, callback_data);

	g_dbus_connection_call (priv->dbus_connection,
	                        priv->dbus_owner,
	                        NM_DBUS_PATH_SECRET_AGENT,
	                        NM_DBUS_INTERFACE_SECRET_AGENT,
	                        call_id->method_name,
	                        g_variant_new ("(@a{sa{sv}}o)",
	                                       dict,
	                                       path),
	                        G_VARIANT_TYPE ("()"),
	                        G_DBUS_CALL_FLAGS_NO_AUTO_START,
	                        60000,
	                        call_id->cancellable,
	                        _dbus_call_cb,
	                        call_id);
	return call_id;
}

/*****************************************************************************/

static void
name_owner_changed (NMSecretAgent *self,
                    const char *owner)
{
	NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (self);

	nm_assert (!priv->name_owner_cancellable);

	owner = nm_str_not_empty (owner);

	_LOGT ("name-owner-changed: %s%s%s",
	       NM_PRINT_FMT_QUOTED (owner, "has ", owner, "", "disconnected"));

	if (owner)
		return;

	nm_clear_g_dbus_connection_signal (priv->dbus_connection,
	                                   &priv->name_owner_changed_id);

	g_signal_emit (self, signals[DISCONNECTED], 0);
}

static void
name_owner_changed_cb (GDBusConnection *dbus_connection,
                       const char       *sender_name,
                       const char       *object_path,
                       const char       *interface_name,
                       const char       *signal_name,
                       GVariant         *parameters,
                       gpointer          user_data)
{
	NMSecretAgent *self = NM_SECRET_AGENT (user_data);
	const char *new_owner = NULL;

	if (g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(sss)"))) {
		g_variant_get (parameters,
		               "(&s&s&s)",
		               NULL,
		               NULL,
		               &new_owner);
	}

	nm_clear_g_cancellable (&NM_SECRET_AGENT_GET_PRIVATE (self)->name_owner_cancellable);

	name_owner_changed (self, new_owner);
}

static void
get_name_owner_cb (const char *name_owner,
                   GError *error,
                   gpointer user_data)
{
	NMSecretAgent *self;

	if (   !name_owner
	    && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = user_data;

	g_clear_object (&NM_SECRET_AGENT_GET_PRIVATE (self)->name_owner_cancellable);

	name_owner_changed (self, name_owner);
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
	GDBusConnection *dbus_connection;

	g_return_val_if_fail (context != NULL, NULL);
	g_return_val_if_fail (NM_IS_AUTH_SUBJECT (subject), NULL);
	g_return_val_if_fail (nm_auth_subject_is_unix_process (subject), NULL);
	g_return_val_if_fail (identifier != NULL, NULL);

	dbus_connection = g_dbus_method_invocation_get_connection (context);

	g_return_val_if_fail (G_IS_DBUS_CONNECTION (dbus_connection), NULL);

	uid = nm_auth_subject_get_unix_process_uid (subject);

	pw = getpwuid (uid);
	if (pw && pw->pw_name && pw->pw_name[0])
		owner_username = g_strdup (pw->pw_name);

	dbus_owner = nm_auth_subject_get_unix_process_dbus_sender (subject);

	self = (NMSecretAgent *) g_object_new (NM_TYPE_SECRET_AGENT, NULL);

	priv = NM_SECRET_AGENT_GET_PRIVATE (self);

	priv->dbus_connection = g_object_ref (dbus_connection);

	_LOGT ("constructed: %s, owner=%s%s%s (%s), unique-name=%s%s%s, capabilities=%s",
	       (description = _create_description (dbus_owner, identifier, uid)),
	       NM_PRINT_FMT_QUOTE_STRING (owner_username),
	       nm_auth_subject_to_string (subject, buf_subject, sizeof (buf_subject)),
	       NM_PRINT_FMT_QUOTE_STRING (g_dbus_connection_get_unique_name (priv->dbus_connection)),
	       _capabilities_to_string (capabilities, buf_caps, sizeof (buf_caps)));

	priv->identifier = g_strdup (identifier);
	priv->owner_username = owner_username;
	priv->dbus_owner = g_strdup (dbus_owner);
	priv->description = description;
	priv->capabilities = capabilities;
	priv->subject = g_object_ref (subject);

	priv->name_owner_changed_id = nm_dbus_connection_signal_subscribe_name_owner_changed (priv->dbus_connection,
	                                                                                      priv->dbus_owner,
	                                                                                      name_owner_changed_cb,
	                                                                                      self,
	                                                                                      NULL);

	priv->name_owner_cancellable = g_cancellable_new ();
	nm_dbus_connection_call_get_name_owner (priv->dbus_connection,
	                                        priv->dbus_owner,
	                                        -1,
	                                        priv->name_owner_cancellable,
	                                        get_name_owner_cb,
	                                        self);

	return self;
}

static void
nm_secret_agent_init (NMSecretAgent *self)
{
	NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (self);

	c_list_init (&priv->permissions);
	c_list_init (&priv->requests);
}

static void
dispose (GObject *object)
{
	NMSecretAgent *self = NM_SECRET_AGENT (object);
	NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (self);

	nm_assert (c_list_is_empty (&priv->requests));

	nm_clear_g_dbus_connection_signal (priv->dbus_connection,
	                                   &priv->name_owner_changed_id);

	nm_clear_g_cancellable (&priv->name_owner_cancellable);

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

	nm_c_list_elem_free_all (&priv->permissions, g_free);

	g_clear_object (&priv->subject);

	g_clear_object (&priv->dbus_connection);

	G_OBJECT_CLASS (nm_secret_agent_parent_class)->finalize (object);

	_LOGT ("finalized");
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
