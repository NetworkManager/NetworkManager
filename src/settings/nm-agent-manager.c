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
 * Copyright (C) 2010 - 2013 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-agent-manager.h"

#include <string.h>
#include <pwd.h>

#include "nm-common-macros.h"
#include "nm-dbus-interface.h"
#include "nm-secret-agent.h"
#include "nm-auth-utils.h"
#include "nm-setting-vpn.h"
#include "nm-auth-manager.h"
#include "nm-dbus-manager.h"
#include "nm-session-monitor.h"
#include "nm-simple-connection.h"
#include "NetworkManagerUtils.h"
#include "nm-core-internal.h"
#include "nm-utils/c-list.h"

/*****************************************************************************/

enum {
	AGENT_REGISTERED,
	LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	NMAuthManager *auth_mgr;
	NMSessionMonitor *session_monitor;

	/* Auth chains for checking agent permissions */
	GSList *chains;

	/* Hashed by owner name, not identifier, since two agents in different
	 * sessions can use the same identifier.
	 */
	GHashTable *agents;

	CList requests;

	guint64 agent_version_id;
} NMAgentManagerPrivate;

struct _NMAgentManager {
	NMDBusObject parent;
	NMAgentManagerPrivate _priv;
};

struct _NMAgentManagerClass {
	NMDBusObjectClass parent;
};

G_DEFINE_TYPE (NMAgentManager, nm_agent_manager, NM_TYPE_DBUS_OBJECT)

#define NM_AGENT_MANAGER_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMAgentManager, NM_IS_AGENT_MANAGER)

/*****************************************************************************/

NM_DEFINE_SINGLETON_GETTER (NMAgentManager, nm_agent_manager_get, NM_TYPE_AGENT_MANAGER);

/*****************************************************************************/

#define _NMLOG_PREFIX_NAME    "agent-manager"
#define _NMLOG_DOMAIN         LOGD_AGENTS
#define _NMLOG(level, agent, ...) \
    G_STMT_START { \
        if (nm_logging_enabled ((level), (_NMLOG_DOMAIN))) { \
            char __prefix1[32]; \
            char __prefix2[128]; \
            NMSecretAgent *__agent = (agent); \
            \
            if (!(self)) \
                g_snprintf (__prefix1, sizeof (__prefix1), "%s%s", ""_NMLOG_PREFIX_NAME"", "[]"); \
            else if ((self) != singleton_instance) \
                g_snprintf (__prefix1, sizeof (__prefix1), "%s[%p]", ""_NMLOG_PREFIX_NAME"", (self)); \
            else \
                g_strlcpy (__prefix1, _NMLOG_PREFIX_NAME, sizeof (__prefix1)); \
            if (__agent) { \
                g_snprintf (__prefix2, sizeof (__prefix2), \
                            ": req[%p, %s]", \
                            __agent, \
                            nm_secret_agent_get_description (__agent)); \
            } else \
                __prefix2[0] = '\0'; \
            _nm_log ((level), (_NMLOG_DOMAIN), 0, NULL, NULL, \
                     "%s%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
                     __prefix1, __prefix2 _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
        } \
    } G_STMT_END

#define LOG_REQ_FMT          "[%p/%s%s%s%s%s%s]"
#define LOG_REQ_ARG(req) \
	(req), \
	NM_PRINT_FMT_QUOTE_STRING ((req)->detail), \
	NM_PRINT_FMT_QUOTED (((req)->request_type == REQUEST_TYPE_CON_GET) && (req)->con.get.setting_name, \
	                     "/\"", (req)->con.get.setting_name, "\"", \
	                     ((req)->request_type == REQUEST_TYPE_CON_GET ? "/(none)" : _request_type_to_string ((req)->request_type, FALSE)))

/*****************************************************************************/

typedef struct _NMAgentManagerCallId Request;

static void request_add_agent (Request *req, NMSecretAgent *agent);

static void request_remove_agent (Request *req, NMSecretAgent *agent);

static void request_next_agent (Request *req);

static void _con_get_request_start (Request *req);
static void _con_save_request_start (Request *req);
static void _con_del_request_start (Request *req);

static gboolean _con_get_try_complete_early (Request *req);

/*****************************************************************************/

guint64
nm_agent_manager_get_agent_version_id (NMAgentManager *self)
{
	g_return_val_if_fail (NM_IS_AGENT_MANAGER (self), 0);

	return NM_AGENT_MANAGER_GET_PRIVATE (self)->agent_version_id;
}

/*****************************************************************************/

typedef enum {
	REQUEST_TYPE_INVALID,
	REQUEST_TYPE_CON_GET,
	REQUEST_TYPE_CON_SAVE,
	REQUEST_TYPE_CON_DEL,
} RequestType;

static const char *
_request_type_to_string (RequestType request_type, gboolean verbose)
{
	switch (request_type) {
	case REQUEST_TYPE_CON_GET:  return verbose ? "getting"  : "get";
	case REQUEST_TYPE_CON_SAVE: return verbose ? "saving"   : "sav";
	case REQUEST_TYPE_CON_DEL:  return verbose ? "deleting" : "del";
	default: return "??";
	}
}

/*****************************************************************************/

struct _NMAgentManagerCallId {
	CList lst_request;

	NMAgentManager *self;

	RequestType request_type;

	char *detail;

	NMAuthSubject *subject;

	/* Current agent being asked for secrets */
	NMSecretAgent *current;
	NMSecretAgentCallId *current_call_id;

	/* Stores the sorted list of NMSecretAgents which will be asked for secrets */
	GSList *pending;

	guint idle_id;

	union {
		struct {
			char *path;
			NMConnection *connection;

			NMAuthChain *chain;

			/* Whether the agent currently being asked for secrets
			 * has the system.modify privilege.
			 */
			gboolean current_has_modify;

			union {
				struct {
					NMSecretAgentGetSecretsFlags flags;
					char *setting_name;
					char **hints;

					GVariant *existing_secrets;

					NMAgentSecretsResultFunc callback;
					gpointer callback_data;
				} get;
			};
		} con;
	};
};

/*****************************************************************************/

static gboolean
remove_agent (NMAgentManager *self, const char *owner)
{
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (self);
	NMSecretAgent *agent;
	CList *iter, *safe;

	g_return_val_if_fail (owner != NULL, FALSE);

	/* Make sure this agent has already registered */
	agent = g_hash_table_lookup (priv->agents, owner);
	if (!agent)
		return FALSE;

	_LOGD (agent, "agent unregistered or disappeared");

	/* Remove this agent from any in-progress secrets requests */
	c_list_for_each_safe (iter, safe, &priv->requests)
		request_remove_agent (c_list_entry (iter, Request, lst_request), agent);

	/* And dispose of the agent */
	g_hash_table_remove (priv->agents, owner);
	return TRUE;
}

/* Call this *after* calling request_next_agent() */
static void
maybe_remove_agent_on_error (NMSecretAgent *agent,
                             GError *error)
{
	if (   g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CLOSED)
	    || g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_DISCONNECTED)
	    || g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_NAME_HAS_NO_OWNER))
		remove_agent (nm_agent_manager_get (), nm_secret_agent_get_dbus_owner (agent));
}

/*****************************************************************************/

static gboolean
validate_identifier (const char *identifier, GError **error)
{
	const char *p = identifier;
	size_t id_len;

	if (!identifier) {
		g_set_error_literal (error,
		                     NM_AGENT_MANAGER_ERROR,
		                     NM_AGENT_MANAGER_ERROR_INVALID_IDENTIFIER,
		                     "No identifier was given");
		return FALSE;
	}

	/* Length between 3 and 255 characters inclusive */
	id_len = strlen (identifier);
	if (id_len < 3 || id_len > 255) {
		g_set_error_literal (error,
		                     NM_AGENT_MANAGER_ERROR,
		                     NM_AGENT_MANAGER_ERROR_INVALID_IDENTIFIER,
		                     "Identifier length not between 3 and 255 characters (inclusive)");
		return FALSE;
	}

	if ((identifier[0] == '.') || (identifier[id_len - 1] == '.')) {
		g_set_error_literal (error,
		                     NM_AGENT_MANAGER_ERROR,
		                     NM_AGENT_MANAGER_ERROR_INVALID_IDENTIFIER,
		                     "Identifier must not start or end with '.'");
		return FALSE;
	}

	/* FIXME: do complete validation here */
	while (p && *p) {
		if (!g_ascii_isalnum (*p) && (*p != '_') && (*p != '-') && (*p != '.')) {
			g_set_error (error,
			             NM_AGENT_MANAGER_ERROR,
				         NM_AGENT_MANAGER_ERROR_INVALID_IDENTIFIER,
				         "Identifier contains invalid character '%c'", *p);
			return FALSE;
		}

		if ((*p == '.') && (*(p + 1) == '.')) {
			g_set_error_literal (error,
			                     NM_AGENT_MANAGER_ERROR,
				                 NM_AGENT_MANAGER_ERROR_INVALID_IDENTIFIER,
				                 "Identifier contains two '.' characters in sequence");
			return FALSE;
		}
		p++;
	}

	return TRUE;
}

static void
agent_register_permissions_done (NMAuthChain *chain,
                                 GError *error,
                                 GDBusMethodInvocation *context,
                                 gpointer user_data)
{
	NMAgentManager *self = NM_AGENT_MANAGER (user_data);
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (self);
	NMSecretAgent *agent;
	const char *sender;
	GError *local = NULL;
	NMAuthCallResult result;
	CList *iter;

	g_assert (context);

	priv->chains = g_slist_remove (priv->chains, chain);

	if (error) {
		local = g_error_new (NM_AGENT_MANAGER_ERROR,
		                     NM_AGENT_MANAGER_ERROR_PERMISSION_DENIED,
		                     "Failed to request agent permissions: %s",
		                     error->message);
		g_dbus_method_invocation_take_error (context, local);
	} else {
		agent = nm_auth_chain_steal_data (chain, "agent");
		g_assert (agent);

		result = nm_auth_chain_get_result (chain, NM_AUTH_PERMISSION_WIFI_SHARE_PROTECTED);
		if (result == NM_AUTH_CALL_RESULT_YES)
			nm_secret_agent_add_permission (agent, NM_AUTH_PERMISSION_WIFI_SHARE_PROTECTED, TRUE);

		result = nm_auth_chain_get_result (chain, NM_AUTH_PERMISSION_WIFI_SHARE_OPEN);
		if (result == NM_AUTH_CALL_RESULT_YES)
			nm_secret_agent_add_permission (agent, NM_AUTH_PERMISSION_WIFI_SHARE_OPEN, TRUE);

		priv->agent_version_id += 1;
		sender = nm_secret_agent_get_dbus_owner (agent);
		g_hash_table_insert (priv->agents, g_strdup (sender), agent);
		_LOGD (agent, "agent registered");
		g_dbus_method_invocation_return_value (context, NULL);

		/* Signal an agent was registered */
		g_signal_emit (self, signals[AGENT_REGISTERED], 0, agent);

		/* Add this agent to any in-progress secrets requests */
		c_list_for_each (iter, &priv->requests)
			request_add_agent (c_list_entry (iter, Request, lst_request), agent);
	}

	nm_auth_chain_unref (chain);
}

static NMSecretAgent *
find_agent_by_identifier_and_uid (NMAgentManager *self,
                                  const char *identifier,
                                  gulong sender_uid)
{
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (self);
	GHashTableIter iter;
	NMSecretAgent *agent;

	g_hash_table_iter_init (&iter, priv->agents);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer) &agent)) {
		if (   g_strcmp0 (nm_secret_agent_get_identifier (agent), identifier) == 0
		    && nm_secret_agent_get_owner_uid (agent) == sender_uid)
			return agent;
	}
	return NULL;
}

static void
agent_disconnected_cb (NMSecretAgent *agent, gpointer user_data)
{
	/* The agent quit, so remove it and let interested clients know */
	remove_agent (NM_AGENT_MANAGER (user_data),
	              nm_secret_agent_get_dbus_owner (agent));
}

static void
agent_manager_register_with_capabilities (NMAgentManager *self,
                                          GDBusMethodInvocation *context,
                                          const char *identifier,
                                          guint32 capabilities)
{
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (self);
	NMAuthSubject *subject;
	gulong sender_uid = G_MAXULONG;
	GError *error = NULL;
	NMSecretAgent *agent;
	NMAuthChain *chain;

	subject = nm_auth_subject_new_unix_process_from_context (context);
	if (!subject) {
		error = g_error_new_literal (NM_AGENT_MANAGER_ERROR,
		                             NM_AGENT_MANAGER_ERROR_PERMISSION_DENIED,
		                             "Unable to determine request sender and UID.");
		goto done;
	}
	sender_uid = nm_auth_subject_get_unix_process_uid (subject);

	/* Validate the identifier */
	if (!validate_identifier (identifier, &error))
		goto done;

	/* Only one agent for each identifier is allowed per user */
	if (find_agent_by_identifier_and_uid (self, identifier, sender_uid)) {
		error = g_error_new_literal (NM_AGENT_MANAGER_ERROR,
		                             NM_AGENT_MANAGER_ERROR_PERMISSION_DENIED,
		                             "An agent with this ID is already registered for this user.");
		goto done;
	}

	/* Success, add the new agent */
	agent = nm_secret_agent_new (context, subject, identifier, capabilities);
	if (!agent) {
		error = g_error_new_literal (NM_AGENT_MANAGER_ERROR,
		                             NM_AGENT_MANAGER_ERROR_FAILED,
		                             "Failed to initialize the agent");
		goto done;
	}
	g_signal_connect (agent, NM_SECRET_AGENT_DISCONNECTED,
	                  G_CALLBACK (agent_disconnected_cb), self);

	_LOGD (agent, "requesting permissions");

	/* Kick off permissions requests for this agent */
	chain = nm_auth_chain_new_subject (subject, context, agent_register_permissions_done, self);
	if (chain) {
		nm_auth_chain_set_data (chain, "agent", agent, g_object_unref);
		nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_WIFI_SHARE_PROTECTED, FALSE);
		nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_WIFI_SHARE_OPEN, FALSE);

		priv->chains = g_slist_append (priv->chains, chain);
	} else {
		g_object_unref (agent);
		error = g_error_new_literal (NM_AGENT_MANAGER_ERROR,
		                             NM_AGENT_MANAGER_ERROR_FAILED,
		                             "Unable to start agent authentication.");
	}

done:
	if (error)
		g_dbus_method_invocation_take_error (context, error);
	g_clear_object (&subject);
}

static void
impl_agent_manager_register (NMDBusObject *obj,
                             const NMDBusInterfaceInfoExtended *interface_info,
                             const NMDBusMethodInfoExtended *method_info,
                             GDBusConnection *connection,
                             const char *sender,
                             GDBusMethodInvocation *invocation,
                             GVariant *parameters)
{
	const char *identifier;

	g_variant_get (parameters, "(&s)", &identifier);
	agent_manager_register_with_capabilities (NM_AGENT_MANAGER (obj), invocation, identifier, 0);
}

static void
impl_agent_manager_register_with_capabilities (NMDBusObject *obj,
                                               const NMDBusInterfaceInfoExtended *interface_info,
                                               const NMDBusMethodInfoExtended *method_info,
                                               GDBusConnection *connection,
                                               const char *sender,
                                               GDBusMethodInvocation *invocation,
                                               GVariant *parameters)
{
	const char *identifier;
	guint32 capabilities;

	g_variant_get (parameters, "(&su)", &identifier, &capabilities);
	agent_manager_register_with_capabilities (NM_AGENT_MANAGER (obj), invocation, identifier, capabilities);
}

static void
impl_agent_manager_unregister (NMDBusObject *obj,
                               const NMDBusInterfaceInfoExtended *interface_info,
                               const NMDBusMethodInfoExtended *method_info,
                               GDBusConnection *connection,
                               const char *sender,
                               GDBusMethodInvocation *invocation,
                               GVariant *parameters)
{
	NMAgentManager *self = NM_AGENT_MANAGER (obj);

	if (!remove_agent (self, sender)) {
		g_dbus_method_invocation_return_error_literal (invocation,
		                                               NM_AGENT_MANAGER_ERROR,
		                                               NM_AGENT_MANAGER_ERROR_NOT_REGISTERED,
		                                               "Caller is not registered as an Agent");
		return;
	}

	g_dbus_method_invocation_return_value (invocation, NULL);
}

/*****************************************************************************/

static Request *
request_new (NMAgentManager *self,
             RequestType request_type,
             const char *detail,
             NMAuthSubject *subject)
{
	Request *req;

	req = g_slice_new0 (Request);
	req->self = g_object_ref (self);
	req->request_type = request_type;
	req->detail = g_strdup (detail);
	req->subject = g_object_ref (subject);
	c_list_link_tail (&NM_AGENT_MANAGER_GET_PRIVATE (self)->requests, &req->lst_request);
	return req;
}

static void
request_free (Request *req)
{
	switch (req->request_type) {
	case REQUEST_TYPE_CON_GET:
	case REQUEST_TYPE_CON_SAVE:
	case REQUEST_TYPE_CON_DEL:
		g_object_unref (req->con.connection);
		g_free (req->con.path);
		if (req->con.chain)
			nm_auth_chain_unref (req->con.chain);
		if (req->request_type == REQUEST_TYPE_CON_GET) {
			g_free (req->con.get.setting_name);
			g_strfreev (req->con.get.hints);
			if (req->con.get.existing_secrets)
				g_variant_unref (req->con.get.existing_secrets);
		}
		break;
	default:
		g_assert_not_reached ();
	}

	if (req->idle_id)
		g_source_remove (req->idle_id);

	if (req->current && req->current_call_id) {
		/* cancel-secrets invokes the done-callback synchronously -- in which case
		 * the handler just return.
		 * Hence, we can proceed to free @req... */
		nm_secret_agent_cancel_secrets (req->current, req->current_call_id);
	}

	g_object_unref (req->subject);

	g_free (req->detail);
	g_slist_free_full (req->pending, g_object_unref);

	g_object_unref (req->self);

	if (req->current)
		g_object_unref (req->current);

	memset (req, 0, sizeof (Request));
	g_slice_free (Request, req);
}

static void
req_complete_release (Request *req,
                      GVariant *secrets,
                      const char *agent_dbus_owner,
                      const char *agent_username,
                     GError *error)
{
	NMAgentManager *self = req->self;

	switch (req->request_type) {
	case REQUEST_TYPE_CON_GET:
		req->con.get.callback (self,
		                       req,
		                       agent_dbus_owner,
		                       agent_username,
		                       req->con.current_has_modify,
		                       req->con.get.setting_name,
		                       req->con.get.flags,
		                       error ? NULL : secrets,
		                       error,
		                       req->con.get.callback_data);

		break;
	case REQUEST_TYPE_CON_SAVE:
	case REQUEST_TYPE_CON_DEL:
		break;
	default:
		g_return_if_reached ();
	}

	request_free (req);
}

static void
req_complete_cancel (Request *req, gboolean is_disposing)
{
	gs_free_error GError *error = NULL;

	nm_assert (req && req->self);
	nm_assert (!c_list_contains (&NM_AGENT_MANAGER_GET_PRIVATE (req->self)->requests, &req->lst_request));

	nm_utils_error_set_cancelled (&error, is_disposing, "NMAgentManager");
	req_complete_release (req, NULL, NULL, NULL, error);
}

static void
req_complete (Request *req,
              GVariant *secrets,
              const char *agent_dbus_owner,
              const char *agent_username,
              GError *error)
{
	NMAgentManager *self = req->self;

	nm_assert (c_list_contains (&NM_AGENT_MANAGER_GET_PRIVATE (self)->requests, &req->lst_request));

	c_list_unlink (&req->lst_request);

	req_complete_release (req, secrets, agent_dbus_owner, agent_username, error);
}

static void
req_complete_error (Request *req, GError *error)
{
	req_complete (req, NULL, NULL, NULL, error);
}

static gint
agent_compare_func (gconstpointer aa, gconstpointer bb, gpointer user_data)
{
	NMSecretAgent *a = (NMSecretAgent *)aa;
	NMSecretAgent *b = (NMSecretAgent *)bb;
	Request *req = user_data;
	NMSessionMonitor *sm;
	gboolean a_active, b_active;
	gulong a_pid, b_pid, requester;

	/* Prefer agents in the process the request came from */
	if (nm_auth_subject_is_unix_process (req->subject)) {
		requester = nm_auth_subject_get_unix_process_pid (req->subject);
		a_pid = nm_secret_agent_get_pid (a);
		b_pid = nm_secret_agent_get_pid (b);

		if (a_pid != b_pid) {
			if (a_pid == requester)
				return -1;
			else if (b_pid == requester)
				return 1;
		}
	}

	/* Prefer agents in active sessions */
	sm = NM_AGENT_MANAGER_GET_PRIVATE (req->self)->session_monitor;
	a_active = nm_session_monitor_session_exists (sm, nm_secret_agent_get_owner_uid (a), TRUE);
	b_active = nm_session_monitor_session_exists (sm, nm_secret_agent_get_owner_uid (b), TRUE);
	if (a_active && !b_active)
		return -1;
	else if (a_active == b_active)
		return 0;
	else if (!a_active && b_active)
		return 1;

	return 0;
}

static void
request_add_agent (Request *req, NMSecretAgent *agent)
{
	NMAgentManager *self;

	g_return_if_fail (req != NULL);
	g_return_if_fail (agent != NULL);

	self = req->self;

	if (req->request_type == REQUEST_TYPE_CON_GET) {
		NMAuthSubject *subject = nm_secret_agent_get_subject (agent);

		/* Ensure the caller's username exists in the connection's permissions,
		 * or that the permissions is empty (ie, visible by everyone).
		 */
		if (!nm_auth_is_subject_in_acl (req->con.connection, subject, NULL)) {
			_LOGD (agent, "agent ignored for secrets request "LOG_REQ_FMT" (not in ACL)",
			       LOG_REQ_ARG (req));
			/* Connection not visible to this agent's user */
			return;
		}
	}

	/* If the request should filter agents by UID, do that now */
	if (nm_auth_subject_is_unix_process (req->subject)) {
		uid_t agent_uid, subject_uid;

		agent_uid = nm_secret_agent_get_owner_uid (agent);
		subject_uid = nm_auth_subject_get_unix_process_uid (req->subject);
		if (agent_uid != subject_uid) {
			_LOGD (agent, "agent ignored for secrets request "LOG_REQ_FMT" "
			       "(uid %ld not required %ld)",
			       LOG_REQ_ARG (req),
			       (long) agent_uid, (long) subject_uid);
			return;
		}
	}

	_LOGD (agent, "agent allowed for secrets request "LOG_REQ_FMT,
	       LOG_REQ_ARG (req));

	/* Add this agent to the list, sorted appropriately */
	req->pending = g_slist_insert_sorted_with_data (req->pending,
	                                                g_object_ref (agent),
	                                                agent_compare_func,
	                                                req);
}

static void
request_add_agents (NMAgentManager *self, Request *req)
{
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (self);
	GHashTableIter iter;
	gpointer data;

	g_hash_table_iter_init (&iter, priv->agents);
	while (g_hash_table_iter_next (&iter, NULL, &data))
		request_add_agent (req, NM_SECRET_AGENT (data));
}

static void
request_next_agent (Request *req)
{
	NMAgentManager *self;
	GError *error = NULL;

	self = req->self;

	if (req->current) {
		if (req->current_call_id)
			nm_secret_agent_cancel_secrets (req->current, req->current_call_id);
		g_clear_object (&req->current);
	}
	nm_assert (!req->current_call_id);

	if (req->pending) {
		/* Send the request to the next agent */
		req->current = req->pending->data;
		req->pending = g_slist_remove (req->pending, req->current);

		_LOGD (req->current, "agent %s secrets for request "LOG_REQ_FMT,
		       _request_type_to_string (req->request_type, TRUE),
		       LOG_REQ_ARG (req));

		switch (req->request_type) {
		case REQUEST_TYPE_CON_GET:
			_con_get_request_start (req);
			break;
		case REQUEST_TYPE_CON_SAVE:
			_con_save_request_start (req);
			break;
		case REQUEST_TYPE_CON_DEL:
			_con_del_request_start (req);
			break;
		default:
			g_assert_not_reached ();
		}
	} else {
		/* No more secret agents are available to fulfill this secrets request */
		error = g_error_new_literal (NM_AGENT_MANAGER_ERROR,
		                             NM_AGENT_MANAGER_ERROR_NO_SECRETS,
		                             "No agents were available for this request.");
		req_complete_error (req, error);
		g_error_free (error);
	}
}

static void
request_remove_agent (Request *req, NMSecretAgent *agent)
{
	NMAgentManager *self;

	g_return_if_fail (req != NULL);
	g_return_if_fail (agent != NULL);

	self = req->self;

	if (agent == req->current) {
		nm_assert (!g_slist_find (req->pending, agent));

		_LOGD (agent, "current agent removed from secrets request "LOG_REQ_FMT,
		       LOG_REQ_ARG (req));

		switch (req->request_type) {
		case REQUEST_TYPE_CON_GET:
		case REQUEST_TYPE_CON_SAVE:
		case REQUEST_TYPE_CON_DEL:
			if (req->con.chain) {
				/* This cancels the pending authorization requests. */
				nm_auth_chain_unref (req->con.chain);
				req->con.chain = NULL;
			}
			break;
		default:
			g_assert_not_reached ();
		}

		request_next_agent (req);
	} else if (g_slist_find (req->pending, agent)) {
		req->pending = g_slist_remove (req->pending, agent);

		_LOGD (agent, "agent removed from secrets request "LOG_REQ_FMT,
		       LOG_REQ_ARG (req));

		g_object_unref (agent);
	}
}

static gboolean
request_start (gpointer user_data)
{
	Request *req = user_data;

	req->idle_id = 0;

	switch (req->request_type) {
	case REQUEST_TYPE_CON_GET:
		if (_con_get_try_complete_early (req))
			goto out;
		break;
	default:
		break;
	}
	request_next_agent (req);

out:
	return FALSE;
}

/*****************************************************************************/

static void
_con_get_request_done (NMSecretAgent *agent,
                       NMSecretAgentCallId *call_id,
                       GVariant *secrets,
                       GError *error,
                       gpointer user_data)
{
	NMAgentManager *self;
	Request *req = user_data;
	GVariant *setting_secrets;
	const char *agent_dbus_owner;
	struct passwd *pw;
	char *agent_uname = NULL;

	g_return_if_fail (call_id == req->current_call_id);
	g_return_if_fail (agent == req->current);
	g_return_if_fail (req->request_type == REQUEST_TYPE_CON_GET);

	self = req->self;

	req->current_call_id = NULL;

	if (error) {
		if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
			_LOGD (agent, "get secrets request cancelled: "LOG_REQ_FMT,
			       LOG_REQ_ARG (req));
			return;
		}

		_LOGD (agent, "agent failed secrets request "LOG_REQ_FMT": %s",
		       LOG_REQ_ARG (req),
		       error->message);

		if (g_error_matches (error, NM_SECRET_AGENT_ERROR, NM_SECRET_AGENT_ERROR_USER_CANCELED)) {
			error = g_error_new_literal (NM_AGENT_MANAGER_ERROR,
			                             NM_AGENT_MANAGER_ERROR_USER_CANCELED,
			                             "User canceled the secrets request.");
			req_complete_error (req, error);
			g_error_free (error);
		} else {
			if (req->current_call_id) {
				/* Tell the failed agent we're no longer interested. */
				nm_secret_agent_cancel_secrets (req->current, req->current_call_id);
			}

			/* Try the next agent */
			request_next_agent (req);
			maybe_remove_agent_on_error (agent, error);
		}
		return;
	}

	/* Ensure the setting we wanted secrets for got returned and has something in it */
	setting_secrets = g_variant_lookup_value (secrets, req->con.get.setting_name, NM_VARIANT_TYPE_SETTING);
	if (!setting_secrets || !g_variant_n_children (setting_secrets)) {
		_LOGD (agent, "agent returned no secrets for request "LOG_REQ_FMT,
		       LOG_REQ_ARG (req));
		/* Try the next agent */
		request_next_agent (req);
		return;
	}

	_LOGD (agent, "agent returned secrets for request "LOG_REQ_FMT,
	       LOG_REQ_ARG (req));

	/* Get the agent's username */
	pw = getpwuid (nm_secret_agent_get_owner_uid (agent));
	if (pw && strlen (pw->pw_name)) {
		/* Needs to be UTF-8 valid since it may be pushed through D-Bus */
		if (g_utf8_validate (pw->pw_name, -1, NULL))
			agent_uname = g_strdup (pw->pw_name);
	}

	agent_dbus_owner = nm_secret_agent_get_dbus_owner (agent);
	req_complete (req, secrets, agent_dbus_owner, agent_uname, NULL);
	g_free (agent_uname);
}

static void
set_secrets_not_required (NMConnection *connection, GVariant *dict)
{
	GVariantIter iter, setting_iter;
	const char *setting_name = NULL;
	GVariant *setting_dict = NULL;

	/* Iterate through the settings dicts */
	g_variant_iter_init (&iter, dict);
	while (g_variant_iter_next (&iter, "{&s@a{sv}}", &setting_name, &setting_dict)) {
		const char *key_name = NULL;
		NMSetting *setting;
		GVariant *val;

		setting = nm_connection_get_setting_by_name (connection, setting_name);
		if (setting) {
			/* Now through each secret in the setting and mark it as not required */
			g_variant_iter_init (&setting_iter, setting_dict);
			while (g_variant_iter_next (&setting_iter, "{&sv}", &key_name, &val)) {
				/* For each secret, set the flag that it's not required; VPN
				 * secrets need slightly different treatment here since the
				 * "secrets" property is actually a dictionary of secrets.
				 */
				if (   strcmp (setting_name, NM_SETTING_VPN_SETTING_NAME) == 0
				    && strcmp (key_name, NM_SETTING_VPN_SECRETS) == 0
				    && g_variant_is_of_type (val, G_VARIANT_TYPE ("a{ss}"))) {
					GVariantIter vpn_secret_iter;
					const char *secret_name, *secret;

					g_variant_iter_init (&vpn_secret_iter, val);
					while (g_variant_iter_next (&vpn_secret_iter, "{&s&s}", &secret_name, &secret))
						nm_setting_set_secret_flags (setting, secret_name, NM_SETTING_SECRET_FLAG_NOT_REQUIRED, NULL);
				} else
					nm_setting_set_secret_flags (setting, key_name, NM_SETTING_SECRET_FLAG_NOT_REQUIRED, NULL);
				g_variant_unref (val);
			}
		}
		g_variant_unref (setting_dict);
	}
}

static void
_con_get_request_start_proceed (Request *req, gboolean include_system_secrets)
{
	NMConnection *tmp;

	g_return_if_fail (req->request_type == REQUEST_TYPE_CON_GET);

	tmp = nm_simple_connection_new_clone (req->con.connection);
	nm_connection_clear_secrets (tmp);
	if (include_system_secrets) {
		if (req->con.get.existing_secrets)
			(void) nm_connection_update_secrets (tmp, req->con.get.setting_name, req->con.get.existing_secrets, NULL);
	} else {
		/* Update secret flags in the temporary connection to indicate that
		 * the system secrets we're not sending to the agent aren't required,
		 * so the agent can properly validate UI controls and such.
		 */
		if (req->con.get.existing_secrets)
			set_secrets_not_required (tmp, req->con.get.existing_secrets);
	}

	req->current_call_id = nm_secret_agent_get_secrets (req->current,
	                                                    req->con.path,
	                                                    tmp,
	                                                    req->con.get.setting_name,
	                                                    (const char **) req->con.get.hints,
	                                                    req->con.get.flags,
	                                                    _con_get_request_done,
	                                                    req);
	if (!req->current_call_id) {
		g_warn_if_reached ();
		request_next_agent (req);
	}

	g_object_unref (tmp);
}

static void
_con_get_request_start_validated (NMAuthChain *chain,
                                 GError *error,
                                 GDBusMethodInvocation *context,
                                 gpointer user_data)
{
	NMAgentManager *self;
	Request *req = user_data;
	const char *perm;

	g_return_if_fail (req->request_type == REQUEST_TYPE_CON_GET);

	self = req->self;

	req->con.chain = NULL;

	if (error) {
		_LOGD (req->current, "agent "LOG_REQ_FMT" MODIFY check error: %s",
		       LOG_REQ_ARG (req),
		       error->message);
		/* Try the next agent */
		request_next_agent (req);
	} else {
		/* If the agent obtained the 'modify' permission, we send all system secrets
		 * to it.  If it didn't, we still ask it for secrets, but we don't send
		 * any system secrets.
		 */
		perm = nm_auth_chain_get_data (chain, "perm");
		g_assert (perm);
		if (nm_auth_chain_get_result (chain, perm) == NM_AUTH_CALL_RESULT_YES)
			req->con.current_has_modify = TRUE;

		_LOGD (req->current, "agent "LOG_REQ_FMT" MODIFY check result %s",
		       LOG_REQ_ARG (req),
		       req->con.current_has_modify ? "YES" : "NO");

		_con_get_request_start_proceed (req, req->con.current_has_modify);
	}

	nm_auth_chain_unref (chain);
}

static void
has_system_secrets_check (NMSetting *setting,
                          const char *key,
                          const GValue *value,
                          GParamFlags flags,
                          gpointer user_data)
{
	NMSettingSecretFlags secret_flags = NM_SETTING_SECRET_FLAG_NONE;
	gboolean *has_system = user_data;

	if (!(flags & NM_SETTING_PARAM_SECRET))
		return;

	/* Clear out system-owned or always-ask secrets */
	if (NM_IS_SETTING_VPN (setting) && !strcmp (key, NM_SETTING_VPN_SECRETS)) {
		GHashTableIter iter;
		const char *secret_name = NULL;

		/* VPNs are special; need to handle each secret separately */
		g_hash_table_iter_init (&iter, (GHashTable *) g_value_get_boxed (value));
		while (g_hash_table_iter_next (&iter, (gpointer *) &secret_name, NULL)) {
			secret_flags = NM_SETTING_SECRET_FLAG_NONE;
			nm_setting_get_secret_flags (setting, secret_name, &secret_flags, NULL);
			if (secret_flags == NM_SETTING_SECRET_FLAG_NONE)
				*has_system = TRUE;
		}
	} else {
		if (!nm_setting_get_secret_flags (setting, key, &secret_flags, NULL))
			g_return_if_reached ();
		if (secret_flags == NM_SETTING_SECRET_FLAG_NONE)
			*has_system = TRUE;
	}
}

static gboolean
has_system_secrets (NMConnection *connection)
{
	gboolean has_system = FALSE;

	nm_connection_for_each_setting_value (connection, has_system_secrets_check, &has_system);
	return has_system;
}

static void
_con_get_request_start (Request *req)
{
	NMAgentManager *self;
	NMSettingConnection *s_con;
	const char *agent_dbus_owner, *perm;

	self = req->self;

	req->con.current_has_modify = FALSE;

	agent_dbus_owner = nm_secret_agent_get_dbus_owner (req->current);

	/* If the request flags allow user interaction, and there are existing
	 * system secrets (or blank secrets that are supposed to be system-owned),
	 * check whether the agent has the 'modify' permission before sending those
	 * secrets to the agent.  We shouldn't leak system-owned secrets to
	 * unprivileged users.
	 */
	if (   (req->con.get.flags != NM_SECRET_AGENT_GET_SECRETS_FLAG_NONE)
	    && (req->con.get.existing_secrets || has_system_secrets (req->con.connection))) {
		_LOGD (NULL, "("LOG_REQ_FMT") request has system secrets; checking agent %s for MODIFY",
		       LOG_REQ_ARG (req), agent_dbus_owner);

		req->con.chain = nm_auth_chain_new_subject (nm_secret_agent_get_subject (req->current),
		                                            NULL,
		                                            _con_get_request_start_validated,
		                                            req);
		g_assert (req->con.chain);

		/* If the caller is the only user in the connection's permissions, then
		 * we use the 'modify.own' permission instead of 'modify.system'.  If the
		 * request affects more than just the caller, require 'modify.system'.
		 */
		s_con = nm_connection_get_setting_connection (req->con.connection);
		g_assert (s_con);
		if (nm_setting_connection_get_num_permissions (s_con) == 1)
			perm = NM_AUTH_PERMISSION_SETTINGS_MODIFY_OWN;
		else
			perm = NM_AUTH_PERMISSION_SETTINGS_MODIFY_SYSTEM;
		nm_auth_chain_set_data (req->con.chain, "perm", (gpointer) perm, NULL);

		nm_auth_chain_add_call (req->con.chain, perm, TRUE);
	} else {
		_LOGD (NULL, "("LOG_REQ_FMT") requesting user-owned secrets from agent %s",
		       LOG_REQ_ARG (req), agent_dbus_owner);

		_con_get_request_start_proceed (req, FALSE);
	}
}

static gboolean
_con_get_try_complete_early (Request *req)
{
	NMAgentManager *self;
	gs_unref_variant GVariant *setting_secrets = NULL;
	gs_unref_object NMConnection *tmp = NULL;
	GError *error = NULL;

	self = req->self;

	/* Check if there are any existing secrets */
	if (req->con.get.existing_secrets)
		setting_secrets = g_variant_lookup_value (req->con.get.existing_secrets, req->con.get.setting_name, NM_VARIANT_TYPE_SETTING);

	if (!setting_secrets || !g_variant_n_children (setting_secrets))
		return FALSE;

	/* The connection already had secrets; check if any more are required.
	 * If no more are required, we're done.  If secrets are still needed,
	 * ask a secret agent for more.  This allows admins to provide generic
	 * secrets but allow additional user-specific ones as well.
	 */
	tmp = nm_simple_connection_new_clone (req->con.connection);
	g_assert (tmp);

	if (!nm_connection_update_secrets (tmp, req->con.get.setting_name, req->con.get.existing_secrets, &error)) {
		req_complete_error (req, error);
		g_clear_error (&error);
		return TRUE;
	}
	/* Do we have everything we need? */
	if (   NM_FLAGS_HAS (req->con.get.flags, NM_SECRET_AGENT_GET_SECRETS_FLAG_ONLY_SYSTEM)
	    || (   (nm_connection_need_secrets (tmp, NULL) == NULL)
	        && !NM_FLAGS_HAS(req->con.get.flags, NM_SECRET_AGENT_GET_SECRETS_FLAG_REQUEST_NEW))) {
		_LOGD (NULL, "("LOG_REQ_FMT") system settings secrets sufficient",
		       LOG_REQ_ARG (req));

		/* Got everything, we're done */
		req_complete (req, req->con.get.existing_secrets, NULL, NULL, NULL);
		return TRUE;
	}

	_LOGD (NULL, "("LOG_REQ_FMT") system settings secrets insufficient, asking agents",
	       LOG_REQ_ARG (req));

	/* We don't, so ask some agents for additional secrets */
	if (   req->con.get.flags & NM_SECRET_AGENT_GET_SECRETS_FLAG_NO_ERRORS
	    && !req->pending) {
		/* The request initiated from GetSecrets() via DBus,
		 * don't error out if any secrets are missing. */
		req_complete (req, req->con.get.existing_secrets, NULL, NULL, NULL);
		return TRUE;
	}

	/* Couldn't get secrets from system settings, so now we ask the
	 * agents for secrets.  Let the Agent Manager handle which agents
	 * we'll ask and in which order.
	 */
	return FALSE;
}

/**
 * nm_agent_manager_get_secrets:
 * @self:
 * @path:
 * @connection:
 * @subject:
 * @existing_secrets:
 * @flags:
 * @hints:
 * @callback:
 * @callback_data:
 *
 * Requests secrets for a connection.
 *
 * This function cannot fail. The callback will be invoked
 * asynchrnously, but it will always be invoked exactly once.
 * Even for cancellation and disposing of @self. In those latter
 * cases, the callback is invoked synchrnously during the cancellation/
 * disposal.
 *
 * Returns: a call-id to cancel the call.
 */
NMAgentManagerCallId
nm_agent_manager_get_secrets (NMAgentManager *self,
                              const char *path,
                              NMConnection *connection,
                              NMAuthSubject *subject,
                              GVariant *existing_secrets,
                              const char *setting_name,
                              NMSecretAgentGetSecretsFlags flags,
                              const char *const*hints,
                              NMAgentSecretsResultFunc callback,
                              gpointer callback_data)
{
	Request *req;

	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (path && *path, NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (callback != NULL, NULL);

	nm_log_dbg (LOGD_SETTINGS,
	            "Secrets requested for connection %s (%s/%s)",
	            path,
	            nm_connection_get_id (connection),
	            setting_name);

	/* NOTE: a few things in the Request handling depend on existing_secrets
	 * being NULL if there aren't any system-owned secrets for this connection.
	 * This in turn depends on nm_connection_to_dbus() and nm_setting_to_hash()
	 * both returning NULL if they didn't hash anything.
	 */
	req = request_new (self,
	                   REQUEST_TYPE_CON_GET,
	                   nm_connection_get_id (connection),
	                   subject);

	req->con.path = g_strdup (path);
	req->con.connection = g_object_ref (connection);
	if (existing_secrets)
		req->con.get.existing_secrets = g_variant_ref (existing_secrets);
	req->con.get.setting_name = g_strdup (setting_name);
	req->con.get.hints = g_strdupv ((char **) hints);
	req->con.get.flags = flags;
	req->con.get.callback = callback;
	req->con.get.callback_data = callback_data;

	/* Kick off the request */
	if (!(req->con.get.flags & NM_SECRET_AGENT_GET_SECRETS_FLAG_ONLY_SYSTEM))
		request_add_agents (self, req);
	req->idle_id = g_idle_add (request_start, req);
	return req;
}

void
nm_agent_manager_cancel_secrets (NMAgentManager *self,
                                 NMAgentManagerCallId request_id)
{
	g_return_if_fail (self != NULL);
	g_return_if_fail (request_id);
	g_return_if_fail (request_id->request_type == REQUEST_TYPE_CON_GET);

	nm_assert (c_list_contains (&NM_AGENT_MANAGER_GET_PRIVATE (self)->requests, &request_id->lst_request));

	c_list_unlink (&request_id->lst_request);

	req_complete_cancel (request_id, FALSE);
}

/*****************************************************************************/

static void
_con_save_request_done (NMSecretAgent *agent,
                        NMSecretAgentCallId *call_id,
                        GVariant *secrets,
                        GError *error,
                        gpointer user_data)
{
	NMAgentManager *self;
	Request *req = user_data;
	const char *agent_dbus_owner;

	g_return_if_fail (call_id == req->current_call_id);
	g_return_if_fail (agent == req->current);
	g_return_if_fail (req->request_type == REQUEST_TYPE_CON_SAVE);

	self = req->self;

	req->current_call_id = NULL;

	if (error) {
		if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
			_LOGD (agent, "save secrets request cancelled: "LOG_REQ_FMT,
			       LOG_REQ_ARG (req));
			return;
		}

		_LOGD (agent, "agent failed save secrets request "LOG_REQ_FMT": %s",
		       LOG_REQ_ARG (req), error->message);
		/* Try the next agent */
		request_next_agent (req);
		maybe_remove_agent_on_error (agent, error);
		return;
	}

	_LOGD (agent, "agent saved secrets for request "LOG_REQ_FMT,
	       LOG_REQ_ARG (req));

	agent_dbus_owner = nm_secret_agent_get_dbus_owner (agent);
	req_complete (req, NULL, NULL, agent_dbus_owner, NULL);
}

static void
_con_save_request_start (Request *req)
{
	req->current_call_id = nm_secret_agent_save_secrets (req->current,
	                                                     req->con.path,
	                                                     req->con.connection,
	                                                     _con_save_request_done,
	                                                     req);
	if (!req->current_call_id) {
		g_warn_if_reached ();
		request_next_agent (req);
	}
}

void
nm_agent_manager_save_secrets (NMAgentManager *self,
                               const char *path,
                               NMConnection *connection,
                               NMAuthSubject *subject)
{
	Request *req;

	g_return_if_fail (self);
	g_return_if_fail (path && *path);
	g_return_if_fail (NM_IS_CONNECTION (connection));

	nm_log_dbg (LOGD_SETTINGS,
	            "Saving secrets for connection %s (%s)",
	            path,
	            nm_connection_get_id (connection));

	req = request_new (self,
	                   REQUEST_TYPE_CON_SAVE,
	                   nm_connection_get_id (connection),
	                   subject);
	req->con.path = g_strdup (path);
	req->con.connection = g_object_ref (connection);

	/* Kick off the request */
	request_add_agents (self, req);
	req->idle_id = g_idle_add (request_start, req);
}

/*****************************************************************************/

static void
_con_del_request_done (NMSecretAgent *agent,
                       NMSecretAgentCallId *call_id,
                       GVariant *secrets,
                       GError *error,
                       gpointer user_data)
{
	NMAgentManager *self;
	Request *req = user_data;

	g_return_if_fail (call_id == req->current_call_id);
	g_return_if_fail (agent == req->current);
	g_return_if_fail (req->request_type == REQUEST_TYPE_CON_DEL);

	self = req->self;

	req->current_call_id = NULL;

	if (error) {
		if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
			_LOGD (agent, "delete secrets request cancelled: "LOG_REQ_FMT,
			       LOG_REQ_ARG (req));
			return;
		}

		_LOGD (agent, "agent failed delete secrets request "LOG_REQ_FMT": %s",
		       LOG_REQ_ARG (req), error->message);
	} else {
		_LOGD (agent, "agent deleted secrets for request "LOG_REQ_FMT,
		       LOG_REQ_ARG (req));
	}

	/* Tell the next agent to delete secrets */
	request_next_agent (req);
	if (error)
		maybe_remove_agent_on_error (agent, error);
}

static void
_con_del_request_start (Request *req)
{
	req->current_call_id = nm_secret_agent_delete_secrets (req->current,
	                                                       req->con.path,
	                                                       req->con.connection,
	                                                       _con_del_request_done,
	                                                       req);
	if (!req->current_call_id) {
		g_warn_if_reached ();
		request_next_agent (req);
	}
}

void
nm_agent_manager_delete_secrets (NMAgentManager *self,
                                 const char *path,
                                 NMConnection *connection)
{
	NMAuthSubject *subject;
	Request *req;

	g_return_if_fail (self != NULL);
	g_return_if_fail (path && *path);
	g_return_if_fail (NM_IS_CONNECTION (connection));

	nm_log_dbg (LOGD_SETTINGS,
	            "Deleting secrets for connection %s (%s)",
	            path,
	            nm_connection_get_id (connection));

	subject = nm_auth_subject_new_internal ();
	req = request_new (self,
	                   REQUEST_TYPE_CON_DEL,
	                   nm_connection_get_id (connection),
	                   subject);
	req->con.path = g_strdup (path);
	req->con.connection = g_object_ref (connection);
	g_object_unref (subject);

	/* Kick off the request */
	request_add_agents (self, req);
	req->idle_id = g_idle_add (request_start, req);
}

/*****************************************************************************/

NMSecretAgent *
nm_agent_manager_get_agent_by_user (NMAgentManager *self, const char *username)
{
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (self);
	GHashTableIter iter;
	NMSecretAgent *agent;

	g_hash_table_iter_init (&iter, priv->agents);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer) &agent)) {
		if (g_strcmp0 (nm_secret_agent_get_owner_username (agent), username) == 0)
			return agent;
	}

	return NULL;
}

/*****************************************************************************/

gboolean
nm_agent_manager_all_agents_have_capability (NMAgentManager *manager,
                                             NMAuthSubject *subject,
                                             NMSecretAgentCapabilities capability)
{
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (manager);
	GHashTableIter iter;
	NMSecretAgent *agent;
	gboolean subject_is_unix_process = nm_auth_subject_is_unix_process (subject);
	gulong subject_uid = subject_is_unix_process ? nm_auth_subject_get_unix_process_uid (subject) : 0;

	g_hash_table_iter_init (&iter, priv->agents);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer) &agent)) {
		if (   subject_is_unix_process
		    && nm_secret_agent_get_owner_uid (agent) != subject_uid)
			continue;

		if (!(nm_secret_agent_get_capabilities (agent) & capability))
			return FALSE;
	}

	return TRUE;
}

/*****************************************************************************/

static void
agent_permissions_changed_done (NMAuthChain *chain,
                                GError *error,
                                GDBusMethodInvocation *context,
                                gpointer user_data)
{
	NMAgentManager *self = NM_AGENT_MANAGER (user_data);
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (self);
	NMSecretAgent *agent;
	gboolean share_protected = FALSE, share_open = FALSE;

	priv->chains = g_slist_remove (priv->chains, chain);

	agent = nm_auth_chain_get_data (chain, "agent");
	g_assert (agent);

	if (error)
		_LOGD (agent, "failed to request updated agent permissions");
	else {
		_LOGD (agent, "updated agent permissions");

		if (nm_auth_chain_get_result (chain, NM_AUTH_PERMISSION_WIFI_SHARE_PROTECTED) == NM_AUTH_CALL_RESULT_YES)
			share_protected = TRUE;
		if (nm_auth_chain_get_result (chain, NM_AUTH_PERMISSION_WIFI_SHARE_OPEN) == NM_AUTH_CALL_RESULT_YES)
			share_open = TRUE;
	}

	nm_secret_agent_add_permission (agent, NM_AUTH_PERMISSION_WIFI_SHARE_PROTECTED, share_protected);
	nm_secret_agent_add_permission (agent, NM_AUTH_PERMISSION_WIFI_SHARE_OPEN, share_open);

	nm_auth_chain_unref (chain);
}

static void
authority_changed_cb (NMAuthManager *auth_manager, NMAgentManager *self)
{
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (self);
	GHashTableIter iter;
	NMSecretAgent *agent;

	/* Recheck the permissions of all secret agents */
	g_hash_table_iter_init (&iter, priv->agents);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer) &agent)) {
		NMAuthChain *chain;

		/* Kick off permissions requests for this agent */
		chain = nm_auth_chain_new_subject (nm_secret_agent_get_subject (agent),
		                                   NULL,
		                                   agent_permissions_changed_done,
		                                   self);
		g_assert (chain);
		priv->chains = g_slist_append (priv->chains, chain);

		/* Make sure if the agent quits while the permissions call is in progress
		 * that the object sticks around until our callback.
		 */
		nm_auth_chain_set_data (chain, "agent", g_object_ref (agent), g_object_unref);
		nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_WIFI_SHARE_PROTECTED, FALSE);
		nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_WIFI_SHARE_OPEN, FALSE);
	}
}

/*****************************************************************************/

static void
nm_agent_manager_init (NMAgentManager *self)
{
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (self);

	priv->agent_version_id = 1;
	c_list_init (&priv->requests);
	priv->agents = g_hash_table_new_full (nm_str_hash, g_str_equal, g_free, g_object_unref);
}

static void
constructed (GObject *object)
{
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE ((NMAgentManager *) object);

	G_OBJECT_CLASS (nm_agent_manager_parent_class)->constructed (object);

	priv->auth_mgr = g_object_ref (nm_auth_manager_get ());
	priv->session_monitor = g_object_ref (nm_session_monitor_get ());

	nm_dbus_object_export (NM_DBUS_OBJECT (object));

	g_signal_connect (priv->auth_mgr,
	                  NM_AUTH_MANAGER_SIGNAL_CHANGED,
	                  G_CALLBACK (authority_changed_cb),
	                  object);
}

static void
dispose (GObject *object)
{
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE ((NMAgentManager *) object);
	CList *iter;

cancel_more:
	c_list_for_each (iter, &priv->requests) {
		c_list_unlink (iter);
		req_complete_cancel (c_list_entry (iter, Request, lst_request), TRUE);
		goto cancel_more;
	}

	g_slist_free_full (priv->chains, (GDestroyNotify) nm_auth_chain_unref);
	priv->chains = NULL;

	if (priv->agents) {
		g_hash_table_destroy (priv->agents);
		priv->agents = NULL;
	}

	if (priv->auth_mgr) {
		g_signal_handlers_disconnect_by_func (priv->auth_mgr,
		                                      G_CALLBACK (authority_changed_cb),
		                                      object);
		g_clear_object (&priv->auth_mgr);
	}

	nm_dbus_object_unexport (NM_DBUS_OBJECT (object));

	g_clear_object (&priv->session_monitor);

	G_OBJECT_CLASS (nm_agent_manager_parent_class)->dispose (object);
}

static const NMDBusInterfaceInfoExtended interface_info_agent_manager = {
	.parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (
		NM_DBUS_INTERFACE_AGENT_MANAGER,
		.methods = NM_DEFINE_GDBUS_METHOD_INFOS (
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"Register",
					.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("identifier", "s"),
					),
				),
				.handle = impl_agent_manager_register,
			),
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"RegisterWithCapabilities",
					.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("identifier",   "s"),
						NM_DEFINE_GDBUS_ARG_INFO ("capabilities", "u"),
					),
				),
				.handle = impl_agent_manager_register_with_capabilities,
			),
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"RegisterWithCapabilities",
					.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("identifier",   "s"),
						NM_DEFINE_GDBUS_ARG_INFO ("capabilities", "u"),
					),
				),
				.handle = impl_agent_manager_register_with_capabilities,
			),
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"Unregister",
				),
				.handle = impl_agent_manager_unregister,
			),
		),
	),
};

static void
nm_agent_manager_class_init (NMAgentManagerClass *agent_manager_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (agent_manager_class);
	NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS (agent_manager_class);

	dbus_object_class->export_path = NM_DBUS_PATH_AGENT_MANAGER;
	dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS (&interface_info_agent_manager);

	object_class->constructed = constructed;
	object_class->dispose = dispose;

	signals[AGENT_REGISTERED] =
	    g_signal_new (NM_AGENT_MANAGER_AGENT_REGISTERED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0,
	                  NULL, NULL,
	                  g_cclosure_marshal_VOID__OBJECT,
	                  G_TYPE_NONE, 1,
	                  G_TYPE_OBJECT);
}
