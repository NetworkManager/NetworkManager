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

#include "config.h"

#include <string.h>
#include <pwd.h>

#include "nm-default.h"
#include "nm-dbus-interface.h"
#include "nm-agent-manager.h"
#include "nm-secret-agent.h"
#include "nm-auth-utils.h"
#include "nm-setting-vpn.h"
#include "nm-setting-connection.h"
#include "nm-enum-types.h"
#include "nm-auth-manager.h"
#include "nm-bus-manager.h"
#include "nm-session-monitor.h"
#include "nm-simple-connection.h"
#include "NetworkManagerUtils.h"
#include "nm-core-internal.h"

#include "nmdbus-agent-manager.h"

NM_DEFINE_SINGLETON_INSTANCE (NMAgentManager);

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
            _nm_log ((level), (_NMLOG_DOMAIN), 0, \
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

G_DEFINE_TYPE (NMAgentManager, nm_agent_manager, NM_TYPE_EXPORTED_OBJECT)

#define NM_AGENT_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                         NM_TYPE_AGENT_MANAGER, \
                                         NMAgentManagerPrivate))

typedef struct {
	NMAuthManager *auth_mgr;

	/* Auth chains for checking agent permissions */
	GSList *chains;

	/* Hashed by owner name, not identifier, since two agents in different
	 * sessions can use the same identifier.
	 */
	GHashTable *agents;

	GHashTable *requests;
} NMAgentManagerPrivate;

enum {
        AGENT_REGISTERED,

        LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };


typedef struct _Request Request;

static void request_add_agent (Request *req, NMSecretAgent *agent);

static void request_remove_agent (Request *req, NMSecretAgent *agent, GSList **pending_reqs);

static void request_next_agent (Request *req);

static void get_next_cb (Request *req);
static void save_next_cb (Request *req);
static void delete_next_cb (Request *req);

static gboolean _con_get_try_complete_early (Request *req);

/*************************************************************/

static gboolean
remove_agent (NMAgentManager *self, const char *owner)
{
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (self);
	NMSecretAgent *agent;
	GHashTableIter iter;
	gpointer data;
	GSList *pending_reqs = NULL;

	g_return_val_if_fail (owner != NULL, FALSE);

	/* Make sure this agent has already registered */
	agent = g_hash_table_lookup (priv->agents, owner);
	if (!agent)
		return FALSE;

	_LOGD (agent, "agent unregistered or disappeared");

	/* Remove this agent from any in-progress secrets requests */
	g_hash_table_iter_init (&iter, priv->requests);
	while (g_hash_table_iter_next (&iter, NULL, &data))
		request_remove_agent ((Request *) data, agent, &pending_reqs);

	/* We cannot call request_next_agent() from from within hash iterating loop,
	 * because it may remove the request from the hash table, which invalidates
	 * the iterator. So, only remove the agent from requests. And store the requests
	 * that should be sent to other agent to a temporary list to proceed afterwards.
	 */
	g_slist_free_full (pending_reqs, (GDestroyNotify) request_next_agent);

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

/*************************************************************/

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
	GHashTableIter iter;
	Request *req;

	g_assert (context);

	priv->chains = g_slist_remove (priv->chains, chain);

	if (error) {
		local = g_error_new (NM_AGENT_MANAGER_ERROR,
		                     NM_AGENT_MANAGER_ERROR_PERMISSION_DENIED,
		                     "Failed to request agent permissions: (%d) %s",
		                     error->code, error->message);
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

		sender = nm_secret_agent_get_dbus_owner (agent);
		g_hash_table_insert (priv->agents, g_strdup (sender), agent);
		_LOGD (agent, "agent registered");
		g_dbus_method_invocation_return_value (context, NULL);

		/* Signal an agent was registered */
		g_signal_emit (self, signals[AGENT_REGISTERED], 0, agent);

		/* Add this agent to any in-progress secrets requests */
		g_hash_table_iter_init (&iter, priv->requests);
		while (g_hash_table_iter_next (&iter, NULL, (gpointer) &req))
			request_add_agent (req, agent);
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
impl_agent_manager_register_with_capabilities (NMAgentManager *self,
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
impl_agent_manager_register (NMAgentManager *self,
                             GDBusMethodInvocation *context,
                             const char *identifier)
{
	impl_agent_manager_register_with_capabilities (self, context, identifier, 0);
}

static void
impl_agent_manager_unregister (NMAgentManager *self,
                               GDBusMethodInvocation *context)
{
	GError *error = NULL;
	char *sender = NULL;

	if (!nm_bus_manager_get_caller_info (nm_bus_manager_get (),
	                                     context,
	                                     &sender,
	                                     NULL,
	                                     NULL)) {
		error = g_error_new_literal (NM_AGENT_MANAGER_ERROR,
		                             NM_AGENT_MANAGER_ERROR_PERMISSION_DENIED,
		                             "Unable to determine request sender.");
		goto done;
	}

	/* Found the agent, unregister and remove it */
	if (!remove_agent (self, sender)) {
		error = g_error_new_literal (NM_AGENT_MANAGER_ERROR,
		                             NM_AGENT_MANAGER_ERROR_NOT_REGISTERED,
		                             "Caller is not registered as an Agent");
		goto done;
	}

	g_dbus_method_invocation_return_value (context, NULL);

done:
	if (error)
		g_dbus_method_invocation_take_error (context, error);
	g_free (sender);
}

/*************************************************************/

struct _Request {
	NMAgentManager *self;

	RequestType request_type;

	guint32 reqid;
	char *detail;

	NMAuthSubject *subject;

	/* Current agent being asked for secrets */
	NMSecretAgent *current;
	NMSecretAgentCallId current_call_id;

	/* Stores the sorted list of NMSecretAgents which will be asked for secrets */
	GSList *pending;

	guint32 idle_id;

	gboolean completed;

	union {
		struct {
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
					gpointer other_data2;
					gpointer other_data3;
				} get;
			};
		} con;
	};
};

static guint32 next_req_id = 1;

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
	req->reqid = next_req_id++;
	req->detail = g_strdup (detail);
	req->subject = g_object_ref (subject);
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

	if (!req->completed) {
		switch (req->request_type) {
		case REQUEST_TYPE_CON_GET:
			req->con.current_has_modify = FALSE;
			if (req->current && req->current_call_id)
				nm_secret_agent_cancel_secrets (req->current, req->current_call_id);
			break;
		default:
			break;
		}
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
req_complete (Request *req,
              GVariant *secrets,
              const char *agent_dbus_owner,
              const char *agent_username,
              GError *error)
{
	NMAgentManager *self = req->self;
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (self);

	req->completed = TRUE;

	switch (req->request_type) {
	case REQUEST_TYPE_CON_GET:
		req->con.get.callback (self,
		                       req->reqid,
		                       agent_dbus_owner,
		                       agent_username,
		                       req->con.current_has_modify,
		                       req->con.get.setting_name,
		                       req->con.get.flags,
		                       error ? NULL : secrets,
		                       error,
		                       req->con.get.callback_data,
		                       req->con.get.other_data2,
		                       req->con.get.other_data3);

		break;
	case REQUEST_TYPE_CON_SAVE:
	case REQUEST_TYPE_CON_DEL:
		break;
	default:
		g_return_if_reached ();
	}

	g_hash_table_remove (priv->requests, GUINT_TO_POINTER (req->reqid));
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
	a_active = nm_session_monitor_session_exists (nm_session_monitor_get (), nm_secret_agent_get_owner_uid (a), TRUE);
	b_active = nm_session_monitor_session_exists (nm_session_monitor_get (), nm_secret_agent_get_owner_uid (b), TRUE);
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
	g_warn_if_fail (!req->current_call_id);

	if (req->pending) {
		/* Send the request to the next agent */
		req->current = req->pending->data;
		req->pending = g_slist_remove (req->pending, req->current);

		_LOGD (req->current, "agent %s secrets for request "LOG_REQ_FMT,
		       _request_type_to_string (req->request_type, TRUE),
		       LOG_REQ_ARG (req));

		switch (req->request_type) {
		case REQUEST_TYPE_CON_GET:
			get_next_cb (req);
			break;
		case REQUEST_TYPE_CON_SAVE:
			save_next_cb (req);
			break;
		case REQUEST_TYPE_CON_DEL:
			delete_next_cb (req);
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
request_remove_agent (Request *req, NMSecretAgent *agent, GSList **pending_reqs)
{
	NMAgentManager *self;

	g_return_if_fail (req != NULL);
	g_return_if_fail (agent != NULL);

	self = req->self;

	if (agent == req->current) {
		nm_assert (!g_slist_find (req->pending, agent));

		_LOGD (agent, "current agent removed from secrets request "LOG_REQ_FMT,
		       LOG_REQ_ARG (req));
		*pending_reqs = g_slist_prepend (*pending_reqs, req);
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

/*************************************************************/

static void
get_done_cb (NMSecretAgent *agent,
             NMSecretAgentCallId call_id,
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
	}
}

static void
get_agent_request_secrets (Request *req, gboolean include_system_secrets)
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
	                                                    tmp,
	                                                    req->con.get.setting_name,
	                                                    (const char **) req->con.get.hints,
	                                                    req->con.get.flags,
	                                                    get_done_cb,
	                                                    req);
	if (!req->current_call_id) {
		g_warn_if_reached ();
		request_next_agent (req);
	}

	g_object_unref (tmp);
}

static void
get_agent_modify_auth_cb (NMAuthChain *chain,
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
		_LOGD (req->current, "agent "LOG_REQ_FMT" MODIFY check error: (%d) %s",
		       LOG_REQ_ARG (req),
		       error->code, error->message ? error->message : "(unknown)");
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

		get_agent_request_secrets (req, req->con.current_has_modify);
	}

	nm_auth_chain_unref (chain);
}

static void
check_system_secrets_cb (NMSetting *setting,
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

	nm_connection_for_each_setting_value (connection, check_system_secrets_cb, &has_system);
	return has_system;
}

static void
get_next_cb (Request *req)
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
		                                            get_agent_modify_auth_cb,
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

		get_agent_request_secrets (req, FALSE);
	}
}

static gboolean
_con_get_try_complete_early (Request *req)
{
	NMAgentManager *self;
	GVariant *setting_secrets = NULL;
	gboolean completed = TRUE;

	self = req->self;

	/* Check if there are any existing secrets */
	if (req->con.get.existing_secrets)
		setting_secrets = g_variant_lookup_value (req->con.get.existing_secrets, req->con.get.setting_name, NM_VARIANT_TYPE_SETTING);

	if (setting_secrets && g_variant_n_children (setting_secrets)) {
		NMConnection *tmp;
		GError *error = NULL;
		gboolean new_secrets = (req->con.get.flags & NM_SECRET_AGENT_GET_SECRETS_FLAG_REQUEST_NEW);

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
		} else {
			/* Do we have everything we need? */
			if (   (req->con.get.flags & NM_SECRET_AGENT_GET_SECRETS_FLAG_ONLY_SYSTEM)
			    || ((nm_connection_need_secrets (tmp, NULL) == NULL) && (new_secrets == FALSE))) {
				_LOGD (NULL, "("LOG_REQ_FMT") system settings secrets sufficient",
				       LOG_REQ_ARG (req));

				/* Got everything, we're done */
				req_complete (req, req->con.get.existing_secrets, NULL, NULL, NULL);
			} else {
				_LOGD (NULL, "("LOG_REQ_FMT") system settings secrets insufficient, asking agents",
				       LOG_REQ_ARG (req));

				/* We don't, so ask some agents for additional secrets */
				if (   req->con.get.flags & NM_SECRET_AGENT_GET_SECRETS_FLAG_NO_ERRORS
				    && !req->pending) {
					/* The request initiated from GetSecrets() via DBus,
					 * don't error out if any secrets are missing. */
					req_complete (req, req->con.get.existing_secrets, NULL, NULL, NULL);
				} else
					completed = FALSE;
			}
		}
		g_object_unref (tmp);
	} else {
		/* Couldn't get secrets from system settings, so now we ask the
		 * agents for secrets.  Let the Agent Manager handle which agents
		 * we'll ask and in which order.
		 */
		completed = FALSE;
	}

	if (setting_secrets)
		g_variant_unref (setting_secrets);

	return completed;
}

guint32
nm_agent_manager_get_secrets (NMAgentManager *self,
                              NMConnection *connection,
                              NMAuthSubject *subject,
                              GVariant *existing_secrets,
                              const char *setting_name,
                              NMSecretAgentGetSecretsFlags flags,
                              const char **hints,
                              NMAgentSecretsResultFunc callback,
                              gpointer callback_data,
                              gpointer other_data2,
                              gpointer other_data3)
{
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (self);
	Request *req;

	g_return_val_if_fail (self != NULL, 0);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), 0);
	g_return_val_if_fail (callback != NULL, 0);

	nm_log_dbg (LOGD_SETTINGS,
	            "Secrets requested for connection %s (%s/%s)",
	            nm_connection_get_path (connection),
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

	req->con.connection = g_object_ref (connection);
	if (existing_secrets)
		req->con.get.existing_secrets = g_variant_ref (existing_secrets);
	req->con.get.setting_name = g_strdup (setting_name);
	req->con.get.hints = g_strdupv ((char **) hints);
	req->con.get.flags = flags;
	req->con.get.callback = callback;
	req->con.get.callback_data = callback_data;
	req->con.get.other_data2 = other_data2;
	req->con.get.other_data3 = other_data3;

	g_hash_table_insert (priv->requests, GUINT_TO_POINTER (req->reqid), req);

	/* Kick off the request */
	if (!(req->con.get.flags & NM_SECRET_AGENT_GET_SECRETS_FLAG_ONLY_SYSTEM))
		request_add_agents (self, req);
	req->idle_id = g_idle_add (request_start, req);
	return req->reqid;
}

void
nm_agent_manager_cancel_secrets (NMAgentManager *self,
                                 guint32 request_id)
{
	g_return_if_fail (self != NULL);
	g_return_if_fail (request_id > 0);

	g_hash_table_remove (NM_AGENT_MANAGER_GET_PRIVATE (self)->requests,
	                     GUINT_TO_POINTER (request_id));
}

/*************************************************************/

static void
save_done_cb (NMSecretAgent *agent,
              NMSecretAgentCallId call_id,
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
save_next_cb (Request *req)
{
	req->current_call_id = nm_secret_agent_save_secrets (req->current,
	                                                     req->con.connection,
	                                                     save_done_cb,
	                                                     req);
	if (!req->current_call_id) {
		g_warn_if_reached ();
		request_next_agent (req);
	}
}

guint32
nm_agent_manager_save_secrets (NMAgentManager *self,
                               NMConnection *connection,
                               NMAuthSubject *subject)
{
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (self);
	Request *req;

	g_return_val_if_fail (self != NULL, 0);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), 0);

	nm_log_dbg (LOGD_SETTINGS,
	            "Saving secrets for connection %s (%s)",
	            nm_connection_get_path (connection),
	            nm_connection_get_id (connection));

	req = request_new (self,
	                   REQUEST_TYPE_CON_SAVE,
	                   nm_connection_get_id (connection),
	                   subject);
	req->con.connection = g_object_ref (connection);
	g_hash_table_insert (priv->requests, GUINT_TO_POINTER (req->reqid), req);

	/* Kick off the request */
	request_add_agents (self, req);
	req->idle_id = g_idle_add (request_start, req);
	return req->reqid;
}

/*************************************************************/

static void
delete_done_cb (NMSecretAgent *agent,
                NMSecretAgentCallId call_id,
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
delete_next_cb (Request *req)
{
	req->current_call_id = nm_secret_agent_delete_secrets (req->current,
	                                                       req->con.connection,
	                                                       delete_done_cb,
	                                                       req);
	if (!req->current_call_id) {
		g_warn_if_reached ();
		request_next_agent (req);
	}
}

guint32
nm_agent_manager_delete_secrets (NMAgentManager *self,
                                 NMConnection *connection)
{
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (self);
	NMAuthSubject *subject;
	Request *req;

	g_return_val_if_fail (self != NULL, 0);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), 0);

	nm_log_dbg (LOGD_SETTINGS,
	            "Deleting secrets for connection %s (%s)",
	            nm_connection_get_path (connection),
	            nm_connection_get_id (connection));

	subject = nm_auth_subject_new_internal ();
	req = request_new (self,
	                   REQUEST_TYPE_CON_DEL,
	                   nm_connection_get_id (connection),
	                   subject);
	req->con.connection = g_object_ref (connection);
	g_object_unref (subject);
	g_hash_table_insert (priv->requests, GUINT_TO_POINTER (req->reqid), req);

	/* Kick off the request */
	request_add_agents (self, req);
	req->idle_id = g_idle_add (request_start, req);
	return req->reqid;
}

/*************************************************************/

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

/*************************************************************/

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

/*************************************************************/

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

/*************************************************************/

NM_DEFINE_SINGLETON_GETTER (NMAgentManager, nm_agent_manager_get, NM_TYPE_AGENT_MANAGER);

static void
nm_agent_manager_init (NMAgentManager *self)
{
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (self);

	priv->agents = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_object_unref);
	priv->requests = g_hash_table_new_full (g_direct_hash,
	                                        g_direct_equal,
	                                        NULL,
	                                        (GDestroyNotify) request_free);
}

static void
constructed (GObject *object)
{
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (object);

	G_OBJECT_CLASS (nm_agent_manager_parent_class)->constructed (object);

	priv->auth_mgr = g_object_ref (nm_auth_manager_get ());

	nm_exported_object_export (NM_EXPORTED_OBJECT (object));

	g_signal_connect (priv->auth_mgr,
	                  NM_AUTH_MANAGER_SIGNAL_CHANGED,
	                  G_CALLBACK (authority_changed_cb),
	                  object);

	NM_UTILS_KEEP_ALIVE (object, nm_session_monitor_get (), "NMAgentManager-depends-on-NMSessionMonitor");
}

static void
dispose (GObject *object)
{
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (object);

	g_slist_free_full (priv->chains, (GDestroyNotify) nm_auth_chain_unref);
	priv->chains = NULL;

	if (priv->agents) {
		g_hash_table_destroy (priv->agents);
		priv->agents = NULL;
	}
	if (priv->requests) {
		g_hash_table_destroy (priv->requests);
		priv->requests = NULL;
	}

	if (priv->auth_mgr) {
		g_signal_handlers_disconnect_by_func (priv->auth_mgr,
		                                      G_CALLBACK (authority_changed_cb),
		                                      object);
		g_clear_object (&priv->auth_mgr);
	}

	nm_exported_object_unexport (NM_EXPORTED_OBJECT (object));

	G_OBJECT_CLASS (nm_agent_manager_parent_class)->dispose (object);
}

static void
nm_agent_manager_class_init (NMAgentManagerClass *agent_manager_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (agent_manager_class);
	NMExportedObjectClass *exported_object_class = NM_EXPORTED_OBJECT_CLASS (agent_manager_class);

	g_type_class_add_private (agent_manager_class, sizeof (NMAgentManagerPrivate));

	exported_object_class->export_path = NM_DBUS_PATH_AGENT_MANAGER;

	/* virtual methods */
	object_class->constructed = constructed;
	object_class->dispose = dispose;

	/* Signals */
	signals[AGENT_REGISTERED] =
		g_signal_new ("agent-registered",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMAgentManagerClass, agent_registered),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__OBJECT,
		              G_TYPE_NONE, 1,
		              G_TYPE_OBJECT);

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (agent_manager_class),
	                                        NMDBUS_TYPE_AGENT_MANAGER_SKELETON,
	                                        "Register", impl_agent_manager_register,
	                                        "RegisterWithCapabilities", impl_agent_manager_register_with_capabilities,
	                                        "Unregister", impl_agent_manager_unregister,
	                                        NULL);
}
