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

#include <config.h>
#include <string.h>
#include <pwd.h>

#include <glib.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>

#include "NetworkManager.h"
#include "nm-logging.h"
#include "nm-agent-manager.h"
#include "nm-secret-agent.h"
#include "nm-manager-auth.h"
#include "nm-dbus-glib-types.h"
#include "nm-manager-auth.h"
#include "nm-setting-vpn.h"
#include "nm-setting-connection.h"
#include "nm-enum-types.h"

G_DEFINE_TYPE (NMAgentManager, nm_agent_manager, G_TYPE_OBJECT)

#define NM_AGENT_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                         NM_TYPE_AGENT_MANAGER, \
                                         NMAgentManagerPrivate))

typedef struct {
	gboolean disposed;

	NMDBusManager *dbus_mgr;

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

static void impl_agent_manager_register (NMAgentManager *self,
                                         const char *identifier,
                                         DBusGMethodInvocation *context);

static void impl_agent_manager_register_with_capabilities (NMAgentManager *self,
                                                           const char *identifier,
                                                           NMSecretAgentCapabilities capabilities,
                                                           DBusGMethodInvocation *context);

static void impl_agent_manager_unregister (NMAgentManager *self,
                                           DBusGMethodInvocation *context);

#include "nm-agent-manager-glue.h"

/********************************************************************/

#define NM_AGENT_MANAGER_ERROR         (nm_agent_manager_error_quark ())

static GQuark
nm_agent_manager_error_quark (void)
{
	static GQuark ret = 0;

	if (G_UNLIKELY (ret == 0))
		ret = g_quark_from_static_string ("nm-agent-manager-error");
	return ret;
}

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

	nm_log_dbg (LOGD_AGENTS, "(%s) agent unregistered or disappeared",
	            nm_secret_agent_get_description (agent));

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
                                 DBusGMethodInvocation *context,
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
		dbus_g_method_return_error (context, local);
		g_error_free (local);
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
		nm_log_dbg (LOGD_AGENTS, "(%s) agent registered",
		            nm_secret_agent_get_description (agent));
		dbus_g_method_return (context);

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
impl_agent_manager_register_with_capabilities (NMAgentManager *self,
                                               const char *identifier,
                                               NMSecretAgentCapabilities capabilities,
                                               DBusGMethodInvocation *context)
{
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (self);
	NMAuthSubject *subject;
	gulong sender_uid = G_MAXULONG;
	GError *error = NULL, *local = NULL;
	NMSecretAgent *agent;
	NMAuthChain *chain;

	subject = nm_auth_subject_new_from_context (context);
	if (!subject) {
		error = g_error_new_literal (NM_AGENT_MANAGER_ERROR,
		                             NM_AGENT_MANAGER_ERROR_SENDER_UNKNOWN,
		                             "Unable to determine request sender and UID.");
		goto done;
	}
	sender_uid = nm_auth_subject_get_uid (subject);

	if (   0 != sender_uid
	    && !nm_session_monitor_uid_has_session (nm_session_monitor_get (),
	                                            sender_uid,
	                                            NULL,
	                                            &local)) {
		error = g_error_new_literal (NM_AGENT_MANAGER_ERROR,
		                             NM_AGENT_MANAGER_ERROR_SESSION_NOT_FOUND,
		                             local && local->message ? local->message : "Session not found");
		goto done;
	}

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
		                             NM_AGENT_MANAGER_ERROR_INTERNAL_ERROR,
		                             "Failed to initialize the agent");
		goto done;
	}

	nm_log_dbg (LOGD_AGENTS, "(%s) requesting permissions",
	            nm_secret_agent_get_description (agent));

	/* Kick off permissions requests for this agent */
	chain = nm_auth_chain_new_subject (subject, context, agent_register_permissions_done, self);
	if (chain) {
		nm_auth_chain_set_data (chain, "agent", agent, g_object_unref);
		nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_WIFI_SHARE_PROTECTED, FALSE);
		nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_WIFI_SHARE_OPEN, FALSE);

		priv->chains = g_slist_append (priv->chains, chain);
	} else {
		error = g_error_new_literal (NM_AGENT_MANAGER_ERROR,
		                             NM_AGENT_MANAGER_ERROR_SENDER_UNKNOWN,
		                             "Unable to start agent authentication.");
	}

done:
	if (error)
		dbus_g_method_return_error (context, error);
	g_clear_error (&error);
	g_clear_error (&local);
	g_clear_object (&subject);
}

static void
impl_agent_manager_register (NMAgentManager *self,
                             const char *identifier,
                             DBusGMethodInvocation *context)
{
	impl_agent_manager_register_with_capabilities (self, identifier, 0, context);
}

static void
impl_agent_manager_unregister (NMAgentManager *self,
                               DBusGMethodInvocation *context)
{
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (self);
	GError *error = NULL;
	char *sender = NULL;

	if (!nm_dbus_manager_get_caller_info (priv->dbus_mgr,
	                                      context,
	                                      &sender,
	                                      NULL,
	                                      NULL)) {
		error = g_error_new_literal (NM_AGENT_MANAGER_ERROR,
		                             NM_AGENT_MANAGER_ERROR_SENDER_UNKNOWN,
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

	dbus_g_method_return (context);

done:
	if (error)
		dbus_g_method_return_error (context, error);
	g_clear_error (&error);
	g_free (sender);
}

/*************************************************************/

typedef void (*RequestCompleteFunc) (Request *req,
                                     GHashTable *secrets,
                                     const char *agent_dbus_owner,
                                     const char *agent_username,
                                     GError *error,
                                     gpointer user_data);
typedef gboolean (*RequestAddAgentFunc) (Request *req, NMSecretAgent *agent);
typedef void (*RequestNextFunc) (Request *req);
typedef void (*RequestCancelFunc) (Request *req);

/* Basic secrets request structure */
struct _Request {
	guint32 reqid;
	char *detail;
	char *verb;

	NMAuthSubject *subject;

	/* Current agent being asked for secrets */
	NMSecretAgent *current;
	gconstpointer current_call_id;

	/* Stores the sorted list of NMSecretAgents which will be asked for secrets */
	GSList *pending;

	/* Stores the list of NMSecretAgent hashes that we've already
	 * asked for secrets, so that we don't ask the same agent twice
	 * if it quits and re-registers during this secrets request.
	 */
	GSList *asked;

	guint32 idle_id;

	RequestAddAgentFunc add_agent_callback;
	RequestCancelFunc cancel_callback;
	RequestNextFunc next_callback;
	RequestCompleteFunc complete_callback;
	gpointer complete_callback_data;
	gboolean completed;

	GDestroyNotify free_func;
};

static guint32 next_req_id = 1;

static Request *
request_new (gsize struct_size,
             const char *detail,
             const char *verb,
             NMAuthSubject *subject,
             RequestCompleteFunc complete_callback,
             gpointer complete_callback_data,
             RequestAddAgentFunc add_agent_callback,
             RequestNextFunc next_callback,
             RequestCancelFunc cancel_callback,
             GDestroyNotify free_func)
{
	Request *req;

	req = g_malloc0 (struct_size);
	req->reqid = next_req_id++;
	req->detail = g_strdup (detail);
	req->verb = g_strdup (verb);
	req->subject = g_object_ref (subject);
	req->complete_callback = complete_callback;
	req->complete_callback_data = complete_callback_data;
	req->add_agent_callback = add_agent_callback,
	req->next_callback = next_callback;
	req->cancel_callback = cancel_callback;
	req->free_func = free_func;
	return req;
}

static void
request_free (Request *req)
{
	if (req->free_func)
		req->free_func ((gpointer) req);

	if (req->idle_id)
		g_source_remove (req->idle_id);

	if (!req->completed && req->cancel_callback)
		req->cancel_callback (req);

	g_object_unref (req->subject);

	g_free (req->detail);
	g_free (req->verb);
	g_slist_free_full (req->pending, g_object_unref);
	g_slist_free (req->asked);
	memset (req, 0, sizeof (Request));
	g_free (req);
}

static void
req_complete_success (Request *req,
                      GHashTable *secrets,
                      const char *agent_dbus_owner,
                      const char *agent_uname)
{
	req->completed = TRUE;
	req->complete_callback (req,
	                        secrets,
	                        agent_dbus_owner,
	                        agent_uname,
	                        NULL,
	                        req->complete_callback_data);
}

static void
req_complete_error (Request *req, GError *error)
{
	req->completed = TRUE;
	req->complete_callback (req, NULL, NULL, NULL, error, req->complete_callback_data);
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
	requester = nm_auth_subject_get_pid (req->subject);
	if (requester != G_MAXULONG) {
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
	a_active = nm_session_monitor_uid_active (nm_session_monitor_get (),
	                                          nm_secret_agent_get_owner_uid (a),
	                                          NULL);
	b_active = nm_session_monitor_uid_active (nm_session_monitor_get (),
	                                          nm_secret_agent_get_owner_uid (b),
	                                          NULL);
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
	g_return_if_fail (req != NULL);
	g_return_if_fail (agent != NULL);

	if (g_slist_find (req->asked, GUINT_TO_POINTER (nm_secret_agent_get_hash (agent))))
		return;

	if (req->add_agent_callback && !req->add_agent_callback (req, agent))
		return;

	/* If the request should filter agents by UID, do that now */
	if (!nm_auth_subject_get_internal (req->subject)) {
		uid_t agent_uid, subject_uid;

		agent_uid = nm_secret_agent_get_owner_uid (agent);
		subject_uid = nm_auth_subject_get_uid (req->subject);
		if (agent_uid != subject_uid) {
			nm_log_dbg (LOGD_AGENTS, "(%s) agent ignored for secrets request %p/%s "
			            "(uid %ld not required %ld)",
			            nm_secret_agent_get_description (agent),
			            req, req->detail,
			            (long)agent_uid, (long)subject_uid);
			return;
		}
	}

	nm_log_dbg (LOGD_AGENTS, "(%s) agent allowed for secrets request %p/%s",
	            nm_secret_agent_get_description (agent),
	            req, req->detail);

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
	GError *error = NULL;

	if (req->pending) {
		/* Send the request to the next agent */
		req->current_call_id = NULL;
		if (req->current)
			g_object_unref (req->current);
		req->current = req->pending->data;
		req->pending = g_slist_remove (req->pending, req->current);

		nm_log_dbg (LOGD_AGENTS, "(%s) agent %s secrets for request %p/%s",
		            nm_secret_agent_get_description (req->current),
		            req->verb, req, req->detail);

		req->next_callback (req);
	} else {
		req->current_call_id = NULL;
		req->current = NULL;

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
	g_return_if_fail (req != NULL);
	g_return_if_fail (agent != NULL);

	req->pending = g_slist_remove (req->pending, agent);

	if (agent == req->current) {
		nm_log_dbg (LOGD_AGENTS, "(%s) current agent removed from secrets request %p/%s",
		            nm_secret_agent_get_description (agent), req, req->detail);
		*pending_reqs = g_slist_prepend (*pending_reqs, req);
	} else {
		nm_log_dbg (LOGD_AGENTS, "(%s) agent removed from secrets request %p/%s",
		            nm_secret_agent_get_description (agent), req, req->detail);
	}
}

static gboolean
request_start (gpointer user_data)
{
	Request *req = user_data;

	req->idle_id = 0;
	request_next_agent (req);
	return FALSE;
}

/*************************************************************/

/* Request subclass for connection secrets */
typedef struct {
	Request parent;

	NMSettingsGetSecretsFlags flags;
	NMConnection *connection;
	char *setting_name;
	char **hints;

	GHashTable *existing_secrets;

	NMAgentSecretsResultFunc callback;
	gpointer callback_data;
	gpointer other_data2;
	gpointer other_data3;

	NMAuthChain *chain;

	/* Whether the agent currently being asked for secrets
	 * has the system.modify privilege.
	 */
	gboolean current_has_modify;
} ConnectionRequest;

static void
connection_request_free (gpointer data)
{
	ConnectionRequest *req = data;

	g_object_unref (req->connection);
	g_free (req->setting_name);
	g_strfreev (req->hints);
	if (req->existing_secrets)
		g_hash_table_unref (req->existing_secrets);
	if (req->chain)
		nm_auth_chain_unref (req->chain);
}

static gboolean
connection_request_add_agent (Request *parent, NMSecretAgent *agent)
{
	ConnectionRequest *req = (ConnectionRequest *) parent;
	uid_t agent_uid = nm_secret_agent_get_owner_uid (agent);

	/* Ensure the caller's username exists in the connection's permissions,
	 * or that the permissions is empty (ie, visible by everyone).
	 */
	if (!nm_auth_uid_in_acl (req->connection, nm_session_monitor_get (), agent_uid, NULL)) {
		nm_log_dbg (LOGD_AGENTS, "(%s) agent ignored for secrets request %p/%s (not in ACL)",
		            nm_secret_agent_get_description (agent),
		            parent, parent->detail);
		/* Connection not visible to this agent's user */
		return FALSE;
	}

	return TRUE;
}

static ConnectionRequest *
connection_request_new_get (NMConnection *connection,
                            NMAuthSubject *subject,
                            GHashTable *existing_secrets,
                            const char *setting_name,
                            const char *verb,
                            NMSettingsGetSecretsFlags flags,
                            const char **hints,
                            NMAgentSecretsResultFunc callback,
                            gpointer callback_data,
                            gpointer other_data2,
                            gpointer other_data3,
                            RequestCompleteFunc complete_callback,
                            gpointer complete_callback_data,
                            RequestNextFunc next_callback,
                            RequestCancelFunc cancel_callback)
{
	ConnectionRequest *req;

	req = (ConnectionRequest *) request_new (sizeof (ConnectionRequest),
	                                         nm_connection_get_id (connection),
	                                         verb,
	                                         subject,
	                                         complete_callback,
	                                         complete_callback_data,
	                                         connection_request_add_agent,
	                                         next_callback,
	                                         cancel_callback,
	                                         connection_request_free);
	g_assert (req);

	req->connection = g_object_ref (connection);
	if (existing_secrets)
		req->existing_secrets = g_hash_table_ref (existing_secrets);
	req->setting_name = g_strdup (setting_name);
	req->hints = g_strdupv ((char **) hints);
	req->flags = flags;
	req->callback = callback;
	req->callback_data = callback_data;
	req->other_data2 = other_data2;
	req->other_data3 = other_data3;
	return req;
}

static ConnectionRequest *
connection_request_new_other (NMConnection *connection,
                              NMAuthSubject *subject,
                              const char *verb,
                              RequestCompleteFunc complete_callback,
                              gpointer complete_callback_data,
                              RequestNextFunc next_callback)
{
	ConnectionRequest *req;

	req = (ConnectionRequest *) request_new (sizeof (ConnectionRequest),
	                                         nm_connection_get_id (connection),
	                                         verb,
	                                         subject,
	                                         complete_callback,
	                                         complete_callback_data,
	                                         NULL,
	                                         next_callback,
	                                         NULL,
	                                         connection_request_free);
	g_assert (req);
	req->connection = g_object_ref (connection);
	return req;
}

static void
get_done_cb (NMSecretAgent *agent,
             gconstpointer call_id,
             GHashTable *secrets,
             GError *error,
             gpointer user_data)
{
	Request *parent = user_data;
	ConnectionRequest *req = user_data;
	GHashTable *setting_secrets;
	const char *agent_dbus_owner;
	struct passwd *pw;
	char *agent_uname = NULL;

	g_return_if_fail (call_id == parent->current_call_id);

	if (error) {
		nm_log_dbg (LOGD_AGENTS, "(%s) agent failed secrets request %p/%s/%s: (%d) %s",
		            nm_secret_agent_get_description (agent),
		            req, parent->detail, req->setting_name,
		            error ? error->code : -1,
		            (error && error->message) ? error->message : "(unknown)");

		if (dbus_g_error_has_name (error, NM_DBUS_INTERFACE_SECRET_AGENT ".UserCanceled")) {
			error = g_error_new_literal (NM_AGENT_MANAGER_ERROR,
			                             NM_AGENT_MANAGER_ERROR_USER_CANCELED,
			                             "User canceled the secrets request.");
			req_complete_error (parent, error);
			g_error_free (error);
		} else {
			/* Try the next agent */
			request_next_agent (parent);
		}
		return;
	}

	/* Ensure the setting we wanted secrets for got returned and has something in it */
	setting_secrets = g_hash_table_lookup (secrets, req->setting_name);
	if (!setting_secrets || !g_hash_table_size (setting_secrets)) {
		nm_log_dbg (LOGD_AGENTS, "(%s) agent returned no secrets for request %p/%s/%s",
		            nm_secret_agent_get_description (agent),
		            req, parent->detail, req->setting_name);
		/* Try the next agent */
		request_next_agent (parent);
		return;
	}

	nm_log_dbg (LOGD_AGENTS, "(%s) agent returned secrets for request %p/%s/%s",
	            nm_secret_agent_get_description (agent),
	            req, parent->detail, req->setting_name);

	/* Get the agent's username */
	pw = getpwuid (nm_secret_agent_get_owner_uid (agent));
	if (pw && strlen (pw->pw_name)) {
		/* Needs to be UTF-8 valid since it may be pushed through D-Bus */
		if (g_utf8_validate (pw->pw_name, -1, NULL))
			agent_uname = g_strdup (pw->pw_name);
	}

	agent_dbus_owner = nm_secret_agent_get_dbus_owner (agent);
	req_complete_success (parent, secrets, agent_dbus_owner, agent_uname);
	g_free (agent_uname);
}

static void
set_secrets_not_required (NMConnection *connection, GHashTable *hash)
{
	GHashTableIter iter, setting_iter;
	const char *setting_name = NULL;
	GHashTable *setting_hash = NULL;

	/* Iterate through the settings hashes */
	g_hash_table_iter_init (&iter, hash);
	while (g_hash_table_iter_next (&iter,
	                               (gpointer *) &setting_name,
	                               (gpointer *) &setting_hash)) {
		const char *key_name = NULL;
		NMSetting *setting;
		GValue *val;

		setting = nm_connection_get_setting_by_name (connection, setting_name);
		if (setting) {
			/* Now through each secret in the setting and mark it as not required */
			g_hash_table_iter_init (&setting_iter, setting_hash);
			while (g_hash_table_iter_next (&setting_iter, (gpointer *) &key_name, (gpointer *) &val)) {
				/* For each secret, set the flag that it's not required; VPN
				 * secrets need slightly different treatment here since the
				 * "secrets" property is actually a hash table of secrets.
				 */
				if (   strcmp (setting_name, NM_SETTING_VPN_SETTING_NAME) == 0
				    && strcmp (key_name, NM_SETTING_VPN_SECRETS) == 0
				    && G_VALUE_HOLDS (val, DBUS_TYPE_G_MAP_OF_STRING)) {
					GHashTableIter vpn_secret_iter;
					const char *secret_name;

					g_hash_table_iter_init (&vpn_secret_iter, g_value_get_boxed (val));
					while (g_hash_table_iter_next (&vpn_secret_iter, (gpointer *) &secret_name, NULL))
						nm_setting_set_secret_flags (setting, secret_name, NM_SETTING_SECRET_FLAG_NOT_REQUIRED, NULL);
				} else
					nm_setting_set_secret_flags (setting, key_name, NM_SETTING_SECRET_FLAG_NOT_REQUIRED, NULL);
			}
		}
	}
}

static void
get_agent_request_secrets (ConnectionRequest *req, gboolean include_system_secrets)
{
	Request *parent = (Request *) req;
	NMConnection *tmp;

	tmp = nm_connection_duplicate (req->connection);
	nm_connection_clear_secrets (tmp);
	if (include_system_secrets) {
		if (req->existing_secrets)
			(void) nm_connection_update_secrets (tmp, req->setting_name, req->existing_secrets, NULL);
	} else {
		/* Update secret flags in the temporary connection to indicate that
		 * the system secrets we're not sending to the agent aren't required,
		 * so the agent can properly validate UI controls and such.
		 */
		if (req->existing_secrets)
			set_secrets_not_required (tmp, req->existing_secrets);
	}

	parent->current_call_id = nm_secret_agent_get_secrets (parent->current,
	                                                       tmp,
	                                                       req->setting_name,
	                                                       (const char **) req->hints,
	                                                       req->flags,
	                                                       get_done_cb,
	                                                       req);
	if (parent->current_call_id == NULL) {
		/* Shouldn't hit this, but handle it anyway */
		g_warn_if_fail (parent->current_call_id != NULL);
		request_next_agent (parent);
	}

	g_object_unref (tmp);
}

static void
get_agent_modify_auth_cb (NMAuthChain *chain,
                          GError *error,
                          DBusGMethodInvocation *context,
                          gpointer user_data)
{
	Request *parent = user_data;
	ConnectionRequest *req = user_data;
	const char *perm;

	req->chain = NULL;

	if (error) {
		nm_log_dbg (LOGD_AGENTS, "(%s) agent %p/%s/%s MODIFY check error: (%d) %s",
		            nm_secret_agent_get_description (parent->current),
		            req, parent->detail, req->setting_name,
		            error->code, error->message ? error->message : "(unknown)");
		/* Try the next agent */
		request_next_agent (parent);
	} else {
		/* If the agent obtained the 'modify' permission, we send all system secrets
		 * to it.  If it didn't, we still ask it for secrets, but we don't send
		 * any system secrets.
		 */
		perm = nm_auth_chain_get_data (chain, "perm");
		g_assert (perm);
		if (nm_auth_chain_get_result (chain, perm) == NM_AUTH_CALL_RESULT_YES)
			req->current_has_modify = TRUE;

		nm_log_dbg (LOGD_AGENTS, "(%s) agent %p/%s/%s MODIFY check result %s",
		            nm_secret_agent_get_description (parent->current),
		            req, parent->detail, req->setting_name,
		            req->current_has_modify ? "YES" : "NO");

		get_agent_request_secrets (req, req->current_has_modify);
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
		nm_setting_get_secret_flags (setting, key, &secret_flags, NULL);
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
get_next_cb (Request *parent)
{
	ConnectionRequest *req = (ConnectionRequest *) parent;
	NMSettingConnection *s_con;
	const char *agent_dbus_owner, *perm;

	req->current_has_modify = FALSE;

	agent_dbus_owner = nm_secret_agent_get_dbus_owner (parent->current);

	/* If the request flags allow user interaction, and there are existing
	 * system secrets (or blank secrets that are supposed to be system-owned),
	 * check whether the agent has the 'modify' permission before sending those
	 * secrets to the agent.  We shouldn't leak system-owned secrets to
	 * unprivileged users.
	 */
	if (   (req->flags != NM_SETTINGS_GET_SECRETS_FLAG_NONE)
	    && (req->existing_secrets || has_system_secrets (req->connection))) {
		nm_log_dbg (LOGD_AGENTS, "(%p/%s/%s) request has system secrets; checking agent %s for MODIFY",
		            req, parent->detail, req->setting_name, agent_dbus_owner);

		req->chain = nm_auth_chain_new_subject (nm_secret_agent_get_subject (parent->current),
		                                        NULL,
		                                        get_agent_modify_auth_cb,
		                                        req);
		g_assert (req->chain);

		/* If the caller is the only user in the connection's permissions, then
		 * we use the 'modify.own' permission instead of 'modify.system'.  If the
		 * request affects more than just the caller, require 'modify.system'.
		 */
		s_con = nm_connection_get_setting_connection (req->connection);
		g_assert (s_con);
		if (nm_setting_connection_get_num_permissions (s_con) == 1)
			perm = NM_AUTH_PERMISSION_SETTINGS_MODIFY_OWN;
		else
			perm = NM_AUTH_PERMISSION_SETTINGS_MODIFY_SYSTEM;
		nm_auth_chain_set_data (req->chain, "perm", (gpointer) perm, NULL);

		nm_auth_chain_add_call (req->chain, perm, TRUE);
	} else {
		nm_log_dbg (LOGD_AGENTS, "(%p/%s/%s) requesting user-owned secrets from agent %s",
		            req, parent->detail, req->setting_name, agent_dbus_owner);

		get_agent_request_secrets (req, FALSE);
	}
}

static gboolean
get_start (gpointer user_data)
{
	Request *parent = user_data;
	ConnectionRequest *req = user_data;
	GHashTable *setting_secrets = NULL;

	parent->idle_id = 0;

	/* Check if there are any existing secrets */
	if (req->existing_secrets)
		setting_secrets = g_hash_table_lookup (req->existing_secrets, req->setting_name);

	if (setting_secrets && g_hash_table_size (setting_secrets)) {
		NMConnection *tmp;
		GError *error = NULL;
		gboolean new_secrets = (req->flags & NM_SETTINGS_GET_SECRETS_FLAG_REQUEST_NEW);

		/* The connection already had secrets; check if any more are required.
		 * If no more are required, we're done.  If secrets are still needed,
		 * ask a secret agent for more.  This allows admins to provide generic
		 * secrets but allow additional user-specific ones as well.
		 */
		tmp = nm_connection_duplicate (req->connection);
		g_assert (tmp);

		if (!nm_connection_update_secrets (tmp, req->setting_name, req->existing_secrets, &error)) {
			req_complete_error (parent, error);
			g_clear_error (&error);
		} else {
			/* Do we have everything we need? */
			if (   (req->flags & NM_SETTINGS_GET_SECRETS_FLAG_ONLY_SYSTEM)
			    || ((nm_connection_need_secrets (tmp, NULL) == NULL) && (new_secrets == FALSE))) {
				nm_log_dbg (LOGD_AGENTS, "(%p/%s/%s) system settings secrets sufficient",
				            req, parent->detail, req->setting_name);

				/* Got everything, we're done */
				req_complete_success (parent, req->existing_secrets, NULL, NULL);
			} else {
				nm_log_dbg (LOGD_AGENTS, "(%p/%s/%s) system settings secrets insufficient, asking agents",
				            req, parent->detail, req->setting_name);

				/* We don't, so ask some agents for additional secrets */
				request_next_agent (parent);
			}
		}
		g_object_unref (tmp);
	} else {
		/* Couldn't get secrets from system settings, so now we ask the
		 * agents for secrets.  Let the Agent Manager handle which agents
		 * we'll ask and in which order.
		 */
		request_next_agent (parent);
	}

	return FALSE;
}

static void
get_complete_cb (Request *parent,
                 GHashTable *secrets,
                 const char *agent_dbus_owner,
                 const char *agent_username,
                 GError *error,
                 gpointer user_data)
{
	NMAgentManager *self = NM_AGENT_MANAGER (user_data);
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (self);
	ConnectionRequest *req = (ConnectionRequest *) parent;

	/* Send secrets back to the requesting object */
	req->callback (self,
	               parent->reqid,
	               agent_dbus_owner,
	               agent_username,
	               req->current_has_modify,
	               req->setting_name,
	               req->flags,
	               error ? NULL : secrets,
	               error,
	               req->callback_data,
	               req->other_data2,
	               req->other_data3);

	g_hash_table_remove (priv->requests, GUINT_TO_POINTER (parent->reqid));
}

static void
get_cancel_cb (Request *parent)
{
	ConnectionRequest *req = (ConnectionRequest *) parent;

	req->current_has_modify = FALSE;
	if (parent->current && parent->current_call_id)
		nm_secret_agent_cancel_secrets (parent->current, parent->current_call_id);
}

guint32
nm_agent_manager_get_secrets (NMAgentManager *self,
                              NMConnection *connection,
                              NMAuthSubject *subject,
                              GHashTable *existing_secrets,
                              const char *setting_name,
                              NMSettingsGetSecretsFlags flags,
                              const char **hints,
                              NMAgentSecretsResultFunc callback,
                              gpointer callback_data,
                              gpointer other_data2,
                              gpointer other_data3)
{
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (self);
	Request *parent;
	ConnectionRequest *req;

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
	 * This in turn depends on nm_connection_to_hash() and nm_setting_to_hash()
	 * both returning NULL if they didn't hash anything.
	 */

	req = connection_request_new_get (connection,
	                                  subject,
	                                  existing_secrets,
	                                  setting_name,
	                                  "getting",
	                                  flags,
	                                  hints,
	                                  callback,
	                                  callback_data,
	                                  other_data2,
	                                  other_data3,
	                                  get_complete_cb,
	                                  self,
	                                  get_next_cb,
	                                  get_cancel_cb);
	parent = (Request *) req;
	g_hash_table_insert (priv->requests, GUINT_TO_POINTER (parent->reqid), req);

	/* Kick off the request */
	if (!(req->flags & NM_SETTINGS_GET_SECRETS_FLAG_ONLY_SYSTEM))
		request_add_agents (self, parent);
	parent->idle_id = g_idle_add (get_start, req);
	return parent->reqid;
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
              gconstpointer call_id,
              GHashTable *secrets,
              GError *error,
              gpointer user_data)
{
	Request *parent = user_data;
	ConnectionRequest *req = user_data;
	const char *agent_dbus_owner;

	g_return_if_fail (call_id == parent->current_call_id);

	if (error) {
		nm_log_dbg (LOGD_AGENTS, "(%s) agent failed save secrets request %p/%s: (%d) %s",
		            nm_secret_agent_get_description (agent),
		            req, parent->detail,
		            error ? error->code : -1,
		            (error && error->message) ? error->message : "(unknown)");
		/* Try the next agent */
		request_next_agent (parent);
		return;
	}

	nm_log_dbg (LOGD_AGENTS, "(%s) agent saved secrets for request %p/%s",
	            nm_secret_agent_get_description (agent),
	            req, parent->detail);

	agent_dbus_owner = nm_secret_agent_get_dbus_owner (agent);
	req_complete_success (parent, NULL, NULL, agent_dbus_owner);
}

static void
save_next_cb (Request *parent)
{
	ConnectionRequest *req = (ConnectionRequest *) parent;

	parent->current_call_id = nm_secret_agent_save_secrets (parent->current,
	                                                        req->connection,
	                                                        save_done_cb,
	                                                        req);
	if (parent->current_call_id == NULL) {
		/* Shouldn't hit this, but handle it anyway */
		g_warn_if_fail (parent->current_call_id != NULL);
		request_next_agent (parent);
	}
}

static void
save_complete_cb (Request *req,
                  GHashTable *secrets,
                  const char *agent_dbus_owner,
                  const char *agent_username,
                  GError *error,
                  gpointer user_data)
{
	g_hash_table_remove (NM_AGENT_MANAGER_GET_PRIVATE (user_data)->requests,
	                     GUINT_TO_POINTER (req->reqid));
}

guint32
nm_agent_manager_save_secrets (NMAgentManager *self,
                               NMConnection *connection,
                               NMAuthSubject *subject)
{
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (self);
	ConnectionRequest *req;
	Request *parent;

	g_return_val_if_fail (self != NULL, 0);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), 0);

	nm_log_dbg (LOGD_SETTINGS,
	            "Saving secrets for connection %s (%s)",
	            nm_connection_get_path (connection),
	            nm_connection_get_id (connection));

	req = connection_request_new_other (connection,
	                                    subject,
	                                    "saving",
	                                    save_complete_cb,
	                                    self,
	                                    save_next_cb);
	parent = (Request *) req;
	g_hash_table_insert (priv->requests, GUINT_TO_POINTER (parent->reqid), req);

	/* Kick off the request */
	request_add_agents (self, parent);
	parent->idle_id = g_idle_add (request_start, req);
	return parent->reqid;
}

/*************************************************************/

static void
delete_done_cb (NMSecretAgent *agent,
              gconstpointer call_id,
              GHashTable *secrets,
              GError *error,
              gpointer user_data)
{
	Request *req = user_data;

	g_return_if_fail (call_id == req->current_call_id);

	if (error) {
		nm_log_dbg (LOGD_AGENTS, "(%s) agent failed delete secrets request %p/%s: (%d) %s",
		            nm_secret_agent_get_description (agent), req, req->detail,
		            error ? error->code : -1,
		            (error && error->message) ? error->message : "(unknown)");
	} else {
		nm_log_dbg (LOGD_AGENTS, "(%s) agent deleted secrets for request %p/%s",
		            nm_secret_agent_get_description (agent), req, req->detail);
	}

	/* Tell the next agent to delete secrets */
	request_next_agent (req);
}

static void
delete_next_cb (Request *parent)
{
	ConnectionRequest *req = (ConnectionRequest *) parent;

	parent->current_call_id = nm_secret_agent_delete_secrets (parent->current,
	                                                          req->connection,
	                                                          delete_done_cb,
	                                                          req);
	if (parent->current_call_id == NULL) {
		/* Shouldn't hit this, but handle it anyway */
		g_warn_if_fail (parent->current_call_id != NULL);
		request_next_agent (parent);
	}
}

static void
delete_complete_cb (Request *req,
                    GHashTable *secrets,
                    const char *agent_dbus_owner,
                    const char *agent_username,
                    GError *error,
                    gpointer user_data)
{
	g_hash_table_remove (NM_AGENT_MANAGER_GET_PRIVATE (user_data)->requests,
	                     GUINT_TO_POINTER (req->reqid));
}

guint32
nm_agent_manager_delete_secrets (NMAgentManager *self,
                                 NMConnection *connection)
{
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (self);
	NMAuthSubject *subject;
	ConnectionRequest *req;
	Request *parent;

	g_return_val_if_fail (self != NULL, 0);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), 0);

	nm_log_dbg (LOGD_SETTINGS,
	            "Deleting secrets for connection %s (%s)",
	            nm_connection_get_path (connection),
	            nm_connection_get_id (connection));

	subject = nm_auth_subject_new_internal ();
	req = connection_request_new_other (connection,
	                                    subject,
	                                    "deleting",
	                                    delete_complete_cb,
	                                    self,
	                                    delete_next_cb);
	g_object_unref (subject);
	parent = (Request *) req;
	g_hash_table_insert (priv->requests, GUINT_TO_POINTER (parent->reqid), req);

	/* Kick off the request */
	request_add_agents (self, parent);
	parent->idle_id = g_idle_add (request_start, req);
	return parent->reqid;
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

	g_hash_table_iter_init (&iter, priv->agents);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer) &agent)) {
		if (   !nm_auth_subject_get_internal (subject)
		    && nm_secret_agent_get_owner_uid (agent) != nm_auth_subject_get_uid (subject))
			continue;

		if (!(nm_secret_agent_get_capabilities (agent) & capability))
			return FALSE;
	}

	return TRUE;
}

/*************************************************************/

static void
name_owner_changed_cb (NMDBusManager *dbus_mgr,
                       const char *name,
                       const char *old_owner,
                       const char *new_owner,
                       gpointer user_data)
{
	if (old_owner) {
		/* The agent quit, so remove it and let interested clients know */
		remove_agent (NM_AGENT_MANAGER (user_data), old_owner);
	}
}

static void
agent_permissions_changed_done (NMAuthChain *chain,
                                GError *error,
                                DBusGMethodInvocation *context,
                                gpointer user_data)
{
	NMAgentManager *self = NM_AGENT_MANAGER (user_data);
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (self);
	NMSecretAgent *agent;
	gboolean share_protected = FALSE, share_open = FALSE;

	priv->chains = g_slist_remove (priv->chains, chain);

	agent = nm_auth_chain_get_data (chain, "agent");
	g_assert (agent);

	if (error) {
		nm_log_dbg (LOGD_AGENTS, "(%s) failed to request updated agent permissions",
		            nm_secret_agent_get_description (agent));
	} else {
		nm_log_dbg (LOGD_AGENTS, "(%s) updated agent permissions",
		            nm_secret_agent_get_description (agent));

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
authority_changed_cb (gpointer user_data)
{
	NMAgentManager *self = NM_AGENT_MANAGER (user_data);
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

NMAgentManager *
nm_agent_manager_get (void)
{
	static NMAgentManager *singleton = NULL;
	NMAgentManagerPrivate *priv;

	if (singleton)
		return g_object_ref (singleton);

	singleton = (NMAgentManager *) g_object_new (NM_TYPE_AGENT_MANAGER, NULL);
	g_assert (singleton);

	priv = NM_AGENT_MANAGER_GET_PRIVATE (singleton);
	priv->dbus_mgr = nm_dbus_manager_get ();

	nm_dbus_manager_register_object (priv->dbus_mgr, NM_DBUS_PATH_AGENT_MANAGER, singleton);

	g_signal_connect (priv->dbus_mgr,
	                  NM_DBUS_MANAGER_NAME_OWNER_CHANGED,
	                  G_CALLBACK (name_owner_changed_cb),
	                  singleton);

	nm_auth_changed_func_register (authority_changed_cb, singleton);

	return singleton;
}

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
dispose (GObject *object)
{
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (object);

	if (!priv->disposed) {
		priv->disposed = TRUE;

		nm_auth_changed_func_unregister (authority_changed_cb, NM_AGENT_MANAGER (object));

		g_slist_free_full (priv->chains, (GDestroyNotify) nm_auth_chain_unref);

		g_hash_table_destroy (priv->agents);
		g_hash_table_destroy (priv->requests);

		priv->dbus_mgr = NULL;
	}

	G_OBJECT_CLASS (nm_agent_manager_parent_class)->dispose (object);
}

static void
nm_agent_manager_class_init (NMAgentManagerClass *agent_manager_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (agent_manager_class);

	g_type_class_add_private (agent_manager_class, sizeof (NMAgentManagerPrivate));

	/* virtual methods */
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

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (agent_manager_class),
	                                 &dbus_glib_nm_agent_manager_object_info);

	dbus_g_error_domain_register (NM_AGENT_MANAGER_ERROR,
	                              NM_DBUS_INTERFACE_AGENT_MANAGER,
	                              NM_TYPE_AGENT_MANAGER_ERROR);
}
