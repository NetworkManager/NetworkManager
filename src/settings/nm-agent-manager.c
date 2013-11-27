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
	NMSessionMonitor *session_monitor;

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

static void request_add_agent (Request *req,
                               NMSecretAgent *agent,
                               NMSessionMonitor *session_monitor);

static void request_remove_agent (gpointer key, gpointer value, gpointer user_data);

static void impl_agent_manager_register (NMAgentManager *self,
                                         const char *identifier,
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

/*----------------------------------------------------------------------------*/
/* GHashTable safe iterating function: x_g_hash_table_safe_for_each()
 * GHashTable can't be modified while iterating, the common solution for that is
 * to flatten the hash table first and iterate over list.
 * Taken from https://github.com/linuxmint/nemo/blob/master/eel/eel-glib-extensions.c
 */
typedef struct {
	GList *keys;
	GList *values;
} FlattenedHashTable;

static void
flatten_hash_table_element (gpointer key, gpointer value, gpointer callback_data)
{
	FlattenedHashTable *flattened_table;

	flattened_table = callback_data;
	flattened_table->keys = g_list_prepend
	        (flattened_table->keys, key);
	flattened_table->values = g_list_prepend
	        (flattened_table->values, value);
}

static void
x_g_hash_table_safe_for_each (GHashTable *hash_table,
                              GHFunc callback,
                              gpointer callback_data)
{
	FlattenedHashTable flattened;
	GList *p, *q;

	flattened.keys = NULL;
	flattened.values = NULL;

	g_hash_table_foreach (hash_table,
	                      flatten_hash_table_element,
	                      &flattened);

	for (p = flattened.keys, q = flattened.values;
	     p != NULL;
	     p = p->next, q = q->next) {
	        (* callback) (p->data, q->data, callback_data);
	}

	g_list_free (flattened.keys);
	g_list_free (flattened.values);
}
/*----------------------------------------------------------------------------*/

static gboolean
remove_agent (NMAgentManager *self, const char *owner)
{
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (self);
	NMSecretAgent *agent;

	g_return_val_if_fail (owner != NULL, FALSE);

	/* Make sure this agent has already registered */
	agent = g_hash_table_lookup (priv->agents, owner);
	if (!agent)
		return FALSE;

	nm_log_dbg (LOGD_AGENTS, "(%s) agent unregistered",
	            nm_secret_agent_get_description (agent));

	/* Remove this agent from any in-progress secrets requests */
	x_g_hash_table_safe_for_each (priv->requests, request_remove_agent, agent);

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
			request_add_agent (req, agent, priv->session_monitor);
	}

	nm_auth_chain_unref (chain);
}

static void
impl_agent_manager_register (NMAgentManager *self,
                             const char *identifier,
                             DBusGMethodInvocation *context)
{
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (self);
	char *error_desc = NULL, *sender = NULL;
	gulong sender_uid = G_MAXULONG;
	GError *error = NULL, *local = NULL;
	NMSecretAgent *agent;
	NMAuthChain *chain;

	if (!nm_auth_get_caller_uid (context, 
		                         priv->dbus_mgr,
	                             &sender_uid,
	                             &error_desc)) {
		error = g_error_new_literal (NM_AGENT_MANAGER_ERROR,
		                             NM_AGENT_MANAGER_ERROR_SENDER_UNKNOWN,
		                             error_desc);
		g_free (error_desc);
		goto done;
	}

	if (   0 != sender_uid
	    && !nm_session_monitor_uid_has_session (priv->session_monitor,
	                                            sender_uid,
	                                            NULL,
	                                            &local)) {
		error = g_error_new_literal (NM_AGENT_MANAGER_ERROR,
		                             NM_AGENT_MANAGER_ERROR_SESSION_NOT_FOUND,
		                             local && local->message ? local->message : "Session not found");
		goto done;
	}

	sender = dbus_g_method_get_sender (context);
	if (!sender) {
		error = g_error_new_literal (NM_AGENT_MANAGER_ERROR,
		                             NM_AGENT_MANAGER_ERROR_SENDER_UNKNOWN,
		                             "Failed to get D-Bus request sender");
		goto done;
	}

	/* Validate the identifier */
	if (!validate_identifier (identifier, &error))
		goto done;

	/* Success, add the new agent */
	agent = nm_secret_agent_new (priv->dbus_mgr, sender, identifier, sender_uid);
	if (!agent) {
		error = g_error_new_literal (NM_AGENT_MANAGER_ERROR,
		                             NM_AGENT_MANAGER_ERROR_INTERNAL_ERROR,
		                             "Failed to initialize the agent");
		goto done;
	}

	nm_log_dbg (LOGD_AGENTS, "(%s) requesting permissions",
	            nm_secret_agent_get_description (agent));

	/* Kick off permissions requests for this agent */
	chain = nm_auth_chain_new (context, NULL, agent_register_permissions_done, self);
	nm_auth_chain_set_data (chain, "agent", agent, g_object_unref);
	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_WIFI_SHARE_PROTECTED, FALSE);
	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_WIFI_SHARE_OPEN, FALSE);

	priv->chains = g_slist_append (priv->chains, chain);

done:
	if (error)
		dbus_g_method_return_error (context, error);
	g_clear_error (&error);
	g_clear_error (&local);
	g_free (sender);
}

static void
impl_agent_manager_unregister (NMAgentManager *self,
                               DBusGMethodInvocation *context)
{
	GError *error = NULL;
	char *sender = NULL;

	sender = dbus_g_method_get_sender (context);
	if (!sender) {
		error = g_error_new_literal (NM_AGENT_MANAGER_ERROR,
		                             NM_AGENT_MANAGER_ERROR_SENDER_UNKNOWN,
		                             "Failed to get D-Bus request sender");
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
                                     gboolean agent_has_modify,
                                     GError *error,
                                     gpointer user_data);
typedef void (*RequestNextFunc) (Request *req);
typedef void (*RequestCancelFunc) (Request *req);

struct _Request {
	guint32 reqid;
	NMAuthChain *chain;

	NMConnection *connection;
	gboolean filter_by_uid;
	gulong uid_filter;
	char *setting_name;
	NMSettingsGetSecretsFlags flags;
	char *hint;

	/* Current agent being asked for secrets */
	NMSecretAgent *current;
	gconstpointer current_call_id;
	gboolean current_has_modify;

	/* Stores the sorted list of NMSecretAgents which will be asked for secrets */
	GSList *pending;

	/* Stores the list of NMSecretAgent hashes that we've already
	 * asked for secrets, so that we don't ask the same agent twice
	 * if it quits and re-registers during this secrets request.
	 */
	GSList *asked;

	guint32 idle_id;

	GHashTable *existing_secrets;

	NMAgentSecretsResultFunc callback;
	gpointer callback_data;
	gpointer other_data2;
	gpointer other_data3;

	RequestCancelFunc cancel_callback;
	RequestNextFunc next_callback;
	RequestCompleteFunc complete_callback;
	gpointer complete_callback_data;
};

static guint32 next_req_id = 1;

static Request *
request_new_get (NMConnection *connection,
                 gboolean filter_by_uid,
                 gulong uid_filter,
                 GHashTable *existing_secrets,
                 const char *setting_name,
                 NMSettingsGetSecretsFlags flags,
                 const char *hint,
                 NMAgentSecretsResultFunc callback,
                 gpointer callback_data,
                 gpointer other_data2,
                 gpointer other_data3,
                 RequestCompleteFunc complete_callback,
                 gpointer complete_callback_data,
                 RequestNextFunc next_callback,
                 RequestCancelFunc cancel_callback)
{
	Request *req;

	req = g_malloc0 (sizeof (Request));
	req->reqid = next_req_id++;
	req->connection = g_object_ref (connection);
	req->filter_by_uid = filter_by_uid;
	req->uid_filter = uid_filter;
	if (existing_secrets)
		req->existing_secrets = g_hash_table_ref (existing_secrets);
	req->setting_name = g_strdup (setting_name);
	req->flags = flags;
	req->hint = g_strdup (hint);
	req->callback = callback;
	req->callback_data = callback_data;
	req->other_data2 = other_data2;
	req->other_data3 = other_data3;
	req->complete_callback = complete_callback;
	req->complete_callback_data = complete_callback_data;
	req->next_callback = next_callback;
	req->cancel_callback = cancel_callback;

	return req;
}

static Request *
request_new_other (NMConnection *connection,
                   gboolean filter_by_uid,
                   gulong uid_filter,
                   RequestCompleteFunc complete_callback,
                   gpointer complete_callback_data,
                   RequestNextFunc next_callback)
{
	Request *req;

	req = g_malloc0 (sizeof (Request));
	req->reqid = next_req_id++;
	req->connection = g_object_ref (connection);
	req->filter_by_uid = filter_by_uid;
	req->uid_filter = uid_filter;
	req->complete_callback = complete_callback;
	req->complete_callback_data = complete_callback_data;
	req->next_callback = next_callback;

	return req;
}

static void
request_free (Request *req)
{
	if (req->idle_id)
		g_source_remove (req->idle_id);

	if (req->cancel_callback)
		req->cancel_callback (req);

	g_slist_free (req->pending);
	g_slist_free (req->asked);
	g_object_unref (req->connection);
	g_free (req->setting_name);
	g_free (req->hint);
	if (req->existing_secrets)
		g_hash_table_unref (req->existing_secrets);
	if (req->chain)
		nm_auth_chain_unref (req->chain);
	memset (req, 0, sizeof (Request));
	g_free (req);
}

static void
req_complete_success (Request *req,
                      GHashTable *secrets,
                      const char *agent_dbus_owner,
                      const char *agent_uname,
                      gboolean agent_has_modify)
{
	req->complete_callback (req,
	                        secrets,
	                        agent_dbus_owner,
	                        agent_uname,
	                        agent_has_modify,
	                        NULL,
	                        req->complete_callback_data);
}

static void
req_complete_error (Request *req, GError *error)
{
	req->complete_callback (req, NULL, NULL, NULL, FALSE, error, req->complete_callback_data);
}

static gint
agent_compare_func (NMSecretAgent *a, NMSecretAgent *b, gpointer user_data)
{
	NMSessionMonitor *session_monitor = NM_SESSION_MONITOR (user_data);
	gboolean a_active, b_active;

	if (a && !b)
		return -1;
	else if (a == b)
		return 0;
	else if (!a && b)
		return 1;

	/* Prefer agents in active sessions */
	a_active = nm_session_monitor_uid_active (session_monitor,
	                                          nm_secret_agent_get_owner_uid (a),
	                                          NULL);
	b_active = nm_session_monitor_uid_active (session_monitor,
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
request_add_agent (Request *req,
                   NMSecretAgent *agent,
                   NMSessionMonitor *session_monitor)
{
	uid_t agent_uid;

	g_return_if_fail (req != NULL);
	g_return_if_fail (agent != NULL);

	if (g_slist_find (req->asked, GUINT_TO_POINTER (nm_secret_agent_get_hash (agent))))
		return;

	/* Ensure the caller's username exists in the connection's permissions,
	 * or that the permissions is empty (ie, visible by everyone).
	 */
	agent_uid = nm_secret_agent_get_owner_uid (agent);
	if (!nm_auth_uid_in_acl (req->connection, session_monitor, agent_uid, NULL)) {
		nm_log_dbg (LOGD_AGENTS, "(%s) agent ignored for secrets request %p/%s (not in ACL)",
		            nm_secret_agent_get_description (agent),
		            req, req->setting_name);
		/* Connection not visible to this agent's user */
		return;
	}

	/* If the request should filter agents by UID, do that now */
	if (req->filter_by_uid && (agent_uid != req->uid_filter)) {
		nm_log_dbg (LOGD_AGENTS, "(%s) agent ignored for secrets request %p/%s "
		            "(uid %d not required %ld)",
				    nm_secret_agent_get_description (agent),
				    req, req->setting_name, agent_uid, req->uid_filter);
		return;
	}

	nm_log_dbg (LOGD_AGENTS, "(%s) agent allowed for secrets request %p/%s",
			    nm_secret_agent_get_description (agent),
			    req, req->setting_name);

	/* Add this agent to the list, preferring active sessions */
	req->pending = g_slist_insert_sorted_with_data (req->pending,
	                                                agent,
	                                                (GCompareDataFunc) agent_compare_func,
	                                                session_monitor);
}

static void
request_add_agents (NMAgentManager *self, Request *req)
{
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (self);
	GHashTableIter iter;
	gpointer data;

	g_hash_table_iter_init (&iter, priv->agents);
	while (g_hash_table_iter_next (&iter, NULL, &data))
		request_add_agent (req, NM_SECRET_AGENT (data), priv->session_monitor);
}

static void
request_remove_agent (gpointer key, gpointer value, gpointer user_data)
{
	Request *req = (Request *) value;
	NMSecretAgent *agent = (NMSecretAgent *) user_data;
	gboolean try_next = FALSE;
	const char *detail = "";

	g_return_if_fail (req != NULL);
	g_return_if_fail (agent != NULL);

	/* If this agent is being asked right now, cancel the request */
	if (agent == req->current) {
		if (req->cancel_callback)
			req->cancel_callback (req);
		req->current_has_modify = FALSE;
		req->current = NULL;
		req->current_call_id = NULL;
		try_next = TRUE;
		detail = " current";
	}

	nm_log_dbg (LOGD_AGENTS, "(%s)%s agent removed from secrets request %p/%s",
				nm_secret_agent_get_description (agent),
				detail, req, req->setting_name);

	req->pending = g_slist_remove (req->pending, agent);

	if (try_next) {
		/* If the agent serving the in-progress secrets request went away then
		 * we need to send the request to the next agent.
		 */
		req->next_callback (req);
	}
}

static gboolean
next_generic (Request *req, const char *detail)
{
	GError *error = NULL;
	gboolean success = FALSE;

	if (req->pending == NULL) {
		/* No more secret agents are available to fulfill this secrets request */
		error = g_error_new_literal (NM_AGENT_MANAGER_ERROR,
		                             NM_AGENT_MANAGER_ERROR_NO_SECRETS,
		                             "No agents were available for this request.");
		req_complete_error (req, error);
		g_error_free (error);
	} else {
		/* Send a secrets request to the next agent */
		req->current_has_modify = FALSE;
		req->current = req->pending->data;
		req->pending = g_slist_remove (req->pending, req->current);

		nm_log_dbg (LOGD_AGENTS, "(%s) agent %s secrets for request %p/%s",
					nm_secret_agent_get_description (req->current),
					detail, req, req->setting_name);
		success = TRUE;
	}

	return success;
}

static gboolean
start_generic (gpointer user_data)
{
	Request *req = user_data;

	req->idle_id = 0;
	req->next_callback (req);
	return FALSE;
}


/*************************************************************/

static void
get_done_cb (NMSecretAgent *agent,
             gconstpointer call_id,
             GHashTable *secrets,
             GError *error,
             gpointer user_data)
{
	Request *req = user_data;
	GHashTable *setting_secrets;
	const char *agent_dbus_owner;
	gboolean agent_has_modify;
	struct passwd *pw;
	char *agent_uname = NULL;

	g_return_if_fail (call_id == req->current_call_id);

	agent_has_modify = req->current_has_modify;
	req->current_has_modify = FALSE;
	req->current = NULL;
	req->current_call_id = NULL;

	if (error) {
		nm_log_dbg (LOGD_AGENTS, "(%s) agent failed secrets request %p/%s: (%d) %s",
		            nm_secret_agent_get_description (agent),
		            req, req->setting_name,
		            error ? error->code : -1,
		            (error && error->message) ? error->message : "(unknown)");

		/* Try the next agent */
		req->next_callback (req);
		return;
	}

	/* Ensure the setting we wanted secrets for got returned and has something in it */
	setting_secrets = g_hash_table_lookup (secrets, req->setting_name);
	if (!setting_secrets || !g_hash_table_size (setting_secrets)) {
		nm_log_dbg (LOGD_AGENTS, "(%s) agent returned no secrets for request %p/%s",
		            nm_secret_agent_get_description (agent),
		            req, req->setting_name);

		/* Try the next agent */
		req->next_callback (req);
		return;
	}

	nm_log_dbg (LOGD_AGENTS, "(%s) agent returned secrets for request %p/%s",
	            nm_secret_agent_get_description (agent),
	            req, req->setting_name);

	/* Get the agent's username */
	pw = getpwuid (nm_secret_agent_get_owner_uid (agent));
	if (pw && strlen (pw->pw_name)) {
		/* Needs to be UTF-8 valid since it may be pushed through D-Bus */
		if (g_utf8_validate (pw->pw_name, -1, NULL))
			agent_uname = g_strdup (pw->pw_name);
	}

	agent_dbus_owner = nm_secret_agent_get_dbus_owner (agent);
	req_complete_success (req, secrets, agent_dbus_owner, agent_uname, agent_has_modify);
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
get_agent_request_secrets (Request *req, gboolean include_system_secrets)
{
	NMConnection *tmp;

	tmp = nm_connection_duplicate (req->connection);
	nm_connection_clear_secrets (tmp);
	if (include_system_secrets) {
		if (req->existing_secrets)
			nm_connection_update_secrets (tmp, req->setting_name, req->existing_secrets, NULL);
	} else {
		/* Update secret flags in the temporary connection to indicate that
		 * the system secrets we're not sending to the agent aren't required,
		 * so the agent can properly validate UI controls and such.
		 */
		if (req->existing_secrets)
			set_secrets_not_required (tmp, req->existing_secrets);
	}

	req->current_call_id = nm_secret_agent_get_secrets (NM_SECRET_AGENT (req->current),
	                                                    tmp,
	                                                    req->setting_name,
	                                                    req->hint,
	                                                    req->flags,
	                                                    get_done_cb,
	                                                    req);
	if (req->current_call_id == NULL) {
		/* Shouldn't hit this, but handle it anyway */
		g_warn_if_fail (req->current_call_id != NULL);
		req->current_has_modify = FALSE;
		req->current = NULL;
		req->next_callback (req);
	}

	g_object_unref (tmp);
}

static void
get_agent_modify_auth_cb (NMAuthChain *chain,
                          GError *error,
                          DBusGMethodInvocation *context,
                          gpointer user_data)
{
	Request *req = user_data;
	NMAuthCallResult result;
	const char *perm;

	req->chain = NULL;

	if (error) {
		nm_log_dbg (LOGD_AGENTS, "(%p/%s) agent MODIFY check error: (%d) %s",
		            req, req->setting_name,
		            error->code, error->message ? error->message : "(unknown)");

		/* Try the next agent */
		req->next_callback (req);
	} else {
		/* If the agent obtained the 'modify' permission, we send all system secrets
		 * to it.  If it didn't, we still ask it for secrets, but we don't send
		 * any system secrets.
		 */
		perm = nm_auth_chain_get_data (chain, "perm");
		g_assert (perm);
		result = nm_auth_chain_get_result (chain, perm);
		if (result == NM_AUTH_CALL_RESULT_YES)
			req->current_has_modify = TRUE;

		nm_log_dbg (LOGD_AGENTS, "(%p/%s) agent MODIFY check result %d",
		            req, req->setting_name, result);

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
get_next_cb (Request *req)
{
	NMSettingConnection *s_con;
	const char *agent_dbus_owner, *perm;

	if (!next_generic (req, "getting"))
		return;

	agent_dbus_owner = nm_secret_agent_get_dbus_owner (NM_SECRET_AGENT (req->current));

	/* If the request flags allow user interaction, and there are existing
	 * system secrets (or blank secrets that are supposed to be system-owned),
	 * check whether the agent has the 'modify' permission before sending those
	 * secrets to the agent.  We shouldn't leak system-owned secrets to
	 * unprivileged users.
	 */
	if (   (req->flags != NM_SETTINGS_GET_SECRETS_FLAG_NONE)
	    && (req->existing_secrets || has_system_secrets (req->connection))) {
		nm_log_dbg (LOGD_AGENTS, "(%p/%s) request has system secrets; checking agent %s for MODIFY",
		            req, req->setting_name, agent_dbus_owner);

		req->chain = nm_auth_chain_new_dbus_sender (agent_dbus_owner,
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
		nm_log_dbg (LOGD_AGENTS, "(%p/%s) requesting user-owned secrets from agent %s",
			        req, req->setting_name, agent_dbus_owner);

		get_agent_request_secrets (req, FALSE);
	}
}

static gboolean
get_start (gpointer user_data)
{
	Request *req = user_data;
	GHashTable *setting_secrets = NULL;

	req->idle_id = 0;

	/* Check if there are any existing secrets */
	if (req->existing_secrets)
		setting_secrets = g_hash_table_lookup (req->existing_secrets, req->setting_name);

	if (setting_secrets && g_hash_table_size (setting_secrets)) {
		NMConnection *tmp;
		GError *error = NULL;
		gboolean request_new = (req->flags & NM_SETTINGS_GET_SECRETS_FLAG_REQUEST_NEW);

		/* The connection already had secrets; check if any more are required.
		 * If no more are required, we're done.  If secrets are still needed,
		 * ask a secret agent for more.  This allows admins to provide generic
		 * secrets but allow additional user-specific ones as well.
		 */
		tmp = nm_connection_duplicate (req->connection);
		g_assert (tmp);

		if (!nm_connection_update_secrets (tmp, req->setting_name, req->existing_secrets, &error)) {
			req_complete_error (req, error);
			g_clear_error (&error);
		} else {
			/* Do we have everything we need? */
			if (   (req->flags & NM_SETTINGS_GET_SECRETS_FLAG_ONLY_SYSTEM)
			    || ((nm_connection_need_secrets (tmp, NULL) == NULL) && (request_new == FALSE))) {
				nm_log_dbg (LOGD_AGENTS, "(%p/%s) system settings secrets sufficient",
				            req, req->setting_name);

				/* Got everything, we're done */
				req_complete_success (req, req->existing_secrets, NULL, NULL, FALSE);
			} else {
				nm_log_dbg (LOGD_AGENTS, "(%p/%s) system settings secrets insufficient, asking agents",
				            req, req->setting_name);

				/* We don't, so ask some agents for additional secrets */
				req->next_callback (req);
			}
		}
		g_object_unref (tmp);
	} else {
		/* Couldn't get secrets from system settings, so now we ask the
		 * agents for secrets.  Let the Agent Manager handle which agents
		 * we'll ask and in which order.
		 */
		req->next_callback (req);
	}

	return FALSE;
}

static void
get_complete_cb (Request *req,
                 GHashTable *secrets,
                 const char *agent_dbus_owner,
                 const char *agent_username,
                 gboolean agent_has_modify,
                 GError *error,
                 gpointer user_data)
{
	NMAgentManager *self = NM_AGENT_MANAGER (user_data);
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (self);

	/* Send secrets back to the requesting object */
	req->callback (self,
	               req->reqid,
	               agent_dbus_owner,
	               agent_username,
	               agent_has_modify,
	               req->setting_name,
	               req->flags,
	               error ? NULL : secrets,
	               error,
	               req->callback_data,
	               req->other_data2,
	               req->other_data3);

	g_hash_table_remove (priv->requests, GUINT_TO_POINTER (req->reqid));
}

static void
get_cancel_cb (Request *req)
{
	if (req->current && req->current_call_id)
		nm_secret_agent_cancel_secrets (req->current, req->current_call_id);
}

guint32
nm_agent_manager_get_secrets (NMAgentManager *self,
                              NMConnection *connection,
                              gboolean filter_by_uid,
                              gulong uid_filter,
                              GHashTable *existing_secrets,
                              const char *setting_name,
                              NMSettingsGetSecretsFlags flags,
                              const char *hint,
                              NMAgentSecretsResultFunc callback,
                              gpointer callback_data,
                              gpointer other_data2,
                              gpointer other_data3)
{
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (self);
	Request *req;

	g_return_val_if_fail (self != NULL, 0);
	g_return_val_if_fail (connection != NULL, 0);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), 0);
	g_return_val_if_fail (callback != NULL, 0);

	nm_log_dbg (LOGD_SETTINGS,
	            "Secrets requested for connection %s (%s)",
	            nm_connection_get_path (connection),
	            setting_name);

	/* NOTE: a few things in the Request handling depend on existing_secrets
	 * being NULL if there aren't any system-owned secrets for this connection.
	 * This in turn depends on nm_connection_to_hash() and nm_setting_to_hash()
	 * both returning NULL if they didn't hash anything.
	 */

	req = request_new_get (connection,
	                       filter_by_uid,
	                       uid_filter,
	                       existing_secrets,
	                       setting_name,
	                       flags,
	                       hint,
	                       callback,
	                       callback_data,
	                       other_data2,
	                       other_data3,
	                       get_complete_cb,
	                       self,
	                       get_next_cb,
	                       get_cancel_cb);
	g_hash_table_insert (priv->requests, GUINT_TO_POINTER (req->reqid), req);

	/* Kick off the request */
	if (!(req->flags & NM_SETTINGS_GET_SECRETS_FLAG_ONLY_SYSTEM))
		request_add_agents (self, req);
	req->idle_id = g_idle_add (get_start, req);

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
              gconstpointer call_id,
              GHashTable *secrets,
              GError *error,
              gpointer user_data)
{
	Request *req = user_data;
	const char *agent_dbus_owner;

	g_return_if_fail (call_id == req->current_call_id);

	req->current = NULL;
	req->current_call_id = NULL;

	if (error) {
		nm_log_dbg (LOGD_AGENTS, "(%s) agent failed save secrets request %p/%s: (%d) %s",
		            nm_secret_agent_get_description (agent),
		            req, req->setting_name,
		            error ? error->code : -1,
		            (error && error->message) ? error->message : "(unknown)");

		/* Try the next agent */
		req->next_callback (req);
		return;
	}

	nm_log_dbg (LOGD_AGENTS, "(%s) agent saved secrets for request %p/%s",
	            nm_secret_agent_get_description (agent),
	            req, req->setting_name);

	agent_dbus_owner = nm_secret_agent_get_dbus_owner (agent);
	req_complete_success (req, NULL, NULL, agent_dbus_owner, FALSE);
}

static void
save_next_cb (Request *req)
{
	if (!next_generic (req, "saving"))
		return;

	req->current_call_id = nm_secret_agent_save_secrets (NM_SECRET_AGENT (req->current),
	                                                     req->connection,
	                                                     save_done_cb,
	                                                     req);
	if (req->current_call_id == NULL) {
		/* Shouldn't hit this, but handle it anyway */
		g_warn_if_fail (req->current_call_id != NULL);
		req->current = NULL;
		req->next_callback (req);
	}
}

static void
save_complete_cb (Request *req,
                  GHashTable *secrets,
                  const char *agent_dbus_owner,
                  const char *agent_username,
                  gboolean agent_has_modify,
                  GError *error,
                  gpointer user_data)
{
	NMAgentManager *self = NM_AGENT_MANAGER (user_data);
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (self);

	g_hash_table_remove (priv->requests, GUINT_TO_POINTER (req->reqid));
}

guint32
nm_agent_manager_save_secrets (NMAgentManager *self,
                               NMConnection *connection,
                               gboolean filter_by_uid,
                               gulong uid_filter)
{
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (self);
	Request *req;

	g_return_val_if_fail (self != NULL, 0);
	g_return_val_if_fail (connection != NULL, 0);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), 0);

	nm_log_dbg (LOGD_SETTINGS,
	            "Saving secrets for connection %s",
	            nm_connection_get_path (connection));

	req = request_new_other (connection,
	                         filter_by_uid,
	                         uid_filter,
	                         save_complete_cb,
	                         self,
	                         save_next_cb);
	g_hash_table_insert (priv->requests, GUINT_TO_POINTER (req->reqid), req);

	/* Kick off the request */
	request_add_agents (self, req);
	req->idle_id = g_idle_add (start_generic, req);

	return req->reqid;
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

	req->current = NULL;
	req->current_call_id = NULL;

	if (error) {
		nm_log_dbg (LOGD_AGENTS, "(%s) agent failed delete secrets request %p/%s: (%d) %s",
		            nm_secret_agent_get_description (agent),
		            req, req->setting_name,
		            error ? error->code : -1,
		            (error && error->message) ? error->message : "(unknown)");
	} else {
		nm_log_dbg (LOGD_AGENTS, "(%s) agent deleted secrets for request %p/%s",
		            nm_secret_agent_get_description (agent),
		            req, req->setting_name);
	}

	/* Tell the next agent to delete secrets */
	req->next_callback (req);
}

static void
delete_next_cb (Request *req)
{
	if (!next_generic (req, "deleting"))
		return;

	req->current_call_id = nm_secret_agent_delete_secrets (NM_SECRET_AGENT (req->current),
	                                                       req->connection,
	                                                       delete_done_cb,
	                                                       req);
	if (req->current_call_id == NULL) {
		/* Shouldn't hit this, but handle it anyway */
		g_warn_if_fail (req->current_call_id != NULL);
		req->current = NULL;
		req->next_callback (req);
	}
}

static void
delete_complete_cb (Request *req,
                    GHashTable *secrets,
                    const char *agent_dbus_owner,
                    const char *agent_username,
                    gboolean agent_has_modify,
                    GError *error,
                    gpointer user_data)
{
	NMAgentManager *self = NM_AGENT_MANAGER (user_data);
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (self);

	g_hash_table_remove (priv->requests, GUINT_TO_POINTER (req->reqid));
}

guint32
nm_agent_manager_delete_secrets (NMAgentManager *self,
                                 NMConnection *connection,
                                 gboolean filter_by_uid,
                                 gulong uid_filter)
{
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (self);
	Request *req;

	g_return_val_if_fail (self != NULL, 0);
	g_return_val_if_fail (connection != NULL, 0);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), 0);

	nm_log_dbg (LOGD_SETTINGS,
	            "Deleting secrets for connection %s",
	            nm_connection_get_path (connection));

	req = request_new_other (connection,
	                         filter_by_uid,
	                         uid_filter,
	                         delete_complete_cb,
	                         self,
	                         delete_next_cb);
	g_hash_table_insert (priv->requests, GUINT_TO_POINTER (req->reqid), req);

	/* Kick off the request */
	request_add_agents (self, req);
	req->idle_id = g_idle_add (start_generic, req);

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
	NMAuthCallResult result;

	priv->chains = g_slist_remove (priv->chains, chain);

	agent = nm_auth_chain_get_data (chain, "agent");

	if (error) {
		nm_log_dbg (LOGD_AGENTS, "(%s) failed to request updated agent permissions",
		            nm_secret_agent_get_description (agent));
		nm_secret_agent_add_permission (agent, NM_AUTH_PERMISSION_WIFI_SHARE_PROTECTED, FALSE);
		nm_secret_agent_add_permission (agent, NM_AUTH_PERMISSION_WIFI_SHARE_OPEN, FALSE);
	} else {
		nm_log_dbg (LOGD_AGENTS, "(%s) updated agent permissions",
		            nm_secret_agent_get_description (agent));

		result = nm_auth_chain_get_result (chain, NM_AUTH_PERMISSION_WIFI_SHARE_PROTECTED);
		nm_secret_agent_add_permission (agent,
		                                NM_AUTH_PERMISSION_WIFI_SHARE_PROTECTED,
		                                (result == NM_AUTH_CALL_RESULT_YES));

		result = nm_auth_chain_get_result (chain, NM_AUTH_PERMISSION_WIFI_SHARE_OPEN);
		nm_secret_agent_add_permission (agent,
		                                NM_AUTH_PERMISSION_WIFI_SHARE_OPEN,
		                                (result == NM_AUTH_CALL_RESULT_YES));
	}

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
		const char *sender;

		/* Kick off permissions requests for this agent */
		sender = nm_secret_agent_get_dbus_owner (agent);
		chain = nm_auth_chain_new_dbus_sender (sender, agent_permissions_changed_done, self);

		/* Make sure if the agent quits while the permissions call is in progress
		 * that the object sticks around until our callback.
		 */
		nm_auth_chain_set_data (chain, "agent", g_object_ref (agent), g_object_unref);
		nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_WIFI_SHARE_PROTECTED, FALSE);
		nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_WIFI_SHARE_OPEN, FALSE);

		priv->chains = g_slist_append (priv->chains, chain);
	}
}

/*************************************************************/

NMAgentManager *
nm_agent_manager_get (void)
{
	static NMAgentManager *singleton = NULL;
	NMAgentManagerPrivate *priv;
	DBusGConnection *connection;

	if (singleton)
		return g_object_ref (singleton);

	singleton = (NMAgentManager *) g_object_new (NM_TYPE_AGENT_MANAGER, NULL);
	g_assert (singleton);

	priv = NM_AGENT_MANAGER_GET_PRIVATE (singleton);
	priv->session_monitor = nm_session_monitor_get ();
	priv->dbus_mgr = nm_dbus_manager_get ();

	connection = nm_dbus_manager_get_connection (priv->dbus_mgr);
	dbus_g_connection_register_g_object (connection,
	                                     NM_DBUS_PATH_AGENT_MANAGER,
	                                     G_OBJECT (singleton));

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

		g_slist_foreach (priv->chains, (GFunc) nm_auth_chain_unref, NULL);

		g_hash_table_destroy (priv->agents);
		g_hash_table_destroy (priv->requests);

		g_object_unref (priv->session_monitor);
		g_object_unref (priv->dbus_mgr);
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
