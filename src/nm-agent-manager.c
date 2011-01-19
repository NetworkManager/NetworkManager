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
#include <ctype.h>

#include <glib.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>

#include "NetworkManager.h"
#include "nm-logging.h"
#include "nm-agent-manager.h"
#include "nm-secret-agent.h"
#include "nm-manager-auth.h"
#include "nm-sysconfig-connection.h"
#include "nm-dbus-glib-types.h"

G_DEFINE_TYPE (NMAgentManager, nm_agent_manager, G_TYPE_OBJECT)

#define NM_AGENT_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                         NM_TYPE_AGENT_MANAGER, \
                                         NMAgentManagerPrivate))

typedef struct {
	gboolean disposed;

	NMDBusManager *dbus_mgr;
	NMSessionMonitor *session_monitor;

	/* Hashed by owner name, not identifier, since two agents in different
	 * sessions can use the same identifier.
	 */
	GHashTable *agents;

	GHashTable *requests;
} NMAgentManagerPrivate;

typedef struct _Request Request;

static void request_add_agent (Request *req,
                               NMSecretAgent *agent,
                               NMSessionMonitor *session_monitor);

static void request_remove_agent (Request *req, NMSecretAgent *agent);

static void impl_agent_manager_register (NMAgentManager *self,
                                         const char *identifier,
                                         DBusGMethodInvocation *context);

static void impl_agent_manager_unregister (NMAgentManager *self,
                                           DBusGMethodInvocation *context);

#include "nm-agent-manager-glue.h"

/********************************************************************/

#define NM_AGENT_MANAGER_ERROR         (nm_agent_manager_error_quark ())
#define NM_TYPE_AGENT_MANAGER_ERROR    (nm_agent_manager_error_get_type ())

typedef enum {
	NM_AGENT_MANAGER_ERROR_SENDER_UNKNOWN = 0,
	NM_AGENT_MANAGER_ERROR_PERMISSION_DENIED,
	NM_AGENT_MANAGER_ERROR_SESSION_NOT_FOUND,
	NM_AGENT_MANAGER_ERROR_INVALID_IDENTIFIER,
	NM_AGENT_MANAGER_ERROR_NOT_REGISTERED,
	NM_AGENT_MANAGER_ERROR_INTERNAL_ERROR,
	NM_AGENT_MANAGER_ERROR_NO_SECRETS
} NMAgentManagerError;

static GQuark
nm_agent_manager_error_quark (void)
{
	static GQuark ret = 0;

	if (G_UNLIKELY (ret == 0))
		ret = g_quark_from_static_string ("nm-agent-manager-error");
	return ret;
}

#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

static GType
nm_agent_manager_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Unable to determine caller's sender or UID */
			ENUM_ENTRY (NM_AGENT_MANAGER_ERROR_SENDER_UNKNOWN, "SenderUnknown"),
			/* Permission for some operation was denied */
			ENUM_ENTRY (NM_AGENT_MANAGER_ERROR_PERMISSION_DENIED, "PermissionDenied"),
			/* The caller's session could not be determined */
			ENUM_ENTRY (NM_AGENT_MANAGER_ERROR_SESSION_NOT_FOUND, "SessionNotFound"),
			/* The identifier was invalid */
			ENUM_ENTRY (NM_AGENT_MANAGER_ERROR_INVALID_IDENTIFIER, "InvalidIdentifier"),
			/* Request was not from a registered agent */
			ENUM_ENTRY (NM_AGENT_MANAGER_ERROR_NOT_REGISTERED, "NotRegistered"),
			/* Some internal error occurred */
			ENUM_ENTRY (NM_AGENT_MANAGER_ERROR_INTERNAL_ERROR, "InternalError"),
			/* No secrets were available */
			ENUM_ENTRY (NM_AGENT_MANAGER_ERROR_NO_SECRETS, "NoSecrets"),
			{ 0, 0, 0 }
		};

		etype = g_enum_register_static ("NMAgentManagerError", values);
	}
	return etype;
}

/*************************************************************/

static gboolean
remove_agent (NMAgentManager *self, const char *owner)
{
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (self);
	NMSecretAgent *agent;
	GHashTableIter iter;
	gpointer data;

	g_return_val_if_fail (owner != NULL, FALSE);

	/* Make sure this agent has already registered */
	agent = g_hash_table_lookup (priv->agents, owner);
	if (!agent)
		return FALSE;

	nm_log_dbg (LOGD_AGENTS, "(%s) agent unregistered",
	            nm_secret_agent_get_description (agent));

	/* Remove this agent to any in-progress secrets requests */
	g_hash_table_iter_init (&iter, priv->requests);
	while (g_hash_table_iter_next (&iter, NULL, &data))
		request_remove_agent ((Request *) data, agent);

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
		if (!isalnum (*p) && (*p != '_') && (*p != '-') && (*p != '.')) {
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
impl_agent_manager_register (NMAgentManager *self,
                             const char *identifier,
                             DBusGMethodInvocation *context)
{
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (self);
	char *error_desc = NULL, *sender = NULL;
	gulong sender_uid = G_MAXULONG;
	GError *error = NULL, *local = NULL;
	NMSecretAgent *agent;
	GHashTableIter iter;
	gpointer data;

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

	if (!nm_session_monitor_uid_has_session (priv->session_monitor,
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

	g_hash_table_insert (priv->agents, g_strdup (sender), agent);
	nm_log_dbg (LOGD_AGENTS, "(%s) agent registered",
	            nm_secret_agent_get_description (agent));
	dbus_g_method_return (context);

	/* Add this agent to any in-progress secrets requests */
	g_hash_table_iter_init (&iter, priv->requests);
	while (g_hash_table_iter_next (&iter, NULL, &data))
		request_add_agent ((Request *) data, agent, priv->session_monitor);

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
                                     GError *error,
                                     gpointer user_data);

struct _Request {
	guint32 reqid;

	NMConnection *connection;
	char *setting_name;
	guint32 flags;
	char *hint;

	/* Current agent being asked for secrets */
	NMSecretAgent *current;
	gconstpointer current_call_id;

	/* Stores the sorted list of NMSecretAgents which will be
	 * asked for secrets.
	 */
	GSList *pending;

	/* Stores the list of NMSecretAgent hashes that we've already
	 * asked for secrets, so that we don't ask the same agent twice
	 * if it quits and re-registers during this secrets request.
	 */
	GSList *asked;

	guint32 idle_id;

	GHashTable *settings_secrets;

	NMAgentSecretsResultFunc callback;
	gpointer callback_data;
	gpointer other_data2;
	gpointer other_data3;

	RequestCompleteFunc complete_callback;
	gpointer complete_callback_data;
};

static Request *
request_new (NMConnection *connection,
             const char *setting_name,
             guint32 flags,
             const char *hint,
             NMAgentSecretsResultFunc callback,
             gpointer callback_data,
             gpointer other_data2,
             gpointer other_data3,
             RequestCompleteFunc complete_callback,
             gpointer complete_callback_data)
{
	Request *req;
	static guint32 next_id = 1;

	req = g_malloc0 (sizeof (Request));
	req->reqid = next_id++;
	req->connection = g_object_ref (connection);
	req->setting_name = g_strdup (setting_name);
	req->flags = flags;
	req->hint = g_strdup (hint);
	req->callback = callback;
	req->callback_data = callback_data;
	req->other_data2 = other_data2;
	req->other_data3 = other_data3;
	req->complete_callback = complete_callback;
	req->complete_callback_data = complete_callback_data;

	return req;
}

static void
request_free (Request *req)
{
	if (req->idle_id)
		g_source_remove (req->idle_id);

	if (req->current && req->current_call_id)
		nm_secret_agent_cancel_secrets (req->current, req->current_call_id);

	g_slist_free (req->pending);
	g_slist_free (req->asked);
	g_object_unref (req->connection);
	g_free (req->setting_name);
	g_free (req->hint);
	if (req->settings_secrets)
		g_hash_table_unref (req->settings_secrets);
	memset (req, 0, sizeof (Request));
	g_free (req);
}

static void request_next (Request *req);

static void
destroy_gvalue (gpointer data)
{
	GValue *value = (GValue *) data;

	g_value_unset (value);
	g_slice_free (GValue, value);
}

static void
merge_secrets (GHashTable *src, GHashTable *dest)
{
	GHashTableIter iter;
	gpointer key, data;

	g_hash_table_iter_init (&iter, src);
	while (g_hash_table_iter_next (&iter, &key, &data)) {
		const char *setting_name = key;
		GHashTable *dstsetting;
		GHashTableIter subiter;
		gpointer subkey, subval;

		/* Find the corresponding setting in the merged secrets hash, or create
		 * it if it doesn't exist.
		 */
		dstsetting = g_hash_table_lookup (dest, setting_name);
		if (!dstsetting) {
			dstsetting = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, (GDestroyNotify) destroy_gvalue);
			g_hash_table_insert (dest, (gpointer) setting_name, dstsetting);
		}

		/* And copy in each secret from src */
		g_hash_table_iter_init (&subiter, (GHashTable *) data);
		while (g_hash_table_iter_next (&subiter, &subkey, &subval)) {
			const char *keyname = subkey;
			GValue *srcval = subval, *dstval;

			dstval = g_slice_new0 (GValue);
			g_value_init (dstval, G_VALUE_TYPE (srcval));
			g_value_copy (srcval, dstval);

			g_hash_table_insert (dstsetting, (gpointer) keyname, dstval);
		}
	}
}

static void
request_secrets_done_cb (NMSecretAgent *agent,
                         gconstpointer call_id,
                         GHashTable *secrets,
                         GError *error,
                         gpointer user_data)
{
	Request *req = user_data;
	GHashTable *setting_secrets, *merged;

	g_return_if_fail (call_id == req->current_call_id);

	req->current = NULL;
	req->current_call_id = NULL;

	if (error) {
		nm_log_dbg (LOGD_AGENTS, "(%s) agent failed secrets request %p/%s: (%d) %s",
				    nm_secret_agent_get_description (agent),
				    req, req->setting_name,
				    error ? error->code : -1,
				    (error && error->message) ? error->message : "(unknown)");

		/* Try the next agent */
		request_next (req);
		return;
	}

	/* Ensure the setting we wanted secrets for got returned and has something in it */
	setting_secrets = g_hash_table_lookup (secrets, req->setting_name);
	if (!setting_secrets || !g_hash_table_size (setting_secrets)) {
		nm_log_dbg (LOGD_AGENTS, "(%s) agent returned no secrets for request %p/%s",
				    nm_secret_agent_get_description (agent),
				    req, req->setting_name);

		/* Try the next agent */
		request_next (req);
		return;
	}

	nm_log_dbg (LOGD_AGENTS, "(%s) agent returned secrets for request %p/%s",
			    nm_secret_agent_get_description (agent),
			    req, req->setting_name);

	/* Success! If we got some secrets from the settings service, merge those
	 * with the ones from the secret agent.
	 */
	if (req->settings_secrets) {
		merged = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, (GDestroyNotify) g_hash_table_unref);

		/* Copy agent secrets first, then overwrite with settings secrets */
		merge_secrets (secrets, merged);
		merge_secrets (req->settings_secrets, merged);

		req->complete_callback (req, merged, NULL, req->complete_callback_data);
		g_hash_table_destroy (merged);
	} else
		req->complete_callback (req, secrets, NULL, req->complete_callback_data);
}

static void
request_next (Request *req)
{
	GError *error = NULL;

	if (req->pending == NULL) {
		/* No more secret agents are available to fulfill this secrets request */
		error = g_error_new_literal (NM_AGENT_MANAGER_ERROR,
		                             NM_AGENT_MANAGER_ERROR_NO_SECRETS,
		                             "No secrets were available for this request.");
		req->complete_callback (req, NULL, error, req->complete_callback_data);
		g_error_free (error);
		return;
	}

	/* Send a secrets request to the next agent */
	req->current = req->pending->data;
	req->pending = g_slist_remove (req->pending, req->current);

	nm_log_dbg (LOGD_AGENTS, "(%s) agent getting secrets for request %p/%s",
			    nm_secret_agent_get_description (req->current),
			    req, req->setting_name);

	req->current_call_id = nm_secret_agent_get_secrets (NM_SECRET_AGENT (req->current),
	                                                    req->connection,
	                                                    req->setting_name,
	                                                    req->hint,
	                                                    req->flags,
	                                                    request_secrets_done_cb,
	                                                    req);
	if (req->current_call_id == NULL) {
		/* Shouldn't hit this, but handle it anyway */
		g_warn_if_fail (req->current_call_id != NULL);
		req->current = NULL;
		request_next (req);
	}
}

static gboolean
request_start_secrets (gpointer user_data)
{
	Request *req = user_data;
	GHashTable *secrets, *setting_secrets = NULL;
	GError *error = NULL;

	req->idle_id = 0;

	nm_log_dbg (LOGD_AGENTS, "(%p/%s) getting secrets from system settings",
			    req, req->setting_name);

	secrets = nm_sysconfig_connection_get_secrets (NM_SYSCONFIG_CONNECTION (req->connection),
	                                               req->setting_name,
	                                               req->hint,
	                                               req->flags ? TRUE : FALSE,
	                                               &error);
	if (secrets)
		setting_secrets = g_hash_table_lookup (secrets, req->setting_name);

	if (setting_secrets && g_hash_table_size (setting_secrets)) {
		NMConnection *tmp;

		/* The connection already had secrets; check if any more are required.
		 * If no more are required, we're done.  If secrets are still needed,
		 * ask a secret agent for more.  This allows admins to provide generic
		 * secrets but allow additional user-specific ones as well.
		 */
		tmp = nm_connection_duplicate (req->connection);
		g_assert (tmp);

		if (!nm_connection_update_secrets (tmp, req->setting_name, secrets, &error)) {
			req->complete_callback (req, NULL, error, req->complete_callback_data);
			g_clear_error (&error);
		} else {
			/* Do we have everything we need? */
			/* FIXME: handle second check for VPN connections */
			if (nm_connection_need_secrets (tmp, NULL) == NULL) {
				nm_log_dbg (LOGD_AGENTS, "(%p/%s) system settings secrets sufficient",
						    req, req->setting_name);

				/* Got everything, we're done */
				req->complete_callback (req, secrets, NULL, req->complete_callback_data);
			} else {
				nm_log_dbg (LOGD_AGENTS, "(%p/%s) system settings secrets insufficient, asking agents",
						    req, req->setting_name);

				/* We don't, so ask some agents for additional secrets */
				req->settings_secrets = g_hash_table_ref (secrets);
				request_next (req);
			}
		}
		g_object_unref (tmp);
	} else if (error) {
		nm_log_dbg (LOGD_AGENTS, "(%p/%s) system settings returned error: (%d) %s",
				    req, req->setting_name, error->code, error->message);

		/* Errors from the system settings are hard errors; we don't go on
		 * to ask agents for secrets if the settings service failed.
		 */
		req->complete_callback (req, NULL, error, req->complete_callback_data);
		g_error_free (error);
	} else {
		/* Couldn't get secrets from system settings, so now we ask the
		 * agents for secrets.  Let the Agent Manager handle which agents
		 * we'll ask and in which order.
		 */
		request_next (req);
	}

	if (secrets)
		g_hash_table_unref (secrets);

	return FALSE;
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
	if (0 != agent_uid) {
		if (!nm_auth_uid_in_acl (req->connection, session_monitor, agent_uid, NULL)) {
			nm_log_dbg (LOGD_AGENTS, "(%s) agent ignored for secrets request %p/%s",
					    nm_secret_agent_get_description (agent),
					    req, req->setting_name);
			/* Connection not visible to this agent's user */
			return;
		}
		/* Caller is allowed to add this connection */
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
request_remove_agent (Request *req, NMSecretAgent *agent)
{
	gboolean try_next = FALSE;
	const char *detail = "";

	g_return_if_fail (req != NULL);
	g_return_if_fail (agent != NULL);

	/* If this agent is being asked right now, cancel the request */
	if (agent == req->current) {
		nm_secret_agent_cancel_secrets (req->current, req->current_call_id);
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
		 * we need to ask the next agent for secrets.
		 */
		request_next (req);
	}
}

/*************************************************************/

static void
mgr_req_complete_cb (Request *req,
                     GHashTable *secrets,
                     GError *error,
                     gpointer user_data)
{
	NMAgentManager *self = NM_AGENT_MANAGER (user_data);
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (self);
	GError *local = NULL;

	if (error)
		local = g_error_copy (error);
	else {
		/* Save the secrets into the connection */
		nm_connection_update_secrets (req->connection,
		                              req->setting_name,
		                              secrets,
		                              &local);
	}

	if (local) {
		nm_log_warn (LOGD_SETTINGS,
		             "Failed to %s connection secrets: (%d) %s",
		             error ? "get" : "update",
		             local->code,
		             local->message ? local->message : "(none)");
	}

	/* Call the activation requests' secrets callback */
	req->callback (self,
	               req->reqid,
	               req->connection,
	               local,
	               req->callback_data,
	               req->other_data2,
	               req->other_data3);

	g_hash_table_remove (priv->requests, GUINT_TO_POINTER (req->reqid));
	g_clear_error (&local);
}

guint32
nm_agent_manager_get_secrets (NMAgentManager *self,
                              NMConnection *connection,
                              const char *setting_name,
                              guint32 flags,
                              const char *hint,
                              NMAgentSecretsResultFunc callback,
                              gpointer callback_data,
                              gpointer other_data2,
                              gpointer other_data3)
{
	NMAgentManagerPrivate *priv = NM_AGENT_MANAGER_GET_PRIVATE (self);
	Request *req;
	GHashTableIter iter;
	gpointer data;

	g_return_val_if_fail (self != NULL, 0);
	g_return_val_if_fail (connection != NULL, 0);
	g_return_val_if_fail (NM_IS_SYSCONFIG_CONNECTION (connection), 0);
	g_return_val_if_fail (callback != NULL, 0);

	nm_log_dbg (LOGD_SETTINGS,
	            "Secrets requested for connection %s (%s)",
	            nm_connection_get_path (connection),
	            setting_name);

	req = request_new (connection,
	                   setting_name,
	                   flags,
	                   hint,
	                   callback,
	                   callback_data,
	                   other_data2,
	                   other_data3,
	                   mgr_req_complete_cb,
	                   self);

	g_hash_table_insert (priv->requests, GUINT_TO_POINTER (req->reqid), req);

	/* Add agents to the request */
	g_hash_table_iter_init (&iter, priv->agents);
	while (g_hash_table_iter_next (&iter, NULL, &data))
		request_add_agent (req, NM_SECRET_AGENT (data), priv->session_monitor);

	req->idle_id = g_idle_add (request_start_secrets, req);

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

/*************************************************************/

NMAgentManager *
nm_agent_manager_new (NMDBusManager *dbus_mgr)
{
	NMAgentManager *self;
	NMAgentManagerPrivate *priv;
	DBusGConnection *connection;

	g_return_val_if_fail (dbus_mgr != NULL, NULL);

	self = (NMAgentManager *) g_object_new (NM_TYPE_AGENT_MANAGER, NULL);
	if (self) {
		priv = NM_AGENT_MANAGER_GET_PRIVATE (self);

		priv->session_monitor = nm_session_monitor_get ();
		priv->dbus_mgr = g_object_ref (dbus_mgr);
		connection = nm_dbus_manager_get_connection (dbus_mgr);
		dbus_g_connection_register_g_object (connection, NM_DBUS_PATH_AGENT_MANAGER, G_OBJECT (self));

		g_signal_connect (priv->dbus_mgr,
		                  NM_DBUS_MANAGER_NAME_OWNER_CHANGED,
		                  G_CALLBACK (name_owner_changed_cb),
		                  self);
	}

	return self;
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

	if (priv->disposed)
		return;
	priv->disposed = TRUE;

	g_object_unref (priv->session_monitor);
	g_object_unref (priv->dbus_mgr);

	g_hash_table_destroy (priv->agents);
	g_hash_table_destroy (priv->requests);

	G_OBJECT_CLASS (nm_agent_manager_parent_class)->dispose (object);
}

static void
nm_agent_manager_class_init (NMAgentManagerClass *agent_manager_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (agent_manager_class);

	g_type_class_add_private (agent_manager_class, sizeof (NMAgentManagerPrivate));

	/* virtual methods */
	object_class->dispose = dispose;

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (agent_manager_class),
	                                 &dbus_glib_nm_agent_manager_object_info);

	dbus_g_error_domain_register (NM_AGENT_MANAGER_ERROR,
	                              NM_DBUS_INTERFACE_AGENT_MANAGER,
	                              NM_TYPE_AGENT_MANAGER_ERROR);
}
