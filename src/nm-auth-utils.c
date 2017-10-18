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
 * Copyright (C) 2010 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-auth-utils.h"

#include <string.h>

#include "nm-utils/nm-hash-utils.h"
#include "nm-setting-connection.h"
#include "nm-auth-subject.h"
#include "nm-auth-manager.h"
#include "nm-session-monitor.h"

struct NMAuthChain {
	guint32 refcount;
	GSList *calls;
	GHashTable *data;

	GDBusMethodInvocation *context;
	NMAuthSubject *subject;
	GError *error;

	guint idle_id;
	gboolean done;

	NMAuthChainResultFunc done_func;
	gpointer user_data;
};

typedef struct {
	NMAuthChain *chain;
	GCancellable *cancellable;
	char *permission;
	guint call_idle_id;
} AuthCall;

typedef struct {
	gpointer data;
	GDestroyNotify destroy;
} ChainData;

static ChainData *
chain_data_new (gpointer data, GDestroyNotify destroy)
{
	ChainData *tmp;

	tmp = g_slice_new (ChainData);
	tmp->data = data;
	tmp->destroy = destroy;
	return tmp;
}

static void
chain_data_free (gpointer data)
{
	ChainData *tmp = data;

	if (tmp->destroy)
		tmp->destroy (tmp->data);
	memset (tmp, 0, sizeof (ChainData));
	g_slice_free (ChainData, tmp);
}

static gboolean
auth_chain_finish (gpointer user_data)
{
	NMAuthChain *self = user_data;

	self->idle_id = 0;
	self->done = TRUE;

	/* Ensure we stay alive across the callback */
	self->refcount++;
	self->done_func (self, self->error, self->context, self->user_data);
	nm_auth_chain_unref (self);
	return FALSE;
}

/* Creates the NMAuthSubject automatically */
NMAuthChain *
nm_auth_chain_new_context (GDBusMethodInvocation *context,
                           NMAuthChainResultFunc done_func,
                           gpointer user_data)
{
	NMAuthSubject *subject;
	NMAuthChain *chain;

	g_return_val_if_fail (context != NULL, NULL);

	subject = nm_auth_subject_new_unix_process_from_context (context);
	if (!subject)
		return NULL;

	chain = nm_auth_chain_new_subject (subject,
	                                   context,
	                                   done_func,
	                                   user_data);
	g_object_unref (subject);
	return chain;
}

/* Requires an NMAuthSubject */
NMAuthChain *
nm_auth_chain_new_subject (NMAuthSubject *subject,
                           GDBusMethodInvocation *context,
                           NMAuthChainResultFunc done_func,
                           gpointer user_data)
{
	NMAuthChain *self;

	g_return_val_if_fail (NM_IS_AUTH_SUBJECT (subject), NULL);
	g_return_val_if_fail (nm_auth_subject_is_unix_process (subject) || nm_auth_subject_is_internal (subject), NULL);

	self = g_slice_new0 (NMAuthChain);
	self->refcount = 1;
	self->data = g_hash_table_new_full (nm_str_hash, g_str_equal, g_free, chain_data_free);
	self->done_func = done_func;
	self->user_data = user_data;
	self->context = context ? g_object_ref (context) : NULL;
	self->subject = g_object_ref (subject);

	return self;
}

static gpointer
_get_data (NMAuthChain *self, const char *tag)
{
	ChainData *tmp;

	tmp = g_hash_table_lookup (self->data, tag);
	return tmp ? tmp->data : NULL;
}

gpointer
nm_auth_chain_get_data (NMAuthChain *self, const char *tag)
{
	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (tag != NULL, NULL);

	return _get_data (self, tag);
}

/**
 * nm_auth_chain_steal_data:
 * @self: A #NMAuthChain.
 * @tag: A "tag" uniquely identifying the data to steal.
 *
 * Removes the datum assocated with @tag from the chain's data associations,
 * without invoking the association's destroy handler.  The caller assumes
 * ownership over the returned value.
 *
 * Returns: the datum originally associated with @tag
 */
gpointer
nm_auth_chain_steal_data (NMAuthChain *self, const char *tag)
{
	ChainData *tmp;
	gpointer value = NULL;
	void *orig_key;

	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (tag != NULL, NULL);

	if (g_hash_table_lookup_extended (self->data, tag, &orig_key, (gpointer)&tmp)) {
		g_hash_table_steal (self->data, tag);
		value = tmp->data;
		/* Make sure the destroy handler isn't called when freeing */
		tmp->destroy = NULL;
		chain_data_free (tmp);
		g_free (orig_key);
	}
	return value;
}

void
nm_auth_chain_set_data (NMAuthChain *self,
                        const char *tag,
                        gpointer data,
                        GDestroyNotify data_destroy)
{
	g_return_if_fail (self != NULL);
	g_return_if_fail (tag != NULL);

	if (data == NULL)
		g_hash_table_remove (self->data, tag);
	else {
		g_hash_table_insert (self->data,
		                     g_strdup (tag),
		                     chain_data_new (data, data_destroy));
	}
}

gulong
nm_auth_chain_get_data_ulong (NMAuthChain *self, const char *tag)
{
	gulong *data;

	g_return_val_if_fail (self != NULL, 0);
	g_return_val_if_fail (tag != NULL, 0);

	data = _get_data (self, tag);
	return data ? *data : 0ul;
}

void
nm_auth_chain_set_data_ulong (NMAuthChain *self,
                              const char *tag,
                              gulong data)
{
	gulong *ptr;

	g_return_if_fail (self != NULL);
	g_return_if_fail (tag != NULL);

	ptr = g_malloc (sizeof (*ptr));
	*ptr = data;
	nm_auth_chain_set_data (self, tag, ptr, g_free);
}

NMAuthSubject *
nm_auth_chain_get_subject (NMAuthChain *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return self->subject;
}

NMAuthCallResult
nm_auth_chain_get_result (NMAuthChain *self, const char *permission)
{
	gpointer data;

	g_return_val_if_fail (self != NULL, NM_AUTH_CALL_RESULT_UNKNOWN);
	g_return_val_if_fail (permission != NULL, NM_AUTH_CALL_RESULT_UNKNOWN);

	data = _get_data (self, permission);
	return data ? GPOINTER_TO_UINT (data) : NM_AUTH_CALL_RESULT_UNKNOWN;
}

static AuthCall *
auth_call_new (NMAuthChain *chain, const char *permission)
{
	AuthCall *call;

	call = g_slice_new0 (AuthCall);
	call->chain = chain;
	call->permission = g_strdup (permission);
	return call;
}

static void
auth_call_free (AuthCall *call)
{
	g_free (call->permission);
	g_clear_object (&call->cancellable);
	g_slice_free (AuthCall, call);
}

static gboolean
auth_call_complete (AuthCall *call)
{
	NMAuthChain *self;

	g_return_val_if_fail (call, G_SOURCE_REMOVE);

	self = call->chain;

	g_return_val_if_fail (self, G_SOURCE_REMOVE);
	g_return_val_if_fail (g_slist_find (self->calls, call), G_SOURCE_REMOVE);

	self->calls = g_slist_remove (self->calls, call);

	if (!self->calls) {
		g_assert (!self->idle_id && !self->done);
		self->idle_id = g_idle_add (auth_chain_finish, self);
	}
	auth_call_free (call);
	return FALSE;
}

static void
auth_call_cancel (gpointer user_data)
{
	AuthCall *call = user_data;

	if (nm_clear_g_cancellable (&call->cancellable)) {
		/* we don't free call immediately. Instead we cancel the async operation
		 * and set cancellable to NULL. pk_call_cb() will check for this and
		 * do the final cleanup. */
	} else {
		g_source_remove (call->call_idle_id);
		auth_call_free (call);
	}
}

#if WITH_POLKIT
static void
pk_call_cb (GObject *object, GAsyncResult *result, gpointer user_data)
{
	AuthCall *call = user_data;
	GError *error = NULL;
	gboolean is_authorized = FALSE, is_challenge = FALSE;
	guint call_result = NM_AUTH_CALL_RESULT_UNKNOWN;

	nm_auth_manager_polkit_authority_check_authorization_finish (NM_AUTH_MANAGER (object),
	                                                             result,
	                                                             &is_authorized,
	                                                             &is_challenge,
	                                                             &error);

	/* If the call is already canceled do nothing */
	if (!call->cancellable) {
		nm_log_dbg (LOGD_CORE, "callback already cancelled");
		g_clear_error (&error);
		auth_call_free (call);
		return;
	}

	if (error) {
		/* Don't ruin the chain. Just leave the result unknown. */
		nm_log_warn (LOGD_CORE, "error requesting auth for %s: %s",
		             call->permission, error->message);
		g_clear_error (&error);
	} else {
		if (is_authorized) {
			/* Caller has the permission */
			call_result = NM_AUTH_CALL_RESULT_YES;
		} else if (is_challenge) {
			/* Caller could authenticate to get the permission */
			call_result = NM_AUTH_CALL_RESULT_AUTH;
		} else
			call_result = NM_AUTH_CALL_RESULT_NO;
	}

	nm_auth_chain_set_data (call->chain, call->permission, GUINT_TO_POINTER (call_result), NULL);

	auth_call_complete (call);
}
#endif

void
nm_auth_chain_add_call (NMAuthChain *self,
                        const char *permission,
                        gboolean allow_interaction)
{
	AuthCall *call;
	NMAuthManager *auth_manager = nm_auth_manager_get ();

	g_return_if_fail (self != NULL);
	g_return_if_fail (permission && *permission);
	g_return_if_fail (self->subject);
	g_return_if_fail (nm_auth_subject_is_unix_process (self->subject) || nm_auth_subject_is_internal (self->subject));
	g_return_if_fail (!self->idle_id && !self->done);

	call = auth_call_new (self, permission);
	self->calls = g_slist_append (self->calls, call);

	if (   nm_auth_subject_is_internal (self->subject)
	    || nm_auth_subject_get_unix_process_uid (self->subject) == 0
	    || !nm_auth_manager_get_polkit_enabled (auth_manager)) {
		/* Root user or non-polkit always gets the permission */
		nm_auth_chain_set_data (self, permission, GUINT_TO_POINTER (NM_AUTH_CALL_RESULT_YES), NULL);
		call->call_idle_id = g_idle_add ((GSourceFunc) auth_call_complete, call);
	} else {
		/* Non-root always gets authenticated when using polkit */
#if WITH_POLKIT
		call->cancellable = g_cancellable_new ();
		nm_auth_manager_polkit_authority_check_authorization (auth_manager,
		                                                      self->subject,
		                                                      permission,
		                                                      allow_interaction,
		                                                      call->cancellable,
		                                                      pk_call_cb,
		                                                      call);
#else
		if (!call->chain->error) {
			call->chain->error = g_error_new_literal (NM_MANAGER_ERROR,
			                                          NM_MANAGER_ERROR_FAILED,
			                                          "Polkit support is disabled at compile time");
		}
		call->call_idle_id = g_idle_add ((GSourceFunc) auth_call_complete, call);
#endif
	}
}

/**
 * nm_auth_chain_unref:
 * @self: the auth-chain
 *
 * Unrefs the auth-chain. By unrefing the auth-chain, you also cancel
 * the receipt of the done-callback. IOW, the callback will not be invoked.
 *
 * The only exception is, if you call nm_auth_chain_unref() from inside
 * the callback. In this case, @self stays alive until the callback returns.
 */
void
nm_auth_chain_unref (NMAuthChain *self)
{
	g_return_if_fail (self != NULL);
	g_return_if_fail (self->refcount > 0);

	self->refcount--;
	if (self->refcount > 0)
		return;

	if (self->idle_id)
		g_source_remove (self->idle_id);

	g_object_unref (self->subject);

	if (self->context)
		g_object_unref (self->context);

	g_slist_free_full (self->calls, auth_call_cancel);

	g_clear_error (&self->error);
	g_hash_table_destroy (self->data);

	memset (self, 0, sizeof (NMAuthChain));
	g_slice_free (NMAuthChain, self);
}

/************ utils **************/

gboolean
nm_auth_is_subject_in_acl (NMConnection *connection,
                           NMAuthSubject *subject,
                           char **out_error_desc)
{
	NMSettingConnection *s_con;
	const char *user = NULL;
	gulong uid;

	g_return_val_if_fail (connection != NULL, FALSE);
	g_return_val_if_fail (NM_IS_AUTH_SUBJECT (subject), FALSE);
	g_return_val_if_fail (nm_auth_subject_is_internal (subject) || nm_auth_subject_is_unix_process (subject), FALSE);

	if (nm_auth_subject_is_internal (subject))
		return TRUE;

	uid = nm_auth_subject_get_unix_process_uid (subject);

	/* Root gets a free pass */
	if (0 == uid)
		return TRUE;

	if (!nm_session_monitor_uid_to_user (uid, &user)) {
		if (out_error_desc)
			*out_error_desc = g_strdup_printf ("Could not determine username for uid %lu", uid);
		return FALSE;
	}

	s_con = nm_connection_get_setting_connection (connection);
	if (!s_con) {
		/* This can only happen when called from AddAndActivate, so we know
		 * the user will be authorized when the connection is completed.
		 */
		return TRUE;
	}

	/* Match the username returned by the session check to a user in the ACL */
	if (!nm_setting_connection_permissions_user_allowed (s_con, user)) {
		if (out_error_desc)
			*out_error_desc = g_strdup_printf ("uid %lu has no permission to perform this operation", uid);
		return FALSE;
	}

	return TRUE;
}


