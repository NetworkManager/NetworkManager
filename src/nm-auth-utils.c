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

#include "nm-utils/nm-c-list.h"

#include "nm-setting-connection.h"
#include "nm-auth-subject.h"
#include "nm-auth-manager.h"
#include "nm-session-monitor.h"

/*****************************************************************************/

struct NMAuthChain {
	GHashTable *data;

	CList auth_call_lst_head;

	GDBusMethodInvocation *context;
	NMAuthSubject *subject;
	GError *error;

	NMAuthChainResultFunc done_func;
	gpointer user_data;

	guint idle_id;

	guint32 refcount;

	bool done:1;
};

typedef struct {
	CList auth_call_lst;
	NMAuthChain *chain;
	GCancellable *cancellable;
	char *permission;
	guint call_idle_id;
} AuthCall;

/*****************************************************************************/

static void
_ASSERT_call (AuthCall *call)
{
	nm_assert (call);
	nm_assert (call->chain);
	nm_assert (nm_c_list_contains_entry (&call->chain->auth_call_lst_head, call, auth_call_lst));
}

/*****************************************************************************/

static void
auth_call_free (AuthCall *call)
{
	nm_clear_g_source (&call->call_idle_id);
	nm_clear_g_cancellable (&call->cancellable);
	c_list_unlink_stale (&call->auth_call_lst);
	g_free (call->permission);
	g_slice_free (AuthCall, call);
}

/*****************************************************************************/

typedef struct {

	/* must be the first field. */
	const char *tag;

	gpointer data;
	GDestroyNotify destroy;
	char tag_data[];
} ChainData;

static ChainData *
chain_data_new (const char *tag, gpointer data, GDestroyNotify destroy)
{
	ChainData *tmp;
	gsize l = strlen (tag);

	tmp = g_malloc (sizeof (ChainData) + l + 1);
	tmp->tag = &tmp->tag_data[0];
	tmp->data = data;
	tmp->destroy = destroy;
	memcpy (&tmp->tag_data[0], tag, l + 1);
	return tmp;
}

static void
chain_data_free (gpointer data)
{
	ChainData *tmp = data;

	if (tmp->destroy)
		tmp->destroy (tmp->data);
	g_free (tmp);
}

static gpointer
_get_data (NMAuthChain *self, const char *tag)
{
	ChainData *tmp;

	tmp = g_hash_table_lookup (self->data, &tag);
	return tmp ? tmp->data : NULL;
}

gpointer
nm_auth_chain_get_data (NMAuthChain *self, const char *tag)
{
	g_return_val_if_fail (self, NULL);
	g_return_val_if_fail (tag, NULL);

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

	g_return_val_if_fail (self, NULL);
	g_return_val_if_fail (tag, NULL);

	tmp = g_hash_table_lookup (self->data, &tag);
	if (!tmp)
		return NULL;

	value = tmp->data;

	/* Make sure the destroy handler isn't called when freeing */
	tmp->destroy = NULL;
	g_hash_table_remove (self->data, &tag);
	return value;
}

void
nm_auth_chain_set_data (NMAuthChain *self,
                        const char *tag,
                        gpointer data,
                        GDestroyNotify data_destroy)
{
	g_return_if_fail (self);
	g_return_if_fail (tag);

	if (data == NULL)
		g_hash_table_remove (self->data, &tag);
	else {
		g_hash_table_add (self->data,
		                  chain_data_new (tag, data, data_destroy));
	}
}

/*****************************************************************************/

NMAuthCallResult
nm_auth_chain_get_result (NMAuthChain *self, const char *permission)
{
	gpointer data;

	g_return_val_if_fail (self, NM_AUTH_CALL_RESULT_UNKNOWN);
	g_return_val_if_fail (permission, NM_AUTH_CALL_RESULT_UNKNOWN);

	data = _get_data (self, permission);
	return data ? GPOINTER_TO_UINT (data) : NM_AUTH_CALL_RESULT_UNKNOWN;
}

NMAuthSubject *
nm_auth_chain_get_subject (NMAuthChain *self)
{
	g_return_val_if_fail (self, NULL);

	return self->subject;
}

/*****************************************************************************/

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

static void
auth_call_complete (AuthCall *call)
{
	NMAuthChain *self;

	_ASSERT_call (call);

	self = call->chain;

	c_list_unlink (&call->auth_call_lst);

	if (c_list_is_empty (&self->auth_call_lst_head)) {
		nm_assert (!self->idle_id && !self->done);
		self->idle_id = g_idle_add (auth_chain_finish, self);
	}

	auth_call_free (call);
}

static gboolean
auth_call_complete_idle_cb (gpointer user_data)
{
	AuthCall *call = user_data;

	_ASSERT_call (call);

	call->call_idle_id = 0;
	auth_call_complete (call);
	return G_SOURCE_REMOVE;
}

#if WITH_POLKIT
static void
pk_call_cb (GObject *object, GAsyncResult *result, gpointer user_data)
{
	AuthCall *call;
	gs_free_error GError *error = NULL;
	gboolean is_authorized = FALSE, is_challenge = FALSE;
	guint call_result = NM_AUTH_CALL_RESULT_UNKNOWN;

	nm_auth_manager_polkit_authority_check_authorization_finish (NM_AUTH_MANAGER (object),
	                                                             result,
	                                                             &is_authorized,
	                                                             &is_challenge,
	                                                             &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		nm_log_dbg (LOGD_CORE, "callback already cancelled");
		return;
	}

	call = user_data;

	g_clear_object (&call->cancellable);

	if (error) {
		/* Don't ruin the chain. Just leave the result unknown. */
		nm_log_warn (LOGD_CORE, "error requesting auth for %s: %s",
		             call->permission, error->message);
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

	g_return_if_fail (self);
	g_return_if_fail (permission && *permission);
	g_return_if_fail (self->subject);
	g_return_if_fail (nm_auth_subject_is_unix_process (self->subject) || nm_auth_subject_is_internal (self->subject));
	g_return_if_fail (!self->idle_id && !self->done);

	call = g_slice_new0 (AuthCall);
	call->chain = self;
	call->permission = g_strdup (permission);
	c_list_link_tail (&self->auth_call_lst_head, &call->auth_call_lst);

	if (   nm_auth_subject_is_internal (self->subject)
	    || nm_auth_subject_get_unix_process_uid (self->subject) == 0
	    || !nm_auth_manager_get_polkit_enabled (auth_manager)) {
		/* Root user or non-polkit always gets the permission */
		nm_auth_chain_set_data (self, permission, GUINT_TO_POINTER (NM_AUTH_CALL_RESULT_YES), NULL);
		call->call_idle_id = g_idle_add (auth_call_complete_idle_cb, call);
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
		call->call_idle_id = g_idle_add (auth_call_complete_idle_cb, call);
#endif
	}
}

/*****************************************************************************/

/* Creates the NMAuthSubject automatically */
NMAuthChain *
nm_auth_chain_new_context (GDBusMethodInvocation *context,
                           NMAuthChainResultFunc done_func,
                           gpointer user_data)
{
	NMAuthSubject *subject;
	NMAuthChain *chain;

	g_return_val_if_fail (context, NULL);

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
	nm_assert (nm_auth_subject_is_unix_process (subject) || nm_auth_subject_is_internal (subject));

	self = g_slice_new0 (NMAuthChain);
	c_list_init (&self->auth_call_lst_head);
	self->refcount = 1;
	self->data = g_hash_table_new_full (nm_pstr_hash, nm_pstr_equal, NULL, chain_data_free);
	self->done_func = done_func;
	self->user_data = user_data;
	self->context = context ? g_object_ref (context) : NULL;
	self->subject = g_object_ref (subject);
	return self;
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
	AuthCall *call;

	g_return_if_fail (self);
	g_return_if_fail (self->refcount > 0);

	if (--self->refcount > 0)
		return;

	nm_clear_g_source (&self->idle_id);

	nm_clear_g_object (&self->subject);
	nm_clear_g_object (&self->context);

	while ((call = c_list_first_entry (&self->auth_call_lst_head, AuthCall, auth_call_lst)))
		auth_call_free (call);

	g_clear_error (&self->error);
	nm_clear_pointer (&self->data, g_hash_table_destroy);

	g_slice_free (NMAuthChain, self);
}

/******************************************************************************
 * utils
 *****************************************************************************/

gboolean
nm_auth_is_subject_in_acl (NMConnection *connection,
                           NMAuthSubject *subject,
                           char **out_error_desc)
{
	NMSettingConnection *s_con;
	const char *user = NULL;
	gulong uid;

	g_return_val_if_fail (connection, FALSE);
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
