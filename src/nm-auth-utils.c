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

#include "nm-glib-aux/nm-c-list.h"
#include "nm-setting-connection.h"
#include "nm-auth-subject.h"
#include "nm-auth-manager.h"
#include "nm-session-monitor.h"

/*****************************************************************************/

struct NMAuthChain {
	GHashTable *data_hash;

	CList auth_call_lst_head;

	GDBusMethodInvocation *context;
	NMAuthSubject *subject;

	NMAuthChainResultFunc done_func;
	gpointer user_data;

	guint32 refcount;

	bool done:1;
};

typedef struct {
	CList auth_call_lst;
	NMAuthChain *chain;
	NMAuthManagerCallId *call_id;
	char *permission;
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
	if (call->call_id)
		nm_auth_manager_check_authorization_cancel (call->call_id);
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

	if (!self->data_hash)
		return NULL;
	tmp = g_hash_table_lookup (self->data_hash, &tag);
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
 * Removes the datum associated with @tag from the chain's data associations,
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

	if (!self->data_hash)
		return NULL;

	tmp = g_hash_table_lookup (self->data_hash, &tag);
	if (!tmp)
		return NULL;

	value = tmp->data;

	/* Make sure the destroy handler isn't called when freeing */
	tmp->destroy = NULL;
	g_hash_table_remove (self->data_hash, tmp);
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

	if (data == NULL) {
		if (self->data_hash)
			g_hash_table_remove (self->data_hash, &tag);
	} else {
		if (!self->data_hash) {
			self->data_hash = g_hash_table_new_full (nm_pstr_hash, nm_pstr_equal,
			                                         NULL, chain_data_free);
		}
		g_hash_table_add (self->data_hash,
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
auth_chain_finish (NMAuthChain *self)
{
	self->done = TRUE;

	/* Ensure we stay alive across the callback */
	nm_assert (self->refcount == 1);
	self->refcount++;
	self->done_func (self, NULL, self->context, self->user_data);
	nm_assert (NM_IN_SET (self->refcount, 1, 2));
	nm_auth_chain_destroy (self);
	return FALSE;
}

static void
auth_call_complete (AuthCall *call)
{
	NMAuthChain *self;

	_ASSERT_call (call);

	self = call->chain;

	nm_assert (!self->done);

	auth_call_free (call);

	if (c_list_is_empty (&self->auth_call_lst_head)) {
		/* we are on an idle-handler or a clean call-stack (non-reentrant). */
		auth_chain_finish (self);
	}
}

static void
pk_call_cb (NMAuthManager *auth_manager,
            NMAuthManagerCallId *call_id,
            gboolean is_authorized,
            gboolean is_challenge,
            GError *error,
            gpointer user_data)
{
	AuthCall *call;
	NMAuthCallResult call_result;

	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	call = user_data;

	nm_assert (call->call_id == call_id);

	call->call_id = NULL;

	call_result = nm_auth_call_result_eval (is_authorized, is_challenge, error);

	nm_auth_chain_set_data (call->chain, call->permission, GUINT_TO_POINTER (call_result), NULL);

	auth_call_complete (call);
}

void
nm_auth_chain_add_call (NMAuthChain *self,
                        const char *permission,
                        gboolean allow_interaction)
{
	AuthCall *call;
	NMAuthManager *auth_manager = nm_auth_manager_get ();

	g_return_if_fail (self);
	g_return_if_fail (self->subject);
	g_return_if_fail (!self->done);
	g_return_if_fail (permission && *permission);
	g_return_if_fail (nm_auth_subject_is_unix_process (self->subject) || nm_auth_subject_is_internal (self->subject));

	call = g_slice_new0 (AuthCall);
	call->chain = self;
	call->permission = g_strdup (permission);
	c_list_link_tail (&self->auth_call_lst_head, &call->auth_call_lst);
	call->call_id = nm_auth_manager_check_authorization (auth_manager,
	                                                     self->subject,
	                                                     permission,
	                                                     allow_interaction,
	                                                     pk_call_cb,
	                                                     call);
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
	self->done_func = done_func;
	self->user_data = user_data;
	self->context = context ? g_object_ref (context) : NULL;
	self->subject = g_object_ref (subject);
	return self;
}

/**
 * nm_auth_chain_destroy:
 * @self: the auth-chain
 *
 * Destroys the auth-chain. By destroying the auth-chain, you also cancel
 * the receipt of the done-callback. IOW, the callback will not be invoked.
 *
 * The only exception is, if may call nm_auth_chain_destroy() from inside
 * the callback. In this case, @self stays alive until the callback returns.
 *
 * Note that you might only destroy an auth-chain exactly once, and never
 * after the callback was handled.
 */
void
nm_auth_chain_destroy (NMAuthChain *self)
{
	AuthCall *call;

	g_return_if_fail (self);
	g_return_if_fail (NM_IN_SET (self->refcount, 1, 2));

	if (--self->refcount > 0)
		return;

	nm_clear_g_object (&self->subject);
	nm_clear_g_object (&self->context);

	while ((call = c_list_first_entry (&self->auth_call_lst_head, AuthCall, auth_call_lst)))
		auth_call_free (call);

	nm_clear_pointer (&self->data_hash, g_hash_table_destroy);

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
		NM_SET_OUT (out_error_desc,
		            g_strdup_printf ("Could not determine username for uid %lu", uid));
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
		NM_SET_OUT (out_error_desc,
		            g_strdup_printf ("uid %lu has no permission to perform this operation", uid));
		return FALSE;
	}

	return TRUE;
}

gboolean
nm_auth_is_subject_in_acl_set_error (NMConnection *connection,
                                     NMAuthSubject *subject,
                                     GQuark err_domain,
                                     int err_code,
                                     GError **error)
{
	char *error_desc = NULL;

	nm_assert (!error || !*error);

	if (nm_auth_is_subject_in_acl (connection,
	                               subject,
	                               error ? &error_desc : NULL))
		return TRUE;

	g_set_error_literal (error, err_domain, err_code, error_desc);
	g_free (error_desc);
	return FALSE;
}
