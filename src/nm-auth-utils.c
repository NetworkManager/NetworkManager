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

	CList parent_lst;

	CList data_lst_head;

	CList auth_call_lst_head;

	GDBusMethodInvocation *context;
	NMAuthSubject *subject;

	NMAuthChainResultFunc done_func;
	gpointer user_data;

	guint num_pending_auth_calls;

	bool is_destroyed:1;
	bool is_finishing:1;
};

G_STATIC_ASSERT (G_STRUCT_OFFSET (NMAuthChain, parent_lst) == 0);

typedef struct {
	CList auth_call_lst;
	NMAuthChain *chain;
	NMAuthManagerCallId *call_id;
	const char *permission;
	NMAuthCallResult result;
} AuthCall;

/*****************************************************************************/

static void _auth_chain_destroy (NMAuthChain *self);

/*****************************************************************************/

static void
_ASSERT_call (AuthCall *call)
{
	nm_assert (call);
	nm_assert (call->chain);
	nm_assert (call->permission && strlen (call->permission) > 0);
	nm_assert (nm_c_list_contains_entry (&call->chain->auth_call_lst_head, call, auth_call_lst));
#if NM_MORE_ASSERTS > 5
	{
		AuthCall *auth_call;
		guint n = 0;

		c_list_for_each_entry (auth_call, &call->chain->auth_call_lst_head, auth_call_lst) {
			nm_assert (   auth_call->result == NM_AUTH_CALL_RESULT_UNKNOWN
			           || !auth_call->call_id);
			if (auth_call->call_id)
				n++;
		}
		nm_assert (n == call->chain->num_pending_auth_calls);
	}
#endif
}

/*****************************************************************************/

static void
auth_call_free (AuthCall *call)
{
	_ASSERT_call (call);

	c_list_unlink_stale (&call->auth_call_lst);
	if (call->call_id) {
		call->chain->num_pending_auth_calls--;
		nm_auth_manager_check_authorization_cancel (call->call_id);
	}
	g_slice_free (AuthCall, call);
}

static AuthCall *
_find_auth_call (NMAuthChain *self, const char *permission)
{
	AuthCall *auth_call;

	c_list_for_each_entry (auth_call, &self->auth_call_lst_head, auth_call_lst) {
		if (nm_streq (auth_call->permission, permission))
			return auth_call;
	}
	return NULL;
}

/*****************************************************************************/

typedef struct {
	CList data_lst;
	const char *tag;
	gpointer data;
	GDestroyNotify destroy;
} ChainData;

static void
chain_data_free (ChainData *chain_data)
{
	c_list_unlink_stale (&chain_data->data_lst);
	if (chain_data->destroy)
		chain_data->destroy (chain_data->data);
	g_slice_free (ChainData, chain_data);
}

static ChainData *
_get_data (NMAuthChain *self, const char *tag)
{
	ChainData *chain_data;

	c_list_for_each_entry (chain_data, &self->data_lst_head, data_lst) {
		if (nm_streq (chain_data->tag, tag))
			return chain_data;
	}
	return NULL;
}

gpointer
nm_auth_chain_get_data (NMAuthChain *self, const char *tag)
{
	ChainData *chain_data;

	g_return_val_if_fail (self, NULL);
	g_return_val_if_fail (tag, NULL);

	chain_data = _get_data (self, tag);
	return chain_data ? chain_data->data : NULL;
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
	ChainData *chain_data;
	gpointer value;

	g_return_val_if_fail (self, NULL);
	g_return_val_if_fail (tag, NULL);

	chain_data = _get_data (self, tag);
	if (!chain_data)
		return NULL;

	value = chain_data->data;

	/* Make sure the destroy handler isn't called when freeing */
	chain_data->destroy = NULL;
	chain_data_free (chain_data);
	return value;
}

/**
 * nm_auth_chain_set_data_unsafe:
 * @self: the #NMAuthChain
 * @tag: the tag for referencing the attached data.
 * @data: the data to attach. If %NULL, this call has no effect
 *   and nothing is attached.
 * @data_destroy: (allow-none): the destroy function for the data pointer.
 *
 * @tag string is not cloned and must outlife @self. That is why
 * the function is "unsafe". Use nm_auth_chain_set_data() with a C literal
 * instead.
 *
 * It is a bug to add the same tag more than once.
 */
void
nm_auth_chain_set_data_unsafe (NMAuthChain *self,
                               const char *tag,
                               gpointer data,
                               GDestroyNotify data_destroy)
{
	ChainData *chain_data;

	g_return_if_fail (self);
	g_return_if_fail (tag);

	/* we should not track a large number of elements via a linked list. If this becomes
	 * necessary, revert the code to use GHashTable again. */
	nm_assert (c_list_length (&self->data_lst_head) < 25);

	/* The tag must not yet exist. Otherwise we'd have to first search the linked
	 * list for an existing entry. */
	nm_assert (!_get_data (self, tag));

	if (!data) {
		/* we don't track user data of %NULL.
		 *
		 * In the past this had also the meaning of removing a user-data. But since
		 * nm_auth_chain_set_data() does not allow being called more than once
		 * for the same tag, we don't need to remove anything. */
		return;
	}

	chain_data = g_slice_new (ChainData);
	*chain_data = (ChainData) {
		.tag     = tag,
		.data    = data,
		.destroy = data_destroy,
	};

	/* we assert that no duplicate tags are added. But still, add the new
	 * element to the front, so that it would shadow the duplicate element
	 * in the list. */
	c_list_link_front (&self->data_lst_head, &chain_data->data_lst);
}

/*****************************************************************************/

NMAuthCallResult
nm_auth_chain_get_result (NMAuthChain *self, const char *permission)
{
	AuthCall *auth_call;

	g_return_val_if_fail (self, NM_AUTH_CALL_RESULT_UNKNOWN);
	g_return_val_if_fail (permission, NM_AUTH_CALL_RESULT_UNKNOWN);

	/* it is a bug to request the result other than from the done_func()
	 * callback. You are not supposed to poll for the result but request
	 * it upon notification. */
	nm_assert (self->is_finishing);

	auth_call = _find_auth_call (self, permission);

	/* it is a bug to request a permission result that was not
	 * previously requested or which did not complete yet. */
	if (!auth_call)
		g_return_val_if_reached (NM_AUTH_CALL_RESULT_UNKNOWN);

	nm_assert (!auth_call->call_id);

	return auth_call->result;
}

NMAuthSubject *
nm_auth_chain_get_subject (NMAuthChain *self)
{
	g_return_val_if_fail (self, NULL);

	return self->subject;
}

/*****************************************************************************/

static void
pk_call_cb (NMAuthManager *auth_manager,
            NMAuthManagerCallId *call_id,
            gboolean is_authorized,
            gboolean is_challenge,
            GError *error,
            gpointer user_data)
{
	NMAuthChain *self;
	AuthCall *call;

	nm_assert (call_id);

	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	call = user_data;

	_ASSERT_call (call);
	nm_assert (call->call_id == call_id);
	nm_assert (call->result == NM_AUTH_CALL_RESULT_UNKNOWN);

	self = call->chain;

	nm_assert (!self->is_destroyed);
	nm_assert (!self->is_finishing);

	call->call_id = NULL;

	call->result = nm_auth_call_result_eval (is_authorized, is_challenge, error);

	call->chain->num_pending_auth_calls--;

	_ASSERT_call (call);

	if (call->chain->num_pending_auth_calls == 0) {
		/* we are on an idle-handler or a clean call-stack (non-reentrant) so it's safe
		 * to invoke the callback right away. */
		self->is_finishing = TRUE;
		self->done_func (self, self->context, self->user_data);
		nm_assert (self->is_finishing);
		_auth_chain_destroy (self);
	}
}

/**
 * nm_auth_chain_add_call_unsafe:
 * @self: the #NMAuthChain
 * @permission: the permission string. This string is kept by reference
 *   and you must make sure that it's lifetime lasts until the NMAuthChain
 *   gets destroyed. That's why the function is "unsafe". Use
 *   nm_auth_chain_add_call() instead.
 * @allow_interaction: flag
 *
 * It's "unsafe" because @permission is not copied. It's the callers responsibility
 * that the permission string stays valid as long as NMAuthChain.
 *
 * If you can, use nm_auth_chain_add_call() instead!
 *
 * If you have a non-static string, you may attach the permission string as
 * user-data via nm_auth_chain_set_data().
 */
void
nm_auth_chain_add_call_unsafe (NMAuthChain *self,
                               const char *permission,
                               gboolean allow_interaction)
{
	AuthCall *call;

	g_return_if_fail (self);
	g_return_if_fail (self->subject);
	g_return_if_fail (!self->is_finishing);
	g_return_if_fail (!self->is_destroyed);
	g_return_if_fail (permission && *permission);
	nm_assert (   nm_auth_subject_is_unix_process (self->subject)
	           || nm_auth_subject_is_internal (self->subject));

	/* duplicate permissions are not supported, also because nm_auth_chain_get_result()
	 * can only return one-permission. */
	nm_assert (!_find_auth_call (self, permission));

	call = g_slice_new (AuthCall);

	*call = (AuthCall) {
		.chain      = self,
		.call_id    = NULL,
		.result     = NM_AUTH_CALL_RESULT_UNKNOWN,

		/* we don't clone the permission string. It's the callers responsiblity. */
		.permission = permission,
	};

	/* above we assert that no duplicate permissions are added. Still, track the
	 * new request to the front of the list so that it would shadow an earlier
	 * call. */
	c_list_link_front (&self->auth_call_lst_head, &call->auth_call_lst);

	call->call_id = nm_auth_manager_check_authorization (nm_auth_manager_get (),
	                                                     self->subject,
	                                                     permission,
	                                                     allow_interaction,
	                                                     pk_call_cb,
	                                                     call);

	self->num_pending_auth_calls++;

	_ASSERT_call (call);

	/* we track auth-calls in a linked list. If we end up requesting too many permissions this
	 * becomes inefficient. If that ever happens, consider a more efficient data structure for
	 * a large number of requests. */
	nm_assert (self->num_pending_auth_calls < 25);
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
	nm_assert (done_func);

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

NMAuthChain *
nm_auth_chain_new_subject (NMAuthSubject *subject,
                           GDBusMethodInvocation *context,
                           NMAuthChainResultFunc done_func,
                           gpointer user_data)
{
	NMAuthChain *self;

	g_return_val_if_fail (NM_IS_AUTH_SUBJECT (subject), NULL);
	nm_assert (   nm_auth_subject_is_unix_process (subject)
	           || nm_auth_subject_is_internal (subject));
	nm_assert (done_func);

	self = g_slice_new (NMAuthChain);
	*self = (NMAuthChain) {
		.done_func          = done_func,
		.user_data          = user_data,
		.context            = nm_g_object_ref (context),
		.subject            = g_object_ref (subject),
		.parent_lst         = C_LIST_INIT (self->parent_lst),
		.data_lst_head      = C_LIST_INIT (self->data_lst_head),
		.auth_call_lst_head = C_LIST_INIT (self->auth_call_lst_head),
	};
	return self;
}

/**
 * nm_auth_chain_destroy:
 * @self: the auth-chain
 *
 * Destroys the auth-chain. By destroying the auth-chain, you also cancel
 * the receipt of the done-callback. IOW, the callback will not be invoked.
 *
 * The only exception is, you may call nm_auth_chain_destroy() from inside
 * the callback. In this case the call has no effect and @self stays alive
 * until the callback returns.
 *
 * Note that you might only destroy an auth-chain exactly once, and never
 * after the callback was handled. After the callback returns, the auth chain
 * always gets automatically destroyed. So you only need to explicitly destroy
 * it, if you want to abort it before the callback complets.
 */
void
nm_auth_chain_destroy (NMAuthChain *self)
{
	g_return_if_fail (self);
	g_return_if_fail (!self->is_destroyed);

	self->is_destroyed = TRUE;

	if (self->is_finishing) {
		/* we are called from inside the callback. Keep the instance alive for the moment. */
		return;
	}

	_auth_chain_destroy (self);
}

static void
_auth_chain_destroy (NMAuthChain *self)
{
	AuthCall *call;
	ChainData *chain_data;

	c_list_unlink (&self->parent_lst);

	nm_clear_g_object (&self->subject);
	nm_clear_g_object (&self->context);

	/* we must first destry all AuthCall instances before ChainData. The reason is
	 * that AuthData.permission is not cloned and the lifetime of the string must
	 * be ensured by the caller. A sensible thing to do for the caller is attach the
	 * permission string via nm_auth_chain_set_data(). Hence, first free the AuthCall. */
	while ((call = c_list_first_entry (&self->auth_call_lst_head, AuthCall, auth_call_lst)))
		auth_call_free (call);

	while ((chain_data = c_list_first_entry (&self->data_lst_head, ChainData, data_lst)))
		chain_data_free (chain_data);

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
	nm_assert (   nm_auth_subject_is_internal (subject)
	           || nm_auth_subject_is_unix_process (subject));

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
