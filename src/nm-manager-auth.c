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

#include <config.h>
#include <string.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <gio/gio.h>

#if WITH_POLKIT
#include <polkit/polkit.h>
#endif

#include "nm-setting-connection.h"
#include "nm-manager-auth.h"
#include "nm-logging.h"
#include "nm-dbus-manager.h"
#include "nm-auth-subject.h"

struct NMAuthChain {
	guint32 refcount;
#if WITH_POLKIT
	PolkitAuthority *authority;
#endif
	GSList *calls;
	GHashTable *data;

	DBusGMethodInvocation *context;
	char *owner;
	gulong user_uid;
	NMAuthSubject *subject;
	GError *error;

	guint idle_id;

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

static void
free_data (gpointer data)
{
	ChainData *tmp = data;

	if (tmp->destroy)
		tmp->destroy (tmp->data);
	memset (tmp, 0, sizeof (ChainData));
	g_free (tmp);
}

static gboolean
auth_chain_finish (gpointer user_data)
{
	NMAuthChain *self = user_data;

	self->idle_id = 0;

	/* Ensure we say alive across the callback */
	self->refcount++;
	self->done_func (self, self->error, self->context, self->user_data);
	nm_auth_chain_unref (self);
	return FALSE;
}

#if WITH_POLKIT
static PolkitAuthority *
pk_authority_get (GError **error)
{
	static PolkitAuthority *authority = NULL;

	if (authority == NULL)
		authority = polkit_authority_get_sync (NULL, error);

	/* Yes, ref every time; we want to keep the object alive */
	g_warn_if_fail (authority);
	return authority ? g_object_ref (authority) : NULL;
}
#endif

static NMAuthChain *
_auth_chain_new (NMAuthSubject *subject,
                 const char *dbus_sender,
                 gulong user_uid,
                 DBusGMethodInvocation *context,
                 NMAuthChainResultFunc done_func,
                 gpointer user_data)
{
	NMAuthChain *self;

	g_return_val_if_fail (subject || user_uid == 0 || dbus_sender, NULL);

	self = g_malloc0 (sizeof (NMAuthChain));
	self->refcount = 1;
#if WITH_POLKIT
	self->authority = pk_authority_get (&self->error);
#endif
	self->data = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, free_data);
	self->done_func = done_func;
	self->user_data = user_data;
	self->context = context;

	if (subject) {
		self->user_uid = nm_auth_subject_get_uid (subject);
		self->subject = g_object_ref (subject);
	} else {
		self->user_uid = user_uid;
		self->owner = g_strdup (dbus_sender);
		if (user_uid > 0 && !self->owner) {
			/* Need an owner */
			g_warn_if_fail (self->owner);
			nm_auth_chain_unref (self);
			self = NULL;
		}
	}

	return self;
}

NMAuthChain *
nm_auth_chain_new_dbus_sender (const char *dbus_sender,
                               gulong user_uid,
                               NMAuthChainResultFunc done_func,
                               gpointer user_data)
{
	return _auth_chain_new (NULL, dbus_sender, user_uid, NULL, done_func, user_data);
}

/* Creates the NMAuthSubject automatically */
NMAuthChain *
nm_auth_chain_new_context (DBusGMethodInvocation *context,
                           NMAuthChainResultFunc done_func,
                           gpointer user_data)
{
	NMAuthSubject *subject;
	NMAuthChain *chain;

	g_return_val_if_fail (context != NULL, NULL);

	subject = nm_auth_subject_new_from_context (context);
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
                           DBusGMethodInvocation *context,
                           NMAuthChainResultFunc done_func,
                           gpointer user_data)
{
	NMAuthChain *chain;

	g_return_val_if_fail (NM_IS_AUTH_SUBJECT (subject), NULL);
	chain = _auth_chain_new (subject, NULL, G_MAXULONG, context, done_func, user_data);

	/* Chains creation from a valid NMAuthSubject cannot fail since the
	 * subject already has all the necessary auth info.
	 */
	g_assert (chain);
	return chain;
}

gpointer
nm_auth_chain_get_data (NMAuthChain *self, const char *tag)
{
	ChainData *tmp;

	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (tag != NULL, NULL);

	tmp = g_hash_table_lookup (self->data, tag);
	return tmp ? tmp->data : NULL;
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

	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (tag != NULL, NULL);

	tmp = g_hash_table_lookup (self->data, tag);
	if (tmp) {
		g_hash_table_steal (self->data, tag);
		value = tmp->data;
		/* Make sure the destroy handler isn't called when freeing */
		tmp->destroy = NULL;
		free_data (tmp);
	}
	return value;
}

void
nm_auth_chain_set_data (NMAuthChain *self,
                        const char *tag,
                        gpointer data,
                        GDestroyNotify data_destroy)
{
	ChainData *tmp;

	g_return_if_fail (self != NULL);
	g_return_if_fail (tag != NULL);

	if (data == NULL)
		g_hash_table_remove (self->data, tag);
	else {
		tmp = g_malloc0 (sizeof (ChainData));
		tmp->data = data;
		tmp->destroy = data_destroy;

		g_hash_table_insert (self->data, g_strdup (tag), tmp);
	}
}

gulong
nm_auth_chain_get_data_ulong (NMAuthChain *self, const char *tag)
{
	gulong *ptr;

	g_return_val_if_fail (self != NULL, 0);
	g_return_val_if_fail (tag != NULL, 0);

	ptr = nm_auth_chain_get_data (self, tag);
	return *ptr;
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

NMAuthCallResult
nm_auth_chain_get_result (NMAuthChain *self, const char *permission)
{
	g_return_val_if_fail (self != NULL, NM_AUTH_CALL_RESULT_UNKNOWN);
	g_return_val_if_fail (permission != NULL, NM_AUTH_CALL_RESULT_UNKNOWN);

	return GPOINTER_TO_UINT (nm_auth_chain_get_data (self, permission));
}

static void
nm_auth_chain_check_done (NMAuthChain *self)
{
	g_return_if_fail (self != NULL);

	if (g_slist_length (self->calls) == 0) {
		g_assert (self->idle_id == 0);
		self->idle_id = g_idle_add (auth_chain_finish, self);
	}
}

static void
nm_auth_chain_remove_call (NMAuthChain *self, AuthCall *call)
{
	g_return_if_fail (self != NULL);
	g_return_if_fail (call != NULL);

	self->calls = g_slist_remove (self->calls, call);
}

static AuthCall *
auth_call_new (NMAuthChain *chain, const char *permission)
{
	AuthCall *call;

	call = g_malloc0 (sizeof (AuthCall));
	call->chain = chain;
	call->permission = g_strdup (permission);
	chain->calls = g_slist_append (chain->calls, call);
	return call;
}

static void
auth_call_free (AuthCall *call)
{
	g_free (call->permission);
	g_clear_object (&call->cancellable);
	g_free (call);
}

/* This can get used from scheduled idles, hence the boolean return */
static gboolean
auth_call_complete (AuthCall *call)
{
	nm_auth_chain_remove_call (call->chain, call);
	nm_auth_chain_check_done (call->chain);
	auth_call_free (call);
	return FALSE;
}

static void
auth_call_cancel (gpointer user_data)
{
	AuthCall *call = user_data;

	if (call->cancellable) {
		/* we don't free call immediately. Instead we cancel the async operation
		 * and set cancellable to NULL. pk_call_cb() will check for this and
		 * do the final cleanup. */
		g_cancellable_cancel (call->cancellable);
		g_clear_object (&call->cancellable);
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
	PolkitAuthorizationResult *pk_result;
	GError *error = NULL;

	pk_result = polkit_authority_check_authorization_finish ((PolkitAuthority *) object, result, &error);

	/* If the call is already canceled do nothing */
	if (!call->cancellable) {
		g_clear_error (&error);
		g_clear_object (&pk_result);
		auth_call_free (call);
		return;
	}

	if (error) {
		if (!call->chain->error)
			call->chain->error = g_error_copy (error);

		nm_log_warn (LOGD_CORE, "error requesting auth for %s: (%d) %s",
		             call->permission, error->code, error->message);
		g_clear_error (&error);
	} else {
		guint call_result = NM_AUTH_CALL_RESULT_UNKNOWN;

		if (polkit_authorization_result_get_is_authorized (pk_result)) {
			/* Caller has the permission */
			call_result = NM_AUTH_CALL_RESULT_YES;
		} else if (polkit_authorization_result_get_is_challenge (pk_result)) {
			/* Caller could authenticate to get the permission */
			call_result = NM_AUTH_CALL_RESULT_AUTH;
		} else
			call_result = NM_AUTH_CALL_RESULT_NO;

		nm_auth_chain_set_data (call->chain, call->permission, GUINT_TO_POINTER (call_result), NULL);
		g_object_unref (pk_result);
	}

	auth_call_complete (call);
}

static void
auth_call_schedule_complete_with_error (AuthCall *call, const char *msg)
{
	if (!call->chain->error)
		call->chain->error = g_error_new_literal (DBUS_GERROR, DBUS_GERROR_FAILED, msg);
	call->call_idle_id = g_idle_add ((GSourceFunc) auth_call_complete, call);
}

static gboolean
_add_call_polkit (NMAuthChain *self,
                  const char *permission,
                  gboolean allow_interaction)
{
	PolkitSubject *subject;
	PolkitCheckAuthorizationFlags flags = POLKIT_CHECK_AUTHORIZATION_FLAGS_NONE;
	AuthCall *call;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (self->owner || self->subject, FALSE);
	g_return_val_if_fail (permission != NULL, FALSE);

	call = auth_call_new (self, permission);

	if (self->authority == NULL) {
		/* No polkit, no authorization */
		auth_call_schedule_complete_with_error (call, "PolicyKit not running");
		return FALSE;
	}

	if (self->subject) {
		subject = g_object_ref (nm_auth_subject_get_polkit_subject (self->subject));
		g_assert (subject);
	} else {
		g_assert (self->owner);
		subject = polkit_system_bus_name_new (self->owner);
		if (!subject) {
			auth_call_schedule_complete_with_error (call, "Failed to create polkit subject");
			return FALSE;
		}
	}

	if (allow_interaction)
		flags = POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION;

	call->cancellable = g_cancellable_new ();
	polkit_authority_check_authorization (self->authority,
	                                      subject,
	                                      permission,
	                                      NULL,
	                                      flags,
	                                      call->cancellable,
	                                      pk_call_cb,
	                                      call);
	g_object_unref (subject);
	return TRUE;
}
#endif

gboolean
nm_auth_chain_add_call (NMAuthChain *self,
                        const char *permission,
                        gboolean allow_interaction)
{
	AuthCall *call;

	g_return_val_if_fail (self != NULL, FALSE);

#if WITH_POLKIT
	/* Non-root always gets authenticated when using polkit */
	if (self->user_uid > 0)
		return _add_call_polkit (self, permission, allow_interaction);
#endif

	/* Root user or non-polkit always gets the permission */
	call = auth_call_new (self, permission);
	nm_auth_chain_set_data (self, permission, GUINT_TO_POINTER (NM_AUTH_CALL_RESULT_YES), NULL);
	call->call_idle_id = g_idle_add ((GSourceFunc) auth_call_complete, call);
	return TRUE;
}

void
nm_auth_chain_unref (NMAuthChain *self)
{
	g_return_if_fail (self != NULL);

	self->refcount--;
	if (self->refcount > 0)
		return;

	if (self->idle_id)
		g_source_remove (self->idle_id);

#if WITH_POLKIT
	if (self->authority)
		g_object_unref (self->authority);
#endif
	g_free (self->owner);
	g_object_unref (self->subject);

	g_slist_free_full (self->calls, auth_call_cancel);

	g_clear_error (&self->error);
	g_hash_table_destroy (self->data);

	memset (self, 0, sizeof (NMAuthChain));
	g_free (self);
}

/************ utils **************/

gboolean
nm_auth_uid_in_acl (NMConnection *connection,
                    NMSessionMonitor *smon,
                    gulong uid,
                    char **out_error_desc)
{
	NMSettingConnection *s_con;
	const char *user = NULL;
	GError *local = NULL;

	g_return_val_if_fail (connection != NULL, FALSE);
	g_return_val_if_fail (smon != NULL, FALSE);

	/* Root gets a free pass */
	if (0 == uid)
		return TRUE;

	/* Reject the request if the request comes from no session at all */
	if (!nm_session_monitor_uid_has_session (smon, uid, &user, &local)) {
		if (out_error_desc) {
			*out_error_desc = g_strdup_printf ("No session found for uid %lu (%s)",
			                                   uid,
			                                   local && local->message ? local->message : "unknown");
		}
		g_clear_error (&local);
		return FALSE;
	}

	if (!user) {
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

typedef struct {
	GDestroyNotify changed_callback;
	gpointer changed_data;
} PkChangedInfo;

static GSList *funcs = NULL;

#if WITH_POLKIT
static void
pk_authority_changed_cb (GObject *object, gpointer unused)
{
	GSList *iter;

	for (iter = funcs; iter; iter = g_slist_next (iter)) {
		PkChangedInfo *info = iter->data;

		info->changed_callback (info->changed_data);
	}
}
#endif

void
nm_auth_changed_func_register (GDestroyNotify callback, gpointer callback_data)
{
#if WITH_POLKIT
	PolkitAuthority *authority;
	static guint32 changed_id = 0;
#endif
	PkChangedInfo *info;
	GSList *iter;
	gboolean found = FALSE;

#if WITH_POLKIT
	authority = pk_authority_get (NULL);
	if (!authority)
		return;

	/* Hook up the changed signal the first time a callback is registered */
	if (changed_id == 0) {
		changed_id = g_signal_connect (authority,
		                               "changed",
		                               G_CALLBACK (pk_authority_changed_cb),
		                               &funcs);
	}
#endif

	/* No duplicates */
	for (iter = funcs; iter; iter = g_slist_next (iter)) {
		info = iter->data;
		if ((callback == info->changed_callback) && (callback_data == info->changed_data)) {
			found = TRUE;
			break;
		}
	}

	g_warn_if_fail (found == FALSE);
	if (found == FALSE) {
		info = g_malloc0 (sizeof (*info));
		info->changed_callback = callback;
		info->changed_data = callback_data;
		funcs = g_slist_append (funcs, info);
	}

#if WITH_POLKIT
	g_object_unref (authority);
#endif
}

void
nm_auth_changed_func_unregister (GDestroyNotify callback, gpointer callback_data)
{
	GSList *iter;

	for (iter = funcs; iter; iter = g_slist_next (iter)) {
		PkChangedInfo *info = iter->data;

		if ((callback == info->changed_callback) && (callback_data == info->changed_data)) {
			g_free (info);
			funcs = g_slist_delete_link (funcs, iter);
			break;
		}
	}
}

