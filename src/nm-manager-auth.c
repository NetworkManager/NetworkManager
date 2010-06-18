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

#include "nm-manager-auth.h"
#include "nm-logging.h"

#include <dbus/dbus-glib-lowlevel.h>
#include <string.h>

struct NMAuthChain {
	guint32 refcount;
	PolkitAuthority *authority;
	GSList *calls;
	GHashTable *data;

	DBusGMethodInvocation *context;
	char *owner;
	GError *error;

	NMAuthChainResultFunc done_func;
	NMAuthChainCallFunc call_func;
	gpointer user_data;
};

typedef struct {
	NMAuthChain *chain;
	GCancellable *cancellable;
	char *permission;
	gboolean disposed;
} PolkitCall;

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

static void
default_call_func (NMAuthChain *chain,
                   const char *permission,
                   GError *error,
                   NMAuthCallResult result,
                   gpointer user_data)
{
	if (!error)
		nm_auth_chain_set_data (chain, permission, GUINT_TO_POINTER (result), NULL);
}

NMAuthChain *
nm_auth_chain_new (PolkitAuthority *authority,
                   DBusGMethodInvocation *context,
                   DBusGProxy *proxy,
                   NMAuthChainResultFunc done_func,
                   gpointer user_data)
{
	NMAuthChain *self;

	g_return_val_if_fail (context || proxy, NULL);

	self = g_malloc0 (sizeof (NMAuthChain));
	self->refcount = 1;
	self->authority = g_object_ref (authority);
	self->data = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, free_data);
	self->done_func = done_func;
	self->call_func = /* call_func ? call_func : */ default_call_func;
	self->user_data = user_data;
	self->context = context;

	if (proxy)
		self->owner = g_strdup (dbus_g_proxy_get_bus_name (proxy));
	else if (context)
		self->owner = dbus_g_method_get_sender (context);

	if (!self->owner) {
		/* Need an owner */
		g_warn_if_fail (self->owner);
		nm_auth_chain_unref (self);
		self = NULL;
	}

	return self;
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

static void
nm_auth_chain_check_done (NMAuthChain *self)
{
	g_return_if_fail (self != NULL);

	if (g_slist_length (self->calls) == 0) {
		/* Ensure we say alive across the callback */
		self->refcount++;
		self->done_func (self, self->error, self->context, self->user_data);
		nm_auth_chain_unref (self);
	}
}

static void
polkit_call_cancel (PolkitCall *call)
{
	call->disposed = TRUE;
	g_cancellable_cancel (call->cancellable);
}

static void
polkit_call_free (PolkitCall *call)
{
	g_return_if_fail (call != NULL);

	call->disposed = TRUE;
	g_free (call->permission);
	call->permission = NULL;
	call->chain = NULL;
	g_object_unref (call->cancellable);
	call->cancellable = NULL;
	g_free (call);
}

static void
pk_call_cb (GObject *object, GAsyncResult *result, gpointer user_data)
{
	PolkitCall *call = user_data;
	NMAuthChain *chain;
	PolkitAuthorizationResult *pk_result;
	GError *error = NULL;
	guint call_result = NM_AUTH_CALL_RESULT_UNKNOWN;

	/* If the call is already disposed do nothing */
	if (call->disposed) {
		polkit_call_free (call);
		return;
	}

	chain = call->chain;
	chain->calls = g_slist_remove (chain->calls, call);

	pk_result = polkit_authority_check_authorization_finish (chain->authority,
	                                                         result,
	                                                         &error);
	if (error) {
		if (!chain->error)
			chain->error = g_error_copy (error);

		nm_log_warn (LOGD_CORE, "error requesting auth for %s: (%d) %s",
		             call->permission,
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
	} else {
		if (polkit_authorization_result_get_is_authorized (pk_result)) {
			/* Caller has the permission */
			call_result = NM_AUTH_CALL_RESULT_YES;
		} else if (polkit_authorization_result_get_is_challenge (pk_result)) {
			/* Caller could authenticate to get the permission */
			call_result = NM_AUTH_CALL_RESULT_AUTH;
		} else
			call_result = NM_AUTH_CALL_RESULT_NO;
	}

	chain->call_func (chain, call->permission, error, call_result, chain->user_data);
	nm_auth_chain_check_done (chain);

	g_clear_error (&error);
	polkit_call_free (call);
	if (pk_result)
		g_object_unref (pk_result);
}

gboolean
nm_auth_chain_add_call (NMAuthChain *self,
                        const char *permission,
                        gboolean allow_interaction)
{
	PolkitCall *call;
	PolkitSubject *subject;
	PolkitCheckAuthorizationFlags flags = POLKIT_CHECK_AUTHORIZATION_FLAGS_NONE;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (self->owner != NULL, FALSE);
	g_return_val_if_fail (permission != NULL, FALSE);

	subject = polkit_system_bus_name_new (self->owner);
	if (!subject)
		return FALSE;

	call = g_malloc0 (sizeof (PolkitCall));
	call->chain = self;
	call->permission = g_strdup (permission);
	call->cancellable = g_cancellable_new ();

	self->calls = g_slist_append (self->calls, call);

	if (allow_interaction)
		flags = POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION;

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

void
nm_auth_chain_unref (NMAuthChain *self)
{
	GSList *iter;

	g_return_if_fail (self != NULL);

	self->refcount--;
	if (self->refcount > 0)
		return;

	g_object_unref (self->authority);
	g_free (self->owner);

	for (iter = self->calls; iter; iter = g_slist_next (iter))
		polkit_call_cancel ((PolkitCall *) iter->data);
	g_slist_free (self->calls);

	g_clear_error (&self->error);
	g_hash_table_destroy (self->data);

	memset (self, 0, sizeof (NMAuthChain));
	g_free (self);
}

/************ utils **************/

gboolean
nm_auth_get_caller_uid (DBusGMethodInvocation *context,
                        NMDBusManager *dbus_mgr,
                        gulong *out_uid,
                        const char **out_error_desc)
{
	DBusConnection *connection;
	char *sender = NULL;
	gboolean success = FALSE;
	DBusError dbus_error;

	g_return_val_if_fail (context != NULL, FALSE);
	g_return_val_if_fail (dbus_mgr != NULL, FALSE);
	g_return_val_if_fail (out_uid != NULL, FALSE);

	*out_uid = G_MAXULONG;

	sender = dbus_g_method_get_sender (context);
	if (!sender) {
		if (out_error_desc)
			*out_error_desc = "Could not determine D-Bus requestor";
		goto out;
	}

	connection = nm_dbus_manager_get_dbus_connection (dbus_mgr);
	if (!connection) {
		if (out_error_desc)
			*out_error_desc = "Could not get the D-Bus system bus";
		goto out;
	}

	dbus_error_init (&dbus_error);
	/* FIXME: do this async */
	*out_uid = dbus_bus_get_unix_user (connection, sender, &dbus_error);
	if (dbus_error_is_set (&dbus_error)) {
		if (out_error_desc)
			*out_error_desc = "Could not determine the user ID of the requestor";
		dbus_error_free (&dbus_error);
		*out_uid = G_MAXULONG;
	} else
		success = TRUE;

out:
	g_free (sender);
	return success;
}

gboolean
nm_auth_uid_authorized (gulong uid,
                        NMDBusManager *dbus_mgr,
                        DBusGProxy *user_proxy,
                        const char **out_error_desc)
{
	DBusConnection *connection;
	DBusError dbus_error;
	char *service_owner = NULL;
	const char *service_name;
	gulong service_uid = G_MAXULONG;

	g_return_val_if_fail (dbus_mgr != NULL, FALSE);
	g_return_val_if_fail (out_error_desc != NULL, FALSE);

	/* Ensure the request to activate the user connection came from the
	 * same session as the user settings service.  FIXME: use ConsoleKit
	 * too.
	 */

	if (!user_proxy) {
		*out_error_desc = "No user settings service available";
		return FALSE;
	}

	service_name = dbus_g_proxy_get_bus_name (user_proxy);
	if (!service_name) {
		*out_error_desc = "Could not determine user settings service name";
		return FALSE;
	}

	connection = nm_dbus_manager_get_dbus_connection (dbus_mgr);
	if (!connection) {
		*out_error_desc = "Could not get the D-Bus system bus";
		return FALSE;
	}

	service_owner = nm_dbus_manager_get_name_owner (dbus_mgr, service_name, NULL);
	if (!service_owner) {
		*out_error_desc = "Could not determine D-Bus owner of the user settings service";
		return FALSE;
	}

	dbus_error_init (&dbus_error);
	service_uid = dbus_bus_get_unix_user (connection, service_owner, &dbus_error);
	g_free (service_owner);

	if (dbus_error_is_set (&dbus_error)) {
		dbus_error_free (&dbus_error);
		*out_error_desc = "Could not determine the Unix UID of the sender of the request";
		return FALSE;
	}

	/* And finally, the actual UID check */
	if (uid != service_uid) {
		*out_error_desc = "Requestor UID does not match the UID of the user settings service";
		return FALSE;
	}

	return TRUE;
}

