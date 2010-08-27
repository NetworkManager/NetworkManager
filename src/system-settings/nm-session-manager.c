/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager user session tracker
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
 * (C) Copyright 2010 Daniel Gnoutcheff <daniel@gnoutcheff.name>
 */

#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <nm-utils.h>
#include <nm-dbus-glib-types.h>
#include "nm-dbus-manager.h"
#include "nm-session-manager.h"
#include "nm-logging.h"

G_DEFINE_TYPE (NMSessionManager, nm_session_manager, G_TYPE_OBJECT);

/* NMSessionManager data */
typedef struct {
	gboolean disposed;
	gboolean initialized;
	guint init_sessions_left;

	/* The master table of NMSessionInfo instances, keyed by session id. */
	GHashTable *sessions;

	/* DBus proxy of the ConsoleKit manager */
	DBusGProxy *ck_manager;

	/* Table of PendingSessionInfo structs, representing sessions for which we
	 * are waiting for information on. Keyed by session id. */
	GHashTable *pending_sessions;

	/* List of PendingCallerInfo structs, representing ongoing
	 * get_session_of_caller calls. */
	GSList *pending_callers;
} NMSessionManagerPrivate;

#define NM_SESSION_MANAGER_GET_PRIVATE(self) (G_TYPE_INSTANCE_GET_PRIVATE (self, NM_TYPE_SESSION_MANAGER, NMSessionManagerPrivate))


enum {
	ADDED,
	INIT_DONE,

	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };


/**** general utilities for managing callbacks *******************************/

typedef struct {
	NMSessionFunc callback;
	gpointer user_data;
} CallbackInfo;

/* Allocate a new CallbackInfo for the given callback & data */
static CallbackInfo *
callback_info_new (NMSessionFunc callback, gpointer user_data)
{
	CallbackInfo *info = g_slice_new (CallbackInfo);
	info->callback = callback;
	info->user_data = user_data;
	return info;
}

/* Run the callback represented by cb_info and free it. */
static void
callback_info_run (CallbackInfo *cb_info, NMSessionInfo *session, GError *error)
{
	if (cb_info->callback) {
		(cb_info->callback) (session, error, cb_info->user_data);
	}
	g_slice_free (CallbackInfo, cb_info);
}

/* Run the callback with an error message indicating that we've been disposed. */
static void
callback_info_fail_disposed (CallbackInfo *cb_info)
{
	GError *error = g_error_new (NM_SESSION_MANAGER_ERROR,
	                             NM_SESSION_MANAGER_ERROR_DISPOSED,
	                             "NMSessionManager was disposed before operation completed.");
	callback_info_run (cb_info, NULL, error);
	g_error_free (error);
}


/**** get_session stuff ******************************************************/

typedef struct {
	NMSessionManager *manager;
	DBusGProxy *session_proxy;
	DBusGProxyCall *session_call;
	char *session_id;

	GSList *callbacks; /* List of CallbackInfo structs */
} PendingSessionInfo;

/* Called by the pending_sessions GHashTable when removing a PendingSession */
static void
pending_session_destroy (gpointer data)
{
	PendingSessionInfo *pending = (PendingSessionInfo *) data;

	// FIXME this is ugly copy-and-paste
	// If any callbacks remain, send failure messages to them.
	while (pending->callbacks) {
		CallbackInfo *cb_info = (CallbackInfo *) pending->callbacks->data;
		callback_info_fail_disposed (cb_info);
		pending->callbacks = g_slist_remove (pending->callbacks, cb_info);
	}

	g_free (pending->session_id);
	g_object_unref (pending->session_proxy);
	g_object_unref (pending->session_call);
	g_slice_free (PendingSessionInfo, pending);
}

static void
pending_session_finish (PendingSessionInfo *pending, 
                        NMSessionInfo *session,
                        GError *error)
{
	NMSessionManagerPrivate *priv = NM_SESSION_MANAGER_GET_PRIVATE (pending->manager);

	while (pending->callbacks) {
		CallbackInfo *cb_info = (CallbackInfo *) pending->callbacks->data;
		callback_info_run (cb_info, session, error);
		pending->callbacks = g_slist_remove (pending->callbacks, cb_info);
	}

	g_hash_table_remove (priv->pending_sessions, pending->session_id);
	// pending_session_destroy() will be called by GHashTable
}

static void
pending_session_cancel (PendingSessionInfo *pending, GError *error)
{
	dbus_g_proxy_cancel_call (pending->session_proxy, pending->session_call);
	pending_session_finish (pending, NULL, error);
}

static void
get_unix_user_cb (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	PendingSessionInfo *pending = (PendingSessionInfo *) user_data;
	NMSessionManagerPrivate *priv = NM_SESSION_MANAGER_GET_PRIVATE (pending->manager);
	guint user_id;
	struct passwd *pw_info = NULL;
	int ngroups;
	guint group_ids_size = 0;
	gid_t *group_ids = NULL;
	GSList *group_names = NULL;
	NMSessionInfo *session = NULL;
	GError *error = NULL;
	int i;

	if (!dbus_g_proxy_end_call (proxy, call_id, NULL, 
	                            G_TYPE_UINT, &user_id, G_TYPE_NONE)) {
	    error = g_error_new (NM_SESSION_MANAGER_ERROR,
	                         NM_SESSION_MANAGER_ERROR_INFO_GATHERING_FAILED,
	                         "session %s: failed to get uid", 
	                         pending->session_id);
	    goto out;
	}

	pw_info = getpwuid (user_id);
	if (!pw_info) {
	    error = g_error_new (NM_SESSION_MANAGER_ERROR,
	                         NM_SESSION_MANAGER_ERROR_INFO_GATHERING_FAILED,
	                         "session %s: failed to get username for uid %u", 
	                         pending->session_id, user_id);
	    goto out;
	}

	// Figure out how many groups the user is in
	group_ids = g_slice_alloc (0);
	ngroups = 0;
	getgrouplist (pw_info->pw_name, pw_info->pw_gid, group_ids, &ngroups);
	g_slice_free1 (0, group_ids);

	// Get the list of group IDs
	// FIXME what happens if the group list changes in the window between the
	// two getgrouplist calls?
	group_ids_size = ngroups * sizeof (gid_t);
	group_ids = g_slice_alloc (group_ids_size);
	if (getgrouplist (pw_info->pw_name, pw_info->pw_gid, group_ids, &ngroups) == -1) {
	    error = g_error_new (NM_SESSION_MANAGER_ERROR,
	                         NM_SESSION_MANAGER_ERROR_INFO_GATHERING_FAILED,
	                         "session %s: failed to get groups for user %s", 
	                         pending->session_id, pw_info->pw_name);
	    goto out;
	}

	for (i = 0; i < ngroups; i++) {
		struct group *gr_info = getgrgid (group_ids[i]);
		group_names = g_slist_prepend (group_names, g_strdup (gr_info->gr_name));
	}

	session = g_object_new (NM_TYPE_SESSION_INFO, 
	                        NM_SESSION_INFO_ID, pending->session_id,
	                        NM_SESSION_INFO_UNIX_USER, pw_info->pw_name,
	                        NM_SESSION_INFO_UNIX_GROUPS, group_names,
	                        NULL);
	g_assert (session);

	g_hash_table_insert (priv->sessions, nm_session_info_get_id (session), session);
	g_signal_emit (pending->manager, signals[ADDED], 0, session);

out:
	if (group_names)
		nm_utils_slist_free (group_names, g_free);
	if (group_ids)
		g_slice_free1 (group_ids_size, group_ids);

	pending_session_finish (pending, session, error);

	g_clear_error (&error);
}

/* Start the process of loading information about the given session, and return
 * the PendingSessionInfo struct that represents it.
 */ 
static PendingSessionInfo *
pending_session_start (NMSessionManager *self, char *session_id)
{
	PendingSessionInfo *pending = g_slice_new (PendingSessionInfo);
	NMSessionManagerPrivate *priv = NM_SESSION_MANAGER_GET_PRIVATE (self);
	DBusGConnection *connection = nm_dbus_manager_get_connection (nm_dbus_manager_get ());

	pending->session_id = g_strdup (session_id);
	pending->manager = self;
	pending->callbacks = NULL;
		
	pending->session_proxy = dbus_g_proxy_new_for_name (connection,
	                                                    "org.freedesktop.ConsoleKit",
	                                                    pending->session_id,
	                                                    "org.freedesktop.ConsoleKit.Session");

	pending->session_call = dbus_g_proxy_begin_call (pending->session_proxy,
	                                                 "GetUnixUser",
	                                                 get_unix_user_cb,
	                                                 pending,
	                                                 NULL,
	                                                 G_TYPE_INVALID);

	g_hash_table_insert (priv->pending_sessions, pending->session_id, pending);

	return pending;
}

static PendingSessionInfo *
pending_session_find (NMSessionManager *self, char *session_id)
{
	GHashTable *pending_sessions = NM_SESSION_MANAGER_GET_PRIVATE (self)->pending_sessions;
	return g_hash_table_lookup (pending_sessions, session_id);
}

static void
pending_session_add_callback (PendingSessionInfo *pending, CallbackInfo *cb_info)
{
	pending->callbacks = g_slist_prepend (pending->callbacks, cb_info);
}

static void
get_session_internal (NMSessionManager *self,
                      char *session_id,
                      CallbackInfo *cb_info)
{
	NMSessionManagerPrivate *priv = NM_SESSION_MANAGER_GET_PRIVATE (self);
	NMSessionInfo *session;
	
	if (priv->disposed) {
		callback_info_fail_disposed (cb_info);
		return;
	}
	
	session = g_hash_table_lookup (priv->sessions, session_id);
	if (session) {
		callback_info_run (cb_info, session, NULL);
	} else {
		PendingSessionInfo *pending = pending_session_find (self, session_id);
		if (!pending) {
			pending = pending_session_start (self, session_id);
		}
		pending_session_add_callback (pending, cb_info);
	}
}

void
nm_session_manager_get_session (NMSessionManager *self,
                                char *session_id,
                                NMSessionFunc callback,
                                gpointer user_data)
{
	CallbackInfo *cb_info;
	
	g_return_if_fail (NM_IS_SESSION_MANAGER (self));
	g_return_if_fail (session_id != NULL);
	g_return_if_fail (callback != NULL);

	cb_info = callback_info_new (callback, user_data);

	get_session_internal (self, session_id, cb_info);
}

/**** get_sessions stuff *****************************************************/

static void
prepend_slist (gpointer key, gpointer value, gpointer user_data)
{
	GSList **sessions = (GSList **) user_data;

	*sessions = g_slist_prepend (*sessions, value);
}

GSList *
nm_session_manager_get_sessions (NMSessionManager *self)
{
	NMSessionManagerPrivate *priv;
	GSList *sessions;

	g_return_val_if_fail (NM_IS_SESSION_MANAGER (self), NULL);

	priv = NM_SESSION_MANAGER_GET_PRIVATE (self);
	g_hash_table_foreach (priv->sessions, prepend_slist, &sessions);

	return sessions;
}

/**** ConsoleKit signal handling *********************************************/

/* ConsoleKit reports a new session. Pull it into our cache. */
static void
session_added (NMSessionManager *self, char *new_session) 
{
	nm_session_manager_get_session (self, new_session, NULL, NULL);
}

/* ConsoleKit reports that a session has been removed. */
static void
session_removed (NMSessionManager *self, char *removed_id)
{
	NMSessionManagerPrivate *priv = NM_SESSION_MANAGER_GET_PRIVATE (self);
	NMSessionInfo *removed = g_hash_table_lookup (priv->sessions, removed_id);

	if (removed) {
		g_signal_emit_by_name (removed, NM_SESSION_INFO_REMOVED);
		g_hash_table_remove (priv->sessions, removed_id);
	} else {
		PendingSessionInfo *removed_pending = pending_session_find (self, removed_id);
		if (removed_pending) {
			GError *error = g_error_new (NM_SESSION_MANAGER_ERROR,
			                             NM_SESSION_MANAGER_ERROR_NOT_FOUND,
			                             "session %s removed moments ago",
			                             removed_id);
			pending_session_cancel (removed_pending, error);
			g_error_free (error);
		}
	}		
}

/* A DBus signal filter for picking up ConsoleKit signals indicating that
 * sessions have been added or removed. We use this custom message filter as
 * we'd otherwise have to keep track of all the seats and register signal
 * handlers in every one. */
static DBusHandlerResult
ck_session_signal_filter (DBusConnection *connection,
                          DBusMessage *message,
                          void *user_data)
{
	NMSessionManager *self = NM_SESSION_MANAGER (user_data);
	char *session_id;

	// TODO: filter by sender?

	if (dbus_message_is_signal (message, 
	                            "org.freedesktop.ConsoleKit.Seat",
	                            "SessionAdded")) {
		if (dbus_message_get_args (message, NULL, 
			                       DBUS_TYPE_OBJECT_PATH, &session_id,
			                       DBUS_TYPE_INVALID)) {
			session_added (self, session_id);
		}
	}
	else
	if (dbus_message_is_signal (message,
		                        "org.freedesktop.ConsoleKit.Seat",
		                        "SessionRemoved")) {
		if (dbus_message_get_args (message, NULL,
		                           DBUS_TYPE_OBJECT_PATH, &session_id,
		                           DBUS_TYPE_INVALID)) {
			session_removed (self, session_id);
		}
	}

	// If anything else registers message filters for these signals for some
	// reason, we want to be sure not to step on them.
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

/**** get_session_of_caller stuff ********************************************/

typedef struct {
	NMSessionManager *manager;
	CallbackInfo *cb_info;
	DBusGProxy *bus_proxy;
	DBusGProxy *current_call_proxy;
	DBusGProxyCall *current_call;
	char *caller_bus_name;
	char *session_id;
} PendingCallerInfo;

static void
pending_caller_free (PendingCallerInfo *info)
{
	if (info->bus_proxy)
		g_object_unref (info->bus_proxy);

	if (info->caller_bus_name)
		g_free (info->caller_bus_name);

	if (info->session_id)
		g_free (info->session_id);

	// cb_info gets freed when the callback it wraps is run

	g_slice_free (PendingCallerInfo, info);
}

static void
pending_caller_dispose (gpointer data)
{
	PendingCallerInfo *info = (PendingCallerInfo *) data;

	if (info->current_call)
		dbus_g_proxy_cancel_call (info->current_call_proxy, info->current_call);

	callback_info_fail_disposed (info->cb_info);
	pending_caller_free (info);
}

static void
pending_caller_cb (NMSessionInfo *session, GError *error, gpointer user_data)
{
	PendingCallerInfo *info = (PendingCallerInfo *) user_data;

	if (!session) {
		get_session_internal (info->manager, NM_SESSION_INFO_DEFAULT_ID, info->cb_info);
	} else {
		callback_info_run (info->cb_info, session, error);
	}

	pending_caller_free (info);
}

static void
pending_caller_abort (PendingCallerInfo *info, GError *error)
{
	NMSessionManagerPrivate *priv = NM_SESSION_MANAGER_GET_PRIVATE (info->manager);

	priv->pending_callers = g_slist_remove (priv->pending_callers, info);
	pending_caller_cb (NULL, error, info);
}

static void
dbus_name_has_owner_cb (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	PendingCallerInfo *info = (PendingCallerInfo *) user_data;
	NMSessionManagerPrivate *priv = NM_SESSION_MANAGER_GET_PRIVATE (info->manager);
	gboolean has_owner;

	if (!dbus_g_proxy_end_call (proxy, call_id, NULL,
	                            G_TYPE_BOOLEAN, &has_owner, G_TYPE_INVALID)
	        || !has_owner) {
	    pending_caller_abort (info, NULL);
	    return;
	}

	info->current_call = NULL;
	info->current_call_proxy = NULL;
	priv->pending_callers = g_slist_remove (priv->pending_callers, info);

	nm_session_manager_get_session (info->manager, info->session_id,
	                                pending_caller_cb, info);
}

static void
ck_get_session_cb (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	PendingCallerInfo *info = (PendingCallerInfo *) user_data;

	if (!dbus_g_proxy_end_call (proxy, call_id, NULL,
	                            G_TYPE_STRING, &(info->session_id),
	                            G_TYPE_INVALID)) {
		pending_caller_abort (info, NULL);
	    return;
	}

	// Finally, ensure that the calling process is still there, so we are sure
	// that the process we've just examined is indeed the calling process.
	info->current_call = dbus_g_proxy_begin_call (info->bus_proxy,
	                                              "NameHasOwner",
	                                              dbus_name_has_owner_cb,
	                                              info,
	                                              NULL,
	                                              G_TYPE_STRING, info->caller_bus_name,
	                                              G_TYPE_INVALID);
	info->current_call_proxy = info->bus_proxy;
}

static void
dbus_get_pid_cb (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	PendingCallerInfo *info = (PendingCallerInfo *) user_data;
	NMSessionManagerPrivate *priv = NM_SESSION_MANAGER_GET_PRIVATE (info->manager);
	guint pid;

	if (!dbus_g_proxy_end_call (proxy, call_id, NULL,
	                            G_TYPE_UINT, &pid, G_TYPE_INVALID)) {
		pending_caller_abort (info, NULL);
	    return;
	}

	info->current_call = dbus_g_proxy_begin_call (priv->ck_manager,
	                                              "GetSessionForUnixProcess",
	                                              ck_get_session_cb,
	                                              info,
	                                              NULL,
	                                              G_TYPE_UINT, pid,
	                                              G_TYPE_INVALID);
	info->current_call_proxy = priv->ck_manager;
}

static void
get_session_of_caller_internal (NMSessionManager *manager, 
                                DBusGMethodInvocation *method_call,
                                CallbackInfo *cb_info)
{
	NMSessionManagerPrivate *priv = NM_SESSION_MANAGER_GET_PRIVATE (manager);
	DBusGConnection *connection;
	PendingCallerInfo *info;

	if (priv->disposed) {
		callback_info_fail_disposed (cb_info);
		return;
	}
	connection = nm_dbus_manager_get_connection (nm_dbus_manager_get());

	info = g_slice_new (PendingCallerInfo);
	info->manager = manager;
	info->cb_info = cb_info;
	info->caller_bus_name = dbus_g_method_get_sender (method_call);
	info->bus_proxy = dbus_g_proxy_new_for_name (connection,
	                                             "org.freedesktop.DBus",
	                                             "/org/freedesktop/DBus",
	                                             "org.freedesktop.DBus");

	info->current_call = dbus_g_proxy_begin_call (info->bus_proxy,
	                                              "GetConnectionUnixProcessID",
	                                              dbus_get_pid_cb,
	                                              info,
	                                              NULL,
	                                              G_TYPE_STRING, info->caller_bus_name,
	                                              G_TYPE_INVALID);
	info->current_call_proxy = info->bus_proxy;

	priv->pending_callers = g_slist_prepend (priv->pending_callers, info);

	g_object_unref (connection);
}

void
nm_session_manager_get_session_of_caller (NMSessionManager *manager, 
                                          DBusGMethodInvocation *method_call,
                                          NMSessionFunc callback, 
                                          gpointer user_data)
{
	CallbackInfo *cb_info;

	g_return_if_fail (NM_IS_SESSION_MANAGER (manager));
	g_return_if_fail (method_call != NULL);

	cb_info = callback_info_new (callback, user_data);

	get_session_of_caller_internal (manager, method_call, cb_info);
}


/**** Initialization & disposal **********************************************/

gboolean
nm_session_manager_is_initialized (NMSessionManager *self)
{
	g_return_val_if_fail (NM_IS_SESSION_MANAGER (self), FALSE);

	return NM_SESSION_MANAGER_GET_PRIVATE (self)->initialized;
}

/* Callback run for sessions loaded during initialization. Emits the
 * "initialized" signal when all sessions are loaded. */
static void
init_session_load_cb (NMSessionInfo *session, GError *error, gpointer user_data)
{
	NMSessionManager *self = NM_SESSION_MANAGER (user_data);
	NMSessionManagerPrivate *priv = NM_SESSION_MANAGER_GET_PRIVATE (self);

	priv->init_sessions_left--;
	if (priv->init_sessions_left == 0) {
		priv->initialized = TRUE;
		g_signal_emit (self, signals[INIT_DONE], 0);
	}
}

static void
ck_get_sessions_cb (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMSessionManager *self = NM_SESSION_MANAGER (user_data);
	NMSessionManagerPrivate *priv = NM_SESSION_MANAGER_GET_PRIVATE (self);
	GPtrArray *session_ids;
	int i;

	g_assert (priv->initialized == FALSE);
	
	if (!dbus_g_proxy_end_call (proxy, call_id, NULL,
	                            DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH, &session_ids,
	                            G_TYPE_INVALID)) {
	    nm_log_err (LOGD_SYS_SET, "failed to get initial ConsoleKit session list");
	    return;
	}

	priv->init_sessions_left = session_ids->len;
	if (priv->init_sessions_left > 0) {
		for (i = 0; i < session_ids->len; i++) {
			char *session_id = g_ptr_array_index (session_ids, i);
			nm_session_manager_get_session (self, session_id, init_session_load_cb, self);
			g_free (session_id);
		}
	} else {
		/* Make sure we send the init-done signal if there aren't any sessions */
		priv->initialized = TRUE;
		g_signal_emit (self, signals[INIT_DONE], 0);
	}
	g_ptr_array_free (session_ids, TRUE);
}

static void
nm_session_manager_init (NMSessionManager *self)
{
	NMSessionManagerPrivate *priv = NM_SESSION_MANAGER_GET_PRIVATE (self);
	NMSessionInfo *default_session;
	DBusGConnection *g_connection = nm_dbus_manager_get_connection (nm_dbus_manager_get());
	DBusConnection *connection = dbus_g_connection_get_connection (g_connection);

	priv->disposed = FALSE;
	priv->initialized = FALSE;
	priv->sessions = g_hash_table_new_full (g_str_hash, g_str_equal, 
	                                        NULL, g_object_unref);
	priv->pending_sessions = g_hash_table_new_full (g_str_hash, g_str_equal, 
	                                                NULL, pending_session_destroy);
	priv->pending_callers = NULL;

	default_session = NM_SESSION_INFO (g_object_new (NM_TYPE_SESSION_INFO,
	                                                 NM_SESSION_INFO_IS_DEFAULT, TRUE,
	                                                 NM_SESSION_INFO_ID, NM_SESSION_INFO_DEFAULT_ID,
	                                                 NULL));
	g_hash_table_insert (priv->sessions, 
	                     NM_SESSION_INFO_DEFAULT_ID, default_session);


	priv->ck_manager = dbus_g_proxy_new_for_name (g_connection,
	                                              "org.freedesktop.ConsoleKit",
	                                              "/org/freedesktop/ConsoleKit/Manager",
	                                              "org.freedesktop.ConsoleKit.Manager");

	// Setup a signal handler to catch SessionAdded/Removed signals for *all*
	// seats, all in one shot.
	dbus_connection_add_filter (connection,
	                            ck_session_signal_filter,
	                            self,
	                            NULL);
	dbus_bus_add_match (connection,
	                    "type='signal',sender='org.freedesktop.ConsoleKit',"
	                    "interface='org.freedesktop.ConsoleKit.Seat',member='SessionAdded'",
	                    NULL);
	dbus_bus_add_match (connection,
	                    "type='signal',sender='org.freedesktop.ConsoleKit',"
	                    "interface='org.freedesktop.ConsoleKit.Seat',member='SessionRemoved'",
	                    NULL);

	dbus_g_proxy_begin_call (priv->ck_manager,
	                         "GetSessions",
	                         ck_get_sessions_cb,
	                         self,
	                         NULL,
	                         G_TYPE_INVALID);
}

static void
dispose (GObject *object)
{
	NMSessionManagerPrivate *priv = NM_SESSION_MANAGER_GET_PRIVATE (object);
	DBusConnection *connection = nm_dbus_manager_get_dbus_connection (nm_dbus_manager_get ());

	if (priv->disposed)
		return;

	priv->disposed = TRUE;

	dbus_connection_remove_filter (connection, ck_session_signal_filter, object);
	nm_utils_slist_free (priv->pending_callers, pending_caller_dispose);
	g_hash_table_unref (priv->pending_sessions);
	g_hash_table_unref (priv->sessions);
	g_object_unref(priv->ck_manager);

	G_OBJECT_CLASS (nm_session_manager_parent_class)->dispose (object);	
}

static void
nm_session_manager_class_init (NMSessionManagerClass *manager_class)
{
	GObjectClass *g_class = G_OBJECT_CLASS (manager_class);

	g_type_class_add_private (g_class, sizeof(NMSessionManagerPrivate));	
	g_class->dispose = dispose;

	signals[ADDED] = 
		g_signal_new (NM_SESSION_MANAGER_SESSION_ADDED,
		              NM_TYPE_SESSION_MANAGER,
		              G_SIGNAL_RUN_FIRST,
		              0,
		              NULL, NULL,
		              g_cclosure_marshal_VOID__OBJECT,
		              G_TYPE_NONE,
		              1, NM_TYPE_SESSION_INFO);

	signals[INIT_DONE] =
		g_signal_new (NM_SESSION_MANAGER_INIT_DONE,
		              NM_TYPE_SESSION_MANAGER,
		              G_SIGNAL_RUN_FIRST,
		              0,
		              NULL, NULL,
		              g_cclosure_marshal_VOID__VOID,
		              G_TYPE_NONE,
		              0);
}

NMSessionManager *
nm_session_manager_get (void)
{
	static NMSessionManager *singleton = NULL;

	if (!singleton) {
		singleton = NM_SESSION_MANAGER (g_object_new (NM_TYPE_SESSION_MANAGER, NULL));
	}

	return singleton;
}

GQuark
nm_session_manager_error_quark (void)
{
	static GQuark ret = 0;

	if (ret == 0) {
		ret = g_quark_from_string ("nm-session-manager-error");
	}

	return ret;
}
