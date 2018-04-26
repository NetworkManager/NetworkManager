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
 * Copyright (C) 2014 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-auth-manager.h"

#include "c-list/src/c-list.h"
#include "nm-errors.h"
#include "nm-core-internal.h"
#include "NetworkManagerUtils.h"

#define POLKIT_SERVICE                      "org.freedesktop.PolicyKit1"
#define POLKIT_OBJECT_PATH                  "/org/freedesktop/PolicyKit1/Authority"
#define POLKIT_INTERFACE                    "org.freedesktop.PolicyKit1.Authority"

#define CANCELLATION_ID_PREFIX "cancellation-id-"
#define CANCELLATION_TIMEOUT_MS 5000

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_POLKIT_ENABLED,
);

enum {
	CHANGED_SIGNAL,
	LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = {0};

typedef struct {
	CList calls_lst_head;
	GDBusProxy *proxy;
	GCancellable *new_proxy_cancellable;
	GCancellable *cancel_cancellable;
	guint64 call_numid_counter;
	bool polkit_enabled:1;
	bool disposing:1;
	bool shutting_down:1;
} NMAuthManagerPrivate;

struct _NMAuthManager {
	GObject parent;
	NMAuthManagerPrivate _priv;
};

struct _NMAuthManagerClass {
	GObjectClass parent;
};

G_DEFINE_TYPE (NMAuthManager, nm_auth_manager, G_TYPE_OBJECT)

#define NM_AUTH_MANAGER_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMAuthManager, NM_IS_AUTH_MANAGER)

NM_DEFINE_SINGLETON_REGISTER (NMAuthManager);

/*****************************************************************************/

#define _NMLOG_PREFIX_NAME    "auth"
#define _NMLOG_DOMAIN         LOGD_CORE
#define _NMLOG(level, ...) \
    G_STMT_START { \
        if (nm_logging_enabled ((level), (_NMLOG_DOMAIN))) { \
            char __prefix[30] = _NMLOG_PREFIX_NAME; \
            \
            if ((self) != singleton_instance) \
                g_snprintf (__prefix, sizeof (__prefix), ""_NMLOG_PREFIX_NAME"[%p]", (self)); \
            _nm_log ((level), (_NMLOG_DOMAIN), 0, NULL, NULL, \
                     "%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
                     __prefix _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
        } \
    } G_STMT_END

#define _NMLOG2(level, call_id, ...) \
    G_STMT_START { \
        if (nm_logging_enabled ((level), (_NMLOG_DOMAIN))) { \
            NMAuthManagerCallId *_call_id = (call_id); \
            char __prefix[30] = _NMLOG_PREFIX_NAME; \
            \
            if (_call_id->self != singleton_instance) \
                g_snprintf (__prefix, sizeof (__prefix), ""_NMLOG_PREFIX_NAME"[%p]", _call_id->self); \
            _nm_log ((level), (_NMLOG_DOMAIN), 0, NULL, NULL, \
                     "%s: call[%"G_GUINT64_FORMAT"]: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
                     __prefix, \
                     _call_id->call_numid \
                     _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
        } \
    } G_STMT_END

/*****************************************************************************/

gboolean
nm_auth_manager_get_polkit_enabled (NMAuthManager *self)
{
	g_return_val_if_fail (NM_IS_AUTH_MANAGER (self), FALSE);

	return NM_AUTH_MANAGER_GET_PRIVATE (self)->polkit_enabled;
}

/*****************************************************************************/

typedef enum {
	POLKIT_CHECK_AUTHORIZATION_FLAGS_NONE                   = 0,
	POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION = (1<<0),
} PolkitCheckAuthorizationFlags;

typedef enum {
	IDLE_REASON_AUTHORIZED,
	IDLE_REASON_NO_DBUS,
} IdleReason;

struct _NMAuthManagerCallId {
	CList calls_lst;
	NMAuthManager *self;
	GVariant *dbus_parameters;
	GCancellable *dbus_cancellable;
	NMAuthManagerCheckAuthorizationCallback callback;
	gpointer user_data;
	guint64 call_numid;
	guint idle_id;
	IdleReason idle_reason:8;
};

#define cancellation_id_to_str_a(call_numid) \
	nm_sprintf_bufa (NM_STRLEN (CANCELLATION_ID_PREFIX) + 20, \
	                 CANCELLATION_ID_PREFIX"%"G_GUINT64_FORMAT, \
	                 (call_numid))

static void
_call_id_free (NMAuthManagerCallId *call_id)
{
	c_list_unlink (&call_id->calls_lst);
	nm_clear_g_source (&call_id->idle_id);
	if (call_id->dbus_parameters)
		g_variant_unref (g_steal_pointer (&call_id->dbus_parameters));

	if (call_id->dbus_cancellable) {
		/* we have a pending D-Bus call. We keep the call-id instance alive
		 * for _call_check_authorize_cb() */
		g_cancellable_cancel (call_id->dbus_cancellable);
		return;
	}

	g_object_unref (call_id->self);
	g_slice_free (NMAuthManagerCallId, call_id);
}

static void
_call_id_invoke_callback (NMAuthManagerCallId *call_id,
                          gboolean is_authorized,
                          gboolean is_challenge,
                          GError *error)
{
	c_list_unlink (&call_id->calls_lst);

	call_id->callback (call_id->self,
	                   call_id,
	                   is_authorized,
	                   is_challenge,
	                   error,
	                   call_id->user_data);
	_call_id_free (call_id);
}

static void
cancel_check_authorization_cb (GObject *proxy,
                               GAsyncResult *res,
                               gpointer user_data)
{
	NMAuthManagerCallId *call_id = user_data;
	gs_unref_variant GVariant *value = NULL;
	gs_free_error GError *error= NULL;

	value = g_dbus_proxy_call_finish (G_DBUS_PROXY (proxy), res, &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		_LOG2T (call_id, "cancel request was cancelled");
	else if (error)
		_LOG2T (call_id, "cancel request failed: %s", error->message);
	else
		_LOG2T (call_id, "cancel request succeeded");

	_call_id_free (call_id);
}

static void
_call_check_authorize_cb (GObject *proxy,
                          GAsyncResult *res,
                          gpointer user_data)
{
	NMAuthManagerCallId *call_id = user_data;
	NMAuthManager *self;
	NMAuthManagerPrivate *priv;
	gs_unref_variant GVariant *value = NULL;
	gs_free_error GError *error = NULL;
	gboolean is_authorized = FALSE;
	gboolean is_challenge = FALSE;

	/* we need to clear the cancelable, to signal for _call_id_free() that we
	 * are not in a pending call.
	 *
	 * Note how _call_id_free() kept call-id alive, even if the request was
	 * already cancelled. */
	g_clear_object (&call_id->dbus_cancellable);

	self = call_id->self;
	priv = NM_AUTH_MANAGER_GET_PRIVATE (self);

	value = _nm_dbus_proxy_call_finish (G_DBUS_PROXY (proxy), res, G_VARIANT_TYPE ("((bba{ss}))"), &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		/* call_id was cancelled externally, but _call_id_free() kept call_id
		 * alive (and it has still the reference on @self. */

		if (!priv->cancel_cancellable) {
			/* we do a forced shutdown. There is no more time for cancelling... */
			_call_id_free (call_id);

			/* this shouldn't really happen, because:
			 * _call_check_authorize() only scheduled the D-Bus request at a time when
			 * cancel_cancellable was still set. It means, somebody called force-shutdown
			 * after call-id was schedule.
			 * force-shutdown should only be called after:
			 *   - cancel all pending requests
			 *   - give enough time to cancel the request and schedule a D-Bus call
			 *     to CancelCheckAuthorization (below), before issuing force-shutdown. */
			g_return_if_reached ();
		}

		g_dbus_proxy_call (priv->proxy,
		                   "CancelCheckAuthorization",
		                   g_variant_new ("(s)",
		                                  cancellation_id_to_str_a (call_id->call_numid)),
		                   G_DBUS_CALL_FLAGS_NONE,
		                   CANCELLATION_TIMEOUT_MS,
		                   priv->cancel_cancellable,
		                   cancel_check_authorization_cb,
		                   call_id);
		return;
	}

	if (!error) {
		g_variant_get (value,
		               "((bb@a{ss}))",
		               &is_authorized,
		               &is_challenge,
		               NULL);
		_LOG2T (call_id, "completed: authorized=%d, challenge=%d",
		        is_authorized, is_challenge);
	} else
		_LOG2T (call_id, "completed: failed: %s", error->message);

	_call_id_invoke_callback (call_id, is_authorized, is_challenge, error);
}

static void
_call_check_authorize (NMAuthManagerCallId *call_id)
{
	NMAuthManager *self = call_id->self;
	NMAuthManagerPrivate *priv = NM_AUTH_MANAGER_GET_PRIVATE (self);

	nm_assert (call_id->dbus_parameters);
	nm_assert (g_variant_is_floating (call_id->dbus_parameters));
	nm_assert (!call_id->dbus_cancellable);

	call_id->dbus_cancellable = g_cancellable_new ();

	nm_assert (priv->cancel_cancellable);

	g_dbus_proxy_call (priv->proxy,
	                   "CheckAuthorization",
	                   g_steal_pointer (&call_id->dbus_parameters),
	                   G_DBUS_CALL_FLAGS_NONE,
	                   G_MAXINT, /* no timeout */
	                   call_id->dbus_cancellable,
	                   _call_check_authorize_cb,
	                   call_id);
}

static gboolean
_call_on_idle (gpointer user_data)
{
	NMAuthManagerCallId *call_id = user_data;
	gs_free_error GError *error = NULL;
	gboolean is_authorized = FALSE;
	gboolean is_challenge = FALSE;
	const char *error_msg = NULL;

	call_id->idle_id = 0;
	if (call_id->idle_reason == IDLE_REASON_AUTHORIZED) {
		is_authorized = TRUE;
		_LOG2T (call_id, "completed: authorized=%d, challenge=%d (simulated)",
		        is_authorized, is_challenge);
	} else {
		nm_assert (call_id->idle_reason == IDLE_REASON_NO_DBUS);
		error_msg = "failure creating GDBusProxy for authorization request";
		_LOG2T (call_id, "completed: failed due to no D-Bus proxy");
	}

	if (error_msg)
		g_set_error_literal (&error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN, error_msg);
	_call_id_invoke_callback (call_id, is_authorized, is_challenge, error);
	return G_SOURCE_REMOVE;
}

/*
 * @callback must never be invoked synchronously.
 *
 * @callback is always invoked exactly once, and never synchronously.
 * You may cancel the invocation with nm_auth_manager_check_authorization_cancel(),
 * but: you may only do so exactly once, and only before @callback is
 * invoked. Even if you cancel the request, @callback will still be invoked
 * (synchronously, during the _cancel() callback).
 *
 * The request keeps @self alive (it needs to do so, because when cancelling a
 * request we might need to do an additional CancelCheckAuthorization call, for
 * which @self must be live long enough).
 */
NMAuthManagerCallId *
nm_auth_manager_check_authorization (NMAuthManager *self,
                                     NMAuthSubject *subject,
                                     const char *action_id,
                                     gboolean allow_user_interaction,
                                     NMAuthManagerCheckAuthorizationCallback callback,
                                     gpointer user_data)
{
	NMAuthManagerPrivate *priv;
	PolkitCheckAuthorizationFlags flags;
	char subject_buf[64];
	GVariantBuilder builder;
	GVariant *subject_value;
	GVariant *details_value;
	NMAuthManagerCallId *call_id;

	g_return_val_if_fail (NM_IS_AUTH_MANAGER (self), NULL);
	g_return_val_if_fail (NM_IN_SET (nm_auth_subject_get_subject_type (subject),
	                                 NM_AUTH_SUBJECT_TYPE_INTERNAL,
	                                 NM_AUTH_SUBJECT_TYPE_UNIX_PROCESS),
	                      NULL);
	g_return_val_if_fail (action_id, NULL);

	priv = NM_AUTH_MANAGER_GET_PRIVATE (self);

	g_return_val_if_fail (!priv->disposing, NULL);
	g_return_val_if_fail (!priv->shutting_down, NULL);

	flags = allow_user_interaction
	    ? POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION
	    : POLKIT_CHECK_AUTHORIZATION_FLAGS_NONE;

	call_id = g_slice_new0 (NMAuthManagerCallId);
	call_id->self = g_object_ref (self);
	call_id->callback = callback;
	call_id->user_data = user_data;
	call_id->call_numid = ++priv->call_numid_counter;
	c_list_link_tail (&priv->calls_lst_head, &call_id->calls_lst);

	if (!priv->polkit_enabled) {
		_LOG2T (call_id, "CheckAuthorization(%s), subject=%s (succeeding due to polkit authorization disabled)", action_id, nm_auth_subject_to_string (subject, subject_buf, sizeof (subject_buf)));
		call_id->idle_reason = IDLE_REASON_AUTHORIZED;
		call_id->idle_id = g_idle_add (_call_on_idle, call_id);
	} else if (nm_auth_subject_is_internal (subject)) {
		_LOG2T (call_id, "CheckAuthorization(%s), subject=%s (succeeding for internal request)", action_id, nm_auth_subject_to_string (subject, subject_buf, sizeof (subject_buf)));
		call_id->idle_reason = IDLE_REASON_AUTHORIZED;
		call_id->idle_id = g_idle_add (_call_on_idle, call_id);
	} else if (nm_auth_subject_get_unix_process_uid (subject) == 0) {
		_LOG2T (call_id, "CheckAuthorization(%s), subject=%s (succeeding for root)", action_id, nm_auth_subject_to_string (subject, subject_buf, sizeof (subject_buf)));
		call_id->idle_reason = IDLE_REASON_AUTHORIZED;
		call_id->idle_id = g_idle_add (_call_on_idle, call_id);
	} else if (   !priv->proxy
	           && !priv->new_proxy_cancellable) {
		_LOG2T (call_id, "CheckAuthorization(%s), subject=%s (failing due to invalid DBUS proxy)", action_id, nm_auth_subject_to_string (subject, subject_buf, sizeof (subject_buf)));
		call_id->idle_reason = IDLE_REASON_NO_DBUS;
		call_id->idle_id = g_idle_add (_call_on_idle, call_id);
	} else {
		subject_value = nm_auth_subject_unix_process_to_polkit_gvariant (subject);
		nm_assert (g_variant_is_floating (subject_value));

		/* ((PolkitDetails *)NULL) */
		g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{ss}"));
		details_value = g_variant_builder_end (&builder);

		call_id->dbus_parameters = g_variant_new ("(@(sa{sv})s@a{ss}us)",
		                                          subject_value,
		                                          action_id,
		                                          details_value,
		                                          (guint32) flags,
		                                          cancellation_id_to_str_a (call_id->call_numid));
		if (!priv->proxy) {
			_LOG2T (call_id, "CheckAuthorization(%s), subject=%s (wait for proxy)", action_id, nm_auth_subject_to_string (subject, subject_buf, sizeof (subject_buf)));
		} else {
			_LOG2T (call_id, "CheckAuthorization(%s), subject=%s", action_id, nm_auth_subject_to_string (subject, subject_buf, sizeof (subject_buf)));
			_call_check_authorize (call_id);
		}
	}

	return call_id;
}

void
nm_auth_manager_check_authorization_cancel (NMAuthManagerCallId *call_id)
{
	NMAuthManager *self;
	gs_free_error GError *error = NULL;

	g_return_if_fail (call_id);

	self = call_id->self;

	g_return_if_fail (NM_IS_AUTH_MANAGER (self));
	g_return_if_fail (!c_list_is_empty (&call_id->calls_lst));

	nm_assert (c_list_contains (&NM_AUTH_MANAGER_GET_PRIVATE (self)->calls_lst_head, &call_id->calls_lst));

	nm_utils_error_set_cancelled (&error, FALSE, "NMAuthManager");
	_LOG2T (call_id, "completed: failed due to call cancelled");
	_call_id_invoke_callback (call_id,
	                          FALSE,
	                          FALSE,
	                          error);
}

/*****************************************************************************/

static void
_emit_changed_signal (NMAuthManager *self)
{
	_LOGD ("emit changed signal");
	g_signal_emit (self, signals[CHANGED_SIGNAL], 0);
}

static void
_log_name_owner (NMAuthManager *self, char **out_name_owner)
{
	NMAuthManagerPrivate *priv = NM_AUTH_MANAGER_GET_PRIVATE (self);
	gs_free char *name_owner = NULL;

	name_owner = g_dbus_proxy_get_name_owner (priv->proxy);
	if (name_owner)
		_LOGD ("dbus name owner: '%s'", name_owner);
	else
		_LOGD ("dbus name owner: none");

	NM_SET_OUT (out_name_owner, g_steal_pointer (&name_owner));
}

static void
_dbus_on_name_owner_notify_cb (GObject    *object,
                               GParamSpec *pspec,
                               gpointer    user_data)
{
	NMAuthManager *self = user_data;
	gs_free char *name_owner = NULL;

	nm_assert (NM_AUTH_MANAGER_GET_PRIVATE (self)->proxy == (GDBusProxy *) object);

	_log_name_owner (self, &name_owner);
	if (!name_owner) {
		/* when the name disappears, we also want to raise a emit signal.
		 * When it appears, we raise one already. */
		_emit_changed_signal (self);
	}
}

static void
_dbus_on_changed_signal_cb (GDBusProxy *proxy,
                            gpointer    user_data)
{
	NMAuthManager *self = user_data;

	nm_assert (NM_AUTH_MANAGER_GET_PRIVATE (self)->proxy == proxy);

	_LOGD ("dbus signal: \"Changed\"");
	_emit_changed_signal (self);
}

static void
_dbus_new_proxy_cb (GObject *source_object,
                    GAsyncResult *res,
                    gpointer user_data)
{
	NMAuthManager *self;
	NMAuthManagerPrivate *priv;
	gs_free_error GError *error = NULL;
	GDBusProxy *proxy;
	NMAuthManagerCallId *call_id;

	proxy = g_dbus_proxy_new_for_bus_finish  (res, &error);

	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = user_data;
	priv = NM_AUTH_MANAGER_GET_PRIVATE (self);

	priv->proxy = proxy;
	g_clear_object (&priv->new_proxy_cancellable);

	if (!priv->proxy) {
		_LOGE ("could not create polkit proxy: %s", error->message);

again:
		c_list_for_each_entry (call_id, &priv->calls_lst_head, calls_lst) {
			if (call_id->dbus_parameters) {
				_LOG2T (call_id, "completed: failed due to no D-Bus proxy after startup");
				_call_id_invoke_callback (call_id, FALSE, FALSE, error);
				goto again;
			}
		}
		return;
	}

	priv->cancel_cancellable = g_cancellable_new ();

	g_signal_connect (priv->proxy,
	                  "notify::g-name-owner",
	                  G_CALLBACK (_dbus_on_name_owner_notify_cb),
	                  self);
	_nm_dbus_signal_connect (priv->proxy, "Changed", NULL,
	                         G_CALLBACK (_dbus_on_changed_signal_cb),
	                         self);

	_log_name_owner (self, NULL);

	c_list_for_each_entry (call_id, &priv->calls_lst_head, calls_lst) {
		if (call_id->dbus_parameters) {
			_LOG2T (call_id, "CheckAuthorization invoke now");
			_call_check_authorize (call_id);
		}
	}

	_emit_changed_signal (self);
}

/*****************************************************************************/

NMAuthManager *
nm_auth_manager_get ()
{
	g_return_val_if_fail (singleton_instance, NULL);

	return singleton_instance;
}

void
nm_auth_manager_force_shutdown (NMAuthManager *self)
{
	NMAuthManagerPrivate *priv;

	g_return_if_fail (NM_IS_AUTH_MANAGER (self));

	priv = NM_AUTH_MANAGER_GET_PRIVATE (self);

	/* while we have pending requests (NMAuthManagerCallId), the instance
	 * is kept alive.
	 *
	 * Even if the caller cancells all pending call-ids, we still need to keep
	 * a reference to self, in order to handle pending CancelCheckAuthorization
	 * requests.
	 *
	 * To do a corrdinated shutdown, do the following:
	 * - cancel all pending NMAuthManagerCallId requests.
	 * - ensure everybody unrefs the NMAuthManager instance. If by that, the instance
	 *   gets destroyed, the shutdown already completed successfully.
	 * - Otherwise, the object is kept alive by pending CancelCheckAuthorization requests.
	 *   wait a certain timeout (1 second) for all requests to complete (by watching
	 *   for destruction of NMAuthManager).
	 * - if that doesn't happen within timeout, issue nm_auth_manager_force_shutdown() and
	 *   wait longer. After that, soon the instance should be destroyed and you
	 *   did a successful shutdown.
	 * - if the instance was still not destroyed within a short timeout, you leaked
	 *   resources. You cannot properly shutdown.
	 */

	priv->shutting_down = TRUE;
	nm_clear_g_cancellable (&priv->cancel_cancellable);
}

/*****************************************************************************/

static void
set_property (GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
	NMAuthManagerPrivate *priv = NM_AUTH_MANAGER_GET_PRIVATE ((NMAuthManager *) object);

	switch (prop_id) {
	case PROP_POLKIT_ENABLED:
		/* construct-only */
		priv->polkit_enabled = !!g_value_get_boolean (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_auth_manager_init (NMAuthManager *self)
{
	NMAuthManagerPrivate *priv = NM_AUTH_MANAGER_GET_PRIVATE (self);

	c_list_init (&priv->calls_lst_head);
}

static void
constructed (GObject *object)
{
	NMAuthManager *self = NM_AUTH_MANAGER (object);
	NMAuthManagerPrivate *priv = NM_AUTH_MANAGER_GET_PRIVATE (self);

	G_OBJECT_CLASS (nm_auth_manager_parent_class)->constructed (object);

	_LOGD ("create auth-manager: polkit %s", priv->polkit_enabled ? "enabled" : "disabled");

	if (priv->polkit_enabled) {
		priv->new_proxy_cancellable = g_cancellable_new ();
		g_dbus_proxy_new_for_bus (G_BUS_TYPE_SYSTEM,
		                          G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
		                          NULL,
		                          POLKIT_SERVICE,
		                          POLKIT_OBJECT_PATH,
		                          POLKIT_INTERFACE,
		                          priv->new_proxy_cancellable,
		                          _dbus_new_proxy_cb,
		                          self);
	}
}

NMAuthManager *
nm_auth_manager_setup (gboolean polkit_enabled)
{
	NMAuthManager *self;

	g_return_val_if_fail (!singleton_instance, singleton_instance);

	self = g_object_new (NM_TYPE_AUTH_MANAGER,
	                     NM_AUTH_MANAGER_POLKIT_ENABLED, polkit_enabled,
	                     NULL);
	_LOGD ("set instance");

	singleton_instance = self;
	nm_singleton_instance_register ();

	nm_log_dbg (LOGD_CORE, "setup %s singleton (%p)", "NMAuthManager", singleton_instance);

	return self;
}

static void
dispose (GObject *object)
{
	NMAuthManager* self = NM_AUTH_MANAGER (object);
	NMAuthManagerPrivate *priv = NM_AUTH_MANAGER_GET_PRIVATE (self);

	_LOGD ("dispose");

	nm_assert (c_list_is_empty (&priv->calls_lst_head));

	priv->disposing = TRUE;

	nm_clear_g_cancellable (&priv->new_proxy_cancellable);
	nm_clear_g_cancellable (&priv->cancel_cancellable);

	if (priv->proxy) {
		g_signal_handlers_disconnect_by_data (priv->proxy, self);
		g_clear_object (&priv->proxy);
	}

	G_OBJECT_CLASS (nm_auth_manager_parent_class)->dispose (object);
}

static void
nm_auth_manager_class_init (NMAuthManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->set_property = set_property;
	object_class->constructed = constructed;
	object_class->dispose = dispose;

	obj_properties[PROP_POLKIT_ENABLED] =
	     g_param_spec_boolean (NM_AUTH_MANAGER_POLKIT_ENABLED, "", "",
	                           FALSE,
	                           G_PARAM_WRITABLE |
	                           G_PARAM_CONSTRUCT_ONLY |
	                           G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	signals[CHANGED_SIGNAL] = g_signal_new (NM_AUTH_MANAGER_SIGNAL_CHANGED,
	                                        NM_TYPE_AUTH_MANAGER,
	                                        G_SIGNAL_RUN_LAST,
	                                        0, NULL, NULL,
	                                        g_cclosure_marshal_VOID__VOID,
	                                        G_TYPE_NONE, 0);
}
