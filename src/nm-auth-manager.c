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

#include "config.h"

#include "nm-auth-manager.h"

#include "nm-logging.h"
#include "nm-errors.h"
#include "nm-core-internal.h"
#include "NetworkManagerUtils.h"

#define POLKIT_SERVICE                      "org.freedesktop.PolicyKit1"
#define POLKIT_OBJECT_PATH                  "/org/freedesktop/PolicyKit1/Authority"
#define POLKIT_INTERFACE                    "org.freedesktop.PolicyKit1.Authority"


#define _LOG_DEFAULT_DOMAIN  LOGD_CORE

#define _LOG(level, domain, ...) \
    G_STMT_START { \
        if (nm_logging_enabled ((level), (domain))) { \
            char __prefix[30] = "auth"; \
            \
            if ((self) != singleton_instance) \
                g_snprintf (__prefix, sizeof (__prefix), "auth[%p]", (self)); \
            _nm_log ((level), (domain), 0, \
                     "%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
                     __prefix _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
        } \
    } G_STMT_END

#define _LOGD(...)      _LOG (LOGL_DEBUG, _LOG_DEFAULT_DOMAIN, __VA_ARGS__)
#define _LOGI(...)      _LOG (LOGL_INFO,  _LOG_DEFAULT_DOMAIN, __VA_ARGS__)
#define _LOGW(...)      _LOG (LOGL_WARN,  _LOG_DEFAULT_DOMAIN, __VA_ARGS__)
#define _LOGE(...)      _LOG (LOGL_ERR,   _LOG_DEFAULT_DOMAIN, __VA_ARGS__)


enum {
	PROP_0,
	PROP_POLKIT_ENABLED,

	LAST_PROP
};

enum {
	CHANGED_SIGNAL,

	LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = {0};

typedef struct {
	gboolean polkit_enabled;
#if WITH_POLKIT
	guint call_id_counter;
	GCancellable *new_proxy_cancellable;
	GSList *queued_calls;
	GDBusProxy *proxy;
#endif
} NMAuthManagerPrivate;

NM_DEFINE_SINGLETON_REGISTER (NMAuthManager);

G_DEFINE_TYPE (NMAuthManager, nm_auth_manager, G_TYPE_OBJECT)

#define NM_AUTH_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_AUTH_MANAGER, NMAuthManagerPrivate))

/*****************************************************************************/

gboolean
nm_auth_manager_get_polkit_enabled (NMAuthManager *self)
{
	g_return_val_if_fail (NM_IS_AUTH_MANAGER (self), FALSE);

	return NM_AUTH_MANAGER_GET_PRIVATE (self)->polkit_enabled;
}

/*****************************************************************************/

#if WITH_POLKIT

typedef enum {
	POLKIT_CHECK_AUTHORIZATION_FLAGS_NONE                   = 0,
	POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION = (1<<0),
} PolkitCheckAuthorizationFlags;

typedef struct {
	guint call_id;
	NMAuthManager *self;
	GSimpleAsyncResult *simple;
	gchar *cancellation_id;
	GVariant *dbus_parameters;
	GCancellable *cancellable;
} CheckAuthData;

static void
_check_auth_data_free (CheckAuthData *data)
{
	if (data->dbus_parameters)
		g_variant_unref (data->dbus_parameters);
	g_object_unref (data->self);
	g_object_unref (data->simple);
	g_clear_object (&data->cancellable);
	g_free (data->cancellation_id);
	g_free (data);
}

static void
_call_check_authorization_complete_with_error (CheckAuthData *data,
                                               const char *error_message)
{
	NMAuthManager *self = data->self;

	_LOGD ("call[%u]: CheckAuthorization failed due to internal error: %s", data->call_id, error_message);
	g_simple_async_result_set_error (data->simple,
	                                 NM_MANAGER_ERROR,
	                                 NM_MANAGER_ERROR_FAILED,
	                                 "Authorization check failed: %s",
	                                 error_message);

	g_simple_async_result_complete_in_idle (data->simple);

	_check_auth_data_free (data);
}

static void
cancel_check_authorization_cb (GDBusProxy *proxy,
                               GAsyncResult *res,
                               gpointer user_data)
{
	NMAuthManager *self = user_data;
	GVariant *value;
	GError *error= NULL;

	value = g_dbus_proxy_call_finish (proxy, res, &error);
	if (value == NULL) {
		g_dbus_error_strip_remote_error (error);
		_LOGD ("Error cancelling authorization check: %s", error->message);
		g_error_free (error);
	} else
		g_variant_unref (value);

	g_object_unref (self);
}

typedef struct {
	gboolean is_authorized;
	gboolean is_challenge;
} CheckAuthorizationResult;

static void
check_authorization_cb (GDBusProxy *proxy,
                        GAsyncResult *res,
                        gpointer user_data)
{
	CheckAuthData *data = user_data;
	NMAuthManager *self = data->self;
	NMAuthManagerPrivate *priv = NM_AUTH_MANAGER_GET_PRIVATE (self);
	GVariant *value;
	GError *error = NULL;

	value = _nm_dbus_proxy_call_finish (proxy, res, G_VARIANT_TYPE ("((bba{ss}))"), &error);
	if (value == NULL) {
		if (data->cancellation_id != NULL &&
		    (!g_dbus_error_is_remote_error (error) &&
		     error->domain == G_IO_ERROR &&
		     error->code == G_IO_ERROR_CANCELLED)) {
			_LOGD ("call[%u]: CheckAuthorization cancelled", data->call_id);
			g_dbus_proxy_call (priv->proxy,
			                   "CancelCheckAuthorization",
			                   g_variant_new ("(s)", data->cancellation_id),
			                   G_DBUS_CALL_FLAGS_NONE,
			                   -1,
			                   NULL, /* GCancellable */
			                   (GAsyncReadyCallback) cancel_check_authorization_cb,
			                   g_object_ref (self));
		} else
			_LOGD ("call[%u]: CheckAuthorization failed: %s", data->call_id, error->message);
		g_dbus_error_strip_remote_error (error);
		g_simple_async_result_set_error (data->simple,
		                                 NM_MANAGER_ERROR,
		                                 NM_MANAGER_ERROR_FAILED,
		                                 "Authorization check failed: %s",
		                                 error->message);
		g_error_free (error);
	} else {
		CheckAuthorizationResult *result;

		result = g_new0 (CheckAuthorizationResult, 1);

		g_variant_get (value,
		               "((bb@a{ss}))",
		               &result->is_authorized,
		               &result->is_challenge,
		               NULL);
		g_variant_unref (value);

		_LOGD ("call[%u]: CheckAuthorization succeeded: (is_authorized=%d, is_challenge=%d)", data->call_id, result->is_authorized, result->is_challenge);
		g_simple_async_result_set_op_res_gpointer (data->simple, result, g_free);
	}

	g_simple_async_result_complete (data->simple);

	_check_auth_data_free (data);
}

static void
_call_check_authorization (CheckAuthData *data)
{
	NMAuthManagerPrivate *priv = NM_AUTH_MANAGER_GET_PRIVATE (data->self);

	g_dbus_proxy_call (priv->proxy,
	                   "CheckAuthorization",
	                   data->dbus_parameters,
	                   G_DBUS_CALL_FLAGS_NONE,
	                   G_MAXINT, /* no timeout */
	                   data->cancellable,
	                   (GAsyncReadyCallback) check_authorization_cb,
	                   data);
	g_clear_object (&data->cancellable);
	data->dbus_parameters = NULL;
}

void
nm_auth_manager_polkit_authority_check_authorization (NMAuthManager *self,
                                                      NMAuthSubject *subject,
                                                      const char *action_id,
                                                      gboolean allow_user_interaction,
                                                      GCancellable *cancellable,
                                                      GAsyncReadyCallback callback,
                                                      gpointer user_data)
{
	NMAuthManagerPrivate *priv;
	char subject_buf[64];
	GVariantBuilder builder;
	PolkitCheckAuthorizationFlags flags;
	GVariant *subject_value;
	GVariant *details_value;
	CheckAuthData *data;

	g_return_if_fail (NM_IS_AUTH_MANAGER (self));
	g_return_if_fail (NM_IS_AUTH_SUBJECT (subject));
	g_return_if_fail (nm_auth_subject_is_unix_process (subject));
	g_return_if_fail (action_id != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	priv = NM_AUTH_MANAGER_GET_PRIVATE (self);

	g_return_if_fail (priv->polkit_enabled);

	flags = allow_user_interaction
	    ? POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION
	    : POLKIT_CHECK_AUTHORIZATION_FLAGS_NONE;

	subject_value = nm_auth_subject_unix_process_to_polkit_gvariant (subject);
	g_assert (g_variant_is_floating (subject_value));

	/* ((PolkitDetails *)NULL) */
	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{ss}"));
	details_value = g_variant_builder_end (&builder);

	data = g_new0 (CheckAuthData, 1);
	data->call_id = ++priv->call_id_counter;
	data->self = g_object_ref (self);
	data->simple = g_simple_async_result_new (G_OBJECT (self),
	                                          callback,
	                                          user_data,
	                                          nm_auth_manager_polkit_authority_check_authorization);
	if (cancellable != NULL) {
		data->cancellation_id = g_strdup_printf ("cancellation-id-%u", data->call_id);
		data->cancellable = g_object_ref (cancellable);
	}

	data->dbus_parameters = g_variant_new ("(@(sa{sv})s@a{ss}us)",
	                                       subject_value,
	                                       action_id,
	                                       details_value,
	                                       (guint32) flags,
	                                       data->cancellation_id != NULL ? data->cancellation_id : "");

	if (priv->new_proxy_cancellable) {
		_LOGD ("call[%u]: CheckAuthorization(%s), subject=%s (wait for proxy)", data->call_id, action_id, nm_auth_subject_to_string (subject, subject_buf, sizeof (subject_buf)));

		priv->queued_calls = g_slist_prepend (priv->queued_calls, data);
	} else if (!priv->proxy) {
		_LOGD ("call[%u]: CheckAuthorization(%s), subject=%s (fails due to invalid DBUS proxy)", data->call_id, action_id, nm_auth_subject_to_string (subject, subject_buf, sizeof (subject_buf)));

		_call_check_authorization_complete_with_error (data, "invalid DBUS proxy");
	} else {
		_LOGD ("call[%u]: CheckAuthorization(%s), subject=%s", data->call_id, action_id, nm_auth_subject_to_string (subject, subject_buf, sizeof (subject_buf)));

		_call_check_authorization (data);
	}
}

gboolean
nm_auth_manager_polkit_authority_check_authorization_finish (NMAuthManager *self,
                                                             GAsyncResult *res,
                                                             gboolean *out_is_authorized,
                                                             gboolean *out_is_challenge,
                                                             GError **error)
{
	gboolean success = FALSE;
	gboolean is_authorized = FALSE;
	gboolean is_challenge = FALSE;

	g_return_val_if_fail (NM_IS_AUTH_MANAGER (self), FALSE);
	g_return_val_if_fail (G_IS_SIMPLE_ASYNC_RESULT (res), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (res), error)) {
		CheckAuthorizationResult *result;

		result = g_simple_async_result_get_op_res_gpointer (G_SIMPLE_ASYNC_RESULT (res));
		is_authorized = !!result->is_authorized;
		is_challenge = !!result->is_challenge;
		success = TRUE;
	}
	g_assert ((success && !error) || (!success || error));

	if (out_is_authorized)
		*out_is_authorized = is_authorized;
	if (out_is_challenge)
		*out_is_challenge = is_challenge;
	return success;
}

/*****************************************************************************/

static void
_emit_changed_signal (NMAuthManager *self)
{
	_LOGD ("emit changed signal");
	g_signal_emit_by_name (self, NM_AUTH_MANAGER_SIGNAL_CHANGED);
}

static void
_log_name_owner (NMAuthManager *self, char **out_name_owner)
{
	NMAuthManagerPrivate *priv = NM_AUTH_MANAGER_GET_PRIVATE (self);
	char *name_owner;

	name_owner = g_dbus_proxy_get_name_owner (priv->proxy);
	if (name_owner)
		_LOGD ("dbus name owner: '%s'", name_owner);
	else
		_LOGD ("dbus name owner: none");

	if (out_name_owner)
		*out_name_owner = name_owner;
	else
		g_free (name_owner);
}

static void
_dbus_on_name_owner_notify_cb (GObject    *object,
                               GParamSpec *pspec,
                               gpointer    user_data)
{
	NMAuthManager *self = user_data;
	NMAuthManagerPrivate *priv = NM_AUTH_MANAGER_GET_PRIVATE (self);
	char *name_owner;

	g_return_if_fail (priv->proxy == (void *) object);

	_log_name_owner (self, &name_owner);

	if (!name_owner) {
		/* when the name disappears, we also want to raise a emit signal.
		 * When it appears, we raise one already. */
		_emit_changed_signal (self);
	}

	g_free (name_owner);
}

static void
_dbus_on_changed_signal_cb (GDBusProxy *proxy,
                            gpointer    user_data)
{
	NMAuthManager *self = user_data;
	NMAuthManagerPrivate *priv = NM_AUTH_MANAGER_GET_PRIVATE (self);

	g_return_if_fail (priv->proxy == proxy);

	_LOGD ("dbus signal: \"Changed\"");
	_emit_changed_signal (self);
}

static void
_dbus_new_proxy_cb (GObject *source_object,
                    GAsyncResult *res,
                    gpointer user_data)
{
	NMAuthManager **p_self = user_data;
	NMAuthManager *self = NULL;
	NMAuthManagerPrivate *priv;
	GError *error = NULL;
	GDBusProxy *proxy;
	CheckAuthData *data;

	proxy = g_dbus_proxy_new_for_bus_finish  (res, &error);

	if (!*p_self) {
		_LOGD ("_dbus_new_proxy_cb(): manager destroyed before callback finished. Abort");
		g_clear_object (&proxy);
		g_clear_error (&error);
		g_free (p_self);
		return;
	}
	self = *p_self;
	g_object_remove_weak_pointer (G_OBJECT (self), (void **)p_self);
	g_free (p_self);

	priv = NM_AUTH_MANAGER_GET_PRIVATE (self);

	g_return_if_fail (priv->new_proxy_cancellable);
	g_return_if_fail (!priv->proxy);

	g_clear_object (&priv->new_proxy_cancellable);

	priv->queued_calls = g_slist_reverse (priv->queued_calls);

	priv->proxy = proxy;
	if (!priv->proxy) {
		_LOGE ("could not get polkit proxy: %s", error->message);
		g_clear_error (&error);

		while (priv->queued_calls) {
			data = priv->queued_calls->data;
			priv->queued_calls = g_slist_remove (priv->queued_calls, data);

			_call_check_authorization_complete_with_error (data, "error creating DBUS proxy");
		}
		return;
	}

	g_signal_connect (priv->proxy,
	                  "notify::g-name-owner",
	                  G_CALLBACK (_dbus_on_name_owner_notify_cb),
	                  self);
	_nm_dbus_signal_connect (priv->proxy, "Changed", NULL,
	                         G_CALLBACK (_dbus_on_changed_signal_cb),
	                         self);

	_log_name_owner (self, NULL);

	while (priv->queued_calls) {
		data = priv->queued_calls->data;
		priv->queued_calls = g_slist_remove (priv->queued_calls, data);
		_LOGD ("call[%u]: CheckAuthorization invoke now", data->call_id);
		_call_check_authorization (data);
	}
	_emit_changed_signal (self);
}

#endif

/*****************************************************************************/

NMAuthManager *
nm_auth_manager_get ()
{
	g_return_val_if_fail (singleton_instance, NULL);

	return singleton_instance;
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

	return self;
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
	NMAuthManagerPrivate *priv = NM_AUTH_MANAGER_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_POLKIT_ENABLED:
		g_value_set_boolean (value, priv->polkit_enabled);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
	NMAuthManagerPrivate *priv = NM_AUTH_MANAGER_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_POLKIT_ENABLED:
		/* construct only */
		priv->polkit_enabled = !!g_value_get_boolean (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_auth_manager_init (NMAuthManager *self)
{
}

static void
constructed (GObject *object)
{
	NMAuthManager *self = NM_AUTH_MANAGER (object);
	NMAuthManagerPrivate *priv = NM_AUTH_MANAGER_GET_PRIVATE (self);

	G_OBJECT_CLASS (nm_auth_manager_parent_class)->constructed (object);

#if WITH_POLKIT
	_LOGD ("create auth-manager: polkit %s", priv->polkit_enabled ? "enabled" : "disabled");

	if (priv->polkit_enabled) {
		NMAuthManager **p_self;

		priv->new_proxy_cancellable = g_cancellable_new ();
		p_self = g_new (NMAuthManager *, 1);
		*p_self = self;
		g_object_add_weak_pointer (G_OBJECT (self), (void **) p_self);
		g_dbus_proxy_new_for_bus (G_BUS_TYPE_SYSTEM,
		                          G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
		                          NULL,
		                          POLKIT_SERVICE,
		                          POLKIT_OBJECT_PATH,
		                          POLKIT_INTERFACE,
		                          priv->new_proxy_cancellable,
		                          _dbus_new_proxy_cb,
		                          p_self);
	}
#else
	if (priv->polkit_enabled)
		_LOGW ("create auth-manager: polkit disabled at compile time. All authentication requests will fail");
	else
		_LOGD ("create auth-manager: polkit disabled at compile time");
#endif
}


static void
dispose (GObject *object)
{
	NMAuthManager* self = NM_AUTH_MANAGER (object);
#if WITH_POLKIT
	NMAuthManagerPrivate *priv = NM_AUTH_MANAGER_GET_PRIVATE (self);
#endif

	_LOGD ("dispose");

#if WITH_POLKIT
	/* since we take a reference for each queued call, we don't expect to have any queued calls in dispose() */
	g_assert (!priv->queued_calls);

	if (priv->new_proxy_cancellable) {
		g_cancellable_cancel (priv->new_proxy_cancellable);
		g_clear_object (&priv->new_proxy_cancellable);
	}

	if (priv->proxy) {
		g_signal_handlers_disconnect_by_data (priv->proxy, self);
		g_clear_object (&priv->proxy);
	}
#endif

	G_OBJECT_CLASS (nm_auth_manager_parent_class)->dispose (object);
}

static void
nm_auth_manager_class_init (NMAuthManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMAuthManagerPrivate));

	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->constructed = constructed;
	object_class->dispose = dispose;

	g_object_class_install_property
	    (object_class, PROP_POLKIT_ENABLED,
	     g_param_spec_boolean (NM_AUTH_MANAGER_POLKIT_ENABLED, "", "",
	                           FALSE,
	                           G_PARAM_READWRITE |
	                           G_PARAM_CONSTRUCT_ONLY |
	                           G_PARAM_STATIC_STRINGS));

	signals[CHANGED_SIGNAL] = g_signal_new (NM_AUTH_MANAGER_SIGNAL_CHANGED,
	                                        NM_TYPE_AUTH_MANAGER,
	                                        G_SIGNAL_RUN_LAST,
	                                        0,                      /* class offset     */
	                                        NULL,                   /* accumulator      */
	                                        NULL,                   /* accumulator data */
	                                        g_cclosure_marshal_VOID__VOID,
	                                        G_TYPE_NONE,
	                                        0);

}

