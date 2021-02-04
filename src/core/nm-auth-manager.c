/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2014 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-auth-manager.h"

#include "c-list/src/c-list.h"
#include "nm-glib-aux/nm-dbus-aux.h"
#include "nm-errors.h"
#include "nm-core-internal.h"
#include "nm-dbus-manager.h"
#include "NetworkManagerUtils.h"

#define POLKIT_SERVICE     "org.freedesktop.PolicyKit1"
#define POLKIT_OBJECT_PATH "/org/freedesktop/PolicyKit1/Authority"
#define POLKIT_INTERFACE   "org.freedesktop.PolicyKit1.Authority"

#define CANCELLATION_ID_PREFIX  "cancellation-id-"
#define CANCELLATION_TIMEOUT_MS 5000

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_POLKIT_ENABLED, );

enum {
    CHANGED_SIGNAL,
    LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = {0};

typedef struct {
    CList            calls_lst_head;
    GDBusConnection *dbus_connection;
    GCancellable *   main_cancellable;
    char *           name_owner;
    guint64          call_numid_counter;
    guint            changed_id;
    guint            name_owner_changed_id;
    bool             disposing : 1;
    bool             shutting_down : 1;
    bool             got_name_owner : 1;
    NMAuthPolkitMode auth_polkit_mode : 3;
} NMAuthManagerPrivate;

struct _NMAuthManager {
    GObject              parent;
    NMAuthManagerPrivate _priv;
};

struct _NMAuthManagerClass {
    GObjectClass parent;
};

G_DEFINE_TYPE(NMAuthManager, nm_auth_manager, G_TYPE_OBJECT)

#define NM_AUTH_MANAGER_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMAuthManager, NM_IS_AUTH_MANAGER)

NM_DEFINE_SINGLETON_REGISTER(NMAuthManager);

/*****************************************************************************/

#define _NMLOG_PREFIX_NAME "auth"
#define _NMLOG_DOMAIN      LOGD_CORE
#define _NMLOG(level, ...)                                       \
    G_STMT_START                                                 \
    {                                                            \
        if (nm_logging_enabled((level), (_NMLOG_DOMAIN))) {      \
            char __prefix[30] = _NMLOG_PREFIX_NAME;              \
                                                                 \
            if ((self) != singleton_instance)                    \
                g_snprintf(__prefix,                             \
                           sizeof(__prefix),                     \
                           ""_NMLOG_PREFIX_NAME                  \
                           "[%p]",                               \
                           (self));                              \
            _nm_log((level),                                     \
                    (_NMLOG_DOMAIN),                             \
                    0,                                           \
                    NULL,                                        \
                    NULL,                                        \
                    "%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__),   \
                    __prefix _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
        }                                                        \
    }                                                            \
    G_STMT_END

#define _NMLOG2(level, call_id, ...)                                                        \
    G_STMT_START                                                                            \
    {                                                                                       \
        if (nm_logging_enabled((level), (_NMLOG_DOMAIN))) {                                 \
            NMAuthManagerCallId *_call_id     = (call_id);                                  \
            char                 __prefix[30] = _NMLOG_PREFIX_NAME;                         \
                                                                                            \
            if (_call_id->self != singleton_instance)                                       \
                g_snprintf(__prefix,                                                        \
                           sizeof(__prefix),                                                \
                           ""_NMLOG_PREFIX_NAME                                             \
                           "[%p]",                                                          \
                           _call_id->self);                                                 \
            _nm_log((level),                                                                \
                    (_NMLOG_DOMAIN),                                                        \
                    0,                                                                      \
                    NULL,                                                                   \
                    NULL,                                                                   \
                    "%s: call[%" G_GUINT64_FORMAT "]: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
                    __prefix,                                                               \
                    _call_id->call_numid _NM_UTILS_MACRO_REST(__VA_ARGS__));                \
        }                                                                                   \
    }                                                                                       \
    G_STMT_END

/*****************************************************************************/

gboolean
nm_auth_manager_get_polkit_enabled(NMAuthManager *self)
{
    g_return_val_if_fail(NM_IS_AUTH_MANAGER(self), FALSE);

    return NM_AUTH_MANAGER_GET_PRIVATE(self)->dbus_connection != NULL;
}

/*****************************************************************************/

static void
_emit_changed_signal(NMAuthManager *self)
{
    g_signal_emit(self, signals[CHANGED_SIGNAL], 0);
}

typedef enum {
    POLKIT_CHECK_AUTHORIZATION_FLAGS_NONE                   = 0,
    POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION = (1 << 0),
} PolkitCheckAuthorizationFlags;

struct _NMAuthManagerCallId {
    CList                                   calls_lst;
    NMAuthManager *                         self;
    GCancellable *                          dbus_cancellable;
    NMAuthManagerCheckAuthorizationCallback callback;
    gpointer                                user_data;
    guint64                                 call_numid;
    guint                                   idle_id;
    bool                                    idle_is_authorized : 1;
};

#define cancellation_id_to_str_a(call_numid)                     \
    nm_sprintf_bufa(NM_STRLEN(CANCELLATION_ID_PREFIX) + 60,      \
                    CANCELLATION_ID_PREFIX "%" G_GUINT64_FORMAT, \
                    (call_numid))

static void
_call_id_free(NMAuthManagerCallId *call_id)
{
    c_list_unlink(&call_id->calls_lst);
    nm_clear_g_source(&call_id->idle_id);

    if (call_id->dbus_cancellable) {
        /* we have a pending D-Bus call. We keep the call-id instance alive
         * for _call_check_authorize_cb() */
        g_cancellable_cancel(call_id->dbus_cancellable);
        return;
    }

    g_object_unref(call_id->self);
    g_slice_free(NMAuthManagerCallId, call_id);
}

static void
_call_id_invoke_callback(NMAuthManagerCallId *call_id,
                         gboolean             is_authorized,
                         gboolean             is_challenge,
                         GError *             error)
{
    c_list_unlink(&call_id->calls_lst);

    call_id
        ->callback(call_id->self, call_id, is_authorized, is_challenge, error, call_id->user_data);
    _call_id_free(call_id);
}

static void
cancel_check_authorization_cb(GObject *source, GAsyncResult *res, gpointer user_data)
{
    NMAuthManagerCallId *call_id     = user_data;
    gs_unref_variant GVariant *value = NULL;
    gs_free_error GError *error      = NULL;

    value = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), res, &error);
    if (g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        _LOG2T(call_id, "cancel request was cancelled");
    else if (error)
        _LOG2T(call_id, "cancel request failed: %s", error->message);
    else
        _LOG2T(call_id, "cancel request succeeded");

    _call_id_free(call_id);
}

static void
_call_check_authorize_cb(GObject *proxy, GAsyncResult *res, gpointer user_data)
{
    NMAuthManagerCallId * call_id = user_data;
    NMAuthManager *       self;
    NMAuthManagerPrivate *priv;
    gs_unref_variant GVariant *value    = NULL;
    gs_free_error GError *error         = NULL;
    gboolean              is_authorized = FALSE;
    gboolean              is_challenge  = FALSE;

    /* we need to clear the cancelable, to signal for _call_id_free() that we
     * are not in a pending call.
     *
     * Note how _call_id_free() kept call-id alive, even if the request was
     * already cancelled. */
    g_clear_object(&call_id->dbus_cancellable);

    self = call_id->self;
    priv = NM_AUTH_MANAGER_GET_PRIVATE(self);

    value = g_dbus_connection_call_finish(G_DBUS_CONNECTION(proxy), res, &error);

    if (nm_utils_error_is_cancelled(error)) {
        /* call_id was cancelled externally, but _call_id_free() kept call_id
         * alive (and it has still the reference on @self. */

        if (!priv->main_cancellable) {
            /* we do a forced shutdown. There is no more time for cancelling... */
            _call_id_free(call_id);

            /* this shouldn't really happen, because:
             * nm_auth_manager_check_authorization() only scheduled the D-Bus request at a time when
             * main_cancellable was still set. It means, somebody called force-shutdown
             * after call-id was schedule.
             * force-shutdown should only be called after:
             *   - cancel all pending requests
             *   - give enough time to cancel the request and schedule a D-Bus call
             *     to CancelCheckAuthorization (below), before issuing force-shutdown. */
            g_return_if_reached();
        }

        g_dbus_connection_call(priv->dbus_connection,
                               POLKIT_SERVICE,
                               POLKIT_OBJECT_PATH,
                               POLKIT_INTERFACE,
                               "CancelCheckAuthorization",
                               g_variant_new("(s)", cancellation_id_to_str_a(call_id->call_numid)),
                               G_VARIANT_TYPE("()"),
                               G_DBUS_CALL_FLAGS_NONE,
                               CANCELLATION_TIMEOUT_MS,
                               priv->main_cancellable,
                               cancel_check_authorization_cb,
                               call_id);
        return;
    }

    if (!error) {
        g_variant_get(value, "((bb@a{ss}))", &is_authorized, &is_challenge, NULL);
        _LOG2T(call_id, "completed: authorized=%d, challenge=%d", is_authorized, is_challenge);
    } else
        _LOG2T(call_id, "completed: failed: %s", error->message);

    _call_id_invoke_callback(call_id, is_authorized, is_challenge, error);
}

static gboolean
_call_on_idle(gpointer user_data)
{
    NMAuthManagerCallId *call_id = user_data;
    gboolean             is_authorized;
    gboolean             is_challenge = FALSE;

    is_authorized    = call_id->idle_is_authorized;
    call_id->idle_id = 0;

    _LOG2T(call_id,
           "completed: authorized=%d, challenge=%d (simulated)",
           is_authorized,
           is_challenge);

    _call_id_invoke_callback(call_id, is_authorized, is_challenge, NULL);
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
nm_auth_manager_check_authorization(NMAuthManager *                         self,
                                    NMAuthSubject *                         subject,
                                    const char *                            action_id,
                                    gboolean                                allow_user_interaction,
                                    NMAuthManagerCheckAuthorizationCallback callback,
                                    gpointer                                user_data)
{
    NMAuthManagerPrivate *        priv;
    PolkitCheckAuthorizationFlags flags;
    char                          subject_buf[64];
    NMAuthManagerCallId *         call_id;

    g_return_val_if_fail(NM_IS_AUTH_MANAGER(self), NULL);
    g_return_val_if_fail(NM_IN_SET(nm_auth_subject_get_subject_type(subject),
                                   NM_AUTH_SUBJECT_TYPE_INTERNAL,
                                   NM_AUTH_SUBJECT_TYPE_UNIX_PROCESS),
                         NULL);
    g_return_val_if_fail(action_id, NULL);

    priv = NM_AUTH_MANAGER_GET_PRIVATE(self);

    g_return_val_if_fail(!priv->disposing, NULL);
    g_return_val_if_fail(!priv->shutting_down, NULL);

    flags = allow_user_interaction ? POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION
                                   : POLKIT_CHECK_AUTHORIZATION_FLAGS_NONE;

    call_id  = g_slice_new(NMAuthManagerCallId);
    *call_id = (NMAuthManagerCallId){
        .self               = g_object_ref(self),
        .callback           = callback,
        .user_data          = user_data,
        .call_numid         = ++priv->call_numid_counter,
        .idle_is_authorized = TRUE,
    };
    c_list_link_tail(&priv->calls_lst_head, &call_id->calls_lst);

    if (nm_auth_subject_get_subject_type(subject) == NM_AUTH_SUBJECT_TYPE_INTERNAL) {
        _LOG2T(call_id,
               "CheckAuthorization(%s), subject=%s (succeeding for internal request)",
               action_id,
               nm_auth_subject_to_string(subject, subject_buf, sizeof(subject_buf)));
        call_id->idle_id = g_idle_add(_call_on_idle, call_id);
    } else if (nm_auth_subject_get_unix_process_uid(subject) == 0) {
        _LOG2T(call_id,
               "CheckAuthorization(%s), subject=%s (succeeding for root)",
               action_id,
               nm_auth_subject_to_string(subject, subject_buf, sizeof(subject_buf)));
        call_id->idle_id = g_idle_add(_call_on_idle, call_id);
    } else if (priv->auth_polkit_mode != NM_AUTH_POLKIT_MODE_USE_POLKIT) {
        _LOG2T(call_id,
               "CheckAuthorization(%s), subject=%s (PolicyKit disabled and always %s authorization "
               "to non-root user)",
               action_id,
               nm_auth_subject_to_string(subject, subject_buf, sizeof(subject_buf)),
               priv->auth_polkit_mode == NM_AUTH_POLKIT_MODE_ALLOW_ALL ? "grant" : "deny");
        call_id->idle_is_authorized = (priv->auth_polkit_mode == NM_AUTH_POLKIT_MODE_ALLOW_ALL);
        call_id->idle_id            = g_idle_add(_call_on_idle, call_id);
    } else {
        GVariant *      parameters;
        GVariantBuilder builder;
        GVariant *      subject_value;
        GVariant *      details_value;

        subject_value = nm_auth_subject_unix_to_polkit_gvariant(subject);
        nm_assert(g_variant_is_floating(subject_value));

        /* ((PolkitDetails *)NULL) */
        g_variant_builder_init(&builder, G_VARIANT_TYPE("a{ss}"));
        details_value = g_variant_builder_end(&builder);

        parameters = g_variant_new("(@(sa{sv})s@a{ss}us)",
                                   subject_value,
                                   action_id,
                                   details_value,
                                   (guint32) flags,
                                   cancellation_id_to_str_a(call_id->call_numid));

        _LOG2T(call_id,
               "CheckAuthorization(%s), subject=%s",
               action_id,
               nm_auth_subject_to_string(subject, subject_buf, sizeof(subject_buf)));

        call_id->dbus_cancellable = g_cancellable_new();

        nm_assert(priv->main_cancellable);

        g_dbus_connection_call(priv->dbus_connection,
                               POLKIT_SERVICE,
                               POLKIT_OBJECT_PATH,
                               POLKIT_INTERFACE,
                               "CheckAuthorization",
                               parameters,
                               G_VARIANT_TYPE("((bba{ss}))"),
                               G_DBUS_CALL_FLAGS_NONE,
                               G_MAXINT, /* no timeout */
                               call_id->dbus_cancellable,
                               _call_check_authorize_cb,
                               call_id);
    }

    return call_id;
}

void
nm_auth_manager_check_authorization_cancel(NMAuthManagerCallId *call_id)
{
    NMAuthManager *self;
    gs_free_error GError *error = NULL;

    g_return_if_fail(call_id);

    self = call_id->self;

    g_return_if_fail(NM_IS_AUTH_MANAGER(self));
    g_return_if_fail(!c_list_is_empty(&call_id->calls_lst));

    nm_assert(
        c_list_contains(&NM_AUTH_MANAGER_GET_PRIVATE(self)->calls_lst_head, &call_id->calls_lst));

    nm_utils_error_set_cancelled(&error, FALSE, "NMAuthManager");
    _LOG2T(call_id, "completed: failed due to call cancelled");
    _call_id_invoke_callback(call_id, FALSE, FALSE, error);
}

/*****************************************************************************/

static void
changed_signal_cb(GDBusConnection *connection,
                  const char *     sender_name,
                  const char *     object_path,
                  const char *     interface_name,
                  const char *     signal_name,
                  GVariant *       parameters,
                  gpointer         user_data)
{
    NMAuthManager *       self = user_data;
    NMAuthManagerPrivate *priv = NM_AUTH_MANAGER_GET_PRIVATE(self);
    gboolean              valid_sender;

    nm_assert(nm_streq0(signal_name, "Changed"));

    valid_sender = nm_streq0(priv->name_owner, sender_name);

    _LOGD("dbus-signal: \"Changed\" notification%s", valid_sender ? "" : " (ignore)");

    if (valid_sender)
        _emit_changed_signal(self);
}

static void
_name_owner_changed(NMAuthManager *self, const char *name_owner, gboolean is_initial)
{
    NMAuthManagerPrivate *priv = NM_AUTH_MANAGER_GET_PRIVATE(self);
    gboolean              is_changed;
    gs_free char *        old_name_owner = NULL;

    if (is_initial)
        priv->got_name_owner = TRUE;
    else {
        if (!priv->got_name_owner)
            return;
    }

    name_owner = nm_str_not_empty(name_owner);

    is_changed = !nm_streq0(priv->name_owner, name_owner);
    if (is_changed) {
        old_name_owner   = g_steal_pointer(&priv->name_owner);
        priv->name_owner = g_strdup(name_owner);
    } else {
        if (!is_initial)
            return;
    }

    if (!priv->name_owner) {
        if (is_initial)
            _LOGT("name-owner: polkit not running");
        else
            _LOGT("name-owner: polkit stopped (was %s)", old_name_owner);
    } else {
        if (is_initial)
            _LOGT("name-owner: polkit is running (now %s)", priv->name_owner);
        else if (old_name_owner)
            _LOGT("name-owner: polkit restarted (now %s, was %s)",
                  priv->name_owner,
                  old_name_owner);
        else
            _LOGT("name-owner: polkit started (now %s)", priv->name_owner);
    }

    if (priv->name_owner)
        _emit_changed_signal(self);
}

static void
_name_owner_changed_cb(GDBusConnection *connection,
                       const char *     sender_name,
                       const char *     object_path,
                       const char *     interface_name,
                       const char *     signal_name,
                       GVariant *       parameters,
                       gpointer         user_data)
{
    NMAuthManager *self = user_data;
    const char *   new_owner;

    if (!g_variant_is_of_type(parameters, G_VARIANT_TYPE("(sss)")))
        return;

    g_variant_get(parameters, "(&s&s&s)", NULL, NULL, &new_owner);

    _name_owner_changed(self, new_owner, FALSE);
}

static void
_name_owner_get_cb(const char *name_owner, GError *error, gpointer user_data)
{
    if (!nm_utils_error_is_cancelled(error))
        _name_owner_changed(user_data, name_owner, TRUE);
}

/*****************************************************************************/

NMAuthManager *
nm_auth_manager_get()
{
    g_return_val_if_fail(singleton_instance, NULL);

    return singleton_instance;
}

void
nm_auth_manager_force_shutdown(NMAuthManager *self)
{
    NMAuthManagerPrivate *priv;

    g_return_if_fail(NM_IS_AUTH_MANAGER(self));

    priv = NM_AUTH_MANAGER_GET_PRIVATE(self);

    /* FIXME(shutdown): ensure we properly call this API during shutdown as
     * described next. */

    /* while we have pending requests (NMAuthManagerCallId), the instance
     * is kept alive.
     *
     * Even if the caller cancels all pending call-ids, we still need to keep
     * a reference to self, in order to handle pending CancelCheckAuthorization
     * requests.
     *
     * To do a coordinated shutdown, do the following:
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
    nm_clear_g_cancellable(&priv->main_cancellable);
}

/*****************************************************************************/

static void
set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
    NMAuthManagerPrivate *priv = NM_AUTH_MANAGER_GET_PRIVATE(object);
    int                   v_int;

    switch (prop_id) {
    case PROP_POLKIT_ENABLED:
        /* construct-only */
        v_int = g_value_get_int(value);
        g_return_if_fail(NM_IN_SET(v_int,
                                   NM_AUTH_POLKIT_MODE_ROOT_ONLY,
                                   NM_AUTH_POLKIT_MODE_ALLOW_ALL,
                                   NM_AUTH_POLKIT_MODE_USE_POLKIT));
        priv->auth_polkit_mode = v_int;
        nm_assert(priv->auth_polkit_mode == v_int);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

/*****************************************************************************/

static void
nm_auth_manager_init(NMAuthManager *self)
{
    NMAuthManagerPrivate *priv = NM_AUTH_MANAGER_GET_PRIVATE(self);

    c_list_init(&priv->calls_lst_head);
    priv->auth_polkit_mode = NM_AUTH_POLKIT_MODE_ROOT_ONLY;
}

static void
constructed(GObject *object)
{
    NMAuthManager *       self = NM_AUTH_MANAGER(object);
    NMAuthManagerPrivate *priv = NM_AUTH_MANAGER_GET_PRIVATE(self);
    NMLogLevel            logl = LOGL_DEBUG;
    const char *          create_message;

    G_OBJECT_CLASS(nm_auth_manager_parent_class)->constructed(object);

    if (priv->auth_polkit_mode != NM_AUTH_POLKIT_MODE_USE_POLKIT) {
        if (priv->auth_polkit_mode == NM_AUTH_POLKIT_MODE_ROOT_ONLY)
            create_message = "polkit disabled, root-only";
        else
            create_message = "polkit disabled, allow-all";
        goto out;
    }

    priv->dbus_connection = nm_g_object_ref(NM_MAIN_DBUS_CONNECTION_GET);

    if (!priv->dbus_connection) {
        /* This warrants an info level message. */
        logl = LOGL_INFO;
        create_message =
            "D-Bus connection not available. Polkit is disabled and only root will be authorized.";
        priv->auth_polkit_mode = NM_AUTH_POLKIT_MODE_ROOT_ONLY;
        goto out;
    }

    priv->main_cancellable = g_cancellable_new();

    priv->name_owner_changed_id =
        nm_dbus_connection_signal_subscribe_name_owner_changed(priv->dbus_connection,
                                                               POLKIT_SERVICE,
                                                               _name_owner_changed_cb,
                                                               self,
                                                               NULL);

    priv->changed_id = g_dbus_connection_signal_subscribe(priv->dbus_connection,
                                                          POLKIT_SERVICE,
                                                          POLKIT_INTERFACE,
                                                          "Changed",
                                                          POLKIT_OBJECT_PATH,
                                                          NULL,
                                                          G_DBUS_SIGNAL_FLAGS_NONE,
                                                          changed_signal_cb,
                                                          self,
                                                          NULL);

    nm_dbus_connection_call_get_name_owner(priv->dbus_connection,
                                           POLKIT_SERVICE,
                                           -1,
                                           priv->main_cancellable,
                                           _name_owner_get_cb,
                                           self);

    create_message = "polkit enabled";

out:
    _NMLOG(logl, "create auth-manager: %s", create_message);
}

NMAuthManager *
nm_auth_manager_setup(NMAuthPolkitMode auth_polkit_mode)
{
    NMAuthManager *self;

    g_return_val_if_fail(!singleton_instance, singleton_instance);
    nm_assert(NM_IN_SET(auth_polkit_mode,
                        NM_AUTH_POLKIT_MODE_ROOT_ONLY,
                        NM_AUTH_POLKIT_MODE_ALLOW_ALL,
                        NM_AUTH_POLKIT_MODE_USE_POLKIT));

    self = g_object_new(NM_TYPE_AUTH_MANAGER,
                        NM_AUTH_MANAGER_POLKIT_ENABLED,
                        (int) auth_polkit_mode,
                        NULL);
    _LOGD("set instance");

    singleton_instance = self;
    nm_singleton_instance_register();

    nm_log_dbg(LOGD_CORE,
               "setup %s singleton (" NM_HASH_OBFUSCATE_PTR_FMT ")",
               "NMAuthManager",
               NM_HASH_OBFUSCATE_PTR(singleton_instance));

    return self;
}

static void
dispose(GObject *object)
{
    NMAuthManager *       self = NM_AUTH_MANAGER(object);
    NMAuthManagerPrivate *priv = NM_AUTH_MANAGER_GET_PRIVATE(self);

    _LOGD("dispose");

    nm_assert(c_list_is_empty(&priv->calls_lst_head));

    priv->disposing = TRUE;

    nm_clear_g_cancellable(&priv->main_cancellable);

    nm_clear_g_dbus_connection_signal(priv->dbus_connection, &priv->name_owner_changed_id);

    nm_clear_g_dbus_connection_signal(priv->dbus_connection, &priv->changed_id);

    G_OBJECT_CLASS(nm_auth_manager_parent_class)->dispose(object);

    g_clear_object(&priv->dbus_connection);

    nm_clear_g_free(&priv->name_owner);
}

static void
nm_auth_manager_class_init(NMAuthManagerClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS(klass);

    object_class->set_property = set_property;
    object_class->constructed  = constructed;
    object_class->dispose      = dispose;

    obj_properties[PROP_POLKIT_ENABLED] =
        g_param_spec_int(NM_AUTH_MANAGER_POLKIT_ENABLED,
                         "",
                         "",
                         NM_AUTH_POLKIT_MODE_ROOT_ONLY,
                         NM_AUTH_POLKIT_MODE_USE_POLKIT,
                         NM_AUTH_POLKIT_MODE_USE_POLKIT,
                         G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    signals[CHANGED_SIGNAL] = g_signal_new(NM_AUTH_MANAGER_SIGNAL_CHANGED,
                                           NM_TYPE_AUTH_MANAGER,
                                           G_SIGNAL_RUN_LAST,
                                           0,
                                           NULL,
                                           NULL,
                                           g_cclosure_marshal_VOID__VOID,
                                           G_TYPE_NONE,
                                           0);
}
