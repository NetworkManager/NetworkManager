/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2011 - 2015 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-firewalld-manager.h"

#include "libnm-glib-aux/nm-dbus-aux.h"
#include "c-list/src/c-list.h"

#include "NetworkManagerUtils.h"
#include "nm-dbus-manager.h"

#define FIREWALL_DBUS_SERVICE        "org.fedoraproject.FirewallD1"
#define FIREWALL_DBUS_PATH           "/org/fedoraproject/FirewallD1"
#define FIREWALL_DBUS_INTERFACE      "org.fedoraproject.FirewallD1"
#define FIREWALL_DBUS_INTERFACE_ZONE "org.fedoraproject.FirewallD1.zone"

/*****************************************************************************/

enum { STATE_CHANGED, LAST_SIGNAL };

static guint signals[LAST_SIGNAL] = {0};

typedef struct {
    GDBusConnection *dbus_connection;

    GCancellable *get_name_owner_cancellable;

    CList pending_calls;

    char *name_owner;

    guint reloaded_id;
    guint name_owner_changed_id;

    bool dbus_inited : 1;
} NMFirewalldManagerPrivate;

struct _NMFirewalldManager {
    GObject                   parent;
    NMFirewalldManagerPrivate _priv;
};

struct _NMFirewalldManagerClass {
    GObjectClass parent;
};

G_DEFINE_TYPE(NMFirewalldManager, nm_firewalld_manager, G_TYPE_OBJECT)

#define NM_FIREWALLD_MANAGER_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMFirewalldManager, NM_IS_FIREWALLD_MANAGER)

/*****************************************************************************/

NM_DEFINE_SINGLETON_GETTER(NMFirewalldManager, nm_firewalld_manager_get, NM_TYPE_FIREWALLD_MANAGER);

/*****************************************************************************/

typedef enum {
    OPS_TYPE_ADD = 1,
    OPS_TYPE_CHANGE,
    OPS_TYPE_REMOVE,
} OpsType;

struct _NMFirewalldManagerCallId {
    CList lst;

    NMFirewalldManager *self;

    char *iface;

    NMFirewalldManagerAddRemoveCallback callback;
    gpointer                            user_data;

    union {
        struct {
            GCancellable *cancellable;
            GVariant *    arg;
        } dbus;
        struct {
            guint id;
        } idle;
    };

    OpsType ops_type;

    bool is_idle : 1;
};

/*****************************************************************************/

static const char *
_ops_type_to_string(OpsType ops_type)
{
    switch (ops_type) {
    case OPS_TYPE_ADD:
        return "add";
    case OPS_TYPE_REMOVE:
        return "remove";
    case OPS_TYPE_CHANGE:
        return "change";
    }
    nm_assert_not_reached();
    return NULL;
}

#define _NMLOG_DOMAIN      LOGD_FIREWALL
#define _NMLOG_PREFIX_NAME "firewalld"
#define _NMLOG(level, call_id, ...)                                                 \
    G_STMT_START                                                                    \
    {                                                                               \
        if (nm_logging_enabled((level), (_NMLOG_DOMAIN))) {                         \
            NMFirewalldManagerCallId *_call_id = (call_id);                         \
            char                      _prefix_name[30];                             \
            char                      _prefix_info[100];                            \
                                                                                    \
            _nm_log((level),                                                        \
                    (_NMLOG_DOMAIN),                                                \
                    0,                                                              \
                    NULL,                                                           \
                    NULL,                                                           \
                    "%s: %s" _NM_UTILS_MACRO_FIRST(__VA_ARGS__),                    \
                    (self) != singleton_instance ? ({                               \
                        g_snprintf(_prefix_name,                                    \
                                   sizeof(_prefix_name),                            \
                                   "%s[" NM_HASH_OBFUSCATE_PTR_FMT "]",             \
                                   ""_NMLOG_PREFIX_NAME,                            \
                                   NM_HASH_OBFUSCATE_PTR(self));                    \
                        _prefix_name;                                               \
                    })                                                              \
                                                 : _NMLOG_PREFIX_NAME,              \
                    _call_id ? ({                                                   \
                        g_snprintf(_prefix_info,                                    \
                                   sizeof(_prefix_info),                            \
                                   "[" NM_HASH_OBFUSCATE_PTR_FMT ",%s%s:%s%s%s]: ", \
                                   NM_HASH_OBFUSCATE_PTR(_call_id),                 \
                                   _ops_type_to_string(_call_id->ops_type),         \
                                   _call_id->is_idle ? "*" : "",                    \
                                   NM_PRINT_FMT_QUOTE_STRING(_call_id->iface));     \
                        _prefix_info;                                               \
                    })                                                              \
                             : "" _NM_UTILS_MACRO_REST(__VA_ARGS__));               \
        }                                                                           \
    }                                                                               \
    G_STMT_END

/*****************************************************************************/

static void
_signal_emit_state_changed(NMFirewalldManager *self, NMFirewalldManagerStateChangedType signal_type)
{
    g_signal_emit(self, signals[STATE_CHANGED], 0, (int) signal_type);
}

/*****************************************************************************/

static gboolean
_get_running(NMFirewalldManagerPrivate *priv)
{
    /* when starting, we need to asynchronously check whether there is
     * a name owner. During that time we optimistically assume that the
     * service is indeed running. That is the time when we queue the
     * requests, and they will be started once the get-name-owner call
     * returns. */
    return priv->name_owner || (priv->dbus_connection && !priv->dbus_inited);
}

gboolean
nm_firewalld_manager_get_running(NMFirewalldManager *self)
{
    g_return_val_if_fail(NM_IS_FIREWALLD_MANAGER(self), FALSE);

    return _get_running(NM_FIREWALLD_MANAGER_GET_PRIVATE(self));
}

/*****************************************************************************/

static NMFirewalldManagerCallId *
_cb_info_create(NMFirewalldManager *                self,
                OpsType                             ops_type,
                const char *                        iface,
                const char *                        zone,
                NMFirewalldManagerAddRemoveCallback callback,
                gpointer                            user_data)
{
    NMFirewalldManagerPrivate *priv = NM_FIREWALLD_MANAGER_GET_PRIVATE(self);
    NMFirewalldManagerCallId * call_id;

    call_id = g_slice_new0(NMFirewalldManagerCallId);

    call_id->self      = g_object_ref(self);
    call_id->ops_type  = ops_type;
    call_id->iface     = g_strdup(iface);
    call_id->callback  = callback;
    call_id->user_data = user_data;

    if (_get_running(priv)) {
        call_id->is_idle  = FALSE;
        call_id->dbus.arg = g_variant_new("(ss)", zone ?: "", iface);
    } else
        call_id->is_idle = TRUE;

    c_list_link_tail(&priv->pending_calls, &call_id->lst);

    return call_id;
}

static void
_cb_info_complete(NMFirewalldManagerCallId *call_id, GError *error)
{
    c_list_unlink(&call_id->lst);

    if (call_id->callback)
        call_id->callback(call_id->self, call_id, error, call_id->user_data);

    if (call_id->is_idle)
        nm_clear_g_source(&call_id->idle.id);
    else {
        nm_g_variant_unref(call_id->dbus.arg);
        nm_clear_g_cancellable(&call_id->dbus.cancellable);
    }
    g_free(call_id->iface);
    g_object_unref(call_id->self);
    nm_g_slice_free(call_id);
}

static gboolean
_handle_idle_cb(gpointer user_data)
{
    NMFirewalldManager *      self;
    NMFirewalldManagerCallId *call_id = user_data;

    nm_assert(call_id);
    nm_assert(NM_IS_FIREWALLD_MANAGER(call_id->self));
    nm_assert(call_id->is_idle);
    nm_assert(c_list_contains(&NM_FIREWALLD_MANAGER_GET_PRIVATE(call_id->self)->pending_calls,
                              &call_id->lst));

    self = call_id->self;

    _LOGD(call_id, "complete: fake success");

    call_id->idle.id = 0;

    _cb_info_complete(call_id, NULL);
    return G_SOURCE_REMOVE;
}

static gboolean
_handle_idle_start(NMFirewalldManager *self, NMFirewalldManagerCallId *call_id)
{
    if (!call_id->callback) {
        /* if the user did not provide a callback and firewalld is not running,
         * there is no point in scheduling an idle-request to fake success. Just
         * return right away. */
        _LOGD(call_id, "complete: drop request simulating success");
        _cb_info_complete(call_id, NULL);
        return FALSE;
    }
    call_id->idle.id = g_idle_add(_handle_idle_cb, call_id);
    return TRUE;
}

static void
_handle_dbus_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    NMFirewalldManager *      self;
    NMFirewalldManagerCallId *call_id;
    gs_free_error GError *error    = NULL;
    gs_unref_variant GVariant *ret = NULL;

    ret = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), result, &error);

    if (!ret && nm_utils_error_is_cancelled(error))
        return;

    call_id = user_data;

    nm_assert(call_id);
    nm_assert(NM_IS_FIREWALLD_MANAGER(call_id->self));
    nm_assert(!call_id->is_idle);
    nm_assert(c_list_contains(&NM_FIREWALLD_MANAGER_GET_PRIVATE(call_id->self)->pending_calls,
                              &call_id->lst));

    self = call_id->self;

    if (error) {
        const char *non_error = NULL;

        g_dbus_error_strip_remote_error(error);

        switch (call_id->ops_type) {
        case OPS_TYPE_ADD:
        case OPS_TYPE_CHANGE:
            non_error = "ZONE_ALREADY_SET";
            break;
        case OPS_TYPE_REMOVE:
            non_error = "UNKNOWN_INTERFACE";
            break;
        }
        if (error->message && non_error && g_str_has_prefix(error->message, non_error)
            && NM_IN_SET(error->message[strlen(non_error)], '\0', ':')) {
            _LOGD(call_id, "complete: request failed with a non-error (%s)", error->message);

            /* The operation failed with an error reason that we don't want
             * to propagate. Instead, signal success. */
            g_clear_error(&error);
        } else
            _LOGW(call_id, "complete: request failed (%s)", error->message);
    } else
        _LOGD(call_id, "complete: success");

    g_clear_object(&call_id->dbus.cancellable);

    _cb_info_complete(call_id, error);
}

static void
_handle_dbus_start(NMFirewalldManager *self, NMFirewalldManagerCallId *call_id)
{
    NMFirewalldManagerPrivate *priv        = NM_FIREWALLD_MANAGER_GET_PRIVATE(self);
    const char *               dbus_method = NULL;
    GVariant *                 arg;

    nm_assert(call_id);
    nm_assert(priv->name_owner);
    nm_assert(!call_id->is_idle);
    nm_assert(c_list_contains(&priv->pending_calls, &call_id->lst));

    switch (call_id->ops_type) {
    case OPS_TYPE_ADD:
        dbus_method = "addInterface";
        break;
    case OPS_TYPE_CHANGE:
        dbus_method = "changeZoneOfInterface";
        break;
    case OPS_TYPE_REMOVE:
        dbus_method = "removeInterface";
        break;
    }
    nm_assert(dbus_method);

    arg = g_steal_pointer(&call_id->dbus.arg);

    nm_assert(arg && g_variant_is_floating(arg));

    nm_assert(!call_id->dbus.cancellable);

    call_id->dbus.cancellable = g_cancellable_new();

    g_dbus_connection_call(priv->dbus_connection,
                           priv->name_owner,
                           FIREWALL_DBUS_PATH,
                           FIREWALL_DBUS_INTERFACE_ZONE,
                           dbus_method,
                           arg,
                           NULL,
                           G_DBUS_CALL_FLAGS_NONE,
                           10000,
                           call_id->dbus.cancellable,
                           _handle_dbus_cb,
                           call_id);
}

static NMFirewalldManagerCallId *
_start_request(NMFirewalldManager *                self,
               OpsType                             ops_type,
               const char *                        iface,
               const char *                        zone,
               NMFirewalldManagerAddRemoveCallback callback,
               gpointer                            user_data)
{
    NMFirewalldManagerPrivate *priv;
    NMFirewalldManagerCallId * call_id;

    g_return_val_if_fail(NM_IS_FIREWALLD_MANAGER(self), NULL);
    g_return_val_if_fail(iface && *iface, NULL);

    priv = NM_FIREWALLD_MANAGER_GET_PRIVATE(self);

    call_id = _cb_info_create(self, ops_type, iface, zone, callback, user_data);

    _LOGD(call_id,
          "firewall zone %s %s:%s%s%s%s",
          _ops_type_to_string(call_id->ops_type),
          iface,
          NM_PRINT_FMT_QUOTED(zone, "\"", zone, "\"", "default"),
          call_id->is_idle ? " (not running, simulate success)"
                           : (!priv->name_owner ? " (waiting to initialize)" : ""));

    if (!call_id->is_idle) {
        if (priv->name_owner)
            _handle_dbus_start(self, call_id);
        if (!call_id->callback) {
            /* if the user did not provide a callback, the call_id is useless.
             * Especially, the user cannot use the call-id to cancel the request,
             * because he cannot know whether the request is still pending.
             *
             * Hence, returning %NULL doesn't mean that the request could not be started
             * (this function never fails and always starts a request). */
            return NULL;
        }
    } else {
        if (!_handle_idle_start(self, call_id)) {
            /* if the user did not provide a callback and firewalld is not running,
             * there is no point in scheduling an idle-request to fake success. Just
             * return right away. */
            return NULL;
        }
    }

    return call_id;
}

NMFirewalldManagerCallId *
nm_firewalld_manager_add_or_change_zone(NMFirewalldManager *self,
                                        const char *        iface,
                                        const char *        zone,
                                        gboolean            add, /* TRUE == add, FALSE == change */
                                        NMFirewalldManagerAddRemoveCallback callback,
                                        gpointer                            user_data)
{
    return _start_request(self,
                          add ? OPS_TYPE_ADD : OPS_TYPE_CHANGE,
                          iface,
                          zone,
                          callback,
                          user_data);
}

NMFirewalldManagerCallId *
nm_firewalld_manager_remove_from_zone(NMFirewalldManager *                self,
                                      const char *                        iface,
                                      const char *                        zone,
                                      NMFirewalldManagerAddRemoveCallback callback,
                                      gpointer                            user_data)
{
    return _start_request(self, OPS_TYPE_REMOVE, iface, zone, callback, user_data);
}

void
nm_firewalld_manager_cancel_call(NMFirewalldManagerCallId *call_id)
{
    NMFirewalldManager *       self;
    NMFirewalldManagerPrivate *priv;
    gs_free_error GError *error = NULL;

    g_return_if_fail(call_id);
    g_return_if_fail(NM_IS_FIREWALLD_MANAGER(call_id->self));
    g_return_if_fail(!c_list_is_empty(&call_id->lst));

    self = call_id->self;
    priv = NM_FIREWALLD_MANAGER_GET_PRIVATE(self);

    nm_assert(c_list_contains(&priv->pending_calls, &call_id->lst));

    nm_utils_error_set_cancelled(&error, FALSE, "NMFirewalldManager");

    _LOGD(call_id, "complete: cancel (%s)", error->message);

    _cb_info_complete(call_id, error);
}

/*****************************************************************************/

static void
name_owner_changed(NMFirewalldManager *self, const char *owner)
{
    _nm_unused gs_unref_object NMFirewalldManager *self_keep_alive = g_object_ref(self);
    NMFirewalldManagerPrivate *                    priv = NM_FIREWALLD_MANAGER_GET_PRIVATE(self);
    gboolean                                       was_running;
    gboolean                                       now_running;
    gboolean                                       just_initied;
    gboolean                                       name_owner_changed;

    owner = nm_str_not_empty(owner);

    if (!owner)
        _LOGT(NULL, "D-Bus name for firewalld has no owner (firewall stopped)");
    else
        _LOGT(NULL, "D-Bus name for firewalld has owner %s (firewall started)", owner);

    was_running  = _get_running(priv);
    just_initied = !priv->dbus_inited;

    priv->dbus_inited  = TRUE;
    name_owner_changed = nm_utils_strdup_reset(&priv->name_owner, owner);

    now_running = _get_running(priv);

    if (just_initied) {
        NMFirewalldManagerCallId *call_id_safe;
        NMFirewalldManagerCallId *call_id;

        /* We kick of the requests that we have pending. Note that this is
         * entirely asynchronous and also we don't invoke any callbacks for
         * the user.
         * Even _handle_idle_start() just schedules an idle handler. That is,
         * because we don't want to callback to the user before emitting the
         * DISCONNECTED signal below. Also, emitting callbacks means the user
         * can call back to modify the list of pending-calls and we'd have
         * to handle reentrancy. */
        c_list_for_each_entry_safe (call_id, call_id_safe, &priv->pending_calls, lst) {
            nm_assert(!call_id->is_idle);
            nm_assert(call_id->dbus.arg);

            if (priv->name_owner) {
                _LOGD(call_id, "initalizing: make D-Bus call");
                _handle_dbus_start(self, call_id);
            } else {
                /* we don't want to invoke callbacks to the user right away. That is because
                 * the user might schedule/cancel more calls, which messes up the order.
                 *
                 * Instead, convert the pending calls to idle requests... */
                nm_clear_pointer(&call_id->dbus.arg, g_variant_unref);
                call_id->is_idle = TRUE;
                _LOGD(call_id, "initializing: fake success on idle");
                _handle_idle_start(self, call_id);
            }
        }
    }

    if (just_initied)
        _signal_emit_state_changed(self, NM_FIREWALLD_MANAGER_STATE_CHANGED_TYPE_INITIALIZED);
    else if (was_running != now_running || name_owner_changed)
        _signal_emit_state_changed(self,
                                   NM_FIREWALLD_MANAGER_STATE_CHANGED_TYPE_NAME_OWNER_CHANGED);
}

static void
reloaded_cb(GDBusConnection *connection,
            const char *     sender_name,
            const char *     object_path,
            const char *     interface_name,
            const char *     signal_name,
            GVariant *       parameters,
            gpointer         user_data)
{
    NMFirewalldManager *       self = user_data;
    NMFirewalldManagerPrivate *priv = NM_FIREWALLD_MANAGER_GET_PRIVATE(self);

    if (!nm_streq0(sender_name, priv->name_owner))
        return;

    _LOGT(NULL, "reloaded signal received");
    _signal_emit_state_changed(self, NM_FIREWALLD_MANAGER_STATE_CHANGED_TYPE_RELOADED);
}

static void
name_owner_changed_cb(GDBusConnection *connection,
                      const char *     sender_name,
                      const char *     object_path,
                      const char *     interface_name,
                      const char *     signal_name,
                      GVariant *       parameters,
                      gpointer         user_data)
{
    NMFirewalldManager *self = user_data;
    const char *        new_owner;

    if (!g_variant_is_of_type(parameters, G_VARIANT_TYPE("(sss)")))
        return;

    g_variant_get(parameters, "(&s&s&s)", NULL, NULL, &new_owner);

    name_owner_changed(self, new_owner);
}

static void
get_name_owner_cb(const char *name_owner, GError *error, gpointer user_data)
{
    NMFirewalldManager *       self;
    NMFirewalldManagerPrivate *priv;

    if (nm_utils_error_is_cancelled(error))
        return;

    self = user_data;
    priv = NM_FIREWALLD_MANAGER_GET_PRIVATE(self);

    g_clear_object(&priv->get_name_owner_cancellable);

    name_owner_changed(self, name_owner);
}

/*****************************************************************************/

static void
nm_firewalld_manager_init(NMFirewalldManager *self)
{
    NMFirewalldManagerPrivate *priv = NM_FIREWALLD_MANAGER_GET_PRIVATE(self);

    c_list_init(&priv->pending_calls);

    priv->dbus_connection = nm_g_object_ref(NM_MAIN_DBUS_CONNECTION_GET);

    if (!priv->dbus_connection) {
        _LOGD(NULL, "no D-Bus connection");
        return;
    }

    priv->reloaded_id = g_dbus_connection_signal_subscribe(priv->dbus_connection,
                                                           FIREWALL_DBUS_SERVICE,
                                                           FIREWALL_DBUS_INTERFACE,
                                                           "Reloaded",
                                                           FIREWALL_DBUS_PATH,
                                                           NULL,
                                                           G_DBUS_SIGNAL_FLAGS_NONE,
                                                           reloaded_cb,
                                                           self,
                                                           NULL);

    priv->name_owner_changed_id =
        nm_dbus_connection_signal_subscribe_name_owner_changed(priv->dbus_connection,
                                                               FIREWALL_DBUS_SERVICE,
                                                               name_owner_changed_cb,
                                                               self,
                                                               NULL);

    priv->get_name_owner_cancellable = g_cancellable_new();
    nm_dbus_connection_call_get_name_owner(priv->dbus_connection,
                                           FIREWALL_DBUS_SERVICE,
                                           -1,
                                           priv->get_name_owner_cancellable,
                                           get_name_owner_cb,
                                           self);
}

static void
dispose(GObject *object)
{
    NMFirewalldManager *       self = NM_FIREWALLD_MANAGER(object);
    NMFirewalldManagerPrivate *priv = NM_FIREWALLD_MANAGER_GET_PRIVATE(self);

    /* as every pending operation takes a reference to the manager,
     * we don't expect pending operations at this point. */
    nm_assert(c_list_is_empty(&priv->pending_calls));

    nm_clear_g_dbus_connection_signal(priv->dbus_connection, &priv->reloaded_id);
    nm_clear_g_dbus_connection_signal(priv->dbus_connection, &priv->name_owner_changed_id);

    nm_clear_g_cancellable(&priv->get_name_owner_cancellable);

    G_OBJECT_CLASS(nm_firewalld_manager_parent_class)->dispose(object);

    g_clear_object(&priv->dbus_connection);
}

static void
nm_firewalld_manager_class_init(NMFirewalldManagerClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS(klass);

    object_class->dispose = dispose;

    signals[STATE_CHANGED] = g_signal_new(NM_FIREWALLD_MANAGER_STATE_CHANGED,
                                          G_OBJECT_CLASS_TYPE(object_class),
                                          G_SIGNAL_RUN_FIRST,
                                          0,
                                          NULL,
                                          NULL,
                                          g_cclosure_marshal_VOID__INT,
                                          G_TYPE_NONE,
                                          1,
                                          G_TYPE_INT /* signal-type */);
}
