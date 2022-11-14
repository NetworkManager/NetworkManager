/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2015,2019 Red Hat, Inc.
 */

#include "libnm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nm-dbus-aux.h"

/*****************************************************************************/

static void
_nm_dbus_connection_call_get_name_owner_cb(GObject *source, GAsyncResult *res, gpointer user_data)
{
    gs_unref_variant GVariant         *ret   = NULL;
    gs_free_error GError              *error = NULL;
    const char                        *owner = NULL;
    gpointer                           orig_user_data;
    NMDBusConnectionCallGetNameOwnerCb callback;

    nm_utils_user_data_unpack(user_data, &orig_user_data, &callback);

    ret = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), res, &error);
    if (ret)
        g_variant_get(ret, "(&s)", &owner);

    callback(owner, error, orig_user_data);
}

void
nm_dbus_connection_call_get_name_owner(GDBusConnection                   *dbus_connection,
                                       const char                        *service_name,
                                       int                                timeout_msec,
                                       GCancellable                      *cancellable,
                                       NMDBusConnectionCallGetNameOwnerCb callback,
                                       gpointer                           user_data)
{
    nm_assert(callback);

    g_dbus_connection_call(dbus_connection,
                           DBUS_SERVICE_DBUS,
                           DBUS_PATH_DBUS,
                           DBUS_INTERFACE_DBUS,
                           "GetNameOwner",
                           g_variant_new("(s)", service_name),
                           G_VARIANT_TYPE("(s)"),
                           G_DBUS_CALL_FLAGS_NONE,
                           timeout_msec,
                           cancellable,
                           _nm_dbus_connection_call_get_name_owner_cb,
                           nm_utils_user_data_pack(user_data, callback));
}

/*****************************************************************************/

static void
_nm_dbus_connection_call_default_cb(GObject *source, GAsyncResult *res, gpointer user_data)
{
    gs_unref_variant GVariant    *ret   = NULL;
    gs_free_error GError         *error = NULL;
    gpointer                      orig_user_data;
    NMDBusConnectionCallDefaultCb callback;

    nm_utils_user_data_unpack(user_data, &orig_user_data, &callback);

    ret = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), res, &error);

    nm_assert((!!ret) != (!!error));

    callback(ret, error, orig_user_data);
}

void
nm_dbus_connection_call_get_all(GDBusConnection              *dbus_connection,
                                const char                   *bus_name,
                                const char                   *object_path,
                                const char                   *interface_name,
                                int                           timeout_msec,
                                GCancellable                 *cancellable,
                                NMDBusConnectionCallDefaultCb callback,
                                gpointer                      user_data)
{
    nm_assert(callback);

    g_dbus_connection_call(dbus_connection,
                           bus_name,
                           object_path,
                           DBUS_INTERFACE_PROPERTIES,
                           "GetAll",
                           g_variant_new("(s)", interface_name),
                           G_VARIANT_TYPE("(a{sv})"),
                           G_DBUS_CALL_FLAGS_NONE,
                           timeout_msec,
                           cancellable,
                           _nm_dbus_connection_call_default_cb,
                           nm_utils_user_data_pack(user_data, callback));
}

void
nm_dbus_connection_call_get(GDBusConnection              *dbus_connection,
                            const char                   *bus_name,
                            const char                   *object_path,
                            const char                   *interface_name,
                            const char                   *property_name,
                            int                           timeout_msec,
                            GCancellable                 *cancellable,
                            NMDBusConnectionCallDefaultCb callback,
                            gpointer                      user_data)
{
    nm_assert(callback);

    g_dbus_connection_call(dbus_connection,
                           bus_name,
                           object_path,
                           DBUS_INTERFACE_PROPERTIES,
                           "Get",
                           g_variant_new("(s)", interface_name, property_name),
                           G_VARIANT_TYPE("(v)"),
                           G_DBUS_CALL_FLAGS_NONE,
                           timeout_msec,
                           cancellable,
                           _nm_dbus_connection_call_default_cb,
                           nm_utils_user_data_pack(user_data, callback));
}

void
nm_dbus_connection_call_set(GDBusConnection              *dbus_connection,
                            const char                   *bus_name,
                            const char                   *object_path,
                            const char                   *interface_name,
                            const char                   *property_name,
                            GVariant                     *value,
                            int                           timeout_msec,
                            GCancellable                 *cancellable,
                            NMDBusConnectionCallDefaultCb callback,
                            gpointer                      user_data)
{
    g_dbus_connection_call(dbus_connection,
                           bus_name,
                           object_path,
                           DBUS_INTERFACE_PROPERTIES,
                           "Set",
                           g_variant_new("(ssv)", interface_name, property_name, value),
                           G_VARIANT_TYPE("()"),
                           G_DBUS_CALL_FLAGS_NONE,
                           timeout_msec,
                           cancellable,
                           callback ? _nm_dbus_connection_call_default_cb : NULL,
                           callback ? nm_utils_user_data_pack(user_data, callback) : NULL);
}

/*****************************************************************************/

static void
_nm_dbus_connection_call_get_managed_objects_cb(GObject      *source,
                                                GAsyncResult *res,
                                                gpointer      user_data)
{
    gs_unref_variant GVariant    *ret   = NULL;
    gs_unref_variant GVariant    *arg   = NULL;
    gs_free_error GError         *error = NULL;
    gpointer                      orig_user_data;
    NMDBusConnectionCallDefaultCb callback;

    nm_utils_user_data_unpack(user_data, &orig_user_data, &callback);

    ret = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), res, &error);

    nm_assert((!!ret) != (!!error));

    if (ret) {
        nm_assert(g_variant_is_of_type(ret, G_VARIANT_TYPE("(a{oa{sa{sv}}})")));
        arg = g_variant_get_child_value(ret, 0);
    }

    callback(arg, error, orig_user_data);
}

void
nm_dbus_connection_call_get_managed_objects(GDBusConnection              *dbus_connection,
                                            const char                   *bus_name,
                                            const char                   *object_path,
                                            GDBusCallFlags                flags,
                                            int                           timeout_msec,
                                            GCancellable                 *cancellable,
                                            NMDBusConnectionCallDefaultCb callback,
                                            gpointer                      user_data)
{
    nm_assert(callback);

    g_dbus_connection_call(dbus_connection,
                           bus_name,
                           object_path,
                           DBUS_INTERFACE_OBJECT_MANAGER,
                           "GetManagedObjects",
                           NULL,
                           G_VARIANT_TYPE("(a{oa{sa{sv}}})"),
                           flags,
                           timeout_msec,
                           cancellable,
                           _nm_dbus_connection_call_get_managed_objects_cb,
                           nm_utils_user_data_pack(user_data, callback));
}

/*****************************************************************************/

static void
_call_finish_cb(GObject      *source,
                GAsyncResult *result,
                gpointer      user_data,
                gboolean      return_void,
                gboolean      strip_dbus_error)
{
    gs_unref_object GTask     *task  = user_data;
    gs_unref_variant GVariant *ret   = NULL;
    GError                    *error = NULL;

    nm_assert(G_IS_DBUS_CONNECTION(source));
    nm_assert(G_IS_TASK(user_data));

    ret = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), result, &error);
    if (!ret) {
        if (strip_dbus_error)
            g_dbus_error_strip_remote_error(error);
        g_task_return_error(task, error);
        return;
    }

    if (!return_void)
        g_task_return_pointer(task, g_steal_pointer(&ret), (GDestroyNotify) g_variant_unref);
    else {
        nm_assert(g_variant_is_of_type(ret, G_VARIANT_TYPE("()")));
        g_task_return_boolean(task, TRUE);
    }
}

/**
 * nm_dbus_connection_call_finish_void_cb:
 *
 * A default callback to pass as callback to g_dbus_connection_call().
 *
 * - user_data must be a GTask, whose reference will be consumed by the
 *   callback.
 * - the return GVariant must be a empty tuple "()".
 * - the GTask is returned either with error or TRUE boolean.
 */
void
nm_dbus_connection_call_finish_void_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    _call_finish_cb(source, result, user_data, TRUE, FALSE);
}

/**
 * nm_dbus_connection_call_finish_void_strip_dbus_error_cb:
 *
 * Like nm_dbus_connection_call_finish_void_cb(). The difference
 * is that on error this will first call g_dbus_error_strip_remote_error() on the error.
 */
void
nm_dbus_connection_call_finish_void_strip_dbus_error_cb(GObject      *source,
                                                        GAsyncResult *result,
                                                        gpointer      user_data)
{
    _call_finish_cb(source, result, user_data, TRUE, TRUE);
}

/**
 * nm_dbus_connection_call_finish_variant_cb:
 *
 * A default callback to pass as callback to g_dbus_connection_call().
 *
 * - user_data must be a GTask, whose reference will be consumed by the
 *   callback.
 * - the GTask is returned either with error or with a pointer containing the GVariant.
 */
void
nm_dbus_connection_call_finish_variant_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    _call_finish_cb(source, result, user_data, FALSE, FALSE);
}

/**
 * nm_dbus_connection_call_finish_variant_strip_dbus_error_cb:
 *
 * Like nm_dbus_connection_call_finish_variant_strip_dbus_error_cb(). The difference
 * is that on error this will first call g_dbus_error_strip_remote_error() on the error.
 */
void
nm_dbus_connection_call_finish_variant_strip_dbus_error_cb(GObject      *source,
                                                           GAsyncResult *result,
                                                           gpointer      user_data)
{
    _call_finish_cb(source, result, user_data, FALSE, TRUE);
}

/*****************************************************************************/

typedef struct {
    char               *bus_name;
    char               *object_path;
    char               *interface_name;
    char               *method_name;
    GVariant           *parameters;
    GDBusConnection    *connection;
    const GVariantType *reply_type;
    int                 timeout_msec;
} CallAsyncInfo;

static void
call_async_info_destroy(CallAsyncInfo *info)
{
    g_free(info->bus_name);
    g_free(info->object_path);
    g_free(info->interface_name);
    g_free(info->method_name);
    g_variant_unref(info->parameters);
    nm_g_object_unref(info->connection);
    g_free(info);
}

static void
call_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    gs_unref_object GTask *task  = user_data;
    GError                *error = NULL;
    GVariant              *ret;

    ret = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), result, &error);
    if (!ret) {
        g_task_return_error(task, error);
        return;
    }

    g_task_return_pointer(task, ret, (GDestroyNotify) g_variant_unref);
}

static void
call_bus_get_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    gs_unref_object GTask *task = user_data;
    GCancellable          *cancellable;
    CallAsyncInfo         *info;
    GError                *error = NULL;

    info             = g_task_get_task_data(task);
    info->connection = g_bus_get_finish(result, &error);
    cancellable      = g_task_get_cancellable(task);

    if (!info->connection) {
        g_task_return_error(task, g_steal_pointer(&error));
        return;
    }

    g_dbus_connection_call(info->connection,
                           info->bus_name,
                           info->object_path,
                           info->interface_name,
                           info->method_name,
                           info->parameters,
                           info->reply_type,
                           G_DBUS_CALL_FLAGS_NONE,
                           info->timeout_msec,
                           cancellable,
                           call_cb,
                           g_steal_pointer(&task));
}

void
nm_dbus_call(GBusType            bus_type,
             const char         *bus_name,
             const char         *object_path,
             const char         *interface_name,
             const char         *method_name,
             GVariant           *parameters,
             const GVariantType *reply_type,
             GCancellable       *cancellable,
             int                 timeout_msec,
             GAsyncReadyCallback callback,
             gpointer            user_data)
{
    GTask         *task;
    CallAsyncInfo *info;

    info  = g_new(CallAsyncInfo, 1);
    *info = (CallAsyncInfo){
        .bus_name       = g_strdup(bus_name),
        .object_path    = g_strdup(object_path),
        .interface_name = g_strdup(interface_name),
        .method_name    = g_strdup(method_name),
        .parameters     = g_variant_ref_sink(parameters),
        .reply_type     = reply_type,
        .timeout_msec   = timeout_msec,
    };

    task = nm_g_task_new(NULL, cancellable, nm_dbus_call, callback, user_data);
    g_task_set_task_data(task, info, (GDestroyNotify) call_async_info_destroy);

    g_bus_get(bus_type, cancellable, call_bus_get_cb, task);
}

GVariant *
nm_dbus_call_finish(GAsyncResult *result, GError **error)
{
    nm_assert(nm_g_task_is_valid(result, NULL, nm_dbus_call));

    return g_task_propagate_pointer(G_TASK(result), error);
}

/*****************************************************************************/

gboolean
_nm_dbus_error_is(GError *error, ...)
{
    gs_free char *dbus_error = NULL;
    const char   *name;
    va_list       ap;
    gboolean      found = FALSE;

    /* This should only be used for "foreign" D-Bus errors (eg, errors
     * from BlueZ or wpa_supplicant). All NetworkManager D-Bus errors
     * should be properly mapped by gdbus to one of the domains/codes in
     * nm-errors.h. */

    dbus_error = g_dbus_error_get_remote_error(error);
    if (!dbus_error)
        return FALSE;

    va_start(ap, error);
    while ((name = va_arg(ap, const char *))) {
        if (nm_streq(dbus_error, name)) {
            found = TRUE;
            break;
        }
    }
    va_end(ap);

    return found;
}

/*****************************************************************************/

typedef struct {
    GDBusConnection **p_dbus_connection;
    GError          **p_error;
} BusGetData;

static void
_bus_get_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    BusGetData *data = user_data;

    *data->p_dbus_connection = g_bus_get_finish(result, data->p_error);
}

/**
 * nm_g_bus_get_blocking:
 * @cancellable: (allow-none): a #GCancellable to abort the operation.
 * @error: (allow-none): the error.
 *
 * This calls g_bus_get(), but iterates the current (thread-default) GMainContext
 * until the response is ready. As such, it's similar to g_bus_get_sync(),
 * but it allows to cancel the operation (without having multiple threads).
 *
 * Returns: (transfer full): the new #GDBusConnection or %NULL on error.
 */
GDBusConnection *
nm_g_bus_get_blocking(GCancellable *cancellable, GError **error)
{
    gs_free_error GError            *local_error     = NULL;
    gs_unref_object GDBusConnection *dbus_connection = NULL;
    GMainContext                    *main_context    = g_main_context_get_thread_default();
    BusGetData                       data            = {
                                         .p_dbus_connection = &dbus_connection,
                                         .p_error           = &local_error,
    };

    g_bus_get(G_BUS_TYPE_SYSTEM, cancellable, _bus_get_cb, &data);

    while (!dbus_connection && !local_error)
        g_main_context_iteration(main_context, TRUE);

    if (!dbus_connection) {
        g_propagate_error(error, g_steal_pointer(&local_error));
        return NULL;
    }

    return g_steal_pointer(&dbus_connection);
}

/*****************************************************************************/

void
nm_dbus_connection_call_blocking_callback(GObject *source, GAsyncResult *res, gpointer user_data)
{
    NMDBusConnectionCallBlockingData *data = user_data;

    nm_assert(data);
    nm_assert(!data->result);
    nm_assert(!data->error);

    data->result = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), res, &data->error);
}

GVariant *
nm_dbus_connection_call_blocking(NMDBusConnectionCallBlockingData *data, GError **error)
{
    GMainContext              *main_context = g_main_context_get_thread_default();
    gs_free_error GError      *local_error  = NULL;
    gs_unref_variant GVariant *result       = NULL;

    nm_assert(data);

    while (!data->result && !data->error)
        g_main_context_iteration(main_context, TRUE);

    local_error = g_steal_pointer(&data->error);
    result      = g_steal_pointer(&data->result);

    if (!result) {
        g_propagate_error(error, g_steal_pointer(&local_error));
        return NULL;
    }

    return g_steal_pointer(&result);
}

/*****************************************************************************/

typedef struct {
    char               *signal_name;
    const GVariantType *signature;
} NMDBusSignalData;

static void
dbus_signal_data_free(gpointer data, GClosure *closure)
{
    NMDBusSignalData *sd = data;

    g_free(sd->signal_name);
    g_slice_free(NMDBusSignalData, sd);
}

static void
dbus_signal_meta_marshal(GClosure     *closure,
                         GValue       *return_value,
                         guint         n_param_values,
                         const GValue *param_values,
                         gpointer      invocation_hint,
                         gpointer      marshal_data)
{
    NMDBusSignalData *sd = marshal_data;
    const char       *signal_name;
    GVariant         *parameters;
    gs_free GValue   *closure_params_free = NULL;
    GValue           *closure_params;
    gsize             n_params;
    gsize             i;

    g_return_if_fail(n_param_values == 4);

    signal_name = g_value_get_string(&param_values[2]);
    parameters  = g_value_get_variant(&param_values[3]);

    if (!nm_streq(signal_name, sd->signal_name))
        return;

    if (sd->signature) {
        if (!g_variant_is_of_type(parameters, sd->signature)) {
            g_warning("%p: got signal '%s' but parameters were of type '%s', not '%s'",
                      g_value_get_object(&param_values[0]),
                      signal_name,
                      g_variant_get_type_string(parameters),
                      g_variant_type_peek_string(sd->signature));
            return;
        }

        n_params = g_variant_n_children(parameters) + 1;
    } else
        n_params = 1;

    closure_params = nm_malloc0_maybe_a(240, sizeof(GValue) * n_params, &closure_params_free);
    g_value_init(&closure_params[0], G_TYPE_OBJECT);
    g_value_copy(&param_values[0], &closure_params[0]);

    for (i = 1; i < n_params; i++) {
        gs_unref_variant GVariant *param = NULL;

        param = g_variant_get_child_value(parameters, i - 1);
        if (g_variant_is_of_type(param, G_VARIANT_TYPE("ay"))
            || g_variant_is_of_type(param, G_VARIANT_TYPE("aay"))) {
            /* g_dbus_gvariant_to_gvalue() thinks 'ay' means "non-UTF-8 NUL-terminated string" */
            g_value_init(&closure_params[i], G_TYPE_VARIANT);
            g_value_set_variant(&closure_params[i], param);
        } else
            g_dbus_gvariant_to_gvalue(param, &closure_params[i]);
    }

    g_cclosure_marshal_generic(closure, NULL, n_params, closure_params, invocation_hint, NULL);

    for (i = 0; i < n_params; i++)
        g_value_unset(&closure_params[i]);
}

/**
 * _nm_dbus_proxy_signal_connect_data:
 * @proxy: a #GDBusProxy
 * @signal_name: the D-Bus signal to connect to
 * @signature: (allow-none): the signal's type signature (must be a tuple)
 * @c_handler: the signal handler function
 * @data: (allow-none): data to pass to @c_handler
 * @destroy_data: (allow-none): closure destroy notify for @data
 * @connect_flags: connection flags
 *
 * Connects to the D-Bus signal @signal_name on @proxy. @c_handler must be a
 * void function whose first argument is a #GDBusProxy, followed by arguments
 * for each element of @signature, ending with a #gpointer argument for @data.
 *
 * The argument types in @c_handler correspond to the types output by
 * g_dbus_gvariant_to_gvalue(), except for 'ay' and 'aay'. In particular:
 * - both 16-bit and 32-bit integers are passed as #int/#guint
 * - 'as' values are passed as #GStrv (char **)
 * - all other array, tuple, and dict types are passed as #GVariant
 *
 * If @signature is %NULL, then the signal's parameters will be ignored, and
 * @c_handler should take only the #GDBusProxy and #gpointer arguments.
 *
 * Returns: the signal handler ID, which can be used with
 *   g_signal_handler_remove(). Beware that because of the way the signal is
 *   connected, you will not be able to remove it with
 *   g_signal_handlers_disconnect_by_func(), although
 *   g_signal_handlers_disconnect_by_data() will work correctly.
 */
gulong
_nm_dbus_proxy_signal_connect_data(GDBusProxy         *proxy,
                                   const char         *signal_name,
                                   const GVariantType *signature,
                                   GCallback           c_handler,
                                   gpointer            data,
                                   GClosureNotify      destroy_data,
                                   GConnectFlags       connect_flags)
{
    NMDBusSignalData *sd;
    GClosure         *closure;
    gboolean          swapped = !!(connect_flags & G_CONNECT_SWAPPED);
    gboolean          after   = !!(connect_flags & G_CONNECT_AFTER);

    g_return_val_if_fail(G_IS_DBUS_PROXY(proxy), 0);
    g_return_val_if_fail(signal_name != NULL, 0);
    g_return_val_if_fail(signature == NULL || g_variant_type_is_tuple(signature), 0);
    g_return_val_if_fail(c_handler != NULL, 0);

    sd              = g_slice_new(NMDBusSignalData);
    sd->signal_name = g_strdup(signal_name);
    sd->signature   = signature;

    closure = (swapped ? g_cclosure_new_swap : g_cclosure_new)(c_handler, data, destroy_data);
    g_closure_set_marshal(closure, g_cclosure_marshal_generic);
    g_closure_set_meta_marshal(closure, sd, dbus_signal_meta_marshal);
    g_closure_add_finalize_notifier(closure, sd, dbus_signal_data_free);

    return g_signal_connect_closure(proxy, "g-signal", closure, after);
}

/*****************************************************************************/

static gboolean
_nm_dbus_typecheck_response(GVariant *response, const GVariantType *reply_type, GError **error)
{
    g_return_val_if_fail(response, FALSE);

    if (!reply_type)
        return TRUE;
    if (g_variant_is_of_type(response, reply_type))
        return TRUE;

    /* This is the same error code that g_dbus_connection_call() returns if
     * @reply_type doesn't match.
     */
    g_set_error(error,
                G_IO_ERROR,
                G_IO_ERROR_INVALID_ARGUMENT,
                _("Method returned type '%s', but expected '%s'"),
                g_variant_get_type_string(response),
                g_variant_type_peek_string(reply_type));
    return FALSE;
}

/**
 * _nm_dbus_proxy_call_finish:
 * @proxy: A #GDBusProxy.
 * @res: A #GAsyncResult obtained from the #GAsyncReadyCallback passed to
 *   g_dbus_proxy_call().
 * @reply_type: (allow-none): the expected type of the reply, or %NULL
 * @error: Return location for error or %NULL.
 *
 * Finishes an operation started with g_dbus_proxy_call(), as with
 * g_dbus_proxy_call_finish(), except thatif @reply_type is non-%NULL, then it
 * will also check that the response matches that type signature, and return
 * an error if not.
 *
 * Returns: %NULL if @error is set. Otherwise, a #GVariant tuple with
 * return values. Free with g_variant_unref().
 */
GVariant *
_nm_dbus_proxy_call_finish(GDBusProxy         *proxy,
                           GAsyncResult       *res,
                           const GVariantType *reply_type,
                           GError            **error)
{
    GVariant *variant;

    variant = g_dbus_proxy_call_finish(proxy, res, error);
    if (variant && !_nm_dbus_typecheck_response(variant, reply_type, error))
        nm_clear_pointer(&variant, g_variant_unref);
    return variant;
}
