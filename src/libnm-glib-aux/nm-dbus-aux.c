/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2019 Red Hat, Inc.
 */

#include "libnm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nm-dbus-aux.h"

/*****************************************************************************/

static void
_nm_dbus_connection_call_get_name_owner_cb(GObject *source, GAsyncResult *res, gpointer user_data)
{
    gs_unref_variant GVariant *ret           = NULL;
    gs_free_error GError *             error = NULL;
    const char *                       owner = NULL;
    gpointer                           orig_user_data;
    NMDBusConnectionCallGetNameOwnerCb callback;

    nm_utils_user_data_unpack(user_data, &orig_user_data, &callback);

    ret = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), res, &error);
    if (ret)
        g_variant_get(ret, "(&s)", &owner);

    callback(owner, error, orig_user_data);
}

void
nm_dbus_connection_call_get_name_owner(GDBusConnection *                  dbus_connection,
                                       const char *                       service_name,
                                       int                                timeout_msec,
                                       GCancellable *                     cancellable,
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
    gs_unref_variant GVariant *ret      = NULL;
    gs_free_error GError *        error = NULL;
    gpointer                      orig_user_data;
    NMDBusConnectionCallDefaultCb callback;

    nm_utils_user_data_unpack(user_data, &orig_user_data, &callback);

    ret = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), res, &error);

    nm_assert((!!ret) != (!!error));

    callback(ret, error, orig_user_data);
}

void
nm_dbus_connection_call_get_all(GDBusConnection *             dbus_connection,
                                const char *                  bus_name,
                                const char *                  object_path,
                                const char *                  interface_name,
                                int                           timeout_msec,
                                GCancellable *                cancellable,
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
nm_dbus_connection_call_set(GDBusConnection *             dbus_connection,
                            const char *                  bus_name,
                            const char *                  object_path,
                            const char *                  interface_name,
                            const char *                  property_name,
                            GVariant *                    value,
                            int                           timeout_msec,
                            GCancellable *                cancellable,
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
_nm_dbus_connection_call_get_managed_objects_cb(GObject *     source,
                                                GAsyncResult *res,
                                                gpointer      user_data)
{
    gs_unref_variant GVariant *ret      = NULL;
    gs_unref_variant GVariant *arg      = NULL;
    gs_free_error GError *        error = NULL;
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
nm_dbus_connection_call_get_managed_objects(GDBusConnection *             dbus_connection,
                                            const char *                  bus_name,
                                            const char *                  object_path,
                                            GDBusCallFlags                flags,
                                            int                           timeout_msec,
                                            GCancellable *                cancellable,
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
_call_finish_cb(GObject *     source,
                GAsyncResult *result,
                gpointer      user_data,
                gboolean      return_void,
                gboolean      strip_dbus_error)
{
    gs_unref_object GTask *task      = user_data;
    gs_unref_variant GVariant *ret   = NULL;
    GError *                   error = NULL;

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
nm_dbus_connection_call_finish_void_strip_dbus_error_cb(GObject *     source,
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
nm_dbus_connection_call_finish_variant_strip_dbus_error_cb(GObject *     source,
                                                           GAsyncResult *result,
                                                           gpointer      user_data)
{
    _call_finish_cb(source, result, user_data, FALSE, TRUE);
}

/*****************************************************************************/

gboolean
_nm_dbus_error_is(GError *error, ...)
{
    gs_free char *dbus_error = NULL;
    const char *  name;
    va_list       ap;

    dbus_error = g_dbus_error_get_remote_error(error);
    if (!dbus_error)
        return FALSE;

    va_start(ap, error);
    while ((name = va_arg(ap, const char *))) {
        if (nm_streq(dbus_error, name)) {
            va_end(ap);
            return TRUE;
        }
    }
    va_end(ap);

    return FALSE;
}
