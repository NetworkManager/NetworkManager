/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2019 Red Hat, Inc.
 */

#ifndef __NM_DBUS_AUX_H__
#define __NM_DBUS_AUX_H__

#include "libnm-std-aux/nm-dbus-compat.h"

/*****************************************************************************/

static inline gboolean
nm_clear_g_dbus_connection_signal(GDBusConnection *dbus_connection, guint *id)
{
    guint v;

    if (id && (v = *id)) {
        *id = 0;
        g_dbus_connection_signal_unsubscribe(dbus_connection, v);
        return TRUE;
    }
    return FALSE;
}

/*****************************************************************************/

typedef void (*NMDBusConnectionCallDefaultCb)(GVariant *result, GError *error, gpointer user_data);

/*****************************************************************************/

static inline void
nm_dbus_connection_call_start_service_by_name(GDBusConnection    *dbus_connection,
                                              const char         *name,
                                              int                 timeout_msec,
                                              GCancellable       *cancellable,
                                              GAsyncReadyCallback callback,
                                              gpointer            user_data)
{
    g_dbus_connection_call(dbus_connection,
                           DBUS_SERVICE_DBUS,
                           DBUS_PATH_DBUS,
                           DBUS_INTERFACE_DBUS,
                           "StartServiceByName",
                           g_variant_new("(su)", name, 0u),
                           G_VARIANT_TYPE("(u)"),
                           G_DBUS_CALL_FLAGS_NONE,
                           timeout_msec,
                           cancellable,
                           callback,
                           user_data);
}

/*****************************************************************************/

static inline guint
nm_dbus_connection_signal_subscribe_name_owner_changed(GDBusConnection    *dbus_connection,
                                                       const char         *service_name,
                                                       GDBusSignalCallback callback,
                                                       gpointer            user_data,
                                                       GDestroyNotify      user_data_free_func)

{
    return g_dbus_connection_signal_subscribe(dbus_connection,
                                              DBUS_SERVICE_DBUS,
                                              DBUS_INTERFACE_DBUS,
                                              "NameOwnerChanged",
                                              DBUS_PATH_DBUS,
                                              service_name,
                                              G_DBUS_SIGNAL_FLAGS_NONE,
                                              callback,
                                              user_data,
                                              user_data_free_func);
}

typedef void (*NMDBusConnectionCallGetNameOwnerCb)(const char *name_owner,
                                                   GError     *error,
                                                   gpointer    user_data);

void nm_dbus_connection_call_get_name_owner(GDBusConnection                   *dbus_connection,
                                            const char                        *service_name,
                                            int                                timeout_msec,
                                            GCancellable                      *cancellable,
                                            NMDBusConnectionCallGetNameOwnerCb callback,
                                            gpointer                           user_data);

static inline void
nm_dbus_connection_call_request_name(GDBusConnection    *dbus_connection,
                                     const char         *name,
                                     guint32             flags,
                                     int                 timeout_msec,
                                     GCancellable       *cancellable,
                                     GAsyncReadyCallback callback,
                                     gpointer            user_data)
{
    g_dbus_connection_call(dbus_connection,
                           DBUS_SERVICE_DBUS,
                           DBUS_PATH_DBUS,
                           DBUS_INTERFACE_DBUS,
                           "RequestName",
                           g_variant_new("(su)", name, flags),
                           G_VARIANT_TYPE("(u)"),
                           G_DBUS_CALL_FLAGS_NONE,
                           timeout_msec,
                           cancellable,
                           callback,
                           user_data);
}

static inline guint
nm_dbus_connection_signal_subscribe_properties_changed(GDBusConnection    *dbus_connection,
                                                       const char         *bus_name,
                                                       const char         *object_path,
                                                       const char         *interface_name,
                                                       GDBusSignalCallback callback,
                                                       gpointer            user_data,
                                                       GDestroyNotify      user_data_free_func)

{
    nm_assert(bus_name);

    /* it seems that using a non-unique name causes problems that we get signals
     * also from unrelated senders. Usually, you are anyway monitoring the name-owner,
     * so you should have the unique name at hand.
     *
     * If not, investigate this, ensure that it works, and lift this restriction. */
    nm_assert(g_dbus_is_unique_name(bus_name));

    return g_dbus_connection_signal_subscribe(dbus_connection,
                                              bus_name,
                                              DBUS_INTERFACE_PROPERTIES,
                                              "PropertiesChanged",
                                              object_path,
                                              interface_name,
                                              G_DBUS_SIGNAL_FLAGS_NONE,
                                              callback,
                                              user_data,
                                              user_data_free_func);
}

void nm_dbus_connection_call_get_all(GDBusConnection              *dbus_connection,
                                     const char                   *bus_name,
                                     const char                   *object_path,
                                     const char                   *interface_name,
                                     int                           timeout_msec,
                                     GCancellable                 *cancellable,
                                     NMDBusConnectionCallDefaultCb callback,
                                     gpointer                      user_data);

void nm_dbus_connection_call_get(GDBusConnection              *dbus_connection,
                                 const char                   *bus_name,
                                 const char                   *object_path,
                                 const char                   *interface_name,
                                 const char                   *property_name,
                                 int                           timeout_msec,
                                 GCancellable                 *cancellable,
                                 NMDBusConnectionCallDefaultCb callback,
                                 gpointer                      user_data);

void nm_dbus_connection_call_set(GDBusConnection              *dbus_connection,
                                 const char                   *bus_name,
                                 const char                   *object_path,
                                 const char                   *interface_name,
                                 const char                   *property_name,
                                 GVariant                     *value,
                                 int                           timeout_msec,
                                 GCancellable                 *cancellable,
                                 NMDBusConnectionCallDefaultCb callback,
                                 gpointer                      user_data);

/*****************************************************************************/

static inline guint
nm_dbus_connection_signal_subscribe_object_manager(GDBusConnection    *dbus_connection,
                                                   const char         *service_name,
                                                   const char         *object_path,
                                                   const char         *signal_name,
                                                   GDBusSignalCallback callback,
                                                   gpointer            user_data,
                                                   GDestroyNotify      user_data_free_func)
{
    return g_dbus_connection_signal_subscribe(dbus_connection,
                                              service_name,
                                              DBUS_INTERFACE_OBJECT_MANAGER,
                                              signal_name,
                                              object_path,
                                              NULL,
                                              G_DBUS_SIGNAL_FLAGS_NONE,
                                              callback,
                                              user_data,
                                              user_data_free_func);
}

void nm_dbus_connection_call_get_managed_objects(GDBusConnection              *dbus_connection,
                                                 const char                   *bus_name,
                                                 const char                   *object_path,
                                                 GDBusCallFlags                flags,
                                                 int                           timeout_msec,
                                                 GCancellable                 *cancellable,
                                                 NMDBusConnectionCallDefaultCb callback,
                                                 gpointer                      user_data);

/*****************************************************************************/

void
nm_dbus_connection_call_finish_void_cb(GObject *source, GAsyncResult *result, gpointer user_data);

void nm_dbus_connection_call_finish_void_strip_dbus_error_cb(GObject      *source,
                                                             GAsyncResult *result,
                                                             gpointer      user_data);

void nm_dbus_connection_call_finish_variant_cb(GObject      *source,
                                               GAsyncResult *result,
                                               gpointer      user_data);

void nm_dbus_connection_call_finish_variant_strip_dbus_error_cb(GObject      *source,
                                                                GAsyncResult *result,
                                                                gpointer      user_data);

/*****************************************************************************/

void nm_dbus_call(GBusType            bus_type,
                  const char         *bus_name,
                  const char         *object_path,
                  const char         *interface_name,
                  const char         *method_name,
                  GVariant           *parameters,
                  const GVariantType *reply_type,
                  GCancellable       *cancellable,
                  int                 timeout_msec,
                  GAsyncReadyCallback callback,
                  gpointer            user_data);

GVariant *nm_dbus_call_finish(GAsyncResult *result, GError **error);

/*****************************************************************************/

gboolean _nm_dbus_error_is(GError *error, ...) G_GNUC_NULL_TERMINATED;

#define nm_dbus_error_is(error, ...)                           \
    ({                                                         \
        GError *const _error = (error);                        \
                                                               \
        _error &&_nm_dbus_error_is(_error, __VA_ARGS__, NULL); \
    })

#define NM_DBUS_ERROR_NAME_UNKNOWN_METHOD "org.freedesktop.DBus.Error.UnknownMethod"

/*****************************************************************************/

GDBusConnection *nm_g_bus_get_blocking(GCancellable *cancellable, GError **error);

/*****************************************************************************/

typedef struct {
    GVariant *result;
    GError   *error;
} NMDBusConnectionCallBlockingData;

void
nm_dbus_connection_call_blocking_callback(GObject *source, GAsyncResult *res, gpointer user_data);

GVariant *nm_dbus_connection_call_blocking(NMDBusConnectionCallBlockingData *data, GError **error);

/*****************************************************************************/

static inline gboolean
nm_g_variant_tuple_get_u(GVariant *v, guint32 *out_u)
{
    if (g_variant_is_of_type(v, G_VARIANT_TYPE("(u)"))) {
        g_variant_get(v, "(u)", out_u);
        return TRUE;
    }
    return FALSE;
}

/*****************************************************************************/

gulong _nm_dbus_proxy_signal_connect_data(GDBusProxy         *proxy,
                                          const char         *signal_name,
                                          const GVariantType *signature,
                                          GCallback           c_handler,
                                          gpointer            data,
                                          GClosureNotify      destroy_data,
                                          GConnectFlags       connect_flags);

/**
 * _nm_dbus_proxy_signal_connect:
 * @proxy: a #GDBusProxy
 * @signal_name: the D-Bus signal to connect to
 * @signature: the signal's type signature (must be a tuple)
 * @c_handler: the signal handler function
 * @data: (nullable): data to pass to @c_handler
 *
 * Simplified version of _nm_dbus_proxy_signal_connect_data() with fewer arguments.
 *
 * Returns: the signal handler ID, as with _nm_signal_connect_data().
 */
#define _nm_dbus_proxy_signal_connect(proxy, name, signature, handler, data) \
    _nm_dbus_proxy_signal_connect_data(proxy,                                \
                                       name,                                 \
                                       signature,                            \
                                       handler,                              \
                                       data,                                 \
                                       NULL,                                 \
                                       (GConnectFlags) 0)

GVariant *_nm_dbus_proxy_call_finish(GDBusProxy         *proxy,
                                     GAsyncResult       *res,
                                     const GVariantType *reply_type,
                                     GError            **error);

#endif /* __NM_DBUS_AUX_H__ */
