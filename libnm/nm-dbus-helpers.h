/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef __NM_DBUS_HELPERS_PRIVATE_H__
#define __NM_DBUS_HELPERS_PRIVATE_H__

#include <gio/gio.h>

#include "nm-dbus-compat.h"

GBusType _nm_dbus_bus_type (void);

GDBusConnection *_nm_dbus_new_connection        (GCancellable *cancellable,
                                                 GError **error);

void             _nm_dbus_new_connection_async  (GCancellable *cancellable,
                                                 GAsyncReadyCallback callback,
                                                 gpointer user_data);
GDBusConnection *_nm_dbus_new_connection_finish (GAsyncResult *result,
                                                 GError **error);

gboolean         _nm_dbus_is_connection_private (GDBusConnection *connection);

void        _nm_dbus_register_proxy_type             (const char *interface,
                                                      GType proxy_type);
/* Guarantee that @interface is a static string */
#define _nm_dbus_register_proxy_type(interface, proxy_type) \
	_nm_dbus_register_proxy_type (interface "", proxy_type) \

GDBusProxy *_nm_dbus_new_proxy_for_connection        (GDBusConnection *connection,
                                                      const char *path,
                                                      const char *interface,
                                                      GCancellable *cancellable,
                                                      GError **error);

void        _nm_dbus_new_proxy_for_connection_async  (GDBusConnection *connection,
                                                      const char *path,
                                                      const char *interface,
                                                      GCancellable *cancellable,
                                                      GAsyncReadyCallback callback,
                                                      gpointer user_data);
GDBusProxy *_nm_dbus_new_proxy_for_connection_finish (GAsyncResult *result,
                                                      GError **error);

void _nm_dbus_bind_properties (gpointer object,
                               gpointer skeleton);

void _nm_dbus_bind_methods (gpointer object,
                            gpointer skeleton,
                            ...) G_GNUC_NULL_TERMINATED;

#endif /* __NM_DBUS_HELPERS_PRIVATE_H__ */
