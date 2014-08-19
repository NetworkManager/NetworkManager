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
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>

DBusGConnection *_nm_dbus_new_connection        (GCancellable *cancellable,
                                                 GError **error);

void             _nm_dbus_new_connection_async  (GCancellable *cancellable,
                                                 GAsyncReadyCallback callback,
                                                 gpointer user_data);
DBusGConnection *_nm_dbus_new_connection_finish (GAsyncResult *result,
                                                 GError **error);

gboolean         _nm_dbus_is_connection_private (DBusGConnection *connection);

void        _nm_dbus_register_proxy_type             (const char *interface,
                                                      GType proxy_type);

DBusGProxy *_nm_dbus_new_proxy_for_connection        (DBusGConnection *connection,
                                                      const char *path,
                                                      const char *interface,
                                                      GCancellable *cancellable,
                                                      GError **error);

void        _nm_dbus_new_proxy_for_connection_async  (DBusGConnection *connection,
                                                      const char *path,
                                                      const char *interface,
                                                      GCancellable *cancellable,
                                                      GAsyncReadyCallback callback,
                                                      gpointer user_data);
DBusGProxy *_nm_dbus_new_proxy_for_connection_finish (GAsyncResult *result,
                                                      GError **error);

#endif /* __NM_DBUS_HELPERS_PRIVATE_H__ */
