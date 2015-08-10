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
 * Copyright (C) 2006 - 2008 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#ifndef __NM_BUS_MANAGER_H__
#define __NM_BUS_MANAGER_H__

#include "config.h"

#include "nm-default.h"

G_BEGIN_DECLS

#define NM_TYPE_BUS_MANAGER (nm_bus_manager_get_type ())
#define NM_BUS_MANAGER(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), NM_TYPE_BUS_MANAGER, NMBusManager))
#define NM_BUS_MANAGER_CLASS(k) (G_TYPE_CHECK_CLASS_CAST((k), NM_TYPE_BUS_MANAGER, NMBusManagerClass))
#define NM_IS_BUS_MANAGER(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), NM_TYPE_BUS_MANAGER))
#define NM_IS_BUS_MANAGER_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), NM_TYPE_BUS_MANAGER))
#define NM_BUS_MANAGER_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), NM_TYPE_BUS_MANAGER, NMBusManagerClass)) 

#define NM_BUS_MANAGER_DBUS_CONNECTION_CHANGED          "dbus-connection-changed"
#define NM_BUS_MANAGER_PRIVATE_CONNECTION_NEW           "private-connection-new"
#define NM_BUS_MANAGER_PRIVATE_CONNECTION_DISCONNECTED  "private-connection-disconnected"

struct _NMBusManager {
	GObject parent;
};

typedef struct {
	GObjectClass parent;

	/* Signals */
	void (*dbus_connection_changed) (NMBusManager *mgr,
	                                 GDBusConnection *connection);

	void (*private_connection_new) (NMBusManager *mgr,
	                                GDBusConnection *connection);

	void (*private_connection_disconnected) (NMBusManager *mgr,
	                                         GDBusConnection *connection);
} NMBusManagerClass;

GType nm_bus_manager_get_type (void);

NMBusManager * nm_bus_manager_get       (void);
void           nm_bus_manager_setup     (NMBusManager *instance);

gboolean nm_bus_manager_start_service    (NMBusManager *self);

GDBusConnection * nm_bus_manager_get_connection (NMBusManager *self);

gboolean nm_bus_manager_get_caller_info (NMBusManager *self,
                                         GDBusMethodInvocation *context,
                                         char **out_sender,
                                         gulong *out_uid,
                                         gulong *out_pid);

gboolean nm_bus_manager_get_unix_user (NMBusManager *self,
                                       const char *sender,
                                       gulong *out_uid);

gboolean nm_bus_manager_get_caller_info_from_message (NMBusManager *self,
                                                      GDBusConnection *connection,
                                                      GDBusMessage *message,
                                                      char **out_sender,
                                                      gulong *out_uid,
                                                      gulong *out_pid);

void nm_bus_manager_register_object (NMBusManager *self,
                                     const char *path,
                                     gpointer object);

void nm_bus_manager_unregister_object (NMBusManager *self, gpointer object);

gpointer nm_bus_manager_get_registered_object (NMBusManager *self,
                                               const char *path);

void nm_bus_manager_private_server_register (NMBusManager *self,
                                             const char *path,
                                             const char *tag);

GDBusProxy *nm_bus_manager_new_proxy (NMBusManager *self,
                                      GDBusMethodInvocation *context,
                                      GType proxy_type,
                                      const char *name,
                                      const char *path,
                                      const char *iface);

G_END_DECLS

#endif /* __NM_BUS_MANAGER_H__ */
