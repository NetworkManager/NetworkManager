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

#include <config.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>

#include "nm-glib.h"
#include "nm-types.h"

G_BEGIN_DECLS

typedef gboolean (* NMDBusSignalHandlerFunc) (DBusConnection * connection,
                                              DBusMessage *    message,
                                              gpointer         user_data);

#define NM_TYPE_BUS_MANAGER (nm_bus_manager_get_type ())
#define NM_BUS_MANAGER(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), NM_TYPE_BUS_MANAGER, NMBusManager))
#define NM_BUS_MANAGER_CLASS(k) (G_TYPE_CHECK_CLASS_CAST((k), NM_TYPE_BUS_MANAGER, NMBusManagerClass))
#define NM_IS_BUS_MANAGER(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), NM_TYPE_BUS_MANAGER))
#define NM_IS_BUS_MANAGER_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), NM_TYPE_BUS_MANAGER))
#define NM_BUS_MANAGER_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), NM_TYPE_BUS_MANAGER, NMBusManagerClass)) 

#define NM_BUS_MANAGER_DBUS_CONNECTION_CHANGED          "dbus-connection-changed"
#define NM_BUS_MANAGER_NAME_OWNER_CHANGED               "name-owner-changed"
#define NM_BUS_MANAGER_PRIVATE_CONNECTION_NEW           "private-connection-new"
#define NM_BUS_MANAGER_PRIVATE_CONNECTION_DISCONNECTED  "private-connection-disconnected"

struct _NMBusManager {
	GObject parent;
};

typedef struct {
	GObjectClass parent;

	/* Signals */
	void (*dbus_connection_changed) (NMBusManager *mgr,
	                                 DBusConnection *connection);

	void (*name_owner_changed)      (NMBusManager *mgr,
	                                 const char *name,
	                                 const char *old_owner,
	                                 const char *new_owner);

	void (*private_connection_new) (NMBusManager *mgr,
	                                DBusGConnection *connection);

	void (*private_connection_disconnected) (NMBusManager *mgr,
	                                         DBusGConnection *connection);
} NMBusManagerClass;

GType nm_bus_manager_get_type (void);

NMBusManager * nm_bus_manager_get       (void);
void           nm_bus_manager_setup     (NMBusManager *instance);

char * nm_bus_manager_get_name_owner     (NMBusManager *self,
                                          const char *name,
                                          GError **error);

gboolean nm_bus_manager_start_service    (NMBusManager *self);

gboolean nm_bus_manager_name_has_owner   (NMBusManager *self,
                                          const char *name);

DBusConnection * nm_bus_manager_get_dbus_connection (NMBusManager *self);
DBusGConnection * nm_bus_manager_get_connection (NMBusManager *self);

gboolean nm_bus_manager_get_caller_info (NMBusManager *self,
                                         DBusGMethodInvocation *context,
                                         char **out_sender,
                                         gulong *out_uid,
                                         gulong *out_pid);

gboolean nm_bus_manager_get_unix_user (NMBusManager *self,
                                       const char *sender,
                                       gulong *out_uid);

gboolean nm_bus_manager_get_caller_info_from_message (NMBusManager *self,
                                                      DBusConnection *connection,
                                                      DBusMessage *message,
                                                      char **out_sender,
                                                      gulong *out_uid,
                                                      gulong *out_pid);

void nm_bus_manager_register_object (NMBusManager *self,
                                     const char *path,
                                     gpointer object);

void nm_bus_manager_unregister_object (NMBusManager *self, gpointer object);

void nm_bus_manager_private_server_register (NMBusManager *self,
                                             const char *path,
                                             const char *tag);

DBusGProxy *nm_bus_manager_new_proxy (NMBusManager *self,
                                      DBusGMethodInvocation *context,
                                      const char *name,
                                      const char *path,
                                      const char *iface);

#if !HAVE_DBUS_GLIB_GMI_GET_CONNECTION
DBusGConnection *dbus_g_method_invocation_get_g_connection (DBusGMethodInvocation *context);
#endif

G_END_DECLS

#endif /* __NM_BUS_MANAGER_H__ */
