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

#ifndef __NM_DBUS_MANAGER_H__
#define __NM_DBUS_MANAGER_H__

#include "config.h"
#include <glib-object.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>

G_BEGIN_DECLS

typedef gboolean (* NMDBusSignalHandlerFunc) (DBusConnection * connection,
                                              DBusMessage *    message,
                                              gpointer         user_data);

#define NM_TYPE_DBUS_MANAGER (nm_dbus_manager_get_type ())
#define NM_DBUS_MANAGER(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), NM_TYPE_DBUS_MANAGER, NMDBusManager))
#define NM_DBUS_MANAGER_CLASS(k) (G_TYPE_CHECK_CLASS_CAST((k), NM_TYPE_DBUS_MANAGER, NMDBusManagerClass))
#define NM_IS_DBUS_MANAGER(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), NM_TYPE_DBUS_MANAGER))
#define NM_IS_DBUS_MANAGER_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), NM_TYPE_DBUS_MANAGER))
#define NM_DBUS_MANAGER_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), NM_TYPE_DBUS_MANAGER, NMDBusManagerClass)) 

typedef struct {
	GObject parent;
} NMDBusManager;

typedef struct {
	GObjectClass parent;

	/* Signals */
	void (*dbus_connection_changed) (NMDBusManager *mgr,
	                                 DBusConnection *connection);

	void (*name_owner_changed)      (NMDBusManager *mgr,
	                                 const char *name,
	                                 const char *old_owner,
	                                 const char *new_owner);
} NMDBusManagerClass;

GType nm_dbus_manager_get_type (void);

NMDBusManager * nm_dbus_manager_get       (void);

char * nm_dbus_manager_get_name_owner     (NMDBusManager *self,
                                           const char *name,
                                           GError **error);

gboolean nm_dbus_manager_start_service    (NMDBusManager *self);

gboolean nm_dbus_manager_name_has_owner   (NMDBusManager *self,
                                           const char *name);

DBusConnection * nm_dbus_manager_get_dbus_connection (NMDBusManager *self);
DBusGConnection * nm_dbus_manager_get_connection (NMDBusManager *self);

G_END_DECLS

#endif /* __NM_DBUS_MANAGER_H__ */
