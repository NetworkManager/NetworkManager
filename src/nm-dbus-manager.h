/*
 * Copyright (C) 2006 Red Hat, Inc.
 *
 * Written by Dan Williams <dcbw@redhat.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#ifndef __NM_DBUS_MANAGER_H__
#define __NM_DBUS_MANAGER_H__

#include "config.h"
#include "NetworkManagerDbusUtils.h"
#include <glib-object.h>
#include <dbus/dbus.h>

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

typedef struct _NMDBusManager NMDBusManager;
typedef struct _NMDBusManagerClass NMDBusManagerClass;
typedef struct _NMDBusManagerPrivate NMDBusManagerPrivate;

struct _NMDBusManager {
	GObject parent;

	/*< private >*/
	NMDBusManagerPrivate *priv;
};

struct _NMDBusManagerClass {
	GObjectClass parent;

	/* Signals */
	void (*dbus_connection_changed) (NMDBusManager *mgr,
	                                 DBusConnection *connection);

	void (*name_owner_changed)      (NMDBusManager *mgr,
	                                 DBusConnection *connection,
	                                 const char *name,
	                                 const char *old_owner,
	                                 const char *new_owner);
};

GType nm_dbus_manager_get_type (void);

NMDBusManager * nm_dbus_manager_get       (GMainContext *ctx);

char * nm_dbus_manager_get_name_owner     (NMDBusManager *self,
                                           const char *name);

gboolean nm_dbus_manager_start_service    (NMDBusManager *self);

void nm_dbus_manager_register_method_list (NMDBusManager *self,
                                           NMDbusMethodList *list);

gboolean nm_dbus_manager_name_has_owner   (NMDBusManager *self,
                                           const char *name);

guint32 nm_dbus_manager_register_signal_handler (NMDBusManager *self,
                                           const char *interface,
                                           const char *sender,
                                           NMDBusSignalHandlerFunc callback,
                                           gpointer user_data);

void nm_dbus_manager_remove_signal_handler (NMDBusManager *self,
                                           guint32 id);

DBusConnection * nm_dbus_manager_get_dbus_connection (NMDBusManager *self);

G_END_DECLS

#endif /* __NM_DBUS_MANAGER_H__ */
