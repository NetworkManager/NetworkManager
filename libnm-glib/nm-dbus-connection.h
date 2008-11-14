/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * libnm_glib -- Access network status & information from glib applications
 *
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
 * Copyright (C) 2008 Novell, Inc.
 * Copyright (C) 2008 Red Hat, Inc.
 */

#ifndef NM_DBUS_CONNECTION_H
#define NM_DBUS_CONNECTION_H

#include <dbus/dbus-glib.h>
#include <nm-settings.h>

G_BEGIN_DECLS

#define NM_TYPE_DBUS_CONNECTION            (nm_dbus_connection_get_type ())
#define NM_DBUS_CONNECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DBUS_CONNECTION, NMDBusConnection))
#define NM_DBUS_CONNECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DBUS_CONNECTION, NMDBusConnectionClass))
#define NM_IS_DBUS_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DBUS_CONNECTION))
#define NM_IS_DBUS_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_DBUS_CONNECTION))
#define NM_DBUS_CONNECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DBUS_CONNECTION, NMDBusConnectionClass))

#define NM_DBUS_CONNECTION_BUS   "bus"
#define NM_DBUS_CONNECTION_SCOPE "scope"
#define NM_DBUS_CONNECTION_PATH  "path"

typedef struct {
	NMExportedConnection parent;
} NMDBusConnection;

typedef struct {
	NMExportedConnectionClass parent;
} NMDBusConnectionClass;

GType nm_dbus_connection_get_type (void);

NMDBusConnection *nm_dbus_connection_new  (DBusGConnection *dbus_connection,
								   NMConnectionScope scope,
								   const char *path);

G_END_DECLS

#endif /* NM_DBUS_CONNECTION_H */
