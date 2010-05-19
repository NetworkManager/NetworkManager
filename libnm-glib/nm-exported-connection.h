/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service
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
 * (C) Copyright 2009 Red Hat, Inc.
 */

#ifndef NM_EXPORTED_CONNECTION_H
#define NM_EXPORTED_CONNECTION_H

#include <nm-connection.h>
#include <dbus/dbus-glib.h>

G_BEGIN_DECLS

#define NM_TYPE_EXPORTED_CONNECTION            (nm_exported_connection_get_type ())
#define NM_EXPORTED_CONNECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_EXPORTED_CONNECTION, NMExportedConnection))
#define NM_EXPORTED_CONNECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_EXPORTED_CONNECTION, NMExportedConnectionClass))
#define NM_IS_EXPORTED_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_EXPORTED_CONNECTION))
#define NM_IS_EXPORTED_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_EXPORTED_CONNECTION))
#define NM_EXPORTED_CONNECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_EXPORTED_CONNECTION, NMExportedConnectionClass))

typedef struct {
	NMConnection parent;
} NMExportedConnection;

typedef struct {
	NMConnectionClass parent;

	GHashTable * (*get_settings) (NMExportedConnection *self,
	                              GError **error);

	void (*update) (NMExportedConnection *self,
	                GHashTable *new_settings,
	                DBusGMethodInvocation *context);

	void (*delete) (NMExportedConnection *self,
	                DBusGMethodInvocation *context);

	void (*get_secrets) (NMExportedConnection *self,
	                     const gchar *setting_name,
	                     const gchar **hints,
	                     gboolean request_new,
	                     DBusGMethodInvocation *context);

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
	void (*_reserved5) (void);
	void (*_reserved6) (void);
} NMExportedConnectionClass;

GType nm_exported_connection_get_type (void);

NMExportedConnection *nm_exported_connection_new (NMConnectionScope scope);

G_END_DECLS

#endif /* NM_EXPORTED_CONNECTION_H */
