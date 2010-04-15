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
 * Copyright (C) 2007 - 2010 Red Hat, Inc.
 * Copyright (C) 2008 Novell, Inc.
 */

#ifndef NM_ACTIVE_CONNECTION_H
#define NM_ACTIVE_CONNECTION_H

#include <glib.h>
#include <glib-object.h>
#include "nm-object.h"
#include <nm-connection.h>
#include <NetworkManager.h>

G_BEGIN_DECLS

#define NM_TYPE_ACTIVE_CONNECTION            (nm_active_connection_get_type ())
#define NM_ACTIVE_CONNECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_ACTIVE_CONNECTION, NMActiveConnection))
#define NM_ACTIVE_CONNECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_ACTIVE_CONNECTION, NMActiveConnectionClass))
#define NM_IS_ACTIVE_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_ACTIVE_CONNECTION))
#define NM_IS_ACTIVE_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_ACTIVE_CONNECTION))
#define NM_ACTIVE_CONNECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_ACTIVE_CONNECTION, NMActiveConnectionClass))

#define NM_ACTIVE_CONNECTION_SERVICE_NAME        "service-name"
#define NM_ACTIVE_CONNECTION_CONNECTION          "connection"
#define NM_ACTIVE_CONNECTION_SPECIFIC_OBJECT     "specific-object"
#define NM_ACTIVE_CONNECTION_DEVICES             "devices"
#define NM_ACTIVE_CONNECTION_STATE               "state"
#define NM_ACTIVE_CONNECTION_DEFAULT             "default"
#define NM_ACTIVE_CONNECTION_DEFAULT6            "default6"

typedef struct {
	NMObject parent;
} NMActiveConnection;

typedef struct {
	NMObjectClass parent;

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
	void (*_reserved5) (void);
	void (*_reserved6) (void);
} NMActiveConnectionClass;

GType nm_active_connection_get_type (void);

GObject *nm_active_connection_new (DBusGConnection *connection, const char *path);

const char * nm_active_connection_get_service_name        (NMActiveConnection *connection);
NMConnectionScope nm_active_connection_get_scope          (NMActiveConnection *connection);
const char * nm_active_connection_get_connection          (NMActiveConnection *connection);
const char * nm_active_connection_get_specific_object     (NMActiveConnection *connection);
const GPtrArray *nm_active_connection_get_devices         (NMActiveConnection *connection);
NMActiveConnectionState nm_active_connection_get_state    (NMActiveConnection *connection);
gboolean nm_active_connection_get_default                 (NMActiveConnection *connection);
gboolean nm_active_connection_get_default6                (NMActiveConnection *connection);

G_END_DECLS

#endif /* NM_ACTIVE_CONNECTION_H */
