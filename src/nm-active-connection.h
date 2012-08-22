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
 * Copyright (C) 2008 - 2012 Red Hat, Inc.
 */

#ifndef NM_ACTIVE_CONNECTION_H
#define NM_ACTIVE_CONNECTION_H

#include <glib-object.h>
#include "nm-types.h"
#include "nm-connection.h"

#define NM_TYPE_ACTIVE_CONNECTION            (nm_active_connection_get_type ())
#define NM_ACTIVE_CONNECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_ACTIVE_CONNECTION, NMActiveConnection))
#define NM_ACTIVE_CONNECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_ACTIVE_CONNECTION, NMActiveConnectionClass))
#define NM_IS_ACTIVE_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_ACTIVE_CONNECTION))
#define NM_IS_ACTIVE_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_ACTIVE_CONNECTION))
#define NM_ACTIVE_CONNECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_ACTIVE_CONNECTION, NMActiveConnectionClass))

/* D-Bus Exported Properties */
#define NM_ACTIVE_CONNECTION_CONNECTION      "connection"
#define NM_ACTIVE_CONNECTION_UUID            "uuid"
#define NM_ACTIVE_CONNECTION_SPECIFIC_OBJECT "specific-object"
#define NM_ACTIVE_CONNECTION_DEVICES         "devices"
#define NM_ACTIVE_CONNECTION_STATE           "state"
#define NM_ACTIVE_CONNECTION_DEFAULT         "default"
#define NM_ACTIVE_CONNECTION_DEFAULT6        "default6"
#define NM_ACTIVE_CONNECTION_VPN             "vpn"
#define NM_ACTIVE_CONNECTION_MASTER          "master"

/* Internal non-exported construct-time properties */
#define NM_ACTIVE_CONNECTION_INT_CONNECTION     "int-connection"
#define NM_ACTIVE_CONNECTION_INT_DEVICE         "int-device"
#define NM_ACTIVE_CONNECTION_INT_USER_REQUESTED "int-user-requested"
#define NM_ACTIVE_CONNECTION_INT_USER_UID       "int-user-uid"
#define NM_ACTIVE_CONNECTION_INT_ASSUMED        "int-assumed"
#define NM_ACTIVE_CONNECTION_INT_MASTER         "int-master"


typedef struct {
	GObject parent;
} NMActiveConnection;

typedef struct {
	GObjectClass parent;

	/* Signals */
	void (*properties_changed) (NMActiveConnection *active, GHashTable *properties);
} NMActiveConnectionClass;

GType         nm_active_connection_get_type (void);

void          nm_active_connection_export (NMActiveConnection *self);

NMConnection *nm_active_connection_get_connection (NMActiveConnection *self);
const char *  nm_active_connection_get_name       (NMActiveConnection *self);

const char *  nm_active_connection_get_path (NMActiveConnection *self);

const char *  nm_active_connection_get_specific_object (NMActiveConnection *self);

void          nm_active_connection_set_specific_object (NMActiveConnection *self,
                                                        const char *specific_object);

void          nm_active_connection_set_default (NMActiveConnection *self,
                                                gboolean is_default);

gboolean      nm_active_connection_get_default (NMActiveConnection *self);

void          nm_active_connection_set_default6 (NMActiveConnection *self,
                                                 gboolean is_default6);

gboolean      nm_active_connection_get_default6 (NMActiveConnection *self);

NMActiveConnectionState nm_active_connection_get_state (NMActiveConnection *self);

void          nm_active_connection_set_state (NMActiveConnection *self,
                                              NMActiveConnectionState state);

NMDevice *    nm_active_connection_get_device (NMActiveConnection *self);

gboolean      nm_active_connection_get_user_requested (NMActiveConnection *self);

gulong        nm_active_connection_get_user_uid (NMActiveConnection *self);

gboolean      nm_active_connection_get_assumed (NMActiveConnection *self);

NMDevice *    nm_active_connection_get_master (NMActiveConnection *self);

#endif /* NM_ACTIVE_CONNECTION_H */
