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
 * Copyright 2007 - 2014 Red Hat, Inc.
 * Copyright 2008 Novell, Inc.
 */

#ifndef NM_ACTIVE_CONNECTION_H
#define NM_ACTIVE_CONNECTION_H

#include <glib.h>
#include <glib-object.h>
#include "nm-object.h"
#include <nm-connection.h>
#include <NetworkManager.h>
#include "nm-ip4-config.h"
#include "nm-dhcp4-config.h"
#include "nm-ip6-config.h"
#include "nm-dhcp6-config.h"

G_BEGIN_DECLS

#define NM_TYPE_ACTIVE_CONNECTION            (nm_active_connection_get_type ())
#define NM_ACTIVE_CONNECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_ACTIVE_CONNECTION, NMActiveConnection))
#define NM_ACTIVE_CONNECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_ACTIVE_CONNECTION, NMActiveConnectionClass))
#define NM_IS_ACTIVE_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_ACTIVE_CONNECTION))
#define NM_IS_ACTIVE_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_ACTIVE_CONNECTION))
#define NM_ACTIVE_CONNECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_ACTIVE_CONNECTION, NMActiveConnectionClass))

#define NM_ACTIVE_CONNECTION_CONNECTION          "connection"
#define NM_ACTIVE_CONNECTION_ID                  "id"
#define NM_ACTIVE_CONNECTION_UUID                "uuid"
#define NM_ACTIVE_CONNECTION_TYPE                "type"
#define NM_ACTIVE_CONNECTION_SPECIFIC_OBJECT     "specific-object"
#define NM_ACTIVE_CONNECTION_DEVICES             "devices"
#define NM_ACTIVE_CONNECTION_STATE               "state"
#define NM_ACTIVE_CONNECTION_DEFAULT             "default"
#define NM_ACTIVE_CONNECTION_IP4_CONFIG          "ip4-config"
#define NM_ACTIVE_CONNECTION_DHCP4_CONFIG        "dhcp4-config"
#define NM_ACTIVE_CONNECTION_DEFAULT6            "default6"
#define NM_ACTIVE_CONNECTION_IP6_CONFIG          "ip6-config"
#define NM_ACTIVE_CONNECTION_DHCP6_CONFIG        "dhcp6-config"
#define NM_ACTIVE_CONNECTION_VPN                 "vpn"
#define NM_ACTIVE_CONNECTION_MASTER              "master"

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

const char * nm_active_connection_get_connection          (NMActiveConnection *connection);
NM_AVAILABLE_IN_0_9_10
const char * nm_active_connection_get_id                  (NMActiveConnection *connection);
const char * nm_active_connection_get_uuid                (NMActiveConnection *connection);
NM_AVAILABLE_IN_0_9_10
const char * nm_active_connection_get_connection_type     (NMActiveConnection *connection);
const char * nm_active_connection_get_specific_object     (NMActiveConnection *connection);
const GPtrArray *nm_active_connection_get_devices         (NMActiveConnection *connection);
NMActiveConnectionState nm_active_connection_get_state    (NMActiveConnection *connection);
const char * nm_active_connection_get_master              (NMActiveConnection *connection);
gboolean       nm_active_connection_get_default           (NMActiveConnection *connection);
NM_AVAILABLE_IN_0_9_10
NMIP4Config *  nm_active_connection_get_ip4_config        (NMActiveConnection *connection);
NM_AVAILABLE_IN_0_9_10
NMDHCP4Config *nm_active_connection_get_dhcp4_config      (NMActiveConnection *connection);
gboolean       nm_active_connection_get_default6          (NMActiveConnection *connection);
NM_AVAILABLE_IN_0_9_10
NMIP6Config *  nm_active_connection_get_ip6_config        (NMActiveConnection *connection);
NM_AVAILABLE_IN_0_9_10
NMDHCP6Config *nm_active_connection_get_dhcp6_config      (NMActiveConnection *connection);
NM_AVAILABLE_IN_0_9_10
gboolean       nm_active_connection_get_vpn               (NMActiveConnection *connection);

G_END_DECLS

#endif /* NM_ACTIVE_CONNECTION_H */
