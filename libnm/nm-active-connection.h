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

#ifndef __NM_ACTIVE_CONNECTION_H__
#define __NM_ACTIVE_CONNECTION_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-object.h"

G_BEGIN_DECLS

#define NM_TYPE_ACTIVE_CONNECTION            (nm_active_connection_get_type ())
#define NM_ACTIVE_CONNECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_ACTIVE_CONNECTION, NMActiveConnection))
#define NM_ACTIVE_CONNECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_ACTIVE_CONNECTION, NMActiveConnectionClass))
#define NM_IS_ACTIVE_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_ACTIVE_CONNECTION))
#define NM_IS_ACTIVE_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_ACTIVE_CONNECTION))
#define NM_ACTIVE_CONNECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_ACTIVE_CONNECTION, NMActiveConnectionClass))

#define NM_ACTIVE_CONNECTION_CONNECTION           "connection"
#define NM_ACTIVE_CONNECTION_ID                   "id"
#define NM_ACTIVE_CONNECTION_UUID                 "uuid"
#define NM_ACTIVE_CONNECTION_TYPE                 "type"
#define NM_ACTIVE_CONNECTION_SPECIFIC_OBJECT_PATH "specific-object-path"
#define NM_ACTIVE_CONNECTION_DEVICES              "devices"
#define NM_ACTIVE_CONNECTION_STATE                "state"
#define NM_ACTIVE_CONNECTION_STATE_FLAGS          "state-flags"
#define NM_ACTIVE_CONNECTION_DEFAULT              "default"
#define NM_ACTIVE_CONNECTION_IP4_CONFIG           "ip4-config"
#define NM_ACTIVE_CONNECTION_DHCP4_CONFIG         "dhcp4-config"
#define NM_ACTIVE_CONNECTION_DEFAULT6             "default6"
#define NM_ACTIVE_CONNECTION_IP6_CONFIG           "ip6-config"
#define NM_ACTIVE_CONNECTION_DHCP6_CONFIG         "dhcp6-config"
#define NM_ACTIVE_CONNECTION_VPN                  "vpn"
#define NM_ACTIVE_CONNECTION_MASTER               "master"

/**
 * NMActiveConnection:
 */
struct _NMActiveConnection {
	NMObject parent;
};

typedef struct {
	NMObjectClass parent;

	/*< private >*/
	gpointer padding[8];
} NMActiveConnectionClass;

GType nm_active_connection_get_type (void);

NMRemoteConnection            *nm_active_connection_get_connection           (NMActiveConnection *connection);
const char                    *nm_active_connection_get_id                   (NMActiveConnection *connection);
const char                    *nm_active_connection_get_uuid                 (NMActiveConnection *connection);
const char                    *nm_active_connection_get_connection_type      (NMActiveConnection *connection);
const char                    *nm_active_connection_get_specific_object_path (NMActiveConnection *connection);
const GPtrArray               *nm_active_connection_get_devices              (NMActiveConnection *connection);
NMActiveConnectionState        nm_active_connection_get_state                (NMActiveConnection *connection);
NM_AVAILABLE_IN_1_10
NMActivationStateFlags         nm_active_connection_get_state_flags          (NMActiveConnection *connection);
NM_AVAILABLE_IN_1_8
NMActiveConnectionStateReason  nm_active_connection_get_state_reason         (NMActiveConnection *connection);
NMDevice                      *nm_active_connection_get_master               (NMActiveConnection *connection);
gboolean                       nm_active_connection_get_default              (NMActiveConnection *connection);
NMIPConfig                    *nm_active_connection_get_ip4_config           (NMActiveConnection *connection);
NMDhcpConfig                  *nm_active_connection_get_dhcp4_config         (NMActiveConnection *connection);
gboolean                       nm_active_connection_get_default6             (NMActiveConnection *connection);
NMIPConfig                    *nm_active_connection_get_ip6_config           (NMActiveConnection *connection);
NMDhcpConfig                  *nm_active_connection_get_dhcp6_config         (NMActiveConnection *connection);
gboolean                       nm_active_connection_get_vpn                  (NMActiveConnection *connection);

G_END_DECLS

#endif /* __NM_ACTIVE_CONNECTION_H__ */
