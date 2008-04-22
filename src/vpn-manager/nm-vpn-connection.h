/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */
/* NetworkManager -- Network link manager
 *
 * Dan Williams <dcbw@redhat.com>
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2005 Red Hat, Inc.
 */

#ifndef NM_VPN_CONNECTION_H
#define NM_VPN_CONNECTION_H

#include <glib/gtypes.h>
#include <glib-object.h>
#include "NetworkManagerVPN.h"
#include "nm-device.h"
#include "nm-activation-request.h"

#define NM_TYPE_VPN_CONNECTION            (nm_vpn_connection_get_type ())
#define NM_VPN_CONNECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_VPN_CONNECTION, NMVPNConnection))
#define NM_VPN_CONNECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_VPN_CONNECTION, NMVPNConnectionClass))
#define NM_IS_VPN_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_VPN_CONNECTION))
#define NM_IS_VPN_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_VPN_CONNECTION))
#define NM_VPN_CONNECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_VPN_CONNECTION, NMVPNConnectionClass))

#define NM_VPN_CONNECTION_VPN_STATE "vpn-state"
#define NM_VPN_CONNECTION_BANNER "banner"

typedef struct {
	GObject parent;
} NMVPNConnection;

typedef struct {
	GObjectClass parent;

	/* Signals */
	void (*vpn_state_changed) (NMVPNConnection *connection,
	                           NMVPNConnectionState state,
	                           NMVPNConnectionStateReason reason);

	void (*properties_changed) (NMVPNConnection *connection, GHashTable *properties);
} NMVPNConnectionClass;

GType nm_vpn_connection_get_type (void);

NMVPNConnection * nm_vpn_connection_new (NMConnection *connection,
                                         NMActRequest *act_request,
                                         NMDevice *parent_device);

void                 nm_vpn_connection_activate        (NMVPNConnection *connection);
NMConnection *       nm_vpn_connection_get_connection  (NMVPNConnection *connection);
const char *         nm_vpn_connection_get_active_connection_path (NMVPNConnection *connection);
const char *         nm_vpn_connection_get_name        (NMVPNConnection *connection);
NMVPNConnectionState nm_vpn_connection_get_vpn_state   (NMVPNConnection *connection);
const char *         nm_vpn_connection_get_banner      (NMVPNConnection *connection);
void                 nm_vpn_connection_fail            (NMVPNConnection *connection,
                                                        NMVPNConnectionStateReason reason);
void                 nm_vpn_connection_disconnect      (NMVPNConnection *connection,
                                                        NMVPNConnectionStateReason reason);

#endif /* NM_VPN_CONNECTION_H */
