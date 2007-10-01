/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */
/* NetworkManager Wireless Applet -- Display wireless access points and allow user control
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
 * (C) Copyright 2004 Red Hat, Inc.
 */

#ifndef NM_VPN_CONNECTION_H
#define NM_VPN_CONNECTION_H

#include <glib/gtypes.h>
#include <glib-object.h>
#include <dbus/dbus-glib.h>
#include "nm-object.h"
#include "NetworkManagerVPN.h"

G_BEGIN_DECLS

#define NM_TYPE_VPN_CONNECTION            (nm_vpn_connection_get_type ())
#define NM_VPN_CONNECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_VPN_CONNECTION, NMVPNConnection))
#define NM_VPN_CONNECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_VPN_CONNECTION, NMVPNConnectionClass))
#define NM_IS_VPN_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_VPN_CONNECTION))
#define NM_IS_VPN_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_VPN_CONNECTION))
#define NM_VPN_CONNECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_VPN_CONNECTION, NMVPNConnectionClass))

typedef struct {
	NMObject parent;
} NMVPNConnection;

typedef struct {
	NMObjectClass parent;

	/* Signals */
	void (*state_changed) (NMVPNConnection *connection,
	                       NMVPNConnectionState state,
	                       NMVPNConnectionStateReason reason);
} NMVPNConnectionClass;

GType nm_vpn_connection_get_type (void);


NMVPNConnection *     nm_vpn_connection_new (DBusGConnection *dbus_connection,
                                             const char *path);

const char *          nm_vpn_connection_get_name   (NMVPNConnection *vpn);
NMVPNConnectionState  nm_vpn_connection_get_state  (NMVPNConnection *vpn);
const char *          nm_vpn_connection_get_banner (NMVPNConnection *vpn);

void                  nm_vpn_connection_disconnect (NMVPNConnection *vpn);

G_END_DECLS

#endif /* NM_VPN_CONNECTION_H */
