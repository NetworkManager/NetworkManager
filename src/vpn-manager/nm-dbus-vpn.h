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

#ifndef NM_DBUS_VPN_H
#define NM_DBUS_VPN_H

#include "NetworkManagerDbusUtils.h"
#include "nm-vpn-manager.h"
#include "nm-vpn-connection.h"

void				nm_dbus_vpn_schedule_vpn_connections_update	(NMData *app_data);
void				nm_dbus_vpn_update_one_vpn_connection		(DBusConnection *connection, const char *vpn, NMData *data);

void				nm_dbus_vpn_signal_vpn_connection_update	(DBusConnection *con, NMVPNConnection *vpn, const char *signal);
void				nm_dbus_vpn_signal_vpn_failed				(DBusConnection *con, const char *signal, NMVPNConnection *vpn, const char *error_msg);
void				nm_dbus_vpn_signal_vpn_login_banner		(DBusConnection *con, NMVPNConnection *vpn, const char *banner);
void				nm_dbus_vpn_signal_vpn_connection_state_change (DBusConnection *con, NMVPNConnection *vpn, NMVPNActStage new_stage);

char **			nm_dbus_vpn_get_routes					(DBusConnection *connection, NMVPNConnection *vpn, int *num_items);

NMDbusMethodList *	nm_dbus_vpn_methods_setup				(void);

#endif
