/* nm-vpn-manager.h - handle VPN connections within NetworkManager's framework 
 *
 * Copyright (C) 2005 Dan Williams
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */
#ifndef NM_VPN_MANAGER_H
#define NM_VPN_MANAGER_H

#include <dbus/dbus.h>
#include "NetworkManagerMain.h"
#include "nm-vpn-connection.h"
#include "nm-vpn-service.h"


NMVPNManager *		nm_vpn_manager_new						(NMData *app_data);
NMVPNConnection *	nm_vpn_manager_add_connection				(NMVPNManager *manager, const char *name, const char *service_name, const char *user_name);
void				nm_vpn_manager_remove_connection			(NMVPNManager *manager, NMVPNConnection *vpn);
char	**			nm_vpn_manager_get_connection_names		(NMVPNManager *manager);
void				nm_vpn_manager_dispose					(NMVPNManager *manager);

NMVPNActRequest *	nm_vpn_manager_get_vpn_act_request			(NMVPNManager *manager);

GSList *			nm_vpn_manager_vpn_connection_list_copy		(NMVPNManager *manager);

void				nm_vpn_manager_activate_vpn_connection		(NMVPNManager *manager, NMVPNConnection *vpn, char **password_items,
										int password_count, char **data_items, int data_count,
										char **user_routes, int user_routes_count );
void				nm_vpn_manager_deactivate_vpn_connection	(NMVPNManager *manager, NMDevice *dev);

NMVPNConnection *	nm_vpn_manager_find_connection_by_name		(NMVPNManager *manager, const char *con_name);
NMVPNService *		nm_vpn_manager_find_service_by_name		(NMVPNManager *manager, const char *service_name);

gboolean			nm_vpn_manager_process_signal				(NMVPNManager *manager, DBusMessage *signal);
gboolean			nm_vpn_manager_process_name_owner_changed	(NMVPNManager *manager, const char *service, const char *old_owner, const char *new_owner);

void				nm_vpn_manager_schedule_vpn_activation_failed(NMVPNManager *manager, NMVPNActRequest *req);
void				nm_vpn_manager_schedule_vpn_connection_died	(NMVPNManager *manager, NMVPNActRequest *req);

#endif  /* NM_VPN_MANAGER_H */
