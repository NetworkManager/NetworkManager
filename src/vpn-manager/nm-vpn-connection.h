/* nm-vpn-connection.h - handle a single VPN connection within NetworkManager's framework 
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
#ifndef NM_VPN_CONNECTION_H
#define NM_VPN_CONNECTION_H

#include "nm-vpn-service.h"

typedef struct NMVPNConnection NMVPNConnection;


NMVPNConnection	*nm_vpn_connection_new			(const char *name, const char *user_name, NMVPNService *service);
void				 nm_vpn_connection_ref			(NMVPNConnection *connection);
void				 nm_vpn_connection_unref			(NMVPNConnection *connection);

const char *		 nm_vpn_connection_get_name			(NMVPNConnection *connection);
const char *		 nm_vpn_connection_get_user_name		(NMVPNConnection *connection);
NMVPNService *		 nm_vpn_connection_get_service		(NMVPNConnection *connection);

#endif  /* NM_VPN_MANAGER_H */
