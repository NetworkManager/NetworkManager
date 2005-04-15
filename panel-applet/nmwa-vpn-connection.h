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

#ifndef NMWA_VPN_CONNECTION_H
#define NMWA_VPN_CONNECTION_H

#include "NMWirelessApplet.h"

VPNConnection *	nmwa_vpn_connection_new			(const char *name, const char *func);
VPNConnection *	nmwa_vpn_connection_copy			(VPNConnection *vpn, const char *func);
void				nmwa_vpn_connection_ref			(VPNConnection *vpn, const char *func);
void				nmwa_vpn_connection_unref		(VPNConnection *vpn, const char *func);

const char *		nmwa_vpn_connection_get_name		(VPNConnection *vpn);

const char *		nmwa_vpn_connection_get_user_name	(VPNConnection *vpn);
void				nmwa_vpn_connection_set_user_name	(VPNConnection *vpn, const char *user_name);

VPNConnection *	nmwa_vpn_connection_find_by_name	(GSList *list, const char *name);

#endif
