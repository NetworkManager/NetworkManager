/* NetworkManagerInfo -- Manage allowed access points and provide a UI
 *                         for WEP key entry
 *
 * Colin Walters <walters@redhat.com>
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

#ifndef NETWORK_MANAGER_INFO_VPN_H
#define NETWORK_MANAGER_INFO_VPN_H

#include "NetworkManagerInfo.h"

int		nmi_vpn_init	(NMIAppInfo *info);

void		nmi_vpn_request_password (NMIAppInfo *info, DBusMessage *message, const char *vpn, const char *username, gboolean retry);

void		nmi_vpn_cancel_request_password	(NMIAppInfo *info);

#endif
