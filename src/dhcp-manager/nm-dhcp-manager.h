/* nm-dhcp-manager.c - Handle the DHCP daemon for NetworkManager
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

#ifndef NM_DHCP_MANAGER_H
#define NM_DHCP_MANAGER_H

#include "NetworkManagerMain.h"
#include "nm-device.h"

/*
 * FIXME: These should go in a header shared by NetworkManager and dhcdbd,
 * but right now NetworkManager and dhcdbd do not share any header.  The
 * following is copied (and cleaned up) from dhcdbd.h.
 */
enum dhcdbd_state
{
	DHCDBD_NBI=0,		/* no broadcast interfaces found */
	DHCDBD_PREINIT,	/* configuration started */
	DHCDBD_BOUND,		/* lease obtained */
	DHCDBD_RENEW,		/* lease renewed */
	DHCDBD_REBOOT,		/* have valid lease, but now obtained a different one */
	DHCDBD_REBIND,		/* new, different lease */
	DHCDBD_STOP,		/* remove old lease */
	DHCDBD_MEDIUM,		/* media selection begun */
	DHCDBD_TIMEOUT,	/* timed out contacting DHCP server */
	DHCDBD_FAIL,		/* all attempts to contact server timed out, sleeping */
	DHCDBD_EXPIRE,		/* lease has expired, renewing */
	DHCDBD_RELEASE,	/* releasing lease */
	DHCDBD_START,		/* sent when dhclient started OK */
	DHCDBD_ABEND,		/* dhclient exited abnormally */
	DHCDBD_END,		/* dhclient exited normally */
	DHCDBD_END_OPTIONS,	/* last option in subscription sent */
};

char *			get_dhcp_match_string					(const char *owner);

NMDHCPManager *	nm_dhcp_manager_new						(NMData *data);
void				nm_dhcp_manager_dispose					(NMDHCPManager *manager);

gboolean			nm_dhcp_manager_begin_transaction			(NMDHCPManager *manager, NMActRequest *req);
void				nm_dhcp_manager_cancel_transaction			(NMDHCPManager *manager, NMActRequest *req);

NMIP4Config *		nm_dhcp_manager_get_ip4_config			(NMDHCPManager *manager, NMActRequest *req);

gboolean			nm_dhcp_manager_process_signal			(NMDHCPManager *manager, DBusMessage *message);
gboolean			nm_dhcp_manager_process_name_owner_changed	(NMDHCPManager *manager, const char *changed_service_name, const char *old_owner, const char *new_owner);

guint32			nm_dhcp_manager_get_state_for_device		(NMDHCPManager *manager, NMDevice *dev);

#endif
