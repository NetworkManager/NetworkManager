/*
 * dhcpcd - DHCP client daemon -
 * Copyright (C) 1996 - 1997 Yoichi Hariguchi <yoichi@fore.com>
 * Copyright (C) January, 1998 Sergei Viznyuk <sv@phystech.com>
 * 
 * dhcpcd is an RFC2131 and RFC1541 compliant DHCP client daemon.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef ARP_H
#define ARP_H

#include "client.h"

typedef struct arpMessage
{
	struct packed_ether_header	ethhdr;
	u_short htype;	/* hardware type (must be ARPHRD_ETHER) */
	u_short ptype;	/* protocol type (must be ETHERTYPE_IP) */
	u_char  hlen;		/* hardware address length (must be 6) */
	u_char  plen;		/* protocol address length (must be 4) */
	u_short operation;	/* ARP opcode */
	u_char  sHaddr[ETH_ALEN];	/* sender's hardware address */
	u_char  sInaddr[4];	/* sender's IP address */
	u_char  tHaddr[ETH_ALEN];	/* target's hardware address */
	u_char  tInaddr[4];	/* target's IP address */
	u_char  pad[18];	/* pad for min. Ethernet payload (60 bytes) */
} __attribute__((packed)) arpMessage;


#ifdef ARPCHECK
int arpCheck(const dhcp_interface *iface);
#endif
int	arpRelease(const dhcp_interface *iface);
int	arpInform(const dhcp_interface *iface);

#endif
