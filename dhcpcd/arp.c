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

#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <string.h>
#include <syslog.h>
#include "client.h"
#include "arp.h"

#define BasicArpLen(A) (sizeof(A) - (sizeof(A.ethhdr) + sizeof(A.pad)))

extern	int		DebugFlag;

int eth2tr(struct packed_ether_header *frame, int datalen);
int tr2eth(struct packed_ether_header *frame);

/*****************************************************************************/
#ifdef ARPCHECK
int arpCheck(const dhcp_interface *iface)
{
	arpMessage arp_msg_send;
	arpMessage arp_msg_recv;
	struct sockaddr addr;
	int j,i=0;

	memset (&arp_msg_send, 0, sizeof(arpMessage));
	memcpy (arp_msg_send.ethhdr.ether_dhost, MAC_BCAST_ADDR, ETH_ALEN);
	memcpy (arp_msg_send.ethhdr.ether_shost, iface->chaddr, ETH_ALEN);
	arp_msg_send.ethhdr.ether_type = htons(ETHERTYPE_ARP);

	arp_msg_send.htype		= htons(ARPHRD_ETHER);
	arp_msg_send.ptype		= htons(ETHERTYPE_IP);
	arp_msg_send.hlen		= ETH_ALEN;
	arp_msg_send.plen		= 4;
	arp_msg_send.operation	= htons(ARPOP_REQUEST);
	memcpy (arp_msg_send.sHaddr, iface->chaddr, ETH_ALEN);
	memcpy (&arp_msg_send.tInaddr, &(iface->ciaddr), 4);

	if ( DebugFlag )
	{
		syslog(LOG_DEBUG, "broadcasting ARPOP_REQUEST for %u.%u.%u.%u\n",
				arp_msg_send.tInaddr[0],arp_msg_send.tInaddr[1],
				arp_msg_send.tInaddr[2],arp_msg_send.tInaddr[3]);
	}

	do
	{
		do
		{
			if ( i++ > 4 )
				return 0; /*  5 probes  */
			memset (&addr, 0, sizeof(struct sockaddr));
			memcpy (addr.sa_data, iface->iface, strlen (iface->iface));	
			if ( sendto(iface->sk, &arp_msg_send, sizeof (arpMessage), 0, &addr, sizeof(struct sockaddr)) == -1 )
			{
				syslog(LOG_ERR,"arpCheck: sendto: %m\n");
				return -1;
			}
		} while ( peekfd(iface->sk,50000) ); /* 50 msec timeout */

		do
		{
			memset (&arp_msg_recv, 0, sizeof(arpMessage));
			j = sizeof(struct sockaddr);
			if ( recvfrom(iface->sk, &arp_msg_recv, sizeof(arpMessage), 0, (struct sockaddr *)&addr, &j) == -1 )
			{
				syslog(LOG_ERR,"arpCheck: recvfrom: %m\n");
				return -1;
			}

			if ( arp_msg_recv.ethhdr.ether_type != htons(ETHERTYPE_ARP) )
				continue;
			if ( arp_msg_recv.operation == htons(ARPOP_REPLY) )
			{
				if ( DebugFlag )
					syslog(LOG_DEBUG, "ARPOP_REPLY received from %u.%u.%u.%u for %u.%u.%u.%u\n",
							arp_msg_recv.sInaddr[0],arp_msg_recv.sInaddr[1],
							arp_msg_recv.sInaddr[2],arp_msg_recv.sInaddr[3],
							arp_msg_recv.tInaddr[0],arp_msg_recv.tInaddr[1],
							arp_msg_recv.tInaddr[2],arp_msg_recv.tInaddr[3]);
			}
    			else
				continue;
			if ( memcmp (arp_msg_recv.tHaddr, iface->chaddr, ETH_ALEN) )
			{
				if ( DebugFlag )
					syslog(LOG_DEBUG,
						"target hardware address mismatch: %02X.%02X.%02X.%02X.%02X.%02X received, %02X.%02X.%02X.%02X.%02X.%02X expected\n",
						arp_msg_recv.tHaddr[0],arp_msg_recv.tHaddr[1],arp_msg_recv.tHaddr[2],
						arp_msg_recv.tHaddr[3],arp_msg_recv.tHaddr[4],arp_msg_recv.tHaddr[5],
						iface->chaddr[0],iface->chaddr[1],
						iface->chaddr[2],iface->chaddr[3],
						iface->chaddr[4],iface->chaddr[5]);
					continue;
			}
			if (memcmp (&arp_msg_recv.sInaddr, &(iface->ciaddr), 4))
			{
				if ( DebugFlag )
					syslog(LOG_DEBUG, "sender IP address mismatch: %u.%u.%u.%u received, %u.%u.%u.%u expected\n",
						arp_msg_recv.sInaddr[0],arp_msg_recv.sInaddr[1],arp_msg_recv.sInaddr[2],arp_msg_recv.sInaddr[3],
						((unsigned char *)&(iface->ciaddr))[0],
						((unsigned char *)&(iface->ciaddr))[1],
						((unsigned char *)&(iface->ciaddr))[2],
						((unsigned char *)&(iface->ciaddr))[3]);
				continue;
			}
			return 1;
		} while ( peekfd(iface->sk,50000) == 0 );
	} while ( 1 );

	return 0;
}
#endif
/*****************************************************************************/
int arpRelease(const dhcp_interface *iface)  /* sends UNARP message, cf. RFC1868 */
{
	arpMessage ArpMsgSend;
	struct sockaddr addr;
	const int inaddr_broadcast = INADDR_BROADCAST;

	/* build Ethernet header */
	memset (&ArpMsgSend,0,sizeof(arpMessage));
	memcpy (ArpMsgSend.ethhdr.ether_dhost, MAC_BCAST_ADDR, ETH_ALEN);
	memcpy (ArpMsgSend.ethhdr.ether_shost, iface->chaddr, ETH_ALEN);
	ArpMsgSend.ethhdr.ether_type = htons(ETHERTYPE_ARP);

	/* build UNARP message */
	ArpMsgSend.htype	= htons(ARPHRD_ETHER);
	ArpMsgSend.ptype	= htons(ETHERTYPE_IP);
	ArpMsgSend.plen	= 4;
	ArpMsgSend.operation= htons(ARPOP_REPLY);
	memcpy (&ArpMsgSend.sInaddr, &(iface->ciaddr), 4);
	memcpy (&ArpMsgSend.tInaddr, &inaddr_broadcast, 4);
 
	memset(&addr,0,sizeof(struct sockaddr));
	memcpy(addr.sa_data,iface->iface,strlen (iface->iface));
	if ( sendto (iface->sk, &ArpMsgSend, sizeof (arpMessage), 0, &addr, sizeof(struct sockaddr)) == -1 )
	{
		syslog (LOG_ERR,"arpRelease: sendto: %m\n");
		return -1;
	}
	return 0;
}
/*****************************************************************************/
int arpInform(const dhcp_interface *iface)
{
	arpMessage ArpMsgSend;
	struct sockaddr addr;
	const int inaddr_broadcast = INADDR_BROADCAST;

	memset (&ArpMsgSend, 0, sizeof(arpMessage));
	memcpy (ArpMsgSend.ethhdr.ether_dhost, MAC_BCAST_ADDR, ETH_ALEN);
	memcpy (ArpMsgSend.ethhdr.ether_shost, iface->chaddr, ETH_ALEN);
	ArpMsgSend.ethhdr.ether_type = htons(ETHERTYPE_ARP);

	ArpMsgSend.htype	= htons(ARPHRD_ETHER);
	ArpMsgSend.ptype	= htons(ETHERTYPE_IP);
	ArpMsgSend.hlen	= ETH_ALEN;
	ArpMsgSend.plen	= 4;
	ArpMsgSend.operation= htons(ARPOP_REPLY);
	memcpy (ArpMsgSend.sHaddr, iface->chaddr, ETH_ALEN);
	memcpy (ArpMsgSend.tHaddr, iface->shaddr, ETH_ALEN);
	memcpy (ArpMsgSend.sInaddr, &(iface->ciaddr), 4);
	memcpy (ArpMsgSend.tInaddr, &inaddr_broadcast, 4);
 
	memset (&addr, 0, sizeof(struct sockaddr));
	memcpy (addr.sa_data, iface->iface, strlen (iface->iface));
	if ( sendto (iface->sk, &ArpMsgSend, sizeof (arpMessage), 0, &addr, sizeof(struct sockaddr)) == -1 )
	{
		syslog(LOG_ERR,"arpInform: sendto: %m\n");
		return -1;
	}
	return 0;
}
