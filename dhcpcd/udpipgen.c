/*
 * dhcpcd - DHCP client daemon -
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

#include <string.h>
#include "udpipgen.h"
#include "client.h"

/*****************************************************************************/
unsigned short in_cksum(unsigned short *addr, int len)
{
	register int sum = 0;
	register u_short *w = addr;
	register int nleft = len;
	while ( nleft > 1 )
	{
		sum += *w++;
		nleft -= 2;
	}
	if ( nleft == 1 )
	{
		u_short a = 0;
		memcpy(&a,w,1);
		sum += a;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}
/*****************************************************************************/
void udpipgen (udpiphdr *udpip, unsigned int saddr, unsigned int daddr, unsigned short *ip_id, int dhcp_msg_len)
{
	/* Use local copy because udpip->ip is not aligned.  */
	struct ip ip_local;
	struct ip *ip = &ip_local;
	struct ipovly *io = (struct ipovly *)udpip->ip;
	struct udphdr *udp = (struct udphdr *)udpip->udp;
	
	io->ih_next = io->ih_prev = 0;
	io->ih_x1 = 0;
	io->ih_pr = IPPROTO_UDP;
	io->ih_len = htons (dhcp_msg_len + sizeof (struct udphdr));
	io->ih_src.s_addr = saddr;
	io->ih_dst.s_addr = daddr;
	udp->source = htons (DHCP_CLIENT_PORT);
	udp->dest = htons (DHCP_SERVER_PORT);
	udp->len = io->ih_len;
	udp->check = 0;
	udp->check = in_cksum ((unsigned short *)udpip, dhcp_msg_len + sizeof (udpiphdr));
	if (udp->check == 0)
		udp->check = 0xffff;
	memcpy (ip,(struct ip *)udpip->ip, sizeof (ip_local));
	ip->ip_hl = 5;
	ip->ip_v = IPVERSION;
	ip->ip_tos = IPTOS_LOWDELAY;
	ip->ip_len = htons (dhcp_msg_len + sizeof (udpiphdr));

/* Hmm, since the UDP packets shouldnt' be fragmented, ip_id = 0 */ 
#if 0
	ip->ip_id = htons (*ip_id); *ip_id++;
#else
	ip->ip_id = 0;
#endif

	ip->ip_off = 0;
	ip->ip_ttl = IPDEFTTL; /* time to live, 64 by default */
	ip->ip_p = IPPROTO_UDP;
	ip->ip_src.s_addr = saddr;
	ip->ip_dst.s_addr = daddr;
	ip->ip_sum = 0;
	memcpy (udpip->ip, ip, sizeof (ip_local));
	ip->ip_sum = in_cksum ((unsigned short *)&ip_local, sizeof (struct ip));
	memcpy (udpip->ip, ip, sizeof (ip_local));
}
/*****************************************************************************/
int udpipchk(udpiphdr *udpip)
{
	int			hl;
	struct ip		save_ip;
	struct ip		*ip = (struct ip *)udpip->ip;
	struct ipovly	*io = (struct ipovly *)udpip->ip;
	struct udphdr	*udp = (struct udphdr *)udpip->udp;
	udpiphdr		*nudpip = udpip;

	hl = ip->ip_hl<<2;
	if (in_cksum ((unsigned short *)udpip, hl))
		return -1;
	memcpy (&save_ip, udpip->ip, sizeof (struct ip));
	hl -= sizeof (struct ip);
	if (hl)
	{
		/* thrash IP options */
		nudpip = (udpiphdr *)((char *)udpip + hl);
		memmove ((char *)nudpip, udpip, sizeof (struct ip));
		io = (struct ipovly *)nudpip->ip;
		ip = (struct ip *)nudpip->ip;
		udp = (struct udphdr *)nudpip->udp;
	}
	if (udp->check == 0)
		return 0; /* no checksum has been done by sender */
	io->ih_next = io->ih_prev = 0;
	io->ih_x1 = 0;
	io->ih_len = udp->len;
	hl = ntohs (udp->len) + sizeof (struct ip);
	if (in_cksum ((unsigned short *)nudpip, hl))
		return -2;
	memcpy (udpip->ip, &save_ip, sizeof(struct ip));
	return 0;
}
