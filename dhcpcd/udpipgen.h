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

#ifndef UDPIPGEN_H
#define UDPIPGEN_H

#include <netinet/ip.h>

#ifndef IPDEFTTL
#define IPDEFTTL 64
#endif

struct ipovly
{
  int ih_next,ih_prev;
  u_char ih_x1;
  u_char ih_pr;
  u_short ih_len;
  struct in_addr ih_src;
  struct in_addr ih_dst;
} __attribute__((packed));

struct udphdr
{
  u_int16_t uh_sport;
  u_int16_t uh_dport;
  u_int16_t uh_ulen;
  u_int16_t uh_sum;
} __attribute__((packed));

typedef struct udpiphdr
{
  char ip[sizeof(struct ip)];
  char udp[sizeof(struct udphdr)];
} __attribute__((packed)) udpiphdr;

void udpipgen (udpiphdr *udpip, unsigned int saddr, unsigned int daddr, unsigned short *ip_id);
int udpipchk (udpiphdr *udpip);

#endif
