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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_packet.h>
#include <net/route.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <setjmp.h>
#include <time.h>
#include "client.h"
#include "buildmsg.h"
#include "udpipgen.h"
#include "arp.h"

int DebugFlag = 1;
#define DEBUG

void debug_dump_dhcp_options (udpipMessage *udp_msg, dhcpOptions *options);

/*****************************************************************************/
int parseDhcpMsgRecv(udpipMessage *udp_msg, dhcpOptions *options) /* this routine parses dhcp message received */
{
	const struct ip	*ip_msg = (struct ip *)((struct udpiphdr *)udp_msg->udpipmsg)->ip;
	dhcpMessage		*dhcp_msg = (dhcpMessage *)&(udp_msg->udpipmsg[sizeof(udpiphdr)]);
	register u_char	*p = dhcp_msg->options+4;
	unsigned char		*end = dhcp_msg->options + sizeof(dhcp_msg->options);

	/* Force T1 and T2 to 0: either new values will be in message, or they
	   will need to be recalculated from lease time */
	if ( options->val[dhcpT1value] && options->len[dhcpT1value] > 0 )
		memset (options->val[dhcpT1value], 0, options->len[dhcpT1value]);
	if ( options->val[dhcpT2value] && options->len[dhcpT2value] > 0 )
		memset (options->val[dhcpT2value], 0, options->len[dhcpT2value]);

	while ( p < end )
	{
		switch ( *p )
		{
			case endOption:
				goto swend;
			case padOption:
				p++;
				break;
			default:
				if ( p[1] )
				{
					if ( options->len[*p] == p[1] )
						memcpy (options->val[*p], p+2, p[1]);
					else
					{
						options->len[*p] = p[1];
						if ( options->val[*p] )
							free (options->val[*p]);
						else
							options->num++;
						options->val[*p] = malloc (p[1]+1);
						memset (options->val[*p], 0, p[1]+1);
						memcpy (options->val[*p], p+2, p[1]);
					}
				}
				p+=p[1]+2;
		}
	}

swend:
#ifdef DEBUG
	debug_dump_dhcp_options (udp_msg, options);
#endif

#if 0
	if ( ! dhcp_msg->yiaddr )
		dhcp_msg->yiaddr = DhcpMsgSend->ciaddr;
#endif

	if ( ! options->val[dhcpServerIdentifier] ) /* did not get dhcpServerIdentifier */
	{
		/* make it the same as IP address of the sender */
		options->val[dhcpServerIdentifier] = malloc(4);
		memcpy (options->val[dhcpServerIdentifier], &ip_msg->ip_src.s_addr, 4);
		options->len[dhcpServerIdentifier] = 4;
		options->num++;
		if ( DebugFlag )
			syslog(LOG_DEBUG, "dhcpServerIdentifier option is missing in DHCP server response. Assuming %u.%u.%u.%u\n",
				((unsigned char *)options->val[dhcpServerIdentifier])[0],
				((unsigned char *)options->val[dhcpServerIdentifier])[1],
				((unsigned char *)options->val[dhcpServerIdentifier])[2],
				((unsigned char *)options->val[dhcpServerIdentifier])[3]);
	}
	if ( ! options->val[dns] ) /* did not get DNS */
	{
		/* make it the same as dhcpServerIdentifier */
		options->val[dns] = malloc(4);
		memcpy (options->val[dns], options->val[dhcpServerIdentifier], 4);
		options->len[dns] = 4;
		options->num++;
		if ( DebugFlag )
			syslog(LOG_DEBUG, "dns option is missing in DHCP server response. Assuming %u.%u.%u.%u\n",
				((unsigned char *)options->val[dns])[0],
				((unsigned char *)options->val[dns])[1],
				((unsigned char *)options->val[dns])[2],
				((unsigned char *)options->val[dns])[3]);
	}
	if ( ! options->val[subnetMask] ) /* did not get subnetMask */
	{
		options->val[subnetMask] = malloc(4);
		((unsigned char *)options->val[subnetMask])[0] = 255;
		if ( IN_CLASSA(ntohl(dhcp_msg->yiaddr)) )
		{
			((unsigned char *)options->val[subnetMask])[1] = 0; /* class A */
			((unsigned char *)options->val[subnetMask])[2] = 0;
			((unsigned char *)options->val[subnetMask])[3] = 0;
		}
		else
		{
			((unsigned char *)options->val[subnetMask])[1] = 255;
			if ( IN_CLASSB(ntohl(dhcp_msg->yiaddr)) )
			{
				((unsigned char *)(options->val[subnetMask]))[2] = 0;/* class B */
				((unsigned char *)(options->val[subnetMask]))[3] = 0;
			}
			else
			{
				((unsigned char *)options->val[subnetMask])[2] = 255;
				if ( IN_CLASSC(ntohl(dhcp_msg->yiaddr)) )
					((unsigned char *)options->val[subnetMask])[3] = 0; /* class C */
				else
					((unsigned char *)options->val[subnetMask])[3] = 255;
			}
		}
		options->len[subnetMask] = 4;
		options->num++;
		if ( DebugFlag )
			syslog(LOG_DEBUG, "subnetMask option is missing in DHCP server response. Assuming %u.%u.%u.%u\n",
				((unsigned char *)options->val[subnetMask])[0],
				((unsigned char *)options->val[subnetMask])[1],
				((unsigned char *)options->val[subnetMask])[2],
				((unsigned char *)options->val[subnetMask])[3]);
	}
	if ( ! options->val[broadcastAddr] ) /* did not get broadcastAddr */
	{
		int br = dhcp_msg->yiaddr | ~*((int *)options->val[subnetMask]);
		options->val[broadcastAddr] = malloc(4);
		memcpy (options->val[broadcastAddr], &br, 4);
		options->len[broadcastAddr] = 4;
		options->num++;
		if ( DebugFlag )
			syslog(LOG_DEBUG, "broadcastAddr option is missing in DHCP server response. Assuming %u.%u.%u.%u\n",
				((unsigned char *)options->val[broadcastAddr])[0],
				((unsigned char *)options->val[broadcastAddr])[1],
				((unsigned char *)options->val[broadcastAddr])[2],
				((unsigned char *)options->val[broadcastAddr])[3]);
	}
#if 0
	if ( ! options->val[routersOnSubnet] )
	{
		options->val[routersOnSubnet] = malloc(4);
		if ( dhcp_msg->giaddr )
			memcpy(options->val[routersOnSubnet],&dhcp_msg->giaddr,4);
		else
			memcpy(options->val[routersOnSubnet],options->val[dhcpServerIdentifier],4);
		options->len[routersOnSubnet] = 4;
		options->num++;
		if ( DebugFlag )
			syslog(LOG_DEBUG, "routersOnSubnet option is missing in DHCP server response. Assuming %u.%u.%u.%u\n",
				((unsigned char *)options->val[routersOnSubnet])[0],
				((unsigned char *)options->val[routersOnSubnet])[1],
				((unsigned char *)options->val[routersOnSubnet])[2],
				((unsigned char *)options->val[routersOnSubnet])[3]);
	}
#endif
	if ( options->val[dhcpIPaddrLeaseTime] && options->len[dhcpIPaddrLeaseTime] == 4 )
	{
		if ( *(unsigned int *)options->val[dhcpIPaddrLeaseTime] == 0 )
		{
			unsigned int	lease_time = htonl (DHCP_DEFAULT_LEASETIME);
			memcpy (options->val[dhcpIPaddrLeaseTime], &lease_time, 4);
			if ( DebugFlag )
				syslog(LOG_DEBUG,"dhcpIPaddrLeaseTime=0 in DHCP server response. Assuming %u sec\n", lease_time);
		}
		else
		{
			if ( DebugFlag )
				syslog(LOG_DEBUG,"dhcpIPaddrLeaseTime = %u in DHCP server response.\n",
					ntohl(*(unsigned int *)options->val[dhcpIPaddrLeaseTime]));
		}
	}
	else /* did not get dhcpIPaddrLeaseTime */
	{
		unsigned int	lease_time = htonl (DHCP_DEFAULT_LEASETIME);
		options->val[dhcpIPaddrLeaseTime] = malloc(4);
		memcpy (options->val[dhcpIPaddrLeaseTime], &lease_time, 4);
		options->len[dhcpIPaddrLeaseTime] = 4;
		options->num++;
		if ( DebugFlag )
			syslog(LOG_DEBUG,"dhcpIPaddrLeaseTime option is missing in DHCP server response. Assuming %u sec\n", lease_time);
	}
	if ( options->val[dhcpT1value] && options->len[dhcpT1value] == 4 )
	{
		if ( *(unsigned int *)options->val[dhcpT1value] == 0 )
		{
			unsigned t2 = 0.5 * ntohl(*(unsigned int *)options->val[dhcpIPaddrLeaseTime]);
			int t1 = htonl(t2);
			memcpy (options->val[dhcpT1value],&t1,4);
			options->len[dhcpT1value] = 4;
			if ( DebugFlag )
				syslog(LOG_DEBUG,"dhcpT1value is missing in DHCP server response. Assuming %u sec\n",t2);
		}
	}
	else		/* did not get T1 */
	{
		unsigned t2 = 0.5*ntohl(*(unsigned int *)options->val[dhcpIPaddrLeaseTime]);
		int t1 = htonl(t2);
		options->val[dhcpT1value] = malloc(4);
		memcpy (options->val[dhcpT1value],&t1,4);
		options->len[dhcpT1value] = 4;
		options->num++;
		if ( DebugFlag )
			syslog(LOG_DEBUG,"dhcpT1value is missing in DHCP server response. Assuming %u sec\n",t2);
	}
	if ( options->val[dhcpT2value] && options->len[dhcpT2value] == 4 )
	{
		if ( *(unsigned int *)options->val[dhcpT2value] == 0 )
		{
			unsigned t2 = 0.875*ntohl(*(unsigned int *)options->val[dhcpIPaddrLeaseTime]);
			int t1 = htonl(t2);
			memcpy(options->val[dhcpT2value],&t1,4);
			options->len[dhcpT2value] = 4;
			if ( DebugFlag )
				syslog(LOG_DEBUG,"dhcpT2value is missing in DHCP server response. Assuming %u sec\n",t2);
		}
	}
	else		/* did not get T2 */
	{
		unsigned t2 = 0.875*ntohl(*(unsigned int *)options->val[dhcpIPaddrLeaseTime]);
		int t1 = htonl(t2);
		options->val[dhcpT2value] = malloc(4);
		memcpy(options->val[dhcpT2value],&t1,4);
		options->len[dhcpT2value] = 4;
		options->num++;
		if ( DebugFlag )
			syslog(LOG_DEBUG,"dhcpT2value is missing in DHCP server response. Assuming %u sec\n",t2);
	}
	if ( options->val[dhcpMessageType] )
		return *(unsigned char *)options->val[dhcpMessageType];
	return -1;
}
/*****************************************************************************/
void classIDsetup(dhcp_interface *iface, const char *g_cls_id)
{
	unsigned int	 g_cls_id_len = 0;

	if (!iface) return;

	if (g_cls_id)
		g_cls_id_len = strlen (g_cls_id);

	if (g_cls_id_len)
	{
		memcpy (iface->cls_id, g_cls_id, g_cls_id_len);
		iface->cls_id_len = g_cls_id_len;
	}
	else
	{
		struct utsname sname;
		if ( uname(&sname) )
			syslog (LOG_ERR,"classIDsetup: uname: %m\n");
		snprintf (iface->cls_id, DHCP_CLASS_ID_MAX_LEN, "%s %s %s",
				sname.sysname, sname.release, sname.machine);
	}
}
/*****************************************************************************/
void clientIDsetup(dhcp_interface *iface, const char *g_cli_id)
{
	unsigned int	 g_cli_id_len = 0;
	unsigned char	*c = iface->cli_id;

	if (!iface) return;

	if (g_cli_id)
		g_cli_id_len = strlen (g_cli_id);

	*c++ = dhcpClientIdentifier;
	if ( g_cli_id_len )
	{
		*c++ = g_cli_id_len + 1;	/* 1 for the field below */
		*c++ = 0;			/* type: string */
		memcpy (c, g_cli_id, g_cli_id_len);
		iface->cli_id_len = g_cli_id_len + 3;
	}
	else
	{
		*c++ = ETH_ALEN + 1;	        /* length: 6 (MAC Addr) + 1 (# field) */
		*c++ = (iface->bTokenRing) ? ARPHRD_IEEE802_TR : ARPHRD_ETHER;	/* type: Ethernet address */
		memcpy (c, iface->chaddr, ETH_ALEN);
		iface->cli_id_len = ETH_ALEN + 3;
	}
}
/*****************************************************************************/
void releaseDhcpOptions (dhcp_interface *iface)
{
	register int i;
	for ( i = 1; i < 256; i++ )
	{
		if ( iface->dhcp_options.val[i] )
			free(iface->dhcp_options.val[i]);
	}

	memset(&(iface->dhcp_options), 0, sizeof(dhcpOptions));
}
/*****************************************************************************/
#ifdef DEBUG
static void dumpframe(const char *title, struct packed_ether_header *frame)
{
	int i;
	unsigned char *dp;

	printf("%s:", title);
	dp = (unsigned char *)frame;
	for (i = 0; i < 32; i++)
	{
		if ((i % 16) == 0)
			printf("\n");
		printf("0x%02X ", *dp++);
	}
}
#endif /* DEBUG */
/*****************************************************************************/
/***** convert ethernet and token-ring frames *****/
int eth2tr(struct packed_ether_header *frame, int datalen)
{
	struct trh_hdr *phdr;
	struct trllc *pllc;
	char trheader[sizeof(struct trh_hdr) - sizeof(phdr->rseg) + sizeof(struct trllc)];
	int len;

#ifdef DEBUG
	dumpframe("eth2tr: Incoming eth frame", frame);
#endif
	memset(trheader, 0, sizeof(trheader));
	phdr = (struct trh_hdr *)trheader;
	phdr->ac = AC;
	phdr->fc = LLC_FRAME;
	memcpy(phdr->daddr, frame->ether_dhost, TR_ALEN);
	memcpy(phdr->saddr, frame->ether_shost, TR_ALEN);
	if (phdr->daddr[0] & 0x80)
	{ /* Destination is a broadcast */
		phdr->rcf = sizeof(phdr->rcf) | htons(TR_RCF_BROADCAST | 0x70); /* Unlimited frame length */
		pllc = (struct trllc *)&phdr->rseg[0];
		phdr->saddr[0] |= TR_RII; /* Set source-route indicator */
		len = sizeof(trheader);
	}
	else
	{
		pllc = (struct trllc *)&phdr->rcf;
		len = sizeof(trheader) - sizeof(phdr->rcf);
	}
	pllc->dsap = EXTENDED_SAP;
	pllc->ssap = EXTENDED_SAP;
	pllc->llc = UI_CMD;
	pllc->protid[0] = pllc->protid[1] = pllc->protid[2] = 0;
	pllc->ethertype = frame->ether_type;
	/* Make room for larger TR header */
	memmove((char *)(frame + 1) + (len - sizeof(struct packed_ether_header)), frame + 1, datalen);
	memcpy(frame, trheader, len); /* Install TR header */
#ifdef DEBUG
	dumpframe("eth2tr: Outgoing tr frame", frame);
#endif
	return len + datalen;
}
/*****************************************************************************/
int tr2eth(struct packed_ether_header *frame)
{
	struct trh_hdr hdr;
	struct trllc *pllc;
	int hlen = 0;

#ifdef DEBUG
	dumpframe("tr2eth: Incoming tr frame", frame);
#endif
	hdr = *((struct trh_hdr *)frame);
	if (hdr.saddr[0] & TR_RII)
	{
		fake_rif:
		hlen = hdr.rcf & ntohs(TR_RCF_LEN_MASK);
	#ifdef DEBUG
		printf("rcf = 0x%X SR len %d\n", hdr.rcf, hlen);
	#endif
		if (hlen < sizeof(hdr.rcf) || (hlen & 1))
			return 1;
		hdr.saddr[0] &= ~TR_RII;
	}
	pllc = (struct trllc *)(((__u8 *)frame) + sizeof(struct trh_hdr) - TR_MAXRIFLEN + hlen);
	if (pllc->dsap != EXTENDED_SAP || pllc->llc != UI_CMD)
	{
		if (hlen == 0)
			goto fake_rif;	/* Bug in 2.2.3 kernel */
	#ifdef DEBUG
		printf("corrupted TR-IP packet of ui=0x%x and dsap 0x%x discarded\n", pllc->llc, pllc->dsap);
	#endif
		return 1;
	}
	memcpy(frame->ether_dhost, hdr.daddr, ETH_ALEN);
	memcpy(frame->ether_shost, hdr.saddr, ETH_ALEN);
	frame->ether_type = pllc->ethertype;
	memmove(frame + 1, pllc + 1, IPPACKET_SIZE); /* Move data portion: Overlapping buffer */
#ifdef DEBUG
	dumpframe("tr2eth: Outgoing eth frame", frame);
#endif
	return 0;
}
/*****************************************************************************/
/* Subtract the `struct timeval' values X and Y,
   storing the result in RESULT.
   Return 1 if the difference is negative, otherwise 0.  */
static int timeval_subtract(struct timeval *result, struct timeval *x, struct timeval *y)
{
	/* Perform the carry for the later subtraction by updating Y. */
	if (x->tv_usec < y->tv_usec)
	{
		int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
		y->tv_usec -= 1000000 * nsec;
		y->tv_sec += nsec;
	}
	if (x->tv_usec - y->tv_usec > 1000000)
	{
		int nsec = (x->tv_usec - y->tv_usec) / 1000000;
		y->tv_usec += 1000000 * nsec;
		y->tv_sec -= nsec;
	}

	/* Compute the time remaining to wait.
	`tv_usec' is certainly positive. */
	result->tv_sec = x->tv_sec - y->tv_sec;
	result->tv_usec = x->tv_usec - y->tv_usec;

	/* Return 1 if result is negative. */
	return x->tv_sec < y->tv_sec;
}
/*****************************************************************************/
int peekfd (dhcp_interface *iface, time_t tv_usec)
{
	fd_set fs;
	struct timeval begin;
	time_t i = tv_usec;

	FD_ZERO (&fs);
	FD_SET (iface->sk, &fs);
	gettimeofday (&begin, NULL);

	/* Wake up each second to check whether or not we've been told
	 * to stop with iface->cease
	 */
	while (i > 0)
	{
		struct timeval now;
		struct timeval diff;
		struct timeval wait = {1, 0};

		if ( select (iface->sk+1, &fs, NULL, NULL, &wait) == -1 )
			return RET_DHCP_ERROR;
		if ( FD_ISSET(iface->sk, &fs) )
			return RET_DHCP_SUCCESS;
		gettimeofday (&now, NULL);
		timeval_subtract (&diff, &now, &begin);
		i = tv_usec - ((diff.tv_sec * 1000000) + diff.tv_usec);
		if (iface->cease)
			return RET_DHCP_CEASED;
	}
	return RET_DHCP_TIMEOUT;
}
/*****************************************************************************/
int dhcpSendAndRecv (dhcp_interface *iface, unsigned int expected_reply_type,
				dhcp_msg_build_proc buildUdpIpMsg, udpipMessage **return_msg)
{
	udpipMessage		*udp_msg_recv = NULL;
	struct sockaddr	addr;
	int				len, err = RET_DHCP_TIMEOUT, local_timeout = 0;
	int				j = DHCP_INITIAL_RTO / 2;
	struct timeval		local_begin, current, diff;
	struct timeval		overall_end;

	*return_msg = NULL;

	gettimeofday (&overall_end, NULL);
	overall_end.tv_sec += iface->client_options->base_timeout;

	do
	{
		udpipMessage	*udp_msg_send = buildUdpIpMsg (iface);
		int			 send_err = 0;

		if (!udp_msg_send)
			return RET_DHCP_ERROR;

		j += j;
		if (j > DHCP_MAX_RTO)
			j = DHCP_MAX_RTO;

		/* Make sure waiting j seconds isn't greater than our overall time left
		 * on this operation, and clamp j to the overall time left if it is.
		 */
		gettimeofday (&current, NULL);
		if (timeval_subtract (&diff, &overall_end, &current))
		{
			free (udp_msg_send);
			return RET_DHCP_TIMEOUT;
		}
		if (j > ((diff.tv_sec * 1000000) + diff.tv_usec))
			j = (diff.tv_sec * 1000000) + diff.tv_usec;

		if (iface->bTokenRing)      /* Here we convert a Eth frame into an TR frame */
			len = eth2tr (&(udp_msg_send->ethhdr), sizeof(udpiphdr) + sizeof(dhcpMessage));
		else
			len = sizeof (struct packed_ether_header) + sizeof(udpiphdr) + sizeof(dhcpMessage);

		memset (&addr, 0, sizeof(struct sockaddr));
		memcpy (addr.sa_data, iface->iface, strlen (iface->iface));
		do
		{
			send_err = sendto (iface->sk, udp_msg_send, len, MSG_DONTWAIT, &addr, sizeof(struct sockaddr));
			if (iface->cease || ((send_err == -1) && (errno != EAGAIN)))
			{
				free (udp_msg_send);
				return iface->cease ? RET_DHCP_CEASED : RET_DHCP_ERROR;
			}
		} while ((send_err == -1) && (errno == EAGAIN));

		free (udp_msg_send);
		gettimeofday (&local_begin, NULL);
		err = peekfd (iface, (j + random () % 200000));
		if (iface->cease || (err == RET_DHCP_CEASED))
			return RET_DHCP_CEASED;
	} while ( err == RET_DHCP_TIMEOUT );

	do
	{
		struct ip			 ipRecv_local;
		char				*tmp_ip;
		const struct udphdr	*udp_msg_recv_hdr;
		dhcpMessage		*dhcp_msg_recv;
		int				 reply_type = -1;
		char				 foobuf[512];
		int				 i, o;

		udp_msg_recv = calloc (1, sizeof (udpipMessage));
		o = sizeof (struct sockaddr);
		do
		{
			len = recvfrom (iface->sk, udp_msg_recv, sizeof(udpipMessage), MSG_DONTWAIT, (struct sockaddr *)&addr, &o);
			if (iface->cease || ((len == -1) && (errno != EAGAIN)))
			{
				free (udp_msg_recv);
				return iface->cease ? RET_DHCP_CEASED : RET_DHCP_ERROR;
			}
		} while ((len == -1) && (errno == EAGAIN));

		if (iface->bTokenRing)
		{    /* Here we convert a TR frame into an Eth frame */
			if (tr2eth (&(udp_msg_recv->ethhdr)))
			{
				free (udp_msg_recv);
				continue;
			}
		}

		gettimeofday (&current, NULL);
		timeval_subtract (&diff, &current, &local_begin);
		local_timeout = j - diff.tv_sec * 1000000 - diff.tv_usec + random() % 200000;

		/* Make sure waiting local_timeout seconds isn't greater than our overall time left
		 * on this operation, and clamp local_timeout to the overall time left if it is.
		 */
		if (timeval_subtract (&diff, &overall_end, &current))
		{
			free (udp_msg_recv);
			return RET_DHCP_TIMEOUT;
		}
		if ((local_timeout*1000000) > ((diff.tv_sec * 1000000) + diff.tv_usec))
			local_timeout = (diff.tv_sec * 1000000) + diff.tv_usec;

		/* Ignore non-IP packets */
		if ( udp_msg_recv->ethhdr.ether_type != htons(ETHERTYPE_IP) )
		{
			free (udp_msg_recv);
			continue;
		}

		tmp_ip = udp_msg_recv->udpipmsg;
		for (i = 0; i < sizeof (struct ip) - 2; i += 2)
		{
			if ( ( udp_msg_recv->udpipmsg[i] == 0x45 ) && ( udp_msg_recv->udpipmsg[i+1] == 0x00 ) )
			{
				tmp_ip = &(udp_msg_recv->udpipmsg[i]);
				break;
			}
		}

		/* Use local copy because ipRecv is not aligned.  */
		memcpy (&ipRecv_local, ((struct udpiphdr *)tmp_ip)->ip, sizeof(struct ip));
		udp_msg_recv_hdr = (struct udphdr *)((char*)(((struct udpiphdr*)tmp_ip)->ip)+sizeof(struct ip));
		if ( ipRecv_local.ip_p != IPPROTO_UDP )
		{
			free (udp_msg_recv);
			continue;
		}

		if ( iface->bTokenRing && (udp_msg_recv_hdr->uh_dport != htons(DHCP_CLIENT_PORT)))
		{
			free (udp_msg_recv);
			continue;
		}

		len -= sizeof(struct packed_ether_header);
		i = (int)ntohs (ipRecv_local.ip_len);
		if ( len < i )
		{
			if ( DebugFlag )
				syslog(LOG_DEBUG, "corrupted IP packet of size=%d and ip_len=%d discarded\n", len,i);
			free (udp_msg_recv);
			continue;
		}

		len = i - (ipRecv_local.ip_hl << 2);
		i = (int)ntohs(udp_msg_recv_hdr->uh_ulen);
		if ( len < i )
		{
			if ( DebugFlag )
				syslog(LOG_DEBUG, "corrupted UDP msg of size=%d and uh_ulen=%d discarded\n", len,i);
			free (udp_msg_recv);
			continue;
		}

		if ( iface->client_options->do_checksum && (len = udpipchk((udpiphdr *)tmp_ip)))
		{
			if ( DebugFlag )
			{
				switch ( len )
				{
					case -1:
						syslog(LOG_DEBUG, "corrupted IP packet with ip_len=%d discarded\n", (int)ntohs(ipRecv_local.ip_len));
						break;
					case -2:
						syslog(LOG_DEBUG, "corrupted UDP msg with uh_ulen=%d discarded\n", (int)ntohs(udp_msg_recv_hdr->uh_ulen));
						break;
				}
			}
			free (udp_msg_recv);
			continue;
		}

		dhcp_msg_recv = (dhcpMessage *)&(tmp_ip[(ipRecv_local.ip_hl << 2) + sizeof(struct udphdr)]);
		if ( dhcp_msg_recv->xid != iface->xid )
		{
			free (udp_msg_recv);
			continue;
		}

		if (	dhcp_msg_recv->htype != ARPHRD_ETHER && dhcp_msg_recv->htype != (char)ARPHRD_IEEE802_TR )
		{
			if ( DebugFlag )
				syslog (LOG_DEBUG,"wrong msg htype 0x%X discarded\n", dhcp_msg_recv->htype);
			free (udp_msg_recv);
			continue;
		}

		if ( dhcp_msg_recv->op != DHCP_BOOTREPLY )
		{
			free (udp_msg_recv);
			continue;
		}

		while ((iface->foo_sk > 0) && recvfrom (iface->foo_sk, (void *)foobuf, sizeof(foobuf), 0, NULL, NULL) != -1);

		/* Copy DHCP response options from received packet into local options list */
		reply_type = parseDhcpMsgRecv (udp_msg_recv, &(iface->dhcp_options));
		if ( expected_reply_type == reply_type )
		{
			*return_msg = udp_msg_recv;
			return RET_DHCP_SUCCESS;
		}

		free (udp_msg_recv);
		udp_msg_recv = NULL;

		if (reply_type == DHCP_NAK)
		{
			if ( iface->dhcp_options.val[dhcpMsg] )
				syslog(LOG_ERR, "DHCP_NAK server response received: %s\n", (char *)iface->dhcp_options.val[dhcpMsg]);
			else
				syslog(LOG_ERR, "DHCP_NAK server response received\n");
			return RET_DHCP_NAK;
		}

		err = peekfd (iface, local_timeout);
		if (iface->cease || (err == RET_DHCP_CEASED))
			return RET_DHCP_CEASED;
	} while ((local_timeout > 0) && (err == RET_DHCP_SUCCESS));

	return RET_DHCP_TIMEOUT;
}
/*****************************************************************************/
int dhcp_reboot (dhcp_interface *iface)
{
	/* Client has a cached IP and wants to request it again from the server
	 * if possible.  DHCP state INIT-REBOOT.
	 *
 	 * If no response from the server is received, we assume that we can still
	 * use the cached IP address.
	 */

	/* FIXME: get the IP address to renew from somewhere */

	if (!iface) return RET_DHCP_ERROR;

	releaseDhcpOptions (iface);
	return dhcp_request (iface, &buildDhcpReboot);
}
/*****************************************************************************/
int dhcp_init (dhcp_interface *iface)
{
	udpipMessage	*msg = NULL;
	dhcpMessage	*dhcp_msg = NULL;
	int			 err;

	if (!iface) return RET_DHCP_ERROR;

	releaseDhcpOptions (iface);

#ifdef DEBUG
	syslog (LOG_DEBUG, "ClassID  = \"%s\"\n"
		"ClientID = \"%u.%u.%u.%02X.%02X.%02X.%02X.%02X.%02X\"\n", iface->cls_id,
		iface->cli_id[0], iface->cli_id[1], iface->cli_id[2],
		iface->cli_id[3], iface->cli_id[4], iface->cli_id[5],
		iface->cli_id[6], iface->cli_id[7], iface->cli_id[8]);
#endif

	if ( DebugFlag )
		syslog (LOG_INFO, "Broadcasting DHCP_DISCOVER\n");
	iface->xid = random ();
	err = dhcpSendAndRecv (iface, DHCP_OFFER, &buildDhcpDiscover, &msg);
	if (err != RET_DHCP_SUCCESS)
		return err;

	dhcp_msg = (dhcpMessage *)&(msg->udpipmsg[sizeof(udpiphdr)]);
	if ( iface->client_options->send_second_discover )
	{
		udpipMessage	*msg2 = NULL;

		if (DebugFlag)
			syslog (LOG_INFO, "Broadcasting second DHCP_DISCOVER\n");

		iface->xid = dhcp_msg->xid;
		err = dhcpSendAndRecv (iface, DHCP_OFFER, &buildDhcpDiscover, &msg2);
		if (err == RET_DHCP_SUCCESS)
		{
			free (msg);
			msg = msg2;
		}
		dhcp_msg = (dhcpMessage *)&(msg->udpipmsg[sizeof(udpiphdr)]);
	}

	iface->ciaddr = dhcp_msg->yiaddr;
	memcpy (&(iface->siaddr), iface->dhcp_options.val[dhcpServerIdentifier], 4);
	memcpy (iface->shaddr, msg->ethhdr.ether_shost, ETH_ALEN);
	iface->xid = dhcp_msg->xid;

	/* DHCP_OFFER received */
	if ( DebugFlag )
	{
		syslog (LOG_INFO, "DHCP_OFFER received from %s (%u.%u.%u.%u)\n", dhcp_msg->sname,
			((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[0],
			((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[1],
			((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[2],
			((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[3]);
	}
	free (msg);

	return dhcp_request (iface, &buildDhcpRequest);
}
/*****************************************************************************/
int dhcp_request(dhcp_interface *iface, dhcp_msg_build_proc buildDhcpMsg)
{
	udpipMessage	*msg = NULL;
	int			 err;

	/* DHCP state REQUEST: request an address from a _particular_ DHCP server */

	if (!iface) return RET_DHCP_ERROR;

	if ( DebugFlag )
	{
		syslog (LOG_INFO, "Broadcasting DHCP_REQUEST for %u.%u.%u.%u\n",
			((unsigned char *)&(iface->ciaddr))[0], ((unsigned char *)&(iface->ciaddr))[1],
			((unsigned char *)&(iface->ciaddr))[2], ((unsigned char *)&(iface->ciaddr))[3]);
	}

	err = dhcpSendAndRecv (iface, DHCP_ACK, buildDhcpMsg, &msg);
	if (err != RET_DHCP_SUCCESS)
		return err;

	if ( DebugFlag )
	{
		dhcpMessage	*dhcp_msg = (dhcpMessage *)&(msg->udpipmsg[sizeof(udpiphdr)]);
		syslog (LOG_INFO, "DHCP_ACK received from %s (%u.%u.%u.%u)\n", dhcp_msg->sname,
			((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[0],
			((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[1],
			((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[2],
			((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[3]);
	}

	iface->req_sent_time = time (NULL);

#ifdef ARPCHECK
	/* check if the offered IP address already in use */
	if ( arpCheck(iface) )
	{
		if ( DebugFlag )
			syslog (LOG_INFO, "requested %u.%u.%u.%u address is in use\n",
				((unsigned char *)&(iface->ciaddr))[0], ((unsigned char *)&(iface->ciaddr))[1],
				((unsigned char *)&(iface->ciaddr))[2], ((unsigned char *)&(iface->ciaddr))[3]);
		dhcpDecline();
		iface->ciaddr = 0;
		return RET_DHCP_ADDRESS_IN_USE;
	}

	if ( DebugFlag )
	{
		syslog (LOG_INFO, "verified %u.%u.%u.%u address is not in use\n",
			((unsigned char *)&(iface->ciaddr))[0], ((unsigned char *)&(iface->ciaddr))[1],
			((unsigned char *)&(iface->ciaddr))[2], ((unsigned char *)&(iface->ciaddr))[3]);
	}
#endif

	/* Successfull ACK: Use the fields obtained for future requests */
	memcpy (&(iface->siaddr), iface->dhcp_options.val[dhcpServerIdentifier], 4);
	memcpy (iface->shaddr, msg->ethhdr.ether_shost, ETH_ALEN);
	free (msg);

	return RET_DHCP_BOUND;
}
/*****************************************************************************/
#if 0
int dhcp_bound(dhcp_interface *iface)
{
	int i;

	i = iface->req_sent_time + ntohl(*(unsigned int *)(iface->dhcp_options.val[dhcpT1value])) - time (NULL);
	if ( i > 0 )
		alarm(i);
	else
		return STATE_DHCP_RENEW;
	sleep (ntohl(*(u_int *)(iface->dhcp_options.val[dhcpT1value])));

	return STATE_DHCP_RENEW;
}
#endif
/*****************************************************************************/
int dhcp_renew(dhcp_interface *iface)
{
	udpipMessage	*msg = NULL;
	int			 err;

	/* DHCP state RENEW: request renewal of our lease from the original DHCP server */

#if 0
	i = iface->req_sent_time + ntohl(*(unsigned int *)(iface->dhcp_options.val[dhcpT2value])) - time(NULL);
#endif

	if (!iface) return RET_DHCP_ERROR;

	if ( DebugFlag )
	{
		syslog (LOG_INFO,"Sending DHCP_REQUEST for %u.%u.%u.%u to %u.%u.%u.%u\n",
			((unsigned char *)&(iface->ciaddr))[0], ((unsigned char *)&(iface->ciaddr))[1],
			((unsigned char *)&(iface->ciaddr))[2], ((unsigned char *)&(iface->ciaddr))[3],
			((unsigned char *)&(iface->siaddr))[0], ((unsigned char *)&(iface->siaddr))[1],
			((unsigned char *)&(iface->siaddr))[2], ((unsigned char *)&(iface->siaddr))[3]);
	}

	iface->xid = random();
	err = dhcpSendAndRecv (iface, DHCP_ACK, &buildDhcpRenew, &msg);
	if (err != RET_DHCP_SUCCESS);
		return err;

	iface->req_sent_time = time (NULL);

	if ( DebugFlag )
	{
		dhcpMessage	*dhcp_msg = (dhcpMessage *)&(msg->udpipmsg[sizeof(udpiphdr)]);
		syslog (LOG_INFO, "DHCP_ACK received from %s (%u.%u.%u.%u)\n", dhcp_msg->sname,
				((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[0],
				((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[1],
				((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[2],
				((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[3]);
	}
	free (msg);

	return RET_DHCP_BOUND;
}
/*****************************************************************************/
int dhcp_rebind(dhcp_interface *iface)
{
	udpipMessage	*msg = NULL;
	int			 err;

	/* DHCP state REBIND: request renewal of our lease from _any_ DHCP server */

#if 0
	i = iface->req_sent_time + ntohl(*(unsigned int *)(iface->dhcp_options.val[dhcpIPaddrLeaseTime])) - time(NULL);
#endif

	if (!iface) return RET_DHCP_ERROR;

	if ( DebugFlag )
	{
		syslog (LOG_INFO,"Broadcasting DHCP_REQUEST for %u.%u.%u.%u\n",
			((unsigned char *)&(iface->ciaddr))[0],
			((unsigned char *)&(iface->ciaddr))[1],
			((unsigned char *)&(iface->ciaddr))[2],
			((unsigned char *)&(iface->ciaddr))[3]);
	}

	iface->xid = random ();
	err = dhcpSendAndRecv(iface, DHCP_ACK, &buildDhcpRebind, &msg);
	if (err != RET_DHCP_SUCCESS)
		return err;

	iface->req_sent_time = time (NULL);

	if ( DebugFlag )
	{
		dhcpMessage	*dhcp_msg = (dhcpMessage *)&(msg->udpipmsg[sizeof(udpiphdr)]);
		syslog (LOG_INFO, "DHCP_ACK received from %s (%u.%u.%u.%u)\n", dhcp_msg->sname,
				((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[0],
				((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[1],
				((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[2],
				((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[3]);
	}

	/* Successfull ACK: Use the fields obtained for future requests */
	memcpy (&(iface->siaddr), iface->dhcp_options.val[dhcpServerIdentifier], 4);
	memcpy (iface->shaddr, msg->ethhdr.ether_shost, ETH_ALEN);
	free (msg);

	return RET_DHCP_BOUND;
}
/*****************************************************************************/
int dhcp_release(dhcp_interface *iface)
{
	struct sockaddr addr;
	udpipMessage	*msg;

	if ( iface->ciaddr == 0 )
		return RET_DHCP_ERROR;

	iface->xid = random();
	if (!(msg = buildDhcpRelease (iface)))
		return RET_DHCP_ERROR;

	if (DebugFlag)
	{
		syslog (LOG_INFO, "Sending DHCP_RELEASE for %u.%u.%u.%u to %u.%u.%u.%u\n",
			((unsigned char *)&(iface->ciaddr))[0], ((unsigned char *)&(iface->ciaddr))[1],
			((unsigned char *)&(iface->ciaddr))[2], ((unsigned char *)&(iface->ciaddr))[3],
			((unsigned char *)&(iface->siaddr))[0], ((unsigned char *)&(iface->siaddr))[1],
			((unsigned char *)&(iface->siaddr))[2], ((unsigned char *)&(iface->siaddr))[3]);
	}

	memset (&addr, 0, sizeof(struct sockaddr));
	memcpy (addr.sa_data, iface->iface, strlen (iface->iface));
	if ( sendto (iface->sk, msg, sizeof(struct packed_ether_header) + sizeof(udpiphdr) + sizeof(dhcpMessage), 0, &addr, sizeof(struct sockaddr)) == -1 )
		syslog (LOG_ERR, "dhcpRelease: sendto: %m\n");
	free (msg);

	arpRelease (iface); /* clear ARP cache entries for client IP addr */
	iface->ciaddr = 0;

	return RET_DHCP_SUCCESS;
}
/*****************************************************************************/
#ifdef ARPCHECK
int dhcp_decline(dhcp_interface *iface)
{
	udpipMessage *msg;
	struct sockaddr addr;

	iface->xid = random ();
	if (!(msg = buildDhcpDecline (iface)))
		return  RET_DHCP_ERROR;

	memset (&addr, 0, sizeof(struct sockaddr));
	memcpy (addr.sa_data, iface->iface, strlen (iface->iface));
	if ( DebugFlag )
		syslog (LOG_INFO, "Broadcasting DHCP_DECLINE\n");

	if ( sendto (iface->sk, msg, sizeof(struct packed_ether_header) + sizeof(udpiphdr)+sizeof(dhcpMessage), 0, &addr, sizeof(struct sockaddr)) == -1 )
		syslog (LOG_ERR,"dhcpDecline: sendto: %m\n");
	free (msg);

	return RET_DHCP_SUCCESS;
}
#endif
/*****************************************************************************/
int dhcp_inform(dhcp_interface *iface)
{
	udpipMessage	*msg = NULL;
	int			 err;

	if ( DebugFlag )
	{
		syslog (LOG_INFO, "Broadcasting DHCP_INFORM for %u.%u.%u.%u\n",
			((unsigned char *)&(iface->ciaddr))[0],
			((unsigned char *)&(iface->ciaddr))[1],
			((unsigned char *)&(iface->ciaddr))[2],
			((unsigned char *)&(iface->ciaddr))[3]);
	}

	iface->xid = random ();
	err = dhcpSendAndRecv (iface, DHCP_ACK, buildDhcpInform, &msg);
	if (err != RET_DHCP_SUCCESS)
		return err;

	if ( DebugFlag )
	{
		dhcpMessage	*dhcp_msg = (dhcpMessage *)&(msg->udpipmsg[sizeof(udpiphdr)]);
		syslog (LOG_INFO, "DHCP_ACK received from %s (%u.%u.%u.%u)\n", dhcp_msg->sname,
			((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[0],
			((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[1],
			((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[2],
			((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[3]);
	}
	free (msg);

#ifdef ARPCHECK
	/* check if the offered IP address already in use */
	if ( arpCheck(iface) )
	{
		if ( DebugFlag )
			syslog (LOG_INFO, "Requested %u.%u.%u.%u address is in use\n",
				((unsigned char *)&(iface->ciaddr))[0], ((unsigned char *)&(iface->ciaddr))[1],
				((unsigned char *)&(iface->ciaddr))[2], ((unsigned char *)&(iface->ciaddr))[3]);
		dhcpDecline (iface);
		return RET_DHCP_SUCCESS;
	}
	if ( DebugFlag )
	{
		syslog (LOG_INFO, "Verified %u.%u.%u.%u address is not in use\n",
			((unsigned char *)&(iface->ciaddr))[0], ((unsigned char *)&(iface->ciaddr))[1],
			((unsigned char *)&(iface->ciaddr))[2], ((unsigned char *)&(iface->ciaddr))[3]);
	}
#endif

	return RET_DHCP_SUCCESS;
}

/*****************************************************************************/
char *get_dhcp_option_name (int i)
{
	char *buf = NULL;
	if (i <= dhcpClientIdentifier)
		buf = strdup (dhcp_opt_table [i].name);
	else	
		buf = strdup ("unknown");
	return buf;
}

/*****************************************************************************/
void debug_dump_dhcp_options (udpipMessage *udp_msg, dhcpOptions *options)
{
	int i,j;
	dhcpMessage *dhcp_msg = (dhcpMessage *)&(udp_msg->udpipmsg[sizeof(udpiphdr)]);

	syslog (LOG_INFO, "parseDhcpMsgRecv: %d options received:\n", options->num);
	for (i = 1; i < 255; i++)
	{
		if ( options->val[i] )
		{
			switch ( i )
			{
				case 1: /* subnet mask */
				case 3: /* routers on subnet */
				case 4: /* time servers */
				case 5: /* name servers */
				case 6: /* dns servers */
				case 28:/* broadcast addr */
				case 33:/* staticRoute */
				case 41:/* NIS servers */
				case 42:/* NTP servers */
				case 50:/* dhcpRequestdIPaddr */
				case 54:/* dhcpServerIdentifier */
					for (j = 0; j < options->len[i]; j += 4)
					{
						char *opt_name = get_dhcp_option_name (i);
						syslog (LOG_INFO, "i=%-2d (%s)  len=%-2d  option = %u.%u.%u.%u\n",
								i, opt_name, options->len[i],
								((unsigned char *)options->val[i])[0+j],
								((unsigned char *)options->val[i])[1+j],
								((unsigned char *)options->val[i])[2+j],
								((unsigned char *)options->val[i])[3+j]);
						free (opt_name);
					}
					break;
				case 2: /* time offset */
				case 51:/* dhcpAddrLeaseTime */
				case 57:/* dhcpMaxMsgSize */
				case 58:/* dhcpT1value */
				case 59:/* dhcpT2value */
					{
						char *opt_name = get_dhcp_option_name (i);
						syslog (LOG_INFO, "i=%-2d (%s)  len=%-2d  option = %d\n", i, opt_name,
							options->len[i], ntohl(*(int *)options->val[i]));
						free (opt_name);
					}
					break;
				case 23:/* defaultIPTTL */
				case 29:/* performMaskdiscovery */
				case 31:/* performRouterdiscovery */
				case 53:/* dhcpMessageType */
					{
						char *opt_name = get_dhcp_option_name (i);
						syslog (LOG_INFO, "i=%-2d (%s)  len=%-2d  option = %u\n", i, opt_name,
							options->len[i],*(unsigned char *)options->val[i]);
						free (opt_name);
					}
					break;
				default:
					{
						char *opt_name = get_dhcp_option_name (i);
						syslog (LOG_INFO, "i=%-2d (%s)  len=%-2d  option = \"%s\"\n",
							i, opt_name, options->len[i], (char *)options->val[i]);
						free (opt_name);
					}
					break;
			}
		}
	}

	syslog (LOG_INFO, "dhcp_msg->yiaddr  = %u.%u.%u.%u\n"
				"dhcp_msg->siaddr  = %u.%u.%u.%u\n"
				"dhcp_msg->giaddr  = %u.%u.%u.%u\n"
				"dhcp_msg->sname   = \"%s\"\n"
				"ServerHardwareAddr   = %02X.%02X.%02X.%02X.%02X.%02X\n",
				((unsigned char *)&dhcp_msg->yiaddr)[0], ((unsigned char *)&dhcp_msg->yiaddr)[1],
				((unsigned char *)&dhcp_msg->yiaddr)[2], ((unsigned char *)&dhcp_msg->yiaddr)[3],
				((unsigned char *)&dhcp_msg->siaddr)[0], ((unsigned char *)&dhcp_msg->siaddr)[1],
				((unsigned char *)&dhcp_msg->siaddr)[2], ((unsigned char *)&dhcp_msg->siaddr)[3],
				((unsigned char *)&dhcp_msg->giaddr)[0], ((unsigned char *)&dhcp_msg->giaddr)[1],
				((unsigned char *)&dhcp_msg->giaddr)[2], ((unsigned char *)&dhcp_msg->giaddr)[3],
				dhcp_msg->sname,
				udp_msg->ethhdr.ether_shost[0], udp_msg->ethhdr.ether_shost[1],
				udp_msg->ethhdr.ether_shost[2], udp_msg->ethhdr.ether_shost[3],
				udp_msg->ethhdr.ether_shost[4], udp_msg->ethhdr.ether_shost[5]);
}

