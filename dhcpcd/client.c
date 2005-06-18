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
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netpacket/packet.h>
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
#include "arp.h"
#include "udpipgen.h"

#ifdef DEBUG
int DebugFlag = 1;
#else
int DebugFlag = 0;
#endif

typedef struct dhcp_response_return
{
	unsigned int	server_ip_addr;
	char			server_hw_addr[ETH_ALEN];
	dhcpMessage	dhcp_msg;
} dhcp_response_return;


void debug_dump_dhcp_options (struct sockaddr_ll *saddr, dhcpMessage *dhcp_msg, dhcpOptions *options);

/*****************************************************************************/
int parse_dhcp_reply (struct iphdr *iphdr, struct sockaddr_ll *saddr, dhcpMessage *dhcp_msg, dhcpOptions *options)
{
	register u_char	*p = dhcp_msg->options+4;
	unsigned char		*end = dhcp_msg->options + sizeof (dhcp_msg->options);

	/* Force T1 and T2 to 0: either new values will be in message, or they
	   will need to be recalculated from lease time */
	if (options->val[dhcpT1value] && options->len[dhcpT1value] > 0)
		memset (options->val[dhcpT1value], 0, options->len[dhcpT1value]);
	if (options->val[dhcpT2value] && options->len[dhcpT2value] > 0)
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
				if (p[1])
				{
					if (options->len[*p] == p[1])
						memcpy (options->val[*p], p+2, p[1]);
					else
					{
						options->len[*p] = p[1];
						if (options->val[*p])
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
	debug_dump_dhcp_options (saddr, dhcp_msg, options);
#endif

#if 0
	if ( !dhcp_msg->yiaddr )
		dhcp_msg->yiaddr = DhcpMsgSend->ciaddr;
#endif

	if (!options->val[dhcpServerIdentifier]) /* did not get dhcpServerIdentifier */
	{
		/* make it the same as IP address of the sender */
		options->val[dhcpServerIdentifier] = malloc (4);
		memcpy (options->val[dhcpServerIdentifier], &(iphdr->saddr), 4);
		options->len[dhcpServerIdentifier] = 4;
		options->num++;
		if (DebugFlag)
			syslog (LOG_DEBUG, "Server ID option is missing in DHCP server response. Assuming %u.%u.%u.%u.\n",
				((unsigned char *)options->val[dhcpServerIdentifier])[0],
				((unsigned char *)options->val[dhcpServerIdentifier])[1],
				((unsigned char *)options->val[dhcpServerIdentifier])[2],
				((unsigned char *)options->val[dhcpServerIdentifier])[3]);
	}
	if (!options->val[dns]) /* did not get DNS */
	{
		/* make it the same as dhcpServerIdentifier */
		options->val[dns] = malloc (4);
		memcpy (options->val[dns], options->val[dhcpServerIdentifier], 4);
		options->len[dns] = 4;
		options->num++;
		if ( DebugFlag )
			syslog (LOG_DEBUG, "DNS Server option is missing in DHCP server response. Assuming %u.%u.%u.%u.\n",
				((unsigned char *)options->val[dns])[0], ((unsigned char *)options->val[dns])[1],
				((unsigned char *)options->val[dns])[2], ((unsigned char *)options->val[dns])[3]);
	}
	if (!options->val[subnetMask]) /* did not get subnetMask */
	{
		options->val[subnetMask] = malloc (4);
		((unsigned char *)options->val[subnetMask])[0] = 255;
		if (IN_CLASSA (ntohl (dhcp_msg->yiaddr)))
		{
			((unsigned char *)options->val[subnetMask])[1] = 0; /* class A */
			((unsigned char *)options->val[subnetMask])[2] = 0;
			((unsigned char *)options->val[subnetMask])[3] = 0;
		}
		else
		{
			((unsigned char *)options->val[subnetMask])[1] = 255;
			if (IN_CLASSB (ntohl (dhcp_msg->yiaddr)))
			{
				((unsigned char *)(options->val[subnetMask]))[2] = 0;/* class B */
				((unsigned char *)(options->val[subnetMask]))[3] = 0;
			}
			else
			{
				((unsigned char *)options->val[subnetMask])[2] = 255;
				if (IN_CLASSC (ntohl (dhcp_msg->yiaddr)))
					((unsigned char *)options->val[subnetMask])[3] = 0; /* class C */
				else
					((unsigned char *)options->val[subnetMask])[3] = 255;
			}
		}
		options->len[subnetMask] = 4;
		options->num++;
		if (DebugFlag)
			syslog (LOG_DEBUG, "Subnet Mask option is missing in DHCP server response. Assuming %u.%u.%u.%u.\n",
				((unsigned char *)options->val[subnetMask])[0], ((unsigned char *)options->val[subnetMask])[1],
				((unsigned char *)options->val[subnetMask])[2], ((unsigned char *)options->val[subnetMask])[3]);
	}
	if (!options->val[broadcastAddr]) /* did not get broadcastAddr */
	{
		int br = dhcp_msg->yiaddr | ~*((int *)options->val[subnetMask]);
		options->val[broadcastAddr] = malloc (4);
		memcpy (options->val[broadcastAddr], &br, 4);
		options->len[broadcastAddr] = 4;
		options->num++;
		if (DebugFlag)
			syslog(LOG_DEBUG, "Broadcast Address option is missing in DHCP server response. Assuming %u.%u.%u.%u.\n",
				((unsigned char *)options->val[broadcastAddr])[0], ((unsigned char *)options->val[broadcastAddr])[1],
				((unsigned char *)options->val[broadcastAddr])[2], ((unsigned char *)options->val[broadcastAddr])[3]);
	}
	if (!options->val[routersOnSubnet])
	{
		options->val[routersOnSubnet] = malloc (4);
		if (options->val[dhcpServerIdentifier])
			memcpy (options->val[routersOnSubnet], options->val[dhcpServerIdentifier], 4);
		else
			memcpy (options->val[routersOnSubnet], &dhcp_msg->giaddr, 4);
		options->len[routersOnSubnet] = 4;
		options->num++;
		if (DebugFlag)
			syslog (LOG_DEBUG, "Routers option is missing in DHCP server response.  Assuming %u.%u.%u.%u (DHCP server).\n",
				((unsigned char *)options->val[routersOnSubnet])[0], ((unsigned char *)options->val[routersOnSubnet])[1],
				((unsigned char *)options->val[routersOnSubnet])[2], ((unsigned char *)options->val[routersOnSubnet])[3]);
	}

	if (options->val[dhcpIPaddrLeaseTime] && options->len[dhcpIPaddrLeaseTime] == 4)
	{
		if ( *(unsigned int *)options->val[dhcpIPaddrLeaseTime] == 0 )
		{
			unsigned int	lease_time = htonl (DHCP_DEFAULT_LEASETIME);
			memcpy (options->val[dhcpIPaddrLeaseTime], &lease_time, 4);
			if (DebugFlag)
				syslog (LOG_DEBUG, "Lease Time = 0 in DHCP server response. Assuming %us.\n", lease_time);
		}
		else
		{
			if (DebugFlag)
				syslog (LOG_DEBUG, "Lease Time = %u in DHCP server response.\n",
					ntohl (*(unsigned int *)options->val[dhcpIPaddrLeaseTime]));
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
			syslog (LOG_DEBUG, "Lease Time option is missing in DHCP server response. Assuming %us.\n", lease_time);
	}

	if (options->val[dhcpT1value] && options->len[dhcpT1value] == 4)
	{
		if (*(unsigned int *)options->val[dhcpT1value] == 0)
		{
			unsigned t2 = 0.5 * ntohl (*(unsigned int *)options->val[dhcpIPaddrLeaseTime]);
			int t1 = htonl (t2);
			memcpy (options->val[dhcpT1value],&t1,4);
			options->len[dhcpT1value] = 4;
			if (DebugFlag)
				syslog (LOG_DEBUG, "Renewal Time (T1) is missing in DHCP server response. Assuming %us.\n", t2);
		}
	}
	else		/* did not get T1 */
	{
		unsigned t2 = 0.5 * ntohl (*(unsigned int *)options->val[dhcpIPaddrLeaseTime]);
		int t1 = htonl (t2);
		options->val[dhcpT1value] = malloc(4);
		memcpy (options->val[dhcpT1value],&t1,4);
		options->len[dhcpT1value] = 4;
		options->num++;
		if (DebugFlag)
			syslog (LOG_DEBUG, "Renewal Time (T1) is missing in DHCP server response. Assuming %us.\n", t2);
	}

	if (options->val[dhcpT2value] && options->len[dhcpT2value] == 4)
	{
		if (*(unsigned int *)options->val[dhcpT2value] == 0)
		{
			unsigned t2 = 0.875 * ntohl (*(unsigned int *)options->val[dhcpIPaddrLeaseTime]);
			int t1 = htonl (t2);
			memcpy (options->val[dhcpT2value],&t1,4);
			options->len[dhcpT2value] = 4;
			if (DebugFlag)
				syslog (LOG_DEBUG, "Rebind Time (T2) is missing in DHCP server response. Assuming %us.\n", t2);
		}
	}
	else		/* did not get T2 */
	{
		unsigned t2 = 0.875 * ntohl (*(unsigned int *)options->val[dhcpIPaddrLeaseTime]);
		int t1 = htonl (t2);
		options->val[dhcpT2value] = malloc(4);
		memcpy (options->val[dhcpT2value],&t1,4);
		options->len[dhcpT2value] = 4;
		options->num++;
		if (DebugFlag)
			syslog (LOG_DEBUG, "Rebind Time (T2) is missing in DHCP server response. Assuming %us.\n", t2);
	}
	if (options->val[dhcpMessageType])
		return *(unsigned char *)options->val[dhcpMessageType];
	return -1;
}
/*****************************************************************************/
void class_id_setup (dhcp_interface *iface, const char *g_cls_id)
{
	unsigned int	 g_cls_id_len = 0;

	if (!iface) return;

	iface->cls_id_len = 0;
	memset (iface->cls_id, 0, DHCP_CLASS_ID_MAX_LEN);

	if (g_cls_id)
		g_cls_id_len = strlen (g_cls_id);

	if (g_cls_id_len)
	{
		memcpy (iface->cls_id, g_cls_id, g_cls_id_len);
		iface->cls_id_len = g_cls_id_len;
	}
}
/*****************************************************************************/
void client_id_setup (dhcp_interface *iface, const char *g_cli_id)
{
	unsigned int	 g_cli_id_len = 0;
	char			*c;

	if (!iface) return;

	iface->cli_id_len = 0;
	memset (iface->cli_id, 0, DHCP_CLIENT_ID_MAX_LEN);
	c = iface->cli_id;

	if (g_cli_id)
		g_cli_id_len = strlen (g_cli_id);

	if ( g_cli_id_len )
	{
		*c++ = 0;			     /* type: string */
		memcpy (c, g_cli_id, g_cli_id_len);
		iface->cli_id_len = g_cli_id_len + 1;
	}
}
/*****************************************************************************/
void release_dhcp_options (dhcp_interface *iface)
{
	register int i;
	for ( i = 1; i < 256; i++ )
	{
		if ( iface->dhcp_options.val[i] )
			free(iface->dhcp_options.val[i]);
	}

	memset (&(iface->dhcp_options), 0, sizeof (dhcpOptions));
}
/*****************************************************************************/
/* Subtract the `struct timeval' values X and Y,
   storing the result in RESULT.
   Return 1 if the difference is negative, otherwise 0.  */
static int timeval_subtract (struct timeval *result, struct timeval *x, struct timeval *y)
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
/* Ripped from pump.
 */
int verify_checksum(void * buf, int length, void * buf2, int length2)
{
	unsigned int csum;
	unsigned short * sp;

	csum = 0;
	for (sp = (unsigned short *) buf; length > 0; (length -= 2), sp++)
		csum += *sp;

	/* this matches rfc 1071, but not Steven's */
	if (length)
		csum += *((unsigned char *) sp);

	for (sp = (unsigned short *) buf2; length2 > 0; (length2 -= 2), sp++)
		csum += *sp;

	/* this matches rfc 1071, but not Steven's */
	if (length)
		csum += *((unsigned char *) sp);

	while (csum >> 16)
		csum = (csum & 0xffff) + (csum >> 16);

	if (csum!=0x0000 && csum != 0xffff)
		return 0;

	return 1;
}
/*****************************************************************************/
/* "timeout" should be the future point in time when we wish to stop
 * checking for data on the socket.
 */
int peekfd (dhcp_interface *iface, int sk, int min_data, struct timeval *end_time)
{
	struct timeval diff;
	struct timeval now;
	int recv_data_len = 0;
	char ethPacket[ETH_FRAME_LEN];

	if (min_data < 1)
		return RET_DHCP_ERROR;

	/* Wake up each second to check whether or not we've been told
	 * to stop with iface->cease and check our end time.
	 */
	gettimeofday (&now, NULL);
/*	syslog (LOG_INFO, "DHCP waiting for data, overall end_time = {%ds, %dus}\n", (int)end_time->tv_sec, (int)end_time->tv_usec);*/
	while ((timeval_subtract (&diff, end_time, &now) == 0) && !iface->cease && (recv_data_len < min_data))
	{
		fd_set fs;
		struct timeval wait = {1, 0};
/*		syslog (LOG_INFO, "DHCP waiting for data of minimum size %d, remaining timeout = {%ds, %dus}\n", min_data, (int)diff.tv_sec, (int)diff.tv_usec);*/

		FD_ZERO (&fs);
		FD_SET (sk, &fs);

		if (select (sk+1, &fs, NULL, NULL, &wait) == -1)
			return RET_DHCP_ERROR;
		if (FD_ISSET(sk, &fs))
		{
			/* Get length of data waiting on the socket */
			recv_data_len = recvfrom (sk, ethPacket, sizeof (ethPacket), MSG_DONTWAIT | MSG_PEEK, 0, NULL);
			if ((recv_data_len == -1) && (errno != EAGAIN))
				return RET_DHCP_ERROR;		/* Return on fatal errors */
		}
		gettimeofday (&now, NULL);
	};

	if (iface->cease)
		return RET_DHCP_CEASED;
	else if (recv_data_len >= min_data)
		return RET_DHCP_SUCCESS;

	return RET_DHCP_TIMEOUT;
}
/*****************************************************************************/
int dhcp_handle_transaction (dhcp_interface *iface, unsigned int expected_reply_type,
				dhcp_msg_build_proc build_dhcp_msg, dhcp_response_return *dhcp_return)
{
	char				*pkt_recv = NULL;
	int				recv_sk = -1;
	struct sockaddr_in	addr;
	int				tries = 0;
	int				err = RET_DHCP_TIMEOUT;
	struct timeval		recv_end, overall_end, diff, current;
	udpipMessage		*udp_send = NULL;

	if (!dhcp_return)
		return RET_DHCP_ERROR;
	memset (dhcp_return, 0, sizeof (dhcp_response_return));

	pkt_recv = malloc (sizeof (char) * ETH_FRAME_LEN);
	if (!pkt_recv)
		return RET_DHCP_ERROR;

	recv_sk = socket (AF_PACKET, SOCK_DGRAM, ntohs (ETH_P_IP));
	if (recv_sk < 0)
	{
		err = RET_DHCP_ERROR;
		goto out;
	}

	/* Setup the time in the future to quit doing DHCP stuff.  If we reach this time,
	 * we return RET_DHCP_TIMEOUT.
	 */
	gettimeofday (&overall_end, NULL);

	/* Send the request, then wait for the reply for a certain period of time
	 * that increases with each failed request.  Quit when we reach our end time though.
	 */
#ifdef DEBUG
	syslog (LOG_INFO, "DHCP: Starting request loop, overall start_time = {%lds, %ldus}\n",
		(long)overall_end.tv_sec, (long)overall_end.tv_usec);
#endif
	overall_end.tv_sec += iface->client_options->base_timeout;
	do
	{
		udpipMessage		*udp_msg_recv = NULL;
		struct iphdr		*ip_hdr = NULL;
		struct udphdr		*udp_hdr;
		char				*tmp_ip;
		dhcpMessage		*dhcp_msg_recv = NULL;
		int				 reply_type = -1;
		char				 foobuf[512];
		struct sockaddr_ll	 server_hw_addr;
		int				 data_good = 0;
		int				 min_data_len = (sizeof (struct iphdr) + sizeof (struct udphdr));
		int				 int_err = RET_DHCP_TIMEOUT;

		if (iface->cease)
			goto out;

		/* Send the DHCP request */
		do
		{
			int				 udp_send_len = 0;
			struct sockaddr	 addr;

			/* Call the specific DHCP message building routine for this request */
			if (!(udp_send = build_dhcp_msg (iface, &udp_send_len)))
			{
				err = RET_DHCP_ERROR;
				goto out;
			}

			memset (&addr, 0, sizeof (struct sockaddr));
			memcpy (addr.sa_data, iface->iface, strlen (iface->iface));
			int_err = sendto (iface->sk, udp_send, udp_send_len, MSG_DONTWAIT, (struct sockaddr *)&addr, sizeof (struct sockaddr));
			if (iface->cease || ((int_err == -1) && (errno != EAGAIN)))
			{
			#ifdef DEBUG
				syslog (LOG_INFO, "DHCP: error sending, cease = %d, err = %d, errno = %d", iface->cease, int_err, errno);
			#endif
				err = iface->cease ? RET_DHCP_CEASED : RET_DHCP_ERROR;
				goto out;
			}

			/* Return if we've exceeded our timeout */
			gettimeofday (&current, NULL);
			if (timeval_subtract (&diff, &overall_end, &current) != 0)
			{
				err = RET_DHCP_TIMEOUT;
				goto out;
			}
		} while ((int_err == -1) && (errno == EAGAIN));

		/* Set up the future time at which point to stop waiting for data
		 * on our socket and try the request again.  If that future point is
		 * later than our overall DHCP operation timeout (overall_end) then
		 * clamp the receive timeout to overall_end.
		 */
		tries++;
		gettimeofday (&recv_end, NULL);
		recv_end.tv_sec += (tries * DHCP_INITIAL_RTO);
		recv_end.tv_usec += (random () % 200000);
		/* Clamp recv_end to overall_end if its greater than overall_end */
		if (timeval_subtract (&diff, &overall_end, &recv_end) != 0)
			memcpy (&recv_end, &overall_end, sizeof (struct timeval));

	#ifdef DEBUG
		syslog (LOG_INFO, "DHCP: Request sent, waiting for reply...");
	#endif

		/* Packet receive loop */
		data_good = 0;
		gettimeofday (&current, NULL);
		while ((timeval_subtract (&diff, &recv_end, &current) == 0) && !data_good)
		{
			int		len;
			int		o;
			char		ethPacket[ETH_FRAME_LEN];

			/* Wait for some kind of data to appear on the socket */
			if ((int_err = peekfd (iface, recv_sk, min_data_len, &recv_end)) != RET_DHCP_SUCCESS)
			{
				if (int_err == RET_DHCP_TIMEOUT)
					break;
				goto out;
			}

			gettimeofday (&current, NULL);

			/* Ok, we allegedly have the data we need, so grab it from the queue */
			o = sizeof (struct sockaddr_ll);
			len = recvfrom (recv_sk, pkt_recv, ETH_FRAME_LEN, 0, (struct sockaddr *)&server_hw_addr, &o);
		#ifdef DEBUG
			syslog (LOG_INFO, "DHCP: Got some data of length %d.", len);
		#endif
			if (len < (sizeof (struct iphdr) + sizeof (struct udphdr)))
			{
				#ifdef DEBUG
					syslog (LOG_INFO, "DHCP: Data length failed minimum length check (should be %d, got %d)", (sizeof (struct iphdr) + sizeof (struct udphdr)), len);
				#endif
				continue;
			}

			ip_hdr = (struct iphdr *) pkt_recv;
			if (!verify_checksum (NULL, 0, ip_hdr, sizeof (struct iphdr)))
			{
				#ifdef DEBUG
					syslog (LOG_INFO, "DHCP: Reply message had bad IP checksum, won't use it.");
				#endif
				continue;
			}

			if (ntohs (ip_hdr->tot_len) > len)
			{
				#ifdef DEBUG
					syslog (LOG_INFO, "DHCP: Reply message had mismatch in length (IP header said %d, packet was really %d), won't use it.", ntohs (ip_hdr->tot_len), len);
				#endif
				continue;
			}
			len = ntohs (ip_hdr->tot_len);

			if (ip_hdr->protocol != IPPROTO_UDP)
			{
				#ifdef DEBUG
					syslog (LOG_INFO, "DHCP: Reply message was not UDP (ip_hdr->protocol = %d, IPPROTO_UDP = %d), won't use it.", ip_hdr->protocol, IPPROTO_UDP);
				#endif
				continue;
			}

			udp_hdr = (struct udphdr *) (pkt_recv + sizeof (struct iphdr));
			if (ntohs (udp_hdr->source) != DHCP_SERVER_PORT)
			{
				#ifdef DEBUG
					syslog (LOG_INFO, "DHCP: Reply message's source port (%d) was not the DHCP server port number (%d), won't use it.", ntohs (udp_hdr->source), DHCP_SERVER_PORT);
				#endif
				continue;
			}
			if (ntohs (udp_hdr->dest) != DHCP_CLIENT_PORT) 
			{
				#ifdef DEBUG
					syslog (LOG_INFO, "DHCP: Reply message's destination port (%d) was not the DHCP client port number (%d), won't use it.", ntohs (udp_hdr->dest), DHCP_CLIENT_PORT);
				#endif
				continue;
			}

			/* Ok, packet appears to be OK */
			/* Ensure DHCP packet is 0xFF terminated, which isn't the case on Cisco 800 series ISDN router */
			dhcp_msg_recv = malloc (sizeof (dhcpMessage));
			memset (dhcp_msg_recv, 0xFF, sizeof (dhcpMessage));
			memcpy (dhcp_msg_recv, (char *) udp_hdr + sizeof (struct udphdr), len - sizeof (struct iphdr) - sizeof (struct udphdr));

			if (dhcp_msg_recv->xid != iface->xid)
			{
				#ifdef DEBUG
					syslog (LOG_INFO, "DHCP: Reply message's XID does not match expected XID (message %d, expected %d), won't use it.", dhcp_msg_recv->xid, iface->xid);
				#endif
				free (dhcp_msg_recv);
				continue;
			}

			if (dhcp_msg_recv->htype != ARPHRD_ETHER)
			{
				#ifdef DEBUG
					if (DebugFlag)
						syslog (LOG_DEBUG, "DHCP: Reply message's header type was not ARPHRD_ETHER (messgae %d, expected %d), won't use it.", dhcp_msg_recv->htype, ARPHRD_ETHER);
				#endif
				free (dhcp_msg_recv);
				continue;
			}

			if (dhcp_msg_recv->op != DHCP_BOOTREPLY)
			{
				#ifdef DEBUG
					syslog (LOG_INFO, "DHCP: Reply message was not a bootp/DHCP reply, won't use it.");
				#endif
				free (dhcp_msg_recv);
				continue;
			}

			data_good = 1;
		}

		if (!data_good)
			continue;

		/* Clear out all data remaining on the interface in preparation for another broadcast if needed */
		while ((iface->foo_sk > 0) && recvfrom (iface->foo_sk, (void *)foobuf, sizeof (foobuf), 0, NULL, NULL) != -1);

		/* Copy DHCP response options from received packet into local options list */
		reply_type = parse_dhcp_reply (ip_hdr, &server_hw_addr, dhcp_msg_recv, &(iface->dhcp_options));
		if (expected_reply_type == reply_type)
		{
			memcpy (&dhcp_return->server_ip_addr, &(ip_hdr->saddr), 4);
			memcpy (&dhcp_return->server_hw_addr, &server_hw_addr, ETH_ALEN);
			memcpy (&dhcp_return->dhcp_msg, dhcp_msg_recv, sizeof (dhcpMessage));
			free (dhcp_msg_recv);
			err = RET_DHCP_SUCCESS;
			goto out;
		}
		free (dhcp_msg_recv);

		if (reply_type == DHCP_NAK)
		{
			#ifdef DEBUG
				if (iface->dhcp_options.val[dhcpMsg])
					syslog (LOG_ERR, "DHCP: DHCP_NAK response received: %s.", (char *)iface->dhcp_options.val[dhcpMsg]);
				else
					syslog (LOG_ERR, "DHCP: DHCP_NAK response received.");
			#endif
			err = RET_DHCP_NAK;
			goto out;
		}
		gettimeofday (&current, NULL);
	} while (timeval_subtract (&diff, &overall_end, &current) == 0);

out:
	free (udp_send);
	if (err != RET_DHCP_SUCCESS)
		free (pkt_recv);
	if (recv_sk >= 0)
		close (recv_sk);
	if (iface->cease)
		err = RET_DHCP_CEASED;
	return err;
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

	release_dhcp_options (iface);
	return dhcp_request (iface, &build_dhcp_reboot);
}
/*****************************************************************************/
int dhcp_init (dhcp_interface *iface)
{
	dhcp_response_return	dhcp_resp;
	int					err;

	if (!iface) return RET_DHCP_ERROR;

	release_dhcp_options (iface);

#ifdef DEBUG
	if (iface->cls_id_len)
		syslog (LOG_DEBUG, "ClassID  = \"%s\"",  iface->cls_id);
	if (iface->cli_id_len)
		syslog (LOG_DEBUG, "ClientID = \"%u.%u.%u.%02X.%02X.%02X.%02X.%02X.%02X\"\n",
			iface->cli_id[0], iface->cli_id[1], iface->cli_id[2],
			iface->cli_id[3], iface->cli_id[4], iface->cli_id[5],
			iface->cli_id[6], iface->cli_id[7], iface->cli_id[8]);
#endif

	if ( DebugFlag )
		syslog (LOG_INFO, "Broadcasting DHCP_DISCOVER\n");
	iface->xid = random ();
	err = dhcp_handle_transaction (iface, DHCP_OFFER, &build_dhcp_discover, &dhcp_resp);
	if (err != RET_DHCP_SUCCESS)
		return err;

	if (iface->client_options->send_second_discover)
	{
		dhcp_response_return	dhcp_resp2;

		if (DebugFlag)
			syslog (LOG_INFO, "Broadcasting second DHCP_DISCOVER\n");

		iface->xid = dhcp_resp.dhcp_msg.xid;
		err = dhcp_handle_transaction (iface, DHCP_OFFER, &build_dhcp_discover, &dhcp_resp2);
		if (err == RET_DHCP_SUCCESS)
			memcpy (&dhcp_resp, &dhcp_resp2, sizeof (dhcp_response_return));
		else if (err == RET_DHCP_CEASED)
			return err;
	}

	iface->ciaddr = dhcp_resp.dhcp_msg.yiaddr;
	memcpy (&(iface->siaddr), iface->dhcp_options.val[dhcpServerIdentifier], 4);
	memcpy (iface->shaddr, dhcp_resp.server_hw_addr, ETH_ALEN);
	iface->xid = dhcp_resp.dhcp_msg.xid;

	/* DHCP_OFFER received */
	if (DebugFlag)
	{
		syslog (LOG_INFO, "DHCP_OFFER received from %s (%u.%u.%u.%u)\n", dhcp_resp.dhcp_msg.sname,
			((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[0],
			((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[1],
			((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[2],
			((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[3]);
	}

	return dhcp_request (iface, &build_dhcp_request);
}
/*****************************************************************************/
int dhcp_request(dhcp_interface *iface, dhcp_msg_build_proc buildDhcpMsg)
{
	dhcp_response_return	dhcp_resp;
	int					err;

	/* DHCP state REQUEST: request an address from a _particular_ DHCP server */

	if (!iface) return RET_DHCP_ERROR;

	if (DebugFlag)
	{
		syslog (LOG_INFO, "Broadcasting DHCP_REQUEST for %u.%u.%u.%u\n",
			((unsigned char *)&(iface->ciaddr))[0], ((unsigned char *)&(iface->ciaddr))[1],
			((unsigned char *)&(iface->ciaddr))[2], ((unsigned char *)&(iface->ciaddr))[3]);
	}

	err = dhcp_handle_transaction (iface, DHCP_ACK, buildDhcpMsg, &dhcp_resp);
	if (err != RET_DHCP_SUCCESS)
		return err;

	if (DebugFlag)
	{
		syslog (LOG_INFO, "DHCP_ACK received from %s (%u.%u.%u.%u)\n", dhcp_resp.dhcp_msg.sname,
			((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[0],
			((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[1],
			((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[2],
			((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[3]);
	}

#ifdef ARPCHECK
	/* check if the offered IP address already in use */
	if (arpCheck(iface))
	{
		if (DebugFlag)
			syslog (LOG_INFO, "requested %u.%u.%u.%u address is in use\n",
				((unsigned char *)&(iface->ciaddr))[0], ((unsigned char *)&(iface->ciaddr))[1],
				((unsigned char *)&(iface->ciaddr))[2], ((unsigned char *)&(iface->ciaddr))[3]);
		dhcpDecline ();
		iface->ciaddr = 0;
		return iface->cease ? RET_DHCP_CEASED : RET_DHCP_ADDRESS_IN_USE;
	}

	if (DebugFlag)
	{
		syslog (LOG_INFO, "verified %u.%u.%u.%u address is not in use\n",
			((unsigned char *)&(iface->ciaddr))[0], ((unsigned char *)&(iface->ciaddr))[1],
			((unsigned char *)&(iface->ciaddr))[2], ((unsigned char *)&(iface->ciaddr))[3]);
	}
#endif

	/* Successfull ACK: Use the fields obtained for future requests */
	memcpy (&(iface->siaddr), iface->dhcp_options.val[dhcpServerIdentifier], 4);
	memcpy (iface->shaddr, dhcp_resp.server_hw_addr, ETH_ALEN);

	return iface->cease ? RET_DHCP_CEASED : RET_DHCP_BOUND;
}
/*****************************************************************************/
int dhcp_renew(dhcp_interface *iface)
{
	dhcp_response_return	dhcp_resp;
	int					err;

	/* DHCP state RENEW: request renewal of our lease from the original DHCP server */
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
	err = dhcp_handle_transaction (iface, DHCP_ACK, &build_dhcp_renew, &dhcp_resp);
	if (err != RET_DHCP_SUCCESS);
		return err;

	if (DebugFlag)
	{
		syslog (LOG_INFO, "DHCP_ACK received from %s (%u.%u.%u.%u)\n", dhcp_resp.dhcp_msg.sname,
				((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[0],
				((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[1],
				((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[2],
				((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[3]);
	}

	return RET_DHCP_BOUND;
}
/*****************************************************************************/
int dhcp_rebind(dhcp_interface *iface)
{
	dhcp_response_return	dhcp_resp;
	int					err;

	/* DHCP state REBIND: request renewal of our lease from _any_ DHCP server */
	if (!iface) return RET_DHCP_ERROR;

	if (DebugFlag)
	{
		syslog (LOG_INFO,"Broadcasting DHCP_REQUEST for %u.%u.%u.%u\n",
			((unsigned char *)&(iface->ciaddr))[0],
			((unsigned char *)&(iface->ciaddr))[1],
			((unsigned char *)&(iface->ciaddr))[2],
			((unsigned char *)&(iface->ciaddr))[3]);
	}

	iface->xid = random ();
	err = dhcp_handle_transaction(iface, DHCP_ACK, &build_dhcp_rebind, &dhcp_resp);
	if (err != RET_DHCP_SUCCESS)
		return err;

	if (DebugFlag)
	{
		syslog (LOG_INFO, "DHCP_ACK received from %s (%u.%u.%u.%u)\n", dhcp_resp.dhcp_msg.sname,
				((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[0],
				((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[1],
				((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[2],
				((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[3]);
	}

	/* Successfull ACK: Use the fields obtained for future requests */
	memcpy (&(iface->siaddr), iface->dhcp_options.val[dhcpServerIdentifier], 4);
	memcpy (iface->shaddr, dhcp_resp.server_hw_addr, ETH_ALEN);

	return RET_DHCP_BOUND;
}
/*****************************************************************************/
int dhcp_release(dhcp_interface *iface)
{
	udpipMessage	*msg;
	struct sockaddr addr;
	socklen_t		addr_len = sizeof (struct sockaddr);
	int			len;

	if ( iface->ciaddr == 0 )
		return RET_DHCP_ERROR;

	iface->xid = random();
	if (!(msg = build_dhcp_release (iface, &len)))
		return RET_DHCP_ERROR;

	if (DebugFlag)
	{
		syslog (LOG_INFO, "Sending DHCP_RELEASE for %u.%u.%u.%u to %u.%u.%u.%u\n",
			((unsigned char *)&(iface->ciaddr))[0], ((unsigned char *)&(iface->ciaddr))[1],
			((unsigned char *)&(iface->ciaddr))[2], ((unsigned char *)&(iface->ciaddr))[3],
			((unsigned char *)&(iface->siaddr))[0], ((unsigned char *)&(iface->siaddr))[1],
			((unsigned char *)&(iface->siaddr))[2], ((unsigned char *)&(iface->siaddr))[3]);
	}

	memset (&addr, 0, sizeof (struct sockaddr));
	memcpy (addr.sa_data, iface->iface, strlen (iface->iface));
	if (sendto (iface->sk, msg, len, 0, (struct sockaddr *)&addr, addr_len))
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
	udpipMessage	*msg;
	struct sockaddr addr;
	socklen_t		addr_len = sizeof (struct sockaddr);
	int			len;

	iface->xid = random ();
	if (!(msg = build_dhcp_decline (iface, &len)))
		return  RET_DHCP_ERROR;

	if (DebugFlag)
		syslog (LOG_INFO, "Broadcasting DHCP_DECLINE\n");

	memset (&addr, 0, sizeof (struct sockaddr));
	memcpy (addr.sa_data, iface->iface, strlen (iface->iface));
	if (sendto (iface->sk, msg, len, 0, &addr, addr_len))
		syslog (LOG_ERR,"dhcpDecline: sendto: %m\n");
	free (msg);

	return RET_DHCP_SUCCESS;
}
#endif
/*****************************************************************************/
int dhcp_inform(dhcp_interface *iface)
{
	dhcp_response_return	dhcp_resp;
	int					err;

	if (DebugFlag)
	{
		syslog (LOG_INFO, "Broadcasting DHCP_INFORM for %u.%u.%u.%u\n",
			((unsigned char *)&(iface->ciaddr))[0], ((unsigned char *)&(iface->ciaddr))[1],
			((unsigned char *)&(iface->ciaddr))[2], ((unsigned char *)&(iface->ciaddr))[3]);
	}

	iface->xid = random ();
	err = dhcp_handle_transaction (iface, DHCP_ACK, build_dhcp_inform, &dhcp_resp);
	if (err != RET_DHCP_SUCCESS)
		return err;

	if (DebugFlag)
	{
		syslog (LOG_INFO, "DHCP_ACK received from %s (%u.%u.%u.%u)\n", dhcp_resp.dhcp_msg.sname,
			((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[0],
			((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[1],
			((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[2],
			((unsigned char *)(iface->dhcp_options.val[dhcpServerIdentifier]))[3]);
	}

#ifdef ARPCHECK
	/* check if the offered IP address already in use */
	if (arpCheck(iface))
	{
		if (DebugFlag)
			syslog (LOG_INFO, "Requested %u.%u.%u.%u address is in use\n",
				((unsigned char *)&(iface->ciaddr))[0], ((unsigned char *)&(iface->ciaddr))[1],
				((unsigned char *)&(iface->ciaddr))[2], ((unsigned char *)&(iface->ciaddr))[3]);
		dhcpDecline (iface);
		return RET_DHCP_SUCCESS;
	}
	if (DebugFlag)
	{
		syslog (LOG_INFO, "Verified %u.%u.%u.%u address is not in use\n",
			((unsigned char *)&(iface->ciaddr))[0], ((unsigned char *)&(iface->ciaddr))[1],
			((unsigned char *)&(iface->ciaddr))[2], ((unsigned char *)&(iface->ciaddr))[3]);
	}
#endif

	return RET_DHCP_SUCCESS;
}

#ifdef DEBUG

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
void debug_dump_dhcp_options (struct sockaddr_ll *saddr, dhcpMessage *dhcp_msg, dhcpOptions *options)
{
	int i,j;

	syslog (LOG_INFO, "Server replied with %d DHCP options:\n", options->num);
	for (i = 1; i < 255; i++)
	{
		if (options->val[i])
		{
			switch (i)
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
						syslog (LOG_INFO, "\t%s (%d):\t%u.%u.%u.%u\n",
								opt_name, i,
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
						syslog (LOG_INFO, "\t%s (%d):\t%d\n", opt_name, i,
							ntohl(*(int *)options->val[i]));
						free (opt_name);
					}
					break;
				case 23:/* defaultIPTTL */
				case 29:/* performMaskdiscovery */
				case 31:/* performRouterdiscovery */
				case 53:/* dhcpMessageType */
					{
						char *opt_name = get_dhcp_option_name (i);
						syslog (LOG_INFO, "\t%s (%d):\t%u\n", opt_name, i,
							*(unsigned char *)options->val[i]);
						free (opt_name);
					}
					break;
				default:
					{
						char *opt_name = get_dhcp_option_name (i);
						syslog (LOG_INFO, "\t%s (%d):\t\"%s\"\n",
							opt_name, i, (char *)options->val[i]);
						free (opt_name);
					}
					break;
			}
		}
	}

	syslog (LOG_INFO, "\tYour IP Address:\t%u.%u.%u.%u",
				((unsigned char *)&dhcp_msg->yiaddr)[0], ((unsigned char *)&dhcp_msg->yiaddr)[1],
				((unsigned char *)&dhcp_msg->yiaddr)[2], ((unsigned char *)&dhcp_msg->yiaddr)[3]);
	syslog (LOG_INFO, "\tDHCP Server Address:\t%u.%u.%u.%u (HW=%02X:%02X:%02X:%02X:%02X:%02X)",
				((unsigned char *)&dhcp_msg->siaddr)[0], ((unsigned char *)&dhcp_msg->siaddr)[1],
				((unsigned char *)&dhcp_msg->siaddr)[2], ((unsigned char *)&dhcp_msg->siaddr)[3],
				saddr->sll_addr[0], saddr->sll_addr[1], saddr->sll_addr[2], saddr->sll_addr[3],
				saddr->sll_addr[4], saddr->sll_addr[5]);
	if (((unsigned char *)&dhcp_msg->giaddr)[0] != 0)
		syslog (LOG_INFO, "\tGateway Address:\t%u.%u.%u.%u",
				((unsigned char *)&dhcp_msg->giaddr)[0], ((unsigned char *)&dhcp_msg->giaddr)[1],
				((unsigned char *)&dhcp_msg->giaddr)[2], ((unsigned char *)&dhcp_msg->giaddr)[3]);
	if (dhcp_msg->sname && strlen (dhcp_msg->sname))
		syslog (LOG_INFO, "\tServer Name:\t\"%s\"", dhcp_msg->sname);
}

#endif
