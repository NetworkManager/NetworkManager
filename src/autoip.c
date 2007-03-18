// Based upon http://www.zeroconf.org/AVH-IPv4LL.c
// Merged into NetworkManager by Tom Parker <palfrey@tevp.net>
// Original copyright continues below
// 
// ----------------------------------
// Simple IPv4 Link-Local addressing (see <http://www.zeroconf.org/>)
// @(#)llip.c, 1.5, Copyright 2003 by Arthur van Hoff (avh@strangeberry.com)
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
// See <http://www.gnu.org/copyleft/lesser.html>
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/poll.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <syslog.h>
#include <glib.h>
#include <unistd.h>
#include "NetworkManager.h"
#include "nm-device.h"
#include "nm-device-802-3-ethernet.h"
#include "nm-device-802-11-wireless.h"
#include "NetworkManagerMain.h"
#include "NetworkManagerUtils.h"
#include "nm-utils.h"
#include "autoip.h"

// Times here are in seconds
#define LINKLOCAL_ADDR		0xa9fe0000
#define LINKLOCAL_BCAST		0xa9feffff
#define PROBE_NUM			3
#define PROBE_MIN			1
#define PROBE_MAX			2
#define ANNOUNCE_NUM		3
#define ANNOUNCE_INTERVAL	2
#define ANNOUNCE_WAIT		2

#define FAILURE_TIMEOUT		14


typedef struct EtherHeader
{
	u_int8_t	ether_dhost[ETH_ALEN];      /* destination eth addr */
	u_int8_t	ether_shost[ETH_ALEN];      /* source ether addr    */
	u_int16_t	ether_type;                 /* packet type ID field */
} __attribute__((packed)) EtherHeader;


typedef struct ARPMessage
{
	EtherHeader	ethhdr;
	u_short		htype;			/* hardware type (must be ARPHRD_ETHER) */
	u_short		ptype;			/* protocol type (must be ETHERTYPE_IP) */
	u_char		hlen;			/* hardware address length (must be 6) */
	u_char		plen;			/* protocol address length (must be 4) */
	u_short		operation;		/* ARP opcode */
	u_char		sHaddr[ETH_ALEN];	/* sender's hardware address */
	u_char		sInaddr[4];		/* sender's IP address */
	u_char		tHaddr[ETH_ALEN];	/* target's hardware address */
	u_char		tInaddr[4];		/* target's IP address */
	u_char		pad[18];			/* pad for min. Ethernet payload (60 bytes) */
} __attribute__((packed)) ARPMessage;


// Times here are in seconds
#define ARP_DEFAULT_LEASETIME	100

static struct in_addr null_ip = {0};
static struct ether_addr null_addr = {{0, 0, 0, 0, 0, 0}};
static struct ether_addr broadcast_addr = {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};

/**
 * Pick a random link local IP address.
 */
static void pick (struct in_addr *ip)
{
	ip->s_addr = htonl (LINKLOCAL_ADDR | ((abs(random()) % 0xFD00) + (abs(random()) % 0x0100)));

	/* Make sure we don't use 0xFF or 0x00 anywhere */
	while (((ip->s_addr & 0x0000FF00) == 0xFF00) || ((ip->s_addr & 0x0000FF00) == 0x0000))
		ip->s_addr = (ip->s_addr & 0xFFFF00FF) + (abs(random()) && 0xFFFF);

	while (((ip->s_addr & 0x000000FF) == 0xFF) || ((ip->s_addr & 0x000000FF) == 0x00))
		ip->s_addr = (ip->s_addr & 0xFFFFFF00) + (abs(random()) && 0xFF);
}

/**
 * Send out an ARP packet.
 */
static gboolean arp(int fd, struct sockaddr *saddr, int op,
                struct ether_addr *source_addr, struct in_addr source_ip,
                struct ether_addr *target_addr, struct in_addr target_ip)
{
	struct ARPMessage p;
	gboolean success = FALSE;

	memset (&p, 0, sizeof (p));

	/* ether header */
	p.ethhdr.ether_type = htons (ETHERTYPE_ARP);
	memcpy (p.ethhdr.ether_shost, source_addr, ETH_ALEN);
	memcpy (p.ethhdr.ether_dhost, &broadcast_addr, ETH_ALEN);

	/* arp request */
	p.htype = htons (ARPHRD_ETHER);
	p.ptype = htons (ETHERTYPE_IP);
	p.hlen = ETH_ALEN;
	p.plen = 4;
	p.operation = htons (op);
	memcpy (&p.sHaddr, source_addr, ETH_ALEN);
	memcpy (&p.sInaddr, &source_ip, sizeof (p.sInaddr));
	memcpy (&p.tHaddr, target_addr, ETH_ALEN);
	memcpy (&p.tInaddr, &target_ip, sizeof (p.tInaddr));

	/* send it */
	if (sendto (fd, &p, sizeof (p), 0, saddr, sizeof (*saddr)) < 0)
		nm_warning ("autoip ARP sendto() failed.");
	else
		success = TRUE;

	return success;
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

enum return_vals
{
	RET_ERROR = 0,
	RET_TIMEOUT,
	RET_CEASED,
	RET_SUCCESS
};

/*****************************************************************************/
/* "timeout" should be the future point in time when we wish to stop
 * checking for data on the socket.
 */
static int peekfd (NMDevice *dev, int sk, struct timeval *timeout)
{
	struct timeval diff;
	struct timeval now;

	/* Wake up each second to check whether or not we've been told
	 * to stop with iface->cease and check our timeout.
	 */
	gettimeofday (&now, NULL);
//	nm_info ("autoip waiting for data, overall timeout = {%ds, %dus}\n", (int)timeout->tv_sec, (int)timeout->tv_usec);
	while (timeval_subtract (&diff, timeout, &now) == 0)
	{
		fd_set fs;
		struct timeval wait = {1, 0};
//		nm_info ("autoip waiting for data, remaining timeout = {%ds, %dus}\n", (int)diff.tv_sec, (int)diff.tv_usec);

		FD_ZERO (&fs);
		FD_SET (sk, &fs);

		if (select (sk+1, &fs, NULL, NULL, &wait) == -1)
			return RET_ERROR;
		if (FD_ISSET(sk, &fs))
			return RET_SUCCESS;
		if (nm_device_activation_should_cancel (dev))
			return RET_CEASED;
		gettimeofday (&now, NULL);
	};
	return RET_TIMEOUT;
}


gboolean get_autoip (NMDevice *dev, struct in_addr *out_ip)
{
	struct sockaddr	saddr;
	ARPMessage		p;
	struct ether_addr	addr;
	struct in_addr		ip = {0};
	NMSock *			sk = NULL;
	int				nprobes = 0;
	int				nannounce = 0;
	gboolean			success = FALSE;

	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (out_ip != NULL, FALSE);

	out_ip->s_addr = 0;

	/* initialize saddr */
	memset (&saddr, 0, sizeof (saddr));
	strncpy (saddr.sa_data, nm_device_get_iface (dev), sizeof (saddr.sa_data));

	nm_device_get_hw_address (dev, &addr);

	/* open an ARP socket */
	if ((sk = nm_dev_sock_open (dev, NETWORK_CONTROL, __FUNCTION__, NULL)) == NULL)
	{
		nm_warning ("%s: Couldn't open network control socket.", nm_device_get_iface (dev));
		goto out;
	}

	/* bind to the ARP socket */
	if (bind (nm_dev_sock_get_fd (sk), &saddr, sizeof (saddr)) < 0)
	{
		nm_warning ("%s: Couldn't bind to the device.", nm_device_get_iface (dev));
		goto out;
	}

	/* initialize pseudo random selection of IP addresses */
	srandom ( (addr.ether_addr_octet[ETHER_ADDR_LEN-4] << 24) |
			(addr.ether_addr_octet[ETHER_ADDR_LEN-3] << 16) |
			(addr.ether_addr_octet[ETHER_ADDR_LEN-2] <<  8) |
			(addr.ether_addr_octet[ETHER_ADDR_LEN-1] <<  0));
    
	/* pick an ip address */
	if (ip.s_addr == 0)
		pick (&ip);

	while (1)
	{
		struct timeval	timeout;
		int			err;

		/* Make sure we haven't been told to quit */
		if (nm_device_activation_should_cancel (dev))
			goto out;

		if (nprobes < PROBE_NUM)
		{
			nm_info ("autoip: Sending probe #%d for IP address %s.", nprobes, inet_ntoa (ip));
			arp (nm_dev_sock_get_fd (sk), &saddr, ARPOP_REQUEST, &addr, null_ip, &null_addr, ip);
			nprobes++;
			gettimeofday (&timeout, NULL);
			if (nprobes == PROBE_NUM)
			{
				/* Link local specifies a different interval between
				 * the end of probe requests and announce packets.
				 */
				timeout.tv_sec += ANNOUNCE_WAIT;
			}
			else
			{
				unsigned int usecs_to_sleep = ((PROBE_MAX - PROBE_MIN) * 1000000) - 1;

				/* We want to sleep between PROBE_MIN and PROBE_MAX seconds, exclusive */
				timeout.tv_sec += PROBE_MIN;
				timeout.tv_usec += 1 + (random () % usecs_to_sleep);
			}
		}
		else if (nannounce < ANNOUNCE_NUM)
		{
			nm_info ("autoip: Sending announce #%d for IP address %s.", nannounce, inet_ntoa (ip));
			arp (nm_dev_sock_get_fd (sk), &saddr, ARPOP_REQUEST, &addr, ip, &addr, ip);
			nannounce++;
			gettimeofday (&timeout, NULL);
			timeout.tv_sec += ANNOUNCE_INTERVAL;
			timeout.tv_usec += (random () % 200000);
		}
		else
		{
			/* Use our address! */
			memcpy (out_ip, &ip, sizeof (ip));
			success = TRUE;
			goto out;
		}

		nm_info ("autoip: Waiting for reply...");
		err = peekfd (dev, nm_dev_sock_get_fd (sk), &timeout);
		if ((err == RET_ERROR) || (err == RET_CEASED))
			goto out;

		/* There's some data waiting for us */
		if (err == RET_SUCCESS)
		{
			nm_info ("autoip: Got some data to check for reply packet.");

			/* read ARP packet */
			if (recv (nm_dev_sock_get_fd (sk), &p, sizeof (p), 0) < 0)
			{
				nm_warning ("autoip: packet receive failure, ignoring it.");
				continue;
			}

		#ifdef ARP_DEBUG
			nm_warning ("autoip: (%s) recv arp type=%d, op=%d, ", nm_device_get_iface (dev), ntohs(p.ethhdr.ether_type), ntohs(p.operation));
			{
				struct in_addr a;
				memcpy (&(a.s_addr), &(p.sInaddr), sizeof (a.s_addr));
				nm_warning (" source = %s %02X:%02X:%02X:%02X:%02X:%02X, ", inet_ntoa (a),
					p.sHaddr[0], p.sHaddr[1], p.sHaddr[2], p.sHaddr[3], p.sHaddr[4], p.sHaddr[5]);
				memcpy (&(a.s_addr), &(p.tInaddr), sizeof (a.s_addr));
				nm_warning (" target = %s %02X:%02X:%02X:%02X:%02X:%02X\n", inet_ntoa (a),
					p.tHaddr[0], p.tHaddr[1], p.tHaddr[2], p.tHaddr[3], p.tHaddr[4], p.tHaddr[5]);
			}
		#endif

			if (    (ntohs (p.ethhdr.ether_type) == ETHERTYPE_ARP)
				&& (ntohs (p.operation) == ARPOP_REPLY)
				&& ((uint32_t)(*p.tInaddr) == ip.s_addr)
				&& (memcmp (&addr, &p.tHaddr, ETH_ALEN) != 0))
			{
			#ifdef ARP_DEBUG
				nm_warning ("autoip: (%s) ARP conflict for IP address %s.\n", nm_device_get_iface (dev), inet_ntoa(ip));
			#endif

				/* Ok, start all over again */
				pick (&ip);
				nprobes = 0;
				nannounce = 0;
			}
		}
	}

out:
	if (sk)
		nm_dev_sock_close (sk);
	return success;
}
