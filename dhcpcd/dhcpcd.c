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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if_packet.h>
#include <sys/ioctl.h>
#include <net/route.h>
#include <errno.h>
#include <ctype.h>
#include "dhcpcd.h"
#include "client.h"


/*
 * DHCP Client Daemon v1.3.22-pl4
 * Copyright (C) 1996 - 1997 Yoichi Hariguchi <yoichi@fore.com>
 * Copyright (C) January, 1998 Sergei Viznyuk <sv@phystech.com>
 * Location: http://www.phystech.com/download/
 */

extern void class_id_setup (dhcp_interface *iface, const char *g_cls_id);
extern void client_id_setup (dhcp_interface *iface, const char *g_cli_id);
extern void release_dhcp_options (dhcp_interface *iface);

/*****************************************************************************/
dhcp_interface *dhcp_interface_init (const char *if_name, dhcp_client_options *in_opts)
{
	int				o = 1;
	unsigned			i = 3;
	struct ifreq		ifr;
	struct sockaddr_in	addr;
	dhcp_interface		*iface = NULL;
	dhcp_client_options	*opts = NULL;
	struct rtentry		route;

	if (!if_name || !in_opts)
		return NULL;

	if (!(iface = calloc (1, sizeof (dhcp_interface))))
		return NULL;
	iface->iface = strdup (if_name);
	iface->default_lease_time = DHCP_DEFAULT_LEASETIME;
	iface->xid = random ();
	iface->sk = -1;
	iface->foo_sk = -1;

	if (!(opts = calloc (1, sizeof (dhcp_client_options))))
		goto err_out;
	memcpy (opts, in_opts, sizeof (dhcp_client_options));
	iface->client_options = opts;

	memset (&ifr, 0, sizeof(struct ifreq));
	memcpy (ifr.ifr_name, iface->iface, strlen (iface->iface));
	iface->sk = socket (AF_PACKET, SOCK_PACKET, htons(ETH_P_ALL));
	if (iface->sk == -1)
	{
		syslog (LOG_ERR,"dhcp_interface_init: socket: %m\n");
		goto err_out;
	}

	if (ioctl (iface->sk, SIOCGIFFLAGS, &ifr))
 	{  
		syslog (LOG_ERR, "dhcp_interface_init: ioctl SIOCGIFFLAGS: %m\n");  
		goto err_out;
	}
	iface->saved_if_flags = ifr.ifr_flags;

	/* Try to get a valid MAC address.  Sometimes when you bring a card up, especially ones
	 * with downloadable firmware, it takes a couple tries to get a valid MAC address
	 * since the firmware is busy for a bit doing who knows what.
	 */
	do
	{
		struct sockaddr_pkt	sap;
		struct sockaddr_in	*addrp;

		if ( ioctl (iface->sk, SIOCGIFHWADDR, &ifr) )
		{
			syslog(LOG_ERR,"dhcp_interface_init: ioctl SIOCGIFHWADDR: %m\n");
			goto err_out;
		}
		memcpy (iface->chaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

		if (setsockopt (iface->sk, SOL_SOCKET, SO_BROADCAST, &o, sizeof(o)) == -1)
		{
			syslog (LOG_ERR,"dhcp_interface_init: setsockopt (SO_BROADCAST): %m\n");
			goto err_out;
		}

		ifr.ifr_flags = iface->saved_if_flags | IFF_UP | IFF_BROADCAST | IFF_NOTRAILERS | IFF_RUNNING;
		if (ioctl (iface->sk, SIOCSIFFLAGS, &ifr))
		{
			syslog (LOG_ERR,"dhcp_interface_init: ioctl SIOCSIFFLAGS: %m");
			goto err_out;
		}

		memset (&ifr, 0, sizeof (ifr));
		addrp = (struct sockaddr_in *) &ifr.ifr_addr;
		strcpy (ifr.ifr_name, iface->iface);
		addrp->sin_family = AF_INET;
		addrp->sin_port = 0;
		memset (&addrp->sin_addr, 0, sizeof (addrp->sin_addr));
		addrp->sin_addr.s_addr = htonl (0);
		if (ioctl (iface->sk, SIOCSIFADDR, &ifr))
		{
			syslog (LOG_ERR, "dhcp_interface_init: SIOCSIFADDR returned errno %d", errno);
			goto err_out;
		}

		o = 1;
		if (setsockopt (iface->sk, SOL_SOCKET, SO_REUSEADDR, &o, sizeof(o)) == -1)
		{
			syslog (LOG_ERR,"dhcp_interface_init: setsockopt (SO_REUSEADDR): %m");
			goto err_out;
		}

		if (setsockopt (iface->sk, SOL_SOCKET, SO_BINDTODEVICE, iface->iface, strlen (iface->iface)+1))
		{
			syslog (LOG_ERR, "dhcp_interface_init: SO_BINDTODEVICE %s (%d) failed: %s", iface->iface, strlen (iface->iface), strerror (errno));
		}

		memset (&sap, 0, sizeof(sap));
		sap.spkt_protocol = htons (ETH_P_ALL);
		memcpy (sap.spkt_device, iface->iface, strlen (iface->iface));
		sap.spkt_family = AF_PACKET;
		if ( bind (iface->sk, (void*)&sap, sizeof(struct sockaddr)) == -1 )
			syslog (LOG_ERR,"dhcp_interface_init: bind: %m\n");

		if (ioctl (iface->sk, SIOCGIFHWADDR, &ifr))
		{
			syslog (LOG_ERR,"dhcp_interface_init: ioctl SIOCGIFHWADDR: %m");
			goto err_out;
		}

		memcpy (iface->chaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
		syslog (LOG_INFO, "dhcp_interface_init: MAC address = %02x:%02x:%02x:%02x:%02x:%02x\n",
			iface->chaddr[0], iface->chaddr[1], iface->chaddr[2], iface->chaddr[3], iface->chaddr[4], iface->chaddr[5]);
		i--;
	} while (iface->chaddr[0] && iface->chaddr[1] && iface->chaddr[2] && iface->chaddr[3] && iface->chaddr[4] && iface->chaddr[5] && (i > 0));

	iface->foo_sk = socket (AF_INET, SOCK_DGRAM, 0);
	if ( iface->foo_sk == -1 )
	{
		syslog (LOG_ERR,"dhcp_interface_init: socket: %m\n");
		goto err_out;
	}

	if (setsockopt (iface->foo_sk, SOL_SOCKET, SO_BROADCAST, &o, sizeof(o)))
		syslog (LOG_ERR,"dhcp_interface_init: setsockopt: %m\n");
	memset (&addr, 0, sizeof (addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons (DHCP_CLIENT_PORT);
	if ( bind (iface->foo_sk, (struct sockaddr *)&addr, sizeof(addr)) )
	{
		if (errno != EADDRINUSE)
			syslog (LOG_ERR,"dhcp_interface_init: bind: %m\n");
		close (iface->foo_sk);
		iface->foo_sk = -1;
	}
	else if (fcntl (iface->foo_sk, F_SETFL, O_NONBLOCK) == -1)
	{
		syslog (LOG_ERR,"dhcp_interface_init: fcntl: %m\n");
		goto err_out;
	}

	/* Set up at least the broadcast route or something */
	memset (&addr, 0, sizeof (addr));
	addr.sin_family = AF_INET;
	addr.sin_port = 0;

	memset (&route, 0, sizeof (route));
	memcpy (&route.rt_gateway, &addr, sizeof (addr));

	addr.sin_addr.s_addr = INADDR_ANY;
	memcpy (&route.rt_dst, &addr, sizeof(addr));
	memcpy (&route.rt_genmask, &addr, sizeof(addr));

	route.rt_dev = iface->iface;
	route.rt_flags = RTF_UP;
	route.rt_metric = 0;

	if (ioctl (iface->sk, SIOCADDRT, &route) && (errno != EEXIST))
	{
		syslog (LOG_ERR, "dhcp_interface_init: SIOCADDRT failed, errno = %d, dev = %s\n", errno, iface->iface);
		goto err_out;
	}

	i = time (NULL) + iface->chaddr[5] + 4*iface->chaddr[4] + 8*iface->chaddr[3] +
		16*iface->chaddr[2] + 32*iface->chaddr[1] + 64*iface->chaddr[0];
	srandom (i);
	iface->ip_id = i & 0xffff;

	class_id_setup (iface, iface->client_options->class_id);
	client_id_setup (iface, iface->client_options->client_id);

	return iface;

err_out:
	dhcp_interface_free (iface);
	return NULL;
}
/*****************************************************************************/
void dhcp_interface_free (dhcp_interface *iface)
{
	struct ifreq ifr;
	struct sockaddr_in	*p = (struct sockaddr_in *)&(ifr.ifr_addr);

	if (!iface)
		return;

	release_dhcp_options (iface);

	if (iface->foo_sk >= 0)
		close (iface->foo_sk);
	free (iface->iface);
	free (iface->client_options);
	free (iface);
}

/*****************************************************************************/
void dhcp_interface_cease (dhcp_interface *iface)
{
	if (!iface)
		return;

	iface->cease = 1;
}

/*****************************************************************************/
int dhcp_interface_dhcp_field_exists (dhcp_interface *iface, int val)
{
	if (!iface)	return 0;

	return (!!iface->dhcp_options.len[val]);
}

/*****************************************************************************/
void *dhcp_interface_get_dhcp_field (dhcp_interface *iface, int val)
{
	if (!iface)	return 0;

	return (iface->dhcp_options.val[val]);
}

/*****************************************************************************/
int dhcp_interface_get_dhcp_field_len (dhcp_interface *iface, int val)
{
	if (!iface)	return 0;

	return (iface->dhcp_options.len[val]);
}

/*****************************************************************************/
int dhcp_individual_value_len (int val)
{
	if (val <= dhcpClientIdentifier)
		return (dhcp_opt_table[val].len);
	else
		return -1;
}

