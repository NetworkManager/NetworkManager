/* NetworkManager -- Network link manager
 *
 * Dan Williams <dcbw@redhat.com>
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
 * Copyright (C) 2004 Red Hat, Inc.
 * Copyright (C) 1996 - 1997 Yoichi Hariguchi <yoichi@fore.com>
 * Copyright (C) January, 1998 Sergei Viznyuk <sv@phystech.com>
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <net/route.h>
#include <arpa/nameser.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <resolv.h>
#include <netdb.h>
#include <glib.h>
#include "NetworkManagerSystem.h"
#include "NetworkManagerDevice.h"
#include "nm-utils.h"

static int nm_system_open_sock (void)
{
	int	fd;

	/* Try to grab a control socket */
	fd = socket (AF_PACKET, SOCK_PACKET, htons (ETH_P_ALL));
	if (fd >= 0)
	     return (fd);

	nm_warning ("nm_system_open_sock() could not get network control socket.");
	return (-1);
}


gboolean nm_system_device_set_ip4_address (NMDevice *dev, int ip4_address)
{
	struct ifreq		 ifr;
	const char		*iface;
	int				 sk;
	gboolean			 success = FALSE;
	struct sockaddr_in	*p = (struct sockaddr_in *)&(ifr.ifr_addr);

	g_return_val_if_fail (dev != NULL, FALSE);

	iface = nm_device_get_iface (dev);
	sk = nm_system_open_sock ();
	if (sk < 0)
		return FALSE;

	memset (&ifr, 0, sizeof(struct ifreq));
	memcpy (ifr.ifr_name, iface, strlen (iface));
	p->sin_family = AF_INET;
	p->sin_addr.s_addr = ip4_address;
	if (ioctl (sk, SIOCSIFADDR, &ifr) == -1)
		nm_warning ("nm_system_device_set_ip4_address (%s): failed to set IPv4 address!", iface);
	else
	{
		success = TRUE;
		nm_info ("Your IP address = %u.%u.%u.%u",
				((unsigned char *)&ip4_address)[0], ((unsigned char *)&ip4_address)[1],
				((unsigned char *)&ip4_address)[2], ((unsigned char *)&ip4_address)[3]);
	}

	close (sk);
	return (success);
}


gboolean nm_system_device_set_ip4_netmask (NMDevice *dev, int ip4_netmask)
{
	struct ifreq		 ifr;
	const char		*iface;
	int				 sk;
	gboolean			 success = FALSE;
	struct sockaddr_in	*p = (struct sockaddr_in *)&(ifr.ifr_addr);

	g_return_val_if_fail (dev != NULL, FALSE);

	iface = nm_device_get_iface (dev);
	sk = nm_system_open_sock ();
	if (sk < 0)
		return FALSE;

	memset (&ifr, 0, sizeof(struct ifreq));
	memcpy (ifr.ifr_name, iface, strlen (iface));
	p->sin_family = AF_INET;
	p->sin_addr.s_addr = ip4_netmask;
	if (ioctl (sk, SIOCSIFNETMASK, &ifr) == -1)
		nm_warning ("nm_system_device_set_ip4_netmask (%s): failed to set IPv4 netmask! errno = %s", iface, strerror (errno));
	else
		success = TRUE;

	close (sk);
	return (success);
}


gboolean nm_system_device_set_ip4_broadcast (NMDevice *dev, int ip4_broadcast)
{
	struct ifreq		 ifr;
	const char		*iface;
	int				 sk;
	gboolean			 success = FALSE;
	struct sockaddr_in	*p = (struct sockaddr_in *)&(ifr.ifr_addr);

	g_return_val_if_fail (dev != NULL, FALSE);

	iface = nm_device_get_iface (dev);
	sk = nm_system_open_sock ();
	if (sk < 0)
		return FALSE;

	memset (&ifr, 0, sizeof(struct ifreq));
	memcpy (ifr.ifr_name, iface, strlen (iface));
	p->sin_family = AF_INET;
	p->sin_addr.s_addr = ip4_broadcast;
	if (ioctl (sk, SIOCSIFBRDADDR, &ifr) == -1)
		nm_warning ("nm_system_device_set_ip4_netmask (%s): failed to set IPv4 netmask!", iface);
	else
		success = TRUE;

	close (sk);
	return (success);
}


gboolean nm_system_device_set_ip4_default_route (NMDevice *dev, int ip4_def_route)
{
	const char		*iface;
	int				 sk;
	gboolean			 success = FALSE;
	struct rtentry		 rtent;
	struct sockaddr_in	*p;

	g_return_val_if_fail (dev != NULL, FALSE);

	iface = nm_device_get_iface (dev);
	sk = nm_system_open_sock ();
	if (sk < 0)
		return FALSE;

	memset (&rtent, 0, sizeof (struct rtentry));
	p				= (struct sockaddr_in *)&rtent.rt_dst;
	p->sin_family		= AF_INET;
	p->sin_addr.s_addr	= 0;
	p				= (struct sockaddr_in *)&rtent.rt_gateway;
	p->sin_family		= AF_INET;
	p->sin_addr.s_addr	= ip4_def_route;
	p				= (struct sockaddr_in *)&rtent.rt_genmask;
	p->sin_family		= AF_INET;
	p->sin_addr.s_addr	= 0;
	rtent.rt_dev		= (char *)iface;
	rtent.rt_metric	= 1;
	rtent.rt_window	= 0;
	rtent.rt_flags		= RTF_UP | RTF_GATEWAY | ( rtent.rt_window ? RTF_WINDOW : 0);

	if (ioctl (sk, SIOCADDRT, &rtent) == -1)
	{
		if (errno == ENETUNREACH)  /* possibly gateway is over the bridge */
		{                            /* try adding a route to gateway first */
			struct	rtentry		rtent2;
			
			memset (&rtent2, 0, sizeof(struct rtentry));
			p				= (struct sockaddr_in *)&rtent2.rt_dst;
			p->sin_family		= AF_INET;
			p				= (struct sockaddr_in *)&rtent2.rt_gateway;
			p->sin_family		= AF_INET;
			p->sin_addr.s_addr	= ip4_def_route;
			p				= (struct sockaddr_in *)&rtent2.rt_genmask;
			p->sin_family		= AF_INET;
			p->sin_addr.s_addr	= 0xffffffff;
			rtent2.rt_dev		= (char *)iface;
			rtent2.rt_metric	= 0;
			rtent2.rt_flags	= RTF_UP | RTF_HOST;

			if ( ioctl (sk, SIOCADDRT, &rtent2) == 0 )
			{
				if ( ioctl (sk, SIOCADDRT, &rtent) == 0 )
					success = TRUE;
				else
					nm_warning ("nm_system_device_set_ip4_default_route (%s): failed to set IPv4 default route! errno = %d", iface, errno);
			}
		}
		else
			nm_warning ("nm_system_device_set_ip4_default_route (%s): failed to set IPv4 default route! errno = %d", iface, errno);
	}
	else
		success = TRUE;

	close (sk);
	return (success);
}

