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
#include "NetworkManagerUtils.h"

gboolean nm_system_device_set_ip4_address (NMDevice *dev, int ip4_address)
{
	struct ifreq		 ifr;
	const char		*iface;
	NMSock			*sk;
	gboolean			 success = FALSE;
	struct sockaddr_in	*p = (struct sockaddr_in *)&(ifr.ifr_addr);

	g_return_val_if_fail (dev != NULL, FALSE);

	if ((sk = nm_dev_sock_open (dev, NETWORK_CONTROL, __FUNCTION__, NULL)) == NULL)
		return FALSE;

	memset (&ifr, 0, sizeof(struct ifreq));

	iface = nm_device_get_iface (dev);
	memcpy (ifr.ifr_name, iface, strlen (iface));
	p->sin_family = AF_INET;
	p->sin_addr.s_addr = ip4_address;
	if (ioctl (nm_dev_sock_get_fd (sk), SIOCSIFADDR, &ifr) == -1)
		syslog (LOG_ERR,"nm_system_device_set_ip4_address (%s): failed to set IPv4 address!", iface);
	else
	{
		success = TRUE;
		syslog (LOG_INFO, "Your IP address = %u.%u.%u.%u\n",
				((unsigned char *)&ip4_address)[0], ((unsigned char *)&ip4_address)[1],
				((unsigned char *)&ip4_address)[2], ((unsigned char *)&ip4_address)[3]);
	}

	nm_dev_sock_close (sk);
	return (success);
}


gboolean nm_system_device_set_ip4_netmask (NMDevice *dev, int ip4_netmask)
{
	struct ifreq		 ifr;
	const char		*iface;
	NMSock			*sk;
	gboolean			 success = FALSE;
	struct sockaddr_in	*p = (struct sockaddr_in *)&(ifr.ifr_addr);

	g_return_val_if_fail (dev != NULL, FALSE);

	if ((sk = nm_dev_sock_open (dev, NETWORK_CONTROL, __FUNCTION__, NULL)) == NULL)
		return FALSE;

	memset (&ifr, 0, sizeof(struct ifreq));

	iface = nm_device_get_iface (dev);
	memcpy (ifr.ifr_name, iface, strlen (iface));
	p->sin_family = AF_INET;
	p->sin_addr.s_addr = ip4_netmask;
	if (ioctl (nm_dev_sock_get_fd (sk), SIOCSIFNETMASK, &ifr) == -1)
		syslog (LOG_ERR,"nm_system_device_set_ip4_netmask (%s): failed to set IPv4 netmask! errno = %s", iface, strerror (errno));
	else
		success = TRUE;

	nm_dev_sock_close (sk);
	return (success);
}


gboolean nm_system_device_set_ip4_broadcast (NMDevice *dev, int ip4_broadcast)
{
	struct ifreq		 ifr;
	const char		*iface;
	NMSock			*sk;
	gboolean			 success = FALSE;
	struct sockaddr_in	*p = (struct sockaddr_in *)&(ifr.ifr_addr);

	g_return_val_if_fail (dev != NULL, FALSE);

	if ((sk = nm_dev_sock_open (dev, NETWORK_CONTROL, __FUNCTION__, NULL)) == NULL)
		return FALSE;

	memset (&ifr, 0, sizeof(struct ifreq));
	iface = nm_device_get_iface (dev);
	memcpy (ifr.ifr_name, iface, strlen (iface));
	p->sin_family = AF_INET;
	p->sin_addr.s_addr = ip4_broadcast;
	if (ioctl (nm_dev_sock_get_fd (sk), SIOCSIFBRDADDR, &ifr) == -1)
		syslog (LOG_ERR,"nm_system_device_set_ip4_netmask (%s): failed to set IPv4 broadcast address!", iface);
	else
		success = TRUE;

	nm_dev_sock_close (sk);
	return (success);
}


gboolean nm_system_device_set_ip4_default_route (NMDevice *dev, int ip4_def_route)
{
	const char		*iface;
	NMSock			*sk;
	gboolean			 success = FALSE;
	struct rtentry		 rtent;
	struct sockaddr_in	*p;

	g_return_val_if_fail (dev != NULL, FALSE);

	if ((sk = nm_dev_sock_open (dev, NETWORK_CONTROL, __FUNCTION__, NULL)) == NULL)
		return FALSE;

	iface = nm_device_get_iface (dev);

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

	if (ioctl (nm_dev_sock_get_fd (sk), SIOCADDRT, &rtent) == -1)
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

			if (ioctl (nm_dev_sock_get_fd (sk), SIOCADDRT, &rtent2) == 0 )
			{
				if (ioctl (nm_dev_sock_get_fd (sk), SIOCADDRT, &rtent) == 0 )
					success = TRUE;
				else
					syslog (LOG_ERR,"nm_system_device_set_ip4_default_route (%s): failed to set IPv4 default route! errno = %d", iface, errno);
			}
		}
		else
			syslog (LOG_ERR,"nm_system_device_set_ip4_default_route (%s): failed to set IPv4 default route! errno = %d", iface, errno);
	}
	else
		success = TRUE;

	nm_dev_sock_close (sk);
	return (success);
}


gboolean nm_system_device_add_ip4_nameserver (NMDevice *dev, guint32 ip4_nameserver)
{
	gboolean success = FALSE;
	char *nameserver;
	GError *error = NULL;
	NMData *data;
	guint id;

	g_return_val_if_fail (dev != NULL, FALSE);
	data = nm_device_get_app_data (dev);
	g_return_val_if_fail (data != NULL, FALSE);

	nameserver = g_strdup_printf ("%u.%u.%u.%u",
				      ((unsigned char *)&ip4_nameserver)[0],
				      ((unsigned char *)&ip4_nameserver)[1],
				      ((unsigned char *)&ip4_nameserver)[2],
				      ((unsigned char *)&ip4_nameserver)[3]);
	syslog (LOG_WARNING, "Adding nameserver: %s", nameserver);

	if ((id = nm_named_manager_add_nameserver_ipv4 (data->named, nameserver, &error)))
	{
		data->nameserver_ids = g_list_prepend (data->nameserver_ids, GUINT_TO_POINTER (id));
		success = TRUE;
	}
	else
	{
		syslog (LOG_WARNING, "Couldn't add nameserver: %s\n", error->message);
		g_clear_error (&error);
	}
	g_free (nameserver);

	return success;
}


void nm_system_device_clear_ip4_nameservers (NMDevice *dev)
{
	GList *elt;
	GError *error = NULL;
	NMData *data;

	g_return_if_fail (dev != NULL);
	data = nm_device_get_app_data (dev);
	g_return_if_fail (data != NULL);

	/* Reset our nameserver list */
	for (elt = data->nameserver_ids; elt; elt = elt->next)
	{
		if (!nm_named_manager_remove_nameserver_ipv4 (data->named,
							      GPOINTER_TO_UINT (elt->data),
							      &error))
		{
			syslog (LOG_WARNING, "Couldn't remove nameserver: %s", error->message);
			g_clear_error (&error);
		}
	}
	g_list_free (data->nameserver_ids);
	data->nameserver_ids = NULL;
	
}


gboolean nm_system_device_add_domain_search (NMDevice *dev, const char *search)
{
	gboolean success = FALSE;
	guint id;
	GError *error = NULL;
	NMData *data;

	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (search != NULL, FALSE);
	g_return_val_if_fail (strlen (search) >= 0, FALSE);

	data = nm_device_get_app_data (dev);
	g_return_val_if_fail (data != NULL, FALSE);

	syslog (LOG_WARNING, "Adding domain search: %s\n", search);
	if ((id = nm_named_manager_add_domain_search (data->named, search, &error)))
	{
		data->domain_search_ids = g_list_append (data->domain_search_ids, GUINT_TO_POINTER (id));
		success = TRUE;
	}
	else
	{
		syslog (LOG_WARNING, "Couldn't add domain search '%s': %s\n", search, error->message);
		g_clear_error (&error);
	}

	return success;
}

void nm_system_device_clear_domain_searches (NMDevice *dev)
{
	GError *error = NULL;
	GList *elt;
	NMData *data;

	g_return_if_fail (dev != NULL);
	data = nm_device_get_app_data (dev);
	g_return_if_fail (data != NULL);

	/* Reset our domain search list */
	for (elt = data->domain_search_ids; elt; elt = elt->next)
	{
		if (!nm_named_manager_remove_domain_search (data->named,
							    GPOINTER_TO_UINT (elt->data),
							    &error))
		{
			syslog (LOG_WARNING, "Couldn't remove domain search: %s\n", error->message);
			g_clear_error (&error);
		}
	}
	g_list_free (data->domain_search_ids);
	data->domain_search_ids = NULL;
}

