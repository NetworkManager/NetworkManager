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
#include <arpa/inet.h>
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
#include "nm-utils.h"



static gboolean nm_system_device_set_ip4_address					(NMDevice *dev, int ip4_address);
static gboolean nm_system_device_set_ip4_address_with_iface			(NMDevice *dev, const char *iface, int ip4_address);

static gboolean nm_system_device_set_ip4_ptp_address				(NMDevice *dev, int ip4_ptp_address);
static gboolean nm_system_device_set_ip4_ptp_address_with_iface		(NMDevice *dev, const char *iface, int ip4_ptp_address);

static gboolean nm_system_device_set_ip4_netmask					(NMDevice *dev, int ip4_netmask);
static gboolean nm_system_device_set_ip4_netmask_with_iface			(NMDevice *dev, const char *iface, int ip4_netmask);

static gboolean nm_system_device_set_ip4_broadcast				(NMDevice *dev, int ip4_broadcast);
static gboolean nm_system_device_set_ip4_broadcast_with_iface		(NMDevice *dev, const char *iface, int ip4_broadcast);

static gboolean nm_system_device_set_mtu					(NMDevice *dev, guint16 in_mtu);
static gboolean nm_system_device_set_mtu_with_iface				(NMDevice *dev, const char *iface, guint16 in_mtu);

static gboolean nm_system_device_set_ip4_route					(NMDevice *dev, int ip4_gateway, int ip4_dest, int ip4_netmask);
static gboolean nm_system_device_set_ip4_route_with_iface			(NMDevice *dev, const char *iface, int ip4_gateway, int ip4_dest, int ip4_netmask);


/*
 * nm_system_remove_ip4_config_nameservers
 *
 * Remove an IPv4 Config's nameservers from the name service.
 *
 */
void nm_system_remove_ip4_config_nameservers (NMNamedManager *named, NMIP4Config *config)
{
	GError *error = NULL;
	int	i, len;

	g_return_if_fail (config != NULL);

	len = nm_ip4_config_get_num_nameservers (config);
	for (i = 0; i < len; i++)
	{
		guint id = nm_ip4_config_get_nameserver_id (config, i);
		if ((id != 0) && !nm_named_manager_remove_nameserver_ipv4 (named, id, &error))
		{
			nm_warning ("Couldn't remove nameserver: %s", error->message);
			g_clear_error (&error);
		}
		else
			nm_ip4_config_set_nameserver_id (config, i, 0);
	}
}


static void set_nameservers (NMNamedManager *named, NMIP4Config *config)
{
	GError *error = NULL;
	int	i, len;

	g_return_if_fail (config != NULL);

	len = nm_ip4_config_get_num_nameservers (config);
	for (i = 0; i < len; i++)
	{
		guint		id;
		guint		ns_addr = nm_ip4_config_get_nameserver (config, i);
		struct in_addr	temp_addr;
		char *		nameserver;

		temp_addr.s_addr = ns_addr;
		nameserver = g_strdup (inet_ntoa (temp_addr));
		nm_info ("Adding nameserver: %s", nameserver);
		if ((id = nm_named_manager_add_nameserver_ipv4 (named, nameserver, &error)))
			nm_ip4_config_set_nameserver_id (config, i, id);
		else
		{
			nm_warning ("Couldn't add nameserver: %s", error->message);
			g_clear_error (&error);
		}
		g_free (nameserver);
	}
}


/*
 * nm_system_remove_ip4_config_search_domains
 *
 * Remove an IPv4 Config's search domains from the name service.
 *
 */
void nm_system_remove_ip4_config_search_domains (NMNamedManager *named, NMIP4Config *config)
{
	GError *error = NULL;
	int	i, len;

	g_return_if_fail (config != NULL);

	len = nm_ip4_config_get_num_domains (config);
	for (i = 0; i < len; i++)
	{
		guint id = nm_ip4_config_get_domain_id (config, i);
		if ((id != 0) && !nm_named_manager_remove_domain_search (named, id, &error))
		{
			nm_warning ("Couldn't remove domain search: %s", error->message);
			g_clear_error (&error);
		}
		else
			nm_ip4_config_set_domain_id (config, i, 0);
	}
}

static void set_search_domains (NMNamedManager *named, NMIP4Config *config)
{
	GError *error = NULL;
	int	i, len;

	g_return_if_fail (config != NULL);

	len = nm_ip4_config_get_num_domains (config);
	for (i = 0; i < len; i++)
	{
		const char *	domain = nm_ip4_config_get_domain (config, i);
		guint		id;

		nm_info ("Adding domain search: %s", domain);
		if ((id = nm_named_manager_add_domain_search (named, domain, &error)))
			nm_ip4_config_set_domain_id (config, i, id);
		else
		{
			nm_warning ("Couldn't add domain search: %s", error->message);
			g_clear_error (&error);
		}
	}
}


/*
 * nm_system_device_set_from_ip4_config
 *
 * Set IPv4 configuration of the device from an NMIP4Config object.
 *
 */
gboolean nm_system_device_set_from_ip4_config (NMDevice *dev)
{
	NMData *		app_data;
	NMIP4Config *	config;
	gboolean		success = FALSE;

	g_return_val_if_fail (dev != NULL, FALSE);

	app_data = nm_device_get_app_data (dev);
	g_return_val_if_fail (app_data != NULL, FALSE);

	config = nm_device_get_ip4_config (dev);
	g_return_val_if_fail (config != NULL, FALSE);

	nm_system_delete_default_route ();
	nm_system_device_flush_addresses (dev);
	nm_system_device_flush_routes (dev);
	nm_system_flush_arp_cache ();

	nm_system_device_set_ip4_address (dev, nm_ip4_config_get_address (config));
	nm_system_device_set_ip4_netmask (dev, nm_ip4_config_get_netmask (config));
	nm_system_device_set_ip4_broadcast (dev, nm_ip4_config_get_broadcast (config));
	sleep (1);
	nm_system_device_set_ip4_route (dev, nm_ip4_config_get_gateway (config), 0, 0);

	set_nameservers (app_data->named_manager, config);
	set_search_domains (app_data->named_manager, config);

	return TRUE;
}


/*
 * validate_ip4_route
 *
 * Ensure that IP4 routes are in the correct format
 *
 */
static char *validate_ip4_route (const char *route)
{
	char *		ret = NULL;
	char *		temp = NULL;
	int			slash_pos = -1;
	char *		p = NULL;
	int			len, i;
	int			dot_count = 0;
	gboolean		have_slash = FALSE;
	struct in_addr	addr;

	g_return_val_if_fail (route != NULL, NULL);

	len = strlen (route);
	/* Minimum length, ie 1.1.1.1/8 */
	if (len < 9)
		return NULL;

	for (i = 0; i < len; i++)
	{
		/* Ensure there is only one slash */
		if (route[i] == '/')
		{
			if (have_slash)
				goto out;

			have_slash = TRUE;
			slash_pos = i;
			continue;
		}

		if (route[i] == '.')
		{
			if (dot_count >= 4)
				goto out;

			dot_count++;
			continue;
		}

		if (!isdigit (route[i]))
			goto out;
	}

	/* Make sure there is at least one slash and 3 dots */
	if (!have_slash || !slash_pos || (dot_count != 3))
		goto out;

	/* Valid IP address part */
	temp = g_strdup (route);
	temp[slash_pos] = '\0';
	memset (&addr, 0, sizeof (struct in_addr));
	if (inet_aton (temp, &addr) == 0)
		goto out;

	/* Ensure the network # is valid */
	p = temp + slash_pos + 1;
	i = (int) strtol (p, NULL, 10);
	if ((i < 0) || (i > 32))
		goto out;

	/* Success! */
	ret = g_strdup (route);

out:
	g_free (temp);
	return ret;
}


/*
 * nm_system_vpn_device_set_from_ip4_config
 *
 * Set IPv4 configuration of a VPN device from an NMIP4Config object.
 *
 */
gboolean nm_system_vpn_device_set_from_ip4_config (NMNamedManager *named, NMDevice *active_device, const char *iface, NMIP4Config *config, char **routes, int num_routes)
{
	gboolean		success = FALSE;
	NMIP4Config *	ad_config = NULL;

	g_return_val_if_fail (iface != NULL, FALSE);
	g_return_val_if_fail (config != NULL, FALSE);

	if (active_device && (ad_config = nm_device_get_ip4_config (active_device)))
	{
		nm_system_remove_ip4_config_nameservers (named, ad_config);
		nm_system_remove_ip4_config_search_domains (named, ad_config);
		nm_system_device_set_ip4_route (active_device, nm_ip4_config_get_gateway (ad_config), nm_ip4_config_get_gateway (config), 0xFFFFFFFF);
	}

	nm_system_device_set_up_down_with_iface (NULL, iface, TRUE);

	nm_system_device_set_ip4_address_with_iface (NULL, iface, nm_ip4_config_get_address (config));
	nm_system_device_set_ip4_ptp_address_with_iface (NULL, iface, nm_ip4_config_get_address (config));
	nm_system_device_set_ip4_netmask_with_iface (NULL, iface, nm_ip4_config_get_netmask (config));
	nm_system_device_set_mtu_with_iface (NULL, iface, 1412); 
	sleep (1);
	nm_system_device_flush_routes_with_iface (iface);
	if (num_routes <= 0)
	{
		nm_system_delete_default_route ();
		nm_system_device_add_default_route_via_device_with_iface (iface);
	}
	else
	{
		int i;
		for (i = 0; i < num_routes; i++)
		{
			char *valid_ip4_route;

			/* Make sure the route is valid, otherwise it's a security risk as the route
			 * text is simply taken from the user, and passed directly to system().  If
			 * we did not check the route, think of:
			 *
			 *     system("/sbin/ip route add `rm -rf /` dev eth0")
			 *
			 * where `rm -rf /` was the route text.  As UID 0 (root), we have to be careful.
			 */
			if ((valid_ip4_route = validate_ip4_route (routes[i])))
			{
				nm_system_device_add_route_via_device_with_iface (iface, valid_ip4_route);
				g_free (valid_ip4_route);
			}
		}
	}

	set_nameservers (named, config);
	set_search_domains (named, config);

	return TRUE;
}


/*
 * nm_system_device_set_up_down
 *
 * Mark the device as up or down.
 *
 */
gboolean nm_system_device_set_up_down (NMDevice *dev, gboolean up)
{
	g_return_val_if_fail (dev != NULL, FALSE);

	return nm_system_device_set_up_down_with_iface (dev, nm_device_get_iface (dev), up);
}

gboolean nm_system_device_set_up_down_with_iface (NMDevice *dev, const char *iface, gboolean up)
{
	struct ifreq	ifr;
	guint32		flags = up ? IFF_UP : ~IFF_UP;
	NMSock *		sk;
	gboolean		success = FALSE;
	int			err;

	g_return_val_if_fail (iface != NULL, FALSE);

	if ((sk = nm_dev_sock_open (dev, DEV_GENERAL, __FUNCTION__, NULL)) == NULL)
		return FALSE;

	/* Get flags already there */
	memset (&ifr, 0, sizeof (struct ifreq));
	memcpy (ifr.ifr_name, iface, strlen (iface));
#ifdef IOCTL_DEBUG
	nm_info ("%s: About to GET IFFLAGS\n", nm_device_get_iface (dev));
#endif
	err = ioctl (nm_dev_sock_get_fd (sk), SIOCGIFFLAGS, &ifr);
#ifdef IOCTL_DEBUG
	nm_info ("%s: Done with GET IFFLAGS\n", nm_device_get_iface (dev));
#endif

	if (err == -1)
	{
		if (errno != ENODEV)
			nm_warning ("nm_system_device_set_up_down_with_iface() could not get flags for device %s.  errno = %d", iface, errno );
	}
	else
	{
		/* If the interface doesn't have those flags already, set them on it. */
		if ((ifr.ifr_flags^flags) & IFF_UP)
		{
			ifr.ifr_flags &= ~IFF_UP;
			ifr.ifr_flags |= IFF_UP & flags;

#ifdef IOCTL_DEBUG
			nm_info ("%s: About to SET IFFLAGS\n", nm_device_get_iface (dev));
#endif
			err = ioctl (nm_dev_sock_get_fd (sk), SIOCSIFFLAGS, &ifr);
#ifdef IOCTL_DEBUG
			nm_info ("%s: About to SET IFFLAGS\n", nm_device_get_iface (dev));
#endif

			if (err == -1)
			{
				if (errno != ENODEV)
					nm_warning ("nm_system_device_set_up_down_with_iface() could not bring device %s %s.  errno = %d", iface, (up ? "up" : "down"), errno);
			}
		}
	}

	nm_dev_sock_close (sk);
	return success;
}


/*
 * nm_system_device_set_ip4_address
 *
 * Set the device's IPv4 address.
 *
 */
static gboolean nm_system_device_set_ip4_address (NMDevice *dev, int ip4_address)
{
	g_return_val_if_fail (dev != NULL, FALSE);

	return nm_system_device_set_ip4_address_with_iface (dev, nm_device_get_iface (dev), ip4_address);
}

static gboolean nm_system_device_set_ip4_address_with_iface (NMDevice *dev, const char *iface, int ip4_address)
{
	struct ifreq		ifr;
	NMSock *			sk;
	gboolean			success = FALSE;
	struct sockaddr_in *p = (struct sockaddr_in *)&(ifr.ifr_addr);
	int				err;

	g_return_val_if_fail (iface != NULL, FALSE);

	if ((sk = nm_dev_sock_open (dev, NETWORK_CONTROL, __FUNCTION__, NULL)) == NULL)
		return FALSE;

	memset (&ifr, 0, sizeof (struct ifreq));
	memcpy (ifr.ifr_name, iface, strlen (iface));
	p->sin_family = AF_INET;
	p->sin_addr.s_addr = ip4_address;

#ifdef IOCTL_DEBUG
	nm_info ("%s: About to SET IFADDR\n", nm_device_get_iface (dev));
#endif
	err = ioctl (nm_dev_sock_get_fd (sk), SIOCSIFADDR, &ifr);
#ifdef IOCTL_DEBUG
	nm_info ("%s: About to SET IFADDR\n", nm_device_get_iface (dev));
#endif

	if (err == -1)
		nm_warning ("nm_system_device_set_ip4_address_by_iface (%s): failed to set IPv4 address!", iface);
	else
	{
		success = TRUE;
		nm_info ("Your IP address = %u.%u.%u.%u",
				((unsigned char *)&ip4_address)[0], ((unsigned char *)&ip4_address)[1],
				((unsigned char *)&ip4_address)[2], ((unsigned char *)&ip4_address)[3]);
	}

	nm_dev_sock_close (sk);
	return success;
}


/*
 * nm_system_device_set_ip4_ptp_address
 *
 * Set the device's IPv4 point-to-point address.
 *
 */
static gboolean nm_system_device_set_ip4_ptp_address (NMDevice *dev, int ip4_ptp_address)
{
	g_return_val_if_fail (dev != NULL, FALSE);

	return nm_system_device_set_ip4_ptp_address_with_iface (dev, nm_device_get_iface (dev), ip4_ptp_address);
}

static gboolean nm_system_device_set_ip4_ptp_address_with_iface (NMDevice *dev, const char *iface, int ip4_ptp_address)
{
	struct ifreq		ifr;
	NMSock *			sk;
	gboolean			success = FALSE;
	struct sockaddr_in *p = (struct sockaddr_in *)&(ifr.ifr_addr);
	int				err;

	g_return_val_if_fail (iface != NULL, FALSE);

	if ((sk = nm_dev_sock_open (dev, NETWORK_CONTROL, __FUNCTION__, NULL)) == NULL)
		return FALSE;

	memset (&ifr, 0, sizeof (struct ifreq));
	memcpy (ifr.ifr_name, iface, strlen (iface));
	p->sin_family = AF_INET;
	p->sin_port = 0;
	p->sin_addr.s_addr = ip4_ptp_address;

#ifdef IOCTL_DEBUG
	nm_info ("%s: About to SET IFDSTADDR\n", nm_device_get_iface (dev));
#endif
	err = ioctl (nm_dev_sock_get_fd (sk), SIOCSIFDSTADDR, &ifr);
#ifdef IOCTL_DEBUG
	nm_info ("%s: About to SET IFDSTADDR\n", nm_device_get_iface (dev));
#endif

	if (err == -1)
		nm_warning ("nm_system_device_set_ip4_ptp_address (%s): failed to set IPv4 point-to-point address!", iface);
	else
	{
		struct ifreq ifr2;

		memset (&ifr2, 0, sizeof (struct ifreq));
		memcpy (ifr2.ifr_name, iface, strlen (iface));

#ifdef IOCTL_DEBUG
		nm_info ("%s: About to GET IFFLAGS (ptp)\n", nm_device_get_iface (dev));
#endif
		err = ioctl (nm_dev_sock_get_fd (sk), SIOCGIFFLAGS, &ifr2);
#ifdef IOCTL_DEBUG
		nm_info ("%s: About to GET IFFLAGS (ptp)\n", nm_device_get_iface (dev));
#endif

		if (err >= 0)
		{
			memcpy (ifr2.ifr_name, iface, strlen (iface));
			ifr2.ifr_flags |= IFF_POINTOPOINT;

#ifdef IOCTL_DEBUG
			nm_info ("%s: About to SET IFFLAGS (ptp)\n", nm_device_get_iface (dev));
#endif
			err = ioctl (nm_dev_sock_get_fd (sk), SIOCSIFFLAGS, &ifr2);
#ifdef IOCTL_DEBUG
			nm_info ("%s: About to SET IFFLAGS (ptp)\n", nm_device_get_iface (dev));
#endif

			if (err >= 0)
			{
				success = TRUE;
				nm_info ("Your Point-to-Point IP address = %u.%u.%u.%u",
						((unsigned char *)&ip4_ptp_address)[0], ((unsigned char *)&ip4_ptp_address)[1],
						((unsigned char *)&ip4_ptp_address)[2], ((unsigned char *)&ip4_ptp_address)[3]);
			}
			else
				nm_warning ("nm_system_device_set_ip4_ptp_address (%s): failed to set POINTOPOINT flag on device!", iface);
		}
		else
			nm_warning ("nm_system_device_set_ip4_ptp_address (%s): failed to get interface flags!", iface);
	}

	nm_dev_sock_close (sk);
	return (success);
}


/*
 * nm_system_device_set_ip4_netmask
 *
 * Set the IPv4 netmask on a device.
 *
 */
static gboolean nm_system_device_set_ip4_netmask (NMDevice *dev, int ip4_netmask)
{
	g_return_val_if_fail (dev != NULL, FALSE);

	return nm_system_device_set_ip4_netmask_with_iface (dev, nm_device_get_iface (dev), ip4_netmask);
}

static gboolean nm_system_device_set_ip4_netmask_with_iface (NMDevice *dev, const char *iface, int ip4_netmask)
{
	struct ifreq		ifr;
	NMSock *			sk;
	gboolean			success = FALSE;
	struct sockaddr_in *p = (struct sockaddr_in *)&(ifr.ifr_addr);
	int				err;

	g_return_val_if_fail (iface != NULL, FALSE);

	if ((sk = nm_dev_sock_open (dev, NETWORK_CONTROL, __FUNCTION__, NULL)) == NULL)
		return FALSE;

	memset (&ifr, 0, sizeof (struct ifreq));
	memcpy (ifr.ifr_name, iface, strlen (iface));
	p->sin_family = AF_INET;
	p->sin_addr.s_addr = ip4_netmask;
#ifdef IOCTL_DEBUG
	nm_info ("%s: About to SET IFNETMASK\n", nm_device_get_iface (dev));
#endif
	err = ioctl (nm_dev_sock_get_fd (sk), SIOCSIFNETMASK, &ifr);
#ifdef IOCTL_DEBUG
	nm_info ("%s: About to SET IFNETMASK\n", nm_device_get_iface (dev));
#endif

	if (err == -1)
		nm_warning ("nm_system_device_set_ip4_netmask (%s): failed to set IPv4 netmask! errno = %s", iface, strerror (errno));
	else
		success = TRUE;

	nm_dev_sock_close (sk);
	return success;
}


/*
 * nm_system_device_set_ip4_broadcast
 *
 * Set the IPv4 broadcast address on a device.
 *
 */
static gboolean nm_system_device_set_ip4_broadcast (NMDevice *dev, int ip4_broadcast)
{
	g_return_val_if_fail (dev != NULL, FALSE);

	return nm_system_device_set_ip4_broadcast_with_iface (dev, nm_device_get_iface (dev), ip4_broadcast);
}

static gboolean nm_system_device_set_ip4_broadcast_with_iface (NMDevice *dev, const char *iface, int ip4_broadcast)
{
	struct ifreq		ifr;
	NMSock *			sk;
	gboolean			success = FALSE;
	struct sockaddr_in *p = (struct sockaddr_in *)&(ifr.ifr_addr);
	int				err;

	g_return_val_if_fail (iface != NULL, FALSE);

	if ((sk = nm_dev_sock_open (dev, NETWORK_CONTROL, __FUNCTION__, NULL)) == NULL)
		return FALSE;

	memset (&ifr, 0, sizeof(struct ifreq));
	memcpy (ifr.ifr_name, iface, strlen (iface));
	p->sin_family = AF_INET;
	p->sin_addr.s_addr = ip4_broadcast;
#ifdef IOCTL_DEBUG
	nm_info ("%s: About to SET IFBRDADDR\n", nm_device_get_iface (dev));
#endif
	err = ioctl (nm_dev_sock_get_fd (sk), SIOCSIFBRDADDR, &ifr);
#ifdef IOCTL_DEBUG
	nm_info ("%s: About to SET IFBRDADDR\n", nm_device_get_iface (dev));
#endif

	if (err == -1)
		nm_warning ("nm_system_device_set_ip4_netmask (%s): failed to set IPv4 broadcast address!", iface);
	else
		success = TRUE;

	nm_dev_sock_close (sk);
	return success;
}


/*
 * nm_system_device_set_ip4_broadcast
 *
 * Set the IPv4 broadcast address on a device.
 *
 */
static gboolean nm_system_device_set_ip4_route (NMDevice *dev, int ip4_gateway, int ip4_dest, int ip4_netmask)
{
	g_return_val_if_fail (dev != NULL, FALSE);

	return nm_system_device_set_ip4_route_with_iface (dev, nm_device_get_iface (dev), ip4_gateway, ip4_dest, ip4_netmask);
}

/*
 * nm_system_device_set_mtu
 *
 * Set the MTU on a device.
 *
 */
static gboolean nm_system_device_set_mtu (NMDevice *dev, guint16 in_mtu)
{
	g_return_val_if_fail (dev != NULL, FALSE);

	return nm_system_device_set_mtu_with_iface (dev, nm_device_get_iface (dev), in_mtu);
}

static gboolean nm_system_device_set_mtu_with_iface (NMDevice *dev, const char *iface, guint16 in_mtu)
{
	struct ifreq   ifr;
	NMSock *		sk;
	gboolean		success = FALSE;
	int			err;

	g_return_val_if_fail (iface != NULL, FALSE);

	if ((sk = nm_dev_sock_open (dev, NETWORK_CONTROL, __FUNCTION__, NULL)) == NULL)
		return FALSE;

	memset (&ifr, 0, sizeof (struct ifreq));
	memcpy (ifr.ifr_name, iface, strlen (iface));
	ifr.ifr_mtu = in_mtu;
#ifdef IOCTL_DEBUG
	nm_info ("%s: About to SET IFMTU\n", nm_device_get_iface (dev));
#endif
	err = ioctl (nm_dev_sock_get_fd (sk), SIOCSIFMTU, &ifr);
#ifdef IOCTL_DEBUG
	nm_info ("%s: About to SET IFMTU\n", nm_device_get_iface (dev));
#endif

	if (err == -1)
		nm_warning ("nm_system_device_set_mtu (%s): failed to set mtu! errno = %s", iface, strerror (errno));
	else
		success = TRUE;

	nm_dev_sock_close (sk);
	return success;
}

static gboolean nm_system_device_set_ip4_route_with_iface (NMDevice *dev, const char *iface, int ip4_gateway, int ip4_dest, int ip4_netmask)
{
	NMSock *			sk;
	gboolean			success = FALSE;
	struct rtentry		rtent;
	struct sockaddr_in *p;
	int				err;

	g_return_val_if_fail (iface != NULL, FALSE);

	if ((sk = nm_dev_sock_open (dev, NETWORK_CONTROL, __FUNCTION__, NULL)) == NULL)
		return FALSE;

	memset (&rtent, 0, sizeof (struct rtentry));
	p				= (struct sockaddr_in *)&rtent.rt_dst;
	p->sin_family		= AF_INET;
	p->sin_addr.s_addr	= ip4_dest;
	p				= (struct sockaddr_in *)&rtent.rt_gateway;
	p->sin_family		= AF_INET;
	p->sin_addr.s_addr	= ip4_gateway;
	p				= (struct sockaddr_in *)&rtent.rt_genmask;
	p->sin_family		= AF_INET;
	p->sin_addr.s_addr	= ip4_netmask;
	rtent.rt_dev		= (char *)iface;
	rtent.rt_metric	= 1;
	rtent.rt_window	= 0;
	rtent.rt_flags		= RTF_UP | RTF_GATEWAY | (rtent.rt_window ? RTF_WINDOW : 0);

#ifdef IOCTL_DEBUG
	nm_info ("%s: About to CADDRT\n", nm_device_get_iface (dev));
#endif
	err = ioctl (nm_dev_sock_get_fd (sk), SIOCADDRT, &rtent);
#ifdef IOCTL_DEBUG
	nm_info ("%s: About to CADDRT\n", nm_device_get_iface (dev));
#endif

	if (err == -1)
	{
		if (errno == ENETUNREACH)	/* possibly gateway is over the bridge */
		{						/* try adding a route to gateway first */
			struct rtentry	rtent2;
			
			memset (&rtent2, 0, sizeof(struct rtentry));
			p				= (struct sockaddr_in *)&rtent2.rt_dst;
			p->sin_family		= AF_INET;
			p				= (struct sockaddr_in *)&rtent2.rt_gateway;
			p->sin_family		= AF_INET;
			p->sin_addr.s_addr	= ip4_gateway;
			p				= (struct sockaddr_in *)&rtent2.rt_genmask;
			p->sin_family		= AF_INET;
			p->sin_addr.s_addr	= 0xffffffff;
			rtent2.rt_dev		= (char *)iface;
			rtent2.rt_metric	= 0;
			rtent2.rt_flags	= RTF_UP | RTF_HOST;

#ifdef IOCTL_DEBUG
			nm_info ("%s: About to CADDRT (2)\n", nm_device_get_iface (dev));
#endif
			err = ioctl (nm_dev_sock_get_fd (sk), SIOCADDRT, &rtent2);
#ifdef IOCTL_DEBUG
			nm_info ("%s: About to CADDRT (2)\n", nm_device_get_iface (dev));
#endif

			if (err == 0)
			{
#ifdef IOCTL_DEBUG
				nm_info ("%s: About to CADDRT (3)\n", nm_device_get_iface (dev));
#endif
				err = ioctl (nm_dev_sock_get_fd (sk), SIOCADDRT, &rtent);
#ifdef IOCTL_DEBUG
				nm_info ("%s: About to CADDRT (3)\n", nm_device_get_iface (dev));
#endif

				if (err == 0)
					success = TRUE;
				else
					nm_warning ("nm_system_device_set_ip4_route_with_iface (%s): failed to set IPv4 default route! errno = %d", iface, errno);
			}
		}
		else
			nm_warning ("nm_system_device_set_ip4_route_with_iface (%s): failed to set IPv4 default route! errno = %d", iface, errno);
	}
	else
		success = TRUE;

	nm_dev_sock_close (sk);
	return (success);
}

