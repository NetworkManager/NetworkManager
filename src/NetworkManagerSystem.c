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
#include <pthread.h>
#include "NetworkManagerSystem.h"
#include "nm-device.h"
#include "NetworkManagerUtils.h"
#include "nm-utils.h"
#include "nm-netlink.h"

#include <netlink/route/addr.h>
#include <netlink/netlink.h>
#include <netlink/utils.h>
#include <netlink/route/link.h>


/*
 * nm_system_device_set_ip4_route
 *
 */
static gboolean
nm_system_device_set_ip4_route (NMDevice *dev,
                                int ip4_gateway,
                                int ip4_dest,
                                int ip4_netmask,
                                int mss)
{
	NMSock *			sk;
	gboolean			success = FALSE;
	struct rtentry		rtent;
	struct sockaddr_in *p;
	const char *		iface;
	NMIP4Config * config = NULL;
	int				err;
	struct rtentry	rtent2;

	/*
	 * Zero is not a legal gateway and the ioctl will fail.  But zero is a
	 * way of saying "no route" so we just return here.  Hopefully the
	 * caller flushed the routes, first.
	 */
	if (ip4_gateway == 0)
		return TRUE;

	iface = nm_device_get_iface (dev);

	/*
	 * Do not add the route if the destination is on the same subnet.
	 */
	config = nm_device_get_ip4_config(dev);
	if (config &&
	    ((guint32)ip4_dest & nm_ip4_config_get_netmask(config)) ==
	        (nm_ip4_config_get_address(config) & nm_ip4_config_get_netmask(config)))
		return TRUE;


	if ((sk = nm_dev_sock_open (iface, NETWORK_CONTROL, __func__, NULL)) == NULL)
		return FALSE;

	memset (&rtent, 0, sizeof (struct rtentry));
	p				= (struct sockaddr_in *) &rtent.rt_dst;
	p->sin_family		= AF_INET;
	p->sin_addr.s_addr	= ip4_dest;
	p				= (struct sockaddr_in *) &rtent.rt_gateway;
	p->sin_family		= AF_INET;
	p->sin_addr.s_addr	= ip4_gateway;
	p				= (struct sockaddr_in *) &rtent.rt_genmask;
	p->sin_family		= AF_INET;
	p->sin_addr.s_addr	= ip4_netmask;
	rtent.rt_dev		= (char *)iface;
	rtent.rt_metric	= 1;
	rtent.rt_window	= 0;
	rtent.rt_flags		= RTF_UP | RTF_GATEWAY | (rtent.rt_window ? RTF_WINDOW : 0);

	if (mss) {
		rtent.rt_flags |= RTF_MTU;
		rtent.rt_mtu = mss;
	}

	nm_ioctl_info ("%s: About to CADDRT\n", iface);
	err = ioctl (nm_dev_sock_get_fd (sk), SIOCADDRT, &rtent);
	nm_ioctl_info ("%s: About to CADDRT\n", iface);
	if (err == 0) {
		/* Everything good */
		success = TRUE;
		goto out;
	}

	if (errno != ENETUNREACH) {
		nm_warning ("Failed to set IPv4 default route on '%s': %s",
		            iface,
		            strerror (errno));
		goto out;
	}
		
	/* Gateway might be over a bridge; try adding a route to gateway first */
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

	if (mss) {
		rtent2.rt_flags |= RTF_MTU;
		rtent2.rt_mtu = mss;
	}

	/* Add route to gateway over bridge */
	nm_ioctl_info ("%s: About to CADDRT (2)\n", iface);
	err = ioctl (nm_dev_sock_get_fd (sk), SIOCADDRT, &rtent2);
	nm_ioctl_info ("%s: About to CADDRT (2)\n", iface);
	if (err) {
		nm_warning ("Failed to add IPv4 default route on '%s': %s",
		            iface,
		            strerror (errno));
		goto out;
	}

	/* Try adding the route again */
	nm_ioctl_info ("%s: About to CADDRT (3)\n", iface);
	err = ioctl (nm_dev_sock_get_fd (sk), SIOCADDRT, &rtent);
	nm_ioctl_info ("%s: About to CADDRT (3)\n", iface);
	if (!err) {
		success = TRUE;
	} else {
		nm_warning ("Failed to set IPv4 default route on '%s': %s",
		            iface,
		            strerror (errno));
	}

out:
	nm_dev_sock_close (sk);
	return success;
}


/*
 * nm_system_device_set_from_ip4_config
 *
 * Set IPv4 configuration of the device from an NMIP4Config object.
 *
 */
gboolean nm_system_device_set_from_ip4_config (NMDevice *dev)
{
	NMNamedManager * named_mgr;
	NMIP4Config *		config;
	struct nl_handle *	nlh = NULL;
	struct rtnl_addr *	addr = NULL;
	int				err;

	g_return_val_if_fail (dev != NULL, FALSE);

	config = nm_device_get_ip4_config (dev);
	g_return_val_if_fail (config != NULL, FALSE);

	nm_system_delete_default_route ();
	nm_system_device_flush_addresses (dev);
	nm_system_device_flush_routes (dev);
	nm_system_flush_arp_cache ();

	nlh = nm_netlink_get_default_handle ();

	if ((addr = nm_ip4_config_to_rtnl_addr (config, NM_RTNL_ADDR_DEFAULT)))
	{
		rtnl_addr_set_ifindex (addr, nm_device_get_index (dev));
		if ((err = rtnl_addr_add (nlh, addr, 0)) < 0)
			nm_warning ("(%s) error %d returned from rtnl_addr_add():\n%s", nm_device_get_iface (dev), err, nl_geterror());
		rtnl_addr_put (addr);
	}
	else
		nm_warning ("couldn't create rtnl address!\n");

	sleep (1);
	nm_system_device_set_ip4_route (dev, nm_ip4_config_get_gateway (config), 0, 0, nm_ip4_config_get_mss (config));

	named_mgr = nm_named_manager_get ();
	nm_named_manager_add_ip4_config (named_mgr, config);
	g_object_unref (named_mgr);

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
gboolean
nm_system_vpn_device_set_from_ip4_config (NMNamedManager *named,
                                          NMDevice *active_device,
                                          const char *iface,
                                          NMIP4Config *config,
                                          char **routes,
                                          int num_routes)
{
	NMIP4Config *		ad_config = NULL;
	struct nl_handle *	nlh = NULL;
	struct rtnl_addr *	addr = NULL;
	struct rtnl_link *	request = NULL;

	g_return_val_if_fail (config != NULL, FALSE);

	/* Set up a route to the VPN gateway through the real network device */
	if (active_device && (ad_config = nm_device_get_ip4_config (active_device)))
	{
		nm_system_device_set_ip4_route (active_device,
				nm_ip4_config_get_gateway (ad_config),
				nm_ip4_config_get_gateway (config),
				0xFFFFFFFF,
				nm_ip4_config_get_mss (config));
	}

	if (iface != NULL && strlen (iface))
	{
		nm_system_device_set_up_down_with_iface (iface, TRUE);

		nlh = nm_netlink_get_default_handle ();

		if ((addr = nm_ip4_config_to_rtnl_addr (config, NM_RTNL_ADDR_PTP_DEFAULT)))
		{
			int err = 0;
			rtnl_addr_set_ifindex (addr, nm_device_get_index (active_device));
			if ((err = rtnl_addr_add (nlh, addr, 0)) < 0)
				nm_warning ("error %d returned from rtnl_addr_add():\n%s", err, nl_geterror());
			rtnl_addr_put (addr);
		}
		else
			nm_warning ("couldn't create rtnl address!\n");

		/* Set the MTU */
		if ((request = rtnl_link_alloc ()))
		{
			struct rtnl_link * old;
			guint32 mtu;

			old = nm_netlink_index_to_rtnl_link (nm_device_get_index (active_device));
			mtu = nm_ip4_config_get_mtu (config);
			if (mtu == 0)
				mtu = 1412;  /* Default to 1412 (vpnc) */
			rtnl_link_set_mtu (request, mtu);
			rtnl_link_change (nlh, old, request, 0);

			rtnl_link_put (old);
			rtnl_link_put (request);
		}

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
	}

	nm_named_manager_add_ip4_config (named, config);

	return TRUE;
}


/*
 * nm_system_vpn_device_unset_from_ip4_config
 *
 * Unset an IPv4 configuration of a VPN device from an NMIP4Config object.
 *
 */
gboolean nm_system_vpn_device_unset_from_ip4_config (NMNamedManager *named, NMDevice *active_device, const char *iface, NMIP4Config *config)
{
	g_return_val_if_fail (named != NULL, FALSE);
	g_return_val_if_fail (active_device != NULL, FALSE);
	g_return_val_if_fail (config != NULL, FALSE);

	nm_named_manager_remove_ip4_config (named, config);

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

	return nm_system_device_set_up_down_with_iface (nm_device_get_iface (dev), up);
}

gboolean nm_system_device_set_up_down_with_iface (const char *iface, gboolean up)
{
	gboolean success = FALSE;
	guint32 index;
	struct rtnl_link *	request = NULL;
	struct rtnl_link *	old = NULL;

	g_return_val_if_fail (iface != NULL, FALSE);

	if (!(request = rtnl_link_alloc ()))
		goto out;

	if (up)
		rtnl_link_set_flags (request, IFF_UP);
	else
		rtnl_link_unset_flags (request, IFF_UP);

	index = nm_netlink_iface_to_index (iface);
	old = nm_netlink_index_to_rtnl_link (index);
	if (old) {
		struct nl_handle * nlh = nm_netlink_get_default_handle ();
		rtnl_link_change (nlh, old, request, 0);
	}

	rtnl_link_put (old);
	rtnl_link_put (request);
	success = TRUE;

out:
	return success;
}


/*
 * nm_system_set_mtu
 *
 * Set the MTU for a given device.
 */
void nm_system_set_mtu (NMDevice *dev)
{
	struct rtnl_link *	request;
	struct rtnl_link *	old;
	unsigned long		mtu;
	struct nl_handle *	nlh;

	mtu = nm_system_get_mtu (dev);
	if (!mtu)
		return;

	request = rtnl_link_alloc ();
	if (!request)
		return;

	old = nm_netlink_index_to_rtnl_link (nm_device_get_index (dev));
	if (!old)
		goto out_request;

	nm_info ("Setting MTU of interface '%s' to %ld",
	         nm_device_get_iface (dev),
	         mtu);
	rtnl_link_set_mtu (request, mtu);
	nlh = nm_netlink_get_default_handle ();
	rtnl_link_change (nlh, old, request, 0);

	rtnl_link_put (old);
out_request:
	rtnl_link_put (request);
}
