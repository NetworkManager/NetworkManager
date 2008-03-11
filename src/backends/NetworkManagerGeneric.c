/* NetworkManager -- Network link manager
 *
 * Timothee Lecomte <timothee.lecomte@ens.fr>
 *
 * Heavily based on NetworkManagerRedhat.c by Dan Williams <dcbw@redhat.com>
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
 * (C) Copyright 2004 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <sys/types.h>
#include <signal.h>
#include <arpa/inet.h>
#include "NetworkManagerGeneric.h"
#include "NetworkManagerSystem.h"
#include "NetworkManagerUtils.h"
#include "nm-device.h"
#include "nm-device-802-3-ethernet.h"
#include "nm-device-802-11-wireless.h"
#include "nm-utils.h"

/*
 * nm_generic_init
 *
 * Initializes the distribution-specific system backend
 *
 */
void nm_generic_init (void)
{
	/* Kill any dhclients lying around */
	nm_system_kill_all_dhcp_daemons ();
}

/*
 * nm_generic_replace_default_route
 *
 * Replace default route with one via the current device
 *
 */
void
nm_generic_device_replace_default_route (const char *iface, guint32 gw, guint32 mss)
{
	char *buf, *addr_str = NULL, *mss_str = NULL;

	g_return_if_fail (iface != NULL);

	if (gw > 0) {
		struct in_addr addr = { .s_addr = gw };
		char buf2[INET_ADDRSTRLEN + 1];

		memset (buf2, 0, sizeof (buf2));
		inet_ntop (AF_INET, &addr, buf2, INET_ADDRSTRLEN);	
		addr_str = g_strdup_printf ("via %s", buf2);
	}

	if (mss > 0)
		mss_str = g_strdup_printf ("advmss %d", mss);

	buf = g_strdup_printf (IP_BINARY_PATH" route replace default %s %s dev %s",
	                       addr_str ? addr_str : "",
	                       mss_str ? mss_str : "",
	                       iface);
	nm_spawn_process (buf);
	g_free (buf);
}

/*
 * nm_generic_device_add_route_via_device_with_iface
 *
 * Add route to the given device
 *
 */
void nm_generic_device_add_route_via_device_with_iface (const char *iface, const char *route)
{
	char	*buf;

	g_return_if_fail (iface != NULL);

	/* Add default gateway */
	buf = g_strdup_printf (IP_BINARY_PATH" route add %s dev %s", route, iface);
	nm_spawn_process (buf);
	g_free (buf);
}


/*
 * nm_generic_device_flush_addresses
 *
 * Flush all network addresses associated with a network device
 *
 */
void nm_generic_device_flush_routes (NMDevice *dev)
{
	g_return_if_fail (dev != NULL);

	nm_system_device_flush_routes_with_iface (nm_device_get_iface (dev));
}

/*
 * nm_generic_device_flush_routes_with_iface
 *
 * Flush all routes associated with a network device
 *
 */
void nm_generic_device_flush_routes_with_iface (const char *iface)
{
	char	*buf;

	g_return_if_fail (iface != NULL);

	/* Remove routing table entries */
	buf = g_strdup_printf (IP_BINARY_PATH" route flush dev %s", iface);
	nm_spawn_process (buf);
	g_free (buf);
}

/*
 * nm_generic_device_flush_addresses
 *
 * Flush all network addresses associated with a network device
 *
 */
void nm_generic_device_flush_addresses (NMDevice *dev)
{
	g_return_if_fail (dev != NULL);

	nm_system_device_flush_addresses_with_iface (nm_device_get_iface (dev));
}


/*
 * nm_generic_device_flush_addresses_with_iface
 *
 * Flush all network addresses associated with a network device
 *
 */
void nm_generic_device_flush_addresses_with_iface (const char *iface)
{
	char	*buf;

	g_return_if_fail (iface != NULL);

	/* Remove all IP addresses for a device */
	buf = g_strdup_printf (IP_BINARY_PATH" addr flush dev %s", iface);
	nm_spawn_process (buf);
	g_free (buf);
}

/*
 * nm_generic_enable_loopback
 *
 * Bring up the loopback interface
 *
 */
void nm_generic_enable_loopback (void)
{
	nm_spawn_process (IP_BINARY_PATH" link set dev lo up");
	nm_spawn_process (IP_BINARY_PATH" addr add 127.0.0.1/8 brd 127.255.255.255 dev lo scope host label lo");
}


/*
 * nm_generic_flush_loopback_routes
 *
 * Flush all routes associated with the loopback device, because it
 * sometimes gets the first route for ZeroConf/Link-Local traffic.
 *
 */
void nm_generic_flush_loopback_routes (void)
{
	nm_system_device_flush_routes_with_iface ("lo");
}


/*
 * nm_generic_flush_arp_cache
 *
 * Flush all entries in the arp cache.
 *
 */
void nm_generic_flush_arp_cache (void)
{
	nm_spawn_process (IP_BINARY_PATH" neigh flush all");
}


/*
 * nm_generic_kill_all_dhcp_daemons
 *
 * Kill all DHCP daemons currently running, done at startup.
 *
 */
void nm_generic_kill_all_dhcp_daemons (void)
{
}


/*
 * nm_generic_update_dns
 *
 * Make glibc/nscd aware of any changes to the resolv.conf file by
 * restarting nscd.
 *
 */
void nm_generic_update_dns (void)
{
}


/*
 * nm_generic_restart_mdns_responder
 *
 * Restart the multicast DNS responder so that it knows about new
 * network interfaces and IP addresses.
 *
 */
void nm_generic_restart_mdns_responder (void)
{
}


/*
 * nm_generic_device_add_ip6_link_address
 *
 * Add a default link-local IPv6 address to a device.
 *
 */
void nm_generic_device_add_ip6_link_address (NMDevice *dev)
{
	char *buf;
	struct ether_addr hw_addr;
	unsigned char eui[8];

	if (NM_IS_DEVICE_802_3_ETHERNET (dev))
		nm_device_802_3_ethernet_get_address (NM_DEVICE_802_3_ETHERNET (dev), &hw_addr);
	else if (NM_IS_DEVICE_802_11_WIRELESS (dev))
		nm_device_802_11_wireless_get_address (NM_DEVICE_802_11_WIRELESS (dev), &hw_addr);

	memcpy (eui, &(hw_addr.ether_addr_octet), sizeof (hw_addr.ether_addr_octet));
	memmove(eui+5, eui+3, 3);
	eui[3] = 0xff;
	eui[4] = 0xfe;
	eui[0] ^= 2;

	/* Add the default link-local IPv6 address to a device */
	buf = g_strdup_printf (IP_BINARY_PATH" -6 addr add fe80::%x%02x:%x%02x:%x%02x:%x%02x/64 dev %s",
			 eui[0], eui[1], eui[2], eui[3],
			 eui[4], eui[5],
			 eui[6], eui[7], nm_device_get_iface (dev));
	nm_spawn_process (buf);
	g_free (buf);
}

/*
 * nm_generic_set_ip4_config_from_resolv_conf
 *
 * Add nameservers and search names from a resolv.conf format file.
 *
 */
void nm_generic_set_ip4_config_from_resolv_conf (const char *filename, NMIP4Config *ip4_config)
{
	char *	contents = NULL;
	char **	split_contents = NULL;
	int		i, len;

	g_return_if_fail (filename != NULL);
	g_return_if_fail (ip4_config != NULL);

	if (!g_file_get_contents (filename, &contents, NULL, NULL) || (contents == NULL))
		return;

	if (!(split_contents = g_strsplit (contents, "\n", 0)))
		goto out;
	
	len = g_strv_length (split_contents);
	for (i = 0; i < len; i++)
	{
		char *line = split_contents[i];

		/* Ignore comments */
		if (!line || (line[0] == ';') || (line[0] == '#'))
			continue;

		line = g_strstrip (line);
		if ((strncmp (line, "search", 6) == 0) && (strlen (line) > 6))
		{
			char *searches = g_strdup (line + 7);
			char **split_searches = NULL;

			if (!searches || !strlen (searches))
				continue;

			/* Allow space-separated search domains */
			if ((split_searches = g_strsplit (searches, " ", 0)))
			{
				int m, srch_len;

				srch_len = g_strv_length (split_searches);
				for (m = 0; m < srch_len; m++)
				{
					if (split_searches[m])
						nm_ip4_config_add_domain	(ip4_config, split_searches[m]);
				}
				g_strfreev (split_searches);
			}
			else
			{
				/* Only 1 item, add the whole line */
				nm_ip4_config_add_domain	(ip4_config, searches);
			}

			g_free (searches);
		}
		else if ((strncmp (line, "nameserver", 10) == 0) && (strlen (line) > 10))
		{
			guint32	addr = (guint32) (inet_addr (line + 11));

			if (addr != (guint32) -1)
				nm_ip4_config_add_nameserver (ip4_config, addr);
		}
	}

	g_strfreev (split_contents);

out:
	g_free (contents);
}


/*
 * nm_generic_device_get_system_config
 *
 * Retrieve any relevant configuration info for a particular device
 * from the system network configuration information.  Clear out existing
 * info before setting stuff too.
 *
 */
void* nm_generic_device_get_system_config (NMDevice *dev)
{
	return NULL;
}

/*
 * nm_generic_device_free_system_config
 *
 * Free stored system config data
 *
 */
void nm_generic_device_free_system_config (NMDevice *dev, void *system_config_data)
{
	return;
}


/*
 * nm_generic_device_get_use_dhcp
 *
 * Return whether the distro-specific system config tells us to use
 * dhcp for this device.
 *
 */
gboolean nm_generic_device_get_use_dhcp (NMDevice *dev)
{
	return TRUE;
}


/*
 * nm_generic_device_get_disabled
 *
 * Return whether the distro-specific system config tells us to use
 * dhcp for this device.
 *
 */
gboolean nm_generic_device_get_disabled (NMDevice *dev)
{
	return FALSE;
}


NMIP4Config *nm_generic_device_new_ip4_system_config (NMDevice *dev)
{
	return NULL;
}

/*
 * nm_generic_activate_nis
 *
 * set up the nis domain and write a yp.conf
 *
 */
void nm_generic_activate_nis (NMIP4Config *config)
{
}

/*
 * nm_generic_shutdown_nis
 *
 * shutdown ypbind
 *
 */
void nm_generic_shutdown_nis (void)
{
}

/*
 * nm_generic_set_hostname
 *
 * set the hostname
 *
 */
void nm_generic_set_hostname (NMIP4Config *config)
{
}

/*
 * nm_generic_should_modify_resolv_conf
 *
 * Can NM update resolv.conf, or is it locked down?
 */
gboolean nm_generic_should_modify_resolv_conf (void)
{
	return TRUE;
}

