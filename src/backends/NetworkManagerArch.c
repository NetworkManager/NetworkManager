/* NetworkManager -- Network link manager
 *
 * Backend implementation for the Arch Linux distribution http://www.archlinux.org
 * 
 * Tor Krill <tor@krill.nu> and Will Rea <sillywilly@gmail.com>
 *
 * Updated by Wael Nasreddine <gandalf@siemens-mobiles.org>
 *
 * Updated by Valentine Sinitsyn <e_val@inbox.ru>
 * 
 * Heavily based on NetworkManagerDebian.c by Matthew Garrett <mjg59@srcf.ucam.org>
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
 * (C) Copyright 2004 Tom Parker
 * (C) Copyright 2004 Matthew Garrett
 * (C) Copyright 2004 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>
#include <arpa/inet.h>
#include <glib/gprintf.h>
#include <glib/gfileutils.h>
#include <string.h>
#include <stdlib.h>

#include "NetworkManagerGeneric.h"
#include "NetworkManagerSystem.h"
#include "NetworkManagerUtils.h"
#include "nm-device.h"
#include "nm-device-802-3-ethernet.h"
#include "nm-device-802-11-wireless.h"
#include "interface_parser.h"
#include "nm-utils.h"

#define ARPING "/usr/sbin/arping"

/*
 * nm_system_init
 *
 * Initializes the distribution-specific system backend
 *
 */
void nm_system_init (void)
{
	nm_generic_init ();
}

/*
 * nm_system_device_flush_ip4_addresses
 *
 * Flush all network addresses associated with a network device
 *
 */
void nm_system_device_flush_ip4_routes (NMDevice *dev)
{
	nm_generic_device_flush_ip4_routes (dev);
}

/*
 * nm_system_device_flush_ip4_routes_with_iface
 *
 * Flush all routes associated with a network device
 *
 */
void nm_system_device_flush_ip4_routes_with_iface (const char *iface)
{
	nm_generic_device_flush_ip4_routes_with_iface (iface);
}

/*
 * nm_system_device_flush_ip4_addresses
 *
 * Flush all network addresses associated with a network device
 *
 */
void nm_system_device_flush_ip4_addresses (NMDevice *dev)
{
	nm_generic_device_flush_ip4_addresses (dev);
}


/*
 * nm_system_device_flush_ip4_addresses_with_iface
 *
 * Flush all network addresses associated with a network device
 *
 */
void nm_system_device_flush_ip4_addresses_with_iface (const char *iface)
{
	nm_generic_device_flush_ip4_addresses_with_iface (iface);
}

/*
 * nm_system_device_setup_static_ip4_config
 *
 * Set up the device with a particular IPv4 address/netmask/gateway.
 *
 * Returns:	TRUE	on success
 *			FALSE on error
 *
 */
#if 0
gboolean nm_system_device_setup_static_ip4_config (NMDevice *dev)
{
#define IPBITS (sizeof (guint32) * 8)
	struct in_addr  temp_addr;
	struct in_addr  temp_addr2;
	char            *s_tmp;
	char            *s_tmp2;
	int             i;
	guint32         addr;
	guint32         netmask;
	guint32         prefix = IPBITS;	 /* initialize with # bits in ipv4 address */
	guint32         broadcast;
	char            *buf;
	int             err;
	const char            *iface;

	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (!nm_device_config_get_use_dhcp (dev), FALSE);

	addr = nm_device_config_get_ip4_address (dev);
	netmask = nm_device_config_get_ip4_netmask (dev);
	iface = nm_device_get_iface (dev);
	broadcast = nm_device_config_get_ip4_broadcast (dev);

	/* get the prefix from the netmask */
	for (i = 0; i < IPBITS; i++)
	{
		if (!(ntohl (netmask) & ((2 << i) - 1)))
			prefix--;
	}

	/* Calculate the broadcast address if the user didn't specify one */
	if (!broadcast)
		broadcast = ((addr & (int)netmask) | ~(int)netmask);

	/* 
	 * Try and work out if someone else has our IP
	 * using RFC 2131 Duplicate Address Detection
	 */
	temp_addr.s_addr = addr;
	buf = g_strdup_printf ("%s -q -D -c 1 -I %s %s",ARPING, 
					   iface, inet_ntoa (temp_addr));
	if ((err = nm_spawn_process (buf)))
	{
		nm_warning ("Error: Duplicate address '%s' detected for " 
				  "device '%s' \n", iface, inet_ntoa (temp_addr));
		goto error;
	}
	g_free (buf);

	/* set our IP address */
	temp_addr.s_addr = addr;
	temp_addr2.s_addr = broadcast;
	s_tmp = g_strdup (inet_ntoa (temp_addr));
	s_tmp2 = g_strdup (inet_ntoa (temp_addr2));
	buf = g_strdup_printf ("/sbin/ip addr add %s/%d brd %s dev %s label %s",
					   s_tmp, prefix, s_tmp2, iface, iface);
	g_free (s_tmp);
	g_free (s_tmp2);
	if ((err = nm_spawn_process (buf)))
	{
		nm_warning ("Error: could not set network configuration for "
				  "device '%s' using command:\n      '%s'",
				  iface, buf);
		goto error;
	}
	g_free (buf);

	/* Alert other computers of our new address */
	temp_addr.s_addr = addr;
	buf = g_strdup_printf ("%s -q -A -c 1 -I %s %s", ARPING,iface,
					   inet_ntoa (temp_addr));
	nm_spawn_process (buf);
	g_free (buf);
	g_usleep (G_USEC_PER_SEC * 2);
	buf = g_strdup_printf ("%s -q -U -c 1 -I %s %s", ARPING, iface,
					   inet_ntoa (temp_addr));
	nm_spawn_process (buf);
	g_free (buf);

	/* set the default route to be this device's gateway */
	temp_addr.s_addr = nm_device_config_get_ip4_gateway (dev);
	buf = g_strdup_printf ("/sbin/ip route replace default via %s dev %s",
					   inet_ntoa (temp_addr), iface);
	if ((err = nm_spawn_process (buf)))
	{
		nm_warning ("Error: could not set default route using "
				  "command:\n    '%s'", buf);
		goto error;
	}
	g_free (buf);
	return(TRUE);

	error:
	g_free (buf);
	nm_system_device_flush_ip4_addresses (dev);
	nm_system_device_flush_ip4_routes (dev);
	return(FALSE);
}
#endif

/*
 * nm_system_enable_loopback
 *
 * Bring up the loopback interface
 *
 */
void nm_system_enable_loopback (void)
{
	nm_system_device_set_up_down_with_iface ("lo", TRUE);
}


/*
 * nm_system_flush_loopback_routes
 *
 * Flush all routes associated with the loopback device, because it
 * sometimes gets the first route for ZeroConf/Link-Local traffic.
 *
 */
void nm_system_flush_loopback_routes (void)
{
	nm_generic_flush_loopback_routes ();
}


/*
 * nm_system_flush_arp_cache
 *
 * Flush all entries in the arp cache.
 *
 */
void nm_system_flush_arp_cache (void)
{
	nm_generic_flush_arp_cache ();
}


/*
 * nm_system_kill_all_dhcp_daemons
 *
 * Kill all DHCP daemons currently running, done at startup.
 *
 */
void nm_system_kill_all_dhcp_daemons (void)
{
	nm_spawn_process ("/usr/bin/killall -q dhclient");
}


/*
 * nm_system_update_dns
 *
 * Make glibc/nscd aware of any changes to the resolv.conf file by
 * restarting nscd.
 *
 */
void nm_system_update_dns (void)
{
	/* Check if the daemon was already running - do not start a new instance */
	if (g_file_test("/var/run/daemons/nscd", G_FILE_TEST_EXISTS))
	{
		nm_spawn_process ("/etc/rc.d/nscd restart");
	}
}

/*
 * nm_system_activate_nis
 *
 * set up the nis domain and write a yp.conf
 *
 */
void nm_system_activate_nis (NMIP4Config *config)
{
}

/*
 * nm_system_should_modify_resolv_conf
 *
 * Can NM update resolv.conf, or is it locked down?
 */
gboolean nm_system_should_modify_resolv_conf (void)
{
	return TRUE;
}

/*
 * nm_system_shutdown_nis
 *
 * shutdown ypbind
 *
 */
void nm_system_shutdown_nis (void)
{
}

/*
 * nm_system_set_hostname
 *
 * set the hostname
 *
 */
void nm_system_set_hostname (NMIP4Config *config)
{
}

