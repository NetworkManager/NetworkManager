/* NetworkManager -- Network link manager
 *
 * Matthew Garrett <mjg59@srcf.ucam.org>
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

#include <stdio.h>
#include <sys/types.h>
#include <signal.h>
#include <arpa/inet.h>
#include "NetworkManagerSystem.h"
#include "NetworkManagerUtils.h"
#include "NetworkManagerDevice.h"
#include "interface_parser.h"

#define ARPING "/usr/sbin/arping"

/*
 * nm_system_init
 *
 * Initializes the distribution-specific system backend
 *
 */
void nm_system_init (void)
{
}


/*
 * nm_system_device_flush_routes
 *
 * Flush all routes associated with a network device
 *
 */
void nm_system_device_flush_routes (NMDevice *dev)
{
	char	*buf;

	g_return_if_fail (dev != NULL);

	/* Not really applicable for test devices */
	if (nm_device_is_test_device (dev))
		return;

	/* Remove routing table entries */
	buf = g_strdup_printf ("/sbin/ip route flush dev %s", nm_device_get_iface (dev));
	nm_spawn_process (buf);
	g_free (buf);
}


/*
 * nm_system_device_add_default_route_via_device
 *
 * Add default route to the given device
 *
 */
void nm_system_device_add_default_route_via_device (NMDevice *dev)
{
	char	*buf;

	g_return_if_fail (dev != NULL);

	/* Not really applicable for test devices */
	if (nm_device_is_test_device (dev))
		return;

	/* Add default gateway */
	buf = g_strdup_printf ("/sbin/ip route add default dev %s", nm_device_get_iface (dev));
	nm_spawn_process (buf);
	g_free (buf);
}


/*
 * nm_system_device_flush_addresses
 *
 * Flush all network addresses associated with a network device
 *
 */
void nm_system_device_flush_addresses (NMDevice *dev)
{
	char	*buf;

	g_return_if_fail (dev != NULL);

	/* Not really applicable for test devices */
	if (nm_device_is_test_device (dev))
		return;

	/* Remove all IP addresses for a device */
	buf = g_strdup_printf ("/sbin/ip address flush dev %s", 
                               nm_device_get_iface (dev));
	nm_spawn_process (buf);
        g_free (buf);
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
        guint32         prefix = IPBITS;    /* initialize with # bits in ipv4 address */
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
            syslog (LOG_ERR, "Error: Duplicate address '%s' detected for " 
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
            syslog (LOG_ERR, "Error: could not set network configuration for "
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
                syslog (LOG_ERR, "Error: could not set default route using "
                                 "command:\n    '%s'", buf);
                goto error;
        }
        g_free (buf);
        return (TRUE);
        
error:
        g_free (buf);
        nm_system_device_flush_addresses (dev);
        nm_system_device_flush_routes (dev);
        return (FALSE);
}


/*
 * nm_system_enable_loopback
 *
 * Bring up the loopback interface
 *
 */
void nm_system_enable_loopback (void)
{
	nm_spawn_process ("/sbin/ifup lo");
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
	nm_spawn_process ("/sbin/ip route flush dev lo");
}


/*
 * nm_system_delete_default_route
 *
 * Remove the old default route in preparation for a new one
 *
 */
void nm_system_delete_default_route (void)
{
	nm_spawn_process ("/sbin/ip route del default");
}


/*
 * nm_system_flush_arp_cache
 *
 * Flush all entries in the arp cache.
 *
 */
void nm_system_flush_arp_cache (void)
{
	nm_spawn_process ("/sbin/ip neigh flush all");
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
	nm_spawn_process ("/usr/sbin/invoke-rc.d nscd restart");

}


/*
 * nm_system_load_device_modules
 *
 * This is a null op - all our drivers should already be loaded.
 *
 */
void nm_system_load_device_modules (void)
{
	return;
}


/*
 * nm_system_restart_mdns_responder
 *
 * Restart the multicast DNS responder so that it knows about new
 * network interfaces and IP addresses.
 *
 */
void nm_system_restart_mdns_responder (void)
{
	nm_spawn_process ("/usr/bin/killall -q -USR1 mDNSResponder");
}


/*
 * nm_system_device_add_ip6_link_address
 *
 * Add a default link-local IPv6 address to a device.
 *
 */
void nm_system_device_add_ip6_link_address (NMDevice *dev)
{
  char *buf;
  char *addr;
  unsigned char eui[8];

  nm_device_get_hw_address(dev, &eui[0]);

  memmove(eui+5, eui+3, 3);
  eui[3] = 0xff;
  eui[4] = 0xfe;
  eui[0] ^= 2;

  /* Add the default link-local IPv6 address to a device */
  buf = g_strdup_printf ("/sbin/ip -6 address add fe80::%x%02x:%x%02x:%x%02x:%x%02x/64 dev %s",
			 eui[0], eui[1], eui[2], eui[3],
			 eui[4], eui[5],
			 eui[6], eui[7], nm_device_get_iface (dev));
  nm_spawn_process (buf);
  g_free (buf);
}


/*
 * nm_system_device_update_config_info
 *
 * Retrieve any relevant configuration info for a particular device
 * from the system network configuration information.  Clear out existing
 * info before setting stuff too.
 *
 */
void nm_system_device_update_config_info (NMDevice *dev)
{
	gboolean	 use_dhcp = TRUE;
	guint32	 ip4_address = 0;
	guint32	 ip4_netmask = 0;
	guint32	 ip4_gateway = 0;
	guint32	 ip4_broadcast = 0;
	if_block *curr_device;
	const char *buf;

	g_return_if_fail (dev != NULL);

	/* We use DHCP on an interface unless told not to */
	nm_device_config_set_use_dhcp (dev, TRUE);
	nm_device_config_set_ip4_address (dev, 0);
	nm_device_config_set_ip4_gateway (dev, 0);
	nm_device_config_set_ip4_netmask (dev, 0);
	nm_device_config_set_ip4_broadcast (dev, 0);


	ifparser_init();

	/* Make sure this config file is for this device */
	curr_device = ifparser_getif(nm_device_get_iface (dev));
	if (curr_device == NULL)
		goto out;

	buf = ifparser_getkey(curr_device, "inet");
	if (buf)
	{
		if (strcmp (buf, "dhcp")!=0)
			use_dhcp = FALSE;
	}

	buf = ifparser_getkey (curr_device, "address");
	if (buf)
		ip4_address = inet_addr (buf);

	buf = ifparser_getkey (curr_device, "gateway");
	if (buf)
		ip4_gateway = inet_addr (buf);

	buf = ifparser_getkey (curr_device, "netmask");
	if (buf)
		ip4_netmask = inet_addr (buf);
	else
	{
		/* Make a default netmask if we have an IP address */
		if (ip4_address)
		{
			if (((ntohl (ip4_address) & 0xFF000000) >> 24) <= 127)
				ip4_netmask = htonl (0xFF000000);
			else if (((ntohl (ip4_address) & 0xFF000000) >> 24) <= 191)
				ip4_netmask = htonl (0xFFFF0000);
			else
				ip4_netmask = htonl (0xFFFFFF00);
		}
	}

	buf = ifparser_getkey (curr_device, "broadcast");
	if (buf)
		ip4_broadcast = inet_addr (buf);

	if (!use_dhcp && (!ip4_address || !ip4_gateway || !ip4_netmask))
	{
		syslog (LOG_ERR, "Error: network configuration for device '%s' was invalid (non-DHCP configuration,"
						" but no address/gateway specificed).  Will use DHCP instead.\n", nm_device_get_iface (dev));
		use_dhcp = TRUE;
	}

	/* If successful, set values on the device */
	nm_device_config_set_use_dhcp (dev, use_dhcp);
	if (ip4_address)
		nm_device_config_set_ip4_address (dev, ip4_address);
	if (ip4_gateway)
		nm_device_config_set_ip4_gateway (dev, ip4_gateway);
	if (ip4_netmask)
		nm_device_config_set_ip4_netmask (dev, ip4_netmask);
	if (ip4_broadcast)
		nm_device_config_set_ip4_broadcast (dev, ip4_broadcast);

#if 0
	syslog (LOG_DEBUG, "------ Config (%s)", nm_device_get_iface (dev));
	syslog (LOG_DEBUG, "    DHCP=%d\n", use_dhcp);
	syslog (LOG_DEBUG, "    ADDR=%d\n", ip4_address);
	syslog (LOG_DEBUG, "    GW=%d\n", ip4_gateway);
	syslog (LOG_DEBUG, "    NM=%d\n", ip4_netmask);
	syslog (LOG_DEBUG, "---------------------\n");
#endif

out:
	ifparser_destroy();
}
