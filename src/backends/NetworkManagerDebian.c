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
 * nm_system_device_run_dhcp
 *
 * Run the dhcp daemon for a particular interface.
 *
 * Returns:	TRUE on success
 *			FALSE on dhcp error
 *
 */
gboolean nm_system_device_run_dhcp (NMDevice *dev)
{
	char		*buf;
        char		*iface;
	int		 err;

	g_return_val_if_fail (dev != NULL, FALSE);

	/* Fake it for a test device */
	if (nm_device_is_test_device (dev))
	{
		g_usleep (2000);
		return (TRUE);
	}

	/* Unfortunately, dhclient can take a long time to get a dhcp address
	 * (for example, bad WEP key so it can't actually talk to the AP).
	 */
	iface = nm_device_get_iface (dev);
	buf = g_strdup_printf ("/sbin/dhclient -pf /var/run/dhclient-%s.pid %s\n",
		               iface, iface);
	printf("Running %s",buf);
	err = nm_spawn_process (buf);
        g_free (buf);
	return (err == 0);
}


/*
 * nm_system_device_stop_dhcp
 *
 * Kill any dhcp daemon that happens to be around.  We may be changing
 * interfaces and we're going to bring the previous one down, so there's
 * no sense in keeping the dhcp daemon running on the old interface.
 *
 */
void nm_system_device_stop_dhcp (NMDevice *dev)
{
	FILE			*pidfile;
	char			*buf;

	g_return_if_fail (dev != NULL);

	/* Not really applicable for test devices */
	if (nm_device_is_test_device (dev))
		return;

	/* Find and kill the previous dhclient process for this device */
        buf = g_strdup_printf ("/var/run/dhclient-%s.pid", 
                               nm_device_get_iface (dev));
	pidfile = fopen (buf, "r");
	if (pidfile)
	{
		int			len;
		unsigned char	s_pid[20];
		pid_t		n_pid = -1;

		memset (s_pid, 0, 20);
		fgets (s_pid, 19, pidfile);
		len = strlen (s_pid);
		fclose (pidfile);

		n_pid = atoi (s_pid);
		if (n_pid > 0)
			kill (n_pid, SIGTERM);
	}
        g_free (buf);
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
	buf = g_strdup_printf ("/sbin/ip route flush dev %s",
                               nm_device_get_iface (dev));
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
        char            *iface;

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
        buf = g_strdup_printf ("/sbin/arping -q -D -c 1 -I %s %s", 
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
        buf = g_strdup_printf ("/sbin/arping -q -A -c 1 -I %s %s", iface,
                               inet_ntoa (temp_addr));
        nm_spawn_process (buf);
        g_free (buf);
        g_usleep (G_USEC_PER_SEC * 2);
        buf = g_strdup_printf ("/sbin/arping -q -U -c 1 -I %s %s", iface,
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
 * nm_system_device_update_config_info
 *
 * Retrieve any relevant configuration info for a particular device
 * from the system network configuration information.  Clear out existing
 * info before setting stuff too.
 *
 */
void nm_system_device_update_config_info (NMDevice *dev)
{
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

