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
	buf = g_strdup_printf ("/sbin/dhclient -1 -q -lf /var/lib/dhcp/dhclient-%s.leases -pf /var/run/dhclient-%s.pid -cf /etc/dhclient-%s.conf %s\n", iface, iface, iface, iface);
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
	buf = g_strdup_printf ("/var/run/dhclient-%s.pid", nm_device_get_iface (dev));
	pidfile = fopen (buf, "r");
	if (pidfile)
	{
		int			len;
		unsigned char	s_pid[20];
		pid_t		n_pid = -1;

		memset (s_pid, 0, 20);
		fgets (s_pid, 20, pidfile);
		len = strlen (s_pid);
		fclose (pidfile);

		n_pid = atoi (s_pid);
		if (n_pid > 0)
			kill (n_pid, SIGKILL);
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
	buf = g_strdup_printf ("/sbin/ip route flush dev %s", nm_device_get_iface (dev));
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
	buf = g_strdup_printf ("/sbin/ip address flush dev %s", nm_device_get_iface (dev));
	nm_spawn_process (buf);
	g_free (buf);
}


/*
 * nm_system_device_setup_ip_config
 *
 * Set up the device with a particular IPv4 address/netmask/gateway.
 *
 */
void nm_system_device_setup_ip4_config (NMDevice *dev)
{
	g_return_if_fail (dev != NULL);
	g_return_if_fail (!nm_device_config_get_use_dhcp (dev));
}


/*
 * nm_system_enable_loopback
 *
 * Bring up the loopback interface
 *
 */
void nm_system_enable_loopback (void)
{
	nm_spawn_process ("/sbin/ip link set dev lo up");
	nm_spawn_process ("/sbin/ip addr add 127.0.0.1/8 brd 127.255.255.255 dev lo label loopback");
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
	if(nm_spawn_process ("/etc/init.d/nscd status"))
		nm_spawn_process ("/etc/init.d/nscd restart");
}


/*
 * nm_system_load_device_modules
 *
 * Load any network adapter kernel modules that we need to, since Fedora doesn't
 * autoload them at this time.
 *
 */
void nm_system_load_device_modules (void)
{
	nm_spawn_process ("/usr/bin/NMLoadModules");
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
	char		*cfg_file_path = NULL;
	FILE		*file = NULL;
	char		 buffer[100];
	gboolean	 data_good = FALSE;
	gboolean	 use_dhcp = TRUE;
	guint32	 ip4_address = 0;
	guint32	 ip4_netmask = 0;
	guint32	 ip4_gateway = 0;

	g_return_if_fail (dev != NULL);

	/* We use DHCP on an interface unless told not to */
	nm_device_config_set_use_dhcp (dev, TRUE);
	nm_device_config_set_ip4_address (dev, 0);
	nm_device_config_set_ip4_gateway (dev, 0);
	nm_device_config_set_ip4_netmask (dev, 0);

	/* Red Hat/Fedora Core systems store this information in
	 * /etc/sysconfig/network-scripts/ifcfg-* where * is the interface
	 * name.
	 */

	cfg_file_path = g_strdup_printf ("/etc/sysconfig/network-scripts/ifcfg-%s", nm_device_get_iface (dev));
	if (!cfg_file_path)
		return;

	if (!(file = fopen (cfg_file_path, "r")))
	{
		g_free (cfg_file_path);
		return;
	}

	while (fgets (buffer, 499, file) && !feof (file))
	{
		/* Kock off newline if any */
		g_strstrip (buffer);

		if (strncmp (buffer, "DEVICE=", 7) == 0)
		{
			/* Make sure this config file is for this device */
			if (strcmp (&buffer[7], nm_device_get_iface (dev)) != 0)
			{
				syslog (LOG_WARNING, "System config file '%s' was not actually for device '%s'\n",
						cfg_file_path, nm_device_get_iface (dev));
				break;
			}
			else
				data_good = TRUE;
		}
		else if (strncmp (buffer, "BOOTPROTO=dhcp", 14) == 0)
			use_dhcp = TRUE;
		else if (strncmp (buffer, "BOOTPROTO=none", 14) == 0)
			use_dhcp = FALSE;
		else if (strncmp (buffer, "IPADDR=", 7) == 0)
			ip4_address = inet_addr (&buffer[7]);
		else if (strncmp (buffer, "GATEWAY=", 8) == 0)
			ip4_gateway = inet_addr (&buffer[8]);
		else if (strncmp (buffer, "NETMASK=", 8) == 0)
			ip4_netmask = inet_addr (&buffer[8]);
	}
	fclose (file);
	g_free (cfg_file_path);

	/* If successful, set values on the device */
	if (data_good)
	{
		nm_device_config_set_use_dhcp (dev, use_dhcp);
		if (ip4_address)
			nm_device_config_set_ip4_address (dev, ip4_address);
		if (ip4_gateway)
			nm_device_config_set_ip4_gateway (dev, ip4_gateway);
		if (ip4_netmask)
			nm_device_config_set_ip4_netmask (dev, ip4_netmask);
	}
}
