/* NetworkManager -- Network link manager
 *
 * Dan Williams <dcbw@redhat.com>
 * Dan Willemsen <dan@willemsen.us>
 * Robert Paskowitz
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
 * (C) Copyright 2004 Dan Willemsen
 * (C) Copyright 2004 Robert Paskowitz
 */

#include <stdio.h>
#include <sys/types.h>
#include <signal.h>
#include <string.h>
#include "NetworkManagerSystem.h"
#include "NetworkManagerUtils.h"

/*
 * nm_system_init
 *
 * Initializes the distribution-specific system backend
 *
 */
void nm_system_init (void)
{
	/* While dhcpcd is the client of choice, it's not forced upon the user
	 * So we should probably put in a check for available clients, and
	 * modify our commands appropriatly.
	 */
}

/*
 * nm_system_device_run_dhcp
 *
 * Run the dhcp daemon for a particular interface.
 *
 * Returns:	TRUE on success
 *		FALSE on dhcp error
 *
 */
gboolean nm_system_device_run_dhcp (NMDevice *dev)
{
	char		 buf [500];
	char 		*iface;
	int		 err;

	g_return_val_if_fail (dev != NULL, FALSE);

	/* Fake it for a test device */
	if (nm_device_is_test_device (dev))
	{
		g_usleep (2000);
		return (TRUE);
	}

	iface = nm_device_get_iface (dev);
	snprintf (buf, 500, "/sbin/dhcpcd %s", iface);
	err = nm_spawn_process (buf);
	return (err == 0);
}

/*
 * nm_system_device_stop_dhcp
 *
 * Kill any dhcp daemon that happens to be around. We may be changing
 * interfaces and we're going to bring the previous one down, so there's
 * no sense in keeping the dhcp daemon running on the old interface.
 *
 */
void nm_system_device_stop_dhcp (NMDevice *dev)
{
	FILE			*pidfile;
	char			 buf [500];

	g_return_if_fail (dev != NULL);

	/* Not really applicable for test devices */
	if (nm_device_is_test_device (dev))
		return;

	snprintf (buf, 500, "/var/run/dhcpcd-%s.pid", nm_device_get_iface(dev));
	pidfile = fopen (buf, "r");
	if (pidfile)
	{
		int		len;
		unsigned char	s_pid[20];
		pid_t		n_pid = -1;

		memset (s_pid, 0, 20);
		fgets (s_pid, 19, pidfile);
		len = strnlen (s_pid, 20);
		fclose (pidfile);

		n_pid = atoi (s_pid);
		if (n_pid > 0)
			kill (n_pid, SIGTERM);
	}
}

/*
 * nm_system_device_flush_routes
 *
 * Flush all routes associated with a network device
 *
 */
void nm_system_device_flush_routes (NMDevice *dev)
{
	char	buf [100];

	g_return_if_fail (dev != NULL);

	/* Not really applicable for test devices */
	if (nm_device_is_test_device (dev))
		return;
	snprintf (buf, 100, "/sbin/ip route flush dev %s", nm_device_get_iface (dev));
	nm_spawn_process (buf);
}

/*
 * nm_system_device_flush_addresses
 *
 * Flush all network addresses associated with a network device
 *
 */
void nm_system_device_flush_addresses (NMDevice *dev)
{
	char	buf [100];

	g_return_if_fail (dev != NULL);

	/* Not really applicable for test devices */
	if (nm_device_is_test_device (dev))
		return;

	snprintf (buf, 100, "/sbin/ip address flush dev %s", nm_device_get_iface (dev));
	nm_spawn_process (buf);
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
	syslog (LOG_WARNING, "nm_system_device_setup_static_ip4_config() is not implemented yet for this distribution.\n");
#define IPBITS  (sizeof (guint32) * 8)
	struct in_addr	ip_addr, net_addr, broad_addr, gate_addr;
	int			i, err;
	guint32		prefix = IPBITS;
	char		*iface;
	char		*buf;
	char		*addr, *netmask, *broadcast, *gateway;
	
	
	/* Extract the addresses back into strings */

	ip_addr.s_addr = nm_device_config_get_ip4_address (dev);
	net_addr.s_addr = nm_device_config_get_ip4_netmask (dev);
	broad_addr.s_addr = nm_device_config_get_ip4_broadcast (dev);
	gate_addr.s_addr = nm_device_config_get_ip4_gateway (dev);
	
	addr = g_strdup (inet_ntoa (ip_addr));
	netmask = g_strdup (inet_ntoa (net_addr));
	broadcast = g_strdup (inet_ntoa (broad_addr));
	gateway = g_strdup (inet_ntoa (gate_addr));
	iface = nm_device_get_iface (dev);
	
	/* Flush the device and routes */
	nm_system_device_flush_addresses (dev);
	nm_system_device_flush_routes (dev);

	/* Set the IP/broadcast */
	buf = g_strdup_printf("/sbin/ip addr add local %s dev %s broadcast %s %s", addr, iface, broadcast, iface);
	syslog (LOG_WARNING, "Running: %s", buf);
	/* Set the gateway */
	buf = g_strdup_printf("/sbin/ip route replace default dev %s via %s", iface, gateway);
	syslog (LOG_WARNING, "Running: %s", buf);
	
	/* Inform other computers the we are on network */
	buf = g_strdup_printf ("/sbin/arping -q -A -c 1 -I %s %s", iface, addr);
	syslog (LOG_WARNING, "Running: %s", buf);
	buf = g_strdup_printf ("/sbin/arping -q -U -c 1 -I %s %s", iface, addr);
	syslog (LOG_WARNING, "Running: %s", buf);
	
	return(TRUE);
	
error:
	g_free(buf);
	return(FALSE);
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
 * Kill all DHCP daemons currently running, done at startup
 *
 */
void nm_system_kill_all_dhcp_daemons (void)
{
	nm_spawn_process ("/usr/bin/killall -q dhcpcd");
}

/*
 * nm_system_update_dns
 *
 * Make glibc/nscd aware of any changes to the resolv.conf file by
 * restarting nscd. Only restart if already running.
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
 * Loads any network adapter kernel modules, these should already be loaded
 * by /etc/modules.autoload.d/kernel-2.x
 *
 */
void nm_system_load_device_modules (void)
{
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
	char		 confline[100], dhcpline[100], ipline[100];
	int		 ipa, ipb, ipc, ipd;
 	int		 nNext =  0, bNext = 0, count = 0;
	char		*confToken;
	gboolean	 data_good = FALSE;
	gboolean	 use_dhcp = TRUE;
	guint32	 ip4_address = 0;
	guint32	 ip4_netmask = 0;
	guint32	 ip4_gateway = 0;
	guint32	 ip4_broadcast = 0;

	g_return_if_fail (dev != NULL);

	/* We use DHCP on an interface unless told not to */
	nm_device_config_set_use_dhcp (dev, TRUE);
	nm_device_config_set_ip4_address (dev, 0);
	nm_device_config_set_ip4_gateway (dev, 0);
	nm_device_config_set_ip4_netmask (dev, 0);

	/* Gentoo systems store this information in
	 * /etc/conf.d/net, this is for all interfaces.
	 */

	cfg_file_path = g_strdup_printf ("/etc/conf.d/net");
	if (!cfg_file_path)
		return;

	if (!(file = fopen (cfg_file_path, "r")))
	{
		g_free (cfg_file_path);
		return;
	}
 	sprintf(confline, "iface_%s", nm_device_get_iface (dev));
 	sprintf(dhcpline, "iface_%s=\"dhcp\"", nm_device_get_iface (dev));
	while (fgets (buffer, 499, file) && !feof (file))
	{
		/* Kock off newline if any */
		g_strstrip (buffer);

		if (strncmp (buffer, confline, strlen(confline)) == 0)
			{
			/* Make sure this config file is for this device */
			if (strncmp (&buffer[strlen(confline) - strlen(nm_device_get_iface (dev))], 
				nm_device_get_iface (dev), strlen(nm_device_get_iface (dev))) != 0)
				{
				syslog (LOG_WARNING, "System config file '%s' does not define device '%s'\n",
                                             cfg_file_path, nm_device_get_iface (dev));
				break;
			}
			else
				data_good = TRUE;

			if (strncmp (buffer, dhcpline, strlen(dhcpline)) == 0)
			{
				use_dhcp = TRUE;
			}
			else
			{
				use_dhcp = FALSE;
				confToken = strtok(&buffer[strlen(confline) + 2], " ");
				while (count < 3)
					{
					if (nNext == 1 && bNext == 1)
					{
						ip4_address = inet_addr (confToken);
						count++;
						continue;
					}
					if (strcmp(confToken, "netmask") == 0)
					{
						confToken = strtok(NULL, " ");
						ip4_netmask = inet_addr (confToken);
						count++;
						nNext = 1;
					}
					else if (strcmp(confToken, "broadcast") == 0)
					{
						confToken = strtok(NULL, " ");
						count++;
						bNext = 1;
					}
					else
					{
						ip4_address = inet_addr (confToken);
						count++;
					}
						confToken = strtok(NULL, " ");
					}
				}
			}
		/* If we aren't using dhcp, then try to get the gateway */
		if (!use_dhcp)
			{
			sprintf(ipline, "gateway=\"%s/", nm_device_get_iface (dev));
			if (strncmp(buffer, ipline, strlen(ipline) - 1) == 0)
			{
				sprintf(ipline, "gateway=\"%s/%%d.%%d.%%d.%%d\"", nm_device_get_iface (dev) );
				sscanf(buffer, ipline, &ipa, &ipb, &ipc, &ipd);
				sprintf(ipline, "%d.%d.%d.%d", ipa, ipb, ipc, ipd);
				ip4_gateway = inet_addr (ipline);
			}
		}		
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
		if (ip4_broadcast)
			nm_device_config_set_ip4_broadcast (dev, ip4_broadcast);
	}
}
