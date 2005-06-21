/*
 * NetworkManager -- Network link manager
 *
 * Dan Williams <dcbw@redhat.com>
 * Kay Sievers <kay.sievers@suse.de>
 * Robert Love <rml@novell.com>
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
 * (C) Copyright 2005 SuSE GmbH
 */

#include <stdio.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include "NetworkManagerSystem.h"
#include "NetworkManagerUtils.h"
#include "NetworkManagerDevice.h"
#include "nm-utils.h"
#include "shvar.h"

/*
 * nm_system_init
 *
 * Initializes the distribution-specific system backend
 *
 */
void nm_system_init (void)
{
	/* Kill any dhclients lying around */
	nm_system_kill_all_dhcp_daemons ();
}


/*
 * nm_system_device_flush_routes
 *
 * Flush all routes associated with a network device
 *
 */
void nm_system_device_flush_routes (NMDevice *dev)
{
	g_return_if_fail (dev != NULL);

	/* Not really applicable for test devices */
	if (nm_device_is_test_device (dev))
		return;

	nm_system_device_flush_routes_with_iface (nm_device_get_iface (dev));
}


/*
 * nm_system_device_flush_routes_with_iface
 *
 * Flush all routes associated with a network device
 *
 */
void nm_system_device_flush_routes_with_iface (const char *iface)
{
	char	*buf;

	g_return_if_fail (iface != NULL);

	/* Remove routing table entries */
	buf = g_strdup_printf ("/sbin/ip route flush dev %s", iface);
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
	g_return_if_fail (dev != NULL);

	/* Not really applicable for test devices */
	if (nm_device_is_test_device (dev))
		return;

	nm_system_device_add_default_route_via_device_with_iface (nm_device_get_iface (dev));
}


/*
 * nm_system_device_add_default_route_via_device_with_iface
 *
 * Add default route to the given device
 *
 */
void nm_system_device_add_default_route_via_device_with_iface (const char *iface)
{
	char	*buf;

	g_return_if_fail (iface != NULL);

	/* Add default gateway */
	buf = g_strdup_printf ("/sbin/ip route add default dev %s", iface);
	nm_spawn_process (buf);
	g_free (buf);
}


/*
 * nm_system_device_add_route_via_device_with_iface
 *
 * Add route to the given device
 *
 */
void nm_system_device_add_route_via_device_with_iface (const char *iface, const char *route)
{
	char	*buf;

	g_return_if_fail (iface != NULL);

	/* Add default gateway */
	buf = g_strdup_printf ("/sbin/ip route add %s dev %s", route, iface);
	nm_spawn_process (buf);
	g_free (buf);
}


/*
 * nm_system_device_has_active_routes
 *
 * Find out whether the specified device has any routes in the routing
 * table.
 *
 */
gboolean nm_system_device_has_active_routes (NMDevice *dev)
{
	return (FALSE);
}


/*
 * nm_system_device_flush_addresses
 *
 * Flush all network addresses associated with a network device
 *
 */
void nm_system_device_flush_addresses (NMDevice *dev)
{
	g_return_if_fail (dev != NULL);

	/* Not really applicable for test devices */
	if (nm_device_is_test_device (dev))
		return;

	nm_system_device_flush_addresses_with_iface (nm_device_get_iface (dev));
}


/*
 * nm_system_device_flush_addresses_with_iface
 *
 * Flush all network addresses associated with a network device
 *
 */
void nm_system_device_flush_addresses_with_iface (const char *iface)
{
	char	*buf;

	g_return_if_fail (iface != NULL);

	/* Remove all IP addresses for a device */
	buf = g_strdup_printf ("/sbin/ip address flush dev %s", iface);
	nm_spawn_process (buf);
	g_free (buf);
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
	nm_spawn_process ("/sbin/ip addr add 127.0.0.1/8 brd 127.255.255.255 dev lo scope host label loopback");
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
	/* Remove routing table entries for lo */
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
}


/*
 * nm_system_update_dns
 *
 * Invalidate the nscd host cache, if it exists, since
 * we changed resolv.conf.
 *
 */
void nm_system_update_dns (void)
{
#ifdef NM_NO_NAMED
	if (nm_spawn_process ("/etc/init.d/nscd status") != 0)
		nm_spawn_process ("/etc/init.d/nscd restart");

	nm_info ("Clearing nscd hosts cache.");
	nm_spawn_process ("/usr/sbin/nscd -i hosts");
#else
	nm_spawn_process ("/usr/bin/killall -q nscd");
#endif
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
	FILE 		*fp  = NULL;

	if ((fp = fopen ("/var/run/mdnsd.pid", "rt")))
	{
		int pid;
		int res = fscanf (fp, "%d", &pid);
		fclose (fp);
		if (res == 1)
		{
			nm_info ("Restarting mdnsd.");
			kill (pid, SIGUSR1);
		}
	}
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
	struct ether_addr hw_addr;
	unsigned char eui[8];

	nm_device_get_hw_address(dev, &hw_addr);

	memcpy (eui, &(hw_addr.ether_addr_octet), sizeof (hw_addr.ether_addr_octet));
	memmove (eui+5, eui+3, 3);
	eui[3] = 0xff;
	eui[4] = 0xfe;
	eui[0] ^= 2;

	/* Add the default link-local IPv6 address to a device */
	buf = g_strdup_printf ("/sbin/ip -6 address add fe80::%x%02x:%x%02x:%x%02x:%x%02x/64 dev %s",
						eui[0], eui[1], eui[2], eui[3], eui[4], eui[5],
						eui[6], eui[7], nm_device_get_iface (dev));
	nm_spawn_process (buf);
	g_free (buf);
}


typedef struct SuSESystemConfigData
{
	NMIP4Config *	config;
	gboolean		use_dhcp;
} SuSESystemConfigData;

/*
 * set_ip4_config_from_resolv_conf
 *
 * Add nameservers and search names from a resolv.conf format file.
 *
 */
static void set_ip4_config_from_resolv_conf (const char *filename, NMIP4Config *ip4_config)
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
		if (!line || (line[0] == ';'))
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
 * nm_system_device_get_system_config
 *
 * Read in the config file for a device.
 *
 */
void *nm_system_device_get_system_config (NMDevice *dev)
{
	char *cfg_file_path = NULL;
	char mac[18];
	struct stat statbuf;
	shvarFile *file;
	char *buf = NULL;
	SuSESystemConfigData *sys_data = NULL;
	struct ether_addr addr;
	FILE *f = NULL;
	char buffer[512];
	gboolean error = FALSE;
	unsigned int i;
	int len;
	struct in_addr temp_addr;
	char *ip_str;

	g_return_val_if_fail (dev != NULL, NULL);

	/* SuSE stores this information usually in /etc/sysconfig/network/ifcfg-*-<MAC address> */

	sys_data = g_malloc0 (sizeof (SuSESystemConfigData));
	sys_data->use_dhcp = TRUE;

	memset (&addr, 0, sizeof(addr));
	nm_device_get_hw_address (dev, &addr);
	sprintf (mac, "%02x:%02x:%02x:%02x:%02x:%02x",
			addr.ether_addr_octet[0], addr.ether_addr_octet[1],
			addr.ether_addr_octet[2], addr.ether_addr_octet[3],
			addr.ether_addr_octet[4], addr.ether_addr_octet[5]);
	cfg_file_path = g_strdup_printf (SYSCONFDIR"/sysconfig/network/ifcfg-eth-id-%s", mac);
	if (!cfg_file_path)
		return sys_data;
	if (stat(cfg_file_path, &statbuf) == 0)
		goto found;

	g_free(cfg_file_path);
	cfg_file_path = g_strdup_printf (SYSCONFDIR"/sysconfig/network/ifcfg-wlan-id-%s", mac);
	if (!cfg_file_path)
		return sys_data;
	if (stat(cfg_file_path, &statbuf) == 0)
		goto found;

	g_free(cfg_file_path);
	cfg_file_path = g_strdup_printf (SYSCONFDIR"/sysconfig/network/ifcfg-%s", nm_device_get_iface (dev));
	if (!cfg_file_path)
		return sys_data;
	if (stat(cfg_file_path, &statbuf) == 0)
		goto found;

	g_free (cfg_file_path);
	return sys_data;

found:
	nm_debug ("found config %s for if %s", cfg_file_path, nm_device_get_iface (dev));
	if (!(file = svNewFile (cfg_file_path)))
	{
		g_free (cfg_file_path);
		return sys_data;
	}
	g_free (cfg_file_path);

	if ((buf = svGetValue (file, "BOOTPROTO")))
	{
		nm_debug ("BOOTPROTO=%s", buf);
		if (strcasecmp (buf, "dhcp"))
			sys_data->use_dhcp = FALSE;
		free (buf);
	}

	sys_data->config = nm_ip4_config_new ();

	if (!(sys_data->use_dhcp))
	{
		if ((buf = svGetValue (file, "IPADDR")))
		{
			nm_ip4_config_set_address (sys_data->config, inet_addr (buf));
			free (buf);
		}
		else
		{
			nm_warning ("Network configuration for device '%s' was invalid (non-DHCP configuration, "
						"but no IP address specified.  Will use DHCP instead.", nm_device_get_iface (dev));
			error = TRUE;
			goto out;
		}

		if ((buf = svGetValue (file, "NETMASK")))
		{
			nm_ip4_config_set_netmask (sys_data->config, inet_addr (buf));
			free (buf);
		}
		else
		{
			guint32	ip4addr = nm_ip4_config_get_address (sys_data->config);

			/* Make a default netmask if we have an IP address */
			if (((ntohl (ip4addr) & 0xFF000000) >> 24) <= 127)
				nm_ip4_config_set_netmask (sys_data->config, htonl (0xFF000000));
			else if (((ntohl (ip4addr) & 0xFF000000) >> 24) <= 191)
				nm_ip4_config_set_netmask (sys_data->config, htonl (0xFFFF0000));
			else
				nm_ip4_config_set_netmask (sys_data->config, htonl (0xFFFFFF00));
		}

		if ((buf = svGetValue (file, "BROADCAST")))
		{
			nm_ip4_config_set_broadcast (sys_data->config, inet_addr (buf));
			free (buf);
		}
		else
		{
			guint32 broadcast = ((nm_ip4_config_get_address (sys_data->config) & nm_ip4_config_get_netmask (sys_data->config))
									| ~nm_ip4_config_get_netmask (sys_data->config));
			nm_ip4_config_set_broadcast (sys_data->config, broadcast);
		}

		buf = NULL;
		if ((f = fopen ("/etc/sysconfig/network/routes", "r")))
		{
			while (fgets (buffer, 512, f) && !feof (f))
			{
				buf = strtok(buffer, " ");
				if (strcmp(buf, "default") == 0)
				{
					buf = strtok(NULL, " ");
					if (buf)
						nm_ip4_config_set_gateway (sys_data->config, inet_addr (buf));
					break;
				}
			}
			fclose (f);
		}
		if (!buf)
		{
			nm_warning ("Network configuration for device '%s' was invalid (non-DHCP configuration, "
						"but no gateway specified.  Will use DHCP instead.", nm_device_get_iface (dev));
			error = TRUE;
			goto out;
		}

		set_ip4_config_from_resolv_conf (SYSCONFDIR"/resolv.conf", sys_data->config);
	}

out:
	svCloseFile (file);

	if (error)
	{
		nm_debug ("error, enable dhcp");
		sys_data->use_dhcp = TRUE;
		/* Clear out the config */
		nm_ip4_config_unref (sys_data->config);
		sys_data->config = NULL;
	}

	nm_debug ("------ Config (%s)", nm_device_get_iface (dev));
	nm_debug ("dhcp=%u", sys_data->use_dhcp);

	temp_addr.s_addr = nm_ip4_config_get_address (sys_data->config);
	ip_str = g_strdup (inet_ntoa (temp_addr));
	nm_debug ("addr=%s", ip_str);
	g_free (ip_str);

	temp_addr.s_addr = nm_ip4_config_get_gateway (sys_data->config);
	ip_str = g_strdup (inet_ntoa (temp_addr));
	nm_debug ("gw=%s", ip_str);
	g_free (ip_str);

	temp_addr.s_addr = nm_ip4_config_get_netmask (sys_data->config);
	ip_str = g_strdup (inet_ntoa (temp_addr));
	nm_debug ("mask=%s", ip_str);
	g_free (ip_str);

	len = nm_ip4_config_get_num_nameservers (sys_data->config);
	for (i = 0; i < len; i++)
	{
		guint ns_addr = nm_ip4_config_get_nameserver (sys_data->config, i);

		temp_addr.s_addr = ns_addr;
		ip_str = g_strdup (inet_ntoa (temp_addr));
		nm_debug ("ns_%u=%s", i, ip_str);
		g_free (ip_str);
	}
	nm_debug ("---------------------\n");

	return (void *)sys_data;
}


/*
 * nm_system_device_free_system_config
 *
 * Free stored system config data
 *
 */
void nm_system_device_free_system_config (NMDevice *dev, void *system_config_data)
{
	SuSESystemConfigData *sys_data = (SuSESystemConfigData *)system_config_data;

	g_return_if_fail (dev != NULL);

	if (!sys_data)
		return;

	if (sys_data->config)
		nm_ip4_config_unref (sys_data->config);
}


/*
 * nm_system_device_get_use_dhcp
 *
 * Return whether the distro-specific system config tells us to use
 * dhcp for this device.
 *
 */
gboolean nm_system_device_get_use_dhcp (NMDevice *dev)
{
	SuSESystemConfigData	*sys_data;

	g_return_val_if_fail (dev != NULL, TRUE);

	if ((sys_data = nm_device_get_system_config_data (dev)))
		return sys_data->use_dhcp;

	return TRUE;
}


NMIP4Config *nm_system_device_new_ip4_system_config (NMDevice *dev)
{
	SuSESystemConfigData	*sys_data;
	NMIP4Config		*new_config = NULL;

	g_return_val_if_fail (dev != NULL, NULL);

	if ((sys_data = nm_device_get_system_config_data (dev)))
		new_config = nm_ip4_config_copy (sys_data->config);

	return new_config;
}

