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
 * (C) Copyright 2005-2006 SuSE GmbH
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>

#include "NetworkManagerGeneric.h"
#include "NetworkManagerSystem.h"
#include "NetworkManagerUtils.h"
#include "nm-device.h"
#include "NetworkManagerPolicy.h"
#include "nm-device-802-3-ethernet.h"
#include "nm-device-802-11-wireless.h"
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
	nm_generic_init ();
}


/*
 * nm_system_device_flush_routes
 *
 * Flush all routes associated with a network device
 *
 */
void nm_system_device_flush_routes (NMDevice *dev)
{
	nm_generic_device_flush_routes (dev);
}


/*
 * nm_system_device_flush_routes_with_iface
 *
 * Flush all routes associated with a network device
 *
 */
void nm_system_device_flush_routes_with_iface (const char *iface)
{
	nm_generic_device_flush_routes_with_iface (iface);
}


/*
 * nm_system_device_replace_default_route
 *
 * Add default route to the given device
 *
 */
void
nm_system_device_replace_default_route (const char *iface,
                                        guint32 gw,
                                        guint32 mss)
{
	nm_generic_device_replace_default_route (iface, gw, mss);
}


/*
 * nm_system_device_add_route_via_device_with_iface
 *
 * Add route to the given device
 *
 */
void nm_system_device_add_route_via_device_with_iface (const char *iface, const char *route)
{
	nm_generic_device_add_route_via_device_with_iface (iface, route);
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
	return FALSE;
}


/*
 * nm_system_device_flush_addresses
 *
 * Flush all network addresses associated with a network device
 *
 */
void nm_system_device_flush_addresses (NMDevice *dev)
{
	nm_generic_device_flush_addresses (dev);
}


/*
 * nm_system_device_flush_addresses_with_iface
 *
 * Flush all network addresses associated with a network device
 *
 */
void nm_system_device_flush_addresses_with_iface (const char *iface)
{
	nm_generic_device_flush_addresses_with_iface (iface);
}


/*
 * nm_system_enable_loopback
 *
 * Bring up the loopback interface
 *
 */
void nm_system_enable_loopback (void)
{
	nm_generic_enable_loopback ();
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
	nm_info ("Clearing nscd hosts cache.");
	nm_spawn_process ("/usr/sbin/nscd -i hosts");
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
	pid_t pid;
	FILE *fp;
	int res;

	fp = fopen ("/var/run/mdnsd.pid", "rt");
	if (!fp)
		return;

	res = fscanf (fp, "%d", &pid);
	if (res == 1)
	{
		nm_info ("Restarting mdnsd (pid=%d).", pid);
		kill (pid, SIGUSR1);
	}

	fclose (fp);
}


/*
 * nm_system_device_add_ip6_link_address
 *
 * Add a default link-local IPv6 address to a device.
 *
 */
void nm_system_device_add_ip6_link_address (NMDevice *dev)
{
	nm_generic_device_add_ip6_link_address (dev);
}


typedef struct SuSEDeviceConfigData
{
	NMIP4Config *	config;
	gboolean		use_dhcp;
	gboolean		system_disabled;
	guint32		mtu;
} SuSEDeviceConfigData;


/*
 * nm_system_device_get_system_config
 *
 * Read in the config file for a device.
 *
 * SuSE stores this information in /etc/sysconfig/network/ifcfg-*-<MAC address>
 *
 */
void *nm_system_device_get_system_config (NMDevice *dev)
{
	char *cfg_file_path = NULL;
	char mac[18];
	struct stat statbuf;
	shvarFile *file;
	char *buf = NULL;
	SuSEDeviceConfigData *sys_data = NULL;
	struct ether_addr hw_addr;
	FILE *f = NULL;
	char buffer[512];
	gboolean error = FALSE;
	int i, len;
	struct in_addr temp_addr;
	char *ip_str;

	g_return_val_if_fail (dev != NULL, NULL);

	sys_data = g_malloc0 (sizeof (SuSEDeviceConfigData));
	sys_data->use_dhcp = TRUE;

	if (NM_IS_DEVICE_802_3_ETHERNET (dev))
		nm_device_802_3_ethernet_get_address (NM_DEVICE_802_3_ETHERNET (dev), &hw_addr);
	else if (NM_IS_DEVICE_802_11_WIRELESS (dev))
		nm_device_802_11_wireless_get_address (NM_DEVICE_802_11_WIRELESS (dev), &hw_addr);

	sprintf (mac, "%02x:%02x:%02x:%02x:%02x:%02x",
			hw_addr.ether_addr_octet[0], hw_addr.ether_addr_octet[1],
			hw_addr.ether_addr_octet[2], hw_addr.ether_addr_octet[3],
			hw_addr.ether_addr_octet[4], hw_addr.ether_addr_octet[5]);
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
	nm_debug ("found config '%s' for interface '%s'", cfg_file_path, nm_device_get_iface (dev));
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

	if ((buf = svGetValue (file, "NM_CONTROLLED")))
	{
		nm_debug ("NM_CONTROLLED=%s", buf);
		if (!strcasecmp (buf, "no"))
		{
			nm_info ("System configuration disables device %s", nm_device_get_iface (dev));
			sys_data->system_disabled = TRUE;
		}
		free (buf);
	}

	if ((buf = svGetValue (file, "MTU")))
	{
		guint32 mtu;

		errno = 0;
		mtu = strtoul (buf, NULL, 10);
		if (!errno && mtu > 500 && mtu < INT_MAX)
			sys_data->mtu = mtu;
		free (buf);
	}

	sys_data->config = nm_ip4_config_new ();

	if (!sys_data->use_dhcp || sys_data->system_disabled)
	{
		buf = svGetValue (file, "IPADDR");
		if (buf)
		{
			struct in_addr ip;
			int ret;

			ret = inet_aton (buf, &ip);
			if (ret)
				nm_ip4_config_set_address (sys_data->config, ip.s_addr);
			else
				error = TRUE;
			free (buf);
		}
		else
			error = TRUE;

		if (error)
		{
			nm_warning ("Network configuration for device '%s' was invalid: Non-DHCP configuration, "
					  "but no IP address specified.  Will use DHCP instead.", nm_device_get_iface (dev));
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

		nm_ip4_config_set_mtu (sys_data->config, sys_data->mtu);

		buf = NULL;
		if ((f = fopen (SYSCONFDIR"/sysconfig/network/routes", "r")))
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
			nm_info ("Network configuration for device '%s' does not specify a gateway but is "
				 "statically configured (non-DHCP).", nm_device_get_iface (dev));

		nm_generic_set_ip4_config_from_resolv_conf (SYSCONFDIR"/resolv.conf", sys_data->config);
	}

out:
	svCloseFile (file);

	if (error)
	{
		nm_debug ("error, enable dhcp");
		sys_data->use_dhcp = TRUE;
		/* Clear out the config */
		g_object_unref (sys_data->config);
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

	if (sys_data->mtu)
		nm_debug ("mtu=%u", sys_data->mtu);

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

	return sys_data;
}


/*
 * nm_system_device_free_system_config
 *
 * Free stored system config data
 *
 */
void nm_system_device_free_system_config (NMDevice *dev, void *system_config_data)
{
	SuSEDeviceConfigData *sys_data = (SuSEDeviceConfigData *)system_config_data;

	g_return_if_fail (dev != NULL);

	if (!sys_data)
		return;

	if (sys_data->config)
		g_object_unref (sys_data->config);
}


/*
 * nm_system_device_get_disabled
 *
 * Return whether the distribution has flagged this device as disabled.
 *
 */
gboolean nm_system_device_get_disabled (NMDevice *dev)
{
	SuSEDeviceConfigData *sys_data;

	g_return_val_if_fail (dev != NULL, FALSE);

	if ((sys_data = nm_device_get_system_config_data (dev)))
		return sys_data->system_disabled;

	return FALSE;
}


/*
 * nm_system_activate_nis
 *
 * set up the nis domain and write a yp.conf
 *
 */
void nm_system_activate_nis (NMIP4Config *config)
{
	shvarFile *file;
	const char *nis_domain;
	char *name, *buf;
	struct in_addr	temp_addr;
	int i;
	FILE *ypconf = NULL;

	g_return_if_fail (config != NULL);

	nis_domain = nm_ip4_config_get_nis_domain(config);

	name = g_strdup_printf (SYSCONFDIR"/sysconfig/network/dhcp");
	file = svNewFile (name);
	if (!file)
		goto out_gfree;

	buf = svGetValue (file, "DHCLIENT_SET_DOMAINNAME");
	if (!buf)
		goto out_close;

	if ((!strcmp (buf, "yes")) && nis_domain && (setdomainname (nis_domain, strlen (nis_domain)) < 0))
			nm_warning ("Could not set nis domain name.");
	free (buf);

	buf = svGetValue (file, "DHCLIENT_MODIFY_NIS_CONF");
	if (!buf)
		goto out_close;

	if (!strcmp (buf, "yes")) {
		int num_nis_servers;

		num_nis_servers = nm_ip4_config_get_num_nis_servers(config);
		if (num_nis_servers > 0)
		{
			struct stat sb;

			/* write out yp.conf and restart the daemon */

			ypconf = fopen ("/etc/yp.conf", "w");

			if (ypconf)
			{
				fprintf (ypconf, "# generated by NetworkManager, do not edit!\n\n");
				for (i = 0; i < num_nis_servers; i++) {
					temp_addr.s_addr = nm_ip4_config_get_nis_server (config, i);
					fprintf (ypconf, "domain %s server %s\n", nis_domain, inet_ntoa (temp_addr));
				}
				fprintf (ypconf, "\n");
				fclose (ypconf);
			} else
				nm_warning ("Could not commit NIS changes to /etc/yp.conf.");

			if (stat ("/usr/sbin/rcautofs", &sb) != -1)
			{
				nm_info ("Restarting autofs.");
				nm_spawn_process ("/usr/sbin/rcautofs reload");
			}
		}
	}
	free (buf);

out_close:
	svCloseFile (file);
out_gfree:
	g_free (name);
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
	char *filename, *h_name = NULL, *buf;
	shvarFile *file;

	g_return_if_fail (config != NULL);

	filename = g_strdup_printf (SYSCONFDIR"/sysconfig/network/dhcp");
	file = svNewFile (filename);
	if (!file)
		goto out_gfree;

	buf = svGetValue (file, "DHCLIENT_SET_HOSTNAME");
	if (!buf)
		goto out_close;

	if (!strcmp (buf, "yes")) 
	{
		const char *hostname;

		hostname = nm_ip4_config_get_hostname (config);
		if (!hostname)
		{
			struct in_addr temp_addr;
			struct hostent *host;

			/* try to get hostname via dns */
			temp_addr.s_addr = nm_ip4_config_get_address (config);
			host = gethostbyaddr ((char *) &temp_addr, sizeof (temp_addr), AF_INET);
			if (host)
			{
				h_name = g_strdup (host->h_name);
				hostname = strtok (h_name, ".");
			}
			else
				nm_warning ("nm_system_set_hostname(): gethostbyaddr failed, h_errno = %d", h_errno);
		}

		if (hostname)
		{
			nm_info ("Setting hostname to '%s'", hostname);
			if (sethostname (hostname, strlen (hostname)) < 0)
				nm_warning ("Could not set hostname.");
		}
	}

	g_free (h_name);
	free (buf);
out_close:
	svCloseFile (file);
out_gfree:
	g_free (filename);
}

/*
 * nm_system_should_modify_resolv_conf
 *
 * Can NM update resolv.conf, or is it locked down?
 */
gboolean nm_system_should_modify_resolv_conf (void)
{
	char *name, *buf;
	shvarFile *file;
	gboolean ret = TRUE;

	name = g_strdup_printf (SYSCONFDIR"/sysconfig/network/dhcp");
	file = svNewFile (name);
	if (!file)
		goto out_gfree;

	buf = svGetValue (file, "DHCLIENT_MODIFY_RESOLV_CONF");
	if (!buf)
		goto out_close;

	if (strcmp (buf, "no") == 0)
		ret = FALSE;

	free (buf);
out_close:
	svCloseFile (file);
out_gfree:
	g_free (name);

	return ret;
}

