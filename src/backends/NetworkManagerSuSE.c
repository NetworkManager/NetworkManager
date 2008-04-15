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
 * nm_system_device_flush_ip4_routes
 *
 * Flush all routes associated with a network device
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

