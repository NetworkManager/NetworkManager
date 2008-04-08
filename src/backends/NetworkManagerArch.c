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
 * nm_system_device_flush_addresses
 *
 * Flush all network addresses associated with a network device
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
	nm_system_device_flush_addresses (dev);
	nm_system_device_flush_routes (dev);
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
 * nm_system_restart_mdns_responder
 *
 * Restart the multicast DNS responder so that it knows about new
 * network interfaces and IP addresses.
 *
 */
void nm_system_restart_mdns_responder (void)
{
	/* Check if the daemon was already running - do not start a new instance */
	if (g_file_test("/var/run/daemons/avahi-daemon", G_FILE_TEST_EXISTS))
	{
		nm_spawn_process ("/etc/rc.d/avahi-daemon restart");
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
	nm_generic_device_add_ip6_link_address (dev);
}

/*
*   ArchReadConfig
*   
*   Read platform dependant config file and fill hash with relevant info
*/

static GHashTable * ArchReadConfig(const char* file, const char* dev)
{
	gchar *contents=NULL;
	gchar **split_contents=NULL;
	GHashTable *cfg,*ifs;
	guint len;  
	gint i;
	gpointer val;

	if (!g_file_get_contents (file, &contents, NULL, NULL) || (contents == NULL))
	{
		return NULL;
	}

	if (!(split_contents = g_strsplit (contents, "\n", 0)))
	{
		g_free(contents);
		return NULL;
	}

	cfg=g_hash_table_new_full(g_str_hash,g_str_equal,g_free,g_free);
	if (cfg==NULL)
	{
		g_free(contents);
		return NULL;
	}

	ifs=g_hash_table_new_full(g_str_hash,g_str_equal,g_free,g_free);
	if (ifs==NULL)
	{
		g_free(contents);
		g_hash_table_destroy(cfg);
		return NULL;
	}

	/* load hash with key value pairs from config file */
	len = g_strv_length (split_contents);
	for (i = 0; i < len; i++)
	{
		char *line = split_contents[i];
		gchar** splt;

		/* Ignore comments */
		if (!line || (line[0] == ';') || (line[0] == '#'))
		{
			continue;
		}

		line = g_strstrip(line);        

		splt=g_strsplit(line,"=",0);
		if (g_strv_length(splt)==2)
		{
			g_hash_table_insert(cfg,g_strstrip(splt[0]),g_strstrip(splt[1]));
		}
		else
		{
			g_strfreev(splt);
		}

	}

	/* Find our network device */
	if ((val=g_hash_table_lookup(cfg,dev)))
	{
		char hit[128]; 
		gchar** splt;
		gint hits;      

		if (sscanf(val,"\"%[0-9a-zA-Z .]\"",hit))
		{

			splt=g_strsplit(hit," ",0);

			hits=g_strv_length(splt);
			if (hits>1)
			{
				guint j=0;
				while ((hits-=2)>=0)
				{
					g_hash_table_insert(ifs,splt[j],splt[j+1]);
					j+=2;
				}

			}
			else
			{
				/* This interface is probably using DHCP - check this */
				if (!g_ascii_strcasecmp(splt[0],"dhcp"))
				{
					g_hash_table_insert(ifs,g_strdup("dhcp"),g_strdup("true"));
				}
			}

		}
	}

	/* Find out any default route */
	if ((val=g_hash_table_lookup(cfg,"ROUTES")))
	{
		char hit[128];
		gchar** splt;
		gint hits,j;

		if (sscanf(val,"( %[!0-9a-zA-z ] )",hit))
		{

			splt=g_strsplit(hit," ",0);

			hits=g_strv_length(splt);
			for (j=0;j<hits;j++)
			{

				if (splt[j][0]=='!')
				{
					continue;
				}

				if ((val=g_hash_table_lookup(cfg,splt[j])))
				{

					if (sscanf(val," \" default gw %[0-9a-zA-Z.-_] \"",hit))
					{
						g_hash_table_insert(ifs,g_strdup("gateway"),g_strdup(hit));
						break; /* Only one default gw */
					}

				}
			}
			g_strfreev(splt);

		}

	}

	g_hash_table_destroy(cfg);  
	g_strfreev (split_contents);
	g_free(contents);

	return ifs;
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

