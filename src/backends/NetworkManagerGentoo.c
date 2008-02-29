
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <sys/types.h>
#include <signal.h>

#include <arpa/inet.h>
#include "NetworkManagerSystem.h"
#include "NetworkManagerUtils.h"
#include "nm-device.h"
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
	buf = g_strdup_printf (IP_BINARY_PATH " route flush dev %s", iface);
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
	buf = g_strdup_printf (IP_BINARY_PATH " addr flush dev %s", iface);
	nm_spawn_process (buf);
	g_free (buf);
}

#if 0
	/* Alert other computers of our new address */
	temp_addr.s_addr = addr;
	buf = g_strdup_printf ("/sbin/arping -q -A -c 1 -I %s %s", iface, inet_ntoa (temp_addr));
	nm_spawn_process (buf);
	g_free (buf);
	g_usleep (G_USEC_PER_SEC * 2);
	buf = g_strdup_printf ("/sbin/arping -q -U -c 1 -I %s %s", iface, inet_ntoa (temp_addr));
	nm_spawn_process (buf);
	g_free (buf);
#endif

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
	buf = g_strdup_printf (IP_BINARY_PATH " route add %s dev %s", route, iface);
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
	nm_spawn_process("/etc/init.d/net.lo start");
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
	nm_system_device_flush_routes_with_iface ("lo");
}

/*
 * nm_system_delete_default_route
 *
 * Remove the old default route in preparation for a new one
 *
 */
void nm_system_delete_default_route (void)
{
	nm_spawn_process (IP_BINARY_PATH " route del default");
}

/*
 * nm_system_flush_arp_cache
 *
 * Flush all entries in the arp cache.
 *
 */
void nm_system_flush_arp_cache (void)
{
	nm_spawn_process (IP_BINARY_PATH " neigh flush all");
}



/*
 * nm_system_kill_all_dhcp_daemons
 *
 * Kill all DHCP daemons currently running, done at startup
 *
 */
void nm_system_kill_all_dhcp_daemons (void)
{
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
 #ifdef NM_NO_NAMED
	if (nm_spawn_process ("/etc/init.d/nscd status") == 0)
		nm_spawn_process ("/etc/init.d/nscd restart");
 #else
	nm_spawn_process("/usr/bin/killall -q nscd");
 #endif	
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

	// 
	fp = fopen ("/var/run/mDNSResponder.pid", "rt");

	/* Is the mDNS daemon running? */
	/* if (g_file_test("/var/run/mDNSResponder.pid", G_FILE_TEST_EXISTS)) */
	if (fp)
	{
		res = fscanf (fp, "%d", &pid);
		if (res == 1)
		{
			nm_info ("Restarting mDNSResponder (pid=%d).", pid);
			kill (pid, SIGUSR1);
		}
	
		fclose (fp);
	}
	/* Apple's mDNSResponder */
	if (g_file_test("/var/run/mDNSResponderPosix.pid", G_FILE_TEST_EXISTS))
	{
		nm_info("Restarting mDNSResponderPosix");
		nm_spawn_process("/etc/init.d/mDNSResponderPosix restart");
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
	
	nm_device_get_hw_address (dev, &hw_addr);
	memcpy (eui, &(hw_addr.ether_addr_octet), sizeof (hw_addr.ether_addr_octet));
	memmove (eui+5, eui+3, 3);
	eui[3] = 0xff;
	eui[4] = 0xfe;
	eui[0] ^= 2;
	
	/* Add the default link-local IPv6 address to a device */
	buf = g_strdup_printf(IP_BINARY_PATH " -6 addr add fe80::%x%02x:%x%02x:%x%02x:%x%02x/64 dev %s", 
						eui[0], eui[1], eui[2], eui[3], eui[4], eui[5], 
						eui[6], eui[7], nm_device_get_iface(dev));
	nm_spawn_process(buf);
	g_free(buf);
}
/* Get the array associated with the key, and leave the current pointer
 * pointing at the line containing the key.  The char** returned MUST
 * be freed by the caller.
 */
gchar **
svGetArray(shvarFile *s, const char *key)
{
	gchar **values = NULL, **lines, *line, *value;
	GList *restore;
	int len, strvlen, i, j;

	g_assert(s);
	g_assert(key);

	/* Attempt to do things the easy way first */
	line = svGetValue(s, key);
	if (!line)
		return NULL;
	
	restore = s->current;
	
	g_strstrip(strtok(line, "#"));	/* Remove comments and whitespace */
	
	if (line[0] != '(')
	{
		/* This isn't an array, so pretend it's a one item array. */
		values = g_renew(char*, values, 2);
		values[0] = line;
		values[1] = NULL;
		return values;
	}
	
	while(!strrchr(line, ')'))
	{
		s->current = s->current->next;
		value = g_strjoin(" ", line, g_strstrip(strtok(s->current->data, "#")), NULL);
		g_free(line);
		line = value;
		value = NULL;
	}
	
	lines = g_strsplit(line, "\"", 0);
	
	strvlen = g_strv_length(lines);
	if (strvlen == 0)
	{
		/* didn't split, something's wrong */
		g_free(line);
		return NULL;
	}
	
	j = 0;
	for (i = 0; i <= strvlen - 1; i++)
	{
		value = lines[i];
		len = strlen(g_strstrip(value));
		if ((value[0] == '(') || (value[0] == ')') || (len == 0))
			continue;
		
		values = g_renew(char*, values, j + 2);
		values[j+1] = NULL;
		values[j++] = g_strdup(value);
	}
	
	g_free(line);
	g_strfreev(lines);
	s->current = restore;
	
	return values;
}

/*
*   GentooReadConfig
*   
*   Most of this comes from the arch backend, no need to re-invent.
*   Read platform dependant config file and fill hash with relevant info
*/
static GHashTable * GentooReadConfig(const char* dev)
{
	GHashTable *ifs;
	shvarFile	*file;
	int len, hits, i = 0;
	guint32 maskval;
	gchar buf[16], *value, *cidrprefix, *gateway;
	gchar *config_str, *iface_str, *route_str, *mtu_str, *dnsserver_str, *dnssearch_str;	/* Lookup keys */
	gchar **conf, **config = NULL, **routes = NULL;
	struct in_addr mask;
	
	file = svNewFile(SYSCONFDIR"/conf.d/net");
	if (!file)
		return NULL;
	
	ifs = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	if (ifs == NULL)
	{
		nm_debug("Unable to create g_hash_table.");
		svCloseFile(file);
		return NULL;
	}
	
	/* Keys we will use for lookups later */
	config_str = g_strdup_printf("config_%s", dev);
	iface_str = g_strdup_printf("iface_%s", dev);
	route_str = g_strdup_printf("routes_%s", dev);
	mtu_str = g_strdup_printf("mtu_%s", dev);
	dnsserver_str = g_strdup_printf("dns_servers_%s", dev);
	dnssearch_str = g_strdup_printf("dns_search_%s", dev);
	
	
	if ((config = svGetArray(file, iface_str)))
	{
		/* This isn't tested, (or supported, really) so hopefully it works */
		nm_info("You are using a deprecated configuration syntax for %s.", dev);
		nm_info("You are advised to read /etc/conf.d/net.example and upgrade it accordingly.");
		value = svGetValue(file, "gateway");
		if ((value) && (gateway = strstr(value, dev)) && strtok(gateway, "/"))
		{
			/* Is it possible to specify multiple gateways using this variable? */
			gateway = strtok(NULL, "/");
			routes = g_renew(char*, routes, 2);
			routes[0] = g_strdup_printf("default via %s", gateway);
			routes[1] = NULL;
			g_free(value);
		}
	}
	else
	{
		config = svGetArray(file, config_str);
		routes = svGetArray(file, route_str);
	}
	
	
	if ((config) && g_ascii_strcasecmp(config[0], "dhcp"))
	{
		nm_debug("Found %s in %s.", config_str, SYSCONFDIR"/conf.d/net");
	
		if (!g_ascii_strcasecmp(config[0], "null"))
		{
			nm_debug("Config disables device %s.", dev);
			g_hash_table_insert(ifs, g_strdup("disabled"), g_strdup("true"));
		}
		else
		{
			/* TODO: Handle "noop". */
			conf = g_strsplit(config[0], " ", 0);
			hits = g_strv_length(conf);
			
			strtok(conf[0], "/");
			if ((cidrprefix = strtok(NULL, "/")))
			{
				maskval = 0xffffffff;
				maskval <<= (32 - atoi(cidrprefix));
				mask.s_addr = htonl(maskval);
				g_hash_table_insert(ifs, g_strdup("netmask"), g_strdup(inet_ntoa(mask)));
			}
			
			
			if ((hits > 0) && inet_aton(conf[0], &mask))
			{
				g_hash_table_insert(ifs, g_strdup(dev), g_strdup(conf[i++]));
				while ((hits -= 2) > 0)
				{
					g_hash_table_insert(ifs, g_strdup(conf[i]), g_strdup(conf[i+1]));
					i += 2;
				}
			}
			else
			{
				nm_debug("Unhandled configuration. Switching to DHCP.");
				nm_debug("\t%s = %s", config_str, config[0]);
				g_hash_table_insert(ifs, g_strdup("dhcp"), g_strdup("true"));
			}
			g_strfreev(conf);
		}
	}
	else
	{
		nm_debug("Enabling DHCP for device %s.", dev);
		g_hash_table_insert(ifs, g_strdup("dhcp"), g_strdup("true"));
	}
	
	g_strfreev(config);
	
	if (routes)
	{
		nm_debug("Found %s in config.", route_str);
		
		len = g_strv_length(routes);
		for (i = 0; i < len; i++)
		{
			if (!sscanf(routes[i], "default via %[0-9.:]", buf))
				continue;

			g_hash_table_insert(ifs,g_strdup("gateway"),g_strdup( (char*) buf));
		}
	}
	
	g_strfreev(routes);
	
	if ((value = svGetValue(file, mtu_str)))
	{
		nm_debug("Found %s in config.", mtu_str);
		g_hash_table_insert(ifs, g_strdup("mtu"), g_strdup(value));
	}
	
	g_free(value);
	
	if (!(value = svGetValue(file, dnsserver_str)))
	{
		value = svGetValue(file, "dns_servers");
	}
	if (value)
	{
		nm_debug("Found DNS nameservers in config.");
		g_hash_table_insert(ifs, g_strdup("nameservers"), g_strdup(value));
	}
	
	g_free(value);
	
	if (!(value = svGetValue(file, dnssearch_str)))
	{
		value = svGetValue(file, "dns_search");
	}
	if (value)
	{
		nm_debug("Found DNS search in config.");
		g_hash_table_insert(ifs, g_strdup("dnssearch"), g_strdup(value));
	}

	g_free(value);
	svCloseFile(file);
	
	if ((file = svNewFile(SYSCONFDIR"/conf.d/hostname")))
	{	
		if ((value = svGetValue(file, "HOSTNAME")) && (strlen(value) > 0))
		{
			nm_debug("Found hostname.");
			g_hash_table_insert(ifs, g_strdup("hostname"), g_strdup(value));
		}
		
		g_free(value);
		svCloseFile(file);
	}

		
	g_free(config_str);
	g_free(iface_str);
	g_free(route_str);
	g_free(mtu_str);
	g_free(dnsserver_str);
	g_free(dnssearch_str);
	
	return ifs;
}

typedef struct GentooSystemConfigData
{
	NMIP4Config *	config;
	gboolean		use_dhcp;
	gboolean		system_disabled;
	guint32		mtu;
} GentooSystemConfigData;

/*
 * nm_system_device_get_system_config
 *
 * Retrieve any relevant configuration info for a particular device
 * from the system network configuration information.  Clear out existing
 * info before setting stuff too.
 *
 */
void *nm_system_device_get_system_config (NMDevice *dev, NMData *app_data)
{
	GHashTable* ifh;
	gpointer val;
	gchar **strarr;
	GentooSystemConfigData*   sys_data = NULL;
	int len, i;

	g_return_val_if_fail(dev != NULL, NULL);
	
	sys_data = g_malloc0(sizeof (GentooSystemConfigData));
	sys_data->use_dhcp = TRUE;
	sys_data->system_disabled = FALSE;
	sys_data->mtu = 0;
	sys_data->config=NULL;

	ifh = GentooReadConfig(nm_device_get_iface(dev));
	if (ifh == NULL)
	{
		g_free(sys_data);
		return NULL;
	}
	
	val = g_hash_table_lookup(ifh, "disabled");
	if (val)
	{
		if (!strcasecmp (val, "true"))
		{
			nm_info ("System configuration disables device %s", nm_device_get_iface (dev));
			sys_data->system_disabled = TRUE;
		}
	}
	
	val = g_hash_table_lookup(ifh, "mtu");
	if (val)
	{
		guint32 mtu;
		
		mtu = strtoul(val, NULL, 10);
		if (mtu > 500 && mtu < INT_MAX)
		{
			nm_debug("System configuration specifies a MTU of %i for device %s", mtu, nm_device_get_iface(dev));
			sys_data->mtu = mtu;
		}
	}
	val = g_hash_table_lookup(ifh, "hostname");
	if (val)
	{
		nm_ip4_config_set_hostname(sys_data->config, val);
	}
	
	val = g_hash_table_lookup(ifh, nm_device_get_iface(dev));
	if (val && !g_hash_table_lookup(ifh, "dhcp"))
	{
		/* This device does not use DHCP */

		sys_data->use_dhcp=FALSE;
		sys_data->config = nm_ip4_config_new();

		nm_ip4_config_set_address (sys_data->config, inet_addr (val));

		val = g_hash_table_lookup(ifh, "gateway");
		if (val)
			nm_ip4_config_set_gateway (sys_data->config, inet_addr (val));
		else
		{
			nm_info ("Network configuration for device '%s' does not specify a gateway but is "
				 "statically configured (non-DHCP).", nm_device_get_iface (dev));
		}

		val = g_hash_table_lookup(ifh, "netmask");
		if (val)
			nm_ip4_config_set_netmask (sys_data->config, inet_addr (val));
		else
		{
			guint32 addr = nm_ip4_config_get_address (sys_data->config);

			/* Make a default netmask if we have an IP address */
			if (((ntohl (addr) & 0xFF000000) >> 24) <= 127)
				nm_ip4_config_set_netmask (sys_data->config, htonl (0xFF000000));
			else if (((ntohl (addr) & 0xFF000000) >> 24) <= 191)
				nm_ip4_config_set_netmask (sys_data->config, htonl (0xFFFF0000));
			else
				nm_ip4_config_set_netmask (sys_data->config, htonl (0xFFFFFF00));
		}

		val = g_hash_table_lookup(ifh, "broadcast");
		if (val)
			nm_ip4_config_set_broadcast (sys_data->config, inet_addr (val));
		else if ((val = g_hash_table_lookup(ifh, "brd")))
			nm_ip4_config_set_broadcast (sys_data->config, inet_addr (val));
		else
		{
			guint32 broadcast = ((nm_ip4_config_get_address (sys_data->config) & nm_ip4_config_get_netmask (sys_data->config))
							 | ~nm_ip4_config_get_netmask (sys_data->config));
			nm_ip4_config_set_broadcast (sys_data->config, broadcast);
		}
		
		val = g_hash_table_lookup(ifh, "nameservers");
		if (val)
		{
			nm_debug("Using DNS nameservers \"%s\" from config for device %s.", val, nm_device_get_iface(dev));
			if ((strarr = g_strsplit(val, " ", 0)))
			{
				len = g_strv_length(strarr);
				for(i = 0; i < len; i++)
				{
					guint32 addr = (guint32) (inet_addr (strarr[i]));

					if (addr != (guint32) -1)
						nm_ip4_config_add_nameserver(sys_data->config, addr);
				}
				
				g_strfreev(strarr);
			}
			else
			{
				guint32 addr = (guint32) (inet_addr (val));

				if (addr != (guint32) -1)
					nm_ip4_config_add_nameserver(sys_data->config, addr);
			}
		}

		val = g_hash_table_lookup(ifh, "dnssearch");
		if (val)
		{
			nm_debug("Using DNS search \"%s\" from config for device %s.", val, nm_device_get_iface(dev));
			if ((strarr = g_strsplit(val, " ", 0)))
			{
				len = g_strv_length(strarr);
				for(i = 0; i < len; i++)
				{
					if (strarr[i])
						nm_ip4_config_add_domain(sys_data->config, strarr[i]);
				}
				
				g_strfreev(strarr);
			}
			else
			{
				nm_ip4_config_add_domain(sys_data->config, val);
			}
		}
		
		nm_ip4_config_set_mtu (sys_data->config, sys_data->mtu);

#if 0
		{
			int j;
			nm_debug ("------ Config (%s)", nm_device_get_iface (dev));
			nm_debug ("    ADDR=%d", nm_ip4_config_get_address (sys_data->config));
			nm_debug ("    GW  =%d", nm_ip4_config_get_gateway (sys_data->config));
			nm_debug ("    NM  =%d", nm_ip4_config_get_netmask (sys_data->config));
			nm_debug ("    NSs =%d",nm_ip4_config_get_num_nameservers(sys_data->config));
			for (j=0;j<nm_ip4_config_get_num_nameservers(sys_data->config);j++)
			{
				nm_debug ("    NS =%d",nm_ip4_config_get_nameserver(sys_data->config,j));
			}
			nm_debug ("---------------------\n");
		}
#endif

	}
	
	g_hash_table_destroy(ifh);


	return (void *)sys_data;
}

/*
 * nm_system_device_add_default_route_via_device
 *
 * Flush all routes associated with a network device
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
	buf = g_strdup_printf (IP_BINARY_PATH " route add default dev %s", iface);
	nm_spawn_process (buf);
	g_free (buf);
}
 
void nm_system_device_free_system_config (NMDevice *dev, void *system_config_data)
{
	GentooSystemConfigData *sys_data = (GentooSystemConfigData *)system_config_data;

	g_return_if_fail (dev != NULL);

	if (!sys_data)
		return;

	if (sys_data->config)
		nm_ip4_config_unref (sys_data->config);

}

NMIP4Config *nm_system_device_new_ip4_system_config (NMDevice *dev)
{
	GentooSystemConfigData	*sys_data;
	NMIP4Config		*new_config = NULL;

	g_return_val_if_fail (dev != NULL, NULL);

	if ((sys_data = nm_device_get_system_config_data (dev)))
		new_config = nm_ip4_config_copy (sys_data->config);

	return new_config;
}

gboolean nm_system_device_get_use_dhcp (NMDevice *dev)
{
	GentooSystemConfigData	*sys_data;

	g_return_val_if_fail (dev != NULL, TRUE);

	if ((sys_data = nm_device_get_system_config_data (dev)))
		return sys_data->use_dhcp;

	return TRUE;
}

/*
 * nm_system_device_get_disabled
 *
 * Return whether the distro-specific system config tells us to use
 * dhcp for this device.
 *
 */
gboolean nm_system_device_get_disabled (NMDevice *dev)
{
	GentooSystemConfigData *sys_data;

	g_return_val_if_fail (dev != NULL, FALSE);

	if ((sys_data = nm_device_get_system_config_data (dev)))
		return sys_data->system_disabled;

	return FALSE;
}

void nm_system_deactivate_all_dialup (GSList *list)
{
}

gboolean nm_system_deactivate_dialup (GSList *list, const char *dialup)
{
            return FALSE;
}

gboolean nm_system_activate_dialup (GSList *list, const char *dialup)
{
            return FALSE;
}

/*
 *  nm_system_get_dialup_config
 *  
 *  Enumerate dial up options on this system, allocate NMDialUpConfig's,
 *  fill them out, and return.
 *  
 */
GSList * nm_system_get_dialup_config (void)
{
            return NULL;
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
	char *h_name = NULL;
	const char *hostname;

	g_return_if_fail (config != NULL);

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

	g_free (h_name);
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
 * nm_system_get_mtu
 *
 * Return a user-provided or system-mandated MTU for this device or zero if
 * no such MTU is provided.
 */
guint32 nm_system_get_mtu (NMDevice *dev)
{
	GentooSystemConfigData *sys_data;

	g_return_val_if_fail (dev != NULL, 0);

	if ((sys_data = nm_device_get_system_config_data (dev)))
		return sys_data->mtu;

	return 0;
}
