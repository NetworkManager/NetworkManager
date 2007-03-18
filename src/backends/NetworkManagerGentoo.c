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
	nm_spawn_process("/etc/init.d/mDNSResponder stop");
	nm_spawn_process("/etc/init.d/mDNSResponder zap");
	nm_spawn_process("/etc/init.d/mDNSResponder start");
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

typedef struct GentooSystemConfigData
{
	NMIP4Config *	config;
	gboolean		use_dhcp;
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
	char		*cfg_file_path = NULL;
	FILE		*file = NULL;
	char		 buffer[100];
	char		 confline[100], dhcpline[100], ipline[100];
	int		 ipa, ipb, ipc, ipd;
 	int		 nNext =  0, bNext = 0, count = 0;
	char		*confToken;
	gboolean	 data_good = FALSE;
	gboolean	 use_dhcp = TRUE;
	GentooSystemConfigData *sys_data = NULL;
	guint32	 ip4_address = 0;
	guint32	 ip4_netmask = 0;
	guint32	 ip4_gateway = 0;
	guint32	 ip4_broadcast = 0;

	g_return_val_if_fail (dev != NULL, NULL);

	sys_data = g_malloc0 (sizeof (GentooSystemConfigData));
    sys_data->config = nm_device_get_ip4_config(dev);
	/* We use DHCP on an interface unless told not to */
	sys_data->use_dhcp = TRUE;
	nm_device_set_use_dhcp (dev, TRUE);
//	nm_ip4_config_set_address (sys_data->config, 0);
//	nm_ip4_config_set_gateway (sys_data->config, 0);
//	nm_ip4_config_set_netmask (sys_data->config, 0);

	/* Gentoo systems store this information in
	 * /etc/conf.d/net, this is for all interfaces.
	 */

	cfg_file_path = g_strdup_printf ("/etc/conf.d/net");
	if (!cfg_file_path)
		return NULL;

	if (!(file = fopen (cfg_file_path, "r")))
	{
		g_free (cfg_file_path);
		return NULL;
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
				nm_warning ("System config file '%s' does not define device '%s'\n",
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
        nm_warning("data good :-)");
		nm_device_set_use_dhcp (dev, use_dhcp);
		if (ip4_address)
            nm_ip4_config_set_address (sys_data->config, ip4_address);
		if (ip4_gateway)
            nm_ip4_config_set_gateway (sys_data->config, ip4_gateway);
		if (ip4_netmask)
			nm_ip4_config_set_netmask (sys_data->config, ip4_netmask);
		if (ip4_broadcast)
			nm_ip4_config_set_broadcast (sys_data->config, ip4_broadcast);
	}
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
	return 0;
}
