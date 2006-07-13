/* NetworkManager -- Network link manager
 *
 * Jürg Billeter <juerg@paldo.org>
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
 * (C) Copyright 2004 Red Hat, Inc.
 * (C) Copyright 2006 Jürg Billeter
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <sys/types.h>
#include <signal.h>
#include <arpa/inet.h>
#include <glib/gkeyfile.h>
#include "NetworkManagerSystem.h"
#include "NetworkManagerUtils.h"
#include "nm-device.h"
#include "nm-device-802-3-ethernet.h"
#include "nm-device-802-11-wireless.h"

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
	buf = g_strdup_printf (IP_BINARY_PATH " route add default dev %s", iface);
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
	buf = g_strdup_printf (IP_BINARY_PATH " route add %s dev %s", route, iface);
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


/*
 * nm_system_enable_loopback
 *
 * Bring up the loopback interface
 *
 */
void nm_system_enable_loopback (void)
{
	nm_system_device_set_up_down_with_iface ("lo", TRUE);
	nm_spawn_process (IP_BINARY_PATH " addr add 127.0.0.1/8 brd 127.255.255.255 dev lo scope host label loopback");
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
	nm_spawn_process("/etc/init.d/avahi-daemon try-restart");
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

	if (nm_device_is_802_3_ethernet (dev))
		nm_device_802_3_ethernet_get_address (NM_DEVICE_802_3_ETHERNET (dev), &hw_addr);
	else if (nm_device_is_802_11_wireless (dev))
		nm_device_802_11_wireless_get_address (NM_DEVICE_802_11_WIRELESS (dev), &hw_addr);

	memcpy (eui, &(hw_addr.ether_addr_octet), sizeof (hw_addr.ether_addr_octet));
	memmove (eui+5, eui+3, 3);
	eui[3] = 0xff;
	eui[4] = 0xfe;
	eui[0] ^= 2;

	/* Add the default link-local IPv6 address to a device */
	buf = g_strdup_printf (IP_BINARY_PATH " -6 addr add fe80::%x%02x:%x%02x:%x%02x:%x%02x/64 dev %s",
						eui[0], eui[1], eui[2], eui[3], eui[4], eui[5],
						eui[6], eui[7], nm_device_get_iface (dev));
	nm_spawn_process (buf);
	g_free (buf);
}


typedef struct PaldoSystemConfigData
{
	NMIP4Config *	config;
	gboolean		use_dhcp;
	gboolean		system_disabled;
} PaldoSystemConfigData;

#define PALDO_NETDEVICE_CONFIG_DIR SYSCONFDIR "/network/devices"

static GKeyFile *nm_system_device_get_netdevice_file (NMDevice *dev)
{
	GDir *dir;
	GKeyFile *file;
	const char *entry;
	char *path;
	char *file_udi;

	dir = g_dir_open (PALDO_NETDEVICE_CONFIG_DIR, 0, NULL);
	if (dir == NULL)
		return NULL;

	file = g_key_file_new ();
	
	for (entry = g_dir_read_name (dir); entry != NULL; entry = g_dir_read_name (dir))
	{
		if (!g_str_has_suffix (entry, ".netdevice"))
			continue;
		
		path = g_strdup_printf ("%s/%s", PALDO_NETDEVICE_CONFIG_DIR, entry);
		if (!g_key_file_load_from_file (file, path, G_KEY_FILE_NONE, NULL))
		{
			g_free (path);
			continue;
		}
		g_free (path);

		file_udi = g_key_file_get_string (file, "Network Device", "UDI", NULL);
		if (file_udi == NULL)
			continue;
		
		if (strcmp (file_udi, nm_device_get_udi (dev)) != 0) {
			g_free (file_udi);
			continue;
		}
		
		g_free (file_udi);
		break;
	}
	
	if (entry == NULL)
	{
		g_key_file_free (file);
		file = NULL;
	}
	
	g_dir_close (dir);
	
	return file;
}

static NMIP4Config *netdevice_file_get_ip4_config (GKeyFile *file)
{
	NMIP4Config *ip4_config;
	char **ipaddress_list;
	char **ipaddress;
	char *gateway;
	char *value;
	struct in_addr addr;

	ipaddress_list = g_key_file_get_string_list (file, "Network Device", "IPAddress", NULL, NULL);
	if (ipaddress_list == NULL)
		return NULL;
		
	ip4_config = nm_ip4_config_new ();
	
	for (ipaddress = ipaddress_list; *ipaddress != NULL; ipaddress++)
	{
		char *mask_slash, *mask_str;
		int mask, hostmask;

		mask_slash = strchr (*ipaddress, '/');
		if (mask_slash == NULL)
			continue;
		
		mask_str = mask_slash + 1;
		if (*mask_str == '\0')
			continue;
		*mask_slash = '\0';
		
		if (!inet_aton (*ipaddress, &addr))
			continue;

		mask = atoi (mask_str);
		if (mask < 0 || mask > 32)
			continue;

		hostmask = (1 << (32 - mask)) - 1;
		nm_ip4_config_set_address (ip4_config, addr.s_addr);
		nm_ip4_config_set_netmask (ip4_config, ~hostmask);
		nm_ip4_config_set_broadcast (ip4_config, addr.s_addr | hostmask);
		
		break;
	}
	
	g_strfreev (ipaddress_list);
	
	if (ipaddress == NULL)
	{
		nm_ip4_config_unref (ip4_config);
		return NULL;
	}

	gateway = g_key_file_get_string (file, "Network Device", "Gateway", NULL);
	if (gateway != NULL)
	{
		if (inet_aton (gateway, &addr))
			nm_ip4_config_set_gateway (ip4_config, addr.s_addr);
		
		g_free (gateway);
	}

	ipaddress_list = g_key_file_get_string_list (file, "Network Device", "Nameserver", NULL, NULL);
	if (ipaddress_list != NULL)
	{
		for (ipaddress = ipaddress_list; *ipaddress != NULL; ipaddress++)
		{
			if (!inet_aton (*ipaddress, &addr))
				continue;

			nm_ip4_config_add_nameserver (ip4_config, addr.s_addr);
		}
		
		g_strfreev (ipaddress_list);
	}

	value = g_key_file_get_string (file, "Network Device", "Domain", NULL);
	if (value != NULL)
	{
		nm_ip4_config_add_domain (ip4_config, value);
		g_free (value);
	}

	value = g_key_file_get_string (file, "Network Device", "Hostname", NULL);
	if (value != NULL)
	{
		nm_ip4_config_set_hostname (ip4_config, value);
		g_free (value);
	}
	
	return ip4_config;
}

/*
 * nm_system_device_get_system_config
 *
 * Read in the config file for a device.
 *
 */
void *nm_system_device_get_system_config (NMDevice *dev, NMData *app_data)
{
	PaldoSystemConfigData	*sys_data = NULL;
	GKeyFile				*file;
	char					*method;
	GError				*error = NULL;
	gboolean				value;

	g_return_val_if_fail (dev != NULL, NULL);

	sys_data = g_malloc0 (sizeof (PaldoSystemConfigData));
	sys_data->use_dhcp = TRUE;
	
	file = nm_system_device_get_netdevice_file (dev);
	if (file == NULL)
		return sys_data;
	
	method = g_key_file_get_string (file, "Network Device", "Method", NULL);
	if (method != NULL && strcmp (method, "static") == 0)
	{
		sys_data->config = netdevice_file_get_ip4_config (file);
		
		/* only disable dhcp if valid config has been found */
		if (sys_data->config != NULL)
			sys_data->use_dhcp = FALSE;
	}
	g_free (method);

	value = g_key_file_get_boolean (file, "Network Device", "Disabled", &error);
	if (error == NULL)
		sys_data->system_disabled = value;
	g_clear_error (&error);
	
	g_key_file_free (file);
	
	/* FIXME: add /etc/network/networks/example.network files */

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
	PaldoSystemConfigData *sys_data = (PaldoSystemConfigData *)system_config_data;

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
	PaldoSystemConfigData *sys_data;

	g_return_val_if_fail (dev != NULL, TRUE);

	if ((sys_data = nm_device_get_system_config_data (dev)))
		return sys_data->use_dhcp;

	return TRUE;
}


/*
 * nm_system_device_get_disabled
 *
 * Return whether the distro-specific system config tells us to
 * disable this device.
 *
 */
gboolean nm_system_device_get_disabled (NMDevice *dev)
{
	PaldoSystemConfigData *sys_data;

	g_return_val_if_fail (dev != NULL, FALSE);

	if ((sys_data = nm_device_get_system_config_data (dev)))
		return sys_data->system_disabled;

	return FALSE;
}


NMIP4Config *nm_system_device_new_ip4_system_config (NMDevice *dev)
{
	PaldoSystemConfigData	*sys_data;
	NMIP4Config			*new_config = NULL;

	g_return_val_if_fail (dev != NULL, NULL);

	if ((sys_data = nm_device_get_system_config_data (dev)))
		new_config = nm_ip4_config_copy (sys_data->config);

	return new_config;
}


void nm_system_deactivate_all_dialup (GSList *list)
{
	/* FIXME: implement for paldo */
}


gboolean nm_system_deactivate_dialup (GSList *list, const char *dialup)
{
	/* FIXME: implement for paldo */

	return FALSE;
}


gboolean nm_system_activate_dialup (GSList *list, const char *dialup)
{
	/* FIXME: implement for paldo */

	return FALSE;
}


GSList * nm_system_get_dialup_config (void)
{
	/* FIXME: implement for paldo */

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
unsigned int nm_system_get_mtu (NMDevice *dev)
{
	return 0;
}
