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
#include "NetworkManagerGeneric.h"
#include "NetworkManagerSystem.h"
#include "NetworkManagerUtils.h"
#include "nm-device.h"
#include "nm-device-802-3-ethernet.h"
#include "nm-device-802-11-wireless.h"
#include "nm-utils.h"

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
	nm_generic_device_add_ip6_link_address (dev);
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
		g_object_unref (ip4_config);
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
void *nm_system_device_get_system_config (NMDevice *dev)
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
		g_object_unref (sys_data->config);
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

