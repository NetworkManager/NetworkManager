/* NetworkManager -- Network link manager
 *
 * Matthew Garrett <mjg59@srcf.ucam.org>
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
#include <signal.h>
#include <arpa/inet.h>
#include "NetworkManagerGeneric.h"
#include "NetworkManagerSystem.h"
#include "NetworkManagerUtils.h"
#include "nm-device.h"
#include "nm-device-802-3-ethernet.h"
#include "nm-device-802-11-wireless.h"
#include "NetworkManagerDialup.h"
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
 * nm_system_device_add_default_route_via_device
 *
 * Add default route to the given device
 *
 */
void nm_system_device_add_default_route_via_device (NMDevice *dev)
{
	nm_generic_device_add_default_route_via_device (dev);
}


/*
 * nm_system_device_add_default_route_via_device_with_iface
 *
 * Add default route to the given device
 *
 */
void nm_system_device_add_default_route_via_device_with_iface (const char *iface)
{
	nm_generic_device_add_default_route_via_device_with_iface (iface);
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
 * nm_system_enable_loopback
 *
 * Bring up the loopback interface
 *
 */
void nm_system_enable_loopback (void)
{
	nm_spawn_process ("/sbin/ifup lo");
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
 * nm_system_delete_default_route
 *
 * Remove the old default route in preparation for a new one
 *
 */
void nm_system_delete_default_route (void)
{
	nm_generic_delete_default_route ();
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
	nm_spawn_process ("/usr/sbin/invoke-rc.d nscd restart");

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
	nm_spawn_process ("/usr/bin/killall -q -USR1 mDNSResponder");
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

typedef struct DebSystemConfigData
{
	NMIP4Config *	config;
	gboolean		use_dhcp;
} DebSystemConfigData;

/*
 * nm_system_device_get_system_config
 *
 * Retrieve any relevant configuration info for a particular device
 * from the system network configuration information.  Clear out existing
 * info before setting stuff too.
 *
 */
void* nm_system_device_get_system_config (NMDevice *dev)
{
	DebSystemConfigData *	sys_data = NULL;
	if_block *curr_device;
	const char *buf;
	gboolean				error = FALSE;

	g_return_val_if_fail (dev != NULL, NULL);

	sys_data = g_malloc0 (sizeof (DebSystemConfigData));
	sys_data->use_dhcp = TRUE;

	ifparser_init();

	/* Make sure this config file is for this device */
	curr_device = ifparser_getif(nm_device_get_iface (dev));
	if (curr_device == NULL)
		goto out;

	buf = ifparser_getkey(curr_device, "inet");
	if (buf)
	{
		if (strcmp (buf, "dhcp")!=0)
			sys_data->use_dhcp = FALSE;
	}

	sys_data->config = nm_ip4_config_new ();

	buf = ifparser_getkey (curr_device, "address");
	if (buf)
		nm_ip4_config_set_address (sys_data->config, inet_addr (buf));

	buf = ifparser_getkey (curr_device, "gateway");
	if (buf)
		nm_ip4_config_set_gateway (sys_data->config, inet_addr (buf));

	buf = ifparser_getkey (curr_device, "netmask");
	if (buf)
		nm_ip4_config_set_netmask (sys_data->config, inet_addr (buf));
	else
	{
		guint32	addr = nm_ip4_config_get_address (sys_data->config);

		/* Make a default netmask if we have an IP address */
		if (((ntohl (addr) & 0xFF000000) >> 24) <= 127)
			nm_ip4_config_set_netmask (sys_data->config, htonl (0xFF000000));
		else if (((ntohl (addr) & 0xFF000000) >> 24) <= 191)
			nm_ip4_config_set_netmask (sys_data->config, htonl (0xFFFF0000));
		else
			nm_ip4_config_set_netmask (sys_data->config, htonl (0xFFFFFF00));
	}

	buf = ifparser_getkey (curr_device, "broadcast");
	if (buf)
		nm_ip4_config_set_broadcast (sys_data->config, inet_addr (buf));
	else
	{
		guint32 broadcast = ((nm_ip4_config_get_address (sys_data->config) & nm_ip4_config_get_netmask (sys_data->config))
								| ~nm_ip4_config_get_netmask (sys_data->config));
		nm_ip4_config_set_broadcast (sys_data->config, broadcast);
	}

        if (!sys_data->use_dhcp)
            nm_generic_set_ip4_config_from_resolv_conf (SYSCONFDIR"/resolv.conf", sys_data->config);

#if 0
	nm_debug ("------ Config (%s)", nm_device_get_iface (dev));
	nm_debug ("    DHCP=%s\n", sys_data->use_dhcp);
	nm_debug ("    ADDR=%d\n", nm_ip4_config_get_address (sys_data->config));
	nm_debug ("    GW=%d\n", nm_ip4_config_get_gateway (sys_data->config));
	nm_debug ("    NM=%d\n", nm_ip4_config_get_netmask (sys_data->config));
	nm_debug ("---------------------\n");
#endif

out:
	ifparser_destroy();
	if (error)
	{
		sys_data->use_dhcp = TRUE;
		/* Clear out the config */
		g_object_unref (sys_data->config);
		sys_data->config = NULL;
	}

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
	DebSystemConfigData *sys_data = (DebSystemConfigData *)system_config_data;

	g_return_if_fail (dev != NULL);

	if (!sys_data)
		return;

	if (sys_data->config)
		g_object_unref (sys_data->config);
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
	DebSystemConfigData	*sys_data;

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


NMIP4Config *nm_system_device_new_ip4_system_config (NMDevice *dev)
{
	DebSystemConfigData	*sys_data;
	NMIP4Config		*new_config = NULL;

	g_return_val_if_fail (dev != NULL, NULL);

	if ((sys_data = nm_device_get_system_config_data (dev)))
		new_config = nm_ip4_config_copy (sys_data->config);

	return new_config;
}

void nm_system_deactivate_all_dialup (GSList *list)
{
	GSList *elt;

	for (elt = list; elt; elt = g_slist_next (elt))
	{
		NMDialUpConfig *config = (NMDialUpConfig *) elt->data;
		char *cmd;

		cmd = g_strdup_printf ("/sbin/ifdown %s", (char *) config->data);
		nm_spawn_process (cmd);
		g_free (cmd);
	}
}

gboolean nm_system_deactivate_dialup (GSList *list, const char *dialup)
{
	GSList *elt;
	gboolean ret = FALSE;

	for (elt = list; elt; elt = g_slist_next (elt))
	{
		NMDialUpConfig *config = (NMDialUpConfig *) elt->data;
		if (strcmp (dialup, config->name) == 0)
		{
			char *cmd;

			nm_info ("Deactivating dialup device %s (%s) ...", dialup, (char *) config->data);
			cmd = g_strdup_printf ("/sbin/ifdown %s", (char *) config->data);
			nm_spawn_process (cmd);
			g_free (cmd);
			ret = TRUE;
			break;
		}
	}

	return ret;
}

gboolean nm_system_activate_dialup (GSList *list, const char *dialup)
{
	GSList *elt;
	gboolean ret = FALSE;

	for (elt = list; elt; elt = g_slist_next (elt))
	{
		NMDialUpConfig *config = (NMDialUpConfig *) elt->data;
		if (strcmp (dialup, config->name) == 0)
		{
			char *cmd;

			nm_info ("Activating dialup device %s (%s) ...", dialup, (char *) config->data);
			cmd = g_strdup_printf ("/sbin/ifup %s", (char *) config->data);
			nm_spawn_process (cmd);
			g_free (cmd);
			ret = TRUE;
			break;
		}
	}

	return ret;
}

GSList * nm_system_get_dialup_config (void)
{
	const char *buf;
	unsigned int i = 0;
	GSList *list = NULL;
	if_block *curr;
	ifparser_init();

	/* FIXME: get all ppp(and others?) lines from /e/n/i here */
	curr = ifparser_getfirst();
	while(curr!=NULL)
	{
		NMDialUpConfig *config;
		if (strcmp(curr->type,"iface")==0) 
		{
			buf = ifparser_getkey(curr,"inet");
			if (buf && strcmp (buf, "ppp")==0)
			{
				config = g_malloc (sizeof (NMDialUpConfig));
				config->name = g_strdup_printf ("Modem (#%d)", i++);
				config->data = g_strdup (curr->name);	/* interface name */

				list = g_slist_append (list, config);

				nm_info ("Found dial up configuration for %s: %s", config->name, (char *) config->data);
			}
		}
		curr = curr->next;
	}
	ifparser_destroy();

	/* Hack: Go back and remove the "(#0)" if there is only one device */
	if (i == 1)
	{
		NMDialUpConfig *config = (NMDialUpConfig *) list->data;
		g_free (config->name);
		config->name = g_strdup ("Modem");
	}

	return list;
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
