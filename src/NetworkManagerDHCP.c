/* NetworkManager -- Network link manager
 *
 * Dan Williams <dcbw@redhat.com>
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <syslog.h>
#include "NetworkManager.h"
#include "NetworkManagerMain.h"
#include "NetworkManagerDevice.h"
#include "NetworkManagerDevicePrivate.h"
#include "NetworkManagerDHCP.h"
#include "NetworkManagerSystem.h"
#include "NetworkManagerPolicy.h"
#include "nm-named-manager.h"
#include "../dhcpcd/client.h"

extern gboolean get_autoip (NMDevice *dev, struct in_addr *out_ip);

static void set_nameservers (NMDevice *dev, void *data, int len)
{
	int i;
	GList *elt;
	GError *error = NULL;

	/* Reset our nameserver list */
	for (elt = dev->app_data->nameserver_ids; elt; elt = elt->next)
	{
		if (!nm_named_manager_remove_nameserver_ipv4 (dev->app_data->named,
							      GPOINTER_TO_UINT (elt->data),
							      &error))
		{
			syslog (LOG_ERR, G_GNUC_PRETTY_FUNCTION ": Couldn't remove nameserver: %s\n", error->message);
			g_clear_error (&error);
		}
	}
	g_list_free (dev->app_data->nameserver_ids);
	dev->app_data->nameserver_ids = NULL;
	
	for (i = 0; data && (i < len-3); i += 4)
	{
		char *nameserver;
		guint id;
		nameserver = g_strdup_printf ("%u.%u.%u.%u",
					      ((unsigned char *)data)[i],
					      ((unsigned char *)data)[i+1],
					      ((unsigned char *)data)[i+2],
					      ((unsigned char *)data)[i+3]);
		syslog (LOG_ERR, G_GNUC_PRETTY_FUNCTION ": Adding nameserver: %s\n", nameserver);

		if ((id = nm_named_manager_add_nameserver_ipv4 (dev->app_data->named,
								nameserver,
								&error)))
			dev->app_data->nameserver_ids = g_list_prepend (dev->app_data->nameserver_ids,
									GUINT_TO_POINTER (id));
		else
		{
			syslog (LOG_ERR, G_GNUC_PRETTY_FUNCTION ": Couldn't add nameserver: %s\n", error->message);
			g_clear_error (&error);
		}
		g_free (nameserver);
	}
}

static void set_domain_search (NMDevice *dev, const char *domain)
{
	GError *error = NULL;
	guint id;

	if (dev->app_data->domain_search_id
	    && !nm_named_manager_remove_domain_search (dev->app_data->named,
						       dev->app_data->domain_search_id,
						       &error))
	{
		syslog (LOG_ERR, G_GNUC_PRETTY_FUNCTION ": Couldn't remove domain search: %s\n", error->message);
		g_clear_error (&error);
	}
	
	syslog (LOG_ERR, G_GNUC_PRETTY_FUNCTION ": Adding domain search: %s\n", domain);
	if ((id = nm_named_manager_add_domain_search (dev->app_data->named,
						      domain,
						      &error)))
		dev->app_data->domain_search_id = id;
	else
	{
		dev->app_data->domain_search_id = 0;
		syslog (LOG_ERR, G_GNUC_PRETTY_FUNCTION ": Couldn't add domain search: %s\n", error->message);
		g_clear_error (&error);
	}
}

/*
 * nm_device_dhcp_configure
 *
 * Using the results of a DHCP request, configure the device.
 *
 */
static void nm_device_dhcp_configure (NMDevice *dev)
{
	int	temp;

	g_return_if_fail (dev != NULL);
	g_return_if_fail (dev->dhcp_iface != NULL);

	/* DHCP sets up a default route for the device, we need to remove that. */
	nm_system_device_flush_routes (dev);

	/* Replace basic info */
	nm_system_device_set_ip4_address (dev, dev->dhcp_iface->ciaddr);

	if (dhcp_interface_dhcp_field_exists (dev->dhcp_iface, subnetMask))
	{
		memcpy (&temp, dhcp_interface_get_dhcp_field (dev->dhcp_iface, subnetMask), dhcp_individual_value_len (subnetMask));
		nm_system_device_set_ip4_netmask (dev, temp);
	}

	if (dhcp_interface_dhcp_field_exists (dev->dhcp_iface, broadcastAddr))
	{
		memcpy (&temp, dhcp_interface_get_dhcp_field (dev->dhcp_iface, broadcastAddr), dhcp_individual_value_len (broadcastAddr));
		nm_system_device_set_ip4_broadcast (dev, temp);
	}

	/* Default route */
	if (dhcp_interface_dhcp_field_exists (dev->dhcp_iface, routersOnSubnet))
	{
		memcpy (&temp, dhcp_interface_get_dhcp_field (dev->dhcp_iface, routersOnSubnet), dhcp_individual_value_len (routersOnSubnet));
		nm_system_device_set_ip4_default_route (dev, temp);
	}

	/* Update /etc/resolv.conf */
	if (dhcp_interface_dhcp_field_exists (dev->dhcp_iface, dns))
		set_nameservers (dev, dhcp_interface_get_dhcp_field (dev->dhcp_iface, dns), dhcp_interface_get_dhcp_field_len (dev->dhcp_iface, dns));

	if (dhcp_interface_dhcp_field_exists (dev->dhcp_iface, domainName))
		set_domain_search (dev, dhcp_interface_get_dhcp_field (dev->dhcp_iface, domainName));
}


/*
 * nm_device_do_autoip
 *
 * Get and assign a Link Local Address.
 *
 */
gboolean nm_device_do_autoip (NMDevice *dev)
{
	struct in_addr		ip;
	gboolean			success = FALSE;

	g_return_val_if_fail (dev != NULL, FALSE);

	if ((success = get_autoip (dev, &ip)))
	{
		#define LINKLOCAL_BCAST		0xa9feffff
		int	temp = ip.s_addr;

		nm_system_device_set_ip4_address (dev, temp);
		temp = ntohl (0xFFFF0000);
		nm_system_device_set_ip4_netmask (dev, temp);
		temp = ntohl (LINKLOCAL_BCAST);
		nm_system_device_set_ip4_broadcast (dev, temp);

		/* Set all traffic to go through the device */
		nm_system_flush_loopback_routes ();
		nm_system_device_add_default_route_via_device (dev);
	}

	return (success);
}


/*
 * nm_device_dhcp_request
 *
 * Start a DHCP transaction on particular device.
 *
 */
int nm_device_dhcp_request (NMDevice *dev)
{
	dhcp_client_options		opts;
	int					err;

	g_return_val_if_fail (dev != NULL, RET_DHCP_ERROR);

	if (dev->dhcp_iface)
	{
		syslog (LOG_ERR, "nm_device_dhcp_request(): device DHCP info exists, but it should have been cleared already.\n");
		dhcp_interface_free (dev->dhcp_iface);
	}

	memset (&opts, 0, sizeof (dhcp_client_options));
	gethostname (&(opts.host_name[0]), DHCP_HOSTNAME_MAX_LEN);
	opts.base_timeout = 30;	
	if (!(dev->dhcp_iface = dhcp_interface_init (nm_device_get_iface (dev), &opts)))
		return RET_DHCP_ERROR;

	/* Start off in DHCP INIT state, get a completely new IP address 
	 * and settings.
	 */
	if ((err = dhcp_init (dev->dhcp_iface)) == RET_DHCP_BOUND)
	{
		nm_device_dhcp_configure (dev);
		nm_device_update_ip4_address (dev);
		nm_device_dhcp_setup_timeouts (dev);
	}
	else
	{
		dhcp_interface_free (dev->dhcp_iface);
		dev->dhcp_iface = NULL;
	}

	return (err);
}


/*
 * nm_device_dhcp_cease
 *
 * Signal dhcp that its supposed to stop and return.
 *
 */
void nm_device_dhcp_cease (NMDevice *dev)
{
	g_return_if_fail (dev != NULL);
	g_return_if_fail (dev->dhcp_iface != NULL);

	dhcp_interface_cease (dev->dhcp_iface);
}


/*
 * nm_device_dhcp_setup_timeouts
 *
 * Set up the DHCP renew and rebind timeouts for a device.
 *
 * Returns:	FALSE on error
 *			TRUE on success
 *
 */
gboolean nm_device_dhcp_setup_timeouts (NMDevice *dev)
{
	int		 t1 = 0, t2 = 0;
	GSource	*t1_source, *t2_source;

	g_return_val_if_fail (dev != NULL, FALSE);

	if (dhcp_interface_dhcp_field_exists (dev->dhcp_iface, dhcpT1value))
	{
		memcpy (&t1, dhcp_interface_get_dhcp_field (dev->dhcp_iface, dhcpT1value), sizeof (int));
		t1 = ntohl (t1);
	}
	if (dhcp_interface_dhcp_field_exists (dev->dhcp_iface, dhcpT2value))
	{
		memcpy (&t2, dhcp_interface_get_dhcp_field (dev->dhcp_iface, dhcpT2value), sizeof (int));
		t2 = ntohl (t2);
	}
	if (!t1 || !t2)
	{
		syslog (LOG_ERR, "DHCP renew/rebind values were 0!  Won't renew lease.");
		return (FALSE);
	}

	t1_source = g_timeout_source_new (t1 * 1000);
	t2_source = g_timeout_source_new (t2 * 1000);
	g_source_set_callback (t1_source, nm_device_dhcp_renew, dev, NULL);
	g_source_set_callback (t2_source, nm_device_dhcp_rebind, dev, NULL);
	dev->renew_timeout = g_source_attach (t1_source, dev->context);
	dev->rebind_timeout = g_source_attach (t2_source, dev->context);

	return (TRUE);
}


/*
 * nm_device_dhcp_renew
 *
 * Renew a DHCP address.
 *
 */
gboolean nm_device_dhcp_renew (gpointer user_data)
{
	NMDevice				*dev = (NMDevice *)user_data;

	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (dev->app_data != NULL, FALSE);
	g_return_val_if_fail (dev->dhcp_iface, FALSE);

	if (dhcp_renew (dev->dhcp_iface) != RET_DHCP_BOUND)
	{
		/* If the T1 renewal fails, then we wait around until T2
		 * for rebind.
		 */
		return (FALSE);
	}
	else
	{
		/* Lease renewed, start timers again from 0 */
		nm_device_dhcp_setup_timeouts (dev);
	}

	/* Always return false to remove ourselves, since we just
	 * set up another timeout above.
	 */
	return (FALSE);
}


/*
 * nm_device_dhcp_renew
 *
 * Renew a DHCP address.
 *
 */
gboolean nm_device_dhcp_rebind (gpointer user_data)
{
	NMDevice	*dev = (NMDevice *)user_data;

	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (dev->app_data != NULL, FALSE);
	g_return_val_if_fail (dev->dhcp_iface, FALSE);

	if (dhcp_rebind (dev->dhcp_iface) != RET_DHCP_BOUND)
	{
		/* T2 rebind failed, so flush the device's address and signal
		 * that we should find another device to use.
		 */
		/* FIXME: technically we should run out the entire lease time before
		 * flushing the address and getting a new device.  We'll leave that for
		 * a bit later (do a new timer for entire lease time, blah, blah).
		 */
		nm_system_device_flush_addresses (dev);
		nm_device_update_ip4_address (dev);
		nm_policy_schedule_state_update (dev->app_data);

		dhcp_interface_free (dev->dhcp_iface);
		dev->dhcp_iface = NULL;
		return (FALSE);
	}
	else
	{
		/* Lease renewed, start timers again from 0 */
		nm_device_dhcp_setup_timeouts (dev);
	}

	/* Always return false to remove ourselves, since we just
	 * set up another timeout above.
	 */
	return (FALSE);
}

