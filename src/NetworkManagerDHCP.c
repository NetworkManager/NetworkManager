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
#include "NetworkManager.h"
#include "NetworkManagerMain.h"
#include "NetworkManagerDevice.h"
#include "NetworkManagerDHCP.h"
#include "NetworkManagerSystem.h"
#include "../dhcpcd/client.h"

/* Accessors to device data that only this file should need */
dhcp_interface *nm_device_get_dhcp_iface (NMDevice *dev);
void nm_device_set_dhcp_iface (NMDevice *dev, dhcp_interface *dhcp_iface);


/*
 * nm_device_dhcp_run
 *
 * Start a DHCP transaction on particular device.
 *
 */
int nm_device_dhcp_run (NMDevice *dev)
{
	dhcp_interface			*dhcp_iface;
	dhcp_client_options		 opts;
	int					 err;
	const char			*iface;

	g_return_val_if_fail (dev != NULL, RET_DHCP_ERROR);

	memset (&opts, 0, sizeof (dhcp_client_options));
	opts.base_timeout = 25;

	iface = nm_device_get_iface (dev);
	if (!(dhcp_iface = dhcp_interface_init (iface, &opts)))
		return RET_DHCP_ERROR;
	nm_device_set_dhcp_iface (dev, dhcp_iface);

	/* Start off in DHCP INIT state, get a completely new IP address 
	 * and settings.
	 */
	err = dhcp_init (dhcp_iface);
	if (err == RET_DHCP_BOUND)
	{
		int	temp;

		/* Replace basic info */
		nm_system_device_set_ip4_address (dev, dhcp_iface->ciaddr);

		if (dhcp_interface_dhcp_field_exists (dhcp_iface, subnetMask))
		{
			memcpy (&temp, dhcp_interface_get_dhcp_field (dhcp_iface, subnetMask), dhcp_individual_value_len (subnetMask));
			nm_system_device_set_ip4_netmask (dev, temp);
		}

		if (dhcp_interface_dhcp_field_exists (dhcp_iface, subnetMask))
		{
			memcpy (&temp, dhcp_interface_get_dhcp_field (dhcp_iface, broadcastAddr), dhcp_individual_value_len (broadcastAddr));
			nm_system_device_set_ip4_broadcast (dev, temp);
		}

		/* Default route */
		if (dhcp_interface_dhcp_field_exists (dhcp_iface, routersOnSubnet))
		{
			memcpy (&temp, dhcp_interface_get_dhcp_field (dhcp_iface, routersOnSubnet), dhcp_individual_value_len (routersOnSubnet));
			nm_system_device_set_ip4_default_route (dev, temp);
		}

		/* Update /etc/resolv.conf */
		if (dhcp_interface_dhcp_field_exists (dhcp_iface, dns))
		{
			nm_system_device_update_resolv_conf (dhcp_interface_get_dhcp_field (dhcp_iface, dns),
				dhcp_interface_get_dhcp_field_len (dhcp_iface, dns), dhcp_interface_get_dhcp_field (dhcp_iface, domainName));
		}
	}

	dhcp_interface_free (dhcp_iface);
	nm_device_set_dhcp_iface (dev, NULL);

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
	g_return_if_fail (nm_device_get_dhcp_iface (dev) != NULL);

	dhcp_interface_cease (nm_device_get_dhcp_iface (dev));
}

