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
#include "nm-utils.h"

extern gboolean get_autoip (NMDevice *dev, struct in_addr *out_ip);

/*
 * nm_device_new_ip4_autoip_config
 *
 * Build up an IP config with a Link Local address
 *
 */
NMIP4Config *nm_device_new_ip4_autoip_config (NMDevice *dev)
{
	struct in_addr		ip;
	NMIP4Config *		config = NULL;

	g_return_val_if_fail (dev != NULL, NULL);

	if (get_autoip (dev, &ip))
	{
		#define LINKLOCAL_BCAST		0xa9feffff
		int	temp = ip.s_addr;

		config = nm_ip4_config_new ();

		nm_ip4_config_set_address (config, (guint32)(ip.s_addr));
		nm_ip4_config_set_netmask (config, (guint32)(ntohl (0xFFFF0000)));
		nm_ip4_config_set_broadcast (config, (guint32)(ntohl (LINKLOCAL_BCAST)));
		nm_ip4_config_set_gateway (config, 0);
	}

	return config;
}


/*
 * nm_device_dhcp_request
 *
 * Start a DHCP transaction on particular device.
 *
 */
static int nm_device_dhcp_request (NMDevice *dev)
{
	dhcp_client_options		opts;
	int					err;

	g_return_val_if_fail (dev != NULL, RET_DHCP_ERROR);

	if (dev->dhcp_iface)
	{
		nm_warning ("nm_device_dhcp_request(): device DHCP info exists, but it should have been cleared already.\n");
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
		nm_device_dhcp_setup_timeouts (dev);
	else
	{
		dhcp_interface_free (dev->dhcp_iface);
		dev->dhcp_iface = NULL;
	}

	return err;
}


/*
 * nm_device_new_ip4_dhcp_config
 *
 * Get IPv4 configuration info via DHCP, running the DHCP
 * transaction if necessary.
 *
 */
NMIP4Config *nm_device_new_ip4_dhcp_config (NMDevice *dev)
{
	NMIP4Config *	config = NULL;
	int			err;
	dhcp_interface *dhcp_info = NULL;

	g_return_val_if_fail (dev != NULL, NULL);

	err = nm_device_dhcp_request (dev);
	dhcp_info = dev->dhcp_iface;
	if ((err == RET_DHCP_BOUND) && dev->dhcp_iface)
	{
		guint32	temp;

		config = nm_ip4_config_new ();

		nm_ip4_config_set_address (config, dhcp_info->ciaddr);

		if (dhcp_interface_option_present (dhcp_info, subnetMask))
		{
			memcpy (&temp, dhcp_interface_option_payload (dhcp_info, subnetMask), dhcp_option_element_len (subnetMask));
			nm_ip4_config_set_netmask (config, temp);
		}

		if (dhcp_interface_option_present (dhcp_info, broadcastAddr))
		{
			memcpy (&temp, dhcp_interface_option_payload (dhcp_info, broadcastAddr), dhcp_option_element_len (broadcastAddr));
			nm_ip4_config_set_broadcast (config, temp);
		}

		/* Default route */
		if (dhcp_interface_option_present (dhcp_info, routersOnSubnet))
		{
			memcpy (&temp, dhcp_interface_option_payload (dhcp_info, routersOnSubnet), dhcp_option_element_len (routersOnSubnet));
			nm_ip4_config_set_gateway (config, temp);
		}

		/* Update /etc/resolv.conf */
		if (dhcp_interface_option_present (dhcp_info, dns))
		{
			guint32 *data = dhcp_interface_option_payload (dhcp_info, dns);
			int len = dhcp_interface_option_len (dhcp_info, dns) / sizeof (guint32);

			for (temp = 0; temp < len; temp++)
				nm_ip4_config_add_nameserver (config, data[temp]);
		}

		if (dhcp_interface_option_present (dhcp_info, domainName))
		{
			char **searches = g_strsplit (dhcp_interface_option_payload (dev->dhcp_iface, domainName), " ", 0);
			char **s;

			for (s = searches; *s; s++)
				nm_ip4_config_add_domain (config, *s);

			g_strfreev (searches);
		}
	}

	return config;
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

	if (dhcp_interface_option_present (dev->dhcp_iface, dhcpT1value))
	{
		memcpy (&t1, dhcp_interface_option_payload (dev->dhcp_iface, dhcpT1value), sizeof (int));
		t1 = ntohl (t1);
	}
	if (dhcp_interface_option_present (dev->dhcp_iface, dhcpT2value))
	{
		memcpy (&t2, dhcp_interface_option_payload (dev->dhcp_iface, dhcpT2value), sizeof (int));
		t2 = ntohl (t2);
	}
	if (!t1 || !t2)
	{
		nm_warning ("DHCP renew/rebind values were 0!  Won't renew lease.");
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
 * nm_device_dhcp_remove_timeouts
 *
 * Remove the DHCP renew and rebind timeouts for a device.
 *
 */
void nm_device_dhcp_remove_timeouts (NMDevice *dev)
{
	g_return_if_fail (dev != NULL);

	if (dev->renew_timeout > 0)
	{
		g_source_destroy (g_main_context_find_source_by_id (dev->context, dev->renew_timeout));
		dev->renew_timeout = 0;
	}
	if (dev->rebind_timeout > 0)
	{
		g_source_destroy (g_main_context_find_source_by_id (dev->context, dev->rebind_timeout));
		dev->renew_timeout = 0;
	}

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
		return FALSE;
	}
	else
	{
		/* Lease renewed, start timers again from 0 */
		nm_device_dhcp_setup_timeouts (dev);
	}

	/* Always return false to remove ourselves, since we just
	 * set up another timeout above.
	 */
	return FALSE;
}


/*
 * nm_device_dhcp_rebind
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
		return FALSE;
	}
	else
	{
		/* Lease renewed, start timers again from 0 */
		nm_device_dhcp_setup_timeouts (dev);
	}

	/* Always return false to remove ourselves, since we just
	 * set up another timeout above.
	 */
	return FALSE;
}

