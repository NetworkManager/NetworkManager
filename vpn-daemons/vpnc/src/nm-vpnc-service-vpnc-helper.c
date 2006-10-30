/* nm-vpnc-service - vpnc integration with NetworkManager
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
 * (C) Copyright 2005 Red Hat, Inc.
 */

#include <glib.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>
#include <NetworkManager.h>

#include "nm-vpnc-service.h"
#include "nm-utils.h"


/*
 * send_config_error
 *
 * Notify nm-vpnc-service of a config error from 'vpnc'.
 *
 */
static void send_config_error (DBusConnection *con, const char *item)
{
	DBusMessage		*message;

	g_return_if_fail (con != NULL);
	g_return_if_fail (item != NULL);

	if (!(message = dbus_message_new_method_call (NM_DBUS_SERVICE_VPNC, NM_DBUS_PATH_VPNC, NM_DBUS_INTERFACE_VPNC, "signalConfigError")))
	{
		nm_warning ("send_config_error(): Couldn't allocate the dbus message");
		return;
	}

	dbus_message_append_args (message, DBUS_TYPE_STRING, &item, DBUS_TYPE_INVALID);
	if (!dbus_connection_send (con, message, NULL))
		nm_warning ("send_config_error(): could not send dbus message");

	dbus_message_unref (message);
}


/*
 * send_config_info
 *
 * Send IP config info to nm-vpnc-service
 *
 */
static gboolean send_config_info (DBusConnection *con, const char *str_vpn_gateway,
										 const char *tundev,
										 const char *str_internal_ip4_address,
										 const char *str_internal_ip4_netmask,
										 const char *str_internal_ip4_dns,
										 const char *str_internal_ip4_nbns,
										 const char *cisco_def_domain,
										 const char *cisco_banner)
{
	DBusMessage *	message;
	struct in_addr	temp_addr;
	guint32		uint_vpn_gateway = 0;
	guint32		uint_internal_ip4_address = 0;
	guint32		uint_internal_ip4_netmask = 0xFFFFFFFF; /* Default mask of 255.255.255.255 */
	guint32 *		uint_internal_ip4_dns = NULL;
	guint32		uint_internal_ip4_dns_len = 0;
	guint32 *		uint_internal_ip4_nbns = NULL;
	guint32		uint_internal_ip4_nbns_len = 0;
	char **		split;
	char **		item;
	guint32		num_valid = 0, i;
	gboolean		success = FALSE;

	g_return_val_if_fail (con != NULL, FALSE);

	if (!(message = dbus_message_new_method_call (NM_DBUS_SERVICE_VPNC, NM_DBUS_PATH_VPNC, NM_DBUS_INTERFACE_VPNC, "signalIP4Config")))
	{
		nm_warning ("send_config_error(): Couldn't allocate the dbus message");
		return FALSE;
	}

	/* Convert IPv4 address arguments from strings into numbers */
	if (!inet_aton (str_vpn_gateway, &temp_addr))
	{
		nm_warning ("nm-vpnc-service-vpnc-helper didn't receive a valid VPN Gateway from vpnc.");
		send_config_error (con, "VPN Gateway");
		goto out;
	}
	uint_vpn_gateway = temp_addr.s_addr;

	if (!inet_aton (str_internal_ip4_address, &temp_addr))
	{
		nm_warning ("nm-vpnc-service-vpnc-helper didn't receive a valid Internal IP4 Address from vpnc.");
		send_config_error (con, "IP4 Address");
		goto out;
	}
	uint_internal_ip4_address = temp_addr.s_addr;

	if (strlen (str_internal_ip4_netmask) && inet_aton (str_internal_ip4_netmask, &temp_addr))
		uint_internal_ip4_netmask = temp_addr.s_addr;

	if (strlen (str_internal_ip4_dns))
	{
		if ((split = g_strsplit (str_internal_ip4_dns, " ", -1)))
		{
			/* Pass over the array first to determine how many valid entries there are */
			num_valid = 0;
			for (item = split; *item; item++)
				if (inet_aton (*item, &temp_addr))
					num_valid++;

			/* Do the actual string->int conversion and assign to the array. */
			if (num_valid > 0)
			{
				uint_internal_ip4_dns = g_new0 (guint32, num_valid);
				for (item = split, i = 0; *item; item++, i++)
					if (inet_aton (*item, &temp_addr))
						uint_internal_ip4_dns[i] = temp_addr.s_addr;
			}

			g_strfreev (split);
			uint_internal_ip4_dns_len = num_valid;
		}		
	}
	if (!uint_internal_ip4_dns)
	{
		uint_internal_ip4_dns = g_malloc0 (sizeof (guint32));
		uint_internal_ip4_dns[0] = 0;
		uint_internal_ip4_dns_len = 1;
	}

	if (strlen (str_internal_ip4_nbns))
	{
		if ((split = g_strsplit (str_internal_ip4_nbns, " ", -1)))
		{
			/* Pass over the array first to determine how many valid entries there are */
			num_valid = 0;
			for (item = split; *item; item++)
				if (inet_aton (*item, &temp_addr))
					num_valid++;

			/* Do the actual string->int conversion and assign to the array. */
			if (num_valid > 0)
			{
				uint_internal_ip4_nbns = g_new0 (guint32, num_valid);
				for (item = split, i = 0; *item; item++, i++)
					if (inet_aton (*item, &temp_addr))
						uint_internal_ip4_nbns[i] = temp_addr.s_addr;
			}

			g_strfreev (split);
			uint_internal_ip4_nbns_len = num_valid;
		}		
	}
	if (!uint_internal_ip4_nbns)
	{
		uint_internal_ip4_nbns = g_malloc0 (sizeof (guint32));
		uint_internal_ip4_nbns[0] = 0;
		uint_internal_ip4_nbns_len = 1;
	}

	dbus_message_append_args (message, DBUS_TYPE_UINT32, &uint_vpn_gateway,
								DBUS_TYPE_STRING, &tundev,
								DBUS_TYPE_UINT32, &uint_internal_ip4_address,
								DBUS_TYPE_UINT32, &uint_internal_ip4_netmask,
								DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &uint_internal_ip4_dns, uint_internal_ip4_dns_len,
								DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &uint_internal_ip4_nbns, uint_internal_ip4_nbns_len,
								DBUS_TYPE_STRING, &cisco_def_domain,
								DBUS_TYPE_STRING, &cisco_banner, DBUS_TYPE_INVALID);
	if (dbus_connection_send (con, message, NULL))
		success = TRUE;
	else
		nm_warning ("send_config_error(): could not send dbus message");

	dbus_message_unref (message);

out:
	return success;
}


/*
 * Environment variables passed back from 'vpnc':
 *
 * VPNGATEWAY             -- vpn gateway address (always present)
 * TUNDEV                 -- tunnel device (always present)
 * INTERNAL_IP4_ADDRESS   -- address (always present)
 * INTERNAL_IP4_NETMASK   -- netmask (often unset)
 * INTERNAL_IP4_DNS       -- list of dns serverss
 * INTERNAL_IP4_NBNS      -- list of wins servers
 * CISCO_DEF_DOMAIN       -- default domain name
 * CISCO_BANNER           -- banner from server
 *
 */

/*
 * main
 *
 */
int main( int argc, char *argv[] )
{
	DBusConnection *	con;
	DBusError			error;
	char *			reason = NULL;
	char *			vpn_gateway = NULL;
	char *			tundev = NULL;
	char *			internal_ip4_address = NULL;
	char *			internal_ip4_netmask = NULL;
	char *			internal_ip4_dns = NULL;
	char *			internal_ip4_nbns = NULL;
	char *			cisco_def_domain = NULL;
	char *			cisco_banner = NULL;

	g_type_init ();
	if (!g_thread_supported ())
		g_thread_init (NULL);

	dbus_error_init (&error);
	con = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
	if ((con == NULL) || dbus_error_is_set (&error))
	{
		nm_warning ("Could not get the system bus.  Make sure the message bus daemon is running?");
		exit (1);
	}
	dbus_connection_set_exit_on_disconnect (con, FALSE);

	/* vpnc 0.3.3 gives us a "reason" code.  If we are given one,
	 * don't proceed unless its "connect".
	 */
	reason = getenv ("reason");
	if (reason && strcmp (reason, "connect") != 0)
		exit (0);

	vpn_gateway = getenv ("VPNGATEWAY");
	tundev = getenv ("TUNDEV");
	internal_ip4_address = getenv ("INTERNAL_IP4_ADDRESS");
	internal_ip4_netmask = getenv ("INTERNAL_IP4_NETMASK");
	internal_ip4_dns = getenv ("INTERNAL_IP4_DNS");
	internal_ip4_nbns = getenv ("INTERNAL_IP4_NBNS");
	cisco_def_domain = getenv ("CISCO_DEF_DOMAIN");
	cisco_banner = getenv ("CISCO_BANNER");

#if 0
	{
		FILE *file = fopen ("/tmp/vpnstuff", "w");
		fprintf (file, "VPNGATEWAY: '%s'\n", vpn_gateway);
		fprintf (file, "TUNDEF: '%s'\n", tundev);
		fprintf (file, "INTERNAL_IP4_ADDRESS: '%s'\n", internal_ip4_address);
		fprintf (file, "INTERNAL_IP4_NETMASK: '%s'\n", internal_ip4_netmask);
		fprintf (file, "INTERNAL_IP4_DNS: '%s'\n", internal_ip4_dns);
		fprintf (file, "INTERNAL_IP4_NBNS: '%s'\n", internal_ip4_nbns);
		fprintf (file, "CISCO_DEF_DOMAIN: '%s'\n", cisco_def_domain);
		fprintf (file, "CISCO_BANNER: '%s'\n", cisco_banner);
		fclose (file);
	}
#endif

	if (!vpn_gateway)
	{
		nm_warning ("nm-vpnc-service-vpnc-helper didn't receive a VPN Gateway from vpnc.");
		send_config_error (con, "VPN Gateway");
		exit (1);
	}
	if (!tundev || !g_utf8_validate (tundev, -1, NULL))
	{
		nm_warning ("nm-vpnc-service-vpnc-helper didn't receive a Tunnel Device from vpnc, or the tunnel device was not valid UTF-8.");
		send_config_error (con, "Tunnel Device");
		exit (1);
	}
	if (!internal_ip4_address)
	{
		nm_warning ("nm-vpnc-service-vpnc-helper didn't receive an Internal IP4 Address from vpnc.");
		send_config_error (con, "IP4 Address");
		exit (1);
	}

	if (!internal_ip4_netmask)
		internal_ip4_netmask = g_strdup ("");
	if (!internal_ip4_dns)
		internal_ip4_dns = g_strdup ("");
	if (!internal_ip4_nbns)
		internal_ip4_nbns = g_strdup ("");

	/* Ensure strings from network are UTF-8 */
	if (cisco_def_domain && !g_utf8_validate (cisco_def_domain, -1, NULL))
	{
		if (!(cisco_def_domain = g_convert (cisco_def_domain, -1, "ISO-8859-1", "UTF-8", NULL, NULL, NULL)))
			cisco_def_domain = g_convert (cisco_def_domain, -1, "C", "UTF-8", NULL, NULL, NULL);
	}
	if (!cisco_def_domain)
		cisco_def_domain = g_strdup ("");

	if (cisco_banner && !g_utf8_validate (cisco_banner, -1, NULL))
	{
		if (!(cisco_banner = g_convert (cisco_banner, -1, "ISO-8859-1", "UTF-8", NULL, NULL, NULL)))
			cisco_banner = g_convert (cisco_banner, -1, "C", "UTF-8", NULL, NULL, NULL);
	}
	if (!cisco_banner)
		cisco_banner = g_strdup ("");

	/* Send the config info to nm-vpnc-service */
	if (!send_config_info (con, vpn_gateway, tundev, internal_ip4_address, internal_ip4_netmask,
						internal_ip4_dns, internal_ip4_nbns, cisco_def_domain, cisco_banner))
	{
		exit (1);
	}

	exit (0);
}

