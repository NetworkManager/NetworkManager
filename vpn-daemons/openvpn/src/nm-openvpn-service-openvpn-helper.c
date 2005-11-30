/* nm-openvpn-service - openvpn integration with NetworkManager
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
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <regex.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>
#include <NetworkManager/NetworkManager.h>

#include "nm-openvpn-service.h"
#include "nm-utils.h"

/*
 * send_config_error
 *
 * Notify nm-openvpn-service of a config error from 'openvpn'.
 *
 */
static void send_config_error (DBusConnection *con, const char *item)
{
  DBusMessage		*message;

  g_return_if_fail (con != NULL);
  g_return_if_fail (item != NULL);

  if (!(message = dbus_message_new_method_call (NM_DBUS_SERVICE_OPENVPN, NM_DBUS_PATH_OPENVPN, NM_DBUS_INTERFACE_OPENVPN, "signalConfigError")))
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
 * Send IP config info to nm-openvpn-service
 *
 */
static gboolean send_config_info (DBusConnection *con,
				  const char *str_vpn_gateway,
				  const char *str_tundev,
				  const char *str_ip4_address,
				  const char *str_ip4_netmask,
				  const GPtrArray *gpa_ip4_dns,
				  const GPtrArray *gpa_ip4_nbns
				  )
{
  DBusMessage *	message;
  struct in_addr	temp_addr;
  guint32		uint_vpn_gateway = 0;
  guint32		uint_ip4_address = 0;
  guint32		uint_ip4_netmask = 0xFFFFFFFF; /* Default mask of 255.255.255.255 */
  guint32 *	        uint_ip4_dns = NULL;
  guint32		uint_ip4_dns_len = 0;
  guint32 *	        uint_ip4_nbns = NULL;
  guint32		uint_ip4_nbns_len = 0;
  guint32		num_valid = 0, i = 0;
  gboolean        success = FALSE;

  g_return_val_if_fail (con != NULL, FALSE);

  if (!(message = dbus_message_new_method_call (NM_DBUS_SERVICE_OPENVPN, NM_DBUS_PATH_OPENVPN, NM_DBUS_INTERFACE_OPENVPN, "signalIP4Config")))
    {
      nm_warning ("send_config_error(): Couldn't allocate the dbus message");
      return FALSE;
    }

  /* Convert IPv4 address arguments from strings into numbers */
  if (!inet_aton (str_vpn_gateway, &temp_addr))
    {
      nm_warning ("nm-openvpn-service-openvpn-helper didn't receive a valid VPN Gateway from openvpn.");
      send_config_error (con, "VPN Gateway");
		goto out;
    }
  uint_vpn_gateway = temp_addr.s_addr;

  if (!inet_aton (str_ip4_address, &temp_addr))
    {
      nm_warning ("nm-openvpn-service-openvpn-helper didn't receive a valid Internal IP4 Address from openvpn.");
      send_config_error (con, "IP4 Address");
      goto out;
    }
  uint_ip4_address = temp_addr.s_addr;

  if (strlen (str_ip4_netmask) && inet_aton (str_ip4_netmask, &temp_addr))
    uint_ip4_netmask = temp_addr.s_addr;

  if ( gpa_ip4_dns->len > 0 )
    {
      /* Pass over the array first to determine how many valid entries there are */
      num_valid = 0;
      for (i = 0; i < gpa_ip4_dns->len; ++i)
	if (inet_aton ((char *)gpa_ip4_dns->pdata[i], &temp_addr))
	  num_valid++;
      
      /* Do the actual string->int conversion and assign to the array. */
      if (num_valid > 0)
	{
	  uint_ip4_dns = g_new0 (guint32, num_valid);
	  for (i = 0; i < gpa_ip4_dns->len; ++i)
	    if (inet_aton ((char *)gpa_ip4_dns->pdata[i], &temp_addr))
	      uint_ip4_dns[i] = temp_addr.s_addr;
	}
      
      uint_ip4_dns_len = num_valid;
    }
  if (!uint_ip4_dns)
    {
      uint_ip4_dns = g_malloc0 (sizeof (guint32));
      uint_ip4_dns_len = 1;
    }

  if ( gpa_ip4_nbns->len > 0 )
    {
      /* Pass over the array first to determine how many valid entries there are */
      num_valid = 0;
      for (i = 0; i < gpa_ip4_nbns->len; ++i)
	if (inet_aton ((char *)gpa_ip4_nbns->pdata[i], &temp_addr))
	  num_valid++;
      
      /* Do the actual string->int conversion and assign to the array. */
      if (num_valid > 0)
	{
	  uint_ip4_nbns = g_new0 (guint32, num_valid);
	  for (i = 0; i < gpa_ip4_nbns->len; ++i)
	    if (inet_aton ((char *)gpa_ip4_nbns->pdata[i], &temp_addr))
	      uint_ip4_nbns[i] = temp_addr.s_addr;
	}
      
      uint_ip4_nbns_len = num_valid;
    }
  if (!uint_ip4_nbns)
    {
      uint_ip4_nbns = g_malloc0 (sizeof (guint32));
      uint_ip4_nbns_len = 1;
    }

  dbus_message_append_args (message, DBUS_TYPE_UINT32, &uint_vpn_gateway,
			    DBUS_TYPE_STRING, &str_tundev,
			    DBUS_TYPE_UINT32, &uint_ip4_address,
			    DBUS_TYPE_UINT32, &uint_ip4_netmask,
			    DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &uint_ip4_dns, uint_ip4_dns_len,
			    DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &uint_ip4_nbns, uint_ip4_nbns_len,
			    DBUS_TYPE_INVALID);
  if (dbus_connection_send (con, message, NULL))
    success = TRUE;
  else
    nm_warning ("send_config_error(): could not send dbus message");
  
  dbus_message_unref (message);
  
 out:
  return success;
}


/*
 * See the OpenVPN man page for available environment variables.
 *
 *
 */


/** Prints all environment variables to /tmp/environ
 */
static void
print_env()
{
  FILE *f = fopen("/tmp/environ", "w");
  int env = 0;
  while ( __environ[env] != NULL ) {
    fprintf(f, "%s\n", __environ[env++]);
  }
  fclose(f);
}


/*
 * main
 *
 */
int main( int argc, char *argv[] )
{
  DBusConnection  *con;
  DBusError        error;
  char            *vpn_gateway = NULL;
  char            *tundev = NULL;
  char            *ip4_address = NULL;
  char            *ip4_ptp = NULL;
  char            *ip4_netmask = NULL;
  GPtrArray       *ip4_dns = NULL;
  GPtrArray       *ip4_nbns = NULL;
  
  char           **split = NULL;
  char           **item;

  char            *tmp;
  // max(length(envname)) = length("foreign_option_") + length(to_string(MAX_INT)) + 1;
  //                               = 15                     = 10 for 4 byte int
  //                                                    (which should be enough for quite some time)
  char             envname[26];
  int              i = 1;
  int              exit_code = 0;

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

  // print_env();

  vpn_gateway = getenv( "trusted_ip" );
  tundev      = getenv ("dev");
  ip4_ptp     = getenv("ifconfig_remote");
  ip4_address = getenv("ifconfig_local");
  ip4_netmask = getenv("route_netmask_1");
  
  ip4_dns     = g_ptr_array_new();
  ip4_nbns    = g_ptr_array_new();
  
  while (1) {
    sprintf(envname, "foreign_option_%i", i++);
    tmp = getenv( envname );
    
    if ( (tmp == NULL) || (strlen(tmp) == 0) ) {
      break;
    } else {
      
      if ((split = g_strsplit( tmp, " ", -1))) {
	int size = 0;
	for( item = split; *item; item++) {
		++size;
	}
	if ( size != 3 ) continue;
	
	if (strcmp( split[0], "dhcp-option") == 0) {
	  // Interesting, now check if DNS or NBNS/WINS
	  if (strcmp( split[1], "DNS") == 0) {
	    // DNS, push it!
	    g_ptr_array_add( ip4_dns, (gpointer) split[2] );
	  } else if (strcmp( split[1], "WINS") == 0) {
	    // WINS, push it!
	    g_ptr_array_add( ip4_nbns, (gpointer) split[2] );		  
	  }
	}
      }
    }      
  }

#if 0
	{
		FILE *file = fopen ("/tmp/vpnstuff", "w");
		fprintf (file, "VPNGATEWAY: '%s'\n", vpn_gateway);
		fprintf (file, "TUNDEF: '%s'\n", tundev);
		fprintf (file, "IP4_ADDRESS: '%s'\n", ip4_address);
		fprintf (file, "IP4_NETMASK: '%s'\n", ip4_netmask);
		fclose (file);
	}
#endif
  
  if (!vpn_gateway)
    {
      nm_warning ("nm-openvpn-service-openvpn-helper didn't receive a VPN Gateway from openvpn.");
      send_config_error (con, "VPN Gateway");
      exit (1);
    }
  if (!tundev || !g_utf8_validate (tundev, -1, NULL))
    {
      nm_warning ("nm-openvpn-service-openvpn-helper didn't receive a Tunnel Device from openvpn, or the tunnel device was not valid UTF-8.");
      send_config_error (con, "Tunnel Device");
      exit (1);
    }
  if (!ip4_address)
    {
      nm_warning ("nm-openvpn-service-openvpn-helper didn't receive an Internal IP4 Address from openvpn.");
      send_config_error (con, "IP4 Address");
      exit (1);
    }

  if (!ip4_netmask)
    ip4_netmask = g_strdup ("");
  
  
  /* Send the config info to nm-openvpn-service */
  if (!send_config_info (con, vpn_gateway, tundev, ip4_address, ip4_netmask, ip4_dns, ip4_nbns))
    {
      exit_code = 1;
    }
  
  g_strfreev( split );
  g_ptr_array_free( ip4_dns, TRUE );
  g_ptr_array_free( ip4_nbns, TRUE );
  
  exit (exit_code);
}

