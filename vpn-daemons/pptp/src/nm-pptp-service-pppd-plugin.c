/* nm-pptp-service - pptp integration with NetworkManager
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

#include "pppd/pppd.h"
#include "pppd/fsm.h"
#include "pppd/ipcp.h"

#include <glib.h>
#include <stdlib.h>
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

#include "nm-pptp-service.h"
#include "nm-utils.h"

char pppd_version[] = VERSION;

static void pptp_ip_up(void *opaque, int arg);
static void pptp_ip_down(void *opaque, int arg);
int pptp_chap_passwd(char *user, char *passwd);
static void send_config_error (DBusConnection *con, const char *item);

/*      nm_warning ("nm-pptp-service-pptp-helper didn't receive a Tunnel Device from pptp, or the tunnel device was not valid UTF-8.");
      send_config_error (con, "Tunnel Device");
      nm_warning ("nm-pptp-service-pptp-helper didn't receive an Internal IP4 Address from pptp.");
      send_config_error (con, "IP4 Address");
*/

int plugin_init()
{
    DBusConnection *	con;
    DBusError		error;

    g_type_init ();
    if (!g_thread_supported ())
      g_thread_init (NULL);
    
    dbus_error_init (&error);
    con = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
    if ((con == NULL) || dbus_error_is_set (&error))
      {
        nm_warning ("Could not get the system bus.  Make sure the message bus daemon is running?");
        return -1;
      }
    dbus_connection_set_exit_on_disconnect (con, FALSE);

//    add_options(ldap_options);
    chap_passwd_hook = pptp_chap_passwd;

//    add_notifier(&ip_down_notifier, pptp_ip_down, (void *) con);
    add_notifier(&ip_up_notifier, pptp_ip_up, (void *) con);

    info("nm-pptp: plugin initialized.");

    return 0;
}

int pptp_chap_passwd(char *user, char *passwd)
{
    memcpy(passwd, "YOUR PASSWORD IN HERE!!",MAXSECRETLEN);
    passwd[MAXSECRETLEN-1]='\0';
    return 0;
}

static void pptp_ip_down(void *opaque, int arg)
{   
}

static void pptp_ip_up(void *opaque, int arg)
{
  DBusConnection *con = (DBusConnection *)opaque;
  DBusMessage		*message;
  char *		str_ifname        = NULL;
//  guint32 *		uint_ip4_dns   = NULL;
  guint32 		uint_ip4_dns1     = 0;
  guint32 		uint_ip4_dns2     = 0;
  guint32		uint_ip4_dns_len  = 0;
//  guint32 *		uint_ip4_wins  = NULL;
  guint32 		uint_ip4_wins1    = 0;
  guint32 		uint_ip4_wins2    = 0;
  guint32		uint_ip4_wins_len = 0;
  guint32		uint_ip4_address  = 0;
  guint32		uint_ip4_netmask  = 0xFFFFFFFF; /* Default mask of 255.255.255.255 */
  guint32 i=0;
 
  g_return_if_fail (con != NULL);
  if (ipcp_gotoptions[ifunit].ouraddr==0) {
    nm_warning ("nm-pptp-service-pptp-helper didn't receive an Internal IP4 Address from pptp.");
    send_config_error (con, "IP4 Address");
    return;
  }
  uint_ip4_address=ipcp_gotoptions[ifunit].ouraddr;
  
  if (!(message = dbus_message_new_method_call (NM_DBUS_SERVICE_PPTP, NM_DBUS_PATH_PPTP, NM_DBUS_INTERFACE_PPTP, "signalIP4Config")))
    {
      nm_warning ("send_config_error(): Couldn't allocate the dbus message");
      return;
    }


  if (ipcp_gotoptions[ifunit].dnsaddr) {
    if (ipcp_gotoptions[ifunit].dnsaddr[0]!=0) {
      uint_ip4_dns_len++; 
      uint_ip4_dns1=ipcp_gotoptions[ifunit].dnsaddr[0];
      if (ipcp_gotoptions[ifunit].dnsaddr[1]!=0) {
        uint_ip4_dns_len++;
        uint_ip4_dns2=ipcp_gotoptions[ifunit].dnsaddr[1];
      }  
    }
//    if (uint_ip4_dns_len > 0)
//    {
//      uint_ip4_dns = g_new0(guint32,uint_ip4_dns_len);
//      for (i = 0; i < uint_ip4_dns_len; ++i)
//        uint_ip4_dns[i] = ipcp_gotoptions[ifunit].dnsaddr[i];
//    }
  }

  if (ipcp_gotoptions[ifunit].winsaddr) {
    if (ipcp_gotoptions[ifunit].winsaddr[0]!=0) {
      uint_ip4_wins_len++; 
      uint_ip4_wins1=ipcp_gotoptions[ifunit].winsaddr[0];
      if (ipcp_gotoptions[ifunit].winsaddr[1]!=0) {
        uint_ip4_wins_len++;
        uint_ip4_wins2=ipcp_gotoptions[ifunit].winsaddr[1];
      }
    }
//    if (uint_ip4_wins_len > 0)
//    {
//      uint_ip4_wins = g_new0(guint32,uint_ip4_wins_len);
//      for (i = 0; i < uint_ip4_wins_len; ++i)
//        uint_ip4_wins[i] = ipcp_gotoptions[ifunit].winsaddr[i];
//    }
  }
 
  if (ifname==NULL) {
    nm_warning ("nm-pptp-service-pptp-helper didn't receive a tunnel device name.");
    send_config_error (con, "IP4 Address");
  }
  str_ifname = g_strdup(ifname);

/*  Print out some debug info.
  nm_warning("Sending config IFNAME: %s",str_ifname);
  nm_warning("Sending config IPLOCAL: %s", ip_ntoa(uint_ip4_address));
  nm_warning("Sending config NETMASK: %s", ip_ntoa(uint_ip4_netmask));
  nm_warning("Sending config DNS1: %s", ip_ntoa(uint_ip4_dns1));
  nm_warning("Sending config DNS2: %s", ip_ntoa(uint_ip4_dns2));
  nm_warning("Sending config NDNS: %d", uint_ip4_dns_len);
  nm_warning("Sending config WINS1: %s", ip_ntoa(uint_ip4_wins1));
  nm_warning("Sending config WINS2: %s", ip_ntoa(uint_ip4_wins2));
  nm_warning("Sending config NWINS: %d", uint_ip4_wins_len);  */
  
  dbus_message_append_args (message, 
			    DBUS_TYPE_STRING, &str_ifname,
			    DBUS_TYPE_UINT32, &uint_ip4_address,
			    DBUS_TYPE_UINT32, &uint_ip4_netmask,
// Array workaround
                DBUS_TYPE_UINT32, &uint_ip4_dns1,
			    DBUS_TYPE_UINT32, &uint_ip4_dns2,
			    DBUS_TYPE_UINT32, &uint_ip4_dns_len,
			    DBUS_TYPE_UINT32, &uint_ip4_wins1,
			    DBUS_TYPE_UINT32, &uint_ip4_wins2,
			    DBUS_TYPE_UINT32, &uint_ip4_wins_len, 
// 
// For some reason DBUS_TYPE_ARRAYs don't seem to like working inside the pppd plugin
// 
//  testing with:
//     pppd pty "/usr/sbin/pptp SOME.SERVER.IP --nolaunchpppd" nodetach remotename SOME.SERVER user MYUSER usepeerdns plugin nm-pptp-service-pppd-plugin.so
//
//  Fails with (given pointers and allocated arrays with g_new0() ):
//     13646: assertion failed "value != NULL" file "dbus-string.c" line 235 function _dbus_string_init_const_len
//     Fatal signal 6
//     
//  Or if fixed [2] arrays are used:
//     Fatal signal 11
//			    
//			    DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &uint_ip4_dns, uint_ip4_dns_len,
//			    DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &uint_ip4_wins, uint_ip4_wins_len,
			    DBUS_TYPE_INVALID);
  if (!dbus_connection_send (con, message, NULL)) {
    nm_warning ("pptp_ip_up(): could not send dbus message");
    dbus_message_unref (message);
    return;
  }
  
  dbus_message_unref (message);
  
  return;
}


/*
 * send_config_error
 *
 * Notify nm-pptp-service of a config error from 'pptp'.
 *
*/
static void send_config_error (DBusConnection *con, const char *item)
{
  DBusMessage		*message;

  g_return_if_fail (con != NULL);
  g_return_if_fail (item != NULL);

  if (!(message = dbus_message_new_method_call (NM_DBUS_SERVICE_PPTP, NM_DBUS_PATH_PPTP, NM_DBUS_INTERFACE_PPTP, "signalConfigError")))
    {
      nm_warning ("send_config_error(): Couldn't allocate the dbus message");
      return;
    }

  dbus_message_append_args (message, DBUS_TYPE_STRING, &item, DBUS_TYPE_INVALID);
  if (!dbus_connection_send (con, message, NULL))
    nm_warning ("send_config_error(): could not send dbus message");
  
  dbus_message_unref (message);
}


