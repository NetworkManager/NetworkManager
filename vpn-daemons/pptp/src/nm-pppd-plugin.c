/* nm-pptp-service - pptp (and other pppd) integration with NetworkManager
 *
 * Antony J Mee <eemynotna at gmail dot com>
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
 */
#include "pppd/pppd.h"

#include "pppd/fsm.h"
#include "pppd/ipcp.h"

#include <sys/types.h>
#include <unistd.h>
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

#include "nm-ppp-starter.h"
#include "nm-pppd-plugin.h"
#include "nm-utils.h"

typedef struct NmPPPData
{
  DBusConnection	*con;
  gboolean          got_auth_info;
  char              *auth_type;
  char              *username;
  char              *password;
  int               pppd_pid;
} NmPPPData;

char pppd_version[] = PPPD_VERSION;

NmPPPData plugin_data;

int plugin_init();

void nm_ip_up(void *opaque, int arg);
void nm_ip_down(void *opaque, int arg);
void nm_exit_notify(void *opaque, int arg);

int nm_chap_passwd_hook(char *user, char *passwd);
int nm_chap_check_hook(void);

void nm_notify_pid (NmPPPData *data);
void send_config_error (DBusConnection *con, const char *item);
gboolean nm_get_auth_items (NmPPPData *data);
gboolean nm_store_auth_info (NmPPPData *data, char **auth_items, int num_auth_items);
gboolean nm_dbus_prepare_connection(NmPPPData *data);
static DBusHandlerResult nm_dbus_message_handler (DBusConnection *con, DBusMessage *message, void *user_data);
void nm_dbus_kill_connection(NmPPPData *data);

gboolean nm_dbus_prepare_connection(NmPPPData *data)
{
//    DBusMessage *	message = NULL;
    DBusError		error;
//    DBusObjectPathVTable	 vtable = { NULL, 
//                                        &nm_dbus_message_handler, 
//                                        NULL, NULL, NULL, NULL };

    g_return_val_if_fail (data != NULL, FALSE);
    if (data->con != NULL) return TRUE;


    dbus_error_init (&error);
    data->con = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
    if ((data->con == NULL) || dbus_error_is_set (&error))
      {
        info("Could not get the system bus.  Make sure the message bus daemon is running?");
        goto out;
      }
    dbus_connection_set_exit_on_disconnect (data->con, FALSE);

//    dbus_error_init (&error);
//    dbus_bus_request_name (data->con, NM_DBUS_SERVICE_PPP, 0, &error);
//    if (dbus_error_is_set (&error))
//      {
//        nm_warning ("Could not acquire the dbus service.  dbus_bus_request_name() says: '%s'", error.message);
//        goto out;
//      }
    
//    if (!dbus_connection_register_object_path (data->con, NM_DBUS_PATH_PPP, &vtable, data))
//      {
//        nm_warning ("Could not register a dbus handler for nm-ppp-service.  Not enough memory?");
//        dbus_connection_unref(data->con);
//        data->con = NULL;
//      }
out:
    if (dbus_error_is_set (&error))
      {
        dbus_error_free (&error);
        data->con = NULL;
      }
    if (data->con == NULL) return FALSE;
    return TRUE;
}

void nm_dbus_kill_connection(NmPPPData *data)
{
    g_return_if_fail (data != NULL);

    if (data->con != NULL)
      dbus_connection_unref(data->con);
    if (data->username!=NULL) g_free(data->username);
    if (data->password!=NULL) g_free(data->password);
}

/*
 * nm_dbus_message_handler
 *
 * Handle requests for our services.
 *
 */
static DBusHandlerResult nm_dbus_message_handler (DBusConnection *con, DBusMessage *message, void *user_data)
{
  NmPPPData		    *data = (NmPPPData *)user_data;
  const char		*method;
  const char		*path;
  DBusMessage		*reply = NULL;
  gboolean			 handled = TRUE;

  g_return_val_if_fail (data != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
  g_return_val_if_fail (con != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
  g_return_val_if_fail (message != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

  method = dbus_message_get_member (message);
  path = dbus_message_get_path (message);

  nm_info ("nm_dbus_message_handler() got method '%s' for path '%s'.", method, path); 

  handled = FALSE;
  
// reply:
  if (reply)
    {
      dbus_connection_send (con, reply, NULL);
      dbus_message_unref (reply);
    }

  return (handled ? DBUS_HANDLER_RESULT_HANDLED : DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
}


int nm_chap_check_hook(void)
{
    plugin_data.pppd_pid=getpid();
    nm_notify_pid (&plugin_data);

    if (! nm_get_auth_items (&plugin_data))
      {
        return 0;
      }

    if (strcmp("CHAP",plugin_data.auth_type)!=0)
      {
        info("nm-pppd-plugin: No CHAP authentication available!");
        return 0;
      }
    

    info("nm-pppd-plugin: CHAP check hook.");
    return 1;
}

int nm_chap_passwd_hook(char *user, char *passwd)
{
    info("nm-pppd-plugin: CHAP credentials requested.");

    if (user == NULL)
      {
        info("nm-pppd-plugin: pppd didn't provide username buffer");
        return -1;
      }

    if (passwd == NULL)
      {
        info("nm-pppd-plugin: pppd didn't provide password buffer");
        return -1;
      }

    if (plugin_data.username == NULL)
      {
        info("nm-pppd-plugin: CHAP username not set");
        return -1;
      }

    if (plugin_data.password == NULL)
      {
        info("nm-pppd-plugin: CHAP password not set");
        return -1;
      }

    if (strlen(plugin_data.username) >= MAXNAMELEN)
      {
        info("nm-pppd-plugin: CHAP username too long!");
        return -1;
      }

    if (strlen(plugin_data.password) >= MAXSECRETLEN)
      {
        info("nm-pppd-plugin: CHAP password too long!");
        return -1;
      }

    strcpy(user, plugin_data.username);
    user[MAXNAMELEN-1]='\0';
    strcpy(passwd, plugin_data.password);
    passwd[MAXSECRETLEN-1]='\0';
//    info("nm-pppd-plugin: CHAP authenticating as '%s' with '%s'",user,passwd);
//
// Forget the username and password?
//
//    if (plugin_data.username!=NULL) g_free(plugin_data.username);
//    if (plugin_data.password!=NULL) g_free(plugin_data.password);

    return 0;
}

void nm_exit_notify(void *opaque, int arg)
{
  NmPPPData *data = (NmPPPData *)opaque;

  nm_dbus_kill_connection(data);
}

void nm_ip_down(void *opaque, int arg)
{   
//  DBusConnection *con = (DBusConnection *)opaque;

  return;
}

void nm_ip_up(void *opaque, int arg)
{
  NmPPPData *data = (NmPPPData *)opaque;
  DBusConnection *con = data->con;
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
  guint32		uint_ip4_ptp_address  = 0;
  guint32		uint_ip4_netmask  = 0xFFFFFFFF; /* Default mask of 255.255.255.255 */
//  guint32 i=0;

 
  g_return_if_fail (con != NULL);
  if (ipcp_gotoptions[ifunit].ouraddr==0) {
    info ("nm-pppd-plugin: didn't receive an Internal IP4 Address from ppp.");
    send_config_error (con, "IP4 Address");
    return;
  }
  uint_ip4_address=ipcp_gotoptions[ifunit].ouraddr;
  
  if (!(message = dbus_message_new_method_call (NM_DBUS_SERVICE_PPP_STARTER, NM_DBUS_PATH_PPP_STARTER, NM_DBUS_INTERFACE_PPP_STARTER, "signalIP4Config")))
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
  }
 
  if (ifname==NULL) {
    info ("nm-pppd-plugin: didn't receive a tunnel device name.");
    send_config_error (con, "IP4 Address");
  }
  str_ifname = g_strdup(ifname);

  dbus_message_append_args (message, 
			    DBUS_TYPE_STRING, &str_ifname,
			    DBUS_TYPE_UINT32, &uint_ip4_address,
			    DBUS_TYPE_UINT32, &uint_ip4_ptp_address,
			    DBUS_TYPE_UINT32, &uint_ip4_netmask,
// Array workaround
                DBUS_TYPE_UINT32, &uint_ip4_dns1,
			    DBUS_TYPE_UINT32, &uint_ip4_dns2,
			    DBUS_TYPE_UINT32, &uint_ip4_dns_len,
			    DBUS_TYPE_UINT32, &uint_ip4_wins1,
			    DBUS_TYPE_UINT32, &uint_ip4_wins2,
			    DBUS_TYPE_UINT32, &uint_ip4_wins_len, 
			    DBUS_TYPE_INVALID);

  if (!dbus_connection_send (con, message, NULL)) {
    info ("nm_ip_up(): could not send dbus message");
    dbus_message_unref (message);
    g_free(str_ifname);
    return;
  }
  
  g_free(str_ifname);
  dbus_message_unref (message);
  return;
}


/*
 * send_config_error
 *
 * Notify nm-ppp-starter of a config error from pppd.
 *
*/
void send_config_error (DBusConnection *con, const char *item)
{
  DBusMessage		*message;

  g_return_if_fail (con != NULL);
  g_return_if_fail (item != NULL);

  if (!(message = dbus_message_new_method_call (NM_DBUS_SERVICE_PPP_STARTER, NM_DBUS_PATH_PPP_STARTER, NM_DBUS_INTERFACE_PPP_STARTER, "signalConfigError")))
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
 * nm_notify_pid
 *
 * Let the pppd starter service know our PID
 * so that pppd may be killed later.
 *
 */
void nm_notify_pid (NmPPPData *data)
{
  DBusConnection *con;
  DBusMessage *message = NULL;

  if (!nm_dbus_prepare_connection(data)) 
      return;
   
  con = data->con;
  if (!(message = dbus_message_new_method_call (NM_DBUS_SERVICE_PPP_STARTER, NM_DBUS_PATH_PPP_STARTER, NM_DBUS_INTERFACE_PPP_STARTER, "notifyPID")))
  {
    nm_warning ("nm-pppd-plugin: Couldn't allocate the notifyPID dbus message");
    return;
  }

  dbus_message_append_args (message, 
        DBUS_TYPE_UINT32, &(data->pppd_pid),
        DBUS_TYPE_INVALID);

  if (!dbus_connection_send (con, message, NULL)) {
    info ("nm_ip_up(): could not send dbus message");
    dbus_message_unref (message);
    return;
  }
 
//  nm_warning("Sent notify message: %d",data->pppd_pid);
  dbus_message_unref (message);
}
/*
 * nm_get_auth_items
 *
 * Request credentials from PPP_STARTER service.
 *
 */
gboolean nm_get_auth_items (NmPPPData *data)
{
  DBusConnection *con;
  int num_auth_items = -1;
  char *auth_items[3] = { NULL, NULL, NULL };
//  char **auth_items = NULL;
  DBusMessage *message = NULL;
  DBusMessage *reply = NULL;

  if (!nm_dbus_prepare_connection(data)) 
      return FALSE;
   
  con = data->con;

  g_return_val_if_fail (con != NULL,FALSE);
  if (!(message = dbus_message_new_method_call (NM_DBUS_SERVICE_PPP_STARTER, NM_DBUS_PATH_PPP_STARTER, NM_DBUS_INTERFACE_PPP_STARTER, "getAuthInfo")))
  {
    nm_warning("nm-pppd-plugin: failed to create getAuthInfo message.");
    return FALSE;
  }

  reply = dbus_connection_send_with_reply_and_block (con, message, -1, NULL);
  dbus_message_unref (message);
  if (!reply)
    {
      info("nm-pppd-plugin: no reply to getAuthInfo message.");
      return FALSE;
    }

  if (!(dbus_message_get_args (reply, NULL, 
              DBUS_TYPE_STRING, &(auth_items[0]),
              DBUS_TYPE_STRING, &(auth_items[1]),
              DBUS_TYPE_STRING, &(auth_items[2]),
//              DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &auth_items, &num_auth_items, 
              DBUS_TYPE_INVALID)))
  {
    dbus_message_unref (reply);
    return FALSE;
  }
  num_auth_items=3;

  if (!nm_store_auth_info (data, auth_items, num_auth_items))
  {
    //dbus_free_string_array (auth_items);
    dbus_message_unref (reply);
    return FALSE;
  }

  //dbus_free_string_array (auth_items);
  dbus_message_unref (reply);
  return TRUE;
}

/*
 * nm_store_auth_info
 *
 * Decode and temporarily store the authentication info provided.
 *
 */
gboolean nm_store_auth_info (NmPPPData *data, char **auth_items, int num_auth_items)
{
//  int i=0;
  g_return_val_if_fail (auth_items != NULL, FALSE);
  g_return_val_if_fail (num_auth_items >= 1, FALSE);

  nm_warning ("PPPD will authenticate using '%s'.", auth_items[0]);
  
  if (strcmp ("CHAP", auth_items[0]) == 0) {
    g_return_val_if_fail (num_auth_items >= 3, FALSE);
    if (data->auth_type!=NULL) g_free(data->auth_type);
    if (data->username!=NULL) g_free(data->username);
    if (data->password!=NULL) g_free(data->password);
    data->auth_type=g_strdup(auth_items[0]);
    data->username=g_strdup(auth_items[1]);
    data->password=g_strdup(auth_items[2]);
  } else if (strcmp ("NONE", auth_items[0]) == 0) {
    if (data->auth_type!=NULL) g_free(data->auth_type);
    if (data->username!=NULL) g_free(data->username);
    if (data->password!=NULL) g_free(data->password);
    data->auth_type=g_strdup(auth_items[0]);
  } else {
	  nm_warning ("PPPD authentication type '%s' is not allowed.", auth_items[0]);
      return FALSE;
  }

  data->got_auth_info=TRUE;
  return TRUE;
}

int plugin_init()
{
//    DBusConnection *	con = NULL;
//    DBusMessage *	message = NULL;
//    DBusError		error;

//    g_type_init ();
//    if (!g_thread_supported ())
//      g_thread_init (NULL);
    
//    dbus_error_init (&error);
//    con = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
//    if ((con == NULL) || dbus_error_is_set (&error))
//      {
//        dbus_error_free (&error);
//        info("Could not get the system bus.  Make sure the message bus daemon is running?");
//        return -1;
//      }
//    dbus_connection_set_exit_on_disconnect (con, FALSE);
//
//
//    dbus_error_free (&error);

//    add_options(ppp_options);

    chap_check_hook = nm_chap_check_hook;
    chap_passwd_hook = nm_chap_passwd_hook;

    add_notifier(&ip_down_notifier, nm_ip_down, (void *) &plugin_data);
    add_notifier(&ip_up_notifier, nm_ip_up, (void *) &plugin_data);
    add_notifier(&exitnotify, nm_exit_notify, (void *) &plugin_data);

    info("nm-pppd-plugin: plugin initialized.");
    return 0;
}


