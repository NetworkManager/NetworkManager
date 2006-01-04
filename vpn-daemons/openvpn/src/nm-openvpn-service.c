/* nm-openvpn-service - openvpn integration with NetworkManager
 *
 * Tim Niemueller <tim@niemueller.de>
 * Based on work by Dan Williams <dcbw@redhat.com>
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
 * $Id$
 *
 */


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib/gi18n.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>

#include <NetworkManager/NetworkManager.h>
#include <NetworkManager/NetworkManagerVPN.h>

#include "nm-openvpn-service.h"
#include "nm-utils.h"


static const char *openvpn_binary_paths[] =
{
  "/usr/sbin/openvpn",
  "/sbin/openvpn",
  NULL
};

#define NM_OPENVPN_HELPER_PATH		BINDIR"/nm-openvpn-service-openvpn-helper"


typedef struct _NmOpenVPN_IOData
{
  char           *username;
  char           *password;
  char           *certpass;
  gint            child_stdin_fd;
  gint            child_stdout_fd;
  gint            child_stderr_fd;
  GIOChannel     *socket_channel;
  guint           socket_channel_eventid;
} NmOpenVPN_IOData;

typedef struct NmOpenVPNData
{
  GMainLoop            *loop;
  DBusConnection       *con;
  NMVPNState		state;
  GPid			pid;
  guint			quit_timer;
  guint			helper_timer;
  gint                  connection_type;
  guint                 connect_timer;
  guint                 connect_count;
  NmOpenVPN_IOData     *io_data;
} NmOpenVPNData;

static gboolean nm_openvpn_dbus_handle_stop_vpn (NmOpenVPNData *data);


/*
 * nm_dbus_create_error_message
 *
 * Make a DBus error message
 *
 */
static DBusMessage *
nm_dbus_create_error_message (DBusMessage *message, const char *exception_namespace,
			      const char *exception, const char *format, ...)
{
  char *exception_text;
  DBusMessage	*reply;
  va_list		 args;
  char			 error_text[512];

  va_start (args, format);
  vsnprintf (error_text, 512, format, args);
  va_end (args);

  exception_text = g_strdup_printf ("%s.%s", exception_namespace, exception);
  reply = dbus_message_new_error (message, exception_text, error_text);
  g_free (exception_text);
  
  return (reply);
}


/*
 * nm_openvpn_dbus_signal_failure
 *
 * Signal the bus that some VPN operation failed.
 *
 */
static void
nm_openvpn_dbus_signal_failure (NmOpenVPNData *data, const char *signal)
{
  DBusMessage	*message;
  const char	*error_msg = NULL;

  g_return_if_fail (data != NULL);
  g_return_if_fail (signal != NULL);

  if ( strcmp (signal, NM_DBUS_VPN_SIGNAL_LOGIN_FAILED) == 0 )
    error_msg = _("The VPN login failed because the user name and password were not accepted or the certificate password was wrong.");
  else if (strcmp (signal, NM_DBUS_VPN_SIGNAL_LAUNCH_FAILED) == 0 )
    error_msg = _("The VPN login failed because the VPN program could not be started.");
  else if (strcmp (signal, NM_DBUS_VPN_SIGNAL_CONNECT_FAILED) == 0 )
    error_msg = _("The VPN login failed because the VPN program could not connect to the VPN server.");
  else if (strcmp (signal, NM_DBUS_VPN_SIGNAL_VPN_CONFIG_BAD) == 0 )
    error_msg = _("The VPN login failed because the VPN configuration options were invalid.");
  else if (strcmp (signal, NM_DBUS_VPN_SIGNAL_IP_CONFIG_BAD) == 0 )
    error_msg = _("The VPN login failed because the VPN program received an invalid configuration from the VPN server.");
  else
    error_msg = _("VPN connection failed");

  if (!error_msg)
    return;

  if (!(message = dbus_message_new_signal (NM_DBUS_PATH_OPENVPN, NM_DBUS_INTERFACE_OPENVPN, signal)))
    {
      nm_warning ("Not enough memory for new dbus message!");
      return;
    }

  dbus_message_append_args (message, DBUS_TYPE_STRING, &error_msg, DBUS_TYPE_INVALID);
  if (!dbus_connection_send (data->con, message, NULL))
    nm_warning ("Could not raise the signal!");

  dbus_message_unref (message);
}


/*
 * nm_openvpn_dbus_signal_state_change
 *
 * Signal the bus that our state changed.
 *
 */
static void
nm_openvpn_dbus_signal_state_change (NmOpenVPNData *data, NMVPNState old_state)
{
  DBusMessage	*message;

  g_return_if_fail (data != NULL);

  if (!(message = dbus_message_new_signal (NM_DBUS_PATH_OPENVPN, NM_DBUS_INTERFACE_OPENVPN, NM_DBUS_VPN_SIGNAL_STATE_CHANGE)))
    {
      nm_warning ("nm_openvpn_dbus_signal_state_change(): Not enough memory for new dbus message!");
      return;
    }

  dbus_message_append_args (message, DBUS_TYPE_UINT32, &old_state, DBUS_TYPE_UINT32, &(data->state), DBUS_TYPE_INVALID);

  if (!dbus_connection_send (data->con, message, NULL))
    nm_warning ("nm_openvpn_dbus_signal_state_change(): Could not raise the signal!");

  dbus_message_unref (message);
}


/*
 * nm_openvpn_set_state
 *
 * Set our state and make sure to signal the bus.
 *
 */
static void
nm_openvpn_set_state (NmOpenVPNData *data, NMVPNState new_state)
{
  NMVPNState	old_state;

  g_return_if_fail (data != NULL);

  old_state = data->state;

  if (old_state != new_state)
    {
      data->state = new_state;
      nm_openvpn_dbus_signal_state_change (data, old_state);
    }
}


/*
 * nm_openvpn_quit_timer_cb
 *
 * Callback to quit nm-openvpn-service after a certain period of time.
 *
 */
static gboolean
nm_openvpn_quit_timer_cb (NmOpenVPNData *data)
{
  data->quit_timer = 0;

  g_return_val_if_fail (data != NULL, FALSE);

  g_main_loop_quit (data->loop);

  return FALSE;
}


/*
 * nm_openvpn_schedule_quit_timer
 *
 * If openvpn isn't running, and we haven't been asked to do anything in a while,
 * then we just exit since NetworkManager will re-launch us later.
 *
 */
static void
nm_openvpn_schedule_quit_timer (NmOpenVPNData *data, guint interval)
{
  g_return_if_fail (data != NULL);

  if (data->quit_timer == 0)
    data->quit_timer = g_timeout_add (interval, (GSourceFunc) nm_openvpn_quit_timer_cb, data);
}


/*
 * nm_openvpn_cancel_quit_timer
 *
 * Cancel a quit timer that we've scheduled before.
 *
 */
static void
nm_openvpn_cancel_quit_timer (NmOpenVPNData *data)
{
  g_return_if_fail (data != NULL);

  if (data->quit_timer > 0)
    g_source_remove (data->quit_timer);
}




static void
nm_openvpn_disconnect_management_socket (NmOpenVPNData *data)
{
  g_return_if_fail (data != NULL);

  // This should no throw a warning since this can happen in
  // non-password modes
  if ( data->io_data == NULL) return;

  g_source_remove (data->io_data->socket_channel_eventid);
  g_io_channel_shutdown (data->io_data->socket_channel, FALSE, NULL);
  g_io_channel_unref (data->io_data->socket_channel);

  if (data->io_data->username) g_free (data->io_data->username);
  if (data->io_data->password) g_free (data->io_data->password);

  g_free (data->io_data);
  data->io_data = NULL;
}


/*
 * nm_openvpn_helper_timer_cb
 *
 * If we haven't received the IP4 config info from the helper before the timeout
 * occurs, we kill openvpn
 *
 */
static gboolean
nm_openvpn_helper_timer_cb (NmOpenVPNData *data)
{
  data->helper_timer = 0;

  g_return_val_if_fail (data != NULL, FALSE);

  nm_openvpn_disconnect_management_socket (data);

  nm_openvpn_dbus_signal_failure (data, NM_DBUS_VPN_SIGNAL_CONNECT_FAILED);
  nm_openvpn_dbus_handle_stop_vpn (data);

  return FALSE;
}


/*
 * nm_openvpn_schedule_helper_timer
 *
 * Once openvpn is running, we wait for the helper to return the IP4 configuration
 * information to us.  If we don't receive that information within 7 seconds,
 * we kill openvpn
 *
 */
static void
nm_openvpn_schedule_helper_timer (NmOpenVPNData *data)
{
  g_return_if_fail (data != NULL);

  if (data->helper_timer == 0)
    data->helper_timer = g_timeout_add (10000, (GSourceFunc) nm_openvpn_helper_timer_cb, data);
}


/*
 * nm_openvpn_cancel_helper_timer
 *
 * Cancel a helper timer that we've scheduled before.
 *
 */
static void
nm_openvpn_cancel_helper_timer (NmOpenVPNData *data)
{
  g_return_if_fail (data != NULL);

  if (data->helper_timer > 0)
    g_source_remove (data->helper_timer);
}


/*
 * nm_openvpn_csocket_data_cb
 *
 * Called if data is available on the management connection, if asked for user or
 * password it is sent. After password has been sent associated data will be freed
 * and channel closed by returning FALSE.
 *
 */
static gboolean
nm_openvpn_socket_data_cb (GIOChannel *source, GIOCondition condition, gpointer user_data)
{
  NmOpenVPNData    *data    = (NmOpenVPNData *)user_data;
  NmOpenVPN_IOData *io_data = data->io_data;
  char *str = NULL;

  if (! (condition & G_IO_IN))
    return TRUE;

  if (g_io_channel_read_line (source, &str, NULL, NULL, NULL) == G_IO_STATUS_NORMAL) {
    int len;

    len = strlen (str);
    if ( len > 0 ) {
      char *auth;

      // printf("Read: %s\n", str);

      if ( sscanf(str, ">PASSWORD:Need '%a[^']'", &auth) > 0 ) {

	if ( strcmp (auth, "Auth") == 0) {

	  if ( (io_data->username != NULL) &&
	       (io_data->password != NULL) ) {
	    gsize written;
	    char *buf = g_strdup_printf ("username \"%s\" %s\n"
					 "password \"%s\" %s\n",
					 auth, io_data->username,
					 auth, io_data->password);
	    /* Will always write everything in blocking channels (on success) */
	    g_io_channel_write_chars (source, buf, strlen (buf), &written, NULL);
	    g_io_channel_flush (source, NULL);
	    g_free (buf);
	  }
	} else if ( strcmp (auth, "Private Key") == 0 ) {
	  if ( io_data->certpass != NULL ) {
	    gsize written;
	    char *buf = g_strdup_printf ("password \"%s\" %s\n",
					 auth, io_data->certpass);
	    // printf("1: sending: %s\n", buf);
	    /* Will always write everything in blocking channels (on success) */
	    g_io_channel_write_chars (source, buf, strlen (buf), &written, NULL);
	    g_io_channel_flush (source, NULL);
	    g_free (buf);
	  } else {
	    nm_warning("Certificate password requested but certpass == NULL");
	  }
	} else {
	  nm_warning("No clue what to send for username/password request for '%s'", auth);
	  nm_openvpn_dbus_signal_failure (data, NM_DBUS_VPN_SIGNAL_LOGIN_FAILED);
	  nm_openvpn_disconnect_management_socket (data);
	}

	g_free (auth);
	return TRUE;

      } else if ( strstr(str, ">PASSWORD:Verification Failed: ") == str ) {

	nm_warning("Password verification failed");

	nm_openvpn_dbus_signal_failure (data, NM_DBUS_VPN_SIGNAL_LOGIN_FAILED);
	nm_openvpn_disconnect_management_socket (data);

	return FALSE;
      }
    }
  }

  g_free (str);

  return TRUE;
}


/*
 * nm_openvpn_connect_timer_cb
 *
 * We need to wait until OpenVPN has started the management socket
 *
 */
static gboolean
nm_openvpn_connect_timer_cb (NmOpenVPNData *data)
{
  struct sockaddr_in     serv_addr;
  gboolean               connected = FALSE;
  gint                   socket_fd = -1;
  NmOpenVPN_IOData      *io_data;

  g_return_val_if_fail (data != NULL, FALSE);

  io_data = data->io_data;
  g_return_val_if_fail (io_data != NULL, FALSE);

  data->connect_timer = 0;
  data->connect_count++;

  // open socket and start listener
  socket_fd = socket( PF_INET, SOCK_STREAM, IPPROTO_TCP );
  if ( socket_fd < 0 ) {
    // we failed
    return FALSE;
  }

  serv_addr.sin_family = AF_INET;
  inet_aton("127.0.0.1", &(serv_addr.sin_addr));
  serv_addr.sin_port = htons( 1194 );
 
  connected = ( connect (socket_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0 );

  if ( ! connected ) {
    close ( socket_fd );
    if ( data->connect_count <= 30 ) {
      return TRUE;
    } else {
      nm_warning ("Could not open management socket");
      nm_openvpn_dbus_signal_failure (data, NM_DBUS_VPN_SIGNAL_LAUNCH_FAILED);
      return FALSE;
    }
  } else {
    GIOChannel            *openvpn_socket_channel;
    guint                  openvpn_socket_channel_eventid;
    
    openvpn_socket_channel = g_io_channel_unix_new (socket_fd);
    openvpn_socket_channel_eventid = g_io_add_watch (openvpn_socket_channel, G_IO_IN, nm_openvpn_socket_data_cb, data);
    g_io_channel_set_encoding (openvpn_socket_channel, NULL, NULL);

    io_data->socket_channel = openvpn_socket_channel;
    io_data->socket_channel_eventid = openvpn_socket_channel_eventid;

    return FALSE;
  }
}


/*
 * nm_openvpn_schedule_helper_timer
 *
 * Once openvpn is running, we wait for the helper to return the IP4 configuration
 * information to us.  If we don't receive that information within 7 seconds,
 * we kill openvpn
 *
 */
static void
nm_openvpn_schedule_connect_timer (NmOpenVPNData *data)
{
  g_return_if_fail (data != NULL);
  g_return_if_fail (data->io_data != NULL);

  if (data->connect_timer == 0)
    data->connect_timer = g_timeout_add (200, (GSourceFunc) nm_openvpn_connect_timer_cb, data);
}


/*
 * nm_openvpn_cancel_helper_timer
 *
 * Cancel a helper timer that we've scheduled before.
 *
 */
static void
nm_openvpn_cancel_connect_timer (NmOpenVPNData *data)
{
  g_return_if_fail (data != NULL);

  if (data->connect_timer > 0) {
    g_source_remove (data->connect_timer);
    data->connect_timer = 0;
    data->connect_count = 0;
  }
}




/*
 * openvpn_watch_cb
 *
 * Watch our child openvpn process and get notified of events from it.
 *
 */
static void
openvpn_watch_cb (GPid pid, gint status, gpointer user_data)
{
  guint	error = -1;

  NmOpenVPNData *data = (NmOpenVPNData *)user_data;

  if (WIFEXITED (status))
    {
      error = WEXITSTATUS (status);
      if (error != 0)
	nm_warning ("openvpn exited with error code %d", error);
    }
  else if (WIFSTOPPED (status))
    nm_warning ("openvpn stopped unexpectedly with signal %d", WSTOPSIG (status));
  else if (WIFSIGNALED (status))
    nm_warning ("openvpn died with signal %d", WTERMSIG (status));
  else
    nm_warning ("openvpn died from an unknown cause");
  
  /* Reap child if needed. */
  waitpid (data->pid, NULL, WNOHANG);
  data->pid = 0;

  /* Must be after data->state is set since signals use data->state */
  /* This is still code from vpnc, openvpn does not supply useful exit codes :-/ */
  switch (error)
    {
    case 2:	/* Couldn't log in due to bad user/pass */
      nm_openvpn_dbus_signal_failure (data, NM_DBUS_VPN_SIGNAL_LOGIN_FAILED);
      break;

    case 1:	/* Other error (couldn't bind to address, etc) */
      nm_openvpn_dbus_signal_failure (data, NM_DBUS_VPN_SIGNAL_CONNECT_FAILED);
      break;

    default:
      break;
    }

  nm_openvpn_set_state (data, NM_VPN_STATE_STOPPED);
  nm_openvpn_schedule_quit_timer (data, 10000);
}



/*
 * nm_openvpn_start_vpn_binary
 *
 * Start the openvpn binary with a set of arguments and a config file.
 *
 */
static gint
nm_openvpn_start_openvpn_binary (NmOpenVPNData *data,
				 char **data_items, const int num_items,
				 char **passwords, const int num_passwords
				 )
{
  GPid	        pid;
  const char  **openvpn_binary = NULL;
  GPtrArray    *openvpn_argv;
  GError       *error = NULL;
  GSource      *openvpn_watch;
  gint	        stdin_fd = -1;
  gint          stdout_fd = -1;
  gint          stderr_fd = -1;
  int           i = 0;

  char         *username = NULL;
  char         *dev = NULL;
  char         *proto = NULL;
  char         *port = NULL;


  g_return_val_if_fail (data != NULL, -1);

  data->pid = 0;

  if ( (num_items == 0) || (data_items == NULL) ) {
    return -1;
  }

  /* Find openvpn */
  openvpn_binary = openvpn_binary_paths;
  while (*openvpn_binary != NULL) {
    if (g_file_test (*openvpn_binary, G_FILE_TEST_EXISTS))
      break;
    openvpn_binary++;
  }

  if (!*openvpn_binary) {
    nm_info ("Could not find openvpn binary.");
    return -1;
  }

  // First check in which mode we are operating. Since NM does not
  // guarantee any particular order we search this parameter
  // explictly once
  data->connection_type = NM_OPENVPN_CONTYPE_INVALID;
  for (i = 0; i < num_items; ++i) {
    if ( strcmp( data_items[i], "connection-type" ) == 0) {
      ++i;
      if ( strcmp (data_items[i], "x509" ) == 0 ) {
	data->connection_type = NM_OPENVPN_CONTYPE_X509;
      } else if ( strcmp (data_items[i], "shared-key" ) == 0 ) {
	data->connection_type = NM_OPENVPN_CONTYPE_SHAREDKEY;
      } else if ( strcmp (data_items[i], "password" ) == 0 ) {
	data->connection_type = NM_OPENVPN_CONTYPE_PASSWORD;
      } else if ( strcmp (data_items[i], "x509userpass" ) == 0 ) {
	data->connection_type = NM_OPENVPN_CONTYPE_X509USERPASS;
      }
    } else if ( strcmp (data_items[i], "username" ) == 0) {
      username = data_items[++i];
    }
  }

  if ( data->connection_type != NM_OPENVPN_CONTYPE_INVALID ) {

    openvpn_argv = g_ptr_array_new ();
    g_ptr_array_add (openvpn_argv, (gpointer) (*openvpn_binary));

    // Note that it should be guaranteed that num_items % 2 == 0
    // Add global arguments
    for (i = 0; i < num_items; ++i) {
      if ( strcmp( data_items[i], "remote" ) == 0) {
	g_ptr_array_add (openvpn_argv, (gpointer) "--remote");
	g_ptr_array_add (openvpn_argv, (gpointer) data_items[++i]);
      } else if ( (strcmp( data_items[i], "comp-lzo" ) == 0) &&
		  (strcmp( data_items[++i], "yes" ) == 0) ) {
	g_ptr_array_add (openvpn_argv, (gpointer) "--comp-lzo");
      } else if ( (strcmp( data_items[i], "dev" ) == 0) ) {
	dev = data_items[++i];
      } else if ( (strcmp( data_items[i], "proto" ) == 0) ) {
	proto = data_items[++i];
      } else if ( (strcmp( data_items[i], "port") == 0) ) {
	port = data_items[++i];
      }
    }
    g_ptr_array_add (openvpn_argv, (gpointer) "--nobind");

    // Device, either tun or tap
    g_ptr_array_add (openvpn_argv, (gpointer) "--dev");
    if ( (dev != NULL) ) {
      g_ptr_array_add (openvpn_argv, (gpointer) dev);
    } else {
      // Versions prior to 0.3.0 didn't set this so we default for
      // tun for these configs
      g_ptr_array_add (openvpn_argv, (gpointer) "tun");
    }

    // Protocol, either tcp or udp
    g_ptr_array_add (openvpn_argv, (gpointer) "--proto");
    if ( (proto != NULL) ) {
      g_ptr_array_add (openvpn_argv, (gpointer) proto);
    } else {
      // Versions prior to 0.3.1 didn't set this so we default for
      // udp for these configs
      g_ptr_array_add (openvpn_argv, (gpointer) "udp");
    }

    // Port
    g_ptr_array_add (openvpn_argv, (gpointer) "--port");
    if ( (port != NULL) ) {
      g_ptr_array_add (openvpn_argv, (gpointer) port);
    } else {
      // Versions prior to 0.3.2 didn't set this so we default to
      // IANA assigned port 1194
      g_ptr_array_add (openvpn_argv, (gpointer) "1194");
    }

    // Syslog
    g_ptr_array_add (openvpn_argv, (gpointer) "--syslog");
    g_ptr_array_add (openvpn_argv, (gpointer) "nm-openvpn");

    // Up script, called when connection has been established or has been restarted
    g_ptr_array_add (openvpn_argv, (gpointer) "--up");
    g_ptr_array_add (openvpn_argv, (gpointer) NM_OPENVPN_HELPER_PATH);
    g_ptr_array_add (openvpn_argv, (gpointer) "--up-restart");

    // Keep key and tun if restart is needed
    g_ptr_array_add (openvpn_argv, (gpointer) "--persist-key");
    g_ptr_array_add (openvpn_argv, (gpointer) "--persist-tun");

    // Management socket for localhost access to supply username and password
    g_ptr_array_add (openvpn_argv, (gpointer) "--management");
    g_ptr_array_add (openvpn_argv, (gpointer) "127.0.0.1");
    // with have nobind, thus 1194 should be free, it is the IANA assigned port
    g_ptr_array_add (openvpn_argv, (gpointer) "1194");
    // Query on the management socket for user/pass
    g_ptr_array_add (openvpn_argv, (gpointer) "--management-query-passwords");


    // Now append configuration options which are dependent on the configuration type
    switch ( data->connection_type ) {

    case NM_OPENVPN_CONTYPE_X509:

      g_ptr_array_add (openvpn_argv, (gpointer) "--client");
      g_ptr_array_add (openvpn_argv, (gpointer) "--ns-cert-type");
      g_ptr_array_add (openvpn_argv, (gpointer) "server");

      for (i = 0; i < num_items; ++i) {
	if ( strcmp( data_items[i], "ca" ) == 0) {
	  g_ptr_array_add (openvpn_argv, (gpointer) "--ca");
	  g_ptr_array_add (openvpn_argv, (gpointer) data_items[++i]);
	} else if ( strcmp( data_items[i], "cert" ) == 0) {
	  g_ptr_array_add (openvpn_argv, (gpointer) "--cert");
	  g_ptr_array_add (openvpn_argv, (gpointer) data_items[++i]);
	} else if ( strcmp( data_items[i], "key" ) == 0) {
	  g_ptr_array_add (openvpn_argv, (gpointer) "--key");
	  g_ptr_array_add (openvpn_argv, (gpointer) data_items[++i]);
	}
      }
      break;

    case NM_OPENVPN_CONTYPE_SHAREDKEY:
      {
	char *local_ip = NULL;
	char *remote_ip = NULL;

	// Note that it should be guaranteed that num_items % 2 == 0
	for (i = 0; i < num_items; ++i) {
	  if ( strcmp( data_items[i], "local-ip" ) == 0) {
	    local_ip = data_items[++i];
	  } else if ( strcmp( data_items[i], "remote-ip" ) == 0) {
	    remote_ip = data_items[++i];
	  } else if ( strcmp( data_items[i], "shared-key" ) == 0) {
	    g_ptr_array_add (openvpn_argv, (gpointer) "--secret");
	    g_ptr_array_add (openvpn_argv, (gpointer) data_items[++i]);
	  }

	}

	if ( (local_ip == NULL) || (remote_ip == NULL) ) {
	  // Insufficient data
	    g_ptr_array_free (openvpn_argv, TRUE);
	    return -1;
	} else {
	  g_ptr_array_add (openvpn_argv, (gpointer) "--ifconfig");
	  g_ptr_array_add (openvpn_argv, (gpointer) local_ip);
	  g_ptr_array_add (openvpn_argv, (gpointer) remote_ip);
	}
      }
      break;
      
    case NM_OPENVPN_CONTYPE_PASSWORD:

      // Client mode
      g_ptr_array_add (openvpn_argv, (gpointer) "--client");
      g_ptr_array_add (openvpn_argv, (gpointer) "--ns-cert-type");
      g_ptr_array_add (openvpn_argv, (gpointer) "server");
      // Use user/path authentication
      g_ptr_array_add (openvpn_argv, (gpointer) "--auth-user-pass");

      for (i = 0; i < num_items; ++i) {
	if ( strcmp( data_items[i], "ca" ) == 0) {
	  g_ptr_array_add (openvpn_argv, (gpointer) "--ca");
	  g_ptr_array_add (openvpn_argv, (gpointer) data_items[++i]);
	}
      }
      break;


    case NM_OPENVPN_CONTYPE_X509USERPASS:

      g_ptr_array_add (openvpn_argv, (gpointer) "--client");
      g_ptr_array_add (openvpn_argv, (gpointer) "--ns-cert-type");
      g_ptr_array_add (openvpn_argv, (gpointer) "server");

      for (i = 0; i < num_items; ++i) {
	if ( strcmp( data_items[i], "ca" ) == 0) {
	  g_ptr_array_add (openvpn_argv, (gpointer) "--ca");
	  g_ptr_array_add (openvpn_argv, (gpointer) data_items[++i]);
	} else if ( strcmp( data_items[i], "cert" ) == 0) {
	  g_ptr_array_add (openvpn_argv, (gpointer) "--cert");
	  g_ptr_array_add (openvpn_argv, (gpointer) data_items[++i]);
	} else if ( strcmp( data_items[i], "key" ) == 0) {
	  g_ptr_array_add (openvpn_argv, (gpointer) "--key");
	  g_ptr_array_add (openvpn_argv, (gpointer) data_items[++i]);
	}
      }
      // Use user/path authentication
      g_ptr_array_add (openvpn_argv, (gpointer) "--auth-user-pass");
      break;


    }


    g_ptr_array_add (openvpn_argv, NULL);

    if (!g_spawn_async_with_pipes (NULL, (char **) openvpn_argv->pdata, NULL,
				   G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL, &pid, &stdin_fd,
				   &stdout_fd, &stderr_fd, &error))
      {
	g_ptr_array_free (openvpn_argv, TRUE);
	nm_warning ("openvpn failed to start.  error: '%s'", error->message);
	g_error_free(error);
	return -1;
      }
    g_ptr_array_free (openvpn_argv, TRUE);
    
    nm_info ("openvpn started with pid %d", pid);

    data->pid = pid;
    openvpn_watch = g_child_watch_source_new (pid);
    g_source_set_callback (openvpn_watch, (GSourceFunc) openvpn_watch_cb, data, NULL);
    g_source_attach (openvpn_watch, NULL);
    g_source_unref (openvpn_watch);

    /* Listen to the management socket for a few connection types:
       PASSWORD: Will require username and password
       X509USERPASS: Will require username and password and maybe certificate password
       X509: May require certificate password
    */
    if ( (data->connection_type == NM_OPENVPN_CONTYPE_PASSWORD) ||
	 (data->connection_type == NM_OPENVPN_CONTYPE_X509USERPASS) ||
	 (data->connection_type == NM_OPENVPN_CONTYPE_X509)
	 
	 ) {

      NmOpenVPN_IOData  *io_data;

      io_data                  = g_new0 (NmOpenVPN_IOData, 1);
      io_data->child_stdin_fd  = stdin_fd;
      io_data->child_stdout_fd = stdout_fd;
      io_data->child_stderr_fd = stderr_fd;
      io_data->username        = g_strdup(username);
      io_data->password        = g_strdup(passwords[0]);
      io_data->certpass        = g_strdup(passwords[1]);

      data->io_data = io_data;

      nm_openvpn_schedule_connect_timer (data);
    }

    nm_openvpn_schedule_helper_timer (data);

    return stdin_fd;

  } else {
    return -1;
  }
}


typedef enum OptType
{
	OPT_TYPE_UNKNOWN = 0,
	OPT_TYPE_ADDRESS,
	OPT_TYPE_ASCII,
	OPT_TYPE_INTEGER,
	OPT_TYPE_NONE
} OptType;

typedef struct Option
{
	const char *name;
	OptType type;
} Option;

/*
 * nm_openvpn_config_options_validate
 *
 * Make sure the config options are sane
 *
 */
static gboolean
nm_openvpn_config_options_validate (char **data_items, int num_items)
{
  Option	allowed_opts[] = {
    { "remote",			        OPT_TYPE_ADDRESS },
    { "ca",				OPT_TYPE_ASCII },
    { "dev",				OPT_TYPE_ASCII },
    { "proto",				OPT_TYPE_ASCII },
    { "port",				OPT_TYPE_INTEGER },
    { "cert",				OPT_TYPE_ASCII },
    { "key",				OPT_TYPE_ASCII },
    { "comp-lzo",			OPT_TYPE_ASCII },
    { "shared-key",			OPT_TYPE_ASCII },
    { "local-ip",			OPT_TYPE_ADDRESS },
    { "remote-ip",			OPT_TYPE_ADDRESS },
    { "username",			OPT_TYPE_ASCII },
    { "connection-type",		OPT_TYPE_ASCII },
    { NULL,				OPT_TYPE_UNKNOWN } };
  
  unsigned int	i;

  g_return_val_if_fail (data_items != NULL, FALSE);
  g_return_val_if_fail (num_items >= 2, FALSE);

  /* Must be an even numbers of config options */
  if ((num_items % 2) != 0)
    {
      nm_warning ("The number of VPN config options was not even.");
      return FALSE;
    }
  
  for (i = 0; i < num_items; i += 2)
    {
      Option *opt = NULL;
      unsigned int t, len;
      char *opt_value;
      
      if (!data_items[i] || !data_items[i+1])
	return FALSE;
      opt_value = data_items[i+1];

      /* Find the option in the allowed list */
      for (t = 0; t < sizeof (allowed_opts) / sizeof (Option); t++)
	{
	  opt = &allowed_opts[t];
	  if (opt->name && !strcmp (opt->name, data_items[i]))
	    break;
	}
      if (!opt->name)	/* not found */
	{
	  nm_warning ("VPN option '%s' is not allowed.", data_items[i]);
	  return FALSE;
	}

      /* Don't allow control characters at all */
      len = strlen (opt_value);
      for (t = 0; t < len; t++)
	{
	  if (iscntrl (opt_value[t]))
	    {
	      nm_warning ("There were invalid characters in the VPN option '%s' - '%s'.", data_items[i], opt_value);
	      return FALSE;
	    }
	}

      /* Validate the option's data */
      switch (opt->type)
	{
	case OPT_TYPE_ASCII:
	  /* What other characters should we reject?? */
	  break;
	  
	case OPT_TYPE_NONE:
	  /* These have blank data */
	  break;

	case OPT_TYPE_ADDRESS:
	  /* Can be any legal hostname or IP address */
	  break;

	case OPT_TYPE_INTEGER:
	  break;

	default:
	  return FALSE;
	  break;
	}
    }

  return TRUE;
}


/*
 * nm_openvpn_dbus_handle_start_vpn
 *
 * Parse message arguments and start the VPN connection.
 *
 */
static gboolean
nm_openvpn_dbus_handle_start_vpn (DBusMessage *message, NmOpenVPNData *data)
{
  char **		data_items = NULL;
  int		num_items = -1;
  char **		password_items = NULL;
  int		num_passwords = -1;
  const char *	name = NULL;
  const char *	user_name = NULL;
  DBusError		error;
  gboolean		success = FALSE;
  gint			openvpn_fd = -1;	

  g_return_val_if_fail (message != NULL, FALSE);
  g_return_val_if_fail (data != NULL, FALSE);

  nm_openvpn_set_state (data, NM_VPN_STATE_STARTING);

  dbus_error_init (&error);
  if (!dbus_message_get_args (message, &error,
			      DBUS_TYPE_STRING, &name,
			      DBUS_TYPE_STRING, &user_name,
			      DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &password_items, &num_passwords,
			      DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &data_items, &num_items,
			      DBUS_TYPE_INVALID))
    {
      nm_warning ("Could not process the request because its arguments were invalid.  dbus said: '%s'", error.message);
      nm_openvpn_dbus_signal_failure (data, NM_DBUS_VPN_SIGNAL_VPN_CONFIG_BAD);
      dbus_error_free (&error);
      goto out;
    }

  if (!nm_openvpn_config_options_validate (data_items, num_items))
    {
      nm_openvpn_dbus_signal_failure (data, NM_DBUS_VPN_SIGNAL_VPN_CONFIG_BAD);
      goto out;
    }

  /* Now we can finally try to activate the VPN */
  if ((openvpn_fd = nm_openvpn_start_openvpn_binary (data, data_items, num_items, password_items, num_passwords)) >= 0) {
    // Everything ok
    success = TRUE;
  }

  
out:
  dbus_free_string_array (data_items);
  if (!success)
    nm_openvpn_set_state (data, NM_VPN_STATE_STOPPED);
  return success;
}


/*
 * nm_openvpn_dbus_handle_stop_vpn
 *
 * Stop the running openvpn dameon.
 *
 */
static gboolean nm_openvpn_dbus_handle_stop_vpn (NmOpenVPNData *data)
{
  g_return_val_if_fail (data != NULL, FALSE);

  if (data->pid > 0)
    {
      nm_openvpn_set_state (data, NM_VPN_STATE_STOPPING);

      kill (data->pid, SIGINT);
      nm_info ("Terminated openvpn daemon with PID %d.", data->pid);
      data->pid = 0;

      nm_openvpn_set_state (data, NM_VPN_STATE_STOPPED);
      nm_openvpn_schedule_quit_timer (data, 10000);
    }

  return TRUE;
}


/*
 * nm_openvpn_dbus_start_vpn
 *
 * Begin a VPN connection.
 *
 */
static DBusMessage *
nm_openvpn_dbus_start_vpn (DBusConnection *con, DBusMessage *message, NmOpenVPNData *data)
{
  DBusMessage		*reply = NULL;

  g_return_val_if_fail (data != NULL, NULL);
  g_return_val_if_fail (con != NULL, NULL);
  g_return_val_if_fail (message != NULL, NULL);

  switch (data->state)
    {
    case NM_VPN_STATE_STARTING:
      reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE_OPENVPN, NM_DBUS_VPN_STARTING_IN_PROGRESS,
					    "Could not process the request because the VPN connection is already being started.");
      break;

    case NM_VPN_STATE_STARTED:
      reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE_OPENVPN, NM_DBUS_VPN_ALREADY_STARTED,
					    "Could not process the request because a VPN connection was already active.");
      break;

    case NM_VPN_STATE_STOPPING:
      reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE_OPENVPN, NM_DBUS_VPN_STOPPING_IN_PROGRESS,
					    "Could not process the request because the VPN connection is being stopped.");
      break;

    case NM_VPN_STATE_STOPPED:
      nm_openvpn_cancel_quit_timer (data);
      nm_openvpn_dbus_handle_start_vpn (message, data);
      reply = dbus_message_new_method_return (message);
      break;

    default:
      g_assert_not_reached();
      break;
    }

  return reply;
}


/*
 * nm_openvpn_dbus_stop_vpn
 *
 * Terminate a VPN connection.
 *
 */
static DBusMessage *
nm_openvpn_dbus_stop_vpn (DBusConnection *con, DBusMessage *message, NmOpenVPNData *data)
{
  DBusMessage		*reply = NULL;

  g_return_val_if_fail (data != NULL, NULL);
  g_return_val_if_fail (con != NULL, NULL);
  g_return_val_if_fail (message != NULL, NULL);
  
  switch (data->state)
    {
    case NM_VPN_STATE_STOPPING:
      reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE_OPENVPN, NM_DBUS_VPN_STOPPING_IN_PROGRESS,
					    "Could not process the request because the VPN connection is already being stopped.");
      break;

    case NM_VPN_STATE_STOPPED:
      reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE_OPENVPN, NM_DBUS_VPN_ALREADY_STOPPED,
					    "Could not process the request because no VPN connection was active.");
      break;

    case NM_VPN_STATE_STARTING:
    case NM_VPN_STATE_STARTED:
      nm_openvpn_dbus_handle_stop_vpn (data);
      reply = dbus_message_new_method_return (message);
      break;

    default:
      g_assert_not_reached();
      break;
    }

  return reply;
}


/*
 * nm_openvpn_dbus_get_state
 *
 * Return some state information to NetworkManager.
 *
 */
static DBusMessage *
nm_openvpn_dbus_get_state (DBusConnection *con, DBusMessage *message, NmOpenVPNData *data)
{
  DBusMessage		*reply = NULL;

  g_return_val_if_fail (data != NULL, NULL);
  g_return_val_if_fail (con != NULL, NULL);
  g_return_val_if_fail (message != NULL, NULL);

  if ((reply = dbus_message_new_method_return (message)))
    dbus_message_append_args (reply, DBUS_TYPE_UINT32, &(data->state), DBUS_TYPE_INVALID);

  return reply;
}


/*
 * nm_openvpn_dbus_process_helper_config_error
 *
 * Signal the bus that the helper could not get all the configuration information
 * it needed.
 *
 */
static void
nm_openvpn_dbus_process_helper_config_error (DBusConnection *con, DBusMessage *message, NmOpenVPNData *data)
{
  char *error_item;

  g_return_if_fail (data != NULL);
  g_return_if_fail (con != NULL);
  g_return_if_fail (message != NULL);

  /* Only accept the config info if we're in STARTING state */
  if (data->state != NM_VPN_STATE_STARTING)
    return;

  if (dbus_message_get_args (message, NULL, DBUS_TYPE_STRING, &error_item, DBUS_TYPE_INVALID))
    {
      nm_warning ("openvpn helper did not receive adequate configuration information from openvpn.  It is missing '%s'.", error_item);
      nm_openvpn_dbus_signal_failure (data, NM_DBUS_VPN_SIGNAL_IP_CONFIG_BAD);
    }

  nm_openvpn_cancel_helper_timer (data);
  nm_openvpn_disconnect_management_socket (data);
  nm_openvpn_dbus_handle_stop_vpn (data);
}


/*
 * nm_openvpn_dbus_process_helper_ip4_config
 *
 * Signal the bus 
 *
 */
static void
nm_openvpn_dbus_process_helper_ip4_config (DBusConnection *con, DBusMessage *message, NmOpenVPNData *data)
{
  guint32		ip4_vpn_gateway;
  char *		tundev;
  guint32		ip4_address;
  guint32		ip4_netmask;
  guint32 *		ip4_dns;
  guint32		ip4_dns_len;
  guint32 *		ip4_nbns;
  guint32		ip4_nbns_len;
  gboolean		success = FALSE;
  char *                empty = "";

  g_return_if_fail (data != NULL);
  g_return_if_fail (con != NULL);
  g_return_if_fail (message != NULL);
  
  /* Only accept the config info if we're in STARTING state */
  if (data->state != NM_VPN_STATE_STARTING)
    return;

  nm_openvpn_cancel_helper_timer (data);
  nm_openvpn_disconnect_management_socket (data);

  if (dbus_message_get_args(message, NULL, DBUS_TYPE_UINT32, &ip4_vpn_gateway,
			    DBUS_TYPE_STRING, &tundev,
			    DBUS_TYPE_UINT32, &ip4_address,
			    DBUS_TYPE_UINT32, &ip4_netmask,
			    DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &ip4_dns, &ip4_dns_len,
			    DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &ip4_nbns, &ip4_nbns_len,
			    DBUS_TYPE_INVALID))
    {
      DBusMessage	*signal;

      struct in_addr a;

      
      if (!(signal = dbus_message_new_signal (NM_DBUS_PATH_OPENVPN, NM_DBUS_INTERFACE_OPENVPN, NM_DBUS_VPN_SIGNAL_IP4_CONFIG)))
	{
	  nm_warning ("Not enough memory for new dbus message!");
	  goto out;
	}

      a.s_addr = ip4_vpn_gateway;
      a.s_addr = ip4_address;

      dbus_message_append_args (signal, DBUS_TYPE_UINT32, &ip4_vpn_gateway,
				DBUS_TYPE_STRING, &tundev,
				DBUS_TYPE_UINT32, &ip4_address,
				DBUS_TYPE_UINT32, &ip4_netmask,
				DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &ip4_dns, ip4_dns_len,
				DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &ip4_nbns, ip4_nbns_len,
				DBUS_TYPE_STRING, &empty,
				DBUS_TYPE_STRING, &empty,
				DBUS_TYPE_INVALID);

      if (!dbus_connection_send (data->con, signal, NULL))
	{
	  nm_warning ("Could not raise the "NM_DBUS_VPN_SIGNAL_IP4_CONFIG" signal!");
	  goto out;
	}

      dbus_message_unref (signal);
      nm_openvpn_set_state (data, NM_VPN_STATE_STARTED);
      success = TRUE;
    }

out:
  if (!success)
    {
      nm_warning ("Received invalid IP4 Config information from helper, terminating openvpn.");
      nm_openvpn_dbus_handle_stop_vpn (data);
    }
}


/*
 * nm_openvpn_dbus_message_handler
 *
 * Handle requests for our services.
 *
 */
static DBusHandlerResult
nm_openvpn_dbus_message_handler (DBusConnection *con, DBusMessage *message, void *user_data)
{
  NmOpenVPNData		*data = (NmOpenVPNData *)user_data;
  const char		*method;
  const char		*path;
  DBusMessage		*reply = NULL;
  gboolean			 handled = TRUE;

  g_return_val_if_fail (data != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
  g_return_val_if_fail (con != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
  g_return_val_if_fail (message != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

  method = dbus_message_get_member (message);
  path = dbus_message_get_path (message);

  /* nm_info ("nm_openvpn_dbus_message_handler() got method '%s' for path '%s'.", method, path); */

  /* If we aren't ready to accept dbus messages, don't */
  if ((data->state == NM_VPN_STATE_INIT) || (data->state == NM_VPN_STATE_SHUTDOWN))
    {
      nm_warning ("Received dbus messages but couldn't handle them due to INIT or SHUTDOWN states.");
      reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE_OPENVPN, NM_DBUS_VPN_WRONG_STATE,
					    "Could not process the request due to current state of STATE_INIT or STATE_SHUTDOWN.");
      goto reply;
    }

  if (strcmp ("startConnection", method) == 0)
    reply = nm_openvpn_dbus_start_vpn (con, message, data);
  else if (strcmp ("stopConnection", method) == 0)
    reply = nm_openvpn_dbus_stop_vpn (con, message, data);
  else if (strcmp ("getState", method) == 0)
    reply = nm_openvpn_dbus_get_state (con, message, data);
  else if (strcmp ("signalConfigError", method) == 0)
    nm_openvpn_dbus_process_helper_config_error (con, message, data);
  else if (strcmp ("signalIP4Config", method) == 0)
    nm_openvpn_dbus_process_helper_ip4_config (con, message, data);
  else
    handled = FALSE;
  
 reply:
  if (reply)
    {
      dbus_connection_send (con, reply, NULL);
      dbus_message_unref (reply);
    }

  return (handled ? DBUS_HANDLER_RESULT_HANDLED : DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
}


/*
 * nm_openvpn_dbus_filter
 *
 * Handle signals from the bus, like NetworkManager network state
 * signals.
 *
 */
static DBusHandlerResult
nm_openvpn_dbus_filter (DBusConnection *con, DBusMessage *message, void *user_data)
{
  NmOpenVPNData	*data = (NmOpenVPNData *)user_data;
  gboolean		handled = FALSE;
  DBusError		error;
  
  g_return_val_if_fail (data != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
  g_return_val_if_fail (con != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
  g_return_val_if_fail (message != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
  
  if (dbus_message_is_signal (message, DBUS_INTERFACE_DBUS, "NameOwnerChanged"))
    {
      char 	*service;
      char		*old_owner;
      char		*new_owner;
      
      dbus_error_init (&error);
      if (    dbus_message_get_args (message, &error,
				     DBUS_TYPE_STRING, &service,
				     DBUS_TYPE_STRING, &old_owner,
				     DBUS_TYPE_STRING, &new_owner,
				     DBUS_TYPE_INVALID))
	{
	  gboolean old_owner_good = (old_owner && (strlen (old_owner) > 0));
	  gboolean new_owner_good = (new_owner && (strlen (new_owner) > 0));

	  if ((!old_owner_good && new_owner_good) && (strcmp (service, NM_DBUS_SERVICE) == 0))	/* Equivalent to old ServiceCreated signal */
	    {
	    }
	  else if ((old_owner_good && !new_owner_good) && (strcmp (service, NM_DBUS_SERVICE) == 0))	/* Equivalent to old ServiceDeleted signal */
	    {
	      /* If NM goes away, we don't stick around */
	      nm_openvpn_dbus_handle_stop_vpn (data);
	      g_main_loop_quit (data->loop);
	    }
	}
    }
  else if (dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceNoLongerActive"))
    {
      /* If the active device goes down our VPN is certainly not going to work. */
      nm_openvpn_dbus_handle_stop_vpn (data);
    }

  return (handled ? DBUS_HANDLER_RESULT_HANDLED : DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
}


/*
 * nm_openvpn_dbus_init
 *
 * Grab our connection to the system bus, return NULL if anything goes wrong.
 *
 */
DBusConnection *
nm_openvpn_dbus_init (NmOpenVPNData *data)
{
  DBusConnection			*connection = NULL;
  DBusError				 error;
  DBusObjectPathVTable	 vtable = { NULL, &nm_openvpn_dbus_message_handler, NULL, NULL, NULL, NULL };

  g_return_val_if_fail (data != NULL, NULL);
  
  dbus_error_init (&error);
  if (!(connection = dbus_bus_get (DBUS_BUS_SYSTEM, &error)))
    {
      nm_warning ("Error connecting to system bus: '%s'", error.message);
      goto out;
    }
  
  dbus_connection_setup_with_g_main (connection, NULL);

  dbus_error_init (&error);
  dbus_bus_request_name (connection, NM_DBUS_SERVICE_OPENVPN, 0, &error);
  if (dbus_error_is_set (&error))
    {
      nm_warning ("Could not acquire the dbus service.  dbus_bus_request_name() says: '%s'", error.message);
      goto out;
    }
  
  if (!dbus_connection_register_object_path (connection, NM_DBUS_PATH_OPENVPN, &vtable, data))
    {
      nm_warning ("Could not register a dbus handler for nm-openvpn-service.  Not enough memory?");
      return NULL;
    }
  
  if (!dbus_connection_add_filter (connection, nm_openvpn_dbus_filter, data, NULL))
    return NULL;

  dbus_error_init (&error);
  dbus_bus_add_match (connection,
		      "type='signal',"
		      "interface='" NM_DBUS_INTERFACE "',"
		      "sender='" NM_DBUS_SERVICE "',"
		      "path='" NM_DBUS_PATH "'",
		      &error);
  if (dbus_error_is_set (&error))
    goto out;

  dbus_bus_add_match (connection,
		      "type='signal',"
		      "interface='" DBUS_INTERFACE_DBUS "',"
		      "sender='" DBUS_SERVICE_DBUS "'",
		      &error);
  if (dbus_error_is_set (&error))
    goto out;
  
out:
  if (dbus_error_is_set (&error))
    {
      dbus_error_free (&error);
      connection = NULL;
    }
  return connection;
}

NmOpenVPNData *vpn_data = NULL;

static void
sigterm_handler (int signum)
{
  nm_info ("nm-openvpn-service caught SIGINT/SIGTERM");

  g_main_loop_quit (vpn_data->loop);
}


/*
 * main
 *
 */
int
main( int argc, char *argv[] )
{
  struct sigaction	action;
  sigset_t			block_mask;

  g_type_init ();
  if (!g_thread_supported ())
    g_thread_init (NULL);

  vpn_data = g_malloc0 (sizeof (NmOpenVPNData));

  vpn_data->state = NM_VPN_STATE_INIT;

  vpn_data->loop = g_main_loop_new (NULL, FALSE);

  if (system ("/sbin/modprobe tun") == -1)
    exit (EXIT_FAILURE);

  if (!(vpn_data->con = nm_openvpn_dbus_init (vpn_data)))
    exit (EXIT_FAILURE);

  action.sa_handler = sigterm_handler;
  sigemptyset (&block_mask);
  action.sa_mask = block_mask;
  action.sa_flags = 0;
  sigaction (SIGINT, &action, NULL);
  sigaction (SIGTERM, &action, NULL);

  nm_openvpn_set_state (vpn_data, NM_VPN_STATE_STOPPED);
  g_main_loop_run (vpn_data->loop);

  nm_openvpn_dbus_handle_stop_vpn (vpn_data);

  g_main_loop_unref (vpn_data->loop);
  g_free (vpn_data);

  exit (EXIT_SUCCESS);
}
