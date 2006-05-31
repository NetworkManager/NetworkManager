/* nm-pptp-service - pptp integration with NetworkManager
 *
 * Antony Mee <a.j.mee@ncl.ac.uk>
 * Based on work by Tim Niemueller <tim@niemueller.de>
 *              and Dan Williams <dcbw@redhat.com>
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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <netdb.h>

#include <NetworkManager/NetworkManager.h>
#include <NetworkManager/NetworkManagerVPN.h>

#include "nm-pptp-service.h"
#include "nm-utils.h"


static const char *pptp_binary_paths[] =
{
  "/usr/sbin/pptp",
  "/sbin/pptp",
  NULL
};

static const char *pppd_binary_paths[] =
{
  "/usr/sbin/pppd",
  "/sbin/pppd",
  NULL
};

#define NM_PPTP_HELPER_PATH		"nm-pptp-service-pppd-plugin.so"

typedef struct NmPPTPData
{
  GMainLoop         *loop;
  DBusConnection	*con;
  NMVPNState		state;
  GPid				pid;
  guint		     	quit_timer;
  guint			    helper_timer;
  char              *str_ip4_vpn_gateway;
  struct in_addr    ip4_vpn_gateway;
} NmPPTPData;


static gboolean nm_pptp_dbus_handle_stop_vpn (NmPPTPData *data);


/*
 * nm_dbus_create_error_message
 *
 * Make a DBus error message
 *
 */
static DBusMessage *nm_dbus_create_error_message (DBusMessage *message, const char *exception_namespace,
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
 * nm_pptp_dbus_signal_failure
 *
 * Signal the bus that some VPN operation failed.
 *
 */
static void nm_pptp_dbus_signal_failure (NmPPTPData *data, const char *signal)
{
  DBusMessage	*message;
  const char	*error_msg = NULL;

  g_return_if_fail (data != NULL);
  g_return_if_fail (signal != NULL);

  // No sophisticated error message for now
  error_msg = _("VPN Connection failed");
  if (!error_msg)
    return;

  if (!(message = dbus_message_new_signal (NM_DBUS_PATH_PPTP, NM_DBUS_INTERFACE_PPTP, signal)))
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
 * nm_pptp_dbus_signal_state_change
 *
 * Signal the bus that our state changed.
 *
 */
static void nm_pptp_dbus_signal_state_change (NmPPTPData *data, NMVPNState old_state)
{
  DBusMessage	*message;

  g_return_if_fail (data != NULL);

  if (!(message = dbus_message_new_signal (NM_DBUS_PATH_PPTP, NM_DBUS_INTERFACE_PPTP, NM_DBUS_VPN_SIGNAL_STATE_CHANGE)))
    {
      nm_warning ("nm_pptp_dbus_signal_state_change(): Not enough memory for new dbus message!");
      return;
    }

  dbus_message_append_args (message, DBUS_TYPE_UINT32, &old_state, DBUS_TYPE_UINT32, &(data->state), DBUS_TYPE_INVALID);

  if (!dbus_connection_send (data->con, message, NULL))
    nm_warning ("nm_pptp_dbus_signal_state_change(): Could not raise the signal!");

  dbus_message_unref (message);
}


/*
 * nm_pptp_set_state
 *
 * Set our state and make sure to signal the bus.
 *
 */
static void nm_pptp_set_state (NmPPTPData *data, NMVPNState new_state)
{
  NMVPNState	old_state;

  g_return_if_fail (data != NULL);

  old_state = data->state;

  nm_info("PPTP State change: %d -> %d",old_state,new_state);
  
  if (old_state != new_state)
    {
      data->state = new_state;
      nm_pptp_dbus_signal_state_change (data, old_state);
    }
}


/*
 * nm_pptp_quit_timer_cb
 *
 * Callback to quit nm-pptp-service after a certain period of time.
 *
 */
static gboolean nm_pptp_quit_timer_cb (NmPPTPData *data)
{
  data->quit_timer = 0;

  g_return_val_if_fail (data != NULL, FALSE);

  g_main_loop_quit (data->loop);

  return FALSE;
}


/*
 * nm_pptp_schedule_quit_timer
 *
 * If pptp isn't running, and we haven't been asked to do anything in a while,
 * then we just exit since NetworkManager will re-launch us later.
 *
 */
static void nm_pptp_schedule_quit_timer (NmPPTPData *data, guint interval)
{
  g_return_if_fail (data != NULL);

  if (data->quit_timer == 0)
    data->quit_timer = g_timeout_add (interval, (GSourceFunc) nm_pptp_quit_timer_cb, data);
}


/*
 * nm_pptp_cancel_quit_timer
 *
 * Cancel a quit timer that we've scheduled before.
 *
 */
static void nm_pptp_cancel_quit_timer (NmPPTPData *data)
{
  g_return_if_fail (data != NULL);

  if (data->quit_timer > 0)
    g_source_remove (data->quit_timer);
}


/*
 * nm_pptp_helper_timer_cb
 *
 * If we haven't received the IP4 config info from the helper before the timeout
 * occurs, we kill pptp
 *
 */
static gboolean nm_pptp_helper_timer_cb (NmPPTPData *data)
{
  data->helper_timer = 0;

  g_return_val_if_fail (data != NULL, FALSE);

  nm_pptp_dbus_signal_failure (data, NM_DBUS_VPN_SIGNAL_CONNECT_FAILED);
  nm_pptp_dbus_handle_stop_vpn (data);

  return FALSE;
}


/*
 * nm_pptp_schedule_helper_timer
 *
 * Once pptp is running, we wait for the helper to return the IP4 configuration
 * information to us.  If we don't receive that information within 7 seconds,
 * we kill pptp
 *
 */
static void nm_pptp_schedule_helper_timer (NmPPTPData *data)
{
  g_return_if_fail (data != NULL);

  if (data->helper_timer == 0)
    data->helper_timer = g_timeout_add (10000, (GSourceFunc) nm_pptp_helper_timer_cb, data);
}


/*
 * nm_pptp_cancel_helper_timer
 *
 * Cancel a helper timer that we've scheduled before.
 *
 */
static void nm_pptp_cancel_helper_timer (NmPPTPData *data)
{
  g_return_if_fail (data != NULL);

  if (data->helper_timer > 0)
    g_source_remove (data->helper_timer);
}


/*
 * pptp_watch_cb
 *
 * Watch our child pptp process and get notified of events from it.
 *
 */
static void pptp_watch_cb (GPid pid, gint status, gpointer user_data)
{
  guint	error = -1;

  NmPPTPData *data = (NmPPTPData *)user_data;

  if (WIFEXITED (status))
    {
      error = WEXITSTATUS (status);
      if (error != 0)
	  nm_warning ("pptp exited with error code %d", error);
    }
  else if (WIFSTOPPED (status))
    nm_warning ("pptp stopped unexpectedly with signal %d", WSTOPSIG (status));
  else if (WIFSIGNALED (status))
    nm_warning ("pptp died with signal %d", WTERMSIG (status));
  else
    nm_warning ("pptp died from an unknown cause");
  
  /* Reap child if needed. */
  waitpid (data->pid, NULL, WNOHANG);
  data->pid = 0;

  /* Must be after data->state is set since signals use data->state */
  switch (error)
    {
    case 2:	/* Couldn't log in due to bad user/pass */
      nm_pptp_dbus_signal_failure (data, NM_DBUS_VPN_SIGNAL_LOGIN_FAILED);
      break;

    case 1:	/* Other error (couldn't bind to address, etc) */
      nm_pptp_dbus_signal_failure (data, NM_DBUS_VPN_SIGNAL_CONNECT_FAILED);
      break;

    default:
      break;
    }

  nm_pptp_set_state (data, NM_VPN_STATE_STOPPED);
  nm_pptp_schedule_quit_timer (data, 10000);
}


/*
 * nm_pptp_start_vpn_binary
 *
 * Start the pptp binary with a set of arguments and a config file.
 *
 */
static gint nm_pptp_start_pptp_binary (NmPPTPData *data, char **data_items, const int num_items)
{
  GPid			pid;
  const char **		pptp_binary = NULL;
  const char **		pppd_binary = NULL;
  struct hostent    *hostinfo = NULL;
  GPtrArray *	pptp_argv;
  GError *		error = NULL;
  GSource *		pptp_watch;
  gint			stdin_fd = -1;
  int                   i = 0;
  char *        pppd_pty = NULL;

  g_return_val_if_fail (data != NULL, -1);

  data->pid = 0;

  if ( (num_items == 0) || (data_items == NULL) ) {
    return -1;
  }

  /* Find pptp */
  pptp_binary = pptp_binary_paths;
  while (*pptp_binary != NULL) {
    if (g_file_test (*pptp_binary, G_FILE_TEST_EXISTS))
      break;
    pptp_binary++;
  }

  if (!*pptp_binary) {
    nm_info ("Could not find pptp binary.");
    return -1;
  }

  /* Find pppd */
  pppd_binary = pppd_binary_paths;
  while (*pppd_binary != NULL) {
    if (g_file_test (*pppd_binary, G_FILE_TEST_EXISTS))
      break;
    pppd_binary++;
  }

  if (!*pppd_binary) {
    nm_info ("Could not find pppd binary.");
    return -1;
  }

  pptp_argv = g_ptr_array_new ();
  g_ptr_array_add (pptp_argv, (gpointer) (*pppd_binary));

  // First pptp parameter is the PPTP server 
  for (i = 0; i < num_items; ++i) {
    if ( strcmp( data_items[i], "remote" ) == 0) {
      hostinfo = gethostbyname(data_items[++i]);
      if (!hostinfo) {
        nm_info ("Could not resolve VPN servers IP.");
        return -1;
      }
      data -> ip4_vpn_gateway = *(struct in_addr*)(hostinfo->h_addr_list[0]);
      data -> str_ip4_vpn_gateway = g_strdup( inet_ntoa( data -> ip4_vpn_gateway ) );
//      nm_info ("Lookup VPN server IP = '%s'",data->str_ip4_vpn_gateway);

      pppd_pty = g_strdup_printf ("%s %s --nolaunchpppd", (*pptp_binary), data->str_ip4_vpn_gateway);
//      nm_info ("Starting pppd with pty %s",pppd_pty);
      
      g_ptr_array_add (pptp_argv, (gpointer) "pty");
      g_ptr_array_add (pptp_argv, (gpointer) pppd_pty);
      
    }
  }

  g_ptr_array_add (pptp_argv, (gpointer) "nodetach");
  g_ptr_array_add (pptp_argv, (gpointer) "lock");
  g_ptr_array_add (pptp_argv, (gpointer) "noauth");
  g_ptr_array_add (pptp_argv, (gpointer) "nobsdcomp");
  g_ptr_array_add (pptp_argv, (gpointer) "nodeflate");
//  g_ptr_array_add (pptp_argv, (gpointer) "ipparam");
//  g_ptr_array_add (pptp_argv, (gpointer) "nm-pptp-service");
  g_ptr_array_add (pptp_argv, (gpointer) "mtu");
  g_ptr_array_add (pptp_argv, (gpointer) "1000");
  g_ptr_array_add (pptp_argv, (gpointer) "mru");
  g_ptr_array_add (pptp_argv, (gpointer) "1000");
  g_ptr_array_add (pptp_argv, (gpointer) "lcp-echo-failure");
  g_ptr_array_add (pptp_argv, (gpointer) "10");
  g_ptr_array_add (pptp_argv, (gpointer) "lcp-echo-interval");
  g_ptr_array_add (pptp_argv, (gpointer) "10");
  // Set the username...
  for (i = 0; i < num_items; ++i) {
    if ( strcmp( data_items[i], "username" ) == 0) {
      g_ptr_array_add (pptp_argv, (gpointer) "user");
      g_ptr_array_add (pptp_argv, (gpointer) data_items[++i]);
    } else if ( strcmp( data_items[i], "remote" ) == 0) {
      g_ptr_array_add (pptp_argv, (gpointer) "remotename");
      g_ptr_array_add (pptp_argv, (gpointer) data_items[++i]);
    } else if ( (strcmp( data_items[i], "encrypt-mppe" ) == 0) &&
		(strcmp( data_items[++i], "yes" ) == 0) ) {
      g_ptr_array_add (pptp_argv, (gpointer) "require-mppe");
    } else if ( (strcmp( data_items[i], "comp-mppc" ) == 0) &&
		(strcmp( data_items[++i], "yes" ) == 0) ) {
      g_ptr_array_add (pptp_argv, (gpointer) "require-mppc");
    }
  }

  g_ptr_array_add (pptp_argv, (gpointer) "usepeerdns");

  g_ptr_array_add (pptp_argv, (gpointer) "plugin");
  g_ptr_array_add (pptp_argv, (gpointer) NM_PPTP_HELPER_PATH);
  
  g_ptr_array_add (pptp_argv, NULL);

  if (!g_spawn_async_with_pipes (NULL, (char **) pptp_argv->pdata, NULL,
				 G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL, &pid, &stdin_fd,
				 NULL, NULL, &error))
    {
      g_ptr_array_free (pptp_argv, TRUE);
      g_free(pppd_pty);
      nm_warning ("pptp failed to start.  error: '%s'", error->message);
      g_error_free(error);
      return -1;
    }
  g_ptr_array_free (pptp_argv, TRUE);
  g_free(pppd_pty);

  nm_info ("pptp started with pid %d", pid);

  data->pid = pid;
  pptp_watch = g_child_watch_source_new (pid);
  g_source_set_callback (pptp_watch, (GSourceFunc) pptp_watch_cb, data, NULL);
  g_source_attach (pptp_watch, NULL);
  g_source_unref (pptp_watch);

  nm_pptp_schedule_helper_timer (data);

  return stdin_fd;
}


typedef enum OptType
{
	OPT_TYPE_UNKNOWN = 0,
	OPT_TYPE_ADDRESS,
	OPT_TYPE_ASCII,
	OPT_TYPE_NONE
} OptType;

typedef struct Option
{
	const char *name;
	OptType type;
} Option;

/*
 * nm_pptp_config_options_validate
 *
 * Make sure the config options are sane
 *
 */
static gboolean nm_pptp_config_options_validate (char **data_items, int num_items)
{
  Option	allowed_opts[] = {
    { "remote",			OPT_TYPE_ADDRESS },
    { "username",			OPT_TYPE_ASCII },
    { "comp-mppc",			OPT_TYPE_ASCII },
    { "encrypt-mppe",			OPT_TYPE_ASCII },
    { NULL,					OPT_TYPE_UNKNOWN } };
  
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

	default:
	  return FALSE;
	  break;
	}
    }

  return TRUE;
}

/*
 * nm_pptp_dbus_handle_start_vpn
 *
 * Parse message arguments and start the VPN connection.
 *
 */
static gboolean nm_pptp_dbus_handle_start_vpn (DBusMessage *message, NmPPTPData *data)
{
  char **		data_items = NULL;
  int		num_items = -1;
  char **		password_items = NULL;
  int		num_passwords = -1;
  char **		user_routes = NULL;
  int		user_routes_count = -1;
  const char *	name = NULL;
  const char *	user_name = NULL;
  DBusError		error;
  gboolean		success = FALSE;
  gint			pptp_fd = -1;	

  g_return_val_if_fail (message != NULL, FALSE);
  g_return_val_if_fail (data != NULL, FALSE);

  nm_pptp_set_state (data, NM_VPN_STATE_STARTING);

  dbus_error_init (&error);
  if (!dbus_message_get_args (message, &error,
			      DBUS_TYPE_STRING, &name,
			      DBUS_TYPE_STRING, &user_name,
			      DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &password_items, &num_passwords,
			      DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &data_items, &num_items,
			      DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &user_routes, &user_routes_count,
			      DBUS_TYPE_INVALID))
    {
      nm_warning ("Could not process the request because its arguments were invalid.  dbus said: '%s'", error.message);
      nm_pptp_dbus_signal_failure (data, NM_DBUS_VPN_SIGNAL_VPN_CONFIG_BAD);
      dbus_error_free (&error);
      goto out;
    }

  if (!nm_pptp_config_options_validate (data_items, num_items))
    {
      nm_pptp_dbus_signal_failure (data, NM_DBUS_VPN_SIGNAL_VPN_CONFIG_BAD);
      goto out;
    }

  /* Now we can finally try to activate the VPN */
  if ((pptp_fd = nm_pptp_start_pptp_binary (data, data_items, num_items)) >= 0)
    {
      success = TRUE;
    }

out:
  dbus_free_string_array (data_items);
  dbus_free_string_array (password_items);
  dbus_free_string_array (user_routes);
  if (!success)
    nm_pptp_set_state (data, NM_VPN_STATE_STOPPED);
  return success;
}


/*
 * nm_pptp_dbus_handle_stop_vpn
 *
 * Stop the running pppd dameon.
 *
 */
static gboolean nm_pptp_dbus_handle_stop_vpn (NmPPTPData *data)
{
  g_return_val_if_fail (data != NULL, FALSE);

  if (data->pid > 0)
    {
      nm_pptp_set_state (data, NM_VPN_STATE_STOPPING);

      kill (data->pid, SIGTERM);
      nm_info ("Terminated pppd with PID %d.", data->pid);
      data->pid = 0;

      nm_pptp_set_state (data, NM_VPN_STATE_STOPPED);
      nm_pptp_schedule_quit_timer (data, 10000);
    }

  return TRUE;
}


/*
 * nm_pptp_dbus_start_vpn
 *
 * Begin a VPN connection.
 *
 */
static DBusMessage *nm_pptp_dbus_start_vpn (DBusConnection *con, DBusMessage *message, NmPPTPData *data)
{
  DBusMessage		*reply = NULL;

  g_return_val_if_fail (data != NULL, NULL);
  g_return_val_if_fail (con != NULL, NULL);
  g_return_val_if_fail (message != NULL, NULL);

  switch (data->state)
    {
    case NM_VPN_STATE_STARTING:
      reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE_PPTP, NM_DBUS_VPN_STARTING_IN_PROGRESS,
					    "Could not process the request because the VPN connection is already being started.");
      break;

    case NM_VPN_STATE_STARTED:
      reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE_PPTP, NM_DBUS_VPN_ALREADY_STARTED,
					    "Could not process the request because a VPN connection was already active.");
      break;

    case NM_VPN_STATE_STOPPING:
      reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE_PPTP, NM_DBUS_VPN_STOPPING_IN_PROGRESS,
					    "Could not process the request because the VPN connection is being stopped.");
      break;

    case NM_VPN_STATE_STOPPED:
      nm_pptp_cancel_quit_timer (data);
      nm_pptp_dbus_handle_start_vpn (message, data);
      reply = dbus_message_new_method_return (message);
      break;

    default:
      g_assert_not_reached();
      break;
    }

  return reply;
}


/*
 * nm_pptp_dbus_stop_vpn
 *
 * Terminate a VPN connection.
 *
 */
static DBusMessage *nm_pptp_dbus_stop_vpn (DBusConnection *con, DBusMessage *message, NmPPTPData *data)
{
  DBusMessage		*reply = NULL;

  g_return_val_if_fail (data != NULL, NULL);
  g_return_val_if_fail (con != NULL, NULL);
  g_return_val_if_fail (message != NULL, NULL);
  
  switch (data->state)
    {
    case NM_VPN_STATE_STOPPING:
      reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE_PPTP, NM_DBUS_VPN_STOPPING_IN_PROGRESS,
					    "Could not process the request because the VPN connection is already being stopped.");
      break;

    case NM_VPN_STATE_STOPPED:
      reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE_PPTP, NM_DBUS_VPN_ALREADY_STOPPED,
					    "Could not process the request because no VPN connection was active.");
      break;

    case NM_VPN_STATE_STARTING:
    case NM_VPN_STATE_STARTED:
      nm_pptp_dbus_handle_stop_vpn (data);
      reply = dbus_message_new_method_return (message);
      break;

    default:
      g_assert_not_reached();
      break;
    }

  return reply;
}


/*
 * nm_pptp_dbus_get_state
 *
 * Return some state information to NetworkManager.
 *
 */
static DBusMessage *nm_pptp_dbus_get_state (DBusConnection *con, DBusMessage *message, NmPPTPData *data)
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
 * nm_pptp_dbus_process_helper_config_error
 *
 * Signal the bus that the helper could not get all the configuration information
 * it needed.
 *
 */
static void nm_pptp_dbus_process_helper_config_error (DBusConnection *con, DBusMessage *message, NmPPTPData *data)
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
      nm_warning ("pptp helper did not receive adequate configuration information from pppd.  It is missing '%s'.", error_item);
      nm_pptp_dbus_signal_failure (data, NM_DBUS_VPN_SIGNAL_IP_CONFIG_BAD);
    }

  nm_pptp_cancel_helper_timer (data);
  nm_pptp_dbus_handle_stop_vpn (data);
}


/*
 * nm_pptp_dbus_process_helper_ip4_config
 *
 * Signal the bus 
 *
 */
static void nm_pptp_dbus_process_helper_ip4_config (DBusConnection *con, DBusMessage *message, NmPPTPData *data)
{
  guint32		    ip4_vpn_gateway;
  char *		    tundev;
  guint32		    ip4_address;
  guint32		    ip4_ptp_address;
  guint32		    ip4_netmask;
  guint32 *		    ip4_dns = NULL;
  guint32		    ip4_dns_len;
  guint32 		    ip4_dns1;
  guint32 		    ip4_dns2;
  guint32 *		    ip4_nbns = NULL;
  guint32		    ip4_nbns_len;
  guint32 		    ip4_nbns1;
  guint32 		    ip4_nbns2;
  guint32			mss;
  gboolean		    success = FALSE;
  char *            empty = "";

  g_return_if_fail (data != NULL);
  g_return_if_fail (con != NULL);
  g_return_if_fail (message != NULL);
  
  /* Only accept the config info if we're in STARTING state */
  if (data->state != NM_VPN_STATE_STARTING)
    return;

  nm_pptp_cancel_helper_timer (data);

  if (dbus_message_get_args(message, NULL, 
			    DBUS_TYPE_STRING, &tundev,
			    DBUS_TYPE_UINT32, &ip4_address,
			    DBUS_TYPE_UINT32, &ip4_ptp_address,
			    DBUS_TYPE_UINT32, &ip4_netmask,
			    DBUS_TYPE_UINT32, &ip4_dns1,
			    DBUS_TYPE_UINT32, &ip4_dns2,
			    DBUS_TYPE_UINT32, &ip4_dns_len,
			    DBUS_TYPE_UINT32, &ip4_nbns1,
			    DBUS_TYPE_UINT32, &ip4_nbns2,
			    DBUS_TYPE_UINT32, &ip4_nbns_len,
//			    DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &ip4_dns, &ip4_dns_len,
//			    DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &ip4_nbns, &ip4_nbns_len,
			    DBUS_TYPE_INVALID))
    {
      DBusMessage	*signal;

      if (ip4_dns_len) {
        ip4_dns = g_new0(guint32, ip4_dns_len);
        ip4_dns[0]=ip4_dns1;
        if (ip4_dns_len==2) ip4_dns[1]=ip4_dns2;
      }

      if (ip4_nbns_len) {
        ip4_nbns = g_new0(guint32, ip4_nbns_len);
        ip4_nbns[0]=ip4_nbns1;
        if (ip4_nbns_len==2) ip4_nbns[1]=ip4_nbns2;
      }

      if (!(signal = dbus_message_new_signal (NM_DBUS_PATH_PPTP, NM_DBUS_INTERFACE_PPTP, NM_DBUS_VPN_SIGNAL_IP4_CONFIG)))
	{
	  nm_warning ("Not enough memory for new dbus message!");
	  goto out;
	}

	/* PPTP does not care about the MSS */
	mss = 0;

      ip4_vpn_gateway=data->ip4_vpn_gateway.s_addr;
      dbus_message_append_args (signal, 
                DBUS_TYPE_UINT32, &ip4_vpn_gateway,
				DBUS_TYPE_STRING, &tundev,
				DBUS_TYPE_UINT32, &ip4_address,
				DBUS_TYPE_UINT32, &ip4_ptp_address,
				DBUS_TYPE_UINT32, &ip4_netmask,
				DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &ip4_dns, ip4_dns_len,
				DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &ip4_nbns, ip4_nbns_len,
				DBUS_TYPE_UINT32, &mss,
				DBUS_TYPE_STRING, &empty,
				DBUS_TYPE_STRING, &empty,
				DBUS_TYPE_INVALID);

      if (!dbus_connection_send (data->con, signal, NULL))
      {
	    nm_warning ("Could not raise the "NM_DBUS_VPN_SIGNAL_IP4_CONFIG" signal!");
	    goto out;
      }

      dbus_message_unref (signal);
      nm_pptp_set_state (data, NM_VPN_STATE_STARTED);
      success = TRUE;
    }

out:
    if (ip4_nbns!=NULL) g_free(ip4_nbns);  
    if (ip4_dns!=NULL)  g_free(ip4_dns);  
  
    if (!success)
    {
      nm_warning ("Received invalid IP4 Config information from helper, terminating pptp.");
      nm_pptp_dbus_handle_stop_vpn (data);
    }
}


/*
 * nm_pptp_dbus_message_handler
 *
 * Handle requests for our services.
 *
 */
static DBusHandlerResult nm_pptp_dbus_message_handler (DBusConnection *con, DBusMessage *message, void *user_data)
{
  NmPPTPData		*data = (NmPPTPData *)user_data;
  const char		*method;
  const char		*path;
  DBusMessage		*reply = NULL;
  gboolean			 handled = TRUE;

  g_return_val_if_fail (data != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
  g_return_val_if_fail (con != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
  g_return_val_if_fail (message != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

  method = dbus_message_get_member (message);
  path = dbus_message_get_path (message);

  /* nm_info ("nm_pptp_dbus_message_handler() got method '%s' for path '%s'.", method, path); */

  /* If we aren't ready to accept dbus messages, don't */
  if ((data->state == NM_VPN_STATE_INIT) || (data->state == NM_VPN_STATE_SHUTDOWN))
    {
      nm_warning ("Received dbus messages but couldn't handle them due to INIT or SHUTDOWN states.");
      reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE_PPTP, NM_DBUS_VPN_WRONG_STATE,
					    "Could not process the request due to current state of STATE_INIT or STATE_SHUTDOWN.");
      goto reply;
    }

  if (strcmp ("startConnection", method) == 0)
    reply = nm_pptp_dbus_start_vpn (con, message, data);
  else if (strcmp ("stopConnection", method) == 0)
    reply = nm_pptp_dbus_stop_vpn (con, message, data);
  else if (strcmp ("getState", method) == 0)
    reply = nm_pptp_dbus_get_state (con, message, data);
  else if (strcmp ("signalConfigError", method) == 0)
    nm_pptp_dbus_process_helper_config_error (con, message, data);
  else if (strcmp ("signalIP4Config", method) == 0)
    nm_pptp_dbus_process_helper_ip4_config (con, message, data);
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
 * nm_pptp_dbus_filter
 *
 * Handle signals from the bus, like NetworkManager network state
 * signals.
 *
 */
static DBusHandlerResult nm_pptp_dbus_filter (DBusConnection *con, DBusMessage *message, void *user_data)
{
  NmPPTPData	*data = (NmPPTPData *)user_data;
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
	      nm_pptp_dbus_handle_stop_vpn (data);
	      g_main_loop_quit (data->loop);
	    }
	}
    }
  else if (dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceNoLongerActive"))
    {
      /* If the active device goes down our VPN is certainly not going to work. */
      nm_pptp_dbus_handle_stop_vpn (data);
    }

  return (handled ? DBUS_HANDLER_RESULT_HANDLED : DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
}


/*
 * nm_pptp_dbus_init
 *
 * Grab our connection to the system bus, return NULL if anything goes wrong.
 *
 */
DBusConnection *nm_pptp_dbus_init (NmPPTPData *data)
{
  DBusConnection			*connection = NULL;
  DBusError				 error;
  DBusObjectPathVTable	 vtable = { NULL, &nm_pptp_dbus_message_handler, NULL, NULL, NULL, NULL };

  g_return_val_if_fail (data != NULL, NULL);
  
  dbus_error_init (&error);
  if (!(connection = dbus_bus_get (DBUS_BUS_SYSTEM, &error)))
    {
      nm_warning ("Error connecting to system bus: '%s'", error.message);
      goto out;
    }
  
  dbus_connection_setup_with_g_main (connection, NULL);

  dbus_error_init (&error);
  dbus_bus_request_name (connection, NM_DBUS_SERVICE_PPTP, 0, &error);
  if (dbus_error_is_set (&error))
    {
      nm_warning ("Could not acquire the dbus service.  dbus_bus_request_name() says: '%s'", error.message);
      goto out;
    }
  
  if (!dbus_connection_register_object_path (connection, NM_DBUS_PATH_PPTP, &vtable, data))
    {
      nm_warning ("Could not register a dbus handler for nm-pptp-service.  Not enough memory?");
      return NULL;
    }
  
  if (!dbus_connection_add_filter (connection, nm_pptp_dbus_filter, data, NULL))
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

NmPPTPData *vpn_data = NULL;

static void sigterm_handler (int signum)
{
  nm_info ("nm-pptp-service caught SIGINT/SIGTERM");

//  g_main_loop_quit (vpn_data->loop);
}


/*
 * main
 *
 */
int main( int argc, char *argv[] )
{
  struct sigaction	action;
  sigset_t			block_mask;

  g_type_init ();
  if (!g_thread_supported ())
    g_thread_init (NULL);

  vpn_data = g_malloc0 (sizeof (NmPPTPData));

  vpn_data->state = NM_VPN_STATE_INIT;

  vpn_data->loop = g_main_loop_new (NULL, FALSE);

  if (!(vpn_data->con = nm_pptp_dbus_init (vpn_data)))
    exit (1);

  action.sa_handler = sigterm_handler;
  sigemptyset (&block_mask);
  action.sa_mask = block_mask;
  action.sa_flags = 0;
  sigaction (SIGINT, &action, NULL);
  sigaction (SIGTERM, &action, NULL);

  nm_pptp_set_state (vpn_data, NM_VPN_STATE_STOPPED);
  g_main_loop_run (vpn_data->loop);

  nm_pptp_dbus_handle_stop_vpn (vpn_data);

  g_main_loop_unref (vpn_data->loop);

  if (vpn_data->str_ip4_vpn_gateway != NULL) g_free( vpn_data->str_ip4_vpn_gateway );
  g_free (vpn_data);

  exit (0);
}
