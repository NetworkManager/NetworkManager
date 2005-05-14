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

#include "NetworkManager.h"
#include "nm-vpnc-service.h"
#include "nm-utils.h"


static char *vpnc_binary_paths[] =
{
	"/usr/sbin/vpnc",
	"/sbin/vpnc",
	NULL
};

#define NM_VPNC_HELPER_PATH		BINDIR"/nm-vpnc-service-vpnc-helper"
#define NM_VPNC_PID_FILE_PATH		LOCALSTATEDIR"/run/vpnc/pid"
#define NM_VPNC_CONFIG_FILE_PATH	LOCALSTATEDIR"/run/vpnc/nm-vpnc-service-vpnc.conf"

typedef struct NmVpncData
{
	GMainLoop *		loop;
	DBusConnection	*	con;
	NMVPNState		state;
	GPid				pid;
	guint			quit_timer;
	guint			helper_timer;
} NmVpncData;


static gboolean nm_vpnc_dbus_handle_stop_vpn (NmVpncData *data);


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
	DBusMessage	*reply_message;
	va_list		 args;
	char			 error_text[512];

	va_start (args, format);
	vsnprintf (error_text, 512, format, args);
	va_end (args);

	exception_text = g_strdup_printf ("%s.%s", exception_namespace, exception);
	reply_message = dbus_message_new_error (message, exception_text, error_text);
	g_free (exception_text);

	return (reply_message);
}


/*
 * nm_vpnc_dbus_signal_login_failed
 *
 * Signal the bus that VPN login failed.
 *
 */
static void nm_vpnc_dbus_signal_login_failed (NmVpncData *data)
{
	DBusMessage	*message;
	const char	*error_msg = "The VPN login failed because the user name and password were not accepted.";

	g_return_if_fail (data != NULL);

	if (!(message = dbus_message_new_signal (NM_DBUS_PATH_VPNC, NM_DBUS_INTERFACE_VPNC, NM_DBUS_VPN_SIGNAL_LOGIN_FAILED)))
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
 * nm_vpnc_dbus_signal_launch_failed
 *
 * Signal the bus that we couldn't launch the VPN daemon.
 *
 */
static void nm_vpnc_dbus_signal_launch_failed (NmVpncData *data)
{
	DBusMessage	*message;
	const char	*error_msg = "The VPN login failed because the VPN program could not be started.";

	g_return_if_fail (data != NULL);

	if (!(message = dbus_message_new_signal (NM_DBUS_PATH_VPNC, NM_DBUS_INTERFACE_VPNC, NM_DBUS_VPN_SIGNAL_LAUNCH_FAILED)))
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
 * nm_vpnc_dbus_signal_connect_failed
 *
 * Signal the bus that VPN daemon failed to connect to the VPN concentrator.
 *
 */
static void nm_vpnc_dbus_signal_connect_failed (NmVpncData *data)
{
	DBusMessage	*message;
	const char	*error_msg = "The VPN login failed because the VPN program could not connect to the VPN server.";

	g_return_if_fail (data != NULL);

	if (!(message = dbus_message_new_signal (NM_DBUS_PATH_VPNC, NM_DBUS_INTERFACE_VPNC, NM_DBUS_VPN_SIGNAL_CONNECT_FAILED)))
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
 * nm_vpnc_dbus_signal_state_change
 *
 * Signal the bus that our state changed.
 *
 */
static void nm_vpnc_dbus_signal_state_change (NmVpncData *data, NMVPNState old_state)
{
	DBusMessage	*message;

	g_return_if_fail (data != NULL);

	if (!(message = dbus_message_new_signal (NM_DBUS_PATH_VPNC, NM_DBUS_INTERFACE_VPNC, NM_DBUS_VPN_SIGNAL_STATE_CHANGE)))
	{
		nm_warning ("nm_vpnc_dbus_signal_state_change(): Not enough memory for new dbus message!");
		return;
	}

	dbus_message_append_args (message, DBUS_TYPE_UINT32, &old_state, DBUS_TYPE_UINT32, &(data->state), DBUS_TYPE_INVALID);

	if (!dbus_connection_send (data->con, message, NULL))
		nm_warning ("nm_vpnc_dbus_signal_state_change(): Could not raise the signal!");

	dbus_message_unref (message);
}


/*
 * nm_vpnc_set_state
 *
 * Set our state and make sure to signal the bus.
 *
 */
static void nm_vpnc_set_state (NmVpncData *data, NMVPNState new_state)
{
	NMVPNState	old_state;

	g_return_if_fail (data != NULL);

	old_state = data->state;
	data->state = new_state;
	nm_vpnc_dbus_signal_state_change (data, old_state);
}


/*
 * nm_vpnc_quit_timer_cb
 *
 * Callback to quit nm-vpnc-service after a certain period of time.
 *
 */
static gboolean nm_vpnc_quit_timer_cb (NmVpncData *data)
{
	data->quit_timer = 0;

	g_return_val_if_fail (data != NULL, FALSE);

	g_main_loop_quit (data->loop);

	return FALSE;
}


/*
 * nm_vpnc_schedule_quit_timer
 *
 * If vpnc isn't running, and we haven't been asked to do anything in a while,
 * then we just exit since NetworkManager will re-launch us later.
 *
 */
static void nm_vpnc_schedule_quit_timer (NmVpncData *data, guint interval)
{
	g_return_if_fail (data != NULL);

	if (data->quit_timer == 0)
		data->quit_timer = g_timeout_add (interval, (GSourceFunc) nm_vpnc_quit_timer_cb, data);
}


/*
 * nm_vpnc_cancel_quit_timer
 *
 * Cancel a quit timer that we've scheduled before.
 *
 */
static void nm_vpnc_cancel_quit_timer (NmVpncData *data)
{
	g_return_if_fail (data != NULL);

	if (data->quit_timer > 0)
		g_source_remove (data->quit_timer);
}


/*
 * nm_vpnc_helper_timer_cb
 *
 * If we haven't received the IP4 config info from the helper before the timeout
 * occurs, we kill vpnc.
 *
 */
static gboolean nm_vpnc_helper_timer_cb (NmVpncData *data)
{
	data->helper_timer = 0;

	g_return_val_if_fail (data != NULL, FALSE);

	nm_vpnc_dbus_signal_connect_failed (data);
	nm_vpnc_dbus_handle_stop_vpn (data);

	return FALSE;
}


/*
 * nm_vpnc_schedule_helper_timer
 *
 * Once vpnc is running, we wait for the helper to return the IP4 configuration
 * information to us.  If we don't receive that information within 7 seconds,
 * we kill vpnc.
 *
 */
static void nm_vpnc_schedule_helper_timer (NmVpncData *data)
{
	g_return_if_fail (data != NULL);

	if (data->helper_timer == 0)
		data->helper_timer = g_timeout_add (7000, (GSourceFunc) nm_vpnc_helper_timer_cb, data);
}


/*
 * nm_vpnc_cancel_helper_timer
 *
 * Cancel a helper timer that we've scheduled before.
 *
 */
static void nm_vpnc_cancel_helper_timer (NmVpncData *data)
{
	g_return_if_fail (data != NULL);

	if (data->helper_timer > 0)
		g_source_remove (data->helper_timer);
}


/*
 * vpnc_watch_cb
 *
 * Watch our child vpnc process and get notified of events from it.
 *
 */
static void vpnc_watch_cb (GPid pid, gint status, gpointer user_data)
{
	guint	error = -1;

	NmVpncData *data = (NmVpncData *)user_data;

	if (WIFEXITED (status))
	{
		error = WEXITSTATUS (status);
		nm_warning ("vpnc exited with error code %d", error);
	}
	else if (WIFSTOPPED (status))
		nm_warning ("vpnc stopped unexpectedly with signal %d", WSTOPSIG (status));
	else if (WIFSIGNALED (status))
		nm_warning ("vpnc died with signal %d", WTERMSIG (status));
	else
		nm_warning ("vpnc died from an unknown cause");

	/* Reap child if needed. */
	waitpid (data->pid, NULL, WNOHANG);
	data->pid = 0;

	/* Must be after data->state is set since signals use data->state */
	switch (error)
	{
		case 2:	/* Couldn't log in due to bad user/pass */
			nm_vpnc_dbus_signal_login_failed (data);
			break;

		case 1:	/* Other error (couldn't bind to address, etc) */
			nm_vpnc_dbus_signal_connect_failed (data);
			break;

		case 0:	/* Success, vpnc has daemonized */
			{
				GPid	daemon_pid;
				char *contents;

				/* Grab the vpnc daemon's PID from its pidfile */
				if (g_file_get_contents (NM_VPNC_PID_FILE_PATH, &contents, NULL, NULL))
				{
					data->pid = atoi (g_strstrip (contents));
					nm_info ("vpnc daemon's PID is %d\n", data->pid);
					g_free (contents);
				}
			}
			break;

		default:
			break;
	}

	unlink (NM_VPNC_CONFIG_FILE_PATH);

	/* If vpnc did not daemonize (due to errors), we quit after a bit */
	if (data->pid <= 0)
	{
		nm_vpnc_set_state (data, NM_VPN_STATE_STOPPED);
		unlink (NM_VPNC_PID_FILE_PATH);

		nm_vpnc_schedule_quit_timer (data, 10000);
	}

	/* State change from STARTING->STARTED happens when we get successful
	 * ip4 config info from the helper.
	 */
}


/*
 * nm_vpnc_start_vpn_binary
 *
 * Start the vpnc binary with a set of arguments and a config file.
 *
 */
static gboolean nm_vpnc_start_vpnc_binary (NmVpncData *data)
{
	GPid			pid;
	char **		vpnc_binary = NULL;
	GPtrArray *	vpnc_argv;
	GError *		error = NULL;
	gboolean		success = FALSE;
	GSource *		vpnc_watch;

	g_return_val_if_fail (data != NULL, FALSE);

	data->pid = 0;

	unlink (NM_VPNC_PID_FILE_PATH);

	/* Find vpnc */
	vpnc_binary = vpnc_binary_paths;
	while (*vpnc_binary != NULL)
	{
		if (g_file_test (*vpnc_binary, G_FILE_TEST_EXISTS))
			break;
		vpnc_binary++;
	}

	if (!*vpnc_binary)
	{
		nm_info ("Could not find vpnc binary.");
		return FALSE;
	}

	vpnc_argv = g_ptr_array_new ();
	g_ptr_array_add (vpnc_argv, (char *) (*vpnc_binary));
	g_ptr_array_add (vpnc_argv, "--script");
	g_ptr_array_add (vpnc_argv, NM_VPNC_HELPER_PATH);
	g_ptr_array_add (vpnc_argv, "--pid-file");
	g_ptr_array_add (vpnc_argv, NM_VPNC_PID_FILE_PATH);
	g_ptr_array_add (vpnc_argv, NM_VPNC_CONFIG_FILE_PATH);
	g_ptr_array_add (vpnc_argv, NULL);

	if (!g_spawn_async (NULL, (char **) vpnc_argv->pdata, NULL,
				G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL, &pid, &error))
	{
		g_ptr_array_free (vpnc_argv, TRUE);
		nm_warning ("vpnc failed to start.  error: '%s'", error->message);
		g_error_free(error);
		return FALSE;
	}
	g_ptr_array_free (vpnc_argv, TRUE);

	nm_info ("vpnc started with pid %d", pid);

	data->pid = pid;
	vpnc_watch = g_child_watch_source_new (pid);
	g_source_set_callback (vpnc_watch, (GSourceFunc) vpnc_watch_cb, data, NULL);
	g_source_attach (vpnc_watch, NULL);
	g_source_unref (vpnc_watch);

	nm_vpnc_schedule_helper_timer (data);

	return TRUE;
}


/*
 * nm_vpnc_config_file_generate
 *
 * Generate a vpnc config file.
 *
 */
static gboolean nm_vpnc_config_file_generate (const char *user_name, const char *password, const char **data_items, const int num_items)
{
	char *	string;
	int		out_fd;
	int		i, x;
	char *	dirname;
	char *	cmd;
	int		ret;

	g_return_val_if_fail (user_name != NULL, FALSE);
	g_return_val_if_fail (password != NULL, FALSE);
	g_return_val_if_fail (data_items != NULL, FALSE);

	/* Ensure that the config file's directory exists */
	dirname = g_path_get_dirname (NM_VPNC_CONFIG_FILE_PATH);
	if (!dirname || !strlen (dirname))
	{
		nm_warning ("Could not get dirname for vpnc config file path '%s'.", NM_VPNC_CONFIG_FILE_PATH);
		return FALSE;
	}

	cmd = g_strdup_printf ("/bin/mkdir -p -m 700 %s", dirname);
	ret = system (cmd);
	if ((ret == -1) || (WEXITSTATUS(ret) != 0))
	{
		nm_warning ("Could not create dirname for vpnc config file path '%s'.", NM_VPNC_CONFIG_FILE_PATH);
		g_free (cmd);
		g_free (dirname);
		return FALSE;
	}
	g_free (cmd);

	unlink (NM_VPNC_CONFIG_FILE_PATH);
	out_fd = open (NM_VPNC_CONFIG_FILE_PATH, O_WRONLY|O_CREAT|O_TRUNC, 0600);
	if (out_fd < 0)
	{
		nm_warning ("Could not create vpnc config file '%s'.", NM_VPNC_CONFIG_FILE_PATH);
		return FALSE;
	}

	string = g_strdup_printf ("Xauth username %s\n", user_name);
	x = write (out_fd, string, strlen (string));
	g_free (string);
	
	string = g_strdup_printf ("Xauth password %s\n", password);
	x = write (out_fd, string, strlen (string));
	g_free (string);

	for (i = 0; i < num_items; i++)
	{
		char *temp = g_strdup_printf ("%s\n", data_items[i]);
		x = write (out_fd, temp, strlen (temp));
		g_free (temp);
		string++;
	}

	close (out_fd);

	return TRUE;
}


/*
 * nm_vpnc_dbus_handle_start_vpn
 *
 * Parse message arguments and start the VPN connection.
 *
 */
static gboolean nm_vpnc_dbus_handle_start_vpn (DBusMessage *message, DBusMessage **reply, NmVpncData *data)
{
	const char		**data_items = NULL;
	int				  num_items = -1;
	const char		 *name = NULL;
	const char		 *user_name = NULL;
	const char		 *password = NULL;
	DBusError			  error;
	gboolean			  success = FALSE;

	g_return_val_if_fail (message != NULL, FALSE);
	g_return_val_if_fail (data != NULL, FALSE);
	g_return_val_if_fail (reply != NULL, FALSE);

	dbus_error_init (&error);
	if (!dbus_message_get_args (message, &error,
							DBUS_TYPE_STRING, &name,
							DBUS_TYPE_STRING, &user_name,
							DBUS_TYPE_STRING, &password,
							DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &data_items, &num_items,
							DBUS_TYPE_INVALID))
	{
		nm_warning ("Could not process the request because its arguments were invalid.  dbus said: '%s'", error.message);
		dbus_error_free (&error);
		*reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE_VPNC, NM_DBUS_VPN_BAD_ARGUMENTS,
					"Could not process the request because its arguments were invalid.");
		goto out;
	}

	/* Now we can finally try to activate the VPN */
	nm_vpnc_set_state (data, NM_VPN_STATE_STARTING);
	if (nm_vpnc_config_file_generate (user_name, password, data_items, num_items))
		success = nm_vpnc_start_vpnc_binary (data);
	if (!success)
	{
		nm_vpnc_dbus_signal_launch_failed (data);
		nm_vpnc_set_state (data, NM_VPN_STATE_STOPPED);
	}

out:
	return success;
}


/*
 * nm_vpnc_dbus_handle_stop_vpn
 *
 * Stop the running vpnc dameon.
 *
 */
static gboolean nm_vpnc_dbus_handle_stop_vpn (NmVpncData *data)
{
	g_return_val_if_fail (data != NULL, FALSE);

	if (data->pid > 0)
	{
		nm_vpnc_set_state (data, NM_VPN_STATE_STOPPING);

		kill (data->pid, SIGTERM);
		nm_info ("Terminated vpnc daemon with PID %d.", data->pid);
		data->pid = 0;

		nm_vpnc_set_state (data, NM_VPN_STATE_STOPPED);
		nm_vpnc_schedule_quit_timer (data, 10000);
	}

	return TRUE;
}


/*
 * nm_vpnc_dbus_start_vpn
 *
 * Begin a VPN connection.
 *
 */
static DBusMessage *nm_vpnc_dbus_start_vpn (DBusConnection *con, DBusMessage *message, NmVpncData *data)
{
	DBusMessage		*reply = NULL;
	gboolean			 success = FALSE;

	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (con != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	switch (data->state)
	{
		case NM_VPN_STATE_STARTING:
			reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE_VPNC, NM_DBUS_VPN_STARTING_IN_PROGRESS,
						"Could not process the request because the VPN connection is already being started.");
			break;

		case NM_VPN_STATE_STARTED:
			reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE_VPNC, NM_DBUS_VPN_ALREADY_STARTED,
						"Could not process the request because a VPN connection was already active.");
			break;

		case NM_VPN_STATE_STOPPING:
			reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE_VPNC, NM_DBUS_VPN_STOPPING_IN_PROGRESS,
						"Could not process the request because the VPN connection is being stopped.");
			break;

		case NM_VPN_STATE_STOPPED:
			nm_vpnc_cancel_quit_timer (data);
			nm_vpnc_dbus_handle_start_vpn (message, &reply, data);
			if (!reply)
				reply = dbus_message_new_method_return (message);
			break;

		default:
			g_assert_not_reached();
			break;
	}

out:
	return reply;
}


/*
 * nm_vpnc_dbus_stop_vpn
 *
 * Terminate a VPN connection.
 *
 */
static DBusMessage *nm_vpnc_dbus_stop_vpn (DBusConnection *con, DBusMessage *message, NmVpncData *data)
{
	DBusMessage		*reply = NULL;

	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (con != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	switch (data->state)
	{
		case NM_VPN_STATE_STOPPING:
			reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE_VPNC, NM_DBUS_VPN_STOPPING_IN_PROGRESS,
						"Could not process the request because the VPN connection is already being stopped.");
			break;

		case NM_VPN_STATE_STOPPED:
			reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE_VPNC, NM_DBUS_VPN_ALREADY_STOPPED,
						"Could not process the request because no VPN connection was active.");
			break;

		case NM_VPN_STATE_STARTING:
		case NM_VPN_STATE_STARTED:
			nm_vpnc_dbus_handle_stop_vpn (data);
			reply = dbus_message_new_method_return (message);
			break;

		default:
			g_assert_not_reached();
			break;
	}

out:
	return reply;
}


/*
 * nm_vpnc_dbus_get_state
 *
 * Return some state information to NetworkManager.
 *
 */
static DBusMessage *nm_vpnc_dbus_get_state (DBusConnection *con, DBusMessage *message, NmVpncData *data)
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
 * nm_vpnc_dbus_process_helper_config_error
 *
 * Signal the bus that the helper could not get all the configuration information
 * it needed.
 *
 */
static void nm_vpnc_dbus_process_helper_config_error (DBusConnection *con, DBusMessage *message, NmVpncData *data)
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
		nm_warning ("vpnc helper did not receive adequate configuration information from vpnc.  It is missing '%s'.", error_item);
		/* Signal NetworkManager */
	}

	nm_vpnc_cancel_helper_timer (data);
	nm_vpnc_dbus_handle_stop_vpn (data);
}


/*
 *  Prints config returned from vpnc-helper
 */
static void print_vpn_config (guint32 ip4_vpn_gateway,
						const char *tundev,
						guint32 ip4_internal_address,
						gint32 ip4_internal_netmask,
						guint32 *ip4_internal_dns,
						guint32 ip4_internal_dns_len,
						guint32 *ip4_internal_nbns,
						guint32 ip4_internal_nbns_len,
						const char *cisco_def_domain,
						const char *cisco_banner)
{
	struct in_addr	temp_addr;
	guint32 		i;

	temp_addr.s_addr = ip4_vpn_gateway;
	nm_info ("VPN Gateway: %s", inet_ntoa (temp_addr));
	nm_info ("Tunnel Device: %s", tundev);
	temp_addr.s_addr = ip4_internal_address;
	nm_info ("Internal IP4 Address: %s", inet_ntoa (temp_addr));
	temp_addr.s_addr = ip4_internal_netmask;
	nm_info ("Internal IP4 Netmask: %s", inet_ntoa (temp_addr));

	for (i = 0; i < ip4_internal_dns_len; i++)
	{
		if (ip4_internal_dns[i] != 0)
		{
			temp_addr.s_addr = ip4_internal_dns[i];
			nm_info ("Internal IP4 DNS: %s", inet_ntoa (temp_addr));
		}
	}

	for (i = 0; i < ip4_internal_nbns_len; i++)
	{
		if (ip4_internal_nbns[i] != 0)
		{
			temp_addr.s_addr = ip4_internal_nbns[i];
			nm_info ("Internal IP4 NBNS: %s", inet_ntoa (temp_addr));
		}
	}

	nm_info ("Cisco Default Domain: '%s'", cisco_def_domain);
	nm_info ("Cisco Banner:");
	nm_info ("-----------------------------------------");
	nm_info ("%s", cisco_banner);
	nm_info ("-----------------------------------------");
}

/*
 * nm_vpnc_dbus_process_helper_ip4_config
 *
 * Signal the bus 
 *
 */
static void nm_vpnc_dbus_process_helper_ip4_config (DBusConnection *con, DBusMessage *message, NmVpncData *data)
{
	guint32		ip4_vpn_gateway;
	char *		tundev;
	guint32		ip4_internal_address;
	guint32		ip4_internal_netmask;
	guint32 *		ip4_internal_dns;
	guint32		ip4_internal_dns_len;
	guint32 *		ip4_internal_nbns;
	guint32		ip4_internal_nbns_len;
	char *		cisco_def_domain;
	char *		cisco_banner;
	gboolean		success = FALSE;

	g_return_if_fail (data != NULL);
	g_return_if_fail (con != NULL);
	g_return_if_fail (message != NULL);

	/* Only accept the config info if we're in STARTING state */
	if (data->state != NM_VPN_STATE_STARTING)
		return;

	nm_vpnc_cancel_helper_timer (data);

	if (dbus_message_get_args(message, NULL, DBUS_TYPE_UINT32, &ip4_vpn_gateway,
									 DBUS_TYPE_STRING, &tundev,
									 DBUS_TYPE_UINT32, &ip4_internal_address,
									 DBUS_TYPE_UINT32, &ip4_internal_netmask,
									 DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &ip4_internal_dns, &ip4_internal_dns_len,
									 DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &ip4_internal_nbns, &ip4_internal_nbns_len,
									 DBUS_TYPE_STRING, &cisco_def_domain,
									 DBUS_TYPE_STRING, &cisco_banner, DBUS_TYPE_INVALID))
	{
		DBusMessage	*signal;

#if 0
		print_vpn_config (ip4_vpn_gateway, tundev, ip4_internal_address, ip4_internal_netmask,
						ip4_internal_dns, ip4_internal_dns_len, ip4_internal_nbns, ip4_internal_nbns_len,
						cisco_def_domain, cisco_banner);
#endif

		if (!(signal = dbus_message_new_signal (NM_DBUS_PATH_VPNC, NM_DBUS_INTERFACE_VPNC, NM_DBUS_VPN_SIGNAL_IP4_CONFIG)))
		{
			nm_warning ("Not enough memory for new dbus message!");
			goto out;
		}

		dbus_message_append_args (signal, DBUS_TYPE_UINT32, &ip4_vpn_gateway,
									DBUS_TYPE_STRING, &tundev,
									DBUS_TYPE_UINT32, &ip4_internal_address,
									DBUS_TYPE_UINT32, &ip4_internal_netmask,
									DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &ip4_internal_dns, ip4_internal_dns_len,
									DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &ip4_internal_nbns, ip4_internal_nbns_len,
									DBUS_TYPE_STRING, &cisco_def_domain,
									DBUS_TYPE_STRING, &cisco_banner, DBUS_TYPE_INVALID);
		if (!dbus_connection_send (data->con, signal, NULL))
		{
			nm_warning ("Could not raise the "NM_DBUS_VPN_SIGNAL_IP4_CONFIG" signal!");
			goto out;
		}

		dbus_message_unref (signal);
		success = TRUE;
	}

out:
	if (!success)
	{
		nm_warning ("Received invalid IP4 Config information from helper, terminating vpnc.");
		nm_vpnc_dbus_handle_stop_vpn (data);
	}
}


/*
 * nm_vpnc_dbus_message_handler
 *
 * Handle requests for our services.
 *
 */
static DBusHandlerResult nm_vpnc_dbus_message_handler (DBusConnection *con, DBusMessage *message, void *user_data)
{
	NmVpncData		*data = (NmVpncData *)user_data;
	const char		*method;
	const char		*path;
	DBusMessage		*reply = NULL;
	gboolean			 handled = TRUE;

	g_return_val_if_fail (data != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (con != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (message != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	method = dbus_message_get_member (message);
	path = dbus_message_get_path (message);

	/* nm_info ("nm_vpnc_dbus_message_handler() got method '%s' for path '%s'.", method, path); */

	/* If we aren't ready to accept dbus messages, don't */
	if ((data->state == NM_VPN_STATE_INIT) || (data->state == NM_VPN_STATE_SHUTDOWN))
	{
		nm_warning ("Received dbus messages but couldn't handle them due to INIT or SHUTDOWN states.");
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE_VPNC, NM_DBUS_VPN_WRONG_STATE,
						"Could not process the request due to current state of STATE_INIT or STATE_SHUTDOWN.");
		goto reply;
	}

	if (strcmp ("startConnection", method) == 0)
		reply = nm_vpnc_dbus_start_vpn (con, message, data);
	else if (strcmp ("stopConnection", method) == 0)
		reply = nm_vpnc_dbus_stop_vpn (con, message, data);
	else if (strcmp ("getState", method) == 0)
		reply = nm_vpnc_dbus_get_state (con, message, data);
	else if (strcmp ("signalConfigError", method) == 0)
		nm_vpnc_dbus_process_helper_config_error (con, message, data);
	else if (strcmp ("signalIP4Config", method) == 0)
		nm_vpnc_dbus_process_helper_ip4_config (con, message, data);
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
 * nm_vpnc_dbus_filter
 *
 * Handle signals from the bus, like NetworkManager network state
 * signals.
 *
 */
static DBusHandlerResult nm_vpnc_dbus_filter (DBusConnection *con, DBusMessage *message, void *user_data)
{
	NmVpncData	*data = (NmVpncData *)user_data;
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
				nm_vpnc_dbus_handle_stop_vpn (data);
			}
		}
	}
	else if (dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceNoLongerActive"))
	{
		/* If the active device goes down our VPN is certainly not going to work. */
		nm_vpnc_dbus_handle_stop_vpn (data);
	}

	return (handled ? DBUS_HANDLER_RESULT_HANDLED : DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
}


/*
 * nm_vpnc_dbus_init
 *
 * Grab our connection to the system bus, return NULL if anything goes wrong.
 *
 */
DBusConnection *nm_vpnc_dbus_init (NmVpncData *data)
{
	DBusConnection			*connection = NULL;
	DBusError				 error;
	DBusObjectPathVTable	 vtable = { NULL, &nm_vpnc_dbus_message_handler, NULL, NULL, NULL, NULL };

	g_return_val_if_fail (data != NULL, NULL);

	dbus_error_init (&error);
	if (!(connection = dbus_bus_get (DBUS_BUS_SYSTEM, &error)))
	{
		nm_warning ("Error connecting to system bus: '%s'", error.message);
		goto out;
	}

	dbus_connection_setup_with_g_main (connection, NULL);

	dbus_error_init (&error);
	dbus_bus_request_name (connection, NM_DBUS_SERVICE_VPNC, 0, &error);
	if (dbus_error_is_set (&error))
	{
		nm_warning ("Could not acquire the dbus service.  dbus_bus_request_name() says: '%s'", error.message);
		goto out;
	}

	if (!dbus_connection_register_object_path (connection, NM_DBUS_PATH_VPNC, &vtable, data))
	{
		nm_warning ("Could not register a dbus handler for nm-vpnc-service.  Not enough memory?");
		return NULL;
	}

	if (!dbus_connection_add_filter (connection, nm_vpnc_dbus_filter, data, NULL))
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

NmVpncData *vpn_data = NULL;

static void sigterm_handler (int signum)
{
	nm_info ("nm-vpnc-service caught SIGINT/SIGTERM");

	g_main_loop_quit (vpn_data->loop);
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

	if (!(vpn_data = g_malloc0 (sizeof (NmVpncData))))
	{
		nm_warning ("Not enough memory to initialize.");
		exit (1);
	}
	vpn_data->state = NM_VPN_STATE_INIT;

	vpn_data->loop = g_main_loop_new (NULL, FALSE);

	system ("/sbin/modprobe tun");

	if (!(vpn_data->con = nm_vpnc_dbus_init (vpn_data)))
		exit (1);

	action.sa_handler = sigterm_handler;
	sigemptyset (&block_mask);
	action.sa_mask = block_mask;
	action.sa_flags = 0;
	sigaction (SIGINT, &action, NULL);
	sigaction (SIGTERM, &action, NULL);

	nm_vpnc_set_state (vpn_data, NM_VPN_STATE_STOPPED);
	g_main_loop_run (vpn_data->loop);

	nm_vpnc_dbus_handle_stop_vpn (vpn_data);

	g_main_loop_unref (vpn_data->loop);
	g_free (vpn_data);

	exit (0);
}
