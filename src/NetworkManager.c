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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>
#include <getopt.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <glib/gi18n.h>

#include "NetworkManager.h"
#include "nm-utils.h"
#include "NetworkManagerUtils.h"
#include "nm-manager.h"
#include "nm-hal-manager.h"	
#include "nm-device.h"
#include "nm-device-802-3-ethernet.h"
#include "nm-device-802-11-wireless.h"
#include "NetworkManagerPolicy.h"
#include "NetworkManagerDbus.h"
#include "NetworkManagerAP.h"
#include "NetworkManagerAPList.h"
#include "NetworkManagerSystem.h"
#include "nm-named-manager.h"
#include "nm-vpn-act-request.h"
#include "nm-dbus-vpn.h"
#include "nm-dbus-nm.h"
#include "nm-dbus-manager.h"
#include "nm-dbus-device.h"
#include "nm-supplicant-manager.h"
#include "nm-dbus-net.h"
#include "nm-netlink-monitor.h"
#include "nm-logging.h"

#define NM_WIRELESS_LINK_STATE_POLL_INTERVAL (5 * 1000)

#define NM_DEFAULT_PID_FILE	LOCALSTATEDIR"/run/NetworkManager.pid"

/*
 * Globals
 */
static NMData		*nm_data = NULL;
static NMManager *manager = NULL;

static gboolean sigterm_pipe_handler (GIOChannel *src, GIOCondition condition, gpointer data);
static void nm_data_free (NMData *data);

/*
 * nm_state_change_signal_broadcast
 *
 */
static gboolean nm_state_change_signal_broadcast (gpointer user_data)
{
	NMState state;
	NMDBusManager *dbus_mgr;
	DBusConnection *dbus_connection;

	state = nm_manager_get_state (manager);

	dbus_mgr = nm_dbus_manager_get ();
	dbus_connection = nm_dbus_manager_get_dbus_connection (dbus_mgr);
	if (dbus_connection)
		nm_dbus_signal_state_change (dbus_connection, state);
	g_object_unref (dbus_mgr);

	return FALSE;
}


/*
 * nm_schedule_state_change_signal_broadcast
 *
 */
void nm_schedule_state_change_signal_broadcast (NMData *data)
{
	g_idle_add_full (G_PRIORITY_HIGH,
					 nm_state_change_signal_broadcast,
					 NULL,
					 NULL);
}


static void
nm_error_monitoring_device_link_state (NmNetlinkMonitor *monitor,
				      GError 	       *error,
				      NMData	       *data)
{
	/* FIXME: Try to handle the error instead of just printing it. */
	nm_warning ("error monitoring wired ethernet link state: %s\n",
		    error->message);
}

static NmNetlinkMonitor *
nm_monitor_setup (NMData *data)
{
	GError *error = NULL;
	NmNetlinkMonitor *monitor;

	monitor = nm_netlink_monitor_new (data);
	nm_netlink_monitor_open_connection (monitor, &error);
	if (error != NULL)
	{
		nm_warning ("could not monitor wired ethernet devices: %s",
			    error->message);
		g_error_free (error);
		g_object_unref (monitor);
		return NULL;
	}

	g_signal_connect (G_OBJECT (monitor), "error",
			  G_CALLBACK (nm_error_monitoring_device_link_state),
			  data);

	nm_netlink_monitor_attach (monitor, NULL);

	/* Request initial status of cards */
	nm_netlink_monitor_request_status (monitor, NULL);
	return monitor;
}

/*
 * nm_data_new
 *
 * Create data structure used in callbacks from libhal.
 *
 */
static NMData *nm_data_new (gboolean enable_test_devices)
{
	NMData * data;
	guint    id;

	data = g_slice_new0 (NMData);

	data->main_loop = g_main_loop_new (NULL, FALSE);

	/* Allow clean shutdowns by having the thread which receives the signal
	 * notify the main thread to quit, rather than having the receiving
	 * thread try to quit the glib main loop.
	 */
	if (pipe (data->sigterm_pipe) < 0) {
		nm_error ("Couldn't create pipe: %s", g_strerror (errno));
		return NULL;
	}
	data->sigterm_iochannel = g_io_channel_unix_new (data->sigterm_pipe[0]);
	id = g_io_add_watch (data->sigterm_iochannel,
	                     G_IO_IN | G_IO_ERR,
	                     sigterm_pipe_handler,
	                     data);

	/* Initialize the access point lists */
	data->allowed_ap_list = nm_ap_list_new (NETWORK_TYPE_ALLOWED);
	data->invalid_ap_list = nm_ap_list_new (NETWORK_TYPE_INVALID);
	if (!data->allowed_ap_list || !data->invalid_ap_list)
	{
		nm_data_free (data);
		nm_warning ("could not create access point lists.");
		return NULL;
	}

	/* Create watch functions that monitor cards for link status. */
	if (!(data->netlink_monitor = nm_monitor_setup (data)))
	{
		nm_data_free (data);
		nm_warning ("could not create netlink monitor.");
		return NULL;
	}

	data->enable_test_devices = enable_test_devices;
	data->wireless_enabled = TRUE;
	return data;
}


/*
 * nm_data_free
 *
 *   Free data structure used in callbacks.
 *
 */
static void nm_data_free (NMData *data)
{
	NMVPNActRequest *req;

	g_return_if_fail (data != NULL);

	/* Kill any active VPN connection */
	if ((req = nm_vpn_manager_get_vpn_act_request (data->vpn_manager)))
		nm_vpn_manager_deactivate_vpn_connection (data->vpn_manager, nm_vpn_act_request_get_parent_dev (req));

	if (data->netlink_monitor) {
		g_object_unref (G_OBJECT (data->netlink_monitor));
		data->netlink_monitor = NULL;
	}

	nm_ap_list_unref (data->allowed_ap_list);
	nm_ap_list_unref (data->invalid_ap_list);

	nm_dbus_method_list_unref (data->nm_methods);
	nm_dbus_method_list_unref (data->device_methods);

	nm_vpn_manager_dispose (data->vpn_manager);
	g_object_unref (data->named_manager);

	g_main_loop_unref (data->main_loop);
	g_io_channel_unref(data->sigterm_iochannel);

	g_slice_free (NMData, data);
}

int nm_get_sigterm_pipe (void)
{
	return nm_data->sigterm_pipe[1];
}

static gboolean sigterm_pipe_handler (GIOChannel *src, GIOCondition condition, gpointer user_data)
{
	NMData *		data = user_data;

	nm_info ("Caught terminiation signal");
	g_main_loop_quit (data->main_loop);
	return FALSE;
}

static void
nm_name_owner_changed_handler (NMDBusManager *mgr,
                               DBusConnection *connection,
                               const char *name,
                               const char *old,
                               const char *new,
                               gpointer user_data)
{
	NMData * data = (NMData *) user_data;
	gboolean old_owner_good = (old && (strlen (old) > 0));
	gboolean new_owner_good = (new && (strlen (new) > 0));

	if (strcmp (name, NMI_DBUS_SERVICE) == 0) {
		if (!old_owner_good && new_owner_good) {
			/* NMI appeared, update stuff */
			nm_policy_schedule_allowed_ap_list_update (data);
			nm_dbus_vpn_schedule_vpn_connections_update (data);
		} else if (old_owner_good && !new_owner_good) {
			/* nothing */
		}
	}
}

static void
write_pidfile (const char *pidfile)
{
 	char pid[16];
	int fd;
 
	if ((fd = open (pidfile, O_CREAT|O_WRONLY|O_TRUNC, 00644)) < 0)
	{
		nm_warning ("Opening %s failed: %s", pidfile, strerror (errno));
		return;
	}
 	snprintf (pid, sizeof (pid), "%d", getpid ());
	if (write (fd, pid, strlen (pid)) < 0)
		nm_warning ("Writing to %s failed: %s", pidfile, strerror (errno));
	if (close (fd))
		nm_warning ("Closing %s failed: %s", pidfile, strerror (errno));
}


/*
 * nm_print_usage
 *
 * Prints program usage.
 *
 */
static void nm_print_usage (void)
{
	fprintf (stderr,
		"\n"
		"NetworkManager monitors all network connections and automatically\n"
		"chooses the best connection to use.  It also allows the user to\n"
		"specify wireless access points which wireless cards in the computer\n"
		"should associate with.\n"
		"\n");
}


/*
 * main
 *
 */
int
main (int argc, char *argv[])
{
	GOptionContext *opt_ctx = NULL;
	gboolean		become_daemon = FALSE;
	gboolean		enable_test_devices = FALSE;
	gboolean		show_usage = FALSE;
	char *		pidfile = NULL;
	char *		user_pidfile = NULL;
	NMPolicy *policy;
	NMHalManager *hal_manager = NULL;
	NMDBusManager *	dbus_mgr;
	DBusConnection *dbus_connection;
	NMSupplicantManager * sup_mgr = NULL;
	int			exit_status = EXIT_FAILURE;
	guint32     id;

	GOptionEntry options[] = {
		{"no-daemon", 0, 0, G_OPTION_ARG_NONE, &become_daemon, "Don't become a daemon", NULL},
		{"pid-file", 0, 0, G_OPTION_ARG_STRING, &user_pidfile, "Specify the location of a PID file", NULL},
		{"enable-test-devices", 0, 0, G_OPTION_ARG_NONE, &enable_test_devices, "Allow dummy devices to be created via DBUS methods [DEBUG]", NULL},
		{"info", 0, 0, G_OPTION_ARG_NONE, &show_usage, "Show application information", NULL},
		{NULL}
	};

	if (getuid () != 0) {
		g_printerr ("You must be root to run NetworkManager!\n");
		goto exit;
	}

	bindtextdomain (GETTEXT_PACKAGE, GNOMELOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);

	/* Parse options */
	opt_ctx = g_option_context_new("");
	g_option_context_add_main_entries(opt_ctx, options, NULL);
	g_option_context_parse(opt_ctx, &argc, &argv, NULL);
	g_option_context_free(opt_ctx);

	if (show_usage == TRUE) {
		nm_print_usage();
		exit_status = EXIT_SUCCESS;
		goto exit;
	}

	pidfile = g_strdup (user_pidfile ? user_pidfile : NM_DEFAULT_PID_FILE);

	/* Tricky: become_daemon is FALSE by default, so unless it's TRUE because
	 * of a CLI option, it'll become TRUE after this
	 */
	become_daemon = !become_daemon;
	if (become_daemon) {
		if (daemon (0, 0) < 0) {
			int saved_errno;

			saved_errno = errno;
			nm_error ("Could not daemonize: %s [error %u]",
			          g_strerror (saved_errno),
			          saved_errno);
			goto exit;
		}
		write_pidfile (pidfile);
	}

	/*
	 * Set the umask to 0022, which results in 0666 & ~0022 = 0644.
	 * Otherwise, if root (or an su'ing user) has a wacky umask, we could
	 * write out an unreadable resolv.conf.
	 */
	umask (022);

	g_type_init ();
	if (!g_thread_supported ())
		g_thread_init (NULL);
	dbus_g_thread_init ();
	
	nm_logging_setup (become_daemon);
	nm_info ("starting...");

	nm_system_init();

	/* Initialize our instance data */
	nm_data = nm_data_new (enable_test_devices);
	if (!nm_data) {
		nm_error ("Failed to initialize.");
		goto pidfile;
	}

	/* Initialize our DBus service & connection */
	dbus_mgr = nm_dbus_manager_get ();
	dbus_connection = nm_dbus_manager_get_dbus_connection (dbus_mgr);
	if (!dbus_connection) {
		nm_error ("Failed to initialize. "
		          "Either dbus is not running, or the "
		          "NetworkManager dbus security policy "
		          "was not loaded.");
		goto done;
	}
	g_signal_connect (G_OBJECT (dbus_mgr), "name-owner-changed",
	                  G_CALLBACK (nm_name_owner_changed_handler), nm_data);
	id = nm_dbus_manager_register_signal_handler (dbus_mgr,
	                                              NMI_DBUS_INTERFACE,
	                                              NULL,
	                                              nm_dbus_nmi_signal_handler,
	                                              nm_data);
	nm_data->nmi_sig_handler_id = id;

	/* Register DBus method handlers for the main NM objects */
	nm_data->nm_methods = nm_dbus_nm_methods_setup (nm_data);
	nm_dbus_manager_register_method_list (dbus_mgr, nm_data->nm_methods);
	nm_data->device_methods = nm_dbus_device_methods_setup (nm_data);
	nm_dbus_manager_register_method_list (dbus_mgr, nm_data->device_methods);
	nm_data->net_methods = nm_dbus_net_methods_setup (nm_data);

	manager = nm_manager_new ();
	policy = nm_policy_new (manager);

	/* Initialize the supplicant manager */
	sup_mgr = nm_supplicant_manager_get ();
	if (!sup_mgr) {
		nm_error ("Failed to initialize the supplicant manager.");
		goto done;
	}

	nm_data->vpn_manager = nm_vpn_manager_new (manager, nm_data);
	if (!nm_data->vpn_manager) {
		nm_warning ("Failed to start the VPN manager.");
		goto done;
	}

	nm_data->named_manager = nm_named_manager_new ();
	if (!nm_data->named_manager) {
		nm_warning ("Failed to start the named manager.");
		goto done;
	}

	/* Start our DBus service */
	if (!nm_dbus_manager_start_service (dbus_mgr)) {
		nm_warning ("Failed to start the named manager.");
		goto done;
	}

	hal_manager = nm_hal_manager_new (manager, nm_data);
	if (!hal_manager)
		goto done;

	/* If NMI is running, grab allowed wireless network lists from it ASAP */
	if (nm_dbus_manager_name_has_owner (dbus_mgr, NMI_DBUS_SERVICE)) {
		nm_policy_schedule_allowed_ap_list_update (nm_data);
		nm_dbus_vpn_schedule_vpn_connections_update (nm_data);
	}

	/* We run dhclient when we need to, and we don't want any stray ones
	 * lying around upon launch.
	 */
//	nm_system_kill_all_dhcp_daemons ();

	/* Bring up the loopback interface. */
	nm_system_enable_loopback ();

	/* Get modems, ISDN, and so on's configuration from the system */
	nm_data->dialup_list = nm_system_get_dialup_config ();

	/* Run the main loop */
	nm_policy_schedule_device_change_check (nm_data);
	nm_schedule_state_change_signal_broadcast (nm_data);
	exit_status = EXIT_SUCCESS;
	g_main_loop_run (nm_data->main_loop);

done:
	nm_print_open_socks ();

	nm_dbus_manager_remove_signal_handler (dbus_mgr, nm_data->nmi_sig_handler_id);

	nm_hal_manager_destroy (hal_manager);
	nm_policy_destroy (policy);

	if (manager)
		g_object_unref (manager);

	nm_data_free (nm_data);

	if (sup_mgr)
		g_object_unref (sup_mgr);

	/* nm_data_free needs the dbus connection, so must kill the
	 * dbus manager after that.
	 */
	g_object_unref (dbus_mgr);
	nm_logging_shutdown ();

pidfile:
	if (pidfile)
		unlink (pidfile);
	g_free (pidfile);

exit:
	exit (exit_status);
}
