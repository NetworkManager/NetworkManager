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
#include <libhal.h>
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
#include "nm-netlink-monitor.h"
#include "nm-dhcp-manager.h"
#include "nm-logging.h"

#define NM_WIRELESS_LINK_STATE_POLL_INTERVAL (5 * 1000)

#define NM_DEFAULT_PID_FILE	LOCALSTATEDIR"/run/NetworkManager.pid"

/*
 * Globals
 */
static NMData		*nm_data = NULL;

static gboolean sigterm_pipe_handler (GIOChannel *src, GIOCondition condition, gpointer data);
static void nm_data_free (NMData *data);

/*
 * nm_get_device_interface_from_hal
 *
 */
static char *nm_get_device_interface_from_hal (LibHalContext *ctx, const char *udi)
{
	char *iface = NULL;

	if (libhal_device_property_exists (ctx, udi, "net.interface", NULL))
	{
		/* Only use Ethernet and Wireless devices at the moment */
		if (libhal_device_property_exists (ctx, udi, "info.category", NULL))
		{
			char *category = libhal_device_get_property_string (ctx, udi, "info.category", NULL);
			if (category && (!strcmp (category, "net.80203") || !strcmp (category, "net.80211")))
			{
				char *temp = libhal_device_get_property_string (ctx, udi, "net.interface", NULL);
				iface = g_strdup (temp);
				libhal_free_string (temp);
			}
			libhal_free_string (category);
		}
	}

	return (iface);
}


/*
 * nm_create_device_and_add_to_list
 *
 * Create a new network device and add it to our device list.
 *
 * Returns:		newly allocated device on success
 *				NULL on failure
 */
NMDevice * nm_create_device_and_add_to_list (NMData *data, const char *udi, const char *iface,
					     gboolean test_device, NMDeviceType test_device_type)
{
	NMDevice	*dev = NULL;

	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (udi  != NULL, NULL);
	g_return_val_if_fail (iface != NULL, NULL);
	g_return_val_if_fail (strlen (iface) > 0, NULL);

	/* If we are called to create a test devices, but test devices weren't enabled
	 * on the command-line, don't create the device.
	 */
	if (!data->enable_test_devices && test_device)
	{
		nm_warning ("attempted to create a test device, "
			    "but test devices were not enabled "
			    "on the command line.");
		return (NULL);
	}

	/* Make sure the device is not already in the device list */
	if ((dev = nm_get_device_by_iface (data, iface)))
		return (NULL);

	if ((dev = nm_device_new (iface, udi, test_device, test_device_type, data)))
	{
		/* Attempt to acquire mutex for device list addition.  If acquire fails,
		 * just ignore the device addition entirely.
		 */
		if (nm_try_acquire_mutex (data->dev_list_mutex, __FUNCTION__))
		{
			nm_info ("Now managing %s device '%s'.",
				nm_device_is_802_11_wireless (dev) ? "wireless (802.11)" : "wired Ethernet (802.3)", nm_device_get_iface (dev));

			data->dev_list = g_slist_append (data->dev_list, dev);
			nm_device_deactivate (dev);

			nm_unlock_mutex (data->dev_list_mutex, __FUNCTION__);

			nm_policy_schedule_device_change_check (data);
			nm_dbus_schedule_device_status_change_signal (data, dev, NULL, DEVICE_ADDED);
		}
		else
		{
			/* If we couldn't add the device to our list, free its data. */
			nm_warning ("could not acquire device list mutex." );
			g_object_unref (G_OBJECT (dev));
			dev = NULL;
		}
	}

	return (dev);
}


/*
 * nm_remove_device
 *
 * Removes a particular device from the device list.  Requires that
 * the device list is locked, if needed.
 */
void nm_remove_device (NMData *data, NMDevice *dev)
{
	g_return_if_fail (data != NULL);
	g_return_if_fail (dev != NULL);

	nm_device_set_removed (dev, TRUE);
	nm_device_stop (dev);
	nm_dbus_schedule_device_status_change_signal (data, dev, NULL, DEVICE_REMOVED);

	g_object_unref (G_OBJECT (dev));

	/* Remove the device entry from the device list and free its data */
	data->dev_list = g_slist_remove (data->dev_list, dev);
}


/*
 * nm_get_active_device
 *
 * Return the currently active device.
 *
 */
NMDevice *nm_get_active_device (NMData *data)
{
	NMDevice *	dev = NULL;
	GSList *		elt;
	
	g_return_val_if_fail (data != NULL, NULL);

	nm_lock_mutex (data->dev_list_mutex, __FUNCTION__);
	for (elt = data->dev_list; elt; elt = g_slist_next (elt))
	{
		if ((dev = (NMDevice *)(elt->data)) && nm_device_get_act_request (dev))
			break;
		dev = NULL;
	}
	nm_unlock_mutex (data->dev_list_mutex, __FUNCTION__);

	return dev;
}


/* Hal doesn't really give us any way to pass a GMainContext to our
 * mainloop integration function unfortunately.  So we have to use
 * a global.
 */
GMainContext *main_context = NULL;

/*
 * nm_hal_mainloop_integration
 *
 */
static void nm_hal_mainloop_integration (LibHalContext *ctx, DBusConnection * dbus_connection)
{
	dbus_connection_setup_with_g_main (dbus_connection, main_context);
}

/*
 * nm_hal_device_added
 *
 */
static void nm_hal_device_added (LibHalContext *ctx, const char *udi)
{
	NMData	*data = (NMData *)libhal_ctx_get_user_data (ctx);
	char		*iface = NULL;

	g_return_if_fail (data != NULL);

	nm_debug ("New device added (hal udi is '%s').", udi );

	/* Sometimes the device's properties (like net.interface) are not set up yet,
	 * so this call will fail, and it will actually be added when hal sets the device's
	 * capabilities a bit later on.
	 */
	if ((iface = nm_get_device_interface_from_hal (data->hal_ctx, udi)))
	{
		nm_create_device_and_add_to_list (data, udi, iface, FALSE, DEVICE_TYPE_UNKNOWN);
		g_free (iface);
	}
}


/*
 * nm_hal_device_removed
 *
 */
static void nm_hal_device_removed (LibHalContext *ctx, const char *udi)
{
	NMData	*data = (NMData *)libhal_ctx_get_user_data (ctx);
	NMDevice	*dev;

	g_return_if_fail (data != NULL);

	nm_debug ("Device removed (hal udi is '%s').", udi );

	if (!nm_try_acquire_mutex (data->dev_list_mutex, __FUNCTION__))
		return;

	if ((dev = nm_get_device_by_udi (data, udi)))
	{
		nm_remove_device (data, dev);
		nm_policy_schedule_device_change_check (data);
	}

	nm_unlock_mutex (data->dev_list_mutex, __FUNCTION__);
}


/*
 * nm_hal_device_new_capability
 *
 */
static void nm_hal_device_new_capability (LibHalContext *ctx, const char *udi, const char *capability)
{
	NMData	*data = (NMData *)libhal_ctx_get_user_data (ctx);

	g_return_if_fail (data != NULL);

	/*nm_debug ("nm_hal_device_new_capability() called with udi = %s, capability = %s", udi, capability );*/

	if (capability && ((strcmp (capability, "net.80203") == 0) || (strcmp (capability, "net.80211") == 0)))
	{
		char *iface;

		if ((iface = nm_get_device_interface_from_hal (data->hal_ctx, udi)))
		{
			nm_create_device_and_add_to_list (data, udi, iface, FALSE, DEVICE_TYPE_UNKNOWN);
			g_free (iface);
		}
	}
}


/*
 * nm_add_initial_devices
 *
 * Add all devices that hal knows about right now (ie not hotplug devices)
 *
 */
void nm_add_initial_devices (NMData *data)
{
	char **	net_devices;
	int		num_net_devices;
	int		i;
	DBusError	error;

	g_return_if_fail (data != NULL);

	dbus_error_init (&error);
	/* Grab a list of network devices */
	net_devices = libhal_find_device_by_capability (data->hal_ctx, "net", &num_net_devices, &error);
	if (dbus_error_is_set (&error))
	{
		nm_warning ("could not find existing networking devices: %s", error.message);
		dbus_error_free (&error);
	}

	if (net_devices)
	{
		for (i = 0; i < num_net_devices; i++)
		{
			char *iface;

			if ((iface = nm_get_device_interface_from_hal (data->hal_ctx, net_devices[i])))
			{
				nm_create_device_and_add_to_list (data, net_devices[i], iface, FALSE, DEVICE_TYPE_UNKNOWN);
				g_free (iface);
			}
		}
	}

	libhal_free_string_array (net_devices);
}


/*
 * nm_state_change_signal_broadcast
 *
 */
static gboolean nm_state_change_signal_broadcast (gpointer user_data)
{
	NMData *data = (NMData *)user_data;

	g_return_val_if_fail (data != NULL, FALSE);

	nm_dbus_signal_state_change (data->dbus_connection, data);
	return FALSE;
}


/*
 * nm_schedule_state_change_signal_broadcast
 *
 */
void nm_schedule_state_change_signal_broadcast (NMData *data)
{
	guint	 id = 0;
	GSource	*source;

	g_return_if_fail (data != NULL);

	source = g_idle_source_new ();
	g_source_set_priority (source, G_PRIORITY_HIGH);
	g_source_set_callback (source, nm_state_change_signal_broadcast, data, NULL);
	id = g_source_attach (source, data->main_context);
	g_source_unref (source);
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

	nm_netlink_monitor_attach (monitor, data->main_context);

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
	NMData *			data;
	GSource *			iosource;
	
	data = g_new0 (NMData, 1);

	data->main_context = g_main_context_new ();
	data->main_loop = g_main_loop_new (data->main_context, FALSE);

	/* Allow clean shutdowns by having the thread which receives the signal
	 * notify the main thread to quit, rather than having the receiving
	 * thread try to quit the glib main loop.
	 */
	if (pipe (data->sigterm_pipe) < 0)
	{
		nm_error ("Couldn't create pipe: %s", g_strerror (errno));
		return NULL;
	}
	data->sigterm_iochannel = g_io_channel_unix_new (data->sigterm_pipe[0]);
	iosource = g_io_create_watch (data->sigterm_iochannel, G_IO_IN | G_IO_ERR);
	g_source_set_callback (iosource, (GSourceFunc) sigterm_pipe_handler, data, NULL);
	g_source_attach (iosource, data->main_context);
	g_source_unref (iosource);

	/* Initialize the device list mutex to protect additions/deletions to it. */
	data->dev_list_mutex = g_mutex_new ();
	data->dialup_list_mutex = g_mutex_new ();
	if (!data->dev_list_mutex || !data->dialup_list_mutex)
	{
		nm_data_free (data);
		nm_warning ("could not initialize data structure locks.");
		return NULL;
	}
	nm_register_mutex_desc (data->dev_list_mutex, "Device List Mutex");
	nm_register_mutex_desc (data->dialup_list_mutex, "DialUp List Mutex");

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


static void device_stop_and_free (NMDevice *dev, gpointer user_data)
{
	g_return_if_fail (dev != NULL);

	nm_device_set_removed (dev, TRUE);
	nm_device_deactivate (dev);
	g_object_unref (G_OBJECT (dev));
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

	if (data->netlink_monitor)
	{
		g_object_unref (G_OBJECT (data->netlink_monitor));
		data->netlink_monitor = NULL;
	}

	/* Stop and destroy all devices */
	nm_lock_mutex (data->dev_list_mutex, __FUNCTION__);
	g_slist_foreach (data->dev_list, (GFunc) device_stop_and_free, NULL);
	g_slist_free (data->dev_list);
	nm_unlock_mutex (data->dev_list_mutex, __FUNCTION__);

	g_mutex_free (data->dev_list_mutex);

	nm_ap_list_unref (data->allowed_ap_list);
	nm_ap_list_unref (data->invalid_ap_list);

	nm_vpn_manager_dispose (data->vpn_manager);
	nm_dhcp_manager_dispose (data->dhcp_manager);
	g_object_unref (data->named_manager);

	g_main_loop_unref (data->main_loop);
	g_main_context_unref (data->main_context);

	g_io_channel_unref(data->sigterm_iochannel);

	nm_hal_deinit (data);

	memset (data, 0, sizeof (NMData));
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

static LibHalContext *nm_get_hal_ctx (NMData *data)
{
	LibHalContext *	ctx = NULL;
	DBusError			error;

	g_return_val_if_fail (data != NULL, NULL);

	/* Initialize libhal.  We get a connection to the hal daemon here. */
	if ((ctx = libhal_ctx_new()) == NULL)
	{
		nm_error ("libhal_ctx_new() failed, exiting...");
		return NULL;
	}

	nm_hal_mainloop_integration (ctx, data->dbus_connection); 
	libhal_ctx_set_dbus_connection (ctx, data->dbus_connection);
	dbus_error_init (&error);
	if(!libhal_ctx_init (ctx, &error))
	{
		nm_error ("libhal_ctx_init() failed: %s\n"
			  "Make sure the hal daemon is running?", 
			  error.message);

		dbus_error_free (&error);
		libhal_ctx_free (ctx);
		return NULL;
	}

	libhal_ctx_set_user_data (ctx, data);
	libhal_ctx_set_device_added (ctx, nm_hal_device_added);
	libhal_ctx_set_device_removed (ctx, nm_hal_device_removed);
	libhal_ctx_set_device_new_capability (ctx, nm_hal_device_new_capability);

	dbus_error_init (&error);
	libhal_device_property_watch_all (ctx, &error);
	if (dbus_error_is_set (&error))
	{
		nm_error ("libhal_device_property_watch_all(): %s", error.message);
		dbus_error_free (&error);
		libhal_ctx_free (ctx);
	}

	return ctx;
}


void nm_hal_init (NMData *data)
{
	g_return_if_fail (data != NULL);

	if ((data->hal_ctx = nm_get_hal_ctx (data)))
		nm_add_initial_devices (data);
}


void nm_hal_deinit (NMData *data)
{
	g_return_if_fail (data != NULL);

	if (data->hal_ctx)
	{
		DBusError error;

		dbus_error_init (&error);
		libhal_ctx_shutdown (data->hal_ctx, &error);
		if (dbus_error_is_set (&error))
		{
			nm_warning ("libhal shutdown failed - %s", error.message);
			dbus_error_free (&error);
		}
		libhal_ctx_free (data->hal_ctx);
		data->hal_ctx = NULL;
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
int main( int argc, char *argv[] )
{
	gboolean		become_daemon = FALSE;
	gboolean		enable_test_devices = FALSE;
	gboolean		show_usage = FALSE;
	char *		owner;
	char *		pidfile = NULL;
	char *		user_pidfile = NULL;
	
	if (getuid () != 0)
	{
		g_printerr ("You must be root to run NetworkManager!\n");
		return (EXIT_FAILURE);
	}

	bindtextdomain (GETTEXT_PACKAGE, GNOMELOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);

	/* Parse options */
	{
		GOptionContext  *opt_ctx = NULL;
		GOptionEntry options[] = {
			{"no-daemon", 0, 0, G_OPTION_ARG_NONE, &become_daemon, "Don't become a daemon", NULL},
			{"pid-file", 0, 0, G_OPTION_ARG_STRING, &user_pidfile, "Specify the location of a PID file", NULL},
			{"enable-test-devices", 0, 0, G_OPTION_ARG_NONE, &enable_test_devices, "Allow dummy devices to be created via DBUS methods [DEBUG]", NULL},
			{"info", 0, 0, G_OPTION_ARG_NONE, &show_usage, "Show application information", NULL},
			{NULL}
		};
		opt_ctx = g_option_context_new("");
		g_option_context_add_main_entries(opt_ctx, options, NULL);
		g_option_context_parse(opt_ctx, &argc, &argv, NULL);
		g_option_context_free(opt_ctx);
	}

	/* Tricky: become_daemon is FALSE by default, so unless it's TRUE because of a CLI
	 * option, it'll become TRUE after this */
	become_daemon = !become_daemon;
	if (show_usage == TRUE)
	{
		nm_print_usage();
		exit (EXIT_SUCCESS);
	}

	if (become_daemon)
	{
		if (daemon (0, 0) < 0)
		{
			int saved_errno;

			saved_errno = errno;
			nm_error ("NetworkManager could not daemonize: %s [error %u]",
				  g_strerror (saved_errno), saved_errno);
			exit (EXIT_FAILURE);
		}

		pidfile = user_pidfile ? user_pidfile : NM_DEFAULT_PID_FILE;
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
	if (!nm_data)
	{
		nm_error ("nm_data_new() failed... Not enough memory?");
		exit (EXIT_FAILURE);
	}

	/* Create our dbus service */
	nm_data->dbus_connection = nm_dbus_init (nm_data);
	if (!nm_data->dbus_connection)
	{
		nm_error ("nm_dbus_init() failed, exiting. "
			  "Either dbus is not running, or the "
			  "NetworkManager dbus security policy "
			  "was not loaded.");
		exit (EXIT_FAILURE);
	}

	/* Need to happen after DBUS is initialized */
	nm_data->vpn_manager = nm_vpn_manager_new (nm_data);
	nm_data->dhcp_manager = nm_dhcp_manager_new (nm_data);
	nm_data->named_manager = nm_named_manager_new (nm_data->dbus_connection);

	/* If NMI is running, grab allowed wireless network lists from it ASAP */
	if (nm_dbus_is_info_daemon_running (nm_data->dbus_connection))
	{
		nm_policy_schedule_allowed_ap_list_update (nm_data);
		nm_dbus_vpn_schedule_vpn_connections_update (nm_data);
	}

	/* Right before we init hal, we have to make sure our mainloop
	 * integration function knows about our GMainContext.  HAL doesn't give
	 * us any way to pass that into its mainloop integration callback, so
	 * its got to be a global.
	 */
	main_context = nm_data->main_context;

	/* If Hal is around, grab a device list from it */
	if ((owner = get_name_owner (nm_data->dbus_connection, "org.freedesktop.Hal")))
		nm_hal_init (nm_data);

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
	g_main_loop_run (nm_data->main_loop);

	nm_print_open_socks ();
	nm_data_free (nm_data);
	nm_logging_shutdown ();

	/* Clean up pidfile */
	if (pidfile)
		unlink (pidfile);
	g_free (user_pidfile);

	exit (0);
}
