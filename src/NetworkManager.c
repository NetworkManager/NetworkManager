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

#include "NetworkManager.h"
#include "nm-utils.h"
#include "NetworkManagerUtils.h"
#include "NetworkManagerDevice.h"
#include "NetworkManagerPolicy.h"
#include "NetworkManagerWireless.h"
#include "NetworkManagerDbus.h"
#include "NetworkManagerAP.h"
#include "NetworkManagerAPList.h"
#include "NetworkManagerSystem.h"
#include "nm-named-manager.h"
#include "nm-dbus-vpn.h"
#include "nm-netlink-monitor.h"

#define NM_WIRELESS_LINK_STATE_POLL_INTERVAL (5 * 1000)

/*
 * Globals
 */
static NMData		*nm_data = NULL;

static gboolean sigterm_pipe_handler (GIOChannel *src, GIOCondition condition, gpointer data);
static void sigterm_handler (int signum);
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
				nm_device_is_wireless (dev) ? "wireless" : "wired", nm_device_get_iface (dev));

			data->dev_list = g_slist_append (data->dev_list, dev);
			nm_device_deactivate (dev, TRUE);

			nm_device_update_link_state (dev);

			nm_unlock_mutex (data->dev_list_mutex, __FUNCTION__);

			nm_policy_schedule_state_update (data);
			nm_dbus_signal_device_status_change (data->dbus_connection, dev, DEVICE_ADDED);
		}
		else
		{
			/* If we couldn't add the device to our list, free its data. */
			nm_warning ("could not acquire device list mutex." );
			nm_device_unref (dev);
			dev = NULL;
		}
	} else nm_warning ("could not allocate device data." );

	return (dev);
}


/*
 * nm_remove_device_from_list
 *
 * Searches for a device entry in the NLM device list by udi,
 * and if found, removes that element from the list and frees
 * its data.
 */
void nm_remove_device_from_list (NMData *data, const char *udi)
{
	g_return_if_fail (data != NULL);
	g_return_if_fail (udi != NULL);

	/* Attempt to acquire mutex for device list deletion.  If acquire fails,
	 * just ignore the device deletion entirely.
	 */
	if (nm_try_acquire_mutex (data->dev_list_mutex, __FUNCTION__))
	{
		GSList	*elt;
		for (elt = data->dev_list; elt; elt = g_slist_next (elt))
		{
			NMDevice	*dev = (NMDevice *)(elt->data);

			if (dev && (nm_null_safe_strcmp (nm_device_get_udi (dev), udi) == 0))
			{
				if (data->active_device && (dev == data->active_device))
				{
					data->active_device = NULL;
					data->active_device_locked = FALSE;
				}

				nm_device_set_removed (dev, TRUE);
				nm_device_deactivate (dev, FALSE);
				nm_device_worker_thread_stop (dev);
				nm_dbus_signal_device_status_change (data->dbus_connection, dev, DEVICE_REMOVED);
				nm_device_unref (dev);

				/* Remove the device entry from the device list and free its data */
				data->dev_list = g_slist_remove_link (data->dev_list, elt);
				g_slist_free (elt);
				nm_policy_schedule_state_update (data);
				break;
			}
		}
		nm_unlock_mutex (data->dev_list_mutex, __FUNCTION__);
	} else nm_warning ("could not acquire device list mutex." );
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
		nm_create_device_and_add_to_list (data, udi, iface, FALSE, DEVICE_TYPE_DONT_KNOW);
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

	g_return_if_fail (data != NULL);

	nm_debug ("Device removed (hal udi is '%s').", udi );

	nm_remove_device_from_list (data, udi);
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
			nm_create_device_and_add_to_list (data, udi, iface, FALSE, DEVICE_TYPE_DONT_KNOW);
			g_free (iface);
		}
	}
}


/*
 * nm_hal_device_lost_capability
 *
 */
static void nm_hal_device_lost_capability (LibHalContext *ctx, const char *udi, const char *capability)
{
/*	nm_debug ("nm_hal_device_lost_capability() called with udi = %s, capability = %s", udi, capability );*/
}

/*
 * nm_add_initial_devices
 *
 * Add all devices that hal knows about right now (ie not hotplug devices)
 *
 */
static void nm_add_initial_devices (NMData *data)
{
	char		**net_devices;
	int		  num_net_devices;
	int		  i;

        DBusError error;

	g_return_if_fail (data != NULL);
	
        dbus_error_init (&error);
	/* Grab a list of network devices */
	net_devices = libhal_find_device_by_capability (data->hal_ctx, "net", &num_net_devices, &error);
        if (dbus_error_is_set (&error))
          {
            nm_warning ("could not find existing networking devices: %s", 
	    		error.message);
            dbus_error_free (&error);
          }

	if (net_devices)
	{
		for (i = 0; i < num_net_devices; i++)
		{
			char *iface;

			if ((iface = nm_get_device_interface_from_hal (data->hal_ctx, net_devices[i])))
			{
				nm_create_device_and_add_to_list (data, net_devices[i], iface, FALSE, DEVICE_TYPE_DONT_KNOW);
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
	g_source_set_callback (source, nm_state_change_signal_broadcast, data, NULL);
	id = g_source_attach (source, data->main_context);
	g_source_unref (source);
}


/*
 * nm_poll_and_update_wireless_link_state
 *
 * Called every 2s to poll wireless cards and determine if they have a link
 * or not.
 *
 */
gboolean nm_poll_and_update_wireless_link_state (NMData *data)
{
	GSList	*elt;

	g_return_val_if_fail (data != NULL, TRUE);

	if ((data->wireless_enabled == FALSE) || (data->asleep == TRUE))
		return (TRUE);

	/* Attempt to acquire mutex for device list iteration.
	 * If the acquire fails, just ignore the device deletion entirely.
	 */
	if (!nm_try_acquire_mutex (data->dev_list_mutex, __FUNCTION__))
	{
		nm_warning ("could not acquire device list mutex." );
		return TRUE;
	}

	for (elt = data->dev_list; elt; elt = g_slist_next (elt))
	{
		NMDevice	*dev = (NMDevice *)(elt->data);

		if (dev && nm_device_is_wireless (dev))
		{
			if (!nm_device_is_up (dev))
				nm_device_bring_up (dev);

			nm_device_update_link_state (dev);

			/* Is this the currently selected device?
			 * If so, let's make sure it's still has
			 * an active link. If it lost the link,
			 * find a better access point.
			 */
			if (    (dev == data->active_device)
				&& !nm_device_has_active_link (dev))
			{
				if (    nm_device_get_supports_wireless_scan (dev)
					&& !data->forcing_device
					&& data->state_modified_idle_id == 0)	
				{
					nm_device_update_best_ap (dev);
				}
				else
				{
					if (    !nm_device_is_activating (dev)
						&& !data->forcing_device
						&& data->state_modified_idle_id == 0)	
						nm_device_update_best_ap (dev);
				}
			}
		}
	}
	nm_unlock_mutex (data->dev_list_mutex, __FUNCTION__);
	
	return (TRUE);
}

/*
 * nm_data_new
 *
 * Create data structure used in callbacks from libhal.
 *
 */
static NMData *nm_data_new (gboolean enable_test_devices)
{
	struct sigaction action;
	sigset_t block_mask;
	NMData *data;
	GSource *iosource;
	
	data = g_new0 (NMData, 1);

	data->main_context = g_main_context_new ();
	data->main_loop = g_main_loop_new (data->main_context, FALSE);

	if (pipe(data->sigterm_pipe) < 0)
	{
		nm_error ("Couldn't create pipe: %s", g_strerror (errno));
		exit (EXIT_FAILURE);
	}

	data->sigterm_iochannel = g_io_channel_unix_new (data->sigterm_pipe[0]);
	iosource = g_io_create_watch (data->sigterm_iochannel, G_IO_IN | G_IO_ERR);
	g_source_set_callback (iosource, (GSourceFunc) sigterm_pipe_handler, data, NULL);
	g_source_attach (iosource, data->main_context);
	g_source_unref (iosource);

	action.sa_handler = sigterm_handler;
	sigemptyset (&block_mask);
	action.sa_mask = block_mask;
	action.sa_flags = 0;
	sigaction (SIGINT, &action, NULL);
	sigaction (SIGTERM, &action, NULL);

	data->named = nm_named_manager_new (data->main_context);

	/* Initialize the device list mutex to protect additions/deletions to it. */
	data->dev_list_mutex = g_mutex_new ();
	if (!data->dev_list_mutex)
	{
		nm_data_free (data);
		nm_warning ("could not initialize data structure locks.");
		return (NULL);
	}
	nm_register_mutex_desc (data->dev_list_mutex, "Device List Mutex");

	/* Initialize the access point lists */
	data->allowed_ap_list = nm_ap_list_new (NETWORK_TYPE_ALLOWED);
	data->invalid_ap_list = nm_ap_list_new (NETWORK_TYPE_INVALID);
	if (!data->allowed_ap_list || !data->invalid_ap_list)
	{
		nm_data_free (data);
		nm_warning ("could not create access point lists.");
		return (NULL);
	}

	data->state_modified_idle_id = 0;

	data->enable_test_devices = enable_test_devices;

	data->scanning_enabled = TRUE;
	data->wireless_enabled = TRUE;

	nm_policy_schedule_state_update (data);

	return (data);	
}


/*
 * nm_data_free
 *
 *   Free data structure used in callbacks.
 *
 */
static void nm_data_free (NMData *data)
{
	g_return_if_fail (data != NULL);

	nm_vpn_manager_dispose (data->vpn_manager);
	g_object_unref (data->named);

	nm_device_unref (data->active_device);

	g_slist_foreach (data->dev_list, (GFunc) nm_device_unref, NULL);
	g_slist_free (data->dev_list);

	g_mutex_free (data->dev_list_mutex);

	nm_ap_list_unref (data->allowed_ap_list);
	nm_ap_list_unref (data->invalid_ap_list);

	g_main_loop_unref (data->main_loop);
	g_main_context_unref (data->main_context);

	g_io_channel_unref(data->sigterm_iochannel);

	memset (data, 0, sizeof (NMData));
}

static void sigterm_handler (int signum)
{
        int ignore;

	/* FIXME: This line is probably not a great 
	 * thing to have in a signal handler
	 */
	nm_info ("Caught SIGINT/SIGTERM");

	ignore = write (nm_data->sigterm_pipe[1], "X", 1);
}

static gboolean sigterm_pipe_handler (GIOChannel *src, GIOCondition condition, gpointer user_data)
{
	NMData *data = user_data;

	nm_info ("Caught terminiation signal");
	if (data->active_device)
		nm_device_deactivate (data->active_device, FALSE);
	g_main_loop_quit (data->main_loop);
	return FALSE;
}

/*
 * nm_print_usage
 *
 * Prints program usage.
 *
 */
static void nm_print_usage (void)
{
	fprintf (stderr, "\n" "usage : NetworkManager [--no-daemon] [--help]\n");
	fprintf (stderr,
		"\n"
		"        --no-daemon             Don't become a daemon\n"
		"        --enable-test-devices   Allow dummy devices to be created via DBUS methods [DEBUG]\n"
		"        --help                  Show this information and exit\n"
		"\n"
		"NetworkManager monitors all network connections and automatically\n"
		"chooses the best connection to use.  It also allows the user to\n"
		"specify wireless access points which wireless cards in the computer\n"
		"should associate with.\n"
		"\n");
}

static void
nm_monitor_wireless_link_state (NMData *data)
{
	GSource *link_source;
	link_source = g_timeout_source_new (NM_WIRELESS_LINK_STATE_POLL_INTERVAL);
	g_source_set_callback (link_source, 
			       (GSourceFunc) nm_poll_and_update_wireless_link_state, 
			       nm_data, NULL);
	g_source_attach (link_source, nm_data->main_context);
	g_source_unref (link_source);
}

static void
nm_wired_link_activated (NmNetlinkMonitor *monitor,
			 const gchar 	  *interface_name,
			 NMData 	  *data)
{
	if (nm_try_acquire_mutex (data->dev_list_mutex, __FUNCTION__))
	{
		NMDevice *dev = nm_get_device_by_iface (data, interface_name);

		/* Don't do anything if we already have a link */
		if (    (dev != NULL)
			&& nm_device_is_wired (dev)
			&& !nm_device_has_active_link (dev))
		{
			nm_device_set_link_active (dev, TRUE);

			/* If a network cable just got plugged in, force-switch from a wireless
			 * to a wired connection.
			 */
			if (nm_device_has_active_link (dev)
				&& data->active_device
				&& data->active_device_locked
				&& nm_device_is_wireless (data->active_device))
			{
				data->active_device_locked = FALSE;
				nm_policy_schedule_state_update (data);
			}
		}
		nm_unlock_mutex (data->dev_list_mutex, __FUNCTION__);
	}
}

static void
nm_wired_link_deactivated (NmNetlinkMonitor *monitor,
			   const gchar 	  *interface_name,
			   NMData 	  *data)
{
	if (nm_try_acquire_mutex (data->dev_list_mutex, __FUNCTION__))
	{
		NMDevice *dev = nm_get_device_by_iface (data, interface_name);

		if ((dev != NULL) && nm_device_is_wired (dev))
			nm_device_set_link_active (dev, FALSE);
		nm_unlock_mutex (data->dev_list_mutex, __FUNCTION__);
	}
}

static void
nm_error_monitoring_wired_link_state (NmNetlinkMonitor *monitor,
				      GError 	       *error,
				      NMData	       *data)
{
	/* FIXME: Try to handle the error instead of just printing it.
	 */
	nm_warning ("error monitoring wired ethernet link state: %s\n",
		    error->message);
}

static void
nm_monitor_wired_link_state (NMData *data)
{
	GError *error;
	NmNetlinkMonitor *monitor;

	monitor = nm_netlink_monitor_new ();
	
	error = NULL;
	nm_netlink_monitor_open_connection (monitor, &error);

	if (error != NULL)
	{
		nm_warning ("could not monitor wired ethernet devices: %s",
			    error->message);
		g_error_free (error);
		g_object_unref (monitor);
		return;
	}

	g_signal_connect (G_OBJECT (monitor), "interface-connected",
			  G_CALLBACK (nm_wired_link_activated), data);

	g_signal_connect (G_OBJECT (monitor), "interface-disconnected",
			  G_CALLBACK (nm_wired_link_deactivated), data);

	g_signal_connect (G_OBJECT (monitor), "error",
			  G_CALLBACK (nm_error_monitoring_wired_link_state),
			  data);

	nm_netlink_monitor_attach (monitor, data->main_context);

	/* Request initial status of cards
	 */
	nm_netlink_monitor_request_status (monitor, NULL);

	data->netlink_monitor = monitor;
}

static void
nm_info_handler (const gchar	*log_domain,
		GLogLevelFlags	 log_level,
		const gchar	*message,
		gboolean 	 is_daemon)
{
	int syslog_priority;	

	switch (log_level)
	{
		case G_LOG_LEVEL_ERROR:
			syslog_priority = LOG_CRIT;
		break;

		case G_LOG_LEVEL_CRITICAL:
			syslog_priority = LOG_ERR;
		break;

		case G_LOG_LEVEL_WARNING:
			syslog_priority = LOG_WARNING;
		break;

		case G_LOG_LEVEL_MESSAGE:
			syslog_priority = LOG_NOTICE;

		case G_LOG_LEVEL_DEBUG:
			syslog_priority = LOG_DEBUG;
		break;

		case G_LOG_LEVEL_INFO:
		default:
			syslog_priority = LOG_INFO;
		break;
	}

	syslog (syslog_priority, message);
}

static void
nm_set_up_log_handlers (gboolean become_daemon)
{
	if (become_daemon)
		openlog (G_LOG_DOMAIN, LOG_CONS, LOG_DAEMON);
	else
		openlog (G_LOG_DOMAIN, LOG_CONS | LOG_PERROR, LOG_USER);

	g_log_set_handler (G_LOG_DOMAIN, 
	                   G_LOG_LEVEL_MASK,
			   (GLogFunc) nm_info_handler,
			   GINT_TO_POINTER (become_daemon));
}

/*
 * main
 *
 */
int main( int argc, char *argv[] )
{
	LibHalContext	*ctx = NULL;
	guint		 link_source_id;
	GSource		*link_source;
	gboolean		 become_daemon = TRUE;
	gboolean		 enable_test_devices = FALSE;
	GError		*error = NULL;
	DBusError 	dbus_error;

	
	if ((int)getuid() != 0)
	{
		g_printerr ("You must be root to run NetworkManager!\n");
		return (EXIT_FAILURE);
	}

	/* Parse options */
	while (1)
	{
		int c;
		int option_index = 0;
		const char *opt;

		static struct option options[] = {
			{"no-daemon",			0, NULL, 0},
			{"enable-test-devices",	0, NULL, 0},
			{"help",				0, NULL, 0},
			{NULL,				0, NULL, 0}
		};

		c = getopt_long (argc, argv, "", options, &option_index);
		if (c == -1)
			break;

		switch (c)
		{
			case 0:
				opt = options[option_index].name;
				if (strcmp (opt, "help") == 0)
				{
					nm_print_usage ();
					exit (EXIT_SUCCESS);
				}
				else if (strcmp (opt, "no-daemon") == 0)
					become_daemon = FALSE;
				else if (strcmp (opt, "enable-test-devices") == 0)
					enable_test_devices = TRUE;
				break;

			default:
				nm_print_usage ();
				exit (EXIT_FAILURE);
				break;
		}
	}

	if (become_daemon && daemon (0, 0) < 0)
	{
		int saved_errno;

		saved_errno = errno;
		nm_error ("NetworkManager could not daemonize: %s [error %u]",
			  g_strerror (saved_errno), saved_errno);
		exit (EXIT_FAILURE);
	}

	g_type_init ();
	if (!g_thread_supported ())
		g_thread_init (NULL);
	dbus_g_thread_init ();

	nm_set_up_log_handlers (become_daemon);
	nm_info ("starting...");

	nm_system_init();

	/* Load all network device kernel modules.
	 * NOTE: this hack is temporary until device modules get loaded
	 * on startup by something else.  The problem is that unless
	 * the module is loaded, HAL doesn't know its a network device,
	 * and therefore can't tell us about it.
	 */
	nm_system_load_device_modules ();

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
		nm_data_free (nm_data);
		exit (EXIT_FAILURE);
	}

	nm_data->vpn_manager = nm_vpn_manager_new (nm_data);

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

	/* Initialize libhal.  We get a connection to the hal daemon here. */
	if ((ctx = libhal_ctx_new()) == NULL)
	{
		nm_error ("libhal_ctx_new() failed, exiting...");
		exit (EXIT_FAILURE);
	}

	nm_hal_mainloop_integration (ctx, nm_data->dbus_connection); 

	libhal_ctx_set_dbus_connection (ctx, nm_data->dbus_connection);

	dbus_error_init (&dbus_error);
	if(!libhal_ctx_init (ctx, &dbus_error)) {
		nm_error ("libhal_ctx_init() failed: %s\n"
			  "Make sure the hal daemon is running?", 
			  dbus_error.message);

		dbus_error_free (&dbus_error);
		exit (EXIT_FAILURE);
	}

	nm_data->hal_ctx = ctx;
	libhal_ctx_set_user_data (nm_data->hal_ctx, nm_data);

	libhal_ctx_set_device_added (ctx,
				     nm_hal_device_added);
	libhal_ctx_set_device_removed (ctx,
		  		       nm_hal_device_removed);
	libhal_ctx_set_device_new_capability (ctx,
					     nm_hal_device_new_capability);
	libhal_ctx_set_device_lost_capability (ctx,
		  			       nm_hal_device_lost_capability);

	libhal_device_property_watch_all (nm_data->hal_ctx, &dbus_error);

	if (dbus_error_is_set (&dbus_error))
	{
		nm_error ("libhal_device_property_watch_all(): %s",
			  dbus_error.message);
		dbus_error_free (&dbus_error);
		exit (EXIT_FAILURE);
	}

	/* Grab network devices that are already present and add them to our
	 * list */
	nm_add_initial_devices (nm_data);

	/* We run dhclient when we need to, and we don't want any stray ones
	 * lying around upon launch.
	 */
	nm_system_kill_all_dhcp_daemons ();

	/* Bring up the loopback interface. */
	nm_system_enable_loopback ();

	/* Create watch functions that monitor cards for link status. */
	nm_monitor_wireless_link_state (nm_data);
	nm_monitor_wired_link_state (nm_data);

	if (!nm_named_manager_start (nm_data->named, &error))
	{
		nm_error ("couldn't initialize nameserver: %s",
			  error->message);
		exit (EXIT_FAILURE);
	}

	nm_schedule_state_change_signal_broadcast (nm_data);

	/* Wheeee!!! */
	g_main_loop_run (nm_data->main_loop);

	nm_print_open_socks ();

	/* Cleanup */
	libhal_ctx_shutdown (nm_data->hal_ctx, &dbus_error);
	if (dbus_error_is_set (&dbus_error)) {
		nm_warning ("libhal shutdown failed - %s", 
			    dbus_error.message);
		dbus_error_free (&dbus_error);
	}
	libhal_ctx_free (nm_data->hal_ctx);

	nm_data_free (nm_data);

	exit (0);
}
