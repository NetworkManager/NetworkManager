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
#include <hal/libhal.h>
#include <getopt.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "NetworkManager.h"
#include "NetworkManagerUtils.h"
#include "NetworkManagerDevice.h"
#include "NetworkManagerPolicy.h"
#include "NetworkManagerWireless.h"
#include "NetworkManagerDbus.h"
#include "NetworkManagerAP.h"
#include "NetworkManagerAPList.h"


/*
 * Globals
 */
static GMainLoop	*loop  = NULL;
static NMData		*nm_data = NULL;
gboolean			 debug = TRUE;
static gboolean	 quit = FALSE;
extern gboolean	 allowed_ap_worker_exit;

static void nm_data_free (NMData *data);


/*
 * nm_create_device_and_add_to_list
 *
 * Create a new NLM device and add it to our device list.
 *
 * Returns:		newly allocated device on success
 *				NULL on failure
 */
NMDevice * nm_create_device_and_add_to_list (NMData *data, const char *udi)
{
	NMDevice	*dev = NULL;
	gboolean	 success = FALSE;

	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (udi  != NULL, NULL);

	if (hal_device_property_exists (data->hal_ctx, udi, "net.interface"))
	{
		gchar	*iface_name = hal_device_get_property_string (data->hal_ctx, udi, "net.interface");

		/* Make sure the device is not already in the device list */
		if ((dev = nm_get_device_by_iface (data, iface_name)))
		{
			hal_free_string (iface_name);
			return (NULL);
		}

		if ((dev = nm_device_new (iface_name, data)))
		{

			/* Build up the device structure */
			nm_device_set_udi (dev, udi);

			/* Attempt to acquire mutex for device list addition.  If acquire fails,
			 * just ignore the device addition entirely.
			 */
			if (nm_try_acquire_mutex (data->dev_list_mutex, __FUNCTION__))
			{
				NM_DEBUG_PRINT_2( "nm_create_device_and_add_to_list(): adding device '%s' (%s)\n",
					nm_device_get_iface (dev), nm_device_is_wireless (dev) ? "wireless" : "wired" );

				data->dev_list = g_slist_append (data->dev_list, dev);
				nm_device_deactivate (dev, TRUE);
				success = TRUE;

				nm_unlock_mutex (data->dev_list_mutex, __FUNCTION__);
			} else NM_DEBUG_PRINT( "nm_create_device_and_add_to_list() could not acquire device list mutex.\n" );
		} else NM_DEBUG_PRINT( "nm_create_device_and_add_to_list() could not allocate device data.\n" );

		hal_free_string (iface_name);

		if (success)
			nm_data_set_state_modified (data, TRUE);
		else
		{
			/* If we couldn't add the device to our list, free its data. */
			nm_device_unref (dev);
			dev = NULL;
		}
	}

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
	GSList	*element;

	g_return_if_fail (data != NULL);
	g_return_if_fail (udi != NULL);

	/* Attempt to acquire mutex for device list deletion.  If acquire fails,
	 * just ignore the device deletion entirely.
	 */
	if (nm_try_acquire_mutex (data->dev_list_mutex, __FUNCTION__))
	{
		element = data->dev_list;
		while (element)
		{
			NMDevice	*dev = (NMDevice *)(element->data);

			if (dev)
			{
				if (nm_null_safe_strcmp (nm_device_get_udi (dev), udi) == 0)
				{
					if (data->active_device && (dev == data->active_device))
						data->active_device = NULL;

					nm_device_activation_cancel (dev);
					nm_device_unref (dev);

					/* Remove the device entry from the device list and free its data */
					data->dev_list = g_slist_remove_link (data->dev_list, element);
					nm_device_unref (element->data);
					g_slist_free (element);
					nm_data_set_state_modified (data, TRUE);

					break;
				}
			}
			element = g_slist_next (element);
		}
		nm_unlock_mutex (data->dev_list_mutex, __FUNCTION__);
	} else NM_DEBUG_PRINT( "nm_remove_device_from_list() could not acquire device list mutex.\n" );
}


/*
 * nm_hal_mainloop_integration
 *
 */
static void nm_hal_mainloop_integration (LibHalContext *ctx, DBusConnection * dbus_connection)
{
	dbus_connection_setup_with_g_main (dbus_connection, NULL);
}


/*
 * nm_hal_device_added
 *
 */
static void nm_hal_device_added (LibHalContext *ctx, const char *udi)
{
	NMData		*data = (NMData *)hal_ctx_get_user_data (ctx);

	g_return_if_fail (data != NULL);

	NM_DEBUG_PRINT_1( "nm_hal_device_added() called with udi = %s\n", udi );

	/* Sometimes the device's properties (like net.interface) are not set up yet,
	 * so this call will fail, and it will actually be added when hal sets the device's
	 * capabilities a bit later on.
	 */
	nm_create_device_and_add_to_list (data, udi);
}


/*
 * nm_hal_device_removed
 *
 */
static void nm_hal_device_removed (LibHalContext *ctx, const char *udi)
{
	NMData	*data = (NMData *)hal_ctx_get_user_data (ctx);

	g_return_if_fail (data != NULL);

	NM_DEBUG_PRINT_1( "nm_hal_device_removed() called with udi = %s\n", udi );

	nm_remove_device_from_list (data, udi);
}


/*
 * nm_hal_device_new_capability
 *
 */
static void nm_hal_device_new_capability (LibHalContext *ctx, const char *udi, const char *capability)
{
	NMData	*data = (NMData *)hal_ctx_get_user_data (ctx);

	g_return_if_fail (data != NULL);

	NM_DEBUG_PRINT_2( "nm_hal_device_new_capability() called with udi = %s, capability = %s\n", udi, capability );

	if (capability && (strcmp (capability, "net.ethernet") == 0))
		nm_create_device_and_add_to_list (data, udi);
}


/*
 * nm_hal_device_lost_capability
 *
 */
static void nm_hal_device_lost_capability (LibHalContext *ctx, const char *udi, const char *capability)
{
	NM_DEBUG_PRINT_2( "nm_hal_device_lost_capability() called with udi = %s, capability = %s\n", udi, capability );
}


/*
 * nm_hal_device_property_modified
 *
 */
static void nm_hal_device_property_modified (LibHalContext *ctx, const char *udi, const char *key, dbus_bool_t is_removed, dbus_bool_t is_added)
{
/*
	NM_DEBUG_PRINT_4( "nm_hal_device_property_modified() called with udi = %s, key = %s, is_removed = %d, is_added = %d\n", udi, key, is_removed, is_added );
*/
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

	g_return_if_fail (data != NULL);
	
	/* Grab a list of network devices */
	net_devices = hal_find_device_by_capability (data->hal_ctx, "net.ethernet", &num_net_devices);
	if (net_devices)
	{
		for (i = 0; i < num_net_devices; i++)
			nm_create_device_and_add_to_list (data, net_devices[i]);
	}

	hal_free_string_array (net_devices);
}


/*
 * nm_link_state_monitor
 *
 * Called every 2s to poll cards and determine if they have a link
 * or not.
 *
 */
gboolean nm_link_state_monitor (gpointer user_data)
{
	NMData	*data = (NMData *)user_data;
	GSList	*element;

	g_return_val_if_fail (data != NULL, TRUE);

	/* Attempt to acquire mutex for device list iteration.
	 * If the acquire fails, just ignore the device deletion entirely.
	 */
	if (nm_try_acquire_mutex (data->dev_list_mutex, __FUNCTION__))
	{
		element = data->dev_list;
		while (element)
		{
			NMDevice	*dev = (NMDevice *)(element->data);

			if (dev)
			{
				/* Wired cards are always up and active, because otherwise we cannot do
				 * link detection on them.  A wireless card is only up if it's the active
				 * device, since we only do scanning and link detection on the active device
				 * anyway.
				 */
				switch (nm_device_get_type (dev))
				{
					case DEVICE_TYPE_WIRELESS_ETHERNET:
						if (dev != data->active_device)
						{
							if (nm_device_is_up (dev))
								nm_device_bring_down (dev);
						}
						else
							nm_device_update_link_active (dev, FALSE);						
						break;

					case DEVICE_TYPE_WIRED_ETHERNET:
						if (!nm_device_is_up (dev))
							nm_device_bring_up (dev);
						nm_device_update_link_active (dev, FALSE);
						break;

					default:
						break;
				}

				if (dev == data->active_device)
				{
					/* Check if the device's IP address has changed
					 * (ie dhcp lease renew/address change)
					 */
					nm_device_update_ip4_address (dev);
				}
			}

			element = g_slist_next (element);
		}

		nm_unlock_mutex (data->dev_list_mutex, __FUNCTION__);
	} else NM_DEBUG_PRINT( "nm_link_state_monitor() could not acquire device list mutex.\n" );
	
	return (TRUE);
}


/*
 * libhal callback function structure
 */
static LibHalFunctions hal_functions =
{
	nm_hal_mainloop_integration,
	nm_hal_device_added,
	nm_hal_device_removed,
	nm_hal_device_new_capability,
	nm_hal_device_lost_capability,
	nm_hal_device_property_modified,
	NULL
};


/*
 * nm_data_new
 *
 * Create data structure used in callbacks from libhal.
 *
 */
static NMData *nm_data_new (void)
{
	NMData *data;
	
	data = g_new0 (NMData, 1);
	if (!data)
	{
		NM_DEBUG_PRINT("Could not allocate our NetworkManager data... Not enough memory?\n");
		return (NULL);
	}

	/* Initialize the device list mutex to protect additions/deletions to it. */
	data->dev_list_mutex = g_mutex_new ();
	if (!data->dev_list_mutex)
	{
		nm_data_free (data);
		NM_DEBUG_PRINT("Could not create device list mutex.  Whacky shit going on?\n");
		return (NULL);
	}

	/* Initialize the state modified mutex. */
	data->state_modified_mutex = g_mutex_new ();
	if (!data->state_modified_mutex)
	{
		nm_data_free (data);
		NM_DEBUG_PRINT("Could not create state_modified mutex.  Whacky stuff going on?\n");
		return (NULL);
	}

	/* Initialize the access point lists */
	data->trusted_ap_list = nm_ap_list_new (NETWORK_TYPE_TRUSTED);
	data->preferred_ap_list = nm_ap_list_new (NETWORK_TYPE_PREFERRED);
	data->invalid_ap_list = nm_ap_list_new (NETWORK_TYPE_INVALID);

	if (!data->trusted_ap_list || !data->preferred_ap_list || !data->invalid_ap_list)
	{
		nm_data_free (data);
		NM_DEBUG_PRINT("Could not create access point lists.  Whacky stuff going on?\n");
		return (NULL);
	}

	data->state_modified = TRUE;

	return (data);	
}


/*
 * nm_data_dev_list_element_free
 *
 * Frees each member of the device list before the list is
 * disposed of. 
 *
 */
static void nm_data_dev_list_element_free (void *element, void *user_data)
{
	nm_device_unref (element);
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

	nm_device_unref (data->active_device);

	g_slist_foreach (data->dev_list, nm_data_dev_list_element_free, NULL);
	g_slist_free (data->dev_list);
	g_mutex_free (data->dev_list_mutex);

	nm_ap_list_unref (data->trusted_ap_list);
	nm_ap_list_unref (data->preferred_ap_list);
	nm_ap_list_unref (data->invalid_ap_list);

	memset (data, 0, sizeof (NMData));
}


/*
 * nm_data_set_state_modified
 *
 * Locked function to protect state modification changes.
 *
 */
void nm_data_set_state_modified (NMData *data, gboolean modified)
{
	g_return_if_fail (data != NULL);

	g_mutex_lock (data->state_modified_mutex);
	data->state_modified = modified;
	g_mutex_unlock (data->state_modified_mutex);
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
		"        --no-daemon    Become a daemon\n"
		"        --help         Show this information and exit\n"
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
	LibHalContext		*ctx = NULL;
	guint			 link_source;
	guint			 policy_source;
	guint			 wireless_scan_source;
	gboolean			 become_daemon = TRUE;

	/* Parse options */
	while (1)
	{
		int c;
		int option_index = 0;
		const char *opt;

		static struct option options[] = {
			{"no-daemon",	0, NULL, 0},
			{"help",		0, NULL, 0},
			{NULL,		0, NULL, 0}
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
				break;

			default:
				nm_print_usage ();
				exit (EXIT_FAILURE);
				break;
		}
	}

	if (become_daemon)
	{
		int child_pid;

		if (chdir ("/") < 0)
		{
			fprintf( stderr, "NetworkManager could not chdir to /.  errno=%d", errno);
			return (1);
		}

		child_pid = fork ();
		switch (child_pid)
		{
			case -1:
				fprintf( stderr, "NetworkManager could not daemonize.  errno = %d\n", errno );
				break;

			case 0:
				/* Child */
				break;

			default:
				exit (EXIT_SUCCESS);
				break;
		}
	}

	g_type_init ();
	if (!g_thread_supported ())
		g_thread_init (NULL);

	/* Initialize our instance data */
	nm_data = nm_data_new ();
	if (!nm_data)
	{
		NM_DEBUG_PRINT("nm_data_new() failed... Not enough memory?\n");
		exit (EXIT_FAILURE);
	}	

	/* Create our dbus service */
	nm_data->dbus_connection = nm_dbus_init (nm_data);
	if (!nm_data->dbus_connection)
	{
		hal_shutdown (nm_data->hal_ctx);
		nm_data_free (nm_data);
		exit (EXIT_FAILURE);
	}
	nm_data->info_daemon_avail = nm_dbus_is_info_daemon_running (nm_data->dbus_connection);
	nm_data->update_ap_lists = TRUE;

	/* Initialize libhal.  We get a connection to the hal daemon here. */
	if ((ctx = hal_initialize (&hal_functions, FALSE)) == NULL)
	{
		NM_DEBUG_PRINT("hal_initialize() failed, exiting...  Make sure the hal daemon is running?\n");
		exit (EXIT_FAILURE);
	}
	nm_data->hal_ctx = ctx;
	hal_ctx_set_user_data (nm_data->hal_ctx, nm_data);

	/* Grab network devices that are already present and add them to our list */
	nm_add_initial_devices (nm_data);

	/* Create a watch function that monitors cards for link status (hal doesn't do
	 * this for wireless cards yet).
	 */
	link_source = g_timeout_add (5000, nm_link_state_monitor, nm_data);

	/* Another watch function which handles networking state changes and applies
	 * the correct policy on a change.
	 */
	policy_source = g_timeout_add (500, nm_state_modification_monitor, nm_data);

	/* Keep a current list of access points */
	wireless_scan_source = g_timeout_add (10000, nm_wireless_scan_monitor, nm_data);

	/* Watch all devices that HAL knows about for state changes */
	hal_device_property_watch_all (nm_data->hal_ctx);

	/* We run dhclient when we need to, and we don't want any stray ones
	 * lying around upon launch.
	 */
	nm_spawn_process ("/usr/bin/killall dhclient");

	/* Wheeee!!! */
	loop = g_main_loop_new (NULL, FALSE);
	g_main_loop_run (loop);

	/* Kill the watch functions */
	g_source_remove (link_source);
	g_source_remove (policy_source);
	g_source_remove (wireless_scan_source);

	/* Cleanup */
	if (hal_shutdown (nm_data->hal_ctx) != 0)
		g_warning ("hal_shutdown() failed\n");

	nm_data_free (nm_data);

	return (0);
}
