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

#include <errno.h>
#include <glib.h>
#include <dbus/dbus-glib.h>
#include <libhal.h>
#include <iwlib.h>
#include <signal.h>
#include <string.h>

#include "NetworkManager.h"
#include "NetworkManagerMain.h"
#include "NetworkManagerDevice.h"
#include "NetworkManagerDevicePrivate.h"
#include "NetworkManagerUtils.h"
#include "NetworkManagerDbus.h"
#include "NetworkManagerWireless.h"
#include "NetworkManagerPolicy.h"
#include "NetworkManagerAPList.h"
#include "NetworkManagerSystem.h"
#include "NetworkManagerDHCP.h"

/* Local static prototypes */
static gpointer nm_device_worker (gpointer user_data);
static gboolean nm_device_activate (gpointer user_data);
static gboolean nm_device_activation_configure_ip (NMDevice *dev, gboolean do_only_autoip);
static gboolean nm_device_wireless_scan (gpointer user_data);
static gboolean supports_mii_carrier_detect (NMDevice *dev);
static gboolean supports_ethtool_carrier_detect (NMDevice *dev);
static gboolean nm_device_bring_up_wait (NMDevice *dev, gboolean cancelable);
static gboolean nm_device_activation_handle_cancel (NMDevice *dev);

typedef struct
{
	NMDevice					*dev;
	struct wireless_scan_head	 scan_head;
} NMWirelessScanResults;


/******************************************************/


/******************************************************/

/*
 * nm_device_test_wireless_extensions
 *
 * Test whether a given device is a wireless one or not.
 *
 */
static gboolean nm_device_test_wireless_extensions (NMDevice *dev)
{
	int		sk;
	int		err;
	char		ioctl_buf[64];
	
	g_return_val_if_fail (dev != NULL, FALSE);

	/* We obviously cannot probe test devices (since they don't
	 * actually exist in hardware).
	 */
	if (dev->test_device)
		return (FALSE);

	ioctl_buf[63] = 0;
	strncpy(ioctl_buf, nm_device_get_iface(dev), 63);

	sk = iw_sockets_open ();
	err = ioctl(sk, SIOCGIWNAME, ioctl_buf);
	close (sk);
	return (err == 0);
}


/*
 * nm_device_supports_wireless_scan
 *
 * Test whether a given device is a wireless one or not.
 *
 */
static gboolean nm_device_supports_wireless_scan (NMDevice *dev)
{
	int				sk;
	int				err;
	gboolean			can_scan = TRUE;
	wireless_scan_head	scan_data;
	
	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (dev->type == DEVICE_TYPE_WIRELESS_ETHERNET, FALSE);

	/* A test wireless device can always scan (we generate fake scan data for it) */
	if (dev->test_device)
		return (TRUE);
	
	sk = iw_sockets_open ();
	err = iw_scan (sk, (char *)nm_device_get_iface (dev), WIRELESS_EXT, &scan_data);
	nm_dispose_scan_results (scan_data.result);
	if ((err == -1) && (errno == EOPNOTSUPP))
		can_scan = FALSE;
	close (sk);
	return (can_scan);
}


/*
 * nm_get_device_by_udi
 *
 * Search through the device list for a device with a given UDI.
 *
 * NOTE: the caller MUST hold the device list mutex already to make
 * this routine thread-safe.
 *
 */
NMDevice *nm_get_device_by_udi (NMData *data, const char *udi)
{
	NMDevice	*dev = NULL;
	GSList	*elt;
	
	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (udi  != NULL, NULL);

	for (elt = data->dev_list; elt; elt = g_slist_next (elt))
	{
		dev = (NMDevice *)(elt->data);
		if (dev)
		{
			if (nm_null_safe_strcmp (nm_device_get_udi (dev), udi) == 0)
				break;
		}
	}

	return (dev);
}


/*
 * nm_get_device_by_iface
 *
 * Search through the device list for a device with a given iface.
 *
 * NOTE: the caller MUST hold the device list mutex already to make
 * this routine thread-safe.
 *
 */
NMDevice *nm_get_device_by_iface (NMData *data, const char *iface)
{
	NMDevice	*iter_dev = NULL;
	NMDevice	*found_dev = NULL;
	GSList	*elt;
	
	g_return_val_if_fail (data  != NULL, NULL);
	g_return_val_if_fail (iface != NULL, NULL);

	for (elt = data->dev_list; elt; elt = g_slist_next (elt))
	{
		iter_dev = (NMDevice *)(elt->data);
		if (iter_dev)
		{
			if (nm_null_safe_strcmp (nm_device_get_iface (iter_dev), iface) == 0)
			{
				found_dev = iter_dev;
				break;
			}
		}
	}

	return (found_dev);
}


/*****************************************************************************/
/* NMDevice object routines                                                  */
/*****************************************************************************/

/*
 * nm_device_new
 *
 * Creates and initializes the structure representation of an NM device.  For test
 * devices, a device type other than DEVICE_TYPE_DONT_KNOW must be specified, this
 * argument is ignored for real hardware devices since they are auto-probed.
 *
 */
NMDevice *nm_device_new (const char *iface, const char *udi, gboolean test_dev, NMDeviceType test_dev_type, NMData *app_data)
{
	NMDevice	*dev;
	GError	*error = NULL;
	char		*msg;

	g_return_val_if_fail (iface != NULL, NULL);
	g_return_val_if_fail (strlen (iface) > 0, NULL);
	g_return_val_if_fail (app_data != NULL, NULL);

	/* Test devices must have a valid type specified */
	if (test_dev && !(test_dev_type != DEVICE_TYPE_DONT_KNOW))
		return (NULL);

	/* Another check to make sure we don't create a test device unless
	 * test devices were enabled on the command line.
	 */
	if (!app_data->enable_test_devices && test_dev)
	{
		syslog (LOG_ERR, "nm_device_new(): attempt to create a test device, but test devices were not enabled"
					" on the command line.  Will not create the device.\n");
		return (NULL);
	}

	dev = g_malloc0 (sizeof (NMDevice));
	if (!dev)
	{
		syslog (LOG_ERR, "nm_device_new() could not allocate a new device...  Not enough memory?");
		return (NULL);
	}

	dev->refcount = 2; /* 1 for starters, and another 1 for the worker thread */
	dev->app_data = app_data;
	dev->iface = g_strdup (iface);
	dev->test_device = test_dev;
	nm_device_set_udi (dev, udi);

	/* Real hardware devices are probed for their type, test devices must have
	 * their type specified.
	 */
	if (test_dev)
		dev->type = test_dev_type;
	else
		dev->type = nm_device_test_wireless_extensions (dev) ?
						DEVICE_TYPE_WIRELESS_ETHERNET : DEVICE_TYPE_WIRED_ETHERNET;

	/* Device thread's main loop */
	dev->context = g_main_context_new ();
	dev->loop = g_main_loop_new (dev->context, FALSE);

	if (!dev->context || !dev->loop)
		goto err;

	/* Have to bring the device up before checking link status and other stuff */
	nm_device_bring_up_wait (dev, 0);

	/* Get driver support level */
	dev->driver_support_level = nm_get_driver_support_level (dev->app_data->hal_ctx, dev);

	/* Initialize wireless-specific options */
	if (nm_device_is_wireless (dev))
	{
		int					sk;
		NMDeviceWirelessOptions	*opts = &(dev->options.wireless);

		nm_device_set_mode (dev, NETWORK_MODE_INFRA);

		opts->scan_interval = 20;

		opts->scan_mutex = g_mutex_new ();
		opts->best_ap_mutex = g_mutex_new ();
		opts->ap_list = nm_ap_list_new (NETWORK_TYPE_DEVICE);
		if (!opts->scan_mutex || !opts->best_ap_mutex || !opts->ap_list)
			goto err;

		nm_register_mutex_desc (opts->scan_mutex, "Scan Mutex");
		nm_register_mutex_desc (opts->best_ap_mutex, "Best AP Mutex");

		opts->supports_wireless_scan = nm_device_supports_wireless_scan (dev);

		if ((sk = iw_sockets_open ()) >= 0)
		{
			iwrange	range;
			if (iw_get_range_info (sk, nm_device_get_iface (dev), &range) >= 0)
			{
				int i;

				opts->max_qual.qual = range.max_qual.qual;
				opts->max_qual.level = range.max_qual.level;
				opts->max_qual.noise = range.max_qual.noise;
				opts->max_qual.updated = range.max_qual.updated;

				opts->avg_qual.qual = range.avg_qual.qual;
				opts->avg_qual.level = range.avg_qual.level;
				opts->avg_qual.noise = range.avg_qual.noise;
				opts->avg_qual.updated = range.avg_qual.updated;

				opts->num_freqs = MIN (range.num_frequency, IW_MAX_FREQUENCIES);
				for (i = 0; i < opts->num_freqs; i++)
					opts->freqs[i] = iw_freq2float (&(range.freq[i]));
			}
			close (sk);
		}
	}
	else if (nm_device_is_wired (dev))
	{
		if (supports_ethtool_carrier_detect (dev) || supports_mii_carrier_detect (dev))
			dev->options.wired.has_carrier_detect = TRUE;
	}

	if (nm_device_get_driver_support_level (dev) != NM_DRIVER_UNSUPPORTED)
	{
		nm_device_update_link_active (dev);

		nm_device_update_ip4_address (dev);
		nm_device_update_hw_address (dev);

		/* Grab IP config data for this device from the system configuration files */
		nm_system_device_update_config_info (dev);
	}

	if (!g_thread_create (nm_device_worker, dev, FALSE, &error))
	{
		syslog (LOG_CRIT, "nm_device_new (): could not create device worker thread. (glib said: '%s')", error->message);
		g_error_free (error);
		goto err;
	}

	/* Block until our device thread has actually had a chance to start. */
	msg = g_strdup_printf ("%s: waiting for device's worker thread to start...", nm_device_get_iface (dev));
	nm_wait_for_completion (NM_COMPLETION_TRIES_INFINITY,
			G_USEC_PER_SEC / 20, nm_completion_boolean_test, NULL,
			&dev->worker_started, msg, LOG_INFO, 0);
	g_free (msg);
	syslog (LOG_ERR, "%s: device's worker thread started, continuing.\n", nm_device_get_iface (dev));

	return (dev);

err:
	/* Initial refcount is 2 */
	nm_device_unref (dev);
	nm_device_unref (dev);
	return NULL;
}


/*
 * Refcounting functions
 */
void nm_device_ref (NMDevice *dev)
{
	g_return_if_fail (dev != NULL);

	dev->refcount++;
}


/*
 * nm_device_unref
 *
 * Decreases the refcount on a device by 1, and if the refcount reaches 0,
 * deallocates memory used by the device.
 *
 * Returns:	FALSE if device was not deallocated
 *			TRUE if device was deallocated
 */
gboolean nm_device_unref (NMDevice *dev)
{
	gboolean	deleted = FALSE;

	g_return_val_if_fail (dev != NULL, TRUE);

	dev->refcount--;
	if (dev->refcount <= 0)
	{
		nm_device_worker_thread_stop (dev);
		nm_device_bring_down (dev);

		if (nm_device_is_wireless (dev))
		{
			nm_device_ap_list_clear (dev);

			g_mutex_free (dev->options.wireless.scan_mutex);
			if (dev->options.wireless.ap_list)
				nm_ap_list_unref (dev->options.wireless.ap_list);
			if (dev->options.wireless.best_ap)
				nm_ap_unref (dev->options.wireless.best_ap);
			g_mutex_free (dev->options.wireless.best_ap_mutex);
		}

		/* Get rid of DHCP state data */
		if (dev->dhcp_iface)
		{
			dhcp_interface_free (dev->dhcp_iface);
			dev->dhcp_iface = NULL;
		}

		g_free (dev->udi);
		g_free (dev->iface);
		memset (dev, 0, sizeof (NMDevice));
		g_free (dev);
		deleted = TRUE;
	}

	return deleted;
}


/*
 * nm_device_worker
 *
 * Main thread of the device.
 *
 */
static gpointer nm_device_worker (gpointer user_data)
{
	NMDevice *dev = (NMDevice *)user_data;

	if (!dev)
	{
		syslog (LOG_CRIT, "nm_device_worker(): received NULL device object, NetworkManager cannot continue.\n");
		exit (1);
	}

	/* Do an initial wireless scan */
	if (nm_device_is_wireless (dev))
	{
		GSource	*source = g_idle_source_new ();
		guint	 source_id = 0;

		g_source_set_callback (source, nm_device_wireless_scan, dev, NULL);
		source_id = g_source_attach (source, dev->context);
		g_source_unref (source);
	}

	dev->worker_started = TRUE;
	g_main_loop_run (dev->loop);

	/* Remove any DHCP timeouts that might have been running */
	if (nm_device_config_get_use_dhcp (dev))
		nm_device_dhcp_remove_timeouts (dev);

	g_main_loop_unref (dev->loop);
	g_main_context_unref (dev->context);

	dev->loop = NULL;
	dev->context = NULL;

	dev->worker_done = TRUE;
	nm_device_unref (dev);

	return NULL;
}


void nm_device_worker_thread_stop (NMDevice *dev)
{
	g_return_if_fail (dev != NULL);

	if (dev->loop)
		g_main_loop_quit (dev->loop);
	nm_wait_for_completion(NM_COMPLETION_TRIES_INFINITY, 300,
			nm_completion_boolean_test, NULL, &dev->worker_done,
			NULL, NULL, 0);
}


/*
 * nm_device_get_app_data
 *
 */
NMData *nm_device_get_app_data (const NMDevice *dev)
{
	g_return_val_if_fail (dev != NULL, FALSE);

	return (dev->app_data);
}


/*
 * Get/Set for "removed" flag
 */
gboolean nm_device_get_removed (const NMDevice *dev)
{
	g_return_val_if_fail (dev != NULL, TRUE);

	return (dev->removed);
}

void nm_device_set_removed (NMDevice *dev, const gboolean removed)
{
	g_return_if_fail (dev != NULL);

	dev->removed = removed;
}


/*
 * nm_device_open_sock
 *
 * Get a control socket for network operations.
 *
 */
int nm_device_open_sock (void)
{
	int	fd;

	/* Try to grab a control socket */
	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (fd >= 0)
	     return (fd);
	fd = socket(PF_PACKET, SOCK_DGRAM, 0);
	if (fd >= 0)
	     return (fd);
	fd = socket(PF_INET6, SOCK_DGRAM, 0);
	if (fd >= 0)
	     return (fd);

	syslog (LOG_ERR, "nm_device_open_sock () could not get network control socket.");
	return (-1);
}


/*
 * Return the amount of time we should wait for the device
 * to get a link, based on the # of frequencies it has to
 * scan.
 */
gint nm_device_get_association_pause_value (NMDevice *dev)
{
	g_return_val_if_fail (dev != NULL, -1);
	g_return_val_if_fail (nm_device_is_wireless (dev), -1);

	/* If the card supports more than 14 channels, we should probably wait
	 * around 10s so it can scan them all. After we set the ESSID on the card, the card
	 * has to scan all channels to find our requested AP (which can take a long time
	 * if it is an A/B/G chipset like the Atheros 5212, for example).
	 */
	if (dev->options.wireless.num_freqs > 14)
		return 8;
	else
		return 5;
}


/*
 * Get/set functions for UDI
 */
char * nm_device_get_udi (NMDevice *dev)
{
	g_return_val_if_fail (dev != NULL, NULL);

	return (dev->udi);
}

void nm_device_set_udi (NMDevice *dev, const char *udi)
{
	g_return_if_fail (dev != NULL);
	g_return_if_fail (udi != NULL);

	if (dev->udi)
		g_free (dev->udi);

	dev->udi = g_strdup (udi);
}


/*
 * Get/set functions for iface
 */
const char * nm_device_get_iface (NMDevice *dev)
{
	g_return_val_if_fail (dev != NULL, NULL);

	return (dev->iface);
}


/*
 * Get/set functions for type
 */
guint nm_device_get_type (NMDevice *dev)
{
	g_return_val_if_fail (dev != NULL, DEVICE_TYPE_DONT_KNOW);

	return (dev->type);
}

gboolean nm_device_is_wireless (NMDevice *dev)
{
	g_return_val_if_fail (dev != NULL, FALSE);

	return (dev->type == DEVICE_TYPE_WIRELESS_ETHERNET);
}

gboolean nm_device_is_wired (NMDevice *dev)
{
	g_return_val_if_fail (dev != NULL, FALSE);

	return (dev->type == DEVICE_TYPE_WIRED_ETHERNET);
}


/*
 * Accessor for driver support level
 */
NMDriverSupportLevel nm_device_get_driver_support_level (NMDevice *dev)
{
	g_return_val_if_fail (dev != NULL, NM_DRIVER_UNSUPPORTED);

	return (dev->driver_support_level);
}


/*
 * Get/set functions for link_active
 */
gboolean nm_device_get_link_active (NMDevice *dev)
{
	g_return_val_if_fail (dev != NULL, FALSE);

	return (dev->link_active);
}

void nm_device_set_link_active (NMDevice *dev, const gboolean link_active)
{
	g_return_if_fail (dev != NULL);

	dev->link_active = link_active;
}


/*
 * Get/set functions for now_scanning
 */
gboolean nm_device_get_now_scanning (NMDevice *dev)
{
	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (nm_device_is_wireless (dev), FALSE);

	return (dev->options.wireless.now_scanning);
}

void nm_device_set_now_scanning (NMDevice *dev, const gboolean now_scanning)
{
	gboolean	old_val;

	g_return_if_fail (dev != NULL);
	g_return_if_fail (nm_device_is_wireless (dev));

	old_val = nm_device_get_now_scanning (dev);
	dev->options.wireless.now_scanning = now_scanning;
	if (old_val != now_scanning)
		nm_dbus_schedule_device_status_change (dev, DEVICE_STATUS_CHANGE);
}


/*
 * Get function for supports_wireless_scan
 */
gboolean nm_device_get_supports_wireless_scan (NMDevice *dev)
{
	g_return_val_if_fail (dev != NULL, FALSE);

	if (!nm_device_is_wireless (dev))
		return (FALSE);

	return (dev->options.wireless.supports_wireless_scan);
}


/*
 * nm_device_get_supports_carrier_detect
 */
gboolean nm_device_get_supports_carrier_detect (NMDevice *dev)
{
	g_return_val_if_fail (dev != NULL, FALSE);

	if (!nm_device_is_wired (dev))
		return (FALSE);

	return (dev->options.wired.has_carrier_detect);
}

/*
 * nm_device_wireless_is_associated
 *
 * Figure out whether or not we're associated to an access point
 */
static gboolean nm_device_wireless_is_associated (NMDevice *dev)
{
	struct iwreq	wrq;
	int			sk;
	gboolean		associated = FALSE;

	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (dev->app_data != NULL, FALSE);

	/* Test devices have their link state set through DBUS */
	if (dev->test_device)
		return (nm_device_get_link_active (dev));

	if ((sk = iw_sockets_open ()) < 0)
		return (FALSE);

	/* Some cards, for example ipw2x00 cards, can short-circuit the MAC
	 * address check using this check on IWNAME.  Its faster.
	 */
	if (iw_get_ext (sk, nm_device_get_iface (dev), SIOCGIWNAME, &wrq) >= 0)
	{
		if (!strcmp(wrq.u.name, "unassociated"))
		{
			associated = FALSE;
			goto out;
		}
	}

	if (!associated)
	{
		/*
		 * For all other wireless cards, the best indicator of a "link" at this time
		 * seems to be whether the card has a valid access point MAC address.
		 * Is there a better way?  Some cards don't work too well with this check, ie
		 * Lucent WaveLAN.
		 */
		if (iw_get_ext (sk, nm_device_get_iface (dev), SIOCGIWAP, &wrq) >= 0)
			if (nm_ethernet_address_is_valid ((struct ether_addr *)(&(wrq.u.ap_addr.sa_data))))
				associated = TRUE;
	}

out:
	close (sk);

	return (associated);
}

/*
 * nm_device_wireless_link_active
 *
 * Gets the link state of a wireless device
 *
 */
static gboolean nm_device_wireless_link_active (NMDevice *dev)
{
	gboolean 		 link = FALSE;
	NMAccessPoint	*best_ap;

	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (dev->app_data != NULL, FALSE);

	/* Test devices have their link state set through DBUS */
	if (dev->test_device)
		return (nm_device_get_link_active (dev));

	if (!nm_device_wireless_is_associated (dev))
		return (FALSE);

	/* If we don't have a "best" ap, we can't logically have a valid link
	 * that we want to use.
	 */
	if ((best_ap = nm_device_get_best_ap (dev)))
	{
		if (!nm_device_need_ap_switch (dev))
			link = TRUE;
		nm_ap_unref (best_ap);
	}

	return (link);
}


/*
 * nm_device_wired_link_active
 *
 * 
 *
 */
static gboolean nm_device_wired_link_active (NMDevice *dev)
{
	gboolean	link = FALSE;

	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (nm_device_is_wired (dev) == TRUE, FALSE);
	g_return_val_if_fail (dev->app_data != NULL, FALSE);

	/* Test devices have their link state set through DBUS */
	if (dev->test_device)
		return (nm_device_get_link_active (dev));

	/* We say that non-carrier-detect devices always have a link, because
	 * they never get auto-selected by NM.  User has to force them on us,
	 * so we just hope the user knows whether or not the cable's plugged in.
	 */
	if (dev->options.wired.has_carrier_detect != TRUE)
		link = TRUE;
	else
	{
		/* Device has carrier detect, yay! */
		if (hal_device_property_exists (dev->app_data->hal_ctx, nm_device_get_udi (dev), "net.80203.link"))
			link = hal_device_get_property_bool (dev->app_data->hal_ctx, nm_device_get_udi (dev), "net.80203.link");
	}

	return (link);
}


/*
 * nm_device_update_link_active
 *
 * Updates the link state for a particular device.
 *
 */
void nm_device_update_link_active (NMDevice *dev)
{
	gboolean		link = FALSE;

	g_return_if_fail (dev != NULL);
	g_return_if_fail (dev->app_data != NULL);

	switch (nm_device_get_type (dev))
	{
		case DEVICE_TYPE_WIRELESS_ETHERNET:
			link = nm_device_wireless_link_active (dev);
			/* Update our current signal strength too */
			nm_device_update_signal_strength (dev);
			break;

		case DEVICE_TYPE_WIRED_ETHERNET:
			link = nm_device_wired_link_active (dev);
			break;

		default:
			link = nm_device_get_link_active (dev);	/* Can't get link info for this device, so don't change link status */
			break;
	}

	/* Update device link status and global state variable if the status changed */
	if (link != nm_device_get_link_active (dev))
	{
		nm_device_set_link_active (dev, link);
		nm_dbus_schedule_device_status_change (dev, DEVICE_STATUS_CHANGE);
		nm_policy_schedule_state_update (dev->app_data);
	}
}


/*
 * nm_device_get_essid
 *
 * If a device is wireless, return the essid that it is attempting
 * to use.
 *
 * Returns:	allocated string containing essid.  Must be freed by caller.
 *
 */
char * nm_device_get_essid (NMDevice *dev)
{
	int	sk;
	int	err;
	
	g_return_val_if_fail (dev != NULL, NULL);
	g_return_val_if_fail (nm_device_is_wireless (dev), NULL);

	/* Test devices return the essid of their "best" access point
	 * or if there is none, the contents of the cur_essid field.
	 */
	if (dev->test_device)
	{
		NMAccessPoint	*best_ap = nm_device_get_best_ap (dev);
		char			*essid = dev->options.wireless.cur_essid;

		/* Or, if we've got a best ap, use that ESSID instead */
		if (best_ap)
		{
			essid = nm_ap_get_essid (best_ap);
			nm_ap_unref (best_ap);
		}
		return (essid);
	}
	
	sk = iw_sockets_open ();
	if (sk >= 0)
	{
		wireless_config	info;

		err = iw_get_basic_config(sk, nm_device_get_iface (dev), &info);
		if (err >= 0)
		{
			if (dev->options.wireless.cur_essid)
				g_free (dev->options.wireless.cur_essid);
			dev->options.wireless.cur_essid = g_strdup (info.essid);
		}
		else
			syslog (LOG_ERR, "nm_device_get_essid(): error getting ESSID for device %s.  errno = %d", nm_device_get_iface (dev), errno);

		close (sk);
	}

	return (dev->options.wireless.cur_essid);
}


/*
 * nm_device_set_essid
 *
 * If a device is wireless, set the essid that it should use.
 */
void nm_device_set_essid (NMDevice *dev, const char *essid)
{
	int				sk;
	int				err;
	struct iwreq		wreq;
	unsigned char		safe_essid[IW_ESSID_MAX_SIZE + 1] = "\0";
	
	g_return_if_fail (dev != NULL);
	g_return_if_fail (nm_device_is_wireless (dev));

	/* Test devices directly set cur_essid */
	if (dev->test_device)
	{
		if (dev->options.wireless.cur_essid)
			g_free (dev->options.wireless.cur_essid);
		dev->options.wireless.cur_essid = g_strdup (essid);
		return;
	}

	/* Make sure the essid we get passed is a valid size */
	if (!essid)
		safe_essid[0] = '\0';
	else
	{
		strncpy (safe_essid, essid, IW_ESSID_MAX_SIZE);
		safe_essid[IW_ESSID_MAX_SIZE] = '\0';
	}

	sk = iw_sockets_open ();
	if (sk >= 0)
	{
		wreq.u.essid.pointer = (caddr_t) safe_essid;
		wreq.u.essid.length	 = strlen (safe_essid) + 1;
		wreq.u.essid.flags	 = 1;	/* Enable essid on card */
	
		err = iw_set_ext (sk, nm_device_get_iface (dev), SIOCSIWESSID, &wreq);
		if (err == -1)
			syslog (LOG_ERR, "nm_device_set_essid(): error setting ESSID '%s' for device %s.  errno = %d", safe_essid, nm_device_get_iface (dev), errno);

		close (sk);
	}
}


/*
 * nm_device_get_frequency
 *
 * For wireless devices, get the frequency we broadcast/receive on.
 *
 */
double nm_device_get_frequency (NMDevice *dev)
{
	int		sk;
	int		err;
	double	freq = 0;

	g_return_val_if_fail (dev != NULL, 0);
	g_return_val_if_fail (nm_device_is_wireless (dev), 0);

	/* Test devices don't really have a frequency, they always succeed */
	if (dev->test_device)
		return 703000000;

	sk = iw_sockets_open ();
	if (sk >= 0)
	{
		struct iwreq		wrq;

		err = iw_set_ext (sk, nm_device_get_iface (dev), SIOCGIWFREQ, &wrq);
		if (err >= 0)
			freq = iw_freq2float (&wrq.u.freq);
		if (err == -1)
			syslog (LOG_ERR, "nm_device_get_frequency(): error getting frequency for device %s.  errno = %d", nm_device_get_iface (dev), errno);

		close (sk);
	}
	return (freq);
}


/*
 * nm_device_set_frequency
 *
 * For wireless devices, set the frequency to broadcast/receive on.
 * A frequency <= 0 means "auto".
 *
 */
void nm_device_set_frequency (NMDevice *dev, const double freq)
{
	int				sk;
	int				err;
	
	/* HACK FOR NOW */
	if (freq <= 0)
		return;

	g_return_if_fail (dev != NULL);
	g_return_if_fail (nm_device_is_wireless (dev));

	/* Test devices don't really have a frequency, they always succeed */
	if (dev->test_device)
		return;

	if (nm_device_get_frequency (dev) == freq)
		return;

	sk = iw_sockets_open ();
	if (sk >= 0)
	{
		struct iwreq		wrq;

		if (freq <= 0)
		{
			/* Auto */
			/* People like to make things hard for us.  Even though iwlib/iwconfig say
			 * that wrq.u.freq.m should be -1 for "auto" mode, nobody actually supports
			 * that.  Madwifi actually uses "0" to mean "auto".  So, we'll try 0 first
			 * and if that doesn't work, fall back to the iwconfig method and use -1.
			 *
			 * As a further note, it appears that Atheros/Madwifi cards can't go back to
			 * any-channel operation once you force set the channel on them.  For example,
			 * if you set a prism54 card to a specific channel, but then set the ESSID to
			 * something else later, it will scan for the ESSID and switch channels just fine.
			 * Atheros cards, however, just stay at the channel you previously set and don't
			 * budge, no matter what you do to them, until you tell them to go back to
			 * any-channel operation.
			 */
			wrq.u.freq.m = 0;
			wrq.u.freq.e = 0;
			wrq.u.freq.flags = 0;
		}
		else
		{
			/* Fixed */
			wrq.u.freq.flags = IW_FREQ_FIXED;
			iw_float2freq (freq, &wrq.u.freq);
		}
		err = iw_set_ext (sk, nm_device_get_iface (dev), SIOCSIWFREQ, &wrq);
		if (err == -1)
		{
			gboolean	success = FALSE;
			if ((freq <= 0) && ((errno == EINVAL) || (errno == EOPNOTSUPP)))
			{
				/* Ok, try "auto" the iwconfig way if the Atheros way didn't work */
				wrq.u.freq.m = -1;
				wrq.u.freq.e = 0;
				wrq.u.freq.flags = 0;
				if (iw_set_ext (sk, nm_device_get_iface (dev), SIOCSIWFREQ, &wrq) != -1)
					success = TRUE;
			}
		}

		close (sk);
	}
}


/*
 * nm_device_get_bitrate
 *
 * For wireless devices, get the bitrate to broadcast/receive at.
 * Returned value is rate in KHz.
 *
 */
int nm_device_get_bitrate (NMDevice *dev)
{
	int				sk;
	int				err = -1;
	struct iwreq		wrq;
	
	g_return_val_if_fail (dev != NULL, 0);
	g_return_val_if_fail (nm_device_is_wireless (dev), 0);

	/* Test devices don't really have a bitrate, they always succeed */
	if (dev->test_device)
		return 11;

	sk = iw_sockets_open ();
	if (sk >= 0)
	{
		err = iw_set_ext (sk, nm_device_get_iface (dev), SIOCGIWRATE, &wrq);
		close (sk);
	}

	return ((err >= 0) ? wrq.u.bitrate.value / 1000 : 0);
}


/*
 * nm_device_set_bitrate
 *
 * For wireless devices, set the bitrate to broadcast/receive at.
 * Rate argument should be in Mbps (mega-bits per second), or 0 for automatic.
 *
 */
void nm_device_set_bitrate (NMDevice *dev, const int Mbps)
{
	int				sk;
	
	g_return_if_fail (dev != NULL);
	g_return_if_fail (nm_device_is_wireless (dev));

	/* Test devices don't really have a bitrate, they always succeed */
	if (dev->test_device)
		return;

	if (nm_device_get_bitrate (dev) == Mbps)
		return;

	sk = iw_sockets_open ();
	if (sk >= 0)
	{
		struct iwreq		wrq;

		if (Mbps != 0)
		{
			wrq.u.bitrate.value = Mbps * 1000;
			wrq.u.bitrate.fixed = 1;
		}
		else
		{
			/* Auto bitrate */
			wrq.u.bitrate.value = -1;
			wrq.u.bitrate.fixed = 0;
		}
		/* Silently fail as not all drivers support setting bitrate yet (ipw2x00 for example) */
		iw_set_ext (sk, nm_device_get_iface (dev), SIOCSIWRATE, &wrq);

		close (sk);
	}
}


/*
 * nm_device_get_ap_address
 *
 * If a device is wireless, get the access point's ethernet address
 * that the card is associated with.
 */
void nm_device_get_ap_address (NMDevice *dev, struct ether_addr *addr)
{
	int			iwlib_socket;
	struct iwreq	wrq;

	g_return_if_fail (dev != NULL);
	g_return_if_fail (addr != NULL);
	g_return_if_fail (nm_device_is_wireless (dev));

	/* Test devices return an invalid address when there's no link,
	 * and a made-up address when there is a link.
	 */
	if (dev->test_device)
	{
		struct ether_addr	good_addr = { {0x70, 0x37, 0x03, 0x70, 0x37, 0x03} };
		struct ether_addr	bad_addr = { {0x00, 0x00, 0x00, 0x00, 0x00, 0x00} };
		gboolean			link = nm_device_get_link_active (dev);

		memcpy ((link ? &good_addr : &bad_addr), &(wrq.u.ap_addr.sa_data), sizeof (struct ether_addr));
		return;
	}

	iwlib_socket = iw_sockets_open ();
	if (iw_get_ext (iwlib_socket, nm_device_get_iface (dev), SIOCGIWAP, &wrq) >= 0)
		memcpy (addr, &(wrq.u.ap_addr.sa_data), sizeof (struct ether_addr));
	else
		memset (addr, 0, sizeof (struct ether_addr));
	close (iwlib_socket);
}


/*
 * nm_device_set_enc_key
 *
 * If a device is wireless, set the encryption key that it should use.
 *
 * key:	encryption key to use, or NULL or "" to disable encryption.
 *		NOTE that at this time, the key must be the raw HEX key, not
 *		a passphrase.
 */
void nm_device_set_enc_key (NMDevice *dev, const char *key, NMDeviceAuthMethod auth_method)
{
	int				sk;
	int				err;
	struct iwreq		wreq;
	int				keylen;
	unsigned char		safe_key[IW_ENCODING_TOKEN_MAX + 1];
	gboolean			set_key = FALSE;
	
	g_return_if_fail (dev != NULL);
	g_return_if_fail (nm_device_is_wireless (dev));

	/* Test devices just ignore encryption keys */
	if (dev->test_device)
		return;

	/* Make sure the essid we get passed is a valid size */
	if (!key)
		safe_key[0] = '\0';
	else
	{
		strncpy (safe_key, key, IW_ENCODING_TOKEN_MAX);
		safe_key[IW_ENCODING_TOKEN_MAX] = '\0';
	}

	sk = iw_sockets_open ();
	if (sk >= 0)
	{
		wreq.u.data.pointer = (caddr_t) NULL;
		wreq.u.data.length = 0;
		wreq.u.data.flags = IW_ENCODE_ENABLED;

		/* Unfortunately, some drivers (Cisco) don't make a distinction between
		 * Open System authentication mode and whether or not to use WEP.  You
		 * DON'T have to use WEP when using Open System, but these cards force
		 * it.  Therefore, we have to set Open System mode when using WEP.
		 */

		if (strlen (safe_key) == 0)
		{
			wreq.u.data.flags |= IW_ENCODE_DISABLED | IW_ENCODE_NOKEY;
			set_key = TRUE;
		}
		else
		{
			unsigned char		parsed_key[IW_ENCODING_TOKEN_MAX + 1];

			keylen = iw_in_key_full (sk, nm_device_get_iface (dev), safe_key, &parsed_key[0], &wreq.u.data.flags);
			if (keylen > 0)
			{
				switch (auth_method)
				{
					case NM_DEVICE_AUTH_METHOD_OPEN_SYSTEM:
						wreq.u.data.flags |= IW_ENCODE_OPEN;
						break;
					case NM_DEVICE_AUTH_METHOD_SHARED_KEY:
						wreq.u.data.flags |= IW_ENCODE_RESTRICTED;
						break;
					default:
						wreq.u.data.flags |= IW_ENCODE_RESTRICTED;
						break;
				}
				wreq.u.data.pointer	=  (caddr_t) &parsed_key;
				wreq.u.data.length	=  keylen;
				set_key = TRUE;
			}
		}

		if (set_key)
		{
			err = iw_set_ext (sk, nm_device_get_iface (dev), SIOCSIWENCODE, &wreq);
			if (err == -1)
				syslog (LOG_ERR, "nm_device_set_enc_key(): error setting key for device %s.  errno = %d", nm_device_get_iface (dev), errno);
		}

		close (sk);
	} else syslog (LOG_ERR, "nm_device_set_enc_key(): could not get wireless control socket.");
}


/*
 * nm_device_get_signal_strength
 *
 * Get the current signal strength of a wireless device.  This only works when
 * the card is associated with an access point, so will only work for the
 * active device.
 *
 * Returns:	-1 on error
 *			0 - 100  strength percentage of the connection to the current access point
 *
 */
gint8 nm_device_get_signal_strength (NMDevice *dev)
{
	g_return_val_if_fail (dev != NULL, -1);
	g_return_val_if_fail (nm_device_is_wireless (dev), -1);

	return (dev->options.wireless.strength);
}


/*
 * nm_device_update_signal_strength
 *
 * Update the device's idea of the strength of its connection to the
 * current access point.
 *
 */
void nm_device_update_signal_strength (NMDevice *dev)
{
	gboolean	has_range;
	int		sk;
	iwrange	range;
	iwstats	stats;
	int		percent = -1;

	g_return_if_fail (dev != NULL);
	g_return_if_fail (nm_device_is_wireless (dev));
	g_return_if_fail (dev->app_data != NULL);

	/* Grab the scan lock since our strength is meaningless during a scan. */
	if (!nm_try_acquire_mutex (dev->options.wireless.scan_mutex, __FUNCTION__))
		return;

	/* If we aren't the active device, we don't really have a signal strength
	 * that would mean anything.
	 */
	if (dev != dev->app_data->active_device)
	{
		dev->options.wireless.strength = -1;
		goto out;
	}

	/* Fake a value for test devices */
	if (dev->test_device)
	{
		dev->options.wireless.strength = 75;
		goto out;
	}

	sk = iw_sockets_open ();
	has_range = (iw_get_range_info (sk, nm_device_get_iface (dev), &range) >= 0);
	if (iw_get_stats (sk, nm_device_get_iface (dev), &stats, &range, has_range) == 0)
	{
		percent = nm_wireless_qual_to_percent (&stats.qual, (const iwqual *)(&dev->options.wireless.max_qual),
				(const iwqual *)(&dev->options.wireless.avg_qual));
	}
	close (sk);

	/* Try to smooth out the strength.  Atmel cards, for example, will give no strength
	 * one second and normal strength the next.
	 */
	if ((percent == -1) && (++dev->options.wireless.invalid_strength_counter <= 3))
		percent = dev->options.wireless.strength;
	else
		dev->options.wireless.invalid_strength_counter = 0;

	dev->options.wireless.strength = percent;

out:
	nm_unlock_mutex (dev->options.wireless.scan_mutex, __FUNCTION__);
}


/*
 * nm_device_get_ip4_address
 *
 * Get a device's IPv4 address
 *
 */
guint32 nm_device_get_ip4_address(NMDevice *dev)
{
	g_return_val_if_fail (dev != NULL, 0);

	return (dev->ip4_address);
}

void nm_device_update_ip4_address (NMDevice *dev)
{
	guint32		new_address;
	struct ifreq	req;
	int			sk;
	int			err;
	
	g_return_if_fail (dev  != NULL);
	g_return_if_fail (dev->app_data != NULL);
	g_return_if_fail (nm_device_get_iface (dev) != NULL);

	/* Test devices get a nice, bogus IP address */
	if (dev->test_device)
	{
		dev->ip4_address = 0x07030703;
		return;
	}

	if ((sk = nm_device_open_sock ()) < 0)
		return;
	
	memset (&req, 0, sizeof (struct ifreq));
	strncpy ((char *)(&req.ifr_name), nm_device_get_iface (dev), strlen (nm_device_get_iface (dev)));
	err = ioctl (sk, SIOCGIFADDR, &req);
	close (sk);
	if (err != 0)
		return;

	new_address = ((struct sockaddr_in *)(&req.ifr_addr))->sin_addr.s_addr;

	/* If the new address is different, send an IP4AddressChanged signal on the bus */
	if (new_address != nm_device_get_ip4_address (dev))
	{
		nm_dbus_signal_device_ip4_address_change (dev->app_data->dbus_connection, dev);
		dev->ip4_address = new_address;
	}
}


/*
 * nm_device_get_ip6_address
 *
 * Get a device's IPv6 address
 *
 */
void nm_device_get_ip6_address(NMDevice *dev)
{
	/* FIXME
	 * Implement
	 */
}


/*
 * nm_device_get_hw_address
 *
 * Get a device's hardware address
 *
 */
void nm_device_get_hw_address(NMDevice *dev, unsigned char hw_addr[ETH_ALEN])
{
	g_return_if_fail (dev != NULL);

	memcpy (hw_addr, dev->hw_addr, ETH_ALEN);
}

void nm_device_update_hw_address (NMDevice *dev)
{
	struct ifreq	req;
	int			sk;
	int			err;

	g_return_if_fail (dev  != NULL);
	g_return_if_fail (dev->app_data != NULL);
	g_return_if_fail (nm_device_get_iface (dev) != NULL);

	/* Test devices get a nice, bogus IP address */
	if (dev->test_device)
	{
		memset (dev->hw_addr, 0, ETH_ALEN);
		return;
	}

	if ((sk = nm_device_open_sock ()) < 0)
		return;
	
	memset (&req, 0, sizeof (struct ifreq));
	strncpy ((char *)(&req.ifr_name), nm_device_get_iface (dev), strlen (nm_device_get_iface (dev)));
	err = ioctl (sk, SIOCGIFHWADDR, &req);
	close (sk);
	if (err != 0)
		return;

      memcpy (dev->hw_addr, req.ifr_hwaddr.sa_data, ETH_ALEN);
}


/*
 * nm_device_set_up_down
 *
 * Set the up flag on the device on or off
 *
 */
static void nm_device_set_up_down (NMDevice *dev, gboolean up)
{
	struct ifreq	ifr;
	int			sk;
	int			err;
	guint32		flags = up ? IFF_UP : ~IFF_UP;

	g_return_if_fail (dev != NULL);

	/* Test devices do whatever we tell them to do */
	if (dev->test_device)
	{
		dev->test_device_up = up;
		return;
	}

	if (nm_device_get_driver_support_level (dev) == NM_DRIVER_UNSUPPORTED)
		return;

	sk = nm_device_open_sock ();
	if (sk < 0)
		return;

	/* Get flags already there */
	strcpy (ifr.ifr_name, nm_device_get_iface (dev));
	err = ioctl (sk, SIOCGIFFLAGS, &ifr);
	if (!err)
	{
		/* If the interface doesn't have those flags already,
		 * set them on it.
		 */
		if ((ifr.ifr_flags^flags) & IFF_UP)
		{
			ifr.ifr_flags &= ~IFF_UP;
			ifr.ifr_flags |= IFF_UP & flags;
			if ((err = ioctl (sk, SIOCSIFFLAGS, &ifr)))
				syslog (LOG_ERR, "nm_device_set_up_down() could not bring device %s %s.  errno = %d", nm_device_get_iface (dev), (up ? "up" : "down"), errno );
		}
		/* Make sure we have a valid MAC address, some cards reload firmware when they
		 * are brought up.
		 */
		if (!nm_ethernet_address_is_valid((struct ether_addr *)dev->hw_addr))
			nm_device_update_hw_address(dev);
	}
	else
		syslog (LOG_ERR, "nm_device_set_up_down() could not get flags for device %s.  errno = %d", nm_device_get_iface (dev), errno );

	close (sk);
}


/*
 * Interface state functions: bring up, down, check
 *
 */
gboolean nm_device_is_up (NMDevice *dev)
{
	int			sk;
	struct ifreq	ifr;
	int			err;

	g_return_val_if_fail (dev != NULL, FALSE);

	if (dev->test_device)
		return (dev->test_device_up);

	sk = nm_device_open_sock ();
	if (sk < 0)
		return (FALSE);

	/* Get device's flags */
	strcpy (ifr.ifr_name, nm_device_get_iface (dev));
	err = ioctl (sk, SIOCGIFFLAGS, &ifr);
	close (sk);
	if (!err)
		return (!((ifr.ifr_flags^IFF_UP) & IFF_UP));

	syslog (LOG_ERR, "nm_device_is_up() could not get flags for device %s.  errno = %d", nm_device_get_iface (dev), errno );
	return (FALSE);
}

gboolean nm_completion_device_is_up_test (int tries, va_list args)
{
	NMDevice *dev = va_arg (args, NMDevice *);
	gboolean *err = va_arg (args, gboolean *);
	gboolean cancelable = va_arg (args, gboolean);

	g_return_val_if_fail (dev != NULL, TRUE);
	g_return_val_if_fail (err != NULL, TRUE);

	*err = FALSE;
	if (cancelable && nm_device_activation_handle_cancel (dev))
	{
		*err = TRUE;
		return TRUE;
	}
	if (nm_device_is_up (dev))
		return TRUE;
	return FALSE;
}

void nm_device_bring_up (NMDevice *dev)
{
	g_return_if_fail (dev != NULL);

	nm_device_set_up_down (dev, TRUE);
}

gboolean nm_device_bring_up_wait (NMDevice *dev, gboolean cancelable)
{
	gboolean err = FALSE;

	g_return_val_if_fail (dev != NULL, TRUE);

	nm_device_bring_up (dev);
	nm_wait_for_completion (400, G_USEC_PER_SEC / 200, NULL,
			nm_completion_device_is_up_test, dev,
			&err, cancelable);
	if (err)
		syslog (LOG_INFO, "failed to bring device up");
	return err;
}

void nm_device_bring_down (NMDevice *dev)
{
	g_return_if_fail (dev != NULL);

	nm_device_set_up_down (dev, FALSE);
}

gboolean nm_completion_device_is_down_test(int tries, va_list args)
{
	NMDevice *dev = va_arg (args, NMDevice *);
	gboolean *err = va_arg (args, gboolean *);
	gboolean cancelable = va_arg (args, gboolean);

	g_return_val_if_fail (dev != NULL, TRUE);
	g_return_val_if_fail (err != NULL, TRUE);

	*err = FALSE;
	if (cancelable && nm_device_activation_handle_cancel (dev)) 
	{
		*err = TRUE;
		return TRUE;
	}
	if (!nm_device_is_up (dev))
		return TRUE;
	return FALSE;
}

gboolean nm_device_bring_down_wait (NMDevice *dev, gboolean cancelable)
{
	gboolean err = FALSE;

	g_return_val_if_fail (dev != NULL, TRUE);

	nm_device_bring_down (dev);
	nm_wait_for_completion (400, G_USEC_PER_SEC / 200, NULL,
			nm_completion_device_is_down_test, dev,
			&err, cancelable);
	if (err)
		syslog (LOG_INFO, "failed to bring device down");
	return err;
}


/*
 * nm_device_get_mode
 *
 * Get managed/infrastructure/adhoc mode on a device (currently wireless only)
 *
 */
NMNetworkMode nm_device_get_mode (NMDevice *dev)
{
	int			sk;
	NMNetworkMode	mode = NETWORK_MODE_UNKNOWN;

	g_return_val_if_fail (dev != NULL, NETWORK_MODE_UNKNOWN);
	g_return_val_if_fail (nm_device_is_wireless (dev), NETWORK_MODE_UNKNOWN);

	/* Force the card into Managed/Infrastructure mode */
	sk = iw_sockets_open ();
	if (sk >= 0)
	{
		struct iwreq	wrq;
		int			err;

		err = iw_set_ext (sk, nm_device_get_iface (dev), SIOCGIWMODE, &wrq);
		if (err == 0)
		{
			switch (wrq.u.mode)
			{
				case IW_MODE_INFRA:
					mode = NETWORK_MODE_INFRA;
					break;
				case IW_MODE_ADHOC:
					mode = NETWORK_MODE_ADHOC;
					break;
				default:
					break;
			}
		}
		else
			syslog (LOG_ERR, "nm_device_get_mode (%s): error setting card to Infrastructure mode.  errno = %d", nm_device_get_iface (dev), errno);				
		close (sk);
	}

	return (mode);
}


/*
 * nm_device_set_mode
 *
 * Set managed/infrastructure/adhoc mode on a device (currently wireless only)
 *
 */
gboolean nm_device_set_mode (NMDevice *dev, const NMNetworkMode mode)
{
	int			sk;
	gboolean		success = FALSE;

	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (nm_device_is_wireless (dev), FALSE);
	g_return_val_if_fail ((mode == NETWORK_MODE_INFRA) || (mode == NETWORK_MODE_ADHOC), FALSE);

	if (nm_device_get_mode (dev) == mode)
		return TRUE;

	/* Force the card into Managed/Infrastructure mode */
	sk = iw_sockets_open ();
	if (sk >= 0)
	{
		struct iwreq	wreq;
		int			err;
		gboolean		mode_good = FALSE;

		switch (mode)
		{
			case NETWORK_MODE_INFRA:
				wreq.u.mode = IW_MODE_INFRA;
				mode_good = TRUE;
				break;
			case NETWORK_MODE_ADHOC:
				wreq.u.mode = IW_MODE_ADHOC;
				mode_good = TRUE;
				break;
			default:
				mode_good = FALSE;
				break;
		}
		if (mode_good)
		{
			err = iw_set_ext (sk, nm_device_get_iface (dev), SIOCSIWMODE, &wreq);
			if (err == 0)
				success = TRUE;
			else
				syslog (LOG_ERR, "nm_device_set_mode (%s): error setting card to Infrastructure mode.  errno = %d", nm_device_get_iface (dev), errno);				
		}
		close (sk);
	}

	return (success);
}


/*
 * nm_device_activation_schedule_finish
 *
 * Schedule an idle routine in the main thread to finish the activation.
 *
 */
void nm_device_activation_schedule_finish (NMDevice *dev, DeviceStatus activation_result)
{
	GSource			*source = NULL;
	NMActivationResult	*result = NULL;

	g_return_if_fail (dev != NULL);
	g_return_if_fail (dev->app_data != NULL);

	result = g_malloc0 (sizeof (NMActivationResult));
	nm_device_ref (dev);	/* Ref device for idle handler */
	result->dev = dev;
	result->result = activation_result;

	source = g_idle_source_new ();
	g_source_set_callback (source, nm_policy_activation_finish, (gpointer)result, NULL);
	g_source_attach (source, dev->app_data->main_context);
	g_source_unref (source);
}


/*
 * nm_device_activation_schedule_start
 *
 * Tell the device thread to begin activation.
 *
 * Returns:	TRUE on success activation beginning
 *			FALSE on error beginning activation (bad params, couldn't create thread)
 *
 */
gboolean nm_device_activation_schedule_start (NMDevice *dev)
{
	NMData	*data = NULL;
	GSource	*source = NULL;

	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (!dev->activating, TRUE);	/* Return if activation has already begun */

	data = dev->app_data;
	g_return_val_if_fail (data != NULL, FALSE);

	/* Reset communication flags between worker and main thread */
	dev->activating = TRUE;
	dev->quit_activation = FALSE;
	if (nm_device_is_wireless (dev))
	{
		nm_device_set_now_scanning (dev, TRUE);
		dev->options.wireless.user_key_received = FALSE;
	}

	if (nm_device_get_driver_support_level (dev) == NM_DRIVER_UNSUPPORTED)
	{
		dev->activating = FALSE;
		return (FALSE);
	}

	source = g_idle_source_new ();
	g_source_set_callback (source, nm_device_activate, dev, NULL);
	g_source_attach (source, dev->context);
	g_source_unref (source);

	nm_dbus_signal_device_status_change (data->dbus_connection, dev, DEVICE_ACTIVATING);

	return (TRUE);
}


/*
 * nm_device_activation_handle_cancel
 *
 * Check whether we should stop activation, and if so clean up flags
 * and other random things.
 *
 */
static gboolean nm_device_activation_handle_cancel (NMDevice *dev)
{
	g_return_val_if_fail (dev != NULL, TRUE);

	/* If we were told to quit activation, stop the thread and return */
	if (dev->quit_activation)
	{
		syslog (LOG_DEBUG, "nm_device_activation_worker(%s): activation canceled.", nm_device_get_iface (dev));
		if (nm_device_is_wireless (dev))
			nm_device_set_now_scanning (dev, FALSE);
		return (TRUE);
	}

	return (FALSE);
}

static gboolean nm_dwwfl_test (int tries, va_list args)
{
	NMDevice *dev = va_arg (args, NMDevice *);
	guint *assoc_count = va_arg (args, guint *);
	double *last_freq = va_arg (args, double *);
	char *essid = va_arg (args, char *);
	int required = va_arg (args, int);

	double cur_freq = nm_device_get_frequency (dev);
	gboolean assoc = nm_device_wireless_is_associated (dev);
	const char * cur_essid = nm_device_get_essid (dev);

	/* If we've been cancelled, return that we should stop */
	if (nm_device_activation_should_cancel (dev))
		return TRUE;

	/* If we're on the same frequency and essid, and we're associated,
	 * increment the count for how many iterations we've been associated;
	 * otherwise start over. */
	/* XXX floating point comparison this way is dangerous, IIRC */
	if ((cur_freq == *last_freq) && assoc && !strcmp (essid, cur_essid))
	{
		(*assoc_count)++;
	}
	else
	{
		*assoc_count = 0;
		*last_freq = cur_freq;
	}

	/* If we're told to cancel, return that we're finished.
	 * If we've the frequency has been stable for more than the required
	 * interval, return that we're finished.
	 * Otherwise, we're not finished. */
	if (nm_device_activation_should_cancel (dev) || *assoc_count >= required)
		return TRUE;

	return FALSE;
}


/*
 * nm_device_wireless_wait_for_link
 *
 * Try to be clever about when the wireless card really has associated with the access point.
 * Return TRUE when we think that it has, and FALSE when we thing it has not associated.
 *
 */
static gboolean nm_device_wireless_wait_for_link (NMDevice *dev, const char *essid)
{
	guint		assoc = 0;
	double		last_freq = 0;
	guint		assoc_count = 0;
	struct timeval	timeout = { .tv_sec = 0, .tv_usec = 0 };

	/* we want to sleep for a very short amount of time, to minimize
	 * hysteresis on the boundaries of our required time.  But we
	 * also want the maximum to be based on what the card */
	const guint	delay = 30;
	const guint	required_tries = 10;
	const guint	min_delay = 2 * (required_tries / delay);

	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (time > 0, FALSE);

	/* for cards which don't scan many frequencies, this will return 
	 * 5 seconds, which we'll bump up to 6 seconds below.  Oh well. */
	timeout.tv_sec = (time_t)nm_device_get_association_pause_value (dev);

	/* Refuse to to have a timeout that's _less_ than twice the total time
	 * required before calling a link valid */
	if (timeout.tv_sec < min_delay)
		timeout.tv_sec = min_delay;

	/* We more or less keep asking the driver for the frequency the
	 * card is listening on until it connects to an AP.  Once it's 
	 * associated, the driver stops scanning.  To detect that, we look
	 * for the essid and frequency to remain constant for 3 seconds.
	 * When it remains constant, we assume it's a real link. */
	nm_wait_for_timeout (&timeout, G_USEC_PER_SEC / delay,
			    nm_dwwfl_test, nm_dwwfl_test, dev, &assoc,
			    &last_freq, essid, required_tries * 2);

	/* If we've had a reasonable association count, we say we have a link */
	if (assoc > required_tries)
		return TRUE;
	return FALSE;
}

static gboolean nm_device_link_test(int tries, va_list args)
{
	NMDevice *dev = va_arg(args, NMDevice *);
	gboolean *err = va_arg(args, gboolean *);

	g_return_val_if_fail(dev != NULL, TRUE);
	g_return_val_if_fail(err != NULL, TRUE);
 
	if (nm_device_wireless_is_associated (dev) && nm_device_get_essid (dev))
	{
		*err = FALSE;
		return TRUE;
	}
	*err = TRUE;
	return FALSE;
}

static gboolean nm_device_is_up_and_associated_wait (NMDevice *dev, int timeout, int interval)
{
	gboolean err;
	const gint delay = (G_USEC_PER_SEC * nm_device_get_association_pause_value (dev)) / interval;
	const gint max_cycles = timeout * interval;

	g_return_val_if_fail (dev != NULL, TRUE);

	nm_wait_for_completion (max_cycles, delay, NULL, nm_device_link_test, dev, &err);
	return !err;
}


/*
 * nm_device_set_wireless_config
 *
 * Bring up a wireless card with the essid and wep key of its "best" ap
 *
 * Returns:	TRUE on successful activation
 *			FALSE on unsuccessful activation (ie no best AP)
 *
 */
static gboolean nm_device_set_wireless_config (NMDevice *dev, NMAccessPoint *ap)
{
	NMDeviceAuthMethod	 auth;
	const char		*essid = NULL;

	g_return_val_if_fail (dev  != NULL, FALSE);
	g_return_val_if_fail (nm_device_is_wireless (dev), FALSE);
	g_return_val_if_fail (ap != NULL, FALSE);
	g_return_val_if_fail (nm_ap_get_essid (ap) != NULL, FALSE);
	g_return_val_if_fail (nm_ap_get_auth_method (ap) != NM_DEVICE_AUTH_METHOD_UNKNOWN, FALSE);

	/* Force the card into Managed/Infrastructure mode */
	nm_device_bring_down_wait (dev, 0);
	nm_device_bring_up_wait (dev, 0);

	nm_device_set_mode (dev, NETWORK_MODE_INFRA);

	essid = nm_ap_get_essid (ap);
	auth = nm_ap_get_auth_method (ap);

	nm_device_set_mode (dev, nm_ap_get_mode (ap));
	nm_device_set_bitrate (dev, 0);

	if (nm_ap_get_user_created (ap) || (nm_ap_get_freq (ap) && (nm_ap_get_mode (ap) == NETWORK_MODE_ADHOC)))
		nm_device_set_frequency (dev, nm_ap_get_freq (ap));
	else
		nm_device_set_frequency (dev, 0);	/* auto */

	if (nm_ap_get_encrypted (ap) && nm_ap_is_enc_key_valid (ap))
	{
		char				*hashed_key = nm_ap_get_enc_key_hashed (ap);

		if (auth == NM_DEVICE_AUTH_METHOD_NONE)
		{
			nm_ap_set_auth_method (ap, NM_DEVICE_AUTH_METHOD_OPEN_SYSTEM);
			syslog (LOG_ERR, "Activation (%s/wireless): AP '%s' said it was encrypted, but had "
					"'none' for authentication method.  Using Open System authentication method.",
					nm_device_get_iface (dev), nm_ap_get_essid (ap));
		}
		nm_device_set_enc_key (dev, hashed_key, auth);
		g_free (hashed_key);
	}
	else
		nm_device_set_enc_key (dev, NULL, NM_DEVICE_AUTH_METHOD_NONE);

	nm_device_set_essid (dev, essid);

	syslog (LOG_INFO, "Activation (%s/wireless): using essid '%s', with %s authentication.",
			nm_device_get_iface (dev), essid, (auth == NM_DEVICE_AUTH_METHOD_NONE) ? "no" :
				((auth == NM_DEVICE_AUTH_METHOD_OPEN_SYSTEM) ? "Open System" :
				((auth == NM_DEVICE_AUTH_METHOD_SHARED_KEY) ? "Shared Key" : "unknown")));

	/* Bring the device up and pause to allow card to associate.  After we set the ESSID
	 * on the card, the card has to scan all channels to find our requested AP (which can
	 * take a long time if it is an A/B/G chipset like the Atheros 5212, for example).
	 */
	nm_device_is_up_and_associated_wait (dev, 2, 100);

	/* Some cards don't really work well in ad-hoc mode unless you explicitly set the bitrate
	 * on them. (Netgear WG511T/Atheros 5212 with madwifi drivers).  Until we can get rate information
	 * from scanned access points out of iwlib, clamp bitrate for these cards at 11Mbps.
	 */
	if ((nm_ap_get_mode (ap) == NETWORK_MODE_ADHOC) && (nm_device_get_bitrate (dev) <= 0))
		nm_device_set_bitrate (dev, 11000);	/* In Kbps */

	return (TRUE);
}


/*
 * nm_device_activate_wireless_adhoc
 *
 * Create an ad-hoc network (rather than associating with one).
 *
 */
static gboolean nm_device_activate_wireless_adhoc (NMDevice *dev, NMAccessPoint *ap)
{
	gboolean			 success = FALSE;
	NMDeviceAuthMethod	 auth = NM_DEVICE_AUTH_METHOD_NONE;
	NMAPListIter		*iter;
	NMAccessPoint		*tmp_ap;
	double			 card_freqs[IW_MAX_FREQUENCIES];
	int				 num_freqs = 0, i;
	double			 freq_to_use = 0;
	iwrange			 range;
	int				 sk;

	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (ap != NULL, FALSE);

	if (nm_ap_get_encrypted (ap))
		auth = NM_DEVICE_AUTH_METHOD_SHARED_KEY;

	/* Build our local list of frequencies to whittle down until we find a free one */
	memset (&card_freqs, 0, sizeof (card_freqs));
	num_freqs = MIN (dev->options.wireless.num_freqs, IW_MAX_FREQUENCIES);
	for (i = 0; i < num_freqs; i++)
		card_freqs[i] = dev->options.wireless.freqs[i];

	/* We need to find a clear wireless channel to use.  We will
	 * only use 802.11b channels for now.
	 */
	iter = nm_ap_list_iter_new (nm_device_ap_list_get (dev));
	while ((tmp_ap = nm_ap_list_iter_next (iter)))
	{
		double ap_freq = nm_ap_get_freq (tmp_ap);
		for (i = 0; i < num_freqs && ap_freq; i++)
		{
			if (card_freqs[i] == ap_freq)
				card_freqs[i] = 0;
		}
	}
	nm_ap_list_iter_free (iter);

	if ((sk = iw_sockets_open ()) < 0)
		return FALSE;

	if (iw_get_range_info (sk, nm_device_get_iface (dev), &range) < 0)
	{
		close (sk);
		return FALSE;
	}
	close (sk);

	/* Ok, find the first non-zero freq in our table and use it.
	 * For now we only try to use a channel in the 802.11b channel
	 * space so that most everyone can see it.
	 */
	for (i = 0; i < num_freqs; i++)
	{
		int channel = iw_freq_to_channel (card_freqs[i], &range);
		if (card_freqs[i] && (channel > 0) && (channel < 15))
		{
			freq_to_use = card_freqs[i];
			break;
		}
	}

	/* Hmm, no free channels in 802.11b space.  Pick one more or less randomly */
	if (!freq_to_use)
	{
		double pfreq;
		int	channel = (int)(random () % 14);
		int	err;

		err = iw_channel_to_freq (channel, &pfreq, &range);
		if (err == channel)
			freq_to_use = pfreq;
	}

	if (freq_to_use)
	{
		nm_ap_set_freq (ap, freq_to_use);
	
		syslog (LOG_INFO, "Will create network '%s' with frequency %f.\n", nm_ap_get_essid (ap), nm_ap_get_freq (ap));
		if ((success = nm_device_set_wireless_config (dev, ap)))
			success = nm_device_activation_configure_ip (dev, TRUE);
	}

	return (success);
}


static gboolean AP_NEED_KEY (NMDevice *dev, NMAccessPoint *ap)
{
	char		*essid;
	gboolean	 need_key = FALSE;

	g_return_val_if_fail (ap != NULL, FALSE);

	essid = nm_ap_get_essid (ap);

	if (!nm_ap_get_encrypted (ap))
	{
		syslog (LOG_NOTICE, "Activation (%s/wireless): access point '%s' is unencrypted, no key needed.",
			nm_device_get_iface (dev), essid ? essid : "(null)");
	}
	else
	{
		if (nm_ap_is_enc_key_valid (ap))
		{
			syslog (LOG_NOTICE, "Activation (%s/wireless): access point '%s' is encrypted, and a key exists.  No new key needed.",
					nm_device_get_iface (dev), essid ? essid : "(null)");
		}
		else
		{
			syslog (LOG_NOTICE, "Activation (%s/wireless): access point '%s' is encrypted, but NO valid key exists.  New key needed.",
					nm_device_get_iface (dev), essid ? essid : "(null)");
			need_key = TRUE;
		}
	}

	return (need_key);
}


/*
 * get_initial_auth_method
 *
 * Update the auth method of the AP from the last-known-good one saved in the allowed list
 * (which is found from NMI) and ensure that its valid with the encryption status of the AP.
 *
 */
static NMDeviceAuthMethod get_initial_auth_method (NMAccessPoint *ap, NMAccessPointList *allowed_list)
{
	g_return_val_if_fail (ap != NULL, NM_DEVICE_AUTH_METHOD_OPEN_SYSTEM);

	if (nm_ap_get_encrypted (ap))
	{
		NMDeviceAuthMethod	 auth = nm_ap_get_auth_method (ap);
		NMAccessPoint		*allowed_ap = nm_ap_list_get_ap_by_essid (allowed_list, nm_ap_get_essid (ap));
		
		/* Prefer default auth method if we found one for this AP in our allowed list. */
		if (allowed_ap)
			auth = nm_ap_get_auth_method (allowed_ap);

		if (    (auth == NM_DEVICE_AUTH_METHOD_OPEN_SYSTEM)
			|| (auth == NM_DEVICE_AUTH_METHOD_SHARED_KEY))
			return (auth);
		else
			return (NM_DEVICE_AUTH_METHOD_OPEN_SYSTEM);
	}

	return (NM_DEVICE_AUTH_METHOD_NONE);
}


void invalidate_ap (NMDevice *dev, NMAccessPoint *ap)
{
	g_return_if_fail (dev != NULL);
	g_return_if_fail (dev->app_data != NULL);
	g_return_if_fail (ap != NULL);

	/* If its an AP the user forced, notify the user it failed. */
	/* FIXME: we dont' set ap's that are in our scan list as "artificial",
	 * so we won't be able to signal the user when a connection to on of them
	 * failed.
	 */
	if (nm_ap_get_artificial (ap))
		nm_dbus_schedule_network_not_found_signal (dev->app_data, nm_ap_get_essid (ap));	

	nm_ap_set_invalid (ap, TRUE);
	nm_ap_list_append_ap (dev->app_data->invalid_ap_list, ap);
	nm_ap_unref (ap);
	nm_device_update_best_ap (dev);
}


/* this gets called without the scan mutex held */
static gboolean nm_wa_test (int tries, va_list args)
{
	NMDevice *dev = va_arg(args, NMDevice *);
	NMAccessPoint **best_ap = va_arg(args, NMAccessPoint **);
	gboolean *err = va_arg(args, gboolean *);

	g_return_val_if_fail(dev != NULL, TRUE);
	g_return_val_if_fail(best_ap != NULL, TRUE);
	g_return_val_if_fail(err != NULL, TRUE);

	*err = TRUE;
	if (nm_device_activation_handle_cancel(dev))
		return TRUE;

	if (tries % 100 == 0)
		syslog (LOG_INFO, "Activation (%s/wireless): waiting for access point. (attempt %d)", nm_device_get_iface(dev), tries);

	*best_ap = nm_device_get_best_ap (dev);
	if (*best_ap) {
		/* Set ESSID early so that when we send out the
		 * DeviceStatusChanged signal below, we are able to 
		 * respond correctly to queries for "getActiveNetwork"
		 * against our device.  nm_device_get_path_for_ap() uses 
		 * the /card's/ AP, not the best_ap. */
		nm_device_set_essid (dev, nm_ap_get_essid (*best_ap));
		nm_device_set_now_scanning (dev, FALSE);
		*err = FALSE;
		return TRUE;
	}

	return FALSE;
}


/*
 * nm_device_activate_wireless
 *
 * Activate a wireless ethernet device.  Locking could be confusing here, pay attention to it.
 * We grab the scan mutex because scanning requires us to set certain state on the card,
 * like mode, which could screw up device activation link state checks.
 *
 */
static gboolean nm_device_activate_wireless (NMDevice *dev)
{
	NMAccessPoint		*best_ap = NULL;
	gboolean			 success = FALSE;
	guint8			 attempt = 1;
	char				 last_essid [50] = "\0";
	gboolean			 need_key = FALSE;
	gboolean			 found_ap = FALSE;
	gboolean			 err = FALSE;

	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (dev->app_data != NULL, FALSE);

	/* Grab the scan mutex, we don't want the scan thread to mess up our settings
	 * during activation and link detection.
	 */
	nm_lock_mutex (dev->options.wireless.scan_mutex, __FUNCTION__);

	nm_device_bring_up_wait (dev, 1);

get_ap:
	/* If we were told to quit activation, stop the thread and return */
	if (nm_device_activation_handle_cancel (dev))
		goto out;

	/* Get a valid "best" access point we should connect to.  We don't hold the scan
	 * lock here because this might take a while.
	 */
	nm_unlock_mutex (dev->options.wireless.scan_mutex, __FUNCTION__);

	/* Get a valid "best" access point we should connect to. */
	nm_device_set_now_scanning (dev, TRUE);

	/* at most wait 10 seconds, but check every 50th to see if we're done */
	nm_wait_for_completion(NM_COMPLETION_TRIES_INFINITY, G_USEC_PER_SEC / 50, nm_wa_test, NULL, dev, &best_ap, &err);
	if (err)
	{
		/* Wierd as it may seem, we lock here to balance the unlock in "out:" */
		nm_lock_mutex (dev->options.wireless.scan_mutex, __FUNCTION__);
		goto out;
	}
	syslog (LOG_ERR, "Activation (%s/wireless): found access point '%s' to use.", nm_device_get_iface (dev), nm_ap_get_essid (best_ap));

	/* Set ESSID early so that when we send out the DeviceStatusChanged signal below,
	 * we are able to respond correctly to queries for "getActiveNetwork" against
	 * our device.  nm_device_get_path_for_ap() uses the /card's/ AP, not the best_ap.
	 */
	nm_device_set_essid (dev, nm_ap_get_essid (best_ap));

	/* We grab the scan mutex so that scanning cannot screw up our link detection, since
	 * a scan can change most any attribute on the card for a period of time.
	 */
	nm_device_set_now_scanning (dev, FALSE);
	nm_lock_mutex (dev->options.wireless.scan_mutex, __FUNCTION__);

	if (nm_ap_get_artificial (best_ap))
	{
		/* Some Cisco cards (340/350 PCMCIA) don't return non-broadcasting APs
		 * in their scan results, so we can't know beforehand whether or not the
		 * AP was encrypted.  We have to update their encryption status on the fly.
		 */
		if (nm_ap_get_encrypted (best_ap) || nm_ap_is_enc_key_valid (best_ap))
		{
			nm_ap_set_encrypted (best_ap, TRUE);
			nm_ap_set_auth_method (best_ap, NM_DEVICE_AUTH_METHOD_OPEN_SYSTEM);
		}
	}

	need_key = AP_NEED_KEY (dev, best_ap);

need_key:
	if (nm_device_activation_handle_cancel (dev))
		goto out;
	if (need_key)
	{
		char	*essid = nm_ap_get_essid (best_ap);
		if (strcmp (essid, last_essid) != 0)
			attempt = 1;
		strncpy (&last_essid[0], essid, 49);

		/* Don't hold the mutex while waiting for a key */
		nm_unlock_mutex (dev->options.wireless.scan_mutex, __FUNCTION__);

		/* Get a wireless key */
		dev->options.wireless.user_key_received = FALSE;
		nm_dbus_get_user_key_for_network (dev->app_data->dbus_connection, dev, best_ap, attempt);
		attempt++;
		need_key = FALSE;

		/* Wait for the key to come back */
		syslog (LOG_DEBUG, "Activation (%s/wireless): asking for user key.", nm_device_get_iface (dev));
		while (!dev->options.wireless.user_key_received && !dev->quit_activation)
			g_usleep (G_USEC_PER_SEC / 2);

		syslog (LOG_DEBUG, "Activation (%s/wireless): user key received.", nm_device_get_iface (dev));

		/* Done waiting, grab lock again */
		nm_lock_mutex (dev->options.wireless.scan_mutex, __FUNCTION__);

		/* User may have cancelled the key request, so we need to update our best AP again. */
		nm_ap_unref (best_ap);

		goto get_ap;
	}

	if (nm_ap_get_mode (best_ap) == NETWORK_MODE_ADHOC)
	{
		/* Only do auto-ip on Ad-Hoc connections for now.  We technically
		 * could do DHCP on them though.
		 */
		success = nm_device_activation_configure_ip (dev, TRUE);
		goto connect_done;
	}

try_connect:
	/* Initial authentication method */
	nm_ap_set_auth_method (best_ap, get_initial_auth_method (best_ap, dev->app_data->allowed_ap_list));

	while (success == FALSE)
	{
		NMAccessPoint	*tmp_ap = NULL;
		gboolean		 link = FALSE;
		gboolean		 adhoc = (nm_ap_get_mode (best_ap) == NETWORK_MODE_ADHOC);

		/* If we were told to quit activation, stop the thread and return */
		if (nm_device_activation_handle_cancel (dev))
			goto out;

		nm_device_set_wireless_config (dev, best_ap);

		link = nm_device_wireless_wait_for_link (dev, nm_ap_get_essid (best_ap));

		/* If we were told to quit activation, stop the thread and return */
		if (nm_device_activation_handle_cancel (dev))
			goto out;

		if (!link)
		{
			if (nm_ap_get_auth_method (best_ap) == NM_DEVICE_AUTH_METHOD_OPEN_SYSTEM)
			{
				syslog (LOG_DEBUG, "Activation (%s/wireless): no hardware link to '%s' in Open System mode, trying Shared Key.",
						nm_device_get_iface (dev), nm_ap_get_essid (best_ap) ? nm_ap_get_essid (best_ap) : "(none)");
				/* Back down to Shared Key mode */
				nm_ap_set_auth_method (best_ap, NM_DEVICE_AUTH_METHOD_SHARED_KEY);
				continue;
			}
			else if (nm_ap_get_auth_method (best_ap) == NM_DEVICE_AUTH_METHOD_SHARED_KEY)
			{
				/* Must be in Open System mode and it still didn't work, so
				 * we'll invalidate the current "best" ap and get another one */
				syslog (LOG_DEBUG, "Activation (%s/wireless): no hardware link to '%s' in Shared Key mode, trying another access point.",
						nm_device_get_iface (dev), nm_ap_get_essid (best_ap) ? nm_ap_get_essid (best_ap) : "(none)");
			}
			else
			{
				syslog (LOG_DEBUG, "Activation (%s/wireless): no hardware link to '%s' in non-encrypted mode.",
						nm_device_get_iface (dev), nm_ap_get_essid (best_ap) ? nm_ap_get_essid (best_ap) : "(none)");
			}

			/* All applicable modes failed, invalidate current best_ap and get a new one */
			invalidate_ap (dev, best_ap);
			goto get_ap;
		}

		/* For those broken cards that report successful hardware link even when WEP key is wrong,
		 * and also for Open System mode (where you cannot know WEP key is wrong ever), we try to
		 * do DHCP and if that fails, fall back to next auth mode and try again.
		 */
		success = FALSE;
		if ((success = nm_device_activation_configure_ip (dev, adhoc)))
		{
			if (nm_device_activation_handle_cancel (dev))
			{
				success = FALSE;
				goto out;
			}

			/* Cache the last known good auth method in both NetworkManagerInfo and our allowed AP list */
			nm_dbus_update_network_auth_method (dev->app_data->dbus_connection, nm_ap_get_essid (best_ap), nm_ap_get_auth_method (best_ap));
			if ((tmp_ap = nm_ap_list_get_ap_by_essid (dev->app_data->allowed_ap_list, nm_ap_get_essid (best_ap))))
				nm_ap_set_auth_method (tmp_ap, nm_ap_get_auth_method (best_ap));
		}
		else
		{
			if (nm_device_activation_handle_cancel (dev))
				goto out;

			if ((nm_ap_get_auth_method (best_ap) == NM_DEVICE_AUTH_METHOD_OPEN_SYSTEM) && !adhoc)
			{
				/* Back down to Shared Key mode */
				syslog (LOG_DEBUG, "Activation (%s/wireless): could not get IP configuration info for '%s' in Open System mode, trying Shared Key.",
						nm_device_get_iface (dev), nm_ap_get_essid (best_ap) ? nm_ap_get_essid (best_ap) : "(none)");
				nm_ap_set_auth_method (best_ap, NM_DEVICE_AUTH_METHOD_SHARED_KEY);
				continue;
			}
			else if ((nm_ap_get_auth_method (best_ap) == NM_DEVICE_AUTH_METHOD_SHARED_KEY) && !adhoc)
			{
				/* Shared Key mode failed, we must have bad WEP key */
				syslog (LOG_DEBUG, "Activation (%s/wireless): could not get IP configuration info for '%s' in Shared Key mode, asking for new key.",
						nm_device_get_iface (dev), nm_ap_get_essid (best_ap) ? nm_ap_get_essid (best_ap) : "(none)");
				need_key = TRUE;
				goto need_key;
			}
			else
			{
				/* All applicable modes failed, invalidate current best_ap and get a new one */
				invalidate_ap (dev, best_ap);
				goto get_ap;
			}
		}
	}

connect_done:
	/* If we were told to quit activation, stop the thread and return */
	if (nm_device_activation_handle_cancel (dev))
	{
		success = FALSE;
		goto out;
	}

	if (success)
	{
		syslog (LOG_DEBUG, "Activation (%s/wireless): Success!  Connected to access point '%s' and got an IP address.",
				nm_device_get_iface (dev), nm_ap_get_essid (best_ap) ? nm_ap_get_essid (best_ap) : "(none)");
		nm_ap_unref (best_ap);
	}

out:
	nm_device_set_now_scanning (dev, FALSE);
	nm_unlock_mutex (dev->options.wireless.scan_mutex, __FUNCTION__);
	return (success);
}


/*
 * nm_device_activation_configure_ip
 *
 * Perform any IP-based configuration on a device, like running DHCP
 * or manually setting up the IP address, gateway, and default route.
 *
 */
static gboolean nm_device_activation_configure_ip (NMDevice *dev, gboolean do_only_autoip)
{
	gboolean success = FALSE;

	g_return_val_if_fail (dev != NULL, FALSE);

	nm_system_delete_default_route ();
	if (do_only_autoip)
	{
		success = nm_device_do_autoip (dev);
	}
	else if (nm_device_config_get_use_dhcp (dev))
	{
		int		err;

		err = nm_device_dhcp_request (dev);
		if (err == RET_DHCP_BOUND)
			success = TRUE;
		else
		{
			/* Interfaces cannot be down if they are the active interface,
			 * otherwise we cannot use them for scanning or link detection.
			 */
			if (nm_device_is_wireless (dev))
			{
				nm_device_set_essid (dev, "");
				nm_device_set_enc_key (dev, NULL, NM_DEVICE_AUTH_METHOD_NONE);
			}

			if (!nm_device_is_up (dev))
				nm_device_bring_up (dev);
		}
	}
	else
	{
		/* Manually set up the device */
		success = nm_system_device_setup_static_ip4_config (dev);
	}

	if (success)
	{
		nm_system_device_add_ip6_link_address (dev);
		nm_system_flush_arp_cache ();
		nm_system_restart_mdns_responder ();
	}

	return (success);
}


/*
 * nm_device_activate
 *
 * Activate a device, done from the device's worker thread.
 *
 */
static gboolean nm_device_activate (gpointer user_data)
{
	NMDevice			*dev = (NMDevice *)user_data;
	gboolean			 success = FALSE;
	gboolean			 finished = FALSE;

	g_return_val_if_fail (dev  != NULL, FALSE);
	g_return_val_if_fail (dev->app_data != NULL, FALSE);

	syslog (LOG_ERR, "Activation (%s) started...", nm_device_get_iface (dev));

	/* Bring the device up */
	if (!nm_device_is_up (dev));
		nm_device_bring_up (dev);

	if (nm_device_is_wireless (dev))
	{
		gboolean		create_network = FALSE;
		NMAccessPoint *best_ap = nm_device_get_best_ap (dev);

		if (best_ap)
		{
			if (nm_ap_get_user_created (best_ap))
			{
				create_network = TRUE;
				syslog (LOG_INFO, "Creating wireless network '%s'.\n", nm_ap_get_essid (best_ap));
				success = nm_device_activate_wireless_adhoc (dev, best_ap);
				syslog (LOG_INFO, "Wireless network creation for '%s' was %s.\n", nm_ap_get_essid (best_ap), success ? "successful" : "unsuccessful");
			}
			nm_ap_unref (best_ap);
		}

		if (!create_network)
			success = nm_device_activate_wireless (dev);
	}
	else if (nm_device_is_wired (dev))
		success = nm_device_activation_configure_ip (dev, FALSE);

	/* If we were told to quit activation, stop the thread and return */
	if (nm_device_activation_handle_cancel (dev))
		goto out;

	if (success)
		syslog (LOG_DEBUG, "Activation (%s) IP configuration/DHCP successful!\n", nm_device_get_iface (dev));
	else
		syslog (LOG_DEBUG, "Activation (%s) IP configuration/DHCP unsuccessful!  Ending activation...\n", nm_device_get_iface (dev));

	finished = TRUE;

out:
	syslog (LOG_DEBUG, "Activation (%s) ended.\n", nm_device_get_iface (dev));
	dev->activating = FALSE;
	dev->quit_activation = FALSE;
	if (finished)
		nm_device_activation_schedule_finish (dev, success ? DEVICE_NOW_ACTIVE : DEVICE_ACTIVATION_FAILED);

	return FALSE;
}


/*
 * nm_device_is_activating
 *
 * Return whether or not the device is currently activating itself.
 *
 */
gboolean nm_device_is_activating (NMDevice *dev)
{
	g_return_val_if_fail (dev != NULL, FALSE);

	return (dev->activating);
}


/*
 * nm_device_activation_should_cancel
 *
 * Return whether or not we've been told to cancel activation
 *
 */
gboolean nm_device_activation_should_cancel (NMDevice *dev)
{
	g_return_val_if_fail (dev != NULL, FALSE);

	return (dev->quit_activation);
}


static gboolean nm_ac_test (int tries, va_list args)
{
	NMDevice *dev = va_arg (args, NMDevice *);

	g_return_val_if_fail (dev != NULL, TRUE);

	if (tries == 0 && nm_device_get_dhcp_iface (dev))
		nm_device_dhcp_cease (dev);
	
	if (nm_device_is_activating(dev))
	{
		/* Nice race here between quit activation and dhcp.  We may
		 * not have started DHCP when we're told to quit activation,
		 * so we need to keep signalling dhcp to quit, which it will 
		 * pick up whenever it starts.
		 *
		 * This should really be taken care of a better way.
		 */
		if (nm_device_get_dhcp_iface (dev))
			nm_device_dhcp_cease (dev);
		if (tries % 20 == 0)
			syslog (LOG_DEBUG, "Activation (%s/wireless): waiting on dhcp to cease or device to finish activation", nm_device_get_iface(dev));
		return FALSE;
	}

	return TRUE;
}


/*
 * nm_device_activation_cancel
 *
 * Signal activation worker that it should stop and die.
 *
 */
void nm_device_activation_cancel (NMDevice *dev)
{
	g_return_if_fail (dev != NULL);

	if (nm_device_is_activating (dev))
	{
		syslog (LOG_DEBUG, "nm_device_activation_cancel(%s): cancelling...", nm_device_get_iface (dev));
		dev->quit_activation = TRUE;

		/* Spin until cancelled.  Possible race conditions or deadlocks here.
		 * The other problem with waiting here is that we hold up dbus traffic
		 * that we should respond to.
		 */
		nm_wait_for_completion(NM_COMPLETION_TRIES_INFINITY, G_USEC_PER_SEC / 20, nm_ac_test, NULL, dev);
		syslog (LOG_DEBUG, "nm_device_activation_cancel(%s): cancelled.", nm_device_get_iface (dev));
	}
}


/*
 * nm_device_deactivate
 *
 * Remove a device's routing table entries and IP address.
 *
 */
gboolean nm_device_deactivate (NMDevice *dev, gboolean just_added)
{
	g_return_val_if_fail (dev  != NULL, FALSE);
	g_return_val_if_fail (dev->app_data != NULL, FALSE);

	nm_device_activation_cancel (dev);

	if (nm_device_get_driver_support_level (dev) == NM_DRIVER_UNSUPPORTED)
		return (TRUE);

	/* Remove any DHCP timeouts that might have been running */
	if (nm_device_config_get_use_dhcp (dev))
		nm_device_dhcp_remove_timeouts (dev);

	/* Take out any entries in the routing table and any IP address the device had. */
	nm_system_device_flush_routes (dev);
	nm_system_device_flush_addresses (dev);
	nm_device_update_ip4_address (dev);

	if (!just_added && (dev == dev->app_data->active_device))
		nm_dbus_signal_device_status_change (dev->app_data->dbus_connection, dev, DEVICE_NO_LONGER_ACTIVE);

	/* Clean up stuff, don't leave the card associated */
	if (nm_device_is_wireless (dev))
	{
		nm_device_set_essid (dev, "");
		nm_device_set_enc_key (dev, NULL, NM_DEVICE_AUTH_METHOD_NONE);
		nm_device_set_mode (dev, NETWORK_MODE_INFRA);
		dev->options.wireless.scan_interval = 20;
	}

	return (TRUE);
}


/*
 * nm_device_set_user_key_for_network
 *
 * Called upon receipt of a NetworkManagerInfo reply with a
 * user-supplied key.
 *
 */
void nm_device_set_user_key_for_network (NMDevice *dev, NMAccessPointList *invalid_list,
									unsigned char *network, unsigned char *key,
									NMEncKeyType enc_type)
{
	NMAccessPoint	*best_ap;
	const char 	*cancel_message = "***canceled***";

	g_return_if_fail (dev != NULL);
	g_return_if_fail (nm_device_is_wireless (dev));
	g_return_if_fail (network != NULL);
	g_return_if_fail (key != NULL);

	/* If the user canceled, mark the ap as invalid */
	if (strncmp (key, cancel_message, strlen (cancel_message)) == 0)
	{
		NMAccessPoint	*ap;

		if ((ap = nm_device_ap_list_get_ap_by_essid (dev, network)))
		{
			NMAccessPoint	*invalid_ap = nm_ap_new_from_ap (ap);
			if (invalid_list)
				nm_ap_list_append_ap (invalid_list, invalid_ap);
		}

		nm_device_update_best_ap (dev);
	}
	else if ((best_ap = nm_device_get_best_ap (dev)))
	{
		/* Make sure the "best" ap matches the essid we asked for the key of,
		 * then set the new key on the access point.
		 */
		if (nm_null_safe_strcmp (network, nm_ap_get_essid (best_ap)) == 0)
			nm_ap_set_enc_key_source (best_ap, key, enc_type);

		nm_ap_unref (best_ap);
	}
	dev->options.wireless.user_key_received = TRUE;
}


/*
 * nm_device_ap_list_add_ap
 *
 * Add an access point to the devices internal AP list.
 *
 */
static void nm_device_ap_list_add_ap (NMDevice *dev, NMAccessPoint *ap)
{
	g_return_if_fail (dev != NULL);
	g_return_if_fail (ap  != NULL);
	g_return_if_fail (nm_device_is_wireless (dev));

	nm_ap_list_append_ap (dev->options.wireless.ap_list, ap);
	/* Transfer ownership of ap to the list by unrefing it here */
	nm_ap_unref (ap);
}


/*
 * nm_device_ap_list_clear
 *
 * Clears out the device's internal list of available access points.
 *
 */
void	nm_device_ap_list_clear (NMDevice *dev)
{
	g_return_if_fail (dev != NULL);
	g_return_if_fail (nm_device_is_wireless (dev));

	if (!dev->options.wireless.ap_list)
		return;

	nm_ap_list_unref (dev->options.wireless.ap_list);
	dev->options.wireless.ap_list = NULL;
}


/*
 * nm_device_ap_list_get_ap_by_essid
 *
 * Get the access point for a specific essid
 *
 */
NMAccessPoint *nm_device_ap_list_get_ap_by_essid (NMDevice *dev, const char *essid)
{
	NMAccessPoint	*ret_ap = NULL;

	g_return_val_if_fail (dev != NULL, NULL);
	g_return_val_if_fail (nm_device_is_wireless (dev), NULL);
	g_return_val_if_fail (essid != NULL, NULL);

	if (!dev->options.wireless.ap_list)
		return (NULL);

	ret_ap = nm_ap_list_get_ap_by_essid (dev->options.wireless.ap_list, essid);

	return (ret_ap);
}


/*
 * nm_device_ap_list_get_ap_by_address
 *
 * Get the access point for a specific MAC address
 *
 */
NMAccessPoint *nm_device_ap_list_get_ap_by_address (NMDevice *dev, const struct ether_addr *addr)
{
	NMAccessPoint	*ret_ap = NULL;

	g_return_val_if_fail (dev != NULL, NULL);
	g_return_val_if_fail (nm_device_is_wireless (dev), NULL);
	g_return_val_if_fail (addr != NULL, NULL);

	if (!dev->options.wireless.ap_list)
		return (NULL);

	ret_ap = nm_ap_list_get_ap_by_address (dev->options.wireless.ap_list, addr);

	return (ret_ap);
}


/*
 * nm_device_ap_list_get
 *
 * Return a pointer to the AP list
 *
 */
NMAccessPointList *nm_device_ap_list_get (NMDevice *dev)
{
	g_return_val_if_fail (dev != NULL, NULL);
	g_return_val_if_fail (nm_device_is_wireless (dev), NULL);

	return (dev->options.wireless.ap_list);
}

/*
 * Get/Set functions for "best" access point
 *
 * Caller MUST unref returned access point when done with it.
 *
 */
NMAccessPoint *nm_device_get_best_ap (NMDevice *dev)
{
	NMAccessPoint	*best_ap;

	g_return_val_if_fail (dev != NULL, NULL);
	g_return_val_if_fail (nm_device_is_wireless (dev), NULL);

	nm_lock_mutex (dev->options.wireless.best_ap_mutex, __FUNCTION__);
	best_ap = dev->options.wireless.best_ap;
	/* Callers get a reffed AP */
	if (best_ap) nm_ap_ref (best_ap);
	nm_unlock_mutex (dev->options.wireless.best_ap_mutex, __FUNCTION__);
	
	return (best_ap);
}

void nm_device_set_best_ap (NMDevice *dev, NMAccessPoint *ap)
{
	g_return_if_fail (dev != NULL);
	g_return_if_fail (nm_device_is_wireless (dev));

	nm_lock_mutex (dev->options.wireless.best_ap_mutex, __FUNCTION__);

	if (dev->options.wireless.best_ap)
		nm_ap_unref (dev->options.wireless.best_ap);

	if (ap)
		nm_ap_ref (ap);

	dev->options.wireless.best_ap = ap;
	nm_device_unfreeze_best_ap (dev);
	nm_unlock_mutex (dev->options.wireless.best_ap_mutex, __FUNCTION__);
}


/*
 * Freeze/unfreeze best ap
 *
 * If the user explicitly picks a network to associate with, we don't
 * change the active network until it goes out of range.
 *
 */
void nm_device_freeze_best_ap (NMDevice *dev)
{
	g_return_if_fail (dev != NULL);
	g_return_if_fail (nm_device_is_wireless (dev));

	dev->options.wireless.freeze_best_ap = TRUE;
}

void nm_device_unfreeze_best_ap (NMDevice *dev)
{
	g_return_if_fail (dev != NULL);
	g_return_if_fail (nm_device_is_wireless (dev));

	dev->options.wireless.freeze_best_ap = FALSE;
}

gboolean nm_device_is_best_ap_frozen (NMDevice *dev)
{
	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (nm_device_is_wireless (dev), FALSE);

	return (dev->options.wireless.freeze_best_ap);
}


/*
 * Accessor for dhcp_interface
 *
 */
struct dhcp_interface *nm_device_get_dhcp_iface (NMDevice *dev)
{
	g_return_val_if_fail (dev != NULL, FALSE);

	return (dev->dhcp_iface);
}

void nm_device_set_dhcp_iface (NMDevice *dev, struct dhcp_interface *dhcp_iface)
{
	g_return_if_fail (dev != NULL);

	/* NOTE: this function should only be used from the activation worker thread
	 * which will take care of shutting down any active DHCP threads and cleaning
	 * up the dev->dhcp_iface structure.
	 */

	dev->dhcp_iface = dhcp_iface;
}


/*
 * nm_device_get_path_for_ap
 *
 * Return the object path for an access point.
 *
 * NOTE: assumes the access point is actually in the device's access point list.
 *
 */
char * nm_device_get_path_for_ap (NMDevice *dev, NMAccessPoint *ap)
{
	g_return_val_if_fail (dev != NULL, NULL);
	g_return_val_if_fail (ap  != NULL, NULL);

	if (nm_ap_get_essid (ap))
		return (g_strdup_printf ("%s/%s/Networks/%s", NM_DBUS_PATH_DEVICES, nm_device_get_iface (dev), nm_ap_get_essid (ap)));
	else
		return (NULL);
}


/*
 * nm_device_need_ap_switch
 *
 * Returns TRUE if the essid of the card does not match the essid
 * of the "best" access point it should be associating with.
 *
 */
gboolean nm_device_need_ap_switch (NMDevice *dev)
{
	NMAccessPoint	*ap;
	gboolean		 need_switch = FALSE;

	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (nm_device_is_wireless (dev), FALSE);


	/* Since the card's ESSID may change during a scan, we can't really
	 * rely on checking the ESSID during that time.
	 */
	if (!nm_try_acquire_mutex (dev->options.wireless.scan_mutex, __FUNCTION__))
		return FALSE;

	ap = nm_device_get_best_ap (dev);
	if (nm_null_safe_strcmp (nm_device_get_essid (dev), (ap ? nm_ap_get_essid (ap) : NULL)) != 0)
		need_switch = TRUE;

	if (ap)
		nm_ap_unref (ap);
	nm_unlock_mutex (dev->options.wireless.scan_mutex, __FUNCTION__);

	return (need_switch);
}


/*
 * nm_device_update_best_ap
 *
 * Recalculate the "best" access point we should be associating with.  This
 * function may disrupt the current connection, so it should be called only
 * when necessary, ie when the current access point is no longer in range
 * or is for some other reason invalid and should no longer be used.
 *
 */
void nm_device_update_best_ap (NMDevice *dev)
{
	NMAccessPointList	*ap_list;
	NMAPListIter		*iter;
	NMAccessPoint		*scan_ap = NULL;
	NMAccessPoint		*best_ap = NULL;
	NMAccessPoint		*trusted_best_ap = NULL;
	NMAccessPoint		*untrusted_best_ap = NULL;
	GTimeVal			 trusted_latest_timestamp = {0, 0};
	GTimeVal			 untrusted_latest_timestamp = {0, 0};

	g_return_if_fail (dev != NULL);
	g_return_if_fail (dev->app_data != NULL);
	g_return_if_fail (nm_device_is_wireless (dev));

	if (!(ap_list = nm_device_ap_list_get (dev)))
		return;

	/* Iterate over the device's ap list to make sure the current
	 * "best" ap is still in the device's ap list (so that if its
	 * not, we can "unfreeze" the best ap if its been frozen already).
	 * If it is, we don't change the best ap here.
	 */
	if (nm_device_is_best_ap_frozen (dev))
	{
		best_ap = nm_device_get_best_ap (dev);

		/* If its in the device's ap list still, don't change the
		 * best ap, since its frozen.
		 */
		nm_lock_mutex (dev->options.wireless.best_ap_mutex, __FUNCTION__);
		if (best_ap)
		{
			char *essid = nm_ap_get_essid (best_ap);
			/* Two reasons to keep the current best_ap:
			 * 1) Its still valid and we see it in our scan data
			 * 2) Its an ad-hoc network that we've created (and therefore its not in our scan data)
			 */
			if (    (    !nm_ap_list_get_ap_by_essid (dev->app_data->invalid_ap_list, essid)
					&& nm_device_ap_list_get_ap_by_essid (dev, essid))
				|| nm_ap_get_user_created (best_ap))
			{
				nm_ap_unref (best_ap);
				nm_unlock_mutex (dev->options.wireless.best_ap_mutex, __FUNCTION__);
				return;
			}
			nm_ap_unref (best_ap);
		}

		/* Otherwise, its gone away and we don't care about it anymore */
		nm_device_unfreeze_best_ap (dev);
		nm_unlock_mutex (dev->options.wireless.best_ap_mutex, __FUNCTION__);
	}

	if (!(iter = nm_ap_list_iter_new (ap_list)))
		return;
	while ((scan_ap = nm_ap_list_iter_next (iter)))
	{
		NMAccessPoint	*tmp_ap;
		char			*ap_essid = nm_ap_get_essid (scan_ap);

		/* Access points in the "invalid" list cannot be used */
		if (nm_ap_list_get_ap_by_essid (dev->app_data->invalid_ap_list, ap_essid))
			continue;

		if ((tmp_ap = nm_ap_list_get_ap_by_essid (dev->app_data->allowed_ap_list, ap_essid)))
		{
			const GTimeVal *curtime = nm_ap_get_timestamp (tmp_ap);

			if (nm_ap_get_trusted (tmp_ap) && (curtime->tv_sec > trusted_latest_timestamp.tv_sec))
			{
				trusted_latest_timestamp = *nm_ap_get_timestamp (tmp_ap);
				trusted_best_ap = scan_ap;
				/* Merge access point data (mainly to get updated WEP key) */
				nm_ap_set_enc_key_source (trusted_best_ap, nm_ap_get_enc_key_source (tmp_ap), nm_ap_get_enc_type (tmp_ap));
			}
			else if (!nm_ap_get_trusted (tmp_ap) && (curtime->tv_sec > untrusted_latest_timestamp.tv_sec))
			{
				untrusted_latest_timestamp = *nm_ap_get_timestamp (tmp_ap);
				untrusted_best_ap = scan_ap;
				/* Merge access point data (mainly to get updated WEP key) */
				nm_ap_set_enc_key_source (untrusted_best_ap, nm_ap_get_enc_key_source (tmp_ap), nm_ap_get_enc_type (tmp_ap));
			}
		}
	}
	best_ap = trusted_best_ap ? trusted_best_ap : untrusted_best_ap;
	nm_ap_list_iter_free (iter);

	nm_device_set_best_ap (dev, best_ap);
}


typedef struct NMDeviceForceData
{
	NMDevice		*dev;
	const char	*net;
	const char	*key;
	NMEncKeyType	 key_type;
} NMDeviceForceData;


static gboolean nm_device_wireless_force_use (NMDevice *dev, const char *essid, const char *key, NMEncKeyType key_type)
{
	gboolean			 encrypted = FALSE;
	NMAccessPoint		*ap = NULL;
	NMAccessPoint		*tmp_ap = NULL;

	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (dev->app_data != NULL, FALSE);

	if (!essid)
		return FALSE;

	syslog (LOG_DEBUG, "Forcing AP '%s'", essid);

	if (    key
		&& strlen (key)
		&& (key_type != NM_ENC_TYPE_UNKNOWN)
		&& (key_type != NM_ENC_TYPE_NONE))
		encrypted = TRUE;

	/* Find the AP in our card's scan list first.
	 * If its not there, create an entirely new AP.
	 */
	if (!(ap = nm_ap_list_get_ap_by_essid (nm_device_ap_list_get (dev), essid)))
	{
		/* Okay, the card didn't see it in the scan, Cisco cards sometimes do this.
		 * So we make a "fake" access point and add it to the scan list.
		 */
		ap = nm_ap_new ();
		nm_ap_set_essid (ap, essid);
		nm_ap_set_encrypted (ap, encrypted);		
		if (encrypted)
			nm_ap_set_auth_method (ap, NM_DEVICE_AUTH_METHOD_OPEN_SYSTEM);
		else
			nm_ap_set_auth_method (ap, NM_DEVICE_AUTH_METHOD_NONE);
		nm_ap_set_artificial (ap, TRUE);
		nm_ap_list_append_ap (nm_device_ap_list_get (dev), ap);
		nm_ap_unref (ap);
	}

	/* Now that this AP has an essid, copy over encryption keys and whatnot */
	if ((tmp_ap = nm_ap_list_get_ap_by_essid (dev->app_data->allowed_ap_list, nm_ap_get_essid (ap))))
	{
		nm_ap_set_enc_key_source (ap, nm_ap_get_enc_key_source (tmp_ap), nm_ap_get_enc_type (tmp_ap));
		nm_ap_set_auth_method (ap, nm_ap_get_auth_method (tmp_ap));
		nm_ap_set_invalid (ap, nm_ap_get_invalid (tmp_ap));
		nm_ap_set_timestamp (ap, nm_ap_get_timestamp (tmp_ap));
	}

	/* Use the encryption key and type the user sent us if its valid */
	if (encrypted)
		nm_ap_set_enc_key_source (ap, key, key_type);

	nm_device_set_best_ap (dev, ap);
	nm_device_freeze_best_ap (dev);

	return TRUE;
}


gboolean nm_device_wired_force_use (NMDevice *dev)
{
	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (dev->app_data != NULL, FALSE);

	return TRUE;
}


gboolean nm_device_force_use (gpointer user_data)
{
	NMDeviceForceData	*cb_data = (NMDeviceForceData *)user_data;
	NMData			*app_data = NULL;
	gboolean			 success = FALSE;

	g_return_val_if_fail (cb_data != NULL, FALSE);

	if (!cb_data->dev || !cb_data->dev->app_data)
		goto out;
	
	app_data = cb_data->dev->app_data;
	if (nm_device_is_wireless (cb_data->dev))
		success = nm_device_wireless_force_use (cb_data->dev, cb_data->net, cb_data->key, cb_data->key_type);
	else if (nm_device_is_wired (cb_data->dev))
		success = nm_device_wired_force_use (cb_data->dev);

	if (success)
		nm_policy_schedule_device_switch (cb_data->dev, cb_data->dev->app_data);
	
out:
	/* Function that scheduled us must ref the device */
	nm_device_unref (cb_data->dev);

	app_data->forcing_device = FALSE;
	g_free (cb_data);
	return FALSE;
}


void nm_device_schedule_force_use (NMDevice *dev, const char *network, const char *key, NMEncKeyType key_type)
{
	NMDeviceForceData	*cb_data;
	GSource			*source;

	g_return_if_fail (dev != NULL);
	g_return_if_fail (dev->app_data != NULL);
	g_return_if_fail (dev->app_data->main_context != NULL);

	cb_data = g_malloc0 (sizeof (NMDeviceForceData));
	cb_data->dev = dev;
	cb_data->net = network ? g_strdup (network) : NULL;
	cb_data->key = key ? g_strdup (key) : NULL;
	cb_data->key_type = key_type;

	source = g_idle_source_new ();
	g_source_set_callback (source, nm_device_force_use, cb_data, NULL);
	g_source_attach (source, dev->context);
	g_source_unref (source);
}


/*
 * nm_device_do_pseudo_scan
 *
 * Brute-force the allowed access point list to find one that works, if any.
 *
 * FIXME
 * There's probably a better way to do the non-scanning access point discovery
 * than brute forcing it like this, but that makes the state machine here oh so
 * much more complicated.
 */
static void nm_device_do_pseudo_scan (NMDevice *dev)
{
	NMAPListIter		*iter;
	NMAccessPoint		*ap;

	g_return_if_fail (dev  != NULL);
	g_return_if_fail (dev->app_data != NULL);

	/* Test devices shouldn't get here since we fake the AP list earlier */
	g_return_if_fail (!dev->test_device);

	nm_device_ref (dev);

	if (!(iter = nm_ap_list_iter_new (dev->app_data->allowed_ap_list)))
		return;

	nm_device_set_essid (dev, "");
	while ((ap = nm_ap_list_iter_next (iter)))
	{
		gboolean			valid = FALSE;
		struct ether_addr	save_ap_addr;
		struct ether_addr	cur_ap_addr;

		if (!nm_device_is_up (dev));
			nm_device_bring_up (dev);

		/* Save the MAC address */
		nm_device_get_ap_address (dev, &save_ap_addr);

		if (nm_ap_get_enc_key_source (ap))
		{
			char *hashed_key = nm_ap_get_enc_key_hashed (ap);
			nm_device_set_enc_key (dev, hashed_key, NM_DEVICE_AUTH_METHOD_SHARED_KEY);
			g_free (hashed_key);
		}
		else
			nm_device_set_enc_key (dev, NULL, NM_DEVICE_AUTH_METHOD_NONE);
		nm_device_set_essid (dev, nm_ap_get_essid (ap));

		/* Wait a bit for association */
		nm_device_is_up_and_associated_wait (dev, 2, 100);

		/* Do we have a valid MAC address? */
		nm_device_get_ap_address (dev, &cur_ap_addr);
		valid = nm_ethernet_address_is_valid (&cur_ap_addr);

		/* If the ap address we had before, and the ap address we
		 * have now, are the same, AP is invalid.  Certain cards (orinoco)
		 * will let the essid change, but the the card won't actually de-associate
		 * from the previous access point if it can't associate with the new one
		 * (ie signal too weak, etc).
		 */
		if (valid && (memcmp (&save_ap_addr, &cur_ap_addr, sizeof (struct ether_addr)) == 0))
			valid = FALSE;

		if (valid)
		{
			syslog(LOG_INFO, "%s: setting AP '%s' best", nm_device_get_iface (dev), nm_ap_get_essid (ap));

			nm_device_set_best_ap (dev, ap);
			nm_policy_schedule_state_update (dev->app_data);
			break;
		}
	}

	nm_ap_list_iter_free (iter);
	nm_device_unref (dev);
}


/*
 * nm_device_fake_ap_list
 *
 * Fake the access point list, used for test devices.
 *
 */
static void nm_device_fake_ap_list (NMDevice *dev)
{
	#define NUM_FAKE_APS	4

	int				 i;
	NMAccessPointList	*old_ap_list = nm_device_ap_list_get (dev);

	char				*fake_essids[NUM_FAKE_APS] = { "green", "bay", "packers", "rule" };
	struct ether_addr	 fake_addrs[NUM_FAKE_APS] =  {{{0x70, 0x37, 0x03, 0x70, 0x37, 0x03}},
											{{0x12, 0x34, 0x56, 0x78, 0x90, 0xab}},
											{{0xcd, 0xef, 0x12, 0x34, 0x56, 0x78}},
											{{0x90, 0xab, 0xcd, 0xef, 0x12, 0x34}} };
	guint8			 fake_qualities[NUM_FAKE_APS] = { 150, 26, 200, 100 };
	double			 fake_freqs[NUM_FAKE_APS] = { 3.1416, 4.1416, 5.1415, 6.1415 };
	gboolean			 fake_enc[NUM_FAKE_APS] = { FALSE, TRUE, FALSE, TRUE };

	g_return_if_fail (dev != NULL);
	g_return_if_fail (dev->app_data != NULL);

	dev->options.wireless.ap_list = nm_ap_list_new (NETWORK_TYPE_DEVICE);

	for (i = 0; i < NUM_FAKE_APS; i++)
	{
		NMAccessPoint		*nm_ap  = nm_ap_new ();
		NMAccessPoint		*list_ap;

		/* Copy over info from scan to local structure */
		nm_ap_set_essid (nm_ap, fake_essids[i]);

		if (fake_enc[i])
			nm_ap_set_encrypted (nm_ap, FALSE);
		else
			nm_ap_set_encrypted (nm_ap, TRUE);

		nm_ap_set_address (nm_ap, (const struct ether_addr *)(&fake_addrs[i]));
		nm_ap_set_strength (nm_ap, fake_qualities[i]);
		nm_ap_set_freq (nm_ap, fake_freqs[i]);

		/* Merge settings from wireless networks, mainly keys */
		if ((list_ap = nm_ap_list_get_ap_by_essid (dev->app_data->allowed_ap_list, nm_ap_get_essid (nm_ap))))
		{
			nm_ap_set_timestamp (nm_ap, nm_ap_get_timestamp (list_ap));
			nm_ap_set_enc_key_source (nm_ap, nm_ap_get_enc_key_source (list_ap), nm_ap_get_enc_type (list_ap));
		}

		/* Add the AP to the device's AP list */
		nm_device_ap_list_add_ap (dev, nm_ap);
	}

	if (dev == dev->app_data->active_device)
		nm_ap_list_diff (dev->app_data, dev, old_ap_list, nm_device_ap_list_get (dev));
	if (old_ap_list)
		nm_ap_list_unref (old_ap_list);
}


/*
 * nm_device_wireless_schedule_scan
 *
 * Schedule a wireless scan in the /device's/ thread.
 *
 */
static void nm_device_wireless_schedule_scan (NMDevice *dev)
{
	GSource	*wscan_source;
	guint	 wscan_source_id;

	g_return_if_fail (dev != NULL);
	g_return_if_fail (nm_device_is_wireless (dev));

	wscan_source = g_timeout_source_new (dev->options.wireless.scan_interval * 1000);
	g_source_set_callback (wscan_source, nm_device_wireless_scan, dev, NULL);
	wscan_source_id = g_source_attach (wscan_source, dev->context);
	g_source_unref (wscan_source);
}


/*
 * nm_device_wireless_process_scan_results
 *
 * Process results of an iwscan() into our own AP lists.  We're an idle function,
 * but we never reschedule ourselves.
 *
 */
static gboolean nm_device_wireless_process_scan_results (gpointer user_data)
{
	NMWirelessScanResults	*results = (NMWirelessScanResults *)user_data;
	NMDevice				*dev;
	wireless_scan			*tmp_ap;
	gboolean				 have_blank_essids = FALSE;
	NMAPListIter			*iter;
	GTimeVal				 cur_time;
	gboolean				 list_changed = FALSE;

	g_return_val_if_fail (results != NULL, FALSE);	

	dev = results->dev;

	if (!dev || !results->scan_head.result)
		return FALSE;

	/* Test devices get their info faked */
	if (dev->test_device)
	{
		nm_device_fake_ap_list (dev);
		return FALSE;
	}

	/* Devices that don't support scanning have their pseudo-scanning done in
	 * the main thread anyway.
	 */
	if (!nm_device_get_supports_wireless_scan (dev))
	{
		nm_device_do_pseudo_scan (dev);
		return FALSE;
	}

	g_get_current_time (&cur_time);

	/* Translate iwlib scan results to NM access point list */
	for (tmp_ap = results->scan_head.result; tmp_ap; tmp_ap = tmp_ap->next)
	{
		/* We need at least an ESSID or a MAC address for each access point */
		if (tmp_ap->b.has_essid || tmp_ap->has_ap_addr)
		{
			NMAccessPoint		*nm_ap  = nm_ap_new ();
			int				 percent;
			gboolean			 new = FALSE;
			gboolean			 strength_changed = FALSE;
			gboolean			 success = FALSE;

			/* Copy over info from scan to local structure */

			/* ipw2x00 drivers fill in an essid of "<hidden>" if they think the access point
			 * is hiding its MAC address.  Sigh.
			 */
			if (    !tmp_ap->b.has_essid
				|| (tmp_ap->b.essid && !strlen (tmp_ap->b.essid))
				|| (tmp_ap->b.essid && !strcmp (tmp_ap->b.essid, "<hidden>")))	/* Stupid ipw drivers use <hidden> */
				nm_ap_set_essid (nm_ap, NULL);
			else
				nm_ap_set_essid (nm_ap, tmp_ap->b.essid);

			if (tmp_ap->b.has_key && (tmp_ap->b.key_flags & IW_ENCODE_DISABLED))
			{
				nm_ap_set_encrypted (nm_ap, FALSE);
				nm_ap_set_auth_method (nm_ap, NM_DEVICE_AUTH_METHOD_NONE);
			}
			else
			{
				nm_ap_set_encrypted (nm_ap, TRUE);
				nm_ap_set_auth_method (nm_ap, NM_DEVICE_AUTH_METHOD_OPEN_SYSTEM);
			}

			if (tmp_ap->has_ap_addr)
				nm_ap_set_address (nm_ap, (const struct ether_addr *)(tmp_ap->ap_addr.sa_data));

			if (tmp_ap->b.has_mode)
			{
				NMNetworkMode mode = NETWORK_MODE_INFRA;
				switch (tmp_ap->b.mode)
				{
					case IW_MODE_INFRA:
						mode = NETWORK_MODE_INFRA;
						break;
					case IW_MODE_ADHOC:
						mode = NETWORK_MODE_ADHOC;
						break;
					default:
						mode = NETWORK_MODE_INFRA;
						break;
				}
				nm_ap_set_mode (nm_ap, mode);
			}
			else
				nm_ap_set_mode (nm_ap, NETWORK_MODE_INFRA);

			percent = nm_wireless_qual_to_percent (&(tmp_ap->stats.qual),
							(const iwqual *)(&dev->options.wireless.max_qual),
							(const iwqual *)(&dev->options.wireless.avg_qual));
			nm_ap_set_strength (nm_ap, percent);

			if (tmp_ap->b.has_freq)
				nm_ap_set_freq (nm_ap, tmp_ap->b.freq);

			nm_ap_set_last_seen (nm_ap, &cur_time);

			/* If the AP is not broadcasting its ESSID, try to fill it in here from our
			 * allowed list where we cache known MAC->ESSID associations.
			 */
			if (!nm_ap_get_essid (nm_ap))
				nm_ap_list_copy_one_essid_by_address (nm_ap, dev->app_data->allowed_ap_list);

			/* Add the AP to the device's AP list */
			success = nm_ap_list_merge_scanned_ap (nm_device_ap_list_get (dev), nm_ap, &new, &strength_changed);
			if (success)
			{
				/* Handle dbus signals that we need to broadcast when the AP is added to the list or changes
				 * strength.
				*/
				if (new)
				{
					nm_dbus_signal_wireless_network_change	(dev->app_data->dbus_connection, dev, nm_ap,
								NETWORK_STATUS_APPEARED, -1);
					list_changed = TRUE;
				}
				else if (strength_changed)
				{
					nm_dbus_signal_wireless_network_change	(dev->app_data->dbus_connection, dev, nm_ap,
								NETWORK_STATUS_STRENGTH_CHANGED, nm_ap_get_strength (nm_ap));
				}
			}
			nm_ap_unref (nm_ap);
		}
	}	

	/* Once we have the list, copy in any relevant information from our Allowed list. */
	nm_ap_list_copy_properties (nm_device_ap_list_get (dev), dev->app_data->allowed_ap_list);

	/* Walk the access point list and remove any access points older than 120s */
	g_get_current_time (&cur_time);
	if (nm_device_ap_list_get (dev) && (iter = nm_ap_list_iter_new (nm_device_ap_list_get (dev))))
	{
		NMAccessPoint	*outdated_ap;
		GSList		*outdated_list = NULL;
		GSList		*elt;
		NMAccessPoint	*best_ap = nm_device_get_best_ap (dev);

		while ((outdated_ap = nm_ap_list_iter_next (iter)))
		{
			const GTimeVal	*ap_time = nm_ap_get_last_seen (outdated_ap);
			gboolean		 keep_around = FALSE;

			/* Don't ever get prune the AP we're currently associated with */
			if (	    nm_ap_get_essid (outdated_ap)
				&&  (best_ap && (nm_null_safe_strcmp (nm_ap_get_essid (best_ap), nm_ap_get_essid (outdated_ap))) == 0))
				keep_around = TRUE;

			if (!keep_around && (ap_time->tv_sec + 120 < cur_time.tv_sec))
				outdated_list = g_slist_append (outdated_list, outdated_ap);
		}
		nm_ap_list_iter_free (iter);

		/* nm_device_get_best_ap() refs the ap */
		if (best_ap)
			nm_ap_unref (best_ap);

		/* Ok, now remove outdated ones.  We have to do it after the lock
		 * because nm_ap_list_remove_ap() locks the list too.
		 */
		for (elt = outdated_list; elt; elt = g_slist_next (elt))
		{
			if ((outdated_ap = (NMAccessPoint *)(elt->data)))
			{
				nm_dbus_signal_wireless_network_change	(dev->app_data->dbus_connection, dev, outdated_ap, NETWORK_STATUS_DISAPPEARED, -1);
				nm_ap_list_remove_ap (nm_device_ap_list_get (dev), outdated_ap);
				list_changed = TRUE;
			}
		}
		g_slist_free (outdated_list);
	}

	/* If the list changed, decrease our wireless scanning interval */
	if (list_changed)
		dev->options.wireless.scan_interval = 20;
	else
		dev->options.wireless.scan_interval = MIN (60, dev->options.wireless.scan_interval + 10);

	return FALSE;
}


static gboolean nm_completion_scan_has_results (int tries, va_list args)
{
	NMDevice				*dev = va_arg (args, NMDevice *);
	gboolean				*err = va_arg (args, gboolean *);
	int					 sk = va_arg (args, int);
	NMWirelessScanResults	*scan_results = va_arg (args, NMWirelessScanResults *);
	int					 rc;

	g_return_val_if_fail (dev != NULL, TRUE);
	g_return_val_if_fail (err != NULL, TRUE);
	g_return_val_if_fail (scan_results != NULL, TRUE);

	rc = iw_scan(sk, (char *)nm_device_get_iface (dev), WIRELESS_EXT, &(scan_results->scan_head));
	if (rc == -1 && errno == ETIME)
	{
		syslog (LOG_DEBUG, "Warning: the wireless card (%s) requires too much time for scans.  Its driver needs to be fixed.", nm_device_get_iface (dev));
		scan_results->scan_head.result = NULL;
		*err = TRUE;
		return TRUE;
	}
	*err = FALSE;
	if ((rc == -1 && errno == ENODATA) || (rc == 0 && scan_results->scan_head.result == NULL))
	{
		/* Card hasn't had time yet to compile full access point list.
		 * Give it some more time and scan again.  If that doesn't
		 * work, we eventually give up.  */
		scan_results->scan_head.result = NULL;
		return FALSE;
	}
	else if (rc == -1)
	{
		scan_results->scan_head.result = NULL;
		return TRUE;
	}
	return TRUE;
}


/*
 * nm_device_wireless_scan
 *
 * Get a list of access points this device can see.
 *
 */
static gboolean nm_device_wireless_scan (gpointer user_data)
{
	NMDevice 				*dev = (NMDevice *)(user_data);
	int			 		 sk;
	NMWirelessScanResults	*scan_results = NULL;

	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (dev->app_data != NULL, FALSE);

	/* We don't scan on test devices or devices that don't have scanning support */
	if (dev->test_device || !nm_device_get_supports_wireless_scan (dev))
		return FALSE;

	/* Just reschedule ourselves if scanning or all wireless is disabled */
	if (    (dev->app_data->scanning_enabled == FALSE)
		|| (dev->app_data->wireless_enabled == FALSE))
	{
		dev->options.wireless.scan_interval = 10;
		goto reschedule;
	}

	/* Grab the scan mutex */
	if (nm_try_acquire_mutex (dev->options.wireless.scan_mutex, __FUNCTION__))
	{
		gboolean devup_err;

		/* Device must be up before we can scan */
		devup_err = nm_device_bring_up_wait(dev, 1);
		if (devup_err)
		{
			nm_unlock_mutex (dev->options.wireless.scan_mutex, __FUNCTION__);
			nm_device_wireless_schedule_scan (dev);
			return FALSE;
		}

		if ((sk = iw_sockets_open ()) >= 0)
		{
			int			err;
			NMNetworkMode	orig_mode = NETWORK_MODE_INFRA;
			double		orig_freq = 0;
			int			orig_rate = 0;
			const int		max_wait = G_USEC_PER_SEC * nm_device_get_association_pause_value (dev) /2;

			orig_mode = nm_device_get_mode (dev);
			if (orig_mode == NETWORK_MODE_ADHOC)
			{
				orig_freq = nm_device_get_frequency (dev);
				orig_rate = nm_device_get_bitrate (dev);
			}

			/* Must be in infrastructure mode during scan, otherwise we don't get a full
			 * list of scan results.  Scanning doesn't work well in Ad-Hoc mode :( 
			 */
			nm_device_set_mode (dev, NETWORK_MODE_INFRA);
			nm_device_set_frequency (dev, 0);

			scan_results = g_malloc0 (sizeof (NMWirelessScanResults));
			nm_wait_for_completion(max_wait, max_wait/20,
				nm_completion_scan_has_results, NULL,
				dev, &err, sk, scan_results);

			nm_device_set_mode (dev, orig_mode);
			/* Only set frequency if ad-hoc mode */
			if (orig_mode == NETWORK_MODE_ADHOC)
			{
				nm_device_set_frequency (dev, orig_freq);
				nm_device_set_bitrate (dev, orig_rate);
			}

			close (sk);
		}
		nm_unlock_mutex (dev->options.wireless.scan_mutex, __FUNCTION__);
	}

	/* We run the scan processing function from the main thread, since it must deliver
	 * messages over DBUS.  Plus, that way the main thread is the only thread that has
	 * to modify the device's access point list.
	 */
	if ((scan_results != NULL) && (scan_results->scan_head.result != NULL))
	{
		guint	 scan_process_source_id = 0;
		GSource	*scan_process_source = g_idle_source_new ();

		scan_results->dev = dev;
		g_source_set_callback (scan_process_source, nm_device_wireless_process_scan_results, scan_results, NULL);
		scan_process_source_id = g_source_attach (scan_process_source, dev->app_data->main_context);
		g_source_unref (scan_process_source);
	}

reschedule:
	/* Make sure we reschedule ourselves so we keep scanning */
	nm_device_wireless_schedule_scan (dev);

	return FALSE;
}


/* System config data accessors */

gboolean nm_device_config_get_use_dhcp (NMDevice *dev)
{
	g_return_val_if_fail (dev != NULL, 0);

	return (dev->config_info.use_dhcp);
}

void nm_device_config_set_use_dhcp (NMDevice *dev, gboolean use_dhcp)
{
	g_return_if_fail (dev != NULL);

	dev->config_info.use_dhcp = use_dhcp;
}

guint32 nm_device_config_get_ip4_address (NMDevice *dev)
{
	g_return_val_if_fail (dev != NULL, 0);

	return (dev->config_info.ip4_address);
}

void nm_device_config_set_ip4_address (NMDevice *dev, guint32 addr)
{
	g_return_if_fail (dev != NULL);

	dev->config_info.ip4_address = addr;
}

guint32 nm_device_config_get_ip4_gateway (NMDevice *dev)
{
	g_return_val_if_fail (dev != NULL, 0);

	return (dev->config_info.ip4_gateway);
}

void nm_device_config_set_ip4_gateway (NMDevice *dev, guint32 gateway)
{
	g_return_if_fail (dev != NULL);

	dev->config_info.ip4_gateway = gateway;
}

guint32 nm_device_config_get_ip4_netmask (NMDevice *dev)
{
	g_return_val_if_fail (dev != NULL, 0);

	return (dev->config_info.ip4_netmask);
}

void nm_device_config_set_ip4_netmask (NMDevice *dev, guint32 netmask)
{
	g_return_if_fail (dev != NULL);

	dev->config_info.ip4_netmask = netmask;
}
guint32 nm_device_config_get_ip4_broadcast (NMDevice *dev)
{
	g_return_val_if_fail (dev != NULL, 0);

	return (dev->config_info.ip4_broadcast);
}

void nm_device_config_set_ip4_broadcast (NMDevice *dev, guint32 broadcast)
{
	g_return_if_fail (dev != NULL);

	dev->config_info.ip4_broadcast = broadcast;
}


/* Define types for stupid headers */
typedef u_int8_t u8;
typedef u_int16_t u16;
typedef u_int32_t u32;
typedef u_int64_t u64;


/**************************************/
/*    Ethtool capability detection    */
/**************************************/
#include <linux/sockios.h>
#include <linux/ethtool.h>

static gboolean supports_ethtool_carrier_detect (NMDevice *dev)
{
	int				sk;
	struct ifreq		ifr;
	gboolean			supports_ethtool = FALSE;
	struct ethtool_cmd	edata;

	g_return_val_if_fail (dev != NULL, FALSE);

	if ((sk = socket (AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		syslog (LOG_ERR, "cannot open socket on interface %s for MII detect; errno=%d", nm_device_get_iface (dev), errno);
		return (FALSE);
	}

	strncpy (ifr.ifr_name, nm_device_get_iface (dev), sizeof(ifr.ifr_name)-1);
	edata.cmd = ETHTOOL_GLINK;
	ifr.ifr_data = (char *) &edata;
	if (ioctl(sk, SIOCETHTOOL, &ifr) == -1)
		goto out;

	supports_ethtool = TRUE;

out:
	close (sk);
	return (supports_ethtool);
}



/**************************************/
/*    MII capability detection        */
/**************************************/
#include <linux/mii.h>

static int mdio_read (int sk, struct ifreq *ifr, int location)
{
	struct mii_ioctl_data *mii;

	g_return_val_if_fail (sk >= 0, -1);
	g_return_val_if_fail (ifr != NULL, -1);

	mii = (struct mii_ioctl_data *) &(ifr->ifr_data);
	mii->reg_num = location;

	if (ioctl (sk, SIOCGMIIREG, ifr) < 0)
		return -1;

	return (mii->val_out);
}

static gboolean supports_mii_carrier_detect (NMDevice *dev)
{
	int			sk;
	struct ifreq	ifr;
	int			bmsr;
	gboolean		supports_mii = FALSE;

	g_return_val_if_fail (dev != NULL, FALSE);

	if ((sk = socket (AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		syslog (LOG_ERR, "cannot open socket on interface %s for MII detect; errno=%d", nm_device_get_iface (dev), errno);
		return (FALSE);
	}

	strncpy (ifr.ifr_name, nm_device_get_iface (dev), sizeof(ifr.ifr_name)-1);
	if (ioctl(sk, SIOCGMIIPHY, &ifr) < 0)
		goto out;

	/* If we can read the BMSR register, we assume that the card supports MII link detection */
	bmsr = mdio_read(sk, &ifr, MII_BMSR);
	supports_mii = (bmsr != -1) ? TRUE : FALSE;

out:
	close (sk);
	return (supports_mii);	
}

/****************************************/
/* End Code ripped from HAL             */
/****************************************/


/****************************************/
/* Test device routes                   */
/****************************************/

/*
 * nm_device_is_test_device
 *
 */
gboolean nm_device_is_test_device (NMDevice *dev)
{
	g_return_val_if_fail (dev != NULL, FALSE);

	return (dev->test_device);
}
