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
#include <hal/libhal.h>
#include <iwlib.h>
#include <signal.h>
#include <string.h>

#include "NetworkManager.h"
#include "NetworkManagerMain.h"
#include "NetworkManagerDevice.h"
#include "NetworkManagerUtils.h"
#include "NetworkManagerDbus.h"
#include "NetworkManagerWireless.h"
#include "NetworkManagerPolicy.h"
#include "NetworkManagerAPList.h"
#include "backends/NetworkManagerSystem.h"

extern gboolean	debug;

/* Local static prototypes */
static gboolean mii_get_link (NMDevice *dev);
static gpointer nm_device_activation_worker (gpointer user_data);


/******************************************************/

/* Wireless device specific options */
typedef struct NMDeviceWirelessOptions
{
	char				*cur_essid;
	gboolean			 supports_wireless_scan;
	guint8			 max_quality;
	guint8			 noise;
	gint8			 strength;

	GMutex			*scan_mutex;
	/* We keep a couple lists around since wireless cards
	 * are a bit flakey and don't report the same access
	 * points every time.  The lists get merged and diffed
	 * to figure out the "real" list, but the latest_ap_list
	 * is always the most-current scan.
	 */
	NMAccessPointList	*ap_list;
	NMAccessPointList	*cached_ap_list1;
	NMAccessPointList	*cached_ap_list2;
	NMAccessPointList	*cached_ap_list3;
	NMAccessPointList	*cached_ap_list4;

	NMAccessPoint		*best_ap;
	GMutex			*best_ap_mutex;
	gboolean			 freeze_best_ap;

	gboolean			 user_key_received;
	gboolean			 now_scanning;
} NMDeviceWirelessOptions;

/* Wired device specific options */
typedef struct NMDeviceWiredOptions
{
	int	foo;
} NMDeviceWiredOptions;

typedef union NMDeviceOptions
{
	NMDeviceWirelessOptions	wireless;
	NMDeviceWiredOptions	wired;
} NMDeviceOptions;


typedef struct NMDeviceConfigInfo
{
	gboolean	 use_dhcp;
	guint32	 ip4_gateway;
	guint32	 ip4_address;
	guint32	 ip4_netmask;
	guint32  ip4_broadcast;
	/* FIXME: ip6 stuff */
} NMDeviceConfigInfo;

/*
 * NetworkManager device structure
 */
struct NMDevice
{
	guint			 refcount;

	char				*udi;
	char				*iface;
	NMDeviceType		 type;
	NMDriverSupportLevel driver_support_level;

	gboolean			 link_active;
	guint32			 ip4_address;
	/* FIXME: ipv6 address too */
	NMData			*app_data;
	NMDeviceOptions	 options;
	NMDeviceConfigInfo	 config_info;

	gboolean			 activating;		/* Set by main thread before beginning activation */
	gboolean			 just_activated;	/* Set by activation thread after successful activation */
	gboolean			 quit_activation;	/* Flag to signal activation thread to stop activating */

	gboolean			 test_device;
	gboolean			 test_device_up;
};

/******************************************************/

/*
 * nm_device_test_wireless_extensions
 *
 * Test whether a given device is a wireless one or not.
 *
 */
static gboolean nm_device_test_wireless_extensions (NMDevice *dev)
{
	int		iwlib_socket;
	int		error;
	iwstats	stats;
	
	g_return_val_if_fail (dev != NULL, FALSE);

	/* We obviously cannot probe test devices (since they don't
	 * actually exist in hardware).
	 */
	if (dev->test_device)
		return (FALSE);

	iwlib_socket = iw_sockets_open ();
	error = iw_get_stats (iwlib_socket, nm_device_get_iface (dev), &stats, NULL, FALSE);
	close (iwlib_socket);
	return (error == 0);
}


/*
 * nm_device_supports_wireless_scan
 *
 * Test whether a given device is a wireless one or not.
 *
 */
static gboolean nm_device_supports_wireless_scan (NMDevice *dev)
{
	int					iwlib_socket;
	int					error;
	gboolean				can_scan = TRUE;
	wireless_scan_head		scan_data;
	
	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (dev->type == DEVICE_TYPE_WIRELESS_ETHERNET, FALSE);

	/* A test wireless device can always scan (we generate fake scan data for it) */
	if (dev->test_device)
		return (TRUE);
	
	iwlib_socket = iw_sockets_open ();
	error = iw_scan (iwlib_socket, (char *)nm_device_get_iface (dev), WIRELESS_EXT, &scan_data);
	nm_dispose_scan_results (scan_data.result);
	if ((error == -1) && (errno == EOPNOTSUPP))
		can_scan = FALSE;
	close (iwlib_socket);
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
	GSList	*element;
	
	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (udi  != NULL, NULL);

	element = data->dev_list;
	while (element)
	{
		dev = (NMDevice *)(element->data);
		if (dev)
		{
			if (nm_null_safe_strcmp (nm_device_get_udi (dev), udi) == 0)
				break;
		}

		element = g_slist_next (element);
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
	GSList	*element;
	
	g_return_val_if_fail (data  != NULL, NULL);
	g_return_val_if_fail (iface != NULL, NULL);

	element = data->dev_list;
	while (element)
	{
		iter_dev = (NMDevice *)(element->data);
		if (iter_dev)
		{
			if (nm_null_safe_strcmp (nm_device_get_iface (iter_dev), iface) == 0)
			{
				found_dev = iter_dev;
				break;
			}
		}

		element = g_slist_next (element);
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

	dev = g_new0 (NMDevice, 1);
	if (!dev)
	{
		syslog (LOG_ERR, "nm_device_new() could not allocate a new device...  Not enough memory?");
		return (NULL);
	}

	dev->refcount = 1;
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

	/* Initialize wireless-specific options */
	if (nm_device_is_wireless (dev))
	{
		if (!(dev->options.wireless.scan_mutex = g_mutex_new ()))
		{
			g_free (dev->iface);
			g_free (dev);
			return (NULL);
		}

		if (!(dev->options.wireless.best_ap_mutex = g_mutex_new ()))
		{
			g_mutex_free (dev->options.wireless.scan_mutex);
			g_free (dev->iface);
			g_free (dev);
			return (NULL);
		}

		if (!(dev->options.wireless.ap_list = nm_ap_list_new (NETWORK_TYPE_DEVICE)))
		{
			g_free (dev->iface);
			g_mutex_free (dev->options.wireless.best_ap_mutex);
			g_free (dev);
			return (NULL);
		}
		dev->options.wireless.supports_wireless_scan = nm_device_supports_wireless_scan (dev);

		/* Perform an initial wireless scan */
		nm_device_set_mode_managed (dev);
		nm_device_do_wireless_scan (dev);
		nm_device_update_best_ap (dev);
	}

	dev->driver_support_level = nm_get_driver_support_level (dev->app_data->hal_ctx, dev);

	if (nm_device_get_driver_support_level (dev) != NM_DRIVER_UNSUPPORTED)
	{
		/* Grab IP config data for this device from the system configuration files */
		nm_device_update_ip4_address (dev);
		nm_system_device_update_config_info (dev);

		/* Have to bring the device up before checking link status.  */
		nm_device_bring_up (dev);
		nm_device_update_link_active (dev, TRUE);
	}

	return (dev);
}


/*
 * Refcounting functions
 */
void nm_device_ref (NMDevice *dev)
{
	g_return_if_fail (dev != NULL);

	dev->refcount++;
}

void nm_device_unref (NMDevice *dev)
{
	g_return_if_fail (dev != NULL);

	dev->refcount--;
	if (dev->refcount <= 0)
	{
		nm_device_ap_list_clear (dev);
		dev->options.wireless.ap_list = NULL;

		g_free (dev->udi);
		g_free (dev->iface);
		if (nm_device_is_wireless (dev))
		{
			g_mutex_free (dev->options.wireless.scan_mutex);
			if (dev->options.wireless.ap_list)
				nm_ap_list_unref (dev->options.wireless.ap_list);
			if (dev->options.wireless.cached_ap_list1)
				nm_ap_list_unref (dev->options.wireless.cached_ap_list1);
			if (dev->options.wireless.cached_ap_list2)
				nm_ap_list_unref (dev->options.wireless.cached_ap_list2);
			if (dev->options.wireless.cached_ap_list3)
				nm_ap_list_unref (dev->options.wireless.cached_ap_list3);
			if (dev->options.wireless.cached_ap_list4)
				nm_ap_list_unref (dev->options.wireless.cached_ap_list4);
			nm_ap_unref (dev->options.wireless.best_ap);
			g_mutex_free (dev->options.wireless.best_ap_mutex);
		}

		dev->udi = NULL;
		dev->iface = NULL;
		g_free (dev);
	}
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
 * nm_device_wireless_link_active
 *
 * Gets the link state of a wireless device
 *
 */
static gboolean nm_device_wireless_link_active (NMDevice *dev)
{
	struct iwreq	 wrq;
	int			 iwlib_socket;
	gboolean		 link = FALSE;

	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (dev->app_data != NULL, FALSE);

	/* Test devices have their link state set through DBUS */
	if (dev->test_device)
		return (nm_device_get_link_active (dev));

	/*
	 * For wireless cards, the best indicator of a "link" at this time
	 * seems to be whether the card has a valid access point MAC address.
	 * Is there a better way?
	 */
	iwlib_socket = iw_sockets_open ();
	if (iw_get_ext (iwlib_socket, nm_device_get_iface (dev), SIOCGIWAP, &wrq) >= 0)
	{
		if (    nm_ethernet_address_is_valid ((struct ether_addr *)(&(wrq.u.ap_addr.sa_data)))
			&& nm_device_get_best_ap (dev)
			&& !nm_device_need_ap_switch (dev))
			link = TRUE;
	}
	close (iwlib_socket);

	return (link);
}


/*
 * nm_device_wired_link_active
 *
 * Return the link state of a wired device.  We usually just grab the HAL
 * net.80203.link property, but on card insertion we need to check the MII
 * registers of the card to get a more accurate response, since HAL may not
 * have received a netlink socket link event for the device yet, and therefore
 * will return FALSE when the device really does have a link.
 *
 */
static gboolean nm_device_wired_link_active (NMDevice *dev, gboolean check_mii)
{
	gboolean	link = FALSE;

	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (dev->app_data != NULL, FALSE);

	/* Test devices have their link state set through DBUS */
	if (dev->test_device)
		return (nm_device_get_link_active (dev));

	if (check_mii)
		link = mii_get_link (dev);
	else if (hal_device_property_exists (dev->app_data->hal_ctx, nm_device_get_udi (dev), "net.80203.link"))
		link = hal_device_get_property_bool (dev->app_data->hal_ctx, nm_device_get_udi (dev), "net.80203.link");

	return (link);
}


/*
 * nm_device_update_link_active
 *
 * Updates the link state for a particular device.
 *
 */
void nm_device_update_link_active (NMDevice *dev, gboolean check_mii)
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
			link = nm_device_wired_link_active (dev, check_mii);
			break;

		default:
			link = nm_device_get_link_active (dev);	/* Can't get link info for this device, so don't change link status */
			break;
	}

	/* Update device link status and global state variable if the status changed */
	if (link != nm_device_get_link_active (dev))
	{
		nm_device_set_link_active (dev, link);
		nm_data_mark_state_changed (dev->app_data);
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
	int				iwlib_socket;
	int				err;
	
	g_return_val_if_fail (dev != NULL, NULL);
	g_return_val_if_fail (nm_device_is_wireless (dev), NULL);

	/* Test devices return the essid of their "best" access point
	 * or if there is none, the contents of the cur_essid field.
	 */
	if (dev->test_device)
	{
		if (nm_device_get_best_ap (dev))
			return (nm_ap_get_essid (nm_device_get_best_ap (dev)));
		else
			return (dev->options.wireless.cur_essid);
	}
	
	iwlib_socket = iw_sockets_open ();
	if (iwlib_socket >= 0)
	{
		wireless_config	info;

		err = iw_get_basic_config(iwlib_socket, nm_device_get_iface (dev), &info);
		if (err >= 0)
		{
			if (dev->options.wireless.cur_essid)
				g_free (dev->options.wireless.cur_essid);
			dev->options.wireless.cur_essid = g_strdup (info.essid);
		}
		else
			syslog (LOG_ERR, "nm_device_get_essid(): error setting ESSID for device %s.  errno = %d", nm_device_get_iface (dev), errno);

		close (iwlib_socket);
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
	int				iwlib_socket;
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

	iwlib_socket = iw_sockets_open ();
	if (iwlib_socket >= 0)
	{
		wreq.u.essid.pointer = (caddr_t) safe_essid;
		wreq.u.essid.length	 = strlen (safe_essid) + 1;
		wreq.u.essid.flags	 = 1;	/* Enable essid on card */
	
		err = iw_set_ext (iwlib_socket, nm_device_get_iface (dev), SIOCSIWESSID, &wreq);
		if (err == -1)
			syslog (LOG_ERR, "nm_device_set_essid(): error setting ESSID for device %s.  errno = %d", nm_device_get_iface (dev), errno);

		close (iwlib_socket);
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
void nm_device_set_enc_key (NMDevice *dev, const char *key)
{
	int				iwlib_socket;
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

	iwlib_socket = iw_sockets_open ();
	if (iwlib_socket >= 0)
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

			keylen = iw_in_key_full(iwlib_socket, nm_device_get_iface (dev), safe_key, &parsed_key[0], &wreq.u.data.flags);
			if (keylen > 0)
			{
				wreq.u.data.flags |= IW_ENCODE_RESTRICTED;		// FIXME: what about restricted/Shared Key?
				wreq.u.data.pointer	=  (caddr_t) &parsed_key;
				wreq.u.data.length	=  keylen;
				set_key = TRUE;
			}
		}

		if (set_key)
		{
			err = iw_set_ext (iwlib_socket, nm_device_get_iface (dev), SIOCSIWENCODE, &wreq);
			if (err == -1)
				syslog (LOG_ERR, "nm_device_set_enc_key(): error setting key for device %s.  errno = %d", nm_device_get_iface (dev), errno);
		}

		close (iwlib_socket);
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
	int		iwlib_socket;
	iwrange	range;
	iwstats	stats;
	int		percent = -1;

	g_return_if_fail (dev != NULL);
	g_return_if_fail (nm_device_is_wireless (dev));
	g_return_if_fail (dev->app_data != NULL);

	/* If we aren't the active device, we don't really have a signal strength
	 * that would mean anything.
	 */
#if 0
	if (dev != dev->app_data->active_device)
	{
		dev->options.wireless.strength = -1;
		return;
	}
#endif

	/* Fake a value for test devices */
	if (dev->test_device)
	{
		dev->options.wireless.strength = 75;
		return;
	}

	iwlib_socket = iw_sockets_open ();
	has_range = (iw_get_range_info (iwlib_socket, nm_device_get_iface (dev), &range) >= 0);
	if (iw_get_stats (iwlib_socket, nm_device_get_iface (dev), &stats, &range, has_range) == 0)
	{
		/* Update our max quality while we're at it */
		dev->options.wireless.max_quality = range.max_qual.level;
		dev->options.wireless.noise = stats.qual.noise;
		percent = nm_wireless_qual_to_percent (dev, &(stats.qual));
	}
	else
	{
		dev->options.wireless.max_quality = -1;
		dev->options.wireless.noise = -1;
		percent = -1;
	}
	close (iwlib_socket);

	dev->options.wireless.strength = percent;
}


/*
 * nm_device_get_noise
 *
 * Get the current noise level of a wireless device.
 *
 */
guint8 nm_device_get_noise (NMDevice *dev)
{
	g_return_val_if_fail (dev != NULL, 0);
	g_return_val_if_fail (nm_device_is_wireless (dev), 0);

	return (dev->options.wireless.noise);
}


/*
 * nm_device_get_max_quality
 *
 * Get the quality maximum of a wireless device.
 *
 */
guint8 nm_device_get_max_quality (NMDevice *dev)
{
	g_return_val_if_fail (dev != NULL, 0);
	g_return_val_if_fail (nm_device_is_wireless (dev), 0);

	return (dev->options.wireless.max_quality);
}


/*
 * nm_device_get_bad_crypt_packets
 *
 * Return the number of packets the card has dropped because
 * they could not be successfully decrypted.
 *
 */
guint32 nm_device_get_bad_crypt_packets (NMDevice *dev)
{
	iwstats	stats;
	int		sk;
	int		err;

	g_return_val_if_fail (dev != NULL, 0);
	g_return_val_if_fail (nm_device_is_wireless (dev), 0);

	sk = iw_sockets_open ();
	err = iw_get_stats (sk, nm_device_get_iface (dev), &stats, NULL, FALSE);
	close (sk);
	return (err == 0 ? stats.discard.code : 0);
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
	int			socket;
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

	socket = nm_get_network_control_socket ();
	if (socket < 0)
		return;
	
	strncpy ((char *)(&req.ifr_name), nm_device_get_iface (dev), 16);	// 16 == IF_NAMESIZE
	err = ioctl (socket, SIOCGIFADDR, &req);
	close (socket);
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
 * nm_device_set_up_down
 *
 * Set the up flag on the device on or off
 *
 */
static void nm_device_set_up_down (NMDevice *dev, gboolean up)
{
	struct ifreq	ifr;
	int			iface_fd;
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

	iface_fd = nm_get_network_control_socket ();
	if (iface_fd < 0)
		return;

	/* Get flags already there */
	strcpy (ifr.ifr_name, nm_device_get_iface (dev));
	err = ioctl (iface_fd, SIOCGIFFLAGS, &ifr);
	if (!err)
	{
		/* If the interface doesn't have those flags already,
		 * set them on it.
		 */
		if ((ifr.ifr_flags^flags) & IFF_UP)
		{
			ifr.ifr_flags &= ~IFF_UP;
			ifr.ifr_flags |= IFF_UP & flags;
			err = ioctl (iface_fd, SIOCSIFFLAGS, &ifr);
			if (err)
				syslog (LOG_ERR, "nm_device_set_up_down() could not bring device %s %s.  errno = %d", nm_device_get_iface (dev), (up ? "up" : "down"), errno );
		}
	}
	else
		syslog (LOG_ERR, "nm_device_set_up_down() could not get flags for device %s.  errno = %d", nm_device_get_iface (dev), errno );

	close (iface_fd);
}


/*
 * Interface state functions: bring up, down, check
 *
 */
void nm_device_bring_up (NMDevice *dev)
{
	g_return_if_fail (dev != NULL);

	nm_device_set_up_down (dev, TRUE);
}

void nm_device_bring_down (NMDevice *dev)
{
	g_return_if_fail (dev != NULL);

	nm_device_set_up_down (dev, FALSE);
}

gboolean nm_device_is_up (NMDevice *dev)
{
	int			iface_fd;
	struct ifreq	ifr;
	int			err;

	g_return_val_if_fail (dev != NULL, FALSE);

	if (dev->test_device)
		return (dev->test_device_up);

	iface_fd = nm_get_network_control_socket ();
	if (iface_fd < 0)
		return (FALSE);

	/* Get device's flags */
	strcpy (ifr.ifr_name, nm_device_get_iface (dev));
	err = ioctl (iface_fd, SIOCGIFFLAGS, &ifr);
	close (iface_fd);
	if (!err)
		return (!((ifr.ifr_flags^IFF_UP) & IFF_UP));

	syslog (LOG_ERR, "nm_device_is_up() could not get flags for device %s.  errno = %d", nm_device_get_iface (dev), errno );
	return (FALSE);
}


/*
 * nm_device_set_mode_managed
 *
 * Set managed/infrastructure mode on a device (currently wireless only)
 *
 */
void nm_device_set_mode_managed (NMDevice *dev)
{
	int			sk;
	struct iwreq	wreq;

	g_return_if_fail (dev != NULL);
	g_return_if_fail (nm_device_is_wireless (dev));

	/* Force the card into Managed/Infrastructure mode */
	sk = iw_sockets_open ();
	if (sk >= 0)
	{
		int err;
		wreq.u.mode = IW_MODE_INFRA;
		err = iw_set_ext (sk, nm_device_get_iface (dev), SIOCSIWMODE, &wreq);
		if (err == -1)
			syslog (LOG_ERR, "nm_device_set_mode_managed (%s): error setting card to Infrastructure mode.  errno = %d", nm_device_get_iface (dev), errno);	
		close (sk);
	}
}


/*
 * nm_device_set_mode_adhoc
 *
 * Set Ad Hoc mode on a device (currently wireless only)
 *
 */
void nm_device_set_mode_adhoc (NMDevice *dev)
{
	int			sk;
	struct iwreq	wreq;

	g_return_if_fail (dev != NULL);
	g_return_if_fail (nm_device_is_wireless (dev));

	/* Force the card into Adhoc mode */
	sk = iw_sockets_open ();
	if (sk >= 0)
	{
		int err;
		wreq.u.mode = IW_MODE_ADHOC;
		err = iw_set_ext (sk, nm_device_get_iface (dev), SIOCSIWMODE, &wreq);
		if (err == -1)
			syslog (LOG_ERR, "nm_device_set_mode_adhoc (%s): error setting card to Ad Hoc mode.  errno = %d", nm_device_get_iface (dev), errno);	
		close (sk);
	}
}


/*
 * nm_device_activation_begin
 *
 * Spawn a new thread to handle device activation.
 *
 * Returns:	TRUE on success activation beginning
 *			FALSE on error beginning activation (bad params, couldn't create thread)
 *
 */
gboolean nm_device_activation_begin (NMDevice *dev)
{
	GError	*error = NULL;
	NMData	*data = (NMData *)dev->app_data;

	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (!dev->activating, TRUE);	// Return if activation has already begun
	g_return_val_if_fail (data != NULL, FALSE);

	/* Ref the device so it doesn't go away while worker function is active */
	nm_device_ref (dev);

	/* Don't attempt to actually activate if we are just starting NetworkManager and
	 * we are about to activate a wired device that's already configured.  Plays nicer
	 * with the system when NM is started after a network is already set up.
	 *
	 * FIXME: IPv6 here too, and this really should not be here, it should be part of
	 * the policy, not the device code itself.
	 */
	if (data->starting_up && nm_device_is_wired (data->active_device) && nm_device_get_ip4_address (data->active_device))
	{
		dev->activating = FALSE;
		dev->just_activated = TRUE;
		return (TRUE);
	}

	if (nm_device_get_driver_support_level (dev) == NM_DRIVER_UNSUPPORTED)
	{
		dev->activating = FALSE;
		return (FALSE);
	}

	/* Reset communication flags between worker and main thread */
	dev->activating = TRUE;
	dev->just_activated = FALSE;
	dev->quit_activation = FALSE;
	if (nm_device_is_wireless (dev))
	{
		dev->options.wireless.now_scanning = FALSE;
		dev->options.wireless.user_key_received = FALSE;
	}

	if (!g_thread_create (nm_device_activation_worker, dev, FALSE, &error))
	{
		syslog (LOG_CRIT, "nm_device_activation_begin(): could not create activation worker thread.");
		dev->activating = FALSE;
		return (FALSE);
	}

	nm_dbus_signal_device_status_change (data->dbus_connection, dev, DEVICE_ACTIVATING);

	return (TRUE);
}


/*
 * nm_device_activation_should_cancel
 *
 * Check whether we should stop activation, and if so clean up flags
 * and other random things.
 *
 */
static gboolean nm_device_activation_should_cancel (NMDevice *dev)
{
	g_return_val_if_fail (dev != NULL, TRUE);

	/* If we were told to quit activation, stop the thread and return */
	if (dev->quit_activation)
	{
		syslog (LOG_DEBUG, "nm_device_activation_worker(%s): activation canceled.", nm_device_get_iface (dev));
		dev->activating = FALSE;
		dev->just_activated = FALSE;
		return (TRUE);
	}

	return (FALSE);
}


/*
 * nm_device_activate_wireless
 *
 * Bring up a wireless card with the essid and wep key of its "best" ap
 *
 * Returns:	TRUE on successful activation
 *			FALSE on unsuccessful activation (ie no best AP)
 *
 */
static gboolean nm_device_activate_wireless (NMDevice *dev, guint *bad_crypt_packets)
{
	NMAccessPoint	*best_ap;
	gboolean		 success = FALSE;

	g_return_val_if_fail (dev  != NULL, FALSE);
	g_return_val_if_fail (nm_device_is_wireless (dev), FALSE);

	*bad_crypt_packets = 0;
	/* If there is a desired AP to connect to, use that essid and possible WEP key */
	if ((best_ap = nm_device_get_best_ap (dev)) && nm_ap_get_essid (best_ap))
	{
		nm_device_bring_down (dev);

		/* Force the card into Managed/Infrastructure mode */
		nm_device_set_mode_managed (dev);

		/* Disable encryption, then re-enable and set correct key on the card
		 * if we are going to encrypt traffic.
		 */
		nm_device_set_enc_key (dev, NULL);
		if (nm_ap_get_encrypted (best_ap) && nm_ap_get_enc_key_source (best_ap))
		{
			char *hashed_key = nm_ap_get_enc_key_hashed (best_ap);
			nm_device_set_enc_key (dev, hashed_key);
			g_free (hashed_key);
		}

		nm_device_set_essid (dev, nm_ap_get_essid (best_ap));
		*bad_crypt_packets = nm_device_get_bad_crypt_packets (dev);

		syslog (LOG_INFO, "nm_device_wireless_activate(%s) using essid '%s'", nm_device_get_iface (dev), nm_ap_get_essid (best_ap));

		/* Bring the device up and pause to allow card to associate */
		nm_device_bring_up (dev);
		g_usleep (G_USEC_PER_SEC * 2);

		nm_device_update_link_active (dev, FALSE);
		success = TRUE;
	}

	return (success);
}


inline gboolean HAVE_LINK (NMDevice *dev, guint32 bad_crypt_packets)
{
	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (nm_device_is_wireless (dev), FALSE);

	syslog (LOG_NOTICE, "HAVELINK: act=%d && (dev_crypt=%d <= prev_crypt=%d)\n", nm_device_get_link_active (dev), nm_device_get_bad_crypt_packets (dev), bad_crypt_packets);
	return (nm_device_get_link_active (dev) && (nm_device_get_bad_crypt_packets (dev) <= bad_crypt_packets));
}

/*
 * nm_device_activate_wireless_wait_for_link
 *
 * Spin until we have a wireless link, which may mean
 * requesting a key from the user and trying various hashed
 * iterations of that key.
 *
 */
void nm_device_activate_wireless_wait_for_link (NMDevice *dev)
{
	NMAccessPoint	*best_ap;
	guint32		 bad_crypt_packets = 0;

	g_return_if_fail (dev != NULL);

	/* If the card is just inserted, we may not have had a chance to scan yet */
	if (!(best_ap = nm_device_get_best_ap (dev)))
	{
		nm_device_do_wireless_scan (dev);
		nm_device_update_best_ap (dev);
		best_ap = nm_device_get_best_ap (dev);
	}

	/* Try activating the device with the key and access point we have already */
	nm_device_activate_wireless (dev, &bad_crypt_packets);

	/* Wait until we have a link.  Some things that might block us from
	 * getting one:
	 * 1) Access point we want to associate with has encryption enabled and
	 *		we don't have the right encryption key.  If we have a key of some
	 *		sort, try various passhprase->key hashes of it.  If we don't have
	 *		a key, ask the user for one and wait until we are canceled (wireless
	 *		card was ejected or the user plugged the computer into a wired network)
	 *		or until we get a key back.
	 * 2) We don't have any access points we wish to associate with yet.  In that case
	 *		wait for the wireless scan to complete in the other thread and to pick
	 *		a "best" access point for us.
	 *
	 */

	/* There are two ways to check for a good link.  If we are using WEP and Open System
	 * authentication, then we can associate with the base station regardless of whether the
	 * WEP key is right or not.  Therefore, we have to monitor the # of packets the card discards
	 * when its unable to decrypt them, since that gives us some indicator of whether the WEP
	 * key is wrong.  It seems that right after association, at least one packet is dropped by
	 * most cards if the WEP key is wrong.
	 *
	 * The second and better way (if all cards actually supported it) is to check the MAC address
	 * the card is associated with.  However, this doesn't tell us if the WEP key is wrong when we
	 * are using Open System authentication.  Also, not all drivers return an invalid MAC address
	 * when the card cannot communicate with the access point.
	 */

	/* For the link check, ensure that:
	 * 1) a classic link check is good, ie does the card report a valid associated AP MAC address and is it
	 *		receiving WEP-enabled packets OK if WEP is on
	 * 2) we have a best access point, and if that AP is encrypted, that we have a valid encryption key for it
	 *
	 * If either of these things fail, we try other access points or we try to retrieve another encrpytion key
	 * from the user.
	 *
	 */
	while (      !HAVE_LINK (dev, bad_crypt_packets)
			|| (best_ap && (nm_ap_get_encrypted (best_ap) &&
					(!nm_ap_get_enc_key_source (best_ap) || !strlen (nm_ap_get_enc_key_source (best_ap))))))
	{
		if (best_ap)
		{
			syslog (LOG_NOTICE, "LINK: !HAVE=%d, (best_ap=0x%X && (is_enc=%d && (!source=%d || !len_source=%d)))",
				!HAVE_LINK (dev, bad_crypt_packets), best_ap, nm_ap_get_encrypted (best_ap), !nm_ap_get_enc_key_source (best_ap),
				nm_ap_get_enc_key_source (best_ap) ? !strlen (nm_ap_get_enc_key_source (best_ap)) : 0);
		}
		else
			syslog (LOG_NOTICE, "LINK: !HAVE=%d, (best_ap=NULL)", !HAVE_LINK (dev, bad_crypt_packets));


		if ((best_ap = nm_device_get_best_ap (dev)))
		{
			dev->options.wireless.now_scanning = FALSE;

			/* If we don't have a link yet, the encryption key is bad.  Ask the user for a
			 * new one.
			 */
			if (nm_ap_get_encrypted (best_ap))
			{
				dev->options.wireless.user_key_received = FALSE;
				nm_dbus_get_user_key_for_network (dev->app_data->dbus_connection, dev, best_ap);

				/* Wait for the key to come back */
				syslog (LOG_DEBUG, "nm_device_activation_worker(%s): asking for user key.", nm_device_get_iface (dev));
				while (!dev->options.wireless.user_key_received && !dev->quit_activation)
					g_usleep (G_USEC_PER_SEC / 2);

				syslog (LOG_DEBUG, "nm_device_activation_worker(%s): user key received.", nm_device_get_iface (dev));

				/* If we were told to quit activation, stop the thread and return */
				if (nm_device_activation_should_cancel (dev))
					return;
			}

			/* Try activating again with up-to-date access point and keys */	
			nm_device_activate_wireless (dev, &bad_crypt_packets);
		}
		else
		{
			dev->options.wireless.now_scanning = TRUE;
			syslog (LOG_DEBUG, "nm_device_activation_worker(%s): waiting for an access point.", nm_device_get_iface (dev));
			g_usleep (G_USEC_PER_SEC * 2);
		}

		/* If we were told to quit activation, stop the thread and return */
		if (nm_device_activation_should_cancel (dev))
			break;
	}

	dev->options.wireless.now_scanning = FALSE;
}


/*
 * nm_device_activation_configure_ip
 *
 * Perform any IP-based configuration on a device, like running DHCP
 * or manually setting up the IP address, gateway, and default route.
 *
 */
static gboolean nm_device_activation_configure_ip (NMDevice *dev)
{
	gboolean success = FALSE;

	g_return_val_if_fail (dev != NULL, FALSE);

	if (nm_device_config_get_use_dhcp (dev))
	{
		if (nm_system_device_run_dhcp (dev))
			success = TRUE;
		else
		{
			/* Interfaces cannot be down if they are the active interface,
			 * otherwise we cannot use them for scanning or link detection.
			 * If dhclient doesn't get a DHCP address, it will take the interface
			 * down, so we reactivate it here.
			 */
			if (nm_device_is_wireless (dev))
			{
				nm_device_set_essid (dev, "");
				nm_device_set_enc_key (dev, NULL);
			}

			nm_device_bring_up (dev);
		}
	}
	else
	{
		/* Manually set up the device */
		success = nm_system_device_setup_static_ip4_config (dev);
	}

	return (success);
}


/*
 * nm_device_activation_worker
 *
 * Thread worker function to actually activate a device.  We have to do it in another
 * thread because things like dhclient block our main thread's event loop, and thus we
 * wouldn't respond to dbus messages.
 */
static gpointer nm_device_activation_worker (gpointer user_data)
{
	NMDevice		*dev = (NMDevice *)user_data;
	unsigned char	 hostname[100] = "\0";
	int			 host_err;

	g_return_val_if_fail (dev  != NULL, NULL);
	g_return_val_if_fail (dev->app_data != NULL, NULL);

	syslog (LOG_DEBUG, "nm_device_activation_worker (%s) started...", nm_device_get_iface (dev));

	/* If its a wireless device, set the ESSID and WEP key */
	if (nm_device_is_wireless (dev))
	{
		nm_device_activate_wireless_wait_for_link (dev);

		/* If we were told to quit activation, stop the thread and return */
		if (nm_device_activation_should_cancel (dev))
		{
			nm_device_unref (dev);
			return (NULL);
		}

		syslog (LOG_DEBUG, "nm_device_activation_worker(%s): using ESSID '%s'", nm_device_get_iface (dev),
				nm_ap_get_essid (nm_device_get_best_ap (dev)));
	}
	else
	{
		/* Bring the device up */
		if (!nm_device_is_up (dev));
			nm_device_bring_up (dev);
	}

	nm_system_delete_default_route ();
	nm_system_device_stop_dhcp (dev);

	/* If we don't have a "best" ap, don't try to get a DHCP address or restart the name service cache */
	if (nm_device_is_wired (dev) || (nm_device_is_wireless (dev) && nm_device_get_best_ap (dev)))
	{
		gboolean	success;
		/* Save machine host name */
		host_err = gethostname (&hostname[0], 100);

		if (!(success = nm_device_activation_configure_ip (dev)))
			syslog (LOG_DEBUG, "nm_device_activation_worker(%s): could not retrieve and assign IP information to device\n", nm_device_get_iface (dev));

		/* Set the hostname back to what it was before so that X11 doesn't
		 * puke when the hostname changes, and so users can actually launch stuff.
		 */
		if (host_err >= 0)
			sethostname (hostname, strlen (hostname));

		/* If we were told to quit activation, stop the thread and return */
		if (nm_device_activation_should_cancel (dev) || !success)
		{
			nm_device_unref (dev);
			return (NULL);
		}

		/* Make system aware of any new DNS settings from resolv.conf */
		nm_system_update_dns ();
	}

	/* If we were told to quit activation, stop the thread and return */
	if (nm_device_activation_should_cancel (dev))
	{
		nm_device_unref (dev);
		return (NULL);
	}

	dev->just_activated = TRUE;
	syslog (LOG_DEBUG, "nm_device_activation_worker(%s): device activated", nm_device_get_iface (dev));
	nm_device_update_ip4_address (dev);

	dev->activating = FALSE;
	nm_device_unref (dev);
	return (NULL);
}


/*
 * nm_device_is_just_activated
 *
 * Check if the device was just activated successfully or not.  If so, clear
 * its just_activated flag and return TRUE.  If its not activated yet, return FALSE.
 *
 */
gboolean nm_device_is_just_activated (NMDevice *dev)
{
	g_return_val_if_fail (dev != NULL, FALSE);

	if (dev->just_activated)
	{
		dev->just_activated = FALSE;
		return (TRUE);
	}

	return (FALSE);
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
		nm_system_kill_all_dhcp_daemons ();	/* dhcp daemons will block, so have to kill them to return control */

		/* Spin until cancelled.  Possible race conditions or deadlocks here.
		 * The other problem with waiting here is that we hold up dbus traffic
		 * that we should respond to.
		 */
		while (nm_device_is_activating (dev))
			g_usleep (G_USEC_PER_SEC / 2);
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

	/* Take out any entries in the routing table and any IP address the old device had. */
	nm_system_device_flush_routes (dev);
	nm_system_device_flush_addresses (dev);
	dev->ip4_address = 0;

	if (!just_added)
		nm_dbus_signal_device_status_change (dev->app_data->dbus_connection, dev, DEVICE_NO_LONGER_ACTIVE);

	/* Clean up stuff, don't leave the card associated */
	if (nm_device_is_wireless (dev))
	{
		nm_device_set_essid (dev, "");
		nm_device_set_enc_key (dev, NULL);
	}

	return (TRUE);
}


/*
 * nm_device_is_scanning
 *
 * Returns whether the device is scanning, awaiting an access point to connect to.
 * Note that this does NOT get set when the device is actually scanning, just
 * when it is waiting for a valid access point to connect to.
 *
 */
gboolean nm_device_is_scanning (NMDevice *dev)
{
	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (nm_device_is_wireless (dev), FALSE);

	return (dev->options.wireless.now_scanning);
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
									NMEncKeyType enc_method)
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
			nm_ap_set_enc_key_source (best_ap, key, enc_method);
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
 */
NMAccessPoint *nm_device_get_best_ap (NMDevice *dev)
{
	NMAccessPoint	*best_ap;

	g_return_val_if_fail (dev != NULL, NULL);
	g_return_val_if_fail (nm_device_is_wireless (dev), NULL);

	g_mutex_lock (dev->options.wireless.best_ap_mutex);
	best_ap = dev->options.wireless.best_ap;
	g_mutex_unlock (dev->options.wireless.best_ap_mutex);
	
	return (best_ap);
}

void nm_device_set_best_ap (NMDevice *dev, NMAccessPoint *ap)
{
	g_return_if_fail (dev != NULL);
	g_return_if_fail (nm_device_is_wireless (dev));

	g_mutex_lock (dev->options.wireless.best_ap_mutex);

	if (dev->options.wireless.best_ap)
		nm_ap_unref (dev->options.wireless.best_ap);

	if (ap)
		nm_ap_ref (ap);

	dev->options.wireless.best_ap = ap;
	nm_device_unfreeze_best_ap (dev);
	g_mutex_unlock (dev->options.wireless.best_ap_mutex);
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

	ap = nm_device_get_best_ap (dev);
	if (nm_null_safe_strcmp (nm_device_get_essid (dev), (ap ? nm_ap_get_essid (ap) : NULL)) != 0)
		need_switch = TRUE;

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
	NMAccessPoint		*ap = NULL;
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
		NMAccessPoint *best_ap = nm_device_get_best_ap (dev);

		/* If its in the device's ap list still, don't change the
		 * best ap, since its frozen.
		 */
		g_mutex_lock (dev->options.wireless.best_ap_mutex);
		if (    best_ap
			&& !nm_ap_list_get_ap_by_essid (dev->app_data->invalid_ap_list, nm_ap_get_essid (best_ap))
			&& nm_device_ap_list_get_ap_by_essid (dev, nm_ap_get_essid (best_ap)))
		{
			g_mutex_unlock (dev->options.wireless.best_ap_mutex);
			return;
		}

		/* Otherwise, its gone away and we don't care about it anymore */
		nm_device_unfreeze_best_ap (dev);
		g_mutex_unlock (dev->options.wireless.best_ap_mutex);
	}

	if (!(iter = nm_ap_list_iter_new (ap_list)))
		return;
	while ((ap = nm_ap_list_iter_next (iter)))
	{
		NMAccessPoint	*tmp_ap;
		char			*ap_essid = nm_ap_get_essid (ap);

		/* Access points in the "invalid" list cannot be used */
		if (nm_ap_list_get_ap_by_essid (dev->app_data->invalid_ap_list, ap_essid))
			continue;

		if ((tmp_ap = nm_ap_list_get_ap_by_essid (dev->app_data->allowed_ap_list, ap_essid)))
		{
			const GTimeVal *curtime = nm_ap_get_timestamp (tmp_ap);

			if (nm_ap_get_trusted (tmp_ap) && (curtime->tv_sec > trusted_latest_timestamp.tv_sec))
			{
				trusted_latest_timestamp = *nm_ap_get_timestamp (tmp_ap);
				trusted_best_ap = ap;
				/* Merge access point data (mainly to get updated WEP key) */
				nm_ap_set_enc_key_source (trusted_best_ap, nm_ap_get_enc_key_source (tmp_ap), nm_ap_get_enc_method (tmp_ap));
			}
			else if (!nm_ap_get_trusted (tmp_ap) && (curtime->tv_sec > untrusted_latest_timestamp.tv_sec))
			{
				untrusted_latest_timestamp = *nm_ap_get_timestamp (tmp_ap);
				untrusted_best_ap = ap;
				/* Merge access point data (mainly to get updated WEP key) */
				nm_ap_set_enc_key_source (untrusted_best_ap, nm_ap_get_enc_key_source (tmp_ap), nm_ap_get_enc_method (tmp_ap));
			}
		}
	}
	best_ap = trusted_best_ap ? trusted_best_ap : untrusted_best_ap;
	nm_ap_list_iter_free (iter);

	/* If the best ap is NULL, bring device down and clear out its essid and AP */
	nm_device_set_best_ap (dev, best_ap);
	if (!nm_device_get_best_ap (dev))
	{
		nm_device_bring_down (dev);
		nm_device_set_essid (dev, "");
		nm_device_set_enc_key (dev, NULL);
		nm_device_bring_up (dev);
	}
}


/*
 * nm_device_wireless_network_exists
 *
 * Tell the card to explicitly use with a particular essid, and then
 * see if we can associate with some AP using that ESSID.
 * Mainly for non-essid-broadcasting APs to figure out whether or not
 * some random ESSID the user gave us exists or not.
 *
 * WARNING: will blow away any connection the card currently has.
 *
 */
gboolean nm_device_wireless_network_exists (NMDevice *dev, const char *network, struct ether_addr *ap_addr, gboolean *encrypted)
{
	gboolean			success = FALSE;
	struct ether_addr	addr;

	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (network != NULL, FALSE);
	g_return_val_if_fail (ap_addr != NULL, FALSE);
	g_return_val_if_fail (strlen (network), FALSE);
	g_return_val_if_fail (encrypted != NULL, FALSE);

	fprintf (stderr, "nm_device_wireless_network_exists () looking for network '%s'...", network);

	*encrypted = FALSE;
	nm_device_bring_down (dev);

	/* Force the card into Managed/Infrastructure mode */
	nm_device_set_mode_managed (dev);

	nm_device_set_enc_key (dev, NULL);
	nm_device_set_essid (dev, network);

	/* Bring the device up and pause to allow card to associate */
	nm_device_bring_up (dev);
	g_usleep (G_USEC_PER_SEC * 2);

	nm_device_update_link_active (dev, FALSE);
	nm_device_get_ap_address (dev, &addr);
	if (nm_ethernet_address_is_valid (&addr) && nm_device_get_essid (dev))
	{
		nm_device_get_ap_address (dev, ap_addr);
		success = TRUE;
		*encrypted = FALSE;
	}
	else
	{
		/* Okay, try again but set the card into encrypted mode this time */
		nm_device_bring_down (dev);

		/* Force the card into Managed/Infrastructure mode */
		nm_device_set_mode_managed (dev);

		nm_device_set_enc_key (dev, "11111111111111111111111111");
		nm_device_set_essid (dev, network);

		/* Bring the device up and pause to allow card to associate */
		nm_device_bring_up (dev);
		g_usleep (G_USEC_PER_SEC * 2);

		nm_device_update_link_active (dev, FALSE);
		nm_device_get_ap_address (dev, &addr);
		if (nm_ethernet_address_is_valid (&addr) && nm_device_get_essid (dev))
		{
			nm_device_get_ap_address (dev, ap_addr);
			success = TRUE;
			*encrypted = TRUE;
		}
	}

	if (success)
		fprintf (stderr, "  found!\n");
	else
		fprintf (stderr, "  not found\n");

	return (success);
}


/*
 * nm_device_find_and_use_essid
 *
 * Given an essid, attempt to associate with that ESSID even if we can't
 * see it in our scan.  If we successfully find it, mark that network as
 * our "best" and use it during the next activation.
 *
 * Returns:	TRUE on success
 *			FALSE on failure
 */
gboolean nm_device_find_and_use_essid (NMDevice *dev, const char *essid)
{
	struct ether_addr	 ap_addr;
	gboolean			 encrypted = FALSE;
	NMAccessPoint		*ap = NULL;
	gboolean			 success = FALSE;

	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (nm_device_is_wireless (dev), FALSE);
	g_return_val_if_fail (dev->app_data != NULL, FALSE);
	g_return_val_if_fail (essid != NULL, FALSE);

	syslog (LOG_DEBUG, "Forcing AP '%s'", essid);
	/* If the network exists, make sure it has the correct ESSID set
	 * (it might have been a blank ESSID up to this point) and use it.
	 */
	nm_device_deactivate (dev, FALSE);
	if (nm_device_wireless_network_exists (dev, essid, &ap_addr, &encrypted))
	{
		if (!(ap = nm_ap_list_get_ap_by_essid (nm_device_ap_list_get (dev), essid)))
		{
			NMAccessPoint *tmp_ap;

			ap = nm_device_ap_list_get_ap_by_address (dev, &ap_addr);
			if (!ap)
			{
				/* Okay, the card didn't see it in the scan, Cisco cards sometimes do this.
				 * So we make a "fake" access point and add it to the scan list.
				 */
				ap = nm_ap_new ();
				nm_ap_set_encrypted (ap, encrypted);
				nm_ap_set_artificial (ap, TRUE);
				nm_ap_set_address (ap, &ap_addr);
				nm_ap_list_append_ap (nm_device_ap_list_get (dev), ap);
				nm_ap_unref (ap);
			}

			/* Now that this AP has an essid, copy over encryption keys and whatnot */
			nm_ap_set_essid (ap, essid);
			if ((tmp_ap = nm_ap_list_get_ap_by_essid (dev->app_data->allowed_ap_list, essid)))
			{
				nm_ap_set_invalid (ap, nm_ap_get_invalid (tmp_ap));
				nm_ap_set_enc_key_source (ap, nm_ap_get_enc_key_source (tmp_ap), nm_ap_get_enc_method (tmp_ap));
				nm_ap_set_timestamp (ap, nm_ap_get_timestamp (tmp_ap));
			}
		}
	}

	/* If we found a valid access point, use it */
	if (ap)
	{
		nm_device_set_best_ap (dev, ap);
		nm_device_freeze_best_ap (dev);
		nm_device_activation_cancel (dev);
		success = TRUE;
	}

	return (success);
}


/*
 * nm_device_do_normal_scan
 *
 * Scan for access points on cards that support wireless scanning.
 *
 */
static void nm_device_do_normal_scan (NMDevice *dev)
{
	int		 iwlib_socket;
	NMData	*data;

	g_return_if_fail (dev  != NULL);
	g_return_if_fail (dev->app_data != NULL);

	/* Test devices shouldn't get here since we fake the AP list earlier */
	g_return_if_fail (!dev->test_device);

	data = (NMData *)dev->app_data;

	/* Device must be up before we can scan */
	if (!nm_device_is_up (dev))
		nm_device_bring_up (dev);
	g_usleep (G_USEC_PER_SEC);

	iwlib_socket = iw_sockets_open ();
	if (iwlib_socket >= 0)
	{
		wireless_scan_head	 scan_results = { NULL, 0 };
		wireless_scan		*tmp_ap;
		int				 err;
		NMAccessPointList	*old_ap_list = NULL;
		NMAccessPointList	*temp_list;
		gboolean			 have_blank_essids = FALSE;
		NMAPListIter		*iter;
		NMAccessPoint		*artificial_ap;

		err = iw_scan (iwlib_socket, (char *)nm_device_get_iface (dev), WIRELESS_EXT, &scan_results);
		if ((err == -1) && (errno == ENODATA))
		{
			/* Card hasn't had time yet to compile full access point list.
			 * Give it some more time and scan again.  If that doesn't work
			 * give up.
			 */
			g_usleep (G_USEC_PER_SEC / 2);
			err = iw_scan (iwlib_socket, (char *)nm_device_get_iface (dev), WIRELESS_EXT, &scan_results);
			if (err == -1)
			{
				close (iwlib_socket);
				return;
			}
		}

		/* New list for current scan data */
		temp_list = nm_ap_list_new (NETWORK_TYPE_DEVICE);
		if (!temp_list)
		{
			nm_dispose_scan_results (scan_results.result);
			close (iwlib_socket);
			return;
		}

		/* Shift all previous cached scan results and dispose of the oldest one. */
		if (dev->options.wireless.cached_ap_list4)
			nm_ap_list_unref (dev->options.wireless.cached_ap_list4);
		dev->options.wireless.cached_ap_list4 = dev->options.wireless.cached_ap_list3;
		dev->options.wireless.cached_ap_list3 = dev->options.wireless.cached_ap_list2;
		dev->options.wireless.cached_ap_list2 = dev->options.wireless.cached_ap_list1;
		dev->options.wireless.cached_ap_list1 = temp_list;

		/* Iterate over scan results and pick a "most" preferred access point. */
		tmp_ap = scan_results.result;
		while (tmp_ap)
		{
			/* We need at least an ESSID or a MAC address for each access point */
			if (tmp_ap->b.has_essid || tmp_ap->has_ap_addr)
			{
				NMAccessPoint		*nm_ap  = nm_ap_new ();

				/* Copy over info from scan to local structure */
				if (!tmp_ap->b.has_essid || (tmp_ap->b.essid && !strlen (tmp_ap->b.essid)))
				{
					nm_ap_set_essid (nm_ap, NULL);
					have_blank_essids = TRUE;
				}
				else
					nm_ap_set_essid (nm_ap, tmp_ap->b.essid);

				if (tmp_ap->b.has_key && (tmp_ap->b.key_flags & IW_ENCODE_DISABLED))
					nm_ap_set_encrypted (nm_ap, FALSE);
				else
					nm_ap_set_encrypted (nm_ap, TRUE);

				if (tmp_ap->has_ap_addr)
					nm_ap_set_address (nm_ap, (const struct ether_addr *)(tmp_ap->ap_addr.sa_data));

				nm_ap_set_strength (nm_ap, nm_wireless_qual_to_percent (dev, &(tmp_ap->stats.qual)));

				if (tmp_ap->b.has_freq)
					nm_ap_set_freq (nm_ap, tmp_ap->b.freq);

				/* Add the AP to the device's AP list */
				nm_ap_list_append_ap (dev->options.wireless.cached_ap_list1, nm_ap);
				nm_ap_unref (nm_ap);
			}
			tmp_ap = tmp_ap->next;
		}
		nm_dispose_scan_results (scan_results.result);
		close (iwlib_socket);

		/* Compose the current access point list for the card based on the past two scans.  This
		 * is to achieve some stability in the list, since cards don't necessarily return the same
		 * access point list each scan even if you are standing in the same place.
		 * Once we have the list, copy in any relevant information from our Allowed list.
		 */
		old_ap_list = nm_device_ap_list_get (dev);
		dev->options.wireless.ap_list = nm_ap_list_combine (dev->options.wireless.cached_ap_list1, dev->options.wireless.cached_ap_list2);
		nm_ap_list_copy_properties (nm_device_ap_list_get (dev), dev->app_data->allowed_ap_list);

		/* If any blank ESSID networks were detected in the current scan, try to match their
		 * AP MAC address with existing ones in previous scans, and if we get a match, copy the
		 * ESSID over to the newest scan list.  This enures that we keep the known ESSID for that
		 * base station around as long as possible, which allows nm_device_update_best_ap() to do
		 * its job when the user wanted us to connect to a non-broadcasting network.
		 */
		if (have_blank_essids)
			nm_ap_list_copy_essids_by_address (nm_device_ap_list_get (dev), old_ap_list);

		/* Furthermore, if we have an "artificial" access points, ie ones that exist but don't show up in
		 * the scan for some reason, copy those over if we are associated with that access point right now.
		 * Some Cisco cards don't report non-ESSID-broadcasting access points in their scans even though
		 * the card associates with that AP just fine.
		 */
		if ((iter = nm_ap_list_iter_new (old_ap_list)))
		{
			char *essid = nm_device_get_essid (dev);

			while (essid && (artificial_ap = nm_ap_list_iter_next (iter)))
			{
				/* Copy over the artificial AP from the old list to the new one if
				 * its the AP the card is currently associated with.
				 */
				if (	    nm_ap_get_essid (artificial_ap)
					&& !strcmp (essid, nm_ap_get_essid (artificial_ap))
					&&  nm_ap_get_artificial (artificial_ap))
					nm_ap_list_append_ap (nm_device_ap_list_get (dev), artificial_ap);
			}
			nm_ap_list_iter_free (iter);
		}

		nm_ap_list_unref (old_ap_list);

		/* Generate the "old" list from the 3rd and 4th oldest scans we've done */
		old_ap_list = nm_ap_list_combine (dev->options.wireless.cached_ap_list3, dev->options.wireless.cached_ap_list4);

		/* Now do a diff of the old and new networks that we can see, and
		 * signal any changes over dbus, but only if we are active device.
		 */
		nm_ap_list_diff (dev->app_data, dev, old_ap_list, nm_device_ap_list_get (dev));
		if (old_ap_list)
			nm_ap_list_unref (old_ap_list);
	}
	else
		syslog (LOG_ERR, "nm_device_do_normal_scan() could not get a control socket for the wireless card %s.", nm_device_get_iface (dev) );
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

		nm_device_set_essid (dev, nm_ap_get_essid (ap));
		if (nm_ap_get_enc_key_source (ap))
		{
			char *hashed_key = nm_ap_get_enc_key_hashed (ap);
			nm_device_set_enc_key (dev, hashed_key);
			g_free (hashed_key);
		}
		else
			nm_device_set_enc_key (dev, NULL);

		/* Wait a bit for association */
		g_usleep (G_USEC_PER_SEC);

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
			nm_data_mark_state_changed (dev->app_data);
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

		/* Merge settings from wireless networks, mainly Keys */
		if ((list_ap = nm_ap_list_get_ap_by_essid (dev->app_data->allowed_ap_list, nm_ap_get_essid (nm_ap))))
		{
			nm_ap_set_timestamp (nm_ap, nm_ap_get_timestamp (list_ap));
			nm_ap_set_enc_key_source (nm_ap, nm_ap_get_enc_key_source (list_ap), nm_ap_get_enc_method (list_ap));
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
 * nm_device_do_wireless_scan
 *
 * Get a list of access points this device can see.
 *
 */
void nm_device_do_wireless_scan (NMDevice *dev)
{
	g_return_if_fail (dev != NULL);
	g_return_if_fail (dev->app_data != NULL);
	g_return_if_fail (nm_device_is_wireless (dev));

	if (!nm_try_acquire_mutex (dev->options.wireless.scan_mutex, __FUNCTION__))
		return;

	/* Compose a fake list of access points */
	if (dev->test_device)
	{
		nm_device_fake_ap_list (dev);
		nm_unlock_mutex (dev->options.wireless.scan_mutex, __FUNCTION__);
		return;
	}

	if (nm_device_get_supports_wireless_scan (dev))
		nm_device_do_normal_scan (dev);
	else
	{
		struct ether_addr	 ap_addr;

		/* We can't pseudo-scan without switching APs, therefore
		 * if the card has a valid access point and its an allowed
		 * access point, don't pseudo-scan for others.
		 */
		nm_device_get_ap_address (dev, &ap_addr);
		if (    !nm_ethernet_address_is_valid (&ap_addr)
			|| !nm_ap_list_get_ap_by_essid (dev->app_data->allowed_ap_list, nm_device_get_essid (dev))
			|| !nm_device_get_best_ap (dev))
		{
			nm_device_do_pseudo_scan (dev);
		}
	}

	nm_unlock_mutex (dev->options.wireless.scan_mutex, __FUNCTION__);
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


/****************************************/
/* Code ripped from HAL                 */
/*   minor modifications made for       */
/* integration with NLM                 */
/****************************************/

/** Read a word from the MII transceiver management registers 
 *
 *  @param  iface               Which interface
 *  @param  location            Which register
 *  @return                     Word that is read
 */
static guint16 mdio_read (int sockfd, struct ifreq *ifr, int location, gboolean new_ioctl_nums)
{
	guint16 *data = (guint16 *) &(ifr->ifr_data);

	data[1] = location;
	if (ioctl (sockfd, new_ioctl_nums ? 0x8948 : SIOCDEVPRIVATE + 1, ifr) < 0)
	{
		syslog(LOG_ERR, "SIOCGMIIREG on %s failed: %s", ifr->ifr_name, strerror (errno));
		return -1;
	}
	return data[3];
}

static gboolean mii_get_link (NMDevice *dev)
{
	int			sockfd;
	struct ifreq	ifr;
	gboolean		new_ioctl_nums;
	guint16		status_word;
	gboolean		link_active = FALSE;

	sockfd = socket (AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
	{
		syslog (LOG_ERR, "cannot open socket on interface %s; errno=%d", nm_device_get_iface (dev), errno);
		return (FALSE);
	}

	snprintf (ifr.ifr_name, IFNAMSIZ, nm_device_get_iface (dev));
	if (ioctl (sockfd, 0x8947, &ifr) >= 0)
		new_ioctl_nums = TRUE;
	else if (ioctl (sockfd, SIOCDEVPRIVATE, &ifr) >= 0)
		new_ioctl_nums = FALSE;
	else
	{
		syslog (LOG_ERR, "SIOCGMIIPHY on %s failed: %s", ifr.ifr_name, strerror (errno));
		close (sockfd);
		return (FALSE);
	}

	/* Refer to http://www.scyld.com/diag/mii-status.html for
	 * the full explanation of the numbers
	 *
	 * 0x8000  Capable of 100baseT4.
	 * 0x7800  Capable of 10/100 HD/FD (most common).
	 * 0x0040  Preamble suppression permitted.
	 * 0x0020  Autonegotiation complete.
	 * 0x0010  Remote fault.
	 * 0x0008  Capable of Autonegotiation.
	 * 0x0004  Link established ("sticky"* on link failure)
	 * 0x0002  Jabber detected ("sticky"* on transmit jabber)
	 * 0x0001  Extended MII register exist.
	 *
	 */

	/* We have to read it twice to clear any "sticky" bits */
	status_word = mdio_read (sockfd, &ifr, 1, new_ioctl_nums);
	status_word = mdio_read (sockfd, &ifr, 1, new_ioctl_nums);

	if ((status_word & 0x0016) == 0x0004)
		link_active = TRUE;
	else
		link_active = FALSE;

	close (sockfd);

	return (link_active);
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
