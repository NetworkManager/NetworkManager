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
	gchar			*cur_essid;
	gboolean			 supports_wireless_scan;
	GMutex			*scan_mutex;

	NMAccessPointList	*ap_list;

	NMAccessPoint		*best_ap;
	GMutex			*best_ap_mutex;
	gboolean			 freeze_best_ap;

	gboolean			 user_key_received;
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


/*
 * NetworkManager device structure
 */
struct NMDevice
{
	guint			 refcount;

	gchar			*udi;
	gchar			*iface;
	NMDeviceType		 type;
	gboolean			 link_active;
	guint32			 ip4_address;
	/* FIXME: ipv6 address too */
	NMData			*app_data;
	NMDeviceOptions	 options;

	gboolean			 activating;
	gboolean			 just_activated;
	gboolean			 quit_activation;
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
	
	iwlib_socket = iw_sockets_open ();
	error = iw_scan (iwlib_socket, nm_device_get_iface (dev), WIRELESS_EXT, &scan_data);
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
 * Creates and initializes the structure representation of an NM device.
 *
 */
NMDevice *nm_device_new (const char *iface, NMData *app_data)
{
	NMDevice	*dev;

	g_return_val_if_fail (iface != NULL, NULL);
	g_return_val_if_fail (strlen (iface) > 0, NULL);

	dev = g_new0 (NMDevice, 1);
	if (!dev)
	{
		syslog (LOG_ERR, "nm_device_new() could not allocate a new device...  Not enough memory?");
		return (NULL);
	}

	dev->refcount = 1;
	dev->app_data = app_data;
	dev->iface = g_strdup (iface);
	dev->type = nm_device_test_wireless_extensions (dev) ?
						DEVICE_TYPE_WIRELESS_ETHERNET : DEVICE_TYPE_WIRED_ETHERNET;

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
	}

	/* Have to bring the device up before checking link status.  */
	if (!nm_device_is_up (dev))
		nm_device_bring_up (dev);
	nm_device_update_link_active (dev, TRUE);

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
			nm_ap_list_unref (dev->options.wireless.ap_list);
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
char * nm_device_get_iface (NMDevice *dev)
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
 * nm_device_update_link_active
 *
 * Updates the link state for a particular device.
 *
 */
void nm_device_update_link_active (NMDevice *dev, gboolean check_mii)
{
	gboolean		link_active = FALSE;

	g_return_if_fail (dev != NULL);
	g_return_if_fail (dev->app_data != NULL);

	/* FIXME
	 * For wireless cards, the best indicator of a "link" at this time
	 * seems to be whether the card has a valid access point MAC address.
	 * Is there a better way?
	 */
	switch (nm_device_get_type (dev))
	{
		case DEVICE_TYPE_WIRELESS_ETHERNET:
		{
			struct iwreq	 wrq;
			int			 iwlib_socket;
			NMData		*data = (NMData *)dev->app_data;

			/* Since non-active wireless cards are supposed to be powered off anyway,
			 * only scan for active/pending device and clear ap_list and best_ap for
			 * devices that aren't active/pending.
			 */
			if (dev == data->active_device)
			{
				iwlib_socket = iw_sockets_open ();
				if (iw_get_ext (iwlib_socket, nm_device_get_iface (dev), SIOCGIWAP, &wrq) >= 0)
				{
					if (nm_ethernet_address_is_valid ((struct ether_addr *)(&(wrq.u.ap_addr.sa_data))))
						if (nm_device_get_best_ap (dev) && !nm_device_need_ap_switch (dev))
							link_active = TRUE;
				}
				close (iwlib_socket);
			}
			else
			{
				nm_ap_list_unref (dev->options.wireless.ap_list);
				dev->options.wireless.ap_list = NULL;
				if (dev->options.wireless.best_ap)
					nm_ap_unref (dev->options.wireless.best_ap);
			}
			break;
		}

		case DEVICE_TYPE_WIRED_ETHERNET:
		{
			if (check_mii)
				link_active = mii_get_link (dev);
			else
				if (hal_device_property_exists (dev->app_data->hal_ctx, nm_device_get_udi (dev), "net.ethernet.link"))
					link_active = hal_device_get_property_bool (dev->app_data->hal_ctx, nm_device_get_udi (dev), "net.ethernet.link");
			break;
		}

		default:
			link_active = nm_device_get_link_active (dev);	/* Can't get link info for this device, so don't change link status */
			break;
	}

	/* Update device link status and global state variable if the status changed */
	if (link_active != nm_device_get_link_active (dev))
	{
		nm_device_set_link_active (dev, link_active);
		nm_data_set_state_modified (dev->app_data, TRUE);
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
	struct iwreq		wreq;
	char				essid[IW_ESSID_MAX_SIZE + 1];
	
	g_return_val_if_fail (dev != NULL, NULL);
	g_return_val_if_fail (nm_device_is_wireless (dev), NULL);
	
	iwlib_socket = iw_sockets_open ();
	if (iwlib_socket >= 0)
	{
		wreq.u.essid.pointer = (caddr_t) essid;
		wreq.u.essid.length = IW_ESSID_MAX_SIZE + 1;
		wreq.u.essid.flags = 0;
		err = iw_get_ext (iwlib_socket, nm_device_get_iface (dev), SIOCGIWESSID, &wreq);
		if (err >= 0)
		{
			if (dev->options.wireless.cur_essid)
				g_free (dev->options.wireless.cur_essid);
			dev->options.wireless.cur_essid = g_strdup (essid);
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

	/* Do we have a valid MAC address? */
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
		wreq.u.data.flags = IW_ENCODE_ENABLED;
		wreq.u.data.length = 0;

		if (strlen (safe_key) == 0)
		{
			wreq.u.data.flags = IW_ENCODE_DISABLED | IW_ENCODE_NOKEY;	/* Disable WEP */
			set_key = TRUE;
		}
		else
		{
			unsigned char		parsed_key[IW_ENCODING_TOKEN_MAX + 1];

			keylen = iw_in_key_full(iwlib_socket, nm_device_get_iface (dev), safe_key, &parsed_key[0], &wreq.u.data.flags);
			if (keylen > 0)
			{
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

	/* Reset communication flags between worker and main thread */
	dev->activating = FALSE;
	dev->just_activated = FALSE;
	dev->quit_activation = FALSE;
	if (nm_device_is_wireless (dev))
		dev->options.wireless.user_key_received = FALSE;

	if (!g_thread_create (nm_device_activation_worker, dev, FALSE, &error))
	{
		syslog (LOG_CRIT, "nm_device_activation_begin(): could not create activation worker thread.");
		return (FALSE);
	}

	nm_dbus_signal_device_activating (data->dbus_connection, dev);

	return (TRUE);
}


/*
 * nm_device_wireless_activate
 *
 * Bring up a wireless card with the essid and wep key of its "best" ap
 *
 * Returns:	TRUE on successful activation
 *			FALSE on unsuccessful activation (ie no best AP)
 *
 */
static gboolean nm_device_activate_wireless (NMDevice *dev)
{
	NMAccessPoint	*best_ap;
	gboolean		 success = FALSE;

	g_return_val_if_fail (dev  != NULL, FALSE);
	g_return_val_if_fail (nm_device_is_wireless (dev), FALSE);

	/* If the card is just inserted, we may not have had a chance to scan yet */
	if (!(best_ap = nm_device_get_best_ap (dev)))
	{
		nm_device_do_wireless_scan (dev);
		best_ap = nm_device_get_best_ap (dev);
	}

	/* If there is a desired AP to connect to, use that essid and possible WEP key */
	if (best_ap && nm_ap_get_essid (best_ap))
	{
		nm_device_bring_down (dev);

		/* Disable encryption, then re-enable and set correct key on the card
		 * if we are going to encrypt traffic.
		 */
		nm_device_set_enc_key (dev, NULL);
		if (nm_ap_get_encrypted (best_ap) && nm_ap_get_enc_key_source (best_ap))
		{
			char *hashed_key = nm_ap_get_enc_key_hashed (best_ap, nm_ap_get_enc_method (best_ap));
			nm_device_set_enc_key (dev, hashed_key);
			g_free (hashed_key);
		}

		nm_device_set_essid (dev, nm_ap_get_essid (best_ap));

		syslog (LOG_INFO, "nm_device_wireless_activate(%s) using essid '%s'", nm_device_get_iface (dev), nm_ap_get_essid (best_ap));

		/* Bring the device up */
		if (!nm_device_is_up (dev));
			nm_device_bring_up (dev);
		g_usleep (G_USEC_PER_SEC / 2);	/* Pause to allow card to associate */

		nm_device_update_link_active (dev, FALSE);
		success = TRUE;
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
	dev->activating = TRUE;

	/* If its a wireless device, set the ESSID and WEP key */
	if (nm_device_is_wireless (dev))
	{
		nm_device_activate_wireless (dev);

		/* If we don't have a link, it probably means the access point has
		 * encryption enabled and we don't have the right WEP key, or we don't
		 * have a "best" access point.  Sit around and wait for either the WEP key
		 * or a good "best" AP.
		 */
		while (!nm_device_get_link_active (dev))
		{
			NMAccessPoint	*best_ap;

			if ((best_ap = nm_device_get_best_ap (dev)))
			{
				/* WEP key we have is wrong, ask user for one */
				if (    (!nm_device_need_ap_switch (dev) || !nm_ap_get_enc_key_source (best_ap))
					&& nm_ap_get_encrypted (best_ap))
				{
					gboolean	ask_for_key = TRUE;

					/* If we have a key, try all the key/passphrase generation methods
					 * before asking the user for a key.
					 */
					if (nm_ap_get_enc_key_source (best_ap) && !nm_ap_get_enc_method_good (best_ap))
					{
						/* Try another method, since the one set before obviously didn't work */
						switch (nm_ap_get_enc_method (best_ap))
						{
							case (NM_AP_ENC_METHOD_UNKNOWN):
								nm_ap_set_enc_method (best_ap, NM_AP_ENC_METHOD_104_BIT_PASSPHRASE);
								ask_for_key = FALSE;
								break;
							case (NM_AP_ENC_METHOD_104_BIT_PASSPHRASE):
								nm_ap_set_enc_method (best_ap, NM_AP_ENC_METHOD_40_BIT_PASSPHRASE);
								ask_for_key = FALSE;
								break;
							case (NM_AP_ENC_METHOD_40_BIT_PASSPHRASE):
								nm_ap_set_enc_method (best_ap, NM_AP_ENC_METHOD_HEX_KEY);
								ask_for_key = FALSE;
								break;
							default:
								break;
						}
					}

					if (ask_for_key)
					{
						dev->options.wireless.user_key_received = FALSE;
						nm_dbus_get_user_key_for_network (dev->app_data->dbus_connection, dev, best_ap);

						/* Wait for the key to come back */
						while (!dev->options.wireless.user_key_received && !dev->quit_activation)
							g_usleep (G_USEC_PER_SEC / 2);

						syslog (LOG_DEBUG, "nm_device_activation_worker(%s): user key received!", nm_device_get_iface (dev));
					}

					/* If we were told to quit activation, stop the thread and return */
					if (dev->quit_activation)
					{
						syslog (LOG_DEBUG, "nm_device_activation_worker(%s): activation canceled 1", nm_device_get_iface (dev));
						dev->just_activated = FALSE;
						nm_device_unref (dev);
						return (NULL);
					}
				}

				nm_device_activate_wireless (dev);
			}
			else
				g_usleep (G_USEC_PER_SEC * 2);

			/* If we were told to quit activation, stop the thread and return */
			if (dev->quit_activation)
			{
				syslog (LOG_DEBUG, "nm_device_activation_worker(%s): activation canceled 1.5", nm_device_get_iface (dev));
				dev->just_activated = FALSE;
				nm_device_unref (dev);
				return (NULL);
			}
		}

		/* Since we've got a link, the encryption method must be good */
		nm_ap_set_enc_method_good (nm_device_get_best_ap (dev), TRUE);

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
		/* Save machine host name */
		host_err = gethostname (&hostname[0], 100);

		if (!nm_system_device_run_dhcp (dev))
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

		/* Set the hostname back to what it was before so that X11 doesn't
		 * puke when the hostname changes, and so users can actually launch stuff.
		 */
		if (host_err >= 0)
			sethostname (hostname, strlen (hostname));

		/* If we were told to quit activation, stop the thread and return */
		if (dev->quit_activation)
		{
			syslog (LOG_DEBUG, "nm_device_activation_worker(%s): activation canceled 2", nm_device_get_iface (dev));
			dev->just_activated = FALSE;
			nm_device_unref (dev);
			return (NULL);
		}

		/* Make system aware of any new DNS settings from resolv.conf */
		nm_system_update_dns ();
	}

	/* If we were told to quit activation, stop the thread and return */
	if (dev->quit_activation)
	{
		syslog (LOG_DEBUG, "nm_device_activation_worker(%s): activation canceled 3", nm_device_get_iface (dev));
		dev->just_activated = FALSE;
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
 * nm_device_just_activated
 *
 * Check if the device was just activated successfully or not.  If so, clear
 * its just_activated flag and return TRUE.  If its not activated yet, return FALSE.
 *
 */
gboolean nm_device_just_activated (NMDevice *dev)
{
	g_return_val_if_fail (dev != NULL, FALSE);

	if (dev->just_activated)
	{
		dev->just_activated = FALSE;
		return (TRUE);
	}
	else
		return (FALSE);
}


/*
 * nm_device_activating
 *
 * Return whether or not the device is currently activating itself.
 *
 */
gboolean nm_device_activating (NMDevice *dev)
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

	syslog (LOG_DEBUG, "nm_device_activation_cancel(%s): canceled", nm_device_get_iface (dev));
	dev->quit_activation = TRUE;
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

	/* Take out any entries in the routing table and any IP address the old device had. */
	nm_system_device_flush_routes (dev);
	nm_system_device_flush_addresses (dev);
	dev->ip4_address = 0;

	if (!just_added)
		nm_dbus_signal_device_no_longer_active (dev->app_data->dbus_connection, dev);

	/* Clean up stuff, don't leave the card associated or up */
	if (nm_device_is_wireless (dev))
	{
		nm_device_set_essid (dev, "");
		nm_device_set_enc_key (dev, NULL);
		nm_device_bring_down (dev);
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
									unsigned char *network, unsigned char *key)
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
		{
			nm_ap_set_enc_key_source (best_ap, key);
			nm_ap_set_enc_method (best_ap, NM_AP_ENC_METHOD_UNKNOWN);
		}
	}
fprintf( stderr, "Got user key\n");
	dev->options.wireless.user_key_received = TRUE;
}


/*
 * nm_device_ap_list_add
 *
 * Add an access point to the devices internal AP list.
 *
 */
void	nm_device_ap_list_add (NMDevice *dev, NMAccessPoint *ap)
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

gboolean nm_device_get_best_ap_frozen (NMDevice *dev)
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

	return (g_strdup_printf ("%s/%s/Networks/%s", NM_DBUS_PATH_DEVICES, nm_device_get_iface (dev), nm_ap_get_essid (ap)));
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
 * Recalculate the "best" access point we should be associating with.
 *
 */
void nm_device_update_best_ap (NMDevice *dev)
{
	time_t			 latest_timestamp = 0;
	NMAccessPointList	*ap_list;
	NMAPListIter		*iter;
	NMAccessPoint		*ap = NULL;
	NMAccessPoint		*best_ap = NULL;

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
	if (nm_device_get_best_ap_frozen (dev))
	{
		best_ap = nm_device_get_best_ap (dev);

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

	/* Check the trusted list then */
	if (!(iter = nm_ap_list_iter_new (ap_list)))
		return;
	while ((ap = nm_ap_list_iter_next (iter)))
	{
		char		*ap_essid = nm_ap_get_essid (ap);

		/* Access points in the "invalid" list cannot be used */
		if (!nm_ap_list_get_ap_by_essid (dev->app_data->invalid_ap_list, ap_essid))
		{
			NMAccessPoint	*tmp_ap = nm_ap_list_get_ap_by_essid (dev->app_data->trusted_ap_list, ap_essid);

			/* If it exists in the trusted ap list, and it is more recent than
			 * access points already tested, make it the best for now.
			 */
			if (tmp_ap && (nm_ap_get_timestamp (tmp_ap) > latest_timestamp))
			{
				latest_timestamp = nm_ap_get_timestamp (tmp_ap);
				best_ap = ap;
			}
		}
	}
	nm_ap_list_iter_free (iter);

	/* If its not in the trusted list, check the preferred list */
	if (!best_ap)
	{
		latest_timestamp = 0;

		if (!(iter = nm_ap_list_iter_new (ap_list)))
			return;
		while ((ap = nm_ap_list_iter_next (iter)))
		{
			char		*ap_essid = nm_ap_get_essid (ap);

			/* Access points in the "invalid" list cannot be used */
			if (!nm_ap_list_get_ap_by_essid (dev->app_data->invalid_ap_list, ap_essid))
			{
				NMAccessPoint	*tmp_ap = nm_ap_list_get_ap_by_essid (dev->app_data->preferred_ap_list, ap_essid);

				/* If it exists in the preferred ap list, and it is more recent than
				 * access points already tested, make it the best for now.
				 */
				if ( tmp_ap && (nm_ap_get_timestamp (tmp_ap) > latest_timestamp))
				{
					latest_timestamp = nm_ap_get_timestamp (tmp_ap);
					best_ap = ap;
				}
			}
		}
		nm_ap_list_iter_free (iter);
	}

	/* If the best ap is NULL, bring device down and clear out its essid and AP */
	nm_device_set_best_ap (dev, best_ap);
	if (!best_ap)
	{
		nm_device_bring_down (dev);
		nm_device_set_essid (dev, "");
		nm_device_bring_up (dev);
	}
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
		NMAccessPointList	*old_ap_list = nm_device_ap_list_get (dev);

		err = iw_scan (iwlib_socket, nm_device_get_iface (dev), WIRELESS_EXT, &scan_results);
		if ((err == -1) && (errno == ENODATA))
		{
			/* Card hasn't had time yet to compile full access point list.
			 * Give it some more time and scan again.  If that doesn't work
			 * give up.
			 */
			g_usleep (G_USEC_PER_SEC / 2);
			err = iw_scan (iwlib_socket, nm_device_get_iface (dev), WIRELESS_EXT, &scan_results);
			if (err == -1)
			{
				close (iwlib_socket);
				return;
			}
		}

		/* Clear out the ap list for this device in preparation for any new ones */
		dev->options.wireless.ap_list = nm_ap_list_new (NETWORK_TYPE_DEVICE);
		if (!(dev->options.wireless.ap_list))
		{
			nm_dispose_scan_results (scan_results.result);
			close (iwlib_socket);
			return;
		}

		/* Iterate over scan results and pick a "most" preferred access point. */
		tmp_ap = scan_results.result;
		while (tmp_ap)
		{
			/* Blank essids usually indicate an AP that is not broadcasting its essid,
			 * but since its not broadcasting the essid, we cannot use that ap yet.
			 */
			if (tmp_ap->b.has_essid && tmp_ap->b.essid_on && (strlen (tmp_ap->b.essid) > 0))
			{
				NMAccessPoint		*nm_ap  = nm_ap_new ();
				NMAccessPoint		*list_ap;

				/* Copy over info from scan to local structure */
				nm_ap_set_essid (nm_ap, tmp_ap->b.essid);

				if (tmp_ap->b.has_key && (tmp_ap->b.key_flags & IW_ENCODE_DISABLED))
				{
					nm_ap_set_encrypted (nm_ap, FALSE);
					nm_ap_set_enc_method (nm_ap, NM_AP_ENC_METHOD_NONE);
				}
				else
				{
					nm_ap_set_encrypted (nm_ap, TRUE);
					nm_ap_set_enc_method (nm_ap, NM_AP_ENC_METHOD_UNKNOWN);
				}

				if (tmp_ap->has_ap_addr)
					nm_ap_set_address (nm_ap, (const struct ether_addr *)(tmp_ap->ap_addr.sa_data));

				nm_ap_set_quality (nm_ap, tmp_ap->stats.qual.qual);

				if (tmp_ap->b.has_freq)
					nm_ap_set_freq (nm_ap, tmp_ap->b.freq);

				/* Merge settings from Preferred/Allowed networks, mainly Keys */
				list_ap = nm_ap_list_get_ap_by_essid (data->trusted_ap_list, nm_ap_get_essid (nm_ap));
				if (!list_ap)
					list_ap = nm_ap_list_get_ap_by_essid (data->preferred_ap_list, nm_ap_get_essid (nm_ap));
				if (list_ap)
				{
					nm_ap_set_timestamp (nm_ap, nm_ap_get_timestamp (list_ap));
					nm_ap_set_enc_key_source (nm_ap, nm_ap_get_enc_key_source (list_ap));
				}

				/* Add the AP to the device's AP list */
				nm_device_ap_list_add (dev, nm_ap);
			}
			tmp_ap = tmp_ap->next;
		}
		nm_dispose_scan_results (scan_results.result);
		close (iwlib_socket);

		/* Now do a diff of the old and new networks that we can see, and
		 * signal any changes over dbus, but only if we are active device.
		 */
		if (dev == data->active_device)
			nm_ap_list_diff (dev->app_data, dev, old_ap_list, nm_device_ap_list_get (dev));
		if (old_ap_list)
			nm_ap_list_unref (old_ap_list);

		nm_device_update_best_ap (dev);
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
	NMAccessPointList	*list;
	NMAPListIter		*iter;
	NMAccessPoint		*ap;

	g_return_if_fail (dev  != NULL);
	g_return_if_fail (dev->app_data != NULL);

	nm_device_ref (dev);

	if (!(list = nm_device_ap_list_get (dev)))
		return;

	if (!(iter = nm_ap_list_iter_new (list)))
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
			nm_device_set_enc_key (dev, nm_ap_get_enc_key_source (ap));
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
			nm_data_set_state_modified (dev->app_data, TRUE);
			break;
		}
	}

	nm_ap_list_iter_free (iter);
	nm_device_unref (dev);
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
			|| !nm_ap_list_get_ap_by_essid (dev->app_data->trusted_ap_list, nm_device_get_essid (dev))
			|| !nm_ap_list_get_ap_by_essid (dev->app_data->preferred_ap_list, nm_device_get_essid (dev))
			|| !nm_device_get_best_ap (dev))
		{
			nm_device_do_pseudo_scan (dev);
		}
	}

	nm_unlock_mutex (dev->options.wireless.scan_mutex, __FUNCTION__);
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
