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
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "NetworkManager.h"
#include "NetworkManagerDevice.h"
#include "NetworkManagerUtils.h"

extern gboolean	debug;

static gboolean mii_get_link (NMDevice *dev);
static void nm_device_link_detection_init (NMDevice *dev);

/*
 * nm_device_is_wireless
 *
 * Test whether a given device is a wireless one or not.
 *
 */
static gboolean nm_device_is_wireless (NMDevice *dev)
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
	iwstats				stats;
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
/* NMDevice object routines                                      */
/*****************************************************************************/

typedef struct NMDeviceWirelessOptions
{
	gchar				*cur_essid;
	gboolean				 supports_wireless_scan;
	GMutex				*ap_list_mutex;
	GSList				*ap_list;
} NMDeviceWirelessOptions;

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
	NMIfaceType		 iface_type;
	gboolean			 link_active;
	NMDeviceOptions	 dev_options;
};


/*
 * nm_device_new
 *
 * Creates and initializes the structure representation of an NLM device.
 *
 */
NMDevice *nm_device_new (const char *iface)
{
	NMDevice	*dev;

	g_return_val_if_fail (iface != NULL, NULL);
	
	dev = g_new0 (NMDevice, 1);
	if (!dev)
	{
		NM_DEBUG_PRINT("nm_device_new() could not allocate a new device...  Not enough memory?\n");
		return (NULL);
	}

	dev->refcount = 1;
	dev->iface = g_strdup (iface);
	dev->iface_type = nm_device_is_wireless (dev) ?
						NM_IFACE_TYPE_WIRELESS_ETHERNET : NM_IFACE_TYPE_WIRED_ETHERNET;

	if (dev->iface_type == NM_IFACE_TYPE_WIRELESS_ETHERNET)
	{
		dev->dev_options.wireless.supports_wireless_scan = nm_device_supports_wireless_scan (dev);

		dev->dev_options.wireless.ap_list_mutex = g_mutex_new();
		if (!dev->dev_options.wireless.ap_list_mutex)
		{
			g_free (dev->iface);
			return (NULL);
		}
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
	if (dev->refcount == 0)
	{
		nm_device_ap_list_clear (dev);
		dev->dev_options.wireless.ap_list = NULL;

		g_free (dev->udi);
		g_free (dev->iface);
		if (dev->iface_type == NM_IFACE_TYPE_WIRELESS_ETHERNET)
		{
			g_free (dev->dev_options.wireless.cur_essid);
			g_mutex_free (dev->dev_options.wireless.ap_list_mutex);
		}

		dev->udi = NULL;
		dev->iface = NULL;
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
 * Get/set functions for iface_type
 */
guint nm_device_get_iface_type (NMDevice *dev)
{
	g_return_val_if_fail (dev != NULL, NM_IFACE_TYPE_DONT_KNOW);

	return (dev->iface_type);
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

	return (dev->dev_options.wireless.supports_wireless_scan);
}


/*
 * nm_device_update_link_active
 *
 * Updates the link state for a particular device.
 *
 */
gboolean nm_device_update_link_active (NMDevice *dev, gboolean check_mii)
{
	gboolean		link_active = FALSE;

	g_return_val_if_fail (dev  != NULL, FALSE);

	/* FIXME
	 * For wireless cards, the best indicator of a "link" at this time
	 * seems to be whether the card has a valid access point MAC address.
	 * Is there a better way?
	 */

	switch (nm_device_get_iface_type (dev))
	{
		case NM_IFACE_TYPE_WIRELESS_ETHERNET:
		{
			struct iwreq		wrq;
			int				iwlib_socket;

			iwlib_socket = iw_sockets_open ();
			if (iw_get_ext (iwlib_socket, nm_device_get_iface (dev), SIOCGIWAP, &wrq) >= 0)
			{
				struct ether_addr	invalid_addr1;
				struct ether_addr	invalid_addr2;
				struct ether_addr	invalid_addr3;
				struct ether_addr	ap_addr;

				/* Compare the AP address the card has with invalid ethernet MAC addresses.
				 */
				memcpy (&ap_addr, &(wrq.u.ap_addr.sa_data), sizeof (struct ether_addr));
				memset (&invalid_addr1, 0xFF, sizeof(struct ether_addr));
				memset (&invalid_addr2, 0x00, sizeof(struct ether_addr));
				memset (&invalid_addr2, 0x44, sizeof(struct ether_addr));
				if (    (memcmp(&ap_addr, &invalid_addr1, sizeof(struct ether_addr)) != 0)
					&& (memcmp(&ap_addr, &invalid_addr2, sizeof(struct ether_addr)) != 0)
					&& (memcmp(&ap_addr, &invalid_addr3, sizeof(struct ether_addr)) != 0))
					link_active = TRUE;
			}
			close (iwlib_socket);
			break;
		}

		case NM_IFACE_TYPE_WIRED_ETHERNET:
		{
			if (check_mii)
				link_active = mii_get_link (dev);
			else
				if (hal_device_property_exists (nm_get_global_data()->hal_ctx, nm_device_get_udi (dev), "net.ethernet.link"))
					link_active = hal_device_get_property_bool (nm_get_global_data()->hal_ctx, nm_device_get_udi (dev), "net.ethernet.link");
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
		nm_data_set_state_modified (nm_get_global_data(), TRUE);
	}
	return (link_active);
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
	g_return_val_if_fail (dev->iface_type == NM_IFACE_TYPE_WIRELESS_ETHERNET, NULL);
	
	iwlib_socket = iw_sockets_open ();
	if (iwlib_socket >= 0)
	{
		wreq.u.essid.pointer = (caddr_t) essid;
		wreq.u.essid.length = IW_ESSID_MAX_SIZE + 1;
		wreq.u.essid.flags = 0;
		err = iw_get_ext (iwlib_socket, nm_device_get_iface (dev), SIOCGIWESSID, &wreq);
		if (err >= 0)
		{
			if (dev->dev_options.wireless.cur_essid)
				g_free (dev->dev_options.wireless.cur_essid);
			dev->dev_options.wireless.cur_essid = g_strdup (essid);
		}
		else
			NM_DEBUG_PRINT_2 ("nm_device_get_essid(): error setting ESSID for device %s.  errno = %d\n", nm_device_get_iface (dev), errno);

		close (iwlib_socket);
	}

	return (dev->dev_options.wireless.cur_essid);
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
	g_return_if_fail (dev->iface_type == NM_IFACE_TYPE_WIRELESS_ETHERNET);

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
			NM_DEBUG_PRINT_2 ("nm_device_set_essid(): error setting ESSID for device %s.  errno = %d\n", nm_device_get_iface (dev), errno);

		close (iwlib_socket);
	}
}


/*
 * nm_device_set_wep_key
 *
 * If a device is wireless, set the WEP key that it should use.
 *
 * wep_key:		WEP key to use, or NULL or "" to disable WEP
 */
void nm_device_set_wep_key (NMDevice *dev, const char *wep_key)
{
	int				iwlib_socket;
	int				err;
	struct iwreq		wreq;
	int				keylen;
	unsigned char		safe_key[IW_ENCODING_TOKEN_MAX];
	gboolean			set_key = FALSE;
	
	char *it = NULL;
	
	g_return_if_fail (dev != NULL);
	g_return_if_fail (dev->iface_type == NM_IFACE_TYPE_WIRELESS_ETHERNET);

	/* Make sure the essid we get passed is a valid size */
	if (!wep_key)
		safe_key[0] = '\0';
	else
	{
		strncpy (safe_key, wep_key, IW_ENCODING_TOKEN_MAX);
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
			keylen = iw_in_key_full(iwlib_socket, nm_device_get_iface (dev), "", safe_key, &wreq.u.data.flags);
			if (keylen > 0)
			{
				wreq.u.data.pointer	=  (caddr_t) safe_key;
				wreq.u.data.length	=  keylen;
				set_key = TRUE;
			}
		}

		if (set_key)
		{
			err = iw_set_ext (iwlib_socket, nm_device_get_iface (dev), SIOCSIWENCODE, &wreq);
			if (err == -1)
				NM_DEBUG_PRINT_2 ("nm_device_set_wep_key(): error setting key for device %s.  errno = %d\n", nm_device_get_iface (dev), errno);
		}

		close (iwlib_socket);
	}
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
				NM_DEBUG_PRINT_3 ("nm_device_set_up_down() could not bring device %s %s.  errno = %d\n", nm_device_get_iface (dev), (up ? "up" : "down"), errno );
		}
	}
	else
		NM_DEBUG_PRINT_2 ("nm_device_set_up_down() could not get flags for device %s.  errno = %d\n", nm_device_get_iface (dev), errno );

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
	int					 fd;

	g_return_if_fail (dev != NULL);

	nm_device_set_up_down (dev, FALSE);
}

gboolean nm_device_is_up (NMDevice *dev)
{
	int			iface_fd;
	struct ifreq	ifr;
	int			err;

	g_return_if_fail (dev != NULL);

	iface_fd = nm_get_network_control_socket ();
	if (iface_fd < 0)
		return (FALSE);

	/* Get device's flags */
	strcpy (ifr.ifr_name, nm_device_get_iface (dev));
	err = ioctl (iface_fd, SIOCGIFFLAGS, &ifr);
	close (iface_fd);
	if (!err)
		return (!((ifr.ifr_flags^IFF_UP) & IFF_UP));

	NM_DEBUG_PRINT_2 ("nm_device_is_up() could not get flags for device %s.  errno = %d\n", nm_device_get_iface (dev), errno );
	return (FALSE);
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
	g_return_if_fail (dev->iface_type == NM_IFACE_TYPE_WIRELESS_ETHERNET);

	if (nm_try_acquire_mutex (dev->dev_options.wireless.ap_list_mutex, __FUNCTION__))
	{
		nm_ap_ref (ap);
		dev->dev_options.wireless.ap_list = g_slist_append (dev->dev_options.wireless.ap_list, ap);

		nm_unlock_mutex (dev->dev_options.wireless.ap_list_mutex, __FUNCTION__);
	}
}


/*
 * nm_device_ap_list_clear
 *
 * Clears out the device's internal list of available access points.
 *
 */
void	nm_device_ap_list_clear (NMDevice *dev)
{
	GSList	*element;

	g_return_if_fail (dev != NULL);
	g_return_if_fail (dev->iface_type == NM_IFACE_TYPE_WIRELESS_ETHERNET);

	if (!dev->dev_options.wireless.ap_list)
		return;

	if (nm_try_acquire_mutex (dev->dev_options.wireless.ap_list_mutex, __FUNCTION__))
	{
		element = dev->dev_options.wireless.ap_list;
		while (element)
		{
			if (element->data)
			{
				nm_ap_unref (element->data);
				element->data = NULL;
			}

			element = g_slist_next (element);
		}

		g_slist_free (dev->dev_options.wireless.ap_list);
		dev->dev_options.wireless.ap_list = NULL;

		nm_unlock_mutex (dev->dev_options.wireless.ap_list_mutex, __FUNCTION__);
	}
}


/*
 * nm_device_ap_list_get_copy
 *
 * Copy the list of ESSIDs
 *
 */
NMAccessPoint *nm_device_ap_list_get_ap (NMDevice *dev, int index)
{
	GSList		*element;
	NMAccessPoint	*ap = NULL;

	g_return_val_if_fail (dev != NULL, NULL);
	g_return_val_if_fail (dev->iface_type == NM_IFACE_TYPE_WIRELESS_ETHERNET, NULL);

	if (!dev->dev_options.wireless.ap_list)
		return;

	if (nm_try_acquire_mutex (dev->dev_options.wireless.ap_list_mutex, __FUNCTION__))
	{
		int	i = 0;

		element = dev->dev_options.wireless.ap_list;
		while (element)
		{
			if (element->data && (index == i))
			{
				ap = (NMAccessPoint *)(element->data);
				break;
			}

			i++;
			element = g_slist_next (element);
		}
		nm_unlock_mutex (dev->dev_options.wireless.ap_list_mutex, __FUNCTION__);
	}

	return (ap);
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
		NM_DEBUG_PRINT_2("SIOCGMIIREG on %s failed: %s\n", ifr->ifr_name, strerror (errno));
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
		NM_DEBUG_PRINT_2("cannot open socket on interface %s; errno=%d", nm_device_get_iface (dev), errno);
		return (FALSE);
	}

	snprintf (ifr.ifr_name, IFNAMSIZ, nm_device_get_iface (dev));
	if (ioctl (sockfd, 0x8947, &ifr) >= 0)
		new_ioctl_nums = TRUE;
	else if (ioctl (sockfd, SIOCDEVPRIVATE, &ifr) >= 0)
		new_ioctl_nums = FALSE;
	else
	{
		NM_DEBUG_PRINT_2("SIOCGMIIPHY on %s failed: %s", ifr.ifr_name, strerror (errno));
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
