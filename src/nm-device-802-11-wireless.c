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
 * (C) Copyright 2005 Red Hat, Inc.
 */

#include <glib.h>
#include <glib/gi18n.h>
#include <dbus/dbus.h>
#include <netinet/in.h>
#include <string.h>
#include <net/ethernet.h>
#include <iwlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>

#include "nm-device.h"
#include "nm-device-802-11-wireless.h"
#include "nm-device-private.h"
#include "NetworkManagerAPList.h"
#include "NetworkManagerDbus.h"
#include "nm-utils.h"
#include "NetworkManagerUtils.h"
#include "NetworkManagerPolicy.h"
#include "nm-activation-request.h"
#include "nm-dbus-nmi.h"
#include "wpa_ctrl.h"
#include "cipher.h"

#define NM_SUPPLICANT_TIMEOUT	20	/* 20s: how long we wait for wpa_supplicant to associate */

/* #define IW_QUAL_DEBUG */

#define NM_DEVICE_802_11_WIRELESS_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_802_11_WIRELESS, NMDevice80211WirelessPrivate))

struct _NMDevice80211WirelessPrivate
{
	gboolean	dispose_has_run;

	struct ether_addr	hw_addr;

	char *			cur_essid;
	gint8			strength;
	gint8			invalid_strength_counter;
	iwqual			max_qual;
	iwqual			avg_qual;

	gint8			num_freqs;
	double			freqs[IW_MAX_FREQUENCIES];

	GMutex *			scan_mutex;
	NMAccessPointList *	ap_list;
	guint8			scan_interval; /* seconds */
	guint32			last_scan;

	/* Supplicant control */
	GPid				sup_pid;
	GSource *			sup_watch;
	GSource *			sup_status;
	struct wpa_ctrl *	sup_ctrl;
	GSource *			sup_timeout;

	guint32			failed_link_count;
	GSource *			link_timeout;

	/* Static options from driver */
	guint8			we_version;
	guint32			capabilities;
};


typedef struct
{
	NMDevice80211Wireless *	dev;
	guint8 *		results;
	guint32		results_len;
} NMWirelessScanResults;

typedef struct
{
	NMDevice80211Wireless *	dev;
	gboolean		force;
} NMWirelessScanCB;


static void	nm_device_802_11_wireless_ap_list_clear (NMDevice80211Wireless *self);

static gboolean nm_device_802_11_wireless_scan (gpointer user_data);

static gboolean	process_scan_results (NMDevice80211Wireless *dev,
                                          const guint8 *res_buf,
                                          guint32 res_buf_len);

static gboolean	get_scan_results (NMDevice80211Wireless *dev,
                                      NMSock *sk,
                                      guint8 **out_res_buf,
                                      guint32 *data_len);

static int	wireless_qual_to_percent (const struct iw_quality *qual,
                                         const struct iw_quality *max_qual,
                                         const struct iw_quality *avg_qual);

static gboolean	is_associated (NMDevice80211Wireless *self);

static gboolean	link_to_specific_ap (NMDevice80211Wireless *self,
								 NMAccessPoint *ap,
								 gboolean default_link);

static void		supplicant_cleanup (NMDevice80211Wireless *self);

static void		remove_link_timeout (NMDevice80211Wireless *self);

static guint32
real_get_generic_capabilities (NMDevice *dev)
{
	NMSock *			sk;
	int				err;
	guint32			caps = NM_DEVICE_CAP_NONE;
	iwrange			range;
	struct iwreq		wrq;

	/* Check for Wireless Extensions support >= 16 for wireless devices */

	if (!(sk = nm_dev_sock_open (dev, DEV_WIRELESS, __func__, NULL)))
		goto out;

	if (iw_get_range_info (nm_dev_sock_get_fd (sk), nm_device_get_iface (dev), &range) < 0)
		goto out;

	if (range.we_version_compiled < 16)
	{
		nm_warning ("%s: driver's Wireless Extensions version (%d) is too old.  Can't use device.",
			nm_device_get_iface (dev), range.we_version_compiled);
	}
	else
		caps |= NM_DEVICE_CAP_NM_SUPPORTED;

	memset (&wrq, 0, sizeof (struct iwreq));
	err = iw_set_ext (nm_dev_sock_get_fd (sk), nm_device_get_iface (dev), SIOCSIWSCAN, &wrq);
	if (!((err == -1) && (errno == EOPNOTSUPP)))
		caps |= NM_DEVICE_CAP_WIRELESS_SCAN;

out:
	if (sk)
		nm_dev_sock_close (sk);
	return caps;
}

static guint32
get_wireless_capabilities (NMDevice80211Wireless *self,
                           iwrange * range,
                           guint32 data_len)
{
	guint32	minlen;
	guint32	caps = NM_802_11_CAP_NONE;

	g_return_val_if_fail (self != NULL, NM_802_11_CAP_NONE);
	g_return_val_if_fail (range != NULL, NM_802_11_CAP_NONE);

	minlen = ((char *) &range->enc_capa) - (char *) range + sizeof (range->enc_capa);

	/* All drivers should support WEP by default */
	caps |= (NM_802_11_CAP_CIPHER_WEP40 | NM_802_11_CAP_CIPHER_WEP104);
	/* All drivers should support no encryption by default */
	caps |= (NM_802_11_CAP_PROTO_NONE | NM_802_11_CAP_PROTO_WEP);

	if ((data_len >= minlen) && range->we_version_compiled >= 18)
	{
		if (range->enc_capa & IW_ENC_CAPA_WPA)
		{
			caps |= (NM_802_11_CAP_PROTO_WPA
				  | NM_802_11_CAP_KEY_MGMT_PSK
				  | NM_802_11_CAP_KEY_MGMT_802_1X);
		}
		if (range->enc_capa & IW_ENC_CAPA_WPA2)
		{
			caps |= (NM_802_11_CAP_PROTO_WPA2
				  | NM_802_11_CAP_KEY_MGMT_PSK
				  | NM_802_11_CAP_KEY_MGMT_802_1X);
		}

		if (range->enc_capa & IW_ENC_CAPA_CIPHER_TKIP)
			caps |= NM_802_11_CAP_CIPHER_TKIP;
		if (range->enc_capa & IW_ENC_CAPA_CIPHER_CCMP)
			caps |= NM_802_11_CAP_CIPHER_CCMP;
	}

	return caps;
}


static void
nm_device_802_11_wireless_init (NMDevice80211Wireless * self)
{
	self->priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (self);
	self->priv->dispose_has_run = FALSE;

	memset (&(self->priv->hw_addr), 0, sizeof (struct ether_addr));
	self->priv->sup_pid = -1;
}

static void
real_init (NMDevice *dev)
{
	NMDevice80211Wireless *	self = NM_DEVICE_802_11_WIRELESS (dev);
	NMData *				app_data;
	guint32				caps;
	NMSock *				sk;

	self->priv->scan_mutex = g_mutex_new ();
	nm_register_mutex_desc (self->priv->scan_mutex, "Scan Mutex");

	self->priv->ap_list = nm_ap_list_new (NETWORK_TYPE_DEVICE);

	app_data = nm_device_get_app_data (NM_DEVICE (self));
	nm_device_802_11_wireless_set_scan_interval (app_data, self, NM_WIRELESS_SCAN_INTERVAL_ACTIVE);

	nm_device_802_11_wireless_set_mode (self, IW_MODE_INFRA);

	/* Non-scanning devices show the entire allowed AP list as their
	 * available networks.
	 */
	caps = nm_device_get_capabilities (NM_DEVICE (self));
	if (!(caps & NM_DEVICE_CAP_WIRELESS_SCAN))
		nm_device_802_11_wireless_copy_allowed_to_dev_list (self, app_data->allowed_ap_list);

	self->priv->we_version = 0;
	if ((sk = nm_dev_sock_open (NM_DEVICE (self), DEV_WIRELESS, __FUNCTION__, NULL)))
	{
		struct iw_range range;
		struct iwreq wrq;

		memset (&wrq, 0, sizeof (wrq));
		strncpy (wrq.ifr_name, nm_device_get_iface (NM_DEVICE (self)), IFNAMSIZ);
		wrq.u.data.pointer = (caddr_t) &range;
		wrq.u.data.length = sizeof (struct iw_range);

		if (ioctl (nm_dev_sock_get_fd (sk), SIOCGIWRANGE, &wrq) >= 0)
		{
			int i;

			self->priv->max_qual.qual = range.max_qual.qual;
			self->priv->max_qual.level = range.max_qual.level;
			self->priv->max_qual.noise = range.max_qual.noise;
			self->priv->max_qual.updated = range.max_qual.updated;

			self->priv->avg_qual.qual = range.avg_qual.qual;
			self->priv->avg_qual.level = range.avg_qual.level;
			self->priv->avg_qual.noise = range.avg_qual.noise;
			self->priv->avg_qual.updated = range.avg_qual.updated;

			self->priv->num_freqs = MIN (range.num_frequency, IW_MAX_FREQUENCIES);
			for (i = 0; i < self->priv->num_freqs; i++)
				self->priv->freqs[i] = iw_freq2float (&(range.freq[i]));

			self->priv->we_version = range.we_version_compiled;

			/* 802.11 wireless-specific capabilities */
			self->priv->capabilities = get_wireless_capabilities (self, &range, wrq.u.data.length);
		}
		nm_dev_sock_close (sk);
	}
}


static void
real_update_link (NMDevice *dev)
{
	NMDevice80211Wireless *	self = NM_DEVICE_802_11_WIRELESS (dev);

	/* If the supplicant isn't running, we can't possibly have a link */
	if (!self->priv->sup_pid)
		nm_device_set_active_link (NM_DEVICE (self), FALSE);
}


/*
 * nm_device_802_11_periodic_update
 *
 * Periodically update device statistics and link state.
 *
 */
static gboolean
nm_device_802_11_periodic_update (gpointer data)
{
	NMDevice80211Wireless *	self = NM_DEVICE_802_11_WIRELESS (data);

	g_return_val_if_fail (self != NULL, TRUE);

	nm_device_802_11_wireless_update_signal_strength (self);

	return TRUE;
}


static void
real_start (NMDevice *dev)
{
	NMDevice80211Wireless *	self = NM_DEVICE_802_11_WIRELESS (dev);
	GSource *				source;
	guint				source_id;

	/* Start the scanning timeout for devices that can do scanning */
	if (nm_device_get_capabilities (dev) & NM_DEVICE_CAP_WIRELESS_SCAN)
	{
		NMWirelessScanCB *	scan_cb;

		scan_cb = g_malloc0 (sizeof (NMWirelessScanCB));
		scan_cb->dev = self;
		scan_cb->force = TRUE;

		source = g_idle_source_new ();
		g_source_set_callback (source, nm_device_802_11_wireless_scan, scan_cb, NULL);
		source_id = g_source_attach (source, nm_device_get_main_context (dev));
		g_source_unref (source);
	}

	/* Peridoically update link status and signal strength */
	source = g_timeout_source_new (2000);
	g_source_set_callback (source, nm_device_802_11_periodic_update, self, NULL);
	source_id = g_source_attach (source, nm_device_get_main_context (dev));
	g_source_unref (source);
}

static void
real_deactivate_quickly (NMDevice *dev)
{
	NMDevice80211Wireless *	self = NM_DEVICE_802_11_WIRELESS (dev);

	supplicant_cleanup (self);
	remove_link_timeout (self);
}


static void
real_deactivate (NMDevice *dev)
{
	NMDevice80211Wireless *	self = NM_DEVICE_802_11_WIRELESS (dev);
	NMData *				app_data;

	app_data = nm_device_get_app_data (dev);
	g_assert (app_data);

	/* Clean up stuff, don't leave the card associated */
	nm_device_802_11_wireless_set_essid (self, "");
	nm_device_802_11_wireless_set_wep_enc_key (self, NULL, 0);
	nm_device_802_11_wireless_set_mode (self, IW_MODE_INFRA);
	nm_device_802_11_wireless_set_scan_interval (app_data, self, NM_WIRELESS_SCAN_INTERVAL_ACTIVE);
}


/*
 * nm_device_copy_allowed_to_dev_list
 *
 * For devices that don't support wireless scanning, copy
 * the allowed AP list to the device's ap list.
 *
 */
void
nm_device_802_11_wireless_copy_allowed_to_dev_list (NMDevice80211Wireless *self,
                                                    NMAccessPointList *allowed_list)
{
	NMAPListIter		*iter;
	NMAccessPoint		*src_ap;
	NMAccessPointList	*dev_list;

	g_return_if_fail (self != NULL);

	if (allowed_list == NULL)
		return;

	nm_device_802_11_wireless_ap_list_clear (self);
	self->priv->ap_list = nm_ap_list_new (NETWORK_TYPE_ALLOWED);

	if (!(iter = nm_ap_list_iter_new (allowed_list)))
		return;

	dev_list = nm_device_802_11_wireless_ap_list_get (self);
	while ((src_ap = nm_ap_list_iter_next (iter)))
	{
		NMAccessPoint *	dst_ap = nm_ap_new_from_ap (src_ap);

		nm_ap_list_append_ap (dev_list, dst_ap);
		nm_ap_unref (dst_ap);
	}
	nm_ap_list_iter_free (iter);
}


/*
 * nm_device_802_11_wireless_get_address
 *
 * Get a device's hardware address
 *
 */
void
nm_device_802_11_wireless_get_address (NMDevice80211Wireless *self,
                                       struct ether_addr *addr)
{
	g_return_if_fail (self != NULL);
	g_return_if_fail (addr != NULL);

	memcpy (addr, &(self->priv->hw_addr), sizeof (struct ether_addr));
}


/*
 * nm_device_802_11_wireless_set_address
 *
 * Set a device's hardware address
 *
 */
void
nm_device_802_11_wireless_set_address (NMDevice80211Wireless *self)
{
	NMDevice *dev = NM_DEVICE (self);
	struct ifreq req;
	NMSock *sk;
	int ret;

	g_return_if_fail (self != NULL);

	sk = nm_dev_sock_open (dev, DEV_GENERAL, __FUNCTION__, NULL);
	if (!sk)
		return;
	memset (&req, 0, sizeof (struct ifreq));
	strncpy (req.ifr_name, nm_device_get_iface (dev), sizeof (req.ifr_name) - 1);

	ret = ioctl (nm_dev_sock_get_fd (sk), SIOCGIFHWADDR, &req);
	if (ret)
		goto out;

	memcpy (&(self->priv->hw_addr), &(req.ifr_hwaddr.sa_data), sizeof (struct ether_addr));

out:
	nm_dev_sock_close (sk);
}


static gboolean
link_to_specific_ap (NMDevice80211Wireless *self,
                     NMAccessPoint *ap,
                     gboolean default_link)
{
	gboolean have_link = FALSE;

	/* Checking hardware's ESSID during a scan is doesn't work. */
	nm_lock_mutex (self->priv->scan_mutex, __func__);

	if (is_associated (self))
	{
		char *		dev_essid = nm_device_802_11_wireless_get_essid (self);
		const char *	ap_essid = nm_ap_get_essid (ap);

		if (dev_essid && ap_essid && !strcmp (dev_essid, ap_essid))
		{
			self->priv->failed_link_count = 0;
			have_link = TRUE;
		}
	}

	nm_unlock_mutex (self->priv->scan_mutex, __func__);

	if (!have_link)
	{
		self->priv->failed_link_count++;
		if (self->priv->failed_link_count <= 6)
			have_link = default_link;
	}

	return have_link;
}


/*
 * nm_device_update_best_ap
 *
 * Recalculate the "best" access point we should be associating with.
 *
 */
NMAccessPoint *
nm_device_802_11_wireless_get_best_ap (NMDevice80211Wireless *self)
{
	NMAccessPointList *	ap_list;
	NMAPListIter *		iter;
	NMAccessPoint *	scan_ap = NULL;
	NMAccessPoint *	best_ap = NULL;
	NMAccessPoint *	cur_ap = NULL;
	NMActRequest *		req = NULL;
	NMAccessPoint *	trusted_best_ap = NULL;
	NMAccessPoint *	untrusted_best_ap = NULL;
	GTimeVal			trusted_latest_timestamp = {0, 0};
	GTimeVal		 	untrusted_latest_timestamp = {0, 0};
	NMData *			app_data;

	g_return_val_if_fail (self != NULL, NULL);

	app_data = nm_device_get_app_data (NM_DEVICE (self));
	g_assert (app_data);

	/* Devices that can't scan don't do anything automatic.
	 * The user must choose the access point from the menu.
	 */
	if (    !(nm_device_get_capabilities (NM_DEVICE (self)) & NM_DEVICE_CAP_WIRELESS_SCAN)
		&& !nm_device_has_active_link (NM_DEVICE (self)))
		return NULL;

	if (!(ap_list = nm_device_802_11_wireless_ap_list_get (self)))
		return NULL;

	/* We prefer the currently selected access point if its user-chosen or if there
	 * is still a hardware link to it.
	 */
	if ((req = nm_device_get_act_request (NM_DEVICE (self))))
	{
		if ((cur_ap = nm_act_request_get_ap (req)))
		{
			const char *	essid = nm_ap_get_essid (cur_ap);
			gboolean		keep = FALSE;

			if (nm_ap_get_user_created (cur_ap))
				keep = TRUE;
			else if (nm_act_request_get_user_requested (req))
				keep = TRUE;
			else if (link_to_specific_ap (self, cur_ap, TRUE))
				keep = TRUE;

			/* Only keep if its not in the invalid list and its _is_ in our scaned list */
			if ( keep
				&& !nm_ap_list_get_ap_by_essid (app_data->invalid_ap_list, essid)
				&& nm_device_802_11_wireless_ap_list_get_ap_by_essid (self, essid))
			{
				nm_ap_ref (cur_ap);
				return cur_ap;
			}
		}
	}

	if (!(iter = nm_ap_list_iter_new (ap_list)))
		return NULL;
	while ((scan_ap = nm_ap_list_iter_next (iter)))
	{
		NMAccessPoint *tmp_ap;
		const char *	ap_essid = nm_ap_get_essid (scan_ap);

		/* Access points in the "invalid" list cannot be used */
		if (nm_ap_list_get_ap_by_essid (app_data->invalid_ap_list, ap_essid))
			continue;

		if ((tmp_ap = nm_ap_list_get_ap_by_essid (app_data->allowed_ap_list, ap_essid)))
		{
			const GTimeVal *curtime = nm_ap_get_timestamp (tmp_ap);

			/* Only connect to a blacklisted AP if the user has connected
			 * to this specific AP before.
			 */
			gboolean blacklisted = nm_ap_has_manufacturer_default_essid (scan_ap);
			if (blacklisted)
			{
				GSList *elt, *user_addrs;
				const struct ether_addr *ap_addr;
				char char_addr[20];

				ap_addr = nm_ap_get_address (scan_ap);
				user_addrs = nm_ap_get_user_addresses (tmp_ap);

				memset (&char_addr[0], 0, 20);
				iw_ether_ntop (ap_addr, &char_addr[0]);

				for (elt = user_addrs; elt; elt = g_slist_next (elt))
				{
					if (elt->data && !strcmp (elt->data, &char_addr[0]))
					{
						blacklisted = FALSE;
						break;
					}
				}

				g_slist_foreach (user_addrs, (GFunc)g_free, NULL);
				g_slist_free (user_addrs);
			}

			if (!blacklisted && nm_ap_get_trusted (tmp_ap) && (curtime->tv_sec > trusted_latest_timestamp.tv_sec))
			{
				trusted_latest_timestamp = *nm_ap_get_timestamp (tmp_ap);
				trusted_best_ap = scan_ap;
				nm_ap_set_security (trusted_best_ap, nm_ap_get_security (tmp_ap));
			}
			else if (!blacklisted && !nm_ap_get_trusted (tmp_ap) && (curtime->tv_sec > untrusted_latest_timestamp.tv_sec))
			{
				untrusted_latest_timestamp = *nm_ap_get_timestamp (tmp_ap);
				untrusted_best_ap = scan_ap;
				nm_ap_set_security (untrusted_best_ap, nm_ap_get_security (tmp_ap));
			}
		}
	}
	best_ap = trusted_best_ap ? trusted_best_ap : untrusted_best_ap;
	nm_ap_list_iter_free (iter);

	if (best_ap)
		nm_ap_ref (best_ap);

	return best_ap;
}


/*
 * nm_device_802_11_wireless_get_activation_ap
 *
 * Return an access point suitable for use in the device activation
 * request.
 *
 */
NMAccessPoint *
nm_device_802_11_wireless_get_activation_ap (NMDevice80211Wireless *self,
                                             const char *essid,
                                             NMAPSecurity *security)
{
	NMAccessPoint		*ap = NULL;
	NMData *			app_data;
	NMAccessPointList *	dev_ap_list;

	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (essid != NULL, NULL);

	app_data = nm_device_get_app_data (NM_DEVICE (self));
	g_assert (app_data);

	nm_debug ("Forcing AP '%s'", essid);

	/* Find the AP in our card's scan list first.
	 * If its not there, create an entirely new AP.
	 */
	dev_ap_list = nm_device_802_11_wireless_ap_list_get (self);
	if (!(ap = nm_ap_list_get_ap_by_essid (dev_ap_list, essid)))
	{
		/* We need security information from the user if the network they
		 * request isn't in our scan list.
		 */
		if (!security)
		{
			nm_warning ("%s: tried to manually connect to network '%s' without "
						"providing security information!", __func__, essid);
			return NULL;
		}

		/* User chose a network we haven't seen in a scan, so create a
		 * "fake" access point and add it to yhe scan list.
		 */
		ap = nm_ap_new ();
		nm_ap_set_essid (ap, essid);
		nm_ap_set_artificial (ap, TRUE);
		nm_ap_list_append_ap (dev_ap_list, ap);
		nm_ap_unref (ap);
	}
	else
	{
		/* If the AP is in the ignore list, we have to remove it since
		 * the User Knows What's Best.
		 */
		nm_ap_list_remove_ap_by_essid (app_data->invalid_ap_list, nm_ap_get_essid (ap));

		/* If we didn't get any security info, make some up. */
		if (!security)
			security = nm_ap_security_new_from_ap (ap);
	}
	g_assert (security);
	nm_ap_set_security (ap, security);

	return ap;
}


/*
 * nm_device_802_11_wireless_ap_list_clear
 *
 * Clears out the device's internal list of available access points.
 *
 */
static void
nm_device_802_11_wireless_ap_list_clear (NMDevice80211Wireless *self)
{
	g_return_if_fail (self != NULL);

	if (!self->priv->ap_list)
		return;

	nm_ap_list_unref (self->priv->ap_list);
	self->priv->ap_list = NULL;
}


/*
 * nm_device_ap_list_get_ap_by_essid
 *
 * Get the access point for a specific essid
 *
 */
NMAccessPoint *
nm_device_802_11_wireless_ap_list_get_ap_by_essid (NMDevice80211Wireless *self,
                                                   const char *essid)
{
	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (essid != NULL, NULL);

	if (!self->priv->ap_list)
		return NULL;

	return nm_ap_list_get_ap_by_essid (self->priv->ap_list, essid);
}


/*
 * nm_device_ap_list_get_ap_by_bssid
 *
 * Get the access point for a specific BSSID
 *
 */
NMAccessPoint *
nm_device_802_11_wireless_ap_list_get_ap_by_bssid (NMDevice80211Wireless *self,
                                                   const struct ether_addr *bssid)
{
	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (bssid != NULL, NULL);

	if (!self->priv->ap_list)
		return NULL;

	return nm_ap_list_get_ap_by_address (self->priv->ap_list, bssid);
}


/*
 * nm_device_ap_list_get_ap_by_obj_path
 *
 * Get the access point for a dbus object path.  Requires an _unescaped_
 * object path.
 *
 */
NMAccessPoint *
nm_device_802_11_wireless_ap_list_get_ap_by_obj_path (NMDevice80211Wireless *self,
                                                      const char *obj_path)
{
	NMAccessPoint *	ret_ap = NULL;
	char *			built_path;
	char *			dev_path;

	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (obj_path != NULL, NULL);

	if (!self->priv->ap_list)
		return NULL;

	dev_path = nm_dbus_get_object_path_for_device (NM_DEVICE (self));
	dev_path = nm_dbus_unescape_object_path (dev_path);
	built_path = g_strdup_printf ("%s/Networks/", dev_path);
	g_free (dev_path);

	if (strncmp (built_path, obj_path, strlen (built_path)) == 0)
	{
		char *essid = g_strdup (obj_path + strlen (built_path));

		ret_ap = nm_ap_list_get_ap_by_essid (self->priv->ap_list, essid);
		g_free (essid);
	}
	g_free (built_path);

	return ret_ap;
}


/*
 * nm_device_ap_list_get
 *
 * Return a pointer to the AP list
 *
 */
NMAccessPointList *
nm_device_802_11_wireless_ap_list_get (NMDevice80211Wireless *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return self->priv->ap_list;
}


static gboolean
set_scan_interval_cb (gpointer user_data)
{
	NMData *data = (NMData*) user_data;

	nm_device_802_11_wireless_set_scan_interval (data, NULL, NM_WIRELESS_SCAN_INTERVAL_INACTIVE);

	return FALSE;
}

void
nm_device_802_11_wireless_set_scan_interval (NMData *data,
                                             NMDevice80211Wireless *self,
                                             NMWirelessScanInterval interval)
{
	static guint	source_id = 0;
	GSource *		source = NULL;
	GSList *		elt;

	g_return_if_fail (data != NULL);

	if (source_id != 0)
		g_source_remove (source_id);

	for (elt = data->dev_list; elt; elt = g_slist_next (elt))
	{
		NMDevice *d = (NMDevice *)(elt->data);
		if (self && (NM_DEVICE (self) != d))
			continue;

		if (d && nm_device_is_802_11_wireless (d))
		{
			guint seconds;

			switch (interval)
			{
				case NM_WIRELESS_SCAN_INTERVAL_INIT:
					seconds = 15;
					break;

				case NM_WIRELESS_SCAN_INTERVAL_INACTIVE:
					seconds = 120;
					break;

				case NM_WIRELESS_SCAN_INTERVAL_ACTIVE:
				default:
					seconds = 20;
					break;
			}

			NM_DEVICE_802_11_WIRELESS (d)->priv->scan_interval = seconds;
		}
	}

	if (interval != NM_WIRELESS_SCAN_INTERVAL_INACTIVE)
	{
		source = g_timeout_source_new (120000);
		g_source_set_callback (source, set_scan_interval_cb, (gpointer) data, NULL);
		source_id = g_source_attach (source, data->main_context);
		g_source_unref (source);
	}
}


/*
 * nm_device_get_mode
 *
 * Get managed/infrastructure/adhoc mode on a device
 *
 */
int
nm_device_802_11_wireless_get_mode (NMDevice80211Wireless *self)
{
	NMSock *	sk;
	int		mode = IW_MODE_AUTO;

	g_return_val_if_fail (self != NULL, -1);

	/* Force the card into Managed/Infrastructure mode */
	if ((sk = nm_dev_sock_open (NM_DEVICE (self), DEV_WIRELESS, __FUNCTION__, NULL)))
	{
		struct iwreq	wrq;

		memset (&wrq, 0, sizeof (struct iwreq));
#ifdef IOCTL_DEBUG
	nm_info ("%s: About to GET IWMODE.", nm_device_get_iface (NM_DEVICE (self)));
#endif
		if (iw_get_ext (nm_dev_sock_get_fd (sk), nm_device_get_iface (NM_DEVICE (self)), SIOCGIWMODE, &wrq) == 0)
		{
			if ((mode == IW_MODE_ADHOC) || (mode == IW_MODE_INFRA))
				mode = wrq.u.mode;
		}
		else
		{
			nm_warning ("nm_device_get_mode (%s): error getting card mode.  errno = %d",
					nm_device_get_iface (NM_DEVICE (self)), errno);
		}
		nm_dev_sock_close (sk);
	}

	return mode;
}


/*
 * nm_device_set_mode
 *
 * Set managed/infrastructure/adhoc mode on a device
 *
 */
gboolean
nm_device_802_11_wireless_set_mode (NMDevice80211Wireless *self,
                                    const int mode)
{
	NMSock *	sk;
	gboolean	success = FALSE;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail ((mode == IW_MODE_INFRA) || (mode == IW_MODE_ADHOC) || (mode == IW_MODE_AUTO), FALSE);

	if (nm_device_802_11_wireless_get_mode (self) == mode)
		return TRUE;

	/* Force the card into Managed/Infrastructure mode */
	if ((sk = nm_dev_sock_open (NM_DEVICE (self), DEV_WIRELESS, __FUNCTION__, NULL)))
	{
		const char *	iface = nm_device_get_iface (NM_DEVICE (self));
		struct iwreq	wreq;

#ifdef IOCTL_DEBUG
	nm_info ("%s: About to SET IWMODE.", iface);
#endif
		wreq.u.mode = mode;
		if (iw_set_ext (nm_dev_sock_get_fd (sk), iface, SIOCSIWMODE, &wreq) == 0)
			success = TRUE;
		else
		{
			if (errno != ENODEV)
			{
				nm_warning ("nm_device_set_mode (%s): error setting card to %s mode: %s",
					iface,
					mode == IW_MODE_INFRA ? "Infrastructure" : \
						(mode == IW_MODE_ADHOC ? "Ad-Hoc" : \
							(mode == IW_MODE_AUTO ? "Auto" : "unknown")),
					strerror (errno));
			}
		}
		nm_dev_sock_close (sk);
	}

	return success;
}


/*
 * nm_device_802_11_wireless_get_signal_strength
 *
 * Get the current signal strength of a wireless device.  This only works when
 * the card is associated with an access point, so will only work for the
 * active device.
 *
 * Returns:	-1 on error
 *			0 - 100  strength percentage of the connection to the current access point
 *
 */
gint8
nm_device_802_11_wireless_get_signal_strength (NMDevice80211Wireless *self)
{
	g_return_val_if_fail (self != NULL, -1);

	return (self->priv->strength);
}


/*
 * wireless_stats_to_percent
 *
 * Convert an iw_stats structure from a scan or the card into
 * a magical signal strength percentage.
 *
 */
static int
wireless_qual_to_percent (const struct iw_quality *qual,
                          const struct iw_quality *max_qual,
                          const struct iw_quality *avg_qual)
{
	int	percent = -1;
	int	level_percent = -1;

	g_return_val_if_fail (qual != NULL, -1);
	g_return_val_if_fail (max_qual != NULL, -1);
	g_return_val_if_fail (avg_qual != NULL, -1);

#ifdef IW_QUAL_DEBUG
nm_debug ("QL: qual %d/%u/0x%X, level %d/%u/0x%X, noise %d/%u/0x%X, updated: 0x%X  ** MAX: qual %d/%u/0x%X, level %d/%u/0x%X, noise %d/%u/0x%X, updated: 0x%X",
(__s8)qual->qual, qual->qual, qual->qual,
(__s8)qual->level, qual->level, qual->level,
(__s8)qual->noise, qual->noise, qual->noise,
qual->updated,
(__s8)max_qual->qual, max_qual->qual, max_qual->qual,
(__s8)max_qual->level, max_qual->level, max_qual->level,
(__s8)max_qual->noise, max_qual->noise, max_qual->noise,
max_qual->updated);
#endif

	/* Try using the card's idea of the signal quality first as long as it tells us what the max quality is.
	 * Drivers that fill in quality values MUST treat them as percentages, ie the "Link Quality" MUST be 
	 * bounded by 0 and max_qual->qual, and MUST change in a linear fashion.  Within those bounds, drivers
	 * are free to use whatever they want to calculate "Link Quality".
	 */
	if ((max_qual->qual != 0) && !(max_qual->updated & IW_QUAL_QUAL_INVALID) && !(qual->updated & IW_QUAL_QUAL_INVALID))
		percent = (int)(100 * ((double)qual->qual / (double)max_qual->qual));

	/* If the driver doesn't specify a complete and valid quality, we have two options:
	 *
	 * 1) dBm: driver must specify max_qual->level = 0, and have valid values for
	 *        qual->level and (qual->noise OR max_qual->noise)
	 * 2) raw RSSI: driver must specify max_qual->level > 0, and have valid values for
	 *        qual->level and max_qual->level
	 *
	 * This is the WEXT spec.  If this interpretation is wrong, I'll fix it.  Otherwise,
	 * If drivers don't conform to it, they are wrong and need to be fixed.
	 */

	if (    (max_qual->level == 0) && !(max_qual->updated & IW_QUAL_LEVEL_INVALID)		/* Valid max_qual->level == 0 */
		&& !(qual->updated & IW_QUAL_LEVEL_INVALID)								/* Must have valid qual->level */
		&& (    ((max_qual->noise > 0) && !(max_qual->updated & IW_QUAL_NOISE_INVALID))	/* Must have valid max_qual->noise */
			|| ((qual->noise > 0) && !(qual->updated & IW_QUAL_NOISE_INVALID)))		/*    OR valid qual->noise */
	   )
	{
		/* Absolute power values (dBm) */

		/* Reasonable fallbacks for dumb drivers that don't specify either level. */
		#define FALLBACK_NOISE_FLOOR_DBM	-90
		#define FALLBACK_SIGNAL_MAX_DBM	-20
		int	max_level = FALLBACK_SIGNAL_MAX_DBM;
		int	noise = FALLBACK_NOISE_FLOOR_DBM;
		int	level = qual->level - 0x100;

		level = CLAMP (level, FALLBACK_NOISE_FLOOR_DBM, FALLBACK_SIGNAL_MAX_DBM);

		if ((qual->noise > 0) && (!qual->updated & IW_QUAL_NOISE_INVALID))
			noise = qual->noise - 0x100;
		else if ((max_qual->noise > 0) && !(max_qual->updated & IW_QUAL_NOISE_INVALID))
			noise = max_qual->noise - 0x100;
		noise = CLAMP (noise, FALLBACK_NOISE_FLOOR_DBM, FALLBACK_SIGNAL_MAX_DBM);

		/* A sort of signal-to-noise ratio calculation */
		level_percent = (int)(100 - 70 *(
						((double)max_level - (double)level) /
						((double)max_level - (double)noise)));
#ifdef IW_QUAL_DEBUG
		nm_debug ("QL1: level_percent is %d.  max_level %d, level %d, noise_floor %d.", level_percent, max_level, level, noise);
#endif
	}
	else if ((max_qual->level != 0) && !(max_qual->updated & IW_QUAL_LEVEL_INVALID)	/* Valid max_qual->level as upper bound */
			&& !(qual->updated & IW_QUAL_LEVEL_INVALID))
	{
		/* Relative power values (RSSI) */

		int	level = qual->level;

		/* Signal level is relavtive (0 -> max_qual->level) */
		level = CLAMP (level, 0, max_qual->level);
		level_percent = (int)(100 * ((double)level / (double)max_qual->level));
#ifdef IW_QUAL_DEBUG
		nm_debug ("QL2: level_percent is %d.  max_level %d, level %d.", level_percent, max_qual->level, level);
#endif
	}
	else if (percent == -1)
	{
#ifdef IW_QUAL_DEBUG
		nm_debug ("QL: Could not get quality %% value from driver.  Driver is probably buggy.");
#endif
	}

	/* If the quality percent was 0 or doesn't exist, then try to use signal levels instead */
	if ((percent < 1) && (level_percent >= 0))
		percent = level_percent;

#ifdef IW_QUAL_DEBUG
	nm_debug ("QL: Final quality percent is %d (%d).", percent, CLAMP (percent, 0, 100));
#endif
	return (CLAMP (percent, 0, 100));
}


/*
 * nm_device_802_11_wireless_update_signal_strength
 *
 * Update the device's idea of the strength of its connection to the
 * current access point.
 *
 */
void
nm_device_802_11_wireless_update_signal_strength (NMDevice80211Wireless *self)
{
	NMData *		app_data;
	gboolean		has_range = FALSE;
	NMSock *		sk;
	iwrange		range;
	iwstats		stats;
	int			percent = -1;

	g_return_if_fail (self != NULL);

	app_data = nm_device_get_app_data (NM_DEVICE (self));
	g_assert (app_data);

	/* Grab the scan lock since our strength is meaningless during a scan. */
	if (!nm_try_acquire_mutex (self->priv->scan_mutex, __FUNCTION__))
		return;

	/* If we aren't the active device, we don't really have a signal strength
	 * that would mean anything.
	 */
	if (!nm_device_get_act_request (NM_DEVICE (self)))
	{
		self->priv->strength = -1;
		goto out;
	}

	if ((sk = nm_dev_sock_open (NM_DEVICE (self), DEV_WIRELESS, __FUNCTION__, NULL)))
	{
		const char *iface = nm_device_get_iface (NM_DEVICE (self));

		memset (&range, 0, sizeof (iwrange));
		memset (&stats, 0, sizeof (iwstats));
#ifdef IOCTL_DEBUG
	nm_info ("%s: About to GET 'iwrange'.", iface);
#endif
		has_range = (iw_get_range_info (nm_dev_sock_get_fd (sk), iface, &range) >= 0);
#ifdef IOCTL_DEBUG
	nm_info ("%s: About to GET 'iwstats'.", iface);
#endif
		if (iw_get_stats (nm_dev_sock_get_fd (sk), iface, &stats, &range, has_range) == 0)
		{
			percent = wireless_qual_to_percent (&stats.qual, (const iwqual *)(&self->priv->max_qual),
					(const iwqual *)(&self->priv->avg_qual));
		}
		nm_dev_sock_close (sk);
	}

	/* Try to smooth out the strength.  Atmel cards, for example, will give no strength
	 * one second and normal strength the next.
	 */
	if ((percent == -1) && (++self->priv->invalid_strength_counter <= 3))
		percent = self->priv->strength;
	else
		self->priv->invalid_strength_counter = 0;

	if (percent != self->priv->strength)
		nm_dbus_signal_device_strength_change (app_data->dbus_connection, self, percent);

	self->priv->strength = percent;

out:
	nm_unlock_mutex (self->priv->scan_mutex, __func__);
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
char *
nm_device_802_11_wireless_get_essid (NMDevice80211Wireless *self)
{
	NMSock *		sk;
	int			err;
	const char *	iface;

	g_return_val_if_fail (self != NULL, NULL);	

	iface = nm_device_get_iface (NM_DEVICE (self));
	if ((sk = nm_dev_sock_open (NM_DEVICE (self), DEV_WIRELESS, __FUNCTION__, NULL)))
	{
		wireless_config	info;

#ifdef IOCTL_DEBUG
		nm_info ("%s: About to GET 'basic config' for ESSID.", iface);
#endif
		err = iw_get_basic_config (nm_dev_sock_get_fd (sk), iface, &info);
		if (err >= 0)
		{
			if (self->priv->cur_essid)
				g_free (self->priv->cur_essid);
			self->priv->cur_essid = g_strdup (info.essid);
		}
		else
		{
			nm_warning ("nm_device_get_essid(): error getting ESSID for device %s.  errno = %d",
					iface, errno);
		}

		nm_dev_sock_close (sk);
	}

	return self->priv->cur_essid;
}


/*
 * nm_device_802_11_wireless_set_essid
 *
 * If a device is wireless, set the essid that it should use.
 */
void
nm_device_802_11_wireless_set_essid (NMDevice80211Wireless *self,
                                     const char *essid)
{
	NMSock*		sk;
	int			err;
	struct iwreq	wreq;
	unsigned char	safe_essid[IW_ESSID_MAX_SIZE + 1] = "\0";
	const char *	iface;

	g_return_if_fail (self != NULL);

	/* Make sure the essid we get passed is a valid size */
	if (!essid)
		safe_essid[0] = '\0';
	else
	{
		strncpy ((char *) safe_essid, essid, IW_ESSID_MAX_SIZE);
		safe_essid[IW_ESSID_MAX_SIZE] = '\0';
	}

	iface = nm_device_get_iface (NM_DEVICE (self));
	if ((sk = nm_dev_sock_open (NM_DEVICE (self), DEV_WIRELESS, __FUNCTION__, NULL)))
	{
		wreq.u.essid.pointer = (caddr_t) safe_essid;
		wreq.u.essid.length	 = strlen ((char *) safe_essid) + 1;
		wreq.u.essid.flags	 = 1;	/* Enable essid on card */
	
#ifdef IOCTL_DEBUG
	nm_info ("%s: About to SET IWESSID.", iface);
#endif
		if ((err = iw_set_ext (nm_dev_sock_get_fd (sk), iface, SIOCSIWESSID, &wreq)) == -1)
		{
			if (errno != ENODEV)
			{
				nm_warning ("nm_device_set_essid(): error setting ESSID '%s' for device %s.  errno = %d",
						safe_essid, iface, errno);
			}
		}

		nm_dev_sock_close (sk);

		/* Orinoco cards seem to need extra time here to not screw
		 * up the firmware, which reboots when you set the ESSID.
		 * Unfortunately, there's no way to know when the card is back up
		 * again.  Sigh...
		 */
		sleep (2);
	}
}


/*
 * nm_device_get_frequency
 *
 * For wireless devices, get the frequency we broadcast/receive on.
 *
 */
static double
nm_device_802_11_wireless_get_frequency (NMDevice80211Wireless *self)
{
	NMSock *		sk;
	int			err;
	double		freq = 0;
	const char *	iface;

	g_return_val_if_fail (self != NULL, 0);

	iface = nm_device_get_iface (NM_DEVICE (self));
	if ((sk = nm_dev_sock_open (NM_DEVICE (self), DEV_WIRELESS, __FUNCTION__, NULL)))
	{
		struct iwreq		wrq;

#ifdef IOCTL_DEBUG
		nm_info ("%s: About to GET IWFREQ.", iface);
#endif
		err = iw_get_ext (nm_dev_sock_get_fd (sk), iface, SIOCGIWFREQ, &wrq);
		if (err >= 0)
			freq = iw_freq2float (&wrq.u.freq);
		if (err == -1)
		{
			nm_warning ("nm_device_get_frequency(): error getting frequency for device %s.  errno = %d",
					iface, errno);
		}

		nm_dev_sock_close (sk);
	}

	return freq;
}


/*
 * nm_device_set_frequency
 *
 * For wireless devices, set the frequency to broadcast/receive on.
 * A frequency <= 0 means "auto".
 *
 */
static void
nm_device_802_11_wireless_set_frequency (NMDevice80211Wireless *self,
                                         const double freq)
{
	NMSock *		sk;
	int			err;
	const char *	iface;

	/* HACK FOR NOW */
	if (freq <= 0)
		return;

	g_return_if_fail (self != NULL);

	if (fabs (nm_device_802_11_wireless_get_frequency (self) - freq) <= DBL_EPSILON)
		return;

	iface = nm_device_get_iface (NM_DEVICE (self));
	if ((sk = nm_dev_sock_open (NM_DEVICE (self), DEV_WIRELESS, __FUNCTION__, NULL)))
	{
		struct iwreq wrq;

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
#ifdef IOCTL_DEBUG
		nm_info ("%s: About to SET IWFREQ.", iface);
#endif
		if ((err = iw_set_ext (nm_dev_sock_get_fd (sk), iface, SIOCSIWFREQ, &wrq)) == -1)
		{
			gboolean	success = FALSE;
			if ((freq <= 0) && ((errno == EINVAL) || (errno == EOPNOTSUPP)))
			{
				/* Ok, try "auto" the iwconfig way if the Atheros way didn't work */
				wrq.u.freq.m = -1;
				wrq.u.freq.e = 0;
				wrq.u.freq.flags = 0;
				if (iw_set_ext (nm_dev_sock_get_fd (sk), iface, SIOCSIWFREQ, &wrq) != -1)
					success = TRUE;
			}
		}

		nm_dev_sock_close (sk);
	}
}


/*
 * nm_device_get_bitrate
 *
 * For wireless devices, get the bitrate to broadcast/receive at.
 * Returned value is rate in KHz.
 *
 */
static int
nm_device_802_11_wireless_get_bitrate (NMDevice80211Wireless *self)
{
	NMSock *		sk;
	int			err = -1;
	struct iwreq	wrq;
	const char *	iface;

	g_return_val_if_fail (self != NULL, 0);

	iface = nm_device_get_iface (NM_DEVICE (self));
	if ((sk = nm_dev_sock_open (NM_DEVICE (self), DEV_WIRELESS, __FUNCTION__, NULL)))
	{
#ifdef IOCTL_DEBUG
		nm_info ("%s: About to GET IWRATE.", iface);
#endif
		err = iw_get_ext (nm_dev_sock_get_fd (sk), iface, SIOCGIWRATE, &wrq);
		nm_dev_sock_close (sk);
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
static void
nm_device_802_11_wireless_set_bitrate (NMDevice80211Wireless *self,
                                       const int Mbps)
{
	NMSock *		sk;
	const char *	iface;

	g_return_if_fail (self != NULL);

	if (nm_device_802_11_wireless_get_bitrate (self) == Mbps)
		return;

	iface = nm_device_get_iface (NM_DEVICE (self));
	if ((sk = nm_dev_sock_open (NM_DEVICE (self), DEV_WIRELESS, __FUNCTION__, NULL)))
	{
		struct iwreq wrq;

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
#ifdef IOCTL_DEBUG
		nm_info ("%s: About to SET IWRATE.", iface);
#endif
		iw_set_ext (nm_dev_sock_get_fd (sk), iface, SIOCSIWRATE, &wrq);

		nm_dev_sock_close (sk);
	}
}


/*
 * nm_device_get_bssid
 *
 * If a device is wireless, get the access point's ethernet address
 * that the card is associated with.
 */
void
nm_device_802_11_wireless_get_bssid (NMDevice80211Wireless *self,
                                     struct ether_addr *bssid)
{
	NMSock *		sk;
	struct iwreq	wrq;
	const char *	iface;

	g_return_if_fail (self != NULL);
	g_return_if_fail (bssid != NULL);

	memset (bssid, 0, sizeof (struct ether_addr));

	iface = nm_device_get_iface (NM_DEVICE (self));
	if ((sk = nm_dev_sock_open (NM_DEVICE (self), DEV_WIRELESS, __FUNCTION__, NULL)))
	{
#ifdef IOCTL_DEBUG
	nm_info ("%s: About to GET IWAP.", iface);
#endif
		if (iw_get_ext (nm_dev_sock_get_fd (sk), iface, SIOCGIWAP, &wrq) >= 0)
			memcpy (bssid, &(wrq.u.ap_addr.sa_data), sizeof (struct ether_addr));
		nm_dev_sock_close (sk);
	}
}


/*
 * nm_device_set_wep_enc_key
 *
 * If a device is wireless, set the encryption key that it should use.
 *
 * key:	encryption key to use, or NULL or "" to disable encryption.
 */
void
nm_device_802_11_wireless_set_wep_enc_key (NMDevice80211Wireless *self,
                                           const char *key,
                                           int auth_method)
{
	NMSock *		sk;
	struct iwreq	wreq;
	int			keylen;
	unsigned char	safe_key[IW_ENCODING_TOKEN_MAX + 1];
	gboolean		set_key = FALSE;
	const char *	iface;

	g_return_if_fail (self != NULL);

	/* Make sure the essid we get passed is a valid size */
	if (!key)
		safe_key[0] = '\0';
	else
	{
		strncpy ((char *) safe_key, key, IW_ENCODING_TOKEN_MAX);
		safe_key[IW_ENCODING_TOKEN_MAX] = '\0';
	}

	iface = nm_device_get_iface (NM_DEVICE (self));
	if ((sk = nm_dev_sock_open (NM_DEVICE (self), DEV_WIRELESS, __FUNCTION__, NULL)))
	{
		wreq.u.data.pointer = (caddr_t) NULL;
		wreq.u.data.length = 0;
		wreq.u.data.flags = IW_ENCODE_ENABLED;

		/* Unfortunately, some drivers (Cisco) don't make a distinction between
		 * Open System authentication mode and whether or not to use WEP.  You
		 * DON'T have to use WEP when using Open System, but these cards force
		 * it.  Therefore, we have to set Open System mode when using WEP.
		 */

		if (strlen ((char *) safe_key) == 0)
		{
			wreq.u.data.flags |= IW_ENCODE_DISABLED | IW_ENCODE_NOKEY;
			set_key = TRUE;
		}
		else
		{
			unsigned char		parsed_key[IW_ENCODING_TOKEN_MAX + 1];

			keylen = iw_in_key_full (nm_dev_sock_get_fd (sk), iface,
						(char *) safe_key, &parsed_key[0], &wreq.u.data.flags);
			if (keylen > 0)
			{
				switch (auth_method)
				{
					case IW_AUTH_ALG_OPEN_SYSTEM:
						wreq.u.data.flags |= IW_ENCODE_OPEN;
						break;
					case IW_AUTH_ALG_SHARED_KEY:
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
#ifdef IOCTL_DEBUG
			nm_info ("%s: About to SET IWENCODE.", iface);
#endif
			if (iw_set_ext (nm_dev_sock_get_fd (sk), iface, SIOCSIWENCODE, &wreq) == -1)
			{
				if (errno != ENODEV)
				{
					nm_warning ("nm_device_set_wep_enc_key(): error setting key for device %s.  errno = %d",
							iface, errno);
				}
			}
		}

		nm_dev_sock_close (sk);
	} else nm_warning ("nm_device_set_wep_enc_key(): could not get wireless control socket.");
}

/*
 * nm_device_wireless_schedule_scan
 *
 * Schedule a wireless scan in the /device's/ thread.
 *
 */
static void
schedule_scan (NMDevice80211Wireless *self)
{
	GSource *			wscan_source;
	guint			wscan_source_id;
	NMWirelessScanCB *	scan_cb;
	GMainContext *		context;

	g_return_if_fail (self != NULL);

	scan_cb = g_malloc0 (sizeof (NMWirelessScanCB));
	scan_cb->dev = self;
	scan_cb->force = FALSE;

	wscan_source = g_timeout_source_new (self->priv->scan_interval * 1000);
	g_source_set_callback (wscan_source, nm_device_802_11_wireless_scan, scan_cb, NULL);
	context = nm_device_get_main_context (NM_DEVICE (self));
	wscan_source_id = g_source_attach (wscan_source, context);
	g_source_unref (wscan_source);
}


static void
free_process_scan_cb_data (NMWirelessScanResults *cb_data)
{
	if (!cb_data)
		return;

	if (cb_data->results)
		g_free (cb_data->results);
	g_object_unref (G_OBJECT (cb_data->dev));
	memset (cb_data, 0, sizeof (NMWirelessScanResults));
	g_free (cb_data);	
}

/*
 * nm_device_wireless_process_scan_results
 *
 * Process results of an iwscan() into our own AP lists.  We're an idle function,
 * but we never reschedule ourselves.
 *
 */
static gboolean
handle_scan_results (gpointer user_data)
{
	NMWirelessScanResults *	cb_data = (NMWirelessScanResults *) user_data;
	NMDevice80211Wireless *	self;
	GTimeVal				cur_time;
	NMAPListIter *			iter = NULL;
	const char *			iface;
	NMData *				app_data;
	NMAccessPointList *		ap_list;

	g_return_val_if_fail (cb_data != NULL, FALSE);	

	self = NM_DEVICE_802_11_WIRELESS (cb_data->dev);
	if (!self || !cb_data->results)
	{
		free_process_scan_cb_data (cb_data);
		return FALSE;
	}

	iface = nm_device_get_iface (NM_DEVICE (self));
	app_data = nm_device_get_app_data (NM_DEVICE (self));
	if (cb_data->results_len > 0)
	{
		if (!process_scan_results (self, cb_data->results, cb_data->results_len))
			nm_warning ("nm_device_wireless_process_scan_results(%s): process_scan_results() returned an error.", iface);

		/* Once we have the list, copy in any relevant information from our Allowed list. */
		nm_ap_list_copy_properties (nm_device_802_11_wireless_ap_list_get (self), app_data->allowed_ap_list);
	}

	/* Walk the access point list and remove any access points older than 180s */
	g_get_current_time (&cur_time);
	ap_list = nm_device_802_11_wireless_ap_list_get (self);
	if (ap_list && (iter = nm_ap_list_iter_new (ap_list)))
	{
		NMAccessPoint *outdated_ap;
		GSList *		outdated_list = NULL;
		GSList *		elt;
		NMActRequest *	req = nm_device_get_act_request (NM_DEVICE (self));
		NMAccessPoint *cur_ap = NULL;

		if (req)
		{
			cur_ap = nm_act_request_get_ap (req);
			g_assert (cur_ap);
		}

		while ((outdated_ap = nm_ap_list_iter_next (iter)))
		{
			const GTimeVal	*ap_time = nm_ap_get_last_seen (outdated_ap);
			gboolean		 keep_around = FALSE;

			/* Don't ever prune the AP we're currently associated with */
			if (	    nm_ap_get_essid (outdated_ap)
				&&  (cur_ap && (nm_null_safe_strcmp (nm_ap_get_essid (cur_ap), nm_ap_get_essid (outdated_ap))) == 0))
				keep_around = TRUE;

			if (!keep_around && (ap_time->tv_sec + 180 < cur_time.tv_sec))
				outdated_list = g_slist_append (outdated_list, outdated_ap);
		}
		nm_ap_list_iter_free (iter);

		/* Ok, now remove outdated ones.  We have to do it after the lock
		 * because nm_ap_list_remove_ap() locks the list too.
		 */
		for (elt = outdated_list; elt; elt = g_slist_next (elt))
		{
			if ((outdated_ap = (NMAccessPoint *)(elt->data)))
			{
				nm_dbus_signal_wireless_network_change	(app_data->dbus_connection, self, outdated_ap, NETWORK_STATUS_DISAPPEARED, -1);
				nm_ap_list_remove_ap (nm_device_802_11_wireless_ap_list_get (self), outdated_ap);
			}
		}
		g_slist_free (outdated_list);
	}

	nm_policy_schedule_device_change_check (app_data);

	free_process_scan_cb_data (cb_data);

	return FALSE;
}


/*
 * nm_device_wireless_scan
 *
 * Get a list of access points this device can see.
 *
 */
static gboolean
nm_device_802_11_wireless_scan (gpointer user_data)
{
	NMWirelessScanCB *		scan_cb = (NMWirelessScanCB *)(user_data);
	NMDevice80211Wireless *	self = NULL;
	NMWirelessScanResults *	scan_results = NULL;
	guint32				caps;
	NMData *				app_data;

	g_return_val_if_fail (scan_cb != NULL, FALSE);

	self = scan_cb->dev;
	if (!self || !nm_device_get_app_data (NM_DEVICE (self)))
	{
		g_free (scan_cb);
		return FALSE;
	}
	app_data = nm_device_get_app_data (NM_DEVICE (self));

	caps = nm_device_get_capabilities (NM_DEVICE (self));
	if (!(caps & NM_DEVICE_CAP_NM_SUPPORTED) || !(caps & NM_DEVICE_CAP_WIRELESS_SCAN))
	{
		g_free (scan_cb);
		return FALSE;
	}

	/* Reschedule ourselves if all wireless is disabled, we're asleep,
	 * or we are currently activating.
	 */
	if (    (app_data->wireless_enabled == FALSE)
		|| (app_data->asleep == TRUE)
		|| (nm_device_is_activating (NM_DEVICE (self)) == TRUE))
	{
		nm_device_802_11_wireless_set_scan_interval (app_data, self, NM_WIRELESS_SCAN_INTERVAL_INIT);
		goto reschedule;
	}

	/*
	 * A/B/G cards should only scan if they are disconnected.  Set the timeout to active
	 * for the case we lose this connection shortly, it will reach this point and then
	 * nm_device_is_activated will return FALSE, letting the scan proceed.
	 */
	if ((self->priv->num_freqs > 14) && nm_device_is_activated (NM_DEVICE (self)) == TRUE)
	{
		nm_device_802_11_wireless_set_scan_interval (app_data, self, NM_WIRELESS_SCAN_INTERVAL_ACTIVE);
		goto reschedule;
	}

	/* Grab the scan mutex */
	if (nm_try_acquire_mutex (self->priv->scan_mutex, __func__))
	{
		NMSock *	sk;
		gboolean	devup_err;
		const char *	iface;

		/* Device must be up before we can scan */
		devup_err = nm_device_bring_up_wait (NM_DEVICE (self), 1);
		if (devup_err)
		{
			nm_unlock_mutex (self->priv->scan_mutex, __func__);
			goto reschedule;
		}

		iface = nm_device_get_iface (NM_DEVICE (self));
		if ((sk = nm_dev_sock_open (NM_DEVICE (self), DEV_WIRELESS, __FUNCTION__, NULL)))
		{
			int			orig_mode = IW_MODE_INFRA;
			double		orig_freq = 0;
			int			orig_rate = 0;
			struct iwreq	wrq;

			orig_mode = nm_device_802_11_wireless_get_mode (self);
			if (orig_mode == IW_MODE_ADHOC)
			{
				orig_freq = nm_device_802_11_wireless_get_frequency (self);
				orig_rate = nm_device_802_11_wireless_get_bitrate (self);
			}

			/* Must be in infrastructure mode during scan, otherwise we don't get a full
			 * list of scan results.  Scanning doesn't work well in Ad-Hoc mode :( 
			 */
			nm_device_802_11_wireless_set_mode (self, IW_MODE_INFRA);
			nm_device_802_11_wireless_set_frequency (self, 0);

			wrq.u.data.pointer = NULL;
			wrq.u.data.flags = 0;
			wrq.u.data.length = 0;
			if (iw_set_ext (nm_dev_sock_get_fd (sk), iface, SIOCSIWSCAN, &wrq) < 0)
			{
				nm_warning ("nm_device_wireless_scan(%s): couldn't trigger wireless scan.  errno = %d",
						iface, errno);
			}
			else
			{
				guint8 * 	results = NULL;
				guint32	results_len = 0;

				/* Initial pause for card to return data */
				g_usleep (G_USEC_PER_SEC / 4);

				if (get_scan_results (self, sk, &results, &results_len))
				{
					scan_results = g_malloc0 (sizeof (NMWirelessScanResults));
					g_object_ref (G_OBJECT (self));
					scan_results->dev = self;
					scan_results->results = results;
					scan_results->results_len = results_len;
				}
				else
					nm_warning ("nm_device_wireless_scan(%s): get_scan_results() returned an error.", iface);
			}

			nm_device_802_11_wireless_set_mode (self, orig_mode);
			/* Only set frequency if ad-hoc mode */
			if (orig_mode == IW_MODE_ADHOC)
			{
				nm_device_802_11_wireless_set_frequency (self, orig_freq);
				nm_device_802_11_wireless_set_bitrate (self, orig_rate);
			}

			nm_dev_sock_close (sk);
		}
		nm_unlock_mutex (self->priv->scan_mutex, __func__);
	}

	/* We run the scan processing function from the main thread, since it must deliver
	 * messages over DBUS.  Plus, that way the main thread is the only thread that has
	 * to modify the device's access point list.
	 */
	if (scan_results != NULL)
	{
		guint	scan_process_source_id = 0;
		GSource *	scan_process_source = g_idle_source_new ();
		GTimeVal	cur_time;

		g_source_set_callback (scan_process_source, handle_scan_results, scan_results, NULL);
		scan_process_source_id = g_source_attach (scan_process_source, app_data->main_context);
		g_source_unref (scan_process_source);

		g_get_current_time (&cur_time);
		self->priv->last_scan = cur_time.tv_sec;
	}

reschedule:
	/* Make sure we reschedule ourselves so we keep scanning */
	schedule_scan (self);

	g_free (scan_cb);
	return FALSE;
}


#ifdef UNUSED
/*
 * nm_device_set_wireless_config
 *
 * Bring up a wireless card with the essid and wep key of its "best" ap
 *
 * Returns:	TRUE on successful activation
 *			FALSE on unsuccessful activation (ie no best AP)
 *
 */
static gboolean
set_wireless_config (NMDevice80211Wireless *self,
                     NMAccessPoint *ap)
{
	const char *	essid = NULL;
	NMAPSecurity *	security;
	int			we_cipher;

	g_return_val_if_fail (ap != NULL, FALSE);
	g_return_val_if_fail (nm_ap_get_essid (ap) != NULL, FALSE);

	security = nm_ap_get_security (ap);
	g_return_val_if_fail (security != NULL, FALSE);

	self->priv->failed_link_count = 0;

	/* Force the card into Managed/Infrastructure mode */
	nm_device_bring_down_wait (NM_DEVICE (self), 0);
	nm_device_bring_up_wait (NM_DEVICE (self), 0);

	nm_device_802_11_wireless_set_mode (self, IW_MODE_INFRA);

	essid = nm_ap_get_essid (ap);

	nm_device_802_11_wireless_set_mode (self, nm_ap_get_mode (ap));
	nm_device_802_11_wireless_set_bitrate (self, 0);

	if (nm_ap_get_user_created (ap) || (nm_ap_get_freq (ap) && (nm_ap_get_mode (ap) == IW_MODE_ADHOC)))
		nm_device_802_11_wireless_set_frequency (self, nm_ap_get_freq (ap));
	else
		nm_device_802_11_wireless_set_frequency (self, 0);	/* auto */

	/* FIXME: set card's config using wpa_supplicant, not ourselves */
	nm_ap_security_device_setup (security, self);

	nm_device_802_11_wireless_set_essid (self, essid);

	nm_info ("Activation (%s/wireless): using essid '%s', with '%s' security.",
			nm_device_get_iface (NM_DEVICE (self)), essid, nm_ap_security_get_description (security));

	/* Bring the device up and pause to allow card to associate.  After we set the ESSID
	 * on the card, the card has to scan all channels to find our requested AP (which can
	 * take a long time if it is an A/B/G chipset like the Atheros 5212, for example).
	 */
	is_up_and_associated_wait (self, 2, 100);

	/* Some cards don't really work well in ad-hoc mode unless you explicitly set the bitrate
	 * on them. (Netgear WG511T/Atheros 5212 with madwifi drivers).  Until we can get rate information
	 * from scanned access points out of iwlib, clamp bitrate for these cards at 11Mbps.
	 */
	if ((nm_ap_get_mode (ap) == IW_MODE_ADHOC) && (nm_device_802_11_wireless_get_bitrate (self) <= 0))
		nm_device_802_11_wireless_set_bitrate (self, 11000);	/* In Kbps */

	return TRUE;
}


/*
 * nm_device_wireless_configure_adhoc
 *
 * Create an ad-hoc network (rather than associating with one).
 *
 */
static NMActStageReturn
wireless_configure_adhoc (NMDevice80211Wireless *self,
                          NMAccessPoint *ap,
                          NMActRequest *req)
{
	NMData *			data;
	int				auth = 0;
	NMAPListIter *		iter;
	NMAccessPoint *	tmp_ap;
	double			card_freqs[IW_MAX_FREQUENCIES];
	int				num_freqs = 0, i;
	double			freq_to_use = 0;
	iwrange			range;
	NMSock *			sk;
	int				err;
	const char *		iface;

	g_assert (req);
	data = nm_act_request_get_data (req);
	g_assert (data);

	if (nm_ap_get_encrypted (ap))
		auth = IW_AUTH_ALG_SHARED_KEY;

	/* Build our local list of frequencies to whittle down until we find a free one */
	memset (&card_freqs, 0, sizeof (card_freqs));
	num_freqs = MIN (self->priv->num_freqs, IW_MAX_FREQUENCIES);
	for (i = 0; i < num_freqs; i++)
		card_freqs[i] = self->priv->freqs[i];

	/* Compile a list of wireless channels that are currently in use */
	iter = nm_ap_list_iter_new (nm_device_802_11_wireless_ap_list_get (self));
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

	if ((sk = nm_dev_sock_open (NM_DEVICE (self), DEV_WIRELESS, __func__, NULL)) == NULL)
		return NM_ACT_STAGE_RETURN_FAILURE;

	iface = nm_device_get_iface (NM_DEVICE (self));
	err = iw_get_range_info (nm_dev_sock_get_fd (sk), iface, &range);
	nm_dev_sock_close (sk);
	if (err < 0)
		return NM_ACT_STAGE_RETURN_FAILURE;

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

	if (!freq_to_use)
		return NM_ACT_STAGE_RETURN_FAILURE;

	nm_ap_set_freq (ap, freq_to_use);

	nm_info ("Will create network '%s' with frequency %f.", nm_ap_get_essid (ap), nm_ap_get_freq (ap));
	set_wireless_config (self, ap);

	return NM_ACT_STAGE_RETURN_SUCCESS;
}
#endif /* UNUSED */


/*
 * is_associated
 *
 * Figure out whether or not we're associated to an access point
 */
static gboolean
is_associated (NMDevice80211Wireless *self)
{
	struct iwreq	wrq;
	NMSock *		sk;
	gboolean		associated = FALSE;
	NMData *		app_data;
	const char *	iface;

	app_data = nm_device_get_app_data (NM_DEVICE (self));
	g_assert (app_data);

	if ((sk = nm_dev_sock_open (NM_DEVICE (self), DEV_WIRELESS, __FUNCTION__, NULL)) == NULL)
		return FALSE;

	/* Some cards, for example ipw2x00 cards, can short-circuit the MAC
	 * address check using this check on IWNAME.  Its faster.
	 */
	memset (&wrq, 0, sizeof (struct iwreq));
	iface = nm_device_get_iface (NM_DEVICE (self));
#ifdef IOCTL_DEBUG
	nm_info ("%s: About to GET IWNAME.", iface);
#endif
	if (iw_get_ext (nm_dev_sock_get_fd (sk), iface, SIOCGIWNAME, &wrq) >= 0)
	{
		if (!strcmp (wrq.u.name, "unassociated"))
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
#ifdef IOCTL_DEBUG
	nm_info ("%s: About to GET IWAP.", iface);
#endif
		if (iw_get_ext (nm_dev_sock_get_fd (sk), iface, SIOCGIWAP, &wrq) >= 0)
			if (nm_ethernet_address_is_valid ((struct ether_addr *)(&(wrq.u.ap_addr.sa_data))))
				associated = TRUE;
	}

out:
	nm_dev_sock_close (sk);

	return associated;
}


static gboolean
ap_need_key (NMDevice80211Wireless *self, NMAccessPoint *ap)
{
	const char *	essid;
	gboolean		need_key = FALSE;
	NMAPSecurity *	security;
	const char *	iface;

	g_return_val_if_fail (ap != NULL, FALSE);

	essid = nm_ap_get_essid (ap);
	security = nm_ap_get_security (ap);
	g_assert (security);

	iface = nm_device_get_iface (NM_DEVICE (self));

	if (!nm_ap_get_encrypted (ap))
	{
		nm_info ("Activation (%s/wireless): access point '%s' is unencrypted, no key needed.", 
			 iface, essid ? essid : "(null)");
	}
	else
	{
		if (nm_ap_security_get_key (security))
		{
			nm_info ("Activation (%s/wireless): access point '%s' "
				 "is encrypted, and a key exists.  No new key needed.",
			  	 iface, essid ? essid : "(null)");
		}
		else
		{
			nm_info ("Activation (%s/wireless): access point '%s' "
				 "is encrypted, but NO valid key exists.  New key needed.",
				 iface, essid ? essid : "(null)");
			need_key = TRUE;
		}
	}

	return need_key;
}


/****************************************************************************/
/* WPA Supplicant control stuff
 *
 * Originally from:
 *
 *	wpa_supplicant wrapper
 *
 *	Copyright (C) 2005 Kay Sievers <kay.sievers@vrfy.org>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
 */

#define WPA_SUPPLICANT_GLOBAL_SOCKET		"/var/run/wpa_supplicant-global"
#define WPA_SUPPLICANT_CONTROL_SOCKET		"/var/run/wpa_supplicant"


static void
remove_link_timeout (NMDevice80211Wireless *self)
{
	g_return_if_fail (self != NULL);

	if (self->priv->link_timeout != NULL)
	{
		g_source_destroy (self->priv->link_timeout);
		self->priv->link_timeout = NULL;
	}
}

static void
supplicant_remove_timeout (NMDevice80211Wireless *self)
{
	g_return_if_fail (self != NULL);

	/* Remove any pending timeouts on the request */
	if (self->priv->sup_timeout != NULL)
	{
		g_source_destroy (self->priv->sup_timeout);
		self->priv->sup_timeout = NULL;
	}
}

static char *
supplicant_get_device_socket_path (NMDevice80211Wireless *self)
{
	const char *iface;

	g_return_val_if_fail (self != NULL, NULL);

	iface = nm_device_get_iface (NM_DEVICE (self));
	return g_strdup_printf (WPA_SUPPLICANT_CONTROL_SOCKET "/%s", iface);
}

static void
supplicant_cleanup (NMDevice80211Wireless *self)
{
	char * sock_path;

	g_return_if_fail (self != NULL);

	if (self->priv->sup_pid > 0)
	{
		kill (self->priv->sup_pid, SIGTERM);
		self->priv->sup_pid = -1;
	}
	if (self->priv->sup_watch)
	{
		g_source_destroy (self->priv->sup_watch);
		self->priv->sup_watch = NULL;
	}
	if (self->priv->sup_status)
	{
		g_source_destroy (self->priv->sup_status);
		self->priv->sup_status = NULL;
	}
	if (self->priv->sup_ctrl)
	{
		wpa_ctrl_close (self->priv->sup_ctrl);
		self->priv->sup_ctrl = NULL;
	}

	supplicant_remove_timeout (self);
	remove_link_timeout (self);

	/* HACK: should be fixed in wpa_supplicant.  Will likely
	 * require accomodations for selinux.
	 */
	unlink (WPA_SUPPLICANT_GLOBAL_SOCKET);
	sock_path = supplicant_get_device_socket_path (self);
	unlink (sock_path);
	g_free (sock_path);
}

static void
supplicant_watch_cb (GPid pid,
                     gint status,
                     gpointer user_data)
{
	NMDevice *			dev = NM_DEVICE (user_data);
	NMDevice80211Wireless *	self = NM_DEVICE_802_11_WIRELESS (user_data);
	
	g_assert (self);
	
	if (WIFEXITED (status))
		nm_warning ("wpa_supplicant exited with error code %d", WEXITSTATUS (status));
	else if (WIFSTOPPED (status)) 
		nm_warning ("wpa_supplicant stopped unexpectedly with signal %d", WSTOPSIG (status));
	else if (WIFSIGNALED (status))
		nm_warning ("wpa_supplicant died with signal %d", WTERMSIG (status));
	else
		nm_warning ("wpa_supplicant died from an unknown cause");

	supplicant_cleanup (self);

	nm_device_set_active_link (dev, FALSE);
}


static gboolean
link_timeout_cb (gpointer user_data)
{
	NMDevice *			dev = NM_DEVICE (user_data);

	g_assert (dev);

	nm_info ("%s: link timed out.", nm_device_get_iface (dev));
	nm_device_set_active_link (dev, FALSE);

	return FALSE;
}


#define MESSAGE_LEN	2048

static gboolean
supplicant_status_cb (GIOChannel *source,
                      GIOCondition condition,
                      gpointer user_data)
{
	NMDevice *			dev = NM_DEVICE (user_data);
	NMDevice80211Wireless *	self = NM_DEVICE_802_11_WIRELESS (user_data);
	char *				message;
	size_t				len;
	struct wpa_ctrl *		ctrl;
	NMActRequest * 		req;

	g_assert (self);

	ctrl = self->priv->sup_ctrl;
	g_return_val_if_fail (ctrl != NULL, FALSE);

	req = nm_device_get_act_request (NM_DEVICE (self));

	message = g_malloc (MESSAGE_LEN);
	len = MESSAGE_LEN;
	wpa_ctrl_recv (ctrl, message, &len);
	message[len] = '\0';

	if (strstr (message, WPA_EVENT_CONNECTED) != NULL)
	{
		remove_link_timeout (self);
		nm_device_set_active_link (dev, TRUE);

		/* If this is the initial association during device activation,
		 * schedule the next activation stage.
		 */
		if (req && (nm_act_request_get_stage (req) == NM_ACT_STAGE_DEVICE_CONFIG))
		{
			NMAccessPoint	*ap = nm_act_request_get_ap (req);

			nm_info ("Activation (%s/wireless) Stage 2 (Device Configure)"
					"successful.  Connected to access point '%s'.",
					nm_device_get_iface (NM_DEVICE (self)),
					nm_ap_get_essid (ap) ? nm_ap_get_essid (ap) : "(none)");
			supplicant_remove_timeout (self);
			nm_device_activate_schedule_stage3_ip_config_start (req);
		}
	}
	else if (strstr (message, WPA_EVENT_DISCONNECTED) != NULL)
	{
		if (nm_device_is_activated (dev) || nm_device_is_activating (dev))
		{
			/* Start the link timeout so we allow some time for reauthentication */
			if (self->priv->link_timeout == NULL)
			{
				GMainContext *	context = nm_device_get_main_context (dev);
				self->priv->link_timeout = g_timeout_source_new (8000);
				g_source_set_callback (self->priv->link_timeout, link_timeout_cb, self, NULL);
				g_source_attach (self->priv->link_timeout, context);
			}
		}
		else
		{
			nm_device_set_active_link (dev, FALSE);
		}
	}

	return TRUE;
}

static gboolean
supplicant_timeout_cb (gpointer user_data)
{
	NMDevice *			dev = NM_DEVICE (user_data);
	NMDevice80211Wireless *	self = NM_DEVICE_802_11_WIRELESS (user_data);

	g_assert (self);

	nm_info ("Activation (%s/wireless): association took too long (>%ss), failing activation.",
			nm_device_get_iface (dev), NM_SUPPLICANT_TIMEOUT);

	if (nm_device_is_activating (dev))
		nm_policy_schedule_activation_failed (nm_device_get_act_request (dev));

	return FALSE;
}


static gboolean
supplicant_exec (NMDevice80211Wireless *self)
{
	gboolean	success = FALSE;
	char *	argv[4];
	GError *	error = NULL;
	GPid		pid = -1;

	argv[0] = WPA_SUPPLICANT_BIN;
	argv[1] = "-g";
	argv[2] = WPA_SUPPLICANT_GLOBAL_SOCKET;
	argv[3] = NULL;

	if (!(success = g_spawn_async ("/", argv, NULL, 0, NULL, NULL, &pid, &error)))
	{
		if (error)
		{
			nm_warning ("Couldn't start wpa_supplicant.  Error: (%d) %s",
					error->code, error->message);
			g_error_free (error);
		}
		else
			nm_warning ("Couldn't start wpa_supplicant due to an unknown error.");
	}
	else
	{
		g_usleep (G_USEC_PER_SEC);
		self->priv->sup_pid = pid;
		if (self->priv->sup_watch)
			g_source_destroy (self->priv->sup_watch);
		self->priv->sup_watch = g_child_watch_source_new (pid);
		g_source_set_callback (self->priv->sup_watch, (GSourceFunc) supplicant_watch_cb, self, NULL);
		g_source_attach (self->priv->sup_watch, nm_device_get_main_context (NM_DEVICE (self)));
	}

	return success;
}


static gboolean
supplicant_interface_init (NMDevice80211Wireless *self)
{
#define NM_WPA_CTRL_IFACE_DIR		LOCALSTATEDIR"/run/NetworkManager"
	struct wpa_ctrl *	ctrl;
	char *			socket_path;
	const char *		iface = nm_device_get_iface (NM_DEVICE (self));
	gboolean			success = FALSE;
	int				tries = 0;

	/* Ensure our control socket directory is around */
	mkdir (NM_WPA_CTRL_IFACE_DIR, 0700);

	if (!(ctrl = wpa_ctrl_open (WPA_SUPPLICANT_GLOBAL_SOCKET, NM_WPA_CTRL_IFACE_DIR)))
		goto exit;

	/* wpa_cli -g/var/run/wpa_supplicant-global interface_add eth1 "" wext /var/run/wpa_supplicant */
	if (!nm_utils_supplicant_request_with_check (ctrl, "OK", __func__, NULL,
			"INTERFACE_ADD %s\t\twext\t" WPA_SUPPLICANT_CONTROL_SOCKET "\t", iface))
		goto exit;
	wpa_ctrl_close (ctrl);

	/* Get a control socket to wpa_supplicant for this interface.
	 * Try a couple times to work around naive socket naming
	 * in wpa_ctrl that sometimes collides with stale ones.
	 */
	socket_path = supplicant_get_device_socket_path (self);
	while (!self->priv->sup_ctrl && (tries++ < 10))
		self->priv->sup_ctrl = wpa_ctrl_open (socket_path, NM_WPA_CTRL_IFACE_DIR);
	g_free (socket_path);
	if (!self->priv->sup_ctrl)
	{
		nm_info ("Error opening control interface to supplicant.");
		goto exit;
	}
	success = TRUE;

exit:
	return success;
}


static gboolean
supplicant_send_network_config (NMDevice80211Wireless *self,
                                NMActRequest *req)
{
	NMAccessPoint *	ap = NULL;
	gboolean			success = FALSE;
	char *			response = NULL;
	int				nwid;
	const char *		essid;
	struct wpa_ctrl *	ctrl;
	gboolean			user_created;
	char *			hex_essid;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (req != NULL, FALSE);

	ap = nm_act_request_get_ap (req);
	g_assert (ap);

	ctrl = self->priv->sup_ctrl;
	g_assert (ctrl);

	/* Tell wpa_supplicant that we'll do the scanning */
	if (!nm_utils_supplicant_request_with_check (ctrl, "OK", __func__, NULL,
			"AP_SCAN 2"))
		goto out;

	/* Standard network setup info */
	if (!(response = nm_utils_supplicant_request (ctrl, "ADD_NETWORK")))
	{
		nm_warning ("Supplicant error for ADD_NETWORK.\n");
		goto out;
	}
	if (sscanf (response, "%i\n", &nwid) != 1)
	{
		nm_warning ("Supplicant error for ADD_NETWORK.  Response: '%s'\n", response);
		g_free (response);
		goto out;
	}
	g_free (response);

	if (nm_device_activation_should_cancel (NM_DEVICE (self)))
		goto out;

	essid = nm_ap_get_orig_essid (ap);
	hex_essid = cipher_bin2hexstr (essid, strlen (essid), -1);
	if (!nm_utils_supplicant_request_with_check (ctrl, "OK", __func__, NULL,
			"SET_NETWORK %i ssid %s", nwid, hex_essid))
		goto out;

	/* Ad-Hoc ? */
	user_created = nm_ap_get_user_created (ap);
	if (user_created)
	{
		if (!nm_utils_supplicant_request_with_check (ctrl, "OK", __func__, NULL,
				"SET_NETWORK %i mode 1", nwid))
			goto out;
	}

	if (nm_device_activation_should_cancel (NM_DEVICE (self)))
		goto out;

	if (!nm_ap_security_write_supplicant_config (nm_ap_get_security (ap), ctrl, nwid, user_created))
		goto out;

	if (nm_device_activation_should_cancel (NM_DEVICE (self)))
		goto out;

	if (!nm_utils_supplicant_request_with_check (ctrl, "OK", __func__, NULL,
			"ENABLE_NETWORK %i", nwid, essid))
		goto out;

	success = TRUE;
out:
	return success;
}


static gboolean
supplicant_monitor_start (NMDevice80211Wireless *self)
{
	gboolean		success = FALSE;
	int			fd = -1;
	GIOChannel *	channel;
	GMainContext *	context;

	g_return_val_if_fail (self != NULL, FALSE);

	/* register network event monitor */
	if (wpa_ctrl_attach (self->priv->sup_ctrl) != 0)
		goto out;

	if ((fd = wpa_ctrl_get_fd (self->priv->sup_ctrl)) < 0)
		goto out;

	context = nm_device_get_main_context (NM_DEVICE (self));
	channel = g_io_channel_unix_new (fd);
	self->priv->sup_status = g_io_create_watch (channel, G_IO_IN);
	g_source_set_callback (self->priv->sup_status, (GSourceFunc) supplicant_status_cb, self, NULL);
	g_source_attach (self->priv->sup_status, context);

	/* Set up a timeout on the association to kill it after NM_SUPPLICANT_TIMEOUT seconds */
	self->priv->sup_timeout = g_timeout_source_new (NM_SUPPLICANT_TIMEOUT * 1000);
	g_source_set_callback (self->priv->sup_timeout, supplicant_timeout_cb, self, NULL);
	g_source_attach (self->priv->sup_timeout, context);

	success = TRUE;

out:
	return success;
}




/****************************************************************************/

static NMActStageReturn
real_act_stage2_config (NMDevice *dev,
                        NMActRequest *req)
{
	NMDevice80211Wireless *	self = NM_DEVICE_802_11_WIRELESS (dev);
	NMAccessPoint *		ap = nm_act_request_get_ap (req);
	NMActStageReturn		ret = NM_ACT_STAGE_RETURN_FAILURE;
	NMData *				data = nm_act_request_get_data (req);
	const char *			iface;

	g_assert (ap);

	supplicant_cleanup (self);

	/* If we need an encryption key, get one */
	if (ap_need_key (self, ap))
	{
		nm_dbus_get_user_key_for_network (data->dbus_connection, req, FALSE);
		return NM_ACT_STAGE_RETURN_POSTPONE;
	}

	iface = nm_device_get_iface (dev);
	if (!supplicant_exec (self))
	{
		nm_warning ("Activation (%s/wireless): couldn't start the supplicant.",
			iface);
		goto out;
	}
	if (!supplicant_interface_init (self))
	{
		nm_warning ("Activation (%s/wireless): couldn't connect to the supplicant.",
			iface);
		goto out;
	}
	if (!supplicant_send_network_config (self, req))
	{
		nm_warning ("Activation (%s/wireless): couldn't send wireless configuration"
			" to the supplicant.", iface);
		goto out;
	}
	if (!supplicant_monitor_start (self))
	{
		nm_warning ("Activation (%s/wireless): couldn't monitor the supplicant.",
			iface);
		goto out;
	}

	/* We'll get stage3 started when the supplicant connects */
	ret = NM_ACT_STAGE_RETURN_POSTPONE;

out:
	return ret;
}


static NMActStageReturn
real_act_stage3_ip_config_start (NMDevice *dev,
                                 NMActRequest *req)
{
	NMDevice80211Wireless *	self = NM_DEVICE_802_11_WIRELESS (dev);
	NMAccessPoint *		ap = nm_act_request_get_ap (req);
	NMActStageReturn		ret = NM_ACT_STAGE_RETURN_FAILURE;

	g_assert (ap);

	/* User-created access points (ie, Ad-Hoc networks) don't do DHCP,
	 * everything else does.
	 */
	if (!nm_ap_get_user_created (ap))
	{
		NMDevice80211WirelessClass *	klass;
		NMDeviceClass * parent_class;

		/* Chain up to parent */
		klass = NM_DEVICE_802_11_WIRELESS_GET_CLASS (self);
		parent_class = NM_DEVICE_CLASS (g_type_class_peek_parent (klass));
		ret = parent_class->act_stage3_ip_config_start (dev, req);
	}
	else
		ret = NM_ACT_STAGE_RETURN_SUCCESS;

	return ret;
}


static NMActStageReturn
real_act_stage4_get_ip4_config (NMDevice *dev,
                                NMActRequest *req,
                                NMIP4Config **config)
{
	NMDevice80211Wireless *	self = NM_DEVICE_802_11_WIRELESS (dev);
	NMAccessPoint *		ap = nm_act_request_get_ap (req);
	NMActStageReturn		ret = NM_ACT_STAGE_RETURN_FAILURE;
	NMIP4Config *			real_config = NULL;

	g_return_val_if_fail (config != NULL, NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (*config == NULL, NM_ACT_STAGE_RETURN_FAILURE);

	g_assert (ap);
	if (nm_ap_get_user_created (ap))
	{
		real_config = nm_device_new_ip4_autoip_config (NM_DEVICE (self));
		ret = NM_ACT_STAGE_RETURN_SUCCESS;
	}
	else
	{
		NMDevice80211WirelessClass *	klass;
		NMDeviceClass * parent_class;

		/* Chain up to parent */
		klass = NM_DEVICE_802_11_WIRELESS_GET_CLASS (self);
		parent_class = NM_DEVICE_CLASS (g_type_class_peek_parent (klass));
		ret = parent_class->act_stage4_get_ip4_config (dev, req, &real_config);
	}
	*config = real_config;

	return ret;
}


static NMActStageReturn
real_act_stage4_ip_config_timeout (NMDevice *dev,
                                   NMActRequest *req,
                                   NMIP4Config **config)
{
	NMDevice80211Wireless *	self = NM_DEVICE_802_11_WIRELESS (dev);
	NMAccessPoint *		ap = nm_act_request_get_ap (req);
	NMActStageReturn		ret = NM_ACT_STAGE_RETURN_FAILURE;
	NMIP4Config *			real_config = NULL;
	NMAPSecurity *			security;
	NMData *				data;

	g_return_val_if_fail (config != NULL, NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (*config == NULL, NM_ACT_STAGE_RETURN_FAILURE);

	g_assert (ap);

	data = nm_device_get_app_data (dev);
	g_assert (data);

	security = nm_ap_get_security (ap);
	g_assert (security);

	/* FIXME: should we only ask for a new key if the activation request is user-requested? */
	if (nm_ap_security_get_we_cipher (security) != IW_AUTH_CIPHER_NONE)
	{
		/* Activation failed, we must have bad WEP key */
		nm_debug ("Activation (%s/wireless): could not get IP configuration info for '%s', asking for new key.",
				nm_device_get_iface (dev), nm_ap_get_essid (ap) ? nm_ap_get_essid (ap) : "(none)");
		nm_dbus_get_user_key_for_network (data->dbus_connection, req, TRUE);
		ret = NM_ACT_STAGE_RETURN_POSTPONE;
	}
	else
	{
		NMDevice80211WirelessClass *	klass;
		NMDeviceClass * parent_class;

		/* Chain up to parent */
		klass = NM_DEVICE_802_11_WIRELESS_GET_CLASS (self);
		parent_class = NM_DEVICE_CLASS (g_type_class_peek_parent (klass));
		ret = parent_class->act_stage4_ip_config_timeout (dev, req, &real_config);
	}
	*config = real_config;

	return ret;
}


static void
real_activation_success_handler (NMDevice *dev,
                                 NMActRequest *req)
{
	NMDevice80211Wireless *	self = NM_DEVICE_802_11_WIRELESS (dev);
	struct ether_addr	addr;
	NMAccessPoint *	ap = nm_act_request_get_ap (req);
	gboolean			automatic;
	NMData *			app_data;

	app_data = nm_act_request_get_data (req);
	g_assert (app_data);

	/* Cache details in the info-daemon since the connect was successful */
	automatic = !nm_act_request_get_user_requested (req);

	/* If it's a user-created ad-hoc network, add it to the device's scan list */
	if (!automatic && (nm_ap_get_mode (ap) == IW_MODE_ADHOC) && nm_ap_get_user_created (ap))
	{
		NMAccessPointList *ap_list = nm_device_802_11_wireless_ap_list_get (self);
		if (!nm_ap_list_get_ap_by_essid (ap_list, nm_ap_get_essid (ap)))
			nm_ap_list_append_ap (ap_list, ap);
	}

	nm_device_802_11_wireless_get_bssid (self, &addr);
	if (!nm_ap_get_address (ap) || !nm_ethernet_address_is_valid (nm_ap_get_address (ap)))
		nm_ap_set_address (ap, &addr);

	nm_dbus_update_network_info (app_data->dbus_connection, ap, automatic);
}


static void
real_activation_failure_handler (NMDevice *dev,
                                 NMActRequest *req)
{
	NMData *			app_data;
	NMAccessPoint *	ap;

	app_data = nm_act_request_get_data (req);
	g_assert (app_data);

	if ((ap = nm_act_request_get_ap (req)))
	{
		/* Add the AP to the invalid list and force a best ap update */
		nm_ap_set_invalid (ap, TRUE);
		nm_ap_list_append_ap (app_data->invalid_ap_list, ap);
	}

	nm_info ("Activation (%s) failed for access point (%s)", nm_device_get_iface (dev),
			ap ? nm_ap_get_essid (ap) : "(none)");
}

static gboolean
real_can_interrupt_activation (NMDevice *dev)
{
	NMActRequest *			req;
	gboolean interrupt = FALSE;

	if (   (req = nm_device_get_act_request (dev))
	    && (nm_act_request_get_stage (req) == NM_ACT_STAGE_NEED_USER_KEY))
	{
		interrupt = TRUE;
	}
	return interrupt;
}


static guint32
real_get_type_capabilities (NMDevice *dev)
{
	NMDevice80211Wireless *	self = NM_DEVICE_802_11_WIRELESS (dev);

	return self->priv->capabilities;
}


static void
nm_device_802_11_wireless_dispose (GObject *object)
{
	NMDevice80211Wireless *		self = NM_DEVICE_802_11_WIRELESS (object);
	NMDevice80211WirelessClass *	klass = NM_DEVICE_802_11_WIRELESS_GET_CLASS (object);
	NMDeviceClass *			parent_class;

	if (self->priv->dispose_has_run)
		/* If dispose did already run, return. */
		return;

	/* Make sure dispose does not run twice. */
	self->priv->dispose_has_run = TRUE;

	/* 
	 * In dispose, you are supposed to free all types referenced from this
	 * object which might themselves hold a reference to self. Generally,
	 * the most simple solution is to unref all members on which you own a 
	 * reference.
	 */

	nm_device_802_11_wireless_ap_list_clear (self);
	if (self->priv->ap_list)
		nm_ap_list_unref (self->priv->ap_list);
	g_mutex_free (self->priv->scan_mutex);

	/* Chain up to the parent class */
	parent_class = NM_DEVICE_CLASS (g_type_class_peek_parent (klass));
	G_OBJECT_CLASS (parent_class)->dispose (object);
}

static void
nm_device_802_11_wireless_finalize (GObject *object)
{
	NMDevice80211WirelessClass *	klass = NM_DEVICE_802_11_WIRELESS_GET_CLASS (object);
	NMDeviceClass *			parent_class;  

	/* Chain up to the parent class */
	parent_class = NM_DEVICE_CLASS (g_type_class_peek_parent (klass));
	G_OBJECT_CLASS (parent_class)->finalize (object);
}


static void
nm_device_802_11_wireless_class_init (NMDevice80211WirelessClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *parent_class = NM_DEVICE_CLASS (klass);

	object_class->dispose = nm_device_802_11_wireless_dispose;
	object_class->finalize = nm_device_802_11_wireless_finalize;

	parent_class->get_type_capabilities = real_get_type_capabilities;
	parent_class->get_generic_capabilities = real_get_generic_capabilities;
	parent_class->init = real_init;
	parent_class->start = real_start;
	parent_class->update_link = real_update_link;

	parent_class->act_stage2_config = real_act_stage2_config;
	parent_class->act_stage3_ip_config_start = real_act_stage3_ip_config_start;
	parent_class->act_stage4_get_ip4_config = real_act_stage4_get_ip4_config;
	parent_class->act_stage4_ip_config_timeout = real_act_stage4_ip_config_timeout;
	parent_class->deactivate = real_deactivate;
	parent_class->deactivate_quickly = real_deactivate_quickly;
	parent_class->can_interrupt_activation = real_can_interrupt_activation;

	parent_class->activation_failure_handler = real_activation_failure_handler;
	parent_class->activation_success_handler = real_activation_success_handler;

	g_type_class_add_private (object_class, sizeof (NMDevice80211WirelessPrivate));
}

GType
nm_device_802_11_wireless_get_type (void)
{
	static GType type = 0;
	if (type == 0)
	{
		static const GTypeInfo info =
		{
			sizeof (NMDevice80211WirelessClass),
			NULL,	/* base_init */
			NULL,	/* base_finalize */
			(GClassInitFunc) nm_device_802_11_wireless_class_init,
			NULL,	/* class_finalize */
			NULL,	/* class_data */
			sizeof (NMDevice80211Wireless),
			0,		/* n_preallocs */
			(GInstanceInitFunc) nm_device_802_11_wireless_init,
			NULL		/* value_table */
		};
		type = g_type_register_static (NM_TYPE_DEVICE,
					       "NMDevice80211Wireless",
					       &info, 0);
	}
	return type;
}


/*****************************************/
/* Start code ripped from wpa_supplicant */
/*****************************************/
/*
 * Copyright (c) 2003-2005, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */


static int hex2num(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}


static int hex2byte(const char *hex)
{
	int a, b;
	a = hex2num(*hex++);
	if (a < 0)
		return -1;
	b = hex2num(*hex++);
	if (b < 0)
		return -1;
	return (a << 4) | b;
}

static int hexstr2bin(const char *hex, char *buf, size_t len)
{
	int i, a;
	const char *ipos = hex;
	char *opos = buf;

	for (i = 0; i < len; i++) {
		a = hex2byte(ipos);
		if (a < 0)
			return -1;
		*opos++ = a;
		ipos += 2;
	}
	return 0;
}

#define SCAN_SLEEP_CENTISECONDS		10	/* sleep 1/10 of a second, waiting for data */
static gboolean
get_scan_results (NMDevice80211Wireless *dev,
                  NMSock *sk,
                  guint8 **out_res_buf,
                  guint32 *data_len)
{
	struct iwreq iwr;
	guint8 *res_buf;
	size_t res_buf_len = IW_SCAN_MAX_DATA;
	guint8 tries = 0;
	gboolean success = FALSE;

	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (sk != NULL, FALSE);
	g_return_val_if_fail (out_res_buf != NULL, FALSE);
	g_return_val_if_fail (*out_res_buf == NULL, FALSE);
	g_return_val_if_fail (data_len != NULL, FALSE);

	*data_len = 0;

	for (;;)
	{
		res_buf = g_malloc (res_buf_len);
		if (!res_buf)
			break;
		memset (&iwr, 0, sizeof (struct iwreq));
		iwr.u.data.pointer = res_buf;
		iwr.u.data.flags = 0;
		iwr.u.data.length = res_buf_len;

		if (iw_get_ext (nm_dev_sock_get_fd (sk), nm_device_get_iface (NM_DEVICE (dev)), SIOCGIWSCAN, &iwr) == 0)
		{
			/* success */
			*data_len = iwr.u.data.length;
			*out_res_buf = res_buf;
			success = TRUE;
			break;
		}

		g_free (res_buf);
		res_buf = NULL;

		if ((errno == E2BIG) && (res_buf_len < 100000))	/* Buffer not big enough */
		{
			res_buf_len *= 2;
		}
		else if (errno == EAGAIN)	/* Card doesn't have results yet */
		{
			if (tries > 20 * SCAN_SLEEP_CENTISECONDS)
			{
				nm_warning ("get_scan_results(): card took too much time scanning.  Get a better one.");
				break;
			}

			g_usleep (G_USEC_PER_SEC / SCAN_SLEEP_CENTISECONDS);
			tries++;
		}
		else if (errno == ENODATA)	/* No scan results */
		{
			success = TRUE;
			break;
		}
		else		/* Random errors */
		{
			nm_warning ("get_scan_results(): unknown error, or the card returned too much scan info.  errno = %d", errno);
			break;
		}
	}

	return success;
}


static void
add_new_ap_to_device_list (NMDevice80211Wireless *dev,
                           NMAccessPoint *ap)
{
	GTimeVal cur_time;
	NMData *	app_data;
	NMAccessPointList *	ap_list;

	g_return_if_fail (dev != NULL);
	g_return_if_fail (ap != NULL);

	g_get_current_time (&cur_time);
	nm_ap_set_last_seen (ap, &cur_time);

	/* If the AP is not broadcasting its ESSID, try to fill it in here from our
	 * allowed list where we cache known MAC->ESSID associations.
	 */
	app_data = nm_device_get_app_data (NM_DEVICE (dev));
	if (!nm_ap_get_essid (ap))
		nm_ap_list_copy_one_essid_by_address (ap, app_data->allowed_ap_list);

	/* Add the AP to the device's AP list */
	ap_list = nm_device_802_11_wireless_ap_list_get (dev);
	nm_ap_list_merge_scanned_ap (dev, ap_list, ap);
}

static gboolean
process_scan_results (NMDevice80211Wireless *dev,
                      const guint8 *res_buf,
                      guint32 res_buf_len)
{
	char *pos, *end, *custom, *genie, *gpos, *gend;
	NMAccessPoint *ap = NULL;
	size_t clen;
	struct iw_event iwe_buf, *iwe = &iwe_buf;

	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (res_buf != NULL, FALSE);
	g_return_val_if_fail (res_buf_len > 0, FALSE);

	pos = (char *) res_buf;
	end = (char *) res_buf + res_buf_len;

	while (pos + IW_EV_LCP_LEN <= end)
	{
		int ssid_len;

		/* Event data may be unaligned, so make a local, aligned copy
		 * before processing. */
		memcpy (&iwe_buf, pos, IW_EV_LCP_LEN);
		if (iwe->len <= IW_EV_LCP_LEN)
			break;

		custom = pos + IW_EV_POINT_LEN;
		if (dev->priv->we_version > 18 &&
		    (iwe->cmd == SIOCGIWESSID ||
		     iwe->cmd == SIOCGIWENCODE ||
		     iwe->cmd == IWEVGENIE ||
		     iwe->cmd == IWEVCUSTOM))
		{
			/* WE-19 removed the pointer from struct iw_point */
			char *dpos = (char *) &iwe_buf.u.data.length;
			int dlen = dpos - (char *) &iwe_buf;
			memcpy (dpos, pos + IW_EV_LCP_LEN, sizeof (struct iw_event) - dlen);
		}
		else
		{
			memcpy (&iwe_buf, pos, sizeof (struct iw_event));
			custom += IW_EV_POINT_OFF;
		}

		switch (iwe->cmd)
		{
			case SIOCGIWAP:
				/* New access point record */

				/* Merge previous AP */
				if (ap)
				{
					add_new_ap_to_device_list (dev, ap);
					nm_ap_unref (ap);
					ap = NULL;
				}

				/* New AP with some defaults */
				ap = nm_ap_new ();
				nm_ap_set_address (ap, (const struct ether_addr *)(iwe->u.ap_addr.sa_data));
				break;
			case SIOCGIWMODE:
				switch (iwe->u.mode)
				{
					case IW_MODE_ADHOC:
						nm_ap_set_mode (ap, IW_MODE_ADHOC);
						break;
					case IW_MODE_MASTER:
					case IW_MODE_INFRA:
						nm_ap_set_mode (ap, IW_MODE_INFRA);
						break;
					default:
						break;
				}
				break;
			case SIOCGIWESSID:
				ssid_len = iwe->u.essid.length;
				if (custom + ssid_len > end)
					break;
				if (iwe->u.essid.flags && (ssid_len > 0) && (ssid_len <= IW_ESSID_MAX_SIZE))
				{
					gboolean set = TRUE;
					char *essid = g_malloc (IW_ESSID_MAX_SIZE + 1);
					memcpy (essid, custom, ssid_len);
					essid[ssid_len] = '\0';
					if (!strlen(essid))
						set = FALSE;
					else if ((strlen (essid) == 8) && (strcmp (essid, "<hidden>") == 0))	/* Stupid ipw drivers use <hidden> */
						set = FALSE;
					if (set)
						nm_ap_set_essid (ap, essid);
					g_free (essid);
				}
				break;
			case SIOCGIWFREQ:
			     nm_ap_set_freq (ap, iw_freq2float(&(iwe->u.freq)));
				break;
			case IWEVQUAL:
				nm_ap_set_strength (ap, wireless_qual_to_percent (&(iwe->u.qual),
									(const iwqual *)(&dev->priv->max_qual),
									(const iwqual *)(&dev->priv->avg_qual)));
				break;
			case SIOCGIWENCODE:
				if (!(iwe->u.data.flags & IW_ENCODE_DISABLED))
				{
					/* Only add WEP capabilities if this AP doesn't have
					 * any encryption capabilities yet.
					 */
					if (nm_ap_get_capabilities (ap) & NM_802_11_CAP_PROTO_NONE)
						nm_ap_add_capabilities_for_wep (ap);
				}
				break;
#if 0
			case SIOCGIWRATE:
				custom = pos + IW_EV_LCP_LEN;
				clen = iwe->len;
				if (custom + clen > end)
					break;
				maxrate = 0;
				while (((ssize_t) clen) >= sizeof(struct iw_param)) {
					/* Note: may be misaligned, make a local,
					 * aligned copy */
					memcpy(&p, custom, sizeof(struct iw_param));
					if (p.value > maxrate)
						maxrate = p.value;
					clen -= sizeof(struct iw_param);
					custom += sizeof(struct iw_param);
				}
				results[ap_num].maxrate = maxrate;
				break;
#endif
			case IWEVGENIE:
				gpos = genie = custom;
				gend = genie + iwe->u.data.length;
				if (gend > end)
				{
					nm_warning ("get_scan_results(): IWEVGENIE overflow.");
					break;
				}
				while ((gpos + 1 < gend) && (gpos + 2 + (guint8) gpos[1] <= gend))
				{
					guint8 ie = gpos[0], ielen = gpos[1] + 2;
					if (ielen > WPA_MAX_IE_LEN)
					{
						gpos += ielen;
						continue;
					}
					switch (ie)
					{
						case WPA_GENERIC_INFO_ELEM:
							if ((ielen < 2 + 4) || (memcmp (&gpos[2], "\x00\x50\xf2\x01", 4) != 0))
								break;
							nm_ap_add_capabilities_from_ie (ap, (const guint8 *)gpos, ielen);
							break;
						case WPA_RSN_INFO_ELEM:
							nm_ap_add_capabilities_from_ie (ap, (const guint8 *)gpos, ielen);
							break;
					}
					gpos += ielen;
				}
				break;
			case IWEVCUSTOM:
				clen = iwe->u.data.length;
				if (custom + clen > end)
					break;
				if (clen > 7 && ((strncmp (custom, "wpa_ie=", 7) == 0) || (strncmp (custom, "rsn_ie=", 7) == 0)))
				{
					char *spos;
					int bytes;
					char *ie_buf;

					spos = custom + 7;
					bytes = custom + clen - spos;
					if (bytes & 1)
						break;
					bytes /= 2;
					if (bytes > WPA_MAX_IE_LEN)
					{
						nm_warning ("get_scan_results(): IE was too long (%d bytes).", bytes);
						break;
					}
					ie_buf = g_malloc0 (bytes);
					hexstr2bin (spos, ie_buf, bytes);
					if (strncmp (custom, "wpa_ie=", 7) == 0)
						nm_ap_add_capabilities_from_ie (ap, (const guint8 *)ie_buf, bytes);
					else if (strncmp (custom, "rsn_ie=", 7) == 0)
						nm_ap_add_capabilities_from_ie (ap, (const guint8 *)ie_buf, bytes);				
					g_free (ie_buf);
				}
				break;
			default:
				break;
		}

		pos += iwe->len;
	}

	if (ap)
	{
		add_new_ap_to_device_list (dev, ap);
		nm_ap_unref (ap);
		ap = NULL;
	}

	return TRUE;
}

/*****************************************/
/* End code ripped from wpa_supplicant */
/*****************************************/
