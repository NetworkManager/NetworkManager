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
#include <unistd.h>

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
#include "nm-supplicant-manager.h"
#include "nm-supplicant-interface.h"
#include "wpa_ctrl.h"
#include "cipher.h"
#include "dbus-dict-helpers.h"

/* #define IW_QUAL_DEBUG */

#define NM_DEVICE_802_11_WIRELESS_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_802_11_WIRELESS, NMDevice80211WirelessPrivate))

struct _Supplicant
{
	GPid				pid;
	GSource *			watch;
	GSource *			status;
	struct wpa_ctrl *	ctrl;
	GSource *			timeout;

	GSource *			stdout;
};

struct _NMDevice80211WirelessPrivate
{
	gboolean	dispose_has_run;
	gboolean	is_initialized;

	struct ether_addr	hw_addr;

	char *			cur_essid;
	gint8			strength;
	gint8			invalid_strength_counter;
	iwqual			max_qual;
	iwqual			avg_qual;

	gint8			num_freqs;
	double			freqs[IW_MAX_FREQUENCIES];

	gboolean			scanning;
	NMAccessPointList *	ap_list;
	guint8			scan_interval; /* seconds */
	guint32			last_scan;
	GSource *			pending_scan;

	struct _Supplicant	supplicant;

	NMSupplicantInterface * sup_iface;

	guint32			failed_link_count;
	GSource *			link_timeout;

	/* Static options from driver */
	guint8			we_version;
	guint32			capabilities;
};


static void	nm_device_802_11_wireless_ap_list_clear (NMDevice80211Wireless *self);

static gboolean request_wireless_scan (gpointer user_data);

static void	schedule_scan (NMDevice80211Wireless *self);

static void	cancel_pending_scan (NMDevice80211Wireless *self);

static int	wireless_qual_to_percent (const struct iw_quality *qual,
                                         const struct iw_quality *max_qual,
                                         const struct iw_quality *avg_qual);

static gboolean	is_associated (NMDevice80211Wireless *self);

static gboolean	link_to_specific_ap (NMDevice80211Wireless *self,
								 NMAccessPoint *ap,
								 gboolean default_link);

static void		supplicant_cleanup (NMDevice80211Wireless *self);

static void		remove_link_timeout (NMDevice80211Wireless *self);

static void		nm_device_802_11_wireless_disable_encryption (NMDevice80211Wireless *self);

static void supplicant_iface_state_cb (NMSupplicantInterface * iface,
                                       guint32 new_state,
                                       guint32 old_state,
                                       NMDevice80211Wireless *self);

static void supplicant_iface_scanned_ap_cb (NMSupplicantInterface * iface,
                                            DBusMessage * message,
                                            NMDevice80211Wireless * self);

static void supplicant_iface_scan_result_cb (NMSupplicantInterface * iface,
                                             guint32 result,
                                             NMDevice80211Wireless * self);

/*
 * nm_device_802_11_wireless_update_bssid
 *
 * Update the current wireless network's BSSID, presumably in response to
 * roaming.
 *
 */
static void
nm_device_802_11_wireless_update_bssid (NMDevice80211Wireless *self)
{
	NMAccessPoint *		ap;
	NMActRequest *			req;
	struct ether_addr		new_bssid;
	const struct ether_addr	*old_bssid;
	const char *		new_essid;
	const char *		old_essid;

	g_return_if_fail (self != NULL);

	/* The current BSSID is pretty meaningless during a scan */
	if (self->priv->scanning)
		return;

	/* If we aren't the active device with an active AP, there is no meaningful BSSID value */
	req = nm_device_get_act_request (NM_DEVICE (self));
	if (!req)
		return;

	ap = nm_act_request_get_ap (req);
	if (!ap)
		return;

	/* Get the current BSSID.  If it is valid but does not match the stored value,
	 * and the ESSID is the same as what we think its supposed to be, update it. */
	nm_device_802_11_wireless_get_bssid (self, &new_bssid);
	old_bssid = nm_ap_get_address (ap);
	new_essid = nm_device_802_11_wireless_get_essid(self);
	old_essid = nm_ap_get_essid(ap);
	if (     nm_ethernet_address_is_valid (&new_bssid)
		&&  nm_ethernet_address_is_valid (old_bssid)
		&& !nm_ethernet_addresses_are_equal (&new_bssid, old_bssid)
		&& !nm_null_safe_strcmp (old_essid, new_essid))
	{
		NMData *	app_data;
		gboolean	automatic;
		gchar	new_addr[20];
		gchar	old_addr[20];

		memset (new_addr, '\0', sizeof (new_addr));
		memset (old_addr, '\0', sizeof (old_addr));
		iw_ether_ntop (&new_bssid, new_addr);
		iw_ether_ntop (old_bssid, old_addr);
		nm_debug ("Roamed from BSSID %s to %s on wireless network '%s'", old_addr, new_addr, nm_ap_get_essid (ap));

		nm_ap_set_address (ap, &new_bssid);

		automatic = !nm_act_request_get_user_requested (req);
		app_data = nm_device_get_app_data (NM_DEVICE (self));
		g_assert (app_data);
		nm_dbus_update_network_info (ap, automatic);
	}
}


/*
 * nm_device_802_11_wireless_update_signal_strength
 *
 * Update the device's idea of the strength of its connection to the
 * current access point.
 *
 */
static void
nm_device_802_11_wireless_update_signal_strength (NMDevice80211Wireless *self)
{
	gboolean	has_range = FALSE;
	NMSock *	sk;
	iwrange		range;
	iwstats		stats;
	int			percent = -1;

	g_return_if_fail (self != NULL);

	/* Signal strength is pretty meaningless during a scan */
	if (self->priv->scanning)
		return;

	/* If we aren't the active device, we don't really have a signal strength
	 * that would mean anything.
	 */
	if (!nm_device_get_act_request (NM_DEVICE (self))) {
		self->priv->strength = -1;
		return;
	}

	if ((sk = nm_dev_sock_open (NM_DEVICE (self), DEV_WIRELESS, __FUNCTION__, NULL)))
	{
		const char *iface = nm_device_get_iface (NM_DEVICE (self));

		memset (&range, 0, sizeof (iwrange));
		memset (&stats, 0, sizeof (iwstats));

		nm_ioctl_info ("%s: About to GET 'iwrange'.", iface);
		has_range = (iw_get_range_info (nm_dev_sock_get_fd (sk), iface, &range) >= 0);
		nm_ioctl_info ("%s: About to GET 'iwstats'.", iface);

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
		nm_dbus_signal_device_strength_change (self, percent);

	self->priv->strength = percent;
}


static guint nm_wireless_scan_interval_to_seconds (NMWirelessScanInterval interval)
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

	return seconds;
}


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
	self->priv->is_initialized = FALSE;

	memset (&(self->priv->hw_addr), 0, sizeof (struct ether_addr));
	self->priv->supplicant.pid = -1;
}

static void
real_init (NMDevice *dev)
{
	NMDevice80211Wireless *	self = NM_DEVICE_802_11_WIRELESS (dev);
	NMData *				app_data;
	guint32				caps;
	NMSock *				sk;
	NMSupplicantManager *	sup_mgr;

	self->priv->is_initialized = TRUE;
	self->priv->scanning = FALSE;
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

	sup_mgr = nm_supplicant_manager_get ();
	self->priv->sup_iface = nm_supplicant_manager_get_iface (sup_mgr,
	                                                         NM_DEVICE (self));
	if (self->priv->sup_iface == NULL) {
		nm_warning ("Couldn't initialize supplicant interface for %s.",
		            nm_device_get_iface (NM_DEVICE (self)));
	} else {
		g_signal_connect (G_OBJECT (self->priv->sup_iface),
		                  "state",
		                  G_CALLBACK (supplicant_iface_state_cb),
		                  self);

		g_signal_connect (G_OBJECT (self->priv->sup_iface),
		                  "scanned-ap",
		                  G_CALLBACK (supplicant_iface_scanned_ap_cb),
		                  self);

		g_signal_connect (G_OBJECT (self->priv->sup_iface),
		                  "scan-result",
		                  G_CALLBACK (supplicant_iface_scan_result_cb),
		                  self);
	}
	g_object_unref (sup_mgr);
}

static void
real_update_link (NMDevice *dev)
{
	NMDevice80211Wireless *	self = NM_DEVICE_802_11_WIRELESS (dev);

	/* If the supplicant isn't running, we can't possibly have a link */
	if (!self->priv->supplicant.pid)
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
	nm_device_802_11_wireless_update_bssid (self);

	return TRUE;
}


static void
real_start (NMDevice *dev)
{
	NMDevice80211Wireless *	self = NM_DEVICE_802_11_WIRELESS (dev);
	GSource *				source;
	guint				source_id;

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

	/* Clean up stuff, don't leave the card associated */
	nm_device_802_11_wireless_set_essid (self, "");
	nm_device_802_11_wireless_disable_encryption (self);
}


static void
real_deactivate (NMDevice *dev)
{
	NMDevice80211Wireless *	self = NM_DEVICE_802_11_WIRELESS (dev);
	NMData *				app_data;

	app_data = nm_device_get_app_data (dev);
	g_assert (app_data);

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

	/* Fake a link if we're scanning, we'll drop it later
	 * if it's really dead.
	 */
	if (self->priv->scanning)
		return TRUE;

	if (is_associated (self))
	{
		const char *	dev_essid = nm_device_802_11_wireless_get_essid (self);
		const char *	ap_essid = nm_ap_get_essid (ap);

		if (dev_essid && ap_essid && !strcmp (dev_essid, ap_essid))
		{
			self->priv->failed_link_count = 0;
			have_link = TRUE;
		}
	}

	if (!have_link)
	{
		self->priv->failed_link_count++;
		if (self->priv->failed_link_count <= 6)
			have_link = default_link;
	}

	return have_link;
}


static gboolean
get_ap_blacklisted (NMAccessPoint *ap, GSList *addrs)
{
	gboolean blacklisted;

	blacklisted = nm_ap_has_manufacturer_default_essid (ap);
	if (blacklisted)
	{
		GSList *elt;
		const struct ether_addr *ap_addr;
		char char_addr[20];

		ap_addr = nm_ap_get_address (ap);

		memset (&char_addr[0], 0, 20);
		iw_ether_ntop (ap_addr, &char_addr[0]);

		for (elt = addrs; elt; elt = g_slist_next (elt))
		{
			if (elt->data && !strcmp (elt->data, &char_addr[0]))
			{
				blacklisted = FALSE;
				break;
			}
		}
	}

	return blacklisted;
}


/*
 * get_best_fallback_ap
 *
 * Find and return the most suitable "fallback" network, if any.  We "fall back"
 * on these networks and attempt a brute-force connection, given no better options.
 */
static NMAccessPoint *
get_best_fallback_ap (NMDevice80211Wireless *self)
{
	NMAccessPointList *	allowed_list;
	NMAccessPoint *	best_ap = NULL;
	NMAccessPoint *	allowed_ap;
	GTimeVal		 	best_timestamp = {0, 0};
	NMAPListIter *		iter;
	NMData *			app_data;

	app_data = nm_device_get_app_data (NM_DEVICE (self));
	allowed_list = app_data->allowed_ap_list;

	iter = nm_ap_list_iter_new (allowed_list);
	if (!iter)
		return NULL;

	while ((allowed_ap = nm_ap_list_iter_next (iter)))
	{
		const char *		essid;
		GSList *			user_addrs;
		const GTimeVal *	curtime;
		gboolean			blacklisted;

		/* Only designated fallback networks, natch */
		if (!nm_ap_get_fallback (allowed_ap))
			continue;

		/* Only connect to a blacklisted AP if the user has connected to this specific AP before */
		user_addrs = nm_ap_get_user_addresses (allowed_ap);
		blacklisted = get_ap_blacklisted (allowed_ap, user_addrs);
		g_slist_foreach (user_addrs, (GFunc) g_free, NULL);
		g_slist_free (user_addrs);
		if (blacklisted)
			continue;

		/* No fallback to networks on the invalid list -- we probably already tried them and failed */
		essid = nm_ap_get_essid (allowed_ap);
		if (nm_ap_list_get_ap_by_essid (app_data->invalid_ap_list, essid))
			continue;

		curtime = nm_ap_get_timestamp (allowed_ap);
		if (curtime->tv_sec > best_timestamp.tv_sec)
		{
			best_timestamp = *nm_ap_get_timestamp (allowed_ap);
			best_ap = allowed_ap;
		}
	}
	nm_ap_list_iter_free (iter);

	if (best_ap)
	{
		nm_ap_set_broadcast (best_ap, FALSE);
		nm_info ("Attempting to fallback to wireless network '%s'", nm_ap_get_essid (best_ap));
	}

	return best_ap;
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
	GTimeVal		 	best_timestamp = {0, 0};
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

			/* Only keep if its not in the invalid list and its _is_ in our scanned list */
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
			const GTimeVal *	curtime = nm_ap_get_timestamp (tmp_ap);
			gboolean			blacklisted;
			GSList *			user_addrs;

			/* Only connect to a blacklisted AP if the user has connected to this specific AP before */
			user_addrs = nm_ap_get_user_addresses (tmp_ap);
			blacklisted = get_ap_blacklisted (scan_ap, user_addrs);
			g_slist_foreach (user_addrs, (GFunc) g_free, NULL);
			g_slist_free (user_addrs);

			if (!blacklisted && (curtime->tv_sec > best_timestamp.tv_sec))
			{
				best_timestamp = *nm_ap_get_timestamp (tmp_ap);
				best_ap = scan_ap;
				nm_ap_set_security (best_ap, nm_ap_get_security (tmp_ap));
			}
		}
	}
	nm_ap_list_iter_free (iter);

	if (!best_ap)
		best_ap = get_best_fallback_ap (self);

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
		 * "fake" access point and add it to the scan list.
		 */
		ap = nm_ap_new ();
		nm_ap_set_essid (ap, essid);
		nm_ap_set_artificial (ap, TRUE);
		nm_ap_set_broadcast (ap, FALSE);
		/* Ensure the AP has some capabilities.  They will get overwritten
		 * with the correct ones next time the AP is seen in a scan.
		 */
		nm_ap_set_capabilities (ap, nm_ap_security_get_default_capabilities (security));
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
	nm_ap_add_capabilities_from_security (ap, security);

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
	gboolean		found = FALSE;
	guint8		seconds = nm_wireless_scan_interval_to_seconds (interval);

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
			NM_DEVICE_802_11_WIRELESS (d)->priv->scan_interval = seconds;
			if (self && (NM_DEVICE (self) == d))
				found = TRUE;
		}
	}

	/* In case the scan interval didn't get set (which can happen during card
	 * initialization where the device gets set up before being added to the
	 * device list), set interval here
	 */
	if (self && !found)
		self->priv->scan_interval = seconds;

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

		nm_ioctl_info ("%s: About to GET IWMODE.", nm_device_get_iface (NM_DEVICE (self)));

		if (iw_get_ext (nm_dev_sock_get_fd (sk), nm_device_get_iface (NM_DEVICE (self)), SIOCGIWMODE, &wrq) == 0)
		{
			if ((mode == IW_MODE_ADHOC) || (mode == IW_MODE_INFRA))
				mode = wrq.u.mode;
		}
		else
		{
			nm_warning ("error getting card mode on %s: %s",
					nm_device_get_iface (NM_DEVICE (self)), strerror (errno));
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


		nm_ioctl_info ("%s: About to SET IWMODE.", iface);

		wreq.u.mode = mode;
		if (iw_set_ext (nm_dev_sock_get_fd (sk), iface, SIOCSIWMODE, &wreq) == 0)
			success = TRUE;
		else
		{
			if (errno != ENODEV)
			{
				nm_warning ("error setting card %s to %s mode: %s",
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
 * nm_device_get_essid
 *
 * If a device is wireless, return the essid that it is attempting
 * to use.
 *
 * Returns:	allocated string containing essid.  Must be freed by caller.
 *
 */
const char *
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

		nm_ioctl_info ("%s: About to GET 'basic config' for ESSID.", iface);

		err = iw_get_basic_config (nm_dev_sock_get_fd (sk), iface, &info);
		if (err >= 0)
		{
			if (self->priv->cur_essid)
				g_free (self->priv->cur_essid);
			self->priv->cur_essid = g_strdup (info.essid);
		}
		else
		{
			nm_warning ("error getting ESSID for device %s: %s",
					iface, strerror (errno));
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
	char *		safe_essid;
	const char *	iface;
	const char *	driver;
	gint			len = 0;

	g_return_if_fail (self != NULL);

	safe_essid = g_malloc0 (IW_ESSID_MAX_SIZE + 1);

	if (essid)
	{
		len = MIN(IW_ESSID_MAX_SIZE, strlen (essid));
		if (len <= 0)
			len = 0;
		strncpy (safe_essid, essid, len);
	}

	iface = nm_device_get_iface (NM_DEVICE (self));
	if ((sk = nm_dev_sock_open (NM_DEVICE (self), DEV_WIRELESS, __FUNCTION__, NULL)))
	{
		wreq.u.essid.pointer = (caddr_t) safe_essid;
		wreq.u.essid.length	 = len + 1;
		wreq.u.essid.flags	 = (len > 0) ? 1 : 0; /* 1=enable ESSID, 0=disable/any */

		nm_ioctl_info ("%s: About to SET IWESSID.", iface);

		if ((err = iw_set_ext (nm_dev_sock_get_fd (sk), iface, SIOCSIWESSID, &wreq)) == -1)
		{
			if (errno != ENODEV)
			{
				nm_warning ("error setting ESSID to '%s' for device %s: %s",
						safe_essid, iface, strerror (errno));
			}
		}

		nm_dev_sock_close (sk);

		/* Orinoco cards seem to need extra time here to not screw
		 * up the firmware, which reboots when you set the ESSID.
		 * Unfortunately, there's no way to know when the card is back up
		 * again.  Sigh...
		 */
		driver = nm_device_get_driver (NM_DEVICE (self));
		if (!driver || !strcmp (driver, "orinoco"))
			sleep (2);
	}
	g_free (safe_essid);
}


#if 0
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

		nm_ioctl_info ("%s: About to GET IWFREQ.", iface);

		err = iw_get_ext (nm_dev_sock_get_fd (sk), iface, SIOCGIWFREQ, &wrq);
		if (err >= 0)
			freq = iw_freq2float (&wrq.u.freq);
		if (err == -1)
		{
			nm_warning ("error getting frequency for device %s: %s",
					iface, strerror (errno));
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

		nm_ioctl_info ("%s: About to SET IWFREQ.", iface);

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
#endif

/*
 * nm_device_get_bitrate
 *
 * For wireless devices, get the bitrate to broadcast/receive at.
 * Returned value is rate in Mb/s.
 *
 */
int
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
		nm_ioctl_info ("%s: About to GET IWRATE.", iface);
		err = iw_get_ext (nm_dev_sock_get_fd (sk), iface, SIOCGIWRATE, &wrq);
		nm_dev_sock_close (sk);
	}

	return ((err >= 0) ? wrq.u.bitrate.value / 1000000 : 0);
}

#if 0
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
		nm_ioctl_info ("%s: About to SET IWRATE.", iface);
		iw_set_ext (nm_dev_sock_get_fd (sk), iface, SIOCSIWRATE, &wrq);

		nm_dev_sock_close (sk);
	}
}
#endif


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
		nm_ioctl_info ("%s: About to GET IWAP.", iface);
		if (iw_get_ext (nm_dev_sock_get_fd (sk), iface, SIOCGIWAP, &wrq) >= 0)
			memcpy (bssid, &(wrq.u.ap_addr.sa_data), sizeof (struct ether_addr));
		nm_dev_sock_close (sk);
	}
}


/*
 * nm_device_802_11_wireless_disable_encryption
 *
 * Clear any encryption keys the device may have set.
 *
 */
static void
nm_device_802_11_wireless_disable_encryption (NMDevice80211Wireless *self)
{
	const char * iface = nm_device_get_iface (NM_DEVICE (self));
	NMSock *		sk;

	g_return_if_fail (self != NULL);

	if ((sk = nm_dev_sock_open (NM_DEVICE (self), DEV_WIRELESS, __FUNCTION__, NULL)))
	{
     	struct iwreq	wreq = {
			.u.data.pointer = (caddr_t) NULL,
			.u.data.length = 0,
			.u.data.flags = IW_ENCODE_DISABLED
		};

		nm_ioctl_info ("%s: About to SET IWENCODE.", iface);
		if (iw_set_ext (nm_dev_sock_get_fd (sk), iface, SIOCSIWENCODE, &wreq) == -1)
		{
			if (errno != ENODEV)
			{
				nm_warning ("error setting key for device %s: %s",
						iface, strerror (errno));
			}
		}

		nm_dev_sock_close (sk);
	} else nm_warning ("could not get wireless control socket for device %s", iface);
}

static void supplicant_iface_scan_result_cb (NMSupplicantInterface * iface,
                                             guint32 result,
                                             NMDevice80211Wireless * self)
{
	g_return_if_fail (self != NULL);

	/* No matter what the scan result was (error, success), reset
	 * our internal scan tracking variable.
	 */
	self->priv->scanning = FALSE;
	schedule_scan (self);
}

/*
 * request_wireless_scan
 *
 * Reqeust a wireless scan from the supplicant
 *
 */
static gboolean
request_wireless_scan (gpointer user_data)
{
	NMDevice80211Wireless *	self = NM_DEVICE_802_11_WIRELESS (user_data);
	guint32                 caps;
	NMData *                app_data;

	g_return_val_if_fail (self != NULL, FALSE);

	if (!(app_data = nm_device_get_app_data (NM_DEVICE (self))))
		goto out;

	caps = nm_device_get_capabilities (NM_DEVICE (self));
	if (!(caps & NM_DEVICE_CAP_NM_SUPPORTED) || !(caps & NM_DEVICE_CAP_WIRELESS_SCAN))
		goto out;

	g_source_unref (self->priv->pending_scan);	/* Balance g_timeout_source_new() */
	self->priv->pending_scan = NULL;

	/* Reschedule ourselves if all wireless is disabled, we're asleep,
	 * or we are currently activating.
	 */
	if (    (app_data->wireless_enabled == FALSE)
		|| (app_data->asleep == TRUE)
		|| (nm_device_is_activating (NM_DEVICE (self)) == TRUE))
	{
		nm_device_802_11_wireless_set_scan_interval (app_data, self, NM_WIRELESS_SCAN_INTERVAL_INIT);
		schedule_scan (self);
		goto out;
	}

	/*
	 * A/B/G cards should only scan if they are disconnected.  Set the timeout to active
	 * for the case we lose this connection shortly, it will reach this point and then
	 * nm_device_is_activated will return FALSE, letting the scan proceed.
	 */
	if ((self->priv->num_freqs > 14) && nm_device_is_activated (NM_DEVICE (self)) == TRUE)
	{
		nm_device_802_11_wireless_set_scan_interval (app_data, self, NM_WIRELESS_SCAN_INTERVAL_ACTIVE);
		schedule_scan (self);
		goto out;
	}

	self->priv->scanning = TRUE;
	if (!nm_supplicant_interface_request_scan (self->priv->sup_iface)) {
		/* Some sort of error requesting the scan */
		self->priv->scanning = FALSE;
		schedule_scan (self);
	}

out:
	return FALSE;	/* Balance g_source_attach(), destroyed on return */
}


/*
 * schedule_scan
 *
 * Schedule a wireless scan in the /device's/ thread.
 *
 */
static void
schedule_scan (NMDevice80211Wireless *self)
{
	g_return_if_fail (self != NULL);

	cancel_pending_scan (self);

	self->priv->pending_scan = g_timeout_source_new (self->priv->scan_interval * 1000);
	g_source_set_callback (self->priv->pending_scan,
	                       request_wireless_scan, self, NULL);
	g_source_attach (self->priv->pending_scan,
	                 nm_device_get_main_context (NM_DEVICE (self)));
}


static void
cancel_pending_scan (NMDevice80211Wireless *self)
{
	g_return_if_fail (self != NULL);

	self->priv->scanning = FALSE;
	if (self->priv->pending_scan)
	{
		g_source_destroy (self->priv->pending_scan);  /* Balance g_source_attach() */
		g_source_unref (self->priv->pending_scan);  /* Balance g_timeout_source_new() */
		self->priv->pending_scan = NULL;
	}
}


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
	nm_ioctl_info ("%s: About to GET IWNAME.", iface);
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
		nm_ioctl_info ("%s: About to GET IWAP.", iface);
		if (iw_get_ext (nm_dev_sock_get_fd (sk), iface, SIOCGIWAP, &wrq) >= 0)
			if (nm_ethernet_address_is_valid ((struct ether_addr *)(&(wrq.u.ap_addr.sa_data))))
				associated = TRUE;
	}

out:
	nm_dev_sock_close (sk);

	return associated;
}


static gboolean
ap_need_key (NMDevice80211Wireless *self,
             NMAccessPoint *ap,
             gboolean *ask_user)
{
	const char *	essid;
	gboolean		need_key = FALSE;
	NMAPSecurity *	security;
	const char *	iface;
	int			we_cipher;

	g_return_val_if_fail (ap != NULL, FALSE);
	g_return_val_if_fail (ask_user != NULL, FALSE);

	essid = nm_ap_get_essid (ap);
	security = nm_ap_get_security (ap);
	g_assert (security);
	we_cipher = nm_ap_security_get_we_cipher (security);

	iface = nm_device_get_iface (NM_DEVICE (self));

	if (!nm_ap_get_encrypted (ap))
	{
		nm_info ("Activation (%s/wireless): access point '%s' is unencrypted, no key needed.", 
			 iface, essid ? essid : "(null)");

		/* If the user-specified security info doesn't overlap the
		 * scanned access point's info, create new info from the scanned
		 * characteristics of the access point.  Can happen if the AP's
		 * settings were changed.
		 */
		if (we_cipher != IW_AUTH_CIPHER_NONE)
			nm_ap_set_security (ap, nm_ap_security_new_from_ap (ap));
	}
	else
	{
		if (   !nm_ap_security_get_key (security)
		    || (we_cipher == IW_AUTH_CIPHER_NONE))
		{
			nm_info ("Activation (%s/wireless): access point '%s' "
				 "is encrypted, but NO valid key exists.  New key needed.",
				 iface, essid ? essid : "(null)");
			need_key = TRUE;

			/* If the user-specified security info doesn't overlap the
			 * scanned access point's info, ask the user for a completely
			 * new key.
			 */
			if (we_cipher == IW_AUTH_CIPHER_NONE)
				*ask_user = TRUE;
		}
		else
		{
			nm_info ("Activation (%s/wireless): access point '%s' "
				 "is encrypted, and a key exists.  No new key needed.",
			  	 iface, essid ? essid : "(null)");
		}
	}

	return need_key;
}


/*
 * ap_is_auth_required
 *
 * Checks whether or not there is an encryption key present for
 * this connection, and whether or not the authentication method
 * in use will result in an authentication rejection if the key
 * is wrong.  For example, Ad Hoc mode networks don't have a
 * master node and therefore nothing exists to reject the station.
 * Similarly, Open System WEP access points don't reject a station
 * when the key is wrong.  Shared Key WEP access points will.
 *
 * Theory of operation here is that if:
 * (a) the NMAPSecurity object specifies that authentication is
 *     required, and the AP rejects our authentication attempt during
 *     connection (which shows up as a wpa_supplicant disconnection
 *     event); or
 * (b) the NMAPSecurity object specifies that no authentiation is
 *     required, and either DHCP times out or wpa_supplicant times out;
 *
 * then we need a new key from the user because our currenty key
 * and/or authentication method is likely wrong.
 *
 */
static gboolean
ap_is_auth_required (NMAccessPoint *ap, gboolean *has_key)
{
	NMAPSecurity *security;
	int we_cipher;
	gboolean auth_required = FALSE;

	g_return_val_if_fail (ap != NULL, FALSE);
	g_return_val_if_fail (has_key != NULL, FALSE);

	*has_key = FALSE;

	/* Ad Hoc mode doesn't have any master station to validate
	 * security credentials, so no auth can possibly be required.
	 */
	if (nm_ap_get_mode(ap) == IW_MODE_ADHOC)
		return FALSE;

	/* No encryption obviously means no possiblity of auth
	 * rejection due to a wrong encryption key.
	 */
	security = nm_ap_get_security (ap);
	we_cipher = nm_ap_security_get_we_cipher (security);
	if (we_cipher == IW_AUTH_CIPHER_NONE)
		return FALSE;

	auth_required = nm_ap_security_get_authentication_required (security);
	*has_key = TRUE;

	return auth_required;
}


/****************************************************************************
 * WPA Supplicant control stuff
 *
 */
static void
supplicant_iface_state_cb (NMSupplicantInterface * iface,
                           guint32 new_state,
                           guint32 old_state,
                           NMDevice80211Wireless *self)
{
	g_return_if_fail (self != NULL);

	nm_info ("(%s) supplicant interface is now in state %d (from %d).",
             nm_device_get_iface (NM_DEVICE (self)),
             new_state,
             old_state);

	if (new_state == NM_SUPPLICANT_INTERFACE_STATE_READY) {
		/* Start the scanning timeout for devices that can do scanning */
		if (nm_device_get_capabilities (NM_DEVICE (self)) & NM_DEVICE_CAP_WIRELESS_SCAN)
		{
			guint source_id;

			self->priv->pending_scan = g_idle_source_new ();
			g_source_set_callback (self->priv->pending_scan,
					request_wireless_scan, self, NULL);
			source_id = g_source_attach (self->priv->pending_scan,
					nm_device_get_main_context (NM_DEVICE (self)));
		}
	} else if (new_state == NM_SUPPLICANT_INTERFACE_STATE_DOWN) {
		cancel_pending_scan (self);
	}
}


static void
cull_scan_list (NMDevice80211Wireless * self)
{
	GTimeVal            cur_time;
	NMAccessPointList * ap_list;
	NMAccessPoint *     outdated_ap;
	GSList *            outdated_list = NULL;
	GSList *            elt;
	NMActRequest *      req;
	NMAccessPoint *     cur_ap = NULL;
	NMAPListIter *      iter = NULL;
	NMData *            app_data;

	g_return_if_fail (self != NULL);

	app_data = nm_device_get_app_data (NM_DEVICE (self));
	g_assert (app_data);

	if ((req = nm_device_get_act_request (NM_DEVICE (self))))
		cur_ap = nm_act_request_get_ap (req);

	g_get_current_time (&cur_time);

	if (!(ap_list = nm_device_802_11_wireless_ap_list_get (self)))
		goto out;

	if (!(iter = nm_ap_list_iter_new (ap_list)))
		goto out;

	/* Walk the access point list and remove any access points older than
	 * thrice the inactive scan interval.
	 */
	while ((outdated_ap = nm_ap_list_iter_next (iter))) {
		const GTimeVal * ap_time = nm_ap_get_last_seen (outdated_ap);
		gboolean         keep_around = FALSE;
		guint            inactive_interval_s;
		guint            prune_interval_s;
		const char *     ssid;

		/* Don't ever prune the AP we're currently associated with */
		ssid = nm_ap_get_essid (outdated_ap);
		if (ssid && cur_ap) {
			if (nm_null_safe_strcmp (nm_ap_get_essid (cur_ap), ssid) == 0)
				keep_around = TRUE;
		}

		inactive_interval_s = nm_wireless_scan_interval_to_seconds (NM_WIRELESS_SCAN_INTERVAL_INACTIVE);
		prune_interval_s = inactive_interval_s * 3;

		if (!keep_around && (ap_time->tv_sec + prune_interval_s < cur_time.tv_sec))
			outdated_list = g_slist_append (outdated_list, outdated_ap);
	}
	nm_ap_list_iter_free (iter);

	/* Ok, now remove outdated ones.  We have to do it after the lock
	 * because nm_ap_list_remove_ap() locks the list too.
	 */
	for (elt = outdated_list; elt; elt = g_slist_next (elt)) {
		if (!(outdated_ap = (NMAccessPoint *)(elt->data)))
			continue;
		nm_dbus_signal_wireless_network_change (self, outdated_ap, NETWORK_STATUS_DISAPPEARED, -1);
		nm_ap_list_remove_ap (nm_device_802_11_wireless_ap_list_get (self), outdated_ap);
	}
	g_slist_free (outdated_list);

out:
	nm_policy_schedule_device_change_check (app_data);
}

#define HANDLE_DICT_ITEM(in_key, in_type, op) \
	if (!strcmp (entry.key, in_key)) { \
		if (entry.type != in_type) { \
			nm_warning (in_key "had invalid type in scanned AP message."); \
		} else { \
			op \
		} \
		goto next; \
	}

#define HANDLE_DICT_ARRAY_ITEM(in_key, in_ary_type, op) \
	if (!strcmp (entry.key, in_key)) { \
		if (entry.type != DBUS_TYPE_ARRAY) { \
			nm_warning (in_key "had invalid type in scanned AP message."); \
		} else if (entry.array_type != in_ary_type) { \
			nm_warning (in_key "had invalid array type in scanned AP message."); \
		} else { \
			op \
		} \
		goto next; \
	}

#define SET_QUALITY_MEMBER(qual_item, lc_member, uc_member) \
	if (lc_member != -1) { \
		qual_item.lc_member = lc_member; \
		qual_item.updated |= IW_QUAL_##uc_member##_UPDATED; \
	} else { \
		qual_item.updated |= IW_QUAL_##uc_member##_INVALID; \
	}


#define IEEE80211_CAP_ESS       0x0001
#define IEEE80211_CAP_IBSS      0x0002
#define IEEE80211_CAP_PRIVACY   0x0010

static void
supplicant_iface_scanned_ap_cb (NMSupplicantInterface * iface,
                                DBusMessage * message,
                                NMDevice80211Wireless * self)
{
	DBusMessageIter iter, iter_dict;
	NMUDictEntry        entry = { .type = DBUS_TYPE_STRING };
	NMAccessPoint *     ap = NULL;
	GTimeVal            cur_time;
	NMAccessPointList * ap_list;
	int                 qual = -1, level = -1, noise = -1;
	NMData *            app_data;
	struct iw_quality   quality;

	g_return_if_fail (self != NULL);
	g_return_if_fail (message != NULL);
	g_return_if_fail (iface != NULL);

	if (!(app_data = nm_device_get_app_data (NM_DEVICE (self))))
		goto out;

	/* Convert the scanned AP into a NMAccessPoint */
	dbus_message_iter_init (message, &iter);

	if (!nmu_dbus_dict_open_read (&iter, &iter_dict)) {
		nm_warning ("Warning: couldn't get properties dictionary"
		            " from scanned AP message.");
		goto out;
	}

	/* First arg: Dict Type */
	if (dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_ARRAY) {
		nm_warning ("Error: couldn't get properties dictionary"
		          " from scanned AP message.");
		goto out;
	}

	ap = nm_ap_new ();
	if (!ap) {
		nm_warning ("could not allocate new access point.");
		goto out;
	}

	while (nmu_dbus_dict_has_dict_entry (&iter_dict)) {
		if (!nmu_dbus_dict_get_entry (&iter_dict, &entry)) {
			nm_warning ("Error: couldn't read properties dictionary entry"
			            " from scanned AP message.");
			goto out;
		}

		HANDLE_DICT_ARRAY_ITEM("ssid", DBUS_TYPE_BYTE,
			{
				char ssid[33];
				int ssid_len = sizeof (ssid);

				if (entry.array_len < sizeof (ssid))
					ssid_len = entry.array_len;
				if (ssid_len <= 0)
					goto next;
				/* Stupid ieee80211 layer uses <hidden> */
				if ((ssid_len == 8) && (memcmp (entry.bytearray_value, "<hidden>", 8) == 0))
					goto out;
				memset (&ssid, 0, sizeof (ssid));
				memcpy (&ssid, entry.bytearray_value, ssid_len);
				ssid[32] = '\0';
				nm_ap_set_essid (ap, ssid);
			});
		HANDLE_DICT_ARRAY_ITEM("bssid", DBUS_TYPE_BYTE,
			{
				struct ether_addr addr;
				if (entry.array_len != ETH_ALEN)
					goto next;
				memset (&addr, 0, sizeof (struct ether_addr));
				memcpy (&addr, entry.bytearray_value, ETH_ALEN);
				nm_ap_set_address (ap, &addr);
			});

		HANDLE_DICT_ARRAY_ITEM("wpaie", DBUS_TYPE_BYTE,
			{
				guint8 * ie = (guint8 *) &entry.bytearray_value;
				if (entry.array_len <= 0 || entry.array_len > WPA_MAX_IE_LEN)
					goto next;
				nm_ap_add_capabilities_from_ie (ap, ie, entry.array_len);
			});

		HANDLE_DICT_ARRAY_ITEM("rsnie", DBUS_TYPE_BYTE,
			{
				guint8 * ie = (guint8 *) &entry.bytearray_value;
				if (entry.array_len <= 0 || entry.array_len > WPA_MAX_IE_LEN)
					goto next;
				nm_ap_add_capabilities_from_ie (ap, ie, entry.array_len);
			});

		HANDLE_DICT_ITEM("frequency", DBUS_TYPE_INT32,
			{
				double freq = (double) entry.double_value;
				nm_ap_set_freq (ap, freq);
			});

		HANDLE_DICT_ITEM("maxrate", DBUS_TYPE_INT32,
			{ nm_ap_set_rate (ap, entry.int32_value); });

		HANDLE_DICT_ITEM("quality", DBUS_TYPE_INT32,
			{ qual = entry.int32_value; });

		HANDLE_DICT_ITEM("level", DBUS_TYPE_INT32,
			{ level = entry.int32_value; });

		HANDLE_DICT_ITEM("noise", DBUS_TYPE_INT32,
			{ noise = entry.int32_value; });

		HANDLE_DICT_ITEM("capabilities", DBUS_TYPE_UINT16,
			{
				guint32 caps = entry.uint16_value;

				if (caps & IEEE80211_CAP_ESS)
					nm_ap_set_mode (ap, IW_MODE_INFRA);
				else if (caps & IEEE80211_CAP_IBSS)
					nm_ap_set_mode (ap, IW_MODE_ADHOC);

				if (caps & IEEE80211_CAP_PRIVACY) {
					if (nm_ap_get_capabilities (ap) & NM_802_11_CAP_PROTO_NONE)
						nm_ap_add_capabilities_for_wep (ap);
				}
			});

	next:
		nmu_dbus_dict_entry_clear (&entry);
	};

	g_get_current_time (&cur_time);
	self->priv->last_scan = cur_time.tv_sec;
	nm_ap_set_last_seen (ap, &cur_time);

	/* If the AP is not broadcasting its ESSID, try to fill it in here from our
	 * allowed list where we cache known MAC->ESSID associations.
	 */
	if (!nm_ap_get_essid (ap)) {
		nm_ap_set_broadcast (ap, FALSE);
		nm_ap_list_copy_one_essid_by_address (self, ap, app_data->allowed_ap_list);
	}

	/* Calculate and set the AP's signal quality */
	memset (&quality, 0, sizeof (struct iw_quality));
	SET_QUALITY_MEMBER (quality, qual, QUAL);
	SET_QUALITY_MEMBER (quality, level, LEVEL);
	SET_QUALITY_MEMBER (quality, noise, NOISE);
	nm_ap_set_strength (ap, wireless_qual_to_percent (&quality,
						(const iwqual *)(&self->priv->max_qual),
						(const iwqual *)(&self->priv->avg_qual)));

	/* Add the AP to the device's AP list */
	ap_list = nm_device_802_11_wireless_ap_list_get (self);
	nm_ap_list_merge_scanned_ap (self, ap_list, ap);

	/* Once we have the list, copy in any relevant information from our Allowed list. */
	nm_ap_list_copy_properties (ap_list, app_data->allowed_ap_list);

	/* Remove outdated access points */
	cull_scan_list (self);

out:
	if (ap)
		nm_ap_unref (ap);

	/* When we start getting scan results, scanning is over */
	if (self->priv->scanning)
		self->priv->scanning = FALSE;
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

#define WPA_SUPPLICANT_GLOBAL_SOCKET		LOCALSTATEDIR"/run/wpa_supplicant-global"
#define WPA_SUPPLICANT_CONTROL_SOCKET		LOCALSTATEDIR"/run/wpa_supplicant"
#define WPA_SUPPLICANT_NUM_RETRIES		20
#define WPA_SUPPLICANT_RETRY_TIME_US		100*1000


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
	if (self->priv->supplicant.timeout != NULL)
	{
		g_source_destroy (self->priv->supplicant.timeout);
		self->priv->supplicant.timeout = NULL;
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

	if (self->priv->supplicant.pid > 0)
	{
		kill (self->priv->supplicant.pid, SIGTERM);
		self->priv->supplicant.pid = -1;
	}
	if (self->priv->supplicant.watch)
	{
		g_source_destroy (self->priv->supplicant.watch);
		self->priv->supplicant.watch = NULL;
	}
	if (self->priv->supplicant.status)
	{
		g_source_destroy (self->priv->supplicant.status);
		self->priv->supplicant.status = NULL;
	}
	if (self->priv->supplicant.ctrl)
	{
		wpa_ctrl_close (self->priv->supplicant.ctrl);
		self->priv->supplicant.ctrl = NULL;
	}
	if (self->priv->supplicant.stdout)
	{
		g_source_destroy (self->priv->supplicant.stdout);
		self->priv->supplicant.stdout = NULL;
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


/*
 * link_timeout_cb
 *
 * Called when the link to the access point has been down for a specified
 * period of time.
 */
static gboolean
link_timeout_cb (gpointer user_data)
{
	NMDevice *			dev = NM_DEVICE (user_data);
 	NMDevice80211Wireless *	self = NM_DEVICE_802_11_WIRELESS (user_data);	
 	NMActRequest *			req = nm_device_get_act_request (dev);
 	NMAccessPoint *		ap = nm_act_request_get_ap (req);
 	gboolean				has_key;

	g_assert (dev);

 	/* Disconnect event during initial authentication and credentials
 	 * ARE checked - we are likely to have wrong key.  Ask the user for
 	 * another one.
 	 */
 	if (   (nm_act_request_get_stage (req) == NM_ACT_STAGE_DEVICE_CONFIG)
 	    && (ap_is_auth_required (ap, &has_key) && has_key))
 	{
 		/* Association/authentication failed, we must have bad encryption key */
 		nm_info ("Activation (%s/wireless): disconnected during association,"
 		         " asking for new key.", nm_device_get_iface (dev));
 		supplicant_remove_timeout(self);
 		nm_dbus_get_user_key_for_network (req, TRUE);
 	}
 	else
 	{
 		nm_info ("%s: link timed out.", nm_device_get_iface (dev));
 		nm_device_set_active_link (dev, FALSE);
 	}

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

	/* Do nothing if we're supposed to be canceling activation.
	 * We'll get cleaned up by the cancellation handlers later.
	 */
	if (nm_device_activation_should_cancel (dev))
		return TRUE;

	ctrl = self->priv->supplicant.ctrl;
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

			nm_info ("Activation (%s/wireless) Stage 2 of 5 (Device Configure) "
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
			if ((self->priv->link_timeout == NULL) && !self->priv->scanning)
			{
				GMainContext *	context = nm_device_get_main_context (dev);
				self->priv->link_timeout = g_timeout_source_new (20000);
				g_source_set_callback (self->priv->link_timeout, link_timeout_cb, self, NULL);
				g_source_attach (self->priv->link_timeout, context);
			}
		}
		else
		{
			nm_device_set_active_link (dev, FALSE);
		}
	}

	g_free (message);

	return TRUE;
}


#define NM_SUPPLICANT_TIMEOUT	20	/* how long we wait for wpa_supplicant to associate (in seconds) */

static unsigned int
get_supplicant_timeout (NMDevice80211Wireless *self)
{
	if (self->priv->num_freqs > 14)
		return NM_SUPPLICANT_TIMEOUT * 2;
	return NM_SUPPLICANT_TIMEOUT;
}


/*
 * supplicant_timeout_cb
 *
 * Called when the supplicant has been unable to connect to an access point
 * within a specified period of time.
 */
static gboolean
supplicant_timeout_cb (gpointer user_data)
{
	NMDevice *			dev = NM_DEVICE (user_data);
	NMDevice80211Wireless *	self = NM_DEVICE_802_11_WIRELESS (user_data);
	NMActRequest *	req = nm_device_get_act_request (dev);
	NMAccessPoint *	ap = nm_act_request_get_ap (req);
	gboolean	has_key;

	g_assert (self);
		
	/* Timed out waiting for authentication success; if the security method
	 * in use does not require access point side authentication (Open System
	 * WEP, for example) then we are likely using the wrong authentication
	 * algorithm or key.  Request new one from the user.
	 */
	if (!ap_is_auth_required (ap, &has_key) && has_key)
	{
		/* Activation failed, we must have bad encryption key */
		nm_info ("Activation (%s/wireless): association took too long (>%us), asking for new key.",
				nm_device_get_iface (dev), get_supplicant_timeout (self));
		nm_dbus_get_user_key_for_network (req, TRUE);
	}
	else
	{
		nm_info ("Activation (%s/wireless): association took too long (>%us), failing activation.",
				nm_device_get_iface (dev), get_supplicant_timeout (self));
		if (nm_device_is_activating (dev))
			nm_policy_schedule_activation_failed (nm_device_get_act_request (dev));
	}

	return FALSE;
}


/*
 * supplicant_log_stdout
 *
 * Read text from a GIOChannel that's hooked up to the stdout of
 * wpa_supplicant, then write that text to NM's syslog service.
 * Adapted from Gnome's bug-buddy.
 *
 */
static gboolean
supplicant_log_stdout (GIOChannel *ioc, GIOCondition condition, gpointer data)
{
	NMDevice80211Wireless *	self = NM_DEVICE_802_11_WIRELESS (data);
	gboolean retval = FALSE;
	char *buf;
	gsize len;
	GIOStatus io_status;
	GTimeVal start_time, cur_time;

	#define LINE_SIZE 1024
	buf = g_malloc0 (LINE_SIZE);
	g_get_current_time (&start_time);
 try_read:
	io_status = g_io_channel_read_chars (ioc, buf, LINE_SIZE-1, &len, NULL);
	switch (io_status)
	{
		case G_IO_STATUS_AGAIN:
			g_usleep (G_USEC_PER_SEC / 60);
			/* Only wait for data for 1/2 a second */
			g_get_current_time (&cur_time);
			/* Subtract 1/2 second from current time so we don't have
			 * to modify start_time.
			 */
			g_time_val_add (&cur_time, -1 * (G_USEC_PER_SEC / 2));
			/* Compare times.  If cur_time is less, keep trying to read */
			if ((cur_time.tv_sec < start_time.tv_sec)
				|| ((cur_time.tv_sec == start_time.tv_sec)
					&& (cur_time.tv_usec < start_time.tv_usec)))
				goto try_read;
			nm_warning ("Waited too long for wpa_supplicant output, some may be lost.");
			break;
		case G_IO_STATUS_ERROR:
			nm_warning ("Error reading wpa_supplicant output.");
			break;
		case G_IO_STATUS_NORMAL:
			retval = TRUE;
			break;
		default:
			break;
	}

	if (len > 0)
	{
		char *end;
		char *start;

		/* Log each line separately; sometimes we get a couple lines at a time */
		buf[LINE_SIZE-1] = '\0';
		start = end = &buf[0];
		while (*end != '\0')
		{
			if (*end == '\n')
			{
				*end = '\0';
				nm_info ("wpa_supplicant(%d): %s", self->priv->supplicant.pid, start);
				start = end + 1;
			}
			end++;
		}
	}
	g_free (buf);

	return retval;
}

/*
 * supplicant_child_setup
 *
 * Set the process group ID of the newly forked process
 *
 */
static void
supplicant_child_setup (gpointer user_data G_GNUC_UNUSED)
{
	/* We are in the child process at this point */
	pid_t pid = getpid ();
	setpgid (pid, pid);
}

static gboolean
supplicant_exec (NMDevice80211Wireless *self)
{
	gboolean	success = FALSE;
	char *	argv[4];
	GError *	error = NULL;
	GPid		pid = -1;
	int		sup_stdout;

	argv[0] = WPA_SUPPLICANT_BIN;
	argv[1] = "-g";
	argv[2] = WPA_SUPPLICANT_GLOBAL_SOCKET;
	argv[3] = NULL;

	success = g_spawn_async_with_pipes ("/", argv, NULL, 0,
	                    &supplicant_child_setup, NULL, &pid, NULL, &sup_stdout,
	                    NULL, &error);
	if (!success)
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
		GIOChannel *	channel;
		const char *	charset = NULL;

		/* Monitor output from supplicant and redirect to syslog */
		channel = g_io_channel_unix_new (sup_stdout);
		g_io_channel_set_flags (channel, G_IO_FLAG_NONBLOCK, NULL);
		g_get_charset (&charset);
		g_io_channel_set_encoding (channel, charset, NULL);
		self->priv->supplicant.stdout = g_io_create_watch (channel, G_IO_IN | G_IO_ERR);
		g_source_set_priority (self->priv->supplicant.stdout, G_PRIORITY_LOW);
		g_source_set_callback (self->priv->supplicant.stdout, (GSourceFunc) supplicant_log_stdout, self, NULL);
		g_source_attach (self->priv->supplicant.stdout, nm_device_get_main_context (NM_DEVICE (self)));
		g_io_channel_unref (channel);

		/* Monitor the child process so we know when it stops */
		self->priv->supplicant.pid = pid;
		if (self->priv->supplicant.watch)
			g_source_destroy (self->priv->supplicant.watch);
		self->priv->supplicant.watch = g_child_watch_source_new (pid);
		g_source_set_callback (self->priv->supplicant.watch, (GSourceFunc) supplicant_watch_cb, self, NULL);
		g_source_attach (self->priv->supplicant.watch, nm_device_get_main_context (NM_DEVICE (self)));
	}

	return success;
}


static gboolean
supplicant_interface_init (NMDevice80211Wireless *self)
{
	struct wpa_ctrl *	ctrl = NULL;
	char *			socket_path;
	const char *		iface = nm_device_get_iface (NM_DEVICE (self));
	gboolean			success = FALSE;
	int				tries = 0;

	/* Try to open wpa_supplicant's global control socket */
	for (tries = 0; tries < WPA_SUPPLICANT_NUM_RETRIES && !ctrl; tries++)
	{
		ctrl = wpa_ctrl_open (WPA_SUPPLICANT_GLOBAL_SOCKET, NM_RUN_DIR);
		g_usleep (WPA_SUPPLICANT_RETRY_TIME_US);
	}

	if (!ctrl)
	{
		nm_info ("Error opening supplicant global control interface.");
		goto exit;
	}

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
	while (!self->priv->supplicant.ctrl && (tries++ < 10))
		self->priv->supplicant.ctrl = wpa_ctrl_open (socket_path, NM_RUN_DIR);
	g_free (socket_path);
	if (!self->priv->supplicant.ctrl)
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
	gboolean			is_adhoc;
	const char *		hex_essid;
	const char *		ap_scan = "AP_SCAN 1";
	guint32			caps;
	gboolean			supports_wpa;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (req != NULL, FALSE);

	ap = nm_act_request_get_ap (req);
	g_assert (ap);

	ctrl = self->priv->supplicant.ctrl;
	g_assert (ctrl);

	/* Assume that drivers that don't support WPA pretty much suck,
	 * and can't handle NM scanning along with wpa_supplicant.  Which
	 * is the case for most of them, airo in particular.
	 */
	caps = nm_device_get_type_capabilities (NM_DEVICE (self));
	supports_wpa = (caps & NM_802_11_CAP_PROTO_WPA)
				|| (caps & NM_802_11_CAP_PROTO_WPA2);

	/* Use "AP_SCAN 2" if:
	 * - The wireless network is non-broadcast or Ad-Hoc
	 * - The wireless driver does not support WPA (stupid drivers...)
	 */
	is_adhoc = (nm_ap_get_mode(ap) == IW_MODE_ADHOC);
	if (!nm_ap_get_broadcast (ap) || is_adhoc || !supports_wpa)
		ap_scan = "AP_SCAN 2";

	/* Tell wpa_supplicant that we'll do the scanning */
	if (!nm_utils_supplicant_request_with_check (ctrl, "OK", __func__, NULL, ap_scan))
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

	/* For non-broadcast networks, we need to set "scan_ssid 1" to scan with probe request frames.
	 * However, don't try to probe Ad-Hoc networks.
	 */
	if (!nm_ap_get_broadcast (ap) && !is_adhoc)
	{
		if (!nm_utils_supplicant_request_with_check (ctrl, "OK", __func__, NULL,
				"SET_NETWORK %i scan_ssid 1", nwid))
			goto out;
	}

	/* Ad-Hoc ? */
	if (is_adhoc)
	{
		if (!nm_utils_supplicant_request_with_check (ctrl, "OK", __func__, NULL,
				"SET_NETWORK %i mode 1", nwid))
			goto out;
	}

	if (nm_device_activation_should_cancel (NM_DEVICE (self)))
		goto out;

	if (!nm_ap_security_write_supplicant_config (nm_ap_get_security (ap), ctrl, nwid, is_adhoc))
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
	if (wpa_ctrl_attach (self->priv->supplicant.ctrl) != 0)
		goto out;

	if ((fd = wpa_ctrl_get_fd (self->priv->supplicant.ctrl)) < 0)
		goto out;

	context = nm_device_get_main_context (NM_DEVICE (self));
	channel = g_io_channel_unix_new (fd);
	self->priv->supplicant.status = g_io_create_watch (channel, G_IO_IN);
	g_source_set_callback (self->priv->supplicant.status, (GSourceFunc) supplicant_status_cb, self, NULL);
	g_source_attach (self->priv->supplicant.status, context);

	/* Set up a timeout on the association to kill it after get_supplicant_time() seconds */
	self->priv->supplicant.timeout = g_timeout_source_new (get_supplicant_timeout (self) * 1000);
	g_source_set_callback (self->priv->supplicant.timeout, supplicant_timeout_cb, self, NULL);
	g_source_attach (self->priv->supplicant.timeout, context);

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
	const char *			iface;
	gboolean				ask_user = FALSE;

	g_assert (ap);

	supplicant_cleanup (self);

	/* If we need an encryption key, get one */
	if (ap_need_key (self, ap, &ask_user))
	{
		nm_dbus_get_user_key_for_network (req, ask_user);
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
	gboolean		has_key;

	g_return_val_if_fail (config != NULL, NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (*config == NULL, NM_ACT_STAGE_RETURN_FAILURE);

	g_assert (ap);

	data = nm_device_get_app_data (dev);
	g_assert (data);

	security = nm_ap_get_security (ap);
	g_assert (security);

	/* If the security credentials' validity was not checked by any
	 * peer during authentication process, and DHCP times out, then
	 * the encryption key is likely wrong.  Ask the user for a new one.
	 */
	if (!ap_is_auth_required (ap, &has_key) && has_key)
	{
		/* Activation failed, we must have bad encryption key */
		nm_debug ("Activation (%s/wireless): could not get IP configuration info for '%s', asking for new key.",
				nm_device_get_iface (dev), nm_ap_get_essid (ap) ? nm_ap_get_essid (ap) : "(none)");
		nm_dbus_get_user_key_for_network (req, TRUE);
		ret = NM_ACT_STAGE_RETURN_POSTPONE;
	}
	else if (nm_ap_get_mode (ap) == IW_MODE_ADHOC)
	{
		NMDevice80211WirelessClass *	klass;
		NMDeviceClass * parent_class;

		/* For Ad-Hoc networks, chain up to parent to get a Zeroconf IP */
		klass = NM_DEVICE_802_11_WIRELESS_GET_CLASS (self);
		parent_class = NM_DEVICE_CLASS (g_type_class_peek_parent (klass));
		ret = parent_class->act_stage4_ip_config_timeout (dev, req, &real_config);
	}
	else
	{
		/* Non-encrypted network and IP configure failed.  Alert the user. */
		ret = NM_ACT_STAGE_RETURN_FAILURE;
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

	nm_dbus_update_network_info (ap, automatic);
}


static void
real_activation_failure_handler (NMDevice *dev,
                                 NMActRequest *req)
{
	NMData *			app_data;
	NMDevice80211Wireless *	self = NM_DEVICE_802_11_WIRELESS (dev);
	NMAccessPoint *	ap;

	app_data = nm_act_request_get_data (req);
	g_assert (app_data);

	if ((ap = nm_act_request_get_ap (req)))
	{
		if (nm_ap_get_artificial (ap))
		{
			NMAccessPointList *	dev_list;

			/* Artificial APs are ones that don't show up in scans,
			 * but which the user explicitly attempted to connect to.
			 * However, if we fail on one of these, remove it from the
			 * list because we don't have any scan or capability info
			 * for it, and they are pretty much useless.
			 */
			dev_list = nm_device_802_11_wireless_ap_list_get (self);
			nm_ap_list_remove_ap (dev_list, ap);
		}
		else
		{
			/* Add the AP to the invalid list */
			nm_ap_set_invalid (ap, TRUE);
			nm_ap_list_append_ap (app_data->invalid_ap_list, ap);
		}
	}

	nm_info ("Activation (%s) failed for access point (%s)", nm_device_get_iface (dev),
			ap ? nm_ap_get_essid (ap) : "(none)");
}

static void
real_activation_cancel_handler (NMDevice *dev,
                                NMActRequest *req)
{
	NMDevice80211Wireless *		self = NM_DEVICE_802_11_WIRELESS (dev);
	NMDevice80211WirelessClass *	klass;
	NMDeviceClass * 			parent_class;

	/* Chain up to parent first */
	klass = NM_DEVICE_802_11_WIRELESS_GET_CLASS (self);
	parent_class = NM_DEVICE_CLASS (g_type_class_peek_parent (klass));
	parent_class->activation_cancel_handler (dev, req);

	if (nm_act_request_get_stage (req) == NM_ACT_STAGE_NEED_USER_KEY)
		nm_dbus_cancel_get_user_key_for_network (req);
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

	/* Make sure dispose does not run twice. */
	if (self->priv->dispose_has_run)
		return;

	self->priv->dispose_has_run = TRUE;

	/* Only do this part of the cleanup if the object is initialized */
	if (self->priv->is_initialized)
	{
		NMSupplicantManager * sup_mgr;

		self->priv->is_initialized = FALSE;

		/* General cleanup, free references to other objects */
		nm_device_802_11_wireless_ap_list_clear (self);
		if (self->priv->ap_list)
			nm_ap_list_unref (self->priv->ap_list);

		cancel_pending_scan (self);

		sup_mgr = nm_supplicant_manager_get ();
		nm_supplicant_manager_release_iface (sup_mgr, self->priv->sup_iface);
		g_object_unref (sup_mgr);
	}

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
	parent_class->activation_cancel_handler = real_activation_cancel_handler;

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

