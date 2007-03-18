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
#include "wpa_ctrl.h"
#include "cipher.h"

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
	GSource *			scan_timeout;
	GSource *			pending_scan;

	struct _Supplicant	supplicant;

	guint32			failed_link_count;
	GSource *			link_timeout;
	gulong			wireless_event_id;

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


static void	nm_device_802_11_wireless_ap_list_clear (NMDevice80211Wireless *self);

static void schedule_scan_results_timeout (NMDevice80211Wireless *self, guint32 seconds);

static void nm_device_802_11_wireless_scan_done (gpointer user_data);

static gboolean nm_device_802_11_wireless_scan (gpointer user_data);

static void	cancel_scan_results_timeout (NMDevice80211Wireless *self);

static void	cancel_pending_scan (NMDevice80211Wireless *self);

static void	request_and_convert_scan_results (NMDevice80211Wireless *self);

static gboolean	process_scan_results (NMDevice80211Wireless *dev,
                                          const guint8 *res_buf,
                                          guint32 res_buf_len);
static void	schedule_scan (NMDevice80211Wireless *self);

static int	wireless_qual_to_percent (const struct iw_quality *qual,
                                         const struct iw_quality *max_qual,
                                         const struct iw_quality *avg_qual);

static gboolean	is_associated (NMDevice80211Wireless *self);

static gboolean	link_to_specific_ap (NMDevice80211Wireless *self,
								 NMAccessPoint *ap,
								 gboolean default_link);

static void		supplicant_cleanup (NMDevice80211Wireless *self);

static void		remove_link_timeout (NMDevice80211Wireless *self);

static void		nm_device_802_11_wireless_set_wep_enc_key (NMDevice80211Wireless *self,
                                           const char *key,
                                           int auth_method);

static void		nm_device_802_11_wireless_event (NmNetlinkMonitor *monitor,
                                                     GObject *obj,
                                                     char *data,
                                                     int data_len,
                                                     NMDevice80211Wireless *self);

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
	NMData *		app_data;
	gboolean		has_range = FALSE;
	NMSock *		sk;
	iwrange		range;
	iwstats		stats;
	int			percent = -1;

	g_return_if_fail (self != NULL);

	/* Signal strength is pretty meaningless during a scan */
	if (self->priv->scanning)
		return;

	app_data = nm_device_get_app_data (NM_DEVICE (self));
	g_assert (app_data);

	/* If we aren't the active device, we don't really have a signal strength
	 * that would mean anything.
	 */
	if (!nm_device_get_act_request (NM_DEVICE (self)))
	{
		self->priv->strength = -1;
		return;
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
}


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

	/* If we aren't the active device with an active AP, there is no meaningful BSSID value */
	req = nm_device_get_act_request (NM_DEVICE (self));
	if (!req)
                return;

	ap = nm_act_request_get_ap (req);
	if (!ap)
		return;

	/* Get the current BSSID.  If it is valid but does not match the stored value,
	 * and the ESSID is the same as what we think its suposed to be, update it. */
	nm_device_802_11_wireless_get_bssid (self, &new_bssid);
	old_bssid = nm_ap_get_address (ap);
	new_essid = nm_device_802_11_wireless_get_essid(self);
	old_essid = nm_ap_get_essid(ap);
	if (     nm_ethernet_address_is_valid (&new_bssid)
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
		nm_dbus_update_network_info (app_data->dbus_connection, ap, automatic);
	}
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

	self->priv->supplicant.pid = -1;
}

static void
real_init (NMDevice *dev)
{
	NMDevice80211Wireless *	self = NM_DEVICE_802_11_WIRELESS (dev);
	NMData *				app_data;
	guint32				caps;
	NMSock *				sk;
	NmNetlinkMonitor *		monitor;

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

	monitor = app_data->netlink_monitor;
	self->priv->wireless_event_id = 
			g_signal_connect (G_OBJECT (monitor), "wireless-event",
				G_CALLBACK (nm_device_802_11_wireless_event), self);
}


typedef struct WirelessEventCBData
{
	NMDevice80211Wireless *	dev;
	char *				data;
	int					len;
} WirelessEventCBData;

static void
wireless_event_cb_data_free (WirelessEventCBData *data)
{
	if (data) {
		g_object_unref (data->dev);
		g_free (data->data);
		g_free (data);
	}
}

static gboolean
wireless_event_helper (gpointer user_data)
{
	NMDevice80211Wireless *	self;
	WirelessEventCBData *	cb_data;
	struct iw_event iwe_buf, *iwe = &iwe_buf;
	char *pos, *end, *custom;

	cb_data = (WirelessEventCBData *) user_data;
	g_return_val_if_fail (cb_data != NULL, FALSE);

	self = NM_DEVICE_802_11_WIRELESS (cb_data->dev);
	g_return_val_if_fail (self != NULL, FALSE);

	g_return_val_if_fail (cb_data->data != NULL, FALSE);
	g_return_val_if_fail (cb_data->len >= 0, FALSE);

	pos = cb_data->data;
	end = cb_data->data + cb_data->len;

	while (pos + IW_EV_LCP_LEN <= end)
	{
		/* Event data may be unaligned, so make a local, aligned copy
		 * before processing. */
		memcpy (&iwe_buf, pos, IW_EV_LCP_LEN);
		if (iwe->len <= IW_EV_LCP_LEN)
			break;

		custom = pos + IW_EV_POINT_LEN;
		if (self->priv->we_version > 18 &&
		    (iwe->cmd == IWEVMICHAELMICFAILURE ||
		     iwe->cmd == IWEVCUSTOM ||
		     iwe->cmd == IWEVASSOCREQIE ||
		     iwe->cmd == IWEVASSOCRESPIE ||
		     iwe->cmd == IWEVPMKIDCAND))
		{
			/* WE-19 removed the pointer from struct iw_point */
			char *dpos = (char *) &iwe_buf.u.data.length;
			int dlen = dpos - (char *) &iwe_buf;
			memcpy (dpos, pos + IW_EV_LCP_LEN,
			       sizeof (struct iw_event) - dlen);
		}
		else
		{
			memcpy (&iwe_buf, pos, sizeof (struct iw_event));
			custom += IW_EV_POINT_OFF;
		}

		switch (iwe->cmd)
		{
			case SIOCGIWAP:
				if (   memcmp(iwe->u.ap_addr.sa_data,
					   "\x00\x00\x00\x00\x00\x00", ETH_ALEN) == 0
				    || memcmp(iwe->u.ap_addr.sa_data,
					   "\x44\x44\x44\x44\x44\x44", ETH_ALEN) == 0
				    || memcmp(iwe->u.ap_addr.sa_data,
					   "\xFF\xFF\xFF\xFF\xFF\xFF", ETH_ALEN) == 0)
				{
					/* disassociated */
				} else {
					/* associated */
				}
				break;
			case SIOCGIWSCAN:
				/* Batch together scan result updates; cards that background
				 * scan (like ipw cards) send notifications of new scan results
				 * in very quick succession.
				 */
				if (!self->priv->scan_timeout)
					schedule_scan_results_timeout (self, 5);
				break;
		}
		pos += iwe->len;
	}

	return FALSE;
}

static void
nm_device_802_11_wireless_event (NmNetlinkMonitor *monitor,
                                 GObject *obj,
                                 char *data,
                                 int data_len,
                                 NMDevice80211Wireless *self)
{
	GSource *				source;
	WirelessEventCBData *	cb_data;

	/* Make sure signal is for us */
	if (NM_DEVICE (self) != NM_DEVICE (obj))
		return;

	cb_data = g_malloc0 (sizeof (WirelessEventCBData));
	cb_data->dev = g_object_ref (G_OBJECT (self));
	cb_data->data = g_malloc (data_len);
	memcpy (cb_data->data, data, data_len);
	cb_data->len = data_len;

	source = g_idle_source_new ();
	g_source_set_callback (source, (GSourceFunc) wireless_event_helper,
			cb_data, (GDestroyNotify) wireless_event_cb_data_free);
	g_source_attach (source, nm_device_get_main_context (NM_DEVICE (self)));
	g_source_unref (source);
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

	/* Start the scanning timeout for devices that can do scanning */
	if (nm_device_get_capabilities (dev) & NM_DEVICE_CAP_WIRELESS_SCAN)
	{
		self->priv->pending_scan = g_idle_source_new ();
		g_source_set_callback (self->priv->pending_scan,
							   nm_device_802_11_wireless_scan,
							   self,
							   nm_device_802_11_wireless_scan_done);
		source_id = g_source_attach (self->priv->pending_scan,
				nm_device_get_main_context (dev));
		g_source_unref (self->priv->pending_scan);
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

			/* Only keep if its not in the invalid list and it _is_ in our scanned list */
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

		/* The 'else' block will create a new security and we'll going to unref the
		   security at the end of this function. So make sure we don't free the original. */
		g_object_ref (security);

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

	g_object_unref (security);

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
	unsigned char	safe_essid[IW_ESSID_MAX_SIZE + 1] = "\0";
	const char *	iface;
	const char *	driver;

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

#ifdef IOCTL_DEBUG
		nm_info ("%s: About to GET IWFREQ.", iface);
#endif
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
#ifdef IOCTL_DEBUG
		nm_info ("%s: About to GET IWRATE.", iface);
#endif
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
#ifdef IOCTL_DEBUG
		nm_info ("%s: About to SET IWRATE.", iface);
#endif
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
static void
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
					nm_warning ("error setting key for device %s: %s",
							iface, strerror (errno));
				}
			}
		}

		nm_dev_sock_close (sk);
	} else nm_warning ("could not get wireless control socket for device %s", iface);
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
 * convert_scan_results
 *
 * Process results of an iwscan() into our own AP lists.  We're an idle function,
 * but we never reschedule ourselves.
 *
 */
static gboolean
convert_scan_results (gpointer user_data)
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
		return FALSE;

	iface = nm_device_get_iface (NM_DEVICE (self));
	app_data = nm_device_get_app_data (NM_DEVICE (self));
	if (cb_data->results_len > 0)
	{
		if (!process_scan_results (self, cb_data->results, cb_data->results_len))
			nm_warning ("process_scan_results() on device %s returned an error.", iface);

		/* Once we have the list, copy in any relevant information from our Allowed list. */
		nm_ap_list_copy_properties (nm_device_802_11_wireless_ap_list_get (self), app_data->allowed_ap_list);
	}

	/* Walk the access point list and remove any access points older than thrice the inactive scan interval */
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
			guint inactive_interval_s;
			guint prune_interval_s;

			/* Don't ever prune the AP we're currently associated with */
			if (	    nm_ap_get_essid (outdated_ap)
				&&  (cur_ap && (nm_null_safe_strcmp (nm_ap_get_essid (cur_ap), nm_ap_get_essid (outdated_ap))) == 0))
				keep_around = TRUE;

			inactive_interval_s = nm_wireless_scan_interval_to_seconds (NM_WIRELESS_SCAN_INTERVAL_INACTIVE);
			prune_interval_s = inactive_interval_s * 3;

			if (!keep_around && (ap_time->tv_sec + prune_interval_s < cur_time.tv_sec))
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

	return FALSE;
}


#define SCAN_SLEEP_CENTISECONDS		10	/* sleep 1/10 of a second, waiting for data */
static void
request_and_convert_scan_results (NMDevice80211Wireless *self)
{
	NMSock *sk;
	NMWirelessScanResults *scan_results = NULL;
	const char *iface;
	struct iwreq iwr;
	guint8 tries = 0;
	gboolean success = FALSE;
	guint8 *buf = NULL;
	size_t buflen = IW_SCAN_MAX_DATA;

	g_return_if_fail (self != NULL);

	if (!(sk = nm_dev_sock_open (NM_DEVICE (self), DEV_WIRELESS, __FUNCTION__, NULL)))
		return;

	iface = nm_device_get_iface (NM_DEVICE (self));
	for (;;)
	{
		if (!(buf = g_malloc0 (buflen)))
			break;
		iwr.u.data.pointer = buf;
		iwr.u.data.flags = 0;
		iwr.u.data.length = buflen;

		if (iw_get_ext (nm_dev_sock_get_fd (sk), iface, SIOCGIWSCAN, &iwr) == 0)
		{
			/* success */
			buflen = iwr.u.data.length;
			success = TRUE;
			break;
		}

		g_free (buf);
		buf = NULL;

		if ((errno == E2BIG) && (buflen < 100000))	/* Buffer not big enough */
		{
			buflen *= 2;
		}
		else if (errno == EAGAIN)	/* Card doesn't have results yet */
		{
			/* We've already waited for the scan data, so don't give
			 * drivers too much slack here.
			 */
			if (tries > 4 * SCAN_SLEEP_CENTISECONDS)
			{
				nm_warning ("card took too much time scanning.  Get a better one.");
				break;
			}
			g_usleep (G_USEC_PER_SEC / SCAN_SLEEP_CENTISECONDS);
			tries++;
		}
		else if (errno == ENODATA)	/* No scan results */
		{
			buflen = 0;
			success = TRUE;
			break;
		}
		else		/* Random errors */
		{
			nm_warning ("unknown error, or the card returned too much scan info: %s",
					  strerror (errno));
			break;
		}
	}
	nm_dev_sock_close (sk);

	if (success)
	{
		NMData *	app_data = nm_device_get_app_data (NM_DEVICE (self));
		GSource *	convert_source = g_idle_source_new ();
		GTimeVal	cur_time;

		/* We run the scan processing function from the main thread, since it must deliver
		 * messages over DBUS.  Plus, that way the main thread is the only thread that has
		 * to modify the device's access point list.
		 */
		scan_results = g_malloc0 (sizeof (NMWirelessScanResults));
		g_object_ref (G_OBJECT (self));
		scan_results->dev = self;
		scan_results->results = buf;
		scan_results->results_len = buflen;

		g_source_set_callback (convert_source, convert_scan_results, scan_results,
							   (GDestroyNotify) free_process_scan_cb_data);
		g_source_attach (convert_source, app_data->main_context);
		g_source_unref (convert_source);
		g_get_current_time (&cur_time);
		self->priv->last_scan = cur_time.tv_sec;
	}
}


static void
scan_results_timeout_done (gpointer user_data)
{
	NMDevice80211Wireless *device = NM_DEVICE_802_11_WIRELESS (user_data);

	device->priv->scan_timeout = NULL;
}


/*
 * scan_results_timeout
 *
 * Request scan results from the card if it has taken more time than
 * we allow.  Also works around drivers that don't send notifications of
 * completed scans to userspace.
 */
static gboolean
scan_results_timeout (NMDevice80211Wireless *self)
{
	g_return_val_if_fail (self != NULL, FALSE);

	request_and_convert_scan_results (self);
	schedule_scan (self);

	return FALSE;
}


/*
 * schedule_scan_results_timeout
 *
 * For cards that don't send a wireless event for scan results,
 * we hit the card after the timeout and explicitly ask for them.
 *
 */
static void
schedule_scan_results_timeout (NMDevice80211Wireless *self, guint32 seconds)
{
	GMainContext *	context;

	g_return_if_fail (self != NULL);

	cancel_scan_results_timeout (self);

	self->priv->scan_timeout = g_timeout_source_new (seconds * 1000);
	g_source_set_callback (self->priv->scan_timeout,
						   (GSourceFunc) scan_results_timeout,
						   self,
						   scan_results_timeout_done);
	context = nm_device_get_main_context (NM_DEVICE (self));
	g_source_attach (self->priv->scan_timeout, context);
	g_source_unref (self->priv->scan_timeout);
}


/*
 * cancel_scan_results_timeout
 *
 * Cancel an existing scan results timeout
 *
 */
static void
cancel_scan_results_timeout (NMDevice80211Wireless *self)
{
	g_return_if_fail (self != NULL);

	if (self->priv->scan_timeout)
	{
		g_source_destroy (self->priv->scan_timeout); /* Balance g_timeout_source_new() */
		self->priv->scan_timeout = NULL;
	}
}


static void
nm_device_802_11_wireless_scan_done (gpointer user_data)
{
	NMDevice80211Wireless *device = NM_DEVICE_802_11_WIRELESS (user_data);

	device->priv->pending_scan = NULL;
}


/*
 * nm_device_802_11_wireless_scan
 *
 * Trigger a scan request
 *
 */
static gboolean
nm_device_802_11_wireless_scan (gpointer user_data)
{
	NMDevice80211Wireless *	self = NM_DEVICE_802_11_WIRELESS (user_data);
	guint32				caps;
	NMData *				app_data;
	gboolean				success = FALSE;
	const char *			iface;

	g_return_val_if_fail (self != NULL, FALSE);

	if (!(app_data = nm_device_get_app_data (NM_DEVICE (self))))
		goto out;

	caps = nm_device_get_capabilities (NM_DEVICE (self));
	if (!(caps & NM_DEVICE_CAP_NM_SUPPORTED) || !(caps & NM_DEVICE_CAP_WIRELESS_SCAN))
		goto out;

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

	/* Device must be up before we can scan */
	if (nm_device_bring_up_wait (NM_DEVICE (self), 1))
	{
		schedule_scan (self);
		goto out;
	}

	/* If we're currently connected to an AP, let wpa_supplicant initiate
	 * the scan request rather than doing it ourselves.
	 */
	iface = nm_device_get_iface (NM_DEVICE (self));
	if (self->priv->supplicant.ctrl)
	{
		if (nm_utils_supplicant_request_with_check (self->priv->supplicant.ctrl,
				"OK", __func__, NULL, "SCAN"))
			success = TRUE;
	}
	else
	{
		NMSock *		sk;

		if ((sk = nm_dev_sock_open (NM_DEVICE (self), DEV_WIRELESS, __FUNCTION__, NULL)))
		{
			struct iwreq wrq;

			wrq.u.data.pointer = NULL;
			wrq.u.data.flags = 0;
			wrq.u.data.length = 0;
			if (iw_set_ext (nm_dev_sock_get_fd (sk), iface, SIOCSIWSCAN, &wrq) == 0)
				success = TRUE;
			nm_dev_sock_close (sk);
		}
	}

	if (success)
	{
		schedule_scan_results_timeout (self, 10);
	}
	else
	{
		nm_warning ("could not trigger wireless scan on device %s: %s",
				iface, strerror (errno));
		schedule_scan (self);
	}

out:
	return FALSE;	/* Balance g_source_attach(), destroyed on return */
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
	g_return_if_fail (self != NULL);

	cancel_pending_scan (self);

	self->priv->pending_scan = g_timeout_source_new (self->priv->scan_interval * 1000);
	g_source_set_callback (self->priv->pending_scan,
						   nm_device_802_11_wireless_scan,
						   self,
						   nm_device_802_11_wireless_scan_done);
	g_source_attach (self->priv->pending_scan, nm_device_get_main_context (NM_DEVICE (self)));
	g_source_unref (self->priv->pending_scan);
}


static void
cancel_pending_scan (NMDevice80211Wireless *self)
{
	g_return_if_fail (self != NULL);

	self->priv->scanning = FALSE;
	if (self->priv->pending_scan)
	{
		g_source_destroy (self->priv->pending_scan);
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
supplicant_watch_done (gpointer user_data)
{
	NMDevice80211Wireless *device = NM_DEVICE_802_11_WIRELESS (user_data);

	device->priv->supplicant.watch = NULL;
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


static void
link_timeout_done (gpointer user_data)
{
	NMDevice80211Wireless *device = NM_DEVICE_802_11_WIRELESS (user_data);

	device->priv->link_timeout = NULL;
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
 	NMData *				data = nm_device_get_app_data (dev);
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
 		nm_dbus_get_user_key_for_network (data->dbus_connection, req, TRUE);
 	}
 	else
 	{
 		nm_info ("%s: link timed out.", nm_device_get_iface (dev));
 		nm_device_set_active_link (dev, FALSE);
 	}

	return FALSE;
}


static void
supplicant_status_done (gpointer user_data)
{
	NMDevice80211Wireless *device = NM_DEVICE_802_11_WIRELESS (user_data);

	device->priv->supplicant.status = NULL;
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
				self->priv->link_timeout = g_timeout_source_new (8000);
				g_source_set_callback (self->priv->link_timeout,
									   link_timeout_cb,
									   self,
									   link_timeout_done);
				g_source_attach (self->priv->link_timeout, context);
				g_source_unref (self->priv->link_timeout);
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


static void
supplicant_timeout_done (gpointer user_data)
{
	NMDevice80211Wireless *device = NM_DEVICE_802_11_WIRELESS (user_data);

	device->priv->supplicant.timeout = NULL;
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
	NMData *	data = nm_device_get_app_data (dev);
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
		nm_dbus_get_user_key_for_network (data->dbus_connection, req, TRUE);
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


static void
supplicant_log_stdout_done (gpointer user_data)
{
	NMDevice80211Wireless *device = NM_DEVICE_802_11_WIRELESS (user_data);

	device->priv->supplicant.stdout = NULL;
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
		g_io_channel_unref (channel);
		g_source_set_priority (self->priv->supplicant.stdout, G_PRIORITY_LOW);
		g_source_set_callback (self->priv->supplicant.stdout,
							   (GSourceFunc) supplicant_log_stdout,
							   self,
							   supplicant_log_stdout_done);
		g_source_attach (self->priv->supplicant.stdout, nm_device_get_main_context (NM_DEVICE (self)));
		g_source_unref (self->priv->supplicant.stdout);

		/* Monitor the child process so we know when it stops */
		self->priv->supplicant.pid = pid;
		if (self->priv->supplicant.watch)
			g_source_destroy (self->priv->supplicant.watch);
		self->priv->supplicant.watch = g_child_watch_source_new (pid);
		g_source_set_callback (self->priv->supplicant.watch,
							   (GSourceFunc) supplicant_watch_cb,
							   self,
							   supplicant_watch_done);
		g_source_attach (self->priv->supplicant.watch, nm_device_get_main_context (NM_DEVICE (self)));
		g_source_unref (self->priv->supplicant.watch);
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
	char *		hex_essid = NULL;
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
	g_free (hex_essid);

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
	g_io_channel_unref (channel);
	g_source_set_callback (self->priv->supplicant.status,
						   (GSourceFunc) supplicant_status_cb,
						   self,
						   supplicant_status_done);
	g_source_attach (self->priv->supplicant.status, context);
	g_source_unref (self->priv->supplicant.status);

	/* Set up a timeout on the association to kill it after get_supplicant_time() seconds */
	self->priv->supplicant.timeout = g_timeout_source_new (get_supplicant_timeout (self) * 1000);
	g_source_set_callback (self->priv->supplicant.timeout,
						   supplicant_timeout_cb,
						   self,
						   supplicant_timeout_done);
	g_source_attach (self->priv->supplicant.timeout, context);
	g_source_unref (self->priv->supplicant.timeout);

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
	gboolean				ask_user = FALSE;

	g_assert (ap);

	supplicant_cleanup (self);

	/* If we need an encryption key, get one */
	if (ap_need_key (self, ap, &ask_user))
	{
		nm_dbus_get_user_key_for_network (data->dbus_connection, req, ask_user);
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
		nm_dbus_get_user_key_for_network (data->dbus_connection, req, TRUE);
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

	nm_dbus_update_network_info (app_data->dbus_connection, ap, automatic);
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
	{
		NMData *data = nm_device_get_app_data (dev);
		nm_dbus_cancel_get_user_key_for_network (data->dbus_connection, req);
	}
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
	NMData *					data = nm_device_get_app_data (NM_DEVICE (self));

	/* Make sure dispose does not run twice. */
	if (self->priv->dispose_has_run)
		return;

	self->priv->dispose_has_run = TRUE;

	g_free (self->priv->cur_essid);

	/* Only do this part of the cleanup if the object is initialized */
	if (self->priv->is_initialized)
	{
		nm_device_802_11_wireless_ap_list_clear (self);
		if (self->priv->ap_list)
			nm_ap_list_unref (self->priv->ap_list);
	}

	cancel_scan_results_timeout (self);

	g_signal_handler_disconnect (G_OBJECT (data->netlink_monitor),
		self->priv->wireless_event_id);

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

static void
add_new_ap_to_device_list (NMDevice80211Wireless *dev,
                           NMAccessPoint *ap)
{
	GTimeVal cur_time;
	NMAccessPointList *	ap_list;

	g_return_if_fail (dev != NULL);
	g_return_if_fail (ap != NULL);

	g_get_current_time (&cur_time);
	nm_ap_set_last_seen (ap, &cur_time);

	/* If the AP is not broadcasting its ESSID, try to fill it in here from our
	 * allowed list where we cache known MAC->ESSID associations.
	 */
	if (!nm_ap_get_essid (ap))
	{
		NMData *	app_data;

		nm_ap_set_broadcast (ap, FALSE);
		app_data = nm_device_get_app_data (NM_DEVICE (dev));
		nm_ap_list_copy_one_essid_by_address (app_data, dev, ap, app_data->allowed_ap_list);
	}

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
	struct iw_param iwp;
	int maxrate;
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
			case SIOCGIWRATE:
				clen = iwe->len;
				if (custom + clen > end)
					break;
				maxrate = 0;
				while (((ssize_t) clen) >= sizeof(struct iw_param))
				{
					/* the payload may be unaligned, so we align it */
					memcpy(&iwp, custom, sizeof (struct iw_param));
					if (iwp.value > maxrate)
						maxrate = iwp.value;
					clen -= sizeof (struct iw_param);
					custom += sizeof (struct iw_param);
				}
				nm_ap_set_rate (ap, maxrate);
				break;
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
