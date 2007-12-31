/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */
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
#include "nm-device-interface.h"
#include "nm-device-private.h"
#include "nm-utils.h"
#include "NetworkManagerUtils.h"
#include "NetworkManagerPolicy.h"
#include "nm-activation-request.h"
#include "nm-supplicant-manager.h"
#include "nm-supplicant-interface.h"
#include "nm-supplicant-config.h"
#include "nm-properties-changed-signal.h"
#include "nm-setting-connection.h"
#include "nm-setting-wireless.h"

static gboolean impl_device_get_access_points (NMDevice80211Wireless *device,
                                               GPtrArray **aps,
                                               GError **err);

static guint32 nm_device_802_11_wireless_get_frequency (NMDevice80211Wireless *self);

#if DEBUG
static void nm_device_802_11_wireless_ap_list_print (NMDevice80211Wireless *self);
#endif

#include "nm-device-802-11-wireless-glue.h"


/* #define IW_QUAL_DEBUG */

/* All of these are in seconds */
#define SCAN_INTERVAL_MIN 0
#define SCAN_INTERVAL_STEP 20
#define SCAN_INTERVAL_MAX 120


G_DEFINE_TYPE (NMDevice80211Wireless, nm_device_802_11_wireless, NM_TYPE_DEVICE)

#define NM_DEVICE_802_11_WIRELESS_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_802_11_WIRELESS, NMDevice80211WirelessPrivate))


enum {
	PROP_0,
	PROP_HW_ADDRESS,
	PROP_MODE,
	PROP_BITRATE,
	PROP_ACTIVE_ACCESS_POINT,
	PROP_CAPABILITIES,

	LAST_PROP
};

enum {
	ACCESS_POINT_ADDED,
	ACCESS_POINT_REMOVED,
	HIDDEN_AP_FOUND,
	PROPERTIES_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct Supplicant {
	NMSupplicantManager *   mgr;
	NMSupplicantInterface * iface;

	/* signal handler ids */
	guint                   mgr_state_id;
	guint                   iface_error_id;
	guint                   iface_state_id;
	guint                   iface_scanned_ap_id;
	guint                   iface_scan_result_id;
	guint                   iface_con_state_id;

	guint                   con_timeout_id;
} Supplicant;

struct _NMDevice80211WirelessPrivate
{
	gboolean	dispose_has_run;

	struct ether_addr	hw_addr;

	GByteArray *	ssid;
	gint8			invalid_strength_counter;
	iwqual			max_qual;
	iwqual			avg_qual;

	gint8			num_freqs;
	guint32			freqs[IW_MAX_FREQUENCIES];

	GSList *        ap_list;
	NMAccessPoint * current_ap;
	guint32			rate;
	
	gboolean			scanning;
	GTimeVal			scheduled_scan_time;
	guint8			scan_interval; /* seconds */
	guint               pending_scan_id;

	Supplicant          supplicant;

	guint32             failed_link_count;
	guint               periodic_source_id;
	guint               link_timeout_id;

	/* Static options from driver */
	guint8			we_version;
	guint32			capabilities;
};


static void	schedule_scan (NMDevice80211Wireless *self);

static void	cancel_pending_scan (NMDevice80211Wireless *self);

static int	wireless_qual_to_percent (const struct iw_quality *qual,
                                         const struct iw_quality *max_qual,
                                         const struct iw_quality *avg_qual);

static void cleanup_association_attempt (NMDevice80211Wireless * self,
                                         gboolean disconnect);

static void		remove_supplicant_timeouts (NMDevice80211Wireless *self);

static void		nm_device_802_11_wireless_disable_encryption (NMDevice80211Wireless *self);

static void supplicant_iface_state_cb (NMSupplicantInterface * iface,
                                       guint32 new_state,
                                       guint32 old_state,
                                       NMDevice80211Wireless *self);

static void supplicant_iface_connection_state_cb (NMSupplicantInterface * iface,
                                                  guint32 new_state,
                                                  guint32 old_state,
                                                  NMDevice80211Wireless *self);

static void supplicant_iface_scanned_ap_cb (NMSupplicantInterface * iface,
                                            GHashTable *properties,
                                            NMDevice80211Wireless * self);

static void supplicant_iface_scan_result_cb (NMSupplicantInterface * iface,
                                             gboolean result,
                                             NMDevice80211Wireless * self);

static void supplicant_mgr_state_cb (NMSupplicantInterface * iface,
                                     guint32 new_state,
                                     guint32 old_state,
                                     NMDevice80211Wireless *self);

static void cleanup_supplicant_interface (NMDevice80211Wireless * self);

static void device_cleanup (NMDevice80211Wireless *self);

static guint32 nm_device_802_11_wireless_get_bitrate (NMDevice80211Wireless *self);


static void
access_point_removed (NMDevice80211Wireless *device, NMAccessPoint *ap)
{
	g_signal_emit (device, signals[ACCESS_POINT_REMOVED], 0, ap);
}

/*
 * nm_device_802_11_wireless_update_signal_strength
 *
 * Update the device's idea of the strength of its connection to the
 * current access point.
 *
 */
static void
nm_device_802_11_wireless_update_signal_strength (NMDevice80211Wireless *self,
												  NMAccessPoint *ap)
{
	gboolean	has_range = FALSE;
	NMSock *	sk;
	iwrange		range;
	iwstats		stats;
	int			percent = -1;
	const char *iface = nm_device_get_iface (NM_DEVICE (self));

	if ((sk = nm_dev_sock_open (iface, DEV_WIRELESS, __FUNCTION__, NULL)))
	{
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

	if (percent >= 0 || ++self->priv->invalid_strength_counter > 3) {
		nm_ap_set_strength (ap, (gint8) percent);
		self->priv->invalid_strength_counter = 0;
	}
}


static guint32
real_get_generic_capabilities (NMDevice *dev)
{
	NMSock *			sk;
	int				err;
	guint32			caps = NM_DEVICE_CAP_NONE;
	iwrange			range;
	struct iwreq		wrq;
	const char *iface = nm_device_get_iface (dev);

	/* Check for Wireless Extensions support >= 16 for wireless devices */

	if (!(sk = nm_dev_sock_open (iface, DEV_WIRELESS, __func__, NULL)))
		goto out;

	if (iw_get_range_info (nm_dev_sock_get_fd (sk), nm_device_get_iface (dev), &range) < 0)
		goto out;

	if (range.we_version_compiled < 16) {
		nm_warning ("%s: driver's Wireless Extensions version (%d) is too old.",
					iface, range.we_version_compiled);
		goto out;
	} else {
		caps |= NM_DEVICE_CAP_NM_SUPPORTED;
	}

	/* Card's that don't scan aren't supported */
	memset (&wrq, 0, sizeof (struct iwreq));
	err = iw_set_ext (nm_dev_sock_get_fd (sk), nm_device_get_iface (dev), SIOCSIWSCAN, &wrq);
	if ((err == -1) && (errno == EOPNOTSUPP))
		caps = NM_DEVICE_CAP_NONE;

out:
	if (sk)
		nm_dev_sock_close (sk);
	return caps;
}

#define WPA_CAPS (NM_802_11_DEVICE_CAP_CIPHER_TKIP | \
                  NM_802_11_DEVICE_CAP_CIPHER_CCMP | \
                  NM_802_11_DEVICE_CAP_WPA | \
                  NM_802_11_DEVICE_CAP_RSN)

static guint32
get_wireless_capabilities (NMDevice80211Wireless *self,
                           iwrange * range,
                           guint32 data_len)
{
	guint32	minlen;
	guint32	caps = NM_802_11_DEVICE_CAP_NONE;
	const char * iface;

	g_return_val_if_fail (self != NULL, NM_802_11_DEVICE_CAP_NONE);
	g_return_val_if_fail (range != NULL, NM_802_11_DEVICE_CAP_NONE);

	iface = nm_device_get_iface (NM_DEVICE (self));

	minlen = ((char *) &range->enc_capa) - (char *) range + sizeof (range->enc_capa);

	/* All drivers should support WEP by default */
	caps |= NM_802_11_DEVICE_CAP_CIPHER_WEP40 | NM_802_11_DEVICE_CAP_CIPHER_WEP104;

	if ((data_len >= minlen) && range->we_version_compiled >= 18) {
		if (range->enc_capa & IW_ENC_CAPA_CIPHER_TKIP)
			caps |= NM_802_11_DEVICE_CAP_CIPHER_TKIP;

		if (range->enc_capa & IW_ENC_CAPA_CIPHER_CCMP)
			caps |= NM_802_11_DEVICE_CAP_CIPHER_CCMP;

		if (range->enc_capa & IW_ENC_CAPA_WPA)
			caps |= NM_802_11_DEVICE_CAP_WPA;

		if (range->enc_capa & IW_ENC_CAPA_WPA2)
			caps |= NM_802_11_DEVICE_CAP_RSN;

		/* Check for cipher support but not WPA support */
		if (    (caps & (NM_802_11_DEVICE_CAP_CIPHER_TKIP | NM_802_11_DEVICE_CAP_CIPHER_CCMP))
		    && !(caps & (NM_802_11_DEVICE_CAP_WPA | NM_802_11_DEVICE_CAP_RSN))) {
			nm_warning ("%s: device supports WPA ciphers but not WPA protocol; "
			            "WPA unavailable.", iface);
			caps &= ~WPA_CAPS;
		}

		/* Check for WPA support but not cipher support */
		if (    (caps & (NM_802_11_DEVICE_CAP_WPA | NM_802_11_DEVICE_CAP_RSN))
		    && !(caps & (NM_802_11_DEVICE_CAP_CIPHER_TKIP | NM_802_11_DEVICE_CAP_CIPHER_CCMP))) {
			nm_warning ("%s: device supports WPA protocol but not WPA ciphers; "
			            "WPA unavailable.", iface);
			caps &= ~WPA_CAPS;
		}
	}

	return caps;
}


static void
nm_device_802_11_wireless_init (NMDevice80211Wireless * self)
{
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (self);

	self->priv = priv;
	priv->dispose_has_run = FALSE;
	priv->supplicant.iface_error_id = 0;
	priv->scanning = FALSE;
	priv->ap_list = NULL;
	priv->we_version = 0;

	memset (&(self->priv->hw_addr), 0, sizeof (struct ether_addr));

	nm_device_set_device_type (NM_DEVICE (self), DEVICE_TYPE_802_11_WIRELESS);
}

static guint32 iw_freq_to_uint32 (struct iw_freq *freq)
{
	if (freq->e == 0) {
		/* Some drivers report channel not frequency.  Convert to a
		 * frequency; but this assumes that the device is in b/g mode.
		 */
		if ((freq->m >= 1) && (freq->m <= 13))
			return 2407 + (5 * freq->m);
		else if (freq->m == 14)
			return 2484;
	}

	return (guint32) (iw_freq2float (freq) / 1000000);
}

static GObject*
constructor (GType type,
			 guint n_construct_params,
			 GObjectConstructParam *construct_params)
{
	GObject *object;
	GObjectClass *klass;
	NMDevice80211Wireless *self;
	NMDevice80211WirelessPrivate *priv;
	const char *iface;
	NMSock *sk = NULL;
	struct iw_range range;
	struct iwreq wrq;
	int i;

	klass = G_OBJECT_CLASS (nm_device_802_11_wireless_parent_class);
	object = klass->constructor (type, n_construct_params, construct_params);
	if (!object)
		return NULL;

	self = NM_DEVICE_802_11_WIRELESS (object);
	priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (self);

	iface = nm_device_get_iface (NM_DEVICE (self));
	sk = nm_dev_sock_open (iface, DEV_WIRELESS, __FUNCTION__, NULL);
	if (!sk)
		goto error;

	memset (&wrq, 0, sizeof (struct iwreq));
	memset (&range, 0, sizeof (struct iw_range));
	strncpy (wrq.ifr_name, iface, IFNAMSIZ);
	wrq.u.data.pointer = (caddr_t) &range;
	wrq.u.data.length = sizeof (struct iw_range);

	if (ioctl (nm_dev_sock_get_fd (sk), SIOCGIWRANGE, &wrq) < 0)
		goto error;

	priv->max_qual.qual = range.max_qual.qual;
	priv->max_qual.level = range.max_qual.level;
	priv->max_qual.noise = range.max_qual.noise;
	priv->max_qual.updated = range.max_qual.updated;

	priv->avg_qual.qual = range.avg_qual.qual;
	priv->avg_qual.level = range.avg_qual.level;
	priv->avg_qual.noise = range.avg_qual.noise;
	priv->avg_qual.updated = range.avg_qual.updated;

	priv->num_freqs = MIN (range.num_frequency, IW_MAX_FREQUENCIES);
	for (i = 0; i < priv->num_freqs; i++)
		priv->freqs[i] = iw_freq_to_uint32 (&range.freq[i]);

	priv->we_version = range.we_version_compiled;

	/* 802.11 wireless-specific capabilities */
	priv->capabilities = get_wireless_capabilities (self, &range, wrq.u.data.length);

	nm_dev_sock_close (sk);
	return object;

error:
	if (sk)
		nm_dev_sock_close (sk);
	g_object_unref (object);
	return NULL;
}

static void
init_supplicant_interface (NMDevice80211Wireless * self)
{
	Supplicant * sup;
	guint id;

	g_return_if_fail (self != NULL);
	sup = (Supplicant *) &self->priv->supplicant;

	sup->iface = nm_supplicant_manager_get_iface (sup->mgr,
												  nm_device_get_iface (NM_DEVICE (self)),
												  TRUE);
	if (sup->iface == NULL) {
		nm_warning ("Couldn't initialize supplicant interface for %s.",
		            nm_device_get_iface (NM_DEVICE (self)));
	} else {
		id = g_signal_connect (sup->iface,
		                       "state",
		                       G_CALLBACK (supplicant_iface_state_cb),
		                       self);
		sup->iface_state_id = id;

		id = g_signal_connect (sup->iface,
		                       "scanned-ap",
		                       G_CALLBACK (supplicant_iface_scanned_ap_cb),
		                       self);
		sup->iface_scanned_ap_id = id;

		id = g_signal_connect (sup->iface,
		                       "scan-result",
		                       G_CALLBACK (supplicant_iface_scan_result_cb),
		                       self);
		sup->iface_scan_result_id = id;

		id = g_signal_connect (sup->iface,
		                       "connection-state",
		                       G_CALLBACK (supplicant_iface_connection_state_cb),
		                       self);
		sup->iface_con_state_id = id;
	}
}

static void
real_update_link (NMDevice *dev)
{
	NMDevice80211Wireless *	self = NM_DEVICE_802_11_WIRELESS (dev);
	gboolean new_link = FALSE;
	guint32  state;

	/* Ignore link changes when scanning */
	if (self->priv->scanning)
		return;

	if (!self->priv->supplicant.iface)
		goto out;

	state = nm_supplicant_interface_get_state (self->priv->supplicant.iface);
	if (state != NM_SUPPLICANT_INTERFACE_STATE_READY)
		goto out;

	state = nm_supplicant_interface_get_connection_state (self->priv->supplicant.iface);
	if (   state == NM_SUPPLICANT_INTERFACE_CON_STATE_COMPLETED
	    || state == NM_SUPPLICANT_INTERFACE_CON_STATE_ASSOCIATED
	    || state == NM_SUPPLICANT_INTERFACE_CON_STATE_4WAY_HANDSHAKE
	    || state == NM_SUPPLICANT_INTERFACE_CON_STATE_GROUP_HANDSHAKE)
		new_link = TRUE;

out:
	nm_device_set_active_link (NM_DEVICE (self), new_link);
}

static NMAccessPoint *
get_active_ap (NMDevice80211Wireless *self,
               NMAccessPoint *ignore_ap)
{
	struct ether_addr bssid;
	const GByteArray *ssid;
	GSList *iter;

	nm_device_802_11_wireless_get_bssid (self, &bssid);
	if (!nm_ethernet_address_is_valid (&bssid))
		return NULL;

	ssid = nm_device_802_11_wireless_get_ssid (self);

	/* Find this SSID + BSSID in the device's AP list */
	for (iter = self->priv->ap_list; iter; iter = g_slist_next (iter)) {
		NMAccessPoint *ap = NM_AP (iter->data);
		const struct ether_addr	*ap_bssid = nm_ap_get_address (ap);
		const GByteArray *ap_ssid = nm_ap_get_ssid (ap);

		if (ignore_ap && (ap == ignore_ap))
			continue;

		if (   !nm_ethernet_addresses_are_equal (&bssid, ap_bssid)
		    || !nm_utils_same_ssid (ssid, ap_ssid, TRUE))
			continue;

		if (nm_device_802_11_wireless_get_mode (self) != nm_ap_get_mode (ap))
			continue;

		if (nm_device_802_11_wireless_get_frequency (self) != nm_ap_get_freq (ap))
			continue;

		// FIXME: handle security settings here too
		return ap;
	}

	return NULL;
}

static void
set_current_ap (NMDevice80211Wireless *self, NMAccessPoint *new_ap)
{
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (self);
	char *old_path = NULL;

	g_return_if_fail (NM_IS_DEVICE_802_11_WIRELESS (self));

	if (priv->current_ap) {
		old_path = g_strdup (nm_ap_get_dbus_path (priv->current_ap));
		g_object_unref (priv->current_ap);
		priv->current_ap = NULL;
	}

	if (new_ap)
		priv->current_ap = g_object_ref (new_ap);

	/* Only notify if it's really changed */
	if (   (!old_path && new_ap)
	    || (old_path && !new_ap)
	    || (old_path && new_ap && strcmp (old_path, nm_ap_get_dbus_path (new_ap))))
		g_object_notify (G_OBJECT (self), NM_DEVICE_802_11_WIRELESS_ACTIVE_ACCESS_POINT);

	g_free (old_path);
}

static void
periodic_update (NMDevice80211Wireless *self, gboolean honor_scan)
{
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (self);
	NMDeviceState state;
	NMAccessPoint *new_ap;
	guint32 new_rate;

	/* BSSID and signal strength have meaningful values only if the device
	   is activated and not scanning */
	state = nm_device_get_state (NM_DEVICE (self));
	if (state != NM_DEVICE_STATE_ACTIVATED)
		return;

	if (honor_scan && priv->scanning)
		return;

	new_ap = get_active_ap (self, NULL);
	if (new_ap)
		nm_device_802_11_wireless_update_signal_strength (self, new_ap);

	if ((new_ap || priv->current_ap) && (new_ap != priv->current_ap)) {
		const struct ether_addr *new_bssid = NULL;
		const GByteArray *new_ssid = NULL;
		const struct ether_addr *old_bssid = NULL;
		const GByteArray *old_ssid = NULL;
		gchar new_addr[20];
		gchar old_addr[20];

		memset (new_addr, '\0', sizeof (new_addr));
		if (new_ap) {
			new_bssid = nm_ap_get_address (new_ap);
			iw_ether_ntop (new_bssid, new_addr);
			new_ssid = nm_ap_get_ssid (new_ap);
		}

		memset (old_addr, '\0', sizeof (old_addr));
		if (priv->current_ap) {
			old_bssid = nm_ap_get_address (priv->current_ap);
			iw_ether_ntop (old_bssid, old_addr);
			old_ssid = nm_ap_get_ssid (priv->current_ap);
		}

		nm_debug ("Roamed from BSSID %s (%s) to %s (%s)",
		          old_bssid ? old_addr : "(none)",
		          old_ssid ? nm_utils_escape_ssid (old_ssid->data, old_ssid->len) : "(none)",
		          new_bssid ? new_addr : "(none)",
		          new_ssid ? nm_utils_escape_ssid (new_ssid->data, new_ssid->len) : "(none)");

		set_current_ap (self, new_ap);
	}

	new_rate = nm_device_802_11_wireless_get_bitrate (self);
	if (new_rate != priv->rate) {
		priv->rate = new_rate;
		g_object_notify (G_OBJECT (self), NM_DEVICE_802_11_WIRELESS_BITRATE);
	}
}

/*
 * nm_device_802_11_periodic_update
 *
 * Periodically update device statistics.
 *
 */
static gboolean
nm_device_802_11_periodic_update (gpointer data)
{
	NMDevice80211Wireless *self = NM_DEVICE_802_11_WIRELESS (data);

	periodic_update (self, TRUE);
	return TRUE;
}

static gboolean
real_is_up (NMDevice *device)
{
	/* Try device-specific tests first */
	if (NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (device)->periodic_source_id)
		return TRUE;

	return NM_DEVICE_CLASS (nm_device_802_11_wireless_parent_class)->is_up (device);
}

static gboolean
real_bring_up (NMDevice *dev)
{
	NMDevice80211Wireless *self = NM_DEVICE_802_11_WIRELESS (dev);
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (self);

	nm_device_802_11_wireless_set_mode (self, IW_MODE_INFRA);

	priv->supplicant.mgr = nm_supplicant_manager_get ();
	priv->supplicant.mgr_state_id = g_signal_connect (priv->supplicant.mgr,
													  "state",
													  G_CALLBACK (supplicant_mgr_state_cb),
													  self);
	if (nm_supplicant_manager_get_state (priv->supplicant.mgr) == NM_SUPPLICANT_MANAGER_STATE_IDLE) {
		init_supplicant_interface (self);
	}

	/* Peridoically update signal strength */
	priv->periodic_source_id = g_timeout_add (6000, nm_device_802_11_periodic_update, self);

	return TRUE;
}

static void
device_cleanup (NMDevice80211Wireless *self)
{
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (self);

	if (priv->periodic_source_id) {
		g_source_remove (priv->periodic_source_id);
		priv->periodic_source_id = 0;
	}

	cancel_pending_scan (self);

	/* Tell the supplicant to disconnect from the current AP */
	if (priv->supplicant.iface)
		nm_supplicant_interface_disconnect (priv->supplicant.iface);

	cleanup_supplicant_interface (self);

	if (priv->supplicant.mgr_state_id) {
		g_signal_handler_disconnect (priv->supplicant.mgr, priv->supplicant.mgr_state_id);
		priv->supplicant.mgr_state_id = 0;
	}

	if (priv->supplicant.mgr) {
		g_object_unref (priv->supplicant.mgr);
		priv->supplicant.mgr = NULL;
	}
}

static void
real_bring_down (NMDevice *dev)
{
	NMDevice80211Wireless *self = NM_DEVICE_802_11_WIRELESS (dev);

	device_cleanup (self);
}

static void
real_deactivate_quickly (NMDevice *dev)
{
	NMDevice80211Wireless *	self = NM_DEVICE_802_11_WIRELESS (dev);
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (self);

	cleanup_association_attempt (self, TRUE);

	set_current_ap (self, NULL);
	priv->rate = 0;

	/* Clean up stuff, don't leave the card associated */
	nm_device_802_11_wireless_set_ssid (self, NULL);
	nm_device_802_11_wireless_disable_encryption (self);
}

static void
real_deactivate (NMDevice *dev)
{
	NMDevice80211Wireless *	self = NM_DEVICE_802_11_WIRELESS (dev);

	nm_device_802_11_wireless_set_mode (self, IW_MODE_INFRA);
	/* FIXME: Should we reset the scan interval here? */
/* 	nm_device_802_11_wireless_set_scan_interval (app_data, self, NM_WIRELESS_SCAN_INTERVAL_ACTIVE); */
}

static gboolean
real_check_connection_conflicts (NMDevice *device,
                                 NMConnection *connection,
                                 NMConnection *system_connection)
{
	NMDevice80211Wireless *self = NM_DEVICE_802_11_WIRELESS (device);
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (self);
	NMSettingConnection *s_con;
	NMSettingConnection *system_s_con;
	NMSettingWireless *s_wireless;
	NMSettingWireless *system_s_wireless;

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_con);

	system_s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (system_connection, NM_TYPE_SETTING_CONNECTION));
	g_assert (system_s_con);

	s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS));
	g_assert (s_wireless);

	system_s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (system_connection, NM_TYPE_SETTING_WIRELESS));
	g_assert (system_s_wireless);

	if (!system_s_con->lockdown)
		return FALSE;

	if (!strcmp (system_s_con->lockdown, "device")) {
		/* If the system connection has a MAC address and the MAC address
		 * matches this device, the activation request conflicts.
		 */
		if (   system_s_wireless->mac_address
			&& !memcmp (system_s_wireless->mac_address->data, &(priv->hw_addr.ether_addr_octet), ETH_ALEN))
			return TRUE;
	} else if (!strcmp (system_s_con->lockdown, "connection")) {
		/* If the system connection has an SSID and it matches the SSID of the
		 * connection being activated, the connection being activated conflicts.
		 */
		g_assert (system_s_wireless->ssid);
		g_assert (s_wireless->ssid);
		if (nm_utils_same_ssid (system_s_wireless->ssid, s_wireless->ssid, TRUE))
			return TRUE;
	}

	return FALSE;
}

typedef struct BestConnectionInfo {
	NMDevice80211Wireless * self;
	NMConnection * found;
	NMAccessPoint * found_ap;
} BestConnectionInfo;

static void
find_best_connection (gpointer data, gpointer user_data)
{
	BestConnectionInfo * info = (BestConnectionInfo *) user_data;
	NMConnection *connection = NM_CONNECTION (data);
	NMSettingConnection * s_con;
	NMSettingWireless * s_wireless;
	GSList * elt;

	if (info->found)
		return;

	s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
	if (s_con == NULL)
		return;
	if (strcmp (s_con->type, NM_SETTING_WIRELESS_SETTING_NAME))
		return;
	if (!s_con->autoconnect)
		return;

	s_wireless = (NMSettingWireless *) nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS);
	if (s_wireless == NULL)
		return;

	for (elt = info->self->priv->ap_list; elt; elt = g_slist_next (elt)) {
		NMAccessPoint *ap = NM_AP (elt->data);

		if (nm_ap_check_compatible (ap, connection)) {
			/* All good; connection is usable */
			info->found = connection;
			info->found_ap = ap;
			break;
		}
	}
}

static NMConnection *
real_get_best_connection (NMDevice *dev,
                          GSList *connections,
                          char **specific_object)
{
	NMDevice80211Wireless * self = NM_DEVICE_802_11_WIRELESS (dev);
	BestConnectionInfo find_info;

	memset (&find_info, 0, sizeof (BestConnectionInfo));
	find_info.self = self;
	/* Assumes 'connections' list is already sorted according to timestamp */
	g_slist_foreach (connections, find_best_connection, &find_info);

	if (find_info.found)
		*specific_object = (char *) nm_ap_get_dbus_path (find_info.found_ap);
	
	return find_info.found;
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

static NMAccessPoint *
ap_list_get_ap_by_ssid (GSList *list,
                        const GByteArray * ssid)
{
	GSList * elt;

	for (elt = list; elt; elt = g_slist_next (elt)) {
		NMAccessPoint * ap = NM_AP (elt->data);
		const GByteArray * ap_ssid = nm_ap_get_ssid (ap);

		if (ap_ssid && nm_utils_same_ssid (ap_ssid, ssid, TRUE))
			return ap;
	}

	return NULL;
}

#if DEBUG
static void
nm_device_802_11_wireless_ap_list_print (NMDevice80211Wireless *self)
{
	GSList * elt;
	int i = 0;

	g_return_if_fail (NM_IS_DEVICE_802_11_WIRELESS (self));

	nm_info ("AP_LIST_PRINT:");
	for (elt = self->priv->ap_list; elt; elt = g_slist_next (elt), i++) {
		NMAccessPoint * ap = NM_AP (elt->data);
		nm_ap_print_self (ap, "::\t");
	}
	nm_info ("AP_LIST_PRINT: done");
}
#endif

/*
 * nm_device_802_11_wireless_ap_list_get_ap_by_ssid
 *
 * Get the access point for a specific SSID
 *
 */
NMAccessPoint *
nm_device_802_11_wireless_ap_list_get_ap_by_ssid (NMDevice80211Wireless *self,
                                                  const GByteArray * ssid)
{
	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (ssid != NULL, NULL);

	return ap_list_get_ap_by_ssid (self->priv->ap_list, ssid);
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
	GSList * elt;

	for (elt = self->priv->ap_list; elt; elt = g_slist_next (elt)) {
		NMAccessPoint *ap = NM_AP (elt->data);

		if (!strcmp (obj_path, nm_ap_get_dbus_path (ap)))
			return ap;
	}

	return NULL;
}

static gboolean
impl_device_get_access_points (NMDevice80211Wireless *self,
                               GPtrArray **aps,
                               GError **err)
{
	GSList *elt;

	*aps = g_ptr_array_new ();

	for (elt = self->priv->ap_list; elt; elt = g_slist_next (elt)) {
		NMAccessPoint * ap = NM_AP (elt->data);

		if (nm_ap_get_ssid (ap))
			g_ptr_array_add (*aps, g_strdup (nm_ap_get_dbus_path (ap)));
	}
	return TRUE;
}


/* Return TRUE if activation is possible, FALSE if not */
gboolean
nm_device_802_11_wireless_can_activate (NMDevice80211Wireless * self)
{
	NMSupplicantInterface * sup_iface;
	guint32 state;

	g_return_val_if_fail (self != NULL, FALSE);

	sup_iface = self->priv->supplicant.iface;

	if (sup_iface == NULL)
		return FALSE;

	state = nm_supplicant_interface_get_state (sup_iface);
	if (state == NM_SUPPLICANT_INTERFACE_STATE_READY)
		return TRUE;

	return FALSE;
}


void
nm_device_802_11_wireless_reset_scan_interval (NMDevice80211Wireless *self)
{
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (self);

	g_return_if_fail (NM_IS_DEVICE_802_11_WIRELESS (self));

	priv->scan_interval = SCAN_INTERVAL_MIN;

	if (priv->pending_scan_id)
		schedule_scan (self);
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
	NMSock *sk;
	int mode = IW_MODE_AUTO;
	const char *iface;
	struct iwreq wrq;

	g_return_val_if_fail (self != NULL, -1);

	iface = nm_device_get_iface (NM_DEVICE (self));
	sk = nm_dev_sock_open (iface, DEV_WIRELESS, __FUNCTION__, NULL);
	if (!sk)
		goto out;

	memset (&wrq, 0, sizeof (struct iwreq));

	nm_ioctl_info ("%s: About to GET IWMODE.", iface);
	if (iw_get_ext (nm_dev_sock_get_fd (sk), iface, SIOCGIWMODE, &wrq) == 0) {
		if ((wrq.u.mode == IW_MODE_ADHOC) || (wrq.u.mode == IW_MODE_INFRA))
			mode = wrq.u.mode;
	} else {
		if (errno != ENODEV)
			nm_warning ("error getting card mode on %s: %s", iface, strerror (errno));
	}
	nm_dev_sock_close (sk);

out:
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
	NMSock *sk;
	const char *iface;
	gboolean success = FALSE;
	struct iwreq wrq;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail ((mode == IW_MODE_INFRA) || (mode == IW_MODE_ADHOC) || (mode == IW_MODE_AUTO), FALSE);

	if (nm_device_802_11_wireless_get_mode (self) == mode)
		return TRUE;

	iface = nm_device_get_iface (NM_DEVICE (self));

	sk = nm_dev_sock_open (iface, DEV_WIRELESS, __FUNCTION__, NULL);
	if (!sk)
		goto out;

	nm_ioctl_info ("%s: About to SET IWMODE.", iface);

	memset (&wrq, 0, sizeof (struct iwreq));
	wrq.u.mode = mode;

	if (iw_set_ext (nm_dev_sock_get_fd (sk), iface, SIOCSIWMODE, &wrq) == 0)
		success = TRUE;
	else {
		if (errno != ENODEV) {
			nm_warning ("error setting card %s to mode %d: %s",
			            iface, mode, strerror (errno));
		}
	}
	nm_dev_sock_close (sk);

out:
	return success;
}


/*
 * nm_device_802_11_wireless_get_frequency
 *
 * Get current frequency
 *
 */
static guint32
nm_device_802_11_wireless_get_frequency (NMDevice80211Wireless *self)
{
	NMSock *sk;
	int err;
	guint32 freq = 0;
	const char *iface;
	struct iwreq wrq;

	g_return_val_if_fail (self != NULL, 0);

	iface = nm_device_get_iface (NM_DEVICE (self));
	sk = nm_dev_sock_open (iface, DEV_WIRELESS, __FUNCTION__, NULL);
	if (!sk)
		return 0;

	memset (&wrq, 0, sizeof (struct iwreq));

	nm_ioctl_info ("%s: About to GET IWFREQ.", iface);
	err = iw_get_ext (nm_dev_sock_get_fd (sk), iface, SIOCGIWFREQ, &wrq);
	if (err >= 0)
		freq = iw_freq_to_uint32 (&wrq.u.freq);
	else if (err == -1)
		nm_warning ("(%s) error getting frequency: %s", iface, strerror (errno));

	nm_dev_sock_close (sk);
	return freq;
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
 * nm_device_802_11_wireless_get_ssid
 *
 * If a device is wireless, return the ssid that it is attempting
 * to use.
 */
const GByteArray *
nm_device_802_11_wireless_get_ssid (NMDevice80211Wireless *self)
{
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (self);
	const char * iface;
	int	sk;
	struct iwreq wrq;
	char ssid[IW_ESSID_MAX_SIZE + 1];
	guint32 len;

	g_return_val_if_fail (self != NULL, NULL);	

	iface = nm_device_get_iface (NM_DEVICE (self));
	sk = socket (AF_INET, SOCK_DGRAM, 0);
	if (!sk) {
		nm_error ("Couldn't create socket: %d.", errno);
		return NULL;
	}

	memset (ssid, 0, sizeof (ssid));
	wrq.u.essid.pointer = (caddr_t) &ssid;
	wrq.u.essid.length = sizeof (ssid);
	wrq.u.essid.flags = 0;
	if (iw_get_ext (sk, iface, SIOCGIWESSID, &wrq) < 0) {
		nm_warning ("Couldn't get SSID: %d", errno);
		goto out;
    }

	if (priv->ssid) {
		g_byte_array_free (priv->ssid, TRUE);
		priv->ssid = NULL;
	}

	len = wrq.u.essid.length;
	if (!nm_utils_is_empty_ssid ((guint8 *) ssid, len)) {
		/* Some drivers include nul termination in the SSID, so let's
		 * remove it here before further processing. WE-21 changes this
		 * to explicitly require the length _not_ to include nul
		 * termination. */
		if (len > 0 && ssid[len - 1] == '\0' && priv->we_version < 21)
			len--;

		priv->ssid = g_byte_array_sized_new (len);
		g_byte_array_append (priv->ssid, (const guint8 *) ssid, len);
	}

out:
	close (sk);
	return self->priv->ssid;
}


/*
 * nm_device_802_11_wireless_set_ssid
 *
 * If a device is wireless, set the SSID that it should use.
 */
void
nm_device_802_11_wireless_set_ssid (NMDevice80211Wireless *self,
                                    const GByteArray * ssid)
{
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (self);
	int sk;
	struct iwreq wrq;
	const char * iface;
	const char * driver;
	guint32 len = 0;
	char buf[IW_ESSID_MAX_SIZE + 1];

	g_return_if_fail (self != NULL);

	sk = socket (AF_INET, SOCK_DGRAM, 0);
	if (!sk) {
		nm_error ("Couldn't create socket: %d.", errno);
		return;
	}

	iface = nm_device_get_iface (NM_DEVICE (self));

	memset (buf, 0, sizeof (buf));
	if (ssid) {
		len = ssid->len;
		memcpy (buf, ssid->data, MIN (sizeof (buf) - 1, len));
	}
 	wrq.u.essid.pointer = (caddr_t) buf;

	if (priv->we_version < 21) {
		/* For historic reasons, set SSID length to include one extra
		 * character, C string nul termination, even though SSID is
		 * really an octet string that should not be presented as a C
		 * string. Some Linux drivers decrement the length by one and
		 * can thus end up missing the last octet of the SSID if the
		 * length is not incremented here. WE-21 changes this to
		 * explicitly require the length _not_ to include nul
		 * termination. */
		if (len)
			len++;
	}
	wrq.u.essid.length = len;
	wrq.u.essid.flags = (len > 0) ? 1 : 0; /* 1=enable SSID, 0=disable/any */

	if (iw_get_ext (sk, iface, SIOCSIWESSID, &wrq) < 0) {
		if (errno != ENODEV) {
			nm_warning ("error setting SSID to '%s' for device %s: %s",
			            ssid ? nm_utils_escape_ssid (ssid->data, ssid->len) : "(null)",
			            iface, strerror (errno));
		}
    }

	/* Orinoco cards seem to need extra time here to not screw
	 * up the firmware, which reboots when you set the SSID.
	 * Unfortunately, there's no way to know when the card is back up
	 * again.  Sigh...
	 */
	driver = nm_device_get_driver (NM_DEVICE (self));
	if (!driver || !strcmp (driver, "orinoco"))
		sleep (2);

	close (sk);
}


/*
 * nm_device_802_11_wireless_get_bitrate
 *
 * For wireless devices, get the bitrate to broadcast/receive at.
 * Returned value is rate in b/s.
 *
 */
static guint32
nm_device_802_11_wireless_get_bitrate (NMDevice80211Wireless *self)
{
	NMSock *sk;
	int err = -1;
	struct iwreq wrq;
	const char *iface;

	g_return_val_if_fail (self != NULL, 0);

	iface = nm_device_get_iface (NM_DEVICE (self));
	sk = nm_dev_sock_open (iface, DEV_WIRELESS, __func__, NULL);
	if (!sk)
		return 0;

	nm_ioctl_info ("%s: About to GET IWRATE.", iface);
	memset (&wrq, 0, sizeof (wrq));
	err = iw_get_ext (nm_dev_sock_get_fd (sk), iface, SIOCGIWRATE, &wrq);
	nm_dev_sock_close (sk);

	return ((err >= 0) ? wrq.u.bitrate.value : 0);
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
	sk = nm_dev_sock_open (iface, DEV_WIRELESS, __func__, NULL);
	if (!sk) {
		g_warning ("%s: failed to open device socket.", __func__);
		return;
	}

	nm_ioctl_info ("%s: About to GET IWAP.", iface);
	memset (&wrq, 0, sizeof (wrq));
	if (iw_get_ext (nm_dev_sock_get_fd (sk), iface, SIOCGIWAP, &wrq) >= 0)
		memcpy (bssid->ether_addr_octet, &(wrq.u.ap_addr.sa_data), ETH_ALEN);

	nm_dev_sock_close (sk);
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

	if ((sk = nm_dev_sock_open (iface, DEV_WIRELESS, __FUNCTION__, NULL)))
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

static gboolean
can_scan (NMDevice80211Wireless *self)
{
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (self);
	guint32 state;
	gboolean scan = FALSE;

	state = nm_supplicant_interface_get_connection_state (priv->supplicant.iface);

	if (priv->num_freqs >= 14) {
		/* A/B/G cards should only scan if they are disconnected. */
		if (state == NM_SUPPLICANT_INTERFACE_CON_STATE_DISCONNECTED ||
			state == NM_SUPPLICANT_INTERFACE_CON_STATE_INACTIVE)
			scan = TRUE;
	} else if (state == NM_SUPPLICANT_INTERFACE_CON_STATE_DISCONNECTED ||
			   state == NM_SUPPLICANT_INTERFACE_CON_STATE_INACTIVE ||
			   state == NM_SUPPLICANT_INTERFACE_CON_STATE_COMPLETED)
		scan = TRUE;

	return scan;
}

static void
supplicant_iface_scan_result_cb (NMSupplicantInterface * iface,
								 gboolean result,
								 NMDevice80211Wireless * self)
{
	if (can_scan (self))
		schedule_scan (self);
}

static gboolean
request_wireless_scan (gpointer user_data)
{
	NMDevice80211Wireless *self = NM_DEVICE_802_11_WIRELESS (user_data);
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (self);
	gboolean success = TRUE;

	if (can_scan (self)) {
//		nm_debug ("Starting wireless scan for device %s.",
//				  nm_device_get_iface (NM_DEVICE (user_data)));

		success = nm_supplicant_interface_request_scan (priv->supplicant.iface);
		if (success)
			priv->pending_scan_id = 0;
	}

	return !success;
}


/*
 * schedule_scan
 *
 * Schedule a wireless scan.
 *
 */
static void
schedule_scan (NMDevice80211Wireless *self)
{
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (self);
	GTimeVal current_time;

	g_get_current_time (&current_time);

	/* Cancel the pending scan only if it would happen later than what is scheduled right now */
	if (priv->pending_scan_id && (current_time.tv_sec + priv->scan_interval < priv->scheduled_scan_time.tv_sec))
		cancel_pending_scan (self);

	if (!priv->pending_scan_id)
		priv->pending_scan_id = g_timeout_add (priv->scan_interval * 1000,
											   request_wireless_scan,
											   self);

	priv->scheduled_scan_time.tv_sec = current_time.tv_sec + priv->scan_interval;
	if (priv->scan_interval < SCAN_INTERVAL_MAX)
		priv->scan_interval += SCAN_INTERVAL_STEP;
}


static void
cancel_pending_scan (NMDevice80211Wireless *self)
{
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (self);

	if (priv->pending_scan_id) {
		g_source_remove (priv->pending_scan_id);
		priv->pending_scan_id = 0;
	}
}


#if 0
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
	const char *	iface;

	iface = nm_device_get_iface (NM_DEVICE (self));

	if ((sk = nm_dev_sock_open (iface, DEV_WIRELESS, __FUNCTION__, NULL)) == NULL)
		return FALSE;

	/* Some cards, for example ipw2x00 cards, can short-circuit the MAC
	 * address check using this check on IWNAME.  Its faster.
	 */
	memset (&wrq, 0, sizeof (struct iwreq));
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
#endif

static gboolean
is_encrypted (guint32 flags, guint32 wpa_flags, guint32 rsn_flags)
{
	if (flags & NM_802_11_AP_FLAGS_PRIVACY)
		return TRUE;
	if (wpa_flags & (NM_802_11_AP_SEC_KEY_MGMT_PSK | NM_802_11_AP_SEC_KEY_MGMT_802_1X))
		return TRUE;
	if (rsn_flags & (NM_802_11_AP_SEC_KEY_MGMT_PSK | NM_802_11_AP_SEC_KEY_MGMT_802_1X))
		return TRUE;

	return FALSE;
}

/*
 * ap_auth_enforced
 *
 * Checks whether or not there is an encryption key present for
 * this connection, and whether or not the authentication method
 * in use will result in an authentication rejection if the key
 * is wrong.  For example, Ad Hoc mode networks don't have a
 * master node and therefore nothing exists to reject the station.
 * Similarly, Open System WEP access points don't reject a station
 * when the key is wrong.  Shared Key WEP access points will.
 *
 */
static gboolean
ap_auth_enforced (NMConnection *connection,
                  NMAccessPoint *ap,
                  gboolean *encrypted)
{
	guint32 flags, wpa_flags, rsn_flags;
	gboolean enforced = FALSE;

	g_return_val_if_fail (NM_IS_AP (ap), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);
	g_return_val_if_fail (encrypted != NULL, FALSE);

	flags = nm_ap_get_flags (ap);
	wpa_flags = nm_ap_get_wpa_flags (ap);
	rsn_flags = nm_ap_get_rsn_flags (ap);

	if (nm_ap_get_mode (ap) == IW_MODE_ADHOC)
		goto out;

	/* Static WEP */
	if (   (flags & NM_802_11_AP_FLAGS_PRIVACY)
        && (wpa_flags == NM_802_11_AP_SEC_NONE)
        && (rsn_flags == NM_802_11_AP_SEC_NONE)) {
		NMSettingWirelessSecurity *s_wireless_sec;

		/* No way to tell if the key is wrong with Open System
		 * auth mode in WEP.  Auth is not enforced like Shared Key.
		 */
		s_wireless_sec = (NMSettingWirelessSecurity *) nm_connection_get_setting (connection, 
																    NM_TYPE_SETTING_WIRELESS_SECURITY);
		if (s_wireless_sec &&
		    (!s_wireless_sec->auth_alg ||
		     !strcmp (s_wireless_sec->auth_alg, "open")))
			goto out;

		enforced = TRUE;
	} else if (wpa_flags != NM_802_11_AP_SEC_NONE) { /* WPA */
		enforced = TRUE;
	} else if (rsn_flags != NM_802_11_AP_SEC_NONE) { /* WPA2 */
		enforced = TRUE;
	}

out:
	*encrypted = is_encrypted (flags, wpa_flags, rsn_flags);
	return enforced;
}


/****************************************************************************
 * WPA Supplicant control stuff
 *
 */

/*
 * merge_scanned_ap
 *
 * If there is already an entry that matches the BSSID and ESSID of the
 * AP to merge, replace that entry with the scanned AP.  Otherwise, add
 * the scanned AP to the list.
 *
 * TODO: possibly need to differentiate entries based on security too; i.e. if
 * there are two scan results with the same BSSID and SSID but different
 * security options?
 *
 */
static void
merge_scanned_ap (NMDevice80211Wireless *self,
				  NMAccessPoint *merge_ap)
{
	NMAccessPoint * found_ap = NULL;
	const GByteArray *ssid;

	/* Let the manager try to fill in the SSID from seen-bssids lists
	 * if it can
	 */
	ssid = nm_ap_get_ssid (merge_ap);
	if (!ssid || nm_utils_is_empty_ssid (ssid->data, ssid->len)) {
		g_signal_emit (self, signals[HIDDEN_AP_FOUND], 0, merge_ap);
		nm_ap_set_broadcast (merge_ap, FALSE);
	}

	found_ap = nm_ap_match_in_list (merge_ap, self->priv->ap_list, TRUE);
	if (found_ap) {
		nm_ap_set_flags (found_ap, nm_ap_get_flags (merge_ap));
		nm_ap_set_wpa_flags (found_ap, nm_ap_get_wpa_flags (merge_ap));
		nm_ap_set_rsn_flags (found_ap, nm_ap_get_rsn_flags (merge_ap));
		nm_ap_set_strength (found_ap, nm_ap_get_strength (merge_ap));
		nm_ap_set_last_seen (found_ap, nm_ap_get_last_seen (merge_ap));
		nm_ap_set_broadcast (found_ap, nm_ap_get_broadcast (merge_ap));
		nm_ap_set_freq (found_ap, nm_ap_get_freq (merge_ap));

		/* If the AP is noticed in a scan, it's automatically no longer
		 * fake, since it clearly exists somewhere.
		 */
		nm_ap_set_fake (found_ap, FALSE);
	} else {
		/* New entry in the list */
		// FIXME: figure out if reference counts are correct here for AP objects
		g_object_ref (merge_ap);
		self->priv->ap_list = g_slist_append (self->priv->ap_list, merge_ap);
		nm_ap_export_to_dbus (merge_ap);
		g_signal_emit (self, signals[ACCESS_POINT_ADDED], 0, merge_ap);
	}
}

static void
cull_scan_list (NMDevice80211Wireless * self)
{
	GTimeVal        cur_time;
	GSList *        outdated_list = NULL;
	GSList *        elt;
	NMActRequest *  req;
	const char *    cur_ap_path = NULL;

	g_return_if_fail (self != NULL);

	g_get_current_time (&cur_time);

	req = nm_device_get_act_request (NM_DEVICE (self));
	if (req)
		cur_ap_path = nm_act_request_get_specific_object (req);

	/* Walk the access point list and remove any access points older than
	 * three times the inactive scan interval.
	 */
	for (elt = self->priv->ap_list; elt; elt = g_slist_next (elt)) {
		NMAccessPoint * ap = NM_AP (elt->data);
		const glong     ap_time = nm_ap_get_last_seen (ap);
		gboolean        keep = FALSE;
		const guint     prune_interval_s = SCAN_INTERVAL_MAX * 3;

		/* Don't ever prune the AP we're currently associated with */
		if (cur_ap_path && !strcmp (cur_ap_path, nm_ap_get_dbus_path (ap)))
			keep = TRUE;
		if (nm_ap_get_fake (ap))
			keep = TRUE;

		if (!keep && (ap_time + prune_interval_s < cur_time.tv_sec))
			outdated_list = g_slist_append (outdated_list, ap);
	}

	/* Remove outdated APs */
	for (elt = outdated_list; elt; elt = g_slist_next (elt)) {
		NMAccessPoint * outdated_ap = NM_AP (elt->data);

		access_point_removed (self, outdated_ap);
		self->priv->ap_list = g_slist_remove (self->priv->ap_list, outdated_ap);
		g_object_unref (outdated_ap);
	}
	g_slist_free (outdated_list);
}

#define SET_QUALITY_MEMBER(qual_item, lc_member, uc_member) \
	if (lc_member != -1) { \
		qual_item.lc_member = lc_member; \
		qual_item.updated |= IW_QUAL_##uc_member##_UPDATED; \
	} else { \
		qual_item.updated |= IW_QUAL_##uc_member##_INVALID; \
	}

static void
set_ap_strength_from_properties (NMDevice80211Wireless *self,
								 NMAccessPoint *ap,
								 GHashTable *properties)
{
	int qual, level, noise;
	struct iw_quality quality;
	GValue *value;

	value = (GValue *) g_hash_table_lookup (properties, "quality");
	qual = value ? g_value_get_int (value) : -1;

	value = (GValue *) g_hash_table_lookup (properties, "level");
	level = value ? g_value_get_int (value) : -1;

	value = (GValue *) g_hash_table_lookup (properties, "noise");
	noise = value ? g_value_get_int (value) : -1;

	/* Calculate and set the AP's signal quality */
	memset (&quality, 0, sizeof (struct iw_quality));
	SET_QUALITY_MEMBER (quality, qual, QUAL);
	SET_QUALITY_MEMBER (quality, level, LEVEL);
	SET_QUALITY_MEMBER (quality, noise, NOISE);

	nm_ap_set_strength (ap, wireless_qual_to_percent
						(&quality,
						 (const iwqual *)(&self->priv->max_qual),
						 (const iwqual *)(&self->priv->avg_qual)));
}

static void
supplicant_iface_scanned_ap_cb (NMSupplicantInterface * iface,
								GHashTable *properties,
                                NMDevice80211Wireless * self)
{
	NMAccessPoint *ap;

	g_return_if_fail (self != NULL);
	g_return_if_fail (properties != NULL);
	g_return_if_fail (iface != NULL);

	ap = nm_ap_new_from_properties (properties);
	if (!ap)
		return;

	set_ap_strength_from_properties (self, ap, properties);

	/* Add the AP to the device's AP list */
	merge_scanned_ap (self, ap);

	/* Remove outdated access points */
	cull_scan_list (self);

	g_object_unref (ap);
}


static void
remove_supplicant_interface_connection_error_handler (NMDevice80211Wireless * self)
{
	g_return_if_fail (self != NULL);

	if (self->priv->supplicant.iface_error_id != 0) {
		g_signal_handler_disconnect (self->priv->supplicant.iface,
		                             self->priv->supplicant.iface_error_id);
		self->priv->supplicant.iface_error_id = 0;
	}
}

static void
cleanup_association_attempt (NMDevice80211Wireless * self, gboolean disconnect)
{
	g_return_if_fail (self != NULL);

	remove_supplicant_interface_connection_error_handler (self);
	remove_supplicant_timeouts (self);
	if (disconnect && self->priv->supplicant.iface)
		nm_supplicant_interface_disconnect (self->priv->supplicant.iface);
}


static void
remove_link_timeout (NMDevice80211Wireless *self)
{
	g_return_if_fail (self != NULL);

	if (self->priv->link_timeout_id) {
		g_source_remove (self->priv->link_timeout_id);
		self->priv->link_timeout_id = 0;
	}
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
	NMDevice *              dev = NM_DEVICE (user_data);
	NMDevice80211Wireless * self = NM_DEVICE_802_11_WIRELESS (user_data);	
	NMActRequest *          req = NULL;
	NMAccessPoint *         ap = NULL;
	NMConnection *          connection;
	const char *            setting_name;
	gboolean                auth_enforced, encrypted = FALSE;

	g_assert (dev);

	if (self->priv->link_timeout_id)
		self->priv->link_timeout_id = 0;

	req = nm_device_get_act_request (dev);
	ap = nm_device_802_11_wireless_get_activation_ap (self);
	if (req == NULL || ap == NULL) {
		nm_warning ("couldn't get activation request or activation AP.");
		nm_device_set_active_link (dev, FALSE);
		if (nm_device_is_activating (dev)) {
			cleanup_association_attempt (self, TRUE);
			nm_device_state_changed (dev, NM_DEVICE_STATE_FAILED);
		}
		return FALSE;
	}

	/* Disconnect event during initial authentication and credentials
	 * ARE checked - we are likely to have wrong key.  Ask the user for
	 * another one.
	 */
	if (nm_device_get_state (dev) != NM_DEVICE_STATE_CONFIG)
		goto time_out;

	connection = nm_act_request_get_connection (req);
	if (!connection)
		goto time_out;

	auth_enforced = ap_auth_enforced (connection, ap, &encrypted);
	if (!encrypted || !auth_enforced)
		goto time_out;

	nm_connection_clear_secrets (connection);
	setting_name = nm_connection_need_secrets (connection, NULL);
	if (!setting_name)
		goto time_out;

	/* Association/authentication failed during association, probably have a 
	 * bad encryption key and the authenticating entity (AP, RADIUS server, etc)
	 * denied the association due to bad credentials.
	 */
	nm_info ("Activation (%s/wireless): disconnected during association,"
	         " asking for new key.", nm_device_get_iface (dev));
	cleanup_association_attempt (self, TRUE);
	nm_device_state_changed (dev, NM_DEVICE_STATE_NEED_AUTH);
	nm_act_request_request_connection_secrets (req, setting_name, TRUE);	

	return FALSE;

time_out:
	nm_info ("%s: link timed out.", nm_device_get_iface (dev));
	nm_device_set_active_link (dev, FALSE);
	return FALSE;
}


struct state_cb_data {
	NMDevice80211Wireless * self;
	guint32 new_state;
	guint32 old_state;
};

static gboolean
schedule_state_handler (NMDevice80211Wireless * self,
                        GSourceFunc handler,
                        guint32 new_state,
                        guint32 old_state)
{
	struct state_cb_data * cb_data;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (handler != NULL, FALSE);

	if (new_state == old_state)
		return TRUE;

	cb_data = g_slice_new0 (struct state_cb_data);
	if (cb_data == NULL) {
		nm_warning ("Not enough memory to process supplicant manager state"
		            " change.");
		return FALSE;
	}

	cb_data->self = self;
	cb_data->new_state = new_state;
	cb_data->old_state = old_state;

	g_idle_add (handler, cb_data);

	return TRUE;
}

static gboolean
supplicant_iface_state_cb_handler (gpointer user_data)
{
	struct state_cb_data *  cb_data = (struct state_cb_data *) user_data;
	NMDevice80211Wireless * self;
	guint32                 new_state, old_state;

	g_return_val_if_fail (cb_data != NULL, FALSE);

	self = cb_data->self;
	new_state = cb_data->new_state;
	old_state = cb_data->old_state;

	nm_info ("(%s) supplicant interface is now in state %d (from %d).",
             nm_device_get_iface (NM_DEVICE (self)),
             new_state,
             old_state);

	if (new_state == NM_SUPPLICANT_INTERFACE_STATE_READY) {
		nm_device_802_11_wireless_reset_scan_interval (self);
		schedule_scan (self);
	} else if (new_state == NM_SUPPLICANT_INTERFACE_STATE_DOWN) {
		cancel_pending_scan (self);
		cleanup_association_attempt (self, FALSE);
		cleanup_supplicant_interface (self);
		nm_device_set_active_link (NM_DEVICE (self), FALSE);
	}
	
	g_slice_free (struct state_cb_data, cb_data);
	return FALSE;
}


static void
supplicant_iface_state_cb (NMSupplicantInterface * iface,
                           guint32 new_state,
                           guint32 old_state,
                           NMDevice80211Wireless *self)
{
	g_return_if_fail (self != NULL);

	schedule_state_handler (self,
	                        supplicant_iface_state_cb_handler,
	                        new_state,
	                        old_state);
}


static gboolean
supplicant_iface_connection_state_cb_handler (gpointer user_data)
{
	struct state_cb_data *  cb_data = (struct state_cb_data *) user_data;
	NMDevice80211Wireless * self;
	NMDevice *              dev;
	guint32                 new_state, old_state;

	g_return_val_if_fail (cb_data != NULL, FALSE);

	self = cb_data->self;
	dev = NM_DEVICE (self);
	new_state = cb_data->new_state;
	old_state = cb_data->old_state;

	if (!nm_device_get_act_request (NM_DEVICE (self))) {
		/* The device is not activating or already activated; do nothing. */
		goto out;
	}

	nm_info ("(%s) Supplicant interface state change: %d -> %d",
	         nm_device_get_iface (dev), old_state, new_state);

	if (new_state == NM_SUPPLICANT_INTERFACE_CON_STATE_COMPLETED) {
		remove_supplicant_interface_connection_error_handler (self);
		remove_supplicant_timeouts (self);
		nm_device_set_active_link (dev, TRUE);

		/* If this is the initial association during device activation,
		 * schedule the next activation stage.
		 */
		if (nm_device_get_state (dev) == NM_DEVICE_STATE_CONFIG) {
			NMAccessPoint *ap = nm_device_802_11_wireless_get_activation_ap (self);
			const GByteArray * ssid = nm_ap_get_ssid (ap);

			nm_info ("Activation (%s/wireless) Stage 2 of 5 (Device Configure) "
			         "successful.  Connected to wireless network '%s'.",
			         nm_device_get_iface (dev),
			         ssid ? nm_utils_escape_ssid (ssid->data, ssid->len) : "(none)");
			nm_device_activate_schedule_stage3_ip_config_start (dev);
		}
	} else if (new_state == NM_SUPPLICANT_INTERFACE_CON_STATE_DISCONNECTED) {
		if (nm_device_get_state (dev) == NM_DEVICE_STATE_ACTIVATED || nm_device_is_activating (dev)) {
			/* Start the link timeout so we allow some time for reauthentication */
			if ((self->priv->link_timeout_id == 0) && !self->priv->scanning)
				self->priv->link_timeout_id = g_timeout_add (12000, link_timeout_cb, self);
		} else {
			nm_device_set_active_link (dev, FALSE);
		}
	}

	if (new_state == NM_SUPPLICANT_INTERFACE_CON_STATE_SCANNING) {
		self->priv->scanning = TRUE;
	} else {
		self->priv->scanning = FALSE;
	}

out:
	g_slice_free (struct state_cb_data, cb_data);
	return FALSE;
}


static void
supplicant_iface_connection_state_cb (NMSupplicantInterface * iface,
                                      guint32 new_state,
                                      guint32 old_state,
                                      NMDevice80211Wireless *self)
{
	g_return_if_fail (self != NULL);

	schedule_state_handler (self,
	                        supplicant_iface_connection_state_cb_handler,
	                        new_state,
	                        old_state);
}


static void
cleanup_supplicant_interface (NMDevice80211Wireless * self)
{
	Supplicant * sup;

	g_return_if_fail (self != NULL);

	sup = &self->priv->supplicant;

	if (sup->iface_error_id > 0) {
		g_signal_handler_disconnect (sup->iface, sup->iface_error_id);
		sup->iface_error_id = 0;
	}

	if (sup->iface_state_id > 0) {
		g_signal_handler_disconnect (sup->iface, sup->iface_state_id);
		sup->iface_state_id = 0;
	}

	if (sup->iface_scanned_ap_id > 0) {
		g_signal_handler_disconnect (sup->iface, sup->iface_scanned_ap_id);
		sup->iface_scanned_ap_id = 0;
	}

	if (sup->iface_scan_result_id > 0) {
		g_signal_handler_disconnect (sup->iface, sup->iface_scan_result_id);
		sup->iface_scan_result_id = 0;
	}

	if (sup->iface_con_state_id > 0) {
		g_signal_handler_disconnect (sup->iface, sup->iface_con_state_id);
		sup->iface_con_state_id = 0;
	}

	if (sup->iface) {
		nm_supplicant_manager_release_iface (sup->mgr, sup->iface);
		sup->iface = NULL;
	}
}


static gboolean
supplicant_mgr_state_cb_handler (gpointer user_data)
{
	struct state_cb_data * cb_data = (struct state_cb_data *) user_data;
	NMDevice80211Wireless * self;
	guint32 new_state, old_state;

	g_return_val_if_fail (cb_data != NULL, FALSE);

	self = cb_data->self;
	new_state = cb_data->new_state;
	old_state = cb_data->old_state;

	nm_info ("(%s) supplicant manager is now in state %d (from %d).",
             nm_device_get_iface (NM_DEVICE (self)),
             new_state,
             old_state);

	/* If the supplicant went away, release the supplicant interface */
	if (new_state == NM_SUPPLICANT_MANAGER_STATE_DOWN) {
		if (self->priv->supplicant.iface) {
			NMDevice * dev = NM_DEVICE (self);

			cleanup_association_attempt (self, FALSE);
			cleanup_supplicant_interface (self);

			nm_device_set_active_link (NM_DEVICE (self), FALSE);

			if (nm_device_is_activating (dev)) {
				nm_device_state_changed (dev, NM_DEVICE_STATE_FAILED);
			}
		}
	} else if (new_state == NM_SUPPLICANT_MANAGER_STATE_IDLE) {
		if (!self->priv->supplicant.iface) {
			/* request a supplicant interface from the supplicant manager */
			init_supplicant_interface (self);
		}
	}

	g_slice_free (struct state_cb_data, cb_data);
	return FALSE;
}

static void
supplicant_mgr_state_cb (NMSupplicantInterface * iface,
                         guint32 new_state,
                         guint32 old_state,
                         NMDevice80211Wireless *self)
{
	g_return_if_fail (self != NULL);

	schedule_state_handler (self,
	                        supplicant_mgr_state_cb_handler,
	                        new_state,
	                        old_state);
}

struct iface_con_error_cb_data {
	NMDevice80211Wireless * self;
	char * name;
	char * message;
};


static gboolean
supplicant_iface_connection_error_cb_handler (gpointer user_data)
{
	struct iface_con_error_cb_data * cb_data = (struct iface_con_error_cb_data *) user_data;
	NMDevice80211Wireless *          self;

	g_return_val_if_fail (cb_data != NULL, FALSE);

	self = cb_data->self;

	if (!nm_device_is_activating (NM_DEVICE (self)))
		goto out;

	nm_info ("Activation (%s/wireless): association request to the supplicant "
	         "failed: %s - %s",
	         nm_device_get_iface (NM_DEVICE (self)),
	         cb_data->name,
	         cb_data->message);

	cleanup_association_attempt (self, TRUE);
	nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_FAILED);

out:
	g_free (cb_data->name);
	g_free (cb_data->message);
	g_slice_free (struct iface_con_error_cb_data, cb_data);
	return FALSE;
}


static void
supplicant_iface_connection_error_cb (NMSupplicantInterface * iface,
                                      const char * name,
                                      const char * message,
                                      NMDevice80211Wireless * self)
{
	struct iface_con_error_cb_data * cb_data;
	guint                            id;

	g_return_if_fail (self != NULL);

	cb_data = g_slice_new0 (struct iface_con_error_cb_data);
	if (cb_data == NULL) {
		nm_warning ("Not enough memory to process supplicant connection error.");
		return;
	}

	cb_data->self = self;
	cb_data->name = g_strdup (name);
	cb_data->message = g_strdup (message);

	id = g_idle_add (supplicant_iface_connection_error_cb_handler, cb_data);
}

static void
remove_supplicant_connection_timeout (NMDevice80211Wireless *self)
{
	g_return_if_fail (self != NULL);

	/* Remove any pending timeouts on the request */
	if (self->priv->supplicant.con_timeout_id) {
		g_source_remove (self->priv->supplicant.con_timeout_id);
		self->priv->supplicant.con_timeout_id = 0;
	}
}

/*
 * supplicant_connection_timeout_cb
 *
 * Called when the supplicant has been unable to connect to an access point
 * within a specified period of time.
 */
static gboolean
supplicant_connection_timeout_cb (gpointer user_data)
{
	NMDevice *              dev = NM_DEVICE (user_data);
	NMDevice80211Wireless * self = NM_DEVICE_802_11_WIRELESS (user_data);
	NMAccessPoint *         ap;
	NMActRequest *          req;
	NMConnection *          connection = NULL;
	gboolean                auth_enforced = FALSE, encrypted = FALSE;

	cleanup_association_attempt (self, TRUE);

	if (!nm_device_is_activating (dev))
		return FALSE;

	/* Timed out waiting for authentication success; if the security in use
	 * does not require access point side authentication (Open System
	 * WEP, for example) then we are likely using the wrong authentication
	 * algorithm or key.  Request new one from the user.
	 */

	req = nm_device_get_act_request (dev);
	g_assert (req);

	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	ap = nm_device_802_11_wireless_get_activation_ap (self);
	g_assert (ap);

	auth_enforced = ap_auth_enforced (connection, ap, &encrypted);
	if (!encrypted) {
		nm_info ("Activation (%s/wireless): association took too long, "
		         "failing activation.",
		         nm_device_get_iface (dev));
		nm_device_state_changed (dev, NM_DEVICE_STATE_FAILED);
	} else {
		const char *setting_name;

		/* Authentication failed, encryption key is probably bad */
		nm_info ("Activation (%s/wireless): association took too long, "
		         "asking for new key.",
		         nm_device_get_iface (dev));

		nm_device_state_changed (dev, NM_DEVICE_STATE_NEED_AUTH);

		nm_connection_clear_secrets (connection);
		setting_name = nm_connection_need_secrets (connection, NULL);
		if (setting_name)
			nm_act_request_request_connection_secrets (req, setting_name, TRUE);
	}

	return FALSE;
}


static gboolean
start_supplicant_connection_timeout (NMDevice80211Wireless *self)
{
	NMDevice *     dev;
	guint          id;

	g_return_val_if_fail (self != NULL, FALSE);

	dev = NM_DEVICE (self);

	/* Set up a timeout on the connection attempt to fail it after 25 seconds */
	id = g_timeout_add (25000, supplicant_connection_timeout_cb, self);
	if (id <= 0) {
		nm_warning ("Activation (%s/wireless): couldn't start supplicant "
		            "timeout timer.",
		            nm_device_get_iface (dev));
		return FALSE;
	}
	self->priv->supplicant.con_timeout_id = id;
	return TRUE;
}


static void
remove_supplicant_timeouts (NMDevice80211Wireless *self)
{
	g_return_if_fail (self != NULL);

	remove_supplicant_connection_timeout (self);
	remove_link_timeout (self);
}

static guint32
find_supported_frequency (NMDevice80211Wireless *self, guint32 *freqs)
{
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (self);
	int i;

	for (i = 0; i < priv->num_freqs; i++) {
		while (*freqs) {
			if (priv->freqs[i] == *freqs)
				return *freqs;
			freqs++;
		}
	}

	return 0;
}

static NMSupplicantConfig *
build_supplicant_config (NMDevice80211Wireless *self,
                         NMConnection *connection,
                         NMAccessPoint *ap)
{
	NMSupplicantConfig * config = NULL;
	NMSettingWireless * s_wireless;
	NMSettingWirelessSecurity *s_wireless_sec;
	guint32 adhoc_freq = 0;

	g_return_val_if_fail (self != NULL, NULL);

	s_wireless = (NMSettingWireless *) nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS);
	g_return_val_if_fail (s_wireless != NULL, NULL);

	config = nm_supplicant_config_new ();
	if (!config)
		return NULL;

	/* Figure out the Ad-Hoc frequency to use if creating an adhoc network; if
	 * nothing was specified then pick something usable.
	 */
	if ((nm_ap_get_mode (ap) == IW_MODE_ADHOC) && nm_ap_get_user_created (ap)) {
		adhoc_freq = nm_ap_get_freq (ap);
		if (!adhoc_freq) {
			if (s_wireless->band && !strcmp (s_wireless->band, "a")) {
				guint32 a_freqs[] = {5180, 5200, 5220, 5745, 5765, 5785, 5805, 0};
				adhoc_freq = find_supported_frequency (self, a_freqs);
			} else {
				guint32 bg_freqs[] = {2412, 2437, 2462, 2472, 0};
				adhoc_freq = find_supported_frequency (self, bg_freqs);
			}
		}

		if (!adhoc_freq) {
			if (s_wireless->band && !strcmp (s_wireless->band, "a"))
				adhoc_freq = 5180;
			else
				adhoc_freq = 2462;
		}
	}

	if (!nm_supplicant_config_add_setting_wireless (config,
	                                                s_wireless,
	                                                nm_ap_get_broadcast (ap),
	                                                adhoc_freq)) {
		nm_warning ("Couldn't add 802-11-wireless setting to supplicant config.");
		goto error;
	}

	s_wireless_sec = (NMSettingWirelessSecurity *) nm_connection_get_setting (connection,
															    NM_TYPE_SETTING_WIRELESS_SECURITY);
	if (s_wireless_sec) {
		DBusGProxy *proxy = g_object_get_data (G_OBJECT (connection), NM_MANAGER_CONNECTION_PROXY_TAG);
		const char *con_path = dbus_g_proxy_get_path (proxy);

		if (!nm_supplicant_config_add_setting_wireless_security (config,
	                                                             s_wireless_sec,
	                                                             con_path)) {
			nm_warning ("Couldn't add 802-11-wireless-security setting to "
			            "supplicant config.");
			goto error;
		}
	} else {
		/* Unencrypted, wpa_supplicant needs key_mgmt=NONE here */
		if (!nm_supplicant_config_add_option (config, "key_mgmt", "NONE", -1, FALSE)) {
			nm_warning ("Couldn't add 802-11-wireless (no security) setting to"
			            " supplicant config.");
			goto error;
		}
	}

	return config;

error:
	g_object_unref (config);
	return NULL;
}

/****************************************************************************/

static void
real_set_hw_address (NMDevice *dev)
{
	NMDevice80211Wireless *self = NM_DEVICE_802_11_WIRELESS (dev);
	struct ifreq req;
	NMSock *sk;
	int ret;

	sk = nm_dev_sock_open (nm_device_get_iface (dev), DEV_GENERAL, __FUNCTION__, NULL);
	if (!sk)
		return;

	memset (&req, 0, sizeof (struct ifreq));
	strncpy (req.ifr_name, nm_device_get_iface (dev), sizeof (req.ifr_name) - 1);

	ret = ioctl (nm_dev_sock_get_fd (sk), SIOCGIFHWADDR, &req);
	if (ret)
		goto out;

	if (memcmp (&(self->priv->hw_addr), &(req.ifr_hwaddr.sa_data), sizeof (struct ether_addr)) == 0)
		goto out;

	memcpy (&(self->priv->hw_addr), &(req.ifr_hwaddr.sa_data), sizeof (struct ether_addr));
	g_object_notify (G_OBJECT (dev), NM_DEVICE_802_11_WIRELESS_HW_ADDRESS);

out:
	nm_dev_sock_close (sk);
}


static NMActStageReturn
real_act_stage1_prepare (NMDevice *dev)
{
	NMDevice80211Wireless *self = NM_DEVICE_802_11_WIRELESS (dev);
	NMAccessPoint *ap = NULL;

	/* If the user is trying to connect to an AP that NM doesn't yet know about
	 * (hidden network or something), create an fake AP from the security
	 * settings in the connection to use until the AP is recognized from the
	 * scan list, which should show up when the connection is successful.
	 */
	ap = nm_device_802_11_wireless_get_activation_ap (self);
	if (!ap) {
		NMActRequest *req;
		NMConnection *connection;
		GSList *iter;

		req = nm_device_get_act_request (NM_DEVICE (self));
		g_return_val_if_fail (req != NULL, NM_ACT_STAGE_RETURN_FAILURE);

		connection = nm_act_request_get_connection (req);
		g_return_val_if_fail (connection != NULL, NM_ACT_STAGE_RETURN_FAILURE);

		/* Find a compatible AP in the scan list */
		for (iter = self->priv->ap_list; iter; iter = g_slist_next (iter)) {
			NMAccessPoint *candidate = NM_AP (iter->data);

			if (nm_ap_check_compatible (candidate, connection)) {
				ap = candidate;
				break;
			}
		}

		/* If no compatible AP was found, create a fake AP (network is likely
		 * hidden) and try to use that.
		 */
		if (!ap) {
			ap = nm_ap_new_fake_from_connection (connection);
			g_return_val_if_fail (ap != NULL, NM_ACT_STAGE_RETURN_FAILURE);

			switch (nm_ap_get_mode (ap)) {
				case IW_MODE_ADHOC:
					nm_ap_set_user_created (ap, TRUE);
					break;
				case IW_MODE_INFRA:
				default:
					nm_ap_set_broadcast (ap, FALSE);
					break;
			}

			self->priv->ap_list = g_slist_append (self->priv->ap_list, ap);
			nm_ap_export_to_dbus (ap);
			g_signal_emit (self, signals[ACCESS_POINT_ADDED], 0, ap);
		}

		nm_act_request_set_specific_object (req, nm_ap_get_dbus_path (ap));
	}

	set_current_ap (self, ap);

	return NM_ACT_STAGE_RETURN_SUCCESS;
}


static void
real_connection_secrets_updated (NMDevice *dev,
                                 NMConnection *connection,
                                 const char *setting_name)
{
	NMActRequest *req;

	if (nm_device_get_state (dev) != NM_DEVICE_STATE_NEED_AUTH)
		return;

	if (strcmp (setting_name, NM_SETTING_WIRELESS_SECURITY_SETTING_NAME) != 0) {
		nm_warning ("Ignoring updated secrets for setting '%s'.", setting_name);
		return;
	}

	req = nm_device_get_act_request (dev);
	g_assert (req);

	g_return_if_fail (nm_act_request_get_connection (req) == connection);

	nm_device_activate_schedule_stage1_device_prepare (dev);
}

#define WIRELESS_SECRETS_TRIES "wireless-secrets-tries"

static NMActStageReturn
real_act_stage2_config (NMDevice *dev)
{
	NMDevice80211Wireless * self = NM_DEVICE_802_11_WIRELESS (dev);
	NMActStageReturn        ret = NM_ACT_STAGE_RETURN_FAILURE;
	const char *            iface = nm_device_get_iface (dev);
	NMSupplicantConfig *	config = NULL;
	gulong                  id = 0;
	NMActRequest *          req;
	NMAccessPoint *         ap;
	NMConnection *          connection;
	NMSettingConnection *	s_connection;
	const char *			setting_name;

	remove_supplicant_timeouts (self);

	req = nm_device_get_act_request (dev);
	g_assert (req);

	ap = nm_device_802_11_wireless_get_activation_ap (self);
	g_assert (ap);

	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	s_connection = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
	g_assert (s_connection);

	/* If we need secrets, get them */
	setting_name = nm_connection_need_secrets (connection, NULL);
	if (setting_name) {
		guint32 tries;

		nm_info ("Activation (%s/wireless): access point '%s' has security,"
		         " but secrets are required.",
		         iface, s_connection->id);

		nm_device_state_changed (dev, NM_DEVICE_STATE_NEED_AUTH);

		/* Request new secrets if the connection failed to even associate */
		tries = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (connection), WIRELESS_SECRETS_TRIES));
		if (tries > 4) {
			/* Make the user try again explicitly */
			nm_ap_set_invalid (ap, TRUE);
			return NM_ACT_STAGE_RETURN_FAILURE;
		}

		nm_act_request_request_connection_secrets (req, setting_name, tries ? TRUE : FALSE);
		g_object_set_data (G_OBJECT (connection), WIRELESS_SECRETS_TRIES, GUINT_TO_POINTER (++tries));
		return NM_ACT_STAGE_RETURN_POSTPONE;
	} else {
		NMSettingWireless *s_wireless = (NMSettingWireless *) nm_connection_get_setting (connection, 
																		 NM_TYPE_SETTING_WIRELESS);

		if (s_wireless->security) {
			nm_info ("Activation (%s/wireless): connection '%s' has security"
			         ", and secrets exist.  No new secrets needed.",
			         iface, s_connection->id);
		} else {
			nm_info ("Activation (%s/wireless): connection '%s' requires no "
			         "security.  No secrets needed.",
			         iface, s_connection->id);
		}
	}

	config = build_supplicant_config (self, connection, ap);
	if (config == NULL) {
		nm_warning ("Activation (%s/wireless): couldn't build wireless "
			"configuration.", iface);
		goto out;
	}

	/* Hook up error signal handler to capture association errors */
	id = g_signal_connect (self->priv->supplicant.iface,
	                       "connection-error",
	                       G_CALLBACK (supplicant_iface_connection_error_cb),
	                       self);
	self->priv->supplicant.iface_error_id = id;

	if (!nm_supplicant_interface_set_config (self->priv->supplicant.iface, config)) {
		nm_warning ("Activation (%s/wireless): couldn't send wireless "
			"configuration to the supplicant.", iface);
		goto out;
	}

	if (!start_supplicant_connection_timeout (self))
		goto out;

	/* We'll get stage3 started when the supplicant connects */
	ret = NM_ACT_STAGE_RETURN_POSTPONE;

out:
	if (ret == NM_ACT_STAGE_RETURN_FAILURE) {
		cleanup_association_attempt (self, TRUE);
	}

	if (config) {
		/* Supplicant interface object refs the config; we no longer care about
		 * it after this function.
		 */
		g_object_unref (config);
	}
	return ret;
}


static NMActStageReturn
real_act_stage3_ip_config_start (NMDevice *dev)
{
	NMDevice80211Wireless *	self = NM_DEVICE_802_11_WIRELESS (dev);
	NMAccessPoint *		ap;
	NMActStageReturn		ret = NM_ACT_STAGE_RETURN_FAILURE;
	NMActRequest *          req;
	NMConnection *          connection;

	ap = nm_device_802_11_wireless_get_activation_ap (self);
	g_assert (ap);

	req = nm_device_get_act_request (dev);
	g_assert (req);

	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	/* Clear wireless secrets tries once a successful association happens */
	g_object_set_data (G_OBJECT (connection), WIRELESS_SECRETS_TRIES, NULL);

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
		ret = parent_class->act_stage3_ip_config_start (dev);
	}
	else
		ret = NM_ACT_STAGE_RETURN_SUCCESS;

	return ret;
}


static NMActStageReturn
real_act_stage4_get_ip4_config (NMDevice *dev,
                                NMIP4Config **config)
{
	NMDevice80211Wireless *	self = NM_DEVICE_802_11_WIRELESS (dev);
	NMAccessPoint *		ap = nm_device_802_11_wireless_get_activation_ap (self);
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
		ret = parent_class->act_stage4_get_ip4_config (dev, &real_config);
	}
	*config = real_config;

	return ret;
}


static NMActStageReturn
real_act_stage4_ip_config_timeout (NMDevice *dev,
                                   NMIP4Config **config)
{
	NMDevice80211Wireless *	self = NM_DEVICE_802_11_WIRELESS (dev);
	NMAccessPoint *		ap = nm_device_802_11_wireless_get_activation_ap (self);
	NMActStageReturn		ret = NM_ACT_STAGE_RETURN_FAILURE;
	NMIP4Config *			real_config = NULL;
	NMActRequest *          req = nm_device_get_act_request (dev);
	NMConnection *          connection;
	gboolean                auth_enforced = FALSE, encrypted = FALSE;

	g_return_val_if_fail (config != NULL, NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (*config == NULL, NM_ACT_STAGE_RETURN_FAILURE);

	g_assert (ap);

	/* If nothing checks the security authentication information (as in
	 * Open System WEP for example), and DHCP times out, then
	 * the encryption key is likely wrong.  Ask the user for a new one.
	 * Otherwise the failure likely happened after a successful authentication.
	 */
	connection = nm_act_request_get_connection (req);
	auth_enforced = ap_auth_enforced (connection, ap, &encrypted);
	if (encrypted && !auth_enforced) {
		const GByteArray * ssid = nm_ap_get_ssid (ap);
		const char *setting_name;

		/* Activation failed, we must have bad encryption key */
		nm_debug ("Activation (%s/wireless): could not get IP configuration "
		          "info for '%s', asking for new key.",
		          nm_device_get_iface (dev),
		          ssid ? nm_utils_escape_ssid (ssid->data, ssid->len) : "(none)");
		nm_device_state_changed (dev, NM_DEVICE_STATE_NEED_AUTH);

		nm_connection_clear_secrets (connection);
		setting_name = nm_connection_need_secrets (connection, NULL);
		if (setting_name)
			nm_act_request_request_connection_secrets (req, setting_name, TRUE);

		ret = NM_ACT_STAGE_RETURN_POSTPONE;
	} else if (nm_ap_get_mode (ap) == IW_MODE_ADHOC) {
		NMDevice80211WirelessClass *	klass;
		NMDeviceClass * parent_class;

		/* For Ad-Hoc networks, chain up to parent to get a Zeroconf IP */
		klass = NM_DEVICE_802_11_WIRELESS_GET_CLASS (self);
		parent_class = NM_DEVICE_CLASS (g_type_class_peek_parent (klass));
		ret = parent_class->act_stage4_ip_config_timeout (dev, &real_config);
	} else {
		/* Non-encrypted network or authentication is enforced by some
		 * entity (AP, RADIUS server, etc), but IP configure failed.  Alert
		 * the user.
		 */
		ret = NM_ACT_STAGE_RETURN_FAILURE;
	}

	*config = real_config;

	return ret;
}


static void
activation_success_handler (NMDevice *dev)
{
	NMDevice80211Wireless *self = NM_DEVICE_802_11_WIRELESS (dev);
	NMAccessPoint *ap;
	struct ether_addr bssid = { {0x0, 0x0, 0x0, 0x0, 0x0, 0x0} };
	NMAccessPoint *tmp_ap;

	ap = nm_device_802_11_wireless_get_activation_ap (self);

	/* If the activate AP was fake, it probably won't have a BSSID at all.
	 * But if activation was successful, the card will know the BSSID.  Grab
	 * the BSSID off the card and fill in the BSSID of the activation AP.
	 */
	if (!nm_ap_get_fake (ap))
		goto done;

	nm_device_802_11_wireless_get_bssid (self, &bssid);
	if (!nm_ethernet_address_is_valid (nm_ap_get_address (ap)))
		nm_ap_set_address (ap, &bssid);

	tmp_ap = get_active_ap (self, ap);
	if (tmp_ap) {
		NMActRequest *req = nm_device_get_act_request (NM_DEVICE (self));

		/* Found a better match in the scan list than the fake AP.  Use it
		 * instead.
		 */
		nm_act_request_set_specific_object (req, nm_ap_get_dbus_path (tmp_ap));

		self->priv->ap_list = g_slist_remove (self->priv->ap_list, ap);
		g_object_unref (ap);
		ap = tmp_ap;
	}

done:
	periodic_update (self, FALSE);
}


static void
activation_failure_handler (NMDevice *dev)
{
	NMDevice80211Wireless *	self = NM_DEVICE_802_11_WIRELESS (dev);
	NMAccessPoint *	ap;
	const GByteArray * ssid;
	NMActRequest *req;
	NMConnection *connection;

	req = nm_device_get_act_request (dev);
	g_assert (req);

	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	/* Clear wireless secrets tries on failure */
	g_object_set_data (G_OBJECT (connection), WIRELESS_SECRETS_TRIES, NULL);

	if ((ap = nm_device_802_11_wireless_get_activation_ap (self))) {
		if (nm_ap_get_fake (ap)) {
			/* Fake APs are ones that don't show up in scans,
			 * but which the user explicitly attempted to connect to.
			 * However, if we fail on one of these, remove it from the
			 * list because we don't have any scan or capability info
			 * for it, and they are pretty much useless.
			 */
			access_point_removed (self, ap);
			self->priv->ap_list = g_slist_remove (self->priv->ap_list, ap);
			g_object_unref (ap);
		} else {
			/* Add the AP to the invalid list */
			nm_ap_set_invalid (ap, TRUE);
		}
	}

	ssid = nm_ap_get_ssid (ap);
	nm_info ("Activation (%s) failed for access point (%s)",
	         nm_device_get_iface (dev),
	         ssid ? nm_utils_escape_ssid (ssid->data, ssid->len) : "(none)");
}

static void
real_activation_cancel_handler (NMDevice *dev)
{
	NMDevice80211Wireless *self = NM_DEVICE_802_11_WIRELESS (dev);
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (self);
	NMDevice80211WirelessClass *klass;
	NMDeviceClass *parent_class;

	/* Chain up to parent first */
	klass = NM_DEVICE_802_11_WIRELESS_GET_CLASS (self);
	parent_class = NM_DEVICE_CLASS (g_type_class_peek_parent (klass));
	parent_class->activation_cancel_handler (dev);

	cleanup_association_attempt (self, TRUE);

	set_current_ap (self, NULL);
	priv->rate = 0;
}


static gboolean
real_can_interrupt_activation (NMDevice *dev)
{
	if (nm_device_get_state (dev) == NM_DEVICE_STATE_NEED_AUTH)
		return TRUE;

	return FALSE;
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
	NMDevice80211Wireless *self = NM_DEVICE_802_11_WIRELESS (object);
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (self);

	if (priv->dispose_has_run) {
		G_OBJECT_CLASS (nm_device_802_11_wireless_parent_class)->dispose (object);
		return;
	}

	priv->dispose_has_run = TRUE;

	/* General cleanup, free references to other objects */
	g_slist_foreach (self->priv->ap_list, (GFunc) g_object_unref, NULL);
	g_slist_free (self->priv->ap_list);
	self->priv->ap_list = NULL;

	device_cleanup (self);

	set_current_ap (self, NULL);

	G_OBJECT_CLASS (nm_device_802_11_wireless_parent_class)->dispose (object);
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	NMDevice80211Wireless *device = NM_DEVICE_802_11_WIRELESS (object);
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (device);
	struct ether_addr hw_addr;
	char hw_addr_buf[20];

	switch (prop_id) {
	case PROP_HW_ADDRESS:
		memset (hw_addr_buf, 0, 20);
		nm_device_802_11_wireless_get_address (device, &hw_addr);
		iw_ether_ntop (&hw_addr, hw_addr_buf);
		g_value_set_string (value, &hw_addr_buf[0]);
		break;
	case PROP_MODE:
		g_value_set_int (value, nm_device_802_11_wireless_get_mode (device));
		break;
	case PROP_BITRATE:
		g_value_set_uint (value, priv->rate);
		break;
	case PROP_CAPABILITIES:
		g_value_set_uint (value, priv->capabilities);
		break;
	case PROP_ACTIVE_ACCESS_POINT:
		if (priv->current_ap)
			g_value_set_boxed (value, nm_ap_get_dbus_path (priv->current_ap));
		else
			g_value_set_boxed (value, "/");
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_device_802_11_wireless_class_init (NMDevice80211WirelessClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *parent_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMDevice80211WirelessPrivate));

	object_class->constructor = constructor;
	object_class->get_property = get_property;
	object_class->dispose = nm_device_802_11_wireless_dispose;

	parent_class->get_type_capabilities = real_get_type_capabilities;
	parent_class->get_generic_capabilities = real_get_generic_capabilities;
	parent_class->is_up = real_is_up;
	parent_class->bring_up = real_bring_up;
	parent_class->bring_down = real_bring_down;
	parent_class->update_link = real_update_link;
	parent_class->set_hw_address = real_set_hw_address;
	parent_class->get_best_connection = real_get_best_connection;
	parent_class->connection_secrets_updated = real_connection_secrets_updated;
	parent_class->check_connection_conflicts = real_check_connection_conflicts;

	parent_class->act_stage1_prepare = real_act_stage1_prepare;
	parent_class->act_stage2_config = real_act_stage2_config;
	parent_class->act_stage3_ip_config_start = real_act_stage3_ip_config_start;
	parent_class->act_stage4_get_ip4_config = real_act_stage4_get_ip4_config;
	parent_class->act_stage4_ip_config_timeout = real_act_stage4_ip_config_timeout;
	parent_class->deactivate = real_deactivate;
	parent_class->deactivate_quickly = real_deactivate_quickly;
	parent_class->can_interrupt_activation = real_can_interrupt_activation;

	parent_class->activation_cancel_handler = real_activation_cancel_handler;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_802_11_WIRELESS_HW_ADDRESS,
							  "MAC Address",
							  "Hardware MAC address",
							  NULL,
							  G_PARAM_READABLE));
	g_object_class_install_property
		(object_class, PROP_MODE,
		 g_param_spec_int (NM_DEVICE_802_11_WIRELESS_MODE,
						   "Mode",
						   "Mode",
						   0, G_MAXINT32, 0,
						   G_PARAM_READABLE));
	g_object_class_install_property
		(object_class, PROP_BITRATE,
		 g_param_spec_uint (NM_DEVICE_802_11_WIRELESS_BITRATE,
						   "Bitrate",
						   "Bitrate",
						   0, G_MAXUINT32, 0,
						   G_PARAM_READABLE));
	g_object_class_install_property
		(object_class, PROP_ACTIVE_ACCESS_POINT,
		 g_param_spec_boxed (NM_DEVICE_802_11_WIRELESS_ACTIVE_ACCESS_POINT,
							  "Active access point",
							  "Currently active access point",
							  DBUS_TYPE_G_OBJECT_PATH,
							  G_PARAM_READABLE));
	g_object_class_install_property
		(object_class, PROP_CAPABILITIES,
		 g_param_spec_uint (NM_DEVICE_802_11_WIRELESS_CAPABILITIES,
							"Wireless Capabilities",
							"Wireless Capabilities",
							0, G_MAXUINT32, NM_802_11_DEVICE_CAP_NONE,
							G_PARAM_READABLE));

	/* Signals */
	signals[ACCESS_POINT_ADDED] =
		g_signal_new ("access-point-added",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMDevice80211WirelessClass, access_point_added),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__OBJECT,
					  G_TYPE_NONE, 1,
					  G_TYPE_OBJECT);

	signals[ACCESS_POINT_REMOVED] =
		g_signal_new ("access-point-removed",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMDevice80211WirelessClass, access_point_removed),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__OBJECT,
					  G_TYPE_NONE, 1,
					  G_TYPE_OBJECT);

	signals[HIDDEN_AP_FOUND] =
		g_signal_new ("hidden-ap-found",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMDevice80211WirelessClass, hidden_ap_found),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__OBJECT,
					  G_TYPE_NONE, 1,
					  G_TYPE_OBJECT);

	signals[PROPERTIES_CHANGED] =
		nm_properties_changed_signal_new (object_class,
								    G_STRUCT_OFFSET (NMDevice80211WirelessClass, properties_changed));

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (klass),
									 &dbus_glib_nm_device_802_11_wireless_object_info);
}


static void
state_changed_cb (NMDevice *device, NMDeviceState state, gpointer user_data)
{
	switch (state) {
	case NM_DEVICE_STATE_ACTIVATED:
		activation_success_handler (device);
		break;
	case NM_DEVICE_STATE_FAILED:
		activation_failure_handler (device);
		break;
	case NM_DEVICE_STATE_DISCONNECTED:
		// FIXME: ensure that the activation request is destroyed
		break;
	default:
		break;
	}
}


NMDevice80211Wireless *
nm_device_802_11_wireless_new (const char *udi,
						 const char *iface,
						 const char *driver)
{
	GObject *obj;

	g_return_val_if_fail (udi != NULL, NULL);
	g_return_val_if_fail (iface != NULL, NULL);
	g_return_val_if_fail (driver != NULL, NULL);

	obj = g_object_new (NM_TYPE_DEVICE_802_11_WIRELESS,
					NM_DEVICE_INTERFACE_UDI, udi,
					NM_DEVICE_INTERFACE_IFACE, iface,
					NM_DEVICE_INTERFACE_DRIVER, driver,
					NULL);
	if (obj == NULL)
		return NULL;

	g_signal_connect (obj, "state-changed",
				   G_CALLBACK (state_changed_cb),
				   NULL);

	return NM_DEVICE_802_11_WIRELESS (obj);
}

NMAccessPoint *
nm_device_802_11_wireless_get_activation_ap (NMDevice80211Wireless *self)
{
	NMActRequest *req;
	const char *ap_path;

	g_return_val_if_fail (NM_IS_DEVICE_802_11_WIRELESS (self), NULL);

	req = nm_device_get_act_request (NM_DEVICE (self));
	if (!req)
		return NULL;

	ap_path = nm_act_request_get_specific_object (req);
	if (!ap_path)
		return NULL;

	return nm_device_802_11_wireless_ap_list_get_ap_by_obj_path (self, ap_path);
}

