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

static gboolean impl_device_get_active_networks (NMDevice80211Wireless *device,
												 GPtrArray **networks,
												 GError **err);

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
	PROP_ACTIVE_NETWORK,
	PROP_CAPABILITIES,

	LAST_PROP
};

enum {
	NETWORK_ADDED,
	NETWORK_REMOVED,

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
	double			freqs[IW_MAX_FREQUENCIES];

	gboolean			scanning;
	GSList *        ap_list;
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


static void
network_added (NMDevice80211Wireless *device, NMAccessPoint *ap)
{
	g_signal_emit (device, signals[NETWORK_ADDED], 0, ap);
}

static void
network_removed (NMDevice80211Wireless *device, NMAccessPoint *ap)
{
	g_signal_emit (device, signals[NETWORK_REMOVED], 0, ap);
}

/*
 * nm_device_802_11_wireless_update_bssid
 *
 * Update the current wireless network's BSSID, presumably in response to
 * roaming.
 *
 */
static void
nm_device_802_11_wireless_update_bssid (NMDevice80211Wireless *self,
										NMAccessPoint *ap)
{
	struct ether_addr		new_bssid;
	const struct ether_addr	*old_bssid;
	const GByteArray *		new_ssid;
	const GByteArray *		old_ssid;

	/* Get the current BSSID.  If it is valid but does not match the stored value,
	 * and the SSID is the same as what we think its supposed to be, update it. */
	nm_device_802_11_wireless_get_bssid (self, &new_bssid);
	old_bssid = nm_ap_get_address (ap);
	new_ssid = nm_device_802_11_wireless_get_ssid (self);
	old_ssid = nm_ap_get_ssid (ap);
	if (     nm_ethernet_address_is_valid (&new_bssid)
		&&  nm_ethernet_address_is_valid (old_bssid)
		&& !nm_ethernet_addresses_are_equal (&new_bssid, old_bssid)
		&& nm_utils_same_ssid (old_ssid, new_ssid, TRUE))
	{
		gboolean	automatic;
		gchar	new_addr[20];
		gchar	old_addr[20];

		memset (new_addr, '\0', sizeof (new_addr));
		memset (old_addr, '\0', sizeof (old_addr));
		iw_ether_ntop (&new_bssid, new_addr);
		iw_ether_ntop (old_bssid, old_addr);
		nm_debug ("Roamed from BSSID %s to %s on wireless network '%s'",
		          old_addr,
		          new_addr,
		          nm_utils_escape_ssid (old_ssid->data, old_ssid->len));

		nm_ap_set_address (ap, &new_bssid);

		automatic = !nm_act_request_get_user_requested (nm_device_get_act_request (NM_DEVICE (self)));
		// FIXME: push new BSSID to the info-daemon
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
		    && !(caps & (NM_802_11_DEVICE_CAP_CIPHER_TKIP | NM_802_11_DEVICE_CAP_CIPHER_CCMP)))
			nm_warning ("%s: device supports WPA protocol but not WPA ciphers; "
			            "WPA unavailable.", iface);
			caps &= ~WPA_CAPS;
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

static GObject*
constructor (GType type,
			 guint n_construct_params,
			 GObjectConstructParam *construct_params)
{
	GObject *object;
	NMDevice80211Wireless *self;
	NMDevice80211WirelessPrivate *priv;
	const char *iface;
	NMSock *sk;

	object = G_OBJECT_CLASS (nm_device_802_11_wireless_parent_class)->constructor (type,
																				   n_construct_params,
																				   construct_params);
	if (!object)
		return NULL;

	self = NM_DEVICE_802_11_WIRELESS (object);
	priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (self);

	iface = nm_device_get_iface (NM_DEVICE (self));

	if ((sk = nm_dev_sock_open (iface, DEV_WIRELESS, __FUNCTION__, NULL))) {
		struct iw_range range;
		struct iwreq wrq;

		memset (&wrq, 0, sizeof (struct iwreq));
		memset (&range, 0, sizeof (struct iw_range));
		strncpy (wrq.ifr_name, iface, IFNAMSIZ);
		wrq.u.data.pointer = (caddr_t) &range;
		wrq.u.data.length = sizeof (struct iw_range);

		if (ioctl (nm_dev_sock_get_fd (sk), SIOCGIWRANGE, &wrq) >= 0)
		{
			int i;

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
				priv->freqs[i] = iw_freq2float (&(range.freq[i]));

			priv->we_version = range.we_version_compiled;

			/* 802.11 wireless-specific capabilities */
			priv->capabilities = get_wireless_capabilities (self, &range, wrq.u.data.length);
		}
		nm_dev_sock_close (sk);
	}

	return object;
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

	/* BSSID and signal strength have meaningful values only if the device
	   is activated and not scanning */
	if (nm_device_get_state (NM_DEVICE (self)) == NM_DEVICE_STATE_ACTIVATED &&
		!NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (self)->scanning) {
		NMAccessPoint *ap = nm_device_802_11_wireless_get_activation_ap (self);

		nm_device_802_11_wireless_update_signal_strength (self, ap);
		nm_device_802_11_wireless_update_bssid (self, ap);
	}

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

	cleanup_association_attempt (self, TRUE);

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
real_check_connection (NMDevice *dev, NMConnection *connection)
{
	return TRUE;
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

	s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_SETTING_CONNECTION);
	if (s_con == NULL)
		return;
	if (strcmp (s_con->type, NM_SETTING_WIRELESS))
		return;
	if (!s_con->autoconnect)
		return;

	s_wireless = (NMSettingWireless *) nm_connection_get_setting (connection, NM_SETTING_WIRELESS);
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
                          char **specific_object)
{
	NMDevice80211Wireless * self = NM_DEVICE_802_11_WIRELESS (dev);
	NMManager *manager = nm_manager_get ();
	GSList *connections = NULL;
	BestConnectionInfo find_info;

	/* System connections first */
	connections = nm_manager_get_connections (manager, NM_CONNECTION_TYPE_SYSTEM);
	memset (&find_info, 0, sizeof (BestConnectionInfo));
	find_info.self = self;
	g_slist_foreach (connections, find_best_connection, &find_info);
	g_slist_free (connections);

	/* Then user connections */
	if (!find_info.found) {
		connections = nm_manager_get_connections (manager, NM_CONNECTION_TYPE_USER);
		find_info.self = self;
		g_slist_foreach (connections, find_best_connection, &find_info);
		g_slist_free (connections);
	}

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

#if 0
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
		const GByteArray * dev_ssid = nm_device_802_11_wireless_get_ssid (self);
		const GByteArray * ap_ssid = nm_ap_get_ssid (ap);

		if (dev_ssid && ap_ssid && nm_utils_same_ssid (dev_ssid, ap_ssid, TRUE)) {
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

	blacklisted = nm_ap_has_manufacturer_default_ssid (ap);
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

	g_return_val_if_fail (self != NULL, NULL);

	if (!(ap_list = nm_device_802_11_wireless_ap_list_get (self)))
		return NULL;

	/* We prefer the currently selected access point if its user-chosen or if there
	 * is still a hardware link to it.
	 */
	if ((req = nm_device_get_act_request (NM_DEVICE (self)))) {
		if ((cur_ap = nm_device_802_11_wireless_get_activation_ap (self))) {
			const GByteArray * ssid = nm_ap_get_ssid (cur_ap);
			gboolean		keep = FALSE;

			if (nm_ap_get_user_created (cur_ap))
				keep = TRUE;
			else if (nm_act_request_get_user_requested (req))
				keep = TRUE;
			else if (link_to_specific_ap (self, cur_ap, TRUE))
				keep = TRUE;

			/* Only keep if its not in the invalid list and its _is_ in our scanned list */
			if ( keep
				&& !nm_ap_get_invalid (cur_ap)
				&& nm_device_802_11_wireless_ap_list_get_ap_by_ssid (self, ssid))
			{
				return (NMAccessPoint *) g_object_ref (cur_ap);
			}
		}
	}

	if (!(iter = nm_ap_list_iter_new (ap_list)))
		return NULL;
	while ((scan_ap = nm_ap_list_iter_next (iter))) {
		NMAccessPoint *tmp_ap;
		const GByteArray * ap_ssid = nm_ap_get_ssid (scan_ap);

		/* Access points in the "invalid" list cannot be used */
		if (nm_ap_get_invalid (scan_ap))
			continue;

		// FIXME: match up an NMConnection with some NMAccessPoint for the
		// best_ap
#if 0
		if ((tmp_ap = nm_ap_list_get_ap_by_ssid (app_data->allowed_ap_list, ap_ssid)))
		{
			const GTimeVal *	curtime = nm_ap_get_timestamp (tmp_ap);
			gboolean			blacklisted;
			GSList *			user_addrs;

			/* Only connect to a blacklisted AP if the user has connected to this specific AP before */
			user_addrs = nm_ap_get_user_addresses (tmp_ap);
			blacklisted = get_ap_blacklisted (scan_ap, user_addrs);
			g_slist_foreach (user_addrs, (GFunc) g_free, NULL);
			g_slist_free (user_addrs);

			if (!blacklisted && (curtime->tv_sec > best_timestamp.tv_sec)) {
				best_timestamp = *nm_ap_get_timestamp (tmp_ap);
				best_ap = scan_ap;
			}
		}
#endif
	}
	nm_ap_list_iter_free (iter);

	if (best_ap)
		g_object_ref (best_ap);

	return best_ap;
}
#endif

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
impl_device_get_active_networks (NMDevice80211Wireless *self,
								 GPtrArray **networks,
								 GError **err)
{
	GSList *elt;

	*networks = g_ptr_array_new ();

	for (elt = self->priv->ap_list; elt; elt = g_slist_next (elt)) {
		NMAccessPoint * ap = NM_AP (elt->data);

		if (nm_ap_get_ssid (ap))
			g_ptr_array_add (*networks, g_strdup (nm_ap_get_dbus_path (ap)));
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
	NMSock *	sk;
	int		mode = IW_MODE_AUTO;
	const char *iface;

	g_return_val_if_fail (self != NULL, -1);

	iface = nm_device_get_iface (NM_DEVICE (self));

	/* Force the card into Managed/Infrastructure mode */
	if ((sk = nm_dev_sock_open (iface, DEV_WIRELESS, __FUNCTION__, NULL)))
	{
		struct iwreq	wrq;

		memset (&wrq, 0, sizeof (struct iwreq));

		nm_ioctl_info ("%s: About to GET IWMODE.", iface);

		if (iw_get_ext (nm_dev_sock_get_fd (sk), nm_device_get_iface (NM_DEVICE (self)), SIOCGIWMODE, &wrq) == 0)
		{
			if ((mode == IW_MODE_ADHOC) || (mode == IW_MODE_INFRA))
				mode = wrq.u.mode;
		}
		else
		{
			nm_warning ("error getting card mode on %s: %s", iface, strerror (errno));
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
	const char *iface;
	gboolean	success = FALSE;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail ((mode == IW_MODE_INFRA) || (mode == IW_MODE_ADHOC) || (mode == IW_MODE_AUTO), FALSE);

	if (nm_device_802_11_wireless_get_mode (self) == mode)
		return TRUE;

	iface = nm_device_get_iface (NM_DEVICE (self));

	/* Force the card into Managed/Infrastructure mode */
	if ((sk = nm_dev_sock_open (iface, DEV_WIRELESS, __FUNCTION__, NULL)))
	{
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
	if (!nm_utils_is_empty_ssid (ssid, len)) {
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
			            nm_utils_escape_ssid (ssid->data, ssid->len),
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
	if ((sk = nm_dev_sock_open (iface, DEV_WIRELESS, __FUNCTION__, NULL)))
	{
		nm_ioctl_info ("%s: About to GET IWRATE.", iface);
		err = iw_get_ext (nm_dev_sock_get_fd (sk), iface, SIOCGIWRATE, &wrq);
		nm_dev_sock_close (sk);
	}

	return ((err >= 0) ? wrq.u.bitrate.value / 1000000 : 0);
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
	if ((sk = nm_dev_sock_open (iface, DEV_WIRELESS, __FUNCTION__, NULL)))
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
ap_auth_enforced (NMConnection *connection, NMAccessPoint *ap)
{
	guint32 flags, wpa_flags, rsn_flags;

	g_return_val_if_fail (NM_IS_AP (ap), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	if (nm_ap_get_mode (ap) == IW_MODE_ADHOC)
		return FALSE;

	flags = nm_ap_get_flags (ap);
	wpa_flags = nm_ap_get_wpa_flags (ap);
	rsn_flags = nm_ap_get_rsn_flags (ap);

	/* Static WEP */
	if (   (flags & NM_802_11_AP_FLAGS_PRIVACY)
        && (wpa_flags == NM_802_11_AP_SEC_NONE)
        && (rsn_flags == NM_802_11_AP_SEC_NONE)) {
		NMSettingWirelessSecurity *s_wireless_sec;

		/* No way to tell if the key is wrong with Open System
		 * auth mode in WEP.  Auth is not enforced like Shared Key.
		 */
		s_wireless_sec = (NMSettingWirelessSecurity *) nm_connection_get_setting (connection, NM_SETTING_WIRELESS_SECURITY);
		if (s_wireless_sec &&
		    (!s_wireless_sec->auth_alg ||
		     !strcmp (s_wireless_sec->auth_alg, "open")))
			return FALSE;

		return TRUE;
	}

	/* WPA */
	if (wpa_flags != NM_802_11_AP_SEC_NONE)
		return TRUE;

	/* WPA2 */
	if (rsn_flags != NM_802_11_AP_SEC_NONE)
		return TRUE;

	/* No encryption */
	return FALSE;
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
	GSList * elt;
	NMAccessPoint * found_ap = NULL;

	for (elt = self->priv->ap_list; elt; elt = g_slist_next (elt)) {
		NMAccessPoint * list_ap = NM_AP (elt->data);
		const GByteArray * list_ssid = nm_ap_get_ssid (list_ap);
		const struct ether_addr * list_addr = nm_ap_get_address (list_ap);
		int list_mode = nm_ap_get_mode (list_ap);
		double list_freq = nm_ap_get_freq (list_ap);

		const GByteArray * merge_ssid = nm_ap_get_ssid (merge_ap);
		const struct ether_addr * merge_addr = nm_ap_get_address (merge_ap);
		int merge_mode = nm_ap_get_mode (merge_ap);
		double merge_freq = nm_ap_get_freq (merge_ap);

		/* SSID match */
		if (   !list_ssid
		    || !merge_ssid
		    || !nm_utils_same_ssid (list_ssid, merge_ssid, TRUE))
			continue;

		/* BSSID match */
		if (   nm_ethernet_address_is_valid (list_addr)
		    && memcmp (list_addr->ether_addr_octet, 
		               merge_addr->ether_addr_octet,
		               ETH_ALEN) != 0) {
			continue;
		}

		/* mode match */
		if (list_mode != merge_mode)
			continue;

		/* Frequency match */
		if ((int) list_freq != (int) merge_freq)
			continue;

		found_ap = list_ap;
		break;
	}

	if (found_ap) {
		nm_ap_set_flags (found_ap, nm_ap_get_flags (merge_ap));
		nm_ap_set_wpa_flags (found_ap, nm_ap_get_wpa_flags (merge_ap));
		nm_ap_set_rsn_flags (found_ap, nm_ap_get_rsn_flags (merge_ap));
		nm_ap_set_strength (found_ap, nm_ap_get_strength (merge_ap));
		nm_ap_set_last_seen (found_ap, nm_ap_get_last_seen (merge_ap));
		nm_ap_set_broadcast (found_ap, nm_ap_get_broadcast (merge_ap));

		/* If the AP is noticed in a scan, it's automatically no longer
		 * artificial, since it clearly exists somewhere.
		 */
		nm_ap_set_artificial (found_ap, FALSE);
	} else {
		/* New entry in the list */
		// FIXME: figure out if reference counts are correct here for AP objects
		g_object_ref (merge_ap);
		self->priv->ap_list = g_slist_append (self->priv->ap_list, merge_ap);
		nm_ap_export_to_dbus (merge_ap);
		network_added (self, merge_ap);
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

		if (!keep && (ap_time + prune_interval_s < cur_time.tv_sec))
			outdated_list = g_slist_append (outdated_list, ap);
	}

	/* Remove outdated APs */
	for (elt = outdated_list; elt; elt = g_slist_next (elt)) {
		NMAccessPoint * outdated_ap = NM_AP (elt->data);

		network_removed (self, outdated_ap);
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

	/* If the AP is not broadcasting its SSID, try to fill it in here from our
	 * allowed list where we cache known MAC->SSID associations.
	 */
	if (!nm_ap_get_ssid (ap)) {
		nm_ap_set_broadcast (ap, FALSE);
// FIXME: get the saved BSSID from NMConnection/NMSettings 
//		nm_ap_list_copy_one_ssid_by_address (ap, app_data->allowed_ap_list);
	}

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
	NMManager *             manager;
	const char *            setting_name;

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

	if (!ap_auth_enforced (connection, ap))
		goto time_out;

	nm_connection_clear_secrets (connection);
	setting_name = nm_connection_need_secrets (connection);
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

	manager = nm_manager_get ();
 	nm_manager_get_connection_secrets (manager,
	                                   NM_DEVICE_INTERFACE (self),
	                                   connection,
	                                   setting_name,
	                                   TRUE);
	g_object_unref (manager);
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
	NMAccessPoint *         ap = nm_device_802_11_wireless_get_activation_ap (self);
	NMActRequest *          req = nm_device_get_act_request (dev);
	NMConnection *          connection = NULL;

	cleanup_association_attempt (self, TRUE);

	/* Timed out waiting for authentication success; if the security in use
	 * does not require access point side authentication (Open System
	 * WEP, for example) then we are likely using the wrong authentication
	 * algorithm or key.  Request new one from the user.
	 */
	if (req)
		connection = nm_act_request_get_connection (req);

	if (!connection || ap_auth_enforced (connection, ap)) {
		if (nm_device_is_activating (dev)) {
			/* Kicked off by the authenticator most likely */
			nm_info ("Activation (%s/wireless): association took too long, "
			         "failing activation.",
			         nm_device_get_iface (dev));

			nm_device_state_changed (dev, NM_DEVICE_STATE_FAILED);
		}
	} else {
		NMManager *manager = nm_manager_get ();

		/* Activation failed, encryption key is probably bad */
		nm_info ("Activation (%s/wireless): association took too long, "
		         "asking for new key.",
		         nm_device_get_iface (dev));

		nm_device_state_changed (dev, NM_DEVICE_STATE_NEED_AUTH);
		nm_manager_get_connection_secrets (manager,
		                                   NM_DEVICE_INTERFACE (self),
		                                   connection,
		                                   NM_SETTING_WIRELESS_SECURITY,
		                                   TRUE);
		g_object_unref (manager);
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

static NMSupplicantConfig *
build_supplicant_config (NMDevice80211Wireless *self,
                         NMConnection *connection,
                         NMAccessPoint *ap)
{
	NMSupplicantConfig * config = NULL;
	NMSettingWireless * s_wireless;
	NMSettingWirelessSecurity *s_wireless_sec;

	g_return_val_if_fail (self != NULL, NULL);

	s_wireless = (NMSettingWireless *) nm_connection_get_setting (connection, "802-11-wireless");
	g_return_val_if_fail (s_wireless != NULL, NULL);

	config = nm_supplicant_config_new ();
	if (!config)
		return NULL;

	if (!nm_supplicant_config_add_setting_wireless (config,
	                                                s_wireless,
	                                                nm_ap_get_broadcast (ap))) {
		nm_warning ("Couldn't add 802-11-wireless setting to supplicant config.");
		goto error;
	}

	s_wireless_sec = (NMSettingWirelessSecurity *) nm_connection_get_setting (connection, "802-11-wireless-security");
	if (s_wireless_sec) {
		if (!nm_supplicant_config_add_setting_wireless_security (config,
	                                                             s_wireless_sec)) {
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
	if (ret == 0)
		memcpy (&(self->priv->hw_addr), &(req.ifr_hwaddr.sa_data), sizeof (struct ether_addr));

	nm_dev_sock_close (sk);
}


static NMActStageReturn
real_act_stage1_prepare (NMDevice *dev)
{
	NMDevice80211Wireless *self = NM_DEVICE_802_11_WIRELESS (dev);
	NMAccessPoint *ap;

	/* Make sure we've got an AP to connect to */
	ap = nm_device_802_11_wireless_get_activation_ap (self);
	if (!ap)
		return NM_ACT_STAGE_RETURN_FAILURE;

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

	if (strcmp (setting_name, NM_SETTING_WIRELESS_SECURITY) != 0) {
		nm_warning ("Ignoring updated secrets for setting '%s'.", setting_name);
		return;
	}

	req = nm_device_get_act_request (dev);
	g_assert (req);

	g_return_if_fail (nm_act_request_get_connection (req) == connection);

	nm_device_activate_schedule_stage1_device_prepare (dev);
}

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

	s_connection = (NMSettingConnection *) nm_connection_get_setting (connection, NM_SETTING_CONNECTION);
	g_assert (s_connection);

	/* If we need secrets, get them */
	setting_name = nm_connection_need_secrets (connection);
	if (setting_name) {
		NMManager * manager = nm_manager_get ();

		nm_info ("Activation (%s/wireless): access point '%s' has security,"
		         " but secrets are required.",
		         iface, s_connection->name);

		nm_device_state_changed (dev, NM_DEVICE_STATE_NEED_AUTH);
		nm_manager_get_connection_secrets (manager,
		                                   NM_DEVICE_INTERFACE (self),
		                                   connection,
		                                   setting_name,
		                                   FALSE);
		return NM_ACT_STAGE_RETURN_POSTPONE;
	} else {
		NMSettingWireless *s_wireless = (NMSettingWireless *) nm_connection_get_setting (connection, NM_SETTING_WIRELESS);

		if (s_wireless->security) {
			nm_info ("Activation (%s/wireless): connection '%s' has security"
			         ", and secrets exist.  No new secrets needed.",
			         iface, s_connection->name);
		} else {
			nm_info ("Activation (%s/wireless): connection '%s' requires no "
			         "security.  No secrets needed.",
			         iface, s_connection->name);
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
	NMAccessPoint *		ap = nm_device_802_11_wireless_get_activation_ap (self);
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

	g_return_val_if_fail (config != NULL, NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (*config == NULL, NM_ACT_STAGE_RETURN_FAILURE);

	g_assert (ap);

	/* If nothing checks the security authentication information (as in
	 * Open System WEP for example), and DHCP times out, then
	 * the encryption key is likely wrong.  Ask the user for a new one.
	 */
	connection = nm_act_request_get_connection (req);
	if (!ap_auth_enforced (connection, ap)) {
		NMManager *manager = nm_manager_get ();
		const GByteArray * ssid = nm_ap_get_ssid (ap);

		/* Activation failed, we must have bad encryption key */
		nm_debug ("Activation (%s/wireless): could not get IP configuration "
		          "info for '%s', asking for new key.",
		          nm_device_get_iface (dev),
		          ssid ? nm_utils_escape_ssid (ssid->data, ssid->len) : "(none)");
		nm_device_state_changed (dev, NM_DEVICE_STATE_NEED_AUTH);
		nm_manager_get_connection_secrets (manager,
		                                   NM_DEVICE_INTERFACE (self),
		                                   connection,
		                                   NM_SETTING_WIRELESS_SECURITY,
		                                   TRUE);
		g_object_unref (manager);
		ret = NM_ACT_STAGE_RETURN_POSTPONE;
	} else if (nm_ap_get_mode (ap) == IW_MODE_ADHOC) {
		NMDevice80211WirelessClass *	klass;
		NMDeviceClass * parent_class;

		/* For Ad-Hoc networks, chain up to parent to get a Zeroconf IP */
		klass = NM_DEVICE_802_11_WIRELESS_GET_CLASS (self);
		parent_class = NM_DEVICE_CLASS (g_type_class_peek_parent (klass));
		ret = parent_class->act_stage4_ip_config_timeout (dev, &real_config);
	} else {
		/* Non-encrypted network and IP configure failed.  Alert the user. */
		ret = NM_ACT_STAGE_RETURN_FAILURE;
	}

	*config = real_config;

	return ret;
}


static void
activation_success_handler (NMDevice *dev)
{
	NMDevice80211Wireless *	self = NM_DEVICE_802_11_WIRELESS (dev);
	struct ether_addr	addr;
	NMAccessPoint *	ap;
	gboolean			automatic;

	ap = nm_device_802_11_wireless_get_activation_ap (self);

	/* Cache details in the info-daemon since the connect was successful */
	automatic = !nm_act_request_get_user_requested (nm_device_get_act_request (dev));

	/* If it's a user-created ad-hoc network, add it to the device's scan list */
	if (!automatic && (nm_ap_get_mode (ap) == IW_MODE_ADHOC) && nm_ap_get_user_created (ap)) {
		if (!ap_list_get_ap_by_ssid (self->priv->ap_list, nm_ap_get_ssid (ap)))
			self->priv->ap_list = g_slist_append (self->priv->ap_list, ap);
	}

	nm_device_802_11_wireless_get_bssid (self, &addr);
	if (!nm_ap_get_address (ap) || !nm_ethernet_address_is_valid (nm_ap_get_address (ap)))
		nm_ap_set_address (ap, &addr);

	nm_device_802_11_wireless_update_signal_strength (self, ap);

	// FIXME: send connection + new BSSID to info-daemon
}


static void
activation_failure_handler (NMDevice *dev)
{
	NMDevice80211Wireless *	self = NM_DEVICE_802_11_WIRELESS (dev);
	NMAccessPoint *	ap;
	const GByteArray * ssid;

	if ((ap = nm_device_802_11_wireless_get_activation_ap (self))) {
		if (nm_ap_get_artificial (ap)) {
			/* Artificial APs are ones that don't show up in scans,
			 * but which the user explicitly attempted to connect to.
			 * However, if we fail on one of these, remove it from the
			 * list because we don't have any scan or capability info
			 * for it, and they are pretty much useless.
			 */
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
	NMDevice80211Wireless *		self = NM_DEVICE_802_11_WIRELESS (dev);
	NMDevice80211WirelessClass *	klass;
	NMDeviceClass * 			parent_class;

	/* Chain up to parent first */
	klass = NM_DEVICE_802_11_WIRELESS_GET_CLASS (self);
	parent_class = NM_DEVICE_CLASS (g_type_class_peek_parent (klass));
	parent_class->activation_cancel_handler (dev);

	cleanup_association_attempt (self, TRUE);
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

	/* Make sure dispose does not run twice. */
	if (priv->dispose_has_run)
		return;

	priv->dispose_has_run = TRUE;

	/* General cleanup, free references to other objects */
	g_slist_foreach (self->priv->ap_list, (GFunc) g_object_unref, NULL);
	g_slist_free (self->priv->ap_list);
	self->priv->ap_list = NULL;

	device_cleanup (self);

	G_OBJECT_CLASS (nm_device_802_11_wireless_parent_class)->dispose (object);
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	NMDevice80211Wireless *device = NM_DEVICE_802_11_WIRELESS (object);
	NMDevice80211WirelessPrivate *priv = NM_DEVICE_802_11_WIRELESS_GET_PRIVATE (device);
	NMAccessPoint *ap;
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
		g_value_set_int (value, nm_device_802_11_wireless_get_bitrate (device));
		break;
	case PROP_CAPABILITIES:
		g_value_set_uint (value, priv->capabilities);
		break;
	case PROP_ACTIVE_NETWORK:
		if ((ap = nm_device_802_11_wireless_get_activation_ap (device)))
			g_value_set_object (value, ap);
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
	parent_class->check_connection = real_check_connection;
	parent_class->get_best_connection = real_get_best_connection;
	parent_class->connection_secrets_updated = real_connection_secrets_updated;

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
		 g_param_spec_int (NM_DEVICE_802_11_WIRELESS_BITRATE,
						   "Bitrate",
						   "Bitrate",
						   0, G_MAXINT32, 0,
						   G_PARAM_READABLE));
	g_object_class_install_property
		(object_class, PROP_ACTIVE_NETWORK,
		 g_param_spec_object (NM_DEVICE_802_11_WIRELESS_ACTIVE_NETWORK,
							  "Active network",
							  "Currently active network",
							  G_TYPE_OBJECT,
							  G_PARAM_READABLE));
	g_object_class_install_property
		(object_class, PROP_CAPABILITIES,
		 g_param_spec_uint (NM_DEVICE_802_11_WIRELESS_CAPABILITIES,
							"Wireless Capabilities",
							"Wireless Capabilities",
							0, G_MAXUINT32, NM_802_11_DEVICE_CAP_NONE,
							G_PARAM_READABLE));

	/* Signals */
	signals[NETWORK_ADDED] =
		g_signal_new ("network-added",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMDevice80211WirelessClass, network_added),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__OBJECT,
					  G_TYPE_NONE, 1,
					  G_TYPE_OBJECT);

	signals[NETWORK_REMOVED] =
		g_signal_new ("network-removed",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMDevice80211WirelessClass, network_removed),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__OBJECT,
					  G_TYPE_NONE, 1,
					  G_TYPE_OBJECT);

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
nm_device_802_11_wireless_new (int idx,
							   const char *udi,
							   const char *driver,
							   gboolean test_dev)
{
	GObject *obj;

	g_return_val_if_fail (idx >= 0, NULL);
	g_return_val_if_fail (udi != NULL, NULL);
	g_return_val_if_fail (driver != NULL, NULL);

	obj = g_object_new (NM_TYPE_DEVICE_802_11_WIRELESS,
						NM_DEVICE_INTERFACE_UDI, udi,
						NM_DEVICE_INTERFACE_INDEX, idx,
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

