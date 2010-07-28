/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2005 - 2010 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
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
#include <linux/sockios.h>
#include <linux/ethtool.h>
#include <sys/ioctl.h>

#include "nm-glib-compat.h"
#include "nm-device.h"
#include "nm-device-wifi.h"
#include "nm-device-interface.h"
#include "nm-device-private.h"
#include "nm-utils.h"
#include "nm-logging.h"
#include "nm-marshal.h"
#include "NetworkManagerUtils.h"
#include "nm-activation-request.h"
#include "nm-supplicant-manager.h"
#include "nm-supplicant-interface.h"
#include "nm-supplicant-config.h"
#include "nm-properties-changed-signal.h"
#include "nm-setting-connection.h"
#include "nm-setting-wireless.h"
#include "nm-setting-wireless-security.h"
#include "nm-setting-8021x.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-ip6-config.h"
#include "nm-system.h"

static gboolean impl_device_get_access_points (NMDeviceWifi *device,
                                               GPtrArray **aps,
                                               GError **err);

#include "nm-device-wifi-glue.h"


/* All of these are in seconds */
#define SCAN_INTERVAL_MIN 0
#define SCAN_INTERVAL_STEP 20
#define SCAN_INTERVAL_MAX 120

#define WIRELESS_SECRETS_TRIES "wireless-secrets-tries"

static void device_interface_init (NMDeviceInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (NMDeviceWifi, nm_device_wifi, NM_TYPE_DEVICE, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_DEVICE_INTERFACE, device_interface_init))

#define NM_DEVICE_WIFI_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_WIFI, NMDeviceWifiPrivate))


enum {
	PROP_0,
	PROP_HW_ADDRESS,
	PROP_PERM_HW_ADDRESS,
	PROP_MODE,
	PROP_BITRATE,
	PROP_ACTIVE_ACCESS_POINT,
	PROP_CAPABILITIES,
	PROP_SCANNING,
	PROP_IPW_RFKILL_STATE,

	LAST_PROP
};

enum {
	ACCESS_POINT_ADDED,
	ACCESS_POINT_REMOVED,
	HIDDEN_AP_FOUND,
	PROPERTIES_CHANGED,
	SCANNING_ALLOWED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef enum {
	NM_WIFI_ERROR_CONNECTION_NOT_WIRELESS = 0,
	NM_WIFI_ERROR_CONNECTION_INVALID,
	NM_WIFI_ERROR_CONNECTION_INCOMPATIBLE,
} NMWifiError;

#define NM_WIFI_ERROR (nm_wifi_error_quark ())
#define NM_TYPE_WIFI_ERROR (nm_wifi_error_get_type ()) 

typedef struct SupplicantStateTask {
	NMDeviceWifi *self;
	guint32 new_state;
	guint32 old_state;
	gboolean mgr_task;
	guint source_id;
} SupplicantStateTask;

typedef struct Supplicant {
	NMSupplicantManager *mgr;
	NMSupplicantInterface *iface;

	/* signal handler ids */
	guint mgr_state_id;
	guint iface_error_id;
	guint iface_state_id;
	guint iface_scanned_ap_id;
	guint iface_scan_request_result_id;
	guint iface_scan_results_id;
	guint iface_con_state_id;
	guint iface_notify_scanning_id;

	/* Timeouts and idles */
	guint iface_con_error_cb_id;
	guint con_timeout_id;

	GSList *mgr_tasks;
	GSList *iface_tasks;
} Supplicant;

struct _NMDeviceWifiPrivate {
	gboolean          disposed;

	guint8            hw_addr[ETH_ALEN];      /* Currently set MAC address */
	guint8            perm_hw_addr[ETH_ALEN]; /* Permanent MAC address */

	/* Legacy rfkill for ipw2x00; will be fixed with 2.6.33 kernel */
	char *            ipw_rfkill_path;
	guint             ipw_rfkill_id;
	RfKillState       ipw_rfkill_state;

	GByteArray *      ssid;
	gint8             invalid_strength_counter;
	iwqual            max_qual;

	gint8             num_freqs;
	guint32           freqs[IW_MAX_FREQUENCIES];

	GSList *          ap_list;
	NMAccessPoint *   current_ap;
	guint32           rate;
	gboolean          enabled; /* rfkilled or not */
	
	glong             scheduled_scan_time;
	guint8            scan_interval; /* seconds */
	guint             pending_scan_id;

	Supplicant        supplicant;

	guint32           failed_link_count;
	guint             periodic_source_id;
	guint             link_timeout_id;

	/* Static options from driver */
	guint8            we_version;
	guint32           capabilities;
	gboolean          has_scan_capa_ssid;
};

static guint32 nm_device_wifi_get_frequency (NMDeviceWifi *self);

static gboolean request_wireless_scan (gpointer user_data);

static void schedule_scan (NMDeviceWifi *self, gboolean backoff);

static void cancel_pending_scan (NMDeviceWifi *self);

static int wireless_qual_to_percent (const struct iw_quality *qual,
                                     const struct iw_quality *max_qual);

static void cleanup_association_attempt (NMDeviceWifi * self,
                                         gboolean disconnect);

static void remove_supplicant_timeouts (NMDeviceWifi *self);

static void supplicant_iface_state_cb (NMSupplicantInterface * iface,
                                       guint32 new_state,
                                       guint32 old_state,
                                       NMDeviceWifi *self);

static void supplicant_iface_connection_state_cb (NMSupplicantInterface * iface,
                                                  guint32 new_state,
                                                  guint32 old_state,
                                                  NMDeviceWifi *self);

static void supplicant_iface_scanned_ap_cb (NMSupplicantInterface * iface,
                                            GHashTable *properties,
                                            NMDeviceWifi * self);

static void supplicant_iface_scan_request_result_cb (NMSupplicantInterface * iface,
                                                     gboolean success,
                                                     NMDeviceWifi * self);

static void supplicant_iface_scan_results_cb (NMSupplicantInterface * iface,
                                              guint32 num_bssids,
                                              NMDeviceWifi * self);

static void supplicant_mgr_state_cb (NMSupplicantInterface * iface,
                                     guint32 new_state,
                                     guint32 old_state,
                                     NMDeviceWifi *self);

static void supplicant_iface_notify_scanning_cb (NMSupplicantInterface * iface,
                                                 GParamSpec * pspec,
                                                 NMDeviceWifi * self);

static guint32 nm_device_wifi_get_bitrate (NMDeviceWifi *self);

static void cull_scan_list (NMDeviceWifi *self);

static GQuark
nm_wifi_error_quark (void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string ("nm-wifi-error");
	return quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

static GType
nm_wifi_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Connection was not a wireless connection. */
			ENUM_ENTRY (NM_WIFI_ERROR_CONNECTION_NOT_WIRELESS, "ConnectionNotWireless"),
			/* Connection was not a valid wireless connection. */
			ENUM_ENTRY (NM_WIFI_ERROR_CONNECTION_INVALID, "ConnectionInvalid"),
			/* Connection does not apply to this device. */
			ENUM_ENTRY (NM_WIFI_ERROR_CONNECTION_INCOMPATIBLE, "ConnectionIncompatible"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("NMWifiError", values);
	}
	return etype;
}

/* IPW rfkill handling (until 2.6.33) */
RfKillState
nm_device_wifi_get_ipw_rfkill_state (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	char *contents = NULL;
	RfKillState state = RFKILL_UNBLOCKED;
	const char *str_state = NULL;

	if (   priv->ipw_rfkill_path
	    && g_file_get_contents (priv->ipw_rfkill_path, &contents, NULL, NULL)) {
		contents = g_strstrip (contents);

		/* 0 - RF kill not enabled
		 * 1 - SW based RF kill active (sysfs)
		 * 2 - HW based RF kill active
		 * 3 - Both HW and SW baed RF kill active
		 */
		switch (contents[0]) {
		case '1':
			state = RFKILL_SOFT_BLOCKED;
			str_state = "soft-blocked";
			break;
		case '2':
		case '3':
			state = RFKILL_HARD_BLOCKED;
			str_state = "hard-blocked";
			break;
		case '0':
			str_state = "unblocked";
		default:
			break;
		}
		g_free (contents);

		nm_log_dbg (LOGD_RFKILL, "(%s): ipw rfkill state '%s'",
		            nm_device_get_iface (NM_DEVICE (self)),
		            str_state ? str_state : "(unknown)");
	}

	return state;
}

static gboolean
ipw_rfkill_state_work (gpointer user_data)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (user_data);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	RfKillState old_state;

	old_state = priv->ipw_rfkill_state;
	priv->ipw_rfkill_state = nm_device_wifi_get_ipw_rfkill_state (self);
	if (priv->ipw_rfkill_state != old_state)
		g_object_notify (G_OBJECT (self), NM_DEVICE_WIFI_IPW_RFKILL_STATE);

	return TRUE;
}

/*
 * nm_device_wifi_update_signal_strength
 *
 * Update the device's idea of the strength of its connection to the
 * current access point.
 *
 */
static void
nm_device_wifi_update_signal_strength (NMDeviceWifi *self,
                                       NMAccessPoint *ap)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	const char *iface = nm_device_get_iface (NM_DEVICE (self));
	int fd, percent = -1;

	fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (fd >= 0) {
		struct iwreq wrq;
		struct iw_statistics stats;

		memset (&stats, 0, sizeof (stats));

		wrq.u.data.pointer = &stats;
		wrq.u.data.length = sizeof (stats);
		wrq.u.data.flags = 1;  /* Clear updated flag */
		strncpy (wrq.ifr_name, iface, IFNAMSIZ);

		if (ioctl (fd, SIOCGIWSTATS, &wrq) == 0)
			percent = wireless_qual_to_percent (&stats.qual, &priv->max_qual);
		close (fd);
	}

	/* Try to smooth out the strength.  Atmel cards, for example, will give no strength
	 * one second and normal strength the next.
	 */
	if (percent >= 0 || ++priv->invalid_strength_counter > 3) {
		nm_ap_set_strength (ap, (gint8) percent);
		priv->invalid_strength_counter = 0;
	}
}


static gboolean
wireless_get_range (NMDeviceWifi *self,
                    struct iw_range *range,
                    guint32 *response_len)
{
	int fd, i = 26;
	gboolean success = FALSE;
	const char *iface;
	struct iwreq wrq;

	g_return_val_if_fail (NM_IS_DEVICE_WIFI (self), FALSE);
	g_return_val_if_fail (range != NULL, FALSE);

	iface = nm_device_get_iface (NM_DEVICE (self));

	fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		nm_log_err (LOGD_HW, "(%s): couldn't open control socket.", iface);
		return FALSE;
	}

	memset (&wrq, 0, sizeof (struct iwreq));
	strncpy (wrq.ifr_name, iface, IFNAMSIZ);
	wrq.u.data.pointer = (caddr_t) range;
	wrq.u.data.length = sizeof (struct iw_range);

	/* Need to give some drivers time to recover after suspend/resume
	 * (ex ipw3945 takes a few seconds to talk to its regulatory daemon;
	 * see rh bz#362421)
	 */
	while (i-- > 0) {
		if (ioctl (fd, SIOCGIWRANGE, &wrq) == 0) {
			if (response_len)
				*response_len = wrq.u.data.length;
			success = TRUE;
			break;
		} else if (errno != EAGAIN) {
			nm_log_err (LOGD_HW | LOGD_WIFI,
			            "(%s): couldn't get driver range information (%d).",
			            iface, errno);
			break;
		}

		g_usleep (G_USEC_PER_SEC / 4);
	}

	if (i <= 0) {
		nm_log_warn (LOGD_HW | LOGD_WIFI,
		             "(%s): driver took too long to respond to IWRANGE query.",
		             iface);
	}

	close (fd);
	return success;
}

static guint32
real_get_generic_capabilities (NMDevice *dev)
{
	int fd, err;
	guint32 caps = NM_DEVICE_CAP_NONE, response_len = 0;
	struct iwreq wrq;
	struct iw_range range;
	const char *iface = nm_device_get_iface (dev);
	gboolean success;

	memset (&range, 0, sizeof (struct iw_range));
	success = wireless_get_range (NM_DEVICE_WIFI (dev), &range, &response_len);
	if (!success)
		return NM_DEVICE_CAP_NONE;

	/* Check for Wireless Extensions support >= 16 for wireless devices */
	if ((response_len < 300) || (range.we_version_compiled < 16)) {
		nm_log_err (LOGD_HW | LOGD_WIFI,
		            "(%s): driver's Wireless Extensions version (%d) is too old.",
					iface, range.we_version_compiled);
		return NM_DEVICE_CAP_NONE;
	}

	fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		nm_log_err (LOGD_HW, "(%s): couldn't open control socket.", iface);
		goto out;
	}

	/* Cards that don't scan aren't supported */
	memset (&wrq, 0, sizeof (struct iwreq));
	strncpy (wrq.ifr_name, iface, IFNAMSIZ);
	err = ioctl (fd, SIOCSIWSCAN, &wrq);
	close (fd);
	if ((err < 0) && (errno == EOPNOTSUPP))
		caps = NM_DEVICE_CAP_NONE;
	else
		caps |= NM_DEVICE_CAP_NM_SUPPORTED;

out:
	return caps;
}

#define WPA_CAPS (NM_WIFI_DEVICE_CAP_CIPHER_TKIP | \
                  NM_WIFI_DEVICE_CAP_CIPHER_CCMP | \
                  NM_WIFI_DEVICE_CAP_WPA | \
                  NM_WIFI_DEVICE_CAP_RSN)

static guint32
get_wireless_capabilities (NMDeviceWifi *self,
                           iwrange * range,
                           guint32 data_len)
{
	guint32 minlen;
	guint32 caps = NM_WIFI_DEVICE_CAP_NONE;
	const char * iface;

	g_return_val_if_fail (self != NULL, NM_WIFI_DEVICE_CAP_NONE);
	g_return_val_if_fail (range != NULL, NM_WIFI_DEVICE_CAP_NONE);

	iface = nm_device_get_iface (NM_DEVICE (self));

	minlen = ((char *) &range->enc_capa) - (char *) range + sizeof (range->enc_capa);

	/* All drivers should support WEP by default */
	caps |= NM_WIFI_DEVICE_CAP_CIPHER_WEP40 | NM_WIFI_DEVICE_CAP_CIPHER_WEP104;

	if ((data_len >= minlen) && range->we_version_compiled >= 18) {
		if (range->enc_capa & IW_ENC_CAPA_CIPHER_TKIP)
			caps |= NM_WIFI_DEVICE_CAP_CIPHER_TKIP;

		if (range->enc_capa & IW_ENC_CAPA_CIPHER_CCMP)
			caps |= NM_WIFI_DEVICE_CAP_CIPHER_CCMP;

		if (range->enc_capa & IW_ENC_CAPA_WPA)
			caps |= NM_WIFI_DEVICE_CAP_WPA;

		if (range->enc_capa & IW_ENC_CAPA_WPA2)
			caps |= NM_WIFI_DEVICE_CAP_RSN;

		/* Check for cipher support but not WPA support */
		if (    (caps & (NM_WIFI_DEVICE_CAP_CIPHER_TKIP | NM_WIFI_DEVICE_CAP_CIPHER_CCMP))
		    && !(caps & (NM_WIFI_DEVICE_CAP_WPA | NM_WIFI_DEVICE_CAP_RSN))) {
			nm_log_warn (LOGD_WIFI, "%s: device supports WPA ciphers but not WPA protocol; "
			             "WPA unavailable.", iface);
			caps &= ~WPA_CAPS;
		}

		/* Check for WPA support but not cipher support */
		if (    (caps & (NM_WIFI_DEVICE_CAP_WPA | NM_WIFI_DEVICE_CAP_RSN))
		    && !(caps & (NM_WIFI_DEVICE_CAP_CIPHER_TKIP | NM_WIFI_DEVICE_CAP_CIPHER_CCMP))) {
			nm_log_warn (LOGD_WIFI, "%s: device supports WPA protocol but not WPA ciphers; "
			             "WPA unavailable.", iface);
			caps &= ~WPA_CAPS;
		}
	}

	return caps;
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

	return (guint32) (((double) freq->m) * pow (10, freq->e) / 1000000);
}


/* Until a new wireless-tools comes out that has the defs and the structure,
 * need to copy them here.
 */
/* Scan capability flags - in (struct iw_range *)->scan_capa */
#define NM_IW_SCAN_CAPA_NONE    0x00
#define NM_IW_SCAN_CAPA_ESSID   0x01

struct iw_range_with_scan_capa
{
	guint32 throughput;
	guint32 min_nwid;
	guint32 max_nwid;
	guint16 old_num_channels;
	guint8  old_num_frequency;

	guint8  scan_capa;
/* don't need the rest... */
};


static GObject*
constructor (GType type,
             guint n_construct_params,
             GObjectConstructParam *construct_params)
{
	GObject *object;
	GObjectClass *klass;
	NMDeviceWifi *self;
	NMDeviceWifiPrivate *priv;
	struct iw_range range;
	struct iw_range_with_scan_capa *scan_capa_range;
	guint32 response_len = 0;
	gboolean success;
	int i;

	klass = G_OBJECT_CLASS (nm_device_wifi_parent_class);
	object = klass->constructor (type, n_construct_params, construct_params);
	if (!object)
		return NULL;

	self = NM_DEVICE_WIFI (object);
	priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	nm_log_dbg (LOGD_HW | LOGD_WIFI, "(%s): kernel ifindex %d",
	            nm_device_get_iface (NM_DEVICE (self)),
	            nm_device_get_ifindex (NM_DEVICE (self)));

	memset (&range, 0, sizeof (struct iw_range));
	success = wireless_get_range (NM_DEVICE_WIFI (object), &range, &response_len);
	if (!success)
		goto error;

	priv->max_qual.qual = range.max_qual.qual;
	priv->max_qual.level = range.max_qual.level;
	priv->max_qual.noise = range.max_qual.noise;
	priv->max_qual.updated = range.max_qual.updated;

	priv->num_freqs = MIN (range.num_frequency, IW_MAX_FREQUENCIES);
	for (i = 0; i < priv->num_freqs; i++)
		priv->freqs[i] = iw_freq_to_uint32 (&range.freq[i]);

	priv->we_version = range.we_version_compiled;

	/* Check for the ability to scan specific SSIDs.  Until the scan_capa
	 * field gets added to wireless-tools, need to work around that by casting
	 * to the custom structure.
	 */
	scan_capa_range = (struct iw_range_with_scan_capa *) &range;
	if (scan_capa_range->scan_capa & NM_IW_SCAN_CAPA_ESSID) {
		priv->has_scan_capa_ssid = TRUE;
		nm_log_info (LOGD_HW | LOGD_WIFI,
		             "(%s): driver supports SSID scans (scan_capa 0x%02X).",
		             nm_device_get_iface (NM_DEVICE (self)),
		             scan_capa_range->scan_capa);
	} else {
		nm_log_info (LOGD_HW | LOGD_WIFI,
		             "(%s): driver does not support SSID scans (scan_capa 0x%02X).",
		             nm_device_get_iface (NM_DEVICE (self)),
		             scan_capa_range->scan_capa);
	}

	/* 802.11 wireless-specific capabilities */
	priv->capabilities = get_wireless_capabilities (self, &range, response_len);

	/* Connect to the supplicant manager */
	priv->supplicant.mgr = nm_supplicant_manager_get ();
	priv->supplicant.mgr_state_id = g_signal_connect (priv->supplicant.mgr,
	                                                  "state",
	                                                  G_CALLBACK (supplicant_mgr_state_cb),
	                                                  self);

	/* The ipw2x00 drivers don't integrate with the kernel rfkill subsystem until
	 * 2.6.33.  Thus all our nice libgudev magic is useless.  So we get to poll.
	 *
	 * FIXME: when 2.6.33 comes lands, we can do some sysfs parkour to figure out
	 * if we need to poll or not by matching /sys/class/net/ethX/device to one
	 * of the /sys/class/rfkill/rfkillX/device links.  If there's a match, we
	 * don't have to poll.
	 */
	priv->ipw_rfkill_path = g_strdup_printf ("/sys/class/net/%s/device/rf_kill",
	                                         nm_device_get_iface (NM_DEVICE (self)));
	if (!g_file_test (priv->ipw_rfkill_path, G_FILE_TEST_IS_REGULAR)) {
		g_free (priv->ipw_rfkill_path);
		priv->ipw_rfkill_path = NULL;
	}
	priv->ipw_rfkill_state = nm_device_wifi_get_ipw_rfkill_state (self);

	return object;

error:
	g_object_unref (object);
	return NULL;
}

static gboolean
supplicant_interface_acquire (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	guint id, mgr_state;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (priv->supplicant.mgr != NULL, FALSE);
	/* interface already acquired? */
	g_return_val_if_fail (priv->supplicant.iface == NULL, TRUE);

	mgr_state = nm_supplicant_manager_get_state (priv->supplicant.mgr);
	g_return_val_if_fail (mgr_state == NM_SUPPLICANT_MANAGER_STATE_IDLE, FALSE);

	priv->supplicant.iface = nm_supplicant_manager_get_iface (priv->supplicant.mgr,
	                                                          nm_device_get_iface (NM_DEVICE (self)),
	                                                          TRUE);
	if (priv->supplicant.iface == NULL) {
		nm_log_err (LOGD_WIFI, "Couldn't initialize supplicant interface for %s.",
		            nm_device_get_iface (NM_DEVICE (self)));
		return FALSE;
	}

	id = g_signal_connect (priv->supplicant.iface,
	                       "state",
	                       G_CALLBACK (supplicant_iface_state_cb),
	                       self);
	priv->supplicant.iface_state_id = id;

	id = g_signal_connect (priv->supplicant.iface,
	                       "scanned-ap",
	                       G_CALLBACK (supplicant_iface_scanned_ap_cb),
	                       self);
	priv->supplicant.iface_scanned_ap_id = id;

	id = g_signal_connect (priv->supplicant.iface,
	                       "scan-req-result",
	                       G_CALLBACK (supplicant_iface_scan_request_result_cb),
	                       self);
	priv->supplicant.iface_scan_request_result_id = id;

	id = g_signal_connect (priv->supplicant.iface,
	                       "scan-results",
	                       G_CALLBACK (supplicant_iface_scan_results_cb),
	                       self);
	priv->supplicant.iface_scan_results_id = id;

	id = g_signal_connect (priv->supplicant.iface,
	                       "connection-state",
	                       G_CALLBACK (supplicant_iface_connection_state_cb),
	                       self);
	priv->supplicant.iface_con_state_id = id;

	id = g_signal_connect (priv->supplicant.iface,
	                       "notify::scanning",
	                       G_CALLBACK (supplicant_iface_notify_scanning_cb),
	                       self);
	priv->supplicant.iface_notify_scanning_id = id;

	return TRUE;
}

static void
finish_supplicant_task (SupplicantStateTask *task, gboolean remove_source)
{
	NMDeviceWifi *self = task->self;
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	/* idle/timeout handlers should pass FALSE for remove_source, since they
	 * will tell glib to remove their source from the mainloop by returning
	 * FALSE when they exit.  When called from this NMDevice's dispose handler,
	 * remove_source should be TRUE to cancel all outstanding idle/timeout
	 * handlers asynchronously.
	 */
	if (task->source_id && remove_source)
		g_source_remove (task->source_id);

	if (task->mgr_task)
		priv->supplicant.mgr_tasks = g_slist_remove (priv->supplicant.mgr_tasks, task);
	else
		priv->supplicant.iface_tasks = g_slist_remove (priv->supplicant.iface_tasks, task);

	memset (task, 0, sizeof (SupplicantStateTask));
	g_slice_free (SupplicantStateTask, task);
}

static void
remove_supplicant_interface_error_handler (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	if (!priv->supplicant.iface)
		return;

	if (priv->supplicant.iface_error_id > 0) {
		g_signal_handler_disconnect (priv->supplicant.iface, priv->supplicant.iface_error_id);
		priv->supplicant.iface_error_id = 0;
	}

	if (priv->supplicant.iface_con_error_cb_id > 0) {
		g_source_remove (priv->supplicant.iface_con_error_cb_id);
		priv->supplicant.iface_con_error_cb_id = 0;
	}
}

static void
supplicant_interface_release (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv;

	g_return_if_fail (self != NULL);

	priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	cancel_pending_scan (self);

	/* Reset the scan interval to be pretty frequent when disconnected */
	priv->scan_interval = SCAN_INTERVAL_MIN + SCAN_INTERVAL_STEP;
	nm_log_dbg (LOGD_WIFI_SCAN, "(%s): reset scanning interval to %d seconds",
	            nm_device_get_iface (NM_DEVICE (self)));

	remove_supplicant_interface_error_handler (self);

	/* Clean up all pending supplicant interface state idle tasks */
	while (priv->supplicant.iface_tasks)
		finish_supplicant_task ((SupplicantStateTask *) priv->supplicant.iface_tasks->data, TRUE);

	if (priv->supplicant.iface_state_id > 0) {
		g_signal_handler_disconnect (priv->supplicant.iface, priv->supplicant.iface_state_id);
		priv->supplicant.iface_state_id = 0;
	}

	if (priv->supplicant.iface_scanned_ap_id > 0) {
		g_signal_handler_disconnect (priv->supplicant.iface, priv->supplicant.iface_scanned_ap_id);
		priv->supplicant.iface_scanned_ap_id = 0;
	}

	if (priv->supplicant.iface_scan_request_result_id > 0) {
		g_signal_handler_disconnect (priv->supplicant.iface, priv->supplicant.iface_scan_request_result_id);
		priv->supplicant.iface_scan_request_result_id = 0;
	}

	if (priv->supplicant.iface_scan_results_id > 0) {
		g_signal_handler_disconnect (priv->supplicant.iface, priv->supplicant.iface_scan_results_id);
		priv->supplicant.iface_scan_results_id = 0;
	}

	if (priv->supplicant.iface_con_state_id > 0) {
		g_signal_handler_disconnect (priv->supplicant.iface, priv->supplicant.iface_con_state_id);
		priv->supplicant.iface_con_state_id = 0;
	}

	if (priv->supplicant.iface_notify_scanning_id > 0) {
		g_signal_handler_disconnect (priv->supplicant.iface, priv->supplicant.iface_notify_scanning_id);
		priv->supplicant.iface_notify_scanning_id = 0;
	}

	if (priv->supplicant.iface) {
		/* Tell the supplicant to disconnect from the current AP */
		nm_supplicant_interface_disconnect (priv->supplicant.iface);

		nm_supplicant_manager_release_iface (priv->supplicant.mgr, priv->supplicant.iface);
		priv->supplicant.iface = NULL;
	}
}

static NMAccessPoint *
get_active_ap (NMDeviceWifi *self,
               NMAccessPoint *ignore_ap,
               gboolean match_hidden)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	const char *iface = nm_device_get_iface (NM_DEVICE (self));
	struct ether_addr bssid;
	const GByteArray *ssid;
	GSList *iter;
	int i = 0;
	NMAccessPoint *match_nofreq = NULL;
	gboolean found_a_band = FALSE;
	gboolean found_bg_band = FALSE;
	NM80211Mode devmode;
	guint32 devfreq;

	nm_device_wifi_get_bssid (self, &bssid);
	nm_log_dbg (LOGD_WIFI, "(%s): active BSSID: %02x:%02x:%02x:%02x:%02x:%02x",
	            iface,
	            bssid.ether_addr_octet[0], bssid.ether_addr_octet[1],
	            bssid.ether_addr_octet[2], bssid.ether_addr_octet[3],
	            bssid.ether_addr_octet[4], bssid.ether_addr_octet[5]);

	if (!nm_ethernet_address_is_valid (&bssid))
		return NULL;

	ssid = nm_device_wifi_get_ssid (self);
	nm_log_dbg (LOGD_WIFI, "(%s): active SSID: %s%s%s",
	            iface,
	            ssid ? "'" : "",
	            ssid ? nm_utils_escape_ssid (ssid->data, ssid->len) : "(none)",
	            ssid ? "'" : "");

	devmode = nm_device_wifi_get_mode (self);
	devfreq = nm_device_wifi_get_frequency (self);

	/* When matching hidden APs, do a second pass that ignores the SSID check,
	 * because NM might not yet know the SSID of the hidden AP in the scan list
	 * and therefore it won't get matched the first time around.
	 */
	while (i++ < (match_hidden ? 2 : 1)) {
		nm_log_dbg (LOGD_WIFI, "  Pass #%d %s", i, i > 1 ? "(ignoring SSID)" : "");

		/* Find this SSID + BSSID in the device's AP list */
		for (iter = priv->ap_list; iter; iter = g_slist_next (iter)) {
			NMAccessPoint *ap = NM_AP (iter->data);
			const struct ether_addr	*ap_bssid = nm_ap_get_address (ap);
			const GByteArray *ap_ssid = nm_ap_get_ssid (ap);
			NM80211Mode apmode;
			guint32 apfreq;

			nm_log_dbg (LOGD_WIFI, "    AP: %s%s%s  %02x:%02x:%02x:%02x:%02x:%02x",
			            ap_ssid ? "'" : "",
			            ap_ssid ? nm_utils_escape_ssid (ap_ssid->data, ap_ssid->len) : "(none)",
			            ap_ssid ? "'" : "",
			            ap_bssid->ether_addr_octet[0], ap_bssid->ether_addr_octet[1],
			            ap_bssid->ether_addr_octet[2], ap_bssid->ether_addr_octet[3],
			            ap_bssid->ether_addr_octet[4], ap_bssid->ether_addr_octet[5]);

			if (ignore_ap && (ap == ignore_ap)) {
				nm_log_dbg (LOGD_WIFI, "      ignored");
				continue;
			}

			if (memcmp (bssid.ether_addr_octet, ap_bssid->ether_addr_octet, ETH_ALEN)) {
				nm_log_dbg (LOGD_WIFI, "      BSSID mismatch");
				continue;
			}

			if ((i == 0) && !nm_utils_same_ssid (ssid, ap_ssid, TRUE)) {
				nm_log_dbg (LOGD_WIFI, "      SSID mismatch");
				continue;
			}

			apmode = nm_ap_get_mode (ap);
			if (devmode != apmode) {
				nm_log_dbg (LOGD_WIFI, "      mode mismatch (device %d, ap %d)",
				            devmode, apmode);
				continue;
			}

			apfreq = nm_ap_get_freq (ap);
			if (devfreq != apfreq) {
				nm_log_dbg (LOGD_WIFI, "      frequency mismatch (device %u, ap %u)",
				            devfreq, apfreq);

				if (match_nofreq == NULL)
					match_nofreq = ap;

				if (apfreq > 4000)
					found_a_band = TRUE;
				else if (apfreq > 2000)
					found_bg_band = TRUE;
				continue;
			}

			// FIXME: handle security settings here too
			nm_log_dbg (LOGD_WIFI, "      matched");
			return ap;
		}
	}

	/* Some proprietary drivers (wl.o) report tuned frequency (like when
	 * scanning) instead of the associated AP's frequency.  This is a great
	 * example of how WEXT is underspecified.  We use frequency to find the
	 * active AP in the scan list because some configurations use the same
	 * SSID/BSSID on the 2GHz and 5GHz bands simultaneously, and we need to
	 * make sure we get the right AP in the right band.  This configuration
	 * is uncommon though, and the frequency check penalizes closed drivers we
	 * can't fix.  Because we're not total dicks, ignore the frequency condition
	 * if the associated BSSID/SSID exists only in one band since that's most
	 * likely the AP we want.
	 */
	if (match_nofreq && (found_a_band != found_bg_band)) {
		const struct ether_addr	*ap_bssid = nm_ap_get_address (match_nofreq);
		const GByteArray *ap_ssid = nm_ap_get_ssid (match_nofreq);

		nm_log_dbg (LOGD_WIFI, "    matched %s%s%s  %02x:%02x:%02x:%02x:%02x:%02x",
		            ap_ssid ? "'" : "",
		            ap_ssid ? nm_utils_escape_ssid (ap_ssid->data, ap_ssid->len) : "(none)",
		            ap_ssid ? "'" : "",
		            ap_bssid->ether_addr_octet[0], ap_bssid->ether_addr_octet[1],
		            ap_bssid->ether_addr_octet[2], ap_bssid->ether_addr_octet[3],
		            ap_bssid->ether_addr_octet[4], ap_bssid->ether_addr_octet[5]);

		return match_nofreq;
	}

	nm_log_dbg (LOGD_WIFI, "  No matching AP found.");
	return NULL;
}

static void
set_current_ap (NMDeviceWifi *self, NMAccessPoint *new_ap)
{
	NMDeviceWifiPrivate *priv;
	char *old_path = NULL;
	NMAccessPoint *old_ap;

	g_return_if_fail (NM_IS_DEVICE_WIFI (self));

	priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	old_ap = priv->current_ap;

	if (old_ap) {
		old_path = g_strdup (nm_ap_get_dbus_path (old_ap));
		priv->current_ap = NULL;
	}

	if (new_ap) {
		priv->current_ap = g_object_ref (new_ap);

		/* Move the current AP to the front of the scan list.  Since we
		 * do a lot of searches looking for the current AP, it saves
		 * time to have it in front.
		 */
		priv->ap_list = g_slist_remove (priv->ap_list, new_ap);
		priv->ap_list = g_slist_prepend (priv->ap_list, new_ap);
	}

	/* Unref old AP here to ensure object lives if new_ap == old_ap */
	if (old_ap)
		g_object_unref (old_ap);

	/* Only notify if it's really changed */
	if (   (!old_path && new_ap)
	    || (old_path && !new_ap)
	    || (old_path && new_ap && strcmp (old_path, nm_ap_get_dbus_path (new_ap))))
		g_object_notify (G_OBJECT (self), NM_DEVICE_WIFI_ACTIVE_ACCESS_POINT);

	g_free (old_path);
}

static void
periodic_update (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMAccessPoint *new_ap;
	guint32 new_rate;

	/* In IBSS mode, most newer firmware/drivers do "BSS coalescing" where
	 * multiple IBSS stations using the same SSID will eventually switch to
	 * using the same BSSID to avoid network segmentation.  When this happens,
	 * the card's reported BSSID will change, but the the new BSS may not
	 * be in the scan list, since scanning isn't done in ad-hoc mode for
	 * various reasons.  So pull the BSSID from the card and update the
	 * current AP with it, if the current AP is adhoc.
	 */
	if (priv->current_ap && (nm_ap_get_mode (priv->current_ap) == NM_802_11_MODE_ADHOC)) {
		struct ether_addr bssid = { {0x0, 0x0, 0x0, 0x0, 0x0, 0x0} };

		nm_device_wifi_get_bssid (self, &bssid);
		/* 0x02 means "locally administered" and should be OR-ed into
		 * the first byte of IBSS BSSIDs.
		 */
		if (   (bssid.ether_addr_octet[0] & 0x02)
		    && nm_ethernet_address_is_valid (&bssid))
			nm_ap_set_address (priv->current_ap, &bssid);
	}

	new_ap = get_active_ap (self, NULL, FALSE);
	if (new_ap)
		nm_device_wifi_update_signal_strength (self, new_ap);

	if ((new_ap || priv->current_ap) && (new_ap != priv->current_ap)) {
		const struct ether_addr *new_bssid = NULL;
		const GByteArray *new_ssid = NULL;
		const struct ether_addr *old_bssid = NULL;
		const GByteArray *old_ssid = NULL;
		char *old_addr = NULL, *new_addr = NULL;

		if (new_ap) {
			new_bssid = nm_ap_get_address (new_ap);
			new_addr = nm_ether_ntop (new_bssid);
			new_ssid = nm_ap_get_ssid (new_ap);
		}

		if (priv->current_ap) {
			old_bssid = nm_ap_get_address (priv->current_ap);
			old_addr = nm_ether_ntop (old_bssid);
			old_ssid = nm_ap_get_ssid (priv->current_ap);
		}

		nm_log_info (LOGD_WIFI, "(%s): roamed from BSSID %s (%s) to %s (%s)",
		             nm_device_get_iface (NM_DEVICE (self)),
		             old_addr ? old_addr : "(none)",
		             old_ssid ? nm_utils_escape_ssid (old_ssid->data, old_ssid->len) : "(none)",
		             new_addr ? new_addr : "(none)",
		             new_ssid ? nm_utils_escape_ssid (new_ssid->data, new_ssid->len) : "(none)");
		g_free (old_addr);
		g_free (new_addr);

		set_current_ap (self, new_ap);
	}

	new_rate = nm_device_wifi_get_bitrate (self);
	if (new_rate != priv->rate) {
		priv->rate = new_rate;
		g_object_notify (G_OBJECT (self), NM_DEVICE_WIFI_BITRATE);
	}
}

/*
 * nm_device_wifi_periodic_update
 *
 * Periodically update device statistics.
 *
 */
static gboolean
nm_device_wifi_periodic_update (gpointer data)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (data);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMDeviceState state;

	/* BSSID and signal strength have meaningful values only if the device
	   is activated and not scanning */
	state = nm_device_get_state (NM_DEVICE (self));
	if (state != NM_DEVICE_STATE_ACTIVATED)
		goto out;

	if (nm_supplicant_interface_get_scanning (priv->supplicant.iface))
		goto out;

	periodic_update (self);

out:
	return TRUE;
}

static gboolean
real_hw_is_up (NMDevice *device)
{
	return nm_system_device_is_up (device);
}

static gboolean
real_hw_bring_up (NMDevice *device, gboolean *no_firmware)
{
	if (!NM_DEVICE_WIFI_GET_PRIVATE (device)->enabled)
		return FALSE;

	return nm_system_device_set_up_down (device, TRUE, no_firmware);
}

static void
real_hw_take_down (NMDevice *dev)
{
	nm_system_device_set_up_down (dev, FALSE, NULL);
}

static gboolean
real_is_up (NMDevice *device)
{
	if (!NM_DEVICE_WIFI_GET_PRIVATE (device)->periodic_source_id)
		return FALSE;

	return TRUE;
}

static gboolean
real_bring_up (NMDevice *dev)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (dev);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	priv->periodic_source_id = g_timeout_add_seconds (6, nm_device_wifi_periodic_update, self);
	return TRUE;
}

static void
_update_hw_addr (NMDeviceWifi *self, const guint8 *addr)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	g_return_if_fail (addr != NULL);

	if (memcmp (&priv->hw_addr, addr, ETH_ALEN)) {
		memcpy (&priv->hw_addr, addr, ETH_ALEN);
		g_object_notify (G_OBJECT (self), NM_DEVICE_WIFI_HW_ADDRESS);
	}
}

static gboolean
_set_hw_addr (NMDeviceWifi *self, const guint8 *addr, const char *detail)
{
	NMDevice *dev = NM_DEVICE (self);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	const char *iface;
	char *mac_str = NULL;
	gboolean success = FALSE;

	g_return_val_if_fail (addr != NULL, FALSE);

	iface = nm_device_get_iface (dev);

	mac_str = g_strdup_printf ("%02X:%02X:%02X:%02X:%02X:%02X",
	                           addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

	/* Do nothing if current MAC is same */
	if (!memcmp (&priv->hw_addr, addr, ETH_ALEN)) {
		nm_log_dbg (LOGD_DEVICE | LOGD_ETHER, "(%s): no MAC address change needed",
		            iface, detail, mac_str);
		g_free (mac_str);
		return TRUE;
	}

	/* Can't change MAC address while device is up */
	real_hw_take_down (dev);

	success = nm_system_device_set_mac (iface, (struct ether_addr *) addr);
	if (success) {
		/* MAC address succesfully changed; update the current MAC to match */
		_update_hw_addr (self, addr);
		nm_log_info (LOGD_DEVICE | LOGD_ETHER, "(%s): %s MAC address to %s",
		             iface, detail, mac_str);
	} else {
		nm_log_warn (LOGD_DEVICE | LOGD_ETHER, "(%s): failed to %s MAC address to %s",
		             iface, detail, mac_str);
	}
	real_hw_bring_up (dev, NULL);
	g_free (mac_str);

	return success;
}

static void
access_point_removed (NMDeviceWifi *device, NMAccessPoint *ap)
{
	g_signal_emit (device, signals[ACCESS_POINT_REMOVED], 0, ap);
}

static void
remove_all_aps (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	/* Remove outdated APs */
	while (g_slist_length (priv->ap_list)) {
		NMAccessPoint *ap = NM_AP (priv->ap_list->data);

		access_point_removed (self, ap);
		priv->ap_list = g_slist_remove (priv->ap_list, ap);
		g_object_unref (ap);
	}
	g_slist_free (priv->ap_list);
	priv->ap_list = NULL;
}

static void
real_take_down (NMDevice *dev)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (dev);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	if (priv->periodic_source_id) {
		g_source_remove (priv->periodic_source_id);
		priv->periodic_source_id = 0;
	}

	cleanup_association_attempt (self, TRUE);
	set_current_ap (self, NULL);
	remove_all_aps (self);
}

static void
real_deactivate_quickly (NMDevice *dev)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (dev);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMAccessPoint *orig_ap = nm_device_wifi_get_activation_ap (self);

	cleanup_association_attempt (self, TRUE);

	set_current_ap (self, NULL);
	priv->rate = 0;

	/* If the AP is 'fake', i.e. it wasn't actually found from
	 * a scan but the user tried to connect to it manually (maybe it
	 * was non-broadcasting or something) get rid of it, because 'fake'
	 * APs should only live for as long as we're connected to them.  Fixes
	 * a bug where user-created Ad-Hoc APs are never removed from the scan
	 * list, because scanning is disabled while in Ad-Hoc mode (for stability),
	 * and thus the AP culling never happens. (bgo #569241)
	 */
	if (orig_ap && nm_ap_get_fake (orig_ap)) {
		access_point_removed (self, orig_ap);
		priv->ap_list = g_slist_remove (priv->ap_list, orig_ap);
		g_object_unref (orig_ap);
	}

	_set_hw_addr (self, priv->perm_hw_addr, "reset");
}

static void
real_deactivate (NMDevice *dev)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (dev);

	nm_device_wifi_set_mode (self, NM_802_11_MODE_INFRA);
	/* FIXME: Should we reset the scan interval here? */
/* 	nm_device_wifi_set_scan_interval (app_data, self, NM_WIRELESS_SCAN_INTERVAL_ACTIVE); */
}

static gboolean
real_check_connection_compatible (NMDevice *device,
                                  NMConnection *connection,
                                  GError **error)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (device);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	const GByteArray *mac;

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_con);

	if (strcmp (nm_setting_connection_get_connection_type (s_con), NM_SETTING_WIRELESS_SETTING_NAME)) {
		g_set_error (error,
		             NM_WIFI_ERROR, NM_WIFI_ERROR_CONNECTION_NOT_WIRELESS,
		             "The connection was not a WiFi connection.");
		return FALSE;
	}

	s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS));
	if (!s_wireless) {
		g_set_error (error,
		             NM_WIFI_ERROR, NM_WIFI_ERROR_CONNECTION_INVALID,
		             "The connection was not a valid WiFi connection.");
		return FALSE;
	}

	mac = nm_setting_wireless_get_mac_address (s_wireless);
	if (mac && memcmp (mac->data, &priv->perm_hw_addr, ETH_ALEN)) {
		g_set_error (error,
		             NM_WIFI_ERROR, NM_WIFI_ERROR_CONNECTION_INCOMPATIBLE,
		             "The connection's MAC address did not match this device.");
		return FALSE;
	}

	// FIXME: check channel/freq/band against bands the hardware supports
	// FIXME: check encryption against device capabilities
	// FIXME: check bitrate against device capabilities

	return TRUE;
}

static gboolean
real_is_available (NMDevice *dev)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (dev);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMSupplicantInterface *sup_iface;
	guint32 state;

	if (!priv->enabled) {
		nm_log_dbg (LOGD_WIFI, "(%s): not available because not enabled",
		            nm_device_get_iface (dev));
		return FALSE;
	}

	sup_iface = priv->supplicant.iface;
	if (!sup_iface) {
		nm_log_dbg (LOGD_WIFI, "(%s): not available because supplicant not running",
		            nm_device_get_iface (dev));
		return FALSE;
	}

	state = nm_supplicant_interface_get_state (sup_iface);
	if (state != NM_SUPPLICANT_INTERFACE_STATE_READY) {
		nm_log_dbg (LOGD_WIFI, "(%s): not available because supplicant interface not ready",
		            nm_device_get_iface (dev));
		return FALSE;
	}

	return TRUE;
}

static NMConnection *
real_get_best_auto_connection (NMDevice *dev,
                               GSList *connections,
                               char **specific_object)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (dev);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	GSList *iter, *ap_iter;

	for (iter = connections; iter; iter = g_slist_next (iter)) {
		NMConnection *connection = NM_CONNECTION (iter->data);
		NMSettingConnection *s_con;
		NMSettingWireless *s_wireless;
		const GByteArray *mac;
		NMSettingIP4Config *s_ip4;
		const char *method = NULL;

		s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
		if (s_con == NULL)
			continue;
		if (strcmp (nm_setting_connection_get_connection_type (s_con), NM_SETTING_WIRELESS_SETTING_NAME))
			continue;
		if (!nm_setting_connection_get_autoconnect (s_con))
			continue;

		s_wireless = (NMSettingWireless *) nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS);
		if (!s_wireless)
			continue;

		mac = nm_setting_wireless_get_mac_address (s_wireless);
		if (mac && memcmp (mac->data, &priv->perm_hw_addr, ETH_ALEN))
				continue;

		/* Use the connection if it's a shared connection */
		s_ip4 = (NMSettingIP4Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG);
		if (s_ip4)
			method = nm_setting_ip4_config_get_method (s_ip4);

		if (s_ip4 && !strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_SHARED))
			return connection;

		for (ap_iter = priv->ap_list; ap_iter; ap_iter = g_slist_next (ap_iter)) {
			NMAccessPoint *ap = NM_AP (ap_iter->data);

			if (nm_ap_check_compatible (ap, connection)) {
				/* All good; connection is usable */
				*specific_object = (char *) nm_ap_get_dbus_path (ap);
				return connection;
			}
		}
	}
	return NULL;
}

/*
 * nm_device_wifi_get_address
 *
 * Get a device's hardware address
 *
 */
void
nm_device_wifi_get_address (NMDeviceWifi *self,
                            struct ether_addr *addr)
{
	NMDeviceWifiPrivate *priv;

	g_return_if_fail (self != NULL);
	g_return_if_fail (addr != NULL);

	priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	memcpy (addr, &priv->hw_addr, sizeof (struct ether_addr));
}

static void
nm_device_wifi_ap_list_print (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	GSList * elt;
	int i = 0;

	g_return_if_fail (NM_IS_DEVICE_WIFI (self));

	nm_log_dbg (LOGD_WIFI_SCAN, "Current AP list:");
	for (elt = priv->ap_list; elt; elt = g_slist_next (elt), i++) {
		NMAccessPoint * ap = NM_AP (elt->data);
		nm_ap_print_self (ap, "AP: ");
	}
	nm_log_dbg (LOGD_WIFI_SCAN, "Current AP list: done");
}

static gboolean
impl_device_get_access_points (NMDeviceWifi *self,
                               GPtrArray **aps,
                               GError **err)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	GSList *elt;

	*aps = g_ptr_array_new ();

	for (elt = priv->ap_list; elt; elt = g_slist_next (elt)) {
		NMAccessPoint * ap = NM_AP (elt->data);

		if (nm_ap_get_ssid (ap))
			g_ptr_array_add (*aps, g_strdup (nm_ap_get_dbus_path (ap)));
	}
	return TRUE;
}

/*
 * nm_device_get_mode
 *
 * Get managed/infrastructure/adhoc mode on a device
 *
 */
NM80211Mode
nm_device_wifi_get_mode (NMDeviceWifi *self)
{
	int fd;
	NM80211Mode mode = NM_802_11_MODE_UNKNOWN;
	const char *iface;
	struct iwreq wrq;

	g_return_val_if_fail (self != NULL, NM_802_11_MODE_UNKNOWN);

	fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		goto out;

	memset (&wrq, 0, sizeof (struct iwreq));
	iface = nm_device_get_iface (NM_DEVICE (self));
	strncpy (wrq.ifr_name, iface, IFNAMSIZ);

	if (ioctl (fd, SIOCGIWMODE, &wrq) == 0) {
		switch (wrq.u.mode) {
		case IW_MODE_ADHOC:
			mode = NM_802_11_MODE_ADHOC;
			break;
		case IW_MODE_INFRA:
			mode = NM_802_11_MODE_INFRA;
			break;
		default:
			break;
		}
	} else {
		if (errno != ENODEV) {
			nm_log_warn (LOGD_HW | LOGD_WIFI,
			             "(%s): error %d getting card mode",
			             iface, strerror (errno));
		}
	}
	close (fd);

out:
	return mode;
}


/*
 * nm_device_wifi_set_mode
 *
 * Set managed/infrastructure/adhoc mode on a device
 *
 */
gboolean
nm_device_wifi_set_mode (NMDeviceWifi *self, const NM80211Mode mode)
{
	int fd;
	const char *iface;
	gboolean success = FALSE;
	struct iwreq wrq;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail ((mode == NM_802_11_MODE_INFRA) || (mode == NM_802_11_MODE_ADHOC), FALSE);

	if (nm_device_wifi_get_mode (self) == mode)
		return TRUE;

	fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		goto out;

	memset (&wrq, 0, sizeof (struct iwreq));
	switch (mode) {
	case NM_802_11_MODE_ADHOC:
		wrq.u.mode = IW_MODE_ADHOC;
		break;
	case NM_802_11_MODE_INFRA:
		wrq.u.mode = IW_MODE_INFRA;
		break;
	default:
		goto out;
	}

	iface = nm_device_get_iface (NM_DEVICE (self));
	strncpy (wrq.ifr_name, iface, IFNAMSIZ);

	if (ioctl (fd, SIOCSIWMODE, &wrq) < 0) {
		if (errno != ENODEV) {
			nm_log_err (LOGD_HW | LOGD_WIFI,
			            "(%s): error setting mode %d",
			            iface, mode, strerror (errno));
		}
	} else
		success = TRUE;
	close (fd);

out:
	return success;
}


/*
 * nm_device_wifi_get_frequency
 *
 * Get current frequency
 *
 */
static guint32
nm_device_wifi_get_frequency (NMDeviceWifi *self)
{
	int fd;
	guint32 freq = 0;
	const char *iface;
	struct iwreq wrq;

	g_return_val_if_fail (self != NULL, 0);

	fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return 0;

	memset (&wrq, 0, sizeof (struct iwreq));
	iface = nm_device_get_iface (NM_DEVICE (self));
	strncpy (wrq.ifr_name, iface, IFNAMSIZ);

	if (ioctl (fd, SIOCGIWFREQ, &wrq) < 0) {
		nm_log_warn (LOGD_HW | LOGD_WIFI,
		             "(%s): error getting frequency: %s",
		             iface, strerror (errno));
	} else
		freq = iw_freq_to_uint32 (&wrq.u.freq);

	close (fd);
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
                          const struct iw_quality *max_qual)
{
	int percent = -1;
	int level_percent = -1;

	g_return_val_if_fail (qual != NULL, -1);
	g_return_val_if_fail (max_qual != NULL, -1);

	nm_log_dbg (LOGD_WIFI,
	            "QL: qual %d/%u/0x%X, level %d/%u/0x%X, noise %d/%u/0x%X, updated: 0x%X  ** MAX: qual %d/%u/0x%X, level %d/%u/0x%X, noise %d/%u/0x%X, updated: 0x%X",
	            (__s8) qual->qual, qual->qual, qual->qual,
	            (__s8) qual->level, qual->level, qual->level,
	            (__s8) qual->noise, qual->noise, qual->noise,
	            qual->updated,
	            (__s8) max_qual->qual, max_qual->qual, max_qual->qual,
	            (__s8) max_qual->level, max_qual->level, max_qual->level,
	            (__s8) max_qual->noise, max_qual->noise, max_qual->noise,
	            max_qual->updated);

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

	if (    (max_qual->level == 0) && !(max_qual->updated & IW_QUAL_LEVEL_INVALID)          /* Valid max_qual->level == 0 */
		&& !(qual->updated & IW_QUAL_LEVEL_INVALID)                                     /* Must have valid qual->level */
		&& (    ((max_qual->noise > 0) && !(max_qual->updated & IW_QUAL_NOISE_INVALID)) /* Must have valid max_qual->noise */
			|| ((qual->noise > 0) && !(qual->updated & IW_QUAL_NOISE_INVALID)))     /*    OR valid qual->noise */
	   ) {
		/* Absolute power values (dBm) */

		/* Reasonable fallbacks for dumb drivers that don't specify either level. */
		#define FALLBACK_NOISE_FLOOR_DBM  -90
		#define FALLBACK_SIGNAL_MAX_DBM   -20
		int max_level = FALLBACK_SIGNAL_MAX_DBM;
		int noise = FALLBACK_NOISE_FLOOR_DBM;
		int level = qual->level - 0x100;

		level = CLAMP (level, FALLBACK_NOISE_FLOOR_DBM, FALLBACK_SIGNAL_MAX_DBM);

		if ((qual->noise > 0) && !(qual->updated & IW_QUAL_NOISE_INVALID))
			noise = qual->noise - 0x100;
		else if ((max_qual->noise > 0) && !(max_qual->updated & IW_QUAL_NOISE_INVALID))
			noise = max_qual->noise - 0x100;
		noise = CLAMP (noise, FALLBACK_NOISE_FLOOR_DBM, FALLBACK_SIGNAL_MAX_DBM);

		/* A sort of signal-to-noise ratio calculation */
		level_percent = (int)(100 - 70 *(
		                                ((double)max_level - (double)level) /
		                                ((double)max_level - (double)noise)));
		nm_log_dbg (LOGD_WIFI, "QL1: level_percent is %d.  max_level %d, level %d, noise_floor %d.",
		            level_percent, max_level, level, noise);
	} else if (   (max_qual->level != 0)
	           && !(max_qual->updated & IW_QUAL_LEVEL_INVALID) /* Valid max_qual->level as upper bound */
	           && !(qual->updated & IW_QUAL_LEVEL_INVALID)) {
		/* Relative power values (RSSI) */

		int level = qual->level;

		/* Signal level is relavtive (0 -> max_qual->level) */
		level = CLAMP (level, 0, max_qual->level);
		level_percent = (int)(100 * ((double)level / (double)max_qual->level));
		nm_log_dbg (LOGD_WIFI, "QL2: level_percent is %d.  max_level %d, level %d.",
		            level_percent, max_qual->level, level);
	} else if (percent == -1) {
		nm_log_dbg (LOGD_WIFI, "QL: Could not get quality %% value from driver.  Driver is probably buggy.");
	}

	/* If the quality percent was 0 or doesn't exist, then try to use signal levels instead */
	if ((percent < 1) && (level_percent >= 0))
		percent = level_percent;

	nm_log_dbg (LOGD_WIFI, "QL: Final quality percent is %d (%d).",
	            percent, CLAMP (percent, 0, 100));
	return (CLAMP (percent, 0, 100));
}


/*
 * nm_device_wifi_get_ssid
 *
 * If a device is wireless, return the ssid that it is attempting
 * to use.
 */
const GByteArray *
nm_device_wifi_get_ssid (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv;
	int sk;
	struct iwreq wrq;
	char ssid[IW_ESSID_MAX_SIZE + 2];
	guint32 len;

	g_return_val_if_fail (self != NULL, NULL);
	priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	sk = socket (AF_INET, SOCK_DGRAM, 0);
	if (!sk) {
		nm_log_err (LOGD_HW, "couldn't create socket: %d.", errno);
		return NULL;
	}

	memset (ssid, 0, sizeof (ssid));
	wrq.u.essid.pointer = (caddr_t) &ssid;
	wrq.u.essid.length = sizeof (ssid);
	wrq.u.essid.flags = 0;
	strncpy (wrq.ifr_name, nm_device_get_iface (NM_DEVICE (self)), IFNAMSIZ);

	if (ioctl (sk, SIOCGIWESSID, &wrq) < 0) {
		nm_log_err (LOGD_HW | LOGD_WIFI, "(%s): couldn't get SSID: %d",
		            nm_device_get_iface (NM_DEVICE (self)), errno);
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
	return priv->ssid;
}


/*
 * nm_device_wifi_get_bitrate
 *
 * For wireless devices, get the bitrate to broadcast/receive at.
 * Returned value is rate in Kb/s.
 *
 */
static guint32
nm_device_wifi_get_bitrate (NMDeviceWifi *self)
{
	int err = -1, fd;
	struct iwreq wrq;

	g_return_val_if_fail (self != NULL, 0);

	fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return 0;

	memset (&wrq, 0, sizeof (wrq));
	strncpy (wrq.ifr_name, nm_device_get_iface (NM_DEVICE (self)), IFNAMSIZ);
	err = ioctl (fd, SIOCGIWRATE, &wrq);
	close (fd);

	return ((err == 0) ? wrq.u.bitrate.value / 1000 : 0);
}

/*
 * nm_device_get_bssid
 *
 * If a device is wireless, get the access point's ethernet address
 * that the card is associated with.
 */
void
nm_device_wifi_get_bssid (NMDeviceWifi *self,
                          struct ether_addr *bssid)
{
	int fd;
	struct iwreq wrq;

	g_return_if_fail (self != NULL);
	g_return_if_fail (bssid != NULL);

	memset (bssid, 0, sizeof (struct ether_addr));

	fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		nm_log_err (LOGD_WIFI, "failed to open control socket.");
		return;
	}

	memset (&wrq, 0, sizeof (wrq));
	strncpy (wrq.ifr_name, nm_device_get_iface (NM_DEVICE (self)), IFNAMSIZ);
	if (ioctl (fd, SIOCGIWAP, &wrq) == 0)
		memcpy (bssid->ether_addr_octet, &(wrq.u.ap_addr.sa_data), ETH_ALEN);

	close (fd);
}


static gboolean
scanning_allowed (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	guint32 sup_state;
	NMActRequest *req;

	g_return_val_if_fail (priv->supplicant.iface != NULL, FALSE);

	switch (nm_device_get_state (NM_DEVICE (self))) {
	case NM_DEVICE_STATE_UNKNOWN:
	case NM_DEVICE_STATE_UNMANAGED:
	case NM_DEVICE_STATE_UNAVAILABLE:
	case NM_DEVICE_STATE_PREPARE:
	case NM_DEVICE_STATE_CONFIG:
	case NM_DEVICE_STATE_NEED_AUTH:
	case NM_DEVICE_STATE_IP_CONFIG:
		/* Don't scan when unusable or activating */
		return FALSE;
	case NM_DEVICE_STATE_DISCONNECTED:
	case NM_DEVICE_STATE_FAILED:
		/* Can always scan when disconnected */
		return TRUE;
	case NM_DEVICE_STATE_ACTIVATED:
		/* Need to do further checks when activated */
		break;
	}

	/* Don't scan if the supplicant is busy */
	sup_state = nm_supplicant_interface_get_connection_state (priv->supplicant.iface);
	if (   sup_state == NM_SUPPLICANT_INTERFACE_CON_STATE_ASSOCIATING
	    || sup_state == NM_SUPPLICANT_INTERFACE_CON_STATE_ASSOCIATED
	    || sup_state == NM_SUPPLICANT_INTERFACE_CON_STATE_4WAY_HANDSHAKE
	    || sup_state == NM_SUPPLICANT_INTERFACE_CON_STATE_GROUP_HANDSHAKE
	    || nm_supplicant_interface_get_scanning (priv->supplicant.iface))
		return FALSE;

	req = nm_device_get_act_request (NM_DEVICE (self));
	if (req) {
		NMConnection *connection;
		NMSettingIP4Config *s_ip4;
		NMSettingWireless *s_wifi;
		const char *ip4_method = NULL;
		const GByteArray *bssid;

		/* Don't scan when a shared connection is active; it makes drivers mad */
		connection = nm_act_request_get_connection (req);
		s_ip4 = (NMSettingIP4Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG);
		if (s_ip4)
			ip4_method = nm_setting_ip4_config_get_method (s_ip4);

		if (s_ip4 && !strcmp (ip4_method, NM_SETTING_IP4_CONFIG_METHOD_SHARED))
			return FALSE;

		/* Don't scan when the connection is locked to a specifc AP, since
		 * intra-ESS roaming (which requires periodic scanning) isn't being
		 * used due to the specific AP lock. (bgo #513820)
		 */
		s_wifi = (NMSettingWireless *) nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS);
		g_assert (s_wifi);
		bssid = nm_setting_wireless_get_bssid (s_wifi);
		if (bssid && bssid->len == ETH_ALEN)
			return FALSE;
	}

	return TRUE;
}

static gboolean
scanning_allowed_accumulator (GSignalInvocationHint *ihint,
                              GValue *return_accu,
                              const GValue *handler_return,
                              gpointer data)
{
	if (!g_value_get_boolean (handler_return))
		g_value_set_boolean (return_accu, FALSE);
	return TRUE;
}

static gboolean
check_scanning_allowed (NMDeviceWifi *self)
{
	GValue instance = { 0, };
	GValue retval = { 0, };

	g_value_init (&instance, G_TYPE_OBJECT);
	g_value_take_object (&instance, self);

	g_value_init (&retval, G_TYPE_BOOLEAN);
	g_value_set_boolean (&retval, TRUE);

	/* Use g_signal_emitv() rather than g_signal_emit() to avoid the return
	 * value being changed if no handlers are connected */
	g_signal_emitv (&instance, signals[SCANNING_ALLOWED], 0, &retval);

	return g_value_get_boolean (&retval);
}

static gboolean
request_wireless_scan (gpointer user_data)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (user_data);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	gboolean backoff = FALSE;

	if (check_scanning_allowed (self)) {
		nm_log_dbg (LOGD_WIFI_SCAN, "(%s): scanning requested",
		            nm_device_get_iface (NM_DEVICE (self)));

		if (nm_supplicant_interface_request_scan (priv->supplicant.iface)) {
			/* success */
			backoff = TRUE;
		}
	} else {
		nm_log_dbg (LOGD_WIFI_SCAN, "(%s): scan requested but not allowed at this time",
		            nm_device_get_iface (NM_DEVICE (self)));
	}

	priv->pending_scan_id = 0;
	schedule_scan (self, backoff);
	return FALSE;
}


/*
 * schedule_scan
 *
 * Schedule a wireless scan.
 *
 */
static void
schedule_scan (NMDeviceWifi *self, gboolean backoff)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	GTimeVal now;

	g_get_current_time (&now);

	/* Cancel the pending scan if it would happen later than (now + the scan_interval) */
	if (priv->pending_scan_id) {
		if (now.tv_sec + priv->scan_interval < priv->scheduled_scan_time)
			cancel_pending_scan (self);
	}

	if (!priv->pending_scan_id) {
		guint factor = 2, next_scan = priv->scan_interval;

		if (    nm_device_is_activating (NM_DEVICE (self))
		    || (nm_device_get_state (NM_DEVICE (self)) == NM_DEVICE_STATE_ACTIVATED))
			factor = 1;

		priv->pending_scan_id = g_timeout_add_seconds (next_scan,
		                                               request_wireless_scan,
		                                               self);

		priv->scheduled_scan_time = now.tv_sec + priv->scan_interval;
		if (backoff && (priv->scan_interval < (SCAN_INTERVAL_MAX / factor))) {
				priv->scan_interval += (SCAN_INTERVAL_STEP / factor);
				/* Ensure the scan interval will never be less than 20s... */
				priv->scan_interval = MAX(priv->scan_interval, SCAN_INTERVAL_MIN + SCAN_INTERVAL_STEP);
				/* ... or more than 120s */
				priv->scan_interval = MIN(priv->scan_interval, SCAN_INTERVAL_MAX);
		} else if (!backoff && (priv->scan_interval == 0)) {
			/* Invalid combination; would cause continual rescheduling of
			 * the scan and hog CPU.  Reset to something minimally sane.
			 */
			priv->scan_interval = 5;
		}

		nm_log_dbg (LOGD_WIFI_SCAN, "(%s): scheduled scan in %d seconds (interval now %d seconds)",
		            nm_device_get_iface (NM_DEVICE (self)),
		            next_scan,
		            priv->scan_interval);

	}
}


static void
cancel_pending_scan (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	if (priv->pending_scan_id) {
		g_source_remove (priv->pending_scan_id);
		priv->pending_scan_id = 0;
	}
}


static void
supplicant_iface_scan_request_result_cb (NMSupplicantInterface *iface,
                                         gboolean success,
                                         NMDeviceWifi *self)
{
	nm_log_dbg (LOGD_WIFI_SCAN, "(%s): scan request %s",
	            nm_device_get_iface (NM_DEVICE (self)),
	            success ? "successful" : "failed");

	if (check_scanning_allowed (self))
		schedule_scan (self, TRUE);
}

static void
supplicant_iface_scan_results_cb (NMSupplicantInterface *iface,
                                  guint32 num_results,
                                  NMDeviceWifi *self)
{
	nm_log_dbg (LOGD_WIFI_SCAN, "(%s): scan results available (%d APs found)",
	            nm_device_get_iface (NM_DEVICE (self)),
	            num_results);
	if (num_results == 0) {
		/* ensure that old APs get culled, which otherwise only
		 * happens when there are actual scan results to process.
		 */
		cull_scan_list (self);
		nm_device_wifi_ap_list_print (self);
	}
}

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

	if (nm_ap_get_mode (ap) == NM_802_11_MODE_ADHOC)
		goto out;

	/* Static WEP */
	if (   (flags & NM_802_11_AP_FLAGS_PRIVACY)
        && (wpa_flags == NM_802_11_AP_SEC_NONE)
        && (rsn_flags == NM_802_11_AP_SEC_NONE)) {
		NMSettingWirelessSecurity *s_wireless_sec;
		const char *auth_alg;

		/* No way to tell if the key is wrong with Open System
		 * auth mode in WEP.  Auth is not enforced like Shared Key.
		 */
		s_wireless_sec = (NMSettingWirelessSecurity *) nm_connection_get_setting (connection, 
																    NM_TYPE_SETTING_WIRELESS_SECURITY);
		if (s_wireless_sec) {
			auth_alg = nm_setting_wireless_security_get_auth_alg (s_wireless_sec);
			if (!auth_alg || !strcmp (auth_alg, "open"))
				goto out;
		}

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
merge_scanned_ap (NMDeviceWifi *self,
                  NMAccessPoint *merge_ap)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMAccessPoint *found_ap = NULL;
	const GByteArray *ssid;
	gboolean strict_match = TRUE;
	NMAccessPoint *current_ap = NULL;

	/* Let the manager try to fill in the SSID from seen-bssids lists
	 * if it can
	 */
	ssid = nm_ap_get_ssid (merge_ap);
	if (!ssid || nm_utils_is_empty_ssid (ssid->data, ssid->len)) {
		g_signal_emit (self, signals[HIDDEN_AP_FOUND], 0, merge_ap);
		nm_ap_set_broadcast (merge_ap, FALSE);
	}

	/* If the incoming scan result matches the hidden AP that NM is currently
	 * connected to but hasn't been seen in the scan list yet, don't use
	 * strict matching.  Because the capabilities of the fake AP have to be
	 * constructed from the NMConnection of the activation request, they won't
	 * always be the same as the capabilities of the real AP from the scan.
	 */
	current_ap = nm_device_wifi_get_activation_ap (self);
	if (current_ap && nm_ap_get_fake (current_ap))
		strict_match = FALSE;

	found_ap = nm_ap_match_in_list (merge_ap, priv->ap_list, strict_match);
	if (found_ap) {
		nm_ap_set_flags (found_ap, nm_ap_get_flags (merge_ap));
		nm_ap_set_wpa_flags (found_ap, nm_ap_get_wpa_flags (merge_ap));
		nm_ap_set_rsn_flags (found_ap, nm_ap_get_rsn_flags (merge_ap));
		nm_ap_set_strength (found_ap, nm_ap_get_strength (merge_ap));
		nm_ap_set_last_seen (found_ap, nm_ap_get_last_seen (merge_ap));
		nm_ap_set_broadcast (found_ap, nm_ap_get_broadcast (merge_ap));
		nm_ap_set_freq (found_ap, nm_ap_get_freq (merge_ap));
		nm_ap_set_max_bitrate (found_ap, nm_ap_get_max_bitrate (merge_ap));

		/* If the AP is noticed in a scan, it's automatically no longer
		 * fake, since it clearly exists somewhere.
		 */
		nm_ap_set_fake (found_ap, FALSE);
	} else {
		/* New entry in the list */
		// FIXME: figure out if reference counts are correct here for AP objects
		g_object_ref (merge_ap);
		priv->ap_list = g_slist_prepend (priv->ap_list, merge_ap);
		nm_ap_export_to_dbus (merge_ap);
		g_signal_emit (self, signals[ACCESS_POINT_ADDED], 0, merge_ap);
	}
}

static void
cull_scan_list (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv;
	GTimeVal cur_time;
	GSList *outdated_list = NULL;
	GSList *elt;
	NMActRequest *req;
	const char *cur_ap_path = NULL;
	guint32 removed = 0, total = 0;

	g_return_if_fail (self != NULL);
	priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	g_get_current_time (&cur_time);

	req = nm_device_get_act_request (NM_DEVICE (self));
	if (req)
		cur_ap_path = nm_act_request_get_specific_object (req);

	nm_log_dbg (LOGD_WIFI_SCAN, "(%s): checking scan list for outdated APs",
	            nm_device_get_iface (NM_DEVICE (self)));

	/* Walk the access point list and remove any access points older than
	 * three times the inactive scan interval.
	 */
	for (elt = priv->ap_list; elt; elt = g_slist_next (elt), total++) {
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
		NMAccessPoint *outdated_ap = NM_AP (elt->data);
		const struct ether_addr *bssid;
		const GByteArray *ssid;

		bssid = nm_ap_get_address (outdated_ap);
		ssid = nm_ap_get_ssid (outdated_ap);
		nm_log_dbg (LOGD_WIFI_SCAN,
		            "   removing %02x:%02x:%02x:%02x:%02x:%02x (%s%s%s)",
		            bssid->ether_addr_octet[0], bssid->ether_addr_octet[1],
		            bssid->ether_addr_octet[2], bssid->ether_addr_octet[3],
		            bssid->ether_addr_octet[4], bssid->ether_addr_octet[5],
		            ssid ? "'" : "",
		            ssid ? nm_utils_escape_ssid (ssid->data, ssid->len) : "(none)",
		            ssid ? "'" : "");

		access_point_removed (self, outdated_ap);
		priv->ap_list = g_slist_remove (priv->ap_list, outdated_ap);
		g_object_unref (outdated_ap);
		removed++;
	}
	g_slist_free (outdated_list);

	nm_log_dbg (LOGD_WIFI_SCAN, "(%s): removed %d APs (of %d)",
	            nm_device_get_iface (NM_DEVICE (self)),
	            removed, total);
}

#define SET_QUALITY_MEMBER(qual_item, lc_member, uc_member) \
	if (lc_member != -1) { \
		qual_item.lc_member = lc_member; \
		qual_item.updated |= IW_QUAL_##uc_member##_UPDATED; \
	} else { \
		qual_item.updated |= IW_QUAL_##uc_member##_INVALID; \
	}

static void
set_ap_strength_from_properties (NMDeviceWifi *self,
                                 NMAccessPoint *ap,
                                 GHashTable *properties)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	int qual, level, noise;
	struct iw_quality quality;
	GValue *value;
	gint8 strength;

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

	strength = wireless_qual_to_percent (&quality, &priv->max_qual);
	nm_ap_set_strength (ap, strength);
}

static void
supplicant_iface_scanned_ap_cb (NMSupplicantInterface *iface,
                                GHashTable *properties,
                                NMDeviceWifi *self)
{
	NMDeviceState state;
	NMAccessPoint *ap;

	g_return_if_fail (self != NULL);
	g_return_if_fail (properties != NULL);
	g_return_if_fail (iface != NULL);

	/* Ignore new APs when unavailable or unamnaged */
	state = nm_device_get_state (NM_DEVICE (self));
	if (state <= NM_DEVICE_STATE_UNAVAILABLE)
		return;

	ap = nm_ap_new_from_properties (properties);
	if (ap) {
		set_ap_strength_from_properties (self, ap, properties);

		nm_ap_print_self (ap, "AP: ");

		/* Add the AP to the device's AP list */
		merge_scanned_ap (self, ap);
		g_object_unref (ap);

		/* Remove outdated access points */
		cull_scan_list (self);

		nm_device_wifi_ap_list_print (self);
	} else {
		nm_log_warn (LOGD_WIFI_SCAN, "(%s): invalid AP properties received",
		             nm_device_get_iface (NM_DEVICE (self)));
	}
}


static void
cleanup_association_attempt (NMDeviceWifi *self, gboolean disconnect)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	remove_supplicant_interface_error_handler (self);
	remove_supplicant_timeouts (self);
	if (disconnect && priv->supplicant.iface)
		nm_supplicant_interface_disconnect (priv->supplicant.iface);
}


static void
remove_link_timeout (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv;

	g_return_if_fail (self != NULL);
	priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	if (priv->link_timeout_id) {
		g_source_remove (priv->link_timeout_id);
		priv->link_timeout_id = 0;
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
	NMDeviceWifi * self = NM_DEVICE_WIFI (dev);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMActRequest *          req = NULL;
	NMAccessPoint *         ap = NULL;
	NMConnection *          connection;
	const char *            setting_name;
	gboolean                auth_enforced, encrypted = FALSE;

	g_assert (dev);

	priv->link_timeout_id = 0;

	req = nm_device_get_act_request (dev);
	ap = nm_device_wifi_get_activation_ap (self);
	if (req == NULL || ap == NULL) {
		/* shouldn't ever happen */
		nm_log_err (LOGD_WIFI, "couldn't get activation request or activation AP.");
		if (nm_device_is_activating (dev)) {
			cleanup_association_attempt (self, TRUE);
			nm_device_state_changed (dev, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_NONE);
		}
		return FALSE;
	}

	/* Disconnect event while activated; the supplicant hasn't been able
	 * to reassociate within the timeout period, so the connection must
	 * fail.
	 */
	if (nm_device_get_state (dev) == NM_DEVICE_STATE_ACTIVATED) {
		nm_device_state_changed (dev, NM_DEVICE_STATE_DISCONNECTED, NM_DEVICE_STATE_REASON_SUPPLICANT_TIMEOUT);
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

	/* Drivers are still just too crappy, and emit too many disassociation
	 * events during connection.  So for now, just let the driver and supplicant
	 * keep trying to associate, and don't ask for new secrets when we get
	 * disconnected during association.
	 */
	if (0) {
		nm_connection_clear_secrets (connection);
		setting_name = nm_connection_need_secrets (connection, NULL);
		if (!setting_name)
			goto time_out;

		/* Association/authentication failed during association, probably have a 
		 * bad encryption key and the authenticating entity (AP, RADIUS server, etc)
		 * denied the association due to bad credentials.
		 */
		nm_log_info (LOGD_DEVICE | LOGD_WIFI,
		             "Activation (%s/wireless): disconnected during association,"
		             " asking for new key.", nm_device_get_iface (dev));
		cleanup_association_attempt (self, TRUE);
		nm_device_state_changed (dev, NM_DEVICE_STATE_NEED_AUTH, NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT);
		nm_act_request_get_secrets (req,
		                            setting_name,
		                            TRUE,
		                            SECRETS_CALLER_WIFI,
		                            NULL,
		                            NULL);

		return FALSE;
	}

time_out:
	nm_log_warn (LOGD_WIFI, "(%s): link timed out.", nm_device_get_iface (dev));
	return FALSE;
}

static gboolean
schedule_state_handler (NMDeviceWifi *self,
                        GSourceFunc handler,
                        guint32 new_state,
                        guint32 old_state,
                        gboolean mgr_task)
{
	NMDeviceWifiPrivate *priv;
	SupplicantStateTask *task;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (handler != NULL, FALSE);

	if (new_state == old_state)
		return TRUE;

	priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	task = g_slice_new0 (SupplicantStateTask);
	if (!task) {
		nm_log_err (LOGD_WIFI, "Not enough memory to process supplicant manager state change.");
		return FALSE;
	}

	task->self = self;
	task->new_state = new_state;
	task->old_state = old_state;
	task->mgr_task = mgr_task;

	task->source_id = g_idle_add (handler, task);
	if (mgr_task)
		priv->supplicant.mgr_tasks = g_slist_append (priv->supplicant.mgr_tasks, task);
	else
		priv->supplicant.iface_tasks = g_slist_append (priv->supplicant.iface_tasks, task);

	return TRUE;
}

static gboolean
supplicant_iface_state_cb_handler (gpointer user_data)
{
	SupplicantStateTask *task = (SupplicantStateTask *) user_data;
	NMDeviceWifi *self;
	NMDeviceWifiPrivate *priv;

	g_return_val_if_fail (task != NULL, FALSE);

	self = task->self;
	priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	nm_log_info (LOGD_WIFI, "(%s): supplicant interface state:  %s -> %s",
	             nm_device_get_iface (NM_DEVICE (self)),
	             nm_supplicant_interface_state_to_string (task->old_state),
	             nm_supplicant_interface_state_to_string (task->new_state));

	if (task->new_state == NM_SUPPLICANT_INTERFACE_STATE_READY) {
		priv->scan_interval = SCAN_INTERVAL_MIN;

		/* If the interface can now be activated because the supplicant is now
		 * available, transition to DISCONNECTED.
		 */
		if (   (nm_device_get_state (NM_DEVICE (self)) == NM_DEVICE_STATE_UNAVAILABLE)
		    && nm_device_is_available (NM_DEVICE (self))) {
			nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_DISCONNECTED,
			                         NM_DEVICE_STATE_REASON_SUPPLICANT_AVAILABLE);
		}

		nm_log_dbg (LOGD_WIFI_SCAN, "(%s): supplicant ready, requesting initial scan",
		            nm_device_get_iface (NM_DEVICE (self)));

		/* Request a scan to get latest results */
		cancel_pending_scan (self);
		request_wireless_scan (self);
	} else if (task->new_state == NM_SUPPLICANT_INTERFACE_STATE_DOWN) {
		cleanup_association_attempt (self, FALSE);
		supplicant_interface_release (self);
		nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_UNAVAILABLE,
		                         NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
	}

	finish_supplicant_task (task, FALSE);
	return FALSE;
}


static void
supplicant_iface_state_cb (NMSupplicantInterface * iface,
                           guint32 new_state,
                           guint32 old_state,
                           NMDeviceWifi *self)
{
	g_return_if_fail (self != NULL);

	schedule_state_handler (self,
	                        supplicant_iface_state_cb_handler,
	                        new_state,
	                        old_state,
	                        FALSE);
}


static gboolean
supplicant_iface_connection_state_cb_handler (gpointer user_data)
{
	SupplicantStateTask *task = (SupplicantStateTask *) user_data;
	NMDeviceWifi *self = task->self;
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMDevice *dev = NM_DEVICE (self);
	gboolean scanning;

	if (!nm_device_get_act_request (dev)) {
		/* The device is not activating or already activated; do nothing. */
		goto out;
	}

	nm_log_info (LOGD_WIFI, "(%s): supplicant connection state:  %s -> %s",
	             nm_device_get_iface (dev),
	             nm_supplicant_interface_connection_state_to_string (task->old_state),
	             nm_supplicant_interface_connection_state_to_string (task->new_state));

	scanning = nm_supplicant_interface_get_scanning (priv->supplicant.iface);

	if (task->new_state == NM_SUPPLICANT_INTERFACE_CON_STATE_COMPLETED) {
		remove_supplicant_interface_error_handler (self);
		remove_supplicant_timeouts (self);

		/* If this is the initial association during device activation,
		 * schedule the next activation stage.
		 */
		if (nm_device_get_state (dev) == NM_DEVICE_STATE_CONFIG) {
			NMAccessPoint *ap = nm_device_wifi_get_activation_ap (self);
			const GByteArray * ssid = nm_ap_get_ssid (ap);

			nm_log_info (LOGD_DEVICE | LOGD_WIFI,
			             "Activation (%s/wireless) Stage 2 of 5 (Device Configure) "
			             "successful.  Connected to wireless network '%s'.",
			             nm_device_get_iface (dev),
			             ssid ? nm_utils_escape_ssid (ssid->data, ssid->len) : "(none)");
			nm_device_activate_schedule_stage3_ip_config_start (dev);
		}
	} else if (task->new_state == NM_SUPPLICANT_INTERFACE_CON_STATE_DISCONNECTED) {
		if (nm_device_get_state (dev) == NM_DEVICE_STATE_ACTIVATED || nm_device_is_activating (dev)) {
			/* Start the link timeout so we allow some time for reauthentication,
			 * use a longer timeout if we are scanning since some cards take a
			 * while to scan.
			 */
			if (!priv->link_timeout_id) {
				priv->link_timeout_id = g_timeout_add_seconds (scanning ? 30 : 15,
				                                               link_timeout_cb, self);
			}
		}
	}

out:
	/* Signal scanning state changes */
	if (   task->new_state == NM_SUPPLICANT_INTERFACE_CON_STATE_SCANNING
	    || task->old_state == NM_SUPPLICANT_INTERFACE_CON_STATE_SCANNING)
		g_object_notify (G_OBJECT (self), "scanning");

	finish_supplicant_task (task, FALSE);
	return FALSE;
}


static void
supplicant_iface_connection_state_cb (NMSupplicantInterface * iface,
                                      guint32 new_state,
                                      guint32 old_state,
                                      NMDeviceWifi *self)
{
	g_return_if_fail (self != NULL);

	schedule_state_handler (self,
	                        supplicant_iface_connection_state_cb_handler,
	                        new_state,
	                        old_state,
	                        FALSE);
}


static gboolean
supplicant_mgr_state_cb_handler (gpointer user_data)
{
	SupplicantStateTask *task = (SupplicantStateTask *) user_data;
	NMDeviceWifi *self;
	NMDeviceWifiPrivate *priv;
	NMDevice *dev;
	NMDeviceState dev_state;

	g_return_val_if_fail (task != NULL, FALSE);

	self = task->self;
	priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	dev = NM_DEVICE (self);

	nm_log_info (LOGD_WIFI, "(%s): supplicant manager state:  %s -> %s",
	             nm_device_get_iface (NM_DEVICE (self)),
	             nm_supplicant_manager_state_to_string (task->old_state),
	             nm_supplicant_manager_state_to_string (task->new_state));

	/* If the supplicant went away, release the supplicant interface */
	if (task->new_state == NM_SUPPLICANT_MANAGER_STATE_DOWN) {
		if (priv->supplicant.iface) {
			cleanup_association_attempt (self, FALSE);
			supplicant_interface_release (self);
		}

		if (nm_device_get_state (dev) > NM_DEVICE_STATE_UNAVAILABLE) {
			nm_device_state_changed (dev, NM_DEVICE_STATE_UNAVAILABLE,
			                         NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
		}
	} else if (task->new_state == NM_SUPPLICANT_MANAGER_STATE_IDLE) {
		dev_state = nm_device_get_state (dev);
		if (    priv->enabled
		    && !priv->supplicant.iface
		    && (dev_state >= NM_DEVICE_STATE_UNAVAILABLE)
		    && (nm_device_get_firmware_missing (NM_DEVICE (self)) == FALSE)) {
			/* request a supplicant interface from the supplicant manager */
			supplicant_interface_acquire (self);

			/* if wireless is enabled and we have a supplicant interface,
			 * we can transition to the DISCONNECTED state.
			 */
			if (priv->supplicant.iface) {
				nm_device_state_changed (dev, NM_DEVICE_STATE_DISCONNECTED,
				                         NM_DEVICE_STATE_REASON_NONE);
			}
		}
	}

	finish_supplicant_task (task, FALSE);
	return FALSE;
}

static void
supplicant_mgr_state_cb (NMSupplicantInterface * iface,
                         guint32 new_state,
                         guint32 old_state,
                         NMDeviceWifi *self)
{
	g_return_if_fail (self != NULL);

	schedule_state_handler (self,
	                        supplicant_mgr_state_cb_handler,
	                        new_state,
	                        old_state,
	                        TRUE);
}

struct iface_con_error_cb_data {
	NMDeviceWifi *self;
	char *name;
	char *message;
};

static gboolean
supplicant_iface_connection_error_cb_handler (gpointer user_data)
{
	NMDeviceWifi *self;
	NMDeviceWifiPrivate *priv;
	struct iface_con_error_cb_data * cb_data = (struct iface_con_error_cb_data *) user_data;

	g_return_val_if_fail (cb_data != NULL, FALSE);

	self = cb_data->self;
	priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	if (!nm_device_is_activating (NM_DEVICE (self)))
		goto out;

	nm_log_info (LOGD_DEVICE | LOGD_WIFI,
	             "Activation (%s/wireless): association request to the supplicant "
	             "failed: %s - %s",
	             nm_device_get_iface (NM_DEVICE (self)),
	             cb_data->name,
	             cb_data->message);

	cleanup_association_attempt (self, TRUE);
	nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);

out:
	priv->supplicant.iface_con_error_cb_id = 0;
	g_free (cb_data->name);
	g_free (cb_data->message);
	g_slice_free (struct iface_con_error_cb_data, cb_data);
	return FALSE;
}


static void
supplicant_iface_connection_error_cb (NMSupplicantInterface * iface,
                                      const char * name,
                                      const char * message,
                                      NMDeviceWifi * self)
{
	NMDeviceWifiPrivate *priv;
	struct iface_con_error_cb_data *cb_data;
	guint id;

	g_return_if_fail (self != NULL);
	priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	cb_data = g_slice_new0 (struct iface_con_error_cb_data);
	if (cb_data == NULL) {
		nm_log_err (LOGD_WIFI, "Not enough memory to process supplicant connection error.");
		return;
	}

	cb_data->self = self;
	cb_data->name = g_strdup (name);
	cb_data->message = g_strdup (message);

	if (priv->supplicant.iface_con_error_cb_id)
		g_source_remove (priv->supplicant.iface_con_error_cb_id);

	id = g_idle_add (supplicant_iface_connection_error_cb_handler, cb_data);
	priv->supplicant.iface_con_error_cb_id = id;
}

static void
supplicant_iface_notify_scanning_cb (NMSupplicantInterface *iface,
                                     GParamSpec *pspec,
                                     NMDeviceWifi *self)
{
	gboolean scanning;

	scanning = nm_supplicant_interface_get_scanning (iface);
	nm_log_dbg (LOGD_WIFI_SCAN, "(%s): now %s",
	            nm_device_get_iface (NM_DEVICE (self)),
	            scanning ? "scanning" : "not scanning");

	g_object_notify (G_OBJECT (self), "scanning");
}

static void
remove_supplicant_connection_timeout (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv;

	g_return_if_fail (self != NULL);
	priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	/* Remove any pending timeouts on the request */
	if (priv->supplicant.con_timeout_id) {
		g_source_remove (priv->supplicant.con_timeout_id);
		priv->supplicant.con_timeout_id = 0;
	}
}

static NMActStageReturn
handle_auth_or_fail (NMDeviceWifi *self,
                     NMActRequest *req,
                     gboolean new_secrets)
{
	const char *setting_name;
	guint32 tries;
	NMAccessPoint *ap;
	NMConnection *connection;

	g_return_val_if_fail (NM_IS_DEVICE_WIFI (self), NM_ACT_STAGE_RETURN_FAILURE);

	if (!req) {
		req = nm_device_get_act_request (NM_DEVICE (self));
		g_assert (req);
	}

	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	ap = nm_device_wifi_get_activation_ap (self);
	g_assert (ap);

	tries = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (connection), WIRELESS_SECRETS_TRIES));
	if (tries > 3)
		return NM_ACT_STAGE_RETURN_FAILURE;

	nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_NEED_AUTH, NM_DEVICE_STATE_REASON_NONE);

	nm_connection_clear_secrets (connection);
	setting_name = nm_connection_need_secrets (connection, NULL);
	if (setting_name) {
		gboolean get_new;

		/* If the caller doesn't necessarily want completely new secrets,
		 * only ask for new secrets after the first failure.
		 */
		get_new = new_secrets ? TRUE : (tries ? TRUE : FALSE);
		nm_act_request_get_secrets (req,
		                            setting_name,
		                            get_new,
		                            SECRETS_CALLER_WIFI,
		                            NULL,
		                            NULL);

		g_object_set_data (G_OBJECT (connection), WIRELESS_SECRETS_TRIES, GUINT_TO_POINTER (++tries));
	} else {
		nm_log_warn (LOGD_DEVICE, "Cleared secrets, but setting didn't need any secrets.");
	}
	return NM_ACT_STAGE_RETURN_POSTPONE;
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
	NMDeviceWifi * self = NM_DEVICE_WIFI (user_data);
	NMAccessPoint *         ap;
	NMActRequest *          req;
	gboolean                auth_enforced = FALSE, encrypted = FALSE;
	NMConnection *connection;

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

	ap = nm_device_wifi_get_activation_ap (self);
	g_assert (ap);

	auth_enforced = ap_auth_enforced (connection, ap, &encrypted);
	if (!encrypted) {
		nm_log_warn (LOGD_DEVICE | LOGD_WIFI,
		             "Activation (%s/wireless): association took too long, "
		             "failing activation.",
		             nm_device_get_iface (dev));
		nm_device_state_changed (dev, NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_SUPPLICANT_TIMEOUT);
	} else {
		/* Authentication failed, encryption key is probably bad */
		nm_log_warn (LOGD_DEVICE | LOGD_WIFI,
		             "Activation (%s/wireless): association took too long.",
		             nm_device_get_iface (dev));

		if (handle_auth_or_fail (self, req, TRUE) == NM_ACT_STAGE_RETURN_POSTPONE) {
			nm_log_warn (LOGD_DEVICE | LOGD_WIFI,
			             "Activation (%s/wireless): asking for new secrets",
			             nm_device_get_iface (dev));
		} else {
			nm_device_state_changed (dev, NM_DEVICE_STATE_FAILED,
			                         NM_DEVICE_STATE_REASON_NO_SECRETS);
		}
	}

	return FALSE;
}


static gboolean
start_supplicant_connection_timeout (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv;
	guint id;

	g_return_val_if_fail (self != NULL, FALSE);

	priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	/* Set up a timeout on the connection attempt to fail it after 25 seconds */
	id = g_timeout_add_seconds (25, supplicant_connection_timeout_cb, self);
	if (id == 0) {
		nm_log_err (LOGD_DEVICE | LOGD_WIFI,
		            "Activation (%s/wireless): couldn't start supplicant "
		            "timeout timer.",
		            nm_device_get_iface (NM_DEVICE (self)));
		return FALSE;
	}
	priv->supplicant.con_timeout_id = id;
	return TRUE;
}


static void
remove_supplicant_timeouts (NMDeviceWifi *self)
{
	g_return_if_fail (self != NULL);

	remove_supplicant_connection_timeout (self);
	remove_link_timeout (self);
}

static guint32
find_supported_frequency (NMDeviceWifi *self, guint32 *freqs)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
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
build_supplicant_config (NMDeviceWifi *self,
                         NMConnection *connection,
                         NMAccessPoint *ap)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMSupplicantConfig *config = NULL;
	NMSettingWireless *s_wireless;
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
	if ((nm_ap_get_mode (ap) == NM_802_11_MODE_ADHOC) && nm_ap_get_user_created (ap)) {
		const char *band = nm_setting_wireless_get_band (s_wireless);

		adhoc_freq = nm_ap_get_freq (ap);
		if (!adhoc_freq) {
			if (band && !strcmp (band, "a")) {
				guint32 a_freqs[] = {5180, 5200, 5220, 5745, 5765, 5785, 5805, 0};
				adhoc_freq = find_supported_frequency (self, a_freqs);
			} else {
				guint32 bg_freqs[] = {2412, 2437, 2462, 2472, 0};
				adhoc_freq = find_supported_frequency (self, bg_freqs);
			}
		}

		if (!adhoc_freq) {
			if (band && !strcmp (band, "a"))
				adhoc_freq = 5180;
			else
				adhoc_freq = 2462;
		}
	}

	if (!nm_supplicant_config_add_setting_wireless (config,
	                                                s_wireless,
	                                                nm_ap_get_broadcast (ap),
	                                                adhoc_freq,
	                                                priv->has_scan_capa_ssid)) {
		nm_log_err (LOGD_WIFI, "Couldn't add 802-11-wireless setting to supplicant config.");
		goto error;
	}

	s_wireless_sec = (NMSettingWirelessSecurity *) nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS_SECURITY);
	if (s_wireless_sec) {
		NMSetting8021x *s_8021x;
		const char *con_path = nm_connection_get_path (connection);

		g_assert (con_path);
		s_8021x = (NMSetting8021x *) nm_connection_get_setting (connection, NM_TYPE_SETTING_802_1X);
		if (!nm_supplicant_config_add_setting_wireless_security (config,
		                                                         s_wireless_sec,
		                                                         s_8021x,
		                                                         con_path)) {
			nm_log_err (LOGD_WIFI, "Couldn't add 802-11-wireless-security setting to "
			            "supplicant config.");
			goto error;
		}
	} else {
		if (!nm_supplicant_config_add_no_security (config)) {
			nm_log_err (LOGD_WIFI, "Couldn't add unsecured option to supplicant config.");
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
real_update_hw_address (NMDevice *dev)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (dev);
	struct ifreq req;
	int fd;

	fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		nm_log_err (LOGD_HW, "could not open control socket.");
		return;
	}

	memset (&req, 0, sizeof (struct ifreq));
	strncpy (req.ifr_name, nm_device_get_iface (dev), IFNAMSIZ);
	errno = 0;
	if (ioctl (fd, SIOCGIFHWADDR, &req) < 0) {
		nm_log_err (LOGD_HW | LOGD_WIFI, "(%s): unable to read hardware address (error %d)",
		            nm_device_get_iface (dev), errno);
	} else
		_update_hw_addr (self, (const guint8 *) &req.ifr_hwaddr.sa_data);

	close (fd);
}

static void
real_update_permanent_hw_address (NMDevice *dev)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (dev);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	struct ifreq req;
	struct ethtool_perm_addr *epaddr = NULL;
	int fd, ret;

	fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		nm_log_err (LOGD_HW, "could not open control socket.");
		return;
	}

	/* Get permanent MAC address */
	memset (&req, 0, sizeof (struct ifreq));
	strncpy (req.ifr_name, nm_device_get_iface (dev), IFNAMSIZ);

	epaddr = g_malloc0 (sizeof (struct ethtool_perm_addr) + ETH_ALEN);
	epaddr->cmd = ETHTOOL_GPERMADDR;
	epaddr->size = ETH_ALEN;
	req.ifr_data = (void *) epaddr;

	errno = 0;
	ret = ioctl (fd, SIOCETHTOOL, &req);
	if ((ret < 0) || !nm_ethernet_address_is_valid ((struct ether_addr *) epaddr->data)) {
		nm_log_err (LOGD_HW | LOGD_ETHER, "(%s): unable to read permanent MAC address (error %d)",
		            nm_device_get_iface (dev), errno);
		/* Fall back to current address */
		memcpy (epaddr->data, &priv->hw_addr, ETH_ALEN);
	}

	if (memcmp (&priv->perm_hw_addr, epaddr->data, ETH_ALEN)) {
		memcpy (&priv->perm_hw_addr, epaddr->data, ETH_ALEN);
		g_object_notify (G_OBJECT (dev), NM_DEVICE_WIFI_PERMANENT_HW_ADDRESS);
	}

	g_free (epaddr);
	close (fd);
}


static NMActStageReturn
real_act_stage1_prepare (NMDevice *dev, NMDeviceStateReason *reason)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (dev);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMAccessPoint *ap = NULL;
	NMActRequest *req;
	NMConnection *connection;
	NMSettingWireless *s_wireless;
	const GByteArray *cloned_mac;
	GSList *iter;

	req = nm_device_get_act_request (NM_DEVICE (self));
	g_return_val_if_fail (req != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	connection = nm_act_request_get_connection (req);
	g_return_val_if_fail (connection != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	/* Set spoof MAC to the interface */
	s_wireless = (NMSettingWireless *) nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS);
	g_assert (s_wireless);

	cloned_mac = nm_setting_wireless_get_cloned_mac_address (s_wireless);
	if (cloned_mac && (cloned_mac->len == ETH_ALEN))
		_set_hw_addr (self, (const guint8 *) cloned_mac->data, "set");

	/* If the user is trying to connect to an AP that NM doesn't yet know about
	 * (hidden network or something), create an fake AP from the security
	 * settings in the connection to use until the AP is recognized from the
	 * scan list, which should show up when the connection is successful.
	 */
	ap = nm_device_wifi_get_activation_ap (self);
	if (ap)
		goto done;

	/* Find a compatible AP in the scan list */
	for (iter = priv->ap_list; iter; iter = g_slist_next (iter)) {
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
			case NM_802_11_MODE_ADHOC:
				nm_ap_set_user_created (ap, TRUE);
				break;
			case NM_802_11_MODE_INFRA:
			default:
				nm_ap_set_broadcast (ap, FALSE);
				break;
		}

		priv->ap_list = g_slist_prepend (priv->ap_list, ap);
		nm_ap_export_to_dbus (ap);
		g_signal_emit (self, signals[ACCESS_POINT_ADDED], 0, ap);
	}

	nm_act_request_set_specific_object (req, nm_ap_get_dbus_path (ap));

done:
	set_current_ap (self, ap);
	return NM_ACT_STAGE_RETURN_SUCCESS;
}


static void
real_connection_secrets_updated (NMDevice *dev,
                                 NMConnection *connection,
                                 GSList *updated_settings,
                                 RequestSecretsCaller caller)
{
	NMActRequest *req;
	gboolean valid = FALSE;
	GSList *iter;

	g_return_if_fail (caller == SECRETS_CALLER_WIFI);

	if (nm_device_get_state (dev) != NM_DEVICE_STATE_NEED_AUTH)
		return;

	for (iter = updated_settings; iter; iter = g_slist_next (iter)) {
		const char *setting_name = (const char *) iter->data;

		if (   !strcmp (setting_name, NM_SETTING_WIRELESS_SECURITY_SETTING_NAME)
		    || !strcmp (setting_name, NM_SETTING_802_1X_SETTING_NAME)) {
			valid = TRUE;
		} else {
			nm_log_warn (LOGD_DEVICE, "Ignoring updated secrets for setting '%s'.",
			             setting_name);
		}
	}

	req = nm_device_get_act_request (dev);
	g_assert (req);

	g_return_if_fail (nm_act_request_get_connection (req) == connection);

	nm_device_activate_schedule_stage1_device_prepare (dev);
}

static NMActStageReturn
real_act_stage2_config (NMDevice *dev, NMDeviceStateReason *reason)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (dev);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;
	const char *iface = nm_device_get_iface (dev);
	NMSupplicantConfig *config = NULL;
	gulong id = 0;
	NMActRequest *req;
	NMAccessPoint *ap;
	NMConnection *connection;
	NMSettingConnection *s_connection;
	const char *setting_name;
	NMSettingWireless *s_wireless;

	g_return_val_if_fail (reason != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	remove_supplicant_timeouts (self);

	req = nm_device_get_act_request (dev);
	g_assert (req);

	ap = nm_device_wifi_get_activation_ap (self);
	g_assert (ap);

	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	s_connection = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
	g_assert (s_connection);

	s_wireless = (NMSettingWireless *) nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS);
	g_assert (s_wireless);

	/* If we need secrets, get them */
	setting_name = nm_connection_need_secrets (connection, NULL);
	if (setting_name) {
		nm_log_info (LOGD_DEVICE | LOGD_WIFI,
		             "Activation (%s/wireless): access point '%s' has security,"
		             " but secrets are required.",
		             iface, nm_setting_connection_get_id (s_connection));

		ret = handle_auth_or_fail (self, req, FALSE);
		if (ret == NM_ACT_STAGE_RETURN_FAILURE)
			*reason = NM_DEVICE_STATE_REASON_NO_SECRETS;
		goto out;
	}

	/* have secrets, or no secrets required */
	if (nm_setting_wireless_get_security (s_wireless)) {
		nm_log_info (LOGD_DEVICE | LOGD_WIFI,
		             "Activation (%s/wireless): connection '%s' has security"
		             ", and secrets exist.  No new secrets needed.",
		             iface, nm_setting_connection_get_id (s_connection));
	} else {
		nm_log_info (LOGD_DEVICE | LOGD_WIFI,
		             "Activation (%s/wireless): connection '%s' requires no "
		             "security.  No secrets needed.",
		             iface, nm_setting_connection_get_id (s_connection));
	}

	config = build_supplicant_config (self, connection, ap);
	if (config == NULL) {
		nm_log_err (LOGD_DEVICE | LOGD_WIFI,
		             "Activation (%s/wireless): couldn't build wireless configuration.",
		             iface);
		*reason = NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED;
		goto out;
	}

	/* Hook up error signal handler to capture association errors */
	id = g_signal_connect (priv->supplicant.iface,
	                       "connection-error",
	                       G_CALLBACK (supplicant_iface_connection_error_cb),
	                       self);
	priv->supplicant.iface_error_id = id;

	if (!nm_supplicant_interface_set_config (priv->supplicant.iface, config)) {
		nm_log_err (LOGD_DEVICE | LOGD_WIFI,
		            "Activation (%s/wireless): couldn't send wireless "
		            "configuration to the supplicant.", iface);
		*reason = NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED;
		goto out;
	}

	if (!start_supplicant_connection_timeout (self)) {
		*reason = NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED;
		goto out;
	}

	/* We'll get stage3 started when the supplicant connects */
	ret = NM_ACT_STAGE_RETURN_POSTPONE;

out:
	if (ret == NM_ACT_STAGE_RETURN_FAILURE)
		cleanup_association_attempt (self, TRUE);

	if (config) {
		/* Supplicant interface object refs the config; we no longer care about
		 * it after this function.
		 */
		g_object_unref (config);
	}
	return ret;
}

static NMActStageReturn
real_act_stage4_get_ip4_config (NMDevice *dev,
                                NMIP4Config **config,
                                NMDeviceStateReason *reason)
{
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;
	NMDeviceClass *parent_class;

	g_return_val_if_fail (config != NULL, NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (*config == NULL, NM_ACT_STAGE_RETURN_FAILURE);

	/* Chain up to parent */
	parent_class = NM_DEVICE_CLASS (nm_device_wifi_parent_class);
	ret = parent_class->act_stage4_get_ip4_config (dev, config, reason);

	if ((ret == NM_ACT_STAGE_RETURN_SUCCESS) && *config) {
		NMConnection *connection;
		NMSettingWireless *s_wireless;
		guint32 mtu;

		connection = nm_act_request_get_connection (nm_device_get_act_request (dev));
		g_assert (connection);
		s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS));
		g_assert (s_wireless);

		/* MTU override */
		mtu = nm_setting_wireless_get_mtu (s_wireless);
		if (mtu)
			nm_ip4_config_set_mtu (*config, mtu);
	}

	return ret;
}


static NMActStageReturn
handle_ip_config_timeout (NMDeviceWifi *self,
                          NMConnection *connection,
                          gboolean may_fail,
                          gboolean *chain_up,
                          NMDeviceStateReason *reason)
{
	NMAccessPoint *ap;
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;
	gboolean auth_enforced = FALSE, encrypted = FALSE;

	g_return_val_if_fail (connection != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	ap = nm_device_wifi_get_activation_ap (self);
	g_assert (ap);

	/* If nothing checks the security authentication information (as in
	 * Open System WEP for example), and DHCP times out, then
	 * the encryption key is likely wrong.  Ask the user for a new one.
	 * Otherwise the failure likely happened after a successful authentication.
	 */
	auth_enforced = ap_auth_enforced (connection, ap, &encrypted);
	if (encrypted && !auth_enforced && !may_fail) {
		NMSettingConnection *s_con;

		s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));

		/* Activation failed, we must have bad encryption key */
		nm_log_warn (LOGD_DEVICE | LOGD_WIFI,
		             "Activation (%s/wireless): could not get IP configuration for "
		             "connection '%s'.",
				     nm_device_get_iface (NM_DEVICE (self)),
				     nm_setting_connection_get_id (s_con));

		ret = handle_auth_or_fail (self, NULL, TRUE);
		if (ret == NM_ACT_STAGE_RETURN_POSTPONE) {
			nm_log_info (LOGD_DEVICE | LOGD_WIFI,
			             "Activation (%s/wireless): asking for new secrets",
			             nm_device_get_iface (NM_DEVICE (self)));
		} else {
			*reason = NM_DEVICE_STATE_REASON_NO_SECRETS;
		}
	} else {
		/* Non-encrypted network or authentication is enforced by some
		 * entity (AP, RADIUS server, etc), but IP configure failed. Let the
		 * superclass handle it.
		 */
		*chain_up = TRUE;
	}

	return ret;
}


static NMActStageReturn
real_act_stage4_ip4_config_timeout (NMDevice *dev,
                                    NMIP4Config **config,
                                    NMDeviceStateReason *reason)
{
	NMActRequest *req;
	NMConnection *connection;
	NMSettingIP4Config *s_ip4;
	gboolean may_fail = FALSE, chain_up = FALSE;
	NMActStageReturn ret;

	req = nm_device_get_act_request (dev);
	g_assert (req);
	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	s_ip4 = (NMSettingIP4Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG);
	if (s_ip4)
		may_fail = nm_setting_ip4_config_get_may_fail (s_ip4);

	ret = handle_ip_config_timeout (NM_DEVICE_WIFI (dev), connection, may_fail, &chain_up, reason);
	if (chain_up)
		ret = NM_DEVICE_CLASS (nm_device_wifi_parent_class)->act_stage4_ip4_config_timeout (dev, config, reason);

	return ret;
}

static NMActStageReturn
real_act_stage4_ip6_config_timeout (NMDevice *dev,
                                    NMIP6Config **config,
                                    NMDeviceStateReason *reason)
{
	NMActRequest *req;
	NMConnection *connection;
	NMSettingIP6Config *s_ip6;
	gboolean may_fail = FALSE, chain_up = FALSE;
	NMActStageReturn ret;

	req = nm_device_get_act_request (dev);
	g_assert (req);
	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	s_ip6 = (NMSettingIP6Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP6_CONFIG);
	if (s_ip6)
		may_fail = nm_setting_ip6_config_get_may_fail (s_ip6);

	ret = handle_ip_config_timeout (NM_DEVICE_WIFI (dev), connection, may_fail, &chain_up, reason);
	if (chain_up)
		ret = NM_DEVICE_CLASS (nm_device_wifi_parent_class)->act_stage4_ip6_config_timeout (dev, config, reason);

	return ret;
}

static void
activation_success_handler (NMDevice *dev)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (dev);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMAccessPoint *ap;
	struct ether_addr bssid = { {0x0, 0x0, 0x0, 0x0, 0x0, 0x0} };
	NMAccessPoint *tmp_ap;
	NMActRequest *req;
	NMConnection *connection;

	req = nm_device_get_act_request (dev);
	g_assert (req);

	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	/* Clear wireless secrets tries on success */
	g_object_set_data (G_OBJECT (connection), WIRELESS_SECRETS_TRIES, NULL);

	ap = nm_device_wifi_get_activation_ap (self);

	/* If the AP isn't fake, it was found in the scan list and all its
	 * details are known.
	 */
	if (!nm_ap_get_fake (ap))
		goto done;

	/* If the activate AP was fake, it probably won't have a BSSID at all.
	 * But if activation was successful, the card will know the BSSID.  Grab
	 * the BSSID off the card and fill in the BSSID of the activation AP.
	 */
	nm_device_wifi_get_bssid (self, &bssid);
	if (!nm_ethernet_address_is_valid (nm_ap_get_address (ap)))
		nm_ap_set_address (ap, &bssid);
	if (!nm_ap_get_freq (ap))
		nm_ap_set_freq (ap, nm_device_wifi_get_frequency (self));
	if (!nm_ap_get_max_bitrate (ap) && nm_ap_get_user_created (ap))
		nm_ap_set_max_bitrate (ap, nm_device_wifi_get_bitrate (self));

	tmp_ap = get_active_ap (self, ap, TRUE);
	if (tmp_ap) {
		const GByteArray *ssid = nm_ap_get_ssid (tmp_ap);

		/* Found a better match in the scan list than the fake AP.  Use it
		 * instead.
		 */

		/* If the better match was a hidden AP, update it's SSID */
		if (!ssid || nm_utils_is_empty_ssid (ssid->data, ssid->len))
			nm_ap_set_ssid (tmp_ap, nm_ap_get_ssid (ap));

		nm_act_request_set_specific_object (req, nm_ap_get_dbus_path (tmp_ap));

		priv->ap_list = g_slist_remove (priv->ap_list, ap);
		g_object_unref (ap);
	}

done:
	periodic_update (self);

	/* Reset scan interval to something reasonable */
	priv->scan_interval = SCAN_INTERVAL_MIN + (SCAN_INTERVAL_STEP * 2);
}


static void
activation_failure_handler (NMDevice *dev)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (dev);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMAccessPoint *ap;
	const GByteArray * ssid;
	NMActRequest *req;
	NMConnection *connection;

	req = nm_device_get_act_request (dev);
	g_assert (req);

	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	/* Clear wireless secrets tries on failure */
	g_object_set_data (G_OBJECT (connection), WIRELESS_SECRETS_TRIES, NULL);

	if ((ap = nm_device_wifi_get_activation_ap (self))) {
		if (nm_ap_get_fake (ap)) {
			/* Fake APs are ones that don't show up in scans,
			 * but which the user explicitly attempted to connect to.
			 * However, if we fail on one of these, remove it from the
			 * list because we don't have any scan or capability info
			 * for it, and they are pretty much useless.
			 */
			access_point_removed (self, ap);
			priv->ap_list = g_slist_remove (priv->ap_list, ap);
			g_object_unref (ap);
		}
	}

	ssid = nm_ap_get_ssid (ap);
	nm_log_warn (LOGD_DEVICE | LOGD_WIFI,
	             "Activation (%s) failed for access point (%s)",
	             nm_device_get_iface (dev),
	             ssid ? nm_utils_escape_ssid (ssid->data, ssid->len) : "(none)");
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
	return NM_DEVICE_WIFI_GET_PRIVATE (dev)->capabilities;
}


static gboolean
spec_match_list (NMDevice *device, const GSList *specs)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (device);
	char *hwaddr;
	gboolean matched;

	hwaddr = nm_ether_ntop ((struct ether_addr *) &priv->perm_hw_addr);
	matched = nm_match_spec_hwaddr (specs, hwaddr);
	g_free (hwaddr);

	return matched;
}

static void
device_state_changed (NMDevice *device,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason,
                      gpointer user_data)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (device);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	gboolean clear_aps = FALSE;

	if (new_state <= NM_DEVICE_STATE_UNAVAILABLE) {
		/* Clean up the supplicant interface because in these states the
		 * device cannot be used.
		 */
		if (priv->supplicant.iface)
			supplicant_interface_release (self);
	}

	/* Start or stop the rfkill poll worker for ipw cards */
	if (priv->ipw_rfkill_path) {
		if (new_state > NM_DEVICE_STATE_UNMANAGED) {
			if (!priv->ipw_rfkill_id)
				priv->ipw_rfkill_id = g_timeout_add_seconds (3, ipw_rfkill_state_work, self);
		} else if (new_state <= NM_DEVICE_STATE_UNMANAGED) {
			if (priv->ipw_rfkill_id) {
				g_source_remove (priv->ipw_rfkill_id);
				priv->ipw_rfkill_id = 0;
			}
		}
	}

	switch (new_state) {
	case NM_DEVICE_STATE_UNMANAGED:
		clear_aps = TRUE;
		break;
	case NM_DEVICE_STATE_UNAVAILABLE:
		/* If the device is enabled and the supplicant manager is ready,
		 * acquire a supplicant interface and transition to DISCONNECTED because
		 * the device is now ready to use.
		 */
		if (priv->enabled && (nm_device_get_firmware_missing (device) == FALSE)) {
			gboolean success;
			struct iw_range range;

			/* Wait for some drivers like ipw3945 to come back to life */
			success = wireless_get_range (self, &range, NULL);

			if (!priv->supplicant.iface)
				supplicant_interface_acquire (self);
		}
		clear_aps = TRUE;
		break;
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

	if (clear_aps)
		remove_all_aps (self);
}

NMAccessPoint *
nm_device_wifi_get_activation_ap (NMDeviceWifi *self)
{
	NMDeviceWifiPrivate *priv;
	NMActRequest *req;
	const char *ap_path;
	GSList * elt;

	g_return_val_if_fail (NM_IS_DEVICE_WIFI (self), NULL);

	req = nm_device_get_act_request (NM_DEVICE (self));
	if (!req)
		return NULL;

	ap_path = nm_act_request_get_specific_object (req);
	if (!ap_path)
		return NULL;

	/* Find the AP by it's object path */
	priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	for (elt = priv->ap_list; elt; elt = g_slist_next (elt)) {
		NMAccessPoint *ap = NM_AP (elt->data);

		if (!strcmp (ap_path, nm_ap_get_dbus_path (ap)))
			return ap;
	}
	return NULL;
}

static void
real_set_enabled (NMDeviceInterface *device, gboolean enabled)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (device);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);
	NMDeviceState state;

	if (priv->enabled == enabled)
		return;

	priv->enabled = enabled;

	nm_log_dbg (LOGD_WIFI, "(%s): device now %s",
	            nm_device_get_iface (NM_DEVICE (device)),
	            enabled ? "enabled" : "disabled");

	state = nm_device_interface_get_state (NM_DEVICE_INTERFACE (self));
	if (state < NM_DEVICE_STATE_UNAVAILABLE) {
		nm_log_dbg (LOGD_WIFI, "(%s): %s blocked by UNMANAGED state",
		            enabled ? "enable" : "disable",
		            nm_device_get_iface (NM_DEVICE (device)));
		return;
	}

	if (enabled) {
		gboolean no_firmware = FALSE, success;
		struct iw_range range;

		if (state != NM_DEVICE_STATE_UNAVAILABLE)
			nm_log_warn (LOGD_CORE, "not in expected unavailable state!");

		if (!nm_device_hw_bring_up (NM_DEVICE (self), TRUE, &no_firmware)) {
			nm_log_dbg (LOGD_WIFI, "(%s): enable blocked by failure to bring device up",
			            nm_device_get_iface (NM_DEVICE (device)));

			if (no_firmware)
				nm_device_set_firmware_missing (NM_DEVICE (device), TRUE);
			else {
				/* The device sucks, or the kernel was lying to us about the killswitch state */
				priv->enabled = FALSE;
			}
			return;
		}

		/* Wait for some drivers like ipw3945 to come back to life */
		success = wireless_get_range (self, &range, NULL);

		/* iface should be NULL here, but handle it anyway if it's not */
		g_warn_if_fail (priv->supplicant.iface == NULL);
		if (priv->supplicant.iface)
			supplicant_interface_release (self);

		supplicant_interface_acquire (self);
		nm_log_dbg (LOGD_WIFI, "(%s): enable waiting on supplicant state",
		            nm_device_get_iface (NM_DEVICE (device)));
	} else {
		nm_device_state_changed (NM_DEVICE (self),
		                         NM_DEVICE_STATE_UNAVAILABLE,
		                         NM_DEVICE_STATE_REASON_NONE);
		nm_device_hw_take_down (NM_DEVICE (self), TRUE);
	}
}

/********************************************************************/

NMDevice *
nm_device_wifi_new (const char *udi,
                    const char *iface,
                    const char *driver)
{
	g_return_val_if_fail (udi != NULL, NULL);
	g_return_val_if_fail (iface != NULL, NULL);
	g_return_val_if_fail (driver != NULL, NULL);

	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_WIFI,
	                                  NM_DEVICE_INTERFACE_UDI, udi,
	                                  NM_DEVICE_INTERFACE_IFACE, iface,
	                                  NM_DEVICE_INTERFACE_DRIVER, driver,
	                                  NM_DEVICE_INTERFACE_TYPE_DESC, "802.11 WiFi",
	                                  NM_DEVICE_INTERFACE_DEVICE_TYPE, NM_DEVICE_TYPE_WIFI,
	                                  NM_DEVICE_INTERFACE_RFKILL_TYPE, RFKILL_TYPE_WLAN,
	                                  NULL);
}

static void
device_interface_init (NMDeviceInterface *iface_class)
{
    iface_class->set_enabled = real_set_enabled;
}

static void
nm_device_wifi_init (NMDeviceWifi * self)
{
	g_signal_connect (self, "state-changed", G_CALLBACK (device_state_changed), NULL);
}

static void
dispose (GObject *object)
{
	NMDeviceWifi *self = NM_DEVICE_WIFI (object);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (self);

	if (priv->disposed) {
		G_OBJECT_CLASS (nm_device_wifi_parent_class)->dispose (object);
		return;
	}

	priv->disposed = TRUE;

	if (priv->periodic_source_id) {
		g_source_remove (priv->periodic_source_id);
		priv->periodic_source_id = 0;
	}

	/* Clean up all pending supplicant tasks */
	while (priv->supplicant.iface_tasks)
		finish_supplicant_task ((SupplicantStateTask *) priv->supplicant.iface_tasks->data, TRUE);
	while (priv->supplicant.mgr_tasks)
		finish_supplicant_task ((SupplicantStateTask *) priv->supplicant.mgr_tasks->data, TRUE);

	cleanup_association_attempt (self, TRUE);
	supplicant_interface_release (self);

	if (priv->supplicant.mgr_state_id) {
		g_signal_handler_disconnect (priv->supplicant.mgr, priv->supplicant.mgr_state_id);
		priv->supplicant.mgr_state_id = 0;
	}

	if (priv->supplicant.mgr) {
		g_object_unref (priv->supplicant.mgr);
		priv->supplicant.mgr = NULL;
	}

	if (priv->ssid) {
		g_byte_array_free (priv->ssid, TRUE);
		priv->ssid = NULL;
	}

	set_current_ap (self, NULL);
	remove_all_aps (self);

	g_free (priv->ipw_rfkill_path);
	if (priv->ipw_rfkill_id) {
		g_source_remove (priv->ipw_rfkill_id);
		priv->ipw_rfkill_id = 0;
	}

	G_OBJECT_CLASS (nm_device_wifi_parent_class)->dispose (object);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDeviceWifi *device = NM_DEVICE_WIFI (object);
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (device);

	switch (prop_id) {
	case PROP_HW_ADDRESS:
		g_value_take_string (value, nm_ether_ntop ((struct ether_addr *) &priv->hw_addr));
		break;
	case PROP_PERM_HW_ADDRESS:
		g_value_take_string (value, nm_ether_ntop ((struct ether_addr *) &priv->perm_hw_addr));
		break;
	case PROP_MODE:
		g_value_set_uint (value, nm_device_wifi_get_mode (device));
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
	case PROP_SCANNING:
		g_value_set_boolean (value, nm_supplicant_interface_get_scanning (priv->supplicant.iface));
		break;
	case PROP_IPW_RFKILL_STATE:
		g_value_set_uint (value, nm_device_wifi_get_ipw_rfkill_state (device));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec)
{
	NMDeviceWifiPrivate *priv = NM_DEVICE_WIFI_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_IPW_RFKILL_STATE:
		/* construct only */
		priv->ipw_rfkill_state = g_value_get_uint (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}


static void
nm_device_wifi_class_init (NMDeviceWifiClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *parent_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMDeviceWifiPrivate));

	object_class->constructor = constructor;
	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->dispose = dispose;

	parent_class->get_type_capabilities = real_get_type_capabilities;
	parent_class->get_generic_capabilities = real_get_generic_capabilities;
	parent_class->hw_is_up = real_hw_is_up;
	parent_class->hw_bring_up = real_hw_bring_up;
	parent_class->hw_take_down = real_hw_take_down;
	parent_class->is_up = real_is_up;
	parent_class->bring_up = real_bring_up;
	parent_class->take_down = real_take_down;
	parent_class->update_hw_address = real_update_hw_address;
	parent_class->update_permanent_hw_address = real_update_permanent_hw_address;
	parent_class->get_best_auto_connection = real_get_best_auto_connection;
	parent_class->is_available = real_is_available;
	parent_class->connection_secrets_updated = real_connection_secrets_updated;
	parent_class->check_connection_compatible = real_check_connection_compatible;

	parent_class->act_stage1_prepare = real_act_stage1_prepare;
	parent_class->act_stage2_config = real_act_stage2_config;
	parent_class->act_stage4_get_ip4_config = real_act_stage4_get_ip4_config;
	parent_class->act_stage4_ip4_config_timeout = real_act_stage4_ip4_config_timeout;
	parent_class->act_stage4_ip6_config_timeout = real_act_stage4_ip6_config_timeout;
	parent_class->deactivate = real_deactivate;
	parent_class->deactivate_quickly = real_deactivate_quickly;
	parent_class->can_interrupt_activation = real_can_interrupt_activation;
	parent_class->spec_match_list = spec_match_list;

	klass->scanning_allowed = scanning_allowed;

	/* Properties */
	g_object_class_install_property (object_class, PROP_HW_ADDRESS,
		g_param_spec_string (NM_DEVICE_WIFI_HW_ADDRESS,
		                     "Active MAC Address",
		                     "Currently set hardware MAC address",
		                     NULL,
		                     G_PARAM_READABLE));

	g_object_class_install_property (object_class, PROP_PERM_HW_ADDRESS,
		g_param_spec_string (NM_DEVICE_WIFI_PERMANENT_HW_ADDRESS,
		                     "Permanent MAC Address",
		                     "Permanent hardware MAC address",
		                     NULL,
		                     G_PARAM_READABLE));

	g_object_class_install_property (object_class, PROP_MODE,
		g_param_spec_uint (NM_DEVICE_WIFI_MODE,
		                   "Mode",
		                   "Mode",
		                   NM_802_11_MODE_UNKNOWN,
		                   NM_802_11_MODE_INFRA,
		                   NM_802_11_MODE_INFRA,
		                   G_PARAM_READABLE));

	g_object_class_install_property (object_class, PROP_BITRATE,
		g_param_spec_uint (NM_DEVICE_WIFI_BITRATE,
		                   "Bitrate",
		                   "Bitrate",
		                   0, G_MAXUINT32, 0,
		                   G_PARAM_READABLE));

	g_object_class_install_property (object_class, PROP_ACTIVE_ACCESS_POINT,
		g_param_spec_boxed (NM_DEVICE_WIFI_ACTIVE_ACCESS_POINT,
		                    "Active access point",
		                    "Currently active access point",
		                    DBUS_TYPE_G_OBJECT_PATH,
		                    G_PARAM_READABLE));

	g_object_class_install_property (object_class, PROP_CAPABILITIES,
		g_param_spec_uint (NM_DEVICE_WIFI_CAPABILITIES,
		                   "Wireless Capabilities",
		                   "Wireless Capabilities",
		                   0, G_MAXUINT32, NM_WIFI_DEVICE_CAP_NONE,
		                   G_PARAM_READABLE));

	g_object_class_install_property (object_class, PROP_SCANNING,
		g_param_spec_boolean (NM_DEVICE_WIFI_SCANNING,
		                   "Scanning",
		                   "Scanning",
		                   FALSE,
		                   G_PARAM_READABLE | NM_PROPERTY_PARAM_NO_EXPORT));

	g_object_class_install_property (object_class, PROP_IPW_RFKILL_STATE,
		g_param_spec_uint (NM_DEVICE_WIFI_IPW_RFKILL_STATE,
		                   "IpwRfkillState",
		                   "ipw rf-kill state",
		                   RFKILL_UNBLOCKED, RFKILL_HARD_BLOCKED, RFKILL_UNBLOCKED,
		                   G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | NM_PROPERTY_PARAM_NO_EXPORT));

	/* Signals */
	signals[ACCESS_POINT_ADDED] =
		g_signal_new ("access-point-added",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMDeviceWifiClass, access_point_added),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__OBJECT,
		              G_TYPE_NONE, 1,
		              G_TYPE_OBJECT);

	signals[ACCESS_POINT_REMOVED] =
		g_signal_new ("access-point-removed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMDeviceWifiClass, access_point_removed),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__OBJECT,
		              G_TYPE_NONE, 1,
		              G_TYPE_OBJECT);

	signals[HIDDEN_AP_FOUND] =
		g_signal_new ("hidden-ap-found",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMDeviceWifiClass, hidden_ap_found),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__OBJECT,
		              G_TYPE_NONE, 1,
		              G_TYPE_OBJECT);

	signals[PROPERTIES_CHANGED] =
		nm_properties_changed_signal_new (object_class,
		                                  G_STRUCT_OFFSET (NMDeviceWifiClass, properties_changed));

	signals[SCANNING_ALLOWED] =
		g_signal_new ("scanning-allowed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMDeviceWifiClass, scanning_allowed),
		              scanning_allowed_accumulator, NULL,
		              _nm_marshal_BOOLEAN__VOID,
		              G_TYPE_BOOLEAN, 0);

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (klass), &dbus_glib_nm_device_wifi_object_info);

	dbus_g_error_domain_register (NM_WIFI_ERROR, NULL, NM_TYPE_WIFI_ERROR);
}


