// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2005 - 2018 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#include "nm-default.h"

#include "nm-wifi-utils-wext.h"

#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <unistd.h>

/* Hacks necessary to #include wireless.h; yay for WEXT */
#ifndef __user
#define __user
#endif
#include <sys/types.h>
#include <linux/types.h>
#include <sys/socket.h>
#include <linux/wireless.h>

#include "nm-wifi-utils-private.h"
#include "nm-utils.h"
#include "platform/nm-platform-utils.h"
#include "nm-core-internal.h"

typedef struct {
	NMWifiUtils parent;
	int fd;
	struct iw_quality max_qual;
	gint8 num_freqs;
	guint32 freqs[IW_MAX_FREQUENCIES];
} NMWifiUtilsWext;

typedef struct {
	NMWifiUtilsClass parent;
} NMWifiUtilsWextClass;

G_DEFINE_TYPE (NMWifiUtilsWext, nm_wifi_utils_wext, NM_TYPE_WIFI_UTILS)

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

#define _NMLOG_PREFIX_NAME      "wifi-wext"
#define _NMLOG(level, domain, ...) \
	G_STMT_START { \
		nm_log ((level), (domain), NULL, NULL, \
		        "%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
		        _NMLOG_PREFIX_NAME \
		        _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
	} G_STMT_END

static guint32
iw_freq_to_uint32 (const struct iw_freq *freq)
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
	return (guint32) ((((double) freq->m) * nm_utils_exp10 (freq->e)) / 1000000.0);
}

static void
dispose (GObject *object)
{
	NMWifiUtilsWext *wext = NM_WIFI_UTILS_WEXT (object);

	wext->fd = nm_close (wext->fd);
}

static gboolean
get_ifname (int ifindex, char *buffer, const char *op)
{
	int errsv;

	if (!nmp_utils_if_indextoname (ifindex, buffer)) {
		errsv = errno;
		_LOGW (LOGD_PLATFORM | LOGD_WIFI,
		       "error getting interface name for ifindex %d, operation '%s': %s (%d)",
		       ifindex, op, nm_strerror_native (errsv), errsv);
		return FALSE;
	}

	return TRUE;
}

static NM80211Mode
wifi_wext_get_mode_ifname (NMWifiUtils *data, const char *ifname)
{
	NMWifiUtilsWext *wext = (NMWifiUtilsWext *) data;
	struct iwreq wrq;
	int errsv;

	memset (&wrq, 0, sizeof (struct iwreq));
	nm_utils_ifname_cpy (wrq.ifr_name, ifname);

	if (ioctl (wext->fd, SIOCGIWMODE, &wrq) < 0) {
		errsv = errno;
		if (errsv != ENODEV) {
			_LOGW (LOGD_PLATFORM | LOGD_WIFI,
			       "(%s): error %d getting card mode",
			       ifname, errsv);
		}
		return NM_802_11_MODE_UNKNOWN;
	}

	switch (wrq.u.mode) {
	case IW_MODE_ADHOC:
		return NM_802_11_MODE_ADHOC;
	case IW_MODE_MASTER:
		return NM_802_11_MODE_AP;
	case IW_MODE_INFRA:
	case IW_MODE_AUTO: /* hack for WEXT devices reporting IW_MODE_AUTO */
		return NM_802_11_MODE_INFRA;
	default:
		break;
	}
	return NM_802_11_MODE_UNKNOWN;
}

static NM80211Mode
wifi_wext_get_mode (NMWifiUtils *data)
{
	char ifname[IFNAMSIZ];

	if (!get_ifname (data->ifindex, ifname, "get-mode"))
		return FALSE;

	return wifi_wext_get_mode_ifname (data, ifname);
}

static gboolean
wifi_wext_set_mode (NMWifiUtils *data, const NM80211Mode mode)
{
	NMWifiUtilsWext *wext = (NMWifiUtilsWext *) data;
	struct iwreq wrq;
	char ifname[IFNAMSIZ];

	if (!get_ifname (data->ifindex, ifname, "set-mode"))
		return FALSE;

	if (wifi_wext_get_mode_ifname (data, ifname) == mode)
		return TRUE;

	memset (&wrq, 0, sizeof (struct iwreq));
	switch (mode) {
	case NM_802_11_MODE_ADHOC:
		wrq.u.mode = IW_MODE_ADHOC;
		break;
	case NM_802_11_MODE_AP:
		wrq.u.mode = IW_MODE_MASTER;
		break;
	case NM_802_11_MODE_INFRA:
		wrq.u.mode = IW_MODE_INFRA;
		break;
	default:
		g_warn_if_reached ();
		return FALSE;
	}

	nm_utils_ifname_cpy (wrq.ifr_name, ifname);
	if (ioctl (wext->fd, SIOCSIWMODE, &wrq) < 0) {
		if (errno != ENODEV) {
			_LOGE (LOGD_PLATFORM | LOGD_WIFI,
			       "(%s): error setting mode %d",
			       ifname, mode);
		}
		return FALSE;
	}

	return TRUE;
}

static gboolean
wifi_wext_set_powersave (NMWifiUtils *data, guint32 powersave)
{
	NMWifiUtilsWext *wext = (NMWifiUtilsWext *) data;
	struct iwreq wrq;
	char ifname[IFNAMSIZ];

	if (!get_ifname (data->ifindex, ifname, "set-powersave"))
		return FALSE;

	memset (&wrq, 0, sizeof (struct iwreq));
	if (powersave == 1) {
		wrq.u.power.flags = IW_POWER_ALL_R;
	} else
		wrq.u.power.disabled = 1;

	nm_utils_ifname_cpy (wrq.ifr_name, ifname);
	if (ioctl (wext->fd, SIOCSIWPOWER, &wrq) < 0) {
		if (errno != ENODEV) {
			_LOGE (LOGD_PLATFORM | LOGD_WIFI,
			       "(%s): error setting powersave %" G_GUINT32_FORMAT,
			       ifname, powersave);
		}
		return FALSE;
	}

	return TRUE;
}

static guint32
wifi_wext_get_freq (NMWifiUtils *data)
{
	NMWifiUtilsWext *wext = (NMWifiUtilsWext *) data;
	struct iwreq wrq;
	char ifname[IFNAMSIZ];

	if (!get_ifname (data->ifindex, ifname, "get-freq"))
		return FALSE;

	memset (&wrq, 0, sizeof (struct iwreq));
	nm_utils_ifname_cpy (wrq.ifr_name, ifname);
	if (ioctl (wext->fd, SIOCGIWFREQ, &wrq) < 0) {
		_LOGW (LOGD_PLATFORM | LOGD_WIFI,
		       "(%s): error getting frequency: %s",
		       ifname, nm_strerror_native (errno));
		return 0;
	}

	return iw_freq_to_uint32 (&wrq.u.freq);
}

static guint32
wifi_wext_find_freq (NMWifiUtils *data, const guint32 *freqs)
{
	NMWifiUtilsWext *wext = (NMWifiUtilsWext *) data;
	int i;

	for (i = 0; i < wext->num_freqs; i++) {
		while (*freqs) {
			if (wext->freqs[i] == *freqs)
				return *freqs;
			freqs++;
		}
	}
	return 0;
}

static gboolean
wifi_wext_get_bssid (NMWifiUtils *data, guint8 *out_bssid)
{
	NMWifiUtilsWext *wext = (NMWifiUtilsWext *) data;
	struct iwreq wrq;
	char ifname[IFNAMSIZ];

	if (!get_ifname (data->ifindex, ifname, "get-bssid"))
		return FALSE;

	memset (&wrq, 0, sizeof (wrq));
	nm_utils_ifname_cpy (wrq.ifr_name, ifname);
	if (ioctl (wext->fd, SIOCGIWAP, &wrq) < 0) {
		_LOGW (LOGD_PLATFORM | LOGD_WIFI,
		       "(%s): error getting associated BSSID: %s",
		       ifname, nm_strerror_native (errno));
		return FALSE;
	}
	memcpy (out_bssid, &(wrq.u.ap_addr.sa_data), ETH_ALEN);
	return TRUE;
}

static guint32
wifi_wext_get_rate (NMWifiUtils *data)
{
	NMWifiUtilsWext *wext = (NMWifiUtilsWext *) data;
	struct iwreq wrq;
	int err;
	char ifname[IFNAMSIZ];

	if (!get_ifname (data->ifindex, ifname, "get-rate"))
		return FALSE;

	memset (&wrq, 0, sizeof (wrq));
	nm_utils_ifname_cpy (wrq.ifr_name, ifname);
	err = ioctl (wext->fd, SIOCGIWRATE, &wrq);
	return ((err == 0) ? wrq.u.bitrate.value / 1000 : 0);
}

static int
wext_qual_to_percent (const struct iw_quality *qual,
                      const struct iw_quality *max_qual)
{
	int percent = -1;
	int level_percent = -1;

	g_return_val_if_fail (qual != NULL, -1);
	g_return_val_if_fail (max_qual != NULL, -1);

	/* Magically convert the many different WEXT quality representations to a percentage */

	_LOGD (LOGD_WIFI,
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

	if (    (max_qual->level == 0) && !(max_qual->updated & IW_QUAL_LEVEL_INVALID)      /* Valid max_qual->level == 0 */
	    && !(qual->updated & IW_QUAL_LEVEL_INVALID)                                     /* Must have valid qual->level */
	    && (    ((max_qual->noise > 0) && !(max_qual->updated & IW_QUAL_NOISE_INVALID)) /* Must have valid max_qual->noise */
	        || ((qual->noise > 0) && !(qual->updated & IW_QUAL_NOISE_INVALID)))         /*    OR valid qual->noise */
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
		noise = CLAMP (noise, FALLBACK_NOISE_FLOOR_DBM, FALLBACK_SIGNAL_MAX_DBM - 1);

		/* A sort of signal-to-noise ratio calculation */
		level_percent = (int) (100 - 70 * (((double)max_level - (double)level) /
		                                   ((double)max_level - (double)noise)));
		_LOGD (LOGD_WIFI, "QL1: level_percent is %d.  max_level %d, level %d, noise_floor %d.",
		       level_percent, max_level, level, noise);
	} else if (   (max_qual->level != 0)
	           && !(max_qual->updated & IW_QUAL_LEVEL_INVALID) /* Valid max_qual->level as upper bound */
	           && !(qual->updated & IW_QUAL_LEVEL_INVALID)) {
		/* Relative power values (RSSI) */

		int level = qual->level;

		/* Signal level is relavtive (0 -> max_qual->level) */
		level = CLAMP (level, 0, max_qual->level);
		level_percent = (int)(100 * ((double)level / (double)max_qual->level));
		_LOGD (LOGD_WIFI, "QL2: level_percent is %d.  max_level %d, level %d.",
		       level_percent, max_qual->level, level);
	} else if (percent == -1) {
		_LOGD (LOGD_WIFI, "QL: Could not get quality %% value from driver.  Driver is probably buggy.");
	}

	/* If the quality percent was 0 or doesn't exist, then try to use signal levels instead */
	if ((percent < 1) && (level_percent >= 0))
		percent = level_percent;

	_LOGD (LOGD_WIFI, "QL: Final quality percent is %d (%d).",
	       percent, CLAMP (percent, 0, 100));
	return (CLAMP (percent, 0, 100));
}

static int
wifi_wext_get_qual (NMWifiUtils *data)
{
	NMWifiUtilsWext *wext = (NMWifiUtilsWext *) data;
	struct iwreq wrq;
	struct iw_statistics stats;
	char ifname[IFNAMSIZ];

	if (!get_ifname (data->ifindex, ifname, "get-qual"))
		return FALSE;

	memset (&stats, 0, sizeof (stats));
	wrq.u.data.pointer = &stats;
	wrq.u.data.length = sizeof (stats);
	wrq.u.data.flags = 1;  /* Clear updated flag */
	nm_utils_ifname_cpy (wrq.ifr_name, ifname);

	if (ioctl (wext->fd, SIOCGIWSTATS, &wrq) < 0) {
		_LOGW (LOGD_PLATFORM | LOGD_WIFI,
		       "(%s): error getting signal strength: %s",
		       ifname, nm_strerror_native (errno));
		return -1;
	}

	return wext_qual_to_percent (&stats.qual, &wext->max_qual);
}

/*****************************************************************************/
/* OLPC Mesh-only functions */

static guint32
wifi_wext_get_mesh_channel (NMWifiUtils *data)
{
	NMWifiUtilsWext *wext = (NMWifiUtilsWext *) data;
	guint32 freq;
	int i;

	freq = nm_wifi_utils_get_freq (data);
	for (i = 0; i < wext->num_freqs; i++) {
		if (freq == wext->freqs[i])
			return i + 1;
	}
	return 0;
}

static gboolean
wifi_wext_set_mesh_channel (NMWifiUtils *data, guint32 channel)
{
	NMWifiUtilsWext *wext = (NMWifiUtilsWext *) data;
	struct iwreq wrq;
	char ifname[IFNAMSIZ];

	if (!get_ifname (data->ifindex, ifname, "set-mesh-channel"))
		return FALSE;

	memset (&wrq, 0, sizeof (struct iwreq));
	nm_utils_ifname_cpy (wrq.ifr_name, ifname);

	if (channel > 0) {
		wrq.u.freq.flags = IW_FREQ_FIXED;
		wrq.u.freq.e = 0;
		wrq.u.freq.m = channel;
	}

	if (ioctl (wext->fd, SIOCSIWFREQ, &wrq) < 0) {
		_LOGE (LOGD_PLATFORM | LOGD_WIFI | LOGD_OLPC,
		       "(%s): error setting channel to %d: %s",
		       ifname, channel, nm_strerror_native (errno));
		return FALSE;
	}

	return TRUE;
}

static gboolean
wifi_wext_set_mesh_ssid (NMWifiUtils *data, const guint8 *ssid, gsize len)
{
	NMWifiUtilsWext *wext = (NMWifiUtilsWext *) data;
	struct iwreq wrq;
	char buf[IW_ESSID_MAX_SIZE + 1];
	char ifname[IFNAMSIZ];
	int errsv;

	if (!get_ifname (data->ifindex, ifname, "set-mesh-ssid"))
		return FALSE;

	memset (buf, 0, sizeof (buf));
	memcpy (buf, ssid, MIN (sizeof (buf) - 1, len));

	wrq.u.essid.pointer = (caddr_t) buf;
	wrq.u.essid.length = len;
	wrq.u.essid.flags = (len > 0) ? 1 : 0; /* 1=enable SSID, 0=disable/any */

	nm_utils_ifname_cpy (wrq.ifr_name, ifname);
	if (ioctl (wext->fd, SIOCSIWESSID, &wrq) == 0)
		return TRUE;

	errsv = errno;
	if (errsv != ENODEV) {
		gs_free char *ssid_str = NULL;

		_LOGE (LOGD_PLATFORM | LOGD_WIFI | LOGD_OLPC,
		       "(%s): error setting SSID to %s: %s",
		       ifname,
		       (ssid_str = _nm_utils_ssid_to_string_arr (ssid, len)),
		       nm_strerror_native (errsv));
	}

	return FALSE;
}

/*****************************************************************************/

static gboolean
wext_can_scan_ifname (NMWifiUtilsWext *wext, const char *ifname)
{
	struct iwreq wrq;

	memset (&wrq, 0, sizeof (struct iwreq));
	nm_utils_ifname_cpy (wrq.ifr_name, ifname);
	if (ioctl (wext->fd, SIOCSIWSCAN, &wrq) < 0) {
		if (errno == EOPNOTSUPP)
			return FALSE;
	}
	return TRUE;
}

static gboolean
wext_get_range_ifname (NMWifiUtilsWext *wext,
                       const char *ifname,
                       struct iw_range *range,
                       guint32 *response_len)
{
	int i = 26;
	gboolean success = FALSE;
	struct iwreq wrq;
	int errsv;

	memset (&wrq, 0, sizeof (struct iwreq));
	nm_utils_ifname_cpy (wrq.ifr_name, ifname);
	wrq.u.data.pointer = (caddr_t) range;
	wrq.u.data.length = sizeof (struct iw_range);

	/* Need to give some drivers time to recover after suspend/resume
	 * (ex ipw3945 takes a few seconds to talk to its regulatory daemon;
	 * see rh bz#362421)
	 */
	while (i-- > 0) {
		if (ioctl (wext->fd, SIOCGIWRANGE, &wrq) == 0) {
			if (response_len)
				*response_len = wrq.u.data.length;
			success = TRUE;
			break;
		} else {
			errsv = errno;
			if (errsv != EAGAIN) {
				_LOGE (LOGD_PLATFORM | LOGD_WIFI,
				       "(%s): couldn't get driver range information (%d).",
				       ifname, errsv);
				break;
			}
		}

		g_usleep (G_USEC_PER_SEC / 4);
	}

	if (i <= 0) {
		_LOGW (LOGD_PLATFORM | LOGD_WIFI,
		       "(%s): driver took too long to respond to IWRANGE query.",
		       ifname);
	}

	return success;
}

#define WPA_CAPS (NM_WIFI_DEVICE_CAP_CIPHER_TKIP | \
                  NM_WIFI_DEVICE_CAP_CIPHER_CCMP | \
                  NM_WIFI_DEVICE_CAP_WPA | \
                  NM_WIFI_DEVICE_CAP_RSN)

static guint32
wext_get_caps (NMWifiUtilsWext *wext, const char *ifname, struct iw_range *range)
{
	guint32 caps = NM_WIFI_DEVICE_CAP_NONE;

	g_return_val_if_fail (wext != NULL, NM_WIFI_DEVICE_CAP_NONE);
	g_return_val_if_fail (range != NULL, NM_WIFI_DEVICE_CAP_NONE);

	/* All drivers should support WEP by default */
	caps |= NM_WIFI_DEVICE_CAP_CIPHER_WEP40 | NM_WIFI_DEVICE_CAP_CIPHER_WEP104;

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
		_LOGW (LOGD_WIFI,
		       "%s: device supports WPA ciphers but not WPA protocol; WPA unavailable.",
		       ifname);
		caps &= ~WPA_CAPS;
	}

	/* Check for WPA support but not cipher support */
	if (    (caps & (NM_WIFI_DEVICE_CAP_WPA | NM_WIFI_DEVICE_CAP_RSN))
	    && !(caps & (NM_WIFI_DEVICE_CAP_CIPHER_TKIP | NM_WIFI_DEVICE_CAP_CIPHER_CCMP))) {
		_LOGW (LOGD_WIFI,
		       "%s: device supports WPA protocol but not WPA ciphers; WPA unavailable.",
		       ifname);
		caps &= ~WPA_CAPS;
	}

	/* There's no way to detect Ad-Hoc/AP mode support with WEXT
	 * (other than actually trying to do it), so just assume that
	 * Ad-Hoc is supported and AP isn't.
	 */
	caps |= NM_WIFI_DEVICE_CAP_ADHOC;

	return caps;
}

/*****************************************************************************/

static void
nm_wifi_utils_wext_init (NMWifiUtilsWext *self)
{
}

static void
nm_wifi_utils_wext_class_init (NMWifiUtilsWextClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMWifiUtilsClass *wifi_utils_class = NM_WIFI_UTILS_CLASS (klass);

	object_class->dispose = dispose;

	wifi_utils_class->get_mode = wifi_wext_get_mode;
	wifi_utils_class->set_mode = wifi_wext_set_mode;
	wifi_utils_class->set_powersave = wifi_wext_set_powersave;
	wifi_utils_class->get_freq = wifi_wext_get_freq;
	wifi_utils_class->find_freq = wifi_wext_find_freq;
	wifi_utils_class->get_bssid = wifi_wext_get_bssid;
	wifi_utils_class->get_rate = wifi_wext_get_rate;
	wifi_utils_class->get_qual = wifi_wext_get_qual;
	wifi_utils_class->get_mesh_channel = wifi_wext_get_mesh_channel;
	wifi_utils_class->set_mesh_channel = wifi_wext_set_mesh_channel;
	wifi_utils_class->set_mesh_ssid = wifi_wext_set_mesh_ssid;
}

NMWifiUtils *
nm_wifi_utils_wext_new (int ifindex, gboolean check_scan)
{
	NMWifiUtilsWext *wext;
	struct iw_range range;
	guint32 response_len = 0;
	struct iw_range_with_scan_capa *scan_capa_range;
	int i;
	gboolean freq_valid = FALSE, has_5ghz = FALSE, has_2ghz = FALSE;
	char ifname[IFNAMSIZ];

	if (!nmp_utils_if_indextoname (ifindex, ifname)) {
		_LOGW (LOGD_PLATFORM | LOGD_WIFI,
		       "can't determine interface name for ifindex %d", ifindex);
		return NULL;
	}

	wext = g_object_new (NM_TYPE_WIFI_UTILS_WEXT, NULL);

	wext->parent.ifindex = ifindex;
	wext->fd = socket (PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (wext->fd < 0)
		goto error;

	memset (&range, 0, sizeof (struct iw_range));
	if (wext_get_range_ifname (wext, ifname, &range, &response_len) == FALSE) {
		_LOGI (LOGD_PLATFORM | LOGD_WIFI, "(%s): driver WEXT range request failed",
		       ifname);
		goto error;
	}

	if ((response_len < 300) || (range.we_version_compiled < 21)) {
		_LOGI (LOGD_PLATFORM | LOGD_WIFI,
		       "(%s): driver WEXT version too old (got %d, expected >= 21)",
		       ifname,
		       range.we_version_compiled);
		goto error;
	}

	wext->max_qual.qual = range.max_qual.qual;
	wext->max_qual.level = range.max_qual.level;
	wext->max_qual.noise = range.max_qual.noise;
	wext->max_qual.updated = range.max_qual.updated;

	wext->num_freqs = MIN (range.num_frequency, IW_MAX_FREQUENCIES);
	for (i = 0; i < wext->num_freqs; i++) {
		wext->freqs[i] = iw_freq_to_uint32 (&range.freq[i]);
		freq_valid = TRUE;
		if (wext->freqs[i] > 2400 && wext->freqs[i] < 2500)
			has_2ghz = TRUE;
		else if (wext->freqs[i] > 4900 && wext->freqs[i] < 6000)
			has_5ghz = TRUE;
	}

	/* Check for scanning capability; cards that can't scan are not supported */
	if (check_scan && (wext_can_scan_ifname (wext, ifname) == FALSE)) {
		_LOGI (LOGD_PLATFORM | LOGD_WIFI,
		       "(%s): drivers that cannot scan are unsupported",
		       ifname);
		goto error;
	}

	/* Check for the ability to scan specific SSIDs.  Until the scan_capa
	 * field gets added to wireless-tools, need to work around that by casting
	 * to the custom structure.
	 */
	scan_capa_range = (struct iw_range_with_scan_capa *) &range;
	if (scan_capa_range->scan_capa & NM_IW_SCAN_CAPA_ESSID) {
		_LOGI (LOGD_PLATFORM | LOGD_WIFI,
		       "(%s): driver supports SSID scans (scan_capa 0x%02X).",
		       ifname,
		       scan_capa_range->scan_capa);
	} else {
		_LOGI (LOGD_PLATFORM | LOGD_WIFI,
		       "(%s): driver does not support SSID scans (scan_capa 0x%02X).",
		       ifname,
		       scan_capa_range->scan_capa);
	}

	wext->parent.caps = wext_get_caps (wext, ifname, &range);
	if (freq_valid)
		wext->parent.caps |= NM_WIFI_DEVICE_CAP_FREQ_VALID;
	if (has_2ghz)
		wext->parent.caps |= NM_WIFI_DEVICE_CAP_FREQ_2GHZ;
	if (has_5ghz)
		wext->parent.caps |= NM_WIFI_DEVICE_CAP_FREQ_5GHZ;

	_LOGI (LOGD_PLATFORM | LOGD_WIFI,
	       "(%s): using WEXT for Wi-Fi device control",
	       ifname);

	return (NMWifiUtils *) wext;

error:
	g_object_unref (wext);
	return NULL;
}

gboolean
nm_wifi_utils_wext_is_wifi (const char *iface)
{
	int fd;
	struct iwreq iwr;
	gboolean is_wifi = FALSE;

	/* performing an ioctl on a non-existing name may cause the automatic
	 * loading of kernel modules, which should be avoided.
	 *
	 * Usually, we should thus make sure that an interface with this name
	 * exists.
	 *
	 * Note that wifi_wext_is_wifi() has only one caller which just verified
	 * that an interface with this name exists.
	 */

	fd = socket (PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd >= 0) {
		nm_utils_ifname_cpy (iwr.ifr_ifrn.ifrn_name, iface);
		if (ioctl (fd, SIOCGIWNAME, &iwr) == 0)
			is_wifi = TRUE;
		nm_close (fd);
	}
	return is_wifi;
}
