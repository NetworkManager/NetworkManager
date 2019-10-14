// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2004 - 2017 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#include "nm-default.h"

#include "nm-wifi-ap.h"

#include <stdlib.h>

#include "nm-setting-wireless.h"

#include "nm-wifi-utils.h"
#include "NetworkManagerUtils.h"
#include "nm-utils.h"
#include "nm-core-internal.h"
#include "platform/nm-platform.h"
#include "devices/nm-device.h"
#include "nm-dbus-manager.h"

#define PROTO_WPA "wpa"
#define PROTO_RSN "rsn"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMWifiAP,
	PROP_FLAGS,
	PROP_WPA_FLAGS,
	PROP_RSN_FLAGS,
	PROP_SSID,
	PROP_FREQUENCY,
	PROP_HW_ADDRESS,
	PROP_MODE,
	PROP_MAX_BITRATE,
	PROP_STRENGTH,
	PROP_LAST_SEEN,
);

struct _NMWifiAPPrivate {
	char *supplicant_path;   /* D-Bus object path of this AP from wpa_supplicant */

	/* Scanned or cached values */
	GBytes *           ssid;
	char *             address;
	NM80211Mode        mode;
	guint8             strength;
	guint32            freq;        /* Frequency in MHz; ie 2412 (== 2.412 GHz) */
	guint32            max_bitrate; /* Maximum bitrate of the AP in Kbit/s (ie 54000 Kb/s == 54Mbit/s) */

	NM80211ApFlags         flags;      /* General flags */
	NM80211ApSecurityFlags wpa_flags;  /* WPA-related flags */
	NM80211ApSecurityFlags rsn_flags;  /* RSN (WPA2) -related flags */

	bool               metered:1;

	/* Non-scanned attributes */
	bool               fake:1;       /* Whether or not the AP is from a scan */
	bool               hotspot:1;    /* Whether the AP is a local device's hotspot network */
	gint32             last_seen;    /* Timestamp when the AP was seen lastly (obtained via nm_utils_get_monotonic_timestamp_s()) */
};

typedef struct _NMWifiAPPrivate NMWifiAPPrivate;

struct _NMWifiAPClass {
	NMDBusObjectClass parent;
};

G_DEFINE_TYPE (NMWifiAP, nm_wifi_ap, NM_TYPE_DBUS_OBJECT)

#define NM_WIFI_AP_GET_PRIVATE(self) _NM_GET_PRIVATE_PTR(self, NMWifiAP, NM_IS_WIFI_AP)

/*****************************************************************************/

const char *
nm_wifi_ap_get_supplicant_path (NMWifiAP *ap)
{
	g_return_val_if_fail (NM_IS_WIFI_AP (ap), NULL);

	return NM_WIFI_AP_GET_PRIVATE (ap)->supplicant_path;
}

GBytes *
nm_wifi_ap_get_ssid (const NMWifiAP *ap)
{
	g_return_val_if_fail (NM_IS_WIFI_AP (ap), NULL);

	return NM_WIFI_AP_GET_PRIVATE (ap)->ssid;
}

gboolean
nm_wifi_ap_set_ssid_arr (NMWifiAP *ap,
                         const guint8 *ssid,
                         gsize ssid_len)
{
	NMWifiAPPrivate *priv;

	g_return_val_if_fail (NM_IS_WIFI_AP (ap), FALSE);

	if (ssid_len > 32)
		g_return_val_if_reached (FALSE);

	priv = NM_WIFI_AP_GET_PRIVATE (ap);

	if (nm_utils_gbytes_equal_mem (priv->ssid, ssid, ssid_len))
		return FALSE;

	nm_clear_pointer (&priv->ssid, g_bytes_unref);
	if (ssid_len > 0)
		priv->ssid = g_bytes_new (ssid, ssid_len);

	_notify (ap, PROP_SSID);
	return TRUE;
}

gboolean
nm_wifi_ap_set_ssid (NMWifiAP *ap, GBytes *ssid)
{
	NMWifiAPPrivate *priv;
	gsize l;

	g_return_val_if_fail (NM_IS_WIFI_AP (ap), FALSE);

	if (ssid) {
		l = g_bytes_get_size (ssid);
		if (l == 0 || l > 32)
			g_return_val_if_reached (FALSE);
	}

	priv = NM_WIFI_AP_GET_PRIVATE (ap);

	if (ssid == priv->ssid)
		return FALSE;
	if (   ssid
	    && priv->ssid
	    && g_bytes_equal (ssid, priv->ssid))
		return FALSE;

	nm_clear_pointer (&priv->ssid, g_bytes_unref);
	if (ssid)
		priv->ssid = g_bytes_ref (ssid);

	_notify (ap, PROP_SSID);
	return TRUE;
}

static gboolean
nm_wifi_ap_set_flags (NMWifiAP *ap, NM80211ApFlags flags)
{
	NMWifiAPPrivate *priv;

	g_return_val_if_fail (NM_IS_WIFI_AP (ap), FALSE);

	priv = NM_WIFI_AP_GET_PRIVATE (ap);

	if (priv->flags != flags) {
		priv->flags = flags;
		_notify (ap, PROP_FLAGS);
		return TRUE;
	}
	return FALSE;
}

static gboolean
nm_wifi_ap_set_wpa_flags (NMWifiAP *ap, NM80211ApSecurityFlags flags)
{
	NMWifiAPPrivate *priv;

	g_return_val_if_fail (NM_IS_WIFI_AP (ap), FALSE);

	priv = NM_WIFI_AP_GET_PRIVATE (ap);
	if (priv->wpa_flags != flags) {
		priv->wpa_flags = flags;
		_notify (ap, PROP_WPA_FLAGS);
		return TRUE;
	}
	return FALSE;
}

static gboolean
nm_wifi_ap_set_rsn_flags (NMWifiAP *ap, NM80211ApSecurityFlags flags)
{
	NMWifiAPPrivate *priv;

	g_return_val_if_fail (NM_IS_WIFI_AP (ap), FALSE);

	priv = NM_WIFI_AP_GET_PRIVATE (ap);
	if (priv->rsn_flags != flags) {
		priv->rsn_flags = flags;
		_notify (ap, PROP_RSN_FLAGS);
		return TRUE;
	}
	return FALSE;
}

const char *
nm_wifi_ap_get_address (const NMWifiAP *ap)
{
	g_return_val_if_fail (NM_IS_WIFI_AP (ap), NULL);

	return NM_WIFI_AP_GET_PRIVATE (ap)->address;
}

static gboolean
nm_wifi_ap_set_address_bin (NMWifiAP *ap, const guint8 *addr /* ETH_ALEN bytes */)
{
	NMWifiAPPrivate *priv;

	priv = NM_WIFI_AP_GET_PRIVATE (ap);

	if (   !priv->address
	    || !nm_utils_hwaddr_matches (addr, ETH_ALEN, priv->address, -1)) {
		g_free (priv->address);
		priv->address = nm_utils_hwaddr_ntoa (addr, ETH_ALEN);
		_notify (ap, PROP_HW_ADDRESS);
		return TRUE;
	}
	return FALSE;
}

gboolean
nm_wifi_ap_set_address (NMWifiAP *ap, const char *addr)
{
	guint8 addr_buf[ETH_ALEN];

	g_return_val_if_fail (NM_IS_WIFI_AP (ap), FALSE);
	if (   !addr
	    || !nm_utils_hwaddr_aton (addr, addr_buf, sizeof (addr_buf)))
		g_return_val_if_reached (FALSE);

	return nm_wifi_ap_set_address_bin (ap, addr_buf);
}

NM80211Mode
nm_wifi_ap_get_mode (NMWifiAP *ap)
{
	g_return_val_if_fail (NM_IS_WIFI_AP (ap), NM_802_11_MODE_UNKNOWN);

	return NM_WIFI_AP_GET_PRIVATE (ap)->mode;
}

static gboolean
nm_wifi_ap_set_mode (NMWifiAP *ap, const NM80211Mode mode)
{
	NMWifiAPPrivate *priv;

	g_return_val_if_fail (NM_IS_WIFI_AP (ap), FALSE);
	g_return_val_if_fail (   mode == NM_802_11_MODE_ADHOC
	                      || mode == NM_802_11_MODE_INFRA
	                      || mode == NM_802_11_MODE_MESH, FALSE);

	priv = NM_WIFI_AP_GET_PRIVATE (ap);

	if (priv->mode != mode) {
		priv->mode = mode;
		_notify (ap, PROP_MODE);
		return TRUE;
	}
	return FALSE;
}

gboolean
nm_wifi_ap_is_hotspot (NMWifiAP *ap)
{
	g_return_val_if_fail (NM_IS_WIFI_AP (ap), FALSE);

	return NM_WIFI_AP_GET_PRIVATE (ap)->hotspot;
}

gint8
nm_wifi_ap_get_strength (NMWifiAP *ap)
{
	g_return_val_if_fail (NM_IS_WIFI_AP (ap), 0);

	return NM_WIFI_AP_GET_PRIVATE (ap)->strength;
}

gboolean
nm_wifi_ap_set_strength (NMWifiAP *ap, const gint8 strength)
{
	NMWifiAPPrivate *priv;

	g_return_val_if_fail (NM_IS_WIFI_AP (ap), FALSE);

	priv = NM_WIFI_AP_GET_PRIVATE (ap);

	if (priv->strength != strength) {
		priv->strength = strength;
		_notify (ap, PROP_STRENGTH);
		return TRUE;
	}
	return FALSE;
}

guint32
nm_wifi_ap_get_freq (NMWifiAP *ap)
{
	g_return_val_if_fail (NM_IS_WIFI_AP (ap), 0);

	return NM_WIFI_AP_GET_PRIVATE (ap)->freq;
}

gboolean
nm_wifi_ap_set_freq (NMWifiAP *ap,
                     const guint32 freq)
{
	NMWifiAPPrivate *priv;

	g_return_val_if_fail (NM_IS_WIFI_AP (ap), FALSE);

	priv = NM_WIFI_AP_GET_PRIVATE (ap);

	if (priv->freq != freq) {
		priv->freq = freq;
		_notify (ap, PROP_FREQUENCY);
		return TRUE;
	}
	return FALSE;
}

guint32
nm_wifi_ap_get_max_bitrate (NMWifiAP *ap)
{
	g_return_val_if_fail (NM_IS_WIFI_AP (ap), 0);
	g_return_val_if_fail (nm_dbus_object_is_exported (NM_DBUS_OBJECT (ap)), 0);

	return NM_WIFI_AP_GET_PRIVATE (ap)->max_bitrate;
}

gboolean
nm_wifi_ap_set_max_bitrate (NMWifiAP *ap, guint32 bitrate)
{
	NMWifiAPPrivate *priv;

	g_return_val_if_fail (NM_IS_WIFI_AP (ap), FALSE);

	priv = NM_WIFI_AP_GET_PRIVATE (ap);

	if (priv->max_bitrate != bitrate) {
		priv->max_bitrate = bitrate;
		_notify (ap, PROP_MAX_BITRATE);
		return TRUE;
	}
	return FALSE;
}

gboolean
nm_wifi_ap_get_fake (const NMWifiAP *ap)
{
	g_return_val_if_fail (NM_IS_WIFI_AP (ap), FALSE);

	return NM_WIFI_AP_GET_PRIVATE (ap)->fake;
}

gboolean
nm_wifi_ap_set_fake (NMWifiAP *ap, gboolean fake)
{
	NMWifiAPPrivate *priv;

	g_return_val_if_fail (NM_IS_WIFI_AP (ap), FALSE);

	priv = NM_WIFI_AP_GET_PRIVATE (ap);

	if (priv->fake != !!fake) {
		priv->fake = fake;
		return TRUE;
	}
	return FALSE;
}

NM80211ApFlags
nm_wifi_ap_get_flags (const NMWifiAP *ap)
{
	g_return_val_if_fail (NM_IS_WIFI_AP (ap), NM_802_11_AP_FLAGS_NONE);

	return NM_WIFI_AP_GET_PRIVATE (ap)->flags;
}

static gboolean
nm_wifi_ap_set_last_seen (NMWifiAP *ap, gint32 last_seen)
{
	NMWifiAPPrivate *priv;

	g_return_val_if_fail (NM_IS_WIFI_AP (ap), FALSE);

	priv = NM_WIFI_AP_GET_PRIVATE (ap);

	if (priv->last_seen != last_seen) {
		priv->last_seen = last_seen;
		_notify (ap, PROP_LAST_SEEN);
		return TRUE;
	}
	return FALSE;
}

gboolean
nm_wifi_ap_get_metered (const NMWifiAP *self)
{
	return NM_WIFI_AP_GET_PRIVATE (self)->metered;
}

/*****************************************************************************/

static NM80211ApSecurityFlags
security_from_vardict (GVariant *security)
{
	NM80211ApSecurityFlags flags = NM_802_11_AP_SEC_NONE;
	const char **array, *tmp;

	g_return_val_if_fail (g_variant_is_of_type (security, G_VARIANT_TYPE_VARDICT), NM_802_11_AP_SEC_NONE);

	if (   g_variant_lookup (security, "KeyMgmt", "^a&s", &array)
	    && array) {
		if (g_strv_contains (array, "wpa-psk") ||
		    g_strv_contains (array, "wpa-ft-psk"))
			flags |= NM_802_11_AP_SEC_KEY_MGMT_PSK;
		if (g_strv_contains (array, "wpa-eap") ||
		    g_strv_contains (array, "wpa-ft-eap") ||
		    g_strv_contains (array, "wpa-fils-sha256") ||
		    g_strv_contains (array, "wpa-fils-sha384"))
			flags |= NM_802_11_AP_SEC_KEY_MGMT_802_1X;
		if (g_strv_contains (array, "sae"))
			flags |= NM_802_11_AP_SEC_KEY_MGMT_SAE;
		g_free (array);
	}

	if (   g_variant_lookup (security, "Pairwise", "^a&s", &array)
	    && array) {
		if (g_strv_contains (array, "tkip"))
			flags |= NM_802_11_AP_SEC_PAIR_TKIP;
		if (g_strv_contains (array, "ccmp"))
			flags |= NM_802_11_AP_SEC_PAIR_CCMP;
		g_free (array);
	}

	if (g_variant_lookup (security, "Group", "&s", &tmp)) {
		if (strcmp (tmp, "wep40") == 0)
			flags |= NM_802_11_AP_SEC_GROUP_WEP40;
		if (strcmp (tmp, "wep104") == 0)
			flags |= NM_802_11_AP_SEC_GROUP_WEP104;
		if (strcmp (tmp, "tkip") == 0)
			flags |= NM_802_11_AP_SEC_GROUP_TKIP;
		if (strcmp (tmp, "ccmp") == 0)
			flags |= NM_802_11_AP_SEC_GROUP_CCMP;
	}

	return flags;
}

/*****************************************************************************/

static guint32
get_max_rate_ht_20 (int mcs)
{
	switch (mcs) {
	case 0:  return 6500000;
	case 1:
	case 8:  return 13000000;
	case 2:
	case 16: return 19500000;
	case 3:
	case 9:
	case 24: return 26000000;
	case 4:
	case 10:
	case 17: return 39000000;
	case 5:
	case 11:
	case 25: return 52000000;
	case 6:
	case 18: return 58500000;
	case 7:  return 65000000;
	case 12:
	case 19:
	case 26: return 78000000;
	case 13:
	case 27: return 104000000;
	case 14:
	case 20: return 117000000;
	case 15: return 130000000;
	case 21:
	case 28: return 156000000;
	case 22: return 175500000;
	case 23: return 195000000;
	case 29: return 208000000;
	case 30: return 234000000;
	case 31: return 260000000;
	}
	return 0;
}

static guint32
get_max_rate_ht_40 (int mcs)
{
	switch (mcs) {
	case 0:  return 13500000;
	case 1:
	case 8:  return 27000000;
	case 2:  return 40500000;
	case 3:
	case 9:
	case 24: return 54000000;
	case 4:
	case 10:
	case 17: return 81000000;
	case 5:
	case 11:
	case 25: return 108000000;
	case 6:
	case 18: return 121500000;
	case 7:  return 135000000;
	case 12:
	case 19:
	case 26: return 162000000;
	case 13:
	case 27: return 216000000;
	case 14:
	case 20: return 243000000;
	case 15: return 270000000;
	case 16: return 40500000;
	case 21:
	case 28: return 324000000;
	case 22: return 364500000;
	case 23: return 405000000;
	case 29: return 432000000;
	case 30: return 486000000;
	case 31: return 540000000;
	}
	return 0;
}

static guint32
get_max_rate_vht_80_ss1 (int mcs)
{
	switch (mcs) {
	case 0:  return 29300000;
	case 1:  return 58500000;
	case 2:  return 87800000;
	case 3:  return 117000000;
	case 4:  return 175500000;
	case 5:  return 234000000;
	case 6:  return 263300000;
	case 7:  return 292500000;
	case 8:  return 351000000;
	case 9:  return 390000000;
	}
	return 0;
}

static guint32
get_max_rate_vht_80_ss2 (int mcs)
{
	switch (mcs) {
	case 0:  return 58500000;
	case 1:  return 117000000;
	case 2:  return 175500000;
	case 3:  return 234000000;
	case 4:  return 351000000;
	case 5:  return 468000000;
	case 6:  return 526500000;
	case 7:  return 585000000;
	case 8:  return 702000000;
	case 9:  return 780000000;
	}
	return 0;
}

static guint32
get_max_rate_vht_80_ss3 (int mcs)
{
	switch (mcs) {
	case 0:  return 87800000;
	case 1:  return 175500000;
	case 2:  return 263300000;
	case 3:  return 351000000;
	case 4:  return 526500000;
	case 5:  return 702000000;
	case 6:  return 0;
	case 7:  return 877500000;
	case 8:  return 105300000;
	case 9:  return 117000000;
	}
	return 0;
}

static guint32
get_max_rate_vht_160_ss1 (int mcs)
{
	switch (mcs) {
	case 0:  return 58500000;
	case 1:  return 117000000;
	case 2:  return 175500000;
	case 3:  return 234000000;
	case 4:  return 351000000;
	case 5:  return 468000000;
	case 6:  return 526500000;
	case 7:  return 585000000;
	case 8:  return 702000000;
	case 9:  return 780000000;
	}
	return 0;
}

static guint32
get_max_rate_vht_160_ss2 (int mcs)
{
	switch (mcs) {
	case 0:  return 117000000;
	case 1:  return 234000000;
	case 2:  return 351000000;
	case 3:  return 468000000;
	case 4:  return 702000000;
	case 5:  return 936000000;
	case 6:  return 1053000000;
	case 7:  return 1170000000;
	case 8:  return 1404000000;
	case 9:  return 1560000000;
	}
	return 0;
}

static guint32
get_max_rate_vht_160_ss3 (int mcs)
{
	switch (mcs) {
	case 0:  return 175500000;
	case 1:  return 351000000;
	case 2:  return 526500000;
	case 3:  return 702000000;
	case 4:  return 1053000000;
	case 5:  return 1404000000;
	case 6:  return 1579500000;
	case 7:  return 1755000000;
	case 8:  return 2106000000;
	case 9:  return 0;
	}
	return 0;
}

static gboolean
get_max_rate_ht (const guint8 *bytes, guint len, guint32 *out_maxrate)
{
	guint32 i;
	guint8 ht_cap_info;
	const guint8 *supported_mcs_set;
	guint32 rate;

	/* http://standards.ieee.org/getieee802/download/802.11-2012.pdf
	 * https://mrncciew.com/2014/10/19/cwap-ht-capabilities-ie/
	 */

	if (len != 26)
		return FALSE;

	ht_cap_info = bytes[0];
	supported_mcs_set = &bytes[3];
	*out_maxrate = 0;

	/* Find the maximum supported mcs rate */
	for (i = 0; i <= 76; i++) {
		unsigned int mcs_octet = i / 8;
		unsigned int MCS_RATE_BIT = 1 << i % 8;

		if (supported_mcs_set[mcs_octet] & MCS_RATE_BIT) {
			/* Check for 40Mhz wide channel support */
			if (ht_cap_info & (1 << 1))
				rate = get_max_rate_ht_40 (i);
			else
				rate = get_max_rate_ht_20 (i);

			if (rate > *out_maxrate)
				*out_maxrate = rate;
		}
	}

	return TRUE;
}

static gboolean
get_max_rate_vht (const guint8 *bytes, guint len, guint32 *out_maxrate)
{
	guint32 mcs, m;
	guint8 vht_cap, tx_map;

	/* https://tda802dot11.blogspot.it/2014/10/vht-capabilities-element-vht.html
	 * http://chimera.labs.oreilly.com/books/1234000001739/ch03.html#management_frames */

	if (len != 12)
		return FALSE;

	vht_cap = bytes[0];
	tx_map = bytes[8];

	/* Check for mcs rates 8 and 9 support */
	if (tx_map & 0x2a)
		mcs = 9;
	else if (tx_map & 0x15)
		mcs = 8;
	else
		mcs = 7;

	/* Check for 160Mhz wide channel support and
	 * spatial stream support */
	if (vht_cap & (1 << 2)) {
		if (tx_map & 0x30)
			m = get_max_rate_vht_160_ss3 (mcs);
		else if (tx_map & 0x0C)
			m = get_max_rate_vht_160_ss2 (mcs);
		else
			m = get_max_rate_vht_160_ss1 (mcs);
	} else {
		if (tx_map & 0x30)
			m = get_max_rate_vht_80_ss3 (mcs);
		else if (tx_map & 0x0C)
			m = get_max_rate_vht_80_ss2 (mcs);
		else
			m = get_max_rate_vht_80_ss1 (mcs);
	}

	*out_maxrate = m;
	return TRUE;
}

/* Management Frame Information Element IDs, ieee80211_eid */
#define WLAN_EID_HT_CAPABILITY       45
#define WLAN_EID_VHT_CAPABILITY     191
#define WLAN_EID_VENDOR_SPECIFIC    221

static void
parse_ies (const guint8 *bytes, gsize len, guint32 *out_max_rate, gboolean *out_metered)
{
	guint8 id, elem_len;
	guint32 m;

	*out_max_rate = 0;
	*out_metered = FALSE;

	while (len) {
		if (len < 2)
			break;

		id = *bytes++;
		elem_len = *bytes++;
		len -= 2;

		if (elem_len > len)
			break;

		switch (id) {
		case WLAN_EID_HT_CAPABILITY:
			if (get_max_rate_ht (bytes, elem_len, &m))
				*out_max_rate = NM_MAX (*out_max_rate, m);
			break;
		case WLAN_EID_VHT_CAPABILITY:
			if (get_max_rate_vht (bytes, elem_len, &m))
				*out_max_rate = NM_MAX (*out_max_rate, m);
			break;
		case WLAN_EID_VENDOR_SPECIFIC:
			if (   len == 8
			    && bytes[0] == 0x00            /* OUI: Microsoft */
			    && bytes[1] == 0x50
			    && bytes[2] == 0xf2
			    && bytes[3] == 0x11)           /* OUI type: Network cost */
				*out_metered = (bytes[7] > 1); /* Cost level > 1 */
			break;
		}

		len -= elem_len;
		bytes += elem_len;
	}
}

/*****************************************************************************/

gboolean
nm_wifi_ap_update_from_properties (NMWifiAP *ap,
                                   const char *supplicant_path,
                                   GVariant *properties)
{
	NMWifiAPPrivate *priv;
	const guint8 *bytes;
	GVariant *v;
	gsize len;
	gsize i;
	gboolean b = FALSE;
	const char *s;
	gint16 i16;
	guint16 u16;
	gboolean changed = FALSE;
	gboolean metered;
	guint32 max_rate, rate;

	g_return_val_if_fail (NM_IS_WIFI_AP (ap), FALSE);
	g_return_val_if_fail (properties, FALSE);

	priv = NM_WIFI_AP_GET_PRIVATE (ap);

	g_object_freeze_notify (G_OBJECT (ap));

	if (g_variant_lookup (properties, "Privacy", "b", &b) && b)
		changed |= nm_wifi_ap_set_flags (ap, priv->flags | NM_802_11_AP_FLAGS_PRIVACY);

	v = g_variant_lookup_value (properties, "WPS", G_VARIANT_TYPE_VARDICT);
	if (v) {
		if (g_variant_lookup (v, "Type", "&s", &s)) {
			changed |= nm_wifi_ap_set_flags (ap, priv->flags | NM_802_11_AP_FLAGS_WPS);
			if (strcmp (s, "pbc") == 0)
				changed |= nm_wifi_ap_set_flags (ap, priv->flags | NM_802_11_AP_FLAGS_WPS_PBC);
			else if (strcmp (s, "pin") == 0)
				changed |= nm_wifi_ap_set_flags (ap, priv->flags | NM_802_11_AP_FLAGS_WPS_PIN);
		}
		g_variant_unref (v);
	}

	if (g_variant_lookup (properties, "Mode", "&s", &s)) {
		if (!g_strcmp0 (s, "infrastructure"))
			changed |= nm_wifi_ap_set_mode (ap, NM_802_11_MODE_INFRA);
		else if (!g_strcmp0 (s, "ad-hoc"))
			changed |= nm_wifi_ap_set_mode (ap, NM_802_11_MODE_ADHOC);
		else if (!g_strcmp0 (s, "mesh"))
			changed |= nm_wifi_ap_set_mode (ap, NM_802_11_MODE_MESH);
	}

	if (g_variant_lookup (properties, "Signal", "n", &i16))
		changed |= nm_wifi_ap_set_strength (ap, nm_wifi_utils_level_to_quality (i16));

	if (g_variant_lookup (properties, "Frequency", "q", &u16))
		changed |= nm_wifi_ap_set_freq (ap, u16);

	v = g_variant_lookup_value (properties, "SSID", G_VARIANT_TYPE_BYTESTRING);
	if (v) {
		bytes = g_variant_get_fixed_array (v, &len, 1);
		len = MIN (32, len);

		/* Stupid ieee80211 layer uses <hidden> */
		if (   bytes
		    && len
		    && !(   NM_IN_SET (len, 8, 9)
		         && memcmp (bytes, "<hidden>", len) == 0)
		    && !nm_utils_is_empty_ssid (bytes, len)) {
			/* good */
		} else
			len = 0;

		changed |= nm_wifi_ap_set_ssid_arr (ap, bytes, len);

		g_variant_unref (v);
	}

	v = g_variant_lookup_value (properties, "BSSID", G_VARIANT_TYPE_BYTESTRING);
	if (v) {
		bytes = g_variant_get_fixed_array (v, &len, 1);
		if (   len == ETH_ALEN
		    && memcmp (bytes, nm_ip_addr_zero.addr_eth, ETH_ALEN) != 0
		    && memcmp (bytes, (char[ETH_ALEN]) { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, ETH_ALEN) != 0)
			changed |= nm_wifi_ap_set_address_bin (ap, bytes);
		g_variant_unref (v);
	}

	max_rate = 0;
	v = g_variant_lookup_value (properties, "Rates", G_VARIANT_TYPE ("au"));
	if (v) {
		const guint32 *rates = g_variant_get_fixed_array (v, &len, sizeof (guint32));

		for (i = 0; i < len; i++)
			max_rate = NM_MAX (max_rate, rates[i]);
		g_variant_unref (v);
	}
	v = g_variant_lookup_value (properties, "IEs", G_VARIANT_TYPE_BYTESTRING);
	if (v) {
		bytes = g_variant_get_fixed_array (v, &len, 1);
		parse_ies (bytes, len, &rate, &metered);
		max_rate = NM_MAX (max_rate, rate);
		g_variant_unref (v);
		priv->metered = metered;
	}

	if (max_rate)
		changed |= nm_wifi_ap_set_max_bitrate (ap, max_rate / 1000);

	v = g_variant_lookup_value (properties, "WPA", G_VARIANT_TYPE_VARDICT);
	if (v) {
		changed |= nm_wifi_ap_set_wpa_flags (ap, priv->wpa_flags | security_from_vardict (v));
		g_variant_unref (v);
	}

	v = g_variant_lookup_value (properties, "RSN", G_VARIANT_TYPE_VARDICT);
	if (v) {
		changed |= nm_wifi_ap_set_rsn_flags (ap, priv->rsn_flags | security_from_vardict (v));
		g_variant_unref (v);
	}

	if (!priv->supplicant_path) {
		priv->supplicant_path = g_strdup (supplicant_path);
		changed = TRUE;
	}

	changed |= nm_wifi_ap_set_last_seen (ap, nm_utils_get_monotonic_timestamp_s ());
	changed |= nm_wifi_ap_set_fake (ap, FALSE);

	g_object_thaw_notify (G_OBJECT (ap));

	return changed;
}

static gboolean
has_proto (NMSettingWirelessSecurity *sec, const char *proto)
{
	guint32 num_protos = nm_setting_wireless_security_get_num_protos (sec);
	guint32 i;

	if (num_protos == 0)
		return TRUE; /* interpret no protos as "all" */

	for (i = 0; i < num_protos; i++) {
		if (!strcmp (nm_setting_wireless_security_get_proto (sec, i), proto))
			return TRUE;
	}
	return FALSE;
}

static void
add_pair_ciphers (NMWifiAP *ap, NMSettingWirelessSecurity *sec)
{
	NMWifiAPPrivate *priv = NM_WIFI_AP_GET_PRIVATE (ap);
	guint32 num = nm_setting_wireless_security_get_num_pairwise (sec);
	NM80211ApSecurityFlags flags = NM_802_11_AP_SEC_NONE;
	guint32 i;

	/* If no ciphers are specified, that means "all" WPA ciphers */
	if (num == 0) {
		flags |= NM_802_11_AP_SEC_PAIR_TKIP | NM_802_11_AP_SEC_PAIR_CCMP;
	} else {
		for (i = 0; i < num; i++) {
			const char *cipher = nm_setting_wireless_security_get_pairwise (sec, i);

			if (!strcmp (cipher, "tkip"))
				flags |= NM_802_11_AP_SEC_PAIR_TKIP;
			else if (!strcmp (cipher, "ccmp"))
				flags |= NM_802_11_AP_SEC_PAIR_CCMP;
		}
	}

	if (has_proto (sec, PROTO_WPA))
		nm_wifi_ap_set_wpa_flags (ap, priv->wpa_flags | flags);
	if (has_proto (sec, PROTO_RSN))
		nm_wifi_ap_set_rsn_flags (ap, priv->rsn_flags | flags);
}

static void
add_group_ciphers (NMWifiAP *ap, NMSettingWirelessSecurity *sec)
{
	NMWifiAPPrivate *priv = NM_WIFI_AP_GET_PRIVATE (ap);
	guint32 num = nm_setting_wireless_security_get_num_groups (sec);
	NM80211ApSecurityFlags flags = NM_802_11_AP_SEC_NONE;
	guint32 i;

	/* If no ciphers are specified, that means "all" WPA ciphers */
	if (num == 0) {
		flags |= NM_802_11_AP_SEC_GROUP_TKIP | NM_802_11_AP_SEC_GROUP_CCMP;
	} else {
		for (i = 0; i < num; i++) {
			const char *cipher = nm_setting_wireless_security_get_group (sec, i);

			if (!strcmp (cipher, "wep40"))
				flags |= NM_802_11_AP_SEC_GROUP_WEP40;
			else if (!strcmp (cipher, "wep104"))
				flags |= NM_802_11_AP_SEC_GROUP_WEP104;
			else if (!strcmp (cipher, "tkip"))
				flags |= NM_802_11_AP_SEC_GROUP_TKIP;
			else if (!strcmp (cipher, "ccmp"))
				flags |= NM_802_11_AP_SEC_GROUP_CCMP;
		}
	}

	if (has_proto (sec, PROTO_WPA))
		nm_wifi_ap_set_wpa_flags (ap, priv->wpa_flags | flags);
	if (has_proto (sec, PROTO_RSN))
		nm_wifi_ap_set_rsn_flags (ap, priv->rsn_flags | flags);
}

const char *
nm_wifi_ap_to_string (const NMWifiAP *self,
                      char *str_buf,
                      gulong buf_len,
                      gint32 now_s)
{
	const NMWifiAPPrivate *priv;
	const char *supplicant_id = "-";
	const char *export_path;
	guint32 chan;
	gs_free char *ssid_to_free = NULL;

	g_return_val_if_fail (NM_IS_WIFI_AP (self), NULL);

	priv = NM_WIFI_AP_GET_PRIVATE (self);
	chan = nm_utils_wifi_freq_to_channel (priv->freq);
	if (priv->supplicant_path)
		supplicant_id = strrchr (priv->supplicant_path, '/') ?: supplicant_id;

	export_path = nm_dbus_object_get_path (NM_DBUS_OBJECT (self));
	if (export_path)
		export_path = strrchr (export_path, '/') ?: export_path;
	else
		export_path = "/";

	g_snprintf (str_buf, buf_len,
	            "%17s %-35s [ %c %3u %3u%% %c%c W:%04X R:%04X ] %3us sup:%s [nm:%s]",
	            priv->address ?: "(none)",
	            (ssid_to_free = _nm_utils_ssid_to_string (priv->ssid)),
	            (priv->mode == NM_802_11_MODE_ADHOC
	                 ? '*'
	                 : (priv->hotspot
	                        ? '#'
	                        : (priv->fake
	                               ? 'f'
	                               : (priv->mode == NM_802_11_MODE_MESH
	                                      ? 'm'
	                                      : 'a')))),
	            chan,
	            priv->strength,
	            priv->flags & NM_802_11_AP_FLAGS_PRIVACY ? 'P' : '_',
	            priv->metered ? 'M' : '_',
	            priv->wpa_flags & 0xFFFF,
	            priv->rsn_flags & 0xFFFF,
	            priv->last_seen > 0 ? ((now_s > 0 ? now_s : nm_utils_get_monotonic_timestamp_s ()) - priv->last_seen) : -1,
	            supplicant_id,
	            export_path);
	return str_buf;
}

static guint
freq_to_band (guint32 freq)
{
	if (freq >= 4915 && freq <= 5825)
		return 5;
	else if (freq >= 2412 && freq <= 2484)
		return 2;
	return 0;
}

gboolean
nm_wifi_ap_check_compatible (NMWifiAP *self,
                             NMConnection *connection)
{
	NMWifiAPPrivate *priv;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wireless_sec;
	GBytes *ssid;
	const char *mode;
	const char *band;
	const char *bssid;
	guint32 channel;

	g_return_val_if_fail (NM_IS_WIFI_AP (self), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	priv = NM_WIFI_AP_GET_PRIVATE (self);

	s_wireless = nm_connection_get_setting_wireless (connection);
	if (s_wireless == NULL)
		return FALSE;

	ssid = nm_setting_wireless_get_ssid (s_wireless);
	if (ssid != priv->ssid) {
		if (!ssid || !priv->ssid)
			return FALSE;
		if (!g_bytes_equal (ssid, priv->ssid))
			return FALSE;
	}

	bssid = nm_setting_wireless_get_bssid (s_wireless);
	if (bssid && (!priv->address || !nm_utils_hwaddr_matches (bssid, -1, priv->address, -1)))
		return FALSE;

	mode = nm_setting_wireless_get_mode (s_wireless);
	if (mode) {
		if (!strcmp (mode, "infrastructure") && (priv->mode != NM_802_11_MODE_INFRA))
			return FALSE;
		if (!strcmp (mode, "adhoc") && (priv->mode != NM_802_11_MODE_ADHOC))
			return FALSE;
		if (   !strcmp (mode, "ap")
		    && (priv->mode != NM_802_11_MODE_INFRA || priv->hotspot != TRUE))
			return FALSE;
		if (!strcmp (mode, "mesh") && (priv->mode != NM_802_11_MODE_MESH))
			return FALSE;
	}

	band = nm_setting_wireless_get_band (s_wireless);
	if (band) {
		guint ap_band = freq_to_band (priv->freq);

		if (!strcmp (band, "a") && ap_band != 5)
			return FALSE;
		else if (!strcmp (band, "bg") && ap_band != 2)
			return FALSE;
	}

	channel = nm_setting_wireless_get_channel (s_wireless);
	if (channel) {
		guint32 ap_chan = nm_utils_wifi_freq_to_channel (priv->freq);

		if (channel != ap_chan)
			return FALSE;
	}

	s_wireless_sec = nm_connection_get_setting_wireless_security (connection);

	return nm_setting_wireless_ap_security_compatible (s_wireless,
	                                                   s_wireless_sec,
	                                                   priv->flags,
	                                                   priv->wpa_flags,
	                                                   priv->rsn_flags,
	                                                   priv->mode);
}

gboolean
nm_wifi_ap_complete_connection (NMWifiAP *self,
                                NMConnection *connection,
                                gboolean lock_bssid,
                                GError **error)
{
	NMWifiAPPrivate *priv = NM_WIFI_AP_GET_PRIVATE (self);

	g_return_val_if_fail (connection != NULL, FALSE);

	return nm_wifi_utils_complete_connection (priv->ssid,
	                                          priv->address,
	                                          priv->mode,
	                                          priv->freq,
	                                          priv->flags,
	                                          priv->wpa_flags,
	                                          priv->rsn_flags,
	                                          connection,
	                                          lock_bssid,
	                                          error);
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMWifiAP *self = NM_WIFI_AP (object);
	NMWifiAPPrivate *priv = NM_WIFI_AP_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_FLAGS:
		g_value_set_uint (value, priv->flags);
		break;
	case PROP_WPA_FLAGS:
		g_value_set_uint (value, priv->wpa_flags);
		break;
	case PROP_RSN_FLAGS:
		g_value_set_uint (value, priv->rsn_flags);
		break;
	case PROP_SSID:
		g_value_take_variant (value,
		                      nm_utils_gbytes_to_variant_ay (priv->ssid));
		break;
	case PROP_FREQUENCY:
		g_value_set_uint (value, priv->freq);
		break;
	case PROP_HW_ADDRESS:
		g_value_set_string (value, priv->address);
		break;
	case PROP_MODE:
		g_value_set_uint (value, priv->mode);
		break;
	case PROP_MAX_BITRATE:
		g_value_set_uint (value, priv->max_bitrate);
		break;
	case PROP_STRENGTH:
		g_value_set_uchar (value, priv->strength);
		break;
	case PROP_LAST_SEEN:
		g_value_set_int (value,
		                 priv->last_seen > 0
		                     ? (int) nm_utils_monotonic_timestamp_as_boottime (priv->last_seen, NM_UTILS_NS_PER_SECOND)
		                     : -1);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_wifi_ap_init (NMWifiAP *self)
{
	NMWifiAPPrivate *priv;

	priv = G_TYPE_INSTANCE_GET_PRIVATE (self, NM_TYPE_WIFI_AP, NMWifiAPPrivate);

	self->_priv = priv;

	c_list_init (&self->aps_lst);

	priv->mode = NM_802_11_MODE_INFRA;
	priv->flags = NM_802_11_AP_FLAGS_NONE;
	priv->wpa_flags = NM_802_11_AP_SEC_NONE;
	priv->rsn_flags = NM_802_11_AP_SEC_NONE;
	priv->last_seen = -1;
}

NMWifiAP *
nm_wifi_ap_new_from_properties (const char *supplicant_path, GVariant *properties)
{
	NMWifiAP *ap;

	g_return_val_if_fail (supplicant_path != NULL, NULL);
	g_return_val_if_fail (properties != NULL, NULL);

	ap = (NMWifiAP *) g_object_new (NM_TYPE_WIFI_AP, NULL);
	nm_wifi_ap_update_from_properties (ap, supplicant_path, properties);

	/* ignore APs with invalid or missing BSSIDs */
	if (!nm_wifi_ap_get_address (ap)) {
		g_object_unref (ap);
		return NULL;
	}

	return ap;
}

NMWifiAP *
nm_wifi_ap_new_fake_from_connection (NMConnection *connection)
{
	NMWifiAP *ap;
	NMWifiAPPrivate *priv;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wireless_sec;
	const char *mode, *band, *key_mgmt;
	guint32 channel;
	NM80211ApSecurityFlags flags;
	gboolean psk = FALSE, eap = FALSE, adhoc = FALSE;

	g_return_val_if_fail (connection != NULL, NULL);

	s_wireless = nm_connection_get_setting_wireless (connection);
	g_return_val_if_fail (s_wireless != NULL, NULL);

	ap = (NMWifiAP *) g_object_new (NM_TYPE_WIFI_AP, NULL);
	priv = NM_WIFI_AP_GET_PRIVATE (ap);
	priv->fake = TRUE;

	nm_wifi_ap_set_ssid (ap,
	                     nm_setting_wireless_get_ssid (s_wireless));

	// FIXME: bssid too?

	mode = nm_setting_wireless_get_mode (s_wireless);
	if (mode) {
		if (!strcmp (mode, "infrastructure"))
			nm_wifi_ap_set_mode (ap, NM_802_11_MODE_INFRA);
		else if (!strcmp (mode, "adhoc")) {
			nm_wifi_ap_set_mode (ap, NM_802_11_MODE_ADHOC);
			adhoc = TRUE;
		} else if (!strcmp (mode, "mesh"))
			nm_wifi_ap_set_mode (ap, NM_802_11_MODE_MESH);
		else if (!strcmp (mode, "ap")) {
			nm_wifi_ap_set_mode (ap, NM_802_11_MODE_INFRA);
			NM_WIFI_AP_GET_PRIVATE (ap)->hotspot = TRUE;
		} else
			goto error;
	} else {
		nm_wifi_ap_set_mode (ap, NM_802_11_MODE_INFRA);
	}

	band = nm_setting_wireless_get_band (s_wireless);
	channel = nm_setting_wireless_get_channel (s_wireless);

	if (band && channel) {
		guint32 freq = nm_utils_wifi_channel_to_freq (channel, band);

		if (freq == 0)
			goto error;

		nm_wifi_ap_set_freq (ap, freq);
	}

	s_wireless_sec = nm_connection_get_setting_wireless_security (connection);
	/* Assume presence of a security setting means the AP is encrypted */
	if (!s_wireless_sec)
		goto done;

	key_mgmt = nm_setting_wireless_security_get_key_mgmt (s_wireless_sec);

	/* Everything below here uses encryption */
	nm_wifi_ap_set_flags (ap, priv->flags | NM_802_11_AP_FLAGS_PRIVACY);

	/* Static & Dynamic WEP */
	if (!strcmp (key_mgmt, "none") || !strcmp (key_mgmt, "ieee8021x"))
		goto done;

	psk = !strcmp (key_mgmt, "wpa-psk");
	eap = !strcmp (key_mgmt, "wpa-eap");
	if (!adhoc && (psk || eap)) {
		if (has_proto (s_wireless_sec, PROTO_WPA)) {
			flags = priv->wpa_flags | (eap ? NM_802_11_AP_SEC_KEY_MGMT_802_1X : NM_802_11_AP_SEC_KEY_MGMT_PSK);
			nm_wifi_ap_set_wpa_flags (ap, flags);
		}
		if (has_proto (s_wireless_sec, PROTO_RSN)) {
			flags = priv->rsn_flags | (eap ? NM_802_11_AP_SEC_KEY_MGMT_802_1X : NM_802_11_AP_SEC_KEY_MGMT_PSK);
			nm_wifi_ap_set_rsn_flags (ap, flags);
		}

		add_pair_ciphers (ap, s_wireless_sec);
		add_group_ciphers (ap, s_wireless_sec);
	} else if (adhoc && psk) {
		/* Ad-Hoc has special requirements: proto=RSN, pairwise=CCMP and
		 * group=CCMP.
		 */
		flags = priv->wpa_flags | NM_802_11_AP_SEC_KEY_MGMT_PSK;

		/* Clear ciphers; only CCMP is supported */
		flags &= ~(  NM_802_11_AP_SEC_PAIR_WEP40
		           | NM_802_11_AP_SEC_PAIR_WEP104
		           | NM_802_11_AP_SEC_PAIR_TKIP
		           | NM_802_11_AP_SEC_GROUP_WEP40
		           | NM_802_11_AP_SEC_GROUP_WEP104
		           | NM_802_11_AP_SEC_GROUP_TKIP);

		flags |= NM_802_11_AP_SEC_PAIR_CCMP;
		flags |= NM_802_11_AP_SEC_GROUP_CCMP;
		nm_wifi_ap_set_rsn_flags (ap, flags);

		/* Don't use Ad-Hoc WPA (WPA-none) anymore */
		nm_wifi_ap_set_wpa_flags (ap, NM_802_11_AP_SEC_NONE);
	}
done:
	return ap;

error:
	g_object_unref (ap);
	return NULL;
}

static void
finalize (GObject *object)
{
	NMWifiAP *self = NM_WIFI_AP (object);
	NMWifiAPPrivate *priv = NM_WIFI_AP_GET_PRIVATE (self);

	nm_assert (!self->wifi_device);
	nm_assert (c_list_is_empty (&self->aps_lst));

	g_free (priv->supplicant_path);
	if (priv->ssid)
		g_bytes_unref (priv->ssid);
	g_free (priv->address);

	G_OBJECT_CLASS (nm_wifi_ap_parent_class)->finalize (object);
}

static const NMDBusInterfaceInfoExtended interface_info_access_point = {
	.parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (
		NM_DBUS_INTERFACE_ACCESS_POINT,
		.signals = NM_DEFINE_GDBUS_SIGNAL_INFOS (
			&nm_signal_info_property_changed_legacy,
		),
		.properties = NM_DEFINE_GDBUS_PROPERTY_INFOS (
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Flags",      "u",  NM_WIFI_AP_FLAGS),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("WpaFlags",   "u",  NM_WIFI_AP_WPA_FLAGS),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("RsnFlags",   "u",  NM_WIFI_AP_RSN_FLAGS),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Ssid",       "ay", NM_WIFI_AP_SSID),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Frequency",  "u",  NM_WIFI_AP_FREQUENCY),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("HwAddress",  "s",  NM_WIFI_AP_HW_ADDRESS),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Mode",       "u",  NM_WIFI_AP_MODE),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("MaxBitrate", "u",  NM_WIFI_AP_MAX_BITRATE),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Strength",   "y",  NM_WIFI_AP_STRENGTH),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("LastSeen",   "i",  NM_WIFI_AP_LAST_SEEN),
		),
	),
	.legacy_property_changed = TRUE,
};

static void
nm_wifi_ap_class_init (NMWifiAPClass *ap_class)
{
#define ALL_SEC_FLAGS \
	( NM_802_11_AP_SEC_NONE \
	| NM_802_11_AP_SEC_PAIR_WEP40 \
	| NM_802_11_AP_SEC_PAIR_WEP104 \
	| NM_802_11_AP_SEC_PAIR_TKIP \
	| NM_802_11_AP_SEC_PAIR_CCMP \
	| NM_802_11_AP_SEC_GROUP_WEP40 \
	| NM_802_11_AP_SEC_GROUP_WEP104 \
	| NM_802_11_AP_SEC_GROUP_TKIP \
	| NM_802_11_AP_SEC_GROUP_CCMP \
	| NM_802_11_AP_SEC_KEY_MGMT_PSK \
	| NM_802_11_AP_SEC_KEY_MGMT_802_1X \
	| NM_802_11_AP_SEC_KEY_MGMT_SAE )

	GObjectClass *object_class = G_OBJECT_CLASS (ap_class);
	NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS (ap_class);

	g_type_class_add_private (object_class, sizeof (NMWifiAPPrivate));

	dbus_object_class->export_path = NM_DBUS_EXPORT_PATH_NUMBERED (NM_DBUS_PATH_ACCESS_POINT);
	dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS (&interface_info_access_point);

	object_class->get_property = get_property;
	object_class->finalize = finalize;

	obj_properties[PROP_FLAGS] =
	    g_param_spec_uint (NM_WIFI_AP_FLAGS, "", "",
	                       NM_802_11_AP_FLAGS_NONE,
	                       NM_802_11_AP_FLAGS_PRIVACY,
	                       NM_802_11_AP_FLAGS_NONE,
	                       G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_WPA_FLAGS] =
	    g_param_spec_uint (NM_WIFI_AP_WPA_FLAGS, "", "",
	                       NM_802_11_AP_SEC_NONE,
	                       ALL_SEC_FLAGS,
	                       NM_802_11_AP_SEC_NONE,
	                       G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_RSN_FLAGS] =
	    g_param_spec_uint (NM_WIFI_AP_RSN_FLAGS, "", "",
	                       NM_802_11_AP_SEC_NONE,
	                       ALL_SEC_FLAGS,
	                       NM_802_11_AP_SEC_NONE,
	                       G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_SSID] =
	    g_param_spec_variant (NM_WIFI_AP_SSID, "", "",
	                          G_VARIANT_TYPE ("ay"),
	                          NULL,
	                          G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_FREQUENCY] =
	    g_param_spec_uint (NM_WIFI_AP_FREQUENCY, "", "",
	                       0, 10000, 0,
	                       G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_HW_ADDRESS] =
	    g_param_spec_string (NM_WIFI_AP_HW_ADDRESS, "", "",
	                         NULL,
	                         G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_MODE] =
	    g_param_spec_uint (NM_WIFI_AP_MODE, "", "",
	                       NM_802_11_MODE_ADHOC, NM_802_11_MODE_INFRA, NM_802_11_MODE_INFRA,
	                       G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_MAX_BITRATE] =
	    g_param_spec_uint (NM_WIFI_AP_MAX_BITRATE, "", "",
	                       0, G_MAXUINT16, 0,
	                       G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_STRENGTH] =
	    g_param_spec_uchar (NM_WIFI_AP_STRENGTH, "", "",
	                        0, G_MAXINT8, 0,
	                        G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_LAST_SEEN] =
	    g_param_spec_int (NM_WIFI_AP_LAST_SEEN, "", "",
	                      -1, G_MAXINT, -1,
	                       G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}

/*****************************************************************************/

const char **
nm_wifi_aps_get_paths (const CList *aps_lst_head, gboolean include_without_ssid)
{
	NMWifiAP *ap;
	gsize i, n;
	const char **list;
	const char *path;

	n = c_list_length (aps_lst_head);
	list = g_new (const char *, n + 1);

	i = 0;
	if (n > 0) {
		c_list_for_each_entry (ap, aps_lst_head, aps_lst) {
			nm_assert (i < n);
			if (   !include_without_ssid
			    && !nm_wifi_ap_get_ssid (ap))
				continue;

			path = nm_dbus_object_get_path (NM_DBUS_OBJECT (ap));
			nm_assert (path);

			list[i++] = path;
		}
		nm_assert (i <= n);
		nm_assert (!include_without_ssid || i == n);
	}
	list[i] = NULL;
	return list;
}

NMWifiAP *
nm_wifi_aps_find_first_compatible (const CList *aps_lst_head,
                                   NMConnection *connection)
{
	NMWifiAP *ap;

	g_return_val_if_fail (connection, NULL);

	c_list_for_each_entry (ap, aps_lst_head, aps_lst) {
		if (nm_wifi_ap_check_compatible (ap, connection))
			return ap;
	}
	return NULL;
}

NMWifiAP *
nm_wifi_aps_find_by_supplicant_path (const CList *aps_lst_head, const char *path)
{
	NMWifiAP *ap;

	g_return_val_if_fail (path != NULL, NULL);

	c_list_for_each_entry (ap, aps_lst_head, aps_lst) {
		if (nm_streq0 (path, nm_wifi_ap_get_supplicant_path (ap)))
			return ap;
	}
	return NULL;
}

/*****************************************************************************/

NMWifiAP *
nm_wifi_ap_lookup_for_device (NMDevice *device, const char *exported_path)
{
	NMWifiAP *ap;

	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	ap = nm_dbus_manager_lookup_object (nm_dbus_object_get_manager (NM_DBUS_OBJECT (device)),
	                                    exported_path);
	if (   !ap
	    || !NM_IS_WIFI_AP (ap)
	    || ap->wifi_device != device)
		return NULL;

	return ap;
}
