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
 * Copyright (C) 2004 - 2011 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#include "config.h"

#include <string.h>
#include <stdlib.h>

#include "nm-wifi-ap.h"
#include "nm-wifi-ap-utils.h"
#include "NetworkManagerUtils.h"
#include "nm-utils.h"
#include "nm-logging.h"
#include "nm-dbus-manager.h"
#include "nm-core-internal.h"

#include "nm-setting-wireless.h"
#include "nm-glib-compat.h"
#include "gsystem-local-alloc.h"

#include "nm-access-point-glue.h"

/*
 * Encapsulates Access Point information
 */
typedef struct
{
	char *dbus_path;
	char *supplicant_path;   /* D-Bus object path of this AP from wpa_supplicant */
	guint32 id;              /* ID for stable sorting of APs */

	/* Scanned or cached values */
	GByteArray *	ssid;
	char *          address;
	NM80211Mode		mode;
	gint8			strength;
	guint32			freq;		/* Frequency in MHz; ie 2412 (== 2.412 GHz) */
	guint32			max_bitrate;/* Maximum bitrate of the AP in Kbit/s (ie 54000 Kb/s == 54Mbit/s) */

	NM80211ApFlags         flags;      /* General flags */
	NM80211ApSecurityFlags wpa_flags;  /* WPA-related flags */
	NM80211ApSecurityFlags rsn_flags;  /* RSN (WPA2) -related flags */

	/* Non-scanned attributes */
	gboolean			fake;	/* Whether or not the AP is from a scan */
	gboolean            hotspot;    /* Whether the AP is a local device's hotspot network */
	gint32              last_seen;  /* Timestamp when the AP was seen lastly (obtained via nm_utils_get_monotonic_timestamp_s()) */
} NMAccessPointPrivate;

#define NM_AP_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_AP, NMAccessPointPrivate))

G_DEFINE_TYPE (NMAccessPoint, nm_ap, G_TYPE_OBJECT)

enum {
	PROP_0,
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
	LAST_PROP
};

static void
nm_ap_init (NMAccessPoint *ap)
{
	NMAccessPointPrivate *priv = NM_AP_GET_PRIVATE (ap);

	priv->dbus_path = NULL;
	priv->mode = NM_802_11_MODE_INFRA;
	priv->flags = NM_802_11_AP_FLAGS_NONE;
	priv->wpa_flags = NM_802_11_AP_SEC_NONE;
	priv->rsn_flags = NM_802_11_AP_SEC_NONE;
}

static void
finalize (GObject *object)
{
	NMAccessPointPrivate *priv = NM_AP_GET_PRIVATE (object);

	g_free (priv->dbus_path);
	g_free (priv->supplicant_path);
	if (priv->ssid)
		g_byte_array_free (priv->ssid, TRUE);
	g_free (priv->address);

	G_OBJECT_CLASS (nm_ap_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMAccessPoint *ap = NM_AP (object);
	GByteArray *ssid;

	switch (prop_id) {
	case PROP_FLAGS:
		nm_ap_set_flags (ap, g_value_get_uint (value));
		break;
	case PROP_WPA_FLAGS:
		nm_ap_set_wpa_flags (ap, g_value_get_uint (value));
		break;
	case PROP_RSN_FLAGS:
		nm_ap_set_rsn_flags (ap, g_value_get_uint (value));
		break;
	case PROP_SSID:
		ssid = g_value_get_boxed (value);
		if (ssid)
			nm_ap_set_ssid (ap, ssid->data, ssid->len);
		else
			nm_ap_set_ssid (ap, NULL, 0);
		break;
	case PROP_FREQUENCY:
		nm_ap_set_freq (ap, g_value_get_uint (value));
		break;
	case PROP_MODE:
		nm_ap_set_mode (ap, g_value_get_uint (value));
		break;
	case PROP_MAX_BITRATE:
		nm_ap_set_max_bitrate (ap, g_value_get_uint (value));
		break;
	case PROP_STRENGTH:
		nm_ap_set_strength (ap, g_value_get_schar (value));
		break;
	case PROP_HW_ADDRESS:
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	NMAccessPointPrivate *priv = NM_AP_GET_PRIVATE (object);
	GArray * ssid;
	int len;
	int i;

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
		len = priv->ssid ? priv->ssid->len : 0;
		ssid = g_array_sized_new (FALSE, TRUE, sizeof (unsigned char), len);
		for (i = 0; i < len; i++)
			g_array_append_val (ssid, priv->ssid->data[i]);
		g_value_set_boxed (value, ssid);
		g_array_free (ssid, TRUE);
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
		g_value_set_schar (value, priv->strength);
		break;
	case PROP_LAST_SEEN:
		g_value_set_int (value,
		                 priv->last_seen > 0
		                     ? (gint) nm_utils_monotonic_timestamp_as_boottime (priv->last_seen, NM_UTILS_NS_PER_SECOND)
		                     : -1);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_ap_class_init (NMAccessPointClass *ap_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (ap_class);
	const NM80211ApSecurityFlags all_sec_flags =   NM_802_11_AP_SEC_NONE
	                                             | NM_802_11_AP_SEC_PAIR_WEP40
	                                             | NM_802_11_AP_SEC_PAIR_WEP104
	                                             | NM_802_11_AP_SEC_PAIR_TKIP
	                                             | NM_802_11_AP_SEC_PAIR_CCMP
	                                             | NM_802_11_AP_SEC_GROUP_WEP40
	                                             | NM_802_11_AP_SEC_GROUP_WEP104
	                                             | NM_802_11_AP_SEC_GROUP_TKIP
	                                             | NM_802_11_AP_SEC_GROUP_CCMP
	                                             | NM_802_11_AP_SEC_KEY_MGMT_PSK
	                                             | NM_802_11_AP_SEC_KEY_MGMT_802_1X;

	g_type_class_add_private (ap_class, sizeof (NMAccessPointPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize = finalize;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_FLAGS,
		 g_param_spec_uint (NM_AP_FLAGS, "", "",
		                    NM_802_11_AP_FLAGS_NONE,
		                    NM_802_11_AP_FLAGS_PRIVACY,
		                    NM_802_11_AP_FLAGS_NONE,
		                    G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_WPA_FLAGS,
		 g_param_spec_uint (NM_AP_WPA_FLAGS, "", "",
		                    NM_802_11_AP_SEC_NONE,
		                    all_sec_flags,
		                    NM_802_11_AP_SEC_NONE,
		                    G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_RSN_FLAGS,
		 g_param_spec_uint (NM_AP_RSN_FLAGS, "", "",
		                    NM_802_11_AP_SEC_NONE,
		                    all_sec_flags,
		                    NM_802_11_AP_SEC_NONE,
		                    G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_SSID,
	     g_param_spec_boxed (NM_AP_SSID, "", "",
	                         DBUS_TYPE_G_UCHAR_ARRAY,
	                         G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                         G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_FREQUENCY,
		 g_param_spec_uint (NM_AP_FREQUENCY, "", "",
		                    0, 10000, 0,
		                    G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_AP_HW_ADDRESS, "", "",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                      G_PARAM_STATIC_STRINGS));
	
	g_object_class_install_property
		(object_class, PROP_MODE,
		 g_param_spec_uint (NM_AP_MODE, "", "",
		                    NM_802_11_MODE_ADHOC, NM_802_11_MODE_INFRA, NM_802_11_MODE_INFRA,
		                    G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_MAX_BITRATE,
		 g_param_spec_uint (NM_AP_MAX_BITRATE, "", "",
		                    0, G_MAXUINT16, 0,
		                    G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_STRENGTH,
		 g_param_spec_char (NM_AP_STRENGTH, "", "",
		                    G_MININT8, G_MAXINT8, 0,
		                    G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_LAST_SEEN,
		 g_param_spec_int (NM_AP_LAST_SEEN, "", "",
		                   -1, G_MAXINT, -1,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	nm_dbus_manager_register_exported_type (nm_dbus_manager_get (),
	                                        G_TYPE_FROM_CLASS (ap_class),
	                                        &dbus_glib_nm_access_point_object_info);
}

void
nm_ap_export_to_dbus (NMAccessPoint *ap)
{
	NMAccessPointPrivate *priv;
	static guint32 counter = 0;

	g_return_if_fail (NM_IS_AP (ap));

	priv = NM_AP_GET_PRIVATE (ap);

	if (priv->dbus_path) {
		nm_log_err (LOGD_CORE, "Tried to export AP %s twice.", priv->dbus_path);
		return;
	}

	priv->id = counter++;
	priv->dbus_path = g_strdup_printf (NM_DBUS_PATH_ACCESS_POINT "/%d", priv->id);
	nm_dbus_manager_register_object (nm_dbus_manager_get (), priv->dbus_path, ap);
}

/*
 * nm_ap_new
 *
 * Create a new, blank user access point info structure
 *
 */
static NMAccessPoint *
nm_ap_new (void)
{
	return (NMAccessPoint *) g_object_new (NM_TYPE_AP, NULL);
}

static NM80211ApSecurityFlags
security_from_vardict (GVariant *security)
{
	NM80211ApSecurityFlags flags = NM_802_11_AP_SEC_NONE;
	const char **array, *tmp;

	g_return_val_if_fail (g_variant_is_of_type (security, G_VARIANT_TYPE_VARDICT), NM_802_11_AP_SEC_NONE);

	if (g_variant_lookup (security, "KeyMgmt", "^a&s", &array)) {
		if (_nm_utils_string_in_list ("wpa-psk", array))
			flags |= NM_802_11_AP_SEC_KEY_MGMT_PSK;
		if (_nm_utils_string_in_list ("wpa-eap", array))
			flags |= NM_802_11_AP_SEC_KEY_MGMT_802_1X;
		g_free (array);
	}

	if (g_variant_lookup (security, "Pairwise", "^a&s", &array)) {
		if (_nm_utils_string_in_list ("tkip", array))
			flags |= NM_802_11_AP_SEC_PAIR_TKIP;
		if (_nm_utils_string_in_list ("ccmp", array))
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

void
nm_ap_update_from_properties (NMAccessPoint *ap,
                              const char *supplicant_path,
                              GVariant *properties)
{
	char *addr;
	const guint8 *bytes;
	GVariant *v;
	gsize len;
	gboolean b = FALSE;
	const char *s;
	gint16 i16;
	guint16 u16;

	g_return_if_fail (ap != NULL);
	g_return_if_fail (properties != NULL);

	g_object_freeze_notify (G_OBJECT (ap));

	if (g_variant_lookup (properties, "Privacy", "b", &b) && b)
		nm_ap_set_flags (ap, nm_ap_get_flags (ap) | NM_802_11_AP_FLAGS_PRIVACY);

	if (g_variant_lookup (properties, "Mode", "&s", &s)) {
		if (!g_strcmp0 (s, "infrastructure"))
			nm_ap_set_mode (ap, NM_802_11_MODE_INFRA);
		else if (!g_strcmp0 (s, "ad-hoc"))
			nm_ap_set_mode (ap, NM_802_11_MODE_ADHOC);
	}

	if (g_variant_lookup (properties, "Signal", "n", &i16))
		nm_ap_set_strength (ap, nm_ap_utils_level_to_quality (i16));

	if (g_variant_lookup (properties, "Frequency", "q", &u16))
		nm_ap_set_freq (ap, u16);

	v = g_variant_lookup_value (properties, "SSID", G_VARIANT_TYPE_BYTESTRING);
	if (v) {
		bytes = g_variant_get_fixed_array (v, &len, 1);
		len = MIN (32, len);

		/* Stupid ieee80211 layer uses <hidden> */
		if (   bytes && len
		    && !(((len == 8) || (len == 9)) && !memcmp (bytes, "<hidden>", 8))
		    && !nm_utils_is_empty_ssid (bytes, len))
			nm_ap_set_ssid (ap, bytes, len);

		g_variant_unref (v);
	}

	v = g_variant_lookup_value (properties, "BSSID", G_VARIANT_TYPE_BYTESTRING);
	if (v) {
		bytes = g_variant_get_fixed_array (v, &len, 1);
		if (len == ETH_ALEN) {
			addr = nm_utils_hwaddr_ntoa (bytes, len);
			nm_ap_set_address (ap, addr);
			g_free (addr);
		}
		g_variant_unref (v);
	}

	v = g_variant_lookup_value (properties, "Rates", G_VARIANT_TYPE ("au")); 
	if (v) {
		const guint32 *rates = g_variant_get_fixed_array (v, &len, sizeof (guint32));
		guint32 maxrate = 0;
		int i;

		/* Find the max AP rate */
		for (i = 0; i < len; i++) {
			if (rates[i] > maxrate) {
				maxrate = rates[i];
				nm_ap_set_max_bitrate (ap, rates[i] / 1000);
			}
		}
		g_variant_unref (v);
	}

	v = g_variant_lookup_value (properties, "WPA", G_VARIANT_TYPE_VARDICT);
	if (v) {
		nm_ap_set_wpa_flags (ap, nm_ap_get_wpa_flags (ap) | security_from_vardict (v));
		g_variant_unref (v);
	}

	v = g_variant_lookup_value (properties, "RSN", G_VARIANT_TYPE_VARDICT);
	if (v) {
		nm_ap_set_rsn_flags (ap, nm_ap_get_rsn_flags (ap) | security_from_vardict (v));
		g_variant_unref (v);
	}

	if (!nm_ap_get_supplicant_path (ap))
		nm_ap_set_supplicant_path (ap, supplicant_path);

	nm_ap_set_last_seen (ap, nm_utils_get_monotonic_timestamp_s ());

	g_object_thaw_notify (G_OBJECT (ap));
}

NMAccessPoint *
nm_ap_new_from_properties (const char *supplicant_path, GVariant *properties)
{
	const char bad_bssid1[ETH_ALEN] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	const char bad_bssid2[ETH_ALEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
	NMAccessPoint *ap;
	const char *addr;

	g_return_val_if_fail (supplicant_path != NULL, NULL);
	g_return_val_if_fail (properties != NULL, NULL);

	ap = nm_ap_new ();

	nm_ap_update_from_properties (ap, supplicant_path, properties);

	/* ignore APs with invalid BSSIDs */
	addr = nm_ap_get_address (ap);
	if (   nm_utils_hwaddr_matches (addr, -1, bad_bssid1, ETH_ALEN)
	    || nm_utils_hwaddr_matches (addr, -1, bad_bssid2, ETH_ALEN)) {
		g_object_unref (ap);
		return NULL;
	}

	return ap;
}

#define PROTO_WPA "wpa"
#define PROTO_RSN "rsn"

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
add_pair_ciphers (NMAccessPoint *ap, NMSettingWirelessSecurity *sec)
{
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
		nm_ap_set_wpa_flags (ap, nm_ap_get_wpa_flags (ap) | flags);
	if (has_proto (sec, PROTO_RSN))
		nm_ap_set_rsn_flags (ap, nm_ap_get_rsn_flags (ap) | flags);
}

static void
add_group_ciphers (NMAccessPoint *ap, NMSettingWirelessSecurity *sec)
{
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
		nm_ap_set_wpa_flags (ap, nm_ap_get_wpa_flags (ap) | flags);
	if (has_proto (sec, PROTO_RSN))
		nm_ap_set_rsn_flags (ap, nm_ap_get_rsn_flags (ap) | flags);
}

NMAccessPoint *
nm_ap_new_fake_from_connection (NMConnection *connection)
{
	NMAccessPoint *ap;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wireless_sec;
	GBytes *ssid;
	const char *mode, *band, *key_mgmt;
	guint32 channel;
	NM80211ApSecurityFlags flags;
	gboolean psk = FALSE, eap = FALSE;

	g_return_val_if_fail (connection != NULL, NULL);

	s_wireless = nm_connection_get_setting_wireless (connection);
	g_return_val_if_fail (s_wireless != NULL, NULL);

	ssid = nm_setting_wireless_get_ssid (s_wireless);
	g_return_val_if_fail (ssid != NULL, NULL);
	g_return_val_if_fail (g_bytes_get_size (ssid) > 0, NULL);

	ap = nm_ap_new ();
	nm_ap_set_fake (ap, TRUE);
	nm_ap_set_ssid (ap, g_bytes_get_data (ssid, NULL), g_bytes_get_size (ssid));

	// FIXME: bssid too?

	mode = nm_setting_wireless_get_mode (s_wireless);
	if (mode) {
		if (!strcmp (mode, "infrastructure"))
			nm_ap_set_mode (ap, NM_802_11_MODE_INFRA);
		else if (!strcmp (mode, "adhoc"))
			nm_ap_set_mode (ap, NM_802_11_MODE_ADHOC);
		else if (!strcmp (mode, "ap")) {
			nm_ap_set_mode (ap, NM_802_11_MODE_INFRA);
			NM_AP_GET_PRIVATE (ap)->hotspot = TRUE;
		} else
			goto error;
	} else {
		nm_ap_set_mode (ap, NM_802_11_MODE_INFRA);
	}

	band = nm_setting_wireless_get_band (s_wireless);
	channel = nm_setting_wireless_get_channel (s_wireless);

	if (band && channel) {
		guint32 freq = nm_utils_wifi_channel_to_freq (channel, band);

		if (freq == 0)
			goto error;

		nm_ap_set_freq (ap, freq);
	}

	s_wireless_sec = nm_connection_get_setting_wireless_security (connection);
	/* Assume presence of a security setting means the AP is encrypted */
	if (!s_wireless_sec)
		goto done;

	key_mgmt = nm_setting_wireless_security_get_key_mgmt (s_wireless_sec);

	/* Everything below here uses encryption */
	nm_ap_set_flags (ap, nm_ap_get_flags (ap) | NM_802_11_AP_FLAGS_PRIVACY);

	/* Static & Dynamic WEP */
	if (!strcmp (key_mgmt, "none") || !strcmp (key_mgmt, "ieee8021x"))
		goto done;

	psk = !strcmp (key_mgmt, "wpa-psk");
	eap = !strcmp (key_mgmt, "wpa-eap");
	if (psk || eap) {
		if (has_proto (s_wireless_sec, PROTO_WPA)) {
			flags = nm_ap_get_wpa_flags (ap);
			flags |= eap ? NM_802_11_AP_SEC_KEY_MGMT_802_1X : NM_802_11_AP_SEC_KEY_MGMT_PSK;
			nm_ap_set_wpa_flags (ap, flags);
		}
		if (has_proto (s_wireless_sec, PROTO_RSN)) {
			flags = nm_ap_get_rsn_flags (ap);
			flags |= eap ? NM_802_11_AP_SEC_KEY_MGMT_802_1X : NM_802_11_AP_SEC_KEY_MGMT_PSK;
			nm_ap_set_rsn_flags (ap, flags);
		}

		add_pair_ciphers (ap, s_wireless_sec);
		add_group_ciphers (ap, s_wireless_sec);
	} else if (!strcmp (key_mgmt, "wpa-none")) {
		guint32 i;

		/* Ad-Hoc has special requirements: proto=WPA, pairwise=(none), and
		 * group=TKIP/CCMP (but not both).
		 */

		flags = nm_ap_get_wpa_flags (ap);
		flags |= NM_802_11_AP_SEC_KEY_MGMT_PSK;

		/* Clear ciphers; pairwise must be unset anyway, and group gets set below */
		flags &= ~(  NM_802_11_AP_SEC_PAIR_WEP40
		           | NM_802_11_AP_SEC_PAIR_WEP104
		           | NM_802_11_AP_SEC_PAIR_TKIP
		           | NM_802_11_AP_SEC_PAIR_CCMP
		           | NM_802_11_AP_SEC_GROUP_WEP40
		           | NM_802_11_AP_SEC_GROUP_WEP104
		           | NM_802_11_AP_SEC_GROUP_TKIP
		           | NM_802_11_AP_SEC_GROUP_CCMP);

		for (i = 0; i < nm_setting_wireless_security_get_num_groups (s_wireless_sec); i++) {
			if (!strcmp (nm_setting_wireless_security_get_group (s_wireless_sec, i), "ccmp")) {
				flags |= NM_802_11_AP_SEC_GROUP_CCMP;
				break;
			}
		}

		/* Default to TKIP since not all WPA-capable cards can do CCMP */
		if (!(flags & NM_802_11_AP_SEC_GROUP_CCMP))
			flags |= NM_802_11_AP_SEC_GROUP_TKIP;

		nm_ap_set_wpa_flags (ap, flags);

		/* Don't use Ad-Hoc RSN yet */
		nm_ap_set_rsn_flags (ap, NM_802_11_AP_SEC_NONE);
	}

done:
	return ap;

error:
	g_object_unref (ap);
	return NULL;
}

static char
mode_to_char (NMAccessPoint *self)
{
	NMAccessPointPrivate *priv = NM_AP_GET_PRIVATE (self);

	if (priv->mode == NM_802_11_MODE_ADHOC)
		return '*';
	if (priv->hotspot)
		return '#';
	if (priv->fake)
		return '-';
	return ' ';
}

void
nm_ap_dump (NMAccessPoint *self,
            const char *prefix,
            const char *ifname)
{
	NMAccessPointPrivate *priv;
	const char *supplicant_id = "-";
	guint32 chan;

	g_return_if_fail (NM_IS_AP (self));

	priv = NM_AP_GET_PRIVATE (self);
	chan = nm_utils_wifi_freq_to_channel (priv->freq);
	if (priv->supplicant_path)
		supplicant_id = strrchr (priv->supplicant_path, '/');

	nm_log_dbg (LOGD_WIFI_SCAN, "%s[%s%c] %-32s[%s%u %s%u%% %c W:%04X R:%04X] [%3u] %s%s",
	            prefix,
	            str_if_set (priv->address, "(none)"),
	            mode_to_char (self),
	            priv->ssid ? nm_utils_escape_ssid (priv->ssid->data, priv->ssid->len) : "(none)",
	            chan > 99 ? "" : (chan > 9 ? " " : "  "),
	            chan,
	            priv->strength < 100 ? " " : "",
	            priv->strength,
	            priv->flags & NM_802_11_AP_FLAGS_PRIVACY ? 'P' : ' ',
	            priv->wpa_flags & 0xFFFF,
	            priv->rsn_flags & 0xFFFF,
	            priv->last_seen > 0 ? (nm_utils_get_monotonic_timestamp_s () - priv->last_seen) : -1,
	            ifname,
	            supplicant_id);
}

const char *
nm_ap_get_dbus_path (NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_AP (ap), NULL);

	return NM_AP_GET_PRIVATE (ap)->dbus_path;
}

const char *
nm_ap_get_supplicant_path (NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_AP (ap), NULL);

	return NM_AP_GET_PRIVATE (ap)->supplicant_path;
}

guint32
nm_ap_get_id (NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_AP (ap), 0);

	return NM_AP_GET_PRIVATE (ap)->id;
}

void
nm_ap_set_supplicant_path (NMAccessPoint *ap, const char *path)
{
	g_return_if_fail (NM_IS_AP (ap));
	g_return_if_fail (path != NULL);

	g_free (NM_AP_GET_PRIVATE (ap)->supplicant_path);
	NM_AP_GET_PRIVATE (ap)->supplicant_path = g_strdup (path);
}

/*
 * Get/set functions for ssid
 *
 */
const GByteArray * nm_ap_get_ssid (const NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_AP (ap), NULL);

	return NM_AP_GET_PRIVATE (ap)->ssid;
}

void
nm_ap_set_ssid (NMAccessPoint *ap, const guint8 *ssid, gsize len)
{
	NMAccessPointPrivate *priv;

	g_return_if_fail (NM_IS_AP (ap));
	g_return_if_fail (ssid == NULL || len > 0);

	priv = NM_AP_GET_PRIVATE (ap);

	/* same SSID */
	if ((ssid && priv->ssid) && (len == priv->ssid->len)) {
		if (!memcmp (ssid, priv->ssid->data, len))
			return;
	}

	if (priv->ssid) {
		g_byte_array_free (priv->ssid, TRUE);
		priv->ssid = NULL;
	}

	if (ssid) {
		priv->ssid = g_byte_array_new ();
		g_byte_array_append (priv->ssid, ssid, len);
	}

	g_object_notify (G_OBJECT (ap), NM_AP_SSID);
}


NM80211ApFlags
nm_ap_get_flags (NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_AP (ap), NM_802_11_AP_FLAGS_NONE);

	return NM_AP_GET_PRIVATE (ap)->flags;
}


void
nm_ap_set_flags (NMAccessPoint *ap, NM80211ApFlags flags)
{
	NMAccessPointPrivate *priv;

	g_return_if_fail (NM_IS_AP (ap));

	priv = NM_AP_GET_PRIVATE (ap);

	if (priv->flags != flags) {
		priv->flags = flags;
		g_object_notify (G_OBJECT (ap), NM_AP_FLAGS);
	}
}

NM80211ApSecurityFlags
nm_ap_get_wpa_flags (NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_AP (ap), NM_802_11_AP_SEC_NONE);

	return NM_AP_GET_PRIVATE (ap)->wpa_flags;
}


void
nm_ap_set_wpa_flags (NMAccessPoint *ap, NM80211ApSecurityFlags flags)
{
	NMAccessPointPrivate *priv;

	g_return_if_fail (NM_IS_AP (ap));

	priv = NM_AP_GET_PRIVATE (ap);
	if (priv->wpa_flags != flags) {
		priv->wpa_flags = flags;
		g_object_notify (G_OBJECT (ap), NM_AP_WPA_FLAGS);
	}
}

NM80211ApSecurityFlags
nm_ap_get_rsn_flags (NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_AP (ap), NM_802_11_AP_SEC_NONE);

	return NM_AP_GET_PRIVATE (ap)->rsn_flags;
}


void
nm_ap_set_rsn_flags (NMAccessPoint *ap, NM80211ApSecurityFlags flags)
{
	NMAccessPointPrivate *priv;

	g_return_if_fail (NM_IS_AP (ap));

	priv = NM_AP_GET_PRIVATE (ap);
	if (priv->rsn_flags != flags) {
		priv->rsn_flags = flags;
		g_object_notify (G_OBJECT (ap), NM_AP_RSN_FLAGS);
	}
}

/*
 * Get/set functions for address
 *
 */
const char *
nm_ap_get_address (const NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_AP (ap), NULL);

	return NM_AP_GET_PRIVATE (ap)->address;
}

void
nm_ap_set_address (NMAccessPoint *ap, const char *addr)
{
	NMAccessPointPrivate *priv;

	g_return_if_fail (NM_IS_AP (ap));
	g_return_if_fail (addr != NULL);
	g_return_if_fail (nm_utils_hwaddr_valid (addr, ETH_ALEN));

	priv = NM_AP_GET_PRIVATE (ap);

	if (!priv->address || !nm_utils_hwaddr_matches (addr, -1, priv->address, -1)) {
		g_free (priv->address);
		priv->address = g_strdup (addr);
		g_object_notify (G_OBJECT (ap), NM_AP_HW_ADDRESS);
	}
}


/*
 * Get/set functions for mode (ie Ad-Hoc, Infrastructure, etc)
 *
 */
NM80211Mode nm_ap_get_mode (NMAccessPoint *ap)
{
	NM80211Mode mode;

	g_return_val_if_fail (NM_IS_AP (ap), -1);

	g_object_get (ap, NM_AP_MODE, &mode, NULL);

	return mode;
}

void nm_ap_set_mode (NMAccessPoint *ap, const NM80211Mode mode)
{
	NMAccessPointPrivate *priv;

	g_return_if_fail (NM_IS_AP (ap));
	g_return_if_fail (   mode == NM_802_11_MODE_ADHOC
	                  || mode == NM_802_11_MODE_INFRA);

	priv = NM_AP_GET_PRIVATE (ap);

	if (priv->mode != mode) {
		priv->mode = mode;
		g_object_notify (G_OBJECT (ap), NM_AP_MODE);
	}
}

gboolean
nm_ap_is_hotspot (NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_AP (ap), FALSE);

	return NM_AP_GET_PRIVATE (ap)->hotspot;
}

/*
 * Get/set functions for strength
 *
 */
gint8 nm_ap_get_strength (NMAccessPoint *ap)
{
	gint8 strength;

	g_return_val_if_fail (NM_IS_AP (ap), 0);

	g_object_get (ap, NM_AP_STRENGTH, &strength, NULL);

	return strength;
}

void nm_ap_set_strength (NMAccessPoint *ap, const gint8 strength)
{
	NMAccessPointPrivate *priv;

	g_return_if_fail (NM_IS_AP (ap));

	priv = NM_AP_GET_PRIVATE (ap);

	if (priv->strength != strength) {
		priv->strength = strength;
		g_object_notify (G_OBJECT (ap), NM_AP_STRENGTH);
	}
}


/*
 * Get/set functions for frequency
 *
 */
guint32
nm_ap_get_freq (NMAccessPoint *ap)
{
	guint32 freq;

	g_return_val_if_fail (NM_IS_AP (ap), 0);

	g_object_get (ap, NM_AP_FREQUENCY, &freq, NULL);

	return freq;
}

void
nm_ap_set_freq (NMAccessPoint *ap,
                const guint32 freq)
{
	NMAccessPointPrivate *priv;

	g_return_if_fail (NM_IS_AP (ap));

	priv = NM_AP_GET_PRIVATE (ap);

	if (priv->freq != freq) {
		priv->freq = freq;
		g_object_notify (G_OBJECT (ap), NM_AP_FREQUENCY);
	}
}


/*
 * Get/set functions for max bitrate (in kbit/s)
 *
 */
guint32 nm_ap_get_max_bitrate (NMAccessPoint *ap)
{
	guint32 rate;

	g_return_val_if_fail (NM_IS_AP (ap), 0);

	g_object_get (ap, NM_AP_MAX_BITRATE, &rate, NULL);

	return rate;
}

void
nm_ap_set_max_bitrate (NMAccessPoint *ap, guint32 bitrate)
{
	NMAccessPointPrivate *priv;

	g_return_if_fail (NM_IS_AP (ap));

	priv = NM_AP_GET_PRIVATE (ap);

	if (priv->max_bitrate != bitrate) {
		priv->max_bitrate = bitrate;
		g_object_notify (G_OBJECT (ap), NM_AP_MAX_BITRATE);
	}
}

/*
 * Get/Set functions to indicate that an access point is 'fake', ie whether
 * or not it was created from scan results
 */
gboolean nm_ap_get_fake (const NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_AP (ap), FALSE);

	return NM_AP_GET_PRIVATE (ap)->fake;
}

void nm_ap_set_fake (NMAccessPoint *ap, gboolean fake)
{
	g_return_if_fail (NM_IS_AP (ap));

	NM_AP_GET_PRIVATE (ap)->fake = fake;
}

/*
 * Get/Set functions for how long ago the AP was last seen in a scan.
 * APs older than a certain date are dropped from the list.
 *
 */
gint32
nm_ap_get_last_seen (const NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_AP (ap), 0);

	return NM_AP_GET_PRIVATE (ap)->last_seen;
}

void
nm_ap_set_last_seen (NMAccessPoint *ap, gint32 last_seen)
{
	NMAccessPointPrivate *priv;

	g_return_if_fail (NM_IS_AP (ap));

	priv = NM_AP_GET_PRIVATE (ap);

	if (priv->last_seen != last_seen) {
		priv->last_seen = last_seen;
		g_object_notify (G_OBJECT (ap), NM_AP_LAST_SEEN);
	}
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
nm_ap_check_compatible (NMAccessPoint *self,
                        NMConnection *connection)
{
	NMAccessPointPrivate *priv;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wireless_sec;
	GBytes *ssid;
	const char *mode;
	const char *band;
	const char *bssid;
	guint32 channel;

	g_return_val_if_fail (NM_IS_AP (self), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	priv = NM_AP_GET_PRIVATE (self);

	s_wireless = nm_connection_get_setting_wireless (connection);
	if (s_wireless == NULL)
		return FALSE;
	
	ssid = nm_setting_wireless_get_ssid (s_wireless);
	if (   (ssid && !priv->ssid)
	    || (priv->ssid && !ssid))
		return FALSE;

	if (   ssid && priv->ssid &&
	    !nm_utils_same_ssid (g_bytes_get_data (ssid, NULL), g_bytes_get_size (ssid),
	                         priv->ssid->data, priv->ssid->len,
	                         TRUE))
		return FALSE;

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
	                                                   nm_ap_get_flags (self),
	                                                   nm_ap_get_wpa_flags (self),
	                                                   nm_ap_get_rsn_flags (self),
	                                                   nm_ap_get_mode (self));
}

gboolean
nm_ap_complete_connection (NMAccessPoint *self,
                           NMConnection *connection,
                           gboolean lock_bssid,
                           GError **error)
{
	NMAccessPointPrivate *priv = NM_AP_GET_PRIVATE (self);

	g_return_val_if_fail (connection != NULL, FALSE);

	return nm_ap_utils_complete_connection (priv->ssid,
	                                        priv->address,
	                                        priv->mode,
	                                        priv->flags,
	                                        priv->wpa_flags,
	                                        priv->rsn_flags,
	                                        connection,
	                                        lock_bssid,
	                                        error);
}

NMAccessPoint *
nm_ap_match_in_hash (NMAccessPoint *find_ap, GHashTable *hash)
{
	GHashTableIter iter;
	NMAccessPoint *list_ap, *band_match = NULL;

	g_return_val_if_fail (find_ap != NULL, NULL);

	g_hash_table_iter_init (&iter, hash);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer) &list_ap)) {
		const GByteArray * list_ssid = nm_ap_get_ssid (list_ap);
		const char * list_addr = nm_ap_get_address (list_ap);
		const guint32 list_freq = nm_ap_get_freq (list_ap);

		const GByteArray * find_ssid = nm_ap_get_ssid (find_ap);
		const char * find_addr = nm_ap_get_address (find_ap);
		const guint32 find_freq = nm_ap_get_freq (find_ap);

		/* SSID match; if both APs are hiding their SSIDs,
		 * let matching continue on BSSID and other properties
		 */
		if (   (!list_ssid && find_ssid)
		    || (list_ssid && !find_ssid))
			continue;
		if (   list_ssid
		    && find_ssid
		    && !nm_utils_same_ssid (list_ssid->data, list_ssid->len,
		                            find_ssid->data, find_ssid->len,
		                            TRUE))
			continue;

		/* BSSID match */
		if (   nm_ethernet_address_is_valid (list_addr, -1)
		    && !nm_utils_hwaddr_matches (list_addr, -1, find_addr, -1))
			continue;

		/* mode match */
		if (nm_ap_get_mode (list_ap) != nm_ap_get_mode (find_ap))
			continue;

		/* AP flags */
		if (nm_ap_get_flags (list_ap) != nm_ap_get_flags (find_ap))
			continue;

		if (nm_ap_get_wpa_flags (list_ap) != nm_ap_get_wpa_flags (find_ap))
			continue;

		if (nm_ap_get_rsn_flags (list_ap) != nm_ap_get_rsn_flags (find_ap))
			continue;

		if (list_freq != find_freq) {
			/* Must be last check to ensure all other properties match */
			if (freq_to_band (list_freq) == freq_to_band (find_freq))
				band_match = list_ap;
			continue;
		}

		return list_ap;
	}

	return band_match;
}

