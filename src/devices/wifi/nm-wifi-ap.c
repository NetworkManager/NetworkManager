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

#include <string.h>
#include <stdlib.h>
#include <netinet/ether.h>

#include "nm-wifi-ap.h"
#include "nm-wifi-ap-utils.h"
#include "NetworkManagerUtils.h"
#include "nm-utils.h"
#include "nm-logging.h"
#include "nm-dbus-manager.h"

#include "nm-setting-wireless.h"
#include "nm-glib-compat.h"

#include "nm-access-point-glue.h"

/*
 * Encapsulates Access Point information
 */
typedef struct
{
	char *dbus_path;
	char *supplicant_path;   /* D-Bus object path of this AP from wpa_supplicant */

	/* Scanned or cached values */
	GByteArray *	ssid;
	struct ether_addr	address;
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
	gboolean			broadcast;	/* Whether or not the AP is broadcasting (hidden) */
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
	priv->broadcast = TRUE;
}

static void
finalize (GObject *object)
{
	NMAccessPointPrivate *priv = NM_AP_GET_PRIVATE (object);

	g_free (priv->dbus_path);
	g_free (priv->supplicant_path);
	if (priv->ssid)
		g_byte_array_free (priv->ssid, TRUE);

	G_OBJECT_CLASS (nm_ap_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMAccessPoint *ap = NM_AP (object);

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
		nm_ap_set_ssid (ap, (GByteArray *) g_value_get_boxed (value));
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
		g_value_take_string (value, nm_utils_hwaddr_ntoa (&priv->address, ARPHRD_ETHER));
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
		 g_param_spec_uint (NM_AP_FLAGS,
							"Flags",
							"Flags",
							NM_802_11_AP_FLAGS_NONE,
							NM_802_11_AP_FLAGS_PRIVACY,
							NM_802_11_AP_FLAGS_NONE,
							G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_WPA_FLAGS,
		 g_param_spec_uint (NM_AP_WPA_FLAGS,
							"WPA Flags",
							"WPA Flags",
							NM_802_11_AP_SEC_NONE,
							all_sec_flags,
							NM_802_11_AP_SEC_NONE,
							G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_RSN_FLAGS,
		 g_param_spec_uint (NM_AP_RSN_FLAGS,
							"RSN Flags",
							"RSN Flags",
							NM_802_11_AP_SEC_NONE,
							all_sec_flags,
							NM_802_11_AP_SEC_NONE,
							G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_SSID,
	     g_param_spec_boxed (NM_AP_SSID,
	                         "SSID",
	                         "SSID",
	                         DBUS_TYPE_G_UCHAR_ARRAY,
	                         G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_FREQUENCY,
		 g_param_spec_uint (NM_AP_FREQUENCY,
							"Frequency",
							"Frequency",
							0, 10000, 0,
							G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_AP_HW_ADDRESS,
							  "MAC Address",
							  "Hardware MAC address",
							  NULL,
							  G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	
	g_object_class_install_property
		(object_class, PROP_MODE,
		 g_param_spec_uint (NM_AP_MODE,
						   "Mode",
						   "Mode",
						   NM_802_11_MODE_ADHOC, NM_802_11_MODE_INFRA, NM_802_11_MODE_INFRA,
						   G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_MAX_BITRATE,
		 g_param_spec_uint (NM_AP_MAX_BITRATE,
							"Max Bitrate",
							"Max Bitrate",
							0, G_MAXUINT16, 0,
							G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_STRENGTH,
		 g_param_spec_char (NM_AP_STRENGTH,
							"Strength",
							"Strength",
							G_MININT8, G_MAXINT8, 0,
							G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

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

	priv->dbus_path = g_strdup_printf (NM_DBUS_PATH_ACCESS_POINT "/%d", counter++);
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
pair_to_flags (const char *str)
{
	g_return_val_if_fail (str != NULL, NM_802_11_AP_SEC_NONE);

	if (strcmp (str, "tkip") == 0)
		return NM_802_11_AP_SEC_PAIR_TKIP;
	if (strcmp (str, "ccmp") == 0)
		return NM_802_11_AP_SEC_PAIR_CCMP;
	return NM_802_11_AP_SEC_NONE;
}

static NM80211ApSecurityFlags
group_to_flags (const char *str)
{
	g_return_val_if_fail (str != NULL, NM_802_11_AP_SEC_NONE);

	if (strcmp (str, "wep40") == 0)
		return NM_802_11_AP_SEC_GROUP_WEP40;
	if (strcmp (str, "wep104") == 0)
		return NM_802_11_AP_SEC_GROUP_WEP104;
	if (strcmp (str, "tkip") == 0)
		return NM_802_11_AP_SEC_GROUP_TKIP;
	if (strcmp (str, "ccmp") == 0)
		return NM_802_11_AP_SEC_GROUP_CCMP;
	return NM_802_11_AP_SEC_NONE;
}

static NM80211ApSecurityFlags
security_from_dict (GHashTable *security)
{
	GValue *value;
	NM80211ApSecurityFlags flags = NM_802_11_AP_SEC_NONE;
	const char **items, **iter;

	value = g_hash_table_lookup (security, "KeyMgmt");
	if (value) {
		items = g_value_get_boxed (value);
		for (iter = items; iter && *iter; iter++) {
			if (strcmp (*iter, "wpa-psk") == 0)
				flags |= NM_802_11_AP_SEC_KEY_MGMT_PSK;
			else if (strcmp (*iter, "wpa-eap") == 0)
				flags |= NM_802_11_AP_SEC_KEY_MGMT_802_1X;
		}
	}

	value = g_hash_table_lookup (security, "Pairwise");
	if (value) {
		items = g_value_get_boxed (value);
		for (iter = items; iter && *iter; iter++)
			flags |= pair_to_flags (*iter);
	}

	value = g_hash_table_lookup (security, "Group");
	if (value)
		flags |= group_to_flags (g_value_get_string (value));

	return flags;
}

static void
foreach_property_cb (gpointer key, gpointer value, gpointer user_data)
{
	GValue *variant = (GValue *) value;
	NMAccessPoint *ap = (NMAccessPoint *) user_data;

	if (G_VALUE_HOLDS_BOXED (variant)) {
		GArray *array = g_value_get_boxed (variant);

		if (!strcmp (key, "SSID")) {
			guint32 len = MIN (32, array->len);
			GByteArray *ssid;

			/* Stupid ieee80211 layer uses <hidden> */
			if (((len == 8) || (len == 9))
				&& (memcmp (array->data, "<hidden>", 8) == 0))
				return;

			if (nm_utils_is_empty_ssid ((const guint8 *) array->data, len))
				return;

			ssid = g_byte_array_sized_new (len);
			g_byte_array_append (ssid, (const guint8 *) array->data, len);
			nm_ap_set_ssid (ap, ssid);
			g_byte_array_free (ssid, TRUE);
		} else if (!strcmp (key, "BSSID")) {
			struct ether_addr addr;

			if (array->len != ETH_ALEN)
				return;
			memset (&addr, 0, sizeof (struct ether_addr));
			memcpy (&addr, array->data, ETH_ALEN);
			nm_ap_set_address (ap, &addr);
		} else if (!strcmp (key, "Rates")) {
			guint32 maxrate = 0;
			int i;

			/* Find the max AP rate */
			for (i = 0; i < array->len; i++) {
				guint32 r = g_array_index (array, guint32, i);

				if (r > maxrate) {
					maxrate = r;
					nm_ap_set_max_bitrate (ap, r / 1000);
				}
			}
		} else if (!strcmp (key, "WPA")) {
			NM80211ApSecurityFlags flags = nm_ap_get_wpa_flags (ap);

			flags |= security_from_dict (g_value_get_boxed (variant));
			nm_ap_set_wpa_flags (ap, flags);
		} else if (!strcmp (key, "RSN")) {
			NM80211ApSecurityFlags flags = nm_ap_get_rsn_flags (ap);

			flags |= security_from_dict (g_value_get_boxed (variant));
			nm_ap_set_rsn_flags (ap, flags);
		}
	} else if (G_VALUE_HOLDS_UINT (variant)) {
		guint32 val = g_value_get_uint (variant);

		if (!strcmp (key, "Frequency"))
			nm_ap_set_freq (ap, val);
	} else if (G_VALUE_HOLDS_INT (variant)) {
		gint val = g_value_get_int (variant);

		if (!strcmp (key, "Signal"))
			nm_ap_set_strength (ap, nm_ap_utils_level_to_quality (val));
	} else if (G_VALUE_HOLDS_STRING (variant)) {
		const char *val = g_value_get_string (variant);

		if (val && !strcmp (key, "Mode")) {
			if (strcmp (val, "infrastructure") == 0)
				nm_ap_set_mode (ap, NM_802_11_MODE_INFRA);
			else if (strcmp (val, "ad-hoc") == 0)
				nm_ap_set_mode (ap, NM_802_11_MODE_ADHOC);
		}
	} else if (G_VALUE_HOLDS_BOOLEAN (variant)) {
		gboolean val = g_value_get_boolean (variant);

		if (strcmp (key, "Privacy") == 0) {
			if (val) {
				NM80211ApFlags flags = nm_ap_get_flags (ap);
				nm_ap_set_flags (ap, flags | NM_802_11_AP_FLAGS_PRIVACY);
			}
		}
	}
}

NMAccessPoint *
nm_ap_new_from_properties (const char *supplicant_path, GHashTable *properties)
{
	NMAccessPoint *ap;
	const struct ether_addr * addr;
	const char bad_bssid1[ETH_ALEN] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	const char bad_bssid2[ETH_ALEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

	g_return_val_if_fail (properties != NULL, NULL);

	ap = nm_ap_new ();

	g_object_freeze_notify (G_OBJECT (ap));
	g_hash_table_foreach (properties, foreach_property_cb, ap);

	nm_ap_set_supplicant_path (ap, supplicant_path);

	/* ignore APs with invalid BSSIDs */
	addr = nm_ap_get_address (ap);
	if (   !(memcmp (addr->ether_addr_octet, bad_bssid1, ETH_ALEN))
	    || !(memcmp (addr->ether_addr_octet, bad_bssid2, ETH_ALEN))) {
		g_object_unref (ap);
		return NULL;
	}

	nm_ap_set_last_seen (ap, nm_utils_get_monotonic_timestamp_s ());

	if (!nm_ap_get_ssid (ap))
		nm_ap_set_broadcast (ap, FALSE);

	g_object_thaw_notify (G_OBJECT (ap));

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
	const GByteArray *ssid;
	const char *mode, *band, *key_mgmt;
	guint32 channel;
	NM80211ApSecurityFlags flags;
	gboolean psk = FALSE, eap = FALSE;

	g_return_val_if_fail (connection != NULL, NULL);

	s_wireless = nm_connection_get_setting_wireless (connection);
	g_return_val_if_fail (s_wireless != NULL, NULL);

	ssid = nm_setting_wireless_get_ssid (s_wireless);
	g_return_val_if_fail (ssid != NULL, NULL);
	g_return_val_if_fail (ssid->len > 0, NULL);

	ap = nm_ap_new ();
	nm_ap_set_fake (ap, TRUE);
	nm_ap_set_ssid (ap, ssid);

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


#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ARG(x) ((guint8*)(x))[0],((guint8*)(x))[1],((guint8*)(x))[2],((guint8*)(x))[3],((guint8*)(x))[4],((guint8*)(x))[5]

void
nm_ap_dump (NMAccessPoint *ap, const char *prefix)
{
	NMAccessPointPrivate *priv;

	g_return_if_fail (NM_IS_AP (ap));

	priv = NM_AP_GET_PRIVATE (ap);

	nm_log_dbg (LOGD_WIFI_SCAN, "%s'%s' (%p)",
	            prefix,
	            priv->ssid ? nm_utils_escape_ssid (priv->ssid->data, priv->ssid->len) : "(none)",
	            ap);
	nm_log_dbg (LOGD_WIFI_SCAN, "    BSSID     " MAC_FMT, MAC_ARG (priv->address.ether_addr_octet));
	nm_log_dbg (LOGD_WIFI_SCAN, "    mode      %d", priv->mode);
	nm_log_dbg (LOGD_WIFI_SCAN, "    flags     0x%X", priv->flags);
	nm_log_dbg (LOGD_WIFI_SCAN, "    wpa flags 0x%X", priv->wpa_flags);
	nm_log_dbg (LOGD_WIFI_SCAN, "    rsn flags 0x%X", priv->rsn_flags);
	nm_log_dbg (LOGD_WIFI_SCAN, "    quality   %d", priv->strength);
	nm_log_dbg (LOGD_WIFI_SCAN, "    frequency %d", priv->freq);
	nm_log_dbg (LOGD_WIFI_SCAN, "    max rate  %d", priv->max_bitrate);
	nm_log_dbg (LOGD_WIFI_SCAN, "    last-seen %d", (int) priv->last_seen);
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
nm_ap_set_ssid (NMAccessPoint *ap, const GByteArray * ssid)
{
	NMAccessPointPrivate *priv;

	g_return_if_fail (NM_IS_AP (ap));

	priv = NM_AP_GET_PRIVATE (ap);

	if (ssid == priv->ssid)
		return;

	/* same SSID */
	if ((ssid && priv->ssid) && (ssid->len == priv->ssid->len)) {
		if (!memcmp (ssid->data, priv->ssid->data, ssid->len))
			return;
	}

	if (priv->ssid) {
		g_byte_array_free (priv->ssid, TRUE);
		priv->ssid = NULL;
	}

	if (ssid) {
		/* Should never get zero-length SSIDs */
		g_warn_if_fail (ssid->len > 0);

		if (ssid->len) {
			priv->ssid = g_byte_array_sized_new (ssid->len);
			priv->ssid->len = ssid->len;
			memcpy (priv->ssid->data, ssid->data, ssid->len);
		}
	}

	g_object_notify (G_OBJECT (ap), NM_AP_SSID);
}


NM80211ApFlags
nm_ap_get_flags (NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_AP (ap), NM_802_11_AP_SEC_NONE);

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
const struct ether_addr * nm_ap_get_address (const NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_AP (ap), NULL);

	return &NM_AP_GET_PRIVATE (ap)->address;
}

void nm_ap_set_address (NMAccessPoint *ap, const struct ether_addr * addr)
{
	NMAccessPointPrivate *priv;

	g_return_if_fail (NM_IS_AP (ap));
	g_return_if_fail (addr != NULL);

	priv = NM_AP_GET_PRIVATE (ap);

	if (memcmp (addr, &priv->address, sizeof (priv->address))) {
		memcpy (&NM_AP_GET_PRIVATE (ap)->address, addr, sizeof (struct ether_addr));
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
 * Get/Set functions to indicate whether an AP broadcasts its SSID.
 */
gboolean nm_ap_get_broadcast (NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_AP (ap), TRUE);

	return NM_AP_GET_PRIVATE (ap)->broadcast;
}


void nm_ap_set_broadcast (NMAccessPoint *ap, gboolean broadcast)
{
	g_return_if_fail (NM_IS_AP (ap));

	NM_AP_GET_PRIVATE (ap)->broadcast = broadcast;
}


/*
 * Get/Set functions for how long ago the AP was last seen in a scan.
 * APs older than a certain date are dropped from the list.
 *
 */
gint32
nm_ap_get_last_seen (const NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_AP (ap), FALSE);

	return NM_AP_GET_PRIVATE (ap)->last_seen;
}

void
nm_ap_set_last_seen (NMAccessPoint *ap, gint32 last_seen)
{
	g_return_if_fail (NM_IS_AP (ap));

	NM_AP_GET_PRIVATE (ap)->last_seen = last_seen;
}

gboolean
nm_ap_check_compatible (NMAccessPoint *self,
                        NMConnection *connection)
{
	NMAccessPointPrivate *priv;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wireless_sec;
	const char *mode;
	const char *band;
	const GByteArray *bssid;
	guint32 channel;

	g_return_val_if_fail (NM_IS_AP (self), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	priv = NM_AP_GET_PRIVATE (self);

	s_wireless = nm_connection_get_setting_wireless (connection);
	if (s_wireless == NULL)
		return FALSE;
	
	if (!nm_utils_same_ssid (nm_setting_wireless_get_ssid (s_wireless), priv->ssid, TRUE))
		return FALSE;

	bssid = nm_setting_wireless_get_bssid (s_wireless);
	if (bssid && memcmp (bssid->data, &priv->address, ETH_ALEN))
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
		if (!strcmp (band, "a")) {
			if (priv->freq < 4915 || priv->freq > 5825)
				return FALSE;
		} else if (!strcmp (band, "bg")) {
			if (priv->freq < 2412 || priv->freq > 2484)
				return FALSE;
		}
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
	                                        priv->address.ether_addr_octet,
	                                        priv->mode,
	                                        priv->flags,
	                                        priv->wpa_flags,
	                                        priv->rsn_flags,
	                                        connection,
	                                        lock_bssid,
	                                        error);
}

static gboolean
capabilities_compatible (NM80211ApSecurityFlags a_flags, NM80211ApSecurityFlags b_flags)
{
	if (a_flags == b_flags)
		return TRUE;

	/* Make sure there's a common key management method */
	if (!((a_flags & 0x300) & (b_flags & 0x300)))
		return FALSE;

	/* Ensure common pairwise ciphers */
	if (!((a_flags & 0xF) & (b_flags & 0xF)))
		return FALSE;

	/* Ensure common group ciphers */
	if (!((a_flags & 0xF0) & (b_flags & 0xF0)))
		return FALSE;

	return TRUE;
}

NMAccessPoint *
nm_ap_match_in_list (NMAccessPoint *find_ap,
                     GSList *ap_list,
                     gboolean strict_match)
{
	GSList *iter;

	g_return_val_if_fail (find_ap != NULL, NULL);

	for (iter = ap_list; iter; iter = g_slist_next (iter)) {
		NMAccessPoint * list_ap = NM_AP (iter->data);
		const GByteArray * list_ssid = nm_ap_get_ssid (list_ap);
		const struct ether_addr * list_addr = nm_ap_get_address (list_ap);

		const GByteArray * find_ssid = nm_ap_get_ssid (find_ap);
		const struct ether_addr * find_addr = nm_ap_get_address (find_ap);

		/* SSID match; if both APs are hiding their SSIDs,
		 * let matching continue on BSSID and other properties
		 */
		if (   (!list_ssid && find_ssid)
		    || (list_ssid && !find_ssid)
		    || !nm_utils_same_ssid (list_ssid, find_ssid, TRUE))
			continue;

		/* BSSID match */
		if (   (strict_match || nm_ethernet_address_is_valid (find_addr))
		    && nm_ethernet_address_is_valid (list_addr)
		    && memcmp (list_addr->ether_addr_octet, 
		               find_addr->ether_addr_octet,
		               ETH_ALEN) != 0) {
			continue;
		}

		/* mode match */
		if (nm_ap_get_mode (list_ap) != nm_ap_get_mode (find_ap))
			continue;

		/* Frequency match */
		if (nm_ap_get_freq (list_ap) != nm_ap_get_freq (find_ap))
			continue;

		/* AP flags */
		if (nm_ap_get_flags (list_ap) != nm_ap_get_flags (find_ap))
			continue;

		if (strict_match) {
			if (nm_ap_get_wpa_flags (list_ap) != nm_ap_get_wpa_flags (find_ap))
				continue;

			if (nm_ap_get_rsn_flags (list_ap) != nm_ap_get_rsn_flags (find_ap))
				continue;
		} else {
			NM80211ApSecurityFlags list_wpa_flags = nm_ap_get_wpa_flags (list_ap);
			NM80211ApSecurityFlags find_wpa_flags = nm_ap_get_wpa_flags (find_ap);
			NM80211ApSecurityFlags list_rsn_flags = nm_ap_get_rsn_flags (list_ap);
			NM80211ApSecurityFlags find_rsn_flags = nm_ap_get_rsn_flags (find_ap);

			/* Just ensure that there is overlap in the capabilities */
			if (   !capabilities_compatible (list_wpa_flags, find_wpa_flags)
			    && !capabilities_compatible (list_rsn_flags, find_rsn_flags))
				continue;
		}

		return list_ap;
	}

	return NULL;
}

