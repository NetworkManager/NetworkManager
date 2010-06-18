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
 * Copyright (C) 2004 - 2010 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#include "wireless-helper.h"

#include <string.h>

#include "nm-wifi-ap.h"
#include "NetworkManagerUtils.h"
#include "nm-utils.h"
#include "nm-logging.h"
#include "nm-dbus-manager.h"
#include "wpa.h"
#include "nm-properties-changed-signal.h"
#include "nm-setting-wireless.h"

#include "nm-access-point-glue.h"

/*
 * Encapsulates Access Point information
 */
typedef struct
{
	char *dbus_path;

	/* Scanned or cached values */
	GByteArray *	ssid;
	struct ether_addr	address;
	NM80211Mode		mode;
	gint8			strength;
	guint32			freq;		/* Frequency in MHz; ie 2412 (== 2.412 GHz) */
	guint32			max_bitrate;/* Maximum bitrate of the AP in Kbit/s (ie 54000 Kb/s == 54Mbit/s) */

	guint32			flags;		/* General flags */
	guint32			wpa_flags;	/* WPA-related flags */
	guint32			rsn_flags;	/* RSN (WPA2) -related flags */

	/* Non-scanned attributes */
	gboolean			fake;	/* Whether or not the AP is from a scan */
	gboolean			broadcast;	/* Whether or not the AP is broadcasting (hidden) */
	gboolean			user_created;	/* Whether or not the AP was created
										 * by the user with "Create network..."
										 * A subset of Ad-Hoc mode.  user_created
										 * implies Ad-Hoc, but not necessarily
										 * the other way around.
										 */
	glong				last_seen;	/* Last time the AP was seen in a scan in seconds */

	/* Things from user prefs/NetworkManagerInfo */
	GTimeVal			timestamp;
	GSList *			user_addresses;
} NMAccessPointPrivate;

#define NM_AP_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_AP, NMAccessPointPrivate))

G_DEFINE_TYPE (NMAccessPoint, nm_ap, G_TYPE_OBJECT)

enum {
	PROPERTIES_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

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
	if (priv->ssid)
		g_byte_array_free (priv->ssid, TRUE);
	g_slist_foreach (priv->user_addresses, (GFunc)g_free, NULL);
	g_slist_free (priv->user_addresses);

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
		nm_ap_set_strength (ap, g_value_get_char (value));
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
		g_value_take_string (value, nm_ether_ntop (&priv->address));
		break;
	case PROP_MODE:
		g_value_set_uint (value, priv->mode);
		break;
	case PROP_MAX_BITRATE:
		g_value_set_uint (value, priv->max_bitrate);
		break;
	case PROP_STRENGTH:
		g_value_set_char (value, priv->strength);
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
	guint32 all_sec_flags;

	g_type_class_add_private (ap_class, sizeof (NMAccessPointPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize = finalize;

	/* properties */

	all_sec_flags =   NM_802_11_AP_SEC_NONE
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

	g_object_class_install_property
		(object_class, PROP_FLAGS,
		 g_param_spec_uint (NM_AP_FLAGS,
							"Flags",
							"Flags",
							NM_802_11_AP_FLAGS_NONE,
							NM_802_11_AP_FLAGS_PRIVACY,
							NM_802_11_AP_FLAGS_NONE,
							G_PARAM_READWRITE));

	g_object_class_install_property
		(object_class, PROP_WPA_FLAGS,
		 g_param_spec_uint (NM_AP_WPA_FLAGS,
							"WPA Flags",
							"WPA Flags",
							NM_802_11_AP_SEC_NONE,
							all_sec_flags,
							NM_802_11_AP_SEC_NONE,
							G_PARAM_READWRITE));

	g_object_class_install_property
		(object_class, PROP_RSN_FLAGS,
		 g_param_spec_uint (NM_AP_RSN_FLAGS,
							"RSN Flags",
							"RSN Flags",
							NM_802_11_AP_SEC_NONE,
							all_sec_flags,
							NM_802_11_AP_SEC_NONE,
							G_PARAM_READWRITE));

	g_object_class_install_property
		(object_class, PROP_SSID,
	     g_param_spec_boxed (NM_AP_SSID,
	                         "SSID",
	                         "SSID",
	                         DBUS_TYPE_G_UCHAR_ARRAY,
	                         G_PARAM_READWRITE));

	g_object_class_install_property
		(object_class, PROP_FREQUENCY,
		 g_param_spec_uint (NM_AP_FREQUENCY,
							"Frequency",
							"Frequency",
							0, 10000, 0,
							G_PARAM_READWRITE));

	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_AP_HW_ADDRESS,
							  "MAC Address",
							  "Hardware MAC address",
							  NULL,
							  G_PARAM_READABLE));
	
	g_object_class_install_property
		(object_class, PROP_MODE,
		 g_param_spec_uint (NM_AP_MODE,
						   "Mode",
						   "Mode",
						   NM_802_11_MODE_ADHOC, NM_802_11_MODE_INFRA, NM_802_11_MODE_INFRA,
						   G_PARAM_READWRITE));

	g_object_class_install_property
		(object_class, PROP_MAX_BITRATE,
		 g_param_spec_uint (NM_AP_MAX_BITRATE,
							"Max Bitrate",
							"Max Bitrate",
							0, G_MAXUINT16, 0,
							G_PARAM_READWRITE));

	g_object_class_install_property
		(object_class, PROP_STRENGTH,
		 g_param_spec_char (NM_AP_STRENGTH,
							"Strength",
							"Strength",
							G_MININT8, G_MAXINT8, 0,
							G_PARAM_READWRITE));

	/* Signals */
	signals[PROPERTIES_CHANGED] = 
		nm_properties_changed_signal_new (object_class,
								    G_STRUCT_OFFSET (NMAccessPointClass, properties_changed));

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (ap_class),
							   &dbus_glib_nm_access_point_object_info);
}

void
nm_ap_export_to_dbus (NMAccessPoint *ap)
{
	NMAccessPointPrivate *priv;
	NMDBusManager *mgr;
	DBusGConnection *g_connection;
	static guint32 counter = 0;

	g_return_if_fail (NM_IS_AP (ap));

	priv = NM_AP_GET_PRIVATE (ap);

	if (priv->dbus_path) {
		nm_log_err (LOGD_CORE, "Tried to export AP %s twice.", priv->dbus_path);
		return;
	}

	mgr = nm_dbus_manager_get ();
	g_assert (mgr);

	g_connection = nm_dbus_manager_get_connection (mgr);
	g_assert (g_connection);

	priv->dbus_path = g_strdup_printf (NM_DBUS_PATH_ACCESS_POINT "/%d", counter++);
	dbus_g_connection_register_g_object (g_connection, priv->dbus_path, G_OBJECT (ap));

	g_object_unref (mgr);
}

/*
 * nm_ap_new
 *
 * Create a new, blank user access point info structure
 *
 */
NMAccessPoint *nm_ap_new (void)
{
	GObject *object;

	object = g_object_new (NM_TYPE_AP, NULL);
	if (!object)
		return NULL;

	return (NMAccessPoint *) object;
}


#define IEEE80211_CAP_ESS       0x0001
#define IEEE80211_CAP_IBSS      0x0002
#define IEEE80211_CAP_PRIVACY   0x0010

static void
foreach_property_cb (gpointer key, gpointer value, gpointer user_data)
{
	GValue *variant = (GValue *) value;
	NMAccessPoint *ap = (NMAccessPoint *) user_data;

	if (G_VALUE_HOLDS_BOXED (variant)) {
		GArray *array = g_value_get_boxed (variant);

		if (!strcmp (key, "ssid")) {
			guint32 len = MIN (IW_ESSID_MAX_SIZE, array->len);
			GByteArray * ssid;

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
		} else if (!strcmp (key, "bssid")) {
			struct ether_addr addr;

			if (array->len != ETH_ALEN)
				return;
			memset (&addr, 0, sizeof (struct ether_addr));
			memcpy (&addr, array->data, ETH_ALEN);
			nm_ap_set_address (ap, &addr);
		} else if (!strcmp (key, "wpaie")) {
			guint8 * ie = (guint8 *) array->data;
			guint32 flags = nm_ap_get_wpa_flags (ap);

			if (array->len <= 0 || array->len > WPA_MAX_IE_LEN)
				return;
			flags = nm_ap_add_security_from_ie (flags, ie, array->len);
			nm_ap_set_wpa_flags (ap, flags);
		} else if (!strcmp (key, "rsnie")) {
			guint8 * ie = (guint8 *) array->data;
			guint32 flags = nm_ap_get_rsn_flags (ap);

			if (array->len <= 0 || array->len > WPA_MAX_IE_LEN)
				return;
			flags = nm_ap_add_security_from_ie (flags, ie, array->len);
			nm_ap_set_rsn_flags (ap, flags);
		}
	} else if (G_VALUE_HOLDS_INT (variant)) {
		gint32 int_val = g_value_get_int (variant);

		if (!strcmp (key, "frequency")) {
			nm_ap_set_freq (ap, (guint32) int_val);
		} else if (!strcmp (key, "maxrate")) {
			/* Supplicant reports as b/s, we use Kb/s internally */
			nm_ap_set_max_bitrate (ap, int_val / 1000);
		}
	} else if (G_VALUE_HOLDS_UINT (variant)) {
		guint32 val = g_value_get_uint (variant);

		if (!strcmp (key, "capabilities")) {
			if (val & IEEE80211_CAP_ESS) {
				nm_ap_set_mode (ap, NM_802_11_MODE_INFRA);
			} else if (val & IEEE80211_CAP_IBSS) {
				nm_ap_set_mode (ap, NM_802_11_MODE_ADHOC);
			}

			if (val & IEEE80211_CAP_PRIVACY) {
				guint32 flags = nm_ap_get_flags (ap);
				nm_ap_set_flags (ap, flags | NM_802_11_AP_FLAGS_PRIVACY);
			}
		}
	}
}


NMAccessPoint *
nm_ap_new_from_properties (GHashTable *properties)
{
	NMAccessPoint *ap;
	GTimeVal cur_time;
	const struct ether_addr * addr;
	const char bad_bssid1[ETH_ALEN] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	const char bad_bssid2[ETH_ALEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

	g_return_val_if_fail (properties != NULL, NULL);

	ap = nm_ap_new ();

	g_object_freeze_notify (G_OBJECT (ap));
	g_hash_table_foreach (properties, foreach_property_cb, ap);

	/* ignore APs with invalid BSSIDs */
	addr = nm_ap_get_address (ap);
	if (   !(memcmp (addr->ether_addr_octet, bad_bssid1, ETH_ALEN))
	    || !(memcmp (addr->ether_addr_octet, bad_bssid2, ETH_ALEN))) {
		g_object_unref (ap);
		return NULL;
	}

	g_get_current_time (&cur_time);
	nm_ap_set_last_seen (ap, cur_time.tv_sec);

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
	guint32 flags = NM_802_11_AP_SEC_NONE;
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
	guint32 flags = NM_802_11_AP_SEC_NONE;
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
	guint32 channel, flags;
	gboolean psk = FALSE, eap = FALSE;

	g_return_val_if_fail (connection != NULL, NULL);

	s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS));
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
		else
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

	s_wireless_sec = (NMSettingWirelessSecurity *) nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS_SECURITY);
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
nm_ap_print_self (NMAccessPoint *ap,
                  const char * prefix)
{
	NMAccessPointPrivate *priv;

	g_return_if_fail (ap != NULL);
	g_return_if_fail (NM_IS_AP (ap));

	priv = NM_AP_GET_PRIVATE (ap);

	nm_log_dbg (LOGD_WIFI_SCAN, "%s'%s' (%p)",
	            prefix,
	            priv->ssid ? nm_utils_escape_ssid (priv->ssid->data, priv->ssid->len) : "(none)",
	            ap);
	nm_log_dbg (LOGD_WIFI_SCAN, "    BSSID     " MAC_FMT, MAC_ARG (priv->address.ether_addr_octet));
	nm_log_dbg (LOGD_WIFI_SCAN, "    mode      %d", priv->mode);
	nm_log_dbg (LOGD_WIFI_SCAN, "    timestamp %ld", priv->timestamp.tv_sec);
	nm_log_dbg (LOGD_WIFI_SCAN, "    flags     0x%X", priv->flags);
	nm_log_dbg (LOGD_WIFI_SCAN, "    wpa flags 0x%X", priv->wpa_flags);
	nm_log_dbg (LOGD_WIFI_SCAN, "    rsn flags 0x%X", priv->rsn_flags);
	nm_log_dbg (LOGD_WIFI_SCAN, "    quality   %d", priv->strength);
	nm_log_dbg (LOGD_WIFI_SCAN, "    frequency %d", priv->freq);
	nm_log_dbg (LOGD_WIFI_SCAN, "    max rate  %d", priv->max_bitrate);
	nm_log_dbg (LOGD_WIFI_SCAN, "    last-seen %ld", priv->last_seen);
}

const char *
nm_ap_get_dbus_path (NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_AP (ap), NULL);

	return NM_AP_GET_PRIVATE (ap)->dbus_path;
}


/*
 * Get/set functions for timestamp
 *
 */
const GTimeVal *nm_ap_get_timestamp (const NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_AP (ap), 0);

	return (&NM_AP_GET_PRIVATE (ap)->timestamp);
}

void nm_ap_set_timestamp (NMAccessPoint *ap, glong sec, glong usec)
{
	NMAccessPointPrivate *priv;

	g_return_if_fail (NM_IS_AP (ap));

	priv = NM_AP_GET_PRIVATE (ap);

	priv->timestamp.tv_sec = sec;
	priv->timestamp.tv_usec = usec;
}

void nm_ap_set_timestamp_via_timestamp (NMAccessPoint *ap, const GTimeVal *timestamp)
{
	g_return_if_fail (NM_IS_AP (ap));

	NM_AP_GET_PRIVATE (ap)->timestamp = *timestamp;
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

	if ((ssid == priv->ssid) && ssid == NULL)
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
		priv->ssid = g_byte_array_sized_new (ssid->len);
		priv->ssid->len = ssid->len;
		memcpy (priv->ssid->data, ssid->data, ssid->len);
	}

	g_object_notify (G_OBJECT (ap), NM_AP_SSID);
}


guint32
nm_ap_get_flags (NMAccessPoint *ap)
{
	guint32 flags;

	g_return_val_if_fail (NM_IS_AP (ap), NM_802_11_AP_FLAGS_NONE);

	g_object_get (ap, NM_AP_FLAGS, &flags, NULL);

	return flags;
}


void
nm_ap_set_flags (NMAccessPoint *ap, guint32 flags)
{
	NMAccessPointPrivate *priv;

	g_return_if_fail (NM_IS_AP (ap));

	priv = NM_AP_GET_PRIVATE (ap);

	if (priv->flags != flags) {
		priv->flags = flags;
		g_object_notify (G_OBJECT (ap), NM_AP_FLAGS);
	}
}

guint32
nm_ap_get_wpa_flags (NMAccessPoint *ap)
{
	guint32 flags;

	g_return_val_if_fail (NM_IS_AP (ap), NM_802_11_AP_SEC_NONE);

	g_object_get (ap, NM_AP_WPA_FLAGS, &flags, NULL);

	return flags;
}


void
nm_ap_set_wpa_flags (NMAccessPoint *ap, guint32 flags)
{
	NMAccessPointPrivate *priv;

	g_return_if_fail (NM_IS_AP (ap));

	priv = NM_AP_GET_PRIVATE (ap);

	if (priv->wpa_flags != flags) {
		priv->wpa_flags = flags;
		g_object_notify (G_OBJECT (ap), NM_AP_WPA_FLAGS);
	}
}

guint32
nm_ap_get_rsn_flags (NMAccessPoint *ap)
{
	guint32 flags;

	g_return_val_if_fail (NM_IS_AP (ap), NM_802_11_AP_SEC_NONE);

	g_object_get (ap, NM_AP_RSN_FLAGS, &flags, NULL);

	return flags;
}


void
nm_ap_set_rsn_flags (NMAccessPoint *ap, guint32 flags)
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

	if (mode == NM_802_11_MODE_ADHOC || mode == NM_802_11_MODE_INFRA) {
		priv = NM_AP_GET_PRIVATE (ap);

		if (priv->mode != mode) {
			priv->mode = mode;
			g_object_notify (G_OBJECT (ap), NM_AP_MODE);
		}
	} else
		nm_log_warn (LOGD_WIFI, "Invalid AP mode '%d'", mode);
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
 * Get/set functions for max bitrate
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
glong nm_ap_get_last_seen (const NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_AP (ap), FALSE);

	return NM_AP_GET_PRIVATE (ap)->last_seen;
}

void nm_ap_set_last_seen (NMAccessPoint *ap, const glong last_seen)
{
	g_return_if_fail (NM_IS_AP (ap));

	NM_AP_GET_PRIVATE (ap)->last_seen = last_seen;
}


/*
 * Get/Set functions to indicate that an access point is
 * user-created, ie whether or not its a network filled with
 * information from the user and intended to create a new Ad-Hoc
 * wireless network.
 *
 */
gboolean nm_ap_get_user_created (const NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_AP (ap), FALSE);

	return NM_AP_GET_PRIVATE (ap)->user_created;
}

void nm_ap_set_user_created (NMAccessPoint *ap, gboolean user_created)
{
	g_return_if_fail (NM_IS_AP (ap));

	NM_AP_GET_PRIVATE (ap)->user_created = user_created;
}


/*
 * Get/Set functions for user address list
 *
 * The internal address list is always "owned" by the AP and
 * the list returned by nm_ap_get_user_addresses() is a deep copy.
 * Likewise, when setting the list, a deep copy is made for the
 * ap's actual list.
 *
 */
GSList *nm_ap_get_user_addresses (const NMAccessPoint *ap)
{
	GSList	*new = NULL;
	GSList	*elt = NULL;

	g_return_val_if_fail (NM_IS_AP (ap), NULL);

	for (elt = NM_AP_GET_PRIVATE (ap)->user_addresses; elt; elt = g_slist_next (elt))
	{
		if (elt->data)
			new = g_slist_append (new, g_strdup (elt->data));
	}

	/* Return a _deep__copy_ of the address list */
	return new;
}

void nm_ap_set_user_addresses (NMAccessPoint *ap, GSList *list)
{
	NMAccessPointPrivate *priv;
	GSList	*elt = NULL;
	GSList	*new = NULL;

	g_return_if_fail (NM_IS_AP (ap));

	priv = NM_AP_GET_PRIVATE (ap);

	/* Free existing list */
	g_slist_foreach (priv->user_addresses, (GFunc) g_free, NULL);

	/* Copy new list and set as our own */
	for (elt = list; elt; elt = g_slist_next (elt))
	{
		if (elt->data)
			new = g_slist_append (new, g_ascii_strup (elt->data, -1));
	}

	priv->user_addresses = new;
}


guint32
nm_ap_add_security_from_ie (guint32 flags,
                            const guint8 *wpa_ie,
                            guint32 length)
{
	wpa_ie_data * cap_data;

	if (!(cap_data = wpa_parse_wpa_ie (wpa_ie, length)))
		return NM_802_11_AP_SEC_NONE;

	/* Pairwise cipher flags */
	if (cap_data->pairwise_cipher & IW_AUTH_CIPHER_WEP40)
		flags |= NM_802_11_AP_SEC_PAIR_WEP40;
	if (cap_data->pairwise_cipher & IW_AUTH_CIPHER_WEP104)
		flags |= NM_802_11_AP_SEC_PAIR_WEP104;
	if (cap_data->pairwise_cipher & IW_AUTH_CIPHER_TKIP)
		flags |= NM_802_11_AP_SEC_PAIR_TKIP;
	if (cap_data->pairwise_cipher & IW_AUTH_CIPHER_CCMP)
		flags |= NM_802_11_AP_SEC_PAIR_CCMP;

	/* Group cipher flags */
	if (cap_data->group_cipher & IW_AUTH_CIPHER_WEP40)
		flags |= NM_802_11_AP_SEC_GROUP_WEP40;
	if (cap_data->group_cipher & IW_AUTH_CIPHER_WEP104)
		flags |= NM_802_11_AP_SEC_GROUP_WEP104;
	if (cap_data->group_cipher & IW_AUTH_CIPHER_TKIP)
		flags |= NM_802_11_AP_SEC_GROUP_TKIP;
	if (cap_data->group_cipher & IW_AUTH_CIPHER_CCMP)
		flags |= NM_802_11_AP_SEC_GROUP_CCMP;

	if (cap_data->key_mgmt & IW_AUTH_KEY_MGMT_802_1X)
		flags |= NM_802_11_AP_SEC_KEY_MGMT_802_1X;
	if (cap_data->key_mgmt & IW_AUTH_KEY_MGMT_PSK)
		flags |= NM_802_11_AP_SEC_KEY_MGMT_PSK;

	g_slice_free (wpa_ie_data, cap_data);
	return flags;
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

	s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS));
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

	s_wireless_sec = (NMSettingWirelessSecurity *) nm_connection_get_setting (connection,
	                                                                          NM_TYPE_SETTING_WIRELESS_SECURITY);

	return nm_setting_wireless_ap_security_compatible (s_wireless,
	                                                   s_wireless_sec,
	                                                   nm_ap_get_flags (self),
	                                                   nm_ap_get_wpa_flags (self),
	                                                   nm_ap_get_rsn_flags (self),
	                                                   nm_ap_get_mode (self));
}

static gboolean
capabilities_compatible (guint32 a_flags, guint32 b_flags)
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
			guint32 list_wpa_flags = nm_ap_get_wpa_flags (list_ap);
			guint32 find_wpa_flags = nm_ap_get_wpa_flags (find_ap);
			guint32 list_rsn_flags = nm_ap_get_rsn_flags (list_ap);
			guint32 find_rsn_flags = nm_ap_get_rsn_flags (find_ap);

			/* Just ensure that there is overlap in the capabilities */
			if (   !capabilities_compatible (list_wpa_flags, find_wpa_flags)
			    && !capabilities_compatible (list_rsn_flags, find_rsn_flags))
				continue;
		}

		return list_ap;
	}

	return NULL;
}

