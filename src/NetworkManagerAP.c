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
 * (C) Copyright 2004 Red Hat, Inc.
 */

#include "NetworkManagerAP.h"
#include "NetworkManagerUtils.h"
#include "nm-utils.h"
#include "nm-dbus-manager.h"
#include <wireless.h>
#include "wpa.h"

#include "nm-access-point-glue.h"

/* This is a controlled list.  Want to add to it?  Stop.  Ask first. */
static const char * default_ssid_list[] =
{
	"linksys",
	"linksys-a",
	"linksys-g",
	"default",
	"belkin54g",
	"NETGEAR",
	NULL
};

/*
 * Encapsulates Access Point information
 */
typedef struct
{
	char *dbus_path;

	/* Scanned or cached values */
	GByteArray *	ssid;
	struct ether_addr	address;
	int				mode;		/* from IW_MODE_* in wireless.h */
	gint8			strength;
	guint32			freq;		/* Frequency in GHz * 1000; ie 2.412 == 2412 */
	guint16			rate;

	guint32			flags;		/* General flags */
	guint32			wpa_flags;	/* WPA-related flags */
	guint32			rsn_flags;	/* RSN (WPA2) -related flags */

	/* Non-scanned attributes */
	gboolean			invalid;
	gboolean			artificial;	/* Whether or not the AP is from a scan */
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
	STRENGTH_CHANGED,

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
	PROP_RATE,
	PROP_STRENGTH,
	LAST_PROP
};


static void
nm_ap_init (NMAccessPoint *ap)
{
	NMAccessPointPrivate *priv = NM_AP_GET_PRIVATE (ap);
	static guint32 counter = 0;

	priv->dbus_path = g_strdup_printf (NM_DBUS_PATH_ACCESS_POINT "/%d", counter++);
	priv->mode = IW_MODE_INFRA;
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
	NMAccessPointPrivate *priv = NM_AP_GET_PRIVATE (object);
	GArray * ssid;
	int mode;

	switch (prop_id) {
	case PROP_FLAGS:
		priv->flags = g_value_get_uint (value);
		break;
	case PROP_WPA_FLAGS:
		priv->wpa_flags = g_value_get_uint (value);
		break;
	case PROP_RSN_FLAGS:
		priv->rsn_flags = g_value_get_uint (value);
		break;
	case PROP_SSID:
		ssid = g_value_get_boxed (value);
		if (priv->ssid) {
			g_byte_array_free (priv->ssid, TRUE);
			priv->ssid = NULL;
		}
		if (ssid) {
			int i;
			unsigned char byte;
			priv->ssid = g_byte_array_sized_new (ssid->len);
			for (i = 0; i < ssid->len; i++) {
				byte = g_array_index (ssid, unsigned char, i);
				g_byte_array_append (priv->ssid, &byte, 1);
			}
		}
		break;
	case PROP_FREQUENCY:
		priv->freq = g_value_get_uint (value);
		break;
	case PROP_MODE:
		mode = g_value_get_int (value);

		if (mode == IW_MODE_ADHOC || mode == IW_MODE_INFRA)
			priv->mode = mode;
		else
			g_warning ("Invalid mode");
		break;
	case PROP_RATE:
		priv->rate = g_value_get_uint (value);
		break;
	case PROP_STRENGTH:
		nm_ap_set_strength (NM_AP (object), g_value_get_char (value));
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
	char hw_addr_buf[20];
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
		memset (hw_addr_buf, 0, 20);
		iw_ether_ntop (&priv->address, hw_addr_buf);
		g_value_set_string (value, &hw_addr_buf[0]);
		break;
	case PROP_MODE:
		g_value_set_int (value, priv->mode);
		break;
	case PROP_RATE:
		g_value_set_uint (value, priv->rate);
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
		 g_param_spec_int (NM_AP_MODE,
						   "Mode",
						   "Mode",
						   IW_MODE_ADHOC, IW_MODE_INFRA, IW_MODE_INFRA,
						   G_PARAM_READWRITE));

	g_object_class_install_property
		(object_class, PROP_RATE,
		 g_param_spec_uint (NM_AP_RATE,
							"Rate",
							"Rate",
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
	signals[STRENGTH_CHANGED] =
		g_signal_new ("strength_changed",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMAccessPointClass, strength_changed),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__CHAR,
					  G_TYPE_NONE, 1,
					  G_TYPE_CHAR);

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (ap_class),
									 &dbus_glib_nm_access_point_object_info);
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

	dbus_g_connection_register_g_object (nm_dbus_manager_get_connection (nm_dbus_manager_get ()),
										 nm_ap_get_dbus_path (NM_AP (object)),
										 object);

	return (NMAccessPoint *) object;
}


/*
 * nm_ap_new_from_ap
 *
 * Create a new user access point info structure, duplicating an existing one
 *
 */
NMAccessPoint *
nm_ap_new_from_ap (NMAccessPoint *src_ap)
{
	NMAccessPoint *	new_ap;
	NMAccessPointPrivate *src_priv;
	NMAccessPointPrivate *new_priv;

	g_return_val_if_fail (NM_IS_AP (src_ap), NULL);

	if (!(new_ap = nm_ap_new ()))
	{
		nm_warning ("nm_ap_new_from_uap() could not allocate a new user access point structure.  Not enough memory?");
		return NULL;
	}

	src_priv = NM_AP_GET_PRIVATE (src_ap);
	new_priv = NM_AP_GET_PRIVATE (new_ap);

	if (src_priv->ssid) {
		new_priv->ssid = g_byte_array_sized_new (src_priv->ssid->len);
		g_byte_array_append (new_priv->ssid,
		                     src_priv->ssid->data,
		                     src_priv->ssid->len);
	}
	memcpy (&new_priv->address, &src_priv->address, sizeof (struct ether_addr));
	new_priv->mode = src_priv->mode;
	new_priv->strength = src_priv->strength;
	new_priv->freq = src_priv->freq;
	new_priv->rate = src_priv->rate;
	new_priv->artificial = src_priv->artificial;
	new_priv->broadcast = src_priv->broadcast;
	new_priv->flags = src_priv->flags;
	new_priv->wpa_flags = src_priv->wpa_flags;
	new_priv->rsn_flags = src_priv->rsn_flags;

	return new_ap;
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
			nm_ap_set_rate (ap, int_val);
		}
	} else if (G_VALUE_HOLDS_UINT (variant)) {
		guint32 val = g_value_get_uint (variant);

		if (!strcmp (key, "capabilities")) {
			if (val & IEEE80211_CAP_ESS) {
				nm_ap_set_mode (ap, IW_MODE_INFRA);
			} else if (val & IEEE80211_CAP_IBSS) {
				nm_ap_set_mode (ap, IW_MODE_ADHOC);
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

	return ap;
}

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ARG(x) ((guint8*)(x))[0],((guint8*)(x))[1],((guint8*)(x))[2],((guint8*)(x))[3],((guint8*)(x))[4],((guint8*)(x))[5]

void
nm_ap_print_self (NMAccessPoint *ap,
                  const char * prefix)
{
	NMAccessPointPrivate *priv;

	g_return_if_fail (NM_IS_AP (ap));

	priv = NM_AP_GET_PRIVATE (ap);

	nm_info ("%s'%s' (%p) stamp=%ld flags=0x%X wpa-flags=0x%X rsn-flags=0x%x "
	         "bssid=" MAC_FMT " strength=%d freq=%d rate=%d inval=%d "
	         "mode=%d seen=%ld",
	         prefix,
	         priv->ssid ? nm_utils_escape_ssid (priv->ssid->data, priv->ssid->len) : "(none)",
	         ap,
	         priv->timestamp.tv_sec,
	         priv->flags,
	         priv->wpa_flags,
	         priv->rsn_flags,
	         MAC_ARG (priv->address.ether_addr_octet),
	         priv->strength,
	         priv->freq,
	         priv->rate,
	         priv->invalid,
	         priv->mode,
	         priv->last_seen);
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

void nm_ap_set_ssid (NMAccessPoint *ap, const GByteArray * ssid)
{
	g_return_if_fail (NM_IS_AP (ap));

	g_object_set (ap, NM_AP_SSID, ssid, NULL);
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
	g_return_if_fail (NM_IS_AP (ap));

	g_object_set (ap, NM_AP_FLAGS, flags, NULL);
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
	g_return_if_fail (NM_IS_AP (ap));

	g_object_set (ap, NM_AP_WPA_FLAGS, flags, NULL);
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
	g_return_if_fail (NM_IS_AP (ap));

	g_object_set (ap, NM_AP_RSN_FLAGS, flags, NULL);
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
	g_return_if_fail (NM_IS_AP (ap));
	g_return_if_fail (addr != NULL);

	memcpy (&NM_AP_GET_PRIVATE (ap)->address, addr, sizeof (struct ether_addr));
}


/*
 * Get/set functions for mode (ie Ad-Hoc, Infrastructure, etc)
 *
 */
int nm_ap_get_mode (NMAccessPoint *ap)
{
	int mode;

	g_return_val_if_fail (NM_IS_AP (ap), -1);

	g_object_get (ap, NM_AP_MODE, &mode, NULL);

	return mode;
}

void nm_ap_set_mode (NMAccessPoint *ap, const int mode)
{
	g_return_if_fail (NM_IS_AP (ap));

	g_object_set (ap, NM_AP_MODE, mode, NULL);
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
		g_signal_emit (ap, signals[STRENGTH_CHANGED], 0, strength);
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
	g_return_if_fail (NM_IS_AP (ap));

	g_object_set (ap, NM_AP_FREQUENCY, freq, NULL);
}


/*
 * Get/set functions for rate
 *
 */
guint16 nm_ap_get_rate (NMAccessPoint *ap)
{
	guint16 rate;

	g_return_val_if_fail (NM_IS_AP (ap), 0);

	g_object_get (ap, NM_AP_RATE, &rate, NULL);

	return rate;
}

void nm_ap_set_rate (NMAccessPoint *ap, guint16 rate)
{
	g_return_if_fail (NM_IS_AP (ap));

	g_object_set (ap, NM_AP_RATE, rate, NULL);
}


/*
 * Get/set functions for "invalid" access points, ie ones
 * for which a user explicitly does not wish to connect to
 * (by cancelling requests for WEP key, for example)
 *
 */
gboolean nm_ap_get_invalid (const NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_AP (ap), TRUE);

	return NM_AP_GET_PRIVATE (ap)->invalid;
}

void nm_ap_set_invalid (NMAccessPoint *ap, gboolean invalid)
{
	g_return_if_fail (NM_IS_AP (ap));

	NM_AP_GET_PRIVATE (ap)->invalid = invalid;
}


/*
 * Get/Set functions to indicate that an access point is
 * 'artificial', ie whether or not it was actually scanned
 * by the card or not
 *
 */
gboolean nm_ap_get_artificial (const NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_AP (ap), FALSE);

	return NM_AP_GET_PRIVATE (ap)->artificial;
}

void nm_ap_set_artificial (NMAccessPoint *ap, gboolean artificial)
{
	g_return_if_fail (NM_IS_AP (ap));

	NM_AP_GET_PRIVATE (ap)->artificial = artificial;
}


/*
 * Get/Set functions to indicate whether an access point is broadcasting
 * (hidden).  This is a superset of artificial.
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


gboolean nm_ap_has_manufacturer_default_ssid (NMAccessPoint *ap)
{
	const char **default_ssid = default_ssid_list;
	const GByteArray * this_ssid;

	g_return_val_if_fail (NM_IS_AP (ap), FALSE);
	this_ssid = NM_AP_GET_PRIVATE (ap)->ssid;

	while (*default_ssid) {
		if (this_ssid->len == strlen (*default_ssid)) {
			if (!memcmp (*default_ssid, this_ssid->data, this_ssid->len))
				return TRUE;
		}
		default_ssid++;
	}

	return FALSE;
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

static gboolean
match_cipher (const char * cipher,
              const char * expected,
              guint32 wpa_flags,
              guint32 rsn_flags,
              guint32 flag)
{
	if (strcmp (cipher, expected) != 0)
		return FALSE;

	if (!(wpa_flags & flag) && !(rsn_flags & flag))
		return FALSE;

	return TRUE;
}

static gboolean
security_compatible (NMAccessPoint *self,
                     NMConnection *connection,
                     NMSettingWireless *s_wireless)
{
	NMAccessPointPrivate *priv = NM_AP_GET_PRIVATE (self);
	NMSettingWirelessSecurity *s_wireless_sec;
	guint32 flags = priv->flags;
	guint32 wpa_flags = priv->wpa_flags;
	guint32 rsn_flags = priv->rsn_flags;
	
	if (!s_wireless->security) {
		if (   (flags & NM_802_11_AP_FLAGS_PRIVACY)
		    || (wpa_flags != NM_802_11_AP_SEC_NONE)
		    || (rsn_flags != NM_802_11_AP_SEC_NONE))
			return FALSE;
		return TRUE;
	}

	if (strcmp (s_wireless->security, "802-11-wireless-security") != 0)
		return FALSE;

	s_wireless_sec = (NMSettingWirelessSecurity *) nm_connection_get_setting (connection, "802-11-wireless-security");
	if (s_wireless_sec == NULL || !s_wireless_sec->key_mgmt)
		return FALSE;

	/* Static WEP */
	if (!strcmp (s_wireless_sec->key_mgmt, "none")) {
		if (   !(flags & NM_802_11_AP_FLAGS_PRIVACY)
		    || (wpa_flags != NM_802_11_AP_SEC_NONE)
		    || (rsn_flags != NM_802_11_AP_SEC_NONE))
			return FALSE;
		return TRUE;
	}

	/* Adhoc WPA */
	if (!strcmp (s_wireless_sec->key_mgmt, "wpa-none")) {
		if (priv->mode != IW_MODE_ADHOC)
			return FALSE;
		// FIXME: validate ciphers if the BSSID actually puts WPA/RSN IE in
		// it's beacon
		return TRUE;
	}

	/* Stuff after this point requires infrastructure */
	if (priv->mode != IW_MODE_INFRA)
		return FALSE;

	/* Dynamic WEP or LEAP/Network EAP */
	if (!strcmp (s_wireless_sec->key_mgmt, "ieee8021x")) {
		// FIXME: should we allow APs that advertise WPA/RSN support here?
		if (   !(flags & NM_802_11_AP_FLAGS_PRIVACY)
		    || (wpa_flags != NM_802_11_AP_SEC_NONE)
		    || (rsn_flags != NM_802_11_AP_SEC_NONE))
			return FALSE;
		return TRUE;
	}

	/* WPA[2]-PSK */
	if (!strcmp (s_wireless_sec->key_mgmt, "wpa-psk")) {
		GSList * elt;
		gboolean found = FALSE;

		if (!s_wireless_sec->pairwise || !s_wireless_sec->group)
			return FALSE;

		if (   !(wpa_flags & NM_802_11_AP_SEC_KEY_MGMT_PSK)
		    && !(rsn_flags & NM_802_11_AP_SEC_KEY_MGMT_PSK))
			return FALSE;

		// FIXME: should handle WPA and RSN separately here to ensure that
		// if the Connection only uses WPA we don't match a cipher against
		// the AP's RSN IE instead

		/* Match at least one pairwise cipher with AP's capability */
		for (elt = s_wireless_sec->pairwise; elt; elt = g_slist_next (elt)) {
			if ((found = match_cipher (elt->data, "tkip", wpa_flags, rsn_flags, NM_802_11_AP_SEC_PAIR_TKIP)))
				break;
			if ((found = match_cipher (elt->data, "ccmp", wpa_flags, rsn_flags, NM_802_11_AP_SEC_PAIR_CCMP)))
				break;
		}
		if (!found)
			return FALSE;

		/* Match at least one group cipher with AP's capability */
		for (elt = s_wireless_sec->group; elt; elt = g_slist_next (elt)) {
			if ((found = match_cipher (elt->data, "wep40", wpa_flags, rsn_flags, NM_802_11_AP_SEC_GROUP_WEP40)))
				break;
			if ((found = match_cipher (elt->data, "wep104", wpa_flags, rsn_flags, NM_802_11_AP_SEC_GROUP_WEP104)))
				break;
			if ((found = match_cipher (elt->data, "tkip", wpa_flags, rsn_flags, NM_802_11_AP_SEC_GROUP_TKIP)))
				break;
			if ((found = match_cipher (elt->data, "ccmp", wpa_flags, rsn_flags, NM_802_11_AP_SEC_GROUP_CCMP)))
				break;
		}
		if (!found)
			return FALSE;

		return TRUE;
	}

	if (!strcmp (s_wireless_sec->key_mgmt, "wpa-eap")) {
		// FIXME: implement
	}

	return FALSE;
}

gboolean
nm_ap_check_compatible (NMAccessPoint *self,
                        NMConnection *connection)
{
	NMAccessPointPrivate *priv;
	NMSettingWireless *s_wireless;

	g_return_val_if_fail (NM_IS_AP (self), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	priv = NM_AP_GET_PRIVATE (self);

	s_wireless = (NMSettingWireless *) nm_connection_get_setting (connection, "802-11-wireless");
	if (s_wireless == NULL)
		return FALSE;
	
	if (!nm_utils_same_ssid (s_wireless->ssid, priv->ssid, TRUE))
		return FALSE;

	if (s_wireless->bssid) {
		if (memcmp (s_wireless->bssid->data, &priv->address, ETH_ALEN))
			return FALSE;
	}

	if (s_wireless->mode) {
		if (   !strcmp (s_wireless->mode, "infrastructure")
		    && (priv->mode != IW_MODE_INFRA))
			return FALSE;
		if (   !strcmp (s_wireless->mode, "adhoc")
		    && (priv->mode != IW_MODE_ADHOC))
			return FALSE;
	}

	if (s_wireless->band) {
		if (!strcmp (s_wireless->band, "a")) {
			if (priv->freq < 5170 || priv->freq > 5825)
				return FALSE;
		} else if (!strcmp (s_wireless->band, "bg")) {
			if (priv->freq < 2412 || priv->freq > 2472)
				return FALSE;
		}
	}

	if (s_wireless->channel) {
		guint32 ap_chan = freq_to_channel (priv->freq);

		if (s_wireless->channel != ap_chan)
			return FALSE;
	}

	return security_compatible (self, connection, s_wireless);
}


struct cf_pair {
	guint32 chan;
	guint32 freq;
};

static struct cf_pair cf_table[46] = {
	/* B/G band */
	{ 1, 2412 },
	{ 2, 2417 },
	{ 3, 2422 },
	{ 4, 2427 },
	{ 5, 2432 },
	{ 6, 2437 },
	{ 7, 2442 },
	{ 8, 2447 },
	{ 9, 2452 },
	{ 10, 2457 },
	{ 11, 2462 },
	{ 12, 2467 },
	{ 13, 2472 },
	/* A band */
	{ 34, 5170 },
	{ 36, 5180 },
	{ 38, 5190 },
	{ 40, 5200 },
	{ 42, 5210 },
	{ 44, 5220 },
	{ 46, 5230 },
	{ 48, 5240 },
	{ 50, 5250 },
	{ 52, 5260 },
	{ 56, 5280 },
	{ 58, 5290 },
	{ 60, 5300 },
	{ 64, 5320 },
	{ 100, 5500 },
	{ 104, 5520 },
	{ 108, 5540 },
	{ 112, 5560 },
	{ 116, 5580 },
	{ 120, 5600 },
	{ 124, 5620 },
	{ 128, 5640 },
	{ 132, 5660 },
	{ 136, 5680 },
	{ 140, 5700 },
	{ 149, 5745 },
	{ 152, 5760 },
	{ 153, 5765 },
	{ 157, 5785 },
	{ 160, 5800 },
	{ 161, 5805 },
	{ 165, 5825 },
	{ 0, -1 }
};

guint32
freq_to_channel (guint32 freq)
{
	int i = 0;

	while (cf_table[i].chan && (cf_table[i].freq != freq))
		i++;
	return cf_table[i].chan;
}

guint32
channel_to_freq (guint32 channel)
{
	int i = 0;

	while (cf_table[i].chan && (cf_table[i].chan != channel))
		i++;
	return cf_table[i].freq;
}

