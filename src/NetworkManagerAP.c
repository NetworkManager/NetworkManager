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
#include "nm-ap-security.h"
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
	double			freq;
	guint16			rate;
	guint32			capabilities;

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
	gboolean			fallback;
	NMAPSecurity *		security;
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
	PROP_CAPABILITIES,
	PROP_ENCRYPTED,
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
	priv->capabilities = NM_802_11_CAP_PROTO_NONE;
	priv->broadcast = TRUE;
}

static void
finalize (GObject *object)
{
	NMAccessPointPrivate *priv = NM_AP_GET_PRIVATE (object);

	g_free (priv->dbus_path);
	g_byte_array_free (priv->ssid, TRUE);
	g_slist_foreach (priv->user_addresses, (GFunc)g_free, NULL);
	g_slist_free (priv->user_addresses);

	if (priv->security)
		g_object_unref (G_OBJECT (priv->security));

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
	case PROP_CAPABILITIES:
		priv->capabilities = g_value_get_uint (value);
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
		priv->freq = g_value_get_double (value);
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
		nm_ap_set_strength (NM_AP (object), g_value_get_int (value));
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
	int i;

	switch (prop_id) {
	case PROP_CAPABILITIES:
		g_value_set_uint (value, priv->capabilities);
		break;
	case PROP_ENCRYPTED:
		g_value_set_boolean (value, !(priv->capabilities & NM_802_11_CAP_PROTO_NONE));
		break;
	case PROP_SSID:
		ssid = g_array_sized_new (FALSE, TRUE, sizeof (unsigned char), priv->ssid->len);
		for (i = 0; i < priv->ssid->len; i++)
			g_array_append_val (ssid, priv->ssid->data[i]);
		g_value_set_boxed (value, ssid);
		g_array_free (ssid, TRUE);
		break;
	case PROP_FREQUENCY:
		g_value_set_double (value, priv->freq);
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
		g_value_set_int (value, priv->strength);
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
	guint32 all_caps;

	g_type_class_add_private (ap_class, sizeof (NMAccessPointPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize = finalize;

	/* properties */

	all_caps =   NM_802_11_CAP_NONE
	           | NM_802_11_CAP_PROTO_NONE
	           | NM_802_11_CAP_PROTO_WEP
	           | NM_802_11_CAP_PROTO_WPA
	           | NM_802_11_CAP_PROTO_WPA2
	           | NM_802_11_CAP_RESERVED1
	           | NM_802_11_CAP_RESERVED2
	           | NM_802_11_CAP_KEY_MGMT_PSK
	           | NM_802_11_CAP_KEY_MGMT_802_1X
	           | NM_802_11_CAP_RESERVED3
	           | NM_802_11_CAP_RESERVED4
	           | NM_802_11_CAP_RESERVED5
	           | NM_802_11_CAP_RESERVED6
	           | NM_802_11_CAP_CIPHER_WEP40
	           | NM_802_11_CAP_CIPHER_WEP104
	           | NM_802_11_CAP_CIPHER_TKIP
	           | NM_802_11_CAP_CIPHER_CCMP;

	g_object_class_install_property
		(object_class, PROP_CAPABILITIES,
		 g_param_spec_uint (NM_AP_CAPABILITIES,
							"Capabilities",
							"Capabilities",
							NM_802_11_CAP_NONE, all_caps, NM_802_11_CAP_PROTO_NONE,
							G_PARAM_READWRITE));

	g_object_class_install_property
		(object_class, PROP_ENCRYPTED,
		 g_param_spec_boolean (NM_AP_ENCRYPTED,
							   "Encrypted",
							   "Is encrypted",
							   FALSE,
							   G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_SSID,
	     g_param_spec_boxed (NM_AP_SSID,
	                         "SSID",
	                         "SSID",
	                         DBUS_TYPE_G_UCHAR_ARRAY,
	                         G_PARAM_READWRITE));

	g_object_class_install_property
		(object_class, PROP_FREQUENCY,
		 g_param_spec_double (NM_AP_FREQUENCY,
							  "Frequency",
							  "Frequency",
							  0.0, 10000.0, 0.0, /* FIXME */
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
		 g_param_spec_int (NM_AP_STRENGTH,
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
	new_priv->capabilities = src_priv->capabilities;
	new_priv->artificial = src_priv->artificial;
	new_priv->broadcast = src_priv->broadcast;

	if (src_priv->security)
		new_priv->security = nm_ap_security_new_copy (src_priv->security);

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
			g_byte_array_append (ssid, array->data, len);
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
			if (array->len <= 0 || array->len > WPA_MAX_IE_LEN)
				return;
			nm_ap_add_capabilities_from_ie (ap, ie, array->len);
		} else if (!strcmp (key, "rsnie")) {
			guint8 * ie = (guint8 *) array->data;
			if (array->len <= 0 || array->len > WPA_MAX_IE_LEN)
				return;
			nm_ap_add_capabilities_from_ie (ap, ie, array->len);
		}
	} else if (G_VALUE_HOLDS_INT (variant)) {
		gint32 int_val = g_value_get_int (variant);

		if (!strcmp (key, "frequency")) {
			double freq = (double) int_val;
			nm_ap_set_freq (ap, freq);
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
				guint cur_caps;

				cur_caps = nm_ap_get_capabilities (ap);
				if (cur_caps == NM_802_11_CAP_NONE || cur_caps & NM_802_11_CAP_PROTO_NONE)
					nm_ap_add_capabilities_for_wep (ap);
			}
		}
	}
}


NMAccessPoint *
nm_ap_new_from_properties (GHashTable *properties)
{
	NMAccessPoint *ap;
	GTimeVal cur_time;

	g_return_val_if_fail (properties != NULL, NULL);

	ap = nm_ap_new ();

	g_hash_table_foreach (properties, foreach_property_cb, ap);

	g_get_current_time (&cur_time);
	nm_ap_set_last_seen (ap, cur_time.tv_sec);

	if (!nm_ap_get_ssid (ap))
		nm_ap_set_broadcast (ap, FALSE);

	return ap;
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


guint32 nm_ap_get_capabilities (NMAccessPoint *ap)
{
	guint32 caps;

	g_return_val_if_fail (NM_IS_AP (ap), NM_802_11_CAP_NONE);

	g_object_get (ap, NM_AP_CAPABILITIES, &caps, NULL);

	return caps;
}


void nm_ap_set_capabilities (NMAccessPoint *ap, guint32 capabilities)
{
	g_return_if_fail (NM_IS_AP (ap));

	g_object_set (ap, NM_AP_CAPABILITIES, capabilities, NULL);
}


/*
 * Accessor function for encrypted flag
 *
 */
gboolean nm_ap_get_encrypted (NMAccessPoint *ap)
{
	gboolean encrypted;

	g_return_val_if_fail (NM_IS_AP (ap), FALSE);

	g_object_get (ap, NM_AP_ENCRYPTED, &encrypted, NULL);

	return encrypted;
}


/*
 * Accessors for AP security info
 *
 */
NMAPSecurity * nm_ap_get_security (const NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_AP (ap), NULL);

	return NM_AP_GET_PRIVATE (ap)->security;
}

void nm_ap_set_security (NMAccessPoint *ap, NMAPSecurity *security)
{
	NMAccessPointPrivate *priv;

	g_return_if_fail (NM_IS_AP (ap));

	priv = NM_AP_GET_PRIVATE (ap);

	if (priv->security)
	{
		g_object_unref (G_OBJECT (priv->security));
		priv->security = NULL;
	}

	if (security)
		priv->security = nm_ap_security_new_copy (security);
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
double nm_ap_get_freq (NMAccessPoint *ap)
{
	double freq;

	g_return_val_if_fail (NM_IS_AP (ap), 0);

	g_object_get (ap, NM_AP_FREQUENCY, &freq, NULL);

	return freq;
}

void nm_ap_set_freq (NMAccessPoint *ap, const double freq)
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
 * 'fallback'
 *
 */
gboolean nm_ap_get_fallback (const NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_AP (ap), FALSE);

	return NM_AP_GET_PRIVATE (ap)->fallback;
}

void nm_ap_set_fallback (NMAccessPoint *ap, gboolean fallback)
{
	g_return_if_fail (NM_IS_AP (ap));

	NM_AP_GET_PRIVATE (ap)->fallback = fallback;
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
			new = g_slist_append (new, g_strdup (elt->data));
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


static guint32 add_capabilities_from_cipher (guint32 caps, int cipher)
{
	if (cipher & IW_AUTH_CIPHER_WEP40)
	{
		caps |= NM_802_11_CAP_PROTO_WEP;
		caps |= NM_802_11_CAP_CIPHER_WEP40;
		caps &= ~NM_802_11_CAP_PROTO_NONE;
	}
	if (cipher & IW_AUTH_CIPHER_WEP104)
	{
		caps |= NM_802_11_CAP_PROTO_WEP;
		caps |= NM_802_11_CAP_CIPHER_WEP104;
		caps &= ~NM_802_11_CAP_PROTO_NONE;
	}
	if (cipher & IW_AUTH_CIPHER_TKIP)
	{
		caps |= NM_802_11_CAP_CIPHER_TKIP;
		caps &= ~NM_802_11_CAP_PROTO_NONE;
	}
	if (cipher & IW_AUTH_CIPHER_CCMP)
	{
		caps |= NM_802_11_CAP_CIPHER_CCMP;
		caps &= ~NM_802_11_CAP_PROTO_NONE;
	}

	if (cipher == NM_AUTH_TYPE_WPA_PSK_AUTO)
	{
		caps &= ~NM_802_11_CAP_PROTO_NONE;
	}

	if (cipher == NM_AUTH_TYPE_WPA_EAP)
	{
		caps |= NM_802_11_CAP_KEY_MGMT_802_1X;
		caps &= ~NM_802_11_CAP_PROTO_NONE;
	}
	if (cipher == NM_AUTH_TYPE_LEAP)
	{
		caps &= ~NM_802_11_CAP_PROTO_NONE;
	}
	return caps;
}

/*
 * nm_ap_add_capabilities_from_cipher
 *
 * Update a given AP's capabilities via a wireless extension cipher integer
 *
 */
void nm_ap_add_capabilities_from_security (NMAccessPoint *ap, NMAPSecurity *security)
{
	guint32 caps;
	int cipher;

	g_return_if_fail (NM_IS_AP (ap));
	g_return_if_fail (security != NULL);

	cipher = nm_ap_security_get_we_cipher (security);
	caps = nm_ap_get_capabilities (ap);
	caps = add_capabilities_from_cipher (caps, cipher);
	nm_ap_set_capabilities (ap, caps);
}

void nm_ap_add_capabilities_from_ie (NMAccessPoint *ap, const guint8 *wpa_ie, guint32 length)
{
	wpa_ie_data *	cap_data;
	guint32		caps;

	g_return_if_fail (NM_IS_AP (ap));

	if (!(cap_data = wpa_parse_wpa_ie (wpa_ie, length)))
		return;

	caps = nm_ap_get_capabilities (ap);

	/* Mark WEP as unsupported, if it's supported it will be added below */
	caps &= ~NM_802_11_CAP_PROTO_WEP;

	if (cap_data->proto & IW_AUTH_WPA_VERSION_WPA)
	{
		caps |= NM_802_11_CAP_PROTO_WPA;
		caps &= ~NM_802_11_CAP_PROTO_NONE;
	}
	if (cap_data->proto & IW_AUTH_WPA_VERSION_WPA2)
	{
		caps |= NM_802_11_CAP_PROTO_WPA2;
		caps &= ~NM_802_11_CAP_PROTO_NONE;
	}

	caps = add_capabilities_from_cipher (caps, cap_data->pairwise_cipher);
	caps = add_capabilities_from_cipher (caps, cap_data->group_cipher);

	if (cap_data->key_mgmt & IW_AUTH_KEY_MGMT_802_1X)
		caps |= NM_802_11_CAP_KEY_MGMT_802_1X;
	if (cap_data->key_mgmt & IW_AUTH_KEY_MGMT_PSK)
		caps |= NM_802_11_CAP_KEY_MGMT_PSK;

	nm_ap_set_capabilities (ap, caps);

	g_slice_free (wpa_ie_data, cap_data);
}


void nm_ap_add_capabilities_for_wep (NMAccessPoint *ap)
{
	NMAccessPointPrivate *priv;

	g_return_if_fail (NM_IS_AP (ap));

	priv = NM_AP_GET_PRIVATE (ap);

	priv->capabilities |= (NM_802_11_CAP_PROTO_WEP | NM_802_11_CAP_CIPHER_WEP40 | NM_802_11_CAP_CIPHER_WEP104);
	priv->capabilities &= ~NM_802_11_CAP_PROTO_NONE;
}
