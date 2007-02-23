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
#include <wireless.h>


/*
 * Encapsulates Access Point information
 */
struct NMAccessPoint
{
	guint			refcount;

	/* Scanned or cached values */
	char *			essid;
	char *			orig_essid;
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
	GTimeVal			last_seen;	/* Last time the AP was seen in a scan */

	/* Things from user prefs/NetworkManagerInfo */
	gboolean			trusted;
	NMAPSecurity *		security;
	GTimeVal			timestamp;
	GSList *			user_addresses;
};

/* This is a controlled list.  Want to add to it?  Stop.  Ask first. */
static const char * default_essid_list[] =
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
 * nm_ap_new
 *
 * Create a new, blank user access point info structure
 *
 */
NMAccessPoint * nm_ap_new (void)
{
	NMAccessPoint	*ap;
	
	ap = g_malloc0 (sizeof (NMAccessPoint));
	ap->mode = IW_MODE_INFRA;
	ap->refcount = 1;
	ap->capabilities = NM_802_11_CAP_PROTO_NONE;
	ap->broadcast = TRUE;

	return ap;
}


/*
 * nm_ap_new_from_ap
 *
 * Create a new user access point info structure, duplicating an existing one
 *
 */
NMAccessPoint * nm_ap_new_from_ap (NMAccessPoint *src_ap)
{
	NMAccessPoint *	new_ap;

	g_return_val_if_fail (src_ap != NULL, NULL);

	if (!(new_ap = nm_ap_new()))
	{
		nm_warning ("nm_ap_new_from_uap() could not allocate a new user access point structure.  Not enough memory?");
		return (NULL);
	}

	if (src_ap->essid && (strlen (src_ap->essid) > 0))
	{
		new_ap->essid = g_strdup (src_ap->essid);
		new_ap->orig_essid = g_strdup (src_ap->orig_essid);
	}
	memcpy (&new_ap->address, &src_ap->address, sizeof (struct ether_addr));
	new_ap->mode = src_ap->mode;
	new_ap->strength = src_ap->strength;
	new_ap->freq = src_ap->freq;
	new_ap->rate = src_ap->rate;
	new_ap->capabilities = src_ap->capabilities;
	new_ap->artificial = src_ap->artificial;
	new_ap->broadcast = src_ap->broadcast;

	if (src_ap->security)
		new_ap->security = nm_ap_security_new_copy (src_ap->security);

	return new_ap;
}


/*
 * AP refcounting functions
 */
void nm_ap_ref (NMAccessPoint *ap)
{
	g_return_if_fail (ap != NULL);

	ap->refcount++;
}

void nm_ap_unref (NMAccessPoint *ap)
{
	g_return_if_fail (ap != NULL);
	g_return_if_fail (ap->refcount > 0);

	ap->refcount--;
	if (ap->refcount == 0)
	{
		g_free (ap->essid);
		g_free (ap->orig_essid);
		g_slist_foreach (ap->user_addresses, (GFunc)g_free, NULL);
		g_slist_free (ap->user_addresses);

		if (ap->security)
			g_object_unref (G_OBJECT (ap->security));

		memset (ap, 0, sizeof (NMAccessPoint));
		g_free (ap);
	}
}


/*
 * Get/set functions for timestamp
 *
 */
const GTimeVal *nm_ap_get_timestamp (const NMAccessPoint *ap)
{
	g_return_val_if_fail (ap != NULL, 0);

	return (&ap->timestamp);
}

void nm_ap_set_timestamp (NMAccessPoint *ap, glong sec, glong usec)
{
	g_return_if_fail (ap != NULL);

	ap->timestamp.tv_sec = sec;
	ap->timestamp.tv_usec = usec;
}

void nm_ap_set_timestamp_via_timestamp (NMAccessPoint *ap, const GTimeVal *timestamp)
{
	g_return_if_fail (ap != NULL);

	ap->timestamp = *timestamp;
}

/*
 * Get/set functions for essid
 *
 */
const char * nm_ap_get_essid (const NMAccessPoint *ap)
{
	g_return_val_if_fail (ap != NULL, NULL);

	return ap->essid;
}

const char * nm_ap_get_orig_essid (const NMAccessPoint *ap)
{
	g_return_val_if_fail (ap != NULL, NULL);

	return ap->orig_essid;
}

void nm_ap_set_essid (NMAccessPoint *ap, const char * essid)
{
	g_return_if_fail (ap != NULL);

	if (ap->essid)
	{
		g_free (ap->essid);
		g_free (ap->orig_essid);
		ap->essid = NULL;
		ap->orig_essid = NULL;
	}

	if (essid)
	{
		ap->orig_essid = g_strdup (essid);
		ap->essid = nm_utils_essid_to_utf8 (essid);
	}
}


guint32 nm_ap_get_capabilities (NMAccessPoint *ap)
{
	g_return_val_if_fail (ap != NULL, NM_802_11_CAP_NONE);

	return ap->capabilities;
}


void nm_ap_set_capabilities (NMAccessPoint *ap, guint32 capabilities)
{
	g_return_if_fail (ap != NULL);

	ap->capabilities = capabilities;
}


/*
 * Accessor function for encrypted flag
 *
 */
gboolean nm_ap_get_encrypted (const NMAccessPoint *ap)
{
	g_return_val_if_fail (ap != NULL, FALSE);

	return (!(ap->capabilities & NM_802_11_CAP_PROTO_NONE));
}


/*
 * Accessors for AP security info
 *
 */
NMAPSecurity * nm_ap_get_security (const NMAccessPoint *ap)
{
	g_return_val_if_fail (ap != NULL, NULL);

	return ap->security;
}

void nm_ap_set_security (NMAccessPoint *ap, NMAPSecurity *security)
{
	g_return_if_fail (ap != NULL);

	if (ap->security)
	{
		g_object_unref (G_OBJECT (ap->security));
		ap->security = NULL;
	}

	if (security)
		ap->security = nm_ap_security_new_copy (security);
}


/*
 * Get/set functions for address
 *
 */
const struct ether_addr * nm_ap_get_address (const NMAccessPoint *ap)
{
	g_return_val_if_fail (ap != NULL, NULL);

	return &ap->address;
}

void nm_ap_set_address (NMAccessPoint *ap, const struct ether_addr * addr)
{
	g_return_if_fail (ap != NULL);
	g_return_if_fail (addr != NULL);

	memcpy (&ap->address, addr, sizeof (struct ether_addr));
}


/*
 * Get/set functions for mode (ie Ad-Hoc, Infrastructure, etc)
 *
 */
int nm_ap_get_mode (const NMAccessPoint *ap)
{
	g_return_val_if_fail (ap != NULL, -1);

	return ap->mode;
}

void nm_ap_set_mode (NMAccessPoint *ap, const int mode)
{
	g_return_if_fail (ap != NULL);
	g_return_if_fail ((mode == IW_MODE_ADHOC) || (mode == IW_MODE_INFRA));

	ap->mode = mode;
}


/*
 * Get/set functions for strength
 *
 */
gint8 nm_ap_get_strength (const NMAccessPoint *ap)
{
	g_return_val_if_fail (ap != NULL, 0);

	return (ap->strength);
}

void  nm_ap_set_strength (NMAccessPoint *ap, const gint8 strength)
{
	g_return_if_fail (ap != NULL);

	ap->strength = strength;
}


/*
 * Get/set functions for frequency
 *
 */
double nm_ap_get_freq (const NMAccessPoint *ap)
{
	g_return_val_if_fail (ap != NULL, 0);

	return (ap->freq);
}

void nm_ap_set_freq (NMAccessPoint *ap, const double freq)
{
	g_return_if_fail (ap != NULL);

	ap->freq = freq;
}


/*
 * Get/set functions for rate
 *
 */
guint16 nm_ap_get_rate (const NMAccessPoint *ap)
{
	g_return_val_if_fail (ap != NULL, 0);

	return (ap->rate);
}

void nm_ap_set_rate (NMAccessPoint *ap, guint16 rate)
{
	g_return_if_fail (ap != NULL);

	ap->rate = rate;
}


/*
 * Get/set functions for "invalid" access points, ie ones
 * for which a user explicitly does not wish to connect to
 * (by cancelling requests for WEP key, for example)
 *
 */
gboolean nm_ap_get_invalid (const NMAccessPoint *ap)
{
	g_return_val_if_fail (ap != NULL, TRUE);

	return (ap->invalid);
}

void nm_ap_set_invalid (NMAccessPoint *ap, gboolean invalid)
{
	g_return_if_fail (ap != NULL);

	ap->invalid = invalid;
}


/*
 * Get/Set functions to indicate that an access point is
 * 'trusted'
 *
 */
gboolean nm_ap_get_trusted (const NMAccessPoint *ap)
{
	g_return_val_if_fail (ap != NULL, FALSE);

	return (ap->trusted);
}

void nm_ap_set_trusted (NMAccessPoint *ap, gboolean trusted)
{
	g_return_if_fail (ap != NULL);

	ap->trusted = trusted;
}


/*
 * Get/Set functions to indicate that an access point is
 * 'artificial', ie whether or not it was actually scanned
 * by the card or not
 *
 */
gboolean nm_ap_get_artificial (const NMAccessPoint *ap)
{
	g_return_val_if_fail (ap != NULL, FALSE);

	return (ap->artificial);
}

void nm_ap_set_artificial (NMAccessPoint *ap, gboolean artificial)
{
	g_return_if_fail (ap != NULL);

	ap->artificial = artificial;
}


/*
 * Get/Set functions to indicate whether an access point is broadcasting
 * (hidden).  This is a superset of artificial.
 */
gboolean nm_ap_get_broadcast (const NMAccessPoint *ap)
{
	g_return_val_if_fail (ap != NULL, TRUE);
	return ap->broadcast;
}


void nm_ap_set_broadcast (NMAccessPoint *ap, gboolean broadcast)
{
	g_return_if_fail (ap != NULL);
	ap->broadcast = broadcast;
}


/*
 * Get/Set functions for how long ago the AP was last seen in a scan.
 * APs older than a certain date are dropped from the list.
 *
 */
const GTimeVal *nm_ap_get_last_seen (const NMAccessPoint *ap)
{
	g_return_val_if_fail (ap != NULL, FALSE);

	return (&ap->last_seen);
}

void nm_ap_set_last_seen (NMAccessPoint *ap, const GTimeVal *last_seen)
{
	g_return_if_fail (ap != NULL);

	ap->last_seen = *last_seen;
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
	g_return_val_if_fail (ap != NULL, FALSE);

	return (ap->user_created);
}

void nm_ap_set_user_created (NMAccessPoint *ap, gboolean user_created)
{
	g_return_if_fail (ap != NULL);

	ap->user_created = user_created;
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

	g_return_val_if_fail (ap != NULL, NULL);

	for (elt = ap->user_addresses; elt; elt = g_slist_next (elt))
	{
		if (elt->data)
			new = g_slist_append (new, g_strdup (elt->data));
	}

	/* Return a _deep__copy_ of the address list */
	return (new);
}

void nm_ap_set_user_addresses (NMAccessPoint *ap, GSList *list)
{
	GSList	*elt = NULL;
	GSList	*new = NULL;

	g_return_if_fail (ap != NULL);

	/* Free existing list */
	g_slist_foreach (ap->user_addresses, (GFunc) g_free, NULL);
	g_slist_free (ap->user_addresses);

	/* Copy new list and set as our own */
	for (elt = list; elt; elt = g_slist_next (elt))
	{
		if (elt->data)
			new = g_slist_append (new, g_strdup (elt->data));
	}

	ap->user_addresses = new;
}


gboolean nm_ap_has_manufacturer_default_essid (NMAccessPoint *ap)
{
	const char **default_essid = default_essid_list;
	const char *this_essid;

	g_return_val_if_fail (ap != NULL, FALSE);
	this_essid = ap->essid;

	while (*default_essid)
	{
		if (!strcmp (*(default_essid++), this_essid))
			return TRUE;
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

	g_return_if_fail (ap != NULL);
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

	g_return_if_fail (ap != NULL);

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

	g_free (cap_data);

	nm_ap_set_capabilities (ap, caps);
}


void nm_ap_add_capabilities_for_wep (NMAccessPoint *ap)
{
	g_return_if_fail (ap != NULL);

	ap->capabilities |= (NM_802_11_CAP_PROTO_WEP | NM_802_11_CAP_CIPHER_WEP40 | NM_802_11_CAP_CIPHER_WEP104);
	ap->capabilities &= ~NM_802_11_CAP_PROTO_NONE;
}
