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
#include "NetworkManagerWireless.h"
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
	struct ether_addr *	address;
	int				mode;		/* from IW_MODE_* in wireless.h */
	gint8			strength;
	double			freq;
	guint16			rate;
	guint32			capabilities;

	/* Non-scanned attributes */
	gboolean			invalid;
	gboolean			matched;		/* used in ap list diffing */
	gboolean			artificial;	/* Whether or not the AP is from a scan */
	gboolean			user_created;	/* Whether or not the AP was created by the user with "Create network..." */
	GTimeVal			last_seen;	/* Last time the AP was seen in a scan */

	/* Things from user prefs/NetworkManagerInfo */
	gboolean			trusted;
	NMAPSecurity *		security;
	GTimeVal			timestamp;
	GSList *			user_addresses;

	/* Soon to be banished */
	char *			enc_key;
	NMEncKeyType		enc_type;
	int				auth_method; /* from wireless.h; -1 is unknown, zero is none */
};

/* This is a controlled list.  Want to add to it?  Stop.  Ask first. */
static char* default_essid_list[] =
{
	"linksys",
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
	
	ap = g_new0 (NMAccessPoint, 1);
	if (!ap)
	{
		nm_warning ("nm_ap_new() could not allocate a new user access point info structure.  Not enough memory?");
		return (NULL);
	}

	ap->mode = IW_MODE_INFRA;
	ap->auth_method = -1;
	ap->refcount = 1;

	return (ap);
}


/*
 * nm_ap_new_from_ap
 *
 * Create a new user access point info structure, duplicating an existing one
 *
 */
NMAccessPoint * nm_ap_new_from_ap (NMAccessPoint *src_ap)
{
	NMAccessPoint		*new_ap;
	struct ether_addr	*new_addr;

	g_return_val_if_fail (src_ap != NULL, NULL);

	new_addr = g_new0 (struct ether_addr, 1);
	g_return_val_if_fail (new_addr != NULL, NULL);

	new_ap = nm_ap_new();
	if (!new_ap)
	{
		nm_warning ("nm_ap_new_from_uap() could not allocate a new user access point structure.  Not enough memory?");
		return (NULL);
	}

	if (src_ap->essid && (strlen (src_ap->essid) > 0))
		new_ap->essid = g_strdup (src_ap->essid);
	if (src_ap->address)
	{
		memcpy (new_addr, src_ap->address, sizeof (struct ether_addr));
		new_ap->address = new_addr;
	}
	new_ap->mode = src_ap->mode;
	new_ap->strength = src_ap->strength;
	new_ap->freq = src_ap->freq;
	new_ap->rate = src_ap->rate;
	new_ap->capabilities = src_ap->capabilities;

	if (src_ap->enc_key && (strlen (src_ap->enc_key) > 0))
		new_ap->enc_key = g_strdup (src_ap->enc_key);

	return (new_ap);
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

	ap->refcount--;
	if (ap->refcount == 0)
	{
		g_free (ap->essid);
		g_free (ap->address);
		g_free (ap->enc_key);
		g_slist_foreach (ap->user_addresses, (GFunc)g_free, NULL);
		g_slist_free (ap->user_addresses);

		if (ap->security)
			g_object_unref (G_OBJECT (ap->security));

		ap->essid = NULL;
		ap->enc_key = NULL;

		g_free (ap);
		memset (ap, 0, sizeof (NMAccessPoint));
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

void nm_ap_set_timestamp (NMAccessPoint *ap, const GTimeVal *timestamp)
{
	g_return_if_fail (ap != NULL);

	ap->timestamp = *timestamp;
}


/*
 * Get/set functions for essid
 *
 */
char * nm_ap_get_essid (const NMAccessPoint *ap)
{
	g_assert (ap);
	g_return_val_if_fail (ap != NULL, NULL);

	return (ap->essid);
}

void nm_ap_set_essid (NMAccessPoint *ap, const char * essid)
{
	g_return_if_fail (ap != NULL);

	if (ap->essid)
	{
		g_free (ap->essid);
		ap->essid = NULL;
	}

	if (essid)
		ap->essid = g_strdup (essid);
}


/*
 * Get/set functions for encrypted flag
 *
 */
gboolean nm_ap_get_encrypted (const NMAccessPoint *ap)
{
	g_return_val_if_fail (ap != NULL, FALSE);

	return (ap->capabilities & NM_802_11_CAP_PROTO_WEP);
}

void nm_ap_set_encrypted (NMAccessPoint *ap, gboolean privacy)
{
	g_return_if_fail (ap != NULL);

	if (privacy)
		ap->capabilities |= NM_802_11_CAP_PROTO_WEP;
	else
		ap->capabilities &= ~NM_802_11_CAP_PROTO_WEP;
}


/*
 * Return the encryption method the user specified for this access point.
 *
 */
NMEncKeyType nm_ap_get_enc_type (const NMAccessPoint *ap)
{
	g_return_val_if_fail (ap != NULL, TRUE);

	return (ap->enc_type);
}


/*
 * Get/set functions for auth_method
 *
 */
int nm_ap_get_auth_method (const NMAccessPoint *ap)
{
	g_return_val_if_fail (ap != NULL, -1);

	return (ap->auth_method);
}

void nm_ap_set_auth_method (NMAccessPoint *ap, int auth_method)
{
	g_return_if_fail (ap != NULL);

	ap->auth_method = auth_method;
}


/*
 * Accessorts for AP security info
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
	{
		g_object_ref (G_OBJECT (security));
		ap->security = security;
	}
}


/*
 * Get/set functions for address
 *
 */
const struct ether_addr * nm_ap_get_address (const NMAccessPoint *ap)
{
	g_return_val_if_fail (ap != NULL, NULL);

	return (ap->address);
}

void nm_ap_set_address (NMAccessPoint *ap, const struct ether_addr * addr)
{
	struct ether_addr *new_addr;

	g_return_if_fail (ap != NULL);

	new_addr = g_new0 (struct ether_addr, 1);
	g_return_if_fail (new_addr != NULL);

	if (ap->address)
		g_free (ap->address);

	memcpy (new_addr, addr, sizeof (struct ether_addr));
	ap->address = new_addr;
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
 * Get/set functions for "matched", which is used by
 * the ap list diffing functions to speed up the diff
 *
 */
gboolean nm_ap_get_matched (const NMAccessPoint *ap)
{
	g_return_val_if_fail (ap != NULL, TRUE);

	return (ap->matched);
}

void nm_ap_set_matched (NMAccessPoint *ap, gboolean matched)
{
	g_return_if_fail (ap != NULL);

	ap->matched = matched;
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
	int i;

	g_return_val_if_fail (ap != NULL, FALSE);

	for (i = 0; default_essid_list[i] != NULL; i++)
	{
		char *essid = default_essid_list[i];
		if (strcmp (essid, ap->essid) == 0)
			return TRUE;
	}

	return FALSE;
}


static void set_capabilities_from_cipher (NMAccessPoint *ap, int cipher)
{
	if (cipher & IW_AUTH_CIPHER_WEP40)
		ap->capabilities |= NM_802_11_CAP_CIPHER_WEP40;
	if (cipher & IW_AUTH_CIPHER_WEP104)
		ap->capabilities |= NM_802_11_CAP_CIPHER_WEP104;
	if (cipher & IW_AUTH_CIPHER_TKIP)
		ap->capabilities |= NM_802_11_CAP_CIPHER_TKIP;
	if (cipher & IW_AUTH_CIPHER_CCMP)
		ap->capabilities |= NM_802_11_CAP_CIPHER_CCMP;
}

void nm_ap_set_capabilities_from_wpa_ie (NMAccessPoint *ap, const guint8 *wpa_ie, guint32 length)
{
	wpa_ie_data *	cap_data;

	g_return_if_fail (ap != NULL);

	if (!(cap_data = wpa_parse_wpa_ie (wpa_ie, length)))
		return;

	ap->capabilities = NM_802_11_CAP_NONE;

	if (cap_data->proto & IW_AUTH_WPA_VERSION_WPA)
		ap->capabilities |= NM_802_11_CAP_PROTO_WPA;
	if (cap_data->proto & IW_AUTH_WPA_VERSION_WPA2)
		ap->capabilities |= NM_802_11_CAP_PROTO_WPA2;

	set_capabilities_from_cipher (ap, cap_data->pairwise_cipher);
	set_capabilities_from_cipher (ap, cap_data->group_cipher);

	if (cap_data->key_mgmt & IW_AUTH_KEY_MGMT_802_1X)
		ap->capabilities |= NM_802_11_CAP_KEY_MGMT_802_1X;
	if (cap_data->key_mgmt & IW_AUTH_KEY_MGMT_PSK)
		ap->capabilities |= NM_802_11_CAP_KEY_MGMT_PSK;
}


