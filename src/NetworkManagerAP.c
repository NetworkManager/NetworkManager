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
#include "NetworkManagerWireless.h"


/*
 * Encapsulates Access Point information
 */
struct NMAccessPoint
{
	guint			 refcount;
	char				*essid;
	struct ether_addr	*address;
	NMNetworkMode		 mode;
	gint8			 strength;
	double			 freq;
	guint16			 rate;
	gboolean			 encrypted;

	/* Non-scanned attributes */
	gboolean			 invalid;
	gboolean			 matched;	/* used in ap list diffing */
	gboolean			 artificial; /* Whether or not the AP is from a scan */
	gboolean			 user_created; /* Whether or not the AP was created by the user with "Create network..." */
	GTimeVal			 last_seen; /* Last time the AP was seen in a scan */

	/* Things from user prefs/NetworkManagerInfo */
	gboolean			 trusted;
	char				*enc_key;
	NMEncKeyType		 enc_type;
	NMDeviceAuthMethod	 auth_method;
	GTimeVal			 timestamp;
	GSList			*user_addresses;
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
		syslog (LOG_ERR, "nm_ap_new() could not allocate a new user access point info structure.  Not enough memory?");
		return (NULL);
	}

	ap->mode = NETWORK_MODE_INFRA;
	ap->auth_method = NM_DEVICE_AUTH_METHOD_UNKNOWN;
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
		syslog (LOG_ERR, "nm_ap_new_from_uap() could not allocate a new user access point structure.  Not enough memory?");
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
	new_ap->encrypted = src_ap->encrypted;

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

		ap->essid = NULL;
		ap->enc_key = NULL;

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
 * Get/set functions for encryption key
 *
 */
char * nm_ap_get_enc_key_source (const NMAccessPoint *ap)
{
	g_return_val_if_fail (ap != NULL, NULL);

	return (ap->enc_key);
}

void nm_ap_set_enc_key_source (NMAccessPoint *ap, const char * key, NMEncKeyType type)
{
	g_return_if_fail (ap != NULL);

	if (ap->enc_key)
		g_free (ap->enc_key);

	ap->enc_key = g_strdup (key);
	ap->enc_type = type;
}

char *nm_ap_get_enc_key_hashed (const NMAccessPoint *ap)
{
	char	*hashed = NULL;
	char	*source_key;

	g_return_val_if_fail (ap != NULL, NULL);

	source_key = nm_ap_get_enc_key_source (ap);
	switch (ap->enc_type)
	{
		case (NM_ENC_TYPE_128_BIT_PASSPHRASE):
			if (source_key)
				hashed = nm_wireless_128bit_key_from_passphrase (source_key);
			break;
		case (NM_ENC_TYPE_ASCII_KEY):
			if (source_key){
				if(strlen(source_key)<=5)
					hashed = nm_wireless_64bit_ascii_to_hex (source_key);
				else
					hashed = nm_wireless_128bit_ascii_to_hex (source_key);
			}
			break;
		case (NM_ENC_TYPE_HEX_KEY):
		case (NM_ENC_TYPE_UNKNOWN):
			if (source_key)
				hashed = g_strdup (source_key);
			break;

		default:
			break;
	}

	return (hashed);
}


/*
 * Get/set functions for encrypted flag
 *
 */
gboolean nm_ap_get_encrypted (const NMAccessPoint *ap)
{
	g_return_val_if_fail (ap != NULL, FALSE);

	return (ap->encrypted);
}

void nm_ap_set_encrypted (NMAccessPoint *ap, gboolean encrypted)
{
	g_return_if_fail (ap != NULL);

	ap->encrypted = encrypted;
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
NMDeviceAuthMethod nm_ap_get_auth_method (const NMAccessPoint *ap)
{
	g_return_val_if_fail (ap != NULL, NM_DEVICE_AUTH_METHOD_UNKNOWN);

	return (ap->auth_method);
}

void nm_ap_set_auth_method (NMAccessPoint *ap, NMDeviceAuthMethod auth_method)
{
	g_return_if_fail (ap != NULL);

	ap->auth_method = auth_method;
}


/*
 * Get/set functions for address
 *
 */
struct ether_addr * nm_ap_get_address (const NMAccessPoint *ap)
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
NMNetworkMode nm_ap_get_mode (const NMAccessPoint *ap)
{
	g_return_val_if_fail (ap != NULL, NETWORK_MODE_UNKNOWN);

	return (ap->mode);
}

void nm_ap_set_mode (NMAccessPoint *ap, const NMNetworkMode mode)
{
	g_return_if_fail (ap != NULL);

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
	for (elt = ap->user_addresses; elt; elt = g_slist_next (elt))
	{
		if (elt->data)
			g_free (elt->data);
	}

	/* Copy new list and set as our own */
	for (elt = list; elt; elt = g_slist_next (elt))
	{
		if (elt->data)
			new = g_slist_append (new, g_strdup (elt->data));
	}

	ap->user_addresses = new;
}


gboolean nm_ap_is_enc_key_valid (NMAccessPoint *ap)
{
	const char		*key;
	NMEncKeyType		 key_type;

	g_return_val_if_fail (ap != NULL, FALSE);

	key = nm_ap_get_enc_key_source (ap);
	key_type = nm_ap_get_enc_type (ap);

	if (nm_is_enc_key_valid (key, key_type))
		return TRUE;

	return FALSE;
}

gboolean nm_is_enc_key_valid (const char *key, NMEncKeyType key_type)
{
	if (    key
		&& strlen (key)
		&& (key_type != NM_ENC_TYPE_UNKNOWN)
		&& (key_type != NM_ENC_TYPE_NONE))
		return TRUE;

	return FALSE;
}
