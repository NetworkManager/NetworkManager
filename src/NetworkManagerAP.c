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

extern gboolean	debug;


/*
 * Encapsulates Access Point information
 */
struct NMAccessPoint
{
	guint			 refcount;
	gchar			*essid;
	struct ether_addr	*address;
	guint8			 quality;
	double			 freq;
	guint16			 rate;
	gboolean			 encrypted;
	gboolean			 invalid;
	NMAPEncMethod		 enc_method;
	gboolean			 enc_method_good;
	gboolean			 matched;	// used in ap list diffing

	/* Things from user prefs */
	gchar			*enc_key;
	GTimeVal		timestamp;
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
		syslog( LOG_ERR, "nm_ap_new() could not allocate a new user access point info structure.  Not enough memory?" );

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
		syslog( LOG_ERR, "nm_ap_new_from_uap() could not allocate a new user access point info structure.  Not enough memory?" );

	new_ap->refcount = 1;

	if (src_ap->essid && (strlen (src_ap->essid) > 0))
		new_ap->essid = g_strdup (src_ap->essid);
	if (src_ap->address)
	{
		memcpy (new_addr, src_ap->address, sizeof (struct ether_addr));
		new_ap->address = new_addr;
	}
	new_ap->quality = src_ap->quality;
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

		ap->essid = NULL;
		ap->enc_key = NULL;

		g_free (ap);
	}
}


/*
 * Get/set functions for timestamp
 *
 */
const GTimeVal *nm_ap_get_timestamp (NMAccessPoint *ap)
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
gchar * nm_ap_get_essid (NMAccessPoint *ap)
{
	g_return_val_if_fail (ap != NULL, NULL);

	return (ap->essid);
}

void nm_ap_set_essid (NMAccessPoint *ap, gchar * essid)
{
	g_return_if_fail (ap != NULL);

	if (ap->essid)
		g_free (ap->essid);

	ap->essid = g_strdup (essid);
}


/*
 * Get/set functions for encryption key
 *
 */
gchar * nm_ap_get_enc_key_source (NMAccessPoint *ap)
{
	g_return_val_if_fail (ap != NULL, NULL);

	return (ap->enc_key);
}

void nm_ap_set_enc_key_source (NMAccessPoint *ap, gchar * key)
{
	g_return_if_fail (ap != NULL);

	if (ap->enc_key)
		g_free (ap->enc_key);

	ap->enc_key = g_strdup (key);
}

gchar *nm_ap_get_enc_key_hashed (NMAccessPoint *ap, NMAPEncMethod method)
{
	gchar	*hashed = NULL;
	char		*source_key;

	g_return_val_if_fail (ap != NULL, NULL);

	source_key = nm_ap_get_enc_key_source (ap);
	switch (method)
	{
		case (NM_AP_ENC_METHOD_104_BIT_PASSPHRASE):
			if (source_key)
				hashed = nm_wireless_128bit_key_from_passphrase (source_key);
			break;

		case (NM_AP_ENC_METHOD_40_BIT_PASSPHRASE):
		case (NM_AP_ENC_METHOD_HEX_KEY):
		case (NM_AP_ENC_METHOD_UNKNOWN):
			if (source_key)
				hashed = g_strdup (source_key);
			break;

		default:
			hashed = NULL;
			break;
	}

	return (hashed);
}


/*
 * Get/set functions for encrypted flag
 *
 */
gboolean nm_ap_get_encrypted (NMAccessPoint *ap)
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
 * Get/set functions for address
 *
 */
struct ether_addr * nm_ap_get_address (NMAccessPoint *ap)
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
 * Get/set functions for quality
 *
 */
guint8 nm_ap_get_quality (NMAccessPoint *ap)
{
	g_return_val_if_fail (ap != NULL, 0);

	return (ap->quality);
}

void  nm_ap_set_quality (NMAccessPoint *ap, guint8 quality)
{
	g_return_if_fail (ap != NULL);

	ap->quality = quality;
}


/*
 * Get/set functions for frequency
 *
 */
double nm_ap_get_freq (NMAccessPoint *ap)
{
	g_return_val_if_fail (ap != NULL, 0);

	return (ap->freq);
}

void nm_ap_set_freq (NMAccessPoint *ap, double freq)
{
	g_return_if_fail (ap != NULL);

	ap->freq = freq;
}


/*
 * Get/set functions for rate
 *
 */
guint16 nm_ap_get_rate (NMAccessPoint *ap)
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
gboolean nm_ap_get_invalid (NMAccessPoint *ap)
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
gboolean nm_ap_get_matched (NMAccessPoint *ap)
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
 * Get/set functions for encryption method
 * Given some sort of passphrase/wep key from the user, we try it first
 * as a 104-bit passphrase->key conversion, and fall back from there.  These
 * functions are meant to cache which fallback succeeds so we don't have to
 * do it every time.
 *
 */
NMAPEncMethod nm_ap_get_enc_method (NMAccessPoint *ap)
{
	g_return_val_if_fail (ap != NULL, TRUE);

	return (ap->enc_method);
}

void nm_ap_set_enc_method (NMAccessPoint *ap, NMAPEncMethod enc_method)
{
	g_return_if_fail (ap != NULL);

	ap->enc_method = enc_method;

	/* By definition, if the encryption method is "unknown", it cannot be
	 * "firm" (that is, we know what method we need to use to talk to an ap)
	 */
	if (enc_method == NM_AP_ENC_METHOD_UNKNOWN)
		ap->enc_method_good = FALSE;
}

gboolean nm_ap_get_enc_method_good (NMAccessPoint *ap)
{
	g_return_val_if_fail (ap != NULL, FALSE);

	return (ap->enc_method_good);
}

void nm_ap_set_enc_method_good (NMAccessPoint *ap, gboolean good)
{
	g_return_if_fail (ap != NULL);

	ap->enc_method_good = good;
}
