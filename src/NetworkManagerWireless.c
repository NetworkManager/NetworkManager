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

#include <stdio.h>
#include <iwlib.h>
#include "config.h"
#ifdef HAVE_GCRYPT
#include <gcrypt.h>
#else
#include "gnome-keyring-md5.h"
#endif
#include "NetworkManager.h"
#include "NetworkManagerDevice.h"
#include "NetworkManagerWireless.h"
#include "NetworkManagerPolicy.h"
#include "NetworkManagerUtils.h"

/*
 * nm_wireless_64bit_ascii_to_hex
 *
 * Convert an ASCII string into a suitable WEP key.
 *
 */
char *nm_wireless_64bit_ascii_to_hex (const unsigned char *ascii)
{
	static char	 hex_digits[] = "0123456789abcdef";
	unsigned char	*res;
	int			 i;

	res = g_malloc (33);
	for (i = 0; i < 16; i++)
	{
		res[2*i] = hex_digits[(ascii[i] >> 4) & 0xf];
		res[2*i+1] = hex_digits[ascii[i] & 0xf];
	}

	/* We chomp it at byte 10, since WEP keys only use 40 bits */
	res[10] = 0;
	return (res);
}


/*
 * nm_wireless_128bit_ascii_to_hex
 *
 * Convert an ascii string into a suitable string for use
 * as a WEP key.
 *
 * Code originally by Alex Larsson <alexl@redhat.com> and
 *  copyright Red Hat, Inc. under terms of the LGPL.
 *
 */
char *nm_wireless_128bit_ascii_to_hex (const unsigned char *ascii)
{
	static char	 hex_digits[] = "0123456789abcdef";
	unsigned char	*res;
	int			 i;

	res = g_malloc (33);
	for (i = 0; i < 16; i++)
	{
		res[2*i] = hex_digits[(ascii[i] >> 4) & 0xf];
		res[2*i+1] = hex_digits[ascii[i] & 0xf];
	}
	/* We chomp it at byte 26, since WEP keys only use 104 bits */
	res[26] = 0;

	return (res);
}


/*
 * nm_wireless_128bit_key_from_passphrase
 *
 * From a passphrase, generate a standard 128-bit WEP key using
 * MD5 algorithm.
 *
 */
char *nm_wireless_128bit_key_from_passphrase	(const char *passphrase)
{
	char		 	md5_data[65];
	unsigned char	digest[16];
	int			passphrase_len;
	int			i;

	g_return_val_if_fail (passphrase != NULL, NULL);

	passphrase_len = strlen (passphrase);
	if (passphrase_len < 1)
		return (NULL);

	/* Get at least 64 bits */
	for (i = 0; i < 64; i++)
		md5_data [i] = passphrase [i % passphrase_len];

	/* Null terminate md5 data-to-hash and hash it */
	md5_data[64] = 0;
#ifdef HAVE_GCRYPT
	gcry_md_hash_buffer (GCRY_MD_MD5, digest, md5_data, 64);
#else
	gnome_keyring_md5_string (md5_data, digest);
#endif

	return (nm_wireless_128bit_ascii_to_hex (digest));
}


/*
 * nm_wireless_stats_to_percent
 *
 * Convert an iw_stats structure from a scan or the card into
 * a magical signal strength percentage.
 *
 */
int nm_wireless_qual_to_percent (NMDevice *dev, const struct iw_quality *qual)
{
	int	percent = -1;

	g_return_val_if_fail (dev != NULL, -1);
	g_return_val_if_fail (qual != NULL, -1);

	/* Try using the card's idea of the signal quality first */
	if ((nm_device_get_max_quality (dev) == 100) && (qual->qual < 100))
	{
		/* Atmel driver seems to use qual->qual is the percentage value */
		percent = CLAMP (qual->qual, 0, 100);
	}
	else if (qual->qual >= 1)
	{
		/* Try it the Gnome Wireless Applet way */
		percent = (int)rint ((log (qual->qual) / log (94)) * 100.0);
		percent = CLAMP (percent, 0, 100);
	}

	/* If that failed, try to calculate the signal quality based on other
	 * values, like Signal-to-Noise ratio.
	 */
	if (((percent == -1) || (percent == 0)))
	{
		/* If the statistics are in dBm or relative */
		if(qual->level > nm_device_get_max_quality (dev))
		{
			#define	BEST_SIGNAL	85		/* In dBm, stuck card next to AP, this is what I got */

			/* Values in dBm  (absolute power measurement) */
			if (qual->level > 0)
				percent = (int)rint ((double)(((256 - qual->level) / (double)BEST_SIGNAL) * 100));
		}
		else
		{
/* FIXME
 * Not quite sure what to do here...  Above we have a "100% strength" number
 * empirically derived, but I don't have any cards that trigger this code below...
 */
#if 0
			/* Relative values (0 -> max) */
			qual_rel = qual->level;
			qual_max_rel = range->max_qual.level;
			noise_rel = qual->noise;
			noise_max_rel = range->max_qual.noise;
#else
			percent = -1;
#endif
		}
	}

	return (percent);
}


/*
 * nm_wireless_scan_monitor
 *
 * Called every 10s to get a list of access points.
 *
 */
gboolean nm_wireless_scan_monitor (gpointer user_data)
{
	NMData	*data = (NMData *)user_data;
	GSList	*element;
	NMDevice	*dev;

	g_return_val_if_fail (data != NULL, TRUE);

	/* Attempt to acquire mutex so that data->active_device sticks around.
	 * If the acquire fails, just ignore the scan completely.
	 */
	if (!nm_try_acquire_mutex (data->dev_list_mutex, __FUNCTION__))
	{
		syslog (LOG_ERR, "nm_wireless_scan_monitor() could not acquire device list mutex." );
		return (TRUE);
	}

	element = data->dev_list;
	while (element)
	{
		if ((dev = (NMDevice *)(element->data)) && nm_device_is_wireless (dev))
			nm_device_do_wireless_scan (dev);
		element = g_slist_next (element);
	}

	nm_unlock_mutex (data->dev_list_mutex, __FUNCTION__);
	
	return (TRUE);
}
