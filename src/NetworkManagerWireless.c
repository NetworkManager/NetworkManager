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
int nm_wireless_qual_to_percent (const struct iw_quality *qual, const struct iw_quality *max_qual, const struct iw_quality *avg_qual)
{
	int	percent = -1;

	g_return_val_if_fail (qual != NULL, -1);
	g_return_val_if_fail (max_qual != NULL, -1);
	g_return_val_if_fail (avg_qual != NULL, -1);

	/* Try using the card's idea of the signal quality first as long as it tells us what the max quality is */
	if ((max_qual->qual != 0) && !(max_qual->updated & IW_QUAL_QUAL_INVALID) && !(qual->updated & IW_QUAL_QUAL_INVALID))
	{
		percent = (int)(100 * ((double)qual->qual / (double)max_qual->qual));
	}
	else
	{
		if((qual->level > max_qual->level) && (qual->noise != 0))
		{
			int	level = -1;
			int	noise = -1;

			/* Signal level is in dBm  (absolute power measurement) */
			if (!(qual->updated & IW_QUAL_LEVEL_INVALID))
				level = qual->level - 0x100;

			/* Deal with noise level in dBm (absolute power measurement) */
			if (!(qual->updated & IW_QUAL_NOISE_INVALID))
				noise = qual->noise - 0x100;

			/* Try a sort of signal-to-noise ratio */
			percent = abs((int)rint(10 * log ((double)level / ((double)level + (double)noise))));
		}
		else if (!(max_qual->level & IW_QUAL_LEVEL_INVALID) && (max_qual->level != 0))
		{
			/* Signal level is relavtive (0 -> max) */
			if (!(qual->updated & IW_QUAL_LEVEL_INVALID))
			{
				percent = (int)(100 * ((double)qual->level / (double)max_qual->level));
			}
		}
	}

	percent = CLAMP (percent, 0, 100);
	return (percent);
}
