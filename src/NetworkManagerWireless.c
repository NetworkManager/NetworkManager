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
#include "utils/nm-utils.h"

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
	int		percent = -1;
	int		level_percent = -1;

	g_return_val_if_fail (qual != NULL, -1);
	g_return_val_if_fail (max_qual != NULL, -1);
	g_return_val_if_fail (avg_qual != NULL, -1);

#ifdef IW_QUAL_DEBUG
nm_debug ("QL: qual %d/%u/0x%X, level %d/%u/0x%X, noise %d/%u/0x%X, updated: 0x%X  ** MAX: qual %d/%u/0x%X, level %d/%u/0x%X, noise %d/%u/0x%X, updated: 0x%X",
(__s8)qual->qual, qual->qual, qual->qual,
(__s8)qual->level, qual->level, qual->level,
(__s8)qual->noise, qual->noise, qual->noise,
qual->updated,
(__s8)max_qual->qual, max_qual->qual, max_qual->qual,
(__s8)max_qual->level, max_qual->level, max_qual->level,
(__s8)max_qual->noise, max_qual->noise, max_qual->noise,
max_qual->updated);
#endif

	/* Try using the card's idea of the signal quality first as long as it tells us what the max quality is.
	 * Drivers that fill in quality values MUST treat them as percentages, ie the "Link Quality" MUST be 
	 * bounded by 0 and max_qual->qual, and MUST change in a linear fashion.  Within those bounds, drivers
	 * are free to use whatever they want to calculate "Link Quality".
	 */
	if ((max_qual->qual != 0) && !(max_qual->updated & IW_QUAL_QUAL_INVALID) && !(qual->updated & IW_QUAL_QUAL_INVALID))
		percent = (int)(100 * ((double)qual->qual / (double)max_qual->qual));

	/* If the driver doesn't specify a complete and valid quality, we have two options:
	 *
	 * 1) dBm: driver must specify max_qual->level = 0, and have valid values for
	 *        qual->level and (qual->noise OR max_qual->noise)
	 * 2) raw RSSI: driver must specify max_qual->level > 0, and have valid values for
	 *        qual->level and max_qual->level
	 *
	 * This is the WEXT spec.  If this interpretation is wrong, I'll fix it.  Otherwise,
	 * If drivers don't conform to it, they are wrong and need to be fixed.
	 */

	if (    (max_qual->level == 0) && !(max_qual->updated & IW_QUAL_LEVEL_INVALID)		/* Valid max_qual->level == 0 */
		&& !(qual->updated & IW_QUAL_LEVEL_INVALID)								/* Must have valid qual->level */
		&& (    ((max_qual->noise > 0) && !(max_qual->updated & IW_QUAL_NOISE_INVALID))	/* Must have valid max_qual->noise */
			|| ((qual->noise > 0) && !(qual->updated & IW_QUAL_NOISE_INVALID)))		/*    OR valid qual->noise */
	   )
	{
		/* Absolute power values (dBm) */

		/* Reasonable fallbacks for dumb drivers that don't specify either level. */
		#define FALLBACK_NOISE_FLOOR_DBM	-90
		#define FALLBACK_SIGNAL_MAX_DBM	-20
		int	max_level = FALLBACK_SIGNAL_MAX_DBM;
		int	noise = FALLBACK_NOISE_FLOOR_DBM;
		int	level = qual->level - 0x100;

		level = CLAMP (level, FALLBACK_NOISE_FLOOR_DBM, FALLBACK_SIGNAL_MAX_DBM);

		if ((qual->noise > 0) && (!qual->updated & IW_QUAL_NOISE_INVALID))
			noise = qual->noise - 0x100;
		else if ((max_qual->noise > 0) && !(max_qual->updated & IW_QUAL_NOISE_INVALID))
			noise = max_qual->noise - 0x100;
		noise = CLAMP (noise, FALLBACK_NOISE_FLOOR_DBM, FALLBACK_SIGNAL_MAX_DBM);

		/* A sort of signal-to-noise ratio calculation */
		level_percent = (int)(100 - 70 *(
						((double)max_level - (double)level) /
						((double)max_level - (double)noise)));
#ifdef IW_QUAL_DEBUG
		nm_debug ("QL1: level_percent is %d.  max_level %d, level %d, noise_floor %d.", level_percent, max_level, level, noise);
#endif
	}
	else if ((max_qual->level != 0) && !(max_qual->updated & IW_QUAL_LEVEL_INVALID)	/* Valid max_qual->level as upper bound */
			&& !(qual->updated & IW_QUAL_LEVEL_INVALID))
	{
		/* Relative power values (RSSI) */

		int	level = qual->level;

		/* Signal level is relavtive (0 -> max_qual->level) */
		level = CLAMP (level, 0, max_qual->level);
		level_percent = (int)(100 * ((double)level / (double)max_qual->level));
#ifdef IW_QUAL_DEBUG
		nm_debug ("QL2: level_percent is %d.  max_level %d, level %d.", level_percent, max_qual->level, level);
#endif
	}
	else if (percent == -1)
	{
#ifdef IW_QUAL_DEBUG
		nm_debug ("QL: Could not get quality %% value from driver.  Driver is probably buggy.");
#endif
	}

	/* If the quality percent was 0 or doesn't exist, then try to use signal levels instead */
	if ((percent < 1) && (level_percent >= 0))
		percent = level_percent;

#ifdef IW_QUAL_DEBUG
	nm_debug ("QL: Final quality percent is %d (%d).", percent, CLAMP (percent, 0, 100));
#endif
	return (CLAMP (percent, 0, 100));
}


void nm_update_device_wireless_timeouts (NMData *data, NMWirelessScanInterval interval)
{
	GSList *elt;
	NMDevice *dev = NULL;

	for (elt = data->dev_list; elt; elt = g_slist_next (elt))
	{
		dev = (NMDevice *)(elt->data);
		if (dev && nm_device_is_wireless (dev))
			nm_device_set_wireless_scan_interval (dev, interval);
	}
}

static gboolean nm_wireless_set_scan_interval_cb (gpointer user_data)
{
	NMData *data = (NMData*) user_data;

	nm_wireless_set_scan_interval (data, NULL, NM_WIRELESS_SCAN_INTERVAL_INACTIVE);

	return FALSE;
}

void nm_wireless_set_scan_interval (NMData *data, NMDevice *dev, NMWirelessScanInterval interval)
{
	static guint source_id = 0;
	GSource *source = NULL;
	GSList *elt;

	g_return_if_fail (data != NULL);

	if (source_id != 0)
		g_source_remove (source_id);

	for (elt = data->dev_list; elt; elt = g_slist_next (elt))
	{
		NMDevice *d = (NMDevice *)(elt->data);
		if (dev && dev != d)
			continue;

		if (d && nm_device_is_wireless (d))
			nm_device_set_wireless_scan_interval (d, interval);
	}

	if (interval != NM_WIRELESS_SCAN_INTERVAL_INACTIVE)
	{
		source = g_timeout_source_new (120000);
		g_source_set_callback (source, nm_wireless_set_scan_interval_cb, (gpointer) data, NULL);
		source_id = g_source_attach (source, data->main_context);
		g_source_unref (source);
	}
}
