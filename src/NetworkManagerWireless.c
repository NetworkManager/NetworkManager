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
 * nm_wireless_md5_digest_to_ascii
 *
 * Convert an MD5 digest into an ascii string suitable for use
 * as a WEP key.
 *
 * Code originally by Alex Larsson <alexl@redhat.com> and
 *  copyright Red Hat, Inc. under terms of the LGPL.
 *
 */
static char *nm_wireless_md5_digest_to_ascii (unsigned char digest[16])
{
	static char	 hex_digits[] = "0123456789abcdef";
	unsigned char	*res;
	int			 i;

	res = g_malloc (33);
	for (i = 0; i < 16; i++)
	{
		res[2*i] = hex_digits[digest[i] >> 4];
		res[2*i+1] = hex_digits[digest[i] & 0xf];
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
char *nm_wireless_128bit_key_from_passphrase	(char *passphrase)
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

	return (nm_wireless_md5_digest_to_ascii (digest));
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
