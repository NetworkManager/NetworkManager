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

extern gboolean	debug;

static char *
nm_md5 (const char *buf, size_t len)
{
#ifdef HAVE_GCRYPT
	char ascii_key[32];
	gcry_md_hash_buffer (GCRY_MD_MD5, ascii_key, buf, len);
	return g_strndup (ascii_key, 32);
#else
	struct GnomeKeyringMD5Context ctx;
	char digest[16];
	
	gnome_keyring_md5_init (&ctx);
	gnome_keyring_md5_update (&ctx, buf, len);
	gnome_keyring_md5_final (digest, &ctx);
	return gnome_keyring_md5_digest_to_ascii (digest);
#endif
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
	char		 temp_buf [65];
	int		 passphrase_len;
	int		 i;

	g_return_val_if_fail (passphrase != NULL, NULL);

	passphrase_len = strlen (passphrase);
	if (passphrase_len < 1)
		return (NULL);

	/* Get at least 64 bits */
	for (i = 0; i < 64; i++)
		temp_buf [i] = passphrase [i % passphrase_len];

	return nm_md5 (temp_buf, 64);
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

	g_return_val_if_fail (data != NULL, TRUE);

	if (!data->active_device)
		return (TRUE);

	/* Attempt to acquire mutex so that data->active_device sticks around.
	 * If the acquire fails, just ignore the scan completely.
	 */
	if (nm_try_acquire_mutex (data->dev_list_mutex, __FUNCTION__))
	{
		if (data->active_device && nm_device_is_wireless (data->active_device))
			nm_device_do_wireless_scan (data->active_device);

		nm_unlock_mutex (data->dev_list_mutex, __FUNCTION__);
	}
	else
		syslog( LOG_ERR, "nm_wireless_scan_monitor() could not acquire device list mutex." );
	
	return (TRUE);
}
