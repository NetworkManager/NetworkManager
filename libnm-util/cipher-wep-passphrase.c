/* NetworkManager Wireless Applet -- Display wireless access points and allow user control
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
 * (C) Copyright 2005 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib.h>
#include <iwlib.h>

#include "cipher.h"
#include "cipher-private.h"
#include "cipher-wep-passphrase.h"

#ifdef HAVE_GCRYPT
#include <gcrypt.h>
#else
#include "gnome-keyring-md5.h"
#endif


static char * cipher_wep128_passphrase_hash_func (IEEE_802_11_Cipher *cipher, const char *ssid, const char *input);
static char * cipher_wep64_passphrase_hash_func (IEEE_802_11_Cipher *cipher, const char *ssid, const char *input);


static char * cipher_wep_passphrase_hash_func (IEEE_802_11_Cipher *cipher, const char *input, int req_keylen)
{
	char		 	md5_data[65];
	unsigned char	digest[16];
	int			input_len;
	int			i;

	g_return_val_if_fail (cipher != NULL, NULL);
	g_return_val_if_fail (input != NULL, NULL);

	input_len = strlen (input);
	if (input_len < 1)
		return NULL;

	/* Get at least 64 bits */
	for (i = 0; i < 64; i++)
		md5_data [i] = input [i % input_len];

	/* Null terminate md5 seed data and hash it */
	md5_data[64] = 0;
#ifdef HAVE_GCRYPT
	gcry_md_hash_buffer (GCRY_MD_MD5, digest, md5_data, 64);
#else
	gnome_keyring_md5_string (md5_data, digest);
#endif

	return (cipher_bin2hexstr ((const char *) &digest, 16, req_keylen));
}


IEEE_802_11_Cipher * cipher_wep128_passphrase_new (void)
{
	IEEE_802_11_Cipher * cipher = g_malloc0 (sizeof (IEEE_802_11_Cipher));

	cipher->refcount = 1;
	cipher->we_cipher = IW_AUTH_CIPHER_WEP104;
	cipher->input_min = 1;  /* What _is_ the min, really? */
	cipher->input_max = 64;
	cipher->cipher_hash_func = cipher_wep128_passphrase_hash_func;
	cipher->cipher_input_validate_func = cipher_default_validate_func;

	return cipher;
}

static char * cipher_wep128_passphrase_hash_func (IEEE_802_11_Cipher *cipher, const char *ssid, const char *input)
{
	g_return_val_if_fail (cipher != NULL, NULL);
	g_return_val_if_fail (input != NULL, NULL);

	return cipher_wep_passphrase_hash_func (cipher, input, 26);
}

IEEE_802_11_Cipher * cipher_wep64_passphrase_new (void)
{
	IEEE_802_11_Cipher * cipher = g_malloc0 (sizeof (IEEE_802_11_Cipher));

	cipher->refcount = 1;
	cipher->we_cipher = IW_AUTH_CIPHER_WEP40;
	cipher->input_min = 1;  /* What _is_ the min, really? */
	cipher->input_max = 64;
	cipher->cipher_hash_func = cipher_wep64_passphrase_hash_func;
	cipher->cipher_input_validate_func = cipher_default_validate_func;

	return cipher;
}

static char * cipher_wep64_passphrase_hash_func (IEEE_802_11_Cipher *cipher, const char *ssid, const char *input)
{
	g_return_val_if_fail (cipher != NULL, NULL);
	g_return_val_if_fail (input != NULL, NULL);

	return cipher_wep_passphrase_hash_func (cipher, input, 10);
}

