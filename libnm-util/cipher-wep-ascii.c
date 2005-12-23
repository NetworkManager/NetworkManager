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

#include <glib.h>
#include <iwlib.h>

#include "cipher.h"
#include "cipher-private.h"
#include "cipher-wep-ascii.h"


static char * cipher_wep128_ascii_hash_func (IEEE_802_11_Cipher *cipher, const char *ssid, const char *input);
static char * cipher_wep64_ascii_hash_func (IEEE_802_11_Cipher *cipher, const char *ssid, const char *input);


static char * cipher_wep_ascii_hash_func (IEEE_802_11_Cipher *cipher, const char *input, int req_keylen)
{
	g_return_val_if_fail (cipher != NULL, NULL);
	g_return_val_if_fail (input != NULL, NULL);
	g_return_val_if_fail (req_keylen > 0, NULL);

	if (strlen (input) != req_keylen)
		return NULL;

	return cipher_bin2hexstr (input, req_keylen, req_keylen * 2);
}


#define WEP128_ASCII_INPUT_SIZE	13
IEEE_802_11_Cipher * cipher_wep128_ascii_new (void)
{
	IEEE_802_11_Cipher * cipher = g_malloc0 (sizeof (IEEE_802_11_Cipher));

	cipher->refcount = 1;
	cipher->we_cipher = IW_AUTH_CIPHER_WEP104;
	cipher->input_min = WEP128_ASCII_INPUT_SIZE;
	cipher->input_max = WEP128_ASCII_INPUT_SIZE;
	cipher->cipher_hash_func = cipher_wep128_ascii_hash_func;
	cipher->cipher_input_validate_func = cipher_default_validate_func;

	return cipher;
}

static char * cipher_wep128_ascii_hash_func (IEEE_802_11_Cipher *cipher, const char *ssid, const char *input)
{
	g_return_val_if_fail (cipher != NULL, NULL);
	g_return_val_if_fail (input != NULL, NULL);

	return cipher_wep_ascii_hash_func (cipher, input, WEP128_ASCII_INPUT_SIZE);
}


#define WEP64_ASCII_INPUT_SIZE	5
IEEE_802_11_Cipher * cipher_wep64_ascii_new (void)
{
	IEEE_802_11_Cipher * cipher = g_malloc0 (sizeof (IEEE_802_11_Cipher));

	cipher->refcount = 1;
	cipher->we_cipher = IW_AUTH_CIPHER_WEP40;
	cipher->input_min = WEP64_ASCII_INPUT_SIZE;
	cipher->input_max = WEP64_ASCII_INPUT_SIZE;
	cipher->cipher_hash_func = cipher_wep64_ascii_hash_func;
	cipher->cipher_input_validate_func = cipher_default_validate_func;

	return cipher;
}

static char * cipher_wep64_ascii_hash_func (IEEE_802_11_Cipher *cipher, const char *ssid, const char *input)
{
	g_return_val_if_fail (cipher != NULL, NULL);
	g_return_val_if_fail (input != NULL, NULL);

	return cipher_wep_ascii_hash_func (cipher, input, WEP64_ASCII_INPUT_SIZE);
}

