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
#include "cipher-wep-hex.h"


static char * cipher_wep128_hex_hash_func (IEEE_802_11_Cipher *cipher, const char *ssid, const char *input);
static char * cipher_wep64_hex_hash_func (IEEE_802_11_Cipher *cipher, const char *ssid, const char *input);


static char * cipher_wep_hex_convert_func (IEEE_802_11_Cipher *cipher, const char *input, int req_keylen)
{
	const char *	p;
	gboolean		success = TRUE;
	int			keylen = 0;
	int			dlen;	/* Digits sequence length */
	GString *		hashed = NULL;
	char *		ret = NULL;

	g_return_val_if_fail (cipher != NULL, NULL);
	g_return_val_if_fail (input != NULL, NULL);
	g_return_val_if_fail (req_keylen > 0, NULL);

	hashed = g_string_sized_new (32);

	/* Code here is mostly ripped from wireless-tools */

	/* Third case : as hexadecimal digits */
	p = input;
	dlen = -1;

	/* Loop until we run out of chars in input or overflow the output */
	while (*p != '\0')
	{
		int	temph;
		int	templ;
		int	count;

		/* No more chars in this sequence */
		if (dlen <= 0)
		{
			/* Skip separator */
			if (dlen == 0)
				p++;
			/* Calculate num of char to next separator */
			dlen = strcspn (p, "-:;.,");
			if (!dlen)
				continue;
		}

		/* Get each char separatly (and not by two) so that we don't
		 * get confused by 'enc' (=> '0E'+'0C') and similar */
		count = sscanf (p, "%1X%1X", &temph, &templ);
		if (count < 1)
		{
			success = FALSE;
			break;		/* Error -> non-hex char */
		}

		/* Fixup odd strings such as '123' is '01'+'23' and not '12'+'03'*/
		if (dlen % 2)
			count = 1;

		/* Put back two chars as one byte and output */
		if (count == 2)
			templ |= temph << 4;
		else
			templ = temph;
		g_string_append_c (hashed, (unsigned char) (templ & 0xFF));

		/* Check overflow in output */
		if (hashed->len >= IW_ENCODING_TOKEN_MAX)
			break;

		/* Move on to next chars */
		p += count;
		keylen += count;
		dlen -= count;
	}

	/* Ensure the actual key data length is what's required */
	if (keylen != req_keylen)
		success = FALSE;

	if (success)
		ret = hashed->str;

	/* Don't free the string data if conversion was successful */
	g_string_free (hashed, (success == TRUE ? FALSE : TRUE));

	return ret;
}


#define WEP128_HEX_INPUT_SIZE	26
IEEE_802_11_Cipher * cipher_wep128_hex_new (void)
{
	IEEE_802_11_Cipher * cipher = g_malloc0 (sizeof (IEEE_802_11_Cipher));

	cipher->refcount = 1;
	cipher->we_cipher = IW_AUTH_CIPHER_WEP104;
	cipher->input_min = WEP128_HEX_INPUT_SIZE;
	cipher->input_max = WEP128_HEX_INPUT_SIZE;
	cipher->cipher_hash_func = cipher_wep128_hex_hash_func;
	cipher->cipher_input_validate_func = cipher_default_validate_func;

	return cipher;
}

static char * cipher_wep128_hex_hash_func (IEEE_802_11_Cipher *cipher, const char *ssid, const char *input)
{
	g_return_val_if_fail (cipher != NULL, NULL);
	g_return_val_if_fail (input != NULL, NULL);

	return cipher_wep_hex_convert_func (cipher, input, WEP128_HEX_INPUT_SIZE);
}


#define WEP64_HEX_INPUT_SIZE	10
IEEE_802_11_Cipher * cipher_wep64_hex_new (void)
{
	IEEE_802_11_Cipher * cipher = g_malloc0 (sizeof (IEEE_802_11_Cipher));

	cipher->refcount = 1;
	cipher->we_cipher = IW_AUTH_CIPHER_WEP40;
	cipher->input_min = WEP64_HEX_INPUT_SIZE;
	cipher->input_max = WEP64_HEX_INPUT_SIZE;
	cipher->cipher_hash_func = cipher_wep64_hex_hash_func;
	cipher->cipher_input_validate_func = cipher_default_validate_func;

	return cipher;
}

static char * cipher_wep64_hex_hash_func (IEEE_802_11_Cipher *cipher, const char *ssid, const char *input)
{
	g_return_val_if_fail (cipher != NULL, NULL);
	g_return_val_if_fail (input != NULL, NULL);

	return cipher_wep_hex_convert_func (cipher, input, WEP64_HEX_INPUT_SIZE);
}
