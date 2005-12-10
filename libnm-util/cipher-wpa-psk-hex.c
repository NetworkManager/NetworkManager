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
#include "cipher-wpa-psk-hex.h"


static char * cipher_wpa_psk_hex_hash_func (IEEE_802_11_Cipher *cipher, const char *ssid, const char *input);


/* From hostap, Copyright (c) 2002-2005, Jouni Malinen <jkmaline@cc.hut.fi> */

static int hex2num(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static int hex2byte(const char *hex)
{
	int a, b;
	a = hex2num(*hex++);
	if (a < 0)
		return -1;
	b = hex2num(*hex++);
	if (b < 0)
		return -1;
	return (a << 4) | b;
}

static int hexstr2bin(const char *hex, char *buf, size_t len)
{
	size_t i;
	int a;
	const char *ipos = hex;
	char *opos = buf;

	for (i = 0; i < len; i++) {
		a = hex2byte(ipos);
		if (a < 0)
			return -1;
		*opos++ = a;
		ipos += 2;
	}
	return 0;
}

/* End from hostap */

IEEE_802_11_Cipher * cipher_wpa_psk_hex_new (void)
{
	IEEE_802_11_Cipher * cipher = g_malloc0 (sizeof (IEEE_802_11_Cipher));

	cipher->we_cipher = IW_AUTH_CIPHER_TKIP;
	cipher->input_min = 2;
	cipher->input_max = WPA_PMK_LEN * 2;
	cipher->cipher_hash_func = cipher_wpa_psk_hex_hash_func;
	cipher->cipher_input_validate_func = cipher_default_validate_func;
	ieee_802_11_cipher_ref (cipher);

	return cipher;
}

static char * cipher_wpa_psk_hex_hash_func (IEEE_802_11_Cipher *cipher, const char *ssid, const char *input)
{
	char * buf = NULL;
	char * ret = NULL;
	int    err = -1;

	g_return_val_if_fail (cipher != NULL, NULL);
	g_return_val_if_fail (input != NULL, NULL);

	buf = g_malloc0 (WPA_PMK_LEN+1);
	err = hexstr2bin (input, buf, WPA_PMK_LEN);
	if (err != 0)
		g_free (buf);
	else
		ret = buf;

	return ret;
}
