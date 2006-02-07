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

#include <stdlib.h>
#include <string.h>
#include <glib.h>

#include "cipher.h"
#include "cipher-private.h"


void ieee_802_11_cipher_ref (IEEE_802_11_Cipher *cipher)
{
	g_return_if_fail (cipher != NULL);
	g_return_if_fail (cipher->refcount > 0);

	cipher->refcount++;
}

void ieee_802_11_cipher_unref (IEEE_802_11_Cipher *cipher)
{
	g_return_if_fail (cipher != NULL);
	g_return_if_fail (cipher->refcount > 0);

	cipher->refcount--;
	if (cipher->refcount <= 0)
	{
		memset (cipher, 0, sizeof (IEEE_802_11_Cipher));
		g_free (cipher);
	}
}

int ieee_802_11_cipher_refcount (IEEE_802_11_Cipher *cipher)
{
	g_return_val_if_fail (cipher != NULL, -1);
	g_return_val_if_fail (cipher->refcount > 0, -1);

	return cipher->refcount;
}

int ieee_802_11_cipher_get_we_cipher (IEEE_802_11_Cipher *cipher)
{
	g_return_val_if_fail (cipher != NULL, -1);
	g_return_val_if_fail (cipher->refcount > 0, -1);

	return cipher->we_cipher;
}

int ieee_802_11_cipher_get_input_min (IEEE_802_11_Cipher *cipher)
{
	g_return_val_if_fail (cipher != NULL, -1);
	g_return_val_if_fail (cipher->refcount > 0, -1);

	return cipher->input_min;
}

int ieee_802_11_cipher_get_input_max (IEEE_802_11_Cipher *cipher)
{
	g_return_val_if_fail (cipher != NULL, -1);
	g_return_val_if_fail (cipher->refcount > 0, -1);

	return cipher->input_max;
}

char *ieee_802_11_cipher_hash (IEEE_802_11_Cipher *cipher, const char *ssid, const char *input)
{
	g_return_val_if_fail (cipher != NULL, NULL);
	g_return_val_if_fail (cipher->refcount > 0, NULL);

	return (*cipher->cipher_hash_func)(cipher, ssid, input);
}

int ieee_802_11_cipher_validate (IEEE_802_11_Cipher *cipher, const char *ssid, const char *input)
{
	g_return_val_if_fail (cipher != NULL, -1);
	g_return_val_if_fail (cipher->refcount > 0, -1);

	if (!cipher->cipher_input_validate_func)
		return cipher_default_validate_func (cipher, ssid, input);

	return (*cipher->cipher_input_validate_func)(cipher, ssid, input);
}


int cipher_default_validate_func (IEEE_802_11_Cipher *cipher, const char *ssid, const char *input)
{
	char *	hashed = NULL;
	int		ret = -1;
	int		len;

	g_return_val_if_fail (cipher != NULL, -1);
	g_return_val_if_fail (cipher->refcount > 0, -1);
	g_return_val_if_fail (input != NULL, -1);

	len = strlen (input);
	if ((len < cipher->input_min) || (len > cipher->input_max))
		return -1;

	hashed = (*cipher->cipher_hash_func)(cipher, ssid, input);
	if (hashed)
		ret = 0;
	g_free (hashed);

	return ret;
}

/*
 * cipher_bin2hexstr
 *
 * Convert a byte-array into a hexadecimal string.
 *
 * Code originally by Alex Larsson <alexl@redhat.com> and
 *  copyright Red Hat, Inc. under terms of the LGPL.
 *
 */
char *
cipher_bin2hexstr (const char *bytes,
                   int len,
                   int final_len)
{
	static char	hex_digits[] = "0123456789abcdef";
	char *		result;
	int			i;

	g_return_val_if_fail (bytes != NULL, NULL);
	g_return_val_if_fail (len > 0, NULL);
	g_return_val_if_fail (len < 256, NULL);	/* Arbitrary limit */

	result = g_malloc0 (len * 2 + 1);
	for (i = 0; i < len; i++)
	{
		result[2*i] = hex_digits[(bytes[i] >> 4) & 0xf];
		result[2*i+1] = hex_digits[bytes[i] & 0xf];
	}
	/* Cut converted key off at the correct length for this cipher type */
	if (final_len > -1)
		result[final_len] = '\0';

	return result;
}

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

char *
cipher_hexstr2bin(const char *hex,
                  size_t len)
{
	size_t		i;
	int			a;
	const char *	ipos = hex;
	char *		buf = NULL;
	char *		opos;

	/* Length must be a multiple of 2 */
	if ((len % 2) != 0)
		return NULL;

	opos = buf = g_malloc0 ((len / 2) + 1);
	for (i = 0; i < len; i += 2)
	{
		a = hex2byte(ipos);
		if (a < 0)
		{
			g_free (buf);
			return NULL;
		}
		*opos++ = a;
		ipos += 2;
	}
	return buf;
}

/* End from hostap */
