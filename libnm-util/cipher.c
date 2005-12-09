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

	cipher->refcount++;
}

void ieee_802_11_cipher_unref (IEEE_802_11_Cipher *cipher)
{
	g_return_if_fail (cipher != NULL);

	cipher->refcount--;
	if (cipher->refcount <= 0)
	{
		memset (cipher, 0, sizeof (IEEE_802_11_Cipher));
		g_free (cipher);
	}
}

int ieee_802_11_cipher_get_we_cipher (IEEE_802_11_Cipher *cipher)
{
	g_return_val_if_fail (cipher != NULL, -1);

	return cipher->we_cipher;
}

int ieee_802_11_cipher_get_input_min (IEEE_802_11_Cipher *cipher)
{
	g_return_val_if_fail (cipher != NULL, -1);

	return cipher->input_min;
}

int ieee_802_11_cipher_get_input_max (IEEE_802_11_Cipher *cipher)
{
	g_return_val_if_fail (cipher != NULL, -1);

	return cipher->input_max;
}

char *ieee_802_11_cipher_hash (IEEE_802_11_Cipher *cipher, const char *ssid, const char *input)
{
	g_return_val_if_fail (cipher != NULL, NULL);

	return (*cipher->cipher_hash_func)(cipher, ssid, input);
}

int ieee_802_11_cipher_validate (IEEE_802_11_Cipher *cipher, const char *ssid, const char *input)
{
	g_return_val_if_fail (cipher != NULL, -1);

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
