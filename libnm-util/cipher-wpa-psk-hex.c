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

#include "NetworkManager.h"
#include "cipher.h"
#include "cipher-private.h"
#include "cipher-wpa-psk-hex.h"


static char * cipher_wpa_psk_hex_hash_func (IEEE_802_11_Cipher *cipher, const char *ssid, const char *input);

#define HEXSTR_WPA_PMK_LEN	WPA_PMK_LEN * 2

IEEE_802_11_Cipher * cipher_wpa_psk_hex_new (void)
{
	IEEE_802_11_Cipher * cipher = g_malloc0 (sizeof (IEEE_802_11_Cipher));

	cipher->refcount = 1;
	cipher->we_cipher = NM_AUTH_TYPE_WPA_PSK_AUTO;
	cipher->input_min = HEXSTR_WPA_PMK_LEN;
	cipher->input_max = HEXSTR_WPA_PMK_LEN;
	cipher->cipher_hash_func = cipher_wpa_psk_hex_hash_func;
	cipher->cipher_input_validate_func = cipher_default_validate_func;

	return cipher;
}


void cipher_wpa_psk_hex_set_we_cipher (IEEE_802_11_Cipher *cipher, int we_cipher)
{
	g_return_if_fail (cipher != NULL);
	g_return_if_fail ((we_cipher == NM_AUTH_TYPE_WPA_PSK_AUTO || we_cipher == IW_AUTH_CIPHER_TKIP) || (we_cipher == IW_AUTH_CIPHER_CCMP));
	g_return_if_fail ((cipher->we_cipher == NM_AUTH_TYPE_WPA_PSK_AUTO || cipher->we_cipher == IW_AUTH_CIPHER_TKIP) || (cipher->we_cipher == IW_AUTH_CIPHER_CCMP));

	cipher->we_cipher = we_cipher;
}


static char * cipher_wpa_psk_hex_hash_func (IEEE_802_11_Cipher *cipher, const char *ssid, const char *input)
{
	char * bin = NULL;
	char * hex = NULL;

	g_return_val_if_fail (cipher != NULL, NULL);
	g_return_val_if_fail (input != NULL, NULL);

	/* Convert -> bin and back to -> hexstr for validation */
	if (!(bin = cipher_hexstr2bin (input, HEXSTR_WPA_PMK_LEN)))
		return NULL;
	if (!(hex = cipher_bin2hexstr (bin, WPA_PMK_LEN, HEXSTR_WPA_PMK_LEN)))
		return NULL;
	g_free (bin);
	return hex;
}
