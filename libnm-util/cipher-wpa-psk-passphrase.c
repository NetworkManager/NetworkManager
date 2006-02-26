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
#include "cipher-wpa-psk-passphrase.h"
#include "sha1.h"


static char * cipher_wpa_psk_passphrase_hash_func (IEEE_802_11_Cipher *cipher, const char *ssid, const char *input);


IEEE_802_11_Cipher * cipher_wpa_psk_passphrase_new (void)
{
	IEEE_802_11_Cipher * cipher = g_malloc0 (sizeof (IEEE_802_11_Cipher));

	cipher->refcount = 1;
	cipher->we_cipher = NM_AUTH_TYPE_WPA_PSK_AUTO;
	/* Passphrase between 8 and 63 characters inclusive */
	cipher->input_min = 8;
	cipher->input_max = (WPA_PMK_LEN * 2) - 1;
	cipher->cipher_hash_func = cipher_wpa_psk_passphrase_hash_func;
	cipher->cipher_input_validate_func = cipher_default_validate_func;

	return cipher;
}


void cipher_wpa_psk_passphrase_set_we_cipher (IEEE_802_11_Cipher *cipher, int we_cipher)
{
	g_return_if_fail (cipher != NULL);
	g_return_if_fail ((we_cipher == NM_AUTH_TYPE_WPA_PSK_AUTO || we_cipher == IW_AUTH_CIPHER_TKIP) || (we_cipher == IW_AUTH_CIPHER_CCMP));
	g_return_if_fail ((cipher->we_cipher == NM_AUTH_TYPE_WPA_PSK_AUTO || cipher->we_cipher == IW_AUTH_CIPHER_TKIP) || (cipher->we_cipher == IW_AUTH_CIPHER_CCMP));

	cipher->we_cipher = we_cipher;
}


static char * cipher_wpa_psk_passphrase_hash_func (IEEE_802_11_Cipher *cipher, const char *ssid, const char *input)
{
	int ssid_len;
	char *buf = NULL;
	char *output = NULL;

	g_return_val_if_fail (cipher != NULL, NULL);
	g_return_val_if_fail (input != NULL, NULL);
	g_return_val_if_fail (ssid != NULL, NULL);

	ssid_len = strlen (ssid);
	g_return_val_if_fail (ssid_len > 0, NULL);

	buf = g_malloc0 (WPA_PMK_LEN * 2);
	pbkdf2_sha1 (input, (char *) ssid, ssid_len, 4096, (unsigned char *) buf, WPA_PMK_LEN);
	output = cipher_bin2hexstr (buf, WPA_PMK_LEN, WPA_PMK_LEN * 2);
	g_free (buf);

	return output;
}
