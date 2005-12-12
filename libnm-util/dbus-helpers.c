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


#include <dbus/dbus.h>
#include <glib.h>
#include <iwlib.h>

#include "dbus-helpers.h"
#include "cipher.h"


dbus_bool_t nmu_dbus_message_append_wep_args (DBusMessage *message, IEEE_802_11_Cipher *cipher,
					const char *ssid, const char *input, int auth_alg)
{
	int			we_cipher = -1;
	char *		hashed = NULL;
	int			hashed_len;
	dbus_bool_t	result;

	g_return_val_if_fail (message != NULL, FALSE);
	g_return_val_if_fail (cipher != NULL, FALSE);
	g_return_val_if_fail ((auth_alg == IW_AUTH_ALG_OPEN_SYSTEM) || (auth_alg == IW_AUTH_ALG_SHARED_KEY), FALSE);

	we_cipher = ieee_802_11_cipher_get_we_cipher (cipher);
fprintf (stderr, "Cipher=%d, ssid='%s', input='%s'\n", we_cipher, ssid, input);
	hashed = ieee_802_11_cipher_hash (cipher, ssid, input);
	hashed_len = strlen (hashed);
fprintf (stderr, "hashed = '%s', len = %d\n", hashed, hashed_len);

	result = dbus_message_append_args (message, DBUS_TYPE_INT32, &we_cipher,
								DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &hashed, hashed_len,
								DBUS_TYPE_INT32, &auth_alg,
								DBUS_TYPE_INVALID);
	g_free (hashed);

	return result;
}


dbus_bool_t nmu_dbus_message_append_wpa_psk_args (DBusMessage *message, IEEE_802_11_Cipher *cipher,
					const char *ssid, const char *input, int wpa_version, int key_mgt)
{
	int			we_cipher = -1;
	char *		hashed = NULL;
	int			hashed_len;
	dbus_bool_t	result;

	g_return_val_if_fail (message != NULL, FALSE);
	g_return_val_if_fail (cipher != NULL, FALSE);
	g_return_val_if_fail ((wpa_version == IW_AUTH_WPA_VERSION_WPA) || (wpa_version == IW_AUTH_WPA_VERSION_WPA2), FALSE);
	g_return_val_if_fail ((key_mgt == IW_AUTH_KEY_MGMT_802_1X) || (key_mgt == IW_AUTH_KEY_MGMT_PSK), FALSE);

	we_cipher = ieee_802_11_cipher_get_we_cipher (cipher);
	hashed = ieee_802_11_cipher_hash (cipher, ssid, input);
	hashed_len = strlen (hashed);

	result = dbus_message_append_args (message, DBUS_TYPE_INT32, &we_cipher,
								DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &hashed, hashed_len,
								DBUS_TYPE_INT32, &wpa_version,
								DBUS_TYPE_INT32, &key_mgt,
								DBUS_TYPE_INVALID);
	g_free (hashed);

	return result;
}

