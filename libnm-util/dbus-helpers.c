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


static void key_append_helper (DBusMessageIter *iter, const char *key)
{
	DBusMessageIter	subiter;
	int				key_len;

	g_return_if_fail (iter != NULL);
	g_return_if_fail (key != NULL);

	key_len = strlen (key);
	g_return_if_fail (key_len > 0);

	if (!dbus_message_iter_open_container (iter, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE_AS_STRING, &subiter))
		return;	
	dbus_message_iter_append_fixed_array (&subiter, DBUS_TYPE_BYTE, &key, key_len);
	dbus_message_iter_close_container (iter, &subiter);
}

dbus_bool_t nmu_dbus_message_append_wep_args (DBusMessage *message, IEEE_802_11_Cipher *cipher,
					const char *ssid, const char *input, int auth_alg)
{
	int				we_cipher = -1;
	char *			key = NULL;
	dbus_bool_t		result = TRUE;
	DBusMessageIter	iter;

	g_return_val_if_fail (message != NULL, FALSE);
	g_return_val_if_fail (cipher != NULL, FALSE);
	g_return_val_if_fail ((auth_alg == IW_AUTH_ALG_OPEN_SYSTEM) || (auth_alg == IW_AUTH_ALG_SHARED_KEY), FALSE);

	dbus_message_iter_init_append (message, &iter);

	/* First arg: WE Cipher (INT32) */
	we_cipher = ieee_802_11_cipher_get_we_cipher (cipher);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_INT32, &we_cipher);

	/* Second arg: hashed key (ARRAY, BYTE) */
	key = ieee_802_11_cipher_hash (cipher, ssid, input);
	key_append_helper (&iter, key);
	g_free (key);

	/* Third arg: WEP authentication algorithm (INT32) */
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_INT32, &auth_alg);

	return result;
}


dbus_bool_t nmu_dbus_message_append_wpa_psk_args (DBusMessage *message, IEEE_802_11_Cipher *cipher,
					const char *ssid, const char *input, int wpa_version, int key_mgt)
{
	int				we_cipher = -1;
	char *			key = NULL;
	dbus_bool_t		result = TRUE;
	DBusMessageIter	iter;

	g_return_val_if_fail (message != NULL, FALSE);
	g_return_val_if_fail (cipher != NULL, FALSE);
	g_return_val_if_fail ((wpa_version == IW_AUTH_WPA_VERSION_WPA) || (wpa_version == IW_AUTH_WPA_VERSION_WPA2), FALSE);
	g_return_val_if_fail ((key_mgt == IW_AUTH_KEY_MGMT_802_1X) || (key_mgt == IW_AUTH_KEY_MGMT_PSK), FALSE);

	dbus_message_iter_init_append (message, &iter);

	/* First arg: WE Cipher (INT32) */
	we_cipher = ieee_802_11_cipher_get_we_cipher (cipher);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_INT32, &we_cipher);

	/* Second arg: hashed key (ARRAY, BYTE) */
	key = ieee_802_11_cipher_hash (cipher, ssid, input);
	key_append_helper (&iter, key);
	g_free (key);

	/* Third arg: WPA version (INT32) */
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_INT32, &wpa_version);

	/* Fourth arg: WPA key management (INT32) */
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_INT32, &key_mgt);

	return result;
}

