/* NetworkManager -- Forget about your network
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dbus/dbus.h>
#include <iwlib.h>

#include "cipher.h"
#include "cipher-wep-ascii.h"
#include "cipher-wep-hex.h"
#include "cipher-wep-passphrase.h"
#include "cipher-wpa-psk-hex.h"
#include "cipher-wpa-psk-passphrase.h"
#include "test-inputs.h"
#include "test-common.h"
#include "dbus-helpers.h"

static char *progname = NULL;
#define ESSID	"ThisIsASSID"

static void
test_serialize_wep (const char * test,
                    IEEE_802_11_Cipher *cipher,
                    int selector,
                    int auth_alg)
{
	DBusMessage *		message;
	const char *		signature;
	DBusMessageIter	iter;
	dbus_int32_t		int_arg;
	char *			str_arg;
	char *			hashed;

	message =  dbus_message_new_method_call ("org.foobar", "/org/foobar", "org.foobar", "foobar");
	if (!message)
		test_result (progname, test, TEST_FAIL, "Couldn't create test dbus message.\n");

	if (!nmu_security_serialize_wep_with_cipher (message,
										cipher,
										ESSID,
										test_input[selector].correct_input,
										auth_alg))
	{
		test_result (progname, test, TEST_FAIL, "Couldn't serialize cipher into dbus message.\n");
	}

	if (!(signature = dbus_message_get_signature (message)))
		test_result (progname, test, TEST_FAIL, "Couldn't retrieve test dbus message's signature.\n");

	/* Verify message signature */
#define CORRECT_SIGNATURE	"isi"
	if (strcmp (signature, CORRECT_SIGNATURE) != 0)
	{
		test_result (progname, test, TEST_FAIL, "Signature of serialized cipher (%s)"
				" didn't match expected (%s).\n", signature, CORRECT_SIGNATURE);
	}

	/* Verify message arguments */
	dbus_message_iter_init (message, &iter);

	if (dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_INT32)
		test_result (progname, test, TEST_FAIL, "Message's we_cipher element expected but not found.\n");

	dbus_message_iter_get_basic (&iter, &int_arg);
	if (int_arg != ieee_802_11_cipher_get_we_cipher (cipher))
	{
		test_result (progname, test, TEST_FAIL, "Message's we_cipher element (%d)"
				" did not match expected value (%d).\n", int_arg, ieee_802_11_cipher_get_we_cipher (cipher));
	}

	if (!dbus_message_iter_has_next (&iter))
		test_result (progname, test, TEST_FAIL, "Message's key element expected but not found.\n");
	dbus_message_iter_next (&iter);
	if (dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_STRING)
		test_result (progname, test, TEST_FAIL, "Message's key element expected but not found after next.\n");

	dbus_message_iter_get_basic (&iter, &str_arg);
	if (!(hashed = ieee_802_11_cipher_hash (cipher, ESSID, test_input[selector].correct_input)))
		test_result (progname, test, TEST_FAIL, "Couldn't hash encryption key input.\n");
	if (!str_arg || (strcmp (hashed, str_arg) != 0))
	{
		test_result (progname, test, TEST_FAIL, "Message's key element (%s) did not match expected value (%s).\n",
				str_arg, hashed);
		g_free (hashed);
	}
	g_free (hashed);

	if (!dbus_message_iter_has_next (&iter))
		test_result (progname, test, TEST_FAIL, "Message's auth_algorithm element expected but not found.\n");
	dbus_message_iter_next (&iter);
	if (dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_INT32)
		test_result (progname, test, TEST_FAIL, "Message's auth_algorithm element expected but not found after next.\n");

	dbus_message_iter_get_basic (&iter, &int_arg);
	if (int_arg != auth_alg)
	{
		test_result (progname, test, TEST_FAIL, "Message's auth_algoritm element (%s) did not match expected value (%s).\n",
				int_arg, auth_alg);
	}

	dbus_message_unref (message);
	test_result (progname, test, TEST_SUCCEED, NULL);
}


static void
test_deserialize_wep (const char *test,
                      int selector,
                      int auth_alg)
{
	DBusMessage *		message;
	DBusMessageIter	iter;
	char *			msg_key = NULL;
	int				msg_key_len;
	int				msg_auth_alg;
	int				real_key_len;

	message =  dbus_message_new_method_call ("org.foobar", "/org/foobar", "org.foobar", "foobar");
	if (!message)
		test_result (progname, test, TEST_FAIL, "Couldn't create test dbus message.\n");

	/* Build up test message */
	dbus_message_iter_init_append (message, &iter);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_INT32, &test_input[selector].we_cipher);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &test_input[selector].correct_output);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_INT32, &auth_alg);

	dbus_message_iter_init (message, &iter);
	/* Skip we_cipher element */
	dbus_message_iter_next (&iter);
	if (!nmu_security_deserialize_wep (&iter, &msg_key, &msg_key_len, &msg_auth_alg))
		test_result (progname, test, TEST_FAIL, "Error deserializing from dbus message.\n");

	if (strcmp (msg_key, test_input[selector].correct_output) != 0)
	{
		test_result (progname, test, TEST_FAIL, "Message's key element (%s) did not match expected value (%s).\n",
				msg_key, test_input[selector].correct_output);
	}

	real_key_len = strlen (test_input[selector].correct_output);
	if (msg_key_len != real_key_len)
	{
		test_result (progname, test, TEST_FAIL, "Message's key element length (%d) did not match expected value (%d).\n",
				msg_key_len, real_key_len);
	}

	if (msg_auth_alg != auth_alg)
	{
		test_result (progname, test, TEST_FAIL, "Message's auth_algorithm (%d) did not match expected value (%d).\n",
				msg_auth_alg, auth_alg);
	}

	dbus_message_unref (message);
	test_result (progname, test, TEST_SUCCEED, NULL);
}
                      

static void test_wep_ascii (void)
{
	IEEE_802_11_Cipher *cipher;

	fprintf (stdout, "\n\n---- START: WEP ASCII ---------------------------------------------\n");

	if (!(cipher = cipher_wep128_ascii_new ()))
		test_result (progname, "new_wep128_ascii", TEST_FAIL, "Could not create WEP104 ASCII cipher.\n");
	test_serialize_wep ("serialize_wep128_ascii_os", cipher, WEP128_ASCII_SELECTOR, IW_AUTH_ALG_OPEN_SYSTEM);
	test_serialize_wep ("serialize_wep128_ascii_sk", cipher, WEP128_ASCII_SELECTOR, IW_AUTH_ALG_SHARED_KEY);
	ieee_802_11_cipher_unref (cipher);

	test_deserialize_wep ("deserialize_wep128_ascii_os", WEP128_ASCII_SELECTOR, IW_AUTH_ALG_OPEN_SYSTEM);
	test_deserialize_wep ("deserialize_wep128_ascii_sk", WEP128_ASCII_SELECTOR, IW_AUTH_ALG_SHARED_KEY);

	if (!(cipher = cipher_wep64_ascii_new ()))
		test_result (progname, "new_wep64_ascii", TEST_FAIL, "Could not create WEP40 ASCII cipher.\n");
	test_serialize_wep ("serialize_wep64_ascii_os", cipher, WEP64_ASCII_SELECTOR, IW_AUTH_ALG_OPEN_SYSTEM);
	test_serialize_wep ("serialize_wep64_ascii_sk", cipher, WEP64_ASCII_SELECTOR, IW_AUTH_ALG_SHARED_KEY);
	ieee_802_11_cipher_unref (cipher);

	test_deserialize_wep ("deserialize_wep64_ascii_os", WEP64_ASCII_SELECTOR, IW_AUTH_ALG_OPEN_SYSTEM);
	test_deserialize_wep ("deserialize_wep64_ascii_sk", WEP64_ASCII_SELECTOR, IW_AUTH_ALG_SHARED_KEY);
}

static void test_wep_hex (void)
{
	IEEE_802_11_Cipher *cipher;

	fprintf (stdout, "\n\n---- START: WEP Hex ---------------------------------------------\n");

	if (!(cipher = cipher_wep128_hex_new ()))
		test_result (progname, "new_wep128_hex", TEST_FAIL, "Could not create WEP104 Hex cipher.\n");
	test_serialize_wep ("serialize_wep128_hex_os", cipher, WEP128_HEX_SELECTOR, IW_AUTH_ALG_OPEN_SYSTEM);
	test_serialize_wep ("serialize_wep128_hex_sk", cipher, WEP128_HEX_SELECTOR, IW_AUTH_ALG_SHARED_KEY);
	ieee_802_11_cipher_unref (cipher);

	test_deserialize_wep ("deserialize_wep128_hex_os", WEP128_HEX_SELECTOR, IW_AUTH_ALG_OPEN_SYSTEM);
	test_deserialize_wep ("deserialize_wep128_hex_sk", WEP128_HEX_SELECTOR, IW_AUTH_ALG_SHARED_KEY);

	if (!(cipher = cipher_wep64_hex_new ()))
		test_result (progname, "new_wep64_hex", TEST_FAIL, "Could not create WEP40 Hex cipher.\n");
	test_serialize_wep ("serialize_wep64_hex_os", cipher, WEP64_HEX_SELECTOR, IW_AUTH_ALG_OPEN_SYSTEM);
	test_serialize_wep ("serialize_wep64_hex_sk", cipher, WEP64_HEX_SELECTOR, IW_AUTH_ALG_SHARED_KEY);
	ieee_802_11_cipher_unref (cipher);

	test_deserialize_wep ("deserialize_wep64_hex_os", WEP64_HEX_SELECTOR, IW_AUTH_ALG_OPEN_SYSTEM);
	test_deserialize_wep ("deserialize_wep64_hex_sk", WEP64_HEX_SELECTOR, IW_AUTH_ALG_SHARED_KEY);
}


static void test_wep_passphrase (void)
{
	IEEE_802_11_Cipher *cipher;

	fprintf (stdout, "\n\n---- START: WEP Passphrase ---------------------------------------------\n");

	if (!(cipher = cipher_wep128_passphrase_new ()))
		test_result (progname, "new_wep128_passphrase", TEST_FAIL, "Could not create WEP104 Passphrase cipher.\n");
	test_serialize_wep ("serialize_wep128_passphrase_os", cipher, WEP128_PASSPHRASE_SELECTOR, IW_AUTH_ALG_OPEN_SYSTEM);
	test_serialize_wep ("serialize_wep128_passphrase_sk", cipher, WEP128_PASSPHRASE_SELECTOR, IW_AUTH_ALG_SHARED_KEY);
	ieee_802_11_cipher_unref (cipher);

	test_deserialize_wep ("deserialize_wep128_passphrase_os", WEP128_PASSPHRASE_SELECTOR, IW_AUTH_ALG_OPEN_SYSTEM);
	test_deserialize_wep ("deserialize_wep128_passphrase_sk", WEP128_PASSPHRASE_SELECTOR, IW_AUTH_ALG_SHARED_KEY);

	if (!(cipher = cipher_wep64_passphrase_new ()))
		test_result (progname, "new_wep64_passphrase", TEST_FAIL, "Could not create WEP40 Passphrase cipher.\n");
	test_serialize_wep ("serialize_wep64_passphrase_os", cipher, WEP64_PASSPHRASE_SELECTOR, IW_AUTH_ALG_OPEN_SYSTEM);
	test_serialize_wep ("serialize_wep64_passphrase_sk", cipher, WEP64_PASSPHRASE_SELECTOR, IW_AUTH_ALG_SHARED_KEY);
	ieee_802_11_cipher_unref (cipher);

	test_deserialize_wep ("deserialize_wep64_passphrase_os", WEP64_PASSPHRASE_SELECTOR, IW_AUTH_ALG_OPEN_SYSTEM);
	test_deserialize_wep ("deserialize_wep64_passphrase_sk", WEP64_PASSPHRASE_SELECTOR, IW_AUTH_ALG_SHARED_KEY);
}

int main (int argc, char **argv)
{
	progname = argv[0];

	test_wep_ascii ();
	test_wep_hex ();
	test_wep_passphrase ();

	fprintf (stderr, "\n\n------ DONE\n");

	return 0;
}
