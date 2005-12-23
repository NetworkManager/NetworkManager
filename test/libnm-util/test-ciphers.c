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

#include "cipher.h"
#include "cipher-wep-ascii.h"
#include "cipher-wep-hex.h"
#include "cipher-wep-passphrase.h"
#include "test-common.h"

static char *progname = NULL;

static void test_refcounts (IEEE_802_11_Cipher *cipher, const char *test)
{
	if (ieee_802_11_cipher_refcount (cipher) != 1)
		test_result (progname, test, TEST_FAIL, "Cipher refcount after creation was not 1.\n");

	ieee_802_11_cipher_ref (cipher);
	if (ieee_802_11_cipher_refcount (cipher) != 2)
		test_result (progname, test, TEST_FAIL, "Cipher refcount after ref was not 2.\n");

	ieee_802_11_cipher_unref (cipher);
	if (ieee_802_11_cipher_refcount (cipher) != 1)
		test_result (progname, test, TEST_FAIL, "Cipher refcount after unref #1 was not 1.\n");

	ieee_802_11_cipher_unref (cipher);
	if (ieee_802_11_cipher_refcount (cipher) != -1)
		test_result (progname, test, TEST_FAIL, "Cipher refcount after unref #2 was not invalid.\n");

	test_result (progname, test, TEST_SUCCEED, NULL);
}


struct Inputs
{
	char * underrun;
	char * overrun;
	char * incorrect_input;
	char * correct_input;
	char * correct_output;
};

#define WEP128_ASCII_SELECTOR		0
#define WEP64_ASCII_SELECTOR		1
#define WEP128_HEX_SELECTOR		2
#define WEP64_HEX_SELECTOR		3
#define WEP128_PASSPHRASE_SELECTOR	4
#define WEP64_PASSPHRASE_SELECTOR	5

struct Inputs test_input[6] =
{
	{
		/* WEP128 ASCII */
		"ph34rm3",
		"herecomessantaclaus",
		NULL,
		"1234567891234",
		"31323334353637383931323334"
	},
	{
		/* WEP64 ASCII */
		"1234",
		"herecomessantaclaus",
		NULL,
		"12345",
		"3132333435"
	},
	{
		/* WEP128 Hex */
		"3dff2f1f93a87ad",
		"3235ab39b9b2e32fda8a919b9a021458",
		"qwertyuiopjxccjvjpapadfjcd",
		"4ec5de9938b606e9d40dff721e",
		"4ec5de9938b606e9d40dff721e"
	},
	{
		/* WEP64 Hex */
		"3dff2f1f",
		"3235ab39b9b2e",
		"qwertyuiop",
		"4ec5de9938",
		"4ec5de9938"
	},
	{
		/* WEP128 Passphrse */
		"",
		"3235ab39b9b2e32fda8a919b9a0214583235ab39b9b2e32fda8a919b9a0214583acb",
		NULL,
		"You don't remember me but I remember you.",
		"06a9c70715fe06129c625a248d"
	},
	{
		/* WEP64 Passphrse */
		"",
		"3235ab39b9b2e32fda8a919b9a0214583235ab39b9b2e32fda8a919b9a0214583acb",
		NULL,
		"Have you forgotten all I know?",
		"18074f3178"
	}
};

static void test_inputs (IEEE_802_11_Cipher *cipher, const char *test, int selector)
{
#define ESSID	"foobar"
	struct Inputs * input = &test_input[selector];
	char *output;
	char *correct_output;

	/* Underrun */
	if ((ieee_802_11_cipher_validate (cipher, ESSID, input->underrun)) != -1)
		test_result (progname, test, TEST_FAIL, "Input underrun was not rejected!\n");

	/* Overrun */
	if (input->overrun && (ieee_802_11_cipher_validate (cipher, ESSID, input->overrun)) != -1)
		test_result (progname, test, TEST_FAIL, "Input overrun was not rejected!\n");

	/* Incorrect input */
	if (input->incorrect_input && (ieee_802_11_cipher_validate (cipher, ESSID, input->incorrect_input)) != -1)
		test_result (progname, test, TEST_FAIL, "Incorrect input was not rejected!\n");

	/* Acceptance of correct input */
	if ((ieee_802_11_cipher_validate (cipher, ESSID, input->correct_input)) != 0)
		test_result (progname, test, TEST_FAIL, "Correct input was not accepted!\n");

	/* Actually hash the correct input */
	if (!(output = ieee_802_11_cipher_hash (cipher, ESSID, input->correct_input)))
		test_result (progname, test, TEST_FAIL, "Correct input was not hashed!\n");

	/* Compare to known output */
	if (memcmp (output, input->correct_output, strlen (input->correct_output)) != 0)
		test_result (progname, test, TEST_FAIL, "Hashed output did not match expected!\n");

	if (!g_utf8_validate (output, strlen (output), NULL))
		test_result (progname, test, TEST_FAIL, "Hashed output was not valid UTF8!\n");

	test_result (progname, test, TEST_SUCCEED, NULL);
}

static void test_wep_ascii (void)
{
	IEEE_802_11_Cipher *cipher;

	/* Test basic object creation */
	if (!(cipher = cipher_wep128_ascii_new ()))
		test_result (progname, "new_wep128_ascii", TEST_FAIL, "Could not create WEP104 ASCII cipher.\n");
	test_result (progname, "new_wep128_ascii", TEST_SUCCEED, NULL);
	/* Test object refcounting */
	test_refcounts (cipher, "wep128_ascii_refcounts");

	/* Test basic object creation */
	if (!(cipher = cipher_wep64_ascii_new ()))
		test_result (progname, "new_wep64_ascii", TEST_FAIL, "Could not create WEP40 ASCII cipher.\n");
	test_result (progname, "new_wep64_ascii", TEST_SUCCEED, NULL);
	/* Test object refcounting */
	test_refcounts (cipher, "wep64_ascii_refcounts");

	/* Test inputs */
	if (!(cipher = cipher_wep128_ascii_new ()))
		test_result (progname, "new_wep128_ascii", TEST_FAIL, "Could not create WEP104 ASCII cipher.\n");
	test_inputs (cipher, "inputs_wep128_ascii", WEP128_ASCII_SELECTOR);
	ieee_802_11_cipher_unref (cipher);

	if (!(cipher = cipher_wep64_ascii_new ()))
		test_result (progname, "new_wep64_ascii", TEST_FAIL, "Could not create WEP40 ASCII cipher.\n");
	test_inputs (cipher, "inputs_wep64_ascii", WEP64_ASCII_SELECTOR);
	ieee_802_11_cipher_unref (cipher);
}

static void test_wep_hex (void)
{
	IEEE_802_11_Cipher *cipher;

	/* Test basic object creation */
	if (!(cipher = cipher_wep128_hex_new ()))
		test_result (progname, "new_wep128_hex", TEST_FAIL, "Could not create WEP104 Hex cipher.\n");
	test_result (progname, "new_wep128_hex", TEST_SUCCEED, NULL);
	/* Test object refcounting */
	test_refcounts (cipher, "wep128_hex_refcounts");

	/* Test basic object creation */
	if (!(cipher = cipher_wep64_hex_new ()))
		test_result (progname, "new_wep64_hex", TEST_FAIL, "Could not create WEP40 Hex cipher.\n");
	test_result (progname, "new_wep64_hex", TEST_SUCCEED, NULL);
	/* Test object refcounting */
	test_refcounts (cipher, "wep64_hex_refcounts");

	/* Test inputs */
	if (!(cipher = cipher_wep128_hex_new ()))
		test_result (progname, "new_wep128_hex", TEST_FAIL, "Could not create WEP104 Hex cipher.\n");
	test_inputs (cipher, "inputs_wep128_hex", WEP128_HEX_SELECTOR);
	ieee_802_11_cipher_unref (cipher);

	if (!(cipher = cipher_wep64_hex_new ()))
		test_result (progname, "new_wep64_hex", TEST_FAIL, "Could not create WEP40 Hex cipher.\n");
	test_inputs (cipher, "inputs_wep64_hex", WEP64_HEX_SELECTOR);
	ieee_802_11_cipher_unref (cipher);
}

static void test_wep_passphrase (void)
{
	IEEE_802_11_Cipher *cipher;

	/* Test basic object creation */
	if (!(cipher = cipher_wep128_passphrase_new ()))
		test_result (progname, "new_wep128_passphrase", TEST_FAIL, "Could not create WEP104 Passphrase cipher.\n");
	test_result (progname, "new_wep128_passphrase", TEST_SUCCEED, NULL);
	/* Test object refcounting */
	test_refcounts (cipher, "wep128_passphrase_refcounts");

	/* Test basic object creation */
	if (!(cipher = cipher_wep64_passphrase_new ()))
		test_result (progname, "new_wep64_passphrase", TEST_FAIL, "Could not create WEP40 Passphrase cipher.\n");
	test_result (progname, "new_wep64_passphrase", TEST_SUCCEED, NULL);
	/* Test object refcounting */
	test_refcounts (cipher, "wep64_passphrase_refcounts");

	/* Test inputs */
	if (!(cipher = cipher_wep128_passphrase_new ()))
		test_result (progname, "new_wep128_passphrase", TEST_FAIL, "Could not create WEP104 Passphrase cipher.\n");
	test_inputs (cipher, "inputs_wep128_passphrase", WEP128_PASSPHRASE_SELECTOR);
	ieee_802_11_cipher_unref (cipher);

	if (!(cipher = cipher_wep64_passphrase_new ()))
		test_result (progname, "new_wep64_passphrase", TEST_FAIL, "Could not create WEP40 Passphrase cipher.\n");
	test_inputs (cipher, "inputs_wep64_passphrase", WEP64_PASSPHRASE_SELECTOR);
	ieee_802_11_cipher_unref (cipher);
}

int main (int argc, char **argv)
{
	progname = argv[0];

	test_wep_ascii ();
	test_wep_hex ();
	test_wep_passphrase ();

	return 0;
}
