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

#ifndef TEST_INPUTS_H
#define TEST_INPUTS_H

#include <iwlib.h>

struct Inputs
{
	int    we_cipher;
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
#define WPA_PSK_HEX_SELECTOR		6
#define WPA_PSK_PASSPHRASE_SELECTOR	7

struct Inputs test_input[8] =
{
	{
		/* WEP128 ASCII */
		IW_AUTH_CIPHER_WEP104,
		"ph34rm3",
		"herecomessantaclaus",
		NULL,
		"1234567891234",
		"31323334353637383931323334"
	},
	{
		/* WEP64 ASCII */
		IW_AUTH_CIPHER_WEP40,
		"1234",
		"herecomessantaclaus",
		NULL,
		"12345",
		"3132333435"
	},
	{
		/* WEP128 Hex */
		IW_AUTH_CIPHER_WEP104,
		"3dff2f1f93a87ad",
		"3235ab39b9b2e32fda8a919b9a021458",
		"qwertyuiopjxccjvjpapadfjcd",
		"4ec5de9938b606e9d40dff721e",
		"4ec5de9938b606e9d40dff721e"
	},
	{
		/* WEP64 Hex */
		IW_AUTH_CIPHER_WEP40,
		"3dff2f1f",
		"3235ab39b9b2e",
		"qwertyuiop",
		"4ec5de9938",
		"4ec5de9938"
	},
	{
		/* WEP128 Passphrse */
		IW_AUTH_CIPHER_WEP104,
		"",
		"3235ab39b9b2e32fda8a919b9a0214583235ab39b9b2e32fda8a919b9a0214583acb",
		NULL,
		"You don't remember me but I remember you.",
		"06a9c70715fe06129c625a248d"
	},
	{
		/* WEP64 Passphrse */
		IW_AUTH_CIPHER_WEP40,
		"",
		"3235ab39b9b2e32fda8a919b9a0214583235ab39b9b2e32fda8a919b9a0214583acb",
		NULL,
		"Have you forgotten all I know?",
		"18074f3178"
	},
	{
		/* WPA PSK Hex */
		IW_AUTH_CIPHER_TKIP,
		"3220a0adbad22310",
		"3235ab39b9b2e32f5a5b5c5a8e8c8b8a09129abfbe293959fa9023b20bacb09320214583acb",
		"waetueuasdghadsg83282af",
		"22ad0a0c0dea0b0a09a6a54aeb5dc42838d7f128a6f6b6e6d77c7c7aa3d4b4ae",
		"22ad0a0c0dea0b0a09a6a54aeb5dc42838d7f128a6f6b6e6d77c7c7aa3d4b4ae"
	},
	{
		/* WPA PSK Passphrase */
		IW_AUTH_CIPHER_TKIP,
		"",
		"This is a really long passphrase since it's supposed to be a test of overflow.",
		NULL,
		"ThisIsAPassword",
		"0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af"
	}
};

#endif	/* TEST_INPUTS_H */
