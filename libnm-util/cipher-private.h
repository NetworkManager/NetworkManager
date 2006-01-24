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

#ifndef CIPHER_PRIVATE_H
#define CIPHER_PRIVATE_H

struct IEEE_802_11_Cipher
{
	int		refcount;

	/* From /usr/include/wireless.h, IW_AUTH_CIPHER_* value
	 * corresponding to this encryption method,
	 * ex IW_AUTH_CIPHER_WEP104
	 */
	int		we_cipher;

	/* Min & max lengths of user-input for this cipher method */
	int		input_min;
	int		input_max;

	/* Secret hash function, if any.  Takes user-entered
	 * password/passphrase/key and returns binary key to be
	 * sent to the card's driver itself.  Returns an allocated
	 * value the the caller must free.
	 */
	char *	(*cipher_hash_func)(IEEE_802_11_Cipher *cipher, const char *ssid, const char *input);

	/* Input validation function, if any.  Takes a user-entered
	 * password/passphrase/key and determines whether it is valid
	 * for this cipher.  Return 0 if valid, -1 if invalid.
	 */
	int		(*cipher_input_validate_func)(IEEE_802_11_Cipher *cipher, const char *ssid, const char *input);
};


int		cipher_default_validate_func (IEEE_802_11_Cipher *cipher,
                                        const char *ssid,
                                        const char *input);

#endif	/* CIPHER_PRIVATE_H */
