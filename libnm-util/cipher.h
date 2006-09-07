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

#ifndef CIPHER_H
#define CIPHER_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct IEEE_802_11_Cipher IEEE_802_11_Cipher;

void          ieee_802_11_cipher_ref (IEEE_802_11_Cipher *cipher);
void          ieee_802_11_cipher_unref (IEEE_802_11_Cipher *cipher);
int           ieee_802_11_cipher_get_we_cipher (IEEE_802_11_Cipher *cipher);
int           ieee_802_11_cipher_get_input_min (IEEE_802_11_Cipher *cipher);
int           ieee_802_11_cipher_get_input_max (IEEE_802_11_Cipher *cipher);
char *        ieee_802_11_cipher_hash (IEEE_802_11_Cipher *cipher, const char *ssid, const char *input);
int           ieee_802_11_cipher_validate (IEEE_802_11_Cipher *cipher, const char *ssid, const char *input);

char *        cipher_bin2hexstr (const char *bytes, int len, int final_len);
char *        cipher_hexstr2bin(const char *hex, size_t len);


/* Private API members (not part of the public API) */
int           ieee_802_11_cipher_refcount (IEEE_802_11_Cipher *cipher);

#ifdef __cplusplus
}
#endif

#endif	/* CIPHER_H */
