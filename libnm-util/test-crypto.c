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
 * (C) Copyright 2007 Red Hat, Inc.
 */

#include <glib.h>
#include <unistd.h>
#include <stdlib.h>
#include <glib/gi18n.h>
#include <stdio.h>
#include <string.h>

#include "crypto.h"

static const char *pem_rsa_key_begin = "-----BEGIN RSA PRIVATE KEY-----";
static const char *pem_rsa_key_end = "-----END RSA PRIVATE KEY-----";

static const char *pem_dsa_key_begin = "-----BEGIN DSA PRIVATE KEY-----";
static const char *pem_dsa_key_end = "-----END DSA PRIVATE KEY-----";

static void
dump_key_to_pem (const char *key, gsize key_len, int key_type)
{
	char *b64 = NULL;
	GString *str = NULL;
	const char *start_tag;
	const char *end_tag;
	char *p;

	switch (key_type) {
	case NM_CRYPTO_KEY_TYPE_RSA:
		start_tag = pem_rsa_key_begin;
		end_tag = pem_rsa_key_end;
		break;
	case NM_CRYPTO_KEY_TYPE_DSA:
		start_tag = pem_dsa_key_begin;
		end_tag = pem_dsa_key_end;
		break;
	default:
		g_warning ("Unknown key type %d", key_type);
		return;
	}

	b64 = g_base64_encode ((const unsigned char *) key, key_len);
	if (!b64) {
		g_warning ("Couldn't base64 encode the key.");
		goto out;
	}

	str = g_string_new (NULL);
	if (!str) {
		g_warning ("Couldn't allocate buffer to write out key.");
		goto out;
	}

	g_string_append (str, start_tag);
	g_string_append_c (str, '\n');

	for (p = b64; p < (b64 + strlen (b64)); p += 64) {
		g_string_append_len (str, p, strnlen (p, 64));
		g_string_append_c (str, '\n');
	}

	g_string_append (str, end_tag);
	g_string_append_c (str, '\n');

	g_message ("Decrypted private key:\n\n%s", str->str);

out:
	g_free (b64);
	if (str)
		g_string_free (str, TRUE);
}

static void
usage (const char *prgname)
{
	fprintf (stderr, "Usage: %s cert <file>\n"
	                 "       %s key <file> <password>\n",
	                 prgname, prgname);
}

#define MODE_CERT 1
#define MODE_KEY  2

int main (int argc, char **argv)
{
	guint32 key_type = 0;
	int mode = 0;
	const char *file;
	GError *error = NULL;

	if (argc < 2) {
		usage (argv[0]);
		return 1;
	}

	if (!strcmp (argv[1], "key")) {
		if (argc < 4) {
			usage (argv[0]);
			return 1;
		}
		mode = MODE_KEY;
	} else if (!strcmp (argv[1], "cert")) {
		if (argc < 3) {
			usage (argv[0]);
			return 1;
		}
		mode = MODE_CERT;
	} else {
		usage (argv[0]);
		return 1;
	}

	if (!crypto_init (&error)) {
		g_warning ("Couldn't initialize crypto library: %d %s.",
		           error->code, error->message);
		return 1;
	}

	file = argv[2];

	if (mode == MODE_CERT) {
		GByteArray *array;

		array = crypto_load_and_verify_certificate (file, &error);
		if (!array) {
			g_warning ("Couldn't read certificate file '%s': %d %s",
			           file, error->code, error->message);
			goto out;
		}
		g_byte_array_free (array, TRUE);
	} else if (mode == MODE_KEY) {
		const char *password = argv[3];
		GByteArray *array;

		array = crypto_get_private_key (file, password, &key_type, &error);
		if (!array) {
			g_warning ("Couldn't read key file '%s': %d %s",
			           file, error->code, error->message);
			goto out;
		}

		dump_key_to_pem ((const char *) array->data, array->len, key_type);
		g_byte_array_free (array, TRUE);
	} else {
		g_assert_not_reached ();
	}

out:
	crypto_deinit ();

	return 0;
}

