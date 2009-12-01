/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
 * Dan Williams <dcbw@redhat.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2007 - 2009 Red Hat, Inc.
 */

#include <glib.h>
#include <unistd.h>
#include <stdlib.h>
#include <glib/gi18n.h>
#include <stdio.h>
#include <string.h>

#include "nm-test-helpers.h"
#include "crypto.h"
#include "nm-utils.h"

#if 0
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
#endif

static void
test_load_cert (const char *path, const char *desc)
{
	GByteArray *array;
	NMCryptoFileFormat format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;
	GError *error = NULL;

	array = crypto_load_and_verify_certificate (path, &format, &error);
	ASSERT (array != NULL, desc,
	        "couldn't read certificate file '%s': %d %s",
	        path, error->code, error->message);

	ASSERT (format == NM_CRYPTO_FILE_FORMAT_X509, desc,
	        "%s: unexpected certificate format (expected %d, got %d)",
	        path, NM_CRYPTO_FILE_FORMAT_X509, format);

	g_byte_array_free (array, TRUE);
}

static void
test_load_private_key (const char *path,
                       const char *password,
                       gboolean expect_fail,
                       const char *desc)
{
	NMCryptoKeyType key_type = NM_CRYPTO_KEY_TYPE_UNKNOWN;
	NMCryptoFileFormat format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;
	GByteArray *array;
	GError *error = NULL;

	array = crypto_get_private_key (path, password, &key_type, &format, &error);
	if (expect_fail) {
		ASSERT (array == NULL, desc,
		        "unexpected success reading private key file '%s' with "
		        "invalid password",
		        path);

		ASSERT (format == NM_CRYPTO_FILE_FORMAT_UNKNOWN, desc,
		        "unexpected success determining private key file '%s' "
		        "format with invalid password (expected %d, got %d)",
		        path, NM_CRYPTO_FILE_FORMAT_UNKNOWN, format);
		return;
	}

	ASSERT (array != NULL, desc,
	        "couldn't read private key file '%s': %d %s",
	        path, error->code, error->message);

	ASSERT (format == NM_CRYPTO_FILE_FORMAT_RAW_KEY, desc,
	        "%s: unexpected private key file format (expected %d, got %d)",
	        path, NM_CRYPTO_FILE_FORMAT_RAW_KEY, format);

	ASSERT (key_type == NM_CRYPTO_KEY_TYPE_RSA, desc,
	        "%s: unexpected private key type (expected %d, got %d)",
	        path, NM_CRYPTO_KEY_TYPE_RSA, format);

	g_byte_array_free (array, TRUE);
}

static void
test_load_pkcs12 (const char *path,
                  const char *password,
                  gboolean expect_fail,
                  const char *desc)
{
	NMCryptoKeyType key_type = NM_CRYPTO_KEY_TYPE_UNKNOWN;
	NMCryptoFileFormat format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;
	GByteArray *array;
	GError *error = NULL;

	array = crypto_get_private_key (path, password, &key_type, &format, &error);
	if (expect_fail) {
		ASSERT (array == NULL, desc,
		        "unexpected success reading PKCS#12 private key file "
		        "'%s' with invalid password",
		        path);

		/* PKCS#12 file format can be determined even if the password
		 * is wrong; check that.
		 */
		ASSERT (format == NM_CRYPTO_FILE_FORMAT_UNKNOWN, desc,
		        "unexpected success determining PKCS#12 private key "
		        "'%s' file format with invalid password (expected %d, "
		        "got %d)",
		        path, NM_CRYPTO_FILE_FORMAT_UNKNOWN, format);
		ASSERT (key_type == NM_CRYPTO_KEY_TYPE_UNKNOWN, desc,
		        "unexpected success determining PKCS#12 private key "
		        "'%s' type with invalid password (expected %d, got %d)",
		        path, NM_CRYPTO_KEY_TYPE_UNKNOWN, key_type);
		return;
	}

	ASSERT (array != NULL, desc,
	        "couldn't read PKCS#12 private key file '%s': %d %s",
	        path, error->code, error->message);

	ASSERT (format == NM_CRYPTO_FILE_FORMAT_PKCS12, desc,
	        "%s: unexpected PKCS#12 private key file format (expected %d, got %d)",
	        path, NM_CRYPTO_FILE_FORMAT_RAW_KEY, format);

	ASSERT (key_type == NM_CRYPTO_KEY_TYPE_ENCRYPTED, desc,
	        "%s: unexpected PKCS#12 private key type (expected %d, got %d)",
	        path, NM_CRYPTO_KEY_TYPE_ENCRYPTED, format);

	g_byte_array_free (array, TRUE);
}

static void
test_is_pkcs12 (const char *path, gboolean expect_fail, const char *desc)
{
	gboolean is_pkcs12;

	is_pkcs12 = crypto_is_pkcs12_file (path, NULL);
	if (expect_fail) {
		ASSERT (is_pkcs12 == FALSE, desc,
		        "unexpected success reading non-PKCS#12 file '%s'",
		        path);
		return;
	}

	ASSERT (is_pkcs12 == TRUE, desc, "couldn't read PKCS#12 file '%s'", path);
}

static void
test_encrypt_private_key (const char *path,
                          const char *password,
                          const char *desc)
{
	NMCryptoKeyType key_type = NM_CRYPTO_KEY_TYPE_UNKNOWN;
	NMCryptoFileFormat format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;
	GByteArray *array, *encrypted, *re_decrypted;
	GError *error = NULL;

	array = crypto_get_private_key (path, password, &key_type, &format, &error);

	ASSERT (array != NULL, desc,
	        "couldn't read private key file '%s': %d %s",
	        path, error->code, error->message);

	ASSERT (format == NM_CRYPTO_FILE_FORMAT_RAW_KEY, desc,
	        "%s: unexpected private key file format (expected %d, got %d)",
	        path, NM_CRYPTO_FILE_FORMAT_RAW_KEY, format);

	ASSERT (key_type == NM_CRYPTO_KEY_TYPE_RSA, desc,
	        "%s: unexpected private key type (expected %d, got %d)",
	        path, NM_CRYPTO_KEY_TYPE_RSA, format);

	/* Now re-encrypt the private key */
	encrypted = nm_utils_rsa_key_encrypt (array, password, NULL, &error);
	ASSERT (encrypted != NULL, desc,
	        "couldn't re-encrypt private key file '%s': %d %s",
	        path, error->code, error->message);

	/* Then re-decrypt the private key */
	key_type = NM_CRYPTO_KEY_TYPE_UNKNOWN;
	format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;
	re_decrypted = crypto_get_private_key_data (encrypted, password, &key_type, &format, &error);

	ASSERT (re_decrypted != NULL, desc,
	        "couldn't read private key file '%s': %d %s",
	        path, error->code, error->message);

	ASSERT (format == NM_CRYPTO_FILE_FORMAT_RAW_KEY, desc,
	        "%s: unexpected private key file format (expected %d, got %d)",
	        path, NM_CRYPTO_FILE_FORMAT_RAW_KEY, format);

	ASSERT (key_type == NM_CRYPTO_KEY_TYPE_RSA, desc,
	        "%s: unexpected private key type (expected %d, got %d)",
	        path, NM_CRYPTO_KEY_TYPE_RSA, format);

	/* Compare the original decrypted key with the re-decrypted key */
	ASSERT (array->len == re_decrypted->len, desc,
	        "%s: unexpected re-decrypted private key length (expected %d, got %d)",
	        path, array->len, re_decrypted->len);

	ASSERT (!memcmp (array->data, re_decrypted->data, array->len), desc,
	        "%s: unexpected private key data",
	        path);

	g_byte_array_free (re_decrypted, TRUE);
	g_byte_array_free (encrypted, TRUE);
	g_byte_array_free (array, TRUE);
}

int main (int argc, char **argv)
{
	GError *error = NULL;
	char *progname;

	ASSERT (argc > 2, "test-crypto",
	        "wrong number of arguments (expected at least an operation and an object)");

	if (!crypto_init (&error))
		FAIL ("crypto-init", "failed to initialize crypto: %s", error->message);

	if (!strcmp (argv[1], "--cert"))
		test_load_cert (argv[2], "cert");
	else if (!strcmp (argv[1], "--key")) {
		ASSERT (argc == 4, "test-crypto",
		        "wrong number of arguments (--key <key file> <password>)");

		test_load_private_key (argv[2], argv[3], FALSE, "private-key");
		test_load_private_key (argv[2], "blahblahblah", TRUE, "private-key-bad-password");
		test_encrypt_private_key (argv[2], argv[3], "private-key-rencrypt");
		test_is_pkcs12 (argv[2], TRUE, "is-pkcs12-not-pkcs12");
	} else if (!strcmp (argv[1], "--p12")) {
		test_is_pkcs12 (argv[2], FALSE, "is-pkcs12");
		test_load_pkcs12 (argv[2], argv[3], FALSE, "pkcs12-private-key");
		test_load_pkcs12 (argv[2], "blahblahblah", TRUE, "pkcs12-private-key-bad-password");
	} else {
		ASSERT (argc > 2, "test-crypto", "unknown test type (not --cert, --key, or --p12)");
	}

	crypto_deinit ();

	progname = g_path_get_basename (argv[0]);
	fprintf (stdout, "%s: SUCCESS\n", progname);
	g_free (progname);
	return 0;
}

