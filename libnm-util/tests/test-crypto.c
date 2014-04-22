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
 * (C) Copyright 2007 - 2011 Red Hat, Inc.
 */

#include <glib.h>
#include <unistd.h>
#include <stdlib.h>
#include <glib/gi18n.h>
#include <stdio.h>
#include <string.h>

#include "crypto.h"
#include "nm-utils.h"

#include "nm-test-utils.h"

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

static GByteArray *
file_to_byte_array (const char *filename)
{
	char *contents;
	GByteArray *array = NULL;
	gsize length = 0;

	if (g_file_get_contents (filename, &contents, &length, NULL)) {
		array = g_byte_array_sized_new (length);
		g_byte_array_append (array, (guint8 *) contents, length);
		g_assert (array->len == length);
		g_free (contents);
	}
	return array;
}

static void
test_load_private_key (const char *path,
                       const char *password,
                       const char *decrypted_path,
                       gboolean expect_fail,
                       const char *desc)
{
	NMCryptoKeyType key_type = NM_CRYPTO_KEY_TYPE_UNKNOWN;
	GByteArray *array, *decrypted;
	GError *error = NULL;

	array = crypto_decrypt_private_key (path, password, &key_type, &error);
	if (expect_fail) {
		ASSERT (array == NULL, desc,
		        "unexpected success reading private key file '%s' with "
		        "invalid password",
		        path);

		ASSERT (key_type != NM_CRYPTO_KEY_TYPE_UNKNOWN, desc,
		        "unexpected failure determining private key file '%s' "
		        "type with invalid password (expected %d, got %d)",
		        path, NM_CRYPTO_KEY_TYPE_UNKNOWN, key_type);
		return;
	}

	ASSERT (array != NULL, desc,
	        "couldn't read private key file '%s': %d %s",
	        path, error->code, error->message);

	ASSERT (key_type == NM_CRYPTO_KEY_TYPE_RSA, desc,
	        "%s: unexpected private key type (expected %d, got %d)",
	        path, NM_CRYPTO_KEY_TYPE_RSA, key_type);

	if (decrypted_path) {
		/* Compare the crypto decrypted key against a known-good decryption */
		decrypted = file_to_byte_array (decrypted_path);
		ASSERT (decrypted != NULL, desc,
		        "couldn't read decrypted private key file '%s': %d %s",
		        decrypted_path, error->code, error->message);

		ASSERT (decrypted->len > 0, desc, "decrypted key file invalid (size 0)");

		ASSERT (decrypted->len == array->len,
			    desc, "decrypted key file (%d) and decrypted key data (%d) lengths don't match",
			    decrypted->len, array->len);

		ASSERT (memcmp (decrypted->data, array->data, array->len) == 0,
			    desc, "decrypted key file and decrypted key data don't match");

		g_byte_array_free (decrypted, TRUE);
	}

	g_byte_array_free (array, TRUE);
}

static void
test_load_pkcs12 (const char *path,
                  const char *password,
                  gboolean expect_fail,
                  const char *desc)
{
	NMCryptoFileFormat format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;
	GError *error = NULL;

	format = crypto_verify_private_key (path, password, &error);
	if (expect_fail) {
		ASSERT (format == NM_CRYPTO_FILE_FORMAT_UNKNOWN, desc,
		        "unexpected success reading PKCS#12 private key file "
		        "'%s' with invalid password",
		        path);
	} else {
		ASSERT (format == NM_CRYPTO_FILE_FORMAT_PKCS12, desc,
			    "%s: unexpected PKCS#12 private key file format (expected %d, got "
			    "%d): %d %s",
			    path, NM_CRYPTO_FILE_FORMAT_PKCS12, format, error->code, error->message);
	}
}

static void
test_load_pkcs12_no_password (const char *path, const char *desc)
{
	NMCryptoFileFormat format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;
	GError *error = NULL;

	/* We should still get a valid returned crypto file format */
	format = crypto_verify_private_key (path, NULL, &error);
	ASSERT (format == NM_CRYPTO_FILE_FORMAT_PKCS12, desc,
		    "%s: unexpected PKCS#12 private key file format (expected %d, got "
		    "%d): %d %s",
		    path, NM_CRYPTO_FILE_FORMAT_PKCS12, format, error->code, error->message);
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
	} else {
		ASSERT (is_pkcs12 == TRUE, desc, "couldn't read PKCS#12 file '%s'", path);
	}
}

static void
test_load_pkcs8 (const char *path,
                 const char *password,
                 gboolean expect_fail,
                 const char *desc)
{
	NMCryptoFileFormat format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;
	GError *error = NULL;

	format = crypto_verify_private_key (path, password, &error);
	if (expect_fail) {
		ASSERT (format == NM_CRYPTO_FILE_FORMAT_UNKNOWN, desc,
		        "unexpected success reading PKCS#8 private key file "
		        "'%s' with invalid password",
		        path);
	} else {
		ASSERT (format == NM_CRYPTO_FILE_FORMAT_RAW_KEY, desc,
			    "%s: unexpected PKCS#8 private key file format (expected %d, got "
			    "%d): %d %s",
			    path, NM_CRYPTO_FILE_FORMAT_RAW_KEY, format, error->code, error->message);
	}
}

static gboolean
is_cipher_aes (const char *path)
{
	char *contents;
	gsize length = 0;
	const char *cipher;
	gboolean is_aes = FALSE;

	if (!g_file_get_contents (path, &contents, &length, NULL))
		return FALSE;

	cipher = strstr (contents, "DEK-Info: ");
	if (cipher) {
		cipher += strlen ("DEK-Info: ");
		if (g_str_has_prefix (cipher, "AES-128-CBC"))
			is_aes = TRUE;
	}

	g_free (contents);
        return is_aes;
}

static void
test_encrypt_private_key (const char *path,
                          const char *password,
                          const char *desc)
{
	NMCryptoKeyType key_type = NM_CRYPTO_KEY_TYPE_UNKNOWN;
	GByteArray *array, *encrypted, *re_decrypted;
	GError *error = NULL;

	array = crypto_decrypt_private_key (path, password, &key_type, &error);
	ASSERT (array != NULL, desc,
	        "couldn't read private key file '%s': %d %s",
	        path, error->code, error->message);

	ASSERT (key_type == NM_CRYPTO_KEY_TYPE_RSA, desc,
	        "%s: unexpected private key type (expected %d, got %d)",
	        path, NM_CRYPTO_KEY_TYPE_RSA, key_type);

	/* Now re-encrypt the private key */
	if (is_cipher_aes (path))
		encrypted = nm_utils_rsa_key_encrypt_aes (array, password, NULL, &error);
	else
		encrypted = nm_utils_rsa_key_encrypt (array, password, NULL, &error);
	ASSERT (encrypted != NULL, desc,
	        "couldn't re-encrypt private key file '%s': %d %s",
	        path, error->code, error->message);

	/* Then re-decrypt the private key */
	key_type = NM_CRYPTO_KEY_TYPE_UNKNOWN;
	re_decrypted = crypto_decrypt_private_key_data (encrypted, password, &key_type, &error);
	ASSERT (re_decrypted != NULL, desc,
	        "couldn't read private key file '%s': %d %s",
	        path, error->code, error->message);

	ASSERT (key_type == NM_CRYPTO_KEY_TYPE_RSA, desc,
	        "%s: unexpected private key type (expected %d, got %d)",
	        path, NM_CRYPTO_KEY_TYPE_RSA, key_type);

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
		const char *decrypted_path = (argc == 5) ? argv[4] : NULL;

		ASSERT (argc == 4 || argc == 5, "test-crypto",
		        "wrong number of arguments (--key <key file> <password> [<decrypted key file>])");

		test_is_pkcs12 (argv[2], TRUE, "not-pkcs12");
		test_load_private_key (argv[2], argv[3], decrypted_path, FALSE, "private-key");
		test_load_private_key (argv[2], "blahblahblah", NULL, TRUE, "private-key-bad-password");
		test_load_private_key (argv[2], NULL, NULL, TRUE, "private-key-no-password");
		test_encrypt_private_key (argv[2], argv[3], "private-key-rencrypt");
	} else if (!strcmp (argv[1], "--p12")) {
		test_is_pkcs12 (argv[2], FALSE, "is-pkcs12");
		test_load_pkcs12 (argv[2], argv[3], FALSE, "pkcs12-private-key");
		test_load_pkcs12 (argv[2], "blahblahblah", TRUE, "pkcs12-private-key-bad-password");
		test_load_pkcs12_no_password (argv[2], "pkcs12-private-key-no-password");
	} else if (!strcmp (argv[1], "--pkcs8")) {
		ASSERT (argc == 4, "test-crypto",
		        "wrong number of arguments (--pkcs8 <key file> <password>)");

		test_is_pkcs12 (argv[2], TRUE, "not-pkcs12");
		test_load_pkcs8 (argv[2], argv[3], FALSE, "pkcs8-private-key");
		/* Until gnutls and NSS grow support for all the ciphers that openssl
		 * can use with PKCS#8, we can't actually verify the password.  So we
		 * expect a bad password to work for the time being.
		 */
		test_load_pkcs8 (argv[2], "blahblahblah", FALSE, "pkcs8-private-key-bad-password");
	} else {
		ASSERT (argc > 2, "test-crypto", "unknown test type (not --cert, --key, or --p12)");
	}

	crypto_deinit ();

	progname = g_path_get_basename (argv[0]);
	fprintf (stdout, "%s: SUCCESS\n", progname);
	g_free (progname);
	return 0;
}

