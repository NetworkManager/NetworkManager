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
 * Copyright 2007 - 2011 Red Hat, Inc.
 */

#include "nm-default.h"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "crypto.h"
#include "nm-utils.h"

#include "nm-utils/nm-test-utils.h"

#define TEST_CERT_DIR                         NM_BUILD_SRCDIR"/libnm-core/tests/certs"

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
test_cert (gconstpointer test_data)
{
	gs_free char *path = NULL;
	GByteArray *array;
	NMCryptoFileFormat format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;
	GError *error = NULL;

	path = g_build_filename (TEST_CERT_DIR, (const char *) test_data, NULL);

	array = crypto_load_and_verify_certificate (path, &format, &error);
	nmtst_assert_success (array != NULL, error);
	g_assert (format == NM_CRYPTO_FILE_FORMAT_X509);

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
		g_assert (!array);
		g_assert ((password && error) || (!password && !error));
		g_assert (key_type != NM_CRYPTO_KEY_TYPE_UNKNOWN);
		g_clear_error (&error);
		return;
	}

	g_assert (array);
	g_assert (key_type == NM_CRYPTO_KEY_TYPE_RSA);

	if (decrypted_path) {
		/* Compare the crypto decrypted key against a known-good decryption */
		decrypted = file_to_byte_array (decrypted_path);
		g_assert (decrypted);
		g_assert_cmpint (decrypted->len, >, 0);
		g_assert_cmpmem (decrypted->data, decrypted->len, array->data, array->len);

		g_byte_array_free (decrypted, TRUE);
	}

	g_clear_error (&error);
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
	if (expect_fail)
		g_assert (format == NM_CRYPTO_FILE_FORMAT_UNKNOWN);
	else
		g_assert (format == NM_CRYPTO_FILE_FORMAT_PKCS12);
	g_clear_error (&error);
}

static void
test_load_pkcs12_no_password (const char *path, const char *desc)
{
	NMCryptoFileFormat format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;
	GError *error = NULL;

	/* We should still get a valid returned crypto file format */
	format = crypto_verify_private_key (path, NULL, &error);
	g_assert (format == NM_CRYPTO_FILE_FORMAT_PKCS12);
}

static void
test_is_pkcs12 (const char *path, gboolean expect_fail, const char *desc)
{
	gboolean is_pkcs12;

	is_pkcs12 = crypto_is_pkcs12_file (path, NULL);
	if (expect_fail)
		g_assert (!is_pkcs12);
	else
		g_assert (is_pkcs12);
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
	if (expect_fail)
		g_assert (format == NM_CRYPTO_FILE_FORMAT_UNKNOWN);
	else
		g_assert (format == NM_CRYPTO_FILE_FORMAT_RAW_KEY);
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
	g_assert (array);
	g_assert_no_error (error);
	g_assert (key_type == NM_CRYPTO_KEY_TYPE_RSA);

	/* Now re-encrypt the private key */
	if (is_cipher_aes (path))
		encrypted = nm_utils_rsa_key_encrypt_aes (array, password, NULL, &error);
	else
		encrypted = nm_utils_rsa_key_encrypt (array, password, NULL, &error);
	g_assert (encrypted);
	g_assert_no_error (error);

	/* Then re-decrypt the private key */
	key_type = NM_CRYPTO_KEY_TYPE_UNKNOWN;
	re_decrypted = crypto_decrypt_private_key_data (encrypted, password, &key_type, &error);
	g_assert (re_decrypted);
	g_assert_no_error (error);
	g_assert (key_type == NM_CRYPTO_KEY_TYPE_RSA);

	/* Compare the original decrypted key with the re-decrypted key */
	g_assert_cmpmem (array->data, array->len, re_decrypted->data, re_decrypted->len);

	g_byte_array_free (re_decrypted, TRUE);
	g_byte_array_free (encrypted, TRUE);
	g_byte_array_free (array, TRUE);
}

static void
test_key (gconstpointer test_data)
{
	char **parts, *path, *password, *decrypted_path;
	int len;

	parts = g_strsplit ((const char *) test_data, ", ", -1);
	len = g_strv_length (parts);
	g_assert (len == 2 || len == 3);

	path = g_build_filename (TEST_CERT_DIR, parts[0], NULL);
	password = parts[1];
	decrypted_path = parts[2] ? g_build_filename (TEST_CERT_DIR, parts[2], NULL) : NULL;

	test_is_pkcs12 (path, TRUE, "not-pkcs12");
	test_load_private_key (path, password, decrypted_path, FALSE, "private-key");
	test_load_private_key (path, "blahblahblah", NULL, TRUE, "private-key-bad-password");
	test_load_private_key (path, NULL, NULL, TRUE, "private-key-no-password");
	test_encrypt_private_key (path, password, "private-key-rencrypt");

	g_free (path);
	g_free (decrypted_path);
	g_strfreev (parts);
}

static void
test_pkcs12 (gconstpointer test_data)
{
	char **parts, *path, *password;

	parts = g_strsplit ((const char *) test_data, ", ", -1);
	g_assert_cmpint (g_strv_length (parts), ==, 2);

	path = g_build_filename (TEST_CERT_DIR, parts[0], NULL);
	password = parts[1];

	test_is_pkcs12 (path, FALSE, "is-pkcs12");
	test_load_pkcs12 (path, password, FALSE, "pkcs12-private-key");
	test_load_pkcs12 (path, "blahblahblah", TRUE, "pkcs12-private-key-bad-password");
	test_load_pkcs12_no_password (path, "pkcs12-private-key-no-password");

	g_free (path);
	g_strfreev (parts);
}

static void
test_pkcs8 (gconstpointer test_data)
{
	char **parts, *path, *password;

	parts = g_strsplit ((const char *) test_data, ", ", -1);
	g_assert_cmpint (g_strv_length (parts), ==, 2);

	path = g_build_filename (TEST_CERT_DIR, parts[0], NULL);
	password = parts[1];

	test_is_pkcs12 (path, TRUE, "not-pkcs12");
	test_load_pkcs8 (path, password, FALSE, "pkcs8-private-key");

	g_free (path);
	g_strfreev (parts);
}

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	GError *error = NULL;
	gboolean success;

	nmtst_init (&argc, &argv, TRUE);

	success = crypto_init (&error);
	g_assert_no_error (error);
	g_assert (success);

	g_test_add_data_func ("/libnm/crypto/cert/pem",
	                      "test_ca_cert.pem",
	                      test_cert);
	g_test_add_data_func ("/libnm/crypto/cert/pem-2",
	                      "test2_ca_cert.pem",
	                      test_cert);
	g_test_add_data_func ("/libnm/crypto/cert/der",
	                      "test_ca_cert.der",
	                      test_cert);
	g_test_add_data_func ("/libnm/crypto/cert/pem-no-ending-newline",
	                      "ca-no-ending-newline.pem",
	                      test_cert);
	g_test_add_data_func ("/libnm/crypto/cert/pem-combined",
	                      "test_key_and_cert.pem",
	                      test_cert);
	g_test_add_data_func ("/libnm/crypto/cert/pem-combined-2",
	                      "test2_key_and_cert.pem",
	                      test_cert);

	g_test_add_data_func ("/libnm/crypto/key/padding-6",
	                      "test_key_and_cert.pem, test, test-key-only-decrypted.der",
	                      test_key);
	g_test_add_data_func ("/libnm/crypto/key/key-only",
	                      "test-key-only.pem, test, test-key-only-decrypted.der",
	                      test_key);
	g_test_add_data_func ("/libnm/crypto/key/padding-8",
	                      "test2_key_and_cert.pem, 12345testing",
	                      test_key);
	g_test_add_data_func ("/libnm/crypto/key/aes-128",
	                      "test-aes-128-key.pem, test-aes-password",
	                      test_key);

	g_test_add_data_func ("/libnm/crypto/PKCS#12/1",
	                      "test-cert.p12, test",
	                      test_pkcs12);
	g_test_add_data_func ("/libnm/crypto/PKCS#12/2",
	                      "test2-cert.p12, 12345testing",
	                      test_pkcs12);

	g_test_add_data_func ("/libnm/crypto/PKCS#8",
	                      "pkcs8-enc-key.pem, 1234567890",
	                      test_pkcs8);

	return g_test_run ();
}

