// SPDX-License-Identifier: LGPL-2.1+
/*
 * Dan Williams <dcbw@redhat.com>
 * Copyright (C) 2007 - 2011 Red Hat, Inc.
 */

#include "nm-default.h"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "nm-crypto-impl.h"
#include "nm-utils.h"
#include "nm-errors.h"
#include "nm-core-internal.h"

#include "nm-utils/nm-test-utils.h"

#define TEST_CERT_DIR              NM_BUILD_SRCDIR"/libnm-core/tests/certs"

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
	gs_unref_bytes GBytes *cert = NULL;
	NMCryptoFileFormat format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;
	GError *error = NULL;
	gboolean success;

	path = g_build_filename (TEST_CERT_DIR, (const char *) test_data, NULL);

	success = nm_crypto_load_and_verify_certificate (path, &format, &cert, &error);
	nmtst_assert_success (success, error);
	g_assert_cmpint (format, ==, NM_CRYPTO_FILE_FORMAT_X509);

	g_assert (nm_utils_file_is_certificate (path));
}

static void
test_load_private_key (const char *path,
                       const char *password,
                       const char *decrypted_path,
                       int expected_error)
{
	NMCryptoKeyType key_type = NM_CRYPTO_KEY_TYPE_UNKNOWN;
	gboolean is_encrypted = FALSE;
	gs_unref_bytes GBytes *array = NULL;
	GError *error = NULL;

	g_assert (nm_utils_file_is_private_key (path, &is_encrypted));
	g_assert (is_encrypted);

	array = nmtst_crypto_decrypt_openssl_private_key (path, password, &key_type, &error);
	/* Even if the password is wrong, we should determine the key type */
	g_assert_cmpint (key_type, ==, NM_CRYPTO_KEY_TYPE_RSA);

	if (expected_error != -1) {
		g_assert (array == NULL);
		g_assert_error (error, NM_CRYPTO_ERROR, expected_error);
		g_clear_error (&error);
		return;
	}

	if (password == NULL) {
		g_assert (array == NULL);
		g_assert_no_error (error);
		return;
	}

	g_assert (array != NULL);

	if (decrypted_path) {
		gs_free char *contents = NULL;
		gsize length;

		/* Compare the crypto decrypted key against a known-good decryption */
		if (!g_file_get_contents (decrypted_path, &contents, &length, NULL))
			g_assert_not_reached ();
		g_assert (nm_utils_gbytes_equal_mem (array, contents, length));
	}
}

static void
test_load_pkcs12 (const char *path,
                  const char *password,
                  int expected_error)
{
	NMCryptoFileFormat format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;
	gboolean is_encrypted = FALSE;
	GError *error = NULL;

	g_assert (nm_utils_file_is_private_key (path, NULL));

	format = nm_crypto_verify_private_key (path, password, &is_encrypted, &error);
	if (expected_error != -1) {
		g_assert_error (error, NM_CRYPTO_ERROR, expected_error);
		g_assert_cmpint (format, ==, NM_CRYPTO_FILE_FORMAT_UNKNOWN);
		g_clear_error (&error);
	} else {
		g_assert_no_error (error);
		g_assert_cmpint (format, ==, NM_CRYPTO_FILE_FORMAT_PKCS12);
		g_assert (is_encrypted);
	}
}

static void
test_load_pkcs12_no_password (const char *path)
{
	NMCryptoFileFormat format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;
	gboolean is_encrypted = FALSE;
	GError *error = NULL;

	g_assert (nm_utils_file_is_private_key (path, NULL));

	/* We should still get a valid returned crypto file format */
	format = nm_crypto_verify_private_key (path, NULL, &is_encrypted, &error);
	g_assert_no_error (error);
	g_assert_cmpint (format, ==, NM_CRYPTO_FILE_FORMAT_PKCS12);
	g_assert (is_encrypted);
}

static void
test_is_pkcs12 (const char *path, gboolean expect_fail)
{
	gboolean is_pkcs12;
	GError *error = NULL;

	is_pkcs12 = nm_crypto_is_pkcs12_file (path, &error);

	if (expect_fail) {
		g_assert_error (error, NM_CRYPTO_ERROR, NM_CRYPTO_ERROR_INVALID_DATA);
		g_assert (!is_pkcs12);
		g_clear_error (&error);
	} else {
		g_assert_no_error (error);
		g_assert (is_pkcs12);
	}
}

static void
test_load_pkcs8 (const char *path,
                 const char *password,
                 int expected_error)
{
	NMCryptoFileFormat format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;
	gboolean is_encrypted = FALSE;
	GError *error = NULL;

	g_assert (nm_utils_file_is_private_key (path, NULL));

	format = nm_crypto_verify_private_key (path, password, &is_encrypted, &error);
	if (expected_error != -1) {
		g_assert_error (error, NM_CRYPTO_ERROR, expected_error);
		g_assert_cmpint (format, ==, NM_CRYPTO_FILE_FORMAT_UNKNOWN);
		g_clear_error (&error);
	} else {
		g_assert_no_error (error);
		g_assert_cmpint (format, ==, NM_CRYPTO_FILE_FORMAT_RAW_KEY);
		g_assert (is_encrypted);
	}
}

static void
test_encrypt_private_key (const char *path,
                          const char *password)
{
	NMCryptoKeyType key_type = NM_CRYPTO_KEY_TYPE_UNKNOWN;
	gs_unref_bytes GBytes *array = NULL;
	gs_unref_bytes GBytes *encrypted = NULL;
	gs_unref_bytes GBytes *re_decrypted = NULL;
	GError *error = NULL;

	array = nmtst_crypto_decrypt_openssl_private_key (path, password, &key_type, &error);
	nmtst_assert_success (array, error);
	g_assert_cmpint (key_type, ==, NM_CRYPTO_KEY_TYPE_RSA);

	/* Now re-encrypt the private key */
	encrypted = nmtst_crypto_rsa_key_encrypt (g_bytes_get_data (array, NULL),
	                                          g_bytes_get_size (array),
	                                          password,
	                                          NULL,
	                                          &error);
	nmtst_assert_success (encrypted, error);

	/* Then re-decrypt the private key */
	key_type = NM_CRYPTO_KEY_TYPE_UNKNOWN;
	re_decrypted = nmtst_crypto_decrypt_openssl_private_key_data (g_bytes_get_data (encrypted, NULL),
	                                                              g_bytes_get_size (encrypted),
	                                                              password,
	                                                              &key_type,
	                                                              &error);
	nmtst_assert_success (re_decrypted, error);
	g_assert_cmpint (key_type, ==, NM_CRYPTO_KEY_TYPE_RSA);

	/* Compare the original decrypted key with the re-decrypted key */
	g_assert (g_bytes_equal (array, re_decrypted));
}

static void
test_key (gconstpointer test_data)
{
	char **parts, *path, *password, *decrypted_path;
	int len;

	parts = g_strsplit ((const char *) test_data, ", ", -1);
	len = g_strv_length (parts);
	if (len != 2 && len != 3)
		g_error ("wrong number of arguments (<key file>, <password>, [<decrypted key file>])");

	path = g_build_filename (TEST_CERT_DIR, parts[0], NULL);
	password = parts[1];
	decrypted_path = parts[2] ? g_build_filename (TEST_CERT_DIR, parts[2], NULL) : NULL;

	test_is_pkcs12 (path, TRUE);
	test_load_private_key (path, password, decrypted_path, -1);
	test_load_private_key (path, "blahblahblah", NULL, NM_CRYPTO_ERROR_DECRYPTION_FAILED);
	test_load_private_key (path, NULL, NULL, -1);
	test_encrypt_private_key (path, password);

	g_free (path);
	g_free (decrypted_path);
	g_strfreev (parts);
}

static void
test_key_decrypted (gconstpointer test_data)
{
	const char *file = (const char *) test_data;
	gboolean is_encrypted = FALSE;
	char *path;

	path = g_build_filename (TEST_CERT_DIR, file, NULL);

	g_assert (nm_utils_file_is_private_key (path, &is_encrypted));
	g_assert (!is_encrypted);

	g_free (path);
}

static void
test_pkcs12 (gconstpointer test_data)
{
	char **parts, *path, *password;

	parts = g_strsplit ((const char *) test_data, ", ", -1);
	if (g_strv_length (parts) != 2)
		g_error ("wrong number of arguments (<file>, <password>)");

	path = g_build_filename (TEST_CERT_DIR, parts[0], NULL);
	password = parts[1];

	test_is_pkcs12 (path, FALSE);
	test_load_pkcs12 (path, password, -1);
	test_load_pkcs12 (path, "blahblahblah", NM_CRYPTO_ERROR_DECRYPTION_FAILED);
	test_load_pkcs12_no_password (path);

	g_free (path);
	g_strfreev (parts);
}

static void
test_pkcs8 (gconstpointer test_data)
{
	char **parts, *path, *password;

	parts = g_strsplit ((const char *) test_data, ", ", -1);
	if (g_strv_length (parts) != 2)
		g_error ("wrong number of arguments (<file>, <password>)");

	path = g_build_filename (TEST_CERT_DIR, parts[0], NULL);
	password = parts[1];

	test_is_pkcs12 (path, TRUE);
	/* Note: NSS and gnutls < 3.5.4 don't support all the ciphers that openssl
	 * can use with PKCS#8 and thus the password can't be actually verified with
	 * such libraries.
	 */
	test_load_pkcs8 (path, password, -1);

	g_free (path);
	g_strfreev (parts);
}

#define SALT "sodium chloride"
#define SHORT_PASSWORD "short"
#define LONG_PASSWORD "this is a longer password than the short one"
#define SHORT_DIGEST 16
#define LONG_DIGEST 57

struct {
	const char *salt, *password;
	gsize digest_size;
	const char *result;
} md5_tests[] = {
	{ NULL, SHORT_PASSWORD, SHORT_DIGEST,
	  "4f09daa9d95bcb166a302407a0e0babe" },
	{ NULL, SHORT_PASSWORD, LONG_DIGEST,
	  "4f09daa9d95bcb166a302407a0e0babeb7d62e5baf706830d007c253f0fe7584ad7e92dc00a599ec277293c298ae70ee3904c348e23be61c91" },
	{ SALT, SHORT_PASSWORD, SHORT_DIGEST,
	  "774771f7292210233b5724991d1f9894" },
	{ SALT, SHORT_PASSWORD, LONG_DIGEST,
	  "774771f7292210233b5724991d1f98941a6ffdb45e4dc7fa04b1fa6aceed379c1ade0577bc8f261d109942ed5736921c052664d72e0d5bade9" },
	{ NULL, LONG_PASSWORD, SHORT_DIGEST,
	  "e9c03517f81ff29bb777dac21fb1699c" },
	{ NULL, LONG_PASSWORD, LONG_DIGEST,
	  "e9c03517f81ff29bb777dac21fb1699c50968c7ccd8db4f0a59d00ffd87b05876d45f25a927d51a8400c35af60fbd64584349a8b7435d62fd9" },
	{ SALT, LONG_PASSWORD, SHORT_DIGEST,
	  "4e5c076e2f85f5e03994acbf3a9e10d6" },
	{ SALT, LONG_PASSWORD, LONG_DIGEST,
	  "4e5c076e2f85f5e03994acbf3a9e10d61a6969c9fdf47ae8b1f7e2725b3767b05cc974bfcb5344b630c91761e015e09d7794b5065662533bc9" },
	{ NULL, "", SHORT_DIGEST,
	  "d41d8cd98f00b204e9800998ecf8427e" },
	{ SALT, "", SHORT_DIGEST,
	  "7df1e0494c977195005d82a1809685e4" },
};

static void
test_md5 (void)
{
	char digest[LONG_DIGEST], *hex;
	int i;

	for (i = 0; i < G_N_ELEMENTS (md5_tests); i++) {
		memset (digest, 0, sizeof (digest));
		nm_crypto_md5_hash ((const guint8 *) md5_tests[i].salt,
		                    /* nm_crypto_md5_hash() used to clamp salt_len to 8.  It
		                     * doesn't any more, so we need to do it here now to
		                     * get output that matches md5_tests[i].result.
		                     */
		                    md5_tests[i].salt ? 8 : 0,
		                    (const guint8 *) md5_tests[i].password,
		                    strlen (md5_tests[i].password),
		                    (guint8 *) digest,
		                    md5_tests[i].digest_size);

		hex = nm_utils_bin2hexstr (digest, md5_tests[i].digest_size, -1);
		g_assert_cmpstr (hex, ==, md5_tests[i].result);
		g_free (hex);
	}
}

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	GError *error = NULL;
	gboolean success;
	int ret;

	nmtst_init (&argc, &argv, TRUE);

	success = _nm_crypto_init (&error);
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
	g_test_add_data_func ("/libnm/crypto/key/aes-256",
	                      "test-aes-256-key.pem, test-aes-password",
	                      test_key);
	g_test_add_data_func ("/libnm/crypto/key/decrypted",
	                      "test-key-only-decrypted.pem",
	                      test_key_decrypted);

	g_test_add_data_func ("/libnm/crypto/PKCS#12/1",
	                      "test-cert.p12, test",
	                      test_pkcs12);
	g_test_add_data_func ("/libnm/crypto/PKCS#12/2",
	                      "test2-cert.p12, 12345testing",
	                      test_pkcs12);

	g_test_add_data_func ("/libnm/crypto/PKCS#8",
	                      "pkcs8-enc-key.pem, 1234567890",
	                      test_pkcs8);

	g_test_add_func ("/libnm/crypto/md5", test_md5);

	ret = g_test_run ();

	return ret;
}

