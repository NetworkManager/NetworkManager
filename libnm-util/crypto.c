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
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <glib/gi18n.h>

#include "crypto.h"

GQuark
_nm_crypto_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-crypto-error-quark");
	return quark;
}


static const char *pem_rsa_key_begin = "-----BEGIN RSA PRIVATE KEY-----";
static const char *pem_rsa_key_end = "-----END RSA PRIVATE KEY-----";

static const char *pem_dsa_key_begin = "-----BEGIN DSA PRIVATE KEY-----";
static const char *pem_dsa_key_end = "-----END DSA PRIVATE KEY-----";

static const char *pem_cert_begin = "-----BEGIN CERTIFICATE-----";
static const char *pem_cert_end = "-----END CERTIFICATE-----";

static const char *
find_tag (const char *tag, const char *buf, gsize len)
{
	gsize i, taglen;

	taglen = strlen (tag);
	if (len < taglen)
		return NULL;

	for (i = 0; i < len - taglen + 1; i++) {
		if (memcmp (buf + i, tag, taglen) == 0)
			return buf + i;
	}
	return NULL;
}

#define DEK_INFO_TAG "DEK-Info: "
#define PROC_TYPE_TAG "Proc-Type: "

static GByteArray *
parse_old_openssl_key_file (GByteArray *contents,
                            int key_type,
                            char **out_cipher,
                            char **out_iv,
                            GError **error)
{
	GByteArray *bindata = NULL;
	char **lines = NULL;
	char **ln = NULL;
	const char *pos;
	const char *end;
	GString *str = NULL;
	int enc_tags = 0;
	char *iv = NULL;
	char *cipher = NULL;
	unsigned char *tmp = NULL;
	gsize tmp_len = 0;
	const char *start_tag;
	const char *end_tag;

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
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_UNKNOWN_KEY_TYPE,
		             "Unknown key type %d",
		             key_type);
		g_assert_not_reached ();
		return NULL;
	}

	pos = find_tag (start_tag, (const char *) contents->data, contents->len);
	if (!pos)
		goto parse_error;

	pos += strlen (start_tag);

	end = find_tag (end_tag, pos, (const char *) contents->data + contents->len - pos);
	if (end == NULL) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_FILE_FORMAT_INVALID,
		             _("PEM key file had no end tag '%s'."),
		             end_tag);
		goto parse_error;
	}
	*((char *) end) = '\0';

	lines = g_strsplit (pos, "\n", 0);
	if (!lines || g_strv_length (lines) <= 1) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_FILE_FORMAT_INVALID,
		             _("Doesn't look like a PEM private key file."));
		goto parse_error;
	}

	str = g_string_new_len (NULL, end - pos);
	if (!str) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_OUT_OF_MEMORY,
		             _("Not enough memory to store PEM file data."));
		goto parse_error;
	}

	for (ln = lines; *ln; ln++) {
		char *p = *ln;

		/* Chug leading spaces */
		p = g_strstrip (p);
		if (!*p)
			continue;

		if (!strncmp (p, PROC_TYPE_TAG, strlen (PROC_TYPE_TAG))) {
			if (enc_tags++ != 0) {
				g_set_error (error, NM_CRYPTO_ERROR,
				             NM_CRYPTO_ERR_FILE_FORMAT_INVALID,
				             _("Malformed PEM file: Proc-Type was not first tag."));
				goto parse_error;
			}

			p += strlen (PROC_TYPE_TAG);
			if (strcmp (p, "4,ENCRYPTED")) {
				g_set_error (error, NM_CRYPTO_ERROR,
				             NM_CRYPTO_ERR_FILE_FORMAT_INVALID,
				             _("Malformed PEM file: unknown Proc-Type tag '%s'."),
				             p);
				goto parse_error;
			}
		} else if (!strncmp (p, DEK_INFO_TAG, strlen (DEK_INFO_TAG))) {
			char *comma;

			if (enc_tags++ != 1) {
				g_set_error (error, NM_CRYPTO_ERROR,
				             NM_CRYPTO_ERR_FILE_FORMAT_INVALID,
				             _("Malformed PEM file: DEK-Info was not the second tag."));
				goto parse_error;
			}

			p += strlen (DEK_INFO_TAG);

			/* Grab the IV first */
			comma = strchr (p, ',');
			if (!comma || (*(comma + 1) == '\0')) {
				g_set_error (error, NM_CRYPTO_ERROR,
				             NM_CRYPTO_ERR_FILE_FORMAT_INVALID,
				             _("Malformed PEM file: no IV found in DEK-Info tag."));
				goto parse_error;
			}
			*comma++ = '\0';
			if (!g_ascii_isxdigit (*comma)) {
				g_set_error (error, NM_CRYPTO_ERROR,
				             NM_CRYPTO_ERR_FILE_FORMAT_INVALID,
				             _("Malformed PEM file: invalid format of IV in DEK-Info tag."));
				goto parse_error;
			}
			iv = g_strdup (comma);

			/* Get the private key cipher */
			if (!strcasecmp (p, "DES-EDE3-CBC")) {
				cipher = g_strdup (p);
			} else if (!strcasecmp (p, "DES-CBC")) {
				cipher = g_strdup (p);
			} else {
				g_set_error (error, NM_CRYPTO_ERROR,
				             NM_CRYPTO_ERR_UNKNOWN_KEY_TYPE,
				             _("Malformed PEM file: unknown private key cipher '%s'."),
				             p);
				goto parse_error;
			}
		} else {
			if ((enc_tags != 0) && (enc_tags != 2)) {
				g_set_error (error, NM_CRYPTO_ERROR,
				             NM_CRYPTO_ERR_FILE_FORMAT_INVALID,
				             "Malformed PEM file: both Proc-Type and DEK-Info tags are required.");
				goto parse_error;
			}
			g_string_append (str, p);
		}
	}

	tmp = g_base64_decode (str->str, &tmp_len);
	if (tmp == NULL || !tmp_len) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_DECODE_FAILED,
		             _("Could not decode private key."));
		goto parse_error;
	}

	if (lines)
		g_strfreev (lines);

	bindata = g_byte_array_sized_new (tmp_len);
	g_byte_array_append (bindata, tmp, tmp_len);
	*out_iv = iv;
	*out_cipher = cipher;
	return bindata;

parse_error:
	g_free (cipher);
	g_free (iv);
	if (lines)
		g_strfreev (lines);
	return NULL;
}

static GByteArray *
file_to_g_byte_array (const char *filename,
                      gboolean privkey,
                      GError **error)
{
	char *contents, *der = NULL;
	GByteArray *array = NULL;
	gsize length = 0;
	const char *pos = NULL;

	if (!g_file_get_contents (filename, &contents, &length, error))
		return NULL;

	if (!privkey)
		pos = find_tag (pem_cert_begin, contents, length);

	if (pos) {
		const char *end;

		pos += strlen (pem_cert_begin);
		end = find_tag (pem_cert_end, pos, contents + length - pos);
		if (end == NULL) {
			g_set_error (error, NM_CRYPTO_ERROR,
			             NM_CRYPTO_ERR_FILE_FORMAT_INVALID,
			             _("PEM certificate '%s' had no end tag '%s'."),
			             filename, pem_cert_end);
			goto done;
		}

		contents[end - contents - 1] = '\0';
		der = (char *) g_base64_decode (pos, &length);
		if (der == NULL || !length) {
			g_set_error (error, NM_CRYPTO_ERROR,
			             NM_CRYPTO_ERR_DECODE_FAILED,
			             _("Failed to decode certificate."));
			goto done;
		}
	}

	array = g_byte_array_sized_new (length);
	if (!array) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_OUT_OF_MEMORY,
		             _("Not enough memory to store certificate data."));
		goto done;
	}

	g_byte_array_append (array, der ? (unsigned char *) der : (unsigned char *) contents, length);
	if (array->len != length) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_OUT_OF_MEMORY,
		             _("Not enough memory to store file data."));
		g_byte_array_free (array, TRUE);
		array = NULL;
	}

done:
	g_free (der);
	g_free (contents);
	return array;
}

/*
 * Convert a hex string into bytes.
 */
static char *
convert_iv (const char *src,
            gsize *out_len,
            GError **error)
{
	int num;
	int i;
	char conv[3];
	char *c;

	g_return_val_if_fail (src != NULL, NULL);

	num = strlen (src);
	if (num % 2) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_RAW_IV_INVALID,
		             _("IV must be an even number of bytes in length."));
		return NULL;
	}

	num /= 2;
	c = g_malloc0 (num + 1);
	if (c == NULL) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_OUT_OF_MEMORY,
		             _("Not enough memory to store the IV."));
        return NULL;
	}

	conv[2] = '\0';
	for (i = 0; i < num; i++) {
        conv[0] = src[(i * 2)];
        conv[1] = src[(i * 2) + 1];
		if (!g_ascii_isxdigit (conv[0]) || !g_ascii_isxdigit (conv[1])) {
			g_set_error (error, NM_CRYPTO_ERROR,
			             NM_CRYPTO_ERR_RAW_IV_INVALID,
			             _("IV contains non-hexadecimal digits."));
			goto error;
		}

		c[i] = strtol(conv, NULL, 16);
	}
	*out_len = num;
	return c;

error:
	g_free (c);
	return NULL;
}

static char *
make_des_key (const char *cipher,
              const char *salt,
              const gsize salt_len,
              const char *password,
              gsize *out_len,
              GError **error)
{
	char *key;
	guint32 digest_len;

	g_return_val_if_fail (cipher != NULL, NULL);
	g_return_val_if_fail (salt != NULL, NULL);
	g_return_val_if_fail (salt_len >= 8, NULL);
	g_return_val_if_fail (password != NULL, NULL);
	g_return_val_if_fail (out_len != NULL, NULL);

	if (!strcmp (cipher, "DES-EDE3-CBC"))
		digest_len = 24;
	else if (!strcmp (cipher, "DES-CBC"))
		digest_len = 8;
	else {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_UNKNOWN_CIPHER,
		             _("Private key cipher '%s' was unknown."),
		             cipher);
		return NULL;
	}

	key = g_malloc0 (digest_len + 1);
	if (!key) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_OUT_OF_MEMORY,
		             _("Not enough memory to decrypt private key."));
		return NULL;
	}

	if (!crypto_md5_hash (salt,
	                      salt_len,
	                      password,
	                      strlen (password),
	                      key,
	                      digest_len,
	                      error))
		goto error;

	*out_len = digest_len;
	return key;

error:
	if (key) {
		/* Don't leak stale key material */
		memset (key, 0, digest_len);
		g_free (key);
	}
	return NULL;
}

static char *
decrypt_key (const char *cipher,
             int key_type,
             GByteArray *data,
             const char *iv,
             const char *password,
             gsize *out_len,
             GError **error)
{
	char *bin_iv = NULL;
	gsize bin_iv_len = 0;
	char *key = NULL;
	gsize key_len = 0;
	char *output = NULL;

	bin_iv = convert_iv (iv, &bin_iv_len, error);
	if (!bin_iv)
		return NULL;

	/* Convert the PIN and IV into a DES key */
	key = make_des_key (cipher, bin_iv, bin_iv_len, password, &key_len, error);
	if (!key || !key_len)
		goto out;

	output = crypto_decrypt (cipher, key_type,
	                         data,
	                         bin_iv, bin_iv_len,
	                         key, key_len,
	                         out_len,
	                         error);
	if (!output)
		goto out;

	if (*out_len == 0) {
		g_free (output);
		output = NULL;
		goto out;
	}
 
out:
	if (key) {
		/* Don't leak stale key material */
		memset (key, 0, key_len);
		g_free (key);
	}
	g_free (bin_iv);
	return output;
}

GByteArray *
crypto_get_private_key_data (GByteArray *contents,
                             const char *password,
                             NMCryptoKeyType *out_key_type,
                             NMCryptoFileFormat *out_file_type,
                             GError **error)
{
	GByteArray *array = NULL;
	NMCryptoKeyType key_type = NM_CRYPTO_KEY_TYPE_RSA;
	GByteArray *data;
	char *iv = NULL;
	char *cipher = NULL;
	char *decrypted = NULL;
	gsize decrypted_len = 0;

	g_return_val_if_fail (contents != NULL, NULL);
	g_return_val_if_fail (password != NULL, NULL);
	g_return_val_if_fail (out_key_type != NULL, NULL);
	g_return_val_if_fail (*out_key_type == NM_CRYPTO_KEY_TYPE_UNKNOWN, NULL);
	g_return_val_if_fail (out_file_type != NULL, NULL);
	g_return_val_if_fail (*out_file_type == NM_CRYPTO_FILE_FORMAT_UNKNOWN, NULL);

	/* Try PKCS#12 first */
	if (crypto_verify_pkcs12 (contents, password, NULL)) {
		*out_key_type = NM_CRYPTO_KEY_TYPE_ENCRYPTED;
		*out_file_type = NM_CRYPTO_FILE_FORMAT_PKCS12;

		array = g_byte_array_sized_new (contents->len);
		g_byte_array_append (array, contents->data, contents->len);
		return array;
	}

	/* OpenSSL non-standard legacy PEM files */

	/* Try RSA keys first */
	data = parse_old_openssl_key_file (contents, key_type, &cipher, &iv, error);
	if (!data) {
		g_clear_error (error);

		/* DSA next */
		key_type = NM_CRYPTO_KEY_TYPE_DSA;
		data = parse_old_openssl_key_file (contents, key_type, &cipher, &iv, error);
		if (!data) {
			g_clear_error (error);
			g_set_error (error, NM_CRYPTO_ERROR,
			             NM_CRYPTO_ERR_FILE_FORMAT_INVALID,
			             _("Unable to determine private key type."));
			goto out;
		}
	}

	decrypted = decrypt_key (cipher,
	                         key_type,
	                         data,
	                         iv,
	                         password,
	                         &decrypted_len,
	                         error);
	if (!decrypted)
		goto out;

	array = g_byte_array_sized_new (decrypted_len);
	if (!array) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_OUT_OF_MEMORY,
		             _("Not enough memory to store decrypted private key."));
		goto out;
	}

	g_byte_array_append (array, (const guint8 *) decrypted, decrypted_len);
	*out_key_type = key_type;
	*out_file_type = NM_CRYPTO_FILE_FORMAT_RAW_KEY;

out:
	if (decrypted) {
		/* Don't expose key material */
		memset (decrypted, 0, decrypted_len);
		g_free (decrypted);
	}
	if (data)
		g_byte_array_free (data, TRUE);
	g_free (cipher);
	g_free (iv);
	return array;
}

GByteArray *
crypto_get_private_key (const char *file,
                        const char *password,
                        NMCryptoKeyType *out_key_type,
                        NMCryptoFileFormat *out_file_type,
                        GError **error)
{
	GByteArray *contents;
	GByteArray *key = NULL;

	contents = file_to_g_byte_array (file, TRUE, error);
	if (contents) {
		key = crypto_get_private_key_data (contents, password, out_key_type, out_file_type, error);
		g_byte_array_free (contents, TRUE);
	}
	return key;
}

GByteArray *
crypto_load_and_verify_certificate (const char *file,
                                    NMCryptoFileFormat *out_file_format,
                                    GError **error)
{
	GByteArray *array;

	g_return_val_if_fail (file != NULL, NULL);
	g_return_val_if_fail (out_file_format != NULL, NULL);
	g_return_val_if_fail (*out_file_format == NM_CRYPTO_FILE_FORMAT_UNKNOWN, NULL);

	array = file_to_g_byte_array (file, FALSE, error);
	if (!array)
		return NULL;

	*out_file_format = crypto_verify_cert (array->data, array->len, error);
	if (*out_file_format == NM_CRYPTO_FILE_FORMAT_UNKNOWN) {
		/* Try PKCS#12 */
		if (crypto_is_pkcs12_data (array)) {
			*out_file_format = NM_CRYPTO_FILE_FORMAT_PKCS12;
			g_clear_error (error);
		} else {
			g_byte_array_free (array, TRUE);
			array = NULL;
		}
	}

	return array;
}

gboolean
crypto_is_pkcs12_data (const GByteArray *data)
{
	GError *error = NULL;
	gboolean success;

	g_return_val_if_fail (data != NULL, FALSE);

	success = crypto_verify_pkcs12 (data, NULL, &error);
	if (success)
		return TRUE;

	/* If the error was just a decryption error, then it's pkcs#12 */
	if (error) {
		if (g_error_matches (error, NM_CRYPTO_ERROR, NM_CRYPTO_ERR_CIPHER_DECRYPT_FAILED))
			success = TRUE;
		g_error_free (error);		
	}

	return success;
}

gboolean
crypto_is_pkcs12_file (const char *file, GError **error)
{
	GByteArray *contents;
	gboolean success = FALSE;

	g_return_val_if_fail (file != NULL, FALSE);

	contents = file_to_g_byte_array (file, TRUE, error);
	if (contents) {
		success = crypto_is_pkcs12_data (contents);
		g_byte_array_free (contents, TRUE);
	}
	return success;
}

