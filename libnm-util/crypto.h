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

#define MD5_HASH_LEN 20
#define CIPHER_DES_EDE3_CBC "DES-EDE3-CBC"
#define CIPHER_DES_CBC "DES-CBC"

enum {
	NM_CRYPTO_ERR_NONE = 0,
	NM_CRYPTO_ERR_CANT_READ_FILE,
	NM_CRYPTO_ERR_PEM_FORMAT_INVALID,
	NM_CRYPTO_ERR_CERT_FORMAT_INVALID,
	NM_CRYPTO_ERR_DECODE_FAILED,
	NM_CRYPTO_ERR_OUT_OF_MEMORY,
	NM_CRYPTO_ERR_UNKNOWN_KEY_TYPE,
	NM_CRYPTO_ERR_UNKNOWN_CIPHER,
	NM_CRYPTO_ERR_RAW_IV_INVALID,
	NM_CRYPTO_ERR_MD5_INIT_FAILED,
	NM_CRYPTO_ERR_CIPHER_INIT_FAILED,
	NM_CRYPTO_ERR_CIPHER_SET_KEY_FAILED,
	NM_CRYPTO_ERR_CIPHER_SET_IV_FAILED,
	NM_CRYPTO_ERR_CIPHER_DECRYPT_FAILED,
};

enum {
	NM_CRYPTO_KEY_TYPE_UNKNOWN = 0,
	NM_CRYPTO_KEY_TYPE_RSA,
	NM_CRYPTO_KEY_TYPE_DSA,
};


#define NM_CRYPTO_ERROR nm_crypto_error_quark ()
GQuark nm_crypto_error_quark (void);

gboolean crypto_init (GError **error);

void crypto_deinit (void);

GByteArray * crypto_get_private_key (const char *file,
                                     const char *password,
                                     guint32 *out_key_type,
                                     GError **error);

GByteArray * crypto_load_and_verify_certificate (const char *file,
                                                 GError **error);

/* Internal utils API bits for crypto providers */

gboolean crypto_md5_hash (const char *salt,
                          const gsize salt_len,
                          const char *password,
                          gsize password_len,
                          char *buffer,
                          gsize buflen,
                          GError **error);

char * crypto_decrypt (const char *cipher,
                       int key_type,
                       const char *data,
                       gsize data_len,
                       const char *iv,
                       const gsize iv_len,
                       const char *key,
                       const gsize key_len,
                       gsize *out_len,
                       GError **error);

gboolean crypto_verify_cert (const unsigned char *data,
                             gsize len,
                             GError **error);


