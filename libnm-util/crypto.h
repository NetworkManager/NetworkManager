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
 * Copyright 2007 - 2014 Red Hat, Inc.
 */

#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include "nm-default.h"

#define MD5_HASH_LEN 20
#define CIPHER_DES_EDE3_CBC "DES-EDE3-CBC"
#define CIPHER_DES_CBC "DES-CBC"
#define CIPHER_AES_CBC "AES-128-CBC"

enum {
	NM_CRYPTO_ERR_NONE = 0,
	NM_CRYPTO_ERR_INIT_FAILED,
	NM_CRYPTO_ERR_CANT_READ_FILE,
	NM_CRYPTO_ERR_FILE_FORMAT_INVALID,
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
	NM_CRYPTO_ERR_INVALID_PASSWORD,
	NM_CRYPTO_ERR_CIPHER_ENCRYPT_FAILED,
	NM_CRYPTO_ERR_RANDOMIZE_FAILED
};

typedef enum {
	NM_CRYPTO_KEY_TYPE_UNKNOWN = 0,
	NM_CRYPTO_KEY_TYPE_RSA,
	NM_CRYPTO_KEY_TYPE_DSA
} NMCryptoKeyType;

typedef enum {
	NM_CRYPTO_FILE_FORMAT_UNKNOWN = 0,
	NM_CRYPTO_FILE_FORMAT_X509,
	NM_CRYPTO_FILE_FORMAT_RAW_KEY,
	NM_CRYPTO_FILE_FORMAT_PKCS12
} NMCryptoFileFormat;

#define NM_CRYPTO_ERROR _nm_crypto_error_quark ()
GQuark _nm_crypto_error_quark (void);

gboolean crypto_init (GError **error);

GByteArray *crypto_decrypt_private_key_data (const GByteArray *contents,
                                             const char *password,
                                             NMCryptoKeyType *out_key_type,
                                             GError **error);

GByteArray *crypto_decrypt_private_key (const char *file,
                                        const char *password,
                                        NMCryptoKeyType *out_key_type,
                                        GError **error);

GByteArray *crypto_load_and_verify_certificate (const char *file,
                                                NMCryptoFileFormat *out_file_format,
                                                GError **error);

gboolean crypto_is_pkcs12_file (const char *file, GError **error);

gboolean crypto_is_pkcs12_data (const GByteArray *data);

NMCryptoFileFormat crypto_verify_private_key_data (const GByteArray *contents,
                                                   const char *password,
                                                   GError **error);

NMCryptoFileFormat crypto_verify_private_key (const char *file,
                                              const char *password,
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
                       GByteArray *data,
                       const char *iv,
                       const gsize iv_len,
                       const char *key,
                       const gsize key_len,
                       gsize *out_len,
                       GError **error);

char * crypto_encrypt (const char *cipher,
                       const GByteArray *data,
                       const char *iv,
                       gsize iv_len,
                       const char *key,
                       gsize key_len,
                       gsize *out_len,
                       GError **error);

gboolean crypto_randomize (void *buffer, gsize buffer_len, GError **error);

NMCryptoFileFormat crypto_verify_cert (const unsigned char *data,
                                       gsize len,
                                       GError **error);

gboolean crypto_verify_pkcs12 (const GByteArray *data,
                               const char *password,
                               GError **error);

gboolean crypto_verify_pkcs8 (const GByteArray *data,
                              gboolean is_encrypted,
                              const char *password,
                              GError **error);

#endif  /* __CRYPTO_H__ */
