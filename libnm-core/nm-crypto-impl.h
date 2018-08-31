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
 * Copyright 2007 - 2018 Red Hat, Inc.
 */

#ifndef __NM_CRYPTO_IMPL_H__
#define __NM_CRYPTO_IMPL_H__

#if !((NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_CORE_PRIVATE)
#error Cannot use this header.
#endif

#include "nm-crypto.h"

gboolean _nm_crypto_init (GError **error);

gboolean _nm_crypto_randomize (void *buffer, gsize buffer_len, GError **error);

gboolean _nm_crypto_verify_x509 (const guint8 *data,
                                 gsize len,
                                 GError **error);

gboolean _nm_crypto_verify_pkcs12 (const guint8 *data,
                                   gsize data_len,
                                   const char *password,
                                   GError **error);

gboolean _nm_crypto_verify_pkcs8 (const guint8 *data,
                                  gsize data_len,
                                  gboolean is_encrypted,
                                  const char *password,
                                  GError **error);

/*****************************************************************************/

guint8 *_nmtst_crypto_encrypt (NMCryptoCipherType cipher,
                               const guint8 *data,
                               gsize data_len,
                               const guint8 *iv,
                               gsize iv_len,
                               const guint8 *key,
                               gsize key_len,
                               gsize *out_len,
                               GError **error);

guint8 *_nmtst_crypto_decrypt (NMCryptoCipherType cipher,
                               const guint8 *data,
                               gsize data_len,
                               const guint8 *iv,
                               gsize iv_len,
                               const guint8 *key,
                               gsize key_len,
                               gsize *out_len,
                               GError **error);

#endif  /* __NM_CRYPTO_IMPL_H__ */
