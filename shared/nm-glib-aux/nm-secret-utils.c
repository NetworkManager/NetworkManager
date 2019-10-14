// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2018 Red Hat, Inc.
 * Copyright (C) 2015 - 2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "nm-default.h"

#include "nm-secret-utils.h"

/*****************************************************************************/

void
nm_explicit_bzero (void *s, gsize n)
{
	/* gracefully handle n == 0. This is important, callers rely on it. */
	if (n == 0)
		return;

	nm_assert (s);

#if defined (HAVE_DECL_EXPLICIT_BZERO) && HAVE_DECL_EXPLICIT_BZERO
	explicit_bzero (s, n);
#else
	{
		volatile guint8 *p = s;

		memset (s, '\0', n);
		while (n-- > 0)
			*(p++) = '\0';
	}
#endif
}

/*****************************************************************************/

char *
nm_secret_strchomp (char *secret)
{
	gsize len;

	g_return_val_if_fail (secret, NULL);

	/* it's actually identical to g_strchomp(). However,
	 * the glib function does not document, that it clears the
	 * memory. For @secret, we don't only want to truncate trailing
	 * spaces, we want to overwrite them with NUL. */

	len = strlen (secret);
	while (len--) {
		if (g_ascii_isspace ((guchar) secret[len]))
			secret[len] = '\0';
		else
			break;
	}

	return secret;
}

/*****************************************************************************/

GBytes *
nm_secret_copy_to_gbytes (gconstpointer mem, gsize mem_len)
{
	NMSecretBuf *b;

	if (mem_len == 0)
		return g_bytes_new_static ("", 0);

	nm_assert (mem);

	/* NUL terminate the buffer.
	 *
	 * The entire buffer is already malloc'ed and likely has some room for padding.
	 * Thus, in many situations, this additional byte will cause no overhead in
	 * practice.
	 *
	 * Even if it causes an overhead, do it just for safety. Yes, the returned
	 * bytes is not a NUL terminated string and no user must rely on this. Do
	 * not treat binary data as NUL terminated strings, unless you know what
	 * you are doing. Anyway, defensive FTW.
	 */

	b = nm_secret_buf_new (mem_len + 1);
	memcpy (b->bin, mem, mem_len);
	b->bin[mem_len] = 0;
	return nm_secret_buf_to_gbytes_take (b, mem_len);
}

/*****************************************************************************/

NMSecretBuf *
nm_secret_buf_new (gsize len)
{
	NMSecretBuf *secret;

	nm_assert (len > 0);

	secret = g_malloc (sizeof (NMSecretBuf) + len);
	*((gsize *) &(secret->len)) = len;
	return secret;
}

static void
_secret_buf_free (gpointer user_data)
{
	NMSecretBuf *secret = user_data;

	nm_assert (secret);
	nm_assert (secret->len > 0);

	nm_explicit_bzero (secret->bin, secret->len);
	g_free (user_data);
}

GBytes *
nm_secret_buf_to_gbytes_take (NMSecretBuf *secret, gssize actual_len)
{
	nm_assert (secret);
	nm_assert (secret->len > 0);
	nm_assert (actual_len == -1 || (actual_len >= 0 && actual_len <= secret->len));
	return g_bytes_new_with_free_func (secret->bin,
	                                   actual_len >= 0 ? (gsize) actual_len : secret->len,
	                                   _secret_buf_free,
	                                   secret);
}

/*****************************************************************************/

/**
 * nm_utils_memeqzero_secret:
 * @data: the data pointer to check (may be %NULL if @length is zero).
 * @length: the number of bytes to check.
 *
 * Checks that all bytes are zero. This always takes the same amount
 * of time to prevent timing attacks.
 *
 * Returns: whether all bytes are zero.
 */
gboolean
nm_utils_memeqzero_secret (gconstpointer data, gsize length)
{
	const guint8 *const key = data;
	volatile guint8 acc = 0;
	gsize i;

	for (i = 0; i < length; i++) {
		acc |= key[i];
		asm volatile("" : "=r"(acc) : "0"(acc));
	}
	return 1 & ((acc - 1) >> 8);
}
