/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#ifndef __NM_RANDOM_UTILS_H__
#define __NM_RANDOM_UTILS_H__

void nm_random_get_bytes_full(void *p, size_t n, gboolean *out_high_quality);

static inline void
nm_random_get_bytes(void *p, size_t n)
{
    nm_random_get_bytes_full(p, n, NULL);
}

int nm_random_get_crypto_bytes(void *p, size_t n);

static inline guint32
nm_random_u32(void)
{
    guint32 v;

    nm_random_get_bytes(&v, sizeof(v));
    return v;
}

static inline guint64
nm_random_u64(void)
{
    guint64 v;

    nm_random_get_bytes(&v, sizeof(v));
    return v;
}

static inline bool
nm_random_bool(void)
{
    guint8 ch;

    nm_random_get_bytes(&ch, sizeof(ch));
    return ch % 2u;
}

guint64 nm_random_u64_range_full(guint64 begin, guint64 end, gboolean crypto_bytes);

static inline guint64
nm_random_u64_range(guint64 end)
{
    return nm_random_u64_range_full(0, end, FALSE);
}

#endif /* __NM_RANDOM_UTILS_H__ */
