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

#endif /* __NM_RANDOM_UTILS_H__ */
