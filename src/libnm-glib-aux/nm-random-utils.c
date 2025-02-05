/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 * Copyright (C) 2025 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "libnm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nm-random-utils.h"

#include <fcntl.h>
#include <sys/auxv.h>
#include <sys/syscall.h>
#include <poll.h>

#if USE_SYS_RANDOM_H
#include <sys/random.h>
#else
#include <linux/random.h>
#endif

#include "nm-shared-utils.h"
#include "nm-time-utils.h"

/*****************************************************************************/

#if !defined(SYS_getrandom) && defined(__NR_getrandom)
#define SYS_getrandom __NR_getrandom
#endif

#ifndef GRND_NONBLOCK
#define GRND_NONBLOCK 0x01
#endif

#ifndef GRND_INSECURE
#define GRND_INSECURE 0x04
#endif

#if !HAVE_GETRANDOM
static ssize_t
getrandom(void *buf, size_t buflen, unsigned flags)
{
#if defined(SYS_getrandom)
    return syscall(SYS_getrandom, buf, buflen, flags);
#else
    errno = ENOSYS;
    return -1;
#endif
}
#endif

/*****************************************************************************/

static ssize_t
getrandom_full(void *buf, size_t count, unsigned flags)
{
    ssize_t  ret;
    uint8_t *p = buf;

    do {
        ret = getrandom(p, count, flags);
        if (ret < 0 && errno == EINTR)
            continue;
        else if (ret < 0)
            return ret;
        p += ret;
        count -= ret;
    } while (count);
    return 0;
}

static void
dev_random_wait(void)
{
    static bool   has_waited = false;
    struct pollfd random_fd  = {.events = POLLIN};
    int           ret;

    if (has_waited)
        return;

    random_fd.fd = open("/dev/random", O_RDONLY);
    nm_assert(random_fd.fd >= 0);
    for (;;) {
        ret = poll(&random_fd, 1, -1);
        if (ret == 1)
            break;
        nm_assert(ret == -1 && errno == EINTR);
    }
    nm_close(random_fd.fd);
    has_waited = true;
}

static ssize_t
dev_urandom_read_full(void *buf, size_t count)
{
    nm_auto_close int fd = open("/dev/urandom", O_RDONLY);

    nm_assert(fd >= 0);
    return nm_utils_fd_read_loop_exact(fd, buf, count, FALSE);
}

/**
 * nm_random_get_bytes:
 * @p: the buffer to fill
 * @n: the number of bytes to fill
 */
void
nm_random_get_bytes(void *p, size_t n)
{
    ssize_t ret;

    ret = getrandom_full(p, n, 0);
    if (ret == 0)
        return;
    nm_assert(ret == 0 || (ret == -1 && errno == ENOSYS));

    dev_random_wait();
    ret = dev_urandom_read_full(p, n);
    nm_assert(ret == 0);
}

/*****************************************************************************/

guint64
nm_random_u64_range(guint64 begin, guint64 end)
{
    guint64 remainder;
    guint64 maxvalue;
    guint64 x;
    guint64 m;

    /* Returns a random #guint64 equally distributed in the range [@begin..@end-1]. */

    if (begin >= end) {
        /* systemd's random_u64_range(0) is an alias for nm_random_u64().
         * Not for us. It's a caller error to request an element from an empty range. */
        return nm_assert_unreachable_val(begin);
    }

    m = end - begin;

    if (m == 1) {
        x = 0;
        goto out;
    }

    remainder = G_MAXUINT64 % m;
    maxvalue  = G_MAXUINT64 - remainder;

    do
        nm_random_get_bytes(&x, sizeof(x));
    while (x >= maxvalue);

out:
    return begin + (x % m);
}
