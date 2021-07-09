/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#include "libnm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nm-random-utils.h"

#include <fcntl.h>
#include <sys/auxv.h>

#if USE_SYS_RANDOM_H
#include <sys/random.h>
#else
#include <linux/random.h>
#endif

#include "nm-shared-utils.h"
#include "nm-time-utils.h"

/*****************************************************************************/

#define SEED_ARRAY_SIZE (16 + 2 + 4 + 2 + 3)

static guint32
_pid_hash(pid_t id)
{
    if (sizeof(pid_t) > sizeof(guint32))
        return (((guint64) id) >> 32) ^ ((guint64) id);
    return id;
}

static void
_rand_init_seed(guint32 seed_array[static SEED_ARRAY_SIZE], GRand *rand)
{
    int           seed_idx;
    const guint8 *p_at_random;
    guint64       now_nsec;

    /* Get some seed material from the provided GRand. */
    for (seed_idx = 0; seed_idx < 16; seed_idx++)
        seed_array[seed_idx] = g_rand_int(rand);

    /* Add an address from the heap. */
    seed_array[seed_idx++] = ((guint64) ((uintptr_t) ((gpointer) rand))) >> 32;
    seed_array[seed_idx++] = ((guint64) ((uintptr_t) ((gpointer) rand)));

    /* Add the per-process, random number. */
    p_at_random = ((gpointer) getauxval(AT_RANDOM));
    if (p_at_random) {
        memcpy(&seed_array[seed_idx], p_at_random, 16);
    } else
        memset(&seed_array[seed_idx], 0, 16);
    G_STATIC_ASSERT_EXPR(sizeof(guint32) == 4);
    seed_idx += 4;

    /* Add the current timestamp, the pid and ppid. */
    now_nsec               = nm_utils_clock_gettime_nsec(CLOCK_BOOTTIME);
    seed_array[seed_idx++] = ((guint64) now_nsec) >> 32;
    seed_array[seed_idx++] = ((guint64) now_nsec);
    seed_array[seed_idx++] = _pid_hash(getpid());
    seed_array[seed_idx++] = _pid_hash(getppid());
    seed_array[seed_idx++] = _pid_hash(nm_utils_gettid());

    nm_assert(seed_idx == SEED_ARRAY_SIZE);
}

static GRand *
_rand_create_thread_local(void)
{
    G_LOCK_DEFINE_STATIC(global_rand);
    static GRand *global_rand = NULL;
    guint32       seed_array[SEED_ARRAY_SIZE];

    /* We use thread-local instances of GRand to create a series of
     * "random" numbers. We use thread-local instances, so that we don't
     * require additional locking except the first time.
     *
     * We trust that once seeded, a GRand gives us a good enough stream of
     * random numbers. If that wouldn't be the case, then maybe GRand should
     * be fixed.
     * Also, we tell our callers that the numbers from GRand are not good.
     * But that isn't gonna help, because callers have no other way to get
     * better random numbers, so usually the just ignore the failure and make
     * the best of it.
     *
     * That means, the remaining problem is to seed the instance well.
     * Note that we are already in a situation where getrandom() failed
     * to give us good random numbers. So we can not do much to get reliably
     * good entropy for the seed. */

    G_LOCK(global_rand);

    if (G_UNLIKELY(!global_rand)) {
        GRand *rand1;

        /* g_rand_new() reads /dev/urandom, but we already noticed that
         * /dev/urandom fails to give us good randomness (which is why
         * we hit this code path). So this may not be as good as we wish,
         * but let's add it to the mix. */
        rand1 = g_rand_new();
        _rand_init_seed(seed_array, rand1);
        global_rand = g_rand_new_with_seed_array(seed_array, SEED_ARRAY_SIZE);
        g_rand_free(rand1);
    }

    _rand_init_seed(seed_array, global_rand);
    G_UNLOCK(global_rand);

    return g_rand_new_with_seed_array(seed_array, SEED_ARRAY_SIZE);
}

/**
 * nm_utils_random_bytes:
 * @p: the buffer to fill
 * @n: the number of bytes to write to @p.
 *
 * Uses getrandom() or reads /dev/urandom to fill the buffer
 * with random data. If all fails, as last fallback it uses
 * GRand to fill the buffer with pseudo random numbers.
 * The function always succeeds in writing some random numbers
 * to the buffer. The return value of FALSE indicates that the
 * obtained bytes are probably not of good randomness.
 *
 * Returns: whether the written bytes are good. If you
 * don't require good randomness, you can ignore the return
 * value.
 *
 * Note that if calling getrandom() fails because there is not enough
 * entropy (at early boot), the function will read /dev/urandom.
 * Which of course, still has low entropy, and cause kernel to log
 * a warning.
 */
gboolean
nm_utils_random_bytes(void *p, size_t n)
{
    int      fd;
    int      r;
    gboolean has_high_quality = TRUE;
    gboolean urandom_success;
    guint8 * buf           = p;
    gboolean avoid_urandom = FALSE;

    g_return_val_if_fail(p, FALSE);
    g_return_val_if_fail(n > 0, FALSE);

#if HAVE_GETRANDOM
    {
        static gboolean have_syscall = TRUE;

        if (have_syscall) {
            r = getrandom(buf, n, GRND_NONBLOCK);
            if (r > 0) {
                if ((size_t) r == n)
                    return TRUE;

                /* no or partial read. There is not enough entropy.
                 * Fill the rest reading from urandom, and remember that
                 * some bits are not high quality. */
                nm_assert(r < n);
                buf += r;
                n -= r;
                has_high_quality = FALSE;

                /* At this point, we don't want to read /dev/urandom, because
                 * the entropy pool is low (early boot?), and asking for more
                 * entropy causes kernel messages to be logged.
                 *
                 * We use our fallback via GRand. Note that g_rand_new() also
                 * tries to seed itself with data from /dev/urandom, but since
                 * we reuse the instance, it shouldn't matter. */
                avoid_urandom = TRUE;
            } else {
                if (errno == ENOSYS) {
                    /* no support for getrandom(). We don't know whether
                     * we urandom will give us good quality. Assume yes. */
                    have_syscall = FALSE;
                } else {
                    /* unknown error. We'll read urandom below, but we don't have
                     * high-quality randomness. */
                    has_high_quality = FALSE;
                }
            }
        }
    }
#endif

    urandom_success = FALSE;
    if (!avoid_urandom) {
fd_open:
        fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC | O_NOCTTY);
        if (fd < 0) {
            r = errno;
            if (r == EINTR)
                goto fd_open;
        } else {
            r = nm_utils_fd_read_loop_exact(fd, buf, n, TRUE);
            nm_close(fd);
            if (r >= 0)
                urandom_success = TRUE;
        }
    }

    if (!urandom_success) {
        static _nm_thread_local GRand *rand_tls = NULL;
        GRand *                        rand;
        gsize                          i;
        int                            j;

        /* we failed to fill the bytes reading from urandom.
         * Fill the bits using GRand pseudo random numbers.
         *
         * We don't have good quality.
         */
        has_high_quality = FALSE;

        rand = rand_tls;
        if (G_UNLIKELY(!rand)) {
            rand     = _rand_create_thread_local();
            rand_tls = rand;
            nm_utils_thread_local_register_destroy(rand, (GDestroyNotify) g_rand_free);
        }

        nm_assert(n > 0);
        i = 0;
        for (;;) {
            const union {
                guint32 v32;
                guint8  v8[4];
            } v = {
                .v32 = g_rand_int(rand),
            };

            for (j = 0; j < 4;) {
                buf[i++] = v.v8[j++];
                if (i >= n)
                    goto done;
            }
        }
done:;
    }

    return has_high_quality;
}
