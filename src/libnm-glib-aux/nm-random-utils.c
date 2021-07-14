/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#include "libnm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nm-random-utils.h"

#include <fcntl.h>
#include <sys/auxv.h>
#include <sys/syscall.h>

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

#if !HAVE_GETRANDOM && defined(SYS_getrandom)
static int
getrandom(void *buf, size_t buflen, unsigned flags)
{
    return syscall(SYS_getrandom, buf, buflen, flags);
}
    #undef HAVE_GETRANDOM
    #define HAVE_GETRANDOM 1
#endif

/*****************************************************************************/

typedef struct _nm_packed {
    uintptr_t heap_ptr;
    uintptr_t stack_ptr;
    gint64    now_bootime;
    gint64    now_real;
    pid_t     pid;
    pid_t     ppid;
    pid_t     tid;
    guint32   grand[16];
    guint8    auxval[16];
    guint8    getrandom_buf[20];
} BadRandSeed;

typedef struct _nm_packed {
    guint64 counter;
    union {
        guint8 full[NM_UTILS_CHECKSUM_LENGTH_SHA256];
        struct {
            guint8 half_1[NM_UTILS_CHECKSUM_LENGTH_SHA256 / 2];
            guint8 half_2[NM_UTILS_CHECKSUM_LENGTH_SHA256 / 2];
        };
    } sha_digest;
    union {
        guint8  u8[NM_UTILS_CHECKSUM_LENGTH_SHA256 / 2];
        guint32 u32[((NM_UTILS_CHECKSUM_LENGTH_SHA256 / 2) + 3) / 4];
    } rand_vals;
    GRand *rand;
} BadRandState;

static void
_bad_random_init_seed(BadRandSeed *seed)
{
    const guint8 *p_at_random;
    int           seed_idx;
    GRand *       rand;

    /* g_rand_new() reads /dev/urandom, but we already noticed that
     * /dev/urandom fails to give us good randomness (which is why
     * we hit the "bad randomness" code path). So this may not be as
     * good as we wish, but let's hope that it it does something smart
     * to give some extra entropy... */
    rand = g_rand_new();

    /* Get some seed material from a GRand. */
    for (seed_idx = 0; seed_idx < (int) G_N_ELEMENTS(seed->grand); seed_idx++)
        seed->grand[seed_idx] = g_rand_int(rand);

    /* Add an address from the heap and stack, maybe ASLR helps a bit? */
    seed->heap_ptr  = (uintptr_t) ((gpointer) rand);
    seed->stack_ptr = (uintptr_t) ((gpointer) &rand);

    g_rand_free(rand);

    /* Add the per-process, random number. */
    p_at_random = ((gpointer) getauxval(AT_RANDOM));
    if (p_at_random) {
        G_STATIC_ASSERT(sizeof(seed->auxval) == 16);
        memcpy(&seed->auxval, p_at_random, 16);
    }

#if HAVE_GETRANDOM
    {
        ssize_t r;

        /* This is likely to fail, because we already failed a moment earlier. Still, give
         * it a try. */
        r = getrandom(seed->getrandom_buf,
                      sizeof(seed->getrandom_buf),
                      GRND_INSECURE | GRND_NONBLOCK);
        (void) r;
    }
#endif

    seed->now_bootime = nm_utils_clock_gettime_nsec(CLOCK_BOOTTIME);
    seed->now_real    = g_get_real_time();
    seed->pid         = getpid();
    seed->ppid        = getppid();
    seed->tid         = nm_utils_gettid();
}

static void
_bad_random_bytes(guint8 *buf, gsize n)
{
    nm_auto_free_checksum GChecksum *sum = g_checksum_new(G_CHECKSUM_SHA256);

    nm_assert(n > 0);

    /* We are in the fallback code path, where getrandom() (and /dev/urandom) failed
     * to give us good randomness. Try our best.
     *
     * Our ability to get entropy for the CPRNG is very limited and thus the overall
     * result will not be good randomness. See _bad_random_init_seed().
     *
     * Once we have some seed material, we combine GRand (which is not a cryptographically
     * secure PRNG) with some iterative sha256 hashing. It would be nice if we had
     * easy access to chacha20, but it's probably more cumbersome to fork those
     * implementations than hack a bad CPRNG by using sha256 hashing. After all, this
     * is fallback code to get *some* randomness. And with the inability to get a good
     * seed, the CPRNG is not going to give us truly good randomness. */

    {
        static BadRandState gl_state;
        static GRand *      gl_rand;
        static GMutex       gl_mutex;
        NM_G_MUTEX_LOCKED(&gl_mutex);

        if (G_UNLIKELY(!gl_rand)) {
            union {
                BadRandSeed d_seed;
                guint32     d_u32[(sizeof(BadRandSeed) + 3) / 4];
            } data = {
                .d_u32 = {0},
            };

            _bad_random_init_seed(&data.d_seed);

            gl_rand = g_rand_new_with_seed_array(data.d_u32, G_N_ELEMENTS(data.d_u32));

            g_checksum_update(sum, (const guchar *) &data, sizeof(data));
            nm_utils_checksum_get_digest(sum, gl_state.sha_digest.full);
        }

        while (TRUE) {
            int i;

            gl_state.counter++;
            for (i = 0; i < G_N_ELEMENTS(gl_state.rand_vals.u32); i++)
                gl_state.rand_vals.u32[i] = g_rand_int(gl_rand);
            g_checksum_reset(sum);
            g_checksum_update(sum, (const guchar *) &gl_state, sizeof(gl_state));
            nm_utils_checksum_get_digest(sum, gl_state.sha_digest.full);

            /* gl_state.sha_digest.full and gl_state.rand_vals contain now our
             * random values, but they are also the state for the next iteration.
             * We must not directly expose that state to the caller, so XOR the values.
             *
             * That means, per iteration we can generate 16 bytes of randomness. That
             * is for example required to generate a random UUID. */
            for (i = 0; i < (int) (NM_UTILS_CHECKSUM_LENGTH_SHA256 / 2); i++) {
                nm_assert(n > 0);
                buf[0] = gl_state.sha_digest.half_1[i] ^ gl_state.sha_digest.half_2[i]
                         ^ gl_state.rand_vals.u8[i];
                buf++;
                n--;
                if (n == 0)
                    return;
            }
        }
    }
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
    guint8 * buf              = p;

    g_return_val_if_fail(p, FALSE);
    g_return_val_if_fail(n > 0, FALSE);

#if HAVE_GETRANDOM
    {
        static gboolean have_syscall = TRUE;

        if (have_syscall) {
            ssize_t r2;
            int     errsv;

            r2 = getrandom(buf, n, GRND_NONBLOCK);
            if (r2 >= 0) {
                if ((size_t) r2 == n)
                    return TRUE;

                /* no or partial read. There is not enough entropy.
                 * Fill the rest reading with the fallback code and remember
                 * that some bits are not high quality. */
                nm_assert((size_t) r2 < n);
                buf += r2;
                n -= r2;

                /* At this point, we don't want to read /dev/urandom, because
                 * the entropy pool is low (early boot?), and asking for more
                 * entropy causes kernel messages to be logged.
                 *
                 * Note that we fall back to _bad_random_bytes(), which (among others) seeds
                 * itself with g_rand_new(). That also will read /dev/urandom, but as
                 * we do that only once, we don't care. But in general, we are here in
                 * a situation where we want to avoid reading /dev/urandom too much. */
                goto out_bad_random;
            }
            errsv = errno;
            if (errsv == ENOSYS) {
                /* no support for getrandom(). We don't know whether
                 * we /dev/urandom will give us good quality. Assume yes. */
                have_syscall = FALSE;
            } else if (errsv == EAGAIN) {
                /* No entropy. We avoid reading /dev/urandom. */
                goto out_bad_random;
            } else {
                /* Unknown error, likely no entropy. We'll read /dev/urandom below, but we don't
                 * have high-quality randomness. */
                has_high_quality = FALSE;
            }
        }
    }
#endif

fd_open:
    fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC | O_NOCTTY);
    if (fd < 0) {
        if (errno == EINTR)
            goto fd_open;
        goto out_bad_random;
    }
    r = nm_utils_fd_read_loop_exact(fd, buf, n, TRUE);
    nm_close(fd);
    if (r >= 0)
        return has_high_quality;

out_bad_random:
    /* we failed to fill the bytes reading from /dev/urandom.
     * Fill the bits using our pseudo random numbers.
     *
     * We don't have good quality.
     */
    _bad_random_bytes(buf, n);
    return FALSE;
}
