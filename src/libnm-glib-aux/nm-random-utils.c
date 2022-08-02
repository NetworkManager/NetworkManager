/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
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
_getrandom(void *buf, size_t buflen, unsigned flags)
{
    static int have_getrandom = TRUE;
    ssize_t    l;
    int        errsv;

    nm_assert(buflen > 0);

    /* This calls getrandom() and either returns the positive
     * success or an negative errno. ENOSYS means getrandom()
     * call is not supported. That result is cached and we don't retry. */

    if (!have_getrandom)
        return -ENOSYS;

    l = getrandom(buf, buflen, flags);
    if (l > 0)
        return l;
    if (l == 0)
        return -EIO;
    errsv = errno;
    if (errsv == ENOSYS)
        have_getrandom = FALSE;
    return -errsv;
}

static ssize_t
_getrandom_insecure(void *buf, size_t buflen)
{
    static int have_grnd_insecure = TRUE;
    ssize_t    l;

    /* GRND_INSECURE was added recently. We catch EINVAL
     * if kernel does not support the flag (and cache it). */

    if (!have_grnd_insecure)
        return -EINVAL;

    l = _getrandom(buf, buflen, GRND_INSECURE);

    if (l == -EINVAL)
        have_grnd_insecure = FALSE;

    return l;
}

static ssize_t
_getrandom_best_effort(void *buf, size_t buflen)
{
    ssize_t l;

    /* To get best-effort bytes, we would use GRND_INSECURE (and we try that
     * first). However, not all kernel versions support that, so we fallback
     * to GRND_NONBLOCK.
     *
     * Granted, this is called from a fallback path where we have no entropy
     * already, it's unlikely that GRND_NONBLOCK would succeed. Still... */
    l = _getrandom_insecure(buf, buflen);
    if (l != -EINVAL)
        return l;

    return _getrandom(buf, buflen, GRND_NONBLOCK);
}

static int
_random_check_entropy(gboolean block)
{
    static gboolean   seen_high_quality = FALSE;
    nm_auto_close int fd                = -1;
    int               r;

    /* We come here because getrandom() gave ENOSYS. We will fallback to /dev/urandom,
     * but the caller wants to know whether we have high quality numbers. Poll
     * /dev/random to find out. */

    if (seen_high_quality) {
        /* We cache the positive result. Once kernel has entropy, we will get
         * good random numbers. */
        return 1;
    }

    fd = open("/dev/random", O_RDONLY | O_CLOEXEC | O_NOCTTY);
    if (fd < 0)
        return -errno;

    r = nm_utils_fd_wait_for_event(fd, POLLIN, block ? -1 : 0);

    if (r <= 0) {
        nm_assert(r < 0 || !block);
        return r;
    }

    nm_assert(r == 1);
    seen_high_quality = TRUE;
    return 1;
}

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
    guint8 rand_vals_getrandom[16];
    gint64 rand_vals_timestamp;
} BadRandState;

static void
_bad_random_init_seed(BadRandSeed *seed)
{
    const guint8 *p_at_random;
    int           seed_idx;
    GRand        *rand;

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

    _getrandom_best_effort(seed->getrandom_buf, sizeof(seed->getrandom_buf));

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
        static GRand       *gl_rand;
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

        _getrandom_best_effort(gl_state.rand_vals_getrandom, sizeof(gl_state.rand_vals_getrandom));

        gl_state.rand_vals_timestamp = nm_utils_clock_gettime_nsec(CLOCK_BOOTTIME);

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

/*****************************************************************************/

/**
 * nm_random_get_bytes_full:
 * @p: the buffer to fill
 * @n: the number of bytes to write to @p.
 * @out_high_quality: (allow-none) (out): whether the returned
 *   random bytes are of high quality.
 *
 * - will never block
 * - will always produce some numbers, but they may not
 *   be of high quality.
 * - Whether they are of high quality, you can know via @out_high_quality.
 * - will always try hard to produce high quality numbers, and on success
 *   they are as good as nm_random_get_crypto_bytes().
 */
void
nm_random_get_bytes_full(void *p, size_t n, gboolean *out_high_quality)
{
    int      fd;
    int      r;
    gboolean has_high_quality;
    ssize_t  l;

    if (n == 0) {
        NM_SET_OUT(out_high_quality, TRUE);
        return;
    }

    g_return_if_fail(p);

again_getrandom:
    l = _getrandom(p, n, GRND_NONBLOCK);
    if (l > 0) {
        if ((size_t) l == n) {
            NM_SET_OUT(out_high_quality, TRUE);
            return;
        }
        p = ((uint8_t *) p) + l;
        n -= l;
        goto again_getrandom;
    }

    /* getrandom() failed. Fallback to read /dev/urandom. */

    if (l == -ENOSYS) {
        /* no support for getrandom(). */
        if (out_high_quality) {
            /* The caller wants to know whether we have high quality. Poll /dev/random
             * to find out. */
            has_high_quality = (_random_check_entropy(FALSE) > 0);
        } else {
            /* The value doesn't matter in this case. It will be unused. */
            has_high_quality = FALSE;
        }
    } else {
        /* Any other failure of getrandom() means we don't have high quality. */
        has_high_quality = FALSE;
        if (l == -EAGAIN) {
            /* getrandom(GRND_NONBLOCK) failed because lack of entropy. Retry with GRND_INSECURE. */
            for (;;) {
                l = _getrandom_insecure(p, n);
                if (l > 0) {
                    if ((size_t) l == n) {
                        NM_SET_OUT(out_high_quality, FALSE);
                        return;
                    }
                    p = ((uint8_t *) p) + l;
                    n -= l;
                    continue;
                }
                /* Any error. Fallback to /dev/urandom. */
                break;
            }
        }
    }

again_open:
    fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC | O_NOCTTY);
    if (fd < 0) {
        if (errno == EINTR)
            goto again_open;
    } else {
        r = nm_utils_fd_read_loop_exact(fd, p, n, TRUE);
        nm_close(fd);
        if (r >= 0) {
            NM_SET_OUT(out_high_quality, has_high_quality);
            return;
        }
    }

    /* we failed to fill the bytes reading from /dev/urandom.
     * Fill the bits using our fallback approach (which obviously
     * cannot give high quality random).
     */
    _bad_random_bytes(p, n);
    NM_SET_OUT(out_high_quality, FALSE);
}

/*****************************************************************************/

/**
 * nm_random_get_crypto_bytes:
 * @p: the buffer to fill
 * @n: the number of bytes to fill
 *
 * - can fail (in which case a negative number is returned
 *   and the output buffer is undefined).
 * - will block trying to get high quality random numbers.
 */
int
nm_random_get_crypto_bytes(void *p, size_t n)
{
    nm_auto_close int fd = -1;
    ssize_t           l;
    int               r;

    if (n == 0)
        return 0;

    nm_assert(p);

again_getrandom:
    l = _getrandom(p, n, 0);
    if (l > 0) {
        if ((size_t) l == n)
            return 0;
        p = (uint8_t *) p + l;
        n -= l;
        goto again_getrandom;
    }

    if (l != -ENOSYS) {
        /* We got a failure, but getrandom seems to be working in principle. We
         * won't get good numbers. Fail. */
        return l;
    }

    /* getrandom() failed with ENOSYS. Fallback to reading /dev/urandom. */

    r = _random_check_entropy(TRUE);
    if (r < 0)
        return r;
    if (r == 0)
        return nm_assert_unreachable_val(-EIO);

    fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC | O_NOCTTY);
    if (fd < 0)
        return -errno;

    return nm_utils_fd_read_loop_exact(fd, p, n, FALSE);
}
