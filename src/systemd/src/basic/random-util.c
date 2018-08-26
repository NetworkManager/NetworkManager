/* SPDX-License-Identifier: LGPL-2.1+ */

#include "nm-sd-adapt.h"

#ifdef __x86_64__
#include <cpuid.h>
#endif

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/random.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#if HAVE_SYS_AUXV_H
#  include <sys/auxv.h>
#endif

#if USE_SYS_RANDOM_H
#  include <sys/random.h>
#else
#  include <linux/random.h>
#endif

#include "fd-util.h"
#include "io-util.h"
#include "missing.h"
#include "random-util.h"
#include "time-util.h"


int rdrand64(uint64_t *ret) {

#ifdef __x86_64__
        static int have_rdrand = -1;
        unsigned char err;

        if (have_rdrand < 0) {
                uint32_t eax, ebx, ecx, edx;

                /* Check if RDRAND is supported by the CPU */
                if (__get_cpuid(1, &eax, &ebx, &ecx, &edx) == 0) {
                        have_rdrand = false;
                        return -EOPNOTSUPP;
                }

                have_rdrand = !!(ecx & (1U << 30));
        }

        if (have_rdrand == 0)
                return -EOPNOTSUPP;

        asm volatile("rdrand %0;"
                     "setc %1"
                     : "=r" (*ret),
                       "=qm" (err));
        if (!err)
                return -EAGAIN;

        return 0;
#else
        return -EOPNOTSUPP;
#endif
}

int acquire_random_bytes(void *p, size_t n, bool high_quality_required) {
        static int have_syscall = -1;

        _cleanup_close_ int fd = -1;
        size_t already_done = 0;
        int r;

        /* Gathers some randomness from the kernel. This call will never block. If
         * high_quality_required, it will always return some data from the kernel,
         * regardless of whether the random pool is fully initialized or not.
         * Otherwise, it will return success if at least some random bytes were
         * successfully acquired, and an error if the kernel has no entropy whatsover
         * for us. */

        /* Use the getrandom() syscall unless we know we don't have it. */
        if (have_syscall != 0 && !HAS_FEATURE_MEMORY_SANITIZER) {
#if !HAVE_GETRANDOM
                /* NetworkManager Note: systemd calls the syscall directly in this case. Don't add that workaround.
                 * If you don't compile against a libc that provides getrandom(), you don't get it. */
                r = -1;
                errno = ENOSYS;
#else
                r = getrandom(p, n, GRND_NONBLOCK);
#endif
                if (r > 0) {
                        have_syscall = true;
                        if ((size_t) r == n)
                                return 0;
                        if (!high_quality_required) {
                                /* Fill in the remaining bytes using pseudorandom values */
                                pseudorandom_bytes((uint8_t*) p + r, n - r);
                                return 0;
                        }

                        already_done = r;
                } else if (errno == ENOSYS)
                          /* We lack the syscall, continue with reading from /dev/urandom. */
                          have_syscall = false;
                else if (errno == EAGAIN) {
                        /* The kernel has no entropy whatsoever. Let's remember to
                         * use the syscall the next time again though.
                         *
                         * If high_quality_required is false, return an error so that
                         * random_bytes() can produce some pseudorandom
                         * bytes. Otherwise, fall back to /dev/urandom, which we know
                         * is empty, but the kernel will produce some bytes for us on
                         * a best-effort basis. */
                        have_syscall = true;

                        if (!high_quality_required) {
                                uint64_t u;
                                size_t k;

                                /* Try x86-64' RDRAND intrinsic if we have it. We only use it if high quality
                                 * randomness is not required, as we don't trust it (who does?). Note that we only do a
                                 * single iteration of RDRAND here, even though the Intel docs suggest calling this in
                                 * a tight loop of 10 invocatins or so. That's because we don't really care about the
                                 * quality here. */

                                if (rdrand64(&u) < 0)
                                        return -ENODATA;

                                k = MIN(n, sizeof(u));
                                memcpy(p, &u, k);

                                /* We only get 64bit out of RDRAND, the rest let's fill up with pseudo-random crap. */
                                pseudorandom_bytes((uint8_t*) p + k, n - k);
                                return 0;
                        }
                } else
                        return -errno;
        }

        fd = open("/dev/urandom", O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0)
                return errno == ENOENT ? -ENOSYS : -errno;

        return loop_read_exact(fd, (uint8_t*) p + already_done, n - already_done, true);
}

void initialize_srand(void) {
        static bool srand_called = false;
        unsigned x;
#if HAVE_SYS_AUXV_H
        void *auxv;
#endif

        if (srand_called)
                return;

#if HAVE_SYS_AUXV_H
        /* The kernel provides us with 16 bytes of entropy in auxv, so let's
         * try to make use of that to seed the pseudo-random generator. It's
         * better than nothing... */

        auxv = (void*) getauxval(AT_RANDOM);
        if (auxv) {
                assert_cc(sizeof(x) <= 16);
                memcpy(&x, auxv, sizeof(x));
        } else
#endif
                x = 0;

        x ^= (unsigned) now(CLOCK_REALTIME);
        x ^= (unsigned) gettid();

        srand(x);
        srand_called = true;
}

/* INT_MAX gives us only 31 bits, so use 24 out of that. */
#if RAND_MAX >= INT_MAX
#  define RAND_STEP 3
#else
/* SHORT_INT_MAX or lower gives at most 15 bits, we just just 8 out of that. */
#  define RAND_STEP 1
#endif

void pseudorandom_bytes(void *p, size_t n) {
        uint8_t *q;

        initialize_srand();

        for (q = p; q < (uint8_t*) p + n; q += RAND_STEP) {
                unsigned rr;

                rr = (unsigned) rand();

#if RAND_STEP >= 3
                if ((size_t) (q - (uint8_t*) p + 2) < n)
                        q[2] = rr >> 16;
#endif
#if RAND_STEP >= 2
                if ((size_t) (q - (uint8_t*) p + 1) < n)
                        q[1] = rr >> 8;
#endif
                q[0] = rr;
        }
}

void random_bytes(void *p, size_t n) {
        int r;

        r = acquire_random_bytes(p, n, false);
        if (r >= 0)
                return;

        /* If some idiot made /dev/urandom unavailable to us, or the
         * kernel has no entropy, use a PRNG instead. */
        return pseudorandom_bytes(p, n);
}
