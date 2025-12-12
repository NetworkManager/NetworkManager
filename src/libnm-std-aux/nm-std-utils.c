/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "nm-default-std.h"

#include "nm-std-utils.h"

#include <assert.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <net/if.h>
#include <pwd.h>
#include <stdint.h>
#include <sys/types.h>

/*****************************************************************************/

NM_STATIC_ASSERT(NM_IFNAMSIZ == IFNAMSIZ);

/*****************************************************************************/
size_t
nm_utils_get_next_realloc_size(bool true_realloc, size_t requested)
{
    size_t n, x;

    /* https://doc.qt.io/qt-5/containers.html#growth-strategies */

    if (requested <= 40) {
        /* small allocations. Increase in small steps of 8 bytes.
         *
         * We get thus sizes of 8, 16, 32, 40. */
        if (requested <= 8)
            return 8;
        if (requested <= 16)
            return 16;
        if (requested <= 32)
            return 32;

        /* The return values for < 104 are essentially hard-coded, and the choice here is
         * made without very strong reasons.
         *
         * We want to stay 24 bytes below the power-of-two border 64. Hence, return 40 here.
         * However, the next step then is already 104 (128 - 24). It's a larger gap than in
         * the steps before.
         *
         * It's not clear whether some of the steps should be adjusted (or how exactly). */
        return 40;
    }

    if (requested <= 0x2000u - 24u || NM_UNLIKELY(!true_realloc)) {
        /* mid sized allocations. Return next power of two, minus 24 bytes extra space
         * at the beginning.
         * That means, we double the size as we grow.
         *
         * With !true_realloc, it means that the caller does not intend to call
         * realloc() but instead clone the buffer. This is for example the case, when we
         * want to nm_explicit_bzero() the old buffer. In that case we really want to grow
         * the buffer exponentially every time and not increment in page sizes of 4K (below).
         *
         * We get thus sizes of 104, 232, 488, 1000, 2024, 4072, 8168... */

        if (NM_UNLIKELY(requested > SIZE_MAX / 2u - 24u))
            goto out_huge;

        x = requested + 24u;
        n = 128u;
        while (n < x) {
            n <<= 1;
            nm_assert(n > 128u);
        }

        nm_assert(n > 24u && n - 24u >= requested);
        return n - 24u;
    }

    if (NM_UNLIKELY(requested > SIZE_MAX - 0x1000u - 24u)) {
        /* overflow happened. */
        goto out_huge;
    }

    /* For large allocations (with !true_realloc) we allocate memory in chunks of
     * 4K (- 24 bytes extra), assuming that the memory gets mmapped and thus
     * realloc() is efficient by just reordering pages. */
    n = ((requested + (0x0FFFu + 24u)) & ~((size_t) 0x0FFFu)) - 24u;
    nm_assert(n >= requested);
    return n;

out_huge:
    if (sizeof(size_t) > 4u) {
        /* on s390x (64 bit), gcc with LTO can complain that the size argument to
         * malloc must not be larger than 9223372036854775807.
         *
         * Work around that by returning SSIZE_MAX. It should be plenty still! */
        assert(requested <= (size_t) SSIZE_MAX);
        return (size_t) SSIZE_MAX;
    }
    return SIZE_MAX;
}

/*****************************************************************************/

bool
nm_utils_set_effective_user(const char *user, char *errbuf, size_t errbuf_len)
{
    struct passwd *pwentry;
    int            errsv;
    char           error[1024];

    errno   = 0;
    pwentry = getpwnam(user);
    if (!pwentry) {
        errsv = errno;
        if (errsv == 0) {
            snprintf(errbuf, errbuf_len, "user not found");
        } else {
            snprintf(errbuf,
                     errbuf_len,
                     "error getting user entry: %d (%s)\n",
                     errsv,
                     strerror_r(errsv, error, sizeof(error)));
        }
        return false;
    }

    if (setgid(pwentry->pw_gid) != 0) {
        errsv = errno;
        snprintf(errbuf,
                 errbuf_len,
                 "failed to change group to %u: %d (%s)\n",
                 pwentry->pw_gid,
                 errsv,
                 strerror_r(errsv, error, sizeof(error)));
        return false;
    }

    if (initgroups(user, pwentry->pw_gid) != 0) {
        errsv = errno;
        snprintf(errbuf,
                 errbuf_len,
                 "failed to reset supplementary group list to %u: %d (%s)\n",
                 pwentry->pw_gid,
                 errsv,
                 strerror_r(errsv, error, sizeof(error)));
        return false;
    }

    if (setuid(pwentry->pw_uid) != 0) {
        errsv = errno;
        snprintf(errbuf,
                 errbuf_len,
                 "failed to change user to %u: %d (%s)\n",
                 pwentry->pw_uid,
                 errsv,
                 strerror_r(errsv, error, sizeof(error)));
        return false;
    }

    return true;
}

/*****************************************************************************/

bool
nm_utils_read_file_to_stdout(const char *filename, char *errbuf, size_t errbuf_len)
{
    nm_auto_close int fd = -1;
    char              buffer[4096];
    char              error[1024];
    ssize_t           bytes_read;
    int               errsv;

    fd = open(filename, O_RDONLY);
    if (fd == -1) {
        errsv = errno;
        snprintf(errbuf,
                 errbuf_len,
                 "error opening the file: %d (%s)",
                 errsv,
                 strerror_r(errsv, error, sizeof(error)));
        return false;
    }

    while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0) {
        if (fwrite(buffer, 1, bytes_read, stdout) != (size_t) bytes_read) {
            errsv = errno;
            snprintf(errbuf,
                     errbuf_len,
                     "error writing to stdout: %d (%s)",
                     errsv,
                     strerror_r(errsv, error, sizeof(error)));
            return false;
        }
    }

    if (bytes_read < 0) {
        errsv = errno;
        snprintf(errbuf,
                 errbuf_len,
                 "error reading the file: %d (%s)",
                 errsv,
                 strerror_r(errsv, error, sizeof(error)));
        return false;
    }

    return true;
}

/*****************************************************************************/

/**
 * _nm_strerror_r:
 * @errsv: the errno passed to strerror_r()
 * @buf: the string buffer, must be non-null
 * @buf_size: the size of the buffer, must be positive.
 *
 * A wrapper around strerror_r(). Does little else, aside clearing up the
 * confusion about the different versions of the function.
 *
 * errno is preserved.
 *
 * Returns: the error string. This is either a static strong or @buf. It
 *   is not guaranteed to be @buf.
 */
const char *
_nm_strerror_r(int errsv, char *buf, size_t buf_size)
{
    NM_AUTO_PROTECT_ERRNO(errsv2);
    char *buf2;

    nm_assert(buf);
    nm_assert(buf_size > 0);

#if (!defined(__GLIBC__) && !defined(__UCLIBC__)) || ((_POSIX_C_SOURCE >= 200112L) && !_GNU_SOURCE)
    /* XSI-compliant */
    if (strerror_r(errsv, buf, buf_size) != 0) {
        snprintf(buf, buf_size, "Unspecified errno %d", errsv);
    }
    buf2 = buf;
#else
    /* GNU-specific */
    buf2 = strerror_r(errsv, buf, buf_size);
#endif

    nm_assert(buf2);
    return buf2;
}
