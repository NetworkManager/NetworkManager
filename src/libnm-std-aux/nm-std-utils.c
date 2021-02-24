/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "nm-default-std.h"

#include "nm-std-utils.h"

#include <stdint.h>
#include <assert.h>
#include <limits.h>

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
