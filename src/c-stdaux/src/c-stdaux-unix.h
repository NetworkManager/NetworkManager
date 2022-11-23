#pragma once

/*
 * c-stdaux-unix: Unix-specific auxiliary macros and functions
 *
 * This header contains all unix-specific features of c-stdaux.h, usually only
 * available on unix-like platforms.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <c-stdaux-generic.h>

/* Documented alongside target properties. */
#define C_MODULE_UNIX 1

/**
 * DOC: Guaranteed Unix Includes
 *
 * c-stdaux-unix includes a set of Unix headers. All those includes are
 * guaranteed and part of the API. See the actual header for a comprehensive
 * list.
 */
/**/

#include <dirent.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

/**
 * DOC: Common Unix Destructors
 *
 * A set of destructors is provided which extends standard library destructors
 * to adhere to some adjuvant rules. In particular, they return an invalid
 * value of the particular object, rather than void. This allows direct
 * assignment to any member-field and/or variable they are defined in, like:
 *
 * .. code-block:: c
 *
 *     foo->bar = c_close(foo->bar);
 *
 * Furthermore, all those destructors can be safely called with the "INVALID"
 * value as argument, and they will be a no-op.
 */
/**/

/**
 * c_close() - Destructor-wrapper for close()
 * @fd:         File-descriptor to pass to destructor, or negative value
 *
 * Wrapper around ``close()``, but a no-op if a negative value is provided.
 * Always returns ``-1``.
 *
 * Return: -1 is returned.
 */
static inline int c_close(int fd) {
        if (fd >= 0)
                close(fd);
        return -1;
}

/**
 * c_closedir() - Destructor-wrapper for closedir()
 * @d:          Directory handle to pass to destructor, or NULL
 *
 * Wrapper around ``closedir()``, but a no-op if ``NULL`` is passed. Always
 * returns ``NULL``.
 *
 * Return: NULL is returned.
 */
static inline DIR *c_closedir(DIR *d) {
        if (d)
                closedir(d);
        return NULL;
}

/**
 * DOC: Common Cleanup Helpers
 *
 * A set of helpers that aid in creating functions suitable for use with
 * :c:macro:`_c_cleanup_()`. Furthermore, a collection of predefined cleanup
 * functions of a set of standard library objects ready for use with
 * :c:macro:`_c_cleanup_()`.
 * Those cleanup helpers are always suffixed with a ``p``.
 *
 * The helpers that are provided are:
 *
 * - ``c_closep()``: Wrapper around :c:func:`c_close()`.
 * - ``c_closedirp()``: Wrapper around :c:func:`c_closedir()`.
 */
/**/

C_DEFINE_DIRECT_CLEANUP(int, c_close);
C_DEFINE_CLEANUP(DIR *, c_closedir);

#ifdef __cplusplus
}
#endif
