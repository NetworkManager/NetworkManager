/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-random-utils.h"

#include <fcntl.h>

#if USE_SYS_RANDOM_H
#include <sys/random.h>
#else
#include <linux/random.h>
#endif

#include "nm-shared-utils.h"

/*****************************************************************************/

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
 * entroy (at early boot), the function will read /dev/urandom.
 * Which of course, still has low entropy, and cause kernel to log
 * a warning.
 */
gboolean
nm_utils_random_bytes (void *p, size_t n)
{
	int fd;
	int r;
	gboolean has_high_quality = TRUE;
	gboolean urandom_success;
	guint8 *buf = p;
	gboolean avoid_urandom = FALSE;

	g_return_val_if_fail (p, FALSE);
	g_return_val_if_fail (n > 0, FALSE);

#if HAVE_GETRANDOM
	{
		static gboolean have_syscall = TRUE;

		if (have_syscall) {
			r = getrandom (buf, n, GRND_NONBLOCK);
			if (r > 0) {
				if ((size_t) r == n)
					return TRUE;

				/* no or partial read. There is not enough entropy.
				 * Fill the rest reading from urandom, and remember that
				 * some bits are not hight quality. */
				nm_assert (r < n);
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
		fd = open ("/dev/urandom", O_RDONLY | O_CLOEXEC | O_NOCTTY);
		if (fd < 0) {
			r = errno;
			if (r == EINTR)
				goto fd_open;
		} else {
			r = nm_utils_fd_read_loop_exact (fd, buf, n, TRUE);
			nm_close (fd);
			if (r >= 0)
				urandom_success = TRUE;
		}
	}

	if (!urandom_success) {
		static _nm_thread_local GRand *rand = NULL;
		gsize i;
		int j;

		/* we failed to fill the bytes reading from urandom.
		 * Fill the bits using GRand pseudo random numbers.
		 *
		 * We don't have good quality.
		 */
		has_high_quality = FALSE;

		if (G_UNLIKELY (!rand))
			rand = g_rand_new ();

		nm_assert (n > 0);
		i = 0;
		for (;;) {
			const union {
				guint32 v32;
				guint8 v8[4];
			} v = {
				.v32 = g_rand_int (rand),
			};

			for (j = 0; j < 4; ) {
				buf[i++] = v.v8[j++];
				if (i >= n)
					goto done;
			}
		}
done:
		;
	}

	return has_high_quality;
}
