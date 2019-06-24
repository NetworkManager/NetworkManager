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
 * (C) Copyright 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-io-utils.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "nm-shared-utils.h"
#include "nm-secret-utils.h"
#include "nm-errno.h"

/*****************************************************************************/

_nm_printf (3, 4)
static int
_get_contents_error (GError **error, int errsv, const char *format, ...)
{
	nm_assert (NM_ERRNO_NATIVE (errsv));

	if (error) {
		gs_free char *msg = NULL;
		va_list args;
		char bstrerr[NM_STRERROR_BUFSIZE];

		va_start (args, format);
		msg = g_strdup_vprintf (format, args);
		va_end (args);
		g_set_error (error,
		             G_FILE_ERROR,
		             g_file_error_from_errno (errsv),
		             "%s: %s",
		             msg,
		             nm_strerror_native_r (errsv, bstrerr, sizeof (bstrerr)));
	}
	return -errsv;
}
#define _get_contents_error_errno(error, ...) \
	({ \
		int _errsv = (errno); \
		\
		_get_contents_error (error, _errsv, __VA_ARGS__); \
	})

static char *
_mem_realloc (char *old, gboolean do_bzero_mem, gsize cur_len, gsize new_len)
{
	char *new;

	/* re-allocating to zero bytes is an odd case. We don't need it
	 * and it's not supported. */
	nm_assert (new_len > 0);

	/* regardless of success/failure, @old will always be freed/consumed. */

	if (do_bzero_mem && cur_len > 0) {
		new = g_try_malloc (new_len);
		if (new)
			memcpy (new, old, NM_MIN (cur_len, new_len));
		nm_explicit_bzero (old, cur_len);
		g_free (old);
	} else {
		new = g_try_realloc (old, new_len);
		if (!new)
			g_free (old);
	}

	return new;
}

/**
 * nm_utils_fd_get_contents:
 * @fd: open file descriptor to read. The fd will not be closed,
 *   but don't rely on its state afterwards.
 * @close_fd: if %TRUE, @fd will be closed by the function.
 *  Passing %TRUE here might safe a syscall for dup().
 * @max_length: allocate at most @max_length bytes. If the
 *   file is larger, reading will fail. Set to zero to use
 *   a very large default.
 *   WARNING: @max_length is here to avoid a crash for huge/unlimited files.
 *   For example, stat(/sys/class/net/enp0s25/ifindex) gives a filesize of
 *   4K, although the actual real is small. @max_length is the memory
 *   allocated in the process of reading the file, thus it must be at least
 *   the size reported by fstat.
 *   If you set it to 1K, read will fail because fstat() claims the
 *   file is larger.
 * @flags: %NMUtilsFileGetContentsFlags for reading the file.
 * @contents: the output buffer with the file read. It is always
 *   NUL terminated. The buffer is at most @max_length long, including
 *  the NUL byte. That is, it reads only files up to a length of
 *  @max_length - 1 bytes.
 * @length: optional output argument of the read file size.
 *
 * A reimplementation of g_file_get_contents() with a few differences:
 *   - accepts an open fd, instead of a path name. This allows you to
 *     use openat().
 *   - limits the maximum filesize to max_length.
 *
 * Returns: a negative error code on failure.
 */
int
nm_utils_fd_get_contents (int fd,
                          gboolean close_fd,
                          gsize max_length,
                          NMUtilsFileGetContentsFlags flags,
                          char **contents,
                          gsize *length,
                          GError **error)
{
	nm_auto_close int fd_keeper = close_fd ? fd : -1;
	struct stat stat_buf;
	gs_free char *str = NULL;
	const bool do_bzero_mem = NM_FLAGS_HAS (flags, NM_UTILS_FILE_GET_CONTENTS_FLAG_SECRET);
	int errsv;

	g_return_val_if_fail (fd >= 0, -EINVAL);
	g_return_val_if_fail (contents, -EINVAL);
	g_return_val_if_fail (!error || !*error, -EINVAL);

	if (fstat (fd, &stat_buf) < 0)
		return _get_contents_error_errno (error, "failure during fstat");

	if (!max_length) {
		/* default to a very large size, but not extreme */
		max_length = 2 * 1024 * 1024;
	}

	if (   stat_buf.st_size > 0
	    && S_ISREG (stat_buf.st_mode)) {
		const gsize n_stat = stat_buf.st_size;
		ssize_t n_read;

		if (n_stat > max_length - 1)
			return _get_contents_error (error, EMSGSIZE, "file too large (%zu+1 bytes with maximum %zu bytes)", n_stat, max_length);

		str = g_try_malloc (n_stat + 1);
		if (!str)
			return _get_contents_error (error, ENOMEM, "failure to allocate buffer of %zu+1 bytes", n_stat);

		n_read = nm_utils_fd_read_loop (fd, str, n_stat, TRUE);
		if (n_read < 0) {
			if (do_bzero_mem)
				nm_explicit_bzero (str, n_stat);
			return _get_contents_error (error, -n_read, "error reading %zu bytes from file descriptor", n_stat);
		}
		str[n_read] = '\0';

		if (n_read < n_stat) {
			if (!(str = _mem_realloc (str, do_bzero_mem, n_stat + 1, n_read + 1)))
				return _get_contents_error (error, ENOMEM, "failure to reallocate buffer with %zu bytes", n_read + 1);
		}
		NM_SET_OUT (length, n_read);
	} else {
		nm_auto_fclose FILE *f = NULL;
		char buf[4096];
		gsize n_have, n_alloc;
		int fd2;

		if (fd_keeper >= 0)
			fd2 = nm_steal_fd (&fd_keeper);
		else {
			fd2 = fcntl (fd, F_DUPFD_CLOEXEC, 0);
			if (fd2 < 0)
				return _get_contents_error_errno (error, "error during dup");
		}

		if (!(f = fdopen (fd2, "r"))) {
			errsv = errno;
			nm_close (fd2);
			return _get_contents_error (error, errsv, "failure during fdopen");
		}

		n_have = 0;
		n_alloc = 0;

		while (!feof (f)) {
			gsize n_read;

			n_read = fread (buf, 1, sizeof (buf), f);
			errsv = errno;
			if (ferror (f)) {
				if (do_bzero_mem)
					nm_explicit_bzero (buf, sizeof (buf));
				return _get_contents_error (error, errsv, "error during fread");
			}

			if (   n_have > G_MAXSIZE - 1 - n_read
			    || n_have + n_read + 1 > max_length) {
				if (do_bzero_mem)
					nm_explicit_bzero (buf, sizeof (buf));
				return _get_contents_error (error, EMSGSIZE, "file stream too large (%zu+1 bytes with maximum %zu bytes)",
				                            (n_have > G_MAXSIZE - 1 - n_read) ? G_MAXSIZE : n_have + n_read,
				                            max_length);
			}

			if (n_have + n_read + 1 >= n_alloc) {
				gsize old_n_alloc = n_alloc;

				if (n_alloc != 0) {
					nm_assert (str);
					if (n_alloc >= max_length / 2)
						n_alloc = max_length;
					else
						n_alloc *= 2;
				} else {
					nm_assert (!str);
					n_alloc = NM_MIN (n_read + 1, sizeof (buf));
				}

				if (!(str = _mem_realloc (str, do_bzero_mem, old_n_alloc, n_alloc))) {
					if (do_bzero_mem)
						nm_explicit_bzero (buf, sizeof (buf));
					return _get_contents_error (error, ENOMEM, "failure to allocate buffer of %zu bytes", n_alloc);
				}
			}

			memcpy (str + n_have, buf, n_read);
			n_have += n_read;
		}

		if (do_bzero_mem)
			nm_explicit_bzero (buf, sizeof (buf));

		if (n_alloc == 0)
			str = g_new0 (char, 1);
		else {
			str[n_have] = '\0';
			if (n_have + 1 < n_alloc) {
				if (!(str = _mem_realloc (str, do_bzero_mem, n_alloc, n_have + 1)))
					return _get_contents_error (error, ENOMEM, "failure to truncate buffer to %zu bytes", n_have + 1);
			}
		}

		NM_SET_OUT (length, n_have);
	}

	*contents = g_steal_pointer (&str);
	return 0;
}

/**
 * nm_utils_file_get_contents:
 * @dirfd: optional file descriptor to use openat(). If negative, use plain open().
 * @filename: the filename to open. Possibly relative to @dirfd.
 * @max_length: allocate at most @max_length bytes.
 *   WARNING: see nm_utils_fd_get_contents() hint about @max_length.
 * @flags: %NMUtilsFileGetContentsFlags for reading the file.
 * @contents: the output buffer with the file read. It is always
 *   NUL terminated. The buffer is at most @max_length long, including
 *   the NUL byte. That is, it reads only files up to a length of
 *   @max_length - 1 bytes.
 * @length: optional output argument of the read file size.
 *
 * A reimplementation of g_file_get_contents() with a few differences:
 *   - accepts an @dirfd to open @filename relative to that path via openat().
 *   - limits the maximum filesize to max_length.
 *   - uses O_CLOEXEC on internal file descriptor
 *
 * Returns: a negative error code on failure.
 */
int
nm_utils_file_get_contents (int dirfd,
                            const char *filename,
                            gsize max_length,
                            NMUtilsFileGetContentsFlags flags,
                            char **contents,
                            gsize *length,
                            GError **error)
{
	int fd;
	int errsv;
	char bstrerr[NM_STRERROR_BUFSIZE];

	g_return_val_if_fail (filename && filename[0], -EINVAL);

	if (dirfd >= 0) {
		fd = openat (dirfd, filename, O_RDONLY | O_CLOEXEC);
		if (fd < 0) {
			errsv = errno;

			g_set_error (error,
			             G_FILE_ERROR,
			             g_file_error_from_errno (errsv),
			             "Failed to open file \"%s\" with openat: %s",
			             filename,
			             nm_strerror_native_r (errsv, bstrerr, sizeof (bstrerr)));
			return -NM_ERRNO_NATIVE (errsv);
		}
	} else {
		fd = open (filename, O_RDONLY | O_CLOEXEC);
		if (fd < 0) {
			errsv = errno;

			g_set_error (error,
			             G_FILE_ERROR,
			             g_file_error_from_errno (errsv),
			             "Failed to open file \"%s\": %s",
			             filename,
			             nm_strerror_native_r (errsv, bstrerr, sizeof (bstrerr)));
			return -NM_ERRNO_NATIVE (errsv);
		}
	}
	return nm_utils_fd_get_contents (fd,
	                                 TRUE,
	                                 max_length,
	                                 flags,
	                                 contents,
	                                 length,
	                                 error);
}

/*****************************************************************************/

/*
 * Copied from GLib's g_file_set_contents() et al., but allows
 * specifying a mode for the new file.
 */
gboolean
nm_utils_file_set_contents (const char *filename,
                            const char *contents,
                            gssize length,
                            mode_t mode,
                            GError **error)
{
	gs_free char *tmp_name = NULL;
	struct stat statbuf;
	int errsv;
	gssize s;
	int fd;
	char bstrerr[NM_STRERROR_BUFSIZE];

	g_return_val_if_fail (filename, FALSE);
	g_return_val_if_fail (contents || !length, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);
	g_return_val_if_fail (length >= -1, FALSE);

	if (length == -1)
		length = strlen (contents);

	tmp_name = g_strdup_printf ("%s.XXXXXX", filename);
	fd = g_mkstemp_full (tmp_name, O_RDWR | O_CLOEXEC, mode);
	if (fd < 0) {
		errsv = errno;
		g_set_error (error,
		             G_FILE_ERROR,
		             g_file_error_from_errno (errsv),
		             "failed to create file %s: %s",
		             tmp_name,
		             nm_strerror_native_r (errsv, bstrerr, sizeof (bstrerr)));
		return FALSE;
	}

	while (length > 0) {
		s = write (fd, contents, length);
		if (s < 0) {
			errsv = errno;
			if (errsv == EINTR)
				continue;

			nm_close (fd);
			unlink (tmp_name);

			g_set_error (error,
			             G_FILE_ERROR,
			             g_file_error_from_errno (errsv),
			             "failed to write to file %s: %s",
			             tmp_name,
			             nm_strerror_native_r (errsv, bstrerr, sizeof (bstrerr)));
			return FALSE;
		}

		g_assert (s <= length);

		contents += s;
		length -= s;
	}

	/* If the final destination exists and is > 0 bytes, we want to sync the
	 * newly written file to ensure the data is on disk when we rename over
	 * the destination. Otherwise if we get a system crash we can lose both
	 * the new and the old file on some filesystems. (I.E. those that don't
	 * guarantee the data is written to the disk before the metadata.)
	 */
	if (   lstat (filename, &statbuf) == 0
	    && statbuf.st_size > 0) {
		if (fsync (fd) != 0) {
			errsv = errno;

			nm_close (fd);
			unlink (tmp_name);

			g_set_error (error,
			             G_FILE_ERROR,
			             g_file_error_from_errno (errsv),
			             "failed to fsync %s: %s",
			             tmp_name,
			             nm_strerror_native_r (errsv, bstrerr, sizeof (bstrerr)));
			return FALSE;
		}
	}

	nm_close (fd);

	if (rename (tmp_name, filename)) {
		errsv = errno;
		unlink (tmp_name);
		g_set_error (error,
		             G_FILE_ERROR,
		             g_file_error_from_errno (errsv),
		             "failed to rename %s to %s: %s",
		             tmp_name,
		             filename,
		             nm_strerror_native_r (errsv, bstrerr, sizeof (bstrerr)));
		return FALSE;
	}

	return TRUE;
}

/**
 * nm_utils_file_stat:
 * @filename: the filename to stat.
 * @out_st: (allow-none) (out): if given, this will be passed to stat().
 *
 * Just wraps stat() and gives the errno number as function result instead
 * of setting the errno (though, errno is also set). It's only for convenience
 * with
 *
 *    if (nm_utils_file_stat (filename, NULL) == -ENOENT) {
 *    }
 *
 * Returns: 0 on success a negative errno on failure. */
int
nm_utils_file_stat (const char *filename, struct stat *out_st)
{
	struct stat st;

	if (stat (filename, out_st ?: &st) != 0)
		return -NM_ERRNO_NATIVE (errno);
	return 0;
}
