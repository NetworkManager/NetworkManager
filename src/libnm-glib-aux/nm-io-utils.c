/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2018 Red Hat, Inc.
 */

#include "libnm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nm-io-utils.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "nm-str-buf.h"
#include "nm-shared-utils.h"
#include "nm-secret-utils.h"
#include "nm-errno.h"

/*****************************************************************************/

_nm_printf(4, 5) static int _get_contents_error(GError **   error,
                                                int         errsv,
                                                int *       out_errsv,
                                                const char *format,
                                                ...)
{
    nm_assert(NM_ERRNO_NATIVE(errsv));

    if (error) {
        gs_free char *msg = NULL;
        va_list       args;
        char          bstrerr[NM_STRERROR_BUFSIZE];

        va_start(args, format);
        msg = g_strdup_vprintf(format, args);
        va_end(args);
        g_set_error(error,
                    G_FILE_ERROR,
                    g_file_error_from_errno(errsv),
                    "%s: %s",
                    msg,
                    nm_strerror_native_r(errsv, bstrerr, sizeof(bstrerr)));
    }

    nm_assert(errsv > 0);
    NM_SET_OUT(out_errsv, errsv);

    return FALSE;
}
#define _get_contents_error_errno(error, out_errsv, ...)            \
    ({                                                              \
        int _errsv = (errno);                                       \
                                                                    \
        _get_contents_error(error, _errsv, out_errsv, __VA_ARGS__); \
    })

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
 * @out_errsv: (allow-none) (out): on error, a positive errno. or zero.
 * @error:
 *
 *
 * A reimplementation of g_file_get_contents() with a few differences:
 *   - accepts an open fd, instead of a path name. This allows you to
 *     use openat().
 *   - limits the maximum filesize to max_length.
 *
 * Returns: TRUE on success.
 */
gboolean
nm_utils_fd_get_contents(int                         fd,
                         gboolean                    close_fd,
                         gsize                       max_length,
                         NMUtilsFileGetContentsFlags flags,
                         char **                     contents,
                         gsize *                     length,
                         int *                       out_errsv,
                         GError **                   error)
{
    nm_auto_close int fd_keeper = close_fd ? fd : -1;
    struct stat       stat_buf;
    gs_free char *    str          = NULL;
    const bool        do_bzero_mem = NM_FLAGS_HAS(flags, NM_UTILS_FILE_GET_CONTENTS_FLAG_SECRET);
    int               errsv;

    g_return_val_if_fail(fd >= 0, FALSE);
    g_return_val_if_fail(contents && !*contents, FALSE);
    g_return_val_if_fail(!error || !*error, FALSE);

    NM_SET_OUT(length, 0);

    if (fstat(fd, &stat_buf) < 0)
        return _get_contents_error_errno(error, out_errsv, "failure during fstat");

    if (!max_length) {
        /* default to a very large size, but not extreme */
        max_length = 2 * 1024 * 1024;
    }

    if (stat_buf.st_size > 0 && S_ISREG(stat_buf.st_mode)) {
        const gsize n_stat = stat_buf.st_size;
        ssize_t     n_read;

        if (n_stat > max_length - 1)
            return _get_contents_error(error,
                                       EMSGSIZE,
                                       out_errsv,
                                       "file too large (%zu+1 bytes with maximum %zu bytes)",
                                       n_stat,
                                       max_length);

        str = g_try_malloc(n_stat + 1);
        if (!str)
            return _get_contents_error(error,
                                       ENOMEM,
                                       out_errsv,
                                       "failure to allocate buffer of %zu+1 bytes",
                                       n_stat);

        n_read = nm_utils_fd_read_loop(fd, str, n_stat, TRUE);
        if (n_read < 0) {
            if (do_bzero_mem)
                nm_explicit_bzero(str, n_stat);
            return _get_contents_error(error,
                                       -n_read,
                                       out_errsv,
                                       "error reading %zu bytes from file descriptor",
                                       n_stat);
        }
        str[n_read] = '\0';

        if (n_read < n_stat) {
            if (!(str = nm_secret_mem_try_realloc_take(str, do_bzero_mem, n_stat + 1, n_read + 1)))
                return _get_contents_error(error,
                                           ENOMEM,
                                           out_errsv,
                                           "failure to reallocate buffer with %zu bytes",
                                           n_read + 1);
        }
        NM_SET_OUT(length, n_read);
    } else {
        nm_auto_fclose FILE *f = NULL;
        char                 buf[4096];
        gsize                n_have, n_alloc;
        int                  fd2;

        if (fd_keeper >= 0)
            fd2 = nm_steal_fd(&fd_keeper);
        else {
            fd2 = fcntl(fd, F_DUPFD_CLOEXEC, 0);
            if (fd2 < 0)
                return _get_contents_error_errno(error, out_errsv, "error during dup");
        }

        if (!(f = fdopen(fd2, "r"))) {
            errsv = errno;
            nm_close(fd2);
            return _get_contents_error(error, errsv, out_errsv, "failure during fdopen");
        }

        n_have  = 0;
        n_alloc = 0;

        while (!feof(f)) {
            gsize n_read;

            n_read = fread(buf, 1, sizeof(buf), f);
            errsv  = errno;
            if (ferror(f)) {
                if (do_bzero_mem)
                    nm_explicit_bzero(buf, sizeof(buf));
                return _get_contents_error(error, errsv, out_errsv, "error during fread");
            }

            if (n_have > G_MAXSIZE - 1 - n_read || n_have + n_read + 1 > max_length) {
                if (do_bzero_mem)
                    nm_explicit_bzero(buf, sizeof(buf));
                return _get_contents_error(
                    error,
                    EMSGSIZE,
                    out_errsv,
                    "file stream too large (%zu+1 bytes with maximum %zu bytes)",
                    (n_have > G_MAXSIZE - 1 - n_read) ? G_MAXSIZE : n_have + n_read,
                    max_length);
            }

            if (n_have + n_read + 1 >= n_alloc) {
                gsize old_n_alloc = n_alloc;

                if (n_alloc != 0) {
                    nm_assert(str);
                    if (n_alloc >= max_length / 2)
                        n_alloc = max_length;
                    else
                        n_alloc *= 2;
                } else {
                    nm_assert(!str);
                    n_alloc = NM_MIN(n_read + 1, sizeof(buf));
                }

                if (!(str = nm_secret_mem_try_realloc_take(str,
                                                           do_bzero_mem,
                                                           old_n_alloc,
                                                           n_alloc))) {
                    if (do_bzero_mem)
                        nm_explicit_bzero(buf, sizeof(buf));
                    return _get_contents_error(error,
                                               ENOMEM,
                                               out_errsv,
                                               "failure to allocate buffer of %zu bytes",
                                               n_alloc);
                }
            }

            memcpy(str + n_have, buf, n_read);
            n_have += n_read;
        }

        if (do_bzero_mem)
            nm_explicit_bzero(buf, sizeof(buf));

        if (n_alloc == 0)
            str = g_new0(char, 1);
        else {
            str[n_have] = '\0';
            if (n_have + 1 < n_alloc) {
                if (!(str = nm_secret_mem_try_realloc_take(str, do_bzero_mem, n_alloc, n_have + 1)))
                    return _get_contents_error(error,
                                               ENOMEM,
                                               out_errsv,
                                               "failure to truncate buffer to %zu bytes",
                                               n_have + 1);
            }
        }

        NM_SET_OUT(length, n_have);
    }

    *contents = g_steal_pointer(&str);
    NM_SET_OUT(out_errsv, 0);
    return TRUE;
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
 * @out_errsv: (allow-none) (out): on error, a positive errno. or zero.
 * @error:
 *
 * A reimplementation of g_file_get_contents() with a few differences:
 *   - accepts an @dirfd to open @filename relative to that path via openat().
 *   - limits the maximum filesize to max_length.
 *   - uses O_CLOEXEC on internal file descriptor
 *   - optionally returns the native errno on failure.
 *
 * Returns: TRUE on success.
 */
gboolean
nm_utils_file_get_contents(int                         dirfd,
                           const char *                filename,
                           gsize                       max_length,
                           NMUtilsFileGetContentsFlags flags,
                           char **                     contents,
                           gsize *                     length,
                           int *                       out_errsv,
                           GError **                   error)
{
    int fd;

    g_return_val_if_fail(filename && filename[0], FALSE);
    g_return_val_if_fail(contents && !*contents, FALSE);

    NM_SET_OUT(length, 0);

    if (dirfd >= 0) {
        fd = openat(dirfd, filename, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            return _get_contents_error_errno(error,
                                             out_errsv,
                                             "Failed to open file \"%s\" with openat",
                                             filename);
        }
    } else {
        fd = open(filename, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            return _get_contents_error_errno(error,
                                             out_errsv,
                                             "Failed to open file \"%s\"",
                                             filename);
        }
    }
    return nm_utils_fd_get_contents(fd,
                                    TRUE,
                                    max_length,
                                    flags,
                                    contents,
                                    length,
                                    out_errsv,
                                    error);
}

/*****************************************************************************/

/*
 * Copied from GLib's g_file_set_contents() et al., but allows
 * specifying a mode for the new file and optionally the last access
 * and last modification times.
 */
gboolean
nm_utils_file_set_contents(const char *           filename,
                           const char *           contents,
                           gssize                 length,
                           mode_t                 mode,
                           const struct timespec *times,
                           int *                  out_errsv,
                           GError **              error)
{
    gs_free char *tmp_name = NULL;
    struct stat   statbuf;
    int           errsv;
    gssize        s;
    int           fd;

    g_return_val_if_fail(filename, FALSE);
    g_return_val_if_fail(contents || !length, FALSE);
    g_return_val_if_fail(!error || !*error, FALSE);
    g_return_val_if_fail(length >= -1, FALSE);

    if (length == -1)
        length = strlen(contents);

    tmp_name = g_strdup_printf("%s.XXXXXX", filename);
    fd       = g_mkstemp_full(tmp_name, O_RDWR | O_CLOEXEC, mode);
    if (fd < 0) {
        return _get_contents_error_errno(error, out_errsv, "failed to create file %s", tmp_name);
    }

    while (length > 0) {
        s = write(fd, contents, length);
        if (s < 0) {
            errsv = NM_ERRNO_NATIVE(errno);
            if (errsv == EINTR)
                continue;

            nm_close(fd);
            unlink(tmp_name);
            return _get_contents_error(error,
                                       errsv,
                                       out_errsv,
                                       "failed to write to file %s",
                                       tmp_name);
        }

        g_assert(s <= length);

        contents += s;
        length -= s;
    }

    /* If the final destination exists and is > 0 bytes, we want to sync the
     * newly written file to ensure the data is on disk when we rename over
     * the destination. Otherwise, if we get a system crash we can lose both
     * the new and the old file on some filesystems. (I.E. those that don't
     * guarantee the data is written to the disk before the metadata.)
     */
    if (lstat(filename, &statbuf) == 0 && statbuf.st_size > 0) {
        if (fsync(fd) != 0) {
            errsv = NM_ERRNO_NATIVE(errno);
            nm_close(fd);
            unlink(tmp_name);
            return _get_contents_error(error, errsv, out_errsv, "failed to fsync %s", tmp_name);
        }
    }

    if (times && futimens(fd, times) != 0) {
        errsv = NM_ERRNO_NATIVE(errno);
        nm_close(fd);
        unlink(tmp_name);
        return _get_contents_error(error,
                                   errsv,
                                   out_errsv,
                                   "failed to set atime and mtime on %s",
                                   tmp_name);
    }

    nm_close(fd);

    if (rename(tmp_name, filename)) {
        errsv = NM_ERRNO_NATIVE(errno);
        unlink(tmp_name);
        return _get_contents_error(error,
                                   errsv,
                                   out_errsv,
                                   "failed rename %s to %s",
                                   tmp_name,
                                   filename);
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
nm_utils_file_stat(const char *filename, struct stat *out_st)
{
    struct stat st;

    if (stat(filename, out_st ?: &st) != 0)
        return -NM_ERRNO_NATIVE(errno);
    return 0;
}

/**
 * nm_utils_fd_read:
 * @fd: the fd to read from.
 * @out_string: (out): output string where read bytes will be stored.
 *
 * Returns: <0 on failure, which is -(errno).
 *          0 on EOF.
 *          >0 on success, which is the number of bytes read.  */
gssize
nm_utils_fd_read(int fd, NMStrBuf *out_string)
{
    gsize  buf_available;
    gssize n_read;
    int    errsv;

    g_return_val_if_fail(fd >= 0, -1);
    g_return_val_if_fail(out_string, -1);

    /* If the buffer size is 0, we allocate NM_UTILS_GET_NEXT_REALLOC_SIZE_1000 (1000 bytes)
     * the first time. Afterwards, the buffer grows exponentially.
     *
     * Note that with @buf_available, we always would read as much buffer as we actually
     * have reserved. */
    nm_str_buf_maybe_expand(out_string, NM_UTILS_GET_NEXT_REALLOC_SIZE_1000, FALSE);

    buf_available = out_string->allocated - out_string->len;

    n_read = read(fd, &((nm_str_buf_get_str_unsafe(out_string))[out_string->len]), buf_available);
    if (n_read < 0) {
        errsv = errno;
        return -NM_ERRNO_NATIVE(errsv);
    }

    if (n_read > 0) {
        nm_assert((gsize) n_read <= buf_available);
        nm_str_buf_set_size(out_string, out_string->len + (gsize) n_read, TRUE, FALSE);
    }

    return n_read;
}

/*****************************************************************************/

typedef struct {
    GSubprocess *subprocess;
    GSource *    timeout_source;
} SubprocessTerminateData;

static void
_subprocess_terminate_wait_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    SubprocessTerminateData *term_data = user_data;

    g_subprocess_wait_finish(G_SUBPROCESS(source), result, NULL);

    nm_clear_g_source_inst(&term_data->timeout_source);
    g_object_unref(term_data->subprocess);
    nm_g_slice_free(term_data);
}

static gboolean
_subprocess_terminate_timeout_cb(gpointer user_data)
{
    SubprocessTerminateData *term_data = user_data;

    nm_clear_g_source_inst(&term_data->timeout_source);
    g_subprocess_send_signal(term_data->subprocess, SIGKILL);
    return G_SOURCE_REMOVE;
}

void
nm_g_subprocess_terminate_in_background(GSubprocess *subprocess, int timeout_msec_before_kill)
{
    SubprocessTerminateData *term_data;
    GMainContext *           main_context;

    nm_assert(timeout_msec_before_kill > 0);

    /* The GSubprocess stays alive until the child is reaped (an internal reference is held).
     *
     * This function first sends SIGTERM to the process right away, and after a
     * timeout "timeout_msec_before_kill" send a SIGKILL.
     *
     * Otherwise, it does nothing, it does not log, there is no notification when the process
     * completes and there is no way to abort the thing.
     *
     * It honors the current g_main_context_get_thread_default(). */

    if (!subprocess)
        return;

    g_return_if_fail(G_IS_SUBPROCESS(subprocess));

    main_context = g_main_context_get_thread_default();

    term_data  = g_slice_new(SubprocessTerminateData);
    *term_data = (SubprocessTerminateData){
        .subprocess     = g_object_ref(subprocess),
        .timeout_source = NULL,
    };

    g_subprocess_send_signal(subprocess, SIGTERM);

    g_subprocess_wait_async(subprocess, NULL, _subprocess_terminate_wait_cb, term_data);

    term_data->timeout_source =
        nm_g_source_attach(nm_g_timeout_source_new(timeout_msec_before_kill,
                                                   G_PRIORITY_DEFAULT,
                                                   _subprocess_terminate_timeout_cb,
                                                   term_data,
                                                   NULL),
                           main_context);
}

/*****************************************************************************/

char **
nm_utils_find_mkstemp_files(const char *dirname, const char *filename)
{
    static const char letters[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    DIR *             dir;
    struct dirent *   entry;
    GPtrArray *       arr = NULL;
    gsize             l;

    /* We write files with g_file_set_contents() and nm_utils_file_set_contents().
     * These create temporary files using g_mkstemp_full(), with a random .XXXXXX suffix.
     *
     * If NetworkManager crashes while writing the file, then those temporary files are
     * left over. We might want to find and delete such files.
     *
     * Beware: only delete such files if you are in full control about which files are
     * supposed to be in the directory. For example, NetworkManager controls
     * /var/lib/NetworkManager/timestamps files, and it thus takes the right to delete
     * all files /var/lib/NetworkManager/timestamps.XXXXXX. That may not be appropriate
     * in other cases! */

    if (!dirname || !filename || !filename[0])
        return NULL;

    dir = opendir(dirname);
    if (!dir)
        return NULL;

    l = strlen(filename);

    while ((entry = readdir(dir))) {
        const char *f = entry->d_name;
        guint       i;

        if (strncmp(f, filename, l) != 0)
            goto next;
        if (f[l] != '.')
            goto next;
        for (i = 1; i <= 6; i++) {
            /* @letters is also what g_mkstemp_full() does! */
            if (!memchr(letters, f[l + i], G_N_ELEMENTS(letters)))
                goto next;
        }
        if (f[l + 7] != '\0')
            goto next;

        if (!arr)
            arr = g_ptr_array_new();

        g_ptr_array_add(arr, g_strdup(f));
next:;
    }

    closedir(dir);

    if (!arr)
        return NULL;

    g_ptr_array_add(arr, NULL);
    return (char **) g_ptr_array_free(arr, FALSE);
}
