/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2018 Red Hat, Inc.
 */

#include "libnm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nm-io-utils.h"

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/ioctl.h>

#include "nm-str-buf.h"
#include "nm-shared-utils.h"
#include "nm-secret-utils.h"
#include "nm-errno.h"

/*****************************************************************************/

int
nm_io_fcntl_getfl(int fd)
{
    int f;

    nm_assert(fd >= 0);

    f = fcntl(fd, F_GETFL, 0);

    /* The caller really must provide a valid FD. For a valid FD, there is not
     * reason why this call could fail (or how we could handle the failure).
     *
     * Unlike plain fcntl(), nm_io_fcntl_getfl() cannot fail. */
    nm_assert(f != -1);

    /* We not only assert that the return value is "!= -1", but that it's not
     * negative. Negative flags would be very odd, and not something we would
     * expect for a successful call. */
    nm_assert(f >= 0);

    return f;
}

int
nm_io_fcntl_setfl(int fd, int flags)
{
    int f;
    int errsv;

    nm_assert(fd >= 0);
    nm_assert(flags >= 0);

    f = fcntl(fd, F_SETFL, flags);
    if (f != 0) {
        errsv = errno;

        nm_assert(errsv != EBADF);

        return -NM_ERRNO_NATIVE(errsv);
    }

    return 0;
}

int
nm_io_fcntl_setfl_update(int fd, int flags_mask, int flags_value)
{
    int flags_current;

    nm_assert(fd >= 0);
    nm_assert(flags_mask > 0);
    nm_assert(flags_value >= 0);
    nm_assert(((~flags_mask) & flags_value) == 0);

    flags_current = nm_io_fcntl_getfl(fd);
    return nm_io_fcntl_setfl(fd, (flags_current & ~flags_mask) | (flags_mask & flags_value));
}

void
nm_io_fcntl_setfl_update_nonblock(int fd)
{
    int r;

    nm_assert(fd >= 0);

    r = nm_io_fcntl_setfl_update(fd, O_NONBLOCK, O_NONBLOCK);

    /* nm_io_fcntl_setfl_update() already asserts that it cannot fail with
     * EBADF.
     *
     * In nm_io_fcntl_setfl_update_nonblock() only sts O_NONBLOCK, where we
     * don't expect any other error. Kernel should never reject setting this
     * flags, and if it did, we have to find out how to handle that. Currently
     * we don't handle it and assert against failure. */

    nm_assert(r == 0);
}

/*****************************************************************************/

_nm_printf(4, 5) static int _get_contents_error(GError    **error,
                                                int         errsv,
                                                int        *out_errsv,
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
 * @out_errsv: (out) (optional): on error, a positive errno. or zero.
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
                         char                      **contents,
                         gsize                      *length,
                         int                        *out_errsv,
                         GError                    **error)
{
    nm_auto_close int fd_keeper = close_fd ? fd : -1;
    struct stat       stat_buf;
    gs_free char     *str          = NULL;
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
 * @out_errsv: (out) (optional): on error, a positive errno. or zero.
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
                           const char                 *filename,
                           gsize                       max_length,
                           NMUtilsFileGetContentsFlags flags,
                           char                      **contents,
                           gsize                      *length,
                           int                        *out_errsv,
                           GError                    **error)
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
nm_utils_file_set_contents(const char            *filename,
                           const char            *contents,
                           gssize                 length,
                           mode_t                 mode,
                           const struct timespec *times,
                           int                   *out_errsv,
                           GError               **error)
{
    gs_free char *tmp_name = NULL;
    struct stat   statbuf;
    int           errsv;
    gssize        s;
    int           fd;
    int           r;

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

    r = nm_close_with_error(fd);
    if (r < 0) {
        errsv = NM_ERRNO_NATIVE(-r);
        unlink(tmp_name);
        return _get_contents_error(error,
                                   errsv,
                                   out_errsv,
                                   "failed close() after writing file %s",
                                   tmp_name);
    }

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
 * @out_st: (out) (nullable): if given, this will be passed to stat().
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

    /* Reserve at least 488+1 bytes of buffer size. That is probably a suitable
     * compromise between not wasting too much buffer space and not reading too much.
     *
     * Note that when we start with an empty buffer, the first allocation of
     * 488+1 bytes will actually allocate 1000 bytes. So if we were to receive
     * one byte at a time, we don't need a reallocation for the first 1000-(488+1)
     * bytes. Afterwards grows the buffer exponentially.
     */
    nm_str_buf_maybe_expand(out_string, NM_UTILS_GET_NEXT_REALLOC_SIZE_488 + 1, FALSE);

    /* We always use all the available buffer size. */
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

/* Taken from systemd's next_datagram_size_fd(). */
gssize
nm_fd_next_datagram_size(int fd)
{
    gssize l;
    int    k;

    /* This is a bit like FIONREAD/SIOCINQ, however a bit more powerful. The difference being: recv(MSG_PEEK) will
     * actually cause the next datagram in the queue to be validated regarding checksums, which FIONREAD doesn't
     * do. This difference is actually of major importance as we need to be sure that the size returned here
     * actually matches what we will read with recvmsg() next, as otherwise we might end up allocating a buffer of
     * the wrong size. */

    l = recv(fd, NULL, 0, MSG_PEEK | MSG_TRUNC);
    if (l < 0) {
        if (NM_IN_SET(errno, EOPNOTSUPP, EFAULT))
            goto fallback;

        return -errno;
    }
    if (l == 0)
        goto fallback;

    return l;

fallback:
    k = 0;

    /* Some sockets (AF_PACKET) do not support null-sized recv() with MSG_TRUNC set, let's fall back to FIONREAD
     * for them. Checksums don't matter for raw sockets anyway, hence this should be fine. */

    if (ioctl(fd, FIONREAD, &k) < 0)
        return -errno;

    return (gssize) k;
}

/*****************************************************************************/

typedef struct {
    GSubprocess *subprocess;
    GSource     *timeout_source;
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
    GMainContext            *main_context;

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
    DIR              *dir;
    struct dirent    *entry;
    GPtrArray        *arr = NULL;
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

/*****************************************************************************/

/* taken from systemd's sockaddr_un_set_path(). */
int
nm_io_sockaddr_un_set(struct sockaddr_un *ret, NMOptionBool is_abstract, const char *path)
{
    gsize l;

    g_return_val_if_fail(ret, -EINVAL);
    g_return_val_if_fail(path, -EINVAL);
    nm_assert_is_ternary(is_abstract);

    if (is_abstract == NM_OPTION_BOOL_DEFAULT)
        is_abstract = nm_io_sockaddr_un_path_is_abstract(path, &path);

    l = strlen(path);
    if (l < 1)
        return -EINVAL;
    if (l > sizeof(ret->sun_path) - 1)
        return -EINVAL;

    if (!is_abstract) {
        if (path[0] != '/') {
            /* non-abstract paths must be absolute. */
            return -EINVAL;
        }
    }

    memset(ret, 0, nm_offsetof(struct sockaddr_un, sun_path));
    ret->sun_family = AF_UNIX;

    if (is_abstract) {
        ret->sun_path[0] = '\0';
        memcpy(&ret->sun_path[1], path, NM_MIN(l + 1, sizeof(ret->sun_path) - 1));
    } else
        memcpy(&ret->sun_path, path, l + 1);

    /* For pathname addresses, we return the size with the trailing NUL.
     * For abstract addresses, we return the size without the trailing NUL
     * (which may not be even written). But as abstract sockets also have
     * a NUL at the beginning of sun_path, the total length is always
     * calculated the same. */
    return (nm_offsetof(struct sockaddr_un, sun_path) + 1) + l;
}

/*****************************************************************************/

/* taken from systemd's sd_notify(). */
int
nm_sd_notify(const char *state)
{
    struct sockaddr_un sockaddr;
    struct iovec       iovec;
    struct msghdr      msghdr = {
             .msg_iov    = &iovec,
             .msg_iovlen = 1,
             .msg_name   = &sockaddr,
    };
    nm_auto_close int fd = -1;
    const char       *e;
    int               r;

    if (!state)
        g_return_val_if_reached(-EINVAL);

    e = getenv("NOTIFY_SOCKET");
    if (!e)
        return 0;

    r = nm_io_sockaddr_un_set(&sockaddr, NM_OPTION_BOOL_DEFAULT, e);
    if (r < 0)
        return r;
    msghdr.msg_namelen = r;

    fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -NM_ERRNO_NATIVE(errno);

    /* systemd calls here fd_set_sndbuf(fd, SNDBUF_SIZE) .We don't bother. */

    iovec = (struct iovec){
        .iov_base = (gpointer) state,
        .iov_len  = strlen(state),
    };

    /* systemd sends ucred, if geteuid()/getegid() does not match getuid()/getgid(). We don't bother. */

    if (sendmsg(fd, &msghdr, MSG_NOSIGNAL) < 0)
        return -NM_ERRNO_NATIVE(errno);

    return 0;
}

/*****************************************************************************/

#define SHELL_NEED_ESCAPE "\"\\`$"

int
nm_parse_env_file_full(
    const char *contents,
    int (*push)(unsigned line, const char *key, const char *value, void *userdata),
    void *userdata)
{
    gsize                    last_value_whitespace = G_MAXSIZE;
    gsize                    last_key_whitespace   = G_MAXSIZE;
    nm_auto_str_buf NMStrBuf key                   = NM_STR_BUF_INIT(0, FALSE);
    nm_auto_str_buf NMStrBuf value                 = NM_STR_BUF_INIT(0, FALSE);
    unsigned                 line                  = 1;
    int                      r;
    enum {
        PRE_KEY,
        KEY,
        PRE_VALUE,
        VALUE,
        VALUE_ESCAPE,
        SINGLE_QUOTE_VALUE,
        DOUBLE_QUOTE_VALUE,
        DOUBLE_QUOTE_VALUE_ESCAPE,
        COMMENT,
        COMMENT_ESCAPE
    } state = PRE_KEY;

    /* Copied and adjusted from systemd's parse_env_file_internal().
     * https://github.com/systemd/systemd/blob/6247128902ca71ee2ad406cf69af04ea389d3d27/src/basic/env-file.c#L15 */

    nm_assert(push);

    if (!contents)
        return -ENOENT;

    for (const char *p = contents; *p; p++) {
        char c = *p;

        switch (state) {
        case PRE_KEY:
            if (NM_IN_SET(c, '#', ';'))
                state = COMMENT;
            else if (!nm_ascii_is_whitespace(c)) {
                state               = KEY;
                last_key_whitespace = G_MAXSIZE;
                nm_str_buf_append_c(&key, c);
            }
            break;

        case KEY:
            if (nm_ascii_is_newline(c)) {
                state = PRE_KEY;
                line++;
                nm_str_buf_reset(&key);
            } else if (c == '=') {
                state                 = PRE_VALUE;
                last_value_whitespace = G_MAXSIZE;
            } else {
                if (!nm_ascii_is_whitespace(c))
                    last_key_whitespace = G_MAXSIZE;
                else if (last_key_whitespace == G_MAXSIZE)
                    last_key_whitespace = key.len;
                nm_str_buf_append_c(&key, c);
            }
            break;

        case PRE_VALUE:
            if (nm_ascii_is_newline(c)) {
                state = PRE_KEY;
                line++;

                /* strip trailing whitespace from key */
                if (last_key_whitespace != G_MAXSIZE)
                    nm_str_buf_get_str_unsafe(&key)[last_key_whitespace] = 0;

                r = push(line,
                         nm_str_buf_get_str(&key),
                         nm_str_buf_get_str(&value) ?: "",
                         userdata);
                if (r < 0)
                    return r;

                nm_str_buf_reset(&key);
                nm_str_buf_reset(&value);
            } else if (c == '\'')
                state = SINGLE_QUOTE_VALUE;
            else if (c == '"')
                state = DOUBLE_QUOTE_VALUE;
            else if (c == '\\')
                state = VALUE_ESCAPE;
            else if (!nm_ascii_is_whitespace(c)) {
                state = VALUE;
                nm_str_buf_append_c(&value, c);
            }

            break;

        case VALUE:
            if (nm_ascii_is_newline(c)) {
                state = PRE_KEY;
                line++;

                /* Chomp off trailing whitespace from value */
                if (last_value_whitespace != G_MAXSIZE)
                    nm_str_buf_get_str_unsafe(&value)[last_value_whitespace] = 0;

                /* strip trailing whitespace from key */
                if (last_key_whitespace != G_MAXSIZE)
                    nm_str_buf_get_str_unsafe(&key)[last_key_whitespace] = 0;

                r = push(line,
                         nm_str_buf_get_str(&key),
                         nm_str_buf_get_str(&value) ?: "",
                         userdata);
                if (r < 0)
                    return r;

                nm_str_buf_reset(&key);
                nm_str_buf_reset(&value);
            } else if (c == '\\') {
                state                 = VALUE_ESCAPE;
                last_value_whitespace = G_MAXSIZE;
            } else {
                if (!nm_ascii_is_whitespace(c))
                    last_value_whitespace = G_MAXSIZE;
                else if (last_value_whitespace == G_MAXSIZE)
                    last_value_whitespace = value.len;
                nm_str_buf_append_c(&value, c);
            }
            break;

        case VALUE_ESCAPE:
            state = VALUE;
            if (!nm_ascii_is_newline(c)) {
                /* Escaped newlines we eat up entirely */
                nm_str_buf_append_c(&value, c);
            }
            break;

        case SINGLE_QUOTE_VALUE:
            if (c == '\'')
                state = PRE_VALUE;
            else
                nm_str_buf_append_c(&value, c);
            break;

        case DOUBLE_QUOTE_VALUE:
            if (c == '"')
                state = PRE_VALUE;
            else if (c == '\\')
                state = DOUBLE_QUOTE_VALUE_ESCAPE;
            else
                nm_str_buf_append_c(&value, c);
            break;

        case DOUBLE_QUOTE_VALUE_ESCAPE:
            state = DOUBLE_QUOTE_VALUE;
            if (strchr(SHELL_NEED_ESCAPE, c)) {
                /* If this is a char that needs escaping, just unescape it. */
                nm_str_buf_append_c(&value, c);
            } else if (c != '\n') {
                /* If other char than what needs escaping, keep the "\" in place, like the
                 * real shell does. */
                nm_str_buf_append_c(&value, '\\', c);
            }
            /* Escaped newlines (aka "continuation lines") are eaten up entirely */
            break;

        case COMMENT:
            if (c == '\\')
                state = COMMENT_ESCAPE;
            else if (nm_ascii_is_newline(c)) {
                state = PRE_KEY;
                line++;
            }
            break;

        case COMMENT_ESCAPE:
            state = COMMENT;
            break;
        }
    }

    if (NM_IN_SET(state,
                  PRE_VALUE,
                  VALUE,
                  VALUE_ESCAPE,
                  SINGLE_QUOTE_VALUE,
                  DOUBLE_QUOTE_VALUE,
                  DOUBLE_QUOTE_VALUE_ESCAPE)) {
        if (state == VALUE)
            if (last_value_whitespace != G_MAXSIZE)
                nm_str_buf_get_str_unsafe(&value)[last_value_whitespace] = 0;

        /* strip trailing whitespace from key */
        if (last_key_whitespace != G_MAXSIZE)
            nm_str_buf_get_str_unsafe(&key)[last_key_whitespace] = 0;

        r = push(line, nm_str_buf_get_str(&key), nm_str_buf_get_str(&value) ?: "", userdata);
        if (r < 0)
            return r;
    }

    return 0;
}

/*****************************************************************************/

static int
check_utf8ness_and_warn(const char *key, const char *value)
{
    /* Taken from systemd's check_utf8ness_and_warn()
     * https://github.com/systemd/systemd/blob/6247128902ca71ee2ad406cf69af04ea389d3d27/src/basic/env-file.c#L273 */

    if (!g_utf8_validate(key, -1, NULL))
        return -EINVAL;

    if (!g_utf8_validate(value, -1, NULL))
        return -EINVAL;

    return 0;
}

static int
parse_env_file_push(unsigned line, const char *key, const char *value, void *userdata)
{
    const char *k;
    va_list    *ap = userdata;
    va_list     aq;
    int         r;

    r = check_utf8ness_and_warn(key, value);
    if (r < 0)
        return r;

    va_copy(aq, *ap);

    while ((k = va_arg(aq, const char *))) {
        char **v;

        v = va_arg(aq, char **);
        if (nm_streq(key, k)) {
            va_end(aq);
            g_free(*v);
            *v = g_strdup(value);
            return 1;
        }
    }

    va_end(aq);
    return 0;
}

int
nm_parse_env_filev(const char *contents, va_list ap)
{
    va_list aq;
    int     r;

    /* Copied from systemd's parse_env_filev().
     * https://github.com/systemd/systemd/blob/6247128902ca71ee2ad406cf69af04ea389d3d27/src/basic/env-file.c#L333 */

    va_copy(aq, ap);
    r = nm_parse_env_file_full(contents, parse_env_file_push, &aq);
    va_end(aq);
    return r;
}

int
nm_parse_env_file_sentinel(const char *contents, ...)
{
    va_list ap;
    int     r;

    /* Copied from systemd's parse_env_file_sentinel().
     * https://github.com/systemd/systemd/blob/6247128902ca71ee2ad406cf69af04ea389d3d27/src/basic/env-file.c#L347 */

    va_start(ap, contents);
    r = nm_parse_env_filev(contents, ap);
    va_end(ap);
    return r;
}
