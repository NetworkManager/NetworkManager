/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "nm-sd-adapt-shared.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hexdecoct.h"
#include "log.h"
#include "macro.h"
#include "mkdir.h"
#include "parse-util.h"
#include "path-util.h"
#include "socket-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "tmpfile-util.h"

#define READ_FULL_BYTES_MAX (4U*1024U*1024U)

int fopen_unlocked(const char *path, const char *options, FILE **ret) {
        assert(ret);

        FILE *f = fopen(path, options);
        if (!f)
                return -errno;

        (void) __fsetlocking(f, FSETLOCKING_BYCALLER);

        *ret = f;
        return 0;
}

int fdopen_unlocked(int fd, const char *options, FILE **ret) {
        assert(ret);

        FILE *f = fdopen(fd, options);
        if (!f)
                return -errno;

        (void) __fsetlocking(f, FSETLOCKING_BYCALLER);

        *ret = f;
        return 0;
}

int take_fdopen_unlocked(int *fd, const char *options, FILE **ret) {
        int     r;

        assert(fd);

        r = fdopen_unlocked(*fd, options, ret);
        if (r < 0)
                return r;

        *fd = -1;

        return 0;
}

FILE* take_fdopen(int *fd, const char *options) {
        assert(fd);

        FILE *f = fdopen(*fd, options);
        if (!f)
                return NULL;

        *fd = -1;

        return f;
}

DIR* take_fdopendir(int *dfd) {
        assert(dfd);

        DIR *d = fdopendir(*dfd);
        if (!d)
                return NULL;

        *dfd = -1;

        return d;
}

FILE* open_memstream_unlocked(char **ptr, size_t *sizeloc) {
        FILE *f = open_memstream(ptr, sizeloc);
        if (!f)
                return NULL;

        (void) __fsetlocking(f, FSETLOCKING_BYCALLER);

        return f;
}

FILE* fmemopen_unlocked(void *buf, size_t size, const char *mode) {
        FILE *f = fmemopen(buf, size, mode);
        if (!f)
                return NULL;

        (void) __fsetlocking(f, FSETLOCKING_BYCALLER);

        return f;
}

#if 0 /* NM_IGNORED */
int write_string_stream_ts(
                FILE *f,
                const char *line,
                WriteStringFileFlags flags,
                const struct timespec *ts) {

        bool needs_nl;
        int r, fd;

        assert(f);
        assert(line);

        if (ferror(f))
                return -EIO;

        if (ts) {
                /* If we shall set the timestamp we need the fd. But fmemopen() streams generally don't have
                 * an fd. Let's fail early in that case. */
                fd = fileno(f);
                if (fd < 0)
                        return -EBADF;
        }

        needs_nl = !(flags & WRITE_STRING_FILE_AVOID_NEWLINE) && !endswith(line, "\n");

        if (needs_nl && (flags & WRITE_STRING_FILE_DISABLE_BUFFER)) {
                /* If STDIO buffering was disabled, then let's append the newline character to the string itself, so
                 * that the write goes out in one go, instead of two */

                line = strjoina(line, "\n");
                needs_nl = false;
        }

        if (fputs(line, f) == EOF)
                return -errno;

        if (needs_nl)
                if (fputc('\n', f) == EOF)
                        return -errno;

        if (flags & WRITE_STRING_FILE_SYNC)
                r = fflush_sync_and_check(f);
        else
                r = fflush_and_check(f);
        if (r < 0)
                return r;

        if (ts) {
                const struct timespec twice[2] = {*ts, *ts};

                if (futimens(fd, twice) < 0)
                        return -errno;
        }

        return 0;
}

static int write_string_file_atomic(
                const char *fn,
                const char *line,
                WriteStringFileFlags flags,
                const struct timespec *ts) {

        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *p = NULL;
        int r;

        assert(fn);
        assert(line);

        /* Note that we'd really like to use O_TMPFILE here, but can't really, since we want replacement
         * semantics here, and O_TMPFILE can't offer that. i.e. rename() replaces but linkat() doesn't. */

        r = fopen_temporary(fn, &f, &p);
        if (r < 0)
                return r;

        r = write_string_stream_ts(f, line, flags, ts);
        if (r < 0)
                goto fail;

        r = fchmod_umask(fileno(f), FLAGS_SET(flags, WRITE_STRING_FILE_MODE_0600) ? 0600 : 0644);
        if (r < 0)
                goto fail;

        if (rename(p, fn) < 0) {
                r = -errno;
                goto fail;
        }

        if (FLAGS_SET(flags, WRITE_STRING_FILE_SYNC)) {
                /* Sync the rename, too */
                r = fsync_directory_of_file(fileno(f));
                if (r < 0)
                        return r;
        }

        return 0;

fail:
        (void) unlink(p);
        return r;
}

int write_string_file_ts(
                const char *fn,
                const char *line,
                WriteStringFileFlags flags,
                const struct timespec *ts) {

        _cleanup_fclose_ FILE *f = NULL;
        int q, r, fd;

        assert(fn);
        assert(line);

        /* We don't know how to verify whether the file contents was already on-disk. */
        assert(!((flags & WRITE_STRING_FILE_VERIFY_ON_FAILURE) && (flags & WRITE_STRING_FILE_SYNC)));

        if (flags & WRITE_STRING_FILE_MKDIR_0755) {
                r = mkdir_parents(fn, 0755);
                if (r < 0)
                        return r;
        }

        if (flags & WRITE_STRING_FILE_ATOMIC) {
                assert(flags & WRITE_STRING_FILE_CREATE);

                r = write_string_file_atomic(fn, line, flags, ts);
                if (r < 0)
                        goto fail;

                return r;
        } else
                assert(!ts);

        /* We manually build our own version of fopen(..., "we") that works without O_CREAT and with O_NOFOLLOW if needed. */
        fd = open(fn, O_WRONLY|O_CLOEXEC|O_NOCTTY |
                  (FLAGS_SET(flags, WRITE_STRING_FILE_NOFOLLOW) ? O_NOFOLLOW : 0) |
                  (FLAGS_SET(flags, WRITE_STRING_FILE_CREATE) ? O_CREAT : 0) |
                  (FLAGS_SET(flags, WRITE_STRING_FILE_TRUNCATE) ? O_TRUNC : 0),
                  (FLAGS_SET(flags, WRITE_STRING_FILE_MODE_0600) ? 0600 : 0666));
        if (fd < 0) {
                r = -errno;
                goto fail;
        }

        r = fdopen_unlocked(fd, "w", &f);
        if (r < 0) {
                safe_close(fd);
                goto fail;
        }

        if (flags & WRITE_STRING_FILE_DISABLE_BUFFER)
                setvbuf(f, NULL, _IONBF, 0);

        r = write_string_stream_ts(f, line, flags, ts);
        if (r < 0)
                goto fail;

        return 0;

fail:
        if (!(flags & WRITE_STRING_FILE_VERIFY_ON_FAILURE))
                return r;

        f = safe_fclose(f);

        /* OK, the operation failed, but let's see if the right
         * contents in place already. If so, eat up the error. */

        q = verify_file(fn, line, !(flags & WRITE_STRING_FILE_AVOID_NEWLINE));
        if (q <= 0)
                return r;

        return 0;
}

int write_string_filef(
                const char *fn,
                WriteStringFileFlags flags,
                const char *format, ...) {

        _cleanup_free_ char *p = NULL;
        va_list ap;
        int r;

        va_start(ap, format);
        r = vasprintf(&p, format, ap);
        va_end(ap);

        if (r < 0)
                return -ENOMEM;

        return write_string_file(fn, p, flags);
}

int read_one_line_file(const char *fn, char **line) {
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(fn);
        assert(line);

        r = fopen_unlocked(fn, "re", &f);
        if (r < 0)
                return r;

        return read_line(f, LONG_LINE_MAX, line);
}

int verify_file(const char *fn, const char *blob, bool accept_extra_nl) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *buf = NULL;
        size_t l, k;
        int r;

        assert(fn);
        assert(blob);

        l = strlen(blob);

        if (accept_extra_nl && endswith(blob, "\n"))
                accept_extra_nl = false;

        buf = malloc(l + accept_extra_nl + 1);
        if (!buf)
                return -ENOMEM;

        r = fopen_unlocked(fn, "re", &f);
        if (r < 0)
                return r;

        /* We try to read one byte more than we need, so that we know whether we hit eof */
        errno = 0;
        k = fread(buf, 1, l + accept_extra_nl + 1, f);
        if (ferror(f))
                return errno_or_else(EIO);

        if (k != l && k != l + accept_extra_nl)
                return 0;
        if (memcmp(buf, blob, l) != 0)
                return 0;
        if (k > l && buf[l] != '\n')
                return 0;

        return 1;
}
#endif /* NM_IGNORED */

int read_full_virtual_file(const char *filename, char **ret_contents, size_t *ret_size) {
        _cleanup_free_ char *buf = NULL;
        _cleanup_close_ int fd = -1;
        struct stat st;
        size_t n, size;
        int n_retries;
        char *p;

        assert(ret_contents);

        /* Virtual filesystems such as sysfs or procfs use kernfs, and kernfs can work
         * with two sorts of virtual files. One sort uses "seq_file", and the results of
         * the first read are buffered for the second read. The other sort uses "raw"
         * reads which always go direct to the device. In the latter case, the content of
         * the virtual file must be retrieved with a single read otherwise a second read
         * might get the new value instead of finding EOF immediately. That's the reason
         * why the usage of fread(3) is prohibited in this case as it always performs a
         * second call to read(2) looking for EOF. See issue 13585. */

        fd = open(filename, O_RDONLY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        /* Start size for files in /proc which usually report a file size of 0. */
        size = LINE_MAX / 2;

        /* Limit the number of attempts to read the number of bytes returned by fstat(). */
        n_retries = 3;

        for (;;) {
                if (n_retries <= 0)
                        return -EIO;

                if (fstat(fd, &st) < 0)
                        return -errno;

                if (!S_ISREG(st.st_mode))
                        return -EBADF;

                /* Be prepared for files from /proc which generally report a file size of 0. */
                if (st.st_size > 0) {
                        size = st.st_size;
                        n_retries--;
                } else
                        size = size * 2;

                if (size > READ_FULL_BYTES_MAX)
                        return -E2BIG;

                p = realloc(buf, size + 1);
                if (!p)
                        return -ENOMEM;
                buf = TAKE_PTR(p);

                for (;;) {
                        ssize_t k;

                        /* Read one more byte so we can detect whether the content of the
                         * file has already changed or the guessed size for files from /proc
                         * wasn't large enough . */
                        k = read(fd, buf, size + 1);
                        if (k >= 0) {
                                n = k;
                                break;
                        }

                        if (errno != EINTR)
                                return -errno;
                }

                /* Consider a short read as EOF */
                if (n <= size)
                        break;

                /* Hmm... either we read too few bytes from /proc or less likely the content
                 * of the file might have been changed (and is now bigger) while we were
                 * processing, let's try again either with a bigger guessed size or the new
                 * file size. */

                if (lseek(fd, 0, SEEK_SET) < 0)
                        return -errno;
        }

        if (n < size) {
                p = realloc(buf, n + 1);
                if (!p)
                        return -ENOMEM;
                buf = TAKE_PTR(p);
        }

        if (!ret_size) {
                /* Safety check: if the caller doesn't want to know the size of what we
                 * just read it will rely on the trailing NUL byte. But if there's an
                 * embedded NUL byte, then we should refuse operation as otherwise
                 * there'd be ambiguity about what we just read. */

                if (memchr(buf, 0, n))
                        return -EBADMSG;
        } else
                *ret_size = n;

        buf[n] = 0;
        *ret_contents = TAKE_PTR(buf);

        return 0;
}

int read_full_stream_full(
                FILE *f,
                const char *filename,
                uint64_t offset,
                size_t size,
                ReadFullFileFlags flags,
                char **ret_contents,
                size_t *ret_size) {

        _cleanup_free_ char *buf = NULL;
        size_t n, n_next, l;
        int fd, r;

        assert(f);
        assert(ret_contents);
        assert(!FLAGS_SET(flags, READ_FULL_FILE_UNBASE64 | READ_FULL_FILE_UNHEX));

        if (offset != UINT64_MAX && offset > LONG_MAX)
                return -ERANGE;

        n_next = size != SIZE_MAX ? size : LINE_MAX; /* Start size */

        fd = fileno(f);
        if (fd >= 0) { /* If the FILE* object is backed by an fd (as opposed to memory or such, see
                        * fmemopen()), let's optimize our buffering */
                struct stat st;

                if (fstat(fd, &st) < 0)
                        return -errno;

                if (S_ISREG(st.st_mode)) {
                        if (size == SIZE_MAX) {
                                uint64_t rsize =
                                        LESS_BY((uint64_t) st.st_size, offset == UINT64_MAX ? 0 : offset);

                                /* Safety check */
                                if (rsize > READ_FULL_BYTES_MAX)
                                        return -E2BIG;

                                /* Start with the right file size. Note that we increase the size to read
                                 * here by one, so that the first read attempt already makes us notice the
                                 * EOF. If the reported size of the file is zero, we avoid this logic
                                 * however, since quite likely it might be a virtual file in procfs that all
                                 * report a zero file size. */
                                if (st.st_size > 0)
                                        n_next = rsize + 1;
                        }

                        if (flags & READ_FULL_FILE_WARN_WORLD_READABLE)
                                (void) warn_file_is_world_accessible(filename, &st, NULL, 0);
                }
        }

        if (offset != UINT64_MAX && fseek(f, offset, SEEK_SET) < 0)
                return -errno;

        n = l = 0;
        for (;;) {
                char *t;
                size_t k;

                if (flags & READ_FULL_FILE_SECURE) {
                        t = malloc(n_next + 1);
                        if (!t) {
                                r = -ENOMEM;
                                goto finalize;
                        }
                        memcpy_safe(t, buf, n);
                        explicit_bzero_safe(buf, n);
                        buf = mfree(buf);
                } else {
                        t = realloc(buf, n_next + 1);
                        if (!t)
                                return -ENOMEM;
                }

                buf = t;
                n = n_next;

                errno = 0;
                k = fread(buf + l, 1, n - l, f);

                assert(k <= n - l);
                l += k;

                if (ferror(f)) {
                        r = errno_or_else(EIO);
                        goto finalize;
                }
                if (feof(f))
                        break;

                if (size != SIZE_MAX) { /* If we got asked to read some specific size, we already sized the buffer right, hence leave */
                        assert(l == size);
                        break;
                }

                assert(k > 0); /* we can't have read zero bytes because that would have been EOF */

                /* Safety check */
                if (n >= READ_FULL_BYTES_MAX) {
                        r = -E2BIG;
                        goto finalize;
                }

                n_next = MIN(n * 2, READ_FULL_BYTES_MAX);
        }

        if (flags & (READ_FULL_FILE_UNBASE64 | READ_FULL_FILE_UNHEX)) {
                _cleanup_free_ void *decoded = NULL;
                size_t decoded_size;

                buf[l++] = 0;
                if (flags & READ_FULL_FILE_UNBASE64)
                        r = unbase64mem_full(buf, l, flags & READ_FULL_FILE_SECURE, &decoded, &decoded_size);
                else
                        r = unhexmem_full(buf, l, flags & READ_FULL_FILE_SECURE, &decoded, &decoded_size);
                if (r < 0)
                        goto finalize;

                if (flags & READ_FULL_FILE_SECURE)
                        explicit_bzero_safe(buf, n);
                free_and_replace(buf, decoded);
                n = l = decoded_size;
        }

        if (!ret_size) {
                /* Safety check: if the caller doesn't want to know the size of what we just read it will rely on the
                 * trailing NUL byte. But if there's an embedded NUL byte, then we should refuse operation as otherwise
                 * there'd be ambiguity about what we just read. */

                if (memchr(buf, 0, l)) {
                        r = -EBADMSG;
                        goto finalize;
                }
        }

        buf[l] = 0;
        *ret_contents = TAKE_PTR(buf);

        if (ret_size)
                *ret_size = l;

        return 0;

finalize:
        if (flags & READ_FULL_FILE_SECURE)
                explicit_bzero_safe(buf, n);

        return r;
}

int read_full_file_full(
                int dir_fd,
                const char *filename,
                uint64_t offset,
                size_t size,
                ReadFullFileFlags flags,
                const char *bind_name,
                char **ret_contents,
                size_t *ret_size) {

        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(filename);
        assert(ret_contents);

        r = xfopenat(dir_fd, filename, "re", 0, &f);
        if (r < 0) {
                _cleanup_close_ int dfd = -1, sk = -1;
                union sockaddr_union sa;

                /* ENXIO is what Linux returns if we open a node that is an AF_UNIX socket */
                if (r != -ENXIO)
                        return r;

                /* If this is enabled, let's try to connect to it */
                if (!FLAGS_SET(flags, READ_FULL_FILE_CONNECT_SOCKET))
                        return -ENXIO;

                /* Seeking is not supported on AF_UNIX sockets */
                if (offset != UINT64_MAX)
                        return -ESPIPE;

                if (dir_fd == AT_FDCWD)
                        r = sockaddr_un_set_path(&sa.un, filename);
                else {
                        char procfs_path[STRLEN("/proc/self/fd/") + DECIMAL_STR_MAX(int)];

                        /* If we shall operate relative to some directory, then let's use O_PATH first to
                         * open the socket inode, and then connect to it via /proc/self/fd/. We have to do
                         * this since there's not connectat() that takes a directory fd as first arg. */

                        dfd = openat(dir_fd, filename, O_PATH|O_CLOEXEC);
                        if (dfd < 0)
                                return -errno;

                        xsprintf(procfs_path, "/proc/self/fd/%i", dfd);
                        r = sockaddr_un_set_path(&sa.un, procfs_path);
                }
                if (r < 0)
                        return r;

                sk = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
                if (sk < 0)
                        return -errno;

                if (bind_name) {
                        /* If the caller specified a socket name to bind to, do so before connecting. This is
                         * useful to communicate some minor, short meta-information token from the client to
                         * the server. */
                        union sockaddr_union bsa;

                        r = sockaddr_un_set_path(&bsa.un, bind_name);
                        if (r < 0)
                                return r;

                        if (bind(sk, &bsa.sa, r) < 0)
                                return r;
                }

                if (connect(sk, &sa.sa, SOCKADDR_UN_LEN(sa.un)) < 0)
                        return errno == ENOTSOCK ? -ENXIO : -errno; /* propagate original error if this is
                                                                     * not a socket after all */

                if (shutdown(sk, SHUT_WR) < 0)
                        return -errno;

                f = fdopen(sk, "r");
                if (!f)
                        return -errno;

                TAKE_FD(sk);
        }

        (void) __fsetlocking(f, FSETLOCKING_BYCALLER);

        return read_full_stream_full(f, filename, offset, size, flags, ret_contents, ret_size);
}

#if 0 /* NM_IGNORED */
int executable_is_script(const char *path, char **interpreter) {
        _cleanup_free_ char *line = NULL;
        size_t len;
        char *ans;
        int r;

        assert(path);

        r = read_one_line_file(path, &line);
        if (r == -ENOBUFS) /* First line overly long? if so, then it's not a script */
                return 0;
        if (r < 0)
                return r;

        if (!startswith(line, "#!"))
                return 0;

        ans = strstrip(line + 2);
        len = strcspn(ans, " \t");

        if (len == 0)
                return 0;

        ans = strndup(ans, len);
        if (!ans)
                return -ENOMEM;

        *interpreter = ans;
        return 1;
}
#endif /* NM_IGNORED */

/**
 * Retrieve one field from a file like /proc/self/status.  pattern
 * should not include whitespace or the delimiter (':'). pattern matches only
 * the beginning of a line. Whitespace before ':' is skipped. Whitespace and
 * zeros after the ':' will be skipped. field must be freed afterwards.
 * terminator specifies the terminating characters of the field value (not
 * included in the value).
 */
int get_proc_field(const char *filename, const char *pattern, const char *terminator, char **field) {
        _cleanup_free_ char *status = NULL;
        char *t, *f;
        size_t len;
        int r;

        assert(terminator);
        assert(filename);
        assert(pattern);
        assert(field);

        r = read_full_virtual_file(filename, &status, NULL);
        if (r < 0)
                return r;

        t = status;

        do {
                bool pattern_ok;

                do {
                        t = strstr(t, pattern);
                        if (!t)
                                return -ENOENT;

                        /* Check that pattern occurs in beginning of line. */
                        pattern_ok = (t == status || t[-1] == '\n');

                        t += strlen(pattern);

                } while (!pattern_ok);

                t += strspn(t, " \t");
                if (!*t)
                        return -ENOENT;

        } while (*t != ':');

        t++;

        if (*t) {
                t += strspn(t, " \t");

                /* Also skip zeros, because when this is used for
                 * capabilities, we don't want the zeros. This way the
                 * same capability set always maps to the same string,
                 * irrespective of the total capability set size. For
                 * other numbers it shouldn't matter. */
                t += strspn(t, "0");
                /* Back off one char if there's nothing but whitespace
                   and zeros */
                if (!*t || isspace(*t))
                        t--;
        }

        len = strcspn(t, terminator);

        f = strndup(t, len);
        if (!f)
                return -ENOMEM;

        *field = f;
        return 0;
}

DIR *xopendirat(int fd, const char *name, int flags) {
        int nfd;
        DIR *d;

        assert(!(flags & O_CREAT));

        nfd = openat(fd, name, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC|flags, 0);
        if (nfd < 0)
                return NULL;

        d = fdopendir(nfd);
        if (!d) {
                safe_close(nfd);
                return NULL;
        }

        return d;
}

static int mode_to_flags(const char *mode) {
        const char *p;
        int flags;

        if ((p = startswith(mode, "r+")))
                flags = O_RDWR;
        else if ((p = startswith(mode, "r")))
                flags = O_RDONLY;
        else if ((p = startswith(mode, "w+")))
                flags = O_RDWR|O_CREAT|O_TRUNC;
        else if ((p = startswith(mode, "w")))
                flags = O_WRONLY|O_CREAT|O_TRUNC;
        else if ((p = startswith(mode, "a+")))
                flags = O_RDWR|O_CREAT|O_APPEND;
        else if ((p = startswith(mode, "a")))
                flags = O_WRONLY|O_CREAT|O_APPEND;
        else
                return -EINVAL;

        for (; *p != 0; p++) {

                switch (*p) {

                case 'e':
                        flags |= O_CLOEXEC;
                        break;

                case 'x':
                        flags |= O_EXCL;
                        break;

                case 'm':
                        /* ignore this here, fdopen() might care later though */
                        break;

                case 'c': /* not sure what to do about this one */
                default:
                        return -EINVAL;
                }
        }

        return flags;
}

int xfopenat(int dir_fd, const char *path, const char *mode, int flags, FILE **ret) {
        FILE *f;

        /* A combination of fopen() with openat() */

        if (dir_fd == AT_FDCWD && flags == 0) {
                f = fopen(path, mode);
                if (!f)
                        return -errno;
        } else {
                int fd, mode_flags;

                mode_flags = mode_to_flags(mode);
                if (mode_flags < 0)
                        return mode_flags;

                fd = openat(dir_fd, path, mode_flags | flags);
                if (fd < 0)
                        return -errno;

                f = fdopen(fd, mode);
                if (!f) {
                        safe_close(fd);
                        return -errno;
                }
        }

        *ret = f;
        return 0;
}

#if 0 /* NM_IGNORED */
static int search_and_fopen_internal(const char *path, const char *mode, const char *root, char **search, FILE **_f) {
        char **i;

        assert(path);
        assert(mode);
        assert(_f);

        if (!path_strv_resolve_uniq(search, root))
                return -ENOMEM;

        STRV_FOREACH(i, search) {
                _cleanup_free_ char *p = NULL;
                FILE *f;

                p = path_join(root, *i, path);
                if (!p)
                        return -ENOMEM;

                f = fopen(p, mode);
                if (f) {
                        *_f = f;
                        return 0;
                }

                if (errno != ENOENT)
                        return -errno;
        }

        return -ENOENT;
}

int search_and_fopen(const char *path, const char *mode, const char *root, const char **search, FILE **_f) {
        _cleanup_strv_free_ char **copy = NULL;

        assert(path);
        assert(mode);
        assert(_f);

        if (path_is_absolute(path)) {
                FILE *f;

                f = fopen(path, mode);
                if (f) {
                        *_f = f;
                        return 0;
                }

                return -errno;
        }

        copy = strv_copy((char**) search);
        if (!copy)
                return -ENOMEM;

        return search_and_fopen_internal(path, mode, root, copy, _f);
}

int search_and_fopen_nulstr(const char *path, const char *mode, const char *root, const char *search, FILE **_f) {
        _cleanup_strv_free_ char **s = NULL;

        if (path_is_absolute(path)) {
                FILE *f;

                f = fopen(path, mode);
                if (f) {
                        *_f = f;
                        return 0;
                }

                return -errno;
        }

        s = strv_split_nulstr(search);
        if (!s)
                return -ENOMEM;

        return search_and_fopen_internal(path, mode, root, s, _f);
}

int chase_symlinks_and_fopen_unlocked(
                const char *path,
                const char *root,
                unsigned chase_flags,
                const char *open_flags,
                FILE **ret_file,
                char **ret_path) {

        _cleanup_close_ int fd = -1;
        _cleanup_free_ char *final_path = NULL;
        int mode_flags, r;
        FILE *f;

        assert(path);
        assert(open_flags);
        assert(ret_file);

        mode_flags = mode_to_flags(open_flags);
        if (mode_flags < 0)
                return mode_flags;

        fd = chase_symlinks_and_open(path, root, chase_flags, mode_flags, ret_path ? &final_path : NULL);
        if (fd < 0)
                return fd;

        r = fdopen_unlocked(fd, open_flags, &f);
        if (r < 0)
                return r;
        TAKE_FD(fd);

        *ret_file = f;
        if (ret_path)
                *ret_path = TAKE_PTR(final_path);
        return 0;
}
#endif /* NM_IGNORED */

int fflush_and_check(FILE *f) {
        assert(f);

        errno = 0;
        fflush(f);

        if (ferror(f))
                return errno_or_else(EIO);

        return 0;
}

#if 0 /* NM_IGNORED */
int fflush_sync_and_check(FILE *f) {
        int r, fd;

        assert(f);

        r = fflush_and_check(f);
        if (r < 0)
                return r;

        /* Not all file streams have an fd associated (think: fmemopen()), let's handle this gracefully and
         * assume that in that case we need no explicit syncing */
        fd = fileno(f);
        if (fd < 0)
                return 0;

        if (fsync(fd) < 0)
                return -errno;

        r = fsync_directory_of_file(fd);
        if (r < 0)
                return r;

        return 0;
}

int write_timestamp_file_atomic(const char *fn, usec_t n) {
        char ln[DECIMAL_STR_MAX(n)+2];

        /* Creates a "timestamp" file, that contains nothing but a
         * usec_t timestamp, formatted in ASCII. */

        if (n <= 0 || n >= USEC_INFINITY)
                return -ERANGE;

        xsprintf(ln, USEC_FMT "\n", n);

        return write_string_file(fn, ln, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC);
}

int read_timestamp_file(const char *fn, usec_t *ret) {
        _cleanup_free_ char *ln = NULL;
        uint64_t t;
        int r;

        r = read_one_line_file(fn, &ln);
        if (r < 0)
                return r;

        r = safe_atou64(ln, &t);
        if (r < 0)
                return r;

        if (t <= 0 || t >= (uint64_t) USEC_INFINITY)
                return -ERANGE;

        *ret = (usec_t) t;
        return 0;
}
#endif /* NM_IGNORED */

int fputs_with_space(FILE *f, const char *s, const char *separator, bool *space) {
        int r;

        assert(s);

        /* Outputs the specified string with fputs(), but optionally prefixes it with a separator. The *space parameter
         * when specified shall initially point to a boolean variable initialized to false. It is set to true after the
         * first invocation. This call is supposed to be use in loops, where a separator shall be inserted between each
         * element, but not before the first one. */

        if (!f)
                f = stdout;

        if (space) {
                if (!separator)
                        separator = " ";

                if (*space) {
                        r = fputs(separator, f);
                        if (r < 0)
                                return r;
                }

                *space = true;
        }

        return fputs(s, f);
}

#if 0 /* NM_IGNORED */
/* A bitmask of the EOL markers we know */
typedef enum EndOfLineMarker {
        EOL_NONE     = 0,
        EOL_ZERO     = 1 << 0,  /* \0 (aka NUL) */
        EOL_TEN      = 1 << 1,  /* \n (aka NL, aka LF)  */
        EOL_THIRTEEN = 1 << 2,  /* \r (aka CR)  */
} EndOfLineMarker;

static EndOfLineMarker categorize_eol(char c, ReadLineFlags flags) {

        if (!IN_SET(flags, READ_LINE_ONLY_NUL)) {
                if (c == '\n')
                        return EOL_TEN;
                if (c == '\r')
                        return EOL_THIRTEEN;
        }

        if (c == '\0')
                return EOL_ZERO;

        return EOL_NONE;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(FILE*, funlockfile);

int read_line_full(FILE *f, size_t limit, ReadLineFlags flags, char **ret) {
        size_t n = 0, allocated = 0, count = 0;
        _cleanup_free_ char *buffer = NULL;
        int r;

        assert(f);

        /* Something like a bounded version of getline().
         *
         * Considers EOF, \n, \r and \0 end of line delimiters (or combinations of these), and does not include these
         * delimiters in the string returned. Specifically, recognizes the following combinations of markers as line
         * endings:
         *
         *     • \n        (UNIX)
         *     • \r        (old MacOS)
         *     • \0        (C strings)
         *     • \n\0
         *     • \r\0
         *     • \r\n      (Windows)
         *     • \n\r
         *     • \r\n\0
         *     • \n\r\0
         *
         * Returns the number of bytes read from the files (i.e. including delimiters — this hence usually differs from
         * the number of characters in the returned string). When EOF is hit, 0 is returned.
         *
         * The input parameter limit is the maximum numbers of characters in the returned string, i.e. excluding
         * delimiters. If the limit is hit we fail and return -ENOBUFS.
         *
         * If a line shall be skipped ret may be initialized as NULL. */

        if (ret) {
                if (!GREEDY_REALLOC(buffer, allocated, 1))
                        return -ENOMEM;
        }

        {
                _unused_ _cleanup_(funlockfilep) FILE *flocked = f;
                EndOfLineMarker previous_eol = EOL_NONE;
                flockfile(f);

                for (;;) {
                        EndOfLineMarker eol;
                        char c;

                        if (n >= limit)
                                return -ENOBUFS;

                        if (count >= INT_MAX) /* We couldn't return the counter anymore as "int", hence refuse this */
                                return -ENOBUFS;

                        r = safe_fgetc(f, &c);
                        if (r < 0)
                                return r;
                        if (r == 0) /* EOF is definitely EOL */
                                break;

                        eol = categorize_eol(c, flags);

                        if (FLAGS_SET(previous_eol, EOL_ZERO) ||
                            (eol == EOL_NONE && previous_eol != EOL_NONE) ||
                            (eol != EOL_NONE && (previous_eol & eol) != 0)) {
                                /* Previous char was a NUL? This is not an EOL, but the previous char was? This type of
                                 * EOL marker has been seen right before?  In either of these three cases we are
                                 * done. But first, let's put this character back in the queue. (Note that we have to
                                 * cast this to (unsigned char) here as ungetc() expects a positive 'int', and if we
                                 * are on an architecture where 'char' equals 'signed char' we need to ensure we don't
                                 * pass a negative value here. That said, to complicate things further ungetc() is
                                 * actually happy with most negative characters and implicitly casts them back to
                                 * positive ones as needed, except for \xff (aka -1, aka EOF), which it refuses. What a
                                 * godawful API!) */
                                assert_se(ungetc((unsigned char) c, f) != EOF);
                                break;
                        }

                        count++;

                        if (eol != EOL_NONE) {
                                /* If we are on a tty, we can't shouldn't wait for more input, because that
                                 * generally means waiting for the user, interactively. In the case of a TTY
                                 * we expect only \n as the single EOL marker, so we are in the lucky
                                 * position that there is no need to wait. We check this condition last, to
                                 * avoid isatty() check if not necessary. */

                                if ((flags & (READ_LINE_IS_A_TTY|READ_LINE_NOT_A_TTY)) == 0) {
                                        int fd;

                                        fd = fileno(f);
                                        if (fd < 0) /* Maybe an fmemopen() stream? Handle this gracefully,
                                                     * and don't call isatty() on an invalid fd */
                                                flags |= READ_LINE_NOT_A_TTY;
                                        else
                                                flags |= isatty(fd) ? READ_LINE_IS_A_TTY : READ_LINE_NOT_A_TTY;
                                }
                                if (FLAGS_SET(flags, READ_LINE_IS_A_TTY))
                                        break;
                        }

                        if (eol != EOL_NONE) {
                                previous_eol |= eol;
                                continue;
                        }

                        if (ret) {
                                if (!GREEDY_REALLOC(buffer, allocated, n + 2))
                                        return -ENOMEM;

                                buffer[n] = c;
                        }

                        n++;
                }
        }

        if (ret) {
                buffer[n] = 0;

                *ret = TAKE_PTR(buffer);
        }

        return (int) count;
}

int safe_fgetc(FILE *f, char *ret) {
        int k;

        assert(f);

        /* A safer version of plain fgetc(): let's propagate the error that happened while reading as such, and
         * separate the EOF condition from the byte read, to avoid those confusion signed/unsigned issues fgetc()
         * has. */

        errno = 0;
        k = fgetc(f);
        if (k == EOF) {
                if (ferror(f))
                        return errno_or_else(EIO);

                if (ret)
                        *ret = 0;

                return 0;
        }

        if (ret)
                *ret = k;

        return 1;
}
#endif /* NM_IGNORED */

int warn_file_is_world_accessible(const char *filename, struct stat *st, const char *unit, unsigned line) {
        struct stat _st;

        if (!filename)
                return 0;

        if (!st) {
                if (stat(filename, &_st) < 0)
                        return -errno;
                st = &_st;
        }

        if ((st->st_mode & S_IRWXO) == 0)
                return 0;

        if (unit)
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "%s has %04o mode that is too permissive, please adjust the ownership and access mode.",
                           filename, st->st_mode & 07777);
        else
                log_warning("%s has %04o mode that is too permissive, please adjust the ownership and access mode.",
                            filename, st->st_mode & 07777);
        return 0;
}

#if 0 /* NM_IGNORED */
int sync_rights(int from, int to) {
        struct stat st;

        if (fstat(from, &st) < 0)
                return -errno;

        return fchmod_and_chown(to, st.st_mode & 07777, st.st_uid, st.st_gid);
}

int rename_and_apply_smack_floor_label(const char *from, const char *to) {
        int r = 0;
        if (rename(from, to) < 0)
                return -errno;

#ifdef SMACK_RUN_LABEL
        r = mac_smack_apply(to, SMACK_ATTR_ACCESS, SMACK_FLOOR_LABEL);
        if (r < 0)
                return r;
#endif
        return r;
}
#endif /* NM_IGNORED */
