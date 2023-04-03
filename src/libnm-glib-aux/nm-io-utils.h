/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2018 Red Hat, Inc.
 */

#ifndef __NM_IO_UTILS_H__
#define __NM_IO_UTILS_H__

#include "nm-macros-internal.h"

/*****************************************************************************/

int nm_io_fcntl_getfl(int fd);

int nm_io_fcntl_setfl(int fd, int flags);

int nm_io_fcntl_setfl_update(int fd, int flags_mask, int flags_value);

void nm_io_fcntl_setfl_update_nonblock(int fd);

/*****************************************************************************/

/**
 * NMUtilsFileGetContentsFlags:
 * @NM_UTILS_FILE_GET_CONTENTS_FLAG_NONE: no flag
 * @NM_UTILS_FILE_GET_CONTENTS_FLAG_SECRET: if present, ensure that no
 *   data is left in memory. Essentially, it means to call nm_explicit_bzero()
 *   to not leave key material on the heap (when reading secrets).
 */
typedef enum {
    NM_UTILS_FILE_GET_CONTENTS_FLAG_NONE   = 0,
    NM_UTILS_FILE_GET_CONTENTS_FLAG_SECRET = (1 << 0),
} NMUtilsFileGetContentsFlags;

gboolean nm_utils_fd_get_contents(int                         fd,
                                  gboolean                    close_fd,
                                  gsize                       max_length,
                                  NMUtilsFileGetContentsFlags flags,
                                  char                      **contents,
                                  gsize                      *length,
                                  int                        *out_errsv,
                                  GError                    **error);

gboolean nm_utils_file_get_contents(int                         dirfd,
                                    const char                 *filename,
                                    gsize                       max_length,
                                    NMUtilsFileGetContentsFlags flags,
                                    char                      **contents,
                                    gsize                      *length,
                                    int                        *out_errsv,
                                    GError                    **error);

gboolean nm_utils_file_set_contents(const char            *filename,
                                    const char            *contents,
                                    gssize                 length,
                                    mode_t                 mode,
                                    const struct timespec *times,
                                    int                   *out_errsv,
                                    GError               **error);

struct _NMStrBuf;

gssize nm_utils_fd_read(int fd, struct _NMStrBuf *out_string);

gssize nm_fd_next_datagram_size(int fd);

struct stat;

int nm_utils_file_stat(const char *filename, struct stat *out_st);

/*****************************************************************************/

/* From systemd's ERRNO_IS_TRANSIENT().
 *
 * For send()/recv() or read()/write(). */
static inline gboolean
NM_ERRNO_IS_TRANSIENT(int r)
{
    return NM_IN_SET((r < 0 ? -r : r), EAGAIN, EINTR);
}

/* From systemd's ERRNO_IS_DISCONNECT().
 *
 * Hint #1: ENETUNREACH happens if we try to connect to "non-existing" special IP addresses, such as ::5.
 *
 * Hint #2: The kernel sends e.g., EHOSTUNREACH or ENONET to userspace in some ICMP error cases.  See the
 *          icmp_err_convert[] in net/ipv4/icmp.c in the kernel sources.
 *
 * Hint #3: When asynchronous connect() on TCP fails because the host never acknowledges a single packet,
 *          kernel tells us that with ETIMEDOUT, see tcp(7). */
static inline gboolean
NM_ERRNO_IS_DISCONNECT(int r)
{
    return NM_IN_SET((r < 0 ? -r : r),
                     ECONNABORTED,
                     ECONNREFUSED,
                     ECONNRESET,
                     EHOSTDOWN,
                     EHOSTUNREACH,
                     ENETDOWN,
                     ENETRESET,
                     ENETUNREACH,
                     ENONET,
                     ENOPROTOOPT,
                     ENOTCONN,
                     EPIPE,
                     EPROTO,
                     ESHUTDOWN,
                     ETIMEDOUT);
}

/*****************************************************************************/

void nm_g_subprocess_terminate_in_background(GSubprocess *subprocess, int timeout_msec_before_kill);

char **nm_utils_find_mkstemp_files(const char *dirname, const char *filename);

static inline gboolean
nm_io_sockaddr_un_path_is_abstract(const char *path, const char **out_path)
{
    if (path && path[0] == '@') {
        NM_SET_OUT(out_path, &path[1]);
        return TRUE;
    }
    NM_SET_OUT(out_path, path);
    return FALSE;
}

struct sockaddr_un;

int nm_io_sockaddr_un_set(struct sockaddr_un *ret, NMOptionBool is_abstract, const char *path);

int nm_sd_notify(const char *state);

/*****************************************************************************/

int nm_parse_env_file_full(
    const char *contents,
    int (*push)(unsigned line, const char *key, const char *value, void *userdata),
    void *userdata);

int nm_parse_env_filev(const char *contents, va_list ap);
int nm_parse_env_file_sentinel(const char *contents, ...) G_GNUC_NULL_TERMINATED;
#define nm_parse_env_file(contents, ...) nm_parse_env_file_sentinel((contents), __VA_ARGS__, NULL)

#endif /* __NM_IO_UTILS_H__ */
