/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2018 Red Hat, Inc.
 */

#ifndef __NM_IO_UTILS_H__
#define __NM_IO_UTILS_H__

#include "nm-macros-internal.h"

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

struct stat;

int nm_utils_file_stat(const char *filename, struct stat *out_st);

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

#endif /* __NM_IO_UTILS_H__ */
