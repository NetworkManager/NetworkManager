// SPDX-License-Identifier: LGPL-2.1+
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
 *   data is left in memory. Essentially, it means to call explicity_bzero()
 *   to not leave key material on the heap (when reading secrets).
 */
typedef enum {
	NM_UTILS_FILE_GET_CONTENTS_FLAG_NONE   = 0,
	NM_UTILS_FILE_GET_CONTENTS_FLAG_SECRET = (1 << 0),
} NMUtilsFileGetContentsFlags;

gboolean nm_utils_fd_get_contents (int fd,
                                   gboolean close_fd,
                                   gsize max_length,
                                   NMUtilsFileGetContentsFlags flags,
                                   char **contents,
                                   gsize *length,
                                   int *out_errsv,
                                   GError **error);

gboolean nm_utils_file_get_contents (int dirfd,
                                     const char *filename,
                                     gsize max_length,
                                     NMUtilsFileGetContentsFlags flags,
                                     char **contents,
                                     gsize *length,
                                     int *out_errsv,
                                     GError **error);

gboolean nm_utils_file_set_contents (const char *filename,
                                     const char *contents,
                                     gssize length,
                                     mode_t mode,
                                     int *out_errsv,
                                     GError **error);

struct stat;

int nm_utils_file_stat (const char *filename, struct stat *out_st);

#endif /* __NM_IO_UTILS_H__ */
