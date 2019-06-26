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

int nm_utils_fd_get_contents (int fd,
                              gboolean close_fd,
                              gsize max_length,
                              NMUtilsFileGetContentsFlags flags,
                              char **contents,
                              gsize *length,
                              GError **error);

int nm_utils_file_get_contents (int dirfd,
                                const char *filename,
                                gsize max_length,
                                NMUtilsFileGetContentsFlags flags,
                                char **contents,
                                gsize *length,
                                GError **error);

gboolean nm_utils_file_set_contents (const char *filename,
                                     const char *contents,
                                     gssize length,
                                     mode_t mode,
                                     GError **error);

struct stat;

int nm_utils_file_stat (const char *filename, struct stat *out_st);

#endif /* __NM_IO_UTILS_H__ */
