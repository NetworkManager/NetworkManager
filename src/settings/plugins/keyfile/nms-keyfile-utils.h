/* NetworkManager system settings service
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2010 - 2018 Red Hat, Inc.
 */

#ifndef __NMS_KEYFILE_UTILS_H__
#define __NMS_KEYFILE_UTILS_H__

#include "NetworkManagerUtils.h"

typedef enum {
	NMS_KEYFILE_FILETYPE_KEYFILE,
	NMS_KEYFILE_FILETYPE_NMMETA,
} NMSKeyfileFiletype;

typedef enum {
	NMS_KEYFILE_STORAGE_TYPE_RUN       = 1, /* read-write, runtime only, e.g. /run */
	NMS_KEYFILE_STORAGE_TYPE_ETC       = 2, /* read-write, persistent,   e.g. /etc     */
	NMS_KEYFILE_STORAGE_TYPE_LIB_BASE  = 3, /* read-only,                e.g. /usr/lib */

	_NMS_KEYFILE_STORAGE_TYPE_LIB_LAST = 1000,
} NMSKeyfileStorageType;

static inline NMSKeyfileStorageType
NMS_KEYFILE_STORAGE_TYPE_LIB (guint run_idx)
{
	nm_assert (run_idx <= (_NMS_KEYFILE_STORAGE_TYPE_LIB_LAST - NMS_KEYFILE_STORAGE_TYPE_LIB_BASE));
	return NMS_KEYFILE_STORAGE_TYPE_LIB_BASE + run_idx;
}

/*****************************************************************************/

const char *nms_keyfile_nmmeta_check_filename (const char *filename,
                                               guint *out_uuid_len);

char *nms_keyfile_nmmeta_filename (const char *dirname,
                                   const char *uuid,
                                   gboolean temporary);

gboolean nms_keyfile_nmmeta_read (const char *dirname,
                                  const char *filename,
                                  char **out_full_filename,
                                  char **out_uuid,
                                  char **out_loaded_path,
                                  char **out_shadowed_storage,
                                  struct stat *out_st);

gboolean nms_keyfile_nmmeta_read_from_file (const char *full_filename,
                                            char **out_dirname,
                                            char **out_filename,
                                            char **out_uuid,
                                            char **out_loaded_path,
                                            char **out_shadowed_storage);

gboolean nms_keyfile_nmmeta_write (const char *dirname,
                                   const char *uuid,
                                   const char *loaded_path,
                                   gboolean loaded_path_allow_relative,
                                   const char *shadowed_storage,
                                   char **out_full_filename);

/*****************************************************************************/

struct stat;
gboolean nms_keyfile_utils_check_file_permissions_stat (NMSKeyfileFiletype filetype,
                                                        const struct stat *st,
                                                        GError **error);

gboolean nms_keyfile_utils_check_file_permissions (NMSKeyfileFiletype filetype,
                                                   const char *filename,
                                                   struct stat *out_st,
                                                   GError **error);

#endif /* __NMS_KEYFILE_UTILS_H__ */
