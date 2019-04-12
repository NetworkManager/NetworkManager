/* This library is free software; you can redistribute it and/or
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
 * Copyright (C) 2018 Red Hat, Inc.
 */

#ifndef __NM_SD_UTILS_SHARED_H__
#define __NM_SD_UTILS_SHARED_H__

/*****************************************************************************/

gboolean nm_sd_utils_path_equal (const char *a, const char *b);

char *nm_sd_utils_path_simplify (char *path, gboolean kill_dots);

const char *nm_sd_utils_path_startswith (const char *path, const char *prefix);

/*****************************************************************************/

int nm_sd_utils_unbase64char (char ch, gboolean accept_padding_equal);

int nm_sd_utils_unbase64mem (const char *p,
                             size_t l,
                             gboolean secure,
                             guint8 **mem,
                             size_t *len);

/*****************************************************************************/

#endif /* __NM_SD_UTILS_SHARED_H__ */
