// SPDX-License-Identifier: LGPL-2.1+
/*
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

int nm_sd_dns_name_to_wire_format (const char *domain,
                                   guint8 *buffer,
                                   size_t len,
                                   gboolean canonical);

#endif /* __NM_SD_UTILS_SHARED_H__ */
