/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2018 Red Hat, Inc.
 */

#ifndef __NM_SD_UTILS_SHARED_H__
#define __NM_SD_UTILS_SHARED_H__

/*****************************************************************************/

gboolean nm_sd_utils_path_equal(const char *a, const char *b);

char *nm_sd_utils_path_simplify(char *path, gboolean kill_dots);

const char *nm_sd_utils_path_startswith(const char *path, const char *prefix);

/*****************************************************************************/

int nm_sd_utils_unbase64char(char ch, gboolean accept_padding_equal);

int nm_sd_utils_unbase64mem(const char *p, size_t l, gboolean secure, guint8 **mem, size_t *len);

/*****************************************************************************/

int
nm_sd_dns_name_to_wire_format(const char *domain, guint8 *buffer, size_t len, gboolean canonical);

int      nm_sd_dns_name_is_valid(const char *s);
gboolean nm_sd_hostname_is_valid(const char *s, bool allow_trailing_dot);

char *nm_sd_dns_name_normalize(const char *s);

/*****************************************************************************/

gboolean nm_sd_http_url_is_valid_https(const char *url);

/*****************************************************************************/

int nmtst_systemd_extract_first_word_all(const char *str, char ***out_strv);

#endif /* __NM_SD_UTILS_SHARED_H__ */
