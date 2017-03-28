/* nmcli - command-line tool to control NetworkManager
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
 * Copyright 2010 - 2017 Red Hat, Inc.
 */

#ifndef __NM_CLIENT_UTILS_H__
#define __NM_CLIENT_UTILS_H__

#include "nm-meta-setting.h"


typedef enum {
	NMC_TRI_STATE_NO,
	NMC_TRI_STATE_YES,
	NMC_TRI_STATE_UNKNOWN,
} NMCTriStateValue;

const char *nmc_string_is_valid (const char *input, const char **allowed, GError **error);

char **nmc_strsplit_set (const char *str, const char *delimiter, int max_tokens);

gboolean nmc_string_to_int_base (const char *str,
                                 int base,
                                 gboolean range_check,
                                 long int min,
                                 long int max,
                                 long int *value);
gboolean nmc_string_to_uint_base (const char *str,
                                  int base,
                                  gboolean range_check,
                                  unsigned long int min,
                                  unsigned long int max,
                                  unsigned long int *value);
gboolean nmc_string_to_int (const char *str,
                            gboolean range_check,
                            long int min,
                            long int max,
                            long int *value);
gboolean nmc_string_to_uint (const char *str,
                             gboolean range_check,
                             unsigned long int min,
                             unsigned long int max,
                             unsigned long int *value);
gboolean nmc_string_to_bool (const char *str, gboolean *val_bool, GError **error);
gboolean nmc_string_to_tristate (const char *str, NMCTriStateValue *val, GError **error);

gboolean matches (const char *cmd, const char *pattern);

#endif /* __NM_CLIENT_UTILS_H__ */
