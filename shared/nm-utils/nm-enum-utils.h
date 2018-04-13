/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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
 * (C) Copyright 2017 Red Hat, Inc.
 */

#ifndef __NM_ENUM_UTILS_H__
#define __NM_ENUM_UTILS_H__

/*****************************************************************************/

typedef struct _NMUtilsEnumValueInfo {
	/* currently, this is only used for _nm_utils_enum_from_str_full() to
	 * declare additional aliases for values. */
	const char *nick;
	int value;
} NMUtilsEnumValueInfo;

char *_nm_utils_enum_to_str_full (GType type,
                                  int value,
                                  const char *sep,
                                  const NMUtilsEnumValueInfo *value_infos);
gboolean _nm_utils_enum_from_str_full (GType type,
                                       const char *str,
                                       int *out_value,
                                       char **err_token,
                                       const NMUtilsEnumValueInfo *value_infos);

const char **_nm_utils_enum_get_values (GType type, gint from, gint to);

/*****************************************************************************/

#endif /* __NM_ENUM_UTILS_H__ */
