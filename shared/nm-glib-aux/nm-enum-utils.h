// SPDX-License-Identifier: LGPL-2.1+
/*
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

const char **_nm_utils_enum_get_values (GType type, int from, int to);

/*****************************************************************************/

#endif /* __NM_ENUM_UTILS_H__ */
