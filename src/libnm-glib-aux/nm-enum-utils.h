/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#ifndef __NM_ENUM_UTILS_H__
#define __NM_ENUM_UTILS_H__

/*****************************************************************************/

typedef struct _NMUtilsEnumValueInfo {
    /* currently, this is only used for _nm_utils_enum_from_str_full() to
     * declare additional aliases for values. */
    const char *nick;
    int         value;
} NMUtilsEnumValueInfo;

typedef struct _NMUtilsEnumValueInfoFull {
    const char  *nick;
    const char **aliases;
    const char  *value_str;
    int          value;
} NMUtilsEnumValueInfoFull;

char    *_nm_utils_enum_to_str_full(GType                       type,
                                    int                         value,
                                    const char                 *sep,
                                    const NMUtilsEnumValueInfo *value_infos);
gboolean _nm_utils_enum_from_str_full(GType                       type,
                                      const char                 *str,
                                      int                        *out_value,
                                      char                      **err_token,
                                      const NMUtilsEnumValueInfo *value_infos);

const char **_nm_utils_enum_get_values(GType type, int from, int to);

GArray *_nm_utils_enum_get_values_full(GType                       type,
                                       int                         from,
                                       int                         to,
                                       const NMUtilsEnumValueInfo *value_infos);

/*****************************************************************************/

#endif /* __NM_ENUM_UTILS_H__ */
