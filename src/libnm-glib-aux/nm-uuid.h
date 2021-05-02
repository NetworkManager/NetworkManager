/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NM_UUID_H__
#define __NM_UUID_H__

typedef struct _NMUuid {
    guint8 uuid[16];
} NMUuid;

char *nm_uuid_unparse_case(const NMUuid *uuid, char out_str[static 37], gboolean upper_case);

static inline char *
nm_uuid_unparse(const NMUuid *uuid, char out_str[static 37])
{
    return nm_uuid_unparse_case(uuid, out_str, FALSE);
}

#endif /* __NM_UUID_H__ */
