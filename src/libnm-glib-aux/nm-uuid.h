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

gboolean nm_uuid_parse_full(const char *str, NMUuid *out_uuid, gboolean *out_is_normalized);

static inline NMUuid *
nm_uuid_parse(const char *str, NMUuid *out_uuid)
{
    nm_assert(out_uuid);

    if (!nm_uuid_parse_full(str, out_uuid, NULL))
        return NULL;
    return out_uuid;
}

NMUuid *nm_uuid_generate_random(NMUuid *out_uuid);

gboolean nm_uuid_is_null(const NMUuid *uuid);

#endif /* __NM_UUID_H__ */
