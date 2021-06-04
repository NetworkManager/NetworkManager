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

/*****************************************************************************/

static inline gboolean
nm_uuid_is_valid(const char *str)
{
    return str && nm_uuid_parse_full(str, NULL, NULL);
}

gboolean nm_uuid_is_normalized_full(const char *str);

static inline gboolean
nm_uuid_is_normalized(const char *str)
{
    gboolean is_normalized;

    return str && nm_uuid_parse_full(str, NULL, &is_normalized) && is_normalized;
}

/*****************************************************************************/

gboolean nm_uuid_is_valid_nmlegacy(const char *str);

gboolean nm_uuid_is_valid_nm(const char *str,
                             gboolean *  out_normalized,
                             char *      out_normalized_str /* [static 37] */);

/*****************************************************************************/

char *nm_uuid_generate_random_str(char buf[static 37]);

#define nm_uuid_generate_random_str_arr(buf)                                    \
    ({                                                                          \
        G_STATIC_ASSERT(sizeof(buf) == G_N_ELEMENTS(buf) && sizeof(buf) >= 37); \
        nm_uuid_generate_random_str(buf);                                       \
    })

#define nm_uuid_generate_random_str_a() (nm_uuid_generate_random_str(g_alloca(37)))

#define nm_uuid_generate_random_str_malloc() (nm_uuid_generate_random_str(g_new(char, 37)))

/*****************************************************************************/

typedef enum {
    NM_UUID_TYPE_LEGACY   = 0,
    NM_UUID_TYPE_VERSION3 = 3,
    NM_UUID_TYPE_VERSION5 = 5,
} NMUuidType;

NMUuid *nm_uuid_generate_from_string(NMUuid *    uuid,
                                     const char *s,
                                     gssize      slen,
                                     NMUuidType  uuid_type,
                                     gpointer    type_args);

char *nm_uuid_generate_from_string_str(const char *s,
                                       gssize      slen,
                                       NMUuidType  uuid_type,
                                       gpointer    type_args);

/* arbitrarily chosen namespace UUID for nm_uuid_generate_from_strings() */
#define NM_UUID_NS1 "b425e9fb-7598-44b4-9e3b-5a2e3aaa4905"

char *nm_uuid_generate_from_strings(const char *string1, ...) G_GNUC_NULL_TERMINATED;

/*****************************************************************************/

#endif /* __NM_UUID_H__ */
