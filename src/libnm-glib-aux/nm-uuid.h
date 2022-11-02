/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NM_UUID_H__
#define __NM_UUID_H__

typedef struct _NMUuid {
    guint8 uuid[16];
} NMUuid;

#define NM_UUID_INIT_ZERO() ((NMUuid){.uuid = {0}})

/* Beware, the 16 macro arguments are two hex-digits, not plain numbers. The macro
 * will automatically add the "0x". In particular, "09" is not an octal number, it's
 * 0x09. This oddity is so that the arguments look very much like the UUID in string form. */
#define NM_UUID_INIT(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15) \
    ((NMUuid){                                                                             \
        .uuid = {(0x##a0),                                                                 \
                 (0x##a1),                                                                 \
                 (0x##a2),                                                                 \
                 (0x##a3),                                                                 \
                 (0x##a4),                                                                 \
                 (0x##a5),                                                                 \
                 (0x##a6),                                                                 \
                 (0x##a7),                                                                 \
                 (0x##a8),                                                                 \
                 (0x##a9),                                                                 \
                 (0x##a10),                                                                \
                 (0x##a11),                                                                \
                 (0x##a12),                                                                \
                 (0x##a13),                                                                \
                 (0x##a14),                                                                \
                 (0x##a15)},                                                               \
    })

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
                             gboolean   *out_normalized,
                             char       *out_normalized_str /* [static 37] */);

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

extern const NMUuid nm_uuid_ns_zero;
extern const NMUuid nm_uuid_ns_1;

#define NM_UUID_NS_ZERO "00000000-0000-0000-0000-000000000000"
#define NM_UUID_NS_1    "b425e9fb-7598-44b4-9e3b-5a2e3aaa4905"

/*****************************************************************************/

typedef enum {
    NM_UUID_TYPE_LEGACY   = 0,
    NM_UUID_TYPE_VERSION3 = 3,
    NM_UUID_TYPE_VERSION5 = 5,
} NMUuidType;

NMUuid *nm_uuid_generate_from_string(NMUuid       *uuid,
                                     const char   *s,
                                     gssize        slen,
                                     NMUuidType    uuid_type,
                                     const NMUuid *type_args);

char *nm_uuid_generate_from_string_str(const char   *s,
                                       gssize        slen,
                                       NMUuidType    uuid_type,
                                       const NMUuid *type_args);

char *nm_uuid_generate_from_strings_strv(NMUuidType         uuid_type,
                                         const NMUuid      *type_args,
                                         const char *const *strv,
                                         gssize             len);

#define nm_uuid_generate_from_strings(uuid_type, type_args, ...)  \
    nm_uuid_generate_from_strings_strv((uuid_type),               \
                                       (type_args),               \
                                       NM_MAKE_STRV(__VA_ARGS__), \
                                       NM_NARG(__VA_ARGS__))

/* Legacy function. Don't use for new code. */
#define nm_uuid_generate_from_strings_old(...)                    \
    nm_uuid_generate_from_strings_strv(NM_UUID_TYPE_VERSION3,     \
                                       &nm_uuid_ns_1,             \
                                       NM_MAKE_STRV(__VA_ARGS__), \
                                       -1)

/*****************************************************************************/

#endif /* __NM_UUID_H__ */
