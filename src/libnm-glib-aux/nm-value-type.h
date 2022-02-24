/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2019 Red Hat, Inc.
 */

#ifndef __NM_VALUE_TYPE_H__
#define __NM_VALUE_TYPE_H__

typedef enum _nm_packed {
    NM_VALUE_TYPE_NONE   = 0,
    NM_VALUE_TYPE_UNSPEC = 1,

    NM_VALUE_TYPE_BOOL,
    NM_VALUE_TYPE_INT32,
    NM_VALUE_TYPE_INT,
    NM_VALUE_TYPE_INT64,
    NM_VALUE_TYPE_UINT32,
    NM_VALUE_TYPE_UINT,
    NM_VALUE_TYPE_UINT64,

    /* Flags are for G_TYPE_FLAGS. That is, internally they are tracked
     * as a guint, they have a g_param_spec_flags() property and they are
     * serialized on D-Bus as "u". */
    NM_VALUE_TYPE_FLAGS,

    /* G_TYPE_ENUM */
    NM_VALUE_TYPE_ENUM,

    NM_VALUE_TYPE_STRING,
    NM_VALUE_TYPE_BYTES,
    NM_VALUE_TYPE_STRV,
} NMValueType;

/*****************************************************************************/

#ifdef NM_VALUE_TYPE_DEFINE_FUNCTIONS

typedef union {
    bool        v_bool;
    gint32      v_int32;
    gint64      v_int64;
    guint64     v_uint64;
    int         v_int;
    const char *v_string;

    /* for convenience, also let the union contain other pointer types. These are
     * for NM_VALUE_TYPE_UNSPEC. */
    gconstpointer   *v_ptr;
    const GPtrArray *v_ptrarray;

} NMValueTypUnion;

/* Set the NMValueTypUnion. You can also assign the member directly.
 * The only purpose of this is that it also returns a pointer to the
 * union. So, you can do
 *
 *   ptr = NM_VALUE_TYP_UNION_SET (&value_typ_union_storage, v_bool, TRUE);
 */
#define NM_VALUE_TYP_UNION_SET(_arg, _type, _val) \
    ({                                            \
        NMValueTypUnion *const _arg2 = (_arg);    \
                                                  \
        *_arg2 = (NMValueTypUnion){               \
            ._type = (_val),                      \
        };                                        \
        _arg2;                                    \
    })

typedef struct {
    bool            has;
    NMValueTypUnion val;
} NMValueTypUnioMaybe;

#define NM_VALUE_TYP_UNIO_MAYBE_SET(_arg, _type, _val) \
    ({                                                 \
        NMValueTypUnioMaybe *const _arg2 = (_arg);     \
                                                       \
        *_arg2 = (NMValueTypUnioMaybe){                \
            .has       = TRUE,                         \
            .val._type = (_val),                       \
        };                                             \
        _arg2;                                         \
    })

/*****************************************************************************/

static inline int
nm_value_type_cmp(NMValueType value_type, gconstpointer p_a, gconstpointer p_b)
{
    switch (value_type) {
    case NM_VALUE_TYPE_BOOL:
        NM_CMP_DIRECT(*((const bool *) p_a), *((const bool *) p_b));
        return 0;
    case NM_VALUE_TYPE_INT32:
        NM_CMP_DIRECT(*((const gint32 *) p_a), *((const gint32 *) p_b));
        return 0;
    case NM_VALUE_TYPE_INT:
    case NM_VALUE_TYPE_ENUM:
        NM_CMP_DIRECT(*((const int *) p_a), *((const int *) p_b));
        return 0;
    case NM_VALUE_TYPE_INT64:
        NM_CMP_DIRECT(*((const gint64 *) p_a), *((const gint64 *) p_b));
        return 0;
    case NM_VALUE_TYPE_UINT32:
        NM_CMP_DIRECT(*((const guint32 *) p_a), *((const guint32 *) p_b));
        return 0;
    case NM_VALUE_TYPE_UINT:
    case NM_VALUE_TYPE_FLAGS:
        NM_CMP_DIRECT(*((const guint *) p_a), *((const guint *) p_b));
        return 0;
    case NM_VALUE_TYPE_UINT64:
        NM_CMP_DIRECT(*((const guint64 *) p_a), *((const guint64 *) p_b));
        return 0;
    case NM_VALUE_TYPE_STRING:
        return nm_strcmp0(*((const char *const *) p_a), *((const char *const *) p_b));

    case NM_VALUE_TYPE_BYTES:
    case NM_VALUE_TYPE_STRV:
        /* These types have implementation define memory representations. */
        break;

    case NM_VALUE_TYPE_NONE:
    case NM_VALUE_TYPE_UNSPEC:
        break;
    }
    return nm_assert_unreachable_val(0);
}

static inline gboolean
nm_value_type_equal(NMValueType value_type, gconstpointer p_a, gconstpointer p_b)
{
    return nm_value_type_cmp(value_type, p_a, p_b) == 0;
}

static inline void
nm_value_type_copy(NMValueType value_type, gpointer dst, gconstpointer src)
{
    switch (value_type) {
    case NM_VALUE_TYPE_BOOL:
        (*((bool *) dst) = *((const bool *) src));
        return;
    case NM_VALUE_TYPE_INT32:
        (*((gint32 *) dst) = *((const gint32 *) src));
        return;
    case NM_VALUE_TYPE_INT:
    case NM_VALUE_TYPE_ENUM:
        (*((int *) dst) = *((const int *) src));
        return;
    case NM_VALUE_TYPE_INT64:
        (*((gint64 *) dst) = *((const gint64 *) src));
        return;
    case NM_VALUE_TYPE_UINT32:
        (*((guint32 *) dst) = *((const guint32 *) src));
        return;
    case NM_VALUE_TYPE_UINT:
    case NM_VALUE_TYPE_FLAGS:
        (*((guint *) dst) = *((const guint *) src));
        return;
    case NM_VALUE_TYPE_UINT64:
        (*((guint64 *) dst) = *((const guint64 *) src));
        return;
    case NM_VALUE_TYPE_STRING:
        /* self assignment safe! */
        if (*((char **) dst) != *((const char *const *) src)) {
            _nm_unused char *old = *((char **) dst);

            *((char **) dst) = g_strdup(*((const char *const *) src));
        }
        return;

    case NM_VALUE_TYPE_BYTES:
    case NM_VALUE_TYPE_STRV:
        /* These types have implementation define memory representations. */
        break;

    case NM_VALUE_TYPE_NONE:
    case NM_VALUE_TYPE_UNSPEC:
        break;
    }
    nm_assert_not_reached();
}

static inline void
nm_value_type_get_from_variant(NMValueType value_type,
                               gpointer    dst,
                               GVariant   *variant,
                               gboolean    clone)
{
    switch (value_type) {
    case NM_VALUE_TYPE_BOOL:
        *((bool *) dst) = g_variant_get_boolean(variant);
        return;
    case NM_VALUE_TYPE_INT32:
        *((gint32 *) dst) = g_variant_get_int32(variant);
        return;
    case NM_VALUE_TYPE_INT64:
        *((gint64 *) dst) = g_variant_get_int64(variant);
        return;
    case NM_VALUE_TYPE_UINT32:
        *((guint32 *) dst) = g_variant_get_uint32(variant);
        return;
    case NM_VALUE_TYPE_UINT64:
        *((guint64 *) dst) = g_variant_get_uint64(variant);
        return;
    case NM_VALUE_TYPE_STRING:
        if (clone) {
            _nm_unused gs_free char *old = *((char **) dst);

            *((char **) dst) = g_variant_dup_string(variant, NULL);
        } else {
            /* we don't clone the string, nor free the previous value. */
            *((const char **) dst) = g_variant_get_string(variant, NULL);
        }
        return;

    case NM_VALUE_TYPE_BYTES:
    case NM_VALUE_TYPE_STRV:
        /* These types have implementation define memory representations. */
        break;

    case NM_VALUE_TYPE_INT:
    case NM_VALUE_TYPE_UINT:
    case NM_VALUE_TYPE_ENUM:
    case NM_VALUE_TYPE_FLAGS:
        /* These types don't have a defined variant type, because it's not
         * clear how many bits we would need or how to handle the type. */
        break;

    case NM_VALUE_TYPE_NONE:
    case NM_VALUE_TYPE_UNSPEC:
        break;
    }
    nm_assert_not_reached();
}

static inline GVariant *
nm_value_type_to_variant(NMValueType value_type, gconstpointer src)
{
    const char *v_string;

    switch (value_type) {
    case NM_VALUE_TYPE_BOOL:
        return g_variant_new_boolean(*((const bool *) src));
    case NM_VALUE_TYPE_INT32:
        return g_variant_new_int32(*((const gint32 *) src));
    case NM_VALUE_TYPE_INT64:
        return g_variant_new_int64(*((const gint64 *) src));
    case NM_VALUE_TYPE_UINT32:
        return g_variant_new_uint32(*((const guint32 *) src));
    case NM_VALUE_TYPE_UINT64:
        return g_variant_new_uint64(*((const guint64 *) src));
    case NM_VALUE_TYPE_STRING:
        v_string = *((const char *const *) src);
        return v_string ? g_variant_new_string(v_string) : NULL;

    case NM_VALUE_TYPE_BYTES:
    case NM_VALUE_TYPE_STRV:
        /* These types have implementation define memory representations. */
        break;

    case NM_VALUE_TYPE_INT:
    case NM_VALUE_TYPE_UINT:
    case NM_VALUE_TYPE_ENUM:
    case NM_VALUE_TYPE_FLAGS:
        /* These types don't have a defined variant type, because it's not
         * clear how many bits we would need or how to handle the type. */
        break;

    case NM_VALUE_TYPE_NONE:
    case NM_VALUE_TYPE_UNSPEC:
        break;
    }
    return nm_assert_unreachable_val(NULL);
}

static inline const GVariantType *
nm_value_type_get_variant_type(NMValueType value_type)
{
    switch (value_type) {
    case NM_VALUE_TYPE_BOOL:
        return G_VARIANT_TYPE_BOOLEAN;
    case NM_VALUE_TYPE_INT32:
        return G_VARIANT_TYPE_INT32;
    case NM_VALUE_TYPE_INT64:
        return G_VARIANT_TYPE_INT64;
    case NM_VALUE_TYPE_UINT32:
        return G_VARIANT_TYPE_UINT32;
    case NM_VALUE_TYPE_UINT64:
        return G_VARIANT_TYPE_UINT64;
    case NM_VALUE_TYPE_STRING:
        return G_VARIANT_TYPE_STRING;
    case NM_VALUE_TYPE_BYTES:
        return G_VARIANT_TYPE_BYTESTRING;
    case NM_VALUE_TYPE_STRV:
        return G_VARIANT_TYPE_STRING_ARRAY;

    case NM_VALUE_TYPE_INT:
    case NM_VALUE_TYPE_UINT:
    case NM_VALUE_TYPE_ENUM:
    case NM_VALUE_TYPE_FLAGS:
        /* These types don't have a defined variant type, because it's not
         * clear how many bits we would need or how to handle the type. */

        /* fall-through */
    case NM_VALUE_TYPE_NONE:
    case NM_VALUE_TYPE_UNSPEC:
        break;
    }
    nm_assert_not_reached();
    return NULL;
}

/*****************************************************************************/

#endif /* NM_VALUE_TYPE_DEFINE_FUNCTIONS */

#endif /* __NM_VALUE_TYPE_H__ */
