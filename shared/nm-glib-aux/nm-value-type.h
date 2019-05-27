/*
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
 * Copyright 2019 Red Hat, Inc.
 */

#ifndef __NM_VALUE_TYPE_H__
#define __NM_VALUE_TYPE_H__

typedef enum {
	NM_VALUE_TYPE_UNSPEC = 1,
	NM_VALUE_TYPE_BOOL   = 2,
	NM_VALUE_TYPE_INT32  = 3,
	NM_VALUE_TYPE_INT    = 4,
	NM_VALUE_TYPE_STRING = 5,
} NMValueType;

/*****************************************************************************/

#ifdef NM_VALUE_TYPE_DEFINE_FUNCTIONS

typedef union {
	bool             v_bool;
	gint32           v_int32;
	int              v_int;
	const char      *v_string;

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
	({ \
		NMValueTypUnion *const _arg2 = (_arg); \
		\
		*_arg2 = (NMValueTypUnion) { \
			._type = (_val), \
		}; \
		_arg2; \
	})

typedef struct {
	bool has;
	NMValueTypUnion val;
} NMValueTypUnioMaybe;

#define NM_VALUE_TYP_UNIO_MAYBE_SET(_arg, _type, _val) \
	({ \
		NMValueTypUnioMaybe *const _arg2 = (_arg); \
		\
		*_arg2 = (NMValueTypUnioMaybe) { \
			.has       = TRUE, \
			.val._type = (_val), \
		}; \
		_arg2; \
	})

/*****************************************************************************/

static inline int
nm_value_type_cmp (NMValueType value_type,
                   gconstpointer p_a,
                   gconstpointer p_b)
{
	switch (value_type) {
	case NM_VALUE_TYPE_BOOL:   NM_CMP_DIRECT (*((const bool   *) p_a), *((const bool   *) p_b)); return 0;
	case NM_VALUE_TYPE_INT32:  NM_CMP_DIRECT (*((const gint32 *) p_a), *((const gint32 *) p_b)); return 0;
	case NM_VALUE_TYPE_INT:    NM_CMP_DIRECT (*((const int    *) p_a), *((const int    *) p_b)); return 0;
	case NM_VALUE_TYPE_STRING: return nm_strcmp0 (*((const char *const*) p_a), *((const char *const*) p_b));
	case NM_VALUE_TYPE_UNSPEC:
		break;
	}
	nm_assert_not_reached ();
	return 0;
}

static inline gboolean
nm_value_type_equal (NMValueType value_type,
                     gconstpointer p_a,
                     gconstpointer p_b)
{
	return nm_value_type_cmp (value_type, p_a, p_b) == 0;
}

static inline void
nm_value_type_copy (NMValueType value_type,
                    gpointer dst,
                    gconstpointer src)
{
	switch (value_type) {
	case NM_VALUE_TYPE_BOOL:   (*((bool   *) dst) = *((const bool   *) src)); return;
	case NM_VALUE_TYPE_INT32:  (*((gint32 *) dst) = *((const gint32 *) src)); return;
	case NM_VALUE_TYPE_INT:    (*((int    *) dst) = *((const int    *) src)); return;
	case NM_VALUE_TYPE_STRING:
		/* self assignment safe! */
		if (*((char **) dst) != *((const char *const*) src)) {
			g_free (*((char **) dst));
			*((char **) dst) = g_strdup (*((const char *const*) src));
		}
		return;
	case NM_VALUE_TYPE_UNSPEC:
		break;
	}
	nm_assert_not_reached ();
}

static inline void
nm_value_type_get_from_variant (NMValueType value_type,
                                gpointer dst,
                                GVariant *variant,
                                gboolean clone)
{
	switch (value_type) {
	case NM_VALUE_TYPE_BOOL:   *((bool   *) dst) = g_variant_get_boolean (variant); return;
	case NM_VALUE_TYPE_INT32:  *((gint32 *) dst) = g_variant_get_int32 (variant);   return;
	case NM_VALUE_TYPE_STRING:
		if (clone) {
			g_free (*((char **) dst));
			*((char **) dst) = g_variant_dup_string (variant, NULL);
		} else {
			/* we don't clone the string, nor free the previous value. */
			*((const char **) dst) = g_variant_get_string (variant, NULL);
		}
		return;

	case NM_VALUE_TYPE_INT:
		/* "int" also does not have a define variant type, because it's not
		 * clear how many bits we would need. */

		/* fall-through */
	case NM_VALUE_TYPE_UNSPEC:
		break;
	}
	nm_assert_not_reached ();
}

static inline GVariant *
nm_value_type_to_variant (NMValueType value_type,
                          gconstpointer src)
{
	const char *v_string;

	switch (value_type) {
	case NM_VALUE_TYPE_BOOL:   return g_variant_new_boolean (*((const bool   *) src));
	case NM_VALUE_TYPE_INT32:  return g_variant_new_int32   (*((const gint32 *) src));;
	case NM_VALUE_TYPE_STRING:
		v_string = *((const char *const*) src);
		return v_string ? g_variant_new_string (v_string) : NULL;

	case NM_VALUE_TYPE_INT:
		/* "int" also does not have a define variant type, because it's not
		 * clear how many bits we would need. */

		/* fall-through */
	case NM_VALUE_TYPE_UNSPEC:
		break;
	}
	nm_assert_not_reached ();
	return NULL;
}

static inline const GVariantType *
nm_value_type_get_variant_type (NMValueType value_type)
{
	switch (value_type) {
	case NM_VALUE_TYPE_BOOL:   return G_VARIANT_TYPE_BOOLEAN;
	case NM_VALUE_TYPE_INT32:  return G_VARIANT_TYPE_INT32;
	case NM_VALUE_TYPE_STRING: return G_VARIANT_TYPE_STRING;

	case NM_VALUE_TYPE_INT:
		/* "int" also does not have a define variant type, because it's not
		 * clear how many bits we would need. */

		/* fall-through */
	case NM_VALUE_TYPE_UNSPEC:
		break;
	}
	nm_assert_not_reached ();
	return NULL;
}

/*****************************************************************************/

#endif /* NM_VALUE_TYPE_DEFINE_FUNCTIONS */

#endif  /* __NM_VALUE_TYPE_H__ */
