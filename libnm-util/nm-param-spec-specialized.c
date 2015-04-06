/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

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
 * Copyright 2007 - 2011 Red Hat, Inc.
 * Copyright 2007 - 2008 Novell, Inc.
 */

#include "config.h"

#include "nm-glib.h"
#include "nm-param-spec-specialized.h"

struct _NMParamSpecSpecialized {
	GParamSpec parent;
};

#include <string.h>
#include <math.h>
#include <netinet/in.h>
#include <dbus/dbus-glib.h>

#include "nm-dbus-glib-types.h"

/***********************************************************/
/* _gvalues_compare */

static gint _gvalues_compare (const GValue *value1, const GValue *value2);

static gboolean
type_is_fixed_size (GType type, gsize *tsize)
{
	switch (type) {
	case G_TYPE_CHAR:
		if (tsize) *tsize = sizeof (char);
		return TRUE;
	case G_TYPE_UCHAR:
		if (tsize) *tsize = sizeof (guchar);
		return TRUE;
	case G_TYPE_BOOLEAN:
		if (tsize) *tsize = sizeof (gboolean);
		return TRUE;
	case G_TYPE_LONG:
		if (tsize) *tsize = sizeof (glong);
		return TRUE;
	case G_TYPE_ULONG:
		if (tsize) *tsize = sizeof (gulong);
		return TRUE;
	case G_TYPE_INT:
		if (tsize) *tsize = sizeof (gint);
		return TRUE;
	case G_TYPE_UINT:
		if (tsize) *tsize = sizeof (guint);
		return TRUE;
	case G_TYPE_INT64:
		if (tsize) *tsize = sizeof (gint64);
		return TRUE;
	case G_TYPE_UINT64:
		if (tsize) *tsize = sizeof (guint64);
		return TRUE;
	case G_TYPE_FLOAT:
		if (tsize) *tsize = sizeof (gfloat);
		return TRUE;
	case G_TYPE_DOUBLE:
		if (tsize) *tsize = sizeof (gdouble);
		return TRUE;
	default:
		return FALSE;
	}
}

#define FLOAT_FACTOR 0.00000001

static gint
_gvalues_compare_fixed (const GValue *value1, const GValue *value2)
{
	int ret = 0;

	switch (G_VALUE_TYPE (value1)) {
	case G_TYPE_CHAR: {
		gchar val1 = g_value_get_schar (value1);
		gchar val2 = g_value_get_schar (value2);
		if (val1 != val2)
			ret = val1 < val2 ? -1 : val1 > val2;
		break;
	}
	case G_TYPE_UCHAR: {
		guchar val1 = g_value_get_uchar (value1);
		guchar val2 = g_value_get_uchar (value2);
		if (val1 != val2)
			ret = val1 < val2 ? -1 : val1 > val2;
		break;
	}
	case G_TYPE_BOOLEAN: {
		gboolean val1 = g_value_get_boolean (value1);
		gboolean val2 = g_value_get_boolean (value2);
		if (val1 != val2)
			ret = val1 < val2 ? -1 : val1 > val2;
		break;
	}
	case G_TYPE_LONG: {
		glong val1 = g_value_get_long (value1);
		glong val2 = g_value_get_long (value2);
		if (val1 != val2)
			ret = val1 < val2 ? -1 : val1 > val2;
		break;
	}
	case G_TYPE_ULONG: {
		gulong val1 = g_value_get_ulong (value1);
		gulong val2 = g_value_get_ulong (value2);
		if (val1 != val2)
			ret = val1 < val2 ? -1 : val1 > val2;
		break;
	}
	case G_TYPE_INT: {
		gint val1 = g_value_get_int (value1);
		gint val2 = g_value_get_int (value2);
		if (val1 != val2)
			ret = val1 < val2 ? -1 : val1 > val2;
		break;
	}
	case G_TYPE_UINT: {
		guint val1 = g_value_get_uint (value1);
		guint val2 = g_value_get_uint (value2);
		if (val1 != val2)
			ret = val1 < val2 ? -1 : val1 > val2;
		break;
	}
	case G_TYPE_INT64: {
		gint64 val1 = g_value_get_int64 (value1);
		gint64 val2 = g_value_get_int64 (value2);
		if (val1 != val2)
			ret = val1 < val2 ? -1 : val1 > val2;
		break;
	}
	case G_TYPE_UINT64: {
		guint64 val1 = g_value_get_uint64 (value1);
		guint64 val2 = g_value_get_uint64 (value2);
		if (val1 != val2)
			ret = val1 < val2 ? -1 : val1 > val2;
		break;
	}
	case G_TYPE_FLOAT: {
		gfloat val1 = g_value_get_float (value1);
		gfloat val2 = g_value_get_float (value2);
		/* Can't use == or != here due to inexactness of FP */
		if (fabsf (val1 - val2) > FLOAT_FACTOR)
			ret = val1 < val2 ? -1 : val1 > val2;
		break;
	}
	case G_TYPE_DOUBLE: {
		gdouble val1 = g_value_get_double (value1);
		gdouble val2 = g_value_get_double (value2);
		if (fabs (val1 - val2) > FLOAT_FACTOR)
			ret = val1 < val2 ? -1 : val1 > val2;
		break;
	}
	default:
		g_warning ("Unhandled fixed size type '%s'", G_VALUE_TYPE_NAME (value1));
	}

	return ret;
}

static gint
_gvalues_compare_string (const GValue *value1, const GValue *value2)
{
	const char *str1 = g_value_get_string (value1);
	const char *str2 = g_value_get_string (value2);

	if (str1 == str2)
		return 0;

	if (!str1)
		return 1;
	if (!str2)
		return -1;

	return strcmp (str1, str2);
}

static gint
_gvalues_compare_strv (const GValue *value1, const GValue *value2)
{
	char **strv1;
	char **strv2;
	gint ret;
	guint i = 0;

	strv1 = (char **) g_value_get_boxed (value1);
	strv2 = (char **) g_value_get_boxed (value2);

	while (strv1[i] && strv2[i]) {
		ret = strcmp (strv1[i], strv2[i]);
		if (ret)
			return ret;
		i++;
	}

	if (strv1[i] == NULL && strv2[i] == NULL)
		return 0;

	if (strv1[i])
		return 1;

	return -1;
}

static void
_gvalue_destroy (gpointer data)
{
	GValue *value = (GValue *) data;

	g_value_unset (value);
	g_slice_free (GValue, value);
}

static GValue *
_gvalue_dup (const GValue *value)
{
	GValue *dup;

	dup = g_slice_new0 (GValue);
	g_value_init (dup, G_VALUE_TYPE (value));
	g_value_copy (value, dup);

	return dup;
}

static void
iterate_collection (const GValue *value, gpointer user_data)
{
	GSList **list = (GSList **) user_data;

	*list = g_slist_prepend (*list, _gvalue_dup (value));
}

static gint
_gvalues_compare_collection (const GValue *value1, const GValue *value2)
{
	gint ret;
	guint len1;
	guint len2;
	GType value_type = dbus_g_type_get_collection_specialization (G_VALUE_TYPE (value1));
	gsize element_size = 0;

	if (type_is_fixed_size (value_type, &element_size)) {
		gpointer data1 = NULL;
		gpointer data2 = NULL;

		dbus_g_type_collection_get_fixed ((GValue *) value1, &data1, &len1);
		dbus_g_type_collection_get_fixed ((GValue *) value2, &data2, &len2);

		if (len1 != len2)
			ret = len1 < len2 ? -1 : len1 > len2;
		else
			ret = memcmp (data1, data2, len1 * element_size);
	} else {
		GSList *list1 = NULL;
		GSList *list2 = NULL;

		dbus_g_type_collection_value_iterate (value1, iterate_collection, &list1);
		len1 = g_slist_length (list1);
		dbus_g_type_collection_value_iterate (value2, iterate_collection, &list2);
		len2 = g_slist_length (list2);

		if (len1 != len2)
			ret = len1 < len2 ? -1 : len1 > len2;
		else {
			GSList *iter1;
			GSList *iter2;

			for (iter1 = list1, iter2 = list2, ret = 0;
			     ret == 0 && iter1 && iter2;
			     iter1 = iter1->next, iter2 = iter2->next)
				ret = _gvalues_compare ((GValue *) iter1->data, (GValue *) iter2->data);
		}

		g_slist_free_full (list1, _gvalue_destroy);
		g_slist_free_full (list2, _gvalue_destroy);
	}

	return ret;
}

static void
iterate_map (const GValue *key_val,
             const GValue *value_val,
             gpointer user_data)
{
	GHashTable **hash = (GHashTable **) user_data;

	g_hash_table_insert (*hash, g_value_dup_string (key_val), _gvalue_dup (value_val));
}

typedef struct {
	GHashTable *hash2;
	gint ret;
} CompareMapInfo;

static void
compare_one_map_item (gpointer key, gpointer val, gpointer user_data)
{
	CompareMapInfo *info = (CompareMapInfo *) user_data;
	GValue *value2;

	if (info->ret)
		return;

	value2 = (GValue *) g_hash_table_lookup (info->hash2, key);
	if (value2)
		info->ret = _gvalues_compare ((GValue *) val, value2);
	else
		info->ret = 1;
}

static gint
_gvalues_compare_map (const GValue *value1, const GValue *value2)
{
	GHashTable *hash1 = NULL;
	GHashTable *hash2 = NULL;
	guint len1;
	guint len2;
	gint ret = 0;

	if (dbus_g_type_get_map_key_specialization (G_VALUE_TYPE (value1)) != G_TYPE_STRING) {
		g_warning ("Can not compare maps with '%s' for keys",
		           g_type_name (dbus_g_type_get_map_key_specialization (G_VALUE_TYPE (value1))));
		return 0;
	}

	hash1 = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, _gvalue_destroy);
	dbus_g_type_map_value_iterate (value1, iterate_map, &hash1);
	len1 = g_hash_table_size (hash1);

	hash2 = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, _gvalue_destroy);
	dbus_g_type_map_value_iterate (value2, iterate_map, &hash2);
	len2 = g_hash_table_size (hash2);

	if (len1 != len2)
		ret = len1 < len2 ? -1 : len1 > len2;
	else {
		CompareMapInfo info;

		info.ret = 0;
		info.hash2 = hash2;
		g_hash_table_foreach (hash1, compare_one_map_item, &info);
		ret = info.ret;
	}

	g_hash_table_destroy (hash1);
	g_hash_table_destroy (hash2);

	return ret;
}

static gint
_gvalue_ip6_address_compare (const GValue *value1, const GValue *value2)
{
	GValueArray *values1, *values2;
	GValue *tmp_val;
	GByteArray *addr1, *addr2;
	guint32 prefix1, prefix2;
	GByteArray *gw1, *gw2;
	gint ret = 0;
	int i;

	/* IP6 addresses are GValueArrays (see nm-dbus-glib-types.h) */
	values1 = g_value_get_boxed (value1);
	values2 = g_value_get_boxed (value2);

	/* Since they are NM IPv6 address structures, we expect both
	 * to contain two elements as specified in nm-dbus-glib-types.h.
	 */
	g_return_val_if_fail (values1->n_values == 3, 0);
	g_return_val_if_fail (values2->n_values == 3, 0);

	/* First struct IPv6 address */
	tmp_val = g_value_array_get_nth (values1, 0);
	addr1 = g_value_get_boxed (tmp_val);
	/* First struct IPv6 prefix */
	tmp_val = g_value_array_get_nth (values1, 1);
	prefix1 = g_value_get_uint (tmp_val);
	/* First struct IPv6 gateway */
	tmp_val = g_value_array_get_nth (values1, 2);
	gw1 = g_value_get_boxed (tmp_val);

	/* Second struct IPv6 address */
	tmp_val = g_value_array_get_nth (values2, 0);
	addr2 = g_value_get_boxed (tmp_val);
	/* Second struct IPv6 prefix */
	tmp_val = g_value_array_get_nth (values2, 1);
	prefix2 = g_value_get_uint (tmp_val);
	/* Second struct IPv6 gateway */
	tmp_val = g_value_array_get_nth (values2, 2);
	gw2 = g_value_get_boxed (tmp_val);

	/* Compare IPv6 addresses */
	if (prefix1 != prefix2)
		return prefix1 < prefix2 ? -1 : prefix1 > prefix2;

	if (!IN6_ARE_ADDR_EQUAL ((struct in6_addr *)addr1->data, (struct in6_addr *)addr2->data)) {
		for (i = 0; ret == 0 && i < addr1->len; i++)
			ret = addr1->data[i] < addr2->data[i] ? -1 : addr1->data[i] > addr2->data[i];
	}

	if (!IN6_ARE_ADDR_EQUAL ((struct in6_addr *) gw1->data, (struct in6_addr *) gw2->data)) {
		for (i = 0; ret == 0 && i < gw1->len; i++)
			ret = gw1->data[i] < gw2->data[i] ? -1 : gw1->data[i] > gw2->data[i];
	}

	return ret;
}

static gint
_gvalue_ip6_route_compare (const GValue *value1, const GValue *value2)
{
	GValueArray *values1, *values2;
	GValue *tmp_val;
	GByteArray *dest1, *dest2;
	GByteArray *next_hop1, *next_hop2;
	guint32 prefix1, prefix2;
	guint32 metric1, metric2;
	gint ret = 0;
	int i;

	/* IP6 routes are GValueArrays (see nm-dbus-glib-types.h) */
	values1 = g_value_get_boxed (value1);
	values2 = g_value_get_boxed (value2);

	/* Since they are NM IPv6 route structures, we expect both
	 * to contain 4 elements as specified in nm-dbus-glib-types.h.
	 */
	g_return_val_if_fail (values1->n_values == 4, 0);
	g_return_val_if_fail (values2->n_values == 4, 0);

	/* First struct IPv6 route */
	tmp_val = g_value_array_get_nth (values1, 0);
	dest1 = g_value_get_boxed (tmp_val);
	tmp_val = g_value_array_get_nth (values1, 1);
	prefix1 = g_value_get_uint (tmp_val);
	tmp_val = g_value_array_get_nth (values1, 2);
	next_hop1 = g_value_get_boxed (tmp_val);
	tmp_val = g_value_array_get_nth (values1, 3);
	metric1 = g_value_get_uint (tmp_val);

	/* Second struct IPv6 route */
	tmp_val = g_value_array_get_nth (values2, 0);
	dest2 = g_value_get_boxed (tmp_val);
	tmp_val = g_value_array_get_nth (values2, 1);
	prefix2 = g_value_get_uint (tmp_val);
	tmp_val = g_value_array_get_nth (values2, 2);
	next_hop2 = g_value_get_boxed (tmp_val);
	tmp_val = g_value_array_get_nth (values2, 3);
	metric2 = g_value_get_uint (tmp_val);

	/* Compare the routes */
	if (prefix1 != prefix2)
		return prefix1 < prefix2 ? -1 : prefix1 > prefix2;

	if (!IN6_ARE_ADDR_EQUAL ((struct in6_addr *)dest1->data, (struct in6_addr *)dest2->data)) {
		for (i = 0; ret == 0 && i < dest1->len; i++)
			ret = dest1->data[i] < dest2->data[i] ? -1 : dest1->data[i] > dest2->data[i];
	}

	if (!IN6_ARE_ADDR_EQUAL ((struct in6_addr *)next_hop1->data, (struct in6_addr *)next_hop2->data)) {
		for (i = 0; ret == 0 && i < next_hop1->len; i++)
			ret = next_hop1->data[i] < next_hop2->data[i] ? -1 : next_hop1->data[i] > next_hop2->data[i];
	}

	if (metric1 != metric2)
		ret = metric1 < metric2 ? -1 : metric1 > metric2;

	return ret;
}

static gint
_gvalues_compare_struct (const GValue *value1, const GValue *value2)
{
	/* value1 and value2 must contain the same type since
	 * _gvalues_compare() enforced that already.
	 */

	if (G_VALUE_HOLDS (value1, DBUS_TYPE_G_IP6_ADDRESS)) {
		return _gvalue_ip6_address_compare (value1, value2);
	} else if (G_VALUE_HOLDS (value1, DBUS_TYPE_G_IP6_ROUTE)) {
		return _gvalue_ip6_route_compare (value1, value2);
	} else {
		g_warning ("Don't know how to compare structures");
		return (value1 == value2);
	}
}

gint
_gvalues_compare (const GValue *value1, const GValue *value2)
{
	GType type1;
	GType type2;
	gint ret;

	if (value1 == value2)
		return 0;
	if (!value1)
		return 1;
	if (!value2)
		return -1;

	type1 = G_VALUE_TYPE (value1);
	type2 = G_VALUE_TYPE (value2);

	if (type1 != type2)
		return type1 < type2 ? -1 : type1 > type2;

	if (type_is_fixed_size (type1, NULL))
		ret = _gvalues_compare_fixed (value1, value2);
	else if (type1 == G_TYPE_STRING)
		ret = _gvalues_compare_string (value1, value2);
	else if (G_VALUE_HOLDS_BOXED (value1)) {
		gpointer p1 = g_value_get_boxed (value1);
		gpointer p2 = g_value_get_boxed (value2);

		if (p1 == p2)
			ret = 0; /* Exactly the same values */
		else if (!p1)
			ret = 1; /* The comparision functions below don't handle NULLs */
		else if (!p2)
			ret = -1; /* The comparision functions below don't handle NULLs */
		else if (type1 == G_TYPE_STRV)
			ret = _gvalues_compare_strv (value1, value2);
		else if (dbus_g_type_is_collection (type1))
			ret = _gvalues_compare_collection (value1, value2);
		else if (dbus_g_type_is_map (type1))
			ret = _gvalues_compare_map (value1, value2);
		else if (dbus_g_type_is_struct (type1))
			ret = _gvalues_compare_struct (value1, value2);
		else if (type1 == G_TYPE_VALUE)
			ret = _gvalues_compare ((GValue *) g_value_get_boxed (value1), (GValue *) g_value_get_boxed (value2));
		else {
			g_warning ("Don't know how to compare boxed types '%s'", g_type_name (type1));
			ret = value1 == value2;
		}
	} else {
		g_warning ("Don't know how to compare types '%s'", g_type_name (type1));
		ret = value1 == value2;
	}

	return ret;
}

/***********************************************************/

static void
param_specialized_init (GParamSpec *pspec)
{
}

static void
param_specialized_set_default (GParamSpec *pspec, GValue *value)
{
	value->data[0].v_pointer = NULL;
}

static gboolean
param_specialized_validate (GParamSpec *pspec, GValue *value)
{
	NMParamSpecSpecialized *sspec = NM_PARAM_SPEC_SPECIALIZED (pspec);
	GType value_type = G_VALUE_TYPE (value);
	gboolean changed = FALSE;

	if (!g_value_type_compatible (value_type, G_PARAM_SPEC_VALUE_TYPE (sspec))) {
		g_value_reset (value);
		changed = TRUE;
	}

	return changed;
}

static gint
param_specialized_values_cmp (GParamSpec *pspec,
                              const GValue *value1,
                              const GValue *value2)
{
	return _gvalues_compare (value1, value2);
}

GType
_nm_param_spec_specialized_get_type (void)
{
	static GType type;

	if (G_UNLIKELY (type) == 0) {
		static const GParamSpecTypeInfo pspec_info = {
			sizeof (NMParamSpecSpecialized),
			0,
			param_specialized_init,
			G_TYPE_OBJECT, /* value_type */
			NULL,          /* finalize */
			param_specialized_set_default,
			param_specialized_validate,
			param_specialized_values_cmp,
		};
		type = g_param_type_register_static ("NMParamSpecSpecialized", &pspec_info);
	}

	return type;
}

GParamSpec *
_nm_param_spec_specialized (const char *name,
                            const char *nick,
                            const char *blurb,
                            GType specialized_type,
                            GParamFlags flags)
{
	NMParamSpecSpecialized *pspec;

	g_return_val_if_fail (g_type_is_a (specialized_type, G_TYPE_BOXED), NULL);

	pspec = g_param_spec_internal (NM_TYPE_PARAM_SPEC_SPECIALIZED,
	                               name, nick, blurb, flags);

	G_PARAM_SPEC (pspec)->value_type = specialized_type;

	return G_PARAM_SPEC (pspec);
}

/***********************************************************/
/* Tests */

#if 0

static void
compare_ints (void)
{
	GValue value1 = G_VALUE_INIT;
	GValue value2 = G_VALUE_INIT;

	g_value_init (&value1, G_TYPE_INT);
	g_value_init (&value2, G_TYPE_INT);

	g_value_set_int (&value1, 5);
	g_value_set_int (&value2, 5);
	g_print ("Comparing ints 5 and 5: %d\n", _gvalues_compare (&value1, &value2));

	g_value_set_int (&value2, 10);
	g_print ("Comparing ints 5 and 10: %d\n", _gvalues_compare (&value1, &value2));

	g_value_set_int (&value2, 1);
	g_print ("Comparing ints 5 and 1: %d\n", _gvalues_compare (&value1, &value2));
}

static void
compare_strings (void)
{
	GValue value1 = G_VALUE_INIT;
	GValue value2 = G_VALUE_INIT;
	const char *str1 = "hello";
	const char *str2 = "world";

	g_value_init (&value1, G_TYPE_STRING);
	g_value_init (&value2, G_TYPE_STRING);

	g_value_set_string (&value1, str1);
	g_value_set_string (&value2, str1);
	g_print ("Comparing identical strings: %d\n", _gvalues_compare (&value1, &value2));

	g_value_set_string (&value2, str2);
	g_print ("Comparing different strings: %d\n", _gvalues_compare (&value1, &value2));
}

static void
compare_strv (void)
{
	GValue value1 = G_VALUE_INIT;
	GValue value2 = G_VALUE_INIT;
	char *strv1[] = { "foo", "bar", "baz", NULL };
	char *strv2[] = { "foo", "bar", "bar", NULL };
	char *strv3[] = { "foo", "bar", NULL };
	char *strv4[] = { "foo", "bar", "baz", "bam", NULL };

	g_value_init (&value1, G_TYPE_STRV);
	g_value_init (&value2, G_TYPE_STRV);

	g_value_set_boxed (&value1, strv1);
	g_value_set_boxed (&value2, strv1);
	g_print ("Comparing identical strv's: %d\n", _gvalues_compare (&value1, &value2));

	g_value_set_boxed (&value2, strv2);
	g_print ("Comparing different strv's: %d\n", _gvalues_compare (&value1, &value2));

	g_value_set_boxed (&value2, strv3);
	g_print ("Comparing different len (smaller) strv's: %d\n", _gvalues_compare (&value1, &value2));

	g_value_set_boxed (&value2, strv4);
	g_print ("Comparing different len (longer) strv's: %d\n", _gvalues_compare (&value1, &value2));
}

static void
compare_garrays (void)
{
	GArray *array1;
	GArray *array2;
	GValue value1 = G_VALUE_INIT;
	GValue value2 = G_VALUE_INIT;
	int i;

	g_value_init (&value1, DBUS_TYPE_G_UINT_ARRAY);
	array1 = g_array_new (FALSE, FALSE, sizeof (guint32));

	g_value_init (&value2, DBUS_TYPE_G_UINT_ARRAY);
	array2 = g_array_new (FALSE, FALSE, sizeof (guint32));

	for (i = 0; i < 5; i++) {
		g_array_append_val (array1, i);
		g_array_append_val (array2, i);
	}

	g_value_set_boxed (&value1, array1);
	g_value_set_boxed (&value2, array2);

	g_print ("Comparing identical arrays's: %d\n", _gvalues_compare (&value1, &value2));

	g_array_remove_index (array2, 0);
	g_value_set_boxed (&value2, array2);
	g_print ("Comparing different length arrays's: %d\n", _gvalues_compare (&value1, &value2));

	i = 7;
	g_array_prepend_val (array2, i);
	g_value_set_boxed (&value2, array2);
	g_print ("Comparing different arrays's: %d\n", _gvalues_compare (&value1, &value2));
}

static void
compare_ptrarrays (void)
{
	GPtrArray *array1;
	GPtrArray *array2;
	GValue value1 = G_VALUE_INIT;
	GValue value2 = G_VALUE_INIT;

	g_value_init (&value1, dbus_g_type_get_collection ("GPtrArray", G_TYPE_STRING));
	array1 = g_ptr_array_new ();

	g_value_init (&value2, dbus_g_type_get_collection ("GPtrArray", G_TYPE_STRING));
	array2 = g_ptr_array_new ();

	g_ptr_array_add (array1, "hello");
	g_ptr_array_add (array1, "world");
	g_value_set_boxed (&value1, array1);

	g_ptr_array_add (array2, "hello");
	g_ptr_array_add (array2, "world");
	g_value_set_boxed (&value2, array2);

	g_print ("Comparing identical ptr arrays's: %d\n", _gvalues_compare (&value1, &value2));

	g_ptr_array_add (array2, "boo");
	g_value_set_boxed (&value2, array2);
	g_print ("Comparing different len ptr arrays's: %d\n", _gvalues_compare (&value1, &value2));

	g_ptr_array_add (array1, "booz");
	g_value_set_boxed (&value1, array1);
	g_print ("Comparing different ptr arrays's: %d\n", _gvalues_compare (&value1, &value2));
}

static void
compare_str_hash (void)
{
	GHashTable *hash1;
	GHashTable *hash2;
	GValue value1 = G_VALUE_INIT;
	GValue value2 = G_VALUE_INIT;

	g_value_init (&value1, dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_STRING));
	g_value_init (&value2, dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_STRING));

	hash1 = g_hash_table_new (g_str_hash, g_str_equal);
	hash2 = g_hash_table_new (g_str_hash, g_str_equal);

	g_hash_table_insert (hash1, "key1", "hello");
	g_hash_table_insert (hash1, "key2", "world");

	g_hash_table_insert (hash2, "key1", "hello");
	g_hash_table_insert (hash2, "key2", "world");

	g_value_set_boxed (&value1, hash1);
	g_value_set_boxed (&value2, hash2);
	g_print ("Comparing identical str hashes: %d\n", _gvalues_compare (&value1, &value2));

	g_hash_table_remove (hash2, "key2");
	g_value_set_boxed (&value2, hash2);
	g_print ("Comparing different length str hashes: %d\n", _gvalues_compare (&value1, &value2));

	g_hash_table_insert (hash2, "key2", "moon");
	g_value_set_boxed (&value2, hash2);
	g_print ("Comparing different str hashes: %d\n", _gvalues_compare (&value1, &value2));
}

static GValue *
str_to_gvalue (const char *str)
{
	GValue *value;

	value = g_slice_new0 (GValue);
	g_value_init (value, G_TYPE_STRING);
	g_value_set_string (value, str);

	return value;
}

static GValue *
int_to_gvalue (int i)
{
	GValue *value;

	value = g_slice_new0 (GValue);
	g_value_init (value, G_TYPE_INT);
	g_value_set_int (value, i);

	return value;
}

static void
compare_gvalue_hash (void)
{
	GHashTable *hash1;
	GHashTable *hash2;
	GValue value1 = G_VALUE_INIT;
	GValue value2 = G_VALUE_INIT;

	g_value_init (&value1, dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_VALUE));
	g_value_init (&value2, dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_VALUE));

	hash1 = g_hash_table_new (g_str_hash, g_str_equal);
	hash2 = g_hash_table_new (g_str_hash, g_str_equal);

	g_hash_table_insert (hash1, "key1", str_to_gvalue ("hello"));
	g_hash_table_insert (hash1, "key2", int_to_gvalue (5));

	g_hash_table_insert (hash2, "key1", str_to_gvalue ("hello"));
	g_hash_table_insert (hash2, "key2", int_to_gvalue (5));

	g_value_set_boxed (&value1, hash1);
	g_value_set_boxed (&value2, hash2);
	g_print ("Comparing identical gvalue hashes: %d\n", _gvalues_compare (&value1, &value2));

	g_hash_table_remove (hash2, "key2");
	g_value_set_boxed (&value2, hash2);
	g_print ("Comparing different length str hashes: %d\n", _gvalues_compare (&value1, &value2));

	g_hash_table_insert (hash2, "key2", str_to_gvalue ("moon"));
	g_value_set_boxed (&value2, hash2);
	g_print ("Comparing different str hashes: %d\n", _gvalues_compare (&value1, &value2));
}

static void
compare_ip6_addresses (void)
{
	GValueArray *array1;
	GValueArray *array2;
	GValueArray *array3;
	GByteArray *ba1;
	GByteArray *ba2;
	GByteArray *ba3;
	GValue element = G_VALUE_INIT;
	GValue value1 = G_VALUE_INIT;
	GValue value2 = G_VALUE_INIT;
	struct in6_addr addr1;
	struct in6_addr addr2;
	struct in6_addr addr3;
	guint32 prefix1 = 64;
	guint32 prefix2 = 64;
	guint32 prefix3 = 0;

	inet_pton (AF_INET6, "1:2:3:4:5:6:7:8", &addr1, sizeof (struct in6_addr));
	inet_pton (AF_INET6, "ffff:2:3:4:5:6:7:8", &addr2, sizeof (struct in6_addr));
	inet_pton (AF_INET6, "::", &addr3, sizeof (struct in6_addr));

	/* address 1 */
	ba1 = g_byte_array_new ();
	array1 = g_value_array_new (2);
	g_value_init (&element, DBUS_TYPE_G_UCHAR_ARRAY);
	g_byte_array_append (ba1, (guint8 *) addr1.s6_addr, 16);
	g_value_take_boxed (&element, ba1);
	g_value_array_append (array1, &element);
	g_value_unset (&element);

	g_value_init (&element, G_TYPE_UINT);
	g_value_set_uint (&element, prefix1);
	g_value_array_append (array1, &element);
	g_value_unset (&element);

	/* address 2 */
	ba2 = g_byte_array_new ();
	array2 = g_value_array_new (2);
	g_value_init (&element, DBUS_TYPE_G_UCHAR_ARRAY);
	g_byte_array_append (ba2, (guint8 *) addr2.s6_addr, 16);
	g_value_take_boxed (&element, ba2);
	g_value_array_append (array2, &element);
	g_value_unset (&element);

	g_value_init (&element, G_TYPE_UINT);
	g_value_set_uint (&element, prefix2);
	g_value_array_append (array2, &element);
	g_value_unset (&element);

	/* address 3 */
	ba3 = g_byte_array_new ();
	array3 = g_value_array_new (2);
	g_value_init (&element, DBUS_TYPE_G_UCHAR_ARRAY);
	g_byte_array_append (ba3, (guint8 *) addr3.s6_addr, 16);
	g_value_take_boxed (&element, ba3);
	g_value_array_append (array3, &element);
	g_value_unset (&element);

	g_value_init (&element, G_TYPE_UINT);
	g_value_set_uint (&element, prefix3);
	g_value_array_append (array3, &element);
	g_value_unset (&element);

	g_value_init (&value1, DBUS_TYPE_G_IP6_ADDRESS);
	g_value_init (&value2, DBUS_TYPE_G_IP6_ADDRESS);

	g_value_set_boxed (&value1, array1);
	g_value_set_boxed (&value2, array1);
	g_print ("Comparing identical IPv6 address structures: %d\n", _gvalues_compare (&value1, &value2));

	g_value_set_boxed (&value1, array1);
	g_value_set_boxed (&value2, array2);
	g_print ("Comparing different IPv6 address structures: %d\n", _gvalues_compare (&value1, &value2));

	g_value_set_boxed (&value1, array1);
	g_value_set_boxed (&value2, array3);
	g_print ("Comparing different IPv6 address structures: %d\n", _gvalues_compare (&value1, &value2));
}

int
main (int argc, char *argv[])
{
	DBusGConnection *bus;

	nm_g_type_init ();

	bus = dbus_g_bus_get (DBUS_BUS_SESSION, NULL);

	compare_ints ();
	compare_strings ();
	compare_strv ();
	compare_garrays ();
	compare_ptrarrays ();
	compare_str_hash ();
	compare_gvalue_hash ();
	compare_ip6_addresses ();

	return 0;
}

#endif
