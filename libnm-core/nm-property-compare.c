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
 * Copyright 2007 - 2014 Red Hat, Inc.
 * Copyright 2007 - 2008 Novell, Inc.
 */

#include "config.h"

#include <string.h>
#include <math.h>
#include <netinet/in.h>

#include "nm-property-compare.h"
#include "nm-glib.h"

static gint
_nm_property_compare_collection (GVariant *value1, GVariant *value2)
{
	GVariant *child1, *child2;
	int i, len1, len2;
	int ret;

	len1 = g_variant_n_children (value1);
	len2 = g_variant_n_children (value2);

	if (len1 != len2)
		return len1 < len2 ? -1 : len1 > len2;

	for (i = 0; i < len1; i++) {
		child1 = g_variant_get_child_value (value1, i);
		child2 = g_variant_get_child_value (value2, i);

		ret = nm_property_compare (child1, child2);
		g_variant_unref (child1);
		g_variant_unref (child2);

		if (ret)
			return ret;
	}

	return 0;
}

static gint
_nm_property_compare_strdict (GVariant *value1, GVariant *value2)
{
	GVariantIter iter;
	int len1, len2;
	const char *key, *val1, *val2;
	int ret;

	len1 = g_variant_n_children (value1);
	len2 = g_variant_n_children (value2);

	if (len1 != len2)
		return len1 < len2 ? -1 : len1 > len2;

	g_variant_iter_init (&iter, value1);
	while (g_variant_iter_next (&iter, "{&s&s}", &key, &val1)) {
		if (!g_variant_lookup (value2, key, "&s", &val2))
			return -1;

		ret = strcmp (val1, val2);
		if (ret)
			return ret;
	}

	return 0;
}

int
nm_property_compare (GVariant *value1, GVariant *value2)
{
	const GVariantType *type1;
	const GVariantType *type2;
	gint ret;

	if (value1 == value2)
		return 0;
	if (!value1)
		return 1;
	if (!value2)
		return -1;

	type1 = g_variant_get_type (value1);
	type2 = g_variant_get_type (value2);

	if (!g_variant_type_equal (type1, type2))
		return type1 < type2 ? -1 : type1 > type2;

	if (g_variant_type_is_basic (type1))
		ret = g_variant_compare (value1, value2);
	else if (g_variant_is_of_type (value1, G_VARIANT_TYPE ("a{ss}")))
		ret = _nm_property_compare_strdict (value1, value2);
	else if (g_variant_type_is_array (type1))
		ret = _nm_property_compare_collection (value1, value2);
	else if (g_variant_type_is_tuple (type1))
		ret = _nm_property_compare_collection (value1, value2);
	else {
		g_warning ("Don't know how to compare variant type '%s'", (const char *) type1);
		ret = value1 == value2;
	}

	return ret;
}
