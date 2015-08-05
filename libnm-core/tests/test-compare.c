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

#include <arpa/inet.h>
#include <netinet/in.h>

#include "nm-default.h"
#include "nm-property-compare.h"

#include "nm-test-utils.h"

static void
compare_ints (void)
{
	GVariant *value1, *value2;

	value1 = g_variant_new_int32 (5);
	value2 = g_variant_new_int32 (5);
	g_assert (nm_property_compare (value1, value2) == 0);

	g_variant_unref (value2);
	value2 = g_variant_new_int32 (10);
	g_assert (nm_property_compare (value1, value2) < 0);

	g_variant_unref (value2);
	value2 = g_variant_new_int32 (-1);
	g_assert (nm_property_compare (value1, value2) > 0);

	g_variant_unref (value1);
	g_variant_unref (value2);
}

static void
compare_strings (void)
{
	GVariant *value1, *value2;
	const char *str1 = "hello";
	const char *str2 = "world";

	value1 = g_variant_new_string (str1);
	value2 = g_variant_new_string (str1);
	g_assert (nm_property_compare (value1, value2) == 0);

	g_variant_unref (value2);
	value2 = g_variant_new_string (str2);
	g_assert (nm_property_compare (value1, value2) < 0);

	g_assert (nm_property_compare (value2, value1) > 0);

	g_variant_unref (value1);
	g_variant_unref (value2);
}

static void
compare_strv (void)
{
	GVariant *value1, *value2;
	const char * const strv1[] = { "foo", "bar", "baz", NULL };
	const char * const strv2[] = { "foo", "bar", "bar", NULL };
	const char * const strv3[] = { "foo", "bar", NULL };
	const char * const strv4[] = { "foo", "bar", "baz", "bam", NULL };

	value1 = g_variant_new_strv (strv1, -1);
	value2 = g_variant_new_strv (strv1, -1);
	g_assert (nm_property_compare (value1, value2) == 0);

	g_variant_unref (value2);
	value2 = g_variant_new_strv (strv2, -1);
	g_assert (nm_property_compare (value1, value2) != 0);

	g_variant_unref (value2);
	value2 = g_variant_new_strv (strv3, -1);
	g_assert (nm_property_compare (value1, value2) != 0);

	g_variant_unref (value2);
	value2 = g_variant_new_strv (strv4, -1);
	g_assert (nm_property_compare (value1, value2) != 0);

	g_variant_unref (value1);
	g_variant_unref (value2);
}

static void
compare_arrays (void)
{
	GVariant *value1, *value2;
	guint32 array[] = { 0, 1, 2, 3, 4 };

	value1 = g_variant_new_fixed_array (G_VARIANT_TYPE_UINT32,
	                                    array, G_N_ELEMENTS (array),
	                                    sizeof (guint32));
	value2 = g_variant_new_fixed_array (G_VARIANT_TYPE_UINT32,
	                                    array, G_N_ELEMENTS (array),
	                                    sizeof (guint32));

	g_assert (nm_property_compare (value1, value2) == 0);

	g_variant_unref (value2);
	value2 = g_variant_new_fixed_array (G_VARIANT_TYPE_UINT32,
	                                    array + 1, G_N_ELEMENTS (array) - 1,
	                                    sizeof (guint32));
	g_assert (nm_property_compare (value1, value2) != 0);

	array[0] = 7;
	g_variant_unref (value2);
	value2 = g_variant_new_fixed_array (G_VARIANT_TYPE_UINT32,
	                                    array, G_N_ELEMENTS (array),
	                                    sizeof (guint32));
	g_assert (nm_property_compare (value1, value2) != 0);

	g_variant_unref (value1);
	g_variant_unref (value2);
}

static void
compare_str_hash (void)
{
	GVariant *value1, *value2;
	GVariantBuilder builder;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{ss}"));
	g_variant_builder_add (&builder, "{ss}", "key1", "hello");
	g_variant_builder_add (&builder, "{ss}", "key2", "world");
	g_variant_builder_add (&builder, "{ss}", "key3", "!");
	value1 = g_variant_builder_end (&builder);

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{ss}"));
	g_variant_builder_add (&builder, "{ss}", "key3", "!");
	g_variant_builder_add (&builder, "{ss}", "key2", "world");
	g_variant_builder_add (&builder, "{ss}", "key1", "hello");
	value2 = g_variant_builder_end (&builder);

	g_assert (nm_property_compare (value1, value2) == 0);

	g_variant_unref (value2);
	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{ss}"));
	g_variant_builder_add (&builder, "{ss}", "key1", "hello");
	g_variant_builder_add (&builder, "{ss}", "key3", "!");
	value2 = g_variant_builder_end (&builder);

	g_assert (nm_property_compare (value1, value2) != 0);
	g_assert (nm_property_compare (value2, value1) != 0);

	g_variant_unref (value2);
	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{ss}"));
	g_variant_builder_add (&builder, "{ss}", "key1", "hello");
	g_variant_builder_add (&builder, "{ss}", "key2", "moon");
	g_variant_builder_add (&builder, "{ss}", "key3", "!");
	value2 = g_variant_builder_end (&builder);

	g_assert (nm_property_compare (value1, value2) != 0);

	g_variant_unref (value1);
	g_variant_unref (value2);
}

static void
compare_ip6_addresses (void)
{
	GVariant *value1, *value2;
	struct in6_addr addr1;
	struct in6_addr addr2;
	struct in6_addr addr3;
	guint32 prefix1 = 64;
	guint32 prefix2 = 64;
	guint32 prefix3 = 0;

	inet_pton (AF_INET6, "1:2:3:4:5:6:7:8", &addr1);
	inet_pton (AF_INET6, "ffff:2:3:4:5:6:7:8", &addr2);
	inet_pton (AF_INET6, "::", &addr3);

	value1 = g_variant_new ("(@ayu@ay)",
	                        g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
	                                                   (guint8 *) addr1.s6_addr, 16, 1),
	                        prefix1,
	                        g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
	                                                   (guint8 *) addr3.s6_addr, 16, 1));

	value2 = g_variant_new ("(@ayu@ay)",
	                        g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
	                                                   (guint8 *) addr1.s6_addr, 16, 1),
	                        prefix1,
	                        g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
	                                                   (guint8 *) addr3.s6_addr, 16, 1));

	g_assert (nm_property_compare (value1, value2) == 0);

	g_variant_unref (value2);
	value2 = g_variant_new ("(@ayu@ay)",
	                        g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
	                                                   (guint8 *) addr2.s6_addr, 16, 1),
	                        prefix2,
	                        g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
	                                                   (guint8 *) addr3.s6_addr, 16, 1));

	g_assert (nm_property_compare (value1, value2) != 0);

	g_variant_unref (value2);
	value2 = g_variant_new ("(@ayu@ay)",
	                        g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
	                                                   (guint8 *) addr3.s6_addr, 16, 1),
	                        prefix3,
	                        g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
	                                                   (guint8 *) addr3.s6_addr, 16, 1));

	g_assert (nm_property_compare (value1, value2) != 0);

	g_variant_unref (value1);
	g_variant_unref (value2);
}

NMTST_DEFINE ();

int
main (int argc, char *argv[])
{
	nmtst_init (&argc, &argv, TRUE);

	g_test_add_func ("/libnm/compare/ints", compare_ints);
	g_test_add_func ("/libnm/compare/strings", compare_strings);
	g_test_add_func ("/libnm/compare/strv", compare_strv);
	g_test_add_func ("/libnm/compare/arrays", compare_arrays);
	g_test_add_func ("/libnm/compare/str_hash", compare_str_hash);
	g_test_add_func ("/libnm/compare/ip6_addresses", compare_ip6_addresses);

	return g_test_run ();
}
