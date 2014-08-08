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

#include "nm-glib-compat.h"

#include <string.h>
#include <math.h>
#include <netinet/in.h>
#include <dbus/dbus-glib.h>

#include "nm-dbus-glib-types.h"

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

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

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
