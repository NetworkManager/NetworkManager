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
 * Copyright 2005 - 2014 Red Hat, Inc.
 */

#include "nm-default.h"

#include <string.h>

#include "nm-gvaluearray-compat.h"
#include "nm-utils.h"
#include "nm-utils-private.h"
#include "nm-dbus-glib-types.h"

static void
_nm_utils_convert_op_to_string (const GValue *src_value, GValue *dest_value)
{
	g_return_if_fail (g_type_is_a (G_VALUE_TYPE (src_value), DBUS_TYPE_G_OBJECT_PATH));

	g_value_set_string (dest_value, (const char *) g_value_get_boxed (src_value));
}

static void
_nm_utils_convert_strv_to_slist (const GValue *src_value, GValue *dest_value)
{
	char **str;
	GSList *list = NULL;
	guint i = 0;

	g_return_if_fail (g_type_is_a (G_VALUE_TYPE (src_value), G_TYPE_STRV));

	str = (char **) g_value_get_boxed (src_value);

	while (str && str[i])
		list = g_slist_prepend (list, g_strdup (str[i++]));

	g_value_take_boxed (dest_value, g_slist_reverse (list));
}

static void
_nm_utils_convert_slist_to_strv (const GValue *src_value, GValue *dest_value)
{
	GSList *slist;
	char **strv;
	int len, i = 0;

	slist = g_value_get_boxed (src_value);
	len = g_slist_length (slist);

	strv = g_new (char *, len + 1);
	for (i = 0; slist; slist = slist->next, i++)
		strv[i] = g_strdup (slist->data);
	strv[i] = NULL;

	g_value_take_boxed (dest_value, strv);
}

static void
_nm_utils_convert_strv_to_ptrarray (const GValue *src_value, GValue *dest_value)
{
	char **str;
	GPtrArray *array = NULL;
	guint i = 0;

	g_return_if_fail (g_type_is_a (G_VALUE_TYPE (src_value), G_TYPE_STRV));

	str = (char **) g_value_get_boxed (src_value);

	array = g_ptr_array_sized_new (3);
	while (str && str[i])
		g_ptr_array_add (array, g_strdup (str[i++]));

	g_value_take_boxed (dest_value, array);
}

static void
_nm_utils_convert_string_list_to_string (const GValue *src_value, GValue *dest_value)
{
	GSList *strings;
	GString *printable;
	GSList *iter;

	g_return_if_fail (g_type_is_a (G_VALUE_TYPE (src_value), DBUS_TYPE_G_LIST_OF_STRING));

	strings = (GSList *) g_value_get_boxed (src_value);

	printable = g_string_new (NULL);
	for (iter = strings; iter; iter = iter->next) {
		if (iter != strings)
			g_string_append_c (printable, ',');
		g_string_append (printable, iter->data ? iter->data : "(null)");
	}

	g_value_take_string (dest_value, g_string_free (printable, FALSE));
}

static void
_string_array_to_string (const GPtrArray *strings, GValue *dest_value)
{
	GString *printable;
	guint i;

	printable = g_string_new (NULL);
	for (i = 0; strings && i < strings->len; i++) {
		if (i > 0)
			g_string_append_c (printable, ',');
		g_string_append (printable, strings->pdata[i]);
	}

	g_value_take_string (dest_value, g_string_free (printable, FALSE));
}

static void
_nm_utils_convert_string_array_to_string (const GValue *src_value, GValue *dest_value)
{
	const GPtrArray *strings;

	g_return_if_fail (g_type_is_a (G_VALUE_TYPE (src_value), DBUS_TYPE_G_ARRAY_OF_STRING));

	strings = (const GPtrArray *) g_value_get_boxed (src_value);
	_string_array_to_string (strings, dest_value);
}

static void
_nm_utils_convert_op_array_to_string (const GValue *src_value, GValue *dest_value)
{
	const GPtrArray *strings;

	g_return_if_fail (g_type_is_a (G_VALUE_TYPE (src_value), DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH));

	strings = (const GPtrArray *) g_value_get_boxed (src_value);
	_string_array_to_string (strings, dest_value);
}

static void
_nm_utils_convert_uint_array_to_string (const GValue *src_value, GValue *dest_value)
{
	GArray *array;
	GString *printable;
	guint i = 0;

	g_return_if_fail (g_type_is_a (G_VALUE_TYPE (src_value), DBUS_TYPE_G_UINT_ARRAY));

	array = (GArray *) g_value_get_boxed (src_value);

	printable = g_string_new (NULL);
	while (array && (i < array->len)) {
		guint32 addr;

		if (i > 0)
			g_string_append (printable, ", ");

		addr = g_array_index (array, guint32, i++);
		g_string_append (printable, nm_utils_inet4_ntop (addr, NULL));
	}

	g_value_take_string (dest_value, g_string_free (printable, FALSE));
}

static void
_nm_utils_convert_ip4_addr_route_struct_array_to_string (const GValue *src_value, GValue *dest_value)
{
	GPtrArray *ptr_array;
	GString *printable;
	guint i = 0;
	char buf[INET_ADDRSTRLEN];

	g_return_if_fail (g_type_is_a (G_VALUE_TYPE (src_value), DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UINT));

	ptr_array = (GPtrArray *) g_value_get_boxed (src_value);

	printable = g_string_new (NULL);
	while (ptr_array && (i < ptr_array->len)) {
		GArray *array;
		gboolean is_addr; /* array contains address x route */

		if (i > 0)
			g_string_append (printable, "; ");

		g_string_append (printable, "{ ");
		array = (GArray *) g_ptr_array_index (ptr_array, i++);
		if (array->len < 2) {
			g_string_append (printable, "invalid");
			continue;
		}
		is_addr = (array->len < 4);

		nm_utils_inet4_ntop (g_array_index (array, guint32, 0), buf);
		if (is_addr)
			g_string_append_printf (printable, "ip = %s", buf);
		else
			g_string_append_printf (printable, "dst = %s", buf);

		g_string_append_printf (printable, "/%u",
		                        g_array_index (array, guint32, 1));

		if (array->len > 2) {
			nm_utils_inet4_ntop (g_array_index (array, guint32, 2), buf);
			if (is_addr)
				g_string_append_printf (printable, ", gw = %s", buf);
			else
				g_string_append_printf (printable, ", nh = %s", buf);
		}

		if (array->len > 3) {
			g_string_append_printf (printable, ", mt = %u",
			                        g_array_index (array, guint32, 3));
		}

		g_string_append (printable, " }");
	}

	g_value_take_string (dest_value, g_string_free (printable, FALSE));
}

static void
convert_one_gvalue_hash_entry (gpointer key, gpointer value, gpointer user_data)
{
	GString *printable = (GString *) user_data;
	char *value_as_string;

	value_as_string = g_strdup_value_contents ((GValue *) value);
	g_string_append_printf (printable, " { '%s': %s },", (const char *) key, value_as_string);
	g_free (value_as_string);
}

static void
_nm_utils_convert_gvalue_hash_to_string (const GValue *src_value, GValue *dest_value)
{
	GHashTable *hash;
	GString *printable;

	g_return_if_fail (g_type_is_a (G_VALUE_TYPE (src_value), DBUS_TYPE_G_MAP_OF_VARIANT));

	hash = (GHashTable *) g_value_get_boxed (src_value);

	printable = g_string_new ("[");
	g_hash_table_foreach (hash, convert_one_gvalue_hash_entry, printable);
	g_string_append (printable, " ]");

	g_value_take_string (dest_value, printable->str);
	g_string_free (printable, FALSE);
}

static void
convert_one_string_hash_entry (gpointer key, gpointer value, gpointer user_data)
{
	GString *printable = (GString *) user_data;

	if (printable->len)
		g_string_append_c (printable, ',');
	g_string_append_printf (printable, "%s=%s", (const char *) key, (const char *) value);
}

static void
_nm_utils_convert_string_hash_to_string (const GValue *src_value, GValue *dest_value)
{
	GHashTable *hash;
	GString *printable;

	g_return_if_fail (g_type_is_a (G_VALUE_TYPE (src_value), DBUS_TYPE_G_MAP_OF_STRING));

	hash = (GHashTable *) g_value_get_boxed (src_value);

	printable = g_string_new (NULL);
	if (hash)
		g_hash_table_foreach (hash, convert_one_string_hash_entry, printable);

	g_value_take_string (dest_value, g_string_free (printable, FALSE));
}

static void
_nm_utils_convert_byte_array_to_string (const GValue *src_value, GValue *dest_value)
{
	GArray *array;
	GString *printable;
	guint i = 0;

	g_return_if_fail (g_type_is_a (G_VALUE_TYPE (src_value), DBUS_TYPE_G_UCHAR_ARRAY));

	array = (GArray *) g_value_get_boxed (src_value);

	printable = g_string_new ("[");
	if (array) {
		while (i < MIN (array->len, 35)) {
			if (i > 0)
				g_string_append_c (printable, ' ');
			g_string_append_printf (printable, "0x%02X",
			                        g_array_index (array, unsigned char, i++));
		}
		if (i < array->len)
			g_string_append (printable, " ... ");
	}
	g_string_append_c (printable, ']');

	g_value_take_string (dest_value, g_string_free (printable, FALSE));
}

static void
_nm_utils_convert_ip6_dns_array_to_string (const GValue *src_value, GValue *dest_value)
{
	GPtrArray *ptr_array;
	GString *printable;
	guint i = 0;

	g_return_if_fail (g_type_is_a (G_VALUE_TYPE (src_value), DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UCHAR));

	ptr_array = (GPtrArray *) g_value_get_boxed (src_value);

	printable = g_string_new (NULL);
	while (ptr_array && (i < ptr_array->len)) {
		GByteArray *bytearray;
		struct in6_addr *addr;

		if (i > 0)
			g_string_append (printable, ", ");

		bytearray = (GByteArray *) g_ptr_array_index (ptr_array, i++);
		if (bytearray->len != 16) {
			g_string_append (printable, "invalid");
			continue;
		}
		addr = (struct in6_addr *) bytearray->data;
		g_string_append (printable, nm_utils_inet6_ntop (addr, NULL));
	}

	g_value_take_string (dest_value, g_string_free (printable, FALSE));
}

static void
_nm_utils_convert_ip6_addr_struct_array_to_string (const GValue *src_value, GValue *dest_value)
{
	GPtrArray *ptr_array;
	GString *printable;
	guint i = 0;

	g_return_if_fail (g_type_is_a (G_VALUE_TYPE (src_value), DBUS_TYPE_G_ARRAY_OF_IP6_ADDRESS));

	ptr_array = (GPtrArray *) g_value_get_boxed (src_value);

	printable = g_string_new (NULL);
	while (ptr_array && (i < ptr_array->len)) {
		GValueArray *elements;
		GValue *tmp;
		GByteArray *ba_addr;
		struct in6_addr *addr;
		guint32 prefix;

		if (i > 0)
			g_string_append (printable, "; ");

		g_string_append (printable, "{ ");
		elements = (GValueArray *) g_ptr_array_index (ptr_array, i++);
		if (!_nm_utils_gvalue_array_validate (elements, 3,
		                                      DBUS_TYPE_G_UCHAR_ARRAY,
		                                      G_TYPE_UINT,
		                                      DBUS_TYPE_G_UCHAR_ARRAY)) {
			g_string_append (printable, "invalid }");
			continue;
		}

		/* IPv6 address */
		tmp = g_value_array_get_nth (elements, 0);
		ba_addr = g_value_get_boxed (tmp);
		if (ba_addr->len != 16) {
			g_string_append (printable, "invalid }");
			continue;
		}
		addr = (struct in6_addr *) ba_addr->data;
		g_string_append_printf (printable, "ip = %s", nm_utils_inet6_ntop (addr, NULL));

		/* Prefix */
		tmp = g_value_array_get_nth (elements, 1);
		prefix = g_value_get_uint (tmp);
		if (prefix > 128) {
			g_string_append (printable, "/invalid }");
			continue;
		}
		g_string_append_printf (printable, "/%u", prefix);
		g_string_append (printable, ", ");

		/* IPv6 Gateway */
		tmp = g_value_array_get_nth (elements, 2);
		ba_addr = g_value_get_boxed (tmp);
		if (ba_addr->len != 16) {
			g_string_append (printable, "invalid }");
			continue;
		}
		addr = (struct in6_addr *) ba_addr->data;
		g_string_append_printf (printable, "gw = %s", nm_utils_inet6_ntop (addr, NULL));
		g_string_append (printable, " }");
	}

	g_value_take_string (dest_value, g_string_free (printable, FALSE));
}

static void
_nm_utils_convert_ip6_route_struct_array_to_string (const GValue *src_value, GValue *dest_value)
{
	GPtrArray *ptr_array;
	GString *printable;
	guint i = 0;

	g_return_if_fail (g_type_is_a (G_VALUE_TYPE (src_value), DBUS_TYPE_G_ARRAY_OF_IP6_ROUTE));

	ptr_array = (GPtrArray *) g_value_get_boxed (src_value);

	printable = g_string_new (NULL);
	while (ptr_array && (i < ptr_array->len)) {
		GValueArray *elements;
		GValue *tmp;
		GByteArray *ba_addr;
		struct in6_addr *addr;
		guint32 prefix, metric;

		if (i > 0)
			g_string_append (printable, "; ");

		g_string_append (printable, "{ ");
		elements = (GValueArray *) g_ptr_array_index (ptr_array, i++);
		if (!_nm_utils_gvalue_array_validate (elements, 4,
		                                      DBUS_TYPE_G_UCHAR_ARRAY,
		                                      G_TYPE_UINT,
		                                      DBUS_TYPE_G_UCHAR_ARRAY,
		                                      G_TYPE_UINT)) {
			g_string_append (printable, "invalid");
			continue;
		}

		/* Destination address */
		tmp = g_value_array_get_nth (elements, 0);
		ba_addr = g_value_get_boxed (tmp);
		if (ba_addr->len != 16) {
			g_string_append (printable, "invalid");
			continue;
		}
		addr = (struct in6_addr *) ba_addr->data;
		g_string_append_printf (printable, "dst = %s", nm_utils_inet6_ntop (addr, NULL));

		/* Prefix */
		tmp = g_value_array_get_nth (elements, 1);
		prefix = g_value_get_uint (tmp);
		if (prefix > 128) {
			g_string_append (printable, "/invalid");
			continue;
		}
		g_string_append_printf (printable, "/%u", prefix);
		g_string_append (printable, ", ");

		/* Next hop addresses */
		tmp = g_value_array_get_nth (elements, 2);
		ba_addr = g_value_get_boxed (tmp);
		if (ba_addr->len != 16) {
			g_string_append (printable, "invalid");
			continue;
		}
		addr = (struct in6_addr *) ba_addr->data;
		g_string_append_printf (printable, "nh = %s", nm_utils_inet6_ntop (addr, NULL));
		g_string_append (printable, ", ");

		/* Metric */
		tmp = g_value_array_get_nth (elements, 3);
		metric = g_value_get_uint (tmp);
		g_string_append_printf (printable, "mt = %u", metric);

		g_string_append (printable, " }");
	}

	g_value_take_string (dest_value, g_string_free (printable, FALSE));
}

#define OLD_DBUS_TYPE_G_IP6_ADDRESS (dbus_g_type_get_struct ("GValueArray", DBUS_TYPE_G_UCHAR_ARRAY, G_TYPE_UINT, G_TYPE_INVALID))
#define OLD_DBUS_TYPE_G_ARRAY_OF_IP6_ADDRESS (dbus_g_type_get_collection ("GPtrArray", OLD_DBUS_TYPE_G_IP6_ADDRESS))

static void
_nm_utils_convert_old_ip6_addr_array (const GValue *src_value, GValue *dst_value)
{
	GPtrArray *src_outer_array;
	GPtrArray *dst_outer_array;
	guint i;

	g_return_if_fail (g_type_is_a (G_VALUE_TYPE (src_value), OLD_DBUS_TYPE_G_ARRAY_OF_IP6_ADDRESS));

	src_outer_array = (GPtrArray *) g_value_get_boxed (src_value);
	dst_outer_array = g_ptr_array_new ();

	for (i = 0; src_outer_array && (i < src_outer_array->len); i++) {
		GValueArray *src_addr_array;
		GValueArray *dst_addr_array;
		GValue element = G_VALUE_INIT;
		GValue *src_addr, *src_prefix;
		GByteArray *ba;

		src_addr_array = (GValueArray *) g_ptr_array_index (src_outer_array, i);
		if (!_nm_utils_gvalue_array_validate (src_addr_array, 2, DBUS_TYPE_G_UCHAR_ARRAY, G_TYPE_UINT)) {
			g_warning ("%s: invalid old IPv6 address type", __func__);
			return;
		}

		dst_addr_array = g_value_array_new (3);

		src_addr = g_value_array_get_nth (src_addr_array, 0);
		g_value_array_append (dst_addr_array, src_addr);
		src_prefix = g_value_array_get_nth (src_addr_array, 1);
		g_value_array_append (dst_addr_array, src_prefix);

		/* Blank Gateway */
		g_value_init (&element, DBUS_TYPE_G_UCHAR_ARRAY);
		ba = g_byte_array_new ();
		g_byte_array_append (ba, (guint8 *) "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16);
		g_value_take_boxed (&element, ba);
		g_value_array_append (dst_addr_array, &element);
		g_value_unset (&element);

		g_ptr_array_add (dst_outer_array, dst_addr_array);
	}

	g_value_take_boxed (dst_value, dst_outer_array);
}

void
_nm_value_transforms_register (void)
{
	static gboolean registered = FALSE;

	if (G_UNLIKELY (!registered)) {
		g_value_register_transform_func (DBUS_TYPE_G_OBJECT_PATH,
		                                 G_TYPE_STRING,
		                                 _nm_utils_convert_op_to_string);
		g_value_register_transform_func (G_TYPE_STRV,
		                                 DBUS_TYPE_G_LIST_OF_STRING,
		                                 _nm_utils_convert_strv_to_slist);
		g_value_register_transform_func (DBUS_TYPE_G_LIST_OF_STRING,
		                                 G_TYPE_STRV,
		                                 _nm_utils_convert_slist_to_strv);
		g_value_register_transform_func (G_TYPE_STRV,
		                                 DBUS_TYPE_G_ARRAY_OF_STRING,
		                                 _nm_utils_convert_strv_to_ptrarray);
		g_value_register_transform_func (DBUS_TYPE_G_LIST_OF_STRING,
		                                 G_TYPE_STRING,
		                                 _nm_utils_convert_string_list_to_string);
		g_value_register_transform_func (DBUS_TYPE_G_ARRAY_OF_STRING,
		                                 G_TYPE_STRING,
		                                 _nm_utils_convert_string_array_to_string);
		g_value_register_transform_func (DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH,
		                                 G_TYPE_STRING,
		                                 _nm_utils_convert_op_array_to_string);
		g_value_register_transform_func (DBUS_TYPE_G_UINT_ARRAY,
		                                 G_TYPE_STRING,
		                                 _nm_utils_convert_uint_array_to_string);
		g_value_register_transform_func (DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UINT,
		                                 G_TYPE_STRING,
		                                 _nm_utils_convert_ip4_addr_route_struct_array_to_string);
		g_value_register_transform_func (DBUS_TYPE_G_MAP_OF_VARIANT,
		                                 G_TYPE_STRING,
		                                 _nm_utils_convert_gvalue_hash_to_string);
		g_value_register_transform_func (DBUS_TYPE_G_MAP_OF_STRING,
		                                 G_TYPE_STRING,
		                                 _nm_utils_convert_string_hash_to_string);
		g_value_register_transform_func (DBUS_TYPE_G_UCHAR_ARRAY,
		                                 G_TYPE_STRING,
		                                 _nm_utils_convert_byte_array_to_string);
		g_value_register_transform_func (DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UCHAR,
		                                 G_TYPE_STRING,
		                                 _nm_utils_convert_ip6_dns_array_to_string);
		g_value_register_transform_func (DBUS_TYPE_G_ARRAY_OF_IP6_ADDRESS,
		                                 G_TYPE_STRING,
		                                 _nm_utils_convert_ip6_addr_struct_array_to_string);
		g_value_register_transform_func (DBUS_TYPE_G_ARRAY_OF_IP6_ROUTE,
		                                 G_TYPE_STRING,
		                                 _nm_utils_convert_ip6_route_struct_array_to_string);
		g_value_register_transform_func (OLD_DBUS_TYPE_G_ARRAY_OF_IP6_ADDRESS,
		                                 DBUS_TYPE_G_ARRAY_OF_IP6_ADDRESS,
		                                 _nm_utils_convert_old_ip6_addr_array);
		registered = TRUE;
	}
}
