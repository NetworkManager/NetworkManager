/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service - keyfile plugin
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2008 - 2009 Novell, Inc.
 * Copyright (C) 2008 - 2010 Red Hat, Inc.
 */

#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <dbus/dbus-glib.h>
#include <nm-setting.h>
#include <nm-setting-ip4-config.h>
#include <nm-setting-ip6-config.h>
#include <nm-setting-vpn.h>
#include <nm-setting-connection.h>
#include <nm-setting-wired.h>
#include <nm-setting-wireless.h>
#include <nm-setting-bluetooth.h>
#include <nm-setting-8021x.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <string.h>
#include <ctype.h>

#include "nm-dbus-glib-types.h"
#include "reader.h"
#include "common.h"

static gboolean
read_array_of_uint (GKeyFile *file,
                    NMSetting *setting,
                    const char *key)
{
	GArray *array = NULL;
	gsize length;
	int i;
	gint *tmp;

	tmp = g_key_file_get_integer_list (file, nm_setting_get_name (setting), key, &length, NULL);
	array = g_array_sized_new (FALSE, FALSE, sizeof (guint32), length);
	for (i = 0; i < length; i++)
		g_array_append_val (array, tmp[i]);

	if (array) {
		g_object_set (setting, key, array, NULL);
		g_array_free (array, TRUE);
	}

	return TRUE;
}

static gboolean
get_one_int (const char *str, guint32 max_val, const char *key_name, guint32 *out)
{
	long tmp;

	errno = 0;
	tmp = strtol (str, NULL, 10);
	if (errno || (tmp < 0) || (tmp > max_val)) {
		g_warning ("%s: ignoring invalid IP %s item '%s'", __func__, key_name, str);
		return FALSE;
	}

	*out = (guint32) tmp;
	return TRUE;
}

static void
free_one_ip4_address (gpointer data, gpointer user_data)
{
	g_array_free ((GArray *) data, TRUE);
}

static GPtrArray *
read_ip4_addresses (GKeyFile *file,
			    const char *setting_name,
			    const char *key)
{
	GPtrArray *addresses;
	int i = 0;

	addresses = g_ptr_array_sized_new (3);

	/* Look for individual addresses */
	while (i++ < 1000) {
		gchar **tmp, **iter;
		char *key_name;
		gsize length = 0;
		int ret;
		GArray *address;
		guint32 empty = 0;
		int j;

		key_name = g_strdup_printf ("%s%d", key, i);
		tmp = g_key_file_get_string_list (file, setting_name, key_name, &length, NULL);
		g_free (key_name);

		if (!tmp || !length)
			break; /* all done */

		if ((length < 2) || (length > 3)) {
			g_warning ("%s: ignoring invalid IPv4 address item '%s'", __func__, key_name);
			goto next;
		}

		/* convert the string array into IP addresses */
		address = g_array_sized_new (FALSE, TRUE, sizeof (guint32), 3);
		for (iter = tmp, j = 0; *iter; iter++, j++) {
			struct in_addr addr;

			if (j == 1) {
				guint32 prefix = 0;

				/* prefix */
				if (!get_one_int (*iter, 32, key_name, &prefix)) {
					g_array_free (address, TRUE);
					goto next;
				}

				g_array_append_val (address, prefix);
			} else {
				/* address and gateway */
				ret = inet_pton (AF_INET, *iter, &addr);
				if (ret <= 0) {
					g_warning ("%s: ignoring invalid IPv4 %s element '%s'", __func__, key_name, *iter);
					g_array_free (address, TRUE);
					goto next;
				}
				g_array_append_val (address, addr.s_addr);
			}
		}

		/* fill in blank gateway if not specified */
		if (address->len == 2)
			g_array_append_val (address, empty);

		g_ptr_array_add (addresses, address);

next:
		g_strfreev (tmp);
	}

	if (addresses->len < 1) {
		g_ptr_array_free (addresses, TRUE);
		addresses = NULL;
	}

	return addresses;
}

static void
ip4_addr_parser (NMSetting *setting, const char *key, GKeyFile *keyfile, const char *keyfile_path)
{
	GPtrArray *addresses;
	const char *setting_name = nm_setting_get_name (setting);

	addresses = read_ip4_addresses (keyfile, setting_name, key);

	/* Work around for previous syntax */
	if (!addresses && !strcmp (key, NM_SETTING_IP4_CONFIG_ADDRESSES))
		addresses = read_ip4_addresses (keyfile, setting_name, "address");

	if (addresses) {
		g_object_set (setting, key, addresses, NULL);
		g_ptr_array_foreach (addresses, free_one_ip4_address, NULL);
		g_ptr_array_free (addresses, TRUE);
	}
}

static void
free_one_ip4_route (gpointer data, gpointer user_data)
{
	g_array_free ((GArray *) data, TRUE);
}

static GPtrArray *
read_ip4_routes (GKeyFile *file,
			 const char *setting_name,
			 const char *key)
{
	GPtrArray *routes;
	int i = 0;

	routes = g_ptr_array_sized_new (3);

	/* Look for individual routes */
	while (i++ < 1000) {
		gchar **tmp, **iter;
		char *key_name;
		gsize length = 0;
		int ret;
		GArray *route;
		int j;

		key_name = g_strdup_printf ("%s%d", key, i);
		tmp = g_key_file_get_string_list (file, setting_name, key_name, &length, NULL);
		g_free (key_name);

		if (!tmp || !length)
			break; /* all done */

		if (length != 4) {
			g_warning ("%s: ignoring invalid IPv4 route item '%s'", __func__, key_name);
			goto next;
		}

		/* convert the string array into IP addresses */
		route = g_array_sized_new (FALSE, TRUE, sizeof (guint32), 4);
		for (iter = tmp, j = 0; *iter; iter++, j++) {
			struct in_addr addr;

			if (j == 1) {
				guint32 prefix = 0;

				/* prefix */
				if (!get_one_int (*iter, 32, key_name, &prefix)) {
					g_array_free (route, TRUE);
					goto next;
				}

				g_array_append_val (route, prefix);
			} else if (j == 3) {
				guint32 metric = 0;

				/* metric */
				if (!get_one_int (*iter, G_MAXUINT32, key_name, &metric)) {
					g_array_free (route, TRUE);
					goto next;
				}

				g_array_append_val (route, metric);
			} else {
				/* address and next hop */
				ret = inet_pton (AF_INET, *iter, &addr);
				if (ret <= 0) {
					g_warning ("%s: ignoring invalid IPv4 %s element '%s'", __func__, key_name, *iter);
					g_array_free (route, TRUE);
					goto next;
				}
				g_array_append_val (route, addr.s_addr);
			}
		}
		g_ptr_array_add (routes, route);

next:
		g_strfreev (tmp);
	}

	if (routes->len < 1) {
		g_ptr_array_free (routes, TRUE);
		routes = NULL;
	}

	return routes;
}

static void
ip4_route_parser (NMSetting *setting, const char *key, GKeyFile *keyfile, const char *keyfile_path)
{
	GPtrArray *routes;
	const char *setting_name = nm_setting_get_name (setting);

	routes = read_ip4_routes (keyfile, setting_name, key);
	if (routes) {
		g_object_set (setting, key, routes, NULL);
		g_ptr_array_foreach (routes, free_one_ip4_route, NULL);
		g_ptr_array_free (routes, TRUE);
	}
}

static void
ip4_dns_parser (NMSetting *setting, const char *key, GKeyFile *keyfile, const char *keyfile_path)
{
	const char *setting_name = nm_setting_get_name (setting);
	GArray *array = NULL;
	gsize length;
	char **list, **iter;
	int ret;

	list = g_key_file_get_string_list (keyfile, setting_name, key, &length, NULL);
	if (!list || !g_strv_length (list))
		return;

	array = g_array_sized_new (FALSE, FALSE, sizeof (guint32), length);
	for (iter = list; *iter; iter++) {
		struct in_addr addr;

		ret = inet_pton (AF_INET, *iter, &addr);
		if (ret <= 0) {
			g_warning ("%s: ignoring invalid DNS server address '%s'", __func__, *iter);
			continue;
		}

		g_array_append_val (array, addr.s_addr);
	}
	g_strfreev (list);

	if (array) {
		g_object_set (setting, key, array, NULL);
		g_array_free (array, TRUE);
	}
}

static void
free_one_ip6_address (gpointer data, gpointer user_data)
{
	g_value_array_free ((GValueArray *) data);
}

static char *
split_prefix (char *addr)
{
	char *slash;

	g_return_val_if_fail (addr != NULL, NULL);

	/* Find the prefix and split the string */
	slash = strchr (addr, '/');
	if (slash && slash > addr) {
		slash++;
		*(slash - 1) = '\0';
	}

	return slash;
}

static char *
split_gw (char *str)
{
	char *comma;

	g_return_val_if_fail (str != NULL, NULL);

	/* Find the prefix and split the string */
	comma = strchr (str, ',');
	if (comma && comma > str) {
		comma++;
		*(comma - 1) = '\0';
		return comma;
	}
	return NULL;
}

static GPtrArray *
read_ip6_addresses (GKeyFile *file,
                    const char *setting_name,
                    const char *key)
{
	GPtrArray *addresses;
	struct in6_addr addr, gw;
	guint32 prefix;
	int i = 0;

	addresses = g_ptr_array_sized_new (3);

	/* Look for individual addresses */
	while (i++ < 1000) {
		char *tmp, *key_name, *str_prefix, *str_gw;
		int ret;
		GValueArray *values;
		GByteArray *address;
		GByteArray *gateway;
		GValue value = { 0 };

		key_name = g_strdup_printf ("%s%d", key, i);
		tmp = g_key_file_get_string (file, setting_name, key_name, NULL);
		g_free (key_name);

		if (!tmp)
			break; /* all done */

		/* convert the string array into IPv6 addresses */
		values = g_value_array_new (2); /* NMIP6Address has 2 items */

		/* Split the address and prefix */
		str_prefix = split_prefix (tmp);

		/* address */
		ret = inet_pton (AF_INET6, tmp, &addr);
		if (ret <= 0) {
			g_warning ("%s: ignoring invalid IPv6 %s element '%s'", __func__, key_name, tmp);
			g_value_array_free (values);
			goto next;
		}

		address = g_byte_array_new ();
		g_byte_array_append (address, (guint8 *) addr.s6_addr, 16);
		g_value_init (&value, DBUS_TYPE_G_UCHAR_ARRAY);
		g_value_take_boxed (&value, address);
		g_value_array_append (values, &value);
		g_value_unset (&value);

		/* prefix */
		prefix = 0;
		if (str_prefix) {
			if (!get_one_int (str_prefix, 128, key_name, &prefix)) {
				g_value_array_free (values);
				goto next;
			}
		} else {
			/* Missing prefix defaults to /64 */
			prefix = 64;
		}

		g_value_init (&value, G_TYPE_UINT);
		g_value_set_uint (&value, prefix);
		g_value_array_append (values, &value);
		g_value_unset (&value);

		/* Gateway (optional) */
		str_gw = split_gw (str_prefix);
		if (str_gw) {
			ret = inet_pton (AF_INET6, str_gw, &gw);
			if (ret <= 0) {
				g_warning ("%s: ignoring invalid IPv6 %s gateway '%s'", __func__, key_name, tmp);
				g_value_array_free (values);
				goto next;
			}

			if (!IN6_IS_ADDR_UNSPECIFIED (&gw)) {
				gateway = g_byte_array_new ();
				g_byte_array_append (gateway, (guint8 *) gw.s6_addr, 16);
				g_value_init (&value, DBUS_TYPE_G_UCHAR_ARRAY);
				g_value_take_boxed (&value, gateway);
				g_value_array_append (values, &value);
				g_value_unset (&value);
			}
		}

		g_ptr_array_add (addresses, values);

next:
		g_free (tmp);
	}

	if (addresses->len < 1) {
		g_ptr_array_free (addresses, TRUE);
		addresses = NULL;
	}

	return addresses;
}

static void
ip6_addr_parser (NMSetting *setting, const char *key, GKeyFile *keyfile, const char *keyfile_path)
{
	GPtrArray *addresses;
	const char *setting_name = nm_setting_get_name (setting);

	addresses = read_ip6_addresses (keyfile, setting_name, key);
	if (addresses) {
		g_object_set (setting, key, addresses, NULL);
		g_ptr_array_foreach (addresses, free_one_ip6_address, NULL);
		g_ptr_array_free (addresses, TRUE);
	}
}

static void
free_one_ip6_route (gpointer data, gpointer user_data)
{
	g_value_array_free ((GValueArray *) data);
}

static GPtrArray *
read_ip6_routes (GKeyFile *file,
                 const char *setting_name,
                 const char *key)
{
	GPtrArray *routes;
	struct in6_addr addr;
	guint32 prefix, metric;
	int i = 0;

	routes = g_ptr_array_sized_new (3);

	/* Look for individual routes */
	while (i++ < 1000) {
		gchar **tmp;
		char *key_name, *str_prefix;
		gsize length = 0;
		int ret;
		GValueArray *values;
		GByteArray *address;
		GValue value = { 0 };

		key_name = g_strdup_printf ("%s%d", key, i);
		tmp = g_key_file_get_string_list (file, setting_name, key_name, &length, NULL);
		g_free (key_name);

		if (!tmp || !length)
			break; /* all done */

		if (length != 3) {
			g_warning ("%s: ignoring invalid IPv6 address item '%s'", __func__, key_name);
			goto next;
		}

		/* convert the string array into IPv6 routes */
		values = g_value_array_new (4); /* NMIP6Route has 4 items */

		/* Split the route and prefix */
		str_prefix = split_prefix (tmp[0]);

		/* destination address */
		ret = inet_pton (AF_INET6, tmp[0], &addr);
		if (ret <= 0) {
			g_warning ("%s: ignoring invalid IPv6 %s element '%s'", __func__, key_name, tmp[0]);
			g_value_array_free (values);
			goto next;
		}
		address = g_byte_array_new ();
		g_byte_array_append (address, (guint8 *) addr.s6_addr, 16);
		g_value_init (&value, DBUS_TYPE_G_UCHAR_ARRAY);
		g_value_take_boxed (&value, address);
		g_value_array_append (values, &value);
		g_value_unset (&value);

		/* prefix */
		prefix = 0;
		if (str_prefix) {
			if (!get_one_int (str_prefix, 128, key_name, &prefix)) {
				g_value_array_free (values);
				goto next;
			}
		} else {
			/* default to 64 if unspecified */
			prefix = 64;
		}
		g_value_init (&value, G_TYPE_UINT);
		g_value_set_uint (&value, prefix);
		g_value_array_append (values, &value);
		g_value_unset (&value);

		/* next hop address */
		ret = inet_pton (AF_INET6, tmp[1], &addr);
		if (ret <= 0) {
			g_warning ("%s: ignoring invalid IPv6 %s element '%s'", __func__, key_name, tmp[1]);
			g_value_array_free (values);
			goto next;
		}
		address = g_byte_array_new ();
		g_byte_array_append (address, (guint8 *) addr.s6_addr, 16);
		g_value_init (&value, DBUS_TYPE_G_UCHAR_ARRAY);
		g_value_take_boxed (&value, address);
		g_value_array_append (values, &value);
		g_value_unset (&value);

		/* metric */
		metric = 0;
		if (!get_one_int (tmp[2], G_MAXUINT32, key_name, &metric)) {
			g_value_array_free (values);
			goto next;
		}
		g_value_init (&value, G_TYPE_UINT);
		g_value_set_uint (&value, metric);
		g_value_array_append (values, &value);
		g_value_unset (&value);

		g_ptr_array_add (routes, values);

next:
		g_strfreev (tmp);
	}

	if (routes->len < 1) {
		g_ptr_array_free (routes, TRUE);
		routes = NULL;
	}

	return routes;
}

static void
ip6_route_parser (NMSetting *setting, const char *key, GKeyFile *keyfile, const char *keyfile_path)
{
	GPtrArray *routes;
	const char *setting_name = nm_setting_get_name (setting);

	routes = read_ip6_routes (keyfile, setting_name, key);

	if (routes) {
		g_object_set (setting, key, routes, NULL);
		g_ptr_array_foreach (routes, free_one_ip6_route, NULL);
		g_ptr_array_free (routes, TRUE);
	}
}

static void
free_one_ip6_dns (gpointer data, gpointer user_data)
{
	g_byte_array_free ((GByteArray *) data, TRUE);
}

static void
ip6_dns_parser (NMSetting *setting, const char *key, GKeyFile *keyfile, const char *keyfile_path)
{
	const char *setting_name = nm_setting_get_name (setting);
	GPtrArray *array = NULL;
	gsize length;
	char **list, **iter;
	int ret;

	list = g_key_file_get_string_list (keyfile, setting_name, key, &length, NULL);
	if (!list || !g_strv_length (list))
		return;

	array = g_ptr_array_sized_new (length);
	for (iter = list; *iter; iter++) {
		GByteArray *byte_array;
		struct in6_addr addr;

		ret = inet_pton (AF_INET6, *iter, &addr);
		if (ret <= 0) {
			g_warning ("%s: ignoring invalid DNS server IPv6 address '%s'", __func__, *iter);
			continue;
		}
		byte_array = g_byte_array_new ();
		g_byte_array_append (byte_array, (guint8 *) addr.s6_addr, 16);

		g_ptr_array_add (array, byte_array);
	}
	g_strfreev (list);

	if (array) {
		g_object_set (setting, key, array, NULL);
		g_ptr_array_foreach (array, free_one_ip6_dns, NULL);
		g_ptr_array_free (array, TRUE);
	}
}

static void
mac_address_parser (NMSetting *setting, const char *key, GKeyFile *keyfile, const char *keyfile_path)
{
	const char *setting_name = nm_setting_get_name (setting);
	struct ether_addr *eth;
	char *tmp_string = NULL, *p;
	gint *tmp_list;
	GByteArray *array = NULL;
	gsize length;
	int i;

	p = tmp_string = g_key_file_get_string (keyfile, setting_name, key, NULL);
	if (tmp_string) {
		/* Look for enough ':' characters to signify a MAC address */
		i = 0;
		while (*p) {
			if (*p == ':')
				i++;
			p++;
		}
		if (i == 5) {
			/* parse as a MAC address */
			eth = ether_aton (tmp_string);
			if (eth) {
				g_free (tmp_string);
				array = g_byte_array_sized_new (ETH_ALEN);
				g_byte_array_append (array, eth->ether_addr_octet, ETH_ALEN);
				goto done;
			}
		}
	}
	g_free (tmp_string);

	/* Old format; list of ints */
	tmp_list = g_key_file_get_integer_list (keyfile, setting_name, key, &length, NULL);
	array = g_byte_array_sized_new (length);
	for (i = 0; i < length; i++) {
		int val = tmp_list[i];
		unsigned char v = (unsigned char) (val & 0xFF);

		if (val < 0 || val > 255) {
			g_warning ("%s: %s / %s ignoring invalid byte element '%d' (not "
			           " between 0 and 255 inclusive)", __func__, setting_name,
			           key, val);
		} else
			g_byte_array_append (array, (const unsigned char *) &v, sizeof (v));
	}
	g_free (tmp_list);

done:
	if (array->len == ETH_ALEN) {
		g_object_set (setting, key, array, NULL);
	} else {
		g_warning ("%s: ignoring invalid MAC address for %s / %s",
		           __func__, setting_name, key);
	}
	g_byte_array_free (array, TRUE);
}

static void
read_hash_of_string (GKeyFile *file, NMSetting *setting, const char *key)
{
	char **keys, **iter;
	char *value;
	const char *setting_name = nm_setting_get_name (setting);

	keys = g_key_file_get_keys (file, setting_name, NULL, NULL);
	if (!keys || !*keys)
		return;

	for (iter = keys; *iter; iter++) {
		value = g_key_file_get_string (file, setting_name, *iter, NULL);
		if (!value)
			continue;

		if (NM_IS_SETTING_VPN (setting)) {
			if (strcmp (*iter, NM_SETTING_VPN_SERVICE_TYPE))
				nm_setting_vpn_add_data_item (NM_SETTING_VPN (setting), *iter, value);
		}
		g_free (value);
	}
	g_strfreev (keys);
}

static GByteArray *
get_uchar_array (GKeyFile *keyfile,
                 const char *setting_name,
                 const char *key)
{
	GByteArray *array = NULL;
	char *p, *tmp_string;
	gint *tmp_list;
	gsize length;
	int i;

	/* New format: just a string.  We try parsing the new format if there are
	 * no ';' in the string or it's not just numbers.
	 */
	p = tmp_string = g_key_file_get_string (keyfile, setting_name, key, NULL);
	if (tmp_string) {
		gboolean new_format = FALSE;

		if (strchr (p, ';') == NULL)
			new_format = TRUE;
		else {
			new_format = TRUE;
			while (p && *p) {
				if (!isdigit (*p++)) {
					new_format = FALSE;
					break;
				}
			}
		}

		if (new_format) {
			array = g_byte_array_sized_new (strlen (tmp_string));
			g_byte_array_append (array, (guint8 *) tmp_string, strlen (tmp_string));
		}
		g_free (tmp_string);
	}

	if (!array) {
		/* Old format; list of ints */
		tmp_list = g_key_file_get_integer_list (keyfile, setting_name, key, &length, NULL);
		array = g_byte_array_sized_new (length);
		for (i = 0; i < length; i++) {
			int val = tmp_list[i];
			unsigned char v = (unsigned char) (val & 0xFF);

			if (val < 0 || val > 255) {
				g_warning ("%s: %s / %s ignoring invalid byte element '%d' (not "
					       " between 0 and 255 inclusive)", __func__, setting_name,
					       key, val);
			} else
				g_byte_array_append (array, (const unsigned char *) &v, sizeof (v));
		}
		g_free (tmp_list);
	}

	if (array->len == 0) {
		g_byte_array_free (array, TRUE);
		array = NULL;
	}
	return array;
}

static void
ssid_parser (NMSetting *setting, const char *key, GKeyFile *keyfile, const char *keyfile_path)
{
	const char *setting_name = nm_setting_get_name (setting);
	GByteArray *array;

	array = get_uchar_array (keyfile, setting_name, key);
	if (array) {
		g_object_set (setting, key, array, NULL);
		g_byte_array_free (array, TRUE);
	} else {
		g_warning ("%s: ignoring invalid SSID for %s / %s",
		           __func__, setting_name, key);
	}
}

static char *
get_cert_path (const char *keyfile_path, GByteArray *cert_path)
{
	const char *base;
	char *p = NULL, *path, *dirname, *tmp;

	g_return_val_if_fail (keyfile_path != NULL, NULL);
	g_return_val_if_fail (cert_path != NULL, NULL);

	base = path = g_malloc0 (cert_path->len + 1);
	memcpy (path, cert_path->data, cert_path->len);

	if (path[0] == '/')
		return path;

	p = strrchr (path, '/');
	if (p)
		base = p + 1;

	dirname = g_path_get_dirname (keyfile_path);
	tmp = g_build_path ("/", dirname, base, NULL);
	g_free (dirname);
	g_free (path);
	return tmp;
}

#define SCHEME_PATH "file://"

static void
cert_parser (NMSetting *setting, const char *key, GKeyFile *keyfile, const char *keyfile_path)
{
	const char *setting_name = nm_setting_get_name (setting);
	GByteArray *array;
	gboolean success = FALSE;

	array = get_uchar_array (keyfile, setting_name, key);
	if (array) {
		/* Value could be either:
		 * 1) the raw key/cert data as a blob
		 * 2) a path scheme (ie, starts with "file://")
		 * 3) a plain path
		 */
		if (   (array->len > strlen (SCHEME_PATH))
		    && g_str_has_prefix ((const char *) array->data, SCHEME_PATH)
		    && (array->data[array->len - 1] == '\0')) {
			/* It's the PATH scheme, can just set plain data */
			g_object_set (setting, key, array, NULL);
			success = TRUE;
		} else if (   (array->len < 500)
		           && g_utf8_validate ((const char *) array->data, array->len, NULL)) {
			GByteArray *val;
			char *path;

			path = get_cert_path (keyfile_path, array);
			if (g_file_test (path, G_FILE_TEST_EXISTS)) {
				/* Construct the proper value as required for the PATH scheme */
				val = g_byte_array_sized_new (strlen (SCHEME_PATH) + array->len + 1);
				g_byte_array_append (val, (const guint8 *) SCHEME_PATH, strlen (SCHEME_PATH));
				g_byte_array_append (val, array->data, array->len);
				g_byte_array_append (val, (const guint8 *) "\0", 1);
				g_object_set (setting, key, val, NULL);
				g_byte_array_free (val, TRUE);
				success = TRUE;
			}
			g_free (path);
		}

		if (!success) {
			/* Assume it's a simple blob value of the certificate or private key's data */
			g_object_set (setting, key, array, NULL);
		}

		g_byte_array_free (array, TRUE);
	} else {
		g_warning ("%s: ignoring invalid SSID for %s / %s",
		           __func__, setting_name, key);
	}
}

typedef struct {
	const char *setting_name;
	const char *key;
	gboolean check_for_key;
	void (*parser) (NMSetting *setting, const char *key, GKeyFile *keyfile, const char *keyfile_path);
} KeyParser;

/* A table of keys that require further parsing/conversion because they are
 * stored in a format that can't be automatically read using the key's type.
 * i.e. IPv4 addresses, which are stored in NetworkManager as guint32, but are
 * stored in keyfiles as strings, eg "10.1.1.2" or IPv6 addresses stored 
 * in struct in6_addr internally, but as string in keyfiles.
 */
static KeyParser key_parsers[] = {
	{ NM_SETTING_IP4_CONFIG_SETTING_NAME,
	  NM_SETTING_IP4_CONFIG_ADDRESSES,
	  FALSE,
	  ip4_addr_parser },
	{ NM_SETTING_IP6_CONFIG_SETTING_NAME,
	  NM_SETTING_IP6_CONFIG_ADDRESSES,
	  FALSE,
	  ip6_addr_parser },
	{ NM_SETTING_IP4_CONFIG_SETTING_NAME,
	  NM_SETTING_IP4_CONFIG_ROUTES,
	  FALSE,
	  ip4_route_parser },
	{ NM_SETTING_IP6_CONFIG_SETTING_NAME,
	  NM_SETTING_IP6_CONFIG_ROUTES,
	  FALSE,
	  ip6_route_parser },
	{ NM_SETTING_IP4_CONFIG_SETTING_NAME,
	  NM_SETTING_IP4_CONFIG_DNS,
	  FALSE,
	  ip4_dns_parser },
	{ NM_SETTING_IP6_CONFIG_SETTING_NAME,
	  NM_SETTING_IP6_CONFIG_DNS,
	  FALSE,
	  ip6_dns_parser },
	{ NM_SETTING_WIRED_SETTING_NAME,
	  NM_SETTING_WIRED_MAC_ADDRESS,
	  TRUE,
	  mac_address_parser },
	{ NM_SETTING_WIRED_SETTING_NAME,
	  NM_SETTING_WIRED_CLONED_MAC_ADDRESS,
	  TRUE,
	  mac_address_parser },
	{ NM_SETTING_WIRELESS_SETTING_NAME,
	  NM_SETTING_WIRELESS_MAC_ADDRESS,
	  TRUE,
	  mac_address_parser },
	{ NM_SETTING_WIRELESS_SETTING_NAME,
	  NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS,
	  TRUE,
	  mac_address_parser },
	{ NM_SETTING_WIRELESS_SETTING_NAME,
	  NM_SETTING_WIRELESS_BSSID,
	  TRUE,
	  mac_address_parser },
	{ NM_SETTING_BLUETOOTH_SETTING_NAME,
	  NM_SETTING_BLUETOOTH_BDADDR,
	  TRUE,
	  mac_address_parser },
	{ NM_SETTING_WIRELESS_SETTING_NAME,
	  NM_SETTING_WIRELESS_SSID,
	  TRUE,
	  ssid_parser },
	{ NM_SETTING_802_1X_SETTING_NAME,
	  NM_SETTING_802_1X_CA_CERT,
	  TRUE,
	  cert_parser },
	{ NM_SETTING_802_1X_SETTING_NAME,
	  NM_SETTING_802_1X_CLIENT_CERT,
	  TRUE,
	  cert_parser },
	{ NM_SETTING_802_1X_SETTING_NAME,
	  NM_SETTING_802_1X_PRIVATE_KEY,
	  TRUE,
	  cert_parser },
	{ NM_SETTING_802_1X_SETTING_NAME,
	  NM_SETTING_802_1X_PHASE2_CA_CERT,
	  TRUE,
	  cert_parser },
	{ NM_SETTING_802_1X_SETTING_NAME,
	  NM_SETTING_802_1X_PHASE2_CLIENT_CERT,
	  TRUE,
	  cert_parser },
	{ NM_SETTING_802_1X_SETTING_NAME,
	  NM_SETTING_802_1X_PHASE2_PRIVATE_KEY,
	  TRUE,
	  cert_parser },
	{ NULL, NULL, FALSE }
};

typedef struct {
	GKeyFile *keyfile;
	const char *keyfile_path;
} ReadInfo;

static void
read_one_setting_value (NMSetting *setting,
                        const char *key,
                        const GValue *value,
                        GParamFlags flags,
                        gpointer user_data)
{
	ReadInfo *info = user_data;
	const char *setting_name;
	GType type;
	GError *err = NULL;
	gboolean check_for_key = TRUE;
	KeyParser *parser = &key_parsers[0];

	/* Property is not writable */
	if (!(flags & G_PARAM_WRITABLE))
		return;

	/* Setting name gets picked up from the keyfile's section name instead */
	if (!strcmp (key, NM_SETTING_NAME))
		return;

	/* Don't read the NMSettingConnection object's 'read-only' property */
	if (   NM_IS_SETTING_CONNECTION (setting)
	    && !strcmp (key, NM_SETTING_CONNECTION_READ_ONLY))
		return;

	setting_name = nm_setting_get_name (setting);

	/* Look through the list of handlers for non-standard format key values */
	while (parser->setting_name) {
		if (!strcmp (parser->setting_name, setting_name) && !strcmp (parser->key, key)) {
			check_for_key = parser->check_for_key;
			break;
		}
		parser++;
	}

	/* VPN properties don't have the exact key name */
	if (NM_IS_SETTING_VPN (setting))
		check_for_key = FALSE;

	/* Check for the exact key in the GKeyFile if required.  Most setting
	 * properties map 1:1 to a key in the GKeyFile, but for those properties
	 * like IP addresses and routes where more than one value is actually
	 * encoded by the setting property, this won't be true.
	 */
	if (check_for_key && !g_key_file_has_key (info->keyfile, setting_name, key, &err)) {
		/* Key doesn't exist or an error ocurred, thus nothing to do. */
		if (err) {
			g_warning ("Error loading setting '%s' value: %s", setting_name, err->message);
			g_error_free (err);
		}
		return;
	}

	/* If there's a custom parser for this key, handle that before the generic
	 * parsers below.
	 */
	if (parser && parser->setting_name) {
		(*parser->parser) (setting, key, info->keyfile, info->keyfile_path);
		return;
	}

	type = G_VALUE_TYPE (value);

	if (type == G_TYPE_STRING) {
		char *str_val;

		str_val = g_key_file_get_string (info->keyfile, setting_name, key, NULL);
		g_object_set (setting, key, str_val, NULL);
		g_free (str_val);
	} else if (type == G_TYPE_UINT) {
		int int_val;

		int_val = g_key_file_get_integer (info->keyfile, setting_name, key, NULL);
		if (int_val < 0)
			g_warning ("Casting negative value (%i) to uint", int_val);
		g_object_set (setting, key, int_val, NULL);
	} else if (type == G_TYPE_INT) {
		int int_val;

		int_val = g_key_file_get_integer (info->keyfile, setting_name, key, NULL);
		g_object_set (setting, key, int_val, NULL);
	} else if (type == G_TYPE_BOOLEAN) {
		gboolean bool_val;

		bool_val = g_key_file_get_boolean (info->keyfile, setting_name, key, NULL);
		g_object_set (setting, key, bool_val, NULL);
	} else if (type == G_TYPE_CHAR) {
		int int_val;

		int_val = g_key_file_get_integer (info->keyfile, setting_name, key, NULL);
		if (int_val < G_MININT8 || int_val > G_MAXINT8)
			g_warning ("Casting value (%i) to char", int_val);

		g_object_set (setting, key, int_val, NULL);
	} else if (type == G_TYPE_UINT64) {
		char *tmp_str;
		guint64 uint_val;

		tmp_str = g_key_file_get_value (info->keyfile, setting_name, key, NULL);
		uint_val = g_ascii_strtoull (tmp_str, NULL, 10);
		g_free (tmp_str);
		g_object_set (setting, key, uint_val, NULL);
 	} else if (type == DBUS_TYPE_G_UCHAR_ARRAY) {
		gint *tmp;
		GByteArray *array;
		gsize length;
		int i;

		tmp = g_key_file_get_integer_list (info->keyfile, setting_name, key, &length, NULL);

		array = g_byte_array_sized_new (length);
		for (i = 0; i < length; i++) {
			int val = tmp[i];
			unsigned char v = (unsigned char) (val & 0xFF);

			if (val < 0 || val > 255) {
				g_warning ("%s: %s / %s ignoring invalid byte element '%d' (not "
				           " between 0 and 255 inclusive)", __func__, setting_name,
				           key, val);
			} else
				g_byte_array_append (array, (const unsigned char *) &v, sizeof (v));
		}

		g_object_set (setting, key, array, NULL);
		g_byte_array_free (array, TRUE);
		g_free (tmp);
 	} else if (type == DBUS_TYPE_G_LIST_OF_STRING) {
		gchar **sa;
		gsize length;
		int i;
		GSList *list = NULL;

		sa = g_key_file_get_string_list (info->keyfile, setting_name, key, &length, NULL);
		for (i = 0; i < length; i++)
			list = g_slist_prepend (list, sa[i]);

		list = g_slist_reverse (list);
		g_object_set (setting, key, list, NULL);

		g_slist_free (list);
		g_strfreev (sa);
	} else if (type == DBUS_TYPE_G_MAP_OF_STRING) {
		read_hash_of_string (info->keyfile, setting, key);
	} else if (type == DBUS_TYPE_G_UINT_ARRAY) {
		if (!read_array_of_uint (info->keyfile, setting, key)) {
			g_warning ("Unhandled setting property type (read): '%s/%s' : '%s'",
					 setting_name, key, G_VALUE_TYPE_NAME (value));
		}
	} else {
		g_warning ("Unhandled setting property type (read): '%s/%s' : '%s'",
				 setting_name, key, G_VALUE_TYPE_NAME (value));
	}
}

static NMSetting *
read_setting (GKeyFile *file, const char *keyfile_path, const char *setting_name)
{
	NMSetting *setting;
	ReadInfo info = { file, keyfile_path };

	setting = nm_connection_create_setting (setting_name);
	if (setting)
		nm_setting_enumerate_values (setting, read_one_setting_value, &info);
	else
		g_warning ("Invalid setting name '%s'", setting_name);

	return setting;
}

static void
read_vpn_secrets (GKeyFile *file, NMSettingVPN *s_vpn)
{
	char **keys, **iter;

	keys = g_key_file_get_keys (file, VPN_SECRETS_GROUP, NULL, NULL);
	for (iter = keys; *iter; iter++) {
		char *secret;

		secret = g_key_file_get_string (file, VPN_SECRETS_GROUP, *iter, NULL);
		if (secret) {
			nm_setting_vpn_add_secret (s_vpn, *iter, secret);
			g_free (secret);
		}
	}
	g_strfreev (keys);
}

NMConnection *
nm_keyfile_plugin_connection_from_file (const char *filename, GError **error)
{
	GKeyFile *key_file;
	struct stat statbuf;
	gboolean bad_owner, bad_permissions;
	NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSetting *setting;
	gchar **groups;
	gsize length;
	int i;
	gboolean vpn_secrets = FALSE;
	const char *ctype;
	GError *verify_error = NULL;

	if (stat (filename, &statbuf) != 0 || !S_ISREG (statbuf.st_mode)) {
		g_set_error_literal (error, KEYFILE_PLUGIN_ERROR, 0,
		                     "File did not exist or was not a regular file");
		return NULL;
	}

	bad_owner = getuid () != statbuf.st_uid;
	bad_permissions = statbuf.st_mode & 0077;

	if (bad_owner || bad_permissions) {
		g_set_error (error, KEYFILE_PLUGIN_ERROR, 0,
		             "File permissions (%o) or owner (%d) were insecure",
		             statbuf.st_mode, statbuf.st_uid);
		return NULL;
	}

	key_file = g_key_file_new ();
	if (!g_key_file_load_from_file (key_file, filename, G_KEY_FILE_NONE, error))
		goto out;

	connection = nm_connection_new ();

	groups = g_key_file_get_groups (key_file, &length);
	for (i = 0; i < length; i++) {
		/* Only read out secrets when needed */
		if (!strcmp (groups[i], VPN_SECRETS_GROUP)) {
			vpn_secrets = TRUE;
			continue;
		}

		setting = read_setting (key_file, filename, groups[i]);
		if (setting)
			nm_connection_add_setting (connection, setting);
	}

	/* Make sure that we have the base device type setting even if
	 * the keyfile didn't include it, which can happen when the base
	 * device type setting is all default values (like ethernet).
	 */
	s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
	if (s_con) {
		ctype = nm_setting_connection_get_connection_type (s_con);
		setting = nm_connection_get_setting_by_name (connection, ctype);
		if (ctype) {
			if (!setting && !strcmp (ctype, NM_SETTING_WIRED_SETTING_NAME))
				nm_connection_add_setting (connection, nm_setting_wired_new ());
		}
	}

	/* Handle vpn secrets after the 'vpn' setting was read */
	if (vpn_secrets) {
		NMSettingVPN *s_vpn;

		s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);
		if (s_vpn)
			read_vpn_secrets (key_file, s_vpn);
	}

	g_strfreev (groups);

	/* Verify the connection */
	if (!nm_connection_verify (connection, &verify_error)) {
		g_set_error (error, KEYFILE_PLUGIN_ERROR, 0,
			         "invalid or missing connection property '%s'",
			         (verify_error && verify_error->message) ? verify_error->message : "(unknown)");
		g_clear_error (&verify_error);
		g_object_unref (connection);
		connection = NULL;
	}

out:
	g_key_file_free (key_file);
	return connection;
}
