/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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
 * Copyright (C) 2011 Red Hat, Inc.
 *
 */

#include <config.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <glib-object.h>

#include "nm-connection.h"
#include "nm-setting-connection.h"
#include "nm-dispatcher-utils.h"
#include "nm-dbus-glib-types.h"
#include "nm-dispatcher-api.h"
#include "nm-utils.h"

/*******************************************/

static void
value_destroy (gpointer data)
{
	GValue *value = (GValue *) data;

	g_value_unset (value);
	g_slice_free (GValue, value);
}

static GHashTable *
value_hash_create (void)
{
	return g_hash_table_new_full (g_str_hash, g_str_equal, g_free, value_destroy);
}

static void
value_hash_add (GHashTable *hash,
				const char *key,
				GValue *value)
{
	g_hash_table_insert (hash, g_strdup (key), value);
}

static void
value_hash_add_string (GHashTable *hash,
					   const char *key,
					   const char *str)
{
	GValue *value;

	value = g_slice_new0 (GValue);
	g_value_init (value, G_TYPE_STRING);
	g_value_set_string (value, str);

	value_hash_add (hash, key, value);
}

static void
value_hash_add_object_path (GHashTable *hash,
							const char *key,
							const char *op)
{
	GValue *value;

	value = g_slice_new0 (GValue);
	g_value_init (value, DBUS_TYPE_G_OBJECT_PATH);
	g_value_set_boxed (value, op);

	value_hash_add (hash, key, value);
}

static void
value_hash_add_uint (GHashTable *hash,
					 const char *key,
					 guint32 val)
{
	GValue *value;

	value = g_slice_new0 (GValue);
	g_value_init (value, G_TYPE_UINT);
	g_value_set_uint (value, val);

	value_hash_add (hash, key, value);
}

static void
value_hash_add_strv (GHashTable *hash,
                     const char *key,
                     char **strv)
{
	GValue *value;

	value = g_slice_new0 (GValue);
	g_value_init (value, G_TYPE_STRV);
	g_value_take_boxed (value, strv);
	value_hash_add (hash, key, value);
}

static void
value_hash_add_uint_array (GHashTable *hash,
					       const char *key,
					       GArray *array)
{
	GValue *value;

	value = g_slice_new0 (GValue);
	g_value_init (value, DBUS_TYPE_G_UINT_ARRAY);
	g_value_take_boxed (value, array);
	value_hash_add (hash, key, value);
}

static gboolean
parse_main (GKeyFile *kf,
            GHashTable **out_con_hash,
            GHashTable **out_con_props,
            char **out_expected_iface,
            char **out_action,
            char **out_vpn_ip_iface,
            GError **error)
{
	char *uuid, *id;
	NMConnection *connection;
	NMSettingConnection *s_con;

	*out_expected_iface = g_key_file_get_string (kf, "main", "expected-iface", error);
	if (*out_expected_iface == NULL)
		return FALSE;

	*out_vpn_ip_iface = g_key_file_get_string (kf, "main", "vpn-ip-iface", NULL);

	*out_action = g_key_file_get_string (kf, "main", "action", error);
	if (*out_action == NULL)
		return FALSE;

	uuid = g_key_file_get_string (kf, "main", "uuid", error);
	if (uuid == NULL)
		return FALSE;
	id = g_key_file_get_string (kf, "main", "id", error);
	if (id == NULL)
		return FALSE;

	connection = nm_connection_new ();
	g_assert (connection);
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	g_assert (s_con);
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_ID, id,
	              NULL);
	g_free (uuid);
	g_free (id);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	*out_con_hash = nm_connection_to_hash (connection, NM_SETTING_HASH_FLAG_ALL);
	g_object_unref (connection);

	*out_con_props = value_hash_create ();
	value_hash_add_object_path (*out_con_props, "connection-path", "/org/freedesktop/NetworkManager/Connections/5");

	return TRUE;
}

static gboolean
parse_device (GKeyFile *kf, GHashTable **out_device_props, GError **error)
{
	char *tmp;
	gint i;

	*out_device_props = value_hash_create ();

	i = g_key_file_get_integer (kf, "device", "state", error);
	if (i == 0)
		return FALSE;
	value_hash_add_uint (*out_device_props, NMD_DEVICE_PROPS_STATE, (guint) i);

	i = g_key_file_get_integer (kf, "device", "type", error);
	if (i == 0)
		return FALSE;
	value_hash_add_uint (*out_device_props, NMD_DEVICE_PROPS_TYPE, (guint) i);

	tmp = g_key_file_get_string (kf, "device", "interface", error);
	if (tmp == NULL)
		return FALSE;
	value_hash_add_string (*out_device_props, NMD_DEVICE_PROPS_INTERFACE, tmp);
	g_free (tmp);

	tmp = g_key_file_get_string (kf, "device", "ip-interface", error);
	if (tmp == NULL)
		return FALSE;
	value_hash_add_string (*out_device_props, NMD_DEVICE_PROPS_IP_INTERFACE, tmp);
	g_free (tmp);

	tmp = g_key_file_get_string (kf, "device", "path", error);
	if (tmp == NULL)
		return FALSE;
	value_hash_add_object_path (*out_device_props, NMD_DEVICE_PROPS_PATH, tmp);
	g_free (tmp);

	return TRUE;
}

static gboolean
add_uint_array (GKeyFile *kf,
                GHashTable *props,
                const char *section,
                const char *key,
                GError **error)
{
	char *tmp;
	char **split, **iter;
	GArray *items;

	tmp = g_key_file_get_string (kf, section, key, error);
	if (tmp == NULL) {
		g_clear_error (error);
		return TRUE;
	}
	split = g_strsplit_set (tmp, " ", -1);
	g_free (tmp);

	if (g_strv_length (split) > 0) {
		items = g_array_sized_new (FALSE, TRUE, sizeof (guint32), g_strv_length (split));
		for (iter = split; iter && *iter; iter++) {
			if (strlen (g_strstrip (*iter))) {
				guint32 addr;

				g_assert_cmpint (inet_pton (AF_INET, *iter, &addr), ==, 1);
				g_array_append_val (items, addr);
			}
		}
		value_hash_add_uint_array (props, key, items);
	}
	g_strfreev (split);
	return TRUE;
}

static gboolean
parse_ip4 (GKeyFile *kf, GHashTable **out_props, const char *section, GError **error)
{
	char *tmp;
	char **split, **iter;
	GSList *list;
	GValue *val;

	*out_props = value_hash_create ();

	/* search domains */
	/* Use char** for domains. (DBUS_TYPE_G_ARRAY_OF_STRING of NMIP4Config
	 * becomes G_TYPE_STRV when sending the value over D-Bus)
	 */
	tmp = g_key_file_get_string (kf, section, "domains", error);
	if (tmp == NULL)
		return FALSE;
	split = g_strsplit_set (tmp, " ", -1);
	g_free (tmp);

	if (g_strv_length (split) > 0) {
		for (iter = split; iter && *iter; iter++)
			g_strstrip (*iter);
		value_hash_add_strv (*out_props, "domains", split);
	}

	/* nameservers */
	if (!add_uint_array (kf, *out_props, "ip4", "nameservers", error))
		return FALSE;
	/* wins-servers */
	if (!add_uint_array (kf, *out_props, "ip4", "wins-servers", error))
		return FALSE;

	/* Addresses */
	tmp = g_key_file_get_string (kf, section, "addresses", error);
	if (tmp == NULL)
		return FALSE;
	split = g_strsplit_set (tmp, ",", -1);
	g_free (tmp);

	if (g_strv_length (split) > 0) {
		list = NULL;
		for (iter = split; iter && *iter; iter++) {
			NMIP4Address *addr;
			guint32 a;
			char *p;

			if (strlen (g_strstrip (*iter)) == 0)
				continue;

			addr = nm_ip4_address_new ();

			p = strchr (*iter, '/');
			g_assert (p);
			*p++ = '\0';

			g_assert_cmpint (inet_pton (AF_INET, *iter, &a), ==, 1);
			nm_ip4_address_set_address (addr, a);
			nm_ip4_address_set_prefix (addr, (guint) atoi (p));

			p = strchr (p, ' ');
			g_assert (p);
			p++;

			g_assert_cmpint (inet_pton (AF_INET, p, &a), ==, 1);
			nm_ip4_address_set_gateway (addr, a);

			list = g_slist_append (list, addr);
		}

		val = g_slice_new0 (GValue);
		g_value_init (val, DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UINT);
		nm_utils_ip4_addresses_to_gvalue (list, val);
		value_hash_add (*out_props, "addresses", val);
	}
	g_strfreev (split);

	/* Routes */
	tmp = g_key_file_get_string (kf, section, "routes", error);
	g_clear_error (error);
	if (tmp) {
		split = g_strsplit_set (tmp, ",", -1);
		g_free (tmp);

		if (g_strv_length (split) > 0) {
			list = NULL;
			for (iter = split; iter && *iter; iter++) {
				NMIP4Route *route;
				guint32 a;
				char *p;

				if (strlen (g_strstrip (*iter)) == 0)
					continue;

				route = nm_ip4_route_new ();

				p = strchr (*iter, '/');
				g_assert (p);
				*p++ = '\0';

				g_assert_cmpint (inet_pton (AF_INET, *iter, &a), ==, 1);
				nm_ip4_route_set_dest (route, a);
				nm_ip4_route_set_prefix (route, (guint) atoi (p));

				p = strchr (p, ' ');
				g_assert (p);
				p++;

				g_assert_cmpint (inet_pton (AF_INET, p, &a), ==, 1);
				nm_ip4_route_set_next_hop (route, a);

				p = strchr (p, ' ');
				g_assert (p);
				p++;
				nm_ip4_route_set_metric (route, (guint) atoi (p));

				list = g_slist_append (list, route);
			}

			val = g_slice_new0 (GValue);
			g_value_init (val, DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UINT);
			nm_utils_ip4_routes_to_gvalue (list, val);
			value_hash_add (*out_props, "routes", val);
		}
		g_strfreev (split);
	}

	return TRUE;
}

static gboolean
parse_dhcp (GKeyFile *kf,
            const char *group_name,
            GHashTable **out_props,
            GError **error)
{
	char **keys, **iter, *val;

	keys = g_key_file_get_keys (kf, group_name, NULL, error);
	if (!keys)
		return FALSE;

	*out_props = value_hash_create ();
	for (iter = keys; iter && *iter; iter++) {
		val = g_key_file_get_string (kf, group_name, *iter, error);
		if (!val)
			return FALSE;
		value_hash_add_string (*out_props, *iter, val);
		g_free (val);
	}

	return TRUE;
}

static gboolean
get_dispatcher_file (const char *file,
                     GHashTable **out_con_hash,
                     GHashTable **out_con_props,
                     GHashTable **out_device_props,
                     GHashTable **out_device_ip4_props,
                     GHashTable **out_device_ip6_props,
                     GHashTable **out_device_dhcp4_props,
                     GHashTable **out_device_dhcp6_props,
                     char **out_vpn_ip_iface,
                     GHashTable **out_vpn_ip4_props,
                     GHashTable **out_vpn_ip6_props,
                     char **out_expected_iface,
                     char **out_action,
                     GHashTable **out_env,
                     GError **error)
{
	GKeyFile *kf;
	gboolean success = FALSE;
	char **keys, **iter, *val;

	kf = g_key_file_new ();
	if (!g_key_file_load_from_file (kf, file, G_KEY_FILE_NONE, error))
		return FALSE;

	if (!parse_main (kf,
	                 out_con_hash,
	                 out_con_props,
	                 out_expected_iface,
	                 out_action,
	                 out_vpn_ip_iface,
	                 error))
		goto out;

	if (!parse_device (kf, out_device_props, error))
		goto out;

	if (g_key_file_has_group (kf, "ip4")) {
		if (!parse_ip4 (kf, out_device_ip4_props, "ip4", error))
			goto out;
	}

	if (g_key_file_has_group (kf, "dhcp4")) {
		if (!parse_dhcp (kf, "dhcp4", out_device_dhcp4_props, error))
			goto out;
	}

	if (g_key_file_has_group (kf, "dhcp6")) {
		if (!parse_dhcp (kf, "dhcp6", out_device_dhcp4_props, error))
			goto out;
	}

	g_assert (g_key_file_has_group (kf, "env"));
	keys = g_key_file_get_keys (kf, "env", NULL, error);
	*out_env = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
	for (iter = keys; iter && *iter; iter++) {
		val = g_key_file_get_string (kf, "env", *iter, error);
		if (!val)
			goto out;
		g_hash_table_insert (*out_env,
		                     g_strdup_printf ("%s=%s", *iter, val),
		                     GUINT_TO_POINTER (1));
		g_free (val);
	}
	g_strfreev (keys);

	success = TRUE;

out:
	g_key_file_free (kf);
	return success;
}

/*******************************************/

static void
test_generic (const char *path, const char *file, const char *override_vpn_ip_iface)
{
	GHashTable *con_hash = NULL;
	GHashTable *con_props = NULL;
	GHashTable *device_props = NULL;
	GHashTable *device_ip4_props = NULL;
	GHashTable *device_ip6_props = NULL;
	GHashTable *device_dhcp4_props = NULL;
	GHashTable *device_dhcp6_props = NULL;
	char *vpn_ip_iface = NULL;
	GHashTable *vpn_ip4_props = NULL;
	GHashTable *vpn_ip6_props = NULL;
	char *expected_iface = NULL;
	char *action = NULL;
	char *out_iface = NULL;
	GHashTable *expected_env = NULL;
	GError *error = NULL;
	gboolean success;
	char *p;
	char **denv, **iter;

	/* Read in the test file */
	p = g_strdup_printf ("%s/%s", path, file);
	success = get_dispatcher_file (p,
	                               &con_hash,
	                               &con_props,
	                               &device_props,
	                               &device_ip4_props,
	                               &device_ip6_props,
	                               &device_dhcp4_props,
	                               &device_dhcp6_props,
	                               &vpn_ip_iface,
	                               &vpn_ip4_props,
	                               &vpn_ip6_props,
	                               &expected_iface,
	                               &action,
	                               &expected_env,
	                               &error);
	g_free (p);
	g_assert_no_error (error);
	g_assert (success);

	/* Get the environment from the dispatcher code */
	denv = nm_dispatcher_utils_construct_envp (action,
	                                           con_hash,
	                                           con_props,
	                                           device_props,
	                                           device_ip4_props,
	                                           device_ip6_props,
	                                           device_dhcp4_props,
	                                           device_dhcp6_props,
	                                           override_vpn_ip_iface ? override_vpn_ip_iface : vpn_ip_iface,
	                                           vpn_ip4_props,
	                                           vpn_ip6_props,
	                                           &out_iface);

	/* Print out environment for now */
#ifdef DEBUG
	g_message ("\n******* Generated environment:");
	for (iter = denv; iter && *iter; iter++)
		g_message ("   %s", *iter);
#endif

#ifdef DEBUG
	{
		GHashTableIter k;
		const char *key;

		g_message ("\n******* Expected environment:");
		g_hash_table_iter_init (&k, expected_env);
		while (g_hash_table_iter_next (&k, (gpointer) &key, NULL))
			g_message ("   %s", key);
	}
#endif

	g_assert_cmpint (g_strv_length (denv), ==, g_hash_table_size (expected_env));

	/* Compare dispatcher generated env and expected env */
	for (iter = denv; iter && *iter; iter++) {
		gpointer foo;
		const char *i_value = *iter;

		if (strstr (i_value, "PATH=") == i_value) {
			g_assert_cmpstr (&i_value[strlen("PATH=")], ==, g_getenv ("PATH"));

			/* The path is constructed dynamically. Ignore the actual value. */
			i_value = "PATH=";
		}

		foo = g_hash_table_lookup (expected_env, i_value);
		if (!foo)
			g_warning ("Failed to find %s in environment", i_value);
		g_assert (foo);
	}

	g_assert_cmpstr (expected_iface, ==, out_iface);

	g_free (out_iface);
	g_free (vpn_ip_iface);
	g_free (expected_iface);
	g_free (action);
	g_hash_table_destroy (con_hash);
	g_hash_table_destroy (con_props);
	g_hash_table_destroy (device_props);
	if (device_ip4_props)
		g_hash_table_destroy (device_ip4_props);
	if (device_ip6_props)
		g_hash_table_destroy (device_ip6_props);
	if (device_dhcp4_props)
		g_hash_table_destroy (device_dhcp4_props);
	if (device_dhcp6_props)
		g_hash_table_destroy (device_dhcp6_props);
	if (vpn_ip4_props)
		g_hash_table_destroy (vpn_ip4_props);
	if (vpn_ip6_props)
		g_hash_table_destroy (vpn_ip6_props);
	g_hash_table_destroy (expected_env);
}

/*******************************************/

static void
test_old_up (const char *path)
{
	test_generic (path, "dispatcher-old-up", NULL);
}

static void
test_old_down (const char *path)
{
	test_generic (path, "dispatcher-old-down", NULL);
}

static void
test_old_vpn_up (const char *path)
{
	test_generic (path, "dispatcher-old-vpn-up", NULL);
}

static void
test_old_vpn_down (const char *path)
{
	test_generic (path, "dispatcher-old-vpn-down", NULL);
}

static void
test_up_empty_vpn_iface (const char *path)
{
	/* Test that an empty VPN iface variable, like is passed through D-Bus
	 * from NM, is ignored by the dispatcher environment construction code.
	 */
	test_generic (path, "dispatcher-old-up", "");
}

/*******************************************/

int
main (int argc, char **argv)
{
	g_assert (argc > 1);

	g_test_init (&argc, &argv, NULL);

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

	g_test_add_data_func ("/dispatcher/old_up", argv[1], (GTestDataFunc) test_old_up);
	g_test_add_data_func ("/dispatcher/old_down", argv[1], (GTestDataFunc) test_old_down);
	g_test_add_data_func ("/dispatcher/old_vpn_up", argv[1], (GTestDataFunc) test_old_vpn_up);
	g_test_add_data_func ("/dispatcher/old_vpn_down", argv[1], (GTestDataFunc) test_old_vpn_down);

	g_test_add_data_func ("/dispatcher/up_empty_vpn_iface", argv[1], (GTestDataFunc) test_up_empty_vpn_iface);

	return g_test_run ();
}

