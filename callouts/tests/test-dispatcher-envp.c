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

#include "config.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#include "nm-default.h"
#include "nm-core-internal.h"
#include "nm-dispatcher-utils.h"
#include "nm-dispatcher-api.h"

#include "nm-test-utils.h"

/*******************************************/

static gboolean
parse_main (GKeyFile *kf,
            const char *filename,
            GVariant **out_con_dict,
            GVariant **out_con_props,
            char **out_expected_iface,
            char **out_action,
            char **out_vpn_ip_iface,
            GError **error)
{
	char *uuid, *id;
	NMConnection *connection;
	NMSettingConnection *s_con;
	GVariantBuilder props;

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

	connection = nm_simple_connection_new ();
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

	*out_con_dict = nm_connection_to_dbus (connection, NM_CONNECTION_SERIALIZE_ALL);
	g_object_unref (connection);

	g_variant_builder_init (&props, G_VARIANT_TYPE ("a{sv}"));
	g_variant_builder_add (&props, "{sv}",
	                       NMD_CONNECTION_PROPS_PATH,
	                       g_variant_new_object_path ("/org/freedesktop/NetworkManager/Connections/5"));

	/* Strip out the non-fixed portion of the filename */
	filename = strstr (filename, "/callouts");
	g_variant_builder_add (&props, "{sv}",
	                       "filename",
	                       g_variant_new_string (filename));

	if (g_key_file_get_boolean (kf, "main", "external", NULL)) {
		g_variant_builder_add (&props, "{sv}",
		                       "external",
		                       g_variant_new_boolean (TRUE));
	}

	*out_con_props = g_variant_builder_end (&props);

	return TRUE;
}

static gboolean
parse_device (GKeyFile *kf, GVariant **out_device_props, GError **error)
{
	GVariantBuilder props;
	char *tmp;
	gint i;

	g_variant_builder_init (&props, G_VARIANT_TYPE ("a{sv}"));

	i = g_key_file_get_integer (kf, "device", "state", error);
	if (i == 0)
		return FALSE;
	g_variant_builder_add (&props, "{sv}",
	                       NMD_DEVICE_PROPS_STATE,
	                       g_variant_new_uint32 (i));

	i = g_key_file_get_integer (kf, "device", "type", error);
	if (i == 0)
		return FALSE;
	g_variant_builder_add (&props, "{sv}",
	                       NMD_DEVICE_PROPS_TYPE,
	                       g_variant_new_uint32 (i));

	tmp = g_key_file_get_string (kf, "device", "interface", error);
	if (tmp == NULL)
		return FALSE;
	g_variant_builder_add (&props, "{sv}",
	                       NMD_DEVICE_PROPS_INTERFACE,
	                       g_variant_new_string (tmp));
	g_free (tmp);

	tmp = g_key_file_get_string (kf, "device", "ip-interface", error);
	if (tmp == NULL)
		return FALSE;
	g_variant_builder_add (&props, "{sv}",
	                       NMD_DEVICE_PROPS_IP_INTERFACE,
	                       g_variant_new_string (tmp));
	g_free (tmp);

	tmp = g_key_file_get_string (kf, "device", "path", error);
	if (tmp == NULL)
		return FALSE;
	g_variant_builder_add (&props, "{sv}",
	                       NMD_DEVICE_PROPS_PATH,
	                       g_variant_new_object_path (tmp));
	g_free (tmp);

	*out_device_props = g_variant_builder_end (&props);
	return TRUE;
}

static gboolean
add_uint_array (GKeyFile *kf,
                GVariantBuilder *props,
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
		g_variant_builder_add (props, "{sv}", key,
		                       g_variant_new_fixed_array (G_VARIANT_TYPE_UINT32,
		                                                  items->data, items->len,
		                                                  sizeof (guint32)));
		g_array_unref (items);
	}
	g_strfreev (split);
	return TRUE;
}

static gboolean
parse_ip4 (GKeyFile *kf, GVariant **out_props, const char *section, GError **error)
{
	GVariantBuilder props;
	char *tmp;
	char **split, **iter;
	GPtrArray *addresses, *routes;
	const char *gateway = NULL;

	g_variant_builder_init (&props, G_VARIANT_TYPE ("a{sv}"));

	/* search domains */
	/* Use char** for domains. (DBUS_TYPE_G_ARRAY_OF_STRING of NMIP4Config
	 * becomes G_TYPE_STRV when sending the value over D-Bus)
	 */
	tmp = g_key_file_get_string (kf, section, "domains", error);
	if (tmp == NULL)
		return FALSE;
	split = g_strsplit_set (tmp, " ", -1);
	g_free (tmp);

	if (split && g_strv_length (split) > 0) {
		for (iter = split; iter && *iter; iter++)
			g_strstrip (*iter);
		g_variant_builder_add (&props, "{sv}", "domains", g_variant_new_strv ((gpointer) split, -1));
	}
	g_strfreev (split);

	/* nameservers */
	if (!add_uint_array (kf, &props, "ip4", "nameservers", error))
		return FALSE;
	/* wins-servers */
	if (!add_uint_array (kf, &props, "ip4", "wins-servers", error))
		return FALSE;

	/* Addresses */
	tmp = g_key_file_get_string (kf, section, "addresses", error);
	if (tmp == NULL)
		return FALSE;
	split = g_strsplit_set (tmp, ",", -1);
	g_free (tmp);

	if (split && g_strv_length (split) > 0) {
		addresses = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_ip_address_unref);
		for (iter = split; iter && *iter; iter++) {
			NMIPAddress *addr;
			char *ip, *prefix;

			if (strlen (g_strstrip (*iter)) == 0)
				continue;

			ip = *iter;

			prefix = strchr (ip, '/');
			g_assert (prefix);
			*prefix++ = '\0';

			if (addresses->len == 0) {
				gateway = strchr (prefix, ' ');
				g_assert (gateway);
				gateway++;
			}

			addr = nm_ip_address_new (AF_INET, ip, (guint) atoi (prefix), error);
			if (!addr) {
				g_ptr_array_unref (addresses);
				return FALSE;
			}
			g_ptr_array_add (addresses, addr);
		}

		g_variant_builder_add (&props, "{sv}", "addresses",
		                       nm_utils_ip4_addresses_to_variant (addresses, gateway));
		g_ptr_array_unref (addresses);
	}
	g_strfreev (split);

	/* Routes */
	tmp = g_key_file_get_string (kf, section, "routes", error);
	g_clear_error (error);
	if (tmp) {
		split = g_strsplit_set (tmp, ",", -1);
		g_free (tmp);

		if (split && g_strv_length (split) > 0) {
			routes = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_ip_route_unref);
			for (iter = split; iter && *iter; iter++) {
				NMIPRoute *route;
				char *dest, *prefix, *next_hop, *metric;

				if (strlen (g_strstrip (*iter)) == 0)
					continue;

				dest = *iter;

				prefix = strchr (dest, '/');
				g_assert (prefix);
				*prefix++ = '\0';

				next_hop = strchr (prefix, ' ');
				g_assert (next_hop);
				next_hop++;

				metric = strchr (next_hop, ' ');
				g_assert (metric);
				metric++;

				route = nm_ip_route_new (AF_INET,
				                         dest, (guint) atoi (prefix),
				                         next_hop, (guint) atoi (metric),
				                         error);
				if (!route) {
					g_ptr_array_unref (routes);
					return FALSE;
				}
				g_ptr_array_add (routes, route);
			}

			g_variant_builder_add (&props, "{sv}", "routes",
			                       nm_utils_ip4_routes_to_variant (routes));
			g_ptr_array_unref (routes);
		}
		g_strfreev (split);
	}

	*out_props = g_variant_builder_end (&props);
	return TRUE;
}

static gboolean
parse_dhcp (GKeyFile *kf,
            const char *group_name,
            GVariant **out_props,
            GError **error)
{
	char **keys, **iter, *val;
	GVariantBuilder props;

	keys = g_key_file_get_keys (kf, group_name, NULL, error);
	if (!keys)
		return FALSE;

	g_variant_builder_init (&props, G_VARIANT_TYPE ("a{sv}"));
	for (iter = keys; iter && *iter; iter++) {
		val = g_key_file_get_string (kf, group_name, *iter, error);
		if (!val) {
			g_strfreev (keys);
			g_variant_builder_clear (&props);
			return FALSE;
		}
		g_variant_builder_add (&props, "{sv}", *iter, g_variant_new_string (val));
		g_free (val);
	}
	g_strfreev (keys);

	*out_props = g_variant_builder_end (&props);
	return TRUE;
}

static gboolean
get_dispatcher_file (const char *file,
                     GVariant **out_con_dict,
                     GVariant **out_con_props,
                     GVariant **out_device_props,
                     GVariant **out_device_ip4_props,
                     GVariant **out_device_ip6_props,
                     GVariant **out_device_dhcp4_props,
                     GVariant **out_device_dhcp6_props,
                     char **out_vpn_ip_iface,
                     GVariant **out_vpn_ip4_props,
                     GVariant **out_vpn_ip6_props,
                     char **out_expected_iface,
                     char **out_action,
                     GHashTable **out_env,
                     GError **error)
{
	GKeyFile *kf;
	gboolean success = FALSE;
	char **keys, **iter, *val;

	g_assert (!error || !*error);
	g_assert (out_con_dict && !*out_con_dict);
	g_assert (out_con_props && !*out_con_props);
	g_assert (out_device_props && !*out_device_props);
	g_assert (out_device_ip4_props && !*out_device_ip4_props);
	g_assert (out_device_ip6_props && !*out_device_ip6_props);
	g_assert (out_device_dhcp4_props && !*out_device_dhcp4_props);
	g_assert (out_device_dhcp6_props && !*out_device_dhcp6_props);
	g_assert (out_vpn_ip_iface && !*out_vpn_ip_iface);
	g_assert (out_vpn_ip4_props && !*out_vpn_ip4_props);
	g_assert (out_vpn_ip6_props && !*out_vpn_ip6_props);
	g_assert (out_expected_iface && !*out_expected_iface);
	g_assert (out_action && !*out_action);
	g_assert (out_env && !*out_env);

	kf = g_key_file_new ();
	if (!g_key_file_load_from_file (kf, file, G_KEY_FILE_NONE, error))
		return FALSE;

	if (!parse_main (kf,
	                 file,
	                 out_con_dict,
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
		if (!parse_dhcp (kf, "dhcp6", out_device_dhcp6_props, error))
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
test_generic (const char *file, const char *override_vpn_ip_iface)
{
	GVariant *con_dict = NULL;
	GVariant *con_props = NULL;
	GVariant *device_props = NULL;
	GVariant *device_ip4_props = NULL;
	GVariant *device_ip6_props = NULL;
	GVariant *device_dhcp4_props = NULL;
	GVariant *device_dhcp6_props = NULL;
	char *vpn_ip_iface = NULL;
	GVariant *vpn_ip4_props = NULL;
	GVariant *vpn_ip6_props = NULL;
	char *expected_iface = NULL;
	char *action = NULL;
	char *out_iface = NULL;
	const char *error_message = NULL;
	GHashTable *expected_env = NULL;
	GError *error = NULL;
	gboolean success;
	char *p;
	char **denv, **iter;

	/* Read in the test file */
	p = g_build_filename (SRCDIR, file, NULL);
	success = get_dispatcher_file (p,
	                               &con_dict,
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
	                                           con_dict,
	                                           con_props,
	                                           device_props,
	                                           device_ip4_props,
	                                           device_ip6_props,
	                                           device_dhcp4_props,
	                                           device_dhcp6_props,
	                                           override_vpn_ip_iface ? override_vpn_ip_iface : vpn_ip_iface,
	                                           vpn_ip4_props,
	                                           vpn_ip6_props,
	                                           &out_iface,
	                                           &error_message);

	g_assert ((!denv && error_message) || (denv && !error_message));

	if (error_message)
		g_warning (error_message);

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

	g_strfreev (denv);
	g_free (out_iface);
	g_free (vpn_ip_iface);
	g_free (expected_iface);
	g_free (action);
	g_variant_unref (con_dict);
	g_variant_unref (con_props);
	g_variant_unref (device_props);
	if (device_ip4_props)
		g_variant_unref (device_ip4_props);
	if (device_ip6_props)
		g_variant_unref (device_ip6_props);
	if (device_dhcp4_props)
		g_variant_unref (device_dhcp4_props);
	if (device_dhcp6_props)
		g_variant_unref (device_dhcp6_props);
	if (vpn_ip4_props)
		g_variant_unref (vpn_ip4_props);
	if (vpn_ip6_props)
		g_variant_unref (vpn_ip6_props);
	g_hash_table_destroy (expected_env);
}

/*******************************************/

static void
test_up (void)
{
	test_generic ("dispatcher-up", NULL);
}

static void
test_down (void)
{
	test_generic ("dispatcher-down", NULL);
}

static void
test_vpn_up (void)
{
	test_generic ("dispatcher-vpn-up", NULL);
}

static void
test_vpn_down (void)
{
	test_generic ("dispatcher-vpn-down", NULL);
}

static void
test_external (void)
{
	test_generic ("dispatcher-external", NULL);
}

static void
test_up_empty_vpn_iface (void)
{
	/* Test that an empty VPN iface variable, like is passed through D-Bus
	 * from NM, is ignored by the dispatcher environment construction code.
	 */
	test_generic ("dispatcher-up", "");
}

/*******************************************/

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	nmtst_init (&argc, &argv, TRUE);

	g_test_add_func ("/dispatcher/up", test_up);
	g_test_add_func ("/dispatcher/down", test_down);
	g_test_add_func ("/dispatcher/vpn_up", test_vpn_up);
	g_test_add_func ("/dispatcher/vpn_down", test_vpn_down);
	g_test_add_func ("/dispatcher/external", test_external);

	g_test_add_func ("/dispatcher/up_empty_vpn_iface", test_up_empty_vpn_iface);

	return g_test_run ();
}

