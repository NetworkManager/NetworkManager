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

#include "nm-default.h"

#include <arpa/inet.h>
#include <stdlib.h>

#include "nm-dispatcher-utils.h"
#include "nm-libnm-core-aux/nm-dispatcher-api.h"

#include "nm-utils/nm-test-utils.h"

#include "nmdbus-dispatcher.h"

#define TEST_DIR      NM_BUILD_SRCDIR"/dispatcher/tests"

/*****************************************************************************/

static void
_print_env (const char *const*denv, GHashTable *expected_env)
{
	const char *const*iter;
	GHashTableIter k;
	const char *key;

	g_print ("\n******* Generated environment:\n");
	for (iter = denv; iter && *iter; iter++)
		g_print ("   %s\n", *iter);

	g_print ("\n******* Expected environment:\n");
	g_hash_table_iter_init (&k, expected_env);
	while (g_hash_table_iter_next (&k, (gpointer) &key, NULL))
		g_print ("   %s\n", key);
}

static gboolean
parse_main (GKeyFile *kf,
            const char *filename,
            GVariant **out_con_dict,
            GVariant **out_con_props,
            char **out_expected_iface,
            char **out_action,
            char **out_connectivity_state,
            char **out_vpn_ip_iface,
            GError **error)
{
	nm_auto_clear_variant_builder GVariantBuilder props = { };
	gs_free char *uuid = NULL;
	gs_free char *id = NULL;
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;

	*out_expected_iface = g_key_file_get_string (kf, "main", "expected-iface", NULL);

	*out_connectivity_state = g_key_file_get_string (kf, "main", "connectivity-state", NULL);
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
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_ID, id,
	              NULL);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	*out_con_dict = nm_connection_to_dbus (connection, NM_CONNECTION_SERIALIZE_ALL);

	g_variant_builder_init (&props, G_VARIANT_TYPE ("a{sv}"));
	g_variant_builder_add (&props, "{sv}",
	                       NMD_CONNECTION_PROPS_PATH,
	                       g_variant_new_object_path ("/org/freedesktop/NetworkManager/Connections/5"));

	/* Strip out the non-fixed portion of the filename */
	filename = strstr (filename, "/dispatcher");
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
	nm_auto_clear_variant_builder GVariantBuilder props = { };
	gs_free char *tmp = NULL;
	int i;

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

	nm_clear_g_free (&tmp);
	tmp = g_key_file_get_string (kf, "device", "ip-interface", error);
	if (tmp == NULL)
		return FALSE;
	g_variant_builder_add (&props, "{sv}",
	                       NMD_DEVICE_PROPS_IP_INTERFACE,
	                       g_variant_new_string (tmp));

	nm_clear_g_free (&tmp);
	tmp = g_key_file_get_string (kf, "device", "path", error);
	if (tmp == NULL)
		return FALSE;
	g_variant_builder_add (&props, "{sv}",
	                       NMD_DEVICE_PROPS_PATH,
	                       g_variant_new_object_path (tmp));

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
	gs_free char *tmp = NULL;
	gs_free const char **split = NULL;
	gsize i;

	tmp = g_key_file_get_string (kf, section, key, NULL);
	if (tmp == NULL)
		return TRUE;

	split = nm_utils_strsplit_set_with_empty (tmp, " ");
	if (split) {
		gs_unref_array GArray *items = NULL;

		items = g_array_sized_new (FALSE, TRUE, sizeof (guint32), NM_PTRARRAY_LEN (split));
		for (i = 0; split[i]; i++) {
			const char *s;

			s = split[i];
			g_strstrip ((char *) s);
			if (s[0]) {
				guint32 addr;

				if (inet_pton (AF_INET, s, &addr) != 1)
					g_assert_not_reached ();
				g_array_append_val (items, addr);
			}
		}
		g_variant_builder_add (props, "{sv}", key,
		                       g_variant_new_fixed_array (G_VARIANT_TYPE_UINT32,
		                                                  items->data, items->len,
		                                                  sizeof (guint32)));
	}

	return TRUE;
}

static gboolean
parse_proxy (GKeyFile *kf, GVariant **out_props, const char *section, GError **error)
{
	nm_auto_clear_variant_builder GVariantBuilder props = { };
	gs_free char *tmp = NULL;

	g_variant_builder_init (&props, G_VARIANT_TYPE ("a{sv}"));

	tmp = g_key_file_get_string (kf, section, "pac-url", error);
	if (tmp == NULL)
		return FALSE;
	g_variant_builder_add (&props, "{sv}",
	                       "pac-url",
	                       g_variant_new_string (tmp));

	nm_clear_g_free (&tmp);
	tmp = g_key_file_get_string (kf, section, "pac-script", error);
	if (tmp == NULL)
		return FALSE;
	g_variant_builder_add (&props, "{sv}",
	                       "pac-script",
	                       g_variant_new_string (tmp));

	*out_props = g_variant_builder_end (&props);
	return TRUE;
}

static gboolean
parse_ip4 (GKeyFile *kf, GVariant **out_props, const char *section, GError **error)
{
	nm_auto_clear_variant_builder GVariantBuilder props = { };
	gs_free char *tmp = NULL;
	gs_free const char **split = NULL;
	const char **iter;

	g_variant_builder_init (&props, G_VARIANT_TYPE ("a{sv}"));

	/* search domains */
	/* Use char** for domains. (DBUS_TYPE_G_ARRAY_OF_STRING of NMIP4Config
	 * becomes G_TYPE_STRV when sending the value over D-Bus)
	 */
	tmp = g_key_file_get_string (kf, section, "domains", error);
	if (tmp == NULL)
		return FALSE;
	split = nm_utils_strsplit_set_with_empty (tmp, " ");
	if (split) {
		for (iter = split; *iter; iter++)
			g_strstrip ((char *) *iter);
		g_variant_builder_add (&props, "{sv}", "domains", g_variant_new_strv ((gpointer) split, -1));
	}
	nm_clear_g_free (&split);

	if (!add_uint_array (kf, &props, "ip4", "nameservers", error))
		return FALSE;

	if (!add_uint_array (kf, &props, "ip4", "wins-servers", error))
		return FALSE;

	nm_clear_g_free (&tmp);
	tmp = g_key_file_get_string (kf, section, "addresses", error);
	if (tmp == NULL)
		return FALSE;
	split = nm_utils_strsplit_set_with_empty (tmp, ",");
	if (split) {
		gs_unref_ptrarray GPtrArray *addresses = NULL;
		const char *gateway = NULL;

		addresses = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_ip_address_unref);
		for (iter = split; *iter; iter++) {
			const char *s = *iter;
			NMIPAddress *addr;
			const char *ip;
			const char *prefix;

			g_strstrip ((char *) s);
			if (s[0] == '\0')
				continue;

			ip = *iter;

			prefix = strchr (ip, '/');
			g_assert (prefix);
			((char *) (prefix++))[0] = '\0';

			if (addresses->len == 0) {
				gateway = strchr (prefix, ' ');
				g_assert (gateway);
				gateway++;
			}

			addr = nm_ip_address_new (AF_INET, ip, (guint) atoi (prefix), error);
			if (!addr)
				return FALSE;

			g_ptr_array_add (addresses, addr);
		}

		g_variant_builder_add (&props, "{sv}", "addresses",
		                       nm_utils_ip4_addresses_to_variant (addresses, gateway));
	}
	nm_clear_g_free (&split);

	nm_clear_g_free (&tmp);
	tmp = g_key_file_get_string (kf, section, "routes", NULL);
	split = nm_utils_strsplit_set_with_empty (tmp, ",");
	if (split) {
		gs_unref_ptrarray GPtrArray *routes = NULL;

		routes = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_ip_route_unref);
		for (iter = split; *iter; iter++) {
			const char *s = *iter;
			NMIPRoute *route;
			const char *dest;
			const char *prefix;
			const char *next_hop;
			const char *metric;

			g_strstrip ((char *) s);
			if (s[0] == '\0')
				continue;

			dest = s;

			prefix = strchr (dest, '/');
			g_assert (prefix);
			((char *) (prefix++))[0] = '\0';

			next_hop = strchr (prefix, ' ');
			g_assert (next_hop);
			((char *) (next_hop++))[0] = '\0';

			metric = strchr (next_hop, ' ');
			g_assert (metric);
			((char *) (metric++))[0] = '\0';

			route = nm_ip_route_new (AF_INET,
			                         dest,
			                         _nm_utils_ascii_str_to_int64 (prefix, 10, 0, 32, 255),
			                         next_hop,
			                         (guint) atoi (metric),
			                         error);
			if (!route)
				return FALSE;
			g_ptr_array_add (routes, route);
		}

		g_variant_builder_add (&props, "{sv}", "routes",
		                       nm_utils_ip4_routes_to_variant (routes));
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
	nm_auto_clear_variant_builder GVariantBuilder props = { };
	gs_strfreev char **keys = NULL;
	char **iter;

	keys = g_key_file_get_keys (kf, group_name, NULL, error);
	if (!keys)
		return FALSE;

	g_variant_builder_init (&props, G_VARIANT_TYPE ("a{sv}"));
	for (iter = keys; iter && *iter; iter++) {
		gs_free char *val = NULL;

		val = g_key_file_get_string (kf, group_name, *iter, error);
		if (!val)
			return FALSE;
		g_variant_builder_add (&props, "{sv}", *iter, g_variant_new_string (val));
	}

	*out_props = g_variant_builder_end (&props);
	return TRUE;
}

static gboolean
get_dispatcher_file (const char *file,
                     GVariant **out_con_dict,
                     GVariant **out_con_props,
                     GVariant **out_device_props,
                     GVariant **out_device_proxy_props,
                     GVariant **out_device_ip4_props,
                     GVariant **out_device_ip6_props,
                     GVariant **out_device_dhcp4_props,
                     GVariant **out_device_dhcp6_props,
                     char **out_connectivity_state,
                     char **out_vpn_ip_iface,
                     GVariant **out_vpn_proxy_props,
                     GVariant **out_vpn_ip4_props,
                     GVariant **out_vpn_ip6_props,
                     char **out_expected_iface,
                     char **out_action,
                     GHashTable **out_env,
                     GError **error)
{
	gs_unref_keyfile GKeyFile *kf = NULL;
	gs_strfreev char **keys = NULL;
	char **iter;

	g_assert (!error || !*error);
	g_assert (out_con_dict && !*out_con_dict);
	g_assert (out_con_props && !*out_con_props);
	g_assert (out_device_props && !*out_device_props);
	g_assert (out_device_proxy_props && !*out_device_proxy_props);
	g_assert (out_device_ip4_props && !*out_device_ip4_props);
	g_assert (out_device_ip6_props && !*out_device_ip6_props);
	g_assert (out_device_dhcp4_props && !*out_device_dhcp4_props);
	g_assert (out_device_dhcp6_props && !*out_device_dhcp6_props);
	g_assert (out_connectivity_state && !*out_connectivity_state);
	g_assert (out_vpn_ip_iface && !*out_vpn_ip_iface);
	g_assert (out_vpn_proxy_props && !*out_vpn_proxy_props);
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
	                 out_connectivity_state,
	                 out_vpn_ip_iface,
	                 error))
		return FALSE;

	if (!parse_device (kf, out_device_props, error))
		return FALSE;

	if (g_key_file_has_group (kf, "proxy")) {
		if (!parse_proxy (kf, out_device_proxy_props, "proxy", error))
			return FALSE;
	}

	if (g_key_file_has_group (kf, "ip4")) {
		if (!parse_ip4 (kf, out_device_ip4_props, "ip4", error))
			return FALSE;
	}

	if (g_key_file_has_group (kf, "dhcp4")) {
		if (!parse_dhcp (kf, "dhcp4", out_device_dhcp4_props, error))
			return FALSE;
	}

	if (g_key_file_has_group (kf, "dhcp6")) {
		if (!parse_dhcp (kf, "dhcp6", out_device_dhcp6_props, error))
			return FALSE;
	}

	g_assert (g_key_file_has_group (kf, "env"));
	keys = g_key_file_get_keys (kf, "env", NULL, error);
	*out_env = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
	for (iter = keys; iter && *iter; iter++) {
		gs_free char *val = NULL;

		val = g_key_file_get_string (kf, "env", *iter, error);
		if (!val)
			return FALSE;
		g_hash_table_insert (*out_env,
		                     g_strdup_printf ("%s=%s", *iter, val),
		                     GUINT_TO_POINTER (1));
	}

	return TRUE;
}

/*****************************************************************************/

static void
test_generic (const char *file, const char *override_vpn_ip_iface)
{
	gs_unref_variant GVariant *con_dict = NULL;
	gs_unref_variant GVariant *con_props = NULL;
	gs_unref_variant GVariant *device_props = NULL;
	gs_unref_variant GVariant *device_proxy_props = NULL;
	gs_unref_variant GVariant *device_ip4_props = NULL;
	gs_unref_variant GVariant *device_ip6_props = NULL;
	gs_unref_variant GVariant *device_dhcp4_props = NULL;
	gs_unref_variant GVariant *device_dhcp6_props = NULL;
	gs_free char *connectivity_change = NULL;
	gs_free char *vpn_ip_iface = NULL;
	gs_unref_variant GVariant *vpn_proxy_props = NULL;
	gs_unref_variant GVariant *vpn_ip4_props = NULL;
	gs_unref_variant GVariant *vpn_ip6_props = NULL;
	gs_free char *expected_iface = NULL;
	gs_free char *action = NULL;
	gs_free char *out_iface = NULL;
	const char *error_message = NULL;
	gs_unref_hashtable GHashTable *expected_env = NULL;
	GError *error = NULL;
	gboolean success;
	gs_free char *filename = NULL;
	gs_strfreev char **denv = NULL;
	char **iter;

	filename = g_build_filename (TEST_DIR, file, NULL);
	success = get_dispatcher_file (filename,
	                               &con_dict,
	                               &con_props,
	                               &device_props,
	                               &device_proxy_props,
	                               &device_ip4_props,
	                               &device_ip6_props,
	                               &device_dhcp4_props,
	                               &device_dhcp6_props,
	                               &connectivity_change,
	                               &vpn_ip_iface,
	                               &vpn_proxy_props,
	                               &vpn_ip4_props,
	                               &vpn_ip6_props,
	                               &expected_iface,
	                               &action,
	                               &expected_env,
	                               &error);
	nmtst_assert_success (success, error);

	/* Get the environment from the dispatcher code */
	denv = nm_dispatcher_utils_construct_envp (action,
	                                           con_dict,
	                                           con_props,
	                                           device_props,
	                                           device_proxy_props,
	                                           device_ip4_props,
	                                           device_ip6_props,
	                                           device_dhcp4_props,
	                                           device_dhcp6_props,
	                                           connectivity_change,
	                                           override_vpn_ip_iface ?: vpn_ip_iface,
	                                           vpn_proxy_props,
	                                           vpn_ip4_props,
	                                           vpn_ip6_props,
	                                           &out_iface,
	                                           &error_message);

	g_assert ((!denv && error_message) || (denv && !error_message));

	if (error_message)
		g_error ("FAILED: %s", error_message);

	if (g_strv_length (denv) != g_hash_table_size (expected_env)) {
		_print_env (NM_CAST_STRV_CC (denv), expected_env);
		g_assert_cmpint (g_strv_length (denv), ==, g_hash_table_size (expected_env));
	}

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
		if (!foo) {
			_print_env (NM_CAST_STRV_CC (denv), expected_env);
			g_error ("Failed to find %s in environment", i_value);
		}
	}

	g_assert_cmpstr (expected_iface, ==, out_iface);
}

/*****************************************************************************/

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
test_connectivity_changed (void)
{
	/* These tests will check that the CONNECTIVITY_STATE environment
	 * variable is only defined for known states, such as 'full'. */
	test_generic ("dispatcher-connectivity-unknown", NULL);
	test_generic ("dispatcher-connectivity-full", NULL);
}

static void
test_up_empty_vpn_iface (void)
{
	/* Test that an empty VPN iface variable, like is passed through D-Bus
	 * from NM, is ignored by the dispatcher environment construction code.
	 */
	test_generic ("dispatcher-up", "");
}

/*****************************************************************************/

static void
test_gdbus_codegen (void)
{
	gs_unref_object NMDBusDispatcher *dbus_dispatcher = NULL;

	dbus_dispatcher = nmdbus_dispatcher_skeleton_new ();
	g_assert (NMDBUS_IS_DISPATCHER_SKELETON (dbus_dispatcher));
}

/*****************************************************************************/

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
	g_test_add_func ("/dispatcher/connectivity_changed", test_connectivity_changed);

	g_test_add_func ("/dispatcher/up_empty_vpn_iface", test_up_empty_vpn_iface);

	g_test_add_func ("/dispatcher/gdbus-codegen", test_gdbus_codegen);

	return g_test_run ();
}

