/*
 *  nmcli - command-line tool for controlling NetworkManager
 *  Common functions and data shared between files.
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
 * Copyright 2012 - 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <readline/readline.h>
#include <readline/history.h>

#include "nm-vpn-helpers.h"
#include "nm-client-utils.h"

#include "utils.h"

/*****************************************************************************/

static char **
_ip_config_get_routes (NMIPConfig *cfg)
{
	gs_unref_hashtable GHashTable *hash = NULL;
	GPtrArray *ptr_array;
	char **arr;
	guint i;

	ptr_array = nm_ip_config_get_routes (cfg);
	if (!ptr_array)
		return NULL;

	if (ptr_array->len == 0)
		return NULL;

	arr = g_new (char *, ptr_array->len + 1);
	for (i = 0; i < ptr_array->len; i++) {
		NMIPRoute *route = g_ptr_array_index (ptr_array, i);
		gs_strfreev char **names = NULL;
		gsize j;
		GString *str;
		guint64 metric;
		gs_free char *attributes = NULL;

		str = g_string_new (NULL);
		g_string_append_printf (str,
		                        "dst = %s/%u, nh = %s",
		                        nm_ip_route_get_dest (route),
		                        nm_ip_route_get_prefix (route),
		                        nm_ip_route_get_next_hop (route)
		                          ?: (nm_ip_route_get_family (route) == AF_INET ? "0.0.0.0" : "::"));

		metric = nm_ip_route_get_metric (route);
		if (metric != -1) {
			g_string_append_printf (str,
			                        ", mt = %u",
			                        (guint) metric);
		}

		names = nm_ip_route_get_attribute_names (route);
		if (names[0]) {
			if (!hash)
				hash = g_hash_table_new (nm_str_hash, g_str_equal);
			else
				g_hash_table_remove_all (hash);

			for (j = 0; names[j]; j++)
				g_hash_table_insert (hash, names[j], nm_ip_route_get_attribute (route, names[j]));

			attributes = nm_utils_format_variant_attributes (hash, ',', '=');
			if (attributes) {
				g_string_append (str, ", ");
				g_string_append (str, attributes);
			}
		}

		arr[i] = g_string_free (str, FALSE);
	}

	nm_assert (i == ptr_array->len);
	arr[i] = NULL;

	return arr;
}

/*****************************************************************************/

static gconstpointer
_metagen_ip4_config_get_fcn (NMC_META_GENERIC_INFO_GET_FCN_ARGS)
{
	NMIPConfig *cfg4 = target;
	GPtrArray *ptr_array;
	char **arr;
	const char *const*arrc;
	guint i = 0;
	const char *str;

	nm_assert (info->info_type < _NMC_GENERIC_INFO_TYPE_IP4_CONFIG_NUM);

	NMC_HANDLE_COLOR (NM_META_COLOR_NONE);
	NM_SET_OUT (out_is_default, TRUE);

	switch (info->info_type) {
	case NMC_GENERIC_INFO_TYPE_IP4_CONFIG_ADDRESS:
		if (!NM_FLAGS_HAS (get_flags, NM_META_ACCESSOR_GET_FLAGS_ACCEPT_STRV))
			return NULL;
		ptr_array = nm_ip_config_get_addresses (cfg4);
		if (ptr_array) {
			arr = g_new (char *, ptr_array->len + 1);
			for (i = 0; i < ptr_array->len; i++) {
				NMIPAddress *addr = g_ptr_array_index (ptr_array, i);

				arr[i] = g_strdup_printf ("%s/%u",
				                          nm_ip_address_get_address (addr),
				                          nm_ip_address_get_prefix (addr));
			}
			arr[i] = NULL;
		} else
			arr = NULL;
		goto arr_out;
	case NMC_GENERIC_INFO_TYPE_IP4_CONFIG_GATEWAY:
		str = nm_ip_config_get_gateway (cfg4);
		NM_SET_OUT (out_is_default, !str);
		return str;
	case NMC_GENERIC_INFO_TYPE_IP4_CONFIG_ROUTE:
		if (!NM_FLAGS_HAS (get_flags, NM_META_ACCESSOR_GET_FLAGS_ACCEPT_STRV))
			return NULL;
		arr = _ip_config_get_routes (cfg4);
		goto arr_out;
	case NMC_GENERIC_INFO_TYPE_IP4_CONFIG_DNS:
		if (!NM_FLAGS_HAS (get_flags, NM_META_ACCESSOR_GET_FLAGS_ACCEPT_STRV))
			return NULL;
		arrc = nm_ip_config_get_nameservers (cfg4);
		goto arrc_out;
	case NMC_GENERIC_INFO_TYPE_IP4_CONFIG_DOMAIN:
		if (!NM_FLAGS_HAS (get_flags, NM_META_ACCESSOR_GET_FLAGS_ACCEPT_STRV))
			return NULL;
		arrc = nm_ip_config_get_domains (cfg4);
		goto arrc_out;
	case NMC_GENERIC_INFO_TYPE_IP4_CONFIG_WINS:
		if (!NM_FLAGS_HAS (get_flags, NM_META_ACCESSOR_GET_FLAGS_ACCEPT_STRV))
			return NULL;
		arrc = nm_ip_config_get_wins_servers (cfg4);
		goto arrc_out;
	default:
		break;
	}

	g_return_val_if_reached (NULL);

arrc_out:
	NM_SET_OUT (out_is_default, !arrc || !arrc[0]);
	*out_flags |= NM_META_ACCESSOR_GET_OUT_FLAGS_STRV;
	return arrc;

arr_out:
	NM_SET_OUT (out_is_default, !arr || !arr[0]);
	*out_flags |= NM_META_ACCESSOR_GET_OUT_FLAGS_STRV;
	*out_to_free = arr;
	return arr;
}

const NmcMetaGenericInfo *const metagen_ip4_config[_NMC_GENERIC_INFO_TYPE_IP4_CONFIG_NUM + 1] = {
#define _METAGEN_IP4_CONFIG(type, name) \
	[type] = NMC_META_GENERIC(name, .info_type = type, .get_fcn = _metagen_ip4_config_get_fcn)
	_METAGEN_IP4_CONFIG (NMC_GENERIC_INFO_TYPE_IP4_CONFIG_ADDRESS, "ADDRESS"),
	_METAGEN_IP4_CONFIG (NMC_GENERIC_INFO_TYPE_IP4_CONFIG_GATEWAY, "GATEWAY"),
	_METAGEN_IP4_CONFIG (NMC_GENERIC_INFO_TYPE_IP4_CONFIG_ROUTE,   "ROUTE"),
	_METAGEN_IP4_CONFIG (NMC_GENERIC_INFO_TYPE_IP4_CONFIG_DNS,     "DNS"),
	_METAGEN_IP4_CONFIG (NMC_GENERIC_INFO_TYPE_IP4_CONFIG_DOMAIN,  "DOMAIN"),
	_METAGEN_IP4_CONFIG (NMC_GENERIC_INFO_TYPE_IP4_CONFIG_WINS,    "WINS"),
};

/*****************************************************************************/

static gconstpointer
_metagen_ip6_config_get_fcn (NMC_META_GENERIC_INFO_GET_FCN_ARGS)
{
	NMIPConfig *cfg6 = target;
	GPtrArray *ptr_array;
	char **arr;
	const char *const*arrc;
	guint i = 0;
	const char *str;

	nm_assert (info->info_type < _NMC_GENERIC_INFO_TYPE_IP6_CONFIG_NUM);

	NMC_HANDLE_COLOR (NM_META_COLOR_NONE);
	NM_SET_OUT (out_is_default, TRUE);

	switch (info->info_type) {
	case NMC_GENERIC_INFO_TYPE_IP6_CONFIG_ADDRESS:
		if (!NM_FLAGS_HAS (get_flags, NM_META_ACCESSOR_GET_FLAGS_ACCEPT_STRV))
			return NULL;
		ptr_array = nm_ip_config_get_addresses (cfg6);
		if (ptr_array) {
			arr = g_new (char *, ptr_array->len + 1);
			for (i = 0; i < ptr_array->len; i++) {
				NMIPAddress *addr = g_ptr_array_index (ptr_array, i);

				arr[i] = g_strdup_printf ("%s/%u",
				                          nm_ip_address_get_address (addr),
				                          nm_ip_address_get_prefix (addr));
			}
			arr[i] = NULL;
		} else
			arr = NULL;
		goto arr_out;
	case NMC_GENERIC_INFO_TYPE_IP6_CONFIG_GATEWAY:
		str = nm_ip_config_get_gateway (cfg6);
		NM_SET_OUT (out_is_default, !str);
		return str;
	case NMC_GENERIC_INFO_TYPE_IP6_CONFIG_ROUTE:
		if (!NM_FLAGS_HAS (get_flags, NM_META_ACCESSOR_GET_FLAGS_ACCEPT_STRV))
			return NULL;
		arr = _ip_config_get_routes (cfg6);
		goto arr_out;
	case NMC_GENERIC_INFO_TYPE_IP6_CONFIG_DNS:
		if (!NM_FLAGS_HAS (get_flags, NM_META_ACCESSOR_GET_FLAGS_ACCEPT_STRV))
			return NULL;
		arrc = nm_ip_config_get_nameservers (cfg6);
		goto arrc_out;
	case NMC_GENERIC_INFO_TYPE_IP6_CONFIG_DOMAIN:
		if (!NM_FLAGS_HAS (get_flags, NM_META_ACCESSOR_GET_FLAGS_ACCEPT_STRV))
			return NULL;
		arrc = nm_ip_config_get_domains (cfg6);
		goto arrc_out;
	default:
		break;
	}

	g_return_val_if_reached (NULL);

arrc_out:
	NM_SET_OUT (out_is_default, !arrc || !arrc[0]);
	*out_flags |= NM_META_ACCESSOR_GET_OUT_FLAGS_STRV;
	return arrc;

arr_out:
	NM_SET_OUT (out_is_default, !arr || !arr[0]);
	*out_flags |= NM_META_ACCESSOR_GET_OUT_FLAGS_STRV;
	*out_to_free = arr;
	return arr;
}

const NmcMetaGenericInfo *const metagen_ip6_config[_NMC_GENERIC_INFO_TYPE_IP6_CONFIG_NUM + 1] = {
#define _METAGEN_IP6_CONFIG(type, name) \
	[type] = NMC_META_GENERIC(name, .info_type = type, .get_fcn = _metagen_ip6_config_get_fcn)
	_METAGEN_IP6_CONFIG (NMC_GENERIC_INFO_TYPE_IP6_CONFIG_ADDRESS, "ADDRESS"),
	_METAGEN_IP6_CONFIG (NMC_GENERIC_INFO_TYPE_IP6_CONFIG_GATEWAY, "GATEWAY"),
	_METAGEN_IP6_CONFIG (NMC_GENERIC_INFO_TYPE_IP6_CONFIG_ROUTE,   "ROUTE"),
	_METAGEN_IP6_CONFIG (NMC_GENERIC_INFO_TYPE_IP6_CONFIG_DNS,     "DNS"),
	_METAGEN_IP6_CONFIG (NMC_GENERIC_INFO_TYPE_IP6_CONFIG_DOMAIN,  "DOMAIN"),
};

/*****************************************************************************/

static gconstpointer
_metagen_dhcp_config_get_fcn (NMC_META_GENERIC_INFO_GET_FCN_ARGS)
{
	NMDhcpConfig *dhcp = target;
	guint i;
	char **arr = NULL;

	NMC_HANDLE_COLOR (NM_META_COLOR_NONE);

	switch (info->info_type) {
	case NMC_GENERIC_INFO_TYPE_DHCP_CONFIG_OPTION:
		{
			GHashTable *table;
			gs_free char **arr2 = NULL;
			guint n;

			if (!NM_FLAGS_HAS (get_flags, NM_META_ACCESSOR_GET_FLAGS_ACCEPT_STRV))
				return NULL;

			table = nm_dhcp_config_get_options (dhcp);
			if (!table)
				goto arr_out;

			arr2 = (char **) nm_utils_strdict_get_keys (table, TRUE, &n);
			if (!n)
				goto arr_out;

			nm_assert (arr2 && !arr2[n] && n == NM_PTRARRAY_LEN (arr2));
			for (i = 0; i < n; i++) {
				const char *k = arr2[i];
				const char *v;

				nm_assert (k);
				v = g_hash_table_lookup (table, k);
				arr2[i] = g_strdup_printf ("%s = %s", k, v);
			}

			arr = g_steal_pointer (&arr2);
			goto arr_out;
		}
	default:
		break;
	}

	g_return_val_if_reached (NULL);

arr_out:
	NM_SET_OUT (out_is_default, !arr || !arr[0]);
	*out_flags |= NM_META_ACCESSOR_GET_OUT_FLAGS_STRV;
	*out_to_free = arr;
	return arr;
}

const NmcMetaGenericInfo *const metagen_dhcp_config[_NMC_GENERIC_INFO_TYPE_DHCP_CONFIG_NUM + 1] = {
#define _METAGEN_DHCP_CONFIG(type, name) \
	[type] = NMC_META_GENERIC(name, .info_type = type, .get_fcn = _metagen_dhcp_config_get_fcn)
	_METAGEN_DHCP_CONFIG (NMC_GENERIC_INFO_TYPE_DHCP_CONFIG_OPTION, "OPTION"),
};

/*****************************************************************************/

gboolean
print_ip_config (NMIPConfig *cfg,
                 int addr_family,
                 const NmcConfig *nmc_config,
                 const char *one_field)
{
	gs_free_error GError *error = NULL;
	gs_free char *field_str = NULL;

	if (!cfg)
		return FALSE;

	if (one_field) {
		field_str = g_strdup_printf ("IP%c.%s",
		                             nm_utils_addr_family_to_char (addr_family),
		                             one_field);
	}

	if (!nmc_print (nmc_config,
	                (gpointer[]) { cfg, NULL },
	                NULL,
	                NULL,
	                addr_family == AF_INET
	                  ? NMC_META_GENERIC_GROUP ("IP4", metagen_ip4_config, N_("GROUP"))
	                  : NMC_META_GENERIC_GROUP ("IP6", metagen_ip6_config, N_("GROUP")),
	                field_str,
	                &error)) {
		return FALSE;
	}
	return TRUE;
}

gboolean
print_dhcp_config (NMDhcpConfig *dhcp,
                   int addr_family,
                   const NmcConfig *nmc_config,
                   const char *one_field)
{
	gs_free_error GError *error = NULL;
	gs_free char *field_str = NULL;

	if (!dhcp)
		return FALSE;

	if (one_field) {
		field_str = g_strdup_printf ("DHCP%c.%s",
		                             nm_utils_addr_family_to_char (addr_family),
		                             one_field);
	}

	if (!nmc_print (nmc_config,
	                (gpointer[]) { dhcp, NULL },
	                NULL,
	                NULL,
	                addr_family == AF_INET
	                  ? NMC_META_GENERIC_GROUP ("DHCP4", metagen_dhcp_config, N_("GROUP"))
	                  : NMC_META_GENERIC_GROUP ("DHCP6", metagen_dhcp_config, N_("GROUP")),
	                field_str,
	                &error)) {
		return FALSE;
	}
	return TRUE;
}

/*
 * nmc_find_connection:
 * @connections: array of NMConnections to search in
 * @filter_type: "id", "uuid", "path", "filename", or %NULL
 * @filter_val: connection to find (connection name, UUID or path)
 * @out_result: if not NULL, attach all matching connection to this
 *   list. If necessary, a new array will be allocated. If the array
 *   already contains a connection, it will not be added a second time.
 *   All object are referenced by the array. If the function allocates
 *   a new array, it will set the free function to g_object_unref.
 * @complete: print possible completions
 *
 * Find a connection in @list according to @filter_val. @filter_type determines
 * what property is used for comparison. When @filter_type is NULL, compare
 * @filter_val against all types. Otherwise, only compare against the specified
 * type. If 'path' filter type is specified, comparison against numeric index
 * (in addition to the whole path) is allowed.
 *
 * Returns: found connection, or %NULL
 */
NMConnection *
nmc_find_connection (const GPtrArray *connections,
                     const char *filter_type,
                     const char *filter_val,
                     GPtrArray **out_result,
                     gboolean complete)
{
	NMConnection *connection;
	NMConnection *best_candidate = NULL;
	GPtrArray *result = out_result ? *out_result : NULL;
	guint i, j;

	nm_assert (connections);
	nm_assert (filter_val);

	for (i = 0; i < connections->len; i++) {
		const char *v, *v_num;

		connection = NM_CONNECTION (connections->pdata[i]);

		/* When filter_type is NULL, compare connection ID (filter_val)
		 * against all types. Otherwise, only compare against the specific
		 * type. If 'path' filter type is specified, comparison against
		 * numeric index (in addition to the whole path) is allowed.
		 */
		if (NM_IN_STRSET (filter_type, NULL, "id")) {
			v = nm_connection_get_id (connection);
			if (complete)
				nmc_complete_strings (filter_val, v, NULL);
			if (nm_streq0 (filter_val, v))
				goto found;
		}

		if (NM_IN_STRSET (filter_type, NULL, "uuid")) {
			v = nm_connection_get_uuid (connection);
			if (complete && (filter_type || *filter_val))
				nmc_complete_strings (filter_val, v, NULL);
			if (nm_streq0 (filter_val, v))
				goto found;
		}

		if (NM_IN_STRSET (filter_type, NULL, "path")) {
			v = nm_connection_get_path (connection);
			v_num = nm_utils_dbus_path_get_last_component (v);
			if (complete && (filter_type || *filter_val))
				nmc_complete_strings (filter_val, v, filter_type ? v_num : NULL, NULL);
			if (   nm_streq0 (filter_val, v)
			    || (filter_type && nm_streq0 (filter_val, v_num)))
				goto found;
		}

		if (NM_IN_STRSET (filter_type, NULL, "filename")) {
			v = nm_remote_connection_get_filename (NM_REMOTE_CONNECTION (connections->pdata[i]));
			if (complete && (filter_type || *filter_val))
				nmc_complete_strings (filter_val, v, NULL);
			if (nm_streq0 (filter_val, v))
				goto found;
		}

		continue;
found:
		if (!out_result)
			return connection;
		if (!best_candidate)
			best_candidate = connection;
		if (!result)
			result = g_ptr_array_new_with_free_func (g_object_unref);
		for (j = 0; j < result->len; j++) {
			if (connection == result->pdata[j])
				break;
		}
		if (j == result->len)
			g_ptr_array_add (result, g_object_ref (connection));
	}

	NM_SET_OUT (out_result, result);
	return best_candidate;
}

NMActiveConnection *
nmc_find_active_connection (const GPtrArray *active_cons,
                            const char *filter_type,
                            const char *filter_val,
                            GPtrArray **out_result,
                            gboolean complete)
{
	guint i, j;
	NMActiveConnection *best_candidate = NULL;
	GPtrArray *result = out_result ? *out_result : NULL;

	nm_assert (filter_val);

	for (i = 0; i < active_cons->len; i++) {
		NMRemoteConnection *con;
		NMActiveConnection *candidate = g_ptr_array_index (active_cons, i);
		const char *v, *v_num;

		con = nm_active_connection_get_connection (candidate);

		/* When filter_type is NULL, compare connection ID (filter_val)
		 * against all types. Otherwise, only compare against the specific
		 * type. If 'path' or 'apath' filter types are specified, comparison
		 * against numeric index (in addition to the whole path) is allowed.
		 */
		if (NM_IN_STRSET (filter_type, NULL, "id")) {
			v = nm_active_connection_get_id (candidate);
			if (complete)
				nmc_complete_strings (filter_val, v, NULL);
			if (nm_streq0 (filter_val, v))
				goto found;
		}

		if (NM_IN_STRSET (filter_type, NULL, "uuid")) {
			v = nm_active_connection_get_uuid (candidate);
			if (complete && (filter_type || *filter_val))
				nmc_complete_strings (filter_val, v, NULL);
			if (nm_streq0 (filter_val, v))
				goto found;
		}

		if (NM_IN_STRSET (filter_type, NULL, "path")) {
			v = con ? nm_connection_get_path (NM_CONNECTION (con)) : NULL;
			v_num = nm_utils_dbus_path_get_last_component (v);
			if (complete && (filter_type || *filter_val))
				nmc_complete_strings (filter_val, v, filter_type ? v_num : NULL, NULL);
			if (   nm_streq0 (filter_val, v)
			    || (filter_type && nm_streq0 (filter_val, v_num)))
				goto found;
		}

		if (NM_IN_STRSET (filter_type, NULL, "filename")) {
			v = nm_remote_connection_get_filename (con);
			if (complete && (filter_type || *filter_val))
				nmc_complete_strings (filter_val, v, NULL);
			if (nm_streq0 (filter_val, v))
				goto found;
		}

		if (NM_IN_STRSET (filter_type, NULL, "apath")) {
			v = nm_object_get_path (NM_OBJECT (candidate));
			v_num = nm_utils_dbus_path_get_last_component (v);
			if (complete && (filter_type || *filter_val))
				nmc_complete_strings (filter_val, v, filter_type ? v_num : NULL, NULL);
			if (   nm_streq0 (filter_val, v)
			    || (filter_type && nm_streq0 (filter_val, v_num)))
				goto found;
		}

		continue;

found:
		if (!out_result)
			return candidate;
		if (!best_candidate)
			best_candidate = candidate;
		if (!result)
			result = g_ptr_array_new_with_free_func (g_object_unref);
		for (j = 0; j < result->len; j++) {
			if (candidate == result->pdata[j])
				break;
		}
		if (j == result->len)
			g_ptr_array_add (result, g_object_ref (candidate));
	}

	NM_SET_OUT (out_result, result);
	return best_candidate;
}

static gboolean
vpn_openconnect_get_secrets (NMConnection *connection, GPtrArray *secrets)
{
	GError *error = NULL;
	NMSettingVpn *s_vpn;
	const char *gw, *port;
	gs_free char *cookie = NULL;
	gs_free char *gateway = NULL;
	gs_free char *gwcert = NULL;
	int status = 0;
	int i;
	gboolean ret;

	if (!connection)
		return FALSE;

	if (!nm_connection_is_type (connection, NM_SETTING_VPN_SETTING_NAME))
		return FALSE;

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (!nm_streq0 (nm_setting_vpn_get_service_type (s_vpn), NM_SECRET_AGENT_VPN_TYPE_OPENCONNECT))
		return FALSE;

	/* Get gateway and port */
	gw = nm_setting_vpn_get_data_item (s_vpn, "gateway");
	port = gw ? strrchr (gw, ':') : NULL;

	/* Interactively authenticate to OpenConnect server and get secrets */
	ret = nm_vpn_openconnect_authenticate_helper (gw, &cookie, &gateway, &gwcert, &status, &error);
	if (!ret) {
		g_printerr (_("Error: openconnect failed: %s\n"), error->message);
		g_clear_error (&error);
		return FALSE;
	}

	if (WIFEXITED (status)) {
		if (WEXITSTATUS (status) != 0)
			g_printerr (_("Error: openconnect failed with status %d\n"), WEXITSTATUS (status));
	} else if (WIFSIGNALED (status))
		g_printerr (_("Error: openconnect failed with signal %d\n"), WTERMSIG (status));

	/* Append port to the host value */
	if (gateway && port) {
		gs_free char *tmp = gateway;

		gateway = g_strdup_printf ("%s%s", tmp, port);
	}

	/* Fill secrets to the array */
	for (i = 0; i < secrets->len; i++) {
		NMSecretAgentSimpleSecret *secret = secrets->pdata[i];

		if (secret->secret_type != NM_SECRET_AGENT_SECRET_TYPE_VPN_SECRET)
			continue;
		if (!nm_streq0 (secret->vpn_type, NM_SECRET_AGENT_VPN_TYPE_OPENCONNECT))
			continue;

		if (nm_streq0 (secret->entry_id, NM_SECRET_AGENT_ENTRY_ID_PREFX_VPN_SECRETS "cookie")) {
			g_free (secret->value);
			secret->value = g_steal_pointer (&cookie);
		} else if (nm_streq0 (secret->entry_id, NM_SECRET_AGENT_ENTRY_ID_PREFX_VPN_SECRETS "gateway")) {
			g_free (secret->value);
			secret->value = g_steal_pointer (&gateway);
		} else if (nm_streq0 (secret->entry_id, NM_SECRET_AGENT_ENTRY_ID_PREFX_VPN_SECRETS "gwcert")) {
			g_free (secret->value);
			secret->value = g_steal_pointer (&gwcert);
		}
	}

	return TRUE;
}

static gboolean
get_secrets_from_user (const NmcConfig *nmc_config,
                       const char *request_id,
                       const char *title,
                       const char *msg,
                       NMConnection *connection,
                       gboolean ask,
                       GHashTable *pwds_hash,
                       GPtrArray *secrets)
{
	int i;

	/* Check if there is a VPN OpenConnect secret to ask for */
	if (ask)
		vpn_openconnect_get_secrets (connection, secrets);

	for (i = 0; i < secrets->len; i++) {
		NMSecretAgentSimpleSecret *secret = secrets->pdata[i];
		char *pwd = NULL;

		/* First try to find the password in provided passwords file,
		 * then ask user. */
		if (pwds_hash && (pwd = g_hash_table_lookup (pwds_hash, secret->entry_id))) {
			pwd = g_strdup (pwd);
		} else {
			if (ask) {
				gboolean echo_on;

				if (secret->value) {
					if (!g_strcmp0 (secret->vpn_type, NM_DBUS_INTERFACE ".openconnect")) {
						/* Do not present and ask user for openconnect secrets, we already have them */
						continue;
					} else {
						/* Prefill the password if we have it. */
						rl_startup_hook = nmc_rl_set_deftext;
						nmc_rl_pre_input_deftext = g_strdup (secret->value);
					}
				}
				if (msg)
					g_print ("%s\n", msg);

				echo_on = secret->is_secret
				          ? nmc_config->show_secrets
				          : TRUE;

				if (secret->no_prompt_entry_id)
					pwd = nmc_readline_echo (nmc_config, echo_on, "%s: ", secret->pretty_name);
				else
					pwd = nmc_readline_echo (nmc_config, echo_on, "%s (%s): ", secret->pretty_name, secret->entry_id);

				if (!pwd)
					pwd = g_strdup ("");
			} else {
				if (msg)
					g_print ("%s\n", msg);
				g_printerr (_("Warning: password for '%s' not given in 'passwd-file' "
				              "and nmcli cannot ask without '--ask' option.\n"),
				            secret->entry_id);
			}
		}
		/* No password provided, cancel the secrets. */
		if (!pwd)
			return FALSE;
		g_free (secret->value);
		secret->value = pwd;
	}
	return TRUE;
}

/**
 * nmc_secrets_requested:
 * @agent: the #NMSecretAgentSimple
 * @request_id: request ID, to eventually pass to
 *   nm_secret_agent_simple_response()
 * @title: a title for the password request
 * @msg: a prompt message for the password request
 * @secrets: (element-type #NMSecretAgentSimpleSecret): array of secrets
 *   being requested.
 * @user_data: user data passed to the function
 *
 * This function is used as a callback for "request-secrets" signal of
 * NMSecretAgentSimpleSecret.
*/
void
nmc_secrets_requested (NMSecretAgentSimple *agent,
                       const char          *request_id,
                       const char          *title,
                       const char          *msg,
                       GPtrArray           *secrets,
                       gpointer             user_data)
{
	NmCli *nmc = (NmCli *) user_data;
	NMConnection *connection = NULL;
	char *path, *p;
	gboolean success = FALSE;
	const GPtrArray *connections;

	if (nmc->nmc_config.print_output == NMC_PRINT_PRETTY)
		nmc_terminal_erase_line ();

	/* Find the connection for the request */
	path = g_strdup (request_id);
	if (path) {
		p = strrchr (path, '/');
		if (p)
			*p = '\0';
		connections = nm_client_get_connections (nmc->client);
		connection = nmc_find_connection (connections, "path", path, NULL, FALSE);
		g_free (path);
	}

	success = get_secrets_from_user (&nmc->nmc_config,
	                                 request_id,
	                                 title,
	                                 msg,
	                                 connection,
	                                 nmc->nmc_config.in_editor || nmc->ask,
	                                 nmc->pwds_hash,
	                                 secrets);
	if (success)
		nm_secret_agent_simple_response (agent, request_id, secrets);
	else {
		/* Unregister our secret agent on failure, so that another agent
		 * may be tried */
		if (nmc->secret_agent) {
			nm_secret_agent_old_unregister (NM_SECRET_AGENT_OLD (nmc->secret_agent), NULL, NULL);
			g_clear_object (&nmc->secret_agent);
		}
	}
}

char *
nmc_unique_connection_name (const GPtrArray *connections, const char *try_name)
{
	NMConnection *connection;
	const char *name;
	char *new_name;
	unsigned num = 1;
	int i = 0;

	new_name = g_strdup (try_name);
	while (i < connections->len) {
		connection = NM_CONNECTION (connections->pdata[i]);

		name = nm_connection_get_id (connection);
		if (g_strcmp0 (new_name, name) == 0) {
			g_free (new_name);
			new_name = g_strdup_printf ("%s-%d", try_name, num++);
			i = 0;
		} else
			i++;
	}
	return new_name;
}

/* readline state variables */
static gboolean nmcli_in_readline = FALSE;
static gboolean rl_got_line;
static char *rl_string;

/**
 * nmc_cleanup_readline:
 *
 * Cleanup readline when nmcli is terminated with a signal.
 * It makes sure the terminal is not garbled.
 */
void
nmc_cleanup_readline (void)
{
	rl_free_line_state ();
	rl_cleanup_after_signal ();
}

gboolean
nmc_get_in_readline (void)
{
	return nmcli_in_readline;
}

void
nmc_set_in_readline (gboolean in_readline)
{
	nmcli_in_readline = in_readline;
}

static void
readline_cb (char *line)
{
	rl_got_line = TRUE;
	rl_string = line;
	rl_callback_handler_remove ();
}

static gboolean
stdin_ready_cb (GIOChannel * io, GIOCondition condition, gpointer data)
{
	rl_callback_read_char ();
	return TRUE;
}

static char *
nmc_readline_helper (const NmcConfig *nmc_config,
                     const char *prompt)
{
	GIOChannel *io = NULL;
	guint io_watch_id;

	nmc_set_in_readline (TRUE);

	io = g_io_channel_unix_new (STDIN_FILENO);
	io_watch_id = g_io_add_watch (io, G_IO_IN, stdin_ready_cb, NULL);
	g_io_channel_unref (io);

read_again:
	rl_string = NULL;
	rl_got_line = FALSE;
	rl_callback_handler_install (prompt, readline_cb);

	while (   !rl_got_line
	       && g_main_loop_is_running (loop)
	       && !nmc_seen_sigint ())
		g_main_context_iteration (NULL, TRUE);

	/* If Ctrl-C was detected, complete the line */
	if (nmc_seen_sigint ()) {
		rl_echo_signal_char (SIGINT);
		if (!rl_got_line) {
			rl_stuff_char ('\n');
			rl_callback_read_char ();
		}
	}

	/* Add string to the history */
	if (rl_string && *rl_string)
		add_history (rl_string);

	if (nmc_seen_sigint ()) {
		/* Ctrl-C */
		nmc_clear_sigint ();
		if (   nmc_config->in_editor
		    || (rl_string  && *rl_string)) {
			/* In editor, or the line is not empty */
			/* Call readline again to get new prompt (repeat) */
			g_free (rl_string);
			goto read_again;
		} else {
			/* Not in editor and line is empty, exit */
			nmc_exit ();
		}
	} else if (!rl_string) {
		/* Ctrl-D, exit */
		nmc_exit ();
	}

	/* Return NULL, not empty string */
	if (rl_string && *rl_string == '\0') {
		g_free (rl_string);
		rl_string = NULL;
	}

	g_source_remove (io_watch_id);
	nmc_set_in_readline (FALSE);

	return rl_string;
}

/**
 * nmc_readline:
 * @prompt_fmt: prompt to print (telling user what to enter). It is standard
 *   printf() format string
 * @...: a list of arguments according to the @prompt_fmt format string
 *
 * Wrapper around libreadline's readline() function.
 * If user pressed Ctrl-C, readline() is called again (if not in editor and
 * line is empty, nmcli will quit).
 * If user pressed Ctrl-D on empty line, nmcli will quit.
 *
 * Returns: the user provided string. In case the user entered empty string,
 * this function returns NULL.
 */
char *
nmc_readline (const NmcConfig *nmc_config,
              const char *prompt_fmt,
              ...)
{
	va_list args;
	gs_free char *prompt = NULL;

	rl_initialize ();

	va_start (args, prompt_fmt);
	prompt = g_strdup_vprintf (prompt_fmt, args);
	va_end (args);
	return nmc_readline_helper (nmc_config, prompt);
}

static void
nmc_secret_redisplay (void)
{
	int save_point = rl_point;
	int save_end = rl_end;
	char *save_line_buffer = rl_line_buffer;
	const char *subst = nmc_password_subst_char ();
	int subst_len = strlen (subst);
	int i;

	rl_point = g_utf8_strlen (save_line_buffer, save_point) * subst_len;
	rl_end = g_utf8_strlen (rl_line_buffer, -1) * subst_len;
	rl_line_buffer = g_slice_alloc (rl_end + 1);

	for (i = 0; i + subst_len <= rl_end; i += subst_len)
		memcpy (&rl_line_buffer[i], subst, subst_len);
	rl_line_buffer[i] = '\0';

	rl_redisplay ();
	g_slice_free1 (rl_end + 1, rl_line_buffer);
	rl_line_buffer = save_line_buffer;
	rl_end = save_end;
	rl_point = save_point;
}

/**
 * nmc_readline_echo:
 *
 * The same as nmc_readline() except it can disable echoing of input characters if @echo_on is %FALSE.
 * nmc_readline(TRUE, ...) == nmc_readline(...)
 */
char *
nmc_readline_echo (const NmcConfig *nmc_config,
                   gboolean echo_on,
                   const char *prompt_fmt,
                   ...)
{
	va_list args;
	gs_free char *prompt = NULL;
	char *str;
	HISTORY_STATE *saved_history;
	HISTORY_STATE passwd_history = { 0, };

	va_start (args, prompt_fmt);
	prompt = g_strdup_vprintf (prompt_fmt, args);
	va_end (args);

	rl_initialize ();

	/* Hide the actual password */
	if (!echo_on) {
		saved_history = history_get_history_state ();
		history_set_history_state (&passwd_history);
		rl_redisplay_function = nmc_secret_redisplay;
	}

	str = nmc_readline_helper (nmc_config, prompt);

	/* Restore the non-hiding behavior */
	if (!echo_on) {
		rl_redisplay_function = rl_redisplay;
		history_set_history_state (saved_history);
	}

	return str;
}

/**
 * nmc_rl_gen_func_basic:
 * @text: text to complete
 * @state: readline state; says whether start from scratch (state == 0)
 * @words: strings for completion
 *
 * Basic function generating list of completion strings for readline.
 * See e.g. http://cnswww.cns.cwru.edu/php/chet/readline/readline.html#SEC49
 */
char *
nmc_rl_gen_func_basic (const char *text, int state, const char *const*words)
{
	static int list_idx, len;
	const char *name;

	if (!state) {
		list_idx = 0;
		len = strlen (text);
	}

	/* Return the next name which partially matches one from the 'words' list. */
	while ((name = words[list_idx])) {
		list_idx++;

		if (strncmp (name, text, len) == 0)
			return g_strdup (name);
	}
	return NULL;
}

static struct {
	bool initialized;
	guint idx;
	char **values;
} _rl_compentry_func_wrap = { 0 };

static char *
_rl_compentry_func_wrap_fcn (const char *text, int state)
{
	g_return_val_if_fail (_rl_compentry_func_wrap.initialized, NULL);

	while (   _rl_compentry_func_wrap.values
	       && _rl_compentry_func_wrap.values[_rl_compentry_func_wrap.idx]
	       && !g_str_has_prefix (_rl_compentry_func_wrap.values[_rl_compentry_func_wrap.idx], text))
		_rl_compentry_func_wrap.idx++;

	if (   !_rl_compentry_func_wrap.values
	    || !_rl_compentry_func_wrap.values[_rl_compentry_func_wrap.idx]) {
		g_strfreev (_rl_compentry_func_wrap.values);
		_rl_compentry_func_wrap.values = NULL;
		_rl_compentry_func_wrap.initialized = FALSE;
		return NULL;
	}

	return g_strdup (_rl_compentry_func_wrap.values[_rl_compentry_func_wrap.idx++]);
}

NmcCompEntryFunc
nmc_rl_compentry_func_wrap (const char *const*values)
{
	g_strfreev (_rl_compentry_func_wrap.values);
	_rl_compentry_func_wrap.values = g_strdupv ((char **) values);
	_rl_compentry_func_wrap.idx = 0;
	_rl_compentry_func_wrap.initialized = TRUE;
	return _rl_compentry_func_wrap_fcn;
}

char *
nmc_rl_gen_func_ifnames (const char *text, int state)
{
	int i;
	const GPtrArray *devices;
	const char **ifnames;
	char *ret;

	devices = nm_client_get_devices (nm_cli.client);
	if (devices->len == 0)
		return NULL;

	ifnames = g_new (const char *, devices->len + 1);
	for (i = 0; i < devices->len; i++) {
		NMDevice *dev = g_ptr_array_index (devices, i);
		const char *ifname = nm_device_get_iface (dev);
		ifnames[i] = ifname;
	}
	ifnames[i] = NULL;

	ret = nmc_rl_gen_func_basic (text, state, ifnames);

	g_free (ifnames);
	return ret;
}

/* for pre-filling a string to readline prompt */
char *nmc_rl_pre_input_deftext;

int
nmc_rl_set_deftext (void)
{
	if (nmc_rl_pre_input_deftext && rl_startup_hook) {
		rl_insert_text (nmc_rl_pre_input_deftext);
		g_free (nmc_rl_pre_input_deftext);
		nmc_rl_pre_input_deftext = NULL;
		rl_startup_hook = NULL;
	}
	return 0;
}

/**
 * nmc_parse_lldp_capabilities:
 * @value: the capabilities value
 *
 * Parses LLDP capabilities flags
 *
 * Returns: a newly allocated string containing capabilities names separated by commas.
 */
char *
nmc_parse_lldp_capabilities (guint value)
{
	/* IEEE Std 802.1AB-2009 - Table 8.4 */
	const char *names[] = { "other", "repeater", "mac-bridge", "wlan-access-point",
	                        "router", "telephone", "docsis-cable-device", "station-only",
	                        "c-vlan-component", "s-vlan-component", "tpmr" };
	gboolean first = TRUE;
	GString *str;
	int i;

	if (!value)
		return g_strdup ("none");

	str = g_string_new ("");

	for (i = 0; i < G_N_ELEMENTS (names); i++) {
		if (value & (1 << i)) {
			if (!first)
				g_string_append_c (str, ',');

			first = FALSE;
			value &= ~(1 << i);
			g_string_append (str, names[i]);
		}
	}

	if (value) {
		if (!first)
			g_string_append_c (str, ',');
		g_string_append (str, "reserved");
	}

	return g_string_free (str, FALSE);
}

static void
command_done (GObject *object, GAsyncResult *res, gpointer user_data)
{
	GSimpleAsyncResult *simple = (GSimpleAsyncResult *)res;
	NmCli *nmc = user_data;
	GError *error = NULL;

	if (g_simple_async_result_propagate_error (simple, &error)) {
		nmc->return_value = error->code;
		g_string_assign (nmc->return_text, error->message);
		g_error_free (error);
	}

	if (!nmc->should_wait)
		g_main_loop_quit (loop);
}

typedef struct {
	NmCli *nmc;
	const NMCCommand *cmd;
	int argc;
	char **argv;
	GSimpleAsyncResult *simple;
} CmdCall;

static void
call_cmd (NmCli *nmc, GSimpleAsyncResult *simple, const NMCCommand *cmd, int argc, char **argv);

static void
got_client (GObject *source_object, GAsyncResult *res, gpointer user_data)
{
	GError *error = NULL;
	CmdCall *call = user_data;
	NmCli *nmc = call->nmc;

	nmc->should_wait--;
	nmc->client = nm_client_new_finish (res, &error);

	if (!nmc->client) {
		g_simple_async_result_set_error (call->simple, NMCLI_ERROR, NMC_RESULT_ERROR_UNKNOWN,
		                                 _("Error: Could not create NMClient object: %s."), error->message);
		g_error_free (error);
		g_simple_async_result_complete (call->simple);
	} else {
		call_cmd (nmc, call->simple, call->cmd, call->argc, call->argv);
	}

	g_slice_free (CmdCall, call);
}

static void
call_cmd (NmCli *nmc, GSimpleAsyncResult *simple, const NMCCommand *cmd, int argc, char **argv)
{
	CmdCall *call;

	if (nmc->client || !cmd->needs_client) {

		/* Check whether NetworkManager is running */
		if (cmd->needs_nm_running && !nm_client_get_nm_running (nmc->client)) {
			g_simple_async_result_set_error (simple, NMCLI_ERROR, NMC_RESULT_ERROR_NM_NOT_RUNNING,
			                                 _("Error: NetworkManager is not running."));
		} else
			nmc->return_value = cmd->func (nmc, argc, argv);
		g_simple_async_result_complete_in_idle (simple);
		g_object_unref (simple);
	} else {
		nmc->should_wait++;
		call = g_slice_new0 (CmdCall);
		call->nmc = nmc;
		call->cmd = cmd;
		call->argc = argc;
		call->argv = argv;
		call->simple = simple;
		nm_client_new_async (NULL, got_client, call);
	}
}

static void
nmc_complete_help (const char *prefix)
{
	nmc_complete_strings (prefix, "help", NULL);
	if (*prefix == '-')
		nmc_complete_strings (prefix, "-help", "--help", NULL);
}

/**
 * nmc_do_cmd:
 * @nmc: Client instance
 * @cmds: Command table
 * @cmd: Command
 * @argc: Argument count
 * @argv: Arguments vector. Must be a global variable.
 *
 * Picks the right callback to handle command from the command table.
 * If --help argument follows and the usage callback is specified for the command
 * it calls the usage callback.
 *
 * The command table is terminated with a %NULL command. The terminating
 * entry's handlers are called if the command is empty.
 *
 * The argument vector needs to be a pointer to the global arguments vector that is
 * never freed, since the command handler will be called asynchronously and there's
 * no callback to free the memory in (for simplicity).
 */
void
nmc_do_cmd (NmCli *nmc, const NMCCommand cmds[], const char *cmd, int argc, char **argv)
{
	const NMCCommand *c;
	GSimpleAsyncResult *simple;

	simple = g_simple_async_result_new (NULL,
	                                    command_done,
	                                    nmc,
	                                    nmc_do_cmd);

	if (argc == 0 && nmc->complete) {
		g_simple_async_result_complete_in_idle (simple);
		g_object_unref (simple);
		return;
	}

	if (argc == 1 && nmc->complete) {
		for (c = cmds; c->cmd; ++c) {
			if (!*cmd || matches (cmd, c->cmd))
				g_print ("%s\n", c->cmd);
		}
		nmc_complete_help (cmd);
		g_simple_async_result_complete_in_idle (simple);
		g_object_unref (simple);
		return;
	}

	for (c = cmds; c->cmd; ++c) {
		if (cmd && matches (cmd, c->cmd))
			break;
	}

	if (c->cmd) {
		/* A valid command was specified. */
		if (c->usage && argc == 2 && nmc->complete)
			nmc_complete_help (*(argv+1));
		if (!nmc->complete && c->usage && nmc_arg_is_help (*(argv+1))) {
			c->usage ();
			g_simple_async_result_complete_in_idle (simple);
			g_object_unref (simple);
		} else {
			call_cmd (nmc, simple, c, argc, argv);
		}
	} else if (cmd) {
		/* Not a known command. */
		if (nmc_arg_is_help (cmd) && c->usage) {
			c->usage ();
			g_simple_async_result_complete_in_idle (simple);
			g_object_unref (simple);
		} else {
			g_simple_async_result_set_error (simple, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			                                 _("Error: argument '%s' not understood. Try passing --help instead."), cmd);
			g_simple_async_result_complete_in_idle (simple);
			g_object_unref (simple);
		}
	} else if (c->func) {
		/* No command, run the default handler. */
		call_cmd (nmc, simple, c, argc, argv);
	} else {
		/* No command and no default handler. */
		g_simple_async_result_set_error (simple, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		                                 _("Error: missing argument. Try passing --help."));
		g_simple_async_result_complete_in_idle (simple);
		g_object_unref (simple);
	}
}

/**
 * nmc_complete_strings:
 * @prefix: a string to match
 * @nargs: the number of elements in @args. Or -1 if @args is a NULL terminated
 *   strv array.
 * @args: the argument list. If @nargs is not -1, then some elements may
 *   be %NULL to indicate to silently skip the values.
 *
 * Prints all the matching candidates for completion. Useful when there's
 * no better way to suggest completion other than a hardcoded string list.
 */
void
nmc_complete_strv (const char *prefix, gssize nargs, const char *const*args)
{
	gsize i, n;

	if (prefix && !prefix[0])
		prefix = NULL;

	if (nargs < 0) {
		nm_assert (nargs == -1);
		n = NM_PTRARRAY_LEN (args);
	} else
		n = (gsize) nargs;

	for (i = 0; i < n; i++) {
		const char *candidate = args[i];

		if (!candidate)
			continue;
		if (   prefix
		    && !matches (prefix, candidate))
			continue;

		g_print ("%s\n", candidate);
	}
}

/**
 * nmc_complete_bool:
 * @prefix: a string to match
 * @...: a %NULL-terminated list of candidate strings
 *
 * Prints all the matching possible boolean values for completion.
 */
void
nmc_complete_bool (const char *prefix)
{
	nmc_complete_strings (prefix, "true", "yes", "on",
	                              "false", "no", "off", NULL);
}

/**
 * nmc_error_get_simple_message:
 * @error: a GError
 *
 * Returns a simplified message for some errors hard to understand.
 */
const char *
nmc_error_get_simple_message (GError *error)
{
	/* Return a clear message instead of the obscure D-Bus policy error */
	if (g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_ACCESS_DENIED))
		return _("access denied");
	else
		return error->message;
}

/*****************************************************************************/

NM_UTILS_LOOKUP_STR_DEFINE (nm_connectivity_to_string, NMConnectivityState,
	NM_UTILS_LOOKUP_DEFAULT (N_("unknown")),
	NM_UTILS_LOOKUP_ITEM (NM_CONNECTIVITY_NONE,    N_("none")),
	NM_UTILS_LOOKUP_ITEM (NM_CONNECTIVITY_PORTAL,  N_("portal")),
	NM_UTILS_LOOKUP_ITEM (NM_CONNECTIVITY_LIMITED, N_("limited")),
	NM_UTILS_LOOKUP_ITEM (NM_CONNECTIVITY_FULL,    N_("full")),
	NM_UTILS_LOOKUP_ITEM_IGNORE (NM_CONNECTIVITY_UNKNOWN),
);
