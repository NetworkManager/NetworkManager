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
 * Copyright 2012 - 2014 Red Hat, Inc.
 */

#include "nm-default.h"

#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <readline/readline.h>
#include <readline/history.h>

#include "nm-utils/nm-hash-utils.h"
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

static gconstpointer
_metagen_ip4_config_get_fcn (const NMMetaEnvironment *environment,
                             gpointer environment_user_data,
                             const NmcMetaGenericInfo *info,
                             gpointer target,
                             NMMetaAccessorGetType get_type,
                             NMMetaAccessorGetFlags get_flags,
                             NMMetaAccessorGetOutFlags *out_flags,
                             gpointer *out_to_free)
{
	NMIPConfig *cfg4 = target;
	GPtrArray *ptr_array;
	char **arr;
	const char *const*arrc;
	guint i = 0;

	nm_assert (info->info_type < _NMC_GENERIC_INFO_TYPE_IP4_CONFIG_NUM);

	NMC_HANDLE_TERMFORMAT (NM_META_TERM_COLOR_NORMAL);

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
		return nm_ip_config_get_gateway (cfg4);
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
	*out_flags |= NM_META_ACCESSOR_GET_OUT_FLAGS_STRV;
	return arrc;

arr_out:
	*out_flags |= NM_META_ACCESSOR_GET_OUT_FLAGS_STRV;
	*out_to_free = arr;
	return arr;
}

static gconstpointer
_metagen_ip6_config_get_fcn (const NMMetaEnvironment *environment,
                             gpointer environment_user_data,
                             const NmcMetaGenericInfo *info,
                             gpointer target,
                             NMMetaAccessorGetType get_type,
                             NMMetaAccessorGetFlags get_flags,
                             NMMetaAccessorGetOutFlags *out_flags,
                             gpointer *out_to_free)
{
	NMIPConfig *cfg6 = target;
	GPtrArray *ptr_array;
	char **arr;
	const char *const*arrc;
	guint i = 0;

	nm_assert (info->info_type < _NMC_GENERIC_INFO_TYPE_IP6_CONFIG_NUM);

	NMC_HANDLE_TERMFORMAT (NM_META_TERM_COLOR_NORMAL);

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
		return nm_ip_config_get_gateway (cfg6);
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
	*out_flags |= NM_META_ACCESSOR_GET_OUT_FLAGS_STRV;
	return arrc;

arr_out:
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

static const NmcMetaGenericInfo *const metagen_ip4_config_group[] = {
	NMC_META_GENERIC_WITH_NESTED ("IP4", metagen_ip4_config, .name_header = N_("GROUP")),
	NULL,
};

const NmcMetaGenericInfo *const metagen_ip6_config[_NMC_GENERIC_INFO_TYPE_IP6_CONFIG_NUM + 1] = {
#define _METAGEN_IP6_CONFIG(type, name) \
	[type] = NMC_META_GENERIC(name, .info_type = type, .get_fcn = _metagen_ip6_config_get_fcn)
	_METAGEN_IP6_CONFIG (NMC_GENERIC_INFO_TYPE_IP6_CONFIG_ADDRESS, "ADDRESS"),
	_METAGEN_IP6_CONFIG (NMC_GENERIC_INFO_TYPE_IP6_CONFIG_GATEWAY, "GATEWAY"),
	_METAGEN_IP6_CONFIG (NMC_GENERIC_INFO_TYPE_IP6_CONFIG_ROUTE,   "ROUTE"),
	_METAGEN_IP6_CONFIG (NMC_GENERIC_INFO_TYPE_IP6_CONFIG_DNS,     "DNS"),
	_METAGEN_IP6_CONFIG (NMC_GENERIC_INFO_TYPE_IP6_CONFIG_DOMAIN,  "DOMAIN"),
};

static const NmcMetaGenericInfo *const metagen_ip6_config_group[] = {
	NMC_META_GENERIC_WITH_NESTED ("IP6", metagen_ip6_config, .name_header = N_("GROUP")),
	NULL,
};

/*****************************************************************************/

const NmcMetaGenericInfo *const nmc_fields_dhcp4_config[] = {
	NMC_META_GENERIC ("GROUP"),    /* 0 */
	NMC_META_GENERIC ("OPTION"),   /* 1 */
	NULL,
};

const NmcMetaGenericInfo *const nmc_fields_ip6_config[] = {
	NMC_META_GENERIC ("GROUP"),     /* 0 */
	NMC_META_GENERIC ("ADDRESS"),   /* 1 */
	NMC_META_GENERIC ("GATEWAY"),   /* 2 */
	NMC_META_GENERIC ("ROUTE"),     /* 3 */
	NMC_META_GENERIC ("DNS"),       /* 4 */
	NMC_META_GENERIC ("DOMAIN"),    /* 5 */
	NULL,
};

const NmcMetaGenericInfo *const nmc_fields_dhcp6_config[] = {
	NMC_META_GENERIC ("GROUP"),    /* 0 */
	NMC_META_GENERIC ("OPTION"),   /* 1 */
	NULL,
};

gboolean
print_ip4_config (NMIPConfig *cfg4,
                  const NmcConfig *nmc_config,
                  const char *one_field)
{
	gs_free_error GError *error = NULL;
	gs_free char *field_str = NULL;

	if (cfg4 == NULL)
		return FALSE;

	if (one_field)
		field_str = g_strdup_printf ("IP4.%s", one_field);

	if (!nmc_print (nmc_config,
	                (gpointer[]) { cfg4, NULL },
	                NULL,
	                (const NMMetaAbstractInfo *const*) metagen_ip4_config_group,
	                field_str,
	                &error)) {
		return FALSE;
	}
	return TRUE;
}

gboolean
print_ip6_config (NMIPConfig *cfg6,
                  const NmcConfig *nmc_config,
                  const char *group_prefix,
                  const char *one_field)
{
	gs_free_error GError *error = NULL;
	gs_free char *field_str = NULL;

	if (cfg6 == NULL)
		return FALSE;

	if (one_field)
		field_str = g_strdup_printf ("IP6.%s", one_field);

	if (!nmc_print (nmc_config,
	                (gpointer[]) { cfg6, NULL },
	                NULL,
	                (const NMMetaAbstractInfo *const*) metagen_ip6_config_group,
	                field_str,
	                &error)) {
		return FALSE;
	}
	return TRUE;
}

gboolean
print_dhcp4_config (NMDhcpConfig *dhcp4,
                    const NmcConfig *nmc_config,
                    const char *group_prefix,
                    const char *one_field)
{
	GHashTable *table;
	const NMMetaAbstractInfo *const*tmpl;
	NmcOutputField *arr;

	if (dhcp4 == NULL)
		return FALSE;

	table = nm_dhcp_config_get_options (dhcp4);
	if (table) {
		GHashTableIter table_iter;
		gpointer key, value;
		char **options_arr = NULL;
		int i = 0;
		NMC_OUTPUT_DATA_DEFINE_SCOPED (out);

		tmpl = (const NMMetaAbstractInfo *const*) nmc_fields_dhcp4_config;
		out_indices = parse_output_fields (one_field,
		                                   tmpl, FALSE, NULL, NULL);
		arr = nmc_dup_fields_array (tmpl, NMC_OF_FLAG_FIELD_NAMES);
		g_ptr_array_add (out.output_data, arr);

		options_arr = g_new (char *, g_hash_table_size (table) + 1);
		g_hash_table_iter_init (&table_iter, table);
		while (g_hash_table_iter_next (&table_iter, &key, &value))
			options_arr[i++] = g_strdup_printf ("%s = %s", (char *) key, (char *) value);
		options_arr[i] = NULL;

		arr = nmc_dup_fields_array (tmpl, NMC_OF_FLAG_SECTION_PREFIX);
		set_val_strc (arr, 0, group_prefix);
		set_val_arr  (arr, 1, options_arr);
		g_ptr_array_add (out.output_data, arr);

		print_data_prepare_width (out.output_data);
		print_data (nmc_config, out_indices, NULL, 0, &out);

		return TRUE;
	}
	return FALSE;
}

gboolean
print_dhcp6_config (NMDhcpConfig *dhcp6,
                    const NmcConfig *nmc_config,
                    const char *group_prefix,
                    const char *one_field)
{
	GHashTable *table;
	const NMMetaAbstractInfo *const*tmpl;
	NmcOutputField *arr;

	if (dhcp6 == NULL)
		return FALSE;

	table = nm_dhcp_config_get_options (dhcp6);
	if (table) {
		GHashTableIter table_iter;
		gpointer key, value;
		char **options_arr = NULL;
		int i = 0;
		NMC_OUTPUT_DATA_DEFINE_SCOPED (out);

		tmpl = (const NMMetaAbstractInfo *const*) nmc_fields_dhcp6_config;
		out_indices = parse_output_fields (one_field,
		                                   tmpl, FALSE, NULL, NULL);
		arr = nmc_dup_fields_array (tmpl, NMC_OF_FLAG_FIELD_NAMES);
		g_ptr_array_add (out.output_data, arr);

		options_arr = g_new (char *, g_hash_table_size (table) + 1);
		g_hash_table_iter_init (&table_iter, table);
		while (g_hash_table_iter_next (&table_iter, &key, &value))
			options_arr[i++] = g_strdup_printf ("%s = %s", (char *) key, (char *) value);
		options_arr[i] = NULL;

		arr = nmc_dup_fields_array (tmpl, NMC_OF_FLAG_SECTION_PREFIX);
		set_val_strc (arr, 0, group_prefix);
		set_val_arr  (arr, 1, options_arr);
		g_ptr_array_add (out.output_data, arr);

		print_data_prepare_width (out.output_data);
		print_data (nmc_config, out_indices, NULL, 0, &out);

		return TRUE;
	}
	return FALSE;
}

/*
 * nmc_find_connection:
 * @connections: array of NMConnections to search in
 * @filter_type: "id", "uuid", "path" or %NULL
 * @filter_val: connection to find (connection name, UUID or path)
 * @start: where to start in @list. The location is updated so that the function
 *   can be called multiple times (for connections with the same name).
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
                     int *start,
                     gboolean complete)
{
	NMConnection *connection;
	NMConnection *found = NULL;
	int i;
	const char *id;
	const char *uuid;
	const char *path, *path_num;

	for (i = start ? *start : 0; i < connections->len; i++) {
		connection = NM_CONNECTION (connections->pdata[i]);

		id = nm_connection_get_id (connection);
		uuid = nm_connection_get_uuid (connection);
		path = nm_connection_get_path (connection);
		path_num = path ? strrchr (path, '/') + 1 : NULL;

		/* When filter_type is NULL, compare connection ID (filter_val)
		 * against all types. Otherwise, only compare against the specific
		 * type. If 'path' filter type is specified, comparison against
		 * numeric index (in addition to the whole path) is allowed.
		 */
		if (!filter_type || strcmp (filter_type, "id")  == 0) {
			if (complete)
				nmc_complete_strings (filter_val, id, NULL);
			if (strcmp (filter_val, id) == 0)
				goto found;
		}

		if (!filter_type || strcmp (filter_type, "uuid") == 0) {
			if (complete && (filter_type || *filter_val))
				nmc_complete_strings (filter_val, uuid, NULL);
			if (strcmp (filter_val, uuid) == 0)
				goto found;
		}

		if (!filter_type || strcmp (filter_type, "path") == 0) {
			if (complete && (filter_type || *filter_val))
				nmc_complete_strings (filter_val, path, filter_type ? path_num : NULL, NULL);
		        if (g_strcmp0 (filter_val, path) == 0 || (filter_type && g_strcmp0 (filter_val, path_num) == 0))
				goto found;
		}

		continue;
found:
		if (!start)
			return connection;
		if (found) {
			*start = i;
			return found;
		}
		found = connection;
	}

	if (start)
		*start = 0;
	return found;
}

static gboolean
vpn_openconnect_get_secrets (NMConnection *connection, GPtrArray *secrets)
{
	GError *error = NULL;
	NMSettingVpn *s_vpn;
	const char *vpn_type, *gw, *port;
	char *cookie = NULL;
	char *gateway = NULL;
	char *gwcert = NULL;
	int status = 0;
	int i;
	gboolean ret;

	if (!connection)
		return FALSE;

	if (!nm_connection_is_type (connection, NM_SETTING_VPN_SETTING_NAME))
		return FALSE;

	s_vpn = nm_connection_get_setting_vpn (connection);
	vpn_type = nm_setting_vpn_get_service_type (s_vpn);
	if (g_strcmp0 (vpn_type, NM_DBUS_INTERFACE ".openconnect"))
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
		char *tmp = gateway;
		gateway = g_strdup_printf ("%s%s", gateway, port);
		g_free (tmp);
	}

	/* Fill secrets to the array */
	for (i = 0; i < secrets->len; i++) {
		NMSecretAgentSimpleSecret *secret = secrets->pdata[i];

		if (!g_strcmp0 (secret->vpn_type, vpn_type)) {
			if (!g_strcmp0 (secret->vpn_property, "cookie")) {
				g_free (secret->value);
				secret->value = cookie;
				cookie = NULL;
			} else if (!g_strcmp0 (secret->vpn_property, "gateway")) {
				g_free (secret->value);
				secret->value = gateway;
				gateway = NULL;
			} else if (!g_strcmp0 (secret->vpn_property, "gwcert")) {
				g_free (secret->value);
				secret->value = gwcert;
				gwcert = NULL;
			}
		}
	}
	g_free (cookie);
	g_free (gateway);
	g_free (gwcert);

	return TRUE;
}

static gboolean
get_secrets_from_user (const char *request_id,
                       const char *title,
                       const char *msg,
                       NMConnection *connection,
                       gboolean ask,
                       gboolean echo_on,
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
		if (pwds_hash && (pwd = g_hash_table_lookup (pwds_hash, secret->prop_name))) {
			pwd = g_strdup (pwd);
		} else {
			if (ask) {
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
				pwd = nmc_readline_echo (secret->password ? echo_on : TRUE,
				                         "%s (%s): ", secret->name, secret->prop_name);
				if (!pwd)
					pwd = g_strdup ("");
			} else {
				if (msg)
					g_print ("%s\n", msg);
				g_printerr (_("Warning: password for '%s' not given in 'passwd-file' "
				              "and nmcli cannot ask without '--ask' option.\n"),
				            secret->prop_name);
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

	success = get_secrets_from_user (request_id, title, msg, connection, nmc->nmc_config.in_editor || nmc->ask,
	                                 nmc->nmc_config.show_secrets, nmc->pwds_hash, secrets);
	if (success)
		nm_secret_agent_simple_response (agent, request_id, secrets);
	else {
		/* Unregister our secret agent on failure, so that another agent
		 * may be tried */
		if (nmc->secret_agent) {
			nm_secret_agent_old_unregister (nmc->secret_agent, NULL, NULL);
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
nmc_readline_helper (const char *prompt)
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
		if (   nm_cli.nmc_config.in_editor
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
nmc_readline (const char *prompt_fmt, ...)
{
	va_list args;
	char *prompt, *str;

	va_start (args, prompt_fmt);
	prompt = g_strdup_vprintf (prompt_fmt, args);
	va_end (args);

	str = nmc_readline_helper (prompt);

	g_free (prompt);

	return str;
}

/**
 * nmc_readline_echo:
 *
 * The same as nmc_readline() except it can disable echoing of input characters if @echo_on is %FALSE.
 * nmc_readline(TRUE, ...) == nmc_readline(...)
 */
char *
nmc_readline_echo (gboolean echo_on, const char *prompt_fmt, ...)
{
	va_list args;
	char *prompt, *str;
	struct termios termios_orig, termios_new;

	va_start (args, prompt_fmt);
	prompt = g_strdup_vprintf (prompt_fmt, args);
	va_end (args);

	/* Disable echoing characters */
	if (!echo_on) {
		tcgetattr (STDIN_FILENO, &termios_orig);
		termios_new = termios_orig;
		termios_new.c_lflag &= ~(ECHO);
		tcsetattr (STDIN_FILENO, TCSADRAIN, &termios_new);
	}

	str = nmc_readline_helper (prompt);

	g_free (prompt);

	/* Restore original terminal settings */
	if (!echo_on) {
		tcsetattr (STDIN_FILENO, TCSADRAIN, &termios_orig);
		/* New line - setting ECHONL | ICANON did not help */
		fprintf (stdout, "\n");
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
		if (c->usage && nmc_arg_is_help (*(argv+1))) {
			if (!nmc->complete)
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
 * @...: a %NULL-terminated list of candidate strings
 *
 * Prints all the matching candidates for completion. Useful when there's
 * no better way to suggest completion other than a hardcoded string list.
 */
void
nmc_complete_strings (const char *prefix, ...)
{
	va_list args;
	const char *candidate;

	va_start (args, prefix);
	while ((candidate = va_arg (args, const char *))) {
		if (!*prefix || matches (prefix, candidate))
			g_print ("%s\n", candidate);
	}
	va_end (args);
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
