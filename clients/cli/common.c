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

#include "config.h"

#include <glib.h>
#include <glib/gi18n.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <readline/readline.h>
#include <readline/history.h>

#include "nm-glib-compat.h"

#include "common.h"
#include "utils.h"

/* Available fields for IPv4 group */
NmcOutputField nmc_fields_ip4_config[] = {
	{"GROUP",      N_("GROUP"),       15},  /* 0 */
	{"ADDRESS",    N_("ADDRESS"),     68},  /* 1 */
	{"GATEWAY",    N_("GATEWAY"),      0},  /* 2 */
	{"ROUTE",      N_("ROUTE"),       68},  /* 3 */
	{"DNS",        N_("DNS"),         35},  /* 4 */
	{"DOMAIN",     N_("DOMAIN"),      35},  /* 5 */
	{"WINS",       N_("WINS"),        20},  /* 6 */
	{NULL,         NULL,               0}
};
#define NMC_FIELDS_IP4_CONFIG_ALL     "GROUP,ADDRESS,GATEWAY,ROUTE,DNS,DOMAIN,WINS"

/* Available fields for DHCPv4 group */
NmcOutputField nmc_fields_dhcp4_config[] = {
	{"GROUP",      N_("GROUP"),       15},  /* 0 */
	{"OPTION",     N_("OPTION"),      80},  /* 1 */
	{NULL,         NULL,               0}
};
#define NMC_FIELDS_DHCP4_CONFIG_ALL     "GROUP,OPTION"

/* Available fields for IPv6 group */
NmcOutputField nmc_fields_ip6_config[] = {
	{"GROUP",      N_("GROUP"),       15},  /* 0 */
	{"ADDRESS",    N_("ADDRESS"),     95},  /* 1 */
	{"GATEWAY",    N_("GATEWAY"),      0},  /* 2 */
	{"ROUTE",      N_("ROUTE"),       95},  /* 3 */
	{"DNS",        N_("DNS"),         60},  /* 4 */
	{"DOMAIN",     N_("DOMAIN"),      35},  /* 5 */
	{NULL,         NULL,               0}
};
#define NMC_FIELDS_IP6_CONFIG_ALL     "GROUP,ADDRESS,GATEWAY,ROUTE,DNS,DOMAIN"

/* Available fields for DHCPv6 group */
NmcOutputField nmc_fields_dhcp6_config[] = {
	{"GROUP",      N_("GROUP"),       15},  /* 0 */
	{"OPTION",     N_("OPTION"),      80},  /* 1 */
	{NULL,         NULL,               0}
};
#define NMC_FIELDS_DHCP6_CONFIG_ALL     "GROUP,OPTION"


gboolean
print_ip4_config (NMIPConfig *cfg4,
                  NmCli *nmc,
                  const char *group_prefix,
                  const char *one_field)
{
	GPtrArray *ptr_array;
	char **addr_arr = NULL;
	char **route_arr = NULL;
	char **dns_arr = NULL;
	char **domain_arr = NULL;
	char **wins_arr = NULL;
	int i = 0;
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;

	if (cfg4 == NULL)
		return FALSE;

	tmpl = nmc_fields_ip4_config;
	tmpl_len = sizeof (nmc_fields_ip4_config);
	nmc->print_fields.indices = parse_output_fields (one_field ? one_field : NMC_FIELDS_IP4_CONFIG_ALL,
	                                                 tmpl, FALSE, NULL, NULL);
	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (nmc->output_data, arr);

	/* addresses */
	ptr_array = nm_ip_config_get_addresses (cfg4);
	if (ptr_array) {
		addr_arr = g_new (char *, ptr_array->len + 1);
		for (i = 0; i < ptr_array->len; i++) {
			NMIPAddress *addr = (NMIPAddress *) g_ptr_array_index (ptr_array, i);

			addr_arr[i] = g_strdup_printf ("%s/%u",
			                               nm_ip_address_get_address (addr),
			                               nm_ip_address_get_prefix (addr));
		}
		addr_arr[i] = NULL;
	}

	/* routes */
	ptr_array = nm_ip_config_get_routes (cfg4);
	if (ptr_array) {
		route_arr = g_new (char *, ptr_array->len + 1);
		for (i = 0; i < ptr_array->len; i++) {
			NMIPRoute *route = (NMIPRoute *) g_ptr_array_index (ptr_array, i);
			const char *next_hop;

			next_hop = nm_ip_route_get_next_hop (route);
			if (!next_hop)
				next_hop = "0.0.0.0";

			route_arr[i] = g_strdup_printf ("dst = %s/%u, nh = %s%c mt = %u",
			                                nm_ip_route_get_dest (route),
			                                nm_ip_route_get_prefix (route),
			                                next_hop,
			                                nm_ip_route_get_metric (route) == -1 ? '\0' : ',',
			                                (guint32) nm_ip_route_get_metric (route));
		}
		route_arr[i] = NULL;
	}

	/* DNS */
	dns_arr = g_strdupv ((char **) nm_ip_config_get_nameservers (cfg4));

	/* domains */
	domain_arr = g_strdupv ((char **) nm_ip_config_get_domains (cfg4));

	/* WINS */
	wins_arr = g_strdupv ((char **) nm_ip_config_get_wins_servers (cfg4));

	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
	set_val_strc (arr, 0, group_prefix);
	set_val_arr  (arr, 1, addr_arr);
	set_val_strc (arr, 2, nm_ip_config_get_gateway (cfg4));
	set_val_arr  (arr, 3, route_arr);
	set_val_arr  (arr, 4, dns_arr);
	set_val_arr  (arr, 5, domain_arr);
	set_val_arr  (arr, 6, wins_arr);
	g_ptr_array_add (nmc->output_data, arr);

	print_data (nmc); /* Print all data */

	/* Remove any previous data */
	nmc_empty_output_fields (nmc);

	return TRUE;
}

gboolean
print_ip6_config (NMIPConfig *cfg6,
                  NmCli *nmc,
                  const char *group_prefix,
                  const char *one_field)
{
	GPtrArray *ptr_array;
	char **addr_arr = NULL;
	char **route_arr = NULL;
	char **dns_arr = NULL;
	char **domain_arr = NULL;
	int i = 0;
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;

	if (cfg6 == NULL)
		return FALSE;

	tmpl = nmc_fields_ip6_config;
	tmpl_len = sizeof (nmc_fields_ip6_config);
	nmc->print_fields.indices = parse_output_fields (one_field ? one_field : NMC_FIELDS_IP6_CONFIG_ALL,
	                                                 tmpl, FALSE, NULL, NULL);
	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (nmc->output_data, arr);

	/* addresses */
	ptr_array = nm_ip_config_get_addresses (cfg6);
	if (ptr_array) {
		addr_arr = g_new (char *, ptr_array->len + 1);
		for (i = 0; i < ptr_array->len; i++) {
			NMIPAddress *addr = (NMIPAddress *) g_ptr_array_index (ptr_array, i);

			addr_arr[i] = g_strdup_printf ("%s/%u",
			                               nm_ip_address_get_address (addr),
			                               nm_ip_address_get_prefix (addr));
		}
		addr_arr[i] = NULL;
	}

	/* routes */
	ptr_array = nm_ip_config_get_routes (cfg6);
	if (ptr_array) {
		route_arr = g_new (char *, ptr_array->len + 1);
		for (i = 0; i < ptr_array->len; i++) {
			NMIPRoute *route = (NMIPRoute *) g_ptr_array_index (ptr_array, i);
			const char *next_hop;

			next_hop = nm_ip_route_get_next_hop (route);
			if (!next_hop)
				next_hop = "::";

			route_arr[i] = g_strdup_printf ("dst = %s/%u, nh = %s%c mt = %u",
			                                nm_ip_route_get_dest (route),
			                                nm_ip_route_get_prefix (route),
			                                next_hop,
			                                nm_ip_route_get_metric (route) == -1 ? '\0' : ',',
			                                (guint32) nm_ip_route_get_metric (route));
		}
		route_arr[i] = NULL;
	}

	/* DNS */
	dns_arr = g_strdupv ((char **) nm_ip_config_get_nameservers (cfg6));

	/* domains */
	domain_arr = g_strdupv ((char **) nm_ip_config_get_domains (cfg6));

	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
	set_val_strc (arr, 0, group_prefix);
	set_val_arr  (arr, 1, addr_arr);
	set_val_strc (arr, 2, nm_ip_config_get_gateway (cfg6));
	set_val_arr  (arr, 3, route_arr);
	set_val_arr  (arr, 4, dns_arr);
	set_val_arr  (arr, 5, domain_arr);
	g_ptr_array_add (nmc->output_data, arr);

	print_data (nmc); /* Print all data */

	/* Remove any previous data */
	nmc_empty_output_fields (nmc);

	return TRUE;
}

gboolean
print_dhcp4_config (NMDhcpConfig *dhcp4,
                    NmCli *nmc,
                    const char *group_prefix,
                    const char *one_field)
{
	GHashTable *table;
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;

	if (dhcp4 == NULL)
		return FALSE;

	table = nm_dhcp_config_get_options (dhcp4);
	if (table) {
		GHashTableIter table_iter;
		gpointer key, value;
		char **options_arr = NULL;
		int i = 0;

		tmpl = nmc_fields_dhcp4_config;
		tmpl_len = sizeof (nmc_fields_dhcp4_config);
		nmc->print_fields.indices = parse_output_fields (one_field ? one_field : NMC_FIELDS_DHCP4_CONFIG_ALL,
		                                                 tmpl, FALSE, NULL, NULL);
		arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
		g_ptr_array_add (nmc->output_data, arr);

		options_arr = g_new (char *, g_hash_table_size (table) + 1);
		g_hash_table_iter_init (&table_iter, table);
		while (g_hash_table_iter_next (&table_iter, &key, &value))
			options_arr[i++] = g_strdup_printf ("%s = %s", (char *) key, (char *) value);
		options_arr[i] = NULL;

		arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
		set_val_strc (arr, 0, group_prefix);
		set_val_arr  (arr, 1, options_arr);
		g_ptr_array_add (nmc->output_data, arr);

		print_data (nmc); /* Print all data */

		/* Remove any previous data */
		nmc_empty_output_fields (nmc);

		return TRUE;
	}
	return FALSE;
}

gboolean
print_dhcp6_config (NMDhcpConfig *dhcp6,
                    NmCli *nmc,
                    const char *group_prefix,
                    const char *one_field)
{
	GHashTable *table;
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;

	if (dhcp6 == NULL)
		return FALSE;

	table = nm_dhcp_config_get_options (dhcp6);
	if (table) {
		GHashTableIter table_iter;
		gpointer key, value;
		char **options_arr = NULL;
		int i = 0;

		tmpl = nmc_fields_dhcp6_config;
		tmpl_len = sizeof (nmc_fields_dhcp6_config);
		nmc->print_fields.indices = parse_output_fields (one_field ? one_field : NMC_FIELDS_DHCP6_CONFIG_ALL,
		                                                 tmpl, FALSE, NULL, NULL);
		arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
		g_ptr_array_add (nmc->output_data, arr);

		options_arr = g_new (char *, g_hash_table_size (table) + 1);
		g_hash_table_iter_init (&table_iter, table);
		while (g_hash_table_iter_next (&table_iter, &key, &value))
			options_arr[i++] = g_strdup_printf ("%s = %s", (char *) key, (char *) value);
		options_arr[i] = NULL;

		arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
		set_val_strc (arr, 0, group_prefix);
		set_val_arr  (arr, 1, options_arr);
		g_ptr_array_add (nmc->output_data, arr);

		print_data (nmc); /* Print all data */

		/* Remove any previous data */
		nmc_empty_output_fields (nmc);

		return TRUE;
	}
	return FALSE;
}

/*
 * Parse IP address from string to NMIPAddress stucture.
 * ip_str is the IP address in the form address/prefix
 */
NMIPAddress *
nmc_parse_and_build_address (int family, const char *ip_str, GError **error)
{
	int max_prefix = (family == AF_INET) ? 32 : 128;
	NMIPAddress *addr = NULL;
	const char *ip;
	char *tmp;
	char *plen;
	long int prefix;
	GError *local = NULL;

	g_return_val_if_fail (ip_str != NULL, NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	tmp = g_strdup (ip_str);
	plen = strchr (tmp, '/');  /* prefix delimiter */
	if (plen)
		*plen++ = '\0';

	ip = tmp;

	prefix = max_prefix;
	if (plen) {
		if (!nmc_string_to_int (plen, TRUE, 1, max_prefix, &prefix)) {
			g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			             _("invalid prefix '%s'; <1-%d> allowed"), plen, max_prefix);
			goto finish;
		}
	}

	addr = nm_ip_address_new (family, ip, (guint32) prefix, &local);
	if (!addr) {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("invalid IP address: %s"), local->message);
		g_clear_error (&local);
	}

finish:
	g_free (tmp);
	return addr;
}

/*
 * nmc_parse_and_build_route:
 * @family: AF_INET or AF_INET6
 * @first: the route destination in the form of "address/prefix"
     (/prefix is optional)
 * @second: (allow-none): next hop address, if third is not NULL. Otherwise it could be
     either next hop address or metric. (It can be NULL when @third is NULL).
 * @third: (allow-none): route metric
 * @error: location to store GError
 *
 * Parse route from strings and return an #NMIPRoute
 *
 * Returns: %TRUE on success, %FALSE on failure
 */
NMIPRoute *
nmc_parse_and_build_route (int family,
                           const char *first,
                           const char *second,
                           const char *third,
                           GError **error)
{
	int max_prefix = (family == AF_INET) ? 32 : 128;
	char *dest = NULL, *plen = NULL;
	const char *next_hop = NULL;
	const char *canon_dest;
	long int prefix = max_prefix, metric = -1;
	NMIPRoute *route = NULL;
	gboolean success = FALSE;
	GError *local = NULL;

	g_return_val_if_fail (family == AF_INET || family == AF_INET6, FALSE);
	g_return_val_if_fail (first != NULL, FALSE);
	g_return_val_if_fail (second || !third, FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	dest = g_strdup (first);
	plen = strchr (dest, '/');  /* prefix delimiter */
	if (plen)
		*plen++ = '\0';

	if (plen) {
		if (!nmc_string_to_int (plen, TRUE, 1, max_prefix, &prefix)) {
			g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			             _("invalid prefix '%s'; <1-%d> allowed"),
			             plen, max_prefix);
			goto finish;
		}
	}

	if (second) {
		if (third || nm_utils_ipaddr_valid (family, second))
			next_hop = second;
		else {
			/* 'second' can be a metric */
			if (!nmc_string_to_int (second, TRUE, 0, G_MAXUINT32, &metric)) {
				g_set_error (error, 1, 0, _("the second component of route ('%s') is neither "
				                            "a next hop address nor a metric"), second);
				goto finish;
			}
		}
	}

	if (third) {
		if (!nmc_string_to_int (third, TRUE, 0, G_MAXUINT32, &metric)) {
			g_set_error (error, 1, 0, _("invalid metric '%s'"), third);
			goto finish;
		}
	}

	route = nm_ip_route_new (family, dest, prefix, next_hop, metric, &local);
	if (!route) {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("invalid route: %s"), local->message);
		g_clear_error (&local);
		goto finish;
	}

	/* We don't accept default routes as NetworkManager handles it
	 * itself. But we have to check this after @route has normalized the
	 * dest string.
	 */
	canon_dest = nm_ip_route_get_dest (route);
	if (!strcmp (canon_dest, "0.0.0.0") || !strcmp (canon_dest, "::")) {
		g_set_error_literal (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		                     _("default route cannot be added (NetworkManager handles it by itself)"));
		g_clear_pointer (&route, nm_ip_route_unref);
		goto finish;
	}

	success = TRUE;

finish:
	g_free (dest);
	return route;
}

const char *
nmc_device_state_to_string (NMDeviceState state)
{
	switch (state) {
	case NM_DEVICE_STATE_UNMANAGED:
		return _("unmanaged");
	case NM_DEVICE_STATE_UNAVAILABLE:
		return _("unavailable");
	case NM_DEVICE_STATE_DISCONNECTED:
		return _("disconnected");
	case NM_DEVICE_STATE_PREPARE:
		return _("connecting (prepare)");
	case NM_DEVICE_STATE_CONFIG:
		return _("connecting (configuring)");
	case NM_DEVICE_STATE_NEED_AUTH:
		return _("connecting (need authentication)");
	case NM_DEVICE_STATE_IP_CONFIG:
		return _("connecting (getting IP configuration)");
	case NM_DEVICE_STATE_IP_CHECK:
		return _("connecting (checking IP connectivity)");
	case NM_DEVICE_STATE_SECONDARIES:
		return _("connecting (starting secondary connections)");
	case NM_DEVICE_STATE_ACTIVATED:
		return _("connected");
	case NM_DEVICE_STATE_DEACTIVATING:
		return _("deactivating");
	case NM_DEVICE_STATE_FAILED:
		return _("connection failed");
	default:
		return _("unknown");
	}
}

const char *
nmc_device_reason_to_string (NMDeviceStateReason reason)
{
	switch (reason) {
	case NM_DEVICE_STATE_REASON_NONE:
		return _("No reason given");

	case NM_DEVICE_STATE_REASON_UNKNOWN:
		return _("Unknown error");

	case NM_DEVICE_STATE_REASON_NOW_MANAGED:
		return _("Device is now managed");

	case NM_DEVICE_STATE_REASON_NOW_UNMANAGED:
		return _("Device is now unmanaged");

	case NM_DEVICE_STATE_REASON_CONFIG_FAILED:
		return _("The device could not be readied for configuration");

	case NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE:
		return _("IP configuration could not be reserved (no available address, timeout, etc.)");

	case NM_DEVICE_STATE_REASON_IP_CONFIG_EXPIRED:
		return _("The IP configuration is no longer valid");

	case NM_DEVICE_STATE_REASON_NO_SECRETS:
		return _("Secrets were required, but not provided");

	case NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT:
		return _("802.1X supplicant disconnected");

	case NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED:
		return _("802.1X supplicant configuration failed");

	case NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED:
		return _("802.1X supplicant failed");

	case NM_DEVICE_STATE_REASON_SUPPLICANT_TIMEOUT:
		return _("802.1X supplicant took too long to authenticate");

	case NM_DEVICE_STATE_REASON_PPP_START_FAILED:
		return _("PPP service failed to start");

	case NM_DEVICE_STATE_REASON_PPP_DISCONNECT:
		return _("PPP service disconnected");

	case NM_DEVICE_STATE_REASON_PPP_FAILED:
		return _("PPP failed");

	case NM_DEVICE_STATE_REASON_DHCP_START_FAILED:
		return _("DHCP client failed to start");

	case NM_DEVICE_STATE_REASON_DHCP_ERROR:
		return _("DHCP client error");

	case NM_DEVICE_STATE_REASON_DHCP_FAILED:
		return _("DHCP client failed");

	case NM_DEVICE_STATE_REASON_SHARED_START_FAILED:
		return _("Shared connection service failed to start");

	case NM_DEVICE_STATE_REASON_SHARED_FAILED:
		return _("Shared connection service failed");

	case NM_DEVICE_STATE_REASON_AUTOIP_START_FAILED:
		return _("AutoIP service failed to start");

	case NM_DEVICE_STATE_REASON_AUTOIP_ERROR:
		return _("AutoIP service error");

	case NM_DEVICE_STATE_REASON_AUTOIP_FAILED:
		return _("AutoIP service failed");

	case NM_DEVICE_STATE_REASON_MODEM_BUSY:
		return _("The line is busy");

	case NM_DEVICE_STATE_REASON_MODEM_NO_DIAL_TONE:
		return _("No dial tone");

	case NM_DEVICE_STATE_REASON_MODEM_NO_CARRIER:
		return _("No carrier could be established");

	case NM_DEVICE_STATE_REASON_MODEM_DIAL_TIMEOUT:
		return _("The dialing request timed out");

	case NM_DEVICE_STATE_REASON_MODEM_DIAL_FAILED:
		return _("The dialing attempt failed");

	case NM_DEVICE_STATE_REASON_MODEM_INIT_FAILED:
		return _("Modem initialization failed");

	case NM_DEVICE_STATE_REASON_GSM_APN_FAILED:
		return _("Failed to select the specified APN");

	case NM_DEVICE_STATE_REASON_GSM_REGISTRATION_NOT_SEARCHING:
		return _("Not searching for networks");

	case NM_DEVICE_STATE_REASON_GSM_REGISTRATION_DENIED:
		return _("Network registration denied");

	case NM_DEVICE_STATE_REASON_GSM_REGISTRATION_TIMEOUT:
		return _("Network registration timed out");

	case NM_DEVICE_STATE_REASON_GSM_REGISTRATION_FAILED:
		return _("Failed to register with the requested network");

	case NM_DEVICE_STATE_REASON_GSM_PIN_CHECK_FAILED:
		return _("PIN check failed");

	case NM_DEVICE_STATE_REASON_FIRMWARE_MISSING:
		return _("Necessary firmware for the device may be missing");

	case NM_DEVICE_STATE_REASON_REMOVED:
		return _("The device was removed");

	case NM_DEVICE_STATE_REASON_SLEEPING:
		return _("NetworkManager went to sleep");

	case NM_DEVICE_STATE_REASON_CONNECTION_REMOVED:
		return _("The device's active connection disappeared");

	case NM_DEVICE_STATE_REASON_USER_REQUESTED:
		return _("Device disconnected by user or client");

	case NM_DEVICE_STATE_REASON_CARRIER:
		return _("Carrier/link changed");

	case NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED:
		return _("The device's existing connection was assumed");

	case NM_DEVICE_STATE_REASON_SUPPLICANT_AVAILABLE:
		return _("The supplicant is now available");

	case NM_DEVICE_STATE_REASON_MODEM_NOT_FOUND:
		return _("The modem could not be found");

	case NM_DEVICE_STATE_REASON_BT_FAILED:
		return _("The Bluetooth connection failed or timed out");

	case NM_DEVICE_STATE_REASON_GSM_SIM_NOT_INSERTED:
		return _("GSM Modem's SIM card not inserted");

	case NM_DEVICE_STATE_REASON_GSM_SIM_PIN_REQUIRED:
		return _("GSM Modem's SIM PIN required");

	case NM_DEVICE_STATE_REASON_GSM_SIM_PUK_REQUIRED:
		return _("GSM Modem's SIM PUK required");

	case NM_DEVICE_STATE_REASON_GSM_SIM_WRONG:
		return _("GSM Modem's SIM wrong");

	case NM_DEVICE_STATE_REASON_INFINIBAND_MODE:
		return _("InfiniBand device does not support connected mode");

        case NM_DEVICE_STATE_REASON_DEPENDENCY_FAILED:
		return _("A dependency of the connection failed");

	case NM_DEVICE_STATE_REASON_BR2684_FAILED:
		return _("A problem with the RFC 2684 Ethernet over ADSL bridge");

	case NM_DEVICE_STATE_REASON_MODEM_MANAGER_UNAVAILABLE:
		return _("ModemManager is unavailable");

	case NM_DEVICE_STATE_REASON_SSID_NOT_FOUND:
		return _("The Wi-Fi network could not be found");

	case NM_DEVICE_STATE_REASON_SECONDARY_CONNECTION_FAILED:
		return _("A secondary connection of the base connection failed");

	case NM_DEVICE_STATE_REASON_DCB_FCOE_FAILED:
		return _("DCB or FCoE setup failed");

	case NM_DEVICE_STATE_REASON_TEAMD_CONTROL_FAILED:
		return _("teamd control failed");

	case NM_DEVICE_STATE_REASON_MODEM_FAILED:
		return _("Modem failed or no longer available");

	case NM_DEVICE_STATE_REASON_MODEM_AVAILABLE:
		return _("Modem now ready and available");

	case NM_DEVICE_STATE_REASON_SIM_PIN_INCORRECT:
		return _("SIM PIN was incorrect");

	case NM_DEVICE_STATE_REASON_NEW_ACTIVATION:
		return _("New connection activation was enqueued");

	case NM_DEVICE_STATE_REASON_PARENT_CHANGED:
		return _("The device's parent changed");

	case NM_DEVICE_STATE_REASON_PARENT_MANAGED_CHANGED:
		return _("The device parent's management changed");

	default:
		/* TRANSLATORS: Unknown reason for a device state change (NMDeviceStateReason) */
		return _("Unknown");
	}
}


/* Max priority values from libnm-core/nm-setting-vlan.c */
#define MAX_SKB_PRIO   G_MAXUINT32
#define MAX_8021P_PRIO 7  /* Max 802.1p priority */

/*
 * Parse VLAN priority mappings from the following format: 2:1,3:4,7:3
 * and verify if the priority numbers are valid
 *
 * Return: string array with split maps, or NULL on error
 * Caller is responsible for freeing the array.
 */
char **
nmc_vlan_parse_priority_maps (const char *priority_map,
                              NMVlanPriorityMap map_type,
                              GError **error)
{
	char **mapping = NULL, **iter;
	unsigned long from, to, from_max, to_max;

	g_return_val_if_fail (priority_map != NULL, NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	if (map_type == NM_VLAN_INGRESS_MAP) {
		from_max = MAX_8021P_PRIO;
		to_max = MAX_SKB_PRIO;
	} else {
		from_max = MAX_SKB_PRIO;
		to_max = MAX_8021P_PRIO;
	}

	mapping = g_strsplit (priority_map, ",", 0);
	for (iter = mapping; iter && *iter; iter++) {
		char *left, *right;

		left = g_strstrip (*iter);
		right = strchr (left, ':');
		if (!right) {
			g_set_error (error, 1, 0, _("invalid priority map '%s'"), *iter);
			g_strfreev (mapping);
			return NULL;
		}
		*right++ = '\0';

		if (!nmc_string_to_uint (left, TRUE, 0, from_max, &from)) {
			g_set_error (error, 1, 0, _("priority '%s' is not valid (<0-%ld>)"),
			             left, from_max);
			g_strfreev (mapping);
			return NULL;
		}
		if (!nmc_string_to_uint (right, TRUE, 0, to_max, &to)) {
			g_set_error (error, 1, 0, _("priority '%s' is not valid (<0-%ld>)"),
			             right, to_max);
			g_strfreev (mapping);
			return NULL;
		}
		*(right-1) = ':'; /* Put back ':' */
	}
	return mapping;
}

const char *
nmc_bond_validate_mode (const char *mode, GError **error)
{
	unsigned long mode_int;
	static const char *valid_modes[] = { "balance-rr",
	                                     "active-backup",
	                                     "balance-xor",
	                                     "broadcast",
	                                     "802.3ad",
	                                     "balance-tlb",
	                                     "balance-alb",
	                                     NULL };
	if (nmc_string_to_uint (mode, TRUE, 0, 6, &mode_int)) {
		/* Translate bonding mode numbers to mode names:
		 * https://www.kernel.org/doc/Documentation/networking/bonding.txt
		 */
		return valid_modes[mode_int];
	} else
		return nmc_string_is_valid (mode, valid_modes, error);
}

/*
 * nmc_team_check_config:
 * @config: file name with team config, or raw team JSON config data
 * @out_config: raw team JSON config data (with removed new-line characters)
 * @error: location to store error, or %NUL
 *
 * Check team config from @config parameter and return the checked/sanitized
 * config in @out_config.
 *
 * Returns: %TRUE if the config is valid, %FALSE if it is invalid
 */
gboolean
nmc_team_check_config (const char *config, char **out_config, GError **error)
{
	char *contents = NULL;
	size_t c_len = 0;

	*out_config = NULL;

	if (!config || strlen (config) == strspn (config, " \t"))
		return TRUE;

	/* 'config' can be either a file name or raw JSON config data */
	if (g_file_test (config, G_FILE_TEST_EXISTS))
		(void) g_file_get_contents (config, &contents, NULL, NULL);
	else
		contents = g_strdup (config);

	if (contents) {
		g_strstrip (contents);
		c_len = strlen (contents);
	}

	/* Do a simple validity check */
	if (!contents || !contents[0] || c_len > 100000 || contents[0] != '{' || contents[c_len-1] != '}') {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("'%s' is not a valid team configuration or file name."), config);
		g_free (contents);
		return FALSE;
	}
	*out_config = g_strdelimit (contents, "\r\n", ' ');
	return TRUE;
}

/*
 * nmc_find_connection:
 * @connections: array of NMConnections to search in
 * @filter_type: "id", "uuid", "path" or %NULL
 * @filter_val: connection to find (connection name, UUID or path)
 * @start: where to start in @list. The location is updated so that the function
 *   can be called multiple times (for connections with the same name).
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
                     int *start)
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
		if (   (   (!filter_type || strcmp (filter_type, "id")  == 0)
		        && strcmp (filter_val, id) == 0)
		    || (   (!filter_type || strcmp (filter_type, "uuid") == 0)
		        && strcmp (filter_val, uuid) == 0)
		    || (   (!filter_type || strcmp (filter_type, "path") == 0)
		        && (g_strcmp0 (filter_val, path) == 0 || (filter_type && g_strcmp0 (filter_val, path_num) == 0)))) {
			if (!start)
				return connection;
			if (found) {
				*start = i;
				return found;
			}
			found = connection;
		}
	}

	if (start)
		*start = 0;
	return found;
}

static gboolean
get_secrets_from_user (const char *request_id,
                       const char *title,
                       const char *msg,
                       gboolean ask,
                       GHashTable *pwds_hash,
                       GPtrArray *secrets)
{
	int i;

	for (i = 0; i < secrets->len; i++) {
		NMSecretAgentSimpleSecret *secret = secrets->pdata[i];
		char *pwd = NULL;

		/* First try to find the password in provided passwords file,
		 * then ask user. */
		if (pwds_hash && (pwd = g_hash_table_lookup (pwds_hash, secret->prop_name))) {
			pwd = g_strdup (pwd);
		} else {
			g_print ("%s\n", msg);
			if (ask) {
				if (secret->value) {
					/* Prefill the password if we have it. */
					rl_startup_hook = nmc_rl_set_deftext;
					nmc_rl_pre_input_deftext = g_strdup (secret->value);
				}
				pwd = nmc_readline ("%s (%s): ", secret->name, secret->prop_name);
				if (!pwd)
					pwd = g_strdup ("");
			} else {
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
	gboolean success = FALSE;

	if (nmc->print_output == NMC_PRINT_PRETTY)
		nmc_terminal_erase_line ();

	success = get_secrets_from_user (request_id, title, msg, nmc->in_editor || nmc->ask,
	                                 nmc->pwds_hash, secrets);
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


static gboolean nmcli_in_readline = FALSE;
static pthread_mutex_t readline_mutex = PTHREAD_MUTEX_INITIALIZER;

gboolean
nmc_get_in_readline (void)
{
	gboolean in_readline;

	pthread_mutex_lock (&readline_mutex);
	in_readline = nmcli_in_readline;
	pthread_mutex_unlock (&readline_mutex);
	return in_readline;
}

void
nmc_set_in_readline (gboolean in_readline)
{
	pthread_mutex_lock (&readline_mutex);
	nmcli_in_readline = in_readline;
	pthread_mutex_unlock (&readline_mutex);
}

/* Global variable defined in nmcli.c */
extern NmCli nm_cli;

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

readline_mark:
	/* We are in readline -> Ctrl-C should not quit nmcli */
	nmc_set_in_readline (TRUE);
	str = readline (prompt);
	/* We are outside readline -> Ctrl-C should quit nmcli */
	nmc_set_in_readline (FALSE);

	/* Add string to the history */
	if (str && *str)
		add_history (str);

	/*-- React on Ctrl-C and Ctrl-D --*/
	/* We quit on Ctrl-D when line is empty */
	if (str == NULL) {
		/* Send SIGQUIT to itself */
		nmc_set_sigquit_internal ();
		kill (getpid (), SIGQUIT);
		/* Sleep in this thread so that we don't do anything else until exit */
		for (;;)
			sleep (3);
	}
	/* Ctrl-C */
	if (nmc_seen_sigint ()) {
		nmc_clear_sigint ();
		if (nm_cli.in_editor || *str) {
			/* In editor, or the line is not empty */
			/* Call readline again to get new prompt (repeat) */
			g_free (str);
			goto readline_mark;
		} else {
			/* Not in editor and line is empty */
			/* Send SIGQUIT to itself */
			nmc_set_sigquit_internal ();
			kill (getpid (), SIGQUIT);
			/* Sleep in this thread so that we don't do anything else until exit */
			for (;;)
				sleep (3);
		}
	}
	g_free (prompt);

	/* Return NULL, not empty string */
	if (str && *str == '\0') {
		g_free (str);
		str = NULL;
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
nmc_rl_gen_func_basic (const char *text, int state, const char **words)
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

