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
 * (C) Copyright 2012 Red Hat, Inc.
 */

#include "config.h"

#include <glib.h>
#include <glib/gi18n.h>

#include "common.h"
#include "utils.h"

/* Available fields for IPv4 group */
static NmcOutputField nmc_fields_ip4_config[] = {
	{"GROUP",      N_("GROUP"),       15, NULL, 0},  /* 0 */
	{"ADDRESS",    N_("ADDRESS"),     68, NULL, 0},  /* 1 */
	{"ROUTE",      N_("ROUTE"),       68, NULL, 0},  /* 2 */
	{"DNS",        N_("DNS"),         35, NULL, 0},  /* 3 */
	{"DOMAIN",     N_("DOMAIN"),      35, NULL, 0},  /* 4 */
	{"WINS",       N_("WINS"),        20, NULL, 0},  /* 5 */
	{NULL,         NULL,               0, NULL, 0}
};
#define NMC_FIELDS_IP4_CONFIG_ALL     "GROUP,ADDRESS,ROUTE,DNS,DOMAIN,WINS"

/* Available fields for DHCPv4 group */
static NmcOutputField nmc_fields_dhcp4_config[] = {
	{"GROUP",      N_("GROUP"),       15, NULL, 0},  /* 0 */
	{"OPTION",     N_("OPTION"),      80, NULL, 0},  /* 1 */
	{NULL,         NULL,               0, NULL, 0}
};
#define NMC_FIELDS_DHCP4_CONFIG_ALL     "GROUP,OPTION"

/* Available fields for IPv6 group */
static NmcOutputField nmc_fields_ip6_config[] = {
	{"GROUP",      N_("GROUP"),       15, NULL, 0},  /* 0 */
	{"ADDRESS",    N_("ADDRESS"),     95, NULL, 0},  /* 1 */
	{"ROUTE",      N_("ROUTE"),       95, NULL, 0},  /* 2 */
	{"DNS",        N_("DNS"),         60, NULL, 0},  /* 3 */
	{"DOMAIN",     N_("DOMAIN"),      35, NULL, 0},  /* 4 */
	{NULL,         NULL,               0, NULL, 0}
};
#define NMC_FIELDS_IP6_CONFIG_ALL     "GROUP,ADDRESS,ROUTE,DNS,DOMAIN"

/* Available fields for DHCPv6 group */
static NmcOutputField nmc_fields_dhcp6_config[] = {
	{"GROUP",      N_("GROUP"),       15, NULL, 0},  /* 0 */
	{"OPTION",     N_("OPTION"),      80, NULL, 0},  /* 1 */
	{NULL,         NULL,               0, NULL, 0}
};
#define NMC_FIELDS_DHCP6_CONFIG_ALL     "GROUP,OPTION"


gboolean
print_ip4_config (NMIP4Config *cfg4, NmCli *nmc, const char *group_prefix)
{
	GSList *list, *iter;
	const GArray *array;
	const GPtrArray *ptr_array;
	char **addr_arr = NULL;
	char **route_arr = NULL;
	char **dns_arr = NULL;
	char **domain_arr = NULL;
	char **wins_arr = NULL;
	int i = 0;
	guint32 mode_flag = (nmc->print_output == NMC_PRINT_PRETTY) ? NMC_PF_FLAG_PRETTY : (nmc->print_output == NMC_PRINT_TERSE) ? NMC_PF_FLAG_TERSE : 0;
	guint32 multiline_flag = nmc->multiline_output ? NMC_PF_FLAG_MULTILINE : 0;
	guint32 escape_flag = nmc->escape_values ? NMC_PF_FLAG_ESCAPE : 0;

	if (cfg4 == NULL)
		return FALSE;

	nmc->allowed_fields = nmc_fields_ip4_config;
	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_FIELD_NAMES;
	nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_IP4_CONFIG_ALL, nmc->allowed_fields, NULL);
	print_fields (nmc->print_fields, nmc->allowed_fields); /* Print header */

	/* addresses */
	list = (GSList *) nm_ip4_config_get_addresses (cfg4);
	addr_arr = g_new (char *, g_slist_length (list) + 1);
	for (iter = list; iter; iter = g_slist_next (iter)) {
		NMIP4Address *addr = (NMIP4Address *) iter->data;
		guint32 prefix;
		char *ip_str, *gw_str;

		ip_str = nmc_ip4_address_as_string (nm_ip4_address_get_address (addr), NULL);
		prefix = nm_ip4_address_get_prefix (addr);
		gw_str = nmc_ip4_address_as_string (nm_ip4_address_get_gateway (addr), NULL);

		addr_arr[i++] = g_strdup_printf ("ip = %s/%u, gw = %s", ip_str, prefix, gw_str);
		g_free (ip_str);
		g_free (gw_str);
	}
	addr_arr[i] = NULL;

	/* routes */
	list = (GSList *) nm_ip4_config_get_routes (cfg4);
	route_arr = g_new (char *, g_slist_length (list) + 1);
	i = 0;
	for (iter = list; iter; iter = g_slist_next (iter)) {
		NMIP4Route *route = (NMIP4Route *) iter->data;
		guint32 prefix, metric;
		char *dest_str, *nexthop_str;

		dest_str = nmc_ip4_address_as_string (nm_ip4_route_get_dest (route), NULL);
		nexthop_str = nmc_ip4_address_as_string (nm_ip4_route_get_next_hop (route), NULL);
		prefix = nm_ip4_route_get_prefix (route);
		metric = nm_ip4_route_get_metric (route);

		route_arr[i++] = g_strdup_printf ("dst = %s/%u, nh = %s, mt = %u", dest_str, prefix, nexthop_str, metric);
		g_free (dest_str);
		g_free (nexthop_str);
	}
	route_arr[i] = NULL;

	/* DNS */
	array = nm_ip4_config_get_nameservers (cfg4);
	if (array) {
		dns_arr = g_new (char *, array->len + 1);
		for (i = 0; i < array->len; i++)
			dns_arr[i] = nmc_ip4_address_as_string (g_array_index (array, guint32, i), NULL);

		dns_arr[i] = NULL;
	}

	/* domains */
	ptr_array = nm_ip4_config_get_domains (cfg4);
	if (ptr_array) {
		domain_arr = g_new (char *, ptr_array->len + 1);
		for (i = 0; i < ptr_array->len; i++)
			domain_arr[i] = g_ptr_array_index (ptr_array, i);

		domain_arr[i] = NULL;
	}

	/* WINS */
	array = nm_ip4_config_get_wins_servers (cfg4);
	if (array) {
		wins_arr = g_new (char *, array->len + 1);
		for (i = 0; i < array->len; i++)
			wins_arr[i] = nmc_ip4_address_as_string (g_array_index (array, guint32, i), NULL);

		wins_arr[i] = NULL;
	}

	set_val_str (nmc->allowed_fields, 0, group_prefix);
	set_val_arr (nmc->allowed_fields, 1, (const char **) addr_arr);
	set_val_arr (nmc->allowed_fields, 2, (const char **) route_arr);
	set_val_arr (nmc->allowed_fields, 3, (const char **) dns_arr);
	set_val_arr (nmc->allowed_fields, 4, (const char **) domain_arr);
	set_val_arr (nmc->allowed_fields, 5, (const char **) wins_arr);

	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_SECTION_PREFIX;
	print_fields (nmc->print_fields, nmc->allowed_fields); /* Print values */

	g_strfreev (addr_arr);
	g_strfreev (route_arr);
	g_strfreev (dns_arr);
	g_free (domain_arr);
	g_strfreev (wins_arr);

	return TRUE;
}

gboolean
print_ip6_config (NMIP6Config *cfg6, NmCli *nmc, const char *group_prefix)
{
	GSList *list, *iter;
	const GPtrArray *ptr_array;
	char **addr_arr = NULL;
	char **route_arr = NULL;
	char **dns_arr = NULL;
	char **domain_arr = NULL;
	int i = 0;
	guint32 mode_flag = (nmc->print_output == NMC_PRINT_PRETTY) ? NMC_PF_FLAG_PRETTY : (nmc->print_output == NMC_PRINT_TERSE) ? NMC_PF_FLAG_TERSE : 0;
	guint32 multiline_flag = nmc->multiline_output ? NMC_PF_FLAG_MULTILINE : 0;
	guint32 escape_flag = nmc->escape_values ? NMC_PF_FLAG_ESCAPE : 0;

	if (cfg6 == NULL)
		return FALSE;

	nmc->allowed_fields = nmc_fields_ip6_config;
	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_FIELD_NAMES;
	nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_IP6_CONFIG_ALL, nmc->allowed_fields, NULL);
	print_fields (nmc->print_fields, nmc->allowed_fields); /* Print header */

	/* addresses */
	list = (GSList *) nm_ip6_config_get_addresses (cfg6);
	addr_arr = g_new (char *, g_slist_length (list) + 1);
	for (iter = list; iter; iter = g_slist_next (iter)) {
		NMIP6Address *addr = (NMIP6Address *) iter->data;
		guint32 prefix;
		char *ip_str, *gw_str;

		ip_str = nmc_ip6_address_as_string (nm_ip6_address_get_address (addr), NULL);
		prefix = nm_ip6_address_get_prefix (addr);
		gw_str = nmc_ip6_address_as_string (nm_ip6_address_get_gateway (addr), NULL);

		addr_arr[i++] = g_strdup_printf ("ip = %s/%u, gw = %s", ip_str, prefix, gw_str);
		g_free (ip_str);
		g_free (gw_str);
	}
	addr_arr[i] = NULL;

	/* routes */
	list = (GSList *) nm_ip6_config_get_routes (cfg6);
	route_arr = g_new (char *, g_slist_length (list) + 1);
	i = 0;
	for (iter = list; iter; iter = g_slist_next (iter)) {
		NMIP6Route *route = (NMIP6Route *) iter->data;
		guint32 prefix, metric;
		char *dest_str, *nexthop_str;

		dest_str = nmc_ip6_address_as_string (nm_ip6_route_get_dest (route), NULL);
		nexthop_str = nmc_ip6_address_as_string (nm_ip6_route_get_next_hop (route), NULL);
		prefix = nm_ip6_route_get_prefix (route);
		metric = nm_ip6_route_get_metric (route);

		route_arr[i++] = g_strdup_printf ("dst = %s/%u, nh = %s, mt = %u", dest_str, prefix, nexthop_str, metric);
		g_free (dest_str);
		g_free (nexthop_str);
	}
	route_arr[i] = NULL;

	/* DNS */
	list = (GSList *) nm_ip6_config_get_nameservers (cfg6);
	dns_arr = g_new (char *, g_slist_length (list) + 1);
	i = 0;
	for (iter = list; iter; iter = g_slist_next (iter))
		dns_arr[i++] = nmc_ip6_address_as_string (iter->data, NULL);

	dns_arr[i] = NULL;

	/* domains */
	ptr_array = nm_ip6_config_get_domains (cfg6);
	if (ptr_array) {
		domain_arr = g_new (char *, ptr_array->len + 1);
		for (i = 0; i < ptr_array->len; i++)
			domain_arr[i] = g_ptr_array_index (ptr_array, i);

		domain_arr[i] = NULL;
	}

	set_val_str (nmc->allowed_fields, 0, group_prefix);
	set_val_arr (nmc->allowed_fields, 1, (const char **) addr_arr);
	set_val_arr (nmc->allowed_fields, 2, (const char **) route_arr);
	set_val_arr (nmc->allowed_fields, 3, (const char **) dns_arr);
	set_val_arr (nmc->allowed_fields, 4, (const char **) domain_arr);

	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_SECTION_PREFIX;
	print_fields (nmc->print_fields, nmc->allowed_fields); /* Print values */

	g_strfreev (addr_arr);
	g_strfreev (route_arr);
	g_strfreev (dns_arr);
	g_free (domain_arr);

	return TRUE;
}

gboolean
print_dhcp4_config (NMDHCP4Config *dhcp4, NmCli *nmc, const char *group_prefix)
{
	GHashTable *table;
	guint32 mode_flag = (nmc->print_output == NMC_PRINT_PRETTY) ? NMC_PF_FLAG_PRETTY : (nmc->print_output == NMC_PRINT_TERSE) ? NMC_PF_FLAG_TERSE : 0;
	guint32 multiline_flag = nmc->multiline_output ? NMC_PF_FLAG_MULTILINE : 0;
	guint32 escape_flag = nmc->escape_values ? NMC_PF_FLAG_ESCAPE : 0;

	if (dhcp4 == NULL)
		return FALSE;

	table = nm_dhcp4_config_get_options (dhcp4);
	if (table) {
		GHashTableIter table_iter;
		gpointer key, value;
		char **options_arr = NULL;
		int i = 0;

		nmc->allowed_fields = nmc_fields_dhcp4_config;
		nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_FIELD_NAMES;
		nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_DHCP4_CONFIG_ALL, nmc->allowed_fields, NULL);
		print_fields (nmc->print_fields, nmc->allowed_fields); /* Print header */

		options_arr = g_new (char *, g_hash_table_size (table) + 1);
		g_hash_table_iter_init (&table_iter, table);
		while (g_hash_table_iter_next (&table_iter, &key, &value))
			options_arr[i++] = g_strdup_printf ("%s = %s", (char *) key, (char *) value);
		options_arr[i] = NULL;

		set_val_str (nmc->allowed_fields, 0, group_prefix);
		set_val_arr (nmc->allowed_fields, 1, (const char **) options_arr);

		nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_SECTION_PREFIX;
		print_fields (nmc->print_fields, nmc->allowed_fields); /* Print values */

		g_strfreev (options_arr);

		return TRUE;
	}
	return FALSE;
}

gboolean
print_dhcp6_config (NMDHCP6Config *dhcp6, NmCli *nmc, const char *group_prefix)
{
	GHashTable *table;
	guint32 mode_flag = (nmc->print_output == NMC_PRINT_PRETTY) ? NMC_PF_FLAG_PRETTY : (nmc->print_output == NMC_PRINT_TERSE) ? NMC_PF_FLAG_TERSE : 0;
	guint32 multiline_flag = nmc->multiline_output ? NMC_PF_FLAG_MULTILINE : 0;
	guint32 escape_flag = nmc->escape_values ? NMC_PF_FLAG_ESCAPE : 0;

	if (dhcp6 == NULL)
		return FALSE;

	table = nm_dhcp6_config_get_options (dhcp6);
	if (table) {
		GHashTableIter table_iter;
		gpointer key, value;
		char **options_arr = NULL;
		int i = 0;

		nmc->allowed_fields = nmc_fields_dhcp6_config;
		nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_FIELD_NAMES;
		nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_DHCP6_CONFIG_ALL, nmc->allowed_fields, NULL);
		print_fields (nmc->print_fields, nmc->allowed_fields); /* Print header */

		options_arr = g_new (char *, g_hash_table_size (table) + 1);
		g_hash_table_iter_init (&table_iter, table);
		while (g_hash_table_iter_next (&table_iter, &key, &value))
			options_arr[i++] = g_strdup_printf ("%s = %s", (char *) key, (char *) value);
		options_arr[i] = NULL;

		set_val_str (nmc->allowed_fields, 0, group_prefix);
		set_val_arr (nmc->allowed_fields, 1, (const char **) options_arr);

		nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_SECTION_PREFIX;
		print_fields (nmc->print_fields, nmc->allowed_fields); /* Print values */

		g_strfreev (options_arr);

		return TRUE;
	}
	return FALSE;
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

	default:
		return _("Unknown");
	}
}

