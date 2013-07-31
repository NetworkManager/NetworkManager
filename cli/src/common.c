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
#include <stdlib.h>
#include <errno.h>

#include "common.h"
#include "utils.h"

/* Available fields for IPv4 group */
static NmcOutputField nmc_fields_ip4_config[] = {
	{"GROUP",      N_("GROUP"),       15},  /* 0 */
	{"ADDRESS",    N_("ADDRESS"),     68},  /* 1 */
	{"ROUTE",      N_("ROUTE"),       68},  /* 2 */
	{"DNS",        N_("DNS"),         35},  /* 3 */
	{"DOMAIN",     N_("DOMAIN"),      35},  /* 4 */
	{"WINS",       N_("WINS"),        20},  /* 5 */
	{NULL,         NULL,               0}
};
#define NMC_FIELDS_IP4_CONFIG_ALL     "GROUP,ADDRESS,ROUTE,DNS,DOMAIN,WINS"

/* Available fields for DHCPv4 group */
static NmcOutputField nmc_fields_dhcp4_config[] = {
	{"GROUP",      N_("GROUP"),       15},  /* 0 */
	{"OPTION",     N_("OPTION"),      80},  /* 1 */
	{NULL,         NULL,               0}
};
#define NMC_FIELDS_DHCP4_CONFIG_ALL     "GROUP,OPTION"

/* Available fields for IPv6 group */
static NmcOutputField nmc_fields_ip6_config[] = {
	{"GROUP",      N_("GROUP"),       15},  /* 0 */
	{"ADDRESS",    N_("ADDRESS"),     95},  /* 1 */
	{"ROUTE",      N_("ROUTE"),       95},  /* 2 */
	{"DNS",        N_("DNS"),         60},  /* 3 */
	{"DOMAIN",     N_("DOMAIN"),      35},  /* 4 */
	{NULL,         NULL,               0}
};
#define NMC_FIELDS_IP6_CONFIG_ALL     "GROUP,ADDRESS,ROUTE,DNS,DOMAIN"

/* Available fields for DHCPv6 group */
static NmcOutputField nmc_fields_dhcp6_config[] = {
	{"GROUP",      N_("GROUP"),       15},  /* 0 */
	{"OPTION",     N_("OPTION"),      80},  /* 1 */
	{NULL,         NULL,               0}
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
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;

	if (cfg4 == NULL)
		return FALSE;

	tmpl = nmc_fields_ip4_config;
	tmpl_len = sizeof (nmc_fields_ip4_config);
	nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_IP4_CONFIG_ALL, tmpl, NULL);
	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (nmc->output_data, arr);

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
			domain_arr[i] = g_strdup (g_ptr_array_index (ptr_array, i));

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

	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
	set_val_strc (arr, 0, group_prefix);
	set_val_arr  (arr, 1, addr_arr);
	set_val_arr  (arr, 2, route_arr);
	set_val_arr  (arr, 3, dns_arr);
	set_val_arr  (arr, 4, domain_arr);
	set_val_arr  (arr, 5, wins_arr);
	g_ptr_array_add (nmc->output_data, arr);

	print_data (nmc); /* Print all data */

	/* Remove any previous data */
	nmc_empty_output_fields (nmc);

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
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;

	if (cfg6 == NULL)
		return FALSE;

	tmpl = nmc_fields_ip6_config;
	tmpl_len = sizeof (nmc_fields_ip6_config);
	nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_IP6_CONFIG_ALL, tmpl, NULL);
	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (nmc->output_data, arr);

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
			domain_arr[i] = g_strdup (g_ptr_array_index (ptr_array, i));

		domain_arr[i] = NULL;
	}

	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
	set_val_strc (arr, 0, group_prefix);
	set_val_arr  (arr, 1, addr_arr);
	set_val_arr  (arr, 2, route_arr);
	set_val_arr  (arr, 3, dns_arr);
	set_val_arr  (arr, 4, domain_arr);
	g_ptr_array_add (nmc->output_data, arr);

	print_data (nmc); /* Print all data */

	/* Remove any previous data */
	nmc_empty_output_fields (nmc);

	return TRUE;
}

gboolean
print_dhcp4_config (NMDHCP4Config *dhcp4, NmCli *nmc, const char *group_prefix)
{
	GHashTable *table;
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;

	if (dhcp4 == NULL)
		return FALSE;

	table = nm_dhcp4_config_get_options (dhcp4);
	if (table) {
		GHashTableIter table_iter;
		gpointer key, value;
		char **options_arr = NULL;
		int i = 0;

		tmpl = nmc_fields_dhcp4_config;
		tmpl_len = sizeof (nmc_fields_dhcp4_config);
		nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_DHCP4_CONFIG_ALL, tmpl, NULL);
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
print_dhcp6_config (NMDHCP6Config *dhcp6, NmCli *nmc, const char *group_prefix)
{
	GHashTable *table;
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;

	if (dhcp6 == NULL)
		return FALSE;

	table = nm_dhcp6_config_get_options (dhcp6);
	if (table) {
		GHashTableIter table_iter;
		gpointer key, value;
		char **options_arr = NULL;
		int i = 0;

		tmpl = nmc_fields_dhcp6_config;
		tmpl_len = sizeof (nmc_fields_dhcp6_config);
		nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_DHCP6_CONFIG_ALL, tmpl, NULL);
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
 * Parse IPv4 address from string to NMIP4Address stucture.
 * ip_str is the IPv4 address in the form address/prefix
 * gw_str is the gateway address (it is optional)
 */
NMIP4Address *
nmc_parse_and_build_ip4_address (const char *ip_str, const char *gw_str, GError **error)
{
	NMIP4Address *addr = NULL;
	guint32 ip4_addr, gw_addr;
	char *tmp;
	char *plen;
	long int prefix;

	g_return_val_if_fail (ip_str != NULL, NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	tmp = g_strdup (ip_str);
	plen = strchr (tmp, '/');  /* prefix delimiter */
	if (plen)
		*plen++ = '\0';

	if (inet_pton (AF_INET, tmp, &ip4_addr) < 1) {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("invalid IPv4 address '%s'"), tmp);
		goto finish;
	}

	prefix = 32;
	if (plen) {
		if (!nmc_string_to_int (plen, TRUE, 1, 32, &prefix)) {
			g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			             _("invalid prefix '%s'; <1-32> allowed"), plen);
			goto finish;
		}
	}

	if (inet_pton (AF_INET, gw_str ? gw_str : "0.0.0.0", &gw_addr) < 1) {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("invalid gateway '%s'"), gw_str);
		goto finish;
	}

	addr = nm_ip4_address_new ();
	nm_ip4_address_set_address (addr, ip4_addr);
	nm_ip4_address_set_prefix (addr, (guint32) prefix);
	nm_ip4_address_set_gateway (addr, gw_addr);

finish:
	g_free (tmp);
	return addr;
}

/*
 * Parse IPv6 address from string to NMIP6Address stucture.
 * ip_str is the IPv6 address in the form address/prefix
 * gw_str is the gateway address (it is optional)
 */
NMIP6Address *
nmc_parse_and_build_ip6_address (const char *ip_str, const char *gw_str, GError **error)
{
	NMIP6Address *addr = NULL;
	struct in6_addr ip_addr, gw_addr;
	char *tmp;
	char *plen;
	long int prefix;

	g_return_val_if_fail (ip_str != NULL, NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	tmp = g_strdup (ip_str);
	plen = strchr (tmp, '/');  /* prefix delimiter */
	if (plen)
		*plen++ = '\0';

	if (inet_pton (AF_INET6, tmp, &ip_addr) < 1) {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("invalid IPv6 address '%s'"), tmp);
		goto finish;
	}

	prefix = 128;
	if (plen) {
		if (!nmc_string_to_int (plen, TRUE, 1, 128, &prefix)) {
			g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			             _("invalid prefix '%s'; <0-128> allowed"), plen);
			goto finish;
		}
	}

	if (inet_pton (AF_INET6, gw_str ? gw_str : "::", &gw_addr) < 1) {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("invalid gateway '%s'"), gw_str);
		goto finish;
	}

	addr = nm_ip6_address_new ();
	nm_ip6_address_set_address (addr, &ip_addr);
	nm_ip6_address_set_prefix (addr, (guint32) prefix);
	nm_ip6_address_set_gateway (addr, &gw_addr);

finish:
	g_free (tmp);
	return addr;
}

/*
 * Parse IPv4 routes from strings to NMIP4Route stucture.
 * ip_str is the IPv4 route in the form of address/prefix
 * next_hop_str is the next_hop address
 * metric_str is the route metric
 */
NMIP4Route *
nmc_parse_and_build_ip4_route (const char *ip_str, const char *next_hop_str, const char *metric_str, GError **error)
{
	NMIP4Route *route = NULL;
	guint32 ip4_addr, next_hop_addr;
	char *tmp;
	char *plen;
	long int prefix, metric;

	g_return_val_if_fail (ip_str != NULL, NULL);
	g_return_val_if_fail (next_hop_str != NULL, NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	tmp = g_strdup (ip_str);
	plen = strchr (tmp, '/');  /* prefix delimiter */
	if (plen)
		*plen++ = '\0';

	if (inet_pton (AF_INET, tmp, &ip4_addr) < 1) {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("invalid IPv4 route '%s'"), tmp);
		goto finish;
	}

	prefix = 32;
	if (plen) {
		if (!nmc_string_to_int (plen, TRUE, 0, 32, &prefix)) {
			g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			             _("invalid prefix '%s'; <0-32> allowed"), plen);
			goto finish;
		}
	}

	if (inet_pton (AF_INET, next_hop_str, &next_hop_addr) < 1) {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("invalid next hop address '%s'"), next_hop_str);
		goto finish;
	}

	metric = 0;
	if (metric_str) {
		if (!nmc_string_to_int (metric_str, TRUE, 0, G_MAXUINT32, &metric)) {
			g_set_error (error, 1, 0, _("invalid metric '%s'"), metric_str);
			goto finish;
		}
	}

	route = nm_ip4_route_new ();
	nm_ip4_route_set_dest (route, ip4_addr);
	nm_ip4_route_set_prefix (route, (guint32) prefix);
	nm_ip4_route_set_next_hop (route, next_hop_addr);
	nm_ip4_route_set_metric (route, (guint32) metric);

finish:
	g_free (tmp);
	return route;
}

/*
 * Parse IPv6 route from strings to NMIP6Route stucture.
 * ip_str is the IPv6 route in the form address/prefix
 * next_hop_str is the next hop
 * metric_str is the route metric
 */
NMIP6Route *
nmc_parse_and_build_ip6_route (const char *ip_str, const char *next_hop_str, const char *metric_str, GError **error)
{
	NMIP6Route *route = NULL;
	struct in6_addr ip_addr, next_hop_addr;
	char *tmp;
	char *plen;
	long int prefix, metric;

	g_return_val_if_fail (ip_str != NULL, NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	tmp = g_strdup (ip_str);
	plen = strchr (tmp, '/');  /* prefix delimiter */
	if (plen)
		*plen++ = '\0';

	if (inet_pton (AF_INET6, tmp, &ip_addr) < 1) {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("invalid IPv6 route '%s'"), tmp);
		goto finish;
	}

	prefix = 128;
	if (plen) {
		if (!nmc_string_to_int (plen, TRUE, 0, 128, &prefix)) {
			g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			             _("invalid prefix '%s'; <0-128> allowed"), plen);
			goto finish;
		}
	}

	if (inet_pton (AF_INET6, next_hop_str, &next_hop_addr) < 1) {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("invalid next hop address '%s'"), next_hop_str);
		goto finish;
	}

	metric = 0;
	if (metric_str) {
		if (!nmc_string_to_int (metric_str, TRUE, 0, G_MAXUINT32, &metric)) {
			g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			             _("invalid metric '%s'"), metric_str);
			goto finish;
		}
	}

	route = nm_ip6_route_new ();
	nm_ip6_route_set_dest (route, &ip_addr);
	nm_ip6_route_set_prefix (route, (guint32) prefix);
	nm_ip6_route_set_next_hop (route, &next_hop_addr);
	nm_ip6_route_set_metric (route, (guint32) metric);

finish:
	g_free (tmp);
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

	default:
		return _("Unknown");
	}
}


/* Max priority values from libnm-util/nm-setting-vlan.c */
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

