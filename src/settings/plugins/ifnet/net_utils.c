/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * Mu Qiao <qiaomuf@gmail.com>
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
 * Copyright (C) 1999-2010 Gentoo Foundation, Inc.
 */

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <nm-utils.h>
#include "NetworkManagerUtils.h"
#include <nm-system-config-interface.h>
#include "nm-config.h"
#include "nm-default.h"
#include "net_utils.h"
#include "wpa_parser.h"
#include "net_parser.h"

/* emit heading and tailing blank space, tab, character t */
gchar *
strip_string (gchar * str, gchar t)
{
	gchar *ret = str;
	gint length = 0;
	guint i = 0;

	while (ret[i] != '\0'
	       && (ret[i] == '\t' || ret[i] == ' ' || ret[i] == t)) {
		length++;
		i++;
	}
	i = 0;
	while (ret[i + length] != '\0') {
		ret[i] = ret[i + length];
		i++;
	}
	ret[i] = '\0';
	length = strlen (ret);
	while ((length - 1) >= 0
	       && (ret[length - 1] == ' ' || ret[length - 1] == '\n'
		   || ret[length - 1] == '\t' || ret[length - 1] == t))
		length--;
	ret[length] = '\0';
	return ret;
}

gboolean
is_hex (const char *value)
{
	const char *p = value;

	if (!p)
		return FALSE;
	while (*p) {
		if (!g_ascii_isxdigit (*p++))
			return FALSE;
	}
	return TRUE;
}

gboolean
is_ascii (const char *value)
{
	const char *p = value;

	while (*p) {
		if (!g_ascii_isprint (*p++))
			return FALSE;
	}
	return TRUE;

}

gboolean
is_true (const char *str)
{
	if (!g_ascii_strcasecmp (str, "yes")
	    || !g_ascii_strcasecmp (str, "true"))
		return TRUE;
	return FALSE;
}

static char *
find_default_gateway_str (char *str)
{
	char *tmp;

	if ((tmp = strstr (str, "default via ")) != NULL) {
		return tmp + strlen ("default via ");
	} else if ((tmp = strstr (str, "default gw ")) != NULL) {
		return tmp + strlen ("default gw ");
	}
	return NULL;
}

static char *
find_gateway_str (char *str)
{
	char *tmp;

	if ((tmp = strstr (str, "via ")) != NULL) {
		return tmp + strlen ("via ");
	} else if ((tmp = strstr (str, "gw ")) != NULL) {
		return tmp + strlen ("gw ");
	}
	return NULL;
}

gboolean
reload_parsers (void)
{
	ifnet_destroy ();
	wpa_parser_destroy ();
	if (!ifnet_init (CONF_NET_FILE))
		return FALSE;
	wpa_parser_init (WPA_SUPPLICANT_CONF);
	return TRUE;
}

gboolean
is_static_ip4 (const char *conn_name)
{
	const char *data = ifnet_get_data (conn_name, "config");
	const char *dhcp6;

	if (!data)
		return FALSE;
	if (!strcmp (data, "shared"))
		return FALSE;
	if (!strcmp (data, "autoip"))
		return FALSE;
	dhcp6 = strstr (data, "dhcp6");
	if (dhcp6) {
		gchar *dhcp4;

		if (strstr (data, "dhcp "))
			return FALSE;
		dhcp4 = strstr (data, "dhcp");
		if (!dhcp4)
			return TRUE;
		if (dhcp4[4] == '\0')
			return FALSE;
		return TRUE;
	}
	return strstr (data, "dhcp") == NULL ? TRUE : FALSE;
}

gboolean
is_static_ip6 (const char *conn_name)
{
	const char *data = ifnet_get_data (conn_name, "config");

	if (!data)
		return TRUE;
	return strstr (data, "dhcp6") == NULL ? TRUE : FALSE;
}

gboolean
is_ip4_address (const char *in_address)
{
	const char *pattern =
	    "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.((\\{\\d{1,3}\\.\\.\\d{1,3}\\})|\\d{1,3})$";
	gchar *address = g_strdup (in_address);
	gboolean result = FALSE;
	gchar *tmp;
	GRegex *regex = g_regex_new (pattern, 0, 0, NULL);
	GMatchInfo *match_info = NULL;

	if (!address)
		goto done;
	g_strstrip (address);
	if ((tmp = strstr (address, "/")) != NULL)
		*tmp = '\0';
	if ((tmp = strstr (address, " ")) != NULL)
		*tmp = '\0';
	g_regex_match (regex, address, 0, &match_info);
	result = g_match_info_matches (match_info);
done:
	if (match_info)
		g_match_info_free (match_info);
	g_regex_unref (regex);
	g_free (address);
	return result;
}

gboolean
is_ip6_address (const char *in_address)
{
	struct in6_addr tmp_ip6_addr;
	gchar *tmp, *address;
	gboolean result = FALSE;

	if (!in_address)
		return FALSE;
	address = g_strdup (in_address);
	g_strstrip (address);
	if ((tmp = strchr (address, '/')) != NULL)
		*tmp = '\0';
	if (inet_pton (AF_INET6, address, &tmp_ip6_addr))
		result = TRUE;
	g_free (address);
	return result;

}

// 'c' is only used for openrc style
static gchar **
split_addresses_by_char (const gchar *addresses, const gchar *c)
{
	gchar **ipset;

	if (addresses == NULL)
		return NULL;

	if (strchr (addresses, '(') != NULL) { // old baselayout style
		gchar *tmp = g_strdup (addresses);
		strip_string (tmp, '(');
		strip_string (tmp, ')');
		strip_string (tmp, '"');
		strip_string (tmp, '\'');
		ipset = g_strsplit (tmp, "\" \"", 0);
		g_free(tmp);
	} else { // openrc style
		if (strstr (addresses, "netmask"))
			// There is only one ip address if "netmask" is specified.
			// '\n' is not used in config so there will be only one split.
			ipset = g_strsplit (addresses, "\n", 0);
		else
			ipset = g_strsplit (addresses, c, 0);
	}

	return ipset;
}

static gchar **
split_addresses (const gchar* addresses)
{
	// " " is only used by openrc style
	return split_addresses_by_char (addresses, " ");
}

static gchar **
split_routes (const gchar* routes)
{
	// "\"" is only used by openrc style
	return split_addresses_by_char (routes, "\"");
}

gboolean
has_ip6_address (const char *conn_name)
{
	gchar **ipset;
	guint length;
	guint i;

	g_return_val_if_fail (conn_name != NULL, FALSE);
	ipset = split_addresses (ifnet_get_data (conn_name, "config"));
	length = ipset ? g_strv_length (ipset) : 0;
	for (i = 0; i < length; i++) {
		if (!is_ip6_address (ipset[i]))
			continue;
		else {
			g_strfreev (ipset);
			return TRUE;
		}

	}
	g_strfreev (ipset);
	return FALSE;
}

gboolean
has_default_route (const char *conn_name, gboolean (*check_fn) (const char *))
{
	char *routes = NULL, *end, *tmp;
	gboolean success = FALSE;

	g_return_val_if_fail (conn_name != NULL, FALSE);

	routes = g_strdup (ifnet_get_data (conn_name, "routes"));
	if (!routes)
		return FALSE;
	tmp = find_default_gateway_str (routes);
	if (tmp) {
		g_strstrip (tmp);
		if ((end = strstr (tmp, "\"")) != NULL)
			*end = '\0';
		if (check_fn (tmp))
			success = TRUE;
	}

	g_free (routes);
	return success;
}

static ip_block *
create_ip4_block (gchar * ip)
{
	ip_block *iblock = g_slice_new0 (ip_block);
	guint32 tmp_ip4_addr;
	int i;
	guint length;
	gchar **ip_mask;

	/* prefix format */
	if (strstr (ip, "/")) {
		gchar *prefix;

		ip_mask = g_strsplit (ip, "/", 0);
		length = g_strv_length (ip_mask);
		if (!nm_utils_ipaddr_valid (AF_INET, ip_mask[0]))
			goto error;
		iblock->ip = g_strdup (ip_mask[0]);
		prefix = ip_mask[1];
		i = 0;
		while (i < length && g_ascii_isdigit (prefix[i]))
			i++;
		prefix[i] = '\0';
		iblock->prefix = (guint32) atoi (ip_mask[1]);
	} else if (strstr (ip, "netmask")) {
		ip_mask = g_strsplit (ip, " ", 0);
		length = g_strv_length (ip_mask);
		if (!nm_utils_ipaddr_valid (AF_INET, ip_mask[0]))
			goto error;
		iblock->ip = g_strdup (ip_mask[0]);
		i = 0;
		while (i < length && !strstr (ip_mask[++i], "netmask")) ;
		while (i < length && ip_mask[++i][0] == '\0') ;
		if (i >= length)
			goto error;
		if (!inet_pton (AF_INET, ip_mask[i], &tmp_ip4_addr))
			goto error;
		iblock->prefix = nm_utils_ip4_netmask_to_prefix (tmp_ip4_addr);
	} else {
		g_slice_free (ip_block, iblock);
		if (!is_ip6_address (ip) && !strstr (ip, "dhcp"))
			nm_log_warn (LOGD_SETTINGS, "Can't handle ipv4 address: %s, missing netmask or prefix", ip);
		return NULL;
	}
	if (iblock->prefix == 0 || iblock->prefix > 32) {
		nm_log_warn (LOGD_SETTINGS, "Can't handle ipv4 address: %s, invalid prefix", ip);
		goto error;
	}
	g_strfreev (ip_mask);
	return iblock;
error:
	if (!is_ip6_address (ip))
		nm_log_warn (LOGD_SETTINGS, "Can't handle IPv4 address: %s", ip);
	g_strfreev (ip_mask);
	g_free (iblock->ip);
	g_slice_free (ip_block, iblock);
	return NULL;
}

static ip_block *
create_ip_block (gchar * ip)
{
	ip_block *iblock = g_slice_new0 (ip_block);
	gchar *dup_ip = g_strdup (ip);
	gchar *prefix = NULL;

	if ((prefix = strstr (dup_ip, "/")) != NULL) {
		*prefix = '\0';
		prefix++;
	}
	if (!nm_utils_ipaddr_valid (AF_INET6, dup_ip))
		goto error;
	iblock->ip = dup_ip;
	if (prefix) {
		errno = 0;
		iblock->prefix = strtol (prefix, NULL, 10);
		if (errno || iblock->prefix <= 0 || iblock->prefix > 128) {
			goto error;
		}
	} else
		iblock->prefix = 64;
	return iblock;
error:
	if (!is_ip4_address (ip))
		nm_log_warn (LOGD_SETTINGS, "Can't handle IPv6 address: %s", ip);
	g_slice_free (ip_block, iblock);
	g_free (dup_ip);
	return NULL;
}

static char *
get_ip4_gateway (gchar * gateway)
{
	gchar *tmp, *split;

	if (!gateway)
		return NULL;
	tmp = find_gateway_str (gateway);
	if (!tmp) {
		nm_log_warn (LOGD_SETTINGS, "Couldn't obtain gateway in \"%s\"", gateway);
		return NULL;
	}
	tmp = g_strdup (tmp);
	strip_string (tmp, ' ');
	strip_string (tmp, '"');

	// Only one gateway is selected
	if ((split = strstr (tmp, "\"")) != NULL)
		*split = '\0';

	if (!nm_utils_ipaddr_valid (AF_INET, tmp))
		goto error;
	return tmp;
error:
	if (!is_ip6_address (tmp))
		nm_log_warn (LOGD_SETTINGS, "Can't handle IPv4 gateway: %s", tmp);
	g_free (tmp);
	return NULL;
}

static char *
get_ip6_next_hop (gchar * next_hop)
{
	gchar *tmp;

	if (!next_hop)
		return NULL;
	tmp = find_gateway_str (next_hop);
	if (!tmp) {
		nm_log_warn (LOGD_SETTINGS, "Couldn't obtain next_hop in \"%s\"", next_hop);
		return NULL;
	}
	tmp = g_strdup (tmp);
	strip_string (tmp, ' ');
	strip_string (tmp, '"');
	g_strstrip (tmp);
	if (!nm_utils_ipaddr_valid (AF_INET6, tmp))
		goto error;
	return tmp;
error:
	if (!is_ip4_address (tmp))
		nm_log_warn (LOGD_SETTINGS, "Can't handle IPv6 next_hop: %s", tmp);
	g_free (tmp);

	return NULL;
}

ip_block *
convert_ip4_config_block (const char *conn_name)
{
	gchar **ipset;
	guint length;
	guint i;
	gchar *ip;
	char *def_gateway = NULL;
	const char *routes;
	ip_block *start = NULL, *current = NULL, *iblock = NULL;

	g_return_val_if_fail (conn_name != NULL, NULL);

	ipset = split_addresses (ifnet_get_data (conn_name, "config"));
	length = ipset ? g_strv_length (ipset) : 0;

	routes = ifnet_get_data (conn_name, "routes");
	if (routes)
		def_gateway = get_ip4_gateway (strstr (routes, "default"));

	for (i = 0; i < length; i++) {
		ip = ipset[i];
		ip = strip_string (ip, '"');
		iblock = create_ip4_block (ip);
		if (iblock == NULL)
			continue;
		if (!iblock->next_hop && def_gateway != NULL)
			iblock->next_hop = g_strdup (def_gateway);
		if (start == NULL)
			start = current = iblock;
		else {
			current->next = iblock;
			current = iblock;
		}
	}
	g_strfreev (ipset);
	g_free (def_gateway);
	return start;
}

ip_block *
convert_ip6_config_block (const char *conn_name)
{
	gchar **ipset;
	guint length;
	guint i;
	gchar *ip;
	ip_block *start = NULL, *current = NULL, *iblock = NULL;

	g_return_val_if_fail (conn_name != NULL, NULL);
	ipset = split_addresses (ifnet_get_data (conn_name, "config"));
	length = ipset ? g_strv_length (ipset) : 0;
	for (i = 0; i < length; i++) {
		ip = ipset[i];
		ip = strip_string (ip, '"');
		iblock = create_ip_block (ip);
		if (iblock == NULL)
			continue;
		if (start == NULL)
			start = current = iblock;
		else {
			current->next = iblock;
			current = iblock;
		}
	}
	g_strfreev (ipset);
	return start;
}

ip_block *
convert_ip4_routes_block (const char *conn_name)
{
	gchar **ipset;
	guint length;
	guint i;
	gchar *ip;
	ip_block *start = NULL, *current = NULL, *iblock = NULL;

	g_return_val_if_fail (conn_name != NULL, NULL);

	ipset = split_routes (ifnet_get_data (conn_name, "routes"));
	length = ipset ? g_strv_length (ipset) : 0;
	for (i = 0; i < length; i++) {
		ip = ipset[i];
		if (find_default_gateway_str (ip) || strstr (ip, "::")
		    || !find_gateway_str (ip))
			continue;
		ip = strip_string (ip, '"');
		iblock = create_ip4_block (ip);
		if (iblock == NULL)
			continue;
		iblock->next_hop = get_ip4_gateway (ip);
		if (start == NULL)
			start = current = iblock;
		else {
			current->next = iblock;
			current = iblock;
		}
	}
	g_strfreev (ipset);
	return start;
}

ip_block *
convert_ip6_routes_block (const char *conn_name)
{
	gchar **ipset;
	guint length;
	guint i;
	gchar *ip, *tmp_addr;
	ip_block *start = NULL, *current = NULL, *iblock = NULL;

	g_return_val_if_fail (conn_name != NULL, NULL);
	ipset = split_routes (ifnet_get_data (conn_name, "routes"));
	length = ipset ? g_strv_length (ipset) : 0;
	for (i = 0; i < length; i++) {
		ip = ipset[i];
		ip = strip_string (ip, '"');
		if (ip[0] == '\0')
			continue;
		if ((tmp_addr = find_default_gateway_str (ip)) != NULL) {
			if (!is_ip6_address (tmp_addr))
				continue;
			else {
				iblock = g_slice_new0 (ip_block);
				iblock->ip = g_strdup ("::");
				iblock->prefix = 128;
			}
		} else
			iblock = create_ip_block (ip);
		if (iblock == NULL)
			continue;
		iblock->next_hop = get_ip6_next_hop (ip);
		if (iblock->next_hop == NULL) {
			destroy_ip_block (iblock);
			continue;
		}
		if (start == NULL)
			start = current = iblock;
		else {
			current->next = iblock;
			current = iblock;
		}
	}
	g_strfreev (ipset);
	return start;
}

void
destroy_ip_block (ip_block * iblock)
{
	g_free (iblock->ip);
	g_free (iblock->next_hop);
	g_slice_free (ip_block, iblock);
}

void
set_ip4_dns_servers (NMSettingIPConfig *s_ip4, const char *conn_name)
{
	const char *dns_servers;
	gchar **server_list, *stripped;
	guint length, i;
	guint32 tmp_ip4_addr;

	dns_servers = ifnet_get_data (conn_name, "dns_servers");
	if (!dns_servers)
		return;
	stripped = g_strdup (dns_servers);
	strip_string (stripped, '"');
	server_list = g_strsplit (stripped, " ", 0);
	g_free (stripped);

	length = g_strv_length (server_list);
	if (length)
		g_object_set (s_ip4, NM_SETTING_IP_CONFIG_IGNORE_AUTO_DNS,
			      TRUE, NULL);
	for (i = 0; i < length; i++) {
		g_strstrip (server_list[i]);
		if (server_list[i][0] == '\0')
			continue;
		if (!inet_pton (AF_INET, server_list[i], &tmp_ip4_addr)) {
			if (!is_ip6_address (server_list[i]))
				nm_log_warn (LOGD_SETTINGS, "ignored dns: %s\n", server_list[i]);
			continue;
		}
		if (!nm_setting_ip_config_add_dns (s_ip4, server_list[i]))
			nm_log_warn (LOGD_SETTINGS, "warning: duplicate DNS server %s", server_list[i]);
	}
	g_strfreev (server_list);
}

void
set_ip6_dns_servers (NMSettingIPConfig *s_ip6, const char *conn_name)
{
	const char *dns_servers;
	gchar **server_list, *stripped;
	guint length, i;
	struct in6_addr tmp_ip6_addr;

	dns_servers = ifnet_get_data (conn_name, "dns_servers");
	if (!dns_servers)
		return;

	stripped = g_strdup (dns_servers);
	strip_string (stripped, '"');
	server_list = g_strsplit (stripped, " ", 0);
	g_free (stripped);

	length = g_strv_length (server_list);
	if (length)
		g_object_set (s_ip6, NM_SETTING_IP_CONFIG_IGNORE_AUTO_DNS,
			      TRUE, NULL);
	for (i = 0; i < length; i++) {
		g_strstrip (server_list[i]);
		if (server_list[i][0] == '\0')
			continue;
		if (!inet_pton (AF_INET6, server_list[i], &tmp_ip6_addr)) {
			if (is_ip6_address (server_list[i]))
				nm_log_warn (LOGD_SETTINGS, "ignored dns: %s\n", server_list[i]);
			continue;
		}
		if (!nm_setting_ip_config_add_dns (s_ip6, server_list[i]))
			nm_log_warn (LOGD_SETTINGS, "warning: duplicate DNS server %s", server_list[i]);
	}
	g_strfreev (server_list);
}

gboolean
is_managed (const char *conn_name)
{
	gchar *config;

	g_return_val_if_fail (conn_name != NULL, FALSE);
	config = (gchar *) ifnet_get_data (conn_name, "managed");
	if (!config)
		return TRUE;
	if (strcmp (config, "false") == 0)
		return FALSE;
	return TRUE;
}

static char *
_has_prefix_impl (char *str, const char *prefix, gsize prefix_len)
{
	if (!g_str_has_prefix (str, prefix))
		return NULL;
	str += prefix_len;
	if (!g_ascii_isspace (str[0]))
		return NULL;
	do {
		str++;
	} while (g_ascii_isspace (str[0]));
	return str;
}
#define _has_prefix(STR, PREFIX) _has_prefix_impl (STR, PREFIX, STRLEN (PREFIX))

void
get_dhcp_hostname_and_client_id (char **hostname, char **client_id)
{
	const char *dhcp_client;
	const gchar *dhcpcd_conf = SYSCONFDIR "/dhcpcd.conf";
	const gchar *dhclient_conf = SYSCONFDIR "/dhcp/dhclient.conf";
	gchar *line = NULL, *tmp = NULL, *contents = NULL, *tmp1;
	gchar **all_lines;
	guint line_num, i;
	gboolean use_dhclient = FALSE;

	*hostname = NULL;
	*client_id = NULL;
	dhcp_client = nm_config_get_dhcp_client (nm_config_get ());
	if (dhcp_client) {
		if (!strcmp (dhcp_client, "dhclient")) {
			g_file_get_contents (dhclient_conf, &contents, NULL,
					     NULL);
			use_dhclient = TRUE;
		} else if (!strcmp (dhcp_client, "dhcpcd"))
			g_file_get_contents (dhcpcd_conf, &contents, NULL,
					     NULL);
	} else {
		if (g_file_test (dhclient_conf, G_FILE_TEST_IS_REGULAR)) {
			g_file_get_contents (dhclient_conf, &contents, NULL,
					     NULL);
			use_dhclient = TRUE;
		}
		else if (g_file_test (dhcpcd_conf, G_FILE_TEST_IS_REGULAR))
			g_file_get_contents (dhcpcd_conf, &contents, NULL,
					     NULL);
	}
	if (!contents)
		return;
	all_lines = g_strsplit (contents, "\n", 0);
	line_num = g_strv_length (all_lines);
	for (i = 0; i < line_num; i++) {
		line = all_lines[i];
		g_strstrip (line);
		if (line[0] == '#' || line[0] == '\0')
			continue;
		if (!use_dhclient) {
			// dhcpcd.conf
			if ((tmp = _has_prefix (line, "hostname"))) {
				if (tmp[0] != '\0') {
					g_free (*hostname);
					*hostname = g_strdup (tmp);
				} else
					nm_log_info (LOGD_SETTINGS, "dhcpcd hostname not defined, ignoring");
			} else if ((tmp = _has_prefix (line, "clientid"))) {
				if (tmp[0] != '\0') {
					g_free (*client_id);
					*client_id = g_strdup (tmp);
				} else
					nm_log_info (LOGD_SETTINGS, "dhcpcd clientid not defined, ignoring");
			}
		} else {
			// dhclient.conf
			if ((tmp1 = _has_prefix (line, "send"))) {
				if ((tmp = _has_prefix (tmp1, "host-name"))) {
					strip_string (tmp, ';');
					strip_string (tmp, '"');
					if (tmp[0] != '\0') {
						g_free (*hostname);
						*hostname = g_strdup (tmp);
					} else
						nm_log_info (LOGD_SETTINGS, "dhclient hostname not defined, ignoring");
				} else if ((tmp = _has_prefix (tmp1, "dhcp-client-identifier"))) {
					strip_string (tmp, ';');
					if (tmp[0] != '\0') {
						g_free (*client_id);
						*client_id = g_strdup (tmp);
					} else
						nm_log_info (LOGD_SETTINGS, "dhclient clientid not defined, ignoring");
				}
			}
		}
	}
	g_strfreev (all_lines);
	g_free (contents);
}

gchar *backup_file (const gchar* target)
{
	GFile *source, *backup;
	gchar* backup_path;
	GError **error = NULL;

	source = g_file_new_for_path (target);
	backup_path = g_strdup_printf ("%s.bak", target);
	backup = g_file_new_for_path (backup_path);

	g_file_copy (source, backup, G_FILE_COPY_OVERWRITE, NULL, NULL, NULL, error);
	if (error && *error) {
		nm_log_warn (LOGD_SETTINGS, "Backup failed: %s", (*error)->message);
		g_free (backup_path);
		backup_path = NULL;
	}

	return backup_path;
}
