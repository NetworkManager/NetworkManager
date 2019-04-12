/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/* NetworkManager system settings service (ifupdown)
 *
 * Alexander Sack <asac@ubuntu.com>
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
 * (C) Copyright 2008 Canonical Ltd.
 */

#include "nm-default.h"

#include "nms-ifupdown-parser.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <ctype.h>

#include "nm-core-internal.h"
#include "settings/nm-settings-plugin.h"

#include "nms-ifupdown-plugin.h"
#include "nms-ifupdown-parser.h"

/*****************************************************************************/

#define _NMLOG_PREFIX_NAME      "ifupdown"
#define _NMLOG_DOMAIN           LOGD_SETTINGS
#define _NMLOG(level, ...) \
    nm_log ((level), _NMLOG_DOMAIN, NULL, NULL, \
            "%s" _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
            _NMLOG_PREFIX_NAME": " \
            _NM_UTILS_MACRO_REST (__VA_ARGS__))

/*****************************************************************************/

#define _str_has_prefix(val, prefix, require_suffix) \
	({ \
		const char *_val = (val); \
		\
		   (strncmp (_val, ""prefix"", NM_STRLEN (prefix)) == 0) \
		&& (   !(require_suffix) \
		    || _val[NM_STRLEN (prefix)] != '\0'); \
	})

static const char*
_ifupdownplugin_guess_connection_type (if_block *block)
{
	const char *ret_type = NULL;

	if (nm_streq0 (ifparser_getkey (block, "inet"), "ppp"))
		ret_type = NM_SETTING_PPP_SETTING_NAME;
	else {
		if_data *ifb;

		c_list_for_each_entry (ifb, &block->data_lst_head, data_lst) {
			if (   _str_has_prefix (ifb->key, "wireless-", FALSE)
			    || _str_has_prefix (ifb->key, "wpa-", FALSE)) {
				ret_type = NM_SETTING_WIRELESS_SETTING_NAME;
				break;
			}
		}
		if (!ret_type)
			ret_type = NM_SETTING_WIRED_SETTING_NAME;
	}

	_LOGI ("guessed connection type (%s) = %s", block->name, ret_type);
	return ret_type;
}

struct _Mapping {
	const char *domain;
	const gpointer target;
};

static gpointer
map_by_mapping (struct _Mapping *mapping, const char *key)
{
	struct _Mapping *curr = mapping;

	while (curr->domain) {
		if (nm_streq (curr->domain, key))
			return curr->target;
		curr++;
	}
	return NULL;
}

static void
update_wireless_setting_from_if_block (NMConnection *connection,
                                       if_block *block)
{
	if_data *curr;
	const char *value = ifparser_getkey (block, "inet");
	struct _Mapping mapping[] = {
		{"ssid", "ssid"},
		{"essid", "ssid"},
		{"mode", "mode"},
		{ NULL, NULL}
	};

	NMSettingWireless *wireless_setting = NULL;

	if (nm_streq0 (value, "ppp"))
		return;

	_LOGI ("update wireless settings (%s).", block->name);
	wireless_setting = NM_SETTING_WIRELESS (nm_setting_wireless_new ());

	c_list_for_each_entry (curr, &block->data_lst_head, data_lst) {
		if (_str_has_prefix (curr->key, "wireless-", TRUE)) {
			const char* newkey = map_by_mapping (mapping, curr->key + NM_STRLEN ("wireless-"));

			_LOGI ("wireless setting key: %s='%s'", newkey, curr->data);
			if (nm_streq0 (newkey, "ssid")) {
				GBytes *ssid;
				int len = strlen (curr->data);

				ssid = g_bytes_new (curr->data, len);
				g_object_set (wireless_setting, NM_SETTING_WIRELESS_SSID, ssid, NULL);
				g_bytes_unref (ssid);
				_LOGI ("setting wireless ssid = %d", len);
			} else if (nm_streq0 (newkey, "mode")) {
				if (!g_ascii_strcasecmp (curr->data, "Managed") || !g_ascii_strcasecmp (curr->data, "Auto"))
					g_object_set (wireless_setting, NM_SETTING_WIRELESS_MODE, NM_SETTING_WIRELESS_MODE_INFRA, NULL);
				else if (!g_ascii_strcasecmp (curr->data, "Ad-Hoc"))
					g_object_set (wireless_setting, NM_SETTING_WIRELESS_MODE, NM_SETTING_WIRELESS_MODE_ADHOC, NULL);
				else if (!g_ascii_strcasecmp (curr->data, "Master"))
					g_object_set (wireless_setting, NM_SETTING_WIRELESS_MODE, NM_SETTING_WIRELESS_MODE_AP, NULL);
				else
					_LOGW ("Invalid mode '%s' (not 'Ad-Hoc', 'Ap', 'Managed', or 'Auto')", curr->data);
			} else {
				g_object_set (wireless_setting,
				              newkey, curr->data,
				              NULL);
			}
		} else if (_str_has_prefix (curr->key, "wpa-", TRUE)) {
			const char* newkey = map_by_mapping (mapping, curr->key + NM_STRLEN ("wpa-"));

			if (nm_streq0 (newkey, "ssid")) {
				GBytes *ssid;
				int len = strlen (curr->data);

				ssid = g_bytes_new (curr->data, len);
				g_object_set (wireless_setting, NM_SETTING_WIRELESS_SSID, ssid, NULL);
				g_bytes_unref (ssid);
				_LOGI ("setting wpa ssid = %d", len);
			} else if (newkey) {

				g_object_set (wireless_setting,
				              newkey, curr->data,
				              NULL);
				_LOGI ("setting wpa newkey(%s)=data(%s)", newkey, curr->data);
			}
		}
	}
	nm_connection_add_setting (connection, (NMSetting*) wireless_setting);
}

typedef char* (*IfupdownStrDupeFunc) (gconstpointer value, gpointer data);
typedef gpointer (*IfupdownStrToTypeFunc) (const char* value);

static char*
normalize_dupe_wireless_key (gpointer value, gpointer data) {
	char* valuec = value;
	char* endc = valuec + strlen (valuec);
	char* delim = valuec;
	char* next = delim;
	char* result = malloc (strlen (valuec) + 1);
	char* result_cur = result;

	while (*delim && (next = strchr (delim, '-')) != NULL) {
		if (next == delim) {
			delim++;
			continue;
		}
		strncpy (result_cur, delim, next - delim);
		result_cur += next - delim;
		delim = next + 1;
	}
	if (*delim && strlen (valuec) > GPOINTER_TO_UINT (delim - valuec)) {
		strncpy (result_cur, delim, endc - delim);
		result_cur += endc - delim;
	}
	*result_cur = '\0';
	return result;
}

static char*
normalize_dupe (gpointer value, gpointer data) {
	return g_strdup (value);
}

static char*
normalize_tolower (gpointer value, gpointer data) {
	return g_ascii_strdown (value, -1);
}

static char *normalize_psk (gpointer value, gpointer data)
{
	if (strlen (value) >= 8 && strlen (value) <= 64)
		return g_strdup (value);
	return NULL;
}

static gpointer
string_to_gpointerint (const char* data)
{
	int result = (int) strtol (data, NULL, 10);
	return GINT_TO_POINTER (result);
}

static gpointer
string_to_glist_of_strings (const char* data)
{
	GSList *ret = NULL;
	char *string = (char*) data;
	while (string) {
		char* next = NULL;
		if ( (next = strchr (string, ' '))  ||
		     (next = strchr (string, '\t')) ||
		     (next = strchr (string, '\0')) ) {

			char *part = g_strndup (string, (next - string));
			ret = g_slist_append (ret, part);
			if (*next)
				string = next+1;
			else
				string = NULL;
		} else {
			string = NULL;
		}
	}
	return ret;
}

static void
slist_free_all (gpointer slist)
{
	g_slist_free_full ((GSList *) slist, g_free);
}

static void
update_wireless_security_setting_from_if_block (NMConnection *connection,
                                                if_block *block)
{
	if_data *curr;
	const char* value = ifparser_getkey (block, "inet");
	struct _Mapping mapping[] = {
		{"psk", "psk"},
		{"identity", "leap-username"},
		{"password", "leap-password"},
		{"key", "wep-key0"},
		{"key-mgmt", "key-mgmt"},
		{"group", "group"},
		{"pairwise", "pairwise"},
		{"proto", "proto"},
		{"pin", "pin"},
		{"wep-key0", "wep-key0"},
		{"wep-key1", "wep-key1"},
		{"wep-key2", "wep-key2"},
		{"wep-key3", "wep-key3"},
		{"wep-tx-keyidx", "wep-tx-keyidx"},
		{ NULL, NULL}
	};

	struct _Mapping dupe_mapping[] = {
		{"psk", normalize_psk},
		{"identity", normalize_dupe},
		{"password", normalize_dupe},
		{"key", normalize_dupe_wireless_key},
		{"key-mgmt", normalize_tolower},
		{"group", normalize_tolower},
		{"pairwise", normalize_tolower},
		{"proto", normalize_tolower},
		{"pin", normalize_dupe},
		{"wep-key0", normalize_dupe_wireless_key},
		{"wep-key1", normalize_dupe_wireless_key},
		{"wep-key2", normalize_dupe_wireless_key},
		{"wep-key3", normalize_dupe_wireless_key},
		{"wep-tx-keyidx", normalize_dupe},
		{ NULL, NULL}
	};

	struct _Mapping type_mapping[] = {
		{"group", string_to_glist_of_strings},
		{"pairwise", string_to_glist_of_strings},
		{"proto", string_to_glist_of_strings},
		{"wep-tx-keyidx", string_to_gpointerint},
		{ NULL, NULL}
	};

	struct _Mapping free_type_mapping[] = {
		{"group", slist_free_all},
		{"pairwise", slist_free_all},
		{"proto", slist_free_all},
		{ NULL, NULL}
	};

	NMSettingWirelessSecurity *wireless_security_setting;
	NMSettingWireless *s_wireless;
	gboolean security = FALSE;

	if (nm_streq0 (value, "ppp"))
		return;

	s_wireless = nm_connection_get_setting_wireless (connection);
	g_return_if_fail (s_wireless);

	_LOGI ("update wireless security settings (%s).", block->name);
	wireless_security_setting = NM_SETTING_WIRELESS_SECURITY (nm_setting_wireless_security_new ());

	c_list_for_each_entry (curr, &block->data_lst_head, data_lst) {
		if (_str_has_prefix (curr->key, "wireless-", TRUE)) {
			const char *key = curr->key + NM_STRLEN ("wireless-");
			char *property_value = NULL;
			gpointer typed_property_value = NULL;
			const char* newkey = map_by_mapping (mapping, key);
			IfupdownStrDupeFunc dupe_func = map_by_mapping (dupe_mapping, key);
			IfupdownStrToTypeFunc type_map_func = map_by_mapping (type_mapping, key);
			GFreeFunc free_func = map_by_mapping (free_type_mapping, key);
			if (!newkey || !dupe_func)
				goto next;

			property_value = (*dupe_func) (curr->data, connection);
			_LOGI ("setting wireless security key: %s=%s",
			       newkey, property_value);

			if (type_map_func) {
				errno = 0;
				typed_property_value = (*type_map_func) (property_value);
				if (errno)
					goto wireless_next;
			}

			g_object_set (wireless_security_setting,
			              newkey, typed_property_value ?: property_value,
			              NULL);
			security = TRUE;

wireless_next:
			g_free (property_value);
			if (typed_property_value && free_func)
				(*free_func) (typed_property_value);

		} else if (_str_has_prefix (curr->key, "wpa-", TRUE)) {
			const char *key = curr->key + NM_STRLEN ("wpa-");
			char *property_value = NULL;
			gpointer typed_property_value = NULL;
			const char* newkey = map_by_mapping (mapping, key);
			IfupdownStrDupeFunc dupe_func = map_by_mapping (dupe_mapping, key);
			IfupdownStrToTypeFunc type_map_func = map_by_mapping (type_mapping, key);
			GFreeFunc free_func = map_by_mapping (free_type_mapping, key);
			if (!newkey || !dupe_func)
				goto next;

			property_value = (*dupe_func) (curr->data, connection);
			_LOGI ("setting wpa security key: %s=%s",
			       newkey,
			       NM_IN_STRSET (newkey, "key",
			                             "leap-password",
			                             "pin",
			                             "psk",
			                             "wep-key0",
			                             "wep-key1",
			                             "wep-key2",
			                             "wep-key3")
			         ? "<omitted>"
			         : property_value
			       );

			if (type_map_func) {
				errno = 0;
				typed_property_value = (*type_map_func) (property_value);
				if (errno)
					goto wpa_next;
			}

			g_object_set (wireless_security_setting,
			              newkey, typed_property_value ?: property_value,
			              NULL);
			security = TRUE;

wpa_next:
			g_free (property_value);
			if (free_func && typed_property_value)
				(*free_func) (typed_property_value);
		}
next:
		;
	}

	if (security)
		nm_connection_add_setting (connection, NM_SETTING (wireless_security_setting));
}

static void
update_wired_setting_from_if_block (NMConnection *connection,
                                    if_block *block)
{
	NMSettingWired *s_wired = NULL;
	s_wired = NM_SETTING_WIRED (nm_setting_wired_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_wired));
}

static void
ifupdown_ip4_add_dns (NMSettingIPConfig *s_ip4, const char *dns)
{
	gs_free const char **list = NULL;
	const char **iter;
	guint32 addr;

	if (dns == NULL)
		return;

	list = nm_utils_strsplit_set (dns, " \t");
	for (iter = list; iter && *iter; iter++) {
		if (!inet_pton (AF_INET, *iter, &addr)) {
			_LOGW ("    ignoring invalid nameserver '%s'", *iter);
			continue;
		}

		if (!nm_setting_ip_config_add_dns (s_ip4, *iter))
			_LOGW ("    duplicate DNS domain '%s'", *iter);
	}
}

static gboolean
update_ip4_setting_from_if_block (NMConnection *connection,
                                  if_block *block,
                                  GError **error)
{

	gs_unref_object NMSettingIPConfig *s_ip4 = NM_SETTING_IP_CONFIG (nm_setting_ip4_config_new ());
	const char *type = ifparser_getkey (block, "inet");

	if (!nm_streq0 (type, "static")) {
		g_object_set (s_ip4,
		              NM_SETTING_IP_CONFIG_METHOD,
		              NM_SETTING_IP4_CONFIG_METHOD_AUTO,
		              NULL);
	} else {
		guint32 tmp_mask;
		NMIPAddress *addr;
		const char *address_v;
		const char *netmask_v;
		const char *gateway_v;
		const char *nameserver_v;
		const char *nameservers_v;
		const char *search_v;
		guint32 netmask_int = 32;

		/* Address */
		address_v = ifparser_getkey (block, "address");
		if (!address_v) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Missing IPv4 address");
			return FALSE;
		}

		/* mask/prefix */
		netmask_v = ifparser_getkey (block, "netmask");
		if (netmask_v) {
			if (strlen (netmask_v) < 7) {
				netmask_int = atoi (netmask_v);
			} else if (!inet_pton (AF_INET, netmask_v, &tmp_mask)) {
				g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
				             "Invalid IPv4 netmask '%s'", netmask_v);
				return FALSE;
			} else {
				netmask_int = nm_utils_ip4_netmask_to_prefix (tmp_mask);
			}
		}

		/* Add the new address to the setting */
		addr = nm_ip_address_new (AF_INET, address_v, netmask_int, error);
		if (!addr)
			return FALSE;

		if (nm_setting_ip_config_add_address (s_ip4, addr)) {
			_LOGI ("addresses count: %d",
			       nm_setting_ip_config_get_num_addresses (s_ip4));
		} else {
			_LOGI ("ignoring duplicate IP4 address");
		}
		nm_ip_address_unref (addr);

		/* gateway */
		gateway_v = ifparser_getkey (block, "gateway");
		if (gateway_v) {
			if (!nm_utils_ipaddr_valid (AF_INET, gateway_v)) {
				g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
				             "Invalid IPv4 gateway '%s'", gateway_v);
				return FALSE;
			}
			if (!nm_setting_ip_config_get_gateway (s_ip4))
				g_object_set (s_ip4, NM_SETTING_IP_CONFIG_GATEWAY, gateway_v, NULL);
		}

		nameserver_v = ifparser_getkey (block, "dns-nameserver");
		ifupdown_ip4_add_dns (s_ip4, nameserver_v);

		nameservers_v = ifparser_getkey (block, "dns-nameservers");
		ifupdown_ip4_add_dns (s_ip4, nameservers_v);

		if (!nm_setting_ip_config_get_num_dns (s_ip4))
			_LOGI ("No dns-nameserver configured in /etc/network/interfaces");

		/* DNS searches */
		search_v = ifparser_getkey (block, "dns-search");
		if (search_v) {
			gs_free const char **list = NULL;
			const char **iter;

			list = nm_utils_strsplit_set (search_v, " \t");
			for (iter = list; iter && *iter; iter++) {
				if (!nm_setting_ip_config_add_dns_search (s_ip4, *iter))
					_LOGW ("    duplicate DNS domain '%s'", *iter);
			}
		}

		g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL, NULL);
	}

	nm_connection_add_setting (connection, NM_SETTING (g_steal_pointer (&s_ip4)));
	return TRUE;
}

static void
ifupdown_ip6_add_dns (NMSettingIPConfig *s_ip6, const char *dns)
{
	gs_free const char **list = NULL;
	const char **iter;
	struct in6_addr addr;

	if (dns == NULL)
		return;

	list = nm_utils_strsplit_set (dns, " \t");
	for (iter = list; iter && *iter; iter++) {
		if (!inet_pton (AF_INET6, *iter, &addr)) {
			_LOGW ("    ignoring invalid nameserver '%s'", *iter);
			continue;
		}

		if (!nm_setting_ip_config_add_dns (s_ip6, *iter))
			_LOGW ("    duplicate DNS domain '%s'", *iter);
	}
}

static gboolean
update_ip6_setting_from_if_block (NMConnection *connection,
                                  if_block *block,
                                  GError **error)
{
	gs_unref_object NMSettingIPConfig *s_ip6 = NM_SETTING_IP_CONFIG (nm_setting_ip6_config_new ());
	const char *type = ifparser_getkey (block, "inet6");

	if (!NM_IN_STRSET (type, "static", "v4tunnel")) {
		g_object_set (s_ip6,
		              NM_SETTING_IP_CONFIG_METHOD,
		              NM_SETTING_IP6_CONFIG_METHOD_AUTO,
		              NULL);
	} else {
		NMIPAddress *addr;
		const char *address_v;
		const char *prefix_v;
		const char *gateway_v;
		const char *nameserver_v;
		const char *nameservers_v;
		const char *search_v;
		int prefix_int = 128;

		/* Address */
		address_v = ifparser_getkey (block, "address");
		if (!address_v) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Missing IPv6 address");
			return FALSE;
		}

		/* Prefix */
		prefix_v = ifparser_getkey (block, "netmask");
		if (prefix_v)
			prefix_int = g_ascii_strtoll (prefix_v, NULL, 10);

		/* Add the new address to the setting */
		addr = nm_ip_address_new (AF_INET6, address_v, prefix_int, error);
		if (!addr)
			return FALSE;

		if (nm_setting_ip_config_add_address (s_ip6, addr)) {
			_LOGI ("addresses count: %d",
			             nm_setting_ip_config_get_num_addresses (s_ip6));
		} else {
			_LOGI ("ignoring duplicate IP6 address");
		}
		nm_ip_address_unref (addr);

		/* gateway */
		gateway_v = ifparser_getkey (block, "gateway");
		if (gateway_v) {
			if (!nm_utils_ipaddr_valid (AF_INET6, gateway_v)) {
				g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
				             "Invalid IPv6 gateway '%s'", gateway_v);
				return FALSE;
			}
			if (!nm_setting_ip_config_get_gateway (s_ip6))
				g_object_set (s_ip6, NM_SETTING_IP_CONFIG_GATEWAY, gateway_v, NULL);
		}

		nameserver_v = ifparser_getkey (block, "dns-nameserver");
		ifupdown_ip6_add_dns (s_ip6, nameserver_v);

		nameservers_v = ifparser_getkey (block, "dns-nameservers");
		ifupdown_ip6_add_dns (s_ip6, nameservers_v);

		if (!nm_setting_ip_config_get_num_dns (s_ip6))
			_LOGI ("No dns-nameserver configured in /etc/network/interfaces");

		/* DNS searches */
		search_v = ifparser_getkey (block, "dns-search");
		if (search_v) {
			gs_free const char **list = NULL;
			const char **iter;

			list = nm_utils_strsplit_set (search_v, " \t");
			for (iter = list; iter && *iter; iter++) {
				if (!nm_setting_ip_config_add_dns_search (s_ip6, *iter))
					_LOGW ("    duplicate DNS domain '%s'", *iter);
			}
		}

		g_object_set (s_ip6,
		              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_MANUAL,
		              NULL);
	}

	nm_connection_add_setting (connection, NM_SETTING (g_steal_pointer (&s_ip6)));
	return TRUE;
}

gboolean
ifupdown_update_connection_from_if_block (NMConnection *connection,
                                          if_block *block,
                                          GError **error)
{
	const char *type;
	gs_free char *idstr = NULL;
	gs_free char *uuid = NULL;
	NMSettingConnection *s_con;
	gboolean success = FALSE;

	s_con = nm_connection_get_setting_connection (connection);
	if (!s_con) {
		s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
		nm_connection_add_setting (connection, NM_SETTING (s_con));
	}

	type = _ifupdownplugin_guess_connection_type (block);
	idstr = g_strconcat ("Ifupdown (", block->name, ")", NULL);

	uuid = nm_utils_uuid_generate_from_string (idstr, -1, NM_UTILS_UUID_TYPE_LEGACY, NULL);
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_TYPE, type,
	              NM_SETTING_CONNECTION_INTERFACE_NAME, block->name,
	              NM_SETTING_CONNECTION_ID, idstr,
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_READ_ONLY, TRUE,
	              NM_SETTING_CONNECTION_AUTOCONNECT, FALSE,
	              NULL);

	_LOGI ("update_connection_setting_from_if_block: name:%s, type:%s, id:%s, uuid: %s",
	       block->name, type, idstr, nm_setting_connection_get_uuid (s_con));

	if (nm_streq (type, NM_SETTING_WIRED_SETTING_NAME))
		update_wired_setting_from_if_block (connection, block);
	else if (nm_streq (type, NM_SETTING_WIRELESS_SETTING_NAME)) {
		update_wireless_setting_from_if_block (connection, block);
		update_wireless_security_setting_from_if_block (connection, block);
	}

	if (ifparser_haskey (block, "inet6"))
		success = update_ip6_setting_from_if_block (connection, block, error);
	else
		success = update_ip4_setting_from_if_block (connection, block, error);

	if (success == TRUE)
		success = nm_connection_verify (connection, error);

	return success;
}
