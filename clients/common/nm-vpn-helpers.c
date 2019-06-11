/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2013 - 2015 Red Hat, Inc.
 */

/**
 * SECTION:nm-vpn-helpers
 * @short_description: VPN-related utilities
 */

#include "nm-default.h"

#include "nm-vpn-helpers.h"

#include <arpa/inet.h>
#include <net/if.h>

#include "nm-client-utils.h"
#include "nm-utils.h"
#include "nm-glib-aux/nm-io-utils.h"
#include "nm-glib-aux/nm-secret-utils.h"

/*****************************************************************************/

NMVpnEditorPlugin *
nm_vpn_get_editor_plugin (const char *service_type, GError **error)
{
	NMVpnEditorPlugin *plugin = NULL;
	NMVpnPluginInfo *plugin_info;
	gs_free_error GError *local = NULL;

	g_return_val_if_fail (service_type, NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	plugin_info = nm_vpn_plugin_info_list_find_by_service (nm_vpn_get_plugin_infos (), service_type);

	if (!plugin_info) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_FAILED,
		             _("unknown VPN plugin \"%s\""), service_type);
		return NULL;
	}
	plugin = nm_vpn_plugin_info_get_editor_plugin (plugin_info);
	if (!plugin)
		plugin = nm_vpn_plugin_info_load_editor_plugin (plugin_info, &local);

	if (!plugin) {
		if (   !nm_vpn_plugin_info_get_plugin (plugin_info)
		    && nm_vpn_plugin_info_lookup_property (plugin_info, NM_VPN_PLUGIN_INFO_KF_GROUP_GNOME, "properties")) {
			g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_FAILED,
			             _("cannot load legacy-only VPN plugin \"%s\" for \"%s\""),
			             nm_vpn_plugin_info_get_name (plugin_info),
			             nm_vpn_plugin_info_get_filename (plugin_info));
		} else if (g_error_matches (local, G_FILE_ERROR, G_FILE_ERROR_NOENT)) {
			g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_FAILED,
			             _("cannot load VPN plugin \"%s\" due to missing \"%s\". Missing client plugin?"),
			             nm_vpn_plugin_info_get_name (plugin_info),
			             nm_vpn_plugin_info_get_plugin (plugin_info));
		} else {
			g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_FAILED,
			             _("failed to load VPN plugin \"%s\": %s"),
			             nm_vpn_plugin_info_get_name (plugin_info),
			             local->message);
		}
		return NULL;
	}

	return plugin;
}

GSList *
nm_vpn_get_plugin_infos (void)
{
	static bool plugins_loaded;
	static GSList *plugins = NULL;

	if (G_LIKELY (plugins_loaded))
		return plugins;
	plugins_loaded = TRUE;
	plugins = nm_vpn_plugin_info_list_load ();
	return plugins;
}

gboolean
nm_vpn_supports_ipv6 (NMConnection *connection)
{
	NMSettingVpn *s_vpn;
	const char *service_type;
	NMVpnEditorPlugin *plugin;
	guint32 capabilities;

	s_vpn = nm_connection_get_setting_vpn (connection);
	g_return_val_if_fail (s_vpn != NULL, FALSE);

	service_type = nm_setting_vpn_get_service_type (s_vpn);
	if (!service_type)
		return FALSE;

	plugin = nm_vpn_get_editor_plugin (service_type, NULL);
	if (!plugin)
		return FALSE;

	capabilities = nm_vpn_editor_plugin_get_capabilities (plugin);
	return NM_FLAGS_HAS (capabilities, NM_VPN_EDITOR_PLUGIN_CAPABILITY_IPV6);
}

const VpnPasswordName *
nm_vpn_get_secret_names (const char *service_type)
{
	static const VpnPasswordName generic_vpn_secrets[] = {
		{ "password", N_("Password") },
		{ 0 }
	};
	static const VpnPasswordName openvpn_secrets[] = {
		{ "password", N_("Password") },
		{ "cert-pass", N_("Certificate password") },
		{ "http-proxy-password", N_("HTTP proxy password") },
		{ 0 }
	};
	static const VpnPasswordName vpnc_secrets[] = {
		{ "Xauth password", N_("Password") },
		{ "IPSec secret", N_("Group password") },
		{ 0 }
	};
	static const VpnPasswordName swan_secrets[] = {
		{ "xauthpassword", N_("Password") },
		{ "pskvalue", N_("Group password") },
		{ 0 }
	};
	static const VpnPasswordName openconnect_secrets[] = {
		{ "gateway", N_("Gateway") },
		{ "cookie", N_("Cookie") },
		{ "gwcert", N_("Gateway certificate hash") },
		{ 0 }
	};
	const char *type;

	if (!service_type)
		return NULL;

	if (   !g_str_has_prefix (service_type, NM_DBUS_INTERFACE)
	    || service_type[NM_STRLEN (NM_DBUS_INTERFACE)] != '.') {
		/* all our well-known, hard-coded vpn-types start with NM_DBUS_INTERFACE. */
		return NULL;
	}

	type = service_type + (NM_STRLEN (NM_DBUS_INTERFACE) + 1);
	if (   !g_strcmp0 (type, "pptp")
	    || !g_strcmp0 (type, "iodine")
	    || !g_strcmp0 (type, "ssh")
	    || !g_strcmp0 (type, "l2tp")
	    || !g_strcmp0 (type, "fortisslvpn"))
		 return generic_vpn_secrets;
	else if (!g_strcmp0 (type, "openvpn"))
		return openvpn_secrets;
	else if (!g_strcmp0 (type, "vpnc"))
		return vpnc_secrets;
	else if (   !g_strcmp0 (type, "openswan")
	         || !g_strcmp0 (type, "libreswan")
	         || !g_strcmp0 (type, "strongswan"))
		return swan_secrets;
	else if (!g_strcmp0 (type, "openconnect"))
		return openconnect_secrets;
	return NULL;
}

static gboolean
_extract_variable_value (char *line, const char *tag, char **value)
{
	char *p1, *p2;

	if (!g_str_has_prefix (line, tag))
		return FALSE;

	p1 = line + strlen (tag);
	p2 = line + strlen (line) - 1;
	if ((*p1 == '\'' || *p1 == '"') && (*p1 == *p2)) {
		p1++;
		*p2 = '\0';
	}
	NM_SET_OUT (value, g_strdup (p1));
	return TRUE;
}

gboolean
nm_vpn_openconnect_authenticate_helper (const char *host,
                                        char **cookie,
                                        char **gateway,
                                        char **gwcert,
                                        int *status,
                                        GError **error)
{
	gs_free char *output = NULL;
	gs_free const char **output_v = NULL;
	const char *const*iter;
	const char *path;
	const char *const DEFAULT_PATHS[] = {
		"/sbin/",
		"/usr/sbin/",
		"/usr/local/sbin/",
		"/bin/",
		"/usr/bin/",
		"/usr/local/bin/",
		NULL,
	};

	path = nm_utils_file_search_in_paths ("openconnect", "/usr/sbin/openconnect", DEFAULT_PATHS,
	                                      G_FILE_TEST_IS_EXECUTABLE, NULL, NULL, error);
	if (!path)
		return FALSE;

	if (!g_spawn_sync (NULL,
	                   (char **) NM_MAKE_STRV (path, "--authenticate", host),
	                   NULL,
	                     G_SPAWN_SEARCH_PATH
	                   | G_SPAWN_CHILD_INHERITS_STDIN,
	                   NULL,
	                   NULL,
	                   &output,
	                   NULL,
	                   status,
	                   error))
		return FALSE;

	/* Parse output and set cookie, gateway and gwcert
	 * output example:
	 * COOKIE='loremipsum'
	 * HOST='1.2.3.4'
	 * FINGERPRINT='sha1:32bac90cf09a722e10ecc1942c67fe2ac8c21e2e'
	 */
	output_v = nm_utils_strsplit_set_with_empty (output, "\r\n");
	for (iter = output_v; iter && *iter; iter++) {
		char *s_mutable = (char *) *iter;

		_extract_variable_value (s_mutable, "COOKIE=", cookie);
		_extract_variable_value (s_mutable, "HOST=", gateway);
		_extract_variable_value (s_mutable, "FINGERPRINT=", gwcert);
	}

	return TRUE;
}

static gboolean
_wg_complete_peer (GPtrArray **p_peers,
                   NMWireGuardPeer *peer_take,
                   gsize peer_start_line_nr,
                   const char *filename,
                   GError **error)
{
	nm_auto_unref_wgpeer NMWireGuardPeer *peer = peer_take;
	gs_free_error GError *local = NULL;

	if (!peer)
		return TRUE;

	if (!nm_wireguard_peer_is_valid (peer, TRUE, TRUE, &local)) {
		nm_utils_error_set (error, NM_UTILS_ERROR_UNKNOWN,
		                    _("Invalid peer starting at %s:%zu: %s"),
		                    filename,
		                    peer_start_line_nr,
		                    local->message);
		return FALSE;
	}

	if (!*p_peers)
		*p_peers = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_wireguard_peer_unref);
	g_ptr_array_add (*p_peers, g_steal_pointer (&peer));
	return TRUE;
}

static gboolean
_line_match (char *line, const char *key, gsize key_len, const char **out_key, char **out_value)
{
	nm_assert (line);
	nm_assert (key);
	nm_assert (strlen (key) == key_len);
	nm_assert (!strchr (key, '='));
	nm_assert (out_key && !*out_key);
	nm_assert (out_value && !*out_value);

	/* Note that `wg-quick` (linux.bash) does case-insensitive comparison (shopt -s nocasematch).
	 * `wg setconf` does case-insensitive comparison too (with strncasecmp, which is locale dependent).
	 *
	 * We do a case-insensitive comparison of the key, however in a locale-independent manner. */

	if (g_ascii_strncasecmp (line, key, key_len) != 0)
		return FALSE;

	if (line[key_len] != '=')
		return FALSE;

	*out_key = key;
	*out_value = &line[key_len + 1];
	return TRUE;
}

#define line_match(line, key, out_key, out_value) \
	_line_match ((line), ""key"", NM_STRLEN (key), (out_key), (out_value))

static gboolean
value_split_word (char **line_remainder, char **out_word)
{
	char *str;

	if ((*line_remainder)[0] == '\0')
		return FALSE;

	*out_word = *line_remainder;

	str = strchrnul (*line_remainder, ',');
	if (str[0] == ',') {
		str[0] = '\0';
		*line_remainder = &str[1];
	} else
		*line_remainder = str;
	return TRUE;
}

NMConnection *
nm_vpn_wireguard_import (const char *filename,
                         GError **error)
{
	nm_auto_clear_secret_ptr NMSecretPtr file_content = NM_SECRET_PTR_INIT ();
	char ifname[IFNAMSIZ];
	gs_free char *uuid = NULL;
	gboolean ifname_valid = FALSE;
	const char *cstr;
	char *line_remainder;
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	NMSettingWireGuard *s_wg;
	gs_free_error GError *local = NULL;
	enum {
		LINE_CONTEXT_INIT,
		LINE_CONTEXT_INTERFACE,
		LINE_CONTEXT_PEER,
	} line_context;
	gsize line_nr;
	gsize current_peer_start_line_nr = 0;
	nm_auto_unref_wgpeer NMWireGuardPeer *current_peer = NULL;
	gs_unref_ptrarray GPtrArray *data_dns_v4 = NULL;
	gs_unref_ptrarray GPtrArray *data_dns_v6 = NULL;
	gs_unref_ptrarray GPtrArray *data_addr_v4 = NULL;
	gs_unref_ptrarray GPtrArray *data_addr_v6 = NULL;
	gs_unref_ptrarray GPtrArray *data_peers = NULL;
	const char *data_private_key = NULL;
	gint64 data_table;
	guint data_listen_port = 0;
	guint data_fwmark = 0;
	guint data_mtu = 0;
	int is_v4;
	guint i;

	g_return_val_if_fail (filename, NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	/* contrary to "wg-quick", we never interpret the filename as "/etc/wireguard/$INTERFACE.conf".
	 * If the filename has no '/', it is interpreted as relative to the current working directory.
	 * However, we do require a suitable filename suffix and that the name corresponds to the interface
	 * name. */
	cstr = strrchr (filename, '/');
	cstr = cstr ? &cstr[1] : filename;
	if (NM_STR_HAS_SUFFIX (cstr, ".conf")) {
		gsize len = strlen (cstr) - NM_STRLEN (".conf");

		if (len > 0 && len < sizeof (ifname)) {
			memcpy (ifname, cstr, len);
			ifname[len] = '\0';

			if (nm_utils_is_valid_iface_name (ifname, NULL))
				ifname_valid = TRUE;
		}
	}
	if (!ifname_valid) {
		nm_utils_error_set_literal (error, NM_UTILS_ERROR_UNKNOWN,
		                            _("The WireGuard config file must be a valid interface name followed by \".conf\""));
		return FALSE;
	}

	if (nm_utils_file_get_contents (-1,
	                                filename,
	                                10*1024*1024,
	                                NM_UTILS_FILE_GET_CONTENTS_FLAG_SECRET,
	                                &file_content.str,
	                                &file_content.len,
	                                error) < 0)
		return NULL;

	/* We interpret the file like `wg-quick up` and `wg setconf` do.
	 *
	 * Of course the WireGuard scripts do something fundamentlly different. They
	 * perform actions to configure the WireGuard link in kernel, add routes and
	 * addresses, and call resolvconf. It all happens at the time when the script
	 * run.
	 *
	 * This code here instead generates a NetworkManager connection profile so that
	 * NetworkManager will apply a similar configuration when later activating the profile. */

#define _TABLE_AUTO  ((gint64) -1)
#define _TABLE_OFF   ((gint64) -2)

	data_table = _TABLE_AUTO;

	line_remainder = file_content.str;
	line_context = LINE_CONTEXT_INIT;
	line_nr = 0;
	while (line_remainder[0] != '\0') {
		const char *matched_key = NULL;
		char *value = NULL;
		char *line;
		char ch;
		gint64 i64;

		line_nr++;

		line = line_remainder;
		line_remainder = strchrnul (line, '\n');
		if (line_remainder[0] != '\0')
			(line_remainder++)[0] = '\0';

		/* Drop all spaces and truncate at first '#'.
		 * See wg's config_read_line().
		 *
		 * Note that wg-quick doesn't do that.
		 *
		 * Neither `wg setconf` nor `wg-quick` does a strict parsing.
		 * We don't either. Just try to interpret the file (mostly) the same as
		 * they would.
		 */
		{
			gsize l, n;

			n = 0;
			for (l = 0; (ch = line[l]); l++) {
				if (g_ascii_isspace (ch)) {
					/* wg-setconf strips all whitespace before parsing the content. That means,
					 * *[I nterface]" will be accepted. We do that too. */
					continue;
				}
				if (ch == '#')
					break;
				line[n++] = line[l];
			}
			if (n == 0)
				continue;
			line[n] = '\0';
		}

		if (g_ascii_strcasecmp (line, "[Interface]") == 0) {
			if (!_wg_complete_peer (&data_peers,
			                        g_steal_pointer (&current_peer),
			                        current_peer_start_line_nr,
			                        filename,
			                        error))
				return FALSE;
			line_context = LINE_CONTEXT_INTERFACE;
			continue;
		}

		if (g_ascii_strcasecmp (line, "[Peer]") == 0) {
			if (!_wg_complete_peer (&data_peers,
			                        g_steal_pointer (&current_peer),
			                        current_peer_start_line_nr,
			                        filename,
			                        error))
				return FALSE;
			current_peer_start_line_nr = line_nr;
			current_peer = nm_wireguard_peer_new ();
			line_context = LINE_CONTEXT_PEER;
			continue;
		}

		if (line_context == LINE_CONTEXT_INTERFACE) {

			if (line_match (line, "Address", &matched_key, &value)) {
				char *value_word;

				while (value_split_word (&value, &value_word)) {
					GPtrArray **p_data_addr;
					NMIPAddr addr_bin;
					int addr_family;
					int prefix_len;

					if (!nm_utils_parse_inaddr_prefix_bin (AF_UNSPEC,
					                                       value_word,
					                                       &addr_family,
					                                       &addr_bin,
					                                       &prefix_len))
						goto fail_invalid_value;

					p_data_addr =   (addr_family == AF_INET)
					              ? &data_addr_v4
					              : &data_addr_v6;

					if (!*p_data_addr)
						*p_data_addr = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_ip_address_unref);

					g_ptr_array_add (*p_data_addr,
					                 nm_ip_address_new_binary (addr_family,
					                                           &addr_bin,
					                                             prefix_len == -1
					                                           ? ((addr_family == AF_INET) ? 32 : 128)
					                                           : prefix_len,
					                                           NULL));
				}
				continue;
			}

			if (line_match (line, "MTU", &matched_key, &value)) {
				i64 = _nm_utils_ascii_str_to_int64 (value, 0, 0, G_MAXUINT32, -1);
				if (i64 == -1)
					goto fail_invalid_value;

				/* wg-quick accepts the "MTU" value, but it also fetches routes to
				 * autodetect it. NetworkManager won't do that, we can only configure
				 * an explicit MTU or no autodetection will be performed. */
				data_mtu = i64;
				continue;
			}

			if (line_match (line, "DNS", &matched_key, &value)) {
				char *value_word;

				while (value_split_word (&value, &value_word)) {
					char addr_s[NM_CONST_MAX (INET_ADDRSTRLEN, INET6_ADDRSTRLEN)];
					GPtrArray **p_data_dns;
					NMIPAddr addr_bin;
					int addr_family;

					if (!nm_utils_parse_inaddr_bin (AF_UNSPEC,
					                                value_word,
					                                &addr_family,
					                                &addr_bin))
						goto fail_invalid_value;

					p_data_dns =   (addr_family == AF_INET)
					             ? &data_dns_v4
					             : &data_dns_v6;
					if (!*p_data_dns)
						*p_data_dns = g_ptr_array_new_with_free_func (g_free);

					inet_ntop (addr_family, &addr_bin, addr_s, sizeof (addr_s));
					g_ptr_array_add (*p_data_dns, g_strdup (addr_s));
				}
				continue;
			}

			if (line_match (line, "Table", &matched_key, &value)) {

				if (nm_streq (value, "auto"))
					data_table = _TABLE_AUTO;
				else if (nm_streq (value, "off"))
					data_table = _TABLE_OFF;
				else {
					/* we don't support table names from /etc/iproute2/rt_tables
					 * But we accept hex like `ip route add` would. */
					i64 = _nm_utils_ascii_str_to_int64 (value, 0, 0, G_MAXINT32, -1);
					if (i64 == -1)
						goto fail_invalid_value;
					data_table = i64;
				}
				continue;
			}

			if (   line_match (line, "PreUp", &matched_key, &value)
			    || line_match (line, "PreDown", &matched_key, &value)
			    || line_match (line, "PostUp", &matched_key, &value)
			    || line_match (line, "PostDown", &matched_key, &value)) {
				/* we don't run any scripts. Silently ignore these parameters. */
				continue;
			}

			if (line_match (line, "SaveConfig", &matched_key, &value)) {
				/* we ignore the setting, but enforce that it's either true or false (like
				 * wg-quick. */
				if (!NM_IN_STRSET (value, "true", "false"))
					goto fail_invalid_value;
				continue;
			}

			if (line_match (line, "ListenPort", &matched_key, &value)) {
				/* we don't use getaddrinfo(), unlike `wg setconf`. Just interpret
				 * the port as plain decimal number. */
				i64 = _nm_utils_ascii_str_to_int64 (value, 10, 0, 0xFFFF, -1);
				if (i64 == -1)
					goto fail_invalid_value;
				data_listen_port = i64;
				continue;
			}

			if (line_match (line, "FwMark", &matched_key, &value)) {
				if (nm_streq (value, "off"))
					data_fwmark = 0;
				else {
					i64 = _nm_utils_ascii_str_to_int64 (value, 0, 0, G_MAXINT32, -1);
					if (i64 == -1)
						goto fail_invalid_value;
					data_fwmark = i64;
				}
				continue;
			}

			if (line_match (line, "PrivateKey", &matched_key, &value)) {
				if (!nm_utils_base64secret_decode (value, NM_WIREGUARD_PUBLIC_KEY_LEN, NULL))
					goto fail_invalid_secret;
				data_private_key = value;
				continue;
			}

			goto fail_invalid_line;
		}


		if (line_context == LINE_CONTEXT_PEER) {

			if (line_match (line, "Endpoint", &matched_key, &value)) {
				if (!nm_wireguard_peer_set_endpoint (current_peer, value, FALSE))
					goto fail_invalid_value;
				continue;
			}

			if (line_match (line, "PublicKey", &matched_key, &value)) {
				if (!nm_wireguard_peer_set_public_key (current_peer, value, FALSE))
					goto fail_invalid_value;
				continue;
			}

			if (line_match (line, "AllowedIPs", &matched_key, &value)) {
				char *value_word;

				while (value_split_word (&value, &value_word)) {
					if (!nm_wireguard_peer_append_allowed_ip (current_peer,
					                                          value_word,
					                                          FALSE))
						goto fail_invalid_value;
				}
				continue;
			}

			if (line_match (line, "PersistentKeepalive", &matched_key, &value)) {
				if (nm_streq (value, "off"))
					i64 = 0;
				else {
					i64 = _nm_utils_ascii_str_to_int64 (value, 10, 0, G_MAXUINT16, -1);
					if (i64 == -1)
						goto fail_invalid_value;
				}
				nm_wireguard_peer_set_persistent_keepalive (current_peer, i64);
				continue;
			}

			if (line_match (line, "PresharedKey", &matched_key, &value)) {
				if (!nm_wireguard_peer_set_preshared_key (current_peer, value, FALSE))
					goto fail_invalid_secret;
				nm_wireguard_peer_set_preshared_key_flags (current_peer, NM_SETTING_SECRET_FLAG_NONE);
				continue;
			}

			goto fail_invalid_line;
		}

fail_invalid_line:
		nm_utils_error_set (error, NM_UTILS_ERROR_INVALID_ARGUMENT,
		                    _("unrecognized line at %s:%zu"),
		                    filename, line_nr);
		return FALSE;
fail_invalid_value:
		nm_utils_error_set (error, NM_UTILS_ERROR_INVALID_ARGUMENT,
		                    _("invalid value for '%s' at %s:%zu"),
		                    matched_key, filename, line_nr);
		return FALSE;
fail_invalid_secret:
		nm_utils_error_set (error, NM_UTILS_ERROR_INVALID_ARGUMENT,
		                    _("invalid secret '%s' at %s:%zu"),
		                    matched_key, filename, line_nr);
		return FALSE;
	}

	if (!_wg_complete_peer (&data_peers,
	                        g_steal_pointer (&current_peer),
	                        current_peer_start_line_nr,
	                        filename,
	                        error))
		return FALSE;

	connection = nm_simple_connection_new ();
	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_con));
	s_ip4 = NM_SETTING_IP_CONFIG (nm_setting_ip4_config_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));
	s_ip6 = NM_SETTING_IP_CONFIG (nm_setting_ip6_config_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));
	s_wg = NM_SETTING_WIREGUARD (nm_setting_wireguard_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_wg));

	uuid = nm_utils_uuid_generate ();

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID,
	              ifname,
	              NM_SETTING_CONNECTION_UUID,
	              uuid,
	              NM_SETTING_CONNECTION_TYPE,
	              NM_SETTING_WIREGUARD_SETTING_NAME,
	              NM_SETTING_CONNECTION_INTERFACE_NAME,
	              ifname,
	              NULL);

	g_object_set (s_wg,
	              NM_SETTING_WIREGUARD_PRIVATE_KEY,
	              data_private_key,
	              NM_SETTING_WIREGUARD_LISTEN_PORT,
	              data_listen_port,
	              NM_SETTING_WIREGUARD_FWMARK,
	              data_fwmark,
	              NM_SETTING_WIREGUARD_MTU,
	              data_mtu,
	              NULL);

	if (data_peers) {
		for (i = 0; i < data_peers->len; i++)
			nm_setting_wireguard_append_peer (s_wg, data_peers->pdata[i]);
	}

	for (is_v4 = 0; is_v4 < 2; is_v4++) {
		const char *method_disabled = is_v4 ? NM_SETTING_IP4_CONFIG_METHOD_DISABLED : NM_SETTING_IP6_CONFIG_METHOD_DISABLED;
		const char *method_manual   = is_v4 ? NM_SETTING_IP4_CONFIG_METHOD_MANUAL   : NM_SETTING_IP6_CONFIG_METHOD_MANUAL;
		NMSettingIPConfig *s_ip     = is_v4 ? s_ip4                                 : s_ip6;
		GPtrArray *data_dns         = is_v4 ? data_dns_v4                           : data_dns_v6;
		GPtrArray *data_addr        = is_v4 ? data_addr_v4                          : data_addr_v6;

		if (data_dns && !data_addr) {
			/* When specifying "DNS", we also require an "Address" for the same address
			 * family. That is because a NMSettingIPConfig cannot have @method_disabled
			 * and DNS settings at the same time.
			 *
			 * We don't have addresses. Silently ignore the DNS setting. */
			data_dns = NULL;
		}

		g_object_set (s_ip,
		              NM_SETTING_IP_CONFIG_METHOD,
		              data_addr ? method_manual : method_disabled,
		              NULL);

		if (data_addr) {
			for (i = 0; i < data_addr->len; i++)
				nm_setting_ip_config_add_address (s_ip, data_addr->pdata[i]);
		}
		if (data_dns) {
			for (i = 0; i < data_dns->len; i++)
				nm_setting_ip_config_add_dns (s_ip, data_dns->pdata[i]);
		}

		if (data_table == _TABLE_AUTO) {
			/* in the "auto" setting, wg-quick adds peer-routes automatically to the main
			 * table. NetworkManager will do that too, but there are differences:
			 *
			 * - NetworkManager (contrary to wg-quick) does not check whether the peer-route is necessary.
			 *   It will always add a route for each allowed-ips range, even if there is already another
			 *   route that would ensure packets to the endpoint are routed via the WireGuard interface.
			 *   If you don't want that, disable "wireguard.peer-routes", and add the necessary routes
			 *   yourself to "ipv4.routes" and "ipv6.routes".
			 *
			 * - With "auto", wg-quick also configures policy routing to handle default-routes (/0) to
			 *   avoid routing loops. That is not yet solved by NetworkManager, you need to configure
			 *   that explicitly (for example, by adding a direct route to the gateway on the interface
			 *   that has the default-route, or by using a script (possibly dispatcher script).
			 */
		} else if (data_table == _TABLE_OFF) {
			if (is_v4) {
				g_object_set (s_wg,
				              NM_SETTING_WIREGUARD_PEER_ROUTES,
				              FALSE,
				              NULL);
			}
		} else {
			g_object_set (s_ip,
			              NM_SETTING_IP_CONFIG_ROUTE_TABLE,
			              (guint) data_table,
			              NULL);
		}
	}

	if (!nm_connection_normalize (connection, NULL, NULL, &local)) {
		nm_utils_error_set (error, NM_UTILS_ERROR_INVALID_ARGUMENT,
		                    _("Failed to create WireGuard connection: %s"),
		                    local->message);
		return FALSE;
	}

	return g_steal_pointer (&connection);
}
