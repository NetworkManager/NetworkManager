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

#include "nm-default.h"

#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <errno.h>

#include "nm-settings-plugin.h"
#include "nm-core-internal.h"
#include "NetworkManagerUtils.h"

#include "net_utils.h"
#include "wpa_parser.h"
#include "connection_parser.h"
#include "nm-ifnet-connection.h"

static char *
connection_id_from_ifnet_name (const char *conn_name)
{
	int name_len = strlen (conn_name);

	/* Convert a hex-encoded conn_name (only used for wifi SSIDs) to human-readable one */
	if ((name_len > 2) && (g_str_has_prefix (conn_name, "0x"))) {
		GBytes *bytes = nm_utils_hexstr2bin (conn_name);
		char *buf;

		if (bytes) {
			buf = g_strndup (g_bytes_get_data (bytes, NULL), g_bytes_get_size (bytes));
			g_bytes_unref (bytes);
			return buf;
		}
	}

	return g_strdup (conn_name);
}

static gboolean eap_simple_reader (const char *eap_method,
                                   const char *ssid,
                                   NMSetting8021x *s_8021x,
                                   gboolean phase2,
                                   const char *basepath,
                                   GError **error);

static gboolean eap_tls_reader (const char *eap_method,
                                const char *ssid,
                                NMSetting8021x *s_8021x,
                                gboolean phase2,
                                const char *basepath,
                                GError **error);

static gboolean eap_peap_reader (const char *eap_method,
                                 const char *ssid,
                                 NMSetting8021x *s_8021x,
                                 gboolean phase2,
                                 const char *basepath,
                                 GError **error);

static gboolean eap_ttls_reader (const char *eap_method,
                                 const char *ssid,
                                 NMSetting8021x *s_8021x,
                                 gboolean phase2,
                                 const char *basepath,
                                 GError **error);

typedef struct {
	const char *method;
	 gboolean (*reader) (const char *eap_method,
	                     const char *ssid,
	                     NMSetting8021x *s_8021x,
	                     gboolean phase2,
	                     const char *basepath,
	                     GError **error);
	gboolean wifi_phase2_only;
} EAPReader;

static EAPReader eap_readers[] = {
	{"md5", eap_simple_reader, TRUE},
	{"pwd", eap_simple_reader, TRUE},
	{"pap", eap_simple_reader, TRUE},
	{"chap", eap_simple_reader, TRUE},
	{"mschap", eap_simple_reader, TRUE},
	{"mschapv2", eap_simple_reader, TRUE},
	{"leap", eap_simple_reader, TRUE},
	{"tls", eap_tls_reader, FALSE},
	{"peap", eap_peap_reader, FALSE},
	{"ttls", eap_ttls_reader, FALSE},
	{NULL, NULL}
};

/* reading identity and password */
static gboolean
eap_simple_reader (const char *eap_method,
                   const char *ssid,
                   NMSetting8021x *s_8021x,
                   gboolean phase2,
                   const char *basepath,
                   GError **error)
{
	const char *value;

	/* identity */
	value = wpa_get_value (ssid, "identity");
	if (!value) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			     "Missing IEEE_8021X_IDENTITY for EAP method '%s'.",
			     eap_method);
		return FALSE;
	}
	g_object_set (s_8021x, NM_SETTING_802_1X_IDENTITY, value, NULL);

	/* password */
	value = wpa_get_value (ssid, "password");
	if (!value) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			     "Missing IEEE_8021X_PASSWORD for EAP method '%s'.",
			     eap_method);
		return FALSE;
	}

	g_object_set (s_8021x, NM_SETTING_802_1X_PASSWORD, value, NULL);

	return TRUE;
}

static char *
get_cert (const char *ssid, const char *key, const char *basepath)
{
	const char *orig;

	/* If it's a relative path, convert to absolute using 'basepath' */
	orig = wpa_get_value (ssid, key);
	if (g_path_is_absolute (orig))
		return g_strdup (orig);
	return g_strdup_printf ("%s/%s", basepath, orig);
}

static gboolean
eap_tls_reader (const char *eap_method,
                const char *ssid,
                NMSetting8021x *s_8021x,
                gboolean phase2,
                const char *basepath,
                GError **error)
{
	const char *value;
	char *ca_cert = NULL;
	char *client_cert = NULL;
	char *privkey = NULL;
	const char *privkey_password = NULL;
	gboolean success = FALSE;
	NMSetting8021xCKFormat privkey_format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;

	/* identity */
	value = wpa_get_value (ssid, "identity");
	if (!value) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			     "Missing IEEE_8021X_IDENTITY for EAP method '%s'.",
			     eap_method);
		return FALSE;
	}
	g_object_set (s_8021x, NM_SETTING_802_1X_IDENTITY, value, NULL);

	/* ca cert */
	ca_cert = get_cert (ssid, phase2 ? "ca_cert2" : "ca_cert", basepath);
	if (ca_cert) {
		if (phase2) {
			if (!nm_setting_802_1x_set_phase2_ca_cert (s_8021x,
								   ca_cert,
								   NM_SETTING_802_1X_CK_SCHEME_PATH,
								   NULL, error))
				goto done;
		} else {
			if (!nm_setting_802_1x_set_ca_cert (s_8021x,
							    ca_cert,
							    NM_SETTING_802_1X_CK_SCHEME_PATH,
							    NULL, error))
				goto done;
		}
	} else {
		nm_log_warn (LOGD_SETTINGS, "    missing %s for EAP method '%s'; this is insecure!",
		             phase2 ? "IEEE_8021X_INNER_CA_CERT" :
		             "IEEE_8021X_CA_CERT", eap_method);
	}

	/* Private key password */
	privkey_password = wpa_get_value (ssid,
					  phase2 ? "private_key2_passwd" :
					  "private_key_passwd");

	if (!privkey_password) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			     "Missing %s for EAP method '%s'.",
			     phase2 ? "IEEE_8021X_INNER_PRIVATE_KEY_PASSWORD" :
			     "IEEE_8021X_PRIVATE_KEY_PASSWORD", eap_method);
		goto done;
	}

	/* The private key itself */
	privkey = get_cert (ssid, phase2 ? "private_key2" : "private_key", basepath);
	if (!privkey) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			     "Missing %s for EAP method '%s'.",
			     phase2 ? "IEEE_8021X_INNER_PRIVATE_KEY" :
			     "IEEE_8021X_PRIVATE_KEY", eap_method);
		goto done;
	}

	if (phase2) {
		if (!nm_setting_802_1x_set_phase2_private_key (s_8021x,
							       privkey,
							       privkey_password,
							       NM_SETTING_802_1X_CK_SCHEME_PATH,
							       &privkey_format,
							       error))
			goto done;
	} else {
		if (!nm_setting_802_1x_set_private_key (s_8021x,
							privkey,
							privkey_password,
							NM_SETTING_802_1X_CK_SCHEME_PATH,
							&privkey_format, error))
			goto done;
	}

	/* Only set the client certificate if the private key is not PKCS#12 format,
	 * as NM (due to supplicant restrictions) requires.  If the key was PKCS#12,
	 * then nm_setting_802_1x_set_private_key() already set the client certificate
	 * to the same value as the private key.
	 */
	if (privkey_format == NM_SETTING_802_1X_CK_FORMAT_RAW_KEY
	    || privkey_format == NM_SETTING_802_1X_CK_FORMAT_X509) {
		client_cert = get_cert (ssid, phase2 ? "client_cert2" : "client_cert", basepath);
		if (!client_cert) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
				     "Missing %s for EAP method '%s'.",
				     phase2 ? "IEEE_8021X_INNER_CLIENT_CERT" :
				     "IEEE_8021X_CLIENT_CERT", eap_method);
			goto done;
		}

		if (phase2) {
			if (!nm_setting_802_1x_set_phase2_client_cert (s_8021x,
								       client_cert,
								       NM_SETTING_802_1X_CK_SCHEME_PATH,
								       NULL,
								       error))
				goto done;
		} else {
			if (!nm_setting_802_1x_set_client_cert (s_8021x,
								client_cert,
								NM_SETTING_802_1X_CK_SCHEME_PATH,
								NULL, error))
				goto done;
		}
	}

	success = TRUE;

done:
	g_free (ca_cert);
	g_free (client_cert);
	g_free (privkey);
	return success;
}

static gboolean
eap_peap_reader (const char *eap_method,
                 const char *ssid,
                 NMSetting8021x *s_8021x,
                 gboolean phase2,
                 const char *basepath,
                 GError **error)
{
	char *ca_cert = NULL;
	const char *inner_auth = NULL;
	const char *peapver = NULL;
	char **list = NULL, **iter, *lower;
	gboolean success = FALSE;

	ca_cert = get_cert (ssid, "ca_cert", basepath);
	if (ca_cert) {
		if (!nm_setting_802_1x_set_ca_cert (s_8021x,
						    ca_cert,
						    NM_SETTING_802_1X_CK_SCHEME_PATH,
						    NULL, error))
			goto done;
	} else {
		nm_log_warn (LOGD_SETTINGS, "    missing IEEE_8021X_CA_CERT for EAP method '%s'; this is insecure!",
		             eap_method);
	}

	peapver = wpa_get_value (ssid, "phase1");
	/* peap version, default is automatic */
	if (peapver && strstr (peapver, "peapver")) {
		if (strstr (peapver, "peapver=0"))
			g_object_set (s_8021x, NM_SETTING_802_1X_PHASE1_PEAPVER,
				      "0", NULL);
		else if (strstr (peapver, "peapver=1"))
			g_object_set (s_8021x, NM_SETTING_802_1X_PHASE1_PEAPVER,
				      "1", NULL);
		else {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
				     "Unknown IEEE_8021X_PEAP_VERSION value '%s'",
				     peapver);
			goto done;
		}
	}

	/* peaplabel */
	if (peapver && strstr (peapver, "peaplabel=1"))
		g_object_set (s_8021x, NM_SETTING_802_1X_PHASE1_PEAPLABEL, "1",
			      NULL);

	inner_auth = wpa_get_value (ssid, "phase2");
	if (!inner_auth) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			     "Missing IEEE_8021X_INNER_AUTH_METHODS.");
		goto done;
	}
	/* Handle options for the inner auth method */
	list = g_strsplit (inner_auth, " ", 0);
	for (iter = list; iter && *iter; iter++) {
		gchar *pos = NULL;

		if (!strlen (*iter))
			continue;

		if (!(pos = strstr (*iter, "MSCHAPV2"))
		    || !(pos = strstr (*iter, "MD5"))
		    || !(pos = strstr (*iter, "GTC"))) {
			if (!eap_simple_reader (pos, ssid, s_8021x, TRUE, basepath, error))
				goto done;
		} else if (!(pos = strstr (*iter, "TLS"))) {
			if (!eap_tls_reader (pos, ssid, s_8021x, TRUE, basepath, error))
				goto done;
		} else {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
				     "Unknown IEEE_8021X_INNER_AUTH_METHOD '%s'.",
				     *iter);
			goto done;
		}

		pos = strchr (*iter, '=');
		if (pos && *pos) {
			pos++;
			lower = g_ascii_strdown (pos, -1);
			g_object_set (s_8021x, NM_SETTING_802_1X_PHASE2_AUTH, lower,
				      NULL);
			g_free (lower);
		} else {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
				     "No IEEE_8021X_INNER_AUTH_METHOD.");
			goto done;
		}
		break;
	}

	if (!nm_setting_802_1x_get_phase2_auth (s_8021x)) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			     "No valid IEEE_8021X_INNER_AUTH_METHODS found.");
		goto done;
	}

	success = TRUE;

done:
	g_free (ca_cert);
	if (list)
		g_strfreev (list);
	return success;
}

static gboolean
eap_ttls_reader (const char *eap_method,
                 const char *ssid,
                 NMSetting8021x *s_8021x,
                 gboolean phase2,
                 const char *basepath,
                 GError **error)
{
	gboolean success = FALSE;
	const char *anon_ident = NULL;
	char *ca_cert = NULL;
	const char *tmp;
	char **list = NULL, **iter, *inner_auth = NULL;

	/* ca cert */
	ca_cert = get_cert (ssid, "ca_cert", basepath);
	if (ca_cert) {
		if (!nm_setting_802_1x_set_ca_cert (s_8021x,
						    ca_cert,
						    NM_SETTING_802_1X_CK_SCHEME_PATH,
						    NULL, error))
			goto done;
	} else {
		nm_log_warn (LOGD_SETTINGS, "    missing IEEE_8021X_CA_CERT for EAP method '%s'; this is insecure!",
		             eap_method);
	}

	/* anonymous indentity for tls */
	anon_ident = wpa_get_value (ssid, "anonymous_identity");
	if (anon_ident && strlen (anon_ident))
		g_object_set (s_8021x, NM_SETTING_802_1X_ANONYMOUS_IDENTITY,
			      anon_ident, NULL);

	tmp = wpa_get_value (ssid, "phase2");
	if (!tmp) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			     "Missing IEEE_8021X_INNER_AUTH_METHODS.");
		goto done;
	}

	/* Handle options for the inner auth method */
	inner_auth = g_ascii_strdown (tmp, -1);
	list = g_strsplit (inner_auth, " ", 0);
	for (iter = list; iter && *iter; iter++) {
		gchar *pos = NULL;

		if (!strlen (*iter))
			continue;
		if ((pos = strstr (*iter, "mschapv2")) != NULL
		    || (pos = strstr (*iter, "mschap")) != NULL
		    || (pos = strstr (*iter, "pap")) != NULL
		    || (pos = strstr (*iter, "chap")) != NULL) {
			if (!eap_simple_reader (pos, ssid, s_8021x, TRUE, basepath, error))
				goto done;
			g_object_set (s_8021x, NM_SETTING_802_1X_PHASE2_AUTH,
				      pos, NULL);
		} else if ((pos = strstr (*iter, "tls")) != NULL) {
			if (!eap_tls_reader (pos, ssid, s_8021x, TRUE, basepath, error))
				goto done;
			g_object_set (s_8021x, NM_SETTING_802_1X_PHASE2_AUTHEAP,
				      "tls", NULL);
		} else if ((pos = strstr (*iter, "mschapv2")) != NULL
			   || (pos = strstr (*iter, "md5")) != NULL) {
			if (!eap_simple_reader (pos, ssid, s_8021x, TRUE, basepath, error)) {
				nm_log_warn (LOGD_SETTINGS, "SIMPLE ERROR");
				goto done;
			}
			g_object_set (s_8021x, NM_SETTING_802_1X_PHASE2_AUTHEAP,
				      pos, NULL);
		} else {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
				     "Unknown IEEE_8021X_INNER_AUTH_METHOD '%s'.",
				     *iter);
			goto done;
		}
		break;
	}

	success = TRUE;
done:
	g_free (ca_cert);
	if (list)
		g_strfreev (list);
	g_free (inner_auth);
	return success;
}

/* type is already decided by net_parser, this function is just used to
 * doing tansformation*/
static const gchar *
guess_connection_type (const char *conn_name)
{
	const gchar *type = ifnet_get_data (conn_name, "type");
	const gchar *ret_type = NULL;

	if (!g_strcmp0 (type, "ppp"))
		ret_type = NM_SETTING_PPPOE_SETTING_NAME;

	if (!g_strcmp0 (type, "wireless"))
		ret_type = NM_SETTING_WIRELESS_SETTING_NAME;

	if (!ret_type)
		ret_type = NM_SETTING_WIRED_SETTING_NAME;

	nm_log_info (LOGD_SETTINGS, "guessed connection type (%s) = %s", conn_name, ret_type);
	return ret_type;
}

/* Reading mac address for setting connection option.
 * Unmanaged device mac address is required by NetworkManager*/
static gboolean
read_mac_address (const char *conn_name, const char **mac, GError **error)
{
	const char *value = ifnet_get_data (conn_name, "mac");

	if (!value || !strlen (value))
		return TRUE;

	if (!nm_utils_hwaddr_valid (value, ETH_ALEN)) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "The MAC address '%s' was invalid.", value);
		return FALSE;
	}

	*mac = value;
	return TRUE;
}

static gboolean
make_wired_connection_setting (NMConnection *connection,
                               const char *conn_name,
                               GError **error)
{
	const char *mac = NULL;
	NMSettingWired *s_wired = NULL;
	const char *value = NULL;

	s_wired = NM_SETTING_WIRED (nm_setting_wired_new ());

	/* mtu_xxx */
	value = ifnet_get_data (conn_name, "mtu");
	if (value) {
		long int mtu;

		errno = 0;
		mtu = strtol (value, NULL, 10);
		if (errno || mtu < 0 || mtu > 65535) {
			nm_log_warn (LOGD_SETTINGS, "    invalid MTU '%s' for %s", value, conn_name);
		} else
			g_object_set (s_wired, NM_SETTING_WIRED_MTU,
				      (guint32) mtu, NULL);
	}

	if (!read_mac_address (conn_name, &mac, error)) {
		g_object_unref (s_wired);
		return FALSE;
	}

	if (mac)
		g_object_set (s_wired, NM_SETTING_WIRED_MAC_ADDRESS, mac, NULL);
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	return TRUE;
}

/* add NM_SETTING_IP_CONFIG_DHCP_HOSTNAME,
 * NM_SETTING_IP_CONFIG_DHCP_CLIENT_ID in future*/
static gboolean
make_ip4_setting (NMConnection *connection,
                  const char *conn_name,
                  GError **error)
{

	NMSettingIPConfig *ip4_setting =
	    NM_SETTING_IP_CONFIG (nm_setting_ip4_config_new ());
	const char *value, *method = NULL;
	gboolean is_static_block = is_static_ip4 (conn_name);
	ip_block *iblock = NULL;

	/* set dhcp options (dhcp_xxx) */
	value = ifnet_get_data (conn_name, "dhcp");
	g_object_set (ip4_setting, NM_SETTING_IP_CONFIG_IGNORE_AUTO_DNS, value
		      && strstr (value, "nodns") ? TRUE : FALSE,
		      NM_SETTING_IP_CONFIG_IGNORE_AUTO_ROUTES, value
		      && strstr (value, "nogateway") ? TRUE : FALSE, NULL);

	if (!is_static_block) {
		method = ifnet_get_data (conn_name, "config");
		if (!method){
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
						 "Unknown config for %s", conn_name);
			g_object_unref (ip4_setting);
			return FALSE;
		}
		if (strstr (method, "dhcp"))
			g_object_set (ip4_setting,
						  NM_SETTING_IP_CONFIG_METHOD,
						  NM_SETTING_IP4_CONFIG_METHOD_AUTO,
						  NM_SETTING_IP_CONFIG_NEVER_DEFAULT, FALSE, NULL);
		else if (strstr (method, "autoip")) {
			g_object_set (ip4_setting,
						  NM_SETTING_IP_CONFIG_METHOD,
						  NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL,
						  NM_SETTING_IP_CONFIG_NEVER_DEFAULT, FALSE, NULL);
			nm_connection_add_setting (connection, NM_SETTING (ip4_setting));
			return TRUE;
		} else if (strstr (method, "shared")) {
			g_object_set (ip4_setting,
						  NM_SETTING_IP_CONFIG_METHOD,
						  NM_SETTING_IP4_CONFIG_METHOD_SHARED,
						  NM_SETTING_IP_CONFIG_NEVER_DEFAULT, FALSE, NULL);
			nm_connection_add_setting (connection, NM_SETTING (ip4_setting));
			return TRUE;
		} else {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
						 "Unknown config for %s", conn_name);
			g_object_unref (ip4_setting);
			return FALSE;
		}
		nm_log_info (LOGD_SETTINGS, "Using %s method for %s", method, conn_name);
	}else {
		iblock = convert_ip4_config_block (conn_name);
		if (!iblock) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
				     "Ifnet plugin: can't aquire ip configuration for %s",
				     conn_name);
			g_object_unref (ip4_setting);
			return FALSE;
		}
		/************** add all ip settings to the connection**********/
		while (iblock) {
			ip_block *current_iblock;
			NMIPAddress *ip4_addr;
			GError *local = NULL;

			ip4_addr = nm_ip_address_new (AF_INET, iblock->ip, iblock->prefix, &local);
			if (iblock->next_hop)
				g_object_set (ip4_setting,
					      NM_SETTING_IP_CONFIG_IGNORE_AUTO_ROUTES,
					      TRUE, NULL);

			if (ip4_addr) {
				if (!nm_setting_ip_config_add_address (ip4_setting, ip4_addr))
					nm_log_warn (LOGD_SETTINGS, "ignoring duplicate IP4 address");
				nm_ip_address_unref (ip4_addr);
			} else {
				nm_log_warn (LOGD_SETTINGS, "    ignoring invalid address entry: %s", local->message);
				g_clear_error (&local);
			}

			current_iblock = iblock;
			iblock = iblock->next;
			destroy_ip_block (current_iblock);

		}
		g_object_set (ip4_setting,
		              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
		              NM_SETTING_IP_CONFIG_NEVER_DEFAULT, !has_default_ip4_route (conn_name),
		              NULL);
	}

	/* add dhcp hostname and client id */
	if (!is_static_block && strstr (method, "dhcp")) {
		gchar *dhcp_hostname, *client_id;

		get_dhcp_hostname_and_client_id (&dhcp_hostname, &client_id);
		if (dhcp_hostname) {
			g_object_set (ip4_setting,
				      NM_SETTING_IP_CONFIG_DHCP_HOSTNAME,
				      dhcp_hostname, NULL);
			nm_log_info (LOGD_SETTINGS, "DHCP hostname: %s", dhcp_hostname);
			g_free (dhcp_hostname);
		}
		if (client_id) {
			g_object_set (ip4_setting,
				      NM_SETTING_IP4_CONFIG_DHCP_CLIENT_ID,
				      client_id, NULL);
			nm_log_info (LOGD_SETTINGS, "DHCP client id: %s", client_id);
			g_free (client_id);
		}
	}

	/* add all IPv4 dns servers, IPv6 servers will be ignored */
	set_ip4_dns_servers (ip4_setting, conn_name);

	/* DNS searches */
	value = ifnet_get_data (conn_name, "dns_search");
	if (value) {
		char *stripped = g_strdup (value);
		char **searches = NULL;

		strip_string (stripped, '"');

		searches = g_strsplit (stripped, " ", 0);
		if (searches) {
			char **item;

			for (item = searches; *item; item++) {
				if (strlen (*item)) {
					if (!nm_setting_ip_config_add_dns_search (ip4_setting, *item))
						nm_log_warn (LOGD_SETTINGS, "    duplicate DNS domain '%s'", *item);
				}
			}
			g_strfreev (searches);
		}
	}

	/* static routes */
	iblock = convert_ip4_routes_block (conn_name);
	while (iblock) {
		ip_block *current_iblock = iblock;
		const char *metric_str;
		char *stripped;
		gint64 metric;
		NMIPRoute *route;
		GError *local = NULL;

		if ((metric_str = ifnet_get_data (conn_name, "metric")) != NULL) {
			metric = _nm_utils_ascii_str_to_int64 (metric_str, 10, 0, G_MAXUINT32, -1);
		} else {
			metric_str = ifnet_get_global_data ("metric");
			if (metric_str) {
				stripped = g_strdup (metric_str);
				strip_string (stripped, '"');
				metric = _nm_utils_ascii_str_to_int64 (metric_str, 10, 0, G_MAXUINT32, -1);
				g_free (stripped);
			} else
				metric = -1;
		}

		route = nm_ip_route_new (AF_INET, iblock->ip, iblock->prefix, iblock->next_hop, metric, &local);
		if (route) {
			if (nm_setting_ip_config_add_route (ip4_setting, route))
				nm_log_info (LOGD_SETTINGS, "new IP4 route:%s\n", iblock->ip);
			else
				nm_log_warn (LOGD_SETTINGS, "duplicate IP4 route");
			nm_ip_route_unref (route);
		} else {
			nm_log_warn (LOGD_SETTINGS, "    ignoring invalid route entry: %s", local->message);
			g_clear_error (&local);
		}

		current_iblock = iblock;
		iblock = iblock->next;
		destroy_ip_block (current_iblock);
	}

	/* Finally add setting to connection */
	nm_connection_add_setting (connection, NM_SETTING (ip4_setting));

	return TRUE;
}

static gboolean
make_ip6_setting (NMConnection *connection,
                  const char *conn_name,
                  GError **error)
{
	NMSettingIPConfig *s_ip6 = NULL;
	gboolean is_static_block = is_static_ip6 (conn_name);

	// used to disable IPv6
	gboolean ipv6_enabled = FALSE;
	gchar *method = NM_SETTING_IP6_CONFIG_METHOD_MANUAL;
	const char *value;
	ip_block *iblock;
	gboolean never_default = !has_default_ip6_route (conn_name);

	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();

	value = ifnet_get_data (conn_name, "enable_ipv6");
	if (value && is_true (value))
		ipv6_enabled = TRUE;

	//FIXME Handle other methods that NM supports in future
	// Currently only Manual and DHCP are supported
	if (!ipv6_enabled) {
		g_object_set (s_ip6,
			      NM_SETTING_IP_CONFIG_METHOD,
			      NM_SETTING_IP6_CONFIG_METHOD_IGNORE, NULL);
		goto done;
	} else if (!is_static_block) {
		// config_eth* contains "dhcp6"
		method = NM_SETTING_IP6_CONFIG_METHOD_AUTO;
		never_default = FALSE;
	}
	// else if (!has_ip6_address(conn_name))
	// doesn't have "dhcp6" && doesn't have any ipv6 address
	// method = NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL;
	else
		// doesn't have "dhcp6" && has at least one ipv6 address
		method = NM_SETTING_IP6_CONFIG_METHOD_MANUAL;
	nm_log_info (LOGD_SETTINGS, "IPv6 for %s enabled, using %s", conn_name, method);

	g_object_set (s_ip6,
		      NM_SETTING_IP_CONFIG_METHOD, method,
		      NM_SETTING_IP_CONFIG_IGNORE_AUTO_DNS, FALSE,
		      NM_SETTING_IP_CONFIG_IGNORE_AUTO_ROUTES, FALSE,
		      NM_SETTING_IP_CONFIG_NEVER_DEFAULT, never_default, NULL);

	/* Make manual settings */
	if (!strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_MANUAL)) {
		ip_block *current_iblock;

		iblock = convert_ip6_config_block (conn_name);
		if (!iblock) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
				     "Ifnet plugin: can't aquire ip6 configuration for %s",
				     conn_name);
			goto error;
		}
		/* add all IPv6 addresses */
		while (iblock) {
			NMIPAddress *ip6_addr;
			GError *local = NULL;

			ip6_addr = nm_ip_address_new (AF_INET6, iblock->ip, iblock->prefix, &local);
			if (ip6_addr) {
				if (nm_setting_ip_config_add_address (s_ip6, ip6_addr)) {
					nm_log_info (LOGD_SETTINGS, "ipv6 addresses count: %d",
					             nm_setting_ip_config_get_num_addresses (s_ip6));
				} else {
					nm_log_warn (LOGD_SETTINGS, "ignoring duplicate IP6 address");
				}
				nm_ip_address_unref (ip6_addr);
			} else {
				nm_log_warn (LOGD_SETTINGS, "    ignoring invalid address entry: %s", local->message);
				g_clear_error (&local);
			}

			current_iblock = iblock;
			iblock = iblock->next;
			destroy_ip_block (current_iblock);
		}

	} else if (!strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_AUTO)) {
		/* - autoconf or DHCPv6 stuff goes here */
	}
	// DNS Servers, set NM_SETTING_IP_CONFIG_IGNORE_AUTO_DNS TRUE here
	set_ip6_dns_servers (s_ip6, conn_name);

	/* DNS searches ('DOMAIN' key) are read by make_ip4_setting() and included in NMSettingIPConfig */

	// Add routes
	iblock = convert_ip6_routes_block (conn_name);
	if (iblock)
		g_object_set (s_ip6, NM_SETTING_IP_CONFIG_IGNORE_AUTO_ROUTES,
			      TRUE, NULL);
	/* Add all IPv6 routes */
	while (iblock) {
		ip_block *current_iblock = iblock;
		const char *metric_str;
		char *stripped;
		gint64 metric;
		NMIPRoute *route;
		GError *local = NULL;

		/* metric is not per routes configuration right now
		 * global metric is also supported (metric="x") */
		if ((metric_str = ifnet_get_data (conn_name, "metric")) != NULL)
			metric = _nm_utils_ascii_str_to_int64 (metric_str, 10, 0, G_MAXUINT32, -1);
		else {
			metric_str = ifnet_get_global_data ("metric");
			if (metric_str) {
				stripped = g_strdup (metric_str);
				strip_string (stripped, '"');
				metric = _nm_utils_ascii_str_to_int64 (metric_str, 10, 0, G_MAXUINT32, -1);
				g_free (stripped);
			} else
				metric = 1;
		}

		route = nm_ip_route_new (AF_INET6, iblock->ip, iblock->prefix, iblock->next_hop, metric, &local);
		if (route) {
			if (nm_setting_ip_config_add_route (s_ip6, route))
				nm_log_info (LOGD_SETTINGS, "    new IP6 route");
			else
				nm_log_warn (LOGD_SETTINGS, "    duplicate IP6 route");
			nm_ip_route_unref (route);
		} else {
			nm_log_warn (LOGD_SETTINGS, "    ignoring invalid route entry: %s", local->message);
			g_clear_error (&local);
		}

		current_iblock = iblock;
		iblock = iblock->next;
		destroy_ip_block (current_iblock);
	}

done:
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));
	return TRUE;

error:
	g_object_unref (s_ip6);
	nm_log_warn (LOGD_SETTINGS, "    Ignore IPv6 for %s", conn_name);
	return FALSE;
}

static NMSetting *
make_wireless_connection_setting (const char *conn_name,
                                  NMSetting8021x **s_8021x,
                                  GError **error)
{
	const char *mac = NULL;
	NMSettingWireless *wireless_setting = NULL;
	gboolean adhoc = FALSE;
	const char *value;
	const char *type;

	/* PPP over WIFI is not supported yet */
	g_return_val_if_fail (conn_name != NULL
			      && strcmp (ifnet_get_data (conn_name, "type"),
					 "ppp") != 0, NULL);
	type = ifnet_get_data (conn_name, "type");
	if (strcmp (type, "ppp") == 0) {
		nm_log_warn (LOGD_SETTINGS, "PPP over WIFI is not supported yet");
		return NULL;
	}

	wireless_setting = NM_SETTING_WIRELESS (nm_setting_wireless_new ());
	if (read_mac_address (conn_name, &mac, error)) {
		if (mac) {
			g_object_set (wireless_setting,
				      NM_SETTING_WIRELESS_MAC_ADDRESS, mac,
				      NULL);
		}
	} else {
		g_object_unref (wireless_setting);
		return NULL;
	}

	/* handle ssid (hex and ascii) */
	if (conn_name) {
		GBytes *bytes;
		gsize ssid_len = 0, value_len = strlen (conn_name);

		ssid_len = value_len;
		if ((value_len > 2) && (g_str_has_prefix (conn_name, "0x"))) {
			/* Hex representation */
			if (value_len % 2) {
				g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
					     "Invalid SSID '%s' size (looks like hex but length not multiple of 2)",
					     conn_name);
				goto error;
			}

			bytes = nm_utils_hexstr2bin (conn_name);
			if (!bytes) {
				g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
				             "Invalid SSID '%s' (looks like hex SSID but isn't)",
				             conn_name);
				goto error;
			}
		} else
			bytes = g_bytes_new (conn_name, value_len);

		ssid_len = g_bytes_get_size (bytes);
		if (ssid_len > 32 || ssid_len == 0) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
				     "Invalid SSID '%s' (size %zu not between 1 and 32 inclusive)",
				     conn_name, ssid_len);
			goto error;
		}

		g_object_set (wireless_setting, NM_SETTING_WIRELESS_SSID, bytes, NULL);
		g_bytes_unref (bytes);
	} else {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			     "Missing SSID");
		goto error;
	}

	/* mode=0: infrastructure
	 * mode=1: adhoc */
	value = wpa_get_value (conn_name, "mode");
	if (value)
		adhoc = strcmp (value, "1") == 0 ? TRUE : FALSE;

	if (exist_ssid (conn_name)) {
		const char *mode = adhoc ? "adhoc" : "infrastructure";

		g_object_set (wireless_setting, NM_SETTING_WIRELESS_MODE, mode,
			      NULL);
		nm_log_info (LOGD_SETTINGS, "Using mode: %s", mode);
	}

	/* BSSID setting */
	value = wpa_get_value (conn_name, "bssid");
	if (value) {
		if (!nm_utils_hwaddr_valid (value, ETH_ALEN)) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
						 "Invalid BSSID '%s'", value);
			goto error;
		}

		g_object_set (wireless_setting, NM_SETTING_WIRELESS_BSSID,
			      value, NULL);

	}

	/* mtu_ssid="xx" */
	value = ifnet_get_data (conn_name, "mtu");
	if (value) {
		long int mtu;

		errno = 0;
		mtu = strtol (value, NULL, 10);
		if (errno || mtu < 0 || mtu > 50000) {
			nm_log_warn (LOGD_SETTINGS, "    invalid MTU '%s' for %s", value, conn_name);
		} else
			g_object_set (wireless_setting, NM_SETTING_WIRELESS_MTU,
				      (guint32) mtu, NULL);

	}

	nm_log_info (LOGD_SETTINGS, "wireless_setting added for %s", conn_name);
	return NM_SETTING (wireless_setting);
error:
	if (wireless_setting)
		g_object_unref (wireless_setting);
	return NULL;

}

static NMSettingWirelessSecurity *
make_leap_setting (const char *ssid, GError **error)
{
	NMSettingWirelessSecurity *wsec;
	const char *value;

	wsec =
	    NM_SETTING_WIRELESS_SECURITY (nm_setting_wireless_security_new ());

	value = wpa_get_value (ssid, "password");
	if (value && strlen (value))
		g_object_set (wsec, NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD,
			      value, NULL);

	value = wpa_get_value (ssid, "identity");
	if (!value || !strlen (value)) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			     "Missing LEAP identity");
		goto error;
	}
	g_object_set (wsec, NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME, value,
		      NULL);

	g_object_set (wsec,
		      NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "ieee8021x",
		      NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "leap", NULL);

	return wsec;
error:
	if (wsec)
		g_object_unref (wsec);
	return NULL;
}

static gboolean
add_one_wep_key (const char *ssid,
                 const char *key,
                 int key_idx,
                 NMSettingWirelessSecurity *s_wsec,
                 GError **error)
{
	const char *value;
	char *converted = NULL;
	gboolean success = FALSE;

	g_return_val_if_fail (ssid != NULL, FALSE);
	g_return_val_if_fail (key != NULL, FALSE);
	g_return_val_if_fail (key_idx >= 0 && key_idx <= 3, FALSE);
	g_return_val_if_fail (s_wsec != NULL, FALSE);

	value = wpa_get_value (ssid, key);
	if (!value)
		return TRUE;

	/* Validate keys */
	if (strlen (value) == 10 || strlen (value) == 26) {
		/* Hexadecimal WEP key */
		if (!is_hex (value)) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Invalid hexadecimal WEP key.");
			goto out;
		}
		converted = g_strdup (value);
	} else if (value[0] == '"'
		   && (strlen (value) == 7 || strlen (value) == 15)) {
		/* ASCII passphrase */
		char *tmp = g_strdup (value);
		char *p = strip_string (tmp, '"');

		if (!is_ascii (p)) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Invalid ASCII WEP passphrase.");
			g_free (tmp);
			goto out;

		}

		converted = nm_utils_bin2hexstr (tmp, strlen (tmp), -1);
		g_free (tmp);
	} else {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			     "Invalid WEP key length. Key: %s", value);
		goto out;
	}

	if (converted) {
		nm_setting_wireless_security_set_wep_key (s_wsec, key_idx, converted);
		g_free (converted);
		success = TRUE;
	}

out:
	return success;
}

static gboolean
add_wep_keys (const char *ssid,
              NMSettingWirelessSecurity *s_wsec,
              GError **error)
{
	if (!add_one_wep_key (ssid, "wep_key0", 0, s_wsec, error))
		return FALSE;
	if (!add_one_wep_key (ssid, "wep_key1", 1, s_wsec, error))
		return FALSE;
	if (!add_one_wep_key (ssid, "wep_key2", 2, s_wsec, error))
		return FALSE;
	if (!add_one_wep_key (ssid, "wep_key3", 3, s_wsec, error))
		return FALSE;
	return TRUE;

}

static NMSettingWirelessSecurity *
make_wep_setting (const char *ssid, GError **error)
{
	const char *auth_alg, *value;
	int default_key_idx = 0;
	NMSettingWirelessSecurity *s_wireless_sec;

	s_wireless_sec =
	    NM_SETTING_WIRELESS_SECURITY (nm_setting_wireless_security_new ());
	g_object_set (s_wireless_sec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT,
		      "none", NULL);

	/* default key index */
	value = wpa_get_value (ssid, "wep_tx_keyidx");
	if (value) {
		default_key_idx = atoi (value);
		if (default_key_idx >= 0 && default_key_idx <= 3) {
			g_object_set (s_wireless_sec,
				      NM_SETTING_WIRELESS_SECURITY_WEP_TX_KEYIDX,
				      default_key_idx, NULL);
			nm_log_info (LOGD_SETTINGS, "Default key index: %d", default_key_idx);
		} else {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
				     "Invalid default WEP key '%s'", value);
			goto error;
		}
	}

	if (!add_wep_keys (ssid, s_wireless_sec, error))
		goto error;

	/* If there's a default key, ensure that key exists */
	if ((default_key_idx == 1)
	    && !nm_setting_wireless_security_get_wep_key (s_wireless_sec, 1)) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			     "Default WEP key index was 2, but no valid KEY2 exists.");
		goto error;
	} else if ((default_key_idx == 2)
		   && !nm_setting_wireless_security_get_wep_key (s_wireless_sec,
								 2)) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			     "Default WEP key index was 3, but no valid KEY3 exists.");
		goto error;
	} else if ((default_key_idx == 3)
		   && !nm_setting_wireless_security_get_wep_key (s_wireless_sec,
								 3)) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			     "Default WEP key index was 4, but no valid KEY4 exists.");
		goto error;
	}

	/* authentication algorithms */
	auth_alg = wpa_get_value (ssid, "auth_alg");
	if (auth_alg) {
		if (strcmp (auth_alg, "OPEN") == 0) {
			g_object_set (s_wireless_sec,
				      NM_SETTING_WIRELESS_SECURITY_AUTH_ALG,
				      "open", NULL);
			nm_log_info (LOGD_SETTINGS, "WEP: Use open system authentication");
		} else if (strcmp (auth_alg, "SHARED") == 0) {
			g_object_set (s_wireless_sec,
				      NM_SETTING_WIRELESS_SECURITY_AUTH_ALG,
				      "shared", NULL);
			nm_log_info (LOGD_SETTINGS, "WEP: Use shared system authentication");
		} else {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
				     "Invalid WEP authentication algorithm '%s'",
				     auth_alg);
			goto error;
		}

	}

	if (!nm_setting_wireless_security_get_wep_key (s_wireless_sec, 0)
	    && !nm_setting_wireless_security_get_wep_key (s_wireless_sec, 1)
	    && !nm_setting_wireless_security_get_wep_key (s_wireless_sec, 2)
	    && !nm_setting_wireless_security_get_wep_key (s_wireless_sec, 3)
	    && !nm_setting_wireless_security_get_wep_tx_keyidx (s_wireless_sec)) {
		if (auth_alg && !strcmp (auth_alg, "shared")) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
				     "WEP Shared Key authentication is invalid for "
				     "unencrypted connections.");
			goto error;
		}
		/* Unencrypted */
		g_object_unref (s_wireless_sec);
		s_wireless_sec = NULL;
	}
	return s_wireless_sec;

error:
	if (s_wireless_sec)
		g_object_unref (s_wireless_sec);
	return NULL;
}

static char *
parse_wpa_psk (const char *psk, GError **error)
{
	char *hashed = NULL;
	gboolean quoted = FALSE;

	if (!psk) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			     "Missing WPA_PSK for WPA-PSK key management");
		return NULL;
	}

	/* Passphrase must be between 10 and 66 characters in length because WPA
	 * hex keys are exactly 64 characters (no quoting), and WPA passphrases
	 * are between 8 and 63 characters (inclusive), plus optional quoting if
	 * the passphrase contains spaces.
	 */

	if (psk[0] == '"' && psk[strlen (psk) - 1] == '"')
		quoted = TRUE;
	if (!quoted && (strlen (psk) == 64)) {
		/* Verify the hex PSK; 64 digits */
		if (!is_hex (psk)) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Invalid WPA_PSK (contains non-hexadecimal characters)");
			goto out;
		}
		hashed = g_strdup (psk);
	} else {
		char *stripped = g_strdup (psk);

		strip_string (stripped, '"');

		/* Length check */
		if (strlen (stripped) < 8 || strlen (stripped) > 63) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
				     "Invalid WPA_PSK (passphrases must be between "
				     "8 and 63 characters long (inclusive))");
			g_free (stripped);
			goto out;
		}

		hashed = g_strdup (stripped);
		g_free (stripped);
	}

	if (!hashed) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			     "Invalid WPA_PSK (doesn't look like a passphrase or hex key)");
		goto out;
	}

out:
	return hashed;
}

static gboolean
fill_wpa_ciphers (const char *ssid,
                  NMSettingWirelessSecurity *wsec,
                  gboolean group,
                  gboolean adhoc)
{
	const char *value;
	char **list = NULL, **iter;
	int i = 0;

	value = wpa_get_value (ssid, group ? "group" : "pairwise");
	if (!value)
		return TRUE;

	list = g_strsplit_set (value, " ", 0);
	for (iter = list; iter && *iter; iter++, i++) {
		/* Ad-Hoc configurations cannot have pairwise ciphers, and can only
		 * have one group cipher.  Ignore any additional group ciphers and
		 * any pairwise ciphers specified.
		 */
		if (adhoc) {
			if (group && (i > 0)) {
				nm_log_warn (LOGD_SETTINGS, "    ignoring group cipher '%s' (only one group cipher allowed in Ad-Hoc mode)",
				             *iter);
				continue;
			} else if (!group) {
				nm_log_warn (LOGD_SETTINGS, "    ignoring pairwise cipher '%s' (pairwise not used in Ad-Hoc mode)",
				             *iter);
				continue;
			}
		}

		if (!strcmp (*iter, "CCMP")) {
			if (group)
				nm_setting_wireless_security_add_group (wsec,
									"ccmp");
			else
				nm_setting_wireless_security_add_pairwise (wsec,
									   "ccmp");
		} else if (!strcmp (*iter, "TKIP")) {
			if (group)
				nm_setting_wireless_security_add_group (wsec,
									"tkip");
			else
				nm_setting_wireless_security_add_pairwise (wsec,
									   "tkip");
		} else if (group && !strcmp (*iter, "WEP104"))
			nm_setting_wireless_security_add_group (wsec, "wep104");
		else if (group && !strcmp (*iter, "WEP40"))
			nm_setting_wireless_security_add_group (wsec, "wep40");
		else {
			nm_log_warn (LOGD_SETTINGS, "    ignoring invalid %s cipher '%s'",
			             group ? "CIPHER_GROUP" : "CIPHER_PAIRWISE",
			             *iter);
		}
	}

	if (list)
		g_strfreev (list);
	return TRUE;
}

static NMSetting8021x *
fill_8021x (const char *ssid,
            const char *key_mgmt,
            gboolean wifi,
            const char *basepath,
            GError **error)
{
	NMSetting8021x *s_8021x;
	const char *value;
	char **list, **iter;

	value = wpa_get_value (ssid, "eap");
	if (!value) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			     "Missing IEEE_8021X_EAP_METHODS for key management '%s'",
			     key_mgmt);
		return NULL;
	}

	list = g_strsplit (value, " ", 0);

	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	/* Validate and handle each EAP method */
	for (iter = list; iter && *iter; iter++) {
		EAPReader *eap = &eap_readers[0];
		gboolean found = FALSE;
		char *lower = NULL;

		lower = g_ascii_strdown (*iter, -1);
		while (eap->method) {
			if (strcmp (eap->method, lower))
				goto next;

			/* Some EAP methods don't provide keying material, thus they
			 * cannot be used with WiFi unless they are an inner method
			 * used with TTLS or PEAP or whatever.
			 */
			if (wifi && eap->wifi_phase2_only) {
				nm_log_warn (LOGD_SETTINGS, "    ignored invalid IEEE_8021X_EAP_METHOD '%s'; not allowed for wifi.",
				             lower);
				goto next;
			}

			/* Parse EAP method specific options */
			if (!(*eap->reader) (lower, ssid, s_8021x, FALSE, basepath, error)) {
				g_free (lower);
				goto error;
			}
			nm_setting_802_1x_add_eap_method (s_8021x, lower);
			found = TRUE;
			break;

		next:
			eap++;
		}

		if (!found) {
			nm_log_warn (LOGD_SETTINGS, "    ignored unknown IEEE_8021X_EAP_METHOD '%s'.", lower);
		}
		g_free (lower);
	}
	g_strfreev (list);

	if (nm_setting_802_1x_get_num_eap_methods (s_8021x) == 0) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			     "No valid EAP methods found in IEEE_8021X_EAP_METHODS.");
		goto error;
	}

	return s_8021x;

error:
	g_object_unref (s_8021x);
	return NULL;
}

static NMSettingWirelessSecurity *
make_wpa_setting (const char *ssid,
                  const char *basepath,
                  NMSetting8021x **s_8021x,
                  GError **error)
{
	NMSettingWirelessSecurity *wsec;
	const char *value;
	char *lower;
	gboolean adhoc = FALSE;

	if (!exist_ssid (ssid)) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			     "No security info found for ssid: %s", ssid);
		return NULL;
	}

	wsec = NM_SETTING_WIRELESS_SECURITY (nm_setting_wireless_security_new ());

	/* mode=1: adhoc
	 * mode=0: infrastructure */
	value = wpa_get_value (ssid, "mode");
	if (value)
		adhoc = strcmp (value, "1") == 0 ? TRUE : FALSE;

	/* Pairwise and Group ciphers */
	fill_wpa_ciphers (ssid, wsec, FALSE, adhoc);
	fill_wpa_ciphers (ssid, wsec, TRUE, adhoc);

	/* WPA and/or RSN */
	if (adhoc) {
		/* Ad-Hoc mode only supports WPA proto for now */
		nm_setting_wireless_security_add_proto (wsec, "wpa");
	} else {
		nm_setting_wireless_security_add_proto (wsec, "wpa");
		nm_setting_wireless_security_add_proto (wsec, "rsn");

	}

	value = wpa_get_value (ssid, "key_mgmt");
	if (!strcmp (value, "WPA-PSK")) {
		char *psk = parse_wpa_psk (wpa_get_value (ssid, "psk"), error);

		if (!psk)
			goto error;
		g_object_set (wsec, NM_SETTING_WIRELESS_SECURITY_PSK, psk,
			      NULL);
		g_free (psk);

		if (adhoc)
			g_object_set (wsec,
				      NM_SETTING_WIRELESS_SECURITY_KEY_MGMT,
				      "wpa-none", NULL);
		else
			g_object_set (wsec,
				      NM_SETTING_WIRELESS_SECURITY_KEY_MGMT,
				      "wpa-psk", NULL);
	} else if (!strcmp (value, "WPA-EAP") || !strcmp (value, "IEEE8021X")) {
		if (adhoc) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
				     "Ad-Hoc mode cannot be used with KEY_MGMT type '%s'",
				     value);
			goto error;
		}
		*s_8021x = fill_8021x (ssid, value, TRUE, basepath, error);
		if (!*s_8021x)
			goto error;

		lower = g_ascii_strdown (value, -1);
		g_object_set (wsec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT,
			      lower, NULL);
		g_free (lower);
	} else {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			     "Unknown wireless KEY_MGMT type '%s'", value);
		goto error;
	}
	return wsec;
error:
	if (wsec)
		g_object_unref (wsec);
	return NULL;
}

static NMSettingWirelessSecurity *
make_wireless_security_setting (const char *conn_name,
                                const char *basepath,
                                NMSetting8021x **s_8021x,
                                GError ** error)
{
	NMSettingWirelessSecurity *wsec = NULL;
	const char *ssid;
	gboolean adhoc = FALSE;
	const char *value;

	g_return_val_if_fail (conn_name != NULL
			      && strcmp (ifnet_get_data (conn_name, "type"),
					 "ppp") != 0, NULL);
	nm_log_info (LOGD_SETTINGS, "updating wireless security settings (%s).", conn_name);

	ssid = conn_name;
	value = wpa_get_value (ssid, "mode");
	if (value)
		adhoc = strcmp (value, "1") == 0 ? TRUE : FALSE;

	value = wpa_get_value (ssid, "key_mgmt");
	if (!adhoc && g_strcmp0 (value, "IEEE8021X") == 0) {
		value = wpa_get_value (ssid, "eap");
		if (value && strcasecmp (value, "LEAP") == 0) {
			wsec = make_leap_setting (ssid, error);
			if (wsec == NULL)
				goto error;
		}
	} else if (g_strcmp0 (value, "WPA-PSK") == 0 || g_strcmp0 (value, "WPA-EAP") == 0) {
		wsec = make_wpa_setting (ssid, basepath, s_8021x, error);
		if (wsec == NULL)
			goto error;
	}
	if (!wsec) {
		wsec = make_wep_setting (ssid, error);
		if (wsec == NULL)
			goto error;
	}
	return wsec;

error:
	g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		     "Can't handle security information for ssid: %s",
		     conn_name);
	return NULL;
}

/* Currently only support username and password */
static gboolean
make_pppoe_connection_setting (NMConnection *connection,
                               const char *conn_name,
                               GError **error)
{
	NMSettingPppoe *s_pppoe;
	NMSettingPpp *s_ppp;
	const char *value;

	s_pppoe = NM_SETTING_PPPOE (nm_setting_pppoe_new ());

	/* username */
	value = ifnet_get_data (conn_name, "username");
	if (!value) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			     "ppp requires at lease a username");
		return FALSE;
	}
	g_object_set (s_pppoe, NM_SETTING_PPPOE_USERNAME, value, NULL);

	/* password */
	value = ifnet_get_data (conn_name, "password");
	if (!value) {
		value = "";
	}

	g_object_set (s_pppoe, NM_SETTING_PPPOE_PASSWORD, value, NULL);
	nm_connection_add_setting (connection, NM_SETTING (s_pppoe));

	/* PPP setting */
	s_ppp = (NMSettingPpp *) nm_setting_ppp_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ppp));

	return TRUE;
}

NMConnection *
ifnet_update_connection_from_config_block (const char *conn_name,
                                           const char *basepath,
                                           GError **error)
{
	const gchar *type = NULL;
	NMConnection *connection = NULL;
	NMSettingConnection *setting = NULL;
	NMSetting8021x *s_8021x = NULL;
	NMSettingWirelessSecurity *wsec = NULL;
	gboolean auto_conn = TRUE;
	const char *value = NULL;
	gchar *id, *uuid;
	gboolean success = FALSE;

	connection = nm_simple_connection_new ();
	setting = nm_connection_get_setting_connection (connection);
	if (!setting) {
		setting = NM_SETTING_CONNECTION (nm_setting_connection_new ());
		g_assert (setting);
		nm_connection_add_setting (connection, NM_SETTING (setting));
	}

	type = guess_connection_type (conn_name);
	value = ifnet_get_data (conn_name, "auto");
	if (value && !strcmp (value, "false"))
		auto_conn = FALSE;

	/* Try to read UUID from the ifnet block, otherwise generate UUID from
	 * the connection ID.
	 */
	id = connection_id_from_ifnet_name (conn_name);
	uuid = g_strdup (ifnet_get_data (conn_name, "uuid"));
	if (!uuid)
		uuid = nm_utils_uuid_generate_from_string (id, -1, NM_UTILS_UUID_TYPE_LEGACY, NULL);

	g_object_set (setting,
	              NM_SETTING_CONNECTION_TYPE, type,
	              NM_SETTING_CONNECTION_ID, id,
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_INTERFACE_NAME, conn_name,
	              NM_SETTING_CONNECTION_READ_ONLY, FALSE,
	              NM_SETTING_CONNECTION_AUTOCONNECT, auto_conn,
	              NULL);
	nm_log_info (LOGD_SETTINGS, "name:%s, id:%s, uuid: %s", conn_name, id, uuid);
	g_free (id);
	g_free (uuid);

	if (!strcmp (NM_SETTING_WIRED_SETTING_NAME, type)
	    || !strcmp (NM_SETTING_PPPOE_SETTING_NAME, type)) {
		/* wired setting */
		if (!make_wired_connection_setting (connection, conn_name, error))
			goto error;

		/* pppoe setting */
		if (!strcmp (NM_SETTING_PPPOE_SETTING_NAME, type)) {
			if (!make_pppoe_connection_setting (connection, conn_name, error))
				goto error;
		}
	} else if (!strcmp (NM_SETTING_WIRELESS_SETTING_NAME, type)) {
		/* wireless setting */
		NMSetting *wireless_setting;

		wireless_setting = make_wireless_connection_setting (conn_name, &s_8021x, error);
		if (!wireless_setting)
			goto error;
		nm_connection_add_setting (connection, wireless_setting);

		/* wireless security setting */
		if (wpa_get_value (conn_name, "ssid")) {
			wsec = make_wireless_security_setting (conn_name, basepath, &s_8021x, error);
			if (!wsec)
				goto error;
			nm_connection_add_setting (connection, NM_SETTING (wsec));
			if (s_8021x)
				nm_connection_add_setting (connection, NM_SETTING (s_8021x));
		}
	} else
		goto error;

	/* IPv4 setting */
	if (!make_ip4_setting (connection, conn_name, error))
		goto error;

	/* IPv6 setting */
	if (!make_ip6_setting (connection, conn_name, error))
		goto error;

	if (nm_connection_verify (connection, error)) {
		nm_log_info (LOGD_SETTINGS, "Connection verified %s:%d", conn_name, success);
	} else {
		goto error;
	}

	return connection;
error:
	g_object_unref (connection);
	return NULL;
}

typedef NMSetting8021xCKScheme (*SchemeFunc) (NMSetting8021x * setting);
typedef const char *(*PathFunc) (NMSetting8021x * setting);
typedef GBytes *(*BlobFunc) (NMSetting8021x * setting);

typedef struct ObjectType {
	const char *setting_key;
	SchemeFunc scheme_func;
	PathFunc path_func;
	BlobFunc blob_func;
	const char *conn_name_key;
	const char *suffix;
} ObjectType;

static const ObjectType ca_type = {
	NM_SETTING_802_1X_CA_CERT,
	nm_setting_802_1x_get_ca_cert_scheme,
	nm_setting_802_1x_get_ca_cert_path,
	nm_setting_802_1x_get_ca_cert_blob,
	"ca_cert",
	"ca-cert.der"
};

static const ObjectType phase2_ca_type = {
	NM_SETTING_802_1X_PHASE2_CA_CERT,
	nm_setting_802_1x_get_phase2_ca_cert_scheme,
	nm_setting_802_1x_get_phase2_ca_cert_path,
	nm_setting_802_1x_get_phase2_ca_cert_blob,
	"ca_cert2",
	"inner-ca-cert.der"
};

static const ObjectType client_type = {
	NM_SETTING_802_1X_CLIENT_CERT,
	nm_setting_802_1x_get_client_cert_scheme,
	nm_setting_802_1x_get_client_cert_path,
	nm_setting_802_1x_get_client_cert_blob,
	"client_cert",
	"client-cert.der"
};

static const ObjectType phase2_client_type = {
	NM_SETTING_802_1X_PHASE2_CLIENT_CERT,
	nm_setting_802_1x_get_phase2_client_cert_scheme,
	nm_setting_802_1x_get_phase2_client_cert_path,
	nm_setting_802_1x_get_phase2_client_cert_blob,
	"client_cert2",
	"inner-client-cert.der"
};

static const ObjectType pk_type = {
	NM_SETTING_802_1X_PRIVATE_KEY,
	nm_setting_802_1x_get_private_key_scheme,
	nm_setting_802_1x_get_private_key_path,
	nm_setting_802_1x_get_private_key_blob,
	"private_key",
	"private-key.pem"
};

static const ObjectType phase2_pk_type = {
	NM_SETTING_802_1X_PHASE2_PRIVATE_KEY,
	nm_setting_802_1x_get_phase2_private_key_scheme,
	nm_setting_802_1x_get_phase2_private_key_path,
	nm_setting_802_1x_get_phase2_private_key_blob,
	"private_key2",
	"inner-private-key.pem"
};

static const ObjectType p12_type = {
	NM_SETTING_802_1X_PRIVATE_KEY,
	nm_setting_802_1x_get_private_key_scheme,
	nm_setting_802_1x_get_private_key_path,
	nm_setting_802_1x_get_private_key_blob,
	"private_key",
	"private-key.p12"
};

static const ObjectType phase2_p12_type = {
	NM_SETTING_802_1X_PHASE2_PRIVATE_KEY,
	nm_setting_802_1x_get_phase2_private_key_scheme,
	nm_setting_802_1x_get_phase2_private_key_path,
	nm_setting_802_1x_get_phase2_private_key_blob,
	"private_key2",
	"inner-private-key.p12"
};

static gboolean
write_object (NMSetting8021x *s_8021x,
              const char *conn_name,
              GBytes *override_data,
              const ObjectType *objtype,
              GError **error)
{
	NMSetting8021xCKScheme scheme;
	const char *path = NULL;
	GBytes *blob = NULL;

	g_return_val_if_fail (conn_name != NULL, FALSE);
	g_return_val_if_fail (objtype != NULL, FALSE);
	if (override_data)
		/* if given explicit data to save, always use that instead of asking
		 * the setting what to do.
		 */
		blob = override_data;
	else {
		scheme = (*(objtype->scheme_func)) (s_8021x);
		switch (scheme) {
		case NM_SETTING_802_1X_CK_SCHEME_BLOB:
			blob = (*(objtype->blob_func)) (s_8021x);
			break;
		case NM_SETTING_802_1X_CK_SCHEME_PATH:
			path = (*(objtype->path_func)) (s_8021x);
			break;
		default:
			break;
		}
	}

	/* If the object path was specified, prefer that over any raw cert data that
	 * may have been sent.
	 */
	if (path) {
		wpa_set_data (conn_name, (gchar *) objtype->conn_name_key,
			      (gchar *) path);
		return TRUE;
	}

	/* does not support writing encryption data now */
	if (blob)
		nm_log_warn (LOGD_SETTINGS, "    Currently we do not support cert writing.");

	return TRUE;
}

static gboolean
write_8021x_certs (NMSetting8021x *s_8021x,
                   gboolean phase2,
                   const char *conn_name,
                   GError **error)
{
	char *password = NULL;
	const ObjectType *otype = NULL;
	gboolean is_pkcs12 = FALSE, success = FALSE;
	GBytes *blob = NULL;
	GBytes *enc_key = NULL;
	gchar *generated_pw = NULL;

	/* CA certificate */
	if (phase2)
		otype = &phase2_ca_type;
	else
		otype = &ca_type;

	if (!write_object (s_8021x, conn_name, NULL, otype, error))
		return FALSE;

	/* Private key */
	if (phase2) {
		if (nm_setting_802_1x_get_phase2_private_key_scheme (s_8021x) !=
		    NM_SETTING_802_1X_CK_SCHEME_UNKNOWN) {
			if (nm_setting_802_1x_get_phase2_private_key_format
			    (s_8021x) == NM_SETTING_802_1X_CK_FORMAT_PKCS12)
				is_pkcs12 = TRUE;
		}
		password = (char *)
		    nm_setting_802_1x_get_phase2_private_key_password (s_8021x);
	} else {
		if (nm_setting_802_1x_get_private_key_scheme (s_8021x) !=
		    NM_SETTING_802_1X_CK_SCHEME_UNKNOWN) {
			if (nm_setting_802_1x_get_private_key_format (s_8021x)
			    == NM_SETTING_802_1X_CK_FORMAT_PKCS12)
				is_pkcs12 = TRUE;
		}
		password = (char *)
		    nm_setting_802_1x_get_private_key_password (s_8021x);
	}

	if (is_pkcs12)
		otype = phase2 ? &phase2_p12_type : &p12_type;
	else
		otype = phase2 ? &phase2_pk_type : &pk_type;

	if ((*(otype->scheme_func)) (s_8021x) ==
	    NM_SETTING_802_1X_CK_SCHEME_BLOB)
		blob = (*(otype->blob_func)) (s_8021x);

	/* Only do the private key re-encrypt dance if we got the raw key data, which
	 * by definition will be unencrypted.  If we're given a direct path to the
	 * private key file, it'll be encrypted, so we don't need to re-encrypt.
	 */
	if (blob && !is_pkcs12) {
		GByteArray *tmp_enc_key;

		/* Encrypt the unencrypted private key with the fake password */
		tmp_enc_key =
		    nm_utils_rsa_key_encrypt (g_bytes_get_data (blob, NULL), g_bytes_get_size (blob),
					      password, &generated_pw, error);
		if (!tmp_enc_key)
			goto out;

		enc_key = g_byte_array_free_to_bytes (tmp_enc_key);

		if (generated_pw)
			password = generated_pw;
	}

	/* Save the private key */
	if (!write_object
	    (s_8021x, conn_name, enc_key ? enc_key : blob, otype, error))
		goto out;

	if (phase2)
		wpa_set_data (conn_name, "private_key2_passwd", password);
	else
		wpa_set_data (conn_name, "private_key_passwd", password);

	/* Client certificate */
	if (is_pkcs12) {
		wpa_set_data (conn_name,
			      phase2 ? "client_cert2" : "client_cert", NULL);
	} else {
		if (phase2)
			otype = &phase2_client_type;
		else
			otype = &client_type;

		/* Save the client certificate */
		if (!write_object (s_8021x, conn_name, NULL, otype, error))
			goto out;
	}

	success = TRUE;
out:
	if (generated_pw) {
		memset (generated_pw, 0, strlen (generated_pw));
		g_free (generated_pw);
	}
	if (enc_key) {
		memset ((gpointer) g_bytes_get_data (enc_key, NULL), 0, g_bytes_get_size (enc_key));
		g_bytes_unref (enc_key);
	}
	return success;
}

static gboolean
write_8021x_setting (NMConnection *connection,
                     const char *conn_name,
                     gboolean wired,
                     GError **error)
{
	NMSetting8021x *s_8021x;
	const char *value;
	char *tmp = NULL;
	gboolean success = FALSE;
	GString *phase2_auth;
	GString *phase1;

	s_8021x = nm_connection_get_setting_802_1x (connection);
	if (!s_8021x) {
		return TRUE;
	}

	nm_log_info (LOGD_SETTINGS, "Adding 8021x setting for %s", conn_name);

	/* If wired, write KEY_MGMT */
	if (wired)
		wpa_set_data (conn_name, "key_mgmt", "IEEE8021X");

	/* EAP method */
	if (nm_setting_802_1x_get_num_eap_methods (s_8021x)) {
		value = nm_setting_802_1x_get_eap_method (s_8021x, 0);
		if (value)
			tmp = g_ascii_strup (value, -1);
	}
	wpa_set_data (conn_name, "eap", tmp ? tmp : NULL);
	g_free (tmp);

	wpa_set_data (conn_name, "identity",
		      (gchar *) nm_setting_802_1x_get_identity (s_8021x));

	wpa_set_data (conn_name, "anonymous_identity", (gchar *)
		      nm_setting_802_1x_get_anonymous_identity (s_8021x));

	wpa_set_data (conn_name, "password",
		      (gchar *) nm_setting_802_1x_get_password (s_8021x));

	phase1 = g_string_new (NULL);

	/* PEAP version */
	wpa_set_data (conn_name, "phase1", NULL);
	value = nm_setting_802_1x_get_phase1_peapver (s_8021x);
	if (value && (!strcmp (value, "0") || !strcmp (value, "1")))
		g_string_append_printf (phase1, "peapver=%s ", value);

	/* PEAP label */
	value = nm_setting_802_1x_get_phase1_peaplabel (s_8021x);
	if (value && !strcmp (value, "1"))
		g_string_append_printf (phase1, "peaplabel=%s ", value);
	if (phase1->len) {
		tmp = g_strstrip (g_strdup (phase1->str));
		wpa_set_data (conn_name, "phase1", tmp);
		g_free (tmp);
	}

	/* Phase2 auth methods */
	wpa_set_data (conn_name, "phase2", NULL);
	phase2_auth = g_string_new (NULL);

	value = nm_setting_802_1x_get_phase2_auth (s_8021x);
	if (value) {
		tmp = g_ascii_strup (value, -1);
		g_string_append_printf (phase2_auth, "auth=%s ", tmp);
		g_free (tmp);
	}

	/* Phase2 auth heap */
	value = nm_setting_802_1x_get_phase2_autheap (s_8021x);
	if (value) {
		tmp = g_ascii_strup (value, -1);
		g_string_append_printf (phase2_auth, "autheap=%s ", tmp);
		g_free (tmp);
	}
	tmp = g_strstrip (g_strdup (phase2_auth->str));
	wpa_set_data (conn_name, "phase2", phase2_auth->len ? tmp : NULL);
	g_free (tmp);

	g_string_free (phase2_auth, TRUE);
	g_string_free (phase1, TRUE);

	success = write_8021x_certs (s_8021x, FALSE, conn_name, error);
	if (success) {
		/* phase2/inner certs */
		success = write_8021x_certs (s_8021x, TRUE, conn_name, error);
	}

	return success;
}

static gboolean
write_wireless_security_setting (NMConnection * connection,
				 gchar * conn_name,
				 gboolean adhoc,
				 gboolean * no_8021x, GError ** error)
{
	NMSettingWirelessSecurity *s_wsec;
	const char *key_mgmt, *auth_alg, *key, *cipher, *psk;
	gboolean wep = FALSE, wpa = FALSE;
	char *tmp;
	guint32 i, num;
	GString *str;

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	if (!s_wsec) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			     "Missing '%s' setting",
			     NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);
		return FALSE;
	}

	key_mgmt = nm_setting_wireless_security_get_key_mgmt (s_wsec);
	g_assert (key_mgmt);

	auth_alg = nm_setting_wireless_security_get_auth_alg (s_wsec);

	if (!strcmp (key_mgmt, "none")) {
		wpa_set_data (conn_name, "key_mgmt", "NONE");
		wep = TRUE;
		*no_8021x = TRUE;
	} else if (!strcmp (key_mgmt, "wpa-none")
		   || !strcmp (key_mgmt, "wpa-psk")) {
		wpa_set_data (conn_name, "key_mgmt", "WPA-PSK");
		wpa = TRUE;
		*no_8021x = TRUE;
	} else if (!strcmp (key_mgmt, "ieee8021x")) {
		wpa_set_data (conn_name, "key_mgmt", "IEEE8021X");
	} else if (!strcmp (key_mgmt, "wpa-eap")) {
		wpa_set_data (conn_name, "key_mgmt", "WPA-EAP");
		wpa = TRUE;
	} else
		nm_log_warn (LOGD_SETTINGS, "Unknown key_mgmt: %s", key_mgmt);

	if (auth_alg) {
		if (!strcmp (auth_alg, "shared"))
			wpa_set_data (conn_name, "auth_alg", "SHARED");
		else if (!strcmp (auth_alg, "open"))
			wpa_set_data (conn_name, "auth_alg", "OPEN");
		else if (!strcmp (auth_alg, "leap")) {
			wpa_set_data (conn_name, "auth_alg", "LEAP");
			wpa_set_data (conn_name, "eap", "LEAP");
			wpa_set_data (conn_name, "identity", (gchar *)
				      nm_setting_wireless_security_get_leap_username
				      (s_wsec));
			wpa_set_data (conn_name, "password", (gchar *)
				      nm_setting_wireless_security_get_leap_password
				      (s_wsec));
			*no_8021x = TRUE;
		}
	} else
		wpa_set_data (conn_name, "auth_alg", NULL);

	/* Default WEP TX key index */
	if (wep) {
		tmp =
		    g_strdup_printf ("%d",
				     nm_setting_wireless_security_get_wep_tx_keyidx
				     (s_wsec));
		wpa_set_data (conn_name, "wep_tx_keyidx", tmp);
		g_free (tmp);
	} else
		wpa_set_data (conn_name, "wep_tx_keyidx", NULL);

	/* WEP keys */
	for (i = 0; i < 4; i++) {
		int length;

		key = nm_setting_wireless_security_get_wep_key (s_wsec, i);
		if (!key)
			continue;
		tmp = g_strdup_printf ("wep_key%d", i);
		length = strlen (key);
		if (length == 10 || length == 26 || length == 58)
			wpa_set_data (conn_name, tmp, (gchar *) key);
		else {
			gchar *tmp_key = g_strdup_printf ("\"%s\"", key);

			wpa_set_data (conn_name, tmp, tmp_key);
			g_free (tmp_key);
		}
		g_free (tmp);
	}

	/* WPA Pairwise ciphers */
	wpa_set_data (conn_name, "pairwise", NULL);
	str = g_string_new (NULL);
	num = nm_setting_wireless_security_get_num_pairwise (s_wsec);
	for (i = 0; i < num; i++) {
		if (i > 0)
			g_string_append_c (str, ' ');
		cipher = nm_setting_wireless_security_get_pairwise (s_wsec, i);
		tmp = g_ascii_strup (cipher, -1);
		g_string_append (str, tmp);
		g_free (tmp);
	}
	if (strlen (str->str))
		wpa_set_data (conn_name, "pairwise", str->str);
	g_string_free (str, TRUE);

	/* WPA Group ciphers */
	wpa_set_data (conn_name, "group", NULL);
	str = g_string_new (NULL);
	num = nm_setting_wireless_security_get_num_groups (s_wsec);
	for (i = 0; i < num; i++) {
		if (i > 0)
			g_string_append_c (str, ' ');
		cipher = nm_setting_wireless_security_get_group (s_wsec, i);
		tmp = g_ascii_strup (cipher, -1);
		g_string_append (str, tmp);
		g_free (tmp);
	}
	if (strlen (str->str))
		wpa_set_data (conn_name, "group", str->str);
	g_string_free (str, TRUE);

	/* WPA Passphrase */
	if (wpa) {
		GString *quoted = NULL;

		psk = nm_setting_wireless_security_get_psk (s_wsec);
		if (psk && (strlen (psk) != 64)) {
			quoted = g_string_sized_new (strlen (psk) + 2);
			g_string_append_c (quoted, '"');
			g_string_append (quoted, psk);
			g_string_append_c (quoted, '"');
		}
		/* psk will be lost here if we don't check it for NULL */
		if (psk)
			wpa_set_data (conn_name, "psk",
					  quoted ? quoted->str : (gchar *) psk);
		if (quoted)
			g_string_free (quoted, TRUE);
	} else
		wpa_set_data (conn_name, "psk", NULL);

	return TRUE;
}

/* remove old ssid and add new one*/
static void
update_wireless_ssid (NMConnection *connection,
                      const char *conn_name,
                      const char *ssid,
                      gboolean hex)
{
	if(strcmp (conn_name, ssid)){
		ifnet_delete_network (conn_name);
		wpa_delete_security (conn_name);
	}

	ifnet_add_network (ssid, "wireless");
	wpa_add_security (ssid);
}

static gboolean
write_wireless_setting (NMConnection *connection,
                        const char *conn_name,
                        gboolean *no_8021x,
                        const char **out_new_name,
                        GError **error)
{
	NMSettingWireless *s_wireless;
	GBytes *ssid;
	const guint8 *ssid_data;
	gsize ssid_len;
	const char *mac, *bssid, *mode;
	char buf[33];
	guint32 mtu, i;
	gboolean adhoc = FALSE, hex_ssid = FALSE;
	gchar *ssid_str, *tmp;

	s_wireless = nm_connection_get_setting_wireless (connection);
	if (!s_wireless) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			     "Missing '%s' setting",
			     NM_SETTING_WIRELESS_SETTING_NAME);
		return FALSE;
	}

	ssid = nm_setting_wireless_get_ssid (s_wireless);
	if (!ssid) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			     "Missing SSID in '%s' setting",
			     NM_SETTING_WIRELESS_SETTING_NAME);
		return FALSE;
	}
	ssid_data = g_bytes_get_data (ssid, &ssid_len);
	if (!ssid_len || ssid_len > 32) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			     "Invalid SSID in '%s' setting",
			     NM_SETTING_WIRELESS_SETTING_NAME);
		return FALSE;
	}

	/* If the SSID contains any non-alnum characters, we need to use
	 * the hex notation of the SSID instead. (Because openrc doesn't
	 * support these characters, see bug #356337)
	 */
	for (i = 0; i < ssid_len; i++) {
		if (!g_ascii_isalnum (ssid_data[i])) {
			hex_ssid = TRUE;
			break;
		}
	}

	if (hex_ssid) {
		GString *str;

		/* Hex SSIDs don't get quoted */
		str = g_string_sized_new (ssid_len * 2 + 3);
		g_string_append (str, "0x");
		for (i = 0; i < ssid_len; i++)
			g_string_append_printf (str, "%02X", ssid_data[i]);
		update_wireless_ssid (connection, conn_name, str->str, hex_ssid);
		ssid_str = g_string_free (str, FALSE);
	} else {
		/* Printable SSIDs get quoted */
		memset (buf, 0, sizeof (buf));
		memcpy (buf, ssid_data, ssid_len);
		g_strstrip (buf);
		update_wireless_ssid (connection, conn_name, buf, hex_ssid);
		ssid_str = g_strdup (buf);
	}

	ifnet_set_data (ssid_str, "mac", NULL);
	mac = nm_setting_wireless_get_mac_address (s_wireless);
	if (mac)
		ifnet_set_data (ssid_str, "mac", mac);

	ifnet_set_data (ssid_str, "mtu", NULL);
	mtu = nm_setting_wireless_get_mtu (s_wireless);
	if (mtu) {
		tmp = g_strdup_printf ("%u", mtu);
		ifnet_set_data (ssid_str, "mtu", tmp);
		g_free (tmp);
	}

	ifnet_set_data (ssid_str, "mode", NULL);
	mode = nm_setting_wireless_get_mode (s_wireless);
	if (!mode || !strcmp (mode, "infrastructure")) {
		wpa_set_data (ssid_str, "mode", "0");
	} else if (!strcmp (mode, "adhoc")) {
		wpa_set_data (ssid_str, "mode", "1");
		adhoc = TRUE;
	} else {
		nm_log_warn (LOGD_SETTINGS, "Invalid mode '%s' in '%s' setting",
		             mode, NM_SETTING_WIRELESS_SETTING_NAME);
		return FALSE;
	}

	wpa_set_data (ssid_str, "bssid", NULL);
	bssid = nm_setting_wireless_get_bssid (s_wireless);
	if (bssid)
		wpa_set_data (ssid_str, "bssid", bssid);

	if (nm_connection_get_setting_wireless_security (connection)) {
		if (!write_wireless_security_setting
		    (connection, ssid_str, adhoc, no_8021x, error))
			return FALSE;
	} else
		wpa_delete_security (ssid_str);

	if (out_new_name)
		*out_new_name = ifnet_get_data (ssid_str, "name");
	g_free (ssid_str);
	return TRUE;
}

static gboolean
write_wired_setting (NMConnection *connection,
                     const char *conn_name,
                     GError **error)
{
	NMSettingWired *s_wired;
	const char *mac;
	char *tmp;
	guint32 mtu;

	s_wired = nm_connection_get_setting_wired (connection);
	if (!s_wired) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			     "Missing '%s' setting",
			     NM_SETTING_WIRED_SETTING_NAME);
		return FALSE;
	}

	ifnet_set_data (conn_name, "mac", NULL);
	mac = nm_setting_wired_get_mac_address (s_wired);
	if (mac)
		ifnet_set_data (conn_name, "mac", mac);

	ifnet_set_data (conn_name, "mtu", NULL);
	mtu = nm_setting_wired_get_mtu (s_wired);
	if (mtu) {
		tmp = g_strdup_printf ("%u", mtu);
		ifnet_set_data (conn_name, "mtu", tmp);
		g_free (tmp);
	}
	//FIXME may add connection type in future
	//ifnet_set_data (conn_name, "TYPE", TYPE_ETHERNET);

	return TRUE;
}

static gboolean
write_ip4_setting (NMConnection *connection, const char *conn_name, GError **error)
{
	NMSettingIPConfig *s_ip4;
	const char *value;
	guint32 i, num;
	GString *searches;
	GString *ips;
	GString *routes;
	GString *dns;
	gboolean success = FALSE;

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	if (!s_ip4) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			     "Missing '%s' setting",
			     NM_SETTING_IP4_CONFIG_SETTING_NAME);
		return FALSE;
	}
	routes = g_string_new (NULL);

	value = nm_setting_ip_config_get_method (s_ip4);
	g_assert (value);
	if (!strcmp (value, NM_SETTING_IP4_CONFIG_METHOD_MANUAL)) {

		num = nm_setting_ip_config_get_num_addresses (s_ip4);
		ips = g_string_new (NULL);
		/* IPv4 addresses */
		for (i = 0; i < num; i++) {
			NMIPAddress *addr;

			addr = nm_setting_ip_config_get_address (s_ip4, i);

			g_string_append_printf (ips, "\"%s/%u",
			                        nm_ip_address_get_address (addr),
			                        nm_ip_address_get_prefix (addr));

			/* only the first gateway will be written */
			if (i == 0 && nm_setting_ip_config_get_gateway (s_ip4)) {
				g_string_append_printf (routes,
				                        "\"default via %s\" ",
				                        nm_setting_ip_config_get_gateway (s_ip4));
			}
		}
		ifnet_set_data (conn_name, "config", ips->str);
		g_string_free (ips, TRUE);
	} else if (!strcmp (value, NM_SETTING_IP4_CONFIG_METHOD_SHARED))
		ifnet_set_data (conn_name, "config", "shared");
	else if (!strcmp (value, NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL))
		ifnet_set_data (conn_name, "config", "autoip");
	else
		ifnet_set_data (conn_name, "config", "dhcp");

	/* DNS Servers */
	num = nm_setting_ip_config_get_num_dns (s_ip4);
	if (num > 0) {
		dns = g_string_new (NULL);
		for (i = 0; i < num; i++) {
			const char *ip;

			ip = nm_setting_ip_config_get_dns (s_ip4, i);
			g_string_append_printf (dns, " %s", ip);
		}
		ifnet_set_data (conn_name, "dns_servers", dns->str);
		g_string_free (dns, TRUE);
	} else
		ifnet_set_data (conn_name, "dns_servers", NULL);

	/* DNS Searches */
	num = nm_setting_ip_config_get_num_dns_searches (s_ip4);
	if (num > 0) {
		searches = g_string_new (NULL);
		for (i = 0; i < num; i++) {
			if (i > 0)
				g_string_append_c (searches, ' ');
			g_string_append (searches,
					 nm_setting_ip_config_get_dns_search
					 (s_ip4, i));
		}
		ifnet_set_data (conn_name, "dns_search", searches->str);
		g_string_free (searches, TRUE);
	} else
		ifnet_set_data (conn_name, "dns_search", NULL);
	/* FIXME Will be implemented when configuration supports it
	   if (!strcmp(value, NM_SETTING_IP4_CONFIG_METHOD_AUTO)) {
	   value = nm_setting_ip_config_get_dhcp_hostname(s_ip4);
	   if (value)
	   ifnet_set_data(conn_name, "DHCP_HOSTNAME", value,
	   FALSE);

	   value = nm_setting_ip_config_get_dhcp_client_id(s_ip4);
	   if (value)
	   ifnet_set_data(conn_name, "DHCP_CLIENT_ID", value,
	   FALSE);
	   }
	 */

	/* Static routes */
	num = nm_setting_ip_config_get_num_routes (s_ip4);
	if (num > 0) {
		for (i = 0; i < num; i++) {
			NMIPRoute *route;
			const char *next_hop;

			route = nm_setting_ip_config_get_route (s_ip4, i);

			next_hop = nm_ip_route_get_next_hop (route);
			if (!next_hop)
				next_hop = "0.0.0.0";

			g_string_append_printf (routes, "\"%s/%u via %s\" ",
			                        nm_ip_route_get_dest (route),
			                        nm_ip_route_get_prefix (route),
			                        next_hop);
		}
	}
	if (routes->len > 0)
		ifnet_set_data (conn_name, "routes", routes->str);
	else
		ifnet_set_data (conn_name, "routes", NULL);
	g_string_free (routes, TRUE);

	success = TRUE;

	return success;
}

static void
write_route6_file (NMSettingIPConfig *s_ip6, const char *conn_name)
{
	NMIPRoute *route;
	const char *next_hop;
	guint32 i, num;
	GString *routes_string;
	const char *old_routes;

	g_return_if_fail (s_ip6 != NULL);
	num = nm_setting_ip_config_get_num_routes (s_ip6);
	if (num == 0)
		return;

	old_routes = ifnet_get_data (conn_name, "routes");
	routes_string = g_string_new (old_routes);
	if (old_routes)
		g_string_append (routes_string, "\" ");
	for (i = 0; i < num; i++) {
		route = nm_setting_ip_config_get_route (s_ip6, i);

		next_hop = nm_ip_route_get_next_hop (route);
		if (!next_hop)
			next_hop = "::";

		g_string_append_printf (routes_string, "\"%s/%u via %s\" ",
		                        nm_ip_route_get_dest (route),
		                        nm_ip_route_get_prefix (route),
		                        next_hop);
	}
	if (num > 0)
		ifnet_set_data (conn_name, "routes", routes_string->str);
	g_string_free (routes_string, TRUE);
}

static gboolean
write_ip6_setting (NMConnection *connection, const char *conn_name, GError **error)
{
	NMSettingIPConfig *s_ip6;
	const char *value;
	guint32 i, num;
	GString *searches;
	NMIPAddress *addr;

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	if (!s_ip6) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			     "Missing '%s' setting",
			     NM_SETTING_IP6_CONFIG_SETTING_NAME);
		return FALSE;
	}

	value = nm_setting_ip_config_get_method (s_ip6);
	g_assert (value);
	if (!strcmp (value, NM_SETTING_IP6_CONFIG_METHOD_IGNORE)) {
		ifnet_set_data (conn_name, "enable_ipv6", "false");
		return TRUE;
	} else if (!strcmp (value, NM_SETTING_IP6_CONFIG_METHOD_MANUAL)) {
		/* nothing to do now */
	} else {
		// if (!strcmp(value, NM_SETTING_IP6_CONFIG_METHOD_AUTO)) {
		const char *config = ifnet_get_data (conn_name, "config");
		gchar *tmp;

		if (!config)
			tmp = g_strdup_printf ("dhcp6");
		else
			tmp = g_strdup_printf ("%s\" \"dhcp6\"", config);
		ifnet_set_data (conn_name, "config", tmp);
		g_free (tmp);
	}
	/* else if (!strcmp(value, NM_SETTING_IP6_CONFIG_METHOD_MANUAL)) {
	   } else if (!strcmp(value, NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL)) {
	   } else if (!strcmp(value, NM_SETTING_IP6_CONFIG_METHOD_SHARED)) {
	   } */

	/* Remember to set IPv6 enabled */
	ifnet_set_data (conn_name, "enable_ipv6", "true");

	if (!strcmp (value, NM_SETTING_IP6_CONFIG_METHOD_MANUAL)) {
		const char *config = ifnet_get_data (conn_name, "config");
		gchar *tmp;
		GString *ip_str;

		if (!config)
			config = "";
		num = nm_setting_ip_config_get_num_addresses (s_ip6);

		/* IPv6 addresses */
		ip_str = g_string_new (NULL);
		for (i = 0; i < num; i++) {
			addr = nm_setting_ip_config_get_address (s_ip6, i);

			g_string_append_printf (ip_str, "\"%s/%u\"",
			                        nm_ip_address_get_address (addr),
			                        nm_ip_address_get_prefix (addr));
		}
		tmp = g_strdup_printf ("%s\" %s", config, ip_str->str);
		ifnet_set_data (conn_name, "config", tmp);
		g_free (tmp);
		g_string_free (ip_str, TRUE);
	}

	/* DNS Servers */
	num = nm_setting_ip_config_get_num_dns (s_ip6);
	if (num > 0) {
		const char *dns_servers = ifnet_get_data (conn_name, "dns_servers");
		gchar *tmp;
		GString *dns_string = g_string_new (NULL);
		const char *dns;

		if (!dns_servers)
			dns_servers = "";
		for (i = 0; i < num; i++) {
			dns = nm_setting_ip_config_get_dns (s_ip6, i);

			if (!strstr (dns_servers, dns))
				g_string_append_printf (dns_string, "%s ", dns);
		}
		tmp = g_strdup_printf ("%s %s", dns_servers, dns_string->str);
		ifnet_set_data (conn_name, "dns_servers", tmp);
		g_free (tmp);
		g_string_free (dns_string, TRUE);

	} else
		/* DNS Searches */
		num = nm_setting_ip_config_get_num_dns_searches (s_ip6);
	if (num > 0) {
		const char *ip4_domains;

		ip4_domains = ifnet_get_data (conn_name, "dns_search");
		if (!ip4_domains)
			ip4_domains = "";
		searches = g_string_new (ip4_domains);
		for (i = 0; i < num; i++) {
			const gchar *search = NULL;

			search =
			    nm_setting_ip_config_get_dns_search (s_ip6, i);
			if (search && !strstr (searches->str, search)) {
				if (searches->len > 0)
					g_string_append_c (searches, ' ');
				g_string_append (searches, search);
			}
		}
		ifnet_set_data (conn_name, "dns_search", searches->str);
		g_string_free (searches, TRUE);
	}

	write_route6_file (s_ip6, conn_name);
	return TRUE;
}

static gboolean
write_pppoe_setting (const char *conn_name, NMSettingPppoe * s_pppoe)
{
	const gchar *value;

	value = nm_setting_pppoe_get_username (s_pppoe);
	if (!value) {
		return FALSE;
	}
	ifnet_set_data (conn_name, "username", (gchar *) value);

	value = nm_setting_pppoe_get_password (s_pppoe);
	/* password could be NULL here */
	if (value) {
		ifnet_set_data (conn_name, "password", (gchar *) value);
	}
	return TRUE;
}

gboolean
ifnet_update_parsers_by_connection (NMConnection *connection,
                                    const char *conn_name,
                                    const char *config_file,
                                    const char *wpa_file,
                                    gchar **out_new_name,
                                    gchar **out_backup,
                                    GError **error)
{
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip6;
	gboolean success = FALSE;
	const char *type;
	gboolean no_8021x = FALSE;
	gboolean wired = FALSE, pppoe = TRUE;
	const char *new_name = NULL;

	if (!ifnet_can_write_connection (connection, error))
		return FALSE;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	type = nm_setting_connection_get_connection_type (s_con);
	if (!type) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			     "Missing connection type!");
		goto out;
	}

	if (!strcmp (type, NM_SETTING_WIRED_SETTING_NAME)) {
		/* Writing wired setting */
		if (!write_wired_setting (connection, conn_name, error))
			goto out;
		wired = TRUE;
		no_8021x = TRUE;
	} else if (!strcmp (type, NM_SETTING_WIRELESS_SETTING_NAME)) {
		/* Writing wireless setting */
		if (!write_wireless_setting (connection, conn_name, &no_8021x, &new_name, error))
			goto out;
	} else if (!strcmp (type, NM_SETTING_PPPOE_SETTING_NAME)) {
		NMSettingPppoe *s_pppoe;

		/* Writing pppoe setting */
		s_pppoe = nm_connection_get_setting_pppoe (connection);
		if (!write_pppoe_setting (conn_name, s_pppoe))
			goto out;
		pppoe = TRUE;
		wired = TRUE;
		no_8021x = TRUE;
	} else {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_NOT_SUPPORTED,
			     "Can't write connection type '%s'", type);
		goto out;
	}

	/* connection name may have been updated; use it when writing out
	 * the rest of the settings.
	 */
	if (new_name)
		conn_name = new_name;

	//FIXME wired connection doesn't support 8021x now
	if (!no_8021x) {
		if (!write_8021x_setting (connection, conn_name, wired, error))
			goto out;
	}

	/* IPv4 Setting */
	if (!write_ip4_setting (connection, conn_name, error))
		goto out;

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	if (s_ip6) {
		/* IPv6 Setting */
		if (!write_ip6_setting (connection, conn_name, error))
			goto out;
	}

	/* Connection Setting */
	ifnet_set_data (conn_name, "auto",
	                nm_setting_connection_get_autoconnect (s_con) ? "true" : "false");
	ifnet_set_data (conn_name, "uuid", nm_connection_get_uuid (connection));

	/* Write changes to disk */
	success = ifnet_flush_to_file (config_file, out_backup);
	if (success)
		wpa_flush_to_file (wpa_file);

	if (out_new_name)
		*out_new_name = g_strdup (conn_name);

out:
	return success;
}

gboolean
ifnet_delete_connection_in_parsers (const char *conn_name,
                                    const char *config_file,
                                    const char *wpa_file,
                                    gchar **out_backup)
{
	gboolean result = FALSE;

	ifnet_delete_network (conn_name);
	result = ifnet_flush_to_file (config_file, out_backup);
	if (result) {
		/* connection may not have security information
		 * so simply ignore the return value*/
		wpa_delete_security (conn_name);
		wpa_flush_to_file (wpa_file);
	}

	return result;
}

static void
check_unsupported_secrets (NMSetting  *setting,
                           const char *key,
                           const GValue *value,
                           GParamFlags flags,
                           gpointer user_data)
{
	gboolean *unsupported_secret = user_data;

	if (flags & NM_SETTING_PARAM_SECRET) {
		NMSettingSecretFlags secret_flags = NM_SETTING_SECRET_FLAG_NONE;

		if (!nm_setting_get_secret_flags (setting, key, &secret_flags, NULL))
			g_return_if_reached ();
		if (secret_flags != NM_SETTING_SECRET_FLAG_NONE)
			*unsupported_secret = TRUE;
	}
}

gboolean
ifnet_can_write_connection (NMConnection *connection, GError **error)
{
	NMSettingConnection *s_con;
	gboolean has_unsupported_secrets = FALSE;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	/* If the connection is not available for all users, ignore
	 * it as this plugin only deals with System Connections */
	if (nm_setting_connection_get_num_permissions (s_con)) {
		g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_NOT_SUPPORTED,
		                     "The ifnet plugin does not support non-system-wide connections.");
		return FALSE;
	}

	/* Only support wired, wifi, and PPPoE */
	if (   !nm_connection_is_type (connection, NM_SETTING_WIRED_SETTING_NAME)
	    && !nm_connection_is_type (connection, NM_SETTING_WIRELESS_SETTING_NAME)
	    && !nm_connection_is_type (connection, NM_SETTING_PPPOE_SETTING_NAME)) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_NOT_SUPPORTED,
		             "The ifnet plugin cannot write the connection '%s' (type '%s')",
		             nm_connection_get_id (connection),
		             nm_setting_connection_get_connection_type (s_con));
		return FALSE;
	}

	/* If the connection has flagged secrets, ignore
	 * it as this plugin does not deal with user agent service */
	nm_connection_for_each_setting_value (connection,
	                                      check_unsupported_secrets,
	                                      &has_unsupported_secrets);
	if (has_unsupported_secrets) {
		g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_NOT_SUPPORTED,
		                     "The ifnet plugin only supports persistent system secrets.");
		return FALSE;
	}

	return TRUE;
}

/* get the available wired name(eth*). */
static gchar *
get_wired_name (void)
{
	int i = 0;

	for (; i < 256; i++) {
		gchar *conn_name = g_strdup_printf ("eth%d", i);

		if (!ifnet_has_network (conn_name)) {
			return conn_name;
		} else
			g_free (conn_name);
	}
	return NULL;
}

/* get the available pppoe name(ppp*). */
static gchar *
get_ppp_name (void)
{
	int i = 0;

	for (; i < 256; i++) {
		gchar *conn_name = g_strdup_printf ("ppp%d", i);

		if (!ifnet_has_network (conn_name)) {
			return conn_name;
		} else
			g_free (conn_name);
	}
	return NULL;
}

/* get wireless ssid */
static gchar *
get_wireless_name (NMConnection * connection)
{
	NMSettingWireless *s_wireless;
	GBytes *ssid;
	const guint8 *ssid_data;
	gsize ssid_len;
	gboolean hex_ssid = FALSE;
	gchar *result = NULL;
	char buf[33];
	int i = 0;

	s_wireless = nm_connection_get_setting_wireless (connection);
	if (!s_wireless)
		return NULL;

	ssid = nm_setting_wireless_get_ssid (s_wireless);
	ssid_data = g_bytes_get_data (ssid, &ssid_len);
	if (!ssid_len || ssid_len > 32) {
		return NULL;
	}

	for (i = 0; i < ssid_len; i++) {
		if (!g_ascii_isprint (ssid_data[i])) {
			hex_ssid = TRUE;
			break;
		}
	}

	if (hex_ssid) {
		GString *str;

		str = g_string_sized_new (ssid_len * 2 + 3);
		g_string_append (str, "0x");
		for (i = 0; i < ssid_len; i++)
			g_string_append_printf (str, "%02X", ssid_data[i]);
		result = g_strdup (str->str);
		g_string_free (str, TRUE);
	} else {
		memset (buf, 0, sizeof (buf));
		memcpy (buf, ssid_data, ssid_len);
		result = g_strdup_printf ("%s", buf);
		g_strstrip (result);
	}

	return result;
}

gboolean
ifnet_add_new_connection (NMConnection *connection,
                          const char *config_file,
                          const char *wpa_file,
                          gchar **out_new_name,
                          gchar **out_backup,
                          GError **error)
{
	NMSettingConnection *s_con;
	gboolean success = FALSE;
	const char *type;
	gchar *new_type, *new_name = NULL;

	if (!ifnet_can_write_connection (connection, error))
		return FALSE;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	type = nm_setting_connection_get_connection_type (s_con);
	g_assert (type);

	nm_log_info (LOGD_SETTINGS, "Adding %s connection", type);

	/* get name and type
	 * Wireless type: wireless
	 * Wired type: wired
	 * PPPoE type: ppp*/
	if (!strcmp (type, NM_SETTING_WIRED_SETTING_NAME)) {
		new_name = get_wired_name ();
		if (!new_name)
			goto out;
		new_type = "wired";
	} else if (!strcmp (type, NM_SETTING_WIRELESS_SETTING_NAME)) {
		new_name = get_wireless_name (connection);
		new_type = "wireless";
	} else if (!strcmp (type, NM_SETTING_PPPOE_SETTING_NAME)) {
		new_name = get_ppp_name ();
		if (!new_name)
			goto out;
		new_type = "ppp";
	} else {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_NOT_SUPPORTED,
			     "Can't write connection type '%s'", type);
		goto out;
	}

	if (ifnet_add_network (new_name, new_type)) {
		success = ifnet_update_parsers_by_connection (connection,
		                                              new_name,
		                                              config_file,
		                                              wpa_file,
		                                              NULL,
		                                              out_backup,
		                                              error);
	}

	nm_log_info (LOGD_SETTINGS, "Added new connection: %s, result: %s",
	             new_name, success ? "success" : "fail");

out:
	if (!success || !out_new_name)
		g_free (new_name);
	else if (out_new_name)
		*out_new_name = new_name;
	return success;
}

