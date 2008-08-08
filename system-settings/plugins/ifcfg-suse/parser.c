/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

/* NetworkManager system settings service
 *
 * Søren Sandmann <sandmann@daimi.au.dk>
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
 * (C) Copyright 2007 Red Hat, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <sys/inotify.h>

#include <glib.h>

#include <nm-connection.h>
#include <NetworkManager.h>
#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>
#include <nm-setting-wired.h>
#include <nm-setting-wireless.h>
#include <nm-setting-8021x.h>
#include <nm-utils.h>

#include "shvar.h"
#include "parser.h"
#include "plugin.h"
#include "sha1.h"

#define WPA_PMK_LEN 32

/* Common */

static gboolean
get_int (const char *str, int *value)
{
	char *e;

	*value = strtol (str, &e, 0);
	if (*e != '\0')
		return FALSE;

	return TRUE;
}

static NMSetting *
make_connection_setting (shvarFile *file,
					const char *iface,
                         const char *type,
                         const char *suggested)
{
	NMSettingConnection *s_con;
	char *str;

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
 	if (suggested) {
		/* For cosmetic reasons, if the suggested name is the same as
		 * the ifcfg files name, don't use it.
		 */
		if (strcmp (iface, suggested))
			s_con->id = g_strdup_printf ("System %s (%s)", suggested, iface);
	}

	if (!s_con->id)
		s_con->id = g_strdup_printf ("System %s", iface);

	s_con->type = g_strdup (type);

	str = svGetValue (file, "STARTMODE");
	if (str && !g_ascii_strcasecmp (str, "manual"))
		s_con->autoconnect = FALSE;
	else
		s_con->autoconnect = TRUE;
	g_free (str);

	return (NMSetting *) s_con;
}


static NMSetting *
make_ip4_setting (shvarFile *ifcfg)
{
	NMSettingIP4Config *s_ip4;
	char *str;
	NMSettingIP4Address tmp = { 0, 0, 0 };

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_setting_ip4_config_new ());

	str = svGetValue (ifcfg, "BOOTPROTO");
	if (str) {
		if (!g_ascii_strcasecmp (str, "bootp") || !g_ascii_strcasecmp (str, "dhcp"))
			s_ip4->method = g_strdup (NM_SETTING_IP4_CONFIG_METHOD_AUTO);
		else if (!g_ascii_strcasecmp (str, "static"))
			s_ip4->method = g_strdup (NM_SETTING_IP4_CONFIG_METHOD_MANUAL);
		else if (!g_ascii_strcasecmp (str, "autoip"))
			s_ip4->method = g_strdup (NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL);

		g_free (str);
	}

	if (!s_ip4->method)
		s_ip4->method = g_strdup (NM_SETTING_IP4_CONFIG_METHOD_AUTO);

	str = svGetValue (ifcfg, "IPADDR");
	if (str) {
		char **pieces;
		struct in_addr ip4_addr;

		pieces = g_strsplit (str, "/", 2);

		if (inet_pton (AF_INET, pieces[0], &ip4_addr) > 0) {
			tmp.address = ip4_addr.s_addr;

			if (g_strv_length (pieces) == 2)
				tmp.prefix = atoi (pieces[1]);
		} else
			g_warning ("Ignoring invalid IP4 address '%s'", str);

		g_strfreev (pieces);
		g_free (str);
	}

	if (tmp.address && tmp.prefix == 0) {
		str = svGetValue (ifcfg, "PREFIXLEN");
		if (str) {
			tmp.prefix = atoi (str);
			g_free (str);
		}
	}

	if (tmp.address && tmp.prefix == 0) {
		str = svGetValue (ifcfg, "NETMASK");
		if (str) {
			struct in_addr mask_addr;

			if (inet_pton (AF_INET, str, &mask_addr) > 0)
				tmp.prefix = nm_utils_ip4_netmask_to_prefix (mask_addr.s_addr);
			else {
				g_warning ("Ignoring invalid IP4 addres: invalid netmask: '%s'", str);
				tmp.address = 0;
				tmp.prefix = 0;
			}
			g_free (str);
		}
	}

	if (!tmp.prefix || tmp.prefix > 32) {
		g_warning ("Ignoring invalid IP4 addres: invalid prefix: '%d'", tmp.prefix);
		tmp.address = 0;
		tmp.prefix = 0;
	}

	if (tmp.address) {
		NMSettingIP4Address *addr;
		addr = g_new0 (NMSettingIP4Address, 1);
		memcpy (addr, &tmp, sizeof (NMSettingIP4Address));
		s_ip4->addresses = g_slist_append (s_ip4->addresses, addr);
	}

	return NM_SETTING (s_ip4);
}

/* Ethernet */

static NMSetting *
make_wired_setting (shvarFile *ifcfg)
{
	NMSettingWired *s_wired;
	char *str;
	int mtu;

	s_wired = NM_SETTING_WIRED (nm_setting_wired_new ());

	str = svGetValue (ifcfg, "MTU");
	if (str) {
		if (strlen (str) < 1)
			/* Ignore empty MTU */
			;
		else if (get_int (str, &mtu)) {
			if (mtu >= 0 && mtu < G_MAXINT)
				s_wired->mtu = mtu;
		} else
			g_warning ("Ignoring invalid MTU: '%s'", str);
		g_free (str);
	}

	return (NMSetting *) s_wired;
}

static void
parse_ethernet (NMConnection *connection, shvarFile *file, const char *iface)
{
	NMSetting *setting;

	setting = make_connection_setting (file, iface, NM_SETTING_WIRED_SETTING_NAME, NULL);
	nm_connection_add_setting (connection, setting);

	setting = make_wired_setting (file);
	nm_connection_add_setting (connection, setting);

	setting = make_ip4_setting (file);
	nm_connection_add_setting (connection, setting);
}

/* Wireless */

static char *
get_one_wep_key (shvarFile *ifcfg, guint8 idx, GError **err)
{
	char *shvar_key;
	char *key = NULL;
	char *value = NULL;
	char *p;

	g_return_val_if_fail (idx <= 3, NULL);

	shvar_key = g_strdup_printf ("WIRELESS_KEY_%d", idx);
	value = svGetValue (ifcfg, shvar_key);
	g_free (shvar_key);

	/* Ignore empty keys */
	if (!value)
		return NULL;

	if (strlen (value) < 1) {
		g_free (value);
		return NULL;
	}

	/* ASCII */
	if (g_str_has_prefix (value, "s:")) {
		p = value + 2;
		if (strlen (p) != 5 || strlen (p) != 13)
			g_set_error (err, ifcfg_plugin_error_quark (), 0, "Invalid hexadecimal WEP key.");
		else {
			while (*p) {
				if (!isascii (*p)) {
					g_set_error (err, ifcfg_plugin_error_quark (), 0, "Invalid hexadecimal WEP key.");
					break;
				}
				p++;
			}
		}

		if (!err)
			key = g_strdup (p);
	} else if (g_str_has_prefix (value, "h:")) {
		/* Hashed passphrase */
		p = value + 2;
		if (p && (strlen (p) > 0 || strlen (p) < 65))
			key = g_strdup (p);
		else
			g_set_error (err, ifcfg_plugin_error_quark (), 0, "Invalid WEP passphrase.");
	} else {
		/* Hexadecimal */
		GString *str;

		str = g_string_sized_new (26);
		p = value + 2;
		while (*p) {
			if (g_ascii_isxdigit (*p))
				str = g_string_append_c (str, *p);
			else if (*p != '-') {
				g_set_error (err, ifcfg_plugin_error_quark (), 0, "Invalid hexadecimal WEP key.");
				break;
			}
			p++;
		}

		p = str->str;

		if (p && (strlen (p) == 10 || strlen (p) == 26))
			key = g_string_free (str, FALSE);
		else
			g_set_error (err, ifcfg_plugin_error_quark (), 0, "Invalid hexadecimal WEP key.");
	}

	g_free (value);

	return key;
}

#define READ_WEP_KEY(idx) \
	{ \
		char *key = get_one_wep_key (ifcfg, idx, &err); \
		if (err) \
			goto error; \
		if (key) { \
			g_object_set (G_OBJECT (security), \
					    NM_SETTING_WIRELESS_SECURITY_WEP_KEY##idx, \
					    key,								  \
					    NULL);							  \
			g_free (key); \
			have_key = TRUE; \
		} \
	}

static void
read_wep_settings (shvarFile *ifcfg, NMSettingWirelessSecurity *security)
{
	char *value;
	GError *err = NULL;
	gboolean have_key = FALSE;

	READ_WEP_KEY(0)
	READ_WEP_KEY(1)
	READ_WEP_KEY(2)
	READ_WEP_KEY(3)

	if (have_key)
		security->key_mgmt = g_strdup ("none");

	value = svGetValue (ifcfg, "WIRELESS_DEFAULT_KEY");
	if (value) {
		gboolean success;
		int key_idx = 0;

		success = get_int (value, &key_idx);
		if (success && (key_idx >= 0) && (key_idx <= 3))
			security->wep_tx_keyidx = key_idx;
		else
			g_warning ("Invalid default WEP key: '%s'", value);

 		g_free (value);
	}

error:
	if (err) {
		g_warning ("%s", err->message);
		g_error_free (err);
	}
}

/* Copied from applet/src/wireless-secuirty/wireless-security.c */
static void
ws_wpa_fill_default_ciphers (NMSettingWirelessSecurity *s_wireless_sec)
{
	// FIXME: allow protocol selection and filter on device capabilities
	s_wireless_sec->proto = g_slist_append (s_wireless_sec->proto, g_strdup ("wpa"));
	s_wireless_sec->proto = g_slist_append (s_wireless_sec->proto, g_strdup ("rsn"));

	// FIXME: allow pairwise cipher selection and filter on device capabilities
	s_wireless_sec->pairwise = g_slist_append (s_wireless_sec->pairwise, g_strdup ("tkip"));
	s_wireless_sec->pairwise = g_slist_append (s_wireless_sec->pairwise, g_strdup ("ccmp"));

	// FIXME: allow group cipher selection and filter on device capabilities
	s_wireless_sec->group = g_slist_append (s_wireless_sec->group, g_strdup ("wep40"));
	s_wireless_sec->group = g_slist_append (s_wireless_sec->group, g_strdup ("wep104"));
	s_wireless_sec->group = g_slist_append (s_wireless_sec->group, g_strdup ("tkip"));
	s_wireless_sec->group = g_slist_append (s_wireless_sec->group, g_strdup ("ccmp"));
}

/*
 * utils_bin2hexstr
 *
 * Convert a byte-array into a hexadecimal string.
 *
 * Code originally by Alex Larsson <alexl@redhat.com> and
 *  copyright Red Hat, Inc. under terms of the LGPL.
 *
 */
static char *
utils_bin2hexstr (const char *bytes, int len, int final_len)
{
	static char	hex_digits[] = "0123456789abcdef";
	char *		result;
	int			i;

	g_return_val_if_fail (bytes != NULL, NULL);
	g_return_val_if_fail (len > 0, NULL);
	g_return_val_if_fail (len < 256, NULL);	/* Arbitrary limit */

	result = g_malloc0 (len * 2 + 1);
	for (i = 0; i < len; i++)
	{
		result[2*i] = hex_digits[(bytes[i] >> 4) & 0xf];
		result[2*i+1] = hex_digits[bytes[i] & 0xf];
	}
	/* Cut converted key off at the correct length for this cipher type */
	if (final_len > -1)
		result[final_len] = '\0';

	return result;
}

static void
read_wpa_psk_settings (shvarFile *ifcfg,
				   NMSettingWirelessSecurity *security,
				   NMSettingWireless *s_wireless)
{
	char *value;

	value = svGetValue (ifcfg, "WIRELESS_WPA_PSK");
	if (value) {
		if (strlen (value) == 64) {
			/* Hex PSK */
			security->psk = g_strdup (value);
		} else {
			/* passphrase */
			unsigned char *buf = g_malloc0 (WPA_PMK_LEN * 2);
			pbkdf2_sha1 (value, (char *) s_wireless->ssid->data, s_wireless->ssid->len, 4096, buf, WPA_PMK_LEN);
			security->psk = utils_bin2hexstr ((const char *) buf, WPA_PMK_LEN, WPA_PMK_LEN * 2);
			g_free (buf);
		}

		g_free (value);

		ws_wpa_fill_default_ciphers (security);
	} else
		g_warning ("Missing WPA-PSK key");
}

static NMSetting *
read_wpa_eap_settings (shvarFile *ifcfg)
{
	NMSetting8021x *s_802_1x;
	char *str;
	GError *err = NULL;

	s_802_1x = NM_SETTING_802_1X (nm_setting_802_1x_new ());

	str = svGetValue (ifcfg, "WIRELESS_EAP_MODE");
	if (str) {
		char **pieces;
		int i;

		pieces = g_strsplit (str, " ", 0);
		for (i = 0; pieces[i]; i++)
			s_802_1x->eap = g_slist_append (s_802_1x->eap, pieces[i]);

		g_free (pieces);
		g_free (str);
	}

	s_802_1x->anonymous_identity = svGetValue (ifcfg, "WIRELESS_WPA_ANONID");
	s_802_1x->phase1_peapver = svGetValue (ifcfg, "WIRELESS_PEAP_VERSION");
	s_802_1x->phase2_auth = svGetValue (ifcfg, "WIRELESS_EAP_AUTH");
	s_802_1x->identity = svGetValue (ifcfg, "WIRELESS_WPA_IDENTITY");
	s_802_1x->password = svGetValue (ifcfg, "WIRELESS_WPA_PASSWORD");

	str = svGetValue (ifcfg, "WIRELESS_CA_CERT");
	if (str) {
		nm_setting_802_1x_set_ca_cert (s_802_1x, str, &err);
		if (err) {
			g_warning ("Error loading WIRELESS_CA_CERT: %s", err->message);
			g_error_free (err);
		}

		g_free (str);
	}

	str = svGetValue (ifcfg, "WIRELESS_CLIENT_CERT");
	if (str) {
		nm_setting_802_1x_set_client_cert (s_802_1x, str, &err);
		if (err) {
			g_warning ("Error loading WIRELESS_CLIENT_CERT: %s", err->message);
			g_error_free (err);
		}

		g_free (str);
	}

	str = svGetValue (ifcfg, "WIRELESS_CLIENT_KEY");
	if (str) {
		char *password;

		password = svGetValue (ifcfg, "WIRELESS_CLIENT_KEY_PASSWORD");
		if (password) {
			nm_setting_802_1x_set_private_key (s_802_1x, str, password, &err);
			if (err) {
				g_warning ("Error loading WIRELESS_CLIENT_KEY: %s", err->message);
				g_error_free (err);
			}

			g_free (password);
		} else
			g_warning ("Missing WIRELESS_CLIENT_KEY_PASSWORD");

		g_free (str);
	}

	return (NMSetting *) s_802_1x;
}

static NMSetting *
make_wireless_security_setting (shvarFile *ifcfg, NMSettingWireless *s_wireless)
{
	NMSettingWirelessSecurity *security;
	char *str;

	str = svGetValue (ifcfg, "WIRELESS_AUTH_MODE");
	if (!str || !g_ascii_strcasecmp (str, "no-encryption")) {
		g_free (str);
		return NULL;
	}

	if (!g_ascii_strcasecmp (str, "eap"))
		return read_wpa_eap_settings (ifcfg);

	security = NM_SETTING_WIRELESS_SECURITY (nm_setting_wireless_security_new ());

	if (!g_ascii_strcasecmp (str, "open")) {
		security->auth_alg = g_strdup ("open");
		read_wep_settings (ifcfg, security);
	} else if (!g_ascii_strcasecmp (str, "sharedkey")) {
		security->auth_alg = g_strdup ("shared");
		read_wep_settings (ifcfg, security);
	} else if (!g_ascii_strcasecmp (str, "psk")) {
		security->key_mgmt = g_strdup ("wpa-psk");
		read_wpa_psk_settings (ifcfg, security, s_wireless);
	} else
		g_warning ("Invalid authentication algorithm: '%s'", str);

	g_free (str);

	return (NMSetting *) security;
}

static NMSetting *
make_wireless_setting (shvarFile *ifcfg)
{
	NMSettingWireless *s_wireless;
	char *str;

	s_wireless = NM_SETTING_WIRELESS (nm_setting_wireless_new ());

	str = svGetValue (ifcfg, "WIRELESS_ESSID");
	if (str) {
		gsize len = strlen (str);

		if (len > 0 && len <= 32) {
			s_wireless->ssid = g_byte_array_sized_new (len);
			g_byte_array_append (s_wireless->ssid, (const guint8 *) str, len);
		} else
			g_warning ("Ignoring invalid ESSID '%s', (size %zu not between 1 and 32 inclusive)", str, len);

		g_free (str);
	}

	str = svGetValue (ifcfg, "WIRLESS_MODE");
	if (str) {
		if (!g_ascii_strcasecmp (str, "ad-hoc"))
			s_wireless->mode = g_strdup ("adhoc");
		else if (!g_ascii_strcasecmp (str, "managed"))
			s_wireless->mode = g_strdup ("infrastructure");

		g_free (str);
	}

	// FIXME: channel/freq, other L2 parameters like RTS

	return NM_SETTING (s_wireless);
}

static char *
get_printable_ssid (NMSetting *setting)
{
	NMSettingWireless *s_wireless = NM_SETTING_WIRELESS (setting);
	char *printable_ssid = NULL;

	if (s_wireless->ssid)
		printable_ssid = nm_utils_ssid_to_utf8 ((const char *) s_wireless->ssid->data,
										(guint32) s_wireless->ssid->len);

	return printable_ssid;
}

static void
parse_wireless (NMConnection *connection, shvarFile *file, const char *iface)
{
	NMSetting *setting;
	NMSetting *security;
	char *printable_ssid;

	setting = make_wireless_setting (file);
	nm_connection_add_setting (connection, setting);

	security = make_wireless_security_setting (file, NM_SETTING_WIRELESS (setting));
	if (security) {
		const char *security_str;

		if (NM_IS_SETTING_802_1X (security))
			security_str = NM_SETTING_802_1X_SETTING_NAME;
		else if (NM_IS_SETTING_WIRELESS_SECURITY (security))
			security_str = NM_SETTING_WIRELESS_SECURITY_SETTING_NAME;
		else {
			security_str = NULL;
			g_warning ("Invalid security type: '%s'", G_OBJECT_TYPE_NAME (security));
		}

		g_object_set (G_OBJECT (setting), NM_SETTING_WIRELESS_SEC, security_str, NULL);
		nm_connection_add_setting (connection, security);
	}

	printable_ssid = get_printable_ssid (setting);
	setting = make_connection_setting (file, iface, NM_SETTING_WIRELESS_SETTING_NAME, printable_ssid);
	nm_connection_add_setting (connection, setting);
	g_free (printable_ssid);

	setting = make_ip4_setting (file);
	nm_connection_add_setting (connection, setting);
}

static shvarFile *
parser_get_ifcfg_for_iface (const char *iface)
{
	char *filename;
	shvarFile *file = NULL;

	filename = g_strdup_printf (SYSCONFDIR "/sysconfig/network/ifcfg-%s", iface);
	if (g_file_test (filename, G_FILE_TEST_IS_REGULAR))
		file = svNewFile (filename);

	g_free (filename);

	return file;
}

NMConnection *
parse_ifcfg (const char *iface, NMDeviceType type)
{
	shvarFile *file;
	NMConnection *connection;
	GError *error = NULL;

	g_return_val_if_fail (iface != NULL, NULL);

	file = parser_get_ifcfg_for_iface (iface);
	if (!file)
		return NULL;

	connection = nm_connection_new ();

	switch (type) {
	case NM_DEVICE_TYPE_ETHERNET:
		parse_ethernet (connection, file, iface);
		break;
	case NM_DEVICE_TYPE_WIFI:
		parse_wireless (connection, file, iface);
		break;
	default:
		break;
	}

	svCloseFile (file);

	if (!nm_connection_verify (connection, &error)) {
		g_warning ("%s: Invalid connection for %s: '%s' / '%s' invalid: %d",
		           __func__, iface,
		           g_type_name (nm_connection_lookup_setting_type_by_quark (error->domain)),
		           error->message, error->code);
		g_error_free (error);
		g_object_unref (connection);
		connection = NULL;
	}

	return connection;
}

gboolean
parser_ignore_device (const char *iface)
{
	shvarFile *file;
	gboolean ignore = FALSE;

	file = parser_get_ifcfg_for_iface (iface);
	if (file) {
		char *str;

		if (!svTrueValue (file, "NM_CONTROLLED", 1))
			ignore = TRUE;

		str = svGetValue (file, "STARTMODE");
		if (str && !g_ascii_strcasecmp (str, "off"))
			ignore = TRUE;
		g_free (str);

		svCloseFile (file);
	}

	return ignore;
}

guint32
parser_parse_routes (const char *filename)
{
	FILE *f;
	char *buf;
	char buffer[512];
	guint route = 0;

	g_return_val_if_fail (filename != NULL, 0);

	if ((f = fopen (filename, "r"))) {
		while (fgets (buffer, 512, f) && !feof (f)) {
			buf = strtok (buffer, " ");
			if (strcmp (buf, "default") == 0) {
				buf = strtok (NULL, " ");
				if (buf)
					route = inet_addr (buf);
				break;
			}
			fclose (f);
		}
	}

	return route;
}
