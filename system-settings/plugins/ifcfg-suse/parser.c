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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
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
#include <nm-utils.h>

#include "shvar.h"
#include "parser.h"
#include "plugin.h"


static gboolean
get_int (const char *str, int *value)
{
	char *e;

	*value = strtol (str, &e, 0);
	if (*e != '\0')
		return FALSE;

	return TRUE;
}

#if 0
static gboolean
read_startmode (shvarFile *file)
{
	char *value;
	gboolean automatic = TRUE;

	value = svGetValue (file, "STARTMODE");
	if (value) {
		if (!g_ascii_strcasecmp (value, "manual"))
			automatic = FALSE;
		else if (!g_ascii_strcasecmp (value, "off")) {
			// FIXME: actually ignore the device, not the connection
			g_message ("Ignoring connection '%s' because NM_CONTROLLED was false", file);
			automatic = FALSE;
		}

		g_free (value);
	}

	return automatic;
}
#endif

static NMSetting *
make_connection_setting (const char *file,
                         shvarFile *ifcfg,
                         const char *type,
                         const char *suggested)
{
	NMSettingConnection *s_con;
	char *basename = NULL;
	int len;
	char *ifcfg_name;

	basename = g_path_get_basename (file);
	if (!basename)
		goto error;
	len = strlen (basename);

	if (len < strlen (IFCFG_TAG) + 1)
		goto error;

	if (strncmp (basename, IFCFG_TAG, strlen (IFCFG_TAG)))
		goto error;

	/* ignore .bak files */
	if ((len > 4) && !strcmp (basename + len - 4, BAK_TAG))
		goto error;

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());

	ifcfg_name = (char *) (basename + strlen (IFCFG_TAG));

 	if (suggested) {
		/* For cosmetic reasons, if the suggested name is the same as
		 * the ifcfg files name, don't use it.
		 */
		if (strcmp (ifcfg_name, suggested)) {
			s_con->id = g_strdup_printf ("System %s (%s)", suggested, ifcfg_name);
			ifcfg_name = NULL;
		}
	}

	if (ifcfg_name)
		s_con->id = g_strdup_printf ("System %s", ifcfg_name);

	s_con->type = g_strdup (type);
	s_con->autoconnect = TRUE;

	return (NMSetting *) s_con;

error:
	g_free (basename);
	return NULL;
}

static guint32
ip4_prefix_to_netmask (int prefix)
{
	guint32 msk = 0x80000000;
	guint32 netmask = 0;

	while (prefix > 0) {
		netmask |= msk;
		msk >>= 1;
		prefix--;
	}

	return htonl (netmask);
}

static NMSetting *
make_ip4_setting (shvarFile *ifcfg, GError **error)
{
	NMSettingIP4Config *s_ip4 = NULL;
	char *value = NULL;
	NMSettingIP4Address tmp = { 0, 0, 0 };
	char *method = NM_SETTING_IP4_CONFIG_METHOD_MANUAL;

	value = svGetValue (ifcfg, "BOOTPROTO");
	if (!value)
		return NULL;

	if (!g_ascii_strcasecmp (value, "bootp") || !g_ascii_strcasecmp (value, "dhcp")) {
		method = NM_SETTING_IP4_CONFIG_METHOD_DHCP;
		return NULL;
	}

	value = svGetValue (ifcfg, "IPADDR");
	if (value) {
		char **pieces;
		struct in_addr ip4_addr;

		pieces = g_strsplit (value, "/", 2);

		if (inet_pton (AF_INET, pieces[0], &ip4_addr))
			tmp.address = ip4_addr.s_addr;
		else {
			g_strfreev (pieces);
			g_set_error (error, ifcfg_plugin_error_quark (), 0, "Invalid IP4 address '%s'", value);
			goto error;
		}

		if (g_strv_length (pieces) == 2)
			tmp.netmask = ip4_prefix_to_netmask (atoi (pieces[1]));

		g_strfreev (pieces);
		g_free (value);
	}

	if (tmp.netmask == 0) {
		value = svGetValue (ifcfg, "PREFIXLEN");
		if (value) {
			tmp.netmask = ip4_prefix_to_netmask (atoi (value));
			g_free (value);
		}
	}

	if (tmp.netmask == 0) {
		value = svGetValue (ifcfg, "NETMASK");
		if (value) {
			struct in_addr mask_addr;

			if (inet_pton (AF_INET, value, &mask_addr))
				tmp.netmask = mask_addr.s_addr;
			else {
				g_set_error (error, ifcfg_plugin_error_quark (), 0, "Invalid IP4 netmask '%s'", value);
				goto error;
			}
			g_free (value);
		}
	}

	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	s_ip4->method = g_strdup (method);
	if (tmp.address || tmp.netmask || tmp.gateway) {
		NMSettingIP4Address *addr;
		addr = g_new0 (NMSettingIP4Address, 1);
		memcpy (addr, &tmp, sizeof (NMSettingIP4Address));
		s_ip4->addresses = g_slist_append (s_ip4->addresses, addr);
	}

	return NM_SETTING (s_ip4);

error:
	g_free (value);
	if (s_ip4)
		g_object_unref (s_ip4);
	return NULL;
}

#if 0
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
#endif

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
		char *key = get_one_wep_key (ifcfg, idx, err); \
		if (*err) \
			goto error; \
		if (key) { \
			g_object_set_data_full (G_OBJECT (security), \
			                        NM_SETTING_WIRELESS_SECURITY_WEP_KEY##idx, \
			                        key, \
			                        g_free); \
			have_key = TRUE; \
		} \
	}


static void
read_wep_settings (shvarFile *ifcfg, NMSettingWirelessSecurity *security, GError **err)
{
	char *value;
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
			g_set_error (err, ifcfg_plugin_error_quark (), 0, "Invalid defualt WEP key '%s'", value);

 		g_free (value);
	}

error:
	return;
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

static void
read_wpa_psk_settings (shvarFile *ifcfg, NMSettingWirelessSecurity *security, GError **err)
{
	char *value;

	value = svGetValue (ifcfg, "WIRELESS_WPA_PSK");
	if (value) {
		if (strlen (value) == 64) {
			/* HEX key */
			security->psk = value;
		} else {
			/* passphrase */

			/* FIXME: */
/* 			unsigned char *buf = g_malloc0 (WPA_PMK_LEN * 2); */
/* 			pbkdf2_sha1 (value, (char *) s_wireless->ssid->data, s_wireless->ssid->len, 4096, buf, WPA_PMK_LEN); */
/* 			security->psk = utils_bin2hexstr ((const char *) buf, WPA_PMK_LEN, WPA_PMK_LEN * 2); */
/* 			g_free (buf); */
			g_free (value);
		}

		ws_wpa_fill_default_ciphers (security);
	} else
		g_set_error (err, ifcfg_plugin_error_quark (), 0, "Missing WPA-PSK key.");
}

#if 0
static void
read_wpa_eap_settings (shvarFile *ifcfg, NMSettingWirelessSecurity *security, GError **err)
{
	char *value;

	value = svGetValue (ifcfg, "WIRELESS_EAP_AUTH");
	if (value) {
		/* valid values are TLS PEAP TTLS */
		security->eap = g_slist_append (NULL, value);
	}

	value = svGetValue (ifcfg, "WIRELESS_WPA_PROTO");
	if (value) {
		/* valid values are WPA RSN (WPA2) */
		security->proto = g_slist_append (NULL, value);
	}

	security->identity = svGetValue (ifcfg, "WIRELESS_WPA_IDENTITY");

	/* FIXME: This should be in get_secrets? */
	value = svGetValue (ifcfg, "WIRELESS_WPA_PASSWORD");
	if (value) {
		g_free (value);
	}

	security->anonymous_identity = svGetValue (ifcfg, "WIRELESS_WPA_ANONID");

	value = svGetValue (ifcfg, "WIRELESS_CA_CERT");
	if (value) {
		g_free (value);
	}

	value = svGetValue (ifcfg, "WIRELESS_CLIENT_CERT");
	if (value) {
		g_free (value);
	}

	/* FIXME: This should be in get_secrets? */
	value = svGetValue (ifcfg, "WIRELESS_CLIENT_KEY");
	if (value) {
		g_free (value);
	}

	/* FIXME: This should be in get_secrets? */
	value = svGetValue (ifcfg, "WIRELESS_CLIENT_KEY_PASSWORD");
	if (value) {
		g_free (value);
	}

	ws_wpa_fill_default_ciphers (security);
}
#endif

static NMSetting *
make_wireless_security_setting (shvarFile *ifcfg, GError **err)
{
	NMSettingWirelessSecurity *s_wireless_sec = NULL;
	char *value;

	value = svGetValue (ifcfg, "WIRELESS_AUTH_MODE");
	if (!value)
		return NULL;

	if (!g_ascii_strcasecmp (value, "no-encryption")) {
		g_free (value);
		return NULL;
	}

	s_wireless_sec = NM_SETTING_WIRELESS_SECURITY (nm_setting_wireless_security_new ());

	if (!g_ascii_strcasecmp (value, "open")) {
		s_wireless_sec->auth_alg = g_strdup ("open");
		read_wep_settings (ifcfg, s_wireless_sec, err);
	} else if (!g_ascii_strcasecmp (value, "sharedkey")) {
		s_wireless_sec->auth_alg = g_strdup ("shared");
		read_wep_settings (ifcfg, s_wireless_sec, err);
	}

	else if (!g_ascii_strcasecmp (value, "psk")) {
		s_wireless_sec->key_mgmt = g_strdup ("wpa-psk");
		read_wpa_psk_settings (ifcfg, s_wireless_sec, err);
	} else if (!g_ascii_strcasecmp (value, "eap")) {
		s_wireless_sec->key_mgmt = g_strdup ("wps-eap");
		/* read_wpa_eap_settings (ifcfg, s_wireless_sec, err); */
	} else
		g_set_error (err, ifcfg_plugin_error_quark (), 0, "Invalid authentication algoritm '%s'", value);

	g_free (value);

	if (*err == NULL)
		return NM_SETTING (s_wireless_sec);

	if (s_wireless_sec)
		g_object_unref (s_wireless_sec);
	return NULL;
}

static NMSetting *
make_wireless_setting (shvarFile *ifcfg,
                       NMSetting *security,
                       GError **err)
{
	NMSettingWireless *s_wireless;
	char *value;

	s_wireless = NM_SETTING_WIRELESS (nm_setting_wireless_new ());

	value = svGetValue (ifcfg, "WIRELESS_ESSID");
	if (value) {
		gsize len = strlen (value);

		if (len > 32 || len == 0) {
			g_set_error (err, ifcfg_plugin_error_quark (), 0,
			             "Invalid SSID '%s' (size %zu not between 1 and 32 inclusive)",
			             value, len);
			goto error;
		}

		s_wireless->ssid = g_byte_array_sized_new (strlen (value));
		g_byte_array_append (s_wireless->ssid, (const guint8 *) value, len);
		g_free (value);
	}

	value = svGetValue (ifcfg, "WIRLESS_MODE");
	if (value) {
		if (!g_ascii_strcasecmp (value, "ad-hoc")) {
			s_wireless->mode = g_strdup ("adhoc");
		} else if (!g_ascii_strcasecmp (value, "managed")) {
			s_wireless->mode = g_strdup ("infrastructure");
		} else {
			g_set_error (err, ifcfg_plugin_error_quark (), 0,
			             "Invalid mode '%s' (not ad-hoc or managed)", value);
			g_free (value);
			goto error;
		}
		g_free (value);
	}

	if (security)
		s_wireless->security = g_strdup (NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);

	// FIXME: channel/freq, other L2 parameters like RTS

	return NM_SETTING (s_wireless);

error:
	if (s_wireless)
		g_object_unref (s_wireless);
	return NULL;
}

static NMConnection *
wireless_connection_from_ifcfg (const char *file, shvarFile *ifcfg, GError **err)
{
	NMConnection *connection = NULL;
	NMSetting *con_setting = NULL;
	NMSetting *wireless_setting = NULL;
	NMSettingWireless *tmp;
	NMSetting *security_setting = NULL;
	char *printable_ssid = NULL;

	connection = nm_connection_new ();
	if (!connection) {
		g_set_error (err, ifcfg_plugin_error_quark (), 0,
		             "Failed to allocate new connection for %s.", file);
		return NULL;
	}

	/* Wireless security */
	security_setting = make_wireless_security_setting (ifcfg, err);
	if (*err)
		goto error;
	if (security_setting)
		nm_connection_add_setting (connection, security_setting);

	/* Wireless */
	wireless_setting = make_wireless_setting (ifcfg, security_setting, err);
	if (!wireless_setting)
		goto error;

	nm_connection_add_setting (connection, wireless_setting);

	tmp = NM_SETTING_WIRELESS (wireless_setting);
	printable_ssid = nm_utils_ssid_to_utf8 ((const char *) tmp->ssid->data,
	                                        (guint32) tmp->ssid->len);

	con_setting = make_connection_setting (file, ifcfg,
	                                       NM_SETTING_WIRELESS_SETTING_NAME,
	                                       printable_ssid);
	g_free (printable_ssid);

	if (!con_setting) {
		g_set_error (err, ifcfg_plugin_error_quark (), 0,
		             "Failed to create connection setting.");
		goto error;
	}
	nm_connection_add_setting (connection, con_setting);

	if (!nm_connection_verify (connection)) {
		g_set_error (err, ifcfg_plugin_error_quark (), 0,
		             "Connection from %s was invalid.", file);
		goto error;
	}

	return connection;

error:
	g_object_unref (connection);
	if (con_setting)
		g_object_unref (con_setting);
	if (wireless_setting)
		g_object_unref (wireless_setting);
	return NULL;
}

static NMSetting *
make_wired_setting (shvarFile *ifcfg, GError **err)
{
	NMSettingWired *s_wired;
	char *value;
	int mtu;

	s_wired = NM_SETTING_WIRED (nm_setting_wired_new ());

	value = svGetValue (ifcfg, "MTU");
	if (value) {
		if (strlen (value) < 1)
			/* Ignore empty MTU */
			;
		else if (get_int (value, &mtu)) {
			if (mtu >= 0 && mtu < 65536)
				s_wired->mtu = mtu;
		} else {
			g_set_error (err, ifcfg_plugin_error_quark (), 0, "Invalid MTU '%s'", value);
			g_object_unref (s_wired);
			s_wired = NULL;
		}
		g_free (value);
	}

	return (NMSetting *) s_wired;
}

static NMConnection *
wired_connection_from_ifcfg (const char *file, shvarFile *ifcfg, GError **err)
{
	NMConnection *connection = NULL;
	NMSetting *con_setting = NULL;
	NMSetting *wired_setting = NULL;

	connection = nm_connection_new ();
	con_setting = make_connection_setting (file, ifcfg, NM_SETTING_WIRED_SETTING_NAME, NULL);
	if (!con_setting) {
		g_set_error (err, ifcfg_plugin_error_quark (), 0,
		             "Failed to create connection setting.");
		goto error;
	}
	nm_connection_add_setting (connection, con_setting);

	wired_setting = make_wired_setting (ifcfg, err);
	if (!wired_setting)
		goto error;

	nm_connection_add_setting (connection, wired_setting);

	if (!nm_connection_verify (connection)) {
		g_set_error (err, ifcfg_plugin_error_quark (), 0,
		             "Connection from %s was invalid.", file);
		goto error;
	}

	return connection;

error:
	g_object_unref (connection);
	if (con_setting)
		g_object_unref (con_setting);
	if (wired_setting)
		g_object_unref (wired_setting);
	return NULL;
}
	
NMConnection *
parser_parse_ifcfg (const char *file, GError **err)
{
	NMConnection *connection = NULL;
	shvarFile *parsed;
	char *type;
	char *nmc = NULL;
	NMSetting *s_ip4;

	g_return_val_if_fail (file != NULL, NULL);

	parsed = svNewFile (file);
	if (!parsed) {
		g_set_error (err, ifcfg_plugin_error_quark (), 0,
		             "Couldn't parse file '%s'", file);
		return NULL;
	}

	nmc = svGetValue (parsed, "NM_CONTROLLED");
	if (nmc) {
		if (!svTrueValue (parsed, nmc, 1)) {
			g_free (nmc);
			// FIXME: actually ignore the device, not the connection
			g_message ("Ignoring connection '%s' because NM_CONTROLLED was false", file);
			goto done;
		}
		g_free (nmc);
	}
	
	type = svGetValue (parsed, "WIRELESS_ESSID");
	if (type) {
		g_free (type);
		connection = wireless_connection_from_ifcfg (file, parsed, err);
	} else
		connection = wired_connection_from_ifcfg (file, parsed, err);

	if (!connection)
		goto done;

	s_ip4 = make_ip4_setting (parsed, err);
	if (*err) {
		g_object_unref (connection);
		connection = NULL;
		goto done;
	} else if (s_ip4) {
		nm_connection_add_setting (connection, s_ip4);
	}

	if (!nm_connection_verify (connection)) {
		g_object_unref (connection);
		connection = NULL;
		g_set_error (err, ifcfg_plugin_error_quark (), 0,
		             "Connection was invalid");
	}

done:
	svCloseFile (parsed);
	return connection;
}

guint32
parser_parse_routes (const char *file, GError **err)
{
	FILE *f;
	char *buf;
	char buffer[512];
	guint route = 0;

	if ((f = fopen (SYSCONFDIR"/sysconfig/network/routes", "r"))) {
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
