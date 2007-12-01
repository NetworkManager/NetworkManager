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

#define SEARCH_TAG "search "
#define NS_TAG "nameserver "

static void
read_profile_resolv_conf (shvarFile *ifcfg, NMSettingIP4Config *s_ip4)
{
	char *file = NULL;
	char *dir = NULL;
	char *contents = NULL;
	char **lines = NULL;
	char **line;

	dir = g_path_get_dirname (ifcfg->fileName);
	if (!dir)
		goto out;

	file = g_strdup_printf ("%s/resolv.conf", dir);
	if (!file)
		goto out;

	if (!g_file_get_contents (file, &contents, NULL, NULL))
		goto out;

	lines = g_strsplit (contents, "\n", 0);
	if (!lines || !*lines)
		goto out;

	s_ip4->dns = g_array_new (FALSE, FALSE, sizeof (guint32));

	for (line = lines; *line; line++) {
		if (!strncmp (*line, SEARCH_TAG, strlen (SEARCH_TAG))) {
			char **searches;

			if (s_ip4->dns_search)
				continue;

			searches = g_strsplit (*line + strlen (SEARCH_TAG), " ", 0);
			if (searches) {
				char **item;
				for (item = searches; *item; item++)
					s_ip4->dns_search = g_slist_append (s_ip4->dns_search, *item);
				g_free (searches);
			}
		} else if (!strncmp (*line, NS_TAG, strlen (NS_TAG))) {
			char *pdns = g_strdup (*line + strlen (NS_TAG));
			struct in_addr dns;

			pdns = g_strstrip (pdns);
			if (inet_pton (AF_INET, pdns, &dns)) {
				g_array_append_val (s_ip4->dns, dns.s_addr);
			} else
				g_warning ("Invalid IP4 DNS server address '%s'", pdns);
			g_free (pdns);
		}
	}

out:
	if (lines)
		g_strfreev (lines);
	g_free (file);
}

static NMSetting *
make_ip4_setting (shvarFile *ifcfg, GError **error)
{
	NMSettingIP4Config *s_ip4 = NULL;
	char *value = NULL;
	NMSettingIP4Address tmp = { 0, 0, 0 };
	gboolean manual = TRUE;

	value = svGetValue (ifcfg, "BOOTPROTO");
	if (!value)
		return NULL;

	if (!strcmp (value, "bootp") || !strcmp (value, "dhcp")) {
		manual = FALSE;
		return NULL;
	}

	value = svGetValue (ifcfg, "IPADDR");
	if (value) {
		struct in_addr ip4_addr;
		if (inet_pton (AF_INET, value, &ip4_addr))
			tmp.address = ip4_addr.s_addr;
		else {
			g_set_error (error, ifcfg_plugin_error_quark (), 0,
			             "Invalid IP4 address '%s'", value);
			goto error;
		}
		g_free (value);
	}

	value = svGetValue (ifcfg, "GATEWAY");
	if (value) {
		struct in_addr gw_addr;
		if (inet_pton (AF_INET, value, &gw_addr))
			tmp.gateway = gw_addr.s_addr;
		else {
			g_set_error (error, ifcfg_plugin_error_quark (), 0,
			             "Invalid IP4 gateway '%s'", value);
			goto error;
		}
		g_free (value);
	}

	value = svGetValue (ifcfg, "NETMASK");
	if (value) {
		struct in_addr mask_addr;
		if (inet_pton (AF_INET, value, &mask_addr))
			tmp.netmask = mask_addr.s_addr;
		else {
			g_set_error (error, ifcfg_plugin_error_quark (), 0,
			             "Invalid IP4 netmask '%s'", value);
			goto error;
		}
		g_free (value);
	}

	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	s_ip4->manual = manual;
	if (tmp.address || tmp.netmask || tmp.gateway) {
		NMSettingIP4Address *addr;
		addr = g_new0 (NMSettingIP4Address, 1);
		memcpy (addr, &tmp, sizeof (NMSettingIP4Address));
		s_ip4->addresses = g_slist_append (s_ip4->addresses, addr);
	}

	read_profile_resolv_conf (ifcfg, s_ip4);

	return NM_SETTING (s_ip4);

error:
	g_free (value);
	if (s_ip4)
		g_object_unref (s_ip4);
	return NULL;
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


static char *
get_one_wep_key (shvarFile *ifcfg, guint8 idx, GError **error)
{
	char *shvar_key;
	char *key = NULL;
	char *value = NULL;

	g_return_val_if_fail (idx <= 3, NULL);

	shvar_key = g_strdup_printf ("KEY%d", idx);
	value = svGetValue (ifcfg, shvar_key);
	if (!value)
		goto out;

	/* Validate keys */
	if (strlen (value) == 10 || strlen (value) == 26) {
		/* Hexadecimal WEP key */
		char *p = value;

		while (*p) {
			if (!g_ascii_isxdigit (*p)) {
				g_set_error (error, ifcfg_plugin_error_quark (), 0,
				             "Invalid hexadecimal WEP key.");
				goto out;
			}
			p++;
		}
		key = g_strdup (value);
	} else if (strlen (value) == 5 || strlen (value) == 13) {
		/* ASCII passphrase */
		char *p = value;

		while (*p) {
			if (!isascii ((int) (*p))) {
				g_set_error (error, ifcfg_plugin_error_quark (), 0,
				             "Invalid ASCII WEP passphrase.");
				goto out;
			}
			p++;
		}

		value = utils_bin2hexstr (value, strlen (value), strlen (value) * 2);
	} else {
		g_set_error (error, ifcfg_plugin_error_quark (), 0, "Invalid WEP key length.");
	}

out:
	g_free (value);
	g_free (shvar_key);
	return key;
}

#define READ_WEP_KEY(idx) \
	{ \
		char *key = get_one_wep_key (ifcfg, idx, error); \
		if (*error) \
			goto error; \
		if (key) { \
			g_object_set_data_full (G_OBJECT (s_wireless_sec), \
			                        NM_SETTING_WIRELESS_SECURITY_WEP_KEY##idx, \
			                        key, \
			                        g_free); \
			have_key = TRUE; \
		} \
	}

static NMSetting *
make_wireless_security_setting (shvarFile *ifcfg, GError **error)
{
	NMSettingWirelessSecurity *s_wireless_sec;
	gboolean have_key = FALSE;
	char *value;

	s_wireless_sec = NM_SETTING_WIRELESS_SECURITY (nm_setting_wireless_security_new ());

	READ_WEP_KEY(0)
	READ_WEP_KEY(1)
	READ_WEP_KEY(2)
	READ_WEP_KEY(3)

	value = svGetValue (ifcfg, "DEFAULTKEY");
	if (value) {
		gboolean success;
		int key_idx = 0;

		success = get_int (value, &key_idx);
		if (success && (key_idx >= 0) && (key_idx <= 3))
			s_wireless_sec->wep_tx_keyidx = key_idx;
		else {
			g_set_error (error, ifcfg_plugin_error_quark (), 0,
			             "Invalid defualt WEP key '%s'", value);
	 		g_free (value);
			goto error;
		}
 		g_free (value);
	}

	value = svGetValue (ifcfg, "SECURITYMODE");
	if (value) {
		char *lcase;

		lcase = g_ascii_strdown (value, -1);
		g_free (value);

		if (!strcmp (lcase, "open")) {
			s_wireless_sec->auth_alg = g_strdup ("open");
		} else if (!strcmp (lcase, "restricted")) {
			s_wireless_sec->auth_alg = g_strdup ("shared");
		} else {
			g_set_error (error, ifcfg_plugin_error_quark (), 0,
			             "Invalid WEP authentication algoritm '%s'",
			             lcase);
			g_free (lcase);
			goto error;
		}
		g_free (lcase);
	}

	if (have_key)
		s_wireless_sec->key_mgmt = g_strdup ("none");

	return NM_SETTING (s_wireless_sec);

error:
	if (s_wireless_sec)
		g_object_unref (s_wireless_sec);
	return NULL;
}


static NMSetting *
make_wireless_setting (shvarFile *ifcfg,
                       NMSetting *security,
                       GError **error)
{
	NMSettingWireless *s_wireless;
	char *value;

	s_wireless = NM_SETTING_WIRELESS (nm_setting_wireless_new ());

	value = svGetValue (ifcfg, "ESSID");
	if (value) {
		gsize len = strlen (value);

		if (len > 32 || len == 0) {
			g_set_error (error, ifcfg_plugin_error_quark (), 0,
			             "Invalid SSID '%s' (size %d not between 1 and 32 inclusive)",
			             value, len);
			goto error;
		}

		s_wireless->ssid = g_byte_array_sized_new (strlen (value));
		g_byte_array_append (s_wireless->ssid, (const guint8 *) value, len);
		g_free (value);
	}

	value = svGetValue (ifcfg, "MODE");
	if (value) {
		char *lcase;

		lcase = g_ascii_strdown (value, -1);
		g_free (value);

		if (!strcmp (lcase, "ad-hoc")) {
			s_wireless->mode = g_strdup ("adhoc");
		} else if (!strcmp (lcase, "managed")) {
			s_wireless->mode = g_strdup ("infrastructure");
		} else {
			g_set_error (error, ifcfg_plugin_error_quark (), 0,
			             "Invalid mode '%s' (not ad-hoc or managed)",
			             lcase);
			g_free (lcase);
			goto error;
		}
		g_free (lcase);
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
wireless_connection_from_ifcfg (const char *file, shvarFile *ifcfg, GError **error)
{
	NMConnection *connection = NULL;
	NMSetting *con_setting = NULL;
	NMSetting *wireless_setting = NULL;
	NMSettingWireless *tmp;
	NMSetting *security_setting = NULL;
	char *printable_ssid = NULL;

	g_return_val_if_fail (file != NULL, NULL);
	g_return_val_if_fail (ifcfg != NULL, NULL);
	g_return_val_if_fail (error != NULL, NULL);
	g_return_val_if_fail (*error == NULL, NULL);

	connection = nm_connection_new ();
	if (!connection) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Failed to allocate new connection for %s.", file);
		return NULL;
	}

	/* Wireless security */
	security_setting = make_wireless_security_setting (ifcfg, error);
	if (*error)
		goto error;
	if (security_setting)
		nm_connection_add_setting (connection, security_setting);

	/* Wireless */
	wireless_setting = make_wireless_setting (ifcfg, security_setting, error);
	if (!wireless_setting)
		goto error;

	nm_connection_add_setting (connection, wireless_setting);

	tmp = NM_SETTING_WIRELESS (wireless_setting);
	printable_ssid = nm_utils_ssid_to_utf8 ((const char *) tmp->ssid->data,
	                                        (guint32) tmp->ssid->len);

	con_setting = make_connection_setting (file, ifcfg,
	                                       NM_SETTING_WIRELESS_SETTING_NAME,
	                                       printable_ssid);
	if (!con_setting) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Failed to create connection setting.");
		goto error;
	}
	nm_connection_add_setting (connection, con_setting);

	if (!nm_connection_verify (connection)) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Connection from %s was invalid.", file);
		goto error;
	}

	return connection;

error:
	g_free (printable_ssid);
	g_object_unref (connection);
	if (con_setting)
		g_object_unref (con_setting);
	if (wireless_setting)
		g_object_unref (wireless_setting);
	return NULL;
}

static NMSetting *
make_wired_setting (shvarFile *ifcfg, GError **error)
{
	NMSettingWired *s_wired;
	char *value;
	int mtu;

	s_wired = NM_SETTING_WIRED (nm_setting_wired_new ());

	value = svGetValue (ifcfg, "MTU");
	if (value) {
		if (get_int (value, &mtu)) {
			if (mtu >= 0 && mtu < 65536)
				s_wired->mtu = mtu;
		} else {
			g_set_error (error, ifcfg_plugin_error_quark (), 0,
			             "Invalid MTU '%s'", value);
			g_object_unref (s_wired);
			s_wired = NULL;
		}
		g_free (value);
	}

	return (NMSetting *) s_wired;
}

static NMConnection *
wired_connection_from_ifcfg (const char *file, shvarFile *ifcfg, GError **error)
{
	NMConnection *connection = NULL;
	NMSetting *con_setting = NULL;
	NMSetting *wired_setting = NULL;

	g_return_val_if_fail (file != NULL, NULL);
	g_return_val_if_fail (ifcfg != NULL, NULL);

	connection = nm_connection_new ();
	if (!connection) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Failed to allocate new connection for %s.", file);
		return NULL;
	}

	con_setting = make_connection_setting (file, ifcfg, NM_SETTING_WIRED_SETTING_NAME, NULL);
	if (!con_setting) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Failed to create connection setting.");
		goto error;
	}
	nm_connection_add_setting (connection, con_setting);

	wired_setting = make_wired_setting (ifcfg, error);
	if (!wired_setting)
		goto error;

	nm_connection_add_setting (connection, wired_setting);

	if (!nm_connection_verify (connection)) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
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
parser_parse_file (const char *file, GError **error)
{
	NMConnection *connection = NULL;
	shvarFile *parsed;
	char *type;
	char *nmc = NULL;
	NMSetting *s_ip4;

	g_return_val_if_fail (file != NULL, NULL);

	parsed = svNewFile(file);
	if (!parsed) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Couldn't parse file '%s'", file);
		return NULL;
	}

	type = svGetValue (parsed, "TYPE");
	if (!type) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "File '%s' didn't have a TYPE key.", file);
		goto done;
	}

	nmc = svGetValue (parsed, "NM_CONTROLLED");
	if (nmc) {
		char *lower;

		lower = g_ascii_strdown (nmc, -1);
		g_free (nmc);

		if (!strcmp (lower, "no") || !strcmp (lower, "n") || !strcmp (lower, "false")) {
			g_free (lower);
			// FIXME: actually ignore the device, not the connection
			g_message ("Ignoring connection '%s' because NM_CONTROLLED was false", file);
			goto done;
		}
		g_free (lower);
	}

	if (!strcmp (type, "Ethernet"))
		connection = wired_connection_from_ifcfg (file, parsed, error);
	else if (!strcmp (type, "Wireless"))
		connection = wireless_connection_from_ifcfg (file, parsed, error);
	else {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Unknown connection type '%s'", type);
	}

	g_free (type);

	if (!connection)
		goto done;

	s_ip4 = make_ip4_setting (parsed, error);
	if (*error) {
		g_object_unref (connection);
		connection = NULL;
		goto done;
	} else if (s_ip4) {
		nm_connection_add_setting (connection, s_ip4);
	}

	if (!nm_connection_verify (connection)) {
		g_object_unref (connection);
		connection = NULL;
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Connection was invalid");
	}

done:
	svCloseFile (parsed);
	return connection;
}

