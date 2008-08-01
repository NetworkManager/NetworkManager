/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service
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
 * (C) Copyright 2008 Red Hat, Inc.
 */

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <sys/inotify.h>
#include <errno.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <netinet/ether.h>

#ifndef __user
#define __user
#endif
#include <linux/types.h>
#include <wireless.h>
#undef __user

#include <glib.h>
#include <nm-connection.h>
#include <NetworkManager.h>
#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>
#include <nm-setting-wired.h>
#include <nm-setting-wireless.h>
#include <nm-utils.h>

#include "common.h"
#include "shvar.h"

#include "reader.h"
#include "nm-system-config-interface.h"

#define TYPE_ETHERNET "Ethernet"
#define TYPE_WIRELESS "Wireless"

static char *
get_ifcfg_name (const char *file)
{
	char *ifcfg_name;
	char *basename;

	basename = g_path_get_basename (file);
	if (!basename)
		return NULL;

	ifcfg_name = g_strdup (basename + strlen (IFCFG_TAG));
	g_free (basename);
	return ifcfg_name;
}

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
	char *ifcfg_name = NULL;

	ifcfg_name = get_ifcfg_name (file);
	if (!ifcfg_name)
		return NULL;

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());

 	if (suggested) {
		/* For cosmetic reasons, if the suggested name is the same as
		 * the ifcfg files name, don't use it.
		 */
		if (strcmp (ifcfg_name, suggested))
			s_con->id = g_strdup_printf ("System %s (%s)", suggested, ifcfg_name);
	}

	if (!s_con->id)
		s_con->id = g_strdup_printf ("System %s", ifcfg_name);

	s_con->type = g_strdup (type);

	/* Be somewhat conservative about autoconnect */
	if (svTrueValue (ifcfg, "ONBOOT", FALSE))
		s_con->autoconnect = TRUE;

	g_free (ifcfg_name);
	return (NMSetting *) s_con;
}

static void
get_one_ip4_addr (shvarFile *ifcfg,
                  const char *tag,
                  guint32 *out_addr,
                  GError **error)
{
	char *value = NULL;
	struct in_addr ip4_addr;

	g_return_if_fail (ifcfg != NULL);
	g_return_if_fail (tag != NULL);
	g_return_if_fail (out_addr != NULL);
	g_return_if_fail (error != NULL);
	g_return_if_fail (*error == NULL);

	value = svGetValue (ifcfg, tag);
	if (!value)
		return;

	if (inet_pton (AF_INET, value, &ip4_addr) > 0)
		*out_addr = ip4_addr.s_addr;
	else {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Invalid %s IP4 address '%s'", tag, value);
	}
	g_free (value);
}

#define GET_ONE_DNS(tag) \
	{ \
		guint32 dns = 0; \
		get_one_ip4_addr (ifcfg, tag, &dns, error); \
		if (*error) \
			goto error; \
		if (dns) \
			g_array_append_val (s_ip4->dns, dns); \
	}
		

static NMSetting *
make_ip4_setting (shvarFile *ifcfg, GError **error)
{
	NMSettingIP4Config *s_ip4 = NULL;
	char *value = NULL;
	NMSettingIP4Address tmp = { 0, 0, 0 };
	char *method = NM_SETTING_IP4_CONFIG_METHOD_MANUAL;
	guint32 netmask = 0;

	value = svGetValue (ifcfg, "BOOTPROTO");
	if (value && (!g_ascii_strcasecmp (value, "bootp") || !g_ascii_strcasecmp (value, "dhcp")))
		method = NM_SETTING_IP4_CONFIG_METHOD_AUTO;

	if (value && !g_ascii_strcasecmp (value, "autoip")) {
		g_free (value);
		s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
		s_ip4->method = g_strdup (NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL);
		return NM_SETTING (s_ip4);
	}

	g_free (value);

	/* Handle manual settings */
	if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_MANUAL)) {
		get_one_ip4_addr (ifcfg, "IPADDR", &tmp.address, error);
		if (*error)
			goto error;

		get_one_ip4_addr (ifcfg, "GATEWAY", &tmp.gateway, error);
		if (*error)
			goto error;

		/* If no gateway in the ifcfg, try /etc/sysconfig/network instead */
		if (!tmp.gateway) {
			shvarFile *network;

			network = svNewFile ("/etc/sysconfig/network");
			if (network) {
				get_one_ip4_addr (network, "GATEWAY", &tmp.gateway, error);
				svCloseFile (network);
				if (*error)
					goto error;
			}
		}

		value = svGetValue (ifcfg, "PREFIX");
		if (value) {
			long int prefix;

			errno = 0;
			prefix = strtol (value, NULL, 10);
			if (errno || prefix <= 0 || prefix > 32) {
				g_set_error (error, ifcfg_plugin_error_quark (), 0,
				             "Invalid IP4 prefix '%s'", value);
				g_free (value);
				goto error;
			}
			tmp.prefix = (guint32) prefix;
			g_free (value);
		}

		/* Fall back to NETMASK if no PREFIX was specified */
		if (!tmp.prefix) {
			get_one_ip4_addr (ifcfg, "NETMASK", &netmask, error);
			if (*error)
				goto error;
			tmp.prefix = nm_utils_ip4_netmask_to_prefix (netmask);
		}

		/* Validate the prefix */
		if (!tmp.prefix || tmp.prefix > 32) {
			g_set_error (error, ifcfg_plugin_error_quark (), 0,
			             "Invalid IP4 prefix '%d'", tmp.prefix);
			goto error;
		}
	}

	/* Yay, let's make an IP4 config */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	s_ip4->method = g_strdup (method);
	s_ip4->ignore_dhcp_dns = !svTrueValue (ifcfg, "PEERDNS", 1);

	/* DHCP hostname for 'send host-name' option */
	if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_AUTO)) {
		value = svGetValue (ifcfg, "DHCP_HOSTNAME");
		if (value && strlen (value))
			s_ip4->dhcp_hostname = g_strdup (value);
		g_free (value);
	}

	if (tmp.address && tmp.prefix) {
		NMSettingIP4Address *addr;
		addr = g_new0 (NMSettingIP4Address, 1);
		memcpy (addr, &tmp, sizeof (NMSettingIP4Address));
		s_ip4->addresses = g_slist_append (s_ip4->addresses, addr);
	}

	s_ip4->dns = g_array_sized_new (FALSE, TRUE, sizeof (guint32), 3);

	GET_ONE_DNS("DNS1");
	GET_ONE_DNS("DNS2");
	GET_ONE_DNS("DNS3");

	if (s_ip4->dns && !s_ip4->dns->len) {
		g_array_free (s_ip4->dns, TRUE);
		s_ip4->dns = NULL;
	}

	/* DNS searches */
	value = svGetValue (ifcfg, "SEARCH");
	if (value) {
		char **searches = NULL;

		searches = g_strsplit (value, " ", 0);
		if (searches) {
			char **item;
			for (item = searches; *item; item++)
				s_ip4->dns_search = g_slist_append (s_ip4->dns_search, *item);
			g_free (searches);
		}
		g_free (value);
	}

	return NM_SETTING (s_ip4);

error:
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

static gboolean
read_mac_address (shvarFile *ifcfg, GByteArray **array, GError **error)
{
	char *value = NULL;
	struct ether_addr *mac;

	g_return_val_if_fail (ifcfg != NULL, FALSE);
	g_return_val_if_fail (array != NULL, FALSE);
	g_return_val_if_fail (*array == NULL, FALSE);
	g_return_val_if_fail (error != NULL, FALSE);
	g_return_val_if_fail (*error == NULL, FALSE);

	value = svGetValue (ifcfg, "HWADDR");
	if (!value || !strlen (value)) {
		g_free (value);
		return TRUE;
	}

	mac = ether_aton (value);
	if (!mac) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "The MAC address '%s' was invalid.", value);
		goto error;
	}

	g_free (value);
	*array = g_byte_array_sized_new (ETH_ALEN);
	g_byte_array_append (*array, (guint8 *) mac->ether_addr_octet, ETH_ALEN);

	return TRUE;

error:
	g_free (value);
	if (*array) {
		g_byte_array_free (*array, TRUE);
		*array = NULL;
	}
	return FALSE;
}

static gboolean
add_one_wep_key (shvarFile *ifcfg,
                 const char *shvar_key,
                 guint8 key_idx,
                 NMSettingWirelessSecurity *s_wsec,
                 GError **error)
{
	char *key = NULL;
	char *value = NULL;
	gboolean success = FALSE;

	g_return_val_if_fail (ifcfg != NULL, FALSE);
	g_return_val_if_fail (shvar_key != NULL, FALSE);
	g_return_val_if_fail (key_idx <= 3, FALSE);
	g_return_val_if_fail (s_wsec != NULL, FALSE);

	value = svGetValue (ifcfg, shvar_key);
	if (!value || !strlen (value)) {
		g_free (value);
		return TRUE;
	}

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
	} else if (   strncmp (value, "s:", 2)
	           && (strlen (value) == 7 || strlen (value) == 15)) {
		/* ASCII passphrase */
		char *p = value + 2;

		while (*p) {
			if (!isascii ((int) (*p))) {
				g_set_error (error, ifcfg_plugin_error_quark (), 0,
				             "Invalid ASCII WEP passphrase.");
				goto out;
			}
			p++;
		}

		key = utils_bin2hexstr (value, strlen (value), strlen (value) * 2);
	} else {
		g_set_error (error, ifcfg_plugin_error_quark (), 0, "Invalid WEP key length.");
	}

	if (key) {
		if (key_idx == 0)
			s_wsec->wep_key0 = key;
		else if (key_idx == 1)
			s_wsec->wep_key1 = key;
		else if (key_idx == 2)
			s_wsec->wep_key2 = key;
		else if (key_idx == 3)
			s_wsec->wep_key3 = key;
		else
			g_assert_not_reached ();
		success = TRUE;
	}

out:
	g_free (value);
	return success;
}

static char *
get_keys_file_path (const char *parent)
{
	char *ifcfg_name;
	char *keys_file = NULL;
	char *tmp = NULL;

	ifcfg_name = get_ifcfg_name (parent);
	if (!ifcfg_name)
		return NULL;

	tmp = g_path_get_dirname (parent);
	if (!tmp)
		goto out;

	keys_file = g_strdup_printf ("%s/" KEYS_TAG "%s", tmp, ifcfg_name);

out:
	g_free (tmp);
	g_free (ifcfg_name);
	return keys_file;
}

static shvarFile *
get_keys_ifcfg (const char *parent)
{
	shvarFile *ifcfg = NULL;
	char *keys_file;

	keys_file = get_keys_file_path (parent);
	if (!keys_file)
		return NULL;

	ifcfg = svNewFile (keys_file);
	g_free (keys_file);
	return ifcfg;
}

static gboolean
read_wep_keys (shvarFile *ifcfg,
               guint8 def_idx,
               NMSettingWirelessSecurity *s_wsec,
               GError **error)
{
	if (!add_one_wep_key (ifcfg, "KEY1", 0, s_wsec, error))
		return FALSE;
	if (!add_one_wep_key (ifcfg, "KEY2", 1, s_wsec, error))
		return FALSE;
	if (!add_one_wep_key (ifcfg, "KEY3", 2, s_wsec, error))
		return FALSE;
	if (!add_one_wep_key (ifcfg, "KEY4", 3, s_wsec, error))
		return FALSE;
	if (!add_one_wep_key (ifcfg, "KEY", def_idx, s_wsec, error))
		return FALSE;

	return TRUE;
}

static NMSetting *
make_wireless_security_setting (shvarFile *ifcfg,
                                const char *file,
                                GError **error)
{
	NMSettingWirelessSecurity *s_wireless_sec;
	char *value;
	shvarFile *keys_ifcfg = NULL;
	int default_key_idx = 0;

	s_wireless_sec = NM_SETTING_WIRELESS_SECURITY (nm_setting_wireless_security_new ());

	value = svGetValue (ifcfg, "DEFAULTKEY");
	if (value) {
		gboolean success;

		success = get_int (value, &default_key_idx);
		if (success && (default_key_idx >= 1) && (default_key_idx <= 4)) {
			default_key_idx--;  /* convert to [0...3] */
			s_wireless_sec->wep_tx_keyidx = default_key_idx;
		} else {
			g_set_error (error, ifcfg_plugin_error_quark (), 0,
			             "Invalid default WEP key '%s'", value);
	 		g_free (value);
			goto error;
		}
 		g_free (value);
	}

	/* Read keys in the ifcfg file */
	if (!read_wep_keys (ifcfg, default_key_idx, s_wireless_sec, error))
		goto error;

	/* Try to get keys from the "shadow" key file */
	keys_ifcfg = get_keys_ifcfg (file);
	if (keys_ifcfg) {
		if (!read_wep_keys (keys_ifcfg, default_key_idx, s_wireless_sec, error)) {
			svCloseFile (keys_ifcfg);
			goto error;
		}
		svCloseFile (keys_ifcfg);
	}

	/* If there's a default key, ensure that key exists */
	if ((default_key_idx == 1) && !s_wireless_sec->wep_key1) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Default WEP key index was 2, but no valid KEY2 exists.");
		goto error;
	} else if ((default_key_idx == 2) && !s_wireless_sec->wep_key2) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Default WEP key index was 3, but no valid KEY3 exists.");
		goto error;
	} else if ((default_key_idx == 3) && !s_wireless_sec->wep_key3) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Default WEP key index was 4, but no valid KEY4 exists.");
		goto error;
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

	if (   !s_wireless_sec->wep_key0
	    && !s_wireless_sec->wep_key1
	    && !s_wireless_sec->wep_key2
	    && !s_wireless_sec->wep_key3
	    && !s_wireless_sec->wep_tx_keyidx) {
		if (s_wireless_sec->auth_alg && !strcmp (s_wireless_sec->auth_alg, "shared")) {
			g_set_error (error, ifcfg_plugin_error_quark (), 0,
			             "WEP Shared Key authentication is invalid for "
			             "unencrypted connections.");
			goto error;
		}

		/* Unencrypted */
		g_object_unref (s_wireless_sec);
		s_wireless_sec = NULL;
	} else {
		// FIXME: WEP-only for now
		s_wireless_sec->key_mgmt = g_strdup ("none");
	}

	return (NMSetting *) s_wireless_sec;

error:
	if (s_wireless_sec)
		g_object_unref (s_wireless_sec);
	return NULL;
}


static NMSetting *
make_wireless_setting (shvarFile *ifcfg,
                       NMSetting *security,
                       gboolean unmanaged,
                       GError **error)
{
	NMSettingWireless *s_wireless;
	char *value;

	s_wireless = NM_SETTING_WIRELESS (nm_setting_wireless_new ());

	if (!read_mac_address (ifcfg, &s_wireless->mac_address, error)) {
		g_object_unref (s_wireless);
		return NULL;
	}

	value = svGetValue (ifcfg, "ESSID");
	if (value) {
		gsize len = strlen (value);

		if (len > 32 || len == 0) {
			g_set_error (error, ifcfg_plugin_error_quark (), 0,
			             "Invalid SSID '%s' (size %zu not between 1 and 32 inclusive)",
			             value, len);
			g_free (value);
			goto error;
		}

		s_wireless->ssid = g_byte_array_sized_new (strlen (value));
		g_byte_array_append (s_wireless->ssid, (const guint8 *) value, len);
		g_free (value);
	} else {
		/* Only fail on lack of SSID if device is managed */
		if (!unmanaged) {
			g_set_error (error, ifcfg_plugin_error_quark (), 0, "Missing SSID");
			goto error;
		}
	}

	if (!unmanaged) {
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
	}

	return NM_SETTING (s_wireless);

error:
	if (s_wireless)
		g_object_unref (s_wireless);
	return NULL;
}

static NMConnection *
wireless_connection_from_ifcfg (const char *file,
                                shvarFile *ifcfg,
                                gboolean unmanaged,
                                GError **error)
{
	NMConnection *connection = NULL;
	NMSetting *con_setting = NULL;
	NMSetting *wireless_setting = NULL;
	NMSettingWireless *s_wireless;
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
	security_setting = make_wireless_security_setting (ifcfg, file, error);
	if (*error) {
		g_object_unref (connection);
		return NULL;
	}
	if (security_setting)
		nm_connection_add_setting (connection, security_setting);

	/* Wireless */
	wireless_setting = make_wireless_setting (ifcfg, security_setting, unmanaged, error);
	if (!wireless_setting) {
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, wireless_setting);

	s_wireless = (NMSettingWireless *) wireless_setting;
	if (s_wireless && s_wireless->ssid) {
		printable_ssid = nm_utils_ssid_to_utf8 ((const char *) s_wireless->ssid->data,
		                                        (guint32) s_wireless->ssid->len);
	} else
		printable_ssid = g_strdup_printf ("unmanaged");

	con_setting = make_connection_setting (file, ifcfg,
	                                       NM_SETTING_WIRELESS_SETTING_NAME,
	                                       printable_ssid);
	g_free (printable_ssid);
	if (!con_setting) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Failed to create connection setting.");
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, con_setting);

	/* Don't verify if unmanaged since we may not have an SSID or whatever */
	if (!unmanaged) {
		if (!nm_connection_verify (connection, error)) {
			g_object_unref (connection);
			return NULL;
		}
	}

	return connection;
}

static NMSetting *
make_wired_setting (shvarFile *ifcfg, gboolean unmanaged, GError **error)
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
			/* Shouldn't be fatal... */
			PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "    warning: invalid MTU '%s'", value);
		}
		g_free (value);
	}

	if (!read_mac_address (ifcfg, &s_wired->mac_address, error)) {
		g_object_unref (s_wired);
		s_wired = NULL;
	}

	return (NMSetting *) s_wired;
}

static NMConnection *
wired_connection_from_ifcfg (const char *file,
                             shvarFile *ifcfg,
                             gboolean unmanaged,
                             GError **error)
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
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, con_setting);

	wired_setting = make_wired_setting (ifcfg, unmanaged, error);
	if (!wired_setting) {
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, wired_setting);

	if (!nm_connection_verify (connection, error)) {
		g_object_unref (connection);
		return NULL;
	}

	return connection;
}

static gboolean
is_wireless_device (const char *iface, gboolean *is_wireless)
{
	int fd;
	struct iw_range range;
	struct iwreq wrq;
	gboolean success = FALSE;

	g_return_val_if_fail (iface != NULL, FALSE);
	g_return_val_if_fail (is_wireless != NULL, FALSE);

	*is_wireless = FALSE;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (!fd)
		return FALSE;

	memset (&wrq, 0, sizeof (struct iwreq));
	memset (&range, 0, sizeof (struct iw_range));
	strncpy (wrq.ifr_name, iface, IFNAMSIZ);
	wrq.u.data.pointer = (caddr_t) &range;
	wrq.u.data.length = sizeof (struct iw_range);

	if (ioctl (fd, SIOCGIWRANGE, &wrq) < 0) {
		if (errno == EOPNOTSUPP)
			success = TRUE;
		goto out;
	}

	*is_wireless = TRUE;
	success = TRUE;

out:
	close (fd);
	return success;
}

NMConnection *
connection_from_file (const char *filename,
                      gboolean *ignored,
                      char **keyfile,
                      GError **error)
{
	NMConnection *connection = NULL;
	shvarFile *parsed;
	char *type;
	char *nmc = NULL;
	NMSetting *s_ip4;
	char *ifcfg_name = NULL;

	g_return_val_if_fail (filename != NULL, NULL);
	g_return_val_if_fail (ignored != NULL, NULL);
	g_return_val_if_fail (keyfile != NULL, NULL);
	g_return_val_if_fail (*keyfile == NULL, NULL);

	ifcfg_name = get_ifcfg_name (filename);
	if (!ifcfg_name) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Ignoring connection '%s' because it's not an ifcfg file.", filename);
		return NULL;
	}
	g_free (ifcfg_name);

	parsed = svNewFile (filename);
	if (!parsed) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Couldn't parse file '%s'", filename);
		return NULL;
	}

	type = svGetValue (parsed, "TYPE");
	if (!type) {
		char *device;
		gboolean is_wireless = FALSE;

		/* If no type, if the device has wireless extensions, it's wifi,
		 * otherwise it's ethernet.
		 */
		device = svGetValue (parsed, "DEVICE");
		if (!device) {
			g_set_error (error, ifcfg_plugin_error_quark (), 0,
			             "File '%s' had neither TYPE nor DEVICE keys.", filename);
			goto done;
		}

		if (!strcmp (device, "lo")) {
			g_set_error (error, ifcfg_plugin_error_quark (), 0,
			             "Ignoring loopback device config.");
			g_free (device);
			goto done;
		}

		/* Test wireless extensions */
		if (!is_wireless_device (device, &is_wireless)) {
			g_set_error (error, ifcfg_plugin_error_quark (), 0,
			             "File '%s' specified device '%s', but the device's "
			             "type could not be determined.", filename, device);
			g_free (device);
			goto done;
		}

		if (is_wireless)
			type = g_strdup (TYPE_WIRELESS);
		else
			type = g_strdup (TYPE_ETHERNET);

		g_free (device);
	}

	nmc = svGetValue (parsed, "NM_CONTROLLED");
	if (nmc) {
		char *lower;

		lower = g_ascii_strdown (nmc, -1);
		g_free (nmc);

		if (!strcmp (lower, "no") || !strcmp (lower, "n") || !strcmp (lower, "false"))
			*ignored = TRUE;
		g_free (lower);
	}

	if (!strcmp (type, TYPE_ETHERNET))
		connection = wired_connection_from_ifcfg (filename, parsed, *ignored, error);
	else if (!strcmp (type, TYPE_WIRELESS))
		connection = wireless_connection_from_ifcfg (filename, parsed, *ignored, error);
	else {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Unknown connection type '%s'", type);
	}

	g_free (type);

	/* Don't bother reading the connection fully if it's unmanaged */
	if (!connection || *ignored)
		goto done;

	s_ip4 = make_ip4_setting (parsed, error);
	if (*error) {
		g_object_unref (connection);
		connection = NULL;
		goto done;
	} else if (s_ip4) {
		nm_connection_add_setting (connection, s_ip4);
	}

	if (!nm_connection_verify (connection, error)) {
		g_object_unref (connection);
		connection = NULL;
	}

	*keyfile = get_keys_file_path (filename);

done:
	svCloseFile (parsed);
	return connection;
}


