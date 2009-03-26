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
 * Copyright (C) 2008 - 2009 Red Hat, Inc.
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
#include <glib/gi18n.h>
#include <nm-connection.h>
#include <NetworkManager.h>
#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>
#include <nm-setting-wired.h>
#include <nm-setting-wireless.h>
#include <nm-setting-8021x.h>
#include <nm-utils.h>

#include "common.h"
#include "shvar.h"
#include "sha1.h"
#include "utils.h"

#include "reader.h"

#define PLUGIN_PRINT(pname, fmt, args...) \
	{ g_message ("   " pname ": " fmt, ##args); }

#define PLUGIN_WARN(pname, fmt, args...) \
	{ g_warning ("   " pname ": " fmt, ##args); }

static gboolean eap_simple_reader (const char *eap_method,
                                   shvarFile *ifcfg,
                                   shvarFile *keys,
                                   NMSetting8021x *s_8021x,
                                   gboolean phase2,
                                   GError **error);

static gboolean eap_tls_reader (const char *eap_method,
                                shvarFile *ifcfg,
                                shvarFile *keys,
                                NMSetting8021x *s_8021x,
                                gboolean phase2,
                                GError **error);

static gboolean eap_peap_reader (const char *eap_method,
                                 shvarFile *ifcfg,
                                 shvarFile *keys,
                                 NMSetting8021x *s_8021x,
                                 gboolean phase2,
                                 GError **error);

static gboolean eap_ttls_reader (const char *eap_method,
                                 shvarFile *ifcfg,
                                 shvarFile *keys,
                                 NMSetting8021x *s_8021x,
                                 gboolean phase2,
                                 GError **error);


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
	char *new_id = NULL, *uuid = NULL, *value;
	char *ifcfg_id;

	ifcfg_name = utils_get_ifcfg_name (file);
	if (!ifcfg_name)
		return NULL;

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());

	/* Try the ifcfg file's internally defined name if available */
	ifcfg_id = svGetValue (ifcfg, "NAME", FALSE);
	if (ifcfg_id && strlen (ifcfg_id))
		g_object_set (s_con, NM_SETTING_CONNECTION_ID, ifcfg_id, NULL);

	if (!nm_setting_connection_get_id (s_con)) {
		if (suggested) {
			/* For cosmetic reasons, if the suggested name is the same as
			 * the ifcfg files name, don't use it.  Mainly for wifi so that
			 * the SSID is shown in the connection ID instead of just "wlan0".
			 */
			if (strcmp (ifcfg_name, suggested)) {
				new_id = g_strdup_printf ("%s %s (%s)", reader_get_prefix (), suggested, ifcfg_name);
				g_object_set (s_con, NM_SETTING_CONNECTION_ID, new_id, NULL);
			}
		}

		/* Use the ifcfg file's name as a last resort */
		if (!nm_setting_connection_get_id (s_con)) {
			new_id = g_strdup_printf ("%s %s", reader_get_prefix (), ifcfg_name);
			g_object_set (s_con, NM_SETTING_CONNECTION_ID, new_id, NULL);
		}
	}

	g_free (new_id);
	g_free (ifcfg_id);

	/* Try for a UUID key before falling back to hashing the file name */
	uuid = svGetValue (ifcfg, "UUID", FALSE);
	if (!uuid || !strlen (uuid)) {
		g_free (uuid);
		uuid = nm_utils_uuid_generate_from_string (ifcfg->fileName);
	}
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_TYPE, type,
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NULL);
	g_free (uuid);

	/* Missing ONBOOT is treated as "ONBOOT=true" by the old network service */
	g_object_set (s_con, NM_SETTING_CONNECTION_AUTOCONNECT,
	              svTrueValue (ifcfg, "ONBOOT", TRUE),
	              NULL);

	value = svGetValue (ifcfg, "LAST_CONNECT", FALSE);
	if (value) {
		unsigned long int tmp;

		errno = 0;
		tmp = strtoul (value, NULL, 10);
		if (errno == 0)
			g_object_set (s_con, NM_SETTING_CONNECTION_TIMESTAMP, tmp, NULL);
		else
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: invalid LAST_CONNECT time");
		g_free (value);
	}

	g_free (ifcfg_name);
	return NM_SETTING (s_con);
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
	g_return_if_fail (*out_addr == 0);
	g_return_if_fail (error != NULL);
	g_return_if_fail (*error == NULL);

	value = svGetValue (ifcfg, tag, FALSE);
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
		if (dns) { \
			if (!nm_setting_ip4_config_add_dns (s_ip4, dns)) \
				PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: duplicate DNS server %s", tag); \
		} \
	}
		

static NMSetting *
make_ip4_setting (shvarFile *ifcfg, const char *network_file, GError **error)
{
	NMSettingIP4Config *s_ip4 = NULL;
	char *value = NULL;
	NMIP4Address *addr = NULL;
	char *method = NM_SETTING_IP4_CONFIG_METHOD_MANUAL;
	guint32 netmask = 0, tmp = 0;
	shvarFile *network_ifcfg;
	gboolean never_default = FALSE;

	network_ifcfg = svNewFile (network_file);
	if (network_ifcfg) {
		char *gatewaydev;

		/* Get the connection ifcfg device name and the global gateway device */
		value = svGetValue (ifcfg, "DEVICE", FALSE);
		gatewaydev = svGetValue (network_ifcfg, "GATEWAYDEV", FALSE);

		/* If there was a global gateway device specified, then only connections
		 * for that device can be the default connection.
		 */
		if (gatewaydev && value && strcmp (value, gatewaydev))
			never_default = TRUE;

		g_free (gatewaydev);
		g_free (value);
		svCloseFile (network_ifcfg);
	}

	value = svGetValue (ifcfg, "BOOTPROTO", FALSE);
	if (value) {
		if (!g_ascii_strcasecmp (value, "bootp") || !g_ascii_strcasecmp (value, "dhcp"))
			method = NM_SETTING_IP4_CONFIG_METHOD_AUTO;
		else if (!g_ascii_strcasecmp (value, "autoip")) {
			g_free (value);
			s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
			g_object_set (s_ip4,
			              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL,
			              NM_SETTING_IP4_CONFIG_NEVER_DEFAULT, never_default,
			              NULL);
			return NM_SETTING (s_ip4);
		} else if (!g_ascii_strcasecmp (value, "shared")) {
			g_free (value);
			s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
			g_object_set (s_ip4,
			              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_SHARED,
			              NM_SETTING_IP4_CONFIG_NEVER_DEFAULT, never_default,
			              NULL);
			return NM_SETTING (s_ip4);
		}
		g_free (value);
	} else {
		char *tmp_ip4, *tmp_prefix, *tmp_netmask;

		/* If there is no BOOTPROTO, no IPADDR, no PREFIX, and no NETMASK,
		 * assume DHCP is to be used.  Happens with minimal ifcfg files like:
		 *
		 * DEVICE=eth0
		 * HWADDR=11:22:33:44:55:66
		 *
		 */
		tmp_ip4 = svGetValue (ifcfg, "IPADDR", FALSE);
		tmp_prefix = svGetValue (ifcfg, "PREFIX", FALSE);
		tmp_netmask = svGetValue (ifcfg, "NETMASK", FALSE);
		if (!tmp_ip4 && !tmp_prefix && !tmp_netmask)
			method = NM_SETTING_IP4_CONFIG_METHOD_AUTO;
		g_free (tmp_ip4);
		g_free (tmp_prefix);
		g_free (tmp_netmask);
	}

	/* Handle manual settings */
	if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_MANUAL)) {
		addr = nm_ip4_address_new ();

		tmp = 0;
		get_one_ip4_addr (ifcfg, "IPADDR", &tmp, error);
		if (*error)
			goto error;
		nm_ip4_address_set_address (addr, tmp);

		tmp = 0;
		get_one_ip4_addr (ifcfg, "GATEWAY", &tmp, error);
		if (*error)
			goto error;
		nm_ip4_address_set_gateway (addr, tmp);

		/* If no gateway in the ifcfg, try /etc/sysconfig/network instead */
		if (!nm_ip4_address_get_gateway (addr)) {
			network_ifcfg = svNewFile (network_file);
			if (network_ifcfg) {
				tmp = 0;
				get_one_ip4_addr (network_ifcfg, "GATEWAY", &tmp, error);
				svCloseFile (network_ifcfg);
				if (*error)
					goto error;
				nm_ip4_address_set_gateway (addr, tmp);
			}
		}

		value = svGetValue (ifcfg, "PREFIX", FALSE);
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
			nm_ip4_address_set_prefix (addr, (guint32) prefix);
			g_free (value);
		}

		/* Fall back to NETMASK if no PREFIX was specified */
		if (!nm_ip4_address_get_prefix (addr)) {
			netmask = 0;
			get_one_ip4_addr (ifcfg, "NETMASK", &netmask, error);
			if (*error)
				goto error;
			nm_ip4_address_set_prefix (addr, nm_utils_ip4_netmask_to_prefix (netmask));
		}

		/* Validate the prefix */
		if (  !nm_ip4_address_get_prefix (addr)
		    || nm_ip4_address_get_prefix (addr) > 32) {
			g_set_error (error, ifcfg_plugin_error_quark (), 0,
			             "Missing or invalid IP4 prefix '%d'",
			             nm_ip4_address_get_prefix (addr));
			goto error;
		}
	}

	/* Yay, let's make an IP4 config */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	g_object_set (s_ip4,
	              NM_SETTING_IP4_CONFIG_METHOD, method,
	              NM_SETTING_IP4_CONFIG_IGNORE_AUTO_DNS, !svTrueValue (ifcfg, "PEERDNS", 1),
	              NM_SETTING_IP4_CONFIG_NEVER_DEFAULT, never_default,
	              NULL);

	/* DHCP hostname for 'send host-name' option */
	if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_AUTO)) {
		value = svGetValue (ifcfg, "DHCP_HOSTNAME", FALSE);
		if (value && strlen (value))
			g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_DHCP_HOSTNAME, value, NULL);
		g_free (value);
	}

	if (addr) {
		if (!nm_setting_ip4_config_add_address (s_ip4, addr))
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: duplicate IP4 address");
	}

	GET_ONE_DNS("DNS1");
	GET_ONE_DNS("DNS2");
	GET_ONE_DNS("DNS3");

	/* DNS searches */
	value = svGetValue (ifcfg, "DOMAIN", FALSE);
	if (value) {
		char **searches = NULL;

		searches = g_strsplit (value, " ", 0);
		if (searches) {
			char **item;
			for (item = searches; *item; item++) {
				if (strlen (*item)) {
					if (!nm_setting_ip4_config_add_dns_search (s_ip4, *item))
						PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: duplicate DNS domain '%s'", *item);
				}
			}
			g_strfreev (searches);
		}
		g_free (value);
	}

	/* Legacy value NM used for a while but is incorrect (rh #459370) */
	if (!nm_setting_ip4_config_get_num_dns_searches (s_ip4)) {
		value = svGetValue (ifcfg, "SEARCH", FALSE);
		if (value) {
			char **searches = NULL;

			searches = g_strsplit (value, " ", 0);
			if (searches) {
				char **item;
				for (item = searches; *item; item++) {
					if (strlen (*item)) {
						if (!nm_setting_ip4_config_add_dns_search (s_ip4, *item))
							PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: duplicate DNS search '%s'", *item);
					}
				}
				g_strfreev (searches);
			}
			g_free (value);
		}
	}

	if (addr)
		nm_ip4_address_unref (addr);

	return NM_SETTING (s_ip4);

error:
	if (addr)
		nm_ip4_address_unref (addr);
	if (s_ip4)
		g_object_unref (s_ip4);
	return NULL;
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

	value = svGetValue (ifcfg, "HWADDR", FALSE);
	if (!value || !strlen (value)) {
		g_free (value);
		return TRUE;
	}

	mac = ether_aton (value);
	if (!mac) {
		g_free (value);
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "The MAC address '%s' was invalid.", value);
		return FALSE;
	}

	g_free (value);
	*array = g_byte_array_sized_new (ETH_ALEN);
	g_byte_array_append (*array, (guint8 *) mac->ether_addr_octet, ETH_ALEN);
	return TRUE;
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

	value = svGetValue (ifcfg, shvar_key, FALSE);
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
		nm_setting_wireless_security_set_wep_key (s_wsec, key_idx, key);
		success = TRUE;
	}

out:
	g_free (value);
	return success;
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
make_wep_setting (shvarFile *ifcfg,
                  const char *file,
                  GError **error)
{
	NMSettingWirelessSecurity *s_wireless_sec;
	char *value;
	shvarFile *keys_ifcfg = NULL;
	int default_key_idx = 0;

	s_wireless_sec = NM_SETTING_WIRELESS_SECURITY (nm_setting_wireless_security_new ());
	g_object_set (s_wireless_sec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "none", NULL);

	value = svGetValue (ifcfg, "DEFAULTKEY", FALSE);
	if (value) {
		gboolean success;

		success = get_int (value, &default_key_idx);
		if (success && (default_key_idx >= 1) && (default_key_idx <= 4)) {
			default_key_idx--;  /* convert to [0...3] */
			g_object_set (s_wireless_sec, NM_SETTING_WIRELESS_SECURITY_WEP_TX_KEYIDX, default_key_idx, NULL);
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
	keys_ifcfg = utils_get_keys_ifcfg (file, FALSE);
	if (keys_ifcfg) {
		if (!read_wep_keys (keys_ifcfg, default_key_idx, s_wireless_sec, error)) {
			svCloseFile (keys_ifcfg);
			goto error;
		}
		svCloseFile (keys_ifcfg);
	}

	/* If there's a default key, ensure that key exists */
	if ((default_key_idx == 1) && !nm_setting_wireless_security_get_wep_key (s_wireless_sec, 1)) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Default WEP key index was 2, but no valid KEY2 exists.");
		goto error;
	} else if ((default_key_idx == 2) && !nm_setting_wireless_security_get_wep_key (s_wireless_sec, 2)) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Default WEP key index was 3, but no valid KEY3 exists.");
		goto error;
	} else if ((default_key_idx == 3) && !nm_setting_wireless_security_get_wep_key (s_wireless_sec, 3)) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Default WEP key index was 4, but no valid KEY4 exists.");
		goto error;
	}

	value = svGetValue (ifcfg, "SECURITYMODE", FALSE);
	if (value) {
		char *lcase;

		lcase = g_ascii_strdown (value, -1);
		g_free (value);

		if (!strcmp (lcase, "open")) {
			g_object_set (s_wireless_sec, NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "open", NULL);
		} else if (!strcmp (lcase, "restricted")) {
			g_object_set (s_wireless_sec, NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "shared", NULL);
		} else {
			g_set_error (error, ifcfg_plugin_error_quark (), 0,
			             "Invalid WEP authentication algorithm '%s'",
			             lcase);
			g_free (lcase);
			goto error;
		}
		g_free (lcase);
	}

	if (   !nm_setting_wireless_security_get_wep_key (s_wireless_sec, 0)
	    && !nm_setting_wireless_security_get_wep_key (s_wireless_sec, 1)
	    && !nm_setting_wireless_security_get_wep_key (s_wireless_sec, 2)
	    && !nm_setting_wireless_security_get_wep_key (s_wireless_sec, 3)
	    && !nm_setting_wireless_security_get_wep_tx_keyidx (s_wireless_sec)) {
		const char *auth_alg;

		auth_alg = nm_setting_wireless_security_get_auth_alg (s_wireless_sec);
		if (auth_alg && !strcmp (auth_alg, "shared")) {
			g_set_error (error, ifcfg_plugin_error_quark (), 0,
			             "WEP Shared Key authentication is invalid for "
			             "unencrypted connections.");
			goto error;
		}

		/* Unencrypted */
		g_object_unref (s_wireless_sec);
		s_wireless_sec = NULL;
	}

	return (NMSetting *) s_wireless_sec;

error:
	if (s_wireless_sec)
		g_object_unref (s_wireless_sec);
	return NULL;
}

static gboolean
fill_wpa_ciphers (shvarFile *ifcfg,
                  NMSettingWirelessSecurity *wsec,
                  gboolean group,
                  gboolean adhoc)
{
	char *value = NULL, *p;
	char **list = NULL, **iter;
	int i = 0;

	p = value = svGetValue (ifcfg, group ? "CIPHER_GROUP" : "CIPHER_PAIRWISE", TRUE);
	if (!value)
		return TRUE;

	/* Strip quotes */
	if (p[0] == '"')
		p++;
	if (p[strlen (p) - 1] == '"')
		p[strlen (p) - 1] = '\0';

	list = g_strsplit_set (p, " ", 0);
	for (iter = list; iter && *iter; iter++, i++) {
		/* Ad-Hoc configurations cannot have pairwise ciphers, and can only
		 * have one group cipher.  Ignore any additional group ciphers and
		 * any pairwise ciphers specified.
		 */
		if (adhoc) {
			if (group && (i > 0)) {
				PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: ignoring group cipher '%s' (only one group cipher allowed in Ad-Hoc mode)",
				             *iter);
				continue;
			} else if (!group) {
				PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: ignoring pairwise cipher '%s' (pairwise not used in Ad-Hoc mode)",
				             *iter);
				continue;
			}
		}

		if (!strcmp (*iter, "CCMP")) {
			if (group)
				nm_setting_wireless_security_add_group (wsec, "ccmp");
			else
				nm_setting_wireless_security_add_pairwise (wsec, "ccmp");
		} else if (!strcmp (*iter, "TKIP")) {
			if (group)
				nm_setting_wireless_security_add_group (wsec, "tkip");
			else
				nm_setting_wireless_security_add_pairwise (wsec, "tkip");
		} else if (group && !strcmp (*iter, "WEP104"))
			nm_setting_wireless_security_add_group (wsec, "wep104");
		else if (group && !strcmp (*iter, "WEP40"))
			nm_setting_wireless_security_add_group (wsec, "wep40");
		else {
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: ignoring invalid %s cipher '%s'",
			             group ? "CIPHER_GROUP" : "CIPHER_PAIRWISE",
			             *iter);
		}
	}

	if (list)
		g_strfreev (list);
	g_free (value);
	return TRUE;
}

#define WPA_PMK_LEN 32

static char *
parse_wpa_psk (shvarFile *ifcfg,
               const char *file,
               const GByteArray *ssid,
               GError **error)
{
	shvarFile *keys_ifcfg;
	char *psk = NULL, *p, *hashed = NULL;

	/* Passphrase must be between 10 and 66 characters in length becuase WPA
	 * hex keys are exactly 64 characters (no quoting), and WPA passphrases
	 * are between 8 and 63 characters (inclusive), plus optional quoting if
	 * the passphrase contains spaces.
	 */

	/* Try to get keys from the "shadow" key file */
	keys_ifcfg = utils_get_keys_ifcfg (file, FALSE);
	if (keys_ifcfg) {
		psk = svGetValue (keys_ifcfg, "WPA_PSK", TRUE);
		svCloseFile (keys_ifcfg);
	}

	/* Fall back to the original ifcfg */
	if (!psk)
		psk = svGetValue (ifcfg, "WPA_PSK", TRUE);

	if (!psk) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Missing WPA_PSK for WPA-PSK key management");
		return NULL;
	}

	p = psk;
	if (p[0] == '"' && psk[strlen (psk) - 1] == '"') {
		unsigned char *buf;

		/* Get rid of the quotes */
		p++;
		p[strlen (p) - 1] = '\0';

		/* Length check */
		if (strlen (p) < 8 || strlen (p) > 63) {
			g_set_error (error, ifcfg_plugin_error_quark (), 0,
			             "Invalid WPA_PSK (passphrases must be between "
			             "8 and 63 characters long (inclusive))");
			goto out;
		}

		/* hash the passphrase to a hex key */
		buf = g_malloc0 (WPA_PMK_LEN * 2);
		pbkdf2_sha1 (p, (char *) ssid->data, ssid->len, 4096, buf, WPA_PMK_LEN);
		hashed = utils_bin2hexstr ((const char *) buf, WPA_PMK_LEN, WPA_PMK_LEN * 2);
		g_free (buf);
	} else if (strlen (psk) == 64) {
		/* Verify the hex PSK; 64 digits */
		while (*p) {
			if (!isxdigit (*p++)) {
				g_set_error (error, ifcfg_plugin_error_quark (), 0,
				             "Invalid WPA_PSK (contains non-hexadecimal characters)");
				goto out;
			}
		}
		hashed = g_strdup (psk);
	} else {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Invalid WPA_PSK (doesn't look like a passphrase or hex key)");
		goto out;
	}

out:
	g_free (psk);
	return hashed;
}

typedef struct {
	const char *method;
	gboolean (*reader)(const char *eap_method,
	                   shvarFile *ifcfg,
	                   shvarFile *keys,
	                   NMSetting8021x *s_8021x,
	                   gboolean phase2,
	                   GError **error);
	gboolean wifi_phase2_only;
} EAPReader;

static EAPReader eap_readers[] = {
	{ "md5", eap_simple_reader, TRUE },
	{ "pap", eap_simple_reader, TRUE },
	{ "chap", eap_simple_reader, TRUE },
	{ "mschap", eap_simple_reader, TRUE },
	{ "mschapv2", eap_simple_reader, TRUE },
	{ "leap", eap_simple_reader, TRUE },
	{ "tls", eap_tls_reader, FALSE },
	{ "peap", eap_peap_reader, FALSE },
	{ "ttls", eap_ttls_reader, FALSE },
	{ NULL, NULL }
};

static gboolean
eap_simple_reader (const char *eap_method,
                   shvarFile *ifcfg,
                   shvarFile *keys,
                   NMSetting8021x *s_8021x,
                   gboolean phase2,
                   GError **error)
{
	char *value;

	value = svGetValue (ifcfg, "IEEE_8021X_IDENTITY", FALSE);
	if (!value) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Missing IEEE_8021X_IDENTITY for EAP method '%s'.",
		             eap_method);
		return FALSE;
	}
	g_object_set (s_8021x, NM_SETTING_802_1X_IDENTITY, value, NULL);
	g_free (value);

	value = svGetValue (ifcfg, "IEEE_8021X_PASSWORD", FALSE);
	if (!value && keys) {
		/* Try the lookaside keys file */
		value = svGetValue (keys, "IEEE_8021X_PASSWORD", FALSE);
	}

	if (!value) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Missing IEEE_8021X_PASSWORD for EAP method '%s'.",
		             eap_method);
		return FALSE;
	}

	g_object_set (s_8021x, NM_SETTING_802_1X_PASSWORD, value, NULL);
	g_free (value);

	return TRUE;
}

static char *
get_cert_file (const char *ifcfg_path, const char *cert_path)
{
	const char *basename = cert_path;
	char *p, *ret, *dirname;

	g_return_val_if_fail (ifcfg_path != NULL, NULL);
	g_return_val_if_fail (cert_path != NULL, NULL);

	if (cert_path[0] == '/')
		return g_strdup (cert_path);

	p = strrchr (cert_path, '/');
	if (p)
		basename = p + 1;

	dirname = g_path_get_dirname (ifcfg_path);
	ret = g_build_path ("/", dirname, basename, NULL);
	g_free (dirname);
	return ret;
}

static void
set_file_path (NMSetting8021x *s_8021x,
               const char *path_tag,
               const char *hash_tag,
               const char *path,
               const char *setting_key)
{
	GByteArray *data = NULL;

	g_object_set_data_full (G_OBJECT (s_8021x), path_tag, g_strdup (path), g_free);
	g_object_get (G_OBJECT (s_8021x), setting_key, &data, NULL);
	if (data)
		g_object_set_data_full (G_OBJECT (s_8021x), hash_tag, utils_hash_byte_array (data), g_free);
}

static gboolean
eap_tls_reader (const char *eap_method,
                shvarFile *ifcfg,
                shvarFile *keys,
                NMSetting8021x *s_8021x,
                gboolean phase2,
                GError **error)
{
	char *ca_cert = NULL;
	char *real_path = NULL;
	char *client_cert = NULL;
	char *privkey = NULL;
	char *privkey_password = NULL;
	gboolean success = FALSE;
	NMSetting8021xCKType privkey_type = NM_SETTING_802_1X_CK_TYPE_UNKNOWN;

	ca_cert = svGetValue (ifcfg,
	                      phase2 ? "IEEE_8021X_INNER_CA_CERT" : "IEEE_8021X_CA_CERT",
	                      FALSE);
	if (ca_cert) {
		real_path = get_cert_file (ifcfg->fileName, ca_cert);
		if (phase2) {
			if (!nm_setting_802_1x_set_phase2_ca_cert_from_file (s_8021x, real_path, NULL, error))
				goto done;
			set_file_path (s_8021x,
			               TAG_PHASE2_CA_CERT_PATH,
			               TAG_PHASE2_CA_CERT_HASH,
			               real_path,
			               NM_SETTING_802_1X_PHASE2_CA_CERT);
		} else {
			if (!nm_setting_802_1x_set_ca_cert_from_file (s_8021x, real_path, NULL, error))
				goto done;
			set_file_path (s_8021x,
			               TAG_CA_CERT_PATH,
			               TAG_CA_CERT_HASH,
			               real_path,
			               NM_SETTING_802_1X_CA_CERT);
		}
	} else {
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: missing %s for EAP"
		             " method '%s'; this is insecure!",
	                     phase2 ? "IEEE_8021X_INNER_CA_CERT" : "IEEE_8021X_CA_CERT",
		             eap_method);
	}

	/* Private key password */
	privkey_password = svGetValue (ifcfg,
	                               phase2 ? "IEEE_8021X_INNER_PRIVATE_KEY_PASSWORD": "IEEE_8021X_PRIVATE_KEY_PASSWORD",
	                               FALSE);
	if (!privkey_password && keys) {
		/* Try the lookaside keys file */
		privkey_password = svGetValue (keys,
		                               phase2 ? "IEEE_8021X_INNER_PRIVATE_KEY_PASSWORD": "IEEE_8021X_PRIVATE_KEY_PASSWORD",
		                               FALSE);
	}

	if (!privkey_password) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Missing %s for EAP method '%s'.",
		             phase2 ? "IEEE_8021X_INNER_PRIVATE_KEY_PASSWORD" : "IEEE_8021X_PRIVATE_KEY_PASSWORD",
		             eap_method);
		goto done;
	}

	/* The private key itself */
	privkey = svGetValue (ifcfg,
	                      phase2 ? "IEEE_8021X_INNER_PRIVATE_KEY" : "IEEE_8021X_PRIVATE_KEY",
	                      FALSE);
	if (!privkey) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Missing %s for EAP method '%s'.",
	                      phase2 ? "IEEE_8021X_INNER_PRIVATE_KEY" : "IEEE_8021X_PRIVATE_KEY",
		             eap_method);
		goto done;
	}

	g_free (real_path);
	real_path = get_cert_file (ifcfg->fileName, privkey);
	if (phase2) {
		if (!nm_setting_802_1x_set_phase2_private_key_from_file (s_8021x, real_path, privkey_password, &privkey_type, error))
			goto done;
		set_file_path (s_8021x,
		               TAG_PHASE2_PRIVATE_KEY_PATH,
		               TAG_PHASE2_PRIVATE_KEY_HASH,
		               real_path,
		               NM_SETTING_802_1X_PHASE2_PRIVATE_KEY);
	} else {
		if (!nm_setting_802_1x_set_private_key_from_file (s_8021x, real_path, privkey_password, &privkey_type, error))
			goto done;
		set_file_path (s_8021x,
		               TAG_PRIVATE_KEY_PATH,
		               TAG_PRIVATE_KEY_HASH,
		               real_path,
		               NM_SETTING_802_1X_PRIVATE_KEY);
	}

	/* Per NM requirements, if the private key is pkcs12, set the client cert to the
	 * same data as the private key, since pkcs12 files contain both.
	 */
	if (privkey_type == NM_SETTING_802_1X_CK_TYPE_PKCS12) {
		if (phase2) {
			if (!nm_setting_802_1x_set_phase2_client_cert_from_file (s_8021x, real_path, NULL, error))
				goto done;
			set_file_path (s_8021x,
			               TAG_PHASE2_CLIENT_CERT_PATH,
			               TAG_PHASE2_CLIENT_CERT_HASH,
			               real_path,
			               NM_SETTING_802_1X_PHASE2_CLIENT_CERT);
		} else {
			if (!nm_setting_802_1x_set_client_cert_from_file (s_8021x, real_path, NULL, error))
				goto done;
			set_file_path (s_8021x,
			               TAG_CLIENT_CERT_PATH,
			               TAG_CLIENT_CERT_HASH,
			               real_path,
			               NM_SETTING_802_1X_CLIENT_CERT);
		}
	} else {
		/* Set the private key password if not PKCS#12 */
		if (phase2)
			g_object_set (s_8021x, NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD, privkey_password, NULL);
		else
			g_object_set (s_8021x, NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD, privkey_password, NULL);

		/* Otherwise, private key is "traditional" OpenSSL format, so
		 * client certificate will be a separate file.
		 */
		client_cert = svGetValue (ifcfg,
		                          phase2 ? "IEEE_8021X_INNER_CLIENT_CERT" : "IEEE_8021X_CLIENT_CERT",
		                          FALSE);
		if (!client_cert) {
			g_set_error (error, ifcfg_plugin_error_quark (), 0,
			             "Missing %s for EAP method '%s'.",
			             phase2 ? "IEEE_8021X_INNER_CLIENT_CERT" : "IEEE_8021X_CLIENT_CERT",
			             eap_method);
			goto done;
		}

		g_free (real_path);
		real_path = get_cert_file (ifcfg->fileName, client_cert);
		if (phase2) {
			if (!nm_setting_802_1x_set_phase2_client_cert_from_file (s_8021x, real_path, NULL, error))
				goto done;
			set_file_path (s_8021x,
			               TAG_PHASE2_CLIENT_CERT_PATH,
			               TAG_PHASE2_CLIENT_CERT_HASH,
			               real_path,
			               NM_SETTING_802_1X_PHASE2_CLIENT_CERT);
		} else {
			if (!nm_setting_802_1x_set_client_cert_from_file (s_8021x, real_path, NULL, error))
				goto done;
			set_file_path (s_8021x,
			               TAG_CLIENT_CERT_PATH,
			               TAG_CLIENT_CERT_HASH,
			               real_path,
			               NM_SETTING_802_1X_CLIENT_CERT);
		}
	}

	success = TRUE;

done:
	g_free (real_path);
	g_free (ca_cert);
	g_free (client_cert);
	g_free (privkey);
	g_free (privkey_password);
	return success;
}

static gboolean
eap_peap_reader (const char *eap_method,
                 shvarFile *ifcfg,
                 shvarFile *keys,
                 NMSetting8021x *s_8021x,
                 gboolean phase2,
                 GError **error)
{
	char *ca_cert = NULL;
	char *real_cert_path = NULL;
	char *inner_auth = NULL;
	char *peapver = NULL;
	char *lower;
	char **list = NULL, **iter;
	gboolean success = FALSE;

	ca_cert = svGetValue (ifcfg, "IEEE_8021X_CA_CERT", FALSE);
	if (ca_cert) {
		real_cert_path = get_cert_file (ifcfg->fileName, ca_cert);
		if (!nm_setting_802_1x_set_ca_cert_from_file (s_8021x, real_cert_path, NULL, error))
			goto done;
		set_file_path (s_8021x,
		               TAG_CA_CERT_PATH,
		               TAG_CA_CERT_HASH,
		               real_cert_path,
		               NM_SETTING_802_1X_CA_CERT);
	} else {
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: missing "
		             "IEEE_8021X_CA_CERT for EAP method '%s'; this is"
		             " insecure!",
		             eap_method);
	}

	peapver = svGetValue (ifcfg, "IEEE_8021X_PEAP_VERSION", FALSE);
	if (peapver) {
		if (!strcmp (peapver, "0"))
			g_object_set (s_8021x, NM_SETTING_802_1X_PHASE1_PEAPVER, "0", NULL);
		else if (!strcmp (peapver, "1"))
			g_object_set (s_8021x, NM_SETTING_802_1X_PHASE1_PEAPVER, "1", NULL);
		else {
			g_set_error (error, ifcfg_plugin_error_quark (), 0,
			             "Unknown IEEE_8021X_PEAP_VERSION value '%s'",
			             peapver);
			goto done;
		}
	}

	if (svTrueValue (ifcfg, "IEEE_8021X_PEAP_FORCE_NEW_LABEL", FALSE))
		g_object_set (s_8021x, NM_SETTING_802_1X_PHASE1_PEAPLABEL, "1", NULL);

	inner_auth = svGetValue (ifcfg, "IEEE_8021X_INNER_AUTH_METHODS", FALSE);
	if (!inner_auth) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Missing IEEE_8021X_INNER_AUTH_METHODS.");
		goto done;
	}

	/* Handle options for the inner auth method */
	list = g_strsplit (inner_auth, " ", 0);
	for (iter = list; iter && *iter; iter++) {
		if (!strlen (*iter))
			continue;

		if (!strcmp (*iter, "MSCHAPV2") || !strcmp (*iter, "MD5")) {
			if (!eap_simple_reader (*iter, ifcfg, keys, s_8021x, TRUE, error))
				goto done;
		} else if (!strcmp (*iter, "TLS")) {
			if (!eap_tls_reader (*iter, ifcfg, keys, s_8021x, TRUE, error))
				goto done;
		} else {
			g_set_error (error, ifcfg_plugin_error_quark (), 0,
			             "Unknown IEEE_8021X_INNER_AUTH_METHOD '%s'.",
			             *iter);
			goto done;
		}

		// FIXME: OTP & GTC too
		lower = g_ascii_strdown (*iter, -1);
		g_object_set (s_8021x, NM_SETTING_802_1X_PHASE2_AUTH, lower, NULL);
		g_free (lower);
		break;
	}

	if (!nm_setting_802_1x_get_phase2_auth (s_8021x)) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "No valid IEEE_8021X_INNER_AUTH_METHODS found.");
		goto done;
	}

	success = TRUE;

done:
	if (list)
		g_strfreev (list);
	g_free (inner_auth);
	g_free (peapver);
	g_free (real_cert_path);
	g_free (ca_cert);
	return success;
}

static gboolean
eap_ttls_reader (const char *eap_method,
                 shvarFile *ifcfg,
                 shvarFile *keys,
                 NMSetting8021x *s_8021x,
                 gboolean phase2,
                 GError **error)
{
	gboolean success = FALSE;
	char *anon_ident = NULL;
	char *ca_cert = NULL;
	char *real_cert_path = NULL;
	char *inner_auth = NULL;
	char *tmp;
	char **list = NULL, **iter;

	ca_cert = svGetValue (ifcfg, "IEEE_8021X_CA_CERT", FALSE);
	if (ca_cert) {
		real_cert_path = get_cert_file (ifcfg->fileName, ca_cert);
		if (!nm_setting_802_1x_set_ca_cert_from_file (s_8021x, real_cert_path, NULL, error))
			goto done;
		set_file_path (s_8021x,
		               TAG_CA_CERT_PATH,
		               TAG_CA_CERT_HASH,
		               real_cert_path,
		               NM_SETTING_802_1X_CA_CERT);
	} else {
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: missing "
		             "IEEE_8021X_CA_CERT for EAP method '%s'; this is"
		             " insecure!",
		             eap_method);
	}

	anon_ident = svGetValue (ifcfg, "IEEE_8021X_ANON_IDENTITY", FALSE);
	if (anon_ident && strlen (anon_ident))
		g_object_set (s_8021x, NM_SETTING_802_1X_ANONYMOUS_IDENTITY, anon_ident, NULL);

	tmp = svGetValue (ifcfg, "IEEE_8021X_INNER_AUTH_METHODS", FALSE);
	if (!tmp) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Missing IEEE_8021X_INNER_AUTH_METHODS.");
		goto done;
	}

	inner_auth = g_ascii_strdown (tmp, -1);
	g_free (tmp);

	/* Handle options for the inner auth method */
	list = g_strsplit (inner_auth, " ", 0);
	for (iter = list; iter && *iter; iter++) {
		if (!strlen (*iter))
			continue;

		if (   !strcmp (*iter, "mschapv2")
		    || !strcmp (*iter, "mschap")
		    || !strcmp (*iter, "pap")
		    || !strcmp (*iter, "chap")) {
			if (!eap_simple_reader (*iter, ifcfg, keys, s_8021x, TRUE, error))
				goto done;
			g_object_set (s_8021x, NM_SETTING_802_1X_PHASE2_AUTH, *iter, NULL);
		} else if (!strcmp (*iter, "eap-tls")) {
			if (!eap_tls_reader (*iter, ifcfg, keys, s_8021x, TRUE, error))
				goto done;
			g_object_set (s_8021x, NM_SETTING_802_1X_PHASE2_AUTHEAP, "tls", NULL);
		} else if (!strcmp (*iter, "eap-mschapv2") || !strcmp (*iter, "eap-md5")) {
			if (!eap_simple_reader (*iter, ifcfg, keys, s_8021x, TRUE, error))
				goto done;
			g_object_set (s_8021x, NM_SETTING_802_1X_PHASE2_AUTHEAP, (*iter + strlen ("eap-")), NULL);
		} else {
			g_set_error (error, ifcfg_plugin_error_quark (), 0,
			             "Unknown IEEE_8021X_INNER_AUTH_METHOD '%s'.",
			             *iter);
			goto done;
		}
		break;
	}

	success = TRUE;

done:
	if (list)
		g_strfreev (list);
	g_free (inner_auth);
	g_free (real_cert_path);
	g_free (ca_cert);
	g_free (anon_ident);
	return success;
}

static NMSetting8021x *
fill_8021x (shvarFile *ifcfg,
            const char *file,
            const char *key_mgmt,
            gboolean wifi,
            GError **error)
{
	NMSetting8021x *s_8021x;
	shvarFile *keys = NULL;
	char *value;
	char **list, **iter;

	value = svGetValue (ifcfg, "IEEE_8021X_EAP_METHODS", FALSE);
	if (!value) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Missing IEEE_8021X_EAP_METHODS for key management '%s'",
		             key_mgmt);
		return NULL;
	}

	list = g_strsplit (value, " ", 0);
	g_free (value);

	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();

	/* Read in the lookaside keys file, if present */
	keys = utils_get_keys_ifcfg (file, FALSE);

	/* Validate and handle each EAP method */
	for (iter = list; iter && *iter; iter++) {
		EAPReader *eap = &eap_readers[0];
		gboolean found = FALSE;
		char *lower = NULL;

		lower = g_ascii_strdown (*iter, -1);
		while (*eap->method && !found) {
			if (strcmp (eap->method, lower))
				goto next;

			/* Some EAP methods don't provide keying material, thus they
			 * cannot be used with WiFi unless they are an inner method
			 * used with TTLS or PEAP or whatever.
			 */
			if (wifi && eap->wifi_phase2_only) {
				PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: ignored invalid "
				             "IEEE_8021X_EAP_METHOD '%s'; not allowed for wifi.",
				             lower);
				goto next;
			}

			/* Parse EAP method specific options */
			if (!(*eap->reader)(lower, ifcfg, keys, s_8021x, FALSE, error)) {
				g_free (lower);
				goto error;
			}
			nm_setting_802_1x_add_eap_method (s_8021x, lower);
			found = TRUE;

		next:
			eap++;
		}

		if (!found) {
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: ignored unknown"
			             "IEEE_8021X_EAP_METHOD '%s'.",
			             lower);
		}
		g_free (lower);
	}
	g_strfreev (list);

	if (nm_setting_802_1x_get_num_eap_methods (s_8021x) == 0) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "No valid EAP methods found in IEEE_8021X_EAP_METHODS.");
		goto error;
	}

	if (keys)
		svCloseFile (keys);
	return s_8021x;

error:
	if (keys)
		svCloseFile (keys);
	g_object_unref (s_8021x);
	return NULL;
}

static NMSetting *
make_wpa_setting (shvarFile *ifcfg,
                  const char *file,
                  const GByteArray *ssid,
                  gboolean adhoc,
                  NMSetting8021x **s_8021x,
                  GError **error)
{
	NMSettingWirelessSecurity *wsec;
	char *value, *psk, *lower;

	wsec = NM_SETTING_WIRELESS_SECURITY (nm_setting_wireless_security_new ());

	value = svGetValue (ifcfg, "KEY_MGMT", FALSE);
	if (!value)
		goto error; /* Not WPA or Dynamic WEP */

	/* Pairwise and Group ciphers */
	fill_wpa_ciphers (ifcfg, wsec, FALSE, adhoc);
	fill_wpa_ciphers (ifcfg, wsec, TRUE, adhoc);

	/* WPA and/or RSN */
	if (adhoc) {
		/* Ad-Hoc mode only supports WPA proto for now */
		nm_setting_wireless_security_add_proto (wsec, "wpa");
	} else {
		if (svTrueValue (ifcfg, "WPA_ALLOW_WPA", TRUE))
			nm_setting_wireless_security_add_proto (wsec, "wpa");
		if (svTrueValue (ifcfg, "WPA_ALLOW_WPA2", TRUE))
			nm_setting_wireless_security_add_proto (wsec, "rsn");
	}

	if (!strcmp (value, "WPA-PSK")) {
		psk = parse_wpa_psk (ifcfg, file, ssid, error);
		if (!psk)
			goto error;
		g_object_set (wsec, NM_SETTING_WIRELESS_SECURITY_PSK, psk, NULL);
		g_free (psk);

		if (adhoc)
			g_object_set (wsec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-none", NULL);
		else
			g_object_set (wsec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-psk", NULL);
	} else if (!strcmp (value, "WPA-EAP") || !strcmp (value, "IEEE8021X")) {
		/* Adhoc mode is mutually exclusive with any 802.1x-based authentication */
		if (adhoc) {
			g_set_error (error, ifcfg_plugin_error_quark (), 0,
			             "Ad-Hoc mode cannot be used with KEY_MGMT type '%s'", value);
			goto error;
		}

		*s_8021x = fill_8021x (ifcfg, file, value, TRUE, error);
		if (!*s_8021x)
			goto error;

		lower = g_ascii_strdown (value, -1);
		g_object_set (wsec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, lower, NULL);
		g_free (lower);
	} else {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Unknown wireless KEY_MGMT type '%s'", value);
		goto error;
	}

	g_free (value);
	return (NMSetting *) wsec;

error:
	g_free (value);
	if (wsec)
		g_object_unref (wsec);
	return NULL;
}

static NMSetting *
make_leap_setting (shvarFile *ifcfg,
                   const char *file,
                   GError **error)
{
	NMSettingWirelessSecurity *wsec;
	shvarFile *keys_ifcfg;
	char *value;

	wsec = NM_SETTING_WIRELESS_SECURITY (nm_setting_wireless_security_new ());

	value = svGetValue (ifcfg, "KEY_MGMT", FALSE);
	if (!value || strcmp (value, "IEEE8021X"))
		goto error; /* Not LEAP */

	g_free (value);
	value = svGetValue (ifcfg, "SECURITYMODE", FALSE);
	if (!value || strcasecmp (value, "leap"))
		goto error; /* Not LEAP */

	g_free (value);

	value = svGetValue (ifcfg, "IEEE_8021X_PASSWORD", FALSE);
	if (!value) {
		/* Try to get keys from the "shadow" key file */
		keys_ifcfg = utils_get_keys_ifcfg (file, FALSE);
		if (keys_ifcfg) {
			value = svGetValue (keys_ifcfg, "IEEE_8021X_PASSWORD", FALSE);
			svCloseFile (keys_ifcfg);
		}
	}
	if (value && strlen (value))
		g_object_set (wsec, NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD, value, NULL);
	g_free (value);

	value = svGetValue (ifcfg, "IEEE_8021X_IDENTITY", FALSE);
	if (!value || !strlen (value)) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Missing LEAP identity");
		goto error;
	}
	g_object_set (wsec, NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME, value, NULL);
	g_free (value);

	g_object_set (wsec,
	              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "ieee8021x",
	              NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "leap",
	              NULL);

	return (NMSetting *) wsec;

error:
	g_free (value);
	if (wsec)
		g_object_unref (wsec);
	return NULL;
}

static NMSetting *
make_wireless_security_setting (shvarFile *ifcfg,
                                const char *file,
                                const GByteArray *ssid,
                                gboolean adhoc,
                                NMSetting8021x **s_8021x,
                                GError **error)
{
	NMSetting *wsec;

	if (!adhoc) {
		wsec = make_leap_setting (ifcfg, file, error);
		if (wsec)
			return wsec;
		else if (*error)
			return NULL;
	}

	wsec = make_wpa_setting (ifcfg, file, ssid, adhoc, s_8021x, error);
	if (wsec)
		return wsec;
	else if (*error)
		return NULL;

	wsec = make_wep_setting (ifcfg, file, error);
	if (wsec)
		return wsec;
	else if (*error)
		return NULL;

	return NULL; /* unencrypted */
}

static NMSetting *
make_wireless_setting (shvarFile *ifcfg,
                       gboolean unmanaged,
                       GError **error)
{
	NMSettingWireless *s_wireless;
	GByteArray *array = NULL;
	char *value;

	s_wireless = NM_SETTING_WIRELESS (nm_setting_wireless_new ());

	if (read_mac_address (ifcfg, &array, error)) {
		g_object_set (s_wireless, NM_SETTING_WIRELESS_MAC_ADDRESS, array, NULL);
		g_byte_array_free (array, TRUE);
	} else {
		g_object_unref (s_wireless);
		return NULL;
	}

	value = svGetValue (ifcfg, "ESSID", TRUE);
	if (value) {
		gsize ssid_len = 0, value_len = strlen (value);
		char *p = value, *tmp;
		gboolean quoted = FALSE;
		char buf[33];

		ssid_len = value_len;
		if (   (value_len >= 2)
		    && (value[0] == '"')
		    && (value[value_len - 1] == '"')) {
			/* Strip the quotes and unescape */
			p = value + 1;
			value[value_len - 1] = '\0';
			svUnescape (p);
			ssid_len = strlen (p);
			quoted = TRUE;
		} else if ((value_len > 2) && (strncmp (value, "0x", 2) == 0)) {
			/* Hex representation */
			if (value_len % 2) {
				g_set_error (error, ifcfg_plugin_error_quark (), 0,
				             "Invalid SSID '%s' size (looks like hex but length not multiple of 2)",
				             value);
				g_free (value);
				goto error;
			}

			p = value + 2;
			while (*p) {
				if (!isxdigit (*p)) {
					g_set_error (error, ifcfg_plugin_error_quark (), 0,
					             "Invalid SSID '%s' character (looks like hex SSID but '%c' isn't a hex digit)",
					             value, *p);
					g_free (value);
					goto error;
				}
				p++;
			}

			tmp = utils_hexstr2bin (value + 2, value_len - 2);
			ssid_len  = (value_len - 2) / 2;
			memcpy (buf, tmp, ssid_len);
			p = &buf[0];
		}

		if (ssid_len > 32 || ssid_len == 0) {
			g_set_error (error, ifcfg_plugin_error_quark (), 0,
			             "Invalid SSID '%s' (size %zu not between 1 and 32 inclusive)",
			             value, ssid_len);
			g_free (value);
			goto error;
		}

		array = g_byte_array_sized_new (strlen (p));
		g_byte_array_append (array, (const guint8 *) p, ssid_len);
		g_object_set (s_wireless, NM_SETTING_WIRELESS_SSID, array, NULL);
		g_byte_array_free (array, TRUE);
		g_free (value);
	} else {
		/* Only fail on lack of SSID if device is managed */
		if (!unmanaged) {
			g_set_error (error, ifcfg_plugin_error_quark (), 0, "Missing SSID");
			goto error;
		}
	}

	if (unmanaged)
		goto done;

	value = svGetValue (ifcfg, "MODE", FALSE);
	if (value) {
		char *lcase;
		const char *mode = NULL;

		lcase = g_ascii_strdown (value, -1);
		g_free (value);

		if (!strcmp (lcase, "ad-hoc")) {
			mode = "adhoc";
		} else if (!strcmp (lcase, "managed")) {
			mode = "infrastructure";
		} else {
			g_set_error (error, ifcfg_plugin_error_quark (), 0,
			             "Invalid mode '%s' (not 'Ad-Hoc' or 'Managed')",
			             lcase);
			g_free (lcase);
			goto error;
		}
		g_free (lcase);

		g_object_set (s_wireless, NM_SETTING_WIRELESS_MODE, mode, NULL);
	}

	value = svGetValue (ifcfg, "BSSID", FALSE);
	if (value) {
		struct ether_addr *eth;
		GByteArray *bssid;

		eth = ether_aton (value);
		if (!eth) {
			g_set_error (error, ifcfg_plugin_error_quark (), 0,
			             "Invalid BSSID '%s'", value);
			goto error;
		}

		bssid = g_byte_array_sized_new (ETH_ALEN);
		g_byte_array_append (bssid, eth->ether_addr_octet, ETH_ALEN);
		g_object_set (s_wireless, NM_SETTING_WIRELESS_BSSID, bssid, NULL);
		g_byte_array_free (bssid, TRUE);
	}
	// FIXME: channel/freq, other L2 parameters like RTS

done:
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
	NMSetting8021x *s_8021x = NULL;
	const GByteArray *ssid;
	NMSetting *security_setting = NULL;
	char *printable_ssid = NULL;
	const char *mode;
	gboolean adhoc = FALSE;

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

	/* Wireless */
	wireless_setting = make_wireless_setting (ifcfg, unmanaged, error);
	if (!wireless_setting) {
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, wireless_setting);

	ssid = nm_setting_wireless_get_ssid (NM_SETTING_WIRELESS (wireless_setting));
	if (ssid)
		printable_ssid = nm_utils_ssid_to_utf8 ((const char *) ssid->data, ssid->len);
	else
		printable_ssid = g_strdup_printf ("unmanaged");

	if (!unmanaged) {
		mode = nm_setting_wireless_get_mode (NM_SETTING_WIRELESS (wireless_setting));
		if (mode && !strcmp (mode, "adhoc"))
			adhoc = TRUE;

		/* Wireless security */
		security_setting = make_wireless_security_setting (ifcfg, file, ssid, adhoc, &s_8021x, error);
		if (*error) {
			g_object_unref (connection);
			return NULL;
		}
		if (security_setting) {
			nm_connection_add_setting (connection, security_setting);
			if (s_8021x)
				nm_connection_add_setting (connection, NM_SETTING (s_8021x));

			g_object_set (wireless_setting, NM_SETTING_WIRELESS_SEC,
			              NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, NULL);
		}
	}

	/* Connection */
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
make_wired_setting (shvarFile *ifcfg,
                    const char *file,
                    gboolean unmanaged,
                    NMSetting8021x **s_8021x,
                    GError **error)
{
	NMSettingWired *s_wired;
	char *value = NULL;
	int mtu;
	GByteArray *mac = NULL;

	s_wired = NM_SETTING_WIRED (nm_setting_wired_new ());

	value = svGetValue (ifcfg, "MTU", FALSE);
	if (value) {
		if (get_int (value, &mtu)) {
			if (mtu >= 0 && mtu < 65536)
				g_object_set (s_wired, NM_SETTING_WIRED_MTU, mtu, NULL);
		} else {
			/* Shouldn't be fatal... */
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: invalid MTU '%s'", value);
		}
		g_free (value);
	}

	if (read_mac_address (ifcfg, &mac, error)) {
		if (mac) {
			g_object_set (s_wired, NM_SETTING_WIRED_MAC_ADDRESS, mac, NULL);
			g_byte_array_free (mac, TRUE);
		}
	} else {
		g_object_unref (s_wired);
		s_wired = NULL;
	}

	value = svGetValue (ifcfg, "KEY_MGMT", FALSE);
	if (value) {
		if (!strcmp (value, "IEEE8021X")) {
			*s_8021x = fill_8021x (ifcfg, file, value, FALSE, error);
			if (!*s_8021x)
				goto error;
		} else {
			g_set_error (error, ifcfg_plugin_error_quark (), 0,
			             "Unknown wired KEY_MGMT type '%s'", value);
			goto error;
		}
		g_free (value);
	}

	return (NMSetting *) s_wired;

error:
	g_free (value);
	g_object_unref (s_wired);
	return NULL;
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
	NMSetting8021x *s_8021x = NULL;

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

	wired_setting = make_wired_setting (ifcfg, file, unmanaged, &s_8021x, error);
	if (!wired_setting) {
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, wired_setting);

	if (s_8021x)
		nm_connection_add_setting (connection, NM_SETTING (s_8021x));

	if (!nm_connection_verify (connection, error)) {
		g_object_unref (connection);
		return NULL;
	}

	return connection;
}

static gboolean
is_wireless_device (const char *iface)
{
	int fd;
	struct iw_range range;
	struct iwreq wrq;
	gboolean is_wireless = FALSE;

	g_return_val_if_fail (iface != NULL, FALSE);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (!fd)
		return FALSE;

	memset (&wrq, 0, sizeof (struct iwreq));
	memset (&range, 0, sizeof (struct iw_range));
	strncpy (wrq.ifr_name, iface, IFNAMSIZ);
	wrq.u.data.pointer = (caddr_t) &range;
	wrq.u.data.length = sizeof (struct iw_range);

	if (ioctl (fd, SIOCGIWRANGE, &wrq) == 0)
		is_wireless = TRUE;
	else {
		if (errno == EOPNOTSUPP)
			is_wireless = FALSE;
		else {
			/* Sigh... some wired devices (kvm/qemu) return EINVAL when the
			 * device is down even though it's not a wireless device.  So try
			 * IWNAME as a fallback.
			 */
			memset (&wrq, 0, sizeof (struct iwreq));
			strncpy (wrq.ifr_name, iface, IFNAMSIZ);
			if (ioctl (fd, SIOCGIWNAME, &wrq) == 0)
				is_wireless = TRUE;
		}
	}

	close (fd);
	return is_wireless;
}

NMConnection *
connection_from_file (const char *filename,
                      const char *network_file,
                      const char *test_type,  /* for unit tests only */
                      gboolean *ignored,
                      char **keyfile,
                      GError **error,
                      gboolean *ignore_error)
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

	/* Non-NULL only for unit tests; normally use /etc/sysconfig/network */
	if (!network_file)
		network_file = SYSCONFDIR "/sysconfig/network";

	ifcfg_name = utils_get_ifcfg_name (filename);
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

	type = svGetValue (parsed, "TYPE", FALSE);
	if (!type) {
		char *device;

		/* If no type, if the device has wireless extensions, it's wifi,
		 * otherwise it's ethernet.
		 */
		device = svGetValue (parsed, "DEVICE", FALSE);
		if (!device) {
			g_set_error (error, ifcfg_plugin_error_quark (), 0,
			             "File '%s' had neither TYPE nor DEVICE keys.", filename);
			goto done;
		}

		if (!strcmp (device, "lo")) {
			*ignore_error = TRUE;
			g_set_error (error, ifcfg_plugin_error_quark (), 0,
			             "Ignoring loopback device config.");
			g_free (device);
			goto done;
		}

		if (!test_type) {
			/* Test wireless extensions */
			if (is_wireless_device (device))
				type = g_strdup (TYPE_WIRELESS);
			else
				type = g_strdup (TYPE_ETHERNET);
		} else {
			/* For the unit tests, there won't necessarily be any
			 * adapters of the connection's type in the system so the
			 * type can't be tested with ioctls.
			 */
			type = g_strdup (test_type);
		}

		g_free (device);
	}

	nmc = svGetValue (parsed, "NM_CONTROLLED", FALSE);
	if (nmc) {
		char *lower;

		lower = g_ascii_strdown (nmc, -1);
		g_free (nmc);

		if (!strcmp (lower, "no") || !strcmp (lower, "n") || !strcmp (lower, "false"))
			*ignored = TRUE;
		g_free (lower);
	}

	if (!strcasecmp (type, TYPE_ETHERNET))
		connection = wired_connection_from_ifcfg (filename, parsed, *ignored, error);
	else if (!strcasecmp (type, TYPE_WIRELESS))
		connection = wireless_connection_from_ifcfg (filename, parsed, *ignored, error);
	else {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Unknown connection type '%s'", type);
	}

	g_free (type);

	/* Don't bother reading the connection fully if it's unmanaged */
	if (!connection || *ignored)
		goto done;

	s_ip4 = make_ip4_setting (parsed, network_file, error);
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

	*keyfile = utils_get_keys_path (filename);

done:
	svCloseFile (parsed);
	return connection;
}

const char *
reader_get_prefix (void)
{
	return _("System");
}

