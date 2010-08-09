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
 * Copyright (C) 2008 - 2010 Red Hat, Inc.
 */

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/wait.h>
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
#include <nm-setting-ip6-config.h>
#include <nm-setting-wired.h>
#include <nm-setting-wireless.h>
#include <nm-setting-8021x.h>
#include <nm-utils.h>

#include "common.h"
#include "shvar.h"
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

	errno = 0;
	*value = strtol (str, &e, 0);
	if (errno || *e != '\0')
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
	const char *ifcfg_name = NULL;
	char *new_id = NULL, *uuid = NULL, *value;
	char *ifcfg_id;

	ifcfg_name = utils_get_ifcfg_name (file, TRUE);
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
		guint64 timestamp;

		errno = 0;
		tmp = strtoul (value, NULL, 10);
		if (errno == 0) {
			timestamp = (guint64) tmp;
			g_object_set (s_con, NM_SETTING_CONNECTION_TIMESTAMP, timestamp, NULL);
		} else
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: invalid LAST_CONNECT time");
		g_free (value);
	}

	return NM_SETTING (s_con);
}

static gboolean
read_mac_address (shvarFile *ifcfg, const char *key, GByteArray **array, GError **error)
{
	char *value = NULL;
	struct ether_addr *mac;

	g_return_val_if_fail (ifcfg != NULL, FALSE);
	g_return_val_if_fail (array != NULL, FALSE);
	g_return_val_if_fail (*array == NULL, FALSE);
	g_return_val_if_fail (error != NULL, FALSE);
	g_return_val_if_fail (*error == NULL, FALSE);

	value = svGetValue (ifcfg, key, FALSE);
	if (!value || !strlen (value)) {
		g_free (value);
		return TRUE;
	}

	mac = ether_aton (value);
	if (!mac) {
		g_free (value);
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "%s: the MAC address '%s' was invalid.", key, value);
		return FALSE;
	}

	g_free (value);
	*array = g_byte_array_sized_new (ETH_ALEN);
	g_byte_array_append (*array, (guint8 *) mac->ether_addr_octet, ETH_ALEN);
	return TRUE;
}

static void
iscsiadm_child_setup (gpointer user_data G_GNUC_UNUSED)
{
	/* We are in the child process here; set a different process group to
	 * ensure signal isolation between child and parent.
	 */
	pid_t pid = getpid ();
	setpgid (pid, pid);
}

static char *
match_iscsiadm_tag (const char *line, const char *tag, gboolean *skip)
{
	char *p;

	if (g_ascii_strncasecmp (line, tag, strlen (tag)))
		return NULL;

	p = strchr (line, '=');
	if (!p) {
		g_warning ("%s: malformed iscsiadm record: no = in '%s'.",
		           __func__, line);
		*skip = TRUE;
		return NULL;
	}

	p++; /* advance past = */
	return g_strstrip (p);
}

#define ISCSI_HWADDR_TAG    "iface.hwaddress"
#define ISCSI_BOOTPROTO_TAG "iface.bootproto"
#define ISCSI_IPADDR_TAG    "iface.ipaddress"
#define ISCSI_SUBNET_TAG    "iface.subnet_mask"
#define ISCSI_GATEWAY_TAG   "iface.gateway"
#define ISCSI_DNS1_TAG      "iface.primary_dns"
#define ISCSI_DNS2_TAG      "iface.secondary_dns"

static gboolean
fill_ip4_setting_from_ibft (shvarFile *ifcfg,
                            NMSettingIP4Config *s_ip4,
                            const char *iscsiadm_path,
                            GError **error)
{
	const char *argv[4] = { iscsiadm_path, "-m", "fw", NULL };
	const char *envp[1] = { NULL };
	gboolean success = FALSE, in_record = FALSE, hwaddr_matched = FALSE, skip = FALSE;
	char *out = NULL, *err = NULL;
	gint status = 0;
	GByteArray *ifcfg_mac = NULL;
	char **lines = NULL, **iter;
	const char *method = NULL;
	struct in_addr ipaddr;
	struct in_addr gateway;
	struct in_addr dns1;
	struct in_addr dns2;
	guint32 prefix = 0;

	g_return_val_if_fail (s_ip4 != NULL, FALSE);
	g_return_val_if_fail (iscsiadm_path != NULL, FALSE);

	if (!g_spawn_sync ("/", (char **) argv, (char **) envp, 0,
	                   iscsiadm_child_setup, NULL, &out, &err, &status, error))
		return FALSE;

	if (!WIFEXITED (status)) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "%s exited abnormally.", iscsiadm_path);
		goto done;
	}

	if (WEXITSTATUS (status) != 0) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "%s exited with error %d.  Message: '%s'",
		             iscsiadm_path, WEXITSTATUS (status), err ? err : "(none)");
		goto done;
	}

	if (!read_mac_address (ifcfg, "HWADDR", &ifcfg_mac, error))
		goto done;
	/* Ensure we got a MAC */
	if (!ifcfg_mac) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Missing device MAC address (no HWADDR tag present).");
		goto done;
	}

	memset (&ipaddr, 0, sizeof (ipaddr));
	memset (&gateway, 0, sizeof (gateway));
	memset (&dns1, 0, sizeof (dns1));
	memset (&dns2, 0, sizeof (dns2));

	/* Success, lets parse the output */
	lines = g_strsplit_set (out, "\n\r", -1);
	for (iter = lines; iter && *iter; iter++) {
		char *p;

		if (!g_ascii_strcasecmp (*iter, "# BEGIN RECORD")) {
			if (in_record) {
				g_warning ("%s: malformed iscsiadm record: already parsing record.", __func__);
				skip = TRUE;
			}
		} else if (!g_ascii_strcasecmp (*iter, "# END RECORD")) {
			if (!skip && hwaddr_matched) {
				/* Record is good; fill IP4 config with its info */
				if (!method) {
					g_warning ("%s: malformed iscsiadm record: missing BOOTPROTO.", __func__);
					return FALSE;
				}

				g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, method, NULL);

				if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_MANUAL)) {
					NMIP4Address *addr;

				    if (!ipaddr.s_addr || !prefix) {
						g_warning ("%s: malformed iscsiadm record: BOOTPROTO=static "
						           "but missing IP address or prefix.", __func__);
						return FALSE;
					}

					addr = nm_ip4_address_new ();
					nm_ip4_address_set_address (addr, ipaddr.s_addr);
					nm_ip4_address_set_prefix (addr, prefix);
					nm_ip4_address_set_gateway (addr, gateway.s_addr);
					nm_setting_ip4_config_add_address (s_ip4, addr);
					nm_ip4_address_unref (addr);

					if (dns1.s_addr)
						nm_setting_ip4_config_add_dns (s_ip4, dns1.s_addr);
					if (dns2.s_addr)
						nm_setting_ip4_config_add_dns (s_ip4, dns2.s_addr);

					// FIXME: DNS search domains?
				}
				return TRUE;
			}
			skip = FALSE;
			hwaddr_matched = FALSE;
			memset (&ipaddr, 0, sizeof (ipaddr));
			memset (&gateway, 0, sizeof (gateway));
			memset (&dns1, 0, sizeof (dns1));
			memset (&dns2, 0, sizeof (dns2));
			prefix = 0;
			method = NULL;
		}

		if (skip)
			continue;

		/* HWADDR */
		if (!skip && (p = match_iscsiadm_tag (*iter, ISCSI_HWADDR_TAG, &skip))) {
			struct ether_addr *ibft_mac;

			ibft_mac = ether_aton (p);
			if (!ibft_mac) {
				g_warning ("%s: malformed iscsiadm record: invalid hwaddress.", __func__);
				skip = TRUE;
				continue;
			}

			if (memcmp (ifcfg_mac->data, (guint8 *) ibft_mac->ether_addr_octet, ETH_ALEN)) {
				/* This record isn't for the current device, ignore it */
				skip = TRUE;
				continue;
			}

			/* Success, this record is for this device */
			hwaddr_matched = TRUE;
		}

		/* BOOTPROTO */
		if (!skip && (p = match_iscsiadm_tag (*iter, ISCSI_BOOTPROTO_TAG, &skip))) {
			if (!g_ascii_strcasecmp (p, "dhcp"))
				method = NM_SETTING_IP4_CONFIG_METHOD_AUTO;
			else if (!g_ascii_strcasecmp (p, "static"))
				method = NM_SETTING_IP4_CONFIG_METHOD_MANUAL;
			else {
				g_warning ("%s: malformed iscsiadm record: unknown BOOTPROTO '%s'.",
				           __func__, p);
				skip = TRUE;
				continue;
			}
		}

		if (!skip && (p = match_iscsiadm_tag (*iter, ISCSI_IPADDR_TAG, &skip))) {
			if (inet_pton (AF_INET, p, &ipaddr) < 1) {
				g_warning ("%s: malformed iscsiadm record: invalid IP address '%s'.",
				           __func__, p);
				skip = TRUE;
				continue;
			}
		}

		if (!skip && (p = match_iscsiadm_tag (*iter, ISCSI_SUBNET_TAG, &skip))) {
			struct in_addr mask;

			if (inet_pton (AF_INET, p, &mask) < 1) {
				g_warning ("%s: malformed iscsiadm record: invalid subnet mask '%s'.",
				           __func__, p);
				skip = TRUE;
				continue;
			}

			prefix = nm_utils_ip4_netmask_to_prefix (mask.s_addr);
		}

		if (!skip && (p = match_iscsiadm_tag (*iter, ISCSI_GATEWAY_TAG, &skip))) {
			if (inet_pton (AF_INET, p, &gateway) < 1) {
				g_warning ("%s: malformed iscsiadm record: invalid IP gateway '%s'.",
				           __func__, p);
				skip = TRUE;
				continue;
			}
		}

		if (!skip && (p = match_iscsiadm_tag (*iter, ISCSI_DNS1_TAG, &skip))) {
			if (inet_pton (AF_INET, p, &dns1) < 1) {
				g_warning ("%s: malformed iscsiadm record: invalid DNS1 address '%s'.",
				           __func__, p);
				skip = TRUE;
				continue;
			}
		}

		if (!skip && (p = match_iscsiadm_tag (*iter, ISCSI_DNS2_TAG, &skip))) {
			if (inet_pton (AF_INET, p, &dns2) < 1) {
				g_warning ("%s: malformed iscsiadm record: invalid DNS2 address '%s'.",
				           __func__, p);
				skip = TRUE;
				continue;
			}
		}
	}

	success = TRUE;

done:
	if (ifcfg_mac)
		g_byte_array_free (ifcfg_mac, TRUE);
	g_strfreev (lines);
	g_free (out);
	g_free (err);
	return success;
}

static gboolean
read_ip4_address (shvarFile *ifcfg,
                  const char *tag,
                  guint32 *out_addr,
                  GError **error)
{
	char *value = NULL;
	struct in_addr ip4_addr;
	gboolean success = FALSE;

	g_return_val_if_fail (ifcfg != NULL, FALSE);
	g_return_val_if_fail (tag != NULL, FALSE);
	g_return_val_if_fail (out_addr != NULL, FALSE);
	g_return_val_if_fail (error != NULL, FALSE);
	g_return_val_if_fail (*error == NULL, FALSE);

	*out_addr = 0;

	value = svGetValue (ifcfg, tag, FALSE);
	if (!value)
		return TRUE;

	if (inet_pton (AF_INET, value, &ip4_addr) > 0) {
		*out_addr = ip4_addr.s_addr;
		success = TRUE;
	} else {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Invalid %s IP4 address '%s'", tag, value);
	}
	g_free (value);
	return success;
}

static gboolean
parse_ip6_address (const char *value,
                  struct in6_addr *out_addr,
                  GError **error)
{
	struct in6_addr ip6_addr;
	gboolean success = FALSE;

	g_return_val_if_fail (value != NULL, FALSE);
	g_return_val_if_fail (out_addr != NULL, FALSE);
	g_return_val_if_fail (error != NULL, FALSE);
	g_return_val_if_fail (*error == NULL, FALSE);

	*out_addr = in6addr_any;

	if (inet_pton (AF_INET6, value, &ip6_addr) > 0) {
		*out_addr = ip6_addr;
		success = TRUE;
	} else {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Invalid IP6 address '%s'", value);
	}
	return success;
}

static NMIP4Address *
read_full_ip4_address (shvarFile *ifcfg,
                       const char *network_file,
                       guint32 which,
                       GError **error)
{
	NMIP4Address *addr;
	char *ip_tag, *prefix_tag, *netmask_tag, *gw_tag;
	guint32 tmp;
	gboolean success = FALSE;
	shvarFile *network_ifcfg;
	char *value;

	g_return_val_if_fail (which > 0, NULL);
	g_return_val_if_fail (ifcfg != NULL, NULL);
	g_return_val_if_fail (network_file != NULL, NULL);

	addr = nm_ip4_address_new ();
	if (which == 1) {
		ip_tag = g_strdup ("IPADDR");
		prefix_tag = g_strdup ("PREFIX");
		netmask_tag = g_strdup ("NETMASK");
		gw_tag = g_strdup ("GATEWAY");
	} else {
		ip_tag = g_strdup_printf ("IPADDR%u", which);
		prefix_tag = g_strdup_printf ("PREFIX%u", which);
		netmask_tag = g_strdup_printf ("NETMASK%u", which);
		gw_tag = g_strdup_printf ("GATEWAY%u", which);
	}

	/* IP address */
	if (!read_ip4_address (ifcfg, ip_tag, &tmp, error))
		goto error;
	if (!tmp) {
		nm_ip4_address_unref (addr);
		addr = NULL;
		success = TRUE;  /* done */
		goto error;
	}
	nm_ip4_address_set_address (addr, tmp);

	/* Gateway */
	if (!read_ip4_address (ifcfg, gw_tag, &tmp, error))
		goto error;
	if (tmp)
		nm_ip4_address_set_gateway (addr, tmp);
	else {
		gboolean read_success;

		/* If no gateway in the ifcfg, try /etc/sysconfig/network instead */
		network_ifcfg = svNewFile (network_file);
		if (network_ifcfg) {
			read_success = read_ip4_address (network_ifcfg, "GATEWAY", &tmp, error);
			svCloseFile (network_ifcfg);
			if (!read_success)
				goto error;
			nm_ip4_address_set_gateway (addr, tmp);
		}
	}

	/* Prefix */
	value = svGetValue (ifcfg, prefix_tag, FALSE);
	if (value) {
		long int prefix;

		errno = 0;
		prefix = strtol (value, NULL, 10);
		if (errno || prefix <= 0 || prefix > 32) {
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
			             "Invalid IP4 prefix '%s'", value);
			g_free (value);
			goto error;
		}
		nm_ip4_address_set_prefix (addr, (guint32) prefix);
		g_free (value);
	}

	/* Fall back to NETMASK if no PREFIX was specified */
	if (!nm_ip4_address_get_prefix (addr)) {
		if (!read_ip4_address (ifcfg, netmask_tag, &tmp, error))
			goto error;
		nm_ip4_address_set_prefix (addr, nm_utils_ip4_netmask_to_prefix (tmp));
	}

	/* Try to autodetermine the prefix for the address' class */
	if (!nm_ip4_address_get_prefix (addr)) {
		guint32 prefix = 0;

		prefix = nm_utils_ip4_get_default_prefix (nm_ip4_address_get_address (addr));
		nm_ip4_address_set_prefix (addr, prefix);

		value = svGetValue (ifcfg, ip_tag, FALSE);
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: missing %s, assuming %s/%u",
		             prefix_tag, value, prefix);
		g_free (value);
	}

	/* Validate the prefix */
	if (nm_ip4_address_get_prefix (addr) > 32) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Missing or invalid IP4 prefix '%d'",
		             nm_ip4_address_get_prefix (addr));
		goto error;
	}

	success = TRUE;

error:
	if (!success) {
		nm_ip4_address_unref (addr);
		addr = NULL;
	}

	g_free (ip_tag);
	g_free (prefix_tag);
	g_free (netmask_tag);
	g_free (gw_tag);
	return addr;
}

static NMIP4Route *
read_one_ip4_route (shvarFile *ifcfg,
                    const char *network_file,
                    guint32 which,
                    GError **error)
{
	NMIP4Route *route;
	char *ip_tag, *netmask_tag, *gw_tag, *metric_tag, *value;
	guint32 tmp;
	gboolean success = FALSE;

	g_return_val_if_fail (ifcfg != NULL, NULL);
	g_return_val_if_fail (network_file != NULL, NULL);
	g_return_val_if_fail (which >= 0, NULL);

	route = nm_ip4_route_new ();

	ip_tag = g_strdup_printf ("ADDRESS%u", which);
	netmask_tag = g_strdup_printf ("NETMASK%u", which);
	gw_tag = g_strdup_printf ("GATEWAY%u", which);
	metric_tag = g_strdup_printf ("METRIC%u", which);

	/* Destination */
	if (!read_ip4_address (ifcfg, ip_tag, &tmp, error))
		goto out;
	if (!tmp) {
		/* Check whether IP is missing or 0.0.0.0 */
		char *val;
		val = svGetValue (ifcfg, ip_tag, FALSE);
		if (!val) {
			nm_ip4_route_unref (route);
			route = NULL;
			success = TRUE;  /* done */
			goto out;
		}
		g_free (val);
	}
	nm_ip4_route_set_dest (route, tmp);

	/* Next hop */
	if (!read_ip4_address (ifcfg, gw_tag, &tmp, error))
		goto out;
	if (!tmp) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Missing or invalid IP4 gateway address '%d'",
		             tmp);
		goto out;
	}
	nm_ip4_route_set_next_hop (route, tmp);

	/* Prefix */
	if (!read_ip4_address (ifcfg, netmask_tag, &tmp, error))
		goto out;
	nm_ip4_route_set_prefix (route, nm_utils_ip4_netmask_to_prefix (tmp));

	/* Validate the prefix */
	if (  !nm_ip4_route_get_prefix (route)
	    || nm_ip4_route_get_prefix (route) > 32) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Missing or invalid IP4 prefix '%d'",
		             nm_ip4_route_get_prefix (route));
		goto out;
	}

	/* Metric */
	value = svGetValue (ifcfg, metric_tag, FALSE);
	if (value) {
		long int metric;

		errno = 0;
		metric = strtol (value, NULL, 10);
		if (errno || metric < 0) {
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
			             "Invalid IP4 route metric '%s'", value);
			g_free (value);
			goto out;
		}
		nm_ip4_route_set_metric (route, (guint32) metric);
		g_free (value);
	}

	success = TRUE;

out:
	if (!success) {
		nm_ip4_route_unref (route);
		route = NULL;
	}

	g_free (ip_tag);
	g_free (netmask_tag);
	g_free (gw_tag);
	g_free (metric_tag);
	return route;
}

static gboolean
read_route_file_legacy (const char *filename, NMSettingIP4Config *s_ip4, GError **error)
{
	char *contents = NULL;
	gsize len = 0;
	char **lines = NULL, **iter;
	GRegex *regex_to1, *regex_to2, *regex_via, *regex_metric;
	GMatchInfo *match_info;
	NMIP4Route *route;
	struct in_addr ip4_addr;
	char *dest = NULL, *prefix = NULL, *next_hop = NULL, *metric = NULL;
	long int prefix_int, metric_int;
	gboolean success = FALSE;

	const char *pattern_empty = "^\\s*(\\#.*)?$";
	const char *pattern_to1 = "^\\s*(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|default)"  /* IP or 'default' keyword */
	                          "(?:/(\\d{1,2}))?";                                         /* optional prefix */
	const char *pattern_to2 = "to\\s+(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|default)" /* IP or 'default' keyword */
	                          "(?:/(\\d{1,2}))?";                                         /* optional prefix */
	const char *pattern_via = "via\\s+(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})";       /* IP of gateway */
	const char *pattern_metric = "metric\\s+(\\d+)";                                      /* metric */

	g_return_val_if_fail (filename != NULL, FALSE);
	g_return_val_if_fail (s_ip4 != NULL, FALSE);
	g_return_val_if_fail (error != NULL, FALSE);
	g_return_val_if_fail (*error == NULL, FALSE);

	/* Read the route file */
	if (!g_file_get_contents (filename, &contents, &len, NULL))
		return FALSE;

	if (len == 0) {
		g_free (contents);
		return FALSE;
	}

	/* Create regexes for pieces to be matched */
	regex_to1 = g_regex_new (pattern_to1, 0, 0, NULL);
	regex_to2 = g_regex_new (pattern_to2, 0, 0, NULL);
	regex_via = g_regex_new (pattern_via, 0, 0, NULL);
	regex_metric = g_regex_new (pattern_metric, 0, 0, NULL);

	/* New NMIP4Route structure */
	route = nm_ip4_route_new ();

	/* Iterate through file lines */
	lines = g_strsplit_set (contents, "\n\r", -1);
	for (iter = lines; iter && *iter; iter++) {

		/* Skip empty lines */
		if (g_regex_match_simple (pattern_empty, *iter, 0, 0))
			continue;

		/* Destination */
		g_regex_match (regex_to1, *iter, 0, &match_info);
		if (!g_match_info_matches (match_info)) {
			g_match_info_free (match_info);
			g_regex_match (regex_to2, *iter, 0, &match_info);
			if (!g_match_info_matches (match_info)) {
				g_match_info_free (match_info);
				g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
					     "Missing IP4 route destination address in record: '%s'", *iter);
				goto error;
			}
		}
		dest = g_match_info_fetch (match_info, 1);
		g_match_info_free (match_info);
		if (!strcmp (dest, "default"))
			strcpy (dest, "0.0.0.0");
		if (inet_pton (AF_INET, dest, &ip4_addr) != 1) {
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
				     "Invalid IP4 route destination address '%s'", dest);
			g_free (dest);
			goto error;
		}
		nm_ip4_route_set_dest (route, ip4_addr.s_addr);
		g_free (dest);

		/* Prefix - is optional; 32 if missing */
		prefix = g_match_info_fetch (match_info, 2);
		prefix_int = 32;
		if (prefix) {
			errno = 0;
			prefix_int = strtol (prefix, NULL, 10);
			if (errno || prefix_int < 0 || prefix_int > 32) {
				g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
					     "Invalid IP4 route destination prefix '%s'", prefix);
				g_free (prefix);
				goto error;
			}
		}

		nm_ip4_route_set_prefix (route, (guint32) prefix_int);
		g_free (prefix);

		/* Next hop */
		g_regex_match (regex_via, *iter, 0, &match_info);
		if (!g_match_info_matches (match_info)) {
			g_match_info_free (match_info);
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
			             "Missing IP4 route gateway address in record: '%s'", *iter);
			goto error;
		}
		next_hop = g_match_info_fetch (match_info, 1);
		g_match_info_free (match_info);
		if (inet_pton (AF_INET, next_hop, &ip4_addr) != 1) {
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
			             "Invalid IP4 route gateway address '%s'", next_hop);
			g_free (next_hop);
			goto error;
		}
		nm_ip4_route_set_next_hop (route, ip4_addr.s_addr);
		g_free (next_hop);

		/* Metric */
		g_regex_match (regex_metric, *iter, 0, &match_info);
		metric_int = 0;
		if (g_match_info_matches (match_info)) {
			metric = g_match_info_fetch (match_info, 1);
			errno = 0;
			metric_int = strtol (metric, NULL, 10);
			if (errno || metric_int < 0) {
				g_match_info_free (match_info);
				g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
				             "Invalid IP4 route metric '%s'", metric);
				g_free (metric);
				goto error;
			}
			g_free (metric);
		}

		nm_ip4_route_set_metric (route, (guint32) metric_int);
		g_match_info_free (match_info);

		if (!nm_setting_ip4_config_add_route (s_ip4, route))
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: duplicate IP4 route");

	}

	success = TRUE;

error:
	g_free (contents);
	g_strfreev (lines);
	nm_ip4_route_unref (route);
	g_regex_unref (regex_to1);
	g_regex_unref (regex_to2);
	g_regex_unref (regex_via);
	g_regex_unref (regex_metric);

	return success;
}

static NMIP6Address *
parse_full_ip6_address (const char *addr_str, GError **error)
{
	NMIP6Address *addr;
	char **list;
	char *ip_tag, *prefix_tag;
	struct in6_addr tmp = IN6ADDR_ANY_INIT;
	gboolean success = FALSE;

	g_return_val_if_fail (addr_str != NULL, NULL);
	g_return_val_if_fail (error != NULL, NULL);
	g_return_val_if_fail (*error == NULL, NULL);

	/* Split the adddress and prefix */
	list = g_strsplit_set (addr_str, "/", 2);
	if (g_strv_length (list) < 1) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Invalid IP6 address '%s'", addr_str);
		goto error;
	}

	ip_tag = list[0];
	prefix_tag = list[1];

	addr = nm_ip6_address_new ();
	/* IP address */
	if (ip_tag) {
		if (!parse_ip6_address (ip_tag, &tmp, error))
			goto error;
	}

	nm_ip6_address_set_address (addr, &tmp);

	/* Prefix */
	if (prefix_tag) {
		long int prefix;

		errno = 0;
		prefix = strtol (prefix_tag, NULL, 10);
		if (errno || prefix <= 0 || prefix > 128) {
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
			             "Invalid IP6 prefix '%s'", prefix_tag);
			goto error;
		}
		nm_ip6_address_set_prefix (addr, (guint32) prefix);
	} else {
		/* Missing prefix is treated as prefix of 64 */
		nm_ip6_address_set_prefix (addr, 64);
	}

	success = TRUE;

error:
	if (!success) {
		nm_ip6_address_unref (addr);
		addr = NULL;
	}

	g_strfreev (list);
	return addr;
}

/* IPv6 address is very complex to describe completely by a regular expression,
 * so don't try to, rather use looser syntax to comprise all possibilities
 * NOTE: The regexes below don't describe all variants allowed by 'ip route add',
 * namely destination IP without 'to' keyword is recognized just at line start.
 */
#define IPV6_ADDR_REGEX "[0-9A-Fa-f:.]+"

static gboolean
read_route6_file (const char *filename, NMSettingIP6Config *s_ip6, GError **error)
{
	char *contents = NULL;
	gsize len = 0;
	char **lines = NULL, **iter;
	GRegex *regex_to1, *regex_to2, *regex_via, *regex_metric;
	GMatchInfo *match_info;
	NMIP6Route *route;
	struct in6_addr ip6_addr;
	char *dest = NULL, *prefix = NULL, *next_hop = NULL, *metric = NULL;
	long int prefix_int, metric_int;
	gboolean success = FALSE;

	const char *pattern_empty = "^\\s*(\\#.*)?$";
	const char *pattern_to1 = "^\\s*(" IPV6_ADDR_REGEX "|default)"  /* IPv6 or 'default' keyword */
	                          "(?:/(\\d{1,2}))?";                   /* optional prefix */
	const char *pattern_to2 = "to\\s+(" IPV6_ADDR_REGEX "|default)" /* IPv6 or 'default' keyword */
	                          "(?:/(\\d{1,2}))?";                   /* optional prefix */
	const char *pattern_via = "via\\s+(" IPV6_ADDR_REGEX ")";       /* IPv6 of gateway */
	const char *pattern_metric = "metric\\s+(\\d+)";                /* metric */

	g_return_val_if_fail (filename != NULL, FALSE);
	g_return_val_if_fail (s_ip6 != NULL, FALSE);
	g_return_val_if_fail (error != NULL, FALSE);
	g_return_val_if_fail (*error == NULL, FALSE);

	/* Read the route file */
	if (!g_file_get_contents (filename, &contents, &len, NULL))
		return FALSE;

	if (len == 0) {
		g_free (contents);
		return FALSE;
	}

	/* Create regexes for pieces to be matched */
	regex_to1 = g_regex_new (pattern_to1, 0, 0, NULL);
	regex_to2 = g_regex_new (pattern_to2, 0, 0, NULL);
	regex_via = g_regex_new (pattern_via, 0, 0, NULL);
	regex_metric = g_regex_new (pattern_metric, 0, 0, NULL);

	/* New NMIP6Route structure */
	route = nm_ip6_route_new ();

	/* Iterate through file lines */
	lines = g_strsplit_set (contents, "\n\r", -1);
	for (iter = lines; iter && *iter; iter++) {

		/* Skip empty lines */
		if (g_regex_match_simple (pattern_empty, *iter, 0, 0))
			continue;

		/* Destination */
		g_regex_match (regex_to1, *iter, 0, &match_info);
		if (!g_match_info_matches (match_info)) {
			g_match_info_free (match_info);
			g_regex_match (regex_to2, *iter, 0, &match_info);
			if (!g_match_info_matches (match_info)) {
				g_match_info_free (match_info);
				g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
					     "Missing IP6 route destination address in record: '%s'", *iter);
				goto error;
			}
		}
		dest = g_match_info_fetch (match_info, 1);
		g_match_info_free (match_info);
		if (!strcmp (dest, "default"))
			strcpy (dest, "::");
		if (inet_pton (AF_INET6, dest, &ip6_addr) != 1) {
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
				     "Invalid IP6 route destination address '%s'", dest);
			g_free (dest);
			goto error;
		}
		nm_ip6_route_set_dest (route, &ip6_addr);
		g_free (dest);

		/* Prefix - is optional; 128 if missing */
		prefix = g_match_info_fetch (match_info, 2);
		prefix_int = 128;
		if (prefix) {
			errno = 0;
			prefix_int = strtol (prefix, NULL, 10);
			if (errno || prefix_int < 0 || prefix_int > 128) {
				g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
					     "Invalid IP6 route destination prefix '%s'", prefix);
				g_free (prefix);
				goto error;
			}
		}

		nm_ip6_route_set_prefix (route, (guint32) prefix_int);
		g_free (prefix);

		/* Next hop */
		g_regex_match (regex_via, *iter, 0, &match_info);
		if (!g_match_info_matches (match_info)) {
			g_match_info_free (match_info);
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
			             "Missing IP6 route gateway address in record: '%s'", *iter);
			goto error;
		}
		next_hop = g_match_info_fetch (match_info, 1);
		g_match_info_free (match_info);
		if (inet_pton (AF_INET6, next_hop, &ip6_addr) != 1) {
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
			             "Invalid IP6 route gateway address '%s'", next_hop);
			g_free (next_hop);
			goto error;
		}
		nm_ip6_route_set_next_hop (route, &ip6_addr);
		g_free (next_hop);

		/* Metric */
		g_regex_match (regex_metric, *iter, 0, &match_info);
		metric_int = 0;
		if (g_match_info_matches (match_info)) {
			metric = g_match_info_fetch (match_info, 1);
			errno = 0;
			metric_int = strtol (metric, NULL, 10);
			if (errno || metric_int < 0 || metric_int > G_MAXUINT32) {
				g_match_info_free (match_info);
				g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
				             "Invalid IP6 route metric '%s'", metric);
				g_free (metric);
				goto error;
			}
			g_free (metric);
		}

		nm_ip6_route_set_metric (route, (guint32) metric_int);
		g_match_info_free (match_info);

		if (!nm_setting_ip6_config_add_route (s_ip6, route))
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: duplicate IP6 route");
	}

	success = TRUE;

error:
	g_free (contents);
	g_strfreev (lines);
	nm_ip6_route_unref (route);
	g_regex_unref (regex_to1);
	g_regex_unref (regex_to2);
	g_regex_unref (regex_via);
	g_regex_unref (regex_metric);

	return success;
}


static NMSetting *
make_ip4_setting (shvarFile *ifcfg,
                  const char *network_file,
                  const char *iscsiadm_path,
                  gboolean valid_ip6_config,
                  GError **error)
{
	NMSettingIP4Config *s_ip4 = NULL;
	char *value = NULL;
	char *route_path = NULL;
	char *method = NM_SETTING_IP4_CONFIG_METHOD_MANUAL;
	guint32 i;
	shvarFile *network_ifcfg;
	shvarFile *route_ifcfg;
	gboolean never_default = FALSE, tmp_success;

	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	if (!s_ip4) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Could not allocate IP4 setting");
		return NULL;
	}

	/* First check if DEFROUTE is set for this device; DEFROUTE has the
	 * opposite meaning from never-default. The default if DEFROUTE is not
	 * specified is DEFROUTE=yes which means that this connection can be used
	 * as a default route
	 */
	never_default = !svTrueValue (ifcfg, "DEFROUTE", TRUE);

	/* Then check if GATEWAYDEV; it's global and overrides DEFROUTE */
	network_ifcfg = svNewFile (network_file);
	if (network_ifcfg) {
		char *gatewaydev;

		/* Get the connection ifcfg device name and the global gateway device */
		value = svGetValue (ifcfg, "DEVICE", FALSE);
		gatewaydev = svGetValue (network_ifcfg, "GATEWAYDEV", FALSE);

		/* If there was a global gateway device specified, then only connections
		 * for that device can be the default connection.
		 */
		if (gatewaydev && value)
			never_default = !!strcmp (value, gatewaydev);

		g_free (gatewaydev);
		g_free (value);
		svCloseFile (network_ifcfg);
	}

	value = svGetValue (ifcfg, "BOOTPROTO", FALSE);
	if (value) {
		if (!g_ascii_strcasecmp (value, "bootp") || !g_ascii_strcasecmp (value, "dhcp"))
			method = NM_SETTING_IP4_CONFIG_METHOD_AUTO;
		else if (!g_ascii_strcasecmp (value, "ibft")) {
			/* iSCSI Boot Firmware Table: need to read values from the iSCSI 
			 * firmware for this device and create the IP4 setting using those.
			 */
			if (fill_ip4_setting_from_ibft (ifcfg, s_ip4, iscsiadm_path, error))
				return NM_SETTING (s_ip4);
			g_object_unref (s_ip4);
			return NULL;
		} else if (!g_ascii_strcasecmp (value, "autoip")) {
			g_free (value);
			g_object_set (s_ip4,
			              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL,
			              NM_SETTING_IP4_CONFIG_NEVER_DEFAULT, never_default,
			              NULL);
			return NM_SETTING (s_ip4);
		} else if (!g_ascii_strcasecmp (value, "shared")) {
			g_free (value);
			g_object_set (s_ip4,
			              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_SHARED,
			              NM_SETTING_IP4_CONFIG_NEVER_DEFAULT, never_default,
			              NULL);
			return NM_SETTING (s_ip4);
		} else if (!g_ascii_strcasecmp (value, "none") || !g_ascii_strcasecmp (value, "static")) {
			/* Static IP */
		} else if (strlen (value)) {
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
			             "Unknown BOOTPROTO '%s'", value);
			g_free (value);
			goto done;
		}
		g_free (value);
	} else {
		char *tmp_ip4, *tmp_prefix, *tmp_netmask;

		/* If there is no BOOTPROTO, no IPADDR, no PREFIX, no NETMASK, but
		 * valid IPv6 configuration, assume that IPv4 is disabled.  Otherwise,
		 * if there is no IPv6 configuration, assume DHCP is to be used.
		 * Happens with minimal ifcfg files like the following that anaconda
		 * sometimes used to write out:
		 *
		 * DEVICE=eth0
		 * HWADDR=11:22:33:44:55:66
		 *
		 */
		tmp_ip4 = svGetValue (ifcfg, "IPADDR", FALSE);
		tmp_prefix = svGetValue (ifcfg, "PREFIX", FALSE);
		tmp_netmask = svGetValue (ifcfg, "NETMASK", FALSE);
		if (!tmp_ip4 && !tmp_prefix && !tmp_netmask) {
			if (valid_ip6_config) {
				/* Nope, no IPv4 */
				g_object_set (s_ip4,
				              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_DISABLED,
				              NULL);
				return NM_SETTING (s_ip4);
			}

			method = NM_SETTING_IP4_CONFIG_METHOD_AUTO;
		}
		g_free (tmp_ip4);
		g_free (tmp_prefix);
		g_free (tmp_netmask);
	}

	g_object_set (s_ip4,
	              NM_SETTING_IP4_CONFIG_METHOD, method,
	              NM_SETTING_IP4_CONFIG_IGNORE_AUTO_DNS, !svTrueValue (ifcfg, "PEERDNS", TRUE),
	              NM_SETTING_IP4_CONFIG_IGNORE_AUTO_ROUTES, !svTrueValue (ifcfg, "PEERROUTES", TRUE),
	              NM_SETTING_IP4_CONFIG_NEVER_DEFAULT, never_default,
	              NM_SETTING_IP4_CONFIG_MAY_FAIL, !svTrueValue (ifcfg, "IPV4_FAILURE_FATAL", TRUE),
	              NULL);

	/* Handle manual settings */
	if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_MANUAL)) {
		NMIP4Address *addr;

		for (i = 1; i < 256; i++) {
			addr = read_full_ip4_address (ifcfg, network_file, i, error);
			if (error && *error)
				goto done;
			if (!addr)
				break;

			if (!nm_setting_ip4_config_add_address (s_ip4, addr))
				PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: duplicate IP4 address");
			nm_ip4_address_unref (addr);
		}
	} else if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_AUTO)) {
		value = svGetValue (ifcfg, "DHCP_HOSTNAME", FALSE);
		if (value && strlen (value))
			g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_DHCP_HOSTNAME, value, NULL);
		g_free (value);

		value = svGetValue (ifcfg, "DHCP_CLIENT_ID", FALSE);
		if (value && strlen (value))
			g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_DHCP_CLIENT_ID, value, NULL);
		g_free (value);
	}

	/* DNS servers
	 * Pick up just IPv4 addresses (IPv6 addresses are taken by make_ip6_setting())
	 */
	for (i = 1, tmp_success = TRUE; i <= 10 && tmp_success; i++) {
		char *tag;
		guint32 dns;
		struct in6_addr ip6_dns;
		GError *tmp_err = NULL;

		tag = g_strdup_printf ("DNS%u", i);
		tmp_success = read_ip4_address (ifcfg, tag, &dns, error);
		if (!tmp_success) {
			/* if it's IPv6, don't exit */
			dns = 0;
			value = svGetValue (ifcfg, tag, FALSE);
			if (value) {
				tmp_success = parse_ip6_address (value, &ip6_dns, &tmp_err);
				g_clear_error (&tmp_err);
				g_free (value);
			}
			if (!tmp_success) {
				g_free (tag);
				goto done;
			}
			g_clear_error (error);
		}

		if (dns && !nm_setting_ip4_config_add_dns (s_ip4, dns))
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: duplicate DNS server %s", tag);
		g_free (tag);
	}

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

	/* Static routes  - route-<name> file */
	route_path = utils_get_route_path (ifcfg->fileName);
	if (!route_path) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Could not get route file path for '%s'", ifcfg->fileName);
		goto done;
	}

	/* First test new/legacy syntax */
	if (utils_has_route_file_new_syntax (route_path)) {
		/* Parse route file in new syntax */
		g_free (route_path);
		route_ifcfg = utils_get_route_ifcfg (ifcfg->fileName, FALSE);
		if (route_ifcfg) {
			NMIP4Route *route;
			for (i = 0; i < 256; i++) {
				route = read_one_ip4_route (route_ifcfg, network_file, i, error);
				if (error && *error) {
					svCloseFile (route_ifcfg);
					goto done;
				}
				if (!route)
					break;

				if (!nm_setting_ip4_config_add_route (s_ip4, route))
					PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: duplicate IP4 route");
				nm_ip4_route_unref (route);
			}
			svCloseFile (route_ifcfg);
		}
	} else {
		read_route_file_legacy (route_path, s_ip4, error);
		g_free (route_path);
		if (error && *error)
			goto done;
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

	return NM_SETTING (s_ip4);

done:
	g_object_unref (s_ip4);
	return NULL;
}

static NMSetting *
make_ip6_setting (shvarFile *ifcfg,
                  const char *network_file,
                  const char *iscsiadm_path,
                  GError **error)
{
	NMSettingIP6Config *s_ip6 = NULL;
	char *value = NULL;
	char *str_value;
	char *route6_path = NULL;
	gboolean bool_value, ipv6forwarding, ipv6_autoconf, dhcp6 = FALSE;
	char *method = NM_SETTING_IP6_CONFIG_METHOD_MANUAL;
	guint32 i;
	shvarFile *network_ifcfg;
	gboolean never_default = FALSE, tmp_success;

	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	if (!s_ip6) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Could not allocate IP6 setting");
		return NULL;
	}

	/* Is IPV6 enabled? Set method to "ignored", when not enabled */
	str_value = svGetValue (ifcfg, "IPV6INIT", FALSE);
	bool_value = svTrueValue (ifcfg, "IPV6INIT", FALSE);
	if (!str_value) {
		network_ifcfg = svNewFile (network_file);
		if (network_ifcfg) {
			bool_value = svTrueValue (network_ifcfg, "IPV6INIT", FALSE);
			svCloseFile (network_ifcfg);
		}
	}
	g_free (str_value);

	if (!bool_value) {
		/* IPv6 is disabled */
		g_object_set (s_ip6,
		              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
		              NULL);
		return NM_SETTING (s_ip6);
	}

	/* First check if IPV6_DEFROUTE is set for this device; IPV6_DEFROUTE has the
	 * opposite meaning from never-default. The default if IPV6_DEFROUTE is not
	 * specified is IPV6_DEFROUTE=yes which means that this connection can be used
	 * as a default route
	 */
	never_default = !svTrueValue (ifcfg, "IPV6_DEFROUTE", TRUE);

	/* Then check if IPV6_DEFAULTGW or IPV6_DEFAULTDEV is specified;
	 * they are global and override IPV6_DEFROUTE
	 * When both are set, the device specified in IPV6_DEFAULTGW takes preference.
	 */
	network_ifcfg = svNewFile (network_file);
	if (network_ifcfg) {
		char *ipv6_defaultgw, *ipv6_defaultdev;
		char *default_dev = NULL;

		/* Get the connection ifcfg device name and the global default route device */
		value = svGetValue (ifcfg, "DEVICE", FALSE);
		ipv6_defaultgw = svGetValue (network_ifcfg, "IPV6_DEFAULTGW", FALSE);
		ipv6_defaultdev = svGetValue (network_ifcfg, "IPV6_DEFAULTDEV", FALSE);

		if (ipv6_defaultgw) {
			default_dev = strchr (ipv6_defaultgw, '%');
			if (default_dev)
				default_dev++;
		}
		if (!default_dev)
			default_dev = ipv6_defaultdev;

		/* If there was a global default route device specified, then only connections
		 * for that device can be the default connection.
		 */
		if (default_dev && value)
			never_default = !!strcmp (value, default_dev);

		g_free (ipv6_defaultgw);
		g_free (ipv6_defaultdev);
		g_free (value);
		svCloseFile (network_ifcfg);
	}

	/* Find out method property */
	ipv6forwarding = svTrueValue (ifcfg, "IPV6FORWARDING", FALSE);
	ipv6_autoconf = svTrueValue (ifcfg, "IPV6_AUTOCONF", !ipv6forwarding);
	dhcp6 = svTrueValue (ifcfg, "DHCPV6C", FALSE);

	if (ipv6_autoconf)
		method = NM_SETTING_IP6_CONFIG_METHOD_AUTO;
	else if (dhcp6)
		method = NM_SETTING_IP6_CONFIG_METHOD_DHCP;
	else {
		/* IPV6_AUTOCONF=no and no IPv6 address -> method 'link-local' */
		str_value = svGetValue (ifcfg, "IPV6ADDR", FALSE);
		if (!str_value)
			str_value = svGetValue (ifcfg, "IPV6ADDR_SECONDARIES", FALSE);

		if (!str_value)
			method = NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL;
		g_free (str_value);
	}
	/* TODO - handle other methods */

	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, method,
	              NM_SETTING_IP6_CONFIG_IGNORE_AUTO_DNS, !svTrueValue (ifcfg, "IPV6_PEERDNS", TRUE),
	              NM_SETTING_IP6_CONFIG_IGNORE_AUTO_ROUTES, !svTrueValue (ifcfg, "IPV6_PEERROUTES", TRUE),
	              NM_SETTING_IP6_CONFIG_NEVER_DEFAULT, never_default,
	              NM_SETTING_IP6_CONFIG_MAY_FAIL, !svTrueValue (ifcfg, "IPV6_FAILURE_FATAL", FALSE),
	              NULL);

	if (!strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_MANUAL)) {
		NMIP6Address *addr;
		char *val;
		char *ipv6addr, *ipv6addr_secondaries;
		char **list = NULL, **iter;

		ipv6addr = svGetValue (ifcfg, "IPV6ADDR", FALSE);
		ipv6addr_secondaries = svGetValue (ifcfg, "IPV6ADDR_SECONDARIES", FALSE);

		val = g_strjoin (ipv6addr && ipv6addr_secondaries ? " " : NULL,
		                 ipv6addr ? ipv6addr : "",
		                 ipv6addr_secondaries ? ipv6addr_secondaries : "",
		                 NULL);
		g_free (ipv6addr);
		g_free (ipv6addr_secondaries);

		list = g_strsplit_set (val, " ", 0);
		g_free (val);
		for (iter = list; iter && *iter; iter++, i++) {
			addr = parse_full_ip6_address (*iter, error);
			if (!addr) {
				g_strfreev (list);
				goto error;
			}

			if (!nm_setting_ip6_config_add_address (s_ip6, addr))
				PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: duplicate IP6 address");
			nm_ip6_address_unref (addr);
		}
		g_strfreev (list);
	} else if (!strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_AUTO)) {
		/* TODO - autoconf or DHCPv6 stuff goes here */
	}

	/* DNS servers
	 * Pick up just IPv6 addresses (IPv4 addresses are taken by make_ip4_setting())
	 */
	for (i = 1, tmp_success = TRUE; i <= 10 && tmp_success; i++) {
		char *tag;
		struct in6_addr ip6_dns;

		ip6_dns = in6addr_any;
		tag = g_strdup_printf ("DNS%u", i);
		value = svGetValue (ifcfg, tag, FALSE);
		if (value)
			tmp_success = parse_ip6_address (value, &ip6_dns, error);

		if (!tmp_success) {
			struct in_addr ip4_addr;
			if (inet_pton (AF_INET, value, &ip4_addr) != 1) {
				g_free (tag);
				g_free (value);
				goto error;
			}
			/* ignore error - it is IPv4 address */
			tmp_success = TRUE;
			g_clear_error (error);
		}

		if (!IN6_IS_ADDR_UNSPECIFIED (&ip6_dns) && !nm_setting_ip6_config_add_dns (s_ip6, &ip6_dns))
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: duplicate DNS server %s", tag);
		g_free (tag);
		g_free (value);
	}

	/* DNS searches ('DOMAIN' key) are read by make_ip4_setting() and included in NMSettingIP4Config */

	/* Read static routes from route6-<interface> file */
	route6_path = utils_get_route6_path (ifcfg->fileName);
	if (!route6_path) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Could not get route6 file path for '%s'", ifcfg->fileName);
		goto error;
	}

	read_route6_file (route6_path, s_ip6, error);
	g_free (route6_path);
	if (error && *error)
		goto error;

	return NM_SETTING (s_ip6);

error:
	g_object_unref (s_ip6);
	return NULL;
}

static gboolean
add_one_wep_key (shvarFile *ifcfg,
                 const char *shvar_key,
                 guint8 key_idx,
                 gboolean passphrase,
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
	if (passphrase) {
		if (strlen (value) && strlen (value) < 64) {
			key = g_strdup (value);
			g_object_set (G_OBJECT (s_wsec),
			              NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE,
			              NM_WEP_KEY_TYPE_PASSPHRASE,
			              NULL);
		}
	} else {
		if (strlen (value) == 10 || strlen (value) == 26) {
			/* Hexadecimal WEP key */
			char *p = value;

			while (*p) {
				if (!g_ascii_isxdigit (*p)) {
					g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
					             "Invalid hexadecimal WEP key.");
					goto out;
				}
				p++;
			}
			key = g_strdup (value);
		} else if (   !strncmp (value, "s:", 2)
		           && (strlen (value) == 7 || strlen (value) == 15)) {
			/* ASCII key */
			char *p = value + 2;

			while (*p) {
				if (!isascii ((int) (*p))) {
					g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
					             "Invalid ASCII WEP key.");
					goto out;
				}
				p++;
			}

			/* Remove 's:' prefix.
			 * Don't convert to hex string. wpa_supplicant takes 'wep_key0' option over D-Bus as byte array
			 * and converts it to hex string itself. Even though we convert hex string keys into a bin string
			 * before passing to wpa_supplicant, this prevents two unnecessary conversions. And mainly,
			 * ASCII WEP key doesn't change to HEX WEP key in UI, which could confuse users.
			 */
			key = g_strdup (value + 2);
		}
	}

	if (key) {
		nm_setting_wireless_security_set_wep_key (s_wsec, key_idx, key);
		success = TRUE;
	} else
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0, "Invalid WEP key length.");

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
	/* Try hex/ascii keys first */
	if (!add_one_wep_key (ifcfg, "KEY1", 0, FALSE, s_wsec, error))
		return FALSE;
	if (!add_one_wep_key (ifcfg, "KEY2", 1, FALSE, s_wsec, error))
		return FALSE;
	if (!add_one_wep_key (ifcfg, "KEY3", 2, FALSE, s_wsec, error))
		return FALSE;
	if (!add_one_wep_key (ifcfg, "KEY4", 3, FALSE, s_wsec, error))
		return FALSE;
	if (!add_one_wep_key (ifcfg, "KEY", def_idx, FALSE, s_wsec, error))
		return FALSE;

	/* And then passphrases */
	if (!add_one_wep_key (ifcfg, "KEY_PASSPHRASE1", 0, TRUE, s_wsec, error))
		return FALSE;
	if (!add_one_wep_key (ifcfg, "KEY_PASSPHRASE2", 1, TRUE, s_wsec, error))
		return FALSE;
	if (!add_one_wep_key (ifcfg, "KEY_PASSPHRASE3", 2, TRUE, s_wsec, error))
		return FALSE;
	if (!add_one_wep_key (ifcfg, "KEY_PASSPHRASE4", 3, TRUE, s_wsec, error))
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
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
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
		g_assert (error == NULL || *error == NULL);
	}

	/* If there's a default key, ensure that key exists */
	if ((default_key_idx == 1) && !nm_setting_wireless_security_get_wep_key (s_wireless_sec, 1)) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Default WEP key index was 2, but no valid KEY2 exists.");
		goto error;
	} else if ((default_key_idx == 2) && !nm_setting_wireless_security_get_wep_key (s_wireless_sec, 2)) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Default WEP key index was 3, but no valid KEY3 exists.");
		goto error;
	} else if ((default_key_idx == 3) && !nm_setting_wireless_security_get_wep_key (s_wireless_sec, 3)) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
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
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
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
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
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
	gboolean quoted = FALSE;

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
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Missing WPA_PSK for WPA-PSK key management");
		return NULL;
	}

	p = psk;

	if (p[0] == '"' && psk[strlen (psk) - 1] == '"')
		quoted = TRUE;

	if (!quoted && (strlen (psk) == 64)) {
		/* Verify the hex PSK; 64 digits */
		while (*p) {
			if (!isxdigit (*p++)) {
				g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
				             "Invalid WPA_PSK (contains non-hexadecimal characters)");
				goto out;
			}
		}
		hashed = g_strdup (psk);
	} else {
		/* Prior to 4f6eef9e77265484555663cf666cde4fa8323469 and
		 * 28e2e446868b94b92edc4a82aa0bf1e3eda8ec54 the writer may not have
		 * properly quoted passphrases, so just handle anything that's unquoted
		 * and between 8 and 63 characters as a passphrase.
		 */

		if (quoted) {
			/* Get rid of the quotes */
			p++;
			p[strlen (p) - 1] = '\0';
		}

		/* Length check */
		if (strlen (p) < 8 || strlen (p) > 63) {
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
			             "Invalid WPA_PSK (passphrases must be between "
			             "8 and 63 characters long (inclusive))");
			goto out;
		}

		hashed = g_strdup (p);
	}

	if (!hashed) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
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
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
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
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
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
	const char *base = cert_path;
	char *p, *ret, *dirname;

	g_return_val_if_fail (ifcfg_path != NULL, NULL);
	g_return_val_if_fail (cert_path != NULL, NULL);

	if (cert_path[0] == '/')
		return g_strdup (cert_path);

	p = strrchr (cert_path, '/');
	if (p)
		base = p + 1;

	dirname = g_path_get_dirname (ifcfg_path);
	ret = g_build_path ("/", dirname, base, NULL);
	g_free (dirname);
	return ret;
}

static gboolean
eap_tls_reader (const char *eap_method,
                shvarFile *ifcfg,
                shvarFile *keys,
                NMSetting8021x *s_8021x,
                gboolean phase2,
                GError **error)
{
	char *value;
	char *ca_cert = NULL;
	char *real_path = NULL;
	char *client_cert = NULL;
	char *privkey = NULL;
	char *privkey_password = NULL;
	gboolean success = FALSE;
	NMSetting8021xCKFormat privkey_format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;

	value = svGetValue (ifcfg, "IEEE_8021X_IDENTITY", FALSE);
	if (!value) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Missing IEEE_8021X_IDENTITY for EAP method '%s'.",
		             eap_method);
		return FALSE;
	}
	g_object_set (s_8021x, NM_SETTING_802_1X_IDENTITY, value, NULL);
	g_free (value);

	ca_cert = svGetValue (ifcfg,
	                      phase2 ? "IEEE_8021X_INNER_CA_CERT" : "IEEE_8021X_CA_CERT",
	                      FALSE);
	if (ca_cert) {
		real_path = get_cert_file (ifcfg->fileName, ca_cert);
		if (phase2) {
			if (!nm_setting_802_1x_set_phase2_ca_cert (s_8021x,
			                                           real_path,
			                                           NM_SETTING_802_1X_CK_SCHEME_PATH,
			                                           NULL,
			                                           error))
				goto done;
		} else {
			if (!nm_setting_802_1x_set_ca_cert (s_8021x,
			                                    real_path,
			                                    NM_SETTING_802_1X_CK_SCHEME_PATH,
			                                    NULL,
			                                    error))
				goto done;
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
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
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
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Missing %s for EAP method '%s'.",
	                      phase2 ? "IEEE_8021X_INNER_PRIVATE_KEY" : "IEEE_8021X_PRIVATE_KEY",
		             eap_method);
		goto done;
	}

	g_free (real_path);
	real_path = get_cert_file (ifcfg->fileName, privkey);
	if (phase2) {
		if (!nm_setting_802_1x_set_phase2_private_key (s_8021x,
		                                               real_path,
		                                               privkey_password,
			                                           NM_SETTING_802_1X_CK_SCHEME_PATH,
		                                               &privkey_format,
		                                               error))
			goto done;
	} else {
		if (!nm_setting_802_1x_set_private_key (s_8021x,
		                                        real_path,
		                                        privkey_password,
			                                    NM_SETTING_802_1X_CK_SCHEME_PATH,
		                                        &privkey_format,
		                                        error))
			goto done;
	}

	/* Only set the client certificate if the private key is not PKCS#12 format,
	 * as NM (due to supplicant restrictions) requires.  If the key was PKCS#12,
	 * then nm_setting_802_1x_set_private_key() already set the client certificate
	 * to the same value as the private key.
	 */
	if (   privkey_format == NM_SETTING_802_1X_CK_FORMAT_RAW_KEY
	    || privkey_format == NM_SETTING_802_1X_CK_FORMAT_X509) {
		client_cert = svGetValue (ifcfg,
		                          phase2 ? "IEEE_8021X_INNER_CLIENT_CERT" : "IEEE_8021X_CLIENT_CERT",
		                          FALSE);
		if (!client_cert) {
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
			             "Missing %s for EAP method '%s'.",
			             phase2 ? "IEEE_8021X_INNER_CLIENT_CERT" : "IEEE_8021X_CLIENT_CERT",
			             eap_method);
			goto done;
		}

		g_free (real_path);
		real_path = get_cert_file (ifcfg->fileName, client_cert);
		if (phase2) {
			if (!nm_setting_802_1x_set_phase2_client_cert (s_8021x,
			                                               real_path,
			                                               NM_SETTING_802_1X_CK_SCHEME_PATH,
			                                               NULL,
			                                               error))
				goto done;
		} else {
			if (!nm_setting_802_1x_set_client_cert (s_8021x,
			                                        real_path,
			                                        NM_SETTING_802_1X_CK_SCHEME_PATH,
			                                        NULL,
			                                        error))
				goto done;
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
		if (!nm_setting_802_1x_set_ca_cert (s_8021x,
		                                    real_cert_path,
		                                    NM_SETTING_802_1X_CK_SCHEME_PATH,
		                                    NULL,
		                                    error))
			goto done;
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
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
			             "Unknown IEEE_8021X_PEAP_VERSION value '%s'",
			             peapver);
			goto done;
		}
	}

	if (svTrueValue (ifcfg, "IEEE_8021X_PEAP_FORCE_NEW_LABEL", FALSE))
		g_object_set (s_8021x, NM_SETTING_802_1X_PHASE1_PEAPLABEL, "1", NULL);

	inner_auth = svGetValue (ifcfg, "IEEE_8021X_INNER_AUTH_METHODS", FALSE);
	if (!inner_auth) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Missing IEEE_8021X_INNER_AUTH_METHODS.");
		goto done;
	}

	/* Handle options for the inner auth method */
	list = g_strsplit (inner_auth, " ", 0);
	for (iter = list; iter && *iter; iter++) {
		if (!strlen (*iter))
			continue;

		if (   !strcmp (*iter, "MSCHAPV2")
		    || !strcmp (*iter, "MD5")
		    || !strcmp (*iter, "GTC")) {
			if (!eap_simple_reader (*iter, ifcfg, keys, s_8021x, TRUE, error))
				goto done;
		} else if (!strcmp (*iter, "TLS")) {
			if (!eap_tls_reader (*iter, ifcfg, keys, s_8021x, TRUE, error))
				goto done;
		} else {
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
			             "Unknown IEEE_8021X_INNER_AUTH_METHOD '%s'.",
			             *iter);
			goto done;
		}

		lower = g_ascii_strdown (*iter, -1);
		g_object_set (s_8021x, NM_SETTING_802_1X_PHASE2_AUTH, lower, NULL);
		g_free (lower);
		break;
	}

	if (!nm_setting_802_1x_get_phase2_auth (s_8021x)) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
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
		if (!nm_setting_802_1x_set_ca_cert (s_8021x,
		                                    real_cert_path,
		                                    NM_SETTING_802_1X_CK_SCHEME_PATH,
		                                    NULL,
		                                    error))
			goto done;
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
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
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
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
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
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
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
		while (eap->method && !found) {
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
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
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
		char *allow_wpa, *allow_rsn;

		allow_wpa = svGetValue (ifcfg, "WPA_ALLOW_WPA", FALSE);
		allow_rsn = svGetValue (ifcfg, "WPA_ALLOW_WPA2", FALSE);

		if (allow_wpa && svTrueValue (ifcfg, "WPA_ALLOW_WPA", TRUE))
			nm_setting_wireless_security_add_proto (wsec, "wpa");
		if (allow_rsn && svTrueValue (ifcfg, "WPA_ALLOW_WPA2", TRUE))
			nm_setting_wireless_security_add_proto (wsec, "rsn");

		/* If neither WPA_ALLOW_WPA or WPA_ALLOW_WPA2 were present, default
		 * to both WPA and RSN allowed.
		 */
		if (!allow_wpa && !allow_rsn) {
			nm_setting_wireless_security_add_proto (wsec, "wpa");
			nm_setting_wireless_security_add_proto (wsec, "rsn");
		}

		g_free (allow_wpa);
		g_free (allow_rsn);
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
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
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
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
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
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
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
                       gboolean nm_controlled,
                       char **unmanaged,
                       GError **error)
{
	NMSettingWireless *s_wireless;
	GByteArray *array = NULL;
	char *value;

	s_wireless = NM_SETTING_WIRELESS (nm_setting_wireless_new ());

	if (read_mac_address (ifcfg, "HWADDR", &array, error)) {
		if (array) {
			g_object_set (s_wireless, NM_SETTING_WIRELESS_MAC_ADDRESS, array, NULL);

			/* A connection can only be unmanaged if we know the MAC address */
			if (!nm_controlled) {
				*unmanaged = g_strdup_printf ("mac:%02x:%02x:%02x:%02x:%02x:%02x",
				                              array->data[0], array->data[1], array->data[2],
				                              array->data[3], array->data[4], array->data[5]);
			}

			g_byte_array_free (array, TRUE);
		} else if (!nm_controlled) {
			/* If NM_CONTROLLED=no but there wasn't a MAC address, notify
			 * the user that the device cannot be unmanaged.
			 */
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: NM_CONTROLLED was false but HWADDR was missing; device will be managed");
		}
	} else {
		g_object_unref (s_wireless);
		return NULL;
	}

	array = NULL;
	if (read_mac_address (ifcfg, "MACADDR", &array, error)) {
		if (array) {
			g_object_set (s_wireless, NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS, array, NULL);
			g_byte_array_free (array, TRUE);
		}
	}

	value = svGetValue (ifcfg, "ESSID", TRUE);
	if (value) {
		gsize ssid_len = 0, value_len = strlen (value);
		char *p = value, *tmp;
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
		} else if ((value_len > 2) && (strncmp (value, "0x", 2) == 0)) {
			/* Hex representation */
			if (value_len % 2) {
				g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
				             "Invalid SSID '%s' size (looks like hex but length not multiple of 2)",
				             value);
				g_free (value);
				goto error;
			}

			p = value + 2;
			while (*p) {
				if (!isxdigit (*p)) {
					g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
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
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
			             "Invalid SSID '%s' (size %zu not between 1 and 32 inclusive)",
			             value, ssid_len);
			g_free (value);
			goto error;
		}

		array = g_byte_array_sized_new (ssid_len);
		g_byte_array_append (array, (const guint8 *) p, ssid_len);
		g_object_set (s_wireless, NM_SETTING_WIRELESS_SSID, array, NULL);
		g_byte_array_free (array, TRUE);
		g_free (value);
	} else {
		/* Only fail on lack of SSID if device is managed */
		if (nm_controlled) {
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0, "Missing SSID");
			goto error;
		}
	}

	if (!nm_controlled)
		goto done;

	value = svGetValue (ifcfg, "MODE", FALSE);
	if (value) {
		char *lcase;
		const char *mode = NULL;

		lcase = g_ascii_strdown (value, -1);
		g_free (value);

		if (!strcmp (lcase, "ad-hoc")) {
			mode = "adhoc";
		} else if (!strcmp (lcase, "managed") || !strcmp (lcase, "auto")) {
			mode = "infrastructure";
		} else {
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
			             "Invalid mode '%s' (not 'Ad-Hoc', 'Managed', or 'Auto')",
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
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
			             "Invalid BSSID '%s'", value);
			goto error;
		}

		bssid = g_byte_array_sized_new (ETH_ALEN);
		g_byte_array_append (bssid, eth->ether_addr_octet, ETH_ALEN);
		g_object_set (s_wireless, NM_SETTING_WIRELESS_BSSID, bssid, NULL);
		g_byte_array_free (bssid, TRUE);
	}

	value = svGetValue (ifcfg, "CHANNEL", FALSE);
	if (value) {
		long int chan;

		errno = 0;
		chan = strtol (value, NULL, 10);
		if (errno || chan <= 0 || chan > 196) {
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
			             "Invalid wireless channel '%s'", value);
			g_free (value);
			goto error;
		}
		g_object_set (s_wireless, NM_SETTING_WIRELESS_CHANNEL, (guint32) chan, NULL);
		if (chan > 14)
			g_object_set (s_wireless, NM_SETTING_WIRELESS_BAND, "a", NULL);
		else
			g_object_set (s_wireless, NM_SETTING_WIRELESS_BAND, "bg", NULL);
	}

	value = svGetValue (ifcfg, "MTU", FALSE);
	if (value) {
		long int mtu;

		errno = 0;
		mtu = strtol (value, NULL, 10);
		if (errno || mtu < 0 || mtu > 50000) {
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
			             "Invalid wireless MTU '%s'", value);
			g_free (value);
			goto error;
		}
		g_object_set (s_wireless, NM_SETTING_WIRELESS_MTU, (guint32) mtu, NULL);
	}

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
                                gboolean nm_controlled,
                                char **unmanaged,
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
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Failed to allocate new connection for %s.", file);
		return NULL;
	}

	/* Wireless */
	wireless_setting = make_wireless_setting (ifcfg, nm_controlled, unmanaged, error);
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

	if (nm_controlled) {
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
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Failed to create connection setting.");
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, con_setting);

	/* Don't verify if unmanaged since we may not have an SSID or whatever */
	if (nm_controlled) {
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
                    gboolean nm_controlled,
                    char **unmanaged,
                    NMSetting8021x **s_8021x,
                    GError **error)
{
	NMSettingWired *s_wired;
	char *value = NULL;
	int mtu;
	GByteArray *mac = NULL;
	char *nettype;

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

	if (read_mac_address (ifcfg, "HWADDR", &mac, error)) {
		if (mac) {
			g_object_set (s_wired, NM_SETTING_WIRED_MAC_ADDRESS, mac, NULL);

			/* A connection can only be unmanaged if we know the MAC address */
			if (!nm_controlled) {
				*unmanaged = g_strdup_printf ("mac:%02x:%02x:%02x:%02x:%02x:%02x",
				                              mac->data[0], mac->data[1], mac->data[2],
				                              mac->data[3], mac->data[4], mac->data[5]);
			}

			g_byte_array_free (mac, TRUE);
		}
	} else {
		g_object_unref (s_wired);
		return NULL;
	}

	value = svGetValue (ifcfg, "SUBCHANNELS", FALSE);
	if (value) {
		const char *p = value;
		gboolean success = TRUE;
		char **chans = NULL;

		/* basic sanity checks */
		while (*p) {
			if (!isxdigit (*p) && (*p != ',') && (*p != '.')) {
				PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: invalid SUBCHANNELS '%s'", value);
				success = FALSE;
				break;
			}
			p++;
		}

		if (success) {
			guint32 num_chans;

			chans = g_strsplit_set (value, ",", 0);
			num_chans = g_strv_length (chans);
			if (num_chans < 2 || num_chans > 3) {
				PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: invalid SUBCHANNELS '%s' (%d channels, 2 or 3 expected)",
				             value, g_strv_length (chans));
			} else {
				GPtrArray *array = g_ptr_array_sized_new (num_chans);

				g_ptr_array_add (array, chans[0]);
				g_ptr_array_add (array, chans[1]);
				if (num_chans == 3)
					g_ptr_array_add (array, chans[2]);

				g_object_set (s_wired, NM_SETTING_WIRED_S390_SUBCHANNELS, array, NULL);
				g_ptr_array_free (array, TRUE);

				/* set the unmanaged spec too */
				if (!nm_controlled && !*unmanaged)
					*unmanaged = g_strdup_printf ("s390-subchannels:%s", value);
			}
			g_strfreev (chans);
		}
		g_free (value);
	}

	value = svGetValue (ifcfg, "PORTNAME", FALSE);
	if (value && strlen (value)) {
		nm_setting_wired_add_s390_option (s_wired, "portname", value);
	}
	g_free (value);

	nettype = svGetValue (ifcfg, "NETTYPE", FALSE);
	if (nettype && strlen (nettype)) {
		if (!strcmp (nettype, "qeth") || !strcmp (nettype, "lcs") || !strcmp (nettype, "ctc"))
			g_object_set (s_wired, NM_SETTING_WIRED_S390_NETTYPE, nettype, NULL);
		else
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: unknown s390 NETTYPE '%s'", nettype);
	}

	value = svGetValue (ifcfg, "OPTIONS", FALSE);
	if (value && strlen (value)) {
		char **options, **iter;

		iter = options = g_strsplit_set (value, " ", 0);
		while (iter && *iter) {
			char *equals = strchr (*iter, '=');
			gboolean valid = FALSE;

			if (equals) {
				*equals = '\0';
				valid = nm_setting_wired_add_s390_option (s_wired, *iter, equals + 1);
			}
			if (!valid)
				PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: invalid s390 OPTION '%s'", *iter);
			iter++;
		}
		g_strfreev (options);
	}
	g_free (value);

	g_free (nettype);

	if (!nm_controlled && !*unmanaged) {
		/* If NM_CONTROLLED=no but there wasn't a MAC address or z/VM
		 * subchannels, notify the user that the device cannot be unmanaged.
		 */
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: NM_CONTROLLED was false but HWADDR or SUBCHANNELS was missing; device will be managed");
	}

	mac = NULL;
	if (read_mac_address (ifcfg, "MACADDR", &mac, error)) {
		if (mac) {
			g_object_set (s_wired, NM_SETTING_WIRED_CLONED_MAC_ADDRESS, mac, NULL);
			g_byte_array_free (mac, TRUE);
		}
	}

	value = svGetValue (ifcfg, "KEY_MGMT", FALSE);
	if (value) {
		if (!strcmp (value, "IEEE8021X")) {
			*s_8021x = fill_8021x (ifcfg, file, value, FALSE, error);
			if (!*s_8021x)
				goto error;
		} else {
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
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
                             gboolean nm_controlled,
                             char **unmanaged,
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
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Failed to allocate new connection for %s.", file);
		return NULL;
	}

	con_setting = make_connection_setting (file, ifcfg, NM_SETTING_WIRED_SETTING_NAME, NULL);
	if (!con_setting) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Failed to create connection setting.");
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, con_setting);

	wired_setting = make_wired_setting (ifcfg, file, nm_controlled, unmanaged, &s_8021x, error);
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

enum {
	IGNORE_REASON_NONE = 0x00,
	IGNORE_REASON_BRIDGE = 0x01,
	IGNORE_REASON_VLAN = 0x02,
};

NMConnection *
connection_from_file (const char *filename,
                      const char *network_file,  /* for unit tests only */
                      const char *test_type,     /* for unit tests only */
                      const char *iscsiadm_path, /* for unit tests only */
                      char **unmanaged,
                      char **keyfile,
                      char **routefile,
                      char **route6file,
                      GError **out_error,
                      gboolean *ignore_error)
{
	NMConnection *connection = NULL;
	shvarFile *parsed;
	char *type, *nmc = NULL, *bootproto, *tmp;
	NMSetting *s_ip4, *s_ip6;
	const char *ifcfg_name = NULL;
	gboolean nm_controlled = TRUE;
	gboolean ip6_used = FALSE;
	GError *error = NULL;
	guint32 ignore_reason = IGNORE_REASON_NONE;

	g_return_val_if_fail (filename != NULL, NULL);
	g_return_val_if_fail (unmanaged != NULL, NULL);
	g_return_val_if_fail (*unmanaged == NULL, NULL);
	g_return_val_if_fail (keyfile != NULL, NULL);
	g_return_val_if_fail (*keyfile == NULL, NULL);
	g_return_val_if_fail (routefile != NULL, NULL);
	g_return_val_if_fail (*routefile == NULL, NULL);
	g_return_val_if_fail (route6file != NULL, NULL);
	g_return_val_if_fail (*route6file == NULL, NULL);

	/* Non-NULL only for unit tests; normally use /etc/sysconfig/network */
	if (!network_file)
		network_file = SYSCONFDIR "/sysconfig/network";

	if (!iscsiadm_path)
		iscsiadm_path = SBINDIR "/iscsiadm";

	ifcfg_name = utils_get_ifcfg_name (filename, TRUE);
	if (!ifcfg_name) {
		g_set_error (out_error, IFCFG_PLUGIN_ERROR, 0,
		             "Ignoring connection '%s' because it's not an ifcfg file.", filename);
		return NULL;
	}

	parsed = svNewFile (filename);
	if (!parsed) {
		g_set_error (out_error, IFCFG_PLUGIN_ERROR, 0,
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
			g_set_error (&error, IFCFG_PLUGIN_ERROR, 0,
			             "File '%s' had neither TYPE nor DEVICE keys.", filename);
			goto done;
		}

		if (!strcmp (device, "lo")) {
			if (ignore_error)
				*ignore_error = TRUE;
			g_set_error (&error, IFCFG_PLUGIN_ERROR, 0,
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
			nm_controlled = FALSE;
		g_free (lower);
	}

	/* Ignore BRIDGE= and VLAN= connections for now too (rh #619863) */
	tmp = svGetValue (parsed, "BRIDGE", FALSE);
	if (tmp) {
		g_free (tmp);
		nm_controlled = FALSE;
		ignore_reason = IGNORE_REASON_BRIDGE;
	}

	if (nm_controlled) {
		tmp = svGetValue (parsed, "VLAN", FALSE);
		if (tmp) {
			g_free (tmp);
			nm_controlled = FALSE;
			ignore_reason = IGNORE_REASON_VLAN;
		}
	}

	/* Construct the connection */
	if (!strcasecmp (type, TYPE_ETHERNET))
		connection = wired_connection_from_ifcfg (filename, parsed, nm_controlled, unmanaged, &error);
	else if (!strcasecmp (type, TYPE_WIRELESS))
		connection = wireless_connection_from_ifcfg (filename, parsed, nm_controlled, unmanaged, &error);
	else if (!strcasecmp (type, TYPE_BRIDGE)) {
		g_set_error (&error, IFCFG_PLUGIN_ERROR, 0,
		             "Bridge connections are not yet supported");
	} else {
		g_set_error (&error, IFCFG_PLUGIN_ERROR, 0,
		             "Unknown connection type '%s'", type);
	}

	if (nm_controlled) {
		g_free (*unmanaged);
		*unmanaged = NULL;
	}

	g_free (type);

	/* Don't bother reading the connection fully if it's unmanaged or ignored */
	if (!connection || *unmanaged || ignore_reason) {
		if (connection && !*unmanaged) {
			/* However,BRIDGE and VLAN connections that don't have HWADDR won't
			 * be unmanaged because the unmanaged state is keyed off HWADDR.
			 * They willl still be tagged 'ignore' from code that checks BRIDGE
			 * and VLAN above.  Since they aren't marked unmanaged, kill them
			 * completely.
			 */
			if (ignore_reason) {
				g_object_unref (connection);
				connection = NULL;
				g_set_error (&error, IFCFG_PLUGIN_ERROR, 0,
				             "%s connections are not yet supported",
				             ignore_reason == IGNORE_REASON_BRIDGE ? "Bridge" : "VLAN");
			}
		}
		goto done;
	}

	s_ip6 = make_ip6_setting (parsed, network_file, iscsiadm_path, &error);
	if (error) {
		g_object_unref (connection);
		connection = NULL;
		goto done;
	} else if (s_ip6) {
		const char *method;

		nm_connection_add_setting (connection, s_ip6);
		method = nm_setting_ip6_config_get_method (NM_SETTING_IP6_CONFIG (s_ip6));
		if (method && strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_IGNORE))
			ip6_used = TRUE;
	}

	s_ip4 = make_ip4_setting (parsed, network_file, iscsiadm_path, ip6_used, &error);
	if (error) {
		g_object_unref (connection);
		connection = NULL;
		goto done;
	} else if (s_ip4)
		nm_connection_add_setting (connection, s_ip4);

	/* iSCSI / ibft connections are read-only since their settings are
	 * stored in NVRAM and can only be changed in BIOS.
	 */
	bootproto = svGetValue (parsed, "BOOTPROTO", FALSE);
	if (   bootproto
	    && connection
	    && !g_ascii_strcasecmp (bootproto, "ibft")) {
		NMSettingConnection *s_con;

		s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
		g_assert (s_con);

		g_object_set (G_OBJECT (s_con), NM_SETTING_CONNECTION_READ_ONLY, TRUE, NULL);
	}

	if (!nm_connection_verify (connection, &error)) {
		g_object_unref (connection);
		connection = NULL;
	}

	*keyfile = utils_get_keys_path (filename);
	*routefile = utils_get_route_path (filename);
	*route6file = utils_get_route6_path (filename);

done:
	svCloseFile (parsed);
	if (error && out_error)
		*out_error = error;
	else
		g_clear_error (&error);
	return connection;
}

const char *
reader_get_prefix (void)
{
	return _("System");
}

