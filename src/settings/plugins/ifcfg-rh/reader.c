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
 * Copyright (C) 2008 - 2012 Red Hat, Inc.
 */

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/inotify.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <netinet/ether.h>
#include <linux/if.h>

#include <glib.h>
#include <glib/gi18n.h>
#include <nm-connection.h>
#include <NetworkManager.h>
#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>
#include <nm-setting-vlan.h>
#include <nm-setting-ip6-config.h>
#include <nm-setting-wired.h>
#include <nm-setting-wireless.h>
#include <nm-setting-8021x.h>
#include <nm-setting-bond.h>
#include <nm-setting-bridge.h>
#include <nm-setting-bridge-port.h>
#include <nm-utils.h>

#include "wifi-utils.h"
#include "nm-posix-signals.h"

#include "common.h"
#include "shvar.h"
#include "utils.h"

#include "reader.h"

#define PLUGIN_PRINT(pname, fmt, args...) \
	{ g_message ("   " pname ": " fmt, ##args); }

#define PLUGIN_WARN(pname, fmt, args...) \
	{ g_warning ("   " pname ": " fmt, ##args); }

static gboolean
get_int (const char *str, int *value)
{
	char *e;
	long int tmp;

	errno = 0;
	tmp = strtol (str, &e, 0);
	if (errno || *e != '\0')
		return FALSE;
	*value = (int) tmp;
	return TRUE;
}

static gboolean
get_uint (const char *str, guint32 *value)
{
	char *e;
	long unsigned int tmp;

	errno = 0;
	tmp = strtoul (str, &e, 0);
	if (errno || *e != '\0')
		return FALSE;
	*value = (guint32) tmp;
	return TRUE;
}

static char *
make_connection_name (shvarFile *ifcfg,
                      const char *ifcfg_name,
                      const char *suggested,
                      const char *prefix)
{
	char *full_name = NULL, *name;

	/* If the ifcfg file already has a NAME, always use that */
	name = svGetValue (ifcfg, "NAME", FALSE);
	if (name && strlen (name))
		return name;

	/* Otherwise construct a new NAME */
	g_free (name);
	if (!prefix)
		prefix = _("System");

	/* For cosmetic reasons, if the suggested name is the same as
	 * the ifcfg files name, don't use it.  Mainly for wifi so that
	 * the SSID is shown in the connection ID instead of just "wlan0".
	 */
	if (suggested && strcmp (ifcfg_name, suggested))
		full_name = g_strdup_printf ("%s %s (%s)", prefix, suggested, ifcfg_name);
	else
		full_name = g_strdup_printf ("%s %s", prefix, ifcfg_name);

	return full_name;
}

static NMSetting *
make_connection_setting (const char *file,
                         shvarFile *ifcfg,
                         const char *type,
                         const char *suggested,
                         const char *prefix)
{
	NMSettingConnection *s_con;
	const char *ifcfg_name = NULL;
	char *new_id, *uuid = NULL, *zone = NULL, *value;

	ifcfg_name = utils_get_ifcfg_name (file, TRUE);
	if (!ifcfg_name)
		return NULL;

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());

	new_id = make_connection_name (ifcfg, ifcfg_name, suggested, prefix);
	g_object_set (s_con, NM_SETTING_CONNECTION_ID, new_id, NULL);
	g_free (new_id);

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

	value = svGetValue (ifcfg, "DEVICE", FALSE);
	if (value) {
		if (nm_utils_iface_valid_name (value)) {
			g_object_set (s_con,
			              NM_SETTING_CONNECTION_INTERFACE_NAME, value,
			              NULL);
		} else
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: invalid DEVICE name '%s'", value);
		g_free (value);
	}

	/* Missing ONBOOT is treated as "ONBOOT=true" by the old network service */
	g_object_set (s_con, NM_SETTING_CONNECTION_AUTOCONNECT,
	              svTrueValue (ifcfg, "ONBOOT", TRUE),
	              NULL);

	value = svGetValue (ifcfg, "USERS", FALSE);
	if (value) {
		char **items, **iter;

		items = g_strsplit_set (value, " ", -1);
		for (iter = items; iter && *iter; iter++) {
			if (strlen (*iter)) {
				if (!nm_setting_connection_add_permission (s_con, "user", *iter, NULL))
					PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: invalid USERS item '%s'", *iter);
			}
		}
		g_free (value);
		g_strfreev (items);
	}


	zone = svGetValue(ifcfg, "ZONE", FALSE);
	if (!zone || !strlen (zone)) {
		g_free (zone);
		zone = NULL;
	}
	g_object_set (s_con, NM_SETTING_CONNECTION_ZONE, zone, NULL);
	g_free (zone);

	value = svGetValue (ifcfg, "SECONDARY_UUIDS", FALSE);
	if (value) {
		char **items, **iter;

		items = g_strsplit_set (value, " \t", -1);
		for (iter = items; iter && *iter; iter++) {
			if (strlen (*iter)) {
				if (!nm_setting_connection_add_secondary (s_con, *iter))
					PLUGIN_WARN (IFCFG_PLUGIN_NAME,
					             "    warning: secondary connection UUID '%s' already added", *iter);
			}
		}
		g_free (value);
		g_strfreev (items);
	}

	value = svGetValue (ifcfg, "BRIDGE", FALSE);
	if (value) {
		const char *bridge;

		if ((bridge = nm_setting_connection_get_master (s_con))) {
			PLUGIN_WARN (IFCFG_PLUGIN_NAME,
			             "     warning: Already configured as slave of %s. "
			             "Ignoring BRIDGE=\"%s\"", bridge, value);
			g_free (value);
		}

		g_object_set (s_con, NM_SETTING_CONNECTION_MASTER, value, NULL);
		g_object_set (s_con, NM_SETTING_CONNECTION_SLAVE_TYPE,
		              NM_SETTING_BRIDGE_SETTING_NAME, NULL);
		g_free (value);
	}

	value = svGetValue (ifcfg, "GATEWAY_PING_TIMEOUT", FALSE);
	if (value) {
		long int tmp;
		guint32 timeout;

		errno = 0;
		tmp = strtol (value, NULL, 10);
		if (errno == 0 && tmp >= 0 && tmp < G_MAXINT32) {
			timeout = (guint32) tmp;
			g_object_set (s_con, NM_SETTING_CONNECTION_GATEWAY_PING_TIMEOUT, timeout, NULL);
		} else
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: invalid GATEWAY_PING_TIMEOUT time");
		g_free (value);
	}

	return NM_SETTING (s_con);
}

static gboolean
read_mac_address (shvarFile *ifcfg, const char *key, int type,
                  GByteArray **array, GError **error)
{
	char *value = NULL;

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

	*array = nm_utils_hwaddr_atoba (value, type);
	if (!*array) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "%s: the MAC address '%s' was invalid.", key, value);
		g_free (value);
		return FALSE;
	}

	g_free (value);
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

	/*
	 * We blocked signals in main(). We need to restore original signal
	 * mask for iscsiadm here so that it can receive signals.
	 */
	nm_unblock_posix_signals (NULL);
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
	guint32 ipaddr;
	guint32 gateway;
	guint32 dns1;
	guint32 dns2;
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

	if (!read_mac_address (ifcfg, "HWADDR", ARPHRD_ETHER, &ifcfg_mac, error))
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
					goto done;
				}

				g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, method, NULL);

				if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_MANUAL)) {
					NMIP4Address *addr;

				    if (!ipaddr || !prefix) {
						g_warning ("%s: malformed iscsiadm record: BOOTPROTO=static "
						           "but missing IP address or prefix.", __func__);
						goto done;
					}

					addr = nm_ip4_address_new ();
					nm_ip4_address_set_address (addr, ipaddr);
					nm_ip4_address_set_prefix (addr, prefix);
					nm_ip4_address_set_gateway (addr, gateway);
					nm_setting_ip4_config_add_address (s_ip4, addr);
					nm_ip4_address_unref (addr);

					if (dns1)
						nm_setting_ip4_config_add_dns (s_ip4, dns1);
					if (dns2)
						nm_setting_ip4_config_add_dns (s_ip4, dns2);

					// FIXME: DNS search domains?
				}
				success = TRUE;
				goto done;
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
			guint32 mask;

			if (inet_pton (AF_INET, p, &mask) < 1) {
				g_warning ("%s: malformed iscsiadm record: invalid subnet mask '%s'.",
				           __func__, p);
				skip = TRUE;
				continue;
			}

			prefix = nm_utils_ip4_netmask_to_prefix (mask);
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

/* Returns TRUE on missing address or valid address */
static gboolean
read_ip4_address (shvarFile *ifcfg,
                  const char *tag,
                  guint32 *out_addr,
                  GError **error)
{
	char *value = NULL;
	guint32 ip4_addr;
	gboolean success = FALSE;

	g_return_val_if_fail (ifcfg != NULL, FALSE);
	g_return_val_if_fail (tag != NULL, FALSE);
	g_return_val_if_fail (out_addr != NULL, FALSE);
	if (error)
		g_return_val_if_fail (*error == NULL, FALSE);

	*out_addr = 0;

	value = svGetValue (ifcfg, tag, FALSE);
	if (!value)
		return TRUE;

	if (inet_pton (AF_INET, value, &ip4_addr) > 0) {
		*out_addr = ip4_addr;
		success = TRUE;
	} else {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Invalid %s IP4 address '%s'", tag, value);
	}
	g_free (value);
	return success;
}

/* Returns TRUE on valid address, including unspecified (::) */
static gboolean
parse_ip6_address (const char *value,
                   struct in6_addr *out_addr,
                   GError **error)
{
	struct in6_addr ip6_addr;

	g_return_val_if_fail (value != NULL, FALSE);
	g_return_val_if_fail (out_addr != NULL, FALSE);
	if (error)
		g_return_val_if_fail (*error == NULL, FALSE);

	*out_addr = in6addr_any;
	if (inet_pton (AF_INET6, value, &ip6_addr) <= 0) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Invalid IP6 address '%s'", value);
		return FALSE;
	}

	*out_addr = ip6_addr;
	return TRUE;
}

/* Returns TRUE on missing address or valid address */
static gboolean
read_full_ip4_address (shvarFile *ifcfg,
                       const char *network_file,
                       gint32 which,
                       NMIP4Address **out_address,
                       GError **error)
{
	NMIP4Address *addr;
	char *ip_tag, *prefix_tag, *netmask_tag, *gw_tag;
	guint32 tmp;
	gboolean success = FALSE;
	shvarFile *network_ifcfg;
	char *value;

	g_return_val_if_fail (which >= -1, FALSE);
	g_return_val_if_fail (ifcfg != NULL, FALSE);
	g_return_val_if_fail (network_file != NULL, FALSE);
	g_return_val_if_fail (out_address != NULL, FALSE);
	g_return_val_if_fail (*out_address == NULL, FALSE);
	if (error)
		g_return_val_if_fail (*error == NULL, FALSE);

	addr = nm_ip4_address_new ();
	if (which == -1) {
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
		goto done;
	if (!tmp) {
		nm_ip4_address_unref (addr);
		addr = NULL;
		success = TRUE;  /* done */
		goto done;
	}
	nm_ip4_address_set_address (addr, tmp);

	/* Gateway */
	if (!read_ip4_address (ifcfg, gw_tag, &tmp, error))
		goto done;
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
				goto done;
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
			goto done;
		}
		nm_ip4_address_set_prefix (addr, (guint32) prefix);
		g_free (value);
	}

	/* Fall back to NETMASK if no PREFIX was specified */
	if (!nm_ip4_address_get_prefix (addr)) {
		if (!read_ip4_address (ifcfg, netmask_tag, &tmp, error))
			goto done;
		if (tmp)
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
		goto done;
	}

	*out_address = addr;
	success = TRUE;

done:
	if (!success && addr)
		nm_ip4_address_unref (addr);

	g_free (ip_tag);
	g_free (prefix_tag);
	g_free (netmask_tag);
	g_free (gw_tag);

	return success;
}

/* Returns TRUE on missing route or valid route */
static gboolean
read_one_ip4_route (shvarFile *ifcfg,
                    const char *network_file,
                    guint32 which,
                    NMIP4Route **out_route,
                    GError **error)
{
	NMIP4Route *route;
	char *ip_tag, *netmask_tag, *gw_tag, *metric_tag, *value;
	guint32 tmp;
	gboolean success = FALSE;

	g_return_val_if_fail (ifcfg != NULL, FALSE);
	g_return_val_if_fail (network_file != NULL, FALSE);
	g_return_val_if_fail (out_route != NULL, FALSE);
	g_return_val_if_fail (*out_route == NULL, FALSE);
	if (error)
		g_return_val_if_fail (*error == NULL, FALSE);

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
			success = TRUE;  /* missing route = success */
			goto out;
		}
		g_free (val);
	}
	nm_ip4_route_set_dest (route, tmp);

	/* Next hop */
	if (!read_ip4_address (ifcfg, gw_tag, &tmp, error))
		goto out;
	/* No need to check tmp, because we don't make distinction between missing GATEWAY IP and 0.0.0.0 */
	nm_ip4_route_set_next_hop (route, tmp);

	/* Prefix */
	if (!read_ip4_address (ifcfg, netmask_tag, &tmp, error))
		goto out;
	if (tmp)
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

	*out_route = route;
	success = TRUE;

out:
	if (!success && route)
		nm_ip4_route_unref (route);

	g_free (ip_tag);
	g_free (netmask_tag);
	g_free (gw_tag);
	g_free (metric_tag);
	return success;
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
	guint32 ip4_addr;
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
	if (error)
		g_return_val_if_fail (*error == NULL, FALSE);

	/* Read the route file */
	if (!g_file_get_contents (filename, &contents, &len, NULL) || !len) {
		g_free (contents);
		return TRUE;  /* missing/empty = success */
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
		if (!strcmp (dest, "default"))
			strcpy (dest, "0.0.0.0");
		if (inet_pton (AF_INET, dest, &ip4_addr) != 1) {
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
				     "Invalid IP4 route destination address '%s'", dest);
			g_free (dest);
			goto error;
		}
		nm_ip4_route_set_dest (route, ip4_addr);
		g_free (dest);

		/* Prefix - is optional; 32 if missing */
		prefix = g_match_info_fetch (match_info, 2);
		g_match_info_free (match_info);
		prefix_int = 32;
		if (prefix) {
			errno = 0;
			prefix_int = strtol (prefix, NULL, 10);
			if (errno || prefix_int <= 0 || prefix_int > 32) {
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
		nm_ip4_route_set_next_hop (route, ip4_addr);
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

static gboolean
parse_full_ip6_address (shvarFile *ifcfg,
                        const char *network_file,
                        const char *addr_str,
                        int i,
                        NMIP6Address **out_address,
                        GError **error)
{
	NMIP6Address *addr = NULL;
	char **list;
	char *ip_val, *prefix_val;
	shvarFile *network_ifcfg;
	char *value = NULL;
	struct in6_addr tmp = IN6ADDR_ANY_INIT;
	gboolean success = FALSE;

	g_return_val_if_fail (addr_str != NULL, FALSE);
	g_return_val_if_fail (out_address != NULL, FALSE);
	g_return_val_if_fail (*out_address == NULL, FALSE);
	if (error)
		g_return_val_if_fail (*error == NULL, FALSE);

	/* Split the address and prefix */
	list = g_strsplit_set (addr_str, "/", 2);
	if (g_strv_length (list) < 1) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Invalid IP6 address '%s'", addr_str);
		goto error;
	}

	ip_val = list[0];
	prefix_val = list[1];

	addr = nm_ip6_address_new ();
	/* IP address */
	if (!parse_ip6_address (ip_val, &tmp, error))
		goto error;
	if (IN6_IS_ADDR_UNSPECIFIED (&tmp)) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Invalid IP6 address '%s'", ip_val);
		goto error;
	}
	nm_ip6_address_set_address (addr, &tmp);

	/* Prefix */
	if (prefix_val) {
		long int prefix;

		errno = 0;
		prefix = strtol (prefix_val, NULL, 10);
		if (errno || prefix <= 0 || prefix > 128) {
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
			             "Invalid IP6 prefix '%s'", prefix_val);
			goto error;
		}
		nm_ip6_address_set_prefix (addr, (guint32) prefix);
	} else {
		/* Missing prefix is treated as prefix of 64 */
		nm_ip6_address_set_prefix (addr, 64);
	}

	/* Gateway */
	tmp = in6addr_any;
	value = svGetValue (ifcfg, "IPV6_DEFAULTGW", FALSE);
	if (i != 0) {
		/* We don't support gateways for IPV6ADDR_SECONDARIES yet */
		g_free (value);
		value = NULL;
	}
	if (!value) {
		/* If no gateway in the ifcfg, try global /etc/sysconfig/network instead */
		network_ifcfg = svNewFile (network_file);
		if (network_ifcfg) {
			value = svGetValue (network_ifcfg, "IPV6_DEFAULTGW", FALSE);
			svCloseFile (network_ifcfg);
		}
	}
	if (value) {
		char *ptr;

		if ((ptr = strchr (value, '%')) != NULL)
			*ptr = '\0';  /* remove %interface prefix if present */
		if (!parse_ip6_address (value, &tmp, error))
			goto error;
		nm_ip6_address_set_gateway (addr, &tmp);
	}

	*out_address = addr;
	success = TRUE;

error:
	if (!success && addr)
		nm_ip6_address_unref (addr);

	g_strfreev (list);
	g_free (value);
	return success;
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
	                          "(?:/(\\d{1,3}))?";                   /* optional prefix */
	const char *pattern_to2 = "to\\s+(" IPV6_ADDR_REGEX "|default)" /* IPv6 or 'default' keyword */
	                          "(?:/(\\d{1,3}))?";                   /* optional prefix */
	const char *pattern_via = "via\\s+(" IPV6_ADDR_REGEX ")";       /* IPv6 of gateway */
	const char *pattern_metric = "metric\\s+(\\d+)";                /* metric */

	g_return_val_if_fail (filename != NULL, FALSE);
	g_return_val_if_fail (s_ip6 != NULL, FALSE);
	if (error)
		g_return_val_if_fail (*error == NULL, FALSE);

	/* Read the route file */
	if (!g_file_get_contents (filename, &contents, &len, NULL) || !len) {
		g_free (contents);
		return TRUE;  /* missing/empty = success */
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
		g_match_info_free (match_info);
		prefix_int = 128;
		if (prefix) {
			errno = 0;
			prefix_int = strtol (prefix, NULL, 10);
			if (errno || prefix_int <= 0 || prefix_int > 128) {
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
                  gboolean can_disable_ip4,
                  GError **error)
{
	NMSettingIP4Config *s_ip4 = NULL;
	char *value = NULL;
	char *route_path = NULL;
	char *method = NM_SETTING_IP4_CONFIG_METHOD_MANUAL;
	gint32 i;
	shvarFile *network_ifcfg;
	shvarFile *route_ifcfg;
	gboolean never_default = FALSE;

	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();

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
			g_free (value);
			g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_NEVER_DEFAULT, never_default, NULL);
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
		char *tmp_ip4_0, *tmp_prefix_0, *tmp_netmask_0;
		char *tmp_ip4_1, *tmp_prefix_1, *tmp_netmask_1;
		char *tmp_ip4_2, *tmp_prefix_2, *tmp_netmask_2;

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
		tmp_ip4_0 = svGetValue (ifcfg, "IPADDR0", FALSE);
		tmp_prefix_0 = svGetValue (ifcfg, "PREFIX0", FALSE);
		tmp_netmask_0 = svGetValue (ifcfg, "NETMASK0", FALSE);
		tmp_ip4_1 = svGetValue (ifcfg, "IPADDR1", FALSE);
		tmp_prefix_1 = svGetValue (ifcfg, "PREFIX1", FALSE);
		tmp_netmask_1 = svGetValue (ifcfg, "NETMASK1", FALSE);
		tmp_ip4_2 = svGetValue (ifcfg, "IPADDR2", FALSE);
		tmp_prefix_2 = svGetValue (ifcfg, "PREFIX2", FALSE);
		tmp_netmask_2 = svGetValue (ifcfg, "NETMASK2", FALSE);
		if (   !tmp_ip4   && !tmp_prefix   && !tmp_netmask
		    && !tmp_ip4_0 && !tmp_prefix_0 && !tmp_netmask_0
		    && !tmp_ip4_1 && !tmp_prefix_1 && !tmp_netmask_1
		    && !tmp_ip4_2 && !tmp_prefix_2 && !tmp_netmask_2) {
			if (can_disable_ip4)
				/* Nope, no IPv4 */
				method = NM_SETTING_IP4_CONFIG_METHOD_DISABLED;
			else
				method = NM_SETTING_IP4_CONFIG_METHOD_AUTO;
		}
		g_free (tmp_ip4);
		g_free (tmp_prefix);
		g_free (tmp_netmask);
		g_free (tmp_ip4_0);
		g_free (tmp_prefix_0);
		g_free (tmp_netmask_0);
		g_free (tmp_ip4_1);
		g_free (tmp_prefix_1);
		g_free (tmp_netmask_1);
		g_free (tmp_ip4_2);
		g_free (tmp_prefix_2);
		g_free (tmp_netmask_2);
	}

	g_object_set (s_ip4,
	              NM_SETTING_IP4_CONFIG_METHOD, method,
	              NM_SETTING_IP4_CONFIG_IGNORE_AUTO_DNS, !svTrueValue (ifcfg, "PEERDNS", TRUE),
	              NM_SETTING_IP4_CONFIG_IGNORE_AUTO_ROUTES, !svTrueValue (ifcfg, "PEERROUTES", TRUE),
	              NM_SETTING_IP4_CONFIG_NEVER_DEFAULT, never_default,
	              NM_SETTING_IP4_CONFIG_MAY_FAIL, !svTrueValue (ifcfg, "IPV4_FAILURE_FATAL", FALSE),
	              NULL);

	if (strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED) == 0)
		return NM_SETTING (s_ip4);

	/* Handle manual settings */
	if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_MANUAL)) {
		for (i = -1; i < 256; i++) {
			NMIP4Address *addr = NULL;

			if (!read_full_ip4_address (ifcfg, network_file, i, &addr, error))
				goto done;
			if (!addr) {
				/* The first mandatory variable is 2-indexed (IPADDR2)
				 * Variables IPADDR, IPADDR0 and IPADDR1 are optional */
				if (i > 1)
					break;
				continue;
			}

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
	for (i = 1; i <= 10; i++) {
		char *tag;
		guint32 dns;
		struct in6_addr ip6_dns;

		tag = g_strdup_printf ("DNS%u", i);
		if (!read_ip4_address (ifcfg, tag, &dns, error)) {
			gboolean valid = TRUE;

			/* Ignore IPv6 addresses */
			dns = 0;
			value = svGetValue (ifcfg, tag, FALSE);
			if (value)
				valid = parse_ip6_address (value, &ip6_dns, NULL);
			g_free (value);

			if (!valid) {
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
		route_ifcfg = utils_get_route_ifcfg (ifcfg->fileName, FALSE);
		if (route_ifcfg) {
			for (i = 0; i < 256; i++) {
				NMIP4Route *route = NULL;

				if (!read_one_ip4_route (route_ifcfg, network_file, i, &route, error)) {
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
		if (!read_route_file_legacy (route_path, s_ip4, error))
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
	g_free (route_path);
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
	gboolean ipv6init, ipv6forwarding, ipv6_autoconf, dhcp6 = FALSE;
	char *method = NM_SETTING_IP6_CONFIG_METHOD_MANUAL;
	guint32 i;
	shvarFile *network_ifcfg;
	gboolean never_default = FALSE;
	gboolean ip6_privacy = FALSE, ip6_privacy_prefer_public_ip;
	char *ip6_privacy_str;
	NMSettingIP6ConfigPrivacy ip6_privacy_val;

	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();

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
	/* Is IPV6 enabled? Set method to "ignored", when not enabled */
	str_value = svGetValue (ifcfg, "IPV6INIT", FALSE);
	ipv6init = svTrueValue (ifcfg, "IPV6INIT", FALSE);
	if (!str_value) {
		network_ifcfg = svNewFile (network_file);
		if (network_ifcfg) {
			ipv6init = svTrueValue (network_ifcfg, "IPV6INIT", FALSE);
			svCloseFile (network_ifcfg);
		}
	}
	g_free (str_value);

	if (!ipv6init)
		method = NM_SETTING_IP6_CONFIG_METHOD_IGNORE;  /* IPv6 is disabled */
	else {
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
	}
	/* TODO - handle other methods */

	/* Read IPv6 Privacy Extensions configuration */
	ip6_privacy_str = svGetValue (ifcfg, "IPV6_PRIVACY", FALSE);
	if (ip6_privacy_str) {
		ip6_privacy = svTrueValue (ifcfg, "IPV6_PRIVACY", FALSE);
		if (!ip6_privacy)
			ip6_privacy = g_strcmp0 (ip6_privacy_str, "rfc4941") == 0 ||
			              g_strcmp0 (ip6_privacy_str, "rfc3041") == 0;
	}
	ip6_privacy_prefer_public_ip = svTrueValue (ifcfg, "IPV6_PRIVACY_PREFER_PUBLIC_IP", FALSE);
	ip6_privacy_val = ip6_privacy_str ?
	                      (ip6_privacy ?
	                          (ip6_privacy_prefer_public_ip ? NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_PUBLIC_ADDR : NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR) :
	                          NM_SETTING_IP6_CONFIG_PRIVACY_DISABLED) :
	                      NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN;
	g_free (ip6_privacy_str);

	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, method,
	              NM_SETTING_IP6_CONFIG_IGNORE_AUTO_DNS, !svTrueValue (ifcfg, "IPV6_PEERDNS", TRUE),
	              NM_SETTING_IP6_CONFIG_IGNORE_AUTO_ROUTES, !svTrueValue (ifcfg, "IPV6_PEERROUTES", TRUE),
	              NM_SETTING_IP6_CONFIG_NEVER_DEFAULT, never_default,
	              NM_SETTING_IP6_CONFIG_MAY_FAIL, !svTrueValue (ifcfg, "IPV6_FAILURE_FATAL", FALSE),
	              NM_SETTING_IP6_CONFIG_IP6_PRIVACY, ip6_privacy_val,
	              NULL);

	/* Don't bother to read IP, DNS and routes when IPv6 is disabled */
	if (strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_IGNORE) == 0)
		return NM_SETTING (s_ip6);

	if (!strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_MANUAL)) {
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
		for (iter = list, i = 0; iter && *iter; iter++, i++) {
			NMIP6Address *addr = NULL;

			if (!parse_full_ip6_address (ifcfg, network_file, *iter, i, &addr, error)) {
				g_strfreev (list);
				goto error;
			}

			if (!nm_setting_ip6_config_add_address (s_ip6, addr))
				PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: duplicate IP6 address");
			nm_ip6_address_unref (addr);
		}
		g_strfreev (list);
	} else if (   !strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_AUTO)
	           || !strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_DHCP)) {
		/* METHOD_AUTO may trigger DHCPv6, so save the hostname to send to DHCP */
		value = svGetValue (ifcfg, "DHCP_HOSTNAME", FALSE);
		if (value && value[0])
			g_object_set (s_ip6, NM_SETTING_IP6_CONFIG_DHCP_HOSTNAME, value, NULL);
		g_free (value);
	}

	/* DNS servers
	 * Pick up just IPv6 addresses (IPv4 addresses are taken by make_ip4_setting())
	 */
	for (i = 1; i <= 10; i++) {
		char *tag;
		struct in6_addr ip6_dns;
		guint32 ip4_addr;

		tag = g_strdup_printf ("DNS%u", i);
		value = svGetValue (ifcfg, tag, FALSE);
		if (!value) {
			g_free (tag);
			break; /* all done */
		}

		ip6_dns = in6addr_any;
		if (parse_ip6_address (value, &ip6_dns, NULL)) {
			if (!IN6_IS_ADDR_UNSPECIFIED (&ip6_dns) && !nm_setting_ip6_config_add_dns (s_ip6, &ip6_dns))
				PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: duplicate DNS server %s", tag);
		} else {
			/* Maybe an IPv4 address? If so ignore it */
			if (inet_pton (AF_INET, value, &ip4_addr) != 1) {
				g_free (tag);
				g_free (value);
				PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: duplicate IP6 address");
				goto error;
			}
		}

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

	if (!read_route6_file (route6_path, s_ip6, error))
		goto error;

	g_free (route6_path);
	return NM_SETTING (s_ip6);

error:
	g_free (route6_path);
	g_object_unref (s_ip6);
	return NULL;
}

static void
check_if_bond_slave (shvarFile *ifcfg,
                     NMSettingConnection *s_con)
{
	char *value;

	value = svGetValue (ifcfg, "MASTER", FALSE);
	if (value) {
		g_object_set (s_con, NM_SETTING_CONNECTION_MASTER, value, NULL);
		g_object_set (s_con,
		              NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_BOND_SETTING_NAME,
		              NULL);
		g_free (value);
	}
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
				if (!g_ascii_isprint ((int) (*p))) {
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
		g_free (key);
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

static NMSettingSecretFlags
read_secret_flags (shvarFile *ifcfg, const char *flags_key)
{
	NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;
	char *val;

	g_return_val_if_fail (flags_key != NULL, NM_SETTING_SECRET_FLAG_NONE);
	g_return_val_if_fail (flags_key[0] != '\0', NM_SETTING_SECRET_FLAG_NONE);
	g_return_val_if_fail (g_str_has_suffix (flags_key, "_FLAGS"), NM_SETTING_SECRET_FLAG_NONE);

	val = svGetValue (ifcfg, flags_key, FALSE);
	if (val) {
		if (strstr (val, SECRET_FLAG_AGENT))
			flags |= NM_SETTING_SECRET_FLAG_AGENT_OWNED;
		if (strstr (val, SECRET_FLAG_NOT_SAVED))
			flags |= NM_SETTING_SECRET_FLAG_NOT_SAVED;
		if (strstr (val, SECRET_FLAG_NOT_REQUIRED))
			flags |= NM_SETTING_SECRET_FLAG_NOT_REQUIRED;

		g_free (val);
	}
	return flags;
}

static NMSetting *
make_wep_setting (shvarFile *ifcfg,
                  const char *file,
                  GError **error)
{
	NMSettingWirelessSecurity *s_wsec;
	char *value;
	shvarFile *keys_ifcfg = NULL;
	int default_key_idx = 0;
	gboolean has_default_key = FALSE, success;
	NMSettingSecretFlags key_flags;

	s_wsec = NM_SETTING_WIRELESS_SECURITY (nm_setting_wireless_security_new ());
	g_object_set (s_wsec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "none", NULL);

	value = svGetValue (ifcfg, "DEFAULTKEY", FALSE);
	if (value) {
		success = get_int (value, &default_key_idx);
		if (success && (default_key_idx >= 1) && (default_key_idx <= 4)) {
			has_default_key = TRUE;
			default_key_idx--;  /* convert to [0...3] */
			g_object_set (s_wsec, NM_SETTING_WIRELESS_SECURITY_WEP_TX_KEYIDX, default_key_idx, NULL);
		} else {
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
			             "Invalid default WEP key '%s'", value);
	 		g_free (value);
			goto error;
		}
 		g_free (value);
	}

	/* Read WEP key flags */
	key_flags = read_secret_flags (ifcfg, "WEP_KEY_FLAGS");
	g_object_set (s_wsec, NM_SETTING_WIRELESS_SECURITY_WEP_KEY_FLAGS, key_flags, NULL);

	/* Read keys in the ifcfg file if they are system-owned */
	if (key_flags == NM_SETTING_SECRET_FLAG_NONE) {
		if (!read_wep_keys (ifcfg, default_key_idx, s_wsec, error))
			goto error;

		/* Try to get keys from the "shadow" key file */
		keys_ifcfg = utils_get_keys_ifcfg (file, FALSE);
		if (keys_ifcfg) {
			if (!read_wep_keys (keys_ifcfg, default_key_idx, s_wsec, error)) {
				svCloseFile (keys_ifcfg);
				goto error;
			}
			svCloseFile (keys_ifcfg);
			g_assert (error == NULL || *error == NULL);
		}
	}

	value = svGetValue (ifcfg, "SECURITYMODE", FALSE);
	if (value) {
		char *lcase;

		lcase = g_ascii_strdown (value, -1);
		g_free (value);

		if (!strcmp (lcase, "open")) {
			g_object_set (s_wsec, NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "open", NULL);
		} else if (!strcmp (lcase, "restricted")) {
			g_object_set (s_wsec, NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "shared", NULL);
		} else {
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
			             "Invalid WEP authentication algorithm '%s'",
			             lcase);
			g_free (lcase);
			goto error;
		}
		g_free (lcase);
	}

	/* If no WEP keys were given, and the keys are not agent-owned, and no
	 * default WEP key index was given, then the connection is unencrypted.
	 */
	if (   !nm_setting_wireless_security_get_wep_key (s_wsec, 0)
	    && !nm_setting_wireless_security_get_wep_key (s_wsec, 1)
	    && !nm_setting_wireless_security_get_wep_key (s_wsec, 2)
	    && !nm_setting_wireless_security_get_wep_key (s_wsec, 3)
	    && (has_default_key == FALSE)
	    && (key_flags == NM_SETTING_SECRET_FLAG_NONE)) {
		const char *auth_alg;

		auth_alg = nm_setting_wireless_security_get_auth_alg (s_wsec);
		if (auth_alg && !strcmp (auth_alg, "shared")) {
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
			             "WEP Shared Key authentication is invalid for "
			             "unencrypted connections.");
			goto error;
		}

		/* Unencrypted */
		g_object_unref (s_wsec);
		s_wsec = NULL;
	}

	return (NMSetting *) s_wsec;

error:
	if (s_wsec)
		g_object_unref (s_wsec);
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
	size_t plen;
	gboolean quoted = FALSE;

	/* Passphrase must be between 10 and 66 characters in length because WPA
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

	if (!psk)
		return NULL;

	p = psk;
	plen = strlen (p);

	if (   (plen >= 2 && (p[0] == '"' || p[0] == '\'') && p[0] == p[plen - 1])
	    || (plen >= 3 && p[0] == '$' && p[1] == '\'' && p[1] == p[plen - 1]))
		quoted = TRUE;

	if (!quoted && (strlen (psk) == 64)) {
		/* Verify the hex PSK; 64 digits */
		while (*p) {
			if (!g_ascii_isxdigit (*p++)) {
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

		/* Get rid of the quotes */
		hashed = utils_single_unquote_string (p);

		/* Length check */
		if (strlen (hashed) < 8 || strlen (hashed) > 63) {
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
			             "Invalid WPA_PSK (passphrases must be between "
			             "8 and 63 characters long (inclusive))");
			g_free (hashed);
			hashed = NULL;
			goto out;
		}
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

static gboolean
eap_simple_reader (const char *eap_method,
                   shvarFile *ifcfg,
                   shvarFile *keys,
                   NMSetting8021x *s_8021x,
                   gboolean phase2,
                   GError **error)
{
	NMSettingSecretFlags flags;
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

	flags = read_secret_flags (ifcfg, "IEEE_8021X_PASSWORD_FLAGS");
	g_object_set (s_8021x, NM_SETTING_802_1X_PASSWORD_FLAGS, flags, NULL);

	/* Only read the password if it's system-owned */
	if (flags == NM_SETTING_SECRET_FLAG_NONE) {
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
	}

	return TRUE;
}

static char *
get_full_file_path (const char *ifcfg_path, const char *file_path)
{
	const char *base = file_path;
	char *p, *ret, *dirname;

	g_return_val_if_fail (ifcfg_path != NULL, NULL);
	g_return_val_if_fail (file_path != NULL, NULL);

	if (file_path[0] == '/')
		return g_strdup (file_path);

	p = strrchr (file_path, '/');
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
	const char *ca_cert_key = phase2 ? "IEEE_8021X_INNER_CA_CERT" : "IEEE_8021X_CA_CERT";
	const char *pk_pw_key = phase2 ? "IEEE_8021X_INNER_PRIVATE_KEY_PASSWORD": "IEEE_8021X_PRIVATE_KEY_PASSWORD";
	const char *pk_key = phase2 ? "IEEE_8021X_INNER_PRIVATE_KEY" : "IEEE_8021X_PRIVATE_KEY";
	const char *cli_cert_key = phase2 ? "IEEE_8021X_INNER_CLIENT_CERT" : "IEEE_8021X_CLIENT_CERT";
	const char *pk_pw_flags_key = phase2 ? "IEEE_8021X_INNER_PRIVATE_KEY_PASSWORD_FLAGS": "IEEE_8021X_PRIVATE_KEY_PASSWORD_FLAGS";
	const char *pk_pw_flags_prop = phase2 ? NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD_FLAGS : NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD_FLAGS;
	NMSettingSecretFlags flags;

	value = svGetValue (ifcfg, "IEEE_8021X_IDENTITY", FALSE);
	if (!value) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Missing IEEE_8021X_IDENTITY for EAP method '%s'.",
		             eap_method);
		return FALSE;
	}
	g_object_set (s_8021x, NM_SETTING_802_1X_IDENTITY, value, NULL);
	g_free (value);

	ca_cert = svGetValue (ifcfg, ca_cert_key, FALSE);
	if (ca_cert) {
		real_path = get_full_file_path (ifcfg->fileName, ca_cert);
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
		g_free (real_path);
		real_path = NULL;
	} else {
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: missing %s for EAP"
		             " method '%s'; this is insecure!",
		             ca_cert_key,
		             eap_method);
	}

	/* Read and set private key password flags */
	flags = read_secret_flags (ifcfg, pk_pw_flags_key);
	g_object_set (s_8021x, pk_pw_flags_prop, flags, NULL);

	/* Read the private key password if it's system-owned */
	if (flags == NM_SETTING_SECRET_FLAG_NONE) {
		/* Private key password */
		privkey_password = svGetValue (ifcfg, pk_pw_key, FALSE);
		if (!privkey_password && keys) {
			/* Try the lookaside keys file */
			privkey_password = svGetValue (keys, pk_pw_key, FALSE);
		}

		if (!privkey_password) {
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
			             "Missing %s for EAP method '%s'.",
			             pk_pw_key,
			             eap_method);
			goto done;
		}
	}

	/* The private key itself */
	privkey = svGetValue (ifcfg, pk_key, FALSE);
	if (!privkey) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Missing %s for EAP method '%s'.",
		             pk_key,
		             eap_method);
		goto done;
	}

	real_path = get_full_file_path (ifcfg->fileName, privkey);
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
	g_free (real_path);
	real_path = NULL;

	/* Only set the client certificate if the private key is not PKCS#12 format,
	 * as NM (due to supplicant restrictions) requires.  If the key was PKCS#12,
	 * then nm_setting_802_1x_set_private_key() already set the client certificate
	 * to the same value as the private key.
	 */
	if (   privkey_format == NM_SETTING_802_1X_CK_FORMAT_RAW_KEY
	    || privkey_format == NM_SETTING_802_1X_CK_FORMAT_X509) {
		client_cert = svGetValue (ifcfg, cli_cert_key, FALSE);
		if (!client_cert) {
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
			             "Missing %s for EAP method '%s'.",
			             cli_cert_key,
			             eap_method);
			goto done;
		}

		real_path = get_full_file_path (ifcfg->fileName, client_cert);
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
		g_free (real_path);
		real_path = NULL;
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
	char *anon_ident = NULL;
	char *ca_cert = NULL;
	char *real_cert_path = NULL;
	char *inner_auth = NULL;
	char *peapver = NULL;
	char *lower;
	char **list = NULL, **iter;
	gboolean success = FALSE;

	ca_cert = svGetValue (ifcfg, "IEEE_8021X_CA_CERT", FALSE);
	if (ca_cert) {
		real_cert_path = get_full_file_path (ifcfg->fileName, ca_cert);
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

	anon_ident = svGetValue (ifcfg, "IEEE_8021X_ANON_IDENTITY", FALSE);
	if (anon_ident && strlen (anon_ident))
		g_object_set (s_8021x, NM_SETTING_802_1X_ANONYMOUS_IDENTITY, anon_ident, NULL);

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
	g_free (anon_ident);
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
		real_cert_path = get_full_file_path (ifcfg->fileName, ca_cert);
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

static gboolean
eap_fast_reader (const char *eap_method,
                 shvarFile *ifcfg,
                 shvarFile *keys,
                 NMSetting8021x *s_8021x,
                 gboolean phase2,
                 GError **error)
{
	char *anon_ident = NULL;
	char *pac_file = NULL;
	char *real_pac_path = NULL;
	char *inner_auth = NULL;
	char *fast_provisioning = NULL;
	char *lower;
	char **list = NULL, **iter;
	const char* pac_prov_str;
	gboolean allow_unauth = FALSE, allow_auth = FALSE;
	gboolean success = FALSE;

	pac_file = svGetValue (ifcfg, "IEEE_8021X_PAC_FILE", FALSE);
	if (pac_file) {
		real_pac_path = get_full_file_path (ifcfg->fileName, pac_file);
		g_object_set (s_8021x, NM_SETTING_802_1X_PAC_FILE, real_pac_path, NULL);
	}

	fast_provisioning = svGetValue (ifcfg, "IEEE_8021X_FAST_PROVISIONING", FALSE);
	if (fast_provisioning) {
		list = g_strsplit_set (fast_provisioning, " \t", 0);
		for (iter = list; iter && *iter; iter++) {
			if (**iter == '\0')
				continue;
			if (strcmp (*iter, "allow-unauth") == 0)
				allow_unauth = TRUE;
			else if (strcmp (*iter, "allow-auth") == 0)
				allow_auth = TRUE;
			else {
				PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: invalid IEEE_8021X_FAST_PROVISIONING '%s' "
				             "(space-separated list of these values [allow-auth, allow-unauth] expected)",
				             *iter);
			}
		}
		g_strfreev (list);
		list = NULL;
	}
	pac_prov_str = allow_unauth ? (allow_auth ? "3" : "1") : (allow_auth ? "2" : "0");
	g_object_set (s_8021x, NM_SETTING_802_1X_PHASE1_FAST_PROVISIONING, pac_prov_str, NULL);

	if (!pac_file && !(allow_unauth || allow_auth)) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "IEEE_8021X_PAC_FILE not provided and EAP-FAST automatic PAC provisioning disabled.");
		goto done;
	}

	anon_ident = svGetValue (ifcfg, "IEEE_8021X_ANON_IDENTITY", FALSE);
	if (anon_ident && strlen (anon_ident))
		g_object_set (s_8021x, NM_SETTING_802_1X_ANONYMOUS_IDENTITY, anon_ident, NULL);

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
		    || !strcmp (*iter, "GTC")) {
			if (!eap_simple_reader (*iter, ifcfg, keys, s_8021x, TRUE, error))
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
	g_strfreev (list);
	g_free (inner_auth);
	g_free (fast_provisioning);
	g_free (real_pac_path);
	g_free (pac_file);
	g_free (anon_ident);
	return success;
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
	{ "leap", eap_simple_reader, FALSE },
	{ "tls", eap_tls_reader, FALSE },
	{ "peap", eap_peap_reader, FALSE },
	{ "ttls", eap_ttls_reader, FALSE },
	{ "fast", eap_fast_reader, FALSE },
	{ NULL, NULL }
};

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
	char **list = NULL, **iter;

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

	if (nm_setting_802_1x_get_num_eap_methods (s_8021x) == 0) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "No valid EAP methods found in IEEE_8021X_EAP_METHODS.");
		goto error;
	}

	if (list)
		g_strfreev (list);
	if (keys)
		svCloseFile (keys);
	return s_8021x;

error:
	if (list)
		g_strfreev (list);
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
	gboolean wpa_psk = FALSE, wpa_eap = FALSE, ieee8021x = FALSE;

	wsec = NM_SETTING_WIRELESS_SECURITY (nm_setting_wireless_security_new ());

	value = svGetValue (ifcfg, "KEY_MGMT", FALSE);
	wpa_psk = !g_strcmp0 (value, "WPA-PSK");
	wpa_eap = !g_strcmp0 (value, "WPA-EAP");
	ieee8021x = !g_strcmp0 (value, "IEEE8021X");
	if (!wpa_psk && !wpa_eap && !ieee8021x)
		goto error; /* Not WPA or Dynamic WEP */

	/* Pairwise and Group ciphers (only relevant for WPA/RSN) */
	if (wpa_psk || wpa_eap) {
		fill_wpa_ciphers (ifcfg, wsec, FALSE, adhoc);
		fill_wpa_ciphers (ifcfg, wsec, TRUE, adhoc);
	}

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
		if (!allow_wpa && !allow_rsn && !ieee8021x) {
			nm_setting_wireless_security_add_proto (wsec, "wpa");
			nm_setting_wireless_security_add_proto (wsec, "rsn");
		}

		g_free (allow_wpa);
		g_free (allow_rsn);
	}

	if (!strcmp (value, "WPA-PSK")) {
		NMSettingSecretFlags psk_flags;

		psk_flags = read_secret_flags (ifcfg, "WPA_PSK_FLAGS");
		g_object_set (wsec, NM_SETTING_WIRELESS_SECURITY_PSK_FLAGS, psk_flags, NULL);

		/* Read PSK if it's system-owned */
		if (psk_flags == NM_SETTING_SECRET_FLAG_NONE) {
			psk = parse_wpa_psk (ifcfg, file, ssid, error);
			if (psk) {
				g_object_set (wsec, NM_SETTING_WIRELESS_SECURITY_PSK, psk, NULL);
				g_free (psk);
			}
		}

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
	NMSettingSecretFlags flags;

	wsec = NM_SETTING_WIRELESS_SECURITY (nm_setting_wireless_security_new ());

	value = svGetValue (ifcfg, "KEY_MGMT", FALSE);
	if (!value || strcmp (value, "IEEE8021X"))
		goto error; /* Not LEAP */

	g_free (value);
	value = svGetValue (ifcfg, "SECURITYMODE", FALSE);
	if (!value || strcasecmp (value, "leap"))
		goto error; /* Not LEAP */

	g_free (value);

	flags = read_secret_flags (ifcfg, "IEEE_8021X_PASSWORD_FLAGS");
	g_object_set (wsec, NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD_FLAGS, flags, NULL);

	/* Read LEAP password if it's system-owned */
	if (flags == NM_SETTING_SECRET_FLAG_NONE) {
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
	}

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
	GSList *macaddr_blacklist = NULL;
	char *value;

	s_wireless = NM_SETTING_WIRELESS (nm_setting_wireless_new ());

	if (read_mac_address (ifcfg, "HWADDR", ARPHRD_ETHER, &array, error)) {
		if (array) {
			g_object_set (s_wireless, NM_SETTING_WIRELESS_MAC_ADDRESS, array, NULL);

			if (!nm_controlled) {
				*unmanaged = g_strdup_printf ("mac:%02x:%02x:%02x:%02x:%02x:%02x",
				                              array->data[0], array->data[1], array->data[2],
				                              array->data[3], array->data[4], array->data[5]);
			}

			g_byte_array_free (array, TRUE);
		}
	} else {
		g_object_unref (s_wireless);
		return NULL;
	}

	array = NULL;
	if (read_mac_address (ifcfg, "MACADDR", ARPHRD_ETHER, &array, error)) {
		if (array) {
			g_object_set (s_wireless, NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS, array, NULL);
			g_byte_array_free (array, TRUE);
		}
	} else {
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: %s", (*error)->message);
		g_clear_error (error);
	}

	value = svGetValue (ifcfg, "HWADDR_BLACKLIST", FALSE);
	if (value) {
		char **list = NULL, **iter;
		struct ether_addr addr;

		list = g_strsplit_set (value, " \t", 0);
		for (iter = list; iter && *iter; iter++) {
			if (**iter == '\0')
				continue;
			if (!ether_aton_r (*iter, &addr)) {
				PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: invalid MAC in HWADDR_BLACKLIST '%s'", *iter);
				continue;
			}
			macaddr_blacklist = g_slist_prepend (macaddr_blacklist, *iter);
		}
		if (macaddr_blacklist) {
			macaddr_blacklist = g_slist_reverse (macaddr_blacklist);
			g_object_set (s_wireless, NM_SETTING_WIRELESS_MAC_ADDRESS_BLACKLIST, macaddr_blacklist, NULL);
			g_slist_free (macaddr_blacklist);
		}
		g_free (value);
		g_strfreev (list);
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
				if (!g_ascii_isxdigit (*p)) {
					g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
					             "Invalid SSID '%s' character (looks like hex SSID but '%c' isn't a hex digit)",
					             value, *p);
					g_free (value);
					goto error;
				}
				p++;
			}

			tmp = nm_utils_hexstr2bin (value + 2, value_len - 2);
			ssid_len  = (value_len - 2) / 2;
			memcpy (buf, tmp, ssid_len);
			p = &buf[0];
			g_free (tmp);
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
		GByteArray *bssid;

		bssid = nm_utils_hwaddr_atoba (value, ARPHRD_ETHER);
		if (!bssid) {
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
			             "Invalid BSSID '%s'", value);
			g_free (value);
			goto error;
		}

		g_object_set (s_wireless, NM_SETTING_WIRELESS_BSSID, bssid, NULL);
		g_byte_array_free (bssid, TRUE);
		g_free (value);
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
		g_free (value);
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
		g_free (value);
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

	/* Wireless */
	wireless_setting = make_wireless_setting (ifcfg, nm_controlled, unmanaged, error);
	if (!wireless_setting) {
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, wireless_setting);

	ssid = nm_setting_wireless_get_ssid (NM_SETTING_WIRELESS (wireless_setting));
	if (ssid)
		printable_ssid = nm_utils_ssid_to_utf8 (ssid);
	else
		printable_ssid = g_strdup_printf ("unmanaged");

	if (nm_controlled) {
		mode = nm_setting_wireless_get_mode (NM_SETTING_WIRELESS (wireless_setting));
		if (mode && !strcmp (mode, "adhoc"))
			adhoc = TRUE;

		/* Wireless security */
		security_setting = make_wireless_security_setting (ifcfg, file, ssid, adhoc, &s_8021x, error);
		if (*error) {
			g_free (printable_ssid);
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
	                                       printable_ssid, NULL);
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
	GSList *macaddr_blacklist = NULL;
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

	if (read_mac_address (ifcfg, "HWADDR", ARPHRD_ETHER, &mac, error)) {
		if (mac) {
			g_object_set (s_wired, NM_SETTING_WIRED_MAC_ADDRESS, mac, NULL);

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
			if (!g_ascii_isxdigit (*p) && (*p != ',') && (*p != '.')) {
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

	value = svGetValue (ifcfg, "CTCPROT", FALSE);
	if (value && strlen (value))
		nm_setting_wired_add_s390_option (s_wired, "ctcprot", value);
	g_free (value);

	nettype = svGetValue (ifcfg, "NETTYPE", FALSE);
	if (nettype && strlen (nettype)) {
		if (!strcmp (nettype, "qeth") || !strcmp (nettype, "lcs") || !strcmp (nettype, "ctc"))
			g_object_set (s_wired, NM_SETTING_WIRED_S390_NETTYPE, nettype, NULL);
		else
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: unknown s390 NETTYPE '%s'", nettype);
	}
	g_free (nettype);

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

	mac = NULL;
	if (read_mac_address (ifcfg, "MACADDR", ARPHRD_ETHER, &mac, error)) {
		if (mac) {
			g_object_set (s_wired, NM_SETTING_WIRED_CLONED_MAC_ADDRESS, mac, NULL);
			g_byte_array_free (mac, TRUE);
		}
	} else {
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: %s", (*error)->message);
		g_clear_error (error);
	}

	value = svGetValue (ifcfg, "HWADDR_BLACKLIST", FALSE);
	if (value) {
		char **list = NULL, **iter;
		struct ether_addr addr;

		list = g_strsplit_set (value, " \t", 0);
		for (iter = list; iter && *iter; iter++) {
			if (**iter == '\0')
				continue;
			if (!ether_aton_r (*iter, &addr)) {
				PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: invalid MAC in HWADDR_BLACKLIST '%s'", *iter);
				continue;
			}
			macaddr_blacklist = g_slist_prepend (macaddr_blacklist, *iter);
		}
		if (macaddr_blacklist) {
			macaddr_blacklist = g_slist_reverse (macaddr_blacklist);
			g_object_set (s_wired, NM_SETTING_WIRED_MAC_ADDRESS_BLACKLIST, macaddr_blacklist, NULL);
			g_slist_free (macaddr_blacklist);
		}
		g_free (value);
		g_strfreev (list);
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

	con_setting = make_connection_setting (file, ifcfg, NM_SETTING_WIRED_SETTING_NAME, NULL, NULL);
	if (!con_setting) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Failed to create connection setting.");
		g_object_unref (connection);
		return NULL;
	}
	check_if_bond_slave (ifcfg, NM_SETTING_CONNECTION (con_setting));
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
parse_infiniband_p_key (shvarFile *ifcfg,
                        int *out_p_key,
                        char **out_parent,
                        GError **error)
{
	char *device = NULL, *physdev = NULL, *pkey_id = NULL, *end;
	char *ifname = NULL;
	guint32 id;
	gboolean ret = FALSE;

	device = svGetValue (ifcfg, "DEVICE", FALSE);
	if (!device) {
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    InfiniBand connection specified PKEY but not DEVICE");
		goto done;
	}

	physdev = svGetValue (ifcfg, "PHYSDEV", FALSE);
	if (!physdev) {
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    InfiniBand connection specified PKEY but not PHYSDEV");
		goto done;
	}

	pkey_id = svGetValue (ifcfg, "PKEY_ID", FALSE);
	if (!pkey_id) {
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    InfiniBand connection specified PKEY but not PKEY_ID");
		goto done;
	}

	if (g_str_has_prefix (pkey_id, "0x"))
		id = strtoul (pkey_id, &end, 16);
	else if (!g_str_has_prefix (pkey_id, "0"))
		id = strtoul (pkey_id, &end, 10);
	else
		end = pkey_id;
	if (end == pkey_id || *end || id > 0xFFFF) {
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    invalid InfiniBand PKEY_ID '%s'", pkey_id);
		goto done;
	}
	id = (id | 0x8000);

	ifname = g_strdup_printf ("%s.%04x", physdev, id);
	if (strcmp (device, ifname) != 0) {
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    InfiniBand DEVICE (%s) does not match PHYSDEV+PKEY_ID (%s)",
		             device, ifname);
		goto done;
	}

	*out_p_key = id;
	*out_parent = g_strdup (physdev);
	ret = TRUE;

 done:
	g_free (device);
	g_free (physdev);
	g_free (pkey_id);
	g_free (ifname);

	if (!ret) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Failed to create InfiniBand setting.");
	}
	return ret;
}


static NMSetting *
make_infiniband_setting (shvarFile *ifcfg,
                         const char *file,
                         gboolean nm_controlled,
                         char **unmanaged,
                         GError **error)
{
	NMSettingInfiniband *s_infiniband;
	char *value = NULL;
	GByteArray *mac = NULL;
	int mtu;

	s_infiniband = NM_SETTING_INFINIBAND (nm_setting_infiniband_new ());

	value = svGetValue (ifcfg, "MTU", FALSE);
	if (value) {
		if (get_int (value, &mtu)) {
			if (mtu >= 0 && mtu < 65536)
				g_object_set (s_infiniband, NM_SETTING_INFINIBAND_MTU, mtu, NULL);
		} else {
			/* Shouldn't be fatal... */
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: invalid MTU '%s'", value);
		}
		g_free (value);
	}

	if (read_mac_address (ifcfg, "HWADDR", ARPHRD_INFINIBAND, &mac, error)) {
		if (mac) {
			g_object_set (s_infiniband, NM_SETTING_INFINIBAND_MAC_ADDRESS, mac, NULL);

			if (!nm_controlled) {
				char *mac_str = nm_utils_hwaddr_ntoa (mac->data, ARPHRD_INFINIBAND);
				*unmanaged = g_strdup_printf ("mac:%s", mac_str);
				g_free (mac_str);
			}

			g_byte_array_free (mac, TRUE);
		}
	} else {
		g_object_unref (s_infiniband);
		return NULL;
	}

	if (svTrueValue (ifcfg, "CONNECTED_MODE", FALSE))
		g_object_set (s_infiniband, NM_SETTING_INFINIBAND_TRANSPORT_MODE, "connected", NULL);
	else
		g_object_set (s_infiniband, NM_SETTING_INFINIBAND_TRANSPORT_MODE, "datagram", NULL);

	if (svTrueValue (ifcfg, "PKEY", FALSE)) {
		int p_key;
		char *parent;

		if (!parse_infiniband_p_key (ifcfg, &p_key, &parent, error)) {
			g_object_unref (s_infiniband);
			return NULL;
		}

		g_object_set (s_infiniband,
		              NM_SETTING_INFINIBAND_P_KEY, p_key,
		              NM_SETTING_INFINIBAND_PARENT, parent,
		              NULL);
	}

	return (NMSetting *) s_infiniband;
}

static NMConnection *
infiniband_connection_from_ifcfg (const char *file,
                                  shvarFile *ifcfg,
                                  gboolean nm_controlled,
                                  char **unmanaged,
                                  GError **error)
{
	NMConnection *connection = NULL;
	NMSetting *con_setting = NULL;
	NMSetting *infiniband_setting = NULL;

	g_return_val_if_fail (file != NULL, NULL);
	g_return_val_if_fail (ifcfg != NULL, NULL);

	connection = nm_connection_new ();

	con_setting = make_connection_setting (file, ifcfg, NM_SETTING_INFINIBAND_SETTING_NAME, NULL, NULL);
	if (!con_setting) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Failed to create connection setting.");
		g_object_unref (connection);
		return NULL;
	}
	check_if_bond_slave (ifcfg, NM_SETTING_CONNECTION (con_setting));
	nm_connection_add_setting (connection, con_setting);

	infiniband_setting = make_infiniband_setting (ifcfg, file, nm_controlled, unmanaged, error);
	if (!infiniband_setting) {
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, infiniband_setting);

	if (!nm_connection_verify (connection, error)) {
		g_object_unref (connection);
		return NULL;
	}

	return connection;
}

static void
handle_bond_option (NMSettingBond *s_bond,
                    const char *key,
                    const char *value)
{
	if (!nm_setting_bond_add_option (s_bond, key, value))
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: invalid bonding option '%s'", key);
}

static NMSetting *
make_bond_setting (shvarFile *ifcfg,
                   const char *file,
                   gboolean nm_controlled,
                   char **unmanaged,
                   GError **error)
{
	NMSettingBond *s_bond;
	char *value;

	s_bond = NM_SETTING_BOND (nm_setting_bond_new ());

	value = svGetValue (ifcfg, "DEVICE", FALSE);
	if (!value || !strlen (value)) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0, "mandatory DEVICE keyword missing");
		goto error;
	}

	g_object_set (s_bond, NM_SETTING_BOND_INTERFACE_NAME, value, NULL);
	g_free (value);

	value = svGetValue (ifcfg, "BONDING_OPTS", FALSE);
	if (value) {
		char **items, **iter;

		items = g_strsplit_set (value, " ", -1);
		for (iter = items; iter && *iter; iter++) {
			if (strlen (*iter)) {
				char **keys, *key, *val;

				keys = g_strsplit_set (*iter, "=", 2);
				if (keys && *keys) {
					key = *keys;
					val = *(keys + 1);
					if (val && strlen(key) && strlen(val))
						handle_bond_option (s_bond, key, val);
				}

				g_strfreev (keys);
			}
		}
		g_free (value);
		g_strfreev (items);
	}

	return (NMSetting *) s_bond;

error:
	g_object_unref (s_bond);
	return NULL;
}

static NMConnection *
bond_connection_from_ifcfg (const char *file,
                            shvarFile *ifcfg,
                            gboolean nm_controlled,
                            char **unmanaged,
                            GError **error)
{
	NMConnection *connection = NULL;
	NMSetting *con_setting = NULL;
	NMSetting *bond_setting = NULL;
	NMSetting *wired_setting = NULL;
	NMSetting8021x *s_8021x = NULL;

	g_return_val_if_fail (file != NULL, NULL);
	g_return_val_if_fail (ifcfg != NULL, NULL);

	connection = nm_connection_new ();

	con_setting = make_connection_setting (file, ifcfg, NM_SETTING_BOND_SETTING_NAME, NULL, _("Bond"));
	if (!con_setting) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Failed to create connection setting.");
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, con_setting);

	bond_setting = make_bond_setting (ifcfg, file, nm_controlled, unmanaged, error);
	if (!bond_setting) {
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, bond_setting);

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

typedef void (*BridgeOptFunc) (NMSetting *setting,
                               gboolean stp,
                               const char *key,
                               const char *value);

static void
handle_bridge_option (NMSetting *setting,
                      gboolean stp,
                      const char *key,
                      const char *value)
{
	guint32 u = 0;

	if (!strcmp (key, "priority")) {
		if (stp == FALSE) {
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: 'priority' invalid when STP is disabled");
		} else if (get_uint (value, &u))
			g_object_set (setting, NM_SETTING_BRIDGE_PRIORITY, u, NULL);
		else
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: invalid priority value '%s'", value);
	} else if (!strcmp (key, "hello_time")) {
		if (stp == FALSE) {
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: 'hello_time' invalid when STP is disabled");
		} else if (get_uint (value, &u))
			g_object_set (setting, NM_SETTING_BRIDGE_HELLO_TIME, u, NULL);
		else
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: invalid hello_time value '%s'", value);
	} else if (!strcmp (key, "max_age")) {
		if (stp == FALSE) {
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: 'max_age' invalid when STP is disabled");
		} else if (get_uint (value, &u))
			g_object_set (setting, NM_SETTING_BRIDGE_MAX_AGE, u, NULL);
		else
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: invalid max_age value '%s'", value);
	} else if (!strcmp (key, "ageing_time")) {
		if (get_uint (value, &u))
			g_object_set (setting, NM_SETTING_BRIDGE_AGEING_TIME, u, NULL);
		else
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: invalid ageing_time value '%s'", value);
	} else
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: unhandled bridge option '%s'", key);
}

static void
handle_bridging_opts (NMSetting *setting,
                      gboolean stp,
                      const char *value,
                      BridgeOptFunc func)
{
	char **items, **iter;

	items = g_strsplit_set (value, " ", -1);
	for (iter = items; iter && *iter; iter++) {
		if (strlen (*iter)) {
			char **keys, *key, *val;

			keys = g_strsplit_set (*iter, "=", 2);
			if (keys && *keys) {
				key = *keys;
				val = *(keys + 1);
				if (val && strlen(key) && strlen(val))
					func (setting, stp, key, val);
			}

			g_strfreev (keys);
		}
	}
	g_strfreev (items);
}

static NMSetting *
make_bridge_setting (shvarFile *ifcfg,
                     const char *file,
                     gboolean nm_controlled,
                     char **unmanaged,
                     GError **error)
{
	NMSettingBridge *s_bridge;
	char *value;
	guint32 u;
	gboolean stp = FALSE;
	gboolean stp_set = FALSE;

	s_bridge = NM_SETTING_BRIDGE (nm_setting_bridge_new ());

	value = svGetValue (ifcfg, "DEVICE", FALSE);
	if (!value || !strlen (value)) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0, "mandatory DEVICE keyword missing");
		goto error;
	}

	g_object_set (s_bridge, NM_SETTING_BRIDGE_INTERFACE_NAME, value, NULL);
	g_free (value);

	value = svGetValue (ifcfg, "STP", FALSE);
	if (value) {
		if (!strcasecmp (value, "on") || !strcasecmp (value, "yes")) {
			g_object_set (s_bridge, NM_SETTING_BRIDGE_STP, TRUE, NULL);
			stp = TRUE;
			stp_set = TRUE;
		} else if (!strcasecmp (value, "off") || !strcasecmp (value, "no")) {
			g_object_set (s_bridge, NM_SETTING_BRIDGE_STP, FALSE, NULL);
			stp_set = TRUE;
		} else
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: invalid STP value '%s'", value);
		g_free (value);
	}

	if (!stp_set) {
		/* Missing or invalid STP property means "no" */
		g_object_set (s_bridge, NM_SETTING_BRIDGE_STP, FALSE, NULL);
	}

	value = svGetValue (ifcfg, "DELAY", FALSE);
	if (value) {
		if (stp) {
			if (get_uint (value, &u))
				g_object_set (s_bridge, NM_SETTING_BRIDGE_FORWARD_DELAY, u, NULL);
			else
				PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: invalid forward delay value '%s'", value);
		} else
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: DELAY invalid when STP is disabled");
		g_free (value);
	}

	value = svGetValue (ifcfg, "BRIDGING_OPTS", FALSE);
	if (value) {
		handle_bridging_opts (NM_SETTING (s_bridge), stp, value, handle_bridge_option);
		g_free (value);
	}

	return (NMSetting *) s_bridge;

error:
	g_object_unref (s_bridge);
	return NULL;
}

static NMConnection *
bridge_connection_from_ifcfg (const char *file,
                              shvarFile *ifcfg,
                              gboolean nm_controlled,
                              char **unmanaged,
                              GError **error)
{
	NMConnection *connection = NULL;
	NMSetting *con_setting = NULL;
	NMSetting *bridge_setting = NULL;

	g_return_val_if_fail (file != NULL, NULL);
	g_return_val_if_fail (ifcfg != NULL, NULL);

	connection = nm_connection_new ();

	con_setting = make_connection_setting (file, ifcfg, NM_SETTING_BRIDGE_SETTING_NAME, NULL, _("Bridge"));
	if (!con_setting) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Failed to create connection setting.");
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, con_setting);

	bridge_setting = make_bridge_setting (ifcfg, file, nm_controlled, unmanaged, error);
	if (!bridge_setting) {
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, bridge_setting);	

	if (!nm_connection_verify (connection, error)) {
		g_object_unref (connection);
		return NULL;
	}

	return connection;
}

static void
handle_bridge_port_option (NMSetting *setting,
                           gboolean stp,
                           const char *key,
                           const char *value)
{
	guint32 u = 0;

	if (!strcmp (key, "priority")) {
		if (get_uint (value, &u))
			g_object_set (setting, NM_SETTING_BRIDGE_PORT_PRIORITY, u, NULL);
		else
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: invalid priority value '%s'", value);
	} else if (!strcmp (key, "path_cost")) {
		if (get_uint (value, &u))
			g_object_set (setting, NM_SETTING_BRIDGE_PORT_PATH_COST, u, NULL);
		else
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: invalid path_cost value '%s'", value);
	} else if (!strcmp (key, "hairpin_mode")) {
		if (!strcasecmp (value, "on") || !strcasecmp (value, "yes") || !strcmp (value, "1"))
			g_object_set (setting, NM_SETTING_BRIDGE_PORT_HAIRPIN_MODE, TRUE, NULL);
		else if (!strcasecmp (value, "off") || !strcasecmp (value, "no"))
			g_object_set (setting, NM_SETTING_BRIDGE_PORT_HAIRPIN_MODE, FALSE, NULL);
		else
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: invalid hairpin_mode value '%s'", value);
	} else
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: unhandled bridge port option '%s'", key);
}

static NMSetting *
make_bridge_port_setting (shvarFile *ifcfg)
{
	NMSetting *s_port = NULL;
	char *value;

	g_return_val_if_fail (ifcfg != NULL, FALSE);

	value = svGetValue (ifcfg, "BRIDGE", FALSE);
	if (value) {
		g_free (value);

		s_port = nm_setting_bridge_port_new ();
		value = svGetValue (ifcfg, "BRIDGING_OPTS", FALSE);
		if (value)
			handle_bridging_opts (s_port, FALSE, value, handle_bridge_port_option);
		g_free (value);
	}

	return s_port;
}

static gboolean
is_bond_device (const char *name, shvarFile *parsed)
{
	g_return_val_if_fail (name != NULL, FALSE);
	g_return_val_if_fail (parsed != NULL, FALSE);

	if (svTrueValue (parsed, "BONDING_MASTER", FALSE))
		return TRUE;
	
	/* XXX: Check for "bond[\d]+"? */

	return FALSE;
}

static gboolean
is_vlan_device (const char *name, shvarFile *parsed)
{
	g_return_val_if_fail (name != NULL, FALSE);
	g_return_val_if_fail (parsed != NULL, FALSE);

	if (svTrueValue (parsed, "VLAN", FALSE))
		return TRUE;

	return FALSE;
}

static void
parse_prio_map_list (NMSettingVlan *s_vlan,
                     shvarFile *ifcfg,
                     const char *key,
                     NMVlanPriorityMap map)
{
	char *value;
	gchar **list = NULL, **iter;

	value = svGetValue (ifcfg, key, FALSE);
	if (!value)
		return;

	list = g_strsplit_set (value, ",", -1);
	g_free (value);

	for (iter = list; iter && *iter; iter++) {
		if (!*iter || !strchr (*iter, ':'))
			continue;

		if (!nm_setting_vlan_add_priority_str (s_vlan, map, *iter)) {
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: invalid %s priority map item '%s'",
			             key, *iter);
		}
	}
	g_strfreev (list);
}

static NMSetting *
make_vlan_setting (shvarFile *ifcfg,
                   const char *file,
                   gboolean nm_controlled,
                   char **out_master,
                   char **unmanaged,
                   NMSetting8021x **s_8021x,
                   GError **error)
{
	NMSettingVlan *s_vlan = NULL;
	char *value = NULL;
	char *iface_name = NULL;
	char *parent = NULL;
	const char *p = NULL;
	char *end = NULL;
	gint vlan_id = -1;
	guint32 vlan_flags = 0;

	value = svGetValue (ifcfg, "VLAN_ID", FALSE);
	if (value) {
		errno = 0;
		vlan_id = (gint) g_ascii_strtoll (value, NULL, 10);
		if (vlan_id < 0 || vlan_id > 4096 || errno) {
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0, "Invalid VLAN_ID '%s'", value);
			g_free (value);
			return NULL;
		}
		g_free (value);
	}

	/* Need DEVICE if we don't have a separate VLAN_ID property */
	iface_name = svGetValue (ifcfg, "DEVICE", FALSE);
	if (!iface_name && vlan_id < 0) {
		g_set_error_literal (error, IFCFG_PLUGIN_ERROR, 0,
		                     "Missing DEVICE property; cannot determine VLAN ID.");
		return NULL;
	}

	s_vlan = NM_SETTING_VLAN (nm_setting_vlan_new ());

	if (iface_name) {
		g_object_set (s_vlan, NM_SETTING_VLAN_INTERFACE_NAME, iface_name, NULL);

		p = strchr (iface_name, '.');
		if (p) {
			/* eth0.43; PHYSDEV is assumed from it */
			parent = g_strndup (iface_name, p - iface_name);
			p++;
		} else {
			/* format like vlan43; PHYSDEV or MASTER must be set */
			if (g_str_has_prefix (iface_name, "vlan"))
				p = iface_name + 4;
		}

		if (p) {
			/* Grab VLAN ID from interface name; this takes precedence over the
			 * separate VLAN_ID property for backwards compat.
			 */
			vlan_id = (gint) g_ascii_strtoll (p, &end, 10);
			if (vlan_id < 0 || vlan_id > 4095 || end == p || *end) {
				g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
				             "Failed to determine VLAN ID from DEVICE '%s'",
				             iface_name);
				goto error;
			}
		}
	}

	if (vlan_id < 0) {
		g_set_error_literal (error, IFCFG_PLUGIN_ERROR, 0,
		                     "Failed to determine VLAN ID from DEVICE or VLAN_ID.");
		goto error;
	}
	g_object_set (s_vlan, NM_SETTING_VLAN_ID, vlan_id, NULL);

	if (!parent)
		parent = svGetValue (ifcfg, "PHYSDEV", FALSE);
	if (parent == NULL) {
		g_set_error_literal (error, IFCFG_PLUGIN_ERROR, 0,
		                     "Failed to determine VLAN parent from DEVICE or PHYSDEV");
		goto error;
	}
	g_object_set (s_vlan, NM_SETTING_VLAN_PARENT, parent, NULL);

	if (svTrueValue (ifcfg, "REORDER_HDR", FALSE))
		vlan_flags |= NM_VLAN_FLAG_REORDER_HEADERS;

	value = svGetValue (ifcfg, "VLAN_FLAGS", FALSE);
	if (value) {
		if (g_strstr_len (value, -1, "GVRP"))
			vlan_flags |= NM_VLAN_FLAG_GVRP;
		if (g_strstr_len (value, -1, "LOOSE_BINDING"))
			vlan_flags |= NM_VLAN_FLAG_LOOSE_BINDING;
	}

	g_object_set (s_vlan, NM_SETTING_VLAN_FLAGS, vlan_flags, NULL);
	g_free (value);

	parse_prio_map_list (s_vlan, ifcfg, "VLAN_INGRESS_PRIORITY_MAP", NM_VLAN_INGRESS_MAP);
	parse_prio_map_list (s_vlan, ifcfg, "VLAN_EGRESS_PRIORITY_MAP", NM_VLAN_EGRESS_MAP);

	if (out_master)
		*out_master = svGetValue (ifcfg, "MASTER", FALSE);
	return (NMSetting *) s_vlan;

error:
	g_free (parent);
	g_free (iface_name);
	g_object_unref (s_vlan);
	return NULL;
}

static NMConnection *
vlan_connection_from_ifcfg (const char *file,
                            shvarFile *ifcfg,
                            gboolean nm_controlled,
                            char **unmanaged,
                            GError **error)
{
	NMConnection *connection = NULL;
	NMSetting *con_setting = NULL;
	NMSetting *wired_setting = NULL;
	NMSetting *vlan_setting = NULL;
	NMSetting8021x *s_8021x = NULL;
	char *master = NULL;

	g_return_val_if_fail (file != NULL, NULL);
	g_return_val_if_fail (ifcfg != NULL, NULL);

	connection = nm_connection_new ();

	con_setting = make_connection_setting (file, ifcfg, NM_SETTING_VLAN_SETTING_NAME, NULL, "Vlan");
	if (!con_setting) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
			     "Failed to create connection setting.");
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, con_setting);

	vlan_setting = make_vlan_setting (ifcfg, file, nm_controlled, &master, unmanaged, &s_8021x, error);
	if (!vlan_setting) {
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, vlan_setting);

	/* Handle master interface or connection */
	if (master) {
		g_object_set (con_setting, NM_SETTING_CONNECTION_MASTER, master, NULL);
		g_object_set (con_setting,
		              NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_VLAN_SETTING_NAME,
		              NULL);
		g_free (master);
	}

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

static void
ensure_unmanaged (shvarFile *ifcfg,
                  char **unmanaged)
{
	char *value;

	if (*unmanaged)
		return;

	value = svGetValue (ifcfg, "DEVICE", FALSE);
	if (value) {
		*unmanaged = g_strdup_printf ("interface-name:%s", value);
		g_free (value);
		return;
	}

	PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: NM_CONTROLLED was false but device was not uniquely identified; device will be managed");
}

char *
uuid_from_file (const char *filename)
{
	const char *ifcfg_name = NULL;
	shvarFile *ifcfg;
	char *uuid;

	g_return_val_if_fail (filename != NULL, NULL);

	ifcfg_name = utils_get_ifcfg_name (filename, TRUE);
	if (!ifcfg_name)
		return NULL;

	ifcfg = svNewFile (filename);
	if (!ifcfg)
		return NULL;

	/* Try for a UUID key before falling back to hashing the file name */
	uuid = svGetValue (ifcfg, "UUID", FALSE);
	if (!uuid || !strlen (uuid)) {
		g_free (uuid);
		uuid = nm_utils_uuid_generate_from_string (ifcfg->fileName);
	}

	svCloseFile (ifcfg);
	return uuid;
}

NMConnection *
connection_from_file (const char *filename,
                      const char *network_file,  /* for unit tests only */
                      const char *test_type,     /* for unit tests only */
                      const char *iscsiadm_path, /* for unit tests only */
                      char **out_unmanaged,
                      char **out_keyfile,
                      char **out_routefile,
                      char **out_route6file,
                      GError **error,
                      gboolean *out_ignore_error)
{
	NMConnection *connection = NULL;
	shvarFile *parsed;
	char *type, *devtype, *nmc = NULL, *bootproto;
	NMSetting *s_ip4, *s_ip6, *s_port;
	const char *ifcfg_name = NULL;
	gboolean nm_controlled = TRUE;
	gboolean can_disable_ip4 = FALSE;
	char *unmanaged = NULL;

	g_return_val_if_fail (filename != NULL, NULL);
	if (out_unmanaged)
		g_return_val_if_fail (*out_unmanaged == NULL, NULL);
	if (out_keyfile)
		g_return_val_if_fail (*out_keyfile == NULL, NULL);
	if (out_routefile)
		g_return_val_if_fail (*out_routefile == NULL, NULL);
	if (out_route6file)
		g_return_val_if_fail (*out_route6file == NULL, NULL);

	/* Non-NULL only for unit tests; normally use /etc/sysconfig/network */
	if (!network_file)
		network_file = SYSCONFDIR "/sysconfig/network";

	if (!iscsiadm_path)
		iscsiadm_path = "/sbin/iscsiadm";

	ifcfg_name = utils_get_ifcfg_name (filename, TRUE);
	if (!ifcfg_name) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Ignoring connection '%s' because it's not an ifcfg file.", filename);
		return NULL;
	}

	parsed = svNewFile (filename);
	if (!parsed) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Couldn't parse file '%s'", filename);
		return NULL;
	}

	/*
	 * Ignore Team connections for now; we don't support team yet.
	 * https://fedorahosted.org/libteam/
	 */
	devtype = svGetValue (parsed, "DEVICETYPE", FALSE);
	if (devtype) {
		if (   !strcasecmp (devtype, TYPE_TEAM)
		    || !strcasecmp (devtype, TYPE_TEAM_PORT)) {
			char *base_name = g_path_get_basename (filename);
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
			            "Ignoring team (DEVICETYPE=\"%s\") connection '%s'; teaming is not supported yet",
			             devtype,
			             base_name);
			g_free (base_name);
			g_free (devtype);
			goto done;
		}
		g_free (devtype);
	}

	type = svGetValue (parsed, "TYPE", FALSE);
	if (!type) {
		char *device;

		device = svGetValue (parsed, "DEVICE", FALSE);
		if (!device) {
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
			             "File '%s' had neither TYPE nor DEVICE keys.", filename);
			goto done;
		}

		if (!strcmp (device, "lo")) {
			if (out_ignore_error)
				*out_ignore_error = TRUE;
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
			             "Ignoring loopback device config.");
			g_free (device);
			goto done;
		}

		if (!test_type) {
			if (is_bond_device (device, parsed))
				type = g_strdup (TYPE_BOND);
			else if (is_vlan_device (device, parsed))
				type = g_strdup (TYPE_VLAN);
			/* Test wireless extensions */
			else if (wifi_utils_is_wifi (device, NULL))
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
	} else {
		/* Check for IBM s390 CTC devices and call them Ethernet */
		if (g_strcmp0 (type, "CTC") == 0) {
			g_free (type);
			type = g_strdup (TYPE_ETHERNET);
		}
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

	if (svTrueValue (parsed, "BONDING_MASTER", FALSE) &&
	    strcasecmp (type, TYPE_BOND)) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "BONDING_MASTER=yes key only allowed in TYPE=bond connections");
		goto done;
	}

	/* Construct the connection */
	if (!strcasecmp (type, TYPE_ETHERNET))
		connection = wired_connection_from_ifcfg (filename, parsed, nm_controlled, &unmanaged, error);
	else if (!strcasecmp (type, TYPE_WIRELESS))
		connection = wireless_connection_from_ifcfg (filename, parsed, nm_controlled, &unmanaged, error);
	else if (!strcasecmp (type, TYPE_INFINIBAND))
		connection = infiniband_connection_from_ifcfg (filename, parsed, nm_controlled, &unmanaged, error);
	else if (!strcasecmp (type, TYPE_BOND))
		connection = bond_connection_from_ifcfg (filename, parsed, nm_controlled, &unmanaged, error);
	else if (!strcasecmp (type, TYPE_VLAN))
		connection = vlan_connection_from_ifcfg (filename, parsed, nm_controlled, &unmanaged, error);
	else if (!strcasecmp (type, TYPE_BRIDGE))
		connection = bridge_connection_from_ifcfg (filename, parsed, nm_controlled, &unmanaged, error);
	else {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0, "Unknown connection type '%s'", type);
	}

	if (!nm_controlled)
		ensure_unmanaged (parsed, &unmanaged);

	g_free (type);

	/* Don't bother reading the connection fully if it's unmanaged or ignored */
	if (!connection || unmanaged)
		goto done;

	s_ip6 = make_ip6_setting (parsed, network_file, iscsiadm_path, error);
	if (!s_ip6) {
		g_object_unref (connection);
		connection = NULL;
		goto done;
	} else if (utils_ignore_ip_config (connection)) {
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: ignoring IP6 configuration");
		g_object_unref (s_ip6);
	} else {
		const char *method;

		nm_connection_add_setting (connection, s_ip6);
		method = nm_setting_ip6_config_get_method (NM_SETTING_IP6_CONFIG (s_ip6));
		if (method && strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_IGNORE))
			can_disable_ip4 = TRUE;
	}

	s_ip4 = make_ip4_setting (parsed, network_file, iscsiadm_path, can_disable_ip4, error);
	if (!s_ip4) {
		g_object_unref (connection);
		connection = NULL;
		goto done;
	} else if (s_ip4 && utils_ignore_ip_config (connection)) {
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: ignoring IP4 configuration");
		g_object_unref (s_ip4);
	} else if (s_ip4)
		nm_connection_add_setting (connection, s_ip4);

	/* Bridge port? */
	s_port = make_bridge_port_setting (parsed);
	if (s_port)
		nm_connection_add_setting (connection, s_port);

	/* iSCSI / ibft connections are read-only since their settings are
	 * stored in NVRAM and can only be changed in BIOS.
	 */
	bootproto = svGetValue (parsed, "BOOTPROTO", FALSE);
	if (   bootproto
	    && connection
	    && !g_ascii_strcasecmp (bootproto, "ibft")) {
		NMSettingConnection *s_con;

		s_con = nm_connection_get_setting_connection (connection);
		g_assert (s_con);

		g_object_set (G_OBJECT (s_con), NM_SETTING_CONNECTION_READ_ONLY, TRUE, NULL);
	}
	g_free (bootproto);

	if (!nm_connection_verify (connection, error)) {
		g_object_unref (connection);
		connection = NULL;
	}

	if (out_keyfile)
		*out_keyfile = utils_get_keys_path (filename);
	if (out_routefile)
		*out_routefile = utils_get_route_path (filename);
	if (out_route6file)
		*out_route6file = utils_get_route6_path (filename);

done:
	if (out_unmanaged)
		*out_unmanaged = unmanaged;
	else
		g_free (unmanaged);

	svCloseFile (parsed);
	return connection;
}

