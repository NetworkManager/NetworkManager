/* NetworkManager initrd configuration generator
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2014 - 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-initrd-generator.h"

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "nm-core-internal.h"
#include "platform/nm-platform.h"
#include "NetworkManagerUtils.h"

/*****************************************************************************/

#define _NMLOG(level, domain, ...) \
    nm_log ((level), (domain), NULL, NULL, \
            "ibft-reader: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__) \
            _NM_UTILS_MACRO_REST (__VA_ARGS__))

/*****************************************************************************/

static GHashTable *
load_one_nic (const char *sysfs_dir, const char *dir_name)
{
	gs_free char *nic_path = g_build_filename (sysfs_dir, dir_name, NULL);
	GDir *nic_dir;
	const char *entry_name;
	char *content;
	gs_free_error GError *error = NULL;
	GHashTable *nic;

	g_return_val_if_fail (sysfs_dir != NULL, FALSE);

	nic_dir = g_dir_open (nic_path, 0, &error);
	if (!nic_dir) {
		_LOGW (LOGD_CORE, "Can't open %s: %s", nic_path, error->message);
		return NULL;
	}

	nic = g_hash_table_new_full (nm_str_hash, g_str_equal, g_free, g_free);
	while ((entry_name = g_dir_read_name (nic_dir))) {
		gs_free char *entry_path = g_build_filename (nic_path, entry_name, NULL);

		if (!g_file_test (entry_path, G_FILE_TEST_IS_REGULAR))
			continue;

		if (!g_file_get_contents (entry_path, &content, NULL, &error)) {
			_LOGW (LOGD_CORE, "Can't read %s: %s", entry_path, error->message);
			g_clear_error (&error);
			continue;
		}

		g_strchomp (content);
		if (!g_hash_table_insert (nic, g_strdup (entry_name), content))
			_LOGW (LOGD_CORE, "Duplicate iBFT entry: %s", entry_name);
	}

	g_dir_close (nic_dir);

	return nic;
}

GHashTable *
nmi_ibft_read (const char *sysfs_dir)
{
	gs_free char *ibft_path = NULL;
	GDir *ibft_dir;
	const char *dir_name;
	GHashTable *ibft, *nic;
	char *mac;
	gs_free_error GError *error = NULL;

	g_return_val_if_fail (sysfs_dir != NULL, FALSE);

	ibft_path = g_build_filename (sysfs_dir, "firmware", "ibft", NULL);

	ibft = g_hash_table_new_full (nm_str_hash, g_str_equal, g_free,
	                              (GDestroyNotify) g_hash_table_unref);

	if (!g_file_test (ibft_path, G_FILE_TEST_IS_DIR))
		nm_utils_modprobe (NULL, FALSE, "iscsi_ibft", NULL);
	if (!g_file_test (ibft_path, G_FILE_TEST_IS_DIR))
		return ibft;

	ibft_dir = g_dir_open (ibft_path, 0, &error);
	if (!ibft_dir) {
		_LOGW (LOGD_CORE, "Unable to open iBFT firmware directory: %s", error->message);
		return ibft;
	}

	while ((dir_name = g_dir_read_name (ibft_dir))) {
		if (!g_str_has_prefix (dir_name, "ethernet"))
			continue;

		nic = load_one_nic (ibft_path, dir_name);
		mac = g_hash_table_lookup (nic, "mac");

		if (!mac) {
			_LOGW (LOGD_CORE, "Ignoring an iBFT record without a MAC address");
			g_hash_table_unref (nic);
			continue;
		}

		mac = g_ascii_strup (mac, -1);
		if (!g_hash_table_insert (ibft, mac, nic))
			_LOGW (LOGD_CORE, "Duplicate iBFT record for %s", mac);
	}

	g_dir_close (ibft_dir);

	return ibft;
}

static gboolean
ip_setting_add_from_block (GHashTable *nic,
                            NMConnection *connection,
                            GError **error)
{
	NMSettingIPConfig *s_ip = NULL;
	NMSettingIPConfig *s_ip4 = NULL;
	NMSettingIPConfig *s_ip6 = NULL;
	NMIPAddress *addr;
	const char *s_ipaddr = NULL;
	const char *s_prefix = NULL;
	const char *s_gateway = NULL;
	const char *s_dns1 = NULL;
	const char *s_dns2 = NULL;
	const char *s_origin = NULL;
	const char *method = NULL;
	int family;
	gint64 prefix;

	s_ipaddr = (const char *)g_hash_table_lookup (nic, "ip-addr");
	s_prefix = (const char *)g_hash_table_lookup (nic, "prefix-len");
	s_gateway = (const char *)g_hash_table_lookup (nic, "gateway");
	s_dns1 = (const char *)g_hash_table_lookup (nic, "primary-dns");
	s_dns2 = (const char *)g_hash_table_lookup (nic, "secondary-dns");
	s_origin = (const char *)g_hash_table_lookup (nic, "origin");

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	if (!s_ip4) {
		s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
		nm_connection_add_setting (connection, (NMSetting *) s_ip4);
	}

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	if (!s_ip6) {
		s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
		nm_connection_add_setting (connection, (NMSetting *) s_ip6);
	}

	family = guess_ip_address_family (s_ipaddr);
	if (family == AF_UNSPEC)
		family = guess_ip_address_family (s_gateway);

	switch (family) {
	case AF_INET:
		s_ip = s_ip4;
		g_object_set (s_ip6, NM_SETTING_IP_CONFIG_METHOD,
		              NM_SETTING_IP6_CONFIG_METHOD_IGNORE, NULL);
		break;
	case AF_INET6:
		s_ip = s_ip6;
		g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD,
		              NM_SETTING_IP4_CONFIG_METHOD_DISABLED, NULL);
		break;
	default:
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "iBFT: invalid IP address '%s'.",
		             s_ipaddr);
		return FALSE;
	}

	if (   (g_strcmp0 (s_origin, "3") == 0 && family == AF_INET)
	    || (g_strcmp0 (s_origin, "4") == 0 && family == AF_INET)) {
		method = NM_SETTING_IP4_CONFIG_METHOD_AUTO;
	} else if (g_strcmp0 (s_origin, "3") == 0 && family == AF_INET6) {
		method = NM_SETTING_IP6_CONFIG_METHOD_DHCP;
	} else if (g_strcmp0 (s_origin, "4") == 0 && family == AF_INET6) {
		method = NM_SETTING_IP6_CONFIG_METHOD_AUTO;
	} else if (family == AF_INET) {
		method = NM_SETTING_IP4_CONFIG_METHOD_MANUAL;
	} else if (family == AF_INET6) {
		method = NM_SETTING_IP6_CONFIG_METHOD_MANUAL;
	} else {
		g_return_val_if_reached (FALSE);
	}
	g_object_set (s_ip,
                      NM_SETTING_IP_CONFIG_METHOD, method,
                      NM_SETTING_IP_CONFIG_MAY_FAIL, FALSE,
	              NULL);

	if (s_gateway && !nm_utils_ipaddr_valid (family, s_gateway)) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "iBFT: invalid IP gateway '%s'.", s_gateway);
		return FALSE;
	}

	if (s_dns1 && !nm_utils_ipaddr_valid (family, s_dns1)) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "iBFT: invalid DNS1 address '%s'.", s_dns1);
		return FALSE;
	}

	if (s_dns2 && !nm_utils_ipaddr_valid (family, s_dns2)) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "iBFT: invalid DNS2 address '%s'.", s_dns2);
		return FALSE;
	}

	if (s_ipaddr) {
		prefix = _nm_utils_ascii_str_to_int64 (s_prefix, 10, 0, 128, -1);
		if (prefix == -1) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "iBFT: invalid IP prefix '%s'.", s_prefix);
			return FALSE;
		}

		addr = nm_ip_address_new (family, s_ipaddr, prefix, error);
		if (!addr) {
			g_prefix_error (error, "iBFT: ");
			return FALSE;
		}

		nm_setting_ip_config_add_address (s_ip, addr);
		nm_ip_address_unref (addr);

		g_object_set (s_ip, NM_SETTING_IP_CONFIG_GATEWAY, s_gateway, NULL);
	}

	if (s_dns1)
		nm_setting_ip_config_add_dns (s_ip, s_dns1);
	if (s_dns2)
		nm_setting_ip_config_add_dns (s_ip, s_dns2);

	return TRUE;
}

static gboolean
connection_setting_add (GHashTable *nic,
                        NMConnection *connection,
                        const char *type,
                        const char *prefix,
                        GError **error)
{
	NMSetting *s_con;
	char *id, *uuid;
	const char *s_index, *s_hwaddr, *s_ipaddr, *s_vlanid;

	s_index = (const char *)g_hash_table_lookup (nic, "index");
	s_hwaddr = (const char *)g_hash_table_lookup (nic, "mac");
	s_ipaddr = (const char *)g_hash_table_lookup (nic, "ip-addr");
	s_vlanid = (const char *)g_hash_table_lookup (nic, "vlan");

	if (!s_hwaddr) {
		g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		                     "iBFT: missing MAC address");
		return FALSE;
	}

	id = g_strdup_printf ("iBFT%s%s Connection%s%s",
	                      prefix ? " " : "",
	                      prefix ? prefix : "",
	                      s_index ? " " : "",
	                      s_index ? s_index : "");

	uuid = _nm_utils_uuid_generate_from_strings ("ibft",
	                                             s_hwaddr,
	                                             s_vlanid ? "V" : "v",
	                                             s_vlanid ? s_vlanid : "",
	                                             s_ipaddr ? "A" : "DHCP",
	                                             s_ipaddr ? s_ipaddr : "",
	                                             NULL);

	s_con = (NMSetting *) nm_connection_get_setting_connection (connection);
	if (!s_con) {
		s_con = nm_setting_connection_new ();
		nm_connection_add_setting (connection, s_con);
	}

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_TYPE, type,
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_ID, id,
	              NULL);

	g_free (uuid);
	g_free (id);

	return TRUE;
}

static gboolean
is_ibft_vlan_device (GHashTable *nic)
{
	const char *s_vlan_id;

	g_assert (nic);

	s_vlan_id = (const char *)g_hash_table_lookup (nic, "vlan");

	if (s_vlan_id) {
		/* VLAN 0 is normally a valid VLAN ID, but in the iBFT case it
		 * means "no VLAN".
		 */
		if (_nm_utils_ascii_str_to_int64 (s_vlan_id, 10, 1, 4095, -1) != -1)
			return TRUE;
	}

	return FALSE;
}

static gboolean
vlan_setting_add_from_block (GHashTable *nic,
                             NMConnection *connection,
                             GError **error)
{
	NMSetting *s_vlan = NULL;
	const char *vlan_id_str = NULL;
	gint64 vlan_id = -1;

	g_assert (nic);
	g_assert (connection);

	/* This won't fail since this function shouldn't be called unless the
	 * iBFT VLAN ID exists and is > 0.
	 */
	vlan_id_str = (const char *)g_hash_table_lookup (nic, "vlan");
	g_assert (vlan_id_str);

	/* VLAN 0 is normally a valid VLAN ID, but in the iBFT case it means "no VLAN" */
	vlan_id = _nm_utils_ascii_str_to_int64 (vlan_id_str, 10, 1, 4095, -1);
	if (vlan_id == -1) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Invalid VLAN_ID '%s'", vlan_id_str);
		return FALSE;
	}

	s_vlan = (NMSetting *) nm_connection_get_setting_vlan (connection);
	if (!s_vlan) {
		s_vlan = nm_setting_vlan_new ();
		nm_connection_add_setting (connection, s_vlan);
	}

	g_object_set (s_vlan, NM_SETTING_VLAN_ID, (guint32) vlan_id, NULL);

	return TRUE;
}

static gboolean
wired_setting_add_from_block (GHashTable *nic,
                              NMConnection *connection,
                              GError **error)
{
	NMSetting *s_wired = NULL;
	const char *hwaddr = NULL;

	g_assert (nic);
	g_assert (connection);


	hwaddr = (const char *)g_hash_table_lookup (nic, "mac");
	if (!hwaddr) {
		g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		                     "iBFT: missing MAC address");
		return FALSE;
	}

	if (!nm_utils_hwaddr_valid (hwaddr, ETH_ALEN)) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "iBFT: invalid MAC address '%s'.", hwaddr);
		return FALSE;
	}

	s_wired = (NMSetting *) nm_connection_get_setting_wired (connection);
	if (!s_wired) {
		s_wired = nm_setting_wired_new ();
		nm_connection_add_setting (connection, s_wired);
	}

	g_object_set (s_wired, NM_SETTING_WIRED_MAC_ADDRESS, hwaddr, NULL);

	return TRUE;
}

gboolean
nmi_ibft_update_connection_from_nic (NMConnection *connection, GHashTable *nic, GError **error)
{
	gboolean is_vlan = FALSE;

	g_assert (nic);

	is_vlan = is_ibft_vlan_device (nic);
	if (is_vlan && !vlan_setting_add_from_block (nic, connection, error))
		return FALSE;

	/* Always have a wired setting; for VLAN it defines the parent */
	if (!wired_setting_add_from_block (nic, connection, error))
		return FALSE;

	if (!ip_setting_add_from_block (nic, connection, error))
		return FALSE;

	if (!connection_setting_add (nic,
	                             connection,
	                             is_vlan ? NM_SETTING_VLAN_SETTING_NAME : NM_SETTING_WIRED_SETTING_NAME,
	                             is_vlan ? "VLAN" : NULL,
	                             error))
		return FALSE;

	if (!nm_connection_normalize (connection, NULL, NULL, error))
		return FALSE;

	return TRUE;
}
