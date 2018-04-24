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
 * Copyright 2014 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nms-ibft-reader.h"

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

#include "nm-core-internal.h"
#include "platform/nm-platform.h"
#include "NetworkManagerUtils.h"

/*****************************************************************************/

#define PARSE_WARNING(msg...) nm_log_warn (LOGD_SETTINGS, "    " msg)

/* Removes trailing whitespace and whitespace before and immediately after the '=' */
static char *
remove_most_whitespace (const char *src)
{
	char *s_new, *s2;
	const char *svalue;

	while (*src && g_ascii_isspace (*src))
		src++;

	svalue = strchr (src, '=');
	if (!svalue || svalue == src)
		return NULL;

	s_new = g_new (char, strlen (src) + 1);

	memcpy (s_new, src, svalue - src);
	s_new[svalue - src] = '\0';
	g_strchomp (s_new);

	svalue++;
	while (*svalue && g_ascii_isspace (*svalue))
		svalue++;

	s2 = strchr (s_new, '\0');
	s2[0] = '=';
	strcpy (++s2, svalue);
	g_strchomp (s2);

	return s_new;
}

#define TAG_BEGIN "# BEGIN RECORD"
#define TAG_END   "# END RECORD"

/**
 * nms_ibft_reader_load_blocks:
 * @iscsiadm_path: path to iscsiadm program
 * @out_blocks: on return if successful, a #GSList of #GPtrArray, or %NULL on
 * failure
 * @error: location for an error on failure
 *
 * Parses iscsiadm output and returns a #GSList of #GPtrArray in the @out_blocks
 * argument on success, otherwise @out_blocks is set to %NULL.  Each #GPtrArray
 * in @out_blocks contains the lines from an iscsiadm interface block.
 *
 * Returns: %TRUE on success, %FALSE on errors
 */
gboolean
nms_ibft_reader_load_blocks (const char *iscsiadm_path,
                             GSList **out_blocks,
                             GError **error)
{
	const char *argv[4] = { iscsiadm_path, "-m", "fw", NULL };
	const char *envp[1] = { NULL };
	GSList *blocks = NULL;
	char *out = NULL, *err = NULL;
	gint status = 0;
	char **lines = NULL, **iter;
	GPtrArray *block_lines = NULL;
	gboolean success = FALSE;

	g_return_val_if_fail (iscsiadm_path != NULL, FALSE);
	g_return_val_if_fail (out_blocks != NULL && *out_blocks == NULL, FALSE);

	if (!g_spawn_sync ("/", (char **) argv, (char **) envp, 0,
	                   NULL, NULL, &out, &err, &status, error))
		goto done;

	if (!WIFEXITED (status)) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "iBFT: %s exited abnormally.", iscsiadm_path);
		goto done;
	}

	if (WEXITSTATUS (status) != 0) {
		if (err) {
			char *nl;

			/* the error message contains newlines. concatenate the lines with whitespace */
			for (nl = err; *nl; nl++) {
				if (*nl == '\n')
					*nl = ' ';
			}
		}
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "iBFT: %s exited with error %d.  Message: '%s'",
		             iscsiadm_path, WEXITSTATUS (status), err ?: "(none)");
		goto done;
	}

	nm_log_dbg (LOGD_SETTINGS, "iBFT records:\n%s", out);

	lines = g_strsplit_set (out, "\n\r", -1);
	for (iter = lines; iter && *iter; iter++) {
		if (!*iter[0])
			continue;

		if (!g_ascii_strncasecmp (*iter, TAG_BEGIN, NM_STRLEN (TAG_BEGIN))) {
			if (block_lines) {
				PARSE_WARNING ("malformed iscsiadm record: missing END RECORD.");
				g_ptr_array_unref (block_lines);
			}
			/* Start new record */
			block_lines = g_ptr_array_new_full (15, g_free);
		} else if (!g_ascii_strncasecmp (*iter, TAG_END, NM_STRLEN (TAG_END))) {
			if (block_lines) {
				if (block_lines->len)
					blocks = g_slist_prepend (blocks, block_lines);
				else
					g_ptr_array_unref (block_lines);
				block_lines = NULL;
			}
		} else if (block_lines) {
			char *s = remove_most_whitespace (*iter);

			if (s)
				g_ptr_array_add (block_lines, s);
			else {
				PARSE_WARNING ("malformed iscsiadm record: no = in '%s'.", *iter);
				g_clear_pointer (&block_lines, g_ptr_array_unref);
			}
		}
	}

	if (block_lines) {
		PARSE_WARNING ("malformed iscsiadm record: missing # END RECORD.");
		g_clear_pointer (&block_lines, g_ptr_array_unref);
	}
	success = TRUE;

done:
	if (lines)
		g_strfreev (lines);
	g_free (out);
	g_free (err);
	if (success)
		*out_blocks = blocks;
	else
		g_slist_free_full (blocks, (GDestroyNotify) g_ptr_array_unref);
	return success;
}

#define ISCSI_HWADDR_TAG     "iface.hwaddress"
#define ISCSI_BOOTPROTO_TAG  "iface.bootproto"
#define ISCSI_IPADDR_TAG     "iface.ipaddress"
#define ISCSI_SUBNET_TAG     "iface.subnet_mask"
#define ISCSI_GATEWAY_TAG    "iface.gateway"
#define ISCSI_DNS1_TAG       "iface.primary_dns"
#define ISCSI_DNS2_TAG       "iface.secondary_dns"
#define ISCSI_VLAN_ID_TAG    "iface.vlan_id"
#define ISCSI_IFACE_TAG      "iface.net_ifacename"

static const char *
match_iscsiadm_tag (const char *line, const char *tag)
{
	gsize taglen = strlen (tag);

	if (g_ascii_strncasecmp (line, tag, taglen) != 0)
		return NULL;
	if (line[taglen] != '=')
		return NULL;
	return line + taglen + 1;
}

/**
 * nms_ibft_reader_parse_block:
 * @block: an array of iscsiadm interface block lines
 * @error: return location for errors
 * @...: pairs of key (const char *) : location (const char **) indicating the
 * key to look for and the location to store the retrieved value in
 *
 * Parses an iscsiadm interface block into variables requested by the caller.
 * Callers should verify the returned data is complete and valid.  Returned
 * strings are owned by @block and should not be used after @block is freed.
 *
 * Returns: %TRUE if at least , %FALSE on failure
 */
gboolean
nms_ibft_reader_parse_block (const GPtrArray *block, GError **error, ...)
{
	gboolean success = FALSE;
	const char **out_value, *p;
	va_list ap;
	const char *key;
	guint i;

	g_return_val_if_fail (block != NULL, FALSE);
	g_return_val_if_fail (block->len > 0, FALSE);

	/* Find requested keys and populate return values */
	va_start (ap, error);
	while ((key = va_arg (ap, const char *))) {
		out_value = va_arg (ap, const char **);
		*out_value = NULL;
		for (i = 0; i < block->len; i++) {
			p = match_iscsiadm_tag (g_ptr_array_index (block, i), key);
			if (p) {
				*out_value = p;
				success = TRUE;
				break;
			}
		}
	}
	va_end (ap);

	if (!success) {
		g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		                     "iBFT: failed to match at least one iscsiadm block field");
	}
	return success;
}

static gboolean
ip4_setting_add_from_block (const GPtrArray *block,
                            NMConnection *connection,
                            GError **error)
{
	NMSettingIPConfig *s_ip4 = NULL;
	NMIPAddress *addr;
	const char *s_method = NULL;
	const char *s_ipaddr = NULL;
	const char *s_gateway = NULL;
	const char *s_dns1 = NULL;
	const char *s_dns2 = NULL;
	const char *s_netmask = NULL;
	guint32 netmask = 0;
	guint32 prefix;

	g_assert (block);

	if (!nms_ibft_reader_parse_block (block, error,
	                                  ISCSI_BOOTPROTO_TAG, &s_method,
	                                  ISCSI_IPADDR_TAG,    &s_ipaddr,
	                                  ISCSI_SUBNET_TAG,    &s_netmask,
	                                  ISCSI_GATEWAY_TAG,   &s_gateway,
	                                  ISCSI_DNS1_TAG,      &s_dns1,
	                                  ISCSI_DNS2_TAG,      &s_dns2,
	                                  NULL))
		goto error;

	if (!s_method) {
		g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		                     "iBFT: malformed iscsiadm record: missing " ISCSI_BOOTPROTO_TAG);
		goto error;
	}

	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();

	if (!g_ascii_strcasecmp (s_method, "dhcp")) {
		g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);
		goto success;
	} else if (g_ascii_strcasecmp (s_method, "static") != 0) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "iBFT: malformed iscsiadm record: unknown " ISCSI_BOOTPROTO_TAG " '%s'.",
		             s_method);
		goto error;
	}

	/* Static configuration stuff */
	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL, NULL);

	/* IP address */
	if (!s_ipaddr || !nm_utils_ipaddr_valid (AF_INET, s_ipaddr)) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "iBFT: malformed iscsiadm record: invalid IP address '%s'.",
		             s_ipaddr);
		goto error;
	}

	/* Subnet/prefix */
	if (!s_netmask || inet_pton (AF_INET, s_netmask, &netmask) != 1) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "iBFT: malformed iscsiadm record: invalid subnet mask '%s'.",
		             s_netmask);
		goto error;
	}
	prefix = nm_utils_ip4_netmask_to_prefix (netmask);

	if (s_gateway && !nm_utils_ipaddr_valid (AF_INET, s_gateway)) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "iBFT: malformed iscsiadm record: invalid IP gateway '%s'.",
		             s_gateway);
		goto error;
	}

	if (s_dns1 && !nm_utils_ipaddr_valid (AF_INET, s_dns1)) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "iBFT: malformed iscsiadm record: invalid DNS1 address '%s'.",
		             s_dns1);
		goto error;
	}

	if (s_dns2 && !nm_utils_ipaddr_valid (AF_INET, s_dns2)) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "iBFT: malformed iscsiadm record: invalid DNS2 address '%s'.",
		             s_dns2);
		goto error;
	}

	addr = nm_ip_address_new (AF_INET, s_ipaddr, prefix, error);
	if (!addr) {
		g_prefix_error (error, "iBFT: malformed iscsiadm record: ");
		goto error;
	}

	nm_setting_ip_config_add_address (s_ip4, addr);
	nm_ip_address_unref (addr);

	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_GATEWAY, s_gateway, NULL);

	if (s_dns1)
		nm_setting_ip_config_add_dns (s_ip4, s_dns1);
	if (s_dns2)
		nm_setting_ip_config_add_dns (s_ip4, s_dns2);

success:
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));
	return TRUE;

error:
	g_clear_object (&s_ip4);
	return FALSE;
}

static gboolean
connection_setting_add (const GPtrArray *block,
                        NMConnection *connection,
                        const char *type,
                        const char *prefix,
                        const char *iface,
                        GError **error)
{
	NMSetting *s_con;
	char *id, *uuid;
	const char *s_hwaddr = NULL, *s_ip4addr = NULL, *s_vlanid;

	if (!nms_ibft_reader_parse_block (block, error,
	                                  ISCSI_VLAN_ID_TAG, &s_vlanid,
	                                  ISCSI_HWADDR_TAG,  &s_hwaddr,
	                                  ISCSI_IPADDR_TAG,  &s_ip4addr,
	                                  NULL))
		return FALSE;
	if (!s_hwaddr) {
		g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		                     "iBFT: malformed iscsiadm record: missing " ISCSI_HWADDR_TAG);
		return FALSE;
	}

	id = g_strdup_printf ("iBFT%s%s %s",
	                      prefix ? " " : "",
	                      prefix ?: "",
	                      iface);

	uuid = _nm_utils_uuid_generate_from_strings ("ibft",
	                                             s_hwaddr,
	                                             s_vlanid ? "V" : "v",
	                                             s_vlanid ?: "",
	                                             s_ip4addr ? "A" : "DHCP",
	                                             s_ip4addr ?: "",
	                                             NULL);

	s_con = nm_setting_connection_new ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_TYPE, type,
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_ID, id,
	              NM_SETTING_CONNECTION_READ_ONLY, TRUE,
	              NULL);

	g_free (uuid);
	g_free (id);

	nm_connection_add_setting (connection, NM_SETTING (s_con));
	return TRUE;
}

static gboolean
is_ibft_vlan_device (const GPtrArray *block)
{
	char *s_vlan_id = NULL;

	if (nms_ibft_reader_parse_block (block, NULL, ISCSI_VLAN_ID_TAG, &s_vlan_id, NULL)) {
		g_assert (s_vlan_id);

		/* VLAN 0 is normally a valid VLAN ID, but in the iBFT case it
		 * means "no VLAN".
		 */
		if (_nm_utils_ascii_str_to_int64 (s_vlan_id, 10, 1, 4095, -1) != -1)
			return TRUE;
	}
	return FALSE;
}

static gboolean
vlan_setting_add_from_block (const GPtrArray *block,
                             NMConnection *connection,
                             GError **error)
{
	NMSetting *s_vlan = NULL;
	const char *vlan_id_str = NULL;
	gint64 vlan_id = -1;
	gboolean success;

	g_assert (block);
	g_assert (connection);

	/* This won't fail since this function shouldn't be called unless the
	 * iBFT VLAN ID exists and is > 0.
	 */
	success = nms_ibft_reader_parse_block (block, NULL, ISCSI_VLAN_ID_TAG, &vlan_id_str, NULL);
	g_assert (success);
	g_assert (vlan_id_str);

	/* VLAN 0 is normally a valid VLAN ID, but in the iBFT case it means "no VLAN" */
	vlan_id = _nm_utils_ascii_str_to_int64 (vlan_id_str, 10, 1, 4095, -1);
	if (vlan_id == -1) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Invalid VLAN_ID '%s'", vlan_id_str);
		return FALSE;
	}

	s_vlan = nm_setting_vlan_new ();
	g_object_set (s_vlan, NM_SETTING_VLAN_ID, (guint32) vlan_id, NULL);
	nm_connection_add_setting (connection, NM_SETTING (s_vlan));

	return TRUE;
}

static gboolean
wired_setting_add_from_block (const GPtrArray *block,
                              NMConnection *connection,
                              GError **error)
{
	NMSetting *s_wired = NULL;
	const char *hwaddr = NULL;

	g_assert (block);
	g_assert (connection);

	if (!nms_ibft_reader_parse_block (block, NULL, ISCSI_HWADDR_TAG, &hwaddr, NULL)) {
		g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		                     "iBFT: malformed iscsiadm record: missing " ISCSI_HWADDR_TAG);
		return FALSE;
	}

	if (!nm_utils_hwaddr_valid (hwaddr, ETH_ALEN)) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "iBFT: malformed iscsiadm record: invalid " ISCSI_HWADDR_TAG " '%s'.",
		             hwaddr);
		return FALSE;
	}

	s_wired = nm_setting_wired_new ();
	g_object_set (s_wired, NM_SETTING_WIRED_MAC_ADDRESS, hwaddr, NULL);

	nm_connection_add_setting (connection, s_wired);
	return TRUE;
}

NMConnection *
nms_ibft_reader_get_connection_from_block (const GPtrArray *block, GError **error)
{
	NMConnection *connection = NULL;
	gboolean is_vlan = FALSE;
	const char *iface = NULL;

	g_assert (block);

	if (!nms_ibft_reader_parse_block (block, error, ISCSI_IFACE_TAG, &iface, NULL)) {
		g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		                     "iBFT: malformed iscsiadm record: missing " ISCSI_IFACE_TAG);
		return NULL;
	}

	connection = nm_simple_connection_new ();

	is_vlan = is_ibft_vlan_device (block);
	if (is_vlan && !vlan_setting_add_from_block (block, connection, error))
		goto error;

	/* Always have a wired setting; for VLAN it defines the parent */
	if (!wired_setting_add_from_block (block, connection, error))
		goto error;

	if (!ip4_setting_add_from_block (block, connection, error))
		goto error;

	if (!connection_setting_add (block,
	                             connection,
	                             is_vlan ? NM_SETTING_VLAN_SETTING_NAME : NM_SETTING_WIRED_SETTING_NAME,
	                             is_vlan ? "VLAN" : NULL,
	                             iface,
	                             error))
		goto error;

	if (!nm_connection_normalize (connection, NULL, NULL, error))
		goto error;

	return connection;

error:
	g_object_unref (connection);
	return NULL;
}

