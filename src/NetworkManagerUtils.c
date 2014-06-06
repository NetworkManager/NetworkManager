/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * Copyright (C) 2004 - 2012 Red Hat, Inc.
 * Copyright (C) 2005 - 2008 Novell, Inc.
 */

#include <glib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <resolv.h>

#include "NetworkManagerUtils.h"
#include "nm-utils.h"
#include "nm-logging.h"
#include "nm-device.h"
#include "nm-setting-connection.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-ip6-config.h"
#include "nm-setting-wireless.h"
#include "nm-setting-wireless-security.h"
#include "nm-manager-auth.h"
#include "nm-posix-signals.h"

/*
 * nm_ethernet_address_is_valid
 *
 * Compares an Ethernet address against known invalid addresses.
 *
 */
gboolean
nm_ethernet_address_is_valid (const struct ether_addr *test_addr)
{
	guint8 invalid_addr1[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	guint8 invalid_addr2[ETH_ALEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	guint8 invalid_addr3[ETH_ALEN] = {0x44, 0x44, 0x44, 0x44, 0x44, 0x44};
	guint8 invalid_addr4[ETH_ALEN] = {0x00, 0x30, 0xb4, 0x00, 0x00, 0x00}; /* prism54 dummy MAC */

	g_return_val_if_fail (test_addr != NULL, FALSE);

	/* Compare the AP address the card has with invalid ethernet MAC addresses. */
	if (!memcmp (test_addr->ether_addr_octet, &invalid_addr1, ETH_ALEN))
		return FALSE;

	if (!memcmp (test_addr->ether_addr_octet, &invalid_addr2, ETH_ALEN))
		return FALSE;

	if (!memcmp (test_addr->ether_addr_octet, &invalid_addr3, ETH_ALEN))
		return FALSE;

	if (!memcmp (test_addr->ether_addr_octet, &invalid_addr4, ETH_ALEN))
		return FALSE;

	if (test_addr->ether_addr_octet[0] & 1)			/* Multicast addresses */
		return FALSE;
	
	return TRUE;
}


/* nm_utils_ip4_address_clear_host_address:
 * @addr: source ip6 address
 * @plen: prefix length of network
 *
 * returns: the input address, with the host address set to 0.
 */
in_addr_t
nm_utils_ip4_address_clear_host_address (in_addr_t addr, guint8 plen)
{
	return addr & nm_utils_ip4_prefix_to_netmask (plen);
}

/* nm_utils_ip6_address_clear_host_address:
 * @dst: destination output buffer, will contain the network part of the @src address
 * @src: source ip6 address
 * @plen: prefix length of network
 *
 * Note: this function is self assignment save, to update @src inplace, set both
 * @dst and @src to the same destination.
 */
void
nm_utils_ip6_address_clear_host_address (struct in6_addr *dst, const struct in6_addr *src, guint8 plen)
{
	g_return_if_fail (plen <= 128);
	g_return_if_fail (src);
	g_return_if_fail (dst);

	if (plen < 128) {
		guint nbytes = plen / 8;
		guint nbits = plen % 8;

		if (nbytes && dst != src)
			memcpy (dst, src, nbytes);
		if (nbits) {
			dst->s6_addr[nbytes] = (src->s6_addr[nbytes] & (0xFF << (8 - nbits)));
			nbytes++;
		}
		if (nbytes <= 15)
			memset (&dst->s6_addr[nbytes], 0, 16 - nbytes);
	} else if (src != dst)
		*dst = *src;
}


int
nm_spawn_process (const char *args)
{
	gint num_args;
	char **argv = NULL;
	int status = -1;
	GError *error = NULL;

	g_return_val_if_fail (args != NULL, -1);

	if (!g_shell_parse_argv (args, &num_args, &argv, &error)) {
		nm_log_warn (LOGD_CORE, "could not parse arguments for '%s': %s", args, error->message);
		g_error_free (error);
		return -1;
	}

	if (!g_spawn_sync ("/", argv, NULL, 0, nm_unblock_posix_signals, NULL, NULL, NULL, &status, &error)) {
		nm_log_warn (LOGD_CORE, "could not spawn process '%s': %s", args, error->message);
		g_error_free (error);
	}

	g_strfreev (argv);
	return status;
}

gboolean
nm_match_spec_string (const GSList *specs, const char *match)
{
	const GSList *iter;

	for (iter = specs; iter; iter = g_slist_next (iter)) {
		if (!g_ascii_strcasecmp ((const char *) iter->data, match))
			return TRUE;
	}

	return FALSE;
}

gboolean
nm_match_spec_hwaddr (const GSList *specs, const char *hwaddr)
{
	char *hwaddr_match;
	gboolean matched;

	g_return_val_if_fail (hwaddr != NULL, FALSE);

	hwaddr_match = g_strdup_printf ("mac:%s", hwaddr);
	matched = nm_match_spec_string (specs, hwaddr_match);
	g_free (hwaddr_match);
	return matched;
}

gboolean
nm_match_spec_interface_name (const GSList *specs, const char *interface_name)
{
	char *iface_match;
	gboolean matched;

	g_return_val_if_fail (interface_name != NULL, FALSE);

	iface_match = g_strdup_printf ("interface-name:%s", interface_name);
	matched = nm_match_spec_string (specs, iface_match);
	g_free (iface_match);
	return matched;
}

#define BUFSIZE 10

static gboolean
parse_subchannels (const char *subchannels, guint32 *a, guint32 *b, guint32 *c)
{
	long unsigned int tmp;
	char buf[BUFSIZE + 1];
	const char *p = subchannels;
	int i = 0;
	char *pa = NULL, *pb = NULL, *pc = NULL;

	g_return_val_if_fail (subchannels != NULL, FALSE);
	g_return_val_if_fail (a != NULL, FALSE);
	g_return_val_if_fail (*a == 0, FALSE);
	g_return_val_if_fail (b != NULL, FALSE);
	g_return_val_if_fail (*b == 0, FALSE);
	g_return_val_if_fail (c != NULL, FALSE);
	g_return_val_if_fail (*c == 0, FALSE);

	/* sanity check */
	if (!g_ascii_isxdigit (subchannels[0]))
		return FALSE;

	/* Get the first channel */
	while (*p && (*p != ',')) {
		if (!g_ascii_isxdigit (*p) && (*p != '.'))
			return FALSE;  /* Invalid chars */
		if (i >= BUFSIZE)
			return FALSE;  /* Too long to be a subchannel */
		buf[i++] = *p++;
	}
	buf[i] = '\0';

	/* and grab each of its elements, there should be 3 */
	pa = &buf[0];
	pb = strchr (buf, '.');
	if (pb)
		pc = strchr (pb + 1, '.');
	if (!pa || !pb || !pc)
		return FALSE;

	/* Split the string */
	*pb++ = '\0';
	*pc++ = '\0';

	errno = 0;
	tmp = strtoul (pa, NULL, 16);
	if (errno)
		return FALSE;
	*a = (guint32) tmp;

	errno = 0;
	tmp = strtoul (pb, NULL, 16);
	if (errno)
		return FALSE;
	*b = (guint32) tmp;

	errno = 0;
	tmp = strtoul (pc, NULL, 16);
	if (errno)
		return FALSE;
	*c = (guint32) tmp;

	return TRUE;
}

#define SUBCHAN_TAG "s390-subchannels:"

gboolean
nm_match_spec_s390_subchannels (const GSList *specs, const char *subchannels)
{
	const GSList *iter;
	guint32 a = 0, b = 0, c = 0;
	guint32 spec_a = 0, spec_b = 0, spec_c = 0;

	g_return_val_if_fail (subchannels != NULL, FALSE);

	if (!parse_subchannels (subchannels, &a, &b, &c))
		return FALSE;

	for (iter = specs; iter; iter = g_slist_next (iter)) {
		const char *spec = iter->data;

		if (!strncmp (spec, SUBCHAN_TAG, strlen (SUBCHAN_TAG))) {
			spec += strlen (SUBCHAN_TAG);
			if (parse_subchannels (spec, &spec_a, &spec_b, &spec_c)) {
				if (a == spec_a && b == spec_b && c == spec_c)
					return TRUE;
			}
		}
	}

	return FALSE;
}

const char *
nm_utils_get_shared_wifi_permission (NMConnection *connection)
{
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	const char *method = NULL;

	method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP4_CONFIG);
	if (strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_SHARED) != 0)
		return NULL;  /* Not shared */

	s_wifi = nm_connection_get_setting_wireless (connection);
	if (s_wifi) {
		s_wsec = nm_connection_get_setting_wireless_security (connection);
		if (s_wsec)
			return NM_AUTH_PERMISSION_WIFI_SHARE_PROTECTED;
		else
			return NM_AUTH_PERMISSION_WIFI_SHARE_OPEN;
	}

	return NULL;
}

/*********************************/

static void
nm_gvalue_destroy (gpointer data)
{
	GValue *value = (GValue *) data;

	g_value_unset (value);
	g_slice_free (GValue, value);
}

GHashTable *
value_hash_create (void)
{
	return g_hash_table_new_full (g_str_hash, g_str_equal, g_free, nm_gvalue_destroy);
}

void
value_hash_add (GHashTable *hash,
				const char *key,
				GValue *value)
{
	g_hash_table_insert (hash, g_strdup (key), value);
}

void
value_hash_add_str (GHashTable *hash,
					const char *key,
					const char *str)
{
	GValue *value;

	value = g_slice_new0 (GValue);
	g_value_init (value, G_TYPE_STRING);
	g_value_set_string (value, str);

	value_hash_add (hash, key, value);
}

void
value_hash_add_object_path (GHashTable *hash,
							const char *key,
							const char *op)
{
	GValue *value;

	value = g_slice_new0 (GValue);
	g_value_init (value, DBUS_TYPE_G_OBJECT_PATH);
	g_value_set_boxed (value, op);

	value_hash_add (hash, key, value);
}

void
value_hash_add_uint (GHashTable *hash,
					 const char *key,
					 guint32 val)
{
	GValue *value;

	value = g_slice_new0 (GValue);
	g_value_init (value, G_TYPE_UINT);
	g_value_set_uint (value, val);

	value_hash_add (hash, key, value);
}

void
value_hash_add_bool (GHashTable *hash,
					 const char *key,
					 gboolean val)
{
	GValue *value;

	value = g_slice_new0 (GValue);
	g_value_init (value, G_TYPE_BOOLEAN);
	g_value_set_boolean (value, val);

	value_hash_add (hash, key, value);
}

void
value_hash_add_object_property (GHashTable *hash,
                                const char *key,
                                GObject *object,
                                const char *prop,
                                GType val_type)
{
	GValue *value;

	value = g_slice_new0 (GValue);
	g_value_init (value, val_type);
	g_object_get_property (object, prop, value);
	value_hash_add (hash, key, value);
}


static char *
get_new_connection_name (const GSList *existing,
                         const char *format,
                         const char *preferred)
{
	GSList *names = NULL;
	const GSList *iter;
	char *cname = NULL;
	int i = 0;
	gboolean preferred_found = FALSE;

	for (iter = existing; iter; iter = g_slist_next (iter)) {
		NMConnection *candidate = NM_CONNECTION (iter->data);
		const char *id;

		id = nm_connection_get_id (candidate);
		g_assert (id);
		names = g_slist_append (names, (gpointer) id);

		if (preferred && !preferred_found && (strcmp (preferred, id) == 0))
			preferred_found = TRUE;
	}

	/* Return the preferred name if it was unique */
	if (preferred && !preferred_found) {
		g_slist_free (names);
		return g_strdup (preferred);
	}

	/* Otherwise find the next available unique connection name using the given
	 * connection name template.
	 */
	while (!cname && (i++ < 10000)) {
		char *temp;
		gboolean found = FALSE;

		temp = g_strdup_printf (format, i);
		for (iter = names; iter; iter = g_slist_next (iter)) {
			if (!strcmp (iter->data, temp)) {
				found = TRUE;
				break;
			}
		}
		if (!found)
			cname = temp;
		else
			g_free (temp);
	}

	g_slist_free (names);
	return cname;
}

void
nm_utils_normalize_connection (NMConnection *connection,
                               gboolean default_enable_ipv6)
{
	NMSettingConnection *s_con = nm_connection_get_setting_connection (connection);
	const char *default_ip4_method = NM_SETTING_IP4_CONFIG_METHOD_AUTO;
	const char *default_ip6_method =
		default_enable_ipv6 ? NM_SETTING_IP6_CONFIG_METHOD_AUTO : NM_SETTING_IP6_CONFIG_METHOD_IGNORE;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	NMSetting *setting;
	const char *method;

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	s_ip6 = nm_connection_get_setting_ip6_config (connection);

	if (nm_setting_connection_get_master (s_con)) {
		/* Slave connections don't have IP configuration. */

		if (s_ip4) {
			method = nm_setting_ip4_config_get_method (s_ip4);
			if (g_strcmp0 (method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED) != 0) {
				nm_log_warn (LOGD_SETTINGS, "ignoring IP4 config on slave '%s'",
				             nm_connection_get_id (connection));
			}
			nm_connection_remove_setting (connection, NM_TYPE_SETTING_IP4_CONFIG);
			s_ip4 = NULL;
		}

		if (s_ip6) {
			method = nm_setting_ip6_config_get_method (s_ip6);
			if (g_strcmp0 (method, NM_SETTING_IP6_CONFIG_METHOD_IGNORE) != 0) {
				nm_log_warn (LOGD_SETTINGS, "ignoring IP6 config on slave '%s'",
				             nm_connection_get_id (connection));
			}
			nm_connection_remove_setting (connection, NM_TYPE_SETTING_IP6_CONFIG);
			s_ip6 = NULL;
		}
	} else {
		/* Ensure all non-slave connections have IP4 and IP6 settings objects. If no
		 * IP6 setting was specified, then assume that means IP6 config is allowed
		 * to fail. But if no IP4 setting was specified, assume the caller was just
		 * being lazy.
		 */
		if (!s_ip4) {
			setting = nm_setting_ip4_config_new ();
			nm_connection_add_setting (connection, setting);

			g_object_set (setting,
			              NM_SETTING_IP4_CONFIG_METHOD, default_ip4_method,
			              NULL);
		}
		if (!s_ip6) {
			setting = nm_setting_ip6_config_new ();
			nm_connection_add_setting (connection, setting);

			g_object_set (setting,
			              NM_SETTING_IP6_CONFIG_METHOD, default_ip6_method,
			              NM_SETTING_IP6_CONFIG_MAY_FAIL, TRUE,
			              NULL);
		}
	}
}

const char *
nm_utils_get_ip_config_method (NMConnection *connection,
                               GType         ip_setting_type)
{
	NMSettingConnection *s_con;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	const char *method;

	s_con = nm_connection_get_setting_connection (connection);

	if (ip_setting_type == NM_TYPE_SETTING_IP4_CONFIG) {
		g_return_val_if_fail (s_con != NULL, NM_SETTING_IP4_CONFIG_METHOD_AUTO);

		if (nm_setting_connection_get_master (s_con))
			return NM_SETTING_IP4_CONFIG_METHOD_DISABLED;
		else {
			s_ip4 = nm_connection_get_setting_ip4_config (connection);
			g_return_val_if_fail (s_ip4 != NULL, NM_SETTING_IP4_CONFIG_METHOD_AUTO);
			method = nm_setting_ip4_config_get_method (s_ip4);
			g_return_val_if_fail (method != NULL, NM_SETTING_IP4_CONFIG_METHOD_AUTO);

			return method;
		}

	} else if (ip_setting_type == NM_TYPE_SETTING_IP6_CONFIG) {
		g_return_val_if_fail (s_con != NULL, NM_SETTING_IP6_CONFIG_METHOD_AUTO);

		if (nm_setting_connection_get_master (s_con))
			return NM_SETTING_IP6_CONFIG_METHOD_IGNORE;
		else {
			s_ip6 = nm_connection_get_setting_ip6_config (connection);
			g_return_val_if_fail (s_ip6 != NULL, NM_SETTING_IP6_CONFIG_METHOD_AUTO);
			method = nm_setting_ip6_config_get_method (s_ip6);
			g_return_val_if_fail (method != NULL, NM_SETTING_IP6_CONFIG_METHOD_AUTO);

			return method;
		}

	} else
		g_assert_not_reached ();
}

void
nm_utils_complete_generic (NMConnection *connection,
                           const char *ctype,
                           const GSList *existing,
                           const char *format,
                           const char *preferred,
                           gboolean default_enable_ipv6)
{
	NMSettingConnection *s_con;
	char *id, *uuid;

	s_con = nm_connection_get_setting_connection (connection);
	if (!s_con) {
		s_con = (NMSettingConnection *) nm_setting_connection_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_con));
	}
	g_object_set (G_OBJECT (s_con), NM_SETTING_CONNECTION_TYPE, ctype, NULL);

	if (!nm_setting_connection_get_uuid (s_con)) {
		uuid = nm_utils_uuid_generate ();
		g_object_set (G_OBJECT (s_con), NM_SETTING_CONNECTION_UUID, uuid, NULL);
		g_free (uuid);
	}

	/* Add a connection ID if absent */
	if (!nm_setting_connection_get_id (s_con)) {
		id = get_new_connection_name (existing, format, preferred);
		g_object_set (G_OBJECT (s_con), NM_SETTING_CONNECTION_ID, id, NULL);
		g_free (id);
	}

	/* Normalize */
	nm_utils_normalize_connection (connection, default_enable_ipv6);
}

char *
nm_utils_new_vlan_name (const char *parent_iface, guint32 vlan_id)
{
	/* Basically VLAN_NAME_TYPE_RAW_PLUS_VID_NO_PAD */
	return g_strdup_printf ("%s.%d", parent_iface, vlan_id);
}

/**
 * nm_utils_read_resolv_conf_nameservers():
 * @rc_contents: contents of a resolv.conf; or %NULL to read /etc/resolv.conf
 *
 * Reads all nameservers out of @rc_contents or /etc/resolv.conf and returns
 * them.
 *
 * Returns: a #GPtrArray of 'char *' elements of each nameserver line from
 * @contents or resolv.conf
 */
GPtrArray *
nm_utils_read_resolv_conf_nameservers (const char *rc_contents)
{
	GPtrArray *nameservers = NULL;
	char *contents = NULL;
	char **lines, **iter;
	char *p;

	if (rc_contents)
		contents = g_strdup (rc_contents);
	else {
		if (!g_file_get_contents (_PATH_RESCONF, &contents, NULL, NULL))
			return NULL;
	}

	nameservers = g_ptr_array_new_full (3, g_free);

	lines = g_strsplit_set (contents, "\r\n", -1);
	for (iter = lines; *iter; iter++) {
		if (!g_str_has_prefix (*iter, "nameserver"))
			continue;
		p = *iter + strlen ("nameserver");
		if (!g_ascii_isspace (*p++))
			continue;
		/* Skip intermediate whitespace */
		while (g_ascii_isspace (*p))
			p++;
		g_strchomp (p);

		g_ptr_array_add (nameservers, g_strdup (p));
	}
	g_strfreev (lines);
	g_free (contents);

	return nameservers;
}

static GHashTable *
check_property_in_hash (GHashTable *hash,
                        const char *s_name,
                        const char *p_name)
{
	GHashTable *props;

	props = g_hash_table_lookup (hash, s_name);
	if (   !props
	    || !g_hash_table_lookup (props, p_name)) {
		return NULL;
	}
	return props;
}

static void
remove_from_hash (GHashTable *s_hash,
                  GHashTable *p_hash,
                  const char *s_name,
                  const char *p_name)
{
	g_hash_table_remove (p_hash, p_name);
	if (g_hash_table_size (p_hash) == 0)
		g_hash_table_remove (s_hash, s_name);
}

static gboolean
check_ip6_method (NMConnection *orig,
                  NMConnection *candidate,
                  GHashTable *settings)
{
	GHashTable *props;
	const char *orig_ip6_method, *candidate_ip6_method;
	NMSettingIP6Config *candidate_ip6;
	gboolean allow = FALSE;

	props = check_property_in_hash (settings,
	                                NM_SETTING_IP6_CONFIG_SETTING_NAME,
	                                NM_SETTING_IP6_CONFIG_METHOD);
	if (!props)
		return TRUE;

	/* If the generated connection is 'link-local' and the candidate is both 'auto'
	 * and may-fail=TRUE, then the candidate is OK to use.  may-fail is included
	 * in the decision because if the candidate is 'auto' but may-fail=FALSE, then
	 * the connection could not possibly have been previously activated on the
	 * device if the device has no non-link-local IPv6 address.
	 */
	orig_ip6_method = nm_utils_get_ip_config_method (orig, NM_TYPE_SETTING_IP6_CONFIG);
	candidate_ip6_method = nm_utils_get_ip_config_method (candidate, NM_TYPE_SETTING_IP6_CONFIG);
	candidate_ip6 = nm_connection_get_setting_ip6_config (candidate);

	if (   strcmp (orig_ip6_method, NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL) == 0
	    && strcmp (candidate_ip6_method, NM_SETTING_IP6_CONFIG_METHOD_AUTO) == 0
	    && (!candidate_ip6 || nm_setting_ip6_config_get_may_fail (candidate_ip6))) {
		allow = TRUE;
	}

	/* If the generated connection method is 'link-local' or 'auto' and the candidate
	 * method is 'ignore' we can take the connection, because NM didn't simply take care
	 * of IPv6.
	 */
	if (  (   strcmp (orig_ip6_method, NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL) == 0
	       || strcmp (orig_ip6_method, NM_SETTING_IP6_CONFIG_METHOD_AUTO) == 0)
	    && strcmp (candidate_ip6_method, NM_SETTING_IP6_CONFIG_METHOD_IGNORE) == 0) {
		allow = TRUE;
	}

	if (allow) {
		remove_from_hash (settings, props,
		                  NM_SETTING_IP6_CONFIG_SETTING_NAME,
		                  NM_SETTING_IP6_CONFIG_METHOD);
	}
	return allow;
}

static gboolean
check_ip4_method (NMConnection *orig,
                  NMConnection *candidate,
                  GHashTable *settings,
                  gboolean device_has_carrier)
{
	GHashTable *props;
	const char *orig_ip4_method, *candidate_ip4_method;
	NMSettingIP4Config *candidate_ip4;

	props = check_property_in_hash (settings,
	                                NM_SETTING_IP4_CONFIG_SETTING_NAME,
	                                NM_SETTING_IP4_CONFIG_METHOD);
	if (!props)
		return TRUE;

	/* If the generated connection is 'disabled' (device had no IP addresses)
	 * but it has no carrier, that most likely means that IP addressing could
	 * not complete and thus no IP addresses were assigned.  In that case, allow
	 * matching to the "auto" method.
	 */
	orig_ip4_method = nm_utils_get_ip_config_method (orig, NM_TYPE_SETTING_IP4_CONFIG);
	candidate_ip4_method = nm_utils_get_ip_config_method (candidate, NM_TYPE_SETTING_IP4_CONFIG);
	candidate_ip4 = nm_connection_get_setting_ip4_config (candidate);

	if (   strcmp (orig_ip4_method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED) == 0
	    && strcmp (candidate_ip4_method, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0
	    && (!candidate_ip4 || nm_setting_ip4_config_get_may_fail (candidate_ip4))
	    && (device_has_carrier == FALSE)) {
		remove_from_hash (settings, props,
		                  NM_SETTING_IP4_CONFIG_SETTING_NAME,
		                  NM_SETTING_IP4_CONFIG_METHOD);
		return TRUE;
	}
	return FALSE;
}

static gboolean
check_connection_interface_name (NMConnection *orig,
                                 NMConnection *candidate,
                                 GHashTable *settings)
{
	GHashTable *props;
	const char *orig_ifname, *cand_ifname;
	NMSettingConnection *s_con_orig, *s_con_cand;

	props = check_property_in_hash (settings,
	                                NM_SETTING_CONNECTION_SETTING_NAME,
	                                NM_SETTING_CONNECTION_INTERFACE_NAME);
	if (!props)
		return TRUE;

	/* If one of the interface names is NULL, we accept that connection */
	s_con_orig = nm_connection_get_setting_connection (orig);
	s_con_cand = nm_connection_get_setting_connection (candidate);
	orig_ifname = nm_setting_connection_get_interface_name (s_con_orig);
	cand_ifname = nm_setting_connection_get_interface_name (s_con_cand);

	if (!orig_ifname || !cand_ifname) {
		remove_from_hash (settings, props,
		                  NM_SETTING_CONNECTION_SETTING_NAME,
		                  NM_SETTING_CONNECTION_INTERFACE_NAME);
		return TRUE;
	}
	return FALSE;
}

static gboolean
check_connection_mac_address (NMConnection *orig,
                              NMConnection *candidate,
                              GHashTable *settings)
{
	GHashTable *props;
	const GByteArray *orig_mac = NULL, *cand_mac = NULL;
	NMSettingWired *s_wired_orig, *s_wired_cand;

	props = check_property_in_hash (settings,
	                                NM_SETTING_WIRED_SETTING_NAME,
	                                NM_SETTING_WIRED_MAC_ADDRESS);
	if (!props)
		return TRUE;

	/* If one of the MAC addresses is NULL, we accept that connection */
	s_wired_orig = nm_connection_get_setting_wired (orig);
	if (s_wired_orig)
		orig_mac = nm_setting_wired_get_mac_address (s_wired_orig);

	s_wired_cand = nm_connection_get_setting_wired (candidate);
	if (s_wired_cand)
		cand_mac = nm_setting_wired_get_mac_address (s_wired_cand);

	if (!orig_mac || !cand_mac) {
		remove_from_hash (settings, props,
		                  NM_SETTING_WIRED_SETTING_NAME,
		                  NM_SETTING_WIRED_MAC_ADDRESS);
		return TRUE;
	}
	return FALSE;
}

static NMConnection *
check_possible_match (NMConnection *orig,
                      NMConnection *candidate,
                      GHashTable *settings,
                      gboolean device_has_carrier)
{
	g_return_val_if_fail (settings != NULL, NULL);

	if (!check_ip6_method (orig, candidate, settings))
		return NULL;

	if (!check_ip4_method (orig, candidate, settings, device_has_carrier))
		return NULL;

	if (!check_connection_interface_name (orig, candidate, settings))
		return NULL;

	if (!check_connection_mac_address (orig, candidate, settings))
		return NULL;

	if (g_hash_table_size (settings) == 0)
		return candidate;
	else
		return NULL;
}

/**
 * nm_utils_match_connection:
 * @connections: a (optionally pre-sorted) list of connections from which to
 * find a matching connection to @original based on "inferrable" properties
 * @original: the #NMConnection to find a match for from @connections
 * @device_has_carrier: pass %TRUE if the device that generated @original has
 * a carrier, %FALSE if not
 * @match_filter_func: a function to check whether each connection from @connections
 * should be considered for matching.  This function should return %TRUE if the
 * connection should be considered, %FALSE if the connection should be ignored
 * @match_compat_data: data pointer passed to @match_filter_func
 *
 * Checks each connection from @connections until a matching connection is found
 * considering only setting properties marked with %NM_SETTING_PARAM_INFERRABLE
 * and checking a few other characteristics like IPv6 method.  If the caller
 * desires some priority order of the connections, @connections should be
 * sorted before calling this function.
 *
 * Returns: the best #NMConnection matching @original, or %NULL if no connection
 * matches well enough.
 */
NMConnection *
nm_utils_match_connection (GSList *connections,
                           NMConnection *original,
                           gboolean device_has_carrier,
                           NMUtilsMatchFilterFunc match_filter_func,
                           gpointer match_filter_data)
{
	NMConnection *best_match = NULL;
	GSList *iter;

	for (iter = connections; iter; iter = iter->next) {
		NMConnection *candidate = NM_CONNECTION (iter->data);
		GHashTable *diffs = NULL;

		if (match_filter_func) {
			if (!match_filter_func (candidate, match_filter_data))
				continue;
		}

		if (!nm_connection_diff (original, candidate, NM_SETTING_COMPARE_FLAG_INFERRABLE, &diffs)) {
			if (!best_match)
				best_match = check_possible_match (original, candidate, diffs, device_has_carrier);

			if (!best_match && nm_logging_enabled (LOGL_DEBUG, LOGD_CORE)) {
				GString *diff_string;
				GHashTableIter s_iter, p_iter;
				gpointer setting_name, setting;
				gpointer property_name, value;

				diff_string = g_string_new (NULL);
				g_hash_table_iter_init (&s_iter, diffs);
				while (g_hash_table_iter_next (&s_iter, &setting_name, &setting)) {
					g_hash_table_iter_init (&p_iter, setting);
					while (g_hash_table_iter_next (&p_iter, &property_name, &value)) {
						if (diff_string->len)
							g_string_append (diff_string, ", ");
						g_string_append_printf (diff_string, "%s.%s",
						                        (char *) setting_name,
						                        (char *) property_name);
					}
				}

				nm_log_dbg (LOGD_CORE, "Connection '%s' differs from candidate '%s' in %s",
				            nm_connection_get_id (original),
				            nm_connection_get_id (candidate),
				            diff_string->str);
				g_string_free (diff_string, TRUE);
			}

			g_hash_table_unref (diffs);
			continue;
		}

		/* Exact match */
		return candidate;
	}

	/* Best match (if any) */
	return best_match;
}

/* nm_utils_ascii_str_to_int64:
 *
 * A wrapper for g_ascii_strtoll, that checks whether the whole string
 * can be successfully converted to a number and is within a given
 * range. On any error, @fallback will be returned and %errno will be set
 * to a non-zero value. On success, %errno will be set to zero, check %errno
 * for errors. Any trailing or leading (ascii) white space is ignored and the
 * functions is locale independent.
 *
 * The function is guaranteed to return a value between @min and @max
 * (inclusive) or @fallback. Also, the parsing is rather strict, it does
 * not allow for any unrecognized characters, except leading and trailing
 * white space.
 **/
gint64
nm_utils_ascii_str_to_int64 (const char *str, guint base, gint64 min, gint64 max, gint64 fallback)
{
	gint64 v;
	size_t len;
	char buf[64], *s, *str_free = NULL;

	if (str) {
		while (g_ascii_isspace (str[0]))
			str++;
	}
	if (!str || !str[0]) {
		errno = EINVAL;
		return fallback;
	}

	len = strlen (str);
	if (g_ascii_isspace (str[--len])) {
		/* backward search the first non-ws character.
		 * We already know that str[0] is non-ws. */
		while (g_ascii_isspace (str[--len]))
			;

		/* str[len] is now the last non-ws character... */
		len++;

		if (len >= sizeof (buf))
			s = str_free = g_malloc (len + 1);
		else
			s = buf;

		memcpy (s, str, len);
		s[len] = 0;

		/*
		g_assert (len > 0 && len < strlen (str) && len == strlen (s));
		g_assert (!g_ascii_isspace (str[len-1]) && g_ascii_isspace (str[len]));
		g_assert (strncmp (str, s, len) == 0);
		*/

		str = s;
	}

	errno = 0;
	v = g_ascii_strtoll (str, &s, base);

	if (errno != 0)
		v = fallback;
	else if (s[0] != 0) {
		errno = EINVAL;
		v = fallback;
	} else if (v > max || v < min) {
		errno = ERANGE;
		v = fallback;
	}

	if (G_UNLIKELY (str_free))
		g_free (str_free);
	return v;
}


static gint64 monotonic_timestamp_offset_sec;

static void
monotonic_timestamp_get (struct timespec *tp)
{
	static gboolean initialized = FALSE;
	int err;

	err = clock_gettime (CLOCK_BOOTTIME, tp);

	g_assert (err == 0); (void)err;
	g_assert (tp->tv_nsec >= 0 && tp->tv_nsec < NM_UTILS_NS_PER_SECOND);

	if (G_LIKELY (initialized))
		return;

	/* Calculate an offset for the time stamp.
	 *
	 * We always want positive values, because then we can initialize
	 * a timestamp with 0 and be sure, that it will be less then any
	 * value nm_utils_get_monotonic_timestamp_*() might return.
	 * For this to be true also for nm_utils_get_monotonic_timestamp_s() at
	 * early boot, we have to shift the timestamp to start counting at
	 * least from 1 second onward.
	 *
	 * Another advantage of shifting is, that this way we make use of the whole 31 bit
	 * range of signed int, before the time stamp for nm_utils_get_monotonic_timestamp_s()
	 * wraps (~68 years).
	 **/
	monotonic_timestamp_offset_sec = (- ((gint64) tp->tv_sec)) + 1;
	initialized = TRUE;

	if (nm_logging_enabled (LOGL_DEBUG, LOGD_CORE)) {
		time_t now = time (NULL);
		struct tm tm;
		char s[255];

		strftime (s, sizeof (s), "%Y-%m-%d %H:%M:%S", localtime_r (&now, &tm));
		nm_log_dbg (LOGD_CORE, "monotonic timestamp started counting 1.%09ld seconds ago with "
		                       "an offset of %lld.0 seconds to CLOCK_BOOTTIME (local time is %s)",
		                       tp->tv_nsec, (long long) -monotonic_timestamp_offset_sec, s);
	}
}

/**
 * nm_utils_get_monotonic_timestamp_ns:
 *
 * Returns: a monotonically increasing time stamp in nanoseconds,
 * starting at an unspecified offset. See clock_gettime(), %CLOCK_BOOTTIME.
 *
 * The returned value will start counting at an undefined point
 * in the past and will always be positive.
 *
 * All the nm_utils_get_monotonic_timestamp_*s functions return the same
 * timestamp but in different scales (nsec, usec, msec, sec).
 **/
gint64
nm_utils_get_monotonic_timestamp_ns (void)
{
	struct timespec tp;

	monotonic_timestamp_get (&tp);

	/* Although the result will always be positive, we return a signed
	 * integer, which makes it easier to calculate time differences (when
	 * you want to subtract signed values).
	 **/
	return (((gint64) tp.tv_sec) + monotonic_timestamp_offset_sec) * NM_UTILS_NS_PER_SECOND +
	       tp.tv_nsec;
}

/**
 * nm_utils_get_monotonic_timestamp_us:
 *
 * Returns: a monotonically increasing time stamp in microseconds,
 * starting at an unspecified offset. See clock_gettime(), %CLOCK_BOOTTIME.
 *
 * The returned value will start counting at an undefined point
 * in the past and will always be positive.
 *
 * All the nm_utils_get_monotonic_timestamp_*s functions return the same
 * timestamp but in different scales (nsec, usec, msec, sec).
 **/
gint64
nm_utils_get_monotonic_timestamp_us (void)
{
	struct timespec tp;

	monotonic_timestamp_get (&tp);

	/* Although the result will always be positive, we return a signed
	 * integer, which makes it easier to calculate time differences (when
	 * you want to subtract signed values).
	 **/
	return (((gint64) tp.tv_sec) + monotonic_timestamp_offset_sec) * ((gint64) G_USEC_PER_SEC) +
	       (tp.tv_nsec / (NM_UTILS_NS_PER_SECOND/G_USEC_PER_SEC));
}

/**
 * nm_utils_get_monotonic_timestamp_ms:
 *
 * Returns: a monotonically increasing time stamp in milliseconds,
 * starting at an unspecified offset. See clock_gettime(), %CLOCK_BOOTTIME.
 *
 * The returned value will start counting at an undefined point
 * in the past and will always be positive.
 *
 * All the nm_utils_get_monotonic_timestamp_*s functions return the same
 * timestamp but in different scales (nsec, usec, msec, sec).
 **/
gint64
nm_utils_get_monotonic_timestamp_ms (void)
{
	struct timespec tp;

	monotonic_timestamp_get (&tp);

	/* Although the result will always be positive, we return a signed
	 * integer, which makes it easier to calculate time differences (when
	 * you want to subtract signed values).
	 **/
	return (((gint64) tp.tv_sec) + monotonic_timestamp_offset_sec) * ((gint64) 1000) +
	       (tp.tv_nsec / (NM_UTILS_NS_PER_SECOND/1000));
}

/**
 * nm_utils_get_monotonic_timestamp_s:
 *
 * Returns: nm_utils_get_monotonic_timestamp_ms() in seconds (throwing
 * away sub second parts). The returned value will always be positive.
 *
 * This value wraps after roughly 68 years which should be fine for any
 * practical purpose.
 *
 * All the nm_utils_get_monotonic_timestamp_*s functions return the same
 * timestamp but in different scales (nsec, usec, msec, sec).
 **/
gint32
nm_utils_get_monotonic_timestamp_s (void)
{
	struct timespec tp;

	monotonic_timestamp_get (&tp);
	return (((gint64) tp.tv_sec) + monotonic_timestamp_offset_sec);
}


/**
 * nm_utils_ip6_property_path:
 * @ifname: an interface name
 * @property: a property name
 *
 * Returns the path to IPv6 property @property on @ifname. Note that
 * this uses a static buffer.
 */
const char *
nm_utils_ip6_property_path (const char *ifname, const char *property)
{
#define IPV6_PROPERTY_DIR "/proc/sys/net/ipv6/conf/"
	static char path[sizeof (IPV6_PROPERTY_DIR) + IFNAMSIZ + 32];
	int len;

	ifname = ASSERT_VALID_PATH_COMPONENT (ifname);
	property = ASSERT_VALID_PATH_COMPONENT (property);

	len = g_snprintf (path, sizeof (path), IPV6_PROPERTY_DIR "%s/%s",
	                  ifname, property);
	g_assert (len < sizeof (path) - 1);

	return path;
}

const char *
ASSERT_VALID_PATH_COMPONENT (const char *name)
{
	const char *n;

	if (name == NULL || name[0] == '\0')
		goto fail;

	if (name[0] == '.') {
		if (name[1] == '\0')
			goto fail;
		if (name[1] == '.' && name[2] == '\0')
			goto fail;
	}
	n = name;
	do {
		if (*n == '/')
			goto fail;
	} while (*(++n) != '\0');

	return name;
fail:
	if (name)
		nm_log_err (LOGD_CORE, "Failed asserting path component: NULL");
	else
		nm_log_err (LOGD_CORE, "Failed asserting path component: \"%s\"", name);
	g_error ("FATAL: Failed asserting path component: %s", name ? name : "(null)");
}

