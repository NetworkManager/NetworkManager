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

/*
 * nm_utils_ip4_netmask_to_prefix
 *
 * Figure out the network prefix from a netmask.  Netmask
 * MUST be in network byte order.
 *
 */
guint32
nm_utils_ip4_netmask_to_prefix (guint32 netmask)
{
	guchar *p, *end;
	guint32 prefix = 0;

	p = (guchar *) &netmask;
	end = p + sizeof (guint32);

	while ((*p == 0xFF) && p < end) {
		prefix += 8;
		p++;
	}

	if (p < end) {
		guchar v = *p;

		while (v) {
			prefix++;
			v <<= 1;
		}
	}

	return prefix;
}

/*
 * nm_utils_ip4_prefix_to_netmask
 *
 * Figure out the netmask from a prefix.
 *
 */
guint32
nm_utils_ip4_prefix_to_netmask (guint32 prefix)
{
	guint32 msk = 0x80000000;
	guint32 netmask = 0;

	while (prefix > 0) {
		netmask |= msk;
		msk >>= 1;
		prefix--;
	}

	return (guint32) htonl (netmask);
}

void
nm_utils_merge_ip4_config (NMIP4Config *ip4_config, NMSettingIP4Config *setting)
{
	int i, j;
	gboolean setting_never_default;

	if (!setting)
		return; /* Defaults are just fine */

	if (nm_setting_ip4_config_get_ignore_auto_dns (setting)) {
		nm_ip4_config_reset_nameservers (ip4_config);
		nm_ip4_config_reset_domains (ip4_config);
		nm_ip4_config_reset_searches (ip4_config);
	}

	if (nm_setting_ip4_config_get_ignore_auto_routes (setting))
		nm_ip4_config_reset_routes (ip4_config);

	for (i = 0; i < nm_setting_ip4_config_get_num_dns (setting); i++) {
		guint32 ns;
		gboolean found = FALSE;

		/* Avoid dupes */
		ns = nm_setting_ip4_config_get_dns (setting, i);
		for (j = 0; j < nm_ip4_config_get_num_nameservers (ip4_config); j++) {
			if (nm_ip4_config_get_nameserver (ip4_config, j) == ns) {
				found = TRUE;
				break;
			}
		}

		if (!found)
			nm_ip4_config_add_nameserver (ip4_config, ns);
	}

	/* DNS search domains */
	for (i = 0; i < nm_setting_ip4_config_get_num_dns_searches (setting); i++) {
		const char *search = nm_setting_ip4_config_get_dns_search (setting, i);
		gboolean found = FALSE;

		/* Avoid dupes */
		for (j = 0; j < nm_ip4_config_get_num_searches (ip4_config); j++) {
			if (!strcmp (search, nm_ip4_config_get_search (ip4_config, j))) {
				found = TRUE;
				break;
			}
		}

		if (!found)
			nm_ip4_config_add_search (ip4_config, search);
	}

	/* IPv4 addresses */
	for (i = 0; i < nm_setting_ip4_config_get_num_addresses (setting); i++) {
		NMIP4Address *setting_addr = nm_setting_ip4_config_get_address (setting, i);
		guint32 num;

		num = nm_ip4_config_get_num_addresses (ip4_config);
		for (j = 0; j < num; j++) {
			NMIP4Address *cfg_addr = nm_ip4_config_get_address (ip4_config, j);

			/* Dupe, override with user-specified address */
			if (nm_ip4_address_get_address (cfg_addr) == nm_ip4_address_get_address (setting_addr)) {
				nm_ip4_config_replace_address (ip4_config, j, setting_addr);
				break;
			}
		}

		if (j == num)
			nm_ip4_config_add_address (ip4_config, setting_addr);
	}

	/* IPv4 routes */
	for (i = 0; i < nm_setting_ip4_config_get_num_routes (setting); i++) {
		NMIP4Route *setting_route = nm_setting_ip4_config_get_route (setting, i);
		guint32 num;

		num = nm_ip4_config_get_num_routes (ip4_config);
		for (j = 0; j < num; j++) {
			NMIP4Route *cfg_route = nm_ip4_config_get_route (ip4_config, j);

			/* Dupe, override with user-specified route */
			if (   (nm_ip4_route_get_dest (cfg_route) == nm_ip4_route_get_dest (setting_route))
			    && (nm_ip4_route_get_prefix (cfg_route) == nm_ip4_route_get_prefix (setting_route))
			    && (nm_ip4_route_get_next_hop (cfg_route) == nm_ip4_route_get_next_hop (setting_route))) {
				nm_ip4_config_replace_route (ip4_config, j, setting_route);
				break;
			}
		}

		if (j == num)
			nm_ip4_config_add_route (ip4_config, setting_route);
	}

	setting_never_default = nm_setting_ip4_config_get_never_default (setting);

	if (nm_setting_ip4_config_get_ignore_auto_routes (setting))
		nm_ip4_config_set_never_default (ip4_config, setting_never_default);
	else {
		if (setting_never_default)
			nm_ip4_config_set_never_default (ip4_config, TRUE);
	}
}

static inline gboolean
ip6_addresses_equal (const struct in6_addr *a, const struct in6_addr *b)
{
	return memcmp (a, b, sizeof (struct in6_addr)) == 0;
}

/* This is exactly identical to nm_utils_merge_ip4_config, with s/4/6/,
 * except that we can't compare addresses with ==.
 */
void
nm_utils_merge_ip6_config (NMIP6Config *ip6_config, NMSettingIP6Config *setting)
{
	int i, j;

	if (!setting)
		return; /* Defaults are just fine */

	if (nm_setting_ip6_config_get_ignore_auto_dns (setting)) {
		nm_ip6_config_reset_nameservers (ip6_config);
		nm_ip6_config_reset_domains (ip6_config);
		nm_ip6_config_reset_searches (ip6_config);
	}

	if (nm_setting_ip6_config_get_ignore_auto_routes (setting))
		nm_ip6_config_reset_routes (ip6_config);

	for (i = 0; i < nm_setting_ip6_config_get_num_dns (setting); i++) {
		const struct in6_addr *ns;
		gboolean found = FALSE;

		/* Avoid dupes */
		ns = nm_setting_ip6_config_get_dns (setting, i);
		for (j = 0; j < nm_ip6_config_get_num_nameservers (ip6_config); j++) {
			if (ip6_addresses_equal (nm_ip6_config_get_nameserver (ip6_config, j), ns)) {
				found = TRUE;
				break;
			}
		}

		if (!found)
			nm_ip6_config_add_nameserver (ip6_config, ns);
	}

	/* DNS search domains */
	for (i = 0; i < nm_setting_ip6_config_get_num_dns_searches (setting); i++) {
		const char *search = nm_setting_ip6_config_get_dns_search (setting, i);
		gboolean found = FALSE;

		/* Avoid dupes */
		for (j = 0; j < nm_ip6_config_get_num_searches (ip6_config); j++) {
			if (!strcmp (search, nm_ip6_config_get_search (ip6_config, j))) {
				found = TRUE;
				break;
			}
		}

		if (!found)
			nm_ip6_config_add_search (ip6_config, search);
	}

	/* IPv6 addresses */
	for (i = 0; i < nm_setting_ip6_config_get_num_addresses (setting); i++) {
		NMIP6Address *setting_addr = nm_setting_ip6_config_get_address (setting, i);
		guint32 num;

		num = nm_ip6_config_get_num_addresses (ip6_config);
		for (j = 0; j < num; j++) {
			NMIP6Address *cfg_addr = nm_ip6_config_get_address (ip6_config, j);

			/* Dupe, override with user-specified address */
			if (ip6_addresses_equal (nm_ip6_address_get_address (cfg_addr), nm_ip6_address_get_address (setting_addr))) {
				nm_ip6_config_replace_address (ip6_config, j, setting_addr);
				break;
			}
		}

		if (j == num)
			nm_ip6_config_add_address (ip6_config, setting_addr);
	}

	/* IPv6 routes */
	for (i = 0; i < nm_setting_ip6_config_get_num_routes (setting); i++) {
		NMIP6Route *setting_route = nm_setting_ip6_config_get_route (setting, i);
		guint32 num;

		num = nm_ip6_config_get_num_routes (ip6_config);
		for (j = 0; j < num; j++) {
			NMIP6Route *cfg_route = nm_ip6_config_get_route (ip6_config, j);

			/* Dupe, override with user-specified route */
			if (   ip6_addresses_equal (nm_ip6_route_get_dest (cfg_route), nm_ip6_route_get_dest (setting_route))
			    && (nm_ip6_route_get_prefix (cfg_route) == nm_ip6_route_get_prefix (setting_route))
				&& ip6_addresses_equal (nm_ip6_route_get_next_hop (cfg_route), nm_ip6_route_get_next_hop (setting_route))) {
				nm_ip6_config_replace_route (ip6_config, j, setting_route);
				break;
			}
		}

		if (j == num)
			nm_ip6_config_add_route (ip6_config, setting_route);
	}

	if (nm_setting_ip6_config_get_never_default (setting))
		nm_ip6_config_set_never_default (ip6_config, TRUE);
}

gboolean
nm_match_spec_hwaddr (const GSList *specs, const char *hwaddr)
{
	const GSList *iter;
	char *hwaddr_match, *p;

	g_return_val_if_fail (hwaddr != NULL, FALSE);

	p = hwaddr_match = g_strdup_printf ("mac:%s", hwaddr);

	while (*p) {
		*p = g_ascii_tolower (*p);
		p++;
	}

	for (iter = specs; iter; iter = g_slist_next (iter)) {
		if (!strcmp ((const char *) iter->data, hwaddr_match)) {
			g_free (hwaddr_match);
			return TRUE;
		}
	}

	g_free (hwaddr_match);
	return FALSE;
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
	NMSettingIP4Config *s_ip4;
	const char *method = NULL;

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	if (s_ip4)
		method = nm_setting_ip4_config_get_method (s_ip4);

	if (g_strcmp0 (method, NM_SETTING_IP4_CONFIG_METHOD_SHARED) != 0)
		return NULL;  /* Not shared */

	s_wifi = nm_connection_get_setting_wireless (connection);
	if (s_wifi) {
		s_wsec = nm_connection_get_setting_wireless_security (connection);
		if (nm_setting_wireless_get_security (s_wifi) || s_wsec)
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

/**
 * nm_utils_do_sysctl:
 * @path: path to write @value to
 * @value: value to write to @path
 *
 * Writes @value to the file at @path, trying 3 times on failure.
 *
 * Returns: %TRUE on success.  On failure, returns %FALSE and sets errno.
 */
gboolean
nm_utils_do_sysctl (const char *path, const char *value)
{
	int fd, len, nwrote, tries, saved_errno = 0;
	char *actual;

	g_return_val_if_fail (path != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);

	fd = open (path, O_WRONLY | O_TRUNC);
	if (fd == -1) {
		saved_errno = errno;
		nm_log_warn (LOGD_CORE, "sysctl: failed to open '%s': (%d) %s",
		             path, saved_errno, strerror (saved_errno));
		errno = saved_errno;
		return FALSE;
	}

	nm_log_dbg (LOGD_CORE, "sysctl: setting '%s' to '%s'", path, value);

	/* Most sysfs and sysctl options don't care about a trailing CR, while some
	 * (like infiniband) do.  So always add the CR.  Also, neither sysfs nor
	 * sysctl support partial writes so the CR must be added to the string we're
	 * about to write.
	 */
	actual = g_strdup_printf ("%s\n", value);

	/* Try to write the entire value three times if a partial write occurs */
	len = strlen (actual);
	for (tries = 0, nwrote = 0; tries < 3 && nwrote != len; tries++) {
		errno = 0;
		nwrote = write (fd, actual, len);
		if (nwrote == -1) {
			if (errno == EINTR)
				continue;
			saved_errno = errno;
			break;
		}
	}
	g_free (actual);
	close (fd);

	if (nwrote != len && saved_errno != EEXIST) {
		nm_log_warn (LOGD_CORE, "sysctl: failed to set '%s' to '%s': (%d) %s",
		             path, value, saved_errno, strerror (saved_errno));
	}

	errno = saved_errno;
	return (nwrote == len);
}

gboolean
nm_utils_get_proc_sys_net_value (const char *path,
                                 const char *iface,
                                 gint32 *out_value)
{
	GError *error = NULL;
	char *contents = NULL;
	gboolean success = FALSE;
	long int tmp;

	if (!g_file_get_contents (path, &contents, NULL, &error)) {
		nm_log_dbg (LOGD_DEVICE, "(%s): error reading %s: (%d) %s",
		            iface, path,
		            error ? error->code : -1,
		            error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
	} else {
		errno = 0;
		tmp = strtol (contents, NULL, 10);
		if (errno == 0) {
			*out_value = (gint32) tmp;
			success = TRUE;
		}
		g_free (contents);
	}

	return success;
}

gboolean
nm_utils_get_proc_sys_net_value_with_bounds (const char *path,
                                             const char *iface,
                                             gint32 *out_value,
                                             gint32 valid_min,
                                             gint32 valid_max)
{
	gboolean result;
	gint32 val;

	result = nm_utils_get_proc_sys_net_value (path, iface, &val);

	if (result) {
		if (val >= valid_min && val <= valid_max)
			*out_value = val;
		else
			result = FALSE;
	}

	return result;
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
nm_utils_complete_generic (NMConnection *connection,
                           const char *ctype,
                           const GSList *existing,
                           const char *format,
                           const char *preferred,
                           gboolean default_enable_ipv6)
{
	NMSettingConnection *s_con;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	const char *method;
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

	/* Add an 'auto' IPv4 connection if present */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	if (!s_ip4) {
		s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_ip4));
	}
	method = nm_setting_ip4_config_get_method (s_ip4);
	if (!method) {
		g_object_set (G_OBJECT (s_ip4),
		              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
		              NULL);
	}

	/* Add an 'auto' IPv6 setting if allowed and not preset */
	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	if (!s_ip6 && default_enable_ipv6) {
		s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_ip6));
	}
	if (s_ip6 && !nm_setting_ip6_config_get_method (s_ip6)) {
		g_object_set (G_OBJECT (s_ip6),
		              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO,
		              NM_SETTING_IP6_CONFIG_MAY_FAIL, TRUE,
		              NULL);
	}
}

char *
nm_utils_new_vlan_name (const char *parent_iface, guint32 vlan_id)
{
	/* Basically VLAN_NAME_TYPE_RAW_PLUS_VID_NO_PAD */
	return g_strdup_printf ("%s.%d", parent_iface, vlan_id);
}

