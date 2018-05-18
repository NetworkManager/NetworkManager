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
 * Copyright 2004 - 2016 Red Hat, Inc.
 * Copyright 2005 - 2008 Novell, Inc.
 */

#include "nm-default.h"

#include "NetworkManagerUtils.h"

#include "nm-utils/nm-c-list.h"

#include "nm-common-macros.h"
#include "nm-utils.h"
#include "nm-setting-connection.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-ip6-config.h"
#include "nm-core-internal.h"

#include "platform/nm-platform.h"
#include "nm-auth-utils.h"

/*****************************************************************************/

/**
 * nm_utils_get_shared_wifi_permission:
 * @connection: the NMConnection to lookup the permission.
 *
 * Returns: a static string of the wifi-permission (if any) or %NULL.
 */
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

/*****************************************************************************/

static char *
get_new_connection_name (NMConnection *const*existing_connections,
                         const char *preferred,
                         const char *fallback_prefix)
{
	gs_free const char **existing_names = NULL;
	guint i, existing_len = 0;

	g_assert (fallback_prefix);

	if (existing_connections) {
		existing_len = NM_PTRARRAY_LEN (existing_connections);
		existing_names = g_new (const char *, existing_len);
		for (i = 0; i < existing_len; i++) {
			NMConnection *candidate;
			const char *id;

			candidate = existing_connections[i];
			nm_assert (NM_IS_CONNECTION (candidate));

			id = nm_connection_get_id (candidate);
			nm_assert (id);

			existing_names[i] = id;

			if (   preferred
				&& nm_streq (preferred, id)) {
				/* the preferred name is already taken. Forget about it. */
				preferred = NULL;
			}
		}
		nm_assert (!existing_connections[i]);
	}

	/* Return the preferred name if it was unique */
	if (preferred)
		return g_strdup (preferred);

	/* Otherwise find the next available unique connection name using the given
	 * connection name template.
	 */
	for (i = 1; TRUE; i++) {
		char *temp;

		/* TRANSLATORS: the first %s is a prefix for the connection id, such
		 * as "Wired Connection" or "VPN Connection". The %d is a number
		 * that is combined with the first argument to create a unique
		 * connection id. */
		temp = g_strdup_printf (C_("connection id fallback", "%s %u"),
		                        fallback_prefix, i);

		if (nm_utils_strv_find_first ((char **) existing_names,
		                              existing_len,
		                              temp) < 0)
			return temp;

		g_free (temp);
	}
}

static char *
get_new_connection_ifname (NMPlatform *platform,
                           NMConnection *const*existing_connections,
                           const char *prefix)
{
	guint i, j;

	for (i = 0; TRUE; i++) {
		char *name;

		name = g_strdup_printf ("%s%d", prefix, i);

		if (nm_platform_link_get_by_ifname (platform, name))
			goto next;

		if (existing_connections) {
			for (j = 0; existing_connections[j]; j++) {
				if (nm_streq0 (nm_connection_get_interface_name (existing_connections[j]),
				               name))
					goto next;
			}
		}

		return name;

next:
		g_free (name);
	}
}

const char *
nm_utils_get_ip_config_method (NMConnection *connection,
                               GType         ip_setting_type)
{
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip4, *s_ip6;
	const char *method;

	s_con = nm_connection_get_setting_connection (connection);

	if (ip_setting_type == NM_TYPE_SETTING_IP4_CONFIG) {
		g_return_val_if_fail (s_con != NULL, NM_SETTING_IP4_CONFIG_METHOD_AUTO);

		s_ip4 = nm_connection_get_setting_ip4_config (connection);
		if (!s_ip4)
			return NM_SETTING_IP4_CONFIG_METHOD_DISABLED;
		method = nm_setting_ip_config_get_method (s_ip4);
		g_return_val_if_fail (method != NULL, NM_SETTING_IP4_CONFIG_METHOD_AUTO);

		return method;

	} else if (ip_setting_type == NM_TYPE_SETTING_IP6_CONFIG) {
		g_return_val_if_fail (s_con != NULL, NM_SETTING_IP6_CONFIG_METHOD_AUTO);

		s_ip6 = nm_connection_get_setting_ip6_config (connection);
		if (!s_ip6)
			return NM_SETTING_IP6_CONFIG_METHOD_IGNORE;
		method = nm_setting_ip_config_get_method (s_ip6);
		g_return_val_if_fail (method != NULL, NM_SETTING_IP6_CONFIG_METHOD_AUTO);

		return method;

	} else
		g_assert_not_reached ();
}

gboolean
nm_utils_connection_has_default_route (NMConnection *connection,
                                       int addr_family,
                                       gboolean *out_is_never_default)
{
	const char *method;
	NMSettingIPConfig *s_ip;
	gboolean is_never_default = FALSE;
	gboolean has_default_route = FALSE;

	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);
	g_return_val_if_fail (NM_IN_SET (addr_family, AF_INET, AF_INET6), FALSE);

	if (!connection)
		goto out;

	if (addr_family == AF_INET)
		s_ip = nm_connection_get_setting_ip4_config (connection);
	else
		s_ip = nm_connection_get_setting_ip6_config (connection);
	if (!s_ip)
		goto out;
	if (nm_setting_ip_config_get_never_default (s_ip)) {
		is_never_default = TRUE;
		goto out;
	}

	if (addr_family == AF_INET) {
		method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP4_CONFIG);
		if (NM_IN_STRSET (method, NULL,
		                          NM_SETTING_IP4_CONFIG_METHOD_DISABLED,
		                          NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL))
			goto out;
	} else {
		method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP6_CONFIG);
		if (NM_IN_STRSET (method, NULL,
		                          NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
		                          NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL))
			goto out;
	}

	has_default_route = TRUE;
out:
	NM_SET_OUT (out_is_never_default, is_never_default);
	return has_default_route;
}

/*****************************************************************************/

void
nm_utils_complete_generic (NMPlatform *platform,
                           NMConnection *connection,
                           const char *ctype,
                           NMConnection *const*existing_connections,
                           const char *preferred_id,
                           const char *fallback_id_prefix,
                           const char *ifname_prefix,
                           gboolean default_enable_ipv6)
{
	NMSettingConnection *s_con;
	char *id, *ifname;
	GHashTable *parameters;

	g_assert (fallback_id_prefix);

	s_con = nm_connection_get_setting_connection (connection);
	if (!s_con) {
		s_con = (NMSettingConnection *) nm_setting_connection_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_con));
	}
	g_object_set (G_OBJECT (s_con), NM_SETTING_CONNECTION_TYPE, ctype, NULL);

	if (!nm_setting_connection_get_uuid (s_con)) {
		char uuid[37];

		g_object_set (G_OBJECT (s_con), NM_SETTING_CONNECTION_UUID, nm_utils_uuid_generate_buf (uuid), NULL);
	}

	/* Add a connection ID if absent */
	if (!nm_setting_connection_get_id (s_con)) {
		id = get_new_connection_name (existing_connections, preferred_id, fallback_id_prefix);
		g_object_set (G_OBJECT (s_con), NM_SETTING_CONNECTION_ID, id, NULL);
		g_free (id);
	}

	/* Add an interface name, if requested */
	if (ifname_prefix && !nm_setting_connection_get_interface_name (s_con)) {
		ifname = get_new_connection_ifname (platform, existing_connections, ifname_prefix);
		g_object_set (G_OBJECT (s_con), NM_SETTING_CONNECTION_INTERFACE_NAME, ifname, NULL);
		g_free (ifname);
	}

	/* Normalize */
	parameters = g_hash_table_new (nm_str_hash, g_str_equal);
	g_hash_table_insert (parameters, NM_CONNECTION_NORMALIZE_PARAM_IP6_CONFIG_METHOD,
	                     default_enable_ipv6 ? NM_SETTING_IP6_CONFIG_METHOD_AUTO : NM_SETTING_IP6_CONFIG_METHOD_IGNORE);
	nm_connection_normalize (connection, parameters, NULL, NULL);
	g_hash_table_destroy (parameters);
}

/*****************************************************************************/

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
	if (!p_hash)
		return;

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
	NMSettingIPConfig *candidate_ip6;
	gboolean allow = FALSE;

	props = check_property_in_hash (settings,
	                                NM_SETTING_IP6_CONFIG_SETTING_NAME,
	                                NM_SETTING_IP_CONFIG_METHOD);
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
	    && (!candidate_ip6 || nm_setting_ip_config_get_may_fail (candidate_ip6))) {
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
		                  NM_SETTING_IP_CONFIG_METHOD);
	}
	return allow;
}

static int
route_compare (NMIPRoute *route1, NMIPRoute *route2, gint64 default_metric)
{
	gint64 r, metric1, metric2;
	int family;
	guint plen;
	NMIPAddr a1 = { 0 }, a2 = { 0 };

	family = nm_ip_route_get_family (route1);
	r = family - nm_ip_route_get_family (route2);
	if (r)
		return r > 0 ? 1 : -1;

	plen = nm_ip_route_get_prefix (route1);
	r = plen - nm_ip_route_get_prefix (route2);
	if (r)
		return r > 0 ? 1 : -1;

	metric1 = nm_ip_route_get_metric (route1) == -1 ? default_metric : nm_ip_route_get_metric (route1);
	metric2 = nm_ip_route_get_metric (route2) == -1 ? default_metric : nm_ip_route_get_metric (route2);

	r = metric1 - metric2;
	if (r)
		return r > 0 ? 1 : -1;

	r = g_strcmp0 (nm_ip_route_get_next_hop (route1), nm_ip_route_get_next_hop (route2));
	if (r)
		return r;

	/* NMIPRoute validates family and dest. inet_pton() is not expected to fail. */
	inet_pton (family, nm_ip_route_get_dest (route1), &a1);
	inet_pton (family, nm_ip_route_get_dest (route2), &a2);
	nm_utils_ipx_address_clear_host_address (family, &a1, &a1, plen);
	nm_utils_ipx_address_clear_host_address (family, &a2, &a2, plen);
	r = memcmp (&a1, &a2, sizeof (a1));
	if (r)
		return r;

	return 0;
}

static int
route_ptr_compare (const void *a, const void *b, gpointer metric)
{
	return route_compare (*(NMIPRoute **) a, *(NMIPRoute **) b, *((gint64 *) metric));
}

static gboolean
check_ip_routes (NMConnection *orig,
                 NMConnection *candidate,
                 GHashTable *settings,
                 gint64 default_metric,
                 gboolean v4)
{
	gs_free NMIPRoute **routes1 = NULL;
	NMIPRoute **routes2;
	NMSettingIPConfig *s_ip1, *s_ip2;
	gint64 m;
	const char *s_name;
	GHashTable *props;
	guint i, i1, i2, num1, num2;
	const guint8 PLEN = v4 ? 32 : 128;

	s_name = v4 ? NM_SETTING_IP4_CONFIG_SETTING_NAME :
	              NM_SETTING_IP6_CONFIG_SETTING_NAME;

	props = check_property_in_hash (settings,
	                                s_name,
	                                NM_SETTING_IP_CONFIG_ROUTES);
	if (!props)
		return TRUE;

	s_ip1 = (NMSettingIPConfig *) nm_connection_get_setting_by_name (orig, s_name);
	s_ip2 = (NMSettingIPConfig *) nm_connection_get_setting_by_name (candidate, s_name);

	if (!s_ip1 || !s_ip2)
		return FALSE;

	num1 = nm_setting_ip_config_get_num_routes (s_ip1);
	num2 = nm_setting_ip_config_get_num_routes (s_ip2);

	routes1 = g_new (NMIPRoute *, (gsize) num1 + num2);
	routes2 = &routes1[num1];

	for (i = 0; i < num1; i++)
		routes1[i] = nm_setting_ip_config_get_route (s_ip1, i);
	for (i = 0; i < num2; i++)
		routes2[i] = nm_setting_ip_config_get_route (s_ip2, i);

	m = nm_setting_ip_config_get_route_metric (s_ip2);
	if (m != -1)
		default_metric = m;

	g_qsort_with_data (routes1, num1, sizeof (NMIPRoute *), route_ptr_compare, &default_metric);
	g_qsort_with_data (routes2, num2, sizeof (NMIPRoute *), route_ptr_compare, &default_metric);

	for (i1 = 0, i2 = 0; i2 < num2; i1++) {
		if (i1 >= num1)
			return FALSE;
		if (route_compare (routes1[i1], routes2[i2], default_metric) == 0) {
			i2++;
			continue;
		}

		/* if @orig (@routes1) contains /32 routes that are missing in @candidate,
		 * we accept that.
		 *
		 * A /32 may have been added automatically, as a direct-route to the gateway.
		 * The generated connection (@orig) would contain that route, so we shall ignore
		 * it.
		 *
		 * Likeweise for /128 for IPv6. */
		if (nm_ip_route_get_prefix (routes1[i1]) == PLEN)
			continue;

		return FALSE;
	}

	/* check that @orig has no left-over (except host routes that we ignore). */
	for (; i1 < num1; i1++) {
		if (nm_ip_route_get_prefix (routes1[i1]) != PLEN)
			return FALSE;
	}

	remove_from_hash (settings, props, s_name, NM_SETTING_IP_CONFIG_ROUTES);
	return TRUE;
}

static gboolean
check_ip4_method (NMConnection *orig,
                  NMConnection *candidate,
                  GHashTable *settings,
                  gboolean device_has_carrier)
{
	GHashTable *props;
	const char *orig_ip4_method, *candidate_ip4_method;
	NMSettingIPConfig *candidate_ip4;

	props = check_property_in_hash (settings,
	                                NM_SETTING_IP4_CONFIG_SETTING_NAME,
	                                NM_SETTING_IP_CONFIG_METHOD);
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
	    && (!candidate_ip4 || nm_setting_ip_config_get_may_fail (candidate_ip4))
	    && (device_has_carrier == FALSE)) {
		remove_from_hash (settings, props,
		                  NM_SETTING_IP4_CONFIG_SETTING_NAME,
		                  NM_SETTING_IP_CONFIG_METHOD);
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
	const char *orig_mac = NULL, *cand_mac = NULL;
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

static gboolean
check_connection_infiniband_mac_address (NMConnection *orig,
                                         NMConnection *candidate,
                                         GHashTable *settings)
{
	GHashTable *props;
	const char *orig_mac = NULL, *cand_mac = NULL;
	NMSettingInfiniband *s_infiniband_orig, *s_infiniband_cand;

	props = check_property_in_hash (settings,
	                                NM_SETTING_INFINIBAND_SETTING_NAME,
	                                NM_SETTING_INFINIBAND_MAC_ADDRESS);
	if (!props)
		return TRUE;

	/* If one of the MAC addresses is NULL, we accept that connection */
	s_infiniband_orig = nm_connection_get_setting_infiniband (orig);
	if (s_infiniband_orig)
		orig_mac = nm_setting_infiniband_get_mac_address (s_infiniband_orig);

	s_infiniband_cand = nm_connection_get_setting_infiniband (candidate);
	if (s_infiniband_cand)
		cand_mac = nm_setting_infiniband_get_mac_address (s_infiniband_cand);

	if (!orig_mac || !cand_mac) {
		remove_from_hash (settings, props,
		                  NM_SETTING_INFINIBAND_SETTING_NAME,
		                  NM_SETTING_INFINIBAND_MAC_ADDRESS);
		return TRUE;
	}
	return FALSE;
}

static gboolean
check_connection_cloned_mac_address (NMConnection *orig,
                                     NMConnection *candidate,
                                     GHashTable *settings)
{
	GHashTable *props;
	const char *orig_mac = NULL, *cand_mac = NULL;
	NMSettingWired *s_wired_orig, *s_wired_cand;

	props = check_property_in_hash (settings,
	                                NM_SETTING_WIRED_SETTING_NAME,
	                                NM_SETTING_WIRED_CLONED_MAC_ADDRESS);
	if (!props)
		return TRUE;

	/* If one of the MAC addresses is NULL, we accept that connection */
	s_wired_orig = nm_connection_get_setting_wired (orig);
	if (s_wired_orig)
		orig_mac = nm_setting_wired_get_cloned_mac_address (s_wired_orig);

	s_wired_cand = nm_connection_get_setting_wired (candidate);
	if (s_wired_cand)
		cand_mac = nm_setting_wired_get_cloned_mac_address (s_wired_cand);

	/* special cloned mac address entries are accepted. */
	if (NM_CLONED_MAC_IS_SPECIAL (orig_mac))
		orig_mac = NULL;
	if (NM_CLONED_MAC_IS_SPECIAL (cand_mac))
		cand_mac = NULL;

	if (!orig_mac || !cand_mac) {
		remove_from_hash (settings, props,
		                  NM_SETTING_WIRED_SETTING_NAME,
		                  NM_SETTING_WIRED_CLONED_MAC_ADDRESS);
		return TRUE;
	}
	return FALSE;
}

static gboolean
check_connection_s390_props (NMConnection *orig,
                             NMConnection *candidate,
                             GHashTable *settings)
{
	GHashTable *props1, *props2, *props3;
	NMSettingWired *s_wired_orig, *s_wired_cand;

	props1 = check_property_in_hash (settings,
	                                 NM_SETTING_WIRED_SETTING_NAME,
	                                 NM_SETTING_WIRED_S390_SUBCHANNELS);
	props2 = check_property_in_hash (settings,
	                                 NM_SETTING_WIRED_SETTING_NAME,
	                                 NM_SETTING_WIRED_S390_NETTYPE);
	props3 = check_property_in_hash (settings,
	                                 NM_SETTING_WIRED_SETTING_NAME,
	                                 NM_SETTING_WIRED_S390_OPTIONS);
	if (!props1 && !props2 && !props3)
		return TRUE;

	/* If the generated connection did not contain wired setting,
	 * allow it to match to a connection with a wired setting,
	 * but default (empty) s390-* properties */
	s_wired_orig = nm_connection_get_setting_wired (orig);
	s_wired_cand = nm_connection_get_setting_wired (candidate);
	if (!s_wired_orig && s_wired_cand) {
		const char * const *subchans = nm_setting_wired_get_s390_subchannels (s_wired_cand);
		const char *nettype = nm_setting_wired_get_s390_nettype (s_wired_cand);
		guint32 num_options = nm_setting_wired_get_num_s390_options (s_wired_cand);

		if ((!subchans || !*subchans) && !nettype && num_options == 0) {
			remove_from_hash (settings, props1,
			                  NM_SETTING_WIRED_SETTING_NAME,
			                  NM_SETTING_WIRED_S390_SUBCHANNELS);
			remove_from_hash (settings, props2,
			                  NM_SETTING_WIRED_SETTING_NAME,
			                  NM_SETTING_WIRED_S390_NETTYPE);
			remove_from_hash (settings, props3,
			                  NM_SETTING_WIRED_SETTING_NAME,
			                  NM_SETTING_WIRED_S390_OPTIONS);
			return TRUE;
		}
	}
	return FALSE;
}

static NMConnection *
check_possible_match (NMConnection *orig,
                      NMConnection *candidate,
                      GHashTable *settings,
                      gboolean device_has_carrier,
                      gint64 default_v4_metric,
                      gint64 default_v6_metric)
{
	g_return_val_if_fail (settings != NULL, NULL);

	if (!check_ip6_method (orig, candidate, settings))
		return NULL;

	if (!check_ip4_method (orig, candidate, settings, device_has_carrier))
		return NULL;

	if (!check_ip_routes (orig, candidate, settings, default_v4_metric, TRUE))
		return NULL;

	if (!check_ip_routes (orig, candidate, settings, default_v6_metric, FALSE))
		return NULL;

	if (!check_connection_interface_name (orig, candidate, settings))
		return NULL;

	if (!check_connection_mac_address (orig, candidate, settings))
		return NULL;

	if (!check_connection_infiniband_mac_address (orig, candidate, settings))
		return NULL;

	if (!check_connection_cloned_mac_address (orig, candidate, settings))
		return NULL;

	if (!check_connection_s390_props (orig, candidate, settings))
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
 * @indicated: whether the match is already hinted/indicated. That is the
 *   case when we found the connection in the state file from a previous run.
 *   In this case, we perform a relexed check, as we have a good hint
 *   that the connection actually matches.
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
nm_utils_match_connection (NMConnection *const*connections,
                           NMConnection *original,
                           gboolean indicated,
                           gboolean device_has_carrier,
                           gint64 default_v4_metric,
                           gint64 default_v6_metric,
                           NMUtilsMatchFilterFunc match_filter_func,
                           gpointer match_filter_data)
{
	NMConnection *best_match = NULL;

	if (!connections)
		return NULL;

	for (; *connections; connections++) {
		NMConnection *candidate = NM_CONNECTION (*connections);
		GHashTable *diffs = NULL;

		if (match_filter_func) {
			if (!match_filter_func (candidate, match_filter_data))
				continue;
		}

		if (indicated) {
			NMSettingConnection *s_orig, *s_cand;

			s_orig = nm_connection_get_setting_connection (original);
			s_cand = nm_connection_get_setting_connection (candidate);

			/* It is indicated that this connection matches. Assume we have
			 * a match, but check for particular differences that let us
			 * reject the candidate. */
			if (!nm_streq0 (nm_setting_connection_get_connection_type (s_orig),
			                nm_setting_connection_get_connection_type (s_cand)))
				continue;
			if (!nm_streq0 (nm_setting_connection_get_slave_type (s_orig),
			                nm_setting_connection_get_slave_type (s_cand)))
				continue;

			/* this is good enough for a match */
		} else if (!nm_connection_diff (original, candidate, NM_SETTING_COMPARE_FLAG_INFERRABLE, &diffs)) {
			if (!best_match) {
				best_match = check_possible_match (original, candidate, diffs, device_has_carrier,
				                                   default_v4_metric, default_v6_metric);
			}

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

/*****************************************************************************/

int
nm_match_spec_device_by_pllink (const NMPlatformLink *pllink,
                                const char *match_device_type,
                                const GSList *specs,
                                int no_match_value)
{
	NMMatchSpecMatchType m;

	/* we can only match by certain properties that are available on the
	 * platform link (and even @pllink might be missing.
	 *
	 * It's still useful because of specs like "*" and "except:interface-name:eth0",
	 * which match even in that case. */
	m = nm_match_spec_device (specs,
	                          pllink ? pllink->name : NULL,
	                          match_device_type,
	                          pllink ? pllink->driver : NULL,
	                          NULL,
	                          NULL,
	                          NULL);

	switch (m) {
	case NM_MATCH_SPEC_MATCH:
		return TRUE;
	case NM_MATCH_SPEC_NEG_MATCH:
		return FALSE;
	case NM_MATCH_SPEC_NO_MATCH:
		return no_match_value;
	}
	nm_assert_not_reached ();
	return no_match_value;
}

/*****************************************************************************/

struct _NMShutdownWaitObjHandle {
	CList lst;
	GObject *watched_obj;
	const char *msg_reason;
};

static CList _shutdown_waitobj_lst_head;

static void
_shutdown_waitobj_unregister (NMShutdownWaitObjHandle *handle)
{
	c_list_unlink_stale (&handle->lst);
	g_slice_free (NMShutdownWaitObjHandle, handle);

	/* FIXME(shutdown): check whether the object list is empty, and
	 * signal shutdown-complete */
}

static void
_shutdown_waitobj_cb (gpointer user_data,
                       GObject *where_the_object_was)
{
	NMShutdownWaitObjHandle *handle = user_data;

	nm_assert (handle);
	nm_assert (handle->watched_obj == where_the_object_was);
	_shutdown_waitobj_unregister (handle);
}

/**
 * _nm_shutdown_wait_obj_register:
 * @watched_obj: the object to watch. Takes a weak reference on the object
 *   to be notified when it gets destroyed.
 * @msg_reason: a reason message, for debugging and logging purposes. It
 *   must be a static string. Or at least, be alive at least as long as
 *   @watched_obj. So, theoretically, if you need a dynamic @msg_reason,
 *   you could attach it to @watched_obj's user-data.
 *
 * Keep track of @watched_obj until it gets destroyed. During shutdown,
 * we wait until all watched objects are destroyed. This is useful, if
 * this object still conducts some asynchronous action, which needs to
 * complete before NetworkManager is allowed to terminate. We re-use
 * the reference-counter of @watched_obj as signal, that the object
 * is still used.
 *
 * FIXME(shutdown): proper shutdown is not yet implemented, and registering
 *   an object (currently) has no effect.
 *
 * Returns: a handle to unregister the object. The caller may choose to ignore
 *   the handle, in which case, the object will be automatically unregistered,
 *   once it gets destroyed.
 */
NMShutdownWaitObjHandle *
_nm_shutdown_wait_obj_register (GObject *watched_obj,
                                const char *msg_reason)
{
	NMShutdownWaitObjHandle *handle;

	g_return_val_if_fail (G_IS_OBJECT (watched_obj), NULL);

	if (G_UNLIKELY (!_shutdown_waitobj_lst_head.next))
		c_list_init (&_shutdown_waitobj_lst_head);

	handle = g_slice_new (NMShutdownWaitObjHandle);
	handle->watched_obj = watched_obj;
	/* we don't clone the string. We require the caller to use pass a static message.
	 * If he really cannot do that, he should attach the string to the watched_obj
	 * as user-data. */
	handle->msg_reason = msg_reason;
	c_list_link_tail (&_shutdown_waitobj_lst_head, &handle->lst);
	g_object_weak_ref (watched_obj, _shutdown_waitobj_cb, handle);
	return handle;
}

void
nm_shutdown_wait_obj_unregister (NMShutdownWaitObjHandle *handle)
{
	g_return_if_fail (handle);

	nm_assert (G_IS_OBJECT (handle->watched_obj));
	nm_assert (nm_c_list_contains_entry (&_shutdown_waitobj_lst_head, handle, lst));

	g_object_weak_unref (handle->watched_obj, _shutdown_waitobj_cb, handle);
	_shutdown_waitobj_unregister (handle);
}
