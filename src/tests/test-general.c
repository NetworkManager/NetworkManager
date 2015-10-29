/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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
 * Copyright (C) 2014 Red Hat, Inc.
 *
 */

#include "config.h"

#include <string.h>
#include <errno.h>

#include "nm-default.h"
#include "NetworkManagerUtils.h"
#include "nm-core-internal.h"

#include "nm-test-utils.h"

/* Reference implementation for nm_utils_ip6_address_clear_host_address.
 * Taken originally from set_address_masked(), src/rdisc/nm-lndp-rdisc.c
 **/
static void
ip6_address_clear_host_address_reference (struct in6_addr *dst, struct in6_addr *src, guint8 plen)
{
	guint nbytes = plen / 8;
	guint nbits = plen % 8;

	g_return_if_fail (plen <= 128);
	g_assert (src);
	g_assert (dst);

	if (plen >= 128)
		*dst = *src;
	else {
		memset (dst, 0, sizeof (*dst));
		memcpy (dst, src, nbytes);
		dst->s6_addr[nbytes] = (src->s6_addr[nbytes] & (0xFF << (8 - nbits)));
	}
}

static void
_randomize_in6_addr (struct in6_addr *addr, GRand *r)
{
	int i;

	for (i=0; i < 4; i++)
		((guint32 *)addr)[i] = g_rand_int (r);
}

static void
test_nm_utils_ip6_address_clear_host_address (void)
{
	GRand *r = g_rand_new ();
	int plen, i;

	g_rand_set_seed (r, 0);

	for (plen = 0; plen <= 128; plen++) {
		for (i =0; i<50; i++) {
			struct in6_addr addr_src, addr_ref;
			struct in6_addr addr1, addr2;

			_randomize_in6_addr (&addr_src, r);
			_randomize_in6_addr (&addr_ref, r);
			_randomize_in6_addr (&addr1, r);
			_randomize_in6_addr (&addr2, r);

			addr1 = addr_src;
			ip6_address_clear_host_address_reference (&addr_ref, &addr1, plen);

			_randomize_in6_addr (&addr1, r);
			_randomize_in6_addr (&addr2, r);
			addr1 = addr_src;
			nm_utils_ip6_address_clear_host_address (&addr2, &addr1, plen);
			g_assert_cmpint (memcmp (&addr1, &addr_src, sizeof (struct in6_addr)), ==, 0);
			g_assert_cmpint (memcmp (&addr2, &addr_ref, sizeof (struct in6_addr)), ==, 0);

			/* test for self assignment/inplace update. */
			_randomize_in6_addr (&addr1, r);
			addr1 = addr_src;
			nm_utils_ip6_address_clear_host_address (&addr1, &addr1, plen);
			g_assert_cmpint (memcmp (&addr1, &addr_ref, sizeof (struct in6_addr)), ==, 0);
		}
	}

	g_rand_free (r);
}


static void
test_nm_utils_log_connection_diff (void)
{
	NMConnection *connection;
	NMConnection *connection2;

	/* if logging is disabled (the default), nm_utils_log_connection_diff() returns
	 * early without doing anything. Hence, in the normal testing, this test does nothing.
	 * It only gets interesting, when run verbosely with NMTST_DEBUG=debug ... */

	nm_log (LOGL_DEBUG, LOGD_CORE, "START TEST test_nm_utils_log_connection_diff...");

	connection = nm_simple_connection_new ();
	nm_connection_add_setting (connection, nm_setting_connection_new ());
	nm_utils_log_connection_diff (connection, NULL, LOGL_DEBUG, LOGD_CORE, "test1", ">>> ");

	nm_connection_add_setting (connection, nm_setting_wired_new ());
	nm_utils_log_connection_diff (connection, NULL, LOGL_DEBUG, LOGD_CORE, "test2", ">>> ");

	connection2 = nm_simple_connection_new_clone (connection);
	nm_utils_log_connection_diff (connection, connection2, LOGL_DEBUG, LOGD_CORE, "test3", ">>> ");

	g_object_set (nm_connection_get_setting_connection (connection),
	              NM_SETTING_CONNECTION_ID, "id",
	              NM_SETTING_CONNECTION_UUID, "uuid",
	              NULL);
	g_object_set (nm_connection_get_setting_connection (connection2),
	              NM_SETTING_CONNECTION_ID, "id2",
	              NM_SETTING_CONNECTION_MASTER, "master2",
	              NULL);
	nm_utils_log_connection_diff (connection, connection2, LOGL_DEBUG, LOGD_CORE, "test4", ">>> ");

	nm_connection_add_setting (connection, nm_setting_802_1x_new ());
	nm_utils_log_connection_diff (connection, connection2, LOGL_DEBUG, LOGD_CORE, "test5", ">>> ");

	g_object_set (nm_connection_get_setting_802_1x (connection),
	              NM_SETTING_802_1X_PASSWORD, "id2",
	              NM_SETTING_802_1X_PASSWORD_FLAGS, NM_SETTING_SECRET_FLAG_NOT_SAVED,
	              NULL);
	nm_utils_log_connection_diff (connection, NULL, LOGL_DEBUG, LOGD_CORE, "test6", ">>> ");
	nm_utils_log_connection_diff (connection, connection2, LOGL_DEBUG, LOGD_CORE, "test7", ">>> ");
	nm_utils_log_connection_diff (connection2, connection, LOGL_DEBUG, LOGD_CORE, "test8", ">>> ");

	g_clear_object (&connection);
	g_clear_object (&connection2);

	connection = nmtst_create_minimal_connection ("id-vpn-1", NULL, NM_SETTING_VPN_SETTING_NAME, NULL);
	nm_utils_log_connection_diff (connection, NULL, LOGL_DEBUG, LOGD_CORE, "test-vpn-1", ">>> ");

	g_clear_object (&connection);
}

/*******************************************/

static NMConnection *
_match_connection_new (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4, *s_ip6;
	char *uuid;

	connection = nm_simple_connection_new ();

	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, (NMSetting *) s_con);
	uuid = nm_utils_uuid_generate ();
	g_object_set (G_OBJECT (s_con),
	              NM_SETTING_CONNECTION_ID, "blahblah",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NM_SETTING_CONNECTION_AUTOCONNECT, FALSE,
	              NULL);
	g_free (uuid);

	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, (NMSetting *) s_wired);

	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, (NMSetting *) s_ip4);
	g_object_set (G_OBJECT (s_ip4),
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NULL);

	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, (NMSetting *) s_ip6);
	g_object_set (G_OBJECT (s_ip6),
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO,
	              NULL);

	return connection;
}

static void
test_connection_match_basic (void)
{
	NMConnection *orig, *copy, *matched;
	GSList *connections = NULL;
	NMSettingIPConfig *s_ip4;

	orig = _match_connection_new ();
	copy = nm_simple_connection_new_clone (orig);
	connections = g_slist_append (connections, copy);

	matched = nm_utils_match_connection (connections, orig, TRUE, NULL, NULL);
	g_assert (matched == copy);

	/* Now change a material property like IPv4 method and ensure matching fails */
	s_ip4 = nm_connection_get_setting_ip4_config (orig);
	g_assert (s_ip4);
	g_object_set (G_OBJECT (s_ip4),
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL,
	              NULL);
	matched = nm_utils_match_connection (connections, orig, TRUE, NULL, NULL);
	g_assert (matched == NULL);

	g_slist_free (connections);
	g_object_unref (orig);
	g_object_unref (copy);
}

static void
test_connection_match_ip6_method (void)
{
	NMConnection *orig, *copy, *matched;
	GSList *connections = NULL;
	NMSettingIPConfig *s_ip6;

	orig = _match_connection_new ();
	copy = nm_simple_connection_new_clone (orig);
	connections = g_slist_append (connections, copy);

	/* Check that if the generated connection is IPv6 method=link-local, and the
	 * candidate is both method=auto and may-faily=true, that the candidate is
	 * matched.
	 */
	s_ip6 = nm_connection_get_setting_ip6_config (orig);
	g_assert (s_ip6);
	g_object_set (G_OBJECT (s_ip6),
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL,
	              NULL);

	s_ip6 = nm_connection_get_setting_ip6_config (copy);
	g_assert (s_ip6);
	g_object_set (G_OBJECT (s_ip6),
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	matched = nm_utils_match_connection (connections, orig, TRUE, NULL, NULL);
	g_assert (matched == copy);

	g_slist_free (connections);
	g_object_unref (orig);
	g_object_unref (copy);
}

static void
test_connection_match_ip6_method_ignore (void)
{
	NMConnection *orig, *copy, *matched;
	GSList *connections = NULL;
	NMSettingIPConfig *s_ip6;

	orig = _match_connection_new ();
	copy = nm_simple_connection_new_clone (orig);
	connections = g_slist_append (connections, copy);

	/* Check that if the generated connection is IPv6 method=link-local, and the
	 * candidate is method=ignore, that the candidate is matched.
	 */
	s_ip6 = nm_connection_get_setting_ip6_config (orig);
	g_assert (s_ip6);
	g_object_set (G_OBJECT (s_ip6),
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL,
	              NULL);

	s_ip6 = nm_connection_get_setting_ip6_config (copy);
	g_assert (s_ip6);
	g_object_set (G_OBJECT (s_ip6),
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NULL);

	matched = nm_utils_match_connection (connections, orig, TRUE, NULL, NULL);
	g_assert (matched == copy);

	g_slist_free (connections);
	g_object_unref (orig);
	g_object_unref (copy);
}

static void
test_connection_match_ip6_method_ignore_auto (void)
{
	NMConnection *orig, *copy, *matched;
	GSList *connections = NULL;
	NMSettingIPConfig *s_ip6;

	orig = _match_connection_new ();
	copy = nm_simple_connection_new_clone (orig);
	connections = g_slist_append (connections, copy);

	/* Check that if the generated connection is IPv6 method=auto, and the
	 * candidate is method=ignore, that the candidate is matched.
	 */
	s_ip6 = nm_connection_get_setting_ip6_config (orig);
	g_assert (s_ip6);
	g_object_set (G_OBJECT (s_ip6),
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO,
	              NULL);

	s_ip6 = nm_connection_get_setting_ip6_config (copy);
	g_assert (s_ip6);
	g_object_set (G_OBJECT (s_ip6),
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NULL);

	matched = nm_utils_match_connection (connections, orig, TRUE, NULL, NULL);
	g_assert (matched == copy);

	g_slist_free (connections);
	g_object_unref (orig);
	g_object_unref (copy);
}


static void
test_connection_match_ip4_method (void)
{
	NMConnection *orig, *copy, *matched;
	GSList *connections = NULL;
	NMSettingIPConfig *s_ip4;

	orig = _match_connection_new ();
	copy = nm_simple_connection_new_clone (orig);
	connections = g_slist_append (connections, copy);

	/* Check that if the generated connection is IPv4 method=disabled, and the
	 * candidate is both method=auto and may-faily=true, and the device has no
	 * carrier that the candidate is matched.
	 */
	s_ip4 = nm_connection_get_setting_ip4_config (orig);
	g_assert (s_ip4);
	g_object_set (G_OBJECT (s_ip4),
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_DISABLED,
	              NULL);

	s_ip4 = nm_connection_get_setting_ip4_config (copy);
	g_assert (s_ip4);
	g_object_set (G_OBJECT (s_ip4),
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	matched = nm_utils_match_connection (connections, orig, FALSE, NULL, NULL);
	g_assert (matched == copy);

	/* Ensure when carrier=true matching fails */
	matched = nm_utils_match_connection (connections, orig, TRUE, NULL, NULL);
	g_assert (matched == NULL);

	g_slist_free (connections);
	g_object_unref (orig);
	g_object_unref (copy);
}

static void
test_connection_match_interface_name (void)
{
	NMConnection *orig, *copy, *matched;
	GSList *connections = NULL;
	NMSettingConnection *s_con;

	orig = _match_connection_new ();
	copy = nm_simple_connection_new_clone (orig);
	connections = g_slist_append (connections, copy);

	/* Check that if the generated connection has an interface name and the
	 * candidate's interface name is NULL, that the candidate is matched.
	 */
	s_con = nm_connection_get_setting_connection (orig);
	g_assert (s_con);
	g_object_set (G_OBJECT (s_con),
	              NM_SETTING_CONNECTION_INTERFACE_NAME, "em1",
	              NULL);

	s_con = nm_connection_get_setting_connection (copy);
	g_assert (s_con);
	g_object_set (G_OBJECT (s_con),
	              NM_SETTING_CONNECTION_INTERFACE_NAME, NULL,
	              NULL);

	matched = nm_utils_match_connection (connections, orig, TRUE, NULL, NULL);
	g_assert (matched == copy);

	g_slist_free (connections);
	g_object_unref (orig);
	g_object_unref (copy);
}

static void
test_connection_match_wired (void)
{
	NMConnection *orig, *copy, *matched;
	GSList *connections = NULL;
	NMSettingWired *s_wired;
	char *subchan_arr[] = { "0.0.8000", "0.0.8001", "0.0.8002", NULL };
	const char *mac = "52:54:00:ab:db:23";

	orig = _match_connection_new ();
	copy = nm_simple_connection_new_clone (orig);
	connections = g_slist_append (connections, copy);

	s_wired = nm_connection_get_setting_wired (orig);
	g_assert (s_wired);
	g_object_set (G_OBJECT (s_wired),
	              NM_SETTING_WIRED_PORT, "tp",           /* port is not compared */
	              NM_SETTING_WIRED_MAC_ADDRESS, mac,     /* we allow MAC address just in one connection */
	              NM_SETTING_WIRED_S390_SUBCHANNELS, subchan_arr,
	              NM_SETTING_WIRED_S390_NETTYPE, "qeth",
	              NULL);

	s_wired = nm_connection_get_setting_wired (copy);
	g_assert (s_wired);
	g_object_set (G_OBJECT (s_wired),
	              NM_SETTING_WIRED_S390_SUBCHANNELS, subchan_arr,
	              NM_SETTING_WIRED_S390_NETTYPE, "qeth",
	              NULL);

	matched = nm_utils_match_connection (connections, orig, TRUE, NULL, NULL);
	g_assert (matched == copy);

	g_slist_free (connections);
	g_object_unref (orig);
	g_object_unref (copy);
}

static void
test_connection_match_wired2 (void)
{
	NMConnection *orig, *copy, *matched;
	GSList *connections = NULL;
	NMSettingWired *s_wired;
	const char *mac = "52:54:00:ab:db:23";

	orig = _match_connection_new ();
	s_wired = nm_connection_get_setting_wired (orig);
	g_assert (s_wired);
	g_object_set (G_OBJECT (s_wired),
	              NM_SETTING_WIRED_PORT, "tp",           /* port is not compared */
	              NM_SETTING_WIRED_MAC_ADDRESS, mac,     /* we allow MAC address just in one connection */
	              NULL);

	copy = nm_simple_connection_new_clone (orig);
	connections = g_slist_append (connections, copy);

	/* Check that if the generated connection do not have wired setting
	 * and s390 properties in the existing connection's setting are default,
	 * the connections match. It can happen if assuming VLAN devices. */
	nm_connection_remove_setting (orig, NM_TYPE_SETTING_WIRED);

	matched = nm_utils_match_connection (connections, orig, TRUE, NULL, NULL);
	g_assert (matched == copy);

	g_slist_free (connections);
	g_object_unref (orig);
	g_object_unref (copy);
}

static void
test_connection_match_cloned_mac (void)
{
	NMConnection *orig, *exact, *fuzzy, *matched;
	GSList *connections = NULL;
	NMSettingWired *s_wired;

	orig = _match_connection_new ();

	fuzzy = nm_simple_connection_new_clone (orig);
	connections = g_slist_append (connections, fuzzy);
	s_wired = nm_connection_get_setting_wired (orig);
	g_assert (s_wired);
	g_object_set (G_OBJECT (s_wired),
	              NM_SETTING_WIRED_CLONED_MAC_ADDRESS, "52:54:00:ab:db:23",
	              NULL);

	matched = nm_utils_match_connection (connections, orig, TRUE, NULL, NULL);
	g_assert (matched == fuzzy);

	exact = nm_simple_connection_new_clone (orig);
	connections = g_slist_append (connections, exact);
	s_wired = nm_connection_get_setting_wired (exact);
	g_assert (s_wired);
	g_object_set (G_OBJECT (s_wired),
	              NM_SETTING_WIRED_CLONED_MAC_ADDRESS, "52:54:00:ab:db:23",
	              NULL);

	matched = nm_utils_match_connection (connections, orig, TRUE, NULL, NULL);
	g_assert (matched == exact);

	g_object_set (G_OBJECT (s_wired),
	              NM_SETTING_WIRED_CLONED_MAC_ADDRESS, "52:54:00:ab:db:24",
	              NULL);

	matched = nm_utils_match_connection (connections, orig, TRUE, NULL, NULL);
	g_assert (matched == fuzzy);

	g_slist_free (connections);
	g_object_unref (orig);
	g_object_unref (fuzzy);
	g_object_unref (exact);
}

static void
test_connection_no_match_ip4_addr (void)
{
	NMConnection *orig, *copy, *matched;
	GSList *connections = NULL;
	NMSettingIPConfig *s_ip4, *s_ip6;
	NMIPAddress *nm_addr;
	GError *error = NULL;

	orig = _match_connection_new ();
	copy = nm_simple_connection_new_clone (orig);
	connections = g_slist_append (connections, copy);

	/* Check that if we have two differences, ipv6.method (exception we allow) and
	 * ipv4.addresses (which is fatal), we don't match the connections.
	 */
	s_ip6 = nm_connection_get_setting_ip6_config (orig);
	g_assert (s_ip6);
	g_object_set (G_OBJECT (s_ip6),
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL,
	              NULL);

	s_ip6 = nm_connection_get_setting_ip6_config (copy);
	g_assert (s_ip6);
	g_object_set (G_OBJECT (s_ip6),
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NULL);


	s_ip4 = nm_connection_get_setting_ip4_config (orig);
	g_assert (s_ip4);
	g_object_set (G_OBJECT (s_ip4),
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	              NM_SETTING_IP_CONFIG_GATEWAY, "1.1.1.254",
	              NULL);
	nm_addr = nm_ip_address_new (AF_INET, "1.1.1.4", 24, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_address (s_ip4, nm_addr);
	nm_ip_address_unref (nm_addr);

	s_ip4 = nm_connection_get_setting_ip4_config (copy);
	g_assert (s_ip4);
	g_object_set (G_OBJECT (s_ip4),
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	              NM_SETTING_IP_CONFIG_GATEWAY, "2.2.2.254",
	              NULL);
	nm_addr = nm_ip_address_new (AF_INET, "2.2.2.4", 24, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_address (s_ip4, nm_addr);
	nm_ip_address_unref (nm_addr);

	matched = nm_utils_match_connection (connections, orig, TRUE, NULL, NULL);
	g_assert (matched != copy);

	g_slist_free (connections);
	g_object_unref (orig);
	g_object_unref (copy);
}

static void
test_connection_no_match_vlan (void)
{
	NMConnection *orig, *copy, *matched;
	GSList *connections = NULL;
	NMSettingConnection *s_con;
	NMSettingVlan *s_vlan_orig, *s_vlan_copy;
	char *uuid;

	orig = nm_simple_connection_new ();
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (orig, (NMSetting *) s_con);
	uuid = nm_utils_uuid_generate ();
	g_object_set (G_OBJECT (s_con),
	              NM_SETTING_CONNECTION_ID, "vlan-test",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_VLAN_SETTING_NAME,
	              NM_SETTING_CONNECTION_AUTOCONNECT, FALSE,
	              NULL);
	g_free (uuid);
	nm_connection_add_setting (orig, nm_setting_vlan_new ());

	copy = nm_simple_connection_new_clone (orig);
	connections = g_slist_append (connections, copy);

	/* Check that the connections do not match if VLAN flags differ */
	s_vlan_orig = nm_connection_get_setting_vlan (orig);
	g_assert (s_vlan_orig);
	g_object_set (G_OBJECT (s_vlan_orig),
	              NM_SETTING_VLAN_FLAGS, NM_VLAN_FLAG_REORDER_HEADERS,
	              NULL);

	s_vlan_copy = nm_connection_get_setting_vlan (copy);
	g_assert (s_vlan_copy);
	g_object_set (G_OBJECT (s_vlan_copy),
	              NM_SETTING_VLAN_FLAGS, 0,
	              NULL);

	matched = nm_utils_match_connection (connections, orig, TRUE, NULL, NULL);
	g_assert (matched != copy);

	/* Check that the connections do not match if VLAN priorities differ */
	g_object_set (G_OBJECT (s_vlan_orig), NM_SETTING_VLAN_FLAGS, 0, NULL);
	nm_setting_vlan_add_priority_str (s_vlan_orig, NM_VLAN_INGRESS_MAP, "1:3");

	g_object_set (G_OBJECT (s_vlan_copy), NM_SETTING_VLAN_FLAGS, 0, NULL);
	nm_setting_vlan_add_priority_str (s_vlan_copy, NM_VLAN_INGRESS_MAP, "4:2");

	matched = nm_utils_match_connection (connections, orig, TRUE, NULL, NULL);
	g_assert (matched != copy);

	g_slist_free (connections);
	g_object_unref (orig);
	g_object_unref (copy);
}

static NMConnection *
_create_connection_autoconnect (const char *id, gboolean autoconnect, int autoconnect_priority)
{
	NMConnection *c;
	NMSettingConnection *s_con;

	c = nmtst_create_minimal_connection (id, NULL, NM_SETTING_WIRED_SETTING_NAME, &s_con);
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_AUTOCONNECT, autoconnect,
	              NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY, autoconnect_priority,
	              NULL);
	nmtst_connection_normalize (c);
	return c;
}

static void
_test_connection_sort_autoconnect_priority_one (NMConnection **list, gboolean shuffle)
{
	int i, j;
	int count = 0;
	gs_unref_ptrarray GPtrArray *connections = g_ptr_array_new ();

	while (list[count])
		count++;
	g_assert (count > 1);

	/* copy the list of connections over to @connections and shuffle. */
	for (i = 0; i < count; i++)
		g_ptr_array_add (connections, list[i]);
	if (shuffle) {
		for (i = count - 1; i > 0; i--) {
			j = g_rand_int (nmtst_get_rand ()) % (i + 1);
			NMTST_SWAP (connections->pdata[i], connections->pdata[j]);
		}
	}

	/* sort it... */
	g_ptr_array_sort (connections, (GCompareFunc) nm_utils_cmp_connection_by_autoconnect_priority);

	for (i = 0; i < count; i++) {
		if (list[i] == connections->pdata[i])
			continue;
		if (shuffle && nm_utils_cmp_connection_by_autoconnect_priority (&list[i], (NMConnection **) &connections->pdata[i]) == 0)
			continue;
		g_message ("After sorting, the order of connections is not as expected!! Offending index: %d", i);
		for (j = 0; j < count; j++)
			g_message ("  %3d:  %p/%-20s - %p/%-20s", j, list[j], nm_connection_get_id (list[j]), connections->pdata[j], nm_connection_get_id (connections->pdata[j]));
		g_assert_not_reached ();
	}
}

static void
_test_connection_sort_autoconnect_priority_free (NMConnection **list)
{
	while (*list) {
		g_object_unref (*list);
		*list = NULL;
	}
}

static void
test_connection_sort_autoconnect_priority (void)
{
	NMConnection *c1[] = {
		_create_connection_autoconnect ("AC/100", TRUE, 100),
		_create_connection_autoconnect ("AC/100", TRUE, 100),
		_create_connection_autoconnect ("AC/99", TRUE, 99),
		_create_connection_autoconnect ("AC/0", TRUE, 0),
		_create_connection_autoconnect ("AC/0", TRUE, 0),
		_create_connection_autoconnect ("AC/-1", TRUE, -1),
		_create_connection_autoconnect ("AC/-3", TRUE, -3),
		_create_connection_autoconnect ("ac/0", FALSE, 0),
		_create_connection_autoconnect ("ac/0", FALSE, 0),
		_create_connection_autoconnect ("ac/1", FALSE, 1),
		_create_connection_autoconnect ("ac/-1", FALSE, -1),
		_create_connection_autoconnect ("ac/1", FALSE, 1),
		_create_connection_autoconnect ("ac/0", FALSE, 0),
		NULL,
	};
	NMConnection *c2[] = {
		_create_connection_autoconnect ("AC/100", TRUE, 100),
		_create_connection_autoconnect ("AC/99", TRUE, 99),
		_create_connection_autoconnect ("AC/0", TRUE, 0),
		_create_connection_autoconnect ("AC/-1", TRUE, -1),
		_create_connection_autoconnect ("AC/-3", TRUE, -3),
		_create_connection_autoconnect ("ac/0", FALSE, 0),
		NULL,
	};

	_test_connection_sort_autoconnect_priority_one (c1, FALSE);
	_test_connection_sort_autoconnect_priority_one (c2, FALSE);
	_test_connection_sort_autoconnect_priority_one (c1, TRUE);
	_test_connection_sort_autoconnect_priority_one (c2, TRUE);

	_test_connection_sort_autoconnect_priority_free (c1);
	_test_connection_sort_autoconnect_priority_free (c2);
}

/*******************************************/

static const char *_test_match_spec_all[] = {
	"e",
	"em",
	"em*",
	"em\\",
	"em\\*",
	"em\\1",
	"em\\11",
	"em\\2",
	"em1",
	"em11",
	"em2",
	"=em*",
	NULL
};

static gboolean
_test_match_spec_contains (const char **matches, const char *match)
{
	guint i;

	for (i = 0; matches && matches[i]; i++) {
		if (strcmp (match, matches[i]) == 0)
			return TRUE;
	}
	return FALSE;
}

static void
test_match_spec_ifname (const char *spec_str, const char **matches, const char **neg_matches)
{
	const char *m;
	GSList *specs, *specs_reverse = NULL, *specs_resplit, *specs_i, *specs_j;
	guint i;
	gs_free char *specs_joined = NULL;

	g_assert (spec_str);

	specs = nm_match_spec_split (spec_str);

	/* assert that split(join(specs)) == specs */
	specs_joined = nm_match_spec_join (specs);
	specs_resplit = nm_match_spec_split (specs_joined);
	specs_i = specs;
	specs_j = specs_resplit;
	while (specs_i && specs_j && g_strcmp0 (specs_i->data, specs_j->data) == 0) {
		specs_i = specs_i->next;
		specs_j = specs_j->next;
	}
	g_assert (!specs_i);
	g_assert (!specs_j);
	g_slist_free_full (specs_resplit, g_free);

	/* also check the matches in the reverse order. They must yield the same result because
	 * matches are inclusive -- except "except:" which always wins. */
	specs_reverse = g_slist_reverse (g_slist_copy (specs));

	for (i = 0; matches && matches[i]; i++) {
		g_assert (nm_match_spec_interface_name (specs, matches[i]) == NM_MATCH_SPEC_MATCH);
		g_assert (nm_match_spec_interface_name (specs_reverse, matches[i]) == NM_MATCH_SPEC_MATCH);
	}
	for (i = 0; neg_matches && neg_matches[i]; i++) {
		g_assert (nm_match_spec_interface_name (specs, neg_matches[i]) == NM_MATCH_SPEC_NEG_MATCH);
		g_assert (nm_match_spec_interface_name (specs_reverse, neg_matches[i]) == NM_MATCH_SPEC_NEG_MATCH);
	}
	for (i = 0; (m = _test_match_spec_all[i]); i++) {
		if (_test_match_spec_contains (matches, m))
			continue;
		if (_test_match_spec_contains (neg_matches, m))
			continue;
		g_assert (nm_match_spec_interface_name (specs, m) == NM_MATCH_SPEC_NO_MATCH);
		g_assert (nm_match_spec_interface_name (specs_reverse, m) == NM_MATCH_SPEC_NO_MATCH);
	}

	g_slist_free (specs_reverse);
	g_slist_free_full (specs, g_free);
}

static void
test_nm_match_spec_interface_name (void)
{
#define S(...) ((const char *[]) { __VA_ARGS__, NULL } )
	test_match_spec_ifname ("em1",
	                        S ("em1"),
	                        NULL);
	test_match_spec_ifname ("em1,em2",
	                        S ("em1", "em2"),
	                        NULL);
	test_match_spec_ifname ("em1,em2,interface-name:em2",
	                        S ("em1", "em2"),
	                        NULL);
	test_match_spec_ifname ("interface-name:em1",
	                        S ("em1"),
	                        NULL);
	test_match_spec_ifname ("interface-name:em*",
	                        S ("em", "em*", "em\\", "em\\*", "em\\1", "em\\11", "em\\2", "em1", "em11", "em2", "em3"),
	                        NULL);
	test_match_spec_ifname ("interface-name:em\\*",
	                        S ("em\\", "em\\*", "em\\1", "em\\11", "em\\2"),
	                        NULL);
	test_match_spec_ifname ("interface-name:~em\\*",
	                        S ("em\\", "em\\*", "em\\1", "em\\11", "em\\2"),
	                        NULL);
	test_match_spec_ifname ("interface-name:=em*",
	                        S ("em*"),
	                        NULL);
	test_match_spec_ifname ("interface-name:em*,except:interface-name:em1*",
	                        S ("em", "em*", "em\\", "em\\*", "em\\1", "em\\11", "em\\2", "em2", "em3"),
	                        S ("em1", "em11"));
	test_match_spec_ifname ("interface-name:em*,except:interface-name:=em*",
	                        S ("em", "em\\", "em\\*", "em\\1", "em\\11", "em\\2", "em1", "em11", "em2", "em3"),
	                        S ("em*"));
	test_match_spec_ifname ("aa,bb,cc\\,dd,e,,",
	                        S ("aa", "bb", "cc,dd", "e"),
	                        NULL);
	test_match_spec_ifname ("aa;bb;cc\\;dd;e,;",
	                        S ("aa", "bb", "cc;dd", "e"),
	                        NULL);
	test_match_spec_ifname ("interface-name:em\\;1,em\\,2,\\,,\\\\,,em\\\\x",
	                        S ("em;1", "em,2", ",", "\\", "em\\x"),
	                        NULL);
	test_match_spec_ifname ("\\s\\s,\\sinterface-name:a,\\s,",
	                        S ("  ", " ", " interface-name:a"),
	                        NULL);
	test_match_spec_ifname (" aa ;  bb   ; cc\\;dd  ;e , ; \t\\t  , ",
	                        S ("aa", "bb", "cc;dd", "e", "\t"),
	                        NULL);
#undef S
}

/*******************************************/

static void
_do_test_match_spec_match_config (const char *file, gint line, const char *spec_str, guint version, guint v_maj, guint v_min, guint v_mic, NMMatchSpecMatchType expected)
{
	GSList *specs;
	NMMatchSpecMatchType match_result;
	guint c_maj, c_min, c_mic;

	g_assert_cmpint (version, ==, nm_encode_version (v_maj, v_min, v_mic));

	nm_decode_version (version, &c_maj, &c_min, &c_mic);
	g_assert_cmpint (c_maj, ==, c_maj);
	g_assert_cmpint (c_min, ==, c_min);
	g_assert_cmpint (c_mic, ==, c_mic);

	specs = nm_match_spec_split (spec_str);

	match_result = nm_match_spec_match_config (specs, version, NULL);

	if (expected != match_result)
		g_error ("%s:%d: faild comparing \"%s\" with %u.%u.%u. Expected %d, but got %d", file, line, spec_str, v_maj, v_min, v_mic, (int) expected, (int) match_result);

	if (g_slist_length (specs) == 1 && match_result != NM_MATCH_SPEC_NEG_MATCH) {
		/* there is only one spec in the list... test that we match except: */
		char *sss = g_strdup_printf ("except:%s", (char *) specs->data);
		GSList *specs2 = g_slist_append (NULL, sss);
		NMMatchSpecMatchType match_result2;


		match_result2 = nm_match_spec_match_config (specs2, version, NULL);
		if (match_result == NM_MATCH_SPEC_NO_MATCH)
			g_assert_cmpint (match_result2, ==, NM_MATCH_SPEC_NO_MATCH);
		else
			g_assert_cmpint (match_result2, ==, NM_MATCH_SPEC_NEG_MATCH);

		g_slist_free_full (specs2, g_free);
	}

	g_slist_free_full (specs, g_free);
}
#define do_test_match_spec_match_config(spec, v_maj, v_min, v_mic, expected) \
	_do_test_match_spec_match_config (__FILE__, __LINE__, (""spec), NM_ENCODE_VERSION ((v_maj), (v_min), (v_mic)), (v_maj), (v_min), (v_mic), (expected))

static void
test_nm_match_spec_match_config (void)
{
	do_test_match_spec_match_config ("", 1, 2, 3, NM_MATCH_SPEC_NO_MATCH);
	do_test_match_spec_match_config ("nm-version:1.2.3", 1, 2, 2, NM_MATCH_SPEC_NO_MATCH);
	do_test_match_spec_match_config ("nm-version:1.2.3", 1, 2, 3, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version:1.2.3", 1, 2, 4, NM_MATCH_SPEC_NO_MATCH);

	do_test_match_spec_match_config ("nm-version:1.2", 1, 1, 2, NM_MATCH_SPEC_NO_MATCH);
	do_test_match_spec_match_config ("nm-version:1.2", 1, 2, 0, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version:1.2", 1, 2, 2, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version:1.2", 1, 2, 3, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version:1.2", 1, 2, 4, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version:1.2", 1, 3, 0, NM_MATCH_SPEC_NO_MATCH);

	do_test_match_spec_match_config ("nm-version-min:1.2.3", 0, 2, 30, NM_MATCH_SPEC_NO_MATCH);
	do_test_match_spec_match_config ("nm-version-min:1.2.3", 1, 1, 1, NM_MATCH_SPEC_NO_MATCH);
	do_test_match_spec_match_config ("nm-version-min:1.2.3", 1, 2, 2, NM_MATCH_SPEC_NO_MATCH);
	do_test_match_spec_match_config ("nm-version-min:1.2.3", 1, 2, 3, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version-min:1.2.3", 1, 2, 5, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version-min:1.2.3", 1, 3, 0, NM_MATCH_SPEC_NO_MATCH);
	do_test_match_spec_match_config ("nm-version-min:1.2.3", 1, 3, 30, NM_MATCH_SPEC_NO_MATCH);
	do_test_match_spec_match_config ("nm-version-min:1.2.3", 1, 4, 30, NM_MATCH_SPEC_NO_MATCH);

	do_test_match_spec_match_config ("nm-version-min:1.2", 0, 2, 30, NM_MATCH_SPEC_NO_MATCH);
	do_test_match_spec_match_config ("nm-version-min:1.2", 1, 1, 1, NM_MATCH_SPEC_NO_MATCH);
	do_test_match_spec_match_config ("nm-version-min:1.2", 1, 2, 0, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version-min:1.2", 1, 2, 3, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version-min:1.2", 1, 2, 5, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version-min:1.2", 1, 3, 0, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version-min:1.2", 1, 3, 30, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version-min:1.2", 1, 4, 30, NM_MATCH_SPEC_MATCH);

	do_test_match_spec_match_config ("nm-version-min:1", 0, 2, 30, NM_MATCH_SPEC_NO_MATCH);
	do_test_match_spec_match_config ("nm-version-min:1", 1, 1, 1, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version-min:1", 1, 2, 0, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version-min:1", 1, 2, 3, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version-min:1", 1, 2, 5, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version-min:1", 1, 3, 0, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version-min:1", 1, 3, 30, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version-min:1", 1, 4, 30, NM_MATCH_SPEC_MATCH);


	do_test_match_spec_match_config ("nm-version-max:1.2.3", 0, 2, 30, NM_MATCH_SPEC_NO_MATCH);
	do_test_match_spec_match_config ("nm-version-max:1.2.3", 1, 1, 1, NM_MATCH_SPEC_NO_MATCH);
	do_test_match_spec_match_config ("nm-version-max:1.2.3", 1, 2, 0, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version-max:1.2.3", 1, 2, 1, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version-max:1.2.3", 1, 2, 2, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version-max:1.2.3", 1, 2, 3, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version-max:1.2.3", 1, 2, 5, NM_MATCH_SPEC_NO_MATCH);
	do_test_match_spec_match_config ("nm-version-max:1.2.3", 1, 3, 0, NM_MATCH_SPEC_NO_MATCH);
	do_test_match_spec_match_config ("nm-version-max:1.2.3", 1, 3, 30, NM_MATCH_SPEC_NO_MATCH);
	do_test_match_spec_match_config ("nm-version-max:1.2.3", 1, 4, 30, NM_MATCH_SPEC_NO_MATCH);

	do_test_match_spec_match_config ("nm-version-max:1.2", 0, 2, 30, NM_MATCH_SPEC_NO_MATCH);
	do_test_match_spec_match_config ("nm-version-max:1.2", 1, 1, 1, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version-max:1.2", 1, 2, 0, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version-max:1.2", 1, 2, 3, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version-max:1.2", 1, 2, 5, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version-max:1.2", 1, 3, 0, NM_MATCH_SPEC_NO_MATCH);
	do_test_match_spec_match_config ("nm-version-max:1.2", 1, 3, 30, NM_MATCH_SPEC_NO_MATCH);
	do_test_match_spec_match_config ("nm-version-max:1.2", 1, 4, 30, NM_MATCH_SPEC_NO_MATCH);

	do_test_match_spec_match_config ("nm-version-max:1", 0, 2, 30, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version-max:1", 1, 1, 1, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version-max:1", 1, 2, 0, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version-max:1", 1, 2, 3, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version-max:1", 1, 2, 5, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version-max:1", 1, 3, 0, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version-max:1", 1, 3, 30, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version-max:1", 1, 4, 30, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version-max:1", 2, 4, 30, NM_MATCH_SPEC_NO_MATCH);

	do_test_match_spec_match_config ("except:nm-version:1.4.8", 1, 6, 0, NM_MATCH_SPEC_NO_MATCH);
	do_test_match_spec_match_config ("nm-version-min:1.6,except:nm-version:1.4.8", 1, 6, 0, NM_MATCH_SPEC_MATCH);

	do_test_match_spec_match_config ("nm-version-min:1.6,nm-version-min:1.4.6,nm-version-min:1.2.16,except:nm-version:1.4.8", 1, 2, 0, NM_MATCH_SPEC_NO_MATCH);
	do_test_match_spec_match_config ("nm-version-min:1.6,nm-version-min:1.4.6,nm-version-min:1.2.16,except:nm-version:1.4.8", 1, 2, 0, NM_MATCH_SPEC_NO_MATCH);
	do_test_match_spec_match_config ("nm-version-min:1.6,nm-version-min:1.4.6,nm-version-min:1.2.16,except:nm-version:1.4.8", 1, 2, 15, NM_MATCH_SPEC_NO_MATCH);
	do_test_match_spec_match_config ("nm-version-min:1.6,nm-version-min:1.4.6,nm-version-min:1.2.16,except:nm-version:1.4.8", 1, 2, 16, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version-min:1.6,nm-version-min:1.4.6,nm-version-min:1.2.16,except:nm-version:1.4.8", 1, 2, 17, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version-min:1.6,nm-version-min:1.4.6,nm-version-min:1.2.16,except:nm-version:1.4.8", 1, 2, 20, NM_MATCH_SPEC_MATCH);

	do_test_match_spec_match_config ("nm-version-min:1.6,nm-version-min:1.4.6,nm-version-min:1.2.16,except:nm-version:1.4.8", 1, 3, 0, NM_MATCH_SPEC_NO_MATCH);
	do_test_match_spec_match_config ("nm-version-min:1.6,nm-version-min:1.4.6,nm-version-min:1.2.16,except:nm-version:1.4.8", 1, 4, 0, NM_MATCH_SPEC_NO_MATCH);
	do_test_match_spec_match_config ("nm-version-min:1.6,nm-version-min:1.4.6,nm-version-min:1.2.16,except:nm-version:1.4.8", 1, 4, 5, NM_MATCH_SPEC_NO_MATCH);
	do_test_match_spec_match_config ("nm-version-min:1.6,nm-version-min:1.4.6,nm-version-min:1.2.16,except:nm-version:1.4.8", 1, 4, 6, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version-min:1.6,nm-version-min:1.4.6,nm-version-min:1.2.16,except:nm-version:1.4.8", 1, 4, 7, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version-min:1.6,nm-version-min:1.4.6,nm-version-min:1.2.16,except:nm-version:1.4.8", 1, 4, 8, NM_MATCH_SPEC_NEG_MATCH);
	do_test_match_spec_match_config ("nm-version-min:1.6,nm-version-min:1.4.6,nm-version-min:1.2.16,except:nm-version:1.4.8", 1, 4, 9, NM_MATCH_SPEC_MATCH);

	do_test_match_spec_match_config ("nm-version-min:1.6,nm-version-min:1.4.6,nm-version-min:1.2.16,except:nm-version:1.4.8", 1, 5, 0, NM_MATCH_SPEC_NO_MATCH);
	do_test_match_spec_match_config ("nm-version-min:1.6,nm-version-min:1.4.6,nm-version-min:1.2.16,except:nm-version:1.4.8", 1, 6, 0, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version-min:1.6,nm-version-min:1.4.6,nm-version-min:1.2.16,except:nm-version:1.4.8", 1, 6, 5, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version-min:1.6,nm-version-min:1.4.6,nm-version-min:1.2.16,except:nm-version:1.4.8", 1, 7, 7, NM_MATCH_SPEC_MATCH);
	do_test_match_spec_match_config ("nm-version-min:1.6,nm-version-min:1.4.6,nm-version-min:1.2.16,except:nm-version:1.4.8", 1, 8, 8, NM_MATCH_SPEC_MATCH);
}

/*******************************************/

static void
test_nm_utils_strbuf_append (void)
{
#define BUF_ORIG "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define STR_ORIG "abcdefghijklmnopqrstuvwxyz"
	int buf_len;
	int rep;
	char buf[STRLEN (BUF_ORIG) + 1];
	char str[STRLEN (BUF_ORIG) + 1];

	for (buf_len = 0; buf_len < 10; buf_len++) {
		for (rep = 0; rep < 50; rep++) {
			const int s_len = nmtst_get_rand_int () % (sizeof (str) - 5);
			char *t_buf;
			gsize t_len;
			int test_mode;

			strcpy (str, STR_ORIG);
			str[s_len] = '\0';

			g_assert_cmpint (str[sizeof (str) - 1], ==, '\0');
			g_assert_cmpint (strlen (str), ==, s_len);

			strcpy (buf, BUF_ORIG);

			t_buf = buf;
			t_len = buf_len;

			test_mode = nmtst_get_rand_int () % 4;

			switch (test_mode) {
			case 0:
				if (s_len == 1) {
					nm_utils_strbuf_append_c (&t_buf, &t_len, str[0]);
					break;
				}
				/* fall-through */
			case 1:
				nm_utils_strbuf_append_str (&t_buf, &t_len, str);
				break;
			case 2:
				if (s_len == 1) {
					nm_utils_strbuf_append (&t_buf, &t_len, "%c", str[0]);
					break;
				}
				/* fall-through */
			case 3:
				nm_utils_strbuf_append (&t_buf, &t_len, "%s", str);
				break;
			}

			/* Assert that the source-buffer is unmodified. */
			g_assert_cmpint (str[s_len], ==, '\0');
			str[s_len] = STR_ORIG[s_len];
			g_assert (!memcmp (str, STR_ORIG, sizeof (str)));
			str[s_len] = '\0';

			g_assert_cmpint (t_len, >=, 0);
			g_assert_cmpint (t_len, <=, buf_len);
			g_assert (t_buf >= buf);

			/* Assert what was written to the destination buffer. */
			switch (buf_len) {
			case 0:
				g_assert_cmpint (t_len, ==, 0);
				g_assert (t_buf == buf);
				g_assert (!memcmp (buf, BUF_ORIG, sizeof (buf)));
				break;
			case 1:
				if (s_len == 0) {
					g_assert_cmpint (t_len, ==, 1);
					g_assert (t_buf == buf);
					g_assert (buf[0] == '\0');
					g_assert (!memcmp (&buf[1], &BUF_ORIG[1], sizeof (buf) - 1));
				} else {
					g_assert_cmpint (t_len, ==, 0);
					g_assert (t_buf == &buf[1]);
					g_assert (buf[0] == '\0');
					g_assert (!memcmp (&buf[1], &BUF_ORIG[1], sizeof (buf) - 1));
				}
				break;
			default:
				if (s_len == 0) {
					g_assert_cmpint (t_len, ==, buf_len);
					g_assert (t_buf == buf);
					g_assert (buf[0] == '\0');
					g_assert (!memcmp (&buf[1], &BUF_ORIG[1], sizeof (buf) - 1));
				} else if (buf_len <= s_len) {
					g_assert_cmpint (t_len, ==, 0);
					g_assert (t_buf == &buf[buf_len]);
					g_assert (!memcmp (buf, STR_ORIG, buf_len - 1));
					g_assert (buf[buf_len - 1] == '\0');
					g_assert (!memcmp (&buf[buf_len], &BUF_ORIG[buf_len], sizeof (buf) - buf_len));
				} else {
					g_assert_cmpint (t_len, >, 0);
					g_assert_cmpint (buf_len - t_len, ==, s_len);
					g_assert_cmpint (strlen (buf), ==, s_len);
					g_assert (t_buf == &buf[s_len]);
					g_assert (!memcmp (buf, STR_ORIG, s_len));
					g_assert (buf[s_len] == '\0');
					g_assert (!memcmp (&buf[s_len + 1], &BUF_ORIG[s_len + 1], sizeof (buf) - s_len - 1));
				}
				break;
			}
		}
	}
}

/*******************************************/

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	nmtst_init_with_logging (&argc, &argv, NULL, "ALL");

	g_test_add_func ("/general/nm_utils_strbuf_append", test_nm_utils_strbuf_append);

	g_test_add_func ("/general/nm_utils_ip6_address_clear_host_address", test_nm_utils_ip6_address_clear_host_address);
	g_test_add_func ("/general/nm_utils_log_connection_diff", test_nm_utils_log_connection_diff);

	g_test_add_func ("/general/connection-match/basic", test_connection_match_basic);
	g_test_add_func ("/general/connection-match/ip6-method", test_connection_match_ip6_method);
	g_test_add_func ("/general/connection-match/ip6-method-ignore", test_connection_match_ip6_method_ignore);
	g_test_add_func ("/general/connection-match/ip6-method-ignore-auto", test_connection_match_ip6_method_ignore_auto);
	g_test_add_func ("/general/connection-match/ip4-method", test_connection_match_ip4_method);
	g_test_add_func ("/general/connection-match/con-interface-name", test_connection_match_interface_name);
	g_test_add_func ("/general/connection-match/wired", test_connection_match_wired);
	g_test_add_func ("/general/connection-match/wired2", test_connection_match_wired2);
	g_test_add_func ("/general/connection-match/cloned_mac", test_connection_match_cloned_mac);
	g_test_add_func ("/general/connection-match/no-match-ip4-addr", test_connection_no_match_ip4_addr);
	g_test_add_func ("/general/connection-match/no-match-vlan", test_connection_no_match_vlan);

	g_test_add_func ("/general/connection-sort/autoconnect-priority", test_connection_sort_autoconnect_priority);

	g_test_add_func ("/general/nm_match_spec_interface_name", test_nm_match_spec_interface_name);
	g_test_add_func ("/general/nm_match_spec_match_config", test_nm_match_spec_match_config);

	return g_test_run ();
}

