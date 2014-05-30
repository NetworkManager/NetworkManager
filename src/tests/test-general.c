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

#include <glib.h>
#include <string.h>
#include <errno.h>
#include <netinet/ether.h>

#include "NetworkManagerUtils.h"
#include "nm-utils.h"


static void
test_nm_utils_ascii_str_to_int64_check (const char *str, guint base, gint64 min,
                                        gint64 max, gint64 fallback, int exp_errno,
                                        gint64 exp_val)
{
	gint64 v;

	errno = 1;
	v = nm_utils_ascii_str_to_int64 (str, base, min, max, fallback);
	g_assert_cmpint (errno, ==, exp_errno);
	g_assert_cmpint (v, ==, exp_val);
}

static void
test_nm_utils_ascii_str_to_int64_do (const char *str, guint base, gint64 min,
                                     gint64 max, gint64 fallback, int exp_errno,
                                     gint64 exp_val)
{
	const char *sign = "";
	const char *val;
	static const char *whitespaces[] = {
		"",
		" ",
		"\r\n\t",
		" \r\n\t ",
		" \r\n\t \t\r\n\t",
		NULL,
	};
	static const char *nulls[] = {
		"",
		"0",
		"00",
		"0000",
		"0000000000000000",
		"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		NULL,
	};
	const char **ws_pre, **ws_post, **null;
	int i;

	if (str == NULL || exp_errno != 0) {
		test_nm_utils_ascii_str_to_int64_check (str, base, min, max, fallback, exp_errno, exp_val);
		return;
	}

	if (strncmp (str, "-", 1) == 0)
		sign = "-";

	val = str + strlen (sign);

	for (ws_pre = whitespaces; *ws_pre; ws_pre++) {
		for (ws_post = whitespaces; *ws_post; ws_post++) {
			for (null = nulls; *null; null++) {
				for (i = 0; ; i++) {
					char *s;
					const char *str_base = "";

					if (base == 16) {
						if (i == 1)
							str_base = "0x";
						else if (i > 1)
							break;
					} else if (base == 8) {
						if (i == 1)
							str_base = "0";
						else if (i > 1)
							break;
					} else if (base == 0) {
						if (i > 0)
							break;
						/* with base==0, a leading zero would be interpreted as octal. Only test without *null */
						if ((*null)[0])
							break;
					} else {
						if (i > 0)
							break;
					}

					s = g_strdup_printf ("%s%s%s%s%s%s", *ws_pre, sign, str_base, *null, val, *ws_post);

					test_nm_utils_ascii_str_to_int64_check (s, base, min, max, fallback, exp_errno, exp_val);
					g_free (s);
				}
			}
		}
	}
}

static void
test_nm_utils_ascii_str_to_int64 (void)
{
	test_nm_utils_ascii_str_to_int64_do (NULL, 10, 0, 10000, -1, EINVAL, -1);
	test_nm_utils_ascii_str_to_int64_do ("", 10, 0, 10000, -1, EINVAL, -1);
	test_nm_utils_ascii_str_to_int64_do ("1x", 10, 0, 10000, -1, EINVAL, -1);
	test_nm_utils_ascii_str_to_int64_do ("4711", 10, 0, 10000, -1, 0, 4711);
	test_nm_utils_ascii_str_to_int64_do ("10000", 10, 0, 10000, -1, 0, 10000);
	test_nm_utils_ascii_str_to_int64_do ("10001", 10, 0, 10000, -1, ERANGE, -1);
	test_nm_utils_ascii_str_to_int64_do ("FF", 16, 0, 10000, -1, 0, 255);
	test_nm_utils_ascii_str_to_int64_do ("FF", 10, 0, 10000, -2, EINVAL, -2);
	test_nm_utils_ascii_str_to_int64_do ("9223372036854775807", 10, 0, G_MAXINT64, -2, 0, G_MAXINT64);
	test_nm_utils_ascii_str_to_int64_do ("7FFFFFFFFFFFFFFF", 16, 0, G_MAXINT64, -2, 0, G_MAXINT64);
	test_nm_utils_ascii_str_to_int64_do ("9223372036854775808", 10, 0, G_MAXINT64, -2, ERANGE, -2);
	test_nm_utils_ascii_str_to_int64_do ("-9223372036854775808", 10, G_MININT64, 0, -2, 0, G_MININT64);
	test_nm_utils_ascii_str_to_int64_do ("-9223372036854775808", 10, G_MININT64+1, 0, -2, ERANGE, -2);
	test_nm_utils_ascii_str_to_int64_do ("-9223372036854775809", 10, G_MININT64, 0, -2, ERANGE, -2);
	test_nm_utils_ascii_str_to_int64_do ("1.0", 10, 1, 1, -1, EINVAL, -1);
	test_nm_utils_ascii_str_to_int64_do ("1x0", 16, -10, 10, -100, EINVAL, -100);
	test_nm_utils_ascii_str_to_int64_do ("0", 16, -10, 10, -100, 0, 0);
	test_nm_utils_ascii_str_to_int64_do ("10001111", 2, -1000, 1000, -100000, 0, 0x8F);
	test_nm_utils_ascii_str_to_int64_do ("-10001111", 2, -1000, 1000, -100000, 0, -0x8F);
	test_nm_utils_ascii_str_to_int64_do ("1111111", 2, G_MININT64, G_MAXINT64, -1, 0, 0x7F);
	test_nm_utils_ascii_str_to_int64_do ("111111111111111", 2, G_MININT64, G_MAXINT64, -1, 0, 0x7FFF);
	test_nm_utils_ascii_str_to_int64_do ("11111111111111111111111111111111111111111111111", 2, G_MININT64, G_MAXINT64, -1, 0, 0x7FFFFFFFFFFF);
	test_nm_utils_ascii_str_to_int64_do ("111111111111111111111111111111111111111111111111111111111111111", 2, G_MININT64, G_MAXINT64, -1, 0, 0x7FFFFFFFFFFFFFFF);
	test_nm_utils_ascii_str_to_int64_do ("100000000000000000000000000000000000000000000000000000000000000", 2, G_MININT64, G_MAXINT64, -1, 0,  0x4000000000000000);
	test_nm_utils_ascii_str_to_int64_do ("1000000000000000000000000000000000000000000000000000000000000000", 2, G_MININT64, G_MAXINT64, -1, ERANGE, -1);
	test_nm_utils_ascii_str_to_int64_do ("-100000000000000000000000000000000000000000000000000000000000000", 2, G_MININT64, G_MAXINT64, -1, 0,  -0x4000000000000000);
	test_nm_utils_ascii_str_to_int64_do ("111111111111111111111111111111111111111111111111111111111111111",  2, G_MININT64, G_MAXINT64, -1, 0, 0x7FFFFFFFFFFFFFFF);
	test_nm_utils_ascii_str_to_int64_do ("-100000000000000000000000000000000000000000000000000000000000000",  2, G_MININT64, G_MAXINT64, -1, 0,  -0x4000000000000000);
	test_nm_utils_ascii_str_to_int64_do ("0x70",  10, G_MININT64, G_MAXINT64, -1, EINVAL, -1);
	test_nm_utils_ascii_str_to_int64_do ("4711",  0, G_MININT64, G_MAXINT64, -1, 0, 4711);
	test_nm_utils_ascii_str_to_int64_do ("04711",  0, G_MININT64, G_MAXINT64, -1, 0, 04711);
	test_nm_utils_ascii_str_to_int64_do ("0x4711",  0, G_MININT64, G_MAXINT64, -1, 0, 0x4711);
	test_nm_utils_ascii_str_to_int64_do ("080",  0, G_MININT64, G_MAXINT64, -1, EINVAL, -1);
	test_nm_utils_ascii_str_to_int64_do ("070",  0, G_MININT64, G_MAXINT64, -1, 0, 7*8);
	test_nm_utils_ascii_str_to_int64_do ("0x70",  0, G_MININT64, G_MAXINT64, -1, 0, 0x70);
}

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
_randomize_in6_addr (struct in6_addr *addr, GRand *rand)
{
	int i;

	for (i=0; i < 4; i++)
		((guint32 *)addr)[i] = g_rand_int (rand);
}

static void
test_nm_utils_ip6_address_clear_host_address (void)
{
	GRand *rand = g_rand_new ();
	int plen, i;

	g_rand_set_seed (rand, 0);

	for (plen = 0; plen <= 128; plen++) {
		for (i =0; i<50; i++) {
			struct in6_addr addr_src, addr_ref;
			struct in6_addr addr1, addr2;

			_randomize_in6_addr (&addr_src, rand);
			_randomize_in6_addr (&addr_ref, rand);
			_randomize_in6_addr (&addr1, rand);
			_randomize_in6_addr (&addr2, rand);

			addr1 = addr_src;
			ip6_address_clear_host_address_reference (&addr_ref, &addr1, plen);

			_randomize_in6_addr (&addr1, rand);
			_randomize_in6_addr (&addr2, rand);
			addr1 = addr_src;
			nm_utils_ip6_address_clear_host_address (&addr2, &addr1, plen);
			g_assert_cmpint (memcmp (&addr1, &addr_src, sizeof (struct in6_addr)), ==, 0);
			g_assert_cmpint (memcmp (&addr2, &addr_ref, sizeof (struct in6_addr)), ==, 0);

			/* test for self assignment/inplace update. */
			_randomize_in6_addr (&addr1, rand);
			addr1 = addr_src;
			nm_utils_ip6_address_clear_host_address (&addr1, &addr1, plen);
			g_assert_cmpint (memcmp (&addr1, &addr_ref, sizeof (struct in6_addr)), ==, 0);
		}
	}

	g_rand_free (rand);
}

/*******************************************/

static NMConnection *
_match_connection_new (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *uuid;

	connection = nm_connection_new ();

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

	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, (NMSetting *) s_ip4);
	g_object_set (G_OBJECT (s_ip4),
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NULL);

	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, (NMSetting *) s_ip6);
	g_object_set (G_OBJECT (s_ip6),
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO,
	              NULL);

	return connection;
}

static void
test_connection_match_basic (void)
{
	NMConnection *orig, *copy, *matched;
	GSList *connections = NULL;
	NMSettingIP4Config *s_ip4;

	orig = _match_connection_new ();
	copy = nm_connection_duplicate (orig);
	connections = g_slist_append (connections, copy);

	matched = nm_utils_match_connection (connections, orig, TRUE, NULL, NULL);
	g_assert (matched == copy);

	/* Now change a material property like IPv4 method and ensure matching fails */
	s_ip4 = nm_connection_get_setting_ip4_config (orig);
	g_assert (s_ip4);
	g_object_set (G_OBJECT (s_ip4),
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL,
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
	NMSettingIP6Config *s_ip6;

	orig = _match_connection_new ();
	copy = nm_connection_duplicate (orig);
	connections = g_slist_append (connections, copy);

	/* Check that if the generated connection is IPv6 method=link-local, and the
	 * candidate is both method=auto and may-faily=true, that the candidate is
	 * matched.
	 */
	s_ip6 = nm_connection_get_setting_ip6_config (orig);
	g_assert (s_ip6);
	g_object_set (G_OBJECT (s_ip6),
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL,
	              NULL);

	s_ip6 = nm_connection_get_setting_ip6_config (copy);
	g_assert (s_ip6);
	g_object_set (G_OBJECT (s_ip6),
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO,
	              NM_SETTING_IP6_CONFIG_MAY_FAIL, TRUE,
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
	NMSettingIP6Config *s_ip6;

	orig = _match_connection_new ();
	copy = nm_connection_duplicate (orig);
	connections = g_slist_append (connections, copy);

	/* Check that if the generated connection is IPv6 method=link-local, and the
	 * candidate is method=ignore, that the candidate is matched.
	 */
	s_ip6 = nm_connection_get_setting_ip6_config (orig);
	g_assert (s_ip6);
	g_object_set (G_OBJECT (s_ip6),
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL,
	              NULL);

	s_ip6 = nm_connection_get_setting_ip6_config (copy);
	g_assert (s_ip6);
	g_object_set (G_OBJECT (s_ip6),
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
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
	NMSettingIP6Config *s_ip6;

	orig = _match_connection_new ();
	copy = nm_connection_duplicate (orig);
	connections = g_slist_append (connections, copy);

	/* Check that if the generated connection is IPv6 method=auto, and the
	 * candidate is method=ignore, that the candidate is matched.
	 */
	s_ip6 = nm_connection_get_setting_ip6_config (orig);
	g_assert (s_ip6);
	g_object_set (G_OBJECT (s_ip6),
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO,
	              NULL);

	s_ip6 = nm_connection_get_setting_ip6_config (copy);
	g_assert (s_ip6);
	g_object_set (G_OBJECT (s_ip6),
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
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
	NMSettingIP4Config *s_ip4;

	orig = _match_connection_new ();
	copy = nm_connection_duplicate (orig);
	connections = g_slist_append (connections, copy);

	/* Check that if the generated connection is IPv4 method=disabled, and the
	 * candidate is both method=auto and may-faily=true, and the device has no
	 * carrier that the candidate is matched.
	 */
	s_ip4 = nm_connection_get_setting_ip4_config (orig);
	g_assert (s_ip4);
	g_object_set (G_OBJECT (s_ip4),
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_DISABLED,
	              NULL);

	s_ip4 = nm_connection_get_setting_ip4_config (copy);
	g_assert (s_ip4);
	g_object_set (G_OBJECT (s_ip4),
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NM_SETTING_IP4_CONFIG_MAY_FAIL, TRUE,
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
	copy = nm_connection_duplicate (orig);
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
	GPtrArray *subchan_arr = g_ptr_array_sized_new (3);
	GByteArray *mac;

	g_ptr_array_add (subchan_arr, "0.0.8000");
	g_ptr_array_add (subchan_arr, "0.0.8001");
	g_ptr_array_add (subchan_arr, "0.0.8002");

	orig = _match_connection_new ();
	copy = nm_connection_duplicate (orig);
	connections = g_slist_append (connections, copy);

	mac = nm_utils_hwaddr_atoba ("52:54:00:ab:db:23", ARPHRD_ETHER);
	s_wired = nm_connection_get_setting_wired (orig);
	g_assert (s_wired);
	g_object_set (G_OBJECT (s_wired),
	              NM_SETTING_WIRED_PORT, "tp",           /* port is not compared */
	              NM_SETTING_WIRED_MAC_ADDRESS, mac,     /* we allow MAC address just in one connection */
	              NM_SETTING_WIRED_S390_SUBCHANNELS, subchan_arr,
	              NM_SETTING_WIRED_S390_NETTYPE, "qeth",
	              NULL);
	g_byte_array_free (mac, TRUE);

	s_wired = nm_connection_get_setting_wired (copy);
	g_assert (s_wired);
	g_object_set (G_OBJECT (s_wired),
	              NM_SETTING_WIRED_S390_SUBCHANNELS, subchan_arr,
	              NM_SETTING_WIRED_S390_NETTYPE, "qeth",
	              NULL);

	matched = nm_utils_match_connection (connections, orig, TRUE, NULL, NULL);
	g_assert (matched == copy);

	g_slist_free (connections);
	g_ptr_array_free (subchan_arr, TRUE);
	g_object_unref (orig);
	g_object_unref (copy);
}

static void
test_connection_no_match_ip4_addr (void)
{
	NMConnection *orig, *copy, *matched;
	GSList *connections = NULL;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	NMIP4Address *nm_addr;
	guint32 addr, gw;

	orig = _match_connection_new ();
	copy = nm_connection_duplicate (orig);
	connections = g_slist_append (connections, copy);

	/* Check that if we have two differences, ipv6.method (exception we allow) and
	 * ipv4.addresses (which is fatal), we don't match the connections.
	 */
	s_ip6 = nm_connection_get_setting_ip6_config (orig);
	g_assert (s_ip6);
	g_object_set (G_OBJECT (s_ip6),
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL,
	              NULL);

	s_ip6 = nm_connection_get_setting_ip6_config (copy);
	g_assert (s_ip6);
	g_object_set (G_OBJECT (s_ip6),
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NULL);


	s_ip4 = nm_connection_get_setting_ip4_config (orig);
	g_assert (s_ip4);
	g_object_set (G_OBJECT (s_ip4),
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	              NULL);
	nm_addr = nm_ip4_address_new ();
	inet_pton (AF_INET, "1.1.1.4", &addr);
	inet_pton (AF_INET, "1.1.1.254", &gw);
	nm_ip4_address_set_address (nm_addr, addr);
	nm_ip4_address_set_prefix (nm_addr, 24);
	nm_ip4_address_set_gateway (nm_addr, gw);
	nm_setting_ip4_config_add_address (s_ip4, nm_addr);
	nm_ip4_address_unref (nm_addr);

	s_ip4 = nm_connection_get_setting_ip4_config (copy);
	g_assert (s_ip4);
	g_object_set (G_OBJECT (s_ip4),
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	              NULL);
	nm_addr = nm_ip4_address_new ();
	inet_pton (AF_INET, "2.2.2.4", &addr);
	inet_pton (AF_INET, "2.2.2.254", &gw);
	nm_ip4_address_set_address (nm_addr, addr);
	nm_ip4_address_set_prefix (nm_addr, 24);
	nm_ip4_address_set_gateway (nm_addr, gw);
	nm_setting_ip4_config_add_address (s_ip4, nm_addr);
	nm_ip4_address_unref (nm_addr);

	matched = nm_utils_match_connection (connections, orig, TRUE, NULL, NULL);
	g_assert (matched != copy);

	g_slist_free (connections);
	g_object_unref (orig);
	g_object_unref (copy);
}

/*******************************************/

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

	g_test_add_func ("/general/nm_utils_ascii_str_to_int64", test_nm_utils_ascii_str_to_int64);
	g_test_add_func ("/general/nm_utils_ip6_address_clear_host_address", test_nm_utils_ip6_address_clear_host_address);

	g_test_add_func ("/general/connection-match/basic", test_connection_match_basic);
	g_test_add_func ("/general/connection-match/ip6-method", test_connection_match_ip6_method);
	g_test_add_func ("/general/connection-match/ip6-method-ignore", test_connection_match_ip6_method_ignore);
	g_test_add_func ("/general/connection-match/ip6-method-ignore-auto", test_connection_match_ip6_method_ignore_auto);
	g_test_add_func ("/general/connection-match/ip4-method", test_connection_match_ip4_method);
	g_test_add_func ("/general/connection-match/con-interface-name", test_connection_match_interface_name);
	g_test_add_func ("/general/connection-match/wired", test_connection_match_wired);
	g_test_add_func ("/general/connection-match/no-match-ip4-addr", test_connection_no_match_ip4_addr);

	return g_test_run ();
}

