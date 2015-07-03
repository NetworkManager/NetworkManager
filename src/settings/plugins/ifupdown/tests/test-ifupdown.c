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
 * Copyright (C) 2010 Red Hat, Inc.
 *
 */

#include "config.h"

#include <glib.h>
#include <string.h>

#include "nm-core-internal.h"
#include "nm-logging.h"
#include "interface_parser.h"
#include "parser.h"
#include "nm-logging.h"

#include "nm-test-utils.h"

typedef struct {
	char *key;
	char *data;
} ExpectedKey;

typedef struct {
	char *type;
	char *name;
	GSList *keys;
} ExpectedBlock;

typedef struct {
	GSList *blocks;
} Expected;

static ExpectedKey *
expected_key_new (const char *key, const char *data)
{
	ExpectedKey *k;

	k = g_malloc0 (sizeof (ExpectedKey));
	k->key = g_strdup (key);
	k->data = g_strdup (data);
	return k;
}

static void
expected_key_free (gpointer ptr)
{
	ExpectedKey *k = ptr;

	g_assert (k);
	g_free (k->key);
	g_free (k->data);
	memset (k, 0, sizeof (ExpectedKey));
	g_free (k);
}

static ExpectedBlock *
expected_block_new (const char *type, const char *name)
{
	ExpectedBlock *b;

	g_assert (type);
	g_assert (name);
	b = g_malloc0 (sizeof (ExpectedBlock));
	g_assert (b);
	b->type = g_strdup (type);
	b->name = g_strdup (name);
	return b;
}

static void
expected_block_free (gpointer ptr)
{
	ExpectedBlock *b = ptr;

	g_assert (b);
	g_slist_free_full (b->keys, expected_key_free);
	g_free (b->type);
	g_free (b->name);
	memset (b, 0, sizeof (ExpectedBlock));
	g_free (b);
}

static void
expected_block_add_key (ExpectedBlock *b, ExpectedKey *k)
{
	g_assert (b);
	g_assert (k);
	b->keys = g_slist_append (b->keys, k);
}

static Expected *
expected_new (void)
{
	return g_malloc0 (sizeof (Expected));
}

static void
expected_add_block (Expected *e, ExpectedBlock *b)
{
	g_assert (e);
	g_assert (b);
	e->blocks = g_slist_append (e->blocks, b);
}

static void
expected_free (Expected *e)
{
	g_assert (e);
	g_slist_free_full (e->blocks, expected_block_free);
	memset (e, 0, sizeof (Expected));
	g_free (e);
}

static void
compare_expected_to_ifparser (Expected *e)
{
	if_block *n;
	GSList *biter, *kiter;

	g_assert_cmpint (g_slist_length (e->blocks), ==, ifparser_get_num_blocks ());

	for (n = ifparser_getfirst (), biter = e->blocks;
	     n && biter;
	     n = n->next, biter = g_slist_next (biter)) {
		if_data *m;
		ExpectedBlock *b = biter->data;

		g_assert (b->type && n->type);
		g_assert_cmpstr (b->type, ==, n->type);
		g_assert (b->name && n->name);
		g_assert_cmpstr (b->name, ==, n->name);

		g_assert_cmpint (g_slist_length (b->keys), ==, ifparser_get_num_info (n));

		for (m = n->info, kiter = b->keys;
		     m && kiter;
		     m = m->next, kiter = g_slist_next (kiter)) {
			ExpectedKey *k = kiter->data;

			g_assert (k->key && m->key);
			g_assert_cmpstr (k->key, ==, m->key);
			g_assert (k->data && m->data);
			g_assert_cmpstr (k->data, ==, m->data);
		}
	}
}

static void
dump_blocks (void)
{
	if_block *n;

	g_message ("\n***************************************************");
	for (n = ifparser_getfirst (); n != NULL; n = n->next) {
		if_data *m;

		// each block start with its type & name 
		// (single quotes used to show typ & name baoundaries)
		g_print("'%s' '%s'\n", n->type, n->name);

		// each key-value pair within a block is indented & separated by a tab
		// (single quotes used to show typ & name baoundaries)
		for (m = n->info; m != NULL; m = m->next)
			   g_print("\t'%s'\t'%s'\n", m->key, m->data);

		// blocks are separated by an empty line
		g_print("\n");
	}
	g_message ("##################################################\n");
}

static void
init_ifparser_with_file (const char *path, const char *file)
{
	char *tmp;

	tmp = g_strdup_printf ("%s/%s", path, file);
	ifparser_init (tmp, 1);
	g_free (tmp);
}

static void
test1_ignore_line_before_first_block (const char *path)
{
	Expected *e;
	ExpectedBlock *b;

	e = expected_new ();
	b = expected_block_new ("auto", "eth0");
	expected_add_block (e, b);
	b = expected_block_new ("iface", "eth0");
	expected_add_block (e, b);
	expected_block_add_key (b, expected_key_new ("inet", "dhcp"));

	init_ifparser_with_file (path, "test1");
	compare_expected_to_ifparser (e);

	ifparser_destroy ();
	expected_free (e);
}

static void
test2_wrapped_line (const char *path)
{
	Expected *e;
	ExpectedBlock *b;

	e = expected_new ();
	b = expected_block_new ("auto", "lo");
	expected_add_block (e, b);

	init_ifparser_with_file (path, "test2");
	compare_expected_to_ifparser (e);

	ifparser_destroy ();
	expected_free (e);
}

static void
test3_wrapped_multiline_multiarg (const char *path)
{
	Expected *e;
	ExpectedBlock *b;

	e = expected_new ();
	b = expected_block_new ("allow-hotplug", "eth0");
	expected_add_block (e, b);
	b = expected_block_new ("allow-hotplug", "wlan0");
	expected_add_block (e, b);
	b = expected_block_new ("allow-hotplug", "bnep0");
	expected_add_block (e, b);

	init_ifparser_with_file (path, "test3");
	compare_expected_to_ifparser (e);

	ifparser_destroy ();
	expected_free (e);
}

static void
test4_allow_auto_is_auto (const char *path)
{
	Expected *e;
	ExpectedBlock *b;

	e = expected_new ();
	b = expected_block_new ("auto", "eth0");
	expected_add_block (e, b);

	init_ifparser_with_file (path, "test4");
	compare_expected_to_ifparser (e);

	ifparser_destroy ();
	expected_free (e);
}

static void
test5_allow_auto_multiarg (const char *path)
{
	Expected *e;
	ExpectedBlock *b;

	e = expected_new ();
	b = expected_block_new ("allow-hotplug", "eth0");
	expected_add_block (e, b);
	b = expected_block_new ("allow-hotplug", "wlan0");
	expected_add_block (e, b);

	init_ifparser_with_file (path, "test5");
	compare_expected_to_ifparser (e);

	ifparser_destroy ();
	expected_free (e);
}

static void
test6_mixed_whitespace (const char *path)
{
	Expected *e;
	ExpectedBlock *b;

	e = expected_new ();
	b = expected_block_new ("iface", "lo");
	expected_block_add_key (b, expected_key_new ("inet", "loopback"));
	expected_add_block (e, b);

	init_ifparser_with_file (path, "test6");
	compare_expected_to_ifparser (e);

	ifparser_destroy ();
	expected_free (e);
}

static void
test7_long_line (const char *path)
{
	init_ifparser_with_file (path, "test7");
	g_assert_cmpint (ifparser_get_num_blocks (), ==, 0);
	ifparser_destroy ();
}

static void
test8_long_line_wrapped (const char *path)
{
	init_ifparser_with_file (path, "test8");
	g_assert_cmpint (ifparser_get_num_blocks (), ==, 0);
	ifparser_destroy ();
}

static void
test9_wrapped_lines_in_block (const char *path)
{
	Expected *e;
	ExpectedBlock *b;

	e = expected_new ();
	b = expected_block_new ("iface", "eth0");
	expected_add_block (e, b);
	expected_block_add_key (b, expected_key_new ("inet", "static"));
	expected_block_add_key (b, expected_key_new ("address", "10.250.2.3"));
	expected_block_add_key (b, expected_key_new ("netmask", "255.255.255.192"));
	expected_block_add_key (b, expected_key_new ("broadcast", "10.250.2.63"));
	expected_block_add_key (b, expected_key_new ("gateway", "10.250.2.50"));

	init_ifparser_with_file (path, "test9");
	compare_expected_to_ifparser (e);

	ifparser_destroy ();
	expected_free (e);
}

static void
test11_complex_wrap (const char *path)
{
	Expected *e;
	ExpectedBlock *b;

	e = expected_new ();
	b = expected_block_new ("iface", "pppoe");
	expected_add_block (e, b);
	expected_block_add_key (b, expected_key_new ("inet", "manual"));
	expected_block_add_key (b, expected_key_new ("pre-up", "/sbin/ifconfig eth0 up"));

	init_ifparser_with_file (path, "test11");
	compare_expected_to_ifparser (e);

	ifparser_destroy ();
	expected_free (e);
}

static void
test12_complex_wrap_split_word (const char *path)
{
	Expected *e;
	ExpectedBlock *b;

	e = expected_new ();
	b = expected_block_new ("iface", "pppoe");
	expected_add_block (e, b);
	expected_block_add_key (b, expected_key_new ("inet", "manual"));
	expected_block_add_key (b, expected_key_new ("up", "ifup ppp0=dsl"));

	init_ifparser_with_file (path, "test12");
	compare_expected_to_ifparser (e);

	ifparser_destroy ();
	expected_free (e);
}

static void
test13_more_mixed_whitespace (const char *path)
{
	Expected *e;
	ExpectedBlock *b;

	e = expected_new ();
	b = expected_block_new ("iface", "dsl");
	expected_block_add_key (b, expected_key_new ("inet", "ppp"));
	expected_add_block (e, b);

	init_ifparser_with_file (path, "test13");
	compare_expected_to_ifparser (e);

	ifparser_destroy ();
	expected_free (e);
}

static void
test14_mixed_whitespace_block_start (const char *path)
{
	Expected *e;
	ExpectedBlock *b;

	e = expected_new ();
	b = expected_block_new ("iface", "wlan0");
	expected_block_add_key (b, expected_key_new ("inet", "manual"));
	expected_add_block (e, b);
	b = expected_block_new ("iface", "wlan-adpm");
	expected_block_add_key (b, expected_key_new ("inet", "dhcp"));
	expected_add_block (e, b);
	b = expected_block_new ("iface", "wlan-default");
	expected_block_add_key (b, expected_key_new ("inet", "dhcp"));
	expected_add_block (e, b);

	init_ifparser_with_file (path, "test14");
	compare_expected_to_ifparser (e);

	ifparser_destroy ();
	expected_free (e);
}

static void
test15_trailing_space (const char *path)
{
	Expected *e;
	ExpectedBlock *b;

	e = expected_new ();
	b = expected_block_new ("iface", "bnep0");
	expected_block_add_key (b, expected_key_new ("inet", "static"));
	expected_add_block (e, b);

	init_ifparser_with_file (path, "test15");
	compare_expected_to_ifparser (e);

	ifparser_destroy ();
	expected_free (e);
}

static void
test16_missing_newline (const char *path)
{
	Expected *e;

	e = expected_new ();
	expected_add_block (e, expected_block_new ("mapping", "eth0"));

	init_ifparser_with_file (path, "test16");
	compare_expected_to_ifparser (e);

	ifparser_destroy ();
	expected_free (e);
}
static void
test17_read_static_ipv4 (const char *path)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip4;
	NMSettingWired *s_wired;
	char *unmanaged = NULL;
	GError *error = NULL;
	const char* tmp;
	const char *expected_id = "Ifupdown (eth0)";
	const char *expected_search1 = "example.com";
	const char *expected_search2 = "foo.example.com";
	NMIPAddress *ip4_addr;
#define TEST17_NAME "wired-static-verify-ip4"
	if_block *block = NULL;

	const char* file = "test17-" TEST17_NAME;

	init_ifparser_with_file (path, file);
	block = ifparser_getfirst ();
	connection = nm_simple_connection_new();
	ifupdown_update_connection_from_if_block(connection, block, &error);

	ASSERT (connection != NULL,
			TEST17_NAME, "failed to read %s: %s", file, error->message);

	ASSERT (nm_connection_verify (connection, &error),
			TEST17_NAME, "failed to verify %s: %s", file, error->message);

	ASSERT (unmanaged == NULL,
			TEST17_NAME, "failed to verify %s: unexpected unmanaged value", file);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
			TEST17_NAME, "failed to verify %s: missing %s setting",
			file,
			NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
			TEST17_NAME, "failed to verify %s: missing %s / %s key",
			file,
			NM_SETTING_CONNECTION_SETTING_NAME,
			NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
			TEST17_NAME, "failed to verify %s: unexpected %s / %s key value: %s",
			file,
			NM_SETTING_CONNECTION_SETTING_NAME,
			NM_SETTING_CONNECTION_ID, tmp);

	/* ===== WIRED SETTING ===== */

	s_wired = nm_connection_get_setting_wired (connection);
	ASSERT (s_wired != NULL,
			TEST17_NAME, "failed to verify %s: missing %s setting",
			file,
			NM_SETTING_WIRED_SETTING_NAME);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	ASSERT (s_ip4 != NULL,
			TEST17_NAME, "failed to verify %s: missing %s setting",
			file,
			NM_SETTING_IP4_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_MANUAL) == 0,
			TEST17_NAME, "failed to verify %s: unexpected %s / %s key value",
			file,
			NM_SETTING_IP4_CONFIG_SETTING_NAME,
			NM_SETTING_IP_CONFIG_METHOD);

	/* IP addresses */
	ASSERT (nm_setting_ip_config_get_num_addresses (s_ip4) == 1,
			TEST17_NAME, "failed to verify %s: unexpected %s / %s key value",
			file,
			NM_SETTING_IP4_CONFIG_SETTING_NAME,
			NM_SETTING_IP_CONFIG_ADDRESSES);

	ip4_addr = nm_setting_ip_config_get_address (s_ip4, 0);
	g_assert (ip4_addr != NULL);
	g_assert_cmpstr (nm_ip_address_get_address (ip4_addr), ==, "10.0.0.3");
	g_assert_cmpint (nm_ip_address_get_prefix (ip4_addr), ==, 8);

	/* DNS Addresses */
	ASSERT (nm_setting_ip_config_get_num_dns (s_ip4) == 2,
			TEST17_NAME, "failed to verify %s: unexpected %s / %s key value",
			file,
			NM_SETTING_IP4_CONFIG_SETTING_NAME,
			NM_SETTING_IP_CONFIG_DNS);

	ASSERT (!strcmp (nm_setting_ip_config_get_dns (s_ip4, 0), "10.0.0.1"),
			TEST17_NAME, "failed to verify %s: unexpected %s / %s key value #1",
			file,
			NM_SETTING_IP4_CONFIG_SETTING_NAME,
			NM_SETTING_IP_CONFIG_DNS);

	ASSERT (!strcmp (nm_setting_ip_config_get_dns (s_ip4, 1), "10.0.0.2"),
			TEST17_NAME, "failed to verify %s: unexpected %s / %s key value #2",
			file,
			NM_SETTING_IP4_CONFIG_SETTING_NAME,
			NM_SETTING_IP_CONFIG_DNS);

	ASSERT (nm_setting_ip_config_get_num_addresses (s_ip4) == 1,
			TEST17_NAME, "failed to verify %s: unexpected %s / %s key value",
			file,
			NM_SETTING_IP4_CONFIG_SETTING_NAME,
			NM_SETTING_IP_CONFIG_DNS);

	/* DNS search domains */
	ASSERT (nm_setting_ip_config_get_num_dns_searches (s_ip4) == 2,
			TEST17_NAME, "failed to verify %s: unexpected %s / %s key value",
			file,
			NM_SETTING_IP4_CONFIG_SETTING_NAME,
			NM_SETTING_IP_CONFIG_DNS);

	tmp = nm_setting_ip_config_get_dns_search (s_ip4, 0);
	ASSERT (tmp != NULL,
			TEST17_NAME, "failed to verify %s: missing %s / %s key",
			file,
			NM_SETTING_IP4_CONFIG_SETTING_NAME,
			NM_SETTING_IP_CONFIG_DNS_SEARCH);
	ASSERT (strcmp (tmp, expected_search1) == 0,
			TEST17_NAME, "failed to verify %s: unexpected %s / %s key value",
			file,
			NM_SETTING_IP4_CONFIG_SETTING_NAME,
			NM_SETTING_IP_CONFIG_DNS_SEARCH);

	tmp = nm_setting_ip_config_get_dns_search (s_ip4, 1);
	ASSERT (tmp != NULL,
			TEST17_NAME, "failed to verify %s: missing %s / %s key",
			file,
			NM_SETTING_IP4_CONFIG_SETTING_NAME,
			NM_SETTING_IP_CONFIG_DNS_SEARCH);

	ASSERT (strcmp (tmp, expected_search2) == 0,
			TEST17_NAME, "failed to verify %s: unexpected %s / %s key value",
			file,
			NM_SETTING_IP4_CONFIG_SETTING_NAME,
			NM_SETTING_IP_CONFIG_DNS_SEARCH);

	g_object_unref (connection);
}

static void
test18_read_static_ipv6 (const char *path)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip6;
	NMSettingWired *s_wired;
	char *unmanaged = NULL;
	GError *error = NULL;
	const char* tmp;
	const char *expected_id = "Ifupdown (myip6tunnel)";
	const char *expected_search1 = "example.com";
	const char *expected_search2 = "foo.example.com";
	NMIPAddress *ip6_addr;
	if_block *block = NULL;
#define TEST18_NAME "wired-static-verify-ip6"
	const char* file = "test18-" TEST18_NAME;

	init_ifparser_with_file (path, file);
	block = ifparser_getfirst ();
	connection = nm_simple_connection_new();
	ifupdown_update_connection_from_if_block(connection, block, &error);

	ASSERT (connection != NULL,
			TEST18_NAME
			"failed to read %s: %s", file, error->message);

	ASSERT (nm_connection_verify (connection, &error),
			TEST18_NAME,
			"failed to verify %s: %s", file, error->message);

	ASSERT (unmanaged == NULL,
			TEST18_NAME,
			"failed to verify %s: unexpected unmanaged value", file);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
			TEST18_NAME, "failed to verify %s: missing %s setting",
			file,
			NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
			TEST18_NAME,
			"failed to verify %s: missing %s / %s key",
			file,
			NM_SETTING_CONNECTION_SETTING_NAME,
			NM_SETTING_CONNECTION_ID);

	ASSERT (strcmp (tmp, expected_id) == 0,
			TEST18_NAME,
			"failed to verify %s: unexpected %s / %s key value",
			file,
			NM_SETTING_CONNECTION_SETTING_NAME,
			NM_SETTING_CONNECTION_ID);

	/* ===== WIRED SETTING ===== */

	s_wired = nm_connection_get_setting_wired (connection);
	ASSERT (s_wired != NULL,
			TEST18_NAME, "failed to verify %s: missing %s setting",
			file,
			NM_SETTING_WIRED_SETTING_NAME);

	/* ===== IPv6 SETTING ===== */

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	ASSERT (s_ip6 != NULL,
			TEST18_NAME,
			"failed to verify %s: missing %s setting",
			file,
			NM_SETTING_IP6_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip_config_get_method (s_ip6);
	ASSERT (strcmp (tmp, NM_SETTING_IP6_CONFIG_METHOD_MANUAL) == 0,
			TEST18_NAME,
			"failed to verify %s: unexpected %s / %s key value",
			file,
			NM_SETTING_IP6_CONFIG_SETTING_NAME,
			NM_SETTING_IP_CONFIG_METHOD);

	/* IP addresses */
	ASSERT (nm_setting_ip_config_get_num_addresses (s_ip6) == 1,
			TEST18_NAME,
			"failed to verify %s: unexpected number of %s / %s",
			file,
			NM_SETTING_IP6_CONFIG_SETTING_NAME,
			NM_SETTING_IP_CONFIG_ADDRESSES);

	ip6_addr = nm_setting_ip_config_get_address (s_ip6, 0);
	g_assert (ip6_addr != NULL);
	g_assert_cmpstr (nm_ip_address_get_address (ip6_addr), ==, "fc00::1");
	g_assert_cmpint (nm_ip_address_get_prefix (ip6_addr), ==, 64);

	/* DNS Addresses */
	ASSERT (nm_setting_ip_config_get_num_dns (s_ip6) == 2,
			TEST18_NAME,
			"failed to verify %s: unexpected number of %s / %s values",
			file,
			NM_SETTING_IP6_CONFIG_SETTING_NAME,
			NM_SETTING_IP_CONFIG_DNS);

	ASSERT (!strcmp (nm_setting_ip_config_get_dns (s_ip6, 0), "fc00::2"),
			TEST18_NAME,
			"failed to verify %s: unexpected %s / %s #1",
			file,
			NM_SETTING_IP6_CONFIG_SETTING_NAME,
			NM_SETTING_IP_CONFIG_DNS);

	ASSERT (!strcmp (nm_setting_ip_config_get_dns (s_ip6, 1), "fc00::3"),
			TEST18_NAME, "failed to verify %s: unexpected %s / %s #2",
			file,
			NM_SETTING_IP6_CONFIG_SETTING_NAME,
			NM_SETTING_IP_CONFIG_DNS);

	/* DNS search domains */
	ASSERT (nm_setting_ip_config_get_num_dns_searches (s_ip6) == 2,
			TEST18_NAME,
			"failed to verify %s: unexpected number of %s / %s values",
			file,
			NM_SETTING_IP6_CONFIG_SETTING_NAME,
			NM_SETTING_IP_CONFIG_DNS_SEARCH);

	tmp = nm_setting_ip_config_get_dns_search (s_ip6, 0);
	ASSERT (tmp != NULL,
			"wired-ipv6-manual-verify-ip6",
			"failed to verify %s: missing %s / %s #1",
			file,
			NM_SETTING_IP6_CONFIG_SETTING_NAME,
			NM_SETTING_IP_CONFIG_DNS_SEARCH);

	ASSERT (strcmp (tmp, expected_search1) == 0,
			"wired-ipv6-manual-verify-ip6",
			"failed to verify %s: unexpected %s / %s #1",
			file,
			NM_SETTING_IP6_CONFIG_SETTING_NAME,
			NM_SETTING_IP_CONFIG_DNS_SEARCH);

	tmp = nm_setting_ip_config_get_dns_search (s_ip6, 1);
	ASSERT (tmp != NULL,
			TEST18_NAME,
			"failed to verify %s: missing %s / %s #2",
			file,
			NM_SETTING_IP6_CONFIG_SETTING_NAME,
			NM_SETTING_IP_CONFIG_DNS_SEARCH);

	ASSERT (strcmp (tmp, expected_search2) == 0,
			TEST18_NAME,
			"failed to verify %s: unexpected %s / %s #2",
			file,
			NM_SETTING_IP6_CONFIG_SETTING_NAME,
			NM_SETTING_IP_CONFIG_DNS_SEARCH);

	g_free (unmanaged);
	g_object_unref (connection);
}

static void
test19_read_static_ipv4_plen (const char *path)
{
	NMConnection *connection;
	NMSettingIPConfig *s_ip4;
	char *unmanaged = NULL;
	GError *error = NULL;
	NMIPAddress *ip4_addr;
#define TEST19_NAME "wired-static-verify-ip4-plen"
	if_block *block = NULL;

	const char* file = "test19-" TEST19_NAME;

	init_ifparser_with_file (path, file);
	block = ifparser_getfirst ();
	connection = nm_simple_connection_new();
	ifupdown_update_connection_from_if_block(connection, block, &error);

	ASSERT (connection != NULL,
			TEST19_NAME, "failed to read %s: %s", file, error->message);

	ASSERT (nm_connection_verify (connection, &error),
			TEST19_NAME, "failed to verify %s: %s", file, error->message);

	ASSERT (unmanaged == NULL,
			TEST19_NAME, "failed to verify %s: unexpected unmanaged value", file);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	ASSERT (s_ip4 != NULL,
			TEST19_NAME, "failed to verify %s: missing %s setting",
			file,
			NM_SETTING_IP4_CONFIG_SETTING_NAME);

	/* IP addresses */
	ASSERT (nm_setting_ip_config_get_num_addresses (s_ip4) == 1,
			TEST19_NAME, "failed to verify %s: unexpected %s / %s key value",
			file,
			NM_SETTING_IP4_CONFIG_SETTING_NAME,
			NM_SETTING_IP_CONFIG_ADDRESSES);

	ip4_addr = nm_setting_ip_config_get_address (s_ip4, 0);
	g_assert (ip4_addr != NULL);
	g_assert_cmpstr (nm_ip_address_get_address (ip4_addr), ==, "10.0.0.3");
	g_assert_cmpint (nm_ip_address_get_prefix (ip4_addr), ==, 8);

	g_object_unref (connection);
}

static void
test20_source_stanza (const char *path)
{
	Expected *e;
	ExpectedBlock *b;

	e = expected_new ();

	b = expected_block_new ("auto", "eth0");
	expected_add_block (e, b);
	b = expected_block_new ("iface", "eth0");
	expected_add_block (e, b);
	expected_block_add_key (b, expected_key_new ("inet", "dhcp"));

	b = expected_block_new ("auto", "eth1");
	expected_add_block (e, b);
	b = expected_block_new ("iface", "eth1");
	expected_add_block (e, b);
	expected_block_add_key (b, expected_key_new ("inet", "dhcp"));

	init_ifparser_with_file (path, "test20-source-stanza");
	compare_expected_to_ifparser (e);

	ifparser_destroy ();
	expected_free (e);
}

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	nmtst_init_assert_logging (&argc, &argv, "WARN", "DEFAULT");

	if (0)
		dump_blocks ();

	g_test_add_data_func ("/ifupdate/ignore_line_before_first_block", TEST_ENI_DIR,
	                      (GTestDataFunc) test1_ignore_line_before_first_block);
	g_test_add_data_func ("/ifupdate/wrapped_line", TEST_ENI_DIR,
	                      (GTestDataFunc) test2_wrapped_line);
	g_test_add_data_func ("/ifupdate/wrapped_multiline_multiarg", TEST_ENI_DIR,
	                      (GTestDataFunc) test3_wrapped_multiline_multiarg);
	g_test_add_data_func ("/ifupdate/allow_auto_is_auto", TEST_ENI_DIR,
	                      (GTestDataFunc) test4_allow_auto_is_auto);
	g_test_add_data_func ("/ifupdate/allow_auto_multiarg", TEST_ENI_DIR,
	                      (GTestDataFunc) test5_allow_auto_multiarg);
	g_test_add_data_func ("/ifupdate/mixed_whitespace", TEST_ENI_DIR,
	                      (GTestDataFunc) test6_mixed_whitespace);
	g_test_add_data_func ("/ifupdate/long_line", TEST_ENI_DIR,
	                      (GTestDataFunc) test7_long_line);
	g_test_add_data_func ("/ifupdate/long_line_wrapped", TEST_ENI_DIR,
	                      (GTestDataFunc) test8_long_line_wrapped);
	g_test_add_data_func ("/ifupdate/wrapped_lines_in_block", TEST_ENI_DIR,
	                      (GTestDataFunc) test9_wrapped_lines_in_block);
	g_test_add_data_func ("/ifupdate/complex_wrap", TEST_ENI_DIR,
	                      (GTestDataFunc) test11_complex_wrap);
	g_test_add_data_func ("/ifupdate/complex_wrap_split_word", TEST_ENI_DIR,
	                      (GTestDataFunc) test12_complex_wrap_split_word);
	g_test_add_data_func ("/ifupdate/more_mixed_whitespace", TEST_ENI_DIR,
	                      (GTestDataFunc) test13_more_mixed_whitespace);
	g_test_add_data_func ("/ifupdate/mixed_whitespace_block_start", TEST_ENI_DIR,
	                      (GTestDataFunc) test14_mixed_whitespace_block_start);
	g_test_add_data_func ("/ifupdate/trailing_space", TEST_ENI_DIR,
	                      (GTestDataFunc) test15_trailing_space);
	g_test_add_data_func ("/ifupdate/missing_newline", TEST_ENI_DIR,
	                      (GTestDataFunc) test16_missing_newline);
	g_test_add_data_func ("/ifupdate/read_static_ipv4", TEST_ENI_DIR,
	                      (GTestDataFunc) test17_read_static_ipv4);
	g_test_add_data_func ("/ifupdate/read_static_ipv6", TEST_ENI_DIR,
	                      (GTestDataFunc) test18_read_static_ipv6);
	g_test_add_data_func ("/ifupdate/read_static_ipv4_plen", TEST_ENI_DIR,
	                      (GTestDataFunc) test19_read_static_ipv4_plen);
	g_test_add_data_func ("/ifupdate/source_stanza", TEST_ENI_DIR,
	                      (GTestDataFunc) test20_source_stanza);

	return g_test_run ();
}

