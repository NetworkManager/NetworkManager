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

#include "nm-default.h"

#include "nm-core-internal.h"

#include "settings/plugins/ifupdown/nms-ifupdown-interface-parser.h"
#include "settings/plugins/ifupdown/nms-ifupdown-parser.h"

#include "nm-test-utils-core.h"

#define TEST_DIR       NM_BUILD_SRCDIR"/src/settings/plugins/ifupdown/tests"

/*****************************************************************************/

#define _connection_from_if_block(block) \
	({ \
		NMConnection *_con; \
		if_block *_block = (block); \
		GError *_local = NULL; \
		\
		g_assert (_block); \
		_con = ifupdown_new_connection_from_if_block (_block, FALSE, &_local); \
		nmtst_assert_success (NM_IS_CONNECTION (_con), _local); \
		nmtst_assert_connection_verifies_without_normalization (_con); \
		_con; \
	})

#define _connection_first_from_parser(parser) \
	({ \
		if_parser *_parser = (parser); \
		\
		g_assert (_parser); \
		_connection_from_if_block (ifparser_getfirst (_parser)); \
	})

/*****************************************************************************/

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
compare_expected_to_ifparser (if_parser *parser, Expected *e)
{
	if_block *n;
	GSList *biter, *kiter;

	g_assert_cmpint (g_slist_length (e->blocks), ==, ifparser_get_num_blocks (parser));

	biter = e->blocks;
	c_list_for_each_entry (n, &parser->block_lst_head, block_lst) {
		if_data *m;
		ExpectedBlock *b = biter->data;

		g_assert (b->type && n->type);
		g_assert_cmpstr (b->type, ==, n->type);
		g_assert (b->name);
		g_assert_cmpstr (b->name, ==, n->name);

		g_assert_cmpint (g_slist_length (b->keys), ==, ifparser_get_num_info (n));

		kiter = b->keys;
		c_list_for_each_entry (m, &n->data_lst_head, data_lst) {
			ExpectedKey *k = kiter->data;

			g_assert (k->key);
			g_assert_cmpstr (k->key, ==, m->key);
			g_assert (k->data && m->data);
			g_assert_cmpstr (k->data, ==, m->data);

			kiter = g_slist_next (kiter);
		}
		g_assert (!kiter);

		biter = g_slist_next (biter);
	}
	g_assert (!biter);
}

static void
dump_blocks (if_parser *parser)
{
	if_block *n;

	g_message ("\n***************************************************");
	c_list_for_each_entry (n, &parser->block_lst_head, block_lst) {
		if_data *m;

		// each block start with its type & name
		// (single quotes used to show typ & name baoundaries)
		g_print("'%s' '%s'\n", n->type, n->name);

		// each key-value pair within a block is indented & separated by a tab
		// (single quotes used to show typ & name baoundaries)
		c_list_for_each_entry (m, &n->data_lst_head, data_lst)
			g_print("\t'%s'\t'%s'\n", m->key, m->data);

		// blocks are separated by an empty line
		g_print("\n");
	}
	g_message ("##################################################\n");
}

static if_parser *
init_ifparser_with_file (const char *file)
{
	if_parser *parser;
	gs_free char *tmp = NULL;

	tmp = g_strdup_printf ("%s/%s", TEST_DIR, file);
	parser = ifparser_parse (tmp, 1);
	g_assert (parser);
	return parser;
}

static void
test1_ignore_line_before_first_block (void)
{
	Expected *e;
	ExpectedBlock *b;
	nm_auto_ifparser if_parser *parser = init_ifparser_with_file ("test1");

	e = expected_new ();
	b = expected_block_new ("auto", "eth0");
	expected_add_block (e, b);
	b = expected_block_new ("iface", "eth0");
	expected_add_block (e, b);
	expected_block_add_key (b, expected_key_new ("inet", "dhcp"));

	compare_expected_to_ifparser (parser, e);

	expected_free (e);
}

static void
test2_wrapped_line (void)
{
	Expected *e;
	ExpectedBlock *b;
	nm_auto_ifparser if_parser *parser = init_ifparser_with_file ("test2");

	e = expected_new ();
	b = expected_block_new ("auto", "lo");
	expected_add_block (e, b);

	compare_expected_to_ifparser (parser, e);

	expected_free (e);
}

static void
test3_wrapped_multiline_multiarg (void)
{
	Expected *e;
	ExpectedBlock *b;
	nm_auto_ifparser if_parser *parser = init_ifparser_with_file ("test3");

	e = expected_new ();
	b = expected_block_new ("allow-hotplug", "eth0");
	expected_add_block (e, b);
	b = expected_block_new ("allow-hotplug", "wlan0");
	expected_add_block (e, b);
	b = expected_block_new ("allow-hotplug", "bnep0");
	expected_add_block (e, b);

	compare_expected_to_ifparser (parser, e);

	expected_free (e);
}

static void
test4_allow_auto_is_auto (void)
{
	Expected *e;
	ExpectedBlock *b;
	nm_auto_ifparser if_parser *parser = init_ifparser_with_file ("test4");

	e = expected_new ();
	b = expected_block_new ("auto", "eth0");
	expected_add_block (e, b);

	compare_expected_to_ifparser (parser, e);

	expected_free (e);
}

static void
test5_allow_auto_multiarg (void)
{
	Expected *e;
	ExpectedBlock *b;
	nm_auto_ifparser if_parser *parser = init_ifparser_with_file ("test5");

	e = expected_new ();
	b = expected_block_new ("allow-hotplug", "eth0");
	expected_add_block (e, b);
	b = expected_block_new ("allow-hotplug", "wlan0");
	expected_add_block (e, b);

	compare_expected_to_ifparser (parser, e);

	expected_free (e);
}

static void
test6_mixed_whitespace (void)
{
	Expected *e;
	ExpectedBlock *b;
	nm_auto_ifparser if_parser *parser = init_ifparser_with_file ("test6");

	e = expected_new ();
	b = expected_block_new ("iface", "lo");
	expected_block_add_key (b, expected_key_new ("inet", "loopback"));
	expected_add_block (e, b);

	compare_expected_to_ifparser (parser, e);

	expected_free (e);
}

static void
test7_long_line (void)
{
	nm_auto_ifparser if_parser *parser = init_ifparser_with_file ("test7");

	g_assert_cmpint (ifparser_get_num_blocks (parser), ==, 0);
}

static void
test8_long_line_wrapped (void)
{
	nm_auto_ifparser if_parser *parser = init_ifparser_with_file ("test8");

	g_assert_cmpint (ifparser_get_num_blocks (parser), ==, 0);
}

static void
test9_wrapped_lines_in_block (void)
{
	Expected *e;
	ExpectedBlock *b;
	nm_auto_ifparser if_parser *parser = init_ifparser_with_file ("test9");

	e = expected_new ();
	b = expected_block_new ("iface", "eth0");
	expected_add_block (e, b);
	expected_block_add_key (b, expected_key_new ("inet", "static"));
	expected_block_add_key (b, expected_key_new ("address", "10.250.2.3"));
	expected_block_add_key (b, expected_key_new ("netmask", "255.255.255.192"));
	expected_block_add_key (b, expected_key_new ("broadcast", "10.250.2.63"));
	expected_block_add_key (b, expected_key_new ("gateway", "10.250.2.50"));

	compare_expected_to_ifparser (parser, e);

	expected_free (e);
}

static void
test11_complex_wrap (void)
{
	Expected *e;
	ExpectedBlock *b;
	nm_auto_ifparser if_parser *parser = init_ifparser_with_file ("test11");

	e = expected_new ();
	b = expected_block_new ("iface", "pppoe");
	expected_add_block (e, b);
	expected_block_add_key (b, expected_key_new ("inet", "manual"));
	expected_block_add_key (b, expected_key_new ("pre-up", "/sbin/ifconfig eth0 up"));

	compare_expected_to_ifparser (parser, e);

	expected_free (e);
}

static void
test12_complex_wrap_split_word (void)
{
	Expected *e;
	ExpectedBlock *b;
	nm_auto_ifparser if_parser *parser = init_ifparser_with_file ("test12");

	e = expected_new ();
	b = expected_block_new ("iface", "pppoe");
	expected_add_block (e, b);
	expected_block_add_key (b, expected_key_new ("inet", "manual"));
	expected_block_add_key (b, expected_key_new ("up", "ifup ppp0=dsl"));

	compare_expected_to_ifparser (parser, e);

	expected_free (e);
}

static void
test13_more_mixed_whitespace (void)
{
	Expected *e;
	ExpectedBlock *b;
	nm_auto_ifparser if_parser *parser = init_ifparser_with_file ("test13");

	e = expected_new ();
	b = expected_block_new ("iface", "dsl");
	expected_block_add_key (b, expected_key_new ("inet", "ppp"));
	expected_add_block (e, b);

	compare_expected_to_ifparser (parser, e);

	expected_free (e);
}

static void
test14_mixed_whitespace_block_start (void)
{
	Expected *e;
	ExpectedBlock *b;
	nm_auto_ifparser if_parser *parser = init_ifparser_with_file ("test14");

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

	compare_expected_to_ifparser (parser, e);

	expected_free (e);
}

static void
test15_trailing_space (void)
{
	Expected *e;
	ExpectedBlock *b;
	nm_auto_ifparser if_parser *parser = init_ifparser_with_file ("test15");

	e = expected_new ();
	b = expected_block_new ("iface", "bnep0");
	expected_block_add_key (b, expected_key_new ("inet", "static"));
	expected_add_block (e, b);

	compare_expected_to_ifparser (parser, e);

	expected_free (e);
}

static void
test16_missing_newline (void)
{
	Expected *e;
	nm_auto_ifparser if_parser *parser = init_ifparser_with_file ("test16");

	e = expected_new ();
	expected_add_block (e, expected_block_new ("mapping", "eth0"));

	compare_expected_to_ifparser (parser, e);

	expected_free (e);
}
static void
test17_read_static_ipv4 (void)
{
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip4;
	NMSettingWired *s_wired;
	NMIPAddress *ip4_addr;
	nm_auto_ifparser if_parser *parser = init_ifparser_with_file ("test17-wired-static-verify-ip4");

	connection = _connection_first_from_parser (parser);

	/* ===== CONNECTION SETTING ===== */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "Ifupdown (eth0)");

	/* ===== WIRED SETTING ===== */
	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);

	/* ===== IPv4 SETTING ===== */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_MANUAL);

	g_assert_cmpint (nm_setting_ip_config_get_num_addresses (s_ip4), ==, 1);
	ip4_addr = nm_setting_ip_config_get_address (s_ip4, 0);
	g_assert (ip4_addr != NULL);
	g_assert_cmpstr (nm_ip_address_get_address (ip4_addr), ==, "10.0.0.3");
	g_assert_cmpint (nm_ip_address_get_prefix (ip4_addr), ==, 8);

	g_assert_cmpint (nm_setting_ip_config_get_num_dns (s_ip4), ==, 2);
	g_assert_cmpstr (nm_setting_ip_config_get_dns (s_ip4, 0), ==, "10.0.0.1");
	g_assert_cmpstr (nm_setting_ip_config_get_dns (s_ip4, 1), ==, "10.0.0.2");

	g_assert_cmpint (nm_setting_ip_config_get_num_dns_searches (s_ip4), ==, 2);
	g_assert_cmpstr (nm_setting_ip_config_get_dns_search (s_ip4, 0), ==, "example.com");
	g_assert_cmpstr (nm_setting_ip_config_get_dns_search (s_ip4, 1), ==, "foo.example.com");
}

static void
test18_read_static_ipv6 (void)
{
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip6;
	NMSettingWired *s_wired;
	NMIPAddress *ip6_addr;
	nm_auto_ifparser if_parser *parser = init_ifparser_with_file ("test18-wired-static-verify-ip6");

	connection = _connection_first_from_parser (parser);

	/* ===== CONNECTION SETTING ===== */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "Ifupdown (myip6tunnel)");

	/* ===== WIRED SETTING ===== */
	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);

	/* ===== IPv6 SETTING ===== */
	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_MANUAL);

	g_assert_cmpint (nm_setting_ip_config_get_num_addresses (s_ip6), ==, 1);
	ip6_addr = nm_setting_ip_config_get_address (s_ip6, 0);
	g_assert (ip6_addr != NULL);
	g_assert_cmpstr (nm_ip_address_get_address (ip6_addr), ==, "fc00::1");
	g_assert_cmpint (nm_ip_address_get_prefix (ip6_addr), ==, 64);

	g_assert_cmpint (nm_setting_ip_config_get_num_dns (s_ip6), ==, 2);
	g_assert_cmpstr (nm_setting_ip_config_get_dns (s_ip6, 0), ==, "fc00::2");
	g_assert_cmpstr (nm_setting_ip_config_get_dns (s_ip6, 1), ==, "fc00::3");

	g_assert_cmpint (nm_setting_ip_config_get_num_dns_searches (s_ip6), ==, 2);
	g_assert_cmpstr (nm_setting_ip_config_get_dns_search (s_ip6, 0), ==, "example.com");
	g_assert_cmpstr (nm_setting_ip_config_get_dns_search (s_ip6, 1), ==, "foo.example.com");
}

static void
test19_read_static_ipv4_plen (void)
{
	gs_unref_object NMConnection *connection = NULL;
	NMSettingIPConfig *s_ip4;
	NMIPAddress *ip4_addr;
	nm_auto_ifparser if_parser *parser = init_ifparser_with_file ("test19-wired-static-verify-ip4-plen");

	connection = _connection_first_from_parser (parser);

	/* ===== IPv4 SETTING ===== */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);

	g_assert_cmpint (nm_setting_ip_config_get_num_addresses (s_ip4), ==, 1);
	ip4_addr = nm_setting_ip_config_get_address (s_ip4, 0);
	g_assert (ip4_addr != NULL);
	g_assert_cmpstr (nm_ip_address_get_address (ip4_addr), ==, "10.0.0.3");
	g_assert_cmpint (nm_ip_address_get_prefix (ip4_addr), ==, 8);
}

static void
test20_source_stanza (void)
{
	Expected *e;
	ExpectedBlock *b;
	nm_auto_ifparser if_parser *parser = init_ifparser_with_file ("test20-source-stanza");

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

	compare_expected_to_ifparser (parser, e);

	expected_free (e);
}

static void
test21_source_dir_stanza (void)
{
	Expected *e;
	ExpectedBlock *b;
	nm_auto_ifparser if_parser *parser = init_ifparser_with_file ("test21-source-dir-stanza");

	e = expected_new ();

	b = expected_block_new ("auto", "eth0");
	expected_add_block (e, b);
	b = expected_block_new ("iface", "eth0");
	expected_add_block (e, b);
	expected_block_add_key (b, expected_key_new ("inet", "dhcp"));

	compare_expected_to_ifparser (parser, e);

	expected_free (e);
}

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	nmtst_init_assert_logging (&argc, &argv, "WARN", "DEFAULT");

	(void) dump_blocks;

	g_test_add_func ("/ifupdate/ignore_line_before_first_block", test1_ignore_line_before_first_block);
	g_test_add_func ("/ifupdate/wrapped_line",                   test2_wrapped_line);
	g_test_add_func ("/ifupdate/wrapped_multiline_multiarg",     test3_wrapped_multiline_multiarg);
	g_test_add_func ("/ifupdate/allow_auto_is_auto",             test4_allow_auto_is_auto);
	g_test_add_func ("/ifupdate/allow_auto_multiarg",            test5_allow_auto_multiarg);
	g_test_add_func ("/ifupdate/mixed_whitespace",               test6_mixed_whitespace);
	g_test_add_func ("/ifupdate/long_line",                      test7_long_line);
	g_test_add_func ("/ifupdate/long_line_wrapped",              test8_long_line_wrapped);
	g_test_add_func ("/ifupdate/wrapped_lines_in_block",         test9_wrapped_lines_in_block);
	g_test_add_func ("/ifupdate/complex_wrap",                   test11_complex_wrap);
	g_test_add_func ("/ifupdate/complex_wrap_split_word",        test12_complex_wrap_split_word);
	g_test_add_func ("/ifupdate/more_mixed_whitespace",          test13_more_mixed_whitespace);
	g_test_add_func ("/ifupdate/mixed_whitespace_block_start",   test14_mixed_whitespace_block_start);
	g_test_add_func ("/ifupdate/trailing_space",                 test15_trailing_space);
	g_test_add_func ("/ifupdate/missing_newline",                test16_missing_newline);
	g_test_add_func ("/ifupdate/read_static_ipv4",               test17_read_static_ipv4);
	g_test_add_func ("/ifupdate/read_static_ipv6",               test18_read_static_ipv6);
	g_test_add_func ("/ifupdate/read_static_ipv4_plen",          test19_read_static_ipv4_plen);
	g_test_add_func ("/ifupdate/source_stanza",                  test20_source_stanza);
	g_test_add_func ("/ifupdate/source_dir_stanza",              test21_source_dir_stanza);

	return g_test_run ();
}
