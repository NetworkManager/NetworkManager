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
 * Copyright (C) 2013 Red Hat, Inc.
 *
 */

#include "nm-default.h"

#include <string.h>
#include <arpa/inet.h>

#include "NetworkManagerUtils.h"
#include "nm-ip4-config.h"
#include "nm-ip6-config.h"
#include "platform/nm-platform.h"

#include "nm-test-utils-core.h"

static void
test_capture_empty (void)
{
	GArray *ns4 = g_array_new (FALSE, FALSE, sizeof (guint32));
	GArray *ns6 = g_array_new (FALSE, FALSE, sizeof (struct in6_addr));

	g_assert (!nm_utils_resolve_conf_parse (AF_INET, "", ns4, NULL));
	g_assert_cmpint (ns4->len, ==, 0);

	g_assert (!nm_utils_resolve_conf_parse (AF_INET6, "", ns6, NULL));
	g_assert_cmpint (ns6->len, ==, 0);

	g_array_free (ns4, TRUE);
	g_array_free (ns6, TRUE);
}

#define assert_dns4_entry(a, i, s) \
	g_assert_cmpint ((g_array_index ((a), guint32, (i))), ==, nmtst_inet4_from_string (s));

#define assert_dns6_entry(a, i, s) \
	g_assert (IN6_ARE_ADDR_EQUAL (&g_array_index ((a), struct in6_addr, (i)), nmtst_inet6_from_string (s)))

#define assert_dns_option(a, i, s) \
	g_assert_cmpstr ((a)->pdata[(i)], ==, (s));

static void
test_capture_basic4 (void)
{
	GArray *ns4 = g_array_new (FALSE, FALSE, sizeof (guint32));
	const char *rc =
"# neato resolv.conf\r\n"
"domain foobar.com\r\n"
"search foobar.com\r\n"
"nameserver 4.2.2.1\r\n"
"nameserver 4.2.2.2\r\n";

	g_assert (nm_utils_resolve_conf_parse (AF_INET, rc, ns4, NULL));
	g_assert_cmpint (ns4->len, ==, 2);
	assert_dns4_entry (ns4, 0, "4.2.2.1");
	assert_dns4_entry (ns4, 1, "4.2.2.2");

	g_array_free (ns4, TRUE);
}

static void
test_capture_dup4 (void)
{
	GArray *ns4 = g_array_new (FALSE, FALSE, sizeof (guint32));
	const char *rc =
"# neato resolv.conf\r\n"
"domain foobar.com\r\n"
"search foobar.com\r\n"
"nameserver 4.2.2.1\r\n"
"nameserver 4.2.2.1\r\n"
"nameserver 4.2.2.2\r\n";

	/* Check that duplicates are ignored */
	g_assert (nm_utils_resolve_conf_parse (AF_INET, rc, ns4, NULL));
	g_assert_cmpint (ns4->len, ==, 2);
	assert_dns4_entry (ns4, 0, "4.2.2.1");
	assert_dns4_entry (ns4, 1, "4.2.2.2");

	g_array_free (ns4, TRUE);
}

static void
test_capture_basic6 (void)
{
	GArray *ns6 = g_array_new (FALSE, FALSE, sizeof (struct in6_addr));
	const char *rc =
"# neato resolv.conf\r\n"
"domain foobar.com\r\n"
"search foobar.com\r\n"
"nameserver 2001:4860:4860::8888\r\n"
"nameserver 2001:4860:4860::8844\r\n";

	g_assert (nm_utils_resolve_conf_parse (AF_INET6, rc, ns6, NULL));
	g_assert_cmpint (ns6->len, ==, 2);
	assert_dns6_entry (ns6, 0, "2001:4860:4860::8888");
	assert_dns6_entry (ns6, 1, "2001:4860:4860::8844");

	g_array_free (ns6, TRUE);
}

static void
test_capture_dup6 (void)
{
	GArray *ns6 = g_array_new (FALSE, FALSE, sizeof (struct in6_addr));
	const char *rc =
"# neato resolv.conf\r\n"
"domain foobar.com\r\n"
"search foobar.com\r\n"
"nameserver 2001:4860:4860::8888\r\n"
"nameserver 2001:4860:4860::8888\r\n"
"nameserver 2001:4860:4860::8844\r\n";

	/* Check that duplicates are ignored */
	g_assert (nm_utils_resolve_conf_parse (AF_INET6, rc, ns6, NULL));
	g_assert_cmpint (ns6->len, ==, 2);
	assert_dns6_entry (ns6, 0, "2001:4860:4860::8888");
	assert_dns6_entry (ns6, 1, "2001:4860:4860::8844");

	g_array_free (ns6, TRUE);
}

static void
test_capture_addr4_with_6 (void)
{
	GArray *ns4 = g_array_new (FALSE, FALSE, sizeof (guint32));
	const char *rc =
"# neato resolv.conf\r\n"
"domain foobar.com\r\n"
"search foobar.com\r\n"
"nameserver 4.2.2.1\r\n"
"nameserver 4.2.2.2\r\n"
"nameserver 2001:4860:4860::8888\r\n";

	g_assert (nm_utils_resolve_conf_parse (AF_INET, rc, ns4, NULL));
	g_assert_cmpint (ns4->len, ==, 2);
	assert_dns4_entry (ns4, 0, "4.2.2.1");
	assert_dns4_entry (ns4, 1, "4.2.2.2");

	g_array_free (ns4, TRUE);
}

static void
test_capture_addr6_with_4 (void)
{
	GArray *ns6 = g_array_new (FALSE, FALSE, sizeof (struct in6_addr));
	const char *rc =
"# neato resolv.conf\r\n"
"domain foobar.com\r\n"
"search foobar.com\r\n"
"nameserver 4.2.2.1\r\n"
"nameserver 2001:4860:4860::8888\r\n"
"nameserver 2001:4860:4860::8844\r\n";

	g_assert (nm_utils_resolve_conf_parse (AF_INET6, rc, ns6, NULL));
	g_assert_cmpint (ns6->len, ==, 2);
	assert_dns6_entry (ns6, 0, "2001:4860:4860::8888");
	assert_dns6_entry (ns6, 1, "2001:4860:4860::8844");

	g_array_free (ns6, TRUE);
}

static void
test_capture_format (void)
{
	GArray *ns4 = g_array_new (FALSE, FALSE, sizeof (guint32));
	const char *rc =
" nameserver 4.2.2.1\r\n"     /* bad */
"nameserver4.2.2.1\r\n"       /* bad */
"nameserver     4.2.2.3\r"    /* good */
"nameserver\t\t4.2.2.4\r\n"   /* good */
"nameserver  4.2.2.5\t\t\r\n" /* good */
"nameserver  4.2.2.6   \r\n"; /* good */

	g_assert (nm_utils_resolve_conf_parse (AF_INET, rc, ns4, NULL));
	g_assert_cmpint (ns4->len, ==, 4);
	assert_dns4_entry (ns4, 0, "4.2.2.3");
	assert_dns4_entry (ns4, 1, "4.2.2.4");
	assert_dns4_entry (ns4, 2, "4.2.2.5");
	assert_dns4_entry (ns4, 3, "4.2.2.6");

	g_array_free (ns4, TRUE);
}

static void
test_capture_dns_options (void)
{
	GArray *ns4 = g_array_new (FALSE, FALSE, sizeof (guint32));
	GPtrArray *dns_options = g_ptr_array_new_with_free_func (g_free);
	const char *rc =
"nameserver 4.2.2.1\r\n"
"options debug rotate  timeout:5 \r\n"
"options edns0\r\n";

	g_assert (nm_utils_resolve_conf_parse (AF_INET, rc, ns4, dns_options));
	g_assert_cmpint (dns_options->len, ==, 4);
	assert_dns_option (dns_options, 0, "debug");
	assert_dns_option (dns_options, 1, "rotate");
	assert_dns_option (dns_options, 2, "timeout:5");
	assert_dns_option (dns_options, 3, "edns0");

	g_array_free (ns4, TRUE);
	g_ptr_array_free (dns_options, TRUE);
}

static void
test_capture_dns_options_dup (void)
{
	GArray *ns4 = g_array_new (FALSE, FALSE, sizeof (guint32));
	GPtrArray *dns_options = g_ptr_array_new_with_free_func (g_free);
	const char *rc =
"options debug rotate timeout:3\r\n"
"options edns0 debug\r\n"
"options timeout:5\r\n";

	g_assert (nm_utils_resolve_conf_parse (AF_INET, rc, ns4, dns_options));
	g_assert_cmpint (dns_options->len, ==, 4);
	assert_dns_option (dns_options, 0, "debug");
	assert_dns_option (dns_options, 1, "rotate");
	assert_dns_option (dns_options, 2, "timeout:3");
	assert_dns_option (dns_options, 3, "edns0");

	g_array_free (ns4, TRUE);
	g_ptr_array_free (dns_options, TRUE);
}

static void
test_capture_dns_options_valid4 (void)
{
	GArray *ns4 = g_array_new (FALSE, FALSE, sizeof (guint32));
	GPtrArray *dns_options = g_ptr_array_new_with_free_func (g_free);
	const char *rc =
"options debug: rotate:yes edns0 foobar : inet6\r\n";

	g_assert (nm_utils_resolve_conf_parse (AF_INET, rc, ns4, dns_options));
	g_assert_cmpint (dns_options->len, ==, 1);
	assert_dns_option (dns_options, 0, "edns0");

	g_array_free (ns4, TRUE);
	g_ptr_array_free (dns_options, TRUE);
}

static void
test_capture_dns_options_valid6 (void)
{
	GArray *ns6 = g_array_new (FALSE, FALSE, sizeof (struct in6_addr));
	GPtrArray *dns_options = g_ptr_array_new_with_free_func (g_free);
	const char *rc =
"options inet6 debug foobar rotate:\r\n";

	g_assert (nm_utils_resolve_conf_parse (AF_INET6, rc, ns6, dns_options));
	g_assert_cmpint (dns_options->len, ==, 2);
	assert_dns_option (dns_options, 0, "inet6");
	assert_dns_option (dns_options, 1, "debug");

	g_array_free (ns6, TRUE);
	g_ptr_array_free (dns_options, TRUE);
}
/*****************************************************************************/

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	nmtst_init_assert_logging (&argc, &argv, "INFO", "DEFAULT");

	g_test_add_func ("/resolvconf-capture/empty", test_capture_empty);
	g_test_add_func ("/resolvconf-capture/basic4", test_capture_basic4);
	g_test_add_func ("/resolvconf-capture/dup4", test_capture_dup4);
	g_test_add_func ("/resolvconf-capture/basic6", test_capture_basic6);
	g_test_add_func ("/resolvconf-capture/dup6", test_capture_dup6);
	g_test_add_func ("/resolvconf-capture/addr4-with-6", test_capture_addr4_with_6);
	g_test_add_func ("/resolvconf-capture/addr6-with-4", test_capture_addr6_with_4);
	g_test_add_func ("/resolvconf-capture/format", test_capture_format);
	g_test_add_func ("/resolvconf-capture/dns-options", test_capture_dns_options);
	g_test_add_func ("/resolvconf-capture/dns-options-dup", test_capture_dns_options_dup);
	g_test_add_func ("/resolvconf-capture/dns-options-valid4", test_capture_dns_options_valid4);
	g_test_add_func ("/resolvconf-capture/dns-options-valid6", test_capture_dns_options_valid6);

	return g_test_run ();
}

