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

#include <glib.h>
#include <string.h>

#include "NetworkManagerUtils.h"
#include "nm-platform.h"

static void
test_capture_empty (void)
{
	GArray *ns4 = g_array_new (FALSE, FALSE, sizeof (guint32));
	GArray *ns6 = g_array_new (FALSE, FALSE, sizeof (struct in6_addr));

	g_assert (nm_ip4_config_capture_resolv_conf (ns4, "") == FALSE);
	g_assert_cmpint (ns4->len, ==, 0);

	g_assert (nm_ip6_config_capture_resolv_conf (ns6, "") == FALSE);
	g_assert_cmpint (ns6->len, ==, 0);

	g_array_free (ns4, TRUE);
	g_array_free (ns6, TRUE);
}

static void
assert_dns4_entry (const GArray *a, guint i, const char *s)
{
	guint32 n, m;

	g_assert (inet_aton (s, (void *) &n) != 0);
	m = g_array_index (a, guint32, i);
	g_assert_cmpint (m, ==, n);
}

static void
assert_dns6_entry (const GArray *a, guint i, const char *s)
{
	struct in6_addr n = IN6ADDR_ANY_INIT;
	struct in6_addr *m;

	g_assert (inet_pton (AF_INET6, s, (void *) &n) == 1);
	m = &g_array_index (a, struct in6_addr, i);
	g_assert (IN6_ARE_ADDR_EQUAL (&n, m));
}

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

	g_assert (nm_ip4_config_capture_resolv_conf (ns4, rc));
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
	g_assert (nm_ip4_config_capture_resolv_conf (ns4, rc));
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

	g_assert (nm_ip6_config_capture_resolv_conf (ns6, rc));
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
	g_assert (nm_ip6_config_capture_resolv_conf (ns6, rc));
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

	g_assert (nm_ip4_config_capture_resolv_conf (ns4, rc));
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

	g_assert (nm_ip6_config_capture_resolv_conf (ns6, rc));
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
"nameserver     4.2.2.3\r"  /* good */
"nameserver\t\t4.2.2.4\r\n"   /* good */
"nameserver  4.2.2.5\t\t\r\n"; /* good */

	g_assert (nm_ip4_config_capture_resolv_conf (ns4, rc));
	g_assert_cmpint (ns4->len, ==, 3);
	assert_dns4_entry (ns4, 0, "4.2.2.3");
	assert_dns4_entry (ns4, 1, "4.2.2.4");
	assert_dns4_entry (ns4, 2, "4.2.2.5");

	g_array_free (ns4, TRUE);
}

/*******************************************/

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

#if !GLIB_CHECK_VERSION (2,35,0)
	g_type_init ();
#endif

	g_test_add_func ("/resolvconf-capture/empty", test_capture_empty);
	g_test_add_func ("/resolvconf-capture/basic4", test_capture_basic4);
	g_test_add_func ("/resolvconf-capture/dup4", test_capture_dup4);
	g_test_add_func ("/resolvconf-capture/basic6", test_capture_basic6);
	g_test_add_func ("/resolvconf-capture/dup6", test_capture_dup6);
	g_test_add_func ("/resolvconf-capture/addr4-with-6", test_capture_addr4_with_6);
	g_test_add_func ("/resolvconf-capture/addr6-with-4", test_capture_addr6_with_4);
	g_test_add_func ("/resolvconf-capture/format", test_capture_format);

	return g_test_run ();
}

