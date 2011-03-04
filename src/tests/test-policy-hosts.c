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

#include <glib.h>
#include <string.h>

#include "nm-policy-hosts.h"

#define DEBUG 0

static void
test_generic (const char *before, const char *after)
{
	GString *newc;

	/* Get the new /etc/hosts contents */
	newc = nm_policy_get_etc_hosts (before, strlen (before));

	if (after == NULL) {
		/* No change to /etc/hosts required */
#if DEBUG
		if (newc != NULL) {
			g_message ("\n- NEW ---------------------------------\n"
			           "%s"
			           "+ EXPECTED NONE +++++++++++++++++++++++++\n",
			           newc->str);
		}
#endif
		g_assert (newc == NULL);
	} else {
		g_assert (newc != NULL);

#if DEBUG
		g_message ("\n- NEW ---------------------------------\n"
		           "%s"
		           "+ EXPECTED ++++++++++++++++++++++++++++++\n"
		           "%s"
		           "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n",
		           newc->str, after);
#endif
		g_assert (strcmp (newc->str, after) == 0);
		g_string_free (newc, TRUE);
	}
}

/*******************************************/

static const char *generic_before = \
	"# Do not remove the following line, or various programs\n"
	"# that require network functionality will fail.\n"
	"127.0.0.1	localhost.localdomain localhost\n"
	"::1		localhost6.localdomain6 localhost6\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n";

static void
test_hosts_generic (void)
{
	test_generic (generic_before, NULL);
}

/*******************************************/

static const char *generic_no_boilerplate_before = \
	"127.0.0.1	localhost.localdomain localhost\n"
	"::1		localhost6.localdomain6 localhost6\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n";

static void
test_hosts_generic_no_boilerplate (void)
{
	test_generic (generic_no_boilerplate_before, NULL);
}

/*******************************************/

static const char *leftover_before = \
	"# Do not remove the following line, or various programs\n"
	"# that require network functionality will fail.\n"
	"192.168.1.2	comet	# Added by NetworkManager\n"
	"127.0.0.1	localhost.localdomain	localhost\n"
	"::1	localhost6.localdomain6	localhost6\n"
	"192.168.1.3	comet\n"
	"3001:abba::3234	comet\n"
	"\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n";

static const char *leftover_after = \
	"# Do not remove the following line, or various programs\n"
	"# that require network functionality will fail.\n"
	"127.0.0.1	localhost.localdomain	localhost\n"
	"::1	localhost6.localdomain6	localhost6\n"
	"192.168.1.3	comet\n"
	"3001:abba::3234	comet\n"
	"\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n";

static void
test_hosts_leftover (void)
{
	test_generic (leftover_before, leftover_after);
}

/*******************************************/

static const char *leftover_double_newline_before = \
	"# Do not remove the following line, or various programs\n"
	"# that require network functionality will fail.\n"
	"192.168.1.2	comet	# Added by NetworkManager\n"
	"127.0.0.1	localhost.localdomain	localhost\n"
	"::1	localhost6.localdomain6	localhost6\n"
	"192.168.1.3	comet\n"
	"3001:abba::3234	comet\n"
	"\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n"
	"\n";

static const char *leftover_double_newline_after = \
	"# Do not remove the following line, or various programs\n"
	"# that require network functionality will fail.\n"
	"127.0.0.1	localhost.localdomain	localhost\n"
	"::1	localhost6.localdomain6	localhost6\n"
	"192.168.1.3	comet\n"
	"3001:abba::3234	comet\n"
	"\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n"
	"\n";

static void
test_hosts_leftover_double_newline (void)
{
	test_generic (leftover_double_newline_before, leftover_double_newline_after);
}

/*******************************************/

#if GLIB_CHECK_VERSION(2,25,12)
typedef GTestFixtureFunc TCFunc;
#else
typedef void (*TCFunc)(void);
#endif

#define TESTCASE(t, d) g_test_create_case (#t, 0, d, NULL, (TCFunc) t, NULL)

int main (int argc, char **argv)
{
	GTestSuite *suite;

	g_test_init (&argc, &argv, NULL);

	suite = g_test_get_root ();

	g_test_suite_add (suite, TESTCASE (test_hosts_generic, NULL));
	g_test_suite_add (suite, TESTCASE (test_hosts_generic_no_boilerplate, NULL));
	g_test_suite_add (suite, TESTCASE (test_hosts_leftover, NULL));
	g_test_suite_add (suite, TESTCASE (test_hosts_leftover_double_newline, NULL));

	return g_test_run ();
}

