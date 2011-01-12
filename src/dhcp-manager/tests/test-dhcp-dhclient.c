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

#include "nm-dhcp-dhclient-utils.h"
#include "nm-utils.h"

#define DEBUG 0

static void
test_config (const char *orig,
             const char *expected,
             const char *hostname,
             const char *dhcp_client_id,
             const char *iface,
             guint8 *anycast_addr)
{
	NMSettingIP4Config *s_ip4;
	char *new;

	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_DHCP_CLIENT_ID, dhcp_client_id, NULL);

	new = nm_dhcp_dhclient_create_config (iface,
	                                      s_ip4,
	                                      anycast_addr,
	                                      hostname,
	                                      "/path/to/dhclient.conf",
	                                      orig);
	g_assert (new != NULL);

#if DEBUG
	g_message ("\n- NEW ---------------------------------\n"
	           "%s"
	           "+ EXPECTED ++++++++++++++++++++++++++++++\n"
	           "%s"
	           "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n",
	           new, expected);
#endif
	g_assert (strlen (new) == strlen (expected));
	g_assert (strcmp (new, expected) == 0);
	g_free (new);
}

/*******************************************/

static const char *orig_missing_expected = \
	"# Created by NetworkManager\n"
	"\n"
	"option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;\n"
	"option ms-classless-static-routes code 249 = array of unsigned integer 8;\n"
	"option wpad code 252 = string;\n"
	"\n"
	"also request rfc3442-classless-static-routes;\n"
	"also request ms-classless-static-routes;\n"
	"also request wpad;\n"
	"also request ntp-servers;\n"
	"\n";

static void
test_orig_missing (void)
{
	test_config (NULL, orig_missing_expected,
	             NULL,
	             NULL,
	             "eth0",
	             NULL);
}

/*******************************************/

static const char *override_client_id_orig = \
	"send dhcp-client-identifier 00:30:04:20:7A:08;\n";

static const char *override_client_id_expected = \
	"# Created by NetworkManager\n"
	"# Merged from /path/to/dhclient.conf\n"
	"\n"
	"send dhcp-client-identifier 11:22:33:44:55:66; # added by NetworkManager\n"
	"\n"
	"option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;\n"
	"option ms-classless-static-routes code 249 = array of unsigned integer 8;\n"
	"option wpad code 252 = string;\n"
	"\n"
	"also request rfc3442-classless-static-routes;\n"
	"also request ms-classless-static-routes;\n"
	"also request wpad;\n"
	"also request ntp-servers;\n"
	"\n";

static void
test_override_client_id (void)
{
	test_config (override_client_id_orig, override_client_id_expected,
	             NULL,
	             "11:22:33:44:55:66",
	             "eth0",
	             NULL);
}

/*******************************************/

static const char *override_hostname_orig = \
	"send host-name \"foobar\";\n";

static const char *override_hostname_expected = \
	"# Created by NetworkManager\n"
	"# Merged from /path/to/dhclient.conf\n"
	"\n"
	"send host-name \"blahblah\"; # added by NetworkManager\n"
	"\n"
	"option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;\n"
	"option ms-classless-static-routes code 249 = array of unsigned integer 8;\n"
	"option wpad code 252 = string;\n"
	"\n"
	"also request rfc3442-classless-static-routes;\n"
	"also request ms-classless-static-routes;\n"
	"also request wpad;\n"
	"also request ntp-servers;\n"
	"\n";

static void
test_override_hostname (void)
{
	test_config (override_hostname_orig, override_hostname_expected,
	             "blahblah",
	             NULL,
	             "eth0",
	             NULL);
}

/*******************************************/

static const char *existing_alsoreq_orig = \
	"also request something;\n"
	"also request another-thing;\n"
	;

static const char *existing_alsoreq_expected = \
	"# Created by NetworkManager\n"
	"# Merged from /path/to/dhclient.conf\n"
	"\n"
	"option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;\n"
	"option ms-classless-static-routes code 249 = array of unsigned integer 8;\n"
	"option wpad code 252 = string;\n"
	"\n"
	"also request something;\n"
	"also request another-thing;\n"
	"also request rfc3442-classless-static-routes;\n"
	"also request ms-classless-static-routes;\n"
	"also request wpad;\n"
	"also request ntp-servers;\n"
	"\n";

static void
test_existing_alsoreq (void)
{
	test_config (existing_alsoreq_orig, existing_alsoreq_expected,
	             NULL,
	             NULL,
	             "eth0",
	             NULL);
}

/*******************************************/

static const char *existing_multiline_alsoreq_orig = \
	"also request something another-thing yet-another-thing\n"
	"    foobar baz blah;\n"
	;

static const char *existing_multiline_alsoreq_expected = \
	"# Created by NetworkManager\n"
	"# Merged from /path/to/dhclient.conf\n"
	"\n"
	"option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;\n"
	"option ms-classless-static-routes code 249 = array of unsigned integer 8;\n"
	"option wpad code 252 = string;\n"
	"\n"
	"also request something;\n"
	"also request another-thing;\n"
	"also request yet-another-thing;\n"
	"also request foobar;\n"
	"also request baz;\n"
	"also request blah;\n"
	"also request rfc3442-classless-static-routes;\n"
	"also request ms-classless-static-routes;\n"
	"also request wpad;\n"
	"also request ntp-servers;\n"
	"\n";

static void
test_existing_multiline_alsoreq (void)
{
	test_config (existing_multiline_alsoreq_orig, existing_multiline_alsoreq_expected,
	             NULL,
	             NULL,
	             "eth0",
	             NULL);
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

	g_type_init ();

	suite = g_test_get_root ();

	g_test_suite_add (suite, TESTCASE (test_orig_missing, NULL));
	g_test_suite_add (suite, TESTCASE (test_override_client_id, NULL));
	g_test_suite_add (suite, TESTCASE (test_override_hostname, NULL));
	g_test_suite_add (suite, TESTCASE (test_existing_alsoreq, NULL));
	g_test_suite_add (suite, TESTCASE (test_existing_multiline_alsoreq, NULL));

	return g_test_run ();
}

