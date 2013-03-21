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
#include <unistd.h>

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
	                                      FALSE,
	                                      s_ip4,
	                                      NULL,
	                                      anycast_addr,
	                                      hostname,
	                                      "/path/to/dhclient.conf",
	                                      orig);
	g_assert (new != NULL);

#if DEBUG
	if (   strlen (new) != strlen (expected)
	    || strcmp (new, expected)) {
		g_message ("\n- NEW ---------------------------------\n"
		           "%s"
		           "+ EXPECTED ++++++++++++++++++++++++++++++\n"
		           "%s"
		           "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n",
		           new, expected);
	}
#endif
	g_assert (strlen (new) == strlen (expected));
	g_assert (strcmp (new, expected) == 0);
	g_free (new);
}

/*******************************************/

static const char *orig_missing_expected = \
	"# Created by NetworkManager\n"
	"\n\n"
	"option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;\n"
	"option ms-classless-static-routes code 249 = array of unsigned integer 8;\n"
	"option wpad code 252 = string;\n"
	"\n"
	"also request rfc3442-classless-static-routes;\n"
	"also request ms-classless-static-routes;\n"
	"also request static-routes;\n"
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
	"also request static-routes;\n"
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
	"also request static-routes;\n"
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
	"\n\n"
	"option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;\n"
	"option ms-classless-static-routes code 249 = array of unsigned integer 8;\n"
	"option wpad code 252 = string;\n"
	"\n"
	"also request something;\n"
	"also request another-thing;\n"
	"also request rfc3442-classless-static-routes;\n"
	"also request ms-classless-static-routes;\n"
	"also request static-routes;\n"
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
	"\n\n"
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
	"also request static-routes;\n"
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

static void
test_one_duid (const char *escaped, const guint8 *unescaped, guint len)
{
	GByteArray *t;
	char *w;

	t = nm_dhcp_dhclient_unescape_duid (escaped);
	g_assert (t);
	g_assert_cmpint (t->len, ==, len);
	g_assert_cmpint (memcmp (t->data, unescaped, len), ==, 0);
	g_byte_array_free (t, TRUE);

	t = g_byte_array_sized_new (len);
	g_byte_array_append (t, unescaped, len);
	w = nm_dhcp_dhclient_escape_duid (t);
	g_assert (w);
	g_assert_cmpint (strlen (escaped), ==, strlen (w));
	g_assert_cmpstr (escaped, ==, w);
}

static void
test_duids (void)
{
	const guint8 test1_u[] = { 0x00, 0x01, 0x00, 0x01, 0x13, 0x6f, 0x13, 0x6e,
	                           0x00, 0x22, 0xfa, 0x8c, 0xd6, 0xc2 };
	const char *test1_s = "\\000\\001\\000\\001\\023o\\023n\\000\\\"\\372\\214\\326\\302";

	const guint8 test2_u[] = { 0x00, 0x01, 0x00, 0x01, 0x17, 0x57, 0xee, 0x39,
	                           0x00, 0x23, 0x15, 0x08, 0x7E, 0xac };
	const char *test2_s = "\\000\\001\\000\\001\\027W\\3569\\000#\\025\\010~\\254";

	const guint8 test3_u[] = { 0x00, 0x01, 0x00, 0x01, 0x17, 0x58, 0xe8, 0x58,
	                           0x00, 0x23, 0x15, 0x08, 0x7e, 0xac };
	const char *test3_s = "\\000\\001\\000\\001\\027X\\350X\\000#\\025\\010~\\254";

	const guint8 test4_u[] = { 0x00, 0x01, 0x00, 0x01, 0x15, 0xd5, 0x31, 0x97,
	                           0x00, 0x16, 0xeb, 0x04, 0x45, 0x18 };
	const char *test4_s = "\\000\\001\\000\\001\\025\\3251\\227\\000\\026\\353\\004E\\030";

	const char *bad_s = "\\000\\001\\000\\001\\425\\3251\\227\\000\\026\\353\\004E\\030";

	test_one_duid (test1_s, test1_u, sizeof (test1_u));
	test_one_duid (test2_s, test2_u, sizeof (test2_u));
	test_one_duid (test3_s, test3_u, sizeof (test3_u));
	test_one_duid (test4_s, test4_u, sizeof (test4_u));

	/* Invalid octal digit */
	g_assert (nm_dhcp_dhclient_unescape_duid (bad_s) == NULL);
}

static void
test_read_duid_from_leasefile (void)
{
	const guint8 expected[] = { 0x00, 0x01, 0x00, 0x01, 0x18, 0x79, 0xa6,
	                            0x13, 0x60, 0x67, 0x20, 0xec, 0x4c, 0x70 };
	GByteArray *duid;
	GError *error = NULL;

	duid = nm_dhcp_dhclient_read_duid (TESTDIR "/test-dhclient-duid.leases", &error);
	g_assert_no_error (error);
	g_assert (duid);
	g_assert_cmpint (duid->len, ==, sizeof (expected));
	g_assert_cmpint (memcmp (duid->data, expected, duid->len), ==, 0);

	g_byte_array_free (duid, TRUE);
}

static void
test_read_commented_duid_from_leasefile (void)
{
	GByteArray *duid;
	GError *error = NULL;

	duid = nm_dhcp_dhclient_read_duid (TESTDIR "/test-dhclient-commented-duid.leases", &error);
	g_assert_no_error (error);
	g_assert (duid == NULL);
}

static void
test_write_duid (void)
{
	const char *duid = "\\000\\001\\000\\001\\027X\\350X\\000#\\025\\010~\\254";
	const char *expected_contents = "default-duid \"\\000\\001\\000\\001\\027X\\350X\\000#\\025\\010~\\254\";\n";
	GError *error = NULL;
	char *contents = NULL;
	gboolean success;
	const char *path = "test-dhclient-write-duid.leases";

	success = nm_dhcp_dhclient_save_duid (path, duid, &error);
	g_assert_no_error (error);
	g_assert (success);

	success = g_file_get_contents (path, &contents, NULL, &error);
	g_assert_no_error (error);
	g_assert (success);

	unlink (path);
	g_assert_cmpstr (expected_contents, ==, contents);

	g_free (contents);
}

static void
test_write_existing_duid (void)
{
	const char *duid = "\\000\\001\\000\\001\\023o\\023n\\000\\\"\\372\\214\\326\\302";
	const char *expected_contents = "default-duid \"\\000\\001\\000\\001\\027X\\350X\\000#\\025\\010~\\254\";\n";
	GError *error = NULL;
	char *contents = NULL;
	gboolean success;
	const char *path = "test-dhclient-write-existing-duid.leases";

	success = g_file_set_contents (path, expected_contents, -1, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* Save other DUID; should be a no-op */
	success = nm_dhcp_dhclient_save_duid (path, duid, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* reread original contents */
	success = g_file_get_contents (path, &contents, NULL, &error);
	g_assert_no_error (error);
	g_assert (success);

	unlink (path);
	g_assert_cmpstr (expected_contents, ==, contents);

	g_free (contents);
}

static void
test_write_existing_commented_duid (void)
{
	#define DUID "\\000\\001\\000\\001\\023o\\023n\\000\\\"\\372\\214\\326\\302"
	#define ORIG_CONTENTS "#default-duid \"\\000\\001\\000\\001\\027X\\350X\\000#\\025\\010~\\254\";\n"
	const char *expected_contents = \
		"default-duid \"" DUID "\";\n"
		ORIG_CONTENTS;
	GError *error = NULL;
	char *contents = NULL;
	gboolean success;
	const char *path = "test-dhclient-write-existing-commented-duid.leases";

	success = g_file_set_contents (path, ORIG_CONTENTS, -1, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* Save other DUID; should be a no-op */
	success = nm_dhcp_dhclient_save_duid (path, DUID, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* reread original contents */
	success = g_file_get_contents (path, &contents, NULL, &error);
	g_assert_no_error (error);
	g_assert (success);

	unlink (path);
	g_assert_cmpstr (expected_contents, ==, contents);

	g_free (contents);
}

/*******************************************/

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

	g_type_init ();

	g_test_add_func ("/dhcp/dhclient/orig_missing", test_orig_missing);
	g_test_add_func ("/dhcp/dhclient/override_client_id", test_override_client_id);
	g_test_add_func ("/dhcp/dhclient/override_hostname", test_override_hostname);
	g_test_add_func ("/dhcp/dhclient/existing_alsoreq", test_existing_alsoreq);
	g_test_add_func ("/dhcp/dhclient/existing_multiline_alsoreq", test_existing_multiline_alsoreq);
	g_test_add_func ("/dhcp/dhclient/duids", test_duids);

	g_test_add_func ("/dhcp/dhclient/read_duid_from_leasefile", test_read_duid_from_leasefile);
	g_test_add_func ("/dhcp/dhclient/read_commented_duid_from_leasefile", test_read_commented_duid_from_leasefile);

	g_test_add_func ("/dhcp/dhclient/write_duid", test_write_duid);
	g_test_add_func ("/dhcp/dhclient/write_existing_duid", test_write_existing_duid);
	g_test_add_func ("/dhcp/dhclient/write_existing_commented_duid", test_write_existing_commented_duid);

	return g_test_run ();
}

