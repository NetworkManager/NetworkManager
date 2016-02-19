/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 *
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
 * Copyright 2008 - 2011 Red Hat, Inc.
 *
 */

#include "nm-default.h"

#include <string.h>

#include "nm-utils.h"
#include "nm-setting-connection.h"
#include "nm-setting-8021x.h"

#include "nm-test-utils.h"

static void
compare_blob_data (const char *test,
                   const char *key_path,
                   GBytes *key)
{
	char *contents = NULL;
	gsize len = 0;
	GError *error = NULL;
	gboolean success;

	g_assert (key && g_bytes_get_size (key) > 0);

	success = g_file_get_contents (key_path, &contents, &len, &error);
	nmtst_assert_success (success, error);

	g_assert_cmpmem (contents, len, g_bytes_get_data (key, NULL), g_bytes_get_size (key));

	g_free (contents);
}

static void
check_scheme_path (GBytes *value, const char *path)
{
	const guint8 *p;

	g_assert (value);

	p = g_bytes_get_data (value, NULL);
	g_assert (memcmp (p, NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH, strlen (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH)) == 0);
	p += strlen (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH);
	g_assert (memcmp (p, path, strlen (path)) == 0);
	p += strlen (path);
	g_assert (*p == '\0');
}

static void
test_private_key_import (const char *path,
                         const char *password,
                         NMSetting8021xCKScheme scheme)
{
	NMSetting8021x *s_8021x;
	gboolean success;
	NMSetting8021xCKFormat format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
	NMSetting8021xCKFormat tmp_fmt;
	GError *error = NULL;
	GBytes *tmp_key = NULL, *client_cert = NULL;
	const char *pw;

	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	g_assert (s_8021x);

	success = nm_setting_802_1x_set_private_key (s_8021x,
	                                             path,
	                                             password,
	                                             scheme,
	                                             &format,
	                                             &error);
	nmtst_assert_success (success, error);
	g_assert (format != NM_SETTING_802_1X_CK_FORMAT_UNKNOWN);
	tmp_fmt = nm_setting_802_1x_get_private_key_format (s_8021x);
	g_assert (tmp_fmt == format);

	/* Make sure the password is what we expect */
	pw = nm_setting_802_1x_get_private_key_password (s_8021x);
	g_assert (pw != NULL);
	g_assert_cmpstr (pw, ==, password);

	if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB) {
		tmp_key = nm_setting_802_1x_get_private_key_blob (s_8021x);
		compare_blob_data ("private-key-import", path, tmp_key);
	} else if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH) {
		g_object_get (s_8021x, NM_SETTING_802_1X_PRIVATE_KEY, &tmp_key, NULL);
		check_scheme_path (tmp_key, path);
		g_bytes_unref (tmp_key);
	} else
		g_assert_not_reached ();

	/* If it's PKCS#12 ensure the client cert is the same value */
	if (format == NM_SETTING_802_1X_CK_FORMAT_PKCS12) {
		g_object_get (s_8021x, NM_SETTING_802_1X_PRIVATE_KEY, &tmp_key, NULL);
		g_assert (tmp_key);

		g_object_get (s_8021x, NM_SETTING_802_1X_CLIENT_CERT, &client_cert, NULL);
		g_assert (client_cert);

		/* make sure they are the same */
		g_assert (g_bytes_equal (tmp_key, client_cert));

		g_bytes_unref (tmp_key);
		g_bytes_unref (client_cert);
	}

	g_object_unref (s_8021x);
}

static void
test_phase2_private_key_import (const char *path,
                                const char *password,
                                NMSetting8021xCKScheme scheme)
{
	NMSetting8021x *s_8021x;
	gboolean success;
	NMSetting8021xCKFormat format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
	NMSetting8021xCKFormat tmp_fmt;
	GError *error = NULL;
	GBytes *tmp_key = NULL, *client_cert = NULL;
	const char *pw;

	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	g_assert (s_8021x);

	success = nm_setting_802_1x_set_phase2_private_key (s_8021x,
	                                                    path,
	                                                    password,
	                                                    scheme,
	                                                    &format,
	                                                    &error);
	nmtst_assert_success (success, error);
	g_assert (format != NM_SETTING_802_1X_CK_FORMAT_UNKNOWN);
	tmp_fmt = nm_setting_802_1x_get_phase2_private_key_format (s_8021x);
	g_assert (tmp_fmt == format);

	/* Make sure the password is what we expect */
	pw = nm_setting_802_1x_get_phase2_private_key_password (s_8021x);
	g_assert (pw);
	g_assert_cmpstr (pw, ==, password);

	if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB) {
		tmp_key = nm_setting_802_1x_get_phase2_private_key_blob (s_8021x);
		compare_blob_data ("phase2-private-key-import", path, tmp_key);
	} else if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH) {
		g_object_get (s_8021x, NM_SETTING_802_1X_PHASE2_PRIVATE_KEY, &tmp_key, NULL);
		check_scheme_path (tmp_key, path);
		g_bytes_unref (tmp_key);
	} else
		g_assert_not_reached ();

	/* If it's PKCS#12 ensure the client cert is the same value */
	if (format == NM_SETTING_802_1X_CK_FORMAT_PKCS12) {
		g_object_get (s_8021x, NM_SETTING_802_1X_PHASE2_PRIVATE_KEY, &tmp_key, NULL);
		g_assert (tmp_key);

		g_object_get (s_8021x, NM_SETTING_802_1X_PHASE2_CLIENT_CERT, &client_cert, NULL);
		g_assert (client_cert);

		/* make sure they are the same */
		g_assert (g_bytes_equal (tmp_key, client_cert));

		g_bytes_unref (tmp_key);
		g_bytes_unref (client_cert);
	}

	g_object_unref (s_8021x);
}

static void
test_wrong_password_keeps_data (const char *path, const char *password)
{
	NMSetting8021x *s_8021x;
	gboolean success;
	NMSetting8021xCKFormat format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
	GError *error = NULL;
	const char *pw;

	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	g_assert (s_8021x);

	success = nm_setting_802_1x_set_private_key (s_8021x,
	                                             path,
	                                             password,
	                                             NM_SETTING_802_1X_CK_SCHEME_BLOB,
	                                             &format,
	                                             &error);
	nmtst_assert_success (success, error);
	g_assert (format != NM_SETTING_802_1X_CK_FORMAT_UNKNOWN);

	/* Now try to set it to something that's not a certificate */
	format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
	success = nm_setting_802_1x_set_private_key (s_8021x,
	                                             "Makefile.am",
	                                             password,
	                                             NM_SETTING_802_1X_CK_SCHEME_BLOB,
	                                             &format,
	                                             &error);
	nmtst_assert_no_success (success, error);
	g_assert (format == NM_SETTING_802_1X_CK_FORMAT_UNKNOWN);
	g_clear_error (&error);

	/* Make sure the password hasn't changed */
	pw = nm_setting_802_1x_get_private_key_password (s_8021x);
	g_assert (pw);
	g_assert_cmpstr (pw, ==, password);

	g_object_unref (s_8021x);
}

static void
test_clear_private_key (const char *path, const char *password)
{
	NMSetting8021x *s_8021x;
	gboolean success;
	NMSetting8021xCKFormat format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
	GError *error = NULL;
	const char *pw;

	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	g_assert (s_8021x);

	success = nm_setting_802_1x_set_private_key (s_8021x,
	                                             path,
	                                             password,
	                                             NM_SETTING_802_1X_CK_SCHEME_BLOB,
	                                             &format,
	                                             &error);
	nmtst_assert_success (success, error);
	g_assert (format != NM_SETTING_802_1X_CK_FORMAT_UNKNOWN);

	/* Make sure the password is what we expect */
	pw = nm_setting_802_1x_get_private_key_password (s_8021x);
	g_assert (pw);
	g_assert_cmpstr (pw, ==, password);

	/* Now clear it */
	success = nm_setting_802_1x_set_private_key (s_8021x,
	                                             NULL,
	                                             NULL,
	                                             NM_SETTING_802_1X_CK_SCHEME_BLOB,
	                                             NULL,
	                                             &error);
	nmtst_assert_success (success, error);

	/* Ensure the password is also now clear */
	g_assert (!nm_setting_802_1x_get_private_key_password (s_8021x));

	g_object_unref (s_8021x);
}

static void
test_wrong_phase2_password_keeps_data (const char *path, const char *password)
{
	NMSetting8021x *s_8021x;
	gboolean success;
	NMSetting8021xCKFormat format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
	GError *error = NULL;
	const char *pw;

	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	g_assert (s_8021x);

	success = nm_setting_802_1x_set_phase2_private_key (s_8021x,
	                                                    path,
	                                                    password,
	                                                    NM_SETTING_802_1X_CK_SCHEME_BLOB,
	                                                    &format,
	                                                    &error);
	nmtst_assert_success (success, error);
	g_assert (format != NM_SETTING_802_1X_CK_FORMAT_UNKNOWN);

	/* Now try to set it to something that's not a certificate */
	format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
	success = nm_setting_802_1x_set_phase2_private_key (s_8021x,
	                                                    "Makefile.am",
	                                                    password,
	                                                    NM_SETTING_802_1X_CK_SCHEME_BLOB,
	                                                    &format,
	                                                    &error);
	nmtst_assert_no_success (success, error);
	g_assert (format == NM_SETTING_802_1X_CK_FORMAT_UNKNOWN);
	g_clear_error (&error);

	/* Make sure the password hasn't changed */
	pw = nm_setting_802_1x_get_phase2_private_key_password (s_8021x);
	g_assert (pw);
	g_assert_cmpstr (pw, ==, password);

	g_object_unref (s_8021x);
}

static void
test_clear_phase2_private_key (const char *path, const char *password)
{
	NMSetting8021x *s_8021x;
	gboolean success;
	NMSetting8021xCKFormat format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
	GError *error = NULL;
	const char *pw;

	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	g_assert (s_8021x);

	success = nm_setting_802_1x_set_phase2_private_key (s_8021x,
	                                                    path,
	                                                    password,
	                                                    NM_SETTING_802_1X_CK_SCHEME_BLOB,
	                                                    &format,
	                                                    &error);
	nmtst_assert_success (success, error);
	g_assert (format != NM_SETTING_802_1X_CK_FORMAT_UNKNOWN);

	/* Make sure the password is what we expect */
	pw = nm_setting_802_1x_get_phase2_private_key_password (s_8021x);
	g_assert (pw);
	g_assert_cmpstr (pw, ==, password);

	/* Now clear it */
	success = nm_setting_802_1x_set_phase2_private_key (s_8021x,
	                                                    NULL,
	                                                    NULL,
	                                                    NM_SETTING_802_1X_CK_SCHEME_BLOB,
	                                                    NULL,
	                                                    &error);
	nmtst_assert_success (success, error);

	/* Ensure the password is also now clear */
	g_assert (!nm_setting_802_1x_get_phase2_private_key_password (s_8021x));

	g_object_unref (s_8021x);
}

static void
do_8021x_test (gconstpointer test_data)
{
	char **parts, *path, *password;

	parts = g_strsplit ((const char *) test_data, ", ", -1);
	g_assert_cmpint (g_strv_length (parts), ==, 2);

	path = g_build_filename (TEST_CERT_DIR, parts[0], NULL);
	password = parts[1];

	/* Test phase1 and phase2 path scheme */
	test_private_key_import (path, password, NM_SETTING_802_1X_CK_SCHEME_PATH);
	test_phase2_private_key_import (path, password, NM_SETTING_802_1X_CK_SCHEME_PATH);

	/* Test phase1 and phase2 blob scheme */
	test_private_key_import (path, password, NM_SETTING_802_1X_CK_SCHEME_BLOB);
	test_phase2_private_key_import (path, password, NM_SETTING_802_1X_CK_SCHEME_BLOB);

	/* Test that using a wrong password does not change existing data */
	test_wrong_password_keeps_data (path, password);
	test_wrong_phase2_password_keeps_data (path, password);

	/* Test clearing the private key */
	test_clear_private_key (path, password);
	test_clear_phase2_private_key (path, password);

	g_free (path);
	g_strfreev (parts);
}

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	nmtst_init (&argc, &argv, TRUE);

	g_test_add_data_func ("/libnm/setting-8021x/key-and-cert",
	                      "test_key_and_cert.pem, test",
	                      do_8021x_test);
	g_test_add_data_func ("/libnm/setting-8021x/key-only",
	                      "test-key-only.pem, test",
	                      do_8021x_test);
	g_test_add_data_func ("/libnm/setting-8021x/pkcs8-enc-key",
	                      "pkcs8-enc-key.pem, 1234567890",
	                      do_8021x_test);
	g_test_add_data_func ("/libnm/setting-8021x/pkcs12",
	                      "test-cert.p12, test",
	                      do_8021x_test);

	return g_test_run ();
}

