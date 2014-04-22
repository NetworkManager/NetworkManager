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
 * Copyright (C) 2008 - 2011 Red Hat, Inc.
 *
 */

#include <glib.h>
#include <string.h>

#include <nm-utils.h>

#include "nm-setting-connection.h"
#include "nm-setting-8021x.h"

#include "nm-test-utils.h"

static void
compare_blob_data (const char *test,
                   const char *key_path,
                   const GByteArray *key)
{
	char *contents = NULL;
	gsize len = 0;
	GError *error = NULL;
	gboolean success;

	success = g_file_get_contents (key_path, &contents, &len, &error);
	ASSERT (success == TRUE,
	        test, "failed to read blob key file: %s", error->message);

	ASSERT (len > 0, test, "blob key file invalid (size 0)");

	ASSERT (len == key->len,
	        test, "blob key file (%d) and setting key data (%d) lengths don't match",
	        len, key->len);

	ASSERT (memcmp (contents, key->data, len) == 0,
	        test, "blob key file and blob key data don't match");

	g_free (contents);
}

#define SCHEME_PATH "file://"

static void
check_scheme_path (GByteArray *value, const char *path)
{
	guint8 *p = value->data;

	g_assert (memcmp (p, SCHEME_PATH, strlen (SCHEME_PATH)) == 0);
	p += strlen (SCHEME_PATH);
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
	GByteArray *tmp_key = NULL, *client_cert = NULL;
	const char *pw;

	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	ASSERT (s_8021x != NULL, "private-key-import", "setting was NULL");

	success = nm_setting_802_1x_set_private_key (s_8021x,
	                                             path,
	                                             password,
	                                             scheme,
	                                             &format,
	                                             &error);
	ASSERT (success == TRUE,
	        "private-key-import", "error reading private key: %s", error->message);
	ASSERT (format != NM_SETTING_802_1X_CK_FORMAT_UNKNOWN,
	        "private-key-import", "unexpected private key format (got %d)", format);
	tmp_fmt = nm_setting_802_1x_get_private_key_format (s_8021x);
	ASSERT (tmp_fmt == format,
	        "private-key-import", "unexpected re-read private key format (expected %d, got %d)",
	        format, tmp_fmt);

	/* Make sure the password is what we expect */
	pw = nm_setting_802_1x_get_private_key_password (s_8021x);
	ASSERT (pw != NULL,
	        "private-key-import", "failed to get previous private key password");
	ASSERT (strcmp (pw, password) == 0,
	        "private-key-import", "failed to compare private key password");

	if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB) {
		tmp_key = (GByteArray *) nm_setting_802_1x_get_private_key_blob (s_8021x);
		ASSERT (tmp_key != NULL, "private-key-import", "missing private key blob");
		compare_blob_data ("private-key-import", path, tmp_key);
	} else if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH) {
		g_object_get (s_8021x, NM_SETTING_802_1X_PRIVATE_KEY, &tmp_key, NULL);
		ASSERT (tmp_key != NULL, "private-key-import", "missing private key value");
		check_scheme_path (tmp_key, path);
		g_byte_array_free (tmp_key, TRUE);
	} else
		g_assert_not_reached ();

	/* If it's PKCS#12 ensure the client cert is the same value */
	if (format == NM_SETTING_802_1X_CK_FORMAT_PKCS12) {
		g_object_get (s_8021x, NM_SETTING_802_1X_PRIVATE_KEY, &tmp_key, NULL);
		ASSERT (tmp_key != NULL, "private-key-import", "missing private key value");

		g_object_get (s_8021x, NM_SETTING_802_1X_CLIENT_CERT, &client_cert, NULL);
		ASSERT (client_cert != NULL, "private-key-import", "missing client certificate value");

		/* make sure they are the same */
		ASSERT (tmp_key->len == client_cert->len,
		        "private-key-import", "unexpected different private key and client cert lengths");
		ASSERT (memcmp (tmp_key->data, client_cert->data, tmp_key->len) == 0,
		        "private-key-import", "unexpected different private key and client cert data");

		g_byte_array_free (tmp_key, TRUE);
		g_byte_array_free (client_cert, TRUE);
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
	GByteArray *tmp_key = NULL, *client_cert = NULL;
	const char *pw;

	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	ASSERT (s_8021x != NULL, "phase2-private-key-import", "setting was NULL");

	success = nm_setting_802_1x_set_phase2_private_key (s_8021x,
	                                                    path,
	                                                    password,
	                                                    scheme,
	                                                    &format,
	                                                    &error);
	ASSERT (success == TRUE,
	        "phase2-private-key-import", "error reading private key: %s", error->message);
	ASSERT (format != NM_SETTING_802_1X_CK_FORMAT_UNKNOWN,
	        "phase2-private-key-import", "unexpected private key format");
	tmp_fmt = nm_setting_802_1x_get_phase2_private_key_format (s_8021x);
	ASSERT (tmp_fmt == format,
	        "phase2-private-key-import", "unexpected re-read private key format (expected %d, got %d)",
	        format, tmp_fmt);

	/* Make sure the password is what we expect */
	pw = nm_setting_802_1x_get_phase2_private_key_password (s_8021x);
	ASSERT (pw != NULL,
	        "phase2-private-key-import", "failed to get previous private key password");
	ASSERT (strcmp (pw, password) == 0,
	        "phase2-private-key-import", "failed to compare private key password");

	if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB) {
		tmp_key = (GByteArray *) nm_setting_802_1x_get_phase2_private_key_blob (s_8021x);
		ASSERT (tmp_key != NULL, "phase2-private-key-import", "missing private key blob");
		compare_blob_data ("phase2-private-key-import", path, tmp_key);
	} else if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH) {
		g_object_get (s_8021x, NM_SETTING_802_1X_PHASE2_PRIVATE_KEY, &tmp_key, NULL);
		ASSERT (tmp_key != NULL, "phase2-private-key-import", "missing private key value");
		check_scheme_path (tmp_key, path);
	} else
		g_assert_not_reached ();

	/* If it's PKCS#12 ensure the client cert is the same value */
	if (format == NM_SETTING_802_1X_CK_FORMAT_PKCS12) {
		g_object_get (s_8021x, NM_SETTING_802_1X_PHASE2_PRIVATE_KEY, &tmp_key, NULL);
		ASSERT (tmp_key != NULL, "private-key-import", "missing private key value");

		g_object_get (s_8021x, NM_SETTING_802_1X_PHASE2_CLIENT_CERT, &client_cert, NULL);
		ASSERT (client_cert != NULL, "private-key-import", "missing client certificate value");

		/* make sure they are the same */
		ASSERT (tmp_key->len == client_cert->len,
		        "private-key-import", "unexpected different private key and client cert lengths");
		ASSERT (memcmp (tmp_key->data, client_cert->data, tmp_key->len) == 0,
		        "private-key-import", "unexpected different private key and client cert data");

		g_byte_array_free (tmp_key, TRUE);
		g_byte_array_free (client_cert, TRUE);
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
	ASSERT (s_8021x != NULL, "wrong-password-keeps-data", "setting was NULL");

	success = nm_setting_802_1x_set_private_key (s_8021x,
	                                             path,
	                                             password,
	                                             NM_SETTING_802_1X_CK_SCHEME_BLOB,
	                                             &format,
	                                             &error);
	ASSERT (success == TRUE,
	        "wrong-password-keeps-data", "error reading private key: %s", error->message);
	ASSERT (format != NM_SETTING_802_1X_CK_FORMAT_UNKNOWN,
	        "wrong-password-keeps-data", "unexpected private key format (got %d)", format);

	/* Now try to set it to something that's not a certificate */
	format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
	success = nm_setting_802_1x_set_private_key (s_8021x,
	                                             "Makefile.am",
	                                             password,
	                                             NM_SETTING_802_1X_CK_SCHEME_BLOB,
	                                             &format,
	                                             &error);
	ASSERT (success == FALSE,
	        "wrong-password-keeps-data", "unexpected success reading private key");
	ASSERT (error != NULL,
	        "wrong-password-keeps-data", "unexpected missing error");
	ASSERT (format == NM_SETTING_802_1X_CK_FORMAT_UNKNOWN,
	        "wrong-password-keeps-data", "unexpected success reading private key format");

	/* Make sure the password hasn't changed */
	pw = nm_setting_802_1x_get_private_key_password (s_8021x);
	ASSERT (pw != NULL,
	        "wrong-password-keeps-data", "failed to get previous private key password");
	ASSERT (strcmp (pw, password) == 0,
	        "wrong-password-keeps-data", "failed to compare private key password");

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
	ASSERT (s_8021x != NULL, "clear-private-key", "setting was NULL");

	success = nm_setting_802_1x_set_private_key (s_8021x,
	                                             path,
	                                             password,
	                                             NM_SETTING_802_1X_CK_SCHEME_BLOB,
	                                             &format,
	                                             &error);
	ASSERT (success == TRUE,
	        "clear-private-key", "error reading private key: %s", error->message);
	ASSERT (format != NM_SETTING_802_1X_CK_FORMAT_UNKNOWN,
	        "clear-private-key", "unexpected private key format (got %d)", format);

	/* Make sure the password is what we expect */
	pw = nm_setting_802_1x_get_private_key_password (s_8021x);
	ASSERT (pw != NULL,
	        "clear-private-key", "failed to get previous private key password");
	ASSERT (strcmp (pw, password) == 0,
	        "clear-private-key", "failed to compare private key password");

	/* Now clear it */
	success = nm_setting_802_1x_set_private_key (s_8021x,
	                                             NULL,
	                                             NULL,
	                                             NM_SETTING_802_1X_CK_SCHEME_BLOB,
	                                             NULL,
	                                             &error);
	ASSERT (success == TRUE,
	        "clear-private-key", "unexpected failure clearing private key");
	ASSERT (error == NULL,
	        "clear-private-key", "unexpected error clearing private key");

	/* Ensure the password is also now clear */
	ASSERT (nm_setting_802_1x_get_private_key_password (s_8021x) == NULL,
	        "clear-private-key", "unexpected private key password");

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
	ASSERT (s_8021x != NULL, "wrong-phase2-password-keeps-data", "setting was NULL");

	success = nm_setting_802_1x_set_phase2_private_key (s_8021x,
	                                                    path,
	                                                    password,
	                                                    NM_SETTING_802_1X_CK_SCHEME_BLOB,
	                                                    &format,
	                                                    &error);
	ASSERT (success == TRUE,
	        "wrong-phase2-password-keeps-data", "error reading private key: %s", error->message);
	ASSERT (format != NM_SETTING_802_1X_CK_FORMAT_UNKNOWN,
	        "wrong-phase2-password-keeps-data", "unexpected private key format (got %d)", format);

	/* Now try to set it to something that's not a certificate */
	format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
	success = nm_setting_802_1x_set_phase2_private_key (s_8021x,
	                                                    "Makefile.am",
	                                                    password,
	                                                    NM_SETTING_802_1X_CK_SCHEME_BLOB,
	                                                    &format,
	                                                    &error);
	ASSERT (success == FALSE,
	        "wrong-phase2-password-keeps-data", "unexpected success reading private key");
	ASSERT (error != NULL,
	        "wrong-phase2-password-keeps-data", "unexpected missing error");
	ASSERT (format == NM_SETTING_802_1X_CK_FORMAT_UNKNOWN,
	        "wrong-phase2-password-keeps-data", "unexpected success reading private key format");

	/* Make sure the password hasn't changed */
	pw = nm_setting_802_1x_get_phase2_private_key_password (s_8021x);
	ASSERT (pw != NULL,
	        "wrong-phase2-password-keeps-data", "failed to get previous private key password");
	ASSERT (strcmp (pw, password) == 0,
	        "wrong-phase2-password-keeps-data", "failed to compare private key password");

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
	ASSERT (s_8021x != NULL, "clear-phase2-private-key", "setting was NULL");

	success = nm_setting_802_1x_set_phase2_private_key (s_8021x,
	                                                    path,
	                                                    password,
	                                                    NM_SETTING_802_1X_CK_SCHEME_BLOB,
	                                                    &format,
	                                                    &error);
	ASSERT (success == TRUE,
	        "clear-phase2-private-key", "error reading private key: %s", error->message);
	ASSERT (format != NM_SETTING_802_1X_CK_FORMAT_UNKNOWN,
	        "clear-phase2-private-key", "unexpected private key format (got %d)", format);

	/* Make sure the password is what we expect */
	pw = nm_setting_802_1x_get_phase2_private_key_password (s_8021x);
	ASSERT (pw != NULL,
	        "clear-phase2-private-key", "failed to get previous private key password");
	ASSERT (strcmp (pw, password) == 0,
	        "clear-phase2-private-key", "failed to compare private key password");

	/* Now clear it */
	success = nm_setting_802_1x_set_phase2_private_key (s_8021x,
	                                                    NULL,
	                                                    NULL,
	                                                    NM_SETTING_802_1X_CK_SCHEME_BLOB,
	                                                    NULL,
	                                                    &error);
	ASSERT (success == TRUE,
	        "clear-phase2-private-key", "unexpected failure clearing private key");
	ASSERT (error == NULL,
	        "clear-phase2-private-key", "unexpected error clearing private key");

	/* Ensure the password is also now clear */
	ASSERT (nm_setting_802_1x_get_phase2_private_key_password (s_8021x) == NULL,
	        "clear-phase2-private-key", "unexpected private key password");

	g_object_unref (s_8021x);
}

int main (int argc, char **argv)
{
	GError *error = NULL;
	char *base;

	if (argc < 3)
		FAIL ("init", "need at least two arguments: <path> <password>");

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

	if (!nm_utils_init (&error))
		FAIL ("nm-utils-init", "failed to initialize libnm-util: %s", error->message);

	/* Test phase1 and phase2 path scheme */
	test_private_key_import (argv[1], argv[2], NM_SETTING_802_1X_CK_SCHEME_PATH);
	test_phase2_private_key_import (argv[1], argv[2], NM_SETTING_802_1X_CK_SCHEME_PATH);

	/* Test phase1 and phase2 blob scheme */
	test_private_key_import (argv[1], argv[2], NM_SETTING_802_1X_CK_SCHEME_BLOB);
	test_phase2_private_key_import (argv[1], argv[2], NM_SETTING_802_1X_CK_SCHEME_BLOB);

	/* Test that using a wrong password does not change existing data */
	test_wrong_password_keeps_data (argv[1], argv[2]);
	test_wrong_phase2_password_keeps_data (argv[1], argv[2]);

	/* Test clearing the private key */
	test_clear_private_key (argv[1], argv[2]);
	test_clear_phase2_private_key (argv[1], argv[2]);

	base = g_path_get_basename (argv[0]);
	fprintf (stdout, "%s: SUCCESS\n", base);
	g_free (base);
	return 0;
}

